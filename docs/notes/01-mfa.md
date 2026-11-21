# 01 · MFA 是怎么验证的

> 一句话：敏感操作先被扣住。只有本人用两种不同的方式、针对"这一笔具体的操作"完成验证，网关才放行。AI 说什么都跳不过这一步。

## 要解决的问题

AI 要读邮件，而邮件是攻击者写的。万一 AI 被骗去发起转账，谁来拦？答案不能是"AI 自己"。所以转账这类操作在代码里被扣住，只有人能放行。

## 整个流程

1. **提交**：`gateway.submit("transfer_funds", {"amount": "9800", "payee_id": "ACME-VENDOR"}, "you")`。
2. **判断要不要验证**：交给 `policy.requires_mfa()`（见第 03 篇）。转账永远要。
3. **扣住**：状态变成 `pending_mfa`，返回 `pending_id` 和 `confirm_digest`，开始 120 秒倒计时。
4. **一个一个提交验证**：每次提交都要带上 `confirm_digest`。
5. **满足策略就放行**：至少两种不同的方式，并且至少一种不是"知道的东西"。
6. **放行的顺序**：先把状态改成 `executed`，再发执行凭证，再调用执行器，最后写审计记录。

途中可能的结局：验证失败太多次 → 作废（`rejected`）；超时 → 作废（`expired`）；放行了但银行拒绝（冷静期、限额）→ `declined`。

## digest：把批准绑在"这一笔"上

```python
def action_digest(action, params, requested_by):
    blob = json.dumps({"a": action.value, "p": params, "u": requested_by}, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]
```

（`phishguard/mutating/gateway.py`）

- 操作类型、参数、申请人放在一起算哈希。金额改一分、收款人换一个，digest 就不一样了。
- 每次提交验证都要回传 digest，网关用常数时间比较（`ct_equal`）。对不上就算一次失败，这次的通行密钥挑战也随之作废。
- 通行密钥签名的挑战值同样绑定这一笔，只能用一次。所以 $1 那笔的签名，放行不了 $9,800 那笔。
- 意义：人批准的就是屏幕上看到的那一笔，中间没法偷换。

## 四种验证方式，分两类

| 方式 | 类别 | 怎么验 |
|---|---|---|
| 密码 `password` | 知道的东西 | argon2id 哈希，常数时间比较；同一个用户错 5 次，密码锁 15 分钟 |
| 安全问题 `security_questions` | 知道的东西 | 答案先规范化再用 argon2id 哈希；每次随机抽 2 题，答完前不换题；每个用户每小时最多失败 3 次 |
| 验证器 App `totp` | 拥有的东西 | 30 秒一个码；每个时间窗只能用一次（记下上次用过的时间步，只接受更新的） |
| 通行密钥 `webauthn`（Touch ID） | 拥有的东西，加本机指纹或 PIN | 必须做用户验证；挑战绑定这一笔、只能用一次；检查来源网址、RP ID 和签名计数器 |

判断"够不够"的代码（`phishguard/mutating/factors.py`）：

```python
def satisfied(self, methods):
    ms = set(methods) & set(METHODS)
    if len(ms) < self.required:  # 默认要 2 种不同方式
        return False
    return self.allow_knowledge_only or any(CATEGORY[m] != KNOWLEDGE for m in ms)
```

为什么"密码 + 安全问题"不够：两个都是"知道的东西"，同一个钓鱼表单可以一次全部骗走。NIST SP 800-63B 也不承认安全问题是一种认证方式。所以至少要有一个"拥有的东西"。

## 两层失败限制

- **每一笔**：错 3 次，这一笔作废（`too_many_attempts`）。
- **每一种操作**（申请人 + 操作类型）：连续失败 5 次，跨多笔也累计，这种操作锁 15 分钟。
- **只有完整放行一笔，计数才清零**。只通过一个验证不清零。否则，手里有偷来密码的攻击者，可以在两次猜验证码之间用密码把计数清零，等于无限次猜。
- 每种方式还有自己的限制：密码锁定，安全问题每小时 3 次。

## 防并发、防重复执行

- 整个验证在一把锁里进行。同时提交两个验证也会排队，放行最多发生一次。
- 先把状态改成 `executed` 再调执行器。哪怕银行接口出错，这一笔也不会被执行第二次。
- 执行时带幂等键 `pg-<pending_id>`，银行那边也能去重。

## 执行凭证：只有网关能发

```python
_SECRET = object()


class ExecutionGrant:
    def __init__(self, token, digest, pending_id=None):
        if token is not _SECRET:
            raise PermissionError("execution grants can only be issued by the MFA gateway")
```

（`phishguard/mutating/executor.py`）

执行器 `run()` 做的第一件事就是检查凭证。不带凭证，或者自己伪造一个，都直接 `PermissionError`。演示脚本第 4 步试的就是这两种。

局限：这是**同一个进程内**的保护。它挡得住 AI 和误调用，挡不住同一进程里的恶意代码，因为那样的代码可以直接 import `_SECRET`。真正的边界需要把执行端拆成独立的服务，用单独的凭证。

## 审计：改不了的记录

- 每一步都记一条：扣住、每次验证、失败、锁定、放行、拒绝。
- 记的是"用了什么方式、结果如何"，从来不记密码、验证码、答案或签名本身。
- 每条记录都包含上一条的哈希（SHA-256 链）。改、删、调换任何一条，`verify_chain()` 都能指出第一个断开的地方。

## 钱的最后一道防线：冷静期和限额

MFA 证明的是"本人批准了这一笔"，证明不了"这笔钱该付"。所以模拟银行还有两道：

- 收款账户信息刚新增或修改过，24 小时内不付款。这专门对付"我们换银行账户了"这类诈骗。
- 单笔限额 60,000，每日限额 100,000。

## 代码在哪

- `phishguard/mutating/gateway.py`：状态机、digest、失败计数、放行
- `phishguard/mutating/factors.py`：四种验证方式和策略
- `phishguard/mutating/executor.py`：执行凭证和执行器
- `phishguard/mutating/audit.py`：哈希链
- 测试：`tests/test_mfa_gateway.py`、`tests/test_mfa_factors.py`、`tests/test_mfa_hardening.py`

## 我学到的

- 关键问题不是"怎么验证一个人"，而是"验证的到底是哪一笔"。没有 digest，一次合法的批准就能被挪用。
- 失败计数"什么时候清零"，本身就是攻击面。
- 顺序很重要：先改状态再执行，比执行完再改状态安全。
