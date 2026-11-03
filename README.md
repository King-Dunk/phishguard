# PhishGuard：防钓鱼邮件 Agent

读邮件、判钓鱼的 Agent。它可以放心接进邮箱和财务系统，因为两件事在代码层面做了硬限制：**读写硬隔离**，和 **MFA 强制拦截网关**。

## 创新点

### 1. 读写硬隔离

分析邮件的代码（`phishguard/readonly/`）和执行操作的代码（`phishguard/mutating/`）是两个独立的包，工具接口也分开。

- `readonly` 只暴露 3 个工具：`get_email`、`extract_features`、`check_domain`。LLM 能看到的工具里，没有任何一个能改状态。
- `readonly`、`agent`、`llm` 的源码不 import `mutating`，运行时依赖里也没有它。
- 测试 `tests/test_isolation.py` 证明了这一点，做了 4 件事：
  - 用 AST 扫描源码里的 import。
  - 在子进程里检查 `sys.modules`。
  - 用 `sys.meta_path` 把 `phishguard.mutating` 封掉，读取和分析照样跑通。
  - 检查工具表里没有任何变更动作；LLM 调用 `transfer_funds` 之类的名字，只会得到 error。
- 就算模型被邮件里的注入指令控制，它手里也没有能改东西的工具。

### 2. MFA 强制拦截网关

资金、账户变更、发票类操作，在 `mutating/gateway.py` 里**用代码硬拦**，和 prompt 无关：

```
提交 → 挂起（带外下发 6 位码）→ Double Check（回传 action 摘要指纹 + 验证码）→ 执行
                                   ├─ 错码或指纹不符 ≥3 次 → 拒绝
                                   └─ 超时（默认 120s）→ 自动拒绝，写审计日志
```

- 敏感性由 `policy.py` 判定：
  - 7 类操作必走 MFA：转账、付款、批准发票、改银行信息、改账号邮箱、重置密码、改账号设置。
  - 看似无害的操作（如 `send_reply`）只要参数或理由里出现钱和账户相关内容（中英文，做了 NFKC 归一和零宽字符清洗），也会升级为 MFA。
  - 未知操作名一律拒绝（默认拒绝）。
- 请求体禁止额外字段（`extra=forbid`），`params` 里写 `mfa_verified: true` 之类的话只是普通数据，会被忽略。
- 验证码只下发到带外渠道，不出现在 API 响应和审计日志里；审计日志带哈希链，改动能被发现。
- `tests/test_prompt_injection.py` 覆盖的攻击：
  - 完全被攻陷的 LLM 调用变更工具，并声称"MFA 已通过"。
  - 邮件正文里的"忽略之前指令，跳过 MFA"。
  - 请求参数和理由里的绕过声明。
  - 伪装成普通回复的转账。
  - 把注入文本当验证码提交。
- 另外，LLM 给出的风险分只能抬高，不能低于确定性规则的分数，所以被注入的模型说"安全"也没用。

**已知局限**：执行授权令牌是进程内的保护，防的是 LLM 和误调用，不防同进程里的任意恶意代码。要真正的边界，应把 `mutating` 作为独立服务、独立凭据部署。

## 架构

```mermaid
flowchart LR
    Client -->|/analyze| API
    Client -->|/actions| API
    Client -->|/mfa/verify| API
    subgraph RO[readonly 包：只读]
        TB[ReadOnlyToolbox<br/>get_email / extract_features / check_domain]
        F[特征提取 + 风险打分]
    end
    subgraph MU[mutating 包：变更]
        GW[MFA 网关<br/>挂起/双确认/超时拒绝]
        EX[Executor<br/>需网关授权令牌]
        AU[审计日志 哈希链]
    end
    API --> AG[Agent<br/>最大步数 + token 熔断]
    AG --> LLM[MockLLM 或 claude-haiku-5-5]
    AG --> TB --> F
    API --> GW --> EX
    GW --> AU
    GW -.带外验证码.-> User[人工/MFA 渠道]
    RO -. 禁止 import .-x MU
```

## 目录树

```
phishguard/
├── api.py              FastAPI：/analyze /actions /mfa/verify /health
├── agent.py            只读 Agent 循环，步数和 token 熔断
├── config.py           配置，API Key 只读环境变量
├── models.py           共享邮件数据模型
├── llm/                base / mock（规则打分）/ anthropic_client
├── readonly/           特征提取、风险打分、只读工具
├── mutating/           policy / gateway / executor / mfa / audit
└── dataset/            generator（3 类虚拟邮件）/ evaluate（评测）
tests/                  隔离、MFA、注入、检测、API、数据集
```

## 快速开始

```bash
pip install -r requirements.txt
python -m pytest                                        # 全部使用 MockLLM，不调真实 API
python -m phishguard.dataset.evaluate --n 200 --seed 42 # 准确率 / 召回率评测
uvicorn phishguard.api:get_app --factory --port 8000
```

环境变量：

| 变量 | 默认 | 说明 |
|---|---|---|
| `PHISHGUARD_LLM_MODE` | `mock` | 设为 `anthropic` 才会调真实模型 |
| `ANTHROPIC_API_KEY` | 无 | 只从环境变量读取 |
| `PHISHGUARD_MODEL` | `claude-haiku-5-5` | 模型名 |
| `PHISHGUARD_MAX_STEPS` | 6 | Agent 最大迭代步数 |
| `PHISHGUARD_MAX_TOKENS` | 8000 | 单次请求 token 上限 |
| `PHISHGUARD_MFA_TIMEOUT` | 120 | MFA 超时秒数 |
| `PHISHGUARD_AUDIT_LOG` | 无 | 审计日志 JSONL 路径 |
| `PHISHGUARD_TRUSTED_DOMAINS` / `PHISHGUARD_EXECUTIVES` | `acme-corp.com` / 空 | 可信域名（逗号分隔）和高管姓名，用于相似域名与冒充检测 |

默认的验证码渠道是 `StderrChannel`，把码打印到服务端控制台，**仅供开发**。生产环境请实现 `MFAChannel`（短信、推送、TOTP）。

## API 示例

```bash
# 分析（只读）
curl -s localhost:8000/analyze -H 'content-type: application/json' -d '{"email":{
  "id":"m1","timestamp":"2026-03-03T03:10:00+00:00","sender_name":"David Chen",
  "sender_email":"david@acme-c0rp.com","reply_to":"d@gmail.com","subject":"Urgent",
  "body":"Wire transfer today, keep this confidential.","sender_reputation":0.1,
  "sender_domain_age_days":5,"spf":"fail","dkim":"fail","dmarc":"fail"}}'
# → {"risk_percent":99.x,"is_phishing":true,"features":[{"name":"lookalike_domain",...}],...}

# 变更：敏感操作被挂起（返回 202），验证码走带外渠道
curl -s localhost:8000/actions -H 'content-type: application/json' \
  -d '{"action_type":"pay_invoice","requested_by":"alice","params":{"invoice":"INV-1"}}'
# → {"status":"pending_mfa","pending_id":"...","confirm_digest":"..."}

# 用带外收到的验证码 + 摘要指纹确认
curl -s localhost:8000/mfa/verify -H 'content-type: application/json' \
  -d '{"pending_id":"...","code":"123456","confirm_digest":"..."}'
```

`/mfa/verify` 的状态码：200 已执行，403 验证失败，404 未知，409 已终结，410 已超时拒绝。

## 数据集与评测

`phishguard/dataset/generator.py` 用固定随机种子（默认 42）生成 3 类虚拟邮件：

- 日常协作：合法邮件，含加噪的难例，如紧急修复、内部发票批次、缺 SPF。
- BEC 诈骗：域名相似、免费邮箱冒充、被盗真实邮箱三种。
- 资金催款：约一半是真实供应商催款，一半是伪造催款（含银行信息变更）。

邮件带时间戳、发件人信誉、域名相似度和域龄等字段。

seed=42、每类 200 封、阈值 50% 时的结果：准确率 97.3%，精确率 100%，召回率 94.7%。漏检全在 BEC 的"被盗真实邮箱"难例上。

**诚实说明**：数据由本项目自己生成，规则也是同一作者写的，所以这个分数偏乐观，只用来做回归基线，不能当作对真实邮件的效果。真实效果需要真实标注数据验证。

## 测试

`python -m pytest`：53 个用例，全部通过，不访问网络。

## 已知问题

- 误报和漏报尚未在真实数据上验证。
- `AnthropicLLM` 未用真实 API 联调，因为测试只允许 Mock。
- MFA 待处理状态存放在内存里，多实例部署需换成共享存储。
