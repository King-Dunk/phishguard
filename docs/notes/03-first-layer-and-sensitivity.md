# 03 · 第一层过滤、"敏感"由谁定义、怎么不被注入

> 一句话：第一层是固定的规则打分，每一分都说得出来源；什么操作算"敏感"写死在代码里；AI 的意见只能让分数更高，不能更低。

## 第一层：规则打分

- 邮件先被解析（`.eml` 原文，包括 HTML、附件、SPF/DKIM/DMARC 认证结果），然后由一组特征分别打分。权重放在 `phishguard/readonly/weights.yaml`（当前 v5，53 个权重项）。
- 每个特征都报告自己加了多少分，加起来就是总分。阈值是 35，到 35 分就判为钓鱼。
- 例子：演示脚本里那封 2025 年冒充 Google Drive 的钓鱼。

| 特征 | 加分 | 证据 |
|---|---|---|
| `link_brand_impersonation` | +26.4 | 链接域名里冒用了 google |
| `link_text_mismatch` | +26.4 | 按钮显示 drive.google.com，实际指向别处 |
| `auth_fail` | +19.1 | SPF 验证失败 |
| `payment_keywords` | +9.9 | 出现 "wire" |
| `off_hours_send` | +3.7 | 非工作时间发出 |
| 合计 | **85.5** | |

### "怎么确保第一层有效？"

诚实的回答：没法"确保"，只能**测量**。

- 公开数据上整体抓到 66%，但 2024–25 年的钓鱼只抓到 47%。
- 真实邮箱里，20% 的正常邮件被误报。

所以第一层只负责"尽量多抓、说得清理由"，不负责安全。安全靠第 01、02 篇的设计。

## "敏感"由谁定义：代码

`phishguard/mutating/policy.py` 里的 `requires_mfa()`：

1. **永远要验证**（`ALWAYS_MFA`）：转账、付发票、批准发票、改银行信息、改账户邮箱、重置密码、改账户设置、新增验证方式、删除邮件、从隔离区放出邮件。
2. **批量邮箱操作**：一次超过 10 封（`MAX_UNATTENDED_BATCH`）要验证；批量参数读不懂，也要验证。
3. **其他操作看内容，只升不降**：参数或理由里出现和钱、账户有关的词（wire、transfer、invoice、bank、iban、password、转账、汇款、银行、密码……），或者参数名像 `amount`、`iban`、`payee`，就升级成要验证。检查前先做 Unicode 规范化（NFKC），去掉零宽字符和文字方向控制符，防止用"拆字"绕过。
4. **查不完就当敏感**：参数嵌套超过 6 层，或者节点超过 2000 个，直接要求验证（fail closed）。这一条就是红队打出的第一个漏洞修出来的。
5. **不认识的操作直接拒绝**：操作名先规范化，不在枚举里就报错（default deny）。

关键：这个判断只看"操作类型、参数、理由"这些**数据**，不看 AI 说了什么。AI 的输出根本不进这个函数。

## 怎么不被上下文注入

注入能改变的只有 AI 的输出。所以只要看 AI 的输出流到了哪里：

| AI 的输出 | 能影响什么 | 怎么限死 |
|---|---|---|
| 工具调用 | 只有三个只读工具 | 写工具不存在（第 02 篇） |
| 风险分 | 默认只能往上抬 | `final = max(规则分, AI 分)` |
| 解释文字 | 会显示给用户 | 判为钓鱼时不显示；AI 想压低分数时也不显示；其余情况清洗、截到 300 字，并标注 `untrusted_model_output` |
| "已经验证过"之类的说法 | 没有作用 | 请求里多出来的字段直接返回 422；参数里的 `mfa_verified` 只是普通数据，策略不认 |

### 唯一允许 AI 压低分数的口子（默认关闭）

`lowered_risk()`（`phishguard/agent.py`）：

```python
def lowered_risk(base, llm, features, s):
    lo, hi = s.llm_lower_zone  # 20–50
    if not s.llm_may_lower or llm >= base or not lo <= base <= hi:
        return base  # 没打开，或不在灰区：规则说了算
    if any(f.name in VETO_FEATURES for f in features):
        return base  # 藏文字、混淆、对 AI 说话：一票否决
    return min(base, max(llm, lo, content_floor(features)))
```

- 只在 20–50 分之间起作用，最低只能压到 20。
- 不能低于"内容分"：能被抵消的只有路由和时间这类背景信号（回复地址不一致、没有认证、非工作时间等 7 个），措辞、链接、附件、身份、认证失败都不能抵消。
- 邮件里有隐藏文字、混淆文字或注入企图，AI 的票直接作废。

效果（详见第 06 篇和 `docs/EVALUATION.md`）：打开这个口子后，一个完全被控制、对什么都说"安全"的 AI，最多让测试集的召回率掉 6.5 个百分点；默认关闭时，影响是 0。

## 代码在哪

- `phishguard/readonly/features.py`、`phishguard/readonly/weights.yaml`：特征和权重
- `phishguard/mutating/policy.py`：敏感的定义
- `phishguard/agent.py`：分数合并、`lowered_risk`
- `phishguard/api.py`：解释文字的处理（`_model_note`）

## 我学到的

- 防注入最可靠的办法，不是认出注入，而是让注入影响不到任何关键决定。
- 给 AI 开口子（比如允许它压分）之前，先写好攻击这个口子的测试，并且把最坏情况量化出来。
