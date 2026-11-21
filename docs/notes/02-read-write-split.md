# 02 · 读写分离：为什么 AI 只能读

> 一句话：读邮件的代码和改东西的代码是两个包，读的那边在代码层面 import 不到写的那边；AI 手里只有三个只读工具；连 Google 发的令牌都是只读的。

## 三层"只读"

### 1. 代码层：两个包互相隔离

- `phishguard/readonly/`：解析邮件、提取特征、打分、只读工具。
- `phishguard/mutating/`：网关、策略、验证方式、执行器、支付、邮箱写操作。
- 只读这边，以及 AI 的代理循环（`agent.py`）和模型客户端（`llm/`），都不能 import `mutating`。

### 2. AI 层：工具箱里只有三个只读工具

- `get_email`（读邮件）、`extract_features`（提取特征）、`check_domain`（查域名）。
- AI 调用其他名字，比如 `transfer_funds`，只会收到一条错误：`unknown tool 'transfer_funds': only read-only tools exist here`。
- 注意：不是"AI 被禁止转账"，而是"转账这个工具在 AI 那边根本不存在"。

### 3. 权限层：令牌本身就是只读的

- Gmail 用 `gmail.readonly`，Microsoft 用 `Mail.Read`。
- 如果读用的令牌里混进了写权限（比如 `gmail.modify`），连接器直接拒绝工作（`OverPrivilegedCredential`），除非有人显式打开开关。
- 写权限（隔离、加标签）是另一份令牌、另一个文件，只有 `mutating/mailbox.py` 会加载。我的真实邮箱试运行根本没有写令牌。
- 意义：就算代码有 bug，Google 那边也会拒绝写操作。

## 怎么证明？靠测试

`tests/test_isolation.py`：

| 测试 | 证明什么 |
|---|---|
| `test_readonly_source_never_mentions_mutating` | 只读包的源码里不出现 `mutating` |
| `test_agent_and_llm_source_never_import_mutating` | 代理循环和模型客户端不 import `mutating` |
| `test_runtime_import_closure_excludes_mutating` | 实际运行时加载的模块里没有 `mutating` |
| `test_readonly_works_even_if_mutating_import_is_blocked` | 把 `mutating` 整个屏蔽掉，只读功能照常工作 |
| `test_toolbox_has_no_mutating_tools` | 工具箱里没有写工具 |
| `test_toolbox_rejects_mutating_tool_calls` | 调用写工具只会得到错误 |

连接器的测试（`tests/test_connectors_*.py`）还会扫描源码里有没有写操作，并真的跑一遍 Gmail 和 Microsoft 的扫描，检查发出的请求全是 GET（取令牌和只读推送订阅除外）。

## 写操作从哪来？只有一个入口

邮件被判为钓鱼 → `mailbox_guard` 把"隔离"提交给网关 → 网关按策略决定直接执行还是扣住。API 的 `/actions` 也一样，先交给网关。通往执行器没有第二条路（见第 01 篇的执行凭证）。

## 和"在提示词里加规则"有什么不同

常见做法是在提示词里写"你不能转账"。这依赖 AI 听话，而注入攻击的本质就是让 AI 不听话。读写分离不靠 AI 听话：它就算想转，也没有工具可用。

## 局限

- 隔离发生在同一个 Python 进程里（import 层面），不是操作系统层面。真正部署时应该把执行端拆成独立的服务，用独立的凭证。
- IMAP 没有只读令牌：应用专用密码什么都能做，只读只能靠代码保证（`EXAMINE`、`BODY.PEEK[]`）。

## 代码在哪

- `phishguard/readonly/tools.py`、`phishguard/agent.py`
- `phishguard/connectors/base.py`（`ensure_read_only`）、`phishguard/connectors/oauth.py`
- `tests/test_isolation.py`、`tests/test_connectors_*.py`

## 我学到的

- 最强的限制是"能力不存在"，而不是"能力被禁止"。
- 权限要在系统外面再保证一次（OAuth scope），代码里的保证只是第一层。
