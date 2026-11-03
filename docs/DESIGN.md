# Design decisions (interview-style Q&A)

**1. Why block in code instead of in the prompt?**
A prompt is a request to the model. Model output can be changed by the email it reads, by a poisoned tool result, or by a plain mistake. So the MFA rule lives in `mutating/gateway.py`, and the executor refuses to run without a grant that only the gateway can issue. Whatever the model writes ("MFA already verified") is just text; no code path reads it as permission.

**2. How is read/write isolation enforced, and how do you prove it?**
Two packages. The LLM is only given `ReadOnlyToolbox`, which has three read tools. `tests/test_isolation.py` checks four things: no import of `mutating` in the source of `readonly`, `llm` and `agent` (AST scan); after importing them in a fresh process, no `phishguard.mutating` in `sys.modules`; the whole analysis still works when a `sys.meta_path` hook blocks `phishguard.mutating`; and tool names don't overlap with action names, with mutating tool calls returning errors. Limit: this is import-level separation inside one process.

**3. What counts as a "sensitive" action, and can a harmless-looking action slip through?**
`policy.py` has two rules. Seven action types always need MFA. For every other type, any param key or text (including `reason`) mentioning money or account words (English and Chinese) escalates to MFA, after NFKC normalization and zero-width removal, so fullwidth or zero-width tricks don't hide it. Unknown action names are denied. This is keyword-based, so a paraphrase with no keyword could pass; the safer direction is to add more always-MFA types, not more keywords.

**4. How do MFA timeout and replay work?**
Each pending action has an expiry from an injectable clock. Every gateway call first sweeps expired items to `expired` and writes an `action_rejected (mfa_timeout)` audit event, so a late correct code is rejected (HTTP 410). A pending action is a small state machine (pending, then executed, rejected or expired) behind a lock; only `pending` can execute, so replaying a used code returns 409. Codes are random per pending action, stored salted and hashed, and compared in constant time. Three failures reject the action.

**5. What is the "double check"?**
`/actions` returns a digest of the exact action (type, params, requester). `/mfa/verify` needs that digest and the code. The approver's client has to echo what was proposed, so a swapped or altered action can't ride on a valid code. A digest mismatch counts as a failed attempt.

**6. Why can the LLM only raise the risk score?**
The final score is `max(deterministic score, LLM score)`. If a prompt-injected model says "risk 0", the rule-based floor still stands. The cost is that the LLM can add false positives; for a security tool failing toward caution is the chosen trade. Email text containing injection phrases is also a feature that raises the score.

**7. How do the circuit breakers save money?**
Two limits per request: `max_steps` and a token budget (input plus output per call, summed). Each call's `max_tokens` is capped to the remaining budget. On a trip, the agent stops and returns the deterministic result with `circuit_break` set, so a looping model costs a bounded amount and the caller still gets an answer. Email body is also truncated to 2000 chars in tool output and capped at 20000 on input.

**8. Why a MockLLM, and what does it prove?**
It makes tests free, offline and deterministic (a test blocks sockets and checks the SDK isn't imported). It proves the control flow, limits and security properties, which don't depend on model quality. It does not prove how a real model behaves; `scripts/smoke_real_api.py` exists for that and hasn't been run yet.

**9. How trustworthy are the evaluation numbers?**
Not very, by design. The data is synthetic and the rules and generator share assumptions, so 97% is a regression baseline. The honest weak spot it shows is BEC from a real compromised mailbox, which only wording reveals.

**10. What would you change to run this in production?**
Run `mutating` as a separate service with its own credentials and network policy (the in-process grant is only a guard against accidents and LLM misuse); store pending actions and audit logs durably; use a real MFA channel (TOTP or push) bound to the approving user, with rate limits; add authentication and per-user authorization on the API; validate the detector on real labeled mail; and replace keyword escalation with an allowlist of low-risk actions, so anything not on it needs MFA.
