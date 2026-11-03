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

## Production hardening (round 2)

**11. Why parse `.eml` yourself instead of trusting fields the caller sends?**
In production the input is the raw message from the MTA. `readonly/eml.py` uses the stdlib `email` package with `policy.default`, walks multipart trees, extracts plain text, strips HTML to text while keeping each anchor's visible text and real `href`, and records attachment name, MIME type and size without executing anything. Raw size is capped at 2 MB before parsing.

**12. Anyone can write an `Authentication-Results` header. How do you trust SPF/DKIM/DMARC?**
Each hop prepends headers, so the topmost one was written by our own receiving MTA; anything below may come from the sender. The parser uses only the header whose `authserv-id` matches `PHISHGUARD_AUTHSERV_ID`, or the topmost one when that is not set. `phish_forged_auth_header.eml` carries a fake `pass` header under the real `fail` and is still scored as failing. `softfail` and `permerror` count as fail.

**13. How do you catch look-alike domains?**
Three layers on the registrable domain: substring of a trusted domain (`acme-corp.com.secure-login.net`); character normalization (`0→o`, `rn→m`) plus similarity ratio; and Levenshtein distance ≤ 2 for names of at least 6 characters (`acmecrop.com`). Punycode labels are decoded and mixed-script letters (Cyrillic `а`, Greek `ο`, ...) are folded to Latin; if the result is or imitates a trusted domain, that is `homoglyph_domain`, the strongest signal. The same checks run on link hosts.

**14. How does the score stay explainable?**
Each feature has a weight `w`. The score is noisy-OR, `1 - Π(1 - w)`, which equals `1 - exp(-Σ Lᵢ)` with `Lᵢ = -ln(1 - wᵢ)`. Each feature's contribution is `score × Lᵢ / ΣL`. The contributions are exact, independent of feature order, and add up to the score, so the API can say "homoglyph_domain +54.7, payment_keywords +13.3 = 68.0". A plain weighted sum would also be additive, but it would exceed 100 and lose the "independent evidence" reading.

**15. Why TOTP, and how is replay prevented?**
TOTP needs no SMS provider and works offline in any authenticator app. A code is valid for its whole 30 s step (±1 step for clock drift), so it could be replayed. The manager stores the last accepted step per user and only accepts a strictly newer one, which burns the current and every older step. The step is stored in SQLite, so a restart does not reopen the window. A TOTP step is only consumed when the action digest also matches, so a typo in the digest does not waste a code.

**16. Why two failure limits (3 per action, 5 per operation)?**
Three bad codes reject one pending action, but an attacker could open a new pending action and keep guessing. So failures are also counted per operation (requester + action type) across pending actions. Five in a row lock that operation for 15 minutes, write `operation_locked` to the audit log, and return 423; while locked, attempts are recorded as `operation_blocked`. A success resets the counter. Locking per operation instead of per user means an attacker hammering `transfer_funds` cannot block the user's other work.

**17. What does the hash chain prove, and what doesn't it?**
Each entry stores the previous entry's SHA-256 and its own hash over canonical JSON. Editing, deleting or reordering any row breaks the chain at that row; re-hashing one edited row breaks the next link. `verify_chain()` checks both memory and the SQLite copy and `first_broken()` names the row. It does not stop someone who can rewrite the whole table and recompute every hash. For that, periodically publish the latest hash somewhere the attacker can't write (a WORM bucket, a separate log service, or a signed checkpoint).

**18. Why API keys, and why constant-time comparison?**
It's the simplest service-to-service auth that a mail gateway or SOAR tool can use. The presented key and every stored key are SHA-256 hashed and compared with `hmac.compare_digest`, and the loop never exits early, so response time reveals neither a matching prefix nor which key matched. The server refuses to start without keys unless `PHISHGUARD_ALLOW_NO_AUTH=1` is set (fail closed). Limit: keys identify a client system, not a person; `requested_by` should come from SSO in production.

**19. How does the rate limiter work and where does it break?**
A sliding-window log per bucket: a deque of timestamps, at most N per 60 s, answering 429 with `Retry-After`. Valid keys get a bucket per key; failed auth gets a bucket per client address, which slows key guessing. Idle buckets are evicted when the table is full, so memory is bounded. It is per process: with several workers the effective limit multiplies. The fix is Redis with an atomic counter.

**20. Why SQLite and no ORM?**
The data is four small tables (pending actions, audit, TOTP, lockouts) and the queries are key lookups and appends. `sqlite3` is in the standard library, adds no dependency, and runs in WAL mode with `synchronous=FULL` so an audit row survives a crash. One connection behind a lock is enough at this scale. The store has no update or delete method for audit rows. For several instances, the same interface maps to Postgres.

**21. What is the hybrid mode for?**
Cost. Rules cost nothing and decide the clear cases. The LLM is only called when the rule score is in the gray zone (30-70), so spending follows the share of ambiguous mail, not total volume. `evaluate.py` reports accuracy, precision, recall, F1, latency, LLM call rate and cost per 1000 mails for `rules`, `llm` and `hybrid`. Prices are CLI inputs, not hard-coded, and the LLM modes only run with `ANTHROPIC_API_KEY`; CI runs `rules` only. On the synthetic set, 16.7% of mail is in the gray zone and all 16 rule misses are in it.

## Red team and self-improvement (round 3)

**22. How does the red team decide that an attack "failed"?**
Not by status codes alone. After every payload the runner checks invariants with oracles that see inside the system: the executor ledger (any money/account action without an approval the runner made itself is a bypass), a wrapper around the SQLite connection that records every statement (each one must be a string literal from `store.py`, so attacker text can never have become SQL), `PRAGMA integrity_check` plus the table list and audit chain, response headers, files in the sandbox directory, and `/health`. The model in the loop is deliberately compromised: it obeys the mail and calls money tools. A breach means an invariant broke; a detection miss is tracked separately.

**23. Why both Docker and in-process modes?**
Docker answers "what can an attacker reach over the network from a separate box": the API container is non-root, read-only, capability-free, resource-limited and on an `internal` network without egress (checked from inside the container). In-process answers "did anything bad happen inside", because only there can the oracles read the ledger and wrap the database. pytest uses in-process so CI needs no Docker. Both modes ran with the same totals.

**24. Which finding mattered most?**
Deeply nested params. The content-based MFA escalation walked params only 6 levels deep and treated "couldn't look" as "nothing there", so `send_reply` with an IBAN 8 levels down executed without MFA. The fix flips the default: anything the policy can't fully inspect requires MFA, and the API rejects such bodies early. The general lesson: every limit in a security check must fail closed.

**25. Why normalize user identities in the gateway?**
`requested_by` is a string. "Alice" and "alice" were different users, so the capitalized one had no TOTP enrollment and fell back to the development code channel, and it had its own lockout counter. Identities are now NFKC-normalized, casefolded and stripped of zero-width and bidi characters in one function used by the gateway and the TOTP store.

**26. How do you know the SQL is parameterized, not just believe it?**
Code review says every query uses `?` placeholders. The red team proves it at run time: the recorder logs the SQL text of every `execute`, and the oracle requires each to be exactly one of the literals parsed out of `store.py` with `ast`. If anyone ever builds SQL with an f-string, the injected statement isn't in that set and the oracle fails, whether or not the injection "worked".

**27. Why can't improve.py change the MFA gateway, even if a human would approve?**
Because its inputs are attacker-influenced (missed phishing, mutated attacks, optional LLM output). A poisoned input could steer a "fix" that weakens the gate, and a human reviewing a long diff can miss one changed comparison. So the boundary is in code: `check_patch` refuses any diff naming a protected path (normalizing `..`, case and diff prefixes, handling renames and binary diffs), and refuses diffs it can't parse. Changes to the gateway are still possible, but only written by a person. improve.py also never applies anything; tests check that a run leaves every source file byte-identical.

**28. How is the $2 LLM cap made hard?**
Each call is checked before it is sent, against its worst case: input bytes (a token is never fewer than one byte) plus the full `max_tokens`. Actual usage is charged after; if a provider ever bills more than the bound, the loop stops. `--budget` can only lower the $2 ceiling, and without explicit prices the LLM step doesn't run, because a dollar cap can't be enforced against unknown prices.

**29. What did self-improvement teach about itself?**
On the synthetic data, the top "phrases common to misses" included "it's sarah" and "it's david": names from the generator's templates. A tool that auto-merged that rule would have overfitted to the test data. The proposal shows the evidence and the simulated effect (7 of 18 misses rescued, 0 legitimate samples matched), and a human has to judge whether the phrases are real signal.

**30. Why ship the public-dataset script without results?**
The build environment's network policy blocks both corpus hosts. The script, loader and comparison table are tested offline with a mocked download. The README states the expected direction of the synthetic-vs-real gap and marks it as unmeasured, rather than inventing numbers.
