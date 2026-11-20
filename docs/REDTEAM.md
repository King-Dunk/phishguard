# Red team

The attacks, the invariants checked after each one, what they found, and the human-reviewed self-improvement loop.

## Results

`redteam/` holds 94 attacks in seven YAML files (`payloads/`), a runner, and a Docker sandbox.

```bash
python -m redteam.runner                      # in-process, writes redteam/report.md (pytest runs this)
install -d -m 0777 redteam/out && docker compose -f redteam/docker-compose.yml up --build --abort-on-container-exit --exit-code-from redteam
```

Sandbox: the API container runs as uid 10001 with a read-only root filesystem, `cap_drop: ALL`, `no-new-privileges`, CPU/memory/pid limits, SQLite on a tmpfs, and sits on an `internal: true` network with no route out. Verified inside the container: writes to `/app` and `/etc` fail with "Read-only file system", and connecting to 1.1.1.1 fails with "Network is unreachable".

After every attack the runner checks: **no MFA bypass** (no money/account action reached the executor without an approval the runner made itself), **SQL parameterized** (every statement SQLite ran is a string literal in `store.py`; the connection is wrapped to record them), **DB integrity** (`PRAGMA integrity_check`, same tables, audit chain intact), **no crash** (no 5xx, `/health` answers), **no injected response headers**, and **no stray files**. Payloads can add expectations such as minimum risk, status code or a time limit, and (`keys_all`/`keys_none`) which weight keys must or must not fire, checked as invariants. The runner itself drives a compromised LLM that obeys the mail and calls money tools.

Results (`redteam/report.md`, in-process). The Docker run gave the same totals for the original 59 attacks. It has not been re-run for the 17 new ones; their passkey flows sign with the software authenticator over HTTP, so they don't need in-process access, but the `executed_once` and audit-secret checks only run in-process. The 5 v4 payloads (`benign_abuse.yaml`) ran in-process only: Docker was not available on the machine used for this round, so neither the image build nor the containerized red team was re-run.

| Category | Attacks | Security invariants held | Detection met | Interception rate |
|---|---|---|---|---|
| a) Prompt injection (body, subject, filename, hidden HTML, zero-width, Base64, Chinese, fullwidth, fake tool markup) | 12 | 12/12 | 12/12 | 100% |
| b) Privilege escalation / MFA bypass (no/bad key, bypass flags, deep params, forged codes, swapped digest, TOTP replay, cross-user approval, identity variants, enrollment takeover, brute force; passkey replay across actions/users, phishing origin, no UV, cloned key, knowledge-only downgrade, same factor twice, question/password brute force, lockout reset, concurrent release, enrollment-token misuse, BEC cooling-off, limit splitting, non-ASCII inputs, secrets in audit) | 34 | 34/34 | n/a | 100% |
| c) Injection & DoS (SQL into every SQLite field, path traversal, 4 MB body, MIME bombs, 50k-deep JSON, ReDoS, CRLF, RTL override, lone surrogates) | 20 | 20/20 | 5/5 | 100% |
| d) Detection evasion (homoglyphs, split words, leetspeak, image-only, polite BEC, payment redirection; v4: abuse of mailto links, own-domain link text, list headers) | 19 | 19/19 | 17/19 | 89% |
| e) LLM benign-vote abuse (a compromised model answers "risk 0, safe" to every mail; reviewer notes, forged verdict JSON, hidden HTML, newsletter dressing, Chinese) | 9 | 9/9 | 9/9 | 100% |
| **Total** | 94 | **94/94** | | **98%** |

The four original misses in (d) (an image-only lure and three polite BEC mails with no money keywords) now score 51-67 and pass, after the payment-redirection and image-lure rules (below). Four new wordings were then added to check that the rules generalize; two of them miss: a polite payee-detail change from an unknown *company* domain (risk 30, under the 35 threshold) and a first-contact probe that asks for nothing yet (risk 40: flagged at the default threshold, under the payload's bar of 50). They are detection gaps, not breaches, and they feed the self-improvement step below.

### Polite BEC and image-only lures

Polite BEC carries no urgency, secrecy or money keyword, so the rules now look at *what is asked*: a request for action ("could you", "please", "I need you to", "are you at your desk") together with money going somewhere the mail itself names. Four meaning families: buying gift cards / sending their codes, pay or salary into a new account, changing the payment details held for a payee, and paying "to the account below / attached / new account". This is `payment_redirect_request` (weight 0.30; 0.45 when the sender or Reply-To is free mail; 0.10 for an authenticated sender on the trusted-domain list, because colleagues do accounts-payable work). `org_name_in_freemail_address` (0.25) fires when a free-mail address carries our organisation's name (`ap.dept.acme@gmail.com`). The `.eml` parser now counts `<img>` tags (1-2 px tracking pixels and hidden ones excluded), and an HTML body that is only pictures with under 25 words fires `image_lure` (0.20, or 0.35 when the picture is itself a web link). No names, greetings or sample phrases are matched; `tests/test_polite_bec.py` uses paraphrases that appear in no payload, plus ordinary business text that must not fire.

Measured before (`main`) and after, rules mode, threshold 35, commands `python -m phishguard.dataset.evaluate --dataset external --split --fpr-ref easy_ham` and `--n 200 --seed 42`:

| Dataset | Version | Recall | Precision | FPR easy_ham | FPR hard_ham |
|---|---|---|---|---|---|
| Real corpus, **test** split | before | 69.6% (2407/3460) | 98.0% | 0.9% (11/1156) | 59.1% (39/66) |
| Real corpus, **test** split | after | 69.9% (2420/3460) | 98.0% | 0.9% (11/1156) | 59.1% (39/66) |
| Real corpus, dev split | before | 69.1% (5604/8111) | 97.7% | 0.9% (24/2744) | 59.2% (109/184) |
| Real corpus, dev split | after | 69.6% (5646/8111) | 97.7% | 0.9% (24/2744) | 59.2% (109/184) |
| Synthetic (600 mails) | before | 92.0% (BEC 176/200) | 100.0% | 0 false positives | |
| Synthetic (600 mails) | after | 93.4% (BEC 180/200) | 100.0% | 0 false positives | |

Read it for what it is. The public corpora contain almost no BEC: on the dev split `payment_redirect_request` fired on 3 of 8,111 phishing mails and on no legitimate mail, so the real-corpus gain (+13 test mails, +42 dev) comes from the HTML image-only rule (115 dev phishing mails, 0 dev ham). "No false positives" here means none on 2002-era ham; modern legitimate mail has more picture-only HTML and more payroll/vendor-change requests, and `org_name_in_freemail_address` cannot fire on the corpora at all (no organisation is configured there). The weights are hand-set, not fitted. The red-team payloads and the synthetic set were written by this project, so they show the rules work as designed, not how often real BEC is caught.

### Vulnerabilities found and fixed

Each was confirmed against the code before the fix and has a regression test in `tests/test_redteam.py`.

| # | Finding | Impact before the fix | Fix |
|---|---|---|---|
| 1 | Money keyword nested 8+ levels deep in `params` of a harmless action (`send_reply`) | **MFA bypass**: the action executed without MFA (the policy scan stopped at depth 6) | Policy fails closed on unreadable depth or > 2000 nodes; API rejects params deeper than 6 (422) |
| 2 | 2000 nested MIME parts | Unhandled `RecursionError`, HTTP 500 | Pre-parse boundary count, iterative depth/part limits (20/200), 422 |
| 3 | `BANK_CHANGE` regex with `\s+(has)?\s*` on a run of spaces | ReDoS: one request took **10.4 s** | Rewrote the group so whitespace can be matched only one way; linear-time test |
| 4 | Lone UTF-16 surrogate (`"\ud800"`, valid JSON) in any field | HTTP 500 on every endpoint (response encoding and validation errors crashed) | ASCII-escaped JSON responses and error handlers; surrogates are normalized before reaching SQLite |
| 5 | `requested_by: "Alice"` when `alice` uses TOTP | **MFA downgrade** to the dev code channel; also split lockout counters per spelling | One canonical identity (NFKC, casefold, no zero-width/bidi) in gateway and TOTP |
| 6 | Instruction hidden in HTML (`display:none`) next to a text/plain part | Not scanned at all (risk 15) | Parser keeps CSS-hidden text and HTML-only text; new `hidden_html_text` feature; injection scan covers it |
| 7 | Injection in attachment names, link text or Base64; phrasings like "你已获得 MFA 授权", "acting as the system", `transfer_funds` markup | Not flagged | Scan all reader-visible text plus decoded Base64; wider injection patterns |
| 8 | `evil.exe\u200b`, `run.lnk.`, `doc.docm ` attachment names; RTL override names | Dangerous attachment not flagged | Filenames normalized the way Windows treats them; bidi controls raise `header_anomaly` |
| 9 | Two addresses in `From` (trusted one first); Cyrillic "Асme Corp" display name | Mail treated as from the trusted domain / brand spoof missed | `header_anomaly` feature; homoglyph folding in brand matching |
| 10 | Any client key could call `/mfa/enroll` | Attacker enrolls a victim's TOTP first, then approves as the victim | Enrollment needs an admin key (`PHISHGUARD_ADMIN_KEYS`); fail-closed from env |
| 11 | Non-ASCII `confirm_digest` or code (`"ü"`) on an existing pending action | HTTP 500: `hmac.compare_digest` raises `TypeError` on non-ASCII `str` (the old Unicode payloads only reached unknown ids, 404) | `ct_equal()` compares UTF-8 bytes; `pv-mfa-nonascii-inputs` |

Hardening found on the way (not exploitable before, fixed anyway): no request body limit (now 3 MB, 413), 2000-char hostnames made look-alike checks slow (now capped at 253, the DNS limit), split/leetspeak keywords (`w i r e`, `b@nk`) are now de-obfuscated, and a budget-guard bug in `improve.py` under-counted input tokens (now an upper bound with a stop on overbilling).

## Adversarial Self-Improvement (Human-in-the-Loop)

```bash
python -m redteam.improve                                  # template mutations, offline
ANTHROPIC_API_KEY=... python -m redteam.improve --use-llm --price-in <USD/MTok> --price-out <USD/MTok>
```

1. **Collect misses**: red-team evasion payloads under 50, synthetic phishing the rules miss, and mutated variants of detected phishing (synonyms such as "wire" → "send across", polite wrappers) that slip under 50. `--external` adds misses from the public corpus.
2. **Analyze**: phrases found in at least 2 misses and in no legitimate sample; which feature combinations the misses share; how many are low-text (image-only) lures.
3. **Propose**: `proposals/YYYYMMDD.md` with the evidence and a simulated effect (misses rescued, legitimate samples matched); an optional `.patch` that adds a `soft_bec_phrasing` regex to `phishguard/readonly/features.py`; and a regression-test draft. Nothing is applied. See `proposals/20261103.md`.

With a key, an LLM writes harder attack variants and suggestions. Spending has a hard cap of **$2**: before each call the worst case (input bytes as an upper bound on tokens, plus the full `max_tokens`) is reserved against the cap, actual usage is charged after, and the loop stops if a provider ever bills more than the bound. `--budget` can only lower the cap. Prices are required inputs, so the cap can't be enforced against unknown prices. Without a key, template mutation is used.

**Why it may not edit security code.** A loop that changes the code that decides whether money moves, based on attacker-supplied mail, is itself an attack surface: poison the inputs and the "improvement" weakens the gate. So the rules are in code, not policy: `PROTECTED` lists `phishguard/mutating/` (gateway, policy, TOTP, audit, store), `api.py`, `security.py`, `config.py`, the runner's oracles, `tests/` and the guard itself. `check_patch()` parses every path a diff names (`---/+++`, `diff --git`, renames, binary diffs), normalizes `..`, case and `a/`/`b/` prefixes, and refuses any match, or a diff with no recognizable paths, before anything is written. `tests/test_improve.py` proves it with 17 hostile patch shapes. It also checks that a run leaves every source file byte-identical and that the generated patch passes `git apply --check`. Even for allowed files, the output is a proposal: today's run suggested phrases such as "it's sarah", which come from the synthetic generator's names. That is exactly why a human reviews before anything is merged.
