# Known limitations and roadmap

## Known limitations

- The execution grant is an in-process guard. It stops the LLM and accidental calls, not malicious code in the same process. A real boundary needs the mutating side as a separate service with its own credentials.
- TOTP secrets are stored unencrypted in SQLite; production needs envelope encryption (KMS) or an HSM. Enrollment needs an admin key (or a token from an approved `add_mfa_factor`) but is not yet tied to SSO identity. There are no reset/recovery flows for lost factors yet; an administrator has to edit the store.
- WebAuthn was tested with a software authenticator (`redteam/virtual_authenticator.py`, real ES256/CBOR verified by py_webauthn) and with Chromium's virtual authenticator driving `/demo/webauthn`. A passkey was registered once with a real Touch ID in Safari on macOS (manual, 2026-11-20), but **no action has been approved with a physical authenticator yet**. Registration uses `attestation: none`, so the server doesn't check which authenticator model was used; the RP ID defaults to `localhost` (demo only).
- Security questions are a weak factor however they are stored; they are offered for compatibility and can never release an action alone or together with the password under the default policy.
- The gateway verifies factors under one process-wide lock (argon2 takes ~20 ms), which serializes approvals; fine for a single instance, not for high volume.
- Payments are simulated (`SimulatedBank`); the ISO 20022, Stripe, Xero, MYOB and identity-provider adapters are documented stubs with no network calls, never tested against a real provider.
- API keys are shared service keys, not per-user identity; `requested_by` is still caller-supplied.
- Rate limits and the SQLite store are per process. Multiple workers or hosts need Redis/Postgres.
- Detection is rule-based with partly hand-set, partly calibrated weights. On the public corpora (test split, weights v5, threshold 35, 2026-11-14) recall is 66.4% (2293/3454) with easy_ham FPR 0.6% (7/1156) and hard_ham FPR 21.2% (14/66): a third of phishing mails are missed by rules alone. On one real 2026 inbox (199 ordinary mails, no phishing) rules alone still flag 40 (20%), most in the 35-50 band that hybrid mode sends to the model. The breakdown in [EVAL_BREAKDOWN.md](EVAL_BREAKDOWN.md) shows where it fails: 47.2% recall on 2024-2025 public phishing, 0 of 21 QR-code lures, none of the tailored mail sent from a compromised account (T4), and every genuine bank-detail change flagged. Open work on this is listed under Roadmap.
- Polite BEC and image-only lures are covered by rules that have **no real BEC data behind them**: the public corpora hold almost none, so recall on real BEC and the false-positive rate on modern mail are unmeasured. Known misses: a polite payee-detail change from an unknown company domain (risk 30), a first-contact probe with no ask, and any lure whose text is inside an image (there is no OCR; only "picture and almost no text" is detected). `requested_by` is self-asserted, so an attacker with a client key can trigger a victim's operation lockout (availability, not a bypass).
- No real mail, banking or MFA push integrations; money moves only inside the simulated bank. Gmail scanning has been run read-only against one personal mailbox; nothing has acted on a live mailbox.
- **Graph and IMAP connectors were tested only against offline fakes**, written from the providers' public documentation; the Gmail connector has read one real personal mailbox (200 messages, incremental paging and a few rate-limit retries observed), but Microsoft 365, Outlook.com and IMAP accounts have not been tried, so error codes, paging edge cases and provider quirks (consent screens, NetEase/QQ behavior, Graph moves with immutable IDs) are unverified.
- Gmail OAuth apps in "Testing" status get refresh tokens that expire after 7 days, and `gmail.readonly` is a restricted scope (Google verification is needed to publish). Personal use means re-authorizing weekly; Workspace "Internal" apps or a service account avoid this.
- IMAP has no read-only credential: an app password can do anything. Read-only scanning is enforced in code (`EXAMINE`, `BODY.PEEK[]`, tests), not by the provider.
- Graph cannot rewrite a received message, so warning banners there are unsupported (use an Exchange transport rule). IMAP "release from quarantine" isn't implemented. Without UIDPLUS, IMAP moves leave the original flagged `\Deleted` rather than risk a plain `EXPUNGE`.
- The checkpoint store and polling worker are single-process; one worker per mailbox.
- Held mailbox actions (delete, release, bulk) need two factors, but only the process that created them can approve them: the API loads pending actions from SQLite at startup and has no remediation credentials, and `mailbox_guard` has no approval interface yet. Until a shared approval service exists they expire unless approved programmatically.

## Roadmap

**Still open, and not doable without real accounts, hardware or providers:**

- Mailbox connectors against real Microsoft 365 / Outlook.com and IMAP accounts (so far only offline fakes; Gmail has read one real inbox).
- Passkeys on physical authenticators (Touch ID, Windows Hello, a FIDO2 key); so far a software authenticator, Chromium's virtual one, and one Touch ID registration with no approval yet.
- A real payment adapter (bank ISO 20022 sandbox, Stripe test mode, Xero); so far `SimulatedBank` and documented stubs.
- KMS / envelope encryption for TOTP secrets (stored unencrypted in SQLite today).

**Further out:**

- Run the mutating side as a separate service with mTLS and its own credentials.
- Shared store (Postgres/Redis) for multi-instance deployments; KMS-encrypted TOTP secrets and password hashes with a pepper; per-action locks instead of one gateway lock.
- Test passkeys on real devices (Touch ID, Windows Hello, a FIDO2 key) and add attestation checks for managed devices; factor recovery and admin reset flows with their own audit trail.
- Implement one real payment adapter against a provider sandbox (Stripe test mode or a bank's ISO 20022 sandbox), with Confirmation-of-Payee style name checks on bank-detail changes.
- Bind approvers to SSO identity, and require a *different* person to approve payments above a threshold (dual control).
- **Hybrid on real mail.** Done twice on a sample ([EVALUATION.md](EVALUATION.md#hybrid-on-real-mail-real-model-sampled)): with v3, raise-only hybrid recovered 13 of 13 missed phishing mails among 60 reviewed and the benign vote took hard_ham FPR from 59.1% to 53.0%; with v4, 14 of 15 were recovered and hard_ham FPR went from 25.8% to 18.2% on the test split. Next: run the full gray zone of the test split (1,329 mails under v4 at ~3 model requests each) to get whole-split recall and easy_ham FPR for hybrid; cut requests per mail (the agent spends two tool calls before answering); and decide on the floor only after measuring both the gain and the injected-model bound for any wider variant.
- Calibrate on a modern legitimate-mail corpus, so era artifacts stop mattering.
- Detection for what the breakdown shows is missed: QR codes and text inside images (OCR), and thread hijacking from compromised accounts, where only out-of-band checks (calling the vendor back on a known number) help.
- Mailbox connectors: run against real Gmail, Microsoft 365, Outlook.com and a few IMAP providers (iCloud, Fastmail, QQ, 163) and fix whatever the fakes got wrong; add certificate credentials for Graph app-only auth; a shared checkpoint store for several workers; per-mailbox rate budgets for large tenants.
