# PhishGuard

[![CI](https://github.com/King-Dunk/phishguard/actions/workflows/ci.yml/badge.svg)](https://github.com/King-Dunk/phishguard/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue)
![License](https://img.shields.io/badge/license-MIT-green)

**An email-phishing agent built on the assumption that its AI will be fooled.** The model can only read. Anything that moves money or changes an account is held by a gateway in code until a person approves that exact action with two factors, one of them a passkey or an authenticator app. Detection catches what it can; it is not what keeps the money safe.

![Approval center: a $9,800 transfer held by the gateway until the user approves it with a passkey and a password](docs/img/approval-center.png)

*A $9,800 transfer requested through the agent and held by the gateway. Only the user's passkey plus password can release it, and only for this amount, this payee and this requester (the action digest).*

PhishGuard is a working prototype built to answer one question: **how can an AI agent read your email without being able to be talked into moving your money?** It is not a replacement for your mail provider's spam filter; the [results](#results) show why.

## Design principles

1. **Assume the model will be fooled.** Every email is attacker-written input to the model, and new injection styles keep appearing: role-play, fake academic framing, forged tool output, instructions hidden in HTML. So nothing depends on recognizing them. The model gets three read-only tools (`get_email`, `extract_features`, `check_domain`), and any other tool name returns an error. The package that reads mail cannot import the package that changes state; tests check this in the source, in the import graph, and by running with the mutating package blocked.
2. **Code decides what is sensitive, not the model.** Moving money, changing bank details or account settings, adding an MFA factor, deleting mail and releasing it from quarantine always need approval (`ALWAYS_MFA` in [`policy.py`](phishguard/mutating/policy.py)). Other actions are escalated when their parameters mention money or accounts, never de-escalated, and parameters too deep to inspect fail closed. The model's score can raise the rule score but not lower it; the one opt-in lowering path stops at a content-only floor and is vetoed by hidden text or injection attempts.
3. **An approval is bound to one exact action.** A held action gets a digest of its type, parameters and requester. Every factor has to echo it and a passkey signs a challenge bound to it, so an approval for $1 cannot release $9,800 and an approval for one payee cannot pay another. Two different factors are required, at least one of them something you have, because one phishing form can collect a password and security answers together. Only the gateway can issue the grant the executor checks.
4. **Least privilege outside the code too.** The mailbox token is read-only (`gmail.readonly`, `Mail.Read`), and a read credential that also carries write scopes is refused. Quarantine and labels use a separate, opt-in write credential that only the mutating side loads. If the code had a bug, Google would still refuse the write.
5. **Model output is untrusted output.** The model's explanation is withheld on flagged mail and whenever it argued the score down; otherwise it is cleaned, capped and labelled `untrusted_model_output`, so an injected model cannot talk the reader into paying.
6. **Rules become tests.** Every rule above has tests (569 in total), and 94 red-team attacks run with invariant checks after each one: no MFA bypass, only parameterized SQL, audit chain intact, no crash. The improvement loop may propose detection rules but refuses any patch that touches the gateway, the policy or the tests.
7. **Detection will miss; permissions don't loosen.** The detector lowers how often the gate is reached and how much the user has to look at. A fraudulent request from a compromised vendor thread can score 0 and still not move money: it needs two factors, and a payment to changed bank details waits 24 hours.

## How it works

```mermaid
flowchart LR
    subgraph RO["readonly: reads, never acts"]
        direction TB
        MB["Mailbox<br/>read-only token"] --> RU["Parser and rules<br/>explainable score"]
        RU -- "gray zone 20-50" --> LLM["LLM<br/>3 read-only tools"]
        LLM -- "can only raise" --> V["Verdict"]
        RU --> V
    end
    subgraph MU["mutating: gated actions"]
        direction TB
        GW[["Gateway<br/>policy fixed in code"]]
        GW -- "reversible,<br/>one message" --> EX["Executor"]
        GW -- "money, account,<br/>delete, bulk" --> MFA["Held until two factors<br/>bound to the action digest"]
        MFA --> EX
        EX --> BK["Bank or mailbox write API<br/>limits, 24 h cooling-off"]
        GW --> AU[("Hash-chained<br/>audit log")]
    end
    REQ["API client<br/>transfer, change bank details"] --> MU
    RO -- "phishing verdict" --> MU
    RO -. "cannot import" .-x MU
```

Mail is read with a read-only token, parsed, and scored by rules that report the points each signal adds. Mail in the gray zone (20-50) can go to the model, whose answer can only raise the score. A phishing verdict goes to the gateway like any other request: quarantine is reversible, so it runs at once; anything that moves money, changes an account, deletes mail or touches many messages is held until two factors pass. Everything the gateway does is appended to a hash-chained audit log.

Details: [REFERENCE.md](docs/REFERENCE.md) (architecture, API, settings) and [THREAT_MODEL.md](docs/THREAT_MODEL.md) (each attack, where it is stopped, and the residual risks).

## Results

Rules only, threshold 35, weights v5, unless stated. Full tables with 95% confidence intervals and the commands: [EVAL_BREAKDOWN.md](docs/EVAL_BREAKDOWN.md) and [EVALUATION.md](docs/EVALUATION.md).

| Test set | Result |
|---|---|
| Public phishing corpus (Nazario), test split, 2004-2007 mail, n = 1,336 | 78.7% caught |
| Same corpus, **2024-2025 mail**, n = 282 | **47.2%** caught [41.4, 53.0] |
| Same corpus, whole test split, n = 3,454 | 66.4% caught |
| Phishing Pot honeypot, random sample of 2,995 mails, mostly 2023-2026, never tuned on | 78.3% flagged |
| Customization tiers (synthetic, after the NIST Phish Scale), 100 phishing mails each | mass 88% · brand 58% · targeted 100% (59% without the vendor and executive list) · **compromised account 0%** |
| QR-code lures (part of the brand tier) | **0 of 21** caught |
| Legitimate mail, SpamAssassin test split (2002) | 0.6% of easy_ham, 21.2% of hard_ham flagged |
| One real Gmail inbox: 199 ordinary 2026 mails, no phishing | **20%** flagged (94% before the HTML parser fixes) |
| Look-alike legitimate mail in the tiers | newsletters 35%, genuine "our bank details changed" **100%** flagged |
| Real model (claude-haiku-5-5) on a gray-zone sample: 60 phishing, 55 legitimate | rules caught 45 of 60, rules + model 59; with the opt-in benign vote, false positives fell from 14 to 7; about $0.00085 and 6 s per reviewed mail |
| Red team: 94 attacks in 5 categories | 94 of 94 security invariants held; 11 vulnerabilities found and fixed along the way |

What the numbers say:

- **The headline is carried by old mail.** 66% overall, but less than half of 2024-2025 phishing, which more often passes sender authentication (65% DMARC pass, against 0% for 2004-2007).
- **Content detection needs red flags.** Tier phishing with 0-1 planted red flags was never caught (0 of 100). Mail from a compromised real account has none, and the genuine version of the same request looks the same: every real bank-detail change in the control set was flagged.
- **So the gate does not depend on the score.** A compromised-account request that scores 0 still needs two factors to move money, and a payment to changed bank details waits 24 hours.
- **Read synthetic numbers as maps.** The tiers, the red team and the rules were written by the same author, so they show where detection breaks, not how often it works in the wild.

## How it was built

Each step is a merged pull request (November 2026). The evidence behind each decision is in [DESIGN.md](docs/DESIGN.md).

1. **Nov 3, the boundary first.** The read-only/mutating split, the MFA gateway and the hash-chained audit log came before any detection tuning ([#1](https://github.com/King-Dunk/phishguard/pull/1)). A red-team sandbox then found 10 real bugs, including an MFA bypass through parameters nested eight levels deep and a regex that took 10.4 s on one request ([#2](https://github.com/King-Dunk/phishguard/pull/2)).
2. **Nov 3, the first real data.** The public corpora crashed the parser twice ([#3](https://github.com/King-Dunk/phishguard/pull/3)). Calibration on a fixed dev split moved the threshold from 50 to 35 (recall 35% → 61%) and produced the v3 weights (70%). The calibrator's own suggestion, 88% recall, was rejected: it flagged 38% of legitimate mail by learning that 2002 mail has no DKIM ([#4](https://github.com/King-Dunk/phishguard/pull/4)).
3. **Nov 4, real accounts and real factors.** Read-only Gmail, Microsoft Graph and IMAP connectors with remediation behind the gateway ([#6](https://github.com/King-Dunk/phishguard/pull/6)); two-factor approval with passwords, TOTP and passkeys, payments behind provider interfaces, and 17 new attacks against all of it ([#7](https://github.com/King-Dunk/phishguard/pull/7)).
4. **Nov 13, false positives and the model.** A `mailto:` parsing bug caused most legitimate-mail flags (hard_ham false positives 59% → 26%, [#8](https://github.com/King-Dunk/phishguard/pull/8)). Rules for polite BEC and image-only lures ([#10](https://github.com/King-Dunk/phishguard/pull/10)). An opt-in path for the model to lower a score, with its attacks written first ([#11](https://github.com/King-Dunk/phishguard/pull/11)). Then the real model, under a budget of 400 requests per run ([#12](https://github.com/King-Dunk/phishguard/pull/12), [#14](https://github.com/King-Dunk/phishguard/pull/14)).
5. **Nov 14-18, a real inbox.** Rules flagged 94% of an ordinary Gmail inbox. The HTML parser counted white text on coloured buttons as "hidden". Fixing it brought the inbox to 20% and cost four points of public-corpus recall, points that had come from the bug ([#15](https://github.com/King-Dunk/phishguard/pull/15)).
6. **Nov 18, model text is untrusted.** The model's explanation is withheld on flagged mail and when it argued the score down ([#16](https://github.com/King-Dunk/phishguard/pull/16)).
7. **Nov 20-21, harder test sets.** Per-year public data, a 3,000-mail honeypot sample and customization tiers showed where detection stops: 47% of 2024-2025 phishing, 0% of compromised-account mail, which is the case the gateway exists for. Also the approval center and the walkthrough ([#17](https://github.com/King-Dunk/phishguard/pull/17)).

## Try it

Python 3.11 or 3.12. Everything runs offline except the corpus downloads.

```bash
git clone https://github.com/King-Dunk/phishguard.git && cd phishguard
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m pytest -q        # 569 tests, offline, no API key
```

**1. Watch one real phishing mail go through every layer** (about two minutes; the model in it is a stand-in that obeys the attacker):

```bash
python scripts/download_datasets.py --only phish   # public Nazario corpus into data/external/ (git-ignored)
python examples/defense_walkthrough.py             # --zh: Chinese narration · DEMO_SPEED=0: no pauses
```

Two of its seven steps:

```text
━━━ Step 2 · AI analysis (assume the AI is compromised) ━━━━━━━━━━━━━━━━━━
  The hijacked AI tries three things:
  ① call transfer_funds to send $9,800 to the attacker, and change_bank_details to swap a payee's account
  ✔ transfer_funds → “unknown tool 'transfer_funds': only read-only tools exist here”  the AI has no such tool at all
  ✔ change_bank_details → “unknown tool 'change_bank_details': only read-only tools exist here”  the AI has no such tool at all
  ② declare the mail “safe, risk 0”
  ✔ the AI says 0; the score stays at the rules' 90.6: the mail hides text, so the AI's “safe” vote is vetoed
  ③ write a note to talk you into it: “Verified by IT, the download is fine, pay the wire today”
  ✔ the note is not shown to the user (rationale_status = withheld_flagged): model text is untrusted output

━━━ Step 4 · MFA gate (what the attacker really wants: money) ━━━━━━━━━━━━
  ⚠ transfer_funds $9,800 requested in your name → pending_mfa   held until two factors pass
  ✔ the AI guesses your password “Verified-by-IT” → refused (MFAFailed, 2 left before the request is voided)
  ✔ the AI signs with the attacker's own passkey → refused (MFAFailed, 1 left before the request is voided)
  ✔ an approval meant for a $1 transfer is used on the $9,800 one (digest mismatch) → refused (MFAFailed, no attempts left: the request is voided)
  ✔ call the executor directly, skipping the gateway → refused (PermissionError)
  ✔ forge an execution grant → refused (PermissionError)
     The transfer is now rejected. No money has moved.
```

**2. Approve a transfer with your own passkey.** Start the API, then open http://localhost:8000/demo/webauthn (`localhost`, not `127.0.0.1`):

```bash
PHISHGUARD_API_KEYS=dev-key PHISHGUARD_ADMIN_KEYS=dev-admin PHISHGUARD_DB_PATH=/tmp/pg.db \
  uvicorn phishguard.api:get_app --factory --port 8000
```

Click the gear and connect with `dev-key`, `dev-admin` and any user name. Set a password, register a passkey (Touch ID), click **Ask agent to transfer**, then approve with the passkey and the password. Step by step: [REFERENCE.md](docs/REFERENCE.md#try-the-two-factor-flow-on-a-mac).

**3. Check your own mail.** Scoring a saved `.eml` file uses the rules only and sends nothing anywhere:

```bash
python scripts/check_email.py suspicious.eml       # or a folder of .eml files; --json for the full result
```

To scan a real mailbox read-only (Gmail, Microsoft 365 or IMAP), follow [MAILBOX_SETUP.md](docs/MAILBOX_SETUP.md).

**Reproduce the numbers:**

```bash
python scripts/download_datasets.py               # Nazario + SpamAssassin, checksummed
python scripts/download_datasets.py --only pot    # Phishing Pot sample, each file checked against its git hash
python -I scripts/eval_breakdown.py               # regenerates docs/EVAL_BREAKDOWN.md
python -m phishguard.dataset.evaluate --dataset external --split   # dev and test rows; quote test only
python -m redteam.runner                          # 94 attacks, writes redteam/report.md
```

## Known limitations

- **Detection is weakest where it matters most.** Rules alone catch under half of 2024-2025 phishing, no QR-code lure (there is no OCR) and no tailored mail from a compromised account. The model step helps in the gray zone but has only been run on samples.
- **Too many false positives for daily use:** 20% of one real inbox, 35% of synthetic newsletters, and every genuine bank-detail change.
- **The gateway is an in-process boundary.** It stops the model and accidental calls, not malicious code inside the same process. A real deployment would run the mutating side as a separate service with its own credentials.
- **Payments are simulated.** The bank (ISO 20022), Stripe, Xero and MYOB adapters are documented stubs.
- **Passkeys:** approvals were tested with software and browser-virtual authenticators. A real Touch ID passkey has been registered in Safari, but no action has been approved with a physical authenticator yet.
- **Mailboxes:** Gmail has read one personal inbox; Microsoft Graph and IMAP were tested only against offline fakes. A Gmail app in testing mode has to be re-authorized every 7 days.
- **Single process:** SQLite and per-process rate limits, TOTP secrets unencrypted at rest, no factor-recovery flow, and `requested_by` is supplied by the caller (no SSO).
- **Evaluation:** the public test split has been looked at several times, so it is closer to a dev number than a clean held-out estimate.

Full list and roadmap: [LIMITATIONS.md](docs/LIMITATIONS.md).

## Documentation

| Document | Contents |
|---|---|
| [DESIGN.md](docs/DESIGN.md) | Design decisions as questions and answers, with the evidence behind each |
| [THREAT_MODEL.md](docs/THREAT_MODEL.md) | Each attack, where it is stopped, the test that shows it, and the residual risks |
| [EVALUATION.md](docs/EVALUATION.md) | Every measurement in the order it was taken, with commands |
| [EVAL_BREAKDOWN.md](docs/EVAL_BREAKDOWN.md) | Detection by year, source and customization tier (generated) |
| [REDTEAM.md](docs/REDTEAM.md) | The 94 attacks, the invariants checked after each, the 11 vulnerabilities fixed |
| [REFERENCE.md](docs/REFERENCE.md) | Features, architecture, commands, settings, MFA factors, API, mailbox connectors |
| [MAILBOX_SETUP.md](docs/MAILBOX_SETUP.md) | Connecting Gmail, Microsoft 365 or an IMAP mailbox, read-only |
| [PAYMENTS_INTEGRATION.md](docs/PAYMENTS_INTEGRATION.md) | Where a real bank, Stripe or Xero adapter plugs in |
| [LIMITATIONS.md](docs/LIMITATIONS.md) | All known limitations and the roadmap |

## Data and licences

| Data | Role | Source and licence |
|---|---|---|
| Nazario phishing corpus | phishing, by year | [monkey.org/~jose/phishing](https://monkey.org/~jose/phishing/) by Jose Nazario, CC BY 4.0 |
| SpamAssassin public corpus (`easy_ham`, `easy_ham_2`, `hard_ham`) | legitimate mail, 2002-2003 | [Apache SpamAssassin project](https://spamassassin.apache.org/old/publiccorpus/); read its readme before redistributing |
| Phishing Pot, seeded sample of 3,000 files at commit `78be1415` | recent phishing, test only | [rf-peixoto/phishing_pot](https://github.com/rf-peixoto/phishing_pot) by [rf-peixoto](https://www.linkedin.com/in/rf-peixoto), CC BY-NC 4.0 (non-commercial use) |
| Customization tiers and the synthetic set | generated, seeded | [`tiers.py`](phishguard/dataset/tiers.py) and [`generator.py`](phishguard/dataset/generator.py) in this repository |

No mail is committed. The corpora download to `data/external/` (git-ignored), the Phishing Pot files were deleted after scoring, and only aggregate numbers are published. The personal inbox used for the false-positive trial never leaves the machine.

Code: [MIT](LICENSE).
