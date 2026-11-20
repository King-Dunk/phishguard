# Evaluation

Every measurement taken during the project, in the order the work was done, with the command that produced it. The per-year, per-source and per-customization-tier breakdown (2026-11-20) is in [EVAL_BREAKDOWN.md](EVAL_BREAKDOWN.md); the raw per-mail scores of the real-model runs are in `hybrid_real_run_*.json`. Older sections quote older weights; each says which.

## Synthetic set

```bash
python -m phishguard.dataset.evaluate --n 200 --seed 42 --sweep                  # rules only (what CI runs)
ANTHROPIC_API_KEY=... python -m phishguard.dataset.evaluate --n 200 --modes rules,llm,hybrid \
    --price-in <USD/MTok> --price-out <USD/MTok>
```

Measured on this branch with `python -m phishguard.dataset.evaluate --n 200 --seed 42` (600 synthetic mails, 200 per category, threshold 35, weights v4; the number is unchanged from v3):

| Mode | Accuracy | Precision | Recall | F1 | Avg latency | LLM call rate | Cost / 1k emails |
|---|---|---|---|---|---|---|---|
| rules | 96.7% | 100.0% | 93.4% | 96.6% | ~0.16 ms | 0% | $0 |
| llm | not run on the synthetic set | | | | | 100% | |
| hybrid | not run on the synthetic set; measured with the real model on a real-mail sample instead, see "Hybrid on real mail" | | | | | | |

Confusion for rules: TP 281, FP 0, TN 299, FN 20 (BEC recall 90.0%, payment chasing 100%). Latency depends on the machine. Besides the table, `evaluate.py` reports recall at a fixed 1% and 5% false-positive rate (`--fpr-ref easy_ham` to measure FPR on one category) and, with `--sweep`, every threshold from 30 to 60 in steps of 5.

**Why hybrid (the money argument).** Most mail is clear-cut: internal notes score near 0, a punycode sender with a failed DMARC scores near 100. Paying an LLM to confirm either is waste. Hybrid runs the free rules first and calls the LLM only when the rule score lands in the gray zone (20-50 by default, `--gray-low/--gray-high`; centered on the default threshold of 35). Cost scales with the gray-zone share instead of with total volume, and the "LLM call rate" column shows that share directly. On this synthetic set 41 of 600 mails (6.8%) fall in 20-50; 9 of the 13 rule misses (scores 22 and 31) are inside it, the other 4 score 15. The real share on real mail must be measured. By default the LLM can only *raise* a score (anti-injection floor), so hybrid can recover gray-zone misses but cannot remove false positives. An opt-in, restricted lowering path exists (`--llm-may-lower`, see "LLM benign vote" below).

**Read this carefully:** the dataset is synthetic, and the rules and the generator were written by the same author, so they share assumptions. Treat these numbers as a regression baseline. The 10 hand-written `.eml` files in `tests/fixtures/` check each new signal, not accuracy. Real validation needs labeled real mail.

## Public dataset evaluation

```bash
python scripts/download_datasets.py                       # fetch + verify + extract into data/external/ (git-ignored)
python -m phishguard.dataset.evaluate --dataset both      # synthetic vs real, side by side
python -m phishguard.dataset.evaluate --dataset external --limit 2000 --json
```

| Corpus | Role | Source | Terms |
|---|---|---|---|
| SpamAssassin public corpus `easy_ham`, `easy_ham_2`, `hard_ham` (2003) | legitimate | https://spamassassin.apache.org/old/publiccorpus/ | Published by the Apache SpamAssassin project for testing filters. Read the corpus readme before redistributing. |
| Nazario phishing corpus (mbox files) | phishing | https://monkey.org/~jose/phishing/ | CC BY 4.0, by Jose Nazario. |
| Phishing Pot (seeded sample of 3,000 `.eml` files, `--only pot`) | phishing, test only | https://github.com/rf-peixoto/phishing_pot (commit `78be1415`) | CC BY-NC 4.0, by rf-peixoto: non-commercial use, attribution. |

Redistribution terms are set by each publisher (check the source pages), so raw mail is **never committed**: `data/external/` is in `.gitignore` and `.dockerignore`. Phishing Pot files are checked against the git blob hashes of a pinned commit. The other two projects publish no checksums, so for them the script uses trust-on-first-use: it records each file's SHA-256 in `data/external/checksums.json` and refuses a changed file later (`--expect-sha256 NAME=HEX` pins a known hash). Archives are extracted by `safe_extract()`, which rejects absolute paths, `..`, links and size bombs (the red team tests this too). Messages go through the same `.eml` parser as the API; ones it refuses (e.g. MIME bombs) are counted as skipped and reported, not dropped silently. The output is a P/R/F1 table plus a per-category confusion matrix (`easy_ham`, `hard_ham`, `nazario_phish`).

The download needs network access to both hosts; the cloud environment this repo is built in blocks them, so real-corpus runs happen locally. The pipeline is tested offline with a mocked download and a small fake corpus (`tests/test_external_dataset.py`, `tests/test_calibration.py`).

### Dev/test protocol (anti-overfitting)

`--split` divides the external data 70/30 into **dev** and **test** by a salted hash of each message's content, so the split is identical on every machine and duplicates can't sit on both sides. All tuning happens on dev: `scripts/error_analysis.py` (aggregate statistics only, safe to commit) and `scripts/calibrate.py` (grid search with an L1 pull toward the hand-set weights, an inner held-out slice, frozen security features, and output to a *suggestion* file that never overwrites `weights.yaml`). **This README reports only test-split numbers**, measured once after the weights are frozen.

```bash
python scripts/download_datasets.py
python -m phishguard.dataset.evaluate --dataset external --split                 # dev and test rows; quote test only
python scripts/error_analysis.py --split dev --out dev_error_analysis.md            # aggregates, no content
python scripts/calibrate.py --out weights.suggested.yaml                           # dev only; recall s.t. easy_ham FPR <= 1%
python -m phishguard.dataset.evaluate --dataset external --split --sweep --fpr-ref easy_ham \
    --weights weights.suggested.yaml --threshold <suggested threshold>
```

### Real data results

**Source:** the maintainer's local run of `python -m phishguard.dataset.evaluate --dataset external --split` on the public corpora, test split (30%, fixed salted content-hash split; the same split on every machine). Rules mode. Not reproducible in the cloud build environment (no network access to the corpora). Numbers below are copied from that run, nothing else.

| Real corpus, **test split** | Recall | Precision | FPR easy_ham | FPR hard_ham |
|---|---|---|---|---|
| `weights.yaml` v2, threshold 50 | 35.0% | 98.7% | 0.2% | 21.2% |
| `weights.yaml` v2, threshold 35 | 60.8% | 97.5% | 1.4% | 56.1% |
| `weights.yaml` v3 (FPR-constrained calibration), threshold 35 | 69.6% | 98.0% | 0.9% | 59.1% |
| **`weights.yaml` v4 (false-positive round), threshold 35 (default)** | **70.4%** | **98.9%** | **0.8%** | **25.8%** |
| `calibrate.py` suggestion (old F1 objective, rejected) | 88.4% | 86.0% | 38.2% | 83.3% |
| *Reference: v1 rules, threshold 50, whole corpus (not a held-out split)* | *60.0%* | *87.7%* | *22.7%* | *34.4%* |

**v4** (test split, measured once after the weights were frozen): recall 70.4% (2435/3460), precision 98.9%, easy_ham FPR 0.8% (9/1156), hard_ham FPR 25.8% (17/66, was 39/66). Recall at 1% easy_ham FPR 70.4% (v3: 69.6%), at 5% 76.8% (v3: 77.2%, a small loss). Synthetic F1 95.9% (unchanged). The hard_ham test set is small (66 mails), so ±6 points is within noise. Most of the gain is a bug fix: `mailto:` links were parsed as web URLs with the address in the host part, so every mailto link fired `link_at_obfuscation` (41% of dev hard_ham). The other changes split keyword features by context and give a lower key to a link-text mismatch whose real target is the sender's own domain. The evidence is in DESIGN Q63-Q68, from the dev split only.

**v4 merged with the polite-BEC and image-lure rules** (re-measured 2026-11-13 on this branch after merging `main`, same command): test split recall 70.6% (2444/3460), precision 99.0%, easy_ham FPR 0.8% (9/1156), hard_ham FPR 25.8% (17/66); dev split recall 70.8% (5741/8111), precision 98.8%, easy_ham FPR 0.8% (23/2744), hard_ham FPR 26.1% (48/184). Before v4 (`main` with v3 weights and the same new rules): test recall 69.9%, easy_ham FPR 0.9%, hard_ham FPR 59.1%. The real-model sample in "Hybrid on real mail" was first run with v3 weights and repeated with v4 on 2026-11-14.

**v3** is the output of the FPR-constrained `calibrate.py` (dev split only, `no_authentication`/`off_hours_send` frozen), checked once on the test split: +8.8 points of recall over v2 with *lower* easy_ham FPR (0.9% vs 1.4%). The calibrator raised `reply_to_mismatch` and `return_path_mismatch` (non-list mail), `link_shortener`, `archive_attachment` and `image_lure`. hard_ham remained the weak spot (59.1%), which v4 addresses.

Compared with v1 (threshold 50), v2 at threshold 35 keeps the same recall (60.8% vs 60.0%) while easy_ham false positives fall from 22.7% to 1.4%. hard_ham (legitimate, marketing-like mail) got worse at 35 (56.1% vs 34.4%). The v1 row comes from a different evaluation set (whole corpus), so treat that comparison as indicative only. This round added `urgency_language_trusted_sender`/`payment_keywords_trusted_sender` damping. It only applies when trusted domains are configured, so it is inert on the public corpora, and the v2 numbers above still describe this version.

**Trade-off: compromised internal mailboxes.** When trusted domains are configured, keyword-only signals (urgency, payment words) are damped for authenticated mail from those domains, which cut false positives on legitimate supplier invoice reminders. The cost: 13 of 200 synthetic BEC mails sent from a *compromised internal mailbox* (authenticated, trusted domain) are no longer flagged. This is deliberate defense in depth: detection is tuned for a usable false-positive rate, and the payment itself still cannot happen without the hard-coded MFA gateway, which does not depend on the detection score.

**Why the default threshold is 35.** At 50, v2 is very precise (98.7%) but misses 65% of phishing. At 35, recall rises by 25.8 points for +1.2 points of easy_ham FPR and -1.2 points of precision. The price is hard_ham: more than half of marketing-like legitimate mail is flagged. For a phishing filter a missed phish (credential theft, payment fraud) costs far more than a newsletter in quarantine, so 35 is the default. The 20-50 band, where hard_ham and missed phishing overlap, is exactly what the planned hybrid step hands to an LLM (Roadmap). Deployments with a lot of bulk mail and no hybrid step can set `PHISHGUARD_THRESHOLD=50`.

**Why the calibration suggestion was rejected.** It raised recall to 88.4% by flagging 38.2% of easy_ham and 83.3% of hard_ham, which is unusable. Two causes: it raised `no_authentication` to 0.45, learning the dataset's era (2002 legitimate mail predates DKIM) instead of anything about phishing; and it optimized F1, which on a test set of about 3 phishing per legitimate mail rewards flagging everything. `calibrate.py` now maximizes recall subject to easy_ham FPR <= 1% (or a class-balanced metric), freezes era/time-zone features by default, and prints a suggested threshold. See "Evaluation pitfalls".

### LLM benign vote (opt-in, injection-resistant lowering)

`PHISHGUARD_LLM_MAY_LOWER=1` (API) or `--llm-may-lower` (`evaluate.py`) lets an LLM answer below the rule score count, under four rules that live in code (`agent.lowered_risk`), not in the prompt:

1. **Band.** Only when the rule score is between 20 and 50. Outside it the rules win.
2. **Band edge.** The result is never below 20.
3. **Content-only floor.** The result is never below the rule score of everything except routing and time context. The only signals a vote can discount are an allowlist: `reply_to_mismatch` (not the free-mail case), `reply_to_mismatch_list`, `return_path_mismatch`, `no_authentication`, `off_hours_send`, `moderate_reputation`, `young_domain`. Wording, links, attachments, identity and authentication failures, and any feature added later, stay.
4. **Veto.** No lowering at all when the mail hides text, obfuscates keywords or addresses the model (`hidden_html_text`, `obfuscated_text`, `prompt_injection_attempt`).

It is **off by default**. The API response reports `rule_risk`, `llm_risk`, `content_floor` and `lowered_by_llm` for audit. The model's free-text `rationale` is treated as untrusted output: it is withheld on flagged mail and whenever the model argued the score down (`rationale_status` says why), and otherwise cleaned, capped at 300 characters and labelled `rationale_trust: untrusted_model_output`, so an injected model cannot use it to talk the reader into paying.

The red-team attacks were written first (`redteam/payloads/benign_vote.yaml`, 9 mails that try to talk the model into "safe", run against a model that answers risk 0 to everything). A new `llm_floor` security invariant is recomputed by the runner from each response, for every attack in every category. Against a naive version that just accepts the model's lower score, the same run reports 38 security breaches in 85 attacks; against this implementation, none. One payload documents the accepted limit: a mail flagged *only* by routing context (risk 35) is lowered to 20 by a compromised model.

What a fully injected model could do, and the most a perfect model could gain, measured on the real corpus with stand-in models (no API calls; rules mode vs hybrid with a model that answers "risk 0" to every gray-zone mail; threshold 35):

| Real corpus split | Mode | Recall | FPR easy_ham | FPR hard_ham | Gray-zone mails | Lowered |
|---|---|---|---|---|---|---|
| **test** | rules | 69.6% (2407/3460) | 0.9% (11/1156) | 59.1% (39/66) | | |
| **test** | hybrid, always-"safe" model, lowering off (default) | 69.6% (2407/3460) | 0.9% (11/1156) | 59.1% (39/66) | 1349 | 0 |
| **test** | hybrid, always-"safe" model, lowering **on** | 63.0% (2181/3460) | 0.8% (9/1156) | 53.0% (35/66) | 1349 | 1182 |
| dev | rules | 69.1% (5604/8111) | 0.9% (24/2744) | 59.2% (109/184) | | |
| dev | hybrid, always-"safe" model, lowering **on** | 63.1% (5121/8111) | 0.7% (20/2744) | 55.4% (102/184) | 3113 | 2742 |

Two things follow. The worst case is bounded but not small: an attacker who fully controls the model's answer on every mail takes 6.5 points of recall on the test split (226 phishing mails that were flagged mainly by routing context). And the best case is modest: even a model that correctly calls every legitimate mail benign can clear at most 4 of the 39 flagged hard_ham test mails (59.1% to 53.0%), because most hard_ham false positives on these weights come from content signals, which the floor protects. That is why the switch is off by default. Those rows use stand-in models; the real model is next.

### Hybrid on real mail (real model, sampled)

**What was run (2026-11-13):** `python -m phishguard.dataset.evaluate --dataset external --split --split-part test --modes rules,hybrid --llm-may-lower --llm-sample "hard_ham=31,easy_ham=30,nazario_phish=60" --max-llm-api-calls 390 --fpr-ref easy_ham --price-in 0.10 --price-out 0.50`, model `claude-haiku-5-5`, weights v3, threshold 35, gray zone 20-50. Raw per-mail scores (no content) are in `docs/hybrid_real_run_20261113.json`.

**This is a sample, not the whole split.** The run had a hard budget of 400 model requests, and one mail takes about three (two tool calls, then the answer). The test split has 1,349 gray-zone mails (74 easy_ham, 31 hard_ham, 1,244 phishing). The model saw 121 of them, chosen by content hash before any model call: **all 31** hard_ham, 30 of 74 easy_ham, 60 of 1,244 phishing. 365 requests were used, plus 6 in a two-mail smoke test: 371 in total.

On the 121 mails the model reviewed (same mails under each scoring, threshold 35):

| Category (reviewed) | Scoring | Flagged | Not flagged |
|---|---|---|---|
| nazario_phish (60) | rules | 47 | 13 missed |
| nazario_phish (60) | hybrid, raise only (default) | 60 | 0 missed |
| nazario_phish (60) | hybrid with benign vote | 60 | 0 missed |
| hard_ham (31) | rules | 24 false positives | 7 |
| hard_ham (31) | hybrid, raise only (default) | 24 false positives | 7 |
| hard_ham (31) | hybrid with benign vote | 20 false positives | 11 |
| easy_ham (30) | rules | 5 false positives | 25 |
| easy_ham (30) | hybrid, raise only (default) | 5 false positives | 25 |
| easy_ham (30) | hybrid with benign vote | 3 false positives | 27 |

| Measured on the 121 reviewed mails | Value |
|---|---|
| Recall on reviewed phishing | rules 78.3% (47/60), hybrid 100% (60/60) |
| Precision on reviewed mails | rules 61.8% (47/76), hybrid raise-only 67.4% (60/89), hybrid with benign vote 72.3% (60/83) |
| Model's own score, where it gave one (119 mails) | 58 of 59 phishing at or above 35; 0 of 60 legitimate at or above 35 |
| No parseable answer / circuit breaker | 2 mails / 1 mail (rule score kept) |
| Scores lowered / raised by the model | 57 / 59 (most lowered scores were already under 35 or stayed above it) |
| Model requests per mail | 3.02 |
| Latency per reviewed mail | mean 6.27 s, median 5.94 s, max 14.37 s (rules alone: 0.81 ms per mail in the same run) |
| Tokens | 568,885 input, 95,934 output |
| Cost | $0.1049 for 121 mails ($0.00087 per reviewed mail), from the API's reported token usage at the list price of $0.10 / $0.50 per million tokens. Smoke test: $0.0020. Not taken from a billing statement. |

Whole test split (4,682 mails), where hybrid means "the model reviewed only the 121 sampled gray-zone mails":

| Real corpus, **test split** | Recall | Precision | FPR easy_ham | FPR hard_ham |
|---|---|---|---|---|
| rules | 69.6% (2407/3460) | 98.0% | 0.9% (11/1156) | 59.1% (39/66) |
| hybrid with benign vote, **sampled** | 69.9% (2420/3460) | 98.2% | 0.8% (9/1156) | 53.0% (35/66) |

Only the hard_ham figure in that last row is complete, because every gray-zone hard_ham mail was reviewed. Recall and easy_ham FPR are understated: 1,184 gray-zone phishing mails and 44 gray-zone easy_ham mails were never shown to the model and kept their rule score. Nothing here is extrapolated to them.

What it says:

- **Raise-only hybrid works on the sample.** All 13 missed phishing mails among the 60 reviewed were recovered, with no new false positive.
- **The model separated the classes almost perfectly on these 119 answered mails** (one phishing mail scored under 35, no legitimate mail scored 35 or more). That is a small sample from one corpus, and hard_ham is 31 mails.
- **The benign vote cleared few false positives, and the floor is why.** The model voted benign on every legitimate mail it answered for, but only 6 of the 29 flagged ones could be lowered (hard_ham 24 to 20, easy_ham 5 to 3). Of the other 23, 22 were held by the content-only floor or a veto and one got no parseable answer. The one phishing mail the model scored under 35 was also held, by the same rule. hard_ham FPR on the test split goes from 59.1% to 53.0%, exactly the ceiling the stand-in run predicted.
- **Cost and latency.** About $0.00087 and 6 seconds per reviewed mail. 28.8% of the test split (1,349 of 4,682) falls in the gray zone; a real inbox has a different mix.
- The floor that blocks 22 correct benign votes is the same floor that bounds an injected model at 6.5 points of recall. Loosening it is a trade, not a fix, and needs the same two measurements first.

#### Repeated with weights v4 (2026-11-14)

Same command, same sample sizes and cap, on `main` with weights v4 and the polite-BEC/image rules. Raw scores: `docs/hybrid_real_run_20261114_v4.json`. v4 moves fewer legitimate mails into the gray zone, so the model reviewed 115 mails: 30 easy_ham, **all 25** gray-zone hard_ham, 60 of the gray-zone phishing. 345 model requests (3.0 per mail), no API errors, one mail with no parseable answer, no circuit breaks.

| On the 115 reviewed mails | rules | hybrid, raise only | hybrid with benign vote | model's own score |
|---|---|---|---|---|
| Phishing caught (of 60) | 45 | 59 | 59 | 58 |
| hard_ham false positives (of 25) | 10 | 10 | 5 | 0 |
| easy_ham false positives (of 30) | 4 | 4 | 2 | 0 |

| Real corpus, **test split** (4,682 mails), v4 | Recall | Precision | FPR easy_ham | FPR hard_ham |
|---|---|---|---|---|
| rules | 70.7% (2445/3460) | 98.9% | 0.8% (9/1156) | 25.8% (17/66) |
| hybrid with benign vote, **sampled** | 71.1% (2459/3460) | 99.2% | 0.6% (7/1156) | 18.2% (12/66) |

- As before, only the hard_ham figure is complete (every gray-zone hard_ham mail was reviewed); recall and easy_ham FPR are understated, because 1,214 gray-zone mails were not sampled.
- With v4, the benign vote halved the reviewed hard_ham false positives (10 → 5). Under v3 it cleared 4 of 24: v4 removed the content signals that used to hold the floor up on marketing mail.
- Cost $0.0979 for 115 mails ($0.00085 each) at $0.10 / $0.50 per million tokens (538,862 input, 87,976 output tokens, from the API's reported usage, not a bill). Latency per reviewed mail: mean 6.06 s, median 5.80 s, max 13.76 s.
- The rules row says 2445 caught; a rules-only run of the same split earlier the same day counted 2444. One mail, not investigated (the same one-mail drift was seen on the v4 branch before).
- The test split has now been looked at several times during this work, so by the rule below these numbers are closer to dev numbers than to a clean held-out estimate.

### Real mailbox results (one personal Gmail inbox)

**What was run (2026-11-14):** `scripts/scan_mailbox.py --provider gmail` with a read-only (`gmail.readonly`) token on the maintainer's own inbox, rules only (`PHISHGUARD_LLM_MODE=mock`, nothing sent to a model), threshold 35. The 200 most recent inbox messages were downloaded and kept locally (one was refused by the parser, 199 scored). They were newsletters and promotions, job alerts, university course notices, receipts and service notifications; none was a phishing mail, so every flag is a false positive.

| Code | Flagged at 35 (of 199) | Median risk |
|---|---|---|
| `main` before this change (weights v4) | 188 (94%) | 40.2 |
| after the fixes below, recipient zone `Australia/Brisbane` | 40 (20%) | 10.0 |

What the 2002-era public corpus could not show, and what changed (DESIGN Q80-Q84):

- **The HTML parser called most of a modern email "hidden".** 185 of 199 mails had over 20 characters of "hidden" text (median about 1,070). Causes: white text on a coloured button or banner (`color:#fff` was treated as invisible regardless of background; 141 mails), `font-size:0` layout wrappers whose children set a real size (43), `visibility:hidden` undone by children (29), and the inbox preview line ("preheader", `display:none`, 106). Visibility now follows CSS inheritance: `display:none`, `opacity:0`, `hidden` and `max-height:0`+`overflow:hidden` hide a subtree for good; `visibility`, `font-size` and `color` can be reset by a descendant; white text counts as hidden only when no ancestor sets a background colour or picture; `aria-hidden` (screen readers only) is ignored. A short hidden line before any visible text (up to 200 characters after invisible padding) is kept as `preheader_text`: not counted as hidden content, still scanned for keywords and prompt injection. Hidden copies of visible text (mobile/desktop versions) no longer count.
- **Hidden template blocks in bulk mail.** After the parser fix, 91 mails still hid real template blocks, 87 of them list/bulk mail (`List-Unsubscribe` etc.). In list mail `hidden_html_text` now uses the key `hidden_html_text_bulk` (0.10) unless the hidden text addresses a machine ("assistant", "classifier", "ignore ... instructions", "mark as safe", ...), which keeps the full 0.35.
- **Authentication results.** Gmail writes the ARC chain's claimed results inside a comment (`arc=pass (i=1 spf=pass dkim=pass dmarc=pass)`); the parser read them as Gmail's own verdicts. Comments are now stripped. DKIM is a pass when any signature verifies (one broken extra signature from a mailing service no longer fails the mail), and a DMARC pass suppresses a separate SPF fail, which is what forwarding (here, a university account forwarded to Gmail) causes.
- **"Secrecy" wording.** `do not share` and a bare `confidential` matched job-alert footers ("do not share this email") and legal disclaimers. The rule now needs a request to keep something secret ("keep this confidential / between us", "don't tell anyone", "confidential acquisition", "do not share this with anyone").
- **Off hours.** `off_hours_send` was judged in the sender's own Date-header zone, and fired on newsletters sent at night. It is now judged in `PHISHGUARD_TIMEZONE` when set (unset keeps the old behaviour, which the corpus numbers use), and it no longer applies to list mail: it is a BEC signal (a "boss" writing at night), not a property of newsletters.

The cost, measured on the public corpus (rules, threshold 35):

| Public corpus | Version | Recall | Precision | FPR easy_ham | FPR hard_ham |
|---|---|---|---|---|---|
| dev split | before | 70.8% (5741/8111) | 98.8% | 0.8% (23/2744) | 26.1% (48/184) |
| dev split | after | 66.3% (5385/8117) | 99.2% | 0.6% (17/2744) | 15.2% (28/184) |
| test split | before | 70.6% (2444/3460) | 99.0% | 0.8% (9/1156) | 25.8% (17/66) |
| test split | after | 66.4% (2293/3454) | 99.1% | 0.6% (7/1156) | 21.2% (14/66) |
| synthetic (600) | before / after | 93.4% / 93.4% | 100% / 100% | 0 FP / 0 FP | |

Read it for what it is:

- **About four points of corpus recall came from a bug.** The old parser marked 1,008 of 11,571 corpus phishing mails as carrying hidden text; the corrected one marks 137. Most of the difference is visible white-on-colour text, which the corpus rewarded because its legitimate mail is 2002 plain text. That signal meant "modern HTML email", which is also why it flagged 94% of a real 2026 inbox.
- The phishing totals differ slightly (8,111 → 8,117 dev, 3,460 → 3,454 test) because the split is keyed on parsed content and the parser changed; the test split has now been looked at many times, so it is closer to a dev number than a clean held-out estimate.
- Of the 40 mails still flagged in the inbox, most sit between 35 and 50: the band that `hybrid` mode sends to the model. The real-model hybrid sample above recovered 59 of 60 gray-zone phishing mails and cleared half of the gray-zone hard_ham, so rules plus hybrid is the intended configuration for a real inbox; that combination has not yet been run on this inbox.
- One mailbox, one person, one week of mail, no phishing in it: this measures false positives on ordinary mail, not recall on real attacks.

### Evaluation pitfalls

- **F1 and accuracy depend on the class ratio.** The test split has about 3 phishing per legitimate mail. A classifier that flags *everything* scores precision ~75%, recall 100%, F1 ~86%, which is better than the default operating point's F1, while being useless. Use measures that don't move with the ratio: recall at a fixed false-positive rate (`Recall @1% FPR` / `@5% FPR` columns), per-category FPR, or a class-balanced metric. A real inbox is mostly legitimate, which makes false positives far more frequent per day than this test split suggests.
- **Era bias.** SpamAssassin ham is from 2002; the phishing spans 2004-2024. Anything that changed over time, such as DKIM/DMARC adoption, HTML habits or time zones, separates the classes in this corpus without saying anything about phishing. A learner will happily use it (`no_authentication` 0.01 -> 0.45). Hence the default `--frozen no_authentication,off_hours_send`.
- **easy_ham vs hard_ham.** A constraint on easy_ham FPR says nothing about hard_ham. Report both; `--max-fpr-hard` adds a second cap.
- **Look at test once.** Calibrate and analyze on dev; a test number seen twice is a dev number.

### What changed from the real-corpus error analysis

Each change and its evidence is in `docs/DESIGN.md` (Q31-Q39; the v4 false-positive round is Q63-Q68). In short:

- The catch-all `suspicious_link` (82.6% of ham vs 84.3% of phish, +23 points each time) is split into specific signals (IP host, shortener, brand on a foreign domain, non-standard port, `@` obfuscation, `data:`/`javascript:`, punycode). The generic "unrelated host" part is weight 0.
- Reply-To / Return-Path mismatches no longer count within one organization and are softened or ignored on mailing-list mail (`List-Id`, `List-Unsubscribe`, `Precedence: list|bulk`). A reply-to that goes to free mail keeps full weight even on list mail.
- More attachment signals: broader double extensions, archives, legacy Office files, password hints next to an attachment, image-only lures.
- Prompt-injection patterns no longer match mailing-list phrases ("you are now subscribed", "as root").
- All weights live in `phishguard/readonly/weights.yaml`.
- v4: `mailto:`/`tel:`/`cid:` hrefs are not web links (they had fired `link_at_obfuscation` on 41% of dev hard_ham). Urgency, payment and credential keywords are split into a specific sub-key (a deadline, a money destination, an account action) and the generic word, whose weight is unchanged; a sub-key never weighs less than its generic word. A link-text mismatch whose real target is the sender's own domain gets a lower key (0.25), except when the link text names a brand or one of our domains, or the sender is itself a look-alike.

**Dataset bias: missing authentication.** The legitimate mail (SpamAssassin, 2002) predates DKIM and DMARC, so 100% of it has no authentication result, while 86.3% of the phishing has none either. In this corpus "no SPF/DKIM/DMARC" mostly encodes the mail's *year*. `no_authentication` is therefore at the minimum weight (0.01), and any real-corpus number should be read with this in mind: a corpus of modern legitimate mail would score differently. Explicit authentication *failures* still count fully.

**Synthetic vs real.** The rules lean on signals the synthetic set was built around: look-alikes of *our* domains, *our* executives' names, sender reputation and domain age. None of those exist in the public corpora, so the score there must come from wording, links, attachments and headers. The gap between the two is the honest measure of how much of the synthetic score comes from shared assumptions. Synthetic F1 is guarded by a test (>= 95% at the default threshold; currently 95.9%, measured with `python -m phishguard.dataset.evaluate --n 200 --seed 42`).
