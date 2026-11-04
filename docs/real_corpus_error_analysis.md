# PhishGuard real-corpus error analysis (aggregate only, no message content)

Rules mode, threshold 50, ctx without trusted domains/executives.

## Group sizes and score distribution

| group | n | median score | p25 | p75 |
|---|---|---|---|---|
| easy_ham FP | 884 | 60.3 | 60.3 | 63.5 |
| easy_ham TN | 3016 | 43.3 | 35.6 | 43.3 |
| hard_ham FP | 86 | 58.5 | 58.3 | 66.8 |
| hard_ham TN | 164 | 35.6 | 35.6 | 40.8 |
| nazario_phish FN | 4633 | 40.8 | 35.6 | 43.3 |
| nazario_phish TP | 6938 | 66.5 | 58.5 | 72.6 |

## Feature fire rate (% of emails where feature fires) and mean contribution when fired

| feature | ham all | phish all | ham FP | phish FN | mean contrib in FP | mean contrib in TP |
|---|---|---|---|---|---|---|
| auth_fail | 0.0% | 3.0% | 0.0% | 0.2% | 0.0 | 26.8 |
| bank_detail_change | 0.0% | 0.1% | 0.0% | 0.0% | 0.0 | 31.9 |
| credential_request | 1.3% | 22.2% | 5.4% | 2.1% | 22.2 | 21.1 |
| header_anomaly | 0.0% | 0.3% | 0.0% | 0.0% | 0.0 | 31.6 |
| hidden_html_text | 0.6% | 8.7% | 2.4% | 1.4% | 22.8 | 21.9 |
| link_text_mismatch | 0.5% | 26.3% | 2.0% | 0.3% | 35.3 | 33.6 |
| no_authentication | 100.0% | 86.3% | 100.0% | 88.7% | 5.4 | 5.0 |
| obfuscated_text | 0.0% | 0.0% | 0.0% | 0.0% | 0.0 | 12.8 |
| off_hours_send | 32.9% | 53.1% | 37.9% | 48.6% | 5.3 | 5.0 |
| payment_keywords | 2.6% | 15.4% | 8.2% | 6.7% | 14.6 | 13.0 |
| prompt_injection_attempt | 0.6% | 0.1% | 2.4% | 0.0% | 37.4 | 36.2 |
| reply_to_mismatch | 18.3% | 7.8% | 75.9% | 2.5% | 22.9 | 21.4 |
| return_path_mismatch | 69.2% | 20.7% | 85.3% | 14.8% | 8.2 | 7.5 |
| risky_attachment | 0.0% | 4.0% | 0.1% | 4.2% | 27.1 | 30.5 |
| secrecy_request | 0.9% | 5.2% | 3.8% | 0.8% | 18.7 | 17.0 |
| suspicious_link | 82.6% | 84.3% | 99.6% | 72.7% | 23.0 | 21.6 |
| urgency_language | 2.8% | 15.8% | 8.9% | 6.8% | 14.5 | 13.0 |

## Structural traits

| trait | ham FP | ham TN | phish TP | phish FN |
|---|---|---|---|---|
| no features fired | 0.0% | 0.0% | 0.0% | 0.3% |
| has links | 99.8% | 82.9% | 94.2% | 82.2% |
| has attachments | 0.5% | 0.7% | 7.4% | 18.2% |
| reply_to set | 80.1% | 12.7% | 39.7% | 26.6% |
| auth spf=none | n/a | n/a | n/a | n/a |

## FP feature combinations (top 10)

| features fired | count |
|---|---|
| no_authentication, reply_to_mismatch, return_path_mismatch, suspicious_link | 394 |
| no_authentication, off_hours_send, reply_to_mismatch, return_path_mismatch, suspicious_link | 245 |
| no_authentication, reply_to_mismatch, suspicious_link | 46 |
| no_authentication, return_path_mismatch, suspicious_link, urgency_language | 37 |
| no_authentication, payment_keywords, return_path_mismatch, suspicious_link | 25 |
| hidden_html_text, no_authentication, off_hours_send, suspicious_link | 16 |
| no_authentication, off_hours_send, payment_keywords, return_path_mismatch, suspicious_link | 15 |
| no_authentication, off_hours_send, return_path_mismatch, suspicious_link, urgency_language | 12 |
| no_authentication, prompt_injection_attempt, return_path_mismatch, suspicious_link | 11 |
| no_authentication, off_hours_send, reply_to_mismatch, return_path_mismatch, suspicious_link, urgency_language | 10 |

Note: SpamAssassin ham is 2002-era mail (mostly no DKIM/DMARC); Nazario phish spans 2004-2024.
