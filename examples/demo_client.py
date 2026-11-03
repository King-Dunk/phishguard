"""Demo client: python examples/demo_client.py --base-url http://127.0.0.1:8000 --code-log server.log

The server (dev StderrChannel) prints MFA codes to its console; this script reads them
from the log file, playing the human holding the phone. Start the server with a short
PHISHGUARD_MFA_TIMEOUT (e.g. 3) so step 5 is quick. `bash examples/run_demo.sh` does it all.
"""

from __future__ import annotations

import argparse
import re
import time

import httpx

PHISH = {
    "id": "demo-1",
    "timestamp": "2026-03-03T03:10:00+00:00",
    "sender_name": "David Chen",
    "sender_email": "david@acme-c0rp.com",
    "reply_to": "d.chen@gmail.com",
    "subject": "Urgent request",
    "body": "Wire transfer today, keep this confidential.",
    "sender_reputation": 0.1,
    "sender_domain_age_days": 5,
    "spf": "fail",
    "dkim": "fail",
    "dmarc": "fail",
}
TRANSFER = {"action_type": "transfer_funds", "requested_by": "alice", "params": {"amount": 50000, "to": "ACME-VENDOR"}}


def code_for(log: str, pid: str) -> str:
    text = open(log, encoding="utf-8").read()
    return re.findall(rf"pending={re.escape(pid)} code=(\d{{6}})", text)[-1]


def show(title: str, r: httpx.Response) -> None:
    print(f"\n== {title}\n<- HTTP {r.status_code} {r.text[:300]}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://127.0.0.1:8000")
    ap.add_argument("--code-log", required=True)
    ap.add_argument("--timeout-wait", type=float, default=4.0, help="seconds to wait for step 5 (> server MFA timeout)")
    a = ap.parse_args()
    c = httpx.Client(base_url=a.base_url, timeout=10)

    r = c.post("/analyze", json={"email": PHISH})
    body = r.json()
    print(
        f"== 1. analyze phishing email\n<- HTTP {r.status_code} risk={body['risk_percent']}% is_phishing={body['is_phishing']}"
    )
    print("   features:", ", ".join(f["name"] for f in body["features"]))

    r = c.post("/actions", json=TRANSFER)
    show("2. transfer_funds is suspended by the MFA gateway", r)
    p = r.json()

    r = c.post(
        "/mfa/verify", json={"pending_id": p["pending_id"], "code": "000000", "confirm_digest": p["confirm_digest"]}
    )
    show("3. wrong code is rejected", r)

    good = code_for(a.code_log, p["pending_id"])
    r = c.post("/mfa/verify", json={"pending_id": p["pending_id"], "code": good, "confirm_digest": p["confirm_digest"]})
    show("4. correct out-of-band code + digest echo is released", r)

    p2 = c.post("/actions", json=TRANSFER).json()
    print(f"\n== 5. second transfer, then wait {a.timeout_wait}s without verifying")
    time.sleep(a.timeout_wait)
    r = c.post(
        "/mfa/verify",
        json={
            "pending_id": p2["pending_id"],
            "code": code_for(a.code_log, p2["pending_id"]),
            "confirm_digest": p2["confirm_digest"],
        },
    )
    show("   late (correct) code after timeout is rejected", r)


if __name__ == "__main__":
    main()
