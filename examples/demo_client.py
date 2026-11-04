"""Demo client: python examples/demo_client.py --base-url http://localhost:8765 --api-key K --admin-key A

Plays both the agent asking to move money and the human approving it. The human's factors are a
password, security questions, a TOTP app (pyotp) and a passkey. The passkey here is the software
authenticator in redteam/virtual_authenticator.py; for a real Touch ID prompt use the browser page at
/demo/webauthn (see README). Start the server with a short PHISHGUARD_MFA_TIMEOUT (e.g. 5) and
PHISHGUARD_WEBAUTHN_ORIGINS matching --base-url. `bash examples/run_demo.sh` does it all.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
import time

import httpx
import pyotp

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from redteam.virtual_authenticator import VirtualAuthenticator  # noqa: E402

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
USER = "alice"
PASSWORD = "correct horse battery staple"
QUESTIONS = [
    {"question": "Name of your first pet?", "answer": "Rex"},
    {"question": "City where you were born?", "answer": "Brisbane"},
    {"question": "Your first school?", "answer": "Hillcrest Primary"},
]
TRANSFER = {
    "action_type": "transfer_funds",
    "requested_by": USER,
    "params": {"amount": 50000, "payee_id": "ACME-VENDOR"},
}


def show(title: str, r: httpx.Response, keys: tuple[str, ...] | None = None) -> None:
    body = r.json() if r.headers.get("content-type", "").startswith("application/json") else r.text
    if keys and isinstance(body, dict):
        body = {k: body[k] for k in keys if k in body}
    text = re.sub(r"secret=[A-Z2-7]+", "secret=<redacted>", str(body))
    print(f"\n== {title}\n<- HTTP {r.status_code} {text[:400]}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://localhost:8000")
    ap.add_argument("--api-key", required=True, help="one of the server's PHISHGUARD_API_KEYS")
    ap.add_argument("--admin-key", required=True, help="one of PHISHGUARD_ADMIN_KEYS (enrollment)")
    ap.add_argument("--origin", default=None, help="WebAuthn origin the server expects (default: --base-url)")
    ap.add_argument("--timeout-wait", type=float, default=6.0, help="seconds to wait in step 9 (> server MFA timeout)")
    ap.add_argument("--code-log", help=argparse.SUPPRESS)  # old flag; console codes are dev-only now
    a = ap.parse_args()
    c = httpx.Client(base_url=a.base_url, timeout=10, headers={"x-api-key": a.api_key})
    admin = {"x-api-key": a.admin_key}

    show("0. no API key is refused", httpx.post(f"{a.base_url}/analyze", json={"email": PHISH}))

    body = c.post("/analyze", json={"email": PHISH}).json()
    print(f"\n== 1. analyze phishing email\n<- risk={body['risk_percent']}% is_phishing={body['is_phishing']}")
    print("   top contributions:", "; ".join(f"{f['name']} +{f['contribution']}" for f in body["features"][:4]))

    # -- enrollment (admin key) ------------------------------------------------------------------
    c.post("/mfa/enroll/password", json={"user": USER, "password": PASSWORD}, headers=admin)
    c.post("/mfa/enroll/questions", json={"user": USER, "questions": QUESTIONS}, headers=admin)
    totp = pyotp.parse_uri(c.post("/mfa/enroll", json={"user": USER}, headers=admin).json()["otpauth_uri"])
    va = VirtualAuthenticator(origin=a.origin or a.base_url)
    opts = c.post("/mfa/webauthn/register/options", json={"user": USER}, headers=admin).json()["publicKey"]
    c.post("/mfa/webauthn/register/verify", json={"user": USER, "credential": va.create(opts)})
    show(f"2. {USER} enrolled four factors (admin key)", c.get(f"/mfa/factors/{USER}"))

    # -- a transfer is held until two factors pass -----------------------------------------------
    r = c.post("/actions", json=TRANSFER)
    show(
        "3. transfer_funds 50,000 AUD is suspended by the MFA gateway",
        r,
        ("status", "confirm_digest", "factors_available", "mfa_policy"),
    )
    p = r.json()
    base = {"pending_id": p["pending_id"], "confirm_digest": p["confirm_digest"]}

    def factor(method: str, response: dict, pend: dict = base) -> httpx.Response:
        return c.post("/mfa/factor", json={**pend, "method": method, "response": response})

    show("4. wrong password is rejected", factor("password", {"password": "Password123"}))
    show("5. right password: still HELD (1 of 2 factors)", factor("password", {"password": PASSWORD}))
    qs = c.post("/mfa/challenge", json={**base, "method": "security_questions"}).json()["questions"]
    ans = {q["question"]: q["answer"] for q in QUESTIONS}
    r = factor("security_questions", {"answers": {q["id"]: ans[q["question"]] for q in qs}})
    show("6. + security questions: still HELD (two knowledge factors are not enough)", r)
    r = c.post("/mfa/verify", json={**base, "code": totp.now()})
    show("7. + TOTP code from the authenticator app: RELEASED", r, ("status",))
    tx = r.json()["result"]["transaction"]
    print(
        f"   {tx['id']}: {tx['amount']} {tx['currency']} -> {tx['payee_id']}, idempotency key {tx['idempotency_key']}"
    )

    # -- passkey + password ----------------------------------------------------------------------
    p2 = c.post("/actions", json={**TRANSFER, "params": {"amount": 1200, "payee_id": "GLOBEX"}}).json()
    b2 = {"pending_id": p2["pending_id"], "confirm_digest": p2["confirm_digest"]}
    factor("password", {"password": PASSWORD}, b2)
    ch = c.post("/mfa/challenge", json={**b2, "method": "webauthn"}).json()["publicKey"]
    r = factor("webauthn", {"credential": va.get(ch)}, b2)
    show("8. second transfer: password + passkey (challenge bound to this action): RELEASED", r, ("status", "factors"))
    r = factor("webauthn", {"credential": va.get(ch)}, b2)
    show("   replaying that passkey assertion is refused", r)

    # -- business email compromise: changed bank details are held ----------------------------
    change = {
        "payee_id": "ACME-VENDOR",
        "account_name": "Acme Office Supplies",
        "bsb": "999999",
        "account_number": "11223344",
    }
    p3 = c.post("/actions", json={"action_type": "change_bank_details", "requested_by": USER, "params": change}).json()
    b3 = {"pending_id": p3["pending_id"], "confirm_digest": p3["confirm_digest"]}
    factor("password", {"password": PASSWORD}, b3)
    ch = c.post("/mfa/challenge", json={**b3, "method": "webauthn"}).json()["publicKey"]
    factor("webauthn", {"credential": va.get(ch)}, b3)
    p4 = c.post(
        "/actions", json={"action_type": "pay_invoice", "requested_by": USER, "params": {"invoice_id": "INV-1001"}}
    ).json()
    b4 = {"pending_id": p4["pending_id"], "confirm_digest": p4["confirm_digest"]}
    factor("password", {"password": PASSWORD}, b4)
    ch = c.post("/mfa/challenge", json={**b4, "method": "webauthn"}).json()["publicKey"]
    show(
        "9. 'our bank details changed' + urgent invoice: MFA passes, bank holds it (cooling-off)",
        factor("webauthn", {"credential": va.get(ch)}, b4),
    )

    # -- timeout -----------------------------------------------------------------------------------
    p5 = c.post("/actions", json=TRANSFER).json()
    print(f"\n== 10. another transfer, then wait {a.timeout_wait}s without approving")
    time.sleep(a.timeout_wait)
    show(
        "    late password after timeout is rejected",
        factor(
            "password", {"password": PASSWORD}, {"pending_id": p5["pending_id"], "confirm_digest": p5["confirm_digest"]}
        ),
    )

    show("11. balances", c.get("/payments/accounts"))
    show("12. audit hash chain verifies", c.get("/audit/verify"))


if __name__ == "__main__":
    main()
