"""API key auth, rate limiting, SQLite persistence and the new endpoints."""

import pathlib

import pyotp
import pytest
from fastapi.testclient import TestClient

from phishguard.api import create_app
from phishguard.config import Settings
from phishguard.mutating import CaptureChannel
from phishguard.security import APIKeyAuth, RateLimiter
from tests.conftest import PASSWORD, FakeClock

KEY = "test-key-0123456789"
H = {"x-api-key": KEY}
FIX = pathlib.Path(__file__).parent / "fixtures"


def _app(tmp_path=None, **kw):
    s = Settings(
        llm_mode="mock",
        executives=("David Chen",),
        api_keys=(KEY, "second-key"),
        allow_unauthenticated=False,
        db_path=str(tmp_path / "pg.db") if tmp_path else None,
        **kw,
    )
    clock, ch = FakeClock(), CaptureChannel()
    app = create_app(s, channel=ch, clock=clock)
    return TestClient(app), app, ch, clock


def test_fail_closed_without_keys(monkeypatch):
    for v in ("PHISHGUARD_API_KEYS", "PHISHGUARD_ALLOW_NO_AUTH"):
        monkeypatch.delenv(v, raising=False)
    with pytest.raises(RuntimeError, match="PHISHGUARD_API_KEYS"):
        create_app()
    monkeypatch.setenv("PHISHGUARD_API_KEYS", "a, b")
    s = Settings.from_env()
    assert s.api_keys == ("a", "b") and "'a'" not in repr(s)


@pytest.mark.parametrize(
    "path",
    [
        "/analyze",
        "/analyze/eml",
        "/actions",
        "/mfa/verify",
        "/mfa/enroll",
        "/mfa/factor",
        "/mfa/challenge",
        "/mfa/enroll/password",
        "/mfa/enroll/questions",
        "/mfa/webauthn/register/options",
        "/mfa/webauthn/register/verify",
    ],
)
def test_every_route_but_health_needs_key(path):
    c, *_ = _app()
    assert c.get("/health").status_code == 200 and c.get("/health").json()["auth"] == "enabled"
    assert c.post(path, json={}).status_code == 401
    assert c.post(path, json={}, headers={"x-api-key": "wrong"}).status_code == 401
    assert c.post(path, json={}, headers={"x-api-key": ""}).status_code == 401
    assert c.post(path, json={}, headers=H).status_code != 401
    assert c.get("/audit/verify").status_code == 401
    for get in ("/payments/accounts", "/payments/payees/ACME-VENDOR", "/mfa/factors/alice", "/mfa/pending/x"):
        assert c.get(get).status_code == 401


def test_constant_time_auth_unit():
    a = APIKeyAuth(("k1", "k2"))
    assert a.check("k1") and a.check("k2") and a.check("k1") != a.check("k2")
    assert a.check(None) is None and a.check("") is None and a.check("k") is None
    assert not APIKeyAuth(()).enabled and APIKeyAuth(()).check("anything") is None


def test_rate_limit_per_key_and_retry_after():
    c, app, _, clock = _app(rate_limit_per_minute=3)
    for _ in range(3):
        assert c.post("/analyze/eml", json={"raw": "Subject: hi\n\nhello"}, headers=H).status_code == 200
    r = c.post("/analyze/eml", json={"raw": "x"}, headers=H)
    assert r.status_code == 429 and int(r.headers["retry-after"]) > 0
    other = {"x-api-key": "second-key"}
    assert c.post("/analyze/eml", json={"raw": "x"}, headers=other).status_code == 200  # separate bucket
    assert c.get("/health").status_code == 200  # health is never limited
    clock.advance(61)
    assert c.post("/analyze/eml", json={"raw": "x"}, headers=H).status_code == 200


def test_bad_key_guessing_is_throttled():
    c, *_ = _app(rate_limit_per_minute=2)
    codes = [c.post("/actions", json={}, headers={"x-api-key": f"g{i}"}).status_code for i in range(4)]
    assert codes == [401, 401, 429, 429]


def test_rate_limiter_unit():
    t = FakeClock()
    rl = RateLimiter(2, 10, clock=t, max_buckets=2)
    assert rl.hit("a") is None and rl.hit("a") is None and rl.hit("a") == 10
    t.advance(5)
    assert rl.hit("a") == 5
    t.advance(5)
    assert rl.hit("a") is None
    rl.hit("b")
    t.advance(20)
    rl.hit("c")  # evicts idle buckets instead of growing forever
    assert len(rl._hits) <= 2


def test_analyze_eml_endpoint_explains_score():
    c, *_ = _app()
    raw = (FIX / "phish_link_text_mismatch.eml").read_text()
    r = c.post("/analyze/eml", json={"raw": raw}, headers=H).json()
    assert r["is_phishing"] and r["parsed"]["auth"] == {"spf": "pass", "dkim": "pass", "dmarc": "pass"}
    assert r["features"][0]["contribution"] >= r["features"][-1]["contribution"]
    assert abs(sum(f["contribution"] for f in r["features"]) - r["risk_percent"]) < 1
    assert r["explanation"][0].startswith(r["features"][0]["name"] + ": +")


def test_enroll_and_totp_verify_over_api(tmp_path):
    c, app, ch, clock = _app(tmp_path)
    r = c.post("/mfa/enroll", json={"user": "alice"}, headers=H)
    assert r.status_code == 200
    t = pyotp.parse_uri(r.json()["otpauth_uri"])
    assert c.post("/mfa/enroll", json={"user": "alice"}, headers=H).status_code == 409
    assert c.post("/mfa/enroll/password", json={"user": "alice", "password": PASSWORD}, headers=H).status_code == 200
    p = c.post("/actions", json={"action_type": "transfer_funds", "requested_by": "alice", "params": {}}, headers=H)
    p = p.json()
    assert p["mfa_method"] == "multi" and p["factors_available"] == ["password", "totp"] and ch.codes == {}
    body = {"pending_id": p["pending_id"], "code": t.at(clock()), "confirm_digest": p["confirm_digest"]}
    first = c.post("/mfa/verify", json=body, headers=H)
    assert first.status_code == 202 and first.json()["factors_satisfied"] == ["totp"]
    pw = {"pending_id": p["pending_id"], "confirm_digest": p["confirm_digest"], "method": "password"}
    done = c.post("/mfa/factor", json={**pw, "response": {"password": PASSWORD}}, headers=H)
    assert done.status_code == 422 and done.json()["status"] == "declined"  # MFA passed; no payee given
    assert done.json()["result"]["error"] == "invalid_request"
    assert c.get("/audit/verify", headers=H).json() == {"chain_ok": True, "first_broken": None}


def test_lockout_returns_423(tmp_path):
    c, app, ch, clock = _app(tmp_path, mfa_max_attempts=10, mfa_lockout_threshold=5)
    assert c.post("/mfa/enroll", json={"user": "m"}, headers=H).status_code == 200
    p = c.post("/actions", json={"action_type": "pay_invoice", "requested_by": "m", "params": {}}, headers=H).json()
    body = {"pending_id": p["pending_id"], "code": "nope", "confirm_digest": p["confirm_digest"]}
    codes = [c.post("/mfa/verify", json=body, headers=H).status_code for _ in range(6)]
    assert codes == [403, 403, 403, 403, 423, 409]
    r = c.post("/actions", json={"action_type": "pay_invoice", "requested_by": "m", "params": {}}, headers=H)
    assert r.status_code == 423


def test_pending_survives_app_restart(tmp_path):
    c1, app1, ch1, clock = _app(tmp_path)
    t = pyotp.parse_uri(c1.post("/mfa/enroll", json={"user": "b"}, headers=H).json()["otpauth_uri"])
    c1.post("/mfa/enroll/password", json={"user": "b", "password": PASSWORD}, headers=H)
    params = {"amount": 1200, "payee_id": "GLOBEX"}
    p = c1.post(
        "/actions", json={"action_type": "transfer_funds", "requested_by": "b", "params": params}, headers=H
    ).json()
    pw = {"pending_id": p["pending_id"], "confirm_digest": p["confirm_digest"], "method": "password"}
    assert c1.post("/mfa/factor", json={**pw, "response": {"password": PASSWORD}}, headers=H).status_code == 202
    app1.state.store.close()
    c2, app2, *_ = _app(tmp_path)  # brand-new app over the same DB file
    assert c2.get("/health").json()["persistence"] == "sqlite"
    body = {"pending_id": p["pending_id"], "code": t.at(clock()), "confirm_digest": p["confirm_digest"]}
    r = c2.post("/mfa/verify", json=body, headers=H)  # second factor after the restart
    assert r.status_code == 200, r.text
    tx = r.json()["result"]["transaction_id"]
    assert c2.get(f"/payments/transactions/{tx}", headers=H).json()["amount"] == "1200.00"
    hist = c2.get("/payments/accounts/OPERATING/transactions", headers=H).json()["transactions"]
    assert [h["id"] for h in hist] == [tx]
    assert c2.get("/audit/verify", headers=H).json()["chain_ok"]
