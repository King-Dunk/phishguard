import pytest
from fastapi.testclient import TestClient

from phishguard.api import create_app
from phishguard.mutating import CaptureChannel
from tests.conftest import FakeClock


@pytest.fixture
def ctx(settings):
    clock, ch = FakeClock(), CaptureChannel()
    app = create_app(settings, channel=ch, clock=clock)
    return TestClient(app), app.state.gateway, ch, clock


def test_health(ctx):
    r = ctx[0].get("/health")
    assert r.json()["status"] == "ok" and r.json()["llm_mode"] == "mock"
    assert "key" not in r.text.lower()


def test_analyze(ctx, phish, benign):
    c = ctx[0]
    r = c.post("/analyze", json={"email": phish.model_dump(mode="json")}).json()
    assert r["is_phishing"] and 0 <= r["risk_percent"] <= 100 and r["features"]
    r = c.post("/analyze", json={"email": benign.model_dump(mode="json")}).json()
    assert not r["is_phishing"]


def test_analyze_validates_input(ctx):
    assert ctx[0].post("/analyze", json={"email": {"id": "x"}}).status_code == 422


def test_actions_flow_end_to_end(ctx):
    c, gw, ch, _ = ctx
    r = c.post(
        "/actions", json={"action_type": "quarantine_email", "requested_by": "bob", "params": {"email_id": "e1"}}
    )
    assert r.status_code == 200 and r.json()["status"] == "executed"
    r = c.post("/actions", json={"action_type": "pay_invoice", "requested_by": "bob", "params": {"invoice": "I-1"}})
    assert r.status_code == 202
    p = r.json()
    assert ch.codes[p["pending_id"]] not in r.text  # code never in response
    ok = c.post(
        "/mfa/verify",
        json={"pending_id": p["pending_id"], "code": ch.codes[p["pending_id"]], "confirm_digest": p["confirm_digest"]},
    )
    assert ok.status_code == 200 and len(gw.executor.ledger) == 2
    again = c.post("/mfa/verify", json={"pending_id": p["pending_id"], "code": "x", "confirm_digest": "y"})
    assert again.status_code == 409


def test_verify_error_codes(ctx):
    c, gw, ch, clock = ctx
    assert c.post("/mfa/verify", json={"pending_id": "nope", "code": "1", "confirm_digest": "x"}).status_code == 404
    p = c.post("/actions", json={"action_type": "transfer_funds", "requested_by": "b", "params": {}}).json()
    bad = c.post(
        "/mfa/verify", json={"pending_id": p["pending_id"], "code": "abcdef", "confirm_digest": p["confirm_digest"]}
    )
    assert bad.status_code == 403 and bad.json()["detail"]["attempts_left"] == 2
    clock.advance(10_000)
    late = c.post(
        "/mfa/verify",
        json={"pending_id": p["pending_id"], "code": ch.codes[p["pending_id"]], "confirm_digest": p["confirm_digest"]},
    )
    assert late.status_code == 410 and gw.executor.ledger == []


def test_unknown_action_400(ctx):
    assert ctx[0].post("/actions", json={"action_type": "rm_rf", "requested_by": "b"}).status_code == 400
