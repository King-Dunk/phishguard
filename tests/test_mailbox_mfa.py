"""Mailbox remediation (PR #6) under the two-factor policy (PR #7): held actions need two distinct factors,
single-message reversible actions still run directly."""

import pytest

from phishguard.config import Settings
from phishguard.mutating import FactorNotAvailable, build_gateway
from phishguard.mutating.policy import MAILBOX_ACTIONS, ActionType
from tests.conftest import PASSWORD, approve, enroll, make_gateway

P = {"provider": "gmail", "mailbox": "gmail:me/INBOX", "message_id": "18c00001abc"}


@pytest.fixture
def env(clock):
    calls = []

    def rec(name):
        return lambda params: calls.append((name, params)) or {"ok": True, "results": [{"ok": True}]}

    gw = make_gateway(clock)
    gw.executor.handlers = {a: rec(a.value) for a in MAILBOX_ACTIONS}
    creds = enroll(gw, "analyst")
    return gw, creds, calls


@pytest.mark.parametrize("action", ["delete_email", "release_from_quarantine"])
def test_delete_and_release_held_until_two_factors(env, clock, action):
    gw, creds, calls = env
    r = gw.submit(action, P, "analyst")
    assert r.status == "pending_mfa" and r.approvable and calls == []
    one = gw.verify_factor(r.pending_id, "password", {"password": PASSWORD}, r.digest)
    assert one.status == "pending_mfa" and calls == []  # one factor is not enough
    out = approve(gw, r, creds, ("webauthn",))
    assert out.status == "executed" and calls == [(action, P)]
    assert out.result["outcome"]["ok"] is True
    ev = gw.audit.entries()[-1]
    assert ev["event"] == "action_executed" and ev["factors"] == ["password", "webauthn"] and ev["ok"] is True


def test_release_with_two_knowledge_factors_stays_held(env, clock):
    gw, creds, calls = env
    r = gw.submit("release_from_quarantine", P, "analyst")
    out = approve(gw, r, creds, ("password", "security_questions"))
    assert out.status == "pending_mfa" and out.needs_non_knowledge and calls == []
    assert approve(gw, r, creds, ("totp",), clock).status == "executed" and len(calls) == 1


def test_bulk_quarantine_needs_two_factors_single_runs_directly(env):
    gw, creds, calls = env
    single = gw.submit("quarantine_email", P, "worker", "risk 80 >= 35")
    assert single.status == "executed" and single.result["ok"] and len(calls) == 1
    bulk = {**P, "message_ids": [f"m{i}" for i in range(11)]}
    del bulk["message_id"]
    r = gw.submit("quarantine_email", bulk, "analyst")
    assert r.status == "pending_mfa" and len(calls) == 1
    assert approve(gw, r, creds).status == "executed" and len(calls) == 2


def test_unenrolled_worker_cannot_get_its_own_delete_approved(env):
    gw, creds, calls = env
    r = gw.submit("delete_email", P, "phishguard-mailbox-guard")
    assert r.status == "pending_mfa" and not r.approvable
    with pytest.raises(FactorNotAvailable):
        gw.verify_factor(r.pending_id, "password", {"password": PASSWORD}, r.digest)
    assert calls == []


def test_handler_failure_after_mfa_is_declined_and_audited(env):
    gw, creds, calls = env

    def boom(params):
        raise RuntimeError("provider said no")

    gw.executor.handlers[ActionType.DELETE_EMAIL] = boom
    r = gw.submit("delete_email", P, "analyst")
    out = approve(gw, r, creds)
    assert out.status == "declined" and "provider said no" in out.result["outcome"]["error"]
    assert gw.audit.entries()[-1]["event"] == "action_declined"


def test_mailbox_guard_wiring_uses_the_two_factor_policy():
    gw = build_gateway(Settings(), handlers={ActionType.DELETE_EMAIL: lambda p: {"ok": True}})
    assert gw.policy.required == 2 and not gw.policy.dev_single_factor
    assert gw.factors.webauthn is not None and ActionType.DELETE_EMAIL in gw.executor.handlers
