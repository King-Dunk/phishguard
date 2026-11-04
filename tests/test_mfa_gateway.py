"""Gateway state machine: suspension, digest double-check, attempts, timeout, replay, default deny.

Default flow is multi-factor (password + passkey here). The last section covers the dev-only
single-factor flow, which must stay available behind its explicit flag.
"""

import pytest

from phishguard.mutating import (
    ActionType,
    AuditLog,
    CaptureChannel,
    Executor,
    MFAFailed,
    MFAGateway,
    MFAPolicy,
    PendingExpired,
    PendingFinalized,
    PendingNotFound,
    UnknownActionError,
    requires_mfa,
)
from phishguard.mutating.executor import ExecutionGrant
from tests.conftest import PASSWORD, approve, enroll, make_gateway

PAY = {"amount": 100, "payee_id": "ACME-VENDOR"}


@pytest.fixture
def env(clock):
    gw = make_gateway(clock, timeout_seconds=60)
    creds = enroll(gw, "alice", ("password", "webauthn"))
    return gw, gw.executor, gw.channel, clock, creds


def _events(gw):
    return [e["event"] for e in gw.audit.entries()]


def test_low_risk_action_runs_without_mfa(env):
    gw, ex, ch, *_ = env
    r = gw.submit("quarantine_email", {"email_id": "e1"}, "alice")
    assert r.status == "executed" and len(ex.ledger) == 1 and not ch.codes


@pytest.mark.parametrize(
    "a",
    [
        x
        for x in ActionType
        if x.name
        in (
            "TRANSFER_FUNDS",
            "PAY_INVOICE",
            "APPROVE_INVOICE",
            "CHANGE_BANK_DETAILS",
            "CHANGE_ACCOUNT_EMAIL",
            "RESET_PASSWORD",
            "CHANGE_ACCOUNT_SETTINGS",
            "ADD_MFA_FACTOR",
        )
    ],
)
def test_sensitive_actions_always_suspended(env, a):
    gw, ex, ch, *_ = env
    r = gw.submit(a.value, {}, "alice")
    assert r.status == "pending_mfa" and ex.ledger == [] and not ch.codes  # no console code in 2-factor mode


def test_happy_path_two_factors_and_double_check(env):
    gw, ex, ch, clock, creds = env
    r = gw.submit("transfer_funds", PAY, "alice")
    assert r.method == "multi" and r.approvable and r.factors_available == ["password", "webauthn"]
    first = gw.verify_factor(r.pending_id, "password", {"password": PASSWORD}, r.digest)
    assert first.status == "pending_mfa" and first.remaining == 1 and first.needs_non_knowledge and ex.ledger == []
    out = approve(gw, r, creds, ("webauthn",))
    assert out.status == "executed" and out.satisfied == ["password", "webauthn"] and len(ex.ledger) == 1
    assert _events(gw) == ["action_suspended", "mfa_factor", "mfa_challenge", "mfa_factor", "action_executed"]
    assert gw.audit.entries()[-1]["factors"] == ["password", "webauthn"]
    assert gw.audit.verify_chain()


def test_wrong_digest_blocks_even_with_right_factors(env):
    gw, ex, *_ = env
    r = gw.submit("transfer_funds", PAY, "alice")
    with pytest.raises(MFAFailed):
        gw.verify_factor(r.pending_id, "password", {"password": PASSWORD}, "deadbeef")
    assert ex.ledger == [] and gw.status(r.pending_id)["factors_satisfied"] == []


def test_three_bad_attempts_reject_then_right_factors_fail(env):
    gw, ex, ch, clock, creds = env
    r = gw.submit("pay_invoice", {"invoice_id": "INV-1001"}, "alice")
    for _ in range(3):
        with pytest.raises(MFAFailed):
            gw.verify_factor(r.pending_id, "password", {"password": "wrong password!"}, r.digest)
    with pytest.raises(PendingFinalized):
        gw.verify_factor(r.pending_id, "password", {"password": PASSWORD}, r.digest)
    assert ex.ledger == [] and "action_rejected" in _events(gw)


def test_timeout_auto_rejects_even_after_one_factor(env):
    gw, ex, ch, clock, creds = env
    r = gw.submit("change_bank_details", {"payee_id": "ACME-VENDOR"}, "alice")
    gw.verify_factor(r.pending_id, "password", {"password": PASSWORD}, r.digest)
    clock.advance(61)
    with pytest.raises(PendingExpired):
        approve(gw, r, creds, ("webauthn",))
    assert ex.ledger == []
    ev = [e for e in gw.audit.entries() if e["event"] == "action_rejected"]
    assert ev and ev[0]["reason"] == "mfa_timeout"


def test_sweep_expires_without_any_verify_call(env):
    gw, ex, ch, clock, _ = env
    r = gw.submit("transfer_funds", {}, "alice")
    clock.advance(120)
    assert gw.sweep() == 1 and gw.state_of(r.pending_id) == "expired"


def test_replay_after_execution_rejected(env):
    gw, ex, ch, clock, creds = env
    r = gw.submit("transfer_funds", PAY, "alice")
    approve(gw, r, creds)
    with pytest.raises(PendingFinalized):
        gw.verify_factor(r.pending_id, "password", {"password": PASSWORD}, r.digest)
    assert len(ex.ledger) == 1


def test_unknown_pending(env):
    with pytest.raises(PendingNotFound):
        env[0].verify_factor("nope", "password", {"password": "x"}, "x")


def test_unknown_action_default_deny(env):
    for raw in ("drop_database", "", "transfer-funds"):
        with pytest.raises(UnknownActionError):
            env[0].submit(raw, {}, "alice")


def test_action_name_obfuscation_still_hits_mfa(env):
    gw, ex, *_ = env
    for raw in ("  TRANSFER_FUNDS ", "ｔｒａｎｓｆｅｒ_ｆｕｎｄｓ", "transfer​_funds"):
        assert gw.submit(raw, {}, "alice").status == "pending_mfa"
    assert ex.ledger == []


def test_innocent_action_with_money_content_escalates(env):
    gw, *_ = env
    assert (
        gw.submit("send_reply", {"body": "Please wire the funds to our new bank account"}, "a").status == "pending_mfa"
    )
    assert gw.submit("send_reply", {"body": "转账到新的银行账户"}, "a").status == "pending_mfa"
    assert gw.submit("block_sender", {"sender": "x@y.com", "iban": "DE00"}, "a").status == "pending_mfa"
    assert gw.submit("quarantine_email", {}, "a", reason="invoice scam").status == "pending_mfa"
    assert gw.submit("send_reply", {"body": "Thanks, see you at 3pm"}, "a").status == "executed"
    assert requires_mfa(ActionType.SEND_REPLY, {"nested": [{"x": "Gift Card"}]})


def test_unenrolled_requester_is_held_and_cannot_be_approved(env):
    gw, ex, *_ = env
    r = gw.submit("transfer_funds", PAY, "nobody")
    assert r.status == "pending_mfa" and not r.approvable and r.factors_available == []
    from phishguard.mutating import FactorNotAvailable

    with pytest.raises(FactorNotAvailable):
        gw.verify_factor(r.pending_id, "password", {"password": PASSWORD}, r.digest)
    assert ex.ledger == []


def test_executor_unreachable_without_gateway_grant():
    with pytest.raises(PermissionError):
        ExecutionGrant(object(), "d")
    with pytest.raises(PermissionError):
        Executor().run(None, ActionType.TRANSFER_FUNDS, {})


def test_audit_never_contains_secrets_and_detects_tampering(env):
    gw, ex, ch, clock, creds = env
    r = gw.submit("transfer_funds", PAY, "alice")
    approve(gw, r, creds)
    dump = str(gw.audit.entries())
    assert PASSWORD not in dump and "signature" not in dump and "clientDataJSON" not in dump
    assert gw.audit.verify_chain()
    gw.audit._entries[0]["by"] = "mallory"
    assert not gw.audit.verify_chain()


# ---- dev single-factor flow (PHISHGUARD_MFA_DEV_SINGLE_FACTOR=1) -------------------------------
@pytest.fixture
def dev(clock):
    ch = CaptureChannel()
    ex = Executor()
    gw = MFAGateway(
        executor=ex,
        audit=AuditLog(clock=clock),
        channel=ch,
        timeout_seconds=60,
        max_attempts=3,
        clock=clock,
        policy=MFAPolicy(dev_single_factor=True),
    )
    return gw, ex, ch, clock


def test_dev_flow_needs_explicit_flag():
    with pytest.raises(ValueError):
        MFAPolicy(required=1)  # a single factor without the dev flag is refused
    assert MFAPolicy().required == 2 and not MFAPolicy().dev_single_factor


def test_dev_flow_console_code_and_digest(dev):
    gw, ex, ch, _ = dev
    r = gw.submit("transfer_funds", PAY, "alice")
    assert r.method == "channel"
    with pytest.raises(MFAFailed):
        gw.verify(r.pending_id, ch.codes[r.pending_id], "deadbeef")
    gw.verify(r.pending_id, ch.codes[r.pending_id], r.digest)
    assert len(ex.ledger) == 1 and _events(gw)[-1] == "action_executed"
    with pytest.raises(PendingFinalized):
        gw.verify(r.pending_id, ch.codes[r.pending_id], r.digest)


def test_dev_flow_code_from_other_pending_does_not_work(dev):
    gw, ex, ch, _ = dev
    a = gw.submit("transfer_funds", {"n": 1}, "alice")
    b = gw.submit("transfer_funds", {"n": 2}, "alice")
    if ch.codes[a.pending_id] == ch.codes[b.pending_id]:
        pytest.skip("1-in-a-million code collision")
    with pytest.raises(MFAFailed):
        gw.verify(b.pending_id, ch.codes[a.pending_id], b.digest)


def test_dev_flow_refuses_new_factor_routes(dev):
    gw, ex, ch, _ = dev
    r = gw.submit("transfer_funds", PAY, "alice")
    from phishguard.mutating import FactorNotAvailable

    with pytest.raises(FactorNotAvailable):
        gw.challenge(r.pending_id, "webauthn", r.digest)
    out = gw.verify_factor(r.pending_id, "channel", {"code": ch.codes[r.pending_id]}, r.digest)
    assert out.status == "executed" and len(ex.ledger) == 1
