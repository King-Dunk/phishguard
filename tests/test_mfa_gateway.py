import pytest

from phishguard.mutating import (
    ActionType,
    AuditLog,
    CaptureChannel,
    Executor,
    MFAFailed,
    MFAGateway,
    PendingExpired,
    PendingFinalized,
    PendingNotFound,
    UnknownActionError,
    requires_mfa,
)
from phishguard.mutating.executor import ExecutionGrant


@pytest.fixture
def env(clock):
    ch = CaptureChannel()
    ex = Executor()
    gw = MFAGateway(
        executor=ex, audit=AuditLog(clock=clock), channel=ch, timeout_seconds=60, max_attempts=3, clock=clock
    )
    return gw, ex, ch, clock


def _events(gw):
    return [e["event"] for e in gw.audit.entries()]


def test_low_risk_action_runs_without_mfa(env):
    gw, ex, ch, _ = env
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
        )
    ],
)
def test_sensitive_actions_always_suspended(env, a):
    gw, ex, ch, _ = env
    r = gw.submit(a.value, {}, "alice")
    assert r.status == "pending_mfa" and ex.ledger == []


def test_happy_path_with_double_check(env):
    gw, ex, ch, _ = env
    r = gw.submit("transfer_funds", {"amount": 100, "to": "ACME"}, "alice")
    gw.verify(r.pending_id, ch.codes[r.pending_id], r.digest)
    assert len(ex.ledger) == 1
    assert _events(gw) == ["action_suspended", "action_executed"]
    assert gw.audit.verify_chain()


def test_wrong_digest_blocks_even_with_right_code(env):
    gw, ex, ch, _ = env
    r = gw.submit("transfer_funds", {"amount": 100}, "alice")
    with pytest.raises(MFAFailed):
        gw.verify(r.pending_id, ch.codes[r.pending_id], "deadbeef")
    assert ex.ledger == []


def test_three_bad_codes_reject_and_right_code_then_fails(env):
    gw, ex, ch, _ = env
    r = gw.submit("pay_invoice", {"invoice": "I1"}, "alice")
    good = ch.codes[r.pending_id]
    bad = "000000" if good != "000000" else "111111"
    for _ in range(3):
        with pytest.raises(MFAFailed):
            gw.verify(r.pending_id, bad, r.digest)
    with pytest.raises(PendingFinalized):
        gw.verify(r.pending_id, good, r.digest)
    assert ex.ledger == []
    assert "action_rejected" in _events(gw)


def test_timeout_auto_rejects_and_audits(env):
    gw, ex, ch, clock = env
    r = gw.submit("change_bank_details", {"iban": "X"}, "alice")
    clock.advance(61)
    with pytest.raises(PendingExpired):
        gw.verify(r.pending_id, ch.codes[r.pending_id], r.digest)
    assert ex.ledger == []
    ev = [e for e in gw.audit.entries() if e["event"] == "action_rejected"]
    assert ev and ev[0]["reason"] == "mfa_timeout"


def test_sweep_expires_without_any_verify_call(env):
    gw, ex, ch, clock = env
    r = gw.submit("transfer_funds", {}, "alice")
    clock.advance(120)
    assert gw.sweep() == 1 and gw.state_of(r.pending_id) == "expired"


def test_replay_after_execution_rejected(env):
    gw, ex, ch, _ = env
    r = gw.submit("transfer_funds", {}, "alice")
    code = ch.codes[r.pending_id]
    gw.verify(r.pending_id, code, r.digest)
    with pytest.raises(PendingFinalized):
        gw.verify(r.pending_id, code, r.digest)
    assert len(ex.ledger) == 1


def test_code_from_other_pending_does_not_work(env):
    gw, ex, ch, _ = env
    a = gw.submit("transfer_funds", {"n": 1}, "alice")
    b = gw.submit("transfer_funds", {"n": 2}, "alice")
    if ch.codes[a.pending_id] == ch.codes[b.pending_id]:
        pytest.skip("1-in-a-million code collision")
    with pytest.raises(MFAFailed):
        gw.verify(b.pending_id, ch.codes[a.pending_id], b.digest)


def test_unknown_pending(env):
    with pytest.raises(PendingNotFound):
        env[0].verify("nope", "123456", "x")


def test_unknown_action_default_deny(env):
    for raw in ("drop_database", "", "transfer-funds"):
        with pytest.raises(UnknownActionError):
            env[0].submit(raw, {}, "alice")


def test_action_name_obfuscation_still_hits_mfa(env):
    gw, ex, ch, _ = env
    for raw in ("  TRANSFER_FUNDS ", "ｔｒａｎｓｆｅｒ_ｆｕｎｄｓ", "transfer​_funds"):
        assert gw.submit(raw, {}, "alice").status == "pending_mfa"
    assert ex.ledger == []


def test_innocent_action_with_money_content_escalates(env):
    gw, ex, ch, _ = env
    assert (
        gw.submit("send_reply", {"body": "Please wire the funds to our new bank account"}, "a").status == "pending_mfa"
    )
    assert gw.submit("send_reply", {"body": "转账到新的银行账户"}, "a").status == "pending_mfa"
    assert gw.submit("block_sender", {"sender": "x@y.com", "iban": "DE00"}, "a").status == "pending_mfa"
    assert gw.submit("quarantine_email", {}, "a", reason="invoice scam").status == "pending_mfa"
    assert gw.submit("send_reply", {"body": "Thanks, see you at 3pm"}, "a").status == "executed"
    assert requires_mfa(ActionType.SEND_REPLY, {"nested": [{"x": "Gift Card"}]})


def test_executor_unreachable_without_gateway_grant():
    with pytest.raises(PermissionError):
        ExecutionGrant(object(), "d")
    with pytest.raises(PermissionError):
        Executor().run(None, ActionType.TRANSFER_FUNDS, {})


def test_audit_never_contains_code_and_detects_tampering(env):
    gw, ex, ch, _ = env
    r = gw.submit("transfer_funds", {"amount": 5}, "alice")
    gw.verify(r.pending_id, ch.codes[r.pending_id], r.digest)
    assert ch.codes[r.pending_id] not in str(gw.audit.entries())
    assert gw.audit.verify_chain()
    gw.audit._entries[0]["by"] = "mallory"
    assert not gw.audit.verify_chain()
