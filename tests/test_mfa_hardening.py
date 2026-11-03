"""TOTP enrollment, anti-replay, lockout, hash-chained audit and SQLite persistence."""

import sqlite3

import pyotp
import pytest

from phishguard.mutating import (
    AlreadyEnrolled,
    AuditLog,
    CaptureChannel,
    Executor,
    MFAFailed,
    MFAGateway,
    OperationLocked,
    SQLiteStore,
    TOTPManager,
)


def _totp(uri: str) -> pyotp.TOTP:
    return pyotp.parse_uri(uri)


def _gw(clock, store=None, **kw):
    totp = TOTPManager(store=store, clock=clock)
    gw = MFAGateway(
        executor=Executor(),
        audit=AuditLog(clock=clock, store=store),
        channel=CaptureChannel(),
        timeout_seconds=600,
        max_attempts=3,
        clock=clock,
        totp=totp,
        store=store,
        **kw,
    )
    return gw, totp


def test_enroll_returns_otpauth_uri_and_refuses_reenroll(clock):
    _, totp = _gw(clock)
    uri = totp.enroll("alice@acme-corp.com")
    assert uri.startswith("otpauth://totp/") and "issuer=PhishGuard" in uri and "secret=" in uri
    with pytest.raises(AlreadyEnrolled):
        totp.enroll("alice@acme-corp.com")


def test_totp_flow_no_code_delivered(clock):
    gw, totp = _gw(clock)
    t = _totp(totp.enroll("alice"))
    r = gw.submit("transfer_funds", {"amount": 10}, "alice")
    assert r.method == "totp" and gw.channel.codes == {}
    gw.verify(r.pending_id, t.at(clock()), r.digest)
    assert len(gw.executor.ledger) == 1


def test_totp_code_cannot_be_replayed_in_same_window(clock):
    gw, totp = _gw(clock)
    t = _totp(totp.enroll("alice"))
    code = t.at(clock())
    a = gw.submit("transfer_funds", {"n": 1}, "alice")
    b = gw.submit("transfer_funds", {"n": 2}, "alice")
    gw.verify(a.pending_id, code, a.digest)
    with pytest.raises(MFAFailed):
        gw.verify(b.pending_id, code, b.digest)  # same code, same 30 s window -> refused
    assert totp.verify("alice", t.at(clock() - 30)) is False  # older window also burned
    clock.advance(30)
    gw.verify(b.pending_id, t.at(clock()), b.digest)  # next window works
    assert len(gw.executor.ledger) == 2


def test_totp_drift_window(clock):
    _, totp = _gw(clock)
    t = _totp(totp.enroll("bob"))
    assert totp.verify("bob", t.at(clock() + 30))  # one step ahead accepted
    assert not totp.verify("bob", t.at(clock() + 120))  # far future refused
    assert not totp.verify("nobody", "123456")


def test_wrong_digest_does_not_burn_totp_step(clock):
    gw, totp = _gw(clock)
    t = _totp(totp.enroll("alice"))
    r = gw.submit("pay_invoice", {}, "alice")
    with pytest.raises(MFAFailed):
        gw.verify(r.pending_id, t.at(clock()), "bad-digest")
    gw.verify(r.pending_id, t.at(clock()), r.digest)


def test_five_consecutive_failures_lock_operation_and_audit(clock):
    gw, _ = _gw(clock, lockout_threshold=5, lockout_seconds=900)
    a = gw.submit("transfer_funds", {"n": 1}, "mallory")
    for _ in range(3):
        with pytest.raises(MFAFailed):
            gw.verify(a.pending_id, "000000x", a.digest)
    b = gw.submit("transfer_funds", {"n": 2}, "mallory")  # fresh pending does not reset the counter
    with pytest.raises(MFAFailed):
        gw.verify(b.pending_id, "000000x", b.digest)
    with pytest.raises(OperationLocked):
        gw.verify(b.pending_id, "000000x", b.digest)  # 5th consecutive failure
    assert gw.state_of(b.pending_id) == "rejected"
    with pytest.raises(OperationLocked):
        gw.submit("transfer_funds", {"n": 3}, "mallory")
    assert gw.submit("pay_invoice", {}, "mallory").status == "pending_mfa"  # other operation not locked
    assert gw.submit("transfer_funds", {}, "alice").status == "pending_mfa"  # other user not locked
    events = [e["event"] for e in gw.audit.entries()]
    assert "operation_locked" in events and "operation_blocked" in events
    lock = next(e for e in gw.audit.entries() if e["event"] == "operation_locked")
    assert lock["key"] == "mallory:transfer_funds" and lock["consecutive_failures"] == 5
    clock.advance(901)
    assert gw.submit("transfer_funds", {}, "mallory").status == "pending_mfa"
    assert gw.executor.ledger == []


def test_success_resets_failure_counter(clock):
    gw, _ = _gw(clock, lockout_threshold=5)
    for _ in range(3):
        r = gw.submit("transfer_funds", {}, "alice")
        with pytest.raises(MFAFailed):
            gw.verify(r.pending_id, "bad", r.digest)
        with pytest.raises(MFAFailed):
            gw.verify(r.pending_id, "bad", r.digest)
        gw.verify(r.pending_id, gw.channel.codes[r.pending_id], r.digest)
    assert len(gw.executor.ledger) == 3


def test_hash_chain_links_entries(clock):
    log = AuditLog(clock=clock)
    for i in range(4):
        log.record("e", i=i)
    es = log.entries()
    assert es[0]["prev"] == "0" * 64 and all(es[i]["prev"] == es[i - 1]["hash"] for i in range(1, 4))
    assert log.verify_chain() and log.first_broken() is None


@pytest.mark.parametrize("attack", ["edit", "delete", "reorder", "rehash_one"])
def test_tamper_detection_in_memory(clock, attack):
    log = AuditLog(clock=clock)
    for i in range(4):
        log.record("e", i=i)
    es = log._entries
    if attack == "edit":
        es[1]["i"] = 99
    elif attack == "delete":
        del es[1]
    elif attack == "reorder":
        es[1], es[2] = es[2], es[1]
    else:  # attacker edits AND recomputes that entry's hash: next link breaks
        from phishguard.mutating.audit import entry_hash

        es[1]["i"] = 99
        es[1]["hash"] = entry_hash({k: v for k, v in es[1].items() if k != "hash"})
    assert not log.verify_chain()
    assert log.first_broken() in (1, 2)


def test_sqlite_tamper_detected(tmp_path, clock):
    db = str(tmp_path / "pg.db")
    log = AuditLog(clock=clock, store=SQLiteStore(db))
    for i in range(3):
        log.record("e", i=i, by="alice")
    con = sqlite3.connect(db)
    row = con.execute("SELECT entry FROM audit WHERE seq = 2").fetchone()[0]
    con.execute("UPDATE audit SET entry = ? WHERE seq = 2", (row.replace("alice", "mallory"),))
    con.commit()
    con.close()
    assert not log.verify_chain()  # the store copy is checked, not just memory
    reloaded = AuditLog(clock=clock, store=SQLiteStore(db))
    assert not reloaded.verify_chain() and reloaded.first_broken() == 1


def test_state_survives_restart(tmp_path, clock):
    db = str(tmp_path / "pg.db")
    gw1, totp1 = _gw(clock, SQLiteStore(db))
    t = _totp(totp1.enroll("alice"))
    r = gw1.submit("transfer_funds", {"amount": 7}, "bob")  # bob: channel code
    code = gw1.channel.codes[r.pending_id]
    r2 = gw1.submit("change_bank_details", {"iban": "X"}, "alice")  # alice: TOTP
    used = t.at(clock())
    gw1.verify(r2.pending_id, used, r2.digest)
    del gw1, totp1  # "process restart"

    gw2, totp2 = _gw(clock, SQLiteStore(db))
    assert gw2.state_of(r.pending_id) == "pending" and gw2.state_of(r2.pending_id) == "executed"
    gw2.verify(r.pending_id, code, r.digest)
    assert gw2.executor.ledger[0]["params"] == {"amount": 7}
    assert totp2.is_enrolled("alice") and not totp2.verify("alice", used)  # replay guard persisted
    assert gw2.audit.verify_chain()
    events = [e["event"] for e in gw2.audit.entries()]
    assert events.count("action_executed") == 2 and events[0] == "action_suspended"


def test_lockout_survives_restart(tmp_path, clock):
    db = str(tmp_path / "pg.db")
    gw1, _ = _gw(clock, SQLiteStore(db), lockout_threshold=2)
    r = gw1.submit("transfer_funds", {}, "m")
    with pytest.raises(MFAFailed):
        gw1.verify(r.pending_id, "x", r.digest)
    with pytest.raises(OperationLocked):
        gw1.verify(r.pending_id, "x", r.digest)
    gw2, _ = _gw(clock, SQLiteStore(db), lockout_threshold=2)
    with pytest.raises(OperationLocked):
        gw2.submit("transfer_funds", {}, "m")
