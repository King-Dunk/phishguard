"""Each verification method (success, failure, replay, wrong action, lockout, timeout) and the 2-factor policy.

WebAuthn is exercised with redteam/virtual_authenticator.py: real ES256 signatures and CBOR, verified by
py_webauthn exactly as for a browser. It is not a physical Touch ID.
"""

import json
import sqlite3
import threading

import pytest

from phishguard.mfa_config import MFAConfig
from phishguard.mutating import (
    KV,
    EnrollmentError,
    EnrollmentGrants,
    FactorAlreadyUsed,
    FactorLocked,
    FactorNotAvailable,
    MFAFailed,
    MFAPolicy,
    OperationLocked,
    PasswordManager,
    PendingExpired,
    SecurityQuestionManager,
    SQLiteStore,
    WebAuthnManager,
)
from phishguard.mutating.factors import normalize_answer
from redteam.virtual_authenticator import VirtualAuthenticator
from tests.conftest import PASSWORD, QUESTIONS, approve, enroll, factor_response, make_gateway

PAY = {"amount": 120, "payee_id": "GLOBEX"}


# ---------------------------------------------------------------------------- policy
def test_policy_default_two_distinct_with_one_non_knowledge():
    p = MFAPolicy()
    assert not p.satisfied(["password"]) and not p.satisfied(["totp"])
    assert not p.satisfied(["password", "security_questions"])  # two knowledge factors
    assert p.satisfied(["password", "totp"]) and p.satisfied(["security_questions", "webauthn"])
    assert p.satisfied(["totp", "webauthn"])
    assert not p.satisfied(["totp", "totp"])  # distinct methods only
    assert p.remaining(["password"]) == 1 and p.remaining(["password", "security_questions"]) == 1
    assert not p.can_satisfy(["password", "security_questions"])


def test_policy_is_configurable():
    assert MFAPolicy(allow_knowledge_only=True).satisfied(["password", "security_questions"])
    three = MFAPolicy(required=3)
    assert not three.satisfied(["password", "totp"]) and three.satisfied(["password", "totp", "webauthn"])
    for bad in (0, 1, 5):
        with pytest.raises(ValueError):
            MFAPolicy(required=bad)


def test_policy_from_env(monkeypatch):
    monkeypatch.setenv("PHISHGUARD_MFA_REQUIRED_FACTORS", "3")
    monkeypatch.setenv("PHISHGUARD_MFA_ALLOW_KNOWLEDGE_ONLY", "1")
    c = MFAConfig.from_env()
    assert c.required_factors == 3 and c.allow_knowledge_only and not c.dev_single_factor
    monkeypatch.setenv("PHISHGUARD_MFA_DEV_SINGLE_FACTOR", "1")
    assert MFAConfig.from_env().dev_single_factor


def test_gateway_knowledge_only_policy_releases_with_password_and_questions(clock):
    gw = make_gateway(clock, mfa=MFAConfig(allow_knowledge_only=True))
    creds = enroll(gw, "kim", ("password", "security_questions"))
    r = gw.submit("transfer_funds", PAY, "kim")
    assert r.approvable
    assert approve(gw, r, creds, ("password", "security_questions")).status == "executed"


def test_gateway_default_policy_holds_password_and_questions(clock):
    gw = make_gateway(clock)
    creds = enroll(gw, "kim", ("password", "security_questions"))
    r = gw.submit("transfer_funds", PAY, "kim")
    assert not r.approvable  # nothing strong enrolled: held until an admin enrolls TOTP or a passkey
    out = approve(gw, r, creds, ("password", "security_questions"))
    assert out.status == "pending_mfa" and out.needs_non_knowledge and gw.executor.ledger == []


@pytest.mark.parametrize(
    "pair", [("password", "totp"), ("totp", "webauthn"), ("security_questions", "webauthn"), ("webauthn", "password")]
)
def test_any_valid_pair_releases(clock, pair):
    gw = make_gateway(clock)
    creds = enroll(gw, "ann")
    r = gw.submit("transfer_funds", PAY, "ann")
    assert approve(gw, r, creds, pair, clock).status == "executed" and len(gw.executor.ledger) == 1


def test_each_factor_is_audited_without_secrets(clock):
    gw = make_gateway(clock)
    creds = enroll(gw, "ann")
    r = gw.submit("transfer_funds", PAY, "ann")
    with pytest.raises(MFAFailed):
        gw.verify_factor(r.pending_id, "password", {"password": "not the password"}, r.digest)
    approve(gw, r, creds, ("security_questions", "password", "webauthn"))
    ev = [e for e in gw.audit.entries() if e["event"] == "mfa_factor"]
    assert [(e["method"], e["result"]) for e in ev] == [
        ("password", "fail"),
        ("security_questions", "ok"),
        ("password", "ok"),
        ("webauthn", "ok"),
    ]
    dump = json.dumps(gw.audit.entries())
    for secret in (PASSWORD, "not the password", "Rex", "Hillcrest", creds.totp.secret, "clientDataJSON"):
        assert secret not in dump


# ---------------------------------------------------------------------------- password
def test_password_hashing_is_argon2id_and_compare_is_strict():
    kv = KV()
    pm = PasswordManager(kv)
    pm.enroll("bob", "Tr0ub4dor&3-long")
    rec = kv.get("password", "bob")
    assert rec["hash"].startswith("$argon2id$") and "Tr0ub4dor" not in json.dumps(rec)
    assert pm.verify("bob", "Tr0ub4dor&3-long") and pm.verify("BOB", "Tr0ub4dor&3-long")  # canonical user
    assert not pm.verify("bob", "tr0ub4dor&3-long")  # passwords keep case
    assert pm.verify("bob", "Ｔｒ0ub4dor&3-long")  # NFKC: fullwidth input from another keyboard
    assert not pm.verify("nobody", "Tr0ub4dor&3-long")  # unknown user checked against a dummy hash
    assert not pm.verify("bob", ["Tr0ub4dor&3-long"])  # type confusion


def test_password_enrollment_rules():
    pm = PasswordManager()
    for bad in ("short", "password123", "x" * 200):
        with pytest.raises(EnrollmentError):
            pm.enroll("u", bad)
    with pytest.raises(EnrollmentError):
        pm.enroll("longusername", "longusername")
    pm.enroll("u", "a perfectly fine passphrase")
    from phishguard.mutating import AlreadyEnrolled

    with pytest.raises(AlreadyEnrolled):
        pm.enroll("U", "another fine passphrase")


def test_password_per_user_lockout_and_expiry(clock):
    pm = PasswordManager(clock=clock, lockout_threshold=3, lockout_seconds=600)
    pm.enroll("eve", PASSWORD)
    assert not pm.verify("eve", "a") and not pm.verify("eve", "b")
    assert pm.verify("eve", PASSWORD)  # success resets consecutive failures
    for g in ("a", "b", "c"):
        assert not pm.verify("eve", g)
    with pytest.raises(FactorLocked):
        pm.verify("eve", PASSWORD)  # even the right password while locked
    clock.advance(601)
    assert pm.verify("eve", PASSWORD)


def test_password_lockout_surfaces_through_gateway(clock):
    gw = make_gateway(clock, max_attempts=10, lockout_threshold=50, mfa=MFAConfig(password_lockout_threshold=3))
    enroll(gw, "eve", ("password", "totp"))
    r = gw.submit("transfer_funds", PAY, "eve")
    for _ in range(3):
        with pytest.raises(MFAFailed):
            gw.verify_factor(r.pending_id, "password", {"password": "guess"}, r.digest)
    other = gw.submit("pay_invoice", {"invoice_id": "INV-1001"}, "eve")  # other operation, same user
    with pytest.raises(FactorLocked):
        gw.verify_factor(other.pending_id, "password", {"password": PASSWORD}, other.digest)
    assert any(e.get("result") == "locked" for e in gw.audit.entries())


# ---------------------------------------------------------------------------- security questions
def test_answers_normalized_and_never_stored_plaintext():
    kv = KV()
    sq = SecurityQuestionManager(kv)
    sq.enroll("amy", QUESTIONS)
    raw = json.dumps(kv.get("questions", "amy"))
    assert "Rex" not in raw and "rex" not in raw and "paulo" not in raw.lower() and "$argon2id$" in raw
    assert normalize_answer("  SÃO   Paulo ") == normalize_answer("são paulo") == normalize_answer("Sa\u0303o paulo")
    assert normalize_answer("ＲＥＸ") == "rex"  # fullwidth
    assert normalize_answer("Re​x") == "rex"
    qs = sq.challenge("amy")
    by_text = {q["question"]: q["answer"] for q in QUESTIONS}
    shouted = {q["id"]: "  " + by_text[q["question"]].upper() + " " for q in qs}
    assert sq.verify("amy", [q["id"] for q in qs], shouted)


def test_question_subset_is_random_but_sticky_until_answered():
    sq = SecurityQuestionManager(per_challenge=2)
    sq.enroll("amy", QUESTIONS)
    first = [q["id"] for q in sq.challenge("amy")]
    assert len(first) == 2 and all(sq.challenge("amy")[i]["id"] == first[i] for i in range(2))  # can't fish
    by_text = {q["question"]: q["answer"] for q in QUESTIONS}
    rows = {r["id"]: r for r in sq._rows("amy")}
    assert sq.verify("amy", first, {i: by_text[rows[i]["question"]] for i in first})
    seen = {tuple(q["id"] for q in sq.challenge("amy"))}
    for _ in range(40):  # after a success a new random subset is drawn
        qs = sq.challenge("amy")
        assert sq.verify("amy", [q["id"] for q in qs], {q["id"]: by_text[q["question"]] for q in qs})
        seen.add(tuple(q["id"] for q in qs))
    assert len(seen) > 1


def test_questions_all_or_nothing_and_exact_keys():
    sq = SecurityQuestionManager(max_failures=10)
    sq.enroll("amy", QUESTIONS)
    qs = sq.challenge("amy")
    by_text = {q["question"]: q["answer"] for q in QUESTIONS}
    ids = [q["id"] for q in qs]
    good = {q["id"]: by_text[q["question"]] for q in qs}
    assert not sq.verify("amy", ids, {ids[0]: good[ids[0]]})  # one missing
    assert not sq.verify("amy", ids, {**good, ids[1]: "wrong"})  # one wrong
    assert not sq.verify("amy", ids, {**good, "q99": "extra"})  # extra key
    assert not sq.verify("amy", ids, "not a dict")


def test_questions_rate_limited_per_user_window(clock):
    sq = SecurityQuestionManager(clock=clock, max_failures=3, window_seconds=3600)
    sq.enroll("amy", QUESTIONS)
    ids = [q["id"] for q in sq.challenge("amy")]
    for _ in range(3):
        assert not sq.verify("amy", ids, {i: "guess" for i in ids})
    with pytest.raises(FactorLocked):
        sq.challenge("amy")
    with pytest.raises(FactorLocked):
        sq.verify("amy", ids, {i: "guess" for i in ids})
    clock.advance(3601)
    assert sq.challenge("amy")


def test_question_enrollment_rules():
    sq = SecurityQuestionManager()
    with pytest.raises(EnrollmentError):
        sq.enroll("u", QUESTIONS[:2])  # too few
    with pytest.raises(EnrollmentError):
        sq.enroll("u", [QUESTIONS[0]] * 3)  # duplicates
    with pytest.raises(EnrollmentError):
        sq.enroll("u", [{"question": "Favourite colour?", "answer": "a"}] + QUESTIONS[1:] + QUESTIONS[:1])


def test_questions_need_a_challenge_bound_to_the_action(clock):
    gw = make_gateway(clock)
    creds = enroll(gw, "amy")
    r = gw.submit("transfer_funds", PAY, "amy")
    other = gw.submit("transfer_funds", {**PAY, "amount": 999}, "amy")
    qs = gw.challenge(r.pending_id, "security_questions", r.digest)["questions"]
    answers = {q["id"]: creds.answers[q["question"]] for q in qs}
    with pytest.raises(MFAFailed):  # answers without a challenge on THIS action
        gw.verify_factor(other.pending_id, "security_questions", {"answers": answers}, other.digest)
    assert gw.verify_factor(r.pending_id, "security_questions", {"answers": answers}, r.digest).status == "pending_mfa"


# ---------------------------------------------------------------------------- WebAuthn
@pytest.fixture
def wa(clock):
    gw = make_gateway(clock)
    creds = enroll(gw, "wes", ("password", "webauthn"))
    return gw, creds


def _assert(gw, r, va, **kw):
    ch = gw.challenge(r.pending_id, "webauthn", r.digest)
    return va.get(ch["publicKey"], **kw), ch


def test_webauthn_registration_requires_uv_and_challenge(clock):
    m = WebAuthnManager(clock=clock)
    va = VirtualAuthenticator()
    opts = m.registration_options("u")
    assert opts["authenticatorSelection"]["userVerification"] == "required" and opts["rp"]["id"] == "localhost"
    with pytest.raises(EnrollmentError):
        m.register("u", va.create(opts, uv=False))  # Touch ID skipped: refused
    with pytest.raises(EnrollmentError):
        m.register("u", va.create(opts))  # challenge was single-use, consumed by the failed attempt
    opts = m.registration_options("u")
    with pytest.raises(EnrollmentError):
        m.register("u", va.create(opts, origin="https://evil.example"))
    opts = m.registration_options("u")
    clock.advance(121)
    with pytest.raises(EnrollmentError):
        m.register("u", va.create(opts))  # expired
    opts = m.registration_options("u")
    cid = m.register("u", va.create(opts))
    assert m.is_enrolled("u") and m.credentials("u")[0]["id"] == cid
    assert m.registration_options("u")["excludeCredentials"][0]["id"] == cid
    with pytest.raises(EnrollmentError):  # the same authenticator key can't be bound to a second user
        m.register("v", va.create(m.registration_options("v")))


def test_webauthn_success_updates_sign_count(wa):
    gw, creds = wa
    r = gw.submit("transfer_funds", PAY, "wes")
    cred, ch = _assert(gw, r, creds.authenticator)
    assert ch["publicKey"]["userVerification"] == "required"
    assert gw.verify_factor(r.pending_id, "webauthn", {"credential": cred}, r.digest).status == "pending_mfa"
    assert gw.factors.webauthn.credentials("wes")[0]["sign_count"] == 1


def test_webauthn_browser_style_null_user_handle(wa):
    gw, creds = wa
    r = gw.submit("transfer_funds", PAY, "wes")
    cred, _ = _assert(gw, r, creds.authenticator)
    cred["response"]["userHandle"] = None  # browsers send null for non-discoverable credentials
    assert gw.verify_factor(r.pending_id, "webauthn", {"credential": cred}, r.digest).status == "pending_mfa"


def test_webauthn_challenge_bound_to_action_digest(wa):
    gw, creds = wa
    r = gw.submit("transfer_funds", PAY, "wes")
    ch = gw.challenge(r.pending_id, "webauthn", r.digest)["publicKey"]
    from phishguard.mutating.webauthn_factor import action_binding, unb64u

    assert unb64u(ch["challenge"])[16:] == action_binding(r.pending_id, r.digest)


@pytest.mark.parametrize(
    "kw,reason",
    [
        ({"origin": "https://acme-corp-login.example"}, "wrong_origin"),
        ({"rp_id": "evil.example"}, "wrong_rp_id"),
        ({"uv": False}, "user_not_verified"),
    ],
)
def test_webauthn_bad_assertions_refused(wa, kw, reason):
    gw, creds = wa
    r = gw.submit("transfer_funds", PAY, "wes")
    cred, _ = _assert(gw, r, creds.authenticator, **kw)
    with pytest.raises(MFAFailed):
        gw.verify_factor(r.pending_id, "webauthn", {"credential": cred}, r.digest)
    fails = [e for e in gw.audit.entries() if e["event"] == "mfa_factor" and e["result"] == "fail"]
    assert fails[-1]["reason"] == reason


def test_webauthn_replay_same_action_and_other_action(wa):
    gw, creds = wa
    a = gw.submit("transfer_funds", PAY, "wes")
    b = gw.submit("transfer_funds", {**PAY, "amount": 50000}, "wes")
    cred_a, _ = _assert(gw, a, creds.authenticator)
    with pytest.raises(MFAFailed):  # B has no challenge yet
        gw.verify_factor(b.pending_id, "webauthn", {"credential": cred_a}, b.digest)
    gw.challenge(b.pending_id, "webauthn", b.digest)
    with pytest.raises(MFAFailed):  # B's challenge is different
        gw.verify_factor(b.pending_id, "webauthn", {"credential": cred_a}, b.digest)
    gw.verify_factor(a.pending_id, "webauthn", {"credential": cred_a}, a.digest)
    with pytest.raises(FactorAlreadyUsed):
        gw.verify_factor(a.pending_id, "webauthn", {"credential": cred_a}, a.digest)
    c = gw.submit("transfer_funds", {**PAY, "amount": 3}, "wes")
    gw.challenge(c.pending_id, "webauthn", c.digest)
    with pytest.raises(MFAFailed):  # replay of a used assertion on a new action
        gw.verify_factor(c.pending_id, "webauthn", {"credential": cred_a}, c.digest)


def test_webauthn_challenge_is_single_use_even_on_failure(wa):
    gw, creds = wa
    r = gw.submit("transfer_funds", PAY, "wes")
    bad, ch = _assert(gw, r, creds.authenticator, uv=False)
    with pytest.raises(MFAFailed):
        gw.verify_factor(r.pending_id, "webauthn", {"credential": bad}, r.digest)
    good = creds.authenticator.get(ch["publicKey"])  # a valid signature over the consumed challenge
    with pytest.raises(MFAFailed):
        gw.verify_factor(r.pending_id, "webauthn", {"credential": good}, r.digest)


def test_webauthn_cloned_authenticator_counter(wa):
    gw, creds = wa
    a = gw.submit("transfer_funds", PAY, "wes")
    cred, _ = _assert(gw, a, creds.authenticator)  # counter 1
    gw.verify_factor(a.pending_id, "webauthn", {"credential": cred}, a.digest)
    b = gw.submit("transfer_funds", {**PAY, "amount": 7}, "wes")
    clone, _ = _assert(gw, b, creds.authenticator, counter=1)
    with pytest.raises(MFAFailed):
        gw.verify_factor(b.pending_id, "webauthn", {"credential": clone}, b.digest)
    assert gw.audit.entries()[-2]["reason"] == "sign_count_not_increased"


def test_webauthn_cross_user_and_malformed(clock):
    gw = make_gateway(clock, max_attempts=10)
    enroll(gw, "wes", ("password", "webauthn"))
    other = enroll(gw, "mal", ("password", "webauthn"))
    r = gw.submit("transfer_funds", PAY, "wes")
    for resp in (
        lambda: {"credential": other.authenticator.get(gw.challenge(r.pending_id, "webauthn", r.digest)["publicKey"])},
        lambda: {"credential": "garbage"},
        lambda: {"credential": {"id": "x", "response": {}}},
        lambda: {},
    ):
        gw.challenge(r.pending_id, "webauthn", r.digest)
        with pytest.raises(MFAFailed):
            gw.verify_factor(r.pending_id, "webauthn", resp(), r.digest)
    assert gw.executor.ledger == []


def test_webauthn_challenge_timeout(wa, clock):
    gw, creds = wa
    r = gw.submit("transfer_funds", PAY, "wes")
    cred, _ = _assert(gw, r, creds.authenticator)
    clock.advance(121)  # challenge lifetime 120 s; the pending action itself lives 600 s here
    with pytest.raises(MFAFailed):
        gw.verify_factor(r.pending_id, "webauthn", {"credential": cred}, r.digest)
    assert gw.audit.entries()[-2]["reason"] == "challenge_expired"


def test_webauthn_state_persists_in_sqlite(tmp_path, clock):
    db = str(tmp_path / "w.db")
    gw1 = make_gateway(clock, store=SQLiteStore(db))
    creds = enroll(gw1, "wes", ("password", "webauthn"))
    gw2 = make_gateway(clock, store=SQLiteStore(db))  # restart
    r = gw2.submit("transfer_funds", PAY, "wes")
    assert approve(gw2, r, creds, ("webauthn", "password")).status == "executed"
    rows = sqlite3.connect(db).execute("SELECT value FROM kv WHERE ns = 'webauthn'").fetchall()
    assert json.loads(rows[0][0])[0]["sign_count"] == 1


# ---------------------------------------------------------------------------- gateway-wide guarantees
def test_factor_attempts_share_the_pending_limit(clock):
    gw = make_gateway(clock)
    enroll(gw, "pat", ("password", "totp"))
    r = gw.submit("transfer_funds", PAY, "pat")
    with pytest.raises(MFAFailed):
        gw.verify_factor(r.pending_id, "password", {"password": "x"}, r.digest)
    with pytest.raises(MFAFailed):
        gw.verify_factor(r.pending_id, "totp", {"code": "000000"}, r.digest)
    with pytest.raises(MFAFailed) as e:
        gw.verify_factor(r.pending_id, "password", {"password": "y"}, r.digest)
    assert e.value.attempts_left == 0 and gw.state_of(r.pending_id) == "rejected"


def test_operation_lockout_across_factors(clock):
    gw = make_gateway(clock, lockout_threshold=4, max_attempts=10)
    enroll(gw, "pat", ("password", "totp"))
    r = gw.submit("transfer_funds", PAY, "pat")
    for m, resp in [("password", {"password": "x"}), ("totp", {"code": "1"}), ("password", {"password": "y"})]:
        with pytest.raises(MFAFailed):
            gw.verify_factor(r.pending_id, m, resp, r.digest)
    with pytest.raises(OperationLocked):
        gw.verify_factor(r.pending_id, "totp", {"code": "2"}, r.digest)


def test_not_enrolled_or_unknown_methods_are_refused_without_counting(clock):
    gw = make_gateway(clock)
    enroll(gw, "pat", ("password", "totp"))
    r = gw.submit("transfer_funds", PAY, "pat")
    for m in ("webauthn", "security_questions", "channel", "TOTP", "totp ", "sms", None, 3):
        with pytest.raises(FactorNotAvailable):
            gw.verify_factor(r.pending_id, m, {}, r.digest)
    assert gw.status(r.pending_id)["state"] == "pending"
    assert [e for e in gw.audit.entries() if e["event"] == "mfa_failed"] == []


def test_timeout_discards_partial_progress(clock):
    gw = make_gateway(clock, timeout_seconds=30)
    creds = enroll(gw, "pat", ("password", "webauthn"))
    r = gw.submit("transfer_funds", PAY, "pat")
    approve(gw, r, creds, ("password",))
    clock.advance(31)
    with pytest.raises(PendingExpired):
        gw.challenge(r.pending_id, "webauthn", r.digest)
    assert gw.executor.ledger == []


def test_concurrent_factor_submissions_release_exactly_once(clock):
    gw = make_gateway(clock)
    creds = enroll(gw, "con")
    for _ in range(5):
        r = gw.submit("transfer_funds", PAY, "con")
        resp = {m: factor_response(gw, r.pending_id, r.digest, m, creds, clock) for m in ("password", "webauthn")}
        results, errors = [], []
        barrier = threading.Barrier(6)

        def go(m, r=r, resp=resp, results=results, errors=errors, barrier=barrier):
            barrier.wait()
            try:
                results.append(gw.verify_factor(r.pending_id, m, resp[m], r.digest).status)
            except Exception as e:  # noqa: BLE001 - losing racers get PendingFinalized / FactorAlreadyUsed
                errors.append(type(e).__name__)

        threads = [threading.Thread(target=go, args=(m,)) for m in ["password", "webauthn"] * 3]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert results.count("executed") == 1, (results, errors)
        assert set(errors) <= {"PendingFinalized", "FactorAlreadyUsed", "MFAFailed"}
        clock.advance(1)
    runs = [e for e in gw.executor.ledger if e["action"] == "transfer_funds"]
    assert len(runs) == 5 and gw.executor.payments.balance_cents("OPERATING") == 25_000_000 - 5 * 12_000


# ---------------------------------------------------------------------------- enrollment grants
def test_enrollment_grant_bound_single_use_and_expiring(clock):
    g = EnrollmentGrants(KV(), clock, ttl_seconds=60)
    tok, _ = g.issue("alice", "webauthn")
    assert not g.consume(tok, "bob", "webauthn") and not g.consume(tok, "alice", "password")
    assert g.consume(tok, "ALICE", "webauthn") and not g.consume(tok, "alice", "webauthn")
    tok2, _ = g.issue("alice", "webauthn")
    clock.advance(61)
    assert not g.consume(tok2, "alice", "webauthn") and not g.consume(None, "alice", "webauthn")


def test_add_mfa_factor_action_issues_token(clock):
    gw = make_gateway(clock)
    creds = enroll(gw, "self", ("password", "webauthn"))
    r = gw.submit("add_mfa_factor", {"method": "totp"}, "self")
    out = approve(gw, r, creds)
    token = out.result["enrollment_token"]
    assert out.status == "executed" and token not in json.dumps(gw.audit.entries())
    assert token not in json.dumps(gw.executor.ledger)
    assert gw.factors.grants.consume(token, "self", "totp")
