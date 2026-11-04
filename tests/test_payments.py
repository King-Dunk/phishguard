"""SimulatedBank (limits, cooling-off, idempotency, persistence), the provider interface, executor
dispatch, adapter stubs, and the read-only payment routes."""

import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

from phishguard.api import create_app
from phishguard.config import Settings
from phishguard.mfa_config import PaymentsConfig
from phishguard.mutating import ActionType, CaptureChannel, Executor, SQLiteStore
from phishguard.mutating.executor import _issue_grant
from phishguard.mutating.payments import (
    BankDetails,
    CoolingOff,
    IdempotencyConflict,
    InsufficientFunds,
    InvalidRequest,
    LimitExceeded,
    PayeeNotFound,
    SimulatedAccounts,
    SimulatedBank,
    TransferRequest,
    build_payment_provider,
)
from phishguard.mutating.payments.adapters import (
    IdentityProviderAdapter,
    Iso20022BankAdapter,
    MYOBAdapter,
    StripeAdapter,
    XeroAdapter,
)
from phishguard.mutating.payments.base import AccountProvider, PaymentProvider, parse_amount
from phishguard.mutating.payments.simulated import iban_ok, validate_details
from tests.conftest import PASSWORD, approve, enroll, make_gateway

DAY = 86_400


def _bank(clock, **kw):
    return SimulatedBank(clock=clock, **kw)


def _tx(amount, payee="ACME-VENDOR", acct="OPERATING", cur="AUD"):
    return TransferRequest(from_account=acct, payee_id=payee, amount=parse_amount(amount), currency=cur)


def test_seeded_demo_data(clock):
    b = _bank(clock)
    accts = {a.id: a for a in b.list_accounts()}
    assert accts["OPERATING"].balance == "250000.00" and accts["PAYROLL"].balance == "80000.00"
    assert b.get_payee("ACME-VENDOR").status == "active"
    assert b.get_payee("ACME-VENDOR").to_dict()["details"]["account_number"] == "****5678"  # masked


def test_transfer_debits_and_records_history(clock):
    b = _bank(clock)
    tx = b.transfer(_tx("1234.50"), idempotency_key="k1")
    assert tx.status.value == "completed" and tx.amount == "1234.50"
    assert b.balance_cents("OPERATING") == 25_000_000 - 123_450
    assert [t.id for t in b.list_transactions("OPERATING")] == [tx.id]
    assert b.get_status(tx.id).payee_id == "ACME-VENDOR"


@pytest.mark.parametrize("bad", [0, -5, "abc", "1.005", None, True, float("nan"), float("inf"), "1e12", [1]])
def test_amount_validation(bad):
    with pytest.raises(InvalidRequest):
        parse_amount(bad)
    assert str(parse_amount(0.1)) == "0.10" and str(parse_amount("19.9")) == "19.90"


def test_unknown_payee_account_and_currency(clock):
    b = _bank(clock)
    with pytest.raises(PayeeNotFound):
        b.transfer(_tx(10, payee="NOPE"), idempotency_key="a")
    with pytest.raises(InvalidRequest):
        b.transfer(_tx(10, cur="USD"), idempotency_key="b")
    with pytest.raises(InvalidRequest):  # ids are validated, not used as raw keys
        b.transfer(_tx(10, payee="../../etc"), idempotency_key="c")


def test_per_transfer_and_daily_limits_reset_next_day(clock):
    b = _bank(clock, daily_limit="100000.00", per_transfer_limit="60000.00")
    with pytest.raises(LimitExceeded):
        b.transfer(_tx("60000.01"), idempotency_key="big")
    b.transfer(_tx(55000), idempotency_key="d1")
    with pytest.raises(LimitExceeded) as e:
        b.transfer(_tx(45001), idempotency_key="d2")
    assert e.value.details["used"] == "55000.00"
    b.transfer(_tx(45000), idempotency_key="d3")  # exactly up to the limit
    clock.advance(DAY)
    b.transfer(_tx(1000), idempotency_key="d4")
    assert {a.id: a.daily_used for a in b.list_accounts()}["OPERATING"] == "1000.00"


def test_insufficient_funds(clock):
    b = _bank(clock, per_transfer_limit="1000000.00", daily_limit="1000000.00")
    with pytest.raises(InsufficientFunds):
        b.transfer(_tx(80000.01, acct="PAYROLL"), idempotency_key="x")
    assert b.balance_cents("PAYROLL") == 8_000_000


def test_cooling_off_for_changed_details(clock):
    b = _bank(clock, cooling_off_seconds=DAY)
    new = BankDetails(account_name="Acme Office Supplies", bsb="999999", account_number="00112233")
    r = b.change_bank_details("ACME-VENDOR", new, idempotency_key="c1")
    assert not r.created and r.effective_at == clock() + DAY and r.details["account_number"] == "****2233"
    with pytest.raises(CoolingOff) as e:
        b.transfer(_tx(100), idempotency_key="t1")
    assert e.value.details["until"] == clock() + DAY
    with pytest.raises(CoolingOff):  # invoices to that payee are held too (the classic BEC follow-up)
        from phishguard.mutating.payments import InvoicePaymentRequest

        b.pay_invoice(InvoicePaymentRequest("INV-1001", "OPERATING"), idempotency_key="i1")
    assert b.get_payee("ACME-VENDOR").status == "cooling_off"
    clock.advance(DAY + 1)
    assert b.transfer(_tx(100), idempotency_key="t2").status.value == "completed"
    hist = b._kv.get("bank_payee", "ACME-VENDOR")["history"]
    assert hist[0]["previous"]["account_number"] == "****5678"  # masked trail of the old details


def test_cooling_off_for_new_payee(clock):
    b = _bank(clock, cooling_off_seconds=3600)
    d = BankDetails(account_name="New Supplier", iban="GB82WEST12345698765432")
    assert b.change_bank_details("NEWCO", d, idempotency_key="n1").created
    with pytest.raises(CoolingOff):
        b.transfer(_tx(5, payee="NEWCO"), idempotency_key="n2")
    clock.advance(3601)
    b.transfer(_tx(5, payee="NEWCO"), idempotency_key="n3")


def test_idempotency(clock):
    b = _bank(clock)
    t1 = b.transfer(_tx(700), idempotency_key="same")
    t2 = b.transfer(_tx(700), idempotency_key="same")
    assert t1.id == t2.id and t2.replayed and b.balance_cents("OPERATING") == 25_000_000 - 70_000
    with pytest.raises(IdempotencyConflict):
        b.transfer(_tx(701), idempotency_key="same")
    d = BankDetails(account_name="X", bsb="111111", account_number="1234")
    first = b.change_bank_details("P1", d, idempotency_key="pc")
    assert b.change_bank_details("P1", d, idempotency_key="pc").to_dict() == first.to_dict()
    with pytest.raises(IdempotencyConflict):
        b.change_bank_details("P2", d, idempotency_key="pc")


def test_invoice_approve_and_pay_once(clock):
    from phishguard.mutating.payments import InvoicePaymentRequest

    b = _bank(clock)
    assert b.approve_invoice("INV-1001", idempotency_key="a").status == "approved"
    tx = b.pay_invoice(InvoicePaymentRequest("INV-1001", "OPERATING"), idempotency_key="p")
    assert tx.amount == "1250.00" and tx.invoice_id == "INV-1001"
    assert b.pay_invoice(InvoicePaymentRequest("INV-1001", "OPERATING"), idempotency_key="p").replayed
    with pytest.raises(InvalidRequest):  # a new key can't pay it twice
        b.pay_invoice(InvoicePaymentRequest("INV-1001", "OPERATING"), idempotency_key="p2")


def test_bank_detail_validation():
    assert iban_ok("GB82WEST12345698765432") and not iban_ok("GB83WEST12345698765432")
    for bad in (
        {"account_name": "x", "iban": "GB83WEST12345698765432"},
        {"account_name": "x", "bsb": "12", "account_number": "123"},
        {"account_name": "", "bsb": "123456", "account_number": "1234"},
        {"account_name": "x"},
        {"account_name": "x", "iban": "GB82WEST12345698765432", "bic": "nope"},
    ):
        with pytest.raises(InvalidRequest):
            validate_details(bad)
    assert validate_details({"name": "Ok", "bsb": "062-000", "account_number": "1234 5678"}).bsb == "062000"


def test_bank_persists_in_sqlite_atomically(tmp_path, clock):
    db = str(tmp_path / "bank.db")
    b1 = SimulatedBank(store=SQLiteStore(db), clock=clock)
    tx = b1.transfer(_tx(99), idempotency_key="persist")
    b2 = SimulatedBank(store=SQLiteStore(db), clock=clock)  # restart: no re-seed, same state
    assert b2.balance_cents("OPERATING") == 25_000_000 - 9_900
    assert b2.transfer(_tx(99), idempotency_key="persist").id == tx.id  # idempotency survives restart
    rows = sqlite3.connect(db).execute("SELECT count(*) FROM bank_tx").fetchone()[0]
    assert rows == 1

    class Boom(SQLiteStore):
        def bank_commit(self, puts, txs):
            self._db.execute("BEGIN IMMEDIATE")
            self._db.execute("INSERT OR REPLACE INTO kv (ns, key, value) VALUES (?, ?, ?)", puts[0])
            self._db.execute("ROLLBACK")
            raise OSError("disk full")

    b3 = SimulatedBank(store=Boom(db), clock=clock)
    with pytest.raises(OSError):
        b3.transfer(_tx(5), idempotency_key="boom")
    assert SimulatedBank(store=SQLiteStore(db), clock=clock).balance_cents("OPERATING") == 25_000_000 - 9_900


def test_simulated_accounts():
    a = SimulatedAccounts()
    r = a.reset_password("alice", idempotency_key="r1")
    assert r.status == "completed" and "password" not in json.dumps(r.detail).replace("password_reset_at", "")
    assert a.reset_password("alice", idempotency_key="r1").reference == r.reference  # idempotent
    with pytest.raises(InvalidRequest):
        a.change_account_email("alice", "not-an-email", idempotency_key="e1")
    assert a.change_account_email("alice", "alice@acme-corp.com", idempotency_key="e2").detail["email"]
    with pytest.raises(InvalidRequest):
        a.change_account_settings("alice", {"x": {"nested": 1}}, idempotency_key="s1")


# ---------------------------------------------------------------------------- interface + adapters
def test_providers_implement_the_interfaces():
    for cls in (SimulatedBank, Iso20022BankAdapter, StripeAdapter, XeroAdapter, MYOBAdapter):
        assert issubclass(cls, PaymentProvider)
    assert issubclass(SimulatedAccounts, AccountProvider) and issubclass(IdentityProviderAdapter, AccountProvider)


@pytest.mark.parametrize("cls", [Iso20022BankAdapter, StripeAdapter, XeroAdapter, MYOBAdapter])
def test_adapter_stubs_raise_and_document(cls):
    a = cls({"base_url": "https://bank.example"})
    calls = {
        "transfer": lambda: a.transfer(_tx(1), idempotency_key="k"),
        "get_payee": lambda: a.get_payee("p"),
        "get_status": lambda: a.get_status("t"),
        "list_accounts": a.list_accounts,
    }
    for name, call in calls.items():
        with pytest.raises(NotImplementedError, match="stub"):
            call()
        assert len(getattr(cls, name).__doc__ or "") > 40, name  # each method says what to implement


def test_provider_chosen_by_config(clock):
    assert isinstance(build_payment_provider(PaymentsConfig(), clock=clock), SimulatedBank)
    assert isinstance(build_payment_provider(PaymentsConfig(provider="stripe")), StripeAdapter)
    with pytest.raises(ValueError):
        build_payment_provider(PaymentsConfig(provider="paypal-lol"))


def test_executor_talks_only_to_the_interface():
    calls = []

    class Recording(PaymentProvider):
        name = "rec"

        def __getattribute__(self, n):
            if n in ("transfer", "pay_invoice", "change_bank_details", "approve_invoice"):
                return lambda *a, **k: calls.append((n, k["idempotency_key"])) or _FakeTx()
            return object.__getattribute__(self, n)

        transfer = pay_invoice = approve_invoice = get_payee = change_bank_details = None
        get_status = list_transactions = list_accounts = None

    class _FakeTx:
        id = "tx_fake"

        def to_dict(self):
            return {"id": self.id}

    Recording.__abstractmethods__ = frozenset()
    ex = Executor(payments=Recording())
    out = ex.run(_issue_grant("d", "PID1"), ActionType.TRANSFER_FUNDS, {"amount": 5, "payee_id": "X"})
    assert out["ok"] and calls == [("transfer", "pg-PID1")]  # idempotency key derived from the pending id


def test_executor_stub_provider_declines_cleanly():
    ex = Executor(payments=StripeAdapter())
    out = ex.run(_issue_grant("d", "p"), ActionType.TRANSFER_FUNDS, {"amount": 5, "payee_id": "X"})
    assert out["ok"] is False and out["error"] == "provider_not_implemented"
    assert ex.ledger[-1] == {
        "action": "transfer_funds",
        "params": {"amount": 5, "payee_id": "X"},
        "digest": "d",
        "ok": False,
        "error": "provider_not_implemented",
    }


# ---------------------------------------------------------------------------- through the gateway
def test_gateway_release_moves_money_once_and_decline_is_audited(clock):
    gw = make_gateway(clock)
    creds = enroll(gw, "fin", ("password", "webauthn"))
    r = gw.submit("transfer_funds", {"amount": 1000, "payee_id": "ACME-VENDOR"}, "fin")
    out = approve(gw, r, creds)
    assert out.status == "executed" and out.result["transaction"]["idempotency_key"] == f"pg-{r.pending_id}"
    change = {"payee_id": "ACME-VENDOR", "account_name": "Acme", "bsb": "999999", "account_number": "4444"}
    r2 = gw.submit("change_bank_details", change, "fin")
    assert approve(gw, r2, creds).status == "executed"
    r3 = gw.submit("transfer_funds", {"amount": 1000, "payee_id": "ACME-VENDOR"}, "fin")
    out3 = approve(gw, r3, creds)
    assert out3.status == "declined" and out3.result["error"] == "cooling_off"
    assert gw.state_of(r3.pending_id) == "declined"
    assert gw.audit.entries()[-1]["event"] == "action_declined" and gw.audit.entries()[-1]["error"] == "cooling_off"
    assert gw.executor.payments.balance_cents("OPERATING") == 25_000_000 - 100_000


def test_payment_routes_read_only_and_masked(tmp_path):
    s = Settings(api_keys=("k",), allow_unauthenticated=False, db_path=str(tmp_path / "p.db"))
    app = create_app(s, channel=CaptureChannel())
    c = TestClient(app)
    H = {"x-api-key": "k"}
    assert c.get("/payments/accounts", headers=H).json()["provider"] == "simulated"
    p = c.get("/payments/payees/ACME-VENDOR", headers=H).json()
    assert p["details"]["account_number"] == "****5678" and "12345678" not in json.dumps(p)
    assert c.get("/payments/payees/NOPE", headers=H).status_code == 404
    assert c.get("/payments/transactions/tx_nope", headers=H).status_code == 404
    assert c.get("/payments/accounts/NOPE/transactions", headers=H).status_code == 404
    assert c.get("/payments/accounts/OPERATING/transactions?limit=0", headers=H).status_code == 422
    for path in ("/payments/transfer", "/payments/accounts", "/payments/payees/ACME-VENDOR"):
        assert c.post(path, json={"amount": 1}, headers=H).status_code in (404, 405)  # no write routes


def test_full_api_two_factor_transfer_with_passkey(tmp_path):
    from redteam.virtual_authenticator import VirtualAuthenticator

    s = Settings(api_keys=("k",), admin_keys=("adm",), allow_unauthenticated=False, open_enrollment=False)
    c = TestClient(create_app(s, channel=CaptureChannel()))
    K, A = {"x-api-key": "k"}, {"x-api-key": "adm"}
    assert c.post("/mfa/enroll/password", json={"user": "zoe", "password": PASSWORD}, headers=K).status_code == 403
    assert c.post("/mfa/enroll/password", json={"user": "zoe", "password": PASSWORD}, headers=A).status_code == 200
    va = VirtualAuthenticator()
    opts = c.post("/mfa/webauthn/register/options", json={"user": "zoe"}, headers=A).json()["publicKey"]
    assert (
        c.post(
            "/mfa/webauthn/register/verify", json={"user": "zoe", "credential": va.create(opts)}, headers=K
        ).status_code
        == 200
    )
    p = c.post(
        "/actions",
        json={"action_type": "transfer_funds", "requested_by": "zoe", "params": {"amount": 42, "payee_id": "GLOBEX"}},
        headers=K,
    ).json()
    base = {"pending_id": p["pending_id"], "confirm_digest": p["confirm_digest"]}
    ch = c.post("/mfa/challenge", json={**base, "method": "webauthn"}, headers=K).json()
    r1 = c.post(
        "/mfa/factor",
        json={**base, "method": "webauthn", "response": {"credential": va.get(ch["publicKey"])}},
        headers=K,
    )
    assert r1.status_code == 202 and r1.json()["factors_remaining"] == 1
    assert c.get(f"/mfa/pending/{p['pending_id']}", headers=K).json()["factors_satisfied"] == ["webauthn"]
    r2 = c.post("/mfa/factor", json={**base, "method": "password", "response": {"password": PASSWORD}}, headers=K)
    assert r2.status_code == 200 and r2.json()["factors"] == ["webauthn", "password"]
    tx = r2.json()["result"]["transaction_id"]
    assert c.get(f"/payments/transactions/{tx}", headers=K).json()["amount"] == "42.00"
    assert c.get("/demo/webauthn").status_code == 200 and "navigator.credentials" in c.get("/demo/webauthn").text


def test_self_service_enrollment_token_over_api():
    from redteam.virtual_authenticator import VirtualAuthenticator

    s = Settings(api_keys=("k",), admin_keys=("adm",), allow_unauthenticated=False, open_enrollment=False)
    app = create_app(s, channel=CaptureChannel())
    c, K, A = TestClient(app), {"x-api-key": "k"}, {"x-api-key": "adm"}
    c.post("/mfa/enroll/password", json={"user": "sam", "password": PASSWORD}, headers=A)
    va = VirtualAuthenticator()
    opts = c.post("/mfa/webauthn/register/options", json={"user": "sam"}, headers=A).json()["publicKey"]
    c.post("/mfa/webauthn/register/verify", json={"user": "sam", "credential": va.create(opts)}, headers=K)
    p = c.post(
        "/actions",
        json={"action_type": "add_mfa_factor", "requested_by": "sam", "params": {"method": "totp"}},
        headers=K,
    ).json()
    base = {"pending_id": p["pending_id"], "confirm_digest": p["confirm_digest"]}
    c.post("/mfa/factor", json={**base, "method": "password", "response": {"password": PASSWORD}}, headers=K)
    ch = c.post("/mfa/challenge", json={**base, "method": "webauthn"}, headers=K).json()
    done = c.post(
        "/mfa/factor",
        json={**base, "method": "webauthn", "response": {"credential": va.get(ch["publicKey"])}},
        headers=K,
    )
    token = done.json()["result"]["enrollment_token"]
    T = {**K, "x-enrollment-token": token}
    assert c.post("/mfa/enroll", json={"user": "someone-else"}, headers=T).status_code == 403
    assert c.post("/mfa/enroll", json={"user": "sam"}, headers=T).status_code == 200  # TOTP added, no admin key
    assert c.post("/mfa/enroll", json={"user": "sam2"}, headers=T).status_code == 403  # single use
    assert c.get("/mfa/factors/sam", headers=K).json()["enrolled"] == ["password", "totp", "webauthn"]
    via = [e["via"] for e in app.state.gateway.audit.entries() if e["event"] == "factor_enrolled"]
    assert via == ["admin", "registration_challenge"]
