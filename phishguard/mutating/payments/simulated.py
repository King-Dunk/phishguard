"""SimulatedBank and SimulatedAccounts: in-process providers with the controls a real bank applies.

- Accounts with balances (integer cents, never floats) and a per-account daily outgoing limit (UTC day).
- A per-transfer limit.
- A payee registry. New payees and changed bank details enter a COOLING-OFF period (default 24 h)
  during which no payment to that payee is released. This is the standard control against business
  email compromise: the attacker's "please update our bank details" mail is followed by an urgent
  invoice, and the delay gives the call-back verification time to catch it.
- Idempotency: the same key + same request returns the original transaction; a different request
  with a used key is refused.
- Persisted in the SQLite store when one is configured (balances, payees, invoices, idempotency records
  and transaction history change in one SQLite transaction), in memory otherwise.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import secrets
import threading
import time
from dataclasses import asdict
from typing import Any

from ..kv import KV
from .base import (
    Account,
    AccountActionResult,
    AccountNotFound,
    AccountProvider,
    BankDetails,
    BankDetailsChange,
    CoolingOff,
    IdempotencyConflict,
    InsufficientFunds,
    InvalidRequest,
    InvoiceNotFound,
    InvoicePaymentRequest,
    InvoiceResult,
    LimitExceeded,
    Payee,
    PayeeNotFound,
    PaymentProvider,
    Transaction,
    TransactionNotFound,
    TransferRequest,
    TxStatus,
    check_id,
    from_cents,
    parse_amount,
    to_cents,
)

_BSB = re.compile(r"^\d{6}$")
_ACCT = re.compile(r"^\d{4,20}$")
_IBAN = re.compile(r"^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$")
_BIC = re.compile(r"^[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?$")
_EMAIL = re.compile(r"^[^@\s]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}$")


def iban_ok(iban: str) -> bool:
    """ISO 13616 mod-97 check."""
    s = iban[4:] + iban[:4]
    digits = "".join(str(int(ch, 36)) for ch in s)
    return int(digits) % 97 == 1


def validate_details(d: dict[str, Any]) -> BankDetails:
    name = " ".join(str(d.get("account_name") or d.get("name") or "").split())[:140]
    bsb = re.sub(r"[\s-]", "", str(d["bsb"])) if d.get("bsb") is not None else None
    acct = re.sub(r"\s", "", str(d["account_number"])) if d.get("account_number") is not None else None
    iban = re.sub(r"\s", "", str(d["iban"])).upper() if d.get("iban") is not None else None
    bic = str(d["bic"]).strip().upper() if d.get("bic") is not None else None
    if not name:
        raise InvalidRequest("account_name is required")
    if iban:
        if not _IBAN.match(iban) or not iban_ok(iban):
            raise InvalidRequest("iban is not valid (format or check digits)")
    elif bsb and acct:
        if not _BSB.match(bsb) or not _ACCT.match(acct):
            raise InvalidRequest("bsb must be 6 digits and account_number 4-20 digits")
    else:
        raise InvalidRequest("give either iban, or bsb and account_number")
    if bic and not _BIC.match(bic):
        raise InvalidRequest("bic is not valid")
    return BankDetails(account_name=name, bsb=bsb, account_number=acct, iban=iban, bic=bic)


def _fingerprint(kind: str, payload: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps({"k": kind, **payload}, sort_keys=True, default=str).encode()).hexdigest()


class SimulatedBank(PaymentProvider):
    name = "simulated"

    def __init__(
        self,
        store=None,
        clock=time.time,
        currency: str = "AUD",
        cooling_off_seconds: int = 86_400,
        daily_limit: str = "100000.00",
        per_transfer_limit: str = "60000.00",
        seed: bool = True,
    ):
        self._store = store
        self._kv = KV(store)
        self._clock = clock
        self.currency = currency
        self.cooling_off = cooling_off_seconds
        self.daily_limit = to_cents(parse_amount(daily_limit))
        self.per_transfer_limit = to_cents(parse_amount(per_transfer_limit))
        self._tx_mem: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        if seed and not self._kv.items("bank_account"):
            self.seed_demo()

    # -- persistence ----------------------------------------------------------------------------
    def _commit(self, puts: list[tuple[str, str, Any]], txs: list[dict[str, Any]] = ()) -> None:
        if self._store:
            self._store.bank_commit(
                [(ns, k, json.dumps(v, sort_keys=True, default=str)) for ns, k, v in puts],
                [(t["id"], t["from_account"], json.dumps(t, sort_keys=True, default=str)) for t in txs],
            )
        else:
            for ns, k, v in puts:
                self._kv.put(ns, k, v)
            self._tx_mem.extend(json.loads(json.dumps(t, default=str)) for t in txs)

    def _tx_rows(self) -> list[dict[str, Any]]:
        if self._store:
            return [json.loads(r) for r in self._store.bank_tx_all()]
        return list(self._tx_mem)

    def seed_demo(self) -> None:
        """Demo data: two accounts, two established payees (past cooling-off), two open invoices."""
        old = self._clock() - 90 * 86_400
        acct = lambda i, n, bal: {"id": i, "name": n, "currency": self.currency, "balance": bal, "daily": {}}  # noqa: E731
        payee = lambda i, n, bsb, num: {  # noqa: E731
            "id": i,
            "name": n,
            "details": asdict(BankDetails(account_name=n, bsb=bsb, account_number=num)),
            "cooling_off_until": 0.0,
            "created_at": old,
            "changed_at": old,
            "history": [],
        }
        inv = lambda i, p, amt: {"id": i, "payee_id": p, "amount": amt, "currency": self.currency, "status": "open"}  # noqa: E731
        self._commit(
            [
                ("bank_account", "OPERATING", acct("OPERATING", "Operating account", 25_000_000)),
                ("bank_account", "PAYROLL", acct("PAYROLL", "Payroll account", 8_000_000)),
                (
                    "bank_payee",
                    "ACME-VENDOR",
                    payee("ACME-VENDOR", "Acme Office Supplies Pty Ltd", "062000", "12345678"),
                ),
                ("bank_payee", "GLOBEX", payee("GLOBEX", "Globex Logistics", "083004", "87654321")),
                ("bank_invoice", "INV-1001", inv("INV-1001", "ACME-VENDOR", 125_000)),
                ("bank_invoice", "INV-1002", inv("INV-1002", "GLOBEX", 480_000)),
            ]
        )

    # -- helpers --------------------------------------------------------------------------------
    def _day(self) -> str:
        return dt.datetime.fromtimestamp(self._clock(), tz=dt.UTC).strftime("%Y-%m-%d")

    def _account(self, account_id: str) -> dict[str, Any]:
        a = self._kv.get("bank_account", check_id(account_id, "from_account"))
        if a is None:
            raise AccountNotFound(f"no account {account_id}")
        return a

    def _payee_row(self, payee_id: str) -> dict[str, Any]:
        p = self._kv.get("bank_payee", check_id(payee_id, "payee_id"))
        if p is None:
            raise PayeeNotFound(f"no payee {payee_id}")
        return p

    def _replay(self, key: str, fp: str) -> Transaction | None:
        rec = self._kv.get("bank_idem", key)
        if rec is None:
            return None
        if rec["fp"] != fp:
            raise IdempotencyConflict("idempotency key already used for a different request")
        if rec.get("tx"):
            tx = self.get_status(rec["tx"])
            tx.replayed = True
            return tx
        return None

    def _debit(self, acct: dict[str, Any], payee: dict[str, Any], cents: int, currency: str) -> None:
        now = self._clock()
        if payee["cooling_off_until"] > now:
            raise CoolingOff(
                f"payee {payee['id']} details changed recently; payments held until cooling-off ends",
                payee_id=payee["id"],
                until=payee["cooling_off_until"],
            )
        if currency != acct["currency"]:
            raise InvalidRequest(f"currency {currency} does not match account currency {acct['currency']}")
        if cents > self.per_transfer_limit:
            raise LimitExceeded("amount above the per-transfer limit", limit=from_cents(self.per_transfer_limit))
        used = acct["daily"].get(self._day(), 0)
        if used + cents > self.daily_limit:
            raise LimitExceeded(
                "daily outgoing limit reached",
                limit=from_cents(self.daily_limit),
                used=from_cents(used),
            )
        if cents > acct["balance"]:
            raise InsufficientFunds("insufficient funds")
        acct["balance"] -= cents
        acct["daily"] = {self._day(): used + cents}  # keep only today's counter

    # -- PaymentProvider ------------------------------------------------------------------------
    def transfer(self, req: TransferRequest, *, idempotency_key: str) -> Transaction:
        cents = to_cents(parse_amount(req.amount))
        fp = _fingerprint("transfer", {"f": req.from_account, "p": req.payee_id, "a": cents, "c": req.currency})
        with self._lock:
            if (tx := self._replay(idempotency_key, fp)) is not None:
                return tx
            acct, payee = self._account(req.from_account), self._payee_row(req.payee_id)
            self._debit(acct, payee, cents, req.currency)
            tx = Transaction(
                id="tx_" + secrets.token_hex(8),
                kind="transfer",
                status=TxStatus.COMPLETED,
                from_account=acct["id"],
                payee_id=payee["id"],
                amount=from_cents(cents),
                currency=req.currency,
                reference=str(req.reference)[:140],
                created_at=self._clock(),
                idempotency_key=idempotency_key,
            )
            self._commit(
                [("bank_account", acct["id"], acct), ("bank_idem", idempotency_key, {"fp": fp, "tx": tx.id})],
                [tx.to_dict()],
            )
            return tx

    def pay_invoice(self, req: InvoicePaymentRequest, *, idempotency_key: str) -> Transaction:
        fp = _fingerprint("invoice", {"i": req.invoice_id, "f": req.from_account})
        with self._lock:
            if (tx := self._replay(idempotency_key, fp)) is not None:
                return tx
            inv = self._kv.get("bank_invoice", check_id(req.invoice_id, "invoice_id"))
            if inv is None:
                raise InvoiceNotFound(f"no invoice {req.invoice_id}")
            if inv["status"] == "paid":
                raise InvalidRequest("invoice already paid")
            acct, payee = self._account(req.from_account), self._payee_row(inv["payee_id"])
            self._debit(acct, payee, inv["amount"], inv["currency"])
            inv["status"] = "paid"
            tx = Transaction(
                id="tx_" + secrets.token_hex(8),
                kind="invoice_payment",
                status=TxStatus.COMPLETED,
                from_account=acct["id"],
                payee_id=payee["id"],
                amount=from_cents(inv["amount"]),
                currency=inv["currency"],
                reference=inv["id"],
                created_at=self._clock(),
                idempotency_key=idempotency_key,
                invoice_id=inv["id"],
            )
            self._commit(
                [
                    ("bank_account", acct["id"], acct),
                    ("bank_invoice", inv["id"], inv),
                    ("bank_idem", idempotency_key, {"fp": fp, "tx": tx.id}),
                ],
                [tx.to_dict()],
            )
            return tx

    def approve_invoice(self, invoice_id: str, *, idempotency_key: str) -> InvoiceResult:
        with self._lock:
            inv = self._kv.get("bank_invoice", check_id(invoice_id, "invoice_id"))
            if inv is None:
                raise InvoiceNotFound(f"no invoice {invoice_id}")
            if inv["status"] == "open":
                inv["status"] = "approved"
                self._commit([("bank_invoice", inv["id"], inv)])
            return InvoiceResult(inv["id"], inv["status"])

    def get_payee(self, payee_id: str) -> Payee:
        p = self._payee_row(payee_id)
        until = p["cooling_off_until"]
        return Payee(
            id=p["id"],
            name=p["name"],
            details=BankDetails(**p["details"]),
            status="cooling_off" if until > self._clock() else "active",
            cooling_off_until=until,
            created_at=p["created_at"],
            changed_at=p["changed_at"],
        )

    def change_bank_details(
        self, payee_id: str, details: BankDetails, *, idempotency_key: str, name: str | None = None
    ) -> BankDetailsChange:
        check_id(payee_id, "payee_id")
        fp = _fingerprint("details", {"p": payee_id, "d": asdict(details), "n": name})
        with self._lock:
            rec = self._kv.get("bank_idem", idempotency_key)
            if rec is not None:
                if rec["fp"] != fp:
                    raise IdempotencyConflict("idempotency key already used for a different request")
                return BankDetailsChange(**rec["result"])
            now = self._clock()
            p = self._kv.get("bank_payee", payee_id)
            created = p is None
            if created:
                p = {"id": payee_id, "name": name or details.account_name, "created_at": now, "history": []}
            else:  # keep a masked trail of previous details for the investigator
                p["history"] = (p.get("history", []) + [{"at": now, "previous": BankDetails(**p["details"]).masked()}])[
                    -20:
                ]
            p["details"] = asdict(details)
            p["changed_at"] = now
            p["cooling_off_until"] = now + self.cooling_off
            if name:
                p["name"] = " ".join(str(name).split())[:140]
            result = BankDetailsChange(payee_id, created, p["cooling_off_until"], details.masked())
            self._commit(
                [("bank_payee", payee_id, p), ("bank_idem", idempotency_key, {"fp": fp, "result": result.to_dict()})]
            )
            return result

    def get_status(self, transaction_id: str) -> Transaction:
        if self._store:
            raw = self._store.bank_tx_get(str(transaction_id))
            row = json.loads(raw) if raw else None
        else:
            row = next((t for t in self._tx_mem if t["id"] == transaction_id), None)
        if row is None:
            raise TransactionNotFound(f"no transaction {transaction_id}")
        row = dict(row)
        row["status"] = TxStatus(row["status"])
        return Transaction(**row)

    def list_transactions(self, account: str, limit: int = 50) -> list[Transaction]:
        self._account(account)
        limit = max(1, min(int(limit), 500))
        if self._store:
            rows = [json.loads(r) for r in self._store.bank_tx_list(account, limit)]
        else:
            rows = [t for t in reversed(self._tx_mem) if t["from_account"] == account][:limit]
        return [Transaction(**{**r, "status": TxStatus(r["status"])}) for r in rows]

    def list_accounts(self) -> list[Account]:
        day = self._day()
        return [
            Account(
                id=a["id"],
                name=a["name"],
                currency=a["currency"],
                balance=from_cents(a["balance"]),
                daily_limit=from_cents(self.daily_limit),
                daily_used=from_cents(a["daily"].get(day, 0)),
            )
            for _, a in self._kv.items("bank_account")
        ]

    def balance_cents(self, account: str) -> int:
        """Test/oracle helper."""
        return self._account(account)["balance"]


class SimulatedAccounts(AccountProvider):
    """Records account changes; never generates or returns a password."""

    name = "simulated"

    def __init__(self, store=None, clock=time.time):
        self._kv = KV(store)
        self._clock = clock
        self._lock = threading.Lock()

    def _apply(self, user: str, action: str, key: str, change: dict[str, Any]) -> AccountActionResult:
        user = str(user)[:100]
        with self._lock:
            done = self._kv.get("acct_idem", key)
            if done is not None:
                return AccountActionResult(**done)
            rec = self._kv.get("acct_user", user, {"history": []})
            rec.update(change)
            rec["history"] = (rec["history"] + [{"at": self._clock(), "action": action}])[-20:]
            res = AccountActionResult(user, action, "completed", "acct_" + secrets.token_hex(6), detail=change)
            self._kv.put("acct_user", user, rec)
            self._kv.put("acct_idem", key, res.to_dict())
            return res

    def reset_password(self, user: str, *, idempotency_key: str) -> AccountActionResult:
        # Real provider: invalidate sessions and send a reset link to the verified address on file.
        return self._apply(user, "reset_password", idempotency_key, {"password_reset_at": self._clock()})

    def change_account_email(self, user: str, new_email: str, *, idempotency_key: str) -> AccountActionResult:
        if not isinstance(new_email, str) or not _EMAIL.match(new_email):
            raise InvalidRequest("new_email is not a valid address")
        return self._apply(user, "change_account_email", idempotency_key, {"email": new_email})

    def change_account_settings(
        self, user: str, settings: dict[str, Any], *, idempotency_key: str
    ) -> AccountActionResult:
        if not isinstance(settings, dict) or not settings or len(settings) > 20:
            raise InvalidRequest("settings must be an object with 1-20 keys")
        clean = {}
        for k, v in settings.items():
            if not isinstance(v, (str, int, float, bool)) or len(str(k)) > 64 or len(str(v)) > 256:
                raise InvalidRequest("settings values must be short scalars")
            clean[str(k)] = v
        return self._apply(user, "change_account_settings", idempotency_key, {"settings": clean})
