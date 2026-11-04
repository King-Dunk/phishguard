"""Performs state changes through provider interfaces. Only callable with a gateway-issued grant.

Money and account actions go to a PaymentProvider / AccountProvider (SimulatedBank by default; real
adapters plug in behind the same interface). Mailbox remediation actions go to `handlers`, e.g.
`mailbox.remediation_handlers()` (quarantine, junk, label, banner, delete, release); without a handler
a mail action is only recorded (simulated backend). Every call is also appended to `ledger`, the
executor's own record of what it was asked to do, which the red team reads to prove nothing ran without approval.

The idempotency key handed to providers is derived from the pending action id, so one approved action
can never move money twice, even if the provider call is retried.

Honest limit: the grant is an in-process guard against accidental/LLM-driven calls,
not a defence against arbitrary code running in the same process. For a real
boundary, run this package as a separate service with its own credentials.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from .factors import CATEGORY, EnrollmentGrants
from .payments import (
    AccountProvider,
    BankDetails,
    InvalidRequest,
    InvoicePaymentRequest,
    PaymentError,
    PaymentProvider,
    ProviderNotImplemented,
    SimulatedAccounts,
    SimulatedBank,
    TransferRequest,
)
from .payments.base import check_id, parse_amount
from .payments.simulated import validate_details
from .policy import ActionType

_SECRET = object()


class ExecutionGrant:
    def __init__(self, token: object, digest: str, pending_id: str | None = None):
        if token is not _SECRET:
            raise PermissionError("execution grants can only be issued by the MFA gateway")
        self.digest = digest
        self.pending_id = pending_id


def _issue_grant(digest: str, pending_id: str | None = None) -> ExecutionGrant:  # used by gateway.py only
    return ExecutionGrant(_SECRET, digest, pending_id)


def _first(params: dict[str, Any], *names: str, default: Any = None) -> Any:
    for n in names:
        if params.get(n) is not None:
            return params[n]
    return default


Handler = Callable[[dict[str, Any]], dict[str, Any]]


class Executor:
    def __init__(
        self,
        handlers: Mapping[ActionType, Handler] | None = None,
        *,
        payments: PaymentProvider | None = None,
        accounts: AccountProvider | None = None,
        grants: EnrollmentGrants | None = None,
        currency: str = "AUD",
        default_account: str = "OPERATING",
    ) -> None:
        self.payments = payments or SimulatedBank(currency=currency)
        self.accounts = accounts or SimulatedAccounts()
        self.grants = grants
        self.currency = currency
        self.default_account = default_account
        self.ledger: list[dict[str, Any]] = []
        self.handlers: dict[ActionType, Handler] = dict(handlers or {})

    def run(
        self, grant: ExecutionGrant, action: ActionType, params: dict[str, Any], requested_by: str = ""
    ) -> dict[str, Any]:
        if not isinstance(grant, ExecutionGrant):
            raise PermissionError("missing execution grant")
        key = f"pg-{grant.pending_id or grant.digest}"
        entry: dict[str, Any] = {"action": action.value, "params": params, "digest": grant.digest}
        handler = self.handlers.get(action)
        if handler is not None:  # real backend call (mailbox remediation)
            try:
                outcome = handler(params)
                ok = bool(outcome.get("ok", True))
            except Exception as e:  # noqa: BLE001 - report the failure; never leak secrets in it
                from ..connectors.secrets import redact

                ok, outcome = False, {"ok": False, "error": redact(f"{type(e).__name__}: {e}")[:300]}
            entry.update(ok=ok, outcome=outcome)
            self.ledger.append(entry)
            return {"ok": ok, "effect_index": len(self.ledger) - 1, "outcome": outcome}
        try:
            out = self._dispatch(action, params, requested_by, key)
            entry.update(ok=True, ref=out.get("transaction_id") or out.get("reference") or out.get("payee_id"))
        except PaymentError as e:
            out = {"ok": False, **e.to_dict()}
            entry.update(ok=False, error=e.code)
        except NotImplementedError as e:
            out = {"ok": False, **ProviderNotImplemented(str(e)).to_dict()}
            entry.update(ok=False, error=ProviderNotImplemented.code)
        self.ledger.append(entry)
        return {"ok": True, **out, "effect_index": len(self.ledger) - 1}

    # -- dispatch -------------------------------------------------------------------------------
    def _dispatch(self, action: ActionType, p: dict[str, Any], user: str, key: str) -> dict[str, Any]:
        A = ActionType
        if action == A.TRANSFER_FUNDS:
            req = TransferRequest(
                from_account=check_id(_first(p, "from_account", default=self.default_account), "from_account"),
                payee_id=check_id(_first(p, "payee_id", "to", "payee"), "payee_id"),
                amount=parse_amount(p.get("amount")),
                currency=str(_first(p, "currency", default=self.currency)).upper()[:3],
                reference=str(_first(p, "reference", "memo", default=""))[:140],
            )
            tx = self.payments.transfer(req, idempotency_key=key)
            return {"transaction_id": tx.id, "transaction": tx.to_dict()}
        if action == A.PAY_INVOICE:
            req = InvoicePaymentRequest(
                invoice_id=check_id(_first(p, "invoice_id", "invoice"), "invoice_id"),
                from_account=check_id(_first(p, "from_account", default=self.default_account), "from_account"),
            )
            tx = self.payments.pay_invoice(req, idempotency_key=key)
            return {"transaction_id": tx.id, "transaction": tx.to_dict()}
        if action == A.APPROVE_INVOICE:
            r = self.payments.approve_invoice(
                check_id(_first(p, "invoice_id", "invoice"), "invoice_id"), idempotency_key=key
            )
            return {"invoice": r.to_dict(), "reference": r.invoice_id}
        if action == A.CHANGE_BANK_DETAILS:
            payee = check_id(_first(p, "payee_id", "payee"), "payee_id")
            details: BankDetails = validate_details(p)
            r = self.payments.change_bank_details(
                payee, details, idempotency_key=key, name=_first(p, "payee_name", default=None)
            )
            return {"payee_id": r.payee_id, "bank_details_change": r.to_dict()}
        target = str(_first(p, "user", default=user))
        if action == A.RESET_PASSWORD:
            r = self.accounts.reset_password(target, idempotency_key=key)
            return {"reference": r.reference, "account_action": r.to_dict()}
        if action == A.CHANGE_ACCOUNT_EMAIL:
            r = self.accounts.change_account_email(target, _first(p, "new_email", "email"), idempotency_key=key)
            return {"reference": r.reference, "account_action": r.to_dict()}
        if action == A.CHANGE_ACCOUNT_SETTINGS:
            settings = (
                p.get("settings")
                if isinstance(p.get("settings"), dict)
                else {k: v for k, v in p.items() if k != "user"}
            )
            r = self.accounts.change_account_settings(target, settings, idempotency_key=key)
            return {"reference": r.reference, "account_action": r.to_dict()}
        if action == A.ADD_MFA_FACTOR:
            method = p.get("method")
            if method not in CATEGORY or self.grants is None:
                raise InvalidRequest(f"method must be one of {sorted(CATEGORY)}")
            token, exp = self.grants.issue(user, method)
            # the token goes back to the approver only; the ledger entry and the audit log never hold it
            return {"enrollment_token": token, "method": method, "user": user, "expires_at": exp}
        # mail actions without a handler: recorded only
        return {"simulated": True}
