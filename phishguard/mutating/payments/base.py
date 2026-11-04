"""Provider interfaces for money and account actions, with typed requests, results and errors.

The executor talks only to these two interfaces. A real integration implements them (see
docs/PAYMENTS_INTEGRATION.md); the MFA gateway, policy and audit stay exactly as they are.

Contract every implementation must keep:
- Every state-changing call takes an `idempotency_key`. The same key with the same request returns the
  original result and changes nothing; the same key with a different request raises IdempotencyConflict.
  The executor derives the key from the pending action id, so a released action moves money at most once
  even if the call is retried after a crash or timeout.
- Failures are raised as PaymentError subclasses with a stable `code`; never return half-done results.
- No method may log or return full bank account numbers; use `mask()`.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from decimal import Decimal, InvalidOperation
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------- errors
class PaymentError(Exception):
    code = "payment_error"
    retryable = False

    def __init__(self, message: str, **details: Any):
        super().__init__(message)
        self.details = details

    def to_dict(self) -> dict[str, Any]:
        return {"error": self.code, "message": str(self), "retryable": self.retryable, **self.details}


class InvalidRequest(PaymentError):
    code = "invalid_request"


class AccountNotFound(PaymentError):
    code = "account_not_found"


class PayeeNotFound(PaymentError):
    code = "payee_not_found"


class InvoiceNotFound(PaymentError):
    code = "invoice_not_found"


class TransactionNotFound(PaymentError):
    code = "transaction_not_found"


class InsufficientFunds(PaymentError):
    code = "insufficient_funds"


class LimitExceeded(PaymentError):
    code = "limit_exceeded"


class CoolingOff(PaymentError):
    """Payee details were added or changed recently; payments are held until `until` (BEC control)."""

    code = "cooling_off"


class IdempotencyConflict(PaymentError):
    code = "idempotency_conflict"


class ProviderUnavailable(PaymentError):
    code = "provider_unavailable"
    retryable = True


class ProviderNotImplemented(PaymentError):
    code = "provider_not_implemented"


# ---------------------------------------------------------------------------- values
MAX_AMOUNT = Decimal("100000000000")  # 1e11, far above any limit; bounds arithmetic on hostile input


def parse_amount(value: Any) -> Decimal:
    """Positive decimal with at most 2 places. Floats go through str() so 0.1 stays 0.1."""
    if isinstance(value, bool) or value is None:
        raise InvalidRequest("amount is required and must be a number")
    try:
        d = Decimal(str(value).strip())
    except (InvalidOperation, ValueError):
        raise InvalidRequest("amount is not a number") from None
    if not d.is_finite() or d <= 0 or d > MAX_AMOUNT:
        raise InvalidRequest("amount must be positive and finite")
    if d != d.quantize(Decimal("0.01")):
        raise InvalidRequest("amount has more than 2 decimal places")
    return d.quantize(Decimal("0.01"))


def to_cents(d: Decimal) -> int:
    return int(d * 100)


def from_cents(c: int) -> str:
    return f"{Decimal(c) / 100:.2f}"


def mask(number: str | None) -> str | None:
    if not number:
        return number
    s = re.sub(r"\s", "", number)
    return ("*" * max(0, len(s) - 4)) + s[-4:]


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def check_id(value: Any, what: str) -> str:
    if not isinstance(value, str) or not _ID.match(value):
        raise InvalidRequest(f"{what} must be 1-64 characters of letters, digits, '.', '_' or '-'")
    return value


class TxStatus(str, Enum):
    SUBMITTED = "submitted"  # accepted by the provider, not yet settled (real rails)
    COMPLETED = "completed"  # settled (the simulator settles immediately)
    FAILED = "failed"
    REVERSED = "reversed"


@dataclass(frozen=True)
class BankDetails:
    account_name: str
    bsb: str | None = None  # Australian bank-state-branch, 6 digits
    account_number: str | None = None
    iban: str | None = None
    bic: str | None = None

    def masked(self) -> dict[str, Any]:
        return {
            "account_name": self.account_name,
            "bsb": self.bsb,
            "account_number": mask(self.account_number),
            "iban": mask(self.iban),
            "bic": self.bic,
        }


@dataclass(frozen=True)
class TransferRequest:
    from_account: str
    payee_id: str
    amount: Decimal
    currency: str
    reference: str = ""


@dataclass(frozen=True)
class InvoicePaymentRequest:
    invoice_id: str
    from_account: str


@dataclass
class Transaction:
    id: str
    kind: str  # transfer | invoice_payment
    status: TxStatus
    from_account: str
    payee_id: str
    amount: str  # decimal string, 2 places
    currency: str
    reference: str
    created_at: float
    idempotency_key: str
    invoice_id: str | None = None
    replayed: bool = False  # True when this result came from an idempotent retry

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d


@dataclass
class Payee:
    id: str
    name: str
    details: BankDetails
    status: str  # active | cooling_off
    cooling_off_until: float
    created_at: float
    changed_at: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "details": self.details.masked(),
            "status": self.status,
            "cooling_off_until": self.cooling_off_until,
            "created_at": self.created_at,
            "changed_at": self.changed_at,
        }


@dataclass
class Account:
    id: str
    name: str
    currency: str
    balance: str
    daily_limit: str
    daily_used: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class BankDetailsChange:
    payee_id: str
    created: bool  # new payee vs changed details
    effective_at: float  # payments allowed from this time (end of cooling-off)
    details: dict[str, Any]  # masked

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class InvoiceResult:
    invoice_id: str
    status: str  # open | approved | paid

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AccountActionResult:
    user: str
    action: str
    status: str
    reference: str
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------- interfaces
class PaymentProvider(ABC):
    """Money movement and payee management. Implementations: SimulatedBank, adapters.py stubs."""

    name = "abstract"

    @abstractmethod
    def transfer(self, req: TransferRequest, *, idempotency_key: str) -> Transaction: ...

    @abstractmethod
    def pay_invoice(self, req: InvoicePaymentRequest, *, idempotency_key: str) -> Transaction: ...

    @abstractmethod
    def approve_invoice(self, invoice_id: str, *, idempotency_key: str) -> InvoiceResult: ...

    @abstractmethod
    def get_payee(self, payee_id: str) -> Payee: ...

    @abstractmethod
    def change_bank_details(
        self, payee_id: str, details: BankDetails, *, idempotency_key: str, name: str | None = None
    ) -> BankDetailsChange: ...

    @abstractmethod
    def get_status(self, transaction_id: str) -> Transaction: ...

    @abstractmethod
    def list_transactions(self, account: str, limit: int = 50) -> list[Transaction]: ...

    @abstractmethod
    def list_accounts(self) -> list[Account]: ...


class AccountProvider(ABC):
    """Identity/account changes (an IdP or HR system in production: Entra ID, Okta, Google Workspace)."""

    name = "abstract"

    @abstractmethod
    def reset_password(self, user: str, *, idempotency_key: str) -> AccountActionResult: ...

    @abstractmethod
    def change_account_email(self, user: str, new_email: str, *, idempotency_key: str) -> AccountActionResult: ...

    @abstractmethod
    def change_account_settings(
        self, user: str, settings: dict[str, Any], *, idempotency_key: str
    ) -> AccountActionResult: ...
