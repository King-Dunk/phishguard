"""Payment and account providers behind interfaces. The executor only sees PaymentProvider/AccountProvider."""

from __future__ import annotations

import time

from .adapters import IdentityProviderAdapter, Iso20022BankAdapter, MYOBAdapter, StripeAdapter, XeroAdapter
from .base import (
    AccountProvider,
    BankDetails,
    CoolingOff,
    IdempotencyConflict,
    InsufficientFunds,
    InvalidRequest,
    InvoicePaymentRequest,
    LimitExceeded,
    PayeeNotFound,
    PaymentError,
    PaymentProvider,
    ProviderNotImplemented,
    Transaction,
    TransferRequest,
    TxStatus,
)
from .simulated import SimulatedAccounts, SimulatedBank

PAYMENT_PROVIDERS = {
    "simulated": SimulatedBank,
    "iso20022": Iso20022BankAdapter,
    "stripe": StripeAdapter,
    "xero": XeroAdapter,
    "myob": MYOBAdapter,
}


def build_payment_provider(cfg, store=None, clock=time.time) -> PaymentProvider:
    """Pick the provider named in config. Unknown names fail at startup, not at the first payment."""
    name = cfg.provider
    if name not in PAYMENT_PROVIDERS:
        raise ValueError(f"unknown payment provider {name!r}; one of {sorted(PAYMENT_PROVIDERS)}")
    if name == "simulated":
        return SimulatedBank(
            store=store,
            clock=clock,
            currency=cfg.currency,
            cooling_off_seconds=cfg.cooling_off_seconds,
            daily_limit=cfg.daily_limit,
            per_transfer_limit=cfg.per_transfer_limit,
            seed=cfg.seed_demo_data,
        )
    return PAYMENT_PROVIDERS[name](cfg.options)


def build_account_provider(cfg, store=None, clock=time.time) -> AccountProvider:
    return SimulatedAccounts(store=store, clock=clock)


__all__ = [
    "AccountProvider",
    "BankDetails",
    "CoolingOff",
    "IdempotencyConflict",
    "IdentityProviderAdapter",
    "InsufficientFunds",
    "InvalidRequest",
    "InvoicePaymentRequest",
    "LimitExceeded",
    "PayeeNotFound",
    "PaymentError",
    "PaymentProvider",
    "ProviderNotImplemented",
    "SimulatedAccounts",
    "SimulatedBank",
    "Transaction",
    "TransferRequest",
    "TxStatus",
    "build_account_provider",
    "build_payment_provider",
]
