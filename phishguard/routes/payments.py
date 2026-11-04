"""Read-only payment routes: balances, transaction history and status, payee (masked details + cooling-off).

There is deliberately no route here that moves money or edits a payee: those are actions and go through
POST /actions and the MFA gateway like everything else.
"""

from __future__ import annotations

from contextlib import contextmanager

from fastapi import APIRouter, HTTPException, Query

from ..mutating.payments.base import (
    AccountNotFound,
    InvalidRequest,
    PayeeNotFound,
    PaymentError,
    PaymentProvider,
    TransactionNotFound,
)


@contextmanager
def _errors():
    try:
        yield
    except (AccountNotFound, PayeeNotFound, TransactionNotFound) as e:
        raise HTTPException(404, e.to_dict()) from None
    except InvalidRequest as e:
        raise HTTPException(400, e.to_dict()) from None
    except PaymentError as e:
        raise HTTPException(502, e.to_dict()) from None
    except NotImplementedError as e:
        raise HTTPException(501, str(e)) from None


def build_payments_router(provider: PaymentProvider, protected) -> APIRouter:
    r = APIRouter()

    @r.get("/payments/accounts", dependencies=protected)
    def accounts():
        with _errors():
            return {"provider": provider.name, "accounts": [a.to_dict() for a in provider.list_accounts()]}

    @r.get("/payments/accounts/{account}/transactions", dependencies=protected)
    def transactions(account: str, limit: int = Query(50, ge=1, le=500)):
        with _errors():
            return {
                "account": account,
                "transactions": [t.to_dict() for t in provider.list_transactions(account[:64], limit)],
            }

    @r.get("/payments/transactions/{tx_id}", dependencies=protected)
    def status(tx_id: str):
        with _errors():
            return provider.get_status(tx_id[:64]).to_dict()

    @r.get("/payments/payees/{payee_id}", dependencies=protected)
    def payee(payee_id: str):
        with _errors():
            return provider.get_payee(payee_id[:64]).to_dict()

    return r
