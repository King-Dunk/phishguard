"""Shared response helpers for the MFA and payments routers (and the few MFA routes still in api.py)."""

from __future__ import annotations

import json
from contextlib import contextmanager
from typing import Any

from fastapi import HTTPException
from fastapi.responses import JSONResponse

from ..mutating import (
    FactorAlreadyUsed,
    FactorLocked,
    FactorNotAvailable,
    FactorResult,
    MFAFailed,
    MFAGateway,
    MFAIncomplete,
    OperationLocked,
    PendingExpired,
    PendingFinalized,
    PendingNotFound,
    SubmitResult,
)


class AsciiJSON(JSONResponse):
    """Same encoding as api.SafeJSONResponse (ASCII escapes, so lone surrogates can't crash a response)."""

    def render(self, content: Any) -> bytes:
        return json.dumps(content, ensure_ascii=True, separators=(",", ":"), default=str).encode("ascii")


@contextmanager
def mfa_errors():
    """Map gateway exceptions to HTTP status codes, identically for every MFA route."""
    try:
        yield
    except PendingNotFound:
        raise HTTPException(404, "unknown pending action") from None
    except PendingExpired:
        raise HTTPException(410, "MFA timed out; action rejected") from None
    except PendingFinalized as e:
        raise HTTPException(409, str(e)) from None
    except FactorAlreadyUsed as e:
        raise HTTPException(409, str(e)) from None
    except FactorNotAvailable as e:
        raise HTTPException(400, str(e)) from None
    except OperationLocked as e:
        raise HTTPException(423, {"error": str(e), "locked_until": e.until}) from None
    except FactorLocked as e:
        raise HTTPException(423, {"error": str(e), "method": e.method, "locked_until": e.until}) from None
    except MFAFailed as e:
        raise HTTPException(403, {"error": str(e), "attempts_left": e.attempts_left}) from None


def _next_hint(res: FactorResult) -> str:
    if res.needs_non_knowledge:
        return "one more factor required, and it must be totp or webauthn (two knowledge factors are not enough)"
    return f"{res.remaining} more factor(s) required: POST /mfa/factor with a different method"


def factor_response(res: FactorResult) -> JSONResponse:
    if res.status == "executed":
        return AsciiJSON({"status": "executed", "result": res.result, "factors": res.satisfied}, status_code=200)
    if res.status == "declined":  # MFA passed, provider refused (cooling-off, limit, funds, bad params)
        return AsciiJSON({"status": "declined", "result": res.result, "factors": res.satisfied}, status_code=422)
    return AsciiJSON(
        {
            "status": "pending_mfa",
            "pending_id": res.pending_id,
            "accepted": res.method,
            "factors_satisfied": res.satisfied,
            "factors_remaining": res.remaining,
            "needs_non_knowledge": res.needs_non_knowledge,
            "factors_available": res.available,
            "next": _next_hint(res),
        },
        status_code=202,
    )


def pending_response(res: SubmitResult) -> JSONResponse:
    if res.method in ("totp", "channel"):  # dev single-factor flow: unchanged response
        nxt = "authenticator app code" if res.method == "totp" else "out-of-band code"
        hint = f"POST /mfa/verify with the {nxt} and confirm_digest"
    elif res.approvable:
        hint = "POST /mfa/factor (and /mfa/challenge for webauthn or security_questions) with confirm_digest"
    else:
        hint = "requester is not enrolled in enough factors to satisfy the policy; an administrator must enroll them"
    return AsciiJSON(
        {
            "status": "pending_mfa",
            "pending_id": res.pending_id,
            "confirm_digest": res.digest,
            "summary": res.summary,
            "expires_at": res.expires_at,
            "mfa_method": res.method,
            "mfa_policy": res.policy,
            "factors_available": res.factors_available,
            "approvable": res.approvable,
            "next": hint,
        },
        status_code=202,
    )


def verify_code(gateway: MFAGateway, pending_id: str, code: str, confirm_digest: str) -> JSONResponse:
    """POST /mfa/verify: the code-only route. In the multi-factor flow the code is the TOTP factor."""
    with mfa_errors():
        try:
            result = gateway.verify(pending_id, code, confirm_digest)
        except MFAIncomplete as e:
            return factor_response(e.result)
    status = "declined" if result.get("ok") is False else "executed"
    return AsciiJSON({"status": status, "result": result}, status_code=422 if status == "declined" else 200)
