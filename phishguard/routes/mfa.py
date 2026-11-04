"""Multi-factor routes: per-factor challenge/verify, enrollment of password / questions / passkeys,
and the localhost WebAuthn demo page.

Enrollment authorization (same rule as POST /mfa/enroll for TOTP): an admin key, OR a single-use
`X-Enrollment-Token` that the user obtained by approving an `add_mfa_factor` action with their current
factors (an already-verified session), OR PHISHGUARD_OPEN_ENROLLMENT=1 in development.
"""

from __future__ import annotations

import pathlib
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..mutating import AlreadyEnrolled, EnrollmentError, MFAGateway
from ..security import json_depth
from .common import AsciiJSON, factor_response, mfa_errors

STATIC = pathlib.Path(__file__).parent / "static"
MAX_RESPONSE_DEPTH = 8


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ChallengeRequest(_Strict):
    pending_id: str = Field(max_length=64)
    confirm_digest: str = Field(max_length=64)
    method: str = Field(max_length=32)


class FactorRequest(_Strict):
    pending_id: str = Field(max_length=64)
    confirm_digest: str = Field(max_length=64)
    method: str = Field(max_length=32)
    response: dict[str, Any] = Field(default_factory=dict)

    @field_validator("response")
    @classmethod
    def _shallow(cls, v: dict[str, Any]) -> dict[str, Any]:
        if json_depth(v) > MAX_RESPONSE_DEPTH:
            raise ValueError("response nested too deeply")
        return v


class PasswordEnroll(_Strict):
    user: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=256)


class QuestionItem(_Strict):
    question: str = Field(min_length=1, max_length=200)
    answer: str = Field(min_length=1, max_length=200)


class QuestionsEnroll(_Strict):
    user: str = Field(min_length=1, max_length=100)
    questions: list[QuestionItem] = Field(max_length=10)


class WebAuthnOptions(_Strict):
    user: str = Field(min_length=1, max_length=100)


class WebAuthnRegister(_Strict):
    user: str = Field(min_length=1, max_length=100)
    credential: dict[str, Any]

    @field_validator("credential")
    @classmethod
    def _shallow(cls, v: dict[str, Any]) -> dict[str, Any]:
        if json_depth(v) > MAX_RESPONSE_DEPTH:
            raise ValueError("credential nested too deeply")
        return v


def build_mfa_router(gateway: MFAGateway, settings, admin, protected) -> APIRouter:
    r = APIRouter()
    f = gateway.factors

    def enrollment_via(request: Request, user: str, method: str) -> str:
        """Return how this enrollment is authorized, or raise 403."""
        if settings.open_enrollment:
            return "open_enrollment"
        if admin.check(request.headers.get("x-api-key")) is not None:
            return "admin"
        if f.grants is not None and f.grants.consume(request.headers.get("x-enrollment-token"), user, method):
            return "enrollment_token"
        raise HTTPException(403, "enrollment requires an admin key or an X-Enrollment-Token for this user and method")

    def enrolled_event(user: str, method: str, via: str, **extra: Any) -> None:
        gateway.audit.record("factor_enrolled", user=user, method=method, via=via, **extra)

    # -- approval -------------------------------------------------------------------------------
    @r.post("/mfa/challenge", dependencies=protected)
    def mfa_challenge(req: ChallengeRequest):
        with mfa_errors():
            return gateway.challenge(req.pending_id, req.method, req.confirm_digest)

    @r.post("/mfa/factor", dependencies=protected)
    def mfa_factor(req: FactorRequest):
        with mfa_errors():
            return factor_response(gateway.verify_factor(req.pending_id, req.method, req.response, req.confirm_digest))

    @r.get("/mfa/pending/{pending_id}", dependencies=protected)
    def mfa_pending(pending_id: str):
        with mfa_errors():
            return gateway.status(pending_id[:64])

    @r.get("/mfa/factors/{user}", dependencies=protected)
    def mfa_factors(user: str):
        enrolled = f.enrolled(user[:100])
        return {
            "user": user[:100],
            "enrolled": enrolled,
            "policy": gateway.policy.describe(),
            "can_approve": gateway.policy.dev_single_factor or gateway.policy.can_satisfy(enrolled),
        }

    # -- enrollment -----------------------------------------------------------------------------
    @r.post("/mfa/enroll/password", dependencies=protected)
    def enroll_password(req: PasswordEnroll, request: Request):
        via = enrollment_via(request, req.user, "password")
        try:
            f.password.enroll(req.user, req.password)
        except AlreadyEnrolled:
            raise HTTPException(409, "password already set; reset requires an administrator") from None
        except EnrollmentError as e:
            raise HTTPException(422, str(e)) from None
        enrolled_event(req.user, "password", via)
        return {"user": req.user, "enrolled": "password"}

    @r.post("/mfa/enroll/questions", dependencies=protected)
    def enroll_questions(req: QuestionsEnroll, request: Request):
        via = enrollment_via(request, req.user, "security_questions")
        try:
            ids = f.questions.enroll(req.user, [q.model_dump() for q in req.questions])
        except AlreadyEnrolled:
            raise HTTPException(409, "security questions already set; reset requires an administrator") from None
        except EnrollmentError as e:
            raise HTTPException(422, str(e)) from None
        enrolled_event(req.user, "security_questions", via, count=len(ids))
        return {"user": req.user, "enrolled": "security_questions", "question_ids": ids}

    @r.post("/mfa/webauthn/register/options", dependencies=protected)
    def webauthn_options(req: WebAuthnOptions, request: Request):
        enrollment_via(request, req.user, "webauthn")
        return {"user": req.user, "publicKey": f.webauthn.registration_options(req.user)}

    @r.post("/mfa/webauthn/register/verify", dependencies=protected)
    def webauthn_register(req: WebAuthnRegister):
        # Authorized by the registration challenge, which only an authorized /options call created.
        try:
            cid = f.webauthn.register(req.user, req.credential)
        except EnrollmentError as e:
            gateway.audit.record("factor_enroll_failed", user=req.user, method="webauthn", reason=str(e)[:80])
            raise HTTPException(400, str(e)) from None
        enrolled_event(req.user, "webauthn", "registration_challenge", credential_id=cid[:16])
        return {"user": req.user, "enrolled": "webauthn", "credential_id": cid}

    # -- demo page ------------------------------------------------------------------------------
    if f.webauthn is not None and f.webauthn.rp_id == "localhost":

        @r.get("/demo/webauthn", include_in_schema=False)
        def webauthn_demo():
            return HTMLResponse((STATIC / "webauthn_demo.html").read_text(encoding="utf-8"))

    return r


__all__ = ["AsciiJSON", "build_mfa_router"]
