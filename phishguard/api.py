"""FastAPI layer. /analyze* is read-only; /actions and /mfa/* go through the MFA gateway.

Every route except /health needs `X-API-Key` (keys from PHISHGUARD_API_KEYS) and is rate
limited per key. Failed auth is rate limited per client address, which also slows key guessing.
"""

from __future__ import annotations

import json
import math
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from . import __version__
from .agent import AnalysisResult, PhishingAgent
from .config import Settings
from .llm import LLMClient, MockLLM
from .models import EmailMessage
from .mutating import (
    AlreadyEnrolled,
    AuditLog,
    MFAChannel,
    MFAFailed,
    MFAGateway,
    OperationLocked,
    PendingExpired,
    PendingFinalized,
    PendingNotFound,
    SQLiteStore,
    TOTPManager,
    UnknownActionError,
)
from .mutating.policy import MAX_PARAM_DEPTH
from .readonly import EmlTooComplex, EmlTooLarge, parse_eml
from .readonly.eml import MAX_RAW_BYTES
from .security import APIKeyAuth, BodySizeLimit, RateLimiter, json_depth


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailMessage


class AnalyzeEmlRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    raw: str = Field(max_length=MAX_RAW_BYTES)


class ActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")  # no hidden "skip_mfa"-style fields
    action_type: str = Field(max_length=64)
    params: dict[str, Any] = Field(default_factory=dict)
    requested_by: str = Field(min_length=1, max_length=100)
    reason: str = Field(default="", max_length=1000)

    @field_validator("params")
    @classmethod
    def _shallow(cls, v: dict[str, Any]) -> dict[str, Any]:
        # The policy also fails closed on deep params; rejecting here gives the caller a clear 422.
        if json_depth(v) > MAX_PARAM_DEPTH:
            raise ValueError(f"params nested deeper than {MAX_PARAM_DEPTH} levels")
        return v


class VerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    pending_id: str = Field(max_length=64)
    code: str = Field(max_length=16)
    confirm_digest: str = Field(max_length=64)


class EnrollRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    user: str = Field(min_length=1, max_length=100)


class SafeJSONResponse(JSONResponse):
    """ASCII-escaped JSON. Attacker text may hold lone UTF-16 surrogates ("\\ud800" is valid JSON);
    encoding those as UTF-8 raises and turned every echoing endpoint into a 500."""

    def render(self, content: Any) -> bytes:
        return json.dumps(content, ensure_ascii=True, separators=(",", ":"), default=str).encode("ascii")


def _build_llm(settings: Settings) -> LLMClient:
    if settings.llm_mode == "anthropic":
        from .llm.anthropic_client import AnthropicLLM

        return AnthropicLLM(settings)
    return MockLLM()


def _result(email_id: str, r: AnalysisResult, threshold: float) -> dict[str, Any]:
    return {
        "email_id": email_id,
        "risk_percent": r.risk_percent,
        "is_phishing": r.risk_percent >= threshold,
        "threshold": threshold,
        "features": r.features,  # sorted by contribution; contributions sum to the rule score
        "explanation": [f"{f['name']}: +{f['contribution']} ({f['evidence']})" for f in r.features],
        "steps_used": r.steps_used,
        "tokens_used": r.tokens_used,
        "circuit_break": r.circuit_break,
        "rationale": r.rationale,
    }


def create_app(
    settings: Settings | None = None,
    llm: LLMClient | None = None,
    channel: MFAChannel | None = None,
    clock=None,
) -> FastAPI:
    settings = settings or Settings.from_env()
    if not settings.api_keys and not settings.allow_unauthenticated:
        raise RuntimeError("Set PHISHGUARD_API_KEYS (or PHISHGUARD_ALLOW_NO_AUTH=1 for local development only)")
    llm = llm or _build_llm(settings)
    kw = {"clock": clock} if clock else {}
    store = SQLiteStore(settings.db_path) if settings.db_path else None
    gateway = MFAGateway(
        audit=AuditLog(settings.audit_log_path, store=store, **kw),
        channel=channel,
        timeout_seconds=settings.mfa_timeout_seconds,
        max_attempts=settings.mfa_max_attempts,
        totp=TOTPManager(store=store, **kw),
        store=store,
        lockout_threshold=settings.mfa_lockout_threshold,
        lockout_seconds=settings.mfa_lockout_seconds,
        **kw,
    )
    agent = PhishingAgent(llm, settings)
    auth = APIKeyAuth(settings.api_keys + settings.admin_keys)
    admin = APIKeyAuth(settings.admin_keys)
    limiter = RateLimiter(settings.rate_limit_per_minute, 60.0, **kw)

    def guard(request: Request) -> str:
        host = request.client.host if request.client else "unknown"
        key_id = auth.check(request.headers.get("x-api-key"))
        if auth.enabled and key_id is None:
            wait = limiter.hit(f"badauth:{host}")
            if wait is not None:
                raise HTTPException(429, "too many requests", headers={"Retry-After": str(math.ceil(wait))})
            raise HTTPException(401, "missing or invalid API key", headers={"WWW-Authenticate": "ApiKey"})
        bucket = f"key:{key_id}" if key_id else f"ip:{host}"
        wait = limiter.hit(bucket)
        if wait is not None:
            raise HTTPException(429, "rate limit exceeded", headers={"Retry-After": str(math.ceil(wait))})
        return bucket

    protected = [Depends(guard)]
    app = FastAPI(title="PhishGuard", version=__version__, default_response_class=SafeJSONResponse)

    @app.exception_handler(HTTPException)
    def _http_error(request: Request, exc: HTTPException):
        return SafeJSONResponse(status_code=exc.status_code, content={"detail": exc.detail}, headers=exc.headers)

    @app.exception_handler(RequestValidationError)
    def _invalid(request: Request, exc: RequestValidationError):
        return SafeJSONResponse(status_code=422, content={"detail": jsonable_encoder(exc.errors())})

    app.add_middleware(BodySizeLimit, max_bytes=settings.max_body_bytes)

    @app.exception_handler(RecursionError)
    def _too_deep(request: Request, exc: RecursionError):  # e.g. JSON body "[[[[...]]]]"
        return SafeJSONResponse(status_code=400, content={"detail": "input nested too deeply"})

    app.state.gateway = gateway
    app.state.settings = settings
    app.state.store = store

    @app.get("/health")
    def health():
        return {
            "status": "ok",
            "version": __version__,
            "llm_mode": settings.llm_mode,
            "model": settings.model,
            "auth": "enabled" if auth.enabled else "disabled",
            "persistence": "sqlite" if store else "memory",
        }

    @app.post("/analyze", dependencies=protected)
    def analyze(req: AnalyzeRequest):
        return _result(req.email.id, agent.analyze(req.email), settings.phishing_threshold)

    @app.post("/analyze/eml", dependencies=protected)
    def analyze_eml(req: AnalyzeEmlRequest):
        try:
            email = parse_eml(req.raw, settings.trusted_authserv_id)
        except EmlTooLarge as e:
            raise HTTPException(413, str(e)) from None
        except EmlTooComplex as e:
            raise HTTPException(422, str(e)) from None
        out = _result(email.id, agent.analyze(email), settings.phishing_threshold)
        out["parsed"] = {
            "from": f"{email.sender_name} <{email.sender_email}>",
            "reply_to": email.reply_to,
            "return_path": email.return_path,
            "auth": {"spf": email.spf, "dkim": email.dkim, "dmarc": email.dmarc},
            "attachments": [a.model_dump() for a in email.attachment_meta],
            "links": len(email.links),
        }
        return out

    @app.post("/actions", dependencies=protected)
    def actions(req: ActionRequest):
        try:
            res = gateway.submit(req.action_type, req.params, req.requested_by, req.reason)
        except UnknownActionError as e:
            raise HTTPException(400, str(e)) from None
        except OperationLocked as e:
            raise HTTPException(423, {"error": str(e), "locked_until": e.until}) from None
        if res.status == "executed":
            return {"status": "executed", "result": res.result}
        nxt = "authenticator app code" if res.method == "totp" else "out-of-band code"
        return SafeJSONResponse(
            status_code=202,
            content={
                "status": "pending_mfa",
                "pending_id": res.pending_id,
                "confirm_digest": res.digest,
                "summary": res.summary,
                "expires_at": res.expires_at,
                "mfa_method": res.method,
                "next": f"POST /mfa/verify with the {nxt} and confirm_digest",
            },
        )

    @app.post("/mfa/enroll", dependencies=protected)
    def mfa_enroll(req: EnrollRequest, request: Request):
        # Enrollment binds a second factor to an identity, so ordinary client keys may not do it:
        # otherwise any caller could enroll a victim first and then approve as them.
        if not settings.open_enrollment and admin.check(request.headers.get("x-api-key")) is None:
            raise HTTPException(403, "enrollment requires an admin key")
        try:
            uri = gateway.totp.enroll(req.user)
        except AlreadyEnrolled:
            raise HTTPException(409, "user already enrolled; reset requires an administrator") from None
        gateway.audit.record("totp_enrolled", user=req.user)
        return {"user": req.user, "otpauth_uri": uri}

    @app.post("/mfa/verify", dependencies=protected)
    def mfa_verify(req: VerifyRequest):
        try:
            result = gateway.verify(req.pending_id, req.code, req.confirm_digest)
        except PendingNotFound:
            raise HTTPException(404, "unknown pending action") from None
        except PendingExpired:
            raise HTTPException(410, "MFA timed out; action rejected") from None
        except PendingFinalized as e:
            raise HTTPException(409, str(e)) from None
        except OperationLocked as e:
            raise HTTPException(423, {"error": str(e), "locked_until": e.until}) from None
        except MFAFailed as e:
            raise HTTPException(403, {"error": str(e), "attempts_left": e.attempts_left}) from None
        return {"status": "executed", "result": result}

    @app.get("/audit/verify", dependencies=protected)
    def audit_verify():
        return {"chain_ok": gateway.audit.verify_chain(), "first_broken": gateway.audit.first_broken()}

    # Mailbox push notifications (separate module; mounted only when configured). Not behind X-API-Key:
    # Google/Microsoft can't send it, so each route authenticates the sender itself.
    from .connectors.webhooks import maybe_router

    if (hooks := maybe_router()) is not None:
        app.include_router(hooks)
    return app


def get_app() -> FastAPI:  # uvicorn --factory phishguard.api:get_app
    return create_app()
