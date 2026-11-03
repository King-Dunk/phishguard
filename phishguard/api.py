"""FastAPI layer. /analyze is read-only; /actions and /mfa/verify go through the MFA gateway."""
from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from . import __version__
from .agent import PhishingAgent
from .config import Settings
from .llm import LLMClient, MockLLM
from .models import EmailMessage
from .mutating import (
    AuditLog,
    MFAChannel,
    MFAFailed,
    MFAGateway,
    PendingExpired,
    PendingFinalized,
    PendingNotFound,
    UnknownActionError,
)


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailMessage


class ActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")  # no hidden "skip_mfa"-style fields
    action_type: str = Field(max_length=64)
    params: dict[str, Any] = Field(default_factory=dict)
    requested_by: str = Field(min_length=1, max_length=100)
    reason: str = Field(default="", max_length=1000)


class VerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    pending_id: str = Field(max_length=64)
    code: str = Field(max_length=16)
    confirm_digest: str = Field(max_length=64)


def _build_llm(settings: Settings) -> LLMClient:
    if settings.llm_mode == "anthropic":
        from .llm.anthropic_client import AnthropicLLM

        return AnthropicLLM(settings)
    return MockLLM()


def create_app(
    settings: Settings | None = None,
    llm: LLMClient | None = None,
    channel: MFAChannel | None = None,
    clock=None,
) -> FastAPI:
    settings = settings or Settings.from_env()
    llm = llm or _build_llm(settings)
    kw = {"clock": clock} if clock else {}
    gateway = MFAGateway(
        audit=AuditLog(settings.audit_log_path, **kw),
        channel=channel,
        timeout_seconds=settings.mfa_timeout_seconds,
        max_attempts=settings.mfa_max_attempts,
        **kw,
    )
    agent = PhishingAgent(llm, settings)

    app = FastAPI(title="PhishGuard", version=__version__)
    app.state.gateway = gateway
    app.state.settings = settings

    @app.get("/health")
    def health():
        return {"status": "ok", "version": __version__, "llm_mode": settings.llm_mode, "model": settings.model}

    @app.post("/analyze")
    def analyze(req: AnalyzeRequest):
        r = agent.analyze(req.email)
        return {
            "email_id": req.email.id,
            "risk_percent": r.risk_percent,
            "is_phishing": r.risk_percent >= 50,
            "features": r.features,
            "steps_used": r.steps_used,
            "tokens_used": r.tokens_used,
            "circuit_break": r.circuit_break,
            "rationale": r.rationale,
        }

    @app.post("/actions")
    def actions(req: ActionRequest):
        try:
            res = gateway.submit(req.action_type, req.params, req.requested_by, req.reason)
        except UnknownActionError as e:
            raise HTTPException(400, str(e))
        if res.status == "executed":
            return {"status": "executed", "result": res.result}
        from fastapi.responses import JSONResponse

        return JSONResponse(
            status_code=202,
            content={
                "status": "pending_mfa",
                "pending_id": res.pending_id,
                "confirm_digest": res.digest,
                "summary": res.summary,
                "expires_at": res.expires_at,
                "next": "POST /mfa/verify with the out-of-band code and confirm_digest",
            },
        )

    @app.post("/mfa/verify")
    def mfa_verify(req: VerifyRequest):
        try:
            result = gateway.verify(req.pending_id, req.code, req.confirm_digest)
        except PendingNotFound:
            raise HTTPException(404, "unknown pending action")
        except PendingExpired:
            raise HTTPException(410, "MFA timed out; action rejected")
        except PendingFinalized as e:
            raise HTTPException(409, str(e))
        except MFAFailed as e:
            raise HTTPException(403, {"error": str(e), "attempts_left": e.attempts_left})
        return {"status": "executed", "result": result}

    return app


def get_app() -> FastAPI:  # uvicorn --factory phishguard.api:get_app
    return create_app()
