"""Runtime settings. The API key is read ONLY from the environment."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

DEFAULT_MODEL = "claude-haiku-5-5"


def _csv(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return tuple(x.strip().lower() for x in raw.split(",") if x.strip())


@dataclass(frozen=True)
class Settings:
    model: str = DEFAULT_MODEL
    llm_mode: str = "mock"  # "mock" (default, offline) or "anthropic"
    max_steps: int = 6  # agent iteration circuit breaker
    max_tokens_per_request: int = 8000  # total token budget per /analyze call
    per_call_max_tokens: int = 1024
    mfa_timeout_seconds: int = 120
    mfa_max_attempts: int = 3
    audit_log_path: str | None = None
    trusted_domains: tuple[str, ...] = ("acme-corp.com",)
    executives: tuple[str, ...] = ()
    api_key: str | None = field(default=None, repr=False)

    @classmethod
    def from_env(cls) -> Settings:
        return cls(
            model=os.environ.get("PHISHGUARD_MODEL", DEFAULT_MODEL),
            llm_mode=os.environ.get("PHISHGUARD_LLM_MODE", "mock").lower(),
            max_steps=int(os.environ.get("PHISHGUARD_MAX_STEPS", "6")),
            max_tokens_per_request=int(os.environ.get("PHISHGUARD_MAX_TOKENS", "8000")),
            per_call_max_tokens=int(os.environ.get("PHISHGUARD_PER_CALL_MAX_TOKENS", "1024")),
            mfa_timeout_seconds=int(os.environ.get("PHISHGUARD_MFA_TIMEOUT", "120")),
            mfa_max_attempts=int(os.environ.get("PHISHGUARD_MFA_MAX_ATTEMPTS", "3")),
            audit_log_path=os.environ.get("PHISHGUARD_AUDIT_LOG"),
            trusted_domains=_csv("PHISHGUARD_TRUSTED_DOMAINS", ("acme-corp.com",)),
            executives=tuple(x.strip() for x in os.environ.get("PHISHGUARD_EXECUTIVES", "").split(",") if x.strip()),
            api_key=os.environ.get("ANTHROPIC_API_KEY"),
        )
