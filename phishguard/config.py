"""Runtime settings. The API key is read ONLY from the environment."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from .mfa_config import MFAConfig, PaymentsConfig

DEFAULT_MODEL = "claude-haiku-5-5"

# Risk score (0-100) at which a mail is flagged as phishing. 35, not 50: on the real-corpus test
# split (local run, 70/30 content-hash split) 50 caught only 35.0% of phishing while 35 caught 60.8%
# with easy_ham FPR 1.4% (vs 0.2%) and precision 97.5% (vs 98.7%). The cost is hard_ham (marketing-like
# legitimate mail): FPR 56.1% vs 21.2%. A missed phish costs more than a flagged newsletter, and the
# planned hybrid step sends exactly that 20-50 band to an LLM. Weights v4 at 35 (test split): recall
# 70.4%, easy_ham FPR 0.8%, hard_ham FPR 25.8%. See README "Real data results".
DEFAULT_THRESHOLD = 35.0


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
    phishing_threshold: float = DEFAULT_THRESHOLD
    # Hybrid "benign vote" (off by default; DESIGN Q67): the LLM may lower a rule score only inside the
    # gray zone, by at most llm_max_lower points, never below the zone's floor, and never when a hard
    # security signal fired. Unmeasured with a real model.
    llm_may_lower: bool = False
    llm_lower_zone: tuple[float, float] = (20.0, 50.0)
    llm_max_lower: float = 15.0
    mfa_timeout_seconds: int = 120
    mfa_max_attempts: int = 3
    audit_log_path: str | None = None
    trusted_domains: tuple[str, ...] = ("acme-corp.com",)
    executives: tuple[str, ...] = ()
    api_key: str | None = field(default=None, repr=False)
    # --- API hardening ---
    api_keys: tuple[str, ...] = field(default=(), repr=False)  # client keys for X-API-Key
    allow_unauthenticated: bool = True  # dataclass default is for tests; from_env() fails closed
    rate_limit_per_minute: int = 60
    db_path: str | None = None  # SQLite file for pending MFA, audit, TOTP, lockouts
    mfa_lockout_threshold: int = 5
    mfa_lockout_seconds: int = 900
    trusted_authserv_id: str | None = None  # only trust Authentication-Results stamped by this MTA
    admin_keys: tuple[str, ...] = field(default=(), repr=False)  # may call /mfa/enroll
    open_enrollment: bool = True  # dataclass default is for tests; from_env() requires an admin key
    max_body_bytes: int = 3_000_000
    mfa: MFAConfig = field(default_factory=MFAConfig)  # factors, policy, WebAuthn RP
    payments: PaymentsConfig = field(default_factory=PaymentsConfig)  # provider, limits, cooling-off

    @classmethod
    def from_env(cls) -> Settings:
        return cls(
            model=os.environ.get("PHISHGUARD_MODEL", DEFAULT_MODEL),
            llm_mode=os.environ.get("PHISHGUARD_LLM_MODE", "mock").lower(),
            max_steps=int(os.environ.get("PHISHGUARD_MAX_STEPS", "6")),
            max_tokens_per_request=int(os.environ.get("PHISHGUARD_MAX_TOKENS", "8000")),
            per_call_max_tokens=int(os.environ.get("PHISHGUARD_PER_CALL_MAX_TOKENS", "1024")),
            phishing_threshold=float(os.environ.get("PHISHGUARD_THRESHOLD", str(DEFAULT_THRESHOLD))),
            llm_may_lower=os.environ.get("PHISHGUARD_LLM_MAY_LOWER") == "1",
            mfa_timeout_seconds=int(os.environ.get("PHISHGUARD_MFA_TIMEOUT", "120")),
            mfa_max_attempts=int(os.environ.get("PHISHGUARD_MFA_MAX_ATTEMPTS", "3")),
            audit_log_path=os.environ.get("PHISHGUARD_AUDIT_LOG"),
            trusted_domains=_csv("PHISHGUARD_TRUSTED_DOMAINS", ("acme-corp.com",)),
            executives=tuple(x.strip() for x in os.environ.get("PHISHGUARD_EXECUTIVES", "").split(",") if x.strip()),
            api_key=os.environ.get("ANTHROPIC_API_KEY"),
            api_keys=tuple(k.strip() for k in os.environ.get("PHISHGUARD_API_KEYS", "").split(",") if k.strip()),
            allow_unauthenticated=os.environ.get("PHISHGUARD_ALLOW_NO_AUTH") == "1",
            rate_limit_per_minute=int(os.environ.get("PHISHGUARD_RATE_LIMIT", "60")),
            db_path=os.environ.get("PHISHGUARD_DB_PATH"),
            mfa_lockout_threshold=int(os.environ.get("PHISHGUARD_MFA_LOCKOUT_THRESHOLD", "5")),
            mfa_lockout_seconds=int(os.environ.get("PHISHGUARD_MFA_LOCKOUT_SECONDS", "900")),
            trusted_authserv_id=os.environ.get("PHISHGUARD_AUTHSERV_ID") or None,
            admin_keys=tuple(k.strip() for k in os.environ.get("PHISHGUARD_ADMIN_KEYS", "").split(",") if k.strip()),
            open_enrollment=os.environ.get("PHISHGUARD_OPEN_ENROLLMENT") == "1",
            max_body_bytes=int(os.environ.get("PHISHGUARD_MAX_BODY_BYTES", "3000000")),
            mfa=MFAConfig.from_env(),
            payments=PaymentsConfig.from_env(),
        )
