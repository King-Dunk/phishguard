"""Settings for multi-factor approval and the payment provider. Plain data, imports nothing from mutating/.

Kept apart from config.py so the MFA/payments knobs live in one place and config.py only nests them.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env_int(name: str, default: int) -> int:
    return int(os.environ.get(name, str(default)))


def _env_csv(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return tuple(x.strip() for x in raw.split(",") if x.strip())


@dataclass(frozen=True)
class MFAConfig:
    # --- policy ---
    required_factors: int = 2  # distinct methods needed before a pending action is released
    # Password and security questions are both "something you know". By default two of them are not
    # enough: at least one factor must be TOTP or WebAuthn (NIST SP 800-63B; see DESIGN.md Q43).
    allow_knowledge_only: bool = False
    # DEV ONLY: the old flow (one TOTP code, or a console code for users without TOTP).
    dev_single_factor: bool = False
    # --- password ---
    password_min_length: int = 8
    password_lockout_threshold: int = 5  # consecutive wrong passwords per user
    password_lockout_seconds: int = 900
    argon2_time_cost: int = 2  # OWASP minimum for argon2id: m=19 MiB, t=2, p=1
    argon2_memory_kib: int = 19456
    # --- security questions ---
    questions_min_enrolled: int = 3
    questions_per_challenge: int = 2
    questions_max_failures: int = 3  # failed challenges per user per window
    questions_window_seconds: int = 3600
    # --- WebAuthn ---
    webauthn_rp_id: str = "localhost"  # must be a domain; browsers refuse IP addresses as RP ID
    webauthn_rp_name: str = "PhishGuard"
    webauthn_origins: tuple[str, ...] = ("http://localhost:8000",)
    webauthn_challenge_seconds: int = 120
    # --- enrollment ---
    enrollment_token_seconds: int = 300

    @classmethod
    def from_env(cls) -> MFAConfig:
        return cls(
            required_factors=_env_int("PHISHGUARD_MFA_REQUIRED_FACTORS", 2),
            allow_knowledge_only=os.environ.get("PHISHGUARD_MFA_ALLOW_KNOWLEDGE_ONLY") == "1",
            dev_single_factor=os.environ.get("PHISHGUARD_MFA_DEV_SINGLE_FACTOR") == "1",
            password_lockout_threshold=_env_int("PHISHGUARD_PASSWORD_LOCKOUT_THRESHOLD", 5),
            password_lockout_seconds=_env_int("PHISHGUARD_PASSWORD_LOCKOUT_SECONDS", 900),
            questions_per_challenge=_env_int("PHISHGUARD_QUESTIONS_PER_CHALLENGE", 2),
            questions_max_failures=_env_int("PHISHGUARD_QUESTIONS_MAX_FAILURES", 3),
            webauthn_rp_id=os.environ.get("PHISHGUARD_WEBAUTHN_RP_ID", "localhost"),
            webauthn_rp_name=os.environ.get("PHISHGUARD_WEBAUTHN_RP_NAME", "PhishGuard"),
            webauthn_origins=_env_csv("PHISHGUARD_WEBAUTHN_ORIGINS", ("http://localhost:8000",)),
        )


@dataclass(frozen=True)
class PaymentsConfig:
    provider: str = "simulated"  # simulated | iso20022 | stripe | xero | myob (stubs raise NotImplementedError)
    currency: str = "AUD"
    cooling_off_seconds: int = 86_400  # new or changed bank details: no payments for 24 h
    daily_limit: str = "100000.00"  # per account, per UTC day
    per_transfer_limit: str = "60000.00"
    seed_demo_data: bool = True  # demo accounts/payees/invoices when the bank is empty
    options: dict[str, str] = field(default_factory=dict)  # provider-specific (e.g. base URL); never secrets

    @classmethod
    def from_env(cls) -> PaymentsConfig:
        return cls(
            provider=os.environ.get("PHISHGUARD_PAYMENT_PROVIDER", "simulated").lower(),
            currency=os.environ.get("PHISHGUARD_CURRENCY", "AUD").upper(),
            cooling_off_seconds=_env_int("PHISHGUARD_COOLING_OFF_SECONDS", 86_400),
            daily_limit=os.environ.get("PHISHGUARD_DAILY_LIMIT", "100000.00"),
            per_transfer_limit=os.environ.get("PHISHGUARD_PER_TRANSFER_LIMIT", "60000.00"),
            seed_demo_data=os.environ.get("PHISHGUARD_PAYMENTS_SEED", "1") == "1",
        )
