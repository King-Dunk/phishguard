"""Builds the gateway, factors and providers from Settings. One place, so api.py stays thin."""

from __future__ import annotations

import time

from .audit import AuditLog
from .executor import Executor
from .factors import EnrollmentGrants, FactorRegistry, MFAPolicy
from .gateway import MFAGateway
from .kv import KV
from .password import PasswordManager
from .payments import build_account_provider, build_payment_provider
from .questions import SecurityQuestionManager
from .totp import TOTPManager
from .webauthn_factor import WebAuthnManager


def build_factors(mfa, store=None, clock=time.time) -> FactorRegistry:
    kv = KV(store)
    return FactorRegistry(
        totp=TOTPManager(store=store, clock=clock),
        password=PasswordManager(
            kv,
            clock,
            min_length=mfa.password_min_length,
            lockout_threshold=mfa.password_lockout_threshold,
            lockout_seconds=mfa.password_lockout_seconds,
            time_cost=mfa.argon2_time_cost,
            memory_kib=mfa.argon2_memory_kib,
        ),
        questions=SecurityQuestionManager(
            kv,
            clock,
            min_enrolled=mfa.questions_min_enrolled,
            per_challenge=mfa.questions_per_challenge,
            max_failures=mfa.questions_max_failures,
            window_seconds=mfa.questions_window_seconds,
            time_cost=mfa.argon2_time_cost,
            memory_kib=mfa.argon2_memory_kib,
        ),
        webauthn=WebAuthnManager(
            kv,
            clock,
            rp_id=mfa.webauthn_rp_id,
            rp_name=mfa.webauthn_rp_name,
            origins=mfa.webauthn_origins,
            challenge_seconds=mfa.webauthn_challenge_seconds,
        ),
        grants=EnrollmentGrants(kv, clock, mfa.enrollment_token_seconds),
    )


def build_policy(mfa) -> MFAPolicy:
    return MFAPolicy(
        required=mfa.required_factors,
        allow_knowledge_only=mfa.allow_knowledge_only,
        dev_single_factor=mfa.dev_single_factor,
    )


def build_gateway(settings, store=None, channel=None, clock=None, handlers=None) -> MFAGateway:
    """`handlers`: real backends for mail actions (mailbox.remediation_handlers); money and account
    actions always go to the configured providers."""
    clock = clock or time.time
    factors = build_factors(settings.mfa, store, clock)
    executor = Executor(
        handlers,
        payments=build_payment_provider(settings.payments, store, clock),
        accounts=build_account_provider(settings.payments, store, clock),
        grants=factors.grants,
        currency=settings.payments.currency,
    )
    return MFAGateway(
        executor=executor,
        audit=AuditLog(settings.audit_log_path, store=store, clock=clock),
        channel=channel,
        timeout_seconds=settings.mfa_timeout_seconds,
        max_attempts=settings.mfa_max_attempts,
        totp=factors.totp,
        store=store,
        lockout_threshold=settings.mfa_lockout_threshold,
        lockout_seconds=settings.mfa_lockout_seconds,
        clock=clock,
        factors=factors,
        policy=build_policy(settings.mfa),
    )
