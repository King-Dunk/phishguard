"""MUTATING package: the only place state-changing actions live. Gated by the MFA gateway."""

from .audit import AuditLog
from .executor import Executor
from .factors import (
    EnrollmentError,
    EnrollmentGrants,
    FactorLocked,
    FactorRegistry,
    MFAPolicy,
)
from .gateway import (
    FactorAlreadyUsed,
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
from .kv import KV
from .mfa import CaptureChannel, MFAChannel, StderrChannel
from .password import PasswordManager
from .policy import ActionType, UnknownActionError, requires_mfa
from .questions import SecurityQuestionManager
from .store import SQLiteStore
from .totp import AlreadyEnrolled, TOTPManager
from .webauthn_factor import WebAuthnManager
from .wiring import build_factors, build_gateway, build_policy

__all__ = [
    "KV",
    "ActionType",
    "AlreadyEnrolled",
    "AuditLog",
    "CaptureChannel",
    "EnrollmentError",
    "EnrollmentGrants",
    "Executor",
    "FactorAlreadyUsed",
    "FactorLocked",
    "FactorNotAvailable",
    "FactorRegistry",
    "FactorResult",
    "MFAChannel",
    "MFAFailed",
    "MFAGateway",
    "MFAIncomplete",
    "MFAPolicy",
    "OperationLocked",
    "PasswordManager",
    "PendingExpired",
    "PendingFinalized",
    "PendingNotFound",
    "SQLiteStore",
    "SecurityQuestionManager",
    "StderrChannel",
    "SubmitResult",
    "TOTPManager",
    "UnknownActionError",
    "WebAuthnManager",
    "build_factors",
    "build_gateway",
    "build_policy",
    "requires_mfa",
]
