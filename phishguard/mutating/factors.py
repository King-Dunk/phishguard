"""Verification methods ("factors"), the multi-factor policy, per-user limiters and enrollment grants.

Methods and the NIST SP 800-63B category each one proves:
- password            something you know
- security_questions  something you know (weak: answers are often public or guessable)
- totp                something you have (the authenticator holding the shared secret)
- webauthn            something you have (the platform key) + something you are/know (Touch ID / PIN,
                      enforced by userVerification=required; the biometric never leaves the device)

The policy releases a pending action once `required` DISTINCT methods have passed and, unless
`allow_knowledge_only`, at least one of them is not a knowledge factor. Two things you know are one
thing an attacker can phish, so password + security questions alone never move money by default.
"""

from __future__ import annotations

import hashlib
import secrets
import threading
import time
import unicodedata
from dataclasses import dataclass
from typing import Any

from .kv import KV
from .policy import normalize_user

KNOWLEDGE = "knowledge"
POSSESSION = "possession"
CATEGORY = {
    "password": KNOWLEDGE,
    "security_questions": KNOWLEDGE,
    "totp": POSSESSION,
    "webauthn": POSSESSION,
}
METHODS = tuple(CATEGORY)
LEGACY_METHODS = ("totp", "channel")  # dev single-factor flow only


class FactorLocked(RuntimeError):
    """A per-user limiter for this method is active (wrong passwords, failed question challenges)."""

    def __init__(self, method: str, until: float):
        super().__init__(f"{method} temporarily locked after repeated failures")
        self.method = method
        self.until = until


class EnrollmentError(ValueError):
    """Enrollment input refused (weak password, too few questions, bad WebAuthn response...)."""


def parse_method(raw: Any) -> str | None:
    """Exact match only. 'TOTP', 'totp ' or 'webauthn\\u200b' are not silently mapped to a method:
    a factor name that needs cleaning up came from something other than our own client."""
    return raw if isinstance(raw, str) and raw in CATEGORY else None


@dataclass(frozen=True)
class MFAPolicy:
    required: int = 2
    allow_knowledge_only: bool = False
    dev_single_factor: bool = False  # the old one-code flow; development only

    def __post_init__(self) -> None:
        if self.dev_single_factor:
            return
        if self.required < 2:
            raise ValueError("required factors must be >= 2 (the single-factor flow needs the explicit dev flag)")
        if self.required > len(METHODS):
            raise ValueError(f"required factors must be <= {len(METHODS)} (number of distinct methods)")

    def satisfied(self, methods: list[str] | set[str]) -> bool:
        ms = set(methods) & set(METHODS)
        if len(ms) < self.required:
            return False
        return self.allow_knowledge_only or any(CATEGORY[m] != KNOWLEDGE for m in ms)

    def remaining(self, methods: list[str] | set[str]) -> int:
        ms = set(methods) & set(METHODS)
        need = max(0, self.required - len(ms))
        if not self.allow_knowledge_only and not any(CATEGORY[m] != KNOWLEDGE for m in ms):
            need = max(need, 1)
        return need

    def can_satisfy(self, available: list[str] | set[str]) -> bool:
        return self.satisfied(available)

    def describe(self) -> dict[str, Any]:
        if self.dev_single_factor:
            return {"mode": "dev_single_factor", "required": 1}
        return {
            "mode": "multi_factor",
            "required": self.required,
            "non_knowledge_required": not self.allow_knowledge_only,
        }


def normalize_secret(text: str) -> str:
    """NFKC (so fullwidth/compatibility forms of the same characters hash alike), drop invisible format
    characters (zero-width, bidi). Passwords keep case and inner spacing; answers are folded further."""
    s = unicodedata.normalize("NFKC", str(text))
    return "".join(ch for ch in s if unicodedata.category(ch) != "Cf")


def normalize_answer(text: str) -> str:
    """Security answers: also casefold and collapse whitespace, so 'Paris', ' paris ' and 'ＰＡＲＩＳ' match."""
    return " ".join(normalize_secret(text).casefold().split())


class UserLimiter:
    """Per-user failure limiter for one method, persisted in the KV store.

    `window_seconds=None`: lock after `threshold` CONSECUTIVE failures (passwords).
    `window_seconds=N`:    lock once `threshold` failures fall inside any N-second window (questions),
                           and a success does not wipe the window, so correct answers to a known
                           question can't be used to reset the count while guessing the others.
    """

    def __init__(self, kv: KV, clock, method: str, threshold: int, lock_seconds: int, window_seconds: int | None):
        self._kv, self._clock, self.method = kv, clock, method
        self.threshold, self.lock_seconds, self.window = threshold, lock_seconds, window_seconds
        self._lock = threading.Lock()

    def _key(self, user: str) -> str:
        return f"{self.method}:{normalize_user(user)}"

    def check(self, user: str) -> None:
        with self._lock:
            st = self._kv.get("factor_limit", self._key(user), {"fails": [], "until": 0.0})
            if st["until"] and self._clock() < st["until"]:
                raise FactorLocked(self.method, st["until"])

    def fail(self, user: str) -> float | None:
        """Record a failure; return the lock expiry if this failure triggered a lock."""
        with self._lock:
            now = self._clock()
            st = self._kv.get("factor_limit", self._key(user), {"fails": [], "until": 0.0})
            fails = [t for t in st["fails"] if self.window is None or now - t < self.window] + [now]
            until = 0.0
            if len(fails) >= self.threshold:
                until = now + self.lock_seconds if self.window is None else fails[0] + self.window
                fails = [] if self.window is None else fails
            self._kv.put("factor_limit", self._key(user), {"fails": fails, "until": until})
            return until or None

    def success(self, user: str) -> None:
        if self.window is not None:
            return
        with self._lock:
            self._kv.put("factor_limit", self._key(user), {"fails": [], "until": 0.0})


class EnrollmentGrants:
    """Single-use, short-lived tokens that let a user enroll a new factor without an admin key.

    Issued only by the executor when an `add_mfa_factor` action is released, i.e. after the user has
    passed the full multi-factor policy. Stored as SHA-256 so a database read does not yield tokens.
    """

    def __init__(self, kv: KV, clock=time.time, ttl_seconds: int = 300):
        self._kv, self._clock, self.ttl = kv, clock, ttl_seconds
        self._lock = threading.Lock()

    @staticmethod
    def _h(token: str) -> str:
        return hashlib.sha256(str(token).encode("utf-8", "replace")).hexdigest()

    def issue(self, user: str, method: str) -> tuple[str, float]:
        token = secrets.token_urlsafe(32)
        exp = self._clock() + self.ttl
        with self._lock:
            self._kv.put("enroll_grant", self._h(token), {"user": normalize_user(user), "method": method, "exp": exp})
        return token, exp

    def consume(self, token: str | None, user: str, method: str) -> bool:
        if not token:
            return False
        with self._lock:
            key = self._h(token)
            g = self._kv.get("enroll_grant", key)
            if g is None:
                return False
            ok = g["user"] == normalize_user(user) and g["method"] == method and self._clock() < g["exp"]
            if ok:  # only a matching use burns it, so a probe with the wrong user can't destroy a victim's grant
                self._kv.delete("enroll_grant", key)
            return ok


class FactorRegistry:
    """The verification methods this deployment offers. Any of them may be None (not offered)."""

    def __init__(self, totp=None, password=None, questions=None, webauthn=None, grants: EnrollmentGrants | None = None):
        self.totp, self.password, self.questions, self.webauthn = totp, password, questions, webauthn
        self.grants = grants

    def get(self, method: str):
        return {
            "totp": self.totp,
            "password": self.password,
            "security_questions": self.questions,
            "webauthn": self.webauthn,
        }.get(method)

    def enrolled(self, user: str) -> list[str]:
        return [m for m in METHODS if (f := self.get(m)) is not None and f.is_enrolled(user)]
