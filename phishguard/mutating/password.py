"""Password re-authentication factor: argon2id hashes, constant-time verification, per-user lockout.

argon2-cffi's `verify` recomputes the hash and compares it in constant time. An unknown user is
checked against a dummy hash, so response time does not reveal who has a password.
"""

from __future__ import annotations

import threading
import time

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from .factors import EnrollmentError, UserLimiter, normalize_secret
from .kv import KV
from .policy import normalize_user
from .totp import AlreadyEnrolled

MAX_LENGTH = 128  # long enough for passphrases; bounds hashing work per request
# A short blocklist in the spirit of NIST SP 800-63B 3.1.1.2 (compare against known-compromised values).
# Production should check a breach corpus (e.g. a k-anonymity range API) instead.
COMMON = frozenset(
    {
        "password",
        "password1",
        "password123",
        "12345678",
        "123456789",
        "1234567890",
        "qwertyuiop",
        "qwerty123",
        "iloveyou",
        "letmein123",
        "welcome123",
        "admin123",
        "changeme",
        "phishguard",
    }
)


class PasswordManager:
    method = "password"

    def __init__(
        self,
        kv: KV | None = None,
        clock=time.time,
        min_length: int = 8,
        lockout_threshold: int = 5,
        lockout_seconds: int = 900,
        time_cost: int = 2,
        memory_kib: int = 19456,
    ):
        self._kv = kv or KV()
        self.min_length = min_length
        self._ph = PasswordHasher(time_cost=time_cost, memory_cost=memory_kib, parallelism=1, type=Type.ID)
        self._dummy = self._ph.hash("dummy-password-for-timing")
        self.limiter = UserLimiter(self._kv, clock, "password", lockout_threshold, lockout_seconds, None)
        self._lock = threading.Lock()

    def is_enrolled(self, user: str) -> bool:
        return self._kv.get("password", normalize_user(user)) is not None

    def enroll(self, user: str, password: str) -> None:
        pw = normalize_secret(password)
        if len(pw) < self.min_length:
            raise EnrollmentError(f"password must be at least {self.min_length} characters")
        if len(pw) > MAX_LENGTH:
            raise EnrollmentError(f"password must be at most {MAX_LENGTH} characters")
        if pw.casefold() in COMMON or pw.casefold() == normalize_user(user):
            raise EnrollmentError("password is too common")
        with self._lock:
            if self.is_enrolled(user):
                raise AlreadyEnrolled(user)  # same rule as TOTP: overwriting needs an administrator
            self._kv.put("password", normalize_user(user), {"hash": self._ph.hash(pw)})

    def verify(self, user: str, password: str) -> bool:
        """True/False; raises FactorLocked while this user's password is locked out."""
        self.limiter.check(user)
        rec = self._kv.get("password", normalize_user(user))
        pw = normalize_secret(password if isinstance(password, str) else "")[: MAX_LENGTH + 1]
        try:
            ok = self._ph.verify(rec["hash"] if rec else self._dummy, pw) and rec is not None
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            ok = False
        if ok:
            self.limiter.success(user)
        else:
            self.limiter.fail(user)
        return ok
