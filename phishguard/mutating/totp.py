"""TOTP (RFC 6238) via pyotp, with one-time use per time step (anti-replay).

A TOTP code stays valid for a whole 30 s window (and +-1 window for clock drift), so a
code seen over someone's shoulder or in a proxy log could be replayed. We remember the
last accepted time step per user and only accept a strictly newer step.
"""

from __future__ import annotations

import hmac
import threading
import time

import pyotp


class AlreadyEnrolled(RuntimeError):
    pass


class TOTPManager:
    def __init__(self, store=None, clock=time.time, issuer: str = "PhishGuard", interval: int = 30, drift: int = 1):
        self._store = store
        self._clock = clock
        self.issuer = issuer
        self.interval = interval
        self.drift = drift
        self._mem: dict[str, tuple[str, int]] = {}
        self._lock = threading.Lock()

    def _get(self, user: str) -> tuple[str, int] | None:
        return self._store.get_totp(user) if self._store else self._mem.get(user)

    def _put(self, user: str, secret: str, last_step: int) -> None:
        if self._store:
            self._store.put_totp(user, secret, last_step)
        else:
            self._mem[user] = (secret, last_step)

    def is_enrolled(self, user: str) -> bool:
        return self._get(user) is not None

    def enroll(self, user: str) -> str:
        """Create a secret and return the otpauth:// URI (render as QR). Refuses re-enrollment:
        overwriting a secret would let anyone holding an API key take over a user's MFA."""
        with self._lock:
            if self._get(user) is not None:
                raise AlreadyEnrolled(user)
            secret = pyotp.random_base32()
            self._put(user, secret, -1)
        return pyotp.TOTP(secret, interval=self.interval).provisioning_uri(name=user, issuer_name=self.issuer)

    def verify(self, user: str, code: str) -> bool:
        with self._lock:
            rec = self._get(user)
            if rec is None:
                return False
            secret, last_step = rec
            totp = pyotp.TOTP(secret, interval=self.interval)
            now_step = int(self._clock() // self.interval)
            for step in range(now_step - self.drift, now_step + self.drift + 1):
                if step > last_step and hmac.compare_digest(totp.generate_otp(step), str(code)):
                    self._put(user, secret, step)  # burn this step and every older one
                    return True
            return False
