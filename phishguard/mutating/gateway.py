"""MFA gateway. Sensitive actions are suspended here, in code, regardless of any LLM output.

Flow: submit -> PENDING (code sent out-of-band) -> verify(code + digest echo = double check)
      -> EXECUTED | REJECTED (bad code x N / digest mismatch) | EXPIRED (timeout, auto-reject)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from .audit import AuditLog
from .executor import Executor, _issue_grant
from .mfa import MFAChannel, StderrChannel
from .policy import ActionType, parse_action_type, requires_mfa


class PendingNotFound(KeyError):
    pass


class PendingFinalized(RuntimeError):
    pass


class PendingExpired(RuntimeError):
    pass


class MFAFailed(RuntimeError):
    def __init__(self, msg: str, attempts_left: int):
        super().__init__(msg)
        self.attempts_left = attempts_left


@dataclass
class _Pending:
    id: str
    action: ActionType
    params: dict[str, Any]
    requested_by: str
    reason: str
    digest: str
    expires_at: float
    salt: str
    code_hash: str
    state: str = "pending"  # pending | executed | rejected | expired
    attempts: int = 0


@dataclass
class SubmitResult:
    status: str  # "executed" | "pending_mfa"
    result: dict[str, Any] | None = None
    pending_id: str | None = None
    digest: str | None = None
    summary: str | None = None
    expires_at: float | None = None


def action_digest(action: ActionType, params: dict[str, Any], requested_by: str) -> str:
    blob = json.dumps({"a": action.value, "p": params, "u": requested_by}, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def _hash(salt: str, code: str) -> str:
    return hashlib.sha256((salt + code).encode()).hexdigest()


class MFAGateway:
    def __init__(
        self,
        executor: Executor | None = None,
        audit: AuditLog | None = None,
        channel: MFAChannel | None = None,
        timeout_seconds: int = 120,
        max_attempts: int = 3,
        clock=time.time,
    ):
        self.executor = executor or Executor()
        self.audit = audit or AuditLog(clock=clock)
        self.channel = channel or StderrChannel()
        self.timeout = timeout_seconds
        self.max_attempts = max_attempts
        self._clock = clock
        self._pending: dict[str, _Pending] = {}
        self._lock = threading.Lock()

    # -- public API ---------------------------------------------------------
    def submit(self, action_type: str, params: dict[str, Any], requested_by: str, reason: str = "") -> SubmitResult:
        action = parse_action_type(action_type)  # raises UnknownActionError (default deny)
        digest = action_digest(action, params, requested_by)
        if not requires_mfa(action, params, reason):
            self.audit.record("action_executed", action=action.value, digest=digest, by=requested_by, mfa=False)
            return SubmitResult("executed", result=self.executor.run(_issue_grant(digest), action, params))

        pid = secrets.token_urlsafe(12)
        code = f"{secrets.randbelow(10**6):06d}"
        salt = secrets.token_hex(8)
        expires = self._clock() + self.timeout
        summary = f"{action.value} (digest {digest}) requested by {requested_by}"
        with self._lock:
            self._sweep_locked()
            self._pending[pid] = _Pending(pid, action, params, requested_by, reason, digest, expires, salt, _hash(salt, code))
        self.audit.record("action_suspended", pending_id=pid, action=action.value, digest=digest, by=requested_by,
                          param_keys=sorted(params))
        self.channel.deliver(pid, code, summary)
        return SubmitResult("pending_mfa", pending_id=pid, digest=digest, summary=summary, expires_at=expires)

    def verify(self, pending_id: str, code: str, confirm_digest: str) -> dict[str, Any]:
        with self._lock:
            self._sweep_locked()
            p = self._pending.get(pending_id)
            if p is None:
                raise PendingNotFound(pending_id)
            if p.state == "expired":
                raise PendingExpired(pending_id)
            if p.state != "pending":
                raise PendingFinalized(f"{pending_id} is already {p.state}")

            left = self.max_attempts - p.attempts - 1
            digest_ok = hmac.compare_digest(str(confirm_digest), p.digest)
            code_ok = hmac.compare_digest(_hash(p.salt, str(code)), p.code_hash)
            if not (digest_ok and code_ok):
                p.attempts += 1
                reason = "digest_mismatch" if not digest_ok else "bad_code"
                self.audit.record("mfa_failed", pending_id=p.id, reason=reason, attempts=p.attempts)
                if left <= 0:
                    p.state = "rejected"
                    self.audit.record("action_rejected", pending_id=p.id, reason="too_many_attempts", digest=p.digest)
                    raise MFAFailed("too many failed attempts; action rejected", 0)
                raise MFAFailed(f"verification failed ({reason})", left)

            p.state = "executed"
            result = self.executor.run(_issue_grant(p.digest), p.action, p.params)
            self.audit.record("action_executed", pending_id=p.id, action=p.action.value, digest=p.digest,
                              by=p.requested_by, mfa=True)
            return result

    def sweep(self) -> int:
        with self._lock:
            return self._sweep_locked()

    def state_of(self, pending_id: str) -> str | None:
        with self._lock:
            self._sweep_locked()
            p = self._pending.get(pending_id)
            return p.state if p else None

    # -- internals ----------------------------------------------------------
    def _sweep_locked(self) -> int:
        now = self._clock()
        n = 0
        for p in self._pending.values():
            if p.state == "pending" and now >= p.expires_at:
                p.state = "expired"
                n += 1
                self.audit.record("action_rejected", pending_id=p.id, reason="mfa_timeout", digest=p.digest,
                                  action=p.action.value, by=p.requested_by)
        return n

