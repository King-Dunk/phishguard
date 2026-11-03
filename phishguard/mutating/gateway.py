"""MFA gateway. Sensitive actions are suspended here, in code, regardless of any LLM output.

Flow: submit -> PENDING (TOTP from the requester's authenticator, or a one-time code sent
      out-of-band) -> verify(code + digest echo = double check)
      -> EXECUTED | REJECTED (bad code x N / lockout) | EXPIRED (timeout, auto-reject)

Two failure limits:
- per pending action: `max_attempts` bad tries reject that action;
- per operation (requester + action type): `lockout_threshold` consecutive failures across
  any number of pending actions lock that operation for `lockout_seconds`. Without this an
  attacker could open new pending actions forever and keep guessing.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
import time
from dataclasses import asdict, dataclass
from typing import Any

from .audit import AuditLog
from .executor import Executor, _issue_grant
from .mfa import MFAChannel, StderrChannel
from .policy import ActionType, parse_action_type, requires_mfa
from .totp import TOTPManager


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


class OperationLocked(RuntimeError):
    def __init__(self, key: str, until: float):
        super().__init__(f"operation {key} locked after repeated MFA failures")
        self.until = until


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
    method: str = "channel"  # channel | totp

    def to_row(self) -> dict[str, Any]:
        return {**asdict(self), "action": self.action.value}

    @classmethod
    def from_row(cls, d: dict[str, Any]) -> _Pending:
        return cls(**{**d, "action": ActionType(d["action"])})


@dataclass
class SubmitResult:
    status: str  # "executed" | "pending_mfa"
    result: dict[str, Any] | None = None
    pending_id: str | None = None
    digest: str | None = None
    summary: str | None = None
    expires_at: float | None = None
    method: str | None = None


def action_digest(action: ActionType, params: dict[str, Any], requested_by: str) -> str:
    blob = json.dumps({"a": action.value, "p": params, "u": requested_by}, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def _hash(salt: str, code: str) -> str:
    return hashlib.sha256((salt + code).encode()).hexdigest()


def _op_key(requested_by: str, action: ActionType) -> str:
    return f"{requested_by}:{action.value}"


class MFAGateway:
    def __init__(
        self,
        executor: Executor | None = None,
        audit: AuditLog | None = None,
        channel: MFAChannel | None = None,
        timeout_seconds: int = 120,
        max_attempts: int = 3,
        clock=time.time,
        totp: TOTPManager | None = None,
        store=None,
        lockout_threshold: int = 5,
        lockout_seconds: int = 900,
    ):
        self.executor = executor or Executor()
        self.audit = audit or AuditLog(clock=clock, store=store)
        self.channel = channel or StderrChannel()
        self.totp = totp
        self.timeout = timeout_seconds
        self.max_attempts = max_attempts
        self.lockout_threshold = lockout_threshold
        self.lockout_seconds = lockout_seconds
        self._clock = clock
        self._store = store
        self._locks_mem: dict[str, tuple[int, float]] = {}
        self._pending: dict[str, _Pending] = {}
        if store:
            self._pending = {d["id"]: _Pending.from_row(d) for d in store.load_pending()}
        self._lock = threading.Lock()

    # -- public API ---------------------------------------------------------
    def submit(self, action_type: str, params: dict[str, Any], requested_by: str, reason: str = "") -> SubmitResult:
        action = parse_action_type(action_type)  # raises UnknownActionError (default deny)
        digest = action_digest(action, params, requested_by)
        if not requires_mfa(action, params, reason):
            self.audit.record("action_executed", action=action.value, digest=digest, by=requested_by, mfa=False)
            return SubmitResult("executed", result=self.executor.run(_issue_grant(digest), action, params))

        key = _op_key(requested_by, action)
        pid = secrets.token_urlsafe(12)
        method = "totp" if self.totp and self.totp.is_enrolled(requested_by) else "channel"
        code = f"{secrets.randbelow(10**6):06d}"
        salt = secrets.token_hex(8)
        expires = self._clock() + self.timeout
        summary = f"{action.value} (digest {digest}) requested by {requested_by}"
        with self._lock:
            self._check_locked(key)
            self._sweep_locked()
            p = _Pending(
                pid,
                action,
                params,
                requested_by,
                reason,
                digest,
                expires,
                salt,
                _hash(salt, code) if method == "channel" else "",
                method=method,
            )
            self._pending[pid] = p
            self._persist(p)
        self.audit.record(
            "action_suspended",
            pending_id=pid,
            action=action.value,
            digest=digest,
            by=requested_by,
            param_keys=sorted(params),
            method=method,
        )
        if method == "channel":
            self.channel.deliver(pid, code, summary)
        return SubmitResult(
            "pending_mfa", pending_id=pid, digest=digest, summary=summary, expires_at=expires, method=method
        )

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
            key = _op_key(p.requested_by, p.action)
            self._check_locked(key)

            left = self.max_attempts - p.attempts - 1
            digest_ok = hmac.compare_digest(str(confirm_digest), p.digest)
            if p.method == "totp":
                # only burn a TOTP step when the digest matches, so a typo in the digest doesn't waste a code
                code_ok = digest_ok and self.totp is not None and self.totp.verify(p.requested_by, str(code))
            else:
                code_ok = hmac.compare_digest(_hash(p.salt, str(code)), p.code_hash)
            if not (digest_ok and code_ok):
                p.attempts += 1
                reason = "digest_mismatch" if not digest_ok else "bad_code"
                self.audit.record("mfa_failed", pending_id=p.id, reason=reason, attempts=p.attempts)
                fails = self._bump_failures(key)
                if fails >= self.lockout_threshold:
                    until = self._clock() + self.lockout_seconds
                    self._set_lock(key, fails, until)
                    p.state = "rejected"
                    self._persist(p)
                    self.audit.record(
                        "operation_locked", key=key, consecutive_failures=fails, until=until, pending_id=p.id
                    )
                    self.audit.record("action_rejected", pending_id=p.id, reason="operation_locked", digest=p.digest)
                    raise OperationLocked(key, until)
                if left <= 0:
                    p.state = "rejected"
                    self._persist(p)
                    self.audit.record("action_rejected", pending_id=p.id, reason="too_many_attempts", digest=p.digest)
                    raise MFAFailed("too many failed attempts; action rejected", 0)
                self._persist(p)
                raise MFAFailed(f"verification failed ({reason})", left)

            p.state = "executed"
            self._persist(p)
            self._set_lock(key, 0, 0.0)  # success resets the consecutive-failure counter
            result = self.executor.run(_issue_grant(p.digest), p.action, p.params)
            self.audit.record(
                "action_executed", pending_id=p.id, action=p.action.value, digest=p.digest, by=p.requested_by, mfa=True
            )
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
    def _persist(self, p: _Pending) -> None:
        if self._store:
            self._store.save_pending(p.id, p.to_row())

    def _get_lock(self, key: str) -> tuple[int, float]:
        return self._store.get_lockout(key) if self._store else self._locks_mem.get(key, (0, 0.0))

    def _set_lock(self, key: str, fails: int, until: float) -> None:
        if self._store:
            self._store.put_lockout(key, fails, until)
        else:
            self._locks_mem[key] = (fails, until)

    def _bump_failures(self, key: str) -> int:
        fails, until = self._get_lock(key)
        self._set_lock(key, fails + 1, until)
        return fails + 1

    def _check_locked(self, key: str) -> None:
        fails, until = self._get_lock(key)
        if until and self._clock() < until:
            self.audit.record("operation_blocked", key=key, until=until)
            raise OperationLocked(key, until)
        if until:  # lock expired: start counting again
            self._set_lock(key, 0, 0.0)

    def _sweep_locked(self) -> int:
        now = self._clock()
        n = 0
        for p in self._pending.values():
            if p.state == "pending" and now >= p.expires_at:
                p.state = "expired"
                self._persist(p)
                n += 1
                self.audit.record(
                    "action_rejected",
                    pending_id=p.id,
                    reason="mfa_timeout",
                    digest=p.digest,
                    action=p.action.value,
                    by=p.requested_by,
                )
        return n
