"""MFA gateway. Sensitive actions are suspended here, in code, regardless of any LLM output.

Flow (default, multi-factor):
    submit -> PENDING -> [challenge(method)] -> verify_factor(method, response, digest echo) ... repeated
           -> EXECUTED (policy satisfied: >= N distinct methods, at least one not a knowledge factor)
           |  DECLINED (released, but the provider refused: cooling-off, limit, funds)
           |  REJECTED (bad factors x N / lockout) | EXPIRED (timeout, auto-reject)

Every factor attempt is checked against the action digest the approver echoes back, and recorded in
the audit chain as method + result (never the code, password, answer or assertion).

Dev flow (`MFAPolicy(dev_single_factor=True)`, env PHISHGUARD_MFA_DEV_SINGLE_FACTOR=1): the original
one-code flow, TOTP if enrolled, otherwise a console code. Development only.

Two failure limits, shared by all methods:
- per pending action: `max_attempts` bad factor attempts reject that action;
- per operation (requester + action type): `lockout_threshold` consecutive failures across any number
  of pending actions lock that operation for `lockout_seconds`. Only a fully released action resets
  the counter; a single correct factor does not, or a stolen password could be used to reset the
  count between TOTP guesses.
Methods add their own per-user limits (password lockout, security-question rate limit).

The whole verification runs under one lock, so concurrent factor submissions for the same action are
serialized and the release (state -> executed, then one executor call) happens at most once.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from .audit import AuditLog
from .executor import Executor, _issue_grant
from .factors import CATEGORY, FactorLocked, FactorRegistry, MFAPolicy, parse_method
from .mfa import MFAChannel, StderrChannel
from .policy import ActionType, ct_equal, normalize_user, parse_action_type, requires_mfa
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


class FactorNotAvailable(ValueError):
    """Unknown method, method not offered, or the requester is not enrolled in it. Not counted as an attempt."""


class FactorAlreadyUsed(RuntimeError):
    """This method already passed for this action; the policy needs a DIFFERENT one."""


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
    state: str = "pending"  # pending | executed | declined | rejected | expired
    attempts: int = 0
    method: str = "channel"  # dev flow: channel | totp; multi-factor flow: multi
    satisfied: list[str] = field(default_factory=list)  # methods that passed, in order
    challenges: dict[str, Any] = field(default_factory=dict)  # outstanding single-use challenges per method

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
    factors_available: list[str] = field(default_factory=list)
    approvable: bool = True
    policy: dict[str, Any] = field(default_factory=dict)


@dataclass
class FactorResult:
    status: str  # "executed" | "declined" | "pending_mfa"
    pending_id: str
    method: str
    result: dict[str, Any] | None = None
    satisfied: list[str] = field(default_factory=list)
    remaining: int = 0
    needs_non_knowledge: bool = False
    available: list[str] = field(default_factory=list)


class MFAIncomplete(RuntimeError):
    """Raised by the code-only `verify()` when the factor passed but the policy needs more."""

    def __init__(self, res: FactorResult):
        super().__init__(f"factor accepted; {res.remaining} more required")
        self.result = res


def action_digest(action: ActionType, params: dict[str, Any], requested_by: str) -> str:
    blob = json.dumps({"a": action.value, "p": params, "u": requested_by}, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def _hash(salt: str, code: str) -> str:
    return hashlib.sha256((salt + code).encode("utf-8", "surrogatepass")).hexdigest()


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
        factors: FactorRegistry | None = None,
        policy: MFAPolicy | None = None,
    ):
        self.executor = executor or Executor()
        self.audit = audit or AuditLog(clock=clock, store=store)
        self.channel = channel or StderrChannel()
        self.factors = factors or FactorRegistry(totp=totp)
        self.totp = totp or self.factors.totp
        self.policy = policy or MFAPolicy()
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
        requested_by = normalize_user(requested_by)
        digest = action_digest(action, params, requested_by)
        if not requires_mfa(action, params, reason):
            result = self.executor.run(_issue_grant(digest), action, params, requested_by)
            self.audit.record(
                "action_executed", action=action.value, digest=digest, by=requested_by, mfa=False, ok=result["ok"]
            )
            return SubmitResult("executed", result=result)

        key = _op_key(requested_by, action)
        pid = secrets.token_urlsafe(12)
        legacy = self.policy.dev_single_factor
        available = self.factors.enrolled(requested_by)
        if legacy:
            method = "totp" if self.totp and self.totp.is_enrolled(requested_by) else "channel"
            approvable = True
        else:
            method = "multi"
            approvable = self.policy.can_satisfy(available)
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
            factors_available=available,
            approvable=approvable,
        )
        if method == "channel":
            self.channel.deliver(pid, code, summary)
        return SubmitResult(
            "pending_mfa",
            pending_id=pid,
            digest=digest,
            summary=summary,
            expires_at=expires,
            method=method,
            factors_available=available,
            approvable=approvable,
            policy=self.policy.describe(),
        )

    def verify(self, pending_id: str, code: str, confirm_digest: str) -> dict[str, Any]:
        """Code-based verification (POST /mfa/verify). Dev flow: the one code releases the action.
        Multi-factor flow: the code is the TOTP factor; raises MFAIncomplete if more factors are needed."""
        if not self.policy.dev_single_factor:
            res = self.verify_factor(pending_id, "totp", {"code": code}, confirm_digest)
            if res.status == "pending_mfa":
                raise MFAIncomplete(res)
            return res.result or {}
        with self._lock:
            return self._verify_code_locked(self._open_locked(pending_id), str(code), confirm_digest)

    def challenge(self, pending_id: str, method: str, confirm_digest: str) -> dict[str, Any]:
        """Start a factor that needs server data first: WebAuthn options (challenge bound to this
        action) or the security questions to answer. Password/TOTP need no challenge."""
        with self._lock:
            p = self._open_locked(pending_id)
            m, factor = self._factor_for_locked(p, method)
            key = _op_key(p.requested_by, p.action)
            self._check_locked(key)
            if not ct_equal(confirm_digest, p.digest):
                self._fail_locked(p, key, "digest_mismatch")
            out: dict[str, Any] = {"pending_id": p.id, "method": m}
            if m == "webauthn":
                opts, state = factor.assertion_options(p.requested_by, p.id, p.digest)
                p.challenges["webauthn"] = state  # replaces any earlier one: only the latest is valid
                out["publicKey"] = opts
            elif m == "security_questions":
                qs = factor.challenge(p.requested_by)  # may raise FactorLocked (rate limit)
                p.challenges["security_questions"] = [q["id"] for q in qs]
                out["questions"] = qs
            self._persist(p)
            self.audit.record("mfa_challenge", pending_id=p.id, method=m)
            return out

    def verify_factor(self, pending_id: str, method: str, response: Any, confirm_digest: str) -> FactorResult:
        with self._lock:
            p = self._open_locked(pending_id)
            if self.policy.dev_single_factor:
                if method not in ("totp", "channel") or method != p.method:
                    raise FactorNotAvailable(f"dev single-factor flow: use method {p.method!r}")
                code = response.get("code", "") if isinstance(response, dict) else ""
                result = self._verify_code_locked(p, str(code), confirm_digest)
                return FactorResult(p.state, p.id, method, result=result, satisfied=[method])
            m, factor = self._factor_for_locked(p, method)
            key = _op_key(p.requested_by, p.action)
            self._check_locked(key)
            digest_ok = ct_equal(confirm_digest, p.digest)
            if not digest_ok:
                p.challenges.pop(m, None)  # a challenge is single-use whatever the outcome
                ok, why = False, "digest_mismatch"
            else:
                try:
                    ok, why = self._check_factor_locked(p, m, factor, response)
                except FactorLocked as e:
                    self._persist(p)
                    self.audit.record("mfa_factor", pending_id=p.id, method=m, result="locked", until=e.until)
                    raise
            extra = {} if ok else {"reason": why}
            self.audit.record("mfa_factor", pending_id=p.id, method=m, result="ok" if ok else "fail", **extra)
            if not ok:
                self._fail_locked(p, key, why)
            p.satisfied.append(m)
            if self.policy.satisfied(p.satisfied):
                result = self._release_locked(p)
                return FactorResult(p.state, p.id, m, result=result, satisfied=list(p.satisfied))
            self._persist(p)
            return self._progress(p, m)

    def status(self, pending_id: str) -> dict[str, Any]:
        with self._lock:
            self._sweep_locked()
            p = self._pending.get(pending_id)
            if p is None:
                raise PendingNotFound(pending_id)
            r = self._progress(p, "")
            return {
                "pending_id": p.id,
                "state": p.state,
                "action": p.action.value,
                "requested_by": p.requested_by,
                "expires_at": p.expires_at,
                "factors_satisfied": r.satisfied,
                "factors_remaining": r.remaining,
                "needs_non_knowledge": r.needs_non_knowledge,
                "factors_available": r.available,
                "policy": self.policy.describe(),
            }

    def sweep(self) -> int:
        with self._lock:
            return self._sweep_locked()

    def state_of(self, pending_id: str) -> str | None:
        with self._lock:
            self._sweep_locked()
            p = self._pending.get(pending_id)
            return p.state if p else None

    # -- internals ----------------------------------------------------------
    def _progress(self, p: _Pending, method: str) -> FactorResult:
        available = self.factors.enrolled(p.requested_by)
        needs_strong = not self.policy.allow_knowledge_only and all(CATEGORY[m] == "knowledge" for m in p.satisfied)
        return FactorResult(
            "pending_mfa",
            p.id,
            method,
            satisfied=list(p.satisfied),
            remaining=self.policy.remaining(p.satisfied),
            needs_non_knowledge=needs_strong,
            available=[m for m in available if m not in p.satisfied],
        )

    def _open_locked(self, pending_id: str) -> _Pending:
        self._sweep_locked()
        p = self._pending.get(pending_id)
        if p is None:
            raise PendingNotFound(pending_id)
        if p.state == "expired":
            raise PendingExpired(pending_id)
        if p.state != "pending":
            raise PendingFinalized(f"{pending_id} is already {p.state}")
        return p

    def _verify_code_locked(self, p: _Pending, code: str, confirm_digest: str) -> dict[str, Any]:
        """Dev single-factor flow: one TOTP or console code releases the action."""
        key = _op_key(p.requested_by, p.action)
        self._check_locked(key)
        digest_ok = ct_equal(confirm_digest, p.digest)
        if p.method == "totp":
            # only burn a TOTP step when the digest matches, so a typo in the digest doesn't waste a code
            code_ok = digest_ok and self.totp is not None and self.totp.verify(p.requested_by, code)
        else:
            code_ok = ct_equal(_hash(p.salt, code), p.code_hash)
        if not (digest_ok and code_ok):
            self._fail_locked(p, key, "digest_mismatch" if not digest_ok else "bad_code")
        return self._release_locked(p)

    def _factor_for_locked(self, p: _Pending, method: Any):
        if self.policy.dev_single_factor:
            raise FactorNotAvailable("dev single-factor flow: use POST /mfa/verify")
        m = parse_method(method)
        if m is None:
            raise FactorNotAvailable(f"unknown verification method; one of {sorted(CATEGORY)}")
        factor = self.factors.get(m)
        if factor is None or not factor.is_enrolled(p.requested_by):
            raise FactorNotAvailable(f"{m} is not enrolled for this user")
        if m in p.satisfied:
            raise FactorAlreadyUsed(f"{m} already verified for this action; use a different method")
        return m, factor

    def _check_factor_locked(self, p: _Pending, m: str, factor, response: Any) -> tuple[bool, str]:
        r = response if isinstance(response, dict) else {}
        user = p.requested_by
        if m == "totp":
            return factor.verify(user, str(r.get("code", ""))[:16]), "bad_code"
        if m == "password":
            pw = r.get("password")
            return factor.verify(user, pw if isinstance(pw, str) else ""), "bad_password"
        if m == "security_questions":
            asked = p.challenges.pop("security_questions", None)
            if not asked:
                return False, "no_challenge"
            return factor.verify(user, asked, r.get("answers")), "bad_answers"
        if m == "webauthn":
            state = p.challenges.pop("webauthn", None)  # consumed before checking: single use
            return factor.verify_assertion(user, r.get("credential"), state, p.id, p.digest)
        return False, "unknown_method"  # pragma: no cover - parse_method already refused it

    def _fail_locked(self, p: _Pending, key: str, reason: str) -> None:
        """Count a failed attempt; always raises."""
        p.attempts += 1
        left = self.max_attempts - p.attempts
        self.audit.record("mfa_failed", pending_id=p.id, reason=reason, attempts=p.attempts)
        fails = self._bump_failures(key)
        if fails >= self.lockout_threshold:
            until = self._clock() + self.lockout_seconds
            self._set_lock(key, fails, until)
            p.state = "rejected"
            self._persist(p)
            self.audit.record("operation_locked", key=key, consecutive_failures=fails, until=until, pending_id=p.id)
            self.audit.record("action_rejected", pending_id=p.id, reason="operation_locked", digest=p.digest)
            raise OperationLocked(key, until)
        if left <= 0:
            p.state = "rejected"
            self._persist(p)
            self.audit.record("action_rejected", pending_id=p.id, reason="too_many_attempts", digest=p.digest)
            raise MFAFailed("too many failed attempts; action rejected", 0)
        self._persist(p)
        raise MFAFailed(f"verification failed ({reason})", left)

    def _release_locked(self, p: _Pending) -> dict[str, Any]:
        # state flips BEFORE the executor runs: even if the provider call raises, this action can't run twice
        p.state = "executed"
        p.challenges = {}
        self._persist(p)
        self._set_lock(_op_key(p.requested_by, p.action), 0, 0.0)  # full success resets the failure counter
        result = self.executor.run(_issue_grant(p.digest, p.id), p.action, p.params, p.requested_by)
        if result.get("ok") is False:
            p.state = "declined"
            self._persist(p)
            self.audit.record(
                "action_declined",
                pending_id=p.id,
                action=p.action.value,
                digest=p.digest,
                by=p.requested_by,
                error=result.get("error") or (result.get("outcome") or {}).get("error", "failed")[:80],
                factors=list(p.satisfied) or [p.method],
            )
            return result
        self.audit.record(
            "action_executed",
            pending_id=p.id,
            action=p.action.value,
            digest=p.digest,
            by=p.requested_by,
            mfa=True,
            ok=True,
            factors=list(p.satisfied) or [p.method],
        )
        return result

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
                p.challenges = {}
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
