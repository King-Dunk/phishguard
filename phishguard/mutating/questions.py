"""Security-question factor. A weak knowledge factor, offered because many organizations still use it.

- Answers are normalized (NFKC, casefold, invisible characters removed, whitespace collapsed) and then
  hashed with argon2id (random salt per answer). Plaintext answers are never stored, logged or audited.
- A challenge asks a random subset of the user's questions. The subset is STICKY until it is answered
  correctly, so an attacker can't keep asking for new challenges until only the easy questions come up.
- Every asked answer is checked (no early exit), and the whole challenge passes or fails as one.
- Failed challenges are rate limited per user in a sliding window (default 3 per hour), on top of the
  gateway's per-action attempts and per-operation lockout.
"""

from __future__ import annotations

import secrets
import threading
import time
from typing import Any

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from .factors import EnrollmentError, UserLimiter, normalize_answer
from .kv import KV
from .policy import normalize_user
from .totp import AlreadyEnrolled

MAX_QUESTIONS = 10
MAX_TEXT = 200


class SecurityQuestionManager:
    method = "security_questions"

    def __init__(
        self,
        kv: KV | None = None,
        clock=time.time,
        min_enrolled: int = 3,
        per_challenge: int = 2,
        max_failures: int = 3,
        window_seconds: int = 3600,
        time_cost: int = 2,
        memory_kib: int = 19456,
    ):
        if per_challenge > min_enrolled:
            raise ValueError("per_challenge must not exceed min_enrolled")
        self._kv = kv or KV()
        self.min_enrolled, self.per_challenge = min_enrolled, per_challenge
        self._ph = PasswordHasher(time_cost=time_cost, memory_cost=memory_kib, parallelism=1, type=Type.ID)
        self._dummy = self._ph.hash("dummy-answer")
        self.limiter = UserLimiter(self._kv, clock, "security_questions", max_failures, 0, window_seconds)
        self._rng = secrets.SystemRandom()
        self._lock = threading.Lock()

    def is_enrolled(self, user: str) -> bool:
        return self._kv.get("questions", normalize_user(user)) is not None

    def enroll(self, user: str, items: list[dict[str, str]]) -> list[str]:
        if not isinstance(items, list) or not (self.min_enrolled <= len(items) <= MAX_QUESTIONS):
            raise EnrollmentError(f"enroll between {self.min_enrolled} and {MAX_QUESTIONS} questions")
        seen, rows = set(), []
        for i, it in enumerate(items, 1):
            q = " ".join(str(it.get("question", "")).split())[:MAX_TEXT]
            a = normalize_answer(str(it.get("answer", "")))[:MAX_TEXT]
            if len(q) < 5 or len(a) < 2:
                raise EnrollmentError("each question needs text and an answer of at least 2 characters")
            if q.casefold() in seen:
                raise EnrollmentError("questions must be distinct")
            seen.add(q.casefold())
            rows.append({"id": f"q{i}", "question": q, "hash": self._ph.hash(a)})
        with self._lock:
            if self.is_enrolled(user):
                raise AlreadyEnrolled(user)
            self._kv.put("questions", normalize_user(user), rows)
        return [r["id"] for r in rows]

    def _rows(self, user: str) -> list[dict[str, Any]]:
        return self._kv.get("questions", normalize_user(user), [])

    def challenge(self, user: str) -> list[dict[str, str]]:
        """The questions to ask now: [{id, question}]. Same subset until answered correctly."""
        self.limiter.check(user)
        rows = {r["id"]: r for r in self._rows(user)}
        if not rows:
            return []
        with self._lock:
            ids = self._kv.get("questions_sticky", normalize_user(user))
            if not ids or any(i not in rows for i in ids):
                ids = sorted(self._rng.sample(sorted(rows), min(self.per_challenge, len(rows))))
                self._kv.put("questions_sticky", normalize_user(user), ids)
        return [{"id": i, "question": rows[i]["question"]} for i in ids]

    def verify(self, user: str, asked: list[str], answers: Any) -> bool:
        self.limiter.check(user)
        rows = {r["id"]: r for r in self._rows(user)}
        given = answers if isinstance(answers, dict) else {}
        ok = bool(rows) and bool(asked) and set(given) == set(asked)
        for qid in asked:  # check every asked answer, no early exit
            h = rows[qid]["hash"] if qid in rows else self._dummy
            try:
                good = self._ph.verify(h, normalize_answer(str(given.get(qid, "")))[:MAX_TEXT]) and qid in rows
            except (VerifyMismatchError, VerificationError, InvalidHashError):
                good = False
            ok = ok and good
        if ok:
            self._kv.delete("questions_sticky", normalize_user(user))
        else:
            self.limiter.fail(user)
        return ok
