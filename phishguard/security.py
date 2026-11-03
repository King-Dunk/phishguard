"""API key authentication and in-memory rate limiting for the HTTP layer."""

from __future__ import annotations

import hashlib
import hmac
import threading
import time
from collections import deque


def _fp(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


class APIKeyAuth:
    """Compares the presented key against every configured key in constant time.

    Keys are hashed first so all comparisons are over equal-length strings, and the loop never
    exits early, so timing reveals neither which key matched nor how many prefix bytes did.
    """

    def __init__(self, keys: tuple[str, ...]):
        self._hashes = [_fp(k) for k in keys]

    @property
    def enabled(self) -> bool:
        return bool(self._hashes)

    def check(self, presented: str | None) -> str | None:
        """Return a stable key id (hash prefix, safe to log) or None."""
        cand = _fp(presented or "")
        match = None
        for h in self._hashes:
            if hmac.compare_digest(cand, h) and presented:
                match = h
        return match[:12] if match else None


class RateLimiter:
    """Sliding-window limiter: at most `limit` hits per `window` seconds per bucket.

    In-memory, per process. Behind several workers each gets its own window; use Redis for a
    shared limit.
    """

    def __init__(self, limit: int, window: float = 60.0, clock=time.monotonic, max_buckets: int = 10_000):
        self.limit = limit
        self.window = window
        self._clock = clock
        self._max_buckets = max_buckets
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def hit(self, bucket: str) -> float | None:
        """Record a hit. Return None if allowed, else seconds until the next slot frees."""
        now = self._clock()
        with self._lock:
            q = self._hits.get(bucket)
            if q is None:
                if len(self._hits) >= self._max_buckets:
                    self._evict(now)
                q = self._hits[bucket] = deque()
            while q and now - q[0] >= self.window:
                q.popleft()
            if len(q) >= self.limit:
                return max(0.0, self.window - (now - q[0]))
            q.append(now)
            return None

    def _evict(self, now: float) -> None:
        for b in [b for b, q in self._hits.items() if not q or now - q[-1] >= self.window]:
            del self._hits[b]
