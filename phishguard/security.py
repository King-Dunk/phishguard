"""API key authentication and in-memory rate limiting for the HTTP layer."""

from __future__ import annotations

import hashlib
import hmac
import threading
import time
from collections import deque
from typing import Any


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


def json_depth(obj: Any, limit: int = 64) -> int:
    """Nesting depth of a parsed JSON value, computed iteratively (no recursion limit issues)."""
    best, stack = 0, [(obj, 1)]
    while stack:
        cur, d = stack.pop()
        if isinstance(cur, (dict, list)):
            best = max(best, d)
            if best > limit:
                return best
            stack.extend((v, d + 1) for v in (cur.values() if isinstance(cur, dict) else cur))
    return best


class BodySizeLimit:
    """ASGI middleware: refuse request bodies over `max_bytes` (Content-Length or streamed)."""

    def __init__(self, app, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = dict(scope.get("headers") or [])
        try:
            declared = int(headers.get(b"content-length", b"0"))
        except ValueError:
            declared = self.max_bytes + 1
        if declared > self.max_bytes:
            return await _reject(send, self.max_bytes)
        seen = 0

        async def limited_receive():
            nonlocal seen
            msg = await receive()
            if msg["type"] == "http.request":
                seen += len(msg.get("body", b""))
                if seen > self.max_bytes:
                    raise _BodyTooLarge
            return msg

        try:
            await self.app(scope, limited_receive, send)
        except _BodyTooLarge:
            await _reject(send, self.max_bytes)


class _BodyTooLarge(Exception):
    pass


async def _reject(send, limit: int) -> None:
    body = b'{"detail":"request body larger than %d bytes"}' % limit
    await send(
        {
            "type": "http.response.start",
            "status": 413,
            "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
        }
    )
    await send({"type": "http.response.body", "body": body})
