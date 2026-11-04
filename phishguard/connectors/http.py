"""HTTP plumbing for provider REST APIs: bearer auth, host allow-list, 401 refresh, 429/503 backoff."""

from __future__ import annotations

import email.utils
import logging
import random
import time
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

import httpx

from .secrets import redact

log = logging.getLogger("phishguard.connectors")
RETRY_STATUS = {429, 500, 502, 503, 504}
GMAIL_RATE_REASONS = {"rateLimitExceeded", "userRateLimitExceeded"}


class ProviderError(RuntimeError):
    def __init__(self, msg: str, status: int | None = None):
        super().__init__(redact(msg))
        self.status = status


class RateLimited(ProviderError):
    def __init__(self, msg: str, retry_after: float | None):
        super().__init__(msg, 429)
        self.retry_after = retry_after


def parse_retry_after(value: str | None, now: float | None = None) -> float | None:
    """Retry-After is either delta-seconds or an HTTP-date (RFC 9110 10.2.3)."""
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return float(value)
    try:
        when = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    base = now if now is not None else datetime.now(UTC).timestamp()
    return max(0.0, when.timestamp() - base)


def _gmail_rate_limited(resp: httpx.Response) -> bool:
    if resp.status_code != 403:
        return False
    try:
        errs = resp.json().get("error", {}).get("errors", [])
    except ValueError:
        return False
    return any(e.get("reason") in GMAIL_RATE_REASONS for e in errs)


class RetryingClient:
    """Wraps httpx.Client.

    - Adds `Authorization: Bearer` from a token provider; on 401 refreshes once and retries.
    - Retries 429/5xx (and Gmail's 403 rateLimitExceeded) honoring Retry-After, else exponential
      backoff with jitter. A Retry-After longer than `max_delay` raises RateLimited so the caller
      reschedules instead of blocking a worker for an hour.
    - Refuses any URL whose host is not on the allow-list: next/delta links come from the server,
      and following one to a foreign host would hand it our bearer token.
    """

    def __init__(
        self,
        client: httpx.Client,
        auth=None,
        allowed_hosts: Iterable[str] = (),
        max_retries: int = 5,
        base_delay: float = 1.0,
        max_delay: float = 120.0,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.client = client
        self.auth = auth
        self.allowed_hosts = {h.lower() for h in allowed_hosts}
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.sleep = sleep
        self.requests: list[tuple[str, str]] = []  # (method, path) log, no query strings or headers

    def _check_host(self, url: str) -> None:
        u = urlparse(url)
        if u.scheme != "https" or (self.allowed_hosts and (u.hostname or "").lower() not in self.allowed_hosts):
            raise ProviderError(f"refusing to call non-allow-listed URL host {u.hostname!r} (scheme {u.scheme})")

    def _headers(self, extra: dict[str, str] | None) -> dict[str, str]:
        h = dict(extra or {})
        if self.auth is not None:
            h["Authorization"] = f"Bearer {self.auth.token()}"
        return h

    def _delay(self, attempt: int, resp: httpx.Response | None) -> float:
        ra = parse_retry_after(resp.headers.get("Retry-After")) if resp is not None else None
        if ra is not None:
            if ra > self.max_delay:
                raise RateLimited(f"provider asked to wait {ra:.0f}s", ra)
            return ra
        return min(self.max_delay, self.base_delay * 2**attempt) * (0.5 + random.random() / 2)

    def _send(self, method: str, url: str, stream: bool = False, headers=None, **kw) -> httpx.Response:
        self._check_host(url)
        refreshed = False
        attempt = 0
        while True:
            req = self.client.build_request(method, url, headers=self._headers(headers), **kw)
            self.requests.append((method, urlparse(url).path))
            try:
                resp = self.client.send(req, stream=stream)
            except httpx.TransportError as e:
                if attempt >= self.max_retries:
                    raise ProviderError(f"{method} {urlparse(url).path}: network error {type(e).__name__}") from None
                self.sleep(self._delay(attempt, None))
                attempt += 1
                continue
            if resp.status_code == 401 and self.auth is not None and not refreshed:
                resp.close()
                self.auth.invalidate()
                refreshed = True
                continue
            if resp.status_code in RETRY_STATUS or _gmail_rate_limited(resp):
                if stream:
                    resp.read()
                if attempt >= self.max_retries:
                    ra = parse_retry_after(resp.headers.get("Retry-After"))
                    raise RateLimited(f"{method} {urlparse(url).path}: still {resp.status_code} after retries", ra)
                delay = self._delay(attempt, resp)
                log.info("provider %s on %s; retrying in %.1fs", resp.status_code, urlparse(url).path, delay)
                resp.close()
                self.sleep(delay)
                attempt += 1
                continue
            if resp.status_code >= 400:
                if stream:
                    resp.read()
                code = ""
                try:
                    body = resp.json()
                    err = body.get("error", {}) if isinstance(body, dict) else {}
                    code = str((err.get("status") or err.get("code") or "") if isinstance(err, dict) else err)[:60]
                except ValueError:
                    pass
                resp.close()
                raise ProviderError(
                    f"{method} {urlparse(url).path} -> HTTP {resp.status_code} {code}".strip(), resp.status_code
                )
            return resp

    def get_json(self, url: str, **kw) -> dict[str, Any]:
        return self._send("GET", url, **kw).json()

    def post_json(self, url: str, body: dict[str, Any], **kw) -> dict[str, Any]:
        r = self._send("POST", url, json=body, **kw)
        return r.json() if r.content else {}

    def request(self, method: str, url: str, **kw) -> httpx.Response:
        return self._send(method, url, **kw)

    def get_bytes_capped(self, url: str, max_bytes: int, **kw) -> bytes | None:
        """Stream a body; return None (and stop downloading) as soon as it exceeds max_bytes."""
        resp = self._send("GET", url, stream=True, **kw)
        try:
            declared = int(resp.headers.get("Content-Length", "0") or 0)
            if declared > max_bytes:
                return None
            buf = bytearray()
            for chunk in resp.iter_bytes():
                buf += chunk
                if len(buf) > max_bytes:
                    return None
            return bytes(buf)
        finally:
            resp.close()
