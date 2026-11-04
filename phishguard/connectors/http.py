"""A small httpx wrapper: auth header, 401 refresh, 429/503 backoff with Retry-After, bounded downloads.

Read-side verbs only: GET, plus POST for OAuth token endpoints and the two read-scoped
subscription calls (Gmail `watch`, Graph `subscriptions`). The mutating side subclasses this
in `phishguard/mutating/mailbox.py` to add PATCH/DELETE/POST for remediation.

The bearer token is only ever attached to hosts in `auth_hosts`, so a tampered `@odata.nextLink`
or stored cursor URL can't send it to someone else's server.
"""

from __future__ import annotations

import email.utils
import random
import time
from datetime import UTC, datetime
from typing import Any, Protocol
from urllib.parse import urlsplit

import httpx

from .base import ConnectorError
from .secrets import get_logger

log = get_logger(__name__)

RETRY_STATUSES = frozenset({429, 503})
GMAIL_RATE_REASONS = frozenset({"rateLimitExceeded", "userRateLimitExceeded"})


class TokenProvider(Protocol):
    def token(self) -> str: ...
    def invalidate(self) -> None: ...


class HttpError(ConnectorError):
    def __init__(self, status: int, method: str, url: str, code: str = ""):
        host_path = urlsplit(url)._replace(query="", fragment="").geturl()  # query may carry cursors; drop it
        super().__init__(f"{method} {host_path} -> HTTP {status}{f' ({code})' if code else ''}")
        self.status = status
        self.code = code


class ResponseTooLarge(ConnectorError):
    def __init__(self, limit: int):
        super().__init__(f"response exceeds {limit} bytes")
        self.limit = limit


def parse_retry_after(value: str | None, now: float) -> float | None:
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return float(value)
    try:
        when = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return max(0.0, when.timestamp() - now)


def _error_code(body: bytes) -> str:
    """A short, non-secret error code from a JSON error body (never the whole body)."""
    try:
        import json

        data = json.loads(body[:20000] or b"{}")
    except ValueError:
        return ""
    if not isinstance(data, dict):
        return ""
    err = data.get("error")
    if isinstance(err, str):
        return err[:64]
    if isinstance(err, dict):
        for e in err.get("errors") or []:
            if isinstance(e, dict) and e.get("reason"):
                return str(e["reason"])[:64]
        return str(err.get("code") or err.get("status") or "")[:64]
    return ""


class HttpClient:
    def __init__(
        self,
        client: httpx.Client | None = None,
        *,
        auth: TokenProvider | None = None,
        auth_hosts: frozenset[str] = frozenset(),
        max_retries: int = 5,
        max_backoff: float = 60.0,
        base_backoff: float = 1.0,
        sleep=time.sleep,
        clock=time.time,
        rng=random.random,
        timeout: float = 30.0,
    ):
        self._client = client or httpx.Client(timeout=timeout, follow_redirects=False)
        self.auth = auth
        self.auth_hosts = frozenset(h.lower() for h in auth_hosts)
        self.max_retries = max_retries
        self.max_backoff = max_backoff
        self.base_backoff = base_backoff
        self._sleep = sleep
        self._clock = clock
        self._rng = rng
        self.retries = 0  # observable for tests and metrics

    # -- read-side verbs ---------------------------------------------------
    def get_json(self, url: str, params: dict | None = None, headers: dict | None = None) -> dict[str, Any]:
        return self._json(self._send("GET", url, params=params, headers=headers), "GET", url)

    def get_bytes(self, url: str, max_bytes: int, params: dict | None = None, headers: dict | None = None) -> bytes:
        return self._send("GET", url, params=params, headers=headers, max_bytes=max_bytes)

    def post_form(self, url: str, data: dict[str, str]) -> dict[str, Any]:
        """OAuth token endpoints. No bearer header; credentials travel in the form body."""
        return self._json(self._send("POST", url, data=data, use_auth=False, ok_statuses=(400,)), "POST", url)

    def post_json(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self._json(self._send("POST", url, json=payload), "POST", url)

    def close(self) -> None:
        self._client.close()

    # -- internals -----------------------------------------------------------
    @staticmethod
    def _json(body: bytes, method: str, url: str) -> dict[str, Any]:
        import json

        try:
            data = json.loads(body or b"{}")
        except ValueError:
            raise ConnectorError(f"{method} {urlsplit(url).path}: response is not JSON") from None
        if not isinstance(data, dict):
            raise ConnectorError(f"{method} {urlsplit(url).path}: expected a JSON object")
        return data

    def _wants_auth(self, url: str) -> bool:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        if self.auth is None:
            return False
        if parts.scheme != "https" or host not in self.auth_hosts:
            raise ConnectorError(f"refusing to send credentials to {parts.scheme}://{host}")
        return True

    def _delay(self, attempt: int, resp: httpx.Response | None) -> float:
        ra = parse_retry_after(resp.headers.get("retry-after"), self._clock()) if resp is not None else None
        if ra is None:
            ra = self.base_backoff * (2**attempt) * (0.5 + self._rng() / 2)  # exponential with jitter
        return min(self.max_backoff, ra)

    def _send(
        self,
        method: str,
        url: str,
        *,
        params: dict | None = None,
        headers: dict | None = None,
        data: dict | None = None,
        json: dict | None = None,
        content: bytes | None = None,
        max_bytes: int = 10_000_000,
        use_auth: bool = True,
        ok_statuses: tuple[int, ...] = (),
    ) -> bytes:
        refreshed = False
        attempt = 0
        while True:
            h = dict(headers or {})
            if use_auth and self._wants_auth(url):
                h["Authorization"] = "Bearer " + self.auth.token()  # type: ignore[union-attr]
            req = self._client.build_request(
                method, url, params=params, headers=h, data=data, json=json, content=content
            )
            try:
                resp = self._client.send(req, stream=True)
            except httpx.TransportError as e:
                if attempt >= self.max_retries:
                    raise ConnectorError(
                        f"{method} {urlsplit(url).hostname}: network error ({type(e).__name__})"
                    ) from None
                self._backoff(attempt, None, f"network error {type(e).__name__}")
                attempt += 1
                continue
            try:
                status = resp.status_code
                if status == 401 and use_auth and self.auth is not None and not refreshed:
                    self.auth.invalidate()
                    refreshed = True
                    continue
                retryable = status in RETRY_STATUSES
                body_small = b""
                if status == 403:
                    body_small = resp.read()[:20000]
                    retryable = _error_code(body_small) in GMAIL_RATE_REASONS
                if retryable:
                    if attempt >= self.max_retries:
                        raise HttpError(status, method, url, "retries exhausted")
                    self._backoff(attempt, resp, f"HTTP {status}")
                    attempt += 1
                    continue
                if status >= 400 and status not in ok_statuses:
                    raise HttpError(status, method, url, _error_code(body_small or resp.read()[:20000]))
                declared = resp.headers.get("content-length")
                if declared and declared.isdigit() and int(declared) > max_bytes:
                    raise ResponseTooLarge(max_bytes)
                buf = bytearray()
                for chunk in resp.iter_bytes():
                    buf += chunk
                    if len(buf) > max_bytes:
                        raise ResponseTooLarge(max_bytes)
                return bytes(buf)
            finally:
                resp.close()

    def _backoff(self, attempt: int, resp: httpx.Response | None, why: str) -> None:
        d = self._delay(attempt, resp)
        self.retries += 1
        log.warning("backing off %.1fs after %s (attempt %d/%d)", d, why, attempt + 1, self.max_retries)
        self._sleep(d)


def utc_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
