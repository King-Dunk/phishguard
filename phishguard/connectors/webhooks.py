"""Push notifications: Gmail via Cloud Pub/Sub push, Microsoft Graph change notifications.

A notification is only a *hint* to poll now. Its content (historyId, resource id) is never used
to decide what to fetch: the worker polls from its own stored cursor. So a forged notification
that somehow passed validation could only cause one extra, idempotent poll.

Validation:
- Graph: the subscription handshake echoes `validationToken` as text/plain (length- and
  charset-limited, nosniff); every notification's `clientState` must equal our secret
  (constant-time compare); others are dropped.
- Gmail/Pub/Sub: the push carries a Google-signed OIDC JWT. We check RS256 against Google's
  JWKS, the audience we configured, the issuer, expiry, and that `email` is our push service
  account with `email_verified`.

These routes run in the worker's own small server (`worker --webhooks`), not in the main API, so
the API process never needs mailbox credentials.
"""

from __future__ import annotations

import base64
import hmac
import json
import re
import threading
import time
from collections.abc import Callable
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import PlainTextResponse, Response

from .http import HttpClient
from .secrets import Secret, get_logger

log = get_logger(__name__)

GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"
GOOGLE_ISSUERS = ("accounts.google.com", "https://accounts.google.com")
MAX_BODY = 256_000
_VALIDATION_TOKEN = re.compile(r"^[\x20-\x7e]{1,1024}$")


class JwksCache:
    def __init__(self, http: HttpClient, url: str = GOOGLE_JWKS_URL, ttl: float = 3600.0, clock=time.time):
        self._http, self._url, self._ttl, self._clock = http, url, ttl, clock
        self._keys: dict[str, dict[str, Any]] = {}
        self._fetched = -1e18
        self._lock = threading.Lock()

    def key(self, kid: str) -> dict[str, Any] | None:
        with self._lock:
            now = self._clock()
            stale = now - self._fetched > self._ttl
            # unknown kid: Google rotated keys; refetch, but at most once a minute
            if stale or (kid not in self._keys and now - self._fetched > 60):
                data = self._http.get_json(self._url)
                self._keys = {k["kid"]: k for k in data.get("keys", []) if isinstance(k, dict) and "kid" in k}
                self._fetched = now
            return self._keys.get(kid)


def verify_pubsub_jwt(token: str, jwks: JwksCache, audience: str, service_account: str) -> dict[str, Any]:
    import jwt
    from jwt.algorithms import RSAAlgorithm

    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError:
        raise PermissionError("malformed token") from None
    if header.get("alg") != "RS256":  # never 'none', never HS256 with the public key as secret
        raise PermissionError("unexpected token algorithm")
    jwk = jwks.key(str(header.get("kid", "")))
    if jwk is None:
        raise PermissionError("unknown signing key")
    try:
        claims = jwt.decode(
            token,
            RSAAlgorithm.from_jwk(json.dumps(jwk)),
            algorithms=["RS256"],
            audience=audience,
            issuer=GOOGLE_ISSUERS,
            options={"require": ["exp", "iat", "iss", "aud"]},
            leeway=30,
        )
    except jwt.PyJWTError as e:
        raise PermissionError(f"token rejected ({type(e).__name__})") from None
    if claims.get("email") != service_account or claims.get("email_verified") is not True:
        raise PermissionError("token not issued for the configured push service account")
    return claims


def make_router(
    trigger: Callable[[str, str], None],
    *,
    graph_client_state: Secret | None = None,
    pubsub_audience: str | None = None,
    pubsub_service_account: str | None = None,
    jwks: JwksCache | None = None,
) -> APIRouter:
    router = APIRouter(prefix="/webhooks", tags=["webhooks"])

    async def _body(request: Request) -> bytes:
        body = await request.body()
        if len(body) > MAX_BODY:
            raise HTTPException(413, "notification too large")
        return body

    @router.post("/graph")
    async def graph_notification(request: Request):
        token = request.query_params.get("validationToken")
        if token is not None:
            if graph_client_state is None:
                raise HTTPException(404, "graph notifications not configured")
            if not _VALIDATION_TOKEN.fullmatch(token):  # fullmatch: `$` would let a trailing \n through
                raise HTTPException(400, "invalid validationToken")
            return PlainTextResponse(token, headers={"X-Content-Type-Options": "nosniff"})
        if graph_client_state is None:
            raise HTTPException(404, "graph notifications not configured")
        try:
            data = json.loads(await _body(request))
            items = data["value"]
            assert isinstance(items, list)
        except (ValueError, KeyError, TypeError, AssertionError):
            raise HTTPException(400, "malformed notification") from None
        accepted = 0
        expected = graph_client_state.reveal().encode()
        for n in items[:100]:
            cs = str(n.get("clientState", "")) if isinstance(n, dict) else ""
            if hmac.compare_digest(cs.encode(), expected):
                accepted += 1
        if not accepted:
            log.warning("dropped %d Graph notification(s) with a wrong clientState", len(items))
            raise HTTPException(403, "clientState mismatch")
        trigger("graph", "")
        return Response(status_code=202)

    @router.post("/gmail")
    async def gmail_push(request: Request):
        if not (pubsub_audience and pubsub_service_account and jwks):
            raise HTTPException(404, "gmail push not configured")
        auth = request.headers.get("authorization", "")
        if not auth.lower().startswith("bearer "):
            raise HTTPException(401, "missing bearer token")
        try:
            verify_pubsub_jwt(auth[7:].strip(), jwks, pubsub_audience, pubsub_service_account)
        except PermissionError as e:
            raise HTTPException(401, str(e)) from None
        try:
            msg = json.loads(await _body(request))["message"]
            payload = json.loads(base64.b64decode(msg.get("data", ""), validate=False) or b"{}")
            address = str(payload.get("emailAddress", ""))[:320]
        except (ValueError, KeyError, TypeError, AttributeError):
            raise HTTPException(400, "malformed push message") from None
        trigger("gmail", address)
        return Response(status_code=204)

    return router
