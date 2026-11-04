"""Push-notification endpoints (Gmail via Pub/Sub, Microsoft Graph change notifications).

A notification never carries mail and is never trusted to say what to do: a valid one only records a
"scan this mailbox soon" trigger in the scan state DB, which the worker picks up. So the worst a forged
notification could do is cause an extra, harmless scan, and forged ones are rejected anyway:
- Graph: the subscription's validationToken handshake is echoed as text/plain; each notification's
  clientState must equal the per-mailbox secret (constant-time compare).
- Gmail/Pub/Sub: the push carries a Google-signed OIDC JWT. We verify RS256 against Google's published
  keys (no other algorithm accepted), issuer, audience, expiry, and the push service account's email.

Mounted by api.py only when PHISHGUARD_MAILBOX_CONFIG is set and the config has a `webhooks` section.
"""

from __future__ import annotations

import base64
import hmac
import json
import os
import time
from collections.abc import Callable
from typing import Any

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import PlainTextResponse, Response

from .factory import load_config
from .secrets import load_secret
from .state import CheckpointStore

GOOGLE_CERTS = "https://www.googleapis.com/oauth2/v3/certs"
GOOGLE_ISSUERS = {"accounts.google.com", "https://accounts.google.com"}
LEEWAY = 60


class InvalidToken(Exception):
    pass


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class GoogleCerts:
    """Google's JWKS, cached for an hour; an unknown kid triggers a refetch at most once a minute (rotation)."""

    def __init__(self, fetch: Callable[[], dict] | None = None, clock: Callable[[], float] = time.time):
        self._fetch = fetch or (lambda: httpx.get(GOOGLE_CERTS, timeout=10).json())
        self._clock, self._keys, self._at = clock, {}, 0.0

    def _refresh(self) -> None:
        self._keys = {k["kid"]: k for k in self._fetch().get("keys", []) if k.get("kty") == "RSA"}
        self._at = self._clock()

    def key(self, kid: str):
        now = self._clock()
        if not self._at or now - self._at > 3600:
            self._refresh()
        elif kid not in self._keys and now - self._at > 60:
            self._refresh()  # key rotation; at most once a minute so forged kids can't make us hammer Google
        if kid not in self._keys:
            raise InvalidToken("unknown signing key")
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

        k = self._keys[kid]
        n, e = (int.from_bytes(_b64d(k[x]), "big") for x in ("n", "e"))
        return RSAPublicNumbers(e, n).public_key()


def verify_google_jwt(
    token: str, audience: str, email: str, certs: GoogleCerts, now: float | None = None
) -> dict[str, Any]:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    try:
        h_b64, c_b64, s_b64 = token.split(".")
        header, claims = json.loads(_b64d(h_b64)), json.loads(_b64d(c_b64))
    except ValueError:
        raise InvalidToken("malformed token") from None
    if header.get("alg") != "RS256":  # never "none", never HS256 with a public key as secret
        raise InvalidToken("unexpected algorithm")
    try:
        certs.key(str(header.get("kid"))).verify(
            _b64d(s_b64), f"{h_b64}.{c_b64}".encode(), padding.PKCS1v15(), hashes.SHA256()
        )
    except InvalidSignature:
        raise InvalidToken("bad signature") from None
    t = time.time() if now is None else now
    if claims.get("iss") not in GOOGLE_ISSUERS:
        raise InvalidToken("bad issuer")
    if claims.get("aud") != audience:
        raise InvalidToken("bad audience")
    if float(claims.get("exp", 0)) < t - LEEWAY or float(claims.get("iat", 0)) > t + LEEWAY:
        raise InvalidToken("expired or not yet valid")
    if claims.get("email") != email or claims.get("email_verified") is not True:
        raise InvalidToken("unexpected sender")
    return claims


def build_router(
    config: dict | None = None,
    store: CheckpointStore | None = None,
    certs: GoogleCerts | None = None,
    clock: Callable[[], float] = time.time,
) -> APIRouter:
    cfg = config if config is not None else load_config(os.environ["PHISHGUARD_MAILBOX_CONFIG"])
    hooks = cfg.get("webhooks") or {}
    store = store or CheckpointStore(os.path.expanduser(cfg.get("state_db", "~/.local/state/phishguard/scan.db")))
    certs = certs or GoogleCerts(clock=clock)
    graph_states = [
        (h["mailbox"], load_secret(env=h.get("client_state_env"), file=h.get("client_state_file")))
        for h in hooks.get("graph", [])
    ]
    gmail = hooks.get("gmail") or {}
    gmail_boxes = {str(k).lower(): v for k, v in (gmail.get("mailboxes") or {}).items()}
    router = APIRouter(prefix="/webhooks", tags=["webhooks"])

    @router.post("/graph")
    async def graph(request: Request):
        token = request.query_params.get("validationToken")
        if token is not None:  # subscription handshake: echo within 10 s, as plain text
            return PlainTextResponse(token[:4096], headers={"X-Content-Type-Options": "nosniff"})
        if not graph_states:
            raise HTTPException(404, "graph webhooks not configured")
        try:
            items = (await request.json()).get("value", [])
        except (ValueError, AttributeError):
            raise HTTPException(400, "invalid notification body") from None
        valid = 0
        for n in items[:100] if isinstance(items, list) else []:
            cs = str(n.get("clientState", "")) if isinstance(n, dict) else ""
            for mailbox, secret in graph_states:
                if secret and hmac.compare_digest(cs.encode(), secret.encode()):
                    store.add_trigger(mailbox, "graph")
                    valid += 1
                    break
        if not valid:
            raise HTTPException(403, "no notification with a valid clientState")
        return Response(status_code=202)

    @router.post("/gmail")
    async def gmail_push(request: Request):
        if not gmail:
            raise HTTPException(404, "gmail webhooks not configured")
        auth = request.headers.get("authorization", "")
        if not auth.lower().startswith("bearer "):
            raise HTTPException(401, "missing bearer token")
        try:
            verify_google_jwt(auth[7:].strip(), gmail["audience"], gmail["service_account"], certs, clock())
        except InvalidToken as e:
            raise HTTPException(403, f"invalid push token: {e}") from None
        try:
            msg = (await request.json())["message"]
            data = json.loads(base64.b64decode(msg["data"]))
        except (ValueError, KeyError, TypeError):
            raise HTTPException(400, "invalid Pub/Sub message") from None
        mailbox = gmail_boxes.get(str(data.get("emailAddress", "")).lower())
        if mailbox:
            store.add_trigger(mailbox, "gmail")
        return Response(status_code=204)  # ack even for unknown addresses, so Pub/Sub doesn't retry forever

    return router


def maybe_router() -> APIRouter | None:
    """Router if mailbox webhooks are configured, else None (api.py mounts nothing)."""
    path = os.environ.get("PHISHGUARD_MAILBOX_CONFIG")
    if not path:
        return None
    cfg = load_config(path)
    return build_router(cfg) if cfg.get("webhooks") else None
