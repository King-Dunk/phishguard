"""OAuth 2.0 token providers for Google and Microsoft, over plain httpx.

Providers:
- GoogleRefreshToken: installed-app (desktop) OAuth client + stored refresh token.
- GoogleServiceAccount: Workspace service account with domain-wide delegation (signed JWT bearer grant).
- MicrosoftClientCredentials: app-only (client credentials) for Microsoft 365 tenants.
- MicrosoftRefreshToken: delegated, refresh token obtained once with the device code flow;
  Microsoft rotates refresh tokens, so every new one is written back to the TokenStore.

One-time interactive flows: `google_loopback_flow` (PKCE + state, 127.0.0.1 redirect) and
`microsoft_device_code_flow`. Access tokens live in memory only.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import threading
import time
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

from .base import ConnectorError
from .http import HttpClient
from .secrets import Secret, TokenStore, get_logger, register_secret

log = get_logger(__name__)

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GMAIL_READ_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
GMAIL_MODIFY_SCOPE = "https://www.googleapis.com/auth/gmail.modify"
GOOGLE_IMAP_SCOPE = "https://mail.google.com/"  # the only scope Gmail IMAP accepts (full access)

MS_LOGIN = "https://login.microsoftonline.com"
GRAPH_READ_SCOPE = "https://graph.microsoft.com/Mail.Read"
GRAPH_WRITE_SCOPE = "https://graph.microsoft.com/Mail.ReadWrite"
GRAPH_APP_SCOPE = "https://graph.microsoft.com/.default"
OUTLOOK_IMAP_SCOPE = "https://outlook.office.com/IMAP.AccessAsUser.All"

GMAIL_WRITE_SCOPES = frozenset(
    {
        "https://mail.google.com/",
        "gmail.modify",
        "gmail.compose",
        "gmail.send",
        "gmail.insert",
        "gmail.labels",
        "gmail.settings.basic",
        "gmail.settings.sharing",
    }
)
GRAPH_WRITE_SCOPES = frozenset(
    {"mail.readwrite", "mail.readwrite.shared", "mail.send", "mail.send.shared", "mailboxsettings.readwrite"}
)
_TENANT_RE = re.compile(r"^[A-Za-z0-9.-]{1,100}$")
EXPIRY_SKEW = 120.0


class OAuthError(ConnectorError):
    pass


def ms_token_url(tenant: str) -> str:
    if not _TENANT_RE.match(tenant):
        raise OAuthError("invalid tenant id")
    return f"{MS_LOGIN}/{tenant}/oauth2/v2.0/token"


def _jwt_claims_unverified(token: str) -> dict[str, Any]:
    """Read our OWN access token's claims (scp/roles) for the least-privilege self-check.

    Not a security decision about an attacker's token, so no signature check. Opaque tokens
    (personal Microsoft accounts) return {}.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return {}
    try:
        return json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except ValueError:
        return {}


class _CachedProvider:
    def __init__(self, http: HttpClient, clock=time.time):
        self._http = http
        self._clock = clock
        self._token: Secret | None = None
        self._expires = 0.0
        self._lock = threading.Lock()
        self.granted_scopes: set[str] | None = None
        self.fetches = 0

    def token(self) -> str:
        with self._lock:
            if self._token is None or self._clock() >= self._expires - EXPIRY_SKEW:
                data = self._fetch()
                tok = data.get("access_token")
                if not isinstance(tok, str) or not tok:
                    raise OAuthError(f"token endpoint returned no access_token ({str(data.get('error', ''))[:64]})")
                self._token = Secret(tok)
                self._expires = self._clock() + float(data.get("expires_in", 3600))
                if isinstance(data.get("scope"), str):
                    self.granted_scopes = set(data["scope"].split())
                else:
                    claims = _jwt_claims_unverified(tok)
                    scopes = set(str(claims.get("scp", "")).split()) | set(claims.get("roles") or [])
                    self.granted_scopes = scopes or None
                self.fetches += 1
            return self._token.reveal()

    def invalidate(self) -> None:
        with self._lock:
            self._token = None

    def _fetch(self) -> dict[str, Any]:  # pragma: no cover - abstract
        raise NotImplementedError

    def _post(self, url: str, form: dict[str, str]) -> dict[str, Any]:
        data = self._http.post_form(url, form)
        if "error" in data:
            raise OAuthError(f"token request refused: {str(data['error'])[:64]}")
        return data


class GoogleRefreshToken(_CachedProvider):
    def __init__(self, http: HttpClient, client_id: str, client_secret: Secret, refresh_token: Secret, **kw):
        super().__init__(http, **kw)
        self.client_id, self._secret, self._refresh = client_id, client_secret, refresh_token

    def _fetch(self) -> dict[str, Any]:
        return self._post(
            GOOGLE_TOKEN_URL,
            {
                "grant_type": "refresh_token",
                "client_id": self.client_id,
                "client_secret": self._secret.reveal(),
                "refresh_token": self._refresh.reveal(),
            },
        )


class GoogleServiceAccount(_CachedProvider):
    """Domain-wide delegation: the service account signs a JWT asserting `sub` = the mailbox user."""

    def __init__(self, http: HttpClient, key_info: dict[str, Any], subject: str, scopes: list[str], **kw):
        super().__init__(http, **kw)
        for k in ("client_email", "private_key"):
            if not key_info.get(k):
                raise OAuthError(f"service account key file is missing '{k}'")
        self._email = key_info["client_email"]
        self._key = Secret(key_info["private_key"])
        self._kid = key_info.get("private_key_id")
        self._token_uri = key_info.get("token_uri") or GOOGLE_TOKEN_URL
        if self._token_uri != GOOGLE_TOKEN_URL:
            raise OAuthError("unexpected token_uri in service account key")
        self.subject, self.scopes = subject, scopes

    def assertion(self) -> str:
        import jwt  # PyJWT[crypto]; only needed for service accounts

        now = int(self._clock())
        claims = {
            "iss": self._email,
            "sub": self.subject,
            "scope": " ".join(self.scopes),
            "aud": GOOGLE_TOKEN_URL,
            "iat": now,
            "exp": now + 3600,
        }
        headers = {"kid": self._kid} if self._kid else None
        token = jwt.encode(claims, self._key.reveal(), algorithm="RS256", headers=headers)
        register_secret(token)
        return token

    def _fetch(self) -> dict[str, Any]:
        data = self._post(
            GOOGLE_TOKEN_URL,
            {"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": self.assertion()},
        )
        data.setdefault("scope", " ".join(self.scopes))  # Google omits it here; DWD grants exactly what was asked
        return data


class MicrosoftClientCredentials(_CachedProvider):
    def __init__(self, http: HttpClient, tenant: str, client_id: str, client_secret: Secret, **kw):
        super().__init__(http, **kw)
        if tenant.lower() in ("common", "organizations", "consumers"):
            raise OAuthError("app-only auth needs a specific tenant id, not 'common'")
        self._url = ms_token_url(tenant)
        self.client_id, self._secret = client_id, client_secret

    def _fetch(self) -> dict[str, Any]:
        return self._post(
            self._url,
            {
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self._secret.reveal(),
                "scope": GRAPH_APP_SCOPE,
            },
        )


class MicrosoftRefreshToken(_CachedProvider):
    """Delegated token; the refresh token is read from and rotated into a TokenStore entry."""

    def __init__(self, http: HttpClient, tenant: str, client_id: str, store: TokenStore, key: str, scopes, **kw):
        super().__init__(http, **kw)
        self._url = ms_token_url(tenant)
        self.client_id, self._store, self._key, self.scopes = client_id, store, key, list(scopes)

    def _fetch(self) -> dict[str, Any]:
        entry = self._store.get(self._key) or {}
        if not entry.get("refresh_token"):
            raise OAuthError(f"no stored refresh token for '{self._key}'; run scripts/scan_mailbox.py --authorize")
        data = self._post(
            self._url,
            {
                "grant_type": "refresh_token",
                "client_id": self.client_id,
                "refresh_token": entry["refresh_token"],
                "scope": " ".join(self.scopes),
            },
        )
        if data.get("refresh_token") and data["refresh_token"] != entry["refresh_token"]:
            register_secret(data["refresh_token"])
            self._store.put(self._key, {**entry, "refresh_token": data["refresh_token"]})
        return data


def microsoft_device_code_flow(
    http: HttpClient,
    tenant: str,
    client_id: str,
    scopes: list[str],
    prompt: Callable[[str], None] = print,
    sleep=time.sleep,
    clock=time.time,
) -> dict[str, Any]:
    """Interactive, once: show the user a code, poll until they approve. Returns the token response."""
    if not _TENANT_RE.match(tenant):
        raise OAuthError("invalid tenant id")
    scope = " ".join([*scopes, "offline_access"])
    dc = http.post_form(f"{MS_LOGIN}/{tenant}/oauth2/v2.0/devicecode", {"client_id": client_id, "scope": scope})
    if "error" in dc or not dc.get("device_code"):
        raise OAuthError(f"device code request refused: {str(dc.get('error', 'no device_code'))[:64]}")
    register_secret(dc["device_code"])
    prompt(
        f"To sign in, open {dc.get('verification_uri', 'https://microsoft.com/devicelogin')} "
        f"and enter the code {dc.get('user_code', '?')}"
    )
    interval = float(dc.get("interval", 5))
    deadline = clock() + float(dc.get("expires_in", 900))
    while clock() < deadline:
        sleep(interval)
        data = http.post_form(
            ms_token_url(tenant),
            {
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "client_id": client_id,
                "device_code": dc["device_code"],
            },
        )
        err = data.get("error")
        if not err:
            for k in ("access_token", "refresh_token"):
                register_secret(data.get(k))
            return data
        if err == "authorization_pending":
            continue
        if err == "slow_down":
            interval += 5
            continue
        raise OAuthError(f"device code sign-in failed: {str(err)[:64]}")
    raise OAuthError("device code expired before sign-in completed")


def _pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)[:96]
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def google_auth_url(client_id: str, redirect_uri: str, scopes: list[str], state: str, challenge: str) -> str:
    q = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": " ".join(scopes),
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "access_type": "offline",  # ask for a refresh token
        "prompt": "consent",  # ...even if the user consented before
        "include_granted_scopes": "false",  # don't merge in scopes granted to this client earlier
    }
    return f"{GOOGLE_AUTH_URL}?{urlencode(q)}"


class _CodeCatcher(BaseHTTPRequestHandler):
    result: dict[str, str] = {}

    def do_GET(self):  # noqa: N802 - stdlib name
        q = {k: v[0] for k, v in parse_qs(urlsplit(self.path).query).items()}
        type(self).result = q
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"PhishGuard: sign-in received. You can close this tab.")

    def log_message(self, *args):  # never log the query string (it holds the code)
        return


def google_loopback_flow(
    http: HttpClient,
    client_id: str,
    client_secret: Secret,
    scopes: list[str],
    open_url: Callable[[str], Any] = print,
    timeout: float = 300.0,
) -> dict[str, Any]:
    """Installed-app flow: listen on 127.0.0.1:<random>, send the user to Google, catch the redirect."""
    verifier, challenge = _pkce()
    state = secrets.token_urlsafe(24)
    handler = type("Catcher", (_CodeCatcher,), {"result": {}})
    server = HTTPServer(("127.0.0.1", 0), handler)
    server.timeout = timeout
    redirect = f"http://127.0.0.1:{server.server_address[1]}/"
    try:
        open_url(google_auth_url(client_id, redirect, scopes, state, challenge))
        server.handle_request()
    finally:
        server.server_close()
    return exchange_google_code(http, client_id, client_secret, handler.result, state, verifier, redirect)


def exchange_google_code(
    http: HttpClient,
    client_id: str,
    client_secret: Secret,
    query: dict[str, str],
    expected_state: str,
    verifier: str,
    redirect: str,
) -> dict[str, Any]:
    if not query:
        raise OAuthError("no redirect received (timed out)")
    if not secrets.compare_digest(query.get("state", ""), expected_state):
        raise OAuthError("state mismatch: possible CSRF, sign-in aborted")
    if query.get("error"):
        raise OAuthError(f"sign-in refused: {query['error'][:64]}")
    code = query.get("code", "")
    register_secret(code)
    data = http.post_form(
        GOOGLE_TOKEN_URL,
        {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret.reveal(),
            "redirect_uri": redirect,
            "code_verifier": verifier,
        },
    )
    if "error" in data:
        raise OAuthError(f"code exchange refused: {str(data['error'])[:64]}")
    for k in ("access_token", "refresh_token"):
        register_secret(data.get(k))
    if not data.get("refresh_token"):
        raise OAuthError("Google returned no refresh token; revoke the app's access and sign in again")
    return data


def load_google_client(info: dict[str, Any]) -> tuple[str, Secret]:
    """Accept the JSON Google Cloud Console downloads for a Desktop OAuth client."""
    inner = info.get("installed") or info.get("web") or info
    cid, sec = inner.get("client_id"), inner.get("client_secret")
    if not cid or not sec:
        raise OAuthError("OAuth client file needs client_id and client_secret (download it as 'Desktop app')")
    return cid, Secret(sec)


class StaticToken:
    """A fixed access token (tests, or a token minted by an external secret manager)."""

    def __init__(self, token: Secret, scopes: set[str] | None = None):
        self._t, self.granted_scopes = token, scopes

    def token(self) -> str:
        return self._t.reveal()

    def invalidate(self) -> None:
        return
