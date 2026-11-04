"""OAuth2 token providers for Gmail and Microsoft Graph (read and write credentials use separate instances).

All providers expose `token()` (cached until 60 s before expiry) and `invalidate()` (after a 401).
Every token or secret that passes through here is registered for redaction.
"""

from __future__ import annotations

import base64
import hashlib
import http.server
import json
import secrets as pysecrets
import threading
import time
import urllib.parse
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Any

import httpx

from .http import ProviderError
from .secrets import TokenStore, register

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GMAIL_READ_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
GMAIL_WRITE_SCOPE = "https://www.googleapis.com/auth/gmail.modify"
GOOGLE_IMAP_SCOPE = "https://mail.google.com/"  # IMAP over XOAUTH2 needs Google's full-mail scope
MS_LOGIN = "https://login.microsoftonline.com"
GRAPH_READ_SCOPES = ("https://graph.microsoft.com/Mail.Read", "offline_access")
GRAPH_WRITE_SCOPES = ("https://graph.microsoft.com/Mail.ReadWrite", "offline_access")
GRAPH_APP_SCOPE = "https://graph.microsoft.com/.default"
OUTLOOK_IMAP_SCOPES = ("https://outlook.office.com/IMAP.AccessAsUser.All", "offline_access")
SKEW = 60.0


class AuthError(ProviderError):
    pass


def _token_request(http: httpx.Client, url: str, data: dict[str, str]) -> dict[str, Any]:
    for k in ("client_secret", "refresh_token", "assertion", "code", "code_verifier", "device_code"):
        register(data.get(k))
    r = http.post(url, data=data, headers={"Accept": "application/json"})
    try:
        body = r.json()
    except ValueError:
        body = {}
    if r.status_code >= 400 or "access_token" not in body:
        # error/error_description never contain the secret, but redact anyway via AuthError
        raise AuthError(f"token endpoint {urllib.parse.urlparse(url).path} -> {r.status_code} {body.get('error', '')}")
    register(body.get("access_token"), body.get("refresh_token"), body.get("id_token"))
    return body


class TokenProvider(ABC):
    def __init__(self, clock: Callable[[], float] = time.time):
        self._clock = clock
        self._token: str | None = None
        self._expires = 0.0
        self._lock = threading.Lock()

    def token(self) -> str:
        with self._lock:
            if self._token is None or self._clock() >= self._expires - SKEW:
                body = self._fetch()
                self._token = body["access_token"]
                self._expires = self._clock() + float(body.get("expires_in", 3600))
            return self._token

    def invalidate(self) -> None:
        with self._lock:
            self._token = None

    @abstractmethod
    def _fetch(self) -> dict[str, Any]: ...


class StaticToken(TokenProvider):
    """A bearer token supplied from outside (tests, or a token minted by another system)."""

    def __init__(self, token: str):
        super().__init__()
        register(token)
        self._static = token

    def _fetch(self) -> dict[str, Any]:
        return {"access_token": self._static, "expires_in": 10**9}


class RefreshTokenProvider(TokenProvider):
    """Installed-app (Google) or delegated (Microsoft) user credentials: refresh token -> access token.
    A rotated refresh token (Microsoft rotates them) is written back to the TokenStore."""

    def __init__(
        self,
        http: httpx.Client,
        token_url: str,
        client_id: str,
        store: TokenStore,
        client_secret: str | None = None,
        scopes: tuple[str, ...] = (),
        clock: Callable[[], float] = time.time,
    ):
        super().__init__(clock)
        self.http, self.token_url, self.client_id, self.client_secret = http, token_url, client_id, client_secret
        self.store, self.scopes = store, scopes
        register(client_secret)

    def _fetch(self) -> dict[str, Any]:
        saved = self.store.load()
        rt = saved.get("refresh_token")
        if not rt:
            raise AuthError(f"no refresh token in {self.store.path}; run the --authorize flow first")
        data = {"grant_type": "refresh_token", "refresh_token": rt, "client_id": self.client_id}
        if self.client_secret:
            data["client_secret"] = self.client_secret
        if self.scopes:
            data["scope"] = " ".join(self.scopes)
        body = _token_request(self.http, self.token_url, data)
        if body.get("refresh_token") and body["refresh_token"] != rt:
            self.store.save({**saved, "refresh_token": body["refresh_token"]})
        return body


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class GoogleServiceAccount(TokenProvider):
    """Workspace service account with domain-wide delegation: a signed JWT (RS256) whose `sub` is the
    mailbox owner is exchanged for an access token limited to `scopes` (RFC 7523)."""

    def __init__(
        self,
        http: httpx.Client,
        key: dict[str, Any],
        subject: str,
        scopes: tuple[str, ...] = (GMAIL_READ_SCOPE,),
        clock: Callable[[], float] = time.time,
    ):
        super().__init__(clock)
        from cryptography.hazmat.primitives import serialization

        self.http, self.subject, self.scopes = http, subject, scopes
        self.client_email = key["client_email"]
        self.token_uri = key.get("token_uri", GOOGLE_TOKEN_URL)
        register(key.get("private_key"), key.get("private_key_id"))
        self._key = serialization.load_pem_private_key(key["private_key"].encode(), password=None)
        self._kid = key.get("private_key_id")

    def assertion(self) -> str:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        now = int(self._clock())
        header = {"alg": "RS256", "typ": "JWT", **({"kid": self._kid} if self._kid else {})}
        claims = {
            "iss": self.client_email,
            "sub": self.subject,
            "scope": " ".join(self.scopes),
            "aud": self.token_uri,
            "iat": now,
            "exp": now + 3600,
        }
        signing_input = f"{_b64url(json.dumps(header).encode())}.{_b64url(json.dumps(claims).encode())}"
        sig = self._key.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
        return f"{signing_input}.{_b64url(sig)}"

    def _fetch(self) -> dict[str, Any]:
        grant = "urn:ietf:params:oauth:grant-type:jwt-bearer"
        return _token_request(self.http, self.token_uri, {"grant_type": grant, "assertion": self.assertion()})


class ClientCredentials(TokenProvider):
    """Microsoft Graph application permissions (no user): client id + secret -> app token."""

    def __init__(
        self,
        http: httpx.Client,
        tenant: str,
        client_id: str,
        client_secret: str,
        scope: str = GRAPH_APP_SCOPE,
        clock: Callable[[], float] = time.time,
    ):
        super().__init__(clock)
        register(client_secret)
        self.http, self.client_id, self.client_secret, self.scope = http, client_id, client_secret, scope
        self.url = f"{MS_LOGIN}/{urllib.parse.quote(tenant)}/oauth2/v2.0/token"

    def _fetch(self) -> dict[str, Any]:
        data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": self.scope,
        }
        return _token_request(self.http, self.url, data)


def ms_token_url(tenant: str) -> str:
    return f"{MS_LOGIN}/{urllib.parse.quote(tenant)}/oauth2/v2.0/token"


# ----------------------------------------------------------------------------- interactive flows
def device_code_flow(
    http: httpx.Client,
    tenant: str,
    client_id: str,
    scopes: tuple[str, ...],
    store: TokenStore,
    out: Callable[[str], None] = print,
    sleep: Callable[[float], None] = time.sleep,
    timeout: float = 900,
) -> None:
    """Microsoft device-code flow (RFC 8628): show a code, the user signs in on another device,
    and the refresh token is stored. Only the user code and URL are printed, never a token."""
    base = f"{MS_LOGIN}/{urllib.parse.quote(tenant)}/oauth2/v2.0"
    r = http.post(f"{base}/devicecode", data={"client_id": client_id, "scope": " ".join(scopes)})
    if r.status_code >= 400:
        raise AuthError(f"device code request failed: HTTP {r.status_code}")
    dc = r.json()
    register(dc.get("device_code"))
    out(f"To sign in, open {dc['verification_uri']} and enter the code {dc['user_code']}")
    interval = float(dc.get("interval", 5))
    waited = 0.0
    while waited < min(timeout, float(dc.get("expires_in", timeout))):
        sleep(interval)
        waited += interval
        r = http.post(
            f"{base}/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "client_id": client_id,
                "device_code": dc["device_code"],
            },
        )
        body = r.json() if r.content else {}
        if "access_token" in body:
            register(body.get("access_token"), body.get("refresh_token"))
            store.save({"refresh_token": body["refresh_token"], "scope": body.get("scope", "")})
            out(f"Signed in. Refresh token saved to {store.path} (mode 0600).")
            return
        err = body.get("error")
        if err == "slow_down":
            interval += 5
        elif err != "authorization_pending":
            raise AuthError(f"device code flow failed: {err or r.status_code}")
    raise AuthError("device code flow timed out")


def pkce_pair() -> tuple[str, str]:
    verifier = _b64url(pysecrets.token_bytes(48))
    challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
    return verifier, challenge


def google_auth_url(client_id: str, redirect_uri: str, scopes: tuple[str, ...], challenge: str, state: str) -> str:
    q = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": " ".join(scopes),
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "access_type": "offline",  # ask for a refresh token
        "prompt": "consent",
        "state": state,
    }
    return f"{GOOGLE_AUTH_URL}?{urllib.parse.urlencode(q)}"


def google_installed_app_flow(
    http: httpx.Client,
    client: dict[str, Any],
    scopes: tuple[str, ...],
    store: TokenStore,
    out: Callable[[str], None] = print,
    open_browser: Callable[[str], Any] | None = None,
    port: int = 0,
    wait_for_code: Callable[[str, str], str] | None = None,
) -> None:
    """Google 'installed app' flow: PKCE + a one-shot loopback server on 127.0.0.1 catches the redirect.
    `client` is the downloaded client_secret JSON ({"installed": {...}}). `wait_for_code` is
    injectable for tests; by default a local HTTP server receives the authorization code."""
    c = client.get("installed") or client.get("web") or client
    verifier, challenge = pkce_pair()
    state = pysecrets.token_urlsafe(16)
    srv = None
    if wait_for_code is None:
        srv = _LoopbackServer(port, state)
        redirect = f"http://127.0.0.1:{srv.port}/"
    else:
        redirect = f"http://127.0.0.1:{port or 8765}/"
    url = google_auth_url(c["client_id"], redirect, scopes, challenge, state)
    out(f"Open this URL in a browser and allow access:\n{url}")
    if open_browser:
        open_browser(url)
    code = srv.wait() if srv else wait_for_code(url, state)
    body = _token_request(
        http,
        c.get("token_uri", GOOGLE_TOKEN_URL),
        {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": c["client_id"],
            "client_secret": c.get("client_secret", ""),
            "redirect_uri": redirect,
            "code_verifier": verifier,
        },
    )
    if not body.get("refresh_token"):
        raise AuthError("Google returned no refresh token (revoke the app's access and authorize again)")
    store.save({"refresh_token": body["refresh_token"], "scope": body.get("scope", "")})
    out(f"Authorized. Refresh token saved to {store.path} (mode 0600).")


class _LoopbackServer:
    def __init__(self, port: int, state: str, timeout: float = 300):
        self.state, self.code, self.timeout = state, None, timeout
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                ok = q.get("state", [""])[0] == outer.state and "code" in q
                if ok:
                    outer.code = q["code"][0]
                    register(outer.code)
                self.send_response(200 if ok else 400)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"PhishGuard: authorized, you can close this tab." if ok else b"Invalid state.")

            def log_message(self, *a):  # never log the query string (it carries the code)
                pass

        self.httpd = http.server.HTTPServer(("127.0.0.1", port), H)
        self.port = self.httpd.server_address[1]

    def wait(self) -> str:
        self.httpd.timeout = self.timeout
        deadline = time.time() + self.timeout
        while self.code is None and time.time() < deadline:
            self.httpd.handle_request()
        self.httpd.server_close()
        if self.code is None:
            raise AuthError("no authorization code received")
        return self.code
