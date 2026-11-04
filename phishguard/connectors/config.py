"""Build connectors and credentials from environment variables (see docs/MAILBOX_SETUP.md).

Read and write credentials are kept apart:
- read tokens live in PHISHGUARD_TOKEN_FILE (default ~/.config/phishguard/tokens.json);
- write tokens live in PHISHGUARD_WRITE_TOKEN_FILE (default ~/.config/phishguard/tokens-write.json),
  are minted only by an explicit `scan_mailbox.py --authorize --write`, and are only ever loaded by
  the remediation side (`phishguard/mutating/mailbox.py`).
A scan-only deployment therefore never has a credential that can change the mailbox.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import httpx

from . import gmail, graph
from .base import ConnectorError, MailboxConnector
from .http import HttpClient
from .imap import PRESETS, ImapConnector
from .oauth import (
    GMAIL_MODIFY_SCOPE,
    GMAIL_READ_SCOPE,
    GOOGLE_IMAP_SCOPE,
    GOOGLE_TOKEN_URL,
    GRAPH_READ_SCOPE,
    GRAPH_WRITE_SCOPE,
    MS_LOGIN,
    OUTLOOK_IMAP_SCOPE,
    GoogleRefreshToken,
    GoogleServiceAccount,
    MicrosoftClientCredentials,
    MicrosoftRefreshToken,
    OAuthError,
    google_loopback_flow,
    load_google_client,
    microsoft_device_code_flow,
)
from .secrets import Secret, TokenStore, read_json_secret_file, secret_from_env

PROVIDERS = ("gmail", "graph", "imap")


def _home_cfg(name: str) -> str:
    return str(Path.home() / ".config" / "phishguard" / name)


def token_store(env: Mapping[str, str], write: bool = False) -> TokenStore:
    if write:
        return TokenStore(env.get("PHISHGUARD_WRITE_TOKEN_FILE") or _home_cfg("tokens-write.json"))
    return TokenStore(env.get("PHISHGUARD_TOKEN_FILE") or _home_cfg("tokens.json"))


def flag(env: Mapping[str, str], name: str) -> bool:
    return env.get(name, "").strip().lower() in ("1", "true", "yes")


def _need(env: Mapping[str, str], name: str) -> str:
    v = env.get(name, "").strip()
    if not v:
        raise ConnectorError(f"set {name} (see docs/MAILBOX_SETUP.md)")
    return v


def new_http(auth=None, hosts: frozenset[str] = frozenset(), client: httpx.Client | None = None, **kw) -> HttpClient:
    return HttpClient(client, auth=auth, auth_hosts=hosts, **kw)


# -- Google ---------------------------------------------------------------------
def google_auth(env: Mapping[str, str], scopes: list[str], store_key: str, write: bool, client=None):
    """Token provider for Gmail API or Gmail IMAP; `write` selects the separate write credential."""
    tok_http = new_http(client=client)
    mode = env.get("PHISHGUARD_GMAIL_AUTH", "oauth")
    if mode == "service_account":
        var = "PHISHGUARD_GMAIL_WRITE_SA_KEY_FILE" if write else "PHISHGUARD_GMAIL_SA_KEY_FILE"
        key = read_json_secret_file(_need(env, var))
        subject = _need(env, "PHISHGUARD_GMAIL_USER")
        if "@" not in subject:
            raise ConnectorError("with a service account, PHISHGUARD_GMAIL_USER must be the mailbox address")
        return GoogleServiceAccount(tok_http, key, subject, scopes)
    if mode != "oauth":
        raise ConnectorError("PHISHGUARD_GMAIL_AUTH must be 'oauth' or 'service_account'")
    cid, secret = load_google_client(read_json_secret_file(_need(env, "PHISHGUARD_GMAIL_CLIENT_FILE")))
    entry = token_store(env, write).get(store_key) or {}
    if not entry.get("refresh_token"):
        flag_ = " --write" if write else ""
        raise OAuthError(
            f"no refresh token for {store_key}; run: python scripts/scan_mailbox.py --authorize{flag_} ..."
        )
    return GoogleRefreshToken(tok_http, cid, secret, Secret(entry["refresh_token"]))


# -- Microsoft -------------------------------------------------------------------
def microsoft_auth(env: Mapping[str, str], scopes: list[str], store_key: str, write: bool, client=None):
    tok_http = new_http(client=client)
    mode = env.get("PHISHGUARD_GRAPH_AUTH", "device")
    prefix = "PHISHGUARD_GRAPH_WRITE_" if write else "PHISHGUARD_GRAPH_"
    client_id = env.get(prefix + "CLIENT_ID") or _need(env, "PHISHGUARD_GRAPH_CLIENT_ID")
    if mode == "app":
        secret = secret_from_env(prefix + "CLIENT_SECRET", dict(env))
        if secret is None:
            raise ConnectorError(f"set {prefix}CLIENT_SECRET or {prefix}CLIENT_SECRET_FILE")
        return MicrosoftClientCredentials(tok_http, _need(env, "PHISHGUARD_GRAPH_TENANT"), client_id, secret)
    if mode != "device":
        raise ConnectorError("PHISHGUARD_GRAPH_AUTH must be 'device' or 'app'")
    tenant = env.get("PHISHGUARD_GRAPH_TENANT", "common")
    return MicrosoftRefreshToken(tok_http, tenant, client_id, token_store(env, write), store_key, scopes)


# -- connectors --------------------------------------------------------------------
def build_connector(
    provider: str, env: Mapping[str, str] | None = None, client: httpx.Client | None = None, **kw: Any
) -> MailboxConnector:
    env = os.environ if env is None else env
    allow_over = flag(env, "PHISHGUARD_ALLOW_OVERPRIVILEGED_READ")
    if provider == "gmail":
        auth = google_auth(env, [GMAIL_READ_SCOPE], "gmail:read", False, client)
        http = new_http(auth, gmail.AUTH_HOSTS, client)
        return gmail.GmailConnector(
            http, user=env.get("PHISHGUARD_GMAIL_USER") or "me", allow_overprivileged=allow_over, **kw
        )
    if provider == "graph":
        auth = microsoft_auth(env, [GRAPH_READ_SCOPE], "graph:read", False, client)
        mailbox = env.get("PHISHGUARD_GRAPH_MAILBOX") or None
        if env.get("PHISHGUARD_GRAPH_AUTH") == "app" and not mailbox:
            raise ConnectorError("app-only Graph auth needs PHISHGUARD_GRAPH_MAILBOX (a user principal name)")
        http = new_http(auth, graph.AUTH_HOSTS, client)
        return graph.GraphConnector(
            http,
            mailbox=mailbox,
            folder=env.get("PHISHGUARD_GRAPH_FOLDER", "inbox"),
            allow_overprivileged=allow_over,
            **kw,
        )
    if provider == "imap":
        return ImapConnector(**imap_params(env, write=False, client=client), **kw)
    raise ConnectorError(f"unknown provider {provider!r}; choose one of {', '.join(PROVIDERS)}")


def imap_params(env: Mapping[str, str], write: bool, client=None) -> dict[str, Any]:
    preset = PRESETS.get(env.get("PHISHGUARD_IMAP_PRESET", "").lower()) if env.get("PHISHGUARD_IMAP_PRESET") else None
    if env.get("PHISHGUARD_IMAP_PRESET") and preset is None:
        raise ConnectorError(f"unknown IMAP preset; choose one of {', '.join(sorted(PRESETS))}")
    host = env.get("PHISHGUARD_IMAP_HOST") or (preset.host if preset else "")
    if not host:
        raise ConnectorError("set PHISHGUARD_IMAP_PRESET or PHISHGUARD_IMAP_HOST")
    user = _need(env, "PHISHGUARD_IMAP_USER")
    tls = env.get("PHISHGUARD_IMAP_TLS", "1") != "0"
    p: dict[str, Any] = {
        "host": host,
        "username": user,
        "port": int(env.get("PHISHGUARD_IMAP_PORT") or (preset.port if preset else 993)),
        "folder": env.get("PHISHGUARD_IMAP_FOLDER", "INBOX"),
        "tls": tls,
        "allow_plaintext": flag(env, "PHISHGUARD_IMAP_ALLOW_PLAINTEXT"),
        "send_id": bool(preset and preset.send_id),
    }
    if env.get("PHISHGUARD_IMAP_AUTH", "password") == "xoauth2":
        which = env.get("PHISHGUARD_IMAP_OAUTH_PROVIDER") or (preset.oauth_provider if preset else None)
        if which == "google":
            p["oauth"] = google_auth(
                env, [GOOGLE_IMAP_SCOPE], "imap-google:" + ("write" if write else "read"), write, client
            )
        elif which == "microsoft":
            p["oauth"] = microsoft_auth(
                env, [OUTLOOK_IMAP_SCOPE], "imap-microsoft:" + ("write" if write else "read"), write, client
            )
        else:
            raise ConnectorError("XOAUTH2 needs PHISHGUARD_IMAP_OAUTH_PROVIDER=google|microsoft")
        return p
    name = "PHISHGUARD_IMAP_WRITE_PASSWORD" if write else "PHISHGUARD_IMAP_PASSWORD"
    pw = secret_from_env(name, dict(env))
    if pw is None:
        raise ConnectorError(f"set {name} or {name}_FILE (an app password, not your account password)")
    p["password"] = pw
    return p


# -- one-time interactive authorization -----------------------------------------------
def authorize(
    provider: str,
    env: Mapping[str, str] | None = None,
    write: bool = False,
    open_url: Callable[[str], Any] = print,
    prompt: Callable[[str], None] = print,
    client: httpx.Client | None = None,
) -> str:
    """Run the provider's sign-in once and store the refresh token. Returns the store key."""
    env = os.environ if env is None else env
    http = new_http(client=client)
    role = "write" if write else "read"
    if provider in ("gmail", "imap-google"):
        if env.get("PHISHGUARD_GMAIL_AUTH") == "service_account":
            raise ConnectorError("service accounts need no sign-in; grant domain-wide delegation in the Admin console")
        cid, secret = load_google_client(read_json_secret_file(_need(env, "PHISHGUARD_GMAIL_CLIENT_FILE")))
        if provider == "gmail":
            scopes, key = [GMAIL_MODIFY_SCOPE if write else GMAIL_READ_SCOPE], f"gmail:{role}"
        else:
            scopes, key = [GOOGLE_IMAP_SCOPE], f"imap-google:{role}"
        data = google_loopback_flow(http, cid, secret, scopes, open_url=open_url)
    elif provider in ("graph", "imap-microsoft"):
        if env.get("PHISHGUARD_GRAPH_AUTH") == "app":
            raise ConnectorError("app-only auth needs no sign-in; grant admin consent in the Azure portal")
        cid = (env.get("PHISHGUARD_GRAPH_WRITE_CLIENT_ID") if write else None) or _need(
            env, "PHISHGUARD_GRAPH_CLIENT_ID"
        )
        tenant = env.get("PHISHGUARD_GRAPH_TENANT", "common")
        if provider == "graph":
            scopes, key = [GRAPH_WRITE_SCOPE if write else GRAPH_READ_SCOPE], f"graph:{role}"
        else:
            scopes, key = [OUTLOOK_IMAP_SCOPE], f"imap-microsoft:{role}"
        data = microsoft_device_code_flow(http, tenant, cid, scopes, prompt=prompt)
    else:
        raise ConnectorError("authorize: provider must be gmail, graph, imap-google or imap-microsoft")
    token_store(env, write).put(key, {"refresh_token": data["refresh_token"], "scope": data.get("scope", "")})
    return key


__all__ = ["GOOGLE_TOKEN_URL", "MS_LOGIN", "PROVIDERS", "authorize", "build_connector", "token_store"]
