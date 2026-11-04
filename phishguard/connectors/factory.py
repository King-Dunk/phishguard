"""Build connectors (and their token providers) from a mailbox config entry.

The config file (YAML, see docs/MAILBOX_SETUP.md) holds no secret values, only where to find them:
`*_env` names an environment variable, `*_file` a private file outside the repository. Read and write
credentials are separate entries (`auth` vs `remediation.auth`) with separate token files, so a read-only
deployment never holds a token that can change mail.
"""

from __future__ import annotations

import os
from typing import Any

import httpx
import yaml

from . import auth as A
from .base import MailboxConnector
from .gmail import API_HOST, GmailConnector
from .graph import GRAPH_HOST, GraphConnector
from .http import RetryingClient
from .imap import ImapConnector
from .presets import PRESETS
from .secrets import TokenStore, load_json_secret, load_secret

PROVIDERS = ("gmail", "graph", "imap")


class ConfigError(ValueError):
    pass


def load_config(path: str | os.PathLike) -> dict[str, Any]:
    cfg = yaml.safe_load(open(os.path.expanduser(path), encoding="utf-8")) or {}
    names = [m.get("name") for m in cfg.get("mailboxes", [])]
    if len(names) != len(set(names)) or not all(names):
        raise ConfigError("every mailbox needs a unique name")
    for m in cfg.get("mailboxes", []):
        if m.get("provider") not in PROVIDERS:
            raise ConfigError(f"mailbox {m.get('name')}: provider must be one of {PROVIDERS}")
        for section in (m.get("auth", {}), (m.get("remediation") or {}).get("auth", {})):
            for k, v in section.items():
                if k in ("password", "client_secret", "refresh_token", "access_token", "private_key"):
                    raise ConfigError(f"mailbox {m['name']}: put secrets in {k}_env or {k}_file, not inline")
                if isinstance(v, str) and k.endswith("_file"):
                    section[k] = os.path.expanduser(v)
    return cfg


def http_client() -> httpx.Client:
    return httpx.Client(timeout=httpx.Timeout(30.0, connect=10.0), follow_redirects=False)


def _secret(a: dict, key: str, required: bool = True) -> str | None:
    return load_secret(env=a.get(f"{key}_env"), file=a.get(f"{key}_file"), required=required)


def _google_client(a: dict) -> dict:
    return load_json_secret(env=a.get("client_env"), file=a.get("client_file"))


def scopes_for(provider: str, write: bool, auth_type: str, oauth: str | None = None) -> tuple[str, ...]:
    if provider == "gmail":
        return (A.GMAIL_WRITE_SCOPE if write else A.GMAIL_READ_SCOPE,)
    if provider == "graph":
        if auth_type == "client_credentials":
            return (A.GRAPH_APP_SCOPE,)
        return A.GRAPH_WRITE_SCOPES if write else A.GRAPH_READ_SCOPES
    if oauth == "google":
        return (A.GOOGLE_IMAP_SCOPE,)
    return A.OUTLOOK_IMAP_SCOPES


def token_provider(
    provider: str, a: dict, write: bool, http: httpx.Client, oauth: str | None = None
) -> A.TokenProvider:
    t = a.get("type", "oauth")
    if provider == "gmail" or (provider == "imap" and oauth == "google"):
        if t == "service_account":
            key = load_json_secret(env=a.get("key_env"), file=a.get("key_file"))
            if not a.get("subject"):
                raise ConfigError("service_account needs `subject` (the mailbox to impersonate)")
            return A.GoogleServiceAccount(http, key, a["subject"], scopes_for(provider, write, t, oauth))
        c = _google_client(a)
        c = c.get("installed") or c.get("web") or c
        return A.RefreshTokenProvider(
            http, A.GOOGLE_TOKEN_URL, c["client_id"], TokenStore(a["token_file"]), c.get("client_secret")
        )
    # Microsoft (Graph, or IMAP XOAUTH2 for Outlook)
    tenant = a.get("tenant", "common")
    if t == "client_credentials":
        if provider == "graph" and a.get("_user", "me") == "me":
            raise ConfigError(
                "Graph application (client_credentials) auth has no signed-in user: set `user` to a UPN or id"
            )
        return A.ClientCredentials(http, tenant, a["client_id"], _secret(a, "client_secret"))
    return A.RefreshTokenProvider(
        http,
        A.ms_token_url(tenant),
        a["client_id"],
        TokenStore(a["token_file"]),
        _secret(a, "client_secret", required=False),
        scopes_for(provider, write, t, oauth),
    )


def imap_settings(m: dict) -> dict[str, Any]:
    preset = PRESETS.get(m.get("preset", ""))
    return {
        "host": m.get("host") or (preset.host if preset else None),
        "port": int(m.get("port") or (preset.port if preset else 993)),
        "send_id": bool(m.get("send_id", preset.send_id if preset else False)),
        "oauth": (m.get("auth") or {}).get("oauth") or (preset.oauth if preset else None),
    }


def build_imap(m: dict, a: dict, ImapClass=ImapConnector):  # noqa: N803
    s = imap_settings(m)
    if not s["host"]:
        raise ConfigError(f"mailbox {m['name']}: imap needs `host` or a known `preset` ({', '.join(PRESETS)})")
    kw: dict[str, Any] = {}
    if a.get("type", "password") == "xoauth2":
        kw["token_provider"] = token_provider("imap", a, False, http_client(), s["oauth"])
    else:
        kw["password"] = _secret(a, "password")
    return ImapClass(
        m["name"],
        s["host"],
        m["username"],
        port=s["port"],
        folder=m.get("folder", "INBOX"),
        tls=m.get("tls", "implicit"),
        allow_plaintext=bool(m.get("allow_plaintext_for_local_testing", False)),
        send_id=s["send_id"],
        **kw,
    )


def build_connector(m: dict, http: httpx.Client | None = None, sleep=None) -> MailboxConnector:
    """Read connector for one mailbox config entry (read credentials only)."""
    a = m.get("auth") or {}
    p = m["provider"]
    if p == "imap":
        return build_imap(m, a)
    http = http or http_client()
    tok = token_provider(p, {**a, "_user": m.get("user", "me")}, False, http)
    kw = {"sleep": sleep} if sleep else {}
    if p == "gmail":
        return GmailConnector(
            RetryingClient(http, tok, [API_HOST], **kw), m["name"], m.get("user", "me"), m.get("query", "in:inbox")
        )
    return GraphConnector(
        RetryingClient(http, tok, [GRAPH_HOST], **kw), m["name"], m.get("user", "me"), m.get("folder", "inbox")
    )
