"""Scan the last N messages of a mailbox and print verdicts. Read-only: never changes the mailbox.

One-time authorization (stores a refresh token, mode 0600, outside the repo):
    python scripts/scan_mailbox.py --provider gmail --client-file ~/.config/phishguard/google-client.json \\
        --token-file ~/.config/phishguard/tokens/gmail-read.json --authorize
    python scripts/scan_mailbox.py --provider graph --client-id <app id> --tenant common \\
        --token-file ~/.config/phishguard/tokens/graph-read.json --authorize

Scan:
    python scripts/scan_mailbox.py --provider gmail --client-file ... --token-file ... --last 20
    python scripts/scan_mailbox.py --provider graph --client-id ... --token-file ... --last 20
    PG_IMAP_PASSWORD=... python scripts/scan_mailbox.py --provider imap --preset icloud \\
        --username you@icloud.com --password-env PG_IMAP_PASSWORD --last 20
    python scripts/scan_mailbox.py --config ~/.config/phishguard/mailboxes.yaml --mailbox work --last 20

Add --write to --authorize to obtain WRITE credentials (gmail.modify / Mail.ReadWrite) for remediation;
store them in a different token file. --state-db makes repeated scans incremental (only new mail).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from phishguard.agent import PhishingAgent  # noqa: E402
from phishguard.config import Settings  # noqa: E402
from phishguard.connectors import CheckpointStore, Scanner  # noqa: E402
from phishguard.connectors import auth as A  # noqa: E402
from phishguard.connectors.factory import build_connector, http_client, load_config, scopes_for  # noqa: E402
from phishguard.connectors.http import ProviderError  # noqa: E402
from phishguard.connectors.secrets import (  # noqa: E402
    SecretError,
    TokenStore,
    install_redaction,
    load_json_secret,
    redact,
)
from phishguard.readonly import DetectionContext  # noqa: E402


def _llm(settings: Settings):
    if settings.llm_mode == "anthropic":
        from phishguard.llm.anthropic_client import AnthropicLLM

        return AnthropicLLM(settings)
    from phishguard.llm import MockLLM

    return MockLLM()


def entry_from_args(a) -> dict:
    if a.provider == "imap":
        auth = (
            {
                "type": "xoauth2",
                "oauth": a.oauth,
                "token_file": a.token_file,
                "client_file": a.client_file,
                "client_id": a.client_id,
                "tenant": a.tenant,
            }
            if a.oauth
            else {"type": "password", "password_env": a.password_env, "password_file": a.password_file}
        )
        return {
            "name": a.name or "cli-imap",
            "provider": "imap",
            "preset": a.preset,
            "host": a.host,
            "port": a.port,
            "username": a.username,
            "folder": a.folder or "INBOX",
            "auth": auth,
        }
    if a.provider == "gmail":
        auth = (
            {"type": "service_account", "key_file": a.service_account_key, "subject": a.subject}
            if a.service_account_key
            else {"type": "oauth", "client_file": a.client_file, "token_file": a.token_file}
        )
        return {"name": a.name or "cli-gmail", "provider": "gmail", "user": a.user or "me", "auth": auth}
    auth = {
        "type": "client_credentials" if a.client_secret_env or a.client_secret_file else "delegated",
        "tenant": a.tenant,
        "client_id": a.client_id,
        "token_file": a.token_file,
        "client_secret_env": a.client_secret_env,
        "client_secret_file": a.client_secret_file,
    }
    return {
        "name": a.name or "cli-graph",
        "provider": "graph",
        "user": a.user or "me",
        "folder": a.folder or "inbox",
        "auth": auth,
    }


def authorize(a) -> int:
    store = TokenStore(a.token_file)
    http = http_client()
    if a.provider == "graph" or (a.provider == "imap" and a.oauth == "microsoft"):
        scopes = scopes_for("graph", a.write, "delegated") if a.provider == "graph" else A.OUTLOOK_IMAP_SCOPES
        A.device_code_flow(http, a.tenant, a.client_id, scopes, store)
        return 0
    client = load_json_secret(file=a.client_file)
    scopes = (A.GOOGLE_IMAP_SCOPE,) if a.provider == "imap" else scopes_for("gmail", a.write, "oauth")
    import webbrowser

    A.google_installed_app_flow(http, client, scopes, store, open_browser=None if a.no_browser else webbrowser.open)
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Scan the last N messages of a mailbox (read-only).")
    ap.add_argument("--config")
    ap.add_argument("--mailbox", help="name of a mailbox in --config")
    ap.add_argument("--provider", choices=["gmail", "graph", "imap"])
    ap.add_argument("--name")
    ap.add_argument("--last", type=int, default=20)
    ap.add_argument("--state-db", help="persist cursor + seen set: later runs only scan new mail")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--redact", action="store_true", help="hide sender and subject in the output")
    ap.add_argument(
        "--authorize", action="store_true", help="run the one-time OAuth consent and store the refresh token"
    )
    ap.add_argument("--write", action="store_true", help="with --authorize: request write scope for remediation")
    ap.add_argument("--no-browser", action="store_true")
    # gmail
    ap.add_argument("--client-file", help="Google OAuth client JSON (Desktop app)")
    ap.add_argument("--token-file", help="where the refresh token is stored (outside the repo)")
    ap.add_argument("--service-account-key", help="Workspace service-account key JSON (domain-wide delegation)")
    ap.add_argument("--subject", help="mailbox to impersonate with the service account")
    ap.add_argument("--user", help="Graph: 'me' or a UPN (app-only); Gmail: 'me'")
    # graph
    ap.add_argument("--tenant", default="common")
    ap.add_argument("--client-id")
    ap.add_argument("--client-secret-env")
    ap.add_argument("--client-secret-file")
    ap.add_argument("--folder")
    # imap
    ap.add_argument("--preset")
    ap.add_argument("--host")
    ap.add_argument("--port", type=int)
    ap.add_argument("--username")
    ap.add_argument("--password-env")
    ap.add_argument("--password-file")
    ap.add_argument("--oauth", choices=["google", "microsoft"], help="IMAP XOAUTH2 instead of a password")
    a = ap.parse_args(argv)
    install_redaction()
    try:
        if a.authorize:
            if not a.token_file:
                ap.error("--authorize needs --token-file")
            return authorize(a)
        if a.config:
            cfg = load_config(a.config)
            entry = next((m for m in cfg["mailboxes"] if m["name"] == a.mailbox), None)
            if entry is None:
                ap.error(f"mailbox {a.mailbox!r} not in {a.config}")
        elif a.provider:
            entry = entry_from_args(a)
        else:
            ap.error("give --config/--mailbox or --provider")
        s = Settings.from_env()
        conn = build_connector(entry)
        agent = PhishingAgent(_llm(s), s, DetectionContext(s.trusted_domains, s.executives))
        store = CheckpointStore(a.state_db or ":memory:")
        res = Scanner(conn, agent, store, s.phishing_threshold, s.trusted_authserv_id).scan(a.last)
    except (ProviderError, SecretError, KeyError, ValueError) as e:
        print(f"error: {redact(e)}", file=sys.stderr)
        return 2
    rows = []
    for v in res.verdicts:
        row = v.public()
        if not a.redact:
            row["sender"], row["subject"] = v.sender[:60], v.subject[:70]
        rows.append(row)
    if a.json:
        print(
            redact(json.dumps({"verdicts": rows, "duplicates": res.duplicates, "notes": res.notes}, ensure_ascii=False))
        )
        return 0
    for r in rows:
        mark = "PHISH" if r["is_phishing"] else ("ok" if r["status"] == "scanned" else r["status"].upper())
        risk = "" if r["risk"] is None else f"{r['risk']:5.1f}"
        who = "" if a.redact else f"  {r['sender']}  |  {r['subject']}"
        print(redact(f"{mark:11} {risk:>5}  {', '.join(r['top_features'])[:50]:50}{who}"))
    flagged = sum(1 for r in rows if r["is_phishing"])
    print(
        f"\n{len(rows)} scanned, {flagged} flagged (threshold {s.phishing_threshold:g}), {res.duplicates} already seen"
    )
    for n in res.notes:
        print(f"note: {n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
