"""Scan the last N messages of a real mailbox and print verdicts (read-only).

    # one-time sign-in (stores a refresh token outside the repo, mode 0600)
    python scripts/scan_mailbox.py --provider gmail --authorize
    python scripts/scan_mailbox.py --provider graph --authorize
    python scripts/scan_mailbox.py --provider imap  --authorize   # only for XOAUTH2 (Gmail/Outlook IMAP)

    # scan
    python scripts/scan_mailbox.py --provider gmail --last 20
    python scripts/scan_mailbox.py --provider imap  --last 50 --json

    # opt-in: a SEPARATE write credential for remediation (python -m phishguard.mailbox_guard)
    python scripts/scan_mailbox.py --provider gmail --authorize --write

Configuration comes from environment variables; see docs/MAILBOX_SETUP.md. This script never
changes the mailbox: Gmail uses gmail.readonly, Graph Mail.Read, IMAP EXAMINE + BODY.PEEK[].
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import webbrowser

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from phishguard.connectors.base import ConnectorError  # noqa: E402
from phishguard.connectors.config import PROVIDERS, authorize  # noqa: E402
from phishguard.connectors.secrets import SecretError, install_redaction, redact  # noqa: E402
from phishguard.connectors.worker import build_scanner  # noqa: E402


def _row(v) -> str:
    if v.status != "scanned":
        return f"{'-':>6}  {v.status.upper():<8} {v.provider_id[:24]:<24} {v.detail[:70]}"
    tag = "PHISH" if v.is_phishing else "ok"
    feats = ", ".join(f"{f['name']}+{f['contribution']}" for f in v.top_features[:3])
    cached = " (cached)" if v.cached else ""
    subj = " ".join(v.subject.split())[:50]
    return f"{v.risk_percent:>6.1f}  {tag:<8} {v.sender[:32]:<32} {subj:<50} {feats}{cached}"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Scan the last N messages of a mailbox (read-only).")
    p.add_argument("--provider", choices=PROVIDERS, required=True)
    p.add_argument("--last", type=int, default=20, help="how many recent messages to scan (default 20)")
    p.add_argument("--json", action="store_true", help="one JSON object per line instead of a table")
    p.add_argument("--state", default=None, help="checkpoint DB (default ~/.phishguard/connector_state.db)")
    p.add_argument("--authorize", action="store_true", help="run the one-time sign-in and store a refresh token")
    p.add_argument("--write", action="store_true", help="with --authorize: mint the separate WRITE credential")
    p.add_argument("--no-browser", action="store_true", help="print the sign-in URL instead of opening it")
    args = p.parse_args(argv)
    if not 1 <= args.last <= 500:
        p.error("--last must be between 1 and 500")
    logging.basicConfig(level=logging.WARNING, handlers=[install_redaction(logging.StreamHandler(sys.stderr))])

    try:
        if args.authorize:
            which = args.provider
            if which == "imap":
                which = "imap-" + (os.environ.get("PHISHGUARD_IMAP_OAUTH_PROVIDER") or "google")
            opener = print if args.no_browser else (lambda u: (print(u), webbrowser.open(u)))
            key = authorize(which, write=args.write, open_url=opener)
            print(
                f"Stored refresh token '{key}'. You can now run: python scripts/scan_mailbox.py --provider {args.provider}"
            )
            return 0
        scanner = build_scanner(args.provider, state_path=args.state)
        verdicts = scanner.scan_recent(args.last)
    except (ConnectorError, SecretError, ValueError) as e:
        print(f"error: {redact(e)}", file=sys.stderr)
        return 2

    if args.json:
        for v in verdicts:
            print(redact(json.dumps(v.to_dict(), ensure_ascii=False)))
    else:
        print(f"{'risk':>6}  {'verdict':<8} {'from':<32} {'subject':<50} top features")
        for v in verdicts:
            print(redact(_row(v)))
        flagged = sum(1 for v in verdicts if v.is_phishing)
        print(f"\n{len(verdicts)} message(s), {flagged} flagged at threshold {scanner.threshold:g}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
