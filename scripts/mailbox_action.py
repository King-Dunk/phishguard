"""Human-initiated mailbox actions through the MFA gateway (delete, restore, bulk quarantine, ...).

    python scripts/mailbox_action.py --config ~/.config/phishguard/mailboxes.yaml --mailbox work \\
        --as alice restore --ids 18c2f0a1b2c3d4e5
    python scripts/mailbox_action.py --config ... --mailbox work --as alice quarantine --ids a,b,c,...

delete and restore always need MFA; more than 10 messages in one request (bulk) needs MFA. When MFA is
required the script asks for the code: the TOTP code if `alice` has enrolled (POST /mfa/enroll), otherwise
the one-time code printed by the development channel. Uses the same SQLite store as the API
(PHISHGUARD_DB_PATH), so pending actions and the audit chain are shared.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from phishguard.connectors.factory import load_config  # noqa: E402
from phishguard.connectors.secrets import install_redaction, redact  # noqa: E402
from phishguard.mutating import MFAFailed, OperationLocked, PendingExpired, UnknownActionError  # noqa: E402
from phishguard.worker import build_worker  # noqa: E402

VERBS = {
    "quarantine": "mailbox_quarantine",
    "label": "mailbox_label",
    "banner": "mailbox_banner",
    "delete": "mailbox_delete",
    "restore": "mailbox_restore",
}


def main(argv: list[str] | None = None, ask=getpass.getpass, worker=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--config", required=worker is None)
    ap.add_argument("--mailbox", required=True)
    ap.add_argument("--as", dest="user", required=True, help="who is asking (their TOTP is used)")
    ap.add_argument("verb", choices=sorted(VERBS))
    ap.add_argument("--ids", required=True, help="comma-separated provider message ids")
    ap.add_argument("--label", default="PhishGuard: suspected phishing")
    ap.add_argument("--reason", default="manual action")
    a = ap.parse_args(argv)
    install_redaction()
    w = worker or build_worker(load_config(a.config))
    gw = w.gateway
    m = w.mailboxes.get(a.mailbox)
    if m is None:
        print(f"unknown mailbox {a.mailbox!r}", file=sys.stderr)
        return 2
    params = {
        "provider": m["provider"],
        "mailbox": a.mailbox,
        "message_ids": [i.strip() for i in a.ids.split(",") if i.strip()],
    }
    if a.verb == "label":
        params["label"] = a.label
    try:
        r = gw.submit(VERBS[a.verb], params, a.user, a.reason)
        if r.status == "pending_mfa":
            print(f"MFA required: {r.summary}\nconfirm digest: {r.digest}")
            for _ in range(gw.max_attempts):
                try:
                    result = gw.verify(r.pending_id, ask("code: ").strip(), r.digest)
                    break
                except MFAFailed as e:
                    print(f"rejected: {e} ({e.attempts_left} left)")
                    if e.attempts_left == 0:
                        return 1
            else:
                return 1
        else:
            result = r.result
    except (UnknownActionError, OperationLocked, PendingExpired) as e:
        print(f"refused: {redact(e)}", file=sys.stderr)
        return 1
    print(redact(f"result: {result}"))
    return 0 if result and result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
