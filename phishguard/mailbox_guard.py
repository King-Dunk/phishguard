"""Scan a mailbox and act on phishing verdicts, through the MFA gateway.

    python -m phishguard.mailbox_guard --provider gmail --action quarantine
    python -m phishguard.mailbox_guard --provider imap --action label --action quarantine --once

This is glue, like api.py: it is allowed to import both sides. The scanning loop is the read-only
worker (`phishguard.connectors.worker.run`); the sink below turns each flagged verdict into
`gateway.submit(...)`. The gateway's policy decides whether MFA is needed (single-message
quarantine/junk/label/banner: no; delete, release, or a batch over 10: yes). The worker never
approves its own MFA: anything that needs MFA stays pending and is reported.

Write access is opt-in: without write credentials (see docs/MAILBOX_SETUP.md) this refuses to start.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import threading
from collections.abc import Mapping

from .config import Settings
from .connectors.base import ConnectorError
from .connectors.config import PROVIDERS
from .connectors.scanner import Verdict
from .connectors.secrets import SecretError, get_logger, install_redaction, redact
from .connectors.worker import build_scanner, run
from .mutating import AuditLog, Executor, MFAGateway, SQLiteStore
from .mutating.mailbox import remediation_handlers, remediator_from_env

log = get_logger(__name__)

ACTIONS = {
    "quarantine": "quarantine_email",
    "junk": "mark_spam",
    "label": "apply_label",
    "banner": "add_warning_banner",
}
REQUESTED_BY = "phishguard-mailbox-guard"


class GatewaySink:
    """Verdict -> gateway.submit for each configured action. Never verifies MFA itself."""

    def __init__(self, gateway: MFAGateway, actions: list[str], label: str = "PhishGuard/Suspicious"):
        unknown = [a for a in actions if a not in ACTIONS]
        if unknown:
            raise ValueError(f"unknown action(s): {unknown}")
        self.gateway, self.actions, self.label = gateway, actions, label
        self.submitted: list[dict] = []

    def __call__(self, v: Verdict) -> None:
        if not v.is_phishing or v.status != "scanned":
            return
        for a in self.actions:
            params: dict = {"provider": v.provider, "mailbox": v.mailbox, "message_id": v.provider_id}
            if a == "label":
                params["label"] = self.label
            if a == "banner":
                params["risk"] = v.risk_percent
            # reason is neutral on purpose: no subject text, so mail content can't steer the policy
            r = self.gateway.submit(ACTIONS[a], params, REQUESTED_BY, reason=f"risk {v.risk_percent} >= {v.threshold}")
            rec = {"action": ACTIONS[a], "message_id": v.provider_id, "status": r.status}
            if r.status == "pending_mfa":
                rec["pending_id"] = r.pending_id
                log.warning("%s on %s needs MFA approval (pending %s)", ACTIONS[a], v.provider_id, r.pending_id)
            elif r.result and not r.result.get("ok"):
                rec["error"] = (r.result.get("outcome") or {}).get("error", "failed")
                log.error("%s on %s failed: %s", ACTIONS[a], v.provider_id, rec["error"])
            self.submitted.append(rec)
            if a == "banner" and r.status == "executed":
                break  # the banner action already quarantined the original


def build_gateway(provider: str, env: Mapping[str, str], settings: Settings, client=None, **kw) -> MFAGateway:
    rem = remediator_from_env(provider, env, client=client, **kw)
    store = SQLiteStore(settings.db_path) if settings.db_path else None
    return MFAGateway(
        executor=Executor(handlers=remediation_handlers(rem)),
        audit=AuditLog(settings.audit_log_path, store=store),
        timeout_seconds=settings.mfa_timeout_seconds,
        max_attempts=settings.mfa_max_attempts,
        store=store,
    )


def main(argv: list[str] | None = None, env: Mapping[str, str] | None = None) -> int:
    env = os.environ if env is None else env
    p = argparse.ArgumentParser(prog="python -m phishguard.mailbox_guard", description=__doc__.split("\n")[0])
    p.add_argument("--provider", choices=PROVIDERS, required=True)
    p.add_argument("--action", action="append", choices=sorted(ACTIONS), help="repeatable; default quarantine")
    p.add_argument("--label", default="PhishGuard/Suspicious")
    p.add_argument("--interval", type=float, default=float(env.get("PHISHGUARD_POLL_INTERVAL", "60")))
    p.add_argument("--once", action="store_true")
    p.add_argument("--backfill", type=int, default=0)
    p.add_argument("--state", default=None)
    args = p.parse_args(argv)
    handler = install_redaction(logging.StreamHandler(sys.stderr))
    logging.basicConfig(
        level=logging.INFO, handlers=[handler], format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    settings = Settings.from_env()
    try:
        gateway = build_gateway(args.provider, env, settings)
        sink = GatewaySink(gateway, args.action or ["quarantine"], label=args.label)
        scanner = build_scanner(args.provider, env, args.state, sink=sink, backfill=args.backfill, settings=settings)
        return run(scanner, args.interval, once=args.once, stop=threading.Event())
    except (ConnectorError, SecretError, ValueError) as e:
        log.error("%s", redact(e))
        return 2


if __name__ == "__main__":
    sys.exit(main())
