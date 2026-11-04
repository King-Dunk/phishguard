"""Polling worker: scan every configured mailbox, then (optionally) remediate through the MFA gateway.

    python -m phishguard.worker --config ~/.config/phishguard/mailboxes.yaml            # loop
    python -m phishguard.worker --config ... --once                                      # one pass (cron)
    python -m phishguard.worker --config ... --dry-run                                   # never remediate

Like api.py this is an orchestrator: it may import both sides. Scanning (phishguard.connectors) is
read-only; every change to a mailbox is a gateway.submit() of a mailbox_* action, which the policy may
suspend for MFA (bulk, delete, restore). Remediation is off unless a mailbox sets remediation.enabled.
Push notifications (webhooks) only add a trigger row; this loop notices it and scans that mailbox early.
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from .agent import PhishingAgent
from .config import Settings
from .connectors import CheckpointStore, Scanner, Verdict
from .connectors.factory import build_connector, load_config
from .connectors.http import ProviderError, RateLimited
from .connectors.secrets import install_redaction, redact
from .llm import MockLLM
from .mutating import AuditLog, MFAGateway, SQLiteStore, StderrChannel, TOTPManager
from .mutating.executor import Executor
from .mutating.remediation import build_writer, handlers
from .readonly import DetectionContext

log = logging.getLogger("phishguard.worker")
REQUESTER = "phishguard-worker"
ACTIONS = {"quarantine": "mailbox_quarantine", "label": "mailbox_label", "banner": "mailbox_banner"}


@dataclass
class MailboxRun:
    name: str
    verdicts: list[Verdict] = field(default_factory=list)
    actions: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None
    retry_after: float | None = None


class MailboxWorker:
    def __init__(
        self, config: dict, settings: Settings, gateway: MFAGateway, store: CheckpointStore, connectors=None, agent=None
    ):
        self.config, self.settings, self.gateway, self.store = config, settings, gateway, store
        self.mailboxes = {m["name"]: m for m in config.get("mailboxes", [])}
        self.connectors = connectors or {}
        ctx = DetectionContext(settings.trusted_domains, settings.executives)
        self.agent = agent or PhishingAgent(_llm(settings), settings, ctx)
        self.limit = int(config.get("limit", 50))
        self.paused_until: dict[str, float] = {}

    def connector(self, name: str):
        if name not in self.connectors:
            self.connectors[name] = build_connector(self.mailboxes[name])
        return self.connectors[name]

    def scan_mailbox(self, name: str, dry_run: bool = False) -> MailboxRun:
        run = MailboxRun(name)
        if time.time() < self.paused_until.get(name, 0):
            run.error = "rate limited; paused"
            return run
        m = self.mailboxes[name]
        try:
            res = Scanner(
                self.connector(name),
                self.agent,
                self.store,
                self.settings.phishing_threshold,
                self.settings.trusted_authserv_id,
            ).scan(self.limit)
        except RateLimited as e:
            self.paused_until[name] = time.time() + (e.retry_after or 300)
            run.error, run.retry_after = str(e), e.retry_after
            return run
        except ProviderError as e:
            run.error = str(e)
            log.warning("mailbox %s: %s", name, e)
            return run
        run.verdicts = res.verdicts
        rem = m.get("remediation") or {}
        if dry_run or not rem.get("enabled"):
            return run
        action = ACTIONS.get(rem.get("action", "quarantine"))
        if action is None:
            run.error = f"unknown remediation action {rem.get('action')!r}"
            return run
        min_risk = float(rem.get("min_risk", self.settings.phishing_threshold))
        for v in res.verdicts:
            if v.status != "scanned" or not v.is_phishing or (v.risk or 0) < min_risk:
                continue
            params = {
                "provider": m["provider"],
                "mailbox": name,
                "message_ids": [v.provider_id],
                "verdict_risk": v.risk,
            }
            if action == "mailbox_label":
                params["label"] = rem.get("label", "PhishGuard: suspected phishing")
            r = self.gateway.submit(action, params, REQUESTER, reason="automatic remediation of a scanned message")
            entry = {"provider_id": v.provider_id, "action": action, "status": r.status}
            if r.status == "executed":
                entry["ok"] = bool(r.result and r.result.get("ok"))
                if not entry["ok"]:
                    entry["error"] = (r.result or {}).get("error")
            else:
                entry["pending_id"] = r.pending_id  # policy wants a human (e.g. content escalation)
            self.gateway.audit.record(
                "remediation_result", mailbox=name, **{k: v for k, v in entry.items() if k != "provider_id"}
            )
            run.actions.append(entry)
        return run

    def run_once(self, names: list[str] | None = None, dry_run: bool = False) -> list[MailboxRun]:
        return [self.scan_mailbox(n, dry_run) for n in (names or list(self.mailboxes))]

    def loop(self, interval: float, stop: threading.Event, dry_run: bool = False, tick: float = 2.0) -> None:
        next_full = 0.0
        while not stop.is_set():
            now = time.time()
            if now >= next_full:
                self._report(self.run_once(dry_run=dry_run))
                next_full = now + interval
            else:
                triggered = [t for t in self.store.pop_triggers() if t in self.mailboxes]
                if triggered:
                    self._report(self.run_once(triggered, dry_run))
            stop.wait(tick)

    @staticmethod
    def _report(runs: list[MailboxRun]) -> None:
        for r in runs:
            flagged = sum(1 for v in r.verdicts if v.is_phishing)
            log.info(
                "mailbox %s: %d new, %d flagged, %d actions%s",
                r.name,
                len(r.verdicts),
                flagged,
                len(r.actions),
                f", error: {r.error}" if r.error else "",
            )


def _llm(settings: Settings):
    if settings.llm_mode == "anthropic":
        from .llm.anthropic_client import AnthropicLLM

        return AnthropicLLM(settings)
    return MockLLM()


def build_worker(config: dict, settings: Settings | None = None, dry_run: bool = False) -> MailboxWorker:
    settings = settings or Settings.from_env()
    writers = {} if dry_run else {m["name"]: w for m in config.get("mailboxes", []) if (w := build_writer(m))}
    gw_store = SQLiteStore(settings.db_path) if settings.db_path else None
    gateway = MFAGateway(
        executor=Executor(handlers(writers)),
        audit=AuditLog(settings.audit_log_path, store=gw_store),
        channel=StderrChannel(),
        timeout_seconds=settings.mfa_timeout_seconds,
        max_attempts=settings.mfa_max_attempts,
        totp=TOTPManager(store=gw_store),
        store=gw_store,
    )
    state = os.path.expanduser(config.get("state_db", "~/.local/state/phishguard/scan.db"))
    if state != ":memory:":
        os.makedirs(os.path.dirname(state), mode=0o700, exist_ok=True)
    return MailboxWorker(config, settings, gateway, CheckpointStore(state))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Poll mailboxes and scan new mail.")
    ap.add_argument(
        "--config",
        default=os.environ.get("PHISHGUARD_MAILBOX_CONFIG"),
        required=os.environ.get("PHISHGUARD_MAILBOX_CONFIG") is None,
    )
    ap.add_argument("--once", action="store_true")
    ap.add_argument(
        "--interval", type=float, default=None, help="seconds between full passes (default: config, else 300)"
    )
    ap.add_argument("--dry-run", action="store_true", help="scan only, never remediate")
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    install_redaction()
    cfg = load_config(a.config)
    w = build_worker(cfg, dry_run=a.dry_run)
    if a.once:
        runs = w.run_once(dry_run=a.dry_run)
        w._report(runs)
        return 1 if any(r.error for r in runs) else 0
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    interval = a.interval or float(cfg.get("interval_seconds", 300))
    log.info("watching %d mailbox(es) every %.0fs", len(w.mailboxes), interval)
    try:
        w.loop(interval, stop, a.dry_run)
    except Exception as e:  # noqa: BLE001
        log.error("worker stopped: %s", redact(e))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
