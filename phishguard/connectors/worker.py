"""Polling worker: scan a mailbox every N seconds and emit one JSON verdict per new message.

    python -m phishguard.connectors.worker --provider gmail --interval 60
    python -m phishguard.connectors.worker --provider graph --once --backfill 20
    python -m phishguard.connectors.worker --provider graph --webhooks --port 8081 \
        --graph-notification-url https://phishguard.example.com/webhooks/graph

Scan-only: this worker never changes the mailbox. To act on verdicts (quarantine, label, banner)
use `python -m phishguard.mailbox_guard`, which runs the same loop with a remediation sink that
goes through the MFA gateway and uses the separate write credential.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import secrets
import signal
import sys
import threading
import time
from collections.abc import Callable, Mapping
from typing import IO, Any

from ..agent import PhishingAgent
from ..config import Settings
from ..llm import LLMClient, MockLLM
from .base import ConnectorError, OverPrivilegedCredential
from .config import PROVIDERS, build_connector
from .oauth import OAuthError
from .scanner import MailboxScanner, Verdict
from .secrets import RedactingFilter, Secret, SecretError, get_logger, install_redaction, redact, secret_from_env
from .state import CheckpointStore, default_state_path

log = get_logger(__name__)
FATAL = (OverPrivilegedCredential, OAuthError, SecretError)


def build_llm(settings: Settings) -> LLMClient:
    if settings.llm_mode == "anthropic":
        from ..llm.anthropic_client import AnthropicLLM

        return AnthropicLLM(settings)
    return MockLLM()


def build_scanner(
    provider: str,
    env: Mapping[str, str] | None = None,
    state_path: str | None = None,
    sink: Callable[[Verdict], None] | None = None,
    backfill: int = 0,
    settings: Settings | None = None,
    **connector_kw: Any,
) -> MailboxScanner:
    settings = settings or Settings.from_env()
    connector = build_connector(provider, env, **connector_kw)
    agent = PhishingAgent(build_llm(settings), settings)
    return MailboxScanner(
        connector, agent, CheckpointStore(state_path or default_state_path()), sink=sink, backfill=backfill
    )


def emit(v: Verdict, out: IO[str]) -> None:
    out.write(redact(json.dumps(v.to_dict(), ensure_ascii=False, default=str)) + "\n")
    out.flush()


def run(
    scanner: MailboxScanner,
    interval: float,
    *,
    once: bool = False,
    out: IO[str] = sys.stdout,
    stop: threading.Event | None = None,
    trigger: threading.Event | None = None,
    max_backoff: float = 900.0,
    max_rounds: int | None = None,
    maintenance: list[tuple[float, Callable[[], Any]]] = (),
    clock=time.monotonic,
) -> int:
    """Poll until stopped. Transient provider errors back off exponentially; config errors stop.

    `maintenance` holds (period_seconds, fn) pairs run when due, e.g. renewing a Gmail watch or
    a Graph subscription before it expires.
    """
    stop = stop or threading.Event()
    trigger = trigger or threading.Event()
    failures = rounds = 0
    due = [clock() + period for period, _ in maintenance]
    while not stop.is_set():
        wait = interval
        for i, (period, fn) in enumerate(maintenance):
            if clock() >= due[i]:
                due[i] = clock() + period
                try:
                    fn()
                except ConnectorError as e:
                    log.error("maintenance task failed (%s)", redact(e))
        try:
            for v in scanner.poll_once():
                emit(v, out)
            s = scanner.last_stats
            log.info(
                "round done: listed=%d scanned=%d flagged=%d seen=%d dup=%d rejected=%d errors=%d",
                s.listed, s.scanned, s.flagged, s.skipped_seen, s.skipped_duplicate, s.rejected, s.errors,
            )  # fmt: skip
            failures = 0
        except FATAL:
            raise
        except ConnectorError as e:
            failures += 1
            wait = min(max_backoff, interval * (2**failures))
            log.error("poll failed (%s); retrying in %.0fs", redact(e), wait)
        rounds += 1
        if once or (max_rounds is not None and rounds >= max_rounds):
            break
        trigger.wait(timeout=wait)  # a webhook sets this to poll early
        trigger.clear()
    return 0


def _serve_webhooks(args, trigger: threading.Event, env: Mapping[str, str]) -> Secret | None:
    import uvicorn
    from fastapi import FastAPI

    from .config import new_http
    from .webhooks import JwksCache, make_router

    client_state = secret_from_env("PHISHGUARD_GRAPH_CLIENT_STATE", dict(env))
    if args.provider == "graph" and client_state is None:
        client_state = Secret(secrets.token_urlsafe(32))  # random per run; only Graph and we know it
    app = FastAPI(title="PhishGuard webhooks", docs_url=None, redoc_url=None, openapi_url=None)
    app.include_router(
        make_router(
            lambda provider, hint: trigger.set(),
            graph_client_state=client_state if args.provider == "graph" else None,
            pubsub_audience=env.get("PHISHGUARD_PUBSUB_AUDIENCE"),
            pubsub_service_account=env.get("PHISHGUARD_PUBSUB_SERVICE_ACCOUNT"),
            jwks=JwksCache(new_http()) if args.provider == "gmail" else None,
        )
    )
    server = uvicorn.Server(uvicorn.Config(app, host=args.host, port=args.port, log_level="warning"))
    threading.Thread(target=server.run, daemon=True, name="webhooks").start()
    return client_state


def main(argv: list[str] | None = None, env: Mapping[str, str] | None = None) -> int:
    env = os.environ if env is None else env
    p = argparse.ArgumentParser(prog="python -m phishguard.connectors.worker", description=__doc__.split("\n")[0])
    p.add_argument("--provider", choices=PROVIDERS, required=True)
    p.add_argument("--interval", type=float, default=float(env.get("PHISHGUARD_POLL_INTERVAL", "60")))
    p.add_argument("--once", action="store_true", help="one round, then exit")
    p.add_argument("--backfill", type=int, default=0, help="on the very first run, also scan the last N messages")
    p.add_argument("--state", default=None, help="checkpoint database (default ~/.phishguard/connector_state.db)")
    p.add_argument("--output", default=None, help="append verdicts as JSON lines to this file (mode 0600)")
    p.add_argument("--webhooks", action="store_true", help="serve /webhooks/{graph,gmail} to poll on push")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8081)
    p.add_argument("--graph-notification-url", default=None, help="public https URL of /webhooks/graph")
    p.add_argument("--gmail-topic", default=None, help="projects/<p>/topics/<t> for Gmail push")
    args = p.parse_args(argv)
    if args.interval < 5:
        p.error("--interval must be at least 5 seconds")

    handler = install_redaction(logging.StreamHandler(sys.stderr))
    logging.basicConfig(
        level=logging.INFO, handlers=[handler], format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    logging.getLogger("httpx").addFilter(RedactingFilter())

    out: IO[str] = sys.stdout
    if args.output:
        fd = os.open(args.output, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        out = os.fdopen(fd, "a", encoding="utf-8")
    stop, trigger = threading.Event(), threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: (stop.set(), trigger.set()))
    maintenance: list[tuple[float, Callable[[], Any]]] = []
    try:
        scanner = build_scanner(args.provider, env, args.state, backfill=args.backfill)
        if args.webhooks and not args.once:
            client_state = _serve_webhooks(args, trigger, env)
            connector: Any = scanner.connector
            if args.graph_notification_url and args.provider == "graph":

                def subscribe() -> None:
                    # a new 70 h subscription every 48 h; the old one lapses on its own (duplicate
                    # pushes only wake the poller early, and polling is idempotent)
                    sub = connector.subscribe(args.graph_notification_url, client_state.reveal())
                    log.info("Graph subscription %s until %s", sub["id"], sub["expirationDateTime"])

                subscribe()
                maintenance.append((48 * 3600.0, subscribe))
            if args.gmail_topic and args.provider == "gmail":

                def watch() -> None:
                    log.info("Gmail watch active until %s", connector.watch(args.gmail_topic)["expiration"])

                watch()
                maintenance.append((24 * 3600.0, watch))  # Google: re-call watch at least every 7 days
        return run(scanner, args.interval, once=args.once, out=out, stop=stop, trigger=trigger, maintenance=maintenance)
    except (ConnectorError, SecretError, ValueError) as e:
        log.error("%s", redact(e))
        return 2
    except KeyboardInterrupt:
        return 0
    finally:
        if out is not sys.stdout:
            out.close()


if __name__ == "__main__":
    sys.exit(main())
