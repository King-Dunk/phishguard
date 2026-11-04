"""Mailbox scanning: connector -> raw bytes -> parse_eml -> PhishingAgent.analyze -> Verdict.

Read-only. A `sink` callback can act on verdicts; the remediation sink lives outside this package
(`phishguard/mailbox_guard.py`) because acting means calling the MFA gateway.

Order inside a round (crash-safety):
  1. retry ids that failed transiently last round;
  2. list ids since the stored cursor;
  3. for each id: skip if seen -> download -> skip if same content seen -> parse -> analyze -> sink -> mark seen;
  4. store the new cursor.
A crash before step 4 re-lists the same ids next round; the seen-set skips the ones already done,
so a message is scanned (and remediated) at most once in normal operation and at least once overall.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from typing import Any

from ..agent import PhishingAgent
from ..readonly import EmlRejected, EmlTooLarge, parse_eml
from .base import ConnectorError, CursorExpired, MailboxConnector, MalformedMessage, MessageRef
from .http import HttpError
from .secrets import get_logger, redact
from .state import MAX_ATTEMPTS, CheckpointStore

log = get_logger(__name__)


@dataclass
class Verdict:
    provider: str
    mailbox: str
    provider_id: str
    status: str  # scanned | rejected | error
    risk_percent: float | None = None
    is_phishing: bool | None = None
    threshold: float | None = None
    top_features: list[dict[str, Any]] = field(default_factory=list)
    sender: str = ""
    subject: str = ""
    message_id: str = ""
    sha256: str = ""
    detail: str = ""
    cached: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PollStats:
    listed: int = 0
    scanned: int = 0
    skipped_seen: int = 0
    skipped_duplicate: int = 0
    rejected: int = 0
    errors: int = 0
    flagged: int = 0


class MailboxScanner:
    def __init__(
        self,
        connector: MailboxConnector,
        agent: PhishingAgent,
        state: CheckpointStore,
        sink: Callable[[Verdict], None] | None = None,
        backfill: int = 0,
    ):
        self.connector = connector
        self.agent = agent
        self.state = state
        self.sink = sink
        self.backfill = backfill
        self.threshold = agent.settings.phishing_threshold
        self.authserv = agent.settings.trusted_authserv_id
        self.last_stats = PollStats()

    @property
    def key(self) -> str:
        return self.connector.mailbox_key

    def _verdict(self, ref: MessageRef, status: str, **kw: Any) -> Verdict:
        return Verdict(self.connector.provider, self.key, ref.provider_id, status, threshold=self.threshold, **kw)

    def _finish(self, ref: MessageRef, v: Verdict, sha: str, stats: PollStats) -> Verdict:
        if v.status == "scanned" and self.sink is not None:
            try:
                self.sink(v)
            except Exception as e:  # noqa: BLE001 - a failing action must not stop the scan
                log.error("action sink failed for %s: %s", ref.provider_id, redact(f"{type(e).__name__}: {e}"))
                v.detail = (v.detail + "; " if v.detail else "") + "sink_failed"
        self.state.mark_seen(self.key, ref.provider_id, sha, v.to_dict())
        if v.status == "rejected":
            stats.rejected += 1
        elif v.status == "error":
            stats.errors += 1
        else:
            stats.scanned += 1
            stats.flagged += bool(v.is_phishing)
        return v

    def process(self, ref: MessageRef, stats: PollStats | None = None) -> Verdict | None:
        stats = stats or PollStats()
        key = self.key
        if self.state.is_seen(key, ref.provider_id):
            stats.skipped_seen += 1
            return None
        try:
            raw = self.connector.fetch_raw(ref)
        except EmlTooLarge as e:
            return self._finish(
                ref, self._verdict(ref, "rejected", detail=f"too_large: {e}"), "rej:" + ref.provider_id, stats
            )
        except MalformedMessage as e:
            return self._finish(
                ref, self._verdict(ref, "rejected", detail=f"malformed: {e}"), "rej:" + ref.provider_id, stats
            )
        except CursorExpired:
            self.state.drop_retry(key, ref.provider_id)
            return None
        except HttpError as e:
            if e.status in (400, 404):  # deleted or moved between list and fetch: nothing to scan
                self.state.drop_retry(key, ref.provider_id)
                return None
            return self._transient(ref, e, stats)
        except ConnectorError as e:
            return self._transient(ref, e, stats)

        sha = hashlib.sha256(raw).hexdigest()
        dup = self.state.seen_sha(key, sha)
        if dup is not None:
            stats.skipped_duplicate += 1
            self.state.mark_seen(key, ref.provider_id, sha, {"status": "duplicate", "of": dup})
            return None
        try:
            email = parse_eml(raw, self.authserv)
        except EmlRejected as e:
            return self._finish(ref, self._verdict(ref, "rejected", sha256=sha, detail=f"rejected: {e}"), sha, stats)
        except Exception as e:  # noqa: BLE001 - one hostile message must not stop the worker
            log.warning("parser failed on %s (%s)", ref.provider_id, type(e).__name__)
            v = self._verdict(ref, "rejected", sha256=sha, detail=f"malformed: parser {type(e).__name__}")
            return self._finish(ref, v, sha, stats)
        r = self.agent.analyze(email)
        v = self._verdict(
            ref,
            "scanned",
            risk_percent=r.risk_percent,
            is_phishing=r.risk_percent >= self.threshold,
            top_features=[{"name": f["name"], "contribution": f["contribution"]} for f in r.features[:5]],
            sender=email.sender_email[:200],
            subject=email.subject[:200],
            message_id=email.id[:200],
            sha256=sha,
            detail=f"circuit_break={r.circuit_break}" if r.circuit_break else "",
        )
        return self._finish(ref, v, sha, stats)

    def _transient(self, ref: MessageRef, e: Exception, stats: PollStats) -> Verdict | None:
        n = self.state.add_retry(self.key, ref.provider_id)
        log.warning("download of %s failed (%s), attempt %d/%d", ref.provider_id, redact(e), n, MAX_ATTEMPTS)
        if n >= MAX_ATTEMPTS:
            v = self._verdict(ref, "error", detail=redact(str(e))[:200])
            return self._finish(ref, v, "err:" + ref.provider_id, stats)
        stats.errors += 1
        return None

    def poll_once(self) -> list[Verdict]:
        stats = PollStats()
        out: list[Verdict] = []
        try:
            for mid in self.state.retries(self.key):
                if (v := self.process(MessageRef(mid), stats)) is not None:
                    out.append(v)
            cursor = self.state.get_cursor(self.key)
            refs, nxt = self.connector.list_new(cursor)
            if cursor is None and self.backfill > 0:
                refs = list(reversed(self.connector.list_recent(self.backfill))) + refs
            stats.listed = len(refs)
            for ref in refs:
                if (v := self.process(ref, stats)) is not None:
                    out.append(v)
            self.state.set_cursor(self.key, nxt)
        finally:
            self.connector.end_poll()
            self.last_stats = stats
        return out

    def scan_recent(self, n: int) -> list[Verdict]:
        """The last n messages, newest first. Already-scanned ones are shown from the store, not rescanned."""
        stats = PollStats()
        out: list[Verdict] = []
        try:
            for ref in self.connector.list_recent(n):
                prev = self.state.verdict(self.key, ref.provider_id)
                if prev is not None and prev.get("status") in ("scanned", "rejected", "error"):
                    out.append(Verdict(**{**prev, "cached": True}))
                    continue
                if (v := self.process(ref, stats)) is not None:
                    out.append(v)
        finally:
            self.connector.end_poll()
            self.last_stats = stats
        return out
