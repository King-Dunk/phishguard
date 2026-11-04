"""Pull new mail from a connector and run it through the same path as POST /analyze/eml:
parse_eml -> PhishingAgent.analyze. Produces verdicts; never acts on them (that is the worker's job,
through the MFA gateway on the mutating side)."""

from __future__ import annotations

import hashlib
import logging
from dataclasses import asdict, dataclass, field

from ..agent import PhishingAgent
from ..readonly import EmlRejected, EmlTooLarge, parse_eml
from .base import MailboxConnector
from .state import CheckpointStore

log = logging.getLogger("phishguard.connectors")


@dataclass
class Verdict:
    mailbox: str
    provider: str
    provider_id: str
    status: str  # scanned | too_large | unparseable
    risk: float | None = None
    is_phishing: bool | None = None
    top_features: list[str] = field(default_factory=list)
    message_id: str = ""
    # display-only fields for the CLI; never logged or written to audit
    sender: str = field(default="", repr=False)
    subject: str = field(default="", repr=False)

    def public(self) -> dict:
        """What may be logged / stored: no subject, no sender, no content."""
        d = asdict(self)
        d.pop("sender")
        d.pop("subject")
        return d


@dataclass
class ScanResult:
    verdicts: list[Verdict]
    duplicates: int
    cursor: dict
    notes: list[str]


class Scanner:
    def __init__(
        self,
        connector: MailboxConnector,
        agent: PhishingAgent,
        store: CheckpointStore,
        threshold: float,
        trusted_authserv_id: str | None = None,
    ):
        self.connector, self.agent, self.store = connector, agent, store
        self.threshold, self.authserv = threshold, trusted_authserv_id

    def scan(self, limit: int = 50) -> ScanResult:
        name = self.connector.mailbox_name
        batch = self.connector.list_new_messages(self.store.get_cursor(name), limit)
        verdicts: list[Verdict] = []
        dups = 0
        for m in batch.messages:
            digest = "sha256:" + hashlib.sha256(m.raw).hexdigest()
            if self.store.is_seen(name, m.provider_id, digest):
                dups += 1
                continue
            v = self._verdict(m.provider_id, m.raw)
            self.store.mark_seen(name, [m.provider_id, digest], v.public())
            verdicts.append(v)
        for r in batch.rejected:
            if self.store.is_seen(name, r.provider_id):
                dups += 1
                continue
            v = Verdict(name, self.connector.provider, r.provider_id, r.reason)
            self.store.mark_seen(name, [r.provider_id], v.public())
            verdicts.append(v)
        # advance the cursor only after every message of the batch is recorded as seen
        self.store.set_cursor(name, batch.cursor)
        for v in verdicts:
            log.info("verdict %s", v.public())
        return ScanResult(verdicts, dups, batch.cursor, batch.notes)

    def _verdict(self, provider_id: str, raw: bytes) -> Verdict:
        name, prov = self.connector.mailbox_name, self.connector.provider
        try:
            email = parse_eml(raw, self.authserv)
        except EmlTooLarge:
            return Verdict(name, prov, provider_id, "too_large")
        except (EmlRejected, ValueError):
            return Verdict(name, prov, provider_id, "unparseable")
        r = self.agent.analyze(email)
        return Verdict(
            name,
            prov,
            provider_id,
            "scanned",
            risk=r.risk_percent,
            is_phishing=r.risk_percent >= self.threshold,
            top_features=[f["name"] for f in r.features[:3]],
            message_id=email.id,
            sender=f"{email.sender_name} <{email.sender_email}>".strip(),
            subject=email.subject,
        )
