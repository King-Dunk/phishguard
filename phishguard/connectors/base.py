"""Read-only mailbox connector interface.

A connector lists messages that arrived after a cursor and returns their raw RFC 822 bytes. It never
changes mailbox state: Gmail/Graph connectors only issue GET requests with read scopes
(gmail.readonly / Mail.Read), IMAP opens folders with EXAMINE and fetches with BODY.PEEK[] so
not even the \\Seen flag changes. Remediation lives in phishguard/mutating/remediation.py.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from ..readonly.eml import MAX_RAW_BYTES  # one size limit for API uploads and mailbox scans

Cursor = dict[str, Any]


@dataclass(frozen=True)
class RawMessage:
    provider_id: str  # Gmail message id, Graph message id, or "<uidvalidity>:<uid>" for IMAP
    raw: bytes


@dataclass(frozen=True)
class Rejected:
    provider_id: str
    reason: str  # "too_large" (not downloaded), ...
    size: int | None = None


@dataclass
class Batch:
    messages: list[RawMessage] = field(default_factory=list)
    rejected: list[Rejected] = field(default_factory=list)
    cursor: Cursor = field(default_factory=dict)  # store this and pass it back next time
    notes: list[str] = field(default_factory=list)  # e.g. "history expired, re-listed inbox"


class MailboxConnector(ABC):
    provider: str = "abstract"
    max_bytes: int = MAX_RAW_BYTES

    def __init__(self, mailbox_name: str):
        self.mailbox_name = mailbox_name  # checkpoint key; a label, not a credential

    @abstractmethod
    def list_new_messages(self, cursor: Cursor | None, limit: int = 50) -> Batch:
        """cursor=None: the newest `limit` messages, and a cursor positioned at "now".
        Otherwise: messages added since the cursor (at most `limit`). The returned cursor only advances
        past what was actually returned, so a crash or a full batch never skips mail."""

    def close(self) -> None:  # noqa: B027 - optional hook, most connectors hold no connection
        """Release network resources (optional)."""
