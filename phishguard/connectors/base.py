"""The read-side mailbox interface. Every provider implements the same four calls.

A connector only *reads*: it lists message ids and downloads raw RFC 822 bytes. It never moves,
labels, flags or deletes anything (IMAP uses EXAMINE and BODY.PEEK[], so even the \\Seen flag
is left alone). State-changing remediation lives in `phishguard/mutating/mailbox.py` behind the
MFA gateway, with separate write credentials.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass


class ConnectorError(RuntimeError):
    """A provider call failed. Messages never contain tokens, passwords or response bodies."""


class CursorExpired(ConnectorError):
    """The provider no longer accepts the stored cursor (Gmail 404 history, Graph 410, IMAP UIDVALIDITY)."""


class MalformedMessage(ConnectorError):
    """The provider returned something that is not a decodable message."""


class OverPrivilegedCredential(ConnectorError):
    """The read credential also grants write access. Refused unless explicitly allowed."""


@dataclass(frozen=True)
class MessageRef:
    """A provider message id, listed cheaply before anything is downloaded."""

    provider_id: str


@dataclass(frozen=True)
class RawMessage:
    provider_id: str
    raw: bytes


class MailboxConnector(ABC):
    provider: str = ""

    @property
    @abstractmethod
    def mailbox_key(self) -> str:
        """Stable identity of the mailbox (and folder) for checkpoints, e.g. 'gmail:alice@x.com'."""

    @abstractmethod
    def initial_cursor(self) -> str:
        """A cursor meaning 'now': list_new() from it returns only mail that arrives later."""

    @abstractmethod
    def list_new(self, cursor: str | None) -> tuple[list[MessageRef], str]:
        """Ids of messages added since `cursor`, oldest first, and the cursor to store afterwards.

        `cursor=None` starts from now (no backlog). An expired cursor is handled inside: the
        connector restarts from now and returns the most recent page, and the scanner's seen-set
        stops anything already scanned from being scanned again.
        """

    @abstractmethod
    def list_recent(self, n: int) -> list[MessageRef]:
        """The `n` most recent message ids, newest first (CLI 'scan the last N')."""

    @abstractmethod
    def fetch_raw(self, ref: MessageRef) -> bytes:
        """Raw RFC 822 bytes. Raises readonly.EmlTooLarge above MAX_RAW_BYTES without reading it all."""

    def close(self) -> None:  # noqa: B027 - optional hook
        """Release connections. Safe to call more than once."""

    def end_poll(self) -> None:  # noqa: B027 - optional hook
        """Called after each polling round (IMAP logs out; HTTP connectors keep their pool)."""

    def list_new_messages(self, cursor: str | None) -> tuple[Iterator[RawMessage], str]:
        """Convenience form: raw bytes + provider id for every new message, and the next cursor."""
        refs, nxt = self.list_new(cursor)
        return (RawMessage(r.provider_id, self.fetch_raw(r)) for r in refs), nxt

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def ensure_read_only(provider: str, granted: set[str] | None, write_scopes: frozenset[str], allow: bool) -> None:
    """Refuse a read credential that can also write. `granted=None` means the provider didn't say."""
    if not granted or allow:
        return
    norm = {s.rsplit("/", 1)[-1].lower() if not s.endswith("/") else s.lower() for s in granted}
    bad = sorted(s for s in norm if s in write_scopes)
    if bad:
        raise OverPrivilegedCredential(
            f"{provider} read credential also grants {', '.join(bad)}. Use a read-only credential for scanning "
            "(write access belongs to the separate remediation credential), or set "
            "PHISHGUARD_ALLOW_OVERPRIVILEGED_READ=1 to accept it knowingly."
        )
