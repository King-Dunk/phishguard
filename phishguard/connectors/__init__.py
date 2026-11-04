"""READ-ONLY mailbox connectors (Gmail API, Microsoft Graph, IMAP over TLS).

Like `phishguard.readonly`, this package must never import `phishguard.mutating` or
`phishguard.api` (enforced by tests/test_isolation.py and tests/test_connectors_isolation.py).
Connectors list and download mail; they cannot move, flag, label or delete it.
"""

from .base import (
    ConnectorError,
    CursorExpired,
    MailboxConnector,
    MalformedMessage,
    MessageRef,
    OverPrivilegedCredential,
    RawMessage,
)
from .scanner import MailboxScanner, PollStats, Verdict
from .state import CheckpointStore

__all__ = [
    "CheckpointStore",
    "ConnectorError",
    "CursorExpired",
    "MailboxConnector",
    "MailboxScanner",
    "MalformedMessage",
    "MessageRef",
    "OverPrivilegedCredential",
    "PollStats",
    "RawMessage",
    "Verdict",
]
