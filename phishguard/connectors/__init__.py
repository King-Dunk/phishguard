"""Mailbox connectors (READ side). Pull mail from Gmail, Microsoft Graph or IMAP and scan it.

Must never import phishguard.mutating (enforced by tests/test_isolation.py). Actions on mail
(quarantine, labels, banners) live in phishguard/mutating/remediation.py behind the MFA gateway.
"""

from .base import Batch, MailboxConnector, RawMessage, Rejected
from .scan import Scanner, ScanResult, Verdict
from .state import CheckpointStore

__all__ = ["Batch", "CheckpointStore", "MailboxConnector", "RawMessage", "Rejected", "ScanResult", "Scanner", "Verdict"]
