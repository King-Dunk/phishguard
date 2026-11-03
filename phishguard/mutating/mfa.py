"""Out-of-band MFA code delivery channels."""

from __future__ import annotations

import sys
from typing import Protocol


class MFAChannel(Protocol):
    def deliver(self, pending_id: str, code: str, summary: str) -> None: ...


class StderrChannel:
    """DEV ONLY: prints the code on the server console. Replace with SMS/push/TOTP in production."""

    def deliver(self, pending_id: str, code: str, summary: str) -> None:
        print(f"[MFA] pending={pending_id} code={code} action={summary}", file=sys.stderr)


class CaptureChannel:
    """Test helper: keeps codes in memory so tests can play the human."""

    def __init__(self) -> None:
        self.codes: dict[str, str] = {}

    def deliver(self, pending_id: str, code: str, summary: str) -> None:
        self.codes[pending_id] = code
