"""Append-only, hash-chained audit log. Never records MFA codes or raw params.

Each entry stores `prev` = SHA-256 of the previous entry, and `hash` = SHA-256 of itself
(canonical JSON, sorted keys). Editing, deleting or reordering any entry breaks the chain
from that point on, which `verify_chain()` reports. With a SQLiteStore the chain continues
across restarts and the stored copy is verified too.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from typing import Any

GENESIS = "0" * 64


def entry_hash(body: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()


def verify_entries(entries: list[dict[str, Any]]) -> tuple[bool, int | None]:
    """Return (ok, index of first bad entry)."""
    prev = GENESIS
    for i, e in enumerate(entries):
        body = {k: v for k, v in e.items() if k != "hash"}
        if body.get("prev") != prev or entry_hash(body) != e.get("hash"):
            return False, i
        prev = e["hash"]
    return True, None


class AuditLog:
    def __init__(self, path: str | None = None, clock=time.time, store=None):
        self._path = path
        self._clock = clock
        self._store = store
        self._lock = threading.Lock()
        self._entries: list[dict[str, Any]] = store.audit_entries() if store else []

    def record(self, event: str, **fields: Any) -> dict[str, Any]:
        with self._lock:
            prev = self._entries[-1]["hash"] if self._entries else GENESIS
            entry = {"ts": self._clock(), "event": event, **fields, "prev": prev}
            entry["hash"] = entry_hash(entry)
            # round-trip through JSON so the in-memory copy hashes exactly like the stored copy
            entry = json.loads(json.dumps(entry, default=str))
            self._entries.append(entry)
            if self._store:
                self._store.append_audit(entry)
            if self._path:
                with open(self._path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry, default=str) + "\n")
            return entry

    def entries(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(e) for e in self._entries]

    def verify_chain(self) -> bool:
        ok, _ = verify_entries(self.entries())
        if ok and self._store:
            ok, _ = verify_entries(self._store.audit_entries())
        return ok

    def first_broken(self) -> int | None:
        src = self._store.audit_entries() if self._store else self.entries()
        return verify_entries(src)[1]
