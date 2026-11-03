"""Append-only, hash-chained audit log. Never records MFA codes or raw params."""

from __future__ import annotations

import hashlib
import json
import threading
import time
from typing import Any


class AuditLog:
    def __init__(self, path: str | None = None, clock=time.time):
        self._path = path
        self._clock = clock
        self._entries: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def record(self, event: str, **fields: Any) -> dict[str, Any]:
        with self._lock:
            prev = self._entries[-1]["hash"] if self._entries else "0" * 64
            entry = {"ts": self._clock(), "event": event, **fields, "prev": prev}
            entry["hash"] = hashlib.sha256(json.dumps(entry, sort_keys=True, default=str).encode()).hexdigest()
            self._entries.append(entry)
            if self._path:
                with open(self._path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry, default=str) + "\n")
            return entry

    def entries(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(e) for e in self._entries]

    def verify_chain(self) -> bool:
        prev = "0" * 64
        for e in self.entries():
            body = {k: v for k, v in e.items() if k != "hash"}
            if body["prev"] != prev:
                return False
            if hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest() != e["hash"]:
                return False
            prev = e["hash"]
        return True
