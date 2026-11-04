"""Checkpoint store for mailbox scans (stdlib sqlite3). Separate from the MFA/audit database.

- cursor:  one row per mailbox (provider cursor, stored only after a round is fully processed)
- seen:    (mailbox, provider id) -> content SHA-256 + verdict summary. A message is scanned once:
           listed again (crash before the cursor moved, expired cursor, overlapping webhook
           trigger) it is skipped before download; re-delivered under a new id (IMAP renumbering,
           a copy in another folder) it is skipped after download by its content hash.
- retry:   ids whose download failed transiently, retried next round (at most MAX_ATTEMPTS).
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

MAX_ATTEMPTS = 3

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cursor (mailbox TEXT PRIMARY KEY, value TEXT NOT NULL, updated REAL NOT NULL);
CREATE TABLE IF NOT EXISTS seen (
    mailbox TEXT NOT NULL, msg_id TEXT NOT NULL, sha TEXT NOT NULL, verdict TEXT NOT NULL, ts REAL NOT NULL,
    PRIMARY KEY (mailbox, msg_id));
CREATE INDEX IF NOT EXISTS seen_sha ON seen (mailbox, sha);
CREATE TABLE IF NOT EXISTS retry (mailbox TEXT NOT NULL, msg_id TEXT NOT NULL, attempts INTEGER NOT NULL,
    PRIMARY KEY (mailbox, msg_id));
"""


def default_state_path() -> str:
    return os.environ.get("PHISHGUARD_CONNECTOR_STATE") or str(Path.home() / ".phishguard" / "connector_state.db")


class CheckpointStore:
    def __init__(self, path: str, clock=time.time):
        if path != ":memory:":
            p = Path(path).expanduser()
            p.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if not p.exists():
                p.touch(mode=0o600)  # holds subjects/senders of scanned mail: owner-only
            path = str(p)
        self._clock = clock
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        if path != ":memory:":
            self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(_SCHEMA)

    def _q(self, sql: str, args: tuple = ()) -> list[tuple]:
        with self._lock:
            return self._db.execute(sql, args).fetchall()

    def get_cursor(self, mailbox: str) -> str | None:
        rows = self._q("SELECT value FROM cursor WHERE mailbox = ?", (mailbox,))
        return rows[0][0] if rows else None

    def set_cursor(self, mailbox: str, value: str) -> None:
        self._q(
            "INSERT OR REPLACE INTO cursor (mailbox, value, updated) VALUES (?, ?, ?)", (mailbox, value, self._clock())
        )

    def is_seen(self, mailbox: str, msg_id: str) -> bool:
        return bool(self._q("SELECT 1 FROM seen WHERE mailbox = ? AND msg_id = ?", (mailbox, msg_id)))

    def seen_sha(self, mailbox: str, sha: str) -> str | None:
        rows = self._q("SELECT msg_id FROM seen WHERE mailbox = ? AND sha = ? LIMIT 1", (mailbox, sha))
        return rows[0][0] if rows else None

    def mark_seen(self, mailbox: str, msg_id: str, sha: str, verdict: dict[str, Any]) -> None:
        self._q(
            "INSERT OR IGNORE INTO seen (mailbox, msg_id, sha, verdict, ts) VALUES (?, ?, ?, ?, ?)",
            (mailbox, msg_id, sha, json.dumps(verdict, default=str), self._clock()),
        )
        self._q("DELETE FROM retry WHERE mailbox = ? AND msg_id = ?", (mailbox, msg_id))

    def verdict(self, mailbox: str, msg_id: str) -> dict[str, Any] | None:
        rows = self._q("SELECT verdict FROM seen WHERE mailbox = ? AND msg_id = ?", (mailbox, msg_id))
        return json.loads(rows[0][0]) if rows else None

    def seen_count(self, mailbox: str) -> int:
        return self._q("SELECT COUNT(*) FROM seen WHERE mailbox = ?", (mailbox,))[0][0]

    def add_retry(self, mailbox: str, msg_id: str) -> int:
        rows = self._q("SELECT attempts FROM retry WHERE mailbox = ? AND msg_id = ?", (mailbox, msg_id))
        n = (rows[0][0] if rows else 0) + 1
        self._q("INSERT OR REPLACE INTO retry (mailbox, msg_id, attempts) VALUES (?, ?, ?)", (mailbox, msg_id, n))
        return n

    def drop_retry(self, mailbox: str, msg_id: str) -> None:
        self._q("DELETE FROM retry WHERE mailbox = ? AND msg_id = ?", (mailbox, msg_id))

    def retries(self, mailbox: str) -> list[str]:
        return [r[0] for r in self._q("SELECT msg_id FROM retry WHERE mailbox = ? ORDER BY msg_id", (mailbox,))]

    def close(self) -> None:
        with self._lock:
            self._db.close()
