"""Scan bookkeeping: per-mailbox cursor and the set of messages already scanned (SQLite, stdlib).

This is PhishGuard's own state, not mailbox state. Idempotency has two keys: the provider's message
id and the SHA-256 of the raw bytes, so a message is scanned once even if the provider renumbers it
(IMAP UIDVALIDITY change) or delivers it twice.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cursor (mailbox TEXT PRIMARY KEY, data TEXT NOT NULL, updated REAL NOT NULL);
CREATE TABLE IF NOT EXISTS seen (mailbox TEXT NOT NULL, key TEXT NOT NULL, scanned REAL NOT NULL,
                                 verdict TEXT NOT NULL, PRIMARY KEY (mailbox, key));
CREATE TABLE IF NOT EXISTS trigger (mailbox TEXT PRIMARY KEY, at REAL NOT NULL, source TEXT NOT NULL);
"""


class CheckpointStore:
    def __init__(self, path: str = ":memory:", clock=time.time):
        self._lock = threading.Lock()
        self._clock = clock
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        if path != ":memory:":
            self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(_SCHEMA)

    def _q(self, sql: str, args: tuple = ()) -> list[tuple]:
        with self._lock:
            return self._db.execute(sql, args).fetchall()

    def get_cursor(self, mailbox: str) -> dict | None:
        rows = self._q("SELECT data FROM cursor WHERE mailbox = ?", (mailbox,))
        return json.loads(rows[0][0]) if rows else None

    def set_cursor(self, mailbox: str, cursor: dict) -> None:
        self._q(
            "INSERT OR REPLACE INTO cursor (mailbox, data, updated) VALUES (?, ?, ?)",
            (mailbox, json.dumps(cursor), self._clock()),
        )

    def is_seen(self, mailbox: str, *keys: str) -> bool:
        for k in keys:
            if self._q("SELECT 1 FROM seen WHERE mailbox = ? AND key = ?", (mailbox, k)):
                return True
        return False

    def mark_seen(self, mailbox: str, keys: list[str], verdict: dict) -> None:
        for k in keys:
            self._q(
                "INSERT OR IGNORE INTO seen (mailbox, key, scanned, verdict) VALUES (?, ?, ?, ?)",
                (mailbox, k, self._clock(), json.dumps(verdict)),
            )

    def seen_count(self, mailbox: str) -> int:
        return self._q("SELECT COUNT(*) FROM seen WHERE mailbox = ?", (mailbox,))[0][0]

    def prune(self, older_than_days: float = 90) -> int:
        cut = self._clock() - older_than_days * 86400
        n = self._q("SELECT COUNT(*) FROM seen WHERE scanned < ?", (cut,))[0][0]
        self._q("DELETE FROM seen WHERE scanned < ?", (cut,))
        return n

    # webhook -> worker hand-off: a push notification only says "something changed, scan soon"
    def add_trigger(self, mailbox: str, source: str) -> None:
        self._q(
            "INSERT OR REPLACE INTO trigger (mailbox, at, source) VALUES (?, ?, ?)", (mailbox, self._clock(), source)
        )

    def pop_triggers(self) -> list[str]:
        with self._lock:
            rows = self._db.execute("SELECT mailbox FROM trigger").fetchall()
            self._db.execute("DELETE FROM trigger")
        return [r[0] for r in rows]

    def close(self) -> None:
        with self._lock:
            self._db.close()
