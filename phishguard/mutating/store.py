"""SQLite persistence (stdlib sqlite3, no ORM) for pending MFA actions, audit log, TOTP and lockouts.

One connection guarded by a lock: FastAPI runs sync endpoints in a thread pool, and the
gateway already serializes its own state changes, so contention is low.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from typing import Any

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY AUTOINCREMENT, entry TEXT NOT NULL, hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS pending (id TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS totp (user TEXT PRIMARY KEY, secret TEXT NOT NULL, last_step INTEGER NOT NULL DEFAULT -1);
CREATE TABLE IF NOT EXISTS lockout (key TEXT PRIMARY KEY, fails INTEGER NOT NULL, locked_until REAL NOT NULL);
"""


class SQLiteStore:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        if path != ":memory:":
            self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")  # an audit row must survive a crash
        self._db.executescript(_SCHEMA)

    def _q(self, sql: str, args: tuple = ()) -> list[tuple]:
        with self._lock:
            return self._db.execute(sql, args).fetchall()

    # audit (append-only: no UPDATE/DELETE method exists)
    def append_audit(self, entry: dict[str, Any]) -> None:
        self._q("INSERT INTO audit (entry, hash) VALUES (?, ?)", (json.dumps(entry, default=str), entry["hash"]))

    def audit_entries(self) -> list[dict[str, Any]]:
        return [json.loads(r[0]) for r in self._q("SELECT entry FROM audit ORDER BY seq")]

    # pending actions
    def save_pending(self, pid: str, data: dict[str, Any]) -> None:
        self._q("INSERT OR REPLACE INTO pending (id, data) VALUES (?, ?)", (pid, json.dumps(data, default=str)))

    def load_pending(self) -> list[dict[str, Any]]:
        return [json.loads(r[0]) for r in self._q("SELECT data FROM pending")]

    # TOTP
    def get_totp(self, user: str) -> tuple[str, int] | None:
        rows = self._q("SELECT secret, last_step FROM totp WHERE user = ?", (user,))
        return (rows[0][0], rows[0][1]) if rows else None

    def put_totp(self, user: str, secret: str, last_step: int) -> None:
        self._q("INSERT OR REPLACE INTO totp (user, secret, last_step) VALUES (?, ?, ?)", (user, secret, last_step))

    # lockouts
    def get_lockout(self, key: str) -> tuple[int, float]:
        rows = self._q("SELECT fails, locked_until FROM lockout WHERE key = ?", (key,))
        return (rows[0][0], rows[0][1]) if rows else (0, 0.0)

    def put_lockout(self, key: str, fails: int, locked_until: float) -> None:
        self._q(
            "INSERT OR REPLACE INTO lockout (key, fails, locked_until) VALUES (?, ?, ?)", (key, fails, locked_until)
        )

    def close(self) -> None:
        with self._lock:
            self._db.close()
