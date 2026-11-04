"""Tiny namespaced key/value interface over SQLiteStore (or memory), used by the MFA factors and the bank.

Values are JSON. Callers keep their own lock around read-modify-write sequences.
"""

from __future__ import annotations

import json
from typing import Any


class KV:
    def __init__(self, store=None):
        self._store = store
        self._mem: dict[tuple[str, str], str] = {}

    @property
    def persistent(self) -> bool:
        return self._store is not None

    def get(self, ns: str, key: str, default: Any = None) -> Any:
        raw = self._store.kv_get(ns, key) if self._store else self._mem.get((ns, key))
        return default if raw is None else json.loads(raw)

    def put(self, ns: str, key: str, value: Any) -> None:
        raw = json.dumps(value, sort_keys=True, default=str)
        if self._store:
            self._store.kv_put(ns, key, raw)
        else:
            self._mem[(ns, key)] = raw

    def delete(self, ns: str, key: str) -> None:
        if self._store:
            self._store.kv_delete(ns, key)
        else:
            self._mem.pop((ns, key), None)

    def items(self, ns: str) -> list[tuple[str, Any]]:
        if self._store:
            return [(k, json.loads(v)) for k, v in self._store.kv_items(ns)]
        return sorted((k, json.loads(v)) for (n, k), v in self._mem.items() if n == ns)
