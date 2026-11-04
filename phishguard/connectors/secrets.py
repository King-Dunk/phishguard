"""Credential loading, redaction and token storage for mailbox connectors.

Rules (tested in tests/test_connectors_secrets.py):
- secrets come only from an environment variable or a file OUTSIDE the repository;
- a secret file readable by group/others is refused (POSIX);
- every secret loaded or minted is registered, and `redact()` / `RedactingFilter` mask it in any
  text that reaches logs, audit records or CLI output;
- token files are written atomically with mode 0600 in a 0700 directory.
"""

from __future__ import annotations

import json
import logging
import os
import pathlib
import stat
import tempfile
import threading
from typing import Any

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_MASK = "***"
_lock = threading.Lock()
_registry: set[str] = set()


class SecretError(RuntimeError):
    pass


def register(*values: str | None) -> None:
    """Remember secret values so they can be masked wherever they might be printed."""
    with _lock:
        for v in values:
            if v and len(v) >= 6:  # very short strings would mask ordinary words
                _registry.add(v)


def redact(text: Any) -> str:
    s = str(text)
    with _lock:
        secrets = sorted(_registry, key=len, reverse=True)
    for v in secrets:
        if v in s:
            s = s.replace(v, _MASK)
    return s


class RedactingFilter(logging.Filter):
    """Masks registered secrets in log messages and arguments."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact(record.getMessage())
        record.args = None
        return True


def install_redaction(logger: logging.Logger | None = None) -> None:
    lg = logger or logging.getLogger("phishguard")
    if not any(isinstance(f, RedactingFilter) for f in lg.filters):
        lg.addFilter(RedactingFilter())
    for h in logging.getLogger().handlers:
        if not any(isinstance(f, RedactingFilter) for f in h.filters):
            h.addFilter(RedactingFilter())


def _check_outside_repo(path: pathlib.Path) -> pathlib.Path:
    p = path.expanduser().resolve()
    if p == REPO_ROOT or REPO_ROOT in p.parents:
        raise SecretError(f"refusing secret/token file inside the repository: {p} (keep it under ~/.config)")
    return p


def _check_private(p: pathlib.Path) -> None:
    if os.name == "posix" and p.exists() and p.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise SecretError(f"{p} is readable by group/others; run: chmod 600 {p}")


def load_secret(*, env: str | None = None, file: str | os.PathLike | None = None, required: bool = True) -> str | None:
    """Read a secret from an environment variable (preferred) or a private file outside the repo."""
    value = None
    if env:
        value = os.environ.get(env)
    if value is None and file:
        p = _check_outside_repo(pathlib.Path(file))
        _check_private(p)
        value = p.read_text(encoding="utf-8").strip()
    if value is None and required:
        where = " or ".join(x for x in (f"env {env}" if env else "", f"file {file}" if file else "") if x)
        raise SecretError(f"secret not found ({where or 'no source given'})")
    register(value)
    return value


def load_json_secret(*, env: str | None = None, file: str | os.PathLike | None = None) -> dict[str, Any]:
    """JSON credentials (Google client_secret.json / service-account key) from env or private file."""
    raw = load_secret(env=env, file=file)
    data = json.loads(raw or "{}")
    for k in ("client_secret", "private_key", "refresh_token", "private_key_id"):
        node = data.get("installed") or data.get("web") or data
        register(node.get(k) if isinstance(node, dict) else None)
    return data


class TokenStore:
    """OAuth token cache on disk: JSON, mode 0600, parent dir 0700, atomic replace, outside the repo."""

    def __init__(self, path: str | os.PathLike):
        self.path = _check_outside_repo(pathlib.Path(path))

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {}
        _check_private(self.path)
        data = json.loads(self.path.read_text(encoding="utf-8") or "{}")
        register(*(v for k, v in data.items() if "token" in k and isinstance(v, str)))
        return data

    def save(self, data: dict[str, Any]) -> None:
        register(*(v for k, v in data.items() if "token" in k and isinstance(v, str)))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if os.name == "posix":
            os.chmod(self.path.parent, 0o700)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".tok-")
        try:
            if os.name == "posix":
                os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f)
            os.replace(tmp, self.path)
        except BaseException:
            pathlib.Path(tmp).unlink(missing_ok=True)
            raise
