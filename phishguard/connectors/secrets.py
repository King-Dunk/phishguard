"""Credentials: loaded only from the environment or from files outside the repository.

- `Secret` wraps a value so that repr/str/f-strings print `***`; the raw value needs `.reveal()`.
- Every Secret is registered with the redactor, and `RedactingFilter` scrubs registered values and
  token-shaped strings (Bearer headers, JWTs, Google `ya29.`/`1//` tokens, `password=...`) from
  log records, so a stray `log.info(response.text)` cannot leak one.
- Secret files must live outside the repo and must not be group/world readable.
- `TokenStore` writes refresh tokens atomically with mode 0600 in a 0700 directory.
"""

from __future__ import annotations

import json
import logging
import os
import re
import stat
import tempfile
import threading
from pathlib import Path
from typing import Any

# The source checkout: phishguard/connectors/secrets.py -> repo root. Secret files may not live under it,
# so they can't be committed by accident or baked into the Docker image (COPY . /app).
REPO_ROOT = Path(__file__).resolve().parents[2]
REDACTED = "[REDACTED]"

_registry: set[str] = set()
_registry_lock = threading.Lock()

_PATTERNS = [
    re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"),  # JWT
    re.compile(r"\bya29\.[A-Za-z0-9._-]{10,}"),  # Google access token
    re.compile(r"\b1//[A-Za-z0-9._-]{10,}"),  # Google refresh token
    re.compile(
        r"(?i)\b(access_token|refresh_token|id_token|client_secret|assertion|password|passwd|device_code)"
        r"([\"']?\s*[:=]\s*[\"']?)([^\s\"'&,}]{4,})"
    ),
    re.compile(r"(?i)\b(code|code_verifier)(=)([^\s&\"']{4,})"),  # OAuth authorization code in a query string
    re.compile(r"auth=Bearer [^\x01\s]+"),  # XOAUTH2 SASL string
]


class SecretError(RuntimeError):
    pass


class Secret:
    """A credential that refuses to be printed."""

    __slots__ = ("_value",)

    def __init__(self, value: str):
        self._value = value
        register_secret(value)

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "Secret('***')"

    __str__ = __repr__

    def __format__(self, spec: str) -> str:
        return "***"

    def __bool__(self) -> bool:
        return bool(self._value)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Secret) and other._value == self._value

    def __hash__(self) -> int:
        return hash(("Secret", self._value))

    def __reduce__(self):
        raise TypeError("Secret values are not picklable")


def register_secret(value: str | None) -> None:
    if value and len(value) >= 6:
        with _registry_lock:
            _registry.add(value)


def redact(text: Any) -> str:
    s = str(text)
    with _registry_lock:
        known = sorted(_registry, key=len, reverse=True)
    for v in known:
        if v in s:
            s = s.replace(v, REDACTED)
    for p in _PATTERNS:
        if p.groups == 3:
            s = p.sub(lambda m: m.group(1) + m.group(2) + REDACTED, s)
        elif p.groups == 1:
            s = p.sub(lambda m: m.group(1) + " " + REDACTED, s)
        else:
            s = p.sub(REDACTED, s)
    return s


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact(record.getMessage())
        record.args = None
        if record.exc_info and record.exc_info[1] is not None:
            # format the traceback now, redacted, and drop the live exception object
            record.exc_text = redact(logging.Formatter().formatException(record.exc_info))
            record.exc_info = None
        return True


def get_logger(name: str) -> logging.Logger:
    log = logging.getLogger(name)
    if not any(isinstance(f, RedactingFilter) for f in log.filters):
        log.addFilter(RedactingFilter())
    return log


def install_redaction(handler: logging.Handler) -> logging.Handler:
    """Attach the filter to a handler too, so records from any logger that reach it are scrubbed."""
    if not any(isinstance(f, RedactingFilter) for f in handler.filters):
        handler.addFilter(RedactingFilter())
    return handler


def _inside_repo(p: Path) -> bool:
    return p == REPO_ROOT or REPO_ROOT in p.parents


def check_secret_path(path: str | os.PathLike, *, must_exist: bool = True) -> Path:
    p = Path(path).expanduser().resolve()
    if _inside_repo(p):
        raise SecretError(
            f"refusing secret file inside the repository ({p.name}); keep credentials outside {REPO_ROOT}"
        )
    if must_exist:
        if not p.is_file():
            raise SecretError(f"secret file not found: {p}")
        mode = p.stat().st_mode
        if os.name == "posix" and mode & (stat.S_IRWXG | stat.S_IRWXO):
            if os.environ.get("PHISHGUARD_ALLOW_INSECURE_SECRET_PERMS") != "1":
                raise SecretError(f"{p} is readable by group/others (mode {oct(mode & 0o777)}); run: chmod 600 {p}")
    return p


def read_secret_file(path: str | os.PathLike) -> Secret:
    return Secret(check_secret_path(path).read_text(encoding="utf-8").strip())


def read_json_secret_file(path: str | os.PathLike) -> dict[str, Any]:
    data = json.loads(check_secret_path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SecretError(f"{Path(path).name}: expected a JSON object")
    for k in ("client_secret", "private_key", "refresh_token"):
        if isinstance(data.get(k), str):
            register_secret(data[k])
    for nested in data.values():
        if isinstance(nested, dict) and isinstance(nested.get("client_secret"), str):
            register_secret(nested["client_secret"])
    return data


def secret_from_env(name: str, env: dict[str, str] | None = None) -> Secret | None:
    """`NAME` holds the value, or `NAME_FILE` holds a path to it (Docker/K8s secret style)."""
    env = os.environ if env is None else env
    if env.get(name):
        return Secret(env[name])
    if env.get(name + "_FILE"):
        return read_secret_file(env[name + "_FILE"])
    return None


class TokenStore:
    """A small JSON file of refresh tokens. Mode 0600, directory 0700, atomic replace, outside the repo."""

    def __init__(self, path: str | os.PathLike):
        self.path = check_secret_path(path, must_exist=False)
        self._lock = threading.Lock()

    def _load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {}
        check_secret_path(self.path)  # permissions may have been loosened since we wrote it
        data = json.loads(self.path.read_text(encoding="utf-8") or "{}")
        for v in data.values():
            if isinstance(v, dict) and isinstance(v.get("refresh_token"), str):
                register_secret(v["refresh_token"])
        return data

    def get(self, key: str) -> dict[str, Any] | None:
        with self._lock:
            return self._load().get(key)

    def put(self, key: str, value: dict[str, Any]) -> None:
        with self._lock:
            data = self._load()
            data[key] = value
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".tok-")
            try:
                os.fchmod(fd, 0o600) if hasattr(os, "fchmod") else None
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(data, f)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp, self.path)
            except BaseException:
                if os.path.exists(tmp):
                    os.unlink(tmp)
                raise
            if os.name == "posix":
                os.chmod(self.path, 0o600)
