"""Generic IMAP4 over TLS (iCloud, Yahoo, Fastmail, QQ, 163/NetEase, Zoho, GMX, ...).

Read-only by construction: the folder is opened with EXAMINE (`select(readonly=True)`) and bodies
are fetched with BODY.PEEK[], so not even the \\Seen flag changes. Plaintext IMAP is refused
unless `allow_plaintext=True` (a development flag, e.g. a local test server).

Cursor = "<UIDVALIDITY>:<last UID seen>". If the server's UIDVALIDITY changes, UIDs were
renumbered; the connector restarts from now and returns the most recent page, and the scanner's
content-hash dedupe stops renumbered copies of old mail from being scanned again.
Provider message id = "<UIDVALIDITY>:<UID>".
"""

from __future__ import annotations

import imaplib
import re
import ssl
from collections.abc import Callable
from dataclasses import dataclass

from ..readonly.eml import MAX_RAW_BYTES, EmlTooLarge
from .base import ConnectorError, CursorExpired, MailboxConnector, MalformedMessage, MessageRef
from .http import TokenProvider
from .secrets import Secret, get_logger, register_secret

log = get_logger(__name__)


@dataclass(frozen=True)
class ImapPreset:
    host: str
    port: int = 993
    auth: tuple[str, ...] = ("app_password",)  # "app_password" and/or "xoauth2"
    oauth_provider: str | None = None  # "google" | "microsoft" when XOAUTH2 is offered to any client
    junk_folder: str = "Junk"
    trash_folder: str = "Trash"
    send_id: bool = False  # RFC 2971 ID before SELECT (NetEase refuses "Unsafe Login" without it)
    notes: str = ""


PRESETS: dict[str, ImapPreset] = {
    "gmail": ImapPreset(
        "imap.gmail.com",
        auth=("app_password", "xoauth2"),
        oauth_provider="google",
        junk_folder="[Gmail]/Spam",
        trash_folder="[Gmail]/Trash",
        notes="Prefer --provider gmail (Gmail API, read-only scope). IMAP needs an app password (2-Step "
        "Verification on) or XOAUTH2 with the full-access https://mail.google.com/ scope.",
    ),
    "outlook": ImapPreset(
        "outlook.office365.com",
        auth=("xoauth2",),
        oauth_provider="microsoft",
        trash_folder="Deleted Items",
        notes="Prefer --provider graph. Basic auth is disabled; XOAUTH2 needs IMAP.AccessAsUser.All.",
    ),
    "icloud": ImapPreset(
        "imap.mail.me.com",
        trash_folder="Deleted Messages",
        notes="App-specific password from account.apple.com > Sign-In and Security. Username: your full "
        "iCloud address.",
    ),
    "yahoo": ImapPreset(
        "imap.mail.yahoo.com",
        trash_folder="Trash",
        junk_folder="Bulk",
        notes="App password from Account security > Generate app password. (Yahoo XOAUTH2 needs an approved app.)",
    ),
    "aol": ImapPreset("imap.aol.com", junk_folder="Bulk", notes="App password from Account security."),
    "fastmail": ImapPreset(
        "imap.fastmail.com",
        junk_folder="Spam",
        notes="App password: Settings > Privacy & Security > Integrations > App passwords (scope: Mail, IMAP).",
    ),
    "qq": ImapPreset(
        "imap.qq.com",
        junk_folder="Junk",
        trash_folder="Deleted Messages",
        notes="Enable IMAP/SMTP in QQ Mail settings > Account, then use the generated authorization code "
        "(授权码) as the password.",
    ),
    "163": ImapPreset(
        "imap.163.com",
        junk_folder="垃圾邮件",
        trash_folder="已删除",
        send_id=True,
        notes="Enable IMAP in Settings > POP3/SMTP/IMAP and use the authorization code (授权码). Requires the "
        "IMAP ID command, which PhishGuard sends.",
    ),
    "126": ImapPreset("imap.126.com", junk_folder="垃圾邮件", trash_folder="已删除", send_id=True, notes="As 163."),
    "yeah": ImapPreset("imap.yeah.net", junk_folder="垃圾邮件", trash_folder="已删除", send_id=True, notes="As 163."),
    "zoho": ImapPreset(
        "imap.zoho.com",
        junk_folder="Spam",
        notes="Enable IMAP access in Zoho Mail settings; with 2FA use an application-specific password. "
        "EU accounts: imap.zoho.eu, India: imap.zoho.in (override with PHISHGUARD_IMAP_HOST).",
    ),
    "gmx": ImapPreset(
        "imap.gmx.com",
        junk_folder="Spam",
        notes="Enable IMAP in GMX settings first. German accounts: imap.gmx.net.",
    ),
    "yandex": ImapPreset("imap.yandex.com", junk_folder="Spam", notes="App password from Yandex ID > Security."),
}

_CRLF = re.compile(r"[\r\n\x00]")
_FETCH_UID = re.compile(rb"UID (\d+)")
_FETCH_SIZE = re.compile(rb"RFC822\.SIZE (\d+)")
_CURSOR = re.compile(r"^(\d{1,10}):(\d{1,10})$")


def quote_mailbox(name: str) -> str:
    if _CRLF.search(name) or not name:
        raise ValueError("invalid IMAP folder name")
    if name.isascii():
        return '"' + name.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return '"' + _utf7_imap(name) + '"'


def _utf7_imap(s: str) -> str:
    """RFC 3501 modified UTF-7, for folder names such as 垃圾邮件."""
    import base64

    out, buf = [], []

    def flush():
        if buf:
            b = base64.b64encode("".join(buf).encode("utf-16-be")).rstrip(b"=").replace(b"/", b",")
            out.append("&" + b.decode() + "-")
            buf.clear()

    for ch in s:
        if 0x20 <= ord(ch) <= 0x7E:
            flush()
            out.append("&-" if ch == "&" else ch)
        else:
            buf.append(ch)
    flush()
    return "".join(out)


def xoauth2_string(user: str, token: str) -> bytes:
    return f"user={user}\x01auth=Bearer {token}\x01\x01".encode()


def tls_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


class ImapConnector(MailboxConnector):
    provider = "imap"

    def __init__(
        self,
        host: str,
        username: str,
        *,
        password: Secret | None = None,
        oauth: TokenProvider | None = None,
        port: int = 993,
        folder: str = "INBOX",
        tls: bool = True,
        allow_plaintext: bool = False,
        send_id: bool = False,
        ssl_context: ssl.SSLContext | None = None,
        timeout: float = 30.0,
        page_size: int = 50,
        imap_factory: Callable[..., imaplib.IMAP4] | None = None,
    ):
        if not tls and not allow_plaintext:
            raise ConnectorError(
                "refusing plaintext IMAP: credentials and mail would cross the network unencrypted. "
                "Use port 993 (TLS). For a local test server only, set PHISHGUARD_IMAP_ALLOW_PLAINTEXT=1."
            )
        if (password is None) == (oauth is None):
            raise ConnectorError("IMAP needs exactly one of password (app password) or oauth (XOAUTH2)")
        if _CRLF.search(host + username):
            raise ValueError("invalid host or username")
        quote_mailbox(folder)
        self.host, self.port, self.username, self.folder = host, port, username, folder
        self.tls, self.send_id, self.timeout, self.page_size = tls, send_id, timeout, page_size
        self._password, self._oauth = password, oauth
        self._ctx = ssl_context or tls_context()
        self._factory = imap_factory
        self._conn: imaplib.IMAP4 | None = None
        self._uidvalidity: int | None = None
        self._uidnext: int | None = None

    @property
    def mailbox_key(self) -> str:
        return f"imap:{self.username.lower()}@{self.host.lower()}/{self.folder}"

    # -- connection ------------------------------------------------------------
    def _open(self) -> imaplib.IMAP4:
        if self._factory:
            conn = self._factory(self.host, self.port, tls=self.tls, ssl_context=self._ctx, timeout=self.timeout)
        elif self.tls:
            conn = imaplib.IMAP4_SSL(self.host, self.port, ssl_context=self._ctx, timeout=self.timeout)
        else:
            log.warning("plaintext IMAP to %s:%d (development flag set)", self.host, self.port)
            conn = imaplib.IMAP4(self.host, self.port, timeout=self.timeout)
        try:
            if self._oauth is not None:
                token = self._oauth.token()
                register_secret(token)
                sent = []

                def answer(_challenge: bytes) -> bytes:
                    if sent:  # server sent an error challenge: reply empty to receive the tagged NO
                        return b""
                    sent.append(1)
                    return xoauth2_string(self.username, token)

                conn.authenticate("XOAUTH2", answer)
            else:
                conn.login(self.username, self._password.reveal())  # type: ignore[union-attr]
            if self.send_id:
                imaplib.Commands.setdefault("ID", ("NONAUTH", "AUTH", "SELECTED"))
                conn._simple_command("ID", '("name" "PhishGuard" "version" "0.1" "vendor" "PhishGuard")')
            self._select(conn, self.folder)
            self._uidvalidity = self._code(conn, "UIDVALIDITY")
            self._uidnext = self._code(conn, "UIDNEXT")
            if self._uidvalidity is None:
                raise ConnectorError("server did not report UIDVALIDITY")
        except imaplib.IMAP4.error as e:
            self._safe_logout(conn)
            # imaplib errors echo the server text, never our password; still, keep it short
            raise ConnectorError(f"IMAP login/select failed: {str(e)[:120]}") from None
        except BaseException:
            self._safe_logout(conn)
            raise
        return conn

    def _select(self, conn: imaplib.IMAP4, folder: str) -> None:
        typ, _ = conn.select(quote_mailbox(folder), readonly=True)  # EXAMINE: nothing can change
        if typ != "OK":
            raise ConnectorError(f"cannot open folder {folder!r}")

    @staticmethod
    def _code(conn: imaplib.IMAP4, name: str) -> int | None:
        _, data = conn.response(name)
        for d in data or []:
            if d is not None:
                m = re.match(rb"\s*(\d+)", d if isinstance(d, bytes) else str(d).encode())
                if m:
                    return int(m.group(1))
        return None

    def _c(self) -> imaplib.IMAP4:
        if self._conn is None:
            self._conn = self._open()
        return self._conn

    @staticmethod
    def _safe_logout(conn) -> None:
        try:
            conn.logout()
        except Exception:  # noqa: BLE001 - best effort
            pass

    def close(self) -> None:
        if self._conn is not None:
            self._safe_logout(self._conn)
            self._conn = None

    end_poll = close  # IMAP connections idle out; reconnect each round

    def _uid(self, *args: str) -> list:
        try:
            typ, data = self._c().uid(*args)
        except (imaplib.IMAP4.abort, OSError):
            self.close()  # dropped connection: reconnect once
            typ, data = self._c().uid(*args)
        if typ != "OK":
            raise ConnectorError(f"IMAP UID {args[0]} failed")
        return data

    # -- interface ---------------------------------------------------------------
    def _search(self, criteria: str) -> list[int]:
        data = self._uid("SEARCH", criteria)
        return sorted({int(x) for x in b" ".join(d for d in data if d).split() if x.isdigit()})

    def initial_cursor(self) -> str:
        self._c()
        last = (self._uidnext - 1) if self._uidnext else max(self._search("ALL") or [0])
        return f"{self._uidvalidity}:{last}"

    def list_new(self, cursor: str | None) -> tuple[list[MessageRef], str]:
        if cursor is None:
            return [], self.initial_cursor()
        m = _CURSOR.match(cursor)
        if not m:
            raise CursorExpired("stored IMAP cursor is malformed")
        validity, last = int(m.group(1)), int(m.group(2))
        self._c()
        if validity != self._uidvalidity:
            log.warning("IMAP UIDVALIDITY changed; restarting from now and rescanning the latest page")
            return list(reversed(self.list_recent(self.page_size))), self.initial_cursor()
        uids = [u for u in self._search(f"UID {last + 1}:*") if u > last]  # n:* always matches the top UID
        nxt = max([last, *uids])
        return [MessageRef(f"{validity}:{u}") for u in uids], f"{validity}:{nxt}"

    def list_recent(self, n: int) -> list[MessageRef]:
        self._c()
        uids = self._search("ALL")[-n:] if n > 0 else []
        return [MessageRef(f"{self._uidvalidity}:{u}") for u in reversed(uids)]

    def _parse_ref(self, ref: MessageRef) -> int:
        m = _CURSOR.match(ref.provider_id)
        if not m:
            raise MalformedMessage("invalid IMAP message id")
        self._c()
        if int(m.group(1)) != self._uidvalidity:
            raise CursorExpired("message id belongs to an old UIDVALIDITY")
        return int(m.group(2))

    def fetch_raw(self, ref: MessageRef) -> bytes:
        uid = self._parse_ref(ref)
        size = None
        for item in self._uid("FETCH", str(uid), "(RFC822.SIZE)"):
            line = item[0] if isinstance(item, tuple) else item
            if isinstance(line, bytes) and (s := _FETCH_SIZE.search(line)):
                size = int(s.group(1))
        if size is None:
            raise MalformedMessage(f"IMAP message {uid} not found")
        if size > MAX_RAW_BYTES:
            raise EmlTooLarge(f"IMAP message {uid} is {size} bytes; limit {MAX_RAW_BYTES}")
        for item in self._uid("FETCH", str(uid), "(BODY.PEEK[])"):  # PEEK: don't set \Seen
            if isinstance(item, tuple) and len(item) == 2 and isinstance(item[1], bytes):
                u = _FETCH_UID.search(item[0])
                if u is None or int(u.group(1)) == uid:
                    raw = item[1]
                    if len(raw) > MAX_RAW_BYTES:
                        raise EmlTooLarge(f"IMAP message {uid} is {len(raw)} bytes; limit {MAX_RAW_BYTES}")
                    return raw
        raise MalformedMessage(f"IMAP message {uid}: no body returned")
