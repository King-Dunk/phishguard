"""Generic IMAP4rev1 connector over TLS (implicit TLS on 993 by default, or STARTTLS).

Read-only by construction: folders are opened with EXAMINE (server-enforced read-only) and messages are
fetched with BODY.PEEK[] so the \\Seen flag never changes. Plaintext IMAP is refused unless
allow_plaintext=True (local test servers only). Certificates and host names are verified.
Cursor: {"uidvalidity": V, "last_uid": N}. If UIDVALIDITY changes the server has renumbered the folder,
so we start over (the content-hash seen-set prevents re-scanning).
"""

from __future__ import annotations

import imaplib
import re
import ssl
from collections.abc import Callable

from .base import Batch, Cursor, MailboxConnector, RawMessage, Rejected
from .http import ProviderError
from .secrets import register

imaplib.Commands.setdefault("ID", ("NONAUTH", "AUTH", "SELECTED"))
imaplib.Commands.setdefault("MOVE", ("SELECTED",))
_SIZE = re.compile(rb"UID (\d+) RFC822\.SIZE (\d+)|RFC822\.SIZE (\d+) UID (\d+)")
_UID = re.compile(rb"UID (\d+)")


class InsecureTransport(ProviderError):
    pass


def xoauth2_string(user: str, token: str) -> bytes:
    register(token)
    return f"user={user}\x01auth=Bearer {token}\x01\x01".encode()


class ImapConnector(MailboxConnector):
    provider = "imap"

    def __init__(
        self,
        mailbox_name: str,
        host: str,
        username: str,
        password: str | None = None,
        token_provider=None,
        port: int = 993,
        folder: str = "INBOX",
        tls: str = "implicit",  # implicit | starttls | none
        allow_plaintext: bool = False,
        ssl_context: ssl.SSLContext | None = None,
        send_id: bool = False,
        timeout: float = 60,
        factory: Callable[..., imaplib.IMAP4] | None = None,
    ):
        super().__init__(mailbox_name)
        if tls not in ("implicit", "starttls", "none"):
            raise ValueError("tls must be implicit, starttls or none")
        if tls == "none" and not allow_plaintext:
            raise InsecureTransport(
                "plaintext IMAP refused: use TLS (port 993) or STARTTLS; allow_plaintext is for local tests only"
            )
        if password is None and token_provider is None:
            raise ValueError("need a password (app password) or an XOAUTH2 token provider")
        register(password)
        self.host, self.port, self.username, self.password = host, port, username, password
        self.token_provider, self.folder, self.tls = token_provider, folder, tls
        self.send_id, self.timeout = send_id, timeout
        self.ssl_context = ssl_context or ssl.create_default_context()  # verifies certificate + host name
        self.factory = factory

    # -- connection ------------------------------------------------------------------------
    def connect(self) -> imaplib.IMAP4:
        if self.factory:
            conn = self.factory(self.host, self.port)
        elif self.tls == "implicit":
            conn = imaplib.IMAP4_SSL(self.host, self.port, ssl_context=self.ssl_context, timeout=self.timeout)
        else:
            conn = imaplib.IMAP4(self.host, self.port, timeout=self.timeout)
            if self.tls == "starttls":
                conn.starttls(ssl_context=self.ssl_context)
        try:
            if self.token_provider is not None:
                tok = self.token_provider.token()
                conn.authenticate("XOAUTH2", lambda _: xoauth2_string(self.username, tok))
            else:
                conn.login(self.username, self.password)
            if self.send_id:
                conn._simple_command("ID", '("name" "PhishGuard" "version" "1.0")')
        except imaplib.IMAP4.error as e:
            try:
                conn.logout()
            except (imaplib.IMAP4.error, OSError):
                pass
            raise ProviderError(f"IMAP login to {self.host} failed: {e}") from None
        return conn

    @staticmethod
    def _uidvalidity(conn: imaplib.IMAP4) -> int:
        _, data = conn.response("UIDVALIDITY")
        if not data or data[0] is None:
            raise ProviderError("server did not report UIDVALIDITY")
        return int(data[0])

    def _examine(self, conn: imaplib.IMAP4) -> int:
        typ, data = conn.select(self._quote(self.folder), readonly=True)  # EXAMINE: server-side read-only
        if typ != "OK":
            raise ProviderError(f"cannot open folder {self.folder!r}: {data}")
        return self._uidvalidity(conn)

    @staticmethod
    def _quote(folder: str) -> str:
        if re.fullmatch(r"[A-Za-z0-9_./-]+", folder):
            return folder
        return '"' + folder.replace("\\", "\\\\").replace('"', '\\"') + '"'

    def _search(self, conn: imaplib.IMAP4, criteria: str) -> list[int]:
        typ, data = conn.uid("SEARCH", *criteria.split())
        if typ != "OK":
            raise ProviderError(f"UID SEARCH failed: {data}")
        return sorted(int(x) for x in b" ".join(d for d in data if d).split())

    def _sizes(self, conn: imaplib.IMAP4, uids: list[int]) -> dict[int, int]:
        if not uids:
            return {}
        typ, data = conn.uid("FETCH", ",".join(map(str, uids)), "(RFC822.SIZE)")
        out = {}
        for line in data or []:
            blob = line[0] if isinstance(line, tuple) else line
            m = _SIZE.search(blob or b"")
            if m:
                uid, size = (m.group(1), m.group(2)) if m.group(1) else (m.group(4), m.group(3))
                out[int(uid)] = int(size)
        return out

    def _body(self, conn: imaplib.IMAP4, uid: int) -> bytes:
        typ, data = conn.uid("FETCH", str(uid), "(BODY.PEEK[])")  # PEEK: do not set \Seen
        for part in data or []:
            if isinstance(part, tuple) and _UID.search(part[0]):
                return part[1]
        raise ProviderError(f"no body returned for UID {uid}")

    # -- interface ---------------------------------------------------------------------------
    def list_new_messages(self, cursor: Cursor | None, limit: int = 50) -> Batch:
        batch = Batch()
        conn = self.connect()
        try:
            uv = self._examine(conn)
            c = cursor or {}
            if c.get("uidvalidity") == uv:
                last = int(c.get("last_uid", 0))
                # "N:*" always matches the highest UID even when it is < N, so filter
                uids = [u for u in self._search(conn, f"UID {last + 1}:*") if u > last][:limit]
                new_last = max(uids, default=last)
            else:
                if c:
                    batch.notes.append("UIDVALIDITY changed; folder renumbered, starting over")
                all_uids = self._search(conn, "ALL")
                uids = all_uids[-limit:]
                new_last = max(all_uids, default=0)
            sizes = self._sizes(conn, uids)
            for uid in uids:
                pid = f"{uv}:{uid}"
                if sizes.get(uid, 0) > self.max_bytes:
                    batch.rejected.append(Rejected(pid, "too_large", sizes[uid]))
                    continue
                batch.messages.append(RawMessage(pid, self._body(conn, uid)))
            batch.cursor = {"uidvalidity": uv, "last_uid": new_last}
        finally:
            try:
                conn.logout()
            except (imaplib.IMAP4.error, OSError):
                pass
        return batch
