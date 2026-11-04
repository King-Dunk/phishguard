"""Mailbox remediation: the only code that changes mailbox state. Runs as Executor handlers, so every call
has passed the MFA gateway (policy.requires_mfa decides which ones need a second factor).

Write credentials are separate from read credentials (config `remediation.auth`, scopes gmail.modify /
Mail.ReadWrite) and only built when remediation is enabled for a mailbox.

Actions (all reversible except delete, which moves to Trash rather than purging):
- quarantine: Gmail label (default "PhishGuard/Quarantine") and remove INBOX; Graph move to Junk Email;
  IMAP UID MOVE to the junk folder
- label: Gmail label / Graph category / IMAP keyword
- banner: Gmail and IMAP insert an annotated copy with a warning banner and quarantine the original
  (providers don't allow editing a received message). Graph: not supported (see DESIGN Q46)
- delete (MFA): Gmail trash / Graph move to Deleted Items / IMAP move to Trash
- restore (MFA): back to the inbox
"""

from __future__ import annotations

import base64
import email
import email.policy
import html
from abc import ABC, abstractmethod
from typing import Any
from urllib.parse import quote

from ..connectors import auth as A
from ..connectors.factory import build_imap, http_client, token_provider
from ..connectors.gmail import API as GMAIL_API
from ..connectors.gmail import API_HOST as GMAIL_HOST
from ..connectors.graph import GRAPH, GRAPH_HOST
from ..connectors.http import RetryingClient
from ..connectors.imap import ImapConnector
from .policy import ActionType

BANNER_TEXT = (
    "WARNING from PhishGuard: this message looks like phishing (risk {risk}). Do not click links, open "
    "attachments, or send money or credentials. The original is in quarantine."
)


class NotSupported(RuntimeError):
    pass


def add_banner(raw: bytes, risk: float | str = "high") -> bytes:
    """Return a copy of the message with a warning prepended to every text part and a verdict header."""
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    text = BANNER_TEXT.format(risk=risk)
    for part in msg.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        ctype = part.get_content_type()
        if ctype not in ("text/plain", "text/html"):
            continue
        try:
            body = part.get_content()
        except (LookupError, ValueError):
            continue
        if ctype == "text/plain":
            part.set_content(f"[{text}]\n\n{body}", subtype="plain")
        else:
            div = (
                '<div style="border:2px solid #b00020;padding:8px;margin:8px 0;font-weight:bold;color:#b00020">'
                f"{html.escape(text)}</div>"
            )
            low = body.lower()
            i = low.find("<body")
            j = low.find(">", i) + 1 if i >= 0 else 0
            part.set_content(body[:j] + div + body[j:], subtype="html")
    del msg["X-PhishGuard-Verdict"]
    msg["X-PhishGuard-Verdict"] = f"phishing; risk={risk}"
    return msg.as_bytes(policy=email.policy.SMTP)


class MailboxWriter(ABC):
    @abstractmethod
    def quarantine(self, ids: list[str]) -> dict: ...

    @abstractmethod
    def label(self, ids: list[str], label: str) -> dict: ...

    @abstractmethod
    def banner(self, ids: list[str], risk: Any) -> dict: ...

    @abstractmethod
    def delete(self, ids: list[str]) -> dict: ...

    @abstractmethod
    def restore(self, ids: list[str]) -> dict: ...


class GmailWriter(MailboxWriter):
    def __init__(self, http: RetryingClient, user: str = "me", quarantine_label: str = "PhishGuard/Quarantine"):
        self.http, self.qlabel = http, quarantine_label
        self.base = f"{GMAIL_API}/{quote(user, safe='@.')}"
        self._label_ids: dict[str, str] = {}

    def _label_id(self, name: str) -> str:
        if name in ("SPAM", "INBOX", "TRASH"):
            return name
        if name not in self._label_ids:
            for lb in self.http.get_json(f"{self.base}/labels").get("labels", []):
                self._label_ids[lb["name"]] = lb["id"]
        if name not in self._label_ids:
            created = self.http.post_json(f"{self.base}/labels", {"name": name, "labelListVisibility": "labelShow"})
            self._label_ids[name] = created["id"]
        return self._label_ids[name]

    def _modify(self, ids, add=(), remove=()) -> None:
        body = {"ids": ids, "addLabelIds": list(add), "removeLabelIds": list(remove)}
        self.http.request("POST", f"{self.base}/messages/batchModify", json=body)

    def quarantine(self, ids):
        self._modify(ids, [self._label_id(self.qlabel)], ["INBOX"])
        return {"moved": len(ids), "to": self.qlabel}

    def label(self, ids, label):
        self._modify(ids, [self._label_id(label)])
        return {"labeled": len(ids), "label": label}

    def banner(self, ids, risk):
        copies = []
        for mid in ids:
            raw_b64 = self.http.get_json(f"{self.base}/messages/{quote(mid)}?format=raw")["raw"]
            raw = base64.urlsafe_b64decode(raw_b64 + "=" * (-len(raw_b64) % 4))
            new = base64.urlsafe_b64encode(add_banner(raw, risk)).decode()
            r = self.http.post_json(
                f"{self.base}/messages?internalDateSource=dateHeader", {"raw": new, "labelIds": ["INBOX"]}
            )
            copies.append(r.get("id"))
        self.quarantine(ids)
        return {"bannered": len(ids), "copies": copies}

    def delete(self, ids):
        for mid in ids:
            self.http.request("POST", f"{self.base}/messages/{quote(mid)}/trash")
        return {"trashed": len(ids)}

    def restore(self, ids):
        self._modify(ids, ["INBOX"], [self._label_id(self.qlabel), "SPAM"])
        return {"restored": len(ids)}


class GraphWriter(MailboxWriter):
    def __init__(self, http: RetryingClient, user: str = "me", quarantine_folder: str = "junkemail"):
        self.http, self.qfolder = http, quarantine_folder
        self.base = f"{GRAPH}/me" if user == "me" else f"{GRAPH}/users/{quote(user, safe='@.')}"

    def _move(self, ids, dest: str) -> int:
        for mid in ids:
            self.http.post_json(f"{self.base}/messages/{quote(mid, safe='')}/move", {"destinationId": dest})
        return len(ids)

    def quarantine(self, ids):
        return {"moved": self._move(ids, self.qfolder), "to": self.qfolder}

    def label(self, ids, label):
        for mid in ids:
            url = f"{self.base}/messages/{quote(mid, safe='')}"
            cats = self.http.get_json(f"{url}?$select=categories").get("categories", [])
            if label not in cats:
                self.http.request("PATCH", url, json={"categories": [*cats, label]})
        return {"labeled": len(ids), "category": label}

    def banner(self, ids, risk):
        raise NotSupported("Graph can't edit a received message; use label (category) and quarantine instead")

    def delete(self, ids):
        return {"moved": self._move(ids, "deleteditems"), "to": "deleteditems"}

    def restore(self, ids):
        return {"moved": self._move(ids, "inbox"), "to": "inbox"}


class ImapWriter(MailboxWriter):
    """Uses its own (write) connection: SELECT instead of EXAMINE. Requires the MOVE extension (RFC 6851),
    which all presets support; there is no silent COPY+EXPUNGE fallback that could lose mail."""

    def __init__(self, connector: ImapConnector, quarantine_folder: str = "Junk", trash_folder: str = "Trash"):
        self.c, self.qfolder, self.trash = connector, quarantine_folder, trash_folder

    @staticmethod
    def _uids(ids: list[str]) -> str:
        return ",".join(i.split(":", 1)[1] for i in ids)

    def _session(self, folder: str | None = None):
        conn = self.c.connect()
        typ, data = conn.select(self.c._quote(folder or self.c.folder))
        if typ != "OK":
            conn.logout()
            raise RuntimeError(f"cannot select {folder or self.c.folder}: {data}")
        return conn

    def _move(self, ids, dest, src=None) -> dict:
        conn = self._session(src)
        try:
            typ, data = conn.uid("MOVE", self._uids(ids), self.c._quote(dest))
            if typ != "OK":
                raise RuntimeError(f"UID MOVE failed: {data}")
        finally:
            conn.logout()
        return {"moved": len(ids), "to": dest}

    def quarantine(self, ids):
        return self._move(ids, self.qfolder)

    def label(self, ids, label):
        keyword = "$" + "".join(ch for ch in label if ch.isalnum())[:40]
        conn = self._session()
        try:
            conn.uid("STORE", self._uids(ids), "+FLAGS", f"({keyword})")
        finally:
            conn.logout()
        return {"labeled": len(ids), "keyword": keyword}

    def banner(self, ids, risk):
        conn = self._session()
        try:
            for i in ids:
                _, data = conn.uid("FETCH", i.split(":", 1)[1], "(BODY.PEEK[])")
                raw = next(p[1] for p in data if isinstance(p, tuple))
                conn.append(self.c._quote(self.c.folder), None, None, add_banner(raw, risk))
        finally:
            conn.logout()
        self.quarantine(ids)
        return {"bannered": len(ids)}

    def delete(self, ids):
        return self._move(ids, self.trash)

    def restore(self, ids):
        # ids are UIDs in the quarantine folder after a quarantine; the caller passes those
        return self._move(ids, self.c.folder, src=self.qfolder)


def build_writer(m: dict) -> MailboxWriter | None:
    """Writer for a mailbox config entry, or None when remediation is not enabled (the default)."""
    rem = m.get("remediation") or {}
    if not rem.get("enabled"):
        return None
    a = rem.get("auth") or {}
    p = m["provider"]
    if p == "imap":
        # IMAP has no scopes: an app password can always write. Separation is by connection mode
        # (EXAMINE for reading, SELECT only here) and by this opt-in.
        return ImapWriter(
            build_imap(m, a or m.get("auth") or {}),
            rem.get("quarantine_folder", "Junk"),
            rem.get("trash_folder", "Trash"),
        )
    if not a:
        raise ValueError(f"mailbox {m['name']}: remediation.auth (write credentials) is required")
    http = http_client()
    tok = token_provider(p, {**a, "_user": m.get("user", "me")}, True, http)
    if p == "gmail":
        return GmailWriter(
            RetryingClient(http, tok, [GMAIL_HOST]),
            m.get("user", "me"),
            rem.get("quarantine_label", "PhishGuard/Quarantine"),
        )
    return GraphWriter(
        RetryingClient(http, tok, [GRAPH_HOST]), m.get("user", "me"), rem.get("quarantine_folder", "junkemail")
    )


def handlers(writers: dict[str, MailboxWriter]) -> dict[ActionType, Any]:
    """Executor handlers. params: {"mailbox": name, "message_ids": [...], "label"?: str, "verdict_risk"?: n}"""

    def w(p: dict) -> MailboxWriter:
        if p.get("mailbox") not in writers:
            raise NotSupported(f"remediation not enabled for mailbox {p.get('mailbox')!r}")
        return writers[p["mailbox"]]

    return {
        ActionType.MAILBOX_QUARANTINE: lambda p: w(p).quarantine(p["message_ids"]),
        ActionType.MAILBOX_LABEL: lambda p: w(p).label(
            p["message_ids"], str(p.get("label", "PhishGuard: suspected phishing"))
        ),
        ActionType.MAILBOX_BANNER: lambda p: w(p).banner(p["message_ids"], p.get("verdict_risk", "high")),
        ActionType.MAILBOX_DELETE: lambda p: w(p).delete(p["message_ids"]),
        ActionType.MAILBOX_RESTORE: lambda p: w(p).restore(p["message_ids"]),
    }


WRITE_SCOPES = {"gmail": A.GMAIL_WRITE_SCOPE, "graph": " ".join(A.GRAPH_WRITE_SCOPES)}
