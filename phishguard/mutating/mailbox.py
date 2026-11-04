"""Mailbox remediation (MUTATING): quarantine, junk, label, warning banner, delete, release.

Only reachable through the MFA gateway: `remediation_handlers()` returns Executor handlers, and
the Executor runs a handler only with a gateway-issued grant. The policy (policy.py) decides which
of these need MFA. Write access is a separate, opt-in credential (`PHISHGUARD_WRITE_TOKEN_FILE`,
`PHISHGUARD_GRAPH_WRITE_*`, `PHISHGUARD_GMAIL_WRITE_SA_KEY_FILE`, `PHISHGUARD_IMAP_WRITE_PASSWORD`);
the read-side connectors never see it.

Per provider:
                    Gmail (gmail.modify)          Graph (Mail.ReadWrite)       IMAP
  quarantine        label PhishGuard/Quarantine,  move to folder               MOVE to folder
                    remove INBOX                  "PhishGuard Quarantine"      PhishGuard-Quarantine
  mark_spam         label SPAM, remove INBOX      move to junkemail            MOVE to the Junk folder
  apply_label       add a user label              add a category               set a keyword flag
  add_warning_banner insert bannered copy,        not supported (use an        APPEND bannered copy,
                    quarantine the original       Exchange transport rule)     quarantine the original
  delete_email      move to Trash                 move to deleteditems         MOVE to Trash
  release           back to INBOX                 move to inbox                not supported
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import imaplib
import re
from collections.abc import Callable, Mapping
from email import message_from_bytes, policy
from typing import Any
from urllib.parse import quote

import httpx

from ..connectors import gmail as gmail_read
from ..connectors import graph as graph_read
from ..connectors.config import google_auth, imap_params, microsoft_auth, new_http
from ..connectors.http import HttpClient
from ..connectors.imap import PRESETS, ImapConnector, quote_mailbox
from ..connectors.oauth import GMAIL_MODIFY_SCOPE, GRAPH_WRITE_SCOPE
from ..connectors.secrets import Secret, get_logger, secret_from_env
from ..readonly.eml import MAX_RAW_BYTES
from .policy import ActionType

log = get_logger(__name__)

QUARANTINE_NAME = "PhishGuard/Quarantine"
GRAPH_QUARANTINE_NAME = "PhishGuard Quarantine"
IMAP_QUARANTINE_NAME = "PhishGuard-Quarantine"
LABEL_RE = re.compile(r"^[\w ./-]{1,64}$")
BANNER_HEADER = "X-PhishGuard-Banner"


class NotSupported(RuntimeError):
    pass


class TargetMismatch(PermissionError):
    pass


# -- warning banner ------------------------------------------------------------------
BANNER_TEXT = (
    "[PhishGuard warning] This message looks like phishing (risk {risk}%). Do not click links, open "
    "attachments or reply with information. The original is in quarantine."
)
_BANNER_HTML = (
    '<div style="border:2px solid #b00020;background:#fdecea;color:#5f0010;padding:8px;margin:0 0 12px 0;'
    'font-family:sans-serif;font-size:14px">{text}</div>'
)


def _banner_mac(key: bytes, mailbox: str, sha: str) -> str:
    return hmac.new(key, f"{mailbox}\n{sha}".encode(), hashlib.sha256).hexdigest()[:32]


def is_bannered(raw: bytes, key: bytes, mailbox: str) -> bool:
    """True only for copies *we* made: the header carries an HMAC no sender can compute."""
    msg = message_from_bytes(raw, policy=policy.default)
    for h in msg.get_all(BANNER_HEADER, []):
        m = re.match(r"v1; sha=([0-9a-f]{64}); mac=([0-9a-f]{32})$", str(h).strip())
        if m and hmac.compare_digest(m.group(2), _banner_mac(key, mailbox, m.group(1))):
            return True
    return False


def add_banner(raw: bytes, key: bytes, mailbox: str, risk: float) -> bytes:
    """Prepend a warning to every text/plain and text/html body part; attachments untouched."""
    sha = hashlib.sha256(raw).hexdigest()
    msg = message_from_bytes(raw, policy=policy.default)
    text = BANNER_TEXT.format(risk=f"{float(risk):.0f}")
    for part in msg.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment" or part.get_filename():
            continue
        ctype = part.get_content_type()
        if ctype not in ("text/plain", "text/html"):
            continue
        try:
            body = part.get_content()
        except (LookupError, ValueError):
            body = (part.get_payload(decode=True) or b"").decode("utf-8", "replace")
        if ctype == "text/plain":
            part.set_content(text + "\n\n" + body, subtype="plain", charset="utf-8")
        else:
            div = _BANNER_HTML.format(text=html.escape(text))
            m = re.search(r"<body[^>]*>", body, re.I)
            new = body[: m.end()] + div + body[m.end() :] if m else div + body
            part.set_content(new, subtype="html", charset="utf-8")
    for h in list(msg.keys()):
        if h.lower() == BANNER_HEADER.lower():
            del msg[h]  # a sender-supplied banner header must never survive
    msg[BANNER_HEADER] = f"v1; sha={sha}; mac={_banner_mac(key, mailbox, sha)}"
    out = msg.as_bytes(policy=policy.SMTP)
    if len(out) > MAX_RAW_BYTES * 2:
        raise NotSupported("bannered copy would be too large")
    return out


# -- providers -------------------------------------------------------------------------
class WriteHttpClient(HttpClient):
    """HttpClient plus the write verbs. Exists only on the mutating side."""

    def send_json(
        self, method: str, url: str, payload: dict[str, Any] | None = None, headers: dict | None = None
    ) -> dict[str, Any]:
        body = self._send(method, url, json=payload, headers=headers)
        return self._json(body, method, url) if body.strip() else {}


class MailboxRemediator:
    provider = ""
    mailbox_key = ""

    def quarantine(self, mid: str) -> dict[str, Any]:
        raise NotSupported(f"{self.provider}: quarantine")

    def mark_spam(self, mid: str) -> dict[str, Any]:
        raise NotSupported(f"{self.provider}: mark_spam")

    def apply_label(self, mid: str, label: str) -> dict[str, Any]:
        raise NotSupported(f"{self.provider}: apply_label")

    def add_warning_banner(self, mid: str, risk: float) -> dict[str, Any]:
        raise NotSupported(f"{self.provider}: add_warning_banner")

    def delete(self, mid: str) -> dict[str, Any]:
        raise NotSupported(f"{self.provider}: delete_email")

    def release(self, mid: str) -> dict[str, Any]:
        raise NotSupported(f"{self.provider}: release_from_quarantine")

    def close(self) -> None:
        return


class GmailRemediator(MailboxRemediator):
    provider = "gmail"

    def __init__(
        self, http: WriteHttpClient, user: str = "me", label_id: str = "INBOX", banner_key: Secret | None = None
    ):
        self.http, self.user, self.label_id, self.banner_key = http, user, label_id, banner_key
        self.mailbox_key = f"gmail:{user.lower()}/{label_id}"
        self._base = f"{gmail_read.API}/{quote(user, safe='@.')}"
        self._labels: dict[str, str] = {}

    def _id(self, mid: str) -> str:
        if not gmail_read._ID_RE.match(mid):
            raise ValueError("invalid Gmail message id")
        return mid

    def _label(self, name: str) -> str:
        if name not in self._labels:
            for lab in self.http.get_json(f"{self._base}/labels").get("labels") or []:
                self._labels[str(lab.get("name"))] = str(lab.get("id"))
        if name not in self._labels:
            made = self.http.send_json(
                "POST",
                f"{self._base}/labels",
                {"name": name, "labelListVisibility": "labelShow", "messageListVisibility": "show"},
            )
            self._labels[name] = str(made["id"])
        return self._labels[name]

    def _modify(self, mid: str, add: list[str], remove: list[str]) -> dict[str, Any]:
        self.http.send_json(
            "POST", f"{self._base}/messages/{self._id(mid)}/modify", {"addLabelIds": add, "removeLabelIds": remove}
        )
        return {"ok": True, "message_id": mid}

    def quarantine(self, mid):
        return self._modify(mid, [self._label(QUARANTINE_NAME)], [self.label_id])

    def mark_spam(self, mid):
        return self._modify(mid, ["SPAM"], [self.label_id])

    def apply_label(self, mid, label):
        return self._modify(mid, [self._label(label)], [])

    def delete(self, mid):
        self.http.send_json("POST", f"{self._base}/messages/{self._id(mid)}/trash")
        return {"ok": True, "message_id": mid, "trashed": True}

    def release(self, mid):
        return self._modify(mid, [self.label_id], [self._label(QUARANTINE_NAME)])

    def add_warning_banner(self, mid, risk):
        if self.banner_key is None:
            raise NotSupported("set PHISHGUARD_BANNER_KEY to enable warning banners")
        key = self.banner_key.reveal().encode()
        data = self.http.get_json(f"{self._base}/messages/{self._id(mid)}", params={"format": "raw"})
        raw_b64 = str(data.get("raw", ""))
        raw = base64.urlsafe_b64decode(raw_b64 + "=" * (-len(raw_b64) % 4))
        if is_bannered(raw, key, self.mailbox_key):
            return {"ok": True, "message_id": mid, "noop": "already bannered"}
        new = add_banner(raw, key, self.mailbox_key, risk)
        made = self.http.send_json(
            "POST",
            f"{self._base}/messages",
            {"raw": base64.urlsafe_b64encode(new).decode(), "labelIds": [self.label_id, "UNREAD"]},
        )
        self.quarantine(mid)
        return {"ok": True, "message_id": mid, "bannered_copy": str(made.get("id", ""))}


class GraphRemediator(MailboxRemediator):
    provider = "graph"

    def __init__(self, http: WriteHttpClient, mailbox: str | None = None, folder: str = "inbox"):
        self.http, self.folder = http, folder
        self.mailbox_key = f"graph:{(mailbox or 'me').lower()}/{folder}"
        self.base = f"{graph_read.GRAPH}/users/{quote(mailbox, safe='@.')}" if mailbox else f"{graph_read.GRAPH}/me"
        self._qid: str | None = None
        self._headers = {"Prefer": 'IdType="ImmutableId"'}

    def _id(self, mid: str) -> str:
        if not graph_read._ID_RE.match(mid):
            raise ValueError("invalid Graph message id")
        return quote(mid, safe="")

    def _quarantine_folder(self) -> str:
        if self._qid is None:
            found = self.http.get_json(
                f"{self.base}/mailFolders",
                params={"$filter": f"displayName eq '{GRAPH_QUARANTINE_NAME}'"},
                headers=self._headers,
            )
            vals = found.get("value") or []
            if vals:
                self._qid = str(vals[0]["id"])
            else:
                made = self.http.send_json(
                    "POST", f"{self.base}/mailFolders", {"displayName": GRAPH_QUARANTINE_NAME}, self._headers
                )
                self._qid = str(made["id"])
        return self._qid

    def _move(self, mid: str, dest: str) -> dict[str, Any]:
        moved = self.http.send_json(
            "POST", f"{self.base}/messages/{self._id(mid)}/move", {"destinationId": dest}, self._headers
        )
        return {"ok": True, "message_id": mid, "new_id": str(moved.get("id", ""))}

    def quarantine(self, mid):
        return self._move(mid, self._quarantine_folder())

    def mark_spam(self, mid):
        return self._move(mid, "junkemail")

    def delete(self, mid):
        return self._move(mid, "deleteditems")

    def release(self, mid):
        return self._move(mid, "inbox")

    def apply_label(self, mid, label):
        cur = self.http.get_json(
            f"{self.base}/messages/{self._id(mid)}", params={"$select": "categories"}, headers=self._headers
        )
        cats = [str(c) for c in cur.get("categories") or []]
        if label not in cats:
            self.http.send_json(
                "PATCH", f"{self.base}/messages/{self._id(mid)}", {"categories": [*cats, label]}, self._headers
            )
        return {"ok": True, "message_id": mid}

    def add_warning_banner(self, mid, risk):
        raise NotSupported(
            "Graph cannot rewrite a received message's body; use an Exchange transport rule for banners, "
            "or apply_label (category) + quarantine"
        )


class _ImapWriteConnection(ImapConnector):
    """The IMAP connector, but the folder is opened read-write (SELECT instead of EXAMINE)."""

    def _select(self, conn, folder):
        typ, _ = conn.select(quote_mailbox(folder), readonly=False)
        if typ != "OK":
            raise RuntimeError(f"cannot open folder {folder!r} for writing")


class ImapRemediator(MailboxRemediator):
    provider = "imap"

    def __init__(
        self,
        conn: ImapConnector,
        junk_folder: str = "Junk",
        trash_folder: str = "Trash",
        banner_key: Secret | None = None,
    ):
        self.conn, self.junk, self.trash, self.banner_key = conn, junk_folder, trash_folder, banner_key
        self.mailbox_key = conn.mailbox_key
        self._created: set[str] = set()

    def _imap(self):
        return self.conn._c()

    def _caps(self) -> set[str]:
        return {c.upper() for c in self._imap().capabilities}

    def _uid(self, mid: str) -> int:
        return self.conn._parse_ref(_Ref(mid))

    def _ensure_folder(self, name: str) -> None:
        if name in self._created:
            return
        typ, data = self._imap().list('""', quote_mailbox(name))
        if typ != "OK" or not [d for d in data or [] if d]:
            typ, _ = self._imap().create(quote_mailbox(name))
            if typ != "OK":
                raise RuntimeError(f"cannot create folder {name!r}")
        self._created.add(name)

    def _move(self, mid: str, dest: str) -> dict[str, Any]:
        uid = str(self._uid(mid))
        self._ensure_folder(dest)
        caps = self._caps()
        if "MOVE" in caps:
            imaplib.Commands.setdefault("MOVE", ("SELECTED",))  # RFC 6851; older imaplib lacks it
            self.conn._uid("MOVE", uid, quote_mailbox(dest))
            return {"ok": True, "message_id": mid, "folder": dest}
        self.conn._uid("COPY", uid, quote_mailbox(dest))
        self.conn._uid("STORE", uid, "+FLAGS.SILENT", "(\\Deleted)")
        if "UIDPLUS" in caps:
            self.conn._uid("EXPUNGE", uid)  # removes only this message
            return {"ok": True, "message_id": mid, "folder": dest}
        # Without UIDPLUS a plain EXPUNGE would also purge anything else the user flagged \Deleted.
        return {"ok": True, "message_id": mid, "folder": dest, "note": "original flagged \\Deleted, not expunged"}

    def quarantine(self, mid):
        return self._move(mid, IMAP_QUARANTINE_NAME)

    def mark_spam(self, mid):
        return self._move(mid, self.junk)

    def delete(self, mid):
        return self._move(mid, self.trash)

    def apply_label(self, mid, label):
        kw = "$" + re.sub(r"[^A-Za-z0-9_]", "", label)[:40]
        self.conn._uid("STORE", str(self._uid(mid)), "+FLAGS.SILENT", f"({kw})")
        return {"ok": True, "message_id": mid, "keyword": kw}

    def add_warning_banner(self, mid, risk):
        if self.banner_key is None:
            raise NotSupported("set PHISHGUARD_BANNER_KEY to enable warning banners")
        key = self.banner_key.reveal().encode()
        raw = self.conn.fetch_raw(_Ref(mid))
        if is_bannered(raw, key, self.mailbox_key):
            return {"ok": True, "message_id": mid, "noop": "already bannered"}
        new = add_banner(raw, key, self.mailbox_key, risk)
        typ, _ = self._imap().append(quote_mailbox(self.conn.folder), None, None, new)
        if typ != "OK":
            raise RuntimeError("APPEND failed")
        self.quarantine(mid)
        return {"ok": True, "message_id": mid, "bannered_copy": True}

    def close(self) -> None:
        self.conn.close()


class _Ref:
    def __init__(self, mid: str):
        self.provider_id = mid


# -- wiring --------------------------------------------------------------------------
def remediation_handlers(rem: MailboxRemediator) -> dict[ActionType, Callable[[dict[str, Any]], dict[str, Any]]]:
    """Executor handlers. Params: provider, mailbox, message_id | message_ids, [label], [risk]."""

    def target(params: Mapping[str, Any]) -> list[str]:
        if params.get("provider") != rem.provider or params.get("mailbox") != rem.mailbox_key:
            raise TargetMismatch("action targets a different mailbox than this remediator's credential")
        ids = params.get("message_ids")
        if ids is None:
            ids = [params.get("message_id")]
        if not ids or not all(isinstance(i, str) and i for i in ids):
            raise ValueError("message_id(s) required")
        return list(ids)

    def each(fn: Callable[[str, Mapping[str, Any]], dict[str, Any]]):
        def handler(params: dict[str, Any]) -> dict[str, Any]:
            results = [fn(mid, params) for mid in target(params)]
            return {"ok": all(r.get("ok") for r in results), "results": results}

        return handler

    def label(mid, p):
        name = str(p.get("label") or "PhishGuard/Suspicious")
        if not LABEL_RE.match(name):
            raise ValueError("invalid label")
        return rem.apply_label(mid, name)

    return {
        ActionType.QUARANTINE_EMAIL: each(lambda mid, p: rem.quarantine(mid)),
        ActionType.MARK_SPAM: each(lambda mid, p: rem.mark_spam(mid)),
        ActionType.APPLY_LABEL: each(label),
        ActionType.ADD_WARNING_BANNER: each(lambda mid, p: rem.add_warning_banner(mid, float(p.get("risk") or 0))),
        ActionType.DELETE_EMAIL: each(lambda mid, p: rem.delete(mid)),
        ActionType.RELEASE_FROM_QUARANTINE: each(lambda mid, p: rem.release(mid)),
    }


def remediator_from_env(
    provider: str, env: Mapping[str, str], client: httpx.Client | None = None, **kw: Any
) -> MailboxRemediator:
    """Build a remediator from the separate WRITE credentials. Fails if none are configured."""
    banner_key = secret_from_env("PHISHGUARD_BANNER_KEY", dict(env))
    if provider == "gmail":
        auth = google_auth(env, [GMAIL_MODIFY_SCOPE], "gmail:write", True, client)
        http = WriteHttpClient(client, auth=auth, auth_hosts=gmail_read.AUTH_HOSTS)
        return GmailRemediator(http, user=env.get("PHISHGUARD_GMAIL_USER") or "me", banner_key=banner_key)
    if provider == "graph":
        auth = microsoft_auth(env, [GRAPH_WRITE_SCOPE], "graph:write", True, client)
        http = WriteHttpClient(client, auth=auth, auth_hosts=graph_read.AUTH_HOSTS)
        return GraphRemediator(
            http,
            mailbox=env.get("PHISHGUARD_GRAPH_MAILBOX") or None,
            folder=env.get("PHISHGUARD_GRAPH_FOLDER", "inbox"),
        )
    if provider == "imap":
        params = imap_params(env, write=True, client=client)
        preset = PRESETS.get(env.get("PHISHGUARD_IMAP_PRESET", "").lower())
        return ImapRemediator(
            _ImapWriteConnection(**params, **kw),
            junk_folder=env.get("PHISHGUARD_IMAP_JUNK_FOLDER") or (preset.junk_folder if preset else "Junk"),
            trash_folder=env.get("PHISHGUARD_IMAP_TRASH_FOLDER") or (preset.trash_folder if preset else "Trash"),
            banner_key=banner_key,
        )
    raise ValueError(f"unknown provider {provider!r}")


__all__ = [
    "GmailRemediator",
    "GraphRemediator",
    "ImapRemediator",
    "MailboxRemediator",
    "NotSupported",
    "TargetMismatch",
    "WriteHttpClient",
    "add_banner",
    "is_bannered",
    "new_http",
    "remediation_handlers",
    "remediator_from_env",
]
