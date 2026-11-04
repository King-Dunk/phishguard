"""Gmail / Google Workspace via the Gmail REST API (scope gmail.readonly, messages.get format=raw).

Cursor = Gmail `historyId`. Incremental listing uses users.history.list(historyTypes=messageAdded,
labelId=INBOX). If the history id is too old Gmail answers 404; the connector then restarts from the
current profile historyId and returns the most recent page, and the scanner's seen-set skips
anything scanned before.
"""

from __future__ import annotations

import base64
import binascii
import re
from urllib.parse import quote

from ..readonly.eml import MAX_RAW_BYTES, EmlTooLarge
from .base import CursorExpired, MailboxConnector, MalformedMessage, MessageRef, ensure_read_only
from .http import HttpClient, HttpError, ResponseTooLarge
from .oauth import GMAIL_WRITE_SCOPES
from .secrets import get_logger

log = get_logger(__name__)

API = "https://gmail.googleapis.com/gmail/v1/users"
AUTH_HOSTS = frozenset({"gmail.googleapis.com"})
_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,256}$")
_HISTORY_RE = re.compile(r"^\d{1,20}$")
# base64url inflates by 4/3; allow for the JSON envelope around `raw` too
RAW_RESPONSE_LIMIT = MAX_RAW_BYTES * 4 // 3 + 64_000


class GmailConnector(MailboxConnector):
    provider = "gmail"

    def __init__(
        self,
        http: HttpClient,
        user: str = "me",
        label_id: str = "INBOX",
        page_size: int = 100,
        max_list: int = 5000,
        allow_overprivileged: bool = False,
    ):
        self.http = http
        self.user = user
        self.label_id = label_id
        self.page_size = max(1, min(page_size, 500))
        self.max_list = max_list
        self.allow_overprivileged = allow_overprivileged
        self._checked = False
        self._base = f"{API}/{quote(user, safe='@.')}"

    @property
    def mailbox_key(self) -> str:
        return f"gmail:{self.user.lower()}/{self.label_id}"

    def _get(self, path: str, params: dict | None = None) -> dict:
        data = self.http.get_json(self._base + path, params=params)
        self._check_scopes()
        return data

    def _check_scopes(self) -> None:
        if not self._checked:
            ensure_read_only(
                "gmail", getattr(self.http.auth, "granted_scopes", None), GMAIL_WRITE_SCOPES, self.allow_overprivileged
            )
            self._checked = True

    def initial_cursor(self) -> str:
        hid = str(self._get("/profile").get("historyId", ""))
        if not _HISTORY_RE.match(hid):
            raise MalformedMessage("profile returned no historyId")
        return hid

    def list_recent(self, n: int) -> list[MessageRef]:
        out: list[MessageRef] = []
        token = None
        while len(out) < n:
            params = {"maxResults": min(self.page_size, n - len(out)), "labelIds": self.label_id}
            if token:
                params["pageToken"] = token
            page = self._get("/messages", params)
            out += [MessageRef(m["id"]) for m in page.get("messages") or [] if _ID_RE.match(str(m.get("id", "")))]
            token = page.get("nextPageToken")
            if not token:
                break
        return out[:n]

    def list_new(self, cursor: str | None) -> tuple[list[MessageRef], str]:
        if cursor is None:
            return [], self.initial_cursor()
        if not _HISTORY_RE.match(cursor):
            raise CursorExpired("stored Gmail cursor is not a history id")
        try:
            return self._history(cursor)
        except HttpError as e:
            if e.status != 404:
                raise
            log.warning("Gmail history id expired; restarting from now and rescanning the latest page")
            fresh = self.initial_cursor()
            return list(reversed(self.list_recent(self.page_size))), fresh

    def _history(self, start: str) -> tuple[list[MessageRef], str]:
        seen: dict[str, None] = {}
        token = None
        latest = start
        while True:
            params = {
                "startHistoryId": start,
                "historyTypes": "messageAdded",
                "labelId": self.label_id,
                "maxResults": self.page_size,
            }
            if token:
                params["pageToken"] = token
            page = self._get("/history", params)
            for h in page.get("history") or []:
                for added in h.get("messagesAdded") or []:
                    m = added.get("message") or {}
                    mid = str(m.get("id", ""))
                    labels = set(m.get("labelIds") or [])
                    if _ID_RE.match(mid) and not labels & {"DRAFT", "SENT"}:
                        seen.setdefault(mid)
            if _HISTORY_RE.match(str(page.get("historyId", ""))):
                latest = str(page["historyId"])
            token = page.get("nextPageToken")
            if not token:
                break
            if len(seen) >= self.max_list:
                log.warning("Gmail backlog exceeds %d messages; the rest are skipped this round", self.max_list)
                break
        return [MessageRef(i) for i in seen], latest

    def fetch_raw(self, ref: MessageRef) -> bytes:
        if not _ID_RE.match(ref.provider_id):
            raise MalformedMessage("invalid Gmail message id")
        try:
            body = self.http.get_bytes(
                f"{self._base}/messages/{ref.provider_id}", RAW_RESPONSE_LIMIT, params={"format": "raw"}
            )
        except ResponseTooLarge:
            raise EmlTooLarge(f"Gmail message {ref.provider_id} exceeds {MAX_RAW_BYTES} bytes") from None
        self._check_scopes()
        import json

        try:
            raw_b64 = json.loads(body).get("raw", "")
            raw = base64.urlsafe_b64decode(raw_b64 + "=" * (-len(raw_b64) % 4))
        except (ValueError, binascii.Error, AttributeError):
            raise MalformedMessage(f"Gmail message {ref.provider_id}: undecodable raw payload") from None
        if not raw:
            raise MalformedMessage(f"Gmail message {ref.provider_id}: empty raw payload")
        if len(raw) > MAX_RAW_BYTES:
            raise EmlTooLarge(f"Gmail message {ref.provider_id} is {len(raw)} bytes; limit {MAX_RAW_BYTES}")
        return raw

    def watch(self, topic_name: str) -> dict:
        """Ask Gmail to publish INBOX changes to a Pub/Sub topic (works with gmail.readonly). Renew daily."""
        if not re.match(r"^projects/[a-z][a-z0-9-]{4,29}/topics/[A-Za-z][\w.~+%-]{2,254}$", topic_name):
            raise ValueError("topic must look like projects/<project>/topics/<name>")
        data = self.http.post_json(f"{self._base}/watch", {"topicName": topic_name, "labelIds": [self.label_id]})
        self._check_scopes()
        return {"historyId": str(data.get("historyId", "")), "expiration": str(data.get("expiration", ""))}
