"""Microsoft 365 / Outlook.com via Microsoft Graph (Mail.Read; MIME from /messages/{id}/$value).

Cursor = the `@odata.deltaLink` URL of a messages delta query on one folder. A fresh cursor is
made with `$filter=receivedDateTime ge <now>`, so the first round returns no backlog. Graph answers
410 Gone (or a `syncStateNotFound` error) when a delta token expires; the connector restarts from
now and returns the most recent page. `Prefer: IdType="ImmutableId"` keeps a message's id stable
when remediation moves it to another folder, so the seen-set still recognizes it.

Delegated tokens use `/me`; app-only tokens must name the mailbox (`/users/{upn}`).
"""

from __future__ import annotations

import re
import time
from urllib.parse import quote, urlsplit

from ..readonly.eml import MAX_RAW_BYTES, EmlTooLarge
from .base import CursorExpired, MailboxConnector, MalformedMessage, MessageRef, ensure_read_only
from .http import HttpClient, HttpError, ResponseTooLarge, utc_iso
from .oauth import GRAPH_WRITE_SCOPES
from .secrets import get_logger

log = get_logger(__name__)

GRAPH = "https://graph.microsoft.com/v1.0"
AUTH_HOSTS = frozenset({"graph.microsoft.com"})
_FOLDER_RE = re.compile(r"^[A-Za-z0-9=_+/-]{1,256}$")
_ID_RE = re.compile(r"^[A-Za-z0-9=_+/-]{1,512}$")
_MAILBOX_RE = re.compile(r"^[^\s/?#]{1,320}$")


class GraphConnector(MailboxConnector):
    provider = "graph"

    def __init__(
        self,
        http: HttpClient,
        mailbox: str | None = None,
        folder: str = "inbox",
        page_size: int = 50,
        max_list: int = 5000,
        allow_overprivileged: bool = False,
        clock=time.time,
    ):
        if mailbox is not None and not _MAILBOX_RE.match(mailbox):
            raise ValueError("invalid mailbox (expected a UPN or object id)")
        if not _FOLDER_RE.match(folder):
            raise ValueError("invalid folder id")
        self.http = http
        self.mailbox = mailbox
        self.folder = folder
        self.page_size = max(1, min(page_size, 100))
        self.max_list = max_list
        self.allow_overprivileged = allow_overprivileged
        self._clock = clock
        self._checked = False
        self.base = f"{GRAPH}/users/{quote(mailbox, safe='@.')}" if mailbox else f"{GRAPH}/me"
        self._headers = {"Prefer": f'IdType="ImmutableId", odata.maxpagesize={self.page_size}'}

    @property
    def mailbox_key(self) -> str:
        return f"graph:{(self.mailbox or 'me').lower()}/{self.folder}"

    def _get(self, url: str, params: dict | None = None) -> dict:
        if not url.startswith(GRAPH + "/"):
            raise CursorExpired("refusing a Graph paging/delta link outside graph.microsoft.com")
        data = self.http.get_json(url, params=params, headers=self._headers)
        self._check_scopes()
        return data

    def _check_scopes(self) -> None:
        if not self._checked:
            ensure_read_only(
                "graph", getattr(self.http.auth, "granted_scopes", None), GRAPH_WRITE_SCOPES, self.allow_overprivileged
            )
            self._checked = True

    def _folder_url(self) -> str:
        return f"{self.base}/mailFolders/{quote(self.folder, safe='')}/messages"

    def _delta(self, url: str, params: dict | None) -> tuple[list[MessageRef], str]:
        seen: dict[str, None] = {}
        while True:
            page = self._get(url, params)
            params = None  # paging links carry their own query
            for m in page.get("value") or []:
                mid = str(m.get("id", ""))
                if "@removed" not in m and _ID_RE.match(mid):
                    seen.setdefault(mid)
            nxt = page.get("@odata.nextLink")
            if nxt:
                if len(seen) >= self.max_list:
                    log.warning("Graph backlog exceeds %d messages; the rest are skipped this round", self.max_list)
                    # finishing the delta round is the only way to get a deltaLink; keep paging without collecting
                url = str(nxt)
                continue
            delta = page.get("@odata.deltaLink")
            if not delta:
                raise MalformedMessage("Graph delta round ended without a deltaLink")
            return [MessageRef(i) for i in list(seen)[: self.max_list]], str(delta)

    def initial_cursor(self) -> str:
        since = utc_iso(self._clock())
        _, delta = self._delta(
            self._folder_url() + "/delta",
            {"$select": "id,receivedDateTime", "$filter": f"receivedDateTime ge {since}"},
        )
        return delta

    def list_new(self, cursor: str | None) -> tuple[list[MessageRef], str]:
        if cursor is None:
            return [], self.initial_cursor()
        try:
            return self._delta(cursor, None)
        except (HttpError, CursorExpired) as e:
            expired = (
                isinstance(e, CursorExpired) or e.status == 410 or e.code in ("syncStateNotFound", "resyncRequired")
            )
            if not expired:
                raise
            log.warning("Graph delta token expired; restarting from now and rescanning the latest page")
            fresh = self.initial_cursor()
            return list(reversed(self.list_recent(self.page_size))), fresh

    def list_recent(self, n: int) -> list[MessageRef]:
        out: list[MessageRef] = []
        url: str | None = self._folder_url()
        params: dict | None = {"$top": min(n, self.page_size), "$select": "id", "$orderby": "receivedDateTime desc"}
        while url and len(out) < n:
            page = self._get(url, params)
            params = None
            out += [MessageRef(m["id"]) for m in page.get("value") or [] if _ID_RE.match(str(m.get("id", "")))]
            url = page.get("@odata.nextLink")
        return out[:n]

    def fetch_raw(self, ref: MessageRef) -> bytes:
        if not _ID_RE.match(ref.provider_id):
            raise MalformedMessage("invalid Graph message id")
        try:
            raw = self.http.get_bytes(
                f"{self.base}/messages/{quote(ref.provider_id, safe='')}/$value", MAX_RAW_BYTES, headers=self._headers
            )
        except ResponseTooLarge:
            raise EmlTooLarge(f"Graph message exceeds {MAX_RAW_BYTES} bytes") from None
        self._check_scopes()
        if not raw:
            raise MalformedMessage("Graph returned an empty MIME body")
        return raw

    def subscribe(self, notification_url: str, client_state: str, minutes: int = 4200) -> dict:
        """Create a change-notification subscription for new mail in the folder (Mail.Read suffices).

        Mail subscriptions last at most 10080 minutes; the worker creates a new one before expiry.
        """
        parts = urlsplit(notification_url)
        if parts.scheme != "https" or not parts.hostname:
            raise ValueError("Graph notification URLs must be https")
        if not 16 <= len(client_state) <= 128:
            raise ValueError("clientState must be 16-128 characters")
        resource = (f"users/{self.mailbox}" if self.mailbox else "me") + f"/mailFolders('{self.folder}')/messages"
        data = self.http.post_json(
            f"{GRAPH}/subscriptions",
            {
                "changeType": "created",
                "notificationUrl": notification_url,
                "resource": resource,
                "expirationDateTime": utc_iso(self._clock() + min(minutes, 10080) * 60),
                "clientState": client_state,
            },
        )
        return {"id": str(data.get("id", "")), "expirationDateTime": str(data.get("expirationDateTime", ""))}
