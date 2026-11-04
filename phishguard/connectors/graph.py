"""Microsoft 365 / Outlook.com connector (Microsoft Graph v1.0, Mail.Read, MIME via /messages/{id}/$value).

Incremental sync uses the inbox's message delta query: the cursor is the @odata.deltaLink. The first scan
lists the newest N messages, then runs an initial delta round (restricted to recent mail) to obtain a
deltaLink. A 410 (sync state expired) resets to a fresh initial scan.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from urllib.parse import quote, urlencode

from .base import Batch, Cursor, MailboxConnector, RawMessage, Rejected
from .http import ProviderError, RetryingClient

GRAPH_HOST = "graph.microsoft.com"
GRAPH = f"https://{GRAPH_HOST}/v1.0"


class GraphConnector(MailboxConnector):
    provider = "graph"

    def __init__(
        self,
        http: RetryingClient,
        mailbox_name: str,
        user: str = "me",
        folder: str = "inbox",
        initial_window_days: int = 7,
        clock=lambda: datetime.now(UTC),
    ):
        super().__init__(mailbox_name)
        self.http, self.folder, self.window, self.clock = http, folder, initial_window_days, clock
        # "me" for delegated tokens; a user id or UPN for application tokens (client credentials)
        self.base = f"{GRAPH}/me" if user == "me" else f"{GRAPH}/users/{quote(user, safe='@.')}"

    def _pages(self, url: str, limit: int | None = None):
        """Yield (items, next_link, delta_link) page by page, following server-provided links."""
        while url:
            page = self.http.get_json(url, headers={"Prefer": "odata.maxpagesize=100"})
            yield page.get("value", []), page.get("@odata.nextLink"), page.get("@odata.deltaLink")
            url = page.get("@odata.nextLink")

    def _newest_ids(self, limit: int) -> list[str]:
        q = {"$top": min(limit, 100), "$orderby": "receivedDateTime desc", "$select": "id"}
        ids: list[str] = []
        for items, _, _ in self._pages(f"{self.base}/mailFolders/{self.folder}/messages?{urlencode(q)}"):
            ids += [m["id"] for m in items]
            if len(ids) >= limit:
                break
        return ids[:limit]

    def _delta(self, url: str, limit: int) -> tuple[list[str], str | None]:
        """(ids, deltaLink or None if we stopped early)."""
        ids: list[str] = []
        for items, _next, delta in self._pages(url):
            ids += [m["id"] for m in items if "@removed" not in m and m["id"] not in ids]
            if delta:
                return ids, delta
            if len(ids) > limit:
                return ids, None
        return ids, None

    def _initial_delta_url(self) -> str:
        since = (self.clock() - timedelta(days=self.window)).strftime("%Y-%m-%dT%H:%M:%SZ")
        q = {"$select": "id", "$filter": f"receivedDateTime ge {since}"}
        return f"{self.base}/mailFolders/{self.folder}/messages/delta?{urlencode(q)}"

    def fetch_raw(self, mid: str) -> RawMessage | Rejected:
        raw = self.http.get_bytes_capped(f"{self.base}/messages/{quote(mid, safe='')}/$value", self.max_bytes)
        return Rejected(mid, "too_large") if raw is None else RawMessage(mid, raw)

    def list_new_messages(self, cursor: Cursor | None, limit: int = 50) -> Batch:
        batch = Batch()
        link = (cursor or {}).get("delta_link")
        ids: list[str] = []
        if link:
            try:
                ids, delta = self._delta(link, limit)
                batch.cursor = {"delta_link": delta or link}
                ids = ids[:limit]
            except ProviderError as e:
                if e.status != 410:
                    raise
                batch.notes.append("delta token expired; re-listed the inbox")
                link = None
        if not link:
            _, delta = self._delta(self._initial_delta_url(), 10**9)  # establish the delta baseline first
            ids = list(reversed(self._newest_ids(limit)))
            batch.cursor = {"delta_link": delta} if delta else {}
        for mid in ids:
            item = self.fetch_raw(mid)
            (batch.messages if isinstance(item, RawMessage) else batch.rejected).append(item)
        return batch

    def subscribe(self, notification_url: str, client_state: str, minutes: int = 4200) -> dict:
        """Create a change-notification subscription for new inbox mail (renew before it expires)."""
        exp = (self.clock() + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")
        owner = "me" if self.base.endswith("/me") else self.base.split("/v1.0/")[1]
        resource = f"{owner}/mailFolders('{self.folder}')/messages"
        body = {
            "changeType": "created",
            "notificationUrl": notification_url,
            "resource": resource,
            "expirationDateTime": exp,
            "clientState": client_state,
        }
        return self.http.post_json(f"{GRAPH}/subscriptions", body)
