"""Gmail / Google Workspace connector (Gmail API v1, scope gmail.readonly, messages fetched as format=raw).

Incremental sync uses Gmail's historyId: the first scan lists the newest N inbox messages and stores the
profile's current historyId; later scans call users.history.list(startHistoryId, messageAdded, INBOX).
If Google has expired that history (HTTP 404, typically after about a week), we fall back to listing the
inbox again; the seen-set makes that re-list harmless.
"""

from __future__ import annotations

import base64
from urllib.parse import quote, urlencode

from .base import Batch, Cursor, MailboxConnector, RawMessage, Rejected
from .http import ProviderError, RetryingClient

API_HOST = "gmail.googleapis.com"
API = f"https://{API_HOST}/gmail/v1/users"
PAGE = 100


class GmailConnector(MailboxConnector):
    provider = "gmail"

    def __init__(self, http: RetryingClient, mailbox_name: str, user: str = "me", query: str = "in:inbox"):
        super().__init__(mailbox_name)
        self.http, self.user, self.query = http, user, query
        self.base = f"{API}/{quote(user, safe='@.')}"

    def profile(self) -> dict:
        return self.http.get_json(f"{self.base}/profile")

    def _list_ids(self, limit: int) -> list[str]:
        ids: list[str] = []
        token = None
        while len(ids) < limit:
            q = {"q": self.query, "maxResults": min(PAGE, limit - len(ids))}
            if token:
                q["pageToken"] = token
            page = self.http.get_json(f"{self.base}/messages?{urlencode(q)}")
            ids += [m["id"] for m in page.get("messages", [])]
            token = page.get("nextPageToken")
            if not token:
                break
        return ids[:limit]

    def _history(self, start: str, limit: int) -> tuple[list[str], str, bool]:
        """(ids oldest-first, latest historyId, drained)."""
        ids: list[str] = []
        token, latest = None, start
        while True:
            q = {"startHistoryId": start, "historyTypes": "messageAdded", "labelId": "INBOX", "maxResults": 500}
            if token:
                q["pageToken"] = token
            page = self.http.get_json(f"{self.base}/history?{urlencode(q)}")
            latest = page.get("historyId", latest)
            for h in page.get("history", []):
                for added in h.get("messagesAdded", []):
                    mid = added["message"]["id"]
                    if mid not in ids:
                        ids.append(mid)
            token = page.get("nextPageToken")
            if not token or len(ids) > limit:
                return ids, latest, not token and len(ids) <= limit

    def fetch_raw(self, mid: str) -> RawMessage | Rejected:
        meta = self.http.get_json(f"{self.base}/messages/{quote(mid)}?format=minimal")
        size = int(meta.get("sizeEstimate") or 0)
        if size > self.max_bytes:  # don't download what parse_eml would refuse anyway
            return Rejected(mid, "too_large", size)
        body = self.http.get_json(f"{self.base}/messages/{quote(mid)}?format=raw")
        raw = base64.urlsafe_b64decode(body["raw"] + "=" * (-len(body["raw"]) % 4))
        if len(raw) > self.max_bytes:
            return Rejected(mid, "too_large", len(raw))
        return RawMessage(mid, raw)

    def list_new_messages(self, cursor: Cursor | None, limit: int = 50) -> Batch:
        batch = Batch()
        start = (cursor or {}).get("history_id")
        if start:
            try:
                ids, latest, drained = self._history(str(start), limit)
                # a partial page: keep the old cursor; the next run re-reads and the seen-set skips repeats
                batch.cursor = {"history_id": latest if drained else start}
                ids = ids[:limit]
            except ProviderError as e:
                if e.status != 404:
                    raise
                batch.notes.append("history expired; re-listed the inbox")
                start = None
        if not start:
            hid = self.profile()["historyId"]  # read BEFORE listing so nothing arriving meanwhile is skipped
            ids = list(reversed(self._list_ids(limit)))  # oldest first
            batch.cursor = {"history_id": str(hid)}
        for mid in ids:
            item = self.fetch_raw(mid)
            (batch.messages if isinstance(item, RawMessage) else batch.rejected).append(item)
        return batch

    def watch(self, topic: str) -> dict:
        """Start Gmail push notifications to a Pub/Sub topic (renew at least every 7 days)."""
        return self.http.post_json(f"{self.base}/watch", {"topicName": topic, "labelIds": ["INBOX"]})
