"""RFC 822 / .eml parser (stdlib only). Turns raw mail into an EmailMessage. Read-only, pure.

Security notes:
- Raw size is capped before parsing (MAX_RAW_BYTES) so a huge upload can't exhaust memory.
- Only ONE Authentication-Results header is trusted: the one stamped by our own MTA
  (matching `trusted_authserv_id`), or, if none is configured, the topmost one (the last hop
  added it). Headers lower in the stack can be forged by the sender.
- HTML is parsed for text and anchors only; nothing is rendered or fetched.
"""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from email import message_from_bytes, policy
from email.message import EmailMessage as StdMessage
from email.utils import getaddresses, parsedate_to_datetime
from html.parser import HTMLParser

from ..models import Attachment, DisplayedLink, EmailMessage

MAX_RAW_BYTES = 2_000_000
_AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.I)
_URL_RE = re.compile(r"https?://[^\s<>\"')]+", re.I)
_AUTH_MAP = {"pass": "pass", "fail": "fail", "softfail": "fail", "permerror": "fail"}


class EmlTooLarge(ValueError):
    pass


class _HTMLText(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.text: list[str] = []
        self.links: list[DisplayedLink] = []
        self._href: str | None = None
        self._anchor: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1
        elif tag == "a":
            self._href = dict(attrs).get("href") or ""
            self._anchor = []
        elif tag in ("br", "p", "div", "tr"):
            self.text.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        elif tag == "a" and self._href is not None:
            text = " ".join("".join(self._anchor).split())
            self.links.append(DisplayedLink(text=text[:512], href=self._href[:2048]))
            self._href = None

    def handle_data(self, data):
        if self._skip:
            return
        self.text.append(data)
        if self._href is not None:
            self._anchor.append(data)


def parse_auth_results(msg: StdMessage, trusted_authserv_id: str | None = None) -> dict[str, str]:
    headers = [str(h) for h in msg.get_all("Authentication-Results", [])]
    chosen = None
    if trusted_authserv_id:
        for h in headers:
            if h.split(";", 1)[0].strip().lower() == trusted_authserv_id.lower():
                chosen = h
                break
    elif headers:
        chosen = headers[0]
    out = {"spf": "none", "dkim": "none", "dmarc": "none"}
    for mech, res in _AUTH_RE.findall(chosen or ""):
        mech = mech.lower()
        if out[mech] == "none" or _AUTH_MAP.get(res.lower()) == "fail":  # any failing signature wins
            out[mech] = _AUTH_MAP.get(res.lower(), "none")
    return out


def _addr(msg: StdMessage, name: str) -> tuple[str, str]:
    raw = msg.get(name)
    if raw is None:
        return "", ""
    pairs = getaddresses([str(raw)])
    return pairs[0] if pairs else ("", "")


def _date(msg: StdMessage) -> datetime:
    try:
        d = parsedate_to_datetime(str(msg.get("Date", "")))
        return d if d.tzinfo else d.replace(tzinfo=UTC)
    except (TypeError, ValueError, IndexError):
        return datetime.now(UTC)


def parse_eml(raw: bytes | str, trusted_authserv_id: str | None = None) -> EmailMessage:
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "surrogateescape")
    if len(raw) > MAX_RAW_BYTES:
        raise EmlTooLarge(f"message is {len(raw)} bytes; limit {MAX_RAW_BYTES}")
    msg: StdMessage = message_from_bytes(raw, policy=policy.default)  # type: ignore[assignment]

    plain: list[str] = []
    html_text: list[str] = []
    pairs: list[DisplayedLink] = []
    atts: list[Attachment] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        fname = part.get_filename()
        if fname or part.get_content_disposition() == "attachment":
            payload = part.get_payload(decode=True) or b""
            atts.append(Attachment(filename=(fname or "")[:256], content_type=ctype[:128], size=len(payload)))
            continue
        if ctype not in ("text/plain", "text/html"):
            continue
        try:
            content = part.get_content()
        except (LookupError, ValueError):
            content = (part.get_payload(decode=True) or b"").decode("utf-8", "replace")
        if ctype == "text/plain":
            plain.append(content)
        else:
            p = _HTMLText()
            p.feed(content)
            html_text.append("".join(p.text))
            pairs.extend(p.links)

    body = "\n".join(plain) if plain else "\n".join(html_text)
    links = [lp.href for lp in pairs if lp.href.lower().startswith(("http://", "https://"))]
    for u in _URL_RE.findall("\n".join(plain)):
        if u not in links:
            links.append(u)

    name, sender = _addr(msg, "From")
    _, reply_to = _addr(msg, "Reply-To")
    _, ret = _addr(msg, "Return-Path")
    auth = parse_auth_results(msg, trusted_authserv_id)
    mid = str(msg.get("Message-ID", "")).strip(" <>") or hashlib.sha256(raw).hexdigest()[:32]
    return EmailMessage(
        id=mid[:128],
        timestamp=_date(msg),
        sender_name=name[:256],
        sender_email=sender[:320],
        reply_to=reply_to[:320] or None,
        return_path=ret[:320] or None,
        recipient=_addr(msg, "To")[1][:320],
        subject=str(msg.get("Subject", ""))[:1000],
        body=body[:20000],
        links=links[:100],
        attachments=[a.filename for a in atts][:50],
        attachment_meta=atts[:50],
        link_pairs=pairs[:100],
        spf=auth["spf"],
        dkim=auth["dkim"],
        dmarc=auth["dmarc"],
    )
