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
MAX_MIME_PARTS = 200  # a real mail has a handful; thousands is a parser DoS
MAX_MIME_DEPTH = 20
_AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.I)
_URL_RE = re.compile(r"https?://[^\s<>\"')]+", re.I)
_AUTH_MAP = {"pass": "pass", "fail": "fail", "softfail": "fail", "permerror": "fail"}


class EmlRejected(ValueError):
    """Input refused before or during parsing (too big / too complex). Maps to HTTP 413/422."""


class EmlTooLarge(EmlRejected):
    pass


class EmlTooComplex(EmlRejected):
    pass


def _check_structure(msg: StdMessage) -> None:
    stack, parts = [(msg, 0)], 0
    while stack:
        part, depth = stack.pop()
        parts += 1
        if depth > MAX_MIME_DEPTH or parts > MAX_MIME_PARTS:
            raise EmlTooComplex(f"MIME tree exceeds depth {MAX_MIME_DEPTH} or {MAX_MIME_PARTS} parts")
        if part.is_multipart():
            stack.extend((p, depth + 1) for p in part.get_payload())


def is_list_mail(msg: StdMessage) -> bool:
    """Mailing-list / bulk mail by RFC 2369/2919 headers or Precedence. Sender-controlled, so callers
    may only use it to soften signals that lists legitimately trigger."""
    if any(msg.get(h) is not None for h in ("List-Id", "List-Unsubscribe", "List-Post", "Mailing-List")):
        return True
    return str(msg.get("Precedence", "")).strip().lower() in ("list", "bulk", "junk")


def _header_anomalies(msg: StdMessage) -> list[str]:
    out = []
    froms = msg.get_all("From", [])
    if len(froms) > 1:
        out.append(f"{len(froms)} From headers")
    if froms and len(getaddresses([str(f) for f in froms])) > 1:
        out.append("From header lists several addresses")
    for h in ("From", "Subject", "Reply-To"):
        v = str(msg.get(h, ""))
        if "\r" in v or "\n" in v:
            out.append(f"line break inside decoded {h} header")
    return out


_HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?![.\d]*[1-9])|opacity\s*:\s*0(?![.\d]*[1-9])"
    r"|max-height\s*:\s*0|color\s*:\s*(#fff(fff)?|white)\b",
    re.I,
)
_VOID = {"br", "img", "hr", "meta", "link", "input", "wbr", "source", "area", "col", "base"}


class _HTMLText(HTMLParser):
    """Visible text, hidden text (CSS-hidden elements) and anchors. Hidden text is a classic
    carrier for instructions aimed at an LLM: the human never sees it, the model does."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.text: list[str] = []
        self.hidden: list[str] = []
        self.links: list[DisplayedLink] = []
        self._href: str | None = None
        self._anchor: list[str] = []
        self._skip = 0
        self._stack: list[tuple[str, bool]] = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag not in _VOID and len(self._stack) < 500:
            hide = "hidden" in a or a.get("aria-hidden") == "true" or bool(_HIDDEN_STYLE.search(a.get("style") or ""))
            self._stack.append((tag, hide))
        if tag in ("script", "style"):
            self._skip += 1
        elif tag == "a":
            self._href = dict(attrs).get("href") or ""
            self._anchor = []
        elif tag in ("br", "p", "div", "tr"):
            self.text.append("\n")

    def handle_endtag(self, tag):
        for i in range(len(self._stack) - 1, -1, -1):
            if self._stack[i][0] == tag:
                del self._stack[i:]
                break
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        elif tag == "a" and self._href is not None:
            text = " ".join("".join(self._anchor).split())
            self.links.append(DisplayedLink(text=text[:512], href=self._href[:2048]))
            self._href = None

    def handle_data(self, data):
        if self._skip:
            return
        if any(h for _, h in self._stack):
            self.hidden.append(data)
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
    try:
        raw = msg.get(name)
    except Exception:  # stdlib header registry crashes on some malformed lists (e.g. stray groups)
        lname = name.lower()
        raw = next((v for k, v in msg.raw_items() if k.lower() == lname), None)
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
        raw = raw.encode("utf-8", "surrogatepass")  # lone surrogates become invalid bytes, not a crash
    if len(raw) > MAX_RAW_BYTES:
        raise EmlTooLarge(f"message is {len(raw)} bytes; limit {MAX_RAW_BYTES}")
    # Cheap pre-check: every multipart needs a boundary parameter.
    if raw.lower().count(b"boundary=") > MAX_MIME_PARTS:
        raise EmlTooComplex("too many MIME boundaries")
    try:
        msg: StdMessage = message_from_bytes(raw, policy=policy.default)  # type: ignore[assignment]
        _check_structure(msg)
        return _to_email(msg, raw, trusted_authserv_id)
    except RecursionError:
        raise EmlTooComplex("MIME structure too deeply nested") from None


def _to_email(msg: StdMessage, raw: bytes, trusted_authserv_id: str | None) -> EmailMessage:

    plain: list[str] = []
    html_text: list[str] = []
    hidden: list[str] = []
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
            hidden.append(" ".join(p.hidden))
            pairs.extend(p.links)

    body = "\n".join(plain) if plain else "\n".join(html_text)
    if plain and html_text:
        # A crafted mail can show one thing in HTML and another in text/plain; read both.
        html_only = "\n".join(html_text)
        if not set(html_only.lower().split()) <= set(body.lower().split()):
            body += "\n[html part]\n" + html_only
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
        hidden_text=" ".join(" ".join(hidden).split())[:5000],
        header_anomalies=[a[:200] for a in _header_anomalies(msg)][:10],
        list_mail=is_list_mail(msg),
    )
