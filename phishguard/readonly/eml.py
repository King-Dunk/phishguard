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


_VOID = {"br", "img", "hr", "meta", "link", "input", "wbr", "source", "area", "col", "base"}
_ZERO = re.compile(r"^-?0*\.?0*(px|pt|em|rem|%)?$")
_WHITE = re.compile(
    r"^(#fff(fff)?|white|rgb\(\s*255\s*,\s*255\s*,\s*255\s*\)|rgba\(\s*255\s*,\s*255\s*,\s*255\s*,\s*1(\.0*)?\s*\))$"
)
_NO_BG = {"", "none", "transparent", "inherit", "initial", "unset"}
# Invisible padding that mail templates put after the preheader so the inbox preview stops there.
_FILLER = re.compile("[͏­​-‍⁠﻿ ]+")
PREHEADER_MAX = 200  # hidden text before any visible text, up to this many characters, is a preview line


def _style(s: str) -> dict[str, str]:
    """Inline CSS declarations, lower-cased, last one wins (as in a browser), without !important."""
    out: dict[str, str] = {}
    for decl in s.split(";"):
        k, sep, v = decl.partition(":")
        if sep:
            out[k.strip().lower()] = v.replace("!important", "").strip().lower()
    return out


class _Vis:
    """Computed visibility of one element, inherited the way CSS inherits it.

    display:none, opacity:0, the `hidden` attribute and max-height:0 with overflow:hidden hide a subtree for
    good. visibility, font-size and color are inherited but a descendant can set them back, so a wrapper with
    font-size:0 (a common email layout trick) does not hide children that set font-size:14px. White text only
    counts as hidden when no ancestor sets a background: white on a coloured button or banner is visible.
    `aria-hidden` hides from screen readers, not from the eye, so it is ignored."""

    __slots__ = ("gone", "vis_hidden", "zero_font", "white", "background")

    def __init__(self, gone=False, vis_hidden=False, zero_font=False, white=False, background=False):
        self.gone, self.vis_hidden, self.zero_font, self.white, self.background = (
            gone,
            vis_hidden,
            zero_font,
            white,
            background,
        )

    def child(self, attrs: dict) -> _Vis:
        st = _style(attrs.get("style") or "")
        v = _Vis(self.gone, self.vis_hidden, self.zero_font, self.white, self.background)
        if (
            "hidden" in attrs
            or st.get("display") == "none"
            or _ZERO.match(st.get("opacity", "1"))
            or (_ZERO.match(st.get("max-height", "none")) and "hidden" in st.get("overflow", ""))
        ):
            v.gone = True
        if "visibility" in st:
            v.vis_hidden = st["visibility"].startswith(("hidden", "collapse"))
        if "font-size" in st:
            v.zero_font = bool(_ZERO.match(st["font-size"]))
        if "color" in st:
            v.white = bool(_WHITE.match(st["color"]))
        bg = (attrs.get("bgcolor") or "").strip().lower()
        bg_css = st.get("background-color", st.get("background", ""))
        if attrs.get("background") or "url(" in st.get("background-image", "") + bg_css:
            v.background = True  # a background picture: assume the text sits on it
        elif bg or bg_css not in _NO_BG:
            v.background = not _WHITE.match(bg or bg_css.split()[0])
        return v

    @property
    def hidden(self) -> bool:
        return self.gone or self.vis_hidden or self.zero_font or (self.white and not self.background)


_ROOT = _Vis()


class _HTMLText(HTMLParser):
    """Visible text, hidden text (CSS-hidden elements) and anchors. Hidden text is a classic
    carrier for instructions aimed at an LLM: the human never sees it, the model does."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.text: list[str] = []
        self.hidden: list[str] = []
        self.preheader: list[str] = []  # hidden text before any visible text (inbox preview line)
        self._seen_visible = False
        self.links: list[DisplayedLink] = []
        self.images = 0  # visible <img>, not counting 1-2 px tracking pixels
        self.linked_images = 0  # of those, inside an <a href="http...">
        self._href: str | None = None
        self._anchor: list[str] = []
        self._skip = 0
        self._stack: list[tuple[str, _Vis]] = []

    def _vis(self) -> _Vis:
        return self._stack[-1][1] if self._stack else _ROOT

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag not in _VOID and len(self._stack) < 500:
            self._stack.append((tag, self._vis().child(a)))
        if tag in ("script", "style"):
            self._skip += 1
        elif tag == "a":
            self._href = dict(attrs).get("href") or ""
            self._anchor = []
        elif tag in ("br", "p", "div", "tr"):
            self.text.append("\n")
        elif tag == "img" and not self._skip and not _tiny(a) and not self._vis().child(a).hidden:
            self.images += 1
            if self._href is not None and self._href.lower().startswith(("http://", "https://")):
                self.linked_images += 1

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
        if self._vis().hidden:
            if not self._seen_visible and len("".join(self.preheader)) + len(data) <= PREHEADER_MAX * 4:
                self.preheader.append(data)
            else:
                self.hidden.append(data)
            return
        if data.strip():
            self._seen_visible = True
        self.text.append(data)
        if self._href is not None:
            self._anchor.append(data)


def _norm(s: str) -> str:
    return " ".join(_FILLER.sub(" ", s).split()).lower()


def _tiny(attrs: dict) -> bool:
    """1-2 px images are tracking pixels / spacers, not content the reader is meant to look at."""
    for k in ("width", "height"):
        v = str(attrs.get(k) or "").strip().lower().removesuffix("px")
        if v.isdigit() and int(v) <= 2:
            return True
    return False


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
    # Parenthesised comments are free text: Gmail puts the ARC chain's *claimed* results there
    # ("arc=pass (i=1 spf=pass dkim=pass dmarc=pass)"), which are not this server's verdicts.
    text = _strip_comments(chosen or "")
    dkim_seen: set[str] = set()
    for mech, res in _AUTH_RE.findall(text):
        mech, val = mech.lower(), _AUTH_MAP.get(res.lower(), "none")
        if mech == "dkim":
            dkim_seen.add(val)
        elif out[mech] == "none" or val == "fail":  # one SPF/DMARC result; a failing one wins
            out[mech] = val
    # DKIM passes if any signature verifies (RFC 6376): an extra broken signature, e.g. from a mailing
    # service re-signing, is not evidence. Whose signature counts for the From domain is DMARC's job.
    out["dkim"] = "pass" if "pass" in dkim_seen else "fail" if "fail" in dkim_seen else "none"
    return out


def _strip_comments(h: str) -> str:
    out, depth = [], 0
    for ch in h[:8000]:
        if ch == "(":
            depth += 1
        elif ch == ")" and depth:
            depth -= 1
        elif not depth:
            out.append(ch)
    return "".join(out)


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
    preheaders: list[str] = []
    pairs: list[DisplayedLink] = []
    atts: list[Attachment] = []
    images = linked_images = 0
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
            visible = "".join(p.text)
            html_text.append(visible)
            pre = _norm(" ".join(p.preheader))
            if len(pre) <= PREHEADER_MAX:
                preheaders.append(pre)
                chunks = p.hidden
            else:  # too long for a preview line: it is hidden text like any other
                chunks = [pre, *p.hidden]
            # Responsive templates hide the mobile or desktop copy of what is shown: not hidden content.
            seen = _norm(visible)
            hidden.append(" ".join(c for c in map(_norm, chunks) if c and c not in seen))
            pairs.extend(p.links)
            images += p.images
            linked_images += p.linked_images

    body = "\n".join(plain) if plain else "\n".join(html_text)
    if plain and html_text:
        # A crafted mail can show one thing in HTML and another in text/plain; read both.
        html_only = "\n".join(html_text)
        if not set(html_only.lower().split()) <= set(body.lower().split()):
            body += "\n[html part]\n" + html_only
    links = [lp.href for lp in pairs if lp.href.lower().startswith(("http://", "https://"))]
    for u in _URL_RE.findall("\n".join(plain)):
        u = u[:2048]  # same cap as HTML hrefs; real tracking links can exceed the model's Url limit
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
        preheader_text=" ".join(" ".join(preheaders).split())[:1000],
        header_anomalies=[a[:200] for a in _header_anomalies(msg)][:10],
        list_mail=is_list_mail(msg),
        inline_images=min(images, 10000),
        linked_images=min(linked_images, 10000),
    )
