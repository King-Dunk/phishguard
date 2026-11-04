"""Deterministic phishing feature extraction and scoring (read-only, pure functions)."""

from __future__ import annotations

import base64
import ipaddress
import math
import pathlib
import re
import unicodedata
from dataclasses import asdict, dataclass, field, replace
from difflib import SequenceMatcher
from urllib.parse import urlparse

import yaml

from ..models import EmailMessage

WEIGHTS_PATH = pathlib.Path(__file__).with_name("weights.yaml")


@dataclass(frozen=True)
class WeightTable:
    weights: dict[str, float]
    brands: dict[str, tuple[str, ...]]

    def get(self, name: str) -> float:
        if name not in self.weights:
            raise KeyError(f"feature {name!r} has no weight in weights.yaml")
        return self.weights[name]


def load_weights(path: str | pathlib.Path | None = None, overrides: dict[str, float] | None = None) -> WeightTable:
    """Read and validate a weight table. `overrides` replaces individual weights (used by calibration)."""
    raw = yaml.safe_load(pathlib.Path(path or WEIGHTS_PATH).read_text(encoding="utf-8"))
    weights = {str(k): float(v) for k, v in raw["weights"].items()}
    weights.update(overrides or {})
    for k, v in weights.items():
        if not 0.0 <= v <= 0.95:
            raise ValueError(f"weight {k}={v} outside [0, 0.95]")
    brands = {str(b).lower(): tuple(str(d).lower() for d in ds) for b, ds in (raw.get("brands") or {}).items()}
    return WeightTable(weights, brands)


DEFAULT_WEIGHTS = load_weights()
WEIGHTS = DEFAULT_WEIGHTS.weights  # read-only view kept for callers of the old constant


FREE_MAIL = {"gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "163.com", "qq.com", "proton.me"}
SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "cutt.ly",
    "rb.gy",
    "ow.ly",
    "buff.ly",
    "tiny.cc",
    "shorturl.at",
    "rebrand.ly",
    "t.ly",
    "s.id",
    "v.gd",
    "x.co",
    "lnkd.in",
}
DEFAULT_SAFE_LINK_DOMAINS = ("google.com", "github.com", "zoom.us", "microsoft.com", "notion.so")

# Keyword features are split by context (DESIGN Q64). The specific sub-pattern of each is checked
# first and scored under its own weight key; the feature *name* stays the same for API callers.
URGENCY_DEADLINE = re.compile(r"\b(within \d+ (hours?|hrs?)|final notice|act now|time[- ]sensitive|overdue)\b|逾期")
URGENCY_WORD = re.compile(r"\b(urgent|immediately|asap|right away)\b|紧急|立即|马上|尽快")
URGENCY = re.compile(f"{URGENCY_DEADLINE.pattern}|{URGENCY_WORD.pattern}")
# Money destinations (where funds go) vs words that are everywhere in normal business/tech mail.
PAYMENT_ACCOUNT = re.compile(r"\b(bank account|iban|swift|gift cards?|bitcoin|routing number)\b|银行账户|礼品卡")
PAYMENT_WORD = re.compile(r"\b(wire|transfer|invoice|payment|remit|crypto)\b|转账|汇款|发票|付款")
PAYMENT = re.compile(f"{PAYMENT_ACCOUNT.pattern}|{PAYMENT_WORD.pattern}")
BANK_CHANGE = re.compile(
    r"(new|updated|changed|different|revised)\s+(bank(ing)?|payment|account|remittance)\s+(details|information|instructions|account|number|info)"
    r"|(bank(ing)?|account)\s+(details|information|number)\s+(?:(?:has|have|had)\s+)?(?:been\s+)?(changed|updated|revised)"
    r"|change\s+(of\s+)?(our\s+)?(bank|account)"
    r"|更换.{0,6}(账户|账号)|账户.{0,4}变更"
)
SECRECY = re.compile(
    r"\b(confidential|don'?t (tell|share|discuss)|do not (tell|share|discuss)|keep this (between|quiet)|discreet)\b|保密|不要告诉"
)
# A request to act on an account vs merely mentioning a password (mailing lists talk about passwords).
CREDENTIAL_ACTION = re.compile(
    r"\b(verify your account|confirm your (identity|account)|login credentials|account (suspended|locked))\b|验证.{0,4}账户"
)
CREDENTIAL_WORD = re.compile(r"\b(password|passcode)\b|密码")
CREDENTIAL = re.compile(f"{CREDENTIAL_ACTION.pattern}|{CREDENTIAL_WORD.pattern}")
INJECTION = re.compile(
    r"ignore (all |any )?(previous|prior|above) (instructions|rules)|system prompt"
    r"|\byou are now (a |an |the |my )?(system|admin(istrator)?|root|developer|ai|assistant|dan|jailbroken|unrestricted)\b"
    r"|disregard .{0,30}(instructions|rules)|mfa (is )?(already )?(verified|approved|passed)"
    r"|(skip|bypass) (the )?mfa|approve (this|the) (transfer|payment)|忽略.{0,6}(指令|规则)|已通过.{0,3}验证"
    r"|(you have been|you've been|you are|you're) (granted|given|authori[sz]ed)\b.{0,30}(mfa|authori[sz]ation|approval|clearance)"
    r"|\b(acting as|act as|in the role of|pretend to be) (the |an? )?(system|admin(istrator)?|root|developer|ai|assistant)\b"
    r"|\b(execute|perform|initiate|complete) (the |this |a )?(wire |fund )?(transfer|payment|wire)\b.{0,40}\b(now|immediately|without)"
    r"|\b(transfer_funds|pay_invoice|approve_invoice|change_bank_details|reset_password|change_account_email)\b"
    r"|</?(system|instructions?|assistant|tool_use|tool_result)>"
    r"|已获得.{0,6}(mfa|授权|验证|批准)|以系统(身份|管理员)|系统指令|执行转账"
)
# (feature name, ((pattern, weight key or None for the name itself), ...)), most specific first.
KEYWORD_FEATURES = (
    ("urgency_language", ((URGENCY_DEADLINE, "urgency_deadline"), (URGENCY_WORD, None))),
    ("payment_keywords", ((PAYMENT_ACCOUNT, "payment_account_terms"), (PAYMENT_WORD, None))),
    ("bank_detail_change", ((BANK_CHANGE, None),)),
    ("secrecy_request", ((SECRECY, None),)),
    ("credential_request", ((CREDENTIAL_ACTION, "credential_action"), (CREDENTIAL_WORD, None))),
    ("prompt_injection_attempt", ((INJECTION, None),)),
)
RISKY_EXT = (
    ".pif",
    ".com",
    ".jse",
    ".vbe",
    ".wsf",
    ".msi",
    ".cpl",
    ".xll",
    ".chm",
    ".exe",
    ".scr",
    ".js",
    ".vbs",
    ".iso",
    ".img",
    ".vhd",
    ".html",
    ".htm",
    ".shtml",
    ".svg",
    ".hta",
    ".lnk",
    ".bat",
    ".cmd",
    ".ps1",
    ".jar",
    ".one",
)
MACRO_EXT = (".docm", ".dotm", ".xlsm", ".xltm", ".xlam", ".pptm", ".potm", ".ppam")
RISKY_CTYPES = (
    "text/html",
    "application/x-iso9660-image",
    "application/x-ms-shortcut",
    "application/x-msdownload",
    "application/hta",
    "application/onenote",
)
_HOMOGLYPHS = str.maketrans(
    "аеорсухіјԁɡոѕνοαρτικмтн",  # Cyrillic / Greek / Armenian letters that render like Latin
    "aeopcyxijdgnsvoaptikmtn",
)
_URLISH = re.compile(r"^(https?://)?([a-z0-9-]+\.)+[a-z]{2,}(:\d+)?(/\S*)?$")
DOUBLE_EXT = re.compile(
    r"\.(pdf|docx?|xlsx?|pptx?|rtf|txt|csv|jpe?g|png|gif|zip|rar|html?|mp3|mp4|wav)"
    r"[\s._-]*\.(exe|scr|com|pif|js|jse|vbs|vbe|wsf|bat|cmd|lnk|hta|ps1|jar|msi|cpl|iso|img|html?|svg)$"
)
ARCHIVE_EXT = (
    ".zip",
    ".rar",
    ".7z",
    ".gz",
    ".tgz",
    ".tar",
    ".bz2",
    ".xz",
    ".cab",
    ".ace",
    ".arj",
    ".lzh",
    ".uue",
    ".z",
)
ARCHIVE_CTYPES = (
    "application/zip",
    "application/x-zip-compressed",
    "application/x-rar-compressed",
    "application/vnd.rar",
    "application/x-7z-compressed",
    "application/gzip",
    "application/x-tar",
)
OFFICE_LEGACY_EXT = (".doc", ".xls", ".ppt", ".rtf", ".dot", ".xlt", ".pps")
IMAGE_EXT = (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tif", ".tiff")
PASSWORD_HINT = re.compile(
    r"\b(password|passcode|passwd|pwd|pin)\s*(is\b\s*[:=]?|[:=-])\s*['\"]?[\w@#$%^&*!.-]{3,}"
    r"|\bpassword[- ]protected\b|\bencrypted (zip|archive|file|attachment|document)\b"
    r"|\b(use|enter) (the )?(password|code) \S{3,} to (open|view|extract)"
    r"|解压密码|密码[:：]\s*\S{3,}"
)
_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff\u00ad"))
# bidirectional controls: "invoice\u202efdp.exe" displays as "invoiceexe.pdf"
BIDI = "\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
_INVISIBLE = {**_ZERO_WIDTH, **dict.fromkeys(map(ord, BIDI))}
_LEET = str.maketrans({"@": "a", "4": "a", "3": "e", "1": "i", "!": "i", "0": "o", "$": "s", "5": "s", "7": "t"})
_SPLIT_RUN = re.compile(r"(?<![\w@$!])(?:[\w@$!][ .\-_*/|]){2,}[\w@$!](?![\w@$!])")
_B64 = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
MAX_HOST = 253  # DNS limit; longer "hosts" are cut so string metrics stay cheap
NON_WEB_SCHEMES = ("mailto:", "tel:", "sms:", "callto:", "cid:", "mid:", "news:", "sip:")


@dataclass(frozen=True)
class DetectionContext:
    trusted_domains: tuple[str, ...] = ("acme-corp.com",)
    executives: tuple[str, ...] = ()
    safe_link_domains: tuple[str, ...] = DEFAULT_SAFE_LINK_DOMAINS
    company_names: tuple[str, ...] = ()  # empty: derived from trusted_domains
    weights: WeightTable | None = field(default=None, compare=False, hash=False)  # None: weights.yaml

    @property
    def table(self) -> WeightTable:
        return self.weights or DEFAULT_WEIGHTS

    def brands(self) -> tuple[str, ...]:
        if self.company_names:
            return tuple(_compact(n) for n in self.company_names if len(_compact(n)) >= 4)
        out: list[str] = []
        for d in self.trusted_domains:
            label = d.split(".")[0]
            for cand in (label.replace("-", ""), label.split("-")[0]):
                if len(cand) >= 4 and cand not in out:
                    out.append(cand)
        return tuple(out)


@dataclass(frozen=True)
class Feature:
    name: str
    weight: float
    evidence: str
    contribution: float = 0.0  # share of the final 0-100 score (sums to the score)
    key: str = ""  # weights.yaml entry used; differs from `name` for sub-cases (e.g. reply_to_freemail)

    def __post_init__(self) -> None:
        if not self.key:
            object.__setattr__(self, "key", self.name)

    def to_dict(self) -> dict:
        return asdict(self)


def clean_text(s: str) -> str:
    return unicodedata.normalize("NFKC", s).translate(_INVISIBLE).lower()


def clean_filename(name: str) -> str:
    """Name as Windows would treat it: no invisible/bidi chars, no trailing dots or spaces."""
    return clean_text(name).strip().rstrip(". ")


def deobfuscate(text: str) -> str:
    """Undo common keyword hiding: 'w i r e', 'u-r-g-e-n-t', 'tr@nsf3r'."""
    joined = _SPLIT_RUN.sub(lambda m: re.sub(r"[ .\-_*/|]", "", m.group(0)), text)
    return joined.translate(_LEET)


def decoded_blobs(text: str, limit: int = 10) -> str:
    """Decode base64-looking tokens (an LLM would read them; the rules should too)."""
    out = []
    for tok in _B64.findall(text)[:limit]:
        try:
            raw = base64.b64decode(tok + "=" * (-len(tok) % 4), validate=False)
            dec = raw.decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if dec.isprintable() or "\n" in dec:
            out.append(dec)
    return clean_text("\n".join(out))


def _compact(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", clean_text(s).translate(_HOMOGLYPHS))


def domain_of(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].strip(" <>").lower()[:MAX_HOST]


def registrable(domain: str) -> str:
    labels = domain.strip(".").split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in {"co", "com", "org", "net", "gov"}:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def is_under(domain: str, parents: tuple[str, ...]) -> bool:
    return any(domain == p or domain.endswith("." + p) for p in parents)


def _norm(label: str) -> str:
    t = label.lower().replace("-", "")
    t = t.replace("rn", "m").replace("vv", "w")
    return t.translate(str.maketrans("0158", "olsb"))


def levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def skeleton(domain: str) -> str:
    """Decode punycode labels and fold look-alike non-Latin letters to Latin."""
    labels = []
    for lab in domain.lower().strip(".").split("."):
        if lab.startswith("xn--"):
            try:
                lab = lab.encode("ascii").decode("idna")
            except (UnicodeError, ValueError):
                pass
        labels.append(unicodedata.normalize("NFKC", lab).translate(_HOMOGLYPHS))
    return ".".join(labels)


def homoglyph_of(domain: str, trusted: tuple[str, ...]) -> str | None:
    """Trusted domain that `domain` spoofs with punycode / mixed-script letters, if any."""
    domain = domain[:MAX_HOST]
    if domain.isascii() and "xn--" not in domain:
        return None
    sk = skeleton(domain)
    if sk == domain or not sk.isascii():
        return None
    if is_under(sk, trusted):
        return next(t for t in trusted if sk == t or sk.endswith("." + t))
    hit = lookalike_of(sk, trusted)
    return hit[0] if hit else None


def lookalike_of(domain: str, trusted: tuple[str, ...]) -> tuple[str, float] | None:
    """Return (trusted_domain, similarity) if `domain` imitates a trusted one."""
    domain = domain[:MAX_HOST]  # similarity metrics are quadratic; DNS names are <= 253 chars
    if not domain or is_under(domain, trusted) or domain in FREE_MAIL:
        return None
    reg = registrable(domain)
    best: tuple[str, float] | None = None
    for t in trusted:
        if t in domain:  # e.g. acme-corp.com.secure-login.net
            return t, 1.0
        a, b = _norm(reg), _norm(t)
        sim = 1.0 if a == b else SequenceMatcher(None, a, b).ratio()
        if sim < 0.84 and min(len(a), len(b)) >= 6 and abs(len(a) - len(b)) <= 2 and levenshtein(a, b) <= 2:
            sim = max(sim, round(1 - levenshtein(a, b) / max(len(a), len(b)), 2))
            sim = max(sim, 0.84)  # edit distance <= 2 on a long name is a look-alike
        if sim >= 0.84 and (best is None or sim > best[1]):
            best = (t, sim)
    return best


def _host(url: str) -> str:
    url = url[:2048]
    try:
        return (urlparse(url if "//" in url else "//" + url).hostname or "").lower()[:MAX_HOST]
    except ValueError:  # e.g. malformed IPv6 literal
        return ""


def _is_ip(host: str) -> bool:
    """Dotted IPv4, IPv6, or the integer/hex forms browsers also accept (http://3232235777/)."""
    h = host.strip("[]")
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        pass
    return bool(re.fullmatch(r"(0x[0-9a-f]{1,8}|\d{8,10})", h)) or bool(
        re.fullmatch(r"((0x[0-9a-f]+|\d+)\.){1,3}(0x[0-9a-f]+|\d+)", h) and "0x" in h
    )


def link_signals(url: str, sreg: str, ctx: DetectionContext) -> list[tuple[str, str]]:
    """Specific, explainable reasons a single link is suspicious (no generic 'unrelated host')."""
    out: list[tuple[str, str]] = []
    raw = url.strip()[:2048]
    low = raw.lower()
    if low.startswith(("data:", "javascript:", "vbscript:")):
        return [("link_data_uri", f"{low.split(':', 1)[0]}: link")]
    if low.startswith(NON_WEB_SCHEMES):
        # mailto:/tel:/cid: are not web links. Parsing "mailto:a@b" as a URL put the address in the
        # netloc, so every mailto link fired link_at_obfuscation (41% of dev hard_ham; DESIGN Q63).
        return out
    try:
        parsed = urlparse(raw if "//" in raw else "//" + raw)
        host = (parsed.hostname or "").lower()[:MAX_HOST]
        port = parsed.port
    except ValueError:
        return out
    if not host:
        return out
    if "@" in (parsed.netloc or ""):
        shown = parsed.netloc.rsplit("@", 1)[0][:60]
        out.append(("link_at_obfuscation", f"link shows '{shown}' before '@' but goes to {host}"))
    if _is_ip(host):
        out.append(("link_ip_host", f"link to IP address {host}"))
    if port is not None and port not in (80, 443):
        out.append(("link_nonstandard_port", f"link to {host}:{port}"))
    if host in SHORTENERS or registrable(host) in SHORTENERS:
        out.append(("link_shortener", f"shortened link via {host}"))
    if "xn--" in host and not is_under(host, ctx.trusted_domains):
        out.append(("link_punycode", f"punycode host {host}"))
    reg = registrable(host)
    tokens = set(re.split(r"[.\-]", host))
    for brand, owned in ctx.table.brands.items():
        if brand in tokens and reg not in owned and not any(host == d or host.endswith("." + d) for d in owned):
            out.append(("link_brand_impersonation", f"{host} uses brand '{brand}' but is not {brand}'s domain"))
            break
    if not out and reg != sreg and not is_under(host, ctx.trusted_domains + ctx.safe_link_domains) and not _is_ip(host):
        out.append(("unrelated_link_host", f"link to unrelated host {host}"))
    return out


def _claims_known_host(host: str, ctx: DetectionContext) -> bool:
    """The host names one of OUR domains (or imitates one) or a well-known brand."""
    if is_under(host, ctx.trusted_domains) or homoglyph_of(host, ctx.trusted_domains):
        return True
    if lookalike_of(host, ctx.trusted_domains):
        return True
    tokens = set(re.split(r"[.\-]", skeleton(host)))
    return any(
        b in tokens or any(host == d or host.endswith("." + d) for d in owned) for b, owned in ctx.table.brands.items()
    )


def extract_features(
    email: EmailMessage, ctx: DetectionContext | None = None, keep_zero: bool = False
) -> list[Feature]:
    """Fire every applicable feature. Weight-0 features are dropped unless `keep_zero` (calibration
    needs to know they fired)."""
    ctx = ctx or DetectionContext()
    table = ctx.table
    out: list[Feature] = []

    def add(name: str, evidence: str, key: str | None = None) -> None:
        w = table.get(key or name)
        if w > 0 or keep_zero:
            out.append(Feature(name, w, evidence, key=key or name))

    sdom = domain_of(email.sender_email)
    sreg = registrable(sdom)
    text = clean_text(f"{email.subject}\n{email.body}")

    homo = homoglyph_of(sdom, ctx.trusted_domains)
    look = None if homo else lookalike_of(sdom, ctx.trusted_domains)
    if homo:
        add("homoglyph_domain", f"{sdom} renders as {skeleton(sdom)}, spoofing {homo}")
    elif look:
        add("lookalike_domain", f"{sdom} imitates {look[0]} (similarity {look[1]:.2f})")

    # Same organization (registrable domain) never counts as a mismatch. Mailing lists rewrite
    # Reply-To and use their own bounce address by design, so list mail is down-weighted/exempt.
    # List headers are sender-controlled, so they never silence the free-mail reply-to (BEC) case.
    if email.reply_to:
        rdom = domain_of(email.reply_to)
        if registrable(rdom) != sreg:
            if rdom in FREE_MAIL and sdom not in FREE_MAIL:
                add("reply_to_mismatch", f"replies go to free mail {rdom}, sender is {sdom}", "reply_to_freemail")
            elif email.list_mail:
                add("reply_to_mismatch", f"list mail: reply-to {rdom} differs from {sdom}", "reply_to_mismatch_list")
            else:
                add("reply_to_mismatch", f"reply-to {rdom} differs from sender {sdom}")
    if email.return_path and not email.list_mail and registrable(domain_of(email.return_path)) != sreg:
        add("return_path_mismatch", f"return-path {domain_of(email.return_path)} differs from sender {sdom}")

    auth = {"spf": email.spf, "dkim": email.dkim, "dmarc": email.dmarc}
    fails = [k for k, v in auth.items() if v == "fail"]
    if fails:
        add("auth_fail", f"failed: {', '.join(fails)}", "auth_fail_multi" if len(fails) >= 2 else None)
    elif all(v == "none" for v in auth.values()):
        add("no_authentication", "no SPF/DKIM/DMARC result")

    rep = email.sender_reputation
    if rep is not None:
        if rep < 0.3:
            add("low_reputation", f"sender reputation {rep:.2f}")
        elif rep < 0.5:
            add("moderate_reputation", f"sender reputation {rep:.2f}")

    age = email.sender_domain_age_days
    if age is not None:
        if age < 30:
            add("new_domain", f"sender domain is {age} days old")
        elif age < 90:
            add("young_domain", f"sender domain is {age} days old")

    anomalies = list(email.header_anomalies)
    for label, val in [("display name", email.sender_name), *(("attachment name", x) for x in email.attachments)]:
        if any(ch in val for ch in BIDI):
            anomalies.append(f"bidirectional control character in {label} {clean_text(val)!r}")
    if anomalies:
        add("header_anomaly", "; ".join(anomalies)[:300])

    # Text the reader (or an LLM) can see: subject, body, attachment names, link texts,
    # plus base64 blobs decoded. Keywords are matched on it and on a de-obfuscated copy.
    extra = [clean_filename(a) for a in email.attachments] + [clean_text(lp.text) for lp in email.link_pairs]
    hidden_txt = clean_text(email.hidden_text)
    if len(hidden_txt.strip()) >= 20:
        add("hidden_html_text", f"{len(hidden_txt)} chars of CSS-hidden text: '{hidden_txt[:60]}'")
    seen = "\n".join([text, *extra, hidden_txt])
    hidden = decoded_blobs(email.body)
    variants = [("", seen), (" (base64-decoded)", hidden), (" (de-obfuscated)", deobfuscate(seen))]
    authenticated = email.dmarc == "pass" or (email.spf == "pass" and email.dkim == "pass")
    known_partner = authenticated and bool(ctx.trusted_domains) and is_under(sdom, ctx.trusted_domains)
    soft = {"urgency_language", "payment_keywords"} if known_partner else set()
    obfuscated = None
    for name, patterns in KEYWORD_FEATURES:
        hit = None
        for rx, sub in patterns:  # specific context first, so it wins over the generic word
            hit = next(((tag, m, sub) for tag, t in variants if t and (m := rx.search(t))), None)
            if hit:
                break
        if not hit:
            continue
        tag, m, sub = hit
        key = f"{name}_trusted_sender" if name in soft else sub
        add(name, f"matched '{m.group(0)}'{tag}", key)
        plain = any(rx.search(seen) for rx, _ in patterns)
        if tag and not plain and obfuscated is None:
            obfuscated = f"keyword '{m.group(0)}' only visible{tag}"
    if obfuscated:
        add("obfuscated_text", obfuscated)

    name = clean_text(email.sender_name)
    external = not is_under(sdom, ctx.trusted_domains)
    for ex in ctx.executives:
        if clean_text(ex) in name and external:
            add("executive_impersonation", f"display name '{email.sender_name}' sent from {sdom}")
            break
    else:
        cname = _compact(email.sender_name)
        brand = next((b for b in ctx.brands() if b in cname), None) if external else None
        if brand:
            add("display_name_spoof", f"display name '{email.sender_name}' uses brand '{brand}' but sent from {sdom}")

    # Each link signal counts once per mail (first evidence wins), whatever the number of links.
    link_hits: dict[str, str] = {}
    hrefs = list(email.links) + [lp.href for lp in email.link_pairs if lp.href not in email.links]
    for url in hrefs[:200]:
        host = _host(url)
        if host and "lookalike_link" not in link_hits:
            if homoglyph_of(host, ctx.trusted_domains) or lookalike_of(host, ctx.trusted_domains):
                link_hits["lookalike_link"] = f"link {host} imitates a trusted domain"
        for name, ev in link_signals(url, sreg, ctx):
            link_hits.setdefault(name, ev)
    if len(link_hits) > 1:
        link_hits.pop("unrelated_link_host", None)
    for name, ev in link_hits.items():
        add(name, ev)

    # A mismatch whose real target is the sender's own registrable domain (its click tracker) reveals
    # nothing the From header doesn't already say, so it gets a lower key. It never applies when the
    # sender itself is a look-alike, or when the shown host is a brand/trusted domain (DESIGN Q65).
    sender_ok = bool(sreg) and not (homo or look)
    own_only: str | None = None
    for lp in email.link_pairs[:100]:
        shown = clean_text(lp.text).strip().rstrip(".,;")
        if not _URLISH.match(shown):
            continue
        th, hh = _host(shown), _host(lp.href)
        if th and hh and registrable(th) != registrable(hh):
            ev = f"link text shows {th} but points to {hh}"
            if sender_ok and registrable(hh) == sreg and not _claims_known_host(th, ctx):
                own_only = own_only or ev
                continue
            add("link_text_mismatch", ev)
            own_only = None
            break
    if own_only:
        add("link_text_mismatch", f"{own_only} (the sender's own domain)", "link_text_mismatch_own_domain")

    names = [(a, "") for a in email.attachments] + [(m.filename, m.content_type) for m in email.attachment_meta]
    att_hits: dict[str, str] = {}
    images = others = 0
    for att, ctype in names:
        a, ct = clean_filename(att), ctype.lower()
        if DOUBLE_EXT.search(a):
            att_hits.setdefault("risky_attachment", f"double extension {att}")
        elif a.endswith(MACRO_EXT) or "macroenabled" in ct:
            att_hits.setdefault("risky_attachment", f"macro document {att or ctype}")
        elif a.endswith(RISKY_EXT) or ct in RISKY_CTYPES:
            att_hits.setdefault("risky_attachment", f"executable/script/container {att or ctype}")
        elif a.endswith(ARCHIVE_EXT) or ct in ARCHIVE_CTYPES:
            att_hits.setdefault("archive_attachment", f"archive {att or ctype}")
        elif a.endswith(OFFICE_LEGACY_EXT) or ct in (
            "application/msword",
            "application/vnd.ms-excel",
            "application/rtf",
        ):
            att_hits.setdefault("office_legacy_attachment", f"legacy Office file {att or ctype}")
        if a.endswith(IMAGE_EXT) or ct.startswith("image/"):
            images += 1
        elif a or ct:
            others += 1
    if names and (m := PASSWORD_HINT.search(seen)):
        att_hits["encrypted_attachment_hint"] = f"attachment with password hint '{m.group(0)[:40]}'"
    words = len(re.findall(r"\w+", text))
    if images and not others and words < 25:
        att_hits["image_lure"] = f"{images} image attachment(s), {words} words of text"
    for name, ev in att_hits.items():
        add(name, ev)

    ts = email.timestamp
    if ts.weekday() >= 5 or ts.hour < 7 or ts.hour >= 20:
        add("off_hours_send", f"sent {ts.isoformat()}")
    return out


def explain(features: list[Feature]) -> list[Feature]:
    """Attach each feature's contribution in score points; contributions sum to the score.

    Noisy-OR is 1 - prod(1 - w_i) = 1 - exp(-sum L_i) with L_i = -ln(1 - w_i), so each
    feature gets the score in proportion to its L_i. Order-independent and exact.
    """
    total = risk_percent(features)
    logs = [-math.log(max(1e-9, 1.0 - f.weight)) for f in features]
    s = sum(logs) or 1.0
    out = [replace(f, contribution=round(total * li / s, 1)) for f, li in zip(features, logs, strict=True)]
    return sorted(out, key=lambda f: -f.contribution)


def risk_percent(features: list[Feature]) -> float:
    """Noisy-OR: independent evidence combines into a 0-100 confidence."""
    miss = 1.0
    for f in features:
        miss *= 1.0 - f.weight
    return round(100 * (1 - miss), 1)
