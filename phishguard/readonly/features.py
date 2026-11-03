"""Deterministic phishing feature extraction and scoring (read-only, pure functions)."""

from __future__ import annotations

import math
import re
import unicodedata
from dataclasses import asdict, dataclass, replace
from difflib import SequenceMatcher
from urllib.parse import urlparse

from ..models import EmailMessage

WEIGHTS = {
    "homoglyph_domain": 0.60,
    "lookalike_domain": 0.55,
    "link_text_mismatch": 0.45,
    "lookalike_link": 0.45,
    "bank_detail_change": 0.45,
    "executive_impersonation": 0.40,
    "display_name_spoof": 0.40,
    "risky_attachment": 0.40,
    "prompt_injection_attempt": 0.50,
    "auth_fail": 0.35,
    "low_reputation": 0.35,
    "reply_to_mismatch": 0.30,
    "suspicious_link": 0.30,
    "credential_request": 0.30,
    "new_domain": 0.25,
    "secrecy_request": 0.25,
    "urgency_language": 0.20,
    "payment_keywords": 0.20,
    "moderate_reputation": 0.15,
    "return_path_mismatch": 0.12,
    "young_domain": 0.10,
    "no_authentication": 0.08,
    "off_hours_send": 0.08,
}

FREE_MAIL = {"gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "163.com", "qq.com", "proton.me"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy"}
DEFAULT_SAFE_LINK_DOMAINS = ("google.com", "github.com", "zoom.us", "microsoft.com", "notion.so")

URGENCY = re.compile(
    r"\b(urgent|immediately|asap|right away|within \d+ (hours?|hrs?)|final notice|act now|time[- ]sensitive|overdue)\b"
    r"|紧急|立即|马上|尽快|逾期"
)
PAYMENT = re.compile(
    r"\b(wire|transfer|invoice|payment|remit|bank account|iban|swift|gift cards?|bitcoin|crypto|routing number)\b"
    r"|转账|汇款|发票|付款|银行账户|礼品卡"
)
BANK_CHANGE = re.compile(
    r"(new|updated|changed|different|revised)\s+(bank(ing)?|payment|account|remittance)\s+(details|information|instructions|account|number|info)"
    r"|(bank(ing)?|account)\s+(details|information|number)\s+(has|have|had)?\s*(been\s+)?(changed|updated|revised)"
    r"|change\s+(of\s+)?(our\s+)?(bank|account)"
    r"|更换.{0,6}(账户|账号)|账户.{0,4}变更"
)
SECRECY = re.compile(
    r"\b(confidential|don'?t (tell|share|discuss)|do not (tell|share|discuss)|keep this (between|quiet)|discreet)\b|保密|不要告诉"
)
CREDENTIAL = re.compile(
    r"\b(password|passcode|verify your account|confirm your (identity|account)|login credentials|account (suspended|locked))\b|验证.{0,4}账户|密码"
)
INJECTION = re.compile(
    r"ignore (all |any )?(previous|prior|above) (instructions|rules)|you are now|system prompt"
    r"|disregard .{0,30}(instructions|rules)|mfa (is )?(already )?(verified|approved|passed)"
    r"|(skip|bypass) (the )?mfa|approve (this|the) (transfer|payment)|忽略.{0,6}(指令|规则)|已通过.{0,3}验证"
)
RISKY_EXT = (
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
DOUBLE_EXT = re.compile(r"\.(pdf|docx?|xlsx?)\.(exe|scr|js|bat|lnk)$")
_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿"))


@dataclass(frozen=True)
class DetectionContext:
    trusted_domains: tuple[str, ...] = ("acme-corp.com",)
    executives: tuple[str, ...] = ()
    safe_link_domains: tuple[str, ...] = DEFAULT_SAFE_LINK_DOMAINS
    company_names: tuple[str, ...] = ()  # empty: derived from trusted_domains

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

    def to_dict(self) -> dict:
        return asdict(self)


def clean_text(s: str) -> str:
    return unicodedata.normalize("NFKC", s).translate(_ZERO_WIDTH).lower()


def _compact(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", clean_text(s))


def domain_of(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].strip(" <>").lower()


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
    if not domain or is_under(domain, trusted) or domain in FREE_MAIL:
        return None
    reg = registrable(domain)
    best: tuple[str, float] | None = None
    for t in trusted:
        if t in domain:  # e.g. acme-corp.com.secure-login.net
            return t, 1.0
        a, b = _norm(reg), _norm(t)
        sim = 1.0 if a == b else SequenceMatcher(None, a, b).ratio()
        if sim < 0.84 and min(len(a), len(b)) >= 6 and levenshtein(a, b) <= 2:
            sim = max(sim, round(1 - levenshtein(a, b) / max(len(a), len(b)), 2))
            sim = max(sim, 0.84)  # edit distance <= 2 on a long name is a look-alike
        if sim >= 0.84 and (best is None or sim > best[1]):
            best = (t, sim)
    return best


def _host(url: str) -> str:
    return (urlparse(url if "//" in url else "//" + url).hostname or "").lower()


def _is_ip(host: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host))


def extract_features(email: EmailMessage, ctx: DetectionContext | None = None) -> list[Feature]:
    ctx = ctx or DetectionContext()
    out: list[Feature] = []

    def add(name: str, evidence: str) -> None:
        out.append(Feature(name, WEIGHTS[name], evidence))

    sdom = domain_of(email.sender_email)
    sreg = registrable(sdom)
    text = clean_text(f"{email.subject}\n{email.body}")

    homo = homoglyph_of(sdom, ctx.trusted_domains)
    look = None if homo else lookalike_of(sdom, ctx.trusted_domains)
    if homo:
        add("homoglyph_domain", f"{sdom} renders as {skeleton(sdom)}, spoofing {homo}")
    elif look:
        add("lookalike_domain", f"{sdom} imitates {look[0]} (similarity {look[1]:.2f})")

    if email.reply_to and registrable(domain_of(email.reply_to)) != sreg:
        add("reply_to_mismatch", f"reply-to {domain_of(email.reply_to)} differs from sender {sdom}")
    if email.return_path and registrable(domain_of(email.return_path)) != sreg:
        add("return_path_mismatch", f"return-path {domain_of(email.return_path)} differs from sender {sdom}")

    auth = {"spf": email.spf, "dkim": email.dkim, "dmarc": email.dmarc}
    fails = [k for k, v in auth.items() if v == "fail"]
    if fails:
        f = Feature("auth_fail", 0.5 if len(fails) >= 2 else WEIGHTS["auth_fail"], f"failed: {', '.join(fails)}")
        out.append(f)
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

    if m := URGENCY.search(text):
        add("urgency_language", f"matched '{m.group(0)}'")
    if m := PAYMENT.search(text):
        add("payment_keywords", f"matched '{m.group(0)}'")
    if m := BANK_CHANGE.search(text):
        add("bank_detail_change", f"matched '{m.group(0)}'")
    if m := SECRECY.search(text):
        add("secrecy_request", f"matched '{m.group(0)}'")
    if m := CREDENTIAL.search(text):
        add("credential_request", f"matched '{m.group(0)}'")
    if m := INJECTION.search(text):
        add("prompt_injection_attempt", f"matched '{m.group(0)}'")

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

    bad_link = None
    for url in email.links:
        host = _host(url)
        if not host:
            continue
        if homoglyph_of(host, ctx.trusted_domains) or lookalike_of(host, ctx.trusted_domains):
            add("lookalike_link", f"link {host} imitates a trusted domain")
            break
        if bad_link is None and (
            _is_ip(host)
            or host in SHORTENERS
            or (registrable(host) != sreg and not is_under(host, ctx.trusted_domains + ctx.safe_link_domains))
        ):
            bad_link = host
    if bad_link:
        add("suspicious_link", f"link to unrelated host {bad_link}")

    for lp in email.link_pairs:
        shown = clean_text(lp.text).strip().rstrip(".,;")
        if not _URLISH.match(shown):
            continue
        th, hh = _host(shown), _host(lp.href)
        if th and hh and registrable(th) != registrable(hh):
            add("link_text_mismatch", f"link text shows {th} but points to {hh}")
            break

    names = [(a, "") for a in email.attachments] + [(m.filename, m.content_type) for m in email.attachment_meta]
    for att, ctype in names:
        a = att.lower()
        kind = (
            "macro document"
            if a.endswith(MACRO_EXT) or "macroenabled" in ctype.lower()
            else "executable/container"
            if a.endswith(RISKY_EXT) or DOUBLE_EXT.search(a) or ctype.lower() in RISKY_CTYPES
            else None
        )
        if kind:
            add("risky_attachment", f"{kind} attachment {att or ctype}")
            break

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
