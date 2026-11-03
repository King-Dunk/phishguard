"""Deterministic phishing feature extraction and scoring (read-only, pure functions)."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import asdict, dataclass
from difflib import SequenceMatcher
from urllib.parse import urlparse

from ..models import EmailMessage

WEIGHTS = {
    "lookalike_domain": 0.55,
    "lookalike_link": 0.45,
    "bank_detail_change": 0.45,
    "executive_impersonation": 0.40,
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
RISKY_EXT = (".exe", ".scr", ".js", ".vbs", ".iso", ".html", ".htm", ".lnk", ".bat", ".jar")
DOUBLE_EXT = re.compile(r"\.(pdf|docx?|xlsx?)\.(exe|scr|js|bat|lnk)$")
_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿"))


@dataclass(frozen=True)
class DetectionContext:
    trusted_domains: tuple[str, ...] = ("acme-corp.com",)
    executives: tuple[str, ...] = ()
    safe_link_domains: tuple[str, ...] = DEFAULT_SAFE_LINK_DOMAINS


@dataclass(frozen=True)
class Feature:
    name: str
    weight: float
    evidence: str

    def to_dict(self) -> dict:
        return asdict(self)


def clean_text(s: str) -> str:
    return unicodedata.normalize("NFKC", s).translate(_ZERO_WIDTH).lower()


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


def lookalike_of(domain: str, trusted: tuple[str, ...]) -> tuple[str, float] | None:
    """Return (trusted_domain, similarity) if `domain` imitates a trusted one."""
    if not domain or is_under(domain, trusted) or domain in FREE_MAIL:
        return None
    reg = registrable(domain)
    best: tuple[str, float] | None = None
    for t in trusted:
        if t in domain:  # e.g. acme-corp.com.secure-login.net
            return t, 1.0
        sim = 1.0 if _norm(reg) == _norm(t) else SequenceMatcher(None, _norm(reg), _norm(t)).ratio()
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

    look = lookalike_of(sdom, ctx.trusted_domains)
    if look:
        add("lookalike_domain", f"{sdom} imitates {look[0]} (similarity {look[1]:.2f})")

    if email.reply_to and registrable(domain_of(email.reply_to)) != sreg:
        add("reply_to_mismatch", f"reply-to {domain_of(email.reply_to)} differs from sender {sdom}")

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
    for ex in ctx.executives:
        if clean_text(ex) in name and not is_under(sdom, ctx.trusted_domains):
            add("executive_impersonation", f"display name '{email.sender_name}' sent from {sdom}")
            break

    bad_link = None
    for url in email.links:
        host = _host(url)
        if not host:
            continue
        if lookalike_of(host, ctx.trusted_domains):
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

    for att in email.attachments:
        a = att.lower()
        if a.endswith(RISKY_EXT) or DOUBLE_EXT.search(a):
            add("risky_attachment", f"attachment {att}")
            break

    ts = email.timestamp
    if ts.weekday() >= 5 or ts.hour < 7 or ts.hour >= 20:
        add("off_hours_send", f"sent {ts.isoformat()}")
    return out


def risk_percent(features: list[Feature]) -> float:
    """Noisy-OR: independent evidence combines into a 0-100 confidence."""
    miss = 1.0
    for f in features:
        miss *= 1.0 - f.weight
    return round(100 * (1 - miss), 1)
