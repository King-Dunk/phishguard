"""Turn YAML attack specs into raw RFC 822 mail or request bodies. Generators build huge/deep inputs."""

from __future__ import annotations

import base64
from email.message import EmailMessage
from email.policy import SMTP, SMTPUTF8
from typing import Any

DEFAULT_FROM = "Updates <news@vendor-mail.example>"
DEFAULT_AUTH = "mx.acme-corp.com; spf=pass smtp.mailfrom=vendor-mail.example; dkim=pass; dmarc=pass"
DATE = "Tue, 03 Mar 2026 10:00:00 +0000"


def build_eml(spec: dict[str, Any]) -> str:
    if "raw" in spec:
        return spec["raw"]
    if "generator" in spec:
        return GENERATORS[spec["generator"]](**spec.get("args", {}))
    m = EmailMessage(policy=SMTPUTF8)
    m["Authentication-Results"] = spec.get("auth", DEFAULT_AUTH)
    m["From"] = spec.get("from", DEFAULT_FROM)
    if "reply_to" in spec:
        m["Reply-To"] = spec["reply_to"]
    m["To"] = spec.get("to", "anna.k@acme-corp.com")
    m["Subject"] = spec.get("subject", "Hello")
    m["Date"] = spec.get("date", DATE)
    m["Message-ID"] = f"<{spec.get('id', 'rt')}@redteam.example>"
    text = spec.get("text", "")
    html = spec.get("html")
    m.set_content(text or " ")
    if html:
        m.add_alternative(html, subtype="html")
    for att in spec.get("attachments", []):
        maintype, subtype = att.get("ctype", "application/octet-stream").split("/", 1)
        m.add_attachment(att.get("content", "x").encode(), maintype=maintype, subtype=subtype, filename=att["name"])
    for k, v in spec.get("headers", {}).items():
        m[k] = v
    try:
        return m.as_string(policy=SMTPUTF8)
    except UnicodeEncodeError:  # pragma: no cover
        return m.as_string(policy=SMTP)


def deep_mime(depth: int = 2000) -> str:
    s = "Content-Type: text/plain\n\nhi\n"
    for i in range(depth):
        s = f'Content-Type: multipart/mixed; boundary="b{i}"\n\n--b{i}\n{s}\n--b{i}--\n'
    return "From: a@evil.example\nSubject: deep\n" + s


def many_parts(parts: int = 5000) -> str:
    body = "".join(f"--B\nContent-Type: text/plain\n\npart {i}\n" for i in range(parts))
    return f'From: a@evil.example\nSubject: wide\nContent-Type: multipart/mixed; boundary="B"\n\n{body}--B--\n'


def redos_body(n: int = 19000) -> str:
    return "From: a@evil.example\nSubject: slow\n\naccount details" + " " * n + "x\n"


def long_hosts(count: int = 100, length: int = 2000) -> str:
    host = "a" * length + ".com"
    links = "\n".join(f"http://{host}/{i}" for i in range(count))
    return f"From: a@evil.example\nSubject: links\n\n{links}\n"


def huge_header(length: int = 500_000) -> str:
    return f"From: a@evil.example\nSubject: {'A' * length}\n\nbody\n"


def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


GENERATORS = {
    "deep_mime": deep_mime,
    "many_parts": many_parts,
    "redos_body": redos_body,
    "long_hosts": long_hosts,
    "huge_header": huge_header,
}


def nested(depth: int, leaf: dict[str, Any]) -> dict[str, Any]:
    d: dict[str, Any] = leaf
    for _ in range(depth):
        d = {"n": d}
    return d


def expand(value: Any) -> Any:
    """Small DSL inside YAML: {"$b64": "..."} -> base64 text, {"$nested": {depth, leaf}} -> deep dict,
    {"$repeat": {s, n}} -> long string."""
    if isinstance(value, dict):
        if "$b64" in value:
            return b64(value["$b64"])
        if "$nested" in value:
            return nested(value["$nested"]["depth"], expand(value["$nested"]["leaf"]))
        if "$repeat" in value:
            return value["$repeat"]["s"] * value["$repeat"]["n"]
        if "$concat" in value:
            return "".join(str(expand(x)) for x in value["$concat"])
        return {k: expand(v) for k, v in value.items()}
    if isinstance(value, list):
        return [expand(v) for v in value]
    return value
