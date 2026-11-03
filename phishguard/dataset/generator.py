"""Synthetic email dataset: collaboration (benign), BEC fraud, payment chasing (mixed). Seeded."""

from __future__ import annotations

import json
import random
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from ..models import EmailMessage

INTERNAL = "acme-corp.com"
VENDORS = ["globalsupply.com", "brightlogistics.com", "northwind-parts.com", "summitcloud.io", "bluepeak-print.com"]
TRUSTED_DOMAINS = (INTERNAL, *VENDORS)
EXECUTIVES = ("David Chen", "Sarah Miller")
STAFF = ["li.wei", "anna.k", "tom.r", "priya.s", "jun.park", "maria.g", "omar.h"]
FINANCE = ["finance", "ap.team"]
BASE_TIME = datetime(2026, 3, 2, 9, 0, tzinfo=UTC)  # a Monday

CATEGORIES = ("collaboration", "bec", "payment_chasing")


@dataclass
class LabeledEmail:
    email: EmailMessage
    category: str
    label: int  # 1 = phishing/fraud, 0 = legitimate

    def to_dict(self) -> dict:
        return {"category": self.category, "label": self.label, "email": self.email.model_dump(mode="json")}


def _lookalike(rng: random.Random, domain: str) -> str:
    name, tld = domain.rsplit(".", 1)
    tricks = [
        lambda n: n.replace("o", "0", 1) if "o" in n else n + "s",
        lambda n: n.replace("m", "rn", 1) if "m" in n else n + "-co",
        lambda n: n.replace("l", "1", 1) if "l" in n else n + "x",
        lambda n: n + "-group",
        lambda n: n.replace("-", "", 1) if "-" in n else n + "s",
    ]
    new = rng.choice(tricks)(name)
    if new == name:
        new += "s"
    return f"{new}.{rng.choice(['com', 'net', 'co'])}" if rng.random() < 0.25 else f"{new}.{tld}"


def _ts(rng: random.Random, business: bool = True) -> datetime:
    day = rng.randint(0, 90)
    t = BASE_TIME + timedelta(days=day, minutes=rng.randint(0, 600))  # 09:00-19:00
    if not business:
        t = t.replace(hour=rng.choice([2, 3, 5, 21, 22, 23]), minute=rng.randint(0, 59))
    return t


def _collaboration(rng: random.Random, i: int) -> LabeledEmail:
    a, b = rng.sample(STAFF, 2)
    kind = rng.choice(["meeting", "review", "schedule", "invoice_batch", "urgent_fix", "external_doc"])
    subj, body, links = {
        "meeting": ("Notes from Monday sync", "Hi, attached are the notes. Next sync is Thursday 10:00. Thanks!", []),
        "review": (
            "Review request: design doc v2",
            "Could you review the design doc when you get a chance? Comments welcome.",
            [],
        ),
        "schedule": ("Sprint planning moved", "Planning is moved to 14:00 tomorrow. Room 4B.", []),
        "invoice_batch": (
            "Q1 invoice batch ready",
            "The invoice batch is in the shared finance folder. Please review before payment run on Friday.",
            [],
        ),
        "urgent_fix": (
            "Urgent: staging build is red",
            "The staging build is failing, please look immediately if you are free. Logs in the pipeline.",
            [],
        ),
        "external_doc": (
            "Shared doc for the workshop",
            "Here is the doc for the workshop agenda.",
            ["https://docs.google.com/document/d/abc123"],
        ),
    }[kind]
    ext_partner = rng.random() < 0.06
    dom = rng.choice(VENDORS) if ext_partner else INTERNAL
    rep = rng.uniform(0.5, 0.7) if ext_partner else rng.uniform(0.8, 1.0)
    spf = "none" if rng.random() < 0.06 else "pass"
    em = EmailMessage(
        id=f"collab-{i}",
        timestamp=_ts(rng, business=rng.random() > 0.08),
        sender_name=a.replace(".", " ").title(),
        sender_email=f"{a}@{dom}",
        recipient=f"{b}@{INTERNAL}",
        subject=subj,
        body=body,
        links=links,
        sender_reputation=round(rep, 2),
        sender_domain_age_days=rng.randint(1000, 4000),
        spf=spf,
        dkim="pass" if spf == "pass" else "none",
        dmarc="pass" if spf == "pass" else "none",
    )
    return LabeledEmail(em, "collaboration", 0)


def _bec(rng: random.Random, i: int) -> LabeledEmail:
    ex = rng.choice(EXECUTIVES)
    first = ex.split()[0].lower()
    variant = rng.choices(["lookalike", "freemail", "compromised"], weights=[45, 40, 15])[0]
    ask = rng.choice(
        [
            "I need you to process a wire transfer today. Keep this confidential until it is done.",
            "Please purchase gift cards for a client event and send me the codes. Do not discuss this with others.",
            "I'm in a meeting and can't talk. Urgent: transfer the payment to the account below and reply when done.",
            "We are closing a confidential acquisition. Wire the deposit immediately, details to follow.",
        ]
    )
    common = dict(
        id=f"bec-{i}",
        timestamp=_ts(rng, business=rng.random() > 0.5),
        sender_name=ex,
        recipient=f"{rng.choice(FINANCE)}@{INTERNAL}",
        subject=rng.choice(["Quick favour", "Urgent request", "Are you available?"]),
        body=f"Hi, it's {first}. {ask}",
    )
    if variant == "lookalike":
        dom = _lookalike(rng, INTERNAL)
        em = EmailMessage(
            **common,
            sender_email=f"{first}@{dom}",
            reply_to=f"{first}.ceo@{rng.choice(['gmail.com', 'outlook.com'])}" if rng.random() < 0.6 else None,
            sender_reputation=round(rng.uniform(0.02, 0.4), 2),
            sender_domain_age_days=rng.randint(1, 60),
            spf="fail",
            dkim=rng.choice(["fail", "none"]),
            dmarc="fail",
        )
    elif variant == "freemail":
        em = EmailMessage(
            **common,
            sender_email=f"{first}.{ex.split()[1].lower()}@{rng.choice(['gmail.com', 'outlook.com', 'qq.com'])}",
            sender_reputation=round(rng.uniform(0.1, 0.5), 2),
            sender_domain_age_days=6000,
            spf=rng.choice(["pass", "none"]),
            dkim="none",
            dmarc="none",
        )
    else:  # compromised real mailbox: hard case, only the wording gives it away
        s = rng.choice(STAFF)
        em = EmailMessage(
            **{**common, "sender_name": s.replace(".", " ").title()},
            sender_email=f"{s}@{INTERNAL}",
            sender_reputation=round(rng.uniform(0.6, 0.9), 2),
            sender_domain_age_days=3000,
            spf="pass",
            dkim="pass",
            dmarc="pass",
        )
    return LabeledEmail(em, "bec", 1)


def _payment_chasing(rng: random.Random, i: int) -> LabeledEmail:
    vendor = rng.choice(VENDORS)
    inv = f"INV-{rng.randint(1000, 9999)}"
    amount = rng.randint(800, 48000)
    fraud = rng.random() < 0.5
    base = dict(id=f"pay-{i}", recipient=f"ap.team@{INTERNAL}", sender_name=vendor.split(".")[0].title() + " Billing")
    if not fraud:
        em = EmailMessage(
            **base,
            timestamp=_ts(rng, business=rng.random() > 0.1),
            sender_email=f"billing@{vendor}",
            subject=f"Payment reminder for {inv}",
            body=rng.choice(
                [
                    f"Our records show invoice {inv} for ${amount} is overdue. Please pay to the bank account on file by month end.",
                    f"Friendly reminder: invoice {inv} (${amount}) is due. Remittance details are unchanged.",
                    f"Final notice: invoice {inv} is overdue. Please arrange payment this week.",
                ]
            ),
            sender_reputation=round(rng.uniform(0.7, 0.95), 2),
            sender_domain_age_days=rng.randint(800, 5000),
            spf="pass",
            dkim="pass",
            dmarc=rng.choice(["pass", "none"]),
            links=[f"https://{vendor}/portal/{inv}"] if rng.random() < 0.5 else [],
        )
        return LabeledEmail(em, "payment_chasing", 0)
    hard = rng.random() < 0.2
    dom = _lookalike(rng, vendor)
    body = rng.choice(
        [
            f"Invoice {inv} for ${amount} is overdue. Our bank details have changed, please pay to the new account number below immediately to avoid penalties.",
            f"Final notice: payment of ${amount} for {inv} outstanding. Use the updated bank account information attached. Respond within 24 hours.",
            f"URGENT: legal action will follow if invoice {inv} is not paid today. New payment instructions attached.",
        ]
    )
    if hard:  # well-formed fraud: decent reputation, auth pass, only the bank-change wording is off
        em = EmailMessage(
            **base,
            timestamp=_ts(rng),
            sender_email=f"billing@{vendor}",
            reply_to=f"billing@{dom}",
            subject=f"Updated payment instructions {inv}",
            body=body,
            sender_reputation=round(rng.uniform(0.6, 0.85), 2),
            sender_domain_age_days=2000,
            spf="pass",
            dkim="pass",
            dmarc="pass",
        )
    else:
        em = EmailMessage(
            **base,
            timestamp=_ts(rng, business=rng.random() > 0.4),
            sender_email=f"billing@{dom}",
            subject=f"OVERDUE {inv} - action required",
            body=body,
            links=[f"http://{rng.choice(['bit.ly/x' + str(i), '185.23.4.' + str(rng.randint(2, 250)) + '/pay'])}"],
            attachments=[rng.choice([f"{inv}.pdf.exe", f"{inv}.html", f"{inv}.pdf"])],
            sender_reputation=round(rng.uniform(0.03, 0.45), 2),
            sender_domain_age_days=rng.randint(2, 70),
            spf=rng.choice(["fail", "none"]),
            dkim=rng.choice(["fail", "none"]),
            dmarc=rng.choice(["fail", "none"]),
        )
    return LabeledEmail(em, "payment_chasing", 1)


_GEN = {"collaboration": _collaboration, "bec": _bec, "payment_chasing": _payment_chasing}


def generate_dataset(n_per_category: int = 100, seed: int = 42) -> list[LabeledEmail]:
    rng = random.Random(seed)
    out = [_GEN[c](rng, i) for c in CATEGORIES for i in range(n_per_category)]
    rng.shuffle(out)
    return out


def write_jsonl(items: list[LabeledEmail], path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for it in items:
            f.write(json.dumps(it.to_dict(), ensure_ascii=False) + "\n")
