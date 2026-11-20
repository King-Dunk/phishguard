"""Customization-tier test set: phishing at four levels of targeting, each with a look-alike legitimate set.

    python -m phishguard.dataset.tiers --out data/tiers --n 100     # write .eml files + manifest.jsonl

Design, fixed before anything was measured (results in docs/EVAL_SETS.md; weights were not tuned on this set).
The tiers follow the two difficulty factors of the NIST Phish Scale (Steves, Greene & Theofanos 2020; NIST TN 2276,
2023): how many observable cues a message carries, and how well its premise fits the recipient's work. As the
attacker customizes more, cues go down and alignment goes up:

  T1 mass      many cues, no alignment       "mailbox full / verify your account", generic greeting, misspellings,
                                             raw IP or random hosts, spoofed or failing authentication
  T2 brand     some cues, generic fit         polished clones of common service notices (Microsoft 365, DocuSign,
                                             DHL, Google Drive, PayPal, voicemail), attacker-owned domains that pass
                                             their own SPF/DKIM, links on free cloud hosting, QR-code lures
  T3 spear     few cues, high alignment       knows names, vendors, projects and invoice numbers; look-alike vendor
                                             domain or a free-mail account posing as an executive
  T4 tailored  almost no cues, full fit       sent from a really compromised vendor or colleague mailbox (real
                                             domain, SPF/DKIM/DMARC pass), continues a real thread, fluent, no
                                             links and no pressure words: what an LLM-assisted attacker writes

Each tier has a matched legitimate control set: L1 newsletters and promotions, L2 genuine service notices, L3
genuine vendor and colleague mail about invoices and documents, L4 genuine thread replies about payments,
including a vendor's real change of bank details. Recall per tier and false-positive rate per control set show
where content-based detection stops working.

Every message is built as raw RFC 822 bytes and goes through the same parser as real mail. No sender reputation or
domain age is injected: a deployment doesn't get those from the message. Each item also lists the cues that were
deliberately planted (`cues`: red flags in NIST Phish Scale terms, independent of PhishGuard's rule names) and, in
`meta["alignment"]`, how it fits the recipient's context, so results can be read against cue count. The organisation, people and vendors are the same fictional ones as generator.py;
attacker infrastructure uses random tokens, so no real third-party domain is labelled malicious.
"""

# ruff: noqa: E501 - message templates are long string literals; wrapping them would hurt readability
from __future__ import annotations

import argparse
import json
import pathlib
import random
import string
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage as MimeMessage
from email.utils import format_datetime

from .generator import EXECUTIVES, INTERNAL, TRUSTED_DOMAINS, VENDORS

TIERS = ("T1", "T2", "T3", "T4")
TIER_NAMES = {
    "T1": "mass / generic",
    "T2": "brand impersonation",
    "T3": "spear (targeted)",
    "T4": "tailored / compromised account",
}
CONTROL_NAMES = {
    "T1": "newsletters & promotions",
    "T2": "genuine service notices",
    "T3": "genuine vendor & colleague mail",
    "T4": "genuine payment threads",
}
STAFF = [
    ("Li Wei", "li.wei"),
    ("Anna Kowalski", "anna.k"),
    ("Tom Reyes", "tom.r"),
    ("Priya Shah", "priya.s"),
    ("Jun Park", "jun.park"),
    ("Maria Garcia", "maria.g"),
    ("Omar Hassan", "omar.h"),
]
VENDOR_NAMES = {
    "globalsupply.com": "Global Supply Co",
    "brightlogistics.com": "Bright Logistics",
    "northwind-parts.com": "Northwind Parts",
    "summitcloud.io": "SummitCloud",
    "bluepeak-print.com": "BluePeak Print",
}
VENDOR_PEOPLE = [("Sam Turner", "sam.turner"), ("Jess Nguyen", "jess.nguyen"), ("Ravi Patel", "ravi.patel")]
PROJECTS = ["Q3 freight contract", "warehouse expansion", "cloud migration", "annual print run", "spare-parts tender"]
BANKS = ["Westpac", "ANZ", "NAB", "Commonwealth Bank", "Macquarie"]
FREEMAIL = ["gmail.com", "outlook.com", "yahoo.com", "icloud.com"]
BASE = datetime(2026, 5, 4, 9, 0, tzinfo=UTC)  # a Monday; the context's working hours are UTC

assert set(VENDORS) == set(VENDOR_NAMES) and len(EXECUTIVES) == 2  # keep in step with generator.py


@dataclass
class TierItem:
    tier: str
    label: int  # 1 phishing, 0 legitimate control
    scenario: str
    cues: list[str]
    raw: bytes
    meta: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------- building blocks
def _tok(rng: random.Random, n: int = 8) -> str:
    return "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def _msgid(rng: random.Random, domain: str) -> str:
    return f"<{_tok(rng, 12)}.{_tok(rng, 8)}@{domain}>"


def _when(rng: random.Random, business: bool = True) -> datetime:
    t = BASE + timedelta(days=rng.randint(0, 120))
    while t.weekday() >= 5:  # business mail on weekdays
        t += timedelta(days=1)
    if business:
        return t.replace(hour=rng.randint(9, 16), minute=rng.randint(0, 59))
    return t.replace(hour=rng.choice([1, 2, 3, 4, 22, 23]), minute=rng.randint(0, 59))


def _staff(rng: random.Random) -> tuple[str, str, str]:
    name, local = rng.choice(STAFF)
    return name, name.split()[0], f"{local}@{INTERNAL}"


def _auth(spf: str, dkim: str, dmarc: str, mailfrom: str, d: str, frm: str) -> str:
    return (
        f"mx.{INTERNAL}; spf={spf} smtp.mailfrom={mailfrom}; dkim={dkim} header.d={d}; dmarc={dmarc} header.from={frm}"
    )


def _free_host(rng: random.Random) -> str:
    t = _tok(rng, rng.randint(6, 10))
    return rng.choice(
        [
            f"https://{t}.web.app/",
            f"https://{t}.pages.dev/",
            f"https://{t}.workers.dev/",
            f"https://pub-{t}.r2.dev/index.html",
            f"https://{t}.firebaseapp.com/",
            f"https://storage.googleapis.com/{t}/index.html",
            f"https://{t}.blob.core.windows.net/$web/index.html",
            f"https://{t}.edgeone.app/",
            f"https://{t}.netlify.app/",
            f"https://docs.google.com/forms/d/e/1FAIpQL{t}/viewform",
        ]
    )


def _attacker_domain(rng: random.Random) -> str:
    word = rng.choice(["notify", "mailsvc", "secure", "alerts", "docs", "cloud", "account", "portal"])
    return f"{word}-{_tok(rng, 6)}.{rng.choice(['com', 'net', 'info', 'online', 'top', 'live'])}"


def _lookalike(rng: random.Random, domain: str) -> str:
    name, tld = domain.rsplit(".", 1)
    for trick in rng.sample(
        [
            lambda n: n.replace("o", "0", 1),
            lambda n: n.replace("l", "1", 1),
            lambda n: n.replace("m", "rn", 1),
            lambda n: n.replace("i", "l", 1),
            lambda n: n.replace("-", "", 1),
            lambda n: n + "-au",
            lambda n: n + "s",
        ],
        7,
    ):
        new = trick(name)
        if new != name:
            return f"{new}.{rng.choice([tld, tld, 'co', 'net'])}"
    return f"{name}s.{tld}"


def _html(paragraphs: list[str], button: tuple[str, str] | None = None, footer: str = "", brand: str = "") -> str:
    head = f'<div style="font:20px Arial;font-weight:bold;padding:12px 0">{brand}</div>' if brand else ""
    body = "".join(f'<p style="font:14px Arial;color:#222">{p}</p>' for p in paragraphs)
    btn = ""
    if button:
        btn = (
            f'<p><a href="{button[1]}" style="background:#0b5cad;color:#ffffff;padding:10px 18px;'
            f'text-decoration:none;font:bold 14px Arial;border-radius:4px">{button[0]}</a></p>'
        )
    foot = f'<p style="font:11px Arial;color:#888">{footer}</p>' if footer else ""
    return f'<html><body style="background:#f4f4f4"><div style="max-width:600px;background:#ffffff;padding:24px">{head}{body}{btn}{foot}</div></body></html>'


def _mail(
    rng: random.Random,
    *,
    display: str,
    sender: str,
    to: str,
    subject: str,
    text: str,
    html: str | None = None,
    when: datetime | None = None,
    auth: str | None = None,
    reply_to: str | None = None,
    return_path: str | None = None,
    list_mail: bool = False,
    thread: str | None = None,
    attachments: list[tuple[str, str, bytes]] | None = None,
) -> bytes:
    m = MimeMessage()
    m["From"] = f"{display} <{sender}>" if display else sender
    m["To"] = to
    m["Subject"] = subject
    m["Date"] = format_datetime(when or _when(rng))
    m["Message-ID"] = _msgid(rng, sender.rsplit("@", 1)[-1])
    m["Return-Path"] = f"<{return_path or sender}>"
    if auth:
        m["Authentication-Results"] = auth
    if reply_to:
        m["Reply-To"] = reply_to
    if thread:
        m["In-Reply-To"] = thread
        m["References"] = thread
    if list_mail:
        dom = sender.rsplit("@", 1)[-1]
        m["List-Unsubscribe"] = f"<https://{dom}/unsubscribe?u={_tok(rng, 12)}>, <mailto:unsubscribe@{dom}>"
        m["List-Unsubscribe-Post"] = "List-Unsubscribe=One-Click"
        m["Precedence"] = "bulk"
    m.set_content(text)
    if html:
        m.add_alternative(html, subtype="html")
    for name, ctype, data in attachments or []:
        maintype, subtype = ctype.split("/", 1)
        m.add_attachment(data, maintype=maintype, subtype=subtype, filename=name)
    for part in m.walk():  # the stdlib draws MIME boundaries from the global RNG: pin them to ours
        if part.is_multipart():
            part.set_boundary(f"===============_{_tok(rng, 20)}==")
    return bytes(m)


PDF = b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n"


# ---------------------------------------------------------------------------- T1 mass phishing
def t1(rng: random.Random) -> TierItem:
    name, first, to = _staff(rng)
    spoof_internal = rng.random() < 0.4
    if spoof_internal:
        display, sender = rng.choice(["IT Helpdesk", "Mail Administrator", "System Admin"]), f"admin@{INTERNAL}"
        auth = _auth("fail", "none", "fail", f"x{_tok(rng, 4)}@{_attacker_domain(rng)}", INTERNAL, INTERNAL)
        cues = ["spoofed_sender", "auth_fail"]
    else:
        dom = _attacker_domain(rng) if rng.random() < 0.5 else rng.choice(FREEMAIL)
        display, sender = (
            rng.choice(["Mail Server", "Account Team", "Support Desk", "Webmail"]),
            f"{_tok(rng, 7)}@{dom}",
        )
        auth = _auth(rng.choice(["softfail", "none", "pass"]), "none", "none", sender, dom, dom)
        cues = ["unknown_sender"]
    link = f"http://{rng.randint(45, 211)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}/{_tok(rng, 5)}/login.php"
    if rng.random() < 0.5:
        link = f"https://{_tok(rng, 9)}.{rng.choice(['xyz', 'top', 'click', 'buzz'])}/owa/?{to}"
    scenario = rng.choice(["quota", "deactivation", "pending_mail", "password_expiry", "voicemail"])
    greet = rng.choice(["Dear User,", "Dear Valued Customer,", f"Dear {to},", "Attention:"])
    misspelled = rng.random() < 0.7
    acct = "acount" if misspelled else "account"
    verify = "verfy" if misspelled else "verify"
    texts = {
        "quota": (
            "Mailbox Storage Full - Action Required",
            f"{greet}\nYour mailbox has exceeded the storage limit of 2GB. You will not be able to send or recieve new messages "
            f"untill you {verify} your {acct}. Click here to increase storage immediately: {link}\nFailure to do so within 24 hours will result in permanent deletion.\nMail Administrator",
        ),
        "deactivation": (
            "Final Notice: Your Account Will Be Deactivated",
            f"{greet}\nWe detected unusual activities on your {acct}. Your {acct} will be deactivated today unless you "
            f"{verify} your login details here: {link}\nThis is your final warning.\nSecurity Team",
        ),
        "pending_mail": (
            f"You have ({rng.randint(4, 17)}) pending incoming messages",
            f"{greet}\nSome messages for {to} were held due to a sync error. Release your pending messages now: {link}\n"
            f"Messages not released within 48 hours will be deleted.\nEmail Service",
        ),
        "password_expiry": (
            f"Password Expiration Notice for {to}",
            f"{greet}\nThe password for {to} expires today. Keep your current password by confirming it below.\n"
            f"Keep Same Password: {link}\nIgnore this and you will loose access to your {acct}.\nIT Support",
        ),
        "voicemail": (
            f"New Voicemail Received ({rng.randint(0, 1)}:{rng.randint(10, 59)} sec)",
            f"{greet}\nYou have a new voice message from +61 4{rng.randint(10, 99)} {rng.randint(100, 999)} {rng.randint(100, 999)}. "
            f"Listen to your voicemail: {link}\nVoice Mail System",
        ),
    }
    subject, text = texts[scenario]
    html = _html(text.split("\n")[1:-1], ("Verify Now" if scenario != "voicemail" else "Play Message", link))
    cues += [
        "generic_greeting" if greet != f"Dear {to}," else "email_as_name",
        "urgency",
        "threat",
        "credential_request",
    ]
    cues += ["suspicious_link"] + (["spelling_errors"] if misspelled else [])
    atts = None
    if scenario == "voicemail" and rng.random() < 0.5:
        atts = [(f"VM_{_tok(rng, 5)}.html", "text/html", f'<script>location="{link}"</script>'.encode())]
        cues.append("risky_attachment")
    when = _when(rng, business=rng.random() < 0.5)
    if when.hour < 9 or when.hour > 17:
        cues.append("off_hours")
    raw = _mail(
        rng,
        display=display,
        sender=sender,
        to=to,
        subject=subject,
        text=text,
        html=html,
        when=when,
        auth=auth,
        attachments=atts,
    )
    return TierItem("T1", 1, scenario, cues, raw)


# ---------------------------------------------------------------------------- T2 brand impersonation
BRANDS = {
    "m365": ("Microsoft 365", "microsoft.com", "account-security-noreply@accountprotection.microsoft.com"),
    "docusign": ("DocuSign", "docusign.net", "dse@docusign.net"),
    "dhl": ("DHL Express", "dhl.com", "noreply@dhl.com"),
    "gdrive": ("Google Drive", "google.com", "drive-shares-dm-noreply@google.com"),
    "paypal": ("PayPal", "paypal.com", "service@paypal.com"),
    "voicemail": ("Microsoft Teams", "microsoft.com", "noreply@email.teams.microsoft.com"),
}


def t2(rng: random.Random) -> TierItem:
    name, first, to = _staff(rng)
    brand_key = rng.choice(list(BRANDS))
    brand, real_dom, _ = BRANDS[brand_key]
    dom = _attacker_domain(rng)
    sender = f"{rng.choice(['no-reply', 'notification', 'service', 'info'])}@{dom}"
    auth = _auth(
        "pass", "pass", rng.choice(["pass", "none"]), sender, dom, dom
    )  # attackers authenticate their own domain
    cues = ["brand_display_name", "unknown_sender_domain"]
    link = _free_host(rng) + (f"#{to}" if rng.random() < 0.5 else "")
    quishing = rng.random() < 0.2
    doc = rng.choice(["Q3_Remittance.pdf", "Signed_Agreement.pdf", "Payroll_Adjustment.xlsx", "Invoice_7741.pdf"])
    copy = {
        "m365": (
            "Action required: verify your Microsoft 365 sign-in",
            [
                f"Hi {first},",
                "We noticed a sign-in attempt that we couldn't verify. To keep your account secure, please review recent activity and confirm it was you.",
                "If you don't review within 24 hours, access to Outlook and Teams will be limited.",
            ],
            "Review activity",
        ),
        "docusign": (
            f"Completed: Please DocuSign {doc}",
            [
                f"{rng.choice(['Accounts Payable', 'HR Department', 'Legal'])} sent you a document to review and sign.",
                f"Document: {doc}",
                "Please review and sign at your earliest convenience.",
            ],
            "REVIEW DOCUMENT",
        ),
        "dhl": (
            f"DHL Shipment Notification: AWB {rng.randint(10**9, 10**10 - 1)}",
            [
                f"Dear {first},",
                "Your parcel is on hold at our facility because of an unpaid customs fee of AUD 3.95.",
                "Please confirm delivery details and pay the fee to release your shipment.",
            ],
            "Schedule delivery",
        ),
        "gdrive": (
            f'{rng.choice(["Accounts", "Finance Team", "Sam Turner"])} shared "{doc}" with you',
            [
                f"{rng.choice(['Accounts', 'Finance Team'])} has invited you to view the following file:",
                doc,
                "Open the file to view it in Google Drive.",
            ],
            "Open",
        ),
        "paypal": (
            "Your account access has been limited",
            [
                f"Hello {first},",
                "We've noticed some unusual activity and temporarily limited what you can do with your account.",
                "Please confirm your information to restore full access.",
            ],
            "Confirm information",
        ),
        "voicemail": (
            "You missed a call: voicemail (0:42)",
            [
                f"Hi {first},",
                "You have a new voicemail from an external caller.",
                "Sign in to listen to the message in Teams.",
            ],
            "Play voicemail",
        ),
    }[brand_key]
    subject, paras, cta = copy
    cues += (
        ["credential_request"]
        if brand_key in ("m365", "paypal", "voicemail", "gdrive", "docusign")
        else ["payment_request"]
    )
    if "24 hours" in " ".join(paras) or brand_key in ("paypal", "dhl"):
        cues.append("urgency")
    if quishing:
        html = _html(
            paras + ["Scan the QR code below with your phone camera to continue."],
            footer=f"© 2026 {brand}",
            brand=brand,
        )
        html = html.replace(
            "</div></body>",
            f'<img src="https://{_tok(rng, 8)}.r2.dev/qr.png" width="180" height="180" alt=""></div></body>',
        )
        text = "\n".join(paras) + "\nScan the QR code to continue."
        cues.append("qr_code")
    else:
        disguise = rng.random() < 0.6  # visible text shows the real brand domain
        label = f"https://www.{real_dom}/" if disguise else cta
        html = _html(paras, (label, link), footer=f"© 2026 {brand}. All rights reserved.", brand=brand)
        text = "\n".join(paras) + f"\n{cta}: {link}"
        cues.append("link_mismatch" if disguise else "suspicious_link")
    raw = _mail(
        rng,
        display=brand,
        sender=sender,
        to=to,
        subject=subject,
        text=text,
        html=html,
        auth=auth,
        when=_when(rng, rng.random() < 0.7),
    )
    return TierItem("T2", 1, brand_key + ("_qr" if quishing else ""), cues, raw)


# ---------------------------------------------------------------------------- T3 spear phishing
def t3(rng: random.Random) -> TierItem:
    name, first, to = _staff(rng)
    vendor = rng.choice(VENDORS)
    vname = VENDOR_NAMES[vendor]
    vperson, vlocal = rng.choice(VENDOR_PEOPLE)
    inv = f"INV-{rng.randint(2000, 9999)}"
    amount = f"{rng.randint(4, 95) * 1000 + rng.choice([0, 250, 480, 900]):,}.{rng.choice(['00', '50', '20'])}"
    project = rng.choice(PROJECTS)
    scenario = rng.choice(["vendor_bank_change", "vendor_doc_link", "exec_payment", "exec_giftcards", "payroll_change"])
    cues: list[str] = []  # red flags only; personalization is premise alignment, recorded in meta
    reply_to = None
    when = _when(rng)
    if scenario in ("vendor_bank_change", "vendor_doc_link"):
        dom = _lookalike(rng, vendor)
        sender = f"{vlocal}@{dom}"
        display = f"{vperson} | {vname}"
        auth = _auth("pass", "pass", "pass", sender, dom, dom)
        cues.append("lookalike_domain")
        if scenario == "vendor_bank_change":
            subject = rng.choice(
                [
                    f"Updated remittance details - {inv}",
                    f"{inv} - change of bank account",
                    f"Re: {project} - payment details",
                ]
            )
            text = (
                f"Hi {first},\n\nHope your week is going well. Ahead of the payment run for {inv} (AUD {amount}), please note that "
                f"{vname} has moved its banking to {rng.choice(BANKS)}. Kindly update our details before processing:\n\n"
                f"Account name: {vname} Pty Ltd\nBSB: {rng.randint(10, 99)}{rng.randint(0, 9)}-{rng.randint(100, 999)}\nAccount: {rng.randint(10**7, 10**8 - 1)}\n\n"
                f"Our old account will be closed at the end of the month. Let me know once updated.\n\nKind regards,\n{vperson}\nAccounts | {vname}"
            )
            cues += ["bank_change", "payment_request"]
            atts = [("Bank_Details_Letter.pdf", "application/pdf", PDF)] if rng.random() < 0.5 else None
            raw = _mail(
                rng,
                display=display,
                sender=sender,
                to=to,
                subject=subject,
                text=text,
                when=when,
                auth=auth,
                attachments=atts,
            )
        else:
            link = rng.choice(
                [
                    _free_host(rng),
                    f"https://{vendor.split('.')[0].replace('-', '')}-{_tok(rng, 4)}.sharepoint.com/:b:/g/{_tok(rng, 12)}",
                ]
            )
            subject = rng.choice(
                [
                    f"{project} - revised terms for review",
                    f"Shared: {project} pricing schedule",
                    f"{inv} statement and updated terms",
                ]
            )
            paras = [
                f"Hi {first},",
                f"As discussed, I've shared the revised {project} documents for your review. You'll need to sign in with your work account to open them.",
                f"Thanks,<br>{vperson}<br>{vname}",
            ]
            text = f"Hi {first},\n\nAs discussed, I've shared the revised {project} documents for your review: {link}\nYou'll need to sign in with your work account to open them.\n\nThanks,\n{vperson}\n{vname}"
            raw = _mail(
                rng,
                display=display,
                sender=sender,
                to=to,
                subject=subject,
                text=text,
                html=_html(paras, ("View documents", link)),
                when=when,
                auth=auth,
            )
            cues += ["credential_request", "suspicious_link"]
    else:
        ex = rng.choice(EXECUTIVES)
        exfirst = ex.split()[0]
        free = rng.choice(FREEMAIL)
        sender = f"{ex.lower().replace(' ', '.')}.{rng.choice(['office', 'ceo', 'mobile', 'private'])}@{free}"
        display = ex
        auth = _auth("pass", "pass", "pass", sender, free, free)
        cues += ["exec_impersonation", "freemail_sender"]
        if scenario == "exec_payment":
            subject = rng.choice(["Quick favour", f"{project} - payment today", "Are you at your desk?"])
            text = (
                f"Hi {first},\n\nI'm tied up in meetings for the {project} all afternoon. We need to settle a deposit with a new supplier today to "
                f"lock in pricing - AUD {amount}. Can you process it? I'll send the details as soon as you confirm. Please keep this between us "
                f"until it's announced.\n\n{exfirst}\nSent from my iPhone"
            )
            cues += ["payment_request", "urgency", "secrecy"]
        elif scenario == "exec_giftcards":
            subject = rng.choice(["Need your help", "Small request", "Staff appreciation"])
            text = (
                f"Hi {first},\n\nAre you available? I need to get {rng.choice([5, 8, 10])} Apple gift cards (AUD 200 each) for the team as a surprise "
                f"thank-you for the {project}. Can you pick them up and send me the codes? I'll reimburse you today.\n\nThanks,\n{exfirst}"
            )
            cues += ["payment_request", "unusual_request"]
        else:
            subject = rng.choice(["Direct deposit update", "Change of payroll account", "Bank details for next pay"])
            text = (
                f"Hi {first},\n\nI've switched banks. Could you update my salary account before the next pay run?\n\n"
                f"BSB {rng.randint(10, 99)}{rng.randint(0, 9)}-{rng.randint(100, 999)}  Account {rng.randint(10**7, 10**8 - 1)}\n\nThanks,\n{exfirst}"
            )
            cues += ["bank_change"]
        if rng.random() < 0.5:
            reply_to = f"{exfirst.lower()}.{_tok(rng, 4)}@{rng.choice(FREEMAIL)}"
            cues.append("reply_to_differs")
        raw = _mail(
            rng,
            display=display,
            sender=sender,
            to=to,
            subject=subject,
            text=text,
            when=when,
            auth=auth,
            reply_to=reply_to,
        )
    return TierItem("T3", 1, scenario, cues, raw, {"alignment": ["personalized"]})


# ---------------------------------------------------------------------------- T4 tailored, compromised account
T4_ALIGNMENT = ("personalized", "thread_continuation")


def t4(rng: random.Random) -> TierItem:
    name, first, to = _staff(rng)
    vendor = rng.choice(VENDORS)
    vname = VENDOR_NAMES[vendor]
    vperson, vlocal = rng.choice(VENDOR_PEOPLE)
    inv = f"INV-{rng.randint(2000, 9999)}"
    project = rng.choice(PROJECTS)
    scenario = rng.choice(["thread_bank_change", "thread_info_gathering", "internal_favour", "thread_doc_share"])
    cues: list[str] = []  # red flags only; see T4_ALIGNMENT
    thread = _msgid(rng, INTERNAL)
    when = _when(rng)
    if scenario == "internal_favour":
        colleague, clocal = rng.choice([s for s in STAFF if s[1] not in to])
        sender = f"{clocal}@{INTERNAL}"
        auth = _auth("pass", "pass", "pass", sender, INTERNAL, INTERNAL)
        subject = rng.choice(
            [f"Re: {project} supplier payment", f"Re: {project} catch-up", "Re: invoices for this week"]
        )
        text = (
            f"Hey {first},\n\nThanks for sorting the PO earlier. One more from my side: the supplier we spoke about for the {project} sent their "
            f"invoice to me instead of AP. I've put the details in the sheet - could you add it to Friday's run? It's the one for AUD "
            f"{rng.randint(6, 40) * 1000:,}. I'll be in workshops most of tomorrow so email is easiest.\n\nCheers,\n{colleague.split()[0]}"
        )
        cues.append("payment_request")
        raw = _mail(
            rng,
            display=colleague,
            sender=sender,
            to=to,
            subject=subject,
            text=text,
            when=when,
            auth=auth,
            thread=thread,
        )
        return TierItem("T4", 1, scenario, cues, raw, {"alignment": list(T4_ALIGNMENT)})
    sender = f"{vlocal}@{vendor}"
    auth = _auth("pass", "pass", "pass", sender, vendor, vendor)
    display = vperson
    quote = f"\n\n> On {format_datetime(when - timedelta(days=2))[:16]}, {name} wrote:\n> Thanks {vperson.split()[0]}, we've received {inv} and it's scheduled for the next run.\n"
    if scenario == "thread_bank_change":
        subject = f"Re: {inv} - {project}"
        text = (
            f"Thanks {first}, appreciate it.\n\nOne thing before it goes out - after our audit we've consolidated our accounts with "
            f"{rng.choice(BANKS)}, so the remittance for {inv} should go to the account in the attached letter rather than the one on file. "
            f"Our finance manager has signed it off. Happy to send it on letterhead if that helps your process.\n\nCheers,\n{vperson.split()[0]}"
            + quote
        )
        cues.append("bank_change")
        raw = _mail(
            rng,
            display=display,
            sender=sender,
            to=to,
            subject=subject,
            text=text,
            when=when,
            auth=auth,
            thread=thread,
            attachments=[("Remittance_Update.pdf", "application/pdf", PDF)],
        )
    elif scenario == "thread_info_gathering":
        subject = f"Re: {project} - reconciliation"
        text = (
            f"Hi {first},\n\nThanks again. While I have you - we're reconciling before quarter end. Could you send me a list of the open {vname} "
            f"invoices on your side with amounts and the remittance account you have on file for us? Want to make sure nothing is going to the "
            f"old details.\n\nThanks,\n{vperson.split()[0]}" + quote
        )
        cues.append("information_request")
        raw = _mail(
            rng, display=display, sender=sender, to=to, subject=subject, text=text, when=when, auth=auth, thread=thread
        )
    else:
        link = f"https://1drv.ms/b/s!{_tok(rng, 14)}"
        subject = f"Re: {project} - updated schedule"
        text = (
            f"Hi {first},\n\nAs promised, here's the updated schedule and the revised rate card: {link}\n\nLet me know if anything looks off "
            f"before we lock it in.\n\nBest,\n{vperson.split()[0]}" + quote
        )
        cues.append("link_to_credential_page")
        raw = _mail(
            rng, display=display, sender=sender, to=to, subject=subject, text=text, when=when, auth=auth, thread=thread
        )
    return TierItem("T4", 1, scenario, cues, raw, {"alignment": list(T4_ALIGNMENT)})


# ---------------------------------------------------------------------------- legitimate controls
def l1(rng: random.Random) -> TierItem:
    """Newsletters and promotions: bulk, tracked links, promotional urgency, ESP bounce domains."""
    name, first, to = _staff(rng)
    vendor = rng.choice(VENDORS + ["shop.example-office.com", "news.techdigest.example"])
    vname = VENDOR_NAMES.get(vendor, vendor.split(".")[1].title())
    sender = f"news@mail.{vendor}" if vendor in VENDORS else f"newsletter@{vendor}"
    bounce = f"bounce-{_tok(rng, 10)}@{rng.choice(['mcsv.net', 'sendgrid.net', 'amazonses.com', 'sparkpostmail.com'])}"
    bdom = bounce.split("@")[1]
    auth = _auth("pass", "pass", "pass", bounce, sender.split("@")[1], sender.split("@")[1])
    track = f"https://click.{bdom}/ls/click?upn={_tok(rng, 24)}"
    kind = rng.choice(["promo", "newsletter", "webinar", "renewal"])
    subj, paras, cta = {
        "promo": (
            rng.choice(
                ["Last chance: 30% off ends tonight", "Flash sale - 48 hours only", "Your exclusive offer expires soon"]
            ),
            [
                f"Hi {first},",
                "Don't miss out! Our biggest sale of the season ends at midnight.",
                "Act now to lock in member pricing on all orders.",
            ],
            "Shop now",
        ),
        "newsletter": (
            f"{vname} monthly update - {rng.choice(['May', 'June', 'July', 'August'])}",
            [
                "What's new this month: product updates, customer stories and upcoming events.",
                "Read the full stories on our blog.",
            ],
            "Read more",
        ),
        "webinar": (
            "Reminder: your webinar starts tomorrow",
            [
                f"Hi {first},",
                "Thanks for registering. Join us tomorrow at 11:00 for a 45-minute session.",
                "Add it to your calendar so you don't miss it.",
            ],
            "Join webinar",
        ),
        "renewal": (
            "Your subscription renews in 7 days",
            [
                f"Hi {first},",
                "Your annual subscription will renew automatically. No action is needed.",
                "Review your plan or update your payment method any time.",
            ],
            "Manage subscription",
        ),
    }[kind]
    shown = f"www.{vendor}" if rng.random() < 0.4 else cta  # tracked link whose text shows the real site
    preheader = (
        '<span style="display:none;font-size:0;max-height:0;overflow:hidden">' + paras[-1] + "</span>"
        if rng.random() < 0.7
        else ""
    )
    html = _html(
        paras,
        (shown, track),
        footer=f"You are receiving this because you subscribed. <a href='{track}'>Unsubscribe</a>",
        brand=vname,
    )
    html = html.replace('<div style="max-width', preheader + '<div style="max-width', 1)
    text = "\n".join(paras) + f"\n{cta}: {track}"
    raw = _mail(
        rng,
        display=vname,
        sender=sender,
        to=to,
        subject=subj,
        text=text,
        html=html,
        auth=auth,
        return_path=bounce,
        list_mail=True,
        when=_when(rng, rng.random() < 0.5),
    )
    return TierItem("T1", 0, kind, [], raw)


def l2(rng: random.Random) -> TierItem:
    """Genuine service notices from the real brands: urgent and credential-flavoured wording is normal here."""
    name, first, to = _staff(rng)
    brand_key = rng.choice(list(BRANDS))
    brand, real_dom, sender = BRANDS[brand_key]
    sdom = sender.split("@")[1]
    auth = _auth("pass", "pass", "pass", sender, real_dom, sdom)
    link = {
        "m365": "https://account.microsoft.com/security",
        "docusign": f"https://na3.docusign.net/Signing/EmailStart.aspx?a={_tok(rng, 16)}",
        "dhl": f"https://www.dhl.com/au-en/home/tracking.html?tracking-id={rng.randint(10**9, 10**10 - 1)}",
        "gdrive": f"https://docs.google.com/document/d/{_tok(rng, 20)}/edit",
        "paypal": "https://www.paypal.com/myaccount/summary",
        "voicemail": "https://teams.microsoft.com/l/voicemail",
    }[brand_key]
    copy = {
        "m365": (
            "New sign-in to your account",
            [
                f"Hi {first},",
                "We detected a new sign-in to your Microsoft account from a new device. If this was you, you can safely ignore this email.",
                "If not, secure your account now.",
            ],
            "Review activity",
        ),
        "docusign": (
            f"Please DocuSign: {rng.choice(['Supplier Agreement', 'NDA', 'Statement of Work'])}",
            [
                f"{rng.choice(VENDOR_PEOPLE)[0]} sent you a document to review and sign.",
                "Please review the document and sign at your earliest convenience.",
            ],
            "REVIEW DOCUMENT",
        ),
        "dhl": (
            "Your DHL shipment is on its way",
            [
                f"Hi {first},",
                "Your shipment will be delivered tomorrow between 9:00 and 13:00. Track it or change the delivery time online.",
            ],
            "Track shipment",
        ),
        "gdrive": (
            f"{rng.choice(STAFF)[0]} shared a document with you",
            ["has invited you to edit the following document:", f"{rng.choice(PROJECTS).title()} notes"],
            "Open",
        ),
        "paypal": (
            "Receipt for your payment",
            [
                f"Hello {first},",
                f"You sent a payment of AUD {rng.randint(20, 400)}.00 to {rng.choice(list(VENDOR_NAMES.values()))}.",
                "Log in to view the transaction details.",
            ],
            "View transaction",
        ),
        "voicemail": (
            "You have a new voicemail",
            [
                f"Hi {first},",
                f"You received a voicemail from {rng.choice(STAFF)[0]} (0:{rng.randint(10, 59)}).",
                "Listen to it in Teams.",
            ],
            "Play voicemail",
        ),
    }[brand_key]
    subject, paras, cta = copy
    html = _html(paras, (cta, link), footer=f"© 2026 {brand}", brand=brand)
    raw = _mail(
        rng,
        display=brand,
        sender=sender,
        to=to,
        subject=subject,
        text="\n".join(paras) + f"\n{cta}: {link}",
        html=html,
        auth=auth,
        when=_when(rng, rng.random() < 0.6),
    )
    return TierItem("T2", 0, brand_key, [], raw)


def l3(rng: random.Random) -> TierItem:
    """Genuine vendor and colleague mail about invoices, payments and shared documents."""
    name, first, to = _staff(rng)
    vendor = rng.choice(VENDORS)
    vname = VENDOR_NAMES[vendor]
    vperson, vlocal = rng.choice(VENDOR_PEOPLE)
    inv = f"INV-{rng.randint(2000, 9999)}"
    amount = f"{rng.randint(2, 60) * 1000 + rng.choice([0, 150, 375]):,}.00"
    kind = rng.choice(["invoice", "reminder", "doc_share", "colleague_doc", "statement"])
    if kind == "colleague_doc":
        colleague, clocal = rng.choice([s for s in STAFF if s[1] not in to])
        sender = f"{clocal}@{INTERNAL}"
        auth = _auth("pass", "pass", "pass", sender, INTERNAL, INTERNAL)
        link = f"https://acmecorp.sharepoint.com/:w:/s/finance/{_tok(rng, 14)}"
        text = f"Hi {first},\n\nHere's the draft budget for the {rng.choice(PROJECTS)}: {link}\nCan you check the vendor lines before Thursday?\n\nThanks,\n{colleague.split()[0]}"
        raw = _mail(
            rng, display=colleague, sender=sender, to=to, subject="Draft budget for review", text=text, auth=auth
        )
        return TierItem("T3", 0, kind, [], raw)
    sender = f"{rng.choice(['accounts', 'billing', vlocal])}@{vendor}"
    auth = _auth("pass", "pass", "pass", sender, vendor, vendor)
    if kind == "invoice":
        subject = f"Invoice {inv} from {vname}"
        text = f"Hi {first},\n\nPlease find attached invoice {inv} for AUD {amount}, due in 30 days. Payment details are on the invoice as usual.\n\nThanks,\n{vperson}\n{vname}"
        atts = [(f"{inv}.pdf", "application/pdf", PDF)]
    elif kind == "reminder":
        subject = f"Reminder: {inv} due on Friday"
        text = f"Hi {first},\n\nJust a friendly reminder that invoice {inv} (AUD {amount}) is due this Friday. If it's already scheduled, please ignore this.\n\nKind regards,\n{vperson}\nAccounts | {vname}"
        atts = None
    elif kind == "statement":
        subject = f"{vname} statement - {rng.choice(['May', 'June', 'July'])}"
        text = f"Hi {first},\n\nAttached is your monthly statement. You can also see it in our customer portal: https://portal.{vendor}/statements\n\nRegards,\n{vname} Accounts"
        atts = [("Statement.pdf", "application/pdf", PDF)]
    else:
        link = f"https://{vendor.split('.')[0].replace('-', '')}.sharepoint.com/:b:/s/customers/{_tok(rng, 14)}"
        subject = f"{rng.choice(PROJECTS).title()} - documents"
        text = f"Hi {first},\n\nAs discussed, here are the documents for the {rng.choice(PROJECTS)}: {link}\n\nBest,\n{vperson}\n{vname}"
        atts = None
    raw = _mail(
        rng,
        display=f"{vperson} | {vname}" if "@" in sender and sender.startswith(vlocal) else vname,
        sender=sender,
        to=to,
        subject=subject,
        text=text,
        auth=auth,
        attachments=atts,
    )
    return TierItem("T3", 0, kind, [], raw)


def l4(rng: random.Random) -> TierItem:
    """Genuine payment threads, including a vendor's real change of bank details."""
    name, first, to = _staff(rng)
    vendor = rng.choice(VENDORS)
    vperson, vlocal = rng.choice(VENDOR_PEOPLE)
    inv = f"INV-{rng.randint(2000, 9999)}"
    sender = f"{vlocal}@{vendor}"
    auth = _auth("pass", "pass", "pass", sender, vendor, vendor)
    when = _when(rng)
    thread = _msgid(rng, INTERNAL)
    quote = f"\n\n> On {format_datetime(when - timedelta(days=2))[:16]}, {name} wrote:\n> Hi {vperson.split()[0]}, {inv} is scheduled for the next run.\n"
    kind = rng.choice(["real_bank_change", "payment_received", "remittance_query", "schedule_reply"])
    if kind == "real_bank_change":
        subject = f"Re: {inv} - change of bank details"
        text = (
            f"Hi {first},\n\nThanks for confirming. As mentioned on the phone, we're moving our accounts to {rng.choice(BANKS)} from next month. "
            f"The signed letter is attached. Please verify it by calling our office on the number you already have on file before updating "
            f"anything - we won't ask you to change details by email alone.\n\nRegards,\n{vperson}" + quote
        )
        atts = [("Change_of_Bank_Details.pdf", "application/pdf", PDF)]
    elif kind == "payment_received":
        subject = f"Re: {inv} - payment received"
        text = (
            f"Hi {first},\n\nConfirming we've received payment for {inv}. Thanks for the quick turnaround!\n\nCheers,\n{vperson.split()[0]}"
            + quote
        )
        atts = None
    elif kind == "remittance_query":
        subject = f"Re: {inv} - remittance advice"
        text = (
            f"Hi {first},\n\nCould you send the remittance advice for {inv} when you get a chance? Our system didn't match it automatically.\n\nThanks,\n{vperson.split()[0]}"
            + quote
        )
        atts = None
    else:
        subject = f"Re: {rng.choice(PROJECTS)} - schedule"
        text = (
            f"Hi {first},\n\nThe updated schedule works for us. We'll invoice the first milestone at the end of the month as agreed.\n\nBest,\n{vperson.split()[0]}"
            + quote
        )
        atts = None
    raw = _mail(
        rng,
        display=vperson,
        sender=sender,
        to=to,
        subject=subject,
        text=text,
        when=when,
        auth=auth,
        thread=thread,
        attachments=atts,
    )
    return TierItem("T4", 0, kind, [], raw)


PHISH = {"T1": t1, "T2": t2, "T3": t3, "T4": t4}
LEGIT = {"T1": l1, "T2": l2, "T3": l3, "T4": l4}


def generate_tiers(n_per_side: int = 100, seed: int = 2026) -> list[TierItem]:
    """n phishing + n legitimate controls per tier, deterministic for a given seed."""
    out: list[TierItem] = []
    for tier in TIERS:
        rng = random.Random(f"{seed}-{tier}")
        for i in range(n_per_side):
            for item in (PHISH[tier](rng), LEGIT[tier](rng)):
                item.meta["index"] = i
                out.append(item)
    return out


def detection_context():
    """The deployment the tiers assume: acme-corp.com with its vendors trusted and its executives known."""
    from ..readonly import DetectionContext

    return DetectionContext(trusted_domains=TRUSTED_DOMAINS, executives=EXECUTIVES, timezone="UTC")


def write_tiers(out: pathlib.Path, n_per_side: int = 100, seed: int = 2026) -> int:
    items = generate_tiers(n_per_side, seed)
    rows = []
    for it in items:
        side = "phish" if it.label else "legit"
        d = out / it.tier / side
        d.mkdir(parents=True, exist_ok=True)
        name = f"{it.tier.lower()}-{side}-{it.meta['index']:03d}.eml"
        (d / name).write_bytes(it.raw)
        rows.append(
            {
                "file": f"{it.tier}/{side}/{name}",
                "tier": it.tier,
                "label": it.label,
                "scenario": it.scenario,
                "cues": it.cues,
            }
        )
    (out / "manifest.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    return len(items)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Write the customization-tier test set as .eml files.")
    ap.add_argument("--out", default="data/tiers")
    ap.add_argument("--n", type=int, default=100, help="phishing and legitimate messages per tier (each)")
    ap.add_argument("--seed", type=int, default=2026)
    a = ap.parse_args(argv)
    n = write_tiers(pathlib.Path(a.out), a.n, a.seed)
    print(f"wrote {n} messages to {a.out} (+ manifest.jsonl)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
