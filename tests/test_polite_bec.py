"""Polite BEC (payment redirection without urgency/secrecy keywords) and image-only lures.

The positive cases are paraphrases, none of them the red-team or synthetic wording, so the rules
are checked on meaning (request + money going somewhere new), not on memorized phrases."""

import time

import pytest

from phishguard.config import DEFAULT_THRESHOLD
from phishguard.readonly import DetectionContext, analyze_email, parse_eml
from redteam.builders import build_eml
from tests.conftest import make_email

CTX = DetectionContext(trusted_domains=("acme-corp.com",), executives=("David Chen",))
FREE = dict(
    sender_email="j.walker.office@gmail.com", sender_name="Jordan Walker", spf="pass", dkim="pass", dmarc="pass"
)
VENDOR = dict(sender_email="ar@unknown-vendor.example", sender_name="AR", spf="pass", dkim="pass", dmarc="pass")


def keys(email, ctx=CTX):
    risk, feats = analyze_email(email, ctx)
    return risk, {f.key for f in feats}


@pytest.mark.parametrize(
    "body",
    [
        # gift cards
        "Morning! Would you be able to help with something? Please grab five Google Play cards for the team and email me the codes.",
        "Can you order a few Amazon vouchers for staff rewards today? I'll expense it later.",
        "I need you to purchase some gift cards for a supplier thank-you. Scratch them and send me photos of the back.",
        # payroll
        "Hi, I've moved to a different bank recently. Would you please change my direct deposit before the next pay run?",
        "Kindly update my payroll details, my wages should go into another account from this month.",
        # payee details
        "Could you amend the bank details we have on record for Contoso? Their finance team sent new ones.",
        "Please replace the supplier account on the Fabrikam file ahead of the next batch.",
        # destination named in the mail
        "We would appreciate it if the outstanding balance is sent to the following account going forward.",
        "Going forward, remit all invoices to our new bank account, IBAN is attached.",
    ],
)
def test_payment_redirection_paraphrases_fire_and_flag_from_free_mail(body):
    risk, k = keys(make_email(body=body, subject="Hello", **FREE))
    assert "payment_redirect_request_freemail" in k, body
    assert risk >= DEFAULT_THRESHOLD, (risk, body)


def test_no_memorized_names_or_greetings():
    """The proposal's auto-drafted phrases ("it's david", "quick favour", "hi it's") are not rules."""
    for body in (
        "Hi, it's David.",
        "Quick favour: can you review my slides?",
        "Many thanks, between us that went well.",
    ):
        risk, k = keys(make_email(body=body, subject="Hello", **FREE))
        assert not any(x.startswith("payment_redirect") for x in k) and risk < DEFAULT_THRESHOLD, body


@pytest.mark.parametrize(
    "body",
    [
        "Could you review the design doc when you get a chance? Comments welcome.",
        "Please pay to the bank account on file by month end.",
        "Friendly reminder: invoice INV-1 ($900) is due. Remittance details are unchanged.",
        "Please update your account information in the portal settings page.",  # credential_request's territory
        "We bought gift cards for the raffle last year, it went well.",  # no request
        "Payroll runs on Friday; please submit timesheets by Wednesday.",
        "I got a new bank card yesterday, the design is nice. Can you send me the lunch menu?",
        "Can you send me the meeting notes? I will pay for lunch.",
        "Your direct deposit of $1,200 was credited to your account.",
    ],
)
def test_ordinary_business_text_does_not_fire(body):
    _, k = keys(make_email(body=body, subject="Hello", **VENDOR))
    assert not any(x.startswith("payment_redirect") for x in k), body


def test_sender_context_picks_the_weight_key():
    body = "Could you amend the bank details we have on record for Contoso?"
    _, k = keys(make_email(body=body, **VENDOR))
    assert "payment_redirect_request" in k
    _, k = keys(make_email(body=body, **{**VENDOR, "reply_to": "ar.contoso@outlook.com"}))
    assert "payment_redirect_request_freemail" in k
    internal = dict(sender_email="tom.r@acme-corp.com", spf="pass", dkim="pass", dmarc="pass")
    risk, k = keys(make_email(body=body, **internal))
    assert k >= {"payment_redirect_request_trusted_sender"} and risk < DEFAULT_THRESHOLD  # colleagues do AP work
    # a spoofed "internal" sender (auth fails) gets no damping
    _, k = keys(make_email(body=body, sender_email="tom.r@acme-corp.com", spf="fail", dkim="fail", dmarc="fail"))
    assert "payment_redirect_request" in k


def test_weight_order():
    w = CTX.table.weights
    assert (
        w["payment_redirect_request_trusted_sender"]
        < w["payment_redirect_request"]
        < w["payment_redirect_request_freemail"]
    )
    assert w["image_lure_inline"] <= w["image_lure_linked"] <= w["image_lure"]


def test_obfuscated_request_still_seen():
    _, k = keys(make_email(body="Pl3ase p-u-r-c-h-a-s-e some g i f t c@rds and send me the codes", **FREE))
    assert "payment_redirect_request_freemail" in k


def test_org_name_in_free_mail_address():
    _, k = keys(make_email(sender_email="hr.acme.team@gmail.com", sender_name="HR", body="hello"))
    assert "org_name_in_freemail_address" in k
    for addr in ("hr.team@gmail.com", "hr@acme-corp.com", "acme@unknown-vendor.example"):
        _, k = keys(make_email(sender_email=addr, sender_name="HR", body="hello"))
        assert "org_name_in_freemail_address" not in k, addr
    _, k = keys(make_email(sender_email="hr.acme.team@gmail.com", body="hello"), DetectionContext(trusted_domains=()))
    assert "org_name_in_freemail_address" not in k  # no configured organisation: inert


def _html_mail(html, text=" ", **kw):
    return parse_eml(build_eml({"from": "Billing <billing@unknown-vendor.example>", "html": html, "text": text, **kw}))


def test_parser_counts_images_but_not_tracking_pixels_or_hidden_ones():
    m = _html_mail(
        '<a href="https://evil.example/pay"><img src="https://evil.example/a.png"></a>'
        '<img src="cid:logo"><img src="https://t.example/p.gif" width="1" height="1">'
        '<div style="display:none"><img src="x.png"></div><a href="mailto:a@b.example"><img src="m.png"></a>'
    )
    assert (m.inline_images, m.linked_images) == (3, 1)


def test_html_image_only_body_is_a_lure():
    risk, k = keys(_html_mail('<a href="https://evil.example/pay"><img src="https://evil.example/notice.png"></a>'))
    assert "image_lure_linked" in k and risk >= DEFAULT_THRESHOLD
    _, k = keys(_html_mail('<img src="cid:scan">', subject="Scan"))
    assert "image_lure_inline" in k


def test_images_with_real_text_or_other_attachments_are_not_a_lure():
    words = "Our spring catalogue is out with new tools, garden furniture and a longer returns window. " * 2
    _, k = keys(_html_mail(f'<img src="https://shop.example/banner.png"><p>{words}</p>', text=words))
    assert not any(x.startswith("image_lure") for x in k)
    _, k = keys(_html_mail('<img src="https://t.example/p.gif" width="1" height="1">'))  # pixel only
    assert not any(x.startswith("image_lure") for x in k)
    m = _html_mail('<img src="cid:scan">', attachments=[{"name": "report.pdf", "ctype": "application/pdf"}])
    assert not any(x.startswith("image_lure") for x in keys(m)[1])


def test_red_team_evasion_cases_now_reach_50():
    import yaml

    with open("redteam/payloads/evasion.yaml", encoding="utf-8") as f:
        attacks = {a["id"]: a for a in yaml.safe_load(f)["attacks"]}
    for aid in ("ev-image-only", "ev-polite-bec-remittance", "ev-polite-bec-giftcards", "ev-polite-bec-payroll"):
        risk, _ = keys(parse_eml(build_eml({**attacks[aid]["eml"], "id": aid})))
        assert risk >= 50, (aid, risk)


def test_new_patterns_stay_fast_on_adversarial_bodies():
    bodies = [
        "please update " + "the " * 6000,
        "new bank " * 2200,
        ("please pay " + "x" * 79 + " ") * 200,
        "salary " + " " * 19000 + "x",
        "cards send " * 1800,
    ]
    t0 = time.perf_counter()
    for b in bodies:
        analyze_email(make_email(body=b[:20000], **FREE), CTX)
    assert time.perf_counter() - t0 < 2.0
