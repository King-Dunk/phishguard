"""Real .eml parsing and the new detection signals, on hand-written fixtures."""

import pathlib

import pytest

from phishguard.dataset.generator import EXECUTIVES, TRUSTED_DOMAINS
from phishguard.readonly import DetectionContext, EmlTooLarge, analyze_email, parse_eml
from phishguard.readonly.features import homoglyph_of, levenshtein, lookalike_of, skeleton
from tests.conftest import make_email

FIX = pathlib.Path(__file__).parent / "fixtures"
CTX = DetectionContext(trusted_domains=TRUSTED_DOMAINS, executives=EXECUTIVES)

# fixture -> (is_phishing, features that must be present)
CASES = {
    "benign_internal_plain.eml": (False, set()),
    "benign_vendor_pdf.eml": (False, set()),
    "benign_html_newsletter.eml": (False, set()),
    "phish_bec_auth_fail.eml": (
        True,
        {"auth_fail", "lookalike_domain", "executive_impersonation", "reply_to_mismatch", "return_path_mismatch"},
    ),
    "phish_link_text_mismatch.eml": (True, {"link_text_mismatch", "display_name_spoof", "credential_request"}),
    "phish_punycode_homoglyph.eml": (True, {"homoglyph_domain"}),
    "phish_html_attachment.eml": (True, {"risky_attachment", "auth_fail"}),
    "phish_iso_attachment.eml": (True, {"risky_attachment", "auth_fail"}),
    "phish_macro_display_name.eml": (True, {"risky_attachment", "display_name_spoof"}),
    "phish_forged_auth_header.eml": (True, {"auth_fail", "lookalike_domain", "bank_detail_change"}),
}


def test_fixture_set_is_complete():
    assert {p.name for p in FIX.glob("*.eml")} == set(CASES) and len(CASES) >= 8


@pytest.mark.parametrize("name", sorted(CASES))
def test_fixture_verdict_and_features(name):
    want_phish, want_feats = CASES[name]
    email = parse_eml((FIX / name).read_bytes())
    risk, feats = analyze_email(email, CTX)
    names = {f.name for f in feats}
    assert (risk >= 50) is want_phish, (risk, names)
    assert want_feats <= names, names
    if not want_phish:
        assert risk < 20


@pytest.mark.parametrize("name", sorted(CASES))
def test_contributions_explain_the_score(name):
    risk, feats = analyze_email(parse_eml((FIX / name).read_bytes()), CTX)
    assert abs(sum(f.contribution for f in feats) - risk) <= 0.1 * max(1, len(feats))
    assert [f.contribution for f in feats] == sorted((f.contribution for f in feats), reverse=True)
    assert all(f.contribution > 0 for f in feats)


def test_multipart_parsing_details():
    e = parse_eml((FIX / "benign_vendor_pdf.eml").read_bytes())
    assert e.sender_name == "Global Supply Billing" and e.sender_email == "billing@globalsupply.com"
    assert e.return_path == "billing@globalsupply.com" and e.id == "stmt-0226@globalsupply.com"
    assert [(a.filename, a.content_type, a.size) for a in e.attachment_meta] == [
        ("statement-feb.pdf", "application/pdf", 21)
    ]
    assert "February statement" in e.body and e.timestamp.isoformat() == "2026-03-04T11:00:00+00:00"


def test_html_body_text_and_anchor_pairs():
    e = parse_eml((FIX / "phish_link_text_mismatch.eml").read_bytes())
    assert "<p>" not in e.body and "password expires" in e.body
    assert e.link_pairs[0].text == "https://login.acme-corp.com/owa"
    assert e.link_pairs[0].href == "http://198.51.100.23/owa/login.php"
    assert e.links == ["http://198.51.100.23/owa/login.php"]


def test_only_topmost_auth_results_trusted():
    raw = (FIX / "phish_forged_auth_header.eml").read_bytes()
    e = parse_eml(raw)
    assert (e.spf, e.dkim, e.dmarc) == ("fail", "fail", "fail")  # forged "pass" header below is ignored
    e2 = parse_eml(raw, trusted_authserv_id="mx.other.net")
    assert (e2.spf, e2.dkim, e2.dmarc) == ("none", "none", "none")  # no header from our MTA -> no auth claim


def test_softfail_maps_to_fail():
    assert parse_eml((FIX / "phish_html_attachment.eml").read_bytes()).spf == "fail"


def test_size_limit():
    with pytest.raises(EmlTooLarge):
        parse_eml(b"Subject: x\n\n" + b"a" * 2_000_001)


def test_garbage_input_does_not_crash():
    e = parse_eml(b"\x00\xff not an email at all")
    assert e.sender_email == "" and e.spf == "none"


def test_homoglyph_and_punycode():
    assert skeleton("xn--cme-corp-06g.com") == "acme-corp.com"
    assert homoglyph_of("xn--cme-corp-06g.com", ("acme-corp.com",)) == "acme-corp.com"
    assert homoglyph_of("асme-corp.com", ("acme-corp.com",)) == "acme-corp.com"  # raw Cyrillic а, с
    assert homoglyph_of("acme-corp.com", ("acme-corp.com",)) is None
    assert homoglyph_of("xn--80ak6aa92e.com", ("acme-corp.com",)) is None  # unrelated IDN


def test_edit_distance_lookalikes():
    assert levenshtein("kitten", "sitting") == 3 and levenshtein("", "abc") == 3
    assert lookalike_of("acmecrop.com", ("acme-corp.com",))  # transposition = distance 2
    assert lookalike_of("globalsuply.com", ("globalsupply.com",))
    assert lookalike_of("github.com", ("acme-corp.com",)) is None


def test_display_name_spoof_and_return_path():
    _, f = analyze_email(make_email(sender_name="ACME-Corp Payroll", sender_email="pay@gmail.com"))
    assert "display_name_spoof" in {x.name for x in f}
    _, f = analyze_email(make_email(sender_name="ACME Corp", sender_email="news@acme-corp.com"))
    assert f == []  # internal sender may use the brand
    _, f = analyze_email(make_email(return_path="bounce@sendgrid.net"))
    assert {x.name for x in f} == {"return_path_mismatch"}


def test_link_text_same_site_is_fine():
    from phishguard.models import DisplayedLink

    pairs = [DisplayedLink(text="www.acme-corp.com/hr", href="https://intranet.acme-corp.com/hr")]
    _, f = analyze_email(make_email(link_pairs=pairs))
    assert "link_text_mismatch" not in {x.name for x in f}
    pairs = [DisplayedLink(text="Click here", href="https://evil.example")]
    _, f = analyze_email(make_email(link_pairs=pairs))
    assert "link_text_mismatch" not in {x.name for x in f}  # plain words are not a URL claim
