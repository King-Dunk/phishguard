"""Default threshold 35, recall at fixed FPR, threshold sweep, trusted-sender damping."""

import pytest

from phishguard.api import create_app
from phishguard.config import DEFAULT_THRESHOLD, Settings
from phishguard.dataset.evaluate import evaluate, main
from phishguard.dataset.metrics import Scored, at_threshold, recall_at_fpr, sweep, threshold_for_fpr
from phishguard.readonly import DetectionContext, analyze_email
from tests.conftest import make_email


def test_default_threshold_is_35_everywhere(monkeypatch):
    assert DEFAULT_THRESHOLD == 35.0 and Settings().phishing_threshold == 35.0
    monkeypatch.setenv("PHISHGUARD_THRESHOLD", "42")
    assert Settings.from_env().phishing_threshold == 42.0
    assert evaluate(10)["threshold"] == 35.0


def test_api_uses_configured_threshold():
    from fastapi.testclient import TestClient

    e = make_email(body="Urgent: please process the wire transfer.", sender_email="x@vendor.example")
    risk = analyze_email(e, DetectionContext(executives=()))[0]
    assert 35 <= risk < 50  # the band the default change is about
    body = {"email": e.model_dump(mode="json")}
    for t, flagged in ((35.0, True), (50.0, False)):
        c = TestClient(create_app(Settings(phishing_threshold=t)))
        r = c.post("/analyze", json=body).json()
        assert r["is_phishing"] is flagged and r["threshold"] == t


def _s(risks, label, cat):
    return [Scored(r, label, cat) for r in risks]


def test_threshold_for_fpr_is_exact_and_tie_safe():
    ham = _s([float(i) for i in range(100)], 0, "easy_ham")  # 0..99
    phish = _s([50.0] * 10 + [99.5] * 10, 1, "p")
    sc = ham + phish
    t = threshold_for_fpr(sc, 0.01)
    assert at_threshold(sc, t)["fpr"] <= 0.01 and 98 < t <= 99
    m = recall_at_fpr(sc, 0.05)
    assert m["fpr"] <= 0.05 and m["recall"] == 0.5
    ties = _s([60.0] * 100, 0, "easy_ham") + phish
    assert at_threshold(ties, threshold_for_fpr(ties, 0.01))["fpr"] == 0.0  # never over the cap on ties


def test_fpr_reference_category():
    sc = _s([10.0] * 100, 0, "easy_ham") + _s([80.0] * 100, 0, "hard_ham") + _s([70.0] * 50, 1, "p")
    easy = recall_at_fpr(sc, 0.01, "easy_ham")
    allham = recall_at_fpr(sc, 0.01)
    # An easy_ham-only constraint is blind to hard_ham: every hard_ham mail gets flagged here.
    assert easy["recall"] == 1.0 and easy["fpr_by_category"]["hard_ham"] == 1.0
    # Constraining on all legitimate mail pushes the threshold above hard_ham and loses all recall.
    assert allham["recall"] == 0.0 and allham["fpr"] <= 0.01 and easy["fpr_reference"] == "easy_ham"


def test_sweep_covers_30_to_60():
    rows = sweep(_s([40.0], 1, "p") + _s([33.0], 0, "h"))
    assert [r["threshold"] for r in rows] == [30, 35, 40, 45, 50, 55, 60]
    assert rows[0]["fpr"] == 1.0 and rows[1]["fpr"] == 0.0 and rows[2]["recall"] == 1.0 and rows[3]["recall"] == 0.0


def test_evaluate_reports_recall_at_fpr_and_sweep(capsys):
    m = evaluate(40, seed=2)
    assert set(m["recall_at_fpr"]) == {"1%", "5%"} and len(m["sweep"]) == 7
    main(["--n", "10", "--sweep"])
    out = capsys.readouterr().out
    assert "Recall @1% FPR" in out and "| synthetic | rules | 60 |" in out


def test_synthetic_f1_at_default_threshold():
    m = evaluate(200, seed=42)
    assert m["threshold"] == 35 and m["f1"] >= 0.95 and m["precision"] >= 0.95


# ---- trusted-sender damping (keeps synthetic precision at threshold 35; inert on the public corpora)
def _invoice(**kw):
    base = dict(sender_email="billing@globalsupply.com", body="Urgent: invoice payment overdue", dmarc="pass")
    return make_email(**{**base, **kw})


CTX = DetectionContext(trusted_domains=("acme-corp.com", "globalsupply.com"))


def test_authenticated_partner_keywords_are_softened():
    names = {f.key for f in analyze_email(_invoice(), CTX)[1]}
    assert {"payment_keywords_trusted_sender", "urgency_language_trusted_sender"} <= names
    assert analyze_email(_invoice(), CTX)[0] < DEFAULT_THRESHOLD


@pytest.mark.parametrize(
    "kw",
    [
        {"dmarc": "fail", "spf": "fail", "dkim": "fail"},  # not authenticated
        {"dmarc": "none", "spf": "pass", "dkim": "none"},  # SPF alone is not enough
        {"sender_email": "billing@globalsupply-pay.com"},  # not a trusted domain
    ],
)
def test_damping_needs_authentication_and_trust(kw):
    names = {f.key for f in analyze_email(_invoice(**kw), CTX)[1]}
    assert "payment_keywords_trusted_sender" not in names


def test_damping_inert_without_trusted_domains_and_bank_change_keeps_weight():
    names = {f.key for f in analyze_email(_invoice(), DetectionContext(trusted_domains=()))[1]}
    assert "payment_keywords" in names and "payment_keywords_trusted_sender" not in names
    e = _invoice(body="Please note our bank account details have been updated.")
    feats = {f.key: f.weight for f in analyze_email(e, CTX)[1]}
    assert feats["bank_detail_change"] == 0.45
