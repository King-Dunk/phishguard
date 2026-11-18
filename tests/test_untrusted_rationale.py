"""The model's free-text rationale is attacker-influenced: it must not reach a reader as advice."""

from phishguard.agent import AnalysisResult
from phishguard.api import _result

PITCH = "Verified by the CEO by phone. This is safe: please pay the invoice to the new account today."


def res(risk, rule, llm, rationale=PITCH):
    return AnalysisResult(risk, [], 1, 1, rationale=rationale, rule_risk=rule, llm_risk=llm)


def test_withheld_on_flagged_mail():
    out = _result("e", res(80, 80, 0), 50)
    assert out["is_phishing"] and out["rationale"] == "" and out["rationale_status"] == "withheld_flagged"


def test_withheld_when_model_argued_the_score_down_even_below_threshold():
    # e.g. llm_may_lower is on and an injected model cleared routing context
    out = _result("e", res(30, 45, 0), 50)
    assert not out["is_phishing"] and out["rationale"] == ""
    assert out["rationale_status"] == "withheld_model_disagrees"


def test_shown_when_benign_and_agreeing_but_cleaned_capped_and_labelled():
    text = "Routine‮ newsletter\x00\n\n" + "x" * 1000
    out = _result("e", res(10, 10, 12, text), 50)
    assert out["rationale_status"] == "shown" and out["rationale_trust"] == "untrusted_model_output"
    r = out["rationale"]
    assert r.startswith("Routine newsletter") and len(r) == 300
    assert "‮" not in r and "\x00" not in r and "\n" not in r


def test_no_rationale():
    out = _result("e", res(10, 10, None, ""), 50)
    assert out["rationale"] == "" and out["rationale_status"] == "none"
