import pytest

from phishguard.agent import PhishingAgent
from phishguard.config import DEFAULT_MODEL, Settings
from phishguard.llm import MockLLM
from phishguard.llm.anthropic_client import AnthropicLLM
from phishguard.llm.base import LLMClient, LLMResponse, MissingAPIKeyError, ToolCall
from phishguard.readonly import DetectionContext, analyze_email
from tests.conftest import make_email


def test_benign_low_risk(benign):
    risk, feats = analyze_email(benign)
    assert risk < 20 and feats == []


def test_phish_high_risk_with_feature_names(phish):
    risk, feats = analyze_email(phish, DetectionContext(executives=("David Chen",)))
    names = {f.name for f in feats}
    assert risk > 90 and 0 <= risk <= 100
    assert {"lookalike_domain", "auth_fail", "reply_to_mismatch", "executive_impersonation", "new_domain"} <= names


def test_lookalike_variants():
    for dom in ("acme-corp.com.secure-login.net", "acrne-corp.com", "acme-c0rp.com", "acme-corps.com"):
        _, f = analyze_email(make_email(sender_email=f"x@{dom}"))
        assert "lookalike_domain" in {x.name for x in f}, dom
    _, f = analyze_email(make_email(sender_email="x@mail.acme-corp.com"))
    assert "lookalike_domain" not in {x.name for x in f}


def test_obfuscated_keywords_still_detected():
    _, f = analyze_email(make_email(body="ｗｉｒｅ transfer​ now, ＵＲＧＥＮＴ"))
    assert {"payment_keywords", "urgency_language"} <= {x.name for x in f}


def test_agent_mock_flow_and_counters(settings, phish):
    r = PhishingAgent(MockLLM(), settings).analyze(phish)
    assert r.steps_used == 2 and r.tokens_used > 0 and r.circuit_break is None
    assert r.tool_calls == ["extract_features"]


class LoopLLM(LLMClient):
    def complete(self, *, system, messages, tools, max_tokens):
        return LLMResponse(
            tool_calls=[ToolCall(f"c{len(messages)}", "get_email", {})], input_tokens=10, output_tokens=5
        )


def test_max_steps_circuit_breaker(benign):
    s = Settings(max_steps=3)
    r = PhishingAgent(LoopLLM(), s).analyze(benign)
    assert r.circuit_break == "max_steps" and r.steps_used == 3


def test_token_budget_circuit_breaker(phish):
    s = Settings(max_tokens_per_request=20, max_steps=10)
    r = PhishingAgent(LoopLLM(), s).analyze(phish)
    assert r.circuit_break == "token_budget" and r.steps_used <= 2
    assert r.risk_percent > 50  # still returns the deterministic verdict


def test_token_budget_passed_to_llm(benign):
    seen = []

    class Spy(LLMClient):
        def complete(self, *, system, messages, tools, max_tokens):
            seen.append(max_tokens)
            return LLMResponse(text='{"risk": 1}', input_tokens=1, output_tokens=1)

    PhishingAgent(Spy(), Settings(max_tokens_per_request=300, per_call_max_tokens=1024)).analyze(benign)
    assert seen == [300]


def test_defaults_and_api_key_from_env_only(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert Settings().model == DEFAULT_MODEL == "claude-haiku-5-5"
    assert Settings.from_env().api_key is None
    with pytest.raises(MissingAPIKeyError):
        AnthropicLLM(Settings(llm_mode="anthropic"))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-123")
    s = Settings.from_env()
    assert s.api_key == "sk-test-123" and "sk-test" not in repr(s)


def test_no_hardcoded_key_in_source():
    import pathlib
    import re

    import phishguard

    for f in pathlib.Path(phishguard.__file__).parent.rglob("*.py"):
        assert not re.search(r"sk-ant-[A-Za-z0-9_-]{10,}", f.read_text()), f
