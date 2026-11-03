import socket
import subprocess
import sys

from phishguard.dataset.evaluate import evaluate
from phishguard.dataset.generator import CATEGORIES, generate_dataset


def test_generator_deterministic_and_balanced():
    a = generate_dataset(30, seed=7)
    b = generate_dataset(30, seed=7)
    assert [x.to_dict() for x in a] == [x.to_dict() for x in b]
    assert [x.to_dict() for x in a] != [x.to_dict() for x in generate_dataset(30, seed=8)]
    assert {c: sum(x.category == c for x in a) for c in CATEGORIES} == {c: 30 for c in CATEGORIES}
    assert {x.label for x in a if x.category == "bec"} == {1}
    assert {x.label for x in a if x.category == "collaboration"} == {0}
    assert {x.label for x in a if x.category == "payment_chasing"} == {0, 1}
    e = a[0].email
    assert e.timestamp and e.sender_reputation is not None and e.sender_domain_age_days is not None


def test_eval_meets_floor_and_makes_no_network_calls(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket.socket, "connect", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    m = evaluate(60, seed=42)
    assert m["accuracy"] >= 0.9 and m["recall"] >= 0.85 and m["precision"] >= 0.9


def test_eval_script_never_imports_anthropic_sdk():
    r = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; from phishguard.dataset.evaluate import evaluate; evaluate(10); "
            "sys.exit(1 if 'anthropic' in sys.modules else 0)",
        ],
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0, r.stderr


class CountingLLM:
    """Wraps MockLLM and counts agent runs (first call of each run)."""

    def __init__(self):
        from phishguard.llm import MockLLM

        self.inner, self.runs = MockLLM(), 0

    def complete(self, **kw):
        if len(kw["messages"]) == 1:
            self.runs += 1
        r = self.inner.complete(**kw)
        r.input_tokens, r.output_tokens = 1000, 100
        return r


def test_rules_mode_metrics_and_zero_cost():
    m = evaluate(30, seed=1, mode="rules")
    assert m["mode"] == "rules" and m["llm_calls"] == 0 and m["cost_per_1k_usd"] == 0.0
    assert 0 < m["f1"] <= 1 and m["avg_latency_ms"] >= 0


def test_hybrid_calls_llm_only_in_gray_zone():
    from phishguard.dataset.generator import EXECUTIVES, TRUSTED_DOMAINS
    from phishguard.readonly import DetectionContext, analyze_email

    ctx = DetectionContext(TRUSTED_DOMAINS, EXECUTIVES)
    gray = sum(30 <= analyze_email(x.email, ctx)[0] <= 70 for x in generate_dataset(30, seed=3))
    h_llm, a_llm = CountingLLM(), CountingLLM()
    h = evaluate(30, seed=3, mode="hybrid", llm=h_llm, price_in=1.0, price_out=5.0, gray_zone=(30, 70))
    a = evaluate(30, seed=3, mode="llm", llm=a_llm, price_in=1.0, price_out=5.0)
    assert h["llm_calls"] == h_llm.runs == gray < a["llm_calls"] == a_llm.runs == 90
    assert h["cost_per_1k_usd"] < a["cost_per_1k_usd"]
    assert evaluate(30, seed=3, mode="llm", llm=CountingLLM())["cost_per_1k_usd"] is None  # no prices given


def test_cli_skips_llm_modes_without_key(monkeypatch, capsys):
    from phishguard.dataset.evaluate import main

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    main(["--n", "5", "--modes", "rules,llm,hybrid"])
    out = capsys.readouterr().out
    assert out.count("skipped: ANTHROPIC_API_KEY not set") == 2 and "| synthetic | rules |" in out


def test_hybrid_default_gray_zone_is_20_to_50():
    import inspect

    assert inspect.signature(evaluate).parameters["gray_zone"].default == (20.0, 50.0)
