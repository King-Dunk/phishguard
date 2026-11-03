"""Compare detection modes on the seeded synthetic dataset.

    python -m phishguard.dataset.evaluate --n 100 --seed 42                      # rules only (CI)
    python -m phishguard.dataset.evaluate --modes rules,llm,hybrid \\
        --price-in <USD per MTok> --price-out <USD per MTok>                      # needs ANTHROPIC_API_KEY

Modes:
- rules:  deterministic features + weighted noisy-OR score. No LLM, zero cost.
- llm:    the full agent (LLM with read-only tools) on every email.
- hybrid: rules first; only emails whose rule score is in the gray zone (default 30-70)
          go to the LLM. Clear-cut mail never costs a token.

llm/hybrid run only when ANTHROPIC_API_KEY is set (or an LLMClient is injected, as tests do).
Prices are inputs, not hard-coded: pass current list prices to get a cost column.
"""

from __future__ import annotations

import argparse
import json
import os
import time

from ..agent import PhishingAgent
from ..config import Settings
from ..llm.base import LLMClient
from ..readonly import DetectionContext, analyze_email
from .generator import CATEGORIES, EXECUTIVES, TRUSTED_DOMAINS, generate_dataset

MODES = ("rules", "llm", "hybrid")


def _div(a: float, b: float) -> float | None:
    return round(a / b, 4) if b else None


def evaluate(
    n_per_category: int = 100,
    seed: int = 42,
    threshold: float = 50.0,
    mode: str = "rules",
    llm: LLMClient | None = None,
    gray_zone: tuple[float, float] = (30.0, 70.0),
    price_in: float | None = None,
    price_out: float | None = None,
) -> dict:
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}")
    ctx = DetectionContext(trusted_domains=TRUSTED_DOMAINS, executives=EXECUTIVES)
    agent = None
    if mode != "rules":
        if llm is None:
            from ..llm.anthropic_client import AnthropicLLM  # lazy: rules mode never imports the SDK

            llm = AnthropicLLM(Settings.from_env())
        agent = PhishingAgent(llm, Settings(), ctx)

    tp = fp = tn = fn = calls = in_tok = out_tok = 0
    latency = 0.0
    per_cat = {c: {"tp": 0, "fp": 0, "tn": 0, "fn": 0} for c in CATEGORIES}
    data = generate_dataset(n_per_category, seed)
    for it in data:
        t0 = time.perf_counter()
        risk, _ = analyze_email(it.email, ctx)
        if agent and (mode == "llm" or gray_zone[0] <= risk <= gray_zone[1]):
            r = agent.analyze(it.email)
            risk = r.risk_percent
            calls += 1
            in_tok += r.input_tokens
            out_tok += r.output_tokens
        latency += time.perf_counter() - t0
        pred = risk >= threshold
        key = ("tp" if pred else "fn") if it.label else ("fp" if pred else "tn")
        per_cat[it.category][key] += 1
        tp += key == "tp"
        fp += key == "fp"
        tn += key == "tn"
        fn += key == "fn"

    total = len(data)
    precision, recall = _div(tp, tp + fp), _div(tp, tp + fn)
    f1 = round(2 * precision * recall / (precision + recall), 4) if precision and recall else 0.0
    if mode == "rules":
        cost = 0.0
    elif price_in is not None and price_out is not None:
        cost = round((in_tok * price_in + out_tok * price_out) / 1e6 / total * 1000, 4)
    else:
        cost = None
    return {
        "mode": mode,
        "seed": seed,
        "n_per_category": n_per_category,
        "threshold": threshold,
        "total": total,
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "accuracy": _div(tp + tn, total),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "avg_latency_ms": round(latency / total * 1000, 3),
        "llm_calls": calls,
        "llm_call_rate": _div(calls, total),
        "tokens": {"input": in_tok, "output": out_tok},
        "cost_per_1k_usd": cost,
        "per_category": {
            c: {
                **v,
                "recall": _div(v["tp"], v["tp"] + v["fn"]),
                "false_positive_rate": _div(v["fp"], v["fp"] + v["tn"]),
            }
            for c, v in per_cat.items()
        },
    }


def _pct(x: float | None) -> str:
    return "n/a" if x is None else f"{x * 100:.1f}%"


def comparison_table(results: list[dict]) -> str:
    rows = [
        "| Mode | Accuracy | Precision | Recall | F1 | Avg latency | LLM call rate | Cost / 1k emails |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in results:
        if r.get("skipped"):
            rows.append(f"| {r['mode']} | skipped: {r['skipped']} | | | | | | |")
            continue
        cost = "n/a (pass --price-in/--price-out)" if r["cost_per_1k_usd"] is None else f"${r['cost_per_1k_usd']}"
        rows.append(
            f"| {r['mode']} | {_pct(r['accuracy'])} | {_pct(r['precision'])} | {_pct(r['recall'])} | "
            f"{_pct(r['f1'])} | {r['avg_latency_ms']} ms | {_pct(r['llm_call_rate'])} | {cost} |"
        )
    return "\n".join(rows)


def run_modes(modes: list[str], **kw) -> list[dict]:
    out = []
    for m in modes:
        if m != "rules" and kw.get("llm") is None and not os.environ.get("ANTHROPIC_API_KEY"):
            out.append({"mode": m, "skipped": "ANTHROPIC_API_KEY not set"})
            continue
        out.append(evaluate(mode=m, **kw))
    return out


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=100, help="emails per category")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--threshold", type=float, default=50.0)
    ap.add_argument("--modes", default="rules", help="comma list of rules,llm,hybrid")
    ap.add_argument("--gray-low", type=float, default=30.0)
    ap.add_argument("--gray-high", type=float, default=70.0)
    ap.add_argument("--price-in", type=float, default=None, help="USD per million input tokens")
    ap.add_argument("--price-out", type=float, default=None, help="USD per million output tokens")
    ap.add_argument("--json", action="store_true", help="print full JSON instead of the table")
    a = ap.parse_args(argv)
    modes = [m.strip() for m in a.modes.split(",") if m.strip()]
    bad = set(modes) - set(MODES)
    if bad:
        ap.error(f"unknown modes: {sorted(bad)}")
    results = run_modes(
        modes,
        n_per_category=a.n,
        seed=a.seed,
        threshold=a.threshold,
        gray_zone=(a.gray_low, a.gray_high),
        price_in=a.price_in,
        price_out=a.price_out,
    )
    print(json.dumps(results, indent=2) if a.json else comparison_table(results))


if __name__ == "__main__":
    main()
