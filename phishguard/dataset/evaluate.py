"""Compare detection modes on the seeded synthetic dataset.

    python -m phishguard.dataset.evaluate --n 100 --seed 42                      # rules only (CI)
    python -m phishguard.dataset.evaluate --modes rules,llm,hybrid \\
        --price-in <USD per MTok> --price-out <USD per MTok>                      # needs ANTHROPIC_API_KEY

Datasets (--dataset):
- synthetic (default): seeded generator, same assumptions as the rules (a regression baseline)
- external: public corpora in data/external/ (scripts/download_datasets.py): SpamAssassin
            easy_ham/hard_ham as legitimate, Nazario phishing corpus as phishing
- both:     run both and print them side by side

Modes:
- rules:  deterministic features + weighted noisy-OR score. No LLM, zero cost.
- llm:    the full agent (LLM with read-only tools) on every email.
- hybrid: rules first; only emails whose rule score is in the gray zone (default 20-50, i.e. around
          the default threshold of 35) go to the LLM. Clear-cut mail never costs a token.

Metrics: accuracy/precision/recall/F1 at --threshold (default 35, see config.DEFAULT_THRESHOLD), plus
recall at a fixed false-positive rate (1% and 5%; class-ratio independent) and --sweep for a
threshold table (30-60, step 5). With --fpr-ref easy_ham the FPR is measured on easy_ham only.

llm/hybrid run only when ANTHROPIC_API_KEY is set (or an LLMClient is injected, as tests do).
Prices are inputs, not hard-coded: pass current list prices to get a cost column.
"""

from __future__ import annotations

import argparse
import json
import os
import time

from ..agent import PhishingAgent
from ..config import DEFAULT_THRESHOLD, Settings
from ..llm.base import LLMClient
from ..readonly import DetectionContext, analyze_email
from .generator import CATEGORIES, EXECUTIVES, TRUSTED_DOMAINS, generate_dataset
from .metrics import Scored, recall_at_fpr, sweep

MODES = ("rules", "llm", "hybrid")


def _div(a: float, b: float) -> float | None:
    return round(a / b, 4) if b else None


def evaluate(
    n_per_category: int = 100,
    seed: int = 42,
    threshold: float = DEFAULT_THRESHOLD,
    mode: str = "rules",
    llm: LLMClient | None = None,
    gray_zone: tuple[float, float] = (20.0, 50.0),
    price_in: float | None = None,
    price_out: float | None = None,
    dataset: str = "synthetic",
    data_dir: str | None = None,
    limit_per_class: int | None = None,
    split: str | None = None,
    weights=None,
    fpr_ref: str | None = None,
    llm_may_lower: bool = False,
) -> dict:
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}")
    skipped: dict[str, int] = {}
    if dataset == "external":
        from .external import load_external_cached, split_items

        ext = load_external_cached(data_dir, limit_per_class, seed)
        data, categories, skipped = ext.items, ext.categories, ext.skipped
        if split:
            data = split_items(data, split)
        # The corpora are not about our company: no trusted domains or executives to imitate.
        ctx = DetectionContext(trusted_domains=(), executives=(), weights=weights)
    elif dataset == "synthetic":
        data, categories = generate_dataset(n_per_category, seed), CATEGORIES
        ctx = DetectionContext(trusted_domains=TRUSTED_DOMAINS, executives=EXECUTIVES, weights=weights)
    else:
        raise ValueError("dataset must be synthetic or external")
    agent = None
    if mode != "rules":
        if llm is None:
            from ..llm.anthropic_client import AnthropicLLM  # lazy: rules mode never imports the SDK

            llm = AnthropicLLM(Settings.from_env())
        agent = PhishingAgent(llm, Settings(llm_may_lower=llm_may_lower), ctx)

    tp = fp = tn = fn = calls = in_tok = out_tok = lowered = raised = steps = 0
    scored: list[Scored] = []
    latency = 0.0
    per_cat = {c: {"tp": 0, "fp": 0, "tn": 0, "fn": 0} for c in categories}
    for it in data:
        t0 = time.perf_counter()
        risk, _ = analyze_email(it.email, ctx)
        if agent and (mode == "llm" or gray_zone[0] <= risk <= gray_zone[1]):
            r = agent.analyze(it.email)
            risk = r.risk_percent
            calls += 1
            steps += r.steps_used
            lowered += r.lowered_by_llm
            raised += r.risk_percent > r.rule_risk
            in_tok += r.input_tokens
            out_tok += r.output_tokens
        latency += time.perf_counter() - t0
        scored.append(Scored(risk, it.label, it.category))
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
        "dataset": f"{dataset}:{split}" if split else dataset,
        "skipped": skipped,
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
        "llm_api_calls": steps,  # model requests (an analyzed mail takes several: tool calls, then the answer)
        "llm_may_lower": llm_may_lower,
        "llm_lowered": lowered,
        "llm_raised": raised,
        "tokens": {"input": in_tok, "output": out_tok},
        "cost_per_1k_usd": cost,
        "recall_at_fpr": {f"{int(t * 100)}%": recall_at_fpr(scored, t, fpr_ref) for t in (0.01, 0.05)},
        "sweep": sweep(scored),
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
        "| Dataset | Mode | Threshold | Accuracy | Precision | Recall | F1 | Recall @1% FPR | Recall @5% FPR "
        "| Avg latency | LLM call rate | Cost / 1k emails |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in results:
        ds = r.get("dataset", "synthetic")
        if r.get("not_run"):
            rows.append(f"| {ds} | {r['mode']} | | skipped: {r['not_run']} | | | | | | | | |")
            continue
        cost = "n/a (pass --price-in/--price-out)" if r["cost_per_1k_usd"] is None else f"${r['cost_per_1k_usd']}"
        rows.append(
            f"| {ds} | {r['mode']} | {r['threshold']:g} | {_pct(r['accuracy'])} | {_pct(r['precision'])} | "
            f"{_pct(r['recall'])} | {_pct(r['f1'])} | {_at(r, '1%')} | {_at(r, '5%')} | "
            f"{r['avg_latency_ms']} ms | {_pct(r['llm_call_rate'])} | {cost} |"
        )
    return "\n".join(rows)


def _at(r: dict, key: str) -> str:
    m = r["recall_at_fpr"][key]
    return f"{_pct(m['recall'])} (t={m['threshold']:.1f})"


def sweep_table(results: list[dict]) -> str:
    cats = sorted({c for r in results if not r.get("not_run") for c in r["sweep"][0]["fpr_by_category"]})
    head = "| Dataset | Mode | Threshold | Precision | Recall | F1 | " + " | ".join(f"FPR {c}" for c in cats) + " |"
    rows = [head, "|" + "---|" * (6 + len(cats))]
    for r in results:
        if r.get("not_run"):
            continue
        for row in r["sweep"]:
            fprs = " | ".join(_pct(row["fpr_by_category"].get(c)) for c in cats)
            rows.append(
                f"| {r['dataset']} | {r['mode']} | {row['threshold']:g} | {_pct(row['precision'])} | "
                f"{_pct(row['recall'])} | {_pct(row['f1'])} | {fprs} |"
            )
    return "\n".join(rows)


def confusion_table(results: list[dict]) -> str:
    rows = ["| Dataset | Mode | Category | TP | FP | TN | FN | Recall | FPR |", "|---|---|---|---|---|---|---|---|---|"]
    for r in results:
        if r.get("not_run"):
            continue
        for cat, v in r["per_category"].items():
            rows.append(
                f"| {r['dataset']} | {r['mode']} | {cat} | {v['tp']} | {v['fp']} | {v['tn']} | {v['fn']} | "
                f"{_pct(v['recall'])} | {_pct(v['false_positive_rate'])} |"
            )
    return "\n".join(rows)


def run_modes(modes: list[str], datasets: tuple[str, ...] = ("synthetic",), split: bool = False, **kw) -> list[dict]:
    """With split=True, external data is reported as two rows: dev (70%) and test (30%).
    Tune on dev; quote only test."""
    out = []
    for ds in datasets:
        parts = ("dev", "test") if split and ds == "external" else (None,)
        for part in parts:
            for m in modes:
                label = f"{ds}:{part}" if part else ds
                if m != "rules" and kw.get("llm") is None and not os.environ.get("ANTHROPIC_API_KEY"):
                    out.append({"mode": m, "dataset": label, "not_run": "ANTHROPIC_API_KEY not set"})
                    continue
                out.append(evaluate(mode=m, dataset=ds, split=part, **kw))
    return out


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=100, help="emails per category")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    ap.add_argument("--sweep", action="store_true", help="also print metrics at thresholds 30-60 (step 5)")
    ap.add_argument("--fpr-ref", default=None, help="category used as the FPR reference, e.g. easy_ham")
    ap.add_argument("--modes", default="rules", help="comma list of rules,llm,hybrid")
    ap.add_argument("--gray-low", type=float, default=20.0)
    ap.add_argument("--gray-high", type=float, default=50.0)
    ap.add_argument(
        "--llm-may-lower",
        action="store_true",
        help="llm/hybrid: allow the benign vote (band-limited, floored; see agent.lowered_risk)",
    )
    ap.add_argument("--price-in", type=float, default=None, help="USD per million input tokens")
    ap.add_argument("--price-out", type=float, default=None, help="USD per million output tokens")
    ap.add_argument("--dataset", choices=["synthetic", "external", "both"], default="synthetic")
    ap.add_argument("--data-dir", default=None, help="default: data/external")
    ap.add_argument("--limit", type=int, default=None, help="external: max messages per class (sampled)")
    ap.add_argument(
        "--split",
        action="store_true",
        help="external: report dev (70%%) and test (30%%) separately; split is a fixed salted content hash",
    )
    ap.add_argument("--weights", default=None, help="alternative weights.yaml (e.g. a calibration suggestion)")
    ap.add_argument("--json", action="store_true", help="print full JSON instead of the table")
    a = ap.parse_args(argv)
    modes = [m.strip() for m in a.modes.split(",") if m.strip()]
    bad = set(modes) - set(MODES)
    if bad:
        ap.error(f"unknown modes: {sorted(bad)}")
    datasets = ("synthetic", "external") if a.dataset == "both" else (a.dataset,)
    if "external" in datasets:
        from .external import ExternalDataMissing, load_external

        try:
            load_external(a.data_dir, 1)
        except ExternalDataMissing as e:
            print(f"external dataset not available: {e}")
            raise SystemExit(2) from None
    weights = None
    if a.weights:
        from ..readonly.features import load_weights

        weights = load_weights(a.weights)
    results = run_modes(
        modes,
        datasets,
        split=a.split,
        weights=weights,
        data_dir=a.data_dir,
        limit_per_class=a.limit,
        n_per_category=a.n,
        seed=a.seed,
        threshold=a.threshold,
        fpr_ref=a.fpr_ref,
        gray_zone=(a.gray_low, a.gray_high),
        price_in=a.price_in,
        price_out=a.price_out,
        llm_may_lower=a.llm_may_lower,
    )
    if a.json:
        print(json.dumps(results, indent=2))
        return
    print(comparison_table(results))
    print()
    print(confusion_table(results))
    if a.sweep:
        print()
        print(sweep_table(results))
    for r in results:
        if r.get("skipped"):
            print(f"\n{r['dataset']}: skipped unparseable/oversized messages: {r['skipped']}")


if __name__ == "__main__":
    main()
