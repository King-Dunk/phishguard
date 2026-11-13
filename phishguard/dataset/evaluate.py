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

Real-model runs on a budget: --max-llm-api-calls N is a hard cap on model requests (one mail takes
several: tool calls, then the answer); --llm-sample "hard_ham=31,easy_ham=30" sends only a fixed
content-hash sample of the gray-zone mails of each category to the model (the rest keep their rule
score); --split-part test evaluates one side of the split. The "LLM-reviewed mails" table then
compares rules and hybrid on exactly the mails the model saw.

llm/hybrid run only when ANTHROPIC_API_KEY is set (or an LLMClient is injected, as tests do).
Prices are inputs, not hard-coded: pass current list prices to get a cost column.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import statistics
import time

from ..agent import PhishingAgent
from ..config import DEFAULT_THRESHOLD, Settings
from ..llm.base import LLMClient, LLMResponse
from ..readonly import DetectionContext, analyze_email
from .generator import CATEGORIES, EXECUTIVES, TRUSTED_DOMAINS, generate_dataset
from .metrics import Scored, recall_at_fpr, sweep

MODES = ("rules", "llm", "hybrid")


class LLMBudgetExhausted(RuntimeError):
    pass


class BudgetedLLM(LLMClient):
    """Hard cap on model requests. The count goes up before the request is sent, so a failed or
    interrupted request still counts, and request number max_calls + 1 is never made."""

    def __init__(self, inner: LLMClient, max_calls: int | None):
        self.inner, self.max_calls, self.calls = inner, max_calls, 0

    def complete(self, **kw) -> LLMResponse:
        if self.max_calls is not None and self.calls >= self.max_calls:
            raise LLMBudgetExhausted(f"LLM call budget of {self.max_calls} requests is used up")
        self.calls += 1
        return self.inner.complete(**kw)


def _sample_key(email) -> str:
    raw = f"llm-sample|{email.sender_email}|{email.subject}|{email.body[:4000]}".encode("utf-8", "replace")
    return hashlib.sha256(raw).hexdigest()


def _confusion(rows: list[tuple[float, int, str]], threshold: float) -> dict:
    """rows: (risk, label, category) -> totals and per-category counts at `threshold`."""
    out: dict = {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "per_category": {}}
    for risk, label, cat in rows:
        pred = risk >= threshold
        key = ("tp" if pred else "fn") if label else ("fp" if pred else "tn")
        out[key] += 1
        out["per_category"].setdefault(cat, {"tp": 0, "fp": 0, "tn": 0, "fn": 0})[key] += 1
    return out


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
    llm_sample: dict[str, int] | None = None,
    max_llm_api_calls: int | None = None,
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

            # no SDK retries when a budget is set: one complete() must be exactly one request
            llm = AnthropicLLM(Settings.from_env(), max_retries=0 if max_llm_api_calls is not None else None)
        llm = BudgetedLLM(llm, max_llm_api_calls)
        agent = PhishingAgent(llm, Settings(llm_may_lower=llm_may_lower), ctx)

    tp = fp = tn = fn = calls = in_tok = out_tok = lowered = raised = steps = 0
    errors = skipped_budget = not_sampled = 0
    first_error = ""
    scored: list[Scored] = []
    latency = 0.0
    llm_seconds: list[float] = []
    reviewed: list[dict] = []  # one row per mail the model actually answered for
    per_cat = {c: {"tp": 0, "fp": 0, "tn": 0, "fn": 0} for c in categories}

    rule_risks = [analyze_email(it.email, ctx)[0] for it in data] if agent and llm_sample is not None else None
    chosen: set[int] | None = None
    if rule_risks is not None:
        # fixed sample: per category, the gray-zone mails with the smallest content hashes
        by_cat: dict[str, list[tuple[str, int]]] = {}
        for i, (it, r0) in enumerate(zip(data, rule_risks, strict=True)):
            if mode == "llm" or gray_zone[0] <= r0 <= gray_zone[1]:
                by_cat.setdefault(it.category, []).append((_sample_key(it.email), i))
        chosen = {i for cat, lst in by_cat.items() for _, i in sorted(lst)[: max(0, llm_sample.get(cat, 0))]}

    for i, it in enumerate(data):
        t0 = time.perf_counter()
        risk, _ = analyze_email(it.email, ctx)
        if agent and (mode == "llm" or gray_zone[0] <= risk <= gray_zone[1]):
            if chosen is not None and i not in chosen:
                not_sampled += 1
            else:
                rule_risk = risk
                try:
                    r = agent.analyze(it.email)
                except LLMBudgetExhausted:
                    skipped_budget += 1
                except Exception as e:  # an API error on one mail must not lose the whole run
                    errors += 1
                    first_error = first_error or f"{type(e).__name__}: {e}"[:300]
                else:
                    risk = r.risk_percent
                    calls += 1
                    steps += r.steps_used
                    in_tok += r.input_tokens
                    out_tok += r.output_tokens
                    lowered += r.lowered_by_llm
                    raised += r.risk_percent > r.rule_risk
                    llm_seconds.append(time.perf_counter() - t0)
                    reviewed.append(
                        {
                            "category": it.category,
                            "label": it.label,
                            "rule_risk": rule_risk,
                            "llm_risk": r.llm_risk,
                            "final_risk": r.risk_percent,
                            "raise_only_risk": rule_risk if r.llm_risk is None else max(rule_risk, r.llm_risk),
                            "content_floor": r.content_floor,
                            "steps": r.steps_used,
                            "circuit_break": r.circuit_break,
                        }
                    )
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
        "llm_api_calls_attempted": llm.calls if agent else 0,  # includes failed and budget-cut mails
        "llm_errors": errors,
        "llm_first_error": first_error,
        "llm_skipped_budget": skipped_budget,
        "llm_not_sampled": not_sampled,
        "llm_sample": llm_sample,
        "llm_cost_usd": (
            round((in_tok * price_in + out_tok * price_out) / 1e6, 6)
            if agent and price_in is not None and price_out is not None
            else None
        ),
        "llm_reviewed": _reviewed_summary(reviewed, llm_seconds, threshold) if agent else None,
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


def _reviewed_summary(rows: list[dict], seconds: list[float], threshold: float) -> dict:
    """Rules vs hybrid on exactly the mails the model answered for (same mails, same threshold)."""

    def conf(field: str) -> dict:
        return _confusion([(r[field], r["label"], r["category"]) for r in rows], threshold)

    answered = [r for r in rows if r["llm_risk"] is not None]
    return {
        "mails": len(rows),
        "no_parseable_answer": len(rows) - len(answered),
        "circuit_breaks": sum(r["circuit_break"] is not None for r in rows),
        "api_calls_per_mail": round(sum(r["steps"] for r in rows) / len(rows), 2) if rows else None,
        "latency_s": (
            {
                "mean": round(statistics.mean(seconds), 2),
                "median": round(statistics.median(seconds), 2),
                "max": round(max(seconds), 2),
            }
            if seconds
            else None
        ),
        "llm_below_threshold": sum(r["llm_risk"] < threshold for r in answered),
        "rules": conf("rule_risk"),
        "hybrid": conf("final_risk"),  # as configured (with or without the benign vote)
        "hybrid_raise_only": conf("raise_only_risk"),  # same answers, benign vote ignored
        "llm_alone": _confusion([(r["llm_risk"], r["label"], r["category"]) for r in answered], threshold),
        "rows": rows,
    }


def reviewed_table(results: list[dict]) -> str:
    rows = [
        "| Dataset | Category | LLM-reviewed mails | Scoring | TP | FP | TN | FN |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in results:
        rv = r.get("llm_reviewed") if not r.get("not_run") else None
        if not rv or not rv["mails"]:
            continue
        names = (("rules", "rules"), ("hybrid", "hybrid (as run)"), ("hybrid_raise_only", "hybrid, raise only"))
        names += (("llm_alone", "LLM score alone"),)
        for cat in sorted(rv["rules"]["per_category"]):
            n = sum(rv["rules"]["per_category"][cat].values())
            for key, label in names:
                v = rv[key]["per_category"].get(cat, {"tp": 0, "fp": 0, "tn": 0, "fn": 0})
                rows.append(
                    f"| {r['dataset']} | {cat} | {n} | {label} | {v['tp']} | {v['fp']} | {v['tn']} | {v['fn']} |"
                )
    return "\n".join(rows)


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


def run_modes(
    modes: list[str],
    datasets: tuple[str, ...] = ("synthetic",),
    split: bool = False,
    split_part: str | None = None,
    **kw,
) -> list[dict]:
    """With split=True, external data is reported as two rows: dev (70%) and test (30%).
    Tune on dev; quote only test."""
    out = []
    for ds in datasets:
        parts = ("dev", "test") if split and ds == "external" else (None,)
        if split_part and parts != (None,):
            parts = (split_part,)
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
    ap.add_argument("--split-part", choices=["dev", "test"], default=None, help="with --split: only this side")
    ap.add_argument("--max-llm-api-calls", type=int, default=None, help="hard cap on model requests per mode and split")
    ap.add_argument(
        "--llm-sample",
        default=None,
        help='send only a fixed sample of gray-zone mails to the model, per category: "hard_ham=31,easy_ham=30"',
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
    llm_sample = None
    if a.llm_sample:
        try:
            llm_sample = {k.strip(): int(v) for k, v in (p.split("=") for p in a.llm_sample.split(","))}
        except ValueError:
            ap.error("--llm-sample wants category=count pairs, e.g. hard_ham=31,easy_ham=30")
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
        llm_sample=llm_sample,
        max_llm_api_calls=a.max_llm_api_calls,
        split_part=a.split_part,
    )
    if a.json:
        print(json.dumps(results, indent=2))
        return
    print(comparison_table(results))
    print()
    print(confusion_table(results))
    rt = reviewed_table(results)
    if rt.count("\n") > 1:
        print("\nLLM-reviewed mails only (same mails under each scoring):\n")
        print(rt)
    for r in results:
        if not r.get("not_run") and r["mode"] != "rules":
            rv = r["llm_reviewed"]
            tok = r["tokens"]
            print(
                f"\n{r['dataset']} {r['mode']}: {rv['mails']} mails reviewed, "
                f"{r['llm_api_calls_attempted']} model requests, tokens in/out {tok['input']}/{tok['output']}, "
                f"cost ${r['llm_cost_usd']}, latency {rv['latency_s']}, lowered {r['llm_lowered']}, "
                f"raised {r['llm_raised']}, errors {r['llm_errors']}, budget-skipped {r['llm_skipped_budget']}, "
                f"not sampled {r['llm_not_sampled']}"
            )
            if r["llm_first_error"]:
                print(f"first error: {r['llm_first_error']}")
    if a.sweep:
        print()
        print(sweep_table(results))
    for r in results:
        if r.get("skipped"):
            print(f"\n{r['dataset']}: skipped unparseable/oversized messages: {r['skipped']}")


if __name__ == "__main__":
    main()
