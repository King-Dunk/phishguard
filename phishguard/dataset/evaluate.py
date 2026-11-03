"""Offline evaluation with MockLLM only.  python -m phishguard.dataset.evaluate --n 100 --seed 42"""
from __future__ import annotations

import argparse
import json

from ..agent import PhishingAgent
from ..config import Settings
from ..llm import MockLLM
from ..readonly import DetectionContext
from .generator import CATEGORIES, EXECUTIVES, TRUSTED_DOMAINS, generate_dataset


def evaluate(n_per_category: int = 100, seed: int = 42, threshold: float = 50.0) -> dict:
    ctx = DetectionContext(trusted_domains=TRUSTED_DOMAINS, executives=EXECUTIVES)
    agent = PhishingAgent(MockLLM(), Settings(), ctx)  # MockLLM is hard-wired: no real API calls
    tp = fp = tn = fn = 0
    per_cat = {c: {"tp": 0, "fp": 0, "tn": 0, "fn": 0} for c in CATEGORIES}
    for it in generate_dataset(n_per_category, seed):
        pred = agent.analyze(it.email).risk_percent >= threshold
        key = ("tp" if pred else "fn") if it.label else ("fp" if pred else "tn")
        per_cat[it.category][key] += 1
        tp += key == "tp"; fp += key == "fp"; tn += key == "tn"; fn += key == "fn"
    div = lambda a, b: round(a / b, 4) if b else None  # noqa: E731
    return {
        "seed": seed, "n_per_category": n_per_category, "threshold": threshold, "total": tp + fp + tn + fn,
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "accuracy": div(tp + tn, tp + fp + tn + fn),
        "precision": div(tp, tp + fp),
        "recall": div(tp, tp + fn),
        "per_category": {
            c: {**v, "recall": div(v["tp"], v["tp"] + v["fn"]), "false_positive_rate": div(v["fp"], v["fp"] + v["tn"])}
            for c, v in per_cat.items()
        },
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=100, help="emails per category")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--threshold", type=float, default=50.0)
    a = ap.parse_args()
    print(json.dumps(evaluate(a.n, a.seed, a.threshold), indent=2))


if __name__ == "__main__":
    main()
