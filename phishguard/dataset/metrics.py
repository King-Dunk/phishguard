"""Threshold-free and threshold-sweep metrics shared by evaluate.py and scripts/calibrate.py.

Why: with phishing:ham around 3:1 in the real test split, F1 and accuracy reward flagging everything.
Recall at a fixed false-positive rate does not depend on the class ratio: it answers "if we may annoy
at most 1% of legitimate mail, how much phishing do we catch?".
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

SWEEP_THRESHOLDS = (30.0, 35.0, 40.0, 45.0, 50.0, 55.0, 60.0)


@dataclass(frozen=True)
class Scored:
    risk: float
    label: int  # 1 phishing, 0 legitimate
    category: str


def _ref(scores: Sequence[Scored], ref_category: str | None) -> list[float]:
    ham = [s for s in scores if not s.label]
    if ref_category and any(s.category == ref_category for s in ham):
        ham = [s for s in ham if s.category == ref_category]
    return sorted((s.risk for s in ham), reverse=True)


def threshold_for_fpr(scores: Sequence[Scored], target_fpr: float, ref_category: str | None = None) -> float:
    """Lowest threshold t (flag if risk >= t) whose FPR on the reference legitimate set is <= target.
    Ties are resolved conservatively: every legitimate mail scoring exactly at the cut stays unflagged."""
    ref = _ref(scores, ref_category)
    if not ref:
        return 0.0
    k = int(target_fpr * len(ref) + 1e-9)  # false positives we may afford
    if k >= len(ref):
        return 0.0
    return round(ref[k] + 1e-6, 6)


def at_threshold(scores: Sequence[Scored], t: float) -> dict:
    tp = sum(s.label and s.risk >= t for s in scores)
    fn = sum(s.label and s.risk < t for s in scores)
    fp = sum((not s.label) and s.risk >= t for s in scores)
    tn = sum((not s.label) and s.risk < t for s in scores)
    p = tp / (tp + fp) if tp + fp else None
    r = tp / (tp + fn) if tp + fn else None
    f1 = 2 * p * r / (p + r) if p and r else 0.0
    cats = sorted({s.category for s in scores if not s.label})
    fpr = {}
    for c in cats:
        hs = [s for s in scores if not s.label and s.category == c]
        fpr[c] = sum(s.risk >= t for s in hs) / len(hs)
    return {
        "threshold": t,
        "precision": p,
        "recall": r,
        "f1": f1,
        "fpr": (fp / (fp + tn)) if fp + tn else None,
        "fpr_by_category": fpr,
    }


def recall_at_fpr(scores: Sequence[Scored], target_fpr: float, ref_category: str | None = None) -> dict:
    t = threshold_for_fpr(scores, target_fpr, ref_category)
    return {**at_threshold(scores, t), "target_fpr": target_fpr, "fpr_reference": ref_category or "all legitimate"}


def sweep(scores: Sequence[Scored], thresholds: Iterable[float] = SWEEP_THRESHOLDS) -> list[dict]:
    return [at_threshold(scores, t) for t in thresholds]
