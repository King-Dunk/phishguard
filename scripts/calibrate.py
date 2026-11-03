"""Suggest feature weights (and a threshold) from the DEV split of the public corpora. Never touches
the test split, never overwrites phishguard/readonly/weights.yaml.

    python scripts/calibrate.py --data-dir data/external --out weights.suggested.yaml
    python scripts/calibrate.py --objective balanced --threshold 35
    python -m phishguard.dataset.evaluate --dataset external --split --fpr-ref easy_ham \\
        --weights weights.suggested.yaml --threshold <suggested>

Objectives (F1 is deliberately NOT one: with phishing:ham about 3:1, F1 rewards flagging everything;
the previous F1-driven suggestion reached 88.4% recall with 38.2% easy_ham FPR):
- recall_at_fpr (default): maximize recall subject to FPR <= --max-fpr (1%) on --fpr-ref (easy_ham).
  The threshold is re-derived for every candidate, so the metric is independent of the class ratio.
  --max-fpr-hard adds a second cap on hard_ham.
- balanced: at a fixed --threshold, the mean of per-category accuracy (recall for each phishing
  category, 1-FPR for each legitimate one). Every category counts equally, whatever its size.
Search: coordinate ascent over a coarse grid, minus l1 * sum |w - w_prior|.

Anti-overfitting:
- only the dev split (70%) is loaded; 20% of it (dev-val, own content hash) is held out and reported
- features firing on fewer than --min-support dev messages keep their prior weight
- the L1 pull toward the hand-set prior; a coarse grid; weight cap 0.8
- frozen features keep their weight:
  * always: security features the corpus has no evidence about (prompt injection, look-alikes of OUR
    domains, executives, bank-detail change, header anomalies, reputation)
  * by default (--frozen): era/time-zone artifacts, no_authentication and off_hours_send. 2002 ham
    has no DKIM/DMARC, so an unfrozen no_authentication learns "old = safe" (the rejected suggestion
    raised it to 0.45). Pass --frozen none to unfreeze them, or your own comma list.
"""

from __future__ import annotations

import argparse
import hashlib
import math
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import yaml  # noqa: E402

from phishguard.config import DEFAULT_THRESHOLD  # noqa: E402
from phishguard.dataset.external import load_external, split_items  # noqa: E402
from phishguard.dataset.metrics import Scored, at_threshold, threshold_for_fpr  # noqa: E402
from phishguard.readonly.features import (  # noqa: E402
    WEIGHTS_PATH,
    DetectionContext,
    extract_features,
    load_weights,
)

GRID = (0.0, 0.01, 0.03, 0.05, 0.08, 0.12, 0.16, 0.2, 0.25, 0.3, 0.35, 0.4, 0.45, 0.5, 0.6, 0.7, 0.8)
FROZEN = frozenset(
    {
        "prompt_injection_attempt",
        "homoglyph_domain",
        "lookalike_domain",
        "lookalike_link",
        "executive_impersonation",
        "display_name_spoof",
        "bank_detail_change",
        "header_anomaly",
        "obfuscated_text",
        "low_reputation",
        "moderate_reputation",
        "new_domain",
        "young_domain",
    }
)


ERA_FROZEN_DEFAULT = ("no_authentication", "off_hours_send")
SECURITY_FROZEN = FROZEN  # cannot be unfrozen from the command line
OBJECTIVES = ("recall_at_fpr", "balanced")


class RefuseOverwrite(RuntimeError):
    pass


Vec = tuple[int, str, tuple[str, ...]]  # (label, category, fired feature keys)


def vectorize(items, ctx) -> list[Vec]:
    """Per message: label, category, fired feature keys (weight-0 features included). No content kept."""
    return [
        (it.label, it.category, tuple(sorted({f.key for f in extract_features(it.email, ctx, keep_zero=True)})))
        for it in items
    ]


def scores(data: list[Vec], weights: dict[str, float]) -> list[Scored]:
    logs = {k: math.log(1 - min(w, 0.999)) for k, w in weights.items()}
    return [Scored(100 * (1 - math.exp(sum(logs.get(k, 0.0) for k in keys))), lab, cat) for lab, cat, keys in data]


def operating_point(data: list[Vec], weights: dict[str, float], cfg: dict) -> dict:
    """Threshold + metrics for one weight table under the chosen objective."""
    sc = scores(data, weights)
    if cfg["objective"] == "recall_at_fpr":
        t = threshold_for_fpr(sc, cfg["max_fpr"], cfg["fpr_ref"])
        if cfg.get("max_fpr_hard") is not None:
            t = max(t, threshold_for_fpr(sc, cfg["max_fpr_hard"], "hard_ham"))
        m = at_threshold(sc, t)
        m["objective"] = m["recall"] or 0.0
    else:
        m = at_threshold(sc, cfg["threshold"])
        m["objective"] = balanced(sc, cfg["threshold"])
    return m


def balanced(sc: list[Scored], t: float) -> float:
    cats = sorted({s.category for s in sc})
    per = []
    for c in cats:
        xs = [s for s in sc if s.category == c]
        ok = sum((s.risk >= t) == bool(s.label) for s in xs)
        per.append(ok / len(xs))
    return sum(per) / len(per) if per else 0.0


def fit(
    data: list[Vec],
    prior: dict[str, float],
    cfg: dict,
    frozen: frozenset[str] = SECURITY_FROZEN,
    min_support: int = 30,
    l1: float = 0.02,
    passes: int = 3,
) -> dict[str, float]:
    support = {k: sum(k in keys for _, _, keys in data) for k in prior}
    tunable = [k for k in sorted(prior) if k not in frozen and support[k] >= min_support]
    w = dict(prior)

    def objective(ws):
        return operating_point(data, ws, cfg)["objective"] - l1 * sum(abs(ws[k] - prior[k]) for k in tunable)

    best = objective(w)
    for _ in range(passes):
        improved = False
        for k in tunable:
            for g in GRID:
                if g == w[k]:
                    continue
                trial = {**w, k: g}
                score = objective(trial)
                if score > best + 1e-9:
                    best, w, improved = score, trial, True
        if not improved:
            break
    return w


def suggest_threshold(data: list[Vec], weights: dict[str, float], cfg: dict) -> float:
    if cfg["objective"] == "recall_at_fpr":
        return math.ceil(operating_point(data, weights, cfg)["threshold"] * 10) / 10
    sc = scores(data, weights)
    return max(range(20, 61), key=lambda t: (balanced(sc, t), -t))


def _inner(email) -> bool:
    """True for the 20% of dev held out for validation (content hash, independent of the dev/test hash)."""
    key = f"dev-val|{email.sender_email}|{email.subject}|{email.body[:4000]}".encode("utf-8", "replace")
    return int.from_bytes(hashlib.sha256(key).digest()[:8], "big") / 2**64 < 0.2


def _fmt(m: dict) -> str:
    def p(x):
        return "n/a" if x is None else f"{100 * x:.1f}%"

    fprs = ", ".join(f"FPR {c} {p(v)}" for c, v in m["fpr_by_category"].items())
    return f"t={m['threshold']:.1f} recall {p(m['recall'])} precision {p(m['precision'])} {fprs}"


def write_suggestion(path: Path, weights: dict[str, float], prior_path: Path, report: dict) -> None:
    if path.resolve() == Path(WEIGHTS_PATH).resolve() or path.resolve() == prior_path.resolve():
        raise RefuseOverwrite(f"refusing to overwrite {path}; write a suggestion and review it")
    raw = yaml.safe_load(prior_path.read_text(encoding="utf-8"))
    raw["weights"] = {k: round(v, 3) for k, v in weights.items()}
    raw["suggested_threshold"] = report["suggested_threshold"]
    header = [
        "# SUGGESTED weights from scripts/calibrate.py. NOT active. Review, then copy values into",
        "# phishguard/readonly/weights.yaml (and the threshold into config) by hand; test split once.",
        f"# objective: {report['objective_desc']}",
        f"# frozen (not tuned): {', '.join(sorted(report['frozen']))}",
        f"# dev-fit n={report['n_fit']}  dev-val n={report['n_val']}  min_support={report['min_support']}",
        f"# dev-val prior:     {report['val_prior']}",
        f"# dev-val suggested: {report['val_new']}  (held out from fitting)",
        f"# suggested threshold: {report['suggested_threshold']}",
        "# changed: "
        + (", ".join(f"{k} {report['prior'][k]}->{v}" for k, v in report["changed"].items()) or "nothing"),
    ]
    path.write_text(
        "\n".join(header) + "\n" + yaml.safe_dump(raw, sort_keys=False, allow_unicode=True), encoding="utf-8"
    )


def calibrate(
    items_dev,
    prior_path: Path = WEIGHTS_PATH,
    min_support: int = 30,
    l1: float = 0.02,
    objective: str = "recall_at_fpr",
    max_fpr: float = 0.01,
    fpr_ref: str = "easy_ham",
    max_fpr_hard: float | None = None,
    threshold: float = DEFAULT_THRESHOLD,
    frozen_extra: tuple[str, ...] = ERA_FROZEN_DEFAULT,
) -> tuple[dict, dict]:
    if objective not in OBJECTIVES:
        raise ValueError(f"objective must be one of {OBJECTIVES}")
    table = load_weights(prior_path)
    unknown = set(frozen_extra) - set(table.weights)
    if unknown:
        raise ValueError(f"--frozen names unknown features: {sorted(unknown)}")
    frozen = SECURITY_FROZEN | frozenset(frozen_extra)
    cfg = {
        "objective": objective,
        "max_fpr": max_fpr,
        "fpr_ref": fpr_ref,
        "max_fpr_hard": max_fpr_hard,
        "threshold": threshold,
    }
    ctx = DetectionContext(trusted_domains=(), executives=(), weights=table)
    fit_v = vectorize([it for it in items_dev if not _inner(it.email)], ctx)
    val_v = vectorize([it for it in items_dev if _inner(it.email)], ctx)
    prior = dict(table.weights)
    new = fit(fit_v, prior, cfg, frozen, min_support, l1)
    t_new = suggest_threshold(fit_v, new, cfg)
    t_prior = suggest_threshold(fit_v, prior, cfg)
    val = val_v or fit_v
    desc = (
        f"max recall s.t. FPR({fpr_ref}) <= {max_fpr:.1%}"
        + (f", FPR(hard_ham) <= {max_fpr_hard:.1%}" if max_fpr_hard else "")
        if objective == "recall_at_fpr"
        else f"balanced per-category accuracy at threshold {threshold:g}"
    )
    report = {
        "objective": objective,
        "objective_desc": desc,
        "frozen": frozen,
        "n_fit": len(fit_v),
        "n_val": len(val_v),
        "min_support": min_support,
        "prior": prior,
        "suggested_threshold": t_new,
        "prior_threshold": t_prior,
        "fit_prior": operating_point(fit_v, prior, cfg),
        "fit_new": operating_point(fit_v, new, cfg),
        "val_prior_m": at_threshold(scores(val, prior), t_prior),
        "val_new_m": at_threshold(scores(val, new), t_new),
        "changed": {k: v for k, v in new.items() if v != prior[k]},
    }
    report["val_prior"] = _fmt(report["val_prior_m"])
    report["val_new"] = _fmt(report["val_new_m"])
    return new, report


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Suggest weights from the dev split (never the test split).")
    ap.add_argument("--data-dir", default=None)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--prior", default=str(WEIGHTS_PATH))
    ap.add_argument("--out", default="weights.suggested.yaml")
    ap.add_argument("--objective", choices=OBJECTIVES, default="recall_at_fpr")
    ap.add_argument("--max-fpr", type=float, default=0.01, help="FPR cap on --fpr-ref (default 1%%)")
    ap.add_argument("--fpr-ref", default="easy_ham", help="legitimate category the FPR cap applies to")
    ap.add_argument("--max-fpr-hard", type=float, default=None, help="optional extra FPR cap on hard_ham")
    ap.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD, help="for --objective balanced")
    ap.add_argument(
        "--frozen",
        default=",".join(ERA_FROZEN_DEFAULT),
        help="comma list of extra features not to tune (default: era/time-zone artifacts); 'none' for none",
    )
    ap.add_argument("--min-support", type=int, default=30)
    ap.add_argument("--l1", type=float, default=0.02)
    a = ap.parse_args(argv)
    frozen_extra = (
        () if a.frozen.strip().lower() == "none" else tuple(x.strip() for x in a.frozen.split(",") if x.strip())
    )
    dev = split_items(load_external(a.data_dir, a.limit).items, "dev")  # the test split is never loaded here
    new, rep = calibrate(
        dev,
        Path(a.prior),
        a.min_support,
        a.l1,
        a.objective,
        a.max_fpr,
        a.fpr_ref,
        a.max_fpr_hard,
        a.threshold,
        frozen_extra,
    )
    write_suggestion(Path(a.out), new, Path(a.prior), rep)
    print(f"objective: {rep['objective_desc']}")
    print(f"dev-val prior:     {rep['val_prior']}")
    print(f"dev-val suggested: {rep['val_new']}  (held out)")
    print(f"suggested threshold: {rep['suggested_threshold']}")
    print("changed:", rep["changed"] or "nothing")
    vp, vn = rep["val_prior_m"], rep["val_new_m"]
    ref = vn["fpr_by_category"].get(a.fpr_ref, vn["fpr"])
    if (vn["recall"] or 0) < (vp["recall"] or 0) or (ref is not None and ref > 2 * a.max_fpr):
        print("WARNING: on held-out dev the suggestion loses recall or breaks the FPR cap. Do not adopt it.")
    print(f"suggestion written to {a.out} (not active)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
