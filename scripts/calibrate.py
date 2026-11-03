"""Suggest feature weights from the DEV split of the public corpora. Never touches the test split,
never overwrites phishguard/readonly/weights.yaml.

    python scripts/calibrate.py --data-dir data/external --out weights.suggested.yaml
    python -m phishguard.dataset.evaluate --dataset external --split --weights weights.suggested.yaml

Method: coordinate ascent over a small grid of weights per feature, maximizing
    F1(dev-fit) - l1 * sum |w - w_prior|
Anti-overfitting:
- only the dev split (70%) is loaded; inside it, 20% (dev-val, by content hash) is held out to show
  whether the gain generalizes before anything is written
- features that fire on fewer than --min-support dev messages keep their prior weight
- the L1 pull toward the hand-set prior keeps weights from swinging for a tiny F1 gain
- a coarse grid (no continuous optimizer) and a weight cap of 0.8
- security-critical features (FROZEN) keep their weight: real-corpus statistics can't speak for
  attacks the corpus doesn't contain (prompt injection, look-alikes of OUR domains, executives)
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

from phishguard.dataset.external import load_external, split_items  # noqa: E402
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


class RefuseOverwrite(RuntimeError):
    pass


def vectorize(items, ctx) -> list[tuple[int, tuple[str, ...]]]:
    """(label, fired feature keys) per message; weight-0 features included."""
    return [(it.label, tuple(sorted({f.key for f in extract_features(it.email, ctx, keep_zero=True)}))) for it in items]


def f1(data, weights: dict[str, float], threshold: float = 50.0) -> float:
    tp = fp = fn = 0
    logs = {k: math.log(1 - min(w, 0.999)) for k, w in weights.items()}
    cut = math.log(1 - threshold / 100)
    for label, keys in data:
        pred = sum(logs.get(k, 0.0) for k in keys) <= cut  # 1 - exp(sum) >= threshold
        tp += pred and label
        fp += pred and not label
        fn += (not pred) and label
    return 2 * tp / (2 * tp + fp + fn) if tp else 0.0


def fit(data, prior: dict[str, float], min_support: int = 30, l1: float = 0.02, passes: int = 3) -> dict[str, float]:
    support = {k: sum(k in keys for _, keys in data) for k in prior}
    tunable = [k for k in sorted(prior) if k not in FROZEN and support[k] >= min_support]
    w = dict(prior)

    def objective(ws):
        return f1(data, ws) - l1 * sum(abs(ws[k] - prior[k]) for k in tunable)

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


def _inner(email) -> bool:
    """True for the 20% of dev held out for validation (content hash, independent of the dev/test hash)."""
    key = f"dev-val|{email.sender_email}|{email.subject}|{email.body[:4000]}".encode("utf-8", "replace")
    return int.from_bytes(hashlib.sha256(key).digest()[:8], "big") / 2**64 < 0.2


def write_suggestion(path: Path, weights: dict[str, float], prior_path: Path, report: dict) -> None:
    if path.resolve() == Path(WEIGHTS_PATH).resolve() or path.resolve() == prior_path.resolve():
        raise RefuseOverwrite(f"refusing to overwrite {path}; write a suggestion and review it")
    raw = yaml.safe_load(prior_path.read_text(encoding="utf-8"))
    raw["weights"] = {k: round(v, 3) for k, v in weights.items()}
    header = [
        "# SUGGESTED weights from scripts/calibrate.py. NOT active. Review, then copy values into",
        "# phishguard/readonly/weights.yaml by hand and re-run the test split once.",
        f"# dev-fit n={report['n_fit']}  dev-val n={report['n_val']}  min_support={report['min_support']}",
        f"# F1 dev-fit {report['f1_fit_prior']:.4f} -> {report['f1_fit_new']:.4f}",
        f"# F1 dev-val {report['f1_val_prior']:.4f} -> {report['f1_val_new']:.4f}  (held out from fitting)",
        "# changed: " + ", ".join(f"{k} {report['prior'][k]}->{v}" for k, v in report["changed"].items()),
    ]
    path.write_text(
        "\n".join(header) + "\n" + yaml.safe_dump(raw, sort_keys=False, allow_unicode=True), encoding="utf-8"
    )


def calibrate(items_dev, prior_path: Path = WEIGHTS_PATH, min_support: int = 30, l1: float = 0.02) -> tuple[dict, dict]:
    table = load_weights(prior_path)
    ctx = DetectionContext(trusted_domains=(), executives=(), weights=table)
    fit_items = [it for it in items_dev if not _inner(it.email)]
    val_items = [it for it in items_dev if _inner(it.email)]
    fit_v, val_v = vectorize(fit_items, ctx), vectorize(val_items, ctx)
    prior = dict(table.weights)
    new = fit(fit_v, prior, min_support=min_support, l1=l1)
    report = {
        "n_fit": len(fit_v),
        "n_val": len(val_v),
        "min_support": min_support,
        "prior": prior,
        "f1_fit_prior": f1(fit_v, prior),
        "f1_fit_new": f1(fit_v, new),
        "f1_val_prior": f1(val_v, prior) if val_v else 0.0,
        "f1_val_new": f1(val_v, new) if val_v else 0.0,
        "changed": {k: v for k, v in new.items() if v != prior[k]},
    }
    return new, report


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Suggest weights from the dev split (never the test split).")
    ap.add_argument("--data-dir", default=None)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--prior", default=str(WEIGHTS_PATH))
    ap.add_argument("--out", default="weights.suggested.yaml")
    ap.add_argument("--min-support", type=int, default=30)
    ap.add_argument("--l1", type=float, default=0.02)
    a = ap.parse_args(argv)
    dev = split_items(load_external(a.data_dir, a.limit).items, "dev")  # the test split is never loaded here
    new, rep = calibrate(dev, Path(a.prior), a.min_support, a.l1)
    write_suggestion(Path(a.out), new, Path(a.prior), rep)
    print(f"dev-fit F1 {rep['f1_fit_prior']:.4f} -> {rep['f1_fit_new']:.4f}")
    print(f"dev-val F1 {rep['f1_val_prior']:.4f} -> {rep['f1_val_new']:.4f} (held out)")
    print("changed:", rep["changed"] or "nothing")
    if rep["f1_val_new"] < rep["f1_val_prior"]:
        print("WARNING: held-out dev F1 got worse; the suggestion likely overfits. Do not adopt it.")
    print(f"suggestion written to {a.out} (not active)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
