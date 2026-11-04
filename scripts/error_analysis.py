"""Aggregate error analysis on the public corpora, in the format of docs/real_corpus_error_analysis.md.

    python scripts/error_analysis.py --data-dir data/external --split dev > dev_error_analysis.md

Privacy: the report holds counts, rates and feature names only. It never prints a subject, body,
address, header value, link or file name, so it can be committed or shared even though the raw mail
cannot. Default split is dev: look at test only once, for the final number.
"""

from __future__ import annotations

import argparse
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from phishguard.dataset.external import load_external, split_items  # noqa: E402
from phishguard.readonly.features import (  # noqa: E402
    DetectionContext,
    explain,
    extract_features,
    load_weights,
    risk_percent,
)

THRESHOLD = 50.0


def _pct(n: int, d: int) -> str:
    return f"{100 * n / d:.1f}%" if d else "n/a"


def collect(items, ctx: DetectionContext, threshold: float = THRESHOLD) -> dict:
    """Per-message: group, score, fired keys (incl. weight-0), contributions, structure. No content kept."""
    rows = []
    for it in items:
        allf = extract_features(it.email, ctx, keep_zero=True)
        scored = [f for f in allf if f.weight > 0]
        risk = risk_percent(scored)
        contrib = {f.key: f.contribution for f in explain(scored)}
        pred = risk >= threshold
        outcome = ("TP" if pred else "FN") if it.label else ("FP" if pred else "TN")
        e = it.email
        rows.append(
            {
                "group": f"{it.category} {outcome}",
                "label": it.label,
                "outcome": outcome,
                "risk": risk,
                "fired": {f.key for f in allf},
                "scored": tuple(sorted({f.key for f in scored})),
                "contrib": contrib,
                "has_links": bool(e.links or e.link_pairs),
                "has_attachments": bool(e.attachments or e.attachment_meta),
                "reply_to": e.reply_to is not None,
                "list_mail": e.list_mail,
                "auth_result": any(v != "none" for v in (e.spf, e.dkim, e.dmarc)),
            }
        )
    return {"rows": rows, "keys": sorted(ctx.table.weights)}


def render(stats: dict, title_note: str = "") -> str:
    rows, keys = stats["rows"], stats["keys"]
    out = [
        "# PhishGuard real-corpus error analysis (aggregate only, no message content)",
        "",
        f"Rules mode, threshold {THRESHOLD:.0f}, ctx without trusted domains/executives. {title_note}".rstrip(),
        "",
        "## Group sizes and score distribution",
        "",
        "| group | n | median score | p25 | p75 |",
        "|---|---|---|---|---|",
    ]
    groups = defaultdict(list)
    for r in rows:
        groups[r["group"]].append(r)
    for g in sorted(groups):
        scores = sorted(r["risk"] for r in groups[g])
        q = statistics.quantiles(scores, n=4, method="inclusive") if len(scores) > 1 else [scores[0]] * 3
        out.append(f"| {g} | {len(scores)} | {statistics.median(scores):.1f} | {q[0]:.1f} | {q[2]:.1f} |")

    ham = [r for r in rows if not r["label"]]
    phish = [r for r in rows if r["label"]]
    fp = [r for r in ham if r["outcome"] == "FP"]
    fn = [r for r in phish if r["outcome"] == "FN"]
    tp = [r for r in phish if r["outcome"] == "TP"]

    def rate(sub, k):
        return _pct(sum(k in r["fired"] for r in sub), len(sub))

    def mean_c(sub, k):
        vals = [r["contrib"][k] for r in sub if k in r["contrib"]]
        return f"{sum(vals) / len(vals):.1f}" if vals else "0.0"

    out += [
        "",
        "## Feature fire rate (% of emails where feature fires) and mean contribution when fired",
        "",
        "Weight-0 features are listed too: they fire but add nothing to the score.",
        "",
        "| feature | ham all | phish all | ham FP | phish FN | mean contrib in FP | mean contrib in TP |",
        "|---|---|---|---|---|---|---|",
    ]
    for k in keys:
        if not any(k in r["fired"] for r in rows):
            continue
        out.append(
            f"| {k} | {rate(ham, k)} | {rate(phish, k)} | {rate(fp, k)} | {rate(fn, k)} | {mean_c(fp, k)} | {mean_c(tp, k)} |"
        )

    traits = [
        ("no features fired", lambda r: not r["scored"]),
        ("has links", lambda r: r["has_links"]),
        ("has attachments", lambda r: r["has_attachments"]),
        ("reply_to set", lambda r: r["reply_to"]),
        ("list headers", lambda r: r["list_mail"]),
        ("any SPF/DKIM/DMARC result", lambda r: r["auth_result"]),
    ]
    tn = [r for r in ham if r["outcome"] == "TN"]
    out += [
        "",
        "## Structural traits",
        "",
        "| trait | ham FP | ham TN | phish TP | phish FN |",
        "|---|---|---|---|---|",
    ]
    for name, fn_ in traits:
        cells = [_pct(sum(fn_(r) for r in sub), len(sub)) for sub in (fp, tn, tp, fn)]
        out.append(f"| {name} | " + " | ".join(cells) + " |")

    out += ["", "## FP feature combinations (top 10)", "", "| features fired | count |", "|---|---|"]
    for combo, n in Counter(r["scored"] for r in fp).most_common(10):
        out.append(f"| {', '.join(combo) or '(none)'} | {n} |")
    out += ["", "## FN feature combinations (top 10)", "", "| features fired | count |", "|---|---|"]
    for combo, n in Counter(r["scored"] for r in fn).most_common(10):
        out.append(f"| {', '.join(combo) or '(none)'} | {n} |")
    out += ["", "Note: SpamAssassin ham is 2002-era mail (mostly no DKIM/DMARC); Nazario phish spans many years."]
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--data-dir", default=None)
    ap.add_argument("--split", choices=["dev", "test", "all"], default="dev")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument(
        "--weights", default=None, help="weights file to analyze (default: phishguard/readonly/weights.yaml)"
    )
    ap.add_argument("--out", default=None, help="write here instead of stdout")
    a = ap.parse_args(argv)
    items = load_external(a.data_dir, a.limit).items
    if a.split != "all":
        items = split_items(items, a.split)
    ctx = DetectionContext(trusted_domains=(), executives=(), weights=load_weights(a.weights) if a.weights else None)
    report = render(collect(items, ctx), f"Split: {a.split}, n={len(items)}.")
    if a.out:
        Path(a.out).write_text(report, encoding="utf-8")
    else:
        print(report, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
