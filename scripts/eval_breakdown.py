"""Break detection results down by source, year and customization tier (aggregate numbers only, no mail content).

    python -I scripts/eval_breakdown.py                      # every part whose data is present -> docs/EVAL_BREAKDOWN.md
    python -I scripts/eval_breakdown.py --parts tiers        # synthetic tiers only (needs no downloads)
    python -I scripts/eval_breakdown.py --json out.json      # also write the numbers as JSON

Parts
  nazario  Nazario public corpus per year. TEST split only, the dev split is shown next to it as an overfitting check
           (weights were tuned on dev). Needs scripts/download_datasets.py --only phish.
  pot      Phishing Pot sample (scripts/download_datasets.py --only pot). Nothing was tuned on it, so all of it is test
           data. CC BY-NC 4.0: non-commercial research only.
  tiers    Synthetic customization tiers (phishguard/dataset/tiers.py), each with look-alike legitimate controls.

Rules mode at the default threshold with the shipped weights; no model is called. Every rate comes with a 95% Wilson
interval, so small groups show how little they can tell.
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import hashlib
import json
import pathlib
import statistics
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from phishguard.config import DEFAULT_THRESHOLD  # noqa: E402
from phishguard.dataset.external import ExternalDataMissing, load_external, split_of  # noqa: E402
from phishguard.dataset.metrics import wilson  # noqa: E402
from phishguard.dataset.pot import load_pot  # noqa: E402
from phishguard.dataset.tiers import CONTROL_NAMES, TIER_NAMES, TIERS, detection_context, generate_tiers  # noqa: E402
from phishguard.readonly import DetectionContext, analyze_email, parse_eml  # noqa: E402
from phishguard.readonly.features import WEIGHTS_PATH  # noqa: E402

THR = DEFAULT_THRESHOLD
NEUTRAL = DetectionContext(trusted_domains=(), executives=())  # same context as the README's public-corpus numbers
ERAS = [
    ("2004-2007", ["phishing0", "phishing1", "phishing2", "phishing3"]),
    ("2007-2015", ["private-phishing4"]),
    ("2015-2019", [f"phishing-{y}" for y in range(2015, 2020)]),
    ("2020-2023", [f"phishing-{y}" for y in range(2020, 2024)]),
    ("2024-2025", ["phishing-2024", "phishing-2025"]),
]


# ---------------------------------------------------------------------------- helpers
def pct(k: int, n: int) -> str:
    if not n:
        return "n/a"
    lo, hi = wilson(k, n)
    return f"{k / n:.1%} [{lo:.1%}, {hi:.1%}]"


def score(email, ctx) -> tuple[float, list[str]]:
    risk, feats = analyze_email(email, ctx)
    return risk, [f.name for f in feats]


def auth_rates(emails) -> dict[str, float]:
    n = len(emails) or 1
    return {m: sum(getattr(e, m) == "pass" for e in emails) / n for m in ("spf", "dkim", "dmarc")}


def top(counter: collections.Counter, n: int, total: int, k: int = 5) -> str:
    return ", ".join(f"`{name}` {c / total:.0%}" for name, c in counter.most_common(k)) if total else "-"


def git_state() -> str:
    try:
        sha = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, capture_output=True, text=True
        ).stdout.strip()
        dirty = subprocess.run(
            ["git", "status", "--porcelain", "--", "phishguard"], cwd=ROOT, capture_output=True, text=True
        ).stdout
        return sha + (" + uncommitted changes in phishguard/" if dirty.strip() else "")
    except OSError:
        return "unknown"


# ---------------------------------------------------------------------------- nazario by year
def part_nazario() -> tuple[str, dict]:
    ext = load_external()
    rows: dict[str, dict] = collections.defaultdict(
        lambda: {"dev": [0, 0], "test": [0, 0], "years": [], "test_emails": []}
    )
    for it in ext.items:
        if it.label != 1:
            continue
        risk, _ = score(it.email, NEUTRAL)
        side = split_of(it.email)
        r = rows[it.source]
        r[side][0] += risk >= THR
        r[side][1] += 1
        if side == "test":
            r["test_emails"].append(it.email)
        if it.email.timestamp:
            r["years"].append(it.email.timestamp.year)

    def span(srcs: list[str]) -> str:
        ys = sorted(y for s in srcs for y in rows[s]["years"])
        if not ys:
            return "?"
        lo, hi = ys[len(ys) // 20], ys[-len(ys) // 20 - 1]
        return str(lo) if lo == hi else f"{lo}-{hi}"

    def agg(srcs: list[str], side: str) -> tuple[int, int]:
        return sum(rows[s][side][0] for s in srcs), sum(rows[s][side][1] for s in srcs)

    out = [
        "## 1. Public corpus by year (Nazario, test split)",
        "",
        "[Nazario phishing corpus](https://monkey.org/~jose/phishing/) by Jose Nazario, CC BY 4.0. "
        f"Rules only, threshold {THR:g}, no trusted domains configured (same setup as the README's public-corpus table). "
        "Weights were tuned on the dev split only; dev is shown as an overfitting check. Dates are the 5th-95th percentile "
        "of the messages' own `Date` headers.",
        "",
        "| Era | Files | Dates | Test n | Test recall [95% CI] | Dev recall | DMARC pass (test) |",
        "|---|---|---|---|---|---|---|",
    ]
    data = {"eras": {}, "years": {}}
    for era, srcs in ERAS:
        srcs = [s for s in srcs if s in rows]
        if not srcs:
            continue
        k, n = agg(srcs, "test")
        kd, nd = agg(srcs, "dev")
        dm = auth_rates([e for s in srcs for e in rows[s]["test_emails"]])["dmarc"]
        files = srcs[0] if len(srcs) == 1 else f"{srcs[0]} .. {srcs[-1]}"
        out.append(f"| **{era}** | {files} | {span(srcs)} | {n} | {pct(k, n)} | {kd / nd:.1%} | {dm:.0%} |")
        data["eras"][era] = {"test": [k, n], "dev": [kd, nd], "dmarc_pass": dm}
    k, n = agg(list(rows), "test")
    kd, nd = agg(list(rows), "dev")
    out.append(f"| **All** | {len(rows)} files | | {n} | {pct(k, n)} | {kd / nd:.1%} | |")
    data["all"] = {"test": [k, n], "dev": [kd, nd]}
    out += [
        "",
        "Per year (2015-2025 files):",
        "",
        "| Year | Test n | Test recall [95% CI] | Dev recall |",
        "|---|---|---|---|",
    ]
    for y in range(2015, 2026):
        s = f"phishing-{y}"
        if s in rows:
            (k, n), (kd, nd) = rows[s]["test"], rows[s]["dev"]
            out.append(f"| {y} | {n} | {pct(k, n)} | {kd / nd:.1%} |")
            data["years"][y] = {"test": [k, n], "dev": [kd, nd]}
    if ext.skipped:
        out += ["", f"Skipped by the parser (whole corpus, ham included): {dict(ext.skipped)}."]
    return "\n".join(out), data


# ---------------------------------------------------------------------------- phishing pot
def part_pot() -> tuple[str, dict]:
    ext, manifest = load_pot()
    flagged_feats, missed_feats = collections.Counter(), collections.Counter()
    by_year: dict[str, list[int]] = collections.defaultdict(lambda: [0, 0])
    risks, flags = [], 0
    for it in ext.items:
        risk, names = score(it.email, NEUTRAL)
        hit = risk >= THR
        flags += hit
        risks.append(risk)
        (flagged_feats if hit else missed_feats).update(set(names))
        y = it.email.timestamp.year if it.email.timestamp else None
        bucket = "unknown" if y is None else "<=2022" if y <= 2022 else str(y) if y <= 2026 else "unknown"
        by_year[bucket][0] += hit
        by_year[bucket][1] += 1
    n = len(ext.items)
    auth = auth_rates([it.email for it in ext.items])
    out = [
        "## 2. Independent recent source (Phishing Pot sample)",
        "",
        f"[Phishing Pot](https://github.com/rf-peixoto/phishing_pot) (maintainer [rf-peixoto](https://www.linkedin.com/in/rf-peixoto)), "
        f"CC BY-NC 4.0, commit `{manifest['commit'][:12]}`, seeded random sample of {manifest['requested']} of its .eml files "
        f"(seed {manifest['seed']}), every file checked against its git blob hash. Nothing was tuned on it. The maintainer notes "
        "that the honeypot also catches spam, fraud and malware delivery, so this is the share of malicious or unsolicited "
        "honeypot mail that gets flagged.",
        "",
        f"- **Flagged: {pct(flags, n)}** of {n} parsed messages; median score {statistics.median(risks):.1f}.",
        f"- Not scored: {dict(ext.skipped) or 'none'} (counted, not dropped).",
        f"- Authentication on these messages: SPF pass {auth['spf']:.0%}, DKIM pass {auth['dkim']:.0%}, DMARC pass {auth['dmarc']:.0%}.",
        "",
        "| Year (`Date` header) | n | Flagged [95% CI] |",
        "|---|---|---|",
    ]
    order = ["<=2022", "2023", "2024", "2025", "2026", "unknown"]
    for b in order:
        if b in by_year:
            k, m = by_year[b]
            out.append(f"| {b} | {m} | {pct(k, m)} |")
    missed = n - flags
    out += [
        "",
        f"Most frequent signals on flagged mail: {top(flagged_feats, 5, flags)}.",
        f"Most frequent signals on missed mail: {top(missed_feats, 5, missed)}.",
    ]
    data = {
        "flagged": [flags, n],
        "skipped": ext.skipped,
        "by_year": dict(by_year),
        "auth_pass": auth,
        "commit": manifest["commit"],
        "seed": manifest["seed"],
    }
    return "\n".join(out), data


# ---------------------------------------------------------------------------- tiers
def part_tiers(n_per_side: int, seed: int) -> tuple[str, dict]:
    ctx = detection_context()
    items = generate_tiers(n_per_side, seed)
    digest = hashlib.sha256(b"".join(it.raw for it in items)).hexdigest()[:16]
    res: dict[tuple[str, int], list] = collections.defaultdict(list)
    by_scenario: dict[tuple[str, int, str], list[int]] = collections.defaultdict(lambda: [0, 0])
    by_cues: dict[str, list[int]] = collections.defaultdict(lambda: [0, 0])
    feats: dict[tuple[str, int], collections.Counter] = collections.defaultdict(collections.Counter)
    for it in items:
        risk, names = score(parse_eml(it.raw), ctx)
        hit = risk >= THR
        res[(it.tier, it.label)].append(risk)
        by_scenario[(it.tier, it.label, it.scenario)][0] += hit
        by_scenario[(it.tier, it.label, it.scenario)][1] += 1
        feats[(it.tier, it.label)].update(set(names))
        if it.label:
            c = len(it.cues)
            b = "0-1" if c <= 1 else "2-3" if c <= 3 else "4-5" if c <= 5 else "6+"
            by_cues[b][0] += hit
            by_cues[b][1] += 1
    out = [
        "## 3. Customization tiers (synthetic, `phishguard/dataset/tiers.py`)",
        "",
        f"{n_per_side} phishing and {n_per_side} look-alike legitimate messages per tier, seed {seed} (set digest `{digest}`). "
        "Context: the fictional acme-corp.com deployment with its vendors trusted and executives known. Tiers follow the "
        "NIST Phish Scale: cues go down and premise alignment goes up from T1 to T4. The generator was written and frozen "
        "before any score was looked at, and no weight was tuned on it; it is still synthetic and written by the same author "
        "as the rules, so read it as a map of where content-based detection stops working, not as real-world accuracy.",
        "",
        "| Tier | Phishing caught [95% CI] | Median score | Look-alike legitimate set | False positives [95% CI] | Median score |",
        "|---|---|---|---|---|---|",
    ]
    data: dict = {"seed": seed, "n_per_side": n_per_side, "digest": digest, "tiers": {}}
    for t in TIERS:
        p, legit = res[(t, 1)], res[(t, 0)]
        kp, kl = sum(r >= THR for r in p), sum(r >= THR for r in legit)
        out.append(
            f"| **{t}** {TIER_NAMES[t]} | {pct(kp, len(p))} | {statistics.median(p):.1f} | {CONTROL_NAMES[t]} | "
            f"{pct(kl, len(legit))} | {statistics.median(legit):.1f} |"
        )
        data["tiers"][t] = {"phish": [kp, len(p)], "legit": [kl, len(legit)]}
    out += [
        "",
        "Caught by number of planted red flags (NIST Phish Scale cues; personalization and thread continuation are "
        "premise alignment, not cues, and are not counted):",
        "",
        "| Planted red flags | n | Caught [95% CI] |",
        "|---|---|---|",
    ]
    for b in ["0-1", "2-3", "4-5", "6+"]:
        if b in by_cues:
            k, m = by_cues[b]
            out.append(f"| {b} | {m} | {pct(k, m)} |")
    neutral: dict[str, list[int]] = collections.defaultdict(lambda: [0, 0])
    for it in items:
        if it.label:
            r, _ = score(parse_eml(it.raw), NEUTRAL)
            neutral[it.tier][0] += r >= THR
            neutral[it.tier][1] += 1
    out += [
        "",
        "Same phishing scored **without** deployment configuration (no trusted vendors, no executive names), to show how "
        "much each tier depends on that configuration:",
        "",
        "| Tier | Caught with config | Caught without config [95% CI] |",
        "|---|---|---|",
    ]
    for t in TIERS:
        k, m = data["tiers"][t]["phish"]
        out.append(f"| {t} | {k / m:.0%} | {pct(*neutral[t])} |")
    data["without_config"] = dict(neutral)
    out += ["", "Per scenario:", "", "| Tier | Side | Scenario | n | Flagged |", "|---|---|---|---|---|"]
    for (t, label, sc), (k, m) in sorted(by_scenario.items()):
        out.append(f"| {t} | {'phishing' if label else 'legitimate'} | {sc} | {m} | {k / m:.0%} |")
    out += ["", "Most frequent signals:", ""]
    for t in TIERS:
        out.append(f"- **{t} phishing**: {top(feats[(t, 1)], 4, len(res[(t, 1)]), 4)}")
        out.append(f"- **{t} legitimate**: {top(feats[(t, 0)], 4, len(res[(t, 0)]), 4)}")
    data["by_cues"] = dict(by_cues)
    data["by_scenario"] = {f"{t}|{label}|{sc}": v for (t, label, sc), v in by_scenario.items()}
    return "\n".join(out), data


# ---------------------------------------------------------------------------- main
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--parts", default="nazario,pot,tiers")
    ap.add_argument("--out", default=str(ROOT / "docs" / "EVAL_BREAKDOWN.md"))
    ap.add_argument("--json", default=None)
    ap.add_argument("--tiers-n", type=int, default=100)
    ap.add_argument("--tiers-seed", type=int, default=2026)
    a = ap.parse_args(argv)
    parts = [p.strip() for p in a.parts.split(",") if p.strip()]
    import yaml

    weights_version = yaml.safe_load(pathlib.Path(WEIGHTS_PATH).read_text()).get("version", "?")
    head = [
        "# Detection by source, year and customization tier",
        "",
        f"Generated by `python -I scripts/eval_breakdown.py` on {dt.datetime.now(dt.UTC):%Y-%m-%d} at code `{git_state()}`, "
        f"weights v{weights_version}, threshold {THR:g}, rules only (no model calls). Aggregate numbers only: "
        "no message content is published. Rates show a 95% Wilson interval.",
    ]
    sections, data = [], {}
    runners = {
        "nazario": part_nazario,
        "pot": part_pot,
        "tiers": lambda: part_tiers(a.tiers_n, a.tiers_seed),
    }
    for p in parts:
        try:
            text, d = runners[p]()
        except ExternalDataMissing as e:
            text, d = f"## {p}\n\nNot run: {e}", {"missing": str(e)}
        sections.append(text)
        data[p] = d
        print(f"done: {p}", file=sys.stderr)
    pathlib.Path(a.out).write_text("\n\n".join(["\n".join(head), *sections]) + "\n")
    if a.json:
        pathlib.Path(a.json).write_text(json.dumps(data, indent=1, default=str))
    print(f"wrote {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
