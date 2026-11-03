"""Adversarial self-improvement with a human in the loop.

    python -m redteam.improve                       # template mutations, no network
    python -m redteam.improve --use-llm --price-in <USD/MTok> --price-out <USD/MTok>   # needs ANTHROPIC_API_KEY

1. collect misses: red-team evasion payloads that scored < 50, synthetic phishing the rules miss,
   external corpus misses (--external), and mutated variants of detected phishing that slip under 50
2. analyze: phrases common to misses and absent from legitimate mail; structural gaps
3. write proposals/YYYYMMDD.md, an optional .patch (only for files outside the protected list) and a
   regression-test draft. Nothing is applied, merged or imported: a human reviews, edits and commits.

The protected list (PROTECTED) covers the MFA gateway and everything that decides whether money
moves. A generated patch that touches it is refused before it is written (check_patch).
"""

from __future__ import annotations

import argparse
import datetime as dt
import difflib
import json
import os
import pathlib
import posixpath
import random
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from phishguard.dataset.generator import EXECUTIVES, TRUSTED_DOMAINS, generate_dataset
from phishguard.models import EmailMessage
from phishguard.readonly import DetectionContext, analyze_email
from phishguard.readonly.features import clean_text

REPO = pathlib.Path(__file__).resolve().parent.parent
THRESHOLD = 50.0
MAX_BUDGET_USD = 2.0  # hard ceiling; --budget can only lower it

# Paths a machine-generated patch may never touch. Directory entries end with "/".
PROTECTED = (
    "phishguard/mutating/",  # MFA gateway, policy, executor, TOTP, audit, store
    "phishguard/api.py",  # exposes /actions and /mfa/*
    "phishguard/security.py",  # API auth and rate limiting
    "phishguard/config.py",  # MFA timeouts, lockout thresholds, keys
    "redteam/improve.py",  # this guard itself
    "redteam/runner.py",  # the oracles that judge fixes
    "tests/",  # existing tests are the contract; drafts go to proposals/
    ".github/",
)


class ProtectedPathError(PermissionError):
    pass


class BudgetExceeded(RuntimeError):
    pass


# ----------------------------------------------------------------------------- patch guard
_HEADER = re.compile(r"^(?:--- |\+\+\+ |rename from |rename to |copy from |copy to )(.+)$")
_GIT = re.compile(r"^diff --git (\S+) (\S+)")
_BINARY = re.compile(r"^Binary files (.+) and (.+) differ")


def _norm_path(raw: str) -> str | None:
    p = raw.split("\t", 1)[0].strip().strip('"')
    if p == "/dev/null":
        return None
    if re.match(r"^[ab]/", p):
        p = p[2:]
    p = p.replace("\\", "/")
    if p.startswith("/") or re.match(r"^[A-Za-z]:", p):
        raise ProtectedPathError(f"absolute path in patch: {raw!r}")
    norm = posixpath.normpath(p)
    if norm == ".." or norm.startswith("../"):
        raise ProtectedPathError(f"path escapes the repository: {raw!r}")
    return norm


def touched_paths(patch: str) -> set[str]:
    paths: set[str] = set()
    for line in patch.splitlines():
        for rx in (_GIT, _BINARY, _HEADER):
            m = rx.match(line)
            if m:
                for g in m.groups():
                    n = _norm_path(g)
                    if n:
                        paths.add(n)
                break
    return paths


def check_patch(patch: str) -> set[str]:
    """Return the files a patch touches, or raise ProtectedPathError. Case-insensitive on purpose
    (macOS/Windows file systems would map PhishGuard/Mutating to the same directory)."""
    paths = touched_paths(patch)
    if not paths:
        raise ProtectedPathError("patch names no files; refusing what cannot be checked")
    for p in paths:
        low = p.lower()
        for prot in PROTECTED:
            if low == prot.lower().rstrip("/") or (prot.endswith("/") and low.startswith(prot.lower())):
                raise ProtectedPathError(f"patch touches protected path {p} (rule {prot})")
    return paths


def write_patch(patch: str, out: pathlib.Path) -> pathlib.Path:
    check_patch(patch)  # refuse BEFORE anything reaches disk
    out.write_text(patch, encoding="utf-8")
    return out


# ----------------------------------------------------------------------------- LLM budget
@dataclass
class BudgetGuard:
    """Hard spending cap. Each call is checked against its worst case (estimated input tokens +
    the full max_tokens output) before it is sent, so the cap holds even if every call maxes out."""

    price_in: float  # USD per million input tokens
    price_out: float
    cap_usd: float = MAX_BUDGET_USD
    spent_usd: float = 0.0
    calls: int = 0

    def __post_init__(self) -> None:
        self.cap_usd = min(self.cap_usd, MAX_BUDGET_USD)

    def reserve(self, est_input_tokens: int, max_tokens: int) -> None:
        worst = (est_input_tokens * self.price_in + max_tokens * self.price_out) / 1e6
        if self.spent_usd + worst > self.cap_usd:
            raise BudgetExceeded(f"next call could cost ${worst:.4f}; spent ${self.spent_usd:.4f} of ${self.cap_usd}")

    def charge(self, input_tokens: int, output_tokens: int) -> None:
        self.spent_usd += (input_tokens * self.price_in + output_tokens * self.price_out) / 1e6
        self.calls += 1


def llm_call(llm, guard: BudgetGuard, prompt: str, max_tokens: int = 800) -> str:
    system = "You help harden a phishing detector. Output only what is asked."
    # Upper bound, not an estimate: a token is at least one UTF-8 byte, plus a fixed message overhead.
    est = len(prompt.encode()) + len(system.encode()) + 64
    guard.reserve(est, max_tokens)
    resp = llm.complete(
        system=system,
        messages=[{"role": "user", "content": prompt}],
        tools=[],
        max_tokens=max_tokens,
    )
    guard.charge(max(resp.input_tokens, est), max(resp.output_tokens, 0))
    if resp.input_tokens > est or resp.output_tokens > max_tokens:
        raise BudgetExceeded("provider billed more than the reserved upper bound; stopping")
    return resp.text


# ----------------------------------------------------------------------------- mutations
_SYNONYMS = [
    (r"\bwire transfer\b", "settlement"),
    (r"\bwire\b", "send across"),
    (r"\btransfer\b", "move"),
    (r"\burgent(ly)?\b", "time-sensitive"),
    (r"\bimmediately\b", "at your earliest convenience today"),
    (r"\bbank (account|details)\b", "remittance details"),
    (r"\binvoice\b", "statement"),
    (r"\bpayment\b", "settlement"),
    (r"\bgift cards?\b", "Apple cards"),
    (r"\bconfidential\b", "between us for now"),
]
_POLITE = [
    "Hi, hope your week is going well! ",
    "Good morning, quick one when you have a sec. ",
    "Hello, hope all is well with you and the team. ",
]


def mutate(text: str, rng: random.Random) -> list[tuple[str, str]]:
    out = []
    t = text
    for pat, rep in _SYNONYMS:
        t = re.sub(pat, rep, t, flags=re.I)
    out.append(("synonyms", t))
    out.append(("polite_wrap", rng.choice(_POLITE) + t + " Many thanks!"))
    return out


# ----------------------------------------------------------------------------- collection
@dataclass
class Miss:
    source: str
    text: str
    risk: float
    features: list[str]
    email: dict[str, Any] = field(default_factory=dict)


def _ctx() -> DetectionContext:
    return DetectionContext(trusted_domains=TRUSTED_DOMAINS, executives=EXECUTIVES)


def _miss(source: str, email: EmailMessage, ctx: DetectionContext) -> Miss | None:
    risk, feats = analyze_email(email, ctx)
    if risk >= THRESHOLD:
        return None
    return Miss(source, f"{email.subject}\n{email.body}", risk, [f.name for f in feats], email.model_dump(mode="json"))


def collect_misses(seed: int = 42, n: int = 60, external: bool = False) -> tuple[list[Miss], list[str]]:
    from .runner import load_payloads, run

    ctx = _ctx()
    misses: list[Miss] = []
    # 1. red-team evasion payloads that fell short of their detection threshold
    for r in run(payloads=[a for a in load_payloads() if a["category"] == "evasion"]):
        if r["detection_ok"] is False:
            spec = r["attack"]["eml"]
            misses.append(
                Miss(f"redteam:{r['id']}", f"{spec.get('subject', '')}\n{spec.get('text', '')}", r["risk"] or 0, [])
            )
    # 2. synthetic phishing the rules miss, 3. mutated variants of detected phishing
    data = generate_dataset(n, seed)
    rng = random.Random(seed)
    for it in data:
        if not it.label:
            continue
        m = _miss(f"synthetic:{it.category}", it.email, ctx)
        if m:
            misses.append(m)
            continue
        for kind, body in mutate(it.email.body, rng):
            v = it.email.model_copy(
                update={"body": body[:20000], "subject": re.sub(r"(?i)urgent:?\s*", "", it.email.subject)}
            )
            m = _miss(f"mutation:{kind}:{it.category}", v, ctx)
            if m:
                misses.append(m)
    # 4. optional: public corpus
    if external:
        from phishguard.dataset.external import load_external

        ext_ctx = DetectionContext(trusted_domains=(), executives=())
        for it in load_external(limit_per_class=500, seed=seed).items:
            if it.label and (m := _miss("external:nazario", it.email, ext_ctx)):
                misses.append(m)
    ham = [clean_text(f"{x.email.subject}\n{x.email.body}") for x in data if not x.label]
    ham += [clean_text(p.read_text(errors="replace")) for p in (REPO / "tests" / "fixtures").glob("benign_*.eml")]
    return misses, ham


# ----------------------------------------------------------------------------- analysis
_WORD = re.compile(r"[a-z][a-z'-]+")
_STOP = set(
    "the a an to of and or for on in at is are be you your we our i me my it this that with as by from have has".split()
)


def _ngrams(text: str) -> set[str]:
    words = [w for w in _WORD.findall(clean_text(text))]
    grams = set()
    for n in (2, 3):  # single words ("today", "quick") are far too generic to be a rule
        for i in range(len(words) - n + 1):
            g = words[i : i + n]
            if g[0] in _STOP or g[-1] in _STOP:
                continue
            grams.add(" ".join(g))
    return grams


def analyze(misses: list[Miss], ham: list[str], top: int = 12) -> dict[str, Any]:
    miss_df = Counter(g for m in misses for g in _ngrams(m.text))
    ham_grams = [_ngrams(h) for h in ham]
    ham_df = Counter(g for gs in ham_grams for g in gs)
    cands = [(g, c) for g, c in miss_df.items() if c >= 2 and ham_df[g] == 0]
    cands.sort(key=lambda x: (-x[1], -len(x[0])))
    picked: list[str] = []
    for g, _ in cands:
        if not any(g in p or p in g for p in picked):
            picked.append(g)
        if len(picked) >= top:
            break
    feature_gaps = Counter(tuple(sorted(m.features)) or ("<none>",) for m in misses).most_common(5)
    sources = Counter(m.source.split(":")[0] for m in misses)
    image_only = [m for m in misses if len(_WORD.findall(m.text.lower())) < 15]
    return {
        "phrases": picked,
        "phrase_df": {g: miss_df[g] for g in picked},
        "feature_gaps": feature_gaps,
        "sources": dict(sources),
        "short_text": len(image_only),
    }


def simulate(misses: list[Miss], ham: list[str], phrases: list[str], weight: float = 0.25) -> dict[str, Any]:
    """What would a new feature (any of `phrases`, weight w) do? Pure arithmetic on noisy-OR."""
    if not phrases:
        return {"rescued": 0, "misses": len(misses), "ham_matched": 0, "pattern": None}
    pat = re.compile(r"\b(" + "|".join(re.escape(p).replace("\\ ", r"\s+") for p in phrases) + r")\b")
    rescued = sum(
        1
        for m in misses
        if pat.search(clean_text(m.text)) and 100 * (1 - (1 - m.risk / 100) * (1 - weight)) >= THRESHOLD
    )
    ham_hit = sum(1 for h in ham if pat.search(h))
    return {"rescued": rescued, "misses": len(misses), "ham_matched": ham_hit, "pattern": pat.pattern, "weight": weight}


# ----------------------------------------------------------------------------- outputs
FEATURES = "phishguard/readonly/features.py"


def build_patch(pattern: str, weight: float, base: pathlib.Path = REPO) -> str:
    src = (base / FEATURES).read_text(encoding="utf-8")
    new = src.replace(
        '    "obfuscated_text": 0.25,\n', f'    "obfuscated_text": 0.25,\n    "soft_bec_phrasing": {weight},\n', 1
    )
    new = new.replace(
        "RISKY_EXT = (\n",
        f"# PROPOSED by redteam/improve.py -- review before merging\nSOFT_BEC = re.compile({pattern!r})\nRISKY_EXT = (\n",
        1,
    )
    new = new.replace(
        '        ("prompt_injection_attempt", INJECTION),\n',
        '        ("prompt_injection_attempt", INJECTION),\n        ("soft_bec_phrasing", SOFT_BEC),\n',
        1,
    )
    if new == src:
        return ""
    diff = difflib.unified_diff(
        src.splitlines(keepends=True), new.splitlines(keepends=True), fromfile=f"a/{FEATURES}", tofile=f"b/{FEATURES}"
    )
    return "".join(diff)


def regression_draft(misses: list[Miss]) -> str:
    cases = [m.text[:400] for m in misses if m.text.strip()][:15]
    return (
        '"""DRAFT regression tests from redteam/improve.py. Not collected (lives outside tests/).\n'
        "Review each sample, drop any that are not really phishing, then move into tests/.\n"
        '"""\n\nfrom datetime import UTC, datetime\n\nimport pytest\n\n'
        "from phishguard.dataset.generator import EXECUTIVES, TRUSTED_DOMAINS\n"
        "from phishguard.models import EmailMessage\n"
        "from phishguard.readonly import DetectionContext, analyze_email\n\n"
        f"CASES = {json.dumps(cases, indent=4, ensure_ascii=False)}\n\n\n"
        '@pytest.mark.parametrize("text", CASES)\n'
        "def test_missed_sample_now_detected(text):\n"
        '    subject, _, body = text.partition("\\n")\n'
        '    e = EmailMessage(id="d", timestamp=datetime(2026, 3, 3, 10, tzinfo=UTC), sender_name="David Chen",\n'
        '                     sender_email="x@gmail.com", subject=subject, body=body)\n'
        "    assert analyze_email(e, DetectionContext(TRUSTED_DOMAINS, EXECUTIVES))[0] >= 50\n"
    )


def render(date: str, analysis: dict, sim: dict, misses: list[Miss], patch_status: str, llm_notes: str) -> str:
    lines = [
        f"# Detection improvement proposal {date}",
        "",
        "> Generated by `redteam/improve.py`. **Nothing here has been applied.** A human must review the",
        "> evidence, edit the rule, run `pytest` and `python -m redteam.runner`, and commit by hand.",
        "",
        "## Misses collected",
        "",
        f"{len(misses)} phishing samples scored below {THRESHOLD:.0f}. By source: {analysis['sources']}.",
        "",
        "| Source | Risk | Features that fired | Text (truncated) |",
        "|---|---|---|---|",
    ]
    for m in misses[:25]:
        txt = " ".join(m.text.split())[:110].replace("|", "/")
        lines.append(f"| {m.source} | {m.risk:.0f} | {', '.join(m.features) or '-'} | {txt} |")
    lines += ["", "## What the misses have in common", ""]
    lines.append("Phrases seen in >= 2 misses and in **no** legitimate sample (doc frequency in misses):")
    lines += [f"- `{p}` ({analysis['phrase_df'][p]})" for p in analysis["phrases"]] or ["- none found"]
    lines += ["", "Feature combinations on missed mail (most common):"]
    lines += [f"- {', '.join(k)}: {v}" for k, v in analysis["feature_gaps"]]
    lines += [f"- {analysis['short_text']} misses carry under 15 words of text (image-only or link-only lures)."]
    lines += [
        "",
        "## Proposal 1: `soft_bec_phrasing` feature",
        "",
        f"Regex over the phrases above, weight {sim.get('weight', 0.25)}. Simulated on the collected data:",
        f"rescues **{sim['rescued']}/{sim['misses']}** misses; matches **{sim['ham_matched']}** legitimate samples.",
        "",
        "Review checklist: drop phrases that are artifacts of the data (personal names, template greetings",
        "of the synthetic generator); ask whether real business mail contains them. The",
        "legitimate set here is small and synthetic, so `ham_matched = 0` is weak evidence. Prefer fewer,",
        "longer phrases. Run the external corpus (`--external`) before merging.",
        "",
        f"Patch: {patch_status}",
        "",
        "## Proposal 2: structural signal for low-text lures",
        "",
        "Mail with an image attachment and almost no text should add a small weight (0.15-0.2), combined",
        "with an external or free-mail sender. Not auto-drafted: needs a human to pick thresholds.",
    ]
    if llm_notes:
        lines += ["", "## LLM suggestions (unreviewed, budget-capped)", "", llm_notes]
    lines += ["", "## Protected paths (patches touching these are refused)", ""]
    lines += [f"- `{p}`" for p in PROTECTED]
    return "\n".join(lines) + "\n"


def run_improve(
    out_dir: pathlib.Path,
    date: str | None = None,
    use_llm: bool = False,
    price_in: float | None = None,
    price_out: float | None = None,
    budget: float = MAX_BUDGET_USD,
    external: bool = False,
    llm=None,
) -> dict[str, Any]:
    out_dir = out_dir.resolve()
    for forbidden in ("phishguard", "tests", "redteam"):
        if out_dir == REPO / forbidden or (REPO / forbidden) in out_dir.parents:
            raise ProtectedPathError(f"refusing to write proposals inside {forbidden}/")
    date = date or dt.date.today().strftime("%Y%m%d")
    misses, ham = collect_misses(external=external)
    analysis = analyze(misses, ham)
    sim = simulate(misses, ham, analysis["phrases"])
    out_dir.mkdir(parents=True, exist_ok=True)

    patch_status = "none (no candidate phrases)"
    if sim["pattern"]:
        patch = build_patch(sim["pattern"], sim["weight"])
        try:
            p = write_patch(patch, out_dir / f"{date}.patch")
            patch_status = f"`{p.name}` (touches only {', '.join(sorted(check_patch(patch)))}; apply with `git apply` after review)"
        except ProtectedPathError as e:
            patch_status = f"REFUSED: {e}"

    llm_notes = ""
    guard = None
    if use_llm:
        if price_in is None or price_out is None:
            llm_notes = "_LLM step skipped: --price-in/--price-out are required to enforce the budget cap._"
        elif llm is None and not os.environ.get("ANTHROPIC_API_KEY"):
            llm_notes = "_LLM step skipped: ANTHROPIC_API_KEY not set._"
        else:
            if llm is None:
                from phishguard.config import Settings
                from phishguard.llm.anthropic_client import AnthropicLLM

                llm = AnthropicLLM(Settings.from_env())
            guard = BudgetGuard(price_in, price_out, cap_usd=budget)
            notes = []
            samples = "\n---\n".join(m.text[:300] for m in misses[:8])
            try:
                notes.append(
                    llm_call(
                        llm,
                        guard,
                        "Suggest up to 5 short, specific phrases or signals that would "
                        f"catch these missed phishing emails without flagging normal business mail:\n{samples}",
                    )
                )
                for m in misses[:20]:
                    notes.append(
                        "Variant: "
                        + llm_call(llm, guard, f"Rewrite as a harder-to-detect variant:\n{m.text[:400]}", 300)
                    )
            except BudgetExceeded as e:
                notes.append(f"_Stopped: {e}_")
            llm_notes = (
                "\n\n".join(notes) + f"\n\n_Spent ${guard.spent_usd:.4f} of ${guard.cap_usd} over {guard.calls} calls._"
            )

    (out_dir / f"{date}.md").write_text(render(date, analysis, sim, misses, patch_status, llm_notes), encoding="utf-8")
    (out_dir / f"{date}_regression_draft.py").write_text(regression_draft(misses), encoding="utf-8")
    return {
        "misses": len(misses),
        "analysis": analysis,
        "simulation": sim,
        "patch": patch_status,
        "spent_usd": guard.spent_usd if guard else 0.0,
    }


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(REPO / "proposals"))
    ap.add_argument("--date", default=None, help="YYYYMMDD (default today)")
    ap.add_argument("--use-llm", action="store_true")
    ap.add_argument("--price-in", type=float, default=None, help="USD per million input tokens")
    ap.add_argument("--price-out", type=float, default=None, help="USD per million output tokens")
    ap.add_argument("--budget", type=float, default=MAX_BUDGET_USD, help=f"USD, capped at {MAX_BUDGET_USD}")
    ap.add_argument("--external", action="store_true", help="also mine misses from data/external")
    a = ap.parse_args(argv)
    r = run_improve(pathlib.Path(a.out), a.date, a.use_llm, a.price_in, a.price_out, a.budget, a.external)
    print(f"{r['misses']} misses; rescued by proposal: {r['simulation']['rescued']}; patch: {r['patch']}")


if __name__ == "__main__":
    main()
