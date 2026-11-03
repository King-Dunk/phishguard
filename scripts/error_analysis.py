import collections
import statistics as st

from phishguard.dataset.external import load_external
from phishguard.readonly import DetectionContext, analyze_email

ctx = DetectionContext(trusted_domains=(), executives=())
s = load_external()
grp = collections.defaultdict(list)  # (cat, outcome) -> list of (risk, feats)
for it in s.items:
    r, f = analyze_email(it.email, ctx)
    pred = r >= 50
    out = ("TP" if pred else "FN") if it.label else ("FP" if pred else "TN")
    grp[(it.category, out)].append((r, f, it.email))
names = sorted({x.name for v in grp.values() for _, f, _ in v for x in f})


def rate(rows, n):
    return sum(any(x.name == n for x in f) for _, f, _ in rows) / max(len(rows), 1)


def contrib(rows, n):
    c = [x.contribution for _, f, _ in rows for x in f if x.name == n]
    return st.mean(c) if c else 0


print("# PhishGuard real-corpus error analysis (aggregate only, no message content)\n")
print("Rules mode, threshold 50, ctx without trusted domains/executives.\n")
print("## Group sizes and score distribution\n\n| group | n | median score | p25 | p75 |\n|---|---|---|---|---|")
for k in sorted(grp):
    sc = sorted(r for r, _, _ in grp[k])
    q = lambda p: sc[int(p * (len(sc) - 1))]
    print(f"| {k[0]} {k[1]} | {len(sc)} | {q(0.5):.1f} | {q(0.25):.1f} | {q(0.75):.1f} |")
ham_fp = grp[("easy_ham", "FP")] + grp[("hard_ham", "FP")]
ham_tn = grp[("easy_ham", "TN")] + grp[("hard_ham", "TN")]
ph_tp, ph_fn = grp[("nazario_phish", "TP")], grp[("nazario_phish", "FN")]
ham = ham_fp + ham_tn
ph = ph_tp + ph_fn
print("\n## Feature fire rate (% of emails where feature fires) and mean contribution when fired\n")
print(
    "| feature | ham all | phish all | ham FP | phish FN | mean contrib in FP | mean contrib in TP |\n|---|---|---|---|---|---|---|"
)
for n in names:
    print(
        f"| {n} | {rate(ham, n):.1%} | {rate(ph, n):.1%} | {rate(ham_fp, n):.1%} | {rate(ph_fn, n):.1%} | {contrib(ham_fp, n):.1f} | {contrib(ph_tp, n):.1f} |"
    )


def traits(rows):
    n = max(len(rows), 1)
    e = [x for _, _, x in rows]
    g = lambda attr, fn: sum(fn(getattr(m, attr, None)) for m in e) / n
    return {
        "no features fired": sum(not f for _, f, _ in rows) / n,
        "has links": g("links", bool),
        "has attachments": g("attachments", bool),
        "reply_to set": g("reply_to", bool),
        "auth spf=none": sum(getattr(getattr(m, "auth", None), "spf", "none") == "none" for m in e) / n
        if hasattr(e[0] if e else None, "auth")
        else None,
    }


print("\n## Structural traits\n\n| trait | ham FP | ham TN | phish TP | phish FN |\n|---|---|---|---|---|")
T = [traits(x) for x in (ham_fp, ham_tn, ph_tp, ph_fn)]
for k in T[0]:
    print(f"| {k} | " + " | ".join("n/a" if t[k] is None else f"{t[k]:.1%}" for t in T) + " |")
print("\n## FP feature combinations (top 10)\n\n| features fired | count |\n|---|---|")
for combo, c in collections.Counter(tuple(sorted(x.name for x in f)) for _, f, _ in ham_fp).most_common(10):
    print(f"| {', '.join(combo) or '(none)'} | {c} |")
print("\nNote: SpamAssassin ham is 2002-era mail (mostly no DKIM/DMARC); Nazario phish spans 2004-2024.")
