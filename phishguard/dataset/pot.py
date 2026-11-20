"""Load the Phishing Pot sample fetched by `scripts/download_datasets.py --only pot` (data/external/pot/).

Phishing Pot (https://github.com/rf-peixoto/phishing_pot, maintainer https://www.linkedin.com/in/rf-peixoto)
is a honeypot-collected set of real phishing mail with full headers, licensed CC BY-NC 4.0: non-commercial
research only, attribution required. Raw mail is never committed; only aggregate numbers are.

It is used purely as an out-of-source test set: nothing was tuned on it. Its maintainer notes that the
honeypot also receives spam, fraud and malware delivery, so "recall" on it means the share of malicious or
unsolicited honeypot mail that gets flagged, and the labels are as noisy as any honeypot's.
"""

from __future__ import annotations

import json
import pathlib

from ..readonly import EmlRejected, parse_eml
from .external import DEFAULT_DIR, ExternalDataMissing, ExternalSet
from .generator import LabeledEmail

CATEGORY = "pot_phish"


def load_pot(data_dir: str | pathlib.Path | None = None) -> tuple[ExternalSet, dict]:
    """(items, manifest). Sampled files that were too large to download, or that the parser refuses,
    are counted in `skipped`, never dropped silently."""
    root = pathlib.Path(data_dir or DEFAULT_DIR) / "pot"
    manifest_path = root / "manifest.json"
    if not manifest_path.is_file():
        raise ExternalDataMissing(f"{root} has no manifest.json; run: python scripts/download_datasets.py --only pot")
    manifest = json.loads(manifest_path.read_text())
    out = ExternalSet([])
    if manifest.get("too_large_not_downloaded"):
        out.skipped["EmlTooLarge"] = len(manifest["too_large_not_downloaded"])
    missing = 0
    for entry in manifest.get("sample", []):
        name = pathlib.PurePosixPath(entry["path"]).name
        if entry["path"] in manifest.get("too_large_not_downloaded", []):
            continue
        p = root / name
        if not p.is_file():
            missing += 1
            continue
        try:
            email = parse_eml(p.read_bytes())
        except (EmlRejected, ValueError) as e:
            out.skipped[type(e).__name__] = out.skipped.get(type(e).__name__, 0) + 1
            continue
        email = email.model_copy(update={"id": f"pot-{name}"})
        out.items.append(LabeledEmail(email, CATEGORY, 1, "phishing_pot"))
    if missing:
        out.skipped["not_downloaded"] = missing
    if not out.items:
        raise ExternalDataMissing(f"no Phishing Pot messages under {root} (cleaned? re-run --only pot)")
    return out, manifest
