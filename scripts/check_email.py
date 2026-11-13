"""Check one or more .eml files for phishing, in-process (no server needed).

Usage:
    .venv/bin/python scripts/check_email.py path/to/mail.eml [more.eml ...]
    .venv/bin/python scripts/check_email.py tests/fixtures/          # every .eml in a folder
    .venv/bin/python scripts/check_email.py mail.eml --json          # full JSON output

Uses the same settings as the API (PHISHGUARD_* environment variables):
PHISHGUARD_LLM_MODE=mock (default, offline) or anthropic, PHISHGUARD_THRESHOLD,
PHISHGUARD_TRUSTED_DOMAINS, PHISHGUARD_EXECUTIVES, PHISHGUARD_AUTHSERV_ID.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from phishguard.agent import PhishingAgent  # noqa: E402
from phishguard.api import _build_llm, _result  # noqa: E402
from phishguard.config import Settings  # noqa: E402
from phishguard.readonly.eml import EmlRejected, parse_eml  # noqa: E402


def collect(paths: list[str]) -> list[pathlib.Path]:
    out: list[pathlib.Path] = []
    for p in map(pathlib.Path, paths):
        if p.is_dir():
            out.extend(sorted(p.glob("*.eml")))
        elif p.is_file():
            out.append(p)
        else:
            print(f"!! not found: {p}", file=sys.stderr)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+", help=".eml files or folders containing them")
    ap.add_argument("--json", action="store_true", help="print the full API-style JSON result")
    args = ap.parse_args()

    settings = Settings.from_env()
    agent = PhishingAgent(_build_llm(settings), settings)
    files = collect(args.paths)
    if not files:
        return 2

    flagged = 0
    for path in files:
        try:
            email = parse_eml(path.read_bytes(), settings.trusted_authserv_id)
        except EmlRejected as e:
            print(f"\n== {path.name}\n   rejected: {e}")
            continue
        res = _result(email.id, agent.analyze(email), settings.phishing_threshold)
        flagged += res["is_phishing"]
        if args.json:
            print(json.dumps({"file": str(path), **res}, ensure_ascii=False, indent=2, default=str))
            continue
        verdict = "PHISHING 钓鱼" if res["is_phishing"] else "looks OK 正常"
        print(f"\n== {path.name}")
        print(f"   From:    {email.sender_name} <{email.sender_email}>")
        print(f"   Subject: {email.subject}")
        print(f"   Risk:    {res['risk_percent']}%  (threshold {res['threshold']})  ->  {verdict}")
        for line in res["explanation"][:8]:
            print(f"     + {line}")
        if not res["explanation"]:
            print("     (no risk signals)")

    print(f"\n{flagged}/{len(files)} flagged as phishing (mode: {settings.llm_mode})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
