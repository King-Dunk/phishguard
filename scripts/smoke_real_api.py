"""Smoke test against the REAL Anthropic API (not part of pytest).

    ANTHROPIC_API_KEY=... python scripts/smoke_real_api.py [--price-in 1.0 --price-out 5.0]

Prices are USD per million tokens and must be supplied by you (check current
pricing); without them only token counts are printed. Exits 0 if no key is set.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from datetime import UTC, datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from phishguard.agent import PhishingAgent  # noqa: E402
from phishguard.config import Settings  # noqa: E402
from phishguard.dataset.generator import EXECUTIVES, TRUSTED_DOMAINS  # noqa: E402
from phishguard.llm.anthropic_client import AnthropicLLM  # noqa: E402
from phishguard.models import EmailMessage  # noqa: E402
from phishguard.readonly import DetectionContext  # noqa: E402

T = datetime(2026, 3, 3, 10, 0, tzinfo=UTC)
SAMPLES = [
    (
        "benign: sync notes",
        0,
        dict(
            sender_name="Anna K",
            sender_email="anna.k@acme-corp.com",
            subject="Notes from Monday sync",
            body="Notes attached. Next sync Thursday 10:00.",
            sender_reputation=0.95,
            spf="pass",
            dkim="pass",
            dmarc="pass",
        ),
    ),
    (
        "benign: vendor reminder",
        0,
        dict(
            sender_name="Globalsupply Billing",
            sender_email="billing@globalsupply.com",
            subject="Payment reminder INV-2041",
            body="Invoice INV-2041 for $1200 is due. Remittance details unchanged.",
            sender_reputation=0.9,
            sender_domain_age_days=3000,
            spf="pass",
            dkim="pass",
            dmarc="pass",
        ),
    ),
    (
        "BEC: lookalike CEO",
        1,
        dict(
            sender_name="David Chen",
            sender_email="david@acme-c0rp.com",
            reply_to="d.chen@gmail.com",
            subject="Urgent request",
            body="Wire transfer today. Keep this confidential.",
            sender_reputation=0.1,
            sender_domain_age_days=5,
            spf="fail",
            dkim="fail",
            dmarc="fail",
        ),
    ),
    (
        "BEC: gift cards",
        1,
        dict(
            sender_name="Sarah Miller",
            sender_email="sarah.miller@gmail.com",
            subject="Are you available?",
            body="Buy gift cards for a client and send me the codes. Do not discuss this.",
            sender_reputation=0.2,
        ),
    ),
    (
        "payment chasing: bank change",
        1,
        dict(
            sender_name="Northwind Billing",
            sender_email="billing@northwlnd-parts.com",
            subject="OVERDUE INV-7781",
            body="Our bank details have changed. Pay the new account number immediately.",
            sender_reputation=0.15,
            sender_domain_age_days=12,
            spf="fail",
        ),
    ),
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--price-in", type=float, default=None, help="USD per 1M input tokens")
    ap.add_argument("--price-out", type=float, default=None, help="USD per 1M output tokens")
    a = ap.parse_args()
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("ANTHROPIC_API_KEY is not set; skipping real-API smoke test.")
        return 0
    settings = Settings.from_env()
    agent = PhishingAgent(AnthropicLLM(settings), settings, DetectionContext(TRUSTED_DOMAINS, EXECUTIVES))
    total_tokens, total_s = 0, 0.0
    print(f"model={settings.model}")
    for i, (name, label, kw) in enumerate(SAMPLES):
        email = EmailMessage(id=f"smoke-{i}", timestamp=T, **kw)
        t0 = time.perf_counter()
        r = agent.analyze(email)
        dt = time.perf_counter() - t0
        total_tokens += r.tokens_used
        total_s += dt
        print(
            f"{name:32s} expected={'phish' if label else 'ok  '} risk={r.risk_percent:5.1f}% "
            f"steps={r.steps_used} tokens={r.tokens_used} time={dt:.1f}s break={r.circuit_break}"
        )
    print(f"total tokens={total_tokens} total time={total_s:.1f}s")
    if a.price_in is not None and a.price_out is not None:
        # AnalysisResult only tracks the combined total; price it at the (higher) output rate as an upper bound.
        print(f"estimated cost <= ${total_tokens * max(a.price_in, a.price_out) / 1e6:.4f} (upper bound)")
    else:
        print("pass --price-in/--price-out (USD per 1M tokens) for a cost estimate")
    return 0


if __name__ == "__main__":
    sys.exit(main())
