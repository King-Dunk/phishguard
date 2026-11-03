from datetime import UTC, datetime

import pytest

from phishguard.config import Settings
from phishguard.models import EmailMessage


class FakeClock:
    def __init__(self, t: float = 1_000_000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, s: float) -> None:
        self.t += s


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def settings():
    return Settings(llm_mode="mock", executives=("David Chen",), mfa_timeout_seconds=60)


def make_email(**kw) -> EmailMessage:
    base = dict(
        id="e1",
        timestamp=datetime(2026, 3, 3, 10, 0, tzinfo=UTC),
        sender_name="Anna K",
        sender_email="anna.k@acme-corp.com",
        subject="Sync notes",
        body="Notes attached.",
        sender_reputation=0.95,
        spf="pass",
        dkim="pass",
        dmarc="pass",
    )
    base.update(kw)
    return EmailMessage(**base)


@pytest.fixture
def benign():
    return make_email()


@pytest.fixture
def phish():
    return make_email(
        id="p1",
        sender_name="David Chen",
        sender_email="david@acme-c0rp.com",
        reply_to="d@gmail.com",
        subject="Urgent request",
        body="Wire transfer today, keep this confidential.",
        sender_reputation=0.1,
        sender_domain_age_days=5,
        spf="fail",
        dkim="fail",
        dmarc="fail",
    )
