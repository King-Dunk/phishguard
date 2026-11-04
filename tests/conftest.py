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


# ---- multi-factor helpers -------------------------------------------------------------------
PASSWORD = "correct horse battery staple"
QUESTIONS = [
    {"question": "Name of your first pet?", "answer": "Rex"},
    {"question": "City where you were born?", "answer": "São Paulo"},
    {"question": "Your first school?", "answer": "Hillcrest Primary"},
]


class Creds:
    """Everything a legitimate approver holds: password, answers, TOTP secret, a passkey."""

    def __init__(self, user, totp=None, authenticator=None):
        self.user, self.totp, self.authenticator = user, totp, authenticator
        self.password = PASSWORD
        self.answers = {q["question"]: q["answer"] for q in QUESTIONS}


def make_gateway(clock, store=None, policy=None, mfa=None, payments=None, **kw):
    """A gateway wired like the API (all four factors, SimulatedBank), on a fake clock."""
    from phishguard.mfa_config import MFAConfig, PaymentsConfig
    from phishguard.mutating import AuditLog, CaptureChannel, Executor, MFAGateway, build_factors, build_policy
    from phishguard.mutating.payments import build_account_provider, build_payment_provider

    mfa = mfa or MFAConfig()
    payments = payments or PaymentsConfig()
    factors = build_factors(mfa, store, clock)
    ex = Executor(
        payments=build_payment_provider(payments, store, clock),
        accounts=build_account_provider(payments, store, clock),
        grants=factors.grants,
    )
    kw.setdefault("timeout_seconds", 600)
    kw.setdefault("max_attempts", 3)
    return MFAGateway(
        executor=ex,
        audit=AuditLog(clock=clock, store=store),
        channel=kw.pop("channel", None) or CaptureChannel(),
        clock=clock,
        totp=factors.totp,
        store=store,
        factors=factors,
        policy=policy or build_policy(mfa),
        **kw,
    )


def enroll(gw, user, methods=("password", "webauthn", "totp", "security_questions")) -> Creds:
    import pyotp

    from redteam.virtual_authenticator import VirtualAuthenticator

    f = gw.factors
    creds = Creds(user)
    if "password" in methods:
        f.password.enroll(user, PASSWORD)
    if "totp" in methods:
        creds.totp = pyotp.parse_uri(f.totp.enroll(user))
    if "security_questions" in methods:
        f.questions.enroll(user, QUESTIONS)
    if "webauthn" in methods:
        creds.authenticator = VirtualAuthenticator()
        f.webauthn.register(user, creds.authenticator.create(f.webauthn.registration_options(user)))
    return creds


def factor_response(gw, pid, digest, method, creds, clock=None):
    """Build a correct response for `method` (fetching a challenge first where needed)."""
    if method == "password":
        return {"password": creds.password}
    if method == "totp":
        return {"code": creds.totp.at(clock()) if clock else creds.totp.now()}
    if method == "security_questions":
        qs = gw.challenge(pid, method, digest)["questions"]
        return {"answers": {q["id"]: creds.answers[q["question"]] for q in qs}}
    if method == "webauthn":
        return {"credential": creds.authenticator.get(gw.challenge(pid, method, digest)["publicKey"])}
    raise ValueError(method)


def approve(gw, res, creds, methods=("password", "webauthn"), clock=None):
    """Pass each method in turn; returns the last FactorResult."""
    out = None
    for m in methods:
        resp = factor_response(gw, res.pending_id, res.digest, m, creds, clock)
        out = gw.verify_factor(res.pending_id, m, resp, res.digest)
    return out
