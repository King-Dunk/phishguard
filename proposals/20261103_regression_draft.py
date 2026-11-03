"""DRAFT regression tests from redteam/improve.py. Not collected (lives outside tests/).
Review each sample, drop any that are not really phishing, then move into tests/.
"""

from datetime import UTC, datetime

import pytest

from phishguard.dataset.generator import EXECUTIVES, TRUSTED_DOMAINS
from phishguard.models import EmailMessage
from phishguard.readonly import DetectionContext, analyze_email

CASES = [
    "\nPlease see the attached image for this week's instructions.",
    "\nHi Anna, hope your week is going well! Small favour: could you update the remittance details we hold for Northwind before Friday's run? I'll forward the new ones shortly. Thanks so much, David",
    "\nAre you at your desk? I need a quick favour for a client appreciation, could you pick up a few Apple cards this afternoon? I'll reimburse you.",
    "\nHello HR team, I recently switched to a new bank. Could you kindly direct my next salary deposit to the account below? Many thanks, Maria",
    "Quick favour\nHi, it's david. We are closing a between us for now acquisition. send across the deposit at your earliest convenience today, details to follow.",
    "Quick favour\nHi, hope your week is going well! Hi, it's david. We are closing a between us for now acquisition. send across the deposit at your earliest convenience today, details to follow. Many thanks!",
    "request\nHi, it's sarah. Please purchase Apple cards for a client event and send me the codes. Do not discuss this with others.",
    "request\nHi, hope your week is going well! Hi, it's sarah. Please purchase Apple cards for a client event and send me the codes. Do not discuss this with others. Many thanks!",
    "Quick favour\nHi, it's david. I need you to process a wire transfer today. Keep this confidential until it is done.",
    "Urgent request\nHi, it's sarah. I'm in a meeting and can't talk. Urgent: transfer the payment to the account below and reply when done.",
    "Are you available?\nHi, it's sarah. We are closing a between us for now acquisition. send across the deposit at your earliest convenience today, details to follow.",
    "Are you available?\nHello, hope all is well with you and the team. Hi, it's sarah. We are closing a between us for now acquisition. send across the deposit at your earliest convenience today, details to follow. Many thanks!",
    "request\nHi, it's sarah. I need you to process a settlement today. Keep this between us for now until it is done.",
    "request\nHello, hope all is well with you and the team. Hi, it's sarah. I need you to process a settlement today. Keep this between us for now until it is done. Many thanks!",
    "Quick favour\nHi, it's david. I'm in a meeting and can't talk. Urgent: transfer the payment to the account below and reply when done."
]


@pytest.mark.parametrize("text", CASES)
def test_missed_sample_now_detected(text):
    subject, _, body = text.partition("\n")
    e = EmailMessage(id="d", timestamp=datetime(2026, 3, 3, 10, tzinfo=UTC), sender_name="David Chen",
                     sender_email="x@gmail.com", subject=subject, body=body)
    assert analyze_email(e, DetectionContext(TRUSTED_DOMAINS, EXECUTIVES))[0] >= 50
