"""Which actions are sensitive. Decided in code, never by the LLM or by request fields."""
from __future__ import annotations

import re
import unicodedata
from enum import Enum
from typing import Any


class ActionType(str, Enum):
    # low risk
    QUARANTINE_EMAIL = "quarantine_email"
    MARK_SPAM = "mark_spam"
    REPORT_PHISHING = "report_phishing"
    BLOCK_SENDER = "block_sender"
    SEND_REPLY = "send_reply"  # escalated to MFA if content touches money/accounts
    # always MFA (funds / account change / invoice)
    TRANSFER_FUNDS = "transfer_funds"
    PAY_INVOICE = "pay_invoice"
    APPROVE_INVOICE = "approve_invoice"
    CHANGE_BANK_DETAILS = "change_bank_details"
    CHANGE_ACCOUNT_EMAIL = "change_account_email"
    RESET_PASSWORD = "reset_password"
    CHANGE_ACCOUNT_SETTINGS = "change_account_settings"


ALWAYS_MFA = frozenset(
    {
        ActionType.TRANSFER_FUNDS,
        ActionType.PAY_INVOICE,
        ActionType.APPROVE_INVOICE,
        ActionType.CHANGE_BANK_DETAILS,
        ActionType.CHANGE_ACCOUNT_EMAIL,
        ActionType.RESET_PASSWORD,
        ActionType.CHANGE_ACCOUNT_SETTINGS,
    }
)

_SENSITIVE_TEXT = re.compile(
    r"wire|transfer|invoice|payment|\bpay\b|remit|bank|iban|swift|routing|account number|gift card|bitcoin|crypto"
    r"|refund|salary|payroll|password|credential|转账|汇款|发票|付款|银行|账户|账号|密码|礼品卡|工资"
)
_SENSITIVE_KEYS = re.compile(r"amount|iban|swift|account|bank|invoice|payee|beneficiary|currency|password")
_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿"))


class UnknownActionError(ValueError):
    pass


def parse_action_type(raw: str) -> ActionType:
    """Default-deny: anything not in the enum is rejected."""
    norm = unicodedata.normalize("NFKC", str(raw)).translate(_ZERO_WIDTH).strip().lower()
    try:
        return ActionType(norm)
    except ValueError:
        raise UnknownActionError(f"unknown action type: {raw!r}") from None


def _walk(obj: Any, depth: int = 0):
    if depth > 6:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield "key", str(k)
            yield from _walk(v, depth + 1)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _walk(v, depth + 1)
    elif obj is not None:
        yield "val", str(obj)


def requires_mfa(action: ActionType, params: dict[str, Any], reason: str = "") -> bool:
    if action in ALWAYS_MFA:
        return True
    texts = [reason]
    for kind, s in _walk(params):
        if kind == "key" and _SENSITIVE_KEYS.search(unicodedata.normalize("NFKC", s).lower()):
            return True
        texts.append(s)
    for t in texts:
        clean = unicodedata.normalize("NFKC", t).translate(_ZERO_WIDTH).lower()
        if _SENSITIVE_TEXT.search(clean):
            return True
    return False
