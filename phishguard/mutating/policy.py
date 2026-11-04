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
    # mailbox remediation (connectors worker / scripts/mailbox_action.py)
    MAILBOX_QUARANTINE = "mailbox_quarantine"  # move out of the inbox; reversible
    MAILBOX_LABEL = "mailbox_label"  # add a label / category / IMAP keyword
    MAILBOX_BANNER = "mailbox_banner"  # add a warning banner (as an annotated copy)
    MAILBOX_DELETE = "mailbox_delete"  # always MFA: destroys evidence, hard to undo for users
    MAILBOX_RESTORE = "mailbox_restore"  # always MFA: releasing suspected phishing is what an attacker wants


ALWAYS_MFA = frozenset(
    {
        ActionType.TRANSFER_FUNDS,
        ActionType.PAY_INVOICE,
        ActionType.APPROVE_INVOICE,
        ActionType.CHANGE_BANK_DETAILS,
        ActionType.CHANGE_ACCOUNT_EMAIL,
        ActionType.RESET_PASSWORD,
        ActionType.CHANGE_ACCOUNT_SETTINGS,
        ActionType.MAILBOX_DELETE,
        ActionType.MAILBOX_RESTORE,
    }
)
MAILBOX_ACTIONS = frozenset(
    {
        ActionType.MAILBOX_QUARANTINE,
        ActionType.MAILBOX_LABEL,
        ActionType.MAILBOX_BANNER,
        ActionType.MAILBOX_DELETE,
        ActionType.MAILBOX_RESTORE,
    }
)
# One automatic action touches one message. More than this in one request is a bulk operation (e.g. "quarantine
# everything from this sender") whose blast radius justifies a human second factor.
MAILBOX_BULK_LIMIT = 10
_MAILBOX_ID = re.compile(r"[A-Za-z0-9_\-=:+/.]{1,512}")

_SENSITIVE_TEXT = re.compile(
    r"wire|transfer|invoice|payment|\bpay\b|remit|bank|iban|swift|routing|account number|gift card|bitcoin|crypto"
    r"|refund|salary|payroll|password|credential|转账|汇款|发票|付款|银行|账户|账号|密码|礼品卡|工资"
)
_SENSITIVE_KEYS = re.compile(r"amount|iban|swift|account|bank|invoice|payee|beneficiary|currency|password")
_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff\u00ad"))
_BIDI = dict.fromkeys(map(ord, "\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"))


class UnknownActionError(ValueError):
    pass


def parse_action_type(raw: str) -> ActionType:
    """Default-deny: anything not in the enum is rejected."""
    norm = unicodedata.normalize("NFKC", str(raw)).translate(_ZERO_WIDTH).translate(_BIDI).strip().lower()
    try:
        return ActionType(norm)
    except ValueError:
        raise UnknownActionError(f"unknown action type: {raw!r}") from None


MAX_PARAM_DEPTH = 6
MAX_PARAM_NODES = 2000


def normalize_user(raw: str) -> str:
    """One canonical identity per user, so 'Alice', ' alice' and fullwidth 'ａｌｉｃｅ' can't
    dodge that user's TOTP enrollment, lockout counter or audit trail."""
    s = unicodedata.normalize("NFKC", str(raw)).translate(_ZERO_WIDTH).translate(_BIDI).strip().casefold()
    return s.encode("utf-8", "replace").decode("utf-8")  # lone surrogates would crash sqlite3 binding


def _walk(obj: Any, depth: int = 0):
    if depth > MAX_PARAM_DEPTH:
        yield "overflow", ""  # too deep to inspect: caller must fail closed
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
    if action in MAILBOX_ACTIONS:
        ids = params.get("message_ids")
        if not isinstance(ids, list) or not ids or len(ids) > MAILBOX_BULK_LIMIT:
            return True  # bulk, or ids we can't count: fail closed
        if not all(isinstance(i, str) and _MAILBOX_ID.fullmatch(i) for i in ids):
            return True
        # provider ids are opaque base64-ish strings that can contain "bank" or "wire" by chance; they were
        # validated above, so only the remaining params go through the content scan
        params = {k: v for k, v in params.items() if k != "message_ids"}
    texts = [reason]
    for n, (kind, s) in enumerate(_walk(params)):
        if kind == "overflow" or n > MAX_PARAM_NODES:
            return True  # fail closed: whatever we could not inspect might move money
        if kind == "key" and _SENSITIVE_KEYS.search(unicodedata.normalize("NFKC", s).lower()):
            return True
        texts.append(s)
    for t in texts:
        clean = unicodedata.normalize("NFKC", t).translate(_ZERO_WIDTH).translate(_BIDI).lower()
        if _SENSITIVE_TEXT.search(clean):
            return True
    return False
