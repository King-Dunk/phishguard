"""Which actions are sensitive. Decided in code, never by the LLM or by request fields."""

from __future__ import annotations

import hmac
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
    # mailbox remediation (reversible; MFA only in bulk, see MAX_UNATTENDED_BATCH)
    APPLY_LABEL = "apply_label"
    ADD_WARNING_BANNER = "add_warning_banner"
    # mailbox, always MFA: irreversible, or undoes a protection
    DELETE_EMAIL = "delete_email"
    RELEASE_FROM_QUARANTINE = "release_from_quarantine"
    # always MFA (funds / account change / invoice)
    TRANSFER_FUNDS = "transfer_funds"
    PAY_INVOICE = "pay_invoice"
    APPROVE_INVOICE = "approve_invoice"
    CHANGE_BANK_DETAILS = "change_bank_details"
    CHANGE_ACCOUNT_EMAIL = "change_account_email"
    RESET_PASSWORD = "reset_password"
    CHANGE_ACCOUNT_SETTINGS = "change_account_settings"
    ADD_MFA_FACTOR = "add_mfa_factor"  # self-service enrollment: approve with current factors, get a one-time token


ALWAYS_MFA = frozenset(
    {
        ActionType.TRANSFER_FUNDS,
        ActionType.PAY_INVOICE,
        ActionType.APPROVE_INVOICE,
        ActionType.CHANGE_BANK_DETAILS,
        ActionType.CHANGE_ACCOUNT_EMAIL,
        ActionType.RESET_PASSWORD,
        ActionType.CHANGE_ACCOUNT_SETTINGS,
        ActionType.ADD_MFA_FACTOR,
        # Deleting mail destroys evidence and can't be undone once the trash is purged. Releasing a
        # quarantined mail puts a suspected phish back in front of the user, which is exactly what an
        # attacker who talks a helpdesk into "please release my invoice" wants.
        ActionType.DELETE_EMAIL,
        ActionType.RELEASE_FROM_QUARANTINE,
    }
)

# Actions that change a real mailbox (phishguard/mutating/mailbox.py). Single-message quarantine,
# junk, label and banner run without MFA: they are reversible and must be fast to be useful. A batch
# larger than this needs MFA: a compromised client key or a poisoned verdict should not be able to
# empty a whole inbox into quarantine in one call.
MAILBOX_ACTIONS = frozenset(
    {
        ActionType.QUARANTINE_EMAIL,
        ActionType.MARK_SPAM,
        ActionType.APPLY_LABEL,
        ActionType.ADD_WARNING_BANNER,
        ActionType.DELETE_EMAIL,
        ActionType.RELEASE_FROM_QUARANTINE,
    }
)
MAX_UNATTENDED_BATCH = 10

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


def ct_equal(a: Any, b: Any) -> bool:
    """Constant-time equality that never raises. hmac.compare_digest refuses str with non-ASCII
    characters (TypeError), which turned a confirm_digest or code like "ü" into an HTTP 500."""

    def enc(x: Any) -> bytes:
        return str(x).encode("utf-8", "surrogatepass")

    return hmac.compare_digest(enc(a), enc(b))


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
        if ids is not None and (not isinstance(ids, (list, tuple)) or len(ids) > MAX_UNATTENDED_BATCH):
            return True  # bulk (or unreadable) batch: fail closed
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
