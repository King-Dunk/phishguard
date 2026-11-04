"""Adapter STUBS for real integrations. None of them makes a network call; every method raises
NotImplementedError. Each docstring says what a real implementation must do. See
docs/PAYMENTS_INTEGRATION.md for the end-to-end guide.

Rules that apply to every adapter:
- Credentials come from the environment or a secrets manager at construction time, never from action
  params (params are attacker-influenced: they come from the agent or the request body).
- Pass the executor's `idempotency_key` through to the provider's own idempotency mechanism
  (Stripe `Idempotency-Key` header, ISO 20022 `EndToEndId`/`InstrId`, Xero `Idempotency-Key`).
- Map provider errors onto the PaymentError subclasses in base.py; a timeout is ProviderUnavailable
  (retryable), never "assume it worked".
- Keep the cooling-off rule. If the provider has no such control, enforce it here from the payee's
  last-changed timestamp before submitting.
"""

from __future__ import annotations

from typing import Any

from .base import (
    Account,
    AccountActionResult,
    AccountProvider,
    BankDetails,
    BankDetailsChange,
    InvoicePaymentRequest,
    InvoiceResult,
    Payee,
    PaymentProvider,
    Transaction,
    TransferRequest,
)


class _Stub:
    def __init__(self, options: dict[str, Any] | None = None):
        self.options = dict(options or {})

    def _todo(self, what: str):
        raise NotImplementedError(f"{type(self).__name__}.{what} is a stub; see docs/PAYMENTS_INTEGRATION.md")


class Iso20022BankAdapter(_Stub, PaymentProvider):
    """Generic bank connection using ISO 20022 messages (host-to-host SFTP or a bank's REST API).

    Options to read at construction: bank API base URL or SFTP host, debtor account (IBAN/BSB+number),
    client certificate / mTLS key reference (from a secrets manager), signing key for pain.001 files.
    """

    name = "iso20022"

    def transfer(self, req: TransferRequest, *, idempotency_key: str) -> Transaction:
        """Build a `pain.001.001.09` CustomerCreditTransferInitiation with one CdtTrfTxInf:
        Dbtr/DbtrAcct from `req.from_account`, Cdtr/CdtrAcct from the payee's stored details,
        InstdAmt `req.amount` in `req.currency`, RmtInf/Ustrd `req.reference`, and
        PmtId/EndToEndId = `idempotency_key` (max 35 chars; hash it if longer). Sign and submit.
        Return status SUBMITTED; settle later from `pain.002` (status report) and `camt.054`
        (debit notification) by EndToEndId. A rejected pain.002 maps to TxStatus.FAILED."""
        self._todo("transfer")

    def pay_invoice(self, req: InvoicePaymentRequest, *, idempotency_key: str) -> Transaction:
        """Look up the invoice in your AP system (amount, creditor), then do exactly what `transfer` does,
        with RmtInf/Strd/RfrdDocInf carrying the invoice number."""
        self._todo("pay_invoice")

    def approve_invoice(self, invoice_id: str, *, idempotency_key: str) -> InvoiceResult:
        """Banks don't approve invoices; delegate to the accounting adapter or raise ProviderNotImplemented."""
        self._todo("approve_invoice")

    def get_payee(self, payee_id: str) -> Payee:
        """Read the creditor from YOUR payee master data (the bank has none). Include changed_at."""
        self._todo("get_payee")

    def change_bank_details(
        self, payee_id: str, details: BankDetails, *, idempotency_key: str, name: str | None = None
    ) -> BankDetailsChange:
        """Update your payee master data and set cooling_off_until = now + configured period. Optionally
        run account-name verification (UK Confirmation of Payee, EU Verification of Payee, AU NPP PayID
        lookup) and refuse on a mismatch."""
        self._todo("change_bank_details")

    def get_status(self, transaction_id: str) -> Transaction:
        """Return the latest status known from pain.002/camt.054 for this EndToEndId."""
        self._todo("get_status")

    def list_transactions(self, account: str, limit: int = 50) -> list[Transaction]:
        """From camt.053 statements / camt.052 intraday reports."""
        self._todo("list_transactions")

    def list_accounts(self) -> list[Account]:
        """Balances from camt.052/053 (or the bank's balance API)."""
        self._todo("list_accounts")


class StripeAdapter(_Stub, PaymentProvider):
    """Stripe payouts / Treasury outbound payments. API key from STRIPE_API_KEY (restricted key with
    only the payout scopes you need). Never log the key."""

    name = "stripe"

    def transfer(self, req: TransferRequest, *, idempotency_key: str) -> Transaction:
        """POST /v1/treasury/outbound_payments (or /v1/payouts to a connected external account) with
        header `Idempotency-Key: <idempotency_key>`, amount in the smallest currency unit
        (int(req.amount * 100) for AUD/USD/EUR; check zero-decimal currencies), destination = the
        payee's stored external account id. Map `card_declined`/`insufficient_funds` errors to
        InsufficientFunds, 429/5xx to ProviderUnavailable."""
        self._todo("transfer")

    def pay_invoice(self, req: InvoicePaymentRequest, *, idempotency_key: str) -> Transaction:
        """Paying a SUPPLIER invoice is an outbound payment as in `transfer`. (Stripe Invoices are for
        invoices you send to customers, not ones you pay.)"""
        self._todo("pay_invoice")

    def approve_invoice(self, invoice_id: str, *, idempotency_key: str) -> InvoiceResult:
        """Not a Stripe concept; delegate to the accounting adapter."""
        self._todo("approve_invoice")

    def get_payee(self, payee_id: str) -> Payee:
        """GET the external account / recipient; take changed_at from your own records or Stripe events."""
        self._todo("get_payee")

    def change_bank_details(
        self, payee_id: str, details: BankDetails, *, idempotency_key: str, name: str | None = None
    ) -> BankDetailsChange:
        """Create a NEW external account (don't mutate the old one), record cooling_off_until, and only
        switch the payee's default destination after cooling-off."""
        self._todo("change_bank_details")

    def get_status(self, transaction_id: str) -> Transaction:
        """GET the outbound payment; map `processing`->SUBMITTED, `posted`->COMPLETED,
        `failed`/`canceled`->FAILED, `returned`->REVERSED. Prefer webhooks for updates."""
        self._todo("get_status")

    def list_transactions(self, account: str, limit: int = 50) -> list[Transaction]:
        """GET /v1/treasury/transactions?financial_account=...&limit=..."""
        self._todo("list_transactions")

    def list_accounts(self) -> list[Account]:
        """GET /v1/treasury/financial_accounts and their balances."""
        self._todo("list_accounts")


class XeroAdapter(_Stub, PaymentProvider):
    """Xero accounting (OAuth 2.0; tenant id and refresh token from a secrets manager). Xero records
    payments and approves bills; money actually moves via the bank (pair with Iso20022BankAdapter)."""

    name = "xero"

    def transfer(self, req: TransferRequest, *, idempotency_key: str) -> Transaction:
        """PUT /api.xro/2.0/BankTransactions (Type=SPEND) with header `Idempotency-Key`; then initiate
        the real payment through the bank adapter."""
        self._todo("transfer")

    def pay_invoice(self, req: InvoicePaymentRequest, *, idempotency_key: str) -> Transaction:
        """PUT /api.xro/2.0/Payments {Invoice: {InvoiceID}, Account: {Code}, Amount, Date} with
        `Idempotency-Key`. Refuse if the bill's contact had bank details changed within cooling-off."""
        self._todo("pay_invoice")

    def approve_invoice(self, invoice_id: str, *, idempotency_key: str) -> InvoiceResult:
        """POST /api.xro/2.0/Invoices/{InvoiceID} with Status=AUTHORISED."""
        self._todo("approve_invoice")

    def get_payee(self, payee_id: str) -> Payee:
        """GET /api.xro/2.0/Contacts/{ContactID}; BankAccountDetails; UpdatedDateUTC as changed_at
        (that timestamp covers any field, so keep your own record of bank-detail changes)."""
        self._todo("get_payee")

    def change_bank_details(
        self, payee_id: str, details: BankDetails, *, idempotency_key: str, name: str | None = None
    ) -> BankDetailsChange:
        """POST /api.xro/2.0/Contacts/{ContactID} with the new BankAccountDetails; record cooling-off."""
        self._todo("change_bank_details")

    def get_status(self, transaction_id: str) -> Transaction:
        """GET /api.xro/2.0/Payments/{PaymentID}; map Status AUTHORISED -> COMPLETED, DELETED -> REVERSED.
        Xero records the payment; settlement status still comes from the bank adapter."""
        self._todo("get_status")

    def list_transactions(self, account: str, limit: int = 50) -> list[Transaction]:
        """GET /api.xro/2.0/BankTransactions?where=BankAccount.Code=="..." (paged)."""
        self._todo("list_transactions")

    def list_accounts(self) -> list[Account]:
        """GET /api.xro/2.0/Accounts?where=Type=="BANK" plus the bank summary report for balances."""
        self._todo("list_accounts")


class MYOBAdapter(_Stub, PaymentProvider):
    """MYOB AccountRight / Business API (OAuth 2.0 + company file credentials). Same shape as Xero:
    supplier payments and bill approval; money moves via the bank."""

    name = "myob"

    def transfer(self, req: TransferRequest, *, idempotency_key: str) -> Transaction:
        """POST /{cf}/Banking/SpendMoneyTxn; store the idempotency key in the memo and look it up before
        retrying (MYOB has no idempotency header)."""
        self._todo("transfer")

    def pay_invoice(self, req: InvoicePaymentRequest, *, idempotency_key: str) -> Transaction:
        """POST /{cf}/Purchase/SupplierPayment referencing the bill; dedupe by memo as in `transfer`."""
        self._todo("pay_invoice")

    def approve_invoice(self, invoice_id: str, *, idempotency_key: str) -> InvoiceResult:
        """Convert the purchase order to a bill / mark approved per your MYOB workflow."""
        self._todo("approve_invoice")

    def get_payee(self, payee_id: str) -> Payee:
        """GET /{cf}/Contact/Supplier/{UID}; PaymentDetails holds the bank account."""
        self._todo("get_payee")

    def change_bank_details(
        self, payee_id: str, details: BankDetails, *, idempotency_key: str, name: str | None = None
    ) -> BankDetailsChange:
        """PUT /{cf}/Contact/Supplier/{UID} with new PaymentDetails (send RowVersion); record cooling-off."""
        self._todo("change_bank_details")

    def get_status(self, transaction_id: str) -> Transaction:
        """GET the SupplierPayment / SpendMoneyTxn by UID."""
        self._todo("get_status")

    def list_transactions(self, account: str, limit: int = 50) -> list[Transaction]:
        """GET /{cf}/Banking/SpendMoneyTxn?$filter=Account/UID eq ... &$top=limit."""
        self._todo("list_transactions")

    def list_accounts(self) -> list[Account]:
        """GET /{cf}/GeneralLedger/Account?$filter=Type eq 'Bank'."""
        self._todo("list_accounts")


class IdentityProviderAdapter(_Stub, AccountProvider):
    """Account actions against an identity provider (Microsoft Entra ID via Graph, Okta, Google
    Workspace Admin SDK). Use an app credential scoped to exactly these operations."""

    name = "idp"

    def reset_password(self, user: str, *, idempotency_key: str) -> AccountActionResult:
        """Okta: POST /api/v1/users/{id}/lifecycle/reset_password?sendEmail=true. Entra: use the
        self-service reset flow or `authentication/methods/{id}/resetPassword`; never return the
        temporary password to the caller. Revoke sessions (Graph `revokeSignInSessions`)."""
        self._todo("reset_password")

    def change_account_email(self, user: str, new_email: str, *, idempotency_key: str) -> AccountActionResult:
        """Update the primary email/UPN; the IdP should verify the new address before it takes effect."""
        self._todo("change_account_email")

    def change_account_settings(
        self, user: str, settings: dict[str, Any], *, idempotency_key: str
    ) -> AccountActionResult:
        """Map an ALLOWLIST of setting names to IdP fields. Mail forwarding and inbox rules are classic
        attacker persistence; route those to the mail system's API and alert on them."""
        self._todo("change_account_settings")
