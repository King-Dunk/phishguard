# Plugging in a real payment or account provider

PhishGuard ships with `SimulatedBank` and `SimulatedAccounts`. They move no real money. This guide is for a company that wants approved actions to reach its real bank, payment processor, accounting system or identity provider. The MFA gateway, policy and audit log don't change: you implement one interface and pick it in config.

## Where a provider sits

```
POST /actions ──> MFAGateway (suspend, two factors, digest echo, timeout, lockout, audit)
                     │ release (at most once per pending action)
                     ▼
                  Executor ──> PaymentProvider  (transfer, pay_invoice, approve_invoice,
                     │                          change_bank_details, get_payee, get_status, ...)
                     └──────> AccountProvider  (reset_password, change_account_email,
                                                change_account_settings)
```

- The executor only runs with a grant the gateway issues after the multi-factor policy passes. A provider never sees an unapproved action.
- The executor maps action `params` to typed requests (`TransferRequest`, `InvoicePaymentRequest`, `BankDetails`) and validates them (`parse_amount`, `check_id`, `validate_details`) before your code runs.
- Your code returns typed results (`Transaction`, `Payee`, `BankDetailsChange`, `InvoiceResult`, `AccountActionResult`) or raises a `PaymentError` subclass. The executor turns an error into a `declined` action (HTTP 422, audit event `action_declined` with the error code). It never retries on its own.

Interfaces: `phishguard/mutating/payments/base.py`. Reference implementation: `payments/simulated.py`. Stubs with per-method notes: `payments/adapters.py`.

## Steps

1. **Pick a stub or start a class.** `Iso20022BankAdapter` (bank host-to-host or bank API, `pain.001` / `pain.002` / `camt.05x`), `StripeAdapter` (Treasury outbound payments / payouts), `XeroAdapter` and `MYOBAdapter` (bill approval and payment records; money still moves through the bank), `IdentityProviderAdapter` (Entra ID / Okta / Google Workspace). Each method's docstring says which API call to make.
2. **Load credentials at construction**, from the environment or a secrets manager. Never from action params: params come from the agent or the request body and are attacker-influenced. Use the narrowest scopes the provider offers (for example a Stripe restricted key with only payout permissions).
3. **Pass the idempotency key through.** The executor gives every call `idempotency_key = "pg-<pending_id>"`, so one approved action has one key. Map it to the provider's mechanism: Stripe `Idempotency-Key` header, ISO 20022 `PmtId/EndToEndId` (max 35 characters; hash longer keys), Xero `Idempotency-Key`. MYOB has none, so store the key in the memo and look it up before retrying. Same key with the same request: return the original result. Same key with a different request: raise `IdempotencyConflict`.
4. **Map errors** to `base.py` classes with stable codes: `InsufficientFunds`, `LimitExceeded`, `PayeeNotFound`, `CoolingOff`, `InvalidRequest`. A timeout or 5xx is `ProviderUnavailable` (`retryable=True`). Never assume a timed-out payment didn't happen: look it up by idempotency key before trying again.
5. **Keep the cooling-off rule.** New payees and changed bank details must not receive money for a period (the simulator defaults to 24 h, `PHISHGUARD_COOLING_OFF_SECONDS`). This stops the most common business-email-compromise pattern ("our bank details changed" followed by an urgent invoice). If your provider has no such control, enforce it in the adapter from your own record of when the payee's details last changed, not from a generic "last updated" timestamp. Where your bank offers it, add account-name checking (UK Confirmation of Payee, EU Verification of Payee, Australian PayID name lookup) in `change_bank_details`.
6. **Report status honestly.** Real rails are asynchronous: return `TxStatus.SUBMITTED` and update it from status reports or webhooks (`COMPLETED`, `FAILED`, `REVERSED`). `GET /payments/transactions/{id}` calls `get_status`.
7. **Mask account numbers** in everything you return (`mask()`); the read-only `/payments/*` routes expose these objects.
8. **Register and select it.** Add the class to `PAYMENT_PROVIDERS` in `payments/__init__.py` and set `PHISHGUARD_PAYMENT_PROVIDER=<name>`. An unknown name stops the server at startup. A stub that is selected but not implemented declines every action with `provider_not_implemented`.
9. **Test against the contract.** Copy the SimulatedBank tests in `tests/test_payments.py` (limits, cooling-off, idempotency, persistence) and run them against your adapter with the provider's sandbox. Then run `python -m redteam.runner`: `pv-pay-bec-cooling-off` and `pv-pay-limit-split` must still pass.

## Limits you should configure at the provider too

The simulator's per-transfer limit (`PHISHGUARD_PER_TRANSFER_LIMIT`), daily limit (`PHISHGUARD_DAILY_LIMIT`) and cooling-off are defense in depth. A real deployment should also set limits, payee allow-lists and dual control *inside* the bank or processor, so a compromise of this service can't exceed them.

## What not to do

- Don't add a route that moves money or edits a payee outside `POST /actions`. Every state change goes through the gateway.
- Don't let the adapter decide that a payment is "safe enough" to skip anything. Approval is the gateway's job; the adapter only executes and refuses.
- Don't log request bodies with full account numbers, credentials or tokens.

## Honest status

Every adapter in `adapters.py` is a stub with no network calls. Nothing here has been tested against a real bank, Stripe, Xero, MYOB or an identity provider.
