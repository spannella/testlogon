# DLU-001 — Internal Dev Log UI Log Input Inventory

This document closes DLU-001 by defining the canonical local log/artifact inputs for the Dev Log UI, including sample record shapes and malformed data patterns the parsers must tolerate.

## Scope
- Email source(s): dev-mode email verification/alert writes.
- SMS source(s): dev-mode SMS verification/alert writes.
- Billing source(s): local Stripe mock process log + backend access log lines for in-process CCBill/PayPal mocks.

---

## 1) Canonical path defaults (ready for env wiring)

| Domain | Canonical default | Env override |
|---|---|---|
| Email | `.logs/dev/emails.log` | `DEVTOOLS_EMAIL_LOG_PATH` (fallback `DEV_EMAIL_LOG`) |
| SMS | `.logs/dev/sms.log` | `DEVTOOLS_SMS_LOG_PATH` (fallback `DEV_SMS_LOG`) |
| Stripe provider log | `.local/logs/stripe-mock.log` | `DEVTOOLS_BILLING_STRIPE_LOG_PATH` |
| CCBill/PayPal request traces | `.logs/dev/backend.log` | `DEVTOOLS_BILLING_BACKEND_LOG_PATH` |

Notes:
- Email/SMS dev logs are application-authored files.
- Stripe has a dedicated mock process log under `.local/logs`.
- CCBill and PayPal mock providers run in-process on backend routes (`/mock/ccbill/*`, `/mock/paypal/*`), so request visibility comes through backend logs.

---

## 2) Format matrix with sample records

## 2.1 Email log (`.logs/dev/emails.log`)
Source writers:
- MFA email code sender
- Alerts email sender

Observed shape: plaintext multi-line blocks with UTC timestamp header.

### Sample (MFA email code)
```txt
[2026-02-28T14:01:22Z] TO=user@example.com PURPOSE=login
  Subject: Your verification code (login)
  Code: 123456
  Body: Your verification code is: 123456

```

### Sample (alert email)
```txt
[2026-02-28T14:03:50Z] ALERT_EMAIL TO=user@example.com
  Subject: New sign-in detected
  Body: We detected a new sign-in from device X

```

Key fields by parser:
- `timestamp` (header bracket time)
- `to`
- `event_kind` (`mfa_email_code` vs `alert_email`)
- `purpose` (MFA only)
- `subject`
- `body`
- optional `code` (MFA only)

## 2.2 SMS log (`.logs/dev/sms.log`)
Source writers:
- MFA SMS code sender
- Alerts SMS sender

Observed shape: plaintext single-line (MFA) and multi-line (alert) entries.

### Sample (MFA SMS)
```txt
[2026-02-28T14:02:10Z] SMS TO=+14155550123 Code: 654321
```

### Sample (alert SMS)
```txt
[2026-02-28T14:04:12Z] ALERT_SMS TO=+14155550123
  Body: Payment failed for subscription sub_123

```

Key fields by parser:
- `timestamp`
- `to` (E.164 where available)
- `event_kind` (`mfa_sms_code` vs `alert_sms`)
- optional `code` (MFA only)
- optional `body` (alert only)

## 2.3 Billing provider inputs

### A) Stripe mock process log (`.local/logs/stripe-mock.log`)
Produced by `scripts/local-stack-up.sh` when `stripe-mock` is started via `nohup` redirection.

Typical shape: process/runtime log lines (not canonical transaction JSON).

### B) Backend log request traces (`.logs/dev/backend.log`)
Contains uvicorn/backend output for in-process mock endpoints, including:
- `POST /mock/ccbill/ccbill-auth/oauth/token`
- `POST /mock/ccbill/transactions/payment-tokens/{id}`
- `POST /mock/paypal/v2/checkout/orders`
- `POST /mock/paypal/v2/checkout/orders/{id}/capture`
- `POST /mock/paypal/v1/billing/subscriptions`

Representative access-log shape:
```txt
INFO:     127.0.0.1:53342 - "POST /mock/paypal/v2/checkout/orders HTTP/1.1" 200 OK
INFO:     127.0.0.1:53343 - "POST /mock/ccbill/transactions/payment-tokens/tok_abc HTTP/1.1" 200 OK
```

### C) Provider response payloads (for parser fixtures)
Because provider process/backend logs are not normalized ledgers, adapters should parse known mock response payload shapes from provider routes and correlate with request traces.

Representative CCBill mock charge response:
```json
{
  "approved": true,
  "responseCode": "200",
  "transactionId": "txn_1740759312123",
  "paymentUniqueId": "txn_1740759312123",
  "subscriptionId": "sub_1740759312123",
  "nextRenewalDate": "2026-03-30T12:00:00Z",
  "message": "Approved"
}
```

Representative PayPal capture response:
```json
{
  "id": "MOCK-ORDER-ABC123",
  "status": "COMPLETED",
  "purchase_units": [
    {
      "payments": {
        "captures": [
          {
            "id": "CAP-XYZ987",
            "status": "COMPLETED",
            "amount": {"currency_code": "USD", "value": "9.99"}
          }
        ]
      }
    }
  ]
}
```

---

## 3) Malformed-line patterns parsers must tolerate

## 3.1 Email/SMS plaintext parser tolerance
- Missing bracket timestamp (`[...Z]`).
- Header present but missing `TO=` token.
- Truncated multi-line blocks (missing subject/body/code line).
- Mixed entry types back-to-back without blank line separator.
- Non-UTF8 bytes or partial writes during tail.
- Duplicate lines after process restart/retry.

## 3.2 Billing parser tolerance
- Missing provider logs (e.g., stripe-mock not started yet).
- Access log lines missing HTTP method/path/status (partial writes).
- Unknown `/mock/*` endpoint variants.
- Provider payloads missing expected IDs (`transactionId`, capture `id`, subscription id).
- Currency or amount values malformed/non-numeric.
- Out-of-order events (capture before create in merged view).

---

## 4) Resolved ambiguities

1. **`email.log` naming vs existing config:** the repo currently defaults to `.logs/dev/emails.log` (plural). DLU parser and UI should treat this as canonical default and optionally support `email.log` aliases via env override.
2. **CCBill/PayPal file location:** no dedicated provider-process logfile exists; these providers are mocked in-process and therefore traced via backend logs.
3. **Billing ledger source quality:** provider logs are useful for trace/debug, but normalized ledger rows should be derived from provider payload contracts + app billing transaction records when available.

---

## 5) Implementation handoff notes

- Settings fields for DLU-001 path defaults are now available as:
  - `S.devtools_email_log_path`
  - `S.devtools_sms_log_path`
  - `S.devtools_billing_stripe_log_path`
  - `S.devtools_billing_backend_log_path`
- Local env template includes commented overrides for all four variables.
- Next ticket (DLU-002) should define canonical DTOs using these inputs.
