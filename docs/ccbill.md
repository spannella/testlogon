# CCBill Billing Integration

This backend includes a CCBill-based billing subsystem with a simple UI embedded in the main control panel (`/`).
The billing UI uses the CCBill Advanced Widget to tokenize cards, then calls backend endpoints to save payment tokens,
charge once, subscribe, and reconcile via webhooks.

## Quick Start (UI)

1. Load the control panel page at `/`.
2. Use **Set tokens** to set your `access_token` (and optional refresh/id tokens).
3. In the **Billing (CCBill)** section:
   - Click **Refresh billing** to load config + balances.
   - Fill the **Add Card** form and click **Create token**.
   - Once tokenized, the UI saves the payment method and you can run a one-time charge or subscription.

## Required Environment Variables

| Variable | Purpose |
| --- | --- |
| `BILLING_TABLE_NAME` | DynamoDB table for billing data (`billing` by default). |
| `CCBILL_BASE_URL` | CCBill API base (default: `https://api.ccbill.com`). |
| `CCBILL_ACCEPT` | CCBill API Accept header (default: `application/vnd.mcn.transaction-service.api.v.2+json`). |
| `CCBILL_FRONTEND_CLIENT_ID` | OAuth client for frontend tokenization. |
| `CCBILL_FRONTEND_CLIENT_SECRET` | OAuth secret for frontend tokenization. |
| `CCBILL_BACKEND_CLIENT_ID` | OAuth client for backend charges. |
| `CCBILL_BACKEND_CLIENT_SECRET` | OAuth secret for backend charges. |
| `CCBILL_CLIENT_ACCNUM` | CCBill client account number. |
| `CCBILL_CLIENT_SUBACC` | CCBill client sub-account number. |
| `DEFAULT_MONTHLY_PRICE_CENTS` | Default subscription price (cents). |
| `DEFAULT_CURRENCY_CODE` | ISO numeric currency code (e.g., 840 for USD). |
| `DEFAULT_CURRENCY` | Currency string (e.g., `usd`). |
| `CCBILL_WEBHOOK_IP_ENFORCE` | Set to `true` to enforce CCBill webhook IP ranges. |

## API Endpoints (Billing)

All endpoints below require a valid UI session (`X-SESSION-ID`) + auth token.

### Settings & Balance

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/api/billing/config` | Returns billing configuration for UI + widget calls. |
| `GET` | `/api/billing/settings` | Returns billing settings (autopay + default payment token). |
| `POST` | `/api/billing/autopay` | Enable/disable autopay. |
| `GET` | `/api/billing/balance` | Returns balance + due amounts. |

### Payment Methods

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/api/billing/payment-methods/ccbill-token` | Save a payment token. |
| `GET` | `/api/billing/payment-methods` | List payment methods. |
| `POST` | `/api/billing/payment-methods/priority` | Set method priority. |
| `POST` | `/api/billing/payment-methods/default` | Set default method. |
| `DELETE` | `/api/billing/payment-methods/{payment_token_id}` | Remove method. |

### Charges & Subscriptions

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/api/billing/charge-once` | Charge a token once. |
| `POST` | `/api/billing/pay-balance` | Pay the settled balance. |
| `POST` | `/api/billing/subscribe-monthly` | Start a monthly subscription. |

### Debug / Internal

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/api/billing/ledger` | List ledger entries. |
| `GET` | `/api/billing/payments` | List payment records. |
| `GET` | `/api/billing/subscriptions` | List subscriptions. |
| `POST` | `/api/billing/_dev/add-charge` | Add a synthetic charge (dev helper). |

### Webhooks

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/api/ccbill/webhook` | CCBill webhook handler. |

## DynamoDB Table Layout

The billing table stores multiple item types in a single partition:

- `user_sub` partition key.
- `sk` sort key values:
  - `BALANCE` for balance snapshots.
  - `BILLING` for settings (default token, autopay).
  - `PM#<token>` for payment methods.
  - `PAY#<transaction>` for payment records.
  - `SUB#<subscription>` for subscriptions.
  - `LEDGER#<ts>#<id>` for ledger entries.

Webhook dedupe and unmatched payloads store under `user_sub` values like `CCBILL_WEBHOOK` and `CCBILL_WEBHOOK_UNMATCHED`.
