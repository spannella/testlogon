# Stripe Billing Integration

This backend includes a Stripe billing subsystem with a UI panel embedded in the main control panel (`/`). The Stripe flow supports cards, ACH setup intents, one-time charges, and balance tracking via the shared billing ledger.

## Architecture at a glance
- **Setup intents**: the control panel requests card or ACH setup intents to collect payment methods.
- **Payment methods**: Stripe webhooks attach and store payment methods in DynamoDB after setup succeeds.
- **Charges + balance**: charges update the billing ledger and balance rows in DynamoDB.
- **Webhooks**: Stripe posts events to `/api/stripe/webhook` for reconciliation and payment status updates.

## Required environment variables

| Variable | Purpose |
| --- | --- |
| `BILLING_TABLE_NAME` | DynamoDB table for billing data. |
| `STRIPE_SECRET_KEY` | Stripe secret key for API access. |
| `STRIPE_PUBLISHABLE_KEY` | Stripe publishable key for the UI. |
| `STRIPE_WEBHOOK_SECRET` | Stripe webhook signing secret. |

## Optional environment variables

| Variable | Purpose |
| --- | --- |
| `STRIPE_DEFAULT_CURRENCY` | Default currency for charges (default: `usd`). |
| `STRIPE_SUCCESS_URL` | Success redirect URL for checkout sessions. |
| `STRIPE_CANCEL_URL` | Cancel redirect URL for checkout sessions. |

## API endpoints (billing)

All endpoints below require a valid UI session (`X-SESSION-ID`) + auth token unless noted.

### Settings & balance

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/api/billing/config` | Returns Stripe publishable key and default currency. |
| `GET` | `/api/billing/settings` | Returns billing settings (autopay + default payment method). |
| `POST` | `/api/billing/autopay` | Enable/disable autopay. |
| `GET` | `/api/billing/balance` | Returns balance + due amounts. |

### Payment methods

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/api/billing/setup-intent/card` | Create a card setup intent. |
| `POST` | `/api/billing/setup-intent/us-bank` | Create an ACH setup intent. |
| `POST` | `/api/billing/us-bank/verify-microdeposits` | Verify ACH microdeposits. |
| `GET` | `/api/billing/payment-methods` | List payment methods. |
| `POST` | `/api/billing/payment-methods/priority` | Set method priority. |
| `POST` | `/api/billing/payment-methods/default` | Set default method. |
| `DELETE` | `/api/billing/payment-methods/{payment_method_id}` | Remove method. |

### Charges & checkout

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/api/billing/pay-balance` | Pay the settled balance. |
| `POST` | `/api/billing/charge-once` | Charge a payment method once. |
| `POST` | `/api/billing/checkout_session` | Create a Stripe checkout session. |

### Debug / internal

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/api/billing/ledger` | List ledger entries. |
| `GET` | `/api/billing/payments` | List payment records. |
| `GET` | `/api/billing/subscriptions` | List subscriptions. |
| `POST` | `/api/billing/_dev/add-charge` | Add a synthetic charge (dev helper). |

### Webhooks

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/api/stripe/webhook` | Stripe webhook handler. |

## Troubleshooting

- **Config endpoint fails**: confirm `STRIPE_PUBLISHABLE_KEY` is set and the Stripe SDK is installed.
- **Payment method missing**: ensure the `setup_intent.succeeded` webhook reaches `/api/stripe/webhook`.
- **Webhook verification errors**: confirm `STRIPE_WEBHOOK_SECRET` matches the signing secret configured in Stripe.
