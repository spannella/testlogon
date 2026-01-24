# PayPal Billing Integration

This backend includes a PayPal billing subsystem with a UI panel embedded in the main control panel (`/`). The PayPal flow supports payment method vaulting, one-time charges, subscriptions, and ledger visibility.

## Architecture at a glance
- **UI setup token flow**: the control panel requests a setup token from `/api/billing/payment-methods/paypal/setup-token`.
- **Token exchange**: once PayPal returns a vault token, the UI exchanges it with `/api/billing/payment-methods/paypal/exchange-token`.
- **Charges + subscriptions**: the UI invokes backend routes that call PayPal APIs for capture/charge/subscription creation.
- **Webhooks**: PayPal posts events to `/api/paypal/webhook` for reconciliation and status updates.

## Required environment variables

| Variable | Purpose |
| --- | --- |
| `BILLING_TABLE_NAME` | DynamoDB table for billing data. |
| `PAYPAL_CLIENT_ID` | PayPal client ID for API access. |
| `PAYPAL_CLIENT_SECRET` | PayPal client secret for API access. |
| `PAYPAL_WEBHOOK_ID` | PayPal webhook ID for signature verification. |

## Optional environment variables

| Variable | Purpose |
| --- | --- |
| `PAYPAL_ENV` | `sandbox` or `live` PayPal environment (default: `sandbox`). |
| `PUBLIC_BASE_URL` | Base URL used for redirect + webhook URLs. |
| `DEFAULT_CURRENCY` | Default currency for charges (e.g., `usd`). |
| `DEFAULT_MONTHLY_PRICE_CENTS` | Default subscription price in cents. |
| `PAYPAL_PLAN_MAP` | CSV mapping of plan names to PayPal plan IDs. |

## API endpoints (billing)

All endpoints below require a valid UI session (`X-SESSION-ID`) + auth token.

### Settings & balance

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/api/billing/config` | Returns billing configuration for UI calls. |
| `GET` | `/api/billing/settings` | Returns billing settings (autopay + default payment token). |
| `POST` | `/api/billing/autopay` | Enable/disable autopay. |
| `GET` | `/api/billing/balance` | Returns balance + due amounts. |

### Payment methods

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/api/billing/payment-methods/paypal/setup-token` | Create a PayPal setup token. |
| `POST` | `/api/billing/payment-methods/paypal/exchange-token` | Exchange the setup token for a vault token. |
| `GET` | `/api/billing/payment-methods` | List payment methods. |
| `POST` | `/api/billing/payment-methods/priority` | Set method priority. |
| `POST` | `/api/billing/payment-methods/default` | Set default method. |
| `DELETE` | `/api/billing/payment-methods/{payment_token_id}` | Remove method. |

### Charges & subscriptions

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/api/billing/charge-once` | Charge a token once. |
| `POST` | `/api/billing/paypal/capture-order` | Capture a PayPal order. |
| `POST` | `/api/billing/pay-balance` | Pay the settled balance. |
| `POST` | `/api/billing/subscribe-monthly` | Start a monthly subscription. |
| `POST` | `/api/billing/subscriptions/cancel` | Cancel a subscription. |

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
| `POST` | `/api/paypal/webhook` | PayPal webhook handler. |

## Troubleshooting

- **Setup token creation fails**: confirm `PAYPAL_CLIENT_ID`, `PAYPAL_CLIENT_SECRET`, and `PAYPAL_ENV` match the PayPal environment.
- **Vaulted method missing**: check the token exchange response from `/api/billing/payment-methods/paypal/exchange-token`.
- **Webhook verification errors**: confirm `PAYPAL_WEBHOOK_ID` matches the webhook configured in the PayPal dashboard and that `PUBLIC_BASE_URL` is correct.
