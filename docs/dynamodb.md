# DynamoDB Setup

This service uses multiple DynamoDB tables to store sessions, MFA devices, recovery codes, API keys, alerts, and billing artifacts. You must create the tables and export the table names as environment variables before running the app.

## Required tables and environment variables

| Purpose | Env var | Notes |
| --- | --- | --- |
| UI sessions | `DDB_SESSIONS_TABLE` | Required. |
| TOTP devices | `DDB_TOTP_TABLE` | Required. |
| SMS MFA devices | `DDB_SMS_TABLE` | Required. |
| Email MFA devices | `DDB_EMAIL_TABLE` | Required. |
| Recovery codes | `DDB_RECOVERY_TABLE` | Required. |
| API keys | `API_KEYS_TABLE_NAME` | Default: `api_keys`. |
| Alerts | `ALERTS_TABLE_NAME` | Default: `alerts`. |
| Alert preferences | `ALERT_PREFS_TABLE_NAME` | Default: `alert_prefs`. |
| Billing data | `BILLING_TABLE_NAME` | Required for Stripe/PayPal/CCBill billing features. |

## Table schema overview
Most tables use a partition key (PK) and optional sort key (SK). The services store JSON-like items that include timestamps (`created_at`, `updated_at`) and user identifiers (`user_sub`, `user_id`).

### Billing table
The billing table is a single-table design storing:
- **Balance**: `sk = BALANCE`
- **Settings**: `sk = BILLING`
- **Payment methods**: `sk = PM#<payment_method_id>`
- **Payments**: `sk = PAY#<payment_intent_id>`
- **Ledger entries**: `sk = LEDGER#<ts>#<id>`

### API keys table
API keys are stored by user and often rely on a secondary index for user lookup (`API_KEYS_USER_INDEX`).

## Provisioning checklist
1. Create the DynamoDB tables in the target AWS region.
2. Configure table names in your environment (`.env` or secrets manager).
3. Ensure the runtime AWS credentials have read/write access to each table.
4. (Optional) Enable TTL where relevant for expiring records like sessions or event dedupe markers.

## Local development tips
- For local testing, you can use DynamoDB Local and point your AWS SDK config at the local endpoint.
- Keep table name env vars in the same `.env` used for other secrets.
