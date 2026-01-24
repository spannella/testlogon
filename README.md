Refactored FastAPI security backend (split from the original single-file server). It powers
session management, MFA, billing, notifications, and a lightweight control panel UI.

## Documentation
- [File reference](docs/file-reference.md)
- [Run and deploy](docs/run-deploy.md)
- [Architecture](docs/architecture.md)
- [DynamoDB setup](docs/dynamodb.md)
- [AWS services](docs/aws-services.md)
- [Twilio SMS](docs/twilio.md)
- [CCBill billing](docs/ccbill.md)
- [Stripe billing](docs/stripe.md)
- [PayPal billing](docs/paypal.md)
- [UPS integration](docs/ups.md)

## What ships in this service
- **FastAPI API surface**: routers for account management, MFA, alerts, billing, file management, and more.
- **Service layer**: DynamoDB-backed helpers for sessions, API keys, alerts, and billing.
- **Static control panel UI**: browser-based dashboard served from `/` for testing and ops.
- **Billing integrations**: Stripe, PayPal endpoints, and a dedicated CCBill flow.

## Quick start
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## Required environment variables (minimum)
| Variable | Purpose | Notes |
| --- | --- | --- |
| `AWS_REGION` | AWS region for DynamoDB/KMS/SES. | |
| `DDB_SESSIONS_TABLE` | DynamoDB table for UI sessions. | |
| `DDB_TOTP_TABLE` | DynamoDB table for TOTP enrollment. | |
| `DDB_SMS_TABLE` | DynamoDB table for SMS MFA. | |
| `DDB_EMAIL_TABLE` | DynamoDB table for email MFA. | |
| `DDB_RECOVERY_TABLE` | DynamoDB table for recovery codes. | |
| `API_KEYS_TABLE_NAME` | API keys table name. | Default: `api_keys`. |
| `API_KEYS_USER_INDEX` | GSI name for lookup by user. | Default: `user_sub-index`. |
| `API_KEY_PEPPER` | Secret pepper for API key hashing. | Store as a secret. |
| `ALERTS_TABLE_NAME` | Alerts table name. | Default: `alerts`. |
| `ALERT_PREFS_TABLE_NAME` | Alert preferences table name. | Default: `alert_prefs`. |
| `WS_TOKEN_SECRET` | HMAC secret for WS tokens. | Store as a secret. |

## Optional environment variables
- `KMS_KEY_ID` for encrypting TOTP secrets.
- `SES_FROM_EMAIL` for email MFA.
- `TWILIO_*` for SMS MFA.
- `ALERTS_*` for outbound alert fanout.
- `PUSH_*` for push notifications (FCM).

## Related docs
- **Billing**: Stripe details live in [Stripe billing](docs/stripe.md). PayPal details live in [PayPal billing](docs/paypal.md). CCBill details live in [CCBill billing](docs/ccbill.md).
- **Endpoints**: See the routers and services catalog in [File reference](docs/file-reference.md).
