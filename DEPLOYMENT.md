# Deployment Guide

## Quick Start (Local Dev)

```bash
cp .env.example .env          # copy and edit with your values
./start.sh                    # starts backend (:8000) + frontend (:3000)
./start.sh stop               # stop both
```

The app runs in **DEV_MODE** by default — Cognito auth is bypassed and you can
authenticate with any `Authorization: Bearer <user_id>` header.
If you want a simple dev login in the UI, set `DEV_TEST_USER` and
`DEV_TEST_PASSWORD` to allow those credentials to start a session in dev mode.

---

## Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| Python | 3.10+ | Backend runtime |
| Node.js | 18+ | Frontend build |
| npm | 9+ | Package manager |
| AWS CLI | 2.x | Optional, for real AWS |
| Docker | 24+ | Optional, for DynamoDB Local |

---

## Architecture Overview

```
┌─────────────┐     proxy /ui, /api,     ┌──────────────┐
│   Frontend   │────  /messaging, etc.  ──│   Backend    │
│  Vite :3000  │                          │ FastAPI :8000│
└─────────────┘                           └──────┬───────┘
                                                 │
        ┌──────────┬──────────┬──────────┬───────┴────────┐
        │          │          │          │                │
   DynamoDB      S3        SES/SNS     KMS         OpenSearch
   (27 tables)  (files)   (email)    (encrypt)     (search)
```

**Backend**: FastAPI + uvicorn (354 routes, 27+ routers)
**Frontend**: React 18 + Vite 6 + TypeScript + Tailwind CSS 4 + shadcn/ui

---

## External Services & API Keys

### Tier 1 — Required for core functionality

| Service | What for | Keys needed | Where to get them |
|---------|----------|-------------|-------------------|
| **AWS DynamoDB** | All data storage (sessions, users, billing, etc.) | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | [IAM Console](https://console.aws.amazon.com/iam/) or use DynamoDB Local (see below) |
| **AWS KMS** | Encrypts TOTP secrets, MFA codes | `KMS_KEY_ID` (ARN) | [KMS Console](https://console.aws.amazon.com/kms/) — Create a symmetric key |

### Tier 2 — Required for specific features

| Service | What for | Keys needed | Where to get them |
|---------|----------|-------------|-------------------|
| **AWS Cognito** | Production JWT authentication | `COGNITO_USER_POOL_ID`, `COGNITO_APP_CLIENT_ID` | [Cognito Console](https://console.aws.amazon.com/cognito/) |
| **AWS SES** | Email MFA codes, alert emails | `SES_FROM_EMAIL` (verified sender) | [SES Console](https://console.aws.amazon.com/ses/) — Verify a domain/email |
| **AWS S3** | File uploads, chat images | `FILEMGR_BUCKET`, `S3_BUCKET_IMAGES` | [S3 Console](https://console.aws.amazon.com/s3/) — Create buckets |
| **Stripe** | Card payments, subscriptions | `STRIPE_SECRET_KEY`, `STRIPE_PUBLISHABLE_KEY`, `STRIPE_WEBHOOK_SECRET` | [Stripe Dashboard](https://dashboard.stripe.com/apikeys) |
| **PayPal** | Alternative payments | `PAYPAL_CLIENT_ID`, `PAYPAL_CLIENT_SECRET`, `PAYPAL_WEBHOOK_ID` | [PayPal Developer](https://developer.paypal.com/dashboard/applications/sandbox) |
| **CCBill** | Alternative payments | 4 client ID/secret pairs, account numbers | CCBill merchant portal |
| **Twilio** | SMS MFA verification | `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_VERIFY_SERVICE_SID` | [Twilio Console](https://console.twilio.com) |
| **Firebase (FCM)** | Push notifications | `FCM_PROJECT_ID`, `FCM_CLIENT_EMAIL`, `FCM_PRIVATE_KEY` | [Firebase Console](https://console.firebase.google.com) > Project Settings > Service Accounts |
| **OpenSearch** | Message full-text search | `OPENSEARCH_ENDPOINT`, `OPENSEARCH_REGION` | [OpenSearch Console](https://console.aws.amazon.com/aos/) |

### Tier 3 — Optional enhancements

| Service | What for | Keys needed | Where to get them |
|---------|----------|-------------|-------------------|
| **Have I Been Pwned** | Password breach checking | `HIBP_API_KEY` | [HIBP API Key](https://haveibeenpwned.com/API/Key) ($3.50/mo) |

---

## AWS Setup

### Option A: DynamoDB Local (no AWS account needed)

For local development without a real AWS account:

```bash
# Run DynamoDB Local in Docker
docker run -d -p 8001:8000 --name dynamodb-local amazon/dynamodb-local

# Set in your .env
AWS_ACCESS_KEY_ID=fakeMyKeyId
AWS_SECRET_ACCESS_KEY=fakeSecretAccessKey
```

> **Note**: The backend uses `boto3` which will need an endpoint override to
> point to localhost:8001. You may need to set `AWS_ENDPOINT_URL=http://localhost:8001`
> or patch the DynamoDB client in `app/core/aws.py`.

### Option B: Real AWS Account

1. **Create an IAM user** with programmatic access
2. **Attach these policies** (or create a custom one):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem",
        "dynamodb:DeleteItem", "dynamodb:Query", "dynamodb:Scan",
        "dynamodb:BatchGetItem", "dynamodb:BatchWriteItem"
      ],
      "Resource": "arn:aws:dynamodb:*:*:table/*"
    },
    {
      "Effect": "Allow",
      "Action": ["kms:Encrypt", "kms:Decrypt"],
      "Resource": "arn:aws:kms:*:*:key/*"
    },
    {
      "Effect": "Allow",
      "Action": ["ses:SendEmail", "ses:SendRawEmail"],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"],
      "Resource": ["arn:aws:s3:::my-app-*", "arn:aws:s3:::my-app-*/*"]
    }
  ]
}
```

3. **Create DynamoDB tables** — the backend expects these tables (all use on-demand capacity):

| Table Name | Partition Key | Sort Key | GSI |
|------------|--------------|----------|-----|
| `sessions` | `user_sub` (S) | `session_id` (S) | — |
| `totp_devices` | `user_sub` (S) | `device_id` (S) | — |
| `sms_devices` | `user_sub` (S) | `phone_e164` (S) | — |
| `email_devices` | `user_sub` (S) | `email` (S) | — |
| `recovery_codes` | `user_sub` (S) | `code_hash` (S) | — |
| `api_keys` | `pk` (S) | `sk` (S) | `user_sub-index` on `user_sub` |
| `alerts` | `user_sub` (S) | `alert_id` (S) | — |
| `alert_prefs` | `user_sub` (S) | `channel` (S) | — |
| `push_devices` | `user_sub` (S) | `device_id` (S) | — |
| `profiles` | `user_sub` (S) | — | — |
| `addresses` | `user_sub` (S) | `address_id` (S) | — |
| `calendar` | `user_sub` (S) | `event_id` (S) | — |
| `billing` | `pk` (S) | `sk` (S) | — |
| `account_state` | `user_sub` (S) | — | — |
| `purchase_transactions` | `pk` (S) | `sk` (S) | — |
| `purchase_transaction_events` | `pk` (S) | `sk` (S) | — |
| `shopping_cart` | `user_sub` (S) | `item_id` (S) | — |
| `shopping_catalog` | `pk` (S) | `sk` (S) | — |
| `subscriptions` | `pk` (S) | `sk` (S) | — |
| `Conversations` | `pk` (S) | `sk` (S) | — |
| `Participants` | `pk` (S) | `sk` (S) | — |
| `Messages` | `pk` (S) | `sk` (S) | — |
| `UserEvents` | `pk` (S) | `sk` (S) | — |
| `Users` | `pk` (S) | — | — |
| `UserPresence` | `pk` (S) | — | — |

> Enable TTL on `ttl_epoch` attribute for: sessions, alerts, api_keys, recovery_codes

4. **Create KMS key**:
```bash
aws kms create-key --description "App encryption key"
# Note the KeyId from the output → set KMS_KEY_ID in .env
```

---

## Stripe Setup

1. Go to [Stripe Dashboard](https://dashboard.stripe.com/apikeys)
2. Copy your **test mode** keys:
   - `STRIPE_SECRET_KEY` = Secret key (`sk_test_...`)
   - `STRIPE_PUBLISHABLE_KEY` = Publishable key (`pk_test_...`)
3. For webhooks:
   - Go to Developers > Webhooks > Add endpoint
   - URL: `https://yourdomain.com/api/stripe/webhook`
   - Events: `payment_intent.succeeded`, `payment_intent.payment_failed`, `customer.subscription.*`
   - Copy the signing secret → `STRIPE_WEBHOOK_SECRET`

For local webhook testing:
```bash
# Install Stripe CLI: https://stripe.com/docs/stripe-cli
stripe listen --forward-to localhost:8000/api/stripe/webhook
# It prints a webhook signing secret — use that for STRIPE_WEBHOOK_SECRET
```

---

## PayPal Setup

1. Go to [PayPal Developer Dashboard](https://developer.paypal.com/dashboard/applications/sandbox)
2. Create a **Sandbox** app
3. Copy: `PAYPAL_CLIENT_ID`, `PAYPAL_CLIENT_SECRET`
4. For subscriptions, create billing plans and map them:
   ```
   PAYPAL_PLAN_MAP={"monthly":"P-XXXXX","yearly":"P-YYYYY"}
   ```
5. Set up a webhook endpoint at `/api/paypal/webhook`

---

## Twilio Setup (SMS MFA)

1. Go to [Twilio Console](https://console.twilio.com)
2. Copy `TWILIO_ACCOUNT_SID` and `TWILIO_AUTH_TOKEN` from the dashboard
3. Go to **Verify** > **Services** > Create a new service
4. Copy the Service SID → `TWILIO_VERIFY_SERVICE_SID`

---

## Firebase Push Notifications Setup

1. Go to [Firebase Console](https://console.firebase.google.com)
2. Create a project (or select existing)
3. Go to **Project Settings** > **Service Accounts**
4. Click **Generate new private key** — downloads a JSON file
5. From that JSON:
   - `FCM_PROJECT_ID` = `project_id`
   - `FCM_CLIENT_EMAIL` = `client_email`
   - `FCM_PRIVATE_KEY` = `private_key` (keep the `\n` escapes)
6. Set `PUSH_ENABLED=1` and `FCM_ENABLED=1` in `.env`

---

## Cognito Setup (Production Auth)

1. Go to [Cognito Console](https://console.aws.amazon.com/cognito/)
2. Create a **User Pool**:
   - Sign-in: Email + password
   - MFA: Optional (the app has its own MFA layer)
   - App client: Create one, note the Client ID
3. Set in `.env`:
   ```
   COGNITO_USER_POOL_ID=us-east-1_XXXXXXXXX
   COGNITO_APP_CLIENT_ID=xxxxxxxxxxxxxxxxxxxxxxxxxx
   COGNITO_REGION=us-east-1
   DEV_MODE=0
   ```

---

## Running in Production

### Environment differences from dev

| Setting | Dev | Production |
|---------|-----|------------|
| `DEV_MODE` | `1` | `0` |
| `UI_COOKIE_SECURE` | `0` | `1` |
| `UI_COOKIE_SAMESITE` | `lax` | `strict` |
| `APP_ENV` | `development` | `production` |
| CORS `allow_origins` | `*` | Your domain only |

### Build the frontend

```bash
cd frontend
npm run build    # outputs to frontend/dist/
```

### Run the backend

```bash
# Production with gunicorn + uvicorn workers
pip install gunicorn
gunicorn app.main:create_app \
  --worker-class uvicorn.workers.UvicornWorker \
  --workers 4 \
  --bind 0.0.0.0:8000 \
  --factory
```

### Serve frontend static files

Option A: Let FastAPI serve them (already configured — `app/static/`)
```bash
cp -r frontend/dist/* app/static/
```

Option B: Use nginx/CloudFront to serve `frontend/dist/` and proxy API routes to the backend

---

## Feature Flags Summary

All optional features are **disabled by default**. Enable them by setting the
corresponding environment variable:

| Feature | Flag | Dependencies |
|---------|------|--------------|
| Cognito JWT auth | `DEV_MODE=0` + Cognito vars | AWS Cognito |
| Email MFA | `SES_FROM_EMAIL` (non-empty) | AWS SES |
| SMS MFA | `TWILIO_ACCOUNT_SID` (non-empty) | Twilio |
| Push notifications | `PUSH_ENABLED=1`, `FCM_ENABLED=1` | Firebase |
| Email alerts | `ALERTS_EMAIL_ENABLED=1` | AWS SES |
| SMS alerts | `ALERTS_SMS_ENABLED=1` | Twilio |
| Webhook alerts | `ALERTS_WEBHOOK_ENABLED=1` | Any HTTP endpoint |
| Password breach check | `HIBP_ENABLED=1` | HIBP API key |
| Magic links | `MAGIC_LINK_ENABLED=1` | AWS SES |
| Stripe payments | `STRIPE_SECRET_KEY` (non-empty) | Stripe |
| PayPal payments | `PAYPAL_CLIENT_ID` (non-empty) | PayPal |
| CCBill payments | `CCBILL_FRONTEND_CLIENT_ID` (non-empty) | CCBill |
| Billing reconciliation | `BILLING_RECONCILE_ENABLED=true` | Stripe/PayPal |
| Billing dunning | `BILLING_DUNNING_ENABLED=true` | Stripe/PayPal |
| File manager purge | `FILEMGR_PURGE_ENABLED=true` | AWS S3 |
| Prometheus metrics | `APP_ENV=production` | — |
| WebAuthn/Passkeys | `WEBAUTHN_RP_ID` (non-empty) | — |

---

## Minimal .env for Local Testing

To get the app running locally with the **least setup possible**:

```bash
# Absolute minimum — backend starts, frontend proxies to it
DEV_MODE=1
UI_ACCESS_TOKEN_SECRET=local-dev-secret-change-in-prod
WS_TOKEN_SECRET=local-ws-secret
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=fakeMyKeyId
AWS_SECRET_ACCESS_KEY=fakeSecretAccessKey

# Optional: allow UI login with dev credentials
DEV_TEST_USER=test-user-1
DEV_TEST_PASSWORD=change-me
```

> This boots the app in dev mode. Most API calls will fail with DynamoDB
> connection errors unless you either run DynamoDB Local or have real AWS
> credentials. The **frontend UI is fully navigable** regardless — it
> gracefully handles API errors with toast notifications.

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `SyntaxError` on startup | Run `python -c "from app.main import create_app; create_app()"` to see the error |
| `pip install` fails on `cryptography` | Use `pip install --ignore-installed -r requirements.txt` |
| Frontend can't reach backend | Check Vite proxy config in `frontend/vite.config.ts` — both must be running |
| 401 on every request | Ensure `DEV_MODE=1` or configure Cognito. In dev mode, send `Authorization: Bearer test-user-1` |
| DynamoDB `ResourceNotFoundException` | Table doesn't exist yet — create it (see AWS Setup above) |
| Port already in use | `./start.sh stop` or `lsof -ti :8000 | xargs kill` |
