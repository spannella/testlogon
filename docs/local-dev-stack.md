# Local Dev Stack Playbook

This document is the **single source of truth** for running and validating the local provider stack (DynamoDB, LocalStack/Cognito/S3/SES, Stripe mock, CCBill mock, PayPal mock wiring, Twilio local testing, and UPS mock).

## 0) Fast path (mock mode)

For a quick local mock run + validation:

```bash
scripts/run_dev.sh
# optional real backend mode:
# scripts/run_dev.sh --real-backend
```

In another terminal:

```bash
scripts/test_mock_mode.sh
```

## 1) Boot local infrastructure

```bash
scripts/local-stack-up.sh
python3 scripts/local-ddb-init.py
python3 scripts/local-ddb-seed.py
python3 scripts/local-s3-init.py
# optional: run manually if you want to re-generate Cognito ids
python3 scripts/local-cognito-init.py
```

`local-stack-up.sh` now supports **Docker mode** (when Docker is installed) and **host mode** (no Docker). In host mode it starts moto (AWS mock including S3/Cognito/SES), DynamoDB Local, and stripe-mock as local processes and stores logs under `.local/logs/`.

If `.env.local` does not exist, copy from `.env.local.example` and adjust as needed.

`local-stack-up.sh` now automatically runs `scripts/local-cognito-init.py`, which writes Cognito settings to both backend `.env.local` and frontend `frontend/.env.local` (`VITE_COGNITO_*`). It also runs `scripts/local-ses-init.py` to pre-verify `SES_FROM_EMAIL` for local email testing in both Docker (LocalStack) and host mode (moto) by reading values from `.env.local` when shell env vars are not exported.

## 2) Start app

```bash
uvicorn app.main:app --reload
```

## 3) Provider mock defaults (recommended local)

Use these in `.env.local`:

- `CCBILL_MOCK_ENABLED=1`
- `CCBILL_BASE_URL=http://localhost:8000/mock/ccbill`
- `CCBILL_WEBHOOK_VERIFY_MODE=local`
- `CCBILL_WEBHOOK_SIGNATURE_SECRET=local-ccbill-webhook-secret`
- `UPS_BASE_URL=http://localhost:8000/mock/ups`
- `UPS_AUTH_URL=http://localhost:8000/mock/ups/oauth/token`
- `UPS_CLIENT_ID=local_ups_client`
- `UPS_CLIENT_SECRET=local_ups_secret`
- `UPS_WEBHOOK_SECRET=local-ups-webhook-secret`
- `SES_FROM_EMAIL=dev-no-reply@example.com`

## 4) QA checklist

Before manual validation, run:

```bash
scripts/test_mock_mode.sh
```

### Core stack
- [ ] UI loads at `/`
- [ ] DynamoDB tables exist and seeded records are queryable
- [ ] S3 buckets exist and upload endpoints work
- [ ] Cognito pool/client exist and `.env.local` has IDs + issuer/JWKS URLs

### Twilio (local validation)
- [ ] Set `TWILIO_*` vars (or keep disabled)
- [ ] Run SMS MFA enroll/verify flow from UI
- [ ] Confirm audit trail/log entries for send + verify

### CCBill
- [ ] `POST /api/billing/ccbill/frontend-oauth` returns token
- [ ] Save tokenized payment method via UI
- [ ] Run `/api/billing/charge-once` and `/api/billing/subscribe-monthly`
- [ ] Emit webhook: `POST /emit/ccbill-webhook` and verify `/api/ccbill/webhook` reconciliation updates payments/subscriptions

### PayPal
- [ ] `/api/billing/config` shows PayPal config
- [ ] Create PayPal setup/payment flow
- [ ] Trigger/forward PayPal webhook locally and verify billing state transition

### UPS (local mock simulation)
- [ ] `POST /api/ups/quote` succeeds against local UPS mock
- [ ] `POST /api/ups/label` returns a mock tracking number + label URL
- [ ] `POST /emit/ups-tracking-webhook` delivers signed webhook to `/api/ups/tracking/webhook`
- [ ] Confirm webhook event persisted under `UPS_TRACKING` records in billing table

## 5) Example UPS local simulation

1. Quote:
```bash
curl -s -X POST http://localhost:8000/api/ups/quote \
  -H 'content-type: application/json' \
  -H 'cookie: ui_session=<session-cookie>' \
  -d '{"service":"ground","package":{"weight":2.5}}'
```

2. Label:
```bash
curl -s -X POST http://localhost:8000/api/ups/label \
  -H 'content-type: application/json' \
  -H 'cookie: ui_session=<session-cookie>' \
  -d '{"service":"ground","package":{"weight":2.5},"to":{"postal":"10001"}}'
```

3. Tracking webhook emit:
```bash
curl -s -X POST http://localhost:8000/emit/ups-tracking-webhook \
  -H 'content-type: application/json' \
  -d '{"payload":{"tracking_number":"1ZMOCK123","status":"DELIVERED"}}'
```
