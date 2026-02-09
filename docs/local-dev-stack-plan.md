# Local Dev Stack: 10-Ticket Plan

This plan sets up a fully local development stack with local DynamoDB, Cognito, S3, and a mock Stripe flow. Each ticket is scoped to be independently shippable and includes acceptance criteria.

## Ticket 1: Local stack bootstrap (Docker Compose + env template)
**Goal:** Provide a single command to start the local infra stack.

**Scope**
- Add `docker-compose.local.yml` with services for DynamoDB Local, LocalStack (S3 + Cognito), and Stripe mock (or Stripe CLI if preferred).
- Add `.env.local.example` with local service endpoints and credentials.
- Add `scripts/local-stack-up.sh` + `scripts/local-stack-down.sh` wrappers.

**Acceptance criteria**
- Running `scripts/local-stack-up.sh` starts all services.
- `scripts/local-stack-down.sh` stops and removes containers.
- `.env.local.example` documents required env vars for local stack.

## Ticket 2: Shared AWS client factory w/ endpoint overrides
**Goal:** Centralize AWS client creation with local endpoint support.

**Scope**
- Add a module (e.g., `app/core/aws_clients.py`) exposing `ddb_resource()`, `s3_client()`, `cognito_client()`, `kms_client()`, and `sqs_client()`.
- Support `AWS_ENDPOINT_URL` (global) and per-service overrides (`DDB_ENDPOINT_URL`, `S3_ENDPOINT_URL`, `COGNITO_ENDPOINT_URL`).
- Add `S3_USE_PATH_STYLE` support for LocalStack/MinIO.

**Acceptance criteria**
- All AWS clients can target local endpoints when env vars are set.
- No production endpoint changes when overrides are absent.

## Ticket 3: DynamoDB Local wiring
**Goal:** Use DynamoDB Local for all DynamoDB access in dev.

**Scope**
- Update `app/core/aws.py` to use the shared client factory and local endpoint overrides.
- Ensure all DynamoDB resources (`ddb.Table(...)`) in routers/services use the updated `ddb` resource.

**Acceptance criteria**
- With `DDB_ENDPOINT_URL` set, all DynamoDB operations target local.
- Existing production behavior is unchanged without overrides.

## Ticket 4: Local DynamoDB table bootstrap
**Goal:** Automate creation of all required DynamoDB tables in local dev.

**Scope**
- Add `scripts/local-ddb-init.py` to create tables from a declarative list.
- Include required tables from `docs/dynamodb.md` plus optional tables referenced in code (billing, file manager, messaging, etc.).
- Add `scripts/local-ddb-seed.py` to insert minimal seed data for the UI.

**Acceptance criteria**
- Running the init script creates all tables in DynamoDB Local.
- Seed script inserts sample data without errors.

## Ticket 5: S3 local wiring (uploads + presign)
**Goal:** Use local S3 for file uploads/presigned URLs.

**Scope**
- Update S3 clients in `messaging`, `newsfeed`, and `filemanager` to use the shared S3 client factory.
- Ensure presigned URLs are generated correctly against local endpoint with path-style support.
- Document required buckets in `.env.local.example`.

**Acceptance criteria**
- Presigned uploads work end-to-end using local S3.
- File manager endpoints can store and retrieve objects from local buckets.

## Ticket 6: Local S3 bucket bootstrap
**Goal:** Automatically create required S3 buckets in local dev.

**Scope**
- Add `scripts/local-s3-init.py` to create and configure buckets (file manager bucket, uploads bucket, chat images bucket).
- Make `local-stack-up.sh` call this script after containers are healthy.

**Acceptance criteria**
- Required S3 buckets exist after running the bootstrap.
- Upload flows succeed without manual bucket creation.

## Ticket 7: Local Cognito wiring (auth + JWKS)
**Goal:** Support local Cognito issuer/JWKS for JWT validation.

**Scope**
- Add settings for `COGNITO_ISSUER_URL` and `COGNITO_JWKS_URL` overrides.
- Update `app/auth/deps.py` to use overrides when present.
- Update `app/services/cognito.py` to use `COGNITO_ENDPOINT_URL` for local IDP.

**Acceptance criteria**
- Local JWT validation works with local Cognito JWKS.
- Production Cognito flow remains unchanged without overrides.

## Ticket 8: Local Cognito bootstrap (user pool + app client)
**Goal:** Create local Cognito resources automatically.

**Scope**
- Add `scripts/local-cognito-init.py` to create a user pool and app client in LocalStack.
- Output configuration to `.env.local` (pool id, client id, issuer/JWKS URLs).

**Acceptance criteria**
- Local Cognito pool + client exist after init script.
- `.env.local` includes required Cognito configuration.

## Ticket 9: Stripe mock integration
**Goal:** Run Stripe flows locally without external Stripe dependency.

**Scope**
- Add `stripe-mock` (or Stripe CLI) to the local compose stack.
- Document test keys + webhook signing secret in `.env.local.example`.
- Add webhook forwarding or configure mock to hit `/api/stripe/webhook`.

**Acceptance criteria**
- `GET /api/billing/config` works with local Stripe keys.
- Webhooks can be delivered locally and verified.

## Ticket 10: Local dev playbook + QA checklist
**Goal:** Provide a single source of truth for running and validating the local stack.

**Scope**
- Add `docs/local-dev-stack.md` with step-by-step instructions.
- Include a QA checklist: start stack, init tables/buckets, seed data, create user, validate uploads, run billing flow.

**Acceptance criteria**
- Developer can follow the doc to run the full stack in <15 minutes.
- QA checklist covers each local service (DDB, Cognito, S3, Stripe).
