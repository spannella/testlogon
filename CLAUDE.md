# CLAUDE.md — Codebase Guide

This file is the authoritative quick-reference for AI assistants and new contributors. Read this first.

---

## What this project is

A full-stack SaaS platform with:
- **Backend**: Python 3.12 / FastAPI, DynamoDB, S3, Cognito (all mocked locally)
- **Frontend**: React 18 + TypeScript + Vite + Tailwind + shadcn/ui
- **Auth**: Cookie-based UI sessions with CSRF protection; Cognito JWT verification for API calls
- **Billing**: Stripe, PayPal, CCBill integrations (all mocked in dev)
- **Features**: Messaging, newsfeed, file manager, calendar, ticketing, questionnaires, signing, subscriptions, e-commerce catalog, admin/root role system, VNC/SSH browser terminals

---

## Quick start (fresh host)

```bash
bash scripts/setup_ubuntu.sh   # one-time: installs Node 20, Java, Python venv, Playwright, generates secrets
just up                        # start dev stack + seed E2E sessions
```

Daily workflow:
```bash
just restart    # clean-wipe + restart + re-seed sessions
just e2e        # run all 1070 Playwright E2E tests
just test       # run pytest unit tests
just status     # check health of all services
```

See `justfile` for all available commands.

---

## Dev stack — services and ports

| Service | Port | Notes |
|---------|------|-------|
| Frontend (Vite) | 3000 | React app; proxies `/api`, `/ui`, `/mock`, `/internal`, etc. to backend |
| Dev Tools UI | 3001 | Standalone React app; no auth needed; proxies `/internal` to backend |
| Backend (uvicorn) | 8000 | FastAPI; `GET /openapi.json` for full API spec, `/docs` for Swagger UI |
| DynamoDB Local | 8001 | Persistent across backend restarts; data in `.local/tools/dynamodb-local/data/` |
| Moto (S3 + Cognito mock) | 4566 | LocalStack-compatible AWS mock |
| Stripe mock | 12111 | stripe-mock binary; off-session PaymentIntents always return `requires_payment_method` |
| Mock KMS | 7999 | `scripts/mock_kms_server.py` |

**Start/stop managed by**: `scripts/dev.sh` (wraps `scripts/local-stack-up.sh` + `scripts/run_local_mock_backend.sh`)

**Backend startup**: Always use `scripts/run_local_mock_backend.sh` — it sources `.env.local` to supply AWS credentials (`AWS_ACCESS_KEY_ID=test`), DDB endpoint, etc. Running `uvicorn` directly will fail with `NoCredentialsError`.

**S3 mock**: moto is started in-process by the FastAPI app at startup (`app/core/dev_s3.py`). There is no separate S3 process — boto3 calls are intercepted at the botocore layer.

---

## Backend structure (`app/`)

```
app/
├── main.py              — FastAPI app factory; registers all routers, middleware, startup tasks
├── models.py            — All Pydantic request/response models (~2000 lines)
├── metrics.py           — Prometheus-style request metrics
├── auth/
│   ├── deps.py          — Auth dependencies: require_ui_session, require_bearer_token, require_root_session
│   └── roles.py         — Role enum (USER, ADMIN, ROOT) + AdminProfile dataclass
├── core/
│   ├── settings.py      — All config via Settings dataclass from env vars; singleton `S`
│   ├── tables.py        — DynamoDB table handles wired from settings
│   ├── aws.py           — boto3 client helpers
│   ├── crypto.py        — HMAC / KMS encrypt-decrypt / WS token helpers
│   ├── cursor.py        — DynamoDB pagination cursor encode/decode
│   ├── normalize.py     — Input normalization (email, phone, CIDR, IP)
│   └── time.py          — `now_ts()` → Unix timestamp int
├── routers/             — One file per feature domain (50+ routers)
└── services/            — Business logic + DynamoDB access (100+ service files)
```

### Router conventions
- All routers are registered in `app/main.py`
- Most endpoints use `Depends(require_ui_session)` for auth — returns `{"user_sub": str, "role": Role, "admin_profile": AdminProfile | None, ...}`
- Admin endpoints use `Depends(require_admin_session)` (requires `role >= ADMIN`)
- Root endpoints use `Depends(require_root_session)` (requires `role == ROOT`)
- Mock/dev endpoints live alongside real ones, gated by `S.dev_mode` or `_mock_enabled()`

### Auth dependency (`app/auth/deps.py`)
The `require_ui_session` dependency supports two auth modes:
1. **Cookie auth** (`ui_session` + `ui_access_token` cookies): Used by the frontend browser. The `ui_access_token` is an HS256 JWT signed with `UI_ACCESS_TOKEN_SECRET` containing `sub`, `role`, and `admin_profile`.
2. **Bearer token auth** (`Authorization: Bearer <token>`): Used by API clients and some E2E tests. Token is a Cognito JWT verified via JWKS.
3. **Dev header fallback**: `X-User-Id` header accepted only when Cognito is not configured AND `dev_mode=True`.

**CSRF**: Cookie-auth non-GET requests require `x-csrf-token: <token>` header matching both the session's stored `csrf_token` and the `ui_csrf` cookie value. Bearer-auth requests skip CSRF.

### DynamoDB patterns
- Table names from `S` settings (e.g., `S.ddb_sessions_table`, `S.alerts_table_name`)
- Table handles via `app/core/tables.py` → `T.sessions`, `T.alerts`, etc.
- All numeric timestamps use `now_ts()` (integer Unix seconds)
- GSI sort keys that are numeric must be declared with `attr_types={"field": "N"}` in `scripts/local-ddb-init.py` — forgetting this causes `ValidationException` at runtime
- Pagination uses cursor encoding from `app/core/cursor.py`

---

## Frontend structure (`frontend/src/`)

```
frontend/src/
├── App.tsx              — React Router routes; lazy-loaded pages
├── main.tsx             — App entry point; React Query client, theme provider
├── api/
│   ├── client.ts        — Axios instance; attaches CSRF cookie header; handles 401 → logout
│   ├── types.ts         — All TypeScript API types (mirrors app/models.py)
│   └── endpoints/       — One file per domain (account.ts, alerts.ts, billing.ts, …)
├── pages/               — Feature pages (one directory per domain)
│   ├── Dashboard.tsx, Login.tsx, Register.tsx, etc.
│   ├── admin/           — Admin role/impersonation management
│   ├── alerts/          — Alert history + preferences
│   ├── billing/         — Stripe/PayPal/CCBill payment methods, wallet, billing history
│   ├── calendar/        — Calendar events + booking
│   ├── contacts/        — Contact management
│   ├── feed/            — Newsfeed posts + comments (markdown/rich text)
│   ├── files/           — File manager
│   ├── messages/        — Messaging (DMs + group chats)
│   ├── projects/        — Project management
│   ├── questionnaires/  — Questionnaire builder + responses
│   ├── remote/          — VNC + SSH browser terminals
│   ├── security/        — MFA devices, API keys, sessions, WebAuthn
│   ├── settings/        — Profile, addresses
│   ├── shop/            — Catalog + shopping cart
│   ├── signing/         — Document signing (PDF)
│   ├── subscriptions/   — Subscription plans + billing
│   └── tickets/         — Support ticket system
├── components/
│   ├── layout/          — AppShell, Header, Sidebar, MobileNav
│   ├── shared/          — Reusable components (dialogs, forms, etc.)
│   └── ui/              — shadcn/ui primitives
└── stores/              — Zustand stores (authStore, impersonationStore, themeStore)
```

### Frontend conventions
- API calls via `api/endpoints/*.ts` using the axios instance in `api/client.ts`
- React Query (`@tanstack/react-query`) for all server state: `useQuery`, `useMutation`, `useInfiniteQuery`
- Forms use React Hook Form + Zod validation
- Components use shadcn/ui primitives (`Button`, `Dialog`, `Card`, etc.) from `components/ui/`
- Vite proxies all `/api`, `/ui`, `/mock`, `/internal`, `/telemetry` paths to `http://localhost:8000`

---

## E2E tests (`frontend/e2e/`)

**Run**: `just e2e` (or `cd frontend && npx playwright test`)
**Config**: `frontend/playwright.config.ts` — 1 worker, 1 retry, Chromium only
**Count**: ~1070 tests across 37 spec files

### Test users (seeded by `e2e_session_setup.py` + `e2e_admin_session_setup.py`)

| Identity | Email | Role |
|----------|-------|------|
| Alice | e2e_alice@test.local | USER |
| Bob | e2e_bob@test.local | USER |
| Root | root.admin@testdev.local | ROOT |
| Charlie (admin) | e2e_charlie@test.local | ADMIN |

Sessions are seeded by writing directly to DynamoDB. **Must re-run after every clean restart** (`just up` and `just restart` do this automatically).

### Key E2E patterns

**Session auth in tests** — inject cookies via `injectAuth(page, identity)`:
```ts
// Sets ui_session, ui_csrf, ui_access_token cookies
await injectAuth(page, "alice");
await page.goto("/messages");
```

**CSRF header for POST requests**:
```ts
// page.request carries cookies, so backend enforces CSRF
await page.request.post("/ui/messaging/conversations", {
  headers: { "x-csrf-token": sessions[identity].csrf_token },
  data: { ... }
});
```

**Bearer-auth requests bypass CSRF** — use the global Playwright `request` fixture (not `page.request`) for Bearer-auth calls:
```ts
test.beforeAll(async ({ browser, request }) => { ... })
// request.post(url, { headers: { Authorization: "Bearer ..." } })
```

**API response shape for messages**: `GET /messaging/conversations/{id}/messages` returns a plain array, NOT `{ messages: [...] }`.

**Triggering React Query refetch from Playwright**:
```ts
await page.evaluate(() => window.dispatchEvent(new Event("online")));
// ConversationView listens for 'online' and calls queryClient.invalidateQueries
```

**Strict mode violations** — `page.getByText(X)` fails if text appears in multiple elements (e.g., sidebar preview + message bubble). Use:
```ts
page.locator("p").filter({ hasText: X })  // scope to message bubbles
```

---

## Pytest unit tests (`tests/`)

**Run**: `just test` (or `.venv/bin/pytest`)
**Config**: `pytest.ini` or `pyproject.toml`

Tests use an in-memory FastAPI test client (`tests/conftest.py`). DynamoDB is mocked via `moto`. Tests do not require the dev stack to be running.

---

## Environment configuration

**Backend env**: `.env.local` (gitignored, created from `.env.local.example` by `setup_ubuntu.sh`)
**Frontend env**: `frontend/.env.local` (gitignored, created from `frontend/.env.local.example`)

Key variables:

| Variable | Purpose |
|----------|---------|
| `UI_ACCESS_TOKEN_SECRET` | HMAC secret for JWT cookie signing — **must be non-empty** |
| `API_KEY_PEPPER` | Secret for API key hashing — **must be non-empty** |
| `DDB_ENDPOINT_URL` | `http://localhost:8001` in dev |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | `test` / `test` in dev (moto accepts any value) |
| `COGNITO_USER_POOL_ID` | Set by `scripts/local-cognito-init.py` at stack startup |
| `DEV_MODE` | `1` enables mock endpoints, dev logging, dev header fallback |

Feature flags (all default to `true` in `.env.local.example`):

| Variable | Feature |
|----------|---------|
| `MESSAGING_ENCRYPTED_MESSAGES_ENABLED` | E2E-encrypted messages |
| `NEWSFEED_MARKDOWN_ENABLED` / `NEWSFEED_RICHTEXT_ENABLED` | Rich newsfeed content |
| `SIGNATURE_PDF_ENABLED` | Document signing |
| `MESSAGING_REPORTING_ENABLED` | Compliance/reporting |

---

## Scripts reference

| Script | Purpose |
|--------|---------|
| `scripts/setup_ubuntu.sh` | First-run host setup (installs everything) |
| `scripts/dev.sh` | Master dev stack control (`start`, `stop`, `restart`, `status`) |
| `scripts/local-stack-up.sh` | Start DynamoDB Local, moto, Stripe mock, KMS mock |
| `scripts/local-stack-down.sh` | Stop background infra processes |
| `scripts/run_local_mock_backend.sh` | Start backend (sources `.env.local`, activates venv) |
| `scripts/local-ddb-init.py` | Create all DynamoDB tables (run once at stack start) |
| `scripts/local-ddb-seed.py` | Seed initial data (optional, `DEV_DDB_SEED=1`) |
| `e2e_session_setup.py` | Seed E2E test sessions for Alice + Bob |
| `e2e_admin_session_setup.py` | Seed E2E sessions for root, alice, bob, charlie_admin, charlie_scoped |
| `scripts/rootctl` | Break-glass root CLI |

---

## Common gotchas

**Cart recovery links + reminder opt-out (FIN-003 / GAP-0190, GAP-0191)**: `app/services/cart_reminders.py` owns both. `generate_recovery_link(user_sub, cart_id)` mints a signed, time-limited (`CART_RECOVERY_LINK_TTL_DAYS`, default 7) HMAC token (same scheme as `mint_ws_token`; secret = `CART_RECOVERY_LINK_SECRET`, falling back to `UI_ACCESS_TOKEN_SECRET`) and returns `{S.public_base_url}/ui/shoppingcart/recover/{token}`. `recover_cart(token)` verifies + consumes it (one-time-use: a `RECOVERY#CONSUMED#{jti}` row is written to `cart_reminder_config` with a conditional put; second use → 400). The public `GET /ui/shoppingcart/recover/{token}` endpoint (no auth) 302-redirects to `/cart?cartId=...&recovered=1`. Opt-out lives in `cart_reminder_config` under `OPTOUT#USER#{sub}` / `META`; `is_user_opted_out`, `get_reminder_preference`, `set_reminder_preference` manage it, and `GET/PUT /ui/shoppingcart/reminders/preferences` (cookie auth) expose it. Both `send_cart_reminder` (legacy, admin sweep + fallback loop) and `_send_stage_reminder` (multi-stage) check opt-out and embed the recovery URL.

**DynamoDB numeric GSI sort keys**: If a GSI sort key is a number (e.g., `created_at`), the `TableDef` in `scripts/local-ddb-init.py` must include `attr_types={"created_at": "N"}`. Missing this causes DynamoDB to store it as String → `ValidationException` when queried with integer values.

**Billing ledger queries use `GSI_LEDGER_DATE` (FIN-013 / GAP-0202)**: The `billing` table has a GSI keyed on `ledger_date` (S) / `sk`. The platform financial dashboard (`app/services/platform_financial_dashboard.py`) queries ledger entries per-day via this index instead of scanning the whole billing table (which also holds `PM#` / `BILLING` rows). New ledger rows must carry `ledger_date` (written by `new_ledger_entry` in `billing_shared.py`) to appear in the index. After adding the GSI in dev, `just restart` recreates the table; in prod it requires an `UpdateTable` + async backfill before the query path is deployed (SECOPS-007 parity — same code/index both envs, no `dev_mode` branch).

**Ledger `provider` attribution (FIN-013 / GAP-0203)**: Provider-originated ledger entries must persist a `provider` field (`stripe` / `paypal` / `ccbill`) or the dashboard provider breakdown buckets them as `"unknown"`. Stripe call sites in `app/routers/billing.py` pass `extra={..., "provider": "stripe"}`; the PayPal wrapper (`app/routers/paypal.py`) and CCBill wrapper (`app/services/billing_ccbill.py`) default a `provider` kwarg onto the item. `extra` is a pass-through onto the persisted DynamoDB item.

**Backend won't start without `.env.local`**: The startup script sources `.env.local` for mock AWS creds. Running `uvicorn` directly causes `NoCredentialsError`.

**Cognito blocks dev-mode header fallback**: When `COGNITO_USER_POOL_ID` is set (which it is in the local stack), the `X-User-Id` dev fallback is disabled. All dev auth goes through either cookie-based sessions or real Cognito JWT tokens.

**`pip install --user` inside a venv**: Ubuntu 24+ rejects `--user` installs when inside a virtualenv. Always use `.venv/bin/pip` directly.

**moto S3 workers**: Run uvicorn with `--workers 1` in dev mode. moto's in-process state is per-process; multiple workers would each have isolated S3 state.

**Audit export worker (ENTERPRISE-004)**: `POST /ui/admin/audit-exports` only writes a `pending` job. `app/services/audit_export_worker.py` (`run_audit_export_worker_loop`, registered via `start_audit_export_worker_task` startup hook in `main.py`, gated by `AUDIT_EXPORT_WORKER_ENABLED`) polls the `AuditExports` table, claims each job via a `status==pending` compare-and-swap, and calls `process_export_job`. `process_export_job` forks on `S.dev_mode` (SECOPS-007 dev/prod parity): dev → `_process_export_inline` (content stored on the DDB item, capped at 500 events); prod (`DEV_MODE=0`) → `_process_export_s3` (streams to S3 via `app.core.aws_clients.s3_client`, writes `s3_key`/`s3_bucket` + HMAC-signed manifest). Both paths run against moto in-process S3 in dev with `DEV_MODE=0`.

**Audit export PDF format (GAP-0209)**: `format=pdf` is accepted by `POST /ui/admin/audit-exports` alongside `csv`/`ndjson`. The PDF is rendered by `_render_audit_pdf` in `app/services/audit_export_pipeline.py` — a self-contained, pure-Python multi-page PDF writer (no `reportlab`/system deps; same dependency-free approach as `app/services/receipts.py`, for SECOPS-007 parity). Layout: cover page (metadata + content SHA-256), sequential row numbers, per-page running SHA-256 footer (tamper-evident), and per-page billing subtotals. Content hash is computed over the canonical NDJSON form so a PDF and NDJSON export of the same events share `file_sha256`. Dev inline path stores the binary base64-encoded under `export_content_b64` (capped at 200 events vs 500 for text) and the download endpoint serves it via a binary-safe `Response(media_type="application/pdf")` — NOT `PlainTextResponse` (which would UTF-8 re-encode and corrupt the bytes). Prod path uploads PDF bytes to S3 with `ContentType=application/pdf`.

**Scheduled audit export reports (GAP-0210)**: Recurring exports live in `app/services/audit_export_schedule.py`. Schedule rows reuse the `AuditExports` table (single-table) with partition key value `SCHEDULE#{schedule_id}` (the table's hash attr is `export_id`, NOT `pk` — the writeup said `pk`), `sk=META`, `GSI1PK="SCHEDULES#ACTIVE"`, `GSI1SK=next_run_at` (numeric) on the `schedules-due-index` GSI (declared with `attr_types={"GSI1SK": "N"}` in `scripts/local-ddb-init.py`). CRUD endpoints: `POST/GET /ui/admin/audit-exports/schedules`, `PATCH/DELETE /ui/admin/audit-exports/schedules/{id}` (ROOT only). IMPORTANT: the `/schedules` routes are declared BEFORE `/{export_id}` in the router — FastAPI matches in declaration order, so a dynamic `/{export_id}` first would capture the literal `schedules`. `run_due_schedules()` (driven by `start_audit_export_scheduler_task` startup loop, gated by `AUDIT_EXPORT_SCHEDULER_ENABLED`) queries due schedules, spawns one-off jobs via `create_export_job`, advances `next_run_at` by one cadence, and notifies recipients via `alerts.send_alert_email` (dev logs, prod SES — SECOPS-007 parity). Disabling a schedule moves `GSI1PK` to `SCHEDULES#DISABLED` so the runner never selects it.

**Stripe mock off-session payments**: `stripe-mock` always returns `requires_payment_method` for off-session PaymentIntents. Wallet deposit tests must seed balance directly via DynamoDB, not through the deposit API.

**Conversations list pagination**: `list_conversations` paginates with `Limit=500` per page (up to 2000 total). Test runs accumulate many DMs; always create test DMs via session auth (`page.request`) not Bearer auth — Bearer-auth DMs don't appear in session-auth conversation lists.

**DDB FilterExpression doesn't reduce page size**: DynamoDB fetches up to 1MB *before* applying `FilterExpression`. Any query that filters a sparse attribute (e.g. `status=scheduled` on a Messages table) must loop via `LastEvaluatedKey` — a single `query()` call silently misses items beyond the first page on a busy table.

**`_cognito_available()` must return False in dev mode**: `local-cognito-init.py` sets `COGNITO_APP_CLIENT_ID`, which causes `_cognito_available()` to return `True`. In dev mode this sends registration down the Cognito path, which fails silently and never creates the user record or MFA challenge in DDB. The function now short-circuits to `False` when `S.dev_mode` is `True`.

**Test data accumulates — run `just restart` before a full e2e suite**: Each run adds helpdesk conversations, DM messages, and rate-limit records that are never cleaned up. After many runs the helpdesk queue response grows to 200KB+, which causes browser network errors that hide the Agent Queue UI (sections 50.2–50.4). Run `just restart` to wipe and re-seed before a clean suite run.

**Billing charge paths are gated (GAP-0206 + GAP-0207)**: Every payment-initiation endpoint now runs two guards before touching the provider SDK. (1) **Provider toggle** — `_require_provider_enabled(provider)` (helper in `billing.py`, `paypal.py`, `billing_ccbill.py`, backed by `is_provider_enabled` in `app/services/payment_provider_health.py`) returns **503** when an admin has disabled the provider via `POST /ui/admin/payment-providers/{provider}/toggle`. Providers with no CONFIG row default to enabled. Stripe paths: `pay_balance`, `charge_once`, `create_checkout_session`, `wallet_deposit`; PayPal: `charge_once`; CCBill: `charge_once_endpoint`, `pay_balance_endpoint`, `subscribe_monthly_endpoint`. (2) **Fraud gate** (stripe only) — `_fraud_gate(...)` in `billing.py` (backed by `app/services/fraud_detection.py`) returns **403** when the account is frozen (`is_frozen`, always runs) or when `evaluate_transaction` returns `action="block"`. `create_checkout_session` runs the fraud gate in observe-only mode (`enforce_block=False`) because the real charge settles later via webhook — but it still 403s frozen accounts. Flags: `FRAUD_DETECTION_ENABLED` (default true; false → eval short-circuits to allow), `FRAUD_BLOCK_ENABLED` (default false → block downgraded to flag). Regression test: `tests/test_gap_0206_0207_billing_gates.py` (offline, handlers called directly, no real AWS).

---

## Adding a new feature — checklist

1. **Backend model**: Add Pydantic models to `app/models.py`
2. **Service layer**: Add business logic + DynamoDB access to `app/services/<feature>.py`
3. **Router**: Add endpoints to `app/routers/<feature>.py`, import + register in `app/main.py`
4. **DynamoDB tables**: Add `TableDef` entries to `scripts/local-ddb-init.py` (remember `attr_types` for numeric keys)
5. **Frontend types**: Add TypeScript interfaces to `frontend/src/api/types.ts`
6. **Frontend API**: Add endpoint wrappers to `frontend/src/api/endpoints/<feature>.ts`
7. **Frontend page**: Add page component under `frontend/src/pages/<feature>/`
8. **Route**: Add route to `frontend/src/App.tsx`
9. **E2E tests**: Add spec file to `frontend/e2e/<feature>.spec.ts`
10. **Docs**: Update `docs/file-reference.md`

---

## Key documentation

| Doc | What it covers |
|-----|---------------|
| `docs/architecture.md` | System architecture overview |
| `docs/local-dev-stack.md` | Dev stack deep dive, Docker mode, Keycloak SSO option |
| `docs/file-reference.md` | Full repository file map |
| `docs/dynamodb.md` | DynamoDB table schemas |
| `docs/run-deploy.md` | Running in production |
| `docs/root-admin-login-plan.md` | Root/admin auth system design |
| `docs/security-hardening-runbook.md` | Security configuration |
| `docs/stripe.md` / `docs/paypal.md` / `docs/ccbill.md` | Billing integrations |
