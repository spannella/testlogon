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

**Instance auto-restart policy + lifecycle timeline (INFRA-008 / GAP-0230, GAP-0231)**: Both live in `app/services/instance_monitoring.py` + its router. (1) Restart policy: EC2/K8s instance items carry `auto_restart_enabled` / `max_restarts` / `restart_count` / `last_restart_at`; `update_restart_policy()` writes them; `PATCH /ui/compute/monitoring/instances/{id}/restart-policy` exposes it. `_check_restart_policy()` runs from `ingest_datapoint` only when a datapoint is `critical` AND the global flag `S.instance_monitoring_auto_restart_enabled` (env `INSTANCE_MONITORING_AUTO_RESTART_ENABLED`, default **false**) is on AND the per-instance flag is on; it restarts via the launchers (EC2 = stop+start, K8s = terminate+launch — honours the mock paths) and enforces `max_restarts`. (2) Timeline: `record_timeline_event()` writes `SK=TIMELINE#{resource_id}#{ts:010d}#{event_id}` into the resource's OWN table (`ec2_instances`/`k8s_pods`, PK=`user_sub`) — sparse to the status/created_at GSIs, no schema change. Best-effort (swallows exceptions). Wired into EC2 launch/stop/start/terminate/reboot + idle auto-terminate, and K8s launch/terminate + TTL-expire. `GET /ui/compute/monitoring/instances/{id}/timeline` returns events newest-first. `resolve_owned_resource()` resolves an id as EC2 (`INSTANCE#`) first, then K8s (`POD#`). Both launchers call `record_timeline_event` via a lazy-import `_record_timeline` helper (avoids circular import, since instance_monitoring imports ec2_launcher). Tests: `tests/test_gap_0230_0231_instance_monitoring.py`.

**Google Drive OAuth state + token exchange (INTEG-001 / GAP-0241, GAP-0242)**: Both fixes live in `app/routers/google_drive_integration.py`. The router does NOT reimplement OAuth — the real path delegates to the shared, tested service `app/services/provider_oauth.py` (same code `app/routers/projects.py` uses): `build_google_oauth_start(user_sub)` (mints a single-use, HMAC-signed, DDB-backed state on `T.projects` + full Google auth URL) for `/connect`, and `complete_google_oauth_callback(user_sub, code=, state=)` (verifies state → POSTs code to `S.google_oauth_token_url` → stores access_token + KMS-encrypted refresh_token + `expires_at` via `upsert_provider_credential`) for `/callback`. The callback runs the (sync) service in `asyncio.to_thread`. The dev/mock path uses local stateless HMAC helpers `_sign_mock_oauth_state` / `_verify_mock_oauth_state` (user_sub|ts|nonce|HMAC, same secret resolver as the service: `google_oauth_state_signing_secret` → `ui_access_token_secret` fallback) so the predictable `state=mock` literal is gone and the mock callback rejects missing/wrong-user/expired/tampered state — keeping the security check identical across envs (SECOPS-007). The frontend `FilesPage` already reads `code`+`state` from the redirect URL and passes both to the callback. Tests: `tests/test_gap_0241_0242_google_drive_oauth.py` (offline; mock-path tests are pure HMAC, real-path uses moto-backed `T.projects` via `object.__setattr__` with `requests.post`/KMS/audit patched). NOTE: `consume_google_oauth_state`'s single-use conditional (`attribute_not_exists(consumed_at)`) fails against a stored `None`/NULL `consumed_at` in both moto and real DynamoDB — tests mock `consume_google_oauth_state` (as `tests/test_provider_oauth.py` does) rather than re-testing that conditional.

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

**SSH `stored_key` auth + key-manager audit (GAP-0220 + GAP-0221)**: The Browser SSH terminal (`app/routers/browser_ssh_terminal.py`) accepts `authType: "stored_key"` in the WebSocket `connect` payload — the browser sends only an opaque `keyId`, never PEM. `_validate_connect_payload` allowlists `{"password","private_key","stored_key"}` and requires `keyId` for stored-key. The connect handler resolves the KMS-encrypted key server-side via `ssh_key_manager.get_decrypted_private_key(user_sub, key_id)`, injects it as `privateKey` and normalises `authType` to `"private_key"` for the existing `ParamikoSshBridge` path (so the PEM never reaches the client; `keyId` is redacted in logs). Unknown/foreign keys → `key_not_found` error (ownership is enforced by the DDB `Key={user_sub, sk}` access pattern). On success, `host_inventory.record_connection` is called for each `associated_hosts` entry. Separately, `app/services/ssh_key_manager.py` now emits audit events (`ssh_key.generate|upload|delete|decrypt|associate|disassociate`) via a fire-and-forget `_audit()` wrapper (local import of `app.services.alerts.audit_event`, mirrors `host_inventory._audit`). Regression test: `tests/test_gap_0220_0221_ssh_stored_key.py` (offline; patches frozen `T.ssh_keys`/`T.host_inventory` via `object.__setattr__`, stubs `kms_encrypt`/`kms_decrypt` + `ParamikoSshBridge`, drives the WS handler on a fresh `asyncio` loop — no real AWS/KMS/network).

**SSH session recording auto-capture + per-host flag (GAP-0233 + GAP-0234, INFRA-010)**: The Browser SSH terminal (`app/routers/browser_ssh_terminal.py`) now auto-records sessions server-side. (1) **GAP-0234** — host records carry a `record_sessions: bool` (added to `host_inventory._item_to_host`, `create_host`, `update_host`, and the `CreateHostIn`/`UpdateHostIn`/`HostOut` Pydantic models; defaults `False` so pre-existing hosts never auto-record). `host_inventory._should_record(user_sub, host_id)` is a never-raising gate: returns `False` for missing `host_id`, when `S.ssh_session_recording_enabled` is off, or on any lookup error. (2) **GAP-0233** — the WS connect handler resolves an optional `host_id` from the `connect` payload (carried through `_validate_connect_payload`), and on a successful connect calls `ssh_session_recording.start_recording(...)` when `_should_record(...) or S.ssh_session_recording_always_record` (new global override env `SSH_SESSION_RECORDING_ALWAYS_RECORD`, default false) AND `S.ssh_session_recording_enabled`. Each non-empty `poll_output()` chunk is appended via `append_events(user_sub, recording_id, [[elapsed, "o", data]])`; the `finally` block calls `stop_recording(...)` (note: finalizer is named `stop_recording`, not `finish_recording`). All three recording calls use lazy imports + `try/except` — a recording failure NEVER interrupts the live terminal. Both paths are DDB-only (SECOPS-007 parity; no mock/real branch). Regression test: `tests/test_gap_0233_0234_ssh_session_recording.py` (offline; moto DynamoDB for `host_inventory` patched onto frozen `T` via `object.__setattr__`, recording-service symbols patched at the source module, `ParamikoSshBridge` stubbed, WS handler driven on a fresh `asyncio.new_event_loop()` — no real AWS/network).

**Multi-hop SSH bastion bridge + chain resolution (GAP-0235 + GAP-0236, INFRA-011)**: `app/services/ssh_bastion.py` can now actually *connect* through stored multi-hop bastion paths (previously it only emitted ProxyJump/ssh_config text via `resolve_path`). (1) **GAP-0236** — `resolve_connection_chain(user_sub, path_id, *, include_keys=True)` resolves a path into an ordered hop list (outermost bastion → target) where each keyed hop is augmented with a decrypted `private_key_pem` via `ssh_key_manager.get_decrypted_private_key` (local import, avoids circular dep). `include_keys=False` returns topology only (no KMS calls) for audit/admin callers. SECURITY: the returned dicts hold plaintext PEM and are server-internal only — never serialise to the API/browser. (2) **GAP-0235** — `MultiHopSshBridge` tunnels through each hop using Paramiko `direct-tcpip` channel forwarding: hop 0 is a direct `client.connect`; every subsequent hop opens a `direct-tcpip` channel through the *previous* hop's transport, wraps it in a fresh `paramiko.Transport`, `start_client()` + `auth_publickey`/`auth_password`, then the final transport gets an interactive shell. Public surface (`connect`/`poll_output`/`send_input`/`resize`/`close`) mirrors `ParamikoSshBridge` so it's drop-in for the WS handler. `build_multihop_bridge(user_sub, path_id, cols, rows)` is the factory that wires `resolve_connection_chain` → bridge. Errors raise `BastionConnectError(code, message)` (mirrors `BrowserSshError`); chains < 2 hops are rejected (use the single-hop `ParamikoSshBridge` instead). NOTE: per task assignment the bridge lives in `ssh_bastion.py` (one owner for the file), not in `browser_ssh_terminal.py` as the writeup originally sketched. Pure Paramiko, no AWS/mock branch — KMS decryption goes through the existing `app/core/crypto.kms_decrypt` abstraction which already handles dev (mock KMS) vs prod transparently (SECOPS-007 parity). Regression test: `tests/test_gap_0235_0236_ssh_bastion_multihop.py` (offline; moto DynamoDB for `ssh_bastion_paths` patched onto frozen `T` via `object.__setattr__`, `get_decrypted_private_key` patched at source, `paramiko` fully stubbed via `patch.dict(sys.modules, ...)` recording `open_channel`/auth/shell calls — NO real SSH/AWS/network).

**EC2 host-inventory lifecycle (GAP-0223 + GAP-0224)**: `app/services/ec2_launcher.py` now auto-registers and de-registers EC2 instances in the host inventory (INFRA-001/003 integration). (1) **GAP-0223** — after the SG-association block in `launch_instance`, if `result["public_ip"]` is non-empty it calls `host_inventory.create_host(user_sub, label=f"{label} (EC2)", hostname=public_ip, port, protocol, username, group="EC2 Instances", os_type, source="ec2_auto")`, back-writes the returned `host_id` to the DDB instance record via `update_item` and onto the in-memory `item`. Protocol/port derive from `AMIS[ami_id]["os_type"]` (windows → rdp/3389, else ssh/22). (2) **GAP-0224** — `terminate_instance` reads `item.get("host_id")` and, when set, first calls `ssh_key_manager.disassociate_key_from_host` (if `ssh_key_id` set) then `host_inventory.delete_host`; the idle-checker auto-terminate path inherits this since it calls `terminate_instance`. Both blocks are wrapped in `try/except` (registration/cleanup failure must NOT roll back launch/termination) and run in BOTH mock and real modes (the host record lives in DDB regardless of `S.ec2_mock_enabled` — SECOPS-007 parity; the mock path is otherwise unchanged). Note `host_inventory.list_hosts` returns `{"hosts": [...], "count", "cursor"}`, not a plain list. Regression test: `tests/test_gap_0223_0224_ec2_host_inventory.py` (offline; moto DynamoDB for `ec2_instances`+`host_inventory` tables patched onto both modules' `T` via a shared `SimpleNamespace`, EC2 client is a `MagicMock` — never real AWS; frozen `S` flipped with `object.__setattr__`).

**K8s pod host-inventory lifecycle (GAP-0226 + GAP-0227)**: `app/services/k8s_launcher.py` now auto-registers/de-registers K8s pods in the host inventory (mirrors the EC2 fix above; INFRA-001/004). (1) **GAP-0226** — after `T.k8s_pods.put_item`, `launch_pod` calls `host_inventory.create_host(user_sub, label=f"{label} (K8s)", hostname=result["service_hostname"], port=22, protocol="ssh", username=image_info["username"], group="K8s Containers", os_type, source="k8s_auto")`, back-writes the returned `host_id` to the pod DDB record via `update_item` and onto the in-memory `item` (was always `""` before). (2) **GAP-0227** — `terminate_pod` reads `item.get("host_id")` and, when non-empty, calls `host_inventory.delete_host(user_sub, host_id)`; the TTL checker (`check_expired_pods`) inherits this since it delegates to `terminate_pod`. Both blocks are `try/except` (registration/cleanup failure must NOT roll back launch/termination) and run in BOTH mock and real K8s modes — the host record lives in DDB regardless of `S.k8s_mock_enabled` (SECOPS-007 parity; the mock K8s path is otherwise unchanged, no `kubernetes` import added). `create_host`/`delete_host` are imported at module level so tests can patch `k8s_launcher.create_host`/`delete_host`. `delete_host` returns `False` (never raises `HostNotFound`) for an unknown host, so a broad `except` suffices. Regression test: `tests/test_gap_0226_0227_k8s_host_inventory.py` (offline; moto DynamoDB for `k8s_pods`+`host_inventory` patched onto both modules' `T` via a shared `SimpleNamespace`; stays on the dev mock K8s path so no fake `kubernetes` module needed; frozen `S` flipped with `object.__setattr__`).

**Compute auto-billing timer wired (GAP-0228)**: `app/services/compute_billing.py` now has `run_compute_billing_timer()` (loop) + `start_compute_billing_timer_task()` (gated on `S.compute_billing_enabled`), registered in `app/main.py` next to `start_k8s_ttl_checker_task`. `_tick_all_running_resources()` scans all running EC2 (`sk=INSTANCE#`) + K8s pods (`sk=POD#`) system-wide, calls the existing `record_billing_tick` per resource (no duplicated billing math), advances a per-resource `last_billed_at`, and auto-terminates on `InsufficientBalanceError`. Interval = `S.compute_billing_poll_interval` (300s). Regression: `tests/test_compute_billing_timer_gap0228.py` (offline; scan/record helpers monkeypatched, `now_ts` patched, frozen `S` via `object.__setattr__`; startup-registration asserted against `create_app().router.on_startup`).

**KYC template-signature endpoints + multi-packet case shape (GAP-0262 + GAP-0264, KYC-007)**: `app/routers/kyc_cases.py` now exposes the five template/witness endpoints wired to the GAP-0261 service singleton `kyc_signature_template_service` (`GET /v1/kyc/cases/templates` — declared **before** `/{case_id}` so the literal `templates` segment isn't captured as a path param; `POST /{case_id}/signature-templates/create-packets`; `GET /{case_id}/signature-templates/status`; `GET /{case_id}/signature-templates/version-check`; `POST /admin/cases/{case_id}/add-witness` — admin/root only, high-risk cases only). (GAP-0264) `case["signature"]` now carries an additive `template_packets: [{template_type, packet_id, version}]` list alongside the legacy scalar `packet_id`. `create-packets` does a read-merge-write of the whole `signature` map (since `update_case_links` replaces it wholesale) deduped by `template_type`, so repeated calls never clobber earlier packets. `_signature_status_for_case()` is backward-compatible: legacy single-`packet_id` cases take the unchanged path (now also returns `template_packets: []`); cases with `template_packets` and no `packet_id` gate submission on **every** template packet being `completed` with a `ready` final PDF. All paths are DDB-backed via the existing packet-store primitives (moto in dev, real in prod, gated by `SIGNATURE_PDF_ENABLED`) — same code path both ways, no AWS divergence (SECOPS-007 parity). Regression test: `tests/test_gap_0262_0264_kyc_template_endpoints.py` (offline/hermetic; NO moto/@mock_aws — patches packet-store + `STORE` + `get_packet`/`get_packet_artifact`/`list_packet_signers`/`audit_event` on the router namespace and calls the route handlers directly; frozen objects not relied upon here since collaborators are patched, not table handles).

**KYC risk-scoring escalation + submission hook (GAP-0265 + GAP-0266, KYC-008)**: (GAP-0265) `_apply_auto_action` in `app/services/kyc_risk_scoring.py` now persists the escalation marker for critical-tier cases instead of only logging. New `KycCaseStore.escalate_case(case_id, score, reason, actor_sub="system_auto_escalate")` in `app/services/kyc_cases.py` writes `review.escalated`/`review.escalation_reason`/`review.escalated_at`/`review.escalated_by` to the case META via a conditional `update_item` (only `submitted`/`under_review`/`needs_more_info` statuses; **no `version` bump** — it's an admin annotation, not a versioned state change; terminal/decided cases are a no-op). The branch is gated by the **new** `S.kyc_risk_auto_escalate_enabled` setting (`KYC_RISK_AUTO_ESCALATE_ENABLED`, default `true`, symmetric with the existing `kyc_risk_auto_approve_enabled`) and emits `audit_event("kyc_auto_escalated", "system_auto_escalate", None, ...)` to `T.alerts`. (GAP-0266) `submit_kyc_case` in `app/routers/kyc_cases.py` now fires `KycRiskScoringService().compute_score(case_id=..., user_sub=..., trigger="submission")` after the existing KYC-006 sanctions-screening hook (best-effort `try/except`, never blocks submission — mirrors the screening hook). The screening-before-scoring ordering is already satisfied (the screening hook runs first), so the `screening_result` factor reflects the fresh summary. Same DDB code path dev (moto) + prod (SECOPS-007 parity). Regression test: `tests/test_gap_0265_0266_kyc_risk_scoring.py` (offline/hermetic; moto in-memory tables with the exact frozen `T.kyc_cases`/`T.kyc_risk_scores`/`T.users` handles monkeypatched via `object.__setattr__` and restored on cleanup; frozen `S` flag toggled via `object.__setattr__`; service/store instances bound to the moto tables; router handler called directly with stubbed deps).

**KYC admin-decision webhook events (GAP-0272 + GAP-0273, KYC-011)**: The admin-decision transitions in `app/services/kyc_cases.py` now dispatch their notification events (previously only `submit_case` did). (GAP-0272) `apply_admin_decision()` calls `_emit_kyc_event_safe(event="kyc.case.approved" if target_status=="approved" else "kyc.case.rejected", user_sub=existing["user_sub"], case_id, decision, reason_codes, note, decided_at, admin_sub)`. (GAP-0273) `request_more_info()` calls `_emit_kyc_event_safe(event="kyc.case.needs_info", user_sub=existing["user_sub"], case_id, requested_items=review["requested_items"], note, requested_by, requested_at)`. Both emits are placed **after** the successful `update_item` try/except and **before** `return self.get_case(case_id)`, so the idempotent early-return paths (replay with same hash) do NOT re-emit. Best-effort: `_emit_kyc_event_safe` swallows all exceptions, so a notification failure never blocks the state transition. All three event types are registered in `WEBHOOK_EVENT_TYPES_V2` (`app/services/webhook_service.py:147-150`) and have alert titles + email subjects in `app/services/kyc_webhooks.py`; `emit_kyc_event` flattens list payloads (`requested_items`, `reason_codes`) to comma-joined strings. Dev/prod parity (SECOPS-007): webhook dispatch is a no-op in dev with no registered endpoints, in-app alert writes to DDB local — no AWS divergence. Regression test: `tests/test_gap_0272_0273_kyc_decision_events.py` (offline/hermetic; injects a `_FakeTable` into `KycCaseStore(_table=...)` — no moto/@mock_aws, no real AWS; spies the emit by monkeypatching the module-level `_emit_kyc_event_safe`; verifies the right event fires per transition and that idempotent replays emit only once).

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
