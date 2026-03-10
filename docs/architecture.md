# Architecture Overview

> For a quick-start guide and dev commands, see `CLAUDE.md` at the repo root.

---

## System components

```
┌─────────────────────────────────────────────────────────┐
│  Browser                                                 │
│  React 18 + TypeScript + Vite (port 3000)               │
│  shadcn/ui · React Query · React Hook Form · Zustand     │
└───────────────────────┬─────────────────────────────────┘
                        │  HTTP (Vite proxy in dev)
                        ▼
┌─────────────────────────────────────────────────────────┐
│  FastAPI Backend (port 8000)                             │
│  Python 3.12 · uvicorn · 50+ routers                    │
│  app/main.py → app/routers/* → app/services/*           │
└───┬──────────────┬──────────────┬───────────────────────┘
    │              │              │
    ▼              ▼              ▼
DynamoDB      S3 / Cognito     External services
(port 8001)   (moto, port      (Stripe, PayPal, CCBill,
DynamoDB      4566 in dev)     Twilio, KMS, SES, UPS)
Local in dev                   (all mocked in dev)
```

---

## Backend layers

### 1. Router layer (`app/routers/`)
FastAPI routers expose REST endpoints. Each router:
- Declares HTTP routes with request/response models from `app/models.py`
- Injects auth context via `Depends(require_ui_session)` or `Depends(require_bearer_token)`
- Calls service-layer functions for business logic
- Returns Pydantic model instances (serialized to JSON by FastAPI)

### 2. Service layer (`app/services/`)
Business logic and DynamoDB access. Services:
- Read/write DynamoDB tables via table handles from `app/core/tables.py`
- Are plain Python functions (not classes); no dependency injection
- Handle pagination, TTL, and data transformation
- Background tasks run as asyncio tasks started in `app/main.py` at startup

### 3. Auth layer (`app/auth/`)
Two auth paths:

| Path | Used by | How it works |
|------|---------|-------------|
| **Cookie auth** | Browser frontend | `ui_session` cookie (session ID) + `ui_access_token` cookie (HS256 JWT with `sub`, `role`, `admin_profile`) + CSRF token |
| **Bearer auth** | API clients, some E2E tests | Cognito JWT verified via JWKS; `X-User-Id` header fallback in dev when Cognito not configured |

CSRF enforcement: non-GET requests via cookie auth must include `x-csrf-token` header matching the `ui_csrf` cookie and the stored session `csrf_token`.

### 4. Data layer (DynamoDB)
- Single-region DynamoDB (local mock in dev, real AWS in prod)
- Table definitions in `scripts/local-ddb-init.py` and `docs/dynamodb.md`
- All timestamps are Unix integer seconds (`now_ts()`)
- Pagination via `LastEvaluatedKey` wrapped in cursor encoding (`app/core/cursor.py`)
- GSI sort keys that are numbers require `attr_types={"field": "N"}` in table definitions

---

## Key feature domains

| Domain | Backend routers | Frontend pages |
|--------|----------------|----------------|
| Auth & sessions | `ui_session`, `ui_mfa`, `register`, `root_auth`, `webauthn`, `passwordless`, `password_recovery` | `Login`, `Register`, `security/` |
| MFA | `mfa_devices`, `ui_mfa`, `recovery` | `security/MfaDevices` |
| Messaging | `messaging` | `messages/` |
| Newsfeed | `newsfeed` | `feed/` |
| File manager | `filemanager` | `files/` |
| Billing | `billing`, `billing_ccbill`, `paypal` | `billing/` |
| Commerce | `catalog`, `shoppingcart`, `purchase_history`, `commercial_checkout`, `subscription_server` | `shop/`, `subscriptions/`, `purchases/` |
| Calendar | `calendar` | `calendar/` |
| Signing | `signature_packets` | `signing/` |
| Ticketing | `tickets`, `ticket_spaces` | `tickets/` |
| Questionnaires | `questionnaires` | `questionnaires/` |
| Remote access | `vnc_sessions`, `browser_ssh_terminal` | `remote/` |
| Admin | `admin_roles`, `admin_impersonation`, `admin_moderation`, `admin_entitlements`, `admin_usage` | `admin/` |
| Moderation | `moderation`, `admin_moderation` | — |
| Alerts | `alerts` | `alerts/` |
| API keys | `api_keys`, `api_usage` | `security/ApiKeys` |
| Entitlements | `entitlements`, `admin_entitlements` | — |
| Projects | `projects` | `projects/` |
| Contacts | `contacts` | `contacts/` |
| Dev tools | `internal_devtools` | `devtools/` |

---

## Request flow (typical)

```
1. Browser fetches GET /ui/profile
2. Vite dev proxy forwards to http://localhost:8000/ui/profile
3. FastAPI routes to app/routers/profile.py
4. Depends(require_ui_session) reads ui_access_token cookie → decodes JWT → returns ctx
5. Router calls app/services/profile.get_profile(user_sub)
6. Service queries T.users DynamoDB table
7. Service returns profile dict
8. Router wraps in ProfileOut Pydantic model → FastAPI serializes to JSON
9. Response flows back to React component
10. React Query caches response under key ["profile", user_sub]
```

---

## Billing architecture

- **Stripe**: Setup intents for saving payment methods; PaymentIntents for charges; webhooks at `/api/stripe/webhook` for event reconciliation
- **PayPal**: Setup tokens + order capture; webhooks at `/api/paypal/webhook`
- **CCBill**: Advanced Widget card tokenization; webhooks at `/api/ccbill/webhook`
- **Ledger model**: All transactions recorded as DynamoDB items (`pk=USER#{id}`, `sk=LEDGER#{timestamp}#{id}`) with amount, currency, reason, status
- **Wallet**: Per-user `sk=WALLET` row with `wallet_balance_cents`; credits/debits via `apply_wallet_delta()` with conditional expression guard against overdraft

---

## Real-time features

- **SSE (Server-Sent Events)**: Alert streaming (`GET /api/alerts/stream`); used for push-style alert delivery to connected browsers
- **Scheduled messages**: Background asyncio task (started in `app/main.py`) polls every 30s and promotes due messages to delivered state
- **Background tasks**: Billing reconciliation, dunning, file purge, project reconciliation all run as asyncio tasks

---

## Frontend state management

- **Server state**: React Query (`@tanstack/react-query`) — all API data cached with structured query keys like `["profile", userId]`, `["messages", conversationId]`
- **Client state**: Zustand stores for auth (`isAuthenticated`, `user`), impersonation, and theme
- **Forms**: React Hook Form + Zod schema validation

---

## Observability

- **Metrics**: Prometheus-style via `app/metrics.py` (opt-in, off by default in dev)
- **Dev logs**: Email, SMS, and billing events logged to `.logs/dev/` files in dev mode; readable via internal dev tools UI at `/dev-tools/log-ui`

---

## Deployment topology

```
Internet → HTTPS load balancer / ingress
         → FastAPI (uvicorn, 1+ workers)
         → AWS DynamoDB (real), S3, Cognito, KMS, SES
```

- Run with `scripts/run_prod.sh` (wraps uvicorn with production settings)
- Requires real AWS credentials and all required env vars from `.env.local.example`
- Static frontend assets served by a CDN or from `app/static/` (production build)
- See `docs/run-deploy.md` for full deployment checklist

---

## Questionnaire data model (ERD)

```
Questionnaire (1) ──< QuestionnaireVersion (1) ──< Section (1) ──< Question
                                              ──< ValidationRule
                                              ──< ResponseSession (1) ──< Answer
```

Access patterns:
- List by owner (owner_id index)
- List by status (status index)
- Resolve published schema by slug (published_slug index)
- Monitor in-progress response sessions (status index)

Tables bootstrapped in `scripts/local-ddb-init.py`; migration script at `scripts/migrations/20260302_questionnaire_schema.py`.
