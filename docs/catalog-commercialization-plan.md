# Catalog Commercialization & Entitlements Plan

## Objective
Enable the catalog to support three monetization patterns with one shared contract:
1. **Date-range file bundles** (buy once or rent for a limited access window).
2. **External API products** (credit packs, higher rate limits, or scoped API access with limits).
3. **Internal API products** (same monetization primitives for internal services such as Messaging and File Manager).

The design should keep pricing, entitlement state, metering, and enforcement deterministic and auditable.

---

## Product capabilities to add

## 1) Catalog product types
Add explicit `product_type` support in the pricing catalog:
- `file_bundle` (date-range or rule-based set of files)
- `api_package` (credits / limit increases / route access)
- `internal_api_package` (same as `api_package` but for internal service namespaces)

Each product should declare:
- `sku`
- `display_name`
- `billing_model` (`one_time`, `rental`, `subscription`, `credit_pack`)
- `effective_at` / optional `sunset_at`
- pricing fields (`amount`, `currency`, tax metadata)
- entitlement template (what capability is granted and with what limits)

## 2) Entitlement lifecycle
Introduce a unified entitlement state machine:
- `pending_payment` -> `active` -> (`expired` | `revoked` | `consumed`)

Common entitlement fields:
- `entitlement_id`, `user_id`, `sku`, `product_type`
- `starts_at`, `ends_at` (nullable for perpetual purchase)
- `usage_limit` and `usage_consumed` (if metered)
- `scope` (files/date range, API routes, service namespace)
- `source_order_id`, `pricing_catalog_version`
- audit fields (`created_by`, `created_at`, `updated_at`)

## 3) Order + payment abstraction
Keep payment providers behind an order domain:
- `orders` table: checkout intent + totals + state.
- `order_items`: one or more catalog SKUs.
- `payments`: provider events and settlement status.
- Webhook reconciliation to activate/revoke entitlements idempotently.

This allows Stripe/PayPal/CCBill (or future providers) without changing entitlement enforcement.

---

## Use-case design details

## A) File bundle purchase and rental
### Product modeling
`file_bundle` definition includes:
- `selection_type`: `date_range` (initial target), optional future `tag_query`.
- `date_start`, `date_end` (inclusive data window).
- `access_mode`: `purchase` (perpetual) or `rental` (time-bound).
- `rental_duration_hours` (required for rental mode).

### Entitlement behavior
- **Purchase:** no `ends_at`; access remains active while account is active.
- **Rental:** `ends_at = payment_captured_at + rental_duration_hours`.
- Access checks for file download/preview validate both:
  1. file is inside entitlement scope (`date_start/date_end`),
  2. entitlement is currently `active` and within time window.

### Delivery options
- Option 1: stream on-demand from existing file APIs with entitlement guard.
- Option 2: generate signed bundle manifests and expiring download links.

Start with Option 1 for lower complexity, then optimize heavy-volume customers with cached manifests.

## B) External API commercialization
### Product variants
- **Credit pack:** grants `N` credits to a balance bucket.
- **Limit tier:** raises quota/rate limits for period (e.g., monthly).
- **Access tier:** unlocks premium endpoints with optional per-endpoint caps.

### Enforcement model
At request time:
1. Authenticate caller -> resolve account + key.
2. Load active entitlements for `api_package`.
3. Check route access permission.
4. Check limits/credits.
5. Record usage event and consume quota/credits atomically.

### Rating and reconciliation
- Reuse/extend existing API usage metering to tie each usage event to:
  - `entitlement_id`
  - `pricing_catalog_version`
  - computed charge (if pay-as-you-go over entitlement)
- Nightly reconciliation validates: request logs == usage events == billed units.

## C) Internal API commercialization (Messaging / File Manager)
Treat internal services as first-class billable namespaces:
- Namespace examples: `messaging.*`, `filemanager.*`.
- Same entitlement primitives as external APIs.
- Service-specific meters (messages sent, attachments processed, storage operations).

Key difference from external API products is mostly routing/identity context, not billing semantics.

---

## Architecture changes

## Data model additions
Add/extend entities:
- `catalog_products`
- `catalog_product_versions`
- `orders`
- `order_items`
- `payments`
- `entitlements`
- `entitlement_usage_events`

Indexing priorities:
- `entitlements` by `(user_id, status, starts_at, ends_at)`
- `entitlement_usage_events` by `(entitlement_id, timestamp)`
- uniqueness/idempotency keys for webhook events and usage writes.

## Service boundaries
Create a dedicated **Entitlements Service** with methods:
- `grant_entitlement(order_id)`
- `revoke_entitlement(entitlement_id, reason)`
- `check_access(subject, action, resource)`
- `consume_usage(subject, meter, amount, idempotency_key)`

Integrations:
- Billing service for payment settlement
- API gateway/middleware for request-time checks
- File/download handlers for file-scope checks
- Messaging/File Manager route handlers for internal API checks

## Policy engine
Define a policy DSL or structured rules object for consistent checks:
- subject (`user`, `api_key`, `service_account`)
- action (`download_file`, `call_route`, `send_message`)
- resource constraints (date window, route set, namespace)
- limit semantics (hard cap, soft cap, burst rate)

This prevents ad hoc authorization logic across services.

---

## API and contract plan

## New/updated endpoints
- `GET /v1/catalog/products` (include product types + versioning metadata)
- `POST /v1/checkout/session` (SKU(s), quantity, intended account)
- `POST /v1/payments/webhook/{provider}`
- `GET /v1/entitlements` (active + upcoming + expired)
- `POST /v1/entitlements/{id}/revoke` (admin support)
- `GET /v1/usage/entitlements/{id}`

Internal middleware contracts:
- `require_entitlement(action, resource)`
- `consume_entitlement_meter(meter, amount, idempotency_key)`

## Backward compatibility
- Existing plan/quota controls remain valid during migration.
- Add feature flags per product family:
  - `ENABLE_FILE_BUNDLE_ENTITLEMENTS`
  - `ENABLE_API_PACKAGE_ENTITLEMENTS`
  - `ENABLE_INTERNAL_API_PACKAGE_ENTITLEMENTS`

---

## Rollout phases

## Phase 0: Foundations (schema + read path)
- Add catalog product typing/versioning.
- Add entitlement storage and read APIs.
- Add no-op policy middleware in observe mode.

## Phase 1: File bundle MVP
- Implement date-range bundle SKUs.
- Support purchase + rental checkout and activation.
- Enforce on file download/preview endpoints.
- Add entitlement visibility in account UI.

## Phase 2: External API packages
- Implement credit packs and route/limit access tiers.
- Enforce in API gateway.
- Add usage burn-down visibility and low-balance alerts.

## Phase 3: Internal API packages
- Integrate Messaging and File Manager meters.
- Apply namespace-level entitlements.
- Add service-specific operational dashboards.

## Phase 4: Hardening and optimization
- Reconciliation jobs + repair tooling.
- Admin tooling for manual adjustments.
- Pricing experimentation (A/B catalog versions).

---

## Risks and mitigations
- **Double charging / over-consumption:** enforce idempotency keys and atomic usage writes.
- **Inconsistent access checks:** centralize in Entitlements Service + shared middleware.
- **Catalog drift:** immutable versioning + effective-date governance.
- **Customer confusion:** clear entitlement UX (what is active, what expires, what was consumed).
- **Provider webhook failures:** retry + dead-letter queue + replay tooling.

---

## Success metrics
- % of paid products represented by typed catalog entries.
- Entitlement activation latency from successful payment.
- Access-check p95 latency impact at API/file endpoints.
- Reconciliation mismatch rate (target near zero).
- Support tickets related to entitlement confusion (trend down after UX rollout).

---

## Implementation ticket breakdown (suggested)
1. Schema migrations + model updates for catalog product typing and entitlements.
2. Checkout/order/payment orchestration with idempotent webhook handlers.
3. Entitlements Service + policy middleware.
4. File bundle purchase/rental enforcement + tests.
5. External API credits/limits enforcement + tests.
6. Internal API namespace enforcement for Messaging/File Manager + tests.
7. Usage/reconciliation jobs + dashboards.
8. Admin/customer UI surfaces for entitlements and consumption history.
