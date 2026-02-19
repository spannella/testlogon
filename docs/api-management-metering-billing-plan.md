# API Management Metering, Limits, and Billing Plan

## Objective
Extend the existing metering and billing model used by File Manager to API Management so we can:
- meter every API call,
- apply limits at multiple levels,
- bill based on per-endpoint pricing,
- and let users set stricter self-imposed limits per API key.

---

## Product outcomes

### Core outcomes
- Every authenticated API call is captured as a usage event with endpoint-level attribution.
- Usage is visible to end users by:
  - account,
  - API key,
  - endpoint,
  - billing period.
- Usage limits can be enforced at:
  - plan/account level,
  - API key level,
  - endpoint (operation) level.

### Billing outcomes
- Billing supports per-API-call pricing by endpoint.
- Price changes are versioned and applied by effective date.
- Billable snapshots are immutable after period finalization.
- Usage and invoice line items are auditable from raw events through aggregates.

---

## Metering model

### Metered dimensions
For each API request, record at minimum:
- request count (always 1 per successful or billable request),
- optional compute weight (if certain endpoints are heavier),
- response class (2xx/4xx/5xx),
- latency bucket (for analytics; not billing-critical).

### Metering scope
Track usage across these entities:
- `user_sub` (account owner),
- `api_key_id` (nullable for non-key auth flows),
- `route_id` (canonical endpoint identifier, e.g., `POST:/v1/messages/send`),
- `period_id` (`YYYY-MM`, UTC).

### Billable vs non-billable rules
Define policy rules for whether requests count toward limits and billing:
- Billable by default: successful calls (`2xx`).
- Configurable behavior for `4xx` and `5xx`:
  - recommended: count toward rate/abuse limits,
  - optionally exclude from billing when caused by server-side errors (`5xx`).
- Exclude internal health checks and trusted internal service-to-service calls.

---

## Data architecture

### 1) Event layer (append-only)
Create `api_usage_events` for every metered request:
- `event_id` (uuid)
- `timestamp`
- `period_id`
- `user_sub`
- `api_key_id`
- `route_id`
- `method`
- `path_template`
- `status_code`
- `billable` (bool)
- `request_units` (default 1)
- `pricing_version`
- `request_id` / trace id

Notes:
- Keep events immutable and replay-safe.
- Use deterministic idempotency key from request_id + route_id to avoid double count on retries.

### 2) Aggregate layer
Add period/day aggregates for fast enforcement and UI:

#### A) Account-period totals
`api_usage_period_totals` keyed by `(user_sub, period_id)`:
- `calls_total`
- `billable_calls_total`
- `cost_subtotal_micros`
- `updated_at`

#### B) Account-key-period totals
`api_key_usage_period_totals` keyed by `(user_sub, api_key_id, period_id)`:
- `calls_total`
- `billable_calls_total`
- `cost_subtotal_micros`
- `self_cap_calls` (optional denormalized)
- `updated_at`

#### C) Route breakdown totals
`api_route_usage_period_totals` keyed by `(user_sub, period_id, route_id)`:
- `calls_total`
- `billable_calls_total`
- `unit_price_micros`
- `cost_subtotal_micros`

#### D) Daily series
`api_usage_daily` keyed by `(user_sub, date_utc)` for UI charts and reconciliation.

### 3) Pricing catalog
Create versioned endpoint pricing catalog:
- `pricing_catalog_version`
- `effective_at`
- entries:
  - `route_id`
  - `included_calls` (optional)
  - `price_per_call_micros`
  - optional tiering (`0-1M`, `1M+`, etc.)

When metering an event, stamp the selected `pricing_version` for auditability.

### 4) Billing snapshot layer
`api_billing_usage_snapshots` keyed by `(user_sub, period_id, version)`:
- frozen totals by route and key,
- computed charges,
- status (`draft`, `finalized`, `invoiced`).

---

## Limit and enforcement model

### Limit hierarchy (highest precedence first)
1. **Platform hard safety limits** (global anti-abuse caps)
2. **Plan/account limits** (commercial plan allowances)
3. **User-defined API key self-limits** (must be <= plan/account remaining policy ceiling)

### Types of limits
- Requests per second/minute (rate limiting, burst control)
- Requests per day/month (quota control)
- Spend cap per month (billing protection)
- Per-route call limits (e.g., expensive endpoint caps)

### Enforcement behavior
- Soft warnings at 70/85/95%.
- Hard rejection at 100% for configured caps.
- Clear machine-readable errors, e.g.:
  - `limit_type`
  - `scope` (`account`, `api_key`, `route`)
  - `current`
  - `limit`
  - `reset_at`

### API key self-limits
Allow users to set optional stricter thresholds for each key:
- monthly calls cap,
- monthly spend cap,
- per-route calls cap.

Validation rules:
- self-limit cannot exceed account-level policy max.
- lowering a limit below current usage should be allowed but takes effect as “no more calls this period”.
- changes are fully audited.

---

## API and UI changes

### API key management additions
Extend API key metadata to include optional self-limits:
- `monthly_calls_cap`
- `monthly_spend_cap_micros`
- `route_caps` map (`route_id -> calls_cap`)

New/updated endpoints:
- `PATCH /ui/api_keys/{key_id}/limits`
- `GET /ui/api_keys/{key_id}/usage?period=YYYY-MM`
- `GET /ui/api-usage/summary?period=YYYY-MM`
- `GET /ui/api-usage/routes?period=YYYY-MM`
- `GET /ui/api-usage/keys?period=YYYY-MM`

### End-user UI
Add API Usage & Billing section with:
- total calls vs plan limit,
- estimated cost this period,
- per-endpoint usage/cost table,
- per-key usage table,
- key self-limit editor and threshold alerts.

### Admin UI / ops endpoints
- recompute endpoint usage for period,
- finalize billing period,
- view top accounts/routes by usage,
- view rejected calls by limit type.

---

## Billing design

### Charge computation
For each finalized period:
1. Load frozen usage totals by route.
2. Apply pricing catalog version and tiering.
3. Produce invoice line items by route (and optionally by API key as sub-lines).
4. Store immutable snapshot and invoice references.

### Edge cases
- Mid-period price change: split charges by event-level pricing version.
- Credits/adjustments: attach adjustment records referencing snapshot version.
- Disputes: replay raw events for reconciliation report.

---

## Implementation phases

### Phase 0 — Discovery and contract design
- Define canonical `route_id` mapping for every API route.
- Finalize billable status-code policy.
- Define pricing catalog schema and versioning process.
- Publish API/UX contract for key self-limits.

### Phase 1 — Instrumentation
- Add metering middleware/hook in API request pipeline.
- Emit `api_usage_events` with idempotency safeguards.
- Backfill route mapping for existing logs where possible.

### Phase 2 — Aggregation + read APIs
- Build aggregate writer/consumer and daily rollups.
- Add user-facing usage endpoints.
- Add admin recompute tooling.

### Phase 3 — Enforcement
- Add runtime quota checks in API gateway/app layer.
- Enforce account limits, then API key self-limits.
- Return standardized limit errors and warning headers.

### Phase 4 — Billing integration
- Implement pricing catalog resolution and charge calculator.
- Add period finalization + immutable snapshots.
- Emit invoice line items and reconciliation reports.

### Phase 5 — UI and alerts
- Build API usage dashboard and per-key controls.
- Add alerting channels (email/webhook/in-app) for threshold crossings.

### Phase 6 — Hardening
- Load/perf test at expected request rates.
- Add replay/recompute jobs and drift detection.
- Run shadow billing before production cutover.

---

## Security, compliance, and audit
- Never store raw API key secrets in usage events.
- Use hashed key IDs where external exports are needed.
- Restrict billing/admin mutations to privileged roles.
- Retain raw usage events per policy window (e.g., 24 months).
- Add tamper-evident audit logs for pricing and limit changes.

---

## Observability and SLOs

### Metrics
- `api_usage_events_ingested_total{route_id,status_class}`
- `api_usage_limit_denied_total{scope,limit_type,route_id}`
- `api_usage_cost_micros_total{route_id}`
- `api_usage_aggregation_lag_seconds`
- `api_billing_snapshot_finalize_failures_total`

### Alerts
- ingestion lag above threshold,
- sudden deny-rate spike,
- reconciliation drift between events and aggregates,
- billing finalization failures.

---

## Risks and mitigations
- **High-cardinality dimensions** (route/key explosion) -> cap labels and use canonical route templates.
- **Double counting on retries** -> strict idempotency keys + replay-safe consumers.
- **Unexpected bill shock** -> spend caps, alerts, and self-limit defaults on key creation.
- **Policy confusion** -> explicit docs and machine-readable limit response payloads.

---

## Acceptance criteria
- Metered events exist for >= 99.99% of eligible API calls.
- Per-route and per-key monthly totals reconcile with raw events within agreed tolerance.
- Limits are enforced consistently under concurrency/load tests.
- Billing snapshot to invoice pipeline is deterministic and auditable.
- Users can set and update per-key self-limits and see near-real-time usage/cost.
