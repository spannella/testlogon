# API Management Metering & Billing — Implementation Ticket Backlog

This backlog translates `docs/api-management-metering-billing-plan.md` into actionable, dependency-ordered tickets.

---

## Epic A — Contracts, scope, and policy decisions

### AMB-001: Define canonical `route_id` contract for all metered endpoints
**Goal**: Ensure every API call maps deterministically to a billable operation key.

**Scope**
- Create route normalization rules (`METHOD:/path-template`).
- Enumerate excluded routes (health/internal probes).
- Publish mapping examples for dynamic paths.

**Acceptance criteria**
- All production API routes resolve to a stable `route_id`.
- Route catalog reviewed and approved by backend + billing owners.

**Dependencies**
- None.

---

### AMB-002: Finalize billable-status policy (`2xx/4xx/5xx`) and error semantics
**Goal**: Establish exactly which calls count toward quota and billing.

**Scope**
- Decide defaults for billable/non-billable by status class.
- Define how rate-limited and auth-failed calls are counted.
- Document machine-readable limit denial payload contract.

**Acceptance criteria**
- Written policy approved by product/finance/engineering.
- Policy exposed as configuration with sane defaults.

**Dependencies**
- AMB-001.

---

### AMB-003: Design versioned pricing catalog schema and governance flow
**Goal**: Support per-endpoint pricing and safe mid-period changes.

**Scope**
- Add schema for `pricing_catalog_version`, `effective_at`, route entries, and optional tiers.
- Define change-management workflow and audit requirements.
- Specify fallback behavior for missing route pricing.

**Acceptance criteria**
- Catalog schema and lifecycle documented and implemented in data layer.
- Price lookup deterministic for any request timestamp.

**Dependencies**
- AMB-001.

---

## Epic B — Metering instrumentation and event ingestion

### AMB-010: Add API usage metering middleware/hooks in request pipeline
**Goal**: Emit a usage event for every eligible API request.

**Scope**
- Capture `user_sub`, `api_key_id`, `route_id`, status code, request_id, period_id.
- Compute `billable` and `request_units` from policy.
- Exclude explicitly non-metered routes.

**Acceptance criteria**
- Metered events emitted for >= 99.99% eligible calls in staging replay.
- Event schema includes required fields from plan.

**Dependencies**
- AMB-001, AMB-002.

---

### AMB-011: Add idempotency safeguards for retry/replay scenarios
**Goal**: Prevent double-counting when requests are retried.

**Scope**
- Implement deterministic event idempotency key (`request_id + route_id + attempt semantics`).
- Add duplicate detection/write guards in storage layer.
- Add tests covering retry and partial-failure paths.

**Acceptance criteria**
- Duplicate emits do not increase aggregates.
- Replay jobs remain safe and deterministic.

**Dependencies**
- AMB-010.

---

### AMB-012: Create `api_usage_events` table/store and retention policy
**Goal**: Persist immutable raw events for audit/reconciliation.

**Scope**
- Provision append-only event storage and indexes.
- Add retention/TTL policy aligned with compliance requirements.
- Add backpressure/failure handling runbook.

**Acceptance criteria**
- Event writes are durable and queryable by period/user/key/route.
- Retention settings validated in infra configuration.

**Dependencies**
- AMB-010.

---

## Epic C — Aggregation and read models

### AMB-020: Build period aggregate writer for account-level totals
**Goal**: Support fast enforcement and dashboard reads.

**Scope**
- Implement `api_usage_period_totals` upserts/increments.
- Track calls, billable calls, and cost subtotal.
- Ensure concurrency-safe updates.

**Acceptance criteria**
- Aggregates reconcile with event source within tolerance.
- Writer is replay-safe.

**Dependencies**
- AMB-011, AMB-012, AMB-003.

---

### AMB-021: Build aggregate writer for API key and route breakdowns
**Goal**: Enable per-key and per-endpoint usage/cost visibility.

**Scope**
- Implement `api_key_usage_period_totals`.
- Implement `api_route_usage_period_totals`.
- Include unit price and subtotal attribution.

**Acceptance criteria**
- Per-key and per-route totals match source events.
- Hot partitions/cardinality limits validated under load.

**Dependencies**
- AMB-020.

---

### AMB-022: Add daily rollups and reconciliation job
**Goal**: Provide charting data and repair workflows.

**Scope**
- Generate `api_usage_daily` series.
- Add recompute/reconciliation job from raw events.
- Produce drift report for aggregates vs source.

**Acceptance criteria**
- Daily series powers expected date-range queries.
- Recompute can repair a corrupted period deterministically.

**Dependencies**
- AMB-020, AMB-021.

---

## Epic D — Quota and limit enforcement

### AMB-030: Implement account-level quota checks (rate + period)
**Goal**: Enforce plan limits before request execution.

**Scope**
- Add pre-request checks for per-second/minute and per-day/month limits.
- Add spend-cap guard at account scope.
- Return standardized limit payload and headers.

**Acceptance criteria**
- Requests beyond cap are denied with deterministic error contract.
- Concurrency tests show no significant overrun race.

**Dependencies**
- AMB-020, AMB-002.

---

### AMB-031: Extend API key model for user-configurable self-limits
**Goal**: Let users set stricter limits on individual keys.

**Scope**
- Add fields: `monthly_calls_cap`, `monthly_spend_cap_micros`, `route_caps`.
- Validate self-limits do not exceed policy/account guardrails.
- Audit all limit mutations.

**Acceptance criteria**
- Key self-limit updates persist and are validated correctly.
- Lower-than-current usage changes take immediate “no further calls” effect.

**Dependencies**
- AMB-030.

---

### AMB-032: Enforce per-key and per-route caps in request path
**Goal**: Apply user-configured caps consistently at runtime.

**Scope**
- Check key-level monthly calls and spend caps.
- Check per-route key caps.
- Add warning thresholds (70/85/95%) exposure.

**Acceptance criteria**
- Calls exceeding key/route cap are rejected with correct scope metadata.
- Warning signals emitted when thresholds crossed.

**Dependencies**
- AMB-031, AMB-021.

---

## Epic E — Usage and management APIs

### AMB-040: Add API usage summary endpoints for end users
**Goal**: Expose account-level usage and cost by period.

**Scope**
- `GET /ui/api-usage/summary?period=YYYY-MM`
- Include totals, limits, remaining, and estimated cost.

**Acceptance criteria**
- Endpoint returns correct aggregated values and limit metadata.
- Authz scope restricts users to own data.

**Dependencies**
- AMB-020, AMB-030.

---

### AMB-041: Add endpoint and key breakdown endpoints
**Goal**: Let users inspect what drives usage and cost.

**Scope**
- `GET /ui/api-usage/routes?period=YYYY-MM`
- `GET /ui/api-usage/keys?period=YYYY-MM`
- Sort/filter pagination strategy for high-volume accounts.

**Acceptance criteria**
- Data aligns with period aggregates.
- Large datasets are pageable and performant.

**Dependencies**
- AMB-021.

---

### AMB-042: Add API key self-limit management endpoints
**Goal**: Enable users to configure per-key caps and inspect key usage.

**Scope**
- `PATCH /ui/api_keys/{key_id}/limits`
- `GET /ui/api_keys/{key_id}/usage?period=YYYY-MM`
- Add validation and audit integration.

**Acceptance criteria**
- Update endpoint enforces validation rules and returns normalized values.
- Usage endpoint reflects near-real-time aggregate state.

**Dependencies**
- AMB-031, AMB-041.

---

## Epic F — Billing pipeline integration

### AMB-050: Implement period finalization and immutable usage snapshots
**Goal**: Freeze usage for invoicing and dispute handling.

**Scope**
- Add `api_billing_usage_snapshots` create/finalize flow.
- Include by-route and by-key breakdown in snapshot payload.
- Enforce immutable-on-finalized semantics.

**Acceptance criteria**
- Finalized snapshots cannot be mutated.
- Snapshot output reproducible from source events.

**Dependencies**
- AMB-022, AMB-003.

---

### AMB-051: Build charge calculator with pricing-version awareness
**Goal**: Compute deterministic charges for each period.

**Scope**
- Apply route pricing and tier logic.
- Handle mid-period price changes using event pricing version.
- Produce route-level line-item breakdowns.

**Acceptance criteria**
- Charge output stable across reruns.
- Test fixtures cover tier and version-split scenarios.

**Dependencies**
- AMB-050.

---

### AMB-052: Emit invoice line items and adjustment linkage
**Goal**: Connect finalized usage charges to billing system artifacts.

**Scope**
- Write invoice lines (route totals and optional key sub-lines).
- Add adjustment model referencing snapshot version.
- Add reconciliation export/report endpoint or job.

**Acceptance criteria**
- Invoice line items are traceable to snapshot + route totals.
- Adjustments preserve full audit trail.

**Dependencies**
- AMB-051.

---

## Epic G — UI, observability, and rollout safety

### AMB-060: Build API Usage & Billing UI surfaces
**Goal**: Provide user self-serve visibility and controls.

**Scope**
- Summary cards (calls, spend, limits, remaining).
- Per-route and per-key usage/cost tables.
- Per-key self-limit editor with inline validation.

**Acceptance criteria**
- UI reads new endpoints and renders threshold states.
- Limit edits update backend and reflect in usage views.

**Dependencies**
- AMB-040, AMB-041, AMB-042.

---

### AMB-061: Add metering/billing observability dashboards and alerts
**Goal**: Detect ingestion, enforcement, and billing failures quickly.

**Scope**
- Dashboards for ingest volume, lag, deny rate, and finalize failures.
- Alerts for lag spikes, reconciliation drift, and billing failures.
- Add runbook links for on-call response.

**Acceptance criteria**
- Alert simulations verify paging paths.
- SLOs defined for ingestion completeness and aggregation latency.

**Dependencies**
- AMB-010, AMB-022, AMB-050.

---

### AMB-062: Execute shadow-billing + production cutover checklist
**Goal**: De-risk launch with parallel validation before charging users.

**Scope**
- Run shadow billing for at least one full cycle.
- Compare shadow charges vs expected/manual samples.
- Define cutover and rollback criteria.

**Acceptance criteria**
- Shadow variance within agreed threshold.
- Go-live signoff from product, finance, and engineering.

**Dependencies**
- AMB-052, AMB-061.

---

## Suggested delivery slices

- **Slice 1 (Foundations):** AMB-001..003, AMB-010..012
- **Slice 2 (Read + enforce basics):** AMB-020..022, AMB-030
- **Slice 3 (Self-limits + user APIs):** AMB-031..032, AMB-040..042
- **Slice 4 (Billing finalization):** AMB-050..052
- **Slice 5 (UI + hardening):** AMB-060..062

This sequencing enables early instrumentation and internal visibility first, followed by safe enforcement, then invoicing and customer-facing rollout.
