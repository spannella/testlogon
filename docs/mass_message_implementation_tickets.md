# Mass Messaging (Immediate + Scheduled) — Implementation Ticket Set

This ticket set translates `docs/mass_message_send_or_schedule_plan.md` into actionable engineering work items.

## Milestone Overview
- **Milestone 1 (Foundation):** data model, schemas, API skeleton, worker scaffold.
- **Milestone 2 (Execution):** destination fanout through shared send helper, immediate and scheduled processing.
- **Milestone 3 (Hardening):** retries, metrics, feature flag rollout controls, optional cancellation.

---

## Epic MM-0 — Alignment & RFC Freeze

### MM-1: Finalize v1 scope and constraints
**Status**
- ✅ Implemented via `docs/mass_message_v1_scope_rfc.md` (scope freeze addendum dated 2026-03-24).

**Description**
- Confirm v1 supports existing conversation IDs only (no conversation auto-create), and identical payload for all destinations.
- Decide v1 message types (recommended: text first, then parity expansion).
- Confirm max destinations per campaign (proposed default: 100).

**Acceptance Criteria**
- A short RFC update captures final v1 scope and limits.
- Product, backend, and abuse/compliance stakeholders approve.

**Dependencies**
- None.

---

## Epic MM-1 — Persistence & Domain Model

### MM-2: Add `MassMessageCampaigns` storage model
**Status**
- ✅ Implemented with `app/services/mass_message_campaigns.py`, table wiring in `app/core/settings.py` + `app/core/tables.py`, and local DDB schema in `scripts/local-ddb-init.py`.

**Description**
- Create table/model for campaign-level metadata:
  - `campaign_id`, `sender_id`, `mode`, `send_at`, `status`, payload hash, aggregate counters, timestamps.
- Add status enum definitions and transition guard helper.

**Acceptance Criteria**
- Migration applied and reversible.
- Basic CRUD via service helper with tests.

**Dependencies**
- MM-1.

### MM-3: Add `MassMessageCampaignDestinations` storage model
**Status**
- ✅ Implemented with `app/services/mass_message_campaign_destinations.py`, table wiring in `app/core/settings.py` + `app/core/tables.py`, and local DDB schema in `scripts/local-ddb-init.py`.

**Description**
- Create table/model keyed by `campaign_id + conversation_id`.
- Track destination state, error codes, generated `message_id`, attempt count, and timestamps.

**Acceptance Criteria**
- Migration applied and reversible.
- Service helper supports create/read/update idempotently.

**Dependencies**
- MM-2.

### MM-4: Add repository/service layer for campaign orchestration
**Description**
- Add domain methods for:
  - create campaign + destination rows atomically (best effort transactional semantics)
  - increment aggregate counters from destination transitions
  - query campaign summary + destination pagination

**Acceptance Criteria**
- Unit tests cover happy path, partial updates, and race-safe counters.

**Dependencies**
- MM-2, MM-3.

---

## Epic MM-2 — API Contracts & Router Endpoints

### MM-5: Define request/response schemas
**Description**
- Add pydantic schemas for:
  - create mass message request
  - create response
  - campaign detail response with destination statuses
- Include optional `send_at` and idempotency key field.

**Acceptance Criteria**
- Validation covers max destination count, `send_at` bounds, payload shape.
- Schema tests added.

**Dependencies**
- MM-1.

### MM-6: Implement `POST /messaging/mass-messages`
**Description**
- Validate sender auth + destination eligibility.
- Persist campaign + destination rows.
- Return accepted/rejected destinations and campaign id.
- For immediate mode, enqueue async execution trigger.

**Acceptance Criteria**
- Endpoint returns deterministic response under request idempotency.
- API integration tests include mixed valid/invalid destination sets.

**Dependencies**
- MM-4, MM-5.

### MM-7: Implement `GET /messaging/mass-messages/{campaign_id}`
**Description**
- Expose aggregate status and destination-level results.

**Acceptance Criteria**
- Sender can read own campaign status.
- Unauthorized users cannot access campaign details.

**Dependencies**
- MM-4, MM-5.

---

## Epic MM-3 — Shared Send Pipeline Integration

### MM-8: Extract shared single-destination send helper
**Description**
- Refactor existing per-conversation send path to an internal helper used by both current endpoints and mass fanout worker.
- Preserve existing behaviors: metering, archive event emission, unread counters, delivery receipts, policy checks.

**Acceptance Criteria**
- No behavior regression in existing send endpoints.
- Existing tests pass; new tests verify helper parity.

**Dependencies**
- MM-6.

### MM-9: Implement immediate campaign fanout worker
**Description**
- Add worker job handler that processes campaign destinations with bounded concurrency.
- Persist destination result after each attempt.

**Acceptance Criteria**
- Successful destinations transition to `sent` with `message_id`.
- Failures are recorded with reason code and do not block remaining destinations.

**Dependencies**
- MM-8.

### MM-10: Implement scheduled campaign dispatcher
**Description**
- Add scheduler loop/query to pick due campaigns by `send_at`.
- Reuse the same fanout worker as immediate mode.

**Acceptance Criteria**
- Scheduled campaigns do not send before due time.
- Due campaigns transition and execute once.

**Dependencies**
- MM-9.

---

## Epic MM-4 — Idempotency, Retry, and Failure Semantics

### MM-11: Add request-level idempotency
**Description**
- Map `(sender_id, idempotency_key)` to existing campaign and deterministic create response.

**Acceptance Criteria**
- Duplicate create calls return same `campaign_id` and no duplicate destination rows.

**Dependencies**
- MM-6.

### MM-12: Add destination-level idempotency + retry policy
**Description**
- Enforce deterministic destination key to prevent duplicate sends during worker retries.
- Retry transient failures with capped backoff and max attempt count.

**Acceptance Criteria**
- Duplicate worker execution does not produce duplicate messages.
- Retry metrics and attempt counters are recorded.

**Dependencies**
- MM-9.

### MM-13: Define canonical error taxonomy
**Description**
- Create stable error codes for destination failures (permission denied, conversation missing, policy blocked, transient infra error, etc.).

**Acceptance Criteria**
- Destination rows and API payload use taxonomy consistently.

**Dependencies**
- MM-9.

---

## Epic MM-5 — Observability, Audit, and Controls

### MM-14: Add campaign + destination metrics
**Description**
- Emit counters/timers for campaign creation, completion, destination success/failure, retry count, worker latency.

**Acceptance Criteria**
- Metrics visible in existing telemetry sink with dashboard-ready names.

**Dependencies**
- MM-9, MM-10.

### MM-15: Add audit/compliance event hooks
**Description**
- Emit campaign submit/complete audit events.
- Ensure destination sends use standard archive/lifecycle event path via shared helper.

**Acceptance Criteria**
- Audit payload includes campaign id and destination mapping to message ids.

**Dependencies**
- MM-8, MM-9.

### MM-16: Feature flag and rollout guardrails
**Description**
- Add `messaging.mass_send.enabled` and staged rollout controls.
- Block new campaign creation when disabled while preserving status reads.

**Acceptance Criteria**
- Flag-off behavior validated by tests.
- Runbook includes rollback steps.

**Dependencies**
- MM-6.

---

## Epic MM-6 — Optional Hardening Enhancements

### MM-17: Campaign cancellation endpoint (optional)
**Description**
- Add `POST /messaging/mass-messages/{campaign_id}/cancel` for campaigns not fully sent.

**Acceptance Criteria**
- Pending destinations become `cancelled`; sent destinations unchanged.
- Worker respects cancellation race conditions safely.

**Dependencies**
- MM-10.

### MM-18: Failed destination replay tooling (optional)
**Description**
- Admin/internal operation to replay only failed destinations.

**Acceptance Criteria**
- Replay operation is auditable and idempotent.

**Dependencies**
- MM-12, MM-13.

---

## QA & Test Tickets

### MM-19: Unit test suite for validation/idempotency/retry
**Acceptance Criteria**
- Covers schema guards, idempotency mapping, retry classifier, status transitions.

### MM-20: Integration tests for immediate + scheduled campaigns
**Acceptance Criteria**
- Immediate mixed DM/group fanout success.
- Scheduled delivery timing correctness.
- Partial failure reporting.
- Duplicate worker execution safety.

### MM-21: Load/perf validation
**Acceptance Criteria**
- Campaign at max recipient count stays within latency/error budget.
- No duplicate sends under induced worker retries.

---

## Recommended Delivery Order (Critical Path)
1. MM-1 → MM-2/MM-3 → MM-4
2. MM-5 → MM-6/MM-7
3. MM-8 → MM-9 → MM-10
4. MM-11/MM-12/MM-13
5. MM-14/MM-15/MM-16
6. MM-19/MM-20 (parallel with epics above), then MM-21
7. Optional MM-17/MM-18

---

## Suggested Ticket Metadata Template
For each ticket in your tracker, include:
- **Type:** Story / Task / Spike
- **Owner:** Team or engineer
- **Estimate:** story points / ideal days
- **Risk level:** Low/Med/High
- **Dependencies:** ticket IDs
- **Definition of Done:** implementation + tests + docs + metrics/audit updates where applicable

---

## Mass Messaging Metrics & Dashboard Queries

### Instrumented metric names
- `messaging_mass_campaign_events_total{event,mode,outcome}`
- `messaging_mass_destination_outcomes_total{mode,outcome,error_code}`
- `messaging_mass_destination_retries_total{mode,error_code}`
- `messaging_mass_worker_latency_seconds_bucket{mode,outcome,le}`

### Suggested dashboard PromQL snippets
- Campaign create rate (5m):
  - `sum(rate(messaging_mass_campaign_events_total{event="create",outcome=~"success|idempotent_replay"}[5m])) by (mode,outcome)`
- Campaign completion count (1h):
  - `sum(increase(messaging_mass_campaign_events_total{event="complete"}[1h])) by (mode,outcome)`
- Destination success vs failure ratio (15m):
  - `sum(rate(messaging_mass_destination_outcomes_total{outcome="sent"}[15m])) / clamp_min(sum(rate(messaging_mass_destination_outcomes_total{outcome="failed"}[15m])), 1e-9)`
- Destination failure breakdown by canonical error code (15m):
  - `sum(rate(messaging_mass_destination_outcomes_total{outcome="failed"}[15m])) by (mode,error_code)`
- Retry volume by canonical error code (15m):
  - `sum(rate(messaging_mass_destination_retries_total[15m])) by (mode,error_code)`
- Worker p95 latency (15m):
  - `histogram_quantile(0.95, sum(rate(messaging_mass_worker_latency_seconds_bucket[15m])) by (le,mode,outcome))`

### Campaign audit events
- `messaging_mass_campaign_submitted`
  - fields: `campaign_id`, `mode`, `accepted_count`, `rejected_count`, `created_new`
- `messaging_mass_campaign_completed`
  - fields: `campaign_id`, `mode`, `processed`, `sent`, `failed`, `outcome`

### Feature flag / kill-switch controls
- `MESSAGING_MASS_SEND_ENABLED` (default `true`): gates campaign creation and worker/dispatcher execution.
- `MESSAGING_MASS_SEND_KILL_SWITCH` (default `false`): immediate operational stop for workers without service restart.
