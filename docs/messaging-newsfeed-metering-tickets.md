# Messaging + Newsfeed Metering Implementation Tickets

This backlog translates the metering plan into deliverable tickets, with scope, dependencies, and acceptance criteria.

## Conventions
- Priority: `P0` (must-have), `P1` (important), `P2` (nice-to-have)
- Size: `S` (~0.5–1 day), `M` (~1–3 days), `L` (~3–5 days)
- Type: `Backend`, `API`, `Data`, `Billing`, `UI`, `Ops`, `QA`

---

## Epic A — Metering Contract + Data Model

### MTR-001 — Define event taxonomy for messaging/newsfeed usage
- **Type:** Backend / Data
- **Priority:** P0
- **Size:** M
- **Description:** Define canonical event types/sources for message sends, post publishes, and attachment upload/download usage.
- **Deliverables:**
  - Event contract doc update with examples.
  - Enumerations for new event sources in metering service.
- **Acceptance criteria:**
  - Contract includes `messaging_send`, `newsfeed_post`, `messaging_attachment_upload`, `messaging_attachment_download`, `newsfeed_attachment_upload`, `newsfeed_attachment_download`.
  - Idempotency key patterns documented for each source.
  - Existing file-manager event types remain backward compatible.
- **Dependencies:** none

### MTR-002 — Extend usage aggregate schemas for unit counters
- **Type:** Data / Backend
- **Priority:** P0
- **Size:** M
- **Description:** Add aggregate fields for unit-based billing dimensions.
- **Deliverables:**
  - `usage_period_totals` and `usage_daily` schema updates.
  - Migration/backward-compatible defaults.
- **Acceptance criteria:**
  - New fields available with zero defaults: `message_send_count_total`, `post_publish_count_total`.
  - Existing readers do not fail on older rows that lack new fields.
- **Dependencies:** MTR-001

### MTR-003 — Snapshot schema versioning for new counters
- **Type:** Billing / Data
- **Priority:** P0
- **Size:** M
- **Description:** Extend billing usage snapshots to capture message/post counters and media transfer dimensions.
- **Deliverables:**
  - Snapshot builder updates.
  - Versioning strategy (`v2` snapshot payload).
- **Acceptance criteria:**
  - Finalized snapshots include new counters.
  - Previous snapshot versions remain readable.
  - Snapshot tests cover version upgrade path.
- **Dependencies:** MTR-002

---

## Epic B — Messaging Instrumentation

### MSG-001 — Meter text message send events
- **Type:** Backend / API
- **Priority:** P0
- **Size:** M
- **Description:** Record one usage unit for each successfully persisted text message.
- **Deliverables:**
  - Metering call in message-send endpoint.
  - Deterministic idempotency key from `user_id + conversation_id + message_id`.
- **Acceptance criteria:**
  - A successful send increments `message_send_count_total` by exactly 1.
  - Retry of same logical send does not double increment.
  - Failed sends do not generate usage events.
- **Dependencies:** MTR-001, MTR-002

### MSG-002 — Meter image/file message send events consistently
- **Type:** Backend / API
- **Priority:** P0
- **Size:** M
- **Description:** Apply the same send-unit metering to image/file message endpoints.
- **Deliverables:**
  - Metering hooks in `/messages/image` and `/messages/file` flows.
- **Acceptance criteria:**
  - Image/file messages increment send counter exactly once per message.
  - Send-unit behavior is consistent across text/image/file endpoints.
- **Dependencies:** MSG-001

### MSG-003 — Meter messaging attachment upload bytes
- **Type:** Backend / API
- **Priority:** P0
- **Size:** M
- **Description:** Record authoritative upload bytes for messaging attachments.
- **Deliverables:**
  - Upload metering on completion path.
  - Source tagging as `messaging_attachment_upload`.
- **Acceptance criteria:**
  - Bytes are sourced from trusted metadata/object head (not client-declared only).
  - Usage totals reflect actual uploaded payload size.
- **Dependencies:** MTR-001

### MSG-004 — Meter messaging attachment download bytes
- **Type:** Backend / API
- **Priority:** P1
- **Size:** M
- **Description:** Meter bytes actually streamed when attachments are downloaded/viewed.
- **Deliverables:**
  - Stream accounting wrapper for messaging media download responses.
  - Source tagging as `messaging_attachment_download`.
- **Acceptance criteria:**
  - Metered bytes align with streamed payload bytes.
  - No duplicate count on partial/retried same request with same idempotency key.
- **Dependencies:** MTR-001

### MSG-005 — Messaging quota pre-check and policy enforcement
- **Type:** Backend / API
- **Priority:** P1
- **Size:** M
- **Description:** Enforce plan-level message limits before send execution.
- **Deliverables:**
  - Guard integrated with subscription access/policy logic.
  - Structured error for over-limit attempts.
- **Acceptance criteria:**
  - Over-limit users receive deterministic machine-readable error.
  - Soft-warning thresholds trigger at 80% and 95% (if enabled).
- **Dependencies:** MSG-001, BILL-002

---

## Epic C — Newsfeed Instrumentation

### NWS-001 — Meter post publish unit events
- **Type:** Backend / API
- **Priority:** P0
- **Size:** M
- **Description:** Record one usage unit for each successful post creation.
- **Deliverables:**
  - Metering hook in `POST /newsfeed/posts`.
  - Idempotency key from `user_id + post_id`.
- **Acceptance criteria:**
  - Successful post increments `post_publish_count_total` by exactly 1.
  - Retry of same logical create does not double count.
  - Failed creates do not produce usage events.
- **Dependencies:** MTR-001, MTR-002

### NWS-002 — Meter newsfeed attachment upload bytes
- **Type:** Backend / API
- **Priority:** P0
- **Size:** M
- **Description:** Meter upload bytes for post attachments.
- **Deliverables:**
  - Usage event on authoritative upload completion path.
  - Source tagging as `newsfeed_attachment_upload`.
- **Acceptance criteria:**
  - Upload usage reflects stored object size.
  - No double counting across retries.
- **Dependencies:** MTR-001

### NWS-003 — Meter newsfeed attachment download bytes
- **Type:** Backend / API
- **Priority:** P1
- **Size:** M
- **Description:** Meter streamed bytes when serving newsfeed attachments.
- **Deliverables:**
  - Stream byte accounting in attachment-serving endpoints.
  - Source tagging as `newsfeed_attachment_download`.
- **Acceptance criteria:**
  - Download usage tracks actual streamed bytes.
  - Metrics label split by source is available.
- **Dependencies:** MTR-001

### NWS-004 — Newsfeed quota pre-check and policy enforcement
- **Type:** Backend / API
- **Priority:** P1
- **Size:** M
- **Description:** Enforce plan-level post creation limits.
- **Deliverables:**
  - Pre-create guard integrated in post creation flow.
- **Acceptance criteria:**
  - Over-limit post attempts blocked (or overage path selected by plan policy).
  - Warning threshold events emitted at configured levels.
- **Dependencies:** NWS-001, BILL-002

---

## Epic D — Billing + Product Policy

### BILL-001 — Extend pricing catalog for message/post unit charges
- **Type:** Billing
- **Priority:** P0
- **Size:** M
- **Description:** Add configurable pricing entries for message sends and post publishes (allowance + overage support).
- **Deliverables:**
  - Catalog schema updates.
  - Validation and defaults.
- **Acceptance criteria:**
  - Supports included allowance and per-unit overage.
  - Catalog versioning preserved.
- **Dependencies:** MTR-003

### BILL-002 — Add plan limits for message/post usage
- **Type:** Billing / Backend
- **Priority:** P0
- **Size:** S
- **Description:** Define configurable monthly limits for message sends and post publishes.
- **Deliverables:**
  - Settings/config additions.
  - Plan model wiring.
- **Acceptance criteria:**
  - Limits readable by enforcement code.
  - Missing limits gracefully treated as unlimited.
- **Dependencies:** none

### BILL-003 — Invoice line item generation for new dimensions
- **Type:** Billing
- **Priority:** P1
- **Size:** L
- **Description:** Compute invoice lines for message/post usage and optional media transfer overages.
- **Deliverables:**
  - Line-item mapping in billing finalization pipeline.
  - Rounding and units normalization.
- **Acceptance criteria:**
  - Finalized invoice includes distinct lines for message/post usage.
  - Totals reconcile with frozen usage snapshot.
- **Dependencies:** BILL-001, MTR-003

---

## Epic E — API + UI Visibility

### API-001 — Extend usage summary endpoints with new counters
- **Type:** API
- **Priority:** P0
- **Size:** M
- **Description:** Return message/post counters and media transfer split in usage summary responses.
- **Deliverables:**
  - API response contract update.
  - Compatibility fields for existing clients.
- **Acceptance criteria:**
  - New counters present in period summary.
  - Existing clients remain functional.
- **Dependencies:** MTR-002

### UI-001 — Show messaging/newsfeed usage on Usage & Billing page
- **Type:** UI
- **Priority:** P1
- **Size:** M
- **Description:** Add cards/sections for message sends and post publishes including percent-to-limit.
- **Deliverables:**
  - UI components and copy.
  - Loading/empty/error states.
- **Acceptance criteria:**
  - User can view current period usage for message/post units.
  - Warning styles shown near threshold.
- **Dependencies:** API-001

### UI-002 — Admin usage panel segmentation by surface
- **Type:** UI / Ops
- **Priority:** P2
- **Size:** M
- **Description:** Show usage split between filemanager, messaging, and newsfeed.
- **Deliverables:**
  - Admin table/chart updates.
- **Acceptance criteria:**
  - Admin can filter by source family and period.
- **Dependencies:** API-001, OPS-001

---

## Epic F — Observability, Feature Flags, and Operations

### OPS-001 — Add metrics and dashboards for new usage dimensions
- **Type:** Ops
- **Priority:** P1
- **Size:** M
- **Description:** Publish counters and dashboard views for sends/posts and media transfer split.
- **Deliverables:**
  - Metrics instrumentation.
  - Dashboard panels/alerts.
- **Acceptance criteria:**
  - Metrics available per source and period.
  - Alert thresholds for abnormal spikes defined.
- **Dependencies:** MSG-001, NWS-001

### OPS-002 — Feature flags for staged rollout
- **Type:** Backend / Ops
- **Priority:** P0
- **Size:** S
- **Description:** Gate metering/enforcement behavior to allow observe-only rollout.
- **Deliverables:**
  - Flags: `metering_messaging_enabled`, `metering_newsfeed_enabled`, `enforce_message_post_limits_enabled`.
- **Acceptance criteria:**
  - Flags can independently toggle metering and enforcement.
  - Default rollout mode is metering on + enforcement off.
- **Dependencies:** none

### OPS-003 — Recompute/reconciliation support for new counters
- **Type:** Data / Ops
- **Priority:** P1
- **Size:** M
- **Description:** Update recompute tooling to rebuild message/post usage totals from events.
- **Deliverables:**
  - Recompute job support for new dimensions.
  - Runbook update.
- **Acceptance criteria:**
  - Recompute output matches aggregates for sampled users.
  - Drift report includes new counters.
- **Dependencies:** MTR-002

---

## Epic G — QA and Validation

### QA-001 — Unit tests for event creation and aggregate updates
- **Type:** QA / Backend
- **Priority:** P0
- **Size:** M
- **Description:** Add unit coverage for new event types and counter rollups.
- **Acceptance criteria:**
  - Tests cover message/post unit events, idempotency, and retries.
  - Tests cover mixed event-type aggregation in same period/day.
- **Dependencies:** MTR-001, MTR-002

### QA-002 — Router tests for send/post instrumentation
- **Type:** QA / API
- **Priority:** P0
- **Size:** M
- **Description:** Verify successful and failed flows for messaging/newsfeed metering.
- **Acceptance criteria:**
  - Successful send/post increments once.
  - Failure paths do not increment usage.
- **Dependencies:** MSG-001, NWS-001

### QA-003 — Billing integration tests for invoice math
- **Type:** QA / Billing
- **Priority:** P1
- **Size:** M
- **Description:** Validate snapshot-to-invoice pipeline for new dimensions.
- **Acceptance criteria:**
  - Invoice totals reconcile with snapshot counters + catalog rates.
  - Edge cases: zero usage, just-at-limit, overage usage.
- **Dependencies:** BILL-003

---

## Suggested implementation order (critical path)
1. MTR-001 → MTR-002 → MTR-003
2. BILL-002 + OPS-002 (early for guarded rollout)
3. MSG-001 + MSG-002 + NWS-001
4. MSG-003 + NWS-002, then MSG-004 + NWS-003
5. API-001, then UI-001
6. BILL-001 + BILL-003
7. QA tickets and OPS-001/OPS-003 hardening

---

## Ready-to-sprint cut (recommended)

### Sprint 1 (must-have MVP)
- MTR-001, MTR-002, OPS-002, BILL-002, MSG-001, NWS-001, QA-001, QA-002

### Sprint 2 (media and visibility)
- MSG-003, NWS-002, API-001, UI-001, OPS-001

### Sprint 3 (downloads + billing finalization)
- MSG-004, NWS-003, MTR-003, BILL-001, BILL-003, QA-003

### Sprint 4 (enforcement + reconciliation)
- MSG-005, NWS-004, OPS-003, UI-002
