# DM Lottery Messages Implementation Tickets

This backlog decomposes `docs/dm-lottery-messages-implementation-plan.md` into implementable tickets with scope, dependencies, and acceptance criteria.

## Conventions
- Priority: `P0` (must-have), `P1` (important), `P2` (nice-to-have)
- Size: `S` (~0.5–1 day), `M` (~1–3 days), `L` (~3–5 days)
- Type: `Backend`, `API`, `Data`, `Frontend`, `Design`, `Security`, `Ops`, `QA`

---

## Epic A — Contract, Schema, and Feature Flags

### LOT-001 — Finalize lottery message product/API contract ✅ Implemented (`docs/dm-lottery-messages-api-contract.md`)
- **Type:** API / Backend
- **Priority:** P0
- **Size:** M
- **Description:** Lock request/response schemas, field names, and client-visible states for lottery DMs.
- **Deliverables:**
  - Contract update for create/unlock/fetch payloads.
  - Error model (`invalid-config`, `already-unlocked`, `unauthorized`, `not-dm`).
- **Acceptance criteria:**
  - API contract includes `message_type=lottery_dm`, `lock_state`, and selected outcome payload shape.
  - Contract defines what is/is not leaked before unlock.
  - Contract approved by backend + frontend owners.
- **Dependencies:** none

### LOT-002 — Add DB schema for immutable lottery config + per-recipient unlock state ✅ Implemented (`scripts/migrations/20260324_lottery_message_schema.py`, `app/services/messaging_lottery_store.py`)
- **Type:** Data / Backend
- **Priority:** P0
- **Size:** L
- **Description:** Add persistent model for outcome weights and recipient unlock results.
- **Deliverables:**
  - Migration(s) for `lottery_config` and `lottery_unlocks`.
  - Unique index/constraint on `(message_id, recipient_id)`.
- **Acceptance criteria:**
  - Config stores `weight_bps` with enforced total 10_000.
  - Unlock state is one row per recipient per message.
  - Migration is backward compatible and rollback-safe.
- **Dependencies:** LOT-001

### LOT-003 — Add feature flag and kill switch wiring ✅ Implemented (`app/core/settings.py`, `app/routers/messaging.py`, `frontend/src/lib/featureFlags.ts`)
- **Type:** Ops / Backend / Frontend
- **Priority:** P0
- **Size:** S
- **Description:** Gate all lottery DM create/unlock/render paths behind `messaging.dm_lottery`.
- **Deliverables:**
  - Server and client flag checks.
  - Runbook note for emergency disable behavior.
- **Acceptance criteria:**
  - Disabled flag fully hides composer entry and blocks API endpoints with deterministic error.
  - Enabling flag restores complete functionality without restart.
- **Dependencies:** LOT-001

---

## Epic B — Message Creation and Validation

### LOT-101 — Implement `POST /messages/lottery` endpoint ✅ Implemented (`app/routers/messaging.py`)
- **Type:** API / Backend
- **Priority:** P0
- **Size:** L
- **Description:** Add send endpoint for DM lottery message creation.
- **Deliverables:**
  - Endpoint handler with auth + DM conversation validation.
  - Persist message + immutable lottery config atomically.
- **Acceptance criteria:**
  - Endpoint rejects non-DM conversations.
  - Created lottery message appears in timeline fetch.
  - Config is immutable after send.
- **Dependencies:** LOT-001, LOT-002, LOT-003

### LOT-102 — Implement backend validation rules for outcomes and weights ✅ Implemented (`app/services/messaging_lottery_store.py`, `app/routers/messaging.py`)
- **Type:** Backend / API
- **Priority:** P0
- **Size:** M
- **Description:** Enforce constraints for number of outcomes, payload types, and weighted totals.
- **Deliverables:**
  - Shared validator used by create path.
  - Validation error mapping with field-level context.
- **Acceptance criteria:**
  - Reject total weights != 10_000 bps.
  - Reject unsupported payloads or missing text/media fields.
  - Reject outcomes outside configured min/max count.
- **Dependencies:** LOT-101

### LOT-103 — Integrate media attachment references for image/video outcomes ✅ Implemented (`app/routers/messaging.py`, `frontend/src/api/types.ts`)
- **Type:** Backend / API
- **Priority:** P0
- **Size:** M
- **Description:** Reuse existing media upload pipeline and store immutable asset references in outcomes.
- **Deliverables:**
  - Asset lookup/ownership checks on create.
  - Stable media metadata in response payload.
- **Acceptance criteria:**
  - Only authorized, existing assets can be attached.
  - Removed/invalid assets fail fast with explicit error code.
- **Dependencies:** LOT-101

---

## Epic C — Server-Authoritative Unlock + Weighted RNG

### LOT-201 — Build shared weighted selection utility ✅ Implemented (`app/services/messaging_lottery_rng.py`)
- **Type:** Backend
- **Priority:** P0
- **Size:** M
- **Description:** Implement deterministic weighted-choice utility using integer basis points and secure RNG.
- **Deliverables:**
  - Utility function with cumulative range selection.
  - Unit tests for boundary/edge cases.
- **Acceptance criteria:**
  - Selection domain is `[1, 10_000]` inclusive.
  - Edge rolls map correctly to expected outcomes.
  - No floating-point arithmetic used in core selection.
- **Dependencies:** LOT-001

### LOT-202 — Implement `POST /messages/{message_id}/lottery/unlock` transactional flow ✅ Implemented (`app/routers/messaging.py`, `app/services/messaging_lottery_store.py`)
- **Type:** API / Backend / Data
- **Priority:** P0
- **Size:** L
- **Description:** Add idempotent unlock endpoint with atomic first-unlock selection persistence.
- **Deliverables:**
  - Transactional unlock path.
  - Existing-row short-circuit to return prior selection.
- **Acceptance criteria:**
  - First unlock writes `selected_outcome_id` + `unlocked_at`.
  - Repeated unlock returns same selection without reroll.
  - Concurrent unlock attempts do not create duplicate rows/outcomes.
- **Dependencies:** LOT-002, LOT-201

### LOT-203 — Add timeline serialization for locked/unlocked states ✅ Implemented (`app/routers/messaging.py`, `frontend/src/api/types.ts`)
- **Type:** API / Backend
- **Priority:** P0
- **Size:** M
- **Description:** Return lottery-specific render state in message fetch APIs.
- **Deliverables:**
  - Serializer changes for `lock_state` and selected payload projection.
  - Policy that hides unrevealed result details.
- **Acceptance criteria:**
  - Locked recipients do not receive selected outcome payload.
  - Unlocked recipients consistently receive selected payload across devices.
- **Dependencies:** LOT-202

### LOT-204 — Add unlock endpoint rate limiting and abuse controls ✅ Implemented (`app/routers/messaging.py`, `app/core/settings.py`)
- **Type:** Security / Backend / Ops
- **Priority:** P1
- **Size:** M
- **Description:** Protect unlock APIs from brute-force/abuse while preserving normal UX.
- **Deliverables:**
  - Rate limit policy keyed by user/conversation/message.
  - Structured `rate_limited` responses and metrics.
- **Acceptance criteria:**
  - Excess unlock calls are throttled with correct status/error body.
  - Normal unlock flow unaffected under expected usage.
- **Dependencies:** LOT-202

---

## Epic D — Frontend Composer and Reveal UX

### LOT-301 — Add DM composer "Lottery" mode and outcome editor UI
- **Type:** Frontend / Design
- **Priority:** P0
- **Size:** L
- **Description:** Add sender workflow to create lottery messages with N outcomes and payload pickers.
- **Deliverables:**
  - Lottery compose entry in DM composer.
  - Add/remove outcome rows, payload type switcher, media picker integration.
- **Acceptance criteria:**
  - Sender can configure mixed payload outcomes (text/image/video).
  - UI prevents invalid submission states.
- **Dependencies:** LOT-001, LOT-102, LOT-103

### LOT-302 — Implement percentage editing and balancing UX
- **Type:** Frontend
- **Priority:** P1
- **Size:** M
- **Description:** Provide intuitive controls for weight input and total validation.
- **Deliverables:**
  - Percentage/bps input handling.
  - Real-time total indicator and field-level validation errors.
- **Acceptance criteria:**
  - Submit disabled unless total == 100% equivalent.
  - Rounding behavior is explicit and deterministic in UI.
- **Dependencies:** LOT-301

### LOT-303 — Render locked lottery card + unlock CTA in conversation
- **Type:** Frontend
- **Priority:** P0
- **Size:** M
- **Description:** Add locked-state message card and unlock action wiring.
- **Deliverables:**
  - Locked visual treatment and button/CTA.
  - Unlock API call integration.
- **Acceptance criteria:**
  - Locked card appears for recipients pre-unlock.
  - Error/retry states are user-friendly and non-destructive.
- **Dependencies:** LOT-203

### LOT-304 — Implement spinner animation reveal state machine
- **Type:** Frontend / Design
- **Priority:** P0
- **Size:** M
- **Description:** Add `idle -> unlocking -> revealing -> revealed` flow with short spinner animation.
- **Deliverables:**
  - Spinner component and timing/reconciliation logic.
  - Reduced-motion accessibility fallback.
- **Acceptance criteria:**
  - Reveal state transitions are consistent even on slow network.
  - Reduced-motion setting disables/reduces animation appropriately.
- **Dependencies:** LOT-303

### LOT-305 — Render selected outcome payloads with existing media components
- **Type:** Frontend
- **Priority:** P0
- **Size:** M
- **Description:** Reuse current message/media components to display revealed text/image/video outcomes.
- **Deliverables:**
  - Text reveal renderer.
  - Image/video reveal with existing attachment players.
- **Acceptance criteria:**
  - Revealed payload matches server-selected outcome.
  - Reloading conversation preserves revealed state.
- **Dependencies:** LOT-304

---

## Epic E — Security, Observability, and Analytics

### LOT-401 — Add audit events for create/unlock actions
- **Type:** Security / Backend
- **Priority:** P1
- **Size:** S
- **Description:** Emit audit records for who created and who unlocked lottery DMs.
- **Deliverables:**
  - Audit event schema additions.
  - Logging hooks in create/unlock paths.
- **Acceptance criteria:**
  - Audit records include actor, message ID, timestamp, and selected outcome ID (where applicable).
  - Logs exclude raw sensitive media URLs.
- **Dependencies:** LOT-101, LOT-202

### LOT-402 — Add metrics dashboards + alerts for unlock reliability
- **Type:** Ops / Backend
- **Priority:** P1
- **Size:** M
- **Description:** Instrument and monitor adoption, errors, and performance.
- **Deliverables:**
  - Counters: sends, unlock attempts/success/failure.
  - Timers: unlock latency and reveal latency.
  - Alert thresholds for unlock error-rate spikes.
- **Acceptance criteria:**
  - Metrics are queryable by environment and client version.
  - Alerts trigger in staging test scenarios.
- **Dependencies:** LOT-101, LOT-202

### LOT-403 — Build distribution sanity checker job
- **Type:** Backend / Ops / QA
- **Priority:** P2
- **Size:** M
- **Description:** Add offline/periodic analysis to compare observed outcome distribution vs configured weights at aggregate level.
- **Deliverables:**
  - Analysis job or report query.
  - Threshold-based anomaly signal.
- **Acceptance criteria:**
  - Report surfaces significant skew beyond configurable tolerance.
  - Checker excludes low-sample groups to avoid noisy alerts.
- **Dependencies:** LOT-202

---

## Epic F — QA, E2E, and Launch

### LOT-501 — Backend test coverage for validation, RNG, and concurrency
- **Type:** QA / Backend
- **Priority:** P0
- **Size:** M
- **Description:** Add automated tests for create/unlock correctness and race conditions.
- **Deliverables:**
  - Unit tests for validators and weighted selection boundaries.
  - Integration tests for idempotent unlock under parallel requests.
- **Acceptance criteria:**
  - Concurrency test proves single persisted outcome per recipient.
  - Boundary tests cover first/last bps intervals.
- **Dependencies:** LOT-102, LOT-201, LOT-202

### LOT-502 — Frontend test coverage for composer and reveal states
- **Type:** QA / Frontend
- **Priority:** P0
- **Size:** M
- **Description:** Add component/integration tests for compose and unlock flows.
- **Deliverables:**
  - Tests for validation, disabled submit, unlock/reveal transitions.
  - Reduced-motion behavior tests.
- **Acceptance criteria:**
  - Tests verify locked->revealed persistence on reload state hydration.
  - Tests cover API error handling and retry UX.
- **Dependencies:** LOT-301, LOT-304, LOT-305

### LOT-503 — End-to-end scenario coverage (DM-only)
- **Type:** QA
- **Priority:** P0
- **Size:** M
- **Description:** Add E2E coverage for cross-user create/unlock consistency.
- **Deliverables:**
  - Test: sender creates mixed outcomes + recipient unlocks once.
  - Test: repeated unlock yields same result.
  - Test: second recipient in separate DM sees independent flow.
- **Acceptance criteria:**
  - E2E passes in CI for feature-flag enabled environment.
  - Failures capture useful artifacts/logs for debugging.
- **Dependencies:** LOT-202, LOT-305

### LOT-504 — Staging rollout checklist and go/no-go gate
- **Type:** Ops / QA
- **Priority:** P1
- **Size:** S
- **Description:** Operational checklist before production ramp.
- **Deliverables:**
  - Checklist for flag enablement, dashboard review, and rollback drill.
  - Signed go/no-go criteria tied to error-rate and latency thresholds.
- **Acceptance criteria:**
  - Rollback path validated in staging.
  - Stakeholders sign off with objective metric gates.
- **Dependencies:** LOT-402, LOT-503

---

## Suggested Execution Order (Critical Path)
1. LOT-001 → LOT-002 → LOT-003
2. LOT-101 → LOT-102 → LOT-103
3. LOT-201 → LOT-202 → LOT-203
4. LOT-301 → LOT-303 → LOT-304 → LOT-305
5. LOT-501 + LOT-502 + LOT-503
6. LOT-402 → LOT-504

## Definition of Done (Feature)
- Feature flag enabled for target cohort with no sev1/sev2 regressions.
- DM lottery create/unlock behavior is idempotent, server-authoritative, and audited.
- Composer, spinner reveal, and text/image/video outcomes are fully functional.
- Test suites and staging checklist pass with rollout metrics in healthy range.
