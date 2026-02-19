# Messaging Once-Media — Ticket Breakdown

This ticket set maps directly to `docs/messaging-once-media-plan.md` and breaks implementation into milestone-based work for view-once images/videos and listen-once audio.

---

## Milestone 0 — Product spec, contracts, and rollout guardrails

### MOM-001: Finalize one-time media product specification
**Scope**
- Lock policy decisions for open/play semantics per media type.
- Define group-chat semantics (per-recipient consume behavior).
- Define interrupted playback/open handling and retry rules.
- Define backup/restore and sender/recipient state visibility expectations.

**Acceptance criteria**
- Product spec is approved by product, backend, and client leads.
- Policy decisions are explicit for image, video, and audio variants.
- Edge-case behavior matrix exists for 1:1 and group chats.
- Specification is published in `docs/messaging-once-media-product-spec.md`.

**Dependencies**
- None.

---

### MOM-002: Define and publish API/schema contract updates
**Scope**
- Add and document contract fields:
  - `consumption_policy`
  - `media_kind`
  - `consumption_state`
  - `consumed_at`
  - `consumption_attempt_id`
- Define response/error contract for `already_consumed`, `grant_expired`, and retryable failures.
- Version contract for backward compatibility with non-once clients.

**Acceptance criteria**
- API contract docs are published in `docs/messaging-once-media-api-contract.md`.
- Schema artifact is published in `docs/messaging-once-media-schema-v1.json` and reviewed.
- Validation behavior is deterministic and documented.
- Legacy clients remain functional without once-media support.

**Dependencies**
- MOM-001.

---

### MOM-003: Add feature flags and kill-switch controls
**Scope**
- Add backend and client flags for once-media send/open features.
- Add per-media-type rollout toggles if needed (`image`, `video`, `audio`).
- Document emergency disable path.

**Acceptance criteria**
- Flag and kill-switch runbook is published in `docs/messaging-once-media-feature-flags-runbook.md`.
- When disabled, once-media composer toggles and consume flow are unavailable.
- Standard media paths remain unchanged when flag is off.
- Kill switch is validated in staging.

**Dependencies**
- MOM-001.

---

## Milestone 1 — Data model and persistence foundations

### MOM-010: Add persistence model for per-recipient consumption state
**Scope**
- Implement database schema changes for per-recipient consume tracking.
- Add indexed fields for `consumption_state` and `consumed_at` as needed.
- Ensure message storage supports image/video/audio once policies.

**Acceptance criteria**
- Per-recipient consumption state is persisted and queryable.
- Schema/bootstrap changes include `DDB_MESSAGE_CONSUMPTION` and backfill script `scripts/backfill_message_consumption_records.py`.
- Schema migration is backward compatible and rollback-safe.
- No behavior change for normal media messages.

**Dependencies**
- MOM-002.

---

### MOM-011: Update serializers/DTOs for once-media metadata
**Scope**
- Extend send/list/detail/realtime DTOs with once-media fields.
- Ensure omitted fields default correctly for non-once media.
- Ensure per-recipient state is accurately represented in responses.

**Acceptance criteria**
- New fields round-trip through API and realtime payloads.
- Existing non-once media payloads are unchanged (once-media fields omitted when policy is `none`).
- Payload parity tests cover list and realtime serializer contract shapes for once-media state.

**Dependencies**
- MOM-002, MOM-010.

---

## Milestone 2 — Backend one-time access enforcement

### MOM-020: Implement one-time media access grant endpoint
**Scope**
- Add server endpoint/service to issue short-lived media access grants.
- Enforce recipient authorization and policy checks.
- Attach strict no-store cache headers for once-media responses.

**Acceptance criteria**
- Authorized unconsumed recipients receive valid short-lived grants from `/messages/{message_id}/attachment/grant`.
- Unauthorized or invalid requests are rejected with documented error codes (`already_consumed`, `grant_expired`, `invalid_grant`).
- Once-media attachment responses set strict no-store cache headers.

**Dependencies**
- MOM-011.

---

### MOM-021: Implement atomic consume transition and idempotency
**Scope**
- Add transactional compare-and-set consumption transition.
- Add idempotent consume handling using `consumption_attempt_id`.
- Prevent double-consume across multi-device concurrent requests.

**Acceptance criteria**
- Exactly one successful consume transition occurs per recipient via conditional state transition (`pending` -> `consumed`).
- Concurrent opens/plays do not produce duplicate success states (subsequent conflicting attempts return `already_consumed`).
- Retries with the same `consumption_attempt_id` are idempotent and deterministic.

**Dependencies**
- MOM-010, MOM-020.

---

### MOM-022: Implement media-type-specific consume semantics
**Scope**
- Implement finalized consume trigger semantics from spec:
  - image: consume on open
  - video: consume on policy-defined threshold
  - audio: consume on policy-defined threshold
- Normalize consume state transition behavior across media handlers.

**Acceptance criteria**
- Image consume requires `trigger=open`; video/audio consume requires `trigger=play`.
- Video/audio consume requires playback thresholds and returns retryable `consume_threshold_not_met` before threshold.
- API trigger semantics align with client policy behavior with no per-media drift.

**Dependencies**
- MOM-001, MOM-021.

---

## Milestone 3 — Client UX and cross-device behavior

### MOM-030: Composer toggles for once-media send
**Scope**
- Add `View once` toggle for image/video attachments.
- Add `Listen once` toggle for audio recordings.
- Ensure toggles are policy-gated and do not affect normal media send.

**Acceptance criteria**
- Composer exposes `View once` (image/video when sender supports those media) and `Listen once` (audio recording when sender supports audio).
- Toggle state is reflected in outgoing payload metadata (`consumption_policy`).
- Toggle visibility obeys once-media feature flags and available send handlers.

**Dependencies**
- MOM-003, MOM-011.

---

### MOM-031: Conversation rendering for pending/consumed once-media states
**Scope**
- Add badges/labels for once-media bubbles.
- Render consumed state UI after successful consume.
- Provide clear error states for expired/already-consumed conditions.

**Acceptance criteria**
- Recipients can distinguish pending vs consumed once-media.
- Consumed messages are non-replayable in client UI.
- Error UX maps to backend error codes.

**Dependencies**
- MOM-011, MOM-022.

---

### MOM-032: Multi-device state sync and reconciliation
**Scope**
- Sync consumed state changes across recipient devices.
- Handle stale local state with deterministic refresh/reconcile behavior.
- Ensure second-device attempts show consumed/expired state quickly.

**Acceptance criteria**
- Consuming once-media on device A updates device B state promptly.
- Race conditions converge to one canonical consumed result.
- Manual refresh and reconnect paths reconcile correctly.

**Implementation notes**
- Messaging event stream invalidates per-conversation message queries for `message_consumed` / `once_media_consumed` / once-media state-change events.
- Conversation view performs deterministic refetch on browser reconnect (`online`) and foreground return (`visibilitychange`) to reconcile stale local state.
- Message queries refetch on reconnect/window focus so second-device attempts surface `consumed` or `expired` quickly.

**Dependencies**
- MOM-021, MOM-031.

---

## Milestone 4 — Security, privacy, and observability

### MOM-040: Security hardening for once-media delivery and playback
**Scope**
- Reduce forwarding/export vectors where policy allows.
- Minimize decrypted-media persistence in client storage.
- Validate sensitive data is excluded from logs/traces/crash reports.

**Acceptance criteria**
- Security review confirms agreed hardening controls are implemented.
- No sensitive media URLs/keys appear in logs.
- Known leakage vectors are documented with platform-specific constraints.

**Implementation notes**
- Once-media UI hides forwarding actions in conversation bubbles to reduce client-side forwarding/export vectors.
- Once-media playback/open uses short-lived grants plus credentialed `fetch(..., { cache: "no-store", referrerPolicy: "no-referrer" })`, then opens an ephemeral blob URL that is revoked to minimize persistence and avoid exposing grant URLs in browser history.
- Client-side error UX and telemetry avoid logging attachment grant tokens or signed once-media URLs; failures are surfaced with code-mapped generic user messages.
- Platform constraint: web clients cannot fully prevent OS/browser-level screen capture; threat model and support runbooks must document this residual leakage vector.

**Dependencies**
- MOM-020, MOM-030, MOM-031.

---

### MOM-041: Add once-media telemetry and dashboards
**Scope**
- Add low-cardinality metrics for send, consume success, consume failure.
- Track conflict/race metrics and grant latency.
- Build or update operational dashboard panels for rollout monitoring.

**Acceptance criteria**
- Metrics exist for each once-media type and major failure mode.
- Dashboard supports feature-flagged cohort monitoring.
- Telemetry excludes message content and secret material.

**Implementation notes**
- Backend exports low-cardinality counters for once-media send, grant, consume, and conflict/race outcomes, plus a grant-latency histogram segmented by `media_kind` and rollout `cohort`.
- Rollout cohort monitoring is driven by sanitized `X-Once-Media-Cohort` labels so operations can compare cohorts without introducing high-cardinality dimensions.
- Dashboard/alert panel queries are documented in `docs/messaging-once-media-observability.md`, and explicitly forbid message bodies, URLs/tokens, and encryption secrets in metric labels.

**Dependencies**
- MOM-021, MOM-022.

---

### MOM-042: Threat model and abuse/support runbook updates
**Scope**
- Update threat model for one-time media replay/token risks.
- Document moderation/support workflows for reported once-media content.
- Add operations guidance for incident response and rollback.

**Acceptance criteria**
- Threat model sign-off completed.
- Support and moderation runbooks are published and linked.
- Incident response checklist includes once-media kill switch procedures.

**Implementation notes**
- Threat model and sign-off are published in `docs/messaging-once-media-threat-model.md` with replay/token abuse risks, residual platform leakage constraints, and control mapping.
- Support/moderation procedures are published in `docs/messaging-once-media-support-moderation-runbook.md` (triage, evidence, escalation, enforcement).
- Incident response checklist explicitly includes the once-media kill switch path and links to `docs/messaging-once-media-feature-flags-runbook.md`.

**Dependencies**
- MOM-003, MOM-040.

---

## Milestone 5 — Validation and launch readiness

### MOM-050: Unit and contract test coverage
**Scope**
- Add unit tests for consume-state transitions and idempotency.
- Add contract tests for once-media API field correctness.
- Add parity tests between REST and realtime payloads.

**Acceptance criteria**
- Consume-state and idempotency tests cover happy-path and race-path cases.
- Contract tests fail on schema drift.
- Existing non-once media tests continue to pass.

**Implementation notes**
- Backend unit tests cover consume transitions for happy-path, idempotent replay, conflict/race (`already_consumed`), and missing-state error handling.
- Contract-drift tests assert once-media schema enums/types (`consumption_policy`, `media_kind`, `consumption_state`, `consumed_at`) stay aligned with `MessageOut`/consume request models.
- REST/realtime parity tests assert once-media state fields serialize consistently across list and event payloads.

**Dependencies**
- MOM-011, MOM-021.

---

### MOM-051: Integration/E2E scenarios for DM and group chats
**Scope**
- Add end-to-end tests for once-image, once-video, and once-audio flows.
- Add tests for multi-device concurrent consume attempts.
- Add offline/reconnect and interrupted playback/open tests.

**Acceptance criteria**
- E2E coverage confirms one-time behavior in 1:1 and group scenarios.
- Concurrent consume behavior is deterministic and policy-compliant.
- Regression tests verify normal media remains unaffected.

**Implementation notes**
- Backend integration-style tests cover DM/group once-image/video/audio flows, interrupted playback then retry behavior, and multi-device consume race outcomes.
- Frontend reconnection tests validate `online` and `visibilitychange` reconcile paths and once-media interrupted-playback error UX.
- Regression tests ensure non-once media send/list behavior remains unchanged when `consumption_policy=none`.

**Dependencies**
- MOM-022, MOM-032, MOM-050.

---

### MOM-052: Rollout checklist and staged release execution
**Scope**
- Define staged rollout cohorts and promotion criteria.
- Define SLO/SLI thresholds for consume success/failure and latency.
- Validate rollback/kill-switch steps before production expansion.

**Acceptance criteria**
- Launch checklist approved by product/engineering/security.
- Rollout progression criteria are explicit and measurable.
- Rollback drill completed in staging.

**Implementation notes**
- Rollout plan and launch checklist are published in `docs/messaging-once-media-rollout-checklist.md` with explicit cohort stages (`C0`→`C4`) and promotion gates.
- SLI/SLO thresholds for consume success/failure, conflict rate, and grant latency are defined with warning/critical alert thresholds.
- Staging rollback drill evidence (global kill switch disable + re-enable smoke checks) is captured in the rollout checklist.

**Dependencies**
- MOM-041, MOM-042, MOM-051.

---

## Suggested execution order
1. **Spec and guardrails:** MOM-001 → MOM-003
2. **Schema foundation:** MOM-010 → MOM-011
3. **Backend enforcement:** MOM-020 → MOM-022
4. **Client behavior:** MOM-030 → MOM-032
5. **Hardening and telemetry:** MOM-040 → MOM-042
6. **Validation and release:** MOM-050 → MOM-052

This sequence prioritizes early contract lock-in, server-authoritative guarantees, then client UX and staged rollout with measurable safety gates.
