# KYC Disputes & Retry — Implementation Tickets

Today a KYC case is terminal once an admin rejects it (`app/services/kyc_cases.py:635` blocks any transition out of `approved`/`rejected`) and `expired` is a dead end, so a user has no way to contest a decision or re-attempt a failed application. This backlog adds a user-initiated **dispute/appeal** flow, a **reopen + resubmit** flow with attempt limits, an **admin dispute-review queue**, new webhook/notification events, and the supporting audit/versioning + frontend work.

## Milestone 1 — Backend state model & versioning

### KYD-001: Add dispute/reopen statuses + feature flags to the case state model
**Type:** Chore  
**Priority:** P0  
**Estimate:** 1 day

**Description**
- Extend `_ALLOWED_STATUSES` (`app/services/kyc_cases.py:33-41`) with `disputed` (a rejected case under appeal) and decide whether reopen reuses the existing `draft`/`needs_more_info` states or adds a `reopened` state — recommend reusing `draft` so the wizard (`KycWizardPage.tsx`) and `submit_case`'s `draft|needs_more_info` gate (`app/services/kyc_cases.py:382`, `app/services/kyc_cases.py:419`) work unchanged.
- Add settings to `app/core/settings.py` next to the existing KYC flags (`app/core/settings.py:1268-1271`): `kyc_dispute_enabled` (default true), `kyc_retry_enabled` (default true), `kyc_retry_max_attempts` (default 3), `kyc_dispute_window_days` (default 30), mirroring the `KYC_*` env-var pattern.
- Document the new transitions in the module docstring: `rejected → disputed` (user), `rejected|expired → draft` (user reopen), `disputed → approved|rejected|needs_more_info` (admin).

**Acceptance Criteria**
- New statuses validate through `create_case`/`update_case_status` without raising `KycCaseValidationError("invalid_kyc_case_status")`.
- All new settings resolve from env vars and have safe defaults; flags off ⇒ existing behavior is byte-for-byte unchanged.
- No existing test in `tests/test_kyc_cases_store.py` regresses.

**Dependencies**
- None.

---

### KYD-002: `KycCaseStore.dispute_case` service method
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Add `dispute_case(case_id, owner_sub, expected_version, reason, note)` to `KycCaseStore` (`app/services/kyc_cases.py:110`), modeled on `apply_admin_decision` (`app/services/kyc_cases.py:613`) for the optimistic-concurrency + conditional-write pattern.
- Only allow `rejected → disputed` (and idempotent replay when already `disputed` with the same dispute hash, mirroring the decision-hash dedupe at `app/services/kyc_cases.py:636-640`); reject from any other status with `KycCaseValidationError("kyc_invalid_transition")`.
- Persist a `review.dispute` sub-map (`reason`, `note`, `disputed_at`, `disputed_by`, `dispute_hash`, `dispute_count`) alongside the existing `review` map (`app/services/kyc_cases.py:85-94`); bump `version` and update `gsi_status_*` keys exactly as `apply_admin_decision` does so the admin queue index stays consistent.
- Enforce `kyc_dispute_window_days` against `review.decided_at` (`app/services/kyc_cases.py:652`); reject expired windows with a dedicated validation code.
- Emit `kyc.case.disputed` via `_emit_kyc_event_safe` (`app/services/kyc_cases.py:20`) after the successful write, following the placement rule from CLAUDE.md GAP-0272 (after `update_item`, before `return self.get_case(...)`).

**Acceptance Criteria**
- `rejected → disputed` succeeds, bumps version by 1, and writes `review.dispute`.
- Replaying the same dispute (same hash) returns the existing case and emits no second event.
- Disputing a non-rejected case, a stale version, or outside the dispute window each raises the correct typed error.

**Dependencies**
- KYD-001.

---

### KYD-003: `KycCaseStore.reopen_case` service method with attempt limits
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Add `reopen_case(case_id, owner_sub, expected_version)` to `KycCaseStore` (`app/services/kyc_cases.py:110`) that transitions `rejected|expired → draft`, clears `submission` (`app/services/kyc_cases.py:97-102`) and the prior `review.decision`/`reason_codes` so the case re-enters the wizard cleanly, and bumps `version`.
- Track `review.attempt_count` (incremented on each reopen) and enforce `S.kyc_retry_max_attempts`; once exhausted raise a typed `kyc_retry_limit_reached` error rather than transitioning.
- Preserve previously-attached `files` and `questionnaire` refs so the user can edit rather than redo from scratch (the file-attach endpoint already allows `draft` — `app/routers/kyc_cases.py:1174`).
- Use a `ConditionExpression` gating on `version` + `status IN (rejected, expired)`, matching the `submit_case` conditional-write style (`app/services/kyc_cases.py:419`).
- Emit `kyc.case.resubmitted` is NOT emitted here (reopen ≠ resubmit); only the eventual `/submit` re-emits `kyc.case.submitted`. Emit a lightweight `kyc.case.reopened` internal audit only (no user webhook) — see KYD-007 for the resubmit event.

**Acceptance Criteria**
- `rejected → draft` and `expired → draft` both succeed and reset submission/decision fields while preserving files/questionnaire.
- `attempt_count` increments; exceeding `kyc_retry_max_attempts` raises `kyc_retry_limit_reached` and leaves the case unchanged.
- Stale version ⇒ `KycCaseConflictError`; non-reopenable status ⇒ `KycCaseValidationError("kyc_invalid_transition")`.

**Dependencies**
- KYD-001.

---

### KYD-004: Admin dispute decision via `apply_admin_decision`
**Type:** Feature  
**Priority:** P1  
**Estimate:** 1 day

**Description**
- Widen `apply_admin_decision` (`app/services/kyc_cases.py:613`) so a `disputed` case can transition to `approved`/`rejected` (currently the guard at `app/services/kyc_cases.py:642` requires `under_review`). Add `disputed` to the allowed source states; keep the terminal-replay dedupe intact (`app/services/kyc_cases.py:635`).
- Allow `request_more_info` (`app/services/kyc_cases.py:540`) to act on a `disputed` case so a reviewer can ask for more during an appeal (route the resulting `needs_more_info → submit` back through the normal flow).
- Persist `review.dispute_resolution` (`outcome`, `resolved_at`, `resolved_by`) when a disputed case is decided, distinct from the original `review.decision`, so the audit trail shows both the original rejection and the appeal outcome.

**Acceptance Criteria**
- `disputed → approved` and `disputed → rejected` succeed and record `review.dispute_resolution`.
- The original `review.decision`/`decided_at` from the first rejection are preserved (not overwritten) so history is auditable.
- Existing `under_review → approved|rejected` path is unaffected.

**Dependencies**
- KYD-002.

---

## Milestone 2 — API surface

### KYD-005: User dispute + reopen endpoints
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Add `POST /v1/kyc/cases/{case_id}/dispute` and `POST /v1/kyc/cases/{case_id}/reopen` to `app/routers/kyc_cases.py`, declared **before** any catch-all `/{case_id}` segment is not an issue here (these are sub-paths), but keep them grouped with the other user case mutations (`app/routers/kyc_cases.py:1159-1361`).
- Both enforce ownership (`case.get("user_sub") != user.sub` ⇒ `kyc_access_forbidden`, mirroring `app/routers/kyc_cases.py:1267-1269`), the `kyc_dispute_enabled`/`kyc_retry_enabled` flags (503/feature-disabled when off), and CSRF via `require_ui_session` (already the dependency on every mutation here).
- Add request contracts to `app/contracts/kyc_cases_contract.py` next to `KycSubmitCaseRequest` (`app/contracts/kyc_cases_contract.py:103`): `KycDisputeRequest{expected_version, reason, note}` and `KycReopenRequest{expected_version}`.
- Map service errors to envelopes via `_raise_kyc_error` (`app/routers/kyc_cases.py:89`): conflict→`kyc_case_update_conflict`, invalid transition→`kyc_invalid_transition`, retry exhaustion→a new `kyc_retry_limit_reached` code in `kyc_error_envelope`/`kyc_error_http_status` (409).
- Emit audit via `_audit_state_transition` (`app/routers/kyc_cases.py:119`) with `action="dispute"`/`action="reopen"`, and `_emit_kyc_metric` `kyc_funnel_transition` (`app/routers/kyc_cases.py:143`).

**Acceptance Criteria**
- `POST .../dispute` on a rejected owned case returns the updated `KycCaseEnvelope` with `status="disputed"`.
- `POST .../reopen` on a rejected/expired owned case returns `status="draft"`; an over-limit reopen returns HTTP 409 `kyc_retry_limit_reached`.
- Non-owner ⇒ 403; flag disabled ⇒ feature-disabled error; stale version ⇒ 409 conflict.

**Dependencies**
- KYD-002, KYD-003.

---

### KYD-006: Admin dispute-review queue + decision endpoints
**Type:** Feature  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Extend the admin queue (`GET /v1/kyc/cases/admin/queue`, `app/routers/kyc_cases.py:1363`) to include `disputed` in its default status set (`app/routers/kyc_cases.py:1379`) and accept `status=disputed` as a filter so reviewers can triage appeals. Surface `review.dispute.reason`/`disputed_at` in `STORE.list_admin_queue` output for sorting.
- Reuse the existing `POST /admin/cases/{case_id}/approve` and `/reject` endpoints (`app/routers/kyc_cases.py:1684-1703`) for dispute decisions now that KYD-004 widened the service layer — no new endpoint needed for the decision itself, but verify scope enforcement `_is_scoped_admin_for_case` (`app/routers/kyc_cases.py:97`) still applies.
- Add `review.dispute` to the admin case-detail payload `_build_admin_case_detail` (`app/routers/kyc_cases.py:614`) and append a `kyc_case_disputed` event to its `timeline` (`app/routers/kyc_cases.py:622`) so admins see when/why the appeal was raised.

**Acceptance Criteria**
- `GET /admin/queue` (and `?status=disputed`) returns disputed cases with dispute metadata; non-admin ⇒ `kyc_admin_role_required`.
- Admin `approve`/`reject` of a `disputed` case succeeds and records `review.dispute_resolution`.
- Admin case detail shows the dispute reason and a `kyc_case_disputed` timeline entry.

**Dependencies**
- KYD-004.

---

## Milestone 3 — Notifications, audit & versioning

### KYD-007: New webhook + notification event types
**Type:** Feature  
**Priority:** P1  
**Estimate:** 1 day

**Description**
- Register `kyc.case.disputed` and `kyc.case.resubmitted` in `WEBHOOK_EVENT_TYPES_V2` (`app/services/webhook_service.py:60`, alongside the existing `kyc.case.*` entries at `app/services/webhook_service.py:146-150`) so subscriptions validate and they flow into `KYC_WEBHOOK_EVENT_TYPES` (`app/services/webhook_service.py:183`).
- Add alert titles (`_ALERT_TITLES`, `app/services/kyc_webhooks.py:37`) and email subjects (`_EMAIL_SUBJECTS`, `app/services/kyc_webhooks.py:58`) for both. Add `kyc.case.disputed` to `_ADMIN_EVENTS` (`app/services/kyc_webhooks.py:66`) so reviewers get the compliance audit alert.
- Emit `kyc.case.resubmitted` from `submit_case` (`app/services/kyc_cases.py:428`) when the case being submitted has `review.attempt_count > 0` (i.e. it's a retry, not a first submission); otherwise keep emitting `kyc.case.submitted` as today.
- Add per-event message bodies in `emit_kyc_event` (`app/services/kyc_webhooks.py:191`, see the `if event == ...` blocks around `app/services/kyc_webhooks.py:317`), flattening list payloads to comma-joined strings per the existing convention.

**Acceptance Criteria**
- Both events appear in the webhook event-type registry and pass `is_kyc_event` validation.
- Disputing a case fires `kyc.case.disputed` (user alert + admin audit); resubmitting after a reopen fires `kyc.case.resubmitted`.
- A first-time submission still fires only `kyc.case.submitted`.

**Dependencies**
- KYD-002, KYD-003.

---

### KYD-008: Audit trail + versioning for dispute/retry lifecycle
**Type:** Chore  
**Priority:** P1  
**Estimate:** 1 day

**Description**
- Ensure every new transition writes a `_audit_state_transition` event (`app/routers/kyc_cases.py:119`) with `from`/`to`/`action` and a `correlation_id` so the existing KYC audit feed captures disputes and reopens.
- Verify `version` is bumped on `dispute_case`/`reopen_case`/`apply_admin_decision`(dispute path) and NOT bumped on annotation-only writes, matching the documented rule for `escalate_case` (`app/services/kyc_cases.py:698-733`).
- Confirm `review.attempt_count`, `review.dispute`, and `review.dispute_resolution` are returned by `get_case` and exposed (or deliberately masked) on the user-facing `KycCaseEnvelope` (`app/contracts/kyc_cases_contract.py:74`) and admin detail.
- Locale-aware emails: route dispute/resubmit notifications through `_send_kyc_notification_email` (`app/routers/kyc_cases.py:787`) with new `event` keys so they localize like approve/reject/needs-info do.

**Acceptance Criteria**
- Audit events for `dispute`/`reopen`/dispute-decision are written and queryable by `kyc_case_id`.
- Optimistic-concurrency invariants hold (version monotonic across the lifecycle; concurrent stale writes ⇒ conflict).
- Dispute/resubmit emails resolve the user's locale via `kyc_translation_service` and fall back to English when no template is seeded.

**Dependencies**
- KYD-005, KYD-006, KYD-007.

---

## Milestone 4 — Frontend

### KYD-009: KycStatusPage "Dispute" + "Try again" actions
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- In `HistoricalCaseCard` (`frontend/src/pages/kyc/KycStatusPage.tsx:168`) replace the bare "Start New" link (`frontend/src/pages/kyc/KycStatusPage.tsx:185-189`) with two actions on `rejected` cases: **Try again** (calls reopen → navigates into the wizard) and **Dispute** (opens a reason/note dialog → calls dispute). Show **Try again** on `expired` cases too.
- Add endpoint wrappers `disputeKycCase` / `reopenKycCase` to `frontend/src/api/endpoints/kyc-cases.ts` (`BASE` is already `/v1/kyc/cases`, `frontend/src/api/endpoints/kyc-cases.ts:13`) and the `KycCaseStatus` union (`frontend/src/api/types.ts:11486`) gains `"disputed"`.
- Use React Query mutations with `qc.invalidateQueries({ queryKey: ["kyc", "cases"] })` on success (mirror `ReuploadControl`, `frontend/src/pages/kyc/KycStatusPage.tsx:95-135`); surface `kyc_retry_limit_reached` as a friendly "no attempts left" toast via `ApiError.detail`.
- Render a `disputed` badge/branch in `statusBadgeClass` (`frontend/src/pages/kyc/KycStatusPage.tsx:23`) and the timeline (`frontend/src/pages/kyc/KycStatusPage.tsx:40-44`); show the dispute reason for an active disputed case in `ActiveCaseCard` (`frontend/src/pages/kyc/KycStatusPage.tsx:137`).

**Acceptance Criteria**
- A rejected case shows **Try again** and **Dispute**; clicking Try again reopens and lands in the wizard, clicking Dispute submits a reason and moves the case to `disputed`.
- An expired case shows **Try again** only; over-limit retry shows a clear toast and no navigation.
- The `disputed` status renders with a distinct badge and appears in the active section.

**Dependencies**
- KYD-005.

---

### KYD-010: Wizard reuse for reopened cases
**Type:** Feature  
**Priority:** P1  
**Estimate:** 1 day

**Description**
- Confirm `KycWizardPage` (`frontend/src/pages/kyc/KycWizardPage.tsx`) picks up a reopened (now `draft`) case via its existing draft lookup (`frontend/src/pages/kyc/KycWizardPage.tsx:91`) and pre-fills attached files/questionnaire (`hasFileType`, `frontend/src/pages/kyc/KycWizardPage.tsx:454-507`) preserved by KYD-003 — no redo-from-scratch.
- Show a banner on a reopened case ("Editing a previous attempt — N attempts remaining") sourced from `review.attempt_count` + `kyc_retry_max_attempts`, and route the final `submitKycCase` (`frontend/src/pages/kyc/KycWizardPage.tsx:652-653`) unchanged (it re-uses `expected_version: c.version`).
- Ensure the resubmit flow’s `kyc.case.resubmitted` event (KYD-007) is reflected in the user’s notification feed (no FE change beyond verifying the existing notifications list renders it).

**Acceptance Criteria**
- Reopening a rejected case opens the wizard with previously-uploaded docs still attached and editable.
- The attempts-remaining banner reflects the backend count and hides when retry is unlimited/disabled.
- Submitting a reopened case transitions it back to `submitted`/`under_review` and shows in the active section.

**Dependencies**
- KYD-009.

---

## Milestone 5 — Tests

### KYD-011: Offline hermetic backend tests
**Type:** Chore  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Add `tests/test_kyc_dispute_retry.py` following the KYC test conventions in CLAUDE.md and `tests/test_gap_0272_0273_kyc_decision_events.py:1-40`: inject a `_FakeTable` into `KycCaseStore(_table=...)` (no moto/@mock_aws, no real AWS), toggle frozen `S` flags via `object.__setattr__`, and spy `_emit_kyc_event_safe` by monkeypatching the module-level helper (`app/services/kyc_cases.py:20`).
- Cover: `dispute_case` happy path + idempotent replay + window expiry + wrong-status; `reopen_case` happy path (rejected & expired) + attempt-limit exhaustion + field-reset/file-preservation; `apply_admin_decision` from `disputed`; event emission for `kyc.case.disputed`/`kyc.case.resubmitted`; version monotonicity + conflict on stale version.
- Add a router-level test (handlers called directly with stubbed deps, per the GAP-0262 pattern) asserting 403 for non-owner, 409 for `kyc_retry_limit_reached`, and feature-flag gating.

**Acceptance Criteria**
- All new tests pass under `.venv/bin/pytest tests/test_kyc_dispute_retry.py` with no network/AWS access.
- Tests assert the right event fires per transition and that idempotent replays emit only once.
- Frozen table/settings handles are restored on cleanup (no cross-test leakage).

**Dependencies**
- KYD-002, KYD-003, KYD-004, KYD-007.

---

### KYD-012: Playwright E2E for dispute/retry
**Type:** Chore  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Add `frontend/e2e/kyc-dispute-retry.spec.ts` seeding a rejected case directly via DynamoDB / session auth (per the E2E patterns in CLAUDE.md), then driving the `KycStatusPage` **Dispute** and **Try again** actions (`data-testid="kyc-historical-case"`, plus new testids for the buttons/dialog).
- Verify: dispute moves the card to the active section as `disputed`; reopen lands in the wizard with docs pre-filled (`data-testid` from `frontend/src/pages/kyc/KycWizardPage.tsx`); over-limit retry surfaces the toast; admin queue (`GET /admin/queue?status=disputed`) lists the disputed case.
- Use `x-csrf-token` headers for `page.request` POSTs and re-seed sessions per the admin/user E2E setup scripts.

**Acceptance Criteria**
- Spec runs green under `cd frontend && npx playwright test e2e/kyc-dispute-retry.spec.ts`.
- Covers user dispute, user retry (success + over-limit), and admin appears-in-queue paths.
- No reliance on cross-test shared state; unique per-run identifiers avoid strict-mode violations.

**Dependencies**
- KYD-006, KYD-009, KYD-010.

---
