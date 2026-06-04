# KYC-025: KYC Decision Appeals / Disputes

**Ticket**: KYC-025
**Author**: Engineering
**Status**: Open
**Date**: 2026-06-04
**Priority**: Medium
**Estimated effort**: 5-7 days
**Dependencies**: KYC-001 (case workflow), KYC-024 (analytics dashboard), KYC-023 (data encryption)

---

## 1. Overview & Motivation

### 1.1 Problem Statement

The KYC system supports **retry/resubmission** (an admin can move a case to
`needs_more_info`, the user reuploads, and it returns to `under_review`), but it
has **no dispute/appeal path** for a *rejected* decision. Today `rejected` is a
terminal state:

- `app/services/kyc_cases.py` (~line 608-615) rejects any transition out of
  `approved`/`rejected` except an idempotent re-application of the same decision,
  and admin decisions can only be applied from `under_review`.
- There are no `appeal`, `dispute`, `contest`, `escalate`, or `reopen` endpoints
  in `app/routers/kyc_cases.py`.
- Rejected cases are eligible for retention purge after
  `kyc_retention_rejected_days` (`kyc_cases.py` ~line 818), so the record may not
  even persist.

A user who is wrongly rejected (bad OCR, a transient document issue, a
false-positive sanctions hit) has **no recourse** and no way to escalate to a
human reviewer. This is both a UX gap and a compliance concern — most KYC/AML
programs require a documented appeals/redress process.

### 1.2 How It Works (proposed)

Introduce an explicit appeal lifecycle layered on top of the existing case state
machine:

1. After a case is `rejected`, the user sees the rejection reason and an
   **"Appeal this decision"** action (available within an `appeal_window_days`
   window before purge).
2. User submits an appeal: a free-text justification + optional new supporting
   documents. The case transitions `rejected → appealed` and an appeal record is
   attached.
3. The appeal lands in an **admin appeals queue** (extension of the existing
   `/admin/cases` queue, filterable by `status=appealed`).
4. An admin (ideally a different reviewer than the original decision-maker — a
   `four_eyes` flag) reviews the appeal and either:
   - **Upholds** the rejection → `appealed → rejected` (terminal again; appeal
     recorded with reason), or
   - **Overturns** → `appealed → under_review` (re-enters normal review, where it
     can then be approved or request more info), or
   - **Approves directly** → `appealed → approved`.
5. All appeal actions are written to the case audit trail and surfaced in the
   KYC analytics funnel (KYC-024) as an appeals/overturn-rate metric.

### 1.3 Design Principles

- **Non-destructive to existing flow**: `needs_more_info` retry stays exactly as
  is; appeals only add transitions out of the previously-terminal `rejected`.
- **Bounded**: One appeal per case (configurable), within `appeal_window_days`;
  prevents indefinite re-litigation. Purge of rejected cases is deferred while an
  appeal is open.
- **Four-eyes**: Appeal review should default to a reviewer other than the
  original decision-maker (configurable).
- **Audited & measurable**: Every appeal + outcome is in the audit log and the
  analytics dashboard.

---

## 2. Implementation

### 2.1 State machine (`app/services/kyc_cases.py`)

- Add `appealed` to the status enum.
- New transitions:
  - `rejected → appealed` (user-initiated `submit_appeal`, within window, ≤ max appeals).
  - `appealed → under_review` (admin overturn / re-review).
  - `appealed → rejected` (admin uphold).
  - `appealed → approved` (admin direct approve).
- Guard purge: a case with an open appeal (`status == "appealed"`) is **not**
  retention-eligible.
- Persist an appeal sub-record: `{ appeal_id, submitted_at, justification,
  document_ids, reviewer_sub, decision, decided_at, reason }`.

### 2.2 API (`app/routers/kyc_cases.py`)

- `POST /ui/kyc/cases/{case_id}/appeal` — user submits appeal (justification +
  optional file attachments via the existing files endpoint).
- `GET /admin/kyc/cases?status=appealed` — appeals queue (reuse existing list).
- `POST /admin/kyc/cases/{case_id}/appeal/decision` — `{ decision:
  uphold|overturn|approve, reason }`, four-eyes enforced.
- Map invalid transitions to the existing `kyc_invalid_transition` error.

### 2.3 Settings (`app/core/settings.py`)

- `KYC_APPEALS_ENABLED` (feature flag, default true in dev).
- `KYC_APPEAL_WINDOW_DAYS` (default 30).
- `KYC_MAX_APPEALS_PER_CASE` (default 1).
- `KYC_APPEAL_FOUR_EYES` (default true).

### 2.4 Frontend

- **User**: On the KYC status page (`kyc-self-service`), when `status==rejected`
  and within the window, show rejection reason + "Appeal this decision" →
  appeal form (justification + reupload). Show appeal status once submitted.
- **Admin**: Appeals tab/filter in the KYC admin dashboard (KYC-024); appeal
  detail with original decision, justification, new docs, and
  uphold/overturn/approve actions.

### 2.5 Analytics (KYC-024)

- Add appeal-submitted count, overturn rate, and time-to-appeal-resolution to the
  funnel dashboard.

---

## 3. Testing

- **E2E** (`frontend/e2e/kyc-appeals.spec.ts`, new): reject → user appeals →
  admin overturn → case back to `under_review` → approve; reject → appeal →
  admin upholds → terminal; appeal window expiry → appeal blocked; second appeal
  blocked when `max_appeals=1`; four-eyes (original reviewer cannot decide the
  appeal).
- **pytest**: state-machine transition tests for every new edge + purge-deferral
  while appealed.

## 4. Out of Scope

- The existing `needs_more_info` retry/resubmission flow (already implemented).
- External regulator reporting of appeal outcomes (future compliance ticket).
