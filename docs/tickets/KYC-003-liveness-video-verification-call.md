# KYC-003: Liveness Video Verification Call

**Ticket**: KYC-003
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 12-16 days
**Dependencies**: KYC-001 (Admin Review Dashboard), CALL-002 (RTCPeerConnection), CALL-009 (Call Recording)

---

## 1. Overview & Motivation

### Problem Statement

Document-based identity verification can be defeated by high-quality forgeries, stolen
documents, or AI-generated images. Regulatory frameworks (e.g., EU AML5D, FinCEN) increasingly
require financial platforms to perform **liveness verification** -- confirming that the person
submitting documents is physically present and matches the identity claimed. The current KYC
system (`app/routers/kyc_cases.py`, `app/services/kyc_cases.py`) has no mechanism to schedule
or conduct a live verification interview as part of the case workflow.

### Goals

1. Allow a verification video call to be scheduled as part of a KYC case review.
2. Implement a verifier pool: admins with a `kyc_verifier` scope who can conduct calls.
3. Auto-assign the next available verifier from the pool when a call is requested.
4. Integrate with the existing call lifecycle (`app/services/messaging_call_lifecycle.py`)
   and call recording (`app/services/messaging_call_sessions.py`).
5. Link call recording to the KYC case as evidence.
6. Allow the verifier to mark the call as passed/failed with structured notes.
7. Display verification call status, join button, and recording playback in the case detail page.

### User Stories

| # | As a... | I want to... | So that... |
|---|---------|-------------|-----------|
| 1 | KYC reviewer | Schedule a verification call for a case under review | I can visually confirm the applicant's identity |
| 2 | KYC verifier | See my upcoming verification call schedule | I can prepare for calls in advance |
| 3 | Applicant | See a scheduled verification call in my KYC case status | I know when to join the call |
| 4 | KYC verifier | Mark a call as passed or failed with notes | The result is recorded in the case |
| 5 | Compliance lead | See verification call recordings linked to KYC cases | I can audit call quality |
| 6 | Platform | Auto-assign verifiers from the pool | Load is distributed evenly |

---

## 2. Current State Analysis

### 2.1 Call Lifecycle

`app/services/messaging_call_lifecycle.py` manages the call state machine:
```
invited -> accepted -> connected -> ended
       -> declined / busy / canceled / failed / missed
```

Call sessions are stored in the `MessageCallSessions` DDB table (PK: `call_id`, no SK).
`CallSessionRecord` fields: `call_id`, `conversation_id`, `caller_user_id`, `callee_user_id`,
`initial_mode`, `state`, `start_ts`, `connect_ts`, `end_ts`, `end_reason`, `lifecycle_events`.

### 2.2 Call Recording

`app/services/messaging_call_sessions.py` tracks recording state. When recording is enabled,
the system stores `recording_s3_key` on the call session after the call ends. Recordings are
stored in S3 at `recordings/{call_id}/recording.webm`.

### 2.3 Calendar Integration

The calendar system (`app/routers/calendar.py`, `app/services/calendar.py`) supports event
creation with structured fields: `title`, `description`, `start_time`, `end_time`, `attendees`.
Calendar events are stored in the `calendar` DDB table (PK: `calendar_id`, SK: `event_id`).

### 2.4 Admin Scopes

`app/auth/roles.py` defines `AdminScope` enum (line 14). Current scopes:
`AUTH_SUPPORT`, `BILLING_SUPPORT`, `CONTENT_MODERATION`, `CONTENT_MODERATION_SENIOR`.
A new `KYC_VERIFIER` scope will be added for verifier pool membership.

### 2.5 KYC Case Structure

The case item in DDB stores nested objects for questionnaire, files, signature, submission,
and review. A new `verification_call` nested object will be added at the same level.

---

## 3. Technical Design

### 3.1 New Admin Scope

**File: `app/auth/roles.py`** -- add to `AdminScope`:

```python
class AdminScope(str, Enum):
    AUTH_SUPPORT = "auth_support"
    BILLING_SUPPORT = "billing_support"
    CONTENT_MODERATION = "content_moderation"
    CONTENT_MODERATION_SENIOR = "content_moderation_senior"
    KYC_VERIFIER = "kyc_verifier"  # new
```

Update `CANONICAL_ADMIN_SCOPES` tuple to include `AdminScope.KYC_VERIFIER`.

### 3.2 KYC Case Verification Call Field

New nested object on the KYC case item:

```python
{
    "verification_call": {
        "call_id": "call_abc123",
        "calendar_event_id": "evt_xyz789",
        "calendar_id": "cal_admin_kyc",
        "scheduled_at": 1716768000,
        "verifier_sub": "admin_user_sub",
        "status": "scheduled",       # scheduled | in_progress | completed | missed | canceled
        "result": null,               # passed | failed | inconclusive (set after call)
        "result_notes": null,
        "result_set_at": null,
        "recording_ref": null,        # S3 key of call recording
        "created_at": 1716681600,
        "updated_at": 1716681600,
    }
}
```

### 3.3 Verifier Pool Service

**File: `app/services/kyc_verifier_pool.py`** (new, ~150 lines)

```python
class KycVerifierPool:
    def list_verifiers(self) -> list[dict]:
        """Query admin profiles with KYC_VERIFIER scope."""

    def get_next_available_verifier(self, *, exclude_subs: list[str] | None = None) -> dict | None:
        """Return the verifier with the fewest active verification calls.
        Round-robin by active_call_count, breaking ties by last_assigned_at (oldest first)."""

    def get_verifier_schedule(self, *, verifier_sub: str, from_ts: int, to_ts: int) -> list[dict]:
        """Get scheduled verification calls for a verifier in a time range."""
```

The pool queries the `admin_roles` table for users with `kyc_verifier` scope, then
cross-references the `kyc_cases` table (via GSI on status=under_review) to count active
verification calls per verifier.

### 3.4 New Router Endpoints

**File: `app/routers/kyc_cases.py`** -- add endpoints:

```python
@router.post("/admin/cases/{case_id}/schedule-verification-call")
def schedule_verification_call(
    case_id: str,
    body: KycScheduleVerificationCallRequest,
    request: Request,
    _ctx: dict = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    """Schedule a verification video call for a KYC case.
    Auto-assigns a verifier from the pool if verifier_sub not specified.
    Creates a calendar event and a DM conversation for the call.
    Requires ADMIN or ROOT role."""

@router.post("/admin/cases/{case_id}/verification-call-result")
def set_verification_call_result(
    case_id: str,
    body: KycVerificationCallResultRequest,
    request: Request,
    _ctx: dict = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    """Record the result of a verification call (passed/failed/inconclusive).
    Only the assigned verifier or ROOT can set the result.
    Links call recording to the case if available."""

@router.get("/admin/verifiers")
def list_verifier_pool(
    request: Request,
    _ctx: dict = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    """List all admins in the KYC verifier pool with their active call counts."""

@router.get("/admin/verifiers/{verifier_sub}/schedule")
def get_verifier_schedule(
    verifier_sub: str,
    from_ts: int = Query(...),
    to_ts: int = Query(...),
    request: Request,
    _ctx: dict = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    """Get a verifier's scheduled verification calls in a time range."""

@router.get("/{case_id}/verification-call")
def get_verification_call_status(
    case_id: str,
    request: Request,
    _ctx: dict = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    """Get verification call status for the case owner's view.
    Shows scheduled_at, status, and join link (when applicable)."""
```

### 3.5 Request/Response Models

**File: `app/contracts/kyc_cases_contract.py`** -- add:

```python
class KycScheduleVerificationCallRequest(BaseModel):
    expected_version: int = Field(..., ge=1)
    scheduled_at: int = Field(..., description="Unix timestamp, must be >= now + 1 hour")
    verifier_sub: str | None = Field(default=None, description="Auto-assign if None")
    duration_minutes: int = Field(default=15, ge=5, le=60)
    note: str | None = Field(default=None, max_length=500)

class KycVerificationCallResultRequest(BaseModel):
    expected_version: int = Field(..., ge=1)
    result: Literal["passed", "failed", "inconclusive"]
    notes: str = Field(..., min_length=1, max_length=2000)
    recording_linked: bool = Field(default=True)
```

### 3.6 Scheduling Flow

```
Admin (reviewer)                    Backend                         Applicant
  |                                   |                                |
  |-- POST schedule-verification-call |                                |
  |   { scheduled_at, note }         |                                |
  |                                   |-- select verifier from pool    |
  |                                   |-- create calendar event        |
  |                                   |-- create DM conversation       |
  |                                   |   (verifier <-> applicant)     |
  |                                   |-- update case.verification_call|
  |                                   |-- audit_event                  |
  |<-- { call_id, verifier_sub,       |                                |
  |      calendar_event_id }          |                                |
  |                                   |-- send notification to         |
  |                                   |   applicant (alert)            |
  |                                   |                                |-- sees notification
  |                                   |                                |-- views KYC case status
  |                                   |                                |   (scheduled call shown)
```

### 3.7 Call Recording Linkage

When a verification call ends (state transitions to `ended`), a post-call hook checks if
the call is associated with a KYC case (by matching `call_id` against
`case.verification_call.call_id`). If so, the `recording_ref` on the verification_call
object is updated with the call session's `recording_s3_key`.

### 3.8 Frontend Changes

**File: `frontend/src/pages/admin/KycCaseDetailPage.tsx`** -- extend:

Add `VerificationCallPanel` component showing:
- Status badge (scheduled/in_progress/completed/missed/canceled)
- Scheduled date/time with verifier name
- "Join Call" button (active when call is in scheduled state and current time is within window)
- Call result display (passed/failed/inconclusive with notes)
- Recording playback widget (audio/video player for the recording)
- "Schedule Call" button (shown when no call is scheduled)

**File: `frontend/src/pages/kyc/KycCaseStatusPage.tsx`** -- extend:

Add verification call status section for the applicant:
- Scheduled date/time
- "Join Call" button when within 5 minutes of scheduled time
- Countdown timer to call
- Call result (if completed)

---

## 4. E2E Test Plan

**File**: `frontend/e2e/kyc-verification-call.spec.ts`
**Total**: ~18 tests across 4 sections (160-163)

### Section 160: Verification Call Scheduling API (5 tests)

```typescript
test("160.1 Admin schedules verification call for submitted case", async () => {
  // POST /v1/kyc/cases/admin/cases/{id}/schedule-verification-call
  // { scheduled_at: now + 3600, duration_minutes: 15 }
  // Verify 200, call_id returned, status=scheduled
});

test("160.2 Auto-assigns verifier when verifier_sub not provided", async () => {
  // Ensure at least one admin has kyc_verifier scope
  // Schedule call without verifier_sub
  // Verify verifier_sub is set in response
});

test("160.3 Schedule call with past timestamp returns 400", async () => {
  // POST with scheduled_at = now - 3600
  // Expect 400
});

test("160.4 Schedule call on non-existent case returns 404", async () => {
  // POST to /v1/kyc/cases/admin/cases/kyc_nonexistent/schedule-verification-call
  // Expect 404
});

test("160.5 Non-admin cannot schedule verification call", async () => {
  // Alice (USER) tries to schedule call
  // Expect 403
});
```

### Section 161: Verification Call Result API (5 tests)

```typescript
test("161.1 Verifier marks call as passed with notes", async () => {
  // POST /v1/kyc/cases/admin/cases/{id}/verification-call-result
  // { result: "passed", notes: "Identity confirmed visually", recording_linked: true }
  // Verify 200, verification_call.result = "passed"
});

test("161.2 Verifier marks call as failed", async () => {
  // { result: "failed", notes: "Person did not match ID photo" }
  // Verify result = "failed"
});

test("161.3 Verifier marks call as inconclusive", async () => {
  // { result: "inconclusive", notes: "Poor video quality, reschedule" }
  // Verify result = "inconclusive"
});

test("161.4 Wrong expected_version returns 409", async () => {
  // POST with expected_version=999
  // Expect 409
});

test("161.5 Setting result on case without scheduled call returns 400", async () => {
  // Case with no verification_call scheduled
  // Expect 400 or 409
});
```

### Section 162: Verifier Pool API (4 tests)

```typescript
test("162.1 List verifiers returns admins with kyc_verifier scope", async () => {
  // GET /v1/kyc/cases/admin/verifiers as Root
  // Verify array of verifiers with user_sub and active_call_count
});

test("162.2 Verifier schedule returns calls in time range", async () => {
  // GET /v1/kyc/cases/admin/verifiers/{sub}/schedule?from_ts=X&to_ts=Y
  // Verify includes the scheduled call from 160.1
});

test("162.3 Empty verifier pool returns empty array", async () => {
  // No admins with kyc_verifier scope
  // Verify empty array
});

test("162.4 Non-admin gets 403 on verifier pool listing", async () => {
  // GET verifiers as Alice
  // Expect 403
});
```

### Section 163: Applicant Verification Call View (4 tests)

```typescript
test("163.1 Case owner sees scheduled verification call status", async () => {
  // GET /v1/kyc/cases/{id}/verification-call as Alice
  // Verify status=scheduled, scheduled_at present
});

test("163.2 Call result visible to case owner after completion", async () => {
  // After verifier sets result
  // GET verification-call as Alice
  // Verify result=passed is visible
});

test("163.3 Non-owner gets 403 on verification call status", async () => {
  // Bob tries to view Alice's case verification call
  // Expect 403
});

test("163.4 Case with no verification call returns null/empty", async () => {
  // GET verification-call for case without scheduled call
  // Verify verification_call is null or status=none
});
```

---

## 5. File Change Summary

| File | Change Type | Description |
|------|-------------|-------------|
| `app/auth/roles.py` | Modify | Add `KYC_VERIFIER` scope to `AdminScope` enum |
| `app/services/kyc_verifier_pool.py` | **New** | Verifier pool management and auto-assignment |
| `app/services/kyc_cases.py` | Modify | Add verification_call field handling to case operations |
| `app/routers/kyc_cases.py` | Modify | Add 5 verification call endpoints |
| `app/contracts/kyc_cases_contract.py` | Modify | Add schedule/result request models and response types |
| `frontend/src/pages/admin/KycCaseDetailPage.tsx` | Modify | Add VerificationCallPanel component |
| `frontend/src/api/endpoints/kyc-admin.ts` | Modify | Add verification call API functions |
| `frontend/e2e/kyc-verification-call.spec.ts` | **New** | 18 E2E tests across sections 160-163 |
