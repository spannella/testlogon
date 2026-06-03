# KYC-003: Liveness Video Verification Call

**Ticket**: KYC-003
**Author**: Engineering
**Status**: Implemented
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
system (see `app/routers/kyc_cases.py:519` for `create_kyc_case`, `app/services/kyc_cases.py:97` for `create_case`) has no mechanism to schedule
or conduct a live verification interview as part of the case workflow.

### Goals

1. Allow a verification video call to be scheduled as part of a KYC case review.
2. Implement a verifier pool: admins with a `kyc_verifier` scope who can conduct calls.
3. Auto-assign the next available verifier from the pool when a call is requested.
4. Integrate with the existing call lifecycle (see `app/services/messaging_call_lifecycle.py:334` for `end_call`)
   and call recording (see `app/services/messaging_call_sessions.py:133` for `create_call_session`).
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

## 2. Architecture Diagram

```
┌────────────────────────────────────────────────────────────────────────┐
│                       Frontend                                         │
│                                                                        │
│  KycCaseDetailPage (admin)              KycCaseStatusPage (applicant)  │
│  ┌──────────────────────────┐          ┌──────────────────────────┐   │
│  │ VerificationCallPanel    │          │ ScheduledCallBanner      │   │
│  │  ├─ StatusBadge          │          │  ├─ Countdown Timer      │   │
│  │  ├─ ScheduledDateTime    │          │  ├─ "Join Call" Button   │   │
│  │  ├─ VerifierName         │          │  └─ CallResult (after)   │   │
│  │  ├─ "Schedule Call" btn  │          └──────────────────────────┘   │
│  │  ├─ "Join Call" btn      │                                         │
│  │  ├─ CallResult display   │                                         │
│  │  └─ RecordingPlayer      │                                         │
│  └──────────────────────────┘                                         │
└──────────────────┬─────────────────────────────┬──────────────────────┘
                   │                             │
                   ▼                             ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     Backend (FastAPI)                                   │
│                                                                        │
│  kyc_cases.py (extended)                                              │
│  ┌──────────────────────────────────────────────────────────────┐     │
│  │ POST /admin/cases/{id}/schedule-verification-call            │     │
│  │ POST /admin/cases/{id}/verification-call-result              │     │
│  │ GET  /admin/verifiers                                        │     │
│  │ GET  /admin/verifiers/{sub}/schedule                         │     │
│  │ GET  /{case_id}/verification-call                            │     │
│  └──────────────────────────────────────────────────────────────┘     │
│                                                                        │
│  kyc_verifier_pool.py (NEW)              messaging_call_lifecycle.py  │
│  ┌─────────────────────────────┐        ┌─────────────────────┐      │
│  │ list_verifiers()            │        │ create_call()        │      │
│  │ get_next_available()        │        │ accept_call()        │      │
│  │ get_verifier_schedule()     │        │ end_call()           │      │
│  └─────────────────────────────┘        └─────────────────────┘      │
│                                                                        │
│  calendar.py                            messaging_call_sessions.py   │
│  ┌────────────────────┐                ┌──────────────────────┐      │
│  │ create_event()     │                │ recording_s3_key     │      │
│  │ get_event()        │                │ post-call hook       │      │
│  └────────────────────┘                └──────────────────────┘      │
└──────────────────┬─────────────────────────────────────────────────────┘
                   │
                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│                      DynamoDB                                          │
│  ┌──────────────┐  ┌─────────────┐  ┌──────────────┐  ┌───────────┐ │
│  │ kyc_cases     │  │ admin_roles │  │ calendar     │  │ call      │ │
│  │ verification_ │  │ KYC_VERIFIER│  │ cal_id,      │  │ sessions  │ │
│  │ call nested   │  │ scope       │  │ event_id     │  │ call_id   │ │
│  └──────────────┘  └─────────────┘  └──────────────┘  └───────────┘ │
└────────────────────────────────────────────────────────────────────────┘
                                          │
                                          ▼
┌────────────────────────────────────────────────────────────────────────┐
│                      S3 (moto mock)                                    │
│  recordings/{call_id}/recording.webm                                  │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Current State Analysis

### 3.1 Call Lifecycle

`app/services/messaging_call_lifecycle.py` (see `:334` for `end_call`) manages the call state machine:
```
invited -> accepted -> connected -> ended
       -> declined / busy / canceled / failed / missed
```

Call sessions are stored in the `MessageCallSessions` DDB table (PK: `call_id`, no SK).
`CallSessionRecord` fields: `call_id`, `conversation_id`, `caller_user_id`, `callee_user_id`,
`initial_mode`, `state`, `start_ts`, `connect_ts`, `end_ts`, `end_reason`, `lifecycle_events`.

### 3.2 Call Recording

`app/services/messaging_call_sessions.py` (see `:19` for `CallSessionRecord`, `:133` for `create_call_session`) tracks recording state. When recording is enabled,
the system stores `recording_s3_key` on the call session after the call ends. Recordings are
stored in S3 at `recordings/{call_id}/recording.webm`.

### 3.3 Calendar Integration

The calendar system (`app/routers/calendar.py`, `app/services/calendar.py`) supports event
creation with structured fields: `title`, `description`, `start_time`, `end_time`, `attendees`.
Calendar events are stored in the `calendar` DDB table (PK: `calendar_id`, SK: `event_id`).

### 3.4 Admin Scopes

`app/auth/roles.py` defines `AdminScope` enum (see `app/auth/roles.py:14`). Current scopes:
`AUTH_SUPPORT`, `BILLING_SUPPORT`, `CONTENT_MODERATION`, `CONTENT_MODERATION_SENIOR` (see `app/auth/roles.py:26-30`).
A new `KYC_VERIFIER` scope will be added for verifier pool membership.
<!-- NOTE: KYC_VERIFIER scope does not exist yet -- new implementation required -->

### 3.5 KYC Case Structure

The case item in DDB stores nested objects for questionnaire, files, signature, submission,
and review. A new `verification_call` nested object will be added at the same level.

---

## 4. DynamoDB Access Patterns

| Access Pattern | Table | PK | SK / GSI | Notes |
|---------------|-------|-----|----------|-------|
| Get case verification call | `kyc_cases` | `KYC#{case_id}` | `META` → nested `verification_call` | Part of case record |
| List verifiers | `admin_roles` | GSI `ByScope` PK=`kyc_verifier` | All items | Filter active admins |
| Count active calls per verifier | `kyc_cases` | GSI `status-updated-index` PK=`STATUS#under_review` | Filter `verification_call.verifier_sub` | Cross-reference |
| Get verifier schedule | `calendar` | `cal_admin_kyc` | SK range `evt_` + time range | Calendar event query |
| Get call recording | `MessageCallSessions` | `call_id` | — | Get `recording_s3_key` |

### Example: Verification Call Nested Object

```json
{
  "verification_call": {
    "call_id": "call_abc123def456",
    "calendar_event_id": "evt_xyz789abc",
    "calendar_id": "cal_admin_kyc",
    "scheduled_at": 1716768000,
    "duration_minutes": 15,
    "verifier_sub": "root.admin@testdev.local",
    "status": "scheduled",
    "result": null,
    "result_notes": null,
    "result_set_at": null,
    "recording_ref": null,
    "created_at": 1716681600,
    "updated_at": 1716681600
  }
}
```

---

## 5. API Request/Response Examples

### 5.1 Schedule Verification Call

```bash
curl -X POST "http://localhost:8000/v1/kyc/cases/admin/cases/kyc_a1b2c3d4/schedule-verification-call" \
  -H "Cookie: ui_session=sess_root; ui_access_token=eyJ...; ui_csrf=csrf_r" \
  -H "x-csrf-token: csrf_r" \
  -H "Content-Type: application/json" \
  -d '{
    "expected_version": 3,
    "scheduled_at": 1716768000,
    "duration_minutes": 15,
    "verifier_sub": null,
    "note": "Verify identity match for enhanced profile"
  }'
```

**Response (200):**
```json
{
  "ok": true,
  "call_id": "call_abc123def456",
  "verifier_sub": "root.admin@testdev.local",
  "calendar_event_id": "evt_xyz789abc",
  "scheduled_at": 1716768000,
  "status": "scheduled"
}
```

### 5.2 Set Verification Call Result

```bash
curl -X POST "http://localhost:8000/v1/kyc/cases/admin/cases/kyc_a1b2c3d4/verification-call-result" \
  -H "Cookie: ui_session=sess_root; ui_access_token=eyJ...; ui_csrf=csrf_r" \
  -H "x-csrf-token: csrf_r" \
  -H "Content-Type: application/json" \
  -d '{
    "expected_version": 4,
    "result": "passed",
    "notes": "Identity confirmed visually. Person matches ID photo. Answered security questions correctly.",
    "recording_linked": true
  }'
```

**Response (200):**
```json
{
  "ok": true,
  "case_id": "kyc_a1b2c3d4",
  "result": "passed",
  "recording_ref": "recordings/call_abc123def456/recording.webm",
  "result_set_at": 1716771600
}
```

### 5.3 List Verifier Pool

```bash
curl -X GET "http://localhost:8000/v1/kyc/cases/admin/verifiers" \
  -H "Cookie: ui_session=sess_root; ui_access_token=eyJ...; ui_csrf=csrf_r"
```

**Response (200):**
```json
{
  "verifiers": [
    {
      "user_sub": "root.admin@testdev.local",
      "display_name": "Root Admin",
      "active_call_count": 2,
      "last_assigned_at": 1716681500
    },
    {
      "user_sub": "e2e_charlie@test.local",
      "display_name": "Charlie Admin",
      "active_call_count": 1,
      "last_assigned_at": 1716681400
    }
  ]
}
```

### 5.4 Applicant View Verification Call Status

```bash
curl -X GET "http://localhost:8000/v1/kyc/cases/kyc_a1b2c3d4/verification-call" \
  -H "Cookie: ui_session=sess_alice; ui_access_token=eyJ...; ui_csrf=csrf_a"
```

**Response (200):**
```json
{
  "verification_call": {
    "status": "scheduled",
    "scheduled_at": 1716768000,
    "duration_minutes": 15,
    "result": null,
    "join_url": "/call/call_abc123def456"
  }
}
```

---

## 6. Error Handling Matrix

| Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|----------|-------------|------------|---------------------|----------------|
| Schedule call on non-existent case | 404 | `kyc_case_not_found` | "Case not found." | Verify case ID |
| Schedule call with past timestamp | 400 | `kyc_invalid_schedule_time` | "Scheduled time must be at least 1 hour in the future." | Pick future time |
| Schedule call on already-scheduled case | 409 | `kyc_call_already_scheduled` | "A verification call is already scheduled for this case." | Cancel existing first |
| No available verifiers in pool | 400 | `kyc_no_verifiers_available` | "No verification agents are available. Try again later." | Add verifiers to pool |
| Set result on case without call | 400 | `kyc_no_call_scheduled` | "No verification call exists for this case." | Schedule call first |
| Wrong expected_version on set result | 409 | `kyc_case_update_conflict` | "Case was modified. Please refresh." | Reload case |
| Non-admin schedules call | 403 | `kyc_admin_role_required` | "Admin access required." | Use admin credentials |
| Non-owner views call status | 403 | `kyc_access_forbidden` | "You do not own this case." | Use correct session |
| Verifier not in pool | 400 | `kyc_invalid_verifier` | "The specified user is not in the verifier pool." | Check verifier scope |

---

## 7. Pydantic Models

```python
from pydantic import BaseModel, Field
from typing import Literal

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

class KycScheduleCallResponse(BaseModel):
    ok: bool = True
    call_id: str
    verifier_sub: str
    calendar_event_id: str
    scheduled_at: int
    status: str = "scheduled"

class KycCallResultResponse(BaseModel):
    ok: bool = True
    case_id: str
    result: Literal["passed", "failed", "inconclusive"]
    recording_ref: str | None = None
    result_set_at: int

class KycVerifierOut(BaseModel):
    user_sub: str
    display_name: str | None = None
    active_call_count: int = 0
    last_assigned_at: int | None = None

class KycVerificationCallStatusOut(BaseModel):
    status: Literal["scheduled", "in_progress", "completed", "missed", "canceled"]
    scheduled_at: int | None = None
    duration_minutes: int | None = None
    result: Literal["passed", "failed", "inconclusive"] | None = None
    join_url: str | None = None
```

---

## 8. Technical Design

### 8.1 New Admin Scope

**File: `app/auth/roles.py`** -- add to `AdminScope`:

```python
class AdminScope(str, Enum):
    AUTH_SUPPORT = "auth_support"
    BILLING_SUPPORT = "billing_support"
    CONTENT_MODERATION = "content_moderation"
    CONTENT_MODERATION_SENIOR = "content_moderation_senior"
    KYC_VERIFIER = "kyc_verifier"  # new
```

### 8.2 Verifier Pool Service

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

### 8.3 Scheduling Flow

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

### 8.4 Call Recording Linkage

When a verification call ends (state transitions to `ended`), a post-call hook checks if
the call is associated with a KYC case (by matching `call_id` against
`case.verification_call.call_id`). If so, the `recording_ref` on the verification_call
object is updated with the call session's `recording_s3_key`.

---

## 9. Frontend Component Tree

```
KycCaseDetailPage (admin view, extended)
└── VerificationCallPanel
    ├── StatusBadge (scheduled | in_progress | completed | missed | canceled)
    ├── ScheduleSection (when no call)
    │   └── Button "Schedule Verification Call" → ScheduleCallDialog
    │       ├── DateTimePicker (scheduled_at)
    │       ├── Select (duration: 5/10/15/30/60 min)
    │       ├── Select (verifier: auto-assign or pick from pool)
    │       ├── Textarea (note)
    │       └── Button "Schedule"
    ├── ScheduledSection (when scheduled)
    │   ├── Text "Scheduled for {datetime}"
    │   ├── Text "Verifier: {name}"
    │   ├── Button "Join Call" (active when within 5min of scheduled time)
    │   └── Button "Cancel Call"
    ├── ResultSection (when completed)
    │   ├── ResultBadge (passed=green | failed=red | inconclusive=yellow)
    │   ├── Text "Notes: {result_notes}"
    │   └── RecordingPlayer (audio/video element, src=recording presigned URL)
    └── SetResultSection (for assigned verifier, when call completed)
        ├── RadioGroup (passed | failed | inconclusive)
        ├── Textarea (notes, required)
        └── Button "Submit Result"

KycCaseStatusPage (applicant view, extended)
└── VerificationCallBanner
    ├── StatusBadge
    ├── CountdownTimer (to scheduled_at)
    ├── Button "Join Call" (active when within 5min window)
    └── ResultDisplay (after completion)
```

---

## 10. Observability & Monitoring

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `kyc_verification_call_scheduled` | Counter | `auto_assigned` (bool) | Calls scheduled |
| `kyc_verification_call_result` | Counter | `result` (passed/failed/inconclusive) | Call outcomes |
| `kyc_verification_call_duration_seconds` | Histogram | — | Actual call durations |
| `kyc_verifier_pool_size` | Gauge | — | Number of active verifiers |
| `kyc_verifier_active_calls` | Gauge | `verifier_sub` | Active calls per verifier |
| `kyc_verification_call_missed` | Counter | — | Missed calls (no-show) |
| `kyc_verification_call_recording_linked` | Counter | — | Recordings successfully linked |

### Alert Thresholds

| Alert | Condition | Severity |
|-------|-----------|----------|
| Verifier pool empty | `pool_size == 0` | P1 |
| High miss rate | `missed / total > 20%` in 24h | P2 |
| Recording linkage failure | `recording_linked_failures > 5` in 1h | P3 |
| Call scheduled but not joined within 15min | Per-call timeout check | P3 (send reminder) |

---

## 11. Rollout Plan

### 11.1 Feature Flag

**Flag:** `KYC_VERIFICATION_CALLS_ENABLED` (default `false`)

### 11.2 Steps

1. Add `KYC_VERIFIER` scope to roles.py (backward compatible)
2. Deploy verifier pool service + endpoints (hidden behind flag)
3. Grant `KYC_VERIFIER` scope to at least 2 admins in staging
4. Enable flag in staging, run E2E tests
5. Enable flag in production, grant scope to compliance verifiers
6. Monitor miss rates and call quality for 1 week

### 11.3 Rollback

1. Set flag to `false` -- "Schedule Call" button hidden
2. Existing scheduled calls remain in DDB but no new ones created
3. Verifier scope remains (harmless if feature off)

---

## 12. Performance Considerations

| Operation | Cost | Notes |
|-----------|------|-------|
| Schedule call | 3 WCU | Case update + calendar event + audit |
| List verifiers | 5-10 RCU | Scan admin_roles table (small) |
| Auto-assign (count active) | 10-20 RCU | Cross-reference cases by status |
| Get call status | 1 RCU | Single GetItem on case |
| Recording linkage | 2 WCU | Update case record + audit |

Caching: Verifier pool list cached for 60s (pool changes infrequently).

---

## 13. E2E Test Plan

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

### Expanded E2E: Edge Cases

```typescript
test("160.6 Double-scheduling returns 409", async () => {
  // Schedule call, then try scheduling again
  // Expect 409 kyc_call_already_scheduled
});

test("161.6 Recording ref is populated after call completes", async () => {
  // After setting result with recording_linked=true
  // GET case detail
  // Verify verification_call.recording_ref is non-null
});

test("162.5 Auto-assignment picks verifier with fewest active calls", async () => {
  // Create 2 verifiers, one with 0 active calls, one with 2
  // Schedule call with auto-assign
  // Verify assigned to verifier with 0 active calls
});
```

---

## 14. File Change Summary

| File | Change Type | Description |
|------|-------------|-------------|
| `app/auth/roles.py` | Modify | Add `KYC_VERIFIER` scope to `AdminScope` enum |
| `app/services/kyc_verifier_pool.py` | **New** | Verifier pool management and auto-assignment |
| `app/services/kyc_cases.py` | Modify | Add verification_call field handling to case operations |
| `app/routers/kyc_cases.py` | Modify | Add 5 verification call endpoints |
| `app/contracts/kyc_cases_contract.py` | Modify | Add schedule/result request models and response types |
| `frontend/src/pages/admin/KycCaseDetailPage.tsx` | Modify | Add VerificationCallPanel component |
| `frontend/src/api/endpoints/kyc-admin.ts` | Modify | Add verification call API functions |
| `frontend/e2e/kyc-verification-call.spec.ts` | **New** | 18+ E2E tests across sections 160-163 |

---

## 15. Expanded E2E Tests: Additional Edge Cases

### Section 160 Additions (3 tests)

```typescript
test("160.7 Schedule call with explicit verifier_sub assigns that verifier", async () => {
  // POST with verifier_sub = charlie_admin's sub
  // Verify response verifier_sub matches charlie's sub
  // Verify calendar event created for charlie
});

test("160.8 Schedule call creates DM conversation between verifier and applicant", async () => {
  // After scheduling, check applicant's conversations
  // Verify a DM exists with the assigned verifier (or system message referencing the call)
});

test("160.9 Duration must be between 5 and 60 minutes", async () => {
  // POST with duration_minutes=3 → expect 422
  // POST with duration_minutes=61 → expect 422
  // POST with duration_minutes=30 → expect 200
});
```

### Section 161 Additions (3 tests)

```typescript
test("161.7 Setting result to inconclusive does not block case progression", async () => {
  // Set result=inconclusive
  // Verify case can still be re-scheduled for another call
});

test("161.8 Result notes are required (empty string rejected)", async () => {
  // POST with notes=""
  // Expect 422 (min_length=1)
});

test("161.9 Result notes max length enforced", async () => {
  // POST with notes of 2001 characters
  // Expect 422 (max_length=2000)
});
```

### Section 162 Additions (2 tests)

```typescript
test("162.6 Verifier with most active calls is not auto-assigned", async () => {
  // Create verifier A with 3 active calls, verifier B with 0
  // Schedule with auto-assign
  // Verify assigned to verifier B (fewest active)
});

test("162.7 Verifier schedule respects time range filter", async () => {
  // Schedule call at time T
  // GET schedule with from_ts=T-1h, to_ts=T+1h → includes call
  // GET schedule with from_ts=T+2h, to_ts=T+3h → empty
});
```

### Section 163 Additions (2 tests)

```typescript
test("163.5 Applicant sees join_url when within 5 minutes of scheduled time", async () => {
  // Schedule call for now+4min (in test, use mock time or a near-future time)
  // GET verification-call as applicant
  // Verify join_url is present and non-null
});

test("163.6 Applicant cannot see verifier's full profile data", async () => {
  // GET verification-call as applicant
  // Verify response does NOT include verifier's email or internal sub
  // Only includes verifier display name (if any)
});
```

---

## Codebase References

> **Verification performed**: 2026-05-29

### Verified (EXISTS in codebase)

| Reference | File | Line(s) | Status |
|-----------|------|---------|--------|
| `CallSessionRecord` class | `app/services/messaging_call_sessions.py` | 19 | VERIFIED |
| `create_call_session()` | `app/services/messaging_call_sessions.py` | 133 | VERIFIED |
| `end_call()` | `app/services/messaging_call_lifecycle.py` | 334 | VERIFIED |
| KYC cases router | `app/routers/kyc_cases.py` | all | VERIFIED (1294 lines) |
| `submit_kyc_case()` | `app/routers/kyc_cases.py` | 830 | VERIFIED |
| `_readiness_for_case()` | `app/routers/kyc_cases.py` | 223 | VERIFIED |
| `kyc_cases` DDB table | `scripts/local-ddb-init.py` | 91-96 | VERIFIED |
| `app/contracts/kyc_cases_contract.py` | `app/contracts/` | exists | VERIFIED |
| `audit_event()` | `app/services/alerts.py` | 695 | VERIFIED |

### Not Yet Implemented (requires new code)

| Reference | Expected Location | Status |
|-----------|-------------------|--------|
| Verification call scheduling/joining endpoints | `app/routers/kyc_cases.py` | NOT FOUND -- new endpoints required |
| Liveness verification service | `app/services/kyc_liveness.py` or similar | NOT FOUND -- new service required |
| Verification call DDB items (SK=CALL#*) | `kyc_cases` table | NOT FOUND -- new item pattern required |
| `KYC_VERIFIER` admin scope | `app/auth/roles.py` | NOT FOUND -- only AUTH_SUPPORT, BILLING_SUPPORT, CONTENT_MODERATION, CONTENT_MODERATION_SENIOR exist (lines 26-30) |

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_kyc_liveness.py`

Mock external dependencies with `moto` (DynamoDB) and `unittest.mock`. All tests run without the dev stack.

  - `test_schedule_liveness_call`
  - `test_start_liveness_session`
  - `test_record_liveness_result_pass`
  - `test_record_liveness_result_fail`
  - `test_liveness_session_expiry`
  - `test_admin_review_liveness_recording`

### Integration Tests

  - Liveness session creates video recording stored in S3
  - Admin can playback liveness recording from dashboard
  - Failed liveness triggers re-verification notification

### E2E Tests (Playwright)

**File**: `frontend/e2e/kyc-liveness.spec.ts`
**Test count**: 10

**Auth pattern**: Use `injectAuth(page, "root")` for admin endpoints; use `injectAuth(page, "alice")` for user-level endpoints. All POST/PATCH/DELETE requests include `x-csrf-token` header matching the session's CSRF token.

**Negative tests**:
- 401: Unauthenticated request returns 401
- 403: Non-admin/non-owner access returns 403
- 404: Non-existent resource returns 404
- 409: Conflict on duplicate or already-processed resource
- 422: Invalid input (bad field values, missing required fields)

**Edge cases**:
- Empty result sets return 200 with empty arrays (not 404)
- Pagination cursor works correctly across pages
- Concurrent requests do not produce inconsistent state

### Test Data Requirements

- **DDB seeds**: Seed `kyc_submissions (liveness records)` table with test records in `beforeAll`
- **Test users**: Alice (USER), Bob (USER), Root (ROOT), Charlie (ADMIN) from `e2e_admin_session_setup.py`
- **Cleanup**: Tests use unique timestamps/IDs per run to avoid cross-run interference

### CI/Pipeline Considerations

- **Feature flag**: `KYC_LIVENESS_ENABLED=true` must be set in test environment
- **Serial execution**: E2E tests run with `workers: 1` to avoid shared-state conflicts
- **Retry safety**: All tests are idempotent; retries do not produce duplicate records

## Dependencies & Merge Safety

### Depends On

| Ticket | Title | Why |
|--------|-------|-----|
| KYC-001 | Admin KYC Review Dashboard | Liveness results reviewed through dashboard |

### Depended On By

| Ticket | Title | Impact |
|--------|-------|--------|
| (none) | — | No other tickets depend on this one |

### Merge Strategy

**Sequential**

Merge after KYC-001. This ticket depends on tables/services introduced by those tickets.

### Merge Checklist

- [ ] All new DDB tables added to `scripts/local-ddb-init.py` with correct `attr_types` for numeric GSI keys
- [ ] New settings added to `app/core/settings.py` and `.env.local.example`
- [ ] New table handles added to `app/core/tables.py`
- [ ] Router registered in `app/main.py`
- [ ] Pydantic models added to `app/models.py`
- [ ] TypeScript types added to `frontend/src/api/types.ts`
- [ ] Route added to `frontend/src/App.tsx`
- [ ] Feature flag defaults to `true` in `.env.local.example`
- [ ] E2E session setup updated if new test identities needed
- [ ] `just restart` completes cleanly with new tables
- [ ] All 10 E2E tests pass with `npx playwright test kyc-liveness.spec.ts`
