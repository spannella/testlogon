# KYC-001: Admin KYC Review Dashboard

**Ticket**: KYC-001
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 12-16 days
**Dependencies**: None (uses existing backend endpoints)

---

## 1. Overview & Motivation

### Problem Statement

The backend already exposes a complete admin KYC review API at `/v1/kyc/cases/admin/*`
(implemented in `app/routers/kyc_cases.py`, lines 908-1294 — see `app/routers/kyc_cases.py:947` for metrics, `:1021` for request-info, `:1099` for approve/reject), including queue listing with
filters, case detail with timeline, approve/reject/request-info actions, metrics snapshot,
and retention purge. However, there is **no frontend** for these endpoints. Admins currently
have no way to review KYC submissions, examine uploaded identity documents, or make approval
decisions through the platform UI. All review activity would need to happen via direct API
calls or external tooling, which is impractical for a compliance workflow that requires
visual document inspection.

### Goals

1. Build a KYC review queue page showing all pending cases with filtering and sorting.
2. Build a case detail page with side-by-side document viewer (uploaded selfie, ID front/back, proof of address).
3. Provide document zoom/rotate controls for visual inspection of uploaded identity documents.
4. Wire approve/reject/request-info actions with reason code selection and notes.
5. Display a case timeline view showing all audit events from the `audit_log` table.
6. Build a metrics dashboard showing funnel counts, approval rate, and average time-to-decision.

### User Stories

| # | As a... | I want to... | So that... |
|---|---------|-------------|-----------|
| 1 | KYC reviewer | See a filterable queue of pending KYC cases | I can prioritize my review workload |
| 2 | KYC reviewer | View uploaded documents side-by-side with user profile data | I can verify identity without switching between screens |
| 3 | KYC reviewer | Zoom and rotate document images | I can read text on angled or low-quality uploads |
| 4 | KYC reviewer | Approve or reject a case with reason codes | Decisions are structured and auditable |
| 5 | KYC reviewer | Request more information from the applicant | I can ask for missing or unclear documents |
| 6 | Compliance lead | See metrics on queue depth, approval rate, and latency | I can monitor team performance and SLA compliance |
| 7 | KYC reviewer | See the full timeline of a case (submissions, status changes, messages) | I have complete context before making a decision |

---

## 2. Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Frontend (React / Vite)                       │
│                                                                      │
│  ┌─────────────────┐  ┌──────────────────────┐  ┌────────────────┐  │
│  │  KycQueuePage   │  │ KycCaseDetailPage     │  │ KycMetrics     │  │
│  │  (/admin/kyc)   │  │ (/admin/kyc/cases/:id)│  │ Dashboard      │  │
│  │                 │  │                        │  │ (/admin/kyc/   │  │
│  │ ┌─────────────┐ │  │ ┌──────────────────┐  │  │  metrics)      │  │
│  │ │ QueueFilters│ │  │ │ DocumentViewer    │  │  │                │  │
│  │ │ QueueTable  │ │  │ │ CaseInfoPanel     │  │  │ FunnelChart    │  │
│  │ │ Pagination  │ │  │ │ CaseActionPanel   │  │  │ LatencyCards   │  │
│  │ └─────────────┘ │  │ │ CaseTimeline      │  │  │ StaleAlert     │  │
│  └────────┬────────┘  │ └──────────────────┘  │  └───────┬────────┘  │
│           │           └──────────┬─────────────┘          │           │
└───────────┼──────────────────────┼────────────────────────┼───────────┘
            │                      │                        │
            ▼                      ▼                        ▼
┌──────────────────────────────────────────────────────────────────────┐
│                   API Layer (kyc-admin.ts)                            │
│  fetchKycQueue()  fetchKycCaseDetail()  approveKycCase()             │
│  rejectKycCase()  requestKycInfo()       fetchKycMetrics()           │
└──────────────────────────────┬───────────────────────────────────────┘
                               │ Axios + CSRF
                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│                    Backend (FastAPI / uvicorn:8000)                   │
│                                                                      │
│  app/routers/kyc_cases.py (lines 908-1295)                          │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │ GET  /v1/kyc/cases/admin/queue         → list_admin_queue() │    │
│  │ GET  /v1/kyc/cases/admin/metrics       → get_metrics()      │    │
│  │ GET  /v1/kyc/cases/admin/cases/{id}    → get_case_detail()  │    │
│  │ POST /v1/kyc/cases/admin/cases/{id}/approve   → approve()   │    │
│  │ POST /v1/kyc/cases/admin/cases/{id}/reject    → reject()    │    │
│  │ POST /v1/kyc/cases/admin/cases/{id}/request-info → req()    │    │
│  │ POST /v1/kyc/cases/admin/purge/run     → retention_purge()  │    │
│  └──────────────────────────────────────────────────────────────┘    │
│                                                                      │
│  app/services/kyc_cases.py (STORE)                                  │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │ list_admin_queue()  get_case()  update_case_status()         │    │
│  │ get_metrics_snapshot()  run_retention_purge()                 │    │
│  └──────────────┬───────────────────────────────────────────────┘    │
└─────────────────┼────────────────────────────────────────────────────┘
                  │
                  ▼
┌──────────────────────────────────────────────────────────────────────┐
│                     DynamoDB Local (:8001)                            │
│                                                                      │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────────────┐ │
│  │ kyc_cases       │  │ audit_log      │  │ files (file manager)   │ │
│  │ PK: KYC#{id}   │  │ PK: USER#{sub} │  │ PK: USER#{sub}         │ │
│  │ SK: META        │  │ SK: TS#{ts}    │  │ SK: NODE#{node_id}     │ │
│  └────────────────┘  └────────────────┘  └────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────────┐
│                        S3 (moto mock :4566)                          │
│  bucket/uploads/kyc/  → selfie, id_front, id_back, proof_of_address │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 3. Current State Analysis

### 3.1 Existing Admin KYC Endpoints

The following endpoints in `app/routers/kyc_cases.py` are fully implemented and tested (see `app/routers/kyc_cases.py`):

| Endpoint | Method | Line | Purpose |
|----------|--------|------|---------|
| `/v1/kyc/cases/admin/queue` | GET | 908 | List cases with status/assignee/risk/wait filters (see `:908`) |
| `/v1/kyc/cases/admin/metrics` | GET | 946 | Funnel counts, review latency, stale queue (see `:947` for `get_admin_kyc_metrics`) |
| `/v1/kyc/cases/admin/purge/run` | POST | 972 | Retention purge (dry_run supported) |
| `/v1/kyc/cases/admin/cases/{case_id}` | GET | 996 | Full case detail with timeline |
| `/v1/kyc/cases/admin/cases/{case_id}/request-info` | POST | 1020 | Request more info from applicant (see `:1021` for `admin_request_more_info`) |
| `/v1/kyc/cases/admin/cases/{case_id}/approve` | POST | 1183 | Approve case (see `:1183`) <!-- NOTE: ticket originally cited line 1184 -- actual decorator is at 1183 --> |
| `/v1/kyc/cases/admin/cases/{case_id}/reject` | POST | 1194 | Reject case (see `:1194`) <!-- NOTE: ticket originally cited line 1195 -- actual decorator is at 1194 --> |

### 3.2 Response Shapes

**Admin queue item** (`KycAdminQueueItem` — see `app/contracts/kyc_cases_contract.py:177`):
- `kyc_case_id`, `user_sub`, `status`, `assigned_admin_sub`, `created_at`, `updated_at`
- `waiting_seconds` (computed server-side), `risk_tier` (from `intake_profile`)

**Admin case detail** (`KycAdminCaseDetailOut` — see `app/contracts/kyc_cases_contract.py:201`):
- `kyc_case_id`, `user_sub`, `status`
- `questionnaire_ref` (questionnaire_id, version_id, response_session_id, response_pdf_ref)
- `files_ref[]` (type, path, verification_state for each file)
- `signature_ref` (packet_id, status, final_pdf_ref)
- `ticket_ref` (ticket_id from review)
- `decision_state` (decision, reason_codes, decided_at)
- `timeline[]` (event_type, source, created_at, actor_sub, details)

**Metrics** (`KycMetricsSummaryOut` — see `app/contracts/kyc_cases_contract.py:218`):
- `funnel_counts` (dict of status -> count)
- `review_latency_seconds` (p50, p90, p99 percentiles)
- `stale_queue_count`, `submit_guard_failures_by_reason`
- `ticket_sync_counters`, `ticket_sync_deadletter_count`

### 3.3 File Access Pattern

KYC files are stored via the file manager. Each file entry in `case.files[]` has a `path`
field pointing to a file manager node. The file content URL is resolved via
`GET /ui/files/download?path={path}` which returns a presigned S3 URL. The frontend
document viewer will use these URLs for image rendering.

### 3.4 Auth & Scopes

All admin endpoints check `normalize_role(user.role) in {Role.ADMIN, Role.ROOT}` (see `app/routers/kyc_cases.py:920`).
The scoped admin check (`_is_scoped_admin_for_case` — see `app/routers/kyc_cases.py:63`) additionally verifies that a
scoped admin is the assigned reviewer for case detail/actions. ROOT bypasses scope checks.

### 3.5 Existing Admin Page Structure

Admin pages live in `frontend/src/pages/admin/`. Examples:
- `RootRoleManagementPage.tsx` -- admin role management
- `ModerationBoardPage.tsx` -- content moderation queue
- `VideoReviewQueuePage.tsx` -- video review

The KYC dashboard will follow the same layout and component patterns.

---

## 4. DynamoDB Access Patterns

### 4.1 KYC Cases Table

| Access Pattern | PK | SK / GSI | Condition | Used By |
|---------------|-----|----------|-----------|---------|
| Get case by ID | `KYC#{case_id}` | `META` | — | Case detail page |
| List cases by status | GSI `status-updated-index` PK=`STATUS#{status}` | SK range on `UPDATED#{ts}` | `ScanIndexForward=False` | Queue page filters |
| List cases by owner | GSI `owner-updated-index` PK=`OWNER#{user_sub}` | SK range | — | User case list |
| Count by status | GSI `status-updated-index` scan each status partition | `Select=COUNT` | — | Metrics funnel counts |

### 4.2 Example DDB Items

**Case META record:**
```json
{
  "pk": "KYC#kyc_a1b2c3d4",
  "sk": "META",
  "kyc_case_id": "kyc_a1b2c3d4",
  "user_sub": "e2e_alice@test.local",
  "status": "submitted",
  "intake_profile": "enhanced",
  "version": 3,
  "files": [
    { "type": "selfie", "path": "/uploads/kyc/alice_selfie.jpg", "verification_state": "pending", "attached_at": 1716681600 },
    { "type": "id_front", "path": "/uploads/kyc/alice_id_front.jpg", "verification_state": "pending", "attached_at": 1716681601 },
    { "type": "id_back", "path": "/uploads/kyc/alice_id_back.jpg", "verification_state": "pending", "attached_at": 1716681602 }
  ],
  "questionnaire": { "questionnaire_id": "q_xyz", "version_id": "v_1", "response_session_id": "rs_abc" },
  "signature": { "packet_id": "pkt_def", "status": "completed" },
  "submission": { "submitted_at": 1716681700, "evidence_hash": "sha256:..." },
  "review": { "ticket_id": "tkt_ghi", "assigned_admin_sub": null },
  "created_at": 1716681500,
  "updated_at": 1716681700,
  "gsi_status_pk": "STATUS#submitted",
  "gsi_status_sk": "UPDATED#0001716681700#KYC#kyc_a1b2c3d4",
  "gsi_owner_pk": "OWNER#e2e_alice@test.local",
  "gsi_owner_sk": "UPDATED#0001716681700#KYC#kyc_a1b2c3d4"
}
```

**Audit log entry:**
```json
{
  "pk": "USER#e2e_alice@test.local",
  "sk": "TS#1716681700#kyc_state_transition",
  "event_name": "kyc_state_transition",
  "actor_sub": "e2e_alice@test.local",
  "case_id": "kyc_a1b2c3d4",
  "from_status": "draft",
  "to_status": "submitted",
  "created_at": 1716681700
}
```

---

## 5. API Request/Response Examples

### 5.1 List KYC Queue

```bash
curl -X GET "http://localhost:8000/v1/kyc/cases/admin/queue?status=submitted&limit=20" \
  -H "Cookie: ui_session=sess_root123; ui_access_token=eyJhbGciOi...; ui_csrf=csrf_abc" \
  -H "Accept: application/json"
```

**Response (200):**
```json
{
  "items": [
    {
      "kyc_case_id": "kyc_a1b2c3d4",
      "user_sub": "e2e_alice@test.local",
      "status": "submitted",
      "assigned_admin_sub": null,
      "created_at": 1716681500,
      "updated_at": 1716681700,
      "waiting_seconds": 3600,
      "risk_tier": "medium"
    }
  ],
  "next_cursor": null
}
```

### 5.2 Get Case Detail

```bash
curl -X GET "http://localhost:8000/v1/kyc/cases/admin/cases/kyc_a1b2c3d4" \
  -H "Cookie: ui_session=sess_root123; ui_access_token=eyJhbGciOi...; ui_csrf=csrf_abc"
```

**Response (200):**
```json
{
  "case": {
    "kyc_case_id": "kyc_a1b2c3d4",
    "user_sub": "e2e_alice@test.local",
    "status": "submitted",
    "questionnaire_ref": {
      "questionnaire_id": "q_xyz",
      "version_id": "v_1",
      "response_session_id": "rs_abc",
      "response_pdf_ref": null
    },
    "files_ref": [
      { "type": "selfie", "path": "/uploads/kyc/alice_selfie.jpg", "verification_state": "pending" },
      { "type": "id_front", "path": "/uploads/kyc/alice_id_front.jpg", "verification_state": "pending" },
      { "type": "id_back", "path": "/uploads/kyc/alice_id_back.jpg", "verification_state": "pending" }
    ],
    "signature_ref": { "packet_id": "pkt_def", "status": "completed", "final_pdf_ref": null },
    "ticket_ref": { "ticket_id": "tkt_ghi" },
    "decision_state": { "decision": null, "reason_codes": [], "decided_at": null },
    "timeline": [
      { "event_type": "case_created", "source": "kyc_case", "created_at": 1716681500, "actor_sub": "e2e_alice@test.local", "details": {} },
      { "event_type": "file_attached", "source": "kyc_case", "created_at": 1716681600, "actor_sub": "e2e_alice@test.local", "details": { "file_type": "selfie" } },
      { "event_type": "case_submitted", "source": "kyc_case", "created_at": 1716681700, "actor_sub": "e2e_alice@test.local", "details": {} }
    ]
  }
}
```

### 5.3 Approve Case

```bash
curl -X POST "http://localhost:8000/v1/kyc/cases/admin/cases/kyc_a1b2c3d4/approve" \
  -H "Cookie: ui_session=sess_root123; ui_access_token=eyJhbGciOi...; ui_csrf=csrf_abc" \
  -H "x-csrf-token: csrf_abc" \
  -H "Content-Type: application/json" \
  -d '{
    "expected_version": 3,
    "reason_codes": ["identity_verified", "documents_valid"],
    "note": "All documents verified, name and DOB match profile."
  }'
```

**Response (200):**
```json
{
  "ok": true,
  "case_id": "kyc_a1b2c3d4",
  "new_status": "approved",
  "decided_at": 1716685300
}
```

### 5.4 Reject Case

```bash
curl -X POST "http://localhost:8000/v1/kyc/cases/admin/cases/kyc_a1b2c3d4/reject" \
  -H "Cookie: ui_session=sess_root123; ui_access_token=eyJhbGciOi...; ui_csrf=csrf_abc" \
  -H "x-csrf-token: csrf_abc" \
  -H "Content-Type: application/json" \
  -d '{
    "expected_version": 3,
    "reason_codes": ["document_illegible", "name_mismatch"],
    "note": "ID front is too blurry to read. Name on ID does not match profile."
  }'
```

**Response (200):**
```json
{
  "ok": true,
  "case_id": "kyc_a1b2c3d4",
  "new_status": "rejected",
  "decided_at": 1716685400
}
```

### 5.5 Request More Info

```bash
curl -X POST "http://localhost:8000/v1/kyc/cases/admin/cases/kyc_a1b2c3d4/request-info" \
  -H "Cookie: ui_session=sess_root123; ui_access_token=eyJhbGciOi...; ui_csrf=csrf_abc" \
  -H "x-csrf-token: csrf_abc" \
  -H "Content-Type: application/json" \
  -d '{
    "expected_version": 3,
    "requested_items": ["proof_of_address", "id_front"],
    "note": "Please upload a clearer photo of your ID front and a utility bill or bank statement."
  }'
```

**Response (200):**
```json
{
  "ok": true,
  "case_id": "kyc_a1b2c3d4",
  "new_status": "needs_more_info",
  "requested_items": ["proof_of_address", "id_front"]
}
```

### 5.6 Fetch Metrics

```bash
curl -X GET "http://localhost:8000/v1/kyc/cases/admin/metrics?stale_after_seconds=172800" \
  -H "Cookie: ui_session=sess_root123; ui_access_token=eyJhbGciOi...; ui_csrf=csrf_abc"
```

**Response (200):**
```json
{
  "metrics": {
    "funnel_counts": {
      "draft": 5,
      "submitted": 12,
      "under_review": 3,
      "needs_more_info": 2,
      "approved": 45,
      "rejected": 8,
      "expired": 1
    },
    "review_latency_seconds": {
      "p50": 14400,
      "p90": 57600,
      "p99": 172800
    },
    "stale_queue_count": 2,
    "submit_guard_failures_by_reason": {},
    "ticket_sync_counters": {},
    "ticket_sync_deadletter_count": 0
  }
}
```

---

## 6. Error Handling Matrix

| Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|----------|-------------|------------|---------------------|----------------|
| Non-admin user accesses admin queue | 403 | `kyc_admin_role_required` | "You do not have permission to access the KYC admin queue." | Redirect to dashboard |
| Scoped admin views unassigned case | 403 | `kyc_access_forbidden` | "You are not assigned as the reviewer for this case." | Contact ROOT admin |
| Case not found | 404 | `kyc_case_not_found` | "The requested KYC case does not exist." | Return to queue |
| Approve with wrong expected_version | 409 | `kyc_case_update_conflict` | "This case was modified by another reviewer. Please refresh." | Reload case detail |
| Approve already-approved case | 409 | `kyc_invalid_transition` | "This case has already been decided." | Reload case detail |
| Approve case not in reviewable status | 400 | `kyc_invalid_status` | "This case cannot be approved in its current status." | Reload case detail |
| Request-info with empty requested_items | 422 | `validation_error` | "At least one requested item must be specified." | Fix form |
| Note exceeds max length (2000 chars) | 422 | `validation_error` | "Note must be 2000 characters or fewer." | Trim note |
| Queue filter with invalid risk_tier | 422 | `validation_error` | "Invalid risk tier filter value." | Clear filter |
| Backend service unavailable | 500 | `internal_error` | "Something went wrong. Please try again." | Retry request |
| DynamoDB throttled | 503 | `service_unavailable` | "The service is temporarily busy. Please try again." | Retry with backoff |
| File download URL expired | 403 | `s3_access_denied` | "Document access has expired. Please reload the page." | Reload page |

---

## 7. Pydantic Models

### 7.1 Backend Models (`app/contracts/kyc_cases_contract.py`)

```python
from pydantic import BaseModel, Field
from typing import Literal

class KycAdminQueueItem(BaseModel):
    kyc_case_id: str
    user_sub: str
    status: str
    assigned_admin_sub: str | None = None
    created_at: int
    updated_at: int
    waiting_seconds: int | None = None
    risk_tier: str | None = None

class KycAdminQueueEnvelope(BaseModel):
    items: list[KycAdminQueueItem]
    next_cursor: str | None = None

class KycTimelineEventOut(BaseModel):
    event_type: str
    source: Literal["kyc_case", "ticket"]
    created_at: int | None = None
    actor_sub: str | None = None
    details: dict = Field(default_factory=dict)

class KycFileRefOut(BaseModel):
    type: str
    path: str
    verification_state: str

class KycAdminCaseDetailOut(BaseModel):
    kyc_case_id: str
    user_sub: str
    status: str
    questionnaire_ref: dict = Field(default_factory=dict)
    files_ref: list[KycFileRefOut] = Field(default_factory=list)
    signature_ref: dict = Field(default_factory=dict)
    ticket_ref: dict = Field(default_factory=dict)
    decision_state: dict = Field(default_factory=dict)
    timeline: list[KycTimelineEventOut] = Field(default_factory=list)

class KycAdminApproveRequest(BaseModel):
    expected_version: int = Field(..., ge=1)
    reason_codes: list[str] = Field(..., min_length=1)
    note: str = Field("", max_length=2000)

class KycAdminRejectRequest(BaseModel):
    expected_version: int = Field(..., ge=1)
    reason_codes: list[str] = Field(..., min_length=1)
    note: str = Field("", max_length=2000)

class KycAdminRequestInfoRequest(BaseModel):
    expected_version: int = Field(..., ge=1)
    requested_items: list[str] = Field(..., min_length=1)
    note: str = Field("", max_length=2000)

class KycMetricsLatency(BaseModel):
    p50: int | None = None
    p90: int | None = None
    p99: int | None = None

class KycMetricsSummaryOut(BaseModel):
    funnel_counts: dict[str, int] = Field(default_factory=dict)
    review_latency_seconds: KycMetricsLatency = Field(default_factory=KycMetricsLatency)
    stale_queue_count: int = 0
    submit_guard_failures_by_reason: dict[str, int] = Field(default_factory=dict)
    ticket_sync_counters: dict[str, int] = Field(default_factory=dict)
    ticket_sync_deadletter_count: int = 0
```

---

## 8. Technical Design

### 8.1 Frontend API Layer

**File: `frontend/src/api/endpoints/kyc-admin.ts`** (new)

```typescript
import api from "../client";

export interface KycQueueItem {
  kyc_case_id: string;
  user_sub: string;
  status: string;
  assigned_admin_sub: string | null;
  created_at: number;
  updated_at: number;
  waiting_seconds: number | null;
  risk_tier: string | null;
}

export interface KycQueueEnvelope {
  items: KycQueueItem[];
  next_cursor: string | null;
}

export interface KycTimelineEvent {
  event_type: string;
  source: "kyc_case" | "ticket";
  created_at: number | null;
  actor_sub: string | null;
  details: Record<string, unknown>;
}

export interface KycCaseDetail {
  kyc_case_id: string;
  user_sub: string;
  status: string;
  questionnaire_ref: Record<string, unknown>;
  files_ref: Array<{ type: string; path: string; verification_state: string }>;
  signature_ref: Record<string, unknown>;
  ticket_ref: Record<string, unknown>;
  decision_state: Record<string, unknown>;
  timeline: KycTimelineEvent[];
}

export interface KycMetrics {
  funnel_counts: Record<string, number>;
  review_latency_seconds: Record<string, number | null>;
  stale_queue_count: number;
}

export const fetchKycQueue = (params: {
  status?: string;
  assignee_admin_sub?: string;
  risk_tier?: string;
  min_waiting_seconds?: number;
  cursor?: string;
  limit?: number;
}) => api.get<KycQueueEnvelope>("/v1/kyc/cases/admin/queue", { params });

export const fetchKycCaseDetail = (caseId: string) =>
  api.get<{ case: KycCaseDetail }>(`/v1/kyc/cases/admin/cases/${caseId}`);

export const fetchKycMetrics = (staleAfterSeconds?: number) =>
  api.get<{ metrics: KycMetrics }>("/v1/kyc/cases/admin/metrics", {
    params: { stale_after_seconds: staleAfterSeconds },
  });

export const approveKycCase = (caseId: string, body: {
  expected_version: number;
  reason_codes: string[];
  note: string;
}) => api.post(`/v1/kyc/cases/admin/cases/${caseId}/approve`, body);

export const rejectKycCase = (caseId: string, body: {
  expected_version: number;
  reason_codes: string[];
  note: string;
}) => api.post(`/v1/kyc/cases/admin/cases/${caseId}/reject`, body);

export const requestKycInfo = (caseId: string, body: {
  expected_version: number;
  requested_items: string[];
  note: string;
}) => api.post(`/v1/kyc/cases/admin/cases/${caseId}/request-info`, body);
```

### 8.2 Frontend Pages

**File: `frontend/src/pages/admin/KycQueuePage.tsx`** (new, ~400 lines)

Components:
- `KycQueueFilters` -- status dropdown (submitted/under_review/needs_more_info/all), risk tier
  dropdown (standard/enhanced/high_risk), assignee text input, min wait time slider
- `KycQueueTable` -- DataTable with columns: Case ID, User, Status (badge), Risk Tier (badge),
  Waiting Time (human-readable), Assigned To, Actions (View button)
- Pagination via `next_cursor` from API response
- Click row or View button navigates to `/admin/kyc/cases/{caseId}`

**File: `frontend/src/pages/admin/KycCaseDetailPage.tsx`** (new, ~500 lines)

Layout: two-column. Left column (60%): document viewer. Right column (40%): case info + actions.

Components:
- `DocumentViewer` -- displays uploaded files (selfie, id_front, id_back, proof_of_address)
  as tabbed image panels with zoom (scroll wheel + pinch), rotate (90-degree CW/CCW buttons),
  and fullscreen toggle. Uses CSS `transform: scale() rotate()`.
- `CaseInfoPanel` -- user_sub, status badge, intake_profile, created_at, questionnaire status,
  signature status
- `CaseActionPanel` -- approve/reject/request-info buttons. Approve and reject open a dialog
  with reason code multi-select and notes textarea. Request-info opens a dialog with checkboxes
  for missing items and a notes field.
- `CaseTimeline` -- vertical timeline of `KycTimelineEvent[]` with icons per event_type,
  actor name, timestamp, and expandable detail JSON

**File: `frontend/src/pages/admin/KycMetricsDashboard.tsx`** (new, ~250 lines)

Components:
- `FunnelChart` -- horizontal bar chart showing counts per status (draft, submitted,
  under_review, approved, rejected, expired)
- `LatencyCards` -- p50/p90/p99 review latency displayed as cards with color coding
  (green < 24h, yellow 24-48h, red > 48h)
- `StaleQueueAlert` -- banner when `stale_queue_count > 0`
- `ApprovalRateCard` -- computed from funnel_counts: `approved / (approved + rejected) * 100`

### 8.3 Frontend Component Tree

```
KycQueuePage
├── PageHeader ("KYC Review Queue")
├── KycQueueFilters
│   ├── Select (status: all | submitted | under_review | needs_more_info)
│   ├── Select (risk_tier: all | standard | enhanced | high_risk)
│   ├── Input (assignee_admin_sub)
│   └── Slider (min_waiting_seconds: 0-86400)
├── DataTable (KycQueueTable)
│   ├── Column: Case ID (link to detail)
│   ├── Column: User (user_sub)
│   ├── Column: Status (Badge variant)
│   ├── Column: Risk Tier (Badge variant)
│   ├── Column: Waiting Time (humanized duration)
│   ├── Column: Assigned To (admin_sub or "Unassigned")
│   └── Column: Actions (Button "View")
└── PaginationControls
    ├── Button "Previous" (disabled if no prev cursor)
    └── Button "Next" (disabled if next_cursor is null)

KycCaseDetailPage
├── PageHeader (case_id + status badge)
├── Grid (2 columns)
│   ├── Column Left (60%)
│   │   └── DocumentViewer
│   │       ├── TabBar (Selfie | ID Front | ID Back | Proof of Address)
│   │       ├── ImagePane
│   │       │   ├── img (src=presigned S3 URL, style=transform)
│   │       │   └── VerificationStateBadge (overlay)
│   │       └── ControlBar
│   │           ├── Button "Zoom In" (+)
│   │           ├── Button "Zoom Out" (-)
│   │           ├── Button "Rotate CW"
│   │           ├── Button "Rotate CCW"
│   │           └── Button "Fullscreen"
│   └── Column Right (40%)
│       ├── CaseInfoPanel
│       │   ├── Field: User Sub
│       │   ├── Field: Status (Badge)
│       │   ├── Field: Intake Profile
│       │   ├── Field: Created At (formatted)
│       │   ├── Field: Questionnaire Status
│       │   └── Field: Signature Status
│       ├── CaseActionPanel
│       │   ├── Button "Approve" → ApproveDialog
│       │   │   ├── CheckboxGroup (reason codes)
│       │   │   ├── Textarea (notes)
│       │   │   └── Button "Confirm Approval"
│       │   ├── Button "Reject" → RejectDialog
│       │   │   ├── CheckboxGroup (reason codes)
│       │   │   ├── Textarea (notes)
│       │   │   └── Button "Confirm Rejection"
│       │   └── Button "Request Info" → RequestInfoDialog
│       │       ├── CheckboxGroup (requested items)
│       │       ├── Textarea (notes)
│       │       └── Button "Send Request"
│       └── CaseTimeline
│           └── TimelineItem[] (map over timeline)
│               ├── Icon (per event_type)
│               ├── Timestamp (formatted)
│               ├── ActorName
│               └── Collapsible (details JSON)

KycMetricsDashboard
├── PageHeader ("KYC Metrics")
├── Grid (2 columns)
│   ├── FunnelChart (horizontal bars per status)
│   └── ApprovalRateCard (percentage + donut chart)
├── Grid (3 columns)
│   ├── LatencyCard (p50)
│   ├── LatencyCard (p90)
│   └── LatencyCard (p99)
└── StaleQueueAlert (conditional banner)
```

### 8.4 Routing

**File: `frontend/src/App.tsx`** -- add routes:

```tsx
<Route path="/admin/kyc" element={<KycQueuePage />} />
<Route path="/admin/kyc/cases/:caseId" element={<KycCaseDetailPage />} />
<Route path="/admin/kyc/metrics" element={<KycMetricsDashboard />} />
```

### 8.5 Sidebar Navigation

**File: `frontend/src/components/layout/Sidebar.tsx`** -- add to Admin group:

```tsx
{ icon: ShieldCheck, label: "KYC Review", href: "/admin/kyc", adminOnly: true }
```

### 8.6 Document Viewer Component

**File: `frontend/src/components/shared/DocumentViewer.tsx`** (new, ~200 lines)

```typescript
interface DocumentViewerProps {
  files: Array<{ type: string; path: string; verification_state: string }>;
  activeTab?: string;
  onTabChange?: (type: string) => void;
}
```

Features:
- Tab bar with file types (Selfie, ID Front, ID Back, Proof of Address)
- Image rendered via `<img>` with presigned URL from `/ui/files/download?path={path}`
- CSS transform state: `{ scale: number; rotation: number }` managed via `useState`
- Zoom: `+`/`-` buttons and scroll wheel (`onWheel` handler)
- Rotate: CW/CCW buttons adjusting rotation by 90 degrees
- Fullscreen: button toggles `position: fixed; inset: 0; z-index: 50` overlay
- Verification state badge overlay (pending/verified/rejected)

---

## 9. Observability & Monitoring

### 9.1 Metrics to Track

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `kyc_queue_page_load_duration_ms` | Histogram | `status_filter` | Time to load queue page data |
| `kyc_case_detail_load_duration_ms` | Histogram | — | Time to load case detail + files |
| `kyc_document_viewer_zoom_count` | Counter | `action` (zoom_in/zoom_out/rotate) | Document interaction frequency |
| `kyc_admin_action_total` | Counter | `action` (approve/reject/request_info), `role` | Admin decision count |
| `kyc_admin_action_duration_ms` | Histogram | `action` | Time from action click to server confirmation |
| `kyc_metrics_page_load_duration_ms` | Histogram | — | Time to load metrics dashboard |
| `kyc_queue_filter_usage` | Counter | `filter_type` (status/risk/assignee/wait) | Which filters admins use most |
| `kyc_stale_queue_alert_shown` | Counter | — | How often stale queue banner is displayed |

### 9.2 Log Events

| Event | Level | Fields | When |
|-------|-------|--------|------|
| `kyc.admin.queue_loaded` | INFO | `admin_sub`, `filter_params`, `result_count`, `duration_ms` | Queue page loads |
| `kyc.admin.case_viewed` | INFO | `admin_sub`, `case_id`, `case_status` | Admin opens case detail |
| `kyc.admin.case_approved` | INFO | `admin_sub`, `case_id`, `reason_codes` | Approval action |
| `kyc.admin.case_rejected` | INFO | `admin_sub`, `case_id`, `reason_codes` | Rejection action |
| `kyc.admin.info_requested` | INFO | `admin_sub`, `case_id`, `requested_items` | Request-info action |
| `kyc.admin.version_conflict` | WARN | `admin_sub`, `case_id`, `expected_version`, `actual_version` | 409 conflict |
| `kyc.admin.queue_load_error` | ERROR | `admin_sub`, `error`, `status_code` | Queue API failure |
| `kyc.admin.document_load_error` | ERROR | `admin_sub`, `case_id`, `file_type`, `error` | S3 URL fetch failure |

### 9.3 Alert Thresholds

| Alert | Condition | Severity | Notification |
|-------|-----------|----------|-------------|
| Stale queue critical | `stale_queue_count > 10` | P2 | Slack + Email to compliance lead |
| Review latency high | `p90 > 172800` (48h) | P3 | Slack to KYC team |
| Queue page error rate | `5xx > 5% of requests in 5min` | P1 | PagerDuty |
| Admin action failures | `409 conflicts > 20 in 1h` | P3 | Slack (possible race condition) |
| Document viewer failures | `S3 URL errors > 10 in 10min` | P2 | Slack to platform team |

### 9.4 Dashboard Queries

**Queue depth over time (Prometheus):**
```promql
sum(kyc_queue_items_total) by (status)
```

**Average review latency trend:**
```promql
histogram_quantile(0.50, rate(kyc_review_latency_seconds_bucket[1h]))
```

**Admin activity breakdown:**
```promql
sum(rate(kyc_admin_action_total[1h])) by (action, role)
```

---

## 10. Rollout Plan

### 10.1 Feature Flag Strategy

**Flag name:** `KYC_ADMIN_DASHBOARD_ENABLED`
**Default:** `false` in production, `true` in dev/staging

```python
# app/core/settings.py
kyc_admin_dashboard_enabled: bool = os.environ.get("KYC_ADMIN_DASHBOARD_ENABLED", "false").lower() == "true"
```

Frontend route guard:
```tsx
// Only render KYC admin routes if feature flag is enabled
{featureFlags.kycAdminDashboard && (
  <>
    <Route path="/admin/kyc" element={<KycQueuePage />} />
    <Route path="/admin/kyc/cases/:caseId" element={<KycCaseDetailPage />} />
    <Route path="/admin/kyc/metrics" element={<KycMetricsDashboard />} />
  </>
)}
```

### 10.2 Migration Steps

1. Deploy backend (no changes needed -- endpoints already exist)
2. Deploy frontend with feature flag `false` (pages exist but routes hidden)
3. Enable flag in staging, run E2E tests
4. Enable flag in production for ROOT users only (soft launch)
5. Enable flag for all ADMIN users after 1 week of ROOT testing

### 10.3 Canary Deployment

- Deploy to 1 canary instance first
- Monitor error rates for 30 minutes
- If error rate < 1%, proceed to full rollout
- Frontend is static assets, so canary is only relevant for the backend flag check

### 10.4 Rollback Procedure

1. Set `KYC_ADMIN_DASHBOARD_ENABLED=false` in production env
2. Redeploy (or just restart backend to pick up env change)
3. Frontend routes become hidden; existing backend endpoints remain functional
4. No data migration needed (dashboard is read-only over existing data)

---

## 11. Performance Considerations

### 11.1 Query Costs

| Query | Estimated RCU | Notes |
|-------|---------------|-------|
| Queue listing (status GSI, limit 20) | 10-20 RCU | Single GSI query, no full scan |
| Case detail (single GetItem) | 2-5 RCU | Depends on case item size (~2-5 KB) |
| Metrics snapshot (count queries per status) | 30-50 RCU | 7 GSI queries (one per status) |
| Timeline (audit log query) | 5-10 RCU | Bounded by timeline array size |

### 11.2 Caching Strategy

| Data | Cache TTL | Strategy |
|------|-----------|----------|
| Queue listing | 0 (no cache) | Always fresh; admins need real-time queue |
| Case detail | 0 (no cache) | Must reflect latest status changes |
| Metrics | 60 seconds | React Query staleTime, acceptable staleness for dashboard |
| File download URLs | 300 seconds | Presigned URLs are valid for 15 minutes; cache for 5 min |
| Reason codes list | Infinity | Static data, hardcoded in frontend |

### 11.3 Pagination Limits

- Queue page: `limit=20` default, max `limit=100`
- Cursor-based pagination via DynamoDB `LastEvaluatedKey`
- Timeline events: unbounded (all events for case), typically < 50 events

### 11.4 Rate Limiting

- Queue endpoint: 60 req/min per admin (standard API rate limit)
- Case detail: 120 req/min per admin (higher for tab switching)
- Approve/reject/request-info: 30 req/min per admin (action rate limit)
- Metrics: 10 req/min per admin (dashboard refresh)

---

## 12. E2E Test Plan

**File**: `frontend/e2e/kyc-admin-dashboard.spec.ts`
**Total**: ~25 tests across 6 sections (150-155)

### Section 150: Admin KYC Queue API (5 tests)

```typescript
test("150.1 Root can list KYC queue with default filters", async () => {
  // Create a KYC case as Alice, submit it
  // GET /v1/kyc/cases/admin/queue as Root
  // Verify items array contains the submitted case
});

test("150.2 Queue filtered by status=submitted returns only submitted cases", async () => {
  // GET /v1/kyc/cases/admin/queue?status=submitted
  // Verify all returned items have status=submitted
});

test("150.3 Queue filtered by risk_tier returns matching cases", async () => {
  // Create case with intake_profile=enhanced, submit
  // GET /v1/kyc/cases/admin/queue?risk_tier=enhanced
  // Verify returned items have risk_tier=enhanced
});

test("150.4 Non-admin user gets 403 on queue endpoint", async () => {
  // GET /v1/kyc/cases/admin/queue as Alice (USER role)
  // Expect 403 with kyc_admin_role_required
});

test("150.5 Queue pagination returns next_cursor when more items exist", async () => {
  // Create multiple cases, submit them
  // GET /v1/kyc/cases/admin/queue?limit=1
  // Verify next_cursor is non-null
  // GET with cursor returns next page
});
```

### Section 151: Admin Case Detail API (5 tests)

```typescript
test("151.1 Root can view case detail with timeline", async () => {
  // GET /v1/kyc/cases/admin/cases/{caseId} as Root
  // Verify response has files_ref, questionnaire_ref, timeline
});

test("151.2 Case detail includes uploaded file references", async () => {
  // Attach selfie, id_front, id_back to case
  // GET case detail
  // Verify files_ref has 3 entries with correct types
});

test("151.3 Case timeline shows submission event", async () => {
  // Submit case
  // GET case detail
  // Verify timeline contains event with event_type containing submit
});

test("151.4 Scoped admin without assignment gets 403", async () => {
  // Charlie (scoped admin) tries to view unassigned case
  // Expect 403 kyc_access_forbidden
});

test("151.5 Case detail for non-existent case returns 404", async () => {
  // GET /v1/kyc/cases/admin/cases/kyc_nonexistent
  // Expect 404 kyc_case_not_found
});
```

### Section 152: Approve / Reject / Request Info API (5 tests)

```typescript
test("152.1 Root approves a submitted case", async () => {
  // POST /v1/kyc/cases/admin/cases/{id}/approve
  // { expected_version, reason_codes: ["identity_verified"], note: "All documents valid" }
  // Verify case status becomes approved
});

test("152.2 Root rejects a case with reason codes", async () => {
  // POST /v1/kyc/cases/admin/cases/{id}/reject
  // { reason_codes: ["document_illegible", "name_mismatch"], note: "..." }
  // Verify case status becomes rejected
});

test("152.3 Root requests more info from applicant", async () => {
  // POST /v1/kyc/cases/admin/cases/{id}/request-info
  // { requested_items: ["proof_of_address"], note: "Please upload a utility bill" }
  // Verify case status becomes needs_more_info
});

test("152.4 Approve with wrong expected_version returns 409", async () => {
  // POST approve with expected_version=999
  // Expect 409 kyc_case_update_conflict
});

test("152.5 Approve already-approved case returns 409", async () => {
  // Approve case, then try to approve again
  // Expect 409 kyc_invalid_transition
});
```

### Section 153: Admin Metrics API (3 tests)

```typescript
test("153.1 Metrics endpoint returns funnel counts", async () => {
  // GET /v1/kyc/cases/admin/metrics as Root
  // Verify funnel_counts has status keys with numeric values
});

test("153.2 Metrics include review latency percentiles", async () => {
  // GET metrics
  // Verify review_latency_seconds has p50, p90, p99 keys
});

test("153.3 Non-admin gets 403 on metrics", async () => {
  // GET metrics as Alice
  // Expect 403
});
```

### Section 154: KYC Queue Page UI (4 tests)

```typescript
test("154.1 Queue page loads and shows pending cases", async ({ page }) => {
  // Navigate to /admin/kyc as Root
  // Verify DataTable is visible with at least one row
  // Verify columns: Case ID, Status, Risk Tier, Waiting
});

test("154.2 Status filter changes displayed cases", async ({ page }) => {
  // Select status=submitted from dropdown
  // Verify all visible status badges show "submitted"
});

test("154.3 Clicking a case row navigates to detail page", async ({ page }) => {
  // Click first row in queue table
  // Verify URL changes to /admin/kyc/cases/{id}
  // Verify case detail components are visible
});

test("154.4 Queue page shows empty state when no cases match filter", async ({ page }) => {
  // Apply filter with no matches (e.g., risk_tier=critical)
  // Verify "No cases found" empty state
});
```

### Section 155: Case Detail Page UI (3 tests)

```typescript
test("155.1 Case detail shows document tabs and viewer", async ({ page }) => {
  // Navigate to /admin/kyc/cases/{id}
  // Verify tab bar shows Selfie, ID Front, ID Back
  // Verify image is displayed in viewer area
});

test("155.2 Approve button opens confirmation dialog", async ({ page }) => {
  // Click Approve button
  // Verify dialog appears with reason code checkboxes and notes textarea
  // Fill form and submit
  // Verify success toast and status badge updates to "approved"
});

test("155.3 Case timeline shows chronological events", async ({ page }) => {
  // Verify timeline section is visible
  // Verify events are in chronological order
  // Verify each event shows timestamp and actor
});
```

### Expanded E2E: Edge Cases & Negative Tests

```typescript
test("150.6 Queue with min_waiting_seconds filter excludes recent cases", async () => {
  // Submit case just now
  // GET /v1/kyc/cases/admin/queue?min_waiting_seconds=3600
  // Verify new case is NOT in results (waiting < 1 hour)
});

test("150.7 Queue with assignee filter returns only assigned cases", async () => {
  // GET /v1/kyc/cases/admin/queue?assignee_admin_sub=root.admin@testdev.local
  // Verify all returned items have matching assigned_admin_sub
});

test("152.6 Reject with empty reason_codes returns 422", async () => {
  // POST reject with reason_codes=[]
  // Expect 422 validation error
});

test("152.7 Request-info then submit documents re-opens case", async () => {
  // Request info, then Alice uploads new documents
  // Verify case status transitions from needs_more_info back to submitted
});

test("155.4 Document viewer zoom controls change image scale", async ({ page }) => {
  // Click zoom in button
  // Verify image CSS transform scale increased
  // Click zoom out button
  // Verify scale decreased
});

test("155.5 Document viewer rotate controls change image rotation", async ({ page }) => {
  // Click rotate CW button
  // Verify image CSS transform rotation = 90deg
  // Click again
  // Verify rotation = 180deg
});

test("155.6 Concurrent admin approval triggers version conflict", async () => {
  // Two admins load same case detail (both see version N)
  // First admin approves (succeeds, version becomes N+1)
  // Second admin approves with version N
  // Expect 409 conflict
});
```

---

## 13. File Change Summary

| File | Change Type | Description |
|------|-------------|-------------|
| `frontend/src/api/endpoints/kyc-admin.ts` | **New** | API client for all admin KYC endpoints |
| `frontend/src/pages/admin/KycQueuePage.tsx` | **New** | KYC review queue with filters and table |
| `frontend/src/pages/admin/KycCaseDetailPage.tsx` | **New** | Case detail with document viewer and actions |
| `frontend/src/pages/admin/KycMetricsDashboard.tsx` | **New** | Metrics dashboard with funnel and latency |
| `frontend/src/components/shared/DocumentViewer.tsx` | **New** | Zoomable/rotatable document image viewer |
| `frontend/src/App.tsx` | Modify | Add 3 admin KYC routes |
| `frontend/src/components/layout/Sidebar.tsx` | Modify | Add KYC Review link to admin group |
| `frontend/src/components/layout/AppShell.tsx` | Modify | Add KYC Review to mobile sidebar |
| `frontend/e2e/kyc-admin-dashboard.spec.ts` | **New** | 25+ E2E tests across sections 150-155 |

---

## Codebase References

> **Verification performed**: 2026-05-29

### Verified (EXISTS in codebase)

| Reference | File | Line(s) | Status |
|-----------|------|---------|--------|
| KYC cases router (admin endpoints) | `app/routers/kyc_cases.py` | 908-1294 | VERIFIED (1294 lines total, not 1295) |
| `get_admin_kyc_metrics()` | `app/routers/kyc_cases.py` | 947 | VERIFIED (ticket cites line 946 -- off by 1) |
| `_admin_decide_case()` | `app/routers/kyc_cases.py` | 1099 | VERIFIED |
| `admin_request_more_info()` | `app/routers/kyc_cases.py` | 1021 | VERIFIED |
| `_audit_state_transition()` | `app/routers/kyc_cases.py` | 85 | VERIFIED |
| KYC cases service | `app/services/kyc_cases.py` | all | VERIFIED (828 lines) |
| `list_admin_queue()` | `app/services/kyc_cases.py` | 646 | VERIFIED |
| `kyc_cases` DDB table | `scripts/local-ddb-init.py` | 91-96 | VERIFIED (2 GSIs: owner-updated-index, status-updated-index) |
| KYC settings | `app/core/settings.py` | 1065-1072 | VERIFIED: table name, index names, retention days |
| KYC cases router registration | `app/main.py` | 406 | VERIFIED: `app.include_router(kyc_cases_router)` |
| `require_root_session` | `app/auth/deps.py` | 273 | VERIFIED |
| `audit_event()` | `app/services/alerts.py` | 695 | VERIFIED |
| `e2e_admin_session_setup.py` | project root | exists | VERIFIED |

### Not Yet Implemented (requires new code)

| Reference | Expected Location | Status |
|-----------|-------------------|--------|
| `frontend/src/pages/admin/KycQueuePage.tsx` | `frontend/src/pages/admin/` | NOT FOUND -- new page required |
| `frontend/src/pages/admin/KycCaseDetailPage.tsx` | `frontend/src/pages/admin/` | NOT FOUND -- new page required |
| `frontend/src/pages/admin/KycMetricsDashboard.tsx` | `frontend/src/pages/admin/` | NOT FOUND -- new page required |
| `frontend/src/components/shared/DocumentViewer.tsx` | `frontend/src/components/shared/` | NOT FOUND -- new component required |
| `frontend/src/api/endpoints/kyc-admin.ts` | `frontend/src/api/endpoints/` | NOT FOUND -- new endpoint file required |
| Admin KYC routes in App.tsx | `frontend/src/App.tsx` | NOT FOUND -- new routes required |
| KYC Review sidebar link | `frontend/src/components/layout/Sidebar.tsx` | NOT FOUND -- needs modification |

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_kyc_review.py`

Mock external dependencies with `moto` (DynamoDB) and `unittest.mock`. All tests run without the dev stack.

  - `test_list_pending_submissions`
  - `test_get_submission_detail`
  - `test_approve_submission`
  - `test_reject_submission_with_reason`
  - `test_request_additional_info`
  - `test_assign_reviewer`
  - `test_submission_audit_trail`
  - `test_filter_by_status`

### Integration Tests

  - Submission approval updates user verification status
  - Rejection sends notification to user with reason
  - Audit trail records reviewer identity and timestamp for each action
  - Dashboard stats count pending/approved/rejected submissions

### E2E Tests (Playwright)

**File**: `frontend/e2e/admin-kyc.spec.ts`
**Test count**: 15

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

- **DDB seeds**: Seed `kyc_submissions` table with test records in `beforeAll`
- **Test users**: Alice (USER), Bob (USER), Root (ROOT), Charlie (ADMIN) from `e2e_admin_session_setup.py`
- **Cleanup**: Tests use unique timestamps/IDs per run to avoid cross-run interference

### CI/Pipeline Considerations

- **Feature flag**: `KYC_ENABLED=true` must be set in test environment
- **Serial execution**: E2E tests run with `workers: 1` to avoid shared-state conflicts
- **Retry safety**: All tests are idempotent; retries do not produce duplicate records

## Dependencies & Merge Safety

### Depends On

| Ticket | Title | Why |
|--------|-------|-----|
| (none) | — | This ticket has no blocking dependencies |

### Depended On By

| Ticket | Title | Impact |
|--------|-------|--------|
| KYC-002 | Identity Document Verification | Reviewed through admin dashboard |
| KYC-003 | Liveness Video Verification | Reviewed through admin dashboard |
| KYC-004 | Proof of Residency | Reviewed through admin dashboard |
| KYC-005 | Proof of Funds | Reviewed through admin dashboard |
| KYC-006 | Sanctions & PEP Screening | Results viewed in admin dashboard |
| KYC-007 | Enhanced Document Signing | Signing status viewed in admin dashboard |
| KYC-008 | Risk Scoring Engine | Risk scores displayed in admin dashboard |
| KYC-009 | Tiered Verification Levels | Tier status displayed in admin dashboard |
| KYC-011 | KYC Webhooks & Notifications | Events triggered from dashboard actions |

### Merge Strategy

**Independent**

This ticket can be merged independently of other tickets. It introduces new tables/endpoints without modifying existing ones in a breaking way.

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
- [ ] All 15 E2E tests pass with `npx playwright test admin-kyc.spec.ts`
