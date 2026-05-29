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
(implemented in `app/routers/kyc_cases.py`, lines 908-1295), including queue listing with
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

## 2. Current State Analysis

### 2.1 Existing Admin KYC Endpoints

The following endpoints in `app/routers/kyc_cases.py` are fully implemented and tested:

| Endpoint | Method | Line | Purpose |
|----------|--------|------|---------|
| `/v1/kyc/cases/admin/queue` | GET | 908 | List cases with status/assignee/risk/wait filters |
| `/v1/kyc/cases/admin/metrics` | GET | 946 | Funnel counts, review latency, stale queue |
| `/v1/kyc/cases/admin/purge/run` | POST | 972 | Retention purge (dry_run supported) |
| `/v1/kyc/cases/admin/cases/{case_id}` | GET | 996 | Full case detail with timeline |
| `/v1/kyc/cases/admin/cases/{case_id}/request-info` | POST | 1020 | Request more info from applicant |
| `/v1/kyc/cases/admin/cases/{case_id}/approve` | POST | 1184 | Approve case |
| `/v1/kyc/cases/admin/cases/{case_id}/reject` | POST | 1195 | Reject case |

### 2.2 Response Shapes

**Admin queue item** (`KycAdminQueueItem` in `app/contracts/kyc_cases_contract.py`, line 177):
- `kyc_case_id`, `user_sub`, `status`, `assigned_admin_sub`, `created_at`, `updated_at`
- `waiting_seconds` (computed server-side), `risk_tier` (from `intake_profile`)

**Admin case detail** (`KycAdminCaseDetailOut`, line 201):
- `kyc_case_id`, `user_sub`, `status`
- `questionnaire_ref` (questionnaire_id, version_id, response_session_id, response_pdf_ref)
- `files_ref[]` (type, path, verification_state for each file)
- `signature_ref` (packet_id, status, final_pdf_ref)
- `ticket_ref` (ticket_id from review)
- `decision_state` (decision, reason_codes, decided_at)
- `timeline[]` (event_type, source, created_at, actor_sub, details)

**Metrics** (`KycMetricsSummaryOut`, line 218):
- `funnel_counts` (dict of status -> count)
- `review_latency_seconds` (p50, p90, p99 percentiles)
- `stale_queue_count`, `submit_guard_failures_by_reason`
- `ticket_sync_counters`, `ticket_sync_deadletter_count`

### 2.3 File Access Pattern

KYC files are stored via the file manager. Each file entry in `case.files[]` has a `path`
field pointing to a file manager node. The file content URL is resolved via
`GET /ui/files/download?path={path}` which returns a presigned S3 URL. The frontend
document viewer will use these URLs for image rendering.

### 2.4 Auth & Scopes

All admin endpoints check `normalize_role(user.role) in {Role.ADMIN, Role.ROOT}` (line 920).
The scoped admin check (`_is_scoped_admin_for_case`, line 63) additionally verifies that a
scoped admin is the assigned reviewer for case detail/actions. ROOT bypasses scope checks.

### 2.5 Existing Admin Page Structure

Admin pages live in `frontend/src/pages/admin/`. Examples:
- `RootRoleManagementPage.tsx` -- admin role management
- `ModerationBoardPage.tsx` -- content moderation queue
- `VideoReviewQueuePage.tsx` -- video review

The KYC dashboard will follow the same layout and component patterns.

---

## 3. Technical Design

### 3.1 Frontend API Layer

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

### 3.2 Frontend Pages

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

### 3.3 Routing

**File: `frontend/src/App.tsx`** -- add routes:

```tsx
<Route path="/admin/kyc" element={<KycQueuePage />} />
<Route path="/admin/kyc/cases/:caseId" element={<KycCaseDetailPage />} />
<Route path="/admin/kyc/metrics" element={<KycMetricsDashboard />} />
```

### 3.4 Sidebar Navigation

**File: `frontend/src/components/layout/Sidebar.tsx`** -- add to Admin group:

```tsx
{ icon: ShieldCheck, label: "KYC Review", href: "/admin/kyc", adminOnly: true }
```

### 3.5 Document Viewer Component

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

## 4. E2E Test Plan

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

---

## 5. File Change Summary

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
| `frontend/e2e/kyc-admin-dashboard.spec.ts` | **New** | 25 E2E tests across sections 150-155 |
