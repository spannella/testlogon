# KYC-019: KYC Case Assignment & Workload Management

**Ticket**: KYC-019
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 8-10 days
**Depends on**: KYC-001 (Admin Review Dashboard), KYC-008 (Risk Scoring Engine)

---

## 1. Overview & Motivation

### 1.1 Problem Statement

The existing KYC admin queue (`list_admin_kyc_queue` in `app/routers/kyc_cases.py`, line 909) presents all pending cases in a flat list sorted by risk tier and waiting time. Admin assignment is implicit -- the `KycCaseReviewRef` (`app/contracts/kyc_cases_contract.py`, line 44) has an `assigned_admin_sub` field, but there is no logic to auto-assign cases, balance workload across admins, enforce SLAs, or escalate overdue cases. In practice, admins manually pick cases from the queue, leading to cherry-picking (easy cases first), uneven workloads, and missed SLA deadlines.

For a compliance operation at scale, the platform needs:
- **Smart assignment**: Automatically route cases to the right admin based on availability, expertise, and current workload.
- **SLA enforcement**: Different verification tiers have different processing time requirements. Breached SLAs must trigger escalation.
- **Workload visibility**: Compliance managers need to see how cases are distributed, which admins are overloaded, and where bottlenecks exist.
- **Escalation chains**: When an SLA is breached, the case must automatically escalate through a defined chain (reviewer -> senior reviewer -> compliance officer).

### 1.2 How It Works

1. When a KYC case transitions to `submitted` or `under_review`, the assignment engine evaluates eligible admins.
2. The engine scores each eligible admin on: current case count (lower is better), tier expertise match, language preference match with the applicant, and on-duty status.
3. The case is assigned to the highest-scoring admin. The `assigned_admin_sub` is written to the case record and a notification is sent.
4. SLA timers start when the case enters `under_review`. Each tier has a configurable deadline.
5. A background task runs every 5 minutes to check SLA compliance. Breached cases are escalated per the escalation rules.
6. Admins can toggle their availability (on-duty/off-duty). Off-duty admins are excluded from auto-assignment but retain their existing cases.
7. Manual reassignment is supported with a required reason (audit trail).

### 1.3 SLA Configuration

| Tier | Target Processing Time | Warning Threshold | Escalation Threshold |
|------|----------------------|-------------------|---------------------|
| tier_1 (Basic) | 24 hours | 18 hours (75%) | 24 hours (100%) |
| tier_2 (Enhanced) | 48 hours | 36 hours (75%) | 48 hours (100%) |
| tier_3 (Full Due Diligence) | 5 business days (120h) | 96 hours (80%) | 120 hours (100%) |

### 1.4 Escalation Chain

```
Level 0: Assigned reviewer (initial)
Level 1: Senior reviewer (first escalation — SLA breached)
Level 2: Compliance officer (second escalation — SLA + 50% breached)
Level 3: Compliance director (third escalation — SLA + 100% breached, alert sent)
```

Each escalation reassigns the case and sends notifications to both the new assignee and the previous one.

### 1.5 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| System | Auto-assign a submitted case to an available admin | Case `assigned_admin_sub` populated; notification sent |
| Admin | Toggle on-duty/off-duty status | Off-duty admin excluded from new assignments; existing cases retained |
| Admin | Manually reassign a case to another admin | Reassignment recorded with reason; audit log entry created |
| Manager | View workload distribution across admins | Dashboard shows cases per admin, avg processing time |
| System | Escalate case when SLA breached | Case reassigned to next level; escalation event in timeline |
| Manager | Configure SLA rules per tier | SLA config stored and applied by the background checker |

---

## 2. Current State Analysis

### 2.1 Admin Queue (`app/routers/kyc_cases.py`, line 909)

The `list_admin_kyc_queue` function queries the `kyc_cases` table's `status-updated-index` GSI for cases with status `submitted` or `under_review`. Results are sorted by risk tier (critical first) and then by waiting time (oldest first) via the `_risk` helper (line 664). The response uses `KycAdminQueueEnvelope` with `KycAdminQueueItem` models that include `assigned_admin_sub`, `waiting_seconds`, and `risk_tier` fields.

The queue currently supports no filtering by assigned admin and has no assignment logic.

### 2.2 KYC Case Store (`app/services/kyc_cases.py`)

The `KycCaseStore` class (line 97) has `update_case_links` (line 245) which can update the `review` sub-object (including `assigned_admin_sub`) via conditional writes with version checks. The `apply_admin_decision` method (line 534) is called when an admin approves/rejects a case. Neither method triggers any auto-assignment logic.

### 2.3 Admin Roles (`app/auth/roles.py`)

The `Role` enum defines `USER`, `ADMIN`, `ROOT`. Admin profiles (`AdminProfile` dataclass) have `scopes` that can restrict admin access to specific feature areas. Currently there is no concept of KYC-specific admin expertise, seniority level, or language preferences.

### 2.4 Alert System (`app/services/alerts.py`)

The `write_alert` function (line 355) creates in-app alerts with `event`, `outcome`, `title`, `details` parameters. This is the integration point for assignment and escalation notifications.

### 2.5 Existing Metrics (`app/routers/kyc_cases.py`, line 947)

The `get_admin_kyc_metrics` endpoint returns `KycMetricsSummaryOut` with `funnel_counts`, `review_latency_seconds`, and `stale_queue_count`. These metrics are aggregate only -- there is no per-admin breakdown.

---

## 3. Technical Design

### 3.1 New Service: `app/services/kyc_assignment.py`

```python
@dataclass
class AdminAvailability:
    admin_sub: str
    on_duty: bool
    current_case_count: int
    avg_processing_hours: float
    expertise_tiers: list[str]       # ["tier_1", "tier_2"]
    languages: list[str]             # ["en", "es"]
    seniority_level: int             # 0=reviewer, 1=senior, 2=officer, 3=director
    last_assigned_at: int            # Unix timestamp

class KycAssignmentService:
    def auto_assign(self, *, case_id: str, case_tier: str,
                    applicant_language: str = "en") -> str | None:
        """Score eligible admins and assign the case to the best match.
        Returns assigned admin_sub or None if no eligible admin found."""

    def manual_reassign(self, *, case_id: str, new_admin_sub: str,
                        reason: str, actor_sub: str) -> dict[str, Any]:
        """Manually reassign a case with audit trail."""

    def set_admin_availability(self, *, admin_sub: str,
                                on_duty: bool) -> dict[str, Any]:
        """Toggle admin on-duty/off-duty status."""

    def get_admin_availability(self, admin_sub: str) -> AdminAvailability:
        """Get current availability and workload for an admin."""

    def list_admin_workloads(self) -> list[AdminAvailability]:
        """Get workload stats for all KYC admins."""

    def check_sla_compliance(self) -> list[dict[str, Any]]:
        """Check all under_review cases for SLA breaches.
        Returns list of cases that need escalation."""

    def escalate_case(self, *, case_id: str, current_level: int,
                      reason: str) -> dict[str, Any]:
        """Escalate case to next level in the chain."""

    def get_sla_config(self) -> dict[str, dict[str, int]]:
        """Return SLA configuration per tier."""

    def update_sla_config(self, *, tier: str, target_hours: int,
                           warning_pct: int, actor_sub: str) -> dict[str, Any]:
        """Update SLA config for a tier (root only)."""

    def _score_admin(self, admin: AdminAvailability, *,
                     case_tier: str, language: str) -> float:
        """Score an admin for assignment.
        Factors: workload (40%), expertise match (30%), language (20%), recency (10%)."""
```

### 3.2 Admin Assignment Scoring Algorithm

```
score = (workload_score * 0.4) + (expertise_score * 0.3) +
        (language_score * 0.2) + (recency_score * 0.1)

workload_score = 1.0 - (current_case_count / max_cases_per_admin)
  — Capped at 0.0 when at capacity

expertise_score = 1.0 if case_tier in admin.expertise_tiers else 0.3

language_score = 1.0 if applicant_language in admin.languages else 0.5

recency_score = 1.0 - min(1.0, hours_since_last_assignment / 8.0)
  — Penalizes recently-assigned admins to spread load
```

### 3.3 DynamoDB Storage

**Admin availability and workload** -- stored in the existing `kyc_cases` table using a single-table pattern:

```
PK: ADMIN#{admin_sub}
SK: AVAILABILITY

Attributes:
  on_duty (BOOL)
  expertise_tiers (L)
  languages (L)
  seniority_level (N)
  max_cases (N)            — default 20
  updated_at (N)
```

**SLA configuration** -- stored in the `kyc_cases` table:

```
PK: CONFIG
SK: SLA#{tier}

Attributes:
  target_hours (N)
  warning_pct (N)
  escalation_pct (N)
  updated_at (N)
  updated_by (S)
```

**Assignment audit log** -- stored in the `kyc_cases` table:

```
PK: AUDIT#ASSIGN#{case_id}
SK: {timestamp}#{event_id}

Attributes:
  event_type (S)           — "auto_assign" | "manual_reassign" | "escalation"
  from_admin (S)
  to_admin (S)
  reason (S)
  actor_sub (S)
  escalation_level (N)
```

No new DDB table needed -- all data fits in the existing `kyc_cases` table via single-table design.

### 3.4 Background SLA Checker

Add a background task to `app/main.py` startup, following the same pattern as the newsfeed scheduler (`app/services/newsfeed_scheduler.py`, line 369):

```python
async def kyc_sla_checker_loop():
    """Runs every 5 minutes. Queries all under_review cases,
    checks SLA compliance, escalates breached cases."""
    while True:
        try:
            assignment_svc = KycAssignmentService()
            breached = assignment_svc.check_sla_compliance()
            for case in breached:
                assignment_svc.escalate_case(
                    case_id=case["kyc_case_id"],
                    current_level=case.get("escalation_level", 0),
                    reason=f"SLA breached: {case['hours_overdue']:.1f}h overdue"
                )
        except Exception:
            logger.exception("KYC SLA checker error")
        await asyncio.sleep(300)  # 5 minutes
```

Register in `app/main.py`:

```python
app.add_event_handler("startup", lambda: asyncio.create_task(kyc_sla_checker_loop()))
```

### 3.5 Router Endpoints

Add to `app/routers/kyc_cases.py`:

```python
# Assignment endpoints
POST /v1/kyc/cases/{case_id}/assign
  — Auto-assign case to best available admin
  — Auth: require_admin_session
  — Response: { "assigned_admin_sub": str, "score": float }

POST /v1/kyc/cases/{case_id}/reassign
  — Manual reassignment
  — Auth: require_admin_session
  — Body: { "new_admin_sub": str, "reason": str }
  — Response: { "ok": true, "previous_admin_sub": str }

# Admin availability
PATCH /v1/kyc/admin/availability
  — Set on-duty/off-duty + update expertise/languages
  — Auth: require_admin_session
  — Body: { "on_duty": bool, "expertise_tiers": [...], "languages": [...] }

GET /v1/kyc/admin/availability
  — Get own availability status
  — Auth: require_admin_session

# Workload dashboard
GET /v1/kyc/admin/workloads
  — Get all admins' workload stats
  — Auth: require_admin_session
  — Response: { "admins": [AdminAvailability], "sla_config": {...} }

# SLA configuration (root only)
GET /v1/kyc/admin/sla-config
  — Get SLA settings per tier
  — Auth: require_root_session

PATCH /v1/kyc/admin/sla-config/{tier}
  — Update SLA settings for a tier
  — Auth: require_root_session
  — Body: { "target_hours": int, "warning_pct": int }

# Assignment audit
GET /v1/kyc/cases/{case_id}/assignment-history
  — Get assignment/escalation history for a case
  — Auth: require_admin_session
  — Response: { "events": [...] }
```

### 3.6 Frontend: Admin Workload Dashboard

**Components:**

- `WorkloadDashboard` — Tab within the existing KYC admin page, showing:
  - Bar chart: cases per admin (active, completed today, SLA warning, SLA breached)
  - Table: admin list with on-duty toggle, case count, avg processing time
  - SLA config panel (root only): edit target hours and warning thresholds per tier
- `AssignmentPanel` — Side panel on case detail showing assignment history, reassign button
- `AvailabilityToggle` — On-duty/off-duty switch in admin header

**Route**: No new route needed -- integrates into existing admin KYC views.

**API endpoints in `frontend/src/api/endpoints/kyc-admin.ts`:**

```typescript
export const autoAssignCase = (caseId: string) =>
  client.post(`/v1/kyc/cases/${caseId}/assign`);

export const reassignCase = (caseId: string, data: { new_admin_sub: string; reason: string }) =>
  client.post(`/v1/kyc/cases/${caseId}/reassign`, data);

export const setAvailability = (data: { on_duty: boolean; expertise_tiers: string[]; languages: string[] }) =>
  client.patch("/v1/kyc/admin/availability", data);

export const getWorkloads = () =>
  client.get<{ admins: AdminAvailability[]; sla_config: SlaConfig }>("/v1/kyc/admin/workloads");

export const getAssignmentHistory = (caseId: string) =>
  client.get<{ events: AssignmentEvent[] }>(`/v1/kyc/cases/${caseId}/assignment-history`);

export const updateSlaConfig = (tier: string, data: { target_hours: number; warning_pct: number }) =>
  client.patch(`/v1/kyc/admin/sla-config/${tier}`, data);
```

---

## 4. E2E Test Plan

**Test file**: `frontend/e2e/kyc-assignment.spec.ts`
**Total**: ~18 tests across 4 sections (221-224)

### Section 221: Auto-Assignment API (5 tests)

```typescript
test("221.1 Auto-assign routes case to on-duty admin", async ({ page }) => {
  // Set Charlie (admin) as on-duty, submit KYC case
  // POST /v1/kyc/cases/{id}/assign
  // Expect assigned_admin_sub == charlie_sub
});

test("221.2 Auto-assign skips off-duty admins", async ({ page }) => {
  // Set Charlie off-duty, set Root as on-duty
  // POST assign -> expect assigned to Root (not Charlie)
});

test("221.3 Auto-assign prefers admin with matching tier expertise", async ({ page }) => {
  // Charlie: expertise=["tier_1"], Root: expertise=["tier_2"]
  // Submit tier_2 case, assign -> Root
});

test("221.4 Auto-assign returns null when no admin available", async ({ page }) => {
  // All admins off-duty
  // POST assign -> 200 with assigned_admin_sub=null
});

test("221.5 Non-admin cannot trigger auto-assign", async ({ page }) => {
  // Alice (USER) POST assign -> 403
});
```

### Section 222: Manual Reassignment & Availability (5 tests)

```typescript
test("222.1 Admin manually reassigns case with reason", async ({ page }) => {
  // POST reassign with new_admin_sub and reason
  // Expect ok=true, previous_admin_sub populated
});

test("222.2 Reassignment without reason returns 400", async ({ page }) => {
  // POST reassign with empty reason -> 400
});

test("222.3 Admin toggles on-duty/off-duty", async ({ page }) => {
  // PATCH availability with on_duty=false
  // GET availability -> on_duty=false
});

test("222.4 Admin sets expertise tiers and languages", async ({ page }) => {
  // PATCH availability with expertise_tiers=["tier_1","tier_2"], languages=["en","es"]
  // GET availability -> fields match
});

test("222.5 Assignment history records all events", async ({ page }) => {
  // Auto-assign + manual reassign
  // GET assignment-history -> 2 events (auto_assign + manual_reassign)
});
```

### Section 223: SLA Configuration & Escalation (5 tests)

```typescript
test("223.1 Root reads default SLA config per tier", async ({ page }) => {
  // GET /v1/kyc/admin/sla-config
  // Expect tier_1.target_hours=24, tier_2.target_hours=48
});

test("223.2 Root updates SLA config for tier_1", async ({ page }) => {
  // PATCH sla-config/tier_1 with target_hours=12
  // GET -> tier_1.target_hours=12
});

test("223.3 Non-root cannot update SLA config", async ({ page }) => {
  // Charlie (admin) PATCH sla-config -> 403
});

test("223.4 Escalation creates audit event and reassigns", async ({ page }) => {
  // Create case, assign to level-0 reviewer
  // Simulate SLA breach by backdating under_review timestamp
  // Trigger SLA check -> case escalated, new admin assigned
  // Assignment history shows escalation event
});

test("223.5 Multiple escalation levels progress through chain", async ({ page }) => {
  // Escalate twice -> escalation_level=2
  // Assignment history shows 2 escalation events with increasing levels
});
```

### Section 224: Workload Dashboard UI (3 tests)

```typescript
test("224.1 Admin sees workload table with case counts", async ({ page }) => {
  // Navigate to admin KYC page, click Workload tab
  // Expect table with admin names, case counts, on-duty status
});

test("224.2 Admin toggles availability via UI", async ({ page }) => {
  // Click on-duty toggle, verify badge changes
});

test("224.3 Reassign dialog shows admin list and requires reason", async ({ page }) => {
  // Open case detail, click Reassign
  // Expect dialog with admin dropdown and reason textarea
  // Submit -> case shows new assignee
});
```

---

## 5. File Change Summary

| File | Change Type | Description |
|------|-------------|-------------|
| `app/services/kyc_assignment.py` | **New** | Assignment engine, scoring, SLA checks, escalation |
| `app/routers/kyc_cases.py` | Modify | Add 7 assignment/availability/SLA endpoints |
| `app/contracts/kyc_cases_contract.py` | Modify | Add assignment request/response models |
| `app/main.py` | Modify | Register SLA checker background task |
| `app/core/settings.py` | Modify | Add `kyc_sla_*` and `kyc_assignment_*` settings |
| `frontend/src/api/endpoints/kyc-admin.ts` | **New** | API client functions for assignment/workload |
| `frontend/src/api/types.ts` | Modify | Add `AdminAvailability`, `SlaConfig`, `AssignmentEvent` types |
| `frontend/src/components/shared/WorkloadDashboard.tsx` | **New** | Workload chart and admin table |
| `frontend/src/components/shared/AssignmentPanel.tsx` | **New** | Case assignment history and reassign UI |
| `frontend/e2e/kyc-assignment.spec.ts` | **New** | 18 E2E tests across sections 221-224 |
