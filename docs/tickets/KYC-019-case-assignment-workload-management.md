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

## 2. Architecture Diagram

```
                    ┌──────────────────────────────────────────┐
                    │           Admin Frontend (React)          │
                    │  ┌───────────────┐  ┌─────────────────┐  │
                    │  │WorkloadDashboard│ │AssignmentPanel  │  │
                    │  │  - Bar chart    │ │  - History      │  │
                    │  │  - Admin table  │ │  - Reassign btn │  │
                    │  │  - SLA config   │ │  - Audit trail  │  │
                    │  └───────┬────────┘  └────────┬────────┘  │
                    │          │                     │           │
                    │  ┌───────▼─────────────────────▼────────┐ │
                    │  │ AvailabilityToggle (header bar)       │ │
                    │  └──────────────────────────────────────┘ │
                    └──────────────────┬───────────────────────┘
                                       │ HTTP (Axios + CSRF)
                                       ▼
                    ┌──────────────────────────────────────────┐
                    │           Backend (FastAPI)                │
                    │                                           │
                    │  ┌────────────────────────────────────┐  │
                    │  │    app/routers/kyc_cases.py         │  │
                    │  │  POST /assign                       │  │
                    │  │  POST /reassign                     │  │
                    │  │  PATCH /admin/availability           │  │
                    │  │  GET  /admin/workloads               │  │
                    │  │  GET  /admin/sla-config              │  │
                    │  │  PATCH /admin/sla-config/{tier}      │  │
                    │  │  GET  /cases/{id}/assignment-history  │  │
                    │  └──────────────┬─────────────────────┘  │
                    │                 │                          │
                    │  ┌──────────────▼─────────────────────┐  │
                    │  │   KycAssignmentService               │  │
                    │  │  auto_assign()                       │  │
                    │  │  manual_reassign()                   │  │
                    │  │  check_sla_compliance()              │  │
                    │  │  escalate_case()                     │  │
                    │  │  _score_admin()                      │  │
                    │  └──────────────┬─────────────────────┘  │
                    │                 │                          │
                    │  ┌──────────────▼─────────────────────┐  │
                    │  │   Background SLA Checker Loop       │  │
                    │  │   (every 5 minutes)                  │  │
                    │  │   - Query under_review cases         │  │
                    │  │   - Check SLA compliance             │  │
                    │  │   - Escalate breached cases          │  │
                    │  └────────────────────────────────────┘  │
                    └──────────────────┬───────────────────────┘
                                       │
                                       ▼
                    ┌──────────────────────────────────────────┐
                    │        DynamoDB (kyc_cases table)         │
                    │                                           │
                    │  PK: ADMIN#{sub}  SK: AVAILABILITY        │
                    │    on_duty, expertise_tiers, languages,   │
                    │    seniority_level, max_cases             │
                    │                                           │
                    │  PK: CONFIG  SK: SLA#{tier}               │
                    │    target_hours, warning_pct              │
                    │                                           │
                    │  PK: AUDIT#ASSIGN#{case_id}  SK: {ts}    │
                    │    event_type, from_admin, to_admin,      │
                    │    reason, escalation_level               │
                    │                                           │
                    │  Case items: assigned_admin_sub,          │
                    │    escalation_level, sla_deadline_at      │
                    └──────────────────────────────────────────┘

Assignment Scoring Flow:
  Case submitted → auto_assign()
       │
       ▼
  Query all ADMIN# AVAILABILITY items
       │
       ▼
  Filter: on_duty=true, case_count < max_cases
       │
       ▼
  Score each admin:
    workload_score * 0.4 + expertise_score * 0.3
    + language_score * 0.2 + recency_score * 0.1
       │
       ▼
  Assign to highest-scoring admin
       │
       ▼
  Write audit log entry (auto_assign)
       │
       ▼
  Send notification to assigned admin
```

---

## 3. Current State Analysis

### 3.1 Admin Queue (`app/routers/kyc_cases.py`, line 909)

The `list_admin_kyc_queue` function queries the `kyc_cases` table's `status-updated-index` GSI for cases with status `submitted` or `under_review`. Results are sorted by risk tier (critical first) and then by waiting time (oldest first) via the `_risk` helper (line 664). The response uses `KycAdminQueueEnvelope` with `KycAdminQueueItem` models that include `assigned_admin_sub`, `waiting_seconds`, and `risk_tier` fields.

The queue currently supports no filtering by assigned admin and has no assignment logic.

### 3.2 KYC Case Store (`app/services/kyc_cases.py`)

The `KycCaseStore` class (line 97) has `update_case_links` (line 245) which can update the `review` sub-object (including `assigned_admin_sub`) via conditional writes with version checks. The `apply_admin_decision` method (line 534) is called when an admin approves/rejects a case. Neither method triggers any auto-assignment logic.

### 3.3 Admin Roles (`app/auth/roles.py`)

The `Role` enum defines `USER`, `ADMIN`, `ROOT`. Admin profiles (`AdminProfile` dataclass) have `scopes` that can restrict admin access to specific feature areas. Currently there is no concept of KYC-specific admin expertise, seniority level, or language preferences.

### 3.4 Alert System (`app/services/alerts.py`)

The `write_alert` function (line 355) creates in-app alerts with `event`, `outcome`, `title`, `details` parameters. This is the integration point for assignment and escalation notifications.

### 3.5 Existing Metrics (`app/routers/kyc_cases.py`, line 947)

The `get_admin_kyc_metrics` endpoint returns `KycMetricsSummaryOut` with `funnel_counts`, `review_latency_seconds`, and `stale_queue_count`. These metrics are aggregate only -- there is no per-admin breakdown.

---

## 4. Technical Design

### 4.1 New Service: `app/services/kyc_assignment.py`

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

### 4.2 Admin Assignment Scoring Algorithm

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

### 4.3 Pydantic Models

```python
# app/contracts/kyc_cases_contract.py additions

from pydantic import BaseModel, Field
from typing import Optional, List


class AdminAvailabilityIn(BaseModel):
    """Request body for PATCH /admin/availability."""
    on_duty: bool = Field(..., description="Whether admin is available for new assignments")
    expertise_tiers: List[str] = Field(
        default_factory=list,
        description="Tiers this admin is qualified to review",
        max_length=5,
    )
    languages: List[str] = Field(
        default_factory=list,
        description="Languages this admin can review in",
        max_length=10,
    )
    max_cases: int = Field(default=20, ge=1, le=100,
                           description="Maximum concurrent case assignments")

    class Config:
        json_schema_extra = {
            "example": {
                "on_duty": True,
                "expertise_tiers": ["tier_1", "tier_2"],
                "languages": ["en", "es"],
                "max_cases": 20,
            }
        }


class AdminAvailabilityOut(BaseModel):
    """Response model for admin availability."""
    admin_sub: str
    on_duty: bool = False
    current_case_count: int = 0
    avg_processing_hours: float = 0.0
    expertise_tiers: List[str] = Field(default_factory=list)
    languages: List[str] = Field(default_factory=list)
    seniority_level: int = 0
    max_cases: int = 20
    last_assigned_at: Optional[int] = None
    updated_at: Optional[int] = None


class AutoAssignOut(BaseModel):
    """Response for POST /assign."""
    assigned_admin_sub: Optional[str] = None
    score: float = 0.0
    reason: str = ""


class ReassignRequest(BaseModel):
    """Request body for POST /reassign."""
    new_admin_sub: str = Field(..., min_length=1)
    reason: str = Field(..., min_length=3, max_length=500,
                        description="Reason for manual reassignment")


class ReassignOut(BaseModel):
    """Response for POST /reassign."""
    ok: bool = True
    previous_admin_sub: Optional[str] = None
    new_admin_sub: str = ""
    reason: str = ""


class SlaConfigOut(BaseModel):
    """SLA configuration for a single tier."""
    tier: str
    target_hours: int
    warning_pct: int
    escalation_pct: int = 100
    updated_at: Optional[int] = None
    updated_by: Optional[str] = None


class SlaConfigUpdateIn(BaseModel):
    """Request body for PATCH /sla-config/{tier}."""
    target_hours: int = Field(..., ge=1, le=720,
                              description="Target processing hours")
    warning_pct: int = Field(..., ge=50, le=99,
                             description="Warning threshold as percentage of target")


class AssignmentEventOut(BaseModel):
    """Single assignment audit event."""
    event_type: str  # "auto_assign" | "manual_reassign" | "escalation"
    from_admin: Optional[str] = None
    to_admin: Optional[str] = None
    reason: str = ""
    actor_sub: Optional[str] = None
    escalation_level: Optional[int] = None
    created_at: int = 0


class AssignmentHistoryOut(BaseModel):
    """Response for GET /assignment-history."""
    events: List[AssignmentEventOut] = Field(default_factory=list)


class WorkloadDashboardOut(BaseModel):
    """Response for GET /admin/workloads."""
    admins: List[AdminAvailabilityOut] = Field(default_factory=list)
    sla_config: dict = Field(default_factory=dict)
    total_active_cases: int = 0
    total_on_duty_admins: int = 0
```

### 4.4 DynamoDB Storage & Access Patterns

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

**Detailed Access Patterns:**

| # | Access Pattern | Table / GSI | PK | SK | Operation | Notes |
|---|---------------|-------------|----|----|-----------|-------|
| 1 | Get admin availability | Main table | `ADMIN#{sub}` | `AVAILABILITY` | GetItem | O(1) lookup |
| 2 | List all admin availabilities | Main table | N/A | N/A | Scan with filter `begins_with(pk, "ADMIN#")` + `sk = "AVAILABILITY"` | Limited to ~50 admins; scan is acceptable |
| 3 | Update admin availability | Main table | `ADMIN#{sub}` | `AVAILABILITY` | PutItem | Overwrites entire availability record |
| 4 | Get SLA config for tier | Main table | `CONFIG` | `SLA#{tier}` | GetItem | O(1) |
| 5 | List all SLA configs | Main table | `CONFIG` | `begins_with("SLA#")` | Query | Returns all tier configs |
| 6 | Update SLA config | Main table | `CONFIG` | `SLA#{tier}` | PutItem | Root-only operation |
| 7 | Write assignment audit event | Main table | `AUDIT#ASSIGN#{case_id}` | `{ts}#{event_id}` | PutItem | Append-only log |
| 8 | Get assignment history for case | Main table | `AUDIT#ASSIGN#{case_id}` | All | Query (ScanIndexForward=False) | Reverse chronological |
| 9 | Count admin's active cases | GSI `assigned-admin-index` | `assigned_admin_sub` | N/A | Query with `status IN (submitted, under_review)` | For workload scoring |
| 10 | Find SLA-breached cases | GSI `status-updated-index` | `status=under_review` | N/A | Query + filter `sla_deadline_at < now()` | Background SLA checker |

**Example DynamoDB Items:**

Admin availability:
```json
{
  "pk": "ADMIN#charlie-uuid",
  "sk": "AVAILABILITY",
  "on_duty": true,
  "expertise_tiers": ["tier_1", "tier_2"],
  "languages": ["en", "es"],
  "seniority_level": 1,
  "max_cases": 20,
  "updated_at": 1748520000
}
```

SLA config:
```json
{
  "pk": "CONFIG",
  "sk": "SLA#tier_1",
  "target_hours": 24,
  "warning_pct": 75,
  "escalation_pct": 100,
  "updated_at": 1748520000,
  "updated_by": "root.admin@testdev.local"
}
```

Assignment audit event:
```json
{
  "pk": "AUDIT#ASSIGN#kyc_abc123",
  "sk": "1748520100#evt_def456",
  "event_type": "auto_assign",
  "from_admin": null,
  "to_admin": "charlie-uuid",
  "reason": "Auto-assigned: score=0.87 (highest eligible)",
  "actor_sub": "SYSTEM",
  "escalation_level": 0,
  "created_at": 1748520100
}
```

### 4.5 Background SLA Checker

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

### 4.6 Router Endpoints

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

### 4.7 API Request/Response Examples

**POST /v1/kyc/cases/{case_id}/assign**

```bash
curl -X POST http://localhost:8000/v1/kyc/cases/kyc_abc123/assign \
  -H "Cookie: ui_session=sess_xxx; ui_csrf=csrf_xxx; ui_access_token=jwt_xxx" \
  -H "x-csrf-token: csrf_xxx"
```

Response (200):
```json
{
  "assigned_admin_sub": "charlie-uuid",
  "score": 0.87,
  "reason": "Highest scoring eligible admin: workload=0.9, expertise=1.0, language=1.0, recency=0.6"
}
```

**POST /v1/kyc/cases/{case_id}/assign (no eligible admin)**

Response (200):
```json
{
  "assigned_admin_sub": null,
  "score": 0.0,
  "reason": "No eligible admins: all off-duty or at capacity"
}
```

**POST /v1/kyc/cases/{case_id}/reassign**

```bash
curl -X POST http://localhost:8000/v1/kyc/cases/kyc_abc123/reassign \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_xxx; ui_csrf=csrf_xxx; ui_access_token=jwt_xxx" \
  -H "x-csrf-token: csrf_xxx" \
  -d '{"new_admin_sub": "root-uuid", "reason": "Charlie on vacation, reassigning to root"}'
```

Response (200):
```json
{
  "ok": true,
  "previous_admin_sub": "charlie-uuid",
  "new_admin_sub": "root-uuid",
  "reason": "Charlie on vacation, reassigning to root"
}
```

**PATCH /v1/kyc/admin/availability**

```bash
curl -X PATCH http://localhost:8000/v1/kyc/admin/availability \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_xxx; ui_csrf=csrf_xxx; ui_access_token=jwt_xxx" \
  -H "x-csrf-token: csrf_xxx" \
  -d '{"on_duty": true, "expertise_tiers": ["tier_1", "tier_2"], "languages": ["en", "es"], "max_cases": 25}'
```

Response (200):
```json
{
  "admin_sub": "charlie-uuid",
  "on_duty": true,
  "current_case_count": 5,
  "avg_processing_hours": 12.3,
  "expertise_tiers": ["tier_1", "tier_2"],
  "languages": ["en", "es"],
  "seniority_level": 1,
  "max_cases": 25,
  "last_assigned_at": 1748520000,
  "updated_at": 1748520100
}
```

**GET /v1/kyc/admin/workloads**

Response (200):
```json
{
  "admins": [
    {
      "admin_sub": "charlie-uuid",
      "on_duty": true,
      "current_case_count": 5,
      "avg_processing_hours": 12.3,
      "expertise_tiers": ["tier_1", "tier_2"],
      "languages": ["en", "es"],
      "seniority_level": 1,
      "max_cases": 20,
      "last_assigned_at": 1748520000
    },
    {
      "admin_sub": "root-uuid",
      "on_duty": true,
      "current_case_count": 3,
      "avg_processing_hours": 8.1,
      "expertise_tiers": ["tier_1", "tier_2", "tier_3"],
      "languages": ["en"],
      "seniority_level": 3,
      "max_cases": 10,
      "last_assigned_at": 1748510000
    }
  ],
  "sla_config": {
    "tier_1": {"target_hours": 24, "warning_pct": 75},
    "tier_2": {"target_hours": 48, "warning_pct": 75},
    "tier_3": {"target_hours": 120, "warning_pct": 80}
  },
  "total_active_cases": 8,
  "total_on_duty_admins": 2
}
```

**GET /v1/kyc/cases/{case_id}/assignment-history**

Response (200):
```json
{
  "events": [
    {
      "event_type": "auto_assign",
      "from_admin": null,
      "to_admin": "charlie-uuid",
      "reason": "Auto-assigned: score=0.87",
      "actor_sub": "SYSTEM",
      "escalation_level": null,
      "created_at": 1748520100
    },
    {
      "event_type": "escalation",
      "from_admin": "charlie-uuid",
      "to_admin": "root-uuid",
      "reason": "SLA breached: 25.3h overdue",
      "actor_sub": "SYSTEM",
      "escalation_level": 1,
      "created_at": 1748610000
    }
  ]
}
```

### 4.8 Frontend: Admin Workload Dashboard

**Components:**

- `WorkloadDashboard` -- Tab within the existing KYC admin page, showing:
  - Bar chart: cases per admin (active, completed today, SLA warning, SLA breached)
  - Table: admin list with on-duty toggle, case count, avg processing time
  - SLA config panel (root only): edit target hours and warning thresholds per tier
- `AssignmentPanel` -- Side panel on case detail showing assignment history, reassign button
- `AvailabilityToggle` -- On-duty/off-duty switch in admin header

**Route**: No new route needed -- integrates into existing admin KYC views.

### 4.9 Frontend Component Tree

```
KycAdminPage
├── Tabs: "Queue" | "Workload" | "SLA Config"
├── WorkloadTab
│   ├── SummaryCards
│   │   ├── Card: "Total Active Cases" (number)
│   │   ├── Card: "On-Duty Admins" (number)
│   │   └── Card: "Avg Processing Time" (hours)
│   ├── WorkloadBarChart
│   │   └── Bar per admin: active/warning/breached case counts
│   └── AdminTable
│       ├── TableHeader: [Admin, Status, Cases, Avg Time, Expertise, Actions]
│       └── AdminRow (for each admin)
│           ├── Avatar + Name
│           ├── OnDutyBadge (green/gray)
│           ├── CaseCountBadge (number, color-coded if near max)
│           ├── AvgTimeDisplay
│           ├── ExpertiseTags (tier badges)
│           └── Actions: [View Cases]
├── SlaConfigTab (root only)
│   └── SlaConfigTable
│       ├── TableHeader: [Tier, Target Hours, Warning %, Actions]
│       └── SlaConfigRow (for each tier)
│           ├── TierBadge
│           ├── EditableHoursInput
│           ├── EditablePercentInput
│           └── SaveButton
└── CaseDetailPanel (side panel)
    ├── AssignmentSection
    │   ├── CurrentAssigneeBadge
    │   ├── AssignButton (auto-assign)
    │   └── ReassignButton → ReassignDialog
    │       ├── AdminSelector (dropdown of on-duty admins)
    │       ├── ReasonTextarea (required)
    │       └── SubmitButton
    └── AssignmentHistoryTimeline
        └── EventItem (for each event)
            ├── EventIcon (assign/reassign/escalation)
            ├── EventDescription
            └── Timestamp
```

**Props interfaces:**

```typescript
interface WorkloadDashboardProps {
  isRoot: boolean;
}

interface AdminTableRowProps {
  admin: AdminAvailability;
  onViewCases: (adminSub: string) => void;
}

interface SlaConfigRowProps {
  config: SlaConfig;
  onSave: (tier: string, data: { target_hours: number; warning_pct: number }) => void;
  editable: boolean;
}

interface ReassignDialogProps {
  caseId: string;
  currentAdminSub?: string;
  availableAdmins: AdminAvailability[];
  onReassign: (adminSub: string, reason: string) => void;
  onClose: () => void;
}

interface AssignmentHistoryTimelineProps {
  events: AssignmentEvent[];
}
```

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

## 5. Error Handling Matrix

| Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|----------|-------------|------------|---------------------|-----------------|
| Case not found | 404 | `case_not_found` | "KYC case not found" | Verify case ID |
| Non-admin attempts assignment | 403 | `forbidden` | "Admin session required" | Use admin credentials |
| No eligible admins for auto-assign | 200 | N/A | Returns `assigned_admin_sub=null` | Wait for admin to come on-duty |
| Reassign with empty reason | 422 | `validation_error` | "Reason must be at least 3 characters" | Provide a reason |
| Reassign to non-existent admin | 404 | `admin_not_found` | "Admin not found" | Use valid admin sub |
| Non-root updates SLA config | 403 | `forbidden` | "Root session required" | Contact root admin |
| Invalid SLA target_hours (< 1) | 422 | `validation_error` | "target_hours must be at least 1" | Use valid value |
| Case already assigned (re-assign) | 200 | N/A | Previous admin recorded in response | Intentional re-assignment |
| SLA config tier not recognized | 400 | `invalid_tier` | "Tier 'tier_4' is not recognized" | Use tier_1, tier_2, or tier_3 |
| Background SLA checker DDB error | N/A | Logged | N/A (background task) | Auto-retries on next 5-min cycle |
| Admin at max case capacity | 200 (skipped) | N/A | Admin excluded from scoring | Admin excluded; others scored |

---

## 6. Observability & Monitoring

### 6.1 Metrics

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `kyc_assignment_total` | Counter | `type` (auto/manual/escalation), `tier` | Total case assignments |
| `kyc_assignment_score` | Histogram | `tier` | Distribution of assignment scores |
| `kyc_admin_case_count` | Gauge | `admin_sub`, `status` | Current cases per admin |
| `kyc_admin_on_duty_count` | Gauge | | Number of on-duty admins |
| `kyc_sla_breached_total` | Counter | `tier`, `escalation_level` | SLA breach events |
| `kyc_sla_warning_total` | Counter | `tier` | Cases entering SLA warning zone |
| `kyc_escalation_total` | Counter | `from_level`, `to_level` | Escalation events |
| `kyc_assignment_latency_ms` | Histogram | `type` | Time to compute assignment |
| `kyc_sla_checker_duration_ms` | Histogram | | Background SLA check cycle duration |

### 6.2 Log Events

| Log Event | Level | Fields | Trigger |
|-----------|-------|--------|---------|
| `assignment.auto_assigned` | INFO | `case_id`, `admin_sub`, `score`, `tier` | Auto-assignment completes |
| `assignment.no_eligible` | WARNING | `case_id`, `tier`, `reason` | No eligible admin found |
| `assignment.manual_reassigned` | INFO | `case_id`, `from`, `to`, `reason`, `actor` | Manual reassignment |
| `assignment.escalated` | WARNING | `case_id`, `from_level`, `to_level`, `hours_overdue` | SLA escalation |
| `assignment.sla_warning` | INFO | `case_id`, `tier`, `pct_elapsed` | Case entering SLA warning |
| `sla_checker.completed` | DEBUG | `cases_checked`, `breached_count`, `duration_ms` | SLA check cycle completes |
| `sla_checker.error` | ERROR | `error_message` | SLA checker fails |

### 6.3 Alerting

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| No admins on duty | `kyc_admin_on_duty_count` = 0 for > 30 minutes | Critical | Page compliance manager |
| High SLA breach rate | > 5 breaches in 1 hour | Warning | Review admin capacity and SLA targets |
| Escalation to level 3 | Any case reaches escalation level 3 | Critical | Alert compliance director directly |
| Unassigned cases accumulating | > 10 unassigned cases for > 1 hour | Warning | Auto-assignment may be failing; check logs |
| SLA checker not running | No `sla_checker.completed` log in 15 minutes | Critical | Background task may have died; restart backend |

---

## 7. Rollout Plan

### 7.1 Feature Flags

| Flag | Environment Variable | Default | Description |
|------|---------------------|---------|-------------|
| `KYC_ASSIGNMENT_ENABLED` | `KYC_ASSIGNMENT_ENABLED` | `true` (dev), `false` (prod) | Master switch |
| `KYC_SLA_CHECKER_ENABLED` | `KYC_SLA_CHECKER_ENABLED` | `true` | Enable background SLA checker |
| `KYC_AUTO_ASSIGN_ON_SUBMIT` | `KYC_AUTO_ASSIGN_ON_SUBMIT` | `false` | Auto-assign when case is submitted |

### 7.2 Phased Rollout

**Phase 1: Infrastructure (Days 1-3)**
- Create `KycAssignmentService` with scoring algorithm
- Add DDB items for admin availability and SLA config
- Seed default SLA configs for all tiers
- Add assignment audit log write

**Phase 2: Endpoints + SLA Checker (Days 4-6)**
- Add 7 router endpoints
- Implement background SLA checker
- Integrate with alert system for notifications

**Phase 3: Frontend Dashboard (Days 7-8)**
- Build WorkloadDashboard, AssignmentPanel, AvailabilityToggle
- Integrate into existing admin KYC page

**Phase 4: E2E Tests + Rollout (Days 9-10)**
- Write 18 E2E tests
- Enable `KYC_ASSIGNMENT_ENABLED=true` in prod
- Monitor for 1 week before enabling auto-assign-on-submit

---

## 8. Performance Considerations

### 8.1 Query Costs

| Operation | DDB Operations | Estimated Cost |
|-----------|---------------|----------------|
| Auto-assign (scoring) | 1 Scan (admin avails, ~50 items) + N Queries (case counts) + 2 PutItems | ~50 RCU + 2 WCU |
| Manual reassign | 1 GetItem + 1 UpdateItem + 1 PutItem (audit) | 2 WCU + 1 RCU |
| SLA check cycle | 1 Query (under_review cases) + N conditional checks | ~100 RCU per cycle |
| Workload dashboard | 1 Scan (admins) + N Queries (case counts) | ~50 RCU |

### 8.2 Caching Strategy

| Cache Layer | TTL | Scope | Invalidation |
|-------------|-----|-------|-------------|
| Admin availability (in-memory) | 60 seconds | Service-level cache | On PATCH /availability |
| SLA config (in-memory) | 5 minutes | Service-level cache | On PATCH /sla-config |
| Workload stats | 30 seconds | React Query (frontend) | Manual invalidation on assignment |

### 8.3 Rate Limiting

| Endpoint | Limit | Scope |
|----------|-------|-------|
| POST /assign | 20 per minute per admin | Prevent rapid re-assignment |
| POST /reassign | 10 per minute per admin | Prevent abuse |
| PATCH /availability | 10 per minute per admin | Normal toggle rate |
| GET /workloads | 30 per minute per admin | Dashboard refresh |

---

## 9. E2E Test Plan

**Test file**: `frontend/e2e/kyc-assignment.spec.ts`
**Total**: ~24 tests across 5 sections (221-225)

### Section 221: Auto-Assignment API (6 tests)

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

test("221.6 Auto-assign prefers admin with lower workload", async ({ page }) => {
  // Charlie has 15 cases, Root has 3 cases, both on-duty with same expertise
  // POST assign -> Root (lower workload score)
});
```

### Section 222: Manual Reassignment & Availability (6 tests)

```typescript
test("222.1 Admin manually reassigns case with reason", async ({ page }) => {
  // POST reassign with new_admin_sub and reason
  // Expect ok=true, previous_admin_sub populated
});

test("222.2 Reassignment without reason returns 422", async ({ page }) => {
  // POST reassign with empty reason -> 422
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

test("222.6 Reassign to non-existent admin returns 404", async ({ page }) => {
  // POST reassign with new_admin_sub="nonexistent"
  // Expect 404
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

### Section 224: Workload Dashboard API (4 tests)

```typescript
test("224.1 Workload endpoint returns all admin stats", async ({ page }) => {
  // GET /v1/kyc/admin/workloads
  // Expect admins array with admin_sub, case_count, on_duty
});

test("224.2 Workload includes SLA config in response", async ({ page }) => {
  // GET workloads -> sla_config has tier_1, tier_2, tier_3 entries
});

test("224.3 Non-admin cannot access workloads", async ({ page }) => {
  // Alice GET workloads -> 403
});

test("224.4 Workload counts reflect assignment changes", async ({ page }) => {
  // Assign a case, GET workloads -> admin case_count incremented
});
```

### Section 225: Workload Dashboard UI (3 tests)

```typescript
test("225.1 Admin sees workload table with case counts", async ({ page }) => {
  // Navigate to admin KYC page, click Workload tab
  // Expect table with admin names, case counts, on-duty status
});

test("225.2 Admin toggles availability via UI", async ({ page }) => {
  // Click on-duty toggle, verify badge changes
});

test("225.3 Reassign dialog shows admin list and requires reason", async ({ page }) => {
  // Open case detail, click Reassign
  // Expect dialog with admin dropdown and reason textarea
  // Submit -> case shows new assignee
});
```

---

## 10. File Change Summary

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
| `frontend/e2e/kyc-assignment.spec.ts` | **New** | 24 E2E tests across sections 221-225 |

---

## 11. Security Considerations

### 11.1 Access Control

| Endpoint | Auth | Notes |
|----------|------|-------|
| POST /assign | `require_admin_session` | Only admins can trigger assignment |
| POST /reassign | `require_admin_session` | Only admins; audit trail recorded |
| PATCH /availability | `require_admin_session` | Admin updates own availability |
| GET /workloads | `require_admin_session` | Admins see all workload data |
| GET/PATCH /sla-config | `require_root_session` | Only root can read/modify SLA rules |
| GET /assignment-history | `require_admin_session` | Visible to any admin for any case |

### 11.2 Audit Trail

Every assignment action (auto, manual, escalation) is recorded in the audit log with:
- Actor identity (admin sub or "SYSTEM" for auto-actions)
- Timestamp
- From/to admin
- Reason text
- Escalation level (if applicable)

Audit records are append-only and cannot be deleted (no DELETE endpoint).
