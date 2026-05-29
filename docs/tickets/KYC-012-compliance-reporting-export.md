# KYC-012: KYC Compliance Reporting & Export

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-29  
**Priority**: High  
**Estimated effort**: 8-10 days  
**Dependencies**: KYC-001 (Admin Dashboard), KYC-006 (Sanctions & PEP Screening), KYC-008 (Risk Scoring Engine)

---

## 1. Overview & Motivation

### 1.1 The Gap

The current KYC admin system provides an admin queue (`GET /v1/kyc/cases/admin/queue`) and a basic metrics snapshot (`GET /v1/kyc/cases/admin/metrics`, line 946 in `app/routers/kyc_cases.py`). The metrics endpoint returns counts by status, average processing time, and percentile data. However, this is an operational dashboard, not a compliance reporting tool.

Regulatory compliance requires:
1. **Periodic reports** (monthly/quarterly) showing KYC volumes, approval/rejection rates, and processing times.
2. **Suspicious Activity Reports (SARs)** for flagged transactions linked to KYC-verified users.
3. **Audit trail exports** — complete history of all KYC events for a specific user or date range.
4. **Data retention compliance** — documentation of what PII exists and when it is scheduled for purge.
5. **Regulatory deadline tracking** — flagging cases that have been pending beyond acceptable thresholds.
6. **Export capabilities** — CSV and PDF formats suitable for regulatory filing.

### 1.2 What This Ticket Adds

1. **Monthly KYC volume report**: Total cases by status, approval/rejection rates, breakdown by document type, average processing time.
2. **Screening hit rate report**: Number of sanctions/PEP matches, false positive rate, escalation outcomes.
3. **Processing time report**: Distribution of time from submission to decision, by risk tier.
4. **SAR generation**: Structured Suspicious Activity Report linking KYC status to transaction anomalies.
5. **Audit trail export**: Full event log for a user or date range, exportable as CSV.
6. **Regulatory deadline tracker**: Cases pending beyond configurable thresholds, with escalation counts.
7. **Data retention report**: Inventory of stored PII, purge schedule, compliance status.
8. **Export formats**: CSV (data tables) and PDF (formatted reports).

### 1.3 Architecture

```
Admin Compliance Dashboard
       │
       ▼
  GET /v1/kyc/reports/{report_type}     → JSON report data
  POST /v1/kyc/reports/{report_type}/export  → CSV or PDF download
       │
       ├── volume_report()              → case counts, rates, averages
       ├── screening_report()           → match counts, resolution breakdown
       ├── processing_time_report()     → distribution by risk tier
       ├── sar_report()                 → SAR-structured data
       ├── audit_trail_export()         → user/date-filtered event log
       ├── deadline_tracker()           → overdue case list
       └── retention_report()           → PII inventory + purge schedule
       │
       ▼
  Export Pipeline:
       │
       ├── CSV: Python csv module → S3 upload → signed URL
       └── PDF: ReportLab/jinja2 → S3 upload → signed URL
```

---

## 2. Current State Analysis

### 2.1 Existing Metrics (`app/routers/kyc_cases.py`, line 946)

The `get_admin_kyc_metrics()` endpoint calls `STORE.get_metrics_snapshot()` (line 701 in `app/services/kyc_cases.py`) which scans the admin queue and computes:
- `total_cases`: count by status
- `processing_time_p50`, `processing_time_p95`: percentiles
- `stale_count`: cases pending longer than `stale_after_seconds` (default 48h)

This is a real-time snapshot, not a historical report. There is no date-range filtering, no breakdown by document type or risk tier, and no export capability.

### 2.2 Audit Log (`app/services/alerts.py`)

`audit_event()` (line 695) writes structured audit entries. KYC events use the `_audit_state_transition()` helper which records `event_name`, `actor_sub`, `case_id`, `from_status`, `to_status`, `action`. These are stored in the audit log table but there is no bulk query/export endpoint.

### 2.3 Existing Export Infrastructure

The codebase has `app/routers/csv_export.py` and `app/routers/audit_export.py` which handle CSV generation and download. The CSV export router provides signed S3 URLs for generated files. This pattern should be reused for KYC report exports.

### 2.4 KYC Cases Table GSIs

The `kyc_cases` table has two GSIs:
- `owner-updated-index`: PK=`gsi_owner_pk` (e.g., `OWNER#{user_sub}`), SK=`gsi_owner_sk`
- `status-updated-index`: PK=`gsi_status_pk` (e.g., `STATUS#{status}`), SK=`gsi_status_sk`

For compliance reports that need date-range queries across all cases, a new GSI or full table scan will be required. The `gsi_status_sk` includes the timestamp (`UPDATED#{ts:013d}#KYC#{case_id}`), enabling date-range queries within a specific status.

### 2.5 Billing Ledger

The billing system (`app/routers/billing.py`) maintains transaction ledger entries. SAR generation needs to cross-reference KYC status with transaction history to identify suspicious patterns.

### 2.6 Retention Purge (`app/services/kyc_cases.py`, line 747)

The `run_retention_purge()` method handles data deletion based on `kyc_retention_rejected_days` (30), `kyc_retention_expired_days` (7), and `kyc_retention_approved_days` (365) from settings. The retention report should expose this schedule and current compliance status.

---

## 3. Technical Design

### 3.1 New Router: `app/routers/kyc_reporting.py`

```python
router = APIRouter(prefix="/v1/kyc/reports", tags=["kyc-reporting"])
```

All endpoints require `require_root_session` — only root users can access compliance reports.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/volume` | `require_root_session` | Monthly volume report |
| `GET` | `/screening` | `require_root_session` | Screening hit rate report |
| `GET` | `/processing-time` | `require_root_session` | Processing time distribution |
| `GET` | `/deadlines` | `require_root_session` | Overdue case tracker |
| `GET` | `/retention` | `require_root_session` | Data retention compliance |
| `GET` | `/audit-trail/{user_sub}` | `require_root_session` | User audit trail |
| `POST` | `/sar` | `require_root_session` | Generate SAR |
| `POST` | `/{report_type}/export` | `require_root_session` | Export report as CSV/PDF |

### 3.2 New Service: `app/services/kyc_reporting.py`

```python
"""KYC compliance reporting — aggregation, export, and SAR generation."""
from __future__ import annotations

from typing import Any
import csv
import io
import uuid
from collections import defaultdict
from datetime import datetime, timezone

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.kyc_cases import STORE


def volume_report(
    *,
    start_date: int | None = None,
    end_date: int | None = None,
) -> dict[str, Any]:
    """Generate KYC volume report for a date range.

    Queries each status GSI partition to count cases within the date range.
    """
    end = end_date or now_ts()
    start = start_date or (end - 30 * 86400)  # Default: last 30 days

    statuses = ["draft", "submitted", "under_review", "needs_more_info",
                "approved", "rejected", "expired"]
    counts: dict[str, int] = {}
    total = 0

    for status in statuses:
        cases = _query_cases_by_status_date_range(status, start, end)
        counts[status] = len(cases)
        total += len(cases)

    approved = counts.get("approved", 0)
    rejected = counts.get("rejected", 0)
    decided = approved + rejected

    return {
        "report_type": "volume",
        "period_start": start,
        "period_end": end,
        "total_cases": total,
        "counts_by_status": counts,
        "approval_rate": round(approved / max(decided, 1) * 100, 1),
        "rejection_rate": round(rejected / max(decided, 1) * 100, 1),
        "generated_at": now_ts(),
    }


def processing_time_report(
    *,
    start_date: int | None = None,
    end_date: int | None = None,
) -> dict[str, Any]:
    """Report on time from submission to decision, bucketed by risk tier."""
    end = end_date or now_ts()
    start = start_date or (end - 30 * 86400)

    approved = _query_cases_by_status_date_range("approved", start, end)
    rejected = _query_cases_by_status_date_range("rejected", start, end)
    decided = approved + rejected

    durations = []
    for case in decided:
        submitted_at = (case.get("submission") or {}).get("submitted_at")
        decided_at = (case.get("review") or {}).get("decided_at")
        if submitted_at and decided_at:
            durations.append(int(decided_at) - int(submitted_at))

    durations.sort()

    return {
        "report_type": "processing_time",
        "period_start": start,
        "period_end": end,
        "total_decided": len(decided),
        "avg_seconds": round(sum(durations) / max(len(durations), 1)),
        "p50_seconds": _percentile(durations, 0.50),
        "p90_seconds": _percentile(durations, 0.90),
        "p95_seconds": _percentile(durations, 0.95),
        "min_seconds": durations[0] if durations else None,
        "max_seconds": durations[-1] if durations else None,
        "generated_at": now_ts(),
    }


def deadline_tracker(
    *,
    warn_after_hours: int = 48,
    critical_after_hours: int = 120,
) -> dict[str, Any]:
    """List cases pending beyond acceptable thresholds."""
    now = now_ts()
    warn_threshold = now - (warn_after_hours * 3600)
    critical_threshold = now - (critical_after_hours * 3600)

    pending_statuses = ["submitted", "under_review", "needs_more_info"]
    overdue_cases: list[dict] = []

    for status in pending_statuses:
        cases = STORE.list_cases_by_status(status=status, limit=100)
        for case in cases:
            submitted_at = (case.get("submission") or {}).get("submitted_at") or case.get("created_at", 0)
            age_hours = (now - int(submitted_at)) / 3600

            if int(submitted_at) < critical_threshold:
                severity = "critical"
            elif int(submitted_at) < warn_threshold:
                severity = "warning"
            else:
                continue

            overdue_cases.append({
                "case_id": case.get("kyc_case_id"),
                "user_sub": case.get("user_sub"),
                "status": case.get("status"),
                "submitted_at": submitted_at,
                "age_hours": round(age_hours, 1),
                "severity": severity,
                "assigned_admin": (case.get("review") or {}).get("assigned_admin_sub"),
            })

    overdue_cases.sort(key=lambda c: c["age_hours"], reverse=True)

    return {
        "report_type": "deadlines",
        "warn_after_hours": warn_after_hours,
        "critical_after_hours": critical_after_hours,
        "total_overdue": len(overdue_cases),
        "critical_count": sum(1 for c in overdue_cases if c["severity"] == "critical"),
        "warning_count": sum(1 for c in overdue_cases if c["severity"] == "warning"),
        "cases": overdue_cases,
        "generated_at": now_ts(),
    }


def retention_report() -> dict[str, Any]:
    """Report on data retention compliance — what PII exists and when it's due for purge."""
    now = now_ts()

    policies = {
        "rejected": S.kyc_retention_rejected_days,
        "expired": S.kyc_retention_expired_days,
        "approved": S.kyc_retention_approved_days,
    }

    inventory: list[dict] = []
    for status, retention_days in policies.items():
        cases = STORE.list_cases_by_status(status=status, limit=200)
        for case in cases:
            decided_at = (case.get("review") or {}).get("decided_at") or case.get("updated_at", 0)
            purge_due = int(decided_at) + (retention_days * 86400)
            is_overdue = purge_due < now
            files = case.get("files", [])

            inventory.append({
                "case_id": case.get("kyc_case_id"),
                "user_sub": case.get("user_sub"),
                "status": status,
                "decided_at": decided_at,
                "retention_days": retention_days,
                "purge_due_at": purge_due,
                "purge_overdue": is_overdue,
                "file_count": len(files),
                "has_selfie": any(f.get("file_type") == "selfie" for f in files),
                "has_id_document": any(f.get("file_type") in ("id_front", "id_back") for f in files),
                "has_proof_of_address": any(f.get("file_type") == "proof_of_address" for f in files),
                "purged": bool((case.get("review") or {}).get("purged_at")),
            })

    inventory.sort(key=lambda c: c["purge_due_at"])

    return {
        "report_type": "retention",
        "policies": {k: f"{v} days" for k, v in policies.items()},
        "total_records": len(inventory),
        "overdue_purge_count": sum(1 for c in inventory if c["purge_overdue"] and not c["purged"]),
        "already_purged_count": sum(1 for c in inventory if c["purged"]),
        "inventory": inventory,
        "generated_at": now_ts(),
    }


def audit_trail_for_user(user_sub: str) -> dict[str, Any]:
    """Export all KYC audit events for a specific user."""
    # Query audit log table for events related to this user
    items = _query_audit_events(user_sub=user_sub, event_prefix="kyc.")
    return {
        "report_type": "audit_trail",
        "user_sub": user_sub,
        "total_events": len(items),
        "events": items,
        "generated_at": now_ts(),
    }


def generate_sar(
    *,
    user_sub: str,
    reason: str,
    transaction_ids: list[str] | None = None,
    admin_sub: str,
) -> dict[str, Any]:
    """Generate a Suspicious Activity Report."""
    ts = now_ts()
    sar_id = f"SAR_{uuid.uuid4().hex[:12]}"

    # Gather user KYC history
    cases = STORE.list_cases_by_owner(user_sub=user_sub, limit=10)

    # Gather transaction history (from billing ledger)
    transactions = _query_user_transactions(user_sub, transaction_ids)

    sar = {
        "sar_id": sar_id,
        "generated_at": ts,
        "generated_by": admin_sub,
        "subject_user_sub": user_sub,
        "reason": reason,
        "kyc_cases": [
            {
                "case_id": c.get("kyc_case_id"),
                "status": c.get("status"),
                "created_at": c.get("created_at"),
                "decided_at": (c.get("review") or {}).get("decided_at"),
            }
            for c in cases
        ],
        "flagged_transactions": transactions,
        "audit_trail": _query_audit_events(user_sub=user_sub, event_prefix="kyc."),
    }

    # Store SAR in kyc_cases table
    T.kyc_cases.put_item(Item={
        "pk": f"SAR#{sar_id}",
        "sk": "META",
        "entity_type": "sar",
        **sar,
    })

    return sar


def export_report_csv(report_data: dict[str, Any]) -> str:
    """Convert a report to CSV format. Returns CSV string."""
    output = io.StringIO()
    writer = csv.writer(output)

    items = report_data.get("cases") or report_data.get("inventory") or report_data.get("events") or []
    if not items:
        return ""

    # Write header from first item's keys
    headers = list(items[0].keys())
    writer.writerow(headers)

    for item in items:
        writer.writerow([item.get(h, "") for h in headers])

    return output.getvalue()


def _query_cases_by_status_date_range(
    status: str, start_ts: int, end_ts: int
) -> list[dict]:
    """Query cases by status within a date range using the status GSI."""
    from app.services.kyc_cases import _status_pk, _updated_sk
    from boto3.dynamodb.conditions import Key

    start_sk = _updated_sk(start_ts, "")
    end_sk = _updated_sk(end_ts, "~")  # '~' sorts after all hex chars

    resp = T.kyc_cases.query(
        IndexName=S.kyc_cases_status_index_name,
        KeyConditionExpression=(
            Key("gsi_status_pk").eq(_status_pk(status))
            & Key("gsi_status_sk").between(start_sk, end_sk)
        ),
        Limit=500,
    )
    return resp.get("Items", [])


def _query_audit_events(*, user_sub: str, event_prefix: str) -> list[dict]:
    """Query audit events for a user with a given event prefix."""
    # In dev mode, audit events are stored in the audit_log table
    # This is a simplified implementation
    return []


def _query_user_transactions(user_sub: str, transaction_ids: list[str] | None) -> list[dict]:
    """Query billing ledger for user transactions."""
    return []


def _percentile(sorted_values: list[int], q: float) -> int | None:
    if not sorted_values:
        return None
    idx = int(len(sorted_values) * q)
    idx = min(idx, len(sorted_values) - 1)
    return sorted_values[idx]
```

### 3.3 Endpoint Implementations

```python
@router.get("/volume")
async def get_volume_report(
    start_date: int | None = Query(None),
    end_date: int | None = Query(None),
    user=Depends(require_root_session),
):
    return volume_report(start_date=start_date, end_date=end_date)


@router.get("/processing-time")
async def get_processing_time_report(
    start_date: int | None = Query(None),
    end_date: int | None = Query(None),
    user=Depends(require_root_session),
):
    return processing_time_report(start_date=start_date, end_date=end_date)


@router.get("/deadlines")
async def get_deadline_report(
    warn_after_hours: int = Query(48, ge=1),
    critical_after_hours: int = Query(120, ge=1),
    user=Depends(require_root_session),
):
    return deadline_tracker(
        warn_after_hours=warn_after_hours,
        critical_after_hours=critical_after_hours,
    )


@router.get("/retention")
async def get_retention_report(user=Depends(require_root_session)):
    return retention_report()


@router.get("/audit-trail/{user_sub}")
async def get_audit_trail(user_sub: str, user=Depends(require_root_session)):
    return audit_trail_for_user(user_sub)


@router.post("/sar")
async def create_sar(
    body: SarRequest,
    user=Depends(require_root_session),
):
    return generate_sar(
        user_sub=body.user_sub,
        reason=body.reason,
        transaction_ids=body.transaction_ids,
        admin_sub=user.sub,
    )


@router.post("/{report_type}/export")
async def export_report(
    report_type: str,
    body: ExportRequest,
    user=Depends(require_root_session),
):
    # Generate report
    generators = {
        "volume": lambda: volume_report(start_date=body.start_date, end_date=body.end_date),
        "processing-time": lambda: processing_time_report(start_date=body.start_date, end_date=body.end_date),
        "deadlines": lambda: deadline_tracker(),
        "retention": lambda: retention_report(),
    }
    if report_type not in generators:
        raise HTTPException(400, f"Unknown report type: {report_type}")

    report_data = generators[report_type]()

    if body.format == "csv":
        csv_content = export_report_csv(report_data)
        return {"format": "csv", "content": csv_content, "report_type": report_type}
    else:
        raise HTTPException(400, "Only CSV export is supported in dev mode")
```

### 3.4 Pydantic Models

```python
class SarRequest(BaseModel):
    user_sub: str = Field(min_length=1)
    reason: str = Field(min_length=10, max_length=2000)
    transaction_ids: list[str] | None = None


class ExportRequest(BaseModel):
    format: Literal["csv", "pdf"] = "csv"
    start_date: int | None = None
    end_date: int | None = None
```

### 3.5 Frontend: Admin Compliance Dashboard

**File**: `frontend/src/pages/admin/KycComplianceDashboard.tsx`

- Report type selector tabs: Volume, Processing Time, Deadlines, Retention, Audit Trail
- Date range picker for time-bounded reports
- Data tables with sortable columns
- Export button (CSV download)
- SAR generation form with user search and reason input

**Route**: `/admin/kyc/compliance` in `App.tsx`

**File**: `frontend/src/api/endpoints/kyc-reporting.ts`

```typescript
export const getVolumeReport = (params?: { start_date?: number; end_date?: number }) =>
  client.get("/v1/kyc/reports/volume", { params });
export const getDeadlineReport = (params?: { warn_after_hours?: number }) =>
  client.get("/v1/kyc/reports/deadlines", { params });
export const getRetentionReport = () => client.get("/v1/kyc/reports/retention");
export const getAuditTrail = (userSub: string) =>
  client.get(`/v1/kyc/reports/audit-trail/${userSub}`);
export const generateSar = (data: SarRequest) =>
  client.post("/v1/kyc/reports/sar", data);
export const exportReport = (reportType: string, data: ExportRequest) =>
  client.post(`/v1/kyc/reports/${reportType}/export`, data);
```

### 3.6 Registration

```python
# app/main.py
from app.routers.kyc_reporting import router as kyc_reporting_router
app.include_router(kyc_reporting_router)
```

---

## 4. Implementation Plan

### Phase 1: Reporting Service (3 days)

| File | Change |
|------|--------|
| `app/services/kyc_reporting.py` | New: report generators, CSV export, SAR generation (~400 lines) |

### Phase 2: Router (2 days)

| File | Change |
|------|--------|
| `app/routers/kyc_reporting.py` | New: 8 endpoints (~200 lines) |
| `app/contracts/kyc_cases_contract.py` | Add: `SarRequest`, `ExportRequest` models |
| `app/main.py` | Register `kyc_reporting_router` |

### Phase 3: Frontend (2 days)

| File | Change |
|------|--------|
| `frontend/src/pages/admin/KycComplianceDashboard.tsx` | New: compliance dashboard page |
| `frontend/src/api/endpoints/kyc-reporting.ts` | New: API endpoint wrappers |
| `frontend/src/App.tsx` | Add `/admin/kyc/compliance` route |

### Phase 4: E2E Tests (2 days)

| File | Change |
|------|--------|
| `frontend/e2e/kyc-reporting.spec.ts` | New: ~15 tests, sections 194-196 |

---

## 5. E2E Test Plan (`frontend/e2e/kyc-reporting.spec.ts`)

**Test file**: `frontend/e2e/kyc-reporting.spec.ts`  
**Total tests**: ~15  
**Sections**: 194-196

### Section 194: Volume & Processing Time Reports (5 tests)

1. `GET /v1/kyc/reports/volume returns report with counts by status` — Seed 3 cases (1 approved, 1 rejected, 1 draft); verify `counts_by_status.approved: 1`, `counts_by_status.rejected: 1`.
2. `Volume report calculates approval and rejection rates` — Verify `approval_rate` and `rejection_rate` sum to 100 when only approved+rejected exist.
3. `Volume report respects date range filter` — Seed cases; query with narrow date range excluding some; verify only matching cases counted.
4. `GET /v1/kyc/reports/processing-time returns percentiles` — Seed 5 decided cases with known submission-to-decision times; verify `p50_seconds` and `p95_seconds` are reasonable.
5. `Non-root user gets 403 on volume report` — Alice (USER role) queries; returns 403.

### Section 195: Deadline Tracker & Retention Report (5 tests)

1. `GET /v1/kyc/reports/deadlines returns overdue cases` — Seed a case with `submitted_at` 72 hours ago; verify it appears in `cases` with `severity: "warning"`.
2. `Critical threshold flags old cases` — Seed case submitted 200 hours ago; verify `severity: "critical"`.
3. `No overdue cases returns empty list` — Fresh environment; verify `total_overdue: 0`.
4. `GET /v1/kyc/reports/retention shows purge schedule` — Seed approved and rejected cases; verify `inventory` contains entries with `purge_due_at` and `retention_days`.
5. `Retention report identifies overdue purges` — Seed rejected case older than `kyc_retention_rejected_days`; verify `purge_overdue: true`.

### Section 196: SAR Generation & Export (5 tests)

1. `POST /v1/kyc/reports/sar generates SAR with case history` — Generate SAR for user with KYC cases; verify `sar_id` starts with `SAR_`, `kyc_cases` array is populated.
2. `SAR is stored in kyc_cases table` — After SAR generation, directly query DDB for `pk=SAR#{sar_id}`; verify record exists.
3. `SAR with short reason returns 422` — Body `{ reason: "bad" }` fails validation (min 10 chars).
4. `POST /v1/kyc/reports/volume/export returns CSV` — Export volume report as CSV; verify `format: "csv"`, content contains header row and data rows.
5. `Export with unknown report type returns 400` — POST to `/v1/kyc/reports/unknown/export`; verify 400.

### Test Setup

```typescript
const TS = Date.now();
let rootPage: Page;

test.beforeAll(async ({ browser }) => {
  rootPage = await browser.newPage();
  await injectAuth(rootPage, "root");

  // Seed KYC cases for reporting tests
  // Case 1: approved
  const case1 = await apiPost(rootPage, "root", "/v1/kyc/cases", {});
  // ... submit and approve case1
  // Case 2: rejected
  // Case 3: draft (pending)
});
```

### Edge Cases

| Edge Case | Expected Behavior |
|-----------|-------------------|
| No cases exist in date range | Volume report returns all zeros, rates are 0 |
| All cases are in draft (no decisions) | Processing time report returns `null` for all percentiles |
| SAR for user with no KYC history | SAR generated with empty `kyc_cases` array |
| CSV export with no data | Returns empty CSV string |
| Very large date range (1 year) | Query paginates through GSI; may hit 500 item limit per status |

---

## 6. Security Considerations

- All reporting endpoints require `require_root_session` — only root users can access compliance data.
- SAR records are stored in the `kyc_cases` table and are subject to the same access controls.
- CSV exports do not include raw document images or file contents — only metadata (case ID, status, timestamps).
- Audit trail exports include event names and actor IDs but not the actual document data.
- PDF export (future) will include a watermark and generation metadata for provenance tracking.

---

## 7. Rollback Plan

- Remove `app/routers/kyc_reporting.py` import from `app/main.py`.
- Delete `app/services/kyc_reporting.py` and `app/routers/kyc_reporting.py`.
- SAR records stored with `pk=SAR#*` are independent and can remain inert in the table.
