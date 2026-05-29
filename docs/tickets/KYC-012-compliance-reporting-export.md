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

The current KYC admin system provides an admin queue (`GET /v1/kyc/cases/admin/queue`) and a basic metrics snapshot (`GET /v1/kyc/cases/admin/metrics` — see `app/routers/kyc_cases.py:947` for `get_admin_kyc_metrics`). The metrics endpoint returns counts by status, average processing time, and percentile data. However, this is an operational dashboard, not a compliance reporting tool.

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

### 2.1 Existing Metrics (see `app/routers/kyc_cases.py:947`)

The `get_admin_kyc_metrics()` endpoint calls `STORE.get_metrics_snapshot()` (see `app/services/kyc_cases.py:701`) which scans the admin queue and computes:
- `total_cases`: count by status
- `processing_time_p50`, `processing_time_p95`: percentiles
- `stale_count`: cases pending longer than `stale_after_seconds` (default 48h)

This is a real-time snapshot, not a historical report. There is no date-range filtering, no breakdown by document type or risk tier, and no export capability.

### 2.2 Audit Log (`app/services/alerts.py`)

`audit_event()` (see `app/services/alerts.py:695`) writes structured audit entries. KYC events use the `_audit_state_transition()` helper (see `app/routers/kyc_cases.py:85`) which records `event_name`, `actor_sub`, `case_id`, `from_status`, `to_status`, `action`. These are stored in the audit log table but there is no bulk query/export endpoint.

### 2.3 Existing Export Infrastructure

The codebase has `app/routers/csv_export.py` (see `app/routers/csv_export.py`) and `app/routers/audit_export.py` (see `app/routers/audit_export.py`) which handle CSV generation and download. The CSV export router provides signed S3 URLs for generated files. This pattern should be reused for KYC report exports.

### 2.4 KYC Cases Table GSIs

The `kyc_cases` table has two GSIs:
- `owner-updated-index`: PK=`gsi_owner_pk` (e.g., `OWNER#{user_sub}`), SK=`gsi_owner_sk`
- `status-updated-index`: PK=`gsi_status_pk` (e.g., `STATUS#{status}`), SK=`gsi_status_sk`

For compliance reports that need date-range queries across all cases, a new GSI or full table scan will be required. The `gsi_status_sk` includes the timestamp (`UPDATED#{ts:013d}#KYC#{case_id}`), enabling date-range queries within a specific status.

### 2.5 Billing Ledger

The billing system (`app/routers/billing.py`) maintains transaction ledger entries. SAR generation needs to cross-reference KYC status with transaction history to identify suspicious patterns.

### 2.6 Retention Purge (see `app/services/kyc_cases.py:747`)

The `run_retention_purge()` method handles data deletion based on `kyc_retention_rejected_days` (30), `kyc_retention_expired_days` (7), and `kyc_retention_approved_days` (365) from settings (see `app/core/settings.py:1065-1072`). The retention report should expose this schedule and current compliance status.

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


def screening_report(
    *,
    start_date: int | None = None,
    end_date: int | None = None,
) -> dict[str, Any]:
    """Report on sanctions/PEP screening hit rates and resolution outcomes.

    Queries screening results from the kyc_cases table where items use
    sk=SCREEN#{ts} to store individual screening results linked to a case.
    """
    end = end_date or now_ts()
    start = start_date or (end - 30 * 86400)

    # Scan screening results stored as separate items
    # Each screening result has sk beginning with SCREEN#
    from boto3.dynamodb.conditions import Attr
    resp = T.kyc_cases.scan(
        FilterExpression=(
            Attr("entity_type").eq("screening_result")
            & Attr("created_at").between(start, end)
        ),
        Limit=1000,
    )
    results = resp.get("Items", [])

    total_screens = len(results)
    hits = [r for r in results if r.get("match_count", 0) > 0]
    resolutions = defaultdict(int)
    for hit in hits:
        resolutions[hit.get("resolution", "pending")] += 1

    return {
        "report_type": "screening",
        "period_start": start,
        "period_end": end,
        "total_screenings": total_screens,
        "total_hits": len(hits),
        "hit_rate_pct": round(len(hits) / max(total_screens, 1) * 100, 2),
        "resolutions": dict(resolutions),
        "false_positive_count": resolutions.get("false_positive", 0),
        "escalated_count": resolutions.get("escalated", 0),
        "confirmed_count": resolutions.get("confirmed_match", 0),
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


@router.get("/screening")
async def get_screening_report(
    start_date: int | None = Query(None),
    end_date: int | None = Query(None),
    user=Depends(require_root_session),
):
    return screening_report(start_date=start_date, end_date=end_date)


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
        "screening": lambda: screening_report(start_date=body.start_date, end_date=body.end_date),
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

### 3.4 Frontend: Admin Compliance Dashboard

**File**: `frontend/src/pages/admin/KycComplianceDashboard.tsx`

- Report type selector tabs: Volume, Screening, Processing Time, Deadlines, Retention, Audit Trail
- Date range picker for time-bounded reports
- Data tables with sortable columns
- Export button (CSV download)
- SAR generation form with user search and reason input

**Route**: `/admin/kyc/compliance` in `App.tsx`

**File**: `frontend/src/api/endpoints/kyc-reporting.ts`

```typescript
export const getVolumeReport = (params?: { start_date?: number; end_date?: number }) =>
  client.get("/v1/kyc/reports/volume", { params });
export const getScreeningReport = (params?: { start_date?: number; end_date?: number }) =>
  client.get("/v1/kyc/reports/screening", { params });
export const getProcessingTimeReport = (params?: { start_date?: number; end_date?: number }) =>
  client.get("/v1/kyc/reports/processing-time", { params });
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

### 3.5 Registration

```python
# app/main.py
from app.routers.kyc_reporting import router as kyc_reporting_router
app.include_router(kyc_reporting_router)
```

---

## 4. Architecture Diagram

```
┌────────────────────────────────────────────────────────────────────────────┐
│                         Admin Browser (Root Session)                       │
│                                                                            │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │  KycComplianceDashboard.tsx                                          │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌───────────┐ │  │
│  │  │ Volume   │ │Screening │ │Processing│ │Deadlines │ │ Retention │ │  │
│  │  │   Tab    │ │   Tab    │ │ Time Tab │ │   Tab    │ │    Tab    │ │  │
│  │  └─────┬────┘ └─────┬────┘ └─────┬────┘ └────┬─────┘ └─────┬─────┘ │  │
│  │        │             │            │           │             │        │  │
│  │        ▼             ▼            ▼           ▼             ▼        │  │
│  │  ┌──────────────────────────────────────────────────────────────┐    │  │
│  │  │  useQuery(["kyc-reports", reportType, dateRange])            │    │  │
│  │  │  → axios GET /v1/kyc/reports/{type}?start_date=&end_date=   │    │  │
│  │  └──────────────────────────┬───────────────────────────────────┘    │  │
│  │                             │                                        │  │
│  │  ┌──────────────────────────┼──────────────────────────────────┐    │  │
│  │  │  ExportButton            │                                   │    │  │
│  │  │  → useMutation POST /v1/kyc/reports/{type}/export           │    │  │
│  │  │  → triggers CSV download via Blob URL                       │    │  │
│  │  └──────────────────────────┼──────────────────────────────────┘    │  │
│  │                             │                                        │  │
│  │  ┌──────────────────────────┼──────────────────────────────────┐    │  │
│  │  │  SarGenerationForm       │                                   │    │  │
│  │  │  → useMutation POST /v1/kyc/reports/sar                     │    │  │
│  │  │  → user_sub + reason + transaction_ids                      │    │  │
│  │  └──────────────────────────┼──────────────────────────────────┘    │  │
│  └─────────────────────────────┼────────────────────────────────────────┘  │
└────────────────────────────────┼──────────────────────────────────────────┘
                                 │  HTTPS + ui_session cookie + CSRF
                                 ▼
┌────────────────────────────────────────────────────────────────────────────┐
│                    FastAPI Backend  (port 8000)                             │
│                                                                            │
│  app/routers/kyc_reporting.py                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  GET  /v1/kyc/reports/volume         → volume_report()              │   │
│  │  GET  /v1/kyc/reports/screening      → screening_report()           │   │
│  │  GET  /v1/kyc/reports/processing-time → processing_time_report()    │   │
│  │  GET  /v1/kyc/reports/deadlines      → deadline_tracker()           │   │
│  │  GET  /v1/kyc/reports/retention      → retention_report()           │   │
│  │  GET  /v1/kyc/reports/audit-trail/{sub} → audit_trail_for_user()    │   │
│  │  POST /v1/kyc/reports/sar            → generate_sar()               │   │
│  │  POST /v1/kyc/reports/{type}/export  → export_report_csv()          │   │
│  └────────────────────────┬────────────────────────────────────────────┘   │
│                           │                                                │
│  app/services/kyc_reporting.py                                             │
│  ┌────────────────────────┼────────────────────────────────────────────┐   │
│  │                        ▼                                            │   │
│  │  volume_report()        screening_report()     deadline_tracker()   │   │
│  │       │                      │                       │              │   │
│  │       ▼                      ▼                       ▼              │   │
│  │  _query_cases_by       T.kyc_cases.scan()     STORE.list_cases     │   │
│  │  _status_date_range()   (entity_type=         _by_status()         │   │
│  │   └→ GSI query           screening_result)                         │   │
│  │                                                                     │   │
│  │  retention_report()    audit_trail_for_user()  generate_sar()       │   │
│  │       │                      │                       │              │   │
│  │       ▼                      ▼                       ▼              │   │
│  │  STORE.list_cases      _query_audit_events()  T.kyc_cases.put_item │   │
│  │  _by_status()           (audit_log table)     (pk=SAR#...)          │   │
│  │                                                                     │   │
│  │  export_report_csv()                                                │   │
│  │       │                                                             │   │
│  │       ▼                                                             │   │
│  │  csv.writer → StringIO → response body                              │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                            │
│  ┌──────────────────────────────┐  ┌────────────────────────────────────┐  │
│  │  require_root_session        │  │  app/services/kyc_cases.py         │  │
│  │  (all endpoints gated)       │  │  STORE.list_cases_by_status()      │  │
│  │                              │  │  STORE.list_cases_by_owner()       │  │
│  │  Validates:                  │  │  STORE.get_metrics_snapshot()      │  │
│  │  • ui_session cookie         │  │                                    │  │
│  │  • ui_access_token JWT       │  │  app/services/alerts.py            │  │
│  │  • role == ROOT              │  │  audit_event()                     │  │
│  │  • x-csrf-token header       │  │                                    │  │
│  └──────────────────────────────┘  └────────────────────────────────────┘  │
└─────────────────────────────────────────┬──────────────────────────────────┘
                                          │
                                          ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    DynamoDB Local  (port 8001)                               │
│                                                                             │
│  kyc_cases table                                                            │
│  ┌────────────────────────────┬──────────────────────────────────────────┐  │
│  │  pk = KYC#{case_id}        │  sk = META                               │  │
│  │                            │  status, user_sub, created_at, files,    │  │
│  │                            │  submission, review, intake_profile       │  │
│  ├────────────────────────────┼──────────────────────────────────────────┤  │
│  │  pk = KYC#{case_id}        │  sk = SCREEN#{ts}                        │  │
│  │                            │  entity_type=screening_result,           │  │
│  │                            │  match_count, resolution, created_at     │  │
│  ├────────────────────────────┼──────────────────────────────────────────┤  │
│  │  pk = SAR#{sar_id}         │  sk = META                               │  │
│  │                            │  entity_type=sar, generated_at,          │  │
│  │                            │  generated_by, reason, kyc_cases,        │  │
│  │                            │  flagged_transactions, audit_trail       │  │
│  ├────────────────────────────┼──────────────────────────────────────────┤  │
│  │  GSI: status-updated-index │                                          │  │
│  │  gsi_status_pk = STATUS#X  │  gsi_status_sk = UPDATED#{ts:013d}#...  │  │
│  │  (enables date-range queries per status)                              │  │
│  └────────────────────────────┴──────────────────────────────────────────┘  │
│                                                                             │
│  audit_log table (read-only for reporting)                                  │
│  ┌────────────────────────────┬──────────────────────────────────────────┐  │
│  │  pk = USER#{user_sub}      │  sk = EVENT#{ts}#{event_id}              │  │
│  │                            │  event_name, actor_sub, outcome, ...     │  │
│  └────────────────────────────┴──────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 5. DynamoDB Access Patterns

### 5.1 Access Patterns Table

| Operation | Table | PK | SK / KeyCondition | GSI | Filter | Notes |
|-----------|-------|----|--------------------|-----|--------|-------|
| Volume report: count cases per status in date range | `kyc_cases` | — | `gsi_status_sk BETWEEN start AND end` | `status-updated-index` | — | One query per status (7 statuses); Limit=500 |
| Screening report: all screening results in date range | `kyc_cases` | — | — | — | `entity_type=screening_result AND created_at BETWEEN` | Full table scan with filter; Limit=1000 |
| Deadline tracker: pending cases by status | `kyc_cases` | — | `gsi_status_pk=STATUS#{status}` | `status-updated-index` | — | One query per pending status (3); Limit=100 |
| Retention report: decided cases by status | `kyc_cases` | — | `gsi_status_pk=STATUS#{status}` | `status-updated-index` | — | One query per retention status (3); Limit=200 |
| Audit trail for user | `audit_log` | `USER#{user_sub}` | `sk begins_with EVENT#` | — | `event_name begins_with "kyc."` | Paginated query |
| Generate SAR: get user's cases | `kyc_cases` | — | `gsi_owner_pk=OWNER#{user_sub}` | `owner-updated-index` | — | Limit=10 |
| Store SAR | `kyc_cases` | `SAR#{sar_id}` | `META` | — | — | PutItem |
| Export CSV | — | — | — | — | — | In-memory; no DDB access |

### 5.2 Example Items

**Volume report query result (single case from GSI)**:

```json
{
  "pk": "KYC#kyc_a1b2c3d4",
  "sk": "META",
  "gsi_status_pk": "STATUS#approved",
  "gsi_status_sk": "UPDATED#0001717000500#KYC#kyc_a1b2c3d4",
  "status": "approved",
  "user_sub": "user_abc123",
  "created_at": 1716900000,
  "updated_at": 1717000500,
  "submission": {
    "submitted_at": 1716950000,
    "evidence_snapshot": { "files_attached": 4 }
  },
  "review": {
    "decided_at": 1717000500,
    "decision": "approved",
    "decided_by": "root.admin@testdev.local",
    "reason_codes": []
  }
}
```

**SAR stored item**:

```json
{
  "pk": "SAR#SAR_7f3a2b1c9d0e",
  "sk": "META",
  "entity_type": "sar",
  "sar_id": "SAR_7f3a2b1c9d0e",
  "generated_at": 1717100000,
  "generated_by": "root.admin@testdev.local",
  "subject_user_sub": "user_abc123",
  "reason": "Unusual transaction patterns following KYC approval — high volume of P2P payments within first 48 hours.",
  "kyc_cases": [
    {
      "case_id": "kyc_a1b2c3d4",
      "status": "approved",
      "created_at": 1716900000,
      "decided_at": 1717000500
    }
  ],
  "flagged_transactions": [],
  "audit_trail": []
}
```

**Screening result item (for screening report scan)**:

```json
{
  "pk": "KYC#kyc_e5f6g7h8",
  "sk": "SCREEN#1717050000",
  "entity_type": "screening_result",
  "case_id": "kyc_e5f6g7h8",
  "provider": "mock_sanctions",
  "match_count": 1,
  "resolution": "false_positive",
  "matches": [
    {
      "list": "OFAC_SDN",
      "name_score": 78,
      "matched_name": "John Smith",
      "reason": "Common name match only — DOB mismatch"
    }
  ],
  "created_at": 1717050000,
  "resolved_at": 1717060000,
  "resolved_by": "root.admin@testdev.local"
}
```

### 5.3 GSI Query Construction

The `_query_cases_by_status_date_range` function builds the SK range for the `status-updated-index`:

```
Start SK: UPDATED#{start_ts:013d}#          → "UPDATED#0001716900000#"
End SK:   UPDATED#{end_ts:013d}#~           → "UPDATED#0001717100000#~"
```

The `#~` suffix ensures the end bound is inclusive of all case IDs at the end timestamp (since `~` sorts after all hex characters in the case ID suffix).

### 5.4 Capacity Estimates

| Operation | Read Units (approx) | Frequency |
|-----------|---------------------|-----------|
| Volume report (7 status queries, 500 items each) | 7 x ~125 RCU = 875 | On-demand (admin clicks) |
| Screening report (table scan, 1000 items) | ~250 RCU | On-demand |
| Deadline tracker (3 status queries, 100 items each) | 3 x ~25 RCU = 75 | On-demand |
| Retention report (3 status queries, 200 items each) | 3 x ~50 RCU = 150 | On-demand |
| SAR generation (owner query + audit query + put) | ~50 RCU + 1 WCU | Rare |

---

## 6. API Request/Response Examples

### 6.1 Volume Report

```bash
curl -s -b "ui_session=sess_root123; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_root123" \
  "http://localhost:8000/v1/kyc/reports/volume?start_date=1716800000&end_date=1717100000"
```

Response (200):
```json
{
  "report_type": "volume",
  "period_start": 1716800000,
  "period_end": 1717100000,
  "total_cases": 47,
  "counts_by_status": {
    "draft": 3,
    "submitted": 8,
    "under_review": 5,
    "needs_more_info": 2,
    "approved": 22,
    "rejected": 6,
    "expired": 1
  },
  "approval_rate": 78.6,
  "rejection_rate": 21.4,
  "generated_at": 1717200000
}
```

### 6.2 Screening Report

```bash
curl -s -b "ui_session=sess_root123; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_root123" \
  "http://localhost:8000/v1/kyc/reports/screening?start_date=1716800000&end_date=1717100000"
```

Response (200):
```json
{
  "report_type": "screening",
  "period_start": 1716800000,
  "period_end": 1717100000,
  "total_screenings": 42,
  "total_hits": 5,
  "hit_rate_pct": 11.9,
  "resolutions": {
    "false_positive": 3,
    "escalated": 1,
    "confirmed_match": 1
  },
  "false_positive_count": 3,
  "escalated_count": 1,
  "confirmed_count": 1,
  "generated_at": 1717200000
}
```

### 6.3 Deadline Tracker

```bash
curl -s -b "ui_session=sess_root123; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_root123" \
  "http://localhost:8000/v1/kyc/reports/deadlines?warn_after_hours=48&critical_after_hours=120"
```

Response (200):
```json
{
  "report_type": "deadlines",
  "warn_after_hours": 48,
  "critical_after_hours": 120,
  "total_overdue": 3,
  "critical_count": 1,
  "warning_count": 2,
  "cases": [
    {
      "case_id": "kyc_old1",
      "user_sub": "user_late1",
      "status": "submitted",
      "submitted_at": 1716400000,
      "age_hours": 222.2,
      "severity": "critical",
      "assigned_admin": null
    },
    {
      "case_id": "kyc_old2",
      "user_sub": "user_late2",
      "status": "under_review",
      "submitted_at": 1716800000,
      "age_hours": 111.1,
      "severity": "warning",
      "assigned_admin": "admin_sub_1"
    }
  ],
  "generated_at": 1717200000
}
```

### 6.4 SAR Generation

```bash
curl -s -X POST -b "ui_session=sess_root123; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_root123" \
  -H "Content-Type: application/json" \
  -d '{
    "user_sub": "user_abc123",
    "reason": "Multiple high-value transactions immediately following KYC approval. Pattern consistent with money laundering typology.",
    "transaction_ids": ["tx_001", "tx_002", "tx_003"]
  }' \
  "http://localhost:8000/v1/kyc/reports/sar"
```

Response (200):
```json
{
  "sar_id": "SAR_7f3a2b1c9d0e",
  "generated_at": 1717200000,
  "generated_by": "root.admin@testdev.local",
  "subject_user_sub": "user_abc123",
  "reason": "Multiple high-value transactions immediately following KYC approval. Pattern consistent with money laundering typology.",
  "kyc_cases": [
    {
      "case_id": "kyc_a1b2c3d4",
      "status": "approved",
      "created_at": 1716900000,
      "decided_at": 1717000500
    }
  ],
  "flagged_transactions": [],
  "audit_trail": []
}
```

### 6.5 CSV Export

```bash
curl -s -X POST -b "ui_session=sess_root123; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_root123" \
  -H "Content-Type: application/json" \
  -d '{ "format": "csv", "start_date": 1716800000, "end_date": 1717100000 }' \
  "http://localhost:8000/v1/kyc/reports/deadlines/export"
```

Response (200):
```json
{
  "format": "csv",
  "content": "case_id,user_sub,status,submitted_at,age_hours,severity,assigned_admin\nkyc_old1,user_late1,submitted,1716400000,222.2,critical,\nkyc_old2,user_late2,under_review,1716800000,111.1,warning,admin_sub_1\n",
  "report_type": "deadlines"
}
```

### 6.6 Audit Trail

```bash
curl -s -b "ui_session=sess_root123; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_root123" \
  "http://localhost:8000/v1/kyc/reports/audit-trail/user_abc123"
```

Response (200):
```json
{
  "report_type": "audit_trail",
  "user_sub": "user_abc123",
  "total_events": 0,
  "events": [],
  "generated_at": 1717200000
}
```

### 6.7 Non-Root User (403)

```bash
curl -s -b "ui_session=sess_alice123; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_alice123" \
  "http://localhost:8000/v1/kyc/reports/volume"
```

Response (403):
```json
{
  "detail": "root_session_required"
}
```

### 6.8 Unknown Report Type Export (400)

```bash
curl -s -X POST -b "ui_session=sess_root123; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_root123" \
  -H "Content-Type: application/json" \
  -d '{ "format": "csv" }' \
  "http://localhost:8000/v1/kyc/reports/foobar/export"
```

Response (400):
```json
{
  "detail": "Unknown report type: foobar"
}
```

---

## 7. Error Handling Matrix

| Error Scenario | HTTP Status | Error Code / Detail | User-Facing Message | Recovery Action |
|----------------|-------------|---------------------|---------------------|-----------------|
| Non-root user accesses reports | 403 | `root_session_required` | "You do not have permission to access compliance reports." | Log in as root |
| Session expired / no session cookie | 401 | `session_expired` | "Your session has expired. Please log in again." | Re-authenticate |
| Missing CSRF token on POST | 403 | `csrf_token_mismatch` | "Security validation failed." | Refresh page, retry |
| Unknown report type in export | 400 | `Unknown report type: {type}` | "The requested report type is not available." | Use a valid report type |
| PDF export requested (not yet supported) | 400 | `Only CSV export is supported in dev mode` | "PDF export is not available. Use CSV." | Switch to CSV format |
| SAR reason too short (<10 chars) | 422 | `value_error` (Pydantic) | "Reason must be at least 10 characters." | Provide a longer reason |
| SAR user_sub empty | 422 | `value_error` (Pydantic) | "User identifier is required." | Provide a valid user_sub |
| Volume report date range start > end | 200 | — (returns zero counts) | N/A (empty report) | Fix date range |
| Deadline tracker warn_after_hours < 1 | 422 | `value_error` (Query validation) | "Warning threshold must be at least 1 hour." | Use a positive integer |
| Critical threshold < warn threshold | 200 | — (logically, all overdue are "critical") | N/A (valid but unhelpful) | Ensure critical > warn |
| DynamoDB GSI pagination exhausted | 200 | — (partial data) | "Note: report may be incomplete due to data volume." | Narrow date range |
| SAR generation for user with no history | 200 | — (`kyc_cases: []`) | N/A (SAR still generated, just empty) | Expected behavior |
| CSV export with no matching data | 200 | `content: ""` | "No data matches the selected criteria." | Adjust filters |
| Screening report scan timeout | 500 | `internal_server_error` | "Report generation timed out." | Narrow date range or retry |
| Retention report: purge_overdue flagged | 200 | — (`purge_overdue: true`) | Dashboard highlights overdue row in red | Run retention purge |
| Concurrent SAR generation (same user) | 200 | — (both succeed, different sar_ids) | N/A | Both SARs stored independently |

---

## 8. Pydantic Models

### 8.1 Request Models

```python
from pydantic import BaseModel, Field
from typing import Literal


class SarRequest(BaseModel):
    """Request body for Suspicious Activity Report generation."""
    user_sub: str = Field(
        min_length=1,
        max_length=256,
        description="The user identifier to generate the SAR for.",
        examples=["user_abc123"],
    )
    reason: str = Field(
        min_length=10,
        max_length=2000,
        description="Detailed reason for generating the SAR. Must be at least 10 characters.",
        examples=["Multiple high-value transactions immediately following KYC approval."],
    )
    transaction_ids: list[str] | None = Field(
        default=None,
        max_length=50,
        description="Optional list of transaction IDs to include in the SAR.",
        examples=[["tx_001", "tx_002"]],
    )


class ExportRequest(BaseModel):
    """Request body for exporting a report as CSV or PDF."""
    format: Literal["csv", "pdf"] = Field(
        default="csv",
        description="Export format. Only CSV is supported in dev mode.",
    )
    start_date: int | None = Field(
        default=None,
        ge=0,
        description="Unix timestamp for the report period start. Defaults to 30 days ago.",
        examples=[1716800000],
    )
    end_date: int | None = Field(
        default=None,
        ge=0,
        description="Unix timestamp for the report period end. Defaults to now.",
        examples=[1717100000],
    )
```

### 8.2 Response Models

```python
from pydantic import BaseModel, Field
from typing import Any


class VolumeReportOut(BaseModel):
    """Response for the KYC volume report."""
    report_type: Literal["volume"] = "volume"
    period_start: int = Field(description="Unix timestamp of period start")
    period_end: int = Field(description="Unix timestamp of period end")
    total_cases: int = Field(ge=0, description="Total cases in the period")
    counts_by_status: dict[str, int] = Field(
        description="Case counts keyed by status name",
        examples=[{"draft": 3, "submitted": 8, "approved": 22, "rejected": 6}],
    )
    approval_rate: float = Field(ge=0, le=100, description="Approval rate as percentage")
    rejection_rate: float = Field(ge=0, le=100, description="Rejection rate as percentage")
    generated_at: int = Field(description="Unix timestamp when report was generated")


class ScreeningReportOut(BaseModel):
    """Response for the sanctions/PEP screening hit rate report."""
    report_type: Literal["screening"] = "screening"
    period_start: int
    period_end: int
    total_screenings: int = Field(ge=0)
    total_hits: int = Field(ge=0)
    hit_rate_pct: float = Field(ge=0, le=100)
    resolutions: dict[str, int] = Field(
        description="Resolution outcome counts",
        examples=[{"false_positive": 3, "escalated": 1, "confirmed_match": 1}],
    )
    false_positive_count: int = Field(ge=0)
    escalated_count: int = Field(ge=0)
    confirmed_count: int = Field(ge=0)
    generated_at: int


class ProcessingTimeReportOut(BaseModel):
    """Response for the processing time distribution report."""
    report_type: Literal["processing_time"] = "processing_time"
    period_start: int
    period_end: int
    total_decided: int = Field(ge=0)
    avg_seconds: int = Field(ge=0)
    p50_seconds: int | None = Field(description="Median processing time in seconds")
    p90_seconds: int | None
    p95_seconds: int | None
    min_seconds: int | None
    max_seconds: int | None
    generated_at: int


class OverdueCaseOut(BaseModel):
    """A single overdue case in the deadline tracker."""
    case_id: str
    user_sub: str
    status: str
    submitted_at: int
    age_hours: float
    severity: Literal["warning", "critical"]
    assigned_admin: str | None


class DeadlineReportOut(BaseModel):
    """Response for the overdue case deadline tracker."""
    report_type: Literal["deadlines"] = "deadlines"
    warn_after_hours: int
    critical_after_hours: int
    total_overdue: int = Field(ge=0)
    critical_count: int = Field(ge=0)
    warning_count: int = Field(ge=0)
    cases: list[OverdueCaseOut]
    generated_at: int


class RetentionInventoryItemOut(BaseModel):
    """A single record in the retention inventory."""
    case_id: str
    user_sub: str
    status: str
    decided_at: int
    retention_days: int
    purge_due_at: int
    purge_overdue: bool
    file_count: int
    has_selfie: bool
    has_id_document: bool
    has_proof_of_address: bool
    purged: bool


class RetentionReportOut(BaseModel):
    """Response for the data retention compliance report."""
    report_type: Literal["retention"] = "retention"
    policies: dict[str, str] = Field(
        description="Retention policies keyed by status",
        examples=[{"rejected": "30 days", "expired": "7 days", "approved": "365 days"}],
    )
    total_records: int = Field(ge=0)
    overdue_purge_count: int = Field(ge=0)
    already_purged_count: int = Field(ge=0)
    inventory: list[RetentionInventoryItemOut]
    generated_at: int


class AuditEventOut(BaseModel):
    """A single audit event in the audit trail."""
    event_name: str
    actor_sub: str
    timestamp: int
    outcome: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class AuditTrailOut(BaseModel):
    """Response for a user's KYC audit trail export."""
    report_type: Literal["audit_trail"] = "audit_trail"
    user_sub: str
    total_events: int = Field(ge=0)
    events: list[AuditEventOut]
    generated_at: int


class SarCaseRefOut(BaseModel):
    """A KYC case reference within a SAR."""
    case_id: str
    status: str
    created_at: int
    decided_at: int | None


class SarOut(BaseModel):
    """Response for a generated Suspicious Activity Report."""
    sar_id: str = Field(pattern=r"^SAR_[a-f0-9]{12}$")
    generated_at: int
    generated_by: str
    subject_user_sub: str
    reason: str
    kyc_cases: list[SarCaseRefOut]
    flagged_transactions: list[dict[str, Any]]
    audit_trail: list[dict[str, Any]]


class ExportOut(BaseModel):
    """Response for a CSV/PDF export."""
    format: Literal["csv", "pdf"]
    content: str = Field(description="CSV content as string, or empty if no data")
    report_type: str
```

---

## 9. Frontend Component Tree

```
KycComplianceDashboard.tsx
├── Props: none (root-only page)
├── State: activeTab (useState), dateRange (useState<{start: number, end: number}>)
├── Queries:
│   ├── useQuery(["kyc-reports", activeTab, dateRange])
│   └── triggered on tab change or date range change
│
├── <PageHeader>
│   ├── <h1>"Compliance Reports"</h1>
│   └── <Badge variant="outline">"Root Access Required"</Badge>
│
├── <DateRangePicker>
│   ├── Props: { value: dateRange, onChange: setDateRange }
│   ├── <Popover>
│   │   └── <Calendar mode="range" />
│   └── Display: "May 1 — May 29, 2026"
│
├── <Tabs value={activeTab} onValueChange={setActiveTab}>
│   ├── <TabsList>
│   │   ├── <TabsTrigger value="volume">"Volume"</TabsTrigger>
│   │   ├── <TabsTrigger value="screening">"Screening"</TabsTrigger>
│   │   ├── <TabsTrigger value="processing-time">"Processing Time"</TabsTrigger>
│   │   ├── <TabsTrigger value="deadlines">"Deadlines"</TabsTrigger>
│   │   ├── <TabsTrigger value="retention">"Retention"</TabsTrigger>
│   │   └── <TabsTrigger value="sar">"SAR Generator"</TabsTrigger>
│   │
│   ├── <TabsContent value="volume">
│   │   └── <VolumeReportPanel>
│   │       ├── Props: { data: VolumeReportOut, isLoading: boolean }
│   │       ├── <Card> Summary stats (total, approval %, rejection %)
│   │       ├── <StatusBreakdownTable>
│   │       │   └── <DataTable columns={["Status","Count","% of Total"]} />
│   │       └── <ExportButton reportType="volume" dateRange={dateRange} />
│   │
│   ├── <TabsContent value="screening">
│   │   └── <ScreeningReportPanel>
│   │       ├── Props: { data: ScreeningReportOut, isLoading: boolean }
│   │       ├── <Card> Hit rate, false positive count, confirmed count
│   │       ├── <ResolutionPieChart>  (resolutions breakdown)
│   │       └── <ExportButton reportType="screening" dateRange={dateRange} />
│   │
│   ├── <TabsContent value="processing-time">
│   │   └── <ProcessingTimePanel>
│   │       ├── Props: { data: ProcessingTimeReportOut, isLoading: boolean }
│   │       ├── <Card> avg, p50, p90, p95 displayed as stat cards
│   │       ├── <PercentileBar p50={} p90={} p95={} />  (visual bar)
│   │       └── <ExportButton reportType="processing-time" dateRange={dateRange} />
│   │
│   ├── <TabsContent value="deadlines">
│   │   └── <DeadlineTrackerPanel>
│   │       ├── Props: { data: DeadlineReportOut, isLoading: boolean }
│   │       ├── <Card> total_overdue, critical_count, warning_count
│   │       ├── <DataTable columns={["Case ID","User","Status","Age","Severity","Admin"]} />
│   │       │   └── Row className: severity==="critical" ? "bg-red-50" : "bg-yellow-50"
│   │       └── <ExportButton reportType="deadlines" dateRange={dateRange} />
│   │
│   ├── <TabsContent value="retention">
│   │   └── <RetentionReportPanel>
│   │       ├── Props: { data: RetentionReportOut, isLoading: boolean }
│   │       ├── <Card> overdue_purge_count (red if > 0), already_purged_count
│   │       ├── <PolicySummary> (rejected: 30d, expired: 7d, approved: 365d)
│   │       ├── <DataTable columns={["Case","Status","Decided","Purge Due","Overdue","Files"]} />
│   │       │   └── Overdue rows highlighted in red
│   │       └── <ExportButton reportType="retention" dateRange={dateRange} />
│   │
│   └── <TabsContent value="sar">
│       └── <SarGenerationPanel>
│           ├── State: userSub, reason, transactionIds (useForm)
│           ├── Mutation: useMutation(["sar"], generateSar)
│           ├── <Form>
│           │   ├── <Input label="User Sub" />
│           │   ├── <Textarea label="Reason" minLength={10} />
│           │   ├── <Input label="Transaction IDs (comma-separated)" />
│           │   └── <Button type="submit">"Generate SAR"</Button>
│           └── <SarResultCard> (shown after successful generation)
│               ├── SAR ID, generated_at, kyc_cases count
│               └── <Button>"Download SAR as CSV"</Button>
│
└── <AuditTrailSection>
    ├── Props: none (separate from tabs, always visible at bottom)
    ├── State: auditUserSub (useState)
    ├── Query: useQuery(["kyc-reports","audit-trail", auditUserSub], enabled: !!auditUserSub)
    ├── <Input label="User Sub" onChange={setAuditUserSub} />
    ├── <Button>"Load Audit Trail"</Button>
    └── <DataTable columns={["Event","Actor","Timestamp","Outcome"]} />

ExportButton.tsx
├── Props: { reportType: string, dateRange: {start: number, end: number} }
├── Mutation: useMutation(exportReport)
├── onClick: mutate → response.content → new Blob(["text/csv"]) → URL.createObjectURL → <a download>
└── <Button variant="outline"><Download /> "Export CSV"</Button>
```

### React Query Keys

| Key | Endpoint | Stale Time |
|-----|----------|------------|
| `["kyc-reports", "volume", start, end]` | `GET /v1/kyc/reports/volume` | 60s |
| `["kyc-reports", "screening", start, end]` | `GET /v1/kyc/reports/screening` | 60s |
| `["kyc-reports", "processing-time", start, end]` | `GET /v1/kyc/reports/processing-time` | 60s |
| `["kyc-reports", "deadlines"]` | `GET /v1/kyc/reports/deadlines` | 30s |
| `["kyc-reports", "retention"]` | `GET /v1/kyc/reports/retention` | 60s |
| `["kyc-reports", "audit-trail", userSub]` | `GET /v1/kyc/reports/audit-trail/{sub}` | 0 (always fresh) |

---

## 10. Observability & Monitoring

### 10.1 Metrics

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `kyc_report_generated_total` | Counter | `report_type` | Total reports generated by type |
| `kyc_report_duration_seconds` | Histogram | `report_type` | Report generation latency |
| `kyc_export_total` | Counter | `report_type`, `format` | Total exports by type and format |
| `kyc_sar_generated_total` | Counter | — | Total SARs generated |
| `kyc_deadline_overdue_gauge` | Gauge | `severity` | Current count of overdue cases |
| `kyc_retention_overdue_gauge` | Gauge | — | Current count of records past purge date |
| `kyc_screening_hit_rate_gauge` | Gauge | — | Rolling screening hit rate percentage |
| `kyc_report_error_total` | Counter | `report_type`, `error_type` | Report generation errors |
| `kyc_csv_export_size_bytes` | Histogram | `report_type` | Size of exported CSV files |

### 10.2 Structured Log Events

| Event | Level | Fields | Trigger |
|-------|-------|--------|---------|
| `kyc.report.generated` | INFO | `report_type`, `period_start`, `period_end`, `total_items`, `duration_ms` | Report successfully generated |
| `kyc.report.export` | INFO | `report_type`, `format`, `csv_size_bytes`, `admin_sub` | Report exported |
| `kyc.sar.generated` | WARN | `sar_id`, `subject_user_sub`, `admin_sub`, `case_count`, `transaction_count` | SAR created |
| `kyc.report.error` | ERROR | `report_type`, `error_type`, `error_msg` | Report generation failed |
| `kyc.deadline.critical` | WARN | `case_id`, `user_sub`, `age_hours` | Case exceeds critical threshold |
| `kyc.retention.overdue` | WARN | `case_id`, `user_sub`, `purge_due_at`, `days_overdue` | Record past purge date |
| `kyc.report.slow_query` | WARN | `report_type`, `query_duration_ms`, `items_scanned` | Query took > 5s |
| `kyc.report.access` | INFO | `report_type`, `admin_sub`, `ip_address` | Root user accessed a report |

### 10.3 Alert Thresholds

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| Overdue purge records > 10 | `retention_overdue_gauge > 10` | P2 | Run retention purge immediately |
| Critical deadline cases > 5 | `deadline_overdue_critical > 5` | P2 | Assign admin reviewers |
| Report generation > 30s | `report_duration_seconds > 30` | P3 | Check DDB throughput; consider caching |
| SAR generated | Any SAR creation | P2 | Compliance officer notification |
| Screening hit rate > 20% | `screening_hit_rate_gauge > 20` | P3 | Review screening provider calibration |
| Report error rate > 5/hour | `rate(report_error_total[1h]) > 5` | P2 | Check DDB connectivity, table capacity |

### 10.4 Dashboard Queries

**Report usage over time**:
```sql
SELECT date_trunc('hour', timestamp) AS hour,
       report_type,
       COUNT(*) AS report_count,
       AVG(duration_ms) AS avg_duration_ms
FROM kyc_report_events
WHERE event = 'kyc.report.generated'
  AND timestamp > NOW() - INTERVAL '7 days'
GROUP BY hour, report_type
ORDER BY hour DESC;
```

**SAR generation history**:
```sql
SELECT sar_id, subject_user_sub, admin_sub, case_count,
       transaction_count, generated_at
FROM kyc_sar_events
WHERE event = 'kyc.sar.generated'
ORDER BY generated_at DESC
LIMIT 50;
```

---

## 11. Rollout Plan

### 11.1 Feature Flags

| Flag | Default | Purpose |
|------|---------|---------|
| `KYC_COMPLIANCE_REPORTS_ENABLED` | `false` | Master switch for all compliance report endpoints |
| `KYC_SAR_GENERATION_ENABLED` | `false` | Separate flag for SAR generation (higher risk) |
| `KYC_CSV_EXPORT_ENABLED` | `true` | CSV export capability |
| `KYC_PDF_EXPORT_ENABLED` | `false` | PDF export (not yet implemented) |

### 11.2 Rollout Phases

**Phase 1: Internal testing (Week 1)**
1. Enable `KYC_COMPLIANCE_REPORTS_ENABLED` in staging.
2. Root admins test all report types against seeded data.
3. Validate CSV export accuracy by cross-referencing with DDB direct queries.
4. Performance test: generate reports against 10K seeded cases.

**Phase 2: Read-only reports (Week 2)**
1. Enable `KYC_COMPLIANCE_REPORTS_ENABLED` in production.
2. SAR generation remains disabled.
3. Monitor report generation latency and DDB read unit consumption.
4. Collect feedback from compliance team on report format.

**Phase 3: SAR generation (Week 3)**
1. Enable `KYC_SAR_GENERATION_ENABLED` in production.
2. First SAR generated under supervision of compliance officer.
3. Verify SAR storage, audit trail, and export.

**Phase 4: Full availability (Week 4)**
1. PDF export implementation (if needed).
2. Scheduled report generation (cron-based monthly reports).
3. Remove feature flags; endpoints become always-available.

### 11.3 Rollback Procedure

1. Set `KYC_COMPLIANCE_REPORTS_ENABLED=false` -- all endpoints return 503.
2. If data corruption suspected: SAR records use independent PK (`SAR#...`) and can be deleted without affecting case records.
3. Remove router import from `app/main.py` if permanent rollback needed.
4. No DynamoDB schema changes to roll back (uses existing table + existing GSIs).

### 11.4 Migration Steps

No DynamoDB migration required. The compliance reporting system reads from existing tables and GSIs. SAR records are stored as new items in the existing `kyc_cases` table with a distinct PK prefix (`SAR#...`).

---

## 12. Performance Considerations

### 12.1 Query Cost Analysis

| Report | DDB Operation | Items Scanned | Estimated RCU | Latency (p50) |
|--------|---------------|---------------|---------------|----------------|
| Volume (7 status queries) | 7 x GSI query | Up to 3500 | ~875 | 200ms |
| Screening (table scan) | 1 x Scan | Up to 1000 | ~250 | 500ms |
| Processing Time (2 status queries) | 2 x GSI query | Up to 1000 | ~250 | 100ms |
| Deadlines (3 status queries) | 3 x GSI query | Up to 300 | ~75 | 80ms |
| Retention (3 status queries) | 3 x GSI query | Up to 600 | ~150 | 120ms |
| Audit trail (single query) | 1 x Query | Up to 100 | ~25 | 50ms |
| SAR generation | 1 x GSI query + 1 x PutItem | Up to 10 | ~5 + 1 WCU | 30ms |

### 12.2 Caching Strategy

Reports are generated on-demand and not cached server-side. The frontend uses React Query with a 60-second stale time, which prevents repeated backend queries when switching between tabs and returning.

For high-traffic compliance teams (multiple root users generating the same report simultaneously), consider adding a short-lived server-side cache:

```python
_report_cache: dict[str, tuple[int, dict]] = {}
CACHE_TTL = 60  # seconds

def _cached_report(cache_key: str, generator: Callable) -> dict:
    now = now_ts()
    if cache_key in _report_cache:
        cached_at, data = _report_cache[cache_key]
        if now - cached_at < CACHE_TTL:
            return data
    data = generator()
    _report_cache[cache_key] = (now, data)
    return data
```

### 12.3 Pagination Limits

- Volume report: 500 items per status query. For tenants with >500 cases in a single status within a date range, pagination via `LastEvaluatedKey` is needed. Current implementation does a single query per status.
- Screening report: 1000-item scan limit. Tenants with >1000 screening results in a 30-day window will get partial data. The scan must be paginated.
- Retention report: 200 items per status. Sufficient for most tenants.

### 12.4 Rate Limiting

Reports are expensive queries. Apply rate limiting per root user:

| Endpoint | Rate Limit | Window |
|----------|------------|--------|
| `GET /v1/kyc/reports/*` | 10 requests | per minute |
| `POST /v1/kyc/reports/sar` | 5 requests | per hour |
| `POST /v1/kyc/reports/*/export` | 10 requests | per minute |

### 12.5 Large Tenant Optimization

For tenants with >10K cases:
1. **Pre-aggregated metrics**: A background job could compute daily/weekly aggregates and store them as `pk=METRICS#{period}`, `sk=STATUS#{status}`. Reports would read aggregates instead of scanning.
2. **Streaming export**: For large CSV exports, stream directly to S3 and return a signed download URL instead of embedding CSV content in the JSON response.
3. **Batch SAR**: For bulk SAR generation across multiple users, a background queue (SQS or DDB stream) would prevent timeout issues.

---

## 13. Implementation Plan

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

## 14. E2E Test Plan (`frontend/e2e/kyc-reporting.spec.ts`)

**Test file**: `frontend/e2e/kyc-reporting.spec.ts`  
**Total tests**: ~15  
**Sections**: 194-196

### Section 194: Volume & Processing Time Reports (5 tests)

1. `GET /v1/kyc/reports/volume returns report with counts by status` -- Seed 3 cases (1 approved, 1 rejected, 1 draft); verify `counts_by_status.approved: 1`, `counts_by_status.rejected: 1`.
2. `Volume report calculates approval and rejection rates` -- Verify `approval_rate` and `rejection_rate` sum to 100 when only approved+rejected exist.
3. `Volume report respects date range filter` -- Seed cases; query with narrow date range excluding some; verify only matching cases counted.
4. `GET /v1/kyc/reports/processing-time returns percentiles` -- Seed 5 decided cases with known submission-to-decision times; verify `p50_seconds` and `p95_seconds` are reasonable.
5. `Non-root user gets 403 on volume report` -- Alice (USER role) queries; returns 403.

### Section 195: Deadline Tracker & Retention Report (5 tests)

1. `GET /v1/kyc/reports/deadlines returns overdue cases` -- Seed a case with `submitted_at` 72 hours ago; verify it appears in `cases` with `severity: "warning"`.
2. `Critical threshold flags old cases` -- Seed case submitted 200 hours ago; verify `severity: "critical"`.
3. `No overdue cases returns empty list` -- Fresh environment; verify `total_overdue: 0`.
4. `GET /v1/kyc/reports/retention shows purge schedule` -- Seed approved and rejected cases; verify `inventory` contains entries with `purge_due_at` and `retention_days`.
5. `Retention report identifies overdue purges` -- Seed rejected case older than `kyc_retention_rejected_days`; verify `purge_overdue: true`.

### Section 196: SAR Generation & Export (5 tests)

1. `POST /v1/kyc/reports/sar generates SAR with case history` -- Generate SAR for user with KYC cases; verify `sar_id` starts with `SAR_`, `kyc_cases` array is populated.
2. `SAR is stored in kyc_cases table` -- After SAR generation, directly query DDB for `pk=SAR#{sar_id}`; verify record exists.
3. `SAR with short reason returns 422` -- Body `{ reason: "bad" }` fails validation (min 10 chars).
4. `POST /v1/kyc/reports/volume/export returns CSV` -- Export volume report as CSV; verify `format: "csv"`, content contains header row and data rows.
5. `Export with unknown report type returns 400` -- POST to `/v1/kyc/reports/unknown/export`; verify 400.

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

## 15. Expanded E2E Test Details

### Section 194a: Volume Report Edge Cases (4 tests)

1. `Volume report with no cases in period returns all zeros` -- Query with date range in the far future (2030); verify `total_cases: 0`, all status counts are 0, `approval_rate: 0`, `rejection_rate: 0`.
2. `Volume report default date range is last 30 days` -- Omit `start_date` and `end_date`; verify `period_start` is approximately 30 days before `period_end`.
3. `Volume report with only drafts shows 0% approval` -- Seed 3 draft-only cases; verify `approval_rate: 0.0`, `rejection_rate: 0.0` (zero decided).
4. `Processing time report with single decided case` -- Seed 1 approved case with known timing; verify `p50_seconds` equals the single duration, `p90_seconds` equals the same value.

### Section 195a: Deadline & Retention Edge Cases (4 tests)

1. `Deadline tracker with custom warn_after_hours=1` -- Set `warn_after_hours=1`; verify recently submitted case (2 hours ago) appears as "warning".
2. `Deadline tracker sorts by age descending` -- Seed 3 overdue cases with different ages; verify `cases[0].age_hours > cases[1].age_hours > cases[2].age_hours`.
3. `Retention report shows purged records` -- Seed a case with `purged_at` set; verify `purged: true` in inventory and it counts toward `already_purged_count`.
4. `Retention report policies match settings` -- Verify `policies.rejected` contains the configured `kyc_retention_rejected_days` value.

### Section 196a: SAR & Export Edge Cases (4 tests)

1. `SAR reason at exactly 10 characters is accepted` -- Reason of exactly 10 chars succeeds.
2. `SAR reason at 2001 characters is rejected (422)` -- Exceeds max_length; verify 422.
3. `CSV export for retention report includes all inventory columns` -- Export retention as CSV; parse CSV header; verify columns include `case_id`, `purge_due_at`, `purge_overdue`, `file_count`.
4. `Two SARs for same user get different sar_ids` -- Generate two SARs for the same user; verify `sar_id` values are distinct.

### Section 196b: Concurrent Access & Authorization (4 tests)

1. `Alice (USER role) cannot generate SAR` -- POST to `/v1/kyc/reports/sar`; verify 403.
2. `Alice cannot export reports` -- POST to `/v1/kyc/reports/volume/export`; verify 403.
3. `Root can access screening report` -- GET `/v1/kyc/reports/screening`; verify 200 with valid response shape.
4. `Expired root session returns 401` -- Clear cookies; attempt GET report; verify 401 or redirect.

---

## 16. Security Considerations

- All reporting endpoints require `require_root_session` -- only root users can access compliance data.
- SAR records are stored in the `kyc_cases` table and are subject to the same access controls.
- CSV exports do not include raw document images or file contents -- only metadata (case ID, status, timestamps).
- Audit trail exports include event names and actor IDs but not the actual document data.
- PDF export (future) will include a watermark and generation metadata for provenance tracking.
- SAR generation creates an audit event (`kyc.sar.generated`) to ensure accountability.
- Rate limiting prevents report endpoint abuse that could degrade DDB performance.

---

## 17. Rollback Plan

- Set `KYC_COMPLIANCE_REPORTS_ENABLED=false` to disable all endpoints (return 503).
- Remove `app/routers/kyc_reporting.py` import from `app/main.py` for permanent rollback.
- Delete `app/services/kyc_reporting.py` and `app/routers/kyc_reporting.py`.
- SAR records stored with `pk=SAR#*` are independent and can remain inert in the table.
- No DynamoDB schema changes need to be reverted.

---

## Codebase References

> **Verification performed**: 2026-05-29

### Verified (EXISTS in codebase)

| Reference | File | Line(s) | Status |
|-----------|------|---------|--------|
| `get_admin_kyc_metrics()` | `app/routers/kyc_cases.py` | 947 | VERIFIED (ticket cites line 946 -- off by 1) |
| KYC cases service | `app/services/kyc_cases.py` | all | VERIFIED (828 lines) |
| `list_cases_by_owner()` | `app/services/kyc_cases.py` | 607 | VERIFIED |
| `list_admin_queue()` | `app/services/kyc_cases.py` | 646 | VERIFIED |
| `_status_pk()` helper | `app/services/kyc_cases.py` | 48 | VERIFIED |
| `_updated_sk()` helper | `app/services/kyc_cases.py` | 40 | VERIFIED |
| `run_retention_purge()` | `app/services/kyc_cases.py` | 747 | VERIFIED |
| `kyc_retention_rejected_days` setting | `app/core/settings.py` | 1068 | VERIFIED: default 30 |
| `kyc_retention_expired_days` setting | `app/core/settings.py` | 1069 | VERIFIED: default 7 |
| `kyc_retention_approved_days` setting | `app/core/settings.py` | 1070 | VERIFIED: default 365 |
| `kyc_cases_status_index_name` setting | `app/core/settings.py` | 1067 | VERIFIED |
| `kyc_cases` DDB table (status-updated-index GSI) | `scripts/local-ddb-init.py` | 91-96 | VERIFIED |
| `audit_event()` | `app/services/alerts.py` | 695 | VERIFIED |
| CSV export router | `app/routers/csv_export.py` | exists | VERIFIED |
| Audit export router | `app/routers/audit_export.py` | exists | VERIFIED |
| `require_root_session` | `app/auth/deps.py` | 273 | VERIFIED |
| `app/contracts/kyc_cases_contract.py` | `app/contracts/` | exists | VERIFIED |

### Corrections

<!-- NOTE: The ticket cites `get_admin_kyc_metrics()` at "line 946" -- actual line is 947. -->
<!-- NOTE: The ticket references `STORE.get_metrics_snapshot()` at "line 701" -- this should be verified; the STORE pattern uses class methods on the KYC case store. -->

### Not Yet Implemented (requires new code)

| Reference | Expected Location | Status |
|-----------|-------------------|--------|
| `app/services/kyc_reporting.py` | `app/services/` | NOT FOUND -- new service required (~400 lines) |
| `app/routers/kyc_reporting.py` | `app/routers/` | NOT FOUND -- new router required (~200 lines) |
| `kyc_reporting_router` registration | `app/main.py` | NOT FOUND -- needs `app.include_router()` |
| `SarRequest`, `ExportRequest` models | `app/contracts/kyc_cases_contract.py` | NOT FOUND -- new models required |
| `KYC_COMPLIANCE_REPORTS_ENABLED` feature flag | `app/core/settings.py` | NOT FOUND -- new setting required |
| `KYC_SAR_GENERATION_ENABLED` feature flag | `app/core/settings.py` | NOT FOUND -- new setting required |
| SAR storage items (pk=SAR#*) | `kyc_cases` table | NOT FOUND -- new item pattern (no schema change needed) |
| `frontend/src/pages/admin/KycComplianceDashboard.tsx` | `frontend/src/pages/admin/` | NOT FOUND -- new page required |
| `frontend/src/api/endpoints/kyc-reporting.ts` | `frontend/src/api/endpoints/` | NOT FOUND -- new endpoint file required |
| `/admin/kyc/compliance` route | `frontend/src/App.tsx` | NOT FOUND -- new route required |

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_kyc_compliance.py`

Mock external dependencies with `moto` (DynamoDB) and `unittest.mock`. All tests run without the dev stack.

  - `test_generate_compliance_report_csv`
  - `test_generate_compliance_report_pdf`
  - `test_report_includes_screening_results`
  - `test_report_includes_risk_scores`
  - `test_filter_by_date_range`
  - `test_filter_by_verification_status`
  - `test_report_sha256_checksum`

### Integration Tests

  - Compliance report aggregates KYC submissions with screening and risk data
  - CSV export includes all required regulatory fields
  - Report generation stored with metadata in audit table

### E2E Tests (Playwright)

**File**: `frontend/e2e/kyc-compliance.spec.ts`
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

- **DDB seeds**: Seed `kyc_submissions, kyc_screening_results` table with test records in `beforeAll`
- **Test users**: Alice (USER), Bob (USER), Root (ROOT), Charlie (ADMIN) from `e2e_admin_session_setup.py`
- **Cleanup**: Tests use unique timestamps/IDs per run to avoid cross-run interference

### CI/Pipeline Considerations

- **Feature flag**: `KYC_COMPLIANCE_REPORTS_ENABLED=true` must be set in test environment
- **Serial execution**: E2E tests run with `workers: 1` to avoid shared-state conflicts
- **Retry safety**: All tests are idempotent; retries do not produce duplicate records

## Dependencies & Merge Safety

### Depends On

| Ticket | Title | Why |
|--------|-------|-----|
| KYC-001 | Admin KYC Review Dashboard | Reports accessed from dashboard |
| KYC-006 | Sanctions & PEP Screening | Screening results included in reports |
| KYC-008 | Risk Scoring Engine | Risk scores included in reports |

### Depended On By

| Ticket | Title | Impact |
|--------|-------|--------|
| (none) | — | No other tickets depend on this one |

### Merge Strategy

**Sequential**

Merge after KYC-001, KYC-006, KYC-008. This ticket depends on tables/services introduced by those tickets.

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
- [ ] All 10 E2E tests pass with `npx playwright test kyc-compliance.spec.ts`
