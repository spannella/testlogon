# FIN-016: Financial Audit Log Export

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-29  
**Priority**: Medium  
**Estimated effort**: 7-9 days  
**Dependencies**: Billing ledger (`app/services/billing_shared.py:217`), admin auth (`app/auth/policy.py:63` `require_root`), financial rollups (FIN-013)

<!-- NOTE: A substantial audit export system ALREADY EXISTS in the codebase:
- `app/services/audit_export.py` (46 lines) — export record model with CSV/NDJSON formatting
- `app/services/audit_export_pipeline.py` (249 lines) — export pipeline (job creation, execution)
- `app/routers/audit_export.py` (192 lines) — REST API at `/ui/admin/audit-exports` with POST (create), GET (list), GET /{id}, GET /{id}/download
- Registered in `app/main.py:157,448` as `audit_export_router`
- DDB table `AuditExports` already exists in `scripts/local-ddb-init.py:1044-1053` (PK=export_id, SK=sk, GSIs: status-created-index, user-created-index)
- Settings exist in `app/core/settings.py:1451-1467`: `audit_export_enabled`, `audit_export_table_name`, `audit_export_max_date_range_days`, `audit_export_s3_bucket`, etc.
- This ticket should extend the existing system rather than creating it from scratch. -->

---

## 1. Overview & Motivation

### The Gap

The billing ledger stores every financial transaction as a DynamoDB row, but there is no way to export this data. Admins who need financial records for accounting, tax filings, or audits must query DynamoDB directly. There are no:

- CSV or PDF export endpoints for ledger data
- Filters for date range, user, transaction type, or amount range
- Scheduled reports (auto-export daily/weekly/monthly)
- Audit-grade formatting (sequential numbering, checksums, tamper evidence)
- Bulk export compatible with accounting software (QuickBooks, Xero)

Without export capabilities, every financial reporting task requires engineering involvement — an unsustainable bottleneck for a growing platform.

### Why This Is Needed

1. **Tax compliance**: Tax authorities require transaction records in standard formats. Manual DynamoDB queries are not audit-ready — they lack sequential numbering, totals, and checksums.

2. **Accounting integration**: Finance teams use QuickBooks, Xero, or similar software. They need CSV exports that match expected column formats for automated import.

3. **Audit preparation**: External auditors need tamper-evident financial records with clear provenance (who exported, when, what filters were applied).

4. **Scheduled reporting**: Monthly financial closes require consistent, automated report generation — not ad-hoc manual work.

5. **Dispute resolution**: When a user disputes a charge, admins need to quickly pull the user's complete transaction history filtered by date range and type.

### User Stories

- As a **platform admin**, I want to export billing ledger entries as CSV filtered by date range and type so I can prepare tax filings.
- As a **platform admin**, I want to export a formatted PDF summary for board reporting.
- As a **platform admin**, I want scheduled reports emailed weekly so I do not have to remember to export manually.
- As a **platform admin**, I want exports to include checksums and sequential numbering so auditors can verify completeness.
- As a **platform admin**, I want to export a specific user's transaction history for dispute resolution.

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                         FINANCIAL AUDIT LOG EXPORT SYSTEM                            │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│  ┌──────────────┐    ┌────────────────────────┐    ┌──────────────────────────┐     │
│  │  Frontend     │    │  FastAPI Router         │    │  Audit Export Service    │     │
│  │  AuditExport  │───>│  admin_audit_export.py  │───>│  audit_export.py        │     │
│  │  Page.tsx     │    │  9 endpoints            │    │                         │     │
│  │              │<───│                        │<───│                         │     │
│  └──────────────┘    └──────────┬─────────────┘    └──────────┬──────────────┘     │
│                                 │                              │                    │
│                    ┌────────────┼─────────────┐                │                    │
│                    v            v             v                v                    │
│          ┌──────────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐           │
│          │ audit_exports │ │ billing  │ │    S3    │ │  Background Task │           │
│          │  DDB Table    │ │  DDB     │ │  Bucket  │ │  (Scheduled      │           │
│          │  (metadata)   │ │ (ledger) │ │ (files)  │ │   Reports)       │           │
│          └──────────────┘ └──────────┘ └──────────┘ └──────────────────┘           │
│                                                                                     │
└─────────────────────────────────────────────────────────────────────────────────────┘

Data Flow: On-Demand CSV Export
═══════════════════════════════

  Admin clicks "Export CSV"
       │
       v
  ┌──────────────────────────────────────────────────────────────────────┐
  │  POST /v1/admin/audit/export/csv                                     │
  │    1. Validate filters (date range, user, type, amount bounds)       │
  │    2. Query billing table via GSI_LEDGER_DATE for date range         │
  │       ├── Paginate with LastEvaluatedKey until all rows fetched      │
  │       ├── Apply FilterExpression for user_id, entry_type, amount     │
  │       └── Collect all matching rows in memory                        │
  │    3. Generate CSV content                                           │
  │       ├── Map columns to requested format (default/quickbooks/xero)  │
  │       ├── Add sequential row numbers                                 │
  │       ├── Compute running subtotals per entry_type                   │
  │       ├── Add TOTAL row, ROWS count, SHA-256 hash                    │
  │       └── Add metadata footer (exported by, filters, timestamp)      │
  │    4. Upload CSV bytes to S3 (key: exports/{export_id}.csv)          │
  │    5. Compute SHA-256 of CSV content                                 │
  │    6. Write export record to audit_exports DDB table                 │
  │    7. Return {export_id, row_count, sha256_hash, status: completed}  │
  └──────────────────────────────────────────────────────────────────────┘

Data Flow: Scheduled Report Execution
══════════════════════════════════════

  Background Task (every 15 minutes)
       │
       v
  ┌──────────────────────────────────────────────────────────────────────┐
  │  run_scheduled_exports()                                             │
  │    1. Query audit_exports GSI1 for SCHEDULES#ACTIVE                  │
  │       where next_run_at <= now                                       │
  │    2. For each due schedule:                                         │
  │       ├── Compute date range from frequency                          │
  │       │     daily:   yesterday 00:00 → 23:59                         │
  │       │     weekly:  previous Monday → Sunday                        │
  │       │     monthly: previous month 1st → last day                   │
  │       ├── Call export_ledger_csv() or export_ledger_pdf()            │
  │       ├── Email download link to recipients (via SES or mock)        │
  │       └── Update last_run_at and next_run_at on schedule item        │
  └──────────────────────────────────────────────────────────────────────┘
```

### Architecture After This Change

```
Admin Export System (/admin/audit-export)
│
├── On-Demand Export
│   ├── Filters: date range, user_id, entry_type, amount_min/max, status
│   ├── Formats: CSV, PDF
│   ├── Accounting-compatible CSV (QuickBooks, Xero column mapping)
│   └── Audit-grade PDF (sequential numbering, page totals, checksum)
│
├── Scheduled Reports
│   ├── Daily / Weekly / Monthly frequency
│   ├── Auto-email to configured admin addresses
│   ├── Template selection (full export, summary, by-type)
│   └── Schedule management (create, edit, delete, pause)
│
├── Export History
│   ├── Log of all exports (who, when, filters, format, row count)
│   ├── Re-download previous exports (cached for 30 days)
│   └── Tamper-evident: SHA-256 hash of export content stored at creation
│
└── Bulk Export
    ├── Large date range export (async, background job)
    ├── Progress tracking (X of Y rows processed)
    ├── Download when ready notification
    └── S3 storage for large files
```

---

## 2. Current State Analysis

### 2.1 Billing Ledger (`app/services/billing_shared.py`)

Ledger entries stored in `billing` table (see `scripts/local-ddb-init.py:59`, `app/core/settings.py:321`):
- `pk`: `USER#{user_id}`, `sk`: `LEDGER#{timestamp}#{entry_id}`
- Fields: `type`, `amount_cents`, `state`, `reason`, `ts` <!-- NOTE: field is `type` not `entry_type`; `currency`, `description`, `created_at`, and `provider` are NOT standard fields in `new_ledger_entry` — see `app/services/billing_shared.py:236`. -->
- Key functions: `new_ledger_entry(...)` at `:217`, `settle_or_reverse_ledger(...)` at `:248` (see `app/services/billing_shared.py`)

### 2.2 Existing Audit Export System (ALREADY EXISTS)

An audit export system already exists:
- **Service**: `app/services/audit_export.py` (46 lines) + `app/services/audit_export_pipeline.py` (249 lines)
- **Router**: `app/routers/audit_export.py` (192 lines) — prefix `/ui/admin/audit-exports`, registered at `app/main.py:157,448`
  - `POST /ui/admin/audit-exports` — create export (categories, format csv/ndjson, date range)
  - `GET /ui/admin/audit-exports` — list exports
  - `GET /ui/admin/audit-exports/{export_id}` — get export details
  - `GET /ui/admin/audit-exports/{export_id}/download` — download export file
- **DDB Table**: `AuditExports` at `scripts/local-ddb-init.py:1044-1053` (PK=export_id, SK=sk, GSIs: status-created-index, user-created-index)
- **Settings**: `app/core/settings.py:1451-1467` — `audit_export_enabled`, `audit_export_table_name`, `audit_export_max_date_range_days` (90), `audit_export_s3_bucket`, `audit_export_url_ttl_seconds`, `audit_export_worker_enabled`, etc.

### 2.3 Existing Admin Payout Router (`app/routers/admin_payouts.py`)

The admin payouts router (**verified** to exist) provides payout listing and approval but no export functionality.

### 2.4 FIN-013 Financial Rollups

FIN-013 introduces daily rollup data and a `GSI_LEDGER_DATE` on the billing table, enabling date-range queries across all users. <!-- NOTE: This GSI does NOT yet exist — the billing table at `scripts/local-ddb-init.py:59` currently has NO GSIs. -->

### 2.4 Gaps

1. No CSV export of ledger entries
2. No PDF export with audit formatting
3. No filter-based export (date range, user, type, amount)
4. No scheduled report system
5. No export history or tamper-evident checksums
6. No accounting software column mapping
7. No bulk/async export for large date ranges

---

## 3. Technical Design

### 3.1 Export Storage Table: `audit_exports`

**Table definition** in `scripts/local-ddb-init.py`:

```python
TableDef(
    name="audit_exports",
    pk="pk", sk="sk",
    gsis=[
        GsiDef("GSI1", "GSI1PK", "GSI1SK"),
    ],
    attr_types={"GSI1SK": "N"},
)
```

**Export record rows**:

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `EXPORT#{export_id}` |
| `sk` | S | `META` |
| `GSI1PK` | S | `EXPORTS#ALL` |
| `GSI1SK` | N | `created_at` |
| `export_id` | S | Unique export ID |
| `admin_sub` | S | Admin who triggered the export |
| `format` | S | `"csv"` or `"pdf"` |
| `filters` | M | Applied filters (date range, user, type, amount) |
| `row_count` | N | Number of rows exported |
| `file_size_bytes` | N | Size of export file |
| `sha256_hash` | S | SHA-256 hash of file content |
| `s3_key` | S | S3 key for stored export file |
| `status` | S | `"pending"`, `"completed"`, `"failed"` |
| `created_at` | N | When export was triggered |
| `expires_at` | N | When export file expires (30 days) |

**Scheduled report rows**:

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `SCHEDULE#{schedule_id}` |
| `sk` | S | `META` |
| `GSI1PK` | S | `SCHEDULES#ACTIVE` |
| `GSI1SK` | N | `next_run_at` |
| `schedule_id` | S | Unique schedule ID |
| `frequency` | S | `"daily"`, `"weekly"`, `"monthly"` |
| `format` | S | `"csv"` or `"pdf"` |
| `template` | S | `"full"`, `"summary"`, `"by_type"` |
| `filters` | M | Default filters for scheduled run |
| `recipients` | L | Email addresses to send report to |
| `active` | BOOL | Whether schedule is active |
| `last_run_at` | N | When last executed |
| `next_run_at` | N | When next scheduled |
| `created_by` | S | Admin who created |

### 3.2 DynamoDB Access Patterns

| Access Pattern | Table/GSI | PK | SK / Filter | Example |
|---|---|---|---|---|
| Get export record | Main table | `EXPORT#{export_id}` | `sk = "META"` | Fetch metadata for export download |
| List all exports (newest first) | GSI1 | `EXPORTS#ALL` | `GSI1SK desc` | Export history page |
| List exports in date range | GSI1 | `EXPORTS#ALL` | `GSI1SK BETWEEN :start AND :end` | Exports from last week |
| Get scheduled report | Main table | `SCHEDULE#{schedule_id}` | `sk = "META"` | Fetch schedule details |
| List active schedules (due) | GSI1 | `SCHEDULES#ACTIVE` | `GSI1SK <= :now` | Background task: find due schedules |
| List all active schedules | GSI1 | `SCHEDULES#ACTIVE` | No SK filter | Admin schedule management page |
| Query billing ledger (date range) | billing / GSI_LEDGER_DATE | `DATE#{YYYY-MM-DD}` | `sort_key range` | Fetch ledger rows for export |

**Example DynamoDB Items (JSON)**:

Export record:
```json
{
  "pk": {"S": "EXPORT#exp_a1b2c3d4"},
  "sk": {"S": "META"},
  "GSI1PK": {"S": "EXPORTS#ALL"},
  "GSI1SK": {"N": "1748520600"},
  "export_id": {"S": "exp_a1b2c3d4"},
  "admin_sub": {"S": "root.admin@testdev.local"},
  "format": {"S": "csv"},
  "filters": {"M": {
    "start_date": {"S": "2026-05-01"},
    "end_date": {"S": "2026-05-29"},
    "entry_type": {"S": "tip_debit"},
    "column_format": {"S": "quickbooks"}
  }},
  "row_count": {"N": "150"},
  "file_size_bytes": {"N": "24576"},
  "sha256_hash": {"S": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"},
  "s3_key": {"S": "exports/exp_a1b2c3d4.csv"},
  "status": {"S": "completed"},
  "created_at": {"N": "1748520600"},
  "expires_at": {"N": "1751112600"}
}
```

Scheduled report:
```json
{
  "pk": {"S": "SCHEDULE#sched_x1y2z3"},
  "sk": {"S": "META"},
  "GSI1PK": {"S": "SCHEDULES#ACTIVE"},
  "GSI1SK": {"N": "1748606400"},
  "schedule_id": {"S": "sched_x1y2z3"},
  "frequency": {"S": "weekly"},
  "format": {"S": "csv"},
  "template": {"S": "full"},
  "filters": {"M": {
    "entry_type": {"NULL": true}
  }},
  "recipients": {"L": [{"S": "admin@test.local"}, {"S": "finance@test.local"}]},
  "active": {"BOOL": true},
  "last_run_at": {"N": "1747915200"},
  "next_run_at": {"N": "1748606400"},
  "created_by": {"S": "root.admin@testdev.local"}
}
```

### 3.3 Audit Export Service: `app/services/audit_export.py`

```python
"""Financial audit log export service (FIN-016).

Generates CSV and PDF exports of billing ledger data with
audit-grade formatting, checksums, and scheduled delivery.
"""

from __future__ import annotations
import csv
import hashlib
import io
import logging
import uuid
from datetime import datetime, timezone, timedelta
from decimal import Decimal
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key, Attr
from app.core.tables import T
from app.core.time import now_ts
from app.core.cursor import encode_cursor, decode_cursor
from app.services.alerts import write_alert

logger = logging.getLogger("audit_export")

EXPORT_TTL_DAYS = 30
MAX_SYNC_ROWS = 50_000  # Above this, use async export

QUICKBOOKS_COLUMNS = [
    "Date", "Transaction Type", "Num", "Name",
    "Amount", "Currency", "Description", "Status",
]

XERO_COLUMNS = [
    "Date", "Amount", "Reference", "Description",
    "Account Code", "Tax Rate",
]

DEFAULT_COLUMNS = [
    "Row#", "Date", "Time", "Entry ID", "User ID",
    "Entry Type", "Amount (cents)", "Currency",
    "Provider", "Description", "Reason", "Status",
]


def export_ledger_csv(
    *, start_date: str, end_date: str,
    user_id: str = None, entry_type: str = None,
    amount_min: int = None, amount_max: int = None,
    column_format: str = "default",
    admin_sub: str,
) -> Dict[str, Any]:
    """Generate CSV export of ledger entries.

    Steps:
    1. Query billing table via GSI_LEDGER_DATE for each day in range
    2. Apply optional filters (user_id, entry_type, amount range)
    3. Format rows according to column_format
    4. Add sequential numbering, totals, and SHA-256 checksum
    5. Upload to S3 and record in audit_exports table

    Returns {export_id, row_count, sha256_hash, download_url, status}.
    """
    export_id = f"exp_{uuid.uuid4().hex[:8]}"
    now = now_ts()

    # Fetch ledger entries
    rows = _query_ledger_range(
        start_date=start_date, end_date=end_date,
        user_id=user_id, entry_type=entry_type,
        amount_min=amount_min, amount_max=amount_max,
    )

    # Generate CSV
    columns = _get_columns(column_format)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(columns)

    total_cents = 0
    for i, row in enumerate(rows, 1):
        csv_row = _format_row(row, i, column_format)
        writer.writerow(csv_row)
        total_cents += int(row.get("amount_cents", 0))

    # Footer
    writer.writerow([])
    writer.writerow(["TOTAL", "", "", "", "", "", str(total_cents), "usd", "", "", "", ""])
    writer.writerow([f"ROWS: {len(rows)}"])

    csv_bytes = buf.getvalue().encode("utf-8")
    sha256 = hashlib.sha256(csv_bytes).hexdigest()

    # Append hash to CSV
    buf.write(f"SHA-256: {sha256}\n")
    buf.write(f"EXPORTED BY: {admin_sub}\n")
    buf.write(f"EXPORTED AT: {datetime.now(timezone.utc).isoformat()}\n")
    buf.write(f"FILTERS: start={start_date}, end={end_date}")
    if user_id:
        buf.write(f", user={user_id}")
    if entry_type:
        buf.write(f", type={entry_type}")
    buf.write("\n")

    csv_bytes = buf.getvalue().encode("utf-8")
    s3_key = f"exports/{export_id}.csv"

    # Upload to S3
    _upload_to_s3(s3_key, csv_bytes, content_type="text/csv")

    # Record export
    expires_at = now + (EXPORT_TTL_DAYS * 86400)
    T.audit_exports.put_item(Item={
        "pk": f"EXPORT#{export_id}",
        "sk": "META",
        "GSI1PK": "EXPORTS#ALL",
        "GSI1SK": Decimal(str(now)),
        "export_id": export_id,
        "admin_sub": admin_sub,
        "format": "csv",
        "filters": {
            "start_date": start_date,
            "end_date": end_date,
            "user_id": user_id or "",
            "entry_type": entry_type or "",
            "amount_min": Decimal(str(amount_min)) if amount_min else None,
            "amount_max": Decimal(str(amount_max)) if amount_max else None,
            "column_format": column_format,
        },
        "row_count": Decimal(str(len(rows))),
        "file_size_bytes": Decimal(str(len(csv_bytes))),
        "sha256_hash": sha256,
        "s3_key": s3_key,
        "status": "completed",
        "created_at": Decimal(str(now)),
        "expires_at": Decimal(str(expires_at)),
    })

    logger.info("csv_export_completed", extra={
        "export_id": export_id, "row_count": len(rows),
        "file_size": len(csv_bytes), "admin": admin_sub,
    })

    return {
        "export_id": export_id,
        "format": "csv",
        "row_count": len(rows),
        "file_size_bytes": len(csv_bytes),
        "sha256_hash": sha256,
        "status": "completed",
        "created_at": now,
        "expires_at": expires_at,
    }


def export_ledger_pdf(
    *, start_date: str, end_date: str,
    user_id: str = None, entry_type: str = None,
    amount_min: int = None, amount_max: int = None,
    admin_sub: str,
) -> Dict[str, Any]:
    """Generate audit-grade PDF export.

    Includes:
    - Cover page with export metadata, filters, and SHA-256 checksum
    - Sequential row numbering
    - Page subtotals at bottom of each page
    - Grand total on final page
    - Filter summary in header of every page
    """
    export_id = f"exp_{uuid.uuid4().hex[:8]}"
    now = now_ts()

    rows = _query_ledger_range(
        start_date=start_date, end_date=end_date,
        user_id=user_id, entry_type=entry_type,
        amount_min=amount_min, amount_max=amount_max,
    )

    pdf_bytes = _render_pdf(rows, admin_sub=admin_sub, filters={
        "start_date": start_date, "end_date": end_date,
        "user_id": user_id, "entry_type": entry_type,
    })

    sha256 = hashlib.sha256(pdf_bytes).hexdigest()
    s3_key = f"exports/{export_id}.pdf"
    _upload_to_s3(s3_key, pdf_bytes, content_type="application/pdf")

    expires_at = now + (EXPORT_TTL_DAYS * 86400)
    T.audit_exports.put_item(Item={
        "pk": f"EXPORT#{export_id}",
        "sk": "META",
        "GSI1PK": "EXPORTS#ALL",
        "GSI1SK": Decimal(str(now)),
        "export_id": export_id,
        "admin_sub": admin_sub,
        "format": "pdf",
        "filters": {
            "start_date": start_date,
            "end_date": end_date,
            "user_id": user_id or "",
            "entry_type": entry_type or "",
        },
        "row_count": Decimal(str(len(rows))),
        "file_size_bytes": Decimal(str(len(pdf_bytes))),
        "sha256_hash": sha256,
        "s3_key": s3_key,
        "status": "completed",
        "created_at": Decimal(str(now)),
        "expires_at": Decimal(str(expires_at)),
    })

    return {
        "export_id": export_id,
        "format": "pdf",
        "row_count": len(rows),
        "file_size_bytes": len(pdf_bytes),
        "sha256_hash": sha256,
        "status": "completed",
        "created_at": now,
        "expires_at": expires_at,
    }


def get_export(export_id: str) -> Optional[Dict[str, Any]]:
    """Get export record by ID."""
    resp = T.audit_exports.get_item(Key={"pk": f"EXPORT#{export_id}", "sk": "META"})
    item = resp.get("Item")
    if not item:
        return None
    return _export_to_dict(item)


def list_exports(*, limit: int = 50, cursor: str = None) -> Dict[str, Any]:
    """List export history, newest first."""
    kwargs = {
        "IndexName": "GSI1",
        "KeyConditionExpression": Key("GSI1PK").eq("EXPORTS#ALL"),
        "ScanIndexForward": False,
        "Limit": limit,
    }
    if cursor:
        kwargs["ExclusiveStartKey"] = decode_cursor(cursor)

    resp = T.audit_exports.query(**kwargs)
    items = resp.get("Items", [])
    next_cursor = None
    if "LastEvaluatedKey" in resp:
        next_cursor = encode_cursor(resp["LastEvaluatedKey"])

    return {
        "exports": [_export_to_dict(it) for it in items],
        "count": len(items),
        "cursor": next_cursor,
    }


def download_export(export_id: str) -> Optional[bytes]:
    """Download export file content from S3."""
    record = get_export(export_id)
    if not record:
        return None
    if record["status"] != "completed":
        return None
    return _download_from_s3(record["s3_key"])


def create_schedule(
    *, frequency: str, format: str, template: str,
    filters: Dict[str, Any], recipients: List[str],
    admin_sub: str,
) -> Dict[str, Any]:
    """Create a scheduled report."""
    schedule_id = f"sched_{uuid.uuid4().hex[:8]}"
    now = now_ts()
    next_run = _compute_next_run(frequency, now)

    T.audit_exports.put_item(Item={
        "pk": f"SCHEDULE#{schedule_id}",
        "sk": "META",
        "GSI1PK": "SCHEDULES#ACTIVE",
        "GSI1SK": Decimal(str(next_run)),
        "schedule_id": schedule_id,
        "frequency": frequency,
        "format": format,
        "template": template,
        "filters": filters,
        "recipients": recipients,
        "active": True,
        "next_run_at": Decimal(str(next_run)),
        "created_by": admin_sub,
    })

    return {
        "schedule_id": schedule_id,
        "frequency": frequency,
        "format": format,
        "template": template,
        "active": True,
        "next_run_at": next_run,
    }


def list_schedules() -> List[Dict[str, Any]]:
    """List all active scheduled reports."""
    resp = T.audit_exports.query(
        IndexName="GSI1",
        KeyConditionExpression=Key("GSI1PK").eq("SCHEDULES#ACTIVE"),
        ScanIndexForward=True,
    )
    return [_schedule_to_dict(it) for it in resp.get("Items", [])]


def update_schedule(schedule_id: str, *, admin_sub: str, **updates) -> Optional[Dict[str, Any]]:
    """Update a scheduled report."""
    resp = T.audit_exports.get_item(Key={"pk": f"SCHEDULE#{schedule_id}", "sk": "META"})
    item = resp.get("Item")
    if not item:
        return None

    for k, v in updates.items():
        if v is not None:
            item[k] = v

    # Recompute next_run if frequency changed
    if "frequency" in updates and updates["frequency"]:
        item["next_run_at"] = Decimal(str(_compute_next_run(updates["frequency"], now_ts())))
        item["GSI1SK"] = item["next_run_at"]

    T.audit_exports.put_item(Item=item)
    return _schedule_to_dict(item)


def delete_schedule(schedule_id: str) -> bool:
    """Delete a scheduled report."""
    T.audit_exports.delete_item(Key={"pk": f"SCHEDULE#{schedule_id}", "sk": "META"})
    return True


def run_scheduled_exports() -> List[Dict[str, Any]]:
    """Execute all due scheduled exports. Called by background task."""
    now = now_ts()
    resp = T.audit_exports.query(
        IndexName="GSI1",
        KeyConditionExpression=Key("GSI1PK").eq("SCHEDULES#ACTIVE")
        & Key("GSI1SK").lte(Decimal(str(now))),
    )
    results = []
    for item in resp.get("Items", []):
        schedule = _schedule_to_dict(item)
        date_range = _compute_date_range(schedule["frequency"])

        try:
            if schedule["format"] == "csv":
                export = export_ledger_csv(
                    start_date=date_range["start"],
                    end_date=date_range["end"],
                    admin_sub=schedule["created_by"],
                    **schedule.get("filters", {}),
                )
            else:
                export = export_ledger_pdf(
                    start_date=date_range["start"],
                    end_date=date_range["end"],
                    admin_sub=schedule["created_by"],
                    **schedule.get("filters", {}),
                )

            # Update schedule timing
            next_run = _compute_next_run(schedule["frequency"], now)
            T.audit_exports.update_item(
                Key={"pk": f"SCHEDULE#{schedule['schedule_id']}", "sk": "META"},
                UpdateExpression="SET last_run_at = :lr, next_run_at = :nr, GSI1SK = :nr",
                ExpressionAttributeValues={
                    ":lr": Decimal(str(now)),
                    ":nr": Decimal(str(next_run)),
                },
            )
            results.append({"schedule_id": schedule["schedule_id"], "export_id": export["export_id"], "status": "ok"})
        except Exception as e:
            logger.exception("scheduled_export_failed", extra={"schedule_id": schedule["schedule_id"]})
            results.append({"schedule_id": schedule["schedule_id"], "status": "error", "error": str(e)})

    return results


# --- Helper functions ---

def _query_ledger_range(*, start_date, end_date, user_id=None, entry_type=None, amount_min=None, amount_max=None):
    """Query billing table for ledger entries in date range with optional filters."""
    # Implementation uses GSI_LEDGER_DATE from FIN-013
    # Paginate through all matching items
    ...

def _get_columns(column_format: str) -> list:
    if column_format == "quickbooks":
        return QUICKBOOKS_COLUMNS
    elif column_format == "xero":
        return XERO_COLUMNS
    return DEFAULT_COLUMNS

def _format_row(row: dict, row_num: int, column_format: str) -> list:
    """Format a ledger entry as a CSV row."""
    ...

def _render_pdf(rows: list, *, admin_sub: str, filters: dict) -> bytes:
    """Render ledger rows as PDF with audit formatting."""
    ...

def _upload_to_s3(key: str, data: bytes, content_type: str):
    """Upload file to S3 bucket."""
    ...

def _download_from_s3(key: str) -> bytes:
    """Download file from S3 bucket."""
    ...

def _compute_next_run(frequency: str, from_ts: int) -> int:
    """Compute next scheduled run timestamp."""
    ...

def _compute_date_range(frequency: str) -> dict:
    """Compute start/end date for a frequency period."""
    ...

def _export_to_dict(item: dict) -> dict:
    return {
        "export_id": item["export_id"],
        "admin_sub": item.get("admin_sub", ""),
        "format": item["format"],
        "filters": dict(item.get("filters", {})),
        "row_count": int(item.get("row_count", 0)),
        "file_size_bytes": int(item.get("file_size_bytes", 0)),
        "sha256_hash": item.get("sha256_hash", ""),
        "status": item.get("status", "pending"),
        "created_at": int(item.get("created_at", 0)),
        "expires_at": int(item.get("expires_at", 0)),
    }

def _schedule_to_dict(item: dict) -> dict:
    return {
        "schedule_id": item["schedule_id"],
        "frequency": item["frequency"],
        "format": item["format"],
        "template": item.get("template", "full"),
        "filters": dict(item.get("filters", {})),
        "recipients": list(item.get("recipients", [])),
        "active": item.get("active", True),
        "last_run_at": int(item["last_run_at"]) if item.get("last_run_at") else None,
        "next_run_at": int(item.get("next_run_at", 0)),
        "created_by": item.get("created_by", ""),
    }
```

### 3.4 Router: `app/routers/admin_audit_export.py`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/v1/admin/audit/export/csv` | `require_admin_session` | Generate CSV export |
| POST | `/v1/admin/audit/export/pdf` | `require_admin_session` | Generate PDF export |
| GET | `/v1/admin/audit/exports` | `require_admin_session` | List export history |
| GET | `/v1/admin/audit/exports/{export_id}` | `require_admin_session` | Get export details |
| GET | `/v1/admin/audit/exports/{export_id}/download` | `require_admin_session` | Download export file |
| POST | `/v1/admin/audit/schedules` | `require_admin_session` | Create scheduled report |
| GET | `/v1/admin/audit/schedules` | `require_admin_session` | List scheduled reports |
| PATCH | `/v1/admin/audit/schedules/{schedule_id}` | `require_admin_session` | Update schedule |
| DELETE | `/v1/admin/audit/schedules/{schedule_id}` | `require_admin_session` | Delete schedule |

### 3.5 API Request/Response Examples

**POST /v1/admin/audit/export/csv**

```bash
curl -s -X POST "http://localhost:8000/v1/admin/audit/export/csv" \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_root_abc; ui_csrf=csrf_root_123; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_root_123" \
  -d '{
    "start_date": "2026-05-01",
    "end_date": "2026-05-29",
    "entry_type": "tip_debit",
    "column_format": "quickbooks"
  }'
```

Response `200 OK`:
```json
{
  "export_id": "exp_a1b2c3d4",
  "format": "csv",
  "row_count": 150,
  "file_size_bytes": 24576,
  "sha256_hash": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
  "status": "completed",
  "created_at": 1748520600,
  "expires_at": 1751112600
}
```

**POST /v1/admin/audit/export/pdf**

```bash
curl -s -X POST "http://localhost:8000/v1/admin/audit/export/pdf" \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_root_abc; ui_csrf=csrf_root_123; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_root_123" \
  -d '{
    "start_date": "2026-05-01",
    "end_date": "2026-05-31",
    "user_id": "alice_sub_123"
  }'
```

Response `200 OK`:
```json
{
  "export_id": "exp_e5f6g7h8",
  "format": "pdf",
  "row_count": 45,
  "file_size_bytes": 102400,
  "sha256_hash": "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3",
  "status": "completed",
  "created_at": 1748520700,
  "expires_at": 1751112700
}
```

**GET /v1/admin/audit/exports?limit=3**

```bash
curl -s -X GET "http://localhost:8000/v1/admin/audit/exports?limit=3" \
  -H "Cookie: ui_session=sess_root_abc; ui_csrf=csrf_root_123; ui_access_token=eyJ..."
```

Response `200 OK`:
```json
{
  "exports": [
    {
      "export_id": "exp_e5f6g7h8",
      "admin_sub": "root.admin@testdev.local",
      "format": "pdf",
      "filters": {"start_date": "2026-05-01", "end_date": "2026-05-31", "user_id": "alice_sub_123"},
      "row_count": 45,
      "file_size_bytes": 102400,
      "sha256_hash": "b2c3d4e5f6a7b8...",
      "status": "completed",
      "created_at": 1748520700,
      "expires_at": 1751112700
    },
    {
      "export_id": "exp_a1b2c3d4",
      "admin_sub": "root.admin@testdev.local",
      "format": "csv",
      "filters": {"start_date": "2026-05-01", "end_date": "2026-05-29", "entry_type": "tip_debit"},
      "row_count": 150,
      "file_size_bytes": 24576,
      "sha256_hash": "a1b2c3d4e5f6a7b8...",
      "status": "completed",
      "created_at": 1748520600,
      "expires_at": 1751112600
    }
  ],
  "count": 2,
  "cursor": null
}
```

**GET /v1/admin/audit/exports/{export_id}/download**

```bash
curl -s -X GET "http://localhost:8000/v1/admin/audit/exports/exp_a1b2c3d4/download" \
  -H "Cookie: ui_session=sess_root_abc; ui_csrf=csrf_root_123; ui_access_token=eyJ..." \
  -o export.csv
```

Response `200 OK` (Content-Type: text/csv):
```
Row#,Date,Time,Entry ID,User ID,Entry Type,Amount (cents),Currency,Provider,Description,Reason,Status
1,2026-05-29,14:23:05,e_abc123,user_001,tip_debit,500,usd,stripe,Tip on message m_xyz,Tip sent,settled
...
```

**POST /v1/admin/audit/schedules**

```bash
curl -s -X POST "http://localhost:8000/v1/admin/audit/schedules" \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_root_abc; ui_csrf=csrf_root_123; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_root_123" \
  -d '{
    "frequency": "weekly",
    "format": "csv",
    "template": "full",
    "filters": {},
    "recipients": ["admin@test.local", "finance@test.local"]
  }'
```

Response `201 Created`:
```json
{
  "schedule_id": "sched_x1y2z3",
  "frequency": "weekly",
  "format": "csv",
  "template": "full",
  "active": true,
  "next_run_at": 1748606400
}
```

**GET /v1/admin/audit/schedules**

```bash
curl -s -X GET "http://localhost:8000/v1/admin/audit/schedules" \
  -H "Cookie: ui_session=sess_root_abc; ui_csrf=csrf_root_123; ui_access_token=eyJ..."
```

Response `200 OK`:
```json
[
  {
    "schedule_id": "sched_x1y2z3",
    "frequency": "weekly",
    "format": "csv",
    "template": "full",
    "filters": {},
    "recipients": ["admin@test.local", "finance@test.local"],
    "active": true,
    "last_run_at": null,
    "next_run_at": 1748606400,
    "created_by": "root.admin@testdev.local"
  }
]
```

**PATCH /v1/admin/audit/schedules/{schedule_id}**

```bash
curl -s -X PATCH "http://localhost:8000/v1/admin/audit/schedules/sched_x1y2z3" \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_root_abc; ui_csrf=csrf_root_123; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_root_123" \
  -d '{"frequency": "monthly", "active": false}'
```

Response `200 OK`:
```json
{
  "schedule_id": "sched_x1y2z3",
  "frequency": "monthly",
  "format": "csv",
  "template": "full",
  "filters": {},
  "recipients": ["admin@test.local", "finance@test.local"],
  "active": false,
  "last_run_at": null,
  "next_run_at": 1751198400,
  "created_by": "root.admin@testdev.local"
}
```

**DELETE /v1/admin/audit/schedules/{schedule_id}**

```bash
curl -s -X DELETE "http://localhost:8000/v1/admin/audit/schedules/sched_x1y2z3" \
  -H "Cookie: ui_session=sess_root_abc; ui_csrf=csrf_root_123; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_root_123"
```

Response `200 OK`:
```json
{"ok": true}
```

### 3.6 Error Handling Matrix

| Error Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|---|---|---|---|---|
| Non-admin requests export | 403 | `forbidden` | "Admin role required" | Use admin session |
| Invalid date format (not YYYY-MM-DD) | 422 | `validation_error` | "start_date must match pattern YYYY-MM-DD" | Correct date format |
| start_date after end_date | 400 | `invalid_date_range` | "start_date must be before end_date" | Swap dates |
| Date range exceeds 1 year | 400 | `date_range_too_large` | "Export date range cannot exceed 365 days" | Narrow date range |
| Invalid column_format | 422 | `validation_error` | "column_format must be default, quickbooks, or xero" | Use valid format |
| Invalid entry_type filter | 422 | `validation_error` | "Unknown entry type: {value}" | Use valid entry type |
| amount_min > amount_max | 400 | `invalid_amount_range` | "amount_min must be less than amount_max" | Correct amount bounds |
| Export not found | 404 | `not_found` | "Export {export_id} not found" | Verify export ID |
| Export file expired (>30 days) | 410 | `gone` | "Export file has expired and been deleted" | Generate new export |
| S3 upload failure | 500 | `export_failed` | "Export generation failed" | Retry; check S3 connectivity |
| Schedule not found | 404 | `not_found` | "Schedule {schedule_id} not found" | Verify schedule ID |
| Invalid frequency | 422 | `validation_error` | "frequency must be daily, weekly, or monthly" | Use valid frequency |
| Empty recipients list | 422 | `validation_error` | "recipients must have at least 1 item" | Provide at least one email |
| Export rate limit exceeded | 429 | `rate_limited` | "Maximum 5 exports per hour" | Wait and retry |
| Export too large for sync (>50K rows) | 202 | `accepted` | "Export queued for async processing" | Poll export status |

### 3.7 Pydantic Models (`app/models.py`)

```python
from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional


class AuditExportRequest(BaseModel):
    """Request to generate an audit export."""
    start_date: str = Field(
        ..., pattern=r"^\d{4}-\d{2}-\d{2}$",
        description="Start date (inclusive) in YYYY-MM-DD format",
        examples=["2026-05-01"],
    )
    end_date: str = Field(
        ..., pattern=r"^\d{4}-\d{2}-\d{2}$",
        description="End date (inclusive) in YYYY-MM-DD format",
        examples=["2026-05-31"],
    )
    user_id: Optional[str] = Field(None, description="Filter by user ID")
    entry_type: Optional[str] = Field(
        None, description="Filter by entry type",
        examples=["tip_debit", "tip_credit", "unlock_debit", "deposit", "payout"],
    )
    amount_min: Optional[int] = Field(default=None, ge=0, description="Minimum amount in cents")
    amount_max: Optional[int] = Field(default=None, ge=0, description="Maximum amount in cents")
    column_format: str = Field(
        default="default",
        pattern=r"^(default|quickbooks|xero)$",
        description="Column format for CSV export",
    )


class AuditExportOut(BaseModel):
    """Response for a generated or retrieved export."""
    export_id: str = Field(..., description="Unique export identifier", examples=["exp_a1b2c3d4"])
    format: str = Field(..., description="Export format", examples=["csv", "pdf"])
    filters: Dict[str, Any] = Field(..., description="Filters applied to the export")
    row_count: int = Field(..., ge=0, description="Number of ledger rows exported")
    file_size_bytes: int = Field(..., ge=0, description="Size of generated file in bytes")
    sha256_hash: str = Field(..., description="SHA-256 hash of file content for tamper detection")
    status: str = Field(..., description="Export status", examples=["completed", "pending", "failed"])
    admin_sub: Optional[str] = Field(None, description="Admin who triggered the export")
    created_at: int = Field(..., description="Unix timestamp of export creation")
    expires_at: int = Field(..., description="Unix timestamp when export file expires")


class AuditExportListOut(BaseModel):
    """Paginated list of exports."""
    exports: List[AuditExportOut]
    count: int = Field(..., ge=0)
    cursor: Optional[str] = None


class ScheduleCreate(BaseModel):
    """Request to create a scheduled report."""
    frequency: str = Field(
        ..., pattern=r"^(daily|weekly|monthly)$",
        description="Report frequency",
    )
    format: str = Field(
        default="csv", pattern=r"^(csv|pdf)$",
        description="Report format",
    )
    template: str = Field(
        default="full", pattern=r"^(full|summary|by_type)$",
        description="Report template to use",
    )
    filters: Dict[str, Any] = Field(
        default_factory=dict,
        description="Default filters for each scheduled run",
    )
    recipients: List[str] = Field(
        ..., min_length=1,
        description="Email addresses to send report to",
        examples=[["admin@test.local"]],
    )


class ScheduleUpdate(BaseModel):
    """Request to update a scheduled report."""
    frequency: Optional[str] = Field(default=None, pattern=r"^(daily|weekly|monthly)$")
    format: Optional[str] = Field(default=None, pattern=r"^(csv|pdf)$")
    template: Optional[str] = Field(default=None, pattern=r"^(full|summary|by_type)$")
    filters: Optional[Dict[str, Any]] = None
    recipients: Optional[List[str]] = None
    active: Optional[bool] = None


class ScheduleOut(BaseModel):
    """Response for a scheduled report."""
    schedule_id: str = Field(..., description="Unique schedule identifier")
    frequency: str
    format: str
    template: str
    filters: Dict[str, Any]
    recipients: List[str]
    active: bool
    last_run_at: Optional[int] = None
    next_run_at: int
    created_by: str
```

### 3.8 Frontend Component Tree

```
AuditExportPage (route: /admin/audit-export)
├── PageHeader
│   ├── h1 "Financial Audit Export"
│   └── Badge ("Admin")
├── Tabs (shadcn)
│   ├── TabPanel: "Export"
│   │   └── ExportForm (props: { onSubmit: (req: AuditExportRequest) => void, isExporting: boolean })
│   │       ├── Form (react-hook-form + zod)
│   │       │   ├── DateRangePicker (props: { startDate: string, endDate: string, onChange: ... })
│   │       │   │   ├── Input (start_date, type="date")
│   │       │   │   └── Input (end_date, type="date")
│   │       │   ├── Input ("User ID", optional)
│   │       │   ├── Select ("Entry Type", options: all/tip_debit/tip_credit/unlock_debit/deposit/payout)
│   │       │   ├── NumberInput ("Amount Min (cents)")
│   │       │   ├── NumberInput ("Amount Max (cents)")
│   │       │   ├── Select ("Column Format", options: default/quickbooks/xero)
│   │       │   └── RadioGroup ("Format", options: CSV/PDF)
│   │       ├── Button ("Generate Export") + loading spinner
│   │       └── ExportResultCard (props: { result: AuditExportOut | null })
│   │           ├── StatRow (row count, file size, checksum truncated)
│   │           └── Button ("Download")
│   ├── TabPanel: "History"
│   │   └── ExportHistoryTable (props: { exports: AuditExportOut[], onDownload: (id: string) => void, onLoadMore: () => void })
│   │       ├── DataTable (shadcn)
│   │       │   └── ExportRow
│   │       │       ├── FormatBadge (CSV | PDF)
│   │       │       ├── FilterSummary (compact text: "May 1-29, tips, QB format")
│   │       │       ├── RowCount
│   │       │       ├── FileSize (formatted: "24.0 KB")
│   │       │       ├── TimeAgo (created_at)
│   │       │       ├── ChecksumCopy (truncated hash with copy-to-clipboard)
│   │       │       └── Button ("Download") — disabled if expired
│   │       └── LoadMoreButton (if cursor present)
│   └── TabPanel: "Schedules"
│       └── ScheduleManager (props: { schedules: ScheduleOut[], onCreate: ..., onEdit: ..., onDelete: ... })
│           ├── Button ("New Schedule") → opens CreateScheduleDialog
│           ├── ScheduleList
│           │   └── ScheduleCard (props: { schedule: ScheduleOut })
│           │       ├── FrequencyBadge (daily | weekly | monthly)
│           │       ├── FormatBadge (CSV | PDF)
│           │       ├── TemplateName
│           │       ├── RecipientsList (comma-separated emails)
│           │       ├── NextRunTime (formatted datetime)
│           │       ├── Switch ("Active") — toggle pause/resume
│           │       ├── Button ("Edit") → opens EditScheduleDialog
│           │       └── Button ("Delete") → confirmation Dialog
│           ├── CreateScheduleDialog (props: { open: boolean, onSubmit: (data: ScheduleCreate) => void })
│           │   ├── Dialog (shadcn)
│           │   ├── Form (react-hook-form + zod)
│           │   │   ├── Select (frequency)
│           │   │   ├── Select (format)
│           │   │   ├── Select (template)
│           │   │   └── TagInput (recipients — email list)
│           │   └── Button ("Create Schedule")
│           └── EditScheduleDialog (similar to Create, pre-filled)
```

### 3.9 CSV Format — Audit Grade

Default CSV columns:

```
Row#,Date,Time,Entry ID,User ID,Entry Type,Amount (cents),Currency,Provider,Description,Reason,Status
1,2026-05-29,14:23:05,e_abc123,user_001,tip_debit,500,usd,stripe,Tip on message m_xyz,Tip sent,settled
2,2026-05-29,14:23:05,e_abc124,user_002,tip_credit,425,usd,stripe,Tip received,Tip received,settled
...
TOTAL,,,,,,12500,usd,,,,
ROWS: 150
SHA-256: a1b2c3d4e5f6...
EXPORTED BY: root.admin@testdev.local
EXPORTED AT: 2026-05-29T14:30:00Z
FILTERS: date_range=2026-05-01..2026-05-29, entry_type=all
```

### 3.10 Frontend API (`frontend/src/api/endpoints/adminAuditExport.ts`)

```typescript
import client from "../client";
import type {
  AuditExportRequest,
  AuditExportOut,
  AuditExportListOut,
  ScheduleCreate,
  ScheduleUpdate,
  ScheduleOut,
} from "../types";

export const exportCsv = (data: AuditExportRequest) =>
  client.post<AuditExportOut>("/v1/admin/audit/export/csv", data);

export const exportPdf = (data: AuditExportRequest) =>
  client.post<AuditExportOut>("/v1/admin/audit/export/pdf", data);

export const listExports = (params?: { limit?: number; cursor?: string }) =>
  client.get<AuditExportListOut>("/v1/admin/audit/exports", { params });

export const getExport = (exportId: string) =>
  client.get<AuditExportOut>(`/v1/admin/audit/exports/${exportId}`);

export const downloadExport = (exportId: string) =>
  client.get(`/v1/admin/audit/exports/${exportId}/download`, { responseType: "blob" });

export const createSchedule = (data: ScheduleCreate) =>
  client.post<ScheduleOut>("/v1/admin/audit/schedules", data);

export const listSchedules = () =>
  client.get<ScheduleOut[]>("/v1/admin/audit/schedules");

export const updateSchedule = (scheduleId: string, data: ScheduleUpdate) =>
  client.patch<ScheduleOut>(`/v1/admin/audit/schedules/${scheduleId}`, data);

export const deleteSchedule = (scheduleId: string) =>
  client.delete(`/v1/admin/audit/schedules/${scheduleId}`);
```

---

## 4. Implementation Plan

### Phase 1: Backend Data Layer (Days 1-2)

1. **`scripts/local-ddb-init.py`**: Add `audit_exports` table with GSI.
2. **`app/core/settings.py`**: Add `audit_exports_table_name`.
3. **`app/core/tables.py`**: Add `audit_exports` table handle.

### Phase 2: Backend Export Service (Days 2-4)

4. **`app/services/audit_export.py`**: New file. CSV/PDF generation, S3 storage, checksum computation, scheduled report management.
5. **S3 integration**: Store export files in `exports/` prefix in the S3 bucket.

### Phase 3: Backend Router (Days 4-5)

6. **`app/models.py`**: Add audit export Pydantic models.
7. **`app/routers/admin_audit_export.py`**: New router with 9 endpoints.
8. **`app/main.py`**: Register router with prefix `/v1/admin/audit`.

### Phase 4: Frontend (Days 5-7)

9. **`frontend/src/api/types.ts`**: Add TypeScript types.
10. **`frontend/src/api/endpoints/adminAuditExport.ts`**: New file.
11. **`frontend/src/pages/admin/audit/AuditExportPage.tsx`**: New page.
12. **`frontend/src/App.tsx`**: Add `/admin/audit-export` route.
13. **`frontend/src/components/layout/Sidebar.tsx`**: Add "Audit Export" admin nav link.

### Phase 5: E2E Tests (Days 8-9)

14. **`frontend/e2e/admin-audit-export.spec.ts`**: 24 tests across 6 sections.

---

## 5. E2E Test Plan

**Test file**: `frontend/e2e/admin-audit-export.spec.ts`

**Setup (beforeAll)**:
- Inject auth for Root, Alice, Charlie (admin)
- Seed billing ledger with 10 entries across different types and providers

**Section 535: CSV Export API (5 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | `Admin generates CSV export` | POST `/v1/admin/audit/export/csv` with date range as Root -> 200; `export_id` present, `status: "completed"`, `row_count > 0` |
| 2 | `CSV export respects entry_type filter` | POST with `entry_type: "tip_debit"` -> 200; `row_count` matches seeded tip entries |
| 3 | `CSV export respects amount range filter` | POST with `amount_min: 100, amount_max: 500` -> 200; `row_count` <= total seeded |
| 4 | `Export includes SHA-256 checksum` | Response has `sha256_hash` (64-char hex string) |
| 5 | `Non-admin cannot export` | POST as Alice -> 403 |

**Section 536: PDF Export & Download API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 6 | `Admin generates PDF export` | POST `/v1/admin/audit/export/pdf` with date range -> 200; `format: "pdf"`, `file_size_bytes > 0` |
| 7 | `Admin downloads export file` | GET `/v1/admin/audit/exports/{id}/download` -> 200; response body is non-empty |
| 8 | `Download of non-existent export returns 404` | GET with bogus ID -> 404 |
| 9 | `PDF export with user_id filter` | POST with `user_id: alice_sub` -> 200; `row_count` <= total seeded for Alice |

**Section 537: Export History API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 10 | `Admin lists export history` | GET `/v1/admin/audit/exports` as Root -> 200; array includes exports from sections above |
| 11 | `Export detail includes filter metadata` | GET `/v1/admin/audit/exports/{id}` -> 200; `filters` object has `start_date`, `end_date` |
| 12 | `History sorted by created_at descending` | First item's `created_at >= second item's created_at` |
| 13 | `Export detail includes checksum and file size` | Response has `sha256_hash` (64 hex chars) and `file_size_bytes > 0` |

**Section 538: Scheduled Reports API (5 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 14 | `Admin creates scheduled report` | POST `/v1/admin/audit/schedules` with `{frequency: "weekly", format: "csv", recipients: ["admin@test.local"]}` -> 201; `schedule_id` present |
| 15 | `Admin lists schedules` | GET `/v1/admin/audit/schedules` -> 200; includes created schedule |
| 16 | `Admin updates schedule frequency` | PATCH `/v1/admin/audit/schedules/{id}` with `{frequency: "monthly"}` -> 200; re-GET shows `frequency: "monthly"` |
| 17 | `Admin pauses schedule` | PATCH with `{active: false}` -> 200; re-GET shows `active: false` |
| 18 | `Admin deletes schedule` | DELETE `/v1/admin/audit/schedules/{id}` -> 200; re-list excludes it |

**Section 539: Export Validation & Edge Cases (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 19 | `Invalid date format returns 422` | POST with `start_date: "May 1, 2026"` -> 422 |
| 20 | `start_date after end_date returns 400` | POST with `start_date: "2026-06-01", end_date: "2026-05-01"` -> 400 |
| 21 | `Empty recipients on schedule create returns 422` | POST schedule with `recipients: []` -> 422 |

**Section 540: Audit Export UI (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 22 | `Audit export page loads with export form` | Navigate to `/admin/audit-export` as Root; verify date inputs, entry type select, format radio buttons visible |
| 23 | `History tab shows previous exports` | Click "History" tab; verify DataTable with format badges, row counts, download buttons |
| 24 | `Schedules tab shows schedule cards` | Click "Schedules" tab; verify schedule list with frequency badges and active toggles |

---

## 6. Observability & Monitoring

### 6.1 Metrics

| Metric Name | Type | Labels | Description |
|---|---|---|---|
| `audit_export_total` | Counter | `format` (csv/pdf), `column_format` | Total exports generated |
| `audit_export_duration_seconds` | Histogram | `format` | Time to generate an export |
| `audit_export_row_count` | Histogram | `format` | Number of rows per export |
| `audit_export_file_size_bytes` | Histogram | `format` | File size per export |
| `audit_export_error_total` | Counter | `error_type` | Export generation failures |
| `audit_schedule_run_total` | Counter | `status` (ok/error) | Scheduled report executions |
| `audit_export_download_total` | Counter | — | Export file downloads |
| `audit_export_expired_total` | Counter | — | Expired export download attempts |

### 6.2 Structured Log Events

```json
{
  "logger": "audit_export",
  "level": "INFO",
  "event": "csv_export_completed",
  "export_id": "exp_a1b2c3d4",
  "admin": "root.admin@testdev.local",
  "row_count": 150,
  "file_size": 24576,
  "duration_ms": 1234,
  "filters": {"start_date": "2026-05-01", "end_date": "2026-05-29", "entry_type": "tip_debit"},
  "timestamp": 1748520600
}
```

```json
{
  "logger": "audit_export",
  "level": "INFO",
  "event": "scheduled_export_completed",
  "schedule_id": "sched_x1y2z3",
  "export_id": "exp_b2c3d4e5",
  "frequency": "weekly",
  "row_count": 500,
  "recipients": ["admin@test.local"],
  "timestamp": 1748606500
}
```

```json
{
  "logger": "audit_export",
  "level": "ERROR",
  "event": "export_failed",
  "export_id": "exp_c3d4e5f6",
  "error": "S3 upload failed: ConnectionError",
  "admin": "root.admin@testdev.local",
  "timestamp": 1748520800
}
```

### 6.3 Alerting Rules

| Alert | Condition | Severity | Action |
|---|---|---|---|
| Export generation failure | > 3 export failures in 1 hour | Warning | Check S3 connectivity and DDB throttling |
| Scheduled export missed | Active schedule not run within 2x frequency period | Warning | Check background task health |
| Export latency degraded | p95 export time > 30 seconds | Warning | Investigate large date ranges; consider async threshold |
| Export file size anomaly | File size > 100MB | Info | May indicate data growth; review retention policy |
| Export rate limit hit | > 10 rate-limit responses in 1 hour | Info | Admin may need higher limit or batch scheduling |

---

## 7. Rollout Plan

### Phase 1: CSV Export Only (Week 1)

**Feature flag**: `AUDIT_EXPORT_ENABLED=true`, `AUDIT_EXPORT_PDF_ENABLED=false`

- Deploy CSV export with all filters and column format options
- Schedule system deployed but not yet enabled
- Export history tracking active
- Duration: 1 week of admin testing

### Phase 2: PDF + Schedules (Week 2)

**Feature flag**: `AUDIT_EXPORT_PDF_ENABLED=true`, `AUDIT_SCHEDULES_ENABLED=true`

- Enable PDF generation
- Enable scheduled reports
- Background task registered in main.py
- Duration: 1 week

### Phase 3: Accounting Integrations (Week 3)

- QuickBooks and Xero column mappings validated with real accounting software import
- Add column mapping documentation in admin dashboard
- Remove beta badges from UI

### Feature Flags

| Flag | Default | Description |
|---|---|---|
| `AUDIT_EXPORT_ENABLED` | `true` | Master toggle for audit export |
| `AUDIT_EXPORT_PDF_ENABLED` | `false` | Enable PDF export format |
| `AUDIT_SCHEDULES_ENABLED` | `false` | Enable scheduled reports |
| `AUDIT_EXPORT_MAX_SYNC_ROWS` | `50000` | Threshold for async export |
| `AUDIT_EXPORT_TTL_DAYS` | `30` | File retention period |
| `AUDIT_EXPORT_RATE_LIMIT` | `5` | Max exports per hour per admin |

### Rollback Procedure

1. Set `AUDIT_EXPORT_ENABLED=false` — disables all export endpoints (returns 503)
2. Existing export files remain in S3 until TTL expiry
3. Schedule execution paused immediately
4. Export metadata retained in DDB for auditing
5. Revert code deployment if needed

---

## 8. Performance Considerations

### 8.1 Latency Targets

| Operation | Target | Notes |
|---|---|---|
| CSV export (< 1K rows) | < 3 seconds | Inline response |
| CSV export (1K-10K rows) | < 15 seconds | Inline response with progress |
| CSV export (10K-50K rows) | < 60 seconds | Inline response, near async threshold |
| CSV export (> 50K rows) | Async (202) | Background job with progress tracking |
| PDF export (any size) | < 30 seconds | PDF rendering adds overhead |
| GET /exports (list) | < 200ms | GSI1 query, paginated |
| GET /exports/{id} | < 50ms | Single DDB get |
| Download file | < 500ms | S3 GetObject, streaming |
| Schedule execution | < 5 minutes | Background task, not user-facing |

### 8.2 DynamoDB Query Costs

| Query | RCU Estimate | Notes |
|---|---|---|
| Billing ledger date range (per day) | 5-50 RCU | Depends on daily transaction volume |
| Full month export (30 days) | 150-1500 RCU | Significant; spread across seconds of export |
| Export metadata get | 0.5 RCU | Single item |
| Export list query | 1-5 RCU | Paginated, metadata only |
| Schedule list query | 0.5-2 RCU | Typically < 20 active schedules |

### 8.3 Memory Management

- CSV rows are streamed into a `StringIO` buffer, not accumulated in a list first. For very large exports, the buffer can grow to 50-100MB in memory. The async export path uses chunked S3 multipart upload to limit memory to ~10MB at a time.
- PDF rendering uses a streaming approach: pages are rendered and flushed to disk incrementally.

### 8.4 S3 Storage

- Export files stored with prefix `exports/{export_id}.{format}`
- S3 lifecycle rule: delete objects older than 30 days
- Average export file size: 20KB (CSV, 200 rows) to 50MB (CSV, 50K rows)
- Estimated monthly storage: < 1GB for moderate usage (20 exports/week)

### 8.5 Rate Limiting

- 5 exports per hour per admin session (configurable)
- Scheduled exports are exempt from rate limiting (server-initiated)
- Download endpoint has a separate limit of 20 downloads per hour per admin

---

## 9. Security Considerations

### 9.1 Role-Based Access
- All export endpoints require ADMIN role
- Export data contains sensitive financial information (user IDs, amounts, providers)

### 9.2 Tamper Evidence
- SHA-256 hash computed at export time and stored in metadata
- Verify hash on download to detect corruption
- Export records are immutable (cannot be modified after creation)

### 9.3 Data Retention
- Export files stored in S3 with 30-day expiry
- Export metadata retained indefinitely for audit trail
- Scheduled report emails should not contain sensitive data inline — link to download

### 9.4 Export Rate Limiting
- Limit to 5 exports per hour per admin to prevent abuse
- Large exports (>100K rows) processed asynchronously

### 9.5 PII Considerations
- User IDs in exports are internal identifiers (not email addresses)
- Admins accessing exports must have signed data handling agreements

---

## 10. Files to Create

| File | Purpose |
|------|---------|
| `app/services/audit_export.py` | <!-- NOTE: ALREADY EXISTS (46 lines). Extend with CSV/PDF billing-specific export, schedule management. --> |
| `app/routers/admin_audit_export.py` | <!-- NOTE: An audit export router ALREADY EXISTS at `app/routers/audit_export.py` (192 lines, registered at `app/main.py:448`). Either extend it or create a separate billing-specific router. --> |
| `frontend/src/api/endpoints/adminAuditExport.ts` | API wrappers |
| `frontend/src/pages/admin/audit/AuditExportPage.tsx` | Export page |
| `frontend/e2e/admin-audit-export.spec.ts` | E2E tests (24 tests, sections 535-540) |

## 11. Files to Modify

| File | Change |
|------|--------|
| `app/models.py` | Add audit export Pydantic models |
| `app/main.py` | Register `admin_audit_export_router` |
| `app/core/settings.py` | <!-- NOTE: `audit_export_table_name` ALREADY EXISTS at `:1452`. No new setting needed for the table name, though scheduled report settings may be new. --> |
| `app/core/tables.py` | <!-- NOTE: Verify if `audit_exports` table handle already exists. --> |
| `scripts/local-ddb-init.py` | <!-- NOTE: `AuditExports` table ALREADY EXISTS at `:1044-1053`. May need to add schedule-specific GSIs. --> |
| `frontend/src/api/types.ts` | Add audit export TypeScript types |
| `frontend/src/App.tsx` | Add `/admin/audit-export` route |
| `frontend/src/components/layout/Sidebar.tsx` | Add "Audit Export" admin nav link |

## 12. Acceptance Criteria

1. CSV export generates valid CSV with sequential row numbering and SHA-256 checksum
2. PDF export produces formatted document with subtotals and grand total
3. Exports filtered by date range, user ID, entry type, and amount range
4. QuickBooks and Xero column format options available for CSV
5. Export history tracks all exports with filter metadata and checksums
6. Previous exports downloadable for 30 days
7. Scheduled reports can be created, listed, updated, and deleted
8. Non-admin users receive 403 on all endpoints
9. All 24 E2E tests pass in `frontend/e2e/admin-audit-export.spec.ts`
10. Export generation completes within latency targets for each size tier
11. SHA-256 checksum verifiable on every download
12. Feature flags allow incremental rollout of CSV, PDF, and scheduling features

---

## Codebase References

| File | Lines | What |
|------|-------|------|
| `app/services/audit_export.py` | 46 total | **ALREADY EXISTS** — export record model with `to_csv_row` at `:29`, `to_ndjson_dict` at `:41` |
| `app/services/audit_export_pipeline.py` | 249 total | **ALREADY EXISTS** — export pipeline (job creation, execution, S3 upload) |
| `app/routers/audit_export.py` | 192 total | **ALREADY EXISTS** — router at prefix `/ui/admin/audit-exports` with `:64` POST, `:102` GET list, `:123` GET detail, `:137` GET download |
| `app/main.py` | :157, :448 | `audit_export_router` import and registration |
| `scripts/local-ddb-init.py` | :1044-1053 | `AuditExports` table (PK=export_id, SK=sk, GSIs: status-created-index, user-created-index) |
| `app/core/settings.py` | :1451-1467 | `audit_export_enabled` at `:1451`, `audit_export_table_name` at `:1452`, `audit_export_max_date_range_days` at `:1453`, `audit_export_s3_bucket` at `:1455`, `audit_export_worker_enabled` at `:1465` |
| `app/services/billing_shared.py` | :217, :248 | `new_ledger_entry` at `:217`, `settle_or_reverse_ledger` at `:248` |
| `app/routers/admin_payouts.py` | — | Existing admin payout router |
| `app/auth/policy.py` | :63, :67 | `require_root` at `:63`, `require_admin_or_root` at `:67` |
| `scripts/local-ddb-init.py` | :59 | `billing` table (PK=pk, SK=sk, NO GSIs) |
