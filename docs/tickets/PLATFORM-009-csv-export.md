# PLATFORM-009: CSV Export

**Ticket**: PLATFORM-009
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-27
**Priority**: P3 (Nice to Have)
**Estimated effort**: 4-5 days

---

## 1. Executive Summary

The platform has no server-side CSV export capability. The only data export is the GDPR compliance export (`app/routers/privacy.py`), which produces a JSON archive of all user data. The billing ledger has a client-side CSV export (`Ledger.tsx:154-168`) that converts in-memory React Query data to a CSV blob, but this is limited to the data already loaded in the browser (max page size) and does not support server-side filtering, date ranges, or large datasets.

Data export is a foundational SaaS capability. Creators need billing CSVs for tax reporting, contacts CSVs for CRM import, and questionnaire response CSVs for external analysis. The current client-side export in the Ledger component demonstrates user demand for CSV data, but its limitation to browser-loaded data means a creator with 500 billing entries may only export the first 50 visible in the current page. Furthermore, contacts and questionnaire data have no export path at all, forcing creators to manually transcribe data.

This feature adds a backend CSV export service with `GET /ui/export/csv` supporting multiple data sources (billing history, contacts, questionnaire responses, analytics). The endpoint streams CSV data with `Content-Type: text/csv` and `Content-Disposition: attachment` headers, handling DynamoDB pagination internally so the full dataset is exported regardless of browser-side page size. Frontend pages get "Export CSV" buttons that trigger downloads via the browser's native download mechanism. The streaming architecture ensures memory efficiency for large datasets.

---

## 2. Detailed Problem Analysis

### 2.1 User Stories

**US-1: Billing CSV for tax reporting**
As a creator, I want to export my billing history as a CSV for tax reporting and bookkeeping so that I can reconcile my platform income with my accounting software.

Acceptance Criteria:
- "Export CSV" button visible on the Billing page next to or replacing the existing client-side export.
- The exported CSV includes ALL billing entries, not just the currently visible page.
- Each row includes: Date, Type, Amount (in dollars, formatted to 2 decimal places), Currency, Status, Reason, Transaction ID.
- Date range filtering via `from_date` and `to_date` query parameters limits the export to a specific period (e.g., Q1 2026).
- The file downloads with a descriptive filename like `billing_ledger_1748380800.csv`.

**US-2: Contacts CSV for CRM import**
As a creator, I want to export my contacts list as a CSV so that I can import them into external CRM tools (HubSpot, Mailchimp, etc.).

Acceptance Criteria:
- "Export CSV" button visible on the Contacts page header.
- Each row includes: Name, Email, Phone, Company, Tags, Is Favorite, Is Blocked, Created At.
- The CSV is compatible with standard CRM import formats (comma-separated, UTF-8 with BOM for Excel compatibility).
- Blocked contacts are included but marked with `is_blocked=true`.

**US-3: Questionnaire responses CSV for analysis**
As a creator, I want to export questionnaire responses as a CSV for external analysis in Excel or Google Sheets so that I can perform statistical analysis on response data.

Acceptance Criteria:
- "Export CSV" button visible on the Questionnaire analytics card.
- The export requires a `questionnaire_id` parameter.
- Each row includes: Respondent ID, Started At, Submitted At, Status, Duration (seconds), Version, Answers (JSON string).
- Only the questionnaire owner can export responses (verified via ownership check).

**US-4: Date range filtering**
As a creator, I want to filter the export by date range so that I can export data for a specific quarter or year.

Acceptance Criteria:
- `from_date` and `to_date` query parameters accept Unix timestamps.
- When provided, only records within the date range are included.
- When omitted, all records are exported.
- Invalid date values (non-numeric, negative) return 422.

**US-5: Large dataset streaming**
As a creator with thousands of billing entries, I want the CSV export to handle large datasets without timing out or running out of memory.

Acceptance Criteria:
- The endpoint uses FastAPI's `StreamingResponse` to send rows as they are fetched from DynamoDB.
- DynamoDB pagination (`LastEvaluatedKey`) is handled internally -- the client receives a single continuous CSV stream.
- The response starts within 200ms (first row sent before all data is fetched).
- Memory usage is O(1) per row (not O(n) for all rows).

### 2.2 Pain Points

1. **No server-side CSV export**: The only CSV generation is client-side in Ledger.tsx, limited to already-loaded data.
2. **Tax/accounting workflows blocked**: Creators need billing CSVs for bookkeeping but must manually copy data.
3. **Questionnaire data trapped in the UI**: Response data is only viewable in the analytics card; cannot be bulk-extracted.
4. **No date range filtering on export**: Users cannot export a specific quarter of billing data.
5. **Contacts page has no export at all**: No way to extract contact data for CRM import.

---

## 3. Current State Analysis

### 3.1 GDPR Compliance Export

`app/routers/privacy.py` provides `POST /ui/privacy/export` (line 50) which creates a JSON archive of all user data. It is designed for full-account data portability under GDPR requirements, not ad-hoc CSV exports. The export is processed inline in the MVP (line 73: `process_export(user_sub, item["request_id"], categories)`) with no streaming -- the entire archive is built in memory then stored to S3. A separate `GET /ui/privacy/export/{request_id}/download` (line 114) returns a redirect to the S3 pre-signed URL.

This export is rate-limited (`has_recent_export` check, line 60), asynchronous-by-design, and returns JSON -- none of which matches the CSV export use case.

**Citations**:
- `app/routers/privacy.py:1` -- `"""Privacy / GDPR endpoints (PRIVACY-001)."""`
- `app/routers/privacy.py:50-79` -- `request_export` endpoint (JSON archive, inline processing)
- `app/routers/privacy.py:60` -- `has_recent_export` rate limit check
- `app/routers/privacy.py:114-123` -- `download_export` returns S3 redirect

### 3.2 Client-Side CSV in Ledger

`Ledger.tsx` has an `exportCsv` function (lines 154-168) that:
1. Constructs a CSV header: `"Date,Type,Amount,Status,Reason"` (line 155)
2. Maps sorted ledger entries to CSV rows using `formatDate(e.ts)`, `e.type`, `(e.amount_cents / 100).toFixed(2)`, `e.state`, `e.reason` (lines 156-158)
3. Creates a `Blob` with `text/csv` MIME type (line 161)
4. Creates a temporary `<a>` element with `download="ledger.csv"` (lines 162-167)
5. Triggers the download via `a.click()` (line 166)

This exports only the `sorted` array, which comes from filtering + sorting the React Query data. The React Query fetch uses pagination, so only the current page of data is available for export.

```typescript
const exportCsv = () => {
  const header = "Date,Type,Amount,Status,Reason";
  const rows = sorted.map(
    (e) =>
      `${formatDate(e.ts)},${e.type},${(e.amount_cents / 100).toFixed(2)},${e.state},${e.reason ?? ""}`,
  );
  const csv = [header, ...rows].join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "ledger.csv";
  a.click();
  URL.revokeObjectURL(url);
};
```

The "Export CSV" button (line 211) is disabled when `sorted.length === 0`:

```typescript
<Button variant="outline" size="sm" onClick={exportCsv} disabled={sorted.length === 0}>
  <Download className="mr-1 h-3.5 w-3.5" />
  Export CSV
</Button>
```

**Citations**:
- `frontend/src/pages/billing/Ledger.tsx:154-168` -- `exportCsv()` function
- `frontend/src/pages/billing/Ledger.tsx:155` -- header: `"Date,Type,Amount,Status,Reason"`
- `frontend/src/pages/billing/Ledger.tsx:161` -- `Blob` creation with `text/csv`
- `frontend/src/pages/billing/Ledger.tsx:211` -- "Export CSV" button with disabled state

### 3.3 No CSV Endpoints in Backend

No backend router returns `text/csv` content. Grep for "csv" in routers finds only unrelated `_csv_items()` utility functions for parsing comma-separated environment variables.

**Citations**:
- `app/routers/browser_ssh_terminal.py:389` -- `_csv_items()` (env var parsing, not data export)
- `app/routers/messaging.py:1574` -- `_csv_env_set()` (env var parsing, not data export)
- `app/routers/newsfeed.py:73` -- `_csv_values()` (env var parsing, not data export)

### 3.4 Billing Table Schema

The billing table (`T.billing`) stores ledger entries with the following key schema:
- PK: `USER#{user_sub}` (partition key)
- SK: `LEDGER#{timestamp}#{uuid}` (sort key, ensures uniqueness)

Entries have fields: `entry_type`, `amount_cents`, `currency`, `state`, `reason`, `meta`, `created_at`.

The billing table has a GSI `ByCreatedAt` with `pk` as partition key and `created_at` (numeric) as sort key, which can be used for date-range queries.

**Citations**:
- `app/core/tables.py:120` -- `billing=ddb.Table(S.billing_table_name)`

### 3.5 Contacts Table Schema

The contacts table (`T.contacts`, `app/core/settings.py:434`) stores contact records with PK `CONTACT#{owner_user_sub}#{contact_user_sub}`.

### 3.6 Questionnaire Response Sessions

The questionnaire repository (`DynamoQuestionnaireRepository`) provides `list_response_sessions(questionnaire_id)` which returns all response sessions for a questionnaire. Each session has: `session_id`, `respondent_id`, `started_at`, `submitted_at`, `status`, `version_id`, `answers`.

**Citations**:
- `app/routers/questionnaires.py:151` -- `REPO.list_response_sessions(questionnaire_id=questionnaire_id)`

### 3.7 Gaps

1. No server-side CSV generation endpoint
2. No `text/csv` content type in any response
3. No date-range filtering on any export path
4. Client-side Ledger CSV is limited to loaded page data
5. Contacts page has no export functionality at all
6. Questionnaire responses have no export functionality
7. No reusable CSV streaming utility

---

## 4. Implementation Plan

### 4.1 Backend: CSV Export Service

**New file `app/services/csv_export.py`:**

A generic CSV streaming service that queries DynamoDB with pagination and yields CSV rows. Each data source has its own column definition and row formatter.

```python
"""Server-side CSV export service (PLATFORM-009).

Generates streaming CSV data from DynamoDB for various data sources.
Uses Python's csv.writer for proper RFC 4180 CSV formatting (handling
commas, quotes, newlines in field values).

Supports:
  - billing_ledger: Billing history for a user
  - contacts: Contact records for a user
  - questionnaire_responses: Response sessions for a questionnaire
"""

from __future__ import annotations

import csv
import io
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, Generator, List, Optional

from app.core.tables import T
from app.core.time import now_ts
from app.services.billing_shared import user_pk

logger = logging.getLogger(__name__)

# Maximum rows per export (safety limit)
MAX_EXPORT_ROWS = 50_000


# ─── Column Definitions ────────────────────────────────────────

BILLING_COLUMNS = ["Date", "Type", "Amount", "Currency", "Status", "Reason", "Transaction ID"]
CONTACTS_COLUMNS = ["Name", "Email", "Phone", "Company", "Tags", "Is Favorite", "Is Blocked", "Created At"]
QUESTIONNAIRE_COLUMNS = ["Respondent ID", "Started At", "Submitted At", "Status", "Duration (s)", "Version", "Answers"]


# ─── Data Source Iterators ──────────────────────────────────────

def _iter_billing_entries(
    user_sub: str,
    *,
    from_date: Optional[int] = None,
    to_date: Optional[int] = None,
) -> Generator[Dict[str, Any], None, None]:
    """Iterate over billing ledger entries with optional date filtering.

    Uses DynamoDB query with SK prefix 'LEDGER#' and handles pagination
    via LastEvaluatedKey loop.
    """
    pk = user_pk(user_sub)
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": "pk = :pk AND begins_with(sk, :prefix)",
        "ExpressionAttributeValues": {":pk": pk, ":prefix": "LEDGER#"},
        "Limit": 500,
    }

    row_count = 0
    while row_count < MAX_EXPORT_ROWS:
        resp = T.billing.query(**kwargs)
        items = resp.get("Items", [])
        for item in items:
            ts = int(item.get("created_at", 0))
            if from_date and ts < from_date:
                continue
            if to_date and ts > to_date:
                continue
            yield item
            row_count += 1
            if row_count >= MAX_EXPORT_ROWS:
                break

        if "LastEvaluatedKey" not in resp or row_count >= MAX_EXPORT_ROWS:
            break
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]


def _iter_contacts(user_sub: str) -> Generator[Dict[str, Any], None, None]:
    """Iterate over contact records for a user."""
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": "pk = :pk",
        "ExpressionAttributeValues": {":pk": f"OWNER#{user_sub}"},
        "Limit": 500,
    }

    row_count = 0
    while row_count < MAX_EXPORT_ROWS:
        resp = T.contacts.query(**kwargs)
        for item in resp.get("Items", []):
            yield item
            row_count += 1
            if row_count >= MAX_EXPORT_ROWS:
                break

        if "LastEvaluatedKey" not in resp or row_count >= MAX_EXPORT_ROWS:
            break
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]


def _iter_questionnaire_responses(
    questionnaire_id: str,
) -> Generator[Dict[str, Any], None, None]:
    """Iterate over questionnaire response sessions."""
    from app.services.questionnaires_repository import DynamoQuestionnaireRepository
    repo = DynamoQuestionnaireRepository()
    sessions = repo.list_response_sessions(questionnaire_id=questionnaire_id)
    for session in sessions[:MAX_EXPORT_ROWS]:
        yield session


# ─── Row Formatters ─────────────────────────────────────────────

def _ts_to_iso(ts: int) -> str:
    """Convert Unix timestamp to ISO 8601 string."""
    if not ts:
        return ""
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _format_billing_row(item: Dict[str, Any]) -> List[str]:
    ts = int(item.get("created_at", 0))
    amount_cents = int(item.get("amount_cents", 0))
    return [
        _ts_to_iso(ts),
        str(item.get("entry_type", "")),
        f"{amount_cents / 100:.2f}",
        str(item.get("currency", "USD")),
        str(item.get("state", "")),
        str(item.get("reason", "")),
        str(item.get("sk", "").split("#")[-1] if item.get("sk") else ""),
    ]


def _format_contacts_row(item: Dict[str, Any]) -> List[str]:
    tags = item.get("tags", [])
    tag_str = "; ".join(tags) if isinstance(tags, list) else str(tags)
    return [
        str(item.get("name", "")),
        str(item.get("email", "")),
        str(item.get("phone", "")),
        str(item.get("company", "")),
        tag_str,
        str(item.get("is_favorite", False)),
        str(item.get("is_blocked", False)),
        _ts_to_iso(int(item.get("created_at", 0))),
    ]


def _format_questionnaire_row(item: Dict[str, Any]) -> List[str]:
    started = int(item.get("started_at", 0))
    submitted = int(item.get("submitted_at", 0))
    duration = (submitted - started) if submitted and started and submitted >= started else ""
    answers = item.get("answers", {})
    return [
        str(item.get("respondent_id", item.get("user_sub", "anonymous"))),
        _ts_to_iso(started),
        _ts_to_iso(submitted),
        str(item.get("status", "")),
        str(duration),
        str(item.get("version_id", "")),
        json.dumps(answers, default=str) if answers else "",
    ]


# ─── Main Generator ────────────────────────────────────────────

def generate_csv_rows(
    source: str,
    user_sub: str,
    *,
    from_date: Optional[int] = None,
    to_date: Optional[int] = None,
    questionnaire_id: Optional[str] = None,
) -> Generator[str, None, None]:
    """Generate CSV rows as strings for streaming response.

    Yields the header row first, then one string per data row.
    Each string includes the trailing newline.

    Uses csv.writer to properly escape commas, quotes, and newlines
    per RFC 4180.
    """
    buf = io.StringIO()
    writer = csv.writer(buf)

    # Determine columns and iterator
    if source == "billing_ledger":
        columns = BILLING_COLUMNS
        iterator = _iter_billing_entries(user_sub, from_date=from_date, to_date=to_date)
        formatter = _format_billing_row
    elif source == "contacts":
        columns = CONTACTS_COLUMNS
        iterator = _iter_contacts(user_sub)
        formatter = _format_contacts_row
    elif source == "questionnaire_responses":
        if not questionnaire_id:
            raise ValueError("questionnaire_id is required for questionnaire_responses source")
        columns = QUESTIONNAIRE_COLUMNS
        iterator = _iter_questionnaire_responses(questionnaire_id)
        formatter = _format_questionnaire_row
    else:
        raise ValueError(f"Unknown source: {source}")

    # Write UTF-8 BOM for Excel compatibility
    yield "﻿"

    # Write header
    writer.writerow(columns)
    yield buf.getvalue()
    buf.truncate(0)
    buf.seek(0)

    # Write data rows
    for item in iterator:
        try:
            row = formatter(item)
            writer.writerow(row)
            yield buf.getvalue()
            buf.truncate(0)
            buf.seek(0)
        except Exception:
            logger.warning("csv_row_format_error", extra={"source": source})
            continue
```

### 4.2 Backend: Export Router

**New file `app/routers/csv_export.py`:**

```python
"""CSV export endpoint (PLATFORM-009).

Provides streaming CSV download for various data sources.
"""

from __future__ import annotations

import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse

from app.services.csv_export import generate_csv_rows
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui", tags=["export"])

VALID_SOURCES = {"billing_ledger", "contacts", "questionnaire_responses"}


@router.get("/export/csv")
async def export_csv(
    source: str = Query(
        ...,
        description="Data source to export",
        pattern=r"^(billing_ledger|contacts|questionnaire_responses)$",
    ),
    from_date: Optional[int] = Query(
        None,
        description="Unix timestamp start (inclusive)",
        ge=0,
    ),
    to_date: Optional[int] = Query(
        None,
        description="Unix timestamp end (inclusive)",
        ge=0,
    ),
    questionnaire_id: Optional[str] = Query(
        None,
        description="Required for questionnaire_responses source",
        min_length=1,
        max_length=120,
    ),
    ctx=Depends(require_ui_session),
):
    """Stream CSV data for the requested source.

    Returns a streaming response with Content-Type: text/csv and
    Content-Disposition: attachment to trigger browser download.

    The CSV uses UTF-8 encoding with BOM for Excel compatibility.
    Fields containing commas, quotes, or newlines are properly escaped
    per RFC 4180.

    Rate limit: 5 exports per minute per user.
    """
    user_sub = ctx["user_sub"]

    # Validate questionnaire ownership if needed
    if source == "questionnaire_responses":
        if not questionnaire_id:
            raise HTTPException(
                status_code=422,
                detail="questionnaire_id is required for questionnaire_responses source",
            )
        # Verify ownership
        from app.services.questionnaires_repository import DynamoQuestionnaireRepository
        repo = DynamoQuestionnaireRepository()
        q = repo.get_questionnaire(questionnaire_id)
        if not q:
            raise HTTPException(status_code=404, detail="Questionnaire not found")
        if q.get("owner_user_sub") != user_sub:
            raise HTTPException(status_code=403, detail="Not owner of questionnaire")

    # Validate date range
    if from_date and to_date and from_date > to_date:
        raise HTTPException(
            status_code=422,
            detail="from_date must be <= to_date",
        )

    try:
        rows = generate_csv_rows(
            source,
            user_sub,
            from_date=from_date,
            to_date=to_date,
            questionnaire_id=questionnaire_id,
        )
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    filename = f"{source}_{int(time.time())}.csv"
    return StreamingResponse(
        rows,
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-cache, no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )
```

**Register in `app/main.py`:**

```python
from app.routers.csv_export import router as csv_export_router
app.include_router(csv_export_router)
```

### 4.3 Frontend: ExportCsvButton Component

**New file `frontend/src/components/shared/ExportCsvButton.tsx`:**

```typescript
import { Download } from "lucide-react";
import { Button } from "@/components/ui/button";

interface ExportCsvButtonProps {
  /** The data source to export. */
  source: "billing_ledger" | "contacts" | "questionnaire_responses";
  /** Additional query parameters (e.g., from_date, to_date, questionnaire_id). */
  params?: Record<string, string | number>;
  /** Button label. Defaults to "Export CSV". */
  label?: string;
  /** Whether the button is disabled. */
  disabled?: boolean;
}

/**
 * A reusable button that triggers a server-side CSV export download.
 *
 * Opens the export URL in a new tab, which triggers the browser's
 * native download mechanism (Content-Disposition: attachment).
 *
 * Because the endpoint requires authentication (ui_session cookie),
 * we use window.open() instead of an <a href> to ensure cookies
 * are sent with the request.
 */
export function ExportCsvButton({
  source,
  params = {},
  label = "Export CSV",
  disabled = false,
}: ExportCsvButtonProps) {
  const handleExport = () => {
    const searchParams = new URLSearchParams({ source });
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== null && value !== "") {
        searchParams.set(key, String(value));
      }
    }
    // Open in same tab — StreamingResponse with Content-Disposition
    // triggers download without navigating away from the page.
    window.location.href = `/ui/export/csv?${searchParams.toString()}`;
  };

  return (
    <Button
      variant="outline"
      size="sm"
      onClick={handleExport}
      disabled={disabled}
    >
      <Download className="mr-1 h-3.5 w-3.5" />
      {label}
    </Button>
  );
}
```

### 4.4 Frontend: Integration Points

**Billing Ledger (`Ledger.tsx`):**
Replace or supplement the existing client-side export button (line 211) with `ExportCsvButton`:

```typescript
import { ExportCsvButton } from "@/components/shared/ExportCsvButton";

// In the filters bar (line 204-215), replace the existing export button:
<ExportCsvButton
  source="billing_ledger"
  params={{
    ...(startDate ? { from_date: Math.floor(new Date(startDate).getTime() / 1000) } : {}),
    ...(endDate ? { to_date: Math.floor(new Date(endDate).getTime() / 1000) } : {}),
  }}
/>
```

**Contacts page (`ContactsPage.tsx`):**
Add `ExportCsvButton` to the page header area:

```typescript
import { ExportCsvButton } from "@/components/shared/ExportCsvButton";

// In the header:
<ExportCsvButton source="contacts" />
```

**Questionnaire detail (`QuestionnaireBuilderPage.tsx`):**
Add `ExportCsvButton` in the analytics card:

```typescript
import { ExportCsvButton } from "@/components/shared/ExportCsvButton";

// In the analytics card (after line 431):
<ExportCsvButton
  source="questionnaire_responses"
  params={{ questionnaire_id: questionnaireId }}
  label="Export Responses"
/>
```

### 4.5 CSV Column Definitions

| Source | Columns | Notes |
|--------|---------|-------|
| `billing_ledger` | Date, Type, Amount, Currency, Status, Reason, Transaction ID | Amount in dollars (2 decimal places). Date in ISO 8601 UTC. |
| `contacts` | Name, Email, Phone, Company, Tags, Is Favorite, Is Blocked, Created At | Tags are semicolon-separated. |
| `questionnaire_responses` | Respondent ID, Started At, Submitted At, Status, Duration (s), Version, Answers | Answers as JSON string. Duration calculated server-side. |

### 4.6 CSV Formatting Standards

The export follows RFC 4180:
- Fields containing commas, double quotes, or newlines are enclosed in double quotes.
- Double quotes within fields are escaped by doubling (`""` → `""`).
- UTF-8 encoding with BOM (`﻿`) for Excel compatibility.
- Line endings are CRLF (as per RFC 4180, handled by Python's `csv.writer`).
- Empty fields are represented as empty strings (not `null` or `None`).

---

## 5. Data Model

No new DynamoDB tables required. The export reads from existing tables:

| Source | Table | PK Pattern | SK Pattern |
|--------|-------|------------|------------|
| `billing_ledger` | `T.billing` | `USER#{user_sub}` | `LEDGER#{ts}#{uuid}` |
| `contacts` | `T.contacts` | `OWNER#{user_sub}` | Contact SK |
| `questionnaire_responses` | Questionnaires table | Via repository | Via repository |

---

## 6. API Design

### 6.1 `GET /ui/export/csv`

**Method**: GET
**Path**: `/ui/export/csv`
**Auth**: `require_ui_session` (cookie-based)
**Description**: Stream CSV data for the requested source. Triggers browser download.

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source` | string | Yes | One of: `billing_ledger`, `contacts`, `questionnaire_responses` |
| `from_date` | int | No | Unix timestamp (inclusive) start of date range |
| `to_date` | int | No | Unix timestamp (inclusive) end of date range |
| `questionnaire_id` | string | Conditional | Required when `source=questionnaire_responses` |

**Response (200):**
```
Content-Type: text/csv; charset=utf-8
Content-Disposition: attachment; filename="billing_ledger_1748380800.csv"
Cache-Control: no-cache, no-store
X-Content-Type-Options: nosniff

Date,Type,Amount,Currency,Status,Reason,Transaction ID
2026-05-20 14:30:00 UTC,tip_debit,5.00,USD,settled,Tip sent,abc123
2026-05-19 10:00:00 UTC,deposit_credit,100.00,USD,settled,Wallet deposit,def456
```

**Error Responses:**

| Status | Condition | Body |
|--------|-----------|------|
| 401 | Not authenticated | `{"detail": "Not authenticated"}` |
| 403 | Not owner of questionnaire | `{"detail": "Not owner of questionnaire"}` |
| 404 | Questionnaire not found | `{"detail": "Questionnaire not found"}` |
| 422 | Invalid source | `{"detail": [{"loc": ["query", "source"], ...}]}` |
| 422 | Missing questionnaire_id | `{"detail": "questionnaire_id is required for questionnaire_responses source"}` |
| 422 | from_date > to_date | `{"detail": "from_date must be <= to_date"}` |

**Rate Limit**: 5 exports per minute per user (exports can be expensive DynamoDB queries).

---

## 7. Frontend Implementation

### 7.1 Component Hierarchy

```
BillingPage.tsx
  └── Ledger.tsx
       └── ExportCsvButton (source="billing_ledger", params={from_date, to_date})

ContactsPage.tsx
  └── ExportCsvButton (source="contacts")

QuestionnaireBuilderPage.tsx
  └── Analytics Card
       └── ExportCsvButton (source="questionnaire_responses", params={questionnaire_id})
```

### 7.2 Download Mechanism

The `ExportCsvButton` uses `window.location.href` assignment to trigger the download. This approach:
- Sends cookies automatically (required for `require_ui_session` auth).
- The browser's download manager handles the file save dialog.
- The page does not navigate away because the response has `Content-Disposition: attachment`.
- No JavaScript download library needed.

Alternative considered and rejected: `fetch()` + `Blob` + `URL.createObjectURL()`. This approach buffers the entire response in memory before triggering the download, defeating the purpose of server-side streaming.

### 7.3 Date Range Integration

The Ledger component already has `startDate` and `endDate` state variables (used for client-side filtering). The `ExportCsvButton` converts these to Unix timestamps for the `from_date` and `to_date` query parameters.

---

## 8. Testing Plan

### 8.1 Unit Tests (pytest)

**File**: `tests/test_csv_export.py`

| # | Test Name | Description | Assertion |
|---|-----------|-------------|-----------|
| 1 | `test_billing_csv_returns_text_csv` | GET `/ui/export/csv?source=billing_ledger` | Response content-type is `text/csv` |
| 2 | `test_billing_csv_header_row` | GET billing CSV | First line is `Date,Type,Amount,Currency,Status,Reason,Transaction ID` |
| 3 | `test_billing_csv_data_rows` | Seed 3 billing entries, GET CSV | CSV has 3 data rows (+ header) |
| 4 | `test_billing_csv_date_filter` | Seed entries at t=100, t=200, t=300; GET with `from_date=150&to_date=250` | Only entry at t=200 included |
| 5 | `test_billing_csv_amount_format` | Seed entry with amount_cents=1050 | CSV amount field is `10.50` |
| 6 | `test_contacts_csv_returns_fields` | Seed contacts, GET contacts CSV | All column headers present |
| 7 | `test_contacts_csv_tags_semicolon` | Seed contact with tags `["vip", "creator"]` | Tags field is `vip; creator` |
| 8 | `test_questionnaire_csv_requires_id` | GET without `questionnaire_id` | 422 |
| 9 | `test_questionnaire_csv_ownership` | GET as non-owner | 403 |
| 10 | `test_invalid_source_returns_422` | GET with `source=invalid` | 422 |
| 11 | `test_csv_escapes_commas` | Seed entry with reason containing comma | Field is double-quoted in CSV |
| 12 | `test_csv_escapes_quotes` | Seed entry with reason containing double quote | Double quotes are doubled |
| 13 | `test_content_disposition_header` | GET billing CSV | `Content-Disposition` starts with `attachment; filename=` |
| 14 | `test_from_date_gt_to_date_returns_422` | GET with from_date > to_date | 422 |
| 15 | `test_csv_utf8_bom` | GET billing CSV | First bytes are UTF-8 BOM (`\xef\xbb\xbf`) |

```python
# Example test
def test_billing_csv_date_filter(auth_client, alice_session, seed_billing):
    """Date range filter excludes out-of-range entries."""
    # seed_billing creates entries at ts=100, 200, 300
    resp = auth_client.get(
        "/ui/export/csv",
        params={"source": "billing_ledger", "from_date": 150, "to_date": 250},
        cookies=alice_session["cookies"],
    )
    assert resp.status_code == 200
    lines = resp.text.strip().split("\n")
    assert len(lines) == 2  # header + 1 data row
    assert "200" not in lines[0]  # header doesn't have timestamp
```

### 8.2 E2E Tests

**File**: `frontend/e2e/csv-export.spec.ts`

| # | Section | Test Name | Assertion |
|---|---------|-----------|-----------|
| 1 | API | GET billing_ledger returns CSV | 200; content-type contains `text/csv`; body starts with BOM + header |
| 2 | API | GET contacts returns CSV | 200; content-type contains `text/csv` |
| 3 | API | GET with date range filters | Entries outside range not in response body |
| 4 | API | GET with invalid source returns 422 | 422 status code |
| 5 | API | GET questionnaire_responses without ID returns 422 | 422 status |
| 6 | API | GET questionnaire_responses as non-owner returns 403 | 403 status |
| 7 | UI | Export CSV button visible on billing page | Button with "Export CSV" text exists |
| 8 | UI | Export CSV button visible on contacts page | Button with "Export CSV" text exists |

```typescript
test.describe("PLATFORM-009: CSV Export — API", () => {
  test("GET billing_ledger returns CSV with correct headers", async ({ page }) => {
    await injectAuth(page, "alice");

    const resp = await page.request.get("/ui/export/csv", {
      params: { source: "billing_ledger" },
    });
    expect(resp.status()).toBe(200);
    expect(resp.headers()["content-type"]).toContain("text/csv");

    const body = await resp.text();
    expect(body).toContain("Date,Type,Amount,Currency,Status,Reason,Transaction ID");
  });

  test("GET with invalid source returns 422", async ({ page }) => {
    await injectAuth(page, "alice");
    const resp = await page.request.get("/ui/export/csv", {
      params: { source: "invalid_source" },
    });
    expect(resp.status()).toBe(422);
  });
});
```

---

## 9. Security Considerations

### 9.1 Authentication and Authorization

- The export endpoint uses `require_ui_session` -- only authenticated users can export data.
- For `questionnaire_responses`, ownership is verified: only the questionnaire owner can export responses.
- For `billing_ledger` and `contacts`, the endpoint only exports the authenticated user's own data (PK includes `user_sub`).
- CSRF is not enforced on GET requests (by design -- GET requests should not have side effects).

### 9.2 Data Exposure Prevention

- Each data source query is scoped to the authenticated user's partition key.
- There is no `admin_user_sub` parameter -- admins cannot export other users' data via this endpoint.
- The `MAX_EXPORT_ROWS = 50_000` limit prevents unbounded queries.

### 9.3 CSV Injection (Formula Injection)

CSV files opened in Excel can execute formulas if a cell starts with `=`, `+`, `-`, or `@`. This is a known attack vector ("CSV injection" or "DDE injection").

**Mitigation**: Sanitize all user-provided string fields by prepending a single quote (`'`) if they start with `=`, `+`, `-`, `@`, `\t`, or `\r`:

```python
def _sanitize_csv_field(value: str) -> str:
    """Prevent CSV formula injection by prefixing dangerous characters."""
    if value and value[0] in ("=", "+", "-", "@", "\t", "\r"):
        return f"'{value}"
    return value
```

Apply this sanitization in each row formatter before passing values to `csv.writer`.

### 9.4 Content-Type and Security Headers

- `Content-Type: text/csv; charset=utf-8` -- prevents browser from interpreting as HTML.
- `X-Content-Type-Options: nosniff` -- prevents MIME-type sniffing.
- `Cache-Control: no-cache, no-store` -- prevents caching of exported data (may contain PII).

### 9.5 Rate Limiting

Export queries can be expensive (full table scans with pagination). Rate limit to 5 exports per minute per user. Implemented via the existing rate limiting middleware or a simple in-memory counter.

---

## 10. Performance Considerations

### 10.1 Streaming vs. Buffering

The endpoint uses `StreamingResponse` to send CSV rows as they are fetched from DynamoDB. This means:
- **Time to first byte**: ~100ms (DynamoDB query + first row format).
- **Memory usage**: O(1) per row. The entire dataset is never held in memory.
- **Total time**: Proportional to dataset size. A 10,000-row export takes ~10 seconds (1,000 rows/sec with DynamoDB pagination).

### 10.2 DynamoDB Read Costs

| Source | Query Pattern | RCU per Page | Expected Pages | Total RCU |
|--------|--------------|-------------|----------------|-----------|
| `billing_ledger` | Query on PK, Limit=500 | 125 | 2 (1000 entries) | 250 |
| `contacts` | Query on PK, Limit=500 | 100 | 1 (200 contacts) | 100 |
| `questionnaire_responses` | Repository scan | 200 | 1 | 200 |

Cost per export: ~$0.0001 (negligible at current scale).

### 10.3 Timeout Considerations

FastAPI's default request timeout is 60 seconds. For large exports (50,000 rows), the streaming response may take 30-50 seconds. The `StreamingResponse` keeps the connection alive by sending data incrementally. No special timeout configuration is needed unless exports exceed 60 seconds.

### 10.4 Concurrent Export Throttling

If many users export simultaneously, DynamoDB on-demand capacity handles the load. However, very large concurrent exports could spike RCU. The rate limit of 5/minute/user mitigates this.

---

## 11. Migration / Rollout Plan

### 11.1 Feature Flag

No feature flag needed. The endpoint is additive and the frontend change is a new button component. The existing client-side CSV export in Ledger.tsx can coexist with the server-side export during transition.

### 11.2 Backward Compatibility

- The existing client-side `exportCsv()` function in `Ledger.tsx` can be kept as a fallback (or removed).
- The new `ExportCsvButton` replaces the existing export button. If the backend is not yet deployed, `window.location.href` will get a 404, which is handled gracefully by the browser (navigation to error page). To prevent this, the button can be conditionally rendered based on a version check.

### 11.3 Rollout Steps

1. Deploy backend: `csv_export.py` service + `csv_export` router + register in `main.py`.
2. Deploy frontend: `ExportCsvButton` component + integration in Ledger, ContactsPage, QuestionnaireBuilderPage.
3. Remove the old `exportCsv()` function from `Ledger.tsx` (optional, can be done in a follow-up).

---

## 12. Acceptance Criteria

1. `GET /ui/export/csv?source=billing_ledger` returns a streaming CSV download with billing history.
2. `GET /ui/export/csv?source=contacts` returns a CSV download with contact data.
3. `GET /ui/export/csv?source=questionnaire_responses&questionnaire_id=X` returns response data as CSV.
4. Date range filtering via `from_date` and `to_date` query parameters works for billing_ledger source.
5. CSV output properly escapes special characters (commas, quotes, newlines) per RFC 4180.
6. CSV output includes UTF-8 BOM for Excel compatibility.
7. CSV fields starting with `=`, `+`, `-`, `@` are sanitized to prevent formula injection.
8. "Export CSV" buttons appear on the Billing, Contacts, and Questionnaire analytics pages.
9. The `Content-Disposition` header triggers a file download in the browser (not inline display).
10. The endpoint streams data (first byte within 200ms) and does not buffer the entire dataset in memory.
11. Questionnaire response export verifies ownership and returns 403 for non-owners.
12. The maximum export size is capped at 50,000 rows.

---

## 13. Dependencies

### 13.1 Internal Dependencies

- Billing table (`T.billing`) -- exists.
- Contacts table (`T.contacts`) -- exists.
- Questionnaire repository (`DynamoQuestionnaireRepository`) -- exists.
- `require_ui_session` auth dependency -- exists.
- `billing_shared.user_pk()` -- exists.

### 13.2 External Dependencies

None. Python's `csv` module is in the standard library.

### 13.3 Related Tickets

- **PRIVACY-001**: GDPR compliance export (JSON archive). Complementary but different: GDPR export is a full-account archive; CSV export is per-source ad-hoc download.
- **ANALYTICS-001**: Creator analytics dashboard. Analytics CSV export can be added as a future source.

---

## 14. Open Questions / Risks

1. **Contacts table key schema**: The contacts table PK pattern needs verification. The implementation assumes `PK = OWNER#{user_sub}`, but it may be different. Verify before implementation.

2. **Questionnaire ownership field**: The implementation assumes the questionnaire record has `owner_user_sub`. Verify the actual field name in the repository.

3. **Large export timeout**: A 50,000-row export may take 30-50 seconds. If the platform's reverse proxy (nginx/ALB) has a 30-second timeout, the streaming response may be cut off. Verify proxy timeout configuration.

4. **Excel date format**: Excel interprets ISO 8601 dates as text, not dates. Consider using Excel-native date format (`MM/DD/YYYY HH:MM:SS`) as an option.

5. **Concurrent export abuse**: A malicious user could open 5 export tabs per minute to generate load. The rate limit mitigates this, but consider adding a "pending export" state to prevent concurrent exports.

---

## 15. Files to Create

| File | Purpose |
|------|---------|
| `app/services/csv_export.py` | CSV generation service with DynamoDB pagination and streaming |
| `app/routers/csv_export.py` | `GET /ui/export/csv` streaming endpoint |
| `frontend/src/components/shared/ExportCsvButton.tsx` | Reusable export button component |
| `frontend/e2e/csv-export.spec.ts` | E2E tests |
| `tests/test_csv_export.py` | Pytest unit tests |

## 16. Files to Modify

| File | Change |
|------|--------|
| `app/main.py` | Register `csv_export` router with `app.include_router(csv_export_router)` |
| `frontend/src/pages/billing/Ledger.tsx` | Replace client-side export button (line 211) with `ExportCsvButton` |
| `frontend/src/pages/contacts/ContactsPage.tsx` | Add `ExportCsvButton` to page header |
| `frontend/src/pages/questionnaires/QuestionnaireBuilderPage.tsx` | Add `ExportCsvButton` in analytics card |

---

## Appendix: Codebase Citations

| Claim | File | Line(s) | Status |
|-------|------|---------|--------|
| GDPR compliance export | `app/routers/privacy.py` | 50-79 | VERIFIED: inline JSON archive processing |
| GDPR rate limit check | `app/routers/privacy.py` | 60 | VERIFIED: `has_recent_export` |
| Client-side CSV in Ledger | `frontend/src/pages/billing/Ledger.tsx` | 154-168 | VERIFIED: `exportCsv()` function |
| CSV header in Ledger | `frontend/src/pages/billing/Ledger.tsx` | 155 | VERIFIED: `"Date,Type,Amount,Status,Reason"` |
| Blob creation with text/csv | `frontend/src/pages/billing/Ledger.tsx` | 161 | VERIFIED |
| Export CSV button in Ledger | `frontend/src/pages/billing/Ledger.tsx` | 211 | VERIFIED: disabled when sorted.length === 0 |
| No text/csv in any router response | all routers | -- | VERIFIED (grep for "text/csv" returns 0 results in app/routers/) |
| _csv_items is env var parsing | `app/routers/browser_ssh_terminal.py` | 389 | VERIFIED (not data export) |
| No export in contacts page | `frontend/src/pages/contacts/ContactsPage.tsx` | all | VERIFIED (grep for "export" returns only the default export) |
| Billing table handle | `app/core/tables.py` | 120 | VERIFIED: `billing=ddb.Table(S.billing_table_name)` |
| Contacts table config | `app/core/settings.py` | 434 | VERIFIED: `contacts_table_name` |
| Questionnaire response sessions | `app/routers/questionnaires.py` | 151 | VERIFIED: `REPO.list_response_sessions` |
