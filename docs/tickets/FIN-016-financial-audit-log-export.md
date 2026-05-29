# FIN-016: Financial Audit Log Export

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-29  
**Priority**: Medium  
**Estimated effort**: 7-9 days  
**Dependencies**: Billing ledger (`billing_shared.py`), admin auth (`auth/deps.py`), financial rollups (FIN-013)

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

Ledger entries stored in `billing` table:
- `pk`: `USER#{user_id}`, `sk`: `LEDGER#{timestamp}#{entry_id}`
- Fields: `entry_type`, `amount_cents`, `currency`, `description`, `reason`, `created_at`, `provider`
- Key functions: `new_ledger_entry(...)`, `settle_or_reverse_ledger(...)`

### 2.2 Existing Admin Payout Router (`app/routers/admin_payouts.py`)

The admin payouts router provides payout listing and approval but no export functionality.

### 2.3 FIN-013 Financial Rollups

FIN-013 introduces daily rollup data and a `GSI_LEDGER_DATE` on the billing table, enabling date-range queries across all users. This GSI is a prerequisite for efficient audit exports.

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

### 3.2 Audit Export Service: `app/services/audit_export.py`

```python
"""Financial audit log export service (FIN-016).

Generates CSV and PDF exports of billing ledger data with
audit-grade formatting, checksums, and scheduled delivery.
"""

QUICKBOOKS_COLUMNS = [
    "Date", "Transaction Type", "Num", "Name",
    "Amount", "Currency", "Description", "Status",
]

XERO_COLUMNS = [
    "Date", "Amount", "Reference", "Description",
    "Account Code", "Tax Rate",
]

def export_ledger_csv(
    *, start_date: str, end_date: str,
    user_id: str = None, entry_type: str = None,
    amount_min: int = None, amount_max: int = None,
    column_format: str = "default",  # "default", "quickbooks", "xero"
    admin_sub: str,
) -> Dict[str, Any]:
    """Generate CSV export of ledger entries.

    Returns {export_id, row_count, sha256_hash, download_url}.
    Writes export record and file to S3.
    """
    ...

def export_ledger_pdf(
    *, start_date: str, end_date: str,
    user_id: str = None, entry_type: str = None,
    amount_min: int = None, amount_max: int = None,
    admin_sub: str,
) -> Dict[str, Any]:
    """Generate audit-grade PDF export.

    Includes sequential numbering, page subtotals, grand total,
    SHA-256 checksum on cover page, and filter summary.
    """
    ...

def get_export(export_id: str) -> Dict[str, Any]:
    """Get export record by ID."""
    ...

def list_exports(
    *, limit: int = 50, cursor: str = None
) -> Dict[str, Any]:
    """List export history."""
    ...

def download_export(export_id: str) -> bytes:
    """Download export file content from S3."""
    ...

def create_schedule(
    *, frequency: str, format: str, template: str,
    filters: Dict[str, Any], recipients: List[str],
    admin_sub: str,
) -> Dict[str, Any]:
    """Create a scheduled report."""
    ...

def list_schedules() -> List[Dict[str, Any]]:
    """List all scheduled reports."""
    ...

def update_schedule(
    schedule_id: str, *, admin_sub: str, **updates
) -> Dict[str, Any]:
    """Update a scheduled report."""
    ...

def delete_schedule(schedule_id: str) -> bool:
    """Delete a scheduled report."""
    ...

def run_scheduled_exports() -> List[Dict[str, Any]]:
    """Execute all due scheduled exports.

    Called by background task. Generates export, emails to recipients,
    updates next_run_at.
    """
    ...
```

### 3.3 Router: `app/routers/admin_audit_export.py`

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

### 3.4 Pydantic Models (`app/models.py`)

```python
class AuditExportRequest(BaseModel):
    start_date: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    end_date: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    user_id: Optional[str] = None
    entry_type: Optional[str] = None
    amount_min: Optional[int] = Field(default=None, ge=0)
    amount_max: Optional[int] = Field(default=None, ge=0)
    column_format: str = Field(default="default", pattern=r"^(default|quickbooks|xero)$")

class AuditExportOut(BaseModel):
    export_id: str
    format: str
    filters: Dict[str, Any]
    row_count: int
    file_size_bytes: int
    sha256_hash: str
    status: str
    created_at: int
    expires_at: int

class ScheduleCreate(BaseModel):
    frequency: str = Field(pattern=r"^(daily|weekly|monthly)$")
    format: str = Field(default="csv", pattern=r"^(csv|pdf)$")
    template: str = Field(default="full", pattern=r"^(full|summary|by_type)$")
    filters: Dict[str, Any] = Field(default_factory=dict)
    recipients: List[str] = Field(min_length=1)

class ScheduleUpdate(BaseModel):
    frequency: Optional[str] = Field(default=None, pattern=r"^(daily|weekly|monthly)$")
    format: Optional[str] = Field(default=None, pattern=r"^(csv|pdf)$")
    template: Optional[str] = Field(default=None, pattern=r"^(full|summary|by_type)$")
    filters: Optional[Dict[str, Any]] = None
    recipients: Optional[List[str]] = None
    active: Optional[bool] = None

class ScheduleOut(BaseModel):
    schedule_id: str
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

### 3.5 CSV Format — Audit Grade

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

### 3.6 Frontend: Audit Export Page

**Route**: `/admin/audit-export` in `frontend/src/App.tsx`  
**Page**: `frontend/src/pages/admin/audit/AuditExportPage.tsx`

```tsx
<Tabs defaultValue="export">
  <TabsList>
    <TabsTrigger value="export">Export</TabsTrigger>
    <TabsTrigger value="history">History</TabsTrigger>
    <TabsTrigger value="schedules">Schedules</TabsTrigger>
  </TabsList>

  <TabsContent value="export">
    <Card>
      <CardHeader><CardTitle>Generate Export</CardTitle></CardHeader>
      <CardContent>
        <ExportForm onSubmit={handleExport} />
        {/* Date range, user ID, entry type, amount range, format, column mapping */}
      </CardContent>
    </Card>
  </TabsContent>

  <TabsContent value="history">
    <ExportHistoryTable exports={exports} onDownload={handleDownload} />
  </TabsContent>

  <TabsContent value="schedules">
    <ScheduleList schedules={schedules} onCreate={...} onEdit={...} onDelete={...} />
  </TabsContent>
</Tabs>
```

### 3.7 Frontend API (`frontend/src/api/endpoints/adminAuditExport.ts`)

```typescript
export const exportCsv = (data: AuditExportRequest) =>
  client.post("/v1/admin/audit/export/csv", data);

export const exportPdf = (data: AuditExportRequest) =>
  client.post("/v1/admin/audit/export/pdf", data);

export const listExports = (params?: { limit?: number; cursor?: string }) =>
  client.get("/v1/admin/audit/exports", { params });

export const getExport = (exportId: string) =>
  client.get(`/v1/admin/audit/exports/${exportId}`);

export const downloadExport = (exportId: string) =>
  client.get(`/v1/admin/audit/exports/${exportId}/download`, { responseType: "blob" });

export const createSchedule = (data: ScheduleCreate) =>
  client.post("/v1/admin/audit/schedules", data);

export const listSchedules = () =>
  client.get("/v1/admin/audit/schedules");

export const updateSchedule = (scheduleId: string, data: ScheduleUpdate) =>
  client.patch(`/v1/admin/audit/schedules/${scheduleId}`, data);

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

14. **`frontend/e2e/admin-audit-export.spec.ts`**: 14 tests across 4 sections.

---

## 5. E2E Test Plan

**Test file**: `frontend/e2e/admin-audit-export.spec.ts`

**Setup (beforeAll)**:
- Inject auth for Root, Alice, Charlie (admin)
- Seed billing ledger with 10 entries across different types and providers

**Section 535: CSV Export API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | `Admin generates CSV export` | POST `/v1/admin/audit/export/csv` with date range as Root -> 200; `export_id` present, `status: "completed"`, `row_count > 0` |
| 2 | `CSV export respects filters` | POST with `entry_type: "tip_debit"` -> 200; `row_count` matches seeded tip entries |
| 3 | `Export includes SHA-256 checksum` | Response has `sha256_hash` (64-char hex string) |
| 4 | `Non-admin cannot export` | POST as Alice -> 403 |

**Section 536: PDF Export & Download API (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 5 | `Admin generates PDF export` | POST `/v1/admin/audit/export/pdf` with date range -> 200; `format: "pdf"`, `file_size_bytes > 0` |
| 6 | `Admin downloads export file` | GET `/v1/admin/audit/exports/{id}/download` -> 200; response body is non-empty |
| 7 | `Download of non-existent export returns 404` | GET with bogus ID -> 404 |

**Section 537: Export History API (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 8 | `Admin lists export history` | GET `/v1/admin/audit/exports` as Root -> 200; array includes exports from sections above |
| 9 | `Export detail includes filter metadata` | GET `/v1/admin/audit/exports/{id}` -> 200; `filters` object has `start_date`, `end_date` |
| 10 | `History sorted by created_at descending` | First item's `created_at >= second item's created_at` |

**Section 538: Scheduled Reports API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 11 | `Admin creates scheduled report` | POST `/v1/admin/audit/schedules` with `{frequency: "weekly", format: "csv", recipients: ["admin@test.local"]}` -> 201; `schedule_id` present |
| 12 | `Admin lists schedules` | GET `/v1/admin/audit/schedules` -> 200; includes created schedule |
| 13 | `Admin updates schedule frequency` | PATCH `/v1/admin/audit/schedules/{id}` with `{frequency: "monthly"}` -> 200; re-GET shows `frequency: "monthly"` |
| 14 | `Admin deletes schedule` | DELETE `/v1/admin/audit/schedules/{id}` -> 200; re-list excludes it |

---

## 6. Security Considerations

### 6.1 Role-Based Access
- All export endpoints require ADMIN role
- Export data contains sensitive financial information (user IDs, amounts, providers)

### 6.2 Tamper Evidence
- SHA-256 hash computed at export time and stored in metadata
- Verify hash on download to detect corruption
- Export records are immutable (cannot be modified after creation)

### 6.3 Data Retention
- Export files stored in S3 with 30-day expiry
- Export metadata retained indefinitely for audit trail
- Scheduled report emails should not contain sensitive data inline — link to download

### 6.4 Export Rate Limiting
- Limit to 5 exports per hour per admin to prevent abuse
- Large exports (>100K rows) processed asynchronously

### 6.5 PII Considerations
- User IDs in exports are internal identifiers (not email addresses)
- Admins accessing exports must have signed data handling agreements

---

## 7. Files to Create

| File | Purpose |
|------|---------|
| `app/services/audit_export.py` | CSV/PDF export generation, schedule management |
| `app/routers/admin_audit_export.py` | Admin audit export API (9 endpoints) |
| `frontend/src/api/endpoints/adminAuditExport.ts` | API wrappers |
| `frontend/src/pages/admin/audit/AuditExportPage.tsx` | Export page |
| `frontend/e2e/admin-audit-export.spec.ts` | E2E tests (14 tests, sections 535-538) |

## 8. Files to Modify

| File | Change |
|------|--------|
| `app/models.py` | Add audit export Pydantic models |
| `app/main.py` | Register `admin_audit_export_router` |
| `app/core/settings.py` | Add `audit_exports_table_name` |
| `app/core/tables.py` | Add `audit_exports` table handle |
| `scripts/local-ddb-init.py` | Add `audit_exports` table |
| `frontend/src/api/types.ts` | Add audit export TypeScript types |
| `frontend/src/App.tsx` | Add `/admin/audit-export` route |
| `frontend/src/components/layout/Sidebar.tsx` | Add "Audit Export" admin nav link |

## 9. Acceptance Criteria

1. CSV export generates valid CSV with sequential row numbering and SHA-256 checksum
2. PDF export produces formatted document with subtotals and grand total
3. Exports filtered by date range, user ID, entry type, and amount range
4. QuickBooks and Xero column format options available for CSV
5. Export history tracks all exports with filter metadata and checksums
6. Previous exports downloadable for 30 days
7. Scheduled reports can be created, listed, updated, and deleted
8. Non-admin users receive 403 on all endpoints
9. All 14 E2E tests pass in `frontend/e2e/admin-audit-export.spec.ts`
