# FIN-017: Bulk Payout/Refund Tools

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-29  
**Priority**: Medium  
**Estimated effort**: 8-10 days  
**Dependencies**: Creator payouts (`creator_payouts.py`), admin payouts router (`admin_payouts.py`), billing ledger (`billing_shared.py`), admin auth (`auth/deps.py`)

---

## 1. Overview & Motivation

### The Gap

The platform supports creator payouts through `creator_payouts.py` and admin management through `admin_payouts.py`. However, all payout approvals and refund processing happen one at a time. When 50 creators request payouts in a single day, an admin must click "Approve" 50 times. There is no:

- Bulk payout approval (select multiple pending payouts and approve all)
- Bulk refund processing (approve or reject multiple refund requests)
- CSV upload for batch operations (import a list of payouts/refunds)
- Progress tracking for batch operations
- Dry-run mode (preview results before executing)
- Undo window for batch operations

With the platform growing, one-at-a-time processing is a bottleneck that wastes admin time and delays creator payouts.

### Why This Is Needed

1. **Admin efficiency**: Processing 50 payouts individually takes 15-20 minutes of clicking. Bulk approval reduces this to a single action with a confirmation step.

2. **Creator satisfaction**: Delayed payouts frustrate creators. Bulk processing enables same-day payout batches instead of multi-day queues.

3. **Refund management**: When a payment provider outage causes incorrect charges, dozens of refund requests may arrive simultaneously. Bulk refund tools handle this gracefully.

4. **CSV import**: Finance teams often prepare payout batches in spreadsheets before processing. CSV upload eliminates re-entry.

5. **Safety**: Dry-run mode prevents costly mistakes by showing exactly what will happen before committing. The undo window provides a safety net for accidental bulk actions.

6. **Auditability**: Batch operations are tracked as a single unit with full details — who initiated, what was included, what succeeded/failed.

### User Stories

- As a **platform admin**, I want to select multiple pending payouts and approve them all at once so I can process the daily payout queue in minutes.
- As a **platform admin**, I want to bulk-reject refund requests with a shared reason so I can clear illegitimate requests quickly.
- As a **platform admin**, I want to upload a CSV of payout amounts and user IDs so I can process externally-prepared batches.
- As a **platform admin**, I want dry-run mode to preview a bulk operation before executing so I can catch errors.
- As a **platform admin**, I want an undo window after batch execution so I can reverse accidental approvals.

### Architecture After This Change

```
Bulk Operations System (/admin/bulk-ops)
│
├── Payout Batch
│   ├── Select from pending payouts queue
│   ├── Or upload CSV (user_id, amount_cents, method)
│   ├── Dry-run preview (show what will happen)
│   ├── Execute batch
│   ├── Progress bar (X of Y processed)
│   └── Results summary (succeeded, failed, reasons)
│
├── Refund Batch
│   ├── Select from pending refund requests
│   ├── Bulk approve or bulk reject with reason
│   ├── Dry-run preview
│   ├── Execute batch
│   └── Results summary
│
├── Batch History
│   ├── All batch operations log
│   ├── Batch detail (items, statuses, errors)
│   └── Undo button (within undo window)
│
└── Progress Tracking
    ├── Real-time progress for running batches
    ├── Per-item status (success/failure/skipped)
    └── Failure details with retry option
```

### Data Flow — Bulk Payout Approval

```
Admin                              Backend                              Payment
  │                                   │                                   │
  │── POST /bulk-ops/payouts/dry-run  │                                   │
  │   { payout_ids: [...] }           │                                   │
  │                                   │── validate each payout ──>        │
  │<── 200 { preview: [               │                                   │
  │     {id, user, amount, valid}     │                                   │
  │     ...                           │                                   │
  │   ], total, valid_count }         │                                   │
  │                                   │                                   │
  │── POST /bulk-ops/payouts/execute  │                                   │
  │   { payout_ids: [...] }           │                                   │
  │                                   │── approve_payout(id1) ───────────>│
  │<── 200 { batch_id, status:        │── approve_payout(id2) ───────────>│
  │   "processing" }                  │── approve_payout(id3) ───────────>│
  │                                   │                                   │
  │── GET /bulk-ops/{batch_id}        │                                   │
  │                                   │                                   │
  │<── 200 { processed: 3/5,          │                                   │
  │   succeeded: 2, failed: 1,       │                                   │
  │   undo_expires_at: ... }          │                                   │
```

---

## 2. Current State Analysis

### 2.1 Creator Payouts (`app/services/creator_payouts.py`)

Existing one-at-a-time functions:
- `request_payout(user_id, amount_cents, method, notes)`: Creates payout request
- `approve_payout(payout_id, admin_user_id)`: Approves a single payout
- `reject_payout(payout_id, admin_user_id, reason)`: Rejects a single payout
- `complete_payout(payout_id)`: Marks payout as completed
- `list_payouts_admin(status, limit, cursor)`: Lists payouts for admin review

### 2.2 Admin Payouts Router (`app/routers/admin_payouts.py`)

Existing endpoints:
- `GET /payouts`: List payout queue
- `GET /payouts/stats`: Payout queue stats
- `POST /payouts/{id}/approve`: Approve single payout
- `POST /payouts/{id}/reject`: Reject single payout
- `POST /payouts/{id}/complete`: Complete single payout

### 2.3 Billing Ledger (`app/services/billing_shared.py`)

- `new_ledger_entry(...)`: Creates ledger entries for payouts
- `settle_or_reverse_ledger(...)`: Reverses ledger entries (used for undo)

### 2.4 Gaps

1. No bulk approval/rejection endpoint
2. No CSV upload for batch import
3. No dry-run/preview mode
4. No batch progress tracking
5. No undo window for batch operations
6. No batch history log
7. No refund batch processing

---

## 3. Technical Design

### 3.1 Batch Operations Table: `bulk_operations`

**Table definition** in `scripts/local-ddb-init.py`:

```python
TableDef(
    name="bulk_operations",
    pk="pk", sk="sk",
    gsis=[
        GsiDef("GSI1", "GSI1PK", "GSI1SK"),
    ],
    attr_types={"GSI1SK": "N"},
)
```

**Batch record row**:

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `BATCH#{batch_id}` |
| `sk` | S | `META` |
| `GSI1PK` | S | `BATCHES#ALL` |
| `GSI1SK` | N | `created_at` |
| `batch_id` | S | Unique batch ID |
| `batch_type` | S | `"payout_approve"`, `"payout_reject"`, `"refund_approve"`, `"refund_reject"` |
| `admin_sub` | S | Admin who initiated |
| `total_items` | N | Total items in batch |
| `processed` | N | Items processed so far |
| `succeeded` | N | Items that succeeded |
| `failed` | N | Items that failed |
| `skipped` | N | Items skipped (already processed, invalid) |
| `status` | S | `"pending"`, `"processing"`, `"completed"`, `"undone"` |
| `undo_expires_at` | N | Unix timestamp when undo window closes |
| `undone_at` | N | When batch was undone (null if not undone) |
| `created_at` | N | When batch was created |
| `completed_at` | N | When batch finished processing |

**Batch item rows** (one per item in the batch):

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `BATCH#{batch_id}` |
| `sk` | S | `ITEM#{item_id}` |
| `item_id` | S | Payout ID or refund ID |
| `user_id` | S | User associated with this item |
| `amount_cents` | N | Amount |
| `item_status` | S | `"pending"`, `"succeeded"`, `"failed"`, `"skipped"`, `"undone"` |
| `error_message` | S | Error details if failed |
| `processed_at` | N | When this item was processed |

### 3.2 Bulk Operations Service: `app/services/bulk_operations.py`

```python
"""Bulk payout and refund processing (FIN-017).

Provides batch approve/reject for payouts and refunds
with dry-run preview, progress tracking, and undo window.
"""

DEFAULT_UNDO_WINDOW_SECONDS = 300  # 5 minutes

def dry_run_payouts(
    *, payout_ids: List[str], action: str, admin_sub: str,
) -> Dict[str, Any]:
    """Preview a bulk payout operation.

    Validates each payout: exists, correct status, sufficient balance.
    Returns preview with per-item validity and summary.
    """
    ...

def execute_payout_batch(
    *, payout_ids: List[str], action: str, admin_sub: str,
    reason: str = "", undo_window_seconds: int = DEFAULT_UNDO_WINDOW_SECONDS,
) -> Dict[str, Any]:
    """Execute a bulk payout approve/reject.

    Creates batch record, processes each item, tracks progress.
    Returns {batch_id, status, total_items}.
    """
    ...

def dry_run_refunds(
    *, refund_ids: List[str], action: str, admin_sub: str,
) -> Dict[str, Any]:
    """Preview a bulk refund operation."""
    ...

def execute_refund_batch(
    *, refund_ids: List[str], action: str, admin_sub: str,
    reason: str = "", undo_window_seconds: int = DEFAULT_UNDO_WINDOW_SECONDS,
) -> Dict[str, Any]:
    """Execute a bulk refund approve/reject."""
    ...

def import_csv_payouts(
    *, csv_content: str, admin_sub: str,
) -> Dict[str, Any]:
    """Parse CSV and create payout requests in bulk.

    Expected columns: user_id, amount_cents, method, notes
    Returns {parsed_count, valid_count, errors: [{row, error}]}.
    """
    ...

def get_batch(batch_id: str) -> Dict[str, Any]:
    """Get batch record with per-item details."""
    ...

def get_batch_progress(batch_id: str) -> Dict[str, Any]:
    """Get batch processing progress (lightweight, no item details)."""
    ...

def list_batches(
    *, limit: int = 50, cursor: str = None
) -> Dict[str, Any]:
    """List batch operation history."""
    ...

def undo_batch(
    batch_id: str, *, admin_sub: str
) -> Dict[str, Any]:
    """Undo a batch operation (within undo window).

    Reverses each succeeded item: re-pends approved payouts,
    reverses refund ledger entries.
    """
    ...
```

### 3.3 Router: `app/routers/admin_bulk_ops.py`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/v1/admin/bulk-ops/payouts/dry-run` | `require_admin_session` | Payout dry run |
| POST | `/v1/admin/bulk-ops/payouts/execute` | `require_admin_session` | Execute payout batch |
| POST | `/v1/admin/bulk-ops/refunds/dry-run` | `require_admin_session` | Refund dry run |
| POST | `/v1/admin/bulk-ops/refunds/execute` | `require_admin_session` | Execute refund batch |
| POST | `/v1/admin/bulk-ops/payouts/import-csv` | `require_admin_session` | Import CSV payouts |
| GET | `/v1/admin/bulk-ops/{batch_id}` | `require_admin_session` | Batch detail |
| GET | `/v1/admin/bulk-ops/{batch_id}/progress` | `require_admin_session` | Batch progress |
| GET | `/v1/admin/bulk-ops` | `require_admin_session` | Batch history |
| POST | `/v1/admin/bulk-ops/{batch_id}/undo` | `require_admin_session` | Undo batch |

### 3.4 Pydantic Models (`app/models.py`)

```python
class BulkPayoutRequest(BaseModel):
    payout_ids: List[str] = Field(min_length=1, max_length=200)
    action: str = Field(pattern=r"^(approve|reject)$")
    reason: str = Field(default="", max_length=500)
    undo_window_seconds: int = Field(default=300, ge=0, le=3600)

class BulkRefundRequest(BaseModel):
    refund_ids: List[str] = Field(min_length=1, max_length=200)
    action: str = Field(pattern=r"^(approve|reject)$")
    reason: str = Field(default="", max_length=500)
    undo_window_seconds: int = Field(default=300, ge=0, le=3600)

class DryRunPreviewItem(BaseModel):
    item_id: str
    user_id: str
    amount_cents: int
    valid: bool
    issue: Optional[str] = None  # Why invalid (e.g., "already processed")

class DryRunPreview(BaseModel):
    items: List[DryRunPreviewItem]
    total: int
    valid_count: int
    invalid_count: int
    total_amount_cents: int

class BatchOut(BaseModel):
    batch_id: str
    batch_type: str
    admin_sub: str
    total_items: int
    processed: int
    succeeded: int
    failed: int
    skipped: int
    status: str
    undo_expires_at: Optional[int] = None
    created_at: int
    completed_at: Optional[int] = None

class BatchItemOut(BaseModel):
    item_id: str
    user_id: str
    amount_cents: int
    item_status: str
    error_message: Optional[str] = None
    processed_at: Optional[int] = None

class BatchDetailOut(BaseModel):
    batch: BatchOut
    items: List[BatchItemOut]

class CsvImportResult(BaseModel):
    parsed_count: int
    valid_count: int
    errors: List[Dict[str, Any]]
    payout_ids: List[str]
```

### 3.5 CSV Import Format

Expected CSV format for payout import:

```csv
user_id,amount_cents,method,notes
user_001,50000,bank_transfer,May payout
user_002,12500,bank_transfer,May payout
user_003,75000,paypal,Bonus payout
```

Validation rules:
- `user_id` must exist and have sufficient balance
- `amount_cents` must be positive integer above minimum payout threshold
- `method` must be one of: `bank_transfer`, `paypal`, `check`
- Duplicate `user_id` rows are flagged as errors
- Maximum 200 rows per CSV import

### 3.6 Undo Mechanism

The undo window defaults to 5 minutes (configurable up to 60 minutes per batch). During the undo window:

- Approved payouts remain in `approved` status but are not yet sent to payment providers
- The batch record has `undo_expires_at` set
- Calling `POST /undo` reverses each succeeded item back to `pending` status
- After the undo window expires, payouts are released for provider processing

### 3.7 Frontend: Bulk Operations Page

**Route**: `/admin/bulk-ops` in `frontend/src/App.tsx`  
**Page**: `frontend/src/pages/admin/bulkOps/BulkOpsPage.tsx`

```tsx
<Tabs defaultValue="payouts">
  <TabsList>
    <TabsTrigger value="payouts">Payouts</TabsTrigger>
    <TabsTrigger value="refunds">Refunds</TabsTrigger>
    <TabsTrigger value="import">CSV Import</TabsTrigger>
    <TabsTrigger value="history">History</TabsTrigger>
  </TabsList>

  <TabsContent value="payouts">
    <PayoutQueueTable
      selectable
      onBulkApprove={handleBulkApprove}
      onBulkReject={handleBulkReject}
    />
  </TabsContent>

  <TabsContent value="refunds">
    <RefundQueueTable selectable ... />
  </TabsContent>

  <TabsContent value="import">
    <CsvImportForm onUpload={handleCsvUpload} />
    <ImportPreview results={importResults} />
  </TabsContent>

  <TabsContent value="history">
    <BatchHistoryTable batches={batches} onUndo={handleUndo} />
  </TabsContent>
</Tabs>

{/* Dry-run preview dialog */}
<DryRunDialog
  open={showDryRun}
  preview={dryRunResult}
  onConfirm={handleExecute}
  onCancel={() => setShowDryRun(false)}
/>

{/* Progress dialog */}
<BatchProgressDialog
  open={showProgress}
  batchId={activeBatchId}
  progress={progress}
/>
```

### 3.8 Frontend API (`frontend/src/api/endpoints/adminBulkOps.ts`)

```typescript
export const dryRunPayouts = (data: { payout_ids: string[]; action: string }) =>
  client.post("/v1/admin/bulk-ops/payouts/dry-run", data);

export const executePayoutBatch = (data: BulkPayoutRequest) =>
  client.post("/v1/admin/bulk-ops/payouts/execute", data);

export const dryRunRefunds = (data: { refund_ids: string[]; action: string }) =>
  client.post("/v1/admin/bulk-ops/refunds/dry-run", data);

export const executeRefundBatch = (data: BulkRefundRequest) =>
  client.post("/v1/admin/bulk-ops/refunds/execute", data);

export const importCsvPayouts = (formData: FormData) =>
  client.post("/v1/admin/bulk-ops/payouts/import-csv", formData);

export const getBatch = (batchId: string) =>
  client.get(`/v1/admin/bulk-ops/${batchId}`);

export const getBatchProgress = (batchId: string) =>
  client.get(`/v1/admin/bulk-ops/${batchId}/progress`);

export const listBatches = (params?: { limit?: number }) =>
  client.get("/v1/admin/bulk-ops", { params });

export const undoBatch = (batchId: string) =>
  client.post(`/v1/admin/bulk-ops/${batchId}/undo`);
```

---

## 4. Implementation Plan

### Phase 1: Backend Data Layer (Days 1-2)

1. **`scripts/local-ddb-init.py`**: Add `bulk_operations` table with GSI.
2. **`app/core/settings.py`**: Add `bulk_operations_table_name`.
3. **`app/core/tables.py`**: Add `bulk_operations` table handle.

### Phase 2: Backend Service (Days 2-5)

4. **`app/services/bulk_operations.py`**: New file. Dry-run, execute, CSV import, progress, undo logic.
5. **Integration**: Call existing `approve_payout`, `reject_payout` from `creator_payouts.py` for each item in the batch.

### Phase 3: Backend Router (Days 5-6)

6. **`app/models.py`**: Add bulk operations Pydantic models.
7. **`app/routers/admin_bulk_ops.py`**: New router with 9 endpoints.
8. **`app/main.py`**: Register router with prefix `/v1/admin/bulk-ops`.

### Phase 4: Frontend (Days 6-8)

9. **`frontend/src/api/types.ts`**: Add TypeScript types.
10. **`frontend/src/api/endpoints/adminBulkOps.ts`**: New file.
11. **`frontend/src/pages/admin/bulkOps/BulkOpsPage.tsx`**: New page with selectable tables, CSV import, dry-run dialog, progress dialog.
12. **`frontend/src/App.tsx`**: Add `/admin/bulk-ops` route.
13. **`frontend/src/components/layout/Sidebar.tsx`**: Add "Bulk Operations" admin nav link.

### Phase 5: E2E Tests (Days 9-10)

14. **`frontend/e2e/admin-bulk-ops.spec.ts`**: 15 tests across 4 sections.

---

## 5. E2E Test Plan

**Test file**: `frontend/e2e/admin-bulk-ops.spec.ts`

**Setup (beforeAll)**:
- Inject auth for Root, Alice, Bob, Charlie (admin)
- Create 5 pending payout requests (3 for Alice, 2 for Bob) via DDB seed
- Create 3 pending refund requests

**Section 539: Payout Dry Run & Execute API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | `Dry run previews payout batch` | POST `/v1/admin/bulk-ops/payouts/dry-run` with 3 payout IDs and `action: "approve"` as Root -> 200; `valid_count === 3`, each item has `valid: true` |
| 2 | `Execute approves payout batch` | POST `/v1/admin/bulk-ops/payouts/execute` with same IDs -> 200; `batch_id` present, `total_items === 3` |
| 3 | `Batch detail shows results` | GET `/v1/admin/bulk-ops/{batch_id}` -> 200; `batch.succeeded === 3`, `items` array has 3 entries with `item_status: "succeeded"` |
| 4 | `Non-admin cannot execute batch` | POST as Alice -> 403 |

**Section 540: Refund Batch & Reject API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 5 | `Dry run previews refund batch` | POST `/v1/admin/bulk-ops/refunds/dry-run` with refund IDs and `action: "reject"` -> 200; `valid_count >= 1` |
| 6 | `Execute rejects refund batch` | POST `/v1/admin/bulk-ops/refunds/execute` with `{action: "reject", reason: "Policy violation"}` -> 200 |
| 7 | `Batch history includes all batches` | GET `/v1/admin/bulk-ops` as Root -> 200; array includes payout and refund batches |
| 8 | `Batch with invalid IDs reports failures` | POST execute with 1 valid + 1 bogus payout ID -> 200; `failed >= 1` |

**Section 541: CSV Import API (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 9 | `CSV import parses valid file` | POST `/v1/admin/bulk-ops/payouts/import-csv` with valid CSV -> 200; `parsed_count === N`, `valid_count === N`, `payout_ids` is non-empty array |
| 10 | `CSV import reports row errors` | POST with CSV containing invalid user_id -> 200; `errors` array has entry with row number and error message |
| 11 | `Empty CSV returns validation error` | POST with empty body -> 422 |

**Section 542: Undo & Progress API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 12 | `Batch progress shows completion state` | GET `/v1/admin/bulk-ops/{batch_id}/progress` -> 200; `processed === total_items`, `status: "completed"` |
| 13 | `Undo reverses batch within window` | POST `/v1/admin/bulk-ops/{batch_id}/undo` as Root -> 200; `status: "undone"`; re-GET batch shows `status: "undone"` |
| 14 | `Undo after window expires returns 409` | Create batch with `undo_window_seconds: 0`, then POST undo -> 409 (window expired) |
| 15 | `Undo already-undone batch returns 409` | POST undo on already-undone batch -> 409 |

---

## 6. Security Considerations

### 6.1 Role-Based Access
- All bulk operation endpoints require ADMIN role
- Batch sizes limited to 200 items to prevent system overload

### 6.2 Batch Safety
- Dry-run mode is mandatory in the UI (always preview before execute)
- Undo window provides recovery from accidental bulk operations
- Each batch operation logged with admin identity
- Concurrent batch operations by the same admin are blocked (only one active batch at a time)

### 6.3 CSV Security
- CSV file size limited to 1MB
- CSV parsing validates each field strictly (no formula injection)
- User IDs in CSV verified against user table before processing

### 6.4 Undo Constraints
- Undo only available within the configured window (default 5 minutes)
- Undo reverses all succeeded items; partially-undone batches are not supported
- Undo creates audit log entries for each reversal
- Completed payouts (already sent to provider) cannot be undone

---

## 7. Files to Create

| File | Purpose |
|------|---------|
| `app/services/bulk_operations.py` | Bulk operation processing service |
| `app/routers/admin_bulk_ops.py` | Admin bulk operations API (9 endpoints) |
| `frontend/src/api/endpoints/adminBulkOps.ts` | API wrappers |
| `frontend/src/pages/admin/bulkOps/BulkOpsPage.tsx` | Bulk operations page |
| `frontend/e2e/admin-bulk-ops.spec.ts` | E2E tests (15 tests, sections 539-542) |

## 8. Files to Modify

| File | Change |
|------|--------|
| `app/models.py` | Add bulk operation Pydantic models |
| `app/main.py` | Register `admin_bulk_ops_router` |
| `app/core/settings.py` | Add `bulk_operations_table_name` |
| `app/core/tables.py` | Add `bulk_operations` table handle |
| `scripts/local-ddb-init.py` | Add `bulk_operations` table |
| `frontend/src/api/types.ts` | Add bulk operation TypeScript types |
| `frontend/src/App.tsx` | Add `/admin/bulk-ops` route |
| `frontend/src/components/layout/Sidebar.tsx` | Add "Bulk Operations" admin nav link |

## 9. Acceptance Criteria

1. Dry-run mode validates each item and returns per-item validity with issues
2. Bulk payout approve processes all valid items and tracks succeeded/failed/skipped
3. Bulk refund approve/reject processes items with shared reason
4. CSV import parses file, validates rows, and creates payout requests
5. Batch detail shows per-item status with error messages for failures
6. Progress endpoint returns real-time processing status
7. Undo reverses all succeeded items within the configurable window
8. Undo after window expiry returns 409
9. Non-admin users receive 403 on all endpoints
10. All 15 E2E tests pass in `frontend/e2e/admin-bulk-ops.spec.ts`
