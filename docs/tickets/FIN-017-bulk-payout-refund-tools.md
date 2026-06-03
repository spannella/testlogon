# FIN-017: Bulk Payout/Refund Tools

**Status**: Implemented  
**Author**: Engineering  
**Date**: 2026-05-29  
**Priority**: Medium  
**Estimated effort**: 8-10 days  
**Dependencies**: Creator payouts (`app/services/creator_payouts.py` — 443 lines; `approve_payout` at `:292`, `reject_payout` at `:321`, `list_payouts_admin` at `:256`), admin payouts router (`app/routers/admin_payouts.py` — 103 lines, prefix `/v1/admin/payouts`; registered at `app/main.py:112,435`), billing ledger (`app/services/billing_shared.py:217`), refund requests router (`app/routers/refund_requests.py`; registered at `app/main.py:158,449`), admin auth (`app/auth/policy.py:63,67`)

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

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                           BULK PAYOUT / REFUND SYSTEM                               │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│  ┌──────────────┐    ┌────────────────────────┐    ┌──────────────────────────┐     │
│  │  Frontend     │    │  FastAPI Router         │    │  Bulk Operations Service │     │
│  │  BulkOps-    │───>│  admin_bulk_ops.py      │───>│  bulk_operations.py      │     │
│  │  Page.tsx     │    │  9 endpoints            │    │                         │     │
│  │              │<───│                        │<───│                         │     │
│  └──────────────┘    └──────────┬─────────────┘    └──────────┬──────────────┘     │
│                                 │                              │                    │
│                    ┌────────────┼──────────┐                   │                    │
│                    v            v          v                   v                    │
│          ┌──────────────┐ ┌──────────┐ ┌──────────────┐ ┌──────────────────┐       │
│          │ bulk_ops      │ │ billing  │ │ creator_     │ │  Alerts Service  │       │
│          │  DDB Table    │ │  DDB     │ │ payouts.py   │ │  (write_alert)   │       │
│          │  (batches)    │ │ (ledger) │ │ (1-at-a-time)│ │                  │       │
│          └──────────────┘ └──────────┘ └──────────────┘ └──────────────────┘       │
│                                                                                     │
└─────────────────────────────────────────────────────────────────────────────────────┘

Data Flow: Bulk Payout Approval
═══════════════════════════════

  Admin selects 5 pending payouts → clicks "Bulk Approve"
       │
       v
  ┌──────────────────────────────────────────────────────────────────────┐
  │  Step 1: DRY RUN (POST /bulk-ops/payouts/dry-run)                   │
  │    For each payout_id:                                               │
  │      1. Fetch payout record from creator_payouts table               │
  │      2. Verify status == "pending"                                   │
  │      3. Verify user exists and is not frozen                         │
  │      4. Verify amount_cents > 0 and <= max_payout_limit              │
  │    Return preview:                                                   │
  │      {items: [{id, user, amount, valid: true/false, issue}],         │
  │       total: 5, valid_count: 4, invalid_count: 1,                    │
  │       total_amount_cents: 125000}                                    │
  └──────────────────────────────────────────────────────────────────────┘
       │
       v  Admin reviews preview → clicks "Confirm"
  ┌──────────────────────────────────────────────────────────────────────┐
  │  Step 2: EXECUTE (POST /bulk-ops/payouts/execute)                    │
  │    1. Create BATCH#{batch_id} record (status: "processing")          │
  │    2. Create ITEM#{payout_id} rows for each item                     │
  │    3. For each valid item (sequentially):                            │
  │       ├── Call approve_payout(payout_id, admin_sub)                  │
  │       ├── Write LEDGER entry in billing table                        │
  │       ├── Update ITEM row: item_status = "succeeded"                 │
  │       └── Increment batch.processed, batch.succeeded                 │
  │    4. For items that fail:                                           │
  │       ├── Log error message                                          │
  │       ├── Update ITEM row: item_status = "failed", error_message     │
  │       └── Increment batch.failed                                     │
  │    5. Update BATCH: status = "completed", undo_expires_at = now+300  │
  └──────────────────────────────────────────────────────────────────────┘
       │
       v
  ┌──────────────────────────────────────────────────────────────────────┐
  │  Step 3: UNDO WINDOW (5 minutes)                                     │
  │    Admin can POST /bulk-ops/{batch_id}/undo                          │
  │    For each succeeded item:                                          │
  │      ├── Reverse payout: set status back to "pending"                │
  │      ├── Reverse LEDGER entry (settle_or_reverse_ledger)             │
  │      └── Update ITEM row: item_status = "undone"                     │
  │    After window expires: payouts released for provider processing    │
  └──────────────────────────────────────────────────────────────────────┘

Data Flow: CSV Import
═════════════════════

  Admin uploads CSV file
       │
       v
  ┌──────────────────────────────────────────────────────────────────────┐
  │  POST /bulk-ops/payouts/import-csv                                   │
  │    1. Parse CSV: validate headers (user_id, amount_cents, method)     │
  │    2. For each row:                                                  │
  │       ├── Validate user_id exists                                    │
  │       ├── Validate amount_cents > 0                                  │
  │       ├── Validate method in (bank_transfer, paypal, check)          │
  │       └── Check for duplicate user_ids                               │
  │    3. For valid rows: call request_payout() to create pending payouts│
  │    4. Return {parsed_count, valid_count, errors, payout_ids}         │
  │    5. Admin can then use dry-run + execute on the created payout_ids │
  └──────────────────────────────────────────────────────────────────────┘
```

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

### 3.2 DynamoDB Access Patterns

| Access Pattern | Table/GSI | PK | SK / Filter | Example |
|---|---|---|---|---|
| Get batch metadata | Main table | `BATCH#{batch_id}` | `sk = "META"` | Fetch batch status and counts |
| Get batch items | Main table | `BATCH#{batch_id}` | `begins_with(sk, "ITEM#")` | All items in a batch |
| Get specific batch item | Main table | `BATCH#{batch_id}` | `sk = "ITEM#{item_id}"` | Single item status |
| List all batches (newest first) | GSI1 | `BATCHES#ALL` | `GSI1SK desc` | Batch history page |
| List batches in date range | GSI1 | `BATCHES#ALL` | `GSI1SK BETWEEN :start AND :end` | Filtered batch history |
| Count active batches for admin | GSI1 query + filter | `BATCHES#ALL` | `FilterExpression: admin_sub = :admin AND status = "processing"` | Check concurrent batch limit |

**Example DynamoDB Items (JSON)**:

Batch record:
```json
{
  "pk": {"S": "BATCH#bat_a1b2c3d4"},
  "sk": {"S": "META"},
  "GSI1PK": {"S": "BATCHES#ALL"},
  "GSI1SK": {"N": "1748520600"},
  "batch_id": {"S": "bat_a1b2c3d4"},
  "batch_type": {"S": "payout_approve"},
  "admin_sub": {"S": "root.admin@testdev.local"},
  "total_items": {"N": "5"},
  "processed": {"N": "5"},
  "succeeded": {"N": "4"},
  "failed": {"N": "1"},
  "skipped": {"N": "0"},
  "status": {"S": "completed"},
  "undo_expires_at": {"N": "1748520900"},
  "undone_at": {"NULL": true},
  "created_at": {"N": "1748520600"},
  "completed_at": {"N": "1748520615"}
}
```

Batch item (succeeded):
```json
{
  "pk": {"S": "BATCH#bat_a1b2c3d4"},
  "sk": {"S": "ITEM#pay_x1y2z3"},
  "item_id": {"S": "pay_x1y2z3"},
  "user_id": {"S": "alice_sub_123"},
  "amount_cents": {"N": "50000"},
  "item_status": {"S": "succeeded"},
  "error_message": {"NULL": true},
  "processed_at": {"N": "1748520603"}
}
```

Batch item (failed):
```json
{
  "pk": {"S": "BATCH#bat_a1b2c3d4"},
  "sk": {"S": "ITEM#pay_invalid99"},
  "item_id": {"S": "pay_invalid99"},
  "user_id": {"S": "unknown_user"},
  "amount_cents": {"N": "0"},
  "item_status": {"S": "failed"},
  "error_message": {"S": "Payout not found or already processed"},
  "processed_at": {"N": "1748520610"}
}
```

### 3.3 Bulk Operations Service: `app/services/bulk_operations.py`

```python
"""Bulk payout and refund processing (FIN-017).

Provides batch approve/reject for payouts and refunds
with dry-run preview, progress tracking, and undo window.
"""

from __future__ import annotations
import csv
import io
import logging
import uuid
from decimal import Decimal
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from app.core.tables import T
from app.core.time import now_ts
from app.core.cursor import encode_cursor, decode_cursor
from app.services.creator_payouts import (
    approve_payout, reject_payout, get_payout,
)
from app.services.billing_shared import settle_or_reverse_ledger
from app.services.alerts import write_alert

logger = logging.getLogger("bulk_operations")

DEFAULT_UNDO_WINDOW_SECONDS = 300  # 5 minutes
MAX_BATCH_SIZE = 200


def dry_run_payouts(
    *, payout_ids: List[str], action: str, admin_sub: str,
) -> Dict[str, Any]:
    """Preview a bulk payout operation.

    Validates each payout: exists, correct status, user not frozen.
    Returns preview with per-item validity and summary totals.
    """
    items = []
    valid_count = 0
    invalid_count = 0
    total_amount = 0

    for pid in payout_ids:
        payout = get_payout(pid)
        if not payout:
            items.append({
                "item_id": pid, "user_id": "", "amount_cents": 0,
                "valid": False, "issue": "Payout not found",
            })
            invalid_count += 1
            continue

        if payout["status"] != "pending":
            items.append({
                "item_id": pid, "user_id": payout["user_id"],
                "amount_cents": int(payout["amount_cents"]),
                "valid": False, "issue": f"Status is '{payout['status']}', expected 'pending'",
            })
            invalid_count += 1
            continue

        # Check if user is frozen (fraud detection)
        frozen = _is_user_frozen(payout["user_id"])
        if frozen:
            items.append({
                "item_id": pid, "user_id": payout["user_id"],
                "amount_cents": int(payout["amount_cents"]),
                "valid": False, "issue": "User financial operations are frozen",
            })
            invalid_count += 1
            continue

        items.append({
            "item_id": pid, "user_id": payout["user_id"],
            "amount_cents": int(payout["amount_cents"]),
            "valid": True, "issue": None,
        })
        valid_count += 1
        total_amount += int(payout["amount_cents"])

    return {
        "items": items,
        "total": len(payout_ids),
        "valid_count": valid_count,
        "invalid_count": invalid_count,
        "total_amount_cents": total_amount,
    }


def execute_payout_batch(
    *, payout_ids: List[str], action: str, admin_sub: str,
    reason: str = "", undo_window_seconds: int = DEFAULT_UNDO_WINDOW_SECONDS,
) -> Dict[str, Any]:
    """Execute a bulk payout approve/reject.

    Creates batch record, processes each item sequentially,
    tracks progress in DDB.
    """
    batch_id = f"bat_{uuid.uuid4().hex[:8]}"
    now = now_ts()
    undo_expires = now + undo_window_seconds if undo_window_seconds > 0 else now

    # Create batch record
    T.bulk_operations.put_item(Item={
        "pk": f"BATCH#{batch_id}",
        "sk": "META",
        "GSI1PK": "BATCHES#ALL",
        "GSI1SK": Decimal(str(now)),
        "batch_id": batch_id,
        "batch_type": f"payout_{action}",
        "admin_sub": admin_sub,
        "total_items": Decimal(str(len(payout_ids))),
        "processed": Decimal("0"),
        "succeeded": Decimal("0"),
        "failed": Decimal("0"),
        "skipped": Decimal("0"),
        "status": "processing",
        "undo_expires_at": Decimal(str(undo_expires)),
        "created_at": Decimal(str(now)),
    })

    # Create item rows
    for pid in payout_ids:
        payout = get_payout(pid)
        T.bulk_operations.put_item(Item={
            "pk": f"BATCH#{batch_id}",
            "sk": f"ITEM#{pid}",
            "item_id": pid,
            "user_id": payout["user_id"] if payout else "",
            "amount_cents": Decimal(str(payout["amount_cents"])) if payout else Decimal("0"),
            "item_status": "pending",
        })

    # Process each item
    succeeded = 0
    failed = 0
    skipped = 0

    for pid in payout_ids:
        ts = now_ts()
        try:
            payout = get_payout(pid)
            if not payout or payout["status"] != "pending":
                _update_batch_item(batch_id, pid, "skipped", "Already processed or not found", ts)
                skipped += 1
                continue

            if action == "approve":
                approve_payout(pid, admin_sub)
            else:
                reject_payout(pid, admin_sub, reason)

            _update_batch_item(batch_id, pid, "succeeded", None, ts)
            succeeded += 1

        except Exception as e:
            logger.warning("batch_item_failed", extra={"batch_id": batch_id, "item_id": pid, "error": str(e)})
            _update_batch_item(batch_id, pid, "failed", str(e), ts)
            failed += 1

        # Update progress
        _update_batch_progress(batch_id, succeeded + failed + skipped, succeeded, failed, skipped)

    # Mark batch complete
    completed_at = now_ts()
    T.bulk_operations.update_item(
        Key={"pk": f"BATCH#{batch_id}", "sk": "META"},
        UpdateExpression="SET #s = :s, completed_at = :ca",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":s": "completed",
            ":ca": Decimal(str(completed_at)),
        },
    )

    logger.info("batch_completed", extra={
        "batch_id": batch_id, "type": f"payout_{action}",
        "total": len(payout_ids), "succeeded": succeeded,
        "failed": failed, "skipped": skipped,
        "admin": admin_sub,
    })

    return {
        "batch_id": batch_id,
        "batch_type": f"payout_{action}",
        "total_items": len(payout_ids),
        "succeeded": succeeded,
        "failed": failed,
        "skipped": skipped,
        "status": "completed",
        "undo_expires_at": undo_expires,
    }


def dry_run_refunds(
    *, refund_ids: List[str], action: str, admin_sub: str,
) -> Dict[str, Any]:
    """Preview a bulk refund operation. Same structure as payout dry run."""
    # Similar validation logic for refund records
    ...


def execute_refund_batch(
    *, refund_ids: List[str], action: str, admin_sub: str,
    reason: str = "", undo_window_seconds: int = DEFAULT_UNDO_WINDOW_SECONDS,
) -> Dict[str, Any]:
    """Execute a bulk refund approve/reject. Same pattern as payout batch."""
    ...


def import_csv_payouts(
    *, csv_content: str, admin_sub: str,
) -> Dict[str, Any]:
    """Parse CSV and create payout requests in bulk.

    Expected columns: user_id, amount_cents, method, notes
    """
    reader = csv.DictReader(io.StringIO(csv_content))
    parsed = 0
    valid = 0
    errors = []
    payout_ids = []
    seen_users = set()

    for i, row in enumerate(reader, 1):
        parsed += 1
        try:
            user_id = row.get("user_id", "").strip()
            if not user_id:
                errors.append({"row": i, "error": "Missing user_id"})
                continue
            if user_id in seen_users:
                errors.append({"row": i, "error": f"Duplicate user_id: {user_id}"})
                continue
            seen_users.add(user_id)

            amount = int(row.get("amount_cents", "0"))
            if amount <= 0:
                errors.append({"row": i, "error": f"Invalid amount_cents: {amount}"})
                continue

            method = row.get("method", "").strip()
            if method not in ("bank_transfer", "paypal", "check"):
                errors.append({"row": i, "error": f"Invalid method: {method}"})
                continue

            # Create payout request
            from app.services.creator_payouts import request_payout
            result = request_payout(
                user_id=user_id, amount_cents=amount,
                method=method, notes=row.get("notes", "CSV import"),
            )
            payout_ids.append(result["payout_id"])
            valid += 1

        except Exception as e:
            errors.append({"row": i, "error": str(e)})

    logger.info("csv_import_completed", extra={
        "parsed": parsed, "valid": valid,
        "errors": len(errors), "admin": admin_sub,
    })

    return {
        "parsed_count": parsed,
        "valid_count": valid,
        "errors": errors,
        "payout_ids": payout_ids,
    }


def get_batch(batch_id: str) -> Optional[Dict[str, Any]]:
    """Get batch record with per-item details."""
    meta_resp = T.bulk_operations.get_item(Key={"pk": f"BATCH#{batch_id}", "sk": "META"})
    meta = meta_resp.get("Item")
    if not meta:
        return None

    items_resp = T.bulk_operations.query(
        KeyConditionExpression=Key("pk").eq(f"BATCH#{batch_id}")
        & Key("sk").begins_with("ITEM#"),
    )
    items = [_item_to_dict(it) for it in items_resp.get("Items", [])]

    return {
        "batch": _batch_to_dict(meta),
        "items": items,
    }


def get_batch_progress(batch_id: str) -> Optional[Dict[str, Any]]:
    """Get batch processing progress (lightweight)."""
    resp = T.bulk_operations.get_item(Key={"pk": f"BATCH#{batch_id}", "sk": "META"})
    item = resp.get("Item")
    if not item:
        return None
    return _batch_to_dict(item)


def list_batches(*, limit: int = 50, cursor: str = None) -> Dict[str, Any]:
    """List batch operation history."""
    kwargs = {
        "IndexName": "GSI1",
        "KeyConditionExpression": Key("GSI1PK").eq("BATCHES#ALL"),
        "ScanIndexForward": False,
        "Limit": limit,
    }
    if cursor:
        kwargs["ExclusiveStartKey"] = decode_cursor(cursor)

    resp = T.bulk_operations.query(**kwargs)
    items = resp.get("Items", [])
    next_cursor = None
    if "LastEvaluatedKey" in resp:
        next_cursor = encode_cursor(resp["LastEvaluatedKey"])

    return {
        "batches": [_batch_to_dict(it) for it in items],
        "count": len(items),
        "cursor": next_cursor,
    }


def undo_batch(batch_id: str, *, admin_sub: str) -> Dict[str, Any]:
    """Undo a batch operation (within undo window)."""
    meta_resp = T.bulk_operations.get_item(Key={"pk": f"BATCH#{batch_id}", "sk": "META"})
    meta = meta_resp.get("Item")
    if not meta:
        return {"error": "Batch not found"}

    if meta["status"] == "undone":
        return {"error": "Batch already undone", "status_code": 409}

    undo_expires = int(meta.get("undo_expires_at", 0))
    if now_ts() > undo_expires:
        return {"error": "Undo window has expired", "status_code": 409}

    # Reverse each succeeded item
    items_resp = T.bulk_operations.query(
        KeyConditionExpression=Key("pk").eq(f"BATCH#{batch_id}")
        & Key("sk").begins_with("ITEM#"),
    )
    undone_count = 0
    for item in items_resp.get("Items", []):
        if item.get("item_status") == "succeeded":
            try:
                # Reverse the payout/refund
                _reverse_item(item, meta["batch_type"])
                T.bulk_operations.update_item(
                    Key={"pk": f"BATCH#{batch_id}", "sk": item["sk"]},
                    UpdateExpression="SET item_status = :s",
                    ExpressionAttributeValues={":s": "undone"},
                )
                undone_count += 1
            except Exception as e:
                logger.error("undo_item_failed", extra={
                    "batch_id": batch_id, "item_id": item["item_id"], "error": str(e),
                })

    T.bulk_operations.update_item(
        Key={"pk": f"BATCH#{batch_id}", "sk": "META"},
        UpdateExpression="SET #s = :s, undone_at = :ua",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":s": "undone",
            ":ua": Decimal(str(now_ts())),
        },
    )

    logger.info("batch_undone", extra={
        "batch_id": batch_id, "undone_count": undone_count, "admin": admin_sub,
    })

    return {"batch_id": batch_id, "status": "undone", "undone_count": undone_count}


# --- Helper functions ---

def _update_batch_item(batch_id, item_id, status, error, ts):
    update_expr = "SET item_status = :s, processed_at = :pa"
    values = {":s": status, ":pa": Decimal(str(ts))}
    if error:
        update_expr += ", error_message = :em"
        values[":em"] = error
    T.bulk_operations.update_item(
        Key={"pk": f"BATCH#{batch_id}", "sk": f"ITEM#{item_id}"},
        UpdateExpression=update_expr,
        ExpressionAttributeValues=values,
    )

def _update_batch_progress(batch_id, processed, succeeded, failed, skipped):
    T.bulk_operations.update_item(
        Key={"pk": f"BATCH#{batch_id}", "sk": "META"},
        UpdateExpression="SET processed = :p, succeeded = :s, failed = :f, skipped = :sk",
        ExpressionAttributeValues={
            ":p": Decimal(str(processed)),
            ":s": Decimal(str(succeeded)),
            ":f": Decimal(str(failed)),
            ":sk": Decimal(str(skipped)),
        },
    )

def _is_user_frozen(user_id):
    """Check fraud_detection table for frozen status."""
    try:
        resp = T.fraud_detection.get_item(
            Key={"pk": f"RISK#USER#{user_id}", "sk": "SCORE"},
        )
        return resp.get("Item", {}).get("frozen", False)
    except Exception:
        return False

def _reverse_item(item, batch_type):
    """Reverse a single batch item (re-pend payout or reverse refund)."""
    ...

def _batch_to_dict(item):
    return {
        "batch_id": item["batch_id"],
        "batch_type": item["batch_type"],
        "admin_sub": item["admin_sub"],
        "total_items": int(item["total_items"]),
        "processed": int(item.get("processed", 0)),
        "succeeded": int(item.get("succeeded", 0)),
        "failed": int(item.get("failed", 0)),
        "skipped": int(item.get("skipped", 0)),
        "status": item["status"],
        "undo_expires_at": int(item["undo_expires_at"]) if item.get("undo_expires_at") else None,
        "undone_at": int(item["undone_at"]) if item.get("undone_at") else None,
        "created_at": int(item.get("created_at", 0)),
        "completed_at": int(item["completed_at"]) if item.get("completed_at") else None,
    }

def _item_to_dict(item):
    return {
        "item_id": item["item_id"],
        "user_id": item.get("user_id", ""),
        "amount_cents": int(item.get("amount_cents", 0)),
        "item_status": item.get("item_status", "pending"),
        "error_message": item.get("error_message"),
        "processed_at": int(item["processed_at"]) if item.get("processed_at") else None,
    }
```

### 3.4 Router: `app/routers/admin_bulk_ops.py`

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

### 3.5 API Request/Response Examples

**POST /v1/admin/bulk-ops/payouts/dry-run**

```bash
curl -s -X POST "http://localhost:8000/v1/admin/bulk-ops/payouts/dry-run" \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_root_abc; ui_csrf=csrf_root_123; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_root_123" \
  -d '{"payout_ids": ["pay_001", "pay_002", "pay_003"], "action": "approve"}'
```

Response `200 OK`:
```json
{
  "items": [
    {"item_id": "pay_001", "user_id": "alice_sub_123", "amount_cents": 50000, "valid": true, "issue": null},
    {"item_id": "pay_002", "user_id": "bob_sub_456", "amount_cents": 12500, "valid": true, "issue": null},
    {"item_id": "pay_003", "user_id": "unknown", "amount_cents": 0, "valid": false, "issue": "Payout not found"}
  ],
  "total": 3,
  "valid_count": 2,
  "invalid_count": 1,
  "total_amount_cents": 62500
}
```

**POST /v1/admin/bulk-ops/payouts/execute**

```bash
curl -s -X POST "http://localhost:8000/v1/admin/bulk-ops/payouts/execute" \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_root_abc; ui_csrf=csrf_root_123; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_root_123" \
  -d '{
    "payout_ids": ["pay_001", "pay_002"],
    "action": "approve",
    "reason": "",
    "undo_window_seconds": 300
  }'
```

Response `200 OK`:
```json
{
  "batch_id": "bat_a1b2c3d4",
  "batch_type": "payout_approve",
  "total_items": 2,
  "succeeded": 2,
  "failed": 0,
  "skipped": 0,
  "status": "completed",
  "undo_expires_at": 1748520900
}
```

**GET /v1/admin/bulk-ops/{batch_id}**

```bash
curl -s -X GET "http://localhost:8000/v1/admin/bulk-ops/bat_a1b2c3d4" \
  -H "Cookie: ui_session=sess_root_abc; ui_csrf=csrf_root_123; ui_access_token=eyJ..."
```

Response `200 OK`:
```json
{
  "batch": {
    "batch_id": "bat_a1b2c3d4",
    "batch_type": "payout_approve",
    "admin_sub": "root.admin@testdev.local",
    "total_items": 2,
    "processed": 2,
    "succeeded": 2,
    "failed": 0,
    "skipped": 0,
    "status": "completed",
    "undo_expires_at": 1748520900,
    "created_at": 1748520600,
    "completed_at": 1748520605
  },
  "items": [
    {"item_id": "pay_001", "user_id": "alice_sub_123", "amount_cents": 50000, "item_status": "succeeded", "error_message": null, "processed_at": 1748520602},
    {"item_id": "pay_002", "user_id": "bob_sub_456", "amount_cents": 12500, "item_status": "succeeded", "error_message": null, "processed_at": 1748520604}
  ]
}
```

**POST /v1/admin/bulk-ops/payouts/import-csv**

```bash
curl -s -X POST "http://localhost:8000/v1/admin/bulk-ops/payouts/import-csv" \
  -H "Content-Type: multipart/form-data" \
  -H "Cookie: ui_session=sess_root_abc; ui_csrf=csrf_root_123; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_root_123" \
  -F "file=@payouts.csv"
```

Response `200 OK`:
```json
{
  "parsed_count": 3,
  "valid_count": 2,
  "errors": [
    {"row": 3, "error": "Invalid method: wire_transfer"}
  ],
  "payout_ids": ["pay_new_001", "pay_new_002"]
}
```

**POST /v1/admin/bulk-ops/{batch_id}/undo**

```bash
curl -s -X POST "http://localhost:8000/v1/admin/bulk-ops/bat_a1b2c3d4/undo" \
  -H "Cookie: ui_session=sess_root_abc; ui_csrf=csrf_root_123; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_root_123"
```

Response `200 OK` (within undo window):
```json
{
  "batch_id": "bat_a1b2c3d4",
  "status": "undone",
  "undone_count": 2
}
```

Response `409 Conflict` (after undo window):
```json
{
  "detail": "Undo window has expired"
}
```

**GET /v1/admin/bulk-ops/{batch_id}/progress**

```bash
curl -s -X GET "http://localhost:8000/v1/admin/bulk-ops/bat_a1b2c3d4/progress" \
  -H "Cookie: ui_session=sess_root_abc; ui_csrf=csrf_root_123; ui_access_token=eyJ..."
```

Response `200 OK`:
```json
{
  "batch_id": "bat_a1b2c3d4",
  "batch_type": "payout_approve",
  "admin_sub": "root.admin@testdev.local",
  "total_items": 2,
  "processed": 2,
  "succeeded": 2,
  "failed": 0,
  "skipped": 0,
  "status": "completed",
  "undo_expires_at": 1748520900,
  "created_at": 1748520600,
  "completed_at": 1748520605
}
```

### 3.6 Error Handling Matrix

| Error Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|---|---|---|---|---|
| Non-admin requests bulk operation | 403 | `forbidden` | "Admin role required" | Use admin session |
| Empty payout_ids list | 422 | `validation_error` | "payout_ids must have at least 1 item" | Provide at least one ID |
| Batch size exceeds 200 | 422 | `validation_error` | "payout_ids must have at most 200 items" | Split into smaller batches |
| Invalid action | 422 | `validation_error` | "action must be approve or reject" | Use valid action |
| Payout not found during execute | N/A | Item-level | Recorded as `skipped` on batch item | Check payout ID |
| Payout already processed | N/A | Item-level | Recorded as `skipped`: "Already processed" | No action needed |
| User frozen during execute | N/A | Item-level | Recorded as `failed`: "User frozen" | Resolve fraud case first |
| Batch not found | 404 | `not_found` | "Batch {batch_id} not found" | Verify batch ID |
| Undo window expired | 409 | `undo_expired` | "Undo window has expired" | Cannot undo after window |
| Undo already-undone batch | 409 | `already_undone` | "Batch already undone" | No action needed |
| Concurrent batch limit | 429 | `concurrent_limit` | "Only one active batch per admin at a time" | Wait for current batch to complete |
| CSV missing required columns | 400 | `invalid_csv` | "CSV must have columns: user_id, amount_cents, method" | Fix CSV headers |
| CSV file too large (>1MB) | 413 | `file_too_large` | "CSV file must be under 1MB" | Split CSV |
| CSV duplicate user_id | N/A | Row-level | Reported in errors array | Deduplicate CSV |
| Reject without reason | 200 | N/A | Allowed (reason is optional) | N/A |
| Undo window 0 seconds | N/A | N/A | Batch immediately non-undoable | By design — admin chose no undo |

### 3.7 Pydantic Models (`app/models.py`)

```python
from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional


class BulkPayoutRequest(BaseModel):
    """Request for bulk payout approve/reject."""
    payout_ids: List[str] = Field(
        ..., min_length=1, max_length=200,
        description="List of payout IDs to process",
    )
    action: str = Field(
        ..., pattern=r"^(approve|reject)$",
        description="Action to perform on each payout",
    )
    reason: str = Field(
        default="", max_length=500,
        description="Reason for rejection (optional for approve)",
    )
    undo_window_seconds: int = Field(
        default=300, ge=0, le=3600,
        description="Seconds during which the batch can be undone (0 = no undo)",
    )


class BulkRefundRequest(BaseModel):
    """Request for bulk refund approve/reject."""
    refund_ids: List[str] = Field(..., min_length=1, max_length=200)
    action: str = Field(..., pattern=r"^(approve|reject)$")
    reason: str = Field(default="", max_length=500)
    undo_window_seconds: int = Field(default=300, ge=0, le=3600)


class DryRunPreviewItem(BaseModel):
    """Single item in a dry-run preview."""
    item_id: str
    user_id: str
    amount_cents: int
    valid: bool
    issue: Optional[str] = Field(None, description="Why item is invalid")


class DryRunPreview(BaseModel):
    """Result of a dry-run preview."""
    items: List[DryRunPreviewItem]
    total: int = Field(..., ge=0)
    valid_count: int = Field(..., ge=0)
    invalid_count: int = Field(..., ge=0)
    total_amount_cents: int = Field(..., ge=0, description="Sum of valid item amounts")


class BatchOut(BaseModel):
    """Batch operation summary."""
    batch_id: str
    batch_type: str
    admin_sub: str
    total_items: int
    processed: int
    succeeded: int
    failed: int
    skipped: int
    status: str = Field(..., description="pending | processing | completed | undone")
    undo_expires_at: Optional[int] = None
    undone_at: Optional[int] = None
    created_at: int
    completed_at: Optional[int] = None


class BatchItemOut(BaseModel):
    """Single item within a batch."""
    item_id: str
    user_id: str
    amount_cents: int
    item_status: str = Field(..., description="pending | succeeded | failed | skipped | undone")
    error_message: Optional[str] = None
    processed_at: Optional[int] = None


class BatchDetailOut(BaseModel):
    """Full batch detail with all items."""
    batch: BatchOut
    items: List[BatchItemOut]


class BatchListOut(BaseModel):
    """Paginated list of batches."""
    batches: List[BatchOut]
    count: int
    cursor: Optional[str] = None


class CsvImportResult(BaseModel):
    """Result of CSV import."""
    parsed_count: int = Field(..., ge=0, description="Total rows parsed")
    valid_count: int = Field(..., ge=0, description="Rows that created payout requests")
    errors: List[Dict[str, Any]] = Field(default_factory=list, description="Per-row errors")
    payout_ids: List[str] = Field(default_factory=list, description="Created payout IDs")
```

### 3.8 CSV Import Format

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

### 3.9 Frontend Component Tree

```
BulkOpsPage (route: /admin/bulk-ops)
├── PageHeader
│   ├── h1 "Bulk Operations"
│   └── Badge ("Admin")
├── Tabs (shadcn)
│   ├── TabPanel: "Payouts"
│   │   └── PayoutQueueTable (props: { onBulkApprove: (ids: string[]) => void, onBulkReject: (ids: string[], reason: string) => void })
│   │       ├── SelectAllCheckbox
│   │       ├── DataTable (shadcn)
│   │       │   └── PayoutRow (selectable)
│   │       │       ├── Checkbox
│   │       │       ├── UserIdCell
│   │       │       ├── AmountCell (formatted $XX.XX)
│   │       │       ├── MethodBadge (bank_transfer | paypal | check)
│   │       │       ├── StatusBadge (pending)
│   │       │       └── TimeAgo (requested_at)
│   │       ├── BulkActionBar (props: { selectedCount: number, onApprove: () => void, onReject: () => void })
│   │       │   ├── span "{N} selected"
│   │       │   ├── Button ("Approve All") — variant="default"
│   │       │   └── Button ("Reject All") — variant="destructive" + ReasonDialog
│   │       └── Pagination
│   ├── TabPanel: "Refunds"
│   │   └── RefundQueueTable (same pattern as PayoutQueueTable)
│   ├── TabPanel: "CSV Import"
│   │   └── CsvImportForm (props: { onUpload: (file: File) => void, isUploading: boolean })
│   │       ├── FileDropzone (accepts .csv, max 1MB)
│   │       ├── Button ("Upload & Parse")
│   │       └── ImportPreview (props: { result: CsvImportResult | null })
│   │           ├── StatsRow (parsed, valid, errors)
│   │           ├── ErrorList (row number + error message)
│   │           └── Button ("Create Payouts from Valid Rows")
│   └── TabPanel: "History"
│       └── BatchHistoryTable (props: { batches: BatchOut[], onViewDetail: (id: string) => void, onUndo: (id: string) => void })
│           ├── DataTable (shadcn)
│           │   └── BatchRow
│           │       ├── TypeBadge (payout_approve | refund_reject | ...)
│           │       ├── ProgressBar (processed / total)
│           │       ├── ResultSummary (succeeded/failed/skipped)
│           │       ├── StatusBadge (completed | undone | processing)
│           │       ├── TimeAgo (created_at)
│           │       ├── UndoCountdown (if within undo window)
│           │       ├── Button ("Undo") — visible only within window
│           │       └── Button ("View Details")
│           └── Pagination
├── DryRunDialog (props: { open: boolean, preview: DryRunPreview, onConfirm: () => void, onCancel: () => void })
│   ├── Dialog (shadcn)
│   ├── SummaryStats (total, valid, invalid, total_amount)
│   ├── PreviewTable
│   │   └── PreviewRow (item_id, user_id, amount, valid badge, issue text)
│   ├── Button ("Cancel")
│   └── Button ("Confirm & Execute")
├── BatchProgressDialog (props: { open: boolean, batch: BatchOut | null })
│   ├── Dialog (shadcn)
│   ├── ProgressBar (animated: processed / total)
│   ├── LiveStats (succeeded, failed, skipped — updates via polling)
│   └── Button ("Close") — enabled when status != "processing"
└── BatchDetailDialog (props: { open: boolean, detail: BatchDetailOut | null })
    ├── Dialog (shadcn)
    ├── BatchSummary (type, admin, time, totals)
    ├── ItemsTable
    │   └── ItemRow (item_id, user, amount, status badge, error message)
    └── UndoSection (if within window)
        └── Button ("Undo Entire Batch") + ConfirmationDialog
```

### 3.10 Frontend API (`frontend/src/api/endpoints/adminBulkOps.ts`)

```typescript
import client from "../client";
import type {
  BulkPayoutRequest,
  BulkRefundRequest,
  DryRunPreview,
  BatchOut,
  BatchDetailOut,
  BatchListOut,
  CsvImportResult,
} from "../types";

export const dryRunPayouts = (data: { payout_ids: string[]; action: string }) =>
  client.post<DryRunPreview>("/v1/admin/bulk-ops/payouts/dry-run", data);

export const executePayoutBatch = (data: BulkPayoutRequest) =>
  client.post<BatchOut>("/v1/admin/bulk-ops/payouts/execute", data);

export const dryRunRefunds = (data: { refund_ids: string[]; action: string }) =>
  client.post<DryRunPreview>("/v1/admin/bulk-ops/refunds/dry-run", data);

export const executeRefundBatch = (data: BulkRefundRequest) =>
  client.post<BatchOut>("/v1/admin/bulk-ops/refunds/execute", data);

export const importCsvPayouts = (formData: FormData) =>
  client.post<CsvImportResult>("/v1/admin/bulk-ops/payouts/import-csv", formData);

export const getBatch = (batchId: string) =>
  client.get<BatchDetailOut>(`/v1/admin/bulk-ops/${batchId}`);

export const getBatchProgress = (batchId: string) =>
  client.get<BatchOut>(`/v1/admin/bulk-ops/${batchId}/progress`);

export const listBatches = (params?: { limit?: number; cursor?: string }) =>
  client.get<BatchListOut>("/v1/admin/bulk-ops", { params });

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

14. **`frontend/e2e/admin-bulk-ops.spec.ts`**: 25 tests across 6 sections.

---

## 5. E2E Test Plan

**Test file**: `frontend/e2e/admin-bulk-ops.spec.ts`

**Setup (beforeAll)**:
- Inject auth for Root, Alice, Bob, Charlie (admin)
- Create 5 pending payout requests (3 for Alice, 2 for Bob) via DDB seed
- Create 3 pending refund requests

**Section 539: Payout Dry Run & Execute API (5 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | `Dry run previews payout batch` | POST `/v1/admin/bulk-ops/payouts/dry-run` with 3 payout IDs and `action: "approve"` as Root -> 200; `valid_count === 3`, each item has `valid: true` |
| 2 | `Dry run reports invalid payout` | Include a bogus payout ID in dry-run; `invalid_count >= 1`, item has `issue: "Payout not found"` |
| 3 | `Execute approves payout batch` | POST `/v1/admin/bulk-ops/payouts/execute` with valid IDs -> 200; `batch_id` present, `total_items === N`, `succeeded === N` |
| 4 | `Batch detail shows per-item results` | GET `/v1/admin/bulk-ops/{batch_id}` -> 200; `batch.succeeded >= 1`, `items` array has entries with `item_status: "succeeded"` |
| 5 | `Non-admin cannot execute batch` | POST as Alice -> 403 |

**Section 540: Refund Batch & Reject API (5 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 6 | `Dry run previews refund batch` | POST `/v1/admin/bulk-ops/refunds/dry-run` with refund IDs and `action: "reject"` -> 200; `valid_count >= 1` |
| 7 | `Execute rejects refund batch with reason` | POST `/v1/admin/bulk-ops/refunds/execute` with `{action: "reject", reason: "Policy violation"}` -> 200 |
| 8 | `Batch history includes all batches` | GET `/v1/admin/bulk-ops` as Root -> 200; array includes payout and refund batches |
| 9 | `Batch with mixed valid and invalid IDs` | POST execute with 1 valid + 1 bogus payout ID -> 200; `succeeded >= 1`, `skipped >= 1` or `failed >= 1` |
| 10 | `Execute payout reject with reason` | POST execute with `action: "reject"` and `reason: "Insufficient documentation"` -> 200 |

**Section 541: CSV Import API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 11 | `CSV import parses valid file` | POST `/v1/admin/bulk-ops/payouts/import-csv` with valid CSV -> 200; `parsed_count > 0`, `valid_count > 0`, `payout_ids` non-empty |
| 12 | `CSV import reports row errors` | POST with CSV containing invalid method -> 200; `errors` array has entry with row number and error |
| 13 | `CSV import detects duplicate user_ids` | POST with CSV having same user_id twice -> 200; `errors` includes duplicate warning |
| 14 | `Empty CSV returns validation error` | POST with empty body -> 422 |

**Section 542: Undo & Progress API (5 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 15 | `Batch progress shows completion` | GET `/v1/admin/bulk-ops/{batch_id}/progress` -> 200; `processed === total_items`, `status: "completed"` |
| 16 | `Undo reverses batch within window` | POST `/v1/admin/bulk-ops/{batch_id}/undo` -> 200; `status: "undone"`, `undone_count >= 1` |
| 17 | `Re-GET after undo shows undone status` | GET batch detail; `batch.status === "undone"`, items have `item_status: "undone"` |
| 18 | `Undo after window expires returns 409` | Create batch with `undo_window_seconds: 0`, then POST undo -> 409 |
| 19 | `Undo already-undone batch returns 409` | POST undo on already-undone batch -> 409 |

**Section 543: Validation & Edge Cases (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 20 | `Batch size exceeding 200 returns 422` | POST with 201 payout IDs -> 422 |
| 21 | `Invalid action returns 422` | POST with `action: "cancel"` -> 422 |
| 22 | `Batch with all items already processed` | POST execute on already-approved payouts -> 200; `skipped === N`, `succeeded === 0` |

**Section 544: Bulk Operations UI (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 23 | `Bulk ops page loads with payout tab` | Navigate to `/admin/bulk-ops` as Root; verify payout queue table visible with checkboxes |
| 24 | `History tab shows completed batches` | Click "History" tab; verify batch rows with type badges, progress bars, undo buttons |
| 25 | `CSV Import tab has file upload area` | Click "CSV Import" tab; verify file dropzone and upload button visible |

---

## 6. Observability & Monitoring

### 6.1 Metrics

| Metric Name | Type | Labels | Description |
|---|---|---|---|
| `bulk_ops_batch_total` | Counter | `batch_type`, `status` (completed/undone) | Total batches executed |
| `bulk_ops_batch_duration_seconds` | Histogram | `batch_type` | Time to execute entire batch |
| `bulk_ops_item_total` | Counter | `batch_type`, `item_status` (succeeded/failed/skipped) | Per-item outcomes |
| `bulk_ops_batch_size` | Histogram | `batch_type` | Distribution of batch sizes |
| `bulk_ops_undo_total` | Counter | `batch_type` | Batches undone |
| `bulk_ops_csv_import_total` | Counter | — | CSV imports processed |
| `bulk_ops_csv_errors_total` | Counter | — | CSV row validation errors |
| `bulk_ops_dry_run_total` | Counter | `batch_type` | Dry-run previews generated |

### 6.2 Structured Log Events

```json
{
  "logger": "bulk_operations",
  "level": "INFO",
  "event": "batch_completed",
  "batch_id": "bat_a1b2c3d4",
  "type": "payout_approve",
  "total": 5,
  "succeeded": 4,
  "failed": 1,
  "skipped": 0,
  "duration_ms": 2500,
  "admin": "root.admin@testdev.local",
  "timestamp": 1748520605
}
```

```json
{
  "logger": "bulk_operations",
  "level": "INFO",
  "event": "batch_undone",
  "batch_id": "bat_a1b2c3d4",
  "undone_count": 4,
  "admin": "root.admin@testdev.local",
  "timestamp": 1748520800
}
```

```json
{
  "logger": "bulk_operations",
  "level": "WARNING",
  "event": "batch_item_failed",
  "batch_id": "bat_a1b2c3d4",
  "item_id": "pay_invalid99",
  "error": "Payout not found or already processed",
  "timestamp": 1748520610
}
```

### 6.3 Alerting Rules

| Alert | Condition | Severity | Action |
|---|---|---|---|
| High batch failure rate | > 50% items failed in a single batch | Warning | Investigate data quality; check payout service health |
| Batch processing stalled | Batch in "processing" state for > 5 minutes | Warning | Check backend process; may need manual intervention |
| Undo after large batch | Batch with > 50 items undone | Info | Review admin decision; may indicate accidental execution |
| CSV import spike | > 10 CSV imports in 1 hour | Info | Unusual activity; verify admin identity |
| Concurrent batch conflict | Admin attempts batch while another is processing | Warning | UI should block; check if race condition |

---

## 7. Rollout Plan

### Phase 1: Payout Batches Only (Week 1)

**Feature flag**: `BULK_OPS_ENABLED=true`, `BULK_OPS_REFUNDS_ENABLED=false`, `BULK_OPS_CSV_ENABLED=false`

- Deploy payout dry-run and execute endpoints
- Undo functionality available
- Progress tracking active
- Batch history recording
- UI: Payouts tab + History tab only

### Phase 2: Refund Batches + CSV (Week 2)

**Feature flag**: `BULK_OPS_REFUNDS_ENABLED=true`, `BULK_OPS_CSV_ENABLED=true`

- Enable refund batch processing
- Enable CSV import for payouts
- UI: All 4 tabs active

### Phase 3: General Availability (Week 3)

- Remove beta badges from UI
- Increase max batch size if needed (default 200)
- Enable undo window configuration in admin settings

### Feature Flags

| Flag | Default | Description |
|---|---|---|
| `BULK_OPS_ENABLED` | `true` | Master toggle for bulk operations |
| `BULK_OPS_REFUNDS_ENABLED` | `false` | Enable refund batch processing |
| `BULK_OPS_CSV_ENABLED` | `false` | Enable CSV import |
| `BULK_OPS_MAX_BATCH_SIZE` | `200` | Maximum items per batch |
| `BULK_OPS_DEFAULT_UNDO_WINDOW` | `300` | Default undo window in seconds |
| `BULK_OPS_CONCURRENT_LIMIT` | `1` | Max active batches per admin |

### Rollback Procedure

1. Set `BULK_OPS_ENABLED=false` — disables all bulk endpoints (returns 503)
2. Active batches in "processing" state will remain; items may need manual resolution
3. Completed batches with active undo windows: undo remains available via DDB direct
4. Batch history retained in DDB for auditing
5. Revert code deployment if needed

---

## 8. Performance Considerations

### 8.1 Latency Targets

| Operation | Target | Notes |
|---|---|---|
| Dry-run (per item) | < 50ms | Single DDB get per payout/refund |
| Dry-run (200 items) | < 10 seconds | Sequential but fast |
| Execute (per item) | < 200ms | DDB get + approve/reject + ledger entry |
| Execute (200 items) | < 40 seconds | Sequential processing |
| GET /batch progress | < 50ms | Single DDB get |
| GET /batch detail | < 500ms | Main query + items query |
| CSV import (200 rows) | < 15 seconds | Parse + validate + create payouts |
| Undo (200 items) | < 40 seconds | Reverse each succeeded item |

### 8.2 DynamoDB Query Costs

| Query | RCU/WCU | Notes |
|---|---|---|
| Dry-run item validation | 0.5 RCU per item | Single get per payout |
| Execute: create batch + items | 1 + N WCU | N = batch size |
| Execute: per-item processing | 1 RCU + 2 WCU per item | Get payout + update payout + write ledger |
| Progress update per item | 1 WCU | Atomic counter update |
| Batch detail query | 1 + ceil(N/100) RCU | Meta + paginated items query |
| Undo per item | 2 WCU per item | Reverse payout + update item |

### 8.3 Scalability

- Batch processing is sequential (not parallel) to avoid DDB write throttling on hot partitions.
- For future scaling: partition batch items across multiple background workers using SQS.
- The 200-item limit keeps single-batch execution time under 40 seconds.
- For larger batches (1000+), the CSV import creates pending payouts that can be split into multiple 200-item execute batches.

### 8.4 Memory

- Dry-run holds all preview items in memory: 200 items at ~200 bytes each = ~40KB (negligible).
- CSV import reads the entire file into memory: 1MB limit ensures this stays manageable.
- Batch execution processes items one at a time; no large in-memory collections.

---

## 9. Security Considerations

### 9.1 Role-Based Access
- All bulk operation endpoints require ADMIN role
- Batch sizes limited to 200 items to prevent system overload

### 9.2 Batch Safety
- Dry-run mode is mandatory in the UI (always preview before execute)
- Undo window provides recovery from accidental bulk operations
- Each batch operation logged with admin identity
- Concurrent batch operations by the same admin are blocked (only one active batch at a time)

### 9.3 CSV Security
- CSV file size limited to 1MB
- CSV parsing validates each field strictly (no formula injection)
- User IDs in CSV verified against user table before processing

### 9.4 Undo Constraints
- Undo only available within the configured window (default 5 minutes)
- Undo reverses all succeeded items; partially-undone batches are not supported
- Undo creates audit log entries for each reversal
- Completed payouts (already sent to provider) cannot be undone

---

## 10. Files to Create

| File | Purpose |
|------|---------|
| `app/services/bulk_operations.py` | Bulk operation processing service |
| `app/routers/admin_bulk_ops.py` | Admin bulk operations API (9 endpoints) |
| `frontend/src/api/endpoints/adminBulkOps.ts` | API wrappers |
| `frontend/src/pages/admin/bulkOps/BulkOpsPage.tsx` | Bulk operations page |
| `frontend/e2e/admin-bulk-ops.spec.ts` | E2E tests (25 tests, sections 539-544) |

## 11. Files to Modify

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

## 12. Acceptance Criteria

1. Dry-run mode validates each item and returns per-item validity with issues
2. Bulk payout approve processes all valid items and tracks succeeded/failed/skipped
3. Bulk refund approve/reject processes items with shared reason
4. CSV import parses file, validates rows, and creates payout requests
5. Batch detail shows per-item status with error messages for failures
6. Progress endpoint returns real-time processing status
7. Undo reverses all succeeded items within the configurable window
8. Undo after window expiry returns 409
9. Non-admin users receive 403 on all endpoints
10. All 25 E2E tests pass in `frontend/e2e/admin-bulk-ops.spec.ts`
11. Batch processing completes within latency targets for 200-item batches
12. Feature flags allow incremental rollout of payouts, refunds, and CSV features

---

## Codebase References

| File | Lines | What |
|------|-------|------|
| `app/services/creator_payouts.py` | 443 total | `get_available_balance` at `:55`, `request_payout` at `:164`, `list_payouts_admin` at `:256`, `approve_payout` at `:292`, `reject_payout` at `:321`, `get_payout_stats` at `:393` |
| `app/routers/admin_payouts.py` | 103 total | Router prefix `/v1/admin/payouts` at `:32`; list `:35`, stats `:48`, approve `:57`, reject `:73`, complete `:90` |
| `app/main.py` | :112, :435 | `admin_payouts_router` import and registration |
| `app/routers/refund_requests.py` | — | Refund requests router; registered at `app/main.py:158,449` |
| `app/services/billing_shared.py` | :217 | `new_ledger_entry` for ledger writes during payout/refund processing |
| `app/services/alerts.py` | :355 | `write_alert` for notification on bulk operation completion |
| `app/auth/policy.py` | :63, :67 | `require_root` at `:63`, `require_admin_or_root` at `:67` |
| `scripts/local-ddb-init.py` | :59 | `billing` table (PK=pk, SK=sk) |

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_bulk_operations.py`

Mock external dependencies with `moto` (DynamoDB) and `unittest.mock`. All tests run without the dev stack.

  - `test_dry_run_payouts_all_valid`
  - `test_dry_run_payouts_not_found`
  - `test_dry_run_payouts_frozen_user`
  - `test_execute_payout_batch_succeeds`
  - `test_execute_payout_batch_mixed_results`
  - `test_import_csv_payouts_valid`
  - `test_import_csv_payouts_duplicate_user`
  - `test_undo_batch_within_window`
  - `test_undo_batch_after_window_fails`

### Integration Tests

  - Bulk approve calls approve_payout for each valid payout in sequence
  - Batch progress updates in DDB after each item processed
  - Undo reverses all succeeded items and updates ledger entries
  - CSV import creates pending payout requests in creator_payouts table

### E2E Tests (Playwright)

**File**: `frontend/e2e/admin-bulk-ops.spec.ts`
**Test count**: 25

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

- **DDB seeds**: Seed `bulk_operations` table with test records in `beforeAll`
- **Test users**: Alice (USER), Bob (USER), Root (ROOT), Charlie (ADMIN) from `e2e_admin_session_setup.py`
- **Cleanup**: Tests use unique timestamps/IDs per run to avoid cross-run interference

### CI/Pipeline Considerations

- **Feature flag**: `BULK_OPS_ENABLED=true` must be set in test environment
- **Serial execution**: E2E tests run with `workers: 1` to avoid shared-state conflicts
- **Retry safety**: All tests are idempotent; retries do not produce duplicate records

## Dependencies & Merge Safety

### Depends On

| Ticket | Title | Why |
|--------|-------|-----|
| FIN-015 | Fraud Detection Dashboard | Checks user frozen status via fraud_detection table |

### Depended On By

| Ticket | Title | Impact |
|--------|-------|--------|
| (none) | — | No other tickets depend on this one |

### Merge Strategy

**Sequential**

Merge after FIN-015. This ticket depends on tables/services introduced by those tickets.

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
- [ ] All 25 E2E tests pass with `npx playwright test admin-bulk-ops.spec.ts`
