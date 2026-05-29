# FIN-004: Consumer Tax Documents

**Ticket**: FIN-004
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 7-9 days

---

## 1. Overview & Motivation

### 1.1 Purpose

FIN-004 adds consumer-facing tax document functionality. Users need annual spending summaries broken down by category for personal tax reporting, expense documentation, and financial record-keeping. The system aggregates billing ledger entries across a user-selected date range, computes category totals, and generates a downloadable PDF summary. Individual transaction receipts (from FIN-001 invoices) can be bulk-exported as a ZIP archive. The feature provides both a Tax Documents page with interactive date-range selection and an API for programmatic access.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Consumer | As a buyer, I want an annual spending summary showing total spent by category. | Tax summary endpoint returns spending grouped by: subscriptions, tips, purchases, unlocks, deposits. |
| Consumer | As a buyer, I want to download my tax summary as a PDF. | PDF contains header with date range, category breakdown table, grand total, and disclaimer text. |
| Consumer | As a buyer, I want to select any date range for my summary. | Date range picker supports: calendar year presets (2024, 2025, 2026) and custom from/to. |
| Consumer | As a buyer, I want to export all receipts for a period as a ZIP. | Bulk download endpoint returns a ZIP file containing individual invoice PDFs for the selected range. |
| Consumer | As a buyer, I want my tax documents page to show a yearly comparison. | Year-over-year comparison table: total spent current year vs. previous year, per category. |
| Admin | As an admin, I want to generate a user's tax summary for support purposes. | Admin endpoint accepts `user_sub` parameter; returns same summary format. |

### 1.3 Why This Is Needed

The platform processes significant financial transactions (tips, subscriptions, purchases, unlocks, deposits) but provides no consolidated view for tax or accounting purposes. Users must manually sum billing ledger entries or export raw data. Tax season requires standardized spending summaries by category. Providing these documents reduces user support burden and demonstrates platform maturity.

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

| Component | Location | Relevance |
|-----------|----------|-----------|
| Billing ledger | `app/services/billing_shared.py` | `new_ledger_entry` writes entries with `type`, `amount_cents`, `reason`, `ts`; `ledger_sk` format: `LEDGER#{ts}#{entry_id}` |
| Billing ledger endpoint | `app/routers/billing.py:2274` | `GET /billing/ledger` returns all entries for a user; SK prefix `LEDGER#` |
| Billing table | `app/core/tables.py` | `T.billing` with PK `USER#{user_sub}` |
| Invoice system | FIN-001 (prerequisite) | Invoice records with `invoice_type`, PDF generation, S3 storage |
| PDF generation | FIN-001 (`fpdf2`) | PDF rendering library available after FIN-001 implementation |
| S3 storage | `app/core/dev_s3.py` | File storage for generated documents |
| Profile service | `app/services/profile.py` | User display name and email for document headers |
| `ulidish()` | `app/services/billing_shared.py` | Unique ID generation |

### 2.2 Gaps

1. **No category aggregation** -- billing ledger entries have `type` and `reason` fields but no standardized `category` for tax grouping.
2. **No date-range ledger query** -- current `GET /billing/ledger` returns all entries without date filtering (SK starts with `LEDGER#` containing timestamp, so range queries are possible but not exposed).
3. **No tax summary computation** -- no function to aggregate ledger entries by category and date range.
4. **No tax document PDF** -- no template for a tax summary document distinct from individual invoices.
5. **No bulk PDF export** -- no ZIP archive generation for multiple invoices.
6. **No year-over-year comparison** -- no historical aggregation endpoint.
7. **No tax document storage** -- generated summaries are not cached.

---

## 3. Technical Design

### 3.1 DynamoDB Schema

#### 3.1.1 Tax Documents Table

**Table name**: `tax_documents` (new table)
**PK**: `pk` (S), **SK**: `sk` (S)

| PK Pattern | SK Pattern | Purpose | Key Fields |
|------------|------------|---------|------------|
| `USER#{user_sub}` | `DOC#{year}#{doc_id}` | Generated tax document record | `doc_id`, `user_sub`, `doc_type` (annual_summary / custom_range), `year`, `date_from`, `date_to`, `categories` (map), `grand_total_cents`, `transaction_count`, `currency`, `s3_key`, `created_at` |
| `USER#{user_sub}` | `CACHE#{year}` | Cached annual summary data | `year`, `categories`, `grand_total_cents`, `transaction_count`, `computed_at` |

No GSIs needed -- all queries are by user PK.

#### 3.1.2 TableDef Entry

```python
TableDef(
    "tax_documents", "pk", "sk",
),
```

#### 3.1.3 Example DynamoDB Items

**Tax document record**:
```json
{
  "pk": "USER#alice@test.local",
  "sk": "DOC#2025#td_abc123",
  "doc_id": "td_abc123",
  "user_sub": "alice@test.local",
  "doc_type": "annual_summary",
  "year": 2025,
  "date_from": 1735689600,
  "date_to": 1767225599,
  "categories": {
    "subscriptions": {"total_cents": 12000, "count": 12},
    "tips": {"total_cents": 5000, "count": 8},
    "purchases": {"total_cents": 25000, "count": 5},
    "unlocks": {"total_cents": 3500, "count": 7},
    "deposits": {"total_cents": 10000, "count": 2}
  },
  "grand_total_cents": 55500,
  "transaction_count": 34,
  "currency": "usd",
  "s3_key": "tax-docs/alice@test.local/2025-annual-summary.pdf",
  "created_at": 1748520100
}
```

**Cached annual summary**:
```json
{
  "pk": "USER#alice@test.local",
  "sk": "CACHE#2025",
  "year": 2025,
  "categories": {
    "subscriptions": {"total_cents": 12000, "count": 12},
    "tips": {"total_cents": 5000, "count": 8},
    "purchases": {"total_cents": 25000, "count": 5},
    "unlocks": {"total_cents": 3500, "count": 7},
    "deposits": {"total_cents": 10000, "count": 2}
  },
  "grand_total_cents": 55500,
  "transaction_count": 34,
  "computed_at": 1748520100
}
```

### 3.2 Category Classification

Billing ledger entries are classified into tax categories by their `type` and `reason` fields:

| Ledger `type` | Ledger `reason` pattern | Tax Category |
|---------------|------------------------|--------------|
| `debit` | "Subscription*" / "Plan*" | `subscriptions` |
| `debit` | "Tip*" | `tips` |
| `debit` | "Purchase*" / "Cart*" / "Order*" | `purchases` |
| `debit` | "Unlock*" | `unlocks` |
| `debit` | "Deposit*" / "Wallet*" | `deposits` |
| `debit` | (other) | `other` |
| `credit` | (all) | Excluded (credits are income, not spending) |

```python
def classify_category(entry: Dict[str, Any]) -> Optional[str]:
    """Classify a billing ledger entry into a tax category."""
    if entry.get("type") != "debit":
        return None  # Only spending (debits) counted
    reason = entry.get("reason", "").lower()
    if reason.startswith("subscription") or reason.startswith("plan"):
        return "subscriptions"
    if reason.startswith("tip"):
        return "tips"
    if reason.startswith("purchase") or reason.startswith("cart") or reason.startswith("order"):
        return "purchases"
    if reason.startswith("unlock"):
        return "unlocks"
    if reason.startswith("deposit") or reason.startswith("wallet"):
        return "deposits"
    return "other"
```

### 3.3 Backend Service

**New file**: `app/services/tax_documents.py` (~350 lines)

```python
"""Consumer tax document generation (FIN-004)."""

from __future__ import annotations
import logging
from typing import Any, Dict, List, Optional
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)


def compute_spending_summary(
    *,
    user_sub: str,
    date_from: int,
    date_to: int,
) -> Dict[str, Any]:
    """Aggregate billing ledger entries by category for a date range.

    Queries billing table for all LEDGER# entries within the range,
    classifies each into a tax category, and returns category totals.
    """


def get_annual_summary(
    *,
    user_sub: str,
    year: int,
    use_cache: bool = True,
) -> Dict[str, Any]:
    """Get or compute annual spending summary. Uses DDB cache if available and current year is past."""


def generate_tax_summary_pdf(
    *,
    user_sub: str,
    summary: Dict[str, Any],
    date_from: int,
    date_to: int,
    buyer_name: str,
    buyer_email: str,
) -> bytes:
    """Render tax summary dict to PDF bytes."""


def download_tax_summary_pdf(
    *,
    user_sub: str,
    year: Optional[int] = None,
    date_from: Optional[int] = None,
    date_to: Optional[int] = None,
) -> bytes:
    """Generate and return tax summary PDF bytes."""


def export_receipts_zip(
    *,
    user_sub: str,
    date_from: int,
    date_to: int,
) -> bytes:
    """Collect individual invoice PDFs for the date range, return as ZIP bytes."""


def get_year_comparison(
    *,
    user_sub: str,
    year: int,
) -> Dict[str, Any]:
    """Compare spending between the given year and the previous year."""


def list_tax_documents(
    *,
    user_sub: str,
    limit: int = 20,
) -> List[Dict[str, Any]]:
    """List previously generated tax documents for a user."""


def admin_get_user_summary(
    *,
    target_user_sub: str,
    date_from: int,
    date_to: int,
) -> Dict[str, Any]:
    """Admin: compute spending summary for any user."""
```

### 3.4 Backend Router

**New file**: `app/routers/tax_documents.py` (~200 lines)

```python
"""Tax document endpoints (FIN-004)."""

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from app.auth.deps import require_ui_session, require_admin_session

router = APIRouter(prefix="/ui/tax-documents", tags=["tax-documents"])
admin_router = APIRouter(prefix="/ui/admin/tax-documents", tags=["tax-documents-admin"])
```

### 3.5 Router Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/ui/tax-documents/summary` | `require_ui_session` | Get spending summary (params: `year` OR `date_from` + `date_to`) |
| `GET` | `/ui/tax-documents/summary/pdf` | `require_ui_session` | Download tax summary as PDF (same params) |
| `GET` | `/ui/tax-documents/receipts/zip` | `require_ui_session` | Download all receipts in range as ZIP |
| `GET` | `/ui/tax-documents/comparison` | `require_ui_session` | Year-over-year spending comparison (param: `year`) |
| `GET` | `/ui/tax-documents/history` | `require_ui_session` | List previously generated documents |
| `GET` | `/ui/admin/tax-documents/summary` | `require_admin_session` | Admin: get any user's spending summary |

### 3.6 Request/Response Models

**Add to `app/models.py`**:

```python
# -- Tax Documents (FIN-004) --

class SpendingCategoryOut(BaseModel):
    category: str  # subscriptions, tips, purchases, unlocks, deposits, other
    total_cents: int = 0
    transaction_count: int = 0

class SpendingSummaryOut(BaseModel):
    date_from: int
    date_to: int
    categories: List[SpendingCategoryOut] = Field(default_factory=list)
    grand_total_cents: int = 0
    transaction_count: int = 0
    currency: str = "usd"

class YearComparisonOut(BaseModel):
    current_year: int
    previous_year: int
    current_summary: SpendingSummaryOut
    previous_summary: SpendingSummaryOut
    change_pct: float = 0.0  # positive = spent more, negative = spent less

class TaxDocumentOut(BaseModel):
    doc_id: str
    doc_type: str  # annual_summary, custom_range
    year: Optional[int] = None
    date_from: int
    date_to: int
    grand_total_cents: int = 0
    transaction_count: int = 0
    created_at: int = 0

class TaxDocumentListOut(BaseModel):
    documents: List[TaxDocumentOut] = Field(default_factory=list)
```

### 3.7 Tax Summary PDF Layout

```
+--------------------------------------------+
|  [Platform Logo]    SPENDING SUMMARY       |
|                                            |
|  Period: January 1, 2025 - Dec 31, 2025   |
|  Prepared for: Alice User                  |
|  Email: alice@example.com                  |
|  Generated: May 29, 2026                   |
|                                            |
|  ----------------------------------------  |
|  Category           Count      Total       |
|  ----------------------------------------  |
|  Subscriptions        12      $120.00      |
|  Tips                  8       $50.00      |
|  Purchases             5      $250.00      |
|  Unlocks               7       $35.00      |
|  Deposits              2      $100.00      |
|  ----------------------------------------  |
|  GRAND TOTAL          34      $555.00      |
|                                            |
|  This document is for informational        |
|  purposes only and does not constitute     |
|  tax advice. Consult a tax professional    |
|  for guidance on deductibility.            |
+--------------------------------------------+
```

### 3.8 Frontend Components

**New files**:

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `frontend/src/pages/billing/TaxDocumentsPage.tsx` | Tax documents main page | ~350 |
| `frontend/src/api/endpoints/taxDocuments.ts` | API wrappers | ~60 |

**Component tree**:

```
TaxDocumentsPage
├── Header: "Tax Documents" with FileText icon
├── Date range selector
│   ├── Year preset buttons: "2024" / "2025" / "2026"
│   └── Custom range: DatePicker (from) + DatePicker (to)
├── Spending Summary Card
│   ├── Grand total (large display)
│   ├── Transaction count
│   └── Category breakdown (horizontal bar chart or table)
│       ├── Subscriptions: $120.00 (12 transactions)
│       ├── Tips: $50.00 (8 transactions)
│       ├── Purchases: $250.00 (5 transactions)
│       ├── Unlocks: $35.00 (7 transactions)
│       └── Deposits: $100.00 (2 transactions)
├── Year Comparison Card
│   ├── Current year total vs. previous year total
│   ├── Change percentage (green/red arrow)
│   └── Per-category comparison bars
├── Action buttons
│   ├── "Download Summary PDF" (FileDown icon)
│   └── "Export All Receipts (ZIP)" (Archive icon)
└── Document History
    └── Table of previously generated documents
        ├── Date, type, period, total, download link
        └── Empty state: "No documents generated yet"
```

### 3.9 Frontend Routes

Add to `frontend/src/App.tsx`:

```typescript
<Route path="/billing/tax-documents" element={<TaxDocumentsPage />} />
```

Add "Tax Documents" link to billing navigation.

### 3.10 Files to Create

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `app/services/tax_documents.py` | Summary computation, PDF generation, ZIP export | ~350 |
| `app/routers/tax_documents.py` | REST API endpoints | ~200 |
| `frontend/src/pages/billing/TaxDocumentsPage.tsx` | Tax documents UI | ~350 |
| `frontend/src/api/endpoints/taxDocuments.ts` | API wrappers | ~60 |
| `frontend/e2e/tax-documents.spec.ts` | E2E tests | ~450 |

### 3.11 Files to Modify

| File | Change |
|------|--------|
| `app/main.py` | Register `tax_documents_router` and `tax_documents_admin_router` |
| `app/models.py` | Add tax document Pydantic models |
| `app/core/settings.py` | Add `tax_documents_table_name` setting |
| `app/core/tables.py` | Add `T.tax_documents` table handle |
| `scripts/local-ddb-init.py` | Add `tax_documents` TableDef |
| `frontend/src/api/types.ts` | Add tax document TypeScript interfaces |
| `frontend/src/App.tsx` | Add tax documents route |

---

## 4. Ledger Query Optimization

### 4.1 Date-Range Ledger Query

The billing ledger SK format is `LEDGER#{ts}#{entry_id}`. To query a date range:

```python
def query_ledger_range(user_sub: str, date_from: int, date_to: int) -> List[Dict[str, Any]]:
    """Query billing ledger entries within a timestamp range."""
    entries = []
    kwargs = {
        "KeyConditionExpression": Key("pk").eq(f"USER#{user_sub}") &
            Key("sk").between(f"LEDGER#{date_from}#", f"LEDGER#{date_to}#~"),
    }
    while True:
        resp = T.billing.query(**kwargs)
        entries.extend(resp.get("Items", []))
        if "LastEvaluatedKey" not in resp:
            break
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
    return entries
```

The `~` suffix on the upper bound ensures all entry IDs within the `date_to` second are included (ASCII `~` > any ULID character).

### 4.2 Caching Strategy

- **Completed years**: Annual summaries for past years (e.g., 2024, 2025) are immutable. Computed once and cached in `CACHE#{year}` record.
- **Current year**: Summary is computed fresh on each request (ledger entries may still be accumulating).
- **Cache invalidation**: No explicit invalidation. Past years never change. Current year is never cached.

### 4.3 ZIP Export Performance

For users with many receipts, ZIP generation could be slow. Mitigations:

- Limit ZIP export to 500 receipts per request (return 400 if exceeded, suggest narrower date range).
- Stream PDF bytes from S3 directly into ZIP buffer (no intermediate disk writes).
- Set response timeout to 60 seconds for ZIP endpoint.

---

## 5. E2E Test Plan

**File**: `frontend/e2e/tax-documents.spec.ts`

### Section 551: Spending Summary API (5 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 551.1 | Annual summary returns category breakdown | Seed billing ledger with known entries (tips, unlocks, purchases). GET `/ui/tax-documents/summary?year=2026`. Response has `categories` with correct `total_cents` per type. |
| 551.2 | Custom date range filters correctly | GET with `date_from` and `date_to` params spanning a subset of entries. `grand_total_cents` matches only entries within range. |
| 551.3 | Empty period returns zero totals | GET summary for a year with no transactions. `grand_total_cents: 0`, `categories` array has entries with `total_cents: 0`. |
| 551.4 | Credits are excluded from spending summary | Seed a credit entry (e.g., refund). GET summary. Credit amount not included in `grand_total_cents`. |
| 551.5 | Summary counts distinct transactions | Multiple ledger entries from different categories. `transaction_count` equals total debit entries in range. |

### Section 552: Tax Summary PDF API (3 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 552.1 | PDF download returns binary content | GET `/ui/tax-documents/summary/pdf?year=2026`; `Content-Type: application/pdf`; body starts with `%PDF`. |
| 552.2 | PDF filename includes year | Response `Content-Disposition` header contains `spending-summary-2026.pdf`. |
| 552.3 | Custom range PDF uses date range in filename | GET with `date_from` + `date_to`; filename contains date range. |

### Section 553: Receipts ZIP Export and Comparison API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 553.1 | ZIP export returns archive | GET `/ui/tax-documents/receipts/zip?year=2026`; `Content-Type: application/zip`; body starts with PK zip header (`PK\x03\x04`). |
| 553.2 | ZIP contains expected number of receipts | Generate 3 invoices in date range. ZIP file contains 3 PDF entries. |
| 553.3 | Year comparison returns both years | GET `/ui/tax-documents/comparison?year=2026`; response has `current_year: 2026`, `previous_year: 2025`, both summaries populated. |
| 553.4 | Change percentage calculated correctly | Seed 2025 with $100 total, 2026 with $150 total. `change_pct` approximately 50.0. |

### Section 554: Admin and Document History API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 554.1 | Admin can view any user's summary | Root GET `/ui/admin/tax-documents/summary?user_sub=alice&year=2026`; returns Alice's spending data. |
| 554.2 | Non-admin cannot access admin endpoint | Alice GET `/ui/admin/tax-documents/summary`; 403. |
| 554.3 | Document history lists generated documents | After generating 2 summaries, GET `/ui/tax-documents/history`; `documents` array has 2 entries. |
| 554.4 | Only own documents visible | Bob GET `/ui/tax-documents/history`; does not contain Alice's documents. |

**Total E2E tests: 16**

---

## 6. Security Considerations

### 6.1 Auth Requirements

| Endpoint | Auth | Authorization |
|----------|------|---------------|
| Spending summary | `require_ui_session` | Only own ledger data |
| PDF download | `require_ui_session` | Only own documents |
| ZIP export | `require_ui_session` | Only own invoices |
| Year comparison | `require_ui_session` | Only own data |
| Document history | `require_ui_session` | Only own documents |
| Admin summary | `require_admin_session` | Admin or root role |

### 6.2 Data Protection

- Tax documents contain sensitive financial data. S3 storage uses server-side encryption.
- S3 keys include `user_sub` path prefix; no cross-user access possible.
- Generated PDFs include disclaimer: "This document is for informational purposes only."
- ZIP exports are capped at 500 files to prevent resource exhaustion.

### 6.3 Rate Limiting

- Summary API: max 30 requests per user per minute.
- PDF generation: max 10 requests per user per minute.
- ZIP export: max 5 requests per user per hour (resource-intensive).
- Admin summary: standard admin rate limits.

---

## 7. Dependencies

| Dependency | Status | Required For |
|------------|--------|-------------|
| FIN-001 | Required | Invoice records and PDF generation infrastructure (`fpdf2`, S3 patterns) |
| `app/services/billing_shared.py` | Exists | Billing ledger data source; `ledger_sk` format for date-range queries |
| `app/routers/billing.py` | Exists | `GET /billing/ledger` endpoint pattern reference |
| `app/core/tables.py` | Exists (modify) | Add `T.tax_documents` table handle |
| `app/services/profile.py` | Exists | User display name and email for PDF header |
| `app/core/dev_s3.py` | Exists | S3 storage for generated PDFs and ZIPs |
| `scripts/local-ddb-init.py` | Exists (modify) | Add `tax_documents` table definition |
| `fpdf2` | Required (from FIN-001) | PDF rendering |
| `zipfile` (stdlib) | Built-in | ZIP archive generation |

---

## 8. Acceptance Criteria

1. Annual spending summary correctly aggregates billing ledger debit entries by category (subscriptions, tips, purchases, unlocks, deposits).
2. Custom date-range queries filter entries accurately using the `LEDGER#` SK timestamp format.
3. Tax summary PDF is properly formatted with period, buyer info, category table, grand total, and disclaimer.
4. ZIP export bundles individual invoice PDFs for the selected period.
5. Year-over-year comparison shows both years' summaries and a percentage change.
6. Past-year summaries are cached; current-year summaries are computed fresh.
7. Users can only access their own tax documents; admins can access any user's data.
8. All 16 E2E tests pass.
