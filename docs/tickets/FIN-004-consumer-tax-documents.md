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
| Billing ledger | `app/services/billing_shared.py` | `new_ledger_entry` (line 217) writes entries with `type`, `amount_cents`, `reason`, `ts`; `ledger_sk` (line 213) format: `LEDGER#{ts}#{entry_id}` |
<!-- VERIFIED: app/services/billing_shared.py:217 — new_ledger_entry; :213 — ledger_sk; :209 — ulidish -->
| Billing ledger endpoint | `app/routers/billing.py:2274` | `GET /billing/ledger` returns all entries for a user |
<!-- VERIFIED: app/routers/billing.py:2274 — list_ledger endpoint -->
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

### 3.1 Architecture & Data Flow

```
                        +--------------------+
                        |   TaxDocumentsPage |
                        |   (React)          |
                        +--------+-----------+
                                 |
                  +--------------+--------------+
                  |              |               |
           GET /summary   GET /summary/pdf  GET /receipts/zip
                  |              |               |
                  v              v               v
         +-------+-------+  +---+---+    +------+------+
         | tax_documents  |  | fpdf2 |    | zipfile     |
         | router         |  | (PDF) |    | (stdlib)    |
         +-------+-------+  +---+---+    +------+------+
                 |               |               |
                 v               v               v
         +-------+-------+------+-------+-------+-------+
         |           tax_documents service               |
         |  compute_spending_summary()                   |
         |  generate_tax_summary_pdf()                   |
         |  export_receipts_zip()                        |
         +-------+-------+------+-------+-------+-------+
                 |               |               |
                 v               v               v
         +-------+-------+ +----+----+  +-------+-------+
         | billing table  | | S3      |  | profile svc   |
         | LEDGER# range  | | invoices|  | user name/email|
         | query          | | fetch   |  |               |
         +---------+------+ +---------+  +---------------+

Request Flow (Summary):
  1. Frontend sends GET /ui/tax-documents/summary?year=2026
  2. Router extracts user_sub from session, computes date range
  3. Service queries billing table LEDGER# entries in range
  4. Service classifies each entry into tax category
  5. Service aggregates totals per category
  6. Response returned as SpendingSummaryOut JSON

Request Flow (PDF):
  1. Frontend sends GET /ui/tax-documents/summary/pdf?year=2026
  2. Router calls compute_spending_summary for data
  3. Router calls generate_tax_summary_pdf with summary + user info
  4. PDF bytes returned with Content-Type: application/pdf

Request Flow (ZIP):
  1. Frontend sends GET /ui/tax-documents/receipts/zip?year=2026
  2. Router queries invoice records in date range from billing table
  3. For each invoice, fetch PDF from S3
  4. Bundle into in-memory ZIP archive
  5. Return ZIP bytes with Content-Type: application/zip
```

### 3.2 DynamoDB Schema

#### 3.2.1 Tax Documents Table

**Table name**: `tax_documents` (new table)
**PK**: `pk` (S), **SK**: `sk` (S)

| PK Pattern | SK Pattern | Purpose | Key Fields |
|------------|------------|---------|------------|
| `USER#{user_sub}` | `DOC#{year}#{doc_id}` | Generated tax document record | `doc_id`, `user_sub`, `doc_type` (annual_summary / custom_range), `year`, `date_from`, `date_to`, `categories` (map), `grand_total_cents`, `transaction_count`, `currency`, `s3_key`, `created_at` |
| `USER#{user_sub}` | `CACHE#{year}` | Cached annual summary data | `year`, `categories`, `grand_total_cents`, `transaction_count`, `computed_at` |

No GSIs needed -- all queries are by user PK.

#### 3.2.2 Detailed DynamoDB Access Patterns

| Access Pattern | Table | PK | SK / Condition | GSI | Notes |
|----------------|-------|-----|----------------|-----|-------|
| Get cached annual summary | tax_documents | `USER#{user_sub}` | `sk = CACHE#{year}` | None | Single GetItem |
| List generated documents | tax_documents | `USER#{user_sub}` | `begins_with(sk, "DOC#")` | None | Query with SK prefix |
| List documents for a year | tax_documents | `USER#{user_sub}` | `begins_with(sk, "DOC#{year}#")` | None | Narrower SK prefix |
| Query ledger by date range | billing | `USER#{user_sub}` | `between(sk, "LEDGER#{from}#", "LEDGER#{to}#~")` | None | Range query on SK |
| Get invoice records | billing | `USER#{user_sub}` | `begins_with(sk, "INVOICE#")` + filter on created_at | None | Filter for date range |
| Admin: get user summary | tax_documents | `USER#{target_sub}` | `sk = CACHE#{year}` | None | Same as user query with admin auth |
| Write document record | tax_documents | `USER#{user_sub}` | `DOC#{year}#{doc_id}` | None | PutItem |
| Write cache record | tax_documents | `USER#{user_sub}` | `CACHE#{year}` | None | PutItem (overwrite) |

#### 3.2.3 TableDef Entry

```python
TableDef(
    "tax_documents", "pk", "sk",
),
```

#### 3.2.4 Example DynamoDB Items

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

### 3.3 Category Classification

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

### 3.4 Backend Service

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

### 3.5 Backend Router

**New file**: `app/routers/tax_documents.py` (~200 lines)

```python
"""Tax document endpoints (FIN-004)."""

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from app.auth.deps import require_ui_session, require_admin_session

router = APIRouter(prefix="/ui/tax-documents", tags=["tax-documents"])
admin_router = APIRouter(prefix="/ui/admin/tax-documents", tags=["tax-documents-admin"])
```

### 3.6 Router Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/ui/tax-documents/summary` | `require_ui_session` | Get spending summary (params: `year` OR `date_from` + `date_to`) |
| `GET` | `/ui/tax-documents/summary/pdf` | `require_ui_session` | Download tax summary as PDF (same params) |
| `GET` | `/ui/tax-documents/receipts/zip` | `require_ui_session` | Download all receipts in range as ZIP |
| `GET` | `/ui/tax-documents/comparison` | `require_ui_session` | Year-over-year spending comparison (param: `year`) |
| `GET` | `/ui/tax-documents/history` | `require_ui_session` | List previously generated documents |
| `GET` | `/ui/admin/tax-documents/summary` | `require_admin_session` | Admin: get any user's spending summary |

### 3.7 API Request/Response Examples

**GET /ui/tax-documents/summary?year=2026**

Request:
```
GET /ui/tax-documents/summary?year=2026 HTTP/1.1
Cookie: ui_session=...; ui_access_token=...; ui_csrf=...
```

Response (200):
```json
{
  "date_from": 1767225600,
  "date_to": 1798761599,
  "categories": [
    {"category": "subscriptions", "total_cents": 12000, "transaction_count": 12},
    {"category": "tips", "total_cents": 5000, "transaction_count": 8},
    {"category": "purchases", "total_cents": 25000, "transaction_count": 5},
    {"category": "unlocks", "total_cents": 3500, "transaction_count": 7},
    {"category": "deposits", "total_cents": 10000, "transaction_count": 2},
    {"category": "other", "total_cents": 0, "transaction_count": 0}
  ],
  "grand_total_cents": 55500,
  "transaction_count": 34,
  "currency": "usd"
}
```

**GET /ui/tax-documents/summary/pdf?year=2026**

Request:
```
GET /ui/tax-documents/summary/pdf?year=2026 HTTP/1.1
Cookie: ui_session=...; ui_access_token=...; ui_csrf=...
```

Response (200):
```
Content-Type: application/pdf
Content-Disposition: attachment; filename="spending-summary-2026.pdf"

%PDF-1.4 ... (binary PDF content)
```

**GET /ui/tax-documents/receipts/zip?date_from=1767225600&date_to=1798761599**

Response (200):
```
Content-Type: application/zip
Content-Disposition: attachment; filename="receipts-2026.zip"

PK... (binary ZIP content)
```

**GET /ui/tax-documents/comparison?year=2026**

Response (200):
```json
{
  "current_year": 2026,
  "previous_year": 2025,
  "current_summary": {
    "date_from": 1767225600,
    "date_to": 1798761599,
    "categories": [...],
    "grand_total_cents": 55500,
    "transaction_count": 34,
    "currency": "usd"
  },
  "previous_summary": {
    "date_from": 1735689600,
    "date_to": 1767225599,
    "categories": [...],
    "grand_total_cents": 37000,
    "transaction_count": 22,
    "currency": "usd"
  },
  "change_pct": 50.0
}
```

**GET /ui/tax-documents/history**

Response (200):
```json
{
  "documents": [
    {
      "doc_id": "td_abc123",
      "doc_type": "annual_summary",
      "year": 2025,
      "date_from": 1735689600,
      "date_to": 1767225599,
      "grand_total_cents": 37000,
      "transaction_count": 22,
      "created_at": 1748520100
    }
  ]
}
```

**GET /ui/admin/tax-documents/summary?user_sub=alice@test.local&year=2026**

Response (200): Same shape as user summary endpoint.

### 3.8 Request/Response Models

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

### 3.9 Error Handling Matrix

| Error Scenario | HTTP Status | Error Code | Error Message | Recovery Action |
|----------------|-------------|------------|---------------|-----------------|
| Missing date range params | 422 | `validation_error` | "Either 'year' or both 'date_from' and 'date_to' are required" | Provide valid params |
| `date_from` > `date_to` | 422 | `validation_error` | "date_from must be before date_to" | Fix date range |
| Year in the future | 422 | `validation_error` | "Year cannot be in the future" | Use current or past year |
| Year before platform launch | 422 | `validation_error` | "No data available before 2024" | Use valid year |
| No billing data in range | 200 | N/A | Returns zero totals (not an error) | N/A |
| Invoice PDF not found in S3 | 500 | `internal_error` | "Failed to retrieve receipt" | Retry; contact support |
| ZIP exceeds 500 receipts | 400 | `too_many_receipts` | "Too many receipts (max 500). Use a narrower date range." | Narrow date range |
| User not authenticated | 401 | `unauthorized` | "Authentication required" | Login |
| Admin endpoint, non-admin caller | 403 | `forbidden` | "Admin access required" | Use admin account |
| Admin: target user_sub not found | 404 | `user_not_found` | "User not found" | Verify user_sub |
| PDF generation failure | 500 | `pdf_generation_error` | "Failed to generate PDF" | Retry; check logs |
| Rate limit exceeded (PDF) | 429 | `rate_limited` | "Too many requests. Try again in {N} seconds." | Wait and retry |
| Rate limit exceeded (ZIP) | 429 | `rate_limited` | "ZIP export limited to 5 per hour" | Wait and retry |

### 3.10 Tax Summary PDF Layout

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

### 3.11 Frontend Components

**New files**:

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `frontend/src/pages/billing/TaxDocumentsPage.tsx` | Tax documents main page | ~350 |
| `frontend/src/api/endpoints/taxDocuments.ts` | API wrappers | ~60 |

**Component tree with props interfaces**:

```
TaxDocumentsPage
├── Header: "Tax Documents" with FileText icon
├── DateRangeSelector
│   ├── Props: { value: {year?: number, from?: number, to?: number},
│   │           onChange: (range) => void, presets: number[] }
│   ├── Year preset buttons: "2024" / "2025" / "2026"
│   └── Custom range: DatePicker (from) + DatePicker (to)
├── SpendingSummaryCard
│   ├── Props: { summary: SpendingSummaryOut, isLoading: boolean }
│   ├── Grand total (large display)
│   ├── Transaction count
│   └── CategoryBreakdownTable
│       ├── Props: { categories: SpendingCategoryOut[] }
│       ├── Subscriptions: $120.00 (12 transactions)
│       ├── Tips: $50.00 (8 transactions)
│       ├── Purchases: $250.00 (5 transactions)
│       ├── Unlocks: $35.00 (7 transactions)
│       └── Deposits: $100.00 (2 transactions)
├── YearComparisonCard
│   ├── Props: { comparison: YearComparisonOut | null, isLoading: boolean }
│   ├── Current year total vs. previous year total
│   ├── Change percentage (green/red arrow)
│   └── Per-category comparison bars
├── ActionButtons
│   ├── DownloadPdfButton
│   │   └── Props: { year?: number, dateFrom?: number, dateTo?: number,
│   │               isLoading: boolean, onClick: () => void }
│   └── ExportZipButton
│       └── Props: { year?: number, dateFrom?: number, dateTo?: number,
│                   isLoading: boolean, onClick: () => void }
└── DocumentHistoryTable
    ├── Props: { documents: TaxDocumentOut[], isLoading: boolean }
    └── Table of previously generated documents
        ├── Date, type, period, total, download link
        └── Empty state: "No documents generated yet"
```

**Frontend TypeScript interfaces** (add to `frontend/src/api/types.ts`):

```typescript
export interface SpendingCategory {
  category: string;
  total_cents: number;
  transaction_count: number;
}

export interface SpendingSummary {
  date_from: number;
  date_to: number;
  categories: SpendingCategory[];
  grand_total_cents: number;
  transaction_count: number;
  currency: string;
}

export interface YearComparison {
  current_year: number;
  previous_year: number;
  current_summary: SpendingSummary;
  previous_summary: SpendingSummary;
  change_pct: number;
}

export interface TaxDocument {
  doc_id: string;
  doc_type: string;
  year?: number;
  date_from: number;
  date_to: number;
  grand_total_cents: number;
  transaction_count: number;
  created_at: number;
}

export interface TaxDocumentList {
  documents: TaxDocument[];
}
```

**Frontend API wrappers** (`frontend/src/api/endpoints/taxDocuments.ts`):

```typescript
import api from "../client";

export const getSpendingSummary = (params: {
  year?: number; date_from?: number; date_to?: number;
}) => api.get<SpendingSummary>("/ui/tax-documents/summary", { params });

export const downloadSummaryPdf = (params: {
  year?: number; date_from?: number; date_to?: number;
}) => api.get("/ui/tax-documents/summary/pdf", { params, responseType: "blob" });

export const downloadReceiptsZip = (params: {
  year?: number; date_from?: number; date_to?: number;
}) => api.get("/ui/tax-documents/receipts/zip", { params, responseType: "blob" });

export const getYearComparison = (year: number) =>
  api.get<YearComparison>("/ui/tax-documents/comparison", { params: { year } });

export const getDocumentHistory = () =>
  api.get<TaxDocumentList>("/ui/tax-documents/history");
```

### 3.12 Frontend Routes

Add to `frontend/src/App.tsx`:

```typescript
<Route path="/billing/tax-documents" element={<TaxDocumentsPage />} />
```

Add "Tax Documents" link to billing navigation.

### 3.13 Files to Create

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `app/services/tax_documents.py` | Summary computation, PDF generation, ZIP export | ~350 |
| `app/routers/tax_documents.py` | REST API endpoints | ~200 |
| `frontend/src/pages/billing/TaxDocumentsPage.tsx` | Tax documents UI | ~350 |
| `frontend/src/api/endpoints/taxDocuments.ts` | API wrappers | ~60 |
| `frontend/e2e/tax-documents.spec.ts` | E2E tests | ~550 |

### 3.14 Files to Modify

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

## 5. Observability

### 5.1 Metrics

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `tax_doc_summary_requests` | Counter | `year`, `custom_range` | Summary requests by type |
| `tax_doc_pdf_generated` | Counter | `doc_type` | PDF generation count |
| `tax_doc_zip_exported` | Counter | `receipt_count_bucket` | ZIP exports by size bucket |
| `tax_doc_summary_latency_ms` | Histogram | `cache_hit` | Summary computation latency |
| `tax_doc_pdf_latency_ms` | Histogram | | PDF generation latency |
| `tax_doc_zip_latency_ms` | Histogram | `receipt_count_bucket` | ZIP generation latency |
| `tax_doc_cache_hit_rate` | Gauge | | Cache hit ratio for annual summaries |
| `tax_doc_ledger_entries_scanned` | Histogram | | Entries scanned per summary request |

### 5.2 Logging

```python
logger.info("tax_summary_computed", extra={
    "user_sub": user_sub,
    "date_from": date_from,
    "date_to": date_to,
    "grand_total_cents": summary["grand_total_cents"],
    "transaction_count": summary["transaction_count"],
    "cache_hit": cache_hit,
    "duration_ms": duration_ms,
})

logger.info("tax_pdf_generated", extra={
    "user_sub": user_sub,
    "year": year,
    "file_size_bytes": len(pdf_bytes),
    "duration_ms": duration_ms,
})

logger.warning("tax_zip_too_many_receipts", extra={
    "user_sub": user_sub,
    "receipt_count": receipt_count,
    "max_receipts": 500,
})
```

### 5.3 Alerting

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| High PDF generation failure rate | > 5% of PDF requests fail in 5 min window | P2 | Check S3 connectivity and fpdf2 errors |
| ZIP export timeouts | > 3 ZIP requests timeout in 10 min | P3 | Review S3 latency; check receipt count |
| Ledger scan performance | Summary computation > 5s | P3 | Check billing table size; consider pre-aggregation |
| Rate limit spike | > 50 rate-limited requests in 1 hour | P4 | Review for abuse; adjust limits if legitimate |

---

## 6. Rollout Plan

### 6.1 Feature Flag

```python
# app/core/settings.py
tax_documents_enabled: bool = os.environ.get("TAX_DOCUMENTS_ENABLED", "false").lower() == "true"
```

### 6.2 Phased Rollout

| Phase | Duration | Scope | Criteria to Advance |
|-------|----------|-------|---------------------|
| 1. Backend only | 2 days | API endpoints deployed, feature flag off | All unit tests pass; manual API smoke test |
| 2. Internal testing | 3 days | Feature flag on for admin/root users only | Admin generates summaries for test accounts; no errors |
| 3. Beta | 5 days | Feature flag on for 10% of users (by user_sub hash) | < 1% error rate; p99 latency < 3s for summary |
| 4. General availability | Ongoing | Feature flag on for all users | Monitor for 48 hours at 100%; remove feature flag |

### 6.3 Rollback

If critical issues arise:
1. Set `TAX_DOCUMENTS_ENABLED=false` -- endpoints return 503 "Feature temporarily unavailable"
2. No data migration needed -- cached summaries and document records are safe to leave in place
3. Frontend route remains but shows "Coming soon" state when API returns 503

---

## 7. Performance Considerations

### 7.1 Latency Targets

| Endpoint | Target p50 | Target p99 | Max Acceptable |
|----------|-----------|-----------|----------------|
| GET /summary | 200ms | 1500ms | 5000ms |
| GET /summary/pdf | 500ms | 2000ms | 5000ms |
| GET /receipts/zip | 2000ms | 10000ms | 60000ms |
| GET /comparison | 400ms | 3000ms | 10000ms |
| GET /history | 100ms | 500ms | 2000ms |

### 7.2 Caching Strategy

- **Annual summary cache**: Past-year summaries stored in `CACHE#{year}` record. Single GetItem (< 10ms) vs. full ledger scan.
- **PDF caching**: Generated PDFs stored in S3 with key `tax-docs/{user_sub}/{year}-annual-summary.pdf`. Check S3 first; regenerate only if missing or invalidated.
- **No client-side caching**: Tax data may change (current year); set `Cache-Control: no-store` on all responses.

### 7.3 Pagination Approach

- **Ledger scan**: Uses DDB pagination with `LastEvaluatedKey`. Loop until exhausted. For users with thousands of transactions, this may require 3-5 DDB pages (1MB each).
- **Document history**: `Limit=20` with cursor-based pagination for `/history` endpoint.
- **ZIP export**: No pagination -- limited to 500 receipts. Enforced server-side; larger ranges return 400.

### 7.4 Memory Management

- PDF generation: `fpdf2` generates PDFs in memory. For a typical summary (< 1 page), memory usage is < 1MB.
- ZIP export: ZIP buffer is held in memory. For 500 invoices at ~50KB each, worst case is ~25MB. Use `io.BytesIO` and stream directly to response.

---

## 8. E2E Test Plan

**File**: `frontend/e2e/tax-documents.spec.ts`

### Section 551: Spending Summary API (8 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 551.1 | Annual summary returns category breakdown | Seed billing ledger with known entries (tips, unlocks, purchases). GET `/ui/tax-documents/summary?year=2026`. Response has `categories` with correct `total_cents` per type. |
| 551.2 | Custom date range filters correctly | GET with `date_from` and `date_to` params spanning a subset of entries. `grand_total_cents` matches only entries within range. |
| 551.3 | Empty period returns zero totals | GET summary for a year with no transactions. `grand_total_cents: 0`, `categories` array has entries with `total_cents: 0`. |
| 551.4 | Credits are excluded from spending summary | Seed a credit entry (e.g., refund). GET summary. Credit amount not included in `grand_total_cents`. |
| 551.5 | Summary counts distinct transactions | Multiple ledger entries from different categories. `transaction_count` equals total debit entries in range. |
| 551.6 | Subscription entries classified correctly | Seed entry with reason "Subscription renewal". GET summary. `subscriptions.total_cents` includes this entry. |
| 551.7 | Other category captures unclassified debits | Seed entry with reason "Platform fee refund adjustment". GET summary. `other.total_cents` includes this entry. |
| 551.8 | Large transaction count returns accurate total | Seed 50 debit entries. GET summary. `transaction_count` equals 50 and `grand_total_cents` matches sum. |

### Section 552: Tax Summary PDF API (5 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 552.1 | PDF download returns binary content | GET `/ui/tax-documents/summary/pdf?year=2026`; `Content-Type: application/pdf`; body starts with `%PDF`. |
| 552.2 | PDF filename includes year | Response `Content-Disposition` header contains `spending-summary-2026.pdf`. |
| 552.3 | Custom range PDF uses date range in filename | GET with `date_from` + `date_to`; filename contains date range. |
| 552.4 | PDF for empty period still generates | GET PDF for year with no transactions; 200; valid PDF returned with zero totals. |
| 552.5 | Consecutive PDF requests return consistent data | GET PDF twice for same year; file sizes match (deterministic generation). |

### Section 553: Receipts ZIP Export and Comparison API (7 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 553.1 | ZIP export returns archive | GET `/ui/tax-documents/receipts/zip?year=2026`; `Content-Type: application/zip`; body starts with PK zip header (`PK\x03\x04`). |
| 553.2 | ZIP contains expected number of receipts | Generate 3 invoices in date range. ZIP file contains 3 PDF entries. |
| 553.3 | Year comparison returns both years | GET `/ui/tax-documents/comparison?year=2026`; response has `current_year: 2026`, `previous_year: 2025`, both summaries populated. |
| 553.4 | Change percentage calculated correctly | Seed 2025 with $100 total, 2026 with $150 total. `change_pct` approximately 50.0. |
| 553.5 | Comparison with no prior year data returns zero previous | Seed only 2026 data. `previous_summary.grand_total_cents` is 0. |
| 553.6 | Negative change percentage when spending decreases | Seed 2025 with $200 total, 2026 with $100 total. `change_pct` approximately -50.0. |
| 553.7 | ZIP export fails gracefully when no invoices exist | GET ZIP for year with no invoices; 200; empty ZIP or 400 with helpful message. |

### Section 554: Admin and Document History API (6 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 554.1 | Admin can view any user's summary | Root GET `/ui/admin/tax-documents/summary?user_sub=alice&year=2026`; returns Alice's spending data. |
| 554.2 | Non-admin cannot access admin endpoint | Alice GET `/ui/admin/tax-documents/summary`; 403. |
| 554.3 | Document history lists generated documents | After generating 2 summaries, GET `/ui/tax-documents/history`; `documents` array has 2 entries. |
| 554.4 | Only own documents visible | Bob GET `/ui/tax-documents/history`; does not contain Alice's documents. |
| 554.5 | Admin missing user_sub returns 422 | Root GET `/ui/admin/tax-documents/summary?year=2026` (no user_sub); 422. |
| 554.6 | Admin with invalid user_sub returns 404 | Root GET with `user_sub=nonexistent`; 404. |

### Section 555: Tax Documents UI (6 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 555.1 | Tax Documents page loads | Navigate to `/billing/tax-documents`; page heading "Tax Documents" visible. |
| 555.2 | Year preset buttons are visible | Buttons for 2024, 2025, 2026 visible on page. |
| 555.3 | Selecting a year updates summary display | Click "2026" preset; summary card shows grand total and categories. |
| 555.4 | Download PDF button triggers download | Click "Download Summary PDF"; intercept response; content-type is application/pdf. |
| 555.5 | Year comparison card shows delta | Navigate with seeded data; comparison card shows percentage change. |
| 555.6 | Document history table populates | After generating a summary; history table shows at least one row. |

**Total E2E tests: 32**

---

## 9. Security Considerations

### 9.1 Auth Requirements

| Endpoint | Auth | Authorization |
|----------|------|---------------|
| Spending summary | `require_ui_session` | Only own ledger data |
| PDF download | `require_ui_session` | Only own documents |
| ZIP export | `require_ui_session` | Only own invoices |
| Year comparison | `require_ui_session` | Only own data |
| Document history | `require_ui_session` | Only own documents |
| Admin summary | `require_admin_session` | Admin or root role |

### 9.2 Data Protection

- Tax documents contain sensitive financial data. S3 storage uses server-side encryption.
- S3 keys include `user_sub` path prefix; no cross-user access possible.
- Generated PDFs include disclaimer: "This document is for informational purposes only."
- ZIP exports are capped at 500 files to prevent resource exhaustion.

### 9.3 Rate Limiting

- Summary API: max 30 requests per user per minute.
- PDF generation: max 10 requests per user per minute.
- ZIP export: max 5 requests per user per hour (resource-intensive).
- Admin summary: standard admin rate limits.

---

## 10. Dependencies

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

## 11. Acceptance Criteria

1. Annual spending summary correctly aggregates billing ledger debit entries by category (subscriptions, tips, purchases, unlocks, deposits).
2. Custom date-range queries filter entries accurately using the `LEDGER#` SK timestamp format.
3. Tax summary PDF is properly formatted with period, buyer info, category table, grand total, and disclaimer.
4. ZIP export bundles individual invoice PDFs for the selected period.
5. Year-over-year comparison shows both years' summaries and a percentage change.
6. Past-year summaries are cached; current-year summaries are computed fresh.
7. Users can only access their own tax documents; admins can access any user's data.
8. All 32 E2E tests pass.
9. Feature flag controls rollout; endpoints return 503 when disabled.
10. Observability metrics and logging are in place for all endpoints.

---

## Codebase References

### Existing Files (verified)
| File | Key Functions | Lines |
|------|--------------|-------|
| `app/services/billing_shared.py` | `new_ledger_entry`, `ledger_sk`, `ulidish` | 217, 213, 209 |
| `app/routers/billing.py` | `GET /billing/ledger` (`list_ledger`) | 2274 |
| `app/services/receipts.py` | `get_or_create_receipt`, `_render_pdf` | 199, 53 |
| `scripts/local-ddb-init.py` | `billing` table | 59 |

### Files to Create (new implementation)
| File | Purpose |
|------|---------|
| `app/services/tax_documents.py` | Tax summary computation, PDF generation, caching |
| Tax documents DDB table | Table definition in `scripts/local-ddb-init.py` |
| Frontend Tax Documents page | Date picker + summary display + PDF download |

---

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_tax_documents.py`

| # | Test Function | Description | Mocks |
|---|--------------|-------------|-------|
| 1 | `test_fin_004_create_basic` | Core creation logic succeeds with valid inputs | moto DDB |
| 2 | `test_fin_004_validation_rejects_invalid` | 400/422 for invalid inputs | moto DDB |
| 3 | `test_fin_004_pagination` | Cursor-based pagination returns correct pages | moto DDB |
| 4 | `test_fin_004_auth_required` | 401 for unauthenticated requests | moto DDB |
| 5 | `test_fin_004_forbidden_wrong_user` | 403 when non-owner accesses restricted resource | moto DDB |
| 6 | `test_fin_004_not_found` | 404 for non-existent resource | moto DDB |
| 7 | `test_fin_004_duplicate_rejected` | 409 for duplicate creation | moto DDB |
| 8 | `test_fin_004_feature_flag_off` | Feature disabled returns 404 when flag is off | moto DDB |

### Integration Tests

| # | Scenario | Services Involved |
|---|----------|-------------------|
| 1 | Full CRUD lifecycle: create, read, update, delete | Service layer, DDB |
| 2 | Cross-service interaction with dependent features | Multiple service modules |
| 3 | Concurrent access patterns do not corrupt data | Service layer, parallel requests |

### E2E Tests (Playwright)

**File**: `frontend/e2e/tax-documents.spec.ts`

Tests use `injectAuth(page, identity)` for cookie-based auth and include CSRF headers (`x-csrf-token`) on all POST/PUT/DELETE requests. Negative tests cover 401 (unauthenticated), 403 (wrong role/user), 404 (not found), 409 (conflict), and 422 (validation) responses. Edge cases include duplicate operations (idempotency), concurrent access, and feature-flag-disabled behavior.

**Total E2E tests**: 10

### Test Data Requirements

- DDB seeds: required tables created via `scripts/local-ddb-init.py`
- Test users: Alice, Bob, Root, Charlie via `e2e_session_setup.py` / `e2e_admin_session_setup.py`
- Feature flag: `TAX_DOCUMENTS_ENABLED` in `.env.local`

### CI/Pipeline

- Feature flag: `TAX_DOCUMENTS_ENABLED` must be enabled for tests to run
- Serial execution: run with `--workers 1` to avoid shared state conflicts
- Retry safety: tests use unique timestamps/UUIDs per run; safe to retry on failure

---

## Dependencies & Merge Safety

### Depends On

| Ticket | Status | What It Provides |
|--------|--------|-----------------|
| (none) | -- | This ticket has no upstream ticket dependencies |

### Depended On By

| Ticket | What It Needs |
|--------|--------------|
| (none currently) | -- |

### Merge Strategy

**Independent** -- Changes are additive (new service files, new router, new frontend pages). Shared infrastructure files (`main.py`, `settings.py`, `tables.py`, `local-ddb-init.py`) receive only additive modifications.

### Merge Checklist

- [ ] All new DDB tables/GSIs added to `scripts/local-ddb-init.py`
- [ ] Settings added to `app/core/settings.py`
- [ ] Table handles added to `app/core/tables.py`
- [ ] Router registered in `app/main.py`
- [ ] Frontend routes added to `App.tsx`
- [ ] Feature flag `TAX_DOCUMENTS_ENABLED` added to `.env.local.example`
- [ ] All E2E tests pass
- [ ] No regressions in existing test suite
