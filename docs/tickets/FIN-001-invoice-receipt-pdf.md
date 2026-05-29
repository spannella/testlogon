# FIN-001: Invoice / Receipt PDF Download

**Ticket**: FIN-001
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 8-10 days

---

## 1. Overview & Motivation

### 1.1 Purpose

FIN-001 adds downloadable PDF invoices and receipts for every financial transaction on the platform. Consumers need purchase documentation for personal record-keeping, expense reporting, and tax filing. The system generates invoices on demand from billing ledger data, stores them in S3 for repeat downloads, and optionally emails them to the user. A dedicated Invoice History page lets users browse, search, and download past invoices with date-range and transaction-type filters.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Consumer | As a buyer, I want to download a PDF receipt for any purchase I make. | Every completed transaction (tip, unlock, subscription, shop order, wallet deposit) has a downloadable PDF link. |
| Consumer | As a buyer, I want to browse my invoice history filtered by date and type. | Invoice list endpoint supports `date_from`, `date_to`, `type` query params; UI shows searchable list. |
| Consumer | As a buyer, I want each invoice to include proper business details. | PDF contains invoice number, date, buyer/seller info, line items, tax breakdown, total, payment method. |
| Consumer | As a buyer, I want to receive an invoice by email after purchase. | Optional "email invoice" button sends the PDF as attachment to user's email on file. |
| Consumer | As a buyer, I want invoices for subscription renewals generated automatically. | Subscription renewal billing hook writes an invoice record; PDF available in history. |
| Admin | As an admin, I want to look up any user's invoice history. | Admin endpoint returns invoices for a given `user_sub` with same filters. |

### 1.3 Why This Is Needed

The platform processes tips, unlocks, subscription payments, shop purchases, and wallet deposits -- but there is no way to download a formal receipt or invoice for any of them. The billing ledger (`/billing/ledger`) returns raw JSON entries without formatting. Users who need purchase records for expense reports, tax filings, or dispute resolution have no self-service option. This ticket closes that gap with a standards-compliant invoice PDF pipeline.

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

| Component | Location | Relevance |
|-----------|----------|-----------|
| Billing ledger | `app/services/billing_shared.py` (`new_ledger_entry`, `ledger_sk`) | Source data for invoices; each ledger entry has `entry_id`, `ts`, `type`, `amount_cents`, `reason`, `meta` |
| Billing ledger endpoint | `app/routers/billing.py` (`GET /billing/ledger`) | Returns raw ledger entries; items with SK starting `LEDGER#` |
| Payment records | `app/routers/billing.py` (`put_payment_record`, `list_payment_records_ddb`) | Stripe payment intents, status tracking |
| Profile service | `app/services/profile.py` | Buyer display name, email for invoice header |
| Alerts + email | `app/services/alerts.py` (SES `send_email`) | Email delivery infrastructure for invoice attachment |
| S3 mock (moto) | `app/core/dev_s3.py` | File storage for generated PDFs in dev mode |
| Subscription payments | `app/routers/subscription_server.py` | Subscription renewal generates billing entries |
| Shopping cart purchase | `app/services/shoppingcart.py` (`purchase_cart`) | Shop orders generate billing entries + purchase history |
| `ulidish()` | `app/services/billing_shared.py` | Time-sortable unique ID generator |

### 2.2 Gaps

1. **No invoice generation** -- no PDF rendering pipeline; no library (e.g., `reportlab`, `weasyprint`, `fpdf2`) installed.
2. **No invoice number sequence** -- ledger entry IDs are ULIDs, not human-readable invoice numbers (e.g., `INV-2026-00042`).
3. **No invoice storage** -- generated PDFs are not stored for repeat download.
4. **No invoice history endpoint** -- `/billing/ledger` returns raw entries without invoice metadata.
5. **No email delivery for invoices** -- SES integration exists but no invoice-specific email template.
6. **No seller info on ledger entries** -- tips, unlocks, and purchases record the recipient but not their display name or business details at the time of transaction.

---

## 3. Technical Design

### 3.1 DynamoDB Schema

#### 3.1.1 Invoices Table

**Table name**: `invoices` (new table)
**PK**: `pk` (S), **SK**: `sk` (S)

**Single-table design** using prefix patterns:

| PK Pattern | SK Pattern | Purpose | Key Fields |
|------------|------------|---------|------------|
| `USER#{user_sub}` | `INV#{invoice_number}` | User's invoice record | `invoice_number`, `invoice_id`, `user_sub`, `invoice_type` (tip/unlock/subscription/shop/deposit), `amount_cents`, `currency`, `tax_cents`, `total_cents`, `status` (generated/emailed), `ledger_entry_id`, `seller_id`, `seller_name`, `buyer_name`, `buyer_email`, `line_items` (list), `payment_method_summary`, `s3_key`, `created_at` |
| `COUNTER` | `SEQ` | Global invoice number counter | `next_seq` (N) -- atomic counter for `INV-YYYY-NNNNN` |

#### 3.1.2 GSIs

**GSI1** (`GSI1PK` / `GSI1SK`): Invoices by type for filtered listing.
- `GSI1PK`: `USER#{user_sub}#TYPE#{invoice_type}`
- `GSI1SK`: `created_at` (N)
- `attr_types={"GSI1SK": "N"}`

**GSI2** (`GSI2PK` / `GSI2SK`): Admin lookup by user.
- `GSI2PK`: `ADMIN_ALL`
- `GSI2SK`: `created_at` (N)

#### 3.1.3 TableDef Entry

```python
TableDef(
    "invoices", "pk", "sk",
    gsis=[
        {"name": "GSI1", "pk": "GSI1PK", "sk": "GSI1SK"},
        {"name": "GSI2", "pk": "GSI2PK", "sk": "GSI2SK"},
    ],
    attr_types={"GSI1SK": "N", "GSI2SK": "N"},
),
```

#### 3.1.4 Example DynamoDB Items

**Invoice record**:
```json
{
  "pk": "USER#alice@test.local",
  "sk": "INV#INV-2026-00042",
  "invoice_id": "inv_abc123",
  "invoice_number": "INV-2026-00042",
  "user_sub": "alice@test.local",
  "invoice_type": "tip",
  "amount_cents": 500,
  "tax_cents": 0,
  "total_cents": 500,
  "currency": "usd",
  "status": "generated",
  "ledger_entry_id": "01JXYZ...",
  "seller_id": "bob@test.local",
  "seller_name": "Bob Creator",
  "buyer_name": "Alice User",
  "buyer_email": "alice@example.com",
  "line_items": [
    {"description": "Tip on message", "amount_cents": 500, "quantity": 1}
  ],
  "payment_method_summary": "Visa ending 4242",
  "s3_key": "invoices/alice@test.local/INV-2026-00042.pdf",
  "created_at": 1748520100,
  "GSI1PK": "USER#alice@test.local#TYPE#tip",
  "GSI1SK": 1748520100,
  "GSI2PK": "ADMIN_ALL",
  "GSI2SK": 1748520100
}
```

**Counter record**:
```json
{
  "pk": "COUNTER",
  "sk": "SEQ",
  "next_seq": 43
}
```

### 3.2 Invoice Number Generation

Invoice numbers use a globally unique, human-readable format: `INV-{YYYY}-{NNNNN}`.

```python
def _next_invoice_number() -> str:
    """Atomically increment global counter and return formatted invoice number."""
    year = datetime.utcnow().year
    result = T.invoices.update_item(
        Key={"pk": "COUNTER", "sk": "SEQ"},
        UpdateExpression="ADD next_seq :inc",
        ExpressionAttributeValues={":inc": 1},
        ReturnValues="UPDATED_NEW",
    )
    seq = int(result["Attributes"]["next_seq"])
    return f"INV-{year}-{seq:05d}"
```

### 3.2b Pydantic Models

```python
# In app/models.py

class InvoiceLineItemOut(BaseModel):
    description: str
    quantity: int = 1
    amount_cents: int

class InvoiceOut(BaseModel):
    invoice_number: str
    invoice_type: str  # "tip", "unlock", "shop", "subscription", "deposit"
    user_sub: str
    total_cents: int
    currency: str = "usd"
    status: str = "paid"
    created_at: int
    line_items: List[InvoiceLineItemOut]
    buyer_name: Optional[str] = None
    seller_name: Optional[str] = None

class InvoiceListOut(BaseModel):
    invoices: List[InvoiceOut]
    next_cursor: Optional[str] = None
```

### 3.3 PDF Generation

Use `fpdf2` (pure-Python, no system dependencies) to render invoices.

**New dependency**: `fpdf2>=2.8.0` added to `requirements.txt`.

```python
def generate_invoice_pdf(invoice: Dict[str, Any]) -> bytes:
    """Render invoice dict to PDF bytes."""
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 20)
    pdf.cell(0, 10, "INVOICE", align="C", new_x="LMARGIN", new_y="NEXT")
    # ... invoice number, date, buyer/seller blocks, line items table,
    # tax breakdown, total, payment method, footer
    return pdf.output()
```

Generated PDFs are uploaded to S3 under `invoices/{user_sub}/{invoice_number}.pdf` and the `s3_key` is stored on the DynamoDB record.

### 3.4 Backend Service

**New file**: `app/services/invoices.py` (~350 lines)

```python
"""Invoice generation and management (FIN-001)."""

from __future__ import annotations
import logging
from typing import Any, Dict, List, Optional
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)


def create_invoice(
    *,
    user_sub: str,
    invoice_type: str,
    amount_cents: int,
    tax_cents: int,
    line_items: List[Dict[str, Any]],
    seller_id: str,
    seller_name: str,
    buyer_name: str,
    buyer_email: str,
    payment_method_summary: str,
    ledger_entry_id: str,
    currency: str = "usd",
) -> Dict[str, Any]:
    """Create invoice record, generate PDF, upload to S3."""


def get_invoice(user_sub: str, invoice_number: str) -> Optional[Dict[str, Any]]:
    """Retrieve a single invoice record."""


def list_invoices(
    *,
    user_sub: str,
    invoice_type: Optional[str] = None,
    date_from: Optional[int] = None,
    date_to: Optional[int] = None,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """List invoices with optional type/date filters."""


def download_invoice_pdf(user_sub: str, invoice_number: str) -> bytes:
    """Return PDF bytes from S3 (or regenerate if missing)."""


def email_invoice(user_sub: str, invoice_number: str) -> bool:
    """Send invoice PDF as email attachment via SES."""


def admin_list_invoices(
    *,
    target_user_sub: Optional[str] = None,
    limit: int = 100,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """Admin: list invoices, optionally filtered by user."""
```

### 3.5 Backend Router

**New file**: `app/routers/invoices.py` (~180 lines)

```python
"""Invoice management router (FIN-001)."""

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from app.auth.deps import require_ui_session, require_admin_session

router = APIRouter(prefix="/ui/invoices", tags=["invoices"])
admin_router = APIRouter(prefix="/ui/admin/invoices", tags=["invoices-admin"])
```

### 3.6 Router Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/ui/invoices` | `require_ui_session` | List user's invoices (params: `type`, `date_from`, `date_to`, `limit`, `cursor`) |
| `GET` | `/ui/invoices/{invoice_number}` | `require_ui_session` | Get single invoice metadata |
| `GET` | `/ui/invoices/{invoice_number}/pdf` | `require_ui_session` | Download invoice PDF (returns `application/pdf`) |
| `POST` | `/ui/invoices/{invoice_number}/email` | `require_ui_session` | Email invoice to user's address on file |
| `GET` | `/ui/admin/invoices` | `require_admin_session` | Admin: list invoices across users |

### 3.7 Request/Response Models

**Add to `app/models.py`**:

```python
# -- Invoices (FIN-001) --

class InvoiceLineItemOut(BaseModel):
    description: str
    amount_cents: int
    quantity: int = 1

class InvoiceOut(BaseModel):
    invoice_id: str
    invoice_number: str
    invoice_type: str  # tip, unlock, subscription, shop, deposit
    amount_cents: int
    tax_cents: int = 0
    total_cents: int
    currency: str = "usd"
    status: str  # generated, emailed
    seller_name: str = ""
    buyer_name: str = ""
    line_items: List[InvoiceLineItemOut] = Field(default_factory=list)
    payment_method_summary: str = ""
    created_at: int = 0

class InvoiceListOut(BaseModel):
    invoices: List[InvoiceOut] = Field(default_factory=list)
    next_cursor: Optional[str] = None

class InvoiceEmailOut(BaseModel):
    ok: bool
    message: str = ""
```

### 3.8 Billing Hook Integration

Invoice creation is triggered automatically from existing billing flows. Each qualifying transaction calls `create_invoice` after the primary billing entry is written.

**Files to modify with hooks**:

| File | Hook Point | Change |
|------|-----------|--------|
| `app/routers/messaging.py` | Tip payment (`/messages/{id}/tip`) | After tip ledger entry, call `create_invoice(invoice_type="tip")` |
| `app/routers/messaging.py` | Unlock payment (`/messages/{id}/unlock`) | After unlock ledger entry, call `create_invoice(invoice_type="unlock")` |
| `app/routers/newsfeed.py` | Post tip (`/posts/{id}/tip`) | After tip ledger entry, call `create_invoice(invoice_type="tip")` |
| `app/routers/newsfeed.py` | Post unlock (`/posts/{id}/unlock`) | After unlock ledger entry, call `create_invoice(invoice_type="unlock")` |
| `app/services/shoppingcart.py` | Cart purchase (`purchase_cart`) | After purchase ledger entry, call `create_invoice(invoice_type="shop")` |
| `app/routers/billing.py` | Wallet deposit | After deposit ledger entry, call `create_invoice(invoice_type="deposit")` |
| `app/routers/subscription_server.py` | Subscription payment | After renewal ledger entry, call `create_invoice(invoice_type="subscription")` |

### 3.9 Frontend Components

**New files**:

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `frontend/src/pages/billing/InvoicesPage.tsx` | Invoice history page with filters | ~300 |
| `frontend/src/pages/billing/InvoiceRow.tsx` | Single invoice row with download/email actions | ~80 |
| `frontend/src/api/endpoints/invoices.ts` | API client wrappers | ~60 |

**Component tree**:

```
InvoicesPage
├── Filter bar
│   ├── Date range picker (from / to)
│   ├── Type dropdown (All / Tip / Unlock / Subscription / Shop / Deposit)
│   └── Search input (invoice number)
├── Invoice table
│   └── InvoiceRow (for each invoice)
│       ├── Invoice number, date, type badge
│       ├── Amount, seller name
│       ├── Download PDF button (Download icon)
│       └── Email button (Mail icon)
└── Pagination (Load more / cursor-based)
```

### 3.10 Frontend Routes

Add to `frontend/src/App.tsx`:

```typescript
<Route path="/billing/invoices" element={<InvoicesPage />} />
```

Add "Invoices" link to billing sidebar/navigation.

### 3.11 Files to Create

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `app/services/invoices.py` | Invoice service (generation, storage, queries) | ~350 |
| `app/routers/invoices.py` | REST API endpoints | ~180 |
| `frontend/src/pages/billing/InvoicesPage.tsx` | Invoice history UI | ~300 |
| `frontend/src/pages/billing/InvoiceRow.tsx` | Invoice row component | ~80 |
| `frontend/src/api/endpoints/invoices.ts` | API wrappers | ~60 |
| `frontend/e2e/invoices.spec.ts` | E2E tests | ~500 |

### 3.12 Files to Modify

| File | Change |
|------|--------|
| `app/main.py` | Register `invoices_router` and `invoices_admin_router` |
| `app/models.py` | Add Invoice Pydantic models |
| `app/core/settings.py` | Add `invoices_table_name` setting |
| `app/core/tables.py` | Add `T.invoices` table handle |
| `scripts/local-ddb-init.py` | Add `invoices` TableDef with 2 GSIs |
| `requirements.txt` | Add `fpdf2>=2.8.0` |
| `app/routers/messaging.py` | Add invoice creation hook to tip/unlock endpoints |
| `app/routers/newsfeed.py` | Add invoice creation hook to post tip/unlock |
| `app/services/shoppingcart.py` | Add invoice creation hook to `purchase_cart` |
| `app/routers/billing.py` | Add invoice creation hook to wallet deposit |
| `frontend/src/api/types.ts` | Add Invoice TypeScript interfaces |
| `frontend/src/App.tsx` | Add invoices route |

---

## 4. PDF Layout Specification

### 4.1 Page Structure

```
+--------------------------------------------+
|  [Platform Logo]           INVOICE         |
|                                            |
|  Invoice: INV-2026-00042                   |
|  Date: May 29, 2026                        |
|  Payment: Visa ending 4242                 |
|                                            |
|  BILL TO:              SELLER:             |
|  Alice User            Bob Creator         |
|  alice@example.com     bob@example.com     |
|                                            |
|  ----------------------------------------  |
|  Description          Qty     Amount       |
|  ----------------------------------------  |
|  Tip on message         1       $5.00      |
|  ----------------------------------------  |
|  Subtotal                       $5.00      |
|  Tax                            $0.00      |
|  TOTAL                          $5.00      |
|                                            |
|  Thank you for your purchase.              |
+--------------------------------------------+
```

### 4.2 Invoice Types and Line Items

| Invoice Type | Line Item Description | Amount Source |
|-------------|----------------------|--------------|
| `tip` | "Tip on message" / "Tip on post" | `amount_cents` from tip |
| `unlock` | "Unlock: {lock_description}" | `lock_price_cents` |
| `subscription` | "Subscription: {plan_name} ({period})" | Subscription price |
| `shop` | One line per cart item: "{item_name} x{qty}" | Item price * qty |
| `deposit` | "Wallet deposit" | Deposit amount |

### 4.3 Edge Cases

- **Multi-item shop orders**: Each cart item becomes a separate line item in the PDF; subtotal sums all lines.
- **Zero-tax invoices**: Tax line shows `$0.00` but is always present for consistency.
- **Refunded transactions**: If the ledger entry state is `reversed`, the invoice shows "REFUNDED" watermark and negative total.
- **Missing seller info**: Platform transactions (deposits) use the platform name as seller.
- **Re-download**: PDF is served from S3 cache; if S3 key is missing, PDF is regenerated from the DynamoDB record.

---

## 5. E2E Test Plan

**File**: `frontend/e2e/invoices.spec.ts`

### Section 539: Invoice Generation API (5 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 539.1 | Tip creates an invoice automatically | Alice tips Bob $5 via messaging. GET `/ui/invoices` returns invoice with `invoice_type="tip"`, `total_cents=500`. |
| 539.2 | Unlock creates an invoice automatically | Alice unlocks Bob's locked message ($2). GET `/ui/invoices` returns invoice with `invoice_type="unlock"`, `total_cents=200`. |
| 539.3 | Shop purchase creates an invoice | Alice purchases a cart. GET `/ui/invoices` returns invoice with `invoice_type="shop"` and correct line items count. |
| 539.4 | Invoice number follows sequence format | Invoice number matches pattern `INV-2026-\d{5}`. Subsequent invoices increment the number. |
| 539.5 | Duplicate tip does not create duplicate invoice | Verify only one invoice per ledger entry (idempotency check via `ledger_entry_id`). |

### Section 540: Invoice Download API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 540.1 | PDF download returns binary content | GET `/ui/invoices/{number}/pdf`; response `Content-Type: application/pdf`; body starts with `%PDF`. |
| 540.2 | Download own invoice succeeds | Alice downloads her own invoice; 200 response. |
| 540.3 | Download other user's invoice returns 404 | Bob tries to download Alice's invoice number; 404. |
| 540.4 | Non-existent invoice returns 404 | GET `/ui/invoices/INV-9999-99999/pdf`; 404. |

### Section 541: Invoice List and Filter API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 541.1 | List returns all invoices sorted by date descending | GET `/ui/invoices`; response has `invoices` array sorted by `created_at` desc. |
| 541.2 | Filter by type returns only matching invoices | GET `/ui/invoices?type=tip`; all items have `invoice_type="tip"`. |
| 541.3 | Date range filter works | GET with `date_from` and `date_to` params; results within range. |
| 541.4 | Pagination with cursor | GET with `limit=2`; response has `next_cursor`; second page returns remaining invoices. |

### Section 542: Invoice Email and Admin API (3 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 542.1 | Email invoice returns success | POST `/ui/invoices/{number}/email`; response `ok: true`. Invoice status becomes `emailed`. |
| 542.2 | Admin lists all invoices | Root GET `/ui/admin/invoices`; response includes invoices from multiple users. |
| 542.3 | Non-admin cannot access admin endpoint | Alice GET `/ui/admin/invoices`; 403. |

**Total E2E tests: 16**

### Section 543: Invoice Edge Cases & Concurrent Access (5 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 543.1 | Concurrent tips create separate invoices | Alice tips Bob twice rapidly; GET invoices returns exactly 2 tip invoices |
| 543.2 | Invoice for zero-amount transaction not created | Attempt to trigger 0-cent ledger entry; no invoice created |
| 543.3 | Invoice PDF includes correct tax calculation | Download PDF; verify tax line matches expected percentage of subtotal |
| 543.4 | Email invoice idempotent | POST email twice for same invoice; second returns 200 (no duplicate email) |
| 543.5 | Invoice list returns empty for new user | New user with no transactions; GET invoices returns empty array |

**Total E2E tests: 21**

---

## 6. API Request/Response Examples

**List invoices** (curl):

```bash
curl -X GET "http://localhost:8000/ui/invoices?limit=10" \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_a; ui_access_token=eyJ..."
```

**Response (200)**:
```json
{
  "invoices": [
    {
      "invoice_number": "INV-2026-00042",
      "invoice_type": "tip",
      "user_sub": "alice@test.local",
      "total_cents": 500,
      "currency": "usd",
      "status": "paid",
      "created_at": 1748520100,
      "line_items": [
        {"description": "Tip to bob@test.local", "amount_cents": 500}
      ]
    }
  ],
  "next_cursor": null
}
```

**Download invoice PDF** (curl):

```bash
curl -X GET http://localhost:8000/ui/invoices/INV-2026-00042/pdf \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_a; ui_access_token=eyJ..." \
  -o invoice.pdf
```

**Response (200)**: Binary PDF with `Content-Type: application/pdf`.

**Email invoice** (curl):

```bash
curl -X POST http://localhost:8000/ui/invoices/INV-2026-00042/email \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_a; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_a"
```

**Response (200)**:
```json
{"ok": true, "emailed_to": "alice@test.local"}
```

---

## 7. Error Handling Matrix

| Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|----------|-------------|------------|---------------------|-----------------|
| Invoice not found | 404 | `not_found` | "Invoice not found" | Check invoice number |
| Not owner of invoice | 404 | `not_found` | "Invoice not found" | Cannot access others' invoices |
| PDF generation failed | 500 | `internal_error` | "Unable to generate PDF" | Retry; check server logs |
| Email delivery failed | 500 | `email_failed` | "Unable to send email" | Retry later |
| Rate limited (PDF) | 429 | `rate_limited` | "Too many download requests" | Wait 1 minute |
| Rate limited (email) | 429 | `rate_limited` | "Too many email requests" | Wait 1 hour |
| Unauthenticated | 401 | `unauthorized` | "Authentication required" | Log in |
| Admin endpoint without admin role | 403 | `forbidden` | "Admin access required" | Use admin account |

---

## 8. Observability

### 8.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `invoice_created_total` | Counter | `type` (tip/unlock/shop/subscription/deposit) | Invoices created |
| `invoice_pdf_downloaded_total` | Counter | — | PDF downloads |
| `invoice_emailed_total` | Counter | — | Invoices emailed |
| `invoice_pdf_generation_ms` | Histogram | — | PDF generation latency |
| `invoice_creation_latency_ms` | Histogram | `type` | Invoice record creation latency |

### 8.2 Logging

| Event | Level | Fields |
|-------|-------|--------|
| Invoice created | INFO | `invoice_number`, `user_sub`, `type`, `total_cents` |
| Invoice PDF downloaded | INFO | `invoice_number`, `user_sub` |
| Invoice emailed | INFO | `invoice_number`, `user_sub`, `email` |
| Invoice creation failed | ERROR | `user_sub`, `type`, `error` |
| PDF generation failed | ERROR | `invoice_number`, `error` |

### 8.3 Alerts

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| Invoice creation failures | > 1% of transactions miss invoices | High | Check ledger hook integration |
| PDF generation slow | p95 > 5s | Medium | Check fpdf2 performance |
| Email delivery failures | > 5% of email attempts fail | High | Check SES configuration |

---

## 9. Rollout Plan

### 9.1 Feature Flag

```python
invoices_enabled: bool = os.environ.get("INVOICES_ENABLED", "true").lower() == "true"
```

### 9.2 Phased Rollout

| Phase | Description | Duration | Criteria |
|-------|-------------|----------|----------|
| Phase 1: Backend | Deploy invoice table + endpoints; flag OFF | 2 days | Unit tests pass |
| Phase 2: Internal | Enable; verify invoices created for all transaction types | 3 days | All 21 E2E pass |
| Phase 3: Canary 10% | Enable for 10% | 3 days | No missing invoices; PDF quality OK |
| Phase 4: GA | Enable for all | Permanent | No regressions |

### 9.3 Rollback

1. Set `INVOICES_ENABLED=false` — hooks stop creating invoices
2. Existing invoices remain accessible
3. PDF download and email still work for existing invoices
4. Missing invoices can be backfilled from ledger entries

---

## 10. Security Considerations

### 6.1 Auth Requirements

| Endpoint | Auth | Authorization |
|----------|------|---------------|
| List / get invoices | `require_ui_session` | Only own invoices (`user_sub` from session) |
| Download PDF | `require_ui_session` | Only own invoices |
| Email invoice | `require_ui_session` | Only own invoices; email sent to address on profile |
| Admin list | `require_admin_session` | Admin or root role |

### 6.2 Data Protection

- Invoice PDFs stored in S3 with server-side encryption (SSE-S3).
- S3 keys include `user_sub` as path prefix to prevent enumeration.
- Invoice numbers are sequential but non-guessable (user must own the invoice to access it).
- Email delivery uses SES with verified sender; attachment size capped at 5 MB.

### 6.3 Rate Limiting

- PDF download: max 30 requests per user per minute (PDF generation is CPU-intensive).
- Email send: max 5 requests per user per hour (prevent email spam).
- Invoice list: standard API rate limits (60/min).

---

## 11. Performance Considerations

| Concern | Target | Mitigation |
|---------|--------|-----------|
| PDF generation CPU | < 2s per invoice | fpdf2 is lightweight; cache generated PDFs in S3 |
| PDF re-generation on download | Avoid | Generate once on creation; store in S3; serve cached on download |
| Invoice list query | < 50ms for 100 invoices | GSI1 on user_sub + created_at; paginated with cursor |
| Invoice number sequence | Globally unique | DDB atomic counter on `INVOICE_SEQ` item; ADD :1 returns new value |
| Concurrent invoice creation | No duplicates | `ledger_entry_id` ConditionExpression prevents duplicate invoices |
| S3 PDF storage cost | < $0.001 per invoice | Small PDFs (~50-200KB each); lifecycle policy archives after 2 years |
| Email attachment size | < 5MB | PDF size always well under limit; reject if exceeds |

---

## 12. Dependencies

| Dependency | Status | Required For |
|------------|--------|-------------|
| `app/services/billing_shared.py` | Exists | `new_ledger_entry` for ledger entry ID correlation |
| `app/routers/messaging.py` | Exists (modify) | Hook invoice creation into tip/unlock flows |
| `app/routers/newsfeed.py` | Exists (modify) | Hook invoice creation into post tip/unlock flows |
| `app/services/shoppingcart.py` | Exists (modify) | Hook invoice creation into cart purchase |
| `app/routers/billing.py` | Exists (modify) | Hook invoice creation into wallet deposit |
| `app/services/alerts.py` | Exists | SES email for invoice delivery |
| `app/services/profile.py` | Exists | Buyer/seller display names for invoice header |
| `app/core/dev_s3.py` | Exists | S3 storage for generated PDFs |
| `fpdf2` | New dependency | Pure-Python PDF generation library |
| `app/auth/deps.py` | Exists | `require_ui_session`, `require_admin_session` |
| `scripts/local-ddb-init.py` | Exists (modify) | Add `invoices` table definition |

---

## 8. Acceptance Criteria

1. Every completed financial transaction (tip, unlock, subscription payment, shop order, wallet deposit) automatically creates an invoice record.
2. Invoice numbers are globally unique, sequential, and human-readable (`INV-YYYY-NNNNN`).
3. PDF download returns a properly formatted invoice document with buyer/seller info, line items, tax, total, and payment method.
4. Invoice history page lists all invoices with type and date-range filters.
5. Email delivery sends the PDF as an attachment to the user's email address on file.
6. Users can only access their own invoices; admins can access all invoices.
7. All 16 E2E tests pass.
