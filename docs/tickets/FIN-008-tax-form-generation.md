# FIN-008: Tax Form Generation (1099/W-9)

**Ticket**: FIN-008
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 12-16 days

---

## 1. Overview & Motivation

### 1.1 Purpose

FIN-008 implements tax compliance infrastructure for the platform: TIN/SSN collection from creators via a W-9 equivalent form, encrypted storage of tax identifiers, annual 1099-NEC generation for creators earning above the IRS threshold ($600), and PDF download of generated forms. This is a legal requirement for any US-based platform that pays independent contractors (creators) more than $600/year.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Creator | As a creator, I want to submit my tax information (W-9). | W-9 form with name, address, TIN fields; submitted and stored encrypted. |
| Creator | As a creator, I want to see my submitted tax info (masked). | Tax info page shows `***-**-1234` (last 4 of TIN), name, address. |
| Creator | As a creator, I want to update my tax information. | Edit form pre-fills non-sensitive fields; TIN must be re-entered. |
| Creator | As a creator, I want to download my 1099-NEC for a tax year. | PDF download link for each year where earnings exceeded $600. |
| Admin | As an admin, I want to view which creators have submitted tax info. | Admin list shows creators with submission status and date. |
| Admin | As an admin, I want to generate 1099-NEC forms for a tax year. | Batch generation endpoint processes all qualifying creators. |
| Admin | As an admin, I want to view the full TIN for a specific creator. | Audit-logged TIN reveal for compliance review. |
| System | TIN/SSN must be encrypted at rest with KMS. | TIN stored as KMS-encrypted ciphertext; only decryptable for 1099 generation. |

### 1.3 Why This Is Needed

IRS regulations require platforms paying non-employee compensation to:
1. Collect a W-9 (or equivalent) from each payee.
2. Issue a 1099-NEC to any payee receiving $600 or more in a calendar year.
3. File 1099-NEC forms with the IRS by January 31 of the following year.

Without this feature, the platform has no mechanism to collect TINs, calculate annual earnings thresholds, generate compliant tax forms, or distribute them to creators.

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

| Component | Location | Relevance |
|-----------|----------|-----------|
| KMS crypto | `app/core/crypto.py` | `kms_encrypt` / `kms_decrypt` functions for sensitive data |
| Mock KMS | `scripts/mock_kms_server.py` (port 7999) | Local KMS mock for dev/test encryption |
| Creator earnings | `app/services/creator_earnings.py` | `get_earnings_summary` aggregates annual credits |
| Creator payouts | `app/services/creator_payouts.py` | Payout records per creator |
| Billing ledger | `app/services/billing_shared.py` | All financial transactions |
| Settings | `app/core/settings.py` | Config via env vars; KMS key ID configured |
| Profile service | `app/services/profile.py` | Creator profile with name, address |

### 2.2 KMS Encryption Pattern

From `app/core/crypto.py`:

```python
def kms_encrypt(plaintext: str) -> str:
    """Encrypt plaintext using KMS. Returns base64-encoded ciphertext."""
    ...

def kms_decrypt(ciphertext_b64: str) -> str:
    """Decrypt KMS-encrypted ciphertext. Returns plaintext string."""
    ...
```

The mock KMS server on port 7999 provides encryption/decryption for local dev. TIN/SSN values will be encrypted using these functions before storage.

### 2.3 Gaps

1. **No tax info collection** -- no W-9 form or TIN storage.
2. **No encrypted PII storage** for tax identifiers.
3. **No 1099-NEC generation** logic or PDF rendering.
4. **No annual earnings threshold check** to determine who qualifies.
5. **No admin tools** for managing tax submissions or batch 1099 generation.
6. **No audit logging** for TIN access.

---

## 3. Technical Design

### 3.1 Data Model

#### 3.1.1 Tax Info Record (Billing Table)

**PK**: `USER#{user_id}`, **SK**: `TAX_INFO`

| Field | Type | Description |
|-------|------|-------------|
| `legal_name` | S | Full legal name (as on tax return) |
| `business_name` | S | Business name (if different from legal name) |
| `tax_classification` | S | `"individual"`, `"sole_proprietor"`, `"llc"`, `"corporation"`, `"partnership"`, `"trust"` |
| `address_line1` | S | Street address |
| `address_line2` | S | Suite/apt (optional) |
| `city` | S | City |
| `state` | S | State code (2-letter) |
| `zip_code` | S | ZIP code |
| `tin_encrypted` | S | KMS-encrypted TIN/SSN (base64) |
| `tin_last4` | S | Last 4 digits of TIN (for display) |
| `tin_type` | S | `"ssn"` or `"ein"` |
| `certified_at` | N | Timestamp of W-9 certification |
| `certified_signature` | S | Electronic signature (typed name) |
| `submitted_at` | N | First submission timestamp |
| `updated_at` | N | Last update timestamp |
| `status` | S | `"active"`, `"expired"`, `"invalid"` |

#### 3.1.2 Generated 1099-NEC Record (Billing Table)

**PK**: `USER#{user_id}`, **SK**: `TAX_1099#{tax_year}`

| Field | Type | Description |
|-------|------|-------------|
| `tax_year` | N | Calendar year (e.g., 2026) |
| `total_earnings_cents` | N | Total non-employee compensation for the year |
| `qualifies` | BOOL | Whether earnings exceed $600 threshold |
| `generated_at` | N | When the 1099 was generated |
| `pdf_s3_key` | S | S3 key for the generated PDF |
| `status` | S | `"generated"`, `"distributed"`, `"corrected"` |
| `correction_id` | S | If corrected, reference to the corrected version |
| `payer_tin_last4` | S | Platform's TIN last 4 (for display on form) |

#### 3.1.3 Tax Info Admin Index (Billing Table)

**GSI**: `ByTaxStatus` (new GSI on billing table)
**PK**: `TAX_STATUS#{status}`, **SK**: `{submitted_at}#{user_id}`

Allows admin to query all creators by tax info status (active, expired, missing).

#### 3.1.4 TIN Access Audit Log (Billing Table)

**PK**: `TAX_AUDIT`, **SK**: `{timestamp}#{audit_id}`

| Field | Type | Description |
|-------|------|-------------|
| `audit_id` | S | Unique ID |
| `action` | S | `"tin_viewed"`, `"1099_generated"`, `"tax_info_updated"` |
| `actor_user_id` | S | Who performed the action |
| `target_user_id` | S | Whose TIN was accessed |
| `ip_address` | S | Actor's IP address |
| `created_at` | N | Timestamp |

### 3.2 Backend Service

**New file**: `app/services/tax_forms.py` (~450 lines)

```python
"""Tax form collection and 1099-NEC generation (FIN-008)."""

from __future__ import annotations
import logging
from typing import Any, Dict, List, Optional
from app.core.tables import T
from app.core.time import now_ts
from app.core.crypto import kms_encrypt, kms_decrypt

logger = logging.getLogger(__name__)

IRS_THRESHOLD_CENTS = 60000  # $600.00


def submit_tax_info(
    user_id: str,
    *,
    legal_name: str,
    business_name: str = "",
    tax_classification: str,
    address_line1: str,
    address_line2: str = "",
    city: str,
    state: str,
    zip_code: str,
    tin: str,
    tin_type: str,
    certified_signature: str,
) -> Dict[str, Any]:
    """Submit or update W-9 equivalent tax info.

    TIN is encrypted via KMS before storage.
    Only last 4 digits are stored in plaintext for display.
    """
    ...


def get_tax_info(user_id: str) -> Optional[Dict[str, Any]]:
    """Get tax info for a user. TIN returned as masked (last 4 only)."""
    ...


def get_tax_info_admin(
    user_id: str,
    admin_user_id: str,
    ip_address: str,
) -> Optional[Dict[str, Any]]:
    """Admin: get full tax info including decrypted TIN. Audit-logged."""
    ...


def list_tax_submissions(
    status: str = "active",
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """Admin: list creators by tax info status."""
    ...


def generate_1099(
    user_id: str,
    tax_year: int,
) -> Dict[str, Any]:
    """Generate a 1099-NEC for a single creator for a tax year.

    1. Calculate total earnings for the year from billing ledger.
    2. Check if earnings exceed IRS threshold ($600).
    3. Decrypt TIN for form generation.
    4. Render PDF and upload to S3.
    5. Write 1099 record to DDB.
    """
    ...


def batch_generate_1099s(
    tax_year: int,
    admin_user_id: str,
) -> Dict[str, Any]:
    """Admin: generate 1099-NEC for all qualifying creators.

    Returns: {total_creators, qualifying, generated, errors}
    """
    ...


def get_1099(user_id: str, tax_year: int) -> Optional[Dict[str, Any]]:
    """Get 1099 record for a user and tax year."""
    ...


def list_1099s(user_id: str) -> List[Dict[str, Any]]:
    """List all 1099s for a creator."""
    ...


def download_1099_pdf(user_id: str, tax_year: int) -> Optional[str]:
    """Get presigned S3 URL for 1099 PDF download."""
    ...


def _write_tax_audit(
    action: str,
    actor_user_id: str,
    target_user_id: str,
    ip_address: str = "",
) -> None:
    """Write an entry to the tax audit log."""
    ...


def _render_1099_pdf(
    payer_info: Dict[str, Any],
    recipient_info: Dict[str, Any],
    amount_cents: int,
    tax_year: int,
) -> bytes:
    """Render a 1099-NEC PDF.

    Uses reportlab or a template-based approach.
    Returns PDF bytes.
    """
    ...
```

### 3.3 Backend Router

**New file**: `app/routers/tax_forms.py` (~180 lines)

### 3.4 Router Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/ui/tax/w9` | `require_ui_session` | Submit or update W-9 tax info |
| `GET` | `/ui/tax/info` | `require_ui_session` | Get own tax info (TIN masked) |
| `GET` | `/ui/tax/1099s` | `require_ui_session` | List own 1099-NEC forms |
| `GET` | `/ui/tax/1099s/{tax_year}` | `require_ui_session` | Get specific 1099 details |
| `GET` | `/ui/tax/1099s/{tax_year}/download` | `require_ui_session` | Download 1099 PDF |
| `GET` | `/ui/admin/tax/submissions` | `require_admin_session` | List all tax submissions |
| `GET` | `/ui/admin/tax/info/{user_id}` | `require_admin_session` | View full tax info (audit-logged) |
| `POST` | `/ui/admin/tax/generate-1099s` | `require_admin_session` | Batch generate 1099s for a year |
| `GET` | `/ui/admin/tax/audit` | `require_admin_session` | View tax audit log |

### 3.5 Request/Response Models

**Add to `app/models.py`**:

```python
# -- Tax Form Generation (FIN-008) --

class W9SubmissionIn(BaseModel):
    legal_name: str = Field(min_length=2, max_length=200)
    business_name: str = Field(default="", max_length=200)
    tax_classification: str = Field(pattern="^(individual|sole_proprietor|llc|corporation|partnership|trust)$")
    address_line1: str = Field(min_length=5, max_length=200)
    address_line2: str = Field(default="", max_length=200)
    city: str = Field(min_length=2, max_length=100)
    state: str = Field(min_length=2, max_length=2)
    zip_code: str = Field(pattern=r"^\d{5}(-\d{4})?$")
    tin: str = Field(min_length=9, max_length=11)
    tin_type: str = Field(pattern="^(ssn|ein)$")
    certified_signature: str = Field(min_length=2, max_length=200)

class TaxInfoOut(BaseModel):
    legal_name: str = ""
    business_name: str = ""
    tax_classification: str = ""
    address_line1: str = ""
    address_line2: str = ""
    city: str = ""
    state: str = ""
    zip_code: str = ""
    tin_masked: str = ""  # "***-**-1234"
    tin_type: str = ""
    certified_at: int = 0
    status: str = ""
    submitted_at: int = 0
    updated_at: int = 0

class TaxInfoAdminOut(TaxInfoOut):
    tin_full: str = ""  # Decrypted TIN (admin only, audit-logged)
    user_id: str = ""

class Form1099Out(BaseModel):
    tax_year: int
    total_earnings_cents: int = 0
    qualifies: bool = False
    generated_at: int = 0
    status: str = ""
    download_url: Optional[str] = None

class Form1099ListOut(BaseModel):
    items: List[Form1099Out] = Field(default_factory=list)

class BatchGenerate1099In(BaseModel):
    tax_year: int = Field(ge=2020, le=2030)

class BatchGenerate1099Out(BaseModel):
    tax_year: int
    total_creators: int = 0
    qualifying: int = 0
    generated: int = 0
    errors: int = 0

class TaxSubmissionListItem(BaseModel):
    user_id: str
    legal_name: str
    status: str
    submitted_at: int = 0
    certified_at: int = 0

class TaxSubmissionListOut(BaseModel):
    items: List[TaxSubmissionListItem] = Field(default_factory=list)
    next_cursor: Optional[str] = None

class TaxAuditEntryOut(BaseModel):
    audit_id: str
    action: str
    actor_user_id: str
    target_user_id: str
    created_at: int
```

### 3.6 TIN Encryption Flow

```
User submits TIN "123-45-6789"
  → Strip non-digits: "123456789"
  → Store last4: "6789"
  → KMS encrypt: kms_encrypt("123456789") → base64 ciphertext
  → Store in DDB: tin_encrypted = ciphertext, tin_last4 = "6789"
  → Return to user: tin_masked = "***-**-6789"
```

Decryption occurs only during:
1. 1099 generation (system, audit-logged)
2. Admin full TIN reveal (audit-logged with IP)

### 3.7 1099-NEC PDF Generation

The 1099-NEC PDF is rendered using a template approach:

1. Load a blank 1099-NEC form template (static PDF with form fields).
2. Fill in payer info (platform name, address, TIN).
3. Fill in recipient info (creator name, address, TIN).
4. Fill in Box 1: Nonemployee compensation amount.
5. Fill in tax year.
6. Save as PDF bytes and upload to S3.

For v1, use `reportlab` to generate a simplified 1099-NEC layout. Full IRS-compliant formatting is a future enhancement.

### 3.8 Frontend Components

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `frontend/src/pages/tax/TaxInfoPage.tsx` | W-9 form + 1099 downloads | ~400 |
| `frontend/src/pages/admin/TaxAdminPage.tsx` | Admin tax management | ~250 |
| `frontend/src/api/endpoints/tax.ts` | API wrappers | ~50 |

**Component tree for TaxInfoPage**:

```
TaxInfoPage
├── Card: "Tax Information (W-9)"
│   ├── Status Badge: "Active" / "Not Submitted" / "Expired"
│   ├── Form (when editing or first submission)
│   │   ├── Legal Name input
│   │   ├── Business Name input (optional)
│   │   ├── Tax Classification select
│   │   ├── Address fields (line1, line2, city, state, zip)
│   │   ├── TIN Type radio (SSN / EIN)
│   │   ├── TIN input (masked, 9 digits)
│   │   ├── Certification checkbox
│   │   ├── Electronic Signature input
│   │   └── Button: "Submit W-9"
│   └── Display (when submitted)
│       ├── Name, Address, Classification (read-only)
│       ├── TIN: "***-**-6789"
│       ├── Certified: date
│       └── Button: "Update Tax Info"
└── Card: "Tax Forms (1099-NEC)"
    ├── Table of available 1099s
    │   ├── Column: Tax Year
    │   ├── Column: Earnings
    │   ├── Column: Status
    │   └── Column: Download (PDF icon)
    └── Info text: "1099-NEC forms are generated annually for earnings over $600."
```

### 3.9 Files to Create

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `app/services/tax_forms.py` | Tax info + 1099 generation service | ~450 |
| `app/routers/tax_forms.py` | Tax API endpoints | ~180 |
| `frontend/src/pages/tax/TaxInfoPage.tsx` | W-9 form + 1099 downloads UI | ~400 |
| `frontend/src/pages/admin/TaxAdminPage.tsx` | Admin tax management UI | ~250 |
| `frontend/src/api/endpoints/tax.ts` | API wrappers | ~50 |
| `frontend/e2e/fin-tax-forms.spec.ts` | E2E tests | ~420 |

### 3.10 Files to Modify

| File | Change |
|------|--------|
| `app/main.py` | Register `tax_forms` router |
| `app/models.py` | Add tax form models |
| `scripts/local-ddb-init.py` | Add tax-related GSI to billing table if needed |
| `frontend/src/api/types.ts` | Add TypeScript interfaces |
| `frontend/src/App.tsx` | Add `/tax` and admin tax routes |
| `frontend/src/components/layout/Sidebar.tsx` | Add Tax link under Billing group |

---

## 4. Security and Compliance

### 4.1 PII Protection

- TIN/SSN is encrypted using KMS before storage. Plaintext TIN never touches DynamoDB.
- Only the last 4 digits are stored in plaintext for display purposes.
- TIN input fields use `type="password"` and are never cached/autocompleted.
- API responses for non-admin endpoints never include full TIN.

### 4.2 Access Control

- Creator can only access their own tax info and 1099 forms.
- Admin TIN reveal is audit-logged with actor ID and IP address.
- Batch 1099 generation requires admin role.

### 4.3 Encryption at Rest

- TIN: KMS-encrypted (`kms_encrypt`).
- 1099 PDFs: Stored in S3 with server-side encryption (SSE-S3 in prod; moto mock in dev).
- DynamoDB: Encryption at rest enabled (default in prod).

### 4.4 Audit Requirements

Every access to unmasked TIN data is logged to `TAX_AUDIT`:
- Admin viewing full TIN
- System decrypting TIN for 1099 generation
- Tax info updates (old/new TIN encrypted separately in audit, not in plaintext)

---

## 5. E2E Test Plan

**File**: `frontend/e2e/fin-tax-forms.spec.ts`

### Section 567: W-9 Submission API (5 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 567.1 | Submit W-9 with valid SSN | POST /tax/w9 with valid data; 200; status = "active" |
| 567.2 | Get own tax info returns masked TIN | GET /tax/info; tin_masked = "***-**-XXXX" (last 4 match) |
| 567.3 | Update tax info replaces previous | POST /tax/w9 with new address; GET reflects new address |
| 567.4 | Invalid TIN format rejected | POST with tin="123"; 422 validation error |
| 567.5 | Invalid state code rejected | POST with state="XX"; 422 validation error |

### Section 568: 1099-NEC Generation API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 568.1 | Generate 1099 for creator above threshold | Seed $1000 in credits; POST generate; 200; qualifies = true |
| 568.2 | Creator below threshold gets qualifies=false | Seed $100 in credits; generate; qualifies = false |
| 568.3 | List 1099s returns generated forms | GET /tax/1099s; items array includes the generated 1099 |
| 568.4 | Download 1099 returns PDF URL | GET /tax/1099s/{year}/download; response has download_url |

### Section 569: Admin Tax Management API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 569.1 | Admin can list tax submissions | GET /admin/tax/submissions; 200; items array with submissions |
| 569.2 | Admin can view full TIN (audit-logged) | GET /admin/tax/info/{user_id}; tin_full is 9-digit string |
| 569.3 | Non-admin cannot access admin tax endpoints | Alice GET /admin/tax/submissions; 403 |
| 569.4 | TIN reveal creates audit log entry | GET audit log after TIN reveal; entry with action="tin_viewed" |

### Section 570: Tax Info UI (5 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 570.1 | Tax page shows W-9 form when no info submitted | Navigate to /tax; form fields visible |
| 570.2 | Submit W-9 form updates status to Active | Fill form; submit; "Active" badge visible |
| 570.3 | Submitted info displays masked TIN | After submission; page shows "***-**-XXXX" |
| 570.4 | 1099 section shows available forms | After 1099 generation; table row with tax year visible |
| 570.5 | Update Tax Info button reveals form | Click "Update Tax Info"; form fields become editable |

**Total E2E tests: 18**

---

## 6. Dependencies

| Dependency | Status | Required For |
|------------|--------|-------------|
| `app/core/crypto.py` | Exists | KMS encryption of TIN |
| `scripts/mock_kms_server.py` | Exists | Local dev TIN encryption |
| `app/services/creator_earnings.py` | Exists | Annual earnings calculation for 1099 threshold |
| `app/services/billing_shared.py` | Exists | Billing ledger queries |
| S3 (moto mock) | Exists | 1099 PDF storage |
| `reportlab` (new dependency) | Needs install | PDF generation |

---

## 7. Acceptance Criteria

1. Creator can submit W-9 equivalent form with TIN.
2. TIN is KMS-encrypted before storage; only last 4 stored in plaintext.
3. Creator sees masked TIN on tax info page.
4. 1099-NEC is generated for creators earning above $600 in a calendar year.
5. Creator can download 1099 PDF from dashboard.
6. Admin can list tax submissions and view full TIN (audit-logged).
7. Admin can batch-generate 1099s for a tax year.
8. All TIN access is audit-logged.
9. All 18 E2E tests pass.
