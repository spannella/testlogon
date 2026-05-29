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
| KMS crypto | `app/core/crypto.py:16` | `kms_encrypt` / `kms_decrypt` functions for sensitive data |
<!-- VERIFIED: app/core/crypto.py:16 — kms_encrypt -->
| Mock KMS | `scripts/mock_kms_server.py` (port 7999) | Local KMS mock for dev/test encryption |
| Creator earnings | `app/services/creator_earnings.py:47` | `get_earnings_summary` aggregates annual credits |
<!-- VERIFIED: app/services/creator_earnings.py:47 — get_earnings_summary -->
| Creator payouts | `app/services/creator_payouts.py:55` | `get_available_balance`, payout records |
<!-- VERIFIED: app/services/creator_payouts.py:55 — get_available_balance -->
| Billing ledger | `app/services/billing_shared.py:217` | `new_ledger_entry` — all financial transactions |
<!-- VERIFIED: app/services/billing_shared.py:217 — new_ledger_entry -->
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

### 3.1 Architecture & Data Flow

```
W-9 Submission Flow
===================

  Browser (TaxInfoPage)
       |
       | POST /ui/tax/w9  { legal_name, tin, ... }
       v
  +--------------------+
  | tax_forms router   |  (app/routers/tax_forms.py)
  | require_ui_session |
  +--------------------+
       |
       v
  +---------------------+      +-------------------+
  | tax_forms service    |----->| KMS (port 7999)   |
  | submit_tax_info()    |      | kms_encrypt(tin)  |
  +---------------------+      +-------------------+
       |                              |
       | writes encrypted             | returns base64
       v                              | ciphertext
  +--------------------+
  | billing DDB table  |  PK=USER#{id}, SK=TAX_INFO
  | tin_encrypted      |  (base64 KMS ciphertext)
  | tin_last4          |  ("6789" -- plaintext last 4)
  +--------------------+


1099-NEC Generation Flow
========================

  Admin triggers batch generation
       |
       | POST /ui/admin/tax/generate-1099s { tax_year: 2026 }
       v
  +----------------------+
  | batch_generate_1099s |
  | for each creator:    |
  |   1. query ledger    |
  |      sum credits     |
  |   2. check >= $600   |
  |   3. decrypt TIN     |
  |      (KMS)           |
  |   4. render PDF      |
  |      (reportlab)     |
  |   5. upload S3       |
  |   6. write 1099 rec  |
  +----------------------+
       |
       v
  +-------------------+      +-------------------+
  | billing DDB       |      | S3 (moto mock)    |
  | PK=USER#{id}      |      | tax-forms/2026/   |
  | SK=TAX_1099#2026  |      |   user_abc.pdf    |
  +-------------------+      +-------------------+


TIN Decryption Audit Flow
=========================

  Admin views full TIN
       |
       | GET /ui/admin/tax/info/{user_id}
       v
  +---------------------+      +------------------+
  | get_tax_info_admin   |----->| KMS decrypt      |
  | audit_logged: YES    |      | kms_decrypt(blob)|
  +---------------------+      +------------------+
       |
       | writes audit record
       v
  +-------------------+
  | billing DDB       |
  | PK=TAX_AUDIT      |
  | SK={ts}#{id}      |
  | action=tin_viewed  |
  +-------------------+
```

### 3.2 Detailed DynamoDB Access Patterns

| # | Access Pattern | Table | Key Condition | GSI | Notes |
|---|---------------|-------|--------------|-----|-------|
| 1 | Get tax info for user | billing | `PK=USER#{user_id}, SK=TAX_INFO` | -- | Single GetItem |
| 2 | Get 1099 for user+year | billing | `PK=USER#{user_id}, SK=TAX_1099#{tax_year}` | -- | Single GetItem |
| 3 | List all 1099s for user | billing | `PK=USER#{user_id}, SK begins_with TAX_1099#` | -- | Query on SK prefix |
| 4 | List creators by tax status | billing | `PK=TAX_STATUS#{status}, SK={submitted_at}#{user_id}` | ByTaxStatus | Paginated GSI query |
| 5 | Write tax audit entry | billing | `PK=TAX_AUDIT, SK={ts}#{audit_id}` | -- | PutItem |
| 6 | List tax audit entries | billing | `PK=TAX_AUDIT, SK begins_with {prefix}` | -- | Query sorted by SK |
| 7 | Sum annual earnings | billing | `PK=USER#{user_id}, SK begins_with LEDGER#` | -- | Query + filter entry_type=*_credit, filter by year |
| 8 | Batch scan all creators with TAX_INFO | billing | Full scan with SK=TAX_INFO filter | -- | Used by batch_generate_1099s; paginated scan |

### 3.3 Data Model

#### 3.3.1 Tax Info Record (Billing Table)

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

#### 3.3.2 Generated 1099-NEC Record (Billing Table)

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

#### 3.3.3 Tax Info Admin Index (Billing Table)

**GSI**: `ByTaxStatus` (new GSI on billing table)
**PK**: `TAX_STATUS#{status}`, **SK**: `{submitted_at}#{user_id}`

Allows admin to query all creators by tax info status (active, expired, missing).

#### 3.3.4 TIN Access Audit Log (Billing Table)

**PK**: `TAX_AUDIT`, **SK**: `{timestamp}#{audit_id}`

| Field | Type | Description |
|-------|------|-------------|
| `audit_id` | S | Unique ID |
| `action` | S | `"tin_viewed"`, `"1099_generated"`, `"tax_info_updated"` |
| `actor_user_id` | S | Who performed the action |
| `target_user_id` | S | Whose TIN was accessed |
| `ip_address` | S | Actor's IP address |
| `created_at` | N | Timestamp |

### 3.4 Backend Service

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

### 3.5 Backend Router

**New file**: `app/routers/tax_forms.py` (~180 lines)

### 3.6 Router Endpoints

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

### 3.7 API Request/Response Examples

**POST /ui/tax/w9 -- Submit W-9**

Request:
```json
{
  "legal_name": "Jane Smith",
  "business_name": "",
  "tax_classification": "individual",
  "address_line1": "123 Main Street",
  "address_line2": "Apt 4B",
  "city": "San Francisco",
  "state": "CA",
  "zip_code": "94102",
  "tin": "123-45-6789",
  "tin_type": "ssn",
  "certified_signature": "Jane Smith"
}
```

Response (200):
```json
{
  "legal_name": "Jane Smith",
  "business_name": "",
  "tax_classification": "individual",
  "address_line1": "123 Main Street",
  "address_line2": "Apt 4B",
  "city": "San Francisco",
  "state": "CA",
  "zip_code": "94102",
  "tin_masked": "***-**-6789",
  "tin_type": "ssn",
  "certified_at": 1748534400,
  "status": "active",
  "submitted_at": 1748534400,
  "updated_at": 1748534400
}
```

**GET /ui/tax/info -- Get Own Tax Info (masked)**

Response (200):
```json
{
  "legal_name": "Jane Smith",
  "business_name": "",
  "tax_classification": "individual",
  "address_line1": "123 Main Street",
  "address_line2": "Apt 4B",
  "city": "San Francisco",
  "state": "CA",
  "zip_code": "94102",
  "tin_masked": "***-**-6789",
  "tin_type": "ssn",
  "certified_at": 1748534400,
  "status": "active",
  "submitted_at": 1748534400,
  "updated_at": 1748534400
}
```

**GET /ui/admin/tax/info/{user_id} -- Admin Full TIN (audit-logged)**

Response (200):
```json
{
  "legal_name": "Jane Smith",
  "business_name": "",
  "tax_classification": "individual",
  "address_line1": "123 Main Street",
  "address_line2": "Apt 4B",
  "city": "San Francisco",
  "state": "CA",
  "zip_code": "94102",
  "tin_masked": "***-**-6789",
  "tin_full": "123456789",
  "tin_type": "ssn",
  "certified_at": 1748534400,
  "status": "active",
  "submitted_at": 1748534400,
  "updated_at": 1748534400,
  "user_id": "user_abc123"
}
```

**POST /ui/admin/tax/generate-1099s -- Batch Generate**

Request:
```json
{
  "tax_year": 2026
}
```

Response (200):
```json
{
  "tax_year": 2026,
  "total_creators": 150,
  "qualifying": 42,
  "generated": 42,
  "errors": 0
}
```

**GET /ui/tax/1099s/{tax_year}/download -- Download 1099 PDF**

Response (200):
```json
{
  "download_url": "/mock/s3/tax-forms/2026/user_abc123_1099nec.pdf?X-Amz-Expires=3600"
}
```

**GET /ui/admin/tax/audit -- Tax Audit Log**

Response (200):
```json
{
  "items": [
    {
      "audit_id": "aud_abc123",
      "action": "tin_viewed",
      "actor_user_id": "root.admin@testdev.local",
      "target_user_id": "user_abc123",
      "ip_address": "127.0.0.1",
      "created_at": 1748534500
    },
    {
      "audit_id": "aud_def456",
      "action": "1099_generated",
      "actor_user_id": "root.admin@testdev.local",
      "target_user_id": "user_abc123",
      "ip_address": "127.0.0.1",
      "created_at": 1748534400
    }
  ],
  "next_cursor": null
}
```

### 3.8 Error Handling Matrix

| # | Scenario | HTTP Status | Error Message | Recovery Action |
|---|----------|-------------|---------------|-----------------|
| 1 | Invalid TIN format (not 9 digits) | 422 | `"tin: String should match pattern '^\\d{9}$' or 'min_length=9'"` | Fix input; TIN must be 9-11 chars (with or without dashes) |
| 2 | Invalid state code | 422 | `"state: String should have at most 2 characters"` | Use 2-letter state code |
| 3 | Invalid tax classification | 422 | `"tax_classification: String should match pattern..."` | Use one of: individual, sole_proprietor, llc, corporation, partnership, trust |
| 4 | No tax info submitted yet (GET) | 404 | `"No tax information found"` | Submit W-9 first |
| 5 | Admin access on non-existent user | 404 | `"User tax information not found"` | Verify user_id |
| 6 | Non-admin access to admin endpoint | 403 | `"Admin role required"` | Use admin credentials |
| 7 | 1099 for non-qualifying year | 200 | `qualifies: false` (not an error) | No action; creator below threshold |
| 8 | 1099 already generated for year | 409 | `"1099 already generated for this tax year"` | Use correction endpoint |
| 9 | Batch generate while another in progress | 429 | `"Batch generation already in progress"` | Wait for current batch |
| 10 | KMS decrypt failure | 500 | `"Internal error: unable to process tax data"` | Check KMS key and permissions |
| 11 | S3 upload failure for PDF | 500 | `"Failed to store generated form"` | Retry; check S3 availability |
| 12 | Expired tax info (>3 years old) | 200 | `status: "expired"` | Creator must re-submit W-9 |
| 13 | Missing certified signature | 422 | `"certified_signature: min_length=2"` | Provide electronic signature |
| 14 | Download 1099 that does not exist | 404 | `"No 1099 found for this tax year"` | Verify tax year; may not be generated yet |

### 3.9 Request/Response Models

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

    @field_validator("tin")
    @classmethod
    def validate_tin_format(cls, v: str) -> str:
        """Strip dashes and validate that TIN is exactly 9 digits."""
        digits = v.replace("-", "")
        if len(digits) != 9 or not digits.isdigit():
            raise ValueError("TIN must be exactly 9 digits")
        return digits

    @field_validator("state")
    @classmethod
    def validate_state_code(cls, v: str) -> str:
        """Validate 2-letter US state code."""
        valid_states = {
            "AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DE", "FL", "GA",
            "HI", "ID", "IL", "IN", "IA", "KS", "KY", "LA", "ME", "MD",
            "MA", "MI", "MN", "MS", "MO", "MT", "NE", "NV", "NH", "NJ",
            "NM", "NY", "NC", "ND", "OH", "OK", "OR", "PA", "RI", "SC",
            "SD", "TN", "TX", "UT", "VT", "VA", "WA", "WV", "WI", "WY",
            "DC", "PR", "VI", "GU", "AS", "MP",
        }
        if v.upper() not in valid_states:
            raise ValueError(f"Invalid state code: {v}")
        return v.upper()

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
    ip_address: str = ""

class TaxAuditListOut(BaseModel):
    items: List[TaxAuditEntryOut] = Field(default_factory=list)
    next_cursor: Optional[str] = None
```

### 3.10 TIN Encryption Flow

```
User submits TIN "123-45-6789"
  -> Strip non-digits: "123456789"
  -> Store last4: "6789"
  -> KMS encrypt: kms_encrypt("123456789") -> base64 ciphertext
  -> Store in DDB: tin_encrypted = ciphertext, tin_last4 = "6789"
  -> Return to user: tin_masked = "***-**-6789"
```

Decryption occurs only during:
1. 1099 generation (system, audit-logged)
2. Admin full TIN reveal (audit-logged with IP)

### 3.11 1099-NEC PDF Generation

The 1099-NEC PDF is rendered using a template approach:

1. Load a blank 1099-NEC form template (static PDF with form fields).
2. Fill in payer info (platform name, address, TIN).
3. Fill in recipient info (creator name, address, TIN).
4. Fill in Box 1: Nonemployee compensation amount.
5. Fill in tax year.
6. Save as PDF bytes and upload to S3.

For v1, use `reportlab` to generate a simplified 1099-NEC layout. Full IRS-compliant formatting is a future enhancement.

### 3.12 Frontend Component Tree

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

**TypeScript Props Interfaces**:

```typescript
interface TaxInfoFormProps {
  initialData?: TaxInfoOut;
  onSubmit: (data: W9SubmissionIn) => Promise<void>;
  isLoading: boolean;
}

interface TaxInfoDisplayProps {
  data: TaxInfoOut;
  onEdit: () => void;
}

interface Form1099TableProps {
  items: Form1099Out[];
  onDownload: (taxYear: number) => void;
  isDownloading: boolean;
}

interface TaxAdminListProps {
  submissions: TaxSubmissionListItem[];
  onViewFull: (userId: string) => void;
  onLoadMore: () => void;
  hasMore: boolean;
}

interface TaxAuditTableProps {
  entries: TaxAuditEntryOut[];
  isLoading: boolean;
}
```

### 3.13 Files to Create

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `app/services/tax_forms.py` | Tax info + 1099 generation service | ~450 |
| `app/routers/tax_forms.py` | Tax API endpoints | ~180 |
| `frontend/src/pages/tax/TaxInfoPage.tsx` | W-9 form + 1099 downloads UI | ~400 |
| `frontend/src/pages/admin/TaxAdminPage.tsx` | Admin tax management UI | ~250 |
| `frontend/src/api/endpoints/tax.ts` | API wrappers | ~50 |
| `frontend/e2e/fin-tax-forms.spec.ts` | E2E tests | ~420 |

### 3.14 Files to Modify

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

## 5. Observability

### 5.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `tax_w9_submissions_total` | counter | `status` | W-9 submissions (new, update) |
| `tax_1099_generated_total` | counter | `tax_year`, `qualifies` | 1099s generated |
| `tax_tin_decryptions_total` | counter | `purpose` | TIN decryption events (admin_view, 1099_gen) |
| `tax_batch_generate_duration_seconds` | histogram | `tax_year` | Batch generation latency |
| `tax_audit_entries_total` | counter | `action` | Audit log entries written |
| `tax_kms_errors_total` | counter | `operation` | KMS encrypt/decrypt failures |

### 5.2 Structured Logging

```python
logger.info(
    "tax_w9_submitted",
    extra={
        "user_id": user_id,
        "tax_classification": tax_classification,
        "tin_type": tin_type,
        "is_update": is_update,
    },
)

logger.info(
    "tax_1099_generated",
    extra={
        "user_id": user_id,
        "tax_year": tax_year,
        "total_earnings_cents": total_earnings_cents,
        "qualifies": qualifies,
    },
)

logger.warning(
    "tax_tin_decrypted",
    extra={
        "actor_user_id": admin_user_id,
        "target_user_id": user_id,
        "purpose": "admin_view",
        "ip_address": ip_address,
    },
)
```

### 5.3 Alert Rules

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| High TIN decryption rate | `rate(tax_tin_decryptions_total[5m]) > 10` | Warning | Investigate admin activity; possible data exfiltration |
| KMS failure spike | `rate(tax_kms_errors_total[5m]) > 1` | Critical | Check KMS key status; may block tax operations |
| Batch generation failure | `tax_batch_generate_errors > 0` | High | Review failed creator list; retry individually |
| Unusual W-9 update volume | `rate(tax_w9_submissions_total{status="update"}[1h]) > 50` | Warning | Potential automated abuse; investigate |

---

## 6. Rollout Plan

### 6.1 Feature Flag

```python
# app/core/settings.py
tax_forms_enabled: bool = os.environ.get("TAX_FORMS_ENABLED", "false").lower() == "true"
```

### 6.2 Phased Rollout

| Phase | Scope | Duration | Gate |
|-------|-------|----------|------|
| 1 | Internal QA | 3 days | TAX_FORMS_ENABLED=true in staging |
| 2 | Admin-only (batch generation) | 5 days | Admin UI available; creator UI hidden |
| 3 | Creator W-9 submission | 7 days | Creator tax page accessible; 1099 download available |
| 4 | Full rollout | Ongoing | Remove feature flag; make tax page permanent |

### 6.3 Rollback Plan

- Disable feature flag (`TAX_FORMS_ENABLED=false`) to hide tax pages and endpoints.
- Encrypted TIN data remains in DDB but is inaccessible via disabled endpoints.
- Generated 1099 PDFs remain in S3; download links stop working when flag is off.
- Audit log data is preserved regardless of feature state.

---

## 7. Performance Considerations

### 7.1 Latency Targets

| Operation | Target | Notes |
|-----------|--------|-------|
| Submit W-9 | < 500ms | KMS encrypt + DDB write + GSI write |
| Get tax info (masked) | < 100ms | Single DDB GetItem (no KMS) |
| Admin view full TIN | < 300ms | DDB GetItem + KMS decrypt + audit write |
| Generate single 1099 | < 3s | Ledger query + KMS decrypt + PDF render + S3 upload |
| Batch generate (100 creators) | < 60s | Sequential processing; parallelize in future |
| Download 1099 PDF | < 200ms | Generate presigned S3 URL |

### 7.2 Caching Strategy

- **No caching of TIN data**: Encrypted TIN and decrypted TIN must never be cached (PII).
- **Tax info metadata cache**: Non-sensitive fields (name, address, status) can be cached at React Query level with 5-minute stale time.
- **1099 list cache**: Form1099ListOut can be cached with 60-second stale time since it changes infrequently.
- **Admin submission list**: No cache; paginated queries run on each page load.

### 7.3 Batch Generation Optimization

- **Sequential v1**: Process creators one at a time (simple, auditable).
- **Batched v2**: Process 10 creators concurrently using `asyncio.gather` with semaphore.
- **Progress tracking**: For >100 creators, write progress to a DDB status record so admin UI can poll.
- **Idempotency**: If a 1099 already exists for user+year, skip (do not regenerate unless `force=true`).

### 7.4 PDF Generation Memory

- `reportlab` generates PDFs in memory. Each 1099 PDF is ~50KB.
- For batch generation of 1000 creators, peak memory is ~50MB (assuming sequential processing).
- If memory is a concern, flush each PDF to S3 immediately and release the bytes buffer.

---

## 8. E2E Test Plan

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

### Section 571: Edge Cases & Negative Tests (5 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 571.1 | EIN format accepted for business entities | POST with tin_type="ein", tin="12-3456789"; 200; status="active" |
| 571.2 | Duplicate W-9 submission overwrites previous | Submit twice with different addresses; GET returns latest address |
| 571.3 | Batch generate with no qualifying creators | Seed 0 credits; batch generate; qualifying=0, generated=0, errors=0 |
| 571.4 | Admin audit log is chronologically ordered | Generate multiple audit events; GET audit; created_at descending |
| 571.5 | Tax info survives backend restart | Submit W-9; restart backend; GET returns same data |

### Section 572: Audit Trail Verification (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 572.1 | W-9 submission creates audit entry | Submit W-9; GET audit; entry with action="tax_info_updated" |
| 572.2 | 1099 generation creates audit entry | Generate 1099; GET audit; entry with action="1099_generated" and target_user_id |
| 572.3 | Multiple TIN views create separate audit entries | View TIN twice; audit log has 2 entries with action="tin_viewed" |
| 572.4 | Audit entries include IP address | View TIN; audit entry has non-empty ip_address field |

**Total E2E tests: 27**

---

## 9. Dependencies

| Dependency | Status | Required For |
|------------|--------|-------------|
| `app/core/crypto.py` | Exists | KMS encryption of TIN |
| `scripts/mock_kms_server.py` | Exists | Local dev TIN encryption |
| `app/services/creator_earnings.py` | Exists | Annual earnings calculation for 1099 threshold |
| `app/services/billing_shared.py` | Exists | Billing ledger queries |
| S3 (moto mock) | Exists | 1099 PDF storage |
| `reportlab` (new dependency) | Needs install | PDF generation |

---

## 10. Acceptance Criteria

1. Creator can submit W-9 equivalent form with TIN.
2. TIN is KMS-encrypted before storage; only last 4 stored in plaintext.
3. Creator sees masked TIN on tax info page.
4. 1099-NEC is generated for creators earning above $600 in a calendar year.
5. Creator can download 1099 PDF from dashboard.
6. Admin can list tax submissions and view full TIN (audit-logged).
7. Admin can batch-generate 1099s for a tax year.
8. All TIN access is audit-logged.
9. All 27 E2E tests pass.

---

## Codebase References

### Existing Files (verified)
| File | Key Functions | Lines |
|------|--------------|-------|
| `app/core/crypto.py` | `kms_encrypt`, `kms_decrypt` | 16 |
| `app/services/creator_earnings.py` | `get_earnings_summary` (annual earnings for threshold) | 47 |
| `app/services/creator_payouts.py` | `get_available_balance` | 55 |
| `app/services/billing_shared.py` | `new_ledger_entry` | 217 |
| `scripts/mock_kms_server.py` | Mock KMS (port 7999) | - |

### Files to Create (new implementation)
| File | Purpose |
|------|---------|
| `app/services/tax_forms.py` | W-9 collection, TIN encryption, 1099 generation, PDF rendering |
| `app/routers/tax_forms.py` | Tax form submission, download, admin batch generation endpoints |
| `tax_forms` DDB table | Table definition in `scripts/local-ddb-init.py` |
| Frontend W-9 form page | TIN input, tax info display |
| Frontend 1099 download page | Annual form download |
