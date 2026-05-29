# KYC-004: Proof of Residency Verification

**Ticket**: KYC-004
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 8-10 days
**Dependencies**: KYC-001 (Admin Review Dashboard), KYC-002 (Identity Document Verification)

---

## 1. Overview & Motivation

### Problem Statement

The current KYC system accepts `proof_of_address` as a single optional file type
(`_KYC_ALLOWED_FILE_TYPES` in `app/routers/kyc_cases.py`, line 51), but there is no
structured handling beyond simple file upload. There is no way to specify what kind of
proof-of-address document was uploaded (utility bill vs. bank statement vs. government
letter), no metadata extraction from the document (issuing entity, document date, address),
no validation that the document is recent (within 90 days), and no automated comparison
of the extracted address against the user's `mailing_address` on their profile.

Regulators typically require proof of residency documents to be **recent** (within 60-90
days), from a **recognized issuing entity**, and to show an address that **matches** the
address on file. Without these checks, reviewers must manually verify every aspect of every
residency document, which is error-prone and slow.

### Goals

1. Define accepted proof-of-residency document types with structured metadata.
2. Capture document metadata: document_type, issuing_entity, document_date, extracted address.
3. Validate document recency: document must be dated within 90 days of submission.
4. Fuzzy-match extracted address against the user's `mailing_address` from their profile.
5. Support multiple proof-of-address documents per case (at least 1 required for enhanced profiles).
6. Provide admin review with side-by-side address comparison (document vs. profile).

### User Stories

| # | As a... | I want to... | So that... |
|---|---------|-------------|-----------|
| 1 | Applicant | Upload a utility bill as proof of address | I can satisfy residency requirements |
| 2 | Applicant | See which document types are accepted | I upload the correct documents |
| 3 | KYC reviewer | See the document date and recency validation | I know if the document is current |
| 4 | KYC reviewer | See extracted address compared to profile address | Mismatches are highlighted |
| 5 | Compliance lead | Enforce 90-day recency on residency documents | Expired documents are flagged |
| 6 | Applicant | Upload multiple residency documents | I can provide additional evidence if needed |

---

## 2. Current State Analysis

### 2.1 Current Proof of Address Handling

`_KYC_ALLOWED_FILE_TYPES` (line 51 of `app/routers/kyc_cases.py`):
```python
_KYC_ALLOWED_FILE_TYPES = set(_KYC_REQUIRED_FILE_TYPES + ["proof_of_address"])
```

The `proof_of_address` type is optional -- it is in `_KYC_ALLOWED_FILE_TYPES` but not in
`_KYC_REQUIRED_FILE_TYPES` (which is `["selfie", "id_front", "id_back"]`). Files attached
with `file_type="proof_of_address"` are stored as opaque entries in the case's `files[]`
array with no additional metadata.

### 2.2 User Mailing Address

`MailingAddress` model (`app/models.py`, line 1273):
```python
class MailingAddress(BaseModel):
    line1: Optional[str] = None
    line2: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    postal_code: Optional[str] = None
    country: Optional[str] = None
```

Stored on the user profile via `app/services/profiles.py`. Accessible via profile
retrieval for the case's `user_sub`.

### 2.3 File Validation

`_validate_file_requirements()` (line 155 of `app/routers/kyc_cases.py`) checks for
required file types but does not validate metadata, recency, or content of proof_of_address
files beyond their presence.

---

## 3. Technical Design

### 3.1 Accepted Residency Document Types

```python
RESIDENCY_DOC_TYPES = {
    "utility_bill",        # Gas, electric, water, internet
    "bank_statement",      # Bank or credit union statement
    "government_letter",   # Tax notice, voter registration, government correspondence
    "tax_document",        # Tax return, tax assessment
    "lease_agreement",     # Signed rental/lease agreement
}
```

### 3.2 Enhanced File Entry Structure

Each proof-of-address file entry in `case.files[]` will be extended with a `residency_meta`
sub-object:

```python
{
    "type": "proof_of_address",
    "path": "/uploads/kyc/alice_utility_bill.pdf",
    "verification_state": "pending",
    "attached_at": 1716681600,
    "residency_meta": {
        "document_type": "utility_bill",
        "issuing_entity": "Pacific Gas & Electric",
        "document_date": "2026-04-15",
        "extracted_address": {
            "line1": "123 Main St",
            "line2": "Apt 4B",
            "city": "San Francisco",
            "state": "CA",
            "postal_code": "94105",
            "country": "US"
        },
        "recency_valid": true,
        "recency_days": 44,
        "address_match": {
            "status": "match",          # match | partial | mismatch
            "profile_address": { ... },
            "field_matches": {
                "line1": "match",
                "city": "match",
                "state": "match",
                "postal_code": "match",
                "country": "match"
            }
        }
    }
}
```

### 3.3 Request Models

**File: `app/contracts/kyc_cases_contract.py`** -- add:

```python
class KycResidencyDocAttachRequest(BaseModel):
    expected_version: int = Field(..., ge=1)
    path: str = Field(..., min_length=1, max_length=1024)
    document_type: Literal[
        "utility_bill", "bank_statement", "government_letter",
        "tax_document", "lease_agreement"
    ]
    issuing_entity: str = Field(..., min_length=1, max_length=200)
    document_date: str = Field(..., pattern=r"^\d{4}-\d{2}-\d{2}$",
                               description="ISO date, e.g. 2026-04-15")
```

### 3.4 New Router Endpoint

**File: `app/routers/kyc_cases.py`** -- add endpoint:

```python
@router.post("/{case_id}/residency-documents")
def attach_residency_document(
    case_id: str,
    body: KycResidencyDocAttachRequest,
    request: Request,
    _ctx: dict = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    """Attach a proof-of-residency document with metadata to a KYC case.
    Validates document recency (within 90 days) and extracts address for matching.
    Multiple residency documents can be attached."""
```

**Validation logic:**
1. Verify case exists and belongs to user
2. Verify case status is `draft` or `needs_more_info`
3. Parse `document_date` and check recency: `(today - document_date).days <= 90`
4. If recency fails: still attach but set `recency_valid=false`
5. Run mock address extraction from file (reuse KYC-002 mock provider pattern)
6. Compare extracted address against user's `mailing_address` using field-by-field fuzzy match
7. Append to `files[]` array with full `residency_meta`

```python
@router.get("/{case_id}/residency-documents")
def list_residency_documents(
    case_id: str,
    request: Request,
    _ctx: dict = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    """List all residency documents attached to a case with metadata."""

@router.delete("/{case_id}/residency-documents/{file_index}")
def remove_residency_document(
    case_id: str,
    file_index: int,
    request: Request,
    _ctx: dict = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    """Remove a residency document from the case (draft/needs_more_info only)."""
```

### 3.5 Address Matching Service

**File: `app/services/kyc_address_matching.py`** (new, ~100 lines)

```python
def match_addresses(extracted: dict, profile: dict) -> dict:
    """Compare two address dicts field by field.

    Returns:
        {
            "status": "match" | "partial" | "mismatch",
            "profile_address": profile,
            "field_matches": { field_name: "match"|"partial"|"mismatch" for each field }
        }
    """
```

Field matching rules:
- `line1`: case-insensitive, normalize abbreviations (St/Street, Ave/Avenue, Dr/Drive)
- `city`: case-insensitive exact match
- `state`: case-insensitive, accept both abbreviation and full name ("CA" = "California")
- `postal_code`: strip whitespace, compare first 5 digits (ignore +4 extension)
- `country`: case-insensitive, accept ISO 2-letter and full name ("US" = "United States")

Overall status:
- All fields match -> `match`
- postal_code + city match but line1 differs -> `partial`
- city or postal_code mismatch -> `mismatch`

### 3.6 Readiness Gate Update

`_readiness_for_case()` (line 223 of `app/routers/kyc_cases.py`) currently does not require
proof_of_address. For `intake_profile="enhanced"` or `"high_risk"` cases, add a new
requirement check:

```python
if case.get("intake_profile") in ("enhanced", "high_risk"):
    residency_docs = [f for f in files_list if f.get("type") == "proof_of_address"]
    valid_residency = any(
        (f.get("residency_meta") or {}).get("recency_valid") for f in residency_docs
    )
    checks["residency_document"] = bool(residency_docs) and valid_residency
```

### 3.7 Frontend Changes

**File: `frontend/src/pages/kyc/KycCaseForm.tsx`** -- extend:

Add "Proof of Residency" section with:
- Document type dropdown (Utility Bill, Bank Statement, etc.)
- Issuing entity text input
- Document date picker (must be within last 90 days)
- File upload button (reuse existing file upload component)
- List of attached residency documents with remove button
- Recency badge (green "Within 90 days" / red "Expired")

**File: `frontend/src/pages/admin/KycCaseDetailPage.tsx`** -- extend:

Add "Residency Verification" tab in document viewer:
- Side-by-side comparison: document address (left) vs. profile address (right)
- Field-by-field match indicators (green/yellow/red)
- Document metadata display (type, issuing entity, date, recency)
- Multiple documents shown as sub-tabs

---

## 4. E2E Test Plan

**File**: `frontend/e2e/kyc-residency-verification.spec.ts`
**Total**: ~15 tests across 3 sections (164-166)

### Section 164: Residency Document Attachment API (6 tests)

```typescript
test("164.1 Attach utility bill with valid metadata", async () => {
  // POST /v1/kyc/cases/{id}/residency-documents
  // { document_type: "utility_bill", issuing_entity: "PG&E",
  //   document_date: "2026-05-01", path: "/uploads/kyc/bill.pdf" }
  // Verify 200, file added with residency_meta
});

test("164.2 Attach bank statement as second residency document", async () => {
  // POST with document_type: "bank_statement"
  // Verify files[] now has 2 proof_of_address entries
});

test("164.3 Document older than 90 days flagged as not recent", async () => {
  // POST with document_date 120 days ago
  // Verify attached but recency_valid=false, recency_days=120
});

test("164.4 Invalid document_type rejected", async () => {
  // POST with document_type: "passport" (not in allowed set)
  // Expect 422
});

test("164.5 Invalid document_date format rejected", async () => {
  // POST with document_date: "May 15, 2026"
  // Expect 422
});

test("164.6 Remove residency document by index", async () => {
  // DELETE /v1/kyc/cases/{id}/residency-documents/0
  // Verify file removed from files[]
});
```

### Section 165: Address Matching (5 tests)

```typescript
test("165.1 Matching address produces match status", async () => {
  // Set Alice profile mailing_address to known values
  // Attach residency document (mock extracts matching address)
  // Verify address_match.status = "match"
});

test("165.2 Different street produces partial match", async () => {
  // Mock extracts line1 = "456 Oak Ave" vs profile "123 Main St"
  // But city and postal_code match
  // Verify address_match.status = "partial"
});

test("165.3 Different city produces mismatch", async () => {
  // Mock extracts city = "Los Angeles" vs profile "San Francisco"
  // Verify address_match.status = "mismatch"
});

test("165.4 State abbreviation matches full name", async () => {
  // Profile has state="California", extracted has state="CA"
  // Verify field_matches.state = "match"
});

test("165.5 Postal code with +4 extension matches 5-digit code", async () => {
  // Profile has postal_code="94105", extracted has "94105-1234"
  // Verify field_matches.postal_code = "match"
});
```

### Section 166: Residency Readiness Gate (4 tests)

```typescript
test("166.1 Standard profile does not require residency document", async () => {
  // Case with intake_profile="standard", no residency docs
  // GET readiness
  // Verify ready_to_submit=true (residency not in checks)
});

test("166.2 Enhanced profile requires valid residency document", async () => {
  // Case with intake_profile="enhanced", no residency docs
  // GET readiness
  // Verify ready_to_submit=false, missing_requirements includes "residency_document"
});

test("166.3 Enhanced profile with expired residency doc still fails gate", async () => {
  // Attach doc with recency_valid=false
  // Verify ready_to_submit=false
});

test("166.4 Enhanced profile with valid residency doc passes gate", async () => {
  // Attach doc with recent date
  // Verify ready_to_submit=true (assuming other requirements met)
});
```

---

## 5. File Change Summary

| File | Change Type | Description |
|------|-------------|-------------|
| `app/services/kyc_address_matching.py` | **New** | Address comparison with field-level fuzzy matching |
| `app/routers/kyc_cases.py` | Modify | Add residency document endpoints; update readiness gate |
| `app/contracts/kyc_cases_contract.py` | Modify | Add `KycResidencyDocAttachRequest` model |
| `app/core/settings.py` | Modify | Add `kyc_residency_recency_days` setting (default 90) |
| `frontend/src/pages/kyc/KycCaseForm.tsx` | Modify | Add residency document upload section |
| `frontend/src/pages/admin/KycCaseDetailPage.tsx` | Modify | Add residency verification tab |
| `frontend/src/api/endpoints/kyc-admin.ts` | Modify | Add residency document API functions |
| `frontend/e2e/kyc-residency-verification.spec.ts` | **New** | 15 E2E tests across sections 164-166 |
