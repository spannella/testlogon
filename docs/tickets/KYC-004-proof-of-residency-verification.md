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
(`_KYC_ALLOWED_FILE_TYPES` — see `app/routers/kyc_cases.py:51`), but there is no
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

## 2. Architecture Diagram

```
┌────────────────────────────────────────────────────────────────────────┐
│                         Frontend                                       │
│                                                                        │
│  KycCaseForm.tsx (user)                 KycCaseDetailPage.tsx (admin)  │
│  ┌─────────────────────────┐          ┌──────────────────────────┐    │
│  │ ResidencySection         │          │ ResidencyVerificationTab │    │
│  │  ├─ DocTypeDropdown      │          │  ├─ DocAddress (left)    │    │
│  │  ├─ IssuingEntityInput   │          │  ├─ ProfileAddress(right)│    │
│  │  ├─ DocumentDatePicker   │          │  ├─ FieldMatchIndicators │    │
│  │  ├─ FileUpload           │          │  ├─ RecencyBadge         │    │
│  │  ├─ RecencyBadge         │          │  └─ MultipleDocs SubTabs │    │
│  │  └─ AttachedDocsList     │          └──────────────────────────┘    │
│  └─────────────────────────┘                                          │
└──────────────────┬─────────────────────────────┬──────────────────────┘
                   │                             │
                   ▼                             ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     Backend (FastAPI)                                   │
│                                                                        │
│  POST /{case_id}/residency-documents        (attach with metadata)    │
│  GET  /{case_id}/residency-documents        (list residency docs)     │
│  DELETE /{case_id}/residency-documents/{idx} (remove by index)        │
│                                                                        │
│  kyc_address_matching.py (NEW)                                        │
│  ┌────────────────────────────────────────────────────────┐           │
│  │ match_addresses(extracted, profile)                     │           │
│  │   ├─ line1: normalize abbreviations, case-insensitive   │           │
│  │   ├─ city: case-insensitive exact                       │           │
│  │   ├─ state: abbrev ↔ full name ("CA" = "California")   │           │
│  │   ├─ postal_code: first 5 digits (ignore +4)           │           │
│  │   └─ country: ISO 2-letter ↔ full name                 │           │
│  └────────────────────────────────────────────────────────┘           │
│                                                                        │
│  Readiness gate update (_readiness_for_case):                         │
│  ┌────────────────────────────────────────────────────────┐           │
│  │ if intake_profile in ("enhanced", "high_risk"):         │           │
│  │   residency_doc required + recency_valid = true         │           │
│  └────────────────────────────────────────────────────────┘           │
└──────────────────┬─────────────────────────────────────────────────────┘
                   │
                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│  DynamoDB: kyc_cases table                                             │
│  case.files[] entry with residency_meta nested object                 │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Current State Analysis

### 3.1 Current Proof of Address Handling

`_KYC_ALLOWED_FILE_TYPES` (see `app/routers/kyc_cases.py:51`):
```python
_KYC_ALLOWED_FILE_TYPES = set(_KYC_REQUIRED_FILE_TYPES + ["proof_of_address"])
```

The `proof_of_address` type is optional -- it is in `_KYC_ALLOWED_FILE_TYPES` but not in
`_KYC_REQUIRED_FILE_TYPES` (which is `["selfie", "id_front", "id_back"]`). Files attached
with `file_type="proof_of_address"` are stored as opaque entries in the case's `files[]`
array with no additional metadata.

### 3.2 User Mailing Address

`MailingAddress` model (see `app/models.py:1273`):
```python
class MailingAddress(BaseModel):
    line1: Optional[str] = None
    line2: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    postal_code: Optional[str] = None
    country: Optional[str] = None
```

### 3.3 File Validation

`_validate_file_requirements()` (see `app/routers/kyc_cases.py:155`) checks for
required file types but does not validate metadata, recency, or content of proof_of_address
files beyond their presence.

---

## 4. DynamoDB Access Patterns

| Access Pattern | PK | SK | Notes |
|---------------|-----|-----|-------|
| Get residency docs for a case | `KYC#{case_id}` | `META` → filter `files[]` where `type=proof_of_address` | Part of case record |
| Update case files array | `KYC#{case_id}` | `META` | Conditional update on `version` |
| Get user profile address | `USER#{user_sub}` | `PROFILE` | For matching |

### Example: Residency Document in files[] Array

```json
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
      "status": "match",
      "profile_address": {
        "line1": "123 Main Street",
        "city": "San Francisco",
        "state": "California",
        "postal_code": "94105",
        "country": "US"
      },
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

---

## 5. API Request/Response Examples

### 5.1 Attach Residency Document

```bash
curl -X POST "http://localhost:8000/v1/kyc/cases/kyc_a1b2c3d4/residency-documents" \
  -H "Cookie: ui_session=sess_alice; ui_access_token=eyJ...; ui_csrf=csrf_a" \
  -H "x-csrf-token: csrf_a" \
  -H "Content-Type: application/json" \
  -d '{
    "expected_version": 3,
    "path": "/uploads/kyc/alice_utility_bill.pdf",
    "document_type": "utility_bill",
    "issuing_entity": "Pacific Gas & Electric",
    "document_date": "2026-04-15"
  }'
```

**Response (200):**
```json
{
  "ok": true,
  "file_index": 3,
  "residency_meta": {
    "document_type": "utility_bill",
    "issuing_entity": "Pacific Gas & Electric",
    "document_date": "2026-04-15",
    "recency_valid": true,
    "recency_days": 44,
    "address_match": {
      "status": "match",
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

### 5.2 List Residency Documents

```bash
curl -X GET "http://localhost:8000/v1/kyc/cases/kyc_a1b2c3d4/residency-documents" \
  -H "Cookie: ui_session=sess_alice; ui_access_token=eyJ...; ui_csrf=csrf_a"
```

**Response (200):**
```json
{
  "documents": [
    {
      "file_index": 3,
      "path": "/uploads/kyc/alice_utility_bill.pdf",
      "residency_meta": {
        "document_type": "utility_bill",
        "issuing_entity": "Pacific Gas & Electric",
        "document_date": "2026-04-15",
        "recency_valid": true,
        "recency_days": 44,
        "address_match": { "status": "match" }
      }
    }
  ]
}
```

### 5.3 Remove Residency Document

```bash
curl -X DELETE "http://localhost:8000/v1/kyc/cases/kyc_a1b2c3d4/residency-documents/0" \
  -H "Cookie: ui_session=sess_alice; ui_access_token=eyJ...; ui_csrf=csrf_a" \
  -H "x-csrf-token: csrf_a"
```

**Response (200):**
```json
{ "ok": true, "removed_index": 0 }
```

---

## 6. Error Handling Matrix

| Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|----------|-------------|------------|---------------------|----------------|
| Invalid document_type | 422 | `validation_error` | "Document type must be one of: utility_bill, bank_statement, government_letter, tax_document, lease_agreement." | Select valid type |
| Invalid document_date format | 422 | `validation_error` | "Document date must be in YYYY-MM-DD format." | Fix date format |
| Document older than 90 days | 200 (attached) | — | Warning: "Document is older than 90 days." | Attach but flagged |
| Case not found | 404 | `kyc_case_not_found` | "Case not found." | Verify case ID |
| Case not in draft/needs_more_info | 400 | `kyc_invalid_status` | "Documents can only be attached to draft or needs_more_info cases." | Check case status |
| Non-owner attaches document | 403 | `kyc_access_forbidden` | "You do not own this case." | Use correct session |
| Remove doc from submitted case | 400 | `kyc_invalid_status` | "Cannot modify files on a submitted case." | Case must be in draft |
| File index out of bounds | 400 | `kyc_invalid_file_index` | "File index not found." | Refresh file list |

---

## 7. Pydantic Models

```python
from pydantic import BaseModel, Field
from typing import Literal

RESIDENCY_DOC_TYPES = Literal[
    "utility_bill", "bank_statement", "government_letter",
    "tax_document", "lease_agreement"
]

class KycResidencyDocAttachRequest(BaseModel):
    expected_version: int = Field(..., ge=1)
    path: str = Field(..., min_length=1, max_length=1024)
    document_type: RESIDENCY_DOC_TYPES
    issuing_entity: str = Field(..., min_length=1, max_length=200)
    document_date: str = Field(..., pattern=r"^\d{4}-\d{2}-\d{2}$",
                               description="ISO date, e.g. 2026-04-15")

class AddressFieldMatch(BaseModel):
    line1: Literal["match", "partial", "mismatch"] | None = None
    city: Literal["match", "partial", "mismatch"] | None = None
    state: Literal["match", "partial", "mismatch"] | None = None
    postal_code: Literal["match", "partial", "mismatch"] | None = None
    country: Literal["match", "partial", "mismatch"] | None = None

class AddressMatchResult(BaseModel):
    status: Literal["match", "partial", "mismatch"]
    profile_address: dict = Field(default_factory=dict)
    field_matches: AddressFieldMatch = Field(default_factory=AddressFieldMatch)

class ResidencyMetaOut(BaseModel):
    document_type: str
    issuing_entity: str
    document_date: str
    extracted_address: dict | None = None
    recency_valid: bool
    recency_days: int
    address_match: AddressMatchResult | None = None
```

---

## 8. Technical Design

### 8.1 Address Matching Service

**File: `app/services/kyc_address_matching.py`** (new, ~100 lines)

```python
def match_addresses(extracted: dict, profile: dict) -> dict:
    """Compare two address dicts field by field."""
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

### 8.2 Street Abbreviation Map

```python
_STREET_ABBREVIATIONS = {
    "st": "street", "ave": "avenue", "blvd": "boulevard", "dr": "drive",
    "ln": "lane", "rd": "road", "ct": "court", "pl": "place",
    "cir": "circle", "pkwy": "parkway", "hwy": "highway",
    "apt": "apartment", "ste": "suite", "fl": "floor",
}
```

### 8.3 Readiness Gate Update

For `intake_profile in ("enhanced", "high_risk")`:
```python
if case.get("intake_profile") in ("enhanced", "high_risk"):
    residency_docs = [f for f in files_list if f.get("type") == "proof_of_address"]
    valid_residency = any(
        (f.get("residency_meta") or {}).get("recency_valid") for f in residency_docs
    )
    checks["residency_document"] = bool(residency_docs) and valid_residency
```

---

## 9. Frontend Component Tree

```
KycCaseForm (user wizard, extended)
└── ResidencyDocumentSection
    ├── SectionHeader ("Proof of Residency")
    ├── Select (document_type: Utility Bill | Bank Statement | ...)
    ├── Input (issuing_entity)
    ├── DatePicker (document_date, max=today, min=today-180)
    ├── FileUpload (accepts PDF, JPG, PNG)
    ├── RecencyBadge
    │   ├── variant="valid" → green "Within 90 days"
    │   └── variant="expired" → red "Expired (X days old)"
    ├── AttachedDocsList
    │   └── DocRow[] (for each attached residency doc)
    │       ├── TypeBadge (utility_bill / bank_statement / ...)
    │       ├── IssuingEntity text
    │       ├── DocumentDate text
    │       ├── RecencyBadge
    │       └── Button "Remove"
    └── Button "Add Another Document"

KycCaseDetailPage (admin, extended)
└── ResidencyVerificationTab
    ├── SubTabBar (one per residency document)
    └── ResidencyDocPanel (per document)
        ├── Grid (2 columns)
        │   ├── DocumentAddressCard (left)
        │   │   ├── line1, line2, city, state, postal_code, country
        │   │   └── Source: "Extracted from document"
        │   └── ProfileAddressCard (right)
        │       ├── line1, line2, city, state, postal_code, country
        │       └── Source: "User profile"
        ├── FieldMatchTable
        │   ├── Row: line1 → match/partial/mismatch badge
        │   ├── Row: city → badge
        │   ├── Row: state → badge
        │   ├── Row: postal_code → badge
        │   └── Row: country → badge
        ├── MetadataPanel
        │   ├── Document Type badge
        │   ├── Issuing Entity
        │   ├── Document Date
        │   └── RecencyBadge
        └── OverallMatchBadge (match/partial/mismatch)
```

---

## 10. Observability & Monitoring

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `kyc_residency_doc_attached` | Counter | `document_type` | Documents attached |
| `kyc_residency_recency_result` | Counter | `valid` (bool) | Recency validation outcomes |
| `kyc_residency_address_match` | Counter | `status` (match/partial/mismatch) | Address matching outcomes |
| `kyc_residency_field_match` | Counter | `field`, `status` | Per-field match results |

### Alerts

| Alert | Condition | Severity |
|-------|-----------|----------|
| High mismatch rate | `mismatch / total > 30%` in 24h | P3 |
| All documents expired | Case with only `recency_valid=false` docs for 48h | P3 (send reminder) |

---

## 11. Rollout Plan

1. Deploy address matching service (no external dependencies)
2. Deploy residency document endpoints (backward compatible -- existing proof_of_address still works)
3. Update readiness gate for enhanced/high_risk profiles
4. Deploy frontend residency section in wizard
5. Deploy admin residency verification tab

### Rollback

- Revert readiness gate change (residency becomes optional again)
- Residency metadata in `files[]` is ignored by existing code
- No DDB schema changes needed (uses existing case files array)

---

## 12. Performance Considerations

| Operation | Cost | Notes |
|-----------|------|-------|
| Attach residency doc | 2-5 WCU | Case update (larger item with metadata) |
| Address matching | 0 DDB | In-memory computation |
| Recency check | 0 DDB | Date arithmetic |
| List residency docs | 1 RCU | Filter on case GetItem |

---

## 13. E2E Test Plan

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

### Expanded E2E: Edge Cases

```typescript
test("164.7 Attach document to submitted case returns 400", async () => {
  // Submit case first, then try to attach residency doc
  // Expect 400 kyc_invalid_status
});

test("165.6 Address with normalized abbreviations matches", async () => {
  // Profile: "123 Main Street", Extracted: "123 Main St"
  // Verify field_matches.line1 = "match"
});

test("165.7 Empty profile address results in no match data", async () => {
  // User has no mailing_address set
  // Verify address_match is null or status = "not_available"
});
```

---

## 14. File Change Summary

| File | Change Type | Description |
|------|-------------|-------------|
| `app/services/kyc_address_matching.py` | **New** | Address comparison with field-level fuzzy matching |
| `app/routers/kyc_cases.py` | Modify | Add residency document endpoints; update readiness gate |
| `app/contracts/kyc_cases_contract.py` | Modify | Add `KycResidencyDocAttachRequest` model |
| `app/core/settings.py` | Modify | Add `kyc_residency_recency_days` setting (default 90) |
| `frontend/src/pages/kyc/KycCaseForm.tsx` | Modify | Add residency document upload section |
| `frontend/src/pages/admin/KycCaseDetailPage.tsx` | Modify | Add residency verification tab |
| `frontend/src/api/endpoints/kyc-admin.ts` | Modify | Add residency document API functions |
| `frontend/e2e/kyc-residency-verification.spec.ts` | **New** | 15+ E2E tests across sections 164-166 |

---

## 15. Pydantic Models

```python
from pydantic import BaseModel, Field
from typing import Literal

RESIDENCY_DOC_TYPES = Literal[
    "utility_bill", "bank_statement", "government_letter",
    "tax_document", "lease_agreement"
]


class KycResidencyDocAttachRequest(BaseModel):
    expected_version: int = Field(..., ge=1)
    path: str = Field(..., min_length=1, max_length=1024)
    document_type: RESIDENCY_DOC_TYPES
    issuing_entity: str = Field(..., min_length=1, max_length=200)
    document_date: str = Field(
        ...,
        pattern=r"^\d{4}-\d{2}-\d{2}$",
        description="ISO date, e.g. 2026-04-15",
    )


class AddressFieldMatch(BaseModel):
    line1: Literal["match", "partial", "mismatch"] | None = None
    city: Literal["match", "partial", "mismatch"] | None = None
    state: Literal["match", "partial", "mismatch"] | None = None
    postal_code: Literal["match", "partial", "mismatch"] | None = None
    country: Literal["match", "partial", "mismatch"] | None = None


class AddressMatchResult(BaseModel):
    status: Literal["match", "partial", "mismatch", "not_available"]
    profile_address: dict = Field(default_factory=dict)
    field_matches: AddressFieldMatch = Field(default_factory=AddressFieldMatch)


class ResidencyMetaOut(BaseModel):
    document_type: str
    issuing_entity: str
    document_date: str
    extracted_address: dict | None = None
    recency_valid: bool
    recency_days: int
    address_match: AddressMatchResult | None = None


class KycResidencyDocOut(BaseModel):
    file_index: int
    path: str
    residency_meta: ResidencyMetaOut


class KycResidencyDocAttachResponse(BaseModel):
    ok: bool = True
    file_index: int
    residency_meta: ResidencyMetaOut


class KycResidencyDocsListResponse(BaseModel):
    documents: list[KycResidencyDocOut] = Field(default_factory=list)
```

---

## 16. Expanded E2E Tests

### Section 164 Additions: Attachment Edge Cases (4 additional tests)

```typescript
test("164.8 Lease agreement document type accepted", async () => {
  // POST with document_type: "lease_agreement"
  // issuing_entity: "Riverside Property Management"
  // Verify 200, type badge shows lease_agreement
});

test("164.9 Document exactly 90 days old is still valid", async () => {
  // POST with document_date = today - 90 days (exactly)
  // Verify recency_valid=true, recency_days=90
});

test("164.10 Document 91 days old is flagged as expired", async () => {
  // POST with document_date = today - 91 days
  // Verify recency_valid=false, recency_days=91
});

test("164.11 Multiple residency docs of different types can coexist", async () => {
  // Attach utility_bill, then bank_statement
  // GET residency-documents
  // Verify 2 documents with distinct types
});
```

### Section 165 Additions: Address Matching Edge Cases (4 additional tests)

```typescript
test("165.8 Boulevard abbreviated to Blvd matches", async () => {
  // Profile: "100 Sunset Boulevard", Extracted: "100 Sunset Blvd"
  // Verify field_matches.line1 = "match"
});

test("165.9 Country ISO code US matches full name United States", async () => {
  // Profile: country="United States", Extracted: country="US"
  // Verify field_matches.country = "match"
});

test("165.10 Suite vs Ste abbreviation matches", async () => {
  // Profile: "Suite 200", Extracted: "Ste 200"
  // Verify this portion matches in line1 normalization
});

test("165.11 Full address match returns status=match with all fields match", async () => {
  // All 5 fields match after normalization
  // Verify address_match.status = "match"
  // Verify all field_matches entries = "match"
});
```

### Section 166 Additions: Readiness Gate Edge Cases (3 additional tests)

```typescript
test("166.5 High-risk profile also requires valid residency doc", async () => {
  // intake_profile="high_risk", no docs
  // GET readiness → missing residency_document
});

test("166.6 Having multiple docs with one valid satisfies gate", async () => {
  // Attach expired doc + valid doc
  // GET readiness → passes (at least one valid)
});

test("166.7 Removing last valid doc re-fails the gate", async () => {
  // After 166.6, remove the valid doc
  // GET readiness → missing residency_document
});
```

---

## Codebase References

> **Verification performed**: 2026-05-29

### Verified (EXISTS in codebase)

| Reference | File | Line(s) | Status |
|-----------|------|---------|--------|
| `attach_kyc_file()` endpoint | `app/routers/kyc_cases.py` | 734 | VERIFIED |
| `_KYC_ALLOWED_FILE_TYPES` | `app/routers/kyc_cases.py` | 51 | VERIFIED |
| `_validate_file_requirements()` | `app/routers/kyc_cases.py` | 155 | VERIFIED |
| `validate_kyc_file_requirements()` endpoint | `app/routers/kyc_cases.py` | 791 | VERIFIED |
| `_readiness_for_case()` | `app/routers/kyc_cases.py` | 223 | VERIFIED |
| `kyc_cases` DDB table | `scripts/local-ddb-init.py` | 91-96 | VERIFIED |
| KYC settings | `app/core/settings.py` | 1065-1072 | VERIFIED |
| `MailingAddress` model | `app/models.py` | 1273 | VERIFIED |
| `app/contracts/kyc_cases_contract.py` | `app/contracts/` | exists | VERIFIED |

### Not Yet Implemented (requires new code)

| Reference | Expected Location | Status |
|-----------|-------------------|--------|
| `proof_of_address` / `residency_document` file type in `_KYC_ALLOWED_FILE_TYPES` | `app/routers/kyc_cases.py` | VERIFY -- may need to add new file type constants |
| Address extraction from PoA documents | `app/services/kyc_document_verification.py` | NOT FOUND -- depends on KYC-002 |
| PoA-specific validation (issuer date, document age) | `app/routers/kyc_cases.py` | NOT FOUND -- new validation logic required |
| Readiness gate for residency document | `app/routers/kyc_cases.py:223` | NOT FOUND -- `_readiness_for_case()` needs modification |
