# KYC-002: Identity Document Verification

**Ticket**: KYC-002
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 10-14 days
**Dependencies**: KYC-001 (Admin Review Dashboard)

---

## 1. Overview & Motivation

### Problem Statement

The KYC system (see `app/routers/kyc_cases.py:734` for `attach_kyc_file`, `app/services/kyc_cases.py:97` for `create_case`) accepts document
uploads (selfie, id_front, id_back, proof_of_address) but treats them as opaque files. There
is no automated extraction of identity data from uploaded documents, no cross-referencing of
extracted data against the user's profile, and no confidence scoring to help reviewers
prioritize cases. Admins must visually inspect every document and manually compare names,
dates, and document numbers against the profile -- a slow, error-prone process.

### Goals

1. Build a mock OCR/extraction service that extracts structured identity data from uploaded
   ID documents (id_front, id_back).
2. Extract: full name, date of birth, document number, expiry date, issuing country.
3. Auto-match extracted fields against the user profile (name from profile, DOB from profile).
4. Produce a confidence score per field: `match`, `mismatch`, `partial`, `not_available`.
5. Store extraction results in a new DynamoDB table for retrieval by the admin dashboard.
6. Integrate extraction results into the KYC-001 case detail page.
7. Mock provider returns deterministic results based on filename patterns for testability.

### User Stories

| # | As a... | I want to... | So that... |
|---|---------|-------------|-----------|
| 1 | KYC reviewer | See extracted text from ID documents alongside the images | I can verify data without squinting at photos |
| 2 | KYC reviewer | See confidence scores for name and DOB matches | Mismatches are flagged automatically |
| 3 | Platform | Auto-flag cases where name or DOB mismatches | High-risk cases are surfaced faster |
| 4 | Developer | Use deterministic mock extraction in dev mode | E2E tests produce predictable results |
| 5 | KYC reviewer | See "extraction pending" status while processing | I know when results are not yet available |

---

## 2. Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────────────┐
│                           Frontend                                       │
│  ┌──────────────────────────────────────────────────────────┐            │
│  │ KycCaseDetailPage (from KYC-001)                         │            │
│  │  ├── DocumentViewer (existing)                            │            │
│  │  └── ExtractionResultsPanel (NEW)                         │            │
│  │       ├── FieldRow (full_name: Match ✓ / Mismatch ✗)     │            │
│  │       ├── FieldRow (date_of_birth: Match ✓ / Mismatch ✗) │            │
│  │       ├── FieldRow (document_number: extracted value)     │            │
│  │       ├── FieldRow (expiry_date: extracted value)         │            │
│  │       ├── OverallConfidenceBadge (high/medium/low)        │            │
│  │       └── Button "Re-extract"                             │            │
│  └──────────────────────────────────────────────────────────┘            │
└───────────────────────────────┬──────────────────────────────────────────┘
                                │ Axios
                                ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                      Backend (FastAPI)                                    │
│                                                                          │
│  app/routers/kyc_cases.py                                               │
│  ┌────────────────────────────────────────────────────────────────┐      │
│  │ POST /{case_id}/extract-documents  → trigger extraction       │      │
│  │ GET  /{case_id}/extractions        → get results (owner)      │      │
│  │ GET  /admin/cases/{id}/extractions → get results (admin)      │      │
│  └────────────────────────────────────────────────────────────────┘      │
│                                                                          │
│  app/services/kyc_document_verification.py (NEW)                        │
│  ┌────────────────────────────────────────────────────────────────┐      │
│  │ DocumentVerificationService                                    │      │
│  │  ├── trigger_extraction()                                      │      │
│  │  │    ├── _run_mock_extraction()  (dev mode)                   │      │
│  │  │    └── _run_provider_extraction()  (prod)                   │      │
│  │  ├── _match_against_profile()                                  │      │
│  │  │    ├── Name: case-insensitive + Levenshtein (>= 0.85)      │      │
│  │  │    └── DOB: exact ISO date comparison                       │      │
│  │  ├── _compute_confidence()                                     │      │
│  │  │    ├── all match → "high"                                   │      │
│  │  │    ├── some partial → "medium"                              │      │
│  │  │    └── any mismatch → "low"                                 │      │
│  │  ├── get_extraction()                                          │      │
│  │  └── get_all_extractions()                                     │      │
│  └───────────────────────┬────────────────────────────────────────┘      │
│                          │                                               │
│  Auto-trigger on submission (submit_kyc_case, line 830):                │
│  ┌────────────────────────────────────────────────────────┐              │
│  │ for file in case.files:                                 │              │
│  │   if file.type in ("id_front", "id_back"):             │              │
│  │     verification_service.trigger_extraction(...)        │              │
│  └────────────────────────────────────────────────────────┘              │
└───────────────────────────────┬──────────────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                    DynamoDB Local (:8001)                                 │
│                                                                          │
│  ┌──────────────────────────────────────────────┐                       │
│  │ kyc_document_extractions (NEW TABLE)          │                       │
│  │ PK: case_id    SK: file_type                  │                       │
│  │ GSI: ByStatus  PK: status  SK: created_at (N) │                       │
│  └──────────────────────────────────────────────┘                       │
│                                                                          │
│  ┌──────────────────────────┐  ┌─────────────────┐                      │
│  │ kyc_cases                │  │ users (profiles) │                      │
│  │ PK: KYC#{case_id}       │  │ PK: USER#{sub}   │                      │
│  └──────────────────────────┘  └─────────────────┘                      │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Current State Analysis

### 3.1 KYC File Attachment Flow

Files are attached to a KYC case via `POST /v1/kyc/cases/{id}/files` (see `app/routers/kyc_cases.py:734`).
The `KycFileAttachmentRequest` model (see `app/contracts/kyc_cases_contract.py:133`)
accepts `path` (file manager path), `file_type` (selfie/id_front/id_back/proof_of_address),
and `expected_version`. The file path points to a node in the file manager
(see `app/services/filemanager.py`), which stores the actual content in S3.

Each file entry stored on the case:
```python
{
    "type": "id_front",
    "path": "/uploads/kyc/alice_id_front.jpg",
    "verification_state": "pending",  # pending | verified | rejected
    "attached_at": 1716681600,
}
```

### 3.2 User Profile Data

User profile data is accessible via `app/services/profiles.py`. Relevant fields for matching:
- `display_name` or `full_name` (from profile record)
- `date_of_birth` (ISO format string, e.g., "1990-05-15")
- `mailing_address` (`MailingAddress` model in `app/models.py`, line 1273: line1, line2, city,
  state, postal_code, country)

### 3.3 File Content Access

File content is accessible via the file manager's S3 integration. The file manager node's
`s3_key` field points to the stored object. In dev mode, S3 is mocked via moto (in-process).
The extraction service will read file bytes via `boto3.client("s3").get_object()`.

---

## 4. DynamoDB Access Patterns

### 4.1 Table: `kyc_document_extractions`

| Access Pattern | PK | SK / GSI | Condition | Used By |
|---------------|-----|----------|-----------|---------|
| Get extraction for specific file | `case_id` | `file_type` (e.g., `id_front`) | GetItem | Case detail, admin view |
| Get all extractions for a case | `case_id` | `begins_with(file_type, "")` | Query all SKeys | Admin case detail |
| List pending extractions | GSI `ByStatus` PK=`pending` | SK=`created_at` (N) range | Background processor | |
| List failed extractions | GSI `ByStatus` PK=`failed` | SK=`created_at` (N) range | Admin monitoring | |

### 4.2 Example DDB Items

**Extraction result (completed, matching):**
```json
{
  "case_id": "kyc_a1b2c3d4",
  "file_type": "id_front",
  "extraction_id": "ext_f8a3b2c1d0e9",
  "status": "completed",
  "provider": "mock_ocr",
  "extracted_fields": {
    "full_name": "ALICE SMITH",
    "date_of_birth": "1990-05-15",
    "document_number": "X12345678",
    "expiry_date": "2030-12-31",
    "issuing_country": "US"
  },
  "match_results": {
    "full_name": {
      "status": "match",
      "profile_value": "Alice Smith",
      "extracted_value": "ALICE SMITH",
      "similarity": 1.0
    },
    "date_of_birth": {
      "status": "match",
      "profile_value": "1990-05-15",
      "extracted_value": "1990-05-15",
      "similarity": 1.0
    }
  },
  "overall_confidence": "high",
  "raw_response": "{\"provider\":\"mock_ocr\",\"raw\":{}}",
  "file_path": "/uploads/kyc/alice_id_front.jpg",
  "created_at": 1716681800,
  "updated_at": 1716681800
}
```

**Extraction result (completed, mismatch):**
```json
{
  "case_id": "kyc_e5f6g7h8",
  "file_type": "id_front",
  "extraction_id": "ext_a1b2c3d4e5f6",
  "status": "completed",
  "provider": "mock_ocr",
  "extracted_fields": {
    "full_name": "WRONG ALICE SMITH",
    "date_of_birth": "1991-05-15",
    "document_number": "Y87654321",
    "expiry_date": "2028-06-30",
    "issuing_country": "US"
  },
  "match_results": {
    "full_name": {
      "status": "mismatch",
      "profile_value": "Alice Smith",
      "extracted_value": "WRONG ALICE SMITH",
      "similarity": 0.62
    },
    "date_of_birth": {
      "status": "mismatch",
      "profile_value": "1990-05-15",
      "extracted_value": "1991-05-15",
      "similarity": 0.0
    }
  },
  "overall_confidence": "low",
  "raw_response": "{}",
  "file_path": "/uploads/kyc/alice_mismatch_id.jpg",
  "created_at": 1716681900,
  "updated_at": 1716681900
}
```

**DDB init** (`scripts/local-ddb-init.py`):
```python
TableDef(
    _resolve_table_name(S.kyc_doc_extractions_table_name, "kyc_document_extractions"),
    partition_key="case_id",
    sort_key="file_type",
    gsis=[
        {"index_name": "status-created-index", "partition_key": "status", "sort_key": "created_at"},
    ],
    attr_types={"created_at": "N"},
)
```

---

## 5. API Request/Response Examples

### 5.1 Trigger Document Extraction

```bash
curl -X POST "http://localhost:8000/v1/kyc/cases/kyc_a1b2c3d4/extract-documents" \
  -H "Cookie: ui_session=sess_alice; ui_access_token=eyJ...; ui_csrf=csrf_a" \
  -H "x-csrf-token: csrf_a" \
  -H "Content-Type: application/json"
```

**Response (200):**
```json
{
  "ok": true,
  "extractions_triggered": 2,
  "extraction_ids": ["ext_f8a3b2c1d0e9", "ext_c4d5e6f7a8b9"]
}
```

### 5.2 Get Extractions for a Case (Owner)

```bash
curl -X GET "http://localhost:8000/v1/kyc/cases/kyc_a1b2c3d4/extractions" \
  -H "Cookie: ui_session=sess_alice; ui_access_token=eyJ...; ui_csrf=csrf_a"
```

**Response (200):**
```json
{
  "extractions": [
    {
      "extraction_id": "ext_f8a3b2c1d0e9",
      "file_type": "id_front",
      "status": "completed",
      "overall_confidence": "high",
      "extracted_fields": {
        "full_name": "ALICE SMITH",
        "date_of_birth": "1990-05-15",
        "document_number": "X12345678",
        "expiry_date": "2030-12-31",
        "issuing_country": "US"
      },
      "created_at": 1716681800
    },
    {
      "extraction_id": "ext_c4d5e6f7a8b9",
      "file_type": "id_back",
      "status": "completed",
      "overall_confidence": "high",
      "extracted_fields": {
        "full_name": "ALICE SMITH",
        "date_of_birth": "1990-05-15"
      },
      "created_at": 1716681801
    }
  ]
}
```

### 5.3 Get Admin Extractions (with match details)

```bash
curl -X GET "http://localhost:8000/v1/kyc/cases/admin/cases/kyc_a1b2c3d4/extractions" \
  -H "Cookie: ui_session=sess_root; ui_access_token=eyJ...; ui_csrf=csrf_r"
```

**Response (200):**
```json
{
  "extractions": [
    {
      "extraction_id": "ext_f8a3b2c1d0e9",
      "file_type": "id_front",
      "status": "completed",
      "overall_confidence": "high",
      "extracted_fields": {
        "full_name": "ALICE SMITH",
        "date_of_birth": "1990-05-15",
        "document_number": "X12345678",
        "expiry_date": "2030-12-31",
        "issuing_country": "US"
      },
      "match_results": {
        "full_name": { "status": "match", "profile_value": "Alice Smith", "extracted_value": "ALICE SMITH", "similarity": 1.0 },
        "date_of_birth": { "status": "match", "profile_value": "1990-05-15", "extracted_value": "1990-05-15", "similarity": 1.0 }
      },
      "provider": "mock_ocr",
      "created_at": 1716681800,
      "updated_at": 1716681800
    }
  ]
}
```

---

## 6. Error Handling Matrix

| Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|----------|-------------|------------|---------------------|----------------|
| Trigger extraction on non-existent case | 404 | `kyc_case_not_found` | "KYC case not found." | Verify case ID |
| Trigger extraction by non-owner | 403 | `kyc_access_forbidden` | "You do not own this case." | Use correct session |
| Trigger extraction with no ID files | 400 | `kyc_no_extractable_files` | "No identity documents to extract from." | Upload id_front/id_back first |
| Extraction provider timeout | 500 | `extraction_provider_error` | "Document extraction failed. Try again later." | Re-trigger manually |
| Get extractions for non-existent case | 404 | `kyc_case_not_found` | "KYC case not found." | Verify case ID |
| Admin views extractions on non-existent case | 404 | `kyc_case_not_found` | "KYC case not found." | Verify case ID |
| Non-admin accesses admin extraction endpoint | 403 | `kyc_admin_role_required` | "Admin access required." | Use admin credentials |
| Re-trigger extraction on same file | 200 | — (idempotent update) | Success, updated result | No action needed |
| File manager node not found (dangling ref) | 500 | `file_not_found` | "Source document file not found." | Re-upload document |
| S3 get_object failure | 500 | `extraction_provider_error` | "Could not read document file." | Retry |

---

## 7. Pydantic Models

```python
from pydantic import BaseModel, Field
from typing import Literal

class ExtractionFieldMatch(BaseModel):
    status: Literal["match", "mismatch", "partial", "not_available"]
    profile_value: str | None = None
    extracted_value: str | None = None
    similarity: float | None = None

class DocumentExtractionOut(BaseModel):
    extraction_id: str
    file_type: Literal["id_front", "id_back"]
    status: Literal["pending", "completed", "failed", "not_supported"]
    provider: str | None = None
    extracted_fields: dict[str, str] = Field(default_factory=dict)
    match_results: dict[str, ExtractionFieldMatch] | None = None
    overall_confidence: Literal["high", "medium", "low", "failed"] | None = None
    file_path: str | None = None
    created_at: int
    updated_at: int

class TriggerExtractionResponse(BaseModel):
    ok: bool = True
    extractions_triggered: int
    extraction_ids: list[str] = Field(default_factory=list)

class ExtractionListResponse(BaseModel):
    extractions: list[DocumentExtractionOut]
```

---

## 8. Technical Design

### 8.1 New DDB Table: `kyc_document_extractions`

**Table name**: `kyc_document_extractions` (env: `KYC_DOC_EXTRACTIONS_TABLE_NAME`)
**Partition key**: `case_id` (String)
**Sort key**: `file_type` (String) -- e.g., `id_front`, `id_back`

| Field | Type | Description |
|-------|------|-------------|
| `case_id` | S (PK) | FK to KYC case |
| `file_type` | S (SK) | `id_front` or `id_back` |
| `extraction_id` | S | `"ext_" + uuid4().hex[:12]` |
| `status` | S | `pending`, `completed`, `failed`, `not_supported` |
| `provider` | S | `mock_ocr` in dev, real provider name in prod |
| `extracted_fields` | M | Map of field_name -> extracted value |
| `match_results` | M | Map of field_name -> { status, profile_value, extracted_value } |
| `overall_confidence` | S | `high`, `medium`, `low`, `failed` |
| `raw_response` | S | JSON string of full provider response |
| `file_path` | S | File manager path that was processed |
| `created_at` | N | Unix timestamp |
| `updated_at` | N | Unix timestamp |

### 8.2 New Service: `app/services/kyc_document_verification.py`

```python
class DocumentVerificationService:
    def __init__(self, table=None):
        self._table = table or T.kyc_document_extractions

    def trigger_extraction(self, *, case_id: str, file_type: str, file_path: str, user_sub: str) -> dict:
        """Create a pending extraction record and run extraction (sync in dev)."""

    def get_extraction(self, *, case_id: str, file_type: str) -> dict | None:
        """Get extraction result for a specific file."""

    def get_all_extractions(self, *, case_id: str) -> list[dict]:
        """Get all extraction results for a case."""

    def _run_mock_extraction(self, *, file_path: str, file_type: str) -> dict:
        """Mock OCR provider. Returns deterministic results based on filename patterns."""

    def _match_against_profile(self, *, extracted: dict, user_sub: str) -> dict:
        """Compare extracted fields against user profile. Returns match_results map."""

    def _compute_confidence(self, match_results: dict) -> str:
        """Compute overall confidence: high (all match), medium (partial), low (mismatch)."""
```

### 8.3 Mock Provider Logic

The mock extraction provider returns deterministic results for testability:

| Filename pattern | Behavior |
|-----------------|----------|
| `*_match_*` or default | Returns extracted fields matching the user profile |
| `*_mismatch_*` | Returns name with "WRONG" prefix, DOB off by 1 year |
| `*_partial_*` | Returns name with minor typo (extra space), DOB matches |
| `*_expired_*` | Returns expiry_date in the past |
| `*_fail_*` | Returns status=failed, no extracted fields |

### 8.4 String Matching Algorithm

Name matching uses case-insensitive comparison with normalization:
1. Strip leading/trailing whitespace
2. Collapse multiple spaces to single space
3. Convert to uppercase
4. Compare: exact match = `match`, Levenshtein ratio >= 0.85 = `partial`, else `mismatch`

DOB matching: exact string comparison after normalizing to ISO format.

### 8.5 Integration with Case Submission

In `submit_kyc_case()` (see `app/routers/kyc_cases.py:830`), after successful
submission, automatically trigger extraction for all id_front and id_back files:

```python
# After successful submission
for file_entry in case.get("files", []):
    if file_entry["type"] in ("id_front", "id_back"):
        verification_service.trigger_extraction(
            case_id=case_id,
            file_type=file_entry["type"],
            file_path=file_entry["path"],
            user_sub=case["user_sub"],
        )
```

### 8.6 Settings

**File: `app/core/settings.py`** -- add:

```python
kyc_doc_extractions_table_name: str = os.environ.get("KYC_DOC_EXTRACTIONS_TABLE_NAME", "kyc_document_extractions")
kyc_extraction_provider: str = os.environ.get("KYC_EXTRACTION_PROVIDER", "mock_ocr")
kyc_name_match_threshold: float = float(os.environ.get("KYC_NAME_MATCH_THRESHOLD", "0.85"))
```

---

## 9. Frontend Component Tree

```
KycCaseDetailPage (extended from KYC-001)
├── DocumentViewer (existing)
│   ├── TabBar (Selfie | ID Front | ID Back | Proof of Address)
│   └── ImagePane
└── ExtractionResultsPanel (NEW)
    ├── SectionHeader ("Extraction Results")
    ├── OverallConfidenceBadge
    │   ├── variant="high" → green "High Confidence"
    │   ├── variant="medium" → yellow "Medium Confidence"
    │   └── variant="low" → red "Low Confidence"
    ├── ExtractionFieldTable
    │   ├── FieldRow (full_name)
    │   │   ├── Label "Full Name"
    │   │   ├── ExtractedValue "ALICE SMITH"
    │   │   ├── ProfileValue "Alice Smith"
    │   │   └── MatchBadge (green "Match" | yellow "Partial" | red "Mismatch")
    │   ├── FieldRow (date_of_birth)
    │   ├── FieldRow (document_number)
    │   ├── FieldRow (expiry_date)
    │   └── FieldRow (issuing_country)
    ├── FailedExtractionBanner (shown when status=failed)
    │   └── Text "Extraction failed for this document."
    ├── PendingExtractionSpinner (shown when status=pending)
    │   └── Loader2 + Text "Extracting document data..."
    └── Button "Re-extract" (triggers POST extract-documents)
```

---

## 10. Observability & Monitoring

### 10.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `kyc_extraction_total` | Counter | `file_type`, `provider`, `status` | Total extractions triggered |
| `kyc_extraction_duration_ms` | Histogram | `provider` | Time to complete extraction |
| `kyc_extraction_confidence` | Histogram | `file_type` | Distribution of confidence levels |
| `kyc_extraction_match_status` | Counter | `field`, `status` | Per-field match outcomes |
| `kyc_extraction_auto_triggered` | Counter | — | Extractions auto-triggered on submission |

### 10.2 Log Events

| Event | Level | Fields |
|-------|-------|--------|
| `kyc.extraction.triggered` | INFO | `case_id`, `file_type`, `provider` |
| `kyc.extraction.completed` | INFO | `case_id`, `file_type`, `confidence`, `match_summary` |
| `kyc.extraction.failed` | ERROR | `case_id`, `file_type`, `error` |
| `kyc.extraction.name_mismatch` | WARN | `case_id`, `profile_name`, `extracted_name`, `similarity` |
| `kyc.extraction.dob_mismatch` | WARN | `case_id`, `profile_dob`, `extracted_dob` |

### 10.3 Alerts

| Alert | Condition | Severity |
|-------|-----------|----------|
| Extraction failure rate high | `failed / total > 10%` in 1h | P2 |
| Extraction latency high | `p95 > 30s` | P3 |
| Name mismatch rate high | `mismatch / total > 25%` in 1h | P3 (may indicate mock issue or real issue) |

---

## 11. Rollout Plan

### 11.1 Feature Flag

**Flag:** `KYC_DOCUMENT_EXTRACTION_ENABLED` (default `true` in dev, `false` in prod)

### 11.2 Migration Steps

1. Deploy DDB table creation (local-ddb-init.py change)
2. Deploy service + router changes with flag off
3. Enable in staging, verify with E2E tests
4. Enable in production (extractions begin on new submissions)
5. Backfill: manually trigger extraction for existing submitted cases

### 11.3 Rollback

1. Set flag to `false` -- auto-trigger on submission stops
2. Existing extraction records remain (read-only)
3. Admin dashboard falls back to no extraction panel
4. No data loss or schema change needed

---

## 12. Performance Considerations

### 12.1 Query Costs

| Operation | RCU/WCU | Notes |
|-----------|---------|-------|
| Trigger extraction (PutItem) | 1 WCU | Single write ~1 KB |
| Get extraction (GetItem) | 1 RCU | Single read |
| Get all extractions (Query) | 1-2 RCU | Max 4 items per case |
| Mock extraction compute | 0 DDB | In-memory computation |

### 12.2 Latency

- Mock extraction: < 50ms (in-memory)
- Production extraction: 2-10s (external API call)
- Auto-trigger adds ~100ms to submission flow (mock) or should be async (production)

### 12.3 Caching

- Extraction results are immutable once completed; cache indefinitely in React Query
- `staleTime: Infinity` for completed extractions
- `staleTime: 5000` for pending extractions (poll for completion)

---

## 13. E2E Test Plan

**File**: `frontend/e2e/kyc-document-verification.spec.ts`
**Total**: ~20 tests across 4 sections (156-159)

### Section 156: Document Extraction API (6 tests)

```typescript
test("156.1 Trigger extraction on submitted case returns 200", async () => {
  // Create case, attach id_front, submit
  // POST /v1/kyc/cases/{id}/extract-documents as owner
  // Verify 200 with extraction_id
});

test("156.2 Get extractions returns completed results", async () => {
  // GET /v1/kyc/cases/{id}/extractions
  // Verify array with id_front entry, status=completed
  // Verify extracted_fields has full_name, date_of_birth
});

test("156.3 Mock provider returns match for default filename", async () => {
  // Upload file with normal filename
  // Trigger extraction
  // Verify match_results.full_name.status = "match"
});

test("156.4 Mock provider returns mismatch for _mismatch_ filename", async () => {
  // Upload file named "alice_mismatch_id.jpg"
  // Trigger extraction
  // Verify match_results.full_name.status = "mismatch"
});

test("156.5 Mock provider returns failed for _fail_ filename", async () => {
  // Upload file named "alice_fail_id.jpg"
  // Trigger extraction
  // Verify status=failed, extracted_fields is empty
});

test("156.6 Non-owner cannot trigger extraction", async () => {
  // Bob tries to trigger extraction on Alice's case
  // Expect 403
});
```

### Section 157: Auto-Extraction on Submission (4 tests)

```typescript
test("157.1 Submitting case auto-triggers extraction for id_front", async () => {
  // Create case with id_front, questionnaire, signature, submit
  // GET extractions immediately
  // Verify id_front extraction exists
});

test("157.2 Auto-extraction processes both id_front and id_back", async () => {
  // Attach both id_front and id_back, submit
  // GET extractions
  // Verify 2 extraction records
});

test("157.3 Auto-extraction skips selfie and proof_of_address", async () => {
  // Attach all 4 file types, submit
  // GET extractions
  // Verify only id_front and id_back have extractions (not selfie or proof_of_address)
});

test("157.4 Extraction results available in admin case detail", async () => {
  // Submit case
  // GET /v1/kyc/cases/admin/cases/{id}/extractions as Root
  // Verify results include match_results and overall_confidence
});
```

### Section 158: Confidence Scoring (5 tests)

```typescript
test("158.1 All fields matching produces high confidence", async () => {
  // Default filename, profile data matches mock output
  // Verify overall_confidence = "high"
});

test("158.2 Name mismatch produces low confidence", async () => {
  // _mismatch_ filename
  // Verify overall_confidence = "low"
});

test("158.3 Partial name match produces medium confidence", async () => {
  // _partial_ filename
  // Verify overall_confidence = "medium"
});

test("158.4 Expired document flagged in extraction results", async () => {
  // _expired_ filename
  // Verify extracted_fields.expiry_date is in the past
  // Verify match_results includes expiry warning
});

test("158.5 Re-extraction updates existing record", async () => {
  // Trigger extraction, verify result
  // Trigger extraction again
  // Verify updated_at changed, extraction_id may differ
});
```

### Section 159: Admin Extraction UI (5 tests)

```typescript
test("159.1 Case detail page shows extraction results panel", async ({ page }) => {
  // Navigate to /admin/kyc/cases/{id} as Root
  // Verify "Extraction Results" section visible
  // Verify field rows with match status badges
});

test("159.2 Match fields show green badge", async ({ page }) => {
  // Verify full_name row has green "Match" badge
});

test("159.3 Mismatch fields show red badge", async ({ page }) => {
  // Case with mismatch extraction
  // Verify date_of_birth row has red "Mismatch" badge
});

test("159.4 Re-extract button triggers new extraction", async ({ page }) => {
  // Click "Re-extract" button
  // Verify loading state, then updated results
});

test("159.5 Failed extraction shows error state", async ({ page }) => {
  // Case with failed extraction
  // Verify "Extraction Failed" banner
});
```

### Expanded E2E: Edge Cases

```typescript
test("156.7 Trigger extraction with no files attached returns 400", async () => {
  // Create case without any files
  // POST extract-documents
  // Expect 400 kyc_no_extractable_files
});

test("158.6 Extraction with name containing special characters still matches", async () => {
  // Profile name "O'Brien-Smith", extracted "OBRIEN SMITH"
  // Verify match or partial based on Levenshtein ratio
});

test("158.7 Concurrent extractions for same file are idempotent", async () => {
  // Trigger extraction twice simultaneously
  // Verify only one final result exists (PutItem is idempotent on PK/SK)
});
```

---

## 14. File Change Summary

| File | Change Type | Description |
|------|-------------|-------------|
| `app/services/kyc_document_verification.py` | **New** | Extraction service with mock provider and profile matching |
| `app/routers/kyc_cases.py` | Modify | Add extraction endpoints; auto-trigger on submission |
| `app/contracts/kyc_cases_contract.py` | Modify | Add extraction request/response models |
| `app/core/settings.py` | Modify | Add extraction table name and provider settings |
| `app/core/tables.py` | Modify | Add `kyc_document_extractions` table handle |
| `scripts/local-ddb-init.py` | Modify | Add `kyc_document_extractions` table with GSI |
| `frontend/src/api/endpoints/kyc-admin.ts` | Modify | Add extraction API functions |
| `frontend/src/pages/admin/KycCaseDetailPage.tsx` | Modify | Add extraction results panel |
| `frontend/e2e/kyc-document-verification.spec.ts` | **New** | 20+ E2E tests across sections 156-159 |

---

## Codebase References

> **Verification performed**: 2026-05-29

### Verified (EXISTS in codebase)

| Reference | File | Line(s) | Status |
|-----------|------|---------|--------|
| `attach_kyc_file()` endpoint | `app/routers/kyc_cases.py` | 734 | VERIFIED |
| `_KYC_ALLOWED_FILE_TYPES` | `app/routers/kyc_cases.py` | 51 | VERIFIED |
| `_validate_file_requirements()` | `app/routers/kyc_cases.py` | 155 | VERIFIED |
| `submit_kyc_case()` | `app/routers/kyc_cases.py` | 830 | VERIFIED |
| `kyc_cases` DDB table | `scripts/local-ddb-init.py` | 91-96 | VERIFIED |
| KYC settings | `app/core/settings.py` | 1065-1072 | VERIFIED |
| `app/contracts/kyc_cases_contract.py` | `app/contracts/` | exists | VERIFIED |

### Not Yet Implemented (requires new code)

| Reference | Expected Location | Status |
|-----------|-------------------|--------|
| `app/services/kyc_document_verification.py` | `app/services/` | NOT FOUND -- new service required |
| `kyc_document_extractions` DDB table | `scripts/local-ddb-init.py` | NOT FOUND -- new table required |
| `kyc_document_extractions` table handle | `app/core/tables.py` | NOT FOUND -- new handle required |
| Extraction settings (table name, provider) | `app/core/settings.py` | NOT FOUND -- new settings required |
| Extraction endpoints in KYC router | `app/routers/kyc_cases.py` | NOT FOUND -- new endpoints required |
| `frontend/src/pages/admin/KycCaseDetailPage.tsx` extraction panel | `frontend/src/pages/admin/` | NOT FOUND -- page does not exist yet (KYC-001 dependency) |

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_kyc_documents.py`

Mock external dependencies with `moto` (DynamoDB) and `unittest.mock`. All tests run without the dev stack.

  - `test_upload_document_image`
  - `test_extract_document_fields_ocr_mock`
  - `test_validate_document_expiry`
  - `test_detect_document_type`
  - `test_store_document_encrypted`
  - `test_get_document_metadata`
  - `test_delete_expired_document`

### Integration Tests

  - Document upload stores encrypted image in S3 and metadata in DDB
  - OCR extraction populates name, DOB, document number fields
  - Admin review shows extracted fields alongside document image

### E2E Tests (Playwright)

**File**: `frontend/e2e/kyc-documents.spec.ts`
**Test count**: 12

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

- **DDB seeds**: Seed `kyc_documents` table with test records in `beforeAll`
- **Test users**: Alice (USER), Bob (USER), Root (ROOT), Charlie (ADMIN) from `e2e_admin_session_setup.py`
- **Cleanup**: Tests use unique timestamps/IDs per run to avoid cross-run interference

### CI/Pipeline Considerations

- **Feature flag**: `KYC_DOC_VERIFICATION_ENABLED=true` must be set in test environment
- **Serial execution**: E2E tests run with `workers: 1` to avoid shared-state conflicts
- **Retry safety**: All tests are idempotent; retries do not produce duplicate records

## Dependencies & Merge Safety

### Depends On

| Ticket | Title | Why |
|--------|-------|-----|
| KYC-001 | Admin KYC Review Dashboard | Documents reviewed through admin dashboard |

### Depended On By

| Ticket | Title | Impact |
|--------|-------|--------|
| KYC-004 | Proof of Residency | Shares document upload infrastructure |
| KYC-006 | Sanctions & PEP Screening | Extracted name/DOB used for screening |
| KYC-008 | Risk Scoring Engine | Document verification status feeds risk score |
| KYC-010 | Passport & National ID Scanner | Extends document OCR capabilities |

### Merge Strategy

**Sequential**

Merge after KYC-001. This ticket depends on tables/services introduced by those tickets.

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
- [ ] All 12 E2E tests pass with `npx playwright test kyc-documents.spec.ts`
