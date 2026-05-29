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

The KYC system (`app/routers/kyc_cases.py`, `app/services/kyc_cases.py`) accepts document
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

## 2. Current State Analysis

### 2.1 KYC File Attachment Flow

Files are attached to a KYC case via `POST /v1/kyc/cases/{id}/files` (line 734 of
`app/routers/kyc_cases.py`). The `KycFileAttachmentRequest` model (contract line 133)
accepts `path` (file manager path), `file_type` (selfie/id_front/id_back/proof_of_address),
and `expected_version`. The file path points to a node in the file manager
(`app/services/filemanager.py`), which stores the actual content in S3.

Each file entry stored on the case:
```python
{
    "type": "id_front",
    "path": "/uploads/kyc/alice_id_front.jpg",
    "verification_state": "pending",  # pending | verified | rejected
    "attached_at": 1716681600,
}
```

### 2.2 User Profile Data

User profile data is accessible via `app/services/profiles.py`. Relevant fields for matching:
- `display_name` or `full_name` (from profile record)
- `date_of_birth` (ISO format string, e.g., "1990-05-15")
- `mailing_address` (`MailingAddress` model in `app/models.py`, line 1273: line1, line2, city,
  state, postal_code, country)

### 2.3 File Content Access

File content is accessible via the file manager's S3 integration. The file manager node's
`s3_key` field points to the stored object. In dev mode, S3 is mocked via moto (in-process).
The extraction service will read file bytes via `boto3.client("s3").get_object()`.

---

## 3. Technical Design

### 3.1 New DDB Table: `kyc_document_extractions`

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

`extracted_fields` map structure:
```json
{
  "full_name": "ALICE SMITH",
  "date_of_birth": "1990-05-15",
  "document_number": "X12345678",
  "expiry_date": "2030-12-31",
  "issuing_country": "US"
}
```

`match_results` map structure:
```json
{
  "full_name": {
    "status": "match",
    "profile_value": "Alice Smith",
    "extracted_value": "ALICE SMITH",
    "similarity": 1.0
  },
  "date_of_birth": {
    "status": "mismatch",
    "profile_value": "1990-05-15",
    "extracted_value": "1991-05-15",
    "similarity": 0.0
  }
}
```

**GSIs**:

| GSI Name | Partition Key | Sort Key | Purpose |
|----------|--------------|----------|---------|
| `ByStatus` | `status` | `created_at` (N) | Query pending extractions for processing |

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

### 3.2 New Service: `app/services/kyc_document_verification.py`

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

### 3.3 Mock Provider Logic

The mock extraction provider returns deterministic results for testability:

| Filename pattern | Behavior |
|-----------------|----------|
| `*_match_*` or default | Returns extracted fields matching the user profile |
| `*_mismatch_*` | Returns name with "WRONG" prefix, DOB off by 1 year |
| `*_partial_*` | Returns name with minor typo (extra space), DOB matches |
| `*_expired_*` | Returns expiry_date in the past |
| `*_fail_*` | Returns status=failed, no extracted fields |

Example mock response for a matching document:
```python
{
    "full_name": profile.display_name.upper(),
    "date_of_birth": profile.date_of_birth,
    "document_number": f"X{uuid4().hex[:8].upper()}",
    "expiry_date": "2030-12-31",
    "issuing_country": "US",
}
```

### 3.4 String Matching Algorithm

Name matching uses case-insensitive comparison with normalization:
1. Strip leading/trailing whitespace
2. Collapse multiple spaces to single space
3. Convert to uppercase
4. Compare: exact match = `match`, Levenshtein ratio >= 0.85 = `partial`, else `mismatch`

DOB matching: exact string comparison after normalizing to ISO format.

### 3.5 New Router Endpoints

**File: `app/routers/kyc_cases.py`** -- add endpoints:

```python
@router.post("/{case_id}/extract-documents")
def trigger_document_extraction(
    case_id: str,
    request: Request,
    _ctx: dict = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    """Trigger extraction for all ID documents attached to the case.
    Called automatically on case submission, or manually by admin."""

@router.get("/{case_id}/extractions")
def get_document_extractions(
    case_id: str,
    request: Request,
    _ctx: dict = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    """Get all extraction results for a case. Available to case owner and admins."""

@router.get("/admin/cases/{case_id}/extractions")
def get_admin_document_extractions(
    case_id: str,
    request: Request,
    _ctx: dict = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    """Admin view of extraction results with match details and confidence."""
```

### 3.6 Integration with Case Submission

In `submit_kyc_case()` (line 830 of `app/routers/kyc_cases.py`), after successful
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

### 3.7 Frontend Integration

**File: `frontend/src/pages/admin/KycCaseDetailPage.tsx`** -- extend:

Add an "Extraction Results" panel below the document viewer showing:
- Per-field extracted value vs profile value with color-coded match status
  (green=match, yellow=partial, red=mismatch, gray=not_available)
- Overall confidence badge
- "Re-extract" button for admin to re-trigger extraction

### 3.8 Settings

**File: `app/core/settings.py`** -- add:

```python
kyc_doc_extractions_table_name: str = os.environ.get("KYC_DOC_EXTRACTIONS_TABLE_NAME", "kyc_document_extractions")
kyc_extraction_provider: str = os.environ.get("KYC_EXTRACTION_PROVIDER", "mock_ocr")
kyc_name_match_threshold: float = float(os.environ.get("KYC_NAME_MATCH_THRESHOLD", "0.85"))
```

---

## 4. E2E Test Plan

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

---

## 5. File Change Summary

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
| `frontend/e2e/kyc-document-verification.spec.ts` | **New** | 20 E2E tests across sections 156-159 |
