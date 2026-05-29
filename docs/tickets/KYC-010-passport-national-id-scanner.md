# KYC-010: Passport & National ID Scanner

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-29  
**Priority**: High  
**Estimated effort**: 8-10 days  
**Dependencies**: KYC-002 (Identity Document Verification / OCR)

---

## 1. Overview & Motivation

### 1.1 The Gap

The current KYC system (`app/routers/kyc_cases.py`) allows users to upload identity documents (selfie, id_front, id_back, proof_of_address) via `POST /{case_id}/files`. However, the system treats these uploads as opaque file attachments — there is no parsing, data extraction, or validation of document contents. The `_KYC_ALLOWED_FILE_TYPES` set (line 51) defines categories but does not distinguish between a passport, national ID card, driving license, or residence permit.

When an admin reviews a case in the admin queue (`GET /admin/queue`), they must manually inspect each uploaded image, read the text, cross-reference it against the user's profile data, and check expiry dates. This is slow, error-prone, and does not scale.

### 1.2 What This Ticket Adds

1. **MRZ (Machine Readable Zone) parsing** for passports and travel documents following ICAO 9303 format.
2. **Mock MRZ parser** for dev mode that extracts structured data from test document metadata.
3. **Document type classification** supporting passport, national_id_card, driving_license, residence_permit.
4. **Field extraction**: surname, given_names, nationality, date_of_birth, sex, expiry_date, document_number, issuing_state.
5. **MRZ checksum validation** on all three lines of TD3 passports and two lines of TD1/TD2 cards.
6. **Cross-referencing** extracted data against user profile data (name, DOB, nationality).
7. **Document expiry checking**: reject expired documents, warn if expiring within 90 days.
8. **Front/back image requirements** per document type (passport: front only; national ID: front + back; driving license: front + back; residence permit: front + back).

### 1.3 MRZ Format Reference

**TD3 (Passport) — 2 lines of 44 characters each**:

```
P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<
L898902C36UTO7408122F1204159ZE184226B<<<<<10
```

Line 1: `P<` + issuing state (3) + surname + `<<` + given names + filler
Line 2: document number (9) + check digit (1) + nationality (3) + DOB (6, YYMMDD) + check digit (1) + sex (1) + expiry (6, YYMMDD) + check digit (1) + optional data (14) + check digit (1) + composite check digit (1)

**TD1 (ID Card) — 3 lines of 30 characters each**:

```
I<UTOD231458907<<<<<<<<<<<<<<<
7408122F1204159UTO<<<<<<<<<<<6
ERIKSSON<<ANNA<MARIA<<<<<<<<<<
```

### 1.4 Architecture

```
Document Upload Flow (Extended):

  User uploads id_front image
       │
       ▼
  POST /{case_id}/files  (existing)
       │
       ▼
  attach_kyc_file() stores file ref on case
       │
       ▼
  POST /{case_id}/scan-document  (NEW)
       │
       ▼
  kyc_document_scanner.scan_document()
       │
       ├── detect_document_type()       → passport | national_id_card | ...
       ├── extract_mrz()                → raw MRZ lines (if passport/ID)
       ├── parse_mrz()                  → structured fields
       ├── validate_mrz_checksums()     → pass/fail per check digit
       ├── check_document_expiry()      → valid | expired | expiring_soon
       └── cross_reference_profile()    → match score for name, DOB, nationality
       │
       ▼
  Store extraction in kyc_cases table (SK=SCAN#{scan_id})
       │
       ▼
  Return extraction result to caller
```

---

## 2. Current State Analysis

### 2.1 File Attachment (`app/routers/kyc_cases.py`, line 733)

The `attach_kyc_file()` endpoint accepts a `KycFileAttachmentRequest` with `file_type` (one of `selfie`, `id_front`, `id_back`, `proof_of_address`) and `file_node_id` (a reference to a file in the file manager). It validates the file type against `_KYC_ALLOWED_FILE_TYPES` and appends a file record to the case's `files` array. No content analysis occurs.

### 2.2 File Validation (`app/routers/kyc_cases.py`, line 790)

The `validate_kyc_file_requirements()` endpoint checks whether all required file types are present (selfie, id_front, id_back) but does not validate document contents, expiry, or data consistency.

### 2.3 File Manager Integration (`app/services/filemanager.py`)

The `get_node(user_sub, node_id)` function retrieves file metadata including `s3_key`, `mime_type`, `file_name`, and `file_size`. The scanner service will use `s3_key` to access the document image for processing.

### 2.4 KYC Cases Table Schema

The `kyc_cases` table uses `pk=KYC#{case_id}`, `sk=META` for the main case record. Extraction results will use `sk=SCAN#{scan_id}` to store per-document scan results alongside the case, following the single-table design pattern.

### 2.5 S3 Mock (`app/core/dev_s3.py`)

moto's in-process S3 mock stores uploaded files. The scanner can retrieve document images via boto3 `get_object()` using the file's `s3_key`.

---

## 3. Technical Design

### 3.1 Document Type Definitions

```python
# app/services/kyc_document_scanner.py

from typing import Literal

DocumentType = Literal["passport", "national_id_card", "driving_license", "residence_permit"]

DOCUMENT_REQUIREMENTS: dict[DocumentType, dict] = {
    "passport": {
        "sides_required": ["front"],
        "has_mrz": True,
        "mrz_format": "TD3",
    },
    "national_id_card": {
        "sides_required": ["front", "back"],
        "has_mrz": True,
        "mrz_format": "TD1",
    },
    "driving_license": {
        "sides_required": ["front", "back"],
        "has_mrz": False,
        "mrz_format": None,
    },
    "residence_permit": {
        "sides_required": ["front", "back"],
        "has_mrz": True,
        "mrz_format": "TD1",
    },
}
```

### 3.2 MRZ Parser

```python
_MRZ_WEIGHTS = [7, 3, 1]

def _mrz_check_digit(data: str) -> int:
    """Compute ICAO 9303 check digit for a string."""
    total = 0
    for i, ch in enumerate(data):
        if ch == "<":
            val = 0
        elif ch.isdigit():
            val = int(ch)
        elif ch.isalpha():
            val = ord(ch.upper()) - ord("A") + 10
        else:
            val = 0
        total += val * _MRZ_WEIGHTS[i % 3]
    return total % 10


def validate_mrz_checksum(data: str, expected: str) -> bool:
    """Validate a single MRZ check digit field."""
    return str(_mrz_check_digit(data)) == str(expected).strip()


def parse_td3_mrz(line1: str, line2: str) -> dict:
    """Parse TD3 (passport) MRZ — 2 lines of 44 chars."""
    if len(line1) != 44 or len(line2) != 44:
        return {"error": "invalid_mrz_length", "valid": False}

    doc_type = line1[0:2].replace("<", "")
    issuing_state = line1[2:5].replace("<", "")
    names_raw = line1[5:44]
    parts = names_raw.split("<<", 1)
    surname = parts[0].replace("<", " ").strip()
    given_names = parts[1].replace("<", " ").strip() if len(parts) > 1 else ""

    doc_number = line2[0:9].replace("<", "")
    doc_check = line2[9]
    nationality = line2[10:13].replace("<", "")
    dob_raw = line2[13:19]  # YYMMDD
    dob_check = line2[19]
    sex = line2[20]
    expiry_raw = line2[21:27]  # YYMMDD
    expiry_check = line2[27]
    optional = line2[28:42]
    optional_check = line2[42]
    composite_check = line2[43]

    checksums = {
        "document_number": validate_mrz_checksum(line2[0:9], doc_check),
        "date_of_birth": validate_mrz_checksum(line2[13:19], dob_check),
        "expiry_date": validate_mrz_checksum(line2[21:27], expiry_check),
        "optional_data": validate_mrz_checksum(line2[28:42], optional_check),
        "composite": validate_mrz_checksum(
            line2[0:10] + line2[13:20] + line2[21:43], composite_check
        ),
    }

    return {
        "valid": all(checksums.values()),
        "format": "TD3",
        "document_type": doc_type,
        "issuing_state": issuing_state,
        "surname": surname,
        "given_names": given_names,
        "document_number": doc_number,
        "nationality": nationality,
        "date_of_birth": _mrz_date_to_iso(dob_raw),
        "sex": {"M": "male", "F": "female", "<": "unspecified"}.get(sex, sex),
        "expiry_date": _mrz_date_to_iso(expiry_raw),
        "checksums": checksums,
    }


def parse_td1_mrz(line1: str, line2: str, line3: str) -> dict:
    """Parse TD1 (ID card) MRZ — 3 lines of 30 chars."""
    if len(line1) != 30 or len(line2) != 30 or len(line3) != 30:
        return {"error": "invalid_mrz_length", "valid": False}

    doc_type = line1[0:2].replace("<", "")
    issuing_state = line1[2:5].replace("<", "")
    doc_number = line1[5:14].replace("<", "")
    doc_check = line1[14]
    optional_1 = line1[15:30]

    dob_raw = line2[0:6]
    dob_check = line2[6]
    sex = line2[7]
    expiry_raw = line2[8:14]
    expiry_check = line2[14]
    nationality = line2[15:18].replace("<", "")
    optional_2 = line2[18:29]
    composite_check = line2[29]

    names_raw = line3[0:30]
    parts = names_raw.split("<<", 1)
    surname = parts[0].replace("<", " ").strip()
    given_names = parts[1].replace("<", " ").strip() if len(parts) > 1 else ""

    checksums = {
        "document_number": validate_mrz_checksum(line1[5:14], doc_check),
        "date_of_birth": validate_mrz_checksum(line2[0:6], dob_check),
        "expiry_date": validate_mrz_checksum(line2[8:14], expiry_check),
        "composite": validate_mrz_checksum(
            line1[5:30] + line2[0:7] + line2[8:15] + line2[18:29], composite_check
        ),
    }

    return {
        "valid": all(checksums.values()),
        "format": "TD1",
        "document_type": doc_type,
        "issuing_state": issuing_state,
        "surname": surname,
        "given_names": given_names,
        "document_number": doc_number,
        "nationality": nationality,
        "date_of_birth": _mrz_date_to_iso(dob_raw),
        "sex": {"M": "male", "F": "female", "<": "unspecified"}.get(sex, sex),
        "expiry_date": _mrz_date_to_iso(expiry_raw),
        "checksums": checksums,
    }


def _mrz_date_to_iso(raw: str) -> str | None:
    """Convert YYMMDD to YYYY-MM-DD. Century pivot: 00-29 = 2000s, 30-99 = 1900s."""
    if len(raw) != 6 or not raw.isdigit():
        return None
    yy, mm, dd = int(raw[0:2]), raw[2:4], raw[4:6]
    century = 2000 if yy <= 29 else 1900
    return f"{century + yy}-{mm}-{dd}"
```

### 3.3 Mock Scanner for Dev Mode

```python
def _mock_scan_document(
    *,
    case_id: str,
    document_type: DocumentType,
    file_metadata: dict,
) -> dict:
    """Mock document scanner — returns structured extraction from test data.

    In dev mode, the file metadata 'description' field is parsed as JSON
    containing mock MRZ data. This allows E2E tests to provide predictable
    extraction results without actual OCR.
    """
    mock_data = {
        "passport": {
            "line1": "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<",
            "line2": "L898902C36UTO7408122F1204159ZE184226B<<<<<10",
        },
        "national_id_card": {
            "line1": "I<UTOD231458907<<<<<<<<<<<<<<<",
            "line2": "7408122F1204159UTO<<<<<<<<<<<6",
            "line3": "ERIKSSON<<ANNA<MARIA<<<<<<<<<<",
        },
    }
    # Allow test override via file description field
    desc = file_metadata.get("description", "")
    if desc.startswith("{"):
        import json
        try:
            mock_data_override = json.loads(desc)
            return _parse_mrz_from_lines(mock_data_override, document_type)
        except (json.JSONDecodeError, KeyError):
            pass

    default = mock_data.get(document_type, {})
    return _parse_mrz_from_lines(default, document_type)
```

### 3.4 Cross-Reference Engine

```python
def cross_reference_profile(
    extraction: dict,
    profile: dict,
) -> dict:
    """Compare extracted document data against user profile fields."""
    matches = {}
    mismatches = {}
    score = 0
    total = 0

    # Name comparison (fuzzy)
    extracted_name = f"{extraction.get('given_names', '')} {extraction.get('surname', '')}".strip().lower()
    profile_name = f"{profile.get('first_name', '')} {profile.get('last_name', '')}".strip().lower()
    if extracted_name and profile_name:
        total += 1
        if extracted_name == profile_name:
            matches["name"] = {"extracted": extracted_name, "profile": profile_name}
            score += 1
        else:
            # Partial match — check if surname matches
            if extraction.get("surname", "").lower() == profile.get("last_name", "").lower():
                matches["surname"] = {"extracted": extraction["surname"], "profile": profile["last_name"]}
                score += 0.5
            else:
                mismatches["name"] = {"extracted": extracted_name, "profile": profile_name}

    # DOB comparison
    extracted_dob = extraction.get("date_of_birth")
    profile_dob = profile.get("date_of_birth")
    if extracted_dob and profile_dob:
        total += 1
        if extracted_dob == profile_dob:
            matches["date_of_birth"] = {"extracted": extracted_dob, "profile": profile_dob}
            score += 1
        else:
            mismatches["date_of_birth"] = {"extracted": extracted_dob, "profile": profile_dob}

    # Nationality comparison
    extracted_nat = extraction.get("nationality", "").upper()
    profile_nat = profile.get("nationality", "").upper()
    if extracted_nat and profile_nat:
        total += 1
        if extracted_nat == profile_nat:
            matches["nationality"] = {"extracted": extracted_nat, "profile": profile_nat}
            score += 1
        else:
            mismatches["nationality"] = {"extracted": extracted_nat, "profile": profile_nat}

    return {
        "matches": matches,
        "mismatches": mismatches,
        "match_score": round(score / max(total, 1) * 100),
        "total_fields_checked": total,
        "fields_matched": len(matches),
    }
```

### 3.5 Document Expiry Checker

```python
import datetime

EXPIRY_WARNING_DAYS = 90

def check_document_expiry(expiry_date_iso: str | None) -> dict:
    """Check if document is expired or expiring soon."""
    if not expiry_date_iso:
        return {"status": "unknown", "message": "No expiry date available"}

    try:
        expiry = datetime.date.fromisoformat(expiry_date_iso)
    except ValueError:
        return {"status": "unknown", "message": f"Invalid date format: {expiry_date_iso}"}

    today = datetime.date.today()
    days_until_expiry = (expiry - today).days

    if days_until_expiry < 0:
        return {
            "status": "expired",
            "message": f"Document expired {abs(days_until_expiry)} days ago",
            "expiry_date": expiry_date_iso,
            "days_until_expiry": days_until_expiry,
        }
    elif days_until_expiry <= EXPIRY_WARNING_DAYS:
        return {
            "status": "expiring_soon",
            "message": f"Document expires in {days_until_expiry} days",
            "expiry_date": expiry_date_iso,
            "days_until_expiry": days_until_expiry,
        }
    else:
        return {
            "status": "valid",
            "message": "Document is valid",
            "expiry_date": expiry_date_iso,
            "days_until_expiry": days_until_expiry,
        }
```

### 3.6 API Endpoints

Add to `app/routers/kyc_cases.py` (or a new `app/routers/kyc_scanner.py`):

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/{case_id}/scan-document` | `require_ui_session` | Scan an attached document for MRZ/data extraction |
| `GET` | `/{case_id}/extractions` | `require_ui_session` | List all extraction results for a case |
| `GET` | `/{case_id}/extractions/{scan_id}` | `require_ui_session` | Get a specific extraction result |
| `POST` | `/{case_id}/validate-document` | `require_ui_session` | Validate document type requirements (sides, expiry) |
| `GET` | `/admin/cases/{case_id}/extractions` | `require_root_session` | Admin view of all extractions (includes cross-ref) |

**Scan request**:

```python
class ScanDocumentRequest(BaseModel):
    document_type: Literal["passport", "national_id_card", "driving_license", "residence_permit"]
    file_type: Literal["id_front", "id_back"] = "id_front"
    mrz_lines: list[str] | None = None  # Optional manual MRZ input for testing
```

**Scan response**:

```json
{
    "scan_id": "scan_abc123",
    "case_id": "kyc_def456",
    "document_type": "passport",
    "extraction": {
        "valid": true,
        "format": "TD3",
        "surname": "ERIKSSON",
        "given_names": "ANNA MARIA",
        "document_number": "L898902C3",
        "nationality": "UTO",
        "date_of_birth": "1974-08-12",
        "sex": "female",
        "expiry_date": "2012-04-15",
        "issuing_state": "UTO",
        "checksums": {
            "document_number": true,
            "date_of_birth": true,
            "expiry_date": true,
            "composite": true
        }
    },
    "expiry_check": {
        "status": "expired",
        "message": "Document expired 5159 days ago",
        "days_until_expiry": -5159
    },
    "cross_reference": {
        "match_score": 67,
        "matches": {"surname": {"extracted": "ERIKSSON", "profile": "Eriksson"}},
        "mismatches": {"date_of_birth": {"extracted": "1974-08-12", "profile": "1990-01-01"}}
    },
    "created_at": 1717000000
}
```

### 3.7 DDB Storage for Extractions

Extraction results stored in the `kyc_cases` table using the single-table pattern:

```
PK: KYC#{case_id}
SK: SCAN#{scan_id}

Fields:
  scan_id: str
  case_id: str
  document_type: str
  file_type: str ("id_front" | "id_back")
  extraction: dict (parsed MRZ fields)
  expiry_check: dict
  cross_reference: dict
  mrz_valid: bool
  created_at: int
  created_by: str (user_sub)
```

### 3.8 Frontend Components

**File**: `frontend/src/pages/kyc/KycDocumentScanner.tsx`

- Document type selector (passport, national ID, driving license, residence permit)
- Front/back image upload indicator showing which sides are needed
- "Scan Document" button that triggers `POST /{case_id}/scan-document`
- Extraction results display: parsed fields, checksum status indicators, expiry warning banner
- Cross-reference comparison table: extracted vs profile data with match/mismatch highlighting

**File**: `frontend/src/api/endpoints/kyc-scanner.ts`

```typescript
export const scanDocument = (caseId: string, data: ScanDocumentRequest) =>
  client.post(`/v1/kyc/cases/${caseId}/scan-document`, data);
export const getExtractions = (caseId: string) =>
  client.get(`/v1/kyc/cases/${caseId}/extractions`);
export const validateDocument = (caseId: string, data: ValidateDocumentRequest) =>
  client.post(`/v1/kyc/cases/${caseId}/validate-document`, data);
```

### 3.9 Registration

```python
# app/main.py — no new router needed if endpoints are added to kyc_cases router
# If separate router:
from app.routers.kyc_scanner import router as kyc_scanner_router
app.include_router(kyc_scanner_router)
```

---

## 4. Implementation Plan

### Phase 1: MRZ Parser (2 days)

| File | Change |
|------|--------|
| `app/services/kyc_document_scanner.py` | New: MRZ parser, TD3 + TD1 support, checksum validation (~350 lines) |

### Phase 2: Scanner Service (2 days)

| File | Change |
|------|--------|
| `app/services/kyc_document_scanner.py` | Add: mock scanner, cross-reference engine, expiry checker |
| `app/contracts/kyc_cases_contract.py` | Add: `ScanDocumentRequest`, `ScanResultOut`, `DocumentValidationOut` models |

### Phase 3: API Endpoints (2 days)

| File | Change |
|------|--------|
| `app/routers/kyc_cases.py` | Add: 5 new endpoints for scanning and extraction (~150 lines) |

### Phase 4: Frontend (2 days)

| File | Change |
|------|--------|
| `frontend/src/pages/kyc/KycDocumentScanner.tsx` | New: document scanner UI component |
| `frontend/src/api/endpoints/kyc-scanner.ts` | New: API endpoint wrappers |
| `frontend/src/api/types.ts` | Add: `ScanResult`, `DocumentExtraction`, `CrossReference` types |

### Phase 5: E2E Tests (2 days)

| File | Change |
|------|--------|
| `frontend/e2e/kyc-scanner.spec.ts` | New: ~20 tests, sections 187-190 |

---

## 5. E2E Test Plan (`frontend/e2e/kyc-scanner.spec.ts`)

**Test file**: `frontend/e2e/kyc-scanner.spec.ts`  
**Total tests**: ~20  
**Sections**: 187-190

### Section 187: MRZ Parsing API (6 tests)

1. `Scan passport with valid TD3 MRZ returns parsed fields` — POST scan with `document_type: "passport"`, `mrz_lines: [line1, line2]`; verify `extraction.surname`, `extraction.given_names`, `extraction.document_number`, `extraction.date_of_birth`.
2. `Scan passport with invalid checksum returns valid=false` — Modify one digit in MRZ line 2; verify `extraction.valid: false` and specific checksum field is `false`.
3. `Scan national ID with valid TD1 MRZ returns parsed fields` — POST scan with 3-line MRZ; verify all extracted fields.
4. `Scan with wrong MRZ line length returns error` — Provide MRZ lines with incorrect length; verify `extraction.error: "invalid_mrz_length"`.
5. `MRZ date parsing handles century pivot correctly` — DOB `740812` = 1974-08-12; DOB `200101` = 2020-01-01.
6. `Composite checksum validates across all fields` — Verify composite check covers document number + DOB + expiry + optional data.

### Section 188: Document Validation API (5 tests)

1. `Passport requires only front side` — POST validate with `document_type: "passport"`; verify `sides_required: ["front"]`.
2. `National ID requires front and back` — POST validate with `document_type: "national_id_card"`; verify `sides_required: ["front", "back"]`.
3. `Expired document returns status=expired` — Provide MRZ with expiry date in the past; verify `expiry_check.status: "expired"`.
4. `Document expiring within 90 days returns status=expiring_soon` — Provide MRZ with expiry 60 days from now; verify `expiry_check.status: "expiring_soon"`.
5. `Valid document returns status=valid` — Provide MRZ with expiry 2 years from now; verify `expiry_check.status: "valid"`.

### Section 189: Cross-Reference API (5 tests)

1. `Exact name match returns match_score=100` — Profile name matches extracted name exactly; verify `cross_reference.match_score: 100`.
2. `Surname-only match returns partial score` — First name differs but surname matches; verify score between 50-99.
3. `DOB mismatch is flagged` — Profile DOB differs from extracted DOB; verify `mismatches.date_of_birth` is present.
4. `All fields mismatch returns match_score=0` — Nothing matches; verify `match_score: 0`.
5. `Missing profile fields are not penalized` — Profile has no DOB or nationality; verify only available fields are checked.

### Section 190: Extraction Storage & Admin View (4 tests)

1. `GET /{case_id}/extractions returns list of scans` — After scanning front and back; verify 2 extraction records.
2. `GET /{case_id}/extractions/{scan_id} returns specific scan` — Verify scan_id matches and all fields present.
3. `Admin GET /admin/cases/{case_id}/extractions includes cross_reference` — Root user queries; verify full extraction with cross-reference data.
4. `Driving license scan without MRZ returns extraction with document_type only` — Driving license has no MRZ; verify `extraction.valid` is null and `document_type: "driving_license"`.

### Test Setup

```typescript
const TS = Date.now();
let alicePage: Page;
let rootPage: Page;
let caseId: string;

const VALID_PASSPORT_MRZ = [
  "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<",
  "L898902C36UTO7408122F1204159ZE184226B<<<<<10",
];

test.beforeAll(async ({ browser }) => {
  alicePage = await browser.newPage();
  await injectAuth(alicePage, "alice");
  rootPage = await browser.newPage();
  await injectAuth(rootPage, "root");

  // Create a KYC case
  const caseResp = await apiPost(alicePage, "alice", "/v1/kyc/cases", {});
  caseId = caseResp.case.kyc_case_id;
});
```

### Edge Cases

| Edge Case | Expected Behavior |
|-----------|-------------------|
| MRZ with all `<` filler characters | Parser returns empty strings for names; `valid` depends on checksums |
| Non-ASCII characters in MRZ | MRZ is ASCII-only per ICAO 9303; non-ASCII chars treated as `<` (value 0) |
| Case with no files attached | Scan endpoint returns 400 "no document attached for file_type" |
| Multiple scans of same document | Each scan creates a new extraction record; previous scans preserved |
| MRZ provided manually vs from image | Manual `mrz_lines` takes precedence over image-based extraction |

---

## 6. Security Considerations

- Document images are stored in S3 (mocked via moto in dev). Access is scoped to the case owner and admin users.
- Extracted PII (name, DOB, document number) is stored in the `kyc_cases` table alongside the case. Retention follows the same purge policy as the case itself (`kyc_retention_approved_days`, `kyc_retention_rejected_days`).
- MRZ parsing is deterministic and does not call external services. In production, the image-to-MRZ extraction would use an OCR service; in dev mode, the mock scanner is used.
- Cross-reference results are not stored on the user profile — they exist only within the case record.

---

## 7. Rollback Plan

- The scanner service is invoked explicitly via `POST /{case_id}/scan-document`. It does not modify the existing file attachment flow.
- Removing the endpoints and service file has no impact on existing KYC case lifecycle.
- Extraction records (`SK=SCAN#*`) are independent of the case `META` record and can be ignored by existing code.
