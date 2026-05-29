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

The current KYC system (see `app/routers/kyc_cases.py`) allows users to upload identity documents (selfie, id_front, id_back, proof_of_address) via `POST /{case_id}/files` (see `:734` for `attach_kyc_file`). However, the system treats these uploads as opaque file attachments -- there is no parsing, data extraction, or validation of document contents. The `_KYC_ALLOWED_FILE_TYPES` set (see `app/routers/kyc_cases.py:51`) defines categories but does not distinguish between a passport, national ID card, driving license, or residence permit.

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

**TD3 (Passport) -- 2 lines of 44 characters each**:

```
P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<
L898902C36UTO7408122F1204159ZE184226B<<<<<10
```

Line 1: `P<` + issuing state (3) + surname + `<<` + given names + filler
Line 2: document number (9) + check digit (1) + nationality (3) + DOB (6, YYMMDD) + check digit (1) + sex (1) + expiry (6, YYMMDD) + check digit (1) + optional data (14) + check digit (1) + composite check digit (1)

**TD1 (ID Card) -- 3 lines of 30 characters each**:

```
I<UTOD231458907<<<<<<<<<<<<<<<
7408122F1204159UTO<<<<<<<<<<<6
ERIKSSON<<ANNA<MARIA<<<<<<<<<<
```

---

## 2. Architecture Diagram

```
+-------------------------------------------------------------------------+
|                            Frontend (React)                             |
|                                                                         |
|  KycDocumentScanner.tsx                                                 |
|  +-------------------------------------------------------------------+ |
|  | DocumentTypeSelector                                               | |
|  |   [Passport] [National ID] [Driving License] [Residence Permit]   | |
|  |                                                                    | |
|  | SideIndicator (front required / back required)                    | |
|  |   [Front: uploaded] [Back: not uploaded]                          | |
|  |                                                                    | |
|  | "Scan Document" button -> POST /scan-document                     | |
|  |                                                                    | |
|  | ExtractionResults (after scan)                                    | |
|  |   +-- ParsedFieldsTable (surname, given_names, DOB, nationality) | |
|  |   +-- ChecksumStatusIndicators (pass/fail per field)             | |
|  |   +-- ExpiryBanner (valid / expiring_soon / expired)             | |
|  |   +-- CrossReferenceTable (extracted vs profile, match/mismatch)  | |
|  +-------------------------------------------------------------------+ |
+--------------------------|----------------------------------------------+
                           |
                  POST/GET |
                           v
+-------------------------------------------------------------------------+
|                       FastAPI Backend (8000)                             |
|                                                                         |
|  POST /{case_id}/scan-document                                          |
|  +-------------------------------------------------------------------+ |
|  | kyc_document_scanner.scan_document()                               | |
|  |   |                                                                | |
|  |   +-- detect_document_type() -> passport | national_id_card | ... | |
|  |   +-- extract_mrz()          -> raw MRZ lines (if applicable)     | |
|  |   +-- parse_mrz()            -> structured fields via TD3/TD1     | |
|  |   +-- validate_mrz_checksums() -> pass/fail per check digit       | |
|  |   +-- check_document_expiry()  -> valid | expired | expiring_soon | |
|  |   +-- cross_reference_profile()-> match score (name, DOB, nat)    | |
|  |   |                                                                | |
|  |   +-- Store extraction in kyc_cases table (SK=SCAN#{scan_id})     | |
|  |   +-- Return extraction result to caller                          | |
|  +-------------------------------------------------------------------+ |
|                                                                         |
|  GET /{case_id}/extractions        -> list all scan results            |
|  GET /{case_id}/extractions/{id}   -> single scan result               |
|  POST /{case_id}/validate-document -> check sides + expiry             |
|  GET /admin/cases/{id}/extractions -> full admin view with cross-ref   |
+--------------------------|----------------------------------------------+
                           |
          +----------------+----------------+
          |                                 |
          v                                 v
+-------------------+            +-------------------+
|   DynamoDB        |            |       S3          |
|                   |            |                   |
| kyc_cases table   |            | kyc-uploads/      |
| PK: KYC#{case_id}|            |   {tenant}/       |
| SK: META          |            |     {case_id}/    |
| SK: SCAN#{scan_id}|           |       id_front.jpg|
|   extraction: {}  |            |       id_back.jpg |
|   expiry_check: {}|            +-------------------+
|   cross_ref: {}   |
+-------------------+
```

---

## 3. Current State Analysis

### 3.1 File Attachment (see `app/routers/kyc_cases.py:734`)
<!-- NOTE: ticket originally cited line 733 -- actual is line 734 -->

The `attach_kyc_file()` endpoint accepts a `KycFileAttachmentRequest` with `file_type` (one of `selfie`, `id_front`, `id_back`, `proof_of_address`) and `file_node_id` (a reference to a file in the file manager). It validates the file type against `_KYC_ALLOWED_FILE_TYPES` (see `:51`) and appends a file record to the case's `files` array. No content analysis occurs.

### 3.2 File Validation (see `app/routers/kyc_cases.py:791`)
<!-- NOTE: ticket originally cited line 790 -- actual is line 791 -->

The `validate_kyc_file_requirements()` endpoint checks whether all required file types are present (selfie, id_front, id_back) but does not validate document contents, expiry, or data consistency.

### 3.3 File Manager Integration (`app/services/filemanager.py`)

The `get_node(user_sub, node_id)` function retrieves file metadata including `s3_key`, `mime_type`, `file_name`, and `file_size`. The scanner service will use `s3_key` to access the document image for processing.

### 3.4 KYC Cases Table Schema

The `kyc_cases` table uses `pk=KYC#{case_id}`, `sk=META` for the main case record. Extraction results will use `sk=SCAN#{scan_id}` to store per-document scan results alongside the case, following the single-table design pattern.

### 3.5 S3 Mock (`app/core/dev_s3.py`)

moto's in-process S3 mock stores uploaded files. The scanner can retrieve document images via boto3 `get_object()` using the file's `s3_key`.

---

## 4. Technical Design

### 4.1 Document Type Definitions

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

### 4.2 MRZ Parser

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
    """Parse TD3 (passport) MRZ -- 2 lines of 44 chars."""
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
    """Parse TD1 (ID card) MRZ -- 3 lines of 30 chars."""
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

### 4.3 Mock Scanner for Dev Mode

```python
def _mock_scan_document(
    *,
    case_id: str,
    document_type: DocumentType,
    file_metadata: dict,
) -> dict:
    """Mock document scanner -- returns structured extraction from test data.

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

### 4.4 Cross-Reference Engine

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
            # Partial match -- check if surname matches
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

### 4.5 Document Expiry Checker

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

### 4.6 API Endpoints

Add to `app/routers/kyc_cases.py` (or a new `app/routers/kyc_scanner.py`):

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/{case_id}/scan-document` | `require_ui_session` | Scan an attached document for MRZ/data extraction |
| `GET` | `/{case_id}/extractions` | `require_ui_session` | List all extraction results for a case |
| `GET` | `/{case_id}/extractions/{scan_id}` | `require_ui_session` | Get a specific extraction result |
| `POST` | `/{case_id}/validate-document` | `require_ui_session` | Validate document type requirements (sides, expiry) |
| `GET` | `/admin/cases/{case_id}/extractions` | `require_root_session` | Admin view of all extractions (includes cross-ref) |

### 4.7 DDB Storage for Extractions

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

### 4.8 Frontend Components

**File**: `frontend/src/pages/kyc/KycDocumentScanner.tsx`

- Document type selector (passport, national ID, driving license, residence permit)
- Front/back image upload indicator showing which sides are needed
- "Scan Document" button that triggers `POST /{case_id}/scan-document`
- Extraction results display: parsed fields, checksum status indicators, expiry warning banner
- Cross-reference comparison table: extracted vs profile data with match/mismatch highlighting

---

## 5. DynamoDB Access Patterns

| # | Access Pattern | Table | Key / Index | Notes |
|---|---------------|-------|-------------|-------|
| 1 | Store scan extraction | `kyc_cases` | PK=`KYC#{case_id}`, SK=`SCAN#{scan_id}` | PutItem with condition `attribute_not_exists(pk)` |
| 2 | Get single extraction | `kyc_cases` | PK=`KYC#{case_id}`, SK=`SCAN#{scan_id}` | GetItem |
| 3 | List all extractions for case | `kyc_cases` | PK=`KYC#{case_id}`, SK begins_with `SCAN#` | Query with `begins_with(sk, :prefix)` |
| 4 | Get case META (for cross-ref) | `kyc_cases` | PK=`KYC#{case_id}`, SK=`META` | Read user_sub from case |
| 5 | Get user profile (for cross-ref) | `profiles` | PK=`PROFILE#{user_sub}` | Read name, DOB, nationality |

### 5.1 Example DynamoDB Item (Scan Extraction)

```json
{
  "pk": { "S": "KYC#kyc_def456" },
  "sk": { "S": "SCAN#scan_abc123" },
  "scan_id": { "S": "scan_abc123" },
  "case_id": { "S": "kyc_def456" },
  "document_type": { "S": "passport" },
  "file_type": { "S": "id_front" },
  "extraction": {
    "M": {
      "valid": { "BOOL": true },
      "format": { "S": "TD3" },
      "surname": { "S": "ERIKSSON" },
      "given_names": { "S": "ANNA MARIA" },
      "document_number": { "S": "L898902C3" },
      "nationality": { "S": "UTO" },
      "date_of_birth": { "S": "1974-08-12" },
      "sex": { "S": "female" },
      "expiry_date": { "S": "2012-04-15" },
      "issuing_state": { "S": "UTO" },
      "checksums": {
        "M": {
          "document_number": { "BOOL": true },
          "date_of_birth": { "BOOL": true },
          "expiry_date": { "BOOL": true },
          "composite": { "BOOL": true }
        }
      }
    }
  },
  "expiry_check": {
    "M": {
      "status": { "S": "expired" },
      "message": { "S": "Document expired 5159 days ago" },
      "expiry_date": { "S": "2012-04-15" },
      "days_until_expiry": { "N": "-5159" }
    }
  },
  "cross_reference": {
    "M": {
      "match_score": { "N": "67" },
      "total_fields_checked": { "N": "3" },
      "fields_matched": { "N": "2" },
      "matches": {
        "M": {
          "surname": {
            "M": {
              "extracted": { "S": "ERIKSSON" },
              "profile": { "S": "Eriksson" }
            }
          }
        }
      },
      "mismatches": {
        "M": {
          "date_of_birth": {
            "M": {
              "extracted": { "S": "1974-08-12" },
              "profile": { "S": "1990-01-01" }
            }
          }
        }
      }
    }
  },
  "mrz_valid": { "BOOL": true },
  "created_at": { "N": "1717000000" },
  "created_by": { "S": "e2e_alice@test.local" }
}
```

---

## 6. API Request/Response Examples

### 6.1 Scan Passport Document

```bash
curl -X POST "http://localhost:8000/v1/kyc/cases/kyc_def456/scan-document" \
  -H "Cookie: ui_session=sess_alice; ui_access_token=eyJ...; ui_csrf=csrf_a" \
  -H "x-csrf-token: csrf_a" \
  -H "Content-Type: application/json" \
  -d '{
    "document_type": "passport",
    "file_type": "id_front",
    "mrz_lines": [
      "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<",
      "L898902C36UTO7408122F1204159ZE184226B<<<<<10"
    ]
  }'
```

**Response (200):**
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
      "optional_data": true,
      "composite": true
    }
  },
  "expiry_check": {
    "status": "expired",
    "message": "Document expired 5159 days ago",
    "expiry_date": "2012-04-15",
    "days_until_expiry": -5159
  },
  "cross_reference": {
    "match_score": 67,
    "total_fields_checked": 3,
    "fields_matched": 2,
    "matches": {
      "surname": {"extracted": "ERIKSSON", "profile": "Eriksson"}
    },
    "mismatches": {
      "date_of_birth": {"extracted": "1974-08-12", "profile": "1990-01-01"}
    }
  },
  "created_at": 1717000000
}
```

### 6.2 Scan National ID Card (TD1)

```bash
curl -X POST "http://localhost:8000/v1/kyc/cases/kyc_def456/scan-document" \
  -H "Cookie: ui_session=sess_alice; ui_access_token=eyJ...; ui_csrf=csrf_a" \
  -H "x-csrf-token: csrf_a" \
  -H "Content-Type: application/json" \
  -d '{
    "document_type": "national_id_card",
    "file_type": "id_front",
    "mrz_lines": [
      "I<UTOD231458907<<<<<<<<<<<<<<<",
      "7408122F1204159UTO<<<<<<<<<<<6",
      "ERIKSSON<<ANNA<MARIA<<<<<<<<<<"
    ]
  }'
```

**Response (200):**
```json
{
  "scan_id": "scan_def456",
  "case_id": "kyc_def456",
  "document_type": "national_id_card",
  "extraction": {
    "valid": true,
    "format": "TD1",
    "surname": "ERIKSSON",
    "given_names": "ANNA MARIA",
    "document_number": "D23145890",
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
  "created_at": 1717000001
}
```

### 6.3 List Extractions for Case

```bash
curl -X GET "http://localhost:8000/v1/kyc/cases/kyc_def456/extractions" \
  -H "Cookie: ui_session=sess_alice; ui_access_token=eyJ...; ui_csrf=csrf_a"
```

**Response (200):**
```json
{
  "extractions": [
    {
      "scan_id": "scan_abc123",
      "document_type": "passport",
      "file_type": "id_front",
      "mrz_valid": true,
      "expiry_status": "expired",
      "match_score": 67,
      "created_at": 1717000000
    },
    {
      "scan_id": "scan_def456",
      "document_type": "national_id_card",
      "file_type": "id_front",
      "mrz_valid": true,
      "expiry_status": "expired",
      "match_score": 67,
      "created_at": 1717000001
    }
  ]
}
```

### 6.4 Scan with Invalid MRZ Length (Error)

```bash
curl -X POST "http://localhost:8000/v1/kyc/cases/kyc_def456/scan-document" \
  -H "Cookie: ui_session=sess_alice; ui_access_token=eyJ...; ui_csrf=csrf_a" \
  -H "x-csrf-token: csrf_a" \
  -H "Content-Type: application/json" \
  -d '{"document_type": "passport", "file_type": "id_front", "mrz_lines": ["TOO_SHORT"]}'
```

**Response (200 -- extraction shows error):**
```json
{
  "scan_id": "scan_ghi789",
  "document_type": "passport",
  "extraction": {
    "error": "invalid_mrz_length",
    "valid": false
  },
  "expiry_check": {"status": "unknown", "message": "No expiry date available"},
  "cross_reference": null
}
```

---

## 7. Error Handling Matrix

| # | Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|---|----------|-------------|------------|---------------------|----------------|
| 1 | Case not found | 404 | `kyc_case_not_found` | "Case not found." | Verify case ID |
| 2 | Non-owner scans document | 403 | `kyc_access_forbidden` | "You do not own this case." | Use correct session |
| 3 | Invalid document_type | 422 | `validation_error` | "document_type must be passport, national_id_card, driving_license, or residence_permit." | Use valid type |
| 4 | No file attached for file_type | 400 | `kyc_file_not_attached` | "No document attached for the specified file_type." | Upload document first |
| 5 | MRZ lines wrong count for TD3 | 400 | `kyc_mrz_invalid_lines` | "Passport (TD3) requires exactly 2 MRZ lines." | Provide 2 lines |
| 6 | MRZ lines wrong count for TD1 | 400 | `kyc_mrz_invalid_lines` | "National ID (TD1) requires exactly 3 MRZ lines." | Provide 3 lines |
| 7 | MRZ line wrong length | 200 | -- | Returns `extraction.error: "invalid_mrz_length"` | Correct MRZ input |
| 8 | MRZ checksum failures | 200 | -- | Returns `extraction.valid: false` with failed checksums | Document may be damaged or tampered |
| 9 | Non-admin accesses admin extraction endpoint | 403 | `kyc_admin_role_required` | "Admin access required." | Use admin credentials |
| 10 | Scan on finalized case | 400 | `kyc_case_finalized` | "Cannot scan documents on a finalized case." | No action |
| 11 | Extraction not found | 404 | `kyc_scan_not_found` | "Extraction result not found." | Verify scan_id |
| 12 | Driving license with MRZ lines provided | 200 | -- | MRZ lines ignored; returns basic extraction | Expected behavior |

---

## 8. Pydantic Models

```python
from pydantic import BaseModel, Field
from typing import Literal


class ScanDocumentRequest(BaseModel):
    """Request to scan an attached identity document."""

    document_type: Literal["passport", "national_id_card", "driving_license", "residence_permit"] = Field(
        ...,
        description="Type of identity document to scan.",
        examples=["passport"],
    )
    file_type: Literal["id_front", "id_back"] = Field(
        "id_front",
        description="Which side of the document to scan.",
    )
    mrz_lines: list[str] | None = Field(
        None,
        description="Optional manual MRZ input for testing. If provided, takes precedence over image-based extraction.",
        examples=[["P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<", "L898902C36UTO7408122F1204159ZE184226B<<<<<10"]],
    )


class ValidateDocumentRequest(BaseModel):
    """Request to validate document type requirements."""

    document_type: Literal["passport", "national_id_card", "driving_license", "residence_permit"] = Field(
        ...,
        description="Type of identity document to validate requirements for.",
    )


class MrzChecksumOut(BaseModel):
    """MRZ checksum validation results."""

    document_number: bool = Field(..., description="Document number check digit valid.")
    date_of_birth: bool = Field(..., description="Date of birth check digit valid.")
    expiry_date: bool = Field(..., description="Expiry date check digit valid.")
    optional_data: bool | None = Field(None, description="Optional data check digit valid (TD3 only).")
    composite: bool = Field(..., description="Composite check digit valid.")


class DocumentExtractionOut(BaseModel):
    """Parsed MRZ extraction result."""

    valid: bool = Field(..., description="Whether all MRZ checksums passed.")
    format: str | None = Field(None, description="MRZ format: TD3 or TD1.")
    error: str | None = Field(None, description="Error code if parsing failed.")
    document_type: str | None = Field(None, description="Document type code from MRZ.")
    issuing_state: str | None = Field(None, description="3-letter issuing state code.")
    surname: str | None = Field(None, description="Extracted surname.")
    given_names: str | None = Field(None, description="Extracted given names.")
    document_number: str | None = Field(None, description="Extracted document number.")
    nationality: str | None = Field(None, description="3-letter nationality code.")
    date_of_birth: str | None = Field(None, description="Extracted DOB (YYYY-MM-DD).")
    sex: str | None = Field(None, description="Extracted sex: male, female, unspecified.")
    expiry_date: str | None = Field(None, description="Extracted expiry date (YYYY-MM-DD).")
    checksums: MrzChecksumOut | None = Field(None, description="Per-field checksum validation results.")


class ExpiryCheckOut(BaseModel):
    """Document expiry check result."""

    status: Literal["valid", "expired", "expiring_soon", "unknown"] = Field(
        ..., description="Expiry status."
    )
    message: str = Field(..., description="Human-readable expiry message.")
    expiry_date: str | None = Field(None, description="Expiry date (YYYY-MM-DD).")
    days_until_expiry: int | None = Field(None, description="Days until expiry (negative = expired).")


class CrossReferenceOut(BaseModel):
    """Cross-reference result comparing extraction against user profile."""

    match_score: int = Field(..., ge=0, le=100, description="Overall match score (0-100).")
    total_fields_checked: int = Field(..., description="Number of fields compared.")
    fields_matched: int = Field(..., description="Number of fields that matched.")
    matches: dict = Field(default_factory=dict, description="Fields that matched.")
    mismatches: dict = Field(default_factory=dict, description="Fields that did not match.")


class ScanResultOut(BaseModel):
    """Complete scan result for a document."""

    scan_id: str = Field(..., description="Unique scan ID.")
    case_id: str = Field(..., description="KYC case ID.")
    document_type: str = Field(..., description="Document type scanned.")
    file_type: str = Field(..., description="File side scanned (id_front / id_back).")
    extraction: DocumentExtractionOut
    expiry_check: ExpiryCheckOut
    cross_reference: CrossReferenceOut | None = Field(None, description="Profile cross-reference (null if extraction failed).")
    mrz_valid: bool = Field(..., description="Whether MRZ passed all checksums.")
    created_at: int = Field(..., description="Unix timestamp of scan.")


class ExtractionListOut(BaseModel):
    """List of extraction summaries for a case."""

    extractions: list[dict] = Field(default_factory=list)


class DocumentValidationOut(BaseModel):
    """Document type requirement validation result."""

    document_type: str
    sides_required: list[str]
    has_mrz: bool
    mrz_format: str | None
    sides_present: list[str]
    all_sides_present: bool
    expiry_status: str | None
```

---

## 9. Frontend Component Tree

```
KycCaseForm
└── KycDocumentScanner
    ├── Card (title="Document Scanner")
    │   ├── DocumentTypeSelector
    │   │   ├── ToggleGroup
    │   │   │   ├── Toggle ("Passport", icon=Globe)
    │   │   │   ├── Toggle ("National ID", icon=CreditCard)
    │   │   │   ├── Toggle ("Driving License", icon=Car)
    │   │   │   └── Toggle ("Residence Permit", icon=Home)
    │   │   └── SideRequirements
    │   │       ├── Badge ("Front: required" / "Front: uploaded")
    │   │       └── Badge ("Back: required" / "Back: uploaded" / "Back: N/A")
    │   ├── ScanButton
    │   │   └── Button ("Scan Document")
    │   │       └── onClick -> useMutation(POST /scan-document)
    │   └── MrzManualInput (dev mode only)
    │       ├── Textarea ("Paste MRZ lines")
    │       └── Text ("For testing: paste 2 lines for passport, 3 for ID card")
    ├── ExtractionResults (after scan completes)
    │   ├── ParsedFieldsCard
    │   │   └── DescriptionList
    │   │       ├── Item ("Surname", extraction.surname)
    │   │       ├── Item ("Given Names", extraction.given_names)
    │   │       ├── Item ("Document Number", extraction.document_number)
    │   │       ├── Item ("Nationality", extraction.nationality)
    │   │       ├── Item ("Date of Birth", extraction.date_of_birth)
    │   │       ├── Item ("Sex", extraction.sex)
    │   │       ├── Item ("Expiry Date", extraction.expiry_date)
    │   │       └── Item ("Issuing State", extraction.issuing_state)
    │   ├── ChecksumStatusCard
    │   │   └── ChecksumGrid
    │   │       ├── ChecksumBadge ("Doc Number", pass/fail)
    │   │       ├── ChecksumBadge ("DOB", pass/fail)
    │   │       ├── ChecksumBadge ("Expiry", pass/fail)
    │   │       ├── ChecksumBadge ("Optional", pass/fail)  [TD3 only]
    │   │       └── ChecksumBadge ("Composite", pass/fail)
    │   ├── ExpiryBanner
    │   │   ├── Alert variant="success" ("Document valid" + days remaining)
    │   │   ├── Alert variant="warning" ("Expiring soon" + days remaining)
    │   │   └── Alert variant="destructive" ("Expired" + days since)
    │   └── CrossReferenceTable
    │       ├── TableHeader (Field | Extracted | Profile | Match)
    │       └── TableBody
    │           ├── Row ("Name", extraction.name, profile.name, check/X)
    │           ├── Row ("DOB", extraction.dob, profile.dob, check/X)
    │           └── Row ("Nationality", extraction.nat, profile.nat, check/X)
    └── PreviousScansAccordion
        └── Accordion (one item per previous scan)
            └── ScanSummaryRow
                ├── ScanId + DocumentType badge
                ├── MrzValid badge
                ├── ExpiryStatus badge
                ├── MatchScore (percentage bar)
                └── Timestamp

KycCaseDetailPage (admin view)
└── ExtractionsTab
    ├── ExtractionTable (sortable by scan_id, document_type, created_at)
    │   └── ExtractionRow[]
    │       ├── DocumentType badge
    │       ├── MrzValid (pass/fail icon)
    │       ├── MatchScore (colored percentage)
    │       ├── ExpiryStatus badge
    │       └── ExpandButton -> full extraction details + cross-reference
    └── AdminNotes
        └── Textarea (per-extraction admin notes for review)
```

---

## 10. Observability & Monitoring

### 10.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `kyc_scan_total` | Counter | `document_type`, `file_type` | Total document scans |
| `kyc_scan_mrz_valid_total` | Counter | `document_type`, `valid` | MRZ validation outcomes |
| `kyc_scan_expiry_status_total` | Counter | `status` | Expiry check outcomes |
| `kyc_scan_match_score_histogram` | Histogram | `document_type` | Cross-reference match score distribution |
| `kyc_scan_checksum_failure_total` | Counter | `document_type`, `checksum_field` | Individual checksum failures |
| `kyc_scan_latency_seconds` | Histogram | `document_type` | Scan processing latency |

### 10.2 Structured Log Events

| Event | Level | Fields | Trigger |
|-------|-------|--------|---------|
| `kyc.scan.started` | INFO | `case_id`, `document_type`, `file_type` | Scan initiated |
| `kyc.scan.completed` | INFO | `case_id`, `scan_id`, `mrz_valid`, `expiry_status`, `match_score` | Scan completed |
| `kyc.scan.mrz_invalid` | WARN | `case_id`, `document_type`, `failed_checksums` | MRZ validation failed |
| `kyc.scan.expired_document` | WARN | `case_id`, `document_type`, `expiry_date`, `days_expired` | Document is expired |
| `kyc.scan.low_match_score` | WARN | `case_id`, `match_score`, `mismatches` | Cross-reference score < 50 |
| `kyc.scan.extraction_error` | ERROR | `case_id`, `document_type`, `error` | MRZ parsing error |

### 10.3 Alert Thresholds

| Alert | Condition | Severity |
|-------|----------|----------|
| High expired document rate | > 20% of scans return `expired` in 24h | P3 (Info) |
| Low match score rate | > 30% of scans have match_score < 50 in 24h | P2 (Warning) |
| Checksum failure spike | > 10% of scans have mrz_valid=false in 1h | P3 (Info) |
| Scan errors | > 5% of scans produce extraction errors in 1h | P2 (Warning) |

---

## 11. Performance Considerations

| Operation | Latency Target | DDB Cost | Notes |
|-----------|---------------|----------|-------|
| Parse TD3 MRZ | < 1ms | 0 DDB | Pure in-memory string parsing |
| Parse TD1 MRZ | < 1ms | 0 DDB | Pure in-memory string parsing |
| Checksum validation | < 1ms | 0 DDB | Arithmetic computation only |
| Cross-reference profile | < 50ms | 1 RCU | Single profile GetItem |
| Full scan pipeline | < 200ms | 2 WCU + 1 RCU | Profile read + extraction write |
| List extractions | < 100ms | 5 RCU | Query with begins_with |
| Get single extraction | < 50ms | 1 RCU | Single GetItem |

### Caching

- Document type requirements (`DOCUMENT_REQUIREMENTS`) are in-memory constants.
- MRZ weights and check digit algorithm are in-memory.
- User profile is read once per scan, not cached (profile may change between scans).

### Payload Size

- Scan result: ~2-3KB (extraction + expiry + cross-reference)
- MRZ lines input: ~100 bytes (2-3 lines of 30-44 chars)
- Extraction list summary: ~200 bytes per scan

---

## 12. Rollout Plan

### Feature Flags

| Flag | Default | Purpose |
|------|---------|---------|
| `KYC_DOCUMENT_SCANNER_ENABLED` | `false` | Gates scanner endpoints and UI |
| `KYC_SCANNER_CROSS_REFERENCE_ENABLED` | `false` | Gates cross-reference against profile |
| `KYC_SCANNER_EXPIRY_BLOCK_ENABLED` | `false` | Gates blocking expired documents from submission |

### Phases

| Phase | Action | Duration |
|-------|--------|----------|
| 1 | Deploy MRZ parser + mock scanner + endpoints behind flag | 2 days |
| 2 | Enable scanner on staging; validate TD3 + TD1 parsing | 1 day |
| 3 | Enable cross-reference; verify match scoring | 1 day |
| 4 | Enable in production (informational -- results stored, not blocking) | 1 week |
| 5 | Enable expiry blocking (expired documents prevent submission) | after 2 weeks |

### Rollback

1. Set `KYC_DOCUMENT_SCANNER_ENABLED=false` -- scanner endpoints return 404
2. Existing extraction records (SK=SCAN#*) remain in DDB but are ignored
3. KYC case submission flow is unaffected (scanner is optional)
4. No DDB schema changes to revert

---

## 13. E2E Test Plan (`frontend/e2e/kyc-scanner.spec.ts`)

**Test file**: `frontend/e2e/kyc-scanner.spec.ts`  
**Total tests**: ~20  
**Sections**: 187-190

### Section 187: MRZ Parsing API (6 tests)

1. `Scan passport with valid TD3 MRZ returns parsed fields` -- POST scan with `document_type: "passport"`, `mrz_lines: [line1, line2]`; verify `extraction.surname`, `extraction.given_names`, `extraction.document_number`, `extraction.date_of_birth`.
2. `Scan passport with invalid checksum returns valid=false` -- Modify one digit in MRZ line 2; verify `extraction.valid: false` and specific checksum field is `false`.
3. `Scan national ID with valid TD1 MRZ returns parsed fields` -- POST scan with 3-line MRZ; verify all extracted fields.
4. `Scan with wrong MRZ line length returns error` -- Provide MRZ lines with incorrect length; verify `extraction.error: "invalid_mrz_length"`.
5. `MRZ date parsing handles century pivot correctly` -- DOB `740812` = 1974-08-12; DOB `200101` = 2020-01-01.
6. `Composite checksum validates across all fields` -- Verify composite check covers document number + DOB + expiry + optional data.

### Section 188: Document Validation API (5 tests)

1. `Passport requires only front side` -- POST validate with `document_type: "passport"`; verify `sides_required: ["front"]`.
2. `National ID requires front and back` -- POST validate with `document_type: "national_id_card"`; verify `sides_required: ["front", "back"]`.
3. `Expired document returns status=expired` -- Provide MRZ with expiry date in the past; verify `expiry_check.status: "expired"`.
4. `Document expiring within 90 days returns status=expiring_soon` -- Provide MRZ with expiry 60 days from now; verify `expiry_check.status: "expiring_soon"`.
5. `Valid document returns status=valid` -- Provide MRZ with expiry 2 years from now; verify `expiry_check.status: "valid"`.

### Section 189: Cross-Reference API (5 tests)

1. `Exact name match returns match_score=100` -- Profile name matches extracted name exactly; verify `cross_reference.match_score: 100`.
2. `Surname-only match returns partial score` -- First name differs but surname matches; verify score between 50-99.
3. `DOB mismatch is flagged` -- Profile DOB differs from extracted DOB; verify `mismatches.date_of_birth` is present.
4. `All fields mismatch returns match_score=0` -- Nothing matches; verify `match_score: 0`.
5. `Missing profile fields are not penalized` -- Profile has no DOB or nationality; verify only available fields are checked.

### Section 190: Extraction Storage & Admin View (4 tests)

1. `GET /{case_id}/extractions returns list of scans` -- After scanning front and back; verify 2 extraction records.
2. `GET /{case_id}/extractions/{scan_id} returns specific scan` -- Verify scan_id matches and all fields present.
3. `Admin GET /admin/cases/{case_id}/extractions includes cross_reference` -- Root user queries; verify full extraction with cross-reference data.
4. `Driving license scan without MRZ returns extraction with document_type only` -- Driving license has no MRZ; verify `extraction.valid` is null and `document_type: "driving_license"`.

---

## 14. Expanded E2E Test Details

### Section 187a: MRZ Parsing Edge Cases (4 additional tests)

```typescript
test("187.7 MRZ with all filler characters returns empty names", async () => {
  // Provide MRZ with all '<' for names section
  // Verify extraction.surname = "" and extraction.given_names = ""
  // Verify checksums still evaluated
});

test("187.8 TD1 MRZ for residence permit parsed correctly", async () => {
  // POST scan with document_type: "residence_permit" and 3-line TD1 MRZ
  // Verify extraction.format = "TD1"
  // Verify all fields extracted same as national_id_card
});

test("187.9 Non-owner cannot scan another user's case", async () => {
  // Bob tries to POST scan-document on Alice's case
  // Expect 403
});

test("187.10 Multiple scans of same document type create separate records", async () => {
  // Scan passport twice
  // GET extractions
  // Verify 2 extraction records with different scan_ids
});
```

### Section 188a: Validation Edge Cases (3 additional tests)

```typescript
test("188.6 Validate driving license has no MRZ requirement", async () => {
  // POST validate with document_type: "driving_license"
  // Verify has_mrz = false, mrz_format = null
});

test("188.7 Scan on finalized case returns 400", async () => {
  // Approve a case, then try to scan
  // Expect 400 kyc_case_finalized
});

test("188.8 Validate returns sides_present based on attached files", async () => {
  // Attach only id_front, no id_back
  // POST validate for national_id_card
  // Verify sides_present = ["front"], all_sides_present = false
});
```

### Section 189a: Cross-Reference Edge Cases (3 additional tests)

```typescript
test("189.6 Cross-reference with case-insensitive name matching", async () => {
  // Profile has "eriksson" (lowercase), extraction has "ERIKSSON" (uppercase)
  // Verify surname match (case-insensitive comparison)
});

test("189.7 Cross-reference with nationality code mapping", async () => {
  // MRZ has "UTO" (3-letter code), profile has "UTO"
  // Verify nationality match
});

test("189.8 Cross-reference excluded when extraction fails", async () => {
  // Provide invalid MRZ (extraction.valid = false)
  // Verify cross_reference is null (not computed for failed extractions)
});
```

---

## 15. Security Considerations

- Document images are stored in S3 (mocked via moto in dev). Access is scoped to the case owner and admin users.
- Extracted PII (name, DOB, document number) is stored in the `kyc_cases` table alongside the case. Retention follows the same purge policy as the case itself (`kyc_retention_approved_days`, `kyc_retention_rejected_days`).
- MRZ parsing is deterministic and does not call external services. In production, the image-to-MRZ extraction would use an OCR service; in dev mode, the mock scanner is used.
- Cross-reference results are not stored on the user profile -- they exist only within the case record.

---

## 16. Implementation Plan

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
| `frontend/e2e/kyc-scanner.spec.ts` | New: ~20+ tests, sections 187-190 |

---

## 17. Rollback Plan

- The scanner service is invoked explicitly via `POST /{case_id}/scan-document`. It does not modify the existing file attachment flow.
- Removing the endpoints and service file has no impact on existing KYC case lifecycle.
- Extraction records (`SK=SCAN#*`) are independent of the case `META` record and can be ignored by existing code.

---

## Codebase References

> **Verification performed**: 2026-05-29

### Verified (EXISTS in codebase)

| Reference | File | Line(s) | Status |
|-----------|------|---------|--------|
| `attach_kyc_file()` endpoint | `app/routers/kyc_cases.py` | 734 | VERIFIED (ticket cites 733 -- off by 1) |
| `validate_kyc_file_requirements()` endpoint | `app/routers/kyc_cases.py` | 791 | VERIFIED (ticket cites 790 -- off by 1) |
| `_KYC_ALLOWED_FILE_TYPES` | `app/routers/kyc_cases.py` | 51 | VERIFIED |
| `submit_kyc_case()` | `app/routers/kyc_cases.py` | 830 | VERIFIED |
| KYC cases service | `app/services/kyc_cases.py` | all | VERIFIED (828 lines) |
| `kyc_cases` DDB table | `scripts/local-ddb-init.py` | 91-96 | VERIFIED |
| KYC settings | `app/core/settings.py` | 1065-1072 | VERIFIED |
| `app/contracts/kyc_cases_contract.py` | `app/contracts/` | exists | VERIFIED |

### Corrections

<!-- NOTE: The ticket cites `attach_kyc_file()` at line 733 -- actual line is 734. -->
<!-- NOTE: The ticket cites `validate_kyc_file_requirements()` at line 790 -- actual line is 791. -->

### Not Yet Implemented (requires new code)

| Reference | Expected Location | Status |
|-----------|-------------------|--------|
| `app/services/kyc_document_scanner.py` | `app/services/` | NOT FOUND -- new service required |
| `POST /{case_id}/scan-document` endpoint | `app/routers/kyc_cases.py` | NOT FOUND -- new endpoint required |
| `GET /{case_id}/scan/{scan_id}` endpoint | `app/routers/kyc_cases.py` | NOT FOUND -- new endpoint required |
| Scan result items (SK=SCAN#*) in kyc_cases | `kyc_cases` table | NOT FOUND -- new item pattern required |
| Scanner settings (provider, confidence threshold) | `app/core/settings.py` | NOT FOUND -- new settings required |
| MRZ/barcode parsing logic | `app/services/kyc_document_scanner.py` | NOT FOUND -- new implementation required |
| `frontend/src/pages/kyc/` scanner components | `frontend/src/pages/kyc/` | NOT FOUND -- no KYC frontend pages exist |

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_kyc_scanner.py`

Mock external dependencies with `moto` (DynamoDB) and `unittest.mock`. All tests run without the dev stack.

  - `test_parse_mrz_passport`
  - `test_parse_mrz_national_id`
  - `test_extract_photo_from_id`
  - `test_validate_mrz_checksum`
  - `test_detect_document_tampering`
  - `test_supported_document_formats`
  - `test_invalid_mrz_returns_error`

### Integration Tests

  - Passport upload triggers MRZ extraction and field population
  - National ID scan extracts photo region for facial comparison
  - Scanner results stored alongside document record in kyc_documents

### E2E Tests (Playwright)

**File**: `frontend/e2e/kyc-scanner.spec.ts`
**Test count**: 10

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

- **DDB seeds**: Seed `kyc_documents (scanner results)` table with test records in `beforeAll`
- **Test users**: Alice (USER), Bob (USER), Root (ROOT), Charlie (ADMIN) from `e2e_admin_session_setup.py`
- **Cleanup**: Tests use unique timestamps/IDs per run to avoid cross-run interference

### CI/Pipeline Considerations

- **Feature flag**: `KYC_SCANNER_ENABLED=true` must be set in test environment
- **Serial execution**: E2E tests run with `workers: 1` to avoid shared-state conflicts
- **Retry safety**: All tests are idempotent; retries do not produce duplicate records

## Dependencies & Merge Safety

### Depends On

| Ticket | Title | Why |
|--------|-------|-----|
| KYC-002 | Identity Document Verification | Extends document OCR with MRZ parsing |

### Depended On By

| Ticket | Title | Impact |
|--------|-------|--------|
| KYC-013 | User Self-Service Portal | Scanner integrated into user upload flow |
| KYC-014 | Facial Comparison | Extracted ID photo used for facial comparison |

### Merge Strategy

**Sequential**

Merge after KYC-002. This ticket depends on tables/services introduced by those tickets.

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
- [ ] All 10 E2E tests pass with `npx playwright test kyc-scanner.spec.ts`
