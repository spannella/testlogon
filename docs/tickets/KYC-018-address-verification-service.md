# KYC-018: Address Verification Service

**Ticket**: KYC-018
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 6-8 days
**Depends on**: KYC-004 (Proof of Residency)

---

## 1. Overview & Motivation

### 1.1 Problem Statement

The KYC case system (`app/routers/kyc_cases.py`, 1295 lines) accepts proof of residency documents (KYC-004) but has no mechanism to independently verify that the address a user provides actually exists, matches the submitted documents, or conforms to the official postal format for the user's country. Admins must manually cross-reference addresses against external postal databases, which is slow, inconsistent, and does not scale.

Address verification is a core component of robust KYC compliance. Regulatory frameworks (FATF, 4AMLD/5AMLD, FinCEN) require financial service providers to verify the residential address of customers. A user could submit a proof of residency document showing one address while entering a different address in their profile, and the system has no way to detect this discrepancy.

### 1.2 How It Works

1. User enters their address in the KYC case profile (or it is pre-populated from their user profile).
2. The backend calls the address verification service, which validates the address against postal authority data.
3. The service returns a confidence score: `verified` (exact match), `partial_match` (close but differs in formatting/unit), or `unverifiable` (no match found).
4. For `verified` and `partial_match` addresses, the service returns a standardized version of the address (official postal format) plus geocoding coordinates (lat/lng).
5. If a proof of residency document has been uploaded (KYC-004), the system cross-references the document's extracted address with the user-provided address.
6. Address verification results are stored on the KYC case and displayed to admins during review.
7. If the user changes their address after verification, the verification status resets to `pending` and re-verification is triggered.

### 1.3 Country-Specific Validation Rules

| Country | Format | Validation Rules |
|---------|--------|-----------------|
| US | ZIP+4 | 5-digit ZIP required; +4 optional; state abbreviation must match ZIP range |
| UK | Postcode | Format: `A9 9AA`, `A99 9AA`, `A9A 9AA`, `AA9 9AA`, `AA99 9AA`, `AA9A 9AA` |
| DE | PLZ | Exactly 5 digits |
| FR | Code postal | Exactly 5 digits; first 2 = department number |
| CA | Postal code | Format: `A9A 9A9` (letter-digit-letter space digit-letter-digit) |
| AU | Postcode | Exactly 4 digits; state must match postcode range |
| JP | Postal code | Format: `999-9999` (7 digits with hyphen) |
| Generic | — | Non-empty street, city, country; postal code if country requires one |

### 1.4 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| User | I enter my address and the system confirms it is valid | Address verification returns `verified` with standardized format |
| User | I enter a partial address and see the standardized suggestion | `partial_match` result shows corrected/standardized address |
| Admin | I see address verification status on the KYC case detail | Admin case detail shows verification_status, confidence, standardized address |
| System | User changes address after verification | Old verification invalidated; re-verification triggered |
| Admin | I compare document address with profile address | Cross-reference result shows match/mismatch with extracted vs provided |

---

## 2. Architecture Diagram

```
                            ┌──────────────────────────────────┐
                            │        Frontend (React)          │
                            │  KYC Case Detail Page            │
                            │  ┌────────────────────────┐      │
                            │  │ AddressVerificationBadge│     │
                            │  │ AddressVerificationPanel│     │
                            │  │ PostalCodeInput         │     │
                            │  └────────────────────────┘      │
                            └──────────────┬───────────────────┘
                                           │ HTTP (Axios + CSRF)
                                           ▼
                            ┌──────────────────────────────────┐
                            │        Backend (FastAPI)          │
                            │  app/routers/kyc_cases.py         │
                            │  ┌────────────────────────────┐  │
                            │  │ POST /verify-address        │  │
                            │  │ GET  /address-verification   │  │
                            │  │ POST /cross-reference-address│  │
                            │  │ POST /validate-postal-code   │  │
                            │  └──────────────┬─────────────┘  │
                            │                 │                 │
                            │  ┌──────────────▼─────────────┐  │
                            │  │ AddressVerificationService  │  │
                            │  │  verify_address()           │  │
                            │  │  cross_reference_document() │  │
                            │  │  validate_postal_code()     │  │
                            │  │  standardize_address()      │  │
                            │  │  geocode_address()          │  │
                            │  │  invalidate_verification()  │  │
                            │  └──────┬───────────┬─────────┘  │
                            │         │           │             │
                            │  ┌──────▼──┐  ┌────▼──────────┐  │
                            │  │MockAddr  │  │ExternalPostal │  │
                            │  │Provider  │  │API (prod)     │  │
                            │  │(dev mode)│  │               │  │
                            │  └─────────┘  └───────────────┘  │
                            └──────────────┬───────────────────┘
                                           │
                                           ▼
                            ┌──────────────────────────────────┐
                            │        DynamoDB                   │
                            │  kyc_cases table                  │
                            │  ┌────────────────────────────┐  │
                            │  │ Case item:                  │  │
                            │  │   address_verification: {   │  │
                            │  │     status, confidence,     │  │
                            │  │     standardized_address,   │  │
                            │  │     geocoding, ...          │  │
                            │  │   }                         │  │
                            │  └────────────────────────────┘  │
                            └──────────────────────────────────┘

Data Flow:
  1. User enters address in KYC case form
  2. Frontend POSTs to /verify-address
  3. Backend calls AddressVerificationService
  4. Service delegates to MockAddressProvider (dev) or external API (prod)
  5. Provider returns verification result
  6. Service stores result on KYC case item in DynamoDB
  7. Frontend displays badge + panel with verification status

Address Change Detection Flow:
  User Profile Update → user_profile.py hook
       │
       ▼
  Compare old/new address fields
       │ (if changed)
       ▼
  Find active KYC cases for user
       │
       ▼
  Reset address_verification.status = "pending"
       │
       ▼
  Trigger re-verification (async)
```

---

## 3. Current State Analysis

### 3.1 KYC Case Model (`app/contracts/kyc_cases_contract.py`)

The `KycCaseOut` model (line 52) contains an `intake_profile` field (string, optional) used to store a profile name reference, but no structured address fields. The case's associated user profile has address fields (`address_line_1`, `address_line_2`, `city`, `state`, `postal_code`, `country`) but these are not formally part of the KYC case data -- they live on the user profile record.

### 3.2 KYC File Attachments (`app/contracts/kyc_cases_contract.py`, line 133)

The `KycFileAttachmentRequest` model supports `file_type` values of `"selfie"`, `"id_front"`, `"id_back"`, `"proof_of_address"`. The proof_of_address attachment is stored but not parsed or compared against the user's entered address.

### 3.3 User Profile Service (`app/services/user_profile.py`)

User profiles are stored in the `users` DDB table with address fields. The profile can be updated at any time, and there is no notification/webhook mechanism when address fields change.

### 3.4 Existing Address Normalization (`app/core/normalize.py`)

The `normalize.py` module provides normalization for emails, phone numbers, CIDR ranges, and IP addresses, but has no address normalization capabilities.

---

## 4. Technical Design

### 4.1 New Service: `app/services/kyc_address_verification.py`

```python
class AddressVerificationResult:
    status: Literal["verified", "partial_match", "unverifiable", "pending", "error"]
    confidence_score: float          # 0.0 - 1.0
    input_address: dict[str, str]    # Original user-provided address
    standardized_address: dict[str, str] | None  # Postal-authority formatted address
    geocoding: dict[str, float] | None  # {"lat": float, "lng": float}
    country_format_valid: bool       # Whether postal code matches country format
    discrepancies: list[str]         # List of field-level differences
    verified_at: int | None          # Unix timestamp

class AddressVerificationService:
    def verify_address(self, *, address: dict[str, str],
                       country: str) -> AddressVerificationResult:
        """Validate address against postal authority data.
        In dev mode, uses mock provider (deterministic results)."""

    def cross_reference_document(self, *, user_address: dict[str, str],
                                  document_address: dict[str, str]) -> dict[str, Any]:
        """Compare user-provided address with address extracted from
        proof of residency document. Returns match_score and discrepancies."""

    def validate_postal_code(self, *, postal_code: str,
                              country: str) -> dict[str, Any]:
        """Country-specific postal code format validation."""

    def standardize_address(self, *, address: dict[str, str],
                             country: str) -> dict[str, str]:
        """Return address in official postal format for the country."""

    def geocode_address(self, *, address: dict[str, str]) -> dict[str, float] | None:
        """Return lat/lng for an address. Mock returns deterministic coords
        based on hash of address string."""

    def invalidate_verification(self, *, case_id: str) -> None:
        """Reset verification status to pending (called on address change)."""
```

### 4.2 Mock Address Provider (Dev Mode)

When `S.dev_mode` is `True`, the verification service uses a built-in mock provider instead of calling an external API:

```python
class MockAddressProvider:
    """Deterministic mock for dev/test.
    - Any address with "123 Main St" -> verified, confidence=1.0
    - Any address with "456 Oak" -> partial_match, confidence=0.75
    - Any address with "999 Nonexistent" -> unverifiable, confidence=0.0
    - All others -> verified, confidence=0.9
    Geocoding: lat/lng derived from hash of concatenated address fields."""
```

### 4.3 Pydantic Models

```python
# app/contracts/kyc_cases_contract.py additions

from pydantic import BaseModel, Field
from typing import Optional, Literal


class AddressInput(BaseModel):
    """Structured address input for verification."""
    line_1: str = Field(..., min_length=1, max_length=200,
                        description="Street address line 1")
    line_2: str = Field(default="", max_length=200,
                        description="Apartment, suite, unit, etc.")
    city: str = Field(..., min_length=1, max_length=100,
                      description="City or municipality")
    state: str = Field(default="", max_length=100,
                       description="State, province, or region")
    postal_code: str = Field(..., min_length=1, max_length=20,
                             description="Postal or ZIP code")
    country: str = Field(..., min_length=2, max_length=2,
                         description="ISO 3166-1 alpha-2 country code")

    class Config:
        json_schema_extra = {
            "example": {
                "line_1": "123 Main St",
                "line_2": "Apt 4B",
                "city": "New York",
                "state": "NY",
                "postal_code": "10001",
                "country": "US"
            }
        }


class VerifyAddressRequest(BaseModel):
    """Request body for POST /verify-address."""
    address: AddressInput


class PostalCodeValidationRequest(BaseModel):
    """Request body for POST /validate-postal-code."""
    postal_code: str = Field(..., min_length=1, max_length=20)
    country: str = Field(..., min_length=2, max_length=2)


class CrossReferenceRequest(BaseModel):
    """Request body for POST /cross-reference-address."""
    document_address: AddressInput


class GeocodingOut(BaseModel):
    """Geocoding coordinates."""
    lat: float = Field(..., ge=-90.0, le=90.0)
    lng: float = Field(..., ge=-180.0, le=180.0)


class AddressVerificationOut(BaseModel):
    """Address verification result."""
    status: Literal["verified", "partial_match", "unverifiable", "pending", "error"]
    confidence_score: float = Field(default=0.0, ge=0.0, le=1.0)
    input_address: Optional[AddressInput] = None
    standardized_address: Optional[AddressInput] = None
    geocoding: Optional[GeocodingOut] = None
    country_format_valid: bool = False
    discrepancies: list[str] = Field(default_factory=list)
    verified_at: Optional[int] = None

    class Config:
        json_schema_extra = {
            "example": {
                "status": "verified",
                "confidence_score": 0.95,
                "input_address": {
                    "line_1": "123 Main St",
                    "city": "New York",
                    "state": "NY",
                    "postal_code": "10001",
                    "country": "US"
                },
                "standardized_address": {
                    "line_1": "123 MAIN ST",
                    "city": "NEW YORK",
                    "state": "NY",
                    "postal_code": "10001-1234",
                    "country": "US"
                },
                "geocoding": {"lat": 40.7128, "lng": -74.006},
                "country_format_valid": True,
                "discrepancies": [],
                "verified_at": 1748520000
            }
        }


class PostalCodeValidationOut(BaseModel):
    """Postal code validation result."""
    valid: bool
    format_hint: str = ""
    normalized: str = ""


class CrossReferenceOut(BaseModel):
    """Cross-reference result between user address and document address."""
    match_score: float = Field(default=0.0, ge=0.0, le=1.0)
    discrepancies: list[str] = Field(default_factory=list)
    field_comparisons: list[dict] = Field(default_factory=list)
```

### 4.4 Router Endpoints

Add endpoints to `app/routers/kyc_cases.py` (extending existing router):

```python
POST /v1/kyc/cases/{case_id}/verify-address
  — Trigger address verification for the case's profile address
  — Auth: require_ui_session (case owner or admin)
  — Body: { "address": { "line_1": str, "line_2": str, "city": str,
             "state": str, "postal_code": str, "country": str } }
  — Response: { "verification": AddressVerificationResult }

GET  /v1/kyc/cases/{case_id}/address-verification
  — Get current verification status
  — Auth: require_ui_session (case owner or admin)
  — Response: { "verification": AddressVerificationResult }

POST /v1/kyc/cases/{case_id}/cross-reference-address
  — Compare profile address with document address (admin only)
  — Auth: require_admin_session
  — Body: { "document_address": { ... } }
  — Response: { "cross_reference": { match_score, discrepancies } }

POST /v1/kyc/validate-postal-code
  — Standalone postal code format validation
  — Auth: require_ui_session
  — Body: { "postal_code": str, "country": str }
  — Response: { "valid": bool, "format_hint": str }
```

### 4.5 API Request/Response Examples

**POST /v1/kyc/cases/{case_id}/verify-address**

```bash
curl -X POST http://localhost:8000/v1/kyc/cases/kyc_abc123/verify-address \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_xxx; ui_csrf=csrf_xxx; ui_access_token=jwt_xxx" \
  -H "x-csrf-token: csrf_xxx" \
  -d '{
    "address": {
      "line_1": "123 Main St",
      "line_2": "Apt 4B",
      "city": "New York",
      "state": "NY",
      "postal_code": "10001",
      "country": "US"
    }
  }'
```

Response (200):
```json
{
  "verification": {
    "status": "verified",
    "confidence_score": 1.0,
    "input_address": {
      "line_1": "123 Main St",
      "line_2": "Apt 4B",
      "city": "New York",
      "state": "NY",
      "postal_code": "10001",
      "country": "US"
    },
    "standardized_address": {
      "line_1": "123 MAIN ST APT 4B",
      "line_2": "",
      "city": "NEW YORK",
      "state": "NY",
      "postal_code": "10001-1234",
      "country": "US"
    },
    "geocoding": {
      "lat": 40.7484,
      "lng": -73.9967
    },
    "country_format_valid": true,
    "discrepancies": [],
    "verified_at": 1748520000
  }
}
```

**POST /v1/kyc/cases/{case_id}/verify-address (partial match)**

```bash
curl -X POST http://localhost:8000/v1/kyc/cases/kyc_abc123/verify-address \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_xxx; ui_csrf=csrf_xxx; ui_access_token=jwt_xxx" \
  -H "x-csrf-token: csrf_xxx" \
  -d '{
    "address": {
      "line_1": "456 Oak Ave",
      "city": "Springfield",
      "state": "IL",
      "postal_code": "62704",
      "country": "US"
    }
  }'
```

Response (200):
```json
{
  "verification": {
    "status": "partial_match",
    "confidence_score": 0.75,
    "input_address": {
      "line_1": "456 Oak Ave",
      "city": "Springfield",
      "state": "IL",
      "postal_code": "62704",
      "country": "US"
    },
    "standardized_address": {
      "line_1": "456 OAK AVENUE",
      "city": "SPRINGFIELD",
      "state": "IL",
      "postal_code": "62704-3201",
      "country": "US"
    },
    "geocoding": {
      "lat": 39.7817,
      "lng": -89.6501
    },
    "country_format_valid": true,
    "discrepancies": ["line_1_abbreviation_differs"],
    "verified_at": 1748520000
  }
}
```

**GET /v1/kyc/cases/{case_id}/address-verification**

```bash
curl -X GET http://localhost:8000/v1/kyc/cases/kyc_abc123/address-verification \
  -H "Cookie: ui_session=sess_xxx; ui_access_token=jwt_xxx"
```

Response (200):
```json
{
  "verification": {
    "status": "verified",
    "confidence_score": 1.0,
    "input_address": {
      "line_1": "123 Main St",
      "city": "New York",
      "state": "NY",
      "postal_code": "10001",
      "country": "US"
    },
    "standardized_address": {
      "line_1": "123 MAIN ST APT 4B",
      "city": "NEW YORK",
      "state": "NY",
      "postal_code": "10001-1234",
      "country": "US"
    },
    "geocoding": {"lat": 40.7484, "lng": -73.9967},
    "country_format_valid": true,
    "discrepancies": [],
    "verified_at": 1748520000
  }
}
```

**POST /v1/kyc/cases/{case_id}/cross-reference-address**

```bash
curl -X POST http://localhost:8000/v1/kyc/cases/kyc_abc123/cross-reference-address \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_xxx; ui_csrf=csrf_xxx; ui_access_token=jwt_xxx" \
  -H "x-csrf-token: csrf_xxx" \
  -d '{
    "document_address": {
      "line_1": "123 Main Street",
      "city": "New York",
      "state": "New York",
      "postal_code": "10002",
      "country": "US"
    }
  }'
```

Response (200):
```json
{
  "cross_reference": {
    "match_score": 0.72,
    "discrepancies": ["postal_code_differs", "state_format_differs"],
    "field_comparisons": [
      {"field": "line_1", "profile": "123 Main St", "document": "123 Main Street", "match": true},
      {"field": "city", "profile": "New York", "document": "New York", "match": true},
      {"field": "state", "profile": "NY", "document": "New York", "match": true},
      {"field": "postal_code", "profile": "10001", "document": "10002", "match": false}
    ]
  }
}
```

**POST /v1/kyc/validate-postal-code**

```bash
curl -X POST http://localhost:8000/v1/kyc/validate-postal-code \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_xxx; ui_csrf=csrf_xxx; ui_access_token=jwt_xxx" \
  -H "x-csrf-token: csrf_xxx" \
  -d '{"postal_code": "ABCDE", "country": "US"}'
```

Response (200):
```json
{
  "valid": false,
  "format_hint": "US ZIP code must be 5 digits, optionally followed by a hyphen and 4 digits (e.g., 10001 or 10001-1234)",
  "normalized": ""
}
```

### 4.6 DynamoDB Storage & Access Patterns

Address verification results are stored as nested attributes on the KYC case item in the `kyc_cases` table (no new table needed):

```json
{
  "address_verification": {
    "status": "verified",
    "confidence_score": 0.95,
    "input_address": { "line_1": "123 Main St", "city": "New York", "state": "NY", "postal_code": "10001", "country": "US" },
    "standardized_address": { "line_1": "123 MAIN ST", "city": "NEW YORK", "state": "NY", "postal_code": "10001-1234", "country": "US" },
    "geocoding": { "lat": 40.7128, "lng": -74.006 },
    "country_format_valid": true,
    "verified_at": 1717000000,
    "cross_reference": {
      "document_match_score": 0.88,
      "discrepancies": ["postal_code_differs"]
    }
  }
}
```

**Detailed DynamoDB Access Patterns:**

| # | Access Pattern | Table / GSI | PK | SK | Operation | Notes |
|---|---------------|-------------|----|----|-----------|-------|
| 1 | Get case with address verification | Main table | `kyc_case_id` | `META` | GetItem | Includes `address_verification` nested map |
| 2 | Update verification result | Main table | `kyc_case_id` | `META` | UpdateItem `SET address_verification = :av` | Conditional on `attribute_exists(kyc_case_id)` |
| 3 | Reset verification to pending | Main table | `kyc_case_id` | `META` | UpdateItem `SET address_verification.status = :pending` | Called on address change |
| 4 | Find active cases for user | GSI `user-sub-index` | `user_sub` | N/A | Query | Returns all cases for a user; filter for `status != closed` |
| 5 | Store cross-reference result | Main table | `kyc_case_id` | `META` | UpdateItem `SET address_verification.cross_reference = :cr` | Appends to existing verification |
| 6 | Check readiness for tier_2+ | Main table | `kyc_case_id` | `META` | GetItem | Check `address_verification.status` in readiness logic |

### 4.7 Address Change Detection

Add a post-update hook to user profile updates. When address fields (`address_line_1`, `city`, `state`, `postal_code`, `country`) change on the user profile, find any active KYC cases for the user and reset their `address_verification.status` to `pending`.

Implementation: extend `app/services/user_profile.py` `update_profile` function to compare old/new address fields and call `AddressVerificationService.invalidate_verification` if changed.

### 4.8 Integration with KYC Case Readiness

Extend `_readiness_for_case` in `app/routers/kyc_cases.py`:

```python
# Check address verification for tier_2+
if target_tier in ("tier_2", "tier_3"):
    av = case.get("address_verification", {})
    if av.get("status") not in ("verified", "partial_match"):
        missing_requirements.append("address_not_verified")
```

### 4.9 Frontend Components

Extend the KYC case detail page (user-facing) with:

- `AddressVerificationBadge` -- Shows verified/partial/unverifiable status with icon
- `AddressVerificationPanel` -- Shows standardized address, geocoding map placeholder, cross-reference results
- `PostalCodeInput` -- Input with real-time format validation based on selected country

These integrate into the existing KYC case flow rather than requiring a new page.

### 4.10 Frontend Component Tree

```
KycCaseDetailPage
├── CaseHeader
│   ├── CaseStatusBadge
│   └── CaseTierBadge
├── ProfileSection
│   ├── AddressForm
│   │   ├── Line1Input
│   │   ├── Line2Input
│   │   ├── CityInput
│   │   ├── StateInput
│   │   ├── PostalCodeInput
│   │   │   └── FormatHint (dynamic per country)
│   │   └── CountrySelect
│   ├── AddressVerificationBadge
│   │   ├── StatusIcon (CheckCircle / AlertTriangle / XCircle)
│   │   └── StatusText ("Verified" / "Partial Match" / "Unverifiable")
│   └── VerifyAddressButton
│       └── onClick → POST /verify-address
├── AddressVerificationPanel (shown after verification)
│   ├── StandardizedAddressCard
│   │   ├── FormattedAddress (official postal format)
│   │   └── ConfidenceBar (0-100% visual)
│   ├── GeocodingDisplay
│   │   └── Placeholder map with lat/lng coordinates
│   ├── DiscrepancyList (if any)
│   │   └── DiscrepancyItem (field name + details)
│   └── CrossReferenceSection (admin only)
│       ├── DocumentAddressCard
│       ├── ProfileAddressCard
│       ├── MatchScoreBadge
│       └── FieldComparisonTable
└── DocumentsSection
    └── ... (existing)
```

**Props interfaces:**

```typescript
interface AddressVerificationBadgeProps {
  status: "verified" | "partial_match" | "unverifiable" | "pending" | "error";
  confidence?: number;
}

interface AddressVerificationPanelProps {
  verification: AddressVerificationResult;
  crossReference?: CrossReferenceResult;
  isAdmin: boolean;
}

interface PostalCodeInputProps {
  value: string;
  onChange: (value: string) => void;
  country: string;
  onValidation?: (result: PostalCodeValidationResult) => void;
}

interface AddressFormProps {
  address: AddressInput;
  onChange: (address: AddressInput) => void;
  verificationStatus?: string;
  disabled?: boolean;
}
```

---

## 5. Error Handling Matrix

| Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|----------|-------------|------------|---------------------|-----------------|
| Case not found | 404 | `case_not_found` | "KYC case not found" | Verify case ID |
| User not case owner or admin | 403 | `forbidden` | "You do not have access to this case" | Use correct account |
| Address fields missing required | 422 | `validation_error` | "Street address and city are required" | Fill in required fields |
| Postal code format invalid | 200 | N/A (returned in validation result) | "Invalid format for US ZIP code" | Follow format hint |
| Country code not recognized | 400 | `invalid_country` | "Country code 'XX' is not recognized" | Use ISO 3166-1 alpha-2 code |
| External API timeout (prod) | 503 | `verification_service_unavailable` | "Address verification temporarily unavailable" | Retry in a few minutes |
| External API rate limited (prod) | 429 | `verification_rate_limited` | "Too many verification requests. Please try again later" | Wait and retry |
| Case already verified (re-verify) | 200 | N/A | Returns new verification result | Old result overwritten |
| Cross-reference without proof doc | 400 | `no_document_address` | "No proof of address document found on this case" | Upload proof of address first |
| Non-admin attempts cross-reference | 403 | `admin_required` | "Admin access required for cross-reference" | Contact admin |
| Address verification disabled (flag) | 400 | `feature_disabled` | "Address verification is currently disabled" | Enable `kyc_address_verification_enabled` |
| DynamoDB write failure | 500 | `internal_error` | "Failed to store verification result" | Retry request |

---

## 6. Observability & Monitoring

### 6.1 Metrics

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `kyc_address_verification_total` | Counter | `status` (verified/partial/unverifiable/error), `country` | Total verification attempts by outcome and country |
| `kyc_address_verification_latency_seconds` | Histogram | `country`, `provider` (mock/external) | Verification request duration |
| `kyc_postal_code_validation_total` | Counter | `country`, `valid` (true/false) | Postal code validation attempts |
| `kyc_cross_reference_total` | Counter | `match_result` (high/medium/low) | Cross-reference attempts by match quality |
| `kyc_address_change_invalidation_total` | Counter | | Address changes that triggered re-verification |
| `kyc_address_geocoding_total` | Counter | `status` (success/failed) | Geocoding attempts |

### 6.2 Log Events

| Log Event | Level | Fields | Trigger |
|-----------|-------|--------|---------|
| `address_verification.completed` | INFO | `case_id`, `status`, `confidence`, `country`, `duration_ms` | Verification completes |
| `address_verification.invalidated` | INFO | `case_id`, `user_sub`, `changed_fields` | Address change triggers reset |
| `address_verification.cross_reference` | INFO | `case_id`, `admin_sub`, `match_score` | Admin runs cross-reference |
| `address_verification.provider_error` | ERROR | `case_id`, `provider`, `error_message` | External provider fails |
| `address_verification.postal_invalid` | DEBUG | `country`, `postal_code`, `format_hint` | Postal code validation fails |

### 6.3 Alerting

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| High unverifiable rate | > 30% of verifications return `unverifiable` in 1 hour | Warning | Review address input quality; check provider health |
| Verification service errors | > 5 `error` outcomes in 5 minutes | Critical | Check external API connectivity; fall back to mock |
| Latency spike | P95 verification latency > 5 seconds for 10 minutes | Warning | Check external API performance; consider cache |
| Cross-reference mismatch spike | > 50% of cross-references have match_score < 0.5 in 1 day | Warning | Review document OCR quality; check user input guidance |

---

## 7. Rollout Plan

### 7.1 Feature Flags

| Flag | Environment Variable | Default | Description |
|------|---------------------|---------|-------------|
| `kyc_address_verification_enabled` | `KYC_ADDRESS_VERIFICATION_ENABLED` | `true` (dev), `false` (prod) | Master switch for address verification |
| `kyc_address_geocoding_enabled` | `KYC_ADDRESS_GEOCODING_ENABLED` | `true` | Enable geocoding (can be disabled to reduce API calls) |
| `kyc_address_auto_reverify` | `KYC_ADDRESS_AUTO_REVERIFY` | `true` | Auto-reverify on address change |

### 7.2 Phased Rollout

**Phase 1: Infrastructure (Days 1-2)**
- Create `AddressVerificationService` with mock provider
- Add postal code validation rules for all supported countries
- Add Pydantic models
- Feature flag: `KYC_ADDRESS_VERIFICATION_ENABLED=true` (dev only)

**Phase 2: Endpoints + Backend Integration (Days 3-4)**
- Add 4 router endpoints
- Integrate with KYC case readiness check
- Add address change detection hook in user_profile.py
- Deploy behind feature flag

**Phase 3: Frontend Components (Days 5-6)**
- Build AddressVerificationBadge, AddressVerificationPanel, PostalCodeInput
- Integrate into KYC case detail page
- Manual testing with mock provider

**Phase 4: E2E Tests + Rollout (Days 7-8)**
- Write 15 E2E tests
- Enable flag for 10% of users in production
- Monitor metrics for 48 hours
- Ramp to 100%

### 7.3 Rollback Procedure

1. Set `KYC_ADDRESS_VERIFICATION_ENABLED=false` -- endpoints return 400 "feature disabled"
2. Existing verification results remain on case items (harmless)
3. Readiness check skips address verification requirement when flag is off
4. Frontend hides verification panel when flag is off
5. No data migration needed for rollback

---

## 8. Performance Considerations

### 8.1 Query Costs

| Operation | DDB Operations | Estimated Cost |
|-----------|---------------|----------------|
| Verify address | 1 GetItem (case) + 1 UpdateItem (store result) | 2 WCU + 1 RCU |
| Get verification status | 1 GetItem (case) | 1 RCU |
| Cross-reference | 1 GetItem (case) + 1 UpdateItem (store result) | 2 WCU + 1 RCU |
| Postal code validation | 0 DDB operations (in-memory) | 0 |
| Address change invalidation | 1 Query (find cases) + N UpdateItems (reset) | N WCU + 1 RCU |

### 8.2 Caching Strategy

| Cache Layer | TTL | Scope | Invalidation |
|-------------|-----|-------|-------------|
| Mock provider results | Infinite (deterministic) | Per-address hash | N/A |
| External provider results | 24 hours | Per-address hash | On address change |
| Postal code rules | Static (in-memory) | Per-country | Deploy-time only |

### 8.3 Rate Limiting

| Endpoint | Limit | Scope |
|----------|-------|-------|
| POST /verify-address | 10 per hour per user | Per-user rate limit |
| POST /validate-postal-code | 60 per minute per user | Per-user rate limit |
| POST /cross-reference-address | 20 per hour per admin | Per-admin rate limit |

### 8.4 Pagination

No pagination needed for this feature -- all operations are single-item or single-case.

---

## 9. E2E Test Plan

**Test file**: `frontend/e2e/kyc-address-verification.spec.ts`
**Total**: ~22 tests across 4 sections (218-221)

### Section 218: Address Verification API (8 tests)

```typescript
test("218.1 Verify valid US address returns verified status", async ({ page }) => {
  // Create KYC case, POST verify-address with "123 Main St", country="US"
  // Expect status="verified", confidence_score >= 0.9
});

test("218.2 Verify partial-match address returns corrected version", async ({ page }) => {
  // POST verify-address with "456 Oak Ave" (mock partial match)
  // Expect status="partial_match", standardized_address differs from input
});

test("218.3 Verify unrecognized address returns unverifiable", async ({ page }) => {
  // POST verify-address with "999 Nonexistent Rd"
  // Expect status="unverifiable", confidence_score=0.0
});

test("218.4 Geocoding returns lat/lng for verified address", async ({ page }) => {
  // After verification, check geocoding field
  // Expect lat and lng are numbers (not null)
});

test("218.5 Non-owner cannot verify another user's case address", async ({ page }) => {
  // Bob tries to verify Alice's case address
  // Expect 403
});

test("218.6 Verify-address on non-existent case returns 404", async ({ page }) => {
  // POST verify-address with fake case_id
  // Expect 404
});

test("218.7 Standardized address uses uppercase formatting", async ({ page }) => {
  // POST verify-address with lowercase input
  // Expect standardized_address fields are uppercase
});

test("218.8 Re-verification overwrites previous result", async ({ page }) => {
  // Verify address, then verify again with different address
  // GET -> latest result returned, not the first
});
```

### Section 219: Postal Code Validation & Cross-Reference (7 tests)

```typescript
test("219.1 US ZIP+4 format validates correctly", async ({ page }) => {
  // POST validate-postal-code with "10001-1234", country="US"
  // Expect valid=true
});

test("219.2 UK postcode format validates correctly", async ({ page }) => {
  // POST validate-postal-code with "SW1A 1AA", country="GB"
  // Expect valid=true
});

test("219.3 Invalid US ZIP returns valid=false with format hint", async ({ page }) => {
  // POST validate-postal-code with "ABCDE", country="US"
  // Expect valid=false, format_hint contains "5-digit"
});

test("219.4 German PLZ validates 5 digits", async ({ page }) => {
  // POST validate-postal-code with "10115", country="DE"
  // Expect valid=true
});

test("219.5 Canadian postal code format validates", async ({ page }) => {
  // POST validate-postal-code with "K1A 0B1", country="CA"
  // Expect valid=true
});

test("219.6 Cross-reference matching addresses returns high score", async ({ page }) => {
  // Admin POST cross-reference with user address matching document address
  // Expect match_score >= 0.8, discrepancies empty
});

test("219.7 Cross-reference mismatched addresses returns low score and discrepancies", async ({ page }) => {
  // Admin POST cross-reference with differing postal codes
  // Expect match_score < 0.8, discrepancies includes "postal_code_differs"
});
```

### Section 220: Address Change Re-verification & Readiness (4 tests)

```typescript
test("220.1 Address verification status appears in case detail", async ({ page }) => {
  // GET case after verification
  // Expect address_verification object with status, confidence_score
});

test("220.2 Changing address resets verification to pending", async ({ page }) => {
  // Verify address, then PATCH user profile with new address
  // GET case -> address_verification.status == "pending"
});

test("220.3 Case readiness includes address_not_verified for tier_2", async ({ page }) => {
  // Create tier_2 case without verifying address
  // GET readiness -> missing_requirements includes "address_not_verified"
});

test("220.4 Case readiness passes after successful verification", async ({ page }) => {
  // Verify address, then check readiness
  // missing_requirements does NOT include "address_not_verified"
});
```

### Section 221: Edge Cases & Concurrent Access (3 tests)

```typescript
test("221.1 Verify address with empty line_2 succeeds", async ({ page }) => {
  // POST verify-address with line_2 omitted
  // Expect 200, verification proceeds normally
});

test("221.2 Verify address with unsupported country uses generic validation", async ({ page }) => {
  // POST verify-address with country="ZZ" (non-existent)
  // Expect 400 or generic validation applied
});

test("221.3 Concurrent verification requests return consistent result", async ({ page }) => {
  // Fire 2 verify-address requests simultaneously
  // Both return consistent result; no DDB conflict errors
});
```

---

## 10. File Change Summary

| File | Change Type | Description |
|------|-------------|-------------|
| `app/services/kyc_address_verification.py` | **New** | Address verification, geocoding, postal validation, cross-reference |
| `app/routers/kyc_cases.py` | Modify | Add 4 address verification endpoints; extend readiness check |
| `app/contracts/kyc_cases_contract.py` | Modify | Add `AddressVerificationResult` model, request/response types |
| `app/services/user_profile.py` | Modify | Add post-update hook for address change detection |
| `app/core/normalize.py` | Modify | Add address normalization/standardization helpers |
| `app/core/settings.py` | Modify | Add `kyc_address_verification_enabled` flag |
| `frontend/src/api/endpoints/kyc-cases.ts` | Modify | Add `verifyAddress`, `getAddressVerification`, `validatePostalCode` |
| `frontend/src/api/types.ts` | Modify | Add `AddressVerificationResult`, `PostalCodeValidation` types |
| `frontend/src/components/shared/AddressVerificationBadge.tsx` | **New** | Status badge component |
| `frontend/src/components/shared/PostalCodeInput.tsx` | **New** | Country-aware postal code input |
| `frontend/e2e/kyc-address-verification.spec.ts` | **New** | 22 E2E tests across sections 218-221 |
