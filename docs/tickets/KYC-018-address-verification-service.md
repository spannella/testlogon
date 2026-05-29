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

## 2. Current State Analysis

### 2.1 KYC Case Model (`app/contracts/kyc_cases_contract.py`)

The `KycCaseOut` model (line 52) contains an `intake_profile` field (string, optional) used to store a profile name reference, but no structured address fields. The case's associated user profile has address fields (`address_line_1`, `address_line_2`, `city`, `state`, `postal_code`, `country`) but these are not formally part of the KYC case data -- they live on the user profile record.

### 2.2 KYC File Attachments (`app/contracts/kyc_cases_contract.py`, line 133)

The `KycFileAttachmentRequest` model supports `file_type` values of `"selfie"`, `"id_front"`, `"id_back"`, `"proof_of_address"`. The proof_of_address attachment is stored but not parsed or compared against the user's entered address.

### 2.3 User Profile Service (`app/services/user_profile.py`)

User profiles are stored in the `users` DDB table with address fields. The profile can be updated at any time, and there is no notification/webhook mechanism when address fields change.

### 2.4 Existing Address Normalization (`app/core/normalize.py`)

The `normalize.py` module provides normalization for emails, phone numbers, CIDR ranges, and IP addresses, but has no address normalization capabilities.

---

## 3. Technical Design

### 3.1 New Service: `app/services/kyc_address_verification.py`

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

### 3.2 Mock Address Provider (Dev Mode)

When `S.dev_mode` is `True`, the verification service uses a built-in mock provider instead of calling an external API:

```python
class MockAddressProvider:
    """Deterministic mock for dev/test.
    - Any address with "123 Main St" → verified, confidence=1.0
    - Any address with "456 Oak" → partial_match, confidence=0.75
    - Any address with "999 Nonexistent" → unverifiable, confidence=0.0
    - All others → verified, confidence=0.9
    Geocoding: lat/lng derived from hash of concatenated address fields."""
```

### 3.3 Router Endpoints

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

### 3.4 DynamoDB Storage

Address verification results are stored as nested attributes on the KYC case item in the `kyc_cases` table (no new table needed):

```json
{
  "address_verification": {
    "status": "verified",
    "confidence_score": 0.95,
    "input_address": { "line_1": "123 Main St", ... },
    "standardized_address": { "line_1": "123 MAIN ST", ... },
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

### 3.5 Address Change Detection

Add a post-update hook to user profile updates. When address fields (`address_line_1`, `city`, `state`, `postal_code`, `country`) change on the user profile, find any active KYC cases for the user and reset their `address_verification.status` to `pending`.

Implementation: extend `app/services/user_profile.py` `update_profile` function to compare old/new address fields and call `AddressVerificationService.invalidate_verification` if changed.

### 3.6 Integration with KYC Case Readiness

Extend `_readiness_for_case` in `app/routers/kyc_cases.py`:

```python
# Check address verification for tier_2+
if target_tier in ("tier_2", "tier_3"):
    av = case.get("address_verification", {})
    if av.get("status") not in ("verified", "partial_match"):
        missing_requirements.append("address_not_verified")
```

### 3.7 Frontend Components

Extend the KYC case detail page (user-facing) with:

- `AddressVerificationBadge` — Shows verified/partial/unverifiable status with icon
- `AddressVerificationPanel` — Shows standardized address, geocoding map placeholder, cross-reference results
- `PostalCodeInput` — Input with real-time format validation based on selected country

These integrate into the existing KYC case flow rather than requiring a new page.

---

## 4. E2E Test Plan

**Test file**: `frontend/e2e/kyc-address-verification.spec.ts`
**Total**: ~15 tests across 3 sections (218-220)

### Section 218: Address Verification API (6 tests)

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
```

### Section 219: Postal Code Validation & Cross-Reference (5 tests)

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

test("219.4 Cross-reference matching addresses returns high score", async ({ page }) => {
  // Admin POST cross-reference with user address matching document address
  // Expect match_score >= 0.8, discrepancies empty
});

test("219.5 Cross-reference mismatched addresses returns low score and discrepancies", async ({ page }) => {
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

---

## 5. File Change Summary

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
| `frontend/e2e/kyc-address-verification.spec.ts` | **New** | 15 E2E tests across sections 218-220 |
