# KYC-022: Electronic Identity Verification (eID)

**Ticket**: KYC-022
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 7-9 days
**Depends on**: KYC-002 (ID Document Verification/OCR), KYC-009 (Tiered Verification Levels)

---

## 1. Overview & Motivation

### 1.1 Problem Statement

The current KYC system (`app/routers/kyc_cases.py`) relies on manual document upload and admin review for identity verification. Users submit scans of passports, national IDs, or driver's licenses, which an admin then manually inspects. This process is slow (average review time in the admin queue can span hours to days), error-prone (visual document inspection cannot detect sophisticated forgeries), and fails to leverage government-issued electronic identity schemes that provide cryptographically signed identity assertions.

Many countries have deployed eID systems that allow citizens to authenticate their identity digitally with the same legal standing as in-person identity checks. By integrating with these schemes, the platform can:

1. **Automate Tier 2 verification**: A successful eID assertion provides government-verified identity data (name, DOB, nationality, document number), bypassing the need for manual ID document review.
2. **Reduce fraud**: eID assertions are cryptographically signed and cannot be forged, unlike scanned document images.
3. **Improve user experience**: Users authenticate via their existing national eID flow (browser redirect or mobile app) instead of taking photos of documents.
4. **Meet regulatory requirements**: In the EU, eIDAS-based identification meets the highest level of identity assurance (LoA High), satisfying AML/KYC requirements without additional documentation.

### 1.2 Supported eID Schemes

| Scheme | Countries | Auth Flow | Trust Level |
|--------|-----------|-----------|-------------|
| eIDAS (EU) | All EU/EEA | Browser redirect to national eID node | LoA High |
| DigiD | Netherlands | Browser redirect | LoA Substantial |
| BankID | Sweden, Norway | Mobile app + QR | LoA High |
| Aadhaar | India | OTP + biometric | LoA Substantial |

In dev mode, all eID flows are handled by a mock provider that returns deterministic identity assertions without requiring actual government infrastructure.

### 1.3 How It Works

```
User Flow:

1. User opens KYC case → selects "Verify with eID" → picks their country/scheme
2. Backend creates an eID verification session → returns redirect URL
3. User redirects to eID provider (national identity portal / BankID app)
4. User authenticates with their eID credentials
5. eID provider redirects back to platform callback URL with signed assertion
6. Backend validates assertion signature, extracts identity fields
7. Identity data stored on KYC case, case auto-upgraded to Tier 2
8. If eID data contradicts previously entered profile data, a discrepancy flag is raised for admin review

Mock Flow (dev mode):

1. User selects "Verify with eID" → picks scheme
2. Backend returns redirect to mock eID endpoint (POST /mock/eid/verify)
3. Mock endpoint returns a pre-built signed assertion with deterministic data
4. Same validation/storage path as production
```

### 1.4 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| User | Verify my identity using Swedish BankID | Redirect to BankID, authenticate, case upgraded to Tier 2 |
| User | Verify using EU eIDAS scheme | Redirect to eIDAS node, assertion processed, identity confirmed |
| Admin | See eID verification result on case detail | Case detail shows eID scheme, assertion ID, verified fields |
| System | Auto-upgrade tier on successful eID | Case tier changed from tier_1 to tier_2, manual ID review skipped |
| System | Flag discrepancy between eID and profile data | Discrepancy alert raised if eID name differs from profile name |
| Developer | Test eID flow without real eID provider | Mock endpoint returns valid assertion |

---

## 2. Current State Analysis

### 2.1 KYC Case Model (`app/contracts/kyc_cases_contract.py`)

The `KycCaseOut` model (line 52) has no fields for eID verification results. The `files` list stores uploaded documents but has no concept of a cryptographically verified identity assertion. The `status` lifecycle (`draft -> submitted -> under_review -> approved/rejected`) does not account for automated verification bypassing the manual review step.

### 2.2 KYC File Types

The `KycFileAttachmentRequest` (line 133) supports `file_type` values: `"selfie"`, `"id_front"`, `"id_back"`, `"proof_of_address"`. There is no `"eid_assertion"` type. The eID assertion is not a file upload -- it is a structured data object received via callback.

### 2.3 Tiered Verification (KYC-009)

KYC-009 establishes tier levels (tier_1: basic, tier_2: enhanced, tier_3: full due diligence). A successful eID verification provides enough assurance to satisfy Tier 2 requirements without manual document review. The tier upgrade logic must be integrated with the eID callback handler.

### 2.4 Mock Infrastructure

The platform uses moto for S3/Cognito mocks (port 4566), a Stripe mock (port 12111), and a mock KMS server (port 7999, `scripts/mock_kms_server.py`). The eID mock will follow the same pattern -- a dev-mode endpoint within the FastAPI app that simulates the eID provider's callback behavior.

### 2.5 OAuth/OIDC Patterns

The platform already has SSO provider integration (`app/routers/sso_providers.py`, admin page at `frontend/src/pages/admin/SsoProvidersPage.tsx`). The eID redirect flow follows a similar pattern: redirect out, callback with code/assertion, validate, extract claims. The implementation can reuse the session-state pattern from the SSO flow.

---

## 3. Technical Design

### 3.1 New Service: `app/services/kyc_eid_provider.py`

```python
@dataclass
class EidAssertion:
    assertion_id: str               # Unique assertion identifier
    scheme: str                     # "eidas", "digid", "bankid", "aadhaar"
    issuer: str                     # Issuing authority identifier
    subject_id: str                 # eID subject identifier (opaque)
    verified_fields: dict[str, str] # Extracted identity fields
    # Fields: first_name, last_name, date_of_birth, nationality,
    #         document_number, document_type, issuing_country
    assurance_level: str            # "low", "substantial", "high"
    issued_at: int                  # Unix timestamp
    expires_at: int                 # Assertion validity window
    raw_assertion: str              # Base64-encoded raw assertion for audit
    signature_valid: bool           # Whether signature verification passed

class EidProviderService:
    def create_verification_session(self, *, case_id: str, scheme: str,
                                      user_sub: str, callback_url: str) -> dict[str, Any]:
        """Create an eID verification session.
        Returns: { session_id, redirect_url, expires_at }
        In dev mode, redirect_url points to mock endpoint."""

    def process_callback(self, *, session_id: str,
                          assertion_data: dict[str, Any]) -> EidAssertion:
        """Validate the eID provider's callback assertion.
        1. Verify signature against provider's public key
        2. Check assertion not expired
        3. Extract identity fields
        4. Return structured assertion"""

    def validate_assertion_signature(self, *, scheme: str,
                                       raw_assertion: str) -> bool:
        """Verify cryptographic signature of the assertion.
        In dev mode, always returns True for mock assertions."""

    def compare_with_profile(self, *, assertion: EidAssertion,
                              user_profile: dict[str, Any]) -> dict[str, Any]:
        """Compare eID-verified fields with user profile.
        Returns: { matches: [...], discrepancies: [...] }"""

    def get_supported_schemes(self, *, country: str | None = None) -> list[dict[str, Any]]:
        """List available eID schemes, optionally filtered by country."""

    def get_verification_session(self, session_id: str) -> dict[str, Any] | None:
        """Retrieve a verification session by ID."""
```

### 3.2 Mock eID Provider

In dev mode (`S.dev_mode == True`), the mock endpoint simulates the eID provider:

```python
# Added to app/routers/kyc_cases.py or a new mock router

@router.post("/mock/eid/verify")
async def mock_eid_verify(body: MockEidRequest):
    """Mock eID provider endpoint.
    Accepts session_id, returns a signed assertion with deterministic data.

    Mock identity:
      first_name: "John"
      last_name: "Doe"
      date_of_birth: "1990-01-15"
      nationality: "SE" (for BankID) / country-specific
      document_number: "MOCK-{hash(session_id)[:8]}"
      assurance_level: "high"

    Signature: HMAC-SHA256 of assertion payload using mock signing key.
    """
```

### 3.3 DynamoDB Storage

eID verification sessions and assertions are stored in the `kyc_cases` table using single-table design:

```
# Verification session (temporary, TTL 1 hour)
PK: EID_SESSION#{session_id}
SK: META
Attributes:
  case_id (S)
  user_sub (S)
  scheme (S)
  callback_url (S)
  status (S)               — "pending" | "completed" | "expired" | "failed"
  created_at (N)
  ttl (N)                  — DDB TTL, 1 hour from creation

# Completed assertion (permanent, linked to case)
PK: EID_ASSERT#{case_id}
SK: {scheme}#{assertion_id}
Attributes:
  assertion_id (S)
  scheme (S)
  issuer (S)
  subject_id (S)
  verified_fields (M)
  assurance_level (S)
  issued_at (N)
  raw_assertion (S)        — Base64
  signature_valid (BOOL)
  discrepancies (L)        — From profile comparison
```

The KYC case item is also updated with an `eid_verification` sub-object:

```json
{
  "eid_verification": {
    "scheme": "bankid",
    "assertion_id": "...",
    "assurance_level": "high",
    "verified_at": 1717000000,
    "auto_tier_upgrade": true,
    "discrepancies": []
  }
}
```

### 3.4 Router Endpoints

Add to `app/routers/kyc_cases.py`:

```python
# eID verification endpoints
POST /v1/kyc/cases/{case_id}/eid/start
  — Start eID verification session
  — Auth: require_ui_session (case owner)
  — Body: { "scheme": "eidas" | "digid" | "bankid" | "aadhaar" }
  — Response: { "session_id": str, "redirect_url": str, "expires_at": int }

GET /v1/kyc/eid/callback
  — eID provider callback (receives assertion)
  — Auth: none (callback from external provider)
  — Query params: session_id, assertion (base64)
  — Redirects to: /kyc/cases/{case_id}?eid=success|failed

GET /v1/kyc/cases/{case_id}/eid/status
  — Get eID verification status for a case
  — Auth: require_ui_session (case owner or admin)
  — Response: { "eid_verification": { scheme, assertion_id, assurance_level, verified_at, discrepancies } }

GET /v1/kyc/eid/schemes
  — List supported eID schemes
  — Auth: require_ui_session
  — Query params: ?country= (optional filter)
  — Response: { "schemes": [{ id, name, countries, assurance_level }] }

# Mock endpoint (dev mode only)
POST /mock/eid/verify
  — Mock eID provider
  — Auth: none
  — Body: { "session_id": str }
  — Response: { "assertion": str, "signature": str }
```

### 3.5 Auto Tier Upgrade Logic

When `process_callback` succeeds and the assertion has `assurance_level` >= "substantial":

```python
def _handle_successful_eid(case_id: str, assertion: EidAssertion):
    case = case_store.get_case(case_id)
    current_tier = case.get("target_tier", "tier_1")

    if current_tier == "tier_1" and assertion.assurance_level in ("substantial", "high"):
        # Auto-upgrade to tier_2
        case_store.update_case_links(
            case_id=case_id,
            version=case["version"],
            updates={
                "target_tier": "tier_2",
                "eid_verification": {
                    "scheme": assertion.scheme,
                    "assertion_id": assertion.assertion_id,
                    "assurance_level": assertion.assurance_level,
                    "verified_at": now_ts(),
                    "auto_tier_upgrade": True,
                    "discrepancies": [],
                },
            },
        )
        # Skip manual ID document review requirement
        # The readiness check recognizes eID as equivalent to id_front + id_back + selfie
```

### 3.6 Discrepancy Detection

After extracting identity fields from the eID assertion, compare with the user's profile:

```python
discrepancies = eid_svc.compare_with_profile(
    assertion=assertion,
    user_profile=user_profile,
)
# Example discrepancies:
# [
#   {"field": "last_name", "profile": "Smith", "eid": "Smith-Jones", "severity": "warning"},
#   {"field": "date_of_birth", "profile": "1990-01-15", "eid": "1990-01-15", "severity": "match"},
# ]
```

If any discrepancy has severity `"critical"` (e.g., DOB mismatch), the auto-upgrade is blocked and the case is flagged for admin review.

### 3.7 Frontend Components

- `EidVerificationPanel` — Shows available eID schemes for the user's country, "Verify with eID" button
- `EidSchemeSelector` — Radio group listing supported schemes with logos and descriptions
- `EidStatusBadge` — Shows verification status (pending, verified, failed)
- `EidResultCard` — Displays verified fields, discrepancies, assurance level after successful verification

Integration into existing KYC case detail page (user-facing):

```tsx
// In KYC case detail page, above the document upload section:
{case.status === "draft" && !case.eid_verification && (
  <EidVerificationPanel caseId={case.kyc_case_id} />
)}
{case.eid_verification && (
  <EidResultCard verification={case.eid_verification} />
)}
```

**API endpoints in `frontend/src/api/endpoints/kyc-eid.ts`:**

```typescript
export const startEidVerification = (caseId: string, scheme: string) =>
  client.post<{ session_id: string; redirect_url: string; expires_at: number }>(
    `/v1/kyc/cases/${caseId}/eid/start`, { scheme }
  );

export const getEidStatus = (caseId: string) =>
  client.get<{ eid_verification: EidVerification }>(
    `/v1/kyc/cases/${caseId}/eid/status`
  );

export const getEidSchemes = (country?: string) =>
  client.get<{ schemes: EidScheme[] }>("/v1/kyc/eid/schemes", { params: { country } });
```

---

## 4. E2E Test Plan

**Test file**: `frontend/e2e/kyc-eid.spec.ts`
**Total**: ~15 tests across 3 sections (231-233)

### Section 231: eID Session & Mock Flow (6 tests)

```typescript
test("231.1 Start eID verification returns redirect URL", async ({ page }) => {
  // Create KYC case, POST /v1/kyc/cases/{id}/eid/start with scheme="bankid"
  // Expect session_id, redirect_url pointing to mock endpoint
});

test("231.2 Mock eID provider returns signed assertion", async ({ page }) => {
  // POST /mock/eid/verify with session_id from 231.1
  // Expect assertion and signature in response
});

test("231.3 Callback processes assertion and updates case", async ({ page }) => {
  // GET /v1/kyc/eid/callback with session_id and assertion
  // GET case -> eid_verification object present
});

test("231.4 List supported eID schemes", async ({ page }) => {
  // GET /v1/kyc/eid/schemes
  // Expect array with eidas, digid, bankid, aadhaar
});

test("231.5 Filter schemes by country", async ({ page }) => {
  // GET /v1/kyc/eid/schemes?country=SE
  // Expect bankid in results, digid not in results
});

test("231.6 Expired session returns error on callback", async ({ page }) => {
  // Create session, wait for expiry (or set TTL to 0 in mock)
  // GET callback -> error redirect with eid=failed
});
```

### Section 232: Auto Tier Upgrade & Discrepancy Detection (5 tests)

```typescript
test("232.1 Successful eID auto-upgrades case to tier_2", async ({ page }) => {
  // Complete eID verification flow
  // GET case -> target_tier="tier_2", eid_verification.auto_tier_upgrade=true
});

test("232.2 eID replaces manual ID document requirement", async ({ page }) => {
  // After eID verification, check readiness
  // missing_requirements does NOT include id_front or id_back
});

test("232.3 Profile data matching eID shows no discrepancies", async ({ page }) => {
  // Set profile name to match mock eID data ("John Doe")
  // Complete eID -> discrepancies array is empty
});

test("232.4 Profile data mismatching eID flags discrepancies", async ({ page }) => {
  // Set profile name to "Jane Smith" (differs from mock "John Doe")
  // Complete eID -> discrepancies includes last_name, first_name
});

test("232.5 Critical discrepancy blocks auto-upgrade", async ({ page }) => {
  // Set profile DOB to "2000-01-01" (differs from mock "1990-01-15")
  // Complete eID -> auto_tier_upgrade=false, case flagged for review
});
```

### Section 233: eID Status & Admin View (4 tests)

```typescript
test("233.1 Get eID verification status for case", async ({ page }) => {
  // GET /v1/kyc/cases/{id}/eid/status
  // Expect scheme, assertion_id, assurance_level, verified_at
});

test("233.2 Admin sees eID verification on case detail", async ({ page }) => {
  // Admin GET case detail -> eid_verification fields visible
});

test("233.3 Non-owner cannot start eID for another user's case", async ({ page }) => {
  // Bob tries to start eID on Alice's case -> 403
});

test("233.4 Second eID verification replaces first", async ({ page }) => {
  // Complete eID with bankid, then start and complete with eidas
  // GET status -> scheme="eidas" (latest)
});
```

---

## 5. File Change Summary

| File | Change Type | Description |
|------|-------------|-------------|
| `app/services/kyc_eid_provider.py` | **New** | eID session management, assertion validation, profile comparison |
| `app/routers/kyc_cases.py` | Modify | Add 4 eID endpoints + mock endpoint |
| `app/contracts/kyc_cases_contract.py` | Modify | Add eID request/response models, `EidVerification` type |
| `app/services/kyc_cases.py` | Modify | Add eID verification storage, auto-tier-upgrade logic |
| `app/core/settings.py` | Modify | Add `kyc_eid_enabled`, `kyc_eid_mock_signing_key` settings |
| `app/core/crypto.py` | Modify | Add HMAC verification helper for mock assertions |
| `frontend/src/api/endpoints/kyc-eid.ts` | **New** | API client for eID endpoints |
| `frontend/src/api/types.ts` | Modify | Add `EidVerification`, `EidScheme` types |
| `frontend/src/components/shared/EidVerificationPanel.tsx` | **New** | Scheme selector and verification start |
| `frontend/src/components/shared/EidResultCard.tsx` | **New** | Verification result display |
| `frontend/e2e/kyc-eid.spec.ts` | **New** | 15 E2E tests across sections 231-233 |
