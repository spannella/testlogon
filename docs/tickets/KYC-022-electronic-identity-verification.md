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

1. User opens KYC case -> selects "Verify with eID" -> picks their country/scheme
2. Backend creates an eID verification session -> returns redirect URL
3. User redirects to eID provider (national identity portal / BankID app)
4. User authenticates with their eID credentials
5. eID provider redirects back to platform callback URL with signed assertion
6. Backend validates assertion signature, extracts identity fields
7. Identity data stored on KYC case, case auto-upgraded to Tier 2
8. If eID data contradicts previously entered profile data, a discrepancy flag is raised for admin review

Mock Flow (dev mode):

1. User selects "Verify with eID" -> picks scheme
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

### 3.1 Architecture Diagram

```
+-------------------+      +-------------------+      +--------------------+
|   React Frontend  |      |   FastAPI Backend  |      |   eID Provider     |
|                   |      |                   |      |   (Mock in Dev)    |
|  EidVerification  | ---> | POST /eid/start   | ---> |                    |
|  Panel            |      |   Creates session  |      |                    |
|                   |      |   Returns redirect |      |                    |
|  Browser redirect | ---> |                   |      | GET /authorize     |
|  to eID provider  |      |                   |      |   User authenticates|
|                   |      |                   |      |   with eID creds   |
|                   |      | GET /eid/callback  | <--- | Redirect back      |
|                   |      |   Validates assert |      | with signed assert |
|  EidResultCard    | <--- |   Updates case     |      |                    |
|  shows result     |      |   Auto-upgrades    |      |                    |
+-------------------+      +-------------------+      +--------------------+
                                    |
                                    v
                           +-------------------+
                           |   DynamoDB Tables  |
                           |                   |
                           | kyc_cases table:   |
                           |  EID_SESSION#{id}  |
                           |  EID_ASSERT#{case} |
                           |  Case item update  |
                           +-------------------+

Data Flow (Mock Mode):

  Frontend                    Backend                     Mock Provider
     |                          |                              |
     | POST /eid/start          |                              |
     | {scheme: "bankid"}       |                              |
     |------------------------->|                              |
     |                          | create EID_SESSION item      |
     |                          | generate redirect URL        |
     | <-- {redirect_url}       |                              |
     |                          |                              |
     | browser.redirect(url)    |                              |
     |----------------------------------------------------->   |
     |                          |     POST /mock/eid/verify    |
     |                          |     {session_id: "..."}      |
     |                          |                              |
     |                          | GET /eid/callback            |
     |                          | ?session_id=...&assertion=...|
     |                          | <----------------------------|
     |                          |                              |
     |                          | validate assertion signature |
     |                          | extract identity fields      |
     |                          | compare with user profile    |
     |                          | store EID_ASSERT item        |
     |                          | update case: eid_verification|
     |                          | auto-upgrade tier if eligible|
     |                          |                              |
     | redirect to /kyc/case/X  |                              |
     | <------------------------|                              |
     |                          |                              |
```

### 3.2 New Service: `app/services/kyc_eid_provider.py`

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

### 3.3 Mock eID Provider

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

### 3.4 DynamoDB Storage

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
  status (S)               -- "pending" | "completed" | "expired" | "failed"
  created_at (N)
  ttl (N)                  -- DDB TTL, 1 hour from creation

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
  raw_assertion (S)        -- Base64
  signature_valid (BOOL)
  discrepancies (L)        -- From profile comparison
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

### 3.5 DynamoDB Access Patterns

| Access Pattern | PK | SK / Index | Operation | Notes |
|---|---|---|---|---|
| Create eID session | `EID_SESSION#{session_id}` | `META` | PutItem | TTL=1h for auto-cleanup |
| Get eID session by ID | `EID_SESSION#{session_id}` | `META` | GetItem | Used during callback processing |
| Update session status | `EID_SESSION#{session_id}` | `META` | UpdateItem | Status transitions: pending->completed/failed |
| Store assertion | `EID_ASSERT#{case_id}` | `{scheme}#{assertion_id}` | PutItem | Permanent record for audit |
| List assertions for case | `EID_ASSERT#{case_id}` | begins_with(scheme) | Query | View all eID verifications on a case |
| Get latest assertion for case | `EID_ASSERT#{case_id}` | ScanIndexForward=False, Limit=1 | Query | Most recent verification |
| Update case with eID result | Case PK/SK | -- | UpdateItem | Adds `eid_verification` map to case |

**Example DynamoDB items:**

Session item:
```json
{
  "pk": "EID_SESSION#es_abc123def456",
  "sk": "META",
  "case_id": "kyc_case_001",
  "user_sub": "alice-uuid",
  "scheme": "bankid",
  "callback_url": "https://platform.example.com/v1/kyc/eid/callback",
  "status": "pending",
  "created_at": 1748520000,
  "ttl": 1748523600
}
```

Assertion item:
```json
{
  "pk": "EID_ASSERT#kyc_case_001",
  "sk": "bankid#ea_789xyz",
  "assertion_id": "ea_789xyz",
  "scheme": "bankid",
  "issuer": "SE-BANKID-PROD",
  "subject_id": "SE:198001012345",
  "verified_fields": {
    "first_name": "John",
    "last_name": "Doe",
    "date_of_birth": "1990-01-15",
    "nationality": "SE",
    "document_number": "MOCK-a1b2c3d4",
    "document_type": "national_id",
    "issuing_country": "SE"
  },
  "assurance_level": "high",
  "issued_at": 1748520100,
  "raw_assertion": "eyJhbGciOiJIUz...",
  "signature_valid": true,
  "discrepancies": []
}
```

### 3.6 Router Endpoints

Add to `app/routers/kyc_cases.py`:

```python
# eID verification endpoints
POST /v1/kyc/cases/{case_id}/eid/start
  -- Start eID verification session
  -- Auth: require_ui_session (case owner)
  -- Body: { "scheme": "eidas" | "digid" | "bankid" | "aadhaar" }
  -- Response: { "session_id": str, "redirect_url": str, "expires_at": int }

GET /v1/kyc/eid/callback
  -- eID provider callback (receives assertion)
  -- Auth: none (callback from external provider)
  -- Query params: session_id, assertion (base64)
  -- Redirects to: /kyc/cases/{case_id}?eid=success|failed

GET /v1/kyc/cases/{case_id}/eid/status
  -- Get eID verification status for a case
  -- Auth: require_ui_session (case owner or admin)
  -- Response: { "eid_verification": { scheme, assertion_id, assurance_level, verified_at, discrepancies } }

GET /v1/kyc/eid/schemes
  -- List supported eID schemes
  -- Auth: require_ui_session
  -- Query params: ?country= (optional filter)
  -- Response: { "schemes": [{ id, name, countries, assurance_level }] }

# Mock endpoint (dev mode only)
POST /mock/eid/verify
  -- Mock eID provider
  -- Auth: none
  -- Body: { "session_id": str }
  -- Response: { "assertion": str, "signature": str }
```

### 3.7 API Request/Response Examples

**Start eID verification:**
```bash
curl -X POST http://localhost:8000/v1/kyc/cases/kyc_case_001/eid/start \
  -H "Cookie: ui_session=sess_abc; ui_csrf=csrf_xyz; ui_access_token=tok_..." \
  -H "x-csrf-token: csrf_xyz" \
  -H "Content-Type: application/json" \
  -d '{"scheme": "bankid"}'

# Response 200:
{
  "session_id": "es_abc123def456",
  "redirect_url": "http://localhost:8000/mock/eid/verify?session_id=es_abc123def456",
  "expires_at": 1748523600
}

# Error 400 - unsupported scheme:
{
  "detail": "Unsupported eID scheme: foobar. Supported: eidas, digid, bankid, aadhaar"
}

# Error 403 - not case owner:
{
  "detail": "Only the case owner can start eID verification"
}

# Error 409 - eID already completed:
{
  "detail": "Case already has a completed eID verification. Start a new session to re-verify."
}
```

**Get eID verification status:**
```bash
curl http://localhost:8000/v1/kyc/cases/kyc_case_001/eid/status \
  -H "Cookie: ui_session=sess_abc; ui_csrf=csrf_xyz; ui_access_token=tok_..."

# Response 200 (verified):
{
  "eid_verification": {
    "scheme": "bankid",
    "assertion_id": "ea_789xyz",
    "assurance_level": "high",
    "verified_at": 1748520100,
    "auto_tier_upgrade": true,
    "discrepancies": [],
    "verified_fields": {
      "first_name": "John",
      "last_name": "Doe",
      "date_of_birth": "1990-01-15",
      "nationality": "SE"
    }
  }
}

# Response 200 (not yet verified):
{
  "eid_verification": null
}
```

**List supported eID schemes:**
```bash
curl "http://localhost:8000/v1/kyc/eid/schemes?country=SE" \
  -H "Cookie: ui_session=sess_abc; ui_csrf=csrf_xyz; ui_access_token=tok_..."

# Response 200:
{
  "schemes": [
    {
      "id": "bankid",
      "name": "BankID",
      "countries": ["SE", "NO"],
      "assurance_level": "high",
      "auth_flow": "mobile_app_qr",
      "description": "Authenticate with your Swedish or Norwegian BankID"
    }
  ]
}
```

### 3.8 Auto Tier Upgrade Logic

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

### 3.9 Discrepancy Detection

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

### 3.10 Pydantic Models

```python
# -- eID Verification (KYC-022) -- Add to app/models.py or app/contracts/kyc_cases_contract.py

class StartEidVerificationIn(BaseModel):
    scheme: str = Field(..., pattern=r"^(eidas|digid|bankid|aadhaar)$",
                        description="eID scheme identifier")

    class Config:
        json_schema_extra = {"example": {"scheme": "bankid"}}


class StartEidVerificationOut(BaseModel):
    session_id: str
    redirect_url: str
    expires_at: int

    class Config:
        json_schema_extra = {
            "example": {
                "session_id": "es_abc123def456",
                "redirect_url": "http://localhost:8000/mock/eid/verify?session_id=es_abc123def456",
                "expires_at": 1748523600,
            }
        }


class EidSchemeOut(BaseModel):
    id: str
    name: str
    countries: list[str]
    assurance_level: str  # "low", "substantial", "high"
    auth_flow: str  # "browser_redirect", "mobile_app_qr", "otp_biometric"
    description: str = ""


class EidSchemesListOut(BaseModel):
    schemes: list[EidSchemeOut]


class EidVerifiedFields(BaseModel):
    first_name: str = ""
    last_name: str = ""
    date_of_birth: str = ""  # ISO date
    nationality: str = ""  # ISO 3166-1 alpha-2
    document_number: str = ""
    document_type: str = ""
    issuing_country: str = ""


class EidDiscrepancy(BaseModel):
    field: str
    profile_value: str
    eid_value: str
    severity: str  # "match", "warning", "critical"


class EidVerificationOut(BaseModel):
    scheme: str
    assertion_id: str
    assurance_level: str
    verified_at: int
    auto_tier_upgrade: bool = False
    discrepancies: list[EidDiscrepancy] = Field(default_factory=list)
    verified_fields: EidVerifiedFields | None = None


class EidStatusOut(BaseModel):
    eid_verification: EidVerificationOut | None = None


class MockEidRequest(BaseModel):
    session_id: str = Field(..., min_length=1)


class MockEidResponse(BaseModel):
    assertion: str  # Base64 encoded assertion payload
    signature: str  # HMAC-SHA256 signature
```

### 3.11 Frontend Components

- `EidVerificationPanel` -- Shows available eID schemes for the user's country, "Verify with eID" button
- `EidSchemeSelector` -- Radio group listing supported schemes with logos and descriptions
- `EidStatusBadge` -- Shows verification status (pending, verified, failed)
- `EidResultCard` -- Displays verified fields, discrepancies, assurance level after successful verification

**Frontend Component Tree:**

```
KycCaseDetailPage
  +-- CaseStatusHeader
  +-- EidVerificationSection
  |     +-- {case.eid_verification ? <EidResultCard /> : <EidVerificationPanel />}
  |     |
  |     +-- EidVerificationPanel
  |     |     +-- EidSchemeSelector
  |     |     |     +-- RadioGroup (one radio per scheme)
  |     |     |     +-- SchemeDescription (logo + text per scheme)
  |     |     +-- Button("Verify with eID")
  |     |     +-- LoadingSpinner (while redirect in progress)
  |     |
  |     +-- EidResultCard
  |           +-- EidStatusBadge (verified/failed icon)
  |           +-- VerifiedFieldsTable (name, DOB, nationality, doc number)
  |           +-- AssuranceLevelBadge ("High" / "Substantial")
  |           +-- DiscrepancyAlert (if discrepancies present)
  |           +-- Button("Re-verify with different scheme") [optional]
  |
  +-- DocumentUploadSection (hidden if eID satisfied Tier 2)
  +-- CaseSubmitButton
```

**TypeScript Props Interfaces:**

```typescript
interface EidVerificationPanelProps {
  caseId: string;
  userCountry?: string;
}

interface EidSchemeSelectorProps {
  schemes: EidScheme[];
  selectedScheme: string | null;
  onSelect: (schemeId: string) => void;
}

interface EidStatusBadgeProps {
  status: "pending" | "verified" | "failed";
}

interface EidResultCardProps {
  verification: EidVerification;
}
```

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

## 4. Error Handling Matrix

| Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|---|---|---|---|---|
| Unsupported eID scheme | 400 | `eid_unsupported_scheme` | "This eID scheme is not supported. Please select from the available options." | Show scheme selector with valid options |
| Case not found | 404 | `case_not_found` | "KYC case not found." | Navigate to KYC cases list |
| Not case owner | 403 | `eid_not_owner` | "Only the case owner can start eID verification." | Show error message |
| Case already has eID | 409 | `eid_already_verified` | "This case already has a completed eID verification." | Show option to re-verify |
| Session expired | 400 | `eid_session_expired` | "Your eID session has expired. Please start a new verification." | Auto-restart verification flow |
| Assertion signature invalid | 400 | `eid_invalid_signature` | "The eID assertion could not be verified. Please try again." | Retry from start |
| Assertion expired | 400 | `eid_assertion_expired` | "The eID assertion has expired. Please re-authenticate." | Retry from start |
| Critical profile discrepancy | 200 (with flag) | `eid_discrepancy_critical` | "We found a discrepancy between your eID data and profile. An admin will review." | Wait for admin review |
| Mock provider unavailable | 500 | `eid_provider_error` | "The identity verification service is temporarily unavailable." | Retry after delay |
| User cancels eID flow | 400 | `eid_user_cancelled` | "You cancelled the eID verification. You can try again at any time." | Return to case detail |
| Rate limit exceeded | 429 | `rate_limit` | "Too many verification attempts. Please wait before trying again." | Wait and retry |
| Case not in draft status | 400 | `eid_case_not_draft` | "eID verification can only be started on draft cases." | Contact support |

---

## 5. Observability & Monitoring

### 5.1 Metrics

| Metric | Type | Labels | Description |
|---|---|---|---|
| `kyc_eid_sessions_created_total` | Counter | `scheme` | Total eID sessions initiated |
| `kyc_eid_verifications_completed_total` | Counter | `scheme`, `result` (success/failure) | Completed verification flows |
| `kyc_eid_verification_latency_seconds` | Histogram | `scheme` | Time from session creation to callback completion |
| `kyc_eid_auto_tier_upgrades_total` | Counter | `from_tier`, `to_tier` | Automatic tier upgrades via eID |
| `kyc_eid_discrepancies_total` | Counter | `field`, `severity` | Profile discrepancies detected |
| `kyc_eid_session_expirations_total` | Counter | `scheme` | Sessions that expired without completion |
| `kyc_eid_mock_requests_total` | Counter | -- | Mock provider requests (dev mode only) |

### 5.2 Log Events

| Event | Level | Fields | Description |
|---|---|---|---|
| `eid.session.created` | INFO | `session_id`, `case_id`, `scheme`, `user_sub` | New verification session |
| `eid.callback.received` | INFO | `session_id`, `scheme`, `assertion_id` | Callback received from provider |
| `eid.assertion.validated` | INFO | `assertion_id`, `scheme`, `assurance_level` | Assertion signature verified |
| `eid.assertion.invalid` | WARN | `session_id`, `scheme`, `reason` | Invalid assertion received |
| `eid.tier.upgraded` | INFO | `case_id`, `from_tier`, `to_tier`, `scheme` | Auto tier upgrade |
| `eid.discrepancy.detected` | WARN | `case_id`, `field`, `severity`, `profile_value`, `eid_value` | Profile mismatch |
| `eid.session.expired` | INFO | `session_id`, `scheme` | TTL cleanup |

### 5.3 Alerting Rules

| Alert | Condition | Severity |
|---|---|---|
| eID verification failure rate spike | `eid_verifications_completed{result=failure}` > 50% over 30 min | P2 |
| eID session expiration rate high | `eid_session_expirations / eid_sessions_created` > 40% over 1 hour | P3 |
| eID provider latency high | P95 of `eid_verification_latency_seconds` > 30s for 10 min | P3 |
| Critical discrepancy spike | `eid_discrepancies{severity=critical}` > 10 in 1 hour | P2 |
| Zero eID completions | `eid_verifications_completed` = 0 for 24 hours (expected > 0) | P3 |

---

## 6. Rollout Plan

### 6.1 Feature Flags

| Flag | Default (Dev) | Default (Prod) | Description |
|---|---|---|---|
| `KYC_EID_ENABLED` | `true` | `false` | Master enable for eID verification |
| `KYC_EID_MOCK_ENABLED` | `true` | `false` | Enable mock eID provider |
| `KYC_EID_AUTO_TIER_UPGRADE` | `true` | `true` | Auto-upgrade tier on successful eID |
| `KYC_EID_SCHEMES` | `eidas,digid,bankid,aadhaar` | `eidas,bankid` | Comma-separated enabled schemes |
| `KYC_EID_MOCK_SIGNING_KEY` | `dev-mock-key` | N/A | HMAC key for mock assertion signing |

### 6.2 Phased Deployment

| Phase | Scope | Duration | Success Criteria |
|---|---|---|---|
| Phase 1: Backend only | Deploy service + endpoints behind `KYC_EID_ENABLED=false` | 1 day | No runtime errors, endpoints return 404 |
| Phase 2: Internal testing | Enable for internal admin users only (allowlist) | 3 days | 10+ successful mock verifications, no data corruption |
| Phase 3: Limited rollout | Enable for 10% of users via feature flag | 5 days | Error rate < 5%, avg latency < 10s, zero critical bugs |
| Phase 4: Full rollout | Enable for all users | Ongoing | Monitor discrepancy rates and support tickets |

### 6.3 Rollback Procedure

1. Set `KYC_EID_ENABLED=false` -- endpoints return 404, frontend hides eID panel
2. Existing eID verifications remain on cases (read-only, no new verifications)
3. Cases auto-upgraded via eID retain their tier (no automatic downgrade)
4. If data corruption suspected: run `scripts/kyc_eid_cleanup.py` to remove eID data from affected cases

---

## 7. Performance Considerations

### 7.1 Query Cost Analysis

| Operation | DDB Operations | Estimated Cost |
|---|---|---|
| Create eID session | 1 PutItem | 1 WCU |
| Process callback | 1 GetItem + 1 PutItem + 1 UpdateItem (case) + 1 PutItem (assertion) | 4 WCU + 1 RCU |
| Get eID status | 1 GetItem (case) | 1 RCU |
| List schemes | In-memory, no DDB | 0 |
| Compare with profile | 1 GetItem (user profile) | 1 RCU |

### 7.2 Caching Strategy

| Data | Cache | TTL | Invalidation |
|---|---|---|---|
| Supported schemes list | In-memory (constant) | Never expires | Application restart |
| eID session data | No cache (short-lived) | -- | TTL cleanup by DDB |
| Case eID status | React Query client-side | 30 seconds | Invalidated on callback completion |
| Mock assertion data | No cache needed | -- | Stateless mock |

### 7.3 Rate Limiting

| Endpoint | Limit | Window | Notes |
|---|---|---|---|
| POST /eid/start | 5 per user | 15 minutes | Prevent session flooding |
| GET /eid/callback | 10 per session_id | 5 minutes | Allow retries |
| GET /eid/status | 30 per user | 1 minute | Standard read rate |
| GET /eid/schemes | 30 per user | 1 minute | Standard read rate |
| POST /mock/eid/verify | 20 per IP | 1 minute | Dev-mode only |

---

## 8. E2E Test Plan

**Test file**: `frontend/e2e/kyc-eid.spec.ts`
**Total**: ~24 tests across 4 sections (231-234)

### Section 231: eID Session & Mock Flow (8 tests)

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

test("231.7 Invalid session_id returns 404 on callback", async ({ page }) => {
  // GET callback with nonexistent session_id -> 404
});

test("231.8 Unsupported scheme returns 400", async ({ page }) => {
  // POST /eid/start with scheme="foobar" -> 400
});
```

### Section 232: Auto Tier Upgrade & Discrepancy Detection (6 tests)

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

test("232.6 Tier 2 case is not downgraded by discrepancy", async ({ page }) => {
  // Case already at tier_2, eID with discrepancy
  // Case stays at tier_2 (no downgrade)
});
```

### Section 233: eID Status & Admin View (5 tests)

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

test("233.5 Case not in draft status rejects eID start", async ({ page }) => {
  // Submit case, then try POST /eid/start -> 400
});
```

### Section 234: Concurrent Access & Edge Cases (5 tests)

```typescript
test("234.1 Two simultaneous eID sessions for same case - second replaces first", async ({ page }) => {
  // Start session A, start session B (both for same case)
  // Complete session B -> succeeds
  // Complete session A -> fails (session replaced)
});

test("234.2 eID verification with all schemes returns correct mock data", async ({ page }) => {
  // For each scheme: start + complete
  // Each has correct nationality and fields for the scheme
});

test("234.3 Rate limit prevents session flooding", async ({ page }) => {
  // Start 6 sessions in rapid succession (limit is 5 per 15 min)
  // 6th returns 429
});

test("234.4 eID callback is idempotent", async ({ page }) => {
  // Complete callback twice with same session_id
  // Second call returns same result without error
});

test("234.5 Mock eID assertion has correct HMAC signature", async ({ page }) => {
  // Verify the mock assertion's HMAC-SHA256 signature using the mock signing key
  // Signature matches expected value
});
```

---

## 9. File Change Summary

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
| `frontend/e2e/kyc-eid.spec.ts` | **New** | 24 E2E tests across sections 231-234 |
