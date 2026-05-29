# KYC-007: Enhanced Document Signing for KYC

**Ticket**: KYC-007
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 10-14 days
**Dependencies**: KYC-001 (Admin Review Dashboard)

---

## 1. Overview & Motivation

### Problem Statement

The KYC system (see `app/routers/kyc_cases.py`) integrates with the signature packet system
(see `app/services/signature_packet_store.py:91` for `create_draft_packet`, `:120` for `get_packet`) for consent
signing. Currently, each KYC case creates a generic signature packet via
`create_or_link_signature_packet()` (see `app/routers/kyc_cases.py:1206`), but there is no
**template library** for standardized KYC consent forms. Each packet is created ad-hoc,
leading to inconsistent consent language across cases.

Additionally, the current system lacks:
- **Pre-built KYC templates**: Terms of service, AML declaration, PEP declaration, etc.
- **Auto-population**: Signer info is manually entered rather than pulled from profile.
- **Witness co-signing**: High-risk cases may require a second admin to co-sign as witness.
- **Notary stamp**: No support for a notary or official stamp field type.
- **Template versioning**: When terms change, existing cases cannot be migrated to new versions.

### Goals

1. Build a template library for KYC-specific signature documents.
2. Templates: terms_of_service, aml_declaration, pep_declaration, tax_compliance, data_consent.
3. Auto-populate signer info (name, email, address) from the user profile.
4. Support witness co-signing for high-risk cases (second admin signs as witness).
5. Add notary stamp field type to signature packets.
6. Template versioning with re-signing migration when terms change.

### User Stories

| # | As a... | I want to... | So that... |
|---|---------|-------------|-----------|
| 1 | Applicant | Sign pre-filled consent forms as part of my KYC application | I don't have to re-enter my information |
| 2 | Compliance officer | Maintain standardized consent templates | All applicants sign the same terms |
| 3 | Compliance officer | Update template versions when regulations change | New applicants get current terms |
| 4 | KYC reviewer | Require witness co-signing for high-risk cases | Enhanced oversight is documented |
| 5 | Applicant | See which templates I need to sign and their status | I know what's left to complete |
| 6 | Admin | Add a notary stamp to KYC signature packets | Official certification is recorded |

---

## 2. Current State Analysis

### 2.1 Signature Packet System

`app/routers/signature_packets.py` (819 lines) provides:
- `create_draft_packet()` -- creates a new packet from a source PDF
- `get_packet()`, `list_packet_signers()` -- retrieve packet state
- Multi-signer support with per-signer status tracking
- Field positioning (text, signature, date fields on PDF pages)
- Legal notice acceptance tracking (`legal_notice_accepted_version`)
- Final PDF generation with signed fields composited

`app/services/signature_packet_store.py` provides DDB storage (see `:91` for `create_draft_packet`, `:120` for `get_packet`, `:133` for `upsert_packet_field`):
- `create_draft_packet()`, `get_packet()`, `upsert_packet_field()`
- `get_packet_artifact()` -- final PDF artifact

### 2.2 KYC Signature Integration

`create_or_link_signature_packet()` (see `app/routers/kyc_cases.py:1206`) creates a signature
packet from a file manager path and links it to the KYC case's `signature` field:

```python
{
    "packet_id": "...",
    "status": "draft" | "completed",
    "final_pdf_ref": "packet:{id}:final-pdf"
}
```

`_signature_status_for_case()` (see `app/routers/kyc_cases.py:184`) checks completion status and legal notice
acceptance. This is one of the three readiness gates for case submission.

### 2.3 Legal Notice Version

`S.signature_packet_legal_notice_version` (from `app/core/settings.py`) controls the
legal notice version that signers must accept. When this value changes, all signers
must re-accept.

### 2.4 User Profile Data

Profile provides: `display_name`, `email`, `mailing_address` (MailingAddress model).
These can be used to auto-populate signer fields.

---

## 3. Technical Design

### 3.1 Template Library

**File: `app/services/kyc_signature_templates.py`** (new, ~300 lines)

```python
KYC_TEMPLATE_TYPES = {
    "terms_of_service": {
        "display_name": "Terms of Service Agreement",
        "description": "Platform terms and conditions acceptance",
        "version": "2026-05-v1",
        "required_for": ["standard", "enhanced", "high_risk"],
        "fields": [
            {"id": "full_name", "type": "text", "label": "Full Legal Name", "auto_populate": "display_name"},
            {"id": "date_of_birth", "type": "text", "label": "Date of Birth", "auto_populate": "date_of_birth"},
            {"id": "signature", "type": "signature", "label": "Signature"},
            {"id": "date_signed", "type": "date", "label": "Date"},
        ],
    },
    "aml_declaration": {
        "display_name": "Anti-Money Laundering Declaration",
        "description": "Declaration that funds are not derived from illegal activity",
        "version": "2026-05-v1",
        "required_for": ["standard", "enhanced", "high_risk"],
        "fields": [
            {"id": "full_name", "type": "text", "label": "Full Legal Name", "auto_populate": "display_name"},
            {"id": "address", "type": "text", "label": "Residential Address", "auto_populate": "mailing_address"},
            {"id": "declaration_checkbox", "type": "checkbox", "label": "I declare that my funds are from legitimate sources"},
            {"id": "signature", "type": "signature", "label": "Signature"},
            {"id": "date_signed", "type": "date", "label": "Date"},
        ],
    },
    "pep_declaration": {
        "display_name": "Politically Exposed Person Declaration",
        "description": "Declaration of PEP status or non-PEP status",
        "version": "2026-05-v1",
        "required_for": ["enhanced", "high_risk"],
        "fields": [
            {"id": "full_name", "type": "text", "label": "Full Legal Name", "auto_populate": "display_name"},
            {"id": "is_pep", "type": "checkbox", "label": "I am or have been a Politically Exposed Person"},
            {"id": "pep_details", "type": "text", "label": "If PEP, describe position held", "conditional_on": "is_pep"},
            {"id": "signature", "type": "signature", "label": "Signature"},
            {"id": "date_signed", "type": "date", "label": "Date"},
        ],
    },
    "tax_compliance": {
        "display_name": "Tax Compliance Declaration",
        "description": "Acknowledgment of tax reporting obligations",
        "version": "2026-05-v1",
        "required_for": ["enhanced", "high_risk"],
        "fields": [
            {"id": "full_name", "type": "text", "label": "Full Legal Name", "auto_populate": "display_name"},
            {"id": "tax_id", "type": "text", "label": "Tax Identification Number"},
            {"id": "tax_country", "type": "text", "label": "Tax Residence Country", "auto_populate": "country"},
            {"id": "signature", "type": "signature", "label": "Signature"},
            {"id": "date_signed", "type": "date", "label": "Date"},
        ],
    },
    "data_consent": {
        "display_name": "Data Processing Consent",
        "description": "Consent for KYC data processing and storage",
        "version": "2026-05-v1",
        "required_for": ["standard", "enhanced", "high_risk"],
        "fields": [
            {"id": "full_name", "type": "text", "label": "Full Legal Name", "auto_populate": "display_name"},
            {"id": "email", "type": "text", "label": "Email Address", "auto_populate": "email"},
            {"id": "consent_checkbox", "type": "checkbox", "label": "I consent to KYC data processing"},
            {"id": "signature", "type": "signature", "label": "Signature"},
            {"id": "date_signed", "type": "date", "label": "Date"},
        ],
    },
}
```

### 3.2 Template Service Methods

```python
class KycSignatureTemplateService:
    def get_required_templates(self, *, intake_profile: str) -> list[dict]:
        """Return templates required for the given intake profile."""

    def create_packets_for_case(self, *, case_id: str, user_sub: str,
                                intake_profile: str) -> list[dict]:
        """Create signature packets for all required templates.
        Auto-populates signer fields from user profile.
        Returns list of created packet summaries."""

    def auto_populate_fields(self, *, template: dict, user_sub: str) -> dict:
        """Fill template fields with user profile data."""

    def get_template_version(self, template_type: str) -> str:
        """Get current version for a template type."""

    def check_version_migration(self, *, case_id: str) -> list[dict]:
        """Check if any signed templates have outdated versions.
        Returns list of templates needing re-signing."""

    def migrate_template(self, *, case_id: str, template_type: str) -> dict:
        """Create new packet from updated template, invalidate old one."""
```

### 3.3 Witness Co-signing

For `intake_profile="high_risk"` cases, specific templates require a witness co-signer
(an admin). The witness is added as a second signer on the signature packet.

```python
def add_witness_signer(self, *, packet_id: str, witness_sub: str) -> dict:
    """Add an admin as witness co-signer to a KYC signature packet.
    Witness signs after the applicant completes their signature.
    Adds witness-specific fields: witness_name, witness_role, witness_signature."""
```

Witness fields added to the packet:
```python
WITNESS_FIELDS = [
    {"id": "witness_name", "type": "text", "label": "Witness Name", "signer": "witness"},
    {"id": "witness_role", "type": "text", "label": "Witness Role", "signer": "witness", "default": "KYC Reviewer"},
    {"id": "witness_signature", "type": "signature", "label": "Witness Signature", "signer": "witness"},
    {"id": "witness_date", "type": "date", "label": "Date", "signer": "witness"},
]
```

### 3.4 Notary Stamp Field Type

**File: `app/services/signature_packet_store.py`** -- extend field types:

Add `notary_stamp` field type alongside existing `text`, `signature`, `date`:
```python
VALID_FIELD_TYPES = {"text", "signature", "date", "checkbox", "notary_stamp"}
```

Notary stamp fields store:
- `stamp_image_ref`: S3 key of the notary stamp image
- `stamp_number`: Official notary registration number
- `stamp_expiry`: Notary commission expiry date
- `stamped_at`: Timestamp when stamp was applied

### 3.5 New Router Endpoints

**File: `app/routers/kyc_cases.py`** -- add endpoints:

```python
@router.get("/templates")
def list_kyc_signature_templates(
    intake_profile: str | None = Query(default=None),
    _ctx: dict = Depends(require_ui_session),
):
    """List available KYC signature templates, optionally filtered by intake profile."""

@router.post("/{case_id}/signature-templates/create-packets")
def create_signature_packets_from_templates(
    case_id: str,
    request: Request,
    _ctx: dict = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    """Create signature packets for all required templates for the case's intake profile.
    Auto-populates fields from user profile."""

@router.get("/{case_id}/signature-templates/status")
def get_signature_templates_status(
    case_id: str,
    _ctx: dict = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    """Get completion status for each required template packet."""

@router.post("/admin/cases/{case_id}/add-witness")
def admin_add_witness_to_packet(
    case_id: str,
    body: KycAddWitnessRequest,
    request: Request,
    _ctx: dict = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    """Add admin as witness co-signer to a KYC case's signature packet.
    Only for high_risk cases. Requires ADMIN or ROOT role."""

@router.get("/{case_id}/signature-templates/version-check")
def check_template_version_migration(
    case_id: str,
    _ctx: dict = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    """Check if any templates have been updated since the case was signed.
    Returns list of templates needing re-signing."""
```

### 3.6 Request Models

**File: `app/contracts/kyc_cases_contract.py`** -- add:

```python
class KycAddWitnessRequest(BaseModel):
    expected_version: int = Field(..., ge=1)
    packet_id: str = Field(..., min_length=1)
    witness_sub: str | None = Field(default=None,
        description="Admin sub to add as witness. If None, uses current user.")

class KycTemplateStatusOut(BaseModel):
    template_type: str
    display_name: str
    version: str
    packet_id: str | None
    packet_status: str | None    # draft | completed
    signed_by_applicant: bool
    signed_by_witness: bool | None   # None if no witness required
    needs_version_migration: bool
```

### 3.7 Frontend Changes

**File: `frontend/src/pages/kyc/KycCaseForm.tsx`** -- extend:

Add "Consent & Declarations" section:
- List of required templates with status badges (Not Started, In Progress, Completed)
- "Create All Packets" button to initialize all required packets
- Per-template "Sign" button opening the signature packet UI
- Auto-populated field preview showing values pulled from profile
- Version migration banner: "Terms updated -- re-signing required"

**File: `frontend/src/pages/admin/KycCaseDetailPage.tsx`** -- extend:

Add "Signatures & Declarations" tab:
- Template list with completion status per signer
- "Add Witness" button for high-risk cases (opens admin picker dialog)
- Witness signing status
- Version check banner with "Require Re-signing" action button

---

## 4. E2E Test Plan

**File**: `frontend/e2e/kyc-enhanced-signing.spec.ts`
**Total**: ~18 tests across 4 sections (174-177)

### Section 174: Template Library API (5 tests)

```typescript
test("174.1 List templates returns all 5 template types", async () => {
  // GET /v1/kyc/cases/templates
  // Verify 5 templates with display_name, version, required_for
});

test("174.2 Filter templates by intake_profile=standard returns 3", async () => {
  // GET /v1/kyc/cases/templates?intake_profile=standard
  // Verify returns terms_of_service, aml_declaration, data_consent
});

test("174.3 Filter by intake_profile=high_risk returns all 5", async () => {
  // Verify all templates returned (all are required for high_risk)
});

test("174.4 Each template has version field", async () => {
  // Verify all templates have version matching "2026-05-v1" pattern
});

test("174.5 Template fields include auto_populate hints", async () => {
  // Verify terms_of_service template has full_name field with auto_populate="display_name"
});
```

### Section 175: Packet Creation with Auto-Population (5 tests)

```typescript
test("175.1 Create packets for standard case produces 3 packets", async () => {
  // POST /v1/kyc/cases/{id}/signature-templates/create-packets
  // Verify 3 packets created (terms_of_service, aml_declaration, data_consent)
});

test("175.2 Auto-populated fields contain profile data", async () => {
  // GET signature template status
  // Verify full_name field has Alice's display name
  // Verify email field has Alice's email
});

test("175.3 Get template status shows all packets as draft", async () => {
  // GET /v1/kyc/cases/{id}/signature-templates/status
  // Verify all entries have packet_status="draft", signed_by_applicant=false
});

test("175.4 Create packets for high_risk case produces 5 packets", async () => {
  // High-risk case
  // Verify 5 packets created
});

test("175.5 Duplicate creation is idempotent", async () => {
  // Call create-packets twice
  // Verify same packet_ids returned (no duplicates)
});
```

### Section 176: Witness Co-signing (4 tests)

```typescript
test("176.1 Add witness to high-risk case packet", async () => {
  // POST /v1/kyc/cases/admin/cases/{id}/add-witness
  // { packet_id, witness_sub: root_sub }
  // Verify 200, witness added to packet signers
});

test("176.2 Witness addition rejected for standard case", async () => {
  // Standard profile case
  // POST add-witness
  // Expect 400 or 409 (witness not required for standard)
});

test("176.3 Template status shows witness signing needed", async () => {
  // GET template status
  // Verify signed_by_witness=false for witnessed template
});

test("176.4 Non-admin cannot add witness", async () => {
  // Alice tries to add witness
  // Expect 403
});
```

### Section 177: Template Versioning (4 tests)

```typescript
test("177.1 Version check returns empty when all templates current", async () => {
  // GET /v1/kyc/cases/{id}/signature-templates/version-check
  // Verify empty list (no migrations needed)
});

test("177.2 Version check detects outdated template", async () => {
  // Manually update template version in service
  // GET version-check
  // Verify returns template with needs_version_migration=true
});

test("177.3 Template status shows version migration flag", async () => {
  // GET template status
  // Verify affected template has needs_version_migration=true
});

test("177.4 Creating new packets after version change uses new version", async () => {
  // Create packets after template version update
  // Verify new packet uses updated version
});
```

---

## 5. File Change Summary

| File | Change Type | Description |
|------|-------------|-------------|
| `app/services/kyc_signature_templates.py` | **New** | Template library, auto-population, versioning, witness support |
| `app/services/signature_packet_store.py` | Modify | Add `notary_stamp` field type |
| `app/routers/kyc_cases.py` | Modify | Add 5 template/witness endpoints |
| `app/contracts/kyc_cases_contract.py` | Modify | Add witness and template request/response models |
| `frontend/src/pages/kyc/KycCaseForm.tsx` | Modify | Add Consent & Declarations section |
| `frontend/src/pages/admin/KycCaseDetailPage.tsx` | Modify | Add Signatures tab with witness controls |
| `frontend/src/api/endpoints/kyc-admin.ts` | Modify | Add template and witness API functions |
| `frontend/e2e/kyc-enhanced-signing.spec.ts` | **New** | 18 E2E tests across sections 174-177 |

---

## 6. Architecture & Data Flow

```
┌────────────────────────────────────────────────────────────────────────────┐
│                           Frontend                                         │
│                                                                            │
│  KycCaseForm.tsx (user)                   KycCaseDetailPage.tsx (admin)    │
│  ┌──────────────────────────────┐        ┌─────────────────────────────┐  │
│  │ ConsentDeclarationsSection    │        │ SignaturesDeclarationsTab    │  │
│  │  ├─ TemplateList              │        │  ├─ TemplateStatusTable      │  │
│  │  │   └─ TemplateRow[]         │        │  │   └─ Row per template     │  │
│  │  │       ├─ TemplateName      │        │  │       ├─ TypeBadge        │  │
│  │  │       ├─ StatusBadge       │        │  │       ├─ SignerStatus     │  │
│  │  │       ├─ AutoPopPreview    │        │  │       ├─ WitnessStatus    │  │
│  │  │       └─ SignButton        │        │  │       └─ VersionBadge     │  │
│  │  ├─ "Create All Packets" btn  │        │  ├─ "Add Witness" btn        │  │
│  │  │   (initializes required)   │        │  │   → AdminPickerDialog     │  │
│  │  └─ VersionMigrationBanner    │        │  └─ VersionCheckBanner       │  │
│  │      ("Terms updated —        │        │      "Require Re-signing"    │  │
│  │       re-signing required")   │        └─────────────────────────────┘  │
│  └──────────────────────────────┘                                          │
└──────────────────┬────────────────────────────────┬────────────────────────┘
                   │                                │
                   ▼                                ▼
┌────────────────────────────────────────────────────────────────────────────┐
│                      Backend (FastAPI)                                      │
│                                                                            │
│  kyc_signature_templates.py (NEW — template library service)              │
│  ┌──────────────────────────────────────────────────────────────────┐     │
│  │ KYC_TEMPLATE_TYPES: 5 templates with fields + auto_populate     │     │
│  │   terms_of_service    → standard, enhanced, high_risk           │     │
│  │   aml_declaration     → standard, enhanced, high_risk           │     │
│  │   pep_declaration     → enhanced, high_risk                     │     │
│  │   tax_compliance      → enhanced, high_risk                     │     │
│  │   data_consent        → standard, enhanced, high_risk           │     │
│  │                                                                  │     │
│  │ get_required_templates(intake_profile) → filtered list           │     │
│  │ create_packets_for_case(case_id, user_sub, profile) → packets   │     │
│  │ auto_populate_fields(template, profile) → field values           │     │
│  │ check_version_migration(case_id) → outdated templates            │     │
│  │ migrate_template(case_id, template_type) → new packet            │     │
│  └──────────────────────────────────────────────────────────────────┘     │
│                                                                            │
│  signature_packet_store.py (MODIFIED — add notary_stamp field type)       │
│  ┌──────────────────────────────────────────────────────────────────┐     │
│  │ VALID_FIELD_TYPES = {text, signature, date, checkbox,            │     │
│  │                      notary_stamp}                                │     │
│  │ notary_stamp stores: stamp_image_ref, stamp_number,              │     │
│  │                      stamp_expiry, stamped_at                     │     │
│  └──────────────────────────────────────────────────────────────────┘     │
│                                                                            │
│  Witness co-signing flow:                                                 │
│  admin_add_witness_to_packet()                                            │
│  ┌──────────────────────────────────────────────────────────────────┐     │
│  │ 1. Validate case is high_risk                                    │     │
│  │ 2. Validate admin has ADMIN or ROOT role                         │     │
│  │ 3. Add witness as second signer on packet                        │     │
│  │ 4. Add WITNESS_FIELDS to packet                                  │     │
│  │ 5. Witness signs AFTER applicant completes signature             │     │
│  └──────────────────────────────────────────────────────────────────┘     │
│                                                                            │
│  Router endpoints:                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐     │
│  │ GET  /templates                                                   │     │
│  │ POST /{case_id}/signature-templates/create-packets               │     │
│  │ GET  /{case_id}/signature-templates/status                       │     │
│  │ POST /admin/cases/{case_id}/add-witness                          │     │
│  │ GET  /{case_id}/signature-templates/version-check                │     │
│  └──────────────────────────────────────────────────────────────────┘     │
└──────────────────┬─────────────────────────────────────────────────────────┘
                   │
                   ▼
┌────────────────────────────────────────────────────────────────────────────┐
│  DynamoDB                                                                  │
│  ┌────────────────────┐  ┌──────────────────────┐  ┌──────────────────┐  │
│  │ kyc_cases           │  │ signature_packets     │  │ signature_packet │  │
│  │ PK=KYC#{case_id}   │  │ PK=packet_id          │  │ _signers         │  │
│  │ SK=META             │  │ Fields: source_path,  │  │ PK=packet_id     │  │
│  │ → signature.packets │  │ status, legal_notice  │  │ SK=signer_sub    │  │
│  │   [{template_type,  │  │ _version, fields[]    │  │ → signer_role:   │  │
│  │     packet_id,      │  └──────────────────────┘  │   "applicant" |   │  │
│  │     version}]       │                             │   "witness"       │  │
│  └────────────────────┘                             └──────────────────┘  │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## 7. DynamoDB Access Patterns

| # | Access Pattern | Table | Key / Index | Notes |
|---|---------------|-------|-------------|-------|
| 1 | Get templates for profile | In-memory | — | `KYC_TEMPLATE_TYPES` constant, filtered by `required_for` |
| 2 | Create signature packet | `signature_packets` | PK=`{packet_id}` | Via `create_draft_packet()` in `signature_packet_store.py` |
| 3 | Add signer to packet | `signature_packet_signers` | PK=`{packet_id}`, SK=`{signer_sub}` | PutItem with `signer_role` |
| 4 | Store template packets on case | `kyc_cases` | PK=`KYC#{case_id}`, SK=`META` | Update `signature.packets` list |
| 5 | Get packet status | `signature_packets` | PK=`{packet_id}` | Check `status` field |
| 6 | List packet signers | `signature_packet_signers` | PK=`{packet_id}` | Query all SK entries |
| 7 | Update field value (auto-populate) | `signature_packet_fields` | PK=`{packet_id}`, SK=`{field_id}` | Via `upsert_packet_field()` |
| 8 | Add witness fields | `signature_packet_fields` | PK=`{packet_id}`, SK=`witness_*` | 4 PutItems for witness fields |

---

## 8. API Request/Response Examples

### 8.1 List KYC Signature Templates

```bash
curl -X GET "http://localhost:8000/v1/kyc/cases/templates?intake_profile=enhanced" \
  -H "Cookie: ui_session=sess_alice; ui_access_token=eyJ...; ui_csrf=csrf_a"
```

**Response (200):**
```json
{
  "templates": [
    {
      "template_type": "terms_of_service",
      "display_name": "Terms of Service Agreement",
      "description": "Platform terms and conditions acceptance",
      "version": "2026-05-v1",
      "required_for": ["standard", "enhanced", "high_risk"],
      "fields": [
        {"id": "full_name", "type": "text", "label": "Full Legal Name", "auto_populate": "display_name"},
        {"id": "date_of_birth", "type": "text", "label": "Date of Birth", "auto_populate": "date_of_birth"},
        {"id": "signature", "type": "signature", "label": "Signature"},
        {"id": "date_signed", "type": "date", "label": "Date"}
      ]
    },
    {
      "template_type": "aml_declaration",
      "display_name": "Anti-Money Laundering Declaration",
      "version": "2026-05-v1",
      "required_for": ["standard", "enhanced", "high_risk"],
      "fields": [
        {"id": "full_name", "type": "text", "label": "Full Legal Name", "auto_populate": "display_name"},
        {"id": "address", "type": "text", "label": "Residential Address", "auto_populate": "mailing_address"},
        {"id": "declaration_checkbox", "type": "checkbox", "label": "I declare that my funds are from legitimate sources"},
        {"id": "signature", "type": "signature", "label": "Signature"},
        {"id": "date_signed", "type": "date", "label": "Date"}
      ]
    },
    {
      "template_type": "pep_declaration",
      "display_name": "Politically Exposed Person Declaration",
      "version": "2026-05-v1",
      "required_for": ["enhanced", "high_risk"],
      "fields": [
        {"id": "full_name", "type": "text", "label": "Full Legal Name", "auto_populate": "display_name"},
        {"id": "is_pep", "type": "checkbox", "label": "I am or have been a Politically Exposed Person"},
        {"id": "pep_details", "type": "text", "label": "If PEP, describe position held", "conditional_on": "is_pep"},
        {"id": "signature", "type": "signature", "label": "Signature"},
        {"id": "date_signed", "type": "date", "label": "Date"}
      ]
    },
    {
      "template_type": "tax_compliance",
      "display_name": "Tax Compliance Declaration",
      "version": "2026-05-v1",
      "required_for": ["enhanced", "high_risk"]
    },
    {
      "template_type": "data_consent",
      "display_name": "Data Processing Consent",
      "version": "2026-05-v1",
      "required_for": ["standard", "enhanced", "high_risk"]
    }
  ]
}
```

### 8.2 Create Signature Packets from Templates

```bash
curl -X POST "http://localhost:8000/v1/kyc/cases/kyc_a1b2c3d4/signature-templates/create-packets" \
  -H "Cookie: ui_session=sess_alice; ui_access_token=eyJ...; ui_csrf=csrf_a" \
  -H "x-csrf-token: csrf_a"
```

**Response (200):**
```json
{
  "ok": true,
  "packets": [
    {
      "template_type": "terms_of_service",
      "packet_id": "pkt_a1b2c3d4e5f6",
      "packet_status": "draft",
      "version": "2026-05-v1",
      "auto_populated_fields": ["full_name", "date_of_birth"]
    },
    {
      "template_type": "aml_declaration",
      "packet_id": "pkt_f6e5d4c3b2a1",
      "packet_status": "draft",
      "version": "2026-05-v1",
      "auto_populated_fields": ["full_name", "address"]
    },
    {
      "template_type": "pep_declaration",
      "packet_id": "pkt_111222333444",
      "packet_status": "draft",
      "version": "2026-05-v1",
      "auto_populated_fields": ["full_name"]
    },
    {
      "template_type": "tax_compliance",
      "packet_id": "pkt_555666777888",
      "packet_status": "draft",
      "version": "2026-05-v1",
      "auto_populated_fields": ["full_name", "tax_country"]
    },
    {
      "template_type": "data_consent",
      "packet_id": "pkt_999000111222",
      "packet_status": "draft",
      "version": "2026-05-v1",
      "auto_populated_fields": ["full_name", "email"]
    }
  ]
}
```

### 8.3 Get Signature Templates Status

```bash
curl -X GET "http://localhost:8000/v1/kyc/cases/kyc_a1b2c3d4/signature-templates/status" \
  -H "Cookie: ui_session=sess_alice; ui_access_token=eyJ...; ui_csrf=csrf_a"
```

**Response (200):**
```json
{
  "statuses": [
    {
      "template_type": "terms_of_service",
      "display_name": "Terms of Service Agreement",
      "version": "2026-05-v1",
      "packet_id": "pkt_a1b2c3d4e5f6",
      "packet_status": "completed",
      "signed_by_applicant": true,
      "signed_by_witness": null,
      "needs_version_migration": false
    },
    {
      "template_type": "aml_declaration",
      "display_name": "Anti-Money Laundering Declaration",
      "version": "2026-05-v1",
      "packet_id": "pkt_f6e5d4c3b2a1",
      "packet_status": "draft",
      "signed_by_applicant": false,
      "signed_by_witness": null,
      "needs_version_migration": false
    }
  ]
}
```

### 8.4 Add Witness to Packet

```bash
curl -X POST "http://localhost:8000/v1/kyc/cases/admin/cases/kyc_a1b2c3d4/add-witness" \
  -H "Cookie: ui_session=sess_root; ui_access_token=eyJ...; ui_csrf=csrf_r" \
  -H "x-csrf-token: csrf_r" \
  -H "Content-Type: application/json" \
  -d '{
    "expected_version": 5,
    "packet_id": "pkt_a1b2c3d4e5f6",
    "witness_sub": null
  }'
```

**Response (200):**
```json
{
  "ok": true,
  "packet_id": "pkt_a1b2c3d4e5f6",
  "witness_sub": "root.admin@testdev.local",
  "witness_fields_added": ["witness_name", "witness_role", "witness_signature", "witness_date"]
}
```

---

## 9. Pydantic Models

### 9.1 Request Models

```python
from pydantic import BaseModel, Field
from typing import Literal


class KycAddWitnessRequest(BaseModel):
    """Request to add an admin as witness co-signer to a KYC signature packet."""

    expected_version: int = Field(
        ...,
        ge=1,
        description="Current case version for OCC.",
        examples=[5],
    )
    packet_id: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description="Signature packet ID to add witness to.",
        examples=["pkt_a1b2c3d4e5f6"],
    )
    witness_sub: str | None = Field(
        default=None,
        description="Admin sub to add as witness. If None, uses the current admin user.",
        examples=["root.admin@testdev.local"],
    )


class KycCreatePacketsRequest(BaseModel):
    """Request to create signature packets from templates for a KYC case.
    No body fields needed -- intake profile is read from the case."""
    pass
```

### 9.2 Response Models

```python
class KycTemplateFieldOut(BaseModel):
    """A field definition within a KYC signature template."""

    id: str = Field(..., description="Field identifier.")
    type: Literal["text", "signature", "date", "checkbox", "notary_stamp"] = Field(
        ..., description="Field type."
    )
    label: str = Field(..., description="Display label for the field.")
    auto_populate: str | None = Field(None, description="Profile field to auto-populate from.")
    conditional_on: str | None = Field(None, description="Field ID that must be checked for this field to appear.")
    default: str | None = Field(None, description="Default value for the field.")


class KycTemplateOut(BaseModel):
    """A KYC signature template definition."""

    template_type: str = Field(..., description="Template type identifier.")
    display_name: str = Field(..., description="Human-readable template name.")
    description: str = Field(..., description="Template description.")
    version: str = Field(..., description="Template version string.")
    required_for: list[str] = Field(..., description="Intake profiles that require this template.")
    fields: list[KycTemplateFieldOut] = Field(default_factory=list, description="Template fields.")


class KycTemplateListOut(BaseModel):
    """List of KYC signature templates."""

    templates: list[KycTemplateOut] = Field(default_factory=list)


class KycPacketCreatedOut(BaseModel):
    """Summary of a created signature packet."""

    template_type: str
    packet_id: str
    packet_status: str = "draft"
    version: str
    auto_populated_fields: list[str] = Field(default_factory=list)


class KycCreatePacketsResponse(BaseModel):
    """Response from creating signature packets."""

    ok: bool = True
    packets: list[KycPacketCreatedOut] = Field(default_factory=list)


class KycTemplateStatusOut(BaseModel):
    """Completion status for a single template's signature packet."""

    template_type: str = Field(..., description="Template type.")
    display_name: str = Field(..., description="Human-readable name.")
    version: str = Field(..., description="Template version used.")
    packet_id: str | None = Field(None, description="Signature packet ID (null if not created).")
    packet_status: str | None = Field(None, description="Packet status: draft | completed.")
    signed_by_applicant: bool = Field(False, description="Whether the applicant has signed.")
    signed_by_witness: bool | None = Field(
        None, description="Whether the witness has signed (null if no witness required)."
    )
    needs_version_migration: bool = Field(
        False, description="Whether the template version has changed since signing."
    )


class KycTemplateStatusListOut(BaseModel):
    """List of template statuses for a case."""

    statuses: list[KycTemplateStatusOut] = Field(default_factory=list)


class KycAddWitnessResponse(BaseModel):
    """Response from adding a witness to a packet."""

    ok: bool = True
    packet_id: str
    witness_sub: str
    witness_fields_added: list[str] = Field(
        default_factory=list,
        description="Field IDs added for the witness signer.",
    )


class KycVersionCheckOut(BaseModel):
    """A template that needs version migration."""

    template_type: str
    display_name: str
    current_version: str
    signed_version: str
    needs_resigning: bool = True


class KycVersionCheckListOut(BaseModel):
    """List of templates needing version migration."""

    migrations: list[KycVersionCheckOut] = Field(default_factory=list)
```

### 9.3 Notary Stamp Field Model

```python
class NotaryStampFieldValue(BaseModel):
    """Value stored in a notary_stamp field type."""

    stamp_image_ref: str = Field(..., description="S3 key of the notary stamp image.")
    stamp_number: str = Field(..., description="Official notary registration number.")
    stamp_expiry: str = Field(..., description="Notary commission expiry date (YYYY-MM-DD).")
    stamped_at: int = Field(..., description="Unix timestamp when stamp was applied.")
    stamped_by: str = Field(..., description="Sub of the admin who applied the stamp.")
```

---

## 10. Frontend Component Tree

### 10.1 User-Facing Consent & Declarations (KycCaseForm.tsx)

```
KycCaseForm
└── Accordion (section="consent-declarations")
    └── ConsentDeclarationsSection
        ├── SectionHeader ("Consent & Declarations")
        ├── CreateAllButton  [if no packets created yet]
        │   └── Button ("Create All Required Documents")
        │       └── onClick -> useMutation(POST /signature-templates/create-packets)
        ├── TemplateList  [after packets created]
        │   └── TemplateRow[] (one per required template)
        │       ├── TemplateIcon (FileText | Shield | Scale | Globe)
        │       ├── TemplateName (display_name)
        │       ├── VersionBadge ("v2026-05-v1")
        │       ├── StatusBadge
        │       │   ├── variant="outline": "Not Signed"
        │       │   ├── variant="warning": "In Progress"
        │       │   └── variant="success": "Completed"
        │       ├── AutoPopulatedPreview  [expandable]
        │       │   └── FieldPreviewList
        │       │       ├── Item ("Full Name: Alice Smith" -> auto-populated)
        │       │       ├── Item ("Email: alice@test.local" -> auto-populated)
        │       │       └── Item ("Signature: [click to sign]")
        │       └── SignButton
        │           └── Button ("Sign" | "View Signed")
        │               └── onClick -> navigate to /signing/{packet_id}
        └── VersionMigrationBanner  [if any template needs migration]
            └── Alert (variant="warning")
                ├── AlertTriangle icon
                ├── Text ("Terms have been updated. Re-signing required for:")
                ├── TemplateNameList (outdated templates)
                └── Button ("Re-sign Now")
                    └── onClick -> useMutation(POST /migrate-template)
```

### 10.2 Admin Signatures & Declarations Tab (KycCaseDetailPage.tsx)

```
KycCaseDetailPage
└── Tabs
    └── TabsContent (value="signatures-declarations")
        └── SignaturesDeclarationsTab
            ├── Card (title="Template Status")
            │   └── Table
            │       ├── TableHeader (Template | Version | Applicant | Witness | Status)
            │       └── TableBody
            │           └── TableRow[] (one per required template)
            │               ├── Cell: TemplateName + TypeBadge
            │               ├── Cell: VersionBadge
            │               ├── Cell: ApplicantSignedBadge (check / pending)
            │               ├── Cell: WitnessSignedBadge (check / pending / N/A)
            │               └── Cell: OverallStatusBadge
            ├── Card (title="Witness Management")  [if high_risk profile]
            │   ├── WitnessInfo  [if witness assigned]
            │   │   ├── Text ("Witness: {witness_name}")
            │   │   ├── Badge (signed: true/false)
            │   │   └── Text ("Assigned at: {timestamp}")
            │   └── AddWitnessButton  [if no witness yet]
            │       └── Dialog (trigger="Add Witness")
            │           ├── DialogTitle ("Assign Witness")
            │           ├── DialogDescription ("Select an admin to co-sign")
            │           ├── AdminPicker (dropdown of ADMIN/ROOT users)
            │           │   └── Select -> sets witness_sub
            │           └── Button ("Assign")
            │               └── onClick -> useMutation(POST /add-witness)
            ├── Card (title="Version Compliance")
            │   ├── VersionCheckResults
            │   │   └── UpToDateBadge  [if all current]
            │   │   └── MigrationNeededList  [if any outdated]
            │   │       └── TemplateRow[] (outdated templates)
            │   │           ├── TemplateName
            │   │           ├── OldVersion -> NewVersion
            │   │           └── Button ("Require Re-signing")
            │   └── Button ("Run Version Check")
            │       └── onClick -> useQuery(GET /version-check, refetch)
            └── Card (title="Notary Stamps")  [if notary stamp feature enabled]
                └── NotaryStampList
                    └── StampRow[]
                        ├── StampImage (thumbnail of stamp)
                        ├── StampNumber
                        ├── StampExpiry
                        └── StampedAt + StampedBy
```

### 10.3 State Management

```typescript
const templateKeys = {
  list: (profile?: string) => ["kyc", "templates", profile] as const,
  status: (caseId: string) => ["kyc", "template-status", caseId] as const,
  versionCheck: (caseId: string) => ["kyc", "version-check", caseId] as const,
};

function useTemplateList(intakeProfile?: string) {
  return useQuery({
    queryKey: templateKeys.list(intakeProfile),
    queryFn: () => listTemplates(intakeProfile),
    staleTime: 300_000, // 5 min (templates are semi-static)
  });
}

function useTemplateStatus(caseId: string) {
  return useQuery({
    queryKey: templateKeys.status(caseId),
    queryFn: () => getTemplateStatus(caseId),
    enabled: !!caseId,
    staleTime: 30_000,
  });
}

function useCreatePackets(caseId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => createPackets(caseId),
    onSuccess: () => qc.invalidateQueries({ queryKey: templateKeys.status(caseId) }),
  });
}

function useAddWitness(caseId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: AddWitnessRequest) => addWitness(caseId, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: templateKeys.status(caseId) }),
  });
}
```

---

## 11. Error Handling Matrix

| # | Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|---|----------|-------------|------------|---------------------|----------------|
| 1 | List templates -- invalid intake_profile | 422 | `validation_error` | "intake_profile must be one of: standard, enhanced, high_risk." | Use valid value |
| 2 | Create packets -- case not in draft | 400 | `kyc_invalid_status` | "Packets can only be created for draft cases." | Check case status |
| 3 | Create packets -- non-owner | 403 | `kyc_access_forbidden` | "You do not own this case." | Use correct session |
| 4 | Create packets -- already created | 200 (idempotent) | -- | Returns existing packet_ids | Safe to call twice |
| 5 | Add witness -- case not high_risk | 400 | `kyc_witness_not_required` | "Witness signing is only required for high-risk cases." | Only for high_risk profile |
| 6 | Add witness -- non-admin | 403 | `kyc_admin_role_required` | "Admin access required." | Use admin credentials |
| 7 | Add witness -- packet not found | 404 | `kyc_packet_not_found` | "Signature packet not found." | Verify packet_id |
| 8 | Add witness -- already has witness | 409 | `kyc_witness_already_added` | "A witness has already been assigned to this packet." | Check witness status |
| 9 | Version check -- no packets created | 200 | -- | Returns empty array (no migrations needed) | Normal behavior |
| 10 | Get status -- non-owner | 403 | `kyc_access_forbidden` | "You do not own this case." | Use correct session |
| 11 | Add witness -- packet already signed by applicant | 400 | `kyc_packet_already_signed` | "Cannot add witness after applicant has already signed." | N/A |
| 12 | Version migration -- packet not found | 404 | `kyc_packet_not_found` | "Signature packet not found for migration." | Verify case has packets |
| 13 | Notary stamp -- non-admin | 403 | `kyc_admin_role_required` | "Admin access required to apply notary stamp." | Use admin credentials |
| 14 | Notary stamp -- expired commission | 400 | `kyc_notary_stamp_expired` | "Notary commission has expired." | Update notary credentials |

---

## 12. Observability & Monitoring

### Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `kyc_template_packets_created` | Counter | `template_type`, `intake_profile` | Packets created per template and profile |
| `kyc_template_auto_populated_fields` | Counter | `field_name` | Auto-populated field count by field |
| `kyc_template_witness_added` | Counter | — | Witness co-signers added |
| `kyc_template_version_migration` | Counter | `template_type` | Templates requiring version migration |
| `kyc_template_signed` | Counter | `template_type`, `signer_role` | Signatures completed per template and role |
| `kyc_notary_stamp_applied` | Counter | — | Notary stamps applied to packets |

### Log Events

| Event | Level | Fields | Trigger |
|-------|-------|--------|---------|
| `kyc.templates.packets_created` | INFO | `case_id`, `count`, `template_types` | create-packets endpoint |
| `kyc.templates.auto_populated` | DEBUG | `case_id`, `template_type`, `fields` | Field auto-population |
| `kyc.templates.witness_added` | INFO | `case_id`, `packet_id`, `witness_sub` | add-witness endpoint |
| `kyc.templates.version_migration_needed` | WARN | `case_id`, `template_type`, `old_version`, `new_version` | Version check detects mismatch |

### Alerts

| Alert | Condition | Severity |
|-------|-----------|----------|
| Version migration backlog | > 50 cases with `needs_version_migration=true` for > 7 days | P3 |
| Witness signing stale | Witness assigned but not signed for > 48h | P3 |

---

## 13. Performance Considerations

| Operation | Latency Target | DDB Cost | Notes |
|-----------|---------------|----------|-------|
| List templates | < 10ms | 0 DDB | In-memory constant lookup |
| Create packets (5 templates) | < 500ms | 5+5+5 WCU | 5 packet creates + 5 signer records + 5x field writes |
| Auto-populate fields | < 100ms | 1 RCU (profile) | Single profile read + in-memory field mapping |
| Get template status | < 200ms | 5 RCU | One GetItem per packet_id |
| Version check | < 150ms | 5 RCU | Compare stored version against current constant |
| Add witness | < 200ms | 3 WCU | Signer record + 4 witness field records |

### Caching

- Template definitions (`KYC_TEMPLATE_TYPES`) are in-memory constants. No DDB or S3 lookups.
- Auto-populated field mapping is also in-memory.
- Packet status can be cached per request (React Query key: `["kyc", "template-status", caseId]`).

---

## 14. Rollout Plan

### Feature Flags

| Flag | Default | Purpose |
|------|---------|---------|
| `KYC_TEMPLATE_SIGNING_ENABLED` | `false` | Gates template-based signing flow |
| `KYC_WITNESS_COSIGNING_ENABLED` | `false` | Gates witness co-signing for high_risk |
| `KYC_NOTARY_STAMP_ENABLED` | `false` | Gates notary stamp field type |

### Phases

| Phase | Description | Duration |
|-------|-------------|----------|
| 1 | Deploy template service + endpoints behind flag | 2 days |
| 2 | Enable template signing in staging; validate auto-population | 1 day |
| 3 | Enable in production for new cases only | gradual |
| 4 | Enable witness co-signing for high_risk profile | after 1 week |
| 5 | Enable notary stamp field type for designated notary admins | after 2 weeks |

### Rollback

1. Set `KYC_TEMPLATE_SIGNING_ENABLED=false` -- hides template section from KYC form.
2. Existing signature packets remain functional (they are standard packets).
3. Witness records remain in DDB but are inert if feature is off.
4. Notary stamp field type degrades to a text field if feature is off.

---

## 15. Expanded E2E Tests

### Section 174 Additions: Template Edge Cases (3 additional tests)

```typescript
test("174.6 Filter templates by intake_profile=enhanced returns 5", async () => {
  // GET /v1/kyc/cases/templates?intake_profile=enhanced
  // All 5 templates required for enhanced
  // Verify count = 5
});

test("174.7 Invalid intake_profile returns 422", async () => {
  // GET /v1/kyc/cases/templates?intake_profile=invalid
  // Expect 422
});

test("174.8 Templates include conditional_on field metadata", async () => {
  // Verify pep_declaration template has pep_details field
  // with conditional_on="is_pep"
});
```

### Section 175 Additions: Auto-Population Edge Cases (3 additional tests)

```typescript
test("175.6 Auto-populated email field uses profile email", async () => {
  // Create packets for case, check data_consent packet
  // Verify email field value = Alice's email from profile
});

test("175.7 Missing profile field uses empty string", async () => {
  // User without mailing_address set
  // Create packets
  // Verify address field is empty but not errored
});

test("175.8 Non-owner cannot create packets for another user's case", async () => {
  // Bob tries to POST create-packets for Alice's case
  // Expect 403
});
```

### Section 176 Additions: Witness Edge Cases (3 additional tests)

```typescript
test("176.5 Witness fields appear on packet after adding witness", async () => {
  // Add witness, then list packet fields
  // Verify witness_name, witness_role, witness_signature, witness_date fields exist
  // Verify signer attribute = "witness"
});

test("176.6 Adding witness twice to same packet returns 409", async () => {
  // Add witness, then try again
  // Expect 409 kyc_witness_already_added
});

test("176.7 Witness with specific sub assigned correctly", async () => {
  // POST add-witness with witness_sub = charlie_admin's sub
  // Verify response witness_sub matches charlie's sub
});
```

### Section 177 Additions: Version Migration Edge Cases (3 additional tests)

```typescript
test("177.5 Multiple templates can be outdated simultaneously", async () => {
  // Update versions of 2 templates
  // GET version-check
  // Verify both templates in the migration needed list
});

test("177.6 Version check on case without packets returns empty", async () => {
  // New case, no create-packets called yet
  // GET version-check
  // Returns empty array (nothing to migrate)
});

test("177.7 Migrated packet has new version but retains auto-populated data", async () => {
  // Create packets, then simulate version change
  // Migrate template
  // Verify new packet has updated version
  // Verify auto-populated fields still contain profile data
});
```

---

## Codebase References

> **Verification performed**: 2026-05-29

### Verified (EXISTS in codebase)

| Reference | File | Line(s) | Status |
|-----------|------|---------|--------|
| `create_or_link_signature_packet()` | `app/routers/kyc_cases.py` | 1206 | VERIFIED |
| `_signature_status_for_case()` | `app/routers/kyc_cases.py` | 184 | VERIFIED |
| `_readiness_for_case()` | `app/routers/kyc_cases.py` | 223 | VERIFIED |
| `create_draft_packet()` | `app/services/signature_packet_store.py` | 91 | VERIFIED |
| `get_packet()` | `app/services/signature_packet_store.py` | 120 | VERIFIED |
| `upsert_packet_field()` | `app/services/signature_packet_store.py` | 133 | VERIFIED |
| Signature packets router | `app/routers/signature_packets.py` | all | VERIFIED (818 lines) |
| Signature settings | `app/core/settings.py` | 798-827 | VERIFIED: table names, expiration, max signers/fields, legal notice |
| `get_profile()` | `app/services/profiles.py` | 220 | VERIFIED |
| `kyc_cases` DDB table | `scripts/local-ddb-init.py` | 91-96 | VERIFIED |

### Not Yet Implemented (requires new code)

| Reference | Expected Location | Status |
|-----------|-------------------|--------|
| Enhanced signing template system | `app/services/signature_packet_store.py` | NOT FOUND -- new template logic required |
| Auto-populated field resolution | `app/services/signature_packet_store.py` | NOT FOUND -- new auto-populate from profile required |
| KYC-specific consent template | n/a | NOT FOUND -- new template definition required |
| Template version migration endpoint | `app/routers/kyc_cases.py` or `app/routers/signature_packets.py` | NOT FOUND -- new endpoint required |
| `frontend/src/pages/kyc/` consent components | `frontend/src/pages/kyc/` | NOT FOUND -- no KYC frontend pages exist |
