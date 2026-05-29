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

The KYC system (`app/routers/kyc_cases.py`) integrates with the signature packet system
(`app/routers/signature_packets.py`, `app/services/signature_packet_store.py`) for consent
signing. Currently, each KYC case creates a generic signature packet via
`create_or_link_signature_packet()` (line 1206 of `kyc_cases.py`), but there is no
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

`app/services/signature_packet_store.py` provides DDB storage:
- `create_draft_packet()`, `get_packet()`, `upsert_packet_field()`
- `get_packet_artifact()` -- final PDF artifact

### 2.2 KYC Signature Integration

`create_or_link_signature_packet()` (line 1206 of `kyc_cases.py`) creates a signature
packet from a file manager path and links it to the KYC case's `signature` field:

```python
{
    "packet_id": "...",
    "status": "draft" | "completed",
    "final_pdf_ref": "packet:{id}:final-pdf"
}
```

`_signature_status_for_case()` (line 184) checks completion status and legal notice
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
