# KYC-017: Document Signing Template Library

**Ticket**: KYC-017
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 8-10 days
**Depends on**: KYC-009 (Tiered Verification Levels), KYC-007 (Enhanced Document Signing)

---

## 1. Overview & Motivation

### 1.1 Problem Statement

The existing KYC case system (`app/routers/kyc_cases.py`, 1295 lines) integrates with the signature packet system (`app/routers/signature_packets.py`, 819 lines) to support document signing as a KYC requirement. However, admins must currently create and upload a PDF for every individual case manually. There is no concept of reusable document templates, no auto-population of user profile data into form fields, and no way to tie specific documents to KYC verification tiers.

In practice, KYC compliance requires users to sign standardized legal documents: terms of service acknowledgments, AML declarations, PEP disclosures, tax compliance forms (W-9, W-8BEN), and data processing consent forms. Without a template library, each admin must manually prepare these PDFs, fill in user details by hand, and upload them per-case -- an error-prone process that does not scale.

### 1.2 How It Works

1. Admin uploads a PDF template with placeholder fields (e.g., `{{full_name}}`, `{{address}}`, `{{date_of_birth}}`) via the Template Library admin page.
2. Admin configures the template metadata: slug, display name, required KYC tier, active/inactive status.
3. Templates are stored in S3 with versioning; each upload creates a new version. Old versions remain available for audit but are not offered for new cases.
4. When a KYC case reaches the signature step, the system looks up which templates are required for the user's target verification tier.
5. The backend merges user profile data (name, address, DOB, email, phone) into the PDF placeholders, producing a personalized PDF.
6. The personalized PDF is linked to a signature packet (existing `create_or_link_signature_packet` flow in `app/routers/kyc_cases.py`, line 1206).
7. The user signs the populated document via the existing signature UI.

### 1.3 Template Catalog

| Slug | Display Name | Default Tier |
|------|-------------|--------------|
| `terms_of_service` | Terms of Service Acknowledgment | tier_1 |
| `privacy_consent` | Privacy & Data Usage Consent | tier_1 |
| `aml_declaration` | Anti-Money Laundering Declaration | tier_2 |
| `pep_declaration` | Politically Exposed Person Declaration | tier_2 |
| `tax_compliance_w9` | IRS Form W-9 (US Tax) | tier_2 |
| `tax_compliance_w8ben` | IRS Form W-8BEN (Non-US Tax) | tier_2 |
| `data_processing_agreement` | Data Processing Agreement | tier_3 |
| `third_party_sharing_consent` | Third-Party Data Sharing Consent | tier_3 |
| `investment_risk_acknowledgment` | Investment Risk Acknowledgment | tier_3 |

### 1.4 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Admin | Upload a new PDF template with placeholder fields | Template stored in S3; DDB record created with slug, version, status=active |
| Admin | Deactivate an outdated template version | Status set to inactive; new cases no longer use this version |
| Admin | Preview a template with mock data merged | Rendered PDF returned with placeholder fields filled with sample data |
| User | Sign KYC documents auto-populated with my profile data | PDF has my name, address, DOB, email pre-filled; I only need to sign |
| System | Link required templates to a KYC case based on tier | Case readiness check includes all tier-required templates |

---

## 2. Current State Analysis

### 2.1 Signature Packet System (`app/services/signature_packet_store.py`)

The signature packet system stores packets in `T.signature_packets` with `packet_id` as the primary key. Signers, fields, events, and artifacts are stored in separate tables (`T.signature_packet_signers`, `T.signature_packet_fields`, `T.signature_packet_events`, `T.signature_packet_artifacts`). The `upsert_packet_field` function (which stores float values as `Decimal(str(x))` for DDB compatibility) writes field values but has no concept of template-driven auto-population.

### 2.2 KYC Case Signature Integration (`app/routers/kyc_cases.py`, line 1206)

The `create_or_link_signature_packet` endpoint creates a signature packet and links it to a KYC case via the `signature` ref field (`KycCaseSignatureRef` in `app/contracts/kyc_cases_contract.py`, line 38). The current flow requires the admin to provide a `source_path` pointing to an already-uploaded PDF. There is no template selection or auto-population step.

### 2.3 KYC Case Readiness (`app/routers/kyc_cases.py`, line 223)

The `_readiness_for_case` function checks whether the signature packet is present and completed. It does not check whether all tier-required templates have been signed -- it only checks for a single signature packet.

### 2.4 S3 Storage (`app/core/dev_s3.py`)

S3 is mocked via moto in dev mode, started in-process by the FastAPI app. Template PDFs will be stored at `s3://{bucket}/kyc-templates/{slug}/{version}/template.pdf`. Rendered (merged) PDFs will be stored at `s3://{bucket}/kyc-templates/rendered/{case_id}/{slug}.pdf`.

### 2.5 User Profile Data

User profile data is stored in the `users` DDB table. Fields available for template merge: `full_name`, `email`, `phone`, `address_line_1`, `address_line_2`, `city`, `state`, `postal_code`, `country`, `date_of_birth`. The profile is accessed via `app/services/user_profile.py`.

---

## 3. Technical Design

### 3.1 New DynamoDB Table: `kyc_templates`

```
Table: kyc_templates
  PK: template_id (S)        — UUID
  SK: VERSION#{version_number} (S) — e.g. "VERSION#3"

  Attributes:
    slug (S)                  — e.g. "aml_declaration"
    display_name (S)          — Human-readable name
    description (S)           — Template purpose description
    status (S)                — "active" | "inactive" | "archived"
    required_tier (S)         — "tier_1" | "tier_2" | "tier_3" | "none"
    s3_key (S)                — S3 object key for the template PDF
    placeholder_fields (L)    — List of placeholder names ["full_name", "address", ...]
    created_by (S)            — Admin user_sub who uploaded
    created_at (N)            — Unix timestamp
    updated_at (N)            — Unix timestamp

  GSI slug-status-index:
    PK: slug (S)
    SK: status (S)
    Projection: ALL

  GSI status-updated-index:
    PK: status (S)
    SK: updated_at (N)
    Projection: ALL
```

Add to `scripts/local-ddb-init.py`:

```python
TableDef(
    _resolve_table_name(S.kyc_templates_table_name, "kyc_templates"),
    partition_key="template_id",
    sort_key="sk",
    gsis=[
        {"index_name": "slug-status-index", "partition_key": "slug", "sort_key": "status"},
        {"index_name": "status-updated-index", "partition_key": "status", "sort_key": "updated_at"},
    ],
    attr_types={"updated_at": "N", "created_at": "N"},
),
```

Add settings to `app/core/settings.py`:

```python
kyc_templates_table_name: str = os.environ.get("KYC_TEMPLATES_TABLE_NAME", "kyc_templates")
kyc_templates_slug_index: str = os.environ.get("KYC_TEMPLATES_SLUG_INDEX", "slug-status-index")
kyc_templates_status_index: str = os.environ.get("KYC_TEMPLATES_STATUS_INDEX", "status-updated-index")
kyc_templates_s3_prefix: str = os.environ.get("KYC_TEMPLATES_S3_PREFIX", "kyc-templates")
```

Add table handle to `app/core/tables.py`:

```python
kyc_templates: Any
# ...
kyc_templates=ddb.Table(S.kyc_templates_table_name),
```

### 3.2 New Service: `app/services/kyc_templates.py`

```python
class KycTemplateService:
    def create_template(self, *, slug: str, display_name: str, description: str,
                        required_tier: str, placeholder_fields: list[str],
                        created_by: str) -> dict[str, Any]:
        """Create a new template record (no PDF yet — version 0 placeholder)."""

    def upload_template_version(self, *, template_id: str, version: int,
                                 pdf_bytes: bytes, uploaded_by: str) -> dict[str, Any]:
        """Upload a new PDF version to S3, create VERSION# SK record."""

    def activate_template(self, *, template_id: str, version: int) -> dict[str, Any]:
        """Set status=active on a specific version, deactivate others for same slug."""

    def deactivate_template(self, *, template_id: str, version: int) -> dict[str, Any]:
        """Set status=inactive."""

    def get_active_template_by_slug(self, slug: str) -> dict[str, Any] | None:
        """Query slug-status-index for slug=slug, status=active. Returns latest."""

    def list_templates(self, *, status: str | None = None,
                       limit: int = 50) -> list[dict[str, Any]]:
        """List all templates, optionally filtered by status."""

    def get_template_versions(self, template_id: str) -> list[dict[str, Any]]:
        """Query all VERSION# sort keys for a template_id."""

    def get_required_templates_for_tier(self, tier: str) -> list[dict[str, Any]]:
        """Return all active templates where required_tier <= tier."""

    def render_template(self, *, template_id: str, version: int,
                        user_profile: dict[str, Any]) -> bytes:
        """Download template PDF from S3, merge user data into placeholders,
        return rendered PDF bytes. Uses simple text replacement for {{field}} markers."""

    def render_and_store(self, *, template_id: str, version: int,
                         user_profile: dict[str, Any], case_id: str,
                         slug: str) -> str:
        """Render template and upload to S3 at rendered/{case_id}/{slug}.pdf.
        Returns S3 key."""

    def preview_template(self, *, template_id: str, version: int) -> bytes:
        """Render template with mock sample data for admin preview."""
```

### 3.3 New Router Endpoints

Add to a new router `app/routers/kyc_templates.py`:

```python
router = APIRouter(prefix="/v1/kyc/templates", tags=["kyc-templates"])

# Admin endpoints (require_admin_session)
POST   /                           — Create template metadata
POST   /{template_id}/versions     — Upload new PDF version (multipart/form-data)
PATCH  /{template_id}/versions/{version}/activate   — Activate version
PATCH  /{template_id}/versions/{version}/deactivate — Deactivate version
GET    /                           — List all templates (optional ?status= filter)
GET    /{template_id}              — Get template detail + versions
GET    /{template_id}/versions/{version}/preview — Preview rendered PDF with mock data
DELETE /{template_id}              — Archive template (soft delete)

# Case integration endpoints (require_ui_session)
GET    /required?tier={tier}       — List templates required for a tier
POST   /render-for-case            — Render all required templates for a case, create signature packets
```

### 3.4 Frontend: `frontend/src/pages/admin/KycTemplatesPage.tsx`

**Components:**

- `KycTemplatesPage` — Main admin page with template list table
- `TemplateUploadDialog` — Dialog for creating template + uploading PDF
- `TemplateVersionsPanel` — Side panel showing version history, activate/deactivate controls
- `TemplatePreviewDialog` — PDF preview iframe showing rendered template with sample data

**Route in `App.tsx`:**

```tsx
const KycTemplatesPage = lazy(() => import("@/pages/admin/KycTemplatesPage"));
// ...
<Route path="admin/kyc/templates" element={<KycTemplatesPage />} />
```

**API endpoints in `frontend/src/api/endpoints/kyc-templates.ts`:**

```typescript
export const listTemplates = (status?: string) =>
  client.get<{ items: KycTemplate[] }>("/v1/kyc/templates", { params: { status } });

export const createTemplate = (data: CreateTemplateRequest) =>
  client.post<{ template: KycTemplate }>("/v1/kyc/templates", data);

export const uploadTemplateVersion = (templateId: string, file: File) => {
  const form = new FormData();
  form.append("file", file);
  return client.post(`/v1/kyc/templates/${templateId}/versions`, form);
};

export const activateVersion = (templateId: string, version: number) =>
  client.patch(`/v1/kyc/templates/${templateId}/versions/${version}/activate`);

export const deactivateVersion = (templateId: string, version: number) =>
  client.patch(`/v1/kyc/templates/${templateId}/versions/${version}/deactivate`);

export const previewTemplate = (templateId: string, version: number) =>
  client.get(`/v1/kyc/templates/${templateId}/versions/${version}/preview`,
    { responseType: "blob" });

export const getRequiredTemplates = (tier: string) =>
  client.get<{ items: KycTemplate[] }>("/v1/kyc/templates/required", { params: { tier } });

export const renderForCase = (caseId: string) =>
  client.post<{ rendered: RenderedTemplate[] }>("/v1/kyc/templates/render-for-case",
    { case_id: caseId });
```

### 3.5 Template Rendering Logic

The renderer reads the template PDF from S3, scans for `{{placeholder}}` patterns, and replaces them with values from the user profile. Supported placeholders:

| Placeholder | Source Field | Fallback |
|-------------|-------------|----------|
| `{{full_name}}` | `user_profile.full_name` | `"[Name]"` |
| `{{email}}` | `user_profile.email` | `"[Email]"` |
| `{{phone}}` | `user_profile.phone` | `"[Phone]"` |
| `{{address_line_1}}` | `user_profile.address_line_1` | `"[Address]"` |
| `{{address_line_2}}` | `user_profile.address_line_2` | `""` |
| `{{city}}` | `user_profile.city` | `"[City]"` |
| `{{state}}` | `user_profile.state` | `"[State]"` |
| `{{postal_code}}` | `user_profile.postal_code` | `"[Postal Code]"` |
| `{{country}}` | `user_profile.country` | `"[Country]"` |
| `{{date_of_birth}}` | `user_profile.date_of_birth` | `"[DOB]"` |
| `{{current_date}}` | `now()` ISO date | — |
| `{{case_id}}` | KYC case ID | — |

In dev mode, placeholder replacement uses simple string substitution on the raw PDF bytes. For production, a PDF form-fill library (e.g., `pdfrw` or `PyPDF2`) would be used, but the dev mock uses byte-level text replacement.

### 3.6 Integration with KYC Case Readiness

Extend `_readiness_for_case` in `app/routers/kyc_cases.py` (line 223) to check template completion:

```python
def _readiness_for_case(case: dict) -> dict:
    # ... existing checks ...
    # NEW: Check all required templates for the case's target tier
    required_templates = kyc_template_svc.get_required_templates_for_tier(case.get("target_tier", "tier_1"))
    signed_slugs = set(case.get("signed_template_slugs", []))
    missing_templates = [t["slug"] for t in required_templates if t["slug"] not in signed_slugs]
    if missing_templates:
        missing_requirements.append(f"unsigned_templates:{','.join(missing_templates)}")
```

---

## 4. E2E Test Plan

**Test file**: `frontend/e2e/kyc-templates.spec.ts`
**Total**: ~18 tests across 4 sections (214-217)

### Section 214: Template CRUD API (5 tests)

```typescript
test("214.1 Admin creates a new template with slug and tier", async ({ page }) => {
  // POST /v1/kyc/templates with slug="aml_declaration", required_tier="tier_2"
  // Expect 201 with template_id, status="active"
});

test("214.2 Admin uploads a PDF version for template", async ({ page }) => {
  // POST /v1/kyc/templates/{id}/versions with multipart PDF
  // Expect 201 with version=1, s3_key populated
});

test("214.3 Admin lists templates filtered by status", async ({ page }) => {
  // GET /v1/kyc/templates?status=active
  // Expect array containing the created template
});

test("214.4 Duplicate slug creation returns 409", async ({ page }) => {
  // POST /v1/kyc/templates with same slug
  // Expect 409 conflict
});

test("214.5 Non-admin cannot create templates", async ({ page }) => {
  // Alice (USER role) POST /v1/kyc/templates
  // Expect 403
});
```

### Section 215: Template Version Management (5 tests)

```typescript
test("215.1 Admin uploads second version", async ({ page }) => {
  // POST /v1/kyc/templates/{id}/versions again
  // Expect version=2
});

test("215.2 Admin activates version 2 and version 1 becomes inactive", async ({ page }) => {
  // PATCH /{id}/versions/2/activate
  // GET /{id} -> version 2 active, version 1 inactive
});

test("215.3 Admin deactivates a version", async ({ page }) => {
  // PATCH /{id}/versions/2/deactivate
  // Expect status=inactive
});

test("215.4 Get template returns all versions sorted", async ({ page }) => {
  // GET /v1/kyc/templates/{id}
  // Expect versions array with version 1 and 2
});

test("215.5 Archive template sets status to archived", async ({ page }) => {
  // DELETE /v1/kyc/templates/{id}
  // GET -> status=archived
});
```

### Section 216: Template Rendering & Case Integration (5 tests)

```typescript
test("216.1 Preview template renders with mock data", async ({ page }) => {
  // GET /{id}/versions/1/preview
  // Expect 200 with content-type application/pdf
});

test("216.2 Get required templates for tier_2 includes tier_1 and tier_2 templates", async ({ page }) => {
  // GET /v1/kyc/templates/required?tier=tier_2
  // Expect templates with required_tier in [tier_1, tier_2]
});

test("216.3 Render for case creates signature packets with merged data", async ({ page }) => {
  // Create KYC case, POST /v1/kyc/templates/render-for-case
  // Expect rendered templates linked to case
});

test("216.4 Case readiness includes missing templates", async ({ page }) => {
  // Create case with tier_2, check readiness
  // missing_requirements includes unsigned_templates
});

test("216.5 Render with incomplete profile uses fallback values", async ({ page }) => {
  // User with missing address fields, render template
  // Expect PDF with "[Address]" fallback text
});
```

### Section 217: Template Library Admin UI (3 tests)

```typescript
test("217.1 Admin sees template list table with slug, tier, status columns", async ({ page }) => {
  // Navigate to /admin/kyc/templates
  // Expect table with at least one row showing template data
});

test("217.2 Admin opens upload dialog and creates template", async ({ page }) => {
  // Click "Add Template", fill form, upload PDF
  // Expect new row in table
});

test("217.3 Admin toggles template version active/inactive via UI", async ({ page }) => {
  // Click template row, open versions panel
  // Click activate/deactivate, verify status badge changes
});
```

---

## 5. File Change Summary

| File | Change Type | Description |
|------|-------------|-------------|
| `app/services/kyc_templates.py` | **New** | Template CRUD, S3 storage, rendering, tier lookup |
| `app/routers/kyc_templates.py` | **New** | REST endpoints for template management and rendering |
| `app/contracts/kyc_templates_contract.py` | **New** | Pydantic models for template requests/responses |
| `app/core/settings.py` | Modify | Add `kyc_templates_*` settings |
| `app/core/tables.py` | Modify | Add `kyc_templates` table handle |
| `app/main.py` | Modify | Register `kyc_templates_router` |
| `scripts/local-ddb-init.py` | Modify | Add `kyc_templates` table definition |
| `app/routers/kyc_cases.py` | Modify | Extend `_readiness_for_case` for template checks |
| `frontend/src/api/endpoints/kyc-templates.ts` | **New** | API client functions |
| `frontend/src/api/types.ts` | Modify | Add `KycTemplate`, `CreateTemplateRequest` types |
| `frontend/src/pages/admin/KycTemplatesPage.tsx` | **New** | Admin template management page |
| `frontend/src/App.tsx` | Modify | Add `/admin/kyc/templates` route |
| `frontend/e2e/kyc-templates.spec.ts` | **New** | 18 E2E tests across sections 214-217 |
