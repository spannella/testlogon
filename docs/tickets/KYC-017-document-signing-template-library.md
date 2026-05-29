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

The existing KYC case system (see `app/routers/kyc_cases.py`, ~1294 lines) integrates with the signature packet system (see `app/routers/signature_packets.py`, ~818 lines) to support document signing as a KYC requirement. However, admins must currently create and upload a PDF for every individual case manually. There is no concept of reusable document templates, no auto-population of user profile data into form fields, and no way to tie specific documents to KYC verification tiers.

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

### 2.1 Signature Packet System (see `app/services/signature_packet_store.py`)

The signature packet system stores packets in `T.signature_packets` (see `scripts/local-ddb-init.py:175`) with `packet_id` as the primary key. Signers, fields, events, and artifacts are stored in separate tables (`T.signature_packet_signers`, `T.signature_packet_fields`, `T.signature_packet_events`, `T.signature_packet_artifacts`). The `upsert_packet_field` function (see `app/services/signature_packet_store.py:133`, stores float values as `Decimal(str(x))` for DDB compatibility) writes field values but has no concept of template-driven auto-population.

### 2.2 KYC Case Signature Integration (see `app/routers/kyc_cases.py:1206`)

The `create_or_link_signature_packet` endpoint creates a signature packet and links it to a KYC case via the `signature` ref field (`KycCaseSignatureRef` in `app/contracts/kyc_cases_contract.py:38`). The current flow requires the admin to provide a `source_path` pointing to an already-uploaded PDF. There is no template selection or auto-population step.

### 2.3 KYC Case Readiness (see `app/routers/kyc_cases.py:223`)

The `_readiness_for_case` function checks whether the signature packet is present and completed. It does not check whether all tier-required templates have been signed -- it only checks for a single signature packet.

### 2.4 S3 Storage (`app/core/dev_s3.py`)

S3 is mocked via moto in dev mode, started in-process by the FastAPI app. Template PDFs will be stored at `s3://{bucket}/kyc-templates/{slug}/{version}/template.pdf`. Rendered (merged) PDFs will be stored at `s3://{bucket}/kyc-templates/rendered/{case_id}/{slug}.pdf`.

### 2.5 User Profile Data

User profile data is stored in the `users` DDB table (see `scripts/local-ddb-init.py:49`). Fields available for template merge: `full_name`, `email`, `phone`, `address_line_1`, `address_line_2`, `city`, `state`, `postal_code`, `country`, `date_of_birth`. The profile is accessed via `app/services/profile.py`.
<!-- NOTE: The ticket references app/services/user_profile.py but the actual file is app/services/profile.py -->

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
<!-- NOTE: app/services/kyc_templates.py does not exist yet — new implementation required -->

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
<!-- NOTE: app/routers/kyc_templates.py does not exist yet — new implementation required -->

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

Extend `_readiness_for_case` in `app/routers/kyc_cases.py` (see line 223) to check template completion:

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

---

## 6. Architecture & Data Flow

```
┌────────────────────────────────────────────────────────────────────────────┐
│                           Frontend                                         │
│                                                                            │
│  KycTemplatesPage.tsx (admin)                                             │
│  ┌──────────────────────────────────────────────────────────────────┐     │
│  │ TemplateListTable                                                 │     │
│  │  └─ Row per template                                              │     │
│  │      ├─ Slug (monospace)                                          │     │
│  │      ├─ DisplayName                                               │     │
│  │      ├─ TierBadge (tier_1 | tier_2 | tier_3)                     │     │
│  │      ├─ StatusBadge (active=green | inactive=gray | archived=red) │     │
│  │      ├─ VersionCount                                              │     │
│  │      └─ ExpandButton → TemplateVersionsPanel (side panel)         │     │
│  │                         ├─ VersionRow[]                            │     │
│  │                         │   ├─ VersionNumber (v1, v2, ...)        │     │
│  │                         │   ├─ StatusBadge                         │     │
│  │                         │   ├─ UploadDate                          │     │
│  │                         │   ├─ PreviewButton → TemplatePreview     │     │
│  │                         │   └─ ActivateToggle                      │     │
│  │                         └─ Button "Upload New Version"             │     │
│  ├─ Button "Add Template" → TemplateUploadDialog                     │     │
│  │                          ├─ Input (slug, kebab-case)               │     │
│  │                          ├─ Input (display_name)                   │     │
│  │                          ├─ Textarea (description)                 │     │
│  │                          ├─ Select (required_tier)                 │     │
│  │                          ├─ TagInput (placeholder_fields)          │     │
│  │                          ├─ FileUpload (PDF)                       │     │
│  │                          └─ Button "Create"                        │     │
│  └─ TemplatePreviewDialog (iframe showing rendered PDF)              │     │
└──────────────────────────────────────────────────────────────────────────┘  │
│                                                                            │
└──────────────────┬─────────────────────────────────────────────────────────┘
                   │
                   ▼
┌────────────────────────────────────────────────────────────────────────────┐
│                      Backend (FastAPI)                                      │
│                                                                            │
│  kyc_templates.py (NEW router — /v1/kyc/templates)                        │
│  ┌──────────────────────────────────────────────────────────────────┐     │
│  │ POST /                        — Create template metadata          │     │
│  │ POST /{id}/versions           — Upload PDF version (multipart)    │     │
│  │ PATCH /{id}/versions/{v}/activate   — Activate version            │     │
│  │ PATCH /{id}/versions/{v}/deactivate — Deactivate version          │     │
│  │ GET  /                        — List templates (?status=)         │     │
│  │ GET  /{id}                    — Get detail + versions             │     │
│  │ GET  /{id}/versions/{v}/preview — Preview rendered with mock data │     │
│  │ DELETE /{id}                  — Archive template (soft delete)     │     │
│  │ GET  /required?tier={tier}    — Required templates for tier       │     │
│  │ POST /render-for-case         — Render + create signature packets │     │
│  └──────────────────────────────────────────────────────────────────┘     │
│                                                                            │
│  KycTemplateService (NEW — app/services/kyc_templates.py)                 │
│  ┌──────────────────────────────────────────────────────────────────┐     │
│  │ create_template()           — DDB record + metadata               │     │
│  │ upload_template_version()   — S3 upload + VERSION# SK record      │     │
│  │ activate_template()         — Set active, deactivate siblings     │     │
│  │ deactivate_template()       — Set inactive                        │     │
│  │ get_active_template_by_slug() — GSI query slug-status-index       │     │
│  │ list_templates()            — Scan/query with status filter       │     │
│  │ get_template_versions()     — Query all VERSION# sort keys        │     │
│  │ get_required_templates_for_tier() — Filter active by tier         │     │
│  │ render_template()           — S3 download + placeholder merge     │     │
│  │ render_and_store()          — Render + upload to S3 rendered/     │     │
│  │ preview_template()          — Render with mock sample data        │     │
│  └──────────────────────────────────────────────────────────────────┘     │
└──────────────────┬─────────────────────────────────────────────────────────┘
                   │
                   ▼
┌────────────────────────────────────────────────────────────────────────────┐
│  DynamoDB: kyc_templates                   S3 (moto mock)                 │
│  ┌──────────────────────────────┐        ┌──────────────────────────────┐│
│  │ PK = template_id             │        │ kyc-templates/               ││
│  │ SK = VERSION#{version_number}│        │   {slug}/{version}/          ││
│  │                              │        │     template.pdf             ││
│  │ GSI slug-status-index:       │        │                              ││
│  │   PK=slug, SK=status         │        │ kyc-templates/rendered/      ││
│  │                              │        │   {case_id}/{slug}.pdf       ││
│  │ GSI status-updated-index:    │        └──────────────────────────────┘│
│  │   PK=status, SK=updated_at   │                                        │
│  └──────────────────────────────┘                                        │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## 7. DynamoDB Access Patterns

| # | Access Pattern | Table / Index | Key Condition | Notes |
|---|---------------|---------------|---------------|-------|
| 1 | Create template | `kyc_templates` | PK=`{template_id}`, SK=`VERSION#0` | Initial metadata placeholder |
| 2 | Upload version | `kyc_templates` | PK=`{template_id}`, SK=`VERSION#{n}` | New version record |
| 3 | Activate version | `kyc_templates` | PK=`{template_id}`, SK=`VERSION#{n}` | Update status=active |
| 4 | Deactivate siblings | GSI `slug-status-index` | PK=`{slug}`, SK=`active` | Query active versions for same slug, set inactive |
| 5 | Get active by slug | GSI `slug-status-index` | PK=`{slug}`, SK=`active` | Returns latest active version |
| 6 | List by status | GSI `status-updated-index` | PK=`{status}`, SK desc | Admin list with status filter |
| 7 | Get all versions | `kyc_templates` | PK=`{template_id}`, SK begins_with `VERSION#` | All versions for detail view |
| 8 | Archive template | `kyc_templates` | PK=`{template_id}`, SK=`VERSION#*` | Update all versions to archived |
| 9 | Required for tier | GSI `status-updated-index` | PK=`active`, filter `required_tier <= {tier}` | Active templates for a tier |

---

## 8. API Request/Response Examples

### 8.1 Create Template

```bash
curl -X POST "http://localhost:8000/v1/kyc/templates" \
  -H "Cookie: ui_session=sess_root; ui_access_token=eyJ...; ui_csrf=csrf_r" \
  -H "x-csrf-token: csrf_r" \
  -H "Content-Type: application/json" \
  -d '{
    "slug": "aml_declaration",
    "display_name": "Anti-Money Laundering Declaration",
    "description": "Declaration that funds are not derived from illegal activity",
    "required_tier": "tier_2",
    "placeholder_fields": ["full_name", "address_line_1", "city", "state", "postal_code", "country", "date_of_birth", "current_date"]
  }'
```

**Response (201):**
```json
{
  "template_id": "tmpl_a1b2c3d4e5f6",
  "slug": "aml_declaration",
  "display_name": "Anti-Money Laundering Declaration",
  "status": "active",
  "required_tier": "tier_2",
  "placeholder_fields": ["full_name", "address_line_1", "city", "state", "postal_code", "country", "date_of_birth", "current_date"],
  "created_at": 1716681600
}
```

### 8.2 Upload PDF Version

```bash
curl -X POST "http://localhost:8000/v1/kyc/templates/tmpl_a1b2c3d4e5f6/versions" \
  -H "Cookie: ui_session=sess_root; ui_access_token=eyJ...; ui_csrf=csrf_r" \
  -H "x-csrf-token: csrf_r" \
  -F "file=@aml_declaration_v1.pdf"
```

**Response (201):**
```json
{
  "template_id": "tmpl_a1b2c3d4e5f6",
  "version": 1,
  "s3_key": "kyc-templates/aml_declaration/1/template.pdf",
  "status": "active",
  "uploaded_by": "root.admin@testdev.local",
  "created_at": 1716681700
}
```

### 8.3 Preview Template with Mock Data

```bash
curl -X GET "http://localhost:8000/v1/kyc/templates/tmpl_a1b2c3d4e5f6/versions/1/preview" \
  -H "Cookie: ui_session=sess_root; ui_access_token=eyJ...; ui_csrf=csrf_r" \
  -o preview.pdf
```

**Response (200):** Binary PDF with placeholders replaced by sample values:
- `{{full_name}}` -> "Jane Sample Doe"
- `{{address_line_1}}` -> "123 Example Street"
- `{{city}}` -> "Sampleville"
- `{{current_date}}` -> "2026-05-29"

### 8.4 Get Required Templates for Tier

```bash
curl -X GET "http://localhost:8000/v1/kyc/templates/required?tier=tier_2" \
  -H "Cookie: ui_session=sess_alice; ui_access_token=eyJ...; ui_csrf=csrf_a"
```

**Response (200):**
```json
{
  "items": [
    {
      "template_id": "tmpl_tos_001",
      "slug": "terms_of_service",
      "display_name": "Terms of Service Acknowledgment",
      "required_tier": "tier_1",
      "status": "active"
    },
    {
      "template_id": "tmpl_privacy_002",
      "slug": "privacy_consent",
      "display_name": "Privacy & Data Usage Consent",
      "required_tier": "tier_1",
      "status": "active"
    },
    {
      "template_id": "tmpl_aml_003",
      "slug": "aml_declaration",
      "display_name": "Anti-Money Laundering Declaration",
      "required_tier": "tier_2",
      "status": "active"
    },
    {
      "template_id": "tmpl_pep_004",
      "slug": "pep_declaration",
      "display_name": "Politically Exposed Person Declaration",
      "required_tier": "tier_2",
      "status": "active"
    }
  ]
}
```

### 8.5 Render Templates for Case

```bash
curl -X POST "http://localhost:8000/v1/kyc/templates/render-for-case" \
  -H "Cookie: ui_session=sess_alice; ui_access_token=eyJ...; ui_csrf=csrf_a" \
  -H "x-csrf-token: csrf_a" \
  -H "Content-Type: application/json" \
  -d '{ "case_id": "kyc_a1b2c3d4" }'
```

**Response (200):**
```json
{
  "rendered": [
    {
      "slug": "terms_of_service",
      "template_id": "tmpl_tos_001",
      "rendered_s3_key": "kyc-templates/rendered/kyc_a1b2c3d4/terms_of_service.pdf",
      "packet_id": "pkt_tos_a1b2c3",
      "fields_populated": 4,
      "fields_fallback": 0
    },
    {
      "slug": "aml_declaration",
      "template_id": "tmpl_aml_003",
      "rendered_s3_key": "kyc-templates/rendered/kyc_a1b2c3d4/aml_declaration.pdf",
      "packet_id": "pkt_aml_d4e5f6",
      "fields_populated": 6,
      "fields_fallback": 2
    }
  ]
}
```

---

## 9. Error Handling Matrix

| Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|----------|-------------|------------|---------------------|----------------|
| Duplicate slug creation | 409 | `kyc_template_slug_exists` | "A template with this slug already exists." | Use different slug |
| Non-admin creates template | 403 | `kyc_admin_role_required` | "Admin access required." | Use admin credentials |
| Upload to non-existent template | 404 | `kyc_template_not_found` | "Template not found." | Verify template_id |
| Upload non-PDF file | 422 | `kyc_invalid_file_type` | "Only PDF files are accepted." | Upload PDF |
| Activate non-existent version | 404 | `kyc_version_not_found` | "Template version not found." | Check version number |
| Archive already-archived template | 409 | `kyc_template_already_archived` | "Template is already archived." | No action needed |
| Render for case without required templates | 400 | `kyc_no_templates_available` | "No active templates found for this tier." | Create and activate templates |
| Render with missing profile fields | 200 | — | Renders with `[Fallback]` values | Update profile before signing |
| PDF too large (> 10MB) | 413 | `kyc_file_too_large` | "PDF must be under 10MB." | Compress PDF |
| Preview with no uploaded version | 400 | `kyc_no_pdf_uploaded` | "No PDF has been uploaded for this version." | Upload PDF first |

---

## 10. Pydantic Models

### 10.1 Request Models

```python
from pydantic import BaseModel, Field
from typing import Literal, Any


class CreateTemplateRequest(BaseModel):
    """Request to create a new signing template."""
    slug: str = Field(
        min_length=3,
        max_length=100,
        pattern=r"^[a-z0-9_-]+$",
        description="URL-safe slug for the template. Must be unique.",
        examples=["kyc-consent-v2"],
    )
    title: str = Field(
        min_length=3,
        max_length=200,
        description="Human-readable title displayed to signers.",
        examples=["KYC Identity Verification Consent"],
    )
    description: str | None = Field(
        default=None,
        max_length=2000,
        description="Optional description of the template purpose.",
    )
    tier: Literal["basic", "standard", "enhanced"] = Field(
        default="standard",
        description="KYC tier this template applies to.",
    )
    fields: list[dict[str, Any]] = Field(
        default_factory=list,
        max_length=50,
        description="Template fields for dynamic rendering.",
        examples=[[
            {"name": "full_name", "type": "text", "source": "profile.full_name", "fallback": "[Full Name]"},
            {"name": "date_of_birth", "type": "date", "source": "profile.dob", "fallback": "[DOB]"},
        ]],
    )
    required_signatures: int = Field(
        default=1,
        ge=1,
        le=10,
        description="Number of signatures required to complete the packet.",
    )
    pdf_page_count: int | None = Field(
        default=None,
        ge=1,
        le=100,
        description="Expected page count of the PDF template.",
    )


class UpdateTemplateRequest(BaseModel):
    """Request to update a template (creates a new version)."""
    title: str | None = Field(default=None, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    tier: Literal["basic", "standard", "enhanced"] | None = None
    fields: list[dict[str, Any]] | None = Field(default=None, max_length=50)
    required_signatures: int | None = Field(default=None, ge=1, le=10)
    expected_version: int = Field(
        ge=1,
        description="OCC version for conflict detection.",
    )


class ActivateTemplateRequest(BaseModel):
    """Request to activate a template version."""
    version: int = Field(
        ge=1,
        description="The version number to activate.",
    )


class RenderTemplateRequest(BaseModel):
    """Request to render a template for a specific KYC case."""
    case_id: str = Field(
        min_length=1,
        max_length=100,
        description="KYC case ID to render the template for.",
    )
    template_slug: str = Field(
        min_length=1,
        max_length=100,
        description="Template slug to render.",
    )
    overrides: dict[str, str] | None = Field(
        default=None,
        max_length=50,
        description="Optional field value overrides (key=field_name, value=override_value).",
    )


class ArchiveTemplateRequest(BaseModel):
    """Request to archive a template."""
    reason: str | None = Field(
        default=None,
        max_length=500,
        description="Optional reason for archiving.",
    )


class UploadTemplatePdfRequest(BaseModel):
    """Request to upload a PDF for a template version."""
    version: int = Field(ge=1, description="Version to upload the PDF for.")
    file_node_id: str = Field(
        min_length=1,
        max_length=256,
        description="File manager node ID for the uploaded PDF.",
    )
```

### 10.2 Response Models

```python
from pydantic import BaseModel, Field
from typing import Any, Literal


class TemplateFieldOut(BaseModel):
    """A dynamic field in a signing template."""
    name: str
    type: str  # text, date, number, checkbox, signature
    source: str = Field(description="Data source path (e.g., profile.full_name)")
    fallback: str = Field(description="Fallback value if source is empty")
    required: bool = True


class TemplateVersionOut(BaseModel):
    """A specific version of a template."""
    version: int = Field(ge=1)
    created_at: int
    created_by: str
    pdf_uploaded: bool = False
    pdf_page_count: int | None = None
    changes_summary: str | None = None


class TemplateOut(BaseModel):
    """A signing template."""
    template_id: str
    slug: str
    title: str
    description: str | None = None
    tier: Literal["basic", "standard", "enhanced"]
    status: Literal["draft", "active", "archived"]
    fields: list[TemplateFieldOut]
    required_signatures: int = Field(ge=1)
    current_version: int = Field(ge=1)
    active_version: int | None = None
    versions: list[TemplateVersionOut] = Field(default_factory=list)
    created_at: int
    updated_at: int
    created_by: str
    archived_at: int | None = None
    archived_by: str | None = None
    archive_reason: str | None = None


class TemplateListOut(BaseModel):
    """List of signing templates."""
    templates: list[TemplateOut]
    total: int
    cursor: str | None = None


class TemplateCreateOut(BaseModel):
    """Response after creating a new template."""
    template_id: str
    slug: str
    version: int = 1
    status: str = "draft"
    created_at: int


class RenderedFieldOut(BaseModel):
    """A rendered field with its resolved value."""
    name: str
    original_value: str
    rendered_value: str
    source: str
    used_fallback: bool


class RenderResultOut(BaseModel):
    """Result of rendering a template for a specific case."""
    template_slug: str
    template_version: int
    case_id: str
    rendered_fields: list[RenderedFieldOut]
    signature_packet_id: str | None = None
    rendered_at: int


class TemplatePreviewOut(BaseModel):
    """Preview data for a template (without creating a packet)."""
    template_slug: str
    title: str
    fields: list[TemplateFieldOut]
    pdf_url: str | None = None
    pdf_page_count: int | None = None


class ArchiveResultOut(BaseModel):
    """Response after archiving a template."""
    template_id: str
    slug: str
    status: Literal["archived"] = "archived"
    archived_at: int
    archived_by: str
    reason: str | None = None
```

---

## 11. Frontend Component Tree

```
TemplateLibraryPage.tsx  (/admin/kyc/templates)
├── Props: none (root-only admin page)
├── State:
│   ├── selectedTemplate: TemplateOut | null
│   ├── showCreateDialog: boolean
│   └── searchQuery: string
├── Queries:
│   └── useQuery(["kyc","templates"]) → TemplateListOut
├── Mutations:
│   ├── useMutation(createTemplate) → invalidate ["kyc","templates"]
│   ├── useMutation(archiveTemplate) → invalidate ["kyc","templates"]
│   └── useMutation(activateTemplate) → invalidate ["kyc","templates"]
│
├── <div className="flex gap-6">
│   │
│   ├── {/* Left panel: template list */}
│   ├── <Card className="w-1/3">
│   │   ├── <CardHeader className="flex justify-between">
│   │   │   ├── <CardTitle>"Template Library"</CardTitle>
│   │   │   └── <Button size="sm" onClick={() => setShowCreateDialog(true)}>
│   │   │       <Plus /> "New Template"
│   │   │   </Button>
│   │   ├── <Input placeholder="Search templates..." onChange={setSearchQuery} />
│   │   └── <CardContent>
│   │       └── filteredTemplates.map(tmpl =>
│   │           <div onClick={() => setSelectedTemplate(tmpl)}
│   │                className={`p-3 border-b cursor-pointer hover:bg-accent
│   │                  ${selected?.slug === tmpl.slug ? "bg-accent" : ""}`}>
│   │             ├── <div className="flex justify-between">
│   │             │   ├── <span className="font-medium">{tmpl.title}</span>
│   │             │   └── <Badge>{tmpl.status}</Badge>
│   │             ├── <span className="text-xs text-muted-foreground">{tmpl.slug}</span>
│   │             └── <div className="flex gap-1">
│   │                 ├── <Badge variant="outline">{tmpl.tier}</Badge>
│   │                 └── <span className="text-xs">v{tmpl.current_version}</span>
│   │           </div>)
│   │   </CardContent>
│   └── </Card>
│   │
│   └── {/* Right panel: template detail */}
│       <Card className="w-2/3">
│       ├── {!selectedTemplate &&
│       │   <CardContent className="text-center text-muted-foreground p-12">
│       │     "Select a template to view details"
│       │   </CardContent>}
│       │
│       └── {selectedTemplate &&
│           <TemplateDetailPanel>
│           ├── Props: { template: TemplateOut }
│           ├── State: activeTab (useState)
│           │
│           ├── <CardHeader>
│           │   ├── <CardTitle>{template.title}</CardTitle>
│           │   ├── <Badge>{template.status}</Badge>
│           │   └── <div className="flex gap-2">
│           │       ├── {status === "draft" &&
│           │       │   <Button onClick={activate}>"Activate"</Button>}
│           │       ├── {status !== "archived" &&
│           │       │   <Button variant="outline" onClick={archive}>"Archive"</Button>}
│           │       └── <Button variant="outline">"New Version"</Button>
│           │
│           ├── <Tabs value={activeTab}>
│           │   ├── <TabsList>
│           │   │   ├── <TabsTrigger value="fields">"Fields"</TabsTrigger>
│           │   │   ├── <TabsTrigger value="versions">"Versions"</TabsTrigger>
│           │   │   ├── <TabsTrigger value="preview">"Preview"</TabsTrigger>
│           │   │   └── <TabsTrigger value="usage">"Usage"</TabsTrigger>
│           │   │
│           │   ├── <TabsContent value="fields">
│           │   │   └── <FieldsEditor>
│           │   │       ├── <DataTable columns={["Name","Type","Source","Fallback","Required"]}>
│           │   │       │   └── template.fields.map(field => <FieldRow>)
│           │   │       └── <Button>"Add Field"</Button>
│           │   │
│           │   ├── <TabsContent value="versions">
│           │   │   └── <VersionHistory>
│           │   │       └── template.versions.map(ver =>
│           │   │           <div className="flex justify-between p-3 border-b">
│           │   │             ├── <span>v{ver.version}</span>
│           │   │             ├── <span>{formatDate(ver.created_at)}</span>
│           │   │             ├── <Badge>{ver.pdf_uploaded ? "PDF" : "No PDF"}</Badge>
│           │   │             ├── {ver.version === active_version &&
│           │   │             │   <Badge variant="success">"Active"</Badge>}
│           │   │             └── <Button size="sm">"Upload PDF"</Button>
│           │   │           </div>)
│           │   │
│           │   ├── <TabsContent value="preview">
│           │   │   └── <TemplatePreview>
│           │   │       ├── <Select label="Preview with case"
│           │   │       │          options={recentCases} />
│           │   │       ├── <RenderedFieldsTable>
│           │   │       │   └── Columns: [Field, Source, Value, Fallback Used]
│           │   │       └── <iframe src={pdfPreviewUrl} /> (if PDF uploaded)
│           │   │
│           │   └── <TabsContent value="usage">
│           │       └── <TemplateUsageStats>
│           │           ├── <p>"Used in {usageCount} signing packets"</p>
│           │           └── <DataTable columns={["Case ID","Signed By","Signed At","Status"]} />
│           │
│           └── </Tabs>
│       </TemplateDetailPanel>}
│   </Card>
└── </div>

{/* Create template dialog */}
<Dialog open={showCreateDialog}>
└── <DialogContent>
    ├── <DialogTitle>"Create New Template"</DialogTitle>
    └── <Form>
        ├── <Input label="Slug" {...register("slug")} />
        ├── <Input label="Title" {...register("title")} />
        ├── <Textarea label="Description" {...register("description")} />
        ├── <Select label="Tier" options={["basic","standard","enhanced"]} />
        ├── <Input type="number" label="Required Signatures" min={1} max={10} />
        └── <Button type="submit">"Create Template"</Button>
    </Form>
</Dialog>
```

### React Query Keys

| Key | Endpoint | Stale Time | Invalidation |
|-----|----------|------------|--------------|
| `["kyc","templates"]` | `GET /v1/kyc/templates` | 30s | After create/archive/activate |
| `["kyc","template", slug]` | `GET /v1/kyc/templates/{slug}` | 10s | After update/version/upload |
| `["kyc","template-preview", slug, caseId]` | `POST /v1/kyc/templates/{slug}/preview` | 0 | Never cached |

---

## 12. Observability & Monitoring

### Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `kyc_template_created` | Counter | `slug` | Templates created |
| `kyc_template_version_uploaded` | Counter | `slug` | PDF versions uploaded |
| `kyc_template_activated` | Counter | `slug`, `version` | Version activations |
| `kyc_template_rendered` | Counter | `slug`, `fallback_count` | Templates rendered for cases |
| `kyc_template_render_latency_ms` | Histogram | `slug` | Render time distribution |
| `kyc_template_preview_served` | Counter | `slug` | Admin preview requests |

### Log Events

| Event | Level | Fields | Trigger |
|-------|-------|--------|---------|
| `kyc.template.created` | INFO | `template_id`, `slug`, `tier` | POST create |
| `kyc.template.version_uploaded` | INFO | `template_id`, `version`, `s3_key` | POST version |
| `kyc.template.activated` | INFO | `template_id`, `version`, `deactivated_count` | PATCH activate |
| `kyc.template.rendered` | INFO | `case_id`, `slug`, `fields_populated`, `fields_fallback` | Render for case |
| `kyc.template.archived` | WARN | `template_id`, `slug` | DELETE archive |
| `kyc.template.render_fallback` | WARN | `case_id`, `slug`, `missing_fields` | Profile fields missing during render |

### Alerts

| Alert | Condition | Severity |
|-------|-----------|----------|
| No active templates for tier | Any tier has 0 active templates | P2 |
| High fallback rate | > 30% of renders use fallback values in 24h | P3 |
| Template upload failures | > 3 S3 upload failures in 1h | P2 |

---

## 13. Performance Considerations

| Operation | Latency Target | DDB Cost | Notes |
|-----------|---------------|----------|-------|
| Create template | < 100ms | 1 WCU | Single PutItem |
| Upload version | < 500ms | 1 WCU + S3 PUT | DDB write + S3 upload (PDF size dependent) |
| Activate version | < 200ms | 1 + N WCU | 1 activate + N deactivate siblings (usually 1-2) |
| List templates | < 200ms | 10 RCU | GSI query with limit |
| Preview template | < 800ms | 1 RCU + S3 GET | S3 download + in-memory placeholder replacement |
| Render for case | < 1s per template | 1 RCU + S3 GET + S3 PUT | Download template + merge + upload rendered |
| Required for tier | < 150ms | 10 RCU | GSI query with tier filter |

### Caching

- Template metadata can be cached in-memory for 5 minutes (templates change infrequently).
- S3 template PDFs can be cached on first read per process (same as S3 mock in-process model).
- Rendered PDFs are stored in S3 and do not need to be re-rendered unless profile data changes.

### Size Limits

- Template PDF: max 10MB per upload.
- Rendered PDF: same size as template (placeholder replacement does not change file size significantly).
- `placeholder_fields` list: max 20 entries.
- Versions per template: unlimited (but UI shows most recent 10).

---

## 14. Rollout Plan

### Feature Flags

| Flag | Default | Purpose |
|------|---------|---------|
| `KYC_TEMPLATE_LIBRARY_ENABLED` | `false` | Gates template admin page and CRUD endpoints |
| `KYC_TEMPLATE_RENDER_ENABLED` | `false` | Gates render-for-case integration |
| `KYC_TEMPLATE_READINESS_GATE` | `false` | Gates readiness check for signed templates |

### Phases

| Phase | Description | Duration |
|-------|-------------|----------|
| 1 | Deploy service + DDB table + admin endpoints behind flag | 2 days |
| 2 | Enable admin page in staging; upload initial template PDFs | 1 day |
| 3 | Enable render-for-case in staging; test with sample KYC cases | 1 day |
| 4 | Enable template library in production (admin-only, no readiness gate) | 1 week |
| 5 | Enable readiness gate (required templates must be signed for submission) | after 2 weeks |

### Rollback

1. Set `KYC_TEMPLATE_LIBRARY_ENABLED=false` -- admin page hidden, CRUD endpoints return 404.
2. Set `KYC_TEMPLATE_RENDER_ENABLED=false` -- render-for-case returns empty (no packets created).
3. Set `KYC_TEMPLATE_READINESS_GATE=false` -- readiness check skips template signing requirement.
4. Existing template records and S3 objects remain in place for audit purposes.
5. Signature packets already created from templates continue to function normally.

---

## 15. Expanded E2E Tests

### Section 214 Additions: Template CRUD Edge Cases (4 additional tests)

```typescript
test("214.6 Admin archives a template (soft delete)", async ({ page }) => {
  // DELETE /v1/kyc/templates/{id}
  // GET -> status=archived
  // Verify archived template not returned in list with status=active
});

test("214.7 Archived template versions are preserved for audit", async ({ page }) => {
  // GET /v1/kyc/templates/{id} after archive
  // Verify versions still accessible
  // Verify each version has original s3_key
});

test("214.8 Create template with empty placeholder_fields succeeds", async ({ page }) => {
  // POST with placeholder_fields=[]
  // Verify 201 success (template with no placeholders is valid)
});

test("214.9 Template slug validation rejects spaces and uppercase", async ({ page }) => {
  // POST with slug="AML Declaration"
  // Expect 422 (slug must be kebab-case/snake_case)
});
```

### Section 215 Additions: Version Edge Cases (3 additional tests)

```typescript
test("215.6 Cannot activate a version on an archived template", async ({ page }) => {
  // Archive template, then try PATCH activate version
  // Expect 400 or 409
});

test("215.7 Uploading version increments automatically", async ({ page }) => {
  // Upload 3 versions sequentially
  // Verify version numbers are 1, 2, 3
});

test("215.8 Deactivating only active version leaves no active version", async ({ page }) => {
  // Deactivate the single active version
  // GET required?tier=tier_2
  // Verify this template not in required list
});
```

### Section 216 Additions: Rendering Edge Cases (4 additional tests)

```typescript
test("216.6 Render with all profile fields populated has 0 fallbacks", async ({ page }) => {
  // Ensure Alice has full profile (name, email, address, DOB, phone)
  // POST render-for-case
  // Verify fields_fallback = 0 for each template
});

test("216.7 Render creates signature packets linked to case", async ({ page }) => {
  // POST render-for-case
  // GET case detail
  // Verify signed_template_slugs or similar field references the rendered templates
});

test("216.8 Double render-for-case is idempotent", async ({ page }) => {
  // POST render-for-case twice
  // Verify same packet_ids returned (no duplicate packets)
});

test("216.9 Render for case with no active templates returns empty", async ({ page }) => {
  // Deactivate all templates
  // POST render-for-case
  // Expect 400 kyc_no_templates_available
});
```

### Section 217 Additions: Admin UI Tests (3 additional tests)

```typescript
test("217.4 Admin previews template PDF in iframe dialog", async ({ page }) => {
  // Click preview button for uploaded template
  // Verify dialog opens with iframe
  // Verify iframe src points to preview endpoint
});

test("217.5 Admin sees placeholder fields listed on template detail", async ({ page }) => {
  // Click template row to open detail
  // Verify placeholder_fields displayed as tags/chips
  // Verify each placeholder shows with {{}} syntax
});

test("217.6 Template list sorts by updated_at descending", async ({ page }) => {
  // Create 2 templates at different times
  // Verify most recently updated template appears first in list
});
```

---

## Codebase References

| Reference | File | Line(s) | Status |
|-----------|------|---------|--------|
| KYC cases router | `app/routers/kyc_cases.py` | 48 | Exists (~1294 lines) |
| Signature packets router | `app/routers/signature_packets.py` | -- | Exists (~818 lines) |
| `create_or_link_signature_packet()` | `app/routers/kyc_cases.py` | 1206 | Exists |
| `_readiness_for_case()` | `app/routers/kyc_cases.py` | 223 | Exists |
| `KycCaseSignatureRef` | `app/contracts/kyc_cases_contract.py` | 38 | Exists |
| `upsert_packet_field()` | `app/services/signature_packet_store.py` | 133 | Exists |
| Signature packets DDB tables | `scripts/local-ddb-init.py` | 175-208 | Exist |
| Users DDB table | `scripts/local-ddb-init.py` | 49 | Exists |
| Profile service | `app/services/profile.py` | -- | Exists (ticket incorrectly calls it `user_profile.py`) |
| S3 mock | `app/core/dev_s3.py` | -- | Exists |
| `kyc_templates` DDB table | -- | -- | Does NOT exist — new table required |
| `kyc_templates_table_name` setting | -- | -- | Does NOT exist — new setting required |
| `app/services/kyc_templates.py` | -- | -- | Does NOT exist — new implementation required |
| `app/routers/kyc_templates.py` | -- | -- | Does NOT exist — new router required |
| `app/contracts/kyc_templates_contract.py` | -- | -- | Does NOT exist — new file required |
| `frontend/src/pages/admin/KycTemplatesPage.tsx` | -- | -- | Does NOT exist — new page required |
| `frontend/src/api/endpoints/kyc-templates.ts` | -- | -- | Does NOT exist — new file required |
