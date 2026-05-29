# KYC-020: Multi-Language KYC Support

**Ticket**: KYC-020
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 6-8 days
**Depends on**: KYC-017 (Document Signing Template Library), KYC-013 (User Self-Service Portal)

---

## 1. Overview & Motivation

### 1.1 Problem Statement

The KYC system currently operates exclusively in English. All KYC forms, questionnaire prompts, document signing legal notices, email notifications, and admin review labels are hard-coded in English. For a platform serving a global user base, this creates multiple problems:

1. **User confusion**: Non-English speakers struggle to understand KYC requirements, leading to incomplete submissions and higher rejection rates.
2. **Legal risk**: In many jurisdictions (EU, LATAM, MENA), legal documents and consent forms must be presented in the user's local language to be legally binding.
3. **Support burden**: Non-English users generate disproportionate support tickets asking for clarification on KYC steps.
4. **Abandonment**: Users who cannot read the KYC forms abandon the process, reducing verification completion rates.

The platform already has a foundational i18n infrastructure (see `app/core/settings.py:1405-1409`): `i18n_default_locale` (default "en"), `i18n_supported_locales` ("en,es,fr"), and `i18n_enabled`/`i18n_rtl_enabled`/`i18n_admin_management_enabled` flags. However, this infrastructure is not wired into the KYC system at all.

### 1.2 Supported Languages

| Code | Language | Script Direction | Priority |
|------|----------|-----------------|----------|
| `en` | English | LTR | P0 (default) |
| `es` | Spanish | LTR | P0 |
| `fr` | French | LTR | P0 |
| `de` | German | LTR | P1 |
| `pt` | Portuguese | LTR | P1 |
| `zh` | Chinese (Simplified) | LTR | P1 |
| `ja` | Japanese | LTR | P1 |
| `ko` | Korean | LTR | P2 |
| `ar` | Arabic | RTL | P2 |
| `hi` | Hindi | LTR | P2 |

### 1.3 How It Works

1. The user's preferred language is determined from their profile `locale` field (e.g., `"es"`) or falls back to `Accept-Language` header, then to `i18n_default_locale` ("en").
2. KYC questionnaire prompts are served in the user's language via the translation lookup service.
3. Document signing legal notices include a localized preamble (e.g., "By signing, you agree to..." in the user's language).
4. Email/SMS notifications for KYC status changes are sent in the user's language.
5. The admin review interface shows the user's preferred language alongside the case, and document labels are translated for reference.
6. Translations are stored in DynamoDB and managed by admins via a translation management interface.
7. If a translation is unavailable for a given key+language, the system falls back to English.

### 1.4 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| User | I see KYC forms in my preferred language (Spanish) | Questionnaire prompts, labels, hints rendered in Spanish |
| User | I receive KYC notification emails in my language | Email subject and body in user's locale |
| User | I sign documents with legal notice in my language | Signature page shows localized legal notice |
| Admin | I see the user's language on the case detail | Case detail shows "Preferred language: es" |
| Admin | I manage translation strings via the admin UI | Admin can add/edit/delete translations per key per language |
| System | Missing translation falls back to English | If `es` translation missing for a key, `en` value is used |

---

## 2. Architecture & Data Flow

### 2.1 Request Flow Diagram

```
 User Browser                   Backend                          DynamoDB
 ────────────                   ───────                          ────────
      │                            │                                │
      │  GET /questionnaire/       │                                │
      │      {slug}/localized      │                                │
      │      ?lang=es              │                                │
      │ ─────────────────────────> │                                │
      │                            │  1. Lookup user profile        │
      │                            │     resolve_locale()           │
      │                            │ ─────────────────────────────> │
      │                            │  <── locale="es"               │
      │                            │                                │
      │                            │  2. Load questionnaire         │
      │                            │     (English template)         │
      │                            │ ─────────────────────────────> │
      │                            │  <── questionnaire object      │
      │                            │                                │
      │                            │  3. BatchGetItem translations  │
      │                            │     kyc_translations table     │
      │                            │     PK="es", SK=key_prefix     │
      │                            │ ─────────────────────────────> │
      │                            │  <── translated strings        │
      │                            │                                │
      │                            │  4. Merge translations into    │
      │                            │     questionnaire object       │
      │                            │                                │
      │  <── localized JSON        │                                │
      │      (Spanish strings)     │                                │
```

### 2.2 Translation Resolution Pipeline

```
  resolve_locale(user_profile, accept_language_header)
      │
      ▼
  ┌─────────────────────────────────┐
  │ 1. user_profile.locale set?     │── Yes ──> locale = profile.locale
  │                                 │
  │ 2. Accept-Language header?      │── Yes ──> parse & match to supported
  │                                 │
  │ 3. Fall back to default         │── Always ──> "en"
  └─────────────────────────────────┘
      │
      ▼
  translate(key, language)
      │
      ▼
  ┌─────────────────────────────────┐
  │ 1. Query kyc_translations       │
  │    PK=language, SK=key          │
  │    Found? ──> return value      │
  │                                 │
  │ 2. language != "en"?            │
  │    Query PK="en", SK=key        │
  │    Found? ──> return EN value   │
  │                                 │
  │ 3. Return fallback or key       │
  └─────────────────────────────────┘
```

### 2.3 Email Localization Flow

```
  KYC Status Change (e.g., case approved)
      │
      ▼
  Resolve user locale from profile
      │
      ▼
  localize_email(event="case_approved", language="es", variables={user_name, case_id})
      │
      ▼
  ┌──────────────────────────────────────┐
  │ Lookup "kyc.email.subject.case_approved" │
  │ Lookup "kyc.email.body.case_approved"    │
  │ for language="es"                        │
  │                                          │
  │ Substitute {{user_name}}, {{case_id}}    │
  │ in translated template                   │
  └──────────────────────────────────────┘
      │
      ▼
  send_alert_email(subject, body, recipient_email)
```

---

## 3. Current State Analysis

### 3.1 i18n Settings (see `app/core/settings.py:1405-1409`)

```python
i18n_default_locale: str = os.environ.get("I18N_DEFAULT_LOCALE", "en")
i18n_supported_locales: str = os.environ.get("I18N_SUPPORTED_LOCALES", "en,es,fr")
i18n_enabled: bool = os.environ.get("I18N_ENABLED", "1") not in ("0", "false", "False")
i18n_rtl_enabled: bool = os.environ.get("I18N_RTL_ENABLED", "1") not in ("0", "false", "False")
i18n_admin_management_enabled: bool = os.environ.get("I18N_ADMIN_MANAGEMENT_ENABLED", "1") not in ("0", "false", "False")
```

These settings exist but are not consumed by any KYC code path.

### 3.2 Questionnaire System (see `app/services/questionnaires_repository.py`)

The questionnaire repository stores questionnaire definitions with `title`, `description`, and question `label`/`hint` fields -- all stored as plain strings with no language dimension. The KYC integration (see `app/routers/kyc_cases.py:625`, `start_kyc_questionnaire`) binds a questionnaire to a case by slug, but the slug lookup returns the English-only version.

### 3.3 Alert/Email System (see `app/services/alerts.py`)

The `write_alert` function (see line 355) accepts `title` and `details` as plain strings. The `send_alert_email` function (see line 458) sends emails with hard-coded English subject/body patterns. Alert email templates (see `app/services/alert_email_templates.py`) have English-only templates.

### 3.4 Signature Packet Legal Notices

The `KycSignatureStatusOut` (see `app/contracts/kyc_cases_contract.py:160`) has a `legal_notice_version` field and `legal_notice_accepted` flag. The legal notice text is currently hard-coded in the frontend signing page, not served from the backend or localized.

### 3.5 User Profile Locale

User profiles can store a `locale` field (e.g., `"es"`, `"fr"`), but this field is not currently used by any KYC code path. The profile is accessible via `app/services/profile.py`.
<!-- NOTE: The ticket originally referenced app/services/user_profile.py which does not exist — the correct file is app/services/profile.py -->

---

## 4. Technical Design

### 4.1 New DynamoDB Table: `kyc_translations`

```
Table: kyc_translations
  PK: language_code (S)      — e.g. "es", "fr", "de"
  SK: key (S)                 — e.g. "kyc.questionnaire.title.identity_verification"

  Attributes:
    value (S)                 — Translated string
    context (S)               — Usage context hint for translators
    updated_by (S)            — Admin who last edited
    updated_at (N)            — Unix timestamp
    status (S)                — "published" | "draft" | "needs_review"

  GSI status-language-index:
    PK: status (S)
    SK: language_code (S)
    Projection: ALL
```

Add to `scripts/local-ddb-init.py`:

```python
TableDef(
    _resolve_table_name(S.kyc_translations_table_name, "kyc_translations"),
    partition_key="language_code",
    sort_key="key",
    gsis=[
        {"index_name": "status-language-index", "partition_key": "status", "sort_key": "language_code"},
    ],
),
```

### 4.2 Detailed DynamoDB Access Patterns

| # | Access Pattern | Table / GSI | PK | SK | Operation | Notes |
|---|---------------|-------------|----|----|-----------|-------|
| 1 | Get single translation | Main table | `language_code = "es"` | `key = "kyc.status.approved"` | GetItem | O(1) lookup |
| 2 | Batch get translations for a questionnaire | Main table | `language_code = "es"` | Multiple keys | BatchGetItem (up to 100) | Used by `translate_batch()` |
| 3 | List all translations for a language | Main table | `language_code = "es"` | `begins_with("kyc.")` | Query | For admin translation management |
| 4 | List translations by key prefix | Main table | `language_code = "es"` | `begins_with("kyc.questionnaire.")` | Query | Scoped listing |
| 5 | List translations by status | GSI status-language-index | `status = "needs_review"` | `language_code = "es"` | Query | Admin review workflow |
| 6 | Coverage comparison (EN vs target) | Main table | Two queries: `"en"` and target language | `begins_with("kyc.")` | Two Queries + set diff | Coverage report generation |
| 7 | Upsert translation | Main table | `language_code = "es"` | `key = "kyc.status.approved"` | PutItem | Admin creates/updates |
| 8 | Delete translation | Main table | `language_code = "es"` | `key = "kyc.status.approved"` | DeleteItem | Admin removes |

### 4.3 Translation Key Naming Convention

```
kyc.questionnaire.title.{slug}         — Questionnaire title
kyc.questionnaire.description.{slug}   — Questionnaire description
kyc.question.label.{question_id}       — Question label
kyc.question.hint.{question_id}        — Question hint text
kyc.status.{status}                    — Status display name (e.g., "Under Review")
kyc.email.subject.{event}             — Email subject line
kyc.email.body.{event}                — Email body template
kyc.legal_notice.{version}            — Signature legal notice text
kyc.requirement.{requirement_key}     — Missing requirement description
kyc.error.{error_code}               — Error message
kyc.ui.label.{component}.{field}      — UI label
```

### 4.4 New Service: `app/services/kyc_i18n.py`
<!-- NOTE: app/services/kyc_i18n.py does not exist yet — new implementation required -->

```python
class KycI18nService:
    def translate(self, *, key: str, language: str,
                  fallback: str | None = None) -> str:
        """Look up translation for key in language.
        Falls back to English, then to fallback string, then to key itself."""

    def translate_batch(self, *, keys: list[str],
                        language: str) -> dict[str, str]:
        """Batch translate multiple keys. Uses BatchGetItem for efficiency."""

    def set_translation(self, *, key: str, language: str, value: str,
                        context: str = "", admin_sub: str) -> dict[str, Any]:
        """Create or update a translation string."""

    def delete_translation(self, *, key: str, language: str) -> None:
        """Remove a translation."""

    def list_translations(self, *, language: str,
                          prefix: str | None = None,
                          status: str | None = None,
                          limit: int = 100) -> list[dict[str, Any]]:
        """List translations for a language, optionally filtered by key prefix."""

    def get_translation_coverage(self, *, language: str) -> dict[str, Any]:
        """Compare keys in target language against English (reference).
        Returns: total_keys, translated_keys, missing_keys, coverage_pct."""

    def resolve_locale(self, *, user_profile: dict[str, Any],
                       accept_language: str | None = None) -> str:
        """Determine effective locale: profile.locale > Accept-Language > default.
        Returns a supported locale code."""

    def localize_questionnaire(self, *, questionnaire: dict[str, Any],
                                language: str) -> dict[str, Any]:
        """Return questionnaire with title, description, question labels/hints
        translated to the target language."""

    def localize_email(self, *, event: str, language: str,
                       variables: dict[str, str]) -> tuple[str, str]:
        """Return (subject, body) for an email notification in the target language.
        Variables like {{user_name}} are substituted after translation."""

    def localize_legal_notice(self, *, version: str,
                               language: str) -> str:
        """Return legal notice text in the target language."""

    def _get_supported_locales(self) -> list[str]:
        """Parse S.i18n_supported_locales into list."""
```

### 4.5 Pydantic Model Definitions

```python
# app/models.py additions

from pydantic import BaseModel, Field
from typing import Optional, Dict, List, Any


class TranslationIn(BaseModel):
    """Request model for creating/updating a translation."""
    value: str = Field(..., min_length=1, max_length=10000,
                       description="Translated string value")
    context: str = Field(default="", max_length=500,
                         description="Usage context hint for translators")
    status: str = Field(default="published",
                        pattern=r"^(published|draft|needs_review)$")


class TranslationOut(BaseModel):
    """Response model for a single translation entry."""
    language_code: str
    key: str
    value: str
    context: str = ""
    status: str = "published"
    updated_by: Optional[str] = None
    updated_at: Optional[int] = None


class TranslationListOut(BaseModel):
    """Response model for listing translations."""
    items: List[TranslationOut] = Field(default_factory=list)
    coverage: Optional[Dict[str, Any]] = None
    total: int = 0


class TranslationCoverageOut(BaseModel):
    """Response model for translation coverage."""
    language_code: str
    total_keys: int = 0
    translated_keys: int = 0
    missing_keys: int = 0
    coverage_pct: float = 0.0


class CoverageReportOut(BaseModel):
    """Response model for multi-language coverage report."""
    languages: Dict[str, TranslationCoverageOut] = Field(default_factory=dict)


class LocalizedQuestionnaireOut(BaseModel):
    """Response model for a localized questionnaire."""
    questionnaire: Dict[str, Any]
    language: str
    fallback_keys: List[str] = Field(default_factory=list,
                                      description="Keys that fell back to English")


class LocalizedLegalNoticeOut(BaseModel):
    """Response model for a localized legal notice."""
    text: str
    language: str
    version: str
    is_fallback: bool = False


class TranslationBulkImportIn(BaseModel):
    """Request model for bulk translation import."""
    translations: Dict[str, str] = Field(
        ..., description="Map of key -> value",
        max_length=500
    )
    language: str = Field(..., min_length=2, max_length=5)
    status: str = Field(default="draft",
                        pattern=r"^(published|draft|needs_review)$")


class TranslationBulkImportOut(BaseModel):
    """Response model for bulk import results."""
    imported: int = 0
    skipped: int = 0
    errors: List[str] = Field(default_factory=list)
```

### 4.6 Router Endpoints

Add to a new router `app/routers/kyc_i18n.py`:

```python
router = APIRouter(prefix="/v1/kyc/i18n", tags=["kyc-i18n"])

# User-facing (require_ui_session)
GET /translations/{language}?prefix={prefix}
  — Get all published translations for a language, optionally by prefix
  — Response: { "translations": { key: value, ... } }

GET /questionnaire/{slug}/localized?lang={lang}
  — Get a questionnaire with all text translated
  — Response: { "questionnaire": {...}, "language": str }

GET /legal-notice/{version}?lang={lang}
  — Get localized legal notice text
  — Response: { "text": str, "language": str }

# Admin (require_admin_session)
GET /admin/translations/{language}?prefix={prefix}&status={status}
  — List translations with edit metadata
  — Response: { "items": [...], "coverage": {...} }

PUT /admin/translations/{language}/{key}
  — Set or update a translation
  — Body: { "value": str, "context": str }

DELETE /admin/translations/{language}/{key}
  — Delete a translation

GET /admin/coverage
  — Translation coverage report across all languages
  — Response: { "languages": { "es": { total: N, translated: N, pct: 0.85 }, ... } }

POST /admin/translations/{language}/bulk-import
  — Import multiple translations at once
  — Body: { "translations": { key: value, ... }, "status": "draft" }
  — Response: { "imported": N, "skipped": N, "errors": [...] }

GET /admin/translations/{language}/export
  — Export all translations for a language as JSON
  — Response: { "language": str, "translations": { key: value, ... } }
```

### 4.7 API Request/Response Examples

**PUT /admin/translations/es/kyc.status.approved**

Request:
```json
{
  "value": "Aprobado",
  "context": "KYC case status label shown to users when their verification is approved"
}
```

Response (200):
```json
{
  "language_code": "es",
  "key": "kyc.status.approved",
  "value": "Aprobado",
  "context": "KYC case status label shown to users when their verification is approved",
  "status": "published",
  "updated_by": "root.admin@testdev.local",
  "updated_at": 1748520000
}
```

**GET /translations/es?prefix=kyc.status**

Response (200):
```json
{
  "translations": {
    "kyc.status.approved": "Aprobado",
    "kyc.status.rejected": "Rechazado",
    "kyc.status.under_review": "En Revision",
    "kyc.status.submitted": "Enviado",
    "kyc.status.draft": "Borrador"
  }
}
```

**GET /questionnaire/identity_verification/localized?lang=es**

Response (200):
```json
{
  "questionnaire": {
    "slug": "identity_verification",
    "title": "Verificacion de Identidad",
    "description": "Complete este formulario para verificar su identidad.",
    "questions": [
      {
        "question_id": "q_001",
        "label": "Nombre completo como aparece en su documento",
        "hint": "Ingrese su nombre legal completo",
        "type": "text",
        "required": true
      },
      {
        "question_id": "q_002",
        "label": "Fecha de nacimiento",
        "hint": "",
        "type": "date",
        "required": true
      }
    ]
  },
  "language": "es",
  "fallback_keys": []
}
```

**GET /legal-notice/v1?lang=fr**

Response (200):
```json
{
  "text": "En signant ce document, vous attestez que les informations fournies sont exactes et completes. Vous autorisez la plateforme a verifier votre identite conformement a notre politique de confidentialite.",
  "language": "fr",
  "version": "v1",
  "is_fallback": false
}
```

**GET /admin/coverage**

Response (200):
```json
{
  "languages": {
    "es": {
      "language_code": "es",
      "total_keys": 85,
      "translated_keys": 72,
      "missing_keys": 13,
      "coverage_pct": 0.847
    },
    "fr": {
      "language_code": "fr",
      "total_keys": 85,
      "translated_keys": 68,
      "missing_keys": 17,
      "coverage_pct": 0.8
    },
    "de": {
      "language_code": "de",
      "total_keys": 85,
      "translated_keys": 0,
      "missing_keys": 85,
      "coverage_pct": 0.0
    }
  }
}
```

**POST /admin/translations/es/bulk-import**

Request:
```json
{
  "translations": {
    "kyc.status.approved": "Aprobado",
    "kyc.status.rejected": "Rechazado",
    "kyc.status.under_review": "En Revision"
  },
  "language": "es",
  "status": "draft"
}
```

Response (200):
```json
{
  "imported": 3,
  "skipped": 0,
  "errors": []
}
```

### 4.8 Error Handling Matrix

| Scenario | HTTP Status | Error Code | Error Message | Recovery Action |
|----------|-------------|------------|---------------|-----------------|
| Translation key not found | 200 (fallback) | N/A | Falls back to English silently | No action needed; fallback is expected behavior |
| Language code not in supported list | 400 | `unsupported_locale` | "Language 'xx' is not supported. Supported: en, es, fr, de, pt, zh, ja, ko, ar, hi" | Use a supported language code |
| Admin PUT with empty value | 422 | `validation_error` | "value: ensure this value has at least 1 character" | Provide non-empty translation value |
| Non-admin attempts PUT/DELETE | 403 | `forbidden` | "Admin session required" | Use admin credentials |
| Translation key too long (>500 chars) | 422 | `validation_error` | "key: ensure this value has at most 500 characters" | Shorten the translation key |
| Bulk import exceeds 500 entries | 422 | `validation_error` | "translations: ensure this value has at most 500 items" | Split into multiple requests |
| Questionnaire slug not found | 404 | `not_found` | "Questionnaire not found" | Verify the questionnaire slug |
| Legal notice version not found | 404 | `not_found` | "Legal notice version not found" | Verify the version string |
| Database timeout during batch get | 500 | `internal_error` | "Translation service temporarily unavailable" | Retry after a few seconds |
| i18n feature disabled | 400 | `feature_disabled` | "Internationalization is currently disabled" | Enable I18N_ENABLED in settings |

### 4.9 Integration Points

**Questionnaire localization**: Modify `start_kyc_questionnaire` in `app/routers/kyc_cases.py` (see line 625) to accept an optional `?lang=` parameter. Before returning the questionnaire to the user, pass it through `kyc_i18n_svc.localize_questionnaire()`.

**Email notification localization**: Modify alert-sending code paths in KYC (case status transitions, decision notifications) to resolve the user's locale and call `kyc_i18n_svc.localize_email()` before `send_alert_email()`.

**Admin case detail**: Extend `_build_admin_case_detail` (line 345) to include `applicant_language` derived from the user's profile locale. The admin UI shows this alongside the case.

**Document signing legal notice**: The frontend signing page fetches the localized legal notice via `GET /v1/kyc/i18n/legal-notice/{version}?lang={lang}` instead of using a hard-coded English string.

### 4.10 Frontend Changes

**Translation fetching**: Add a `useKycTranslations(lang)` React Query hook that fetches and caches translations for the user's locale. Components use `t("kyc.status.under_review")` helper to look up translated strings.

**Admin translation management**: Add a translation editor panel in the admin area:
- Language selector dropdown
- Key list with search/filter
- Inline editing of translation values
- Coverage progress bars per language
- Bulk import/export (JSON format)

### 4.11 Frontend Component Tree

```
KycTranslationsPage (admin)
├── PageHeader
│   ├── Title: "KYC Translations"
│   └── Actions: [Export JSON] [Import JSON]
├── LanguageSelector (dropdown)
│   └── Options: en, es, fr, de, pt, zh, ja, ko, ar, hi
├── CoverageBar
│   └── Progress bar showing translated_keys / total_keys
├── TranslationFilters
│   ├── SearchInput (filter by key prefix)
│   ├── StatusFilter (published | draft | needs_review | all)
│   └── CategoryFilter (status | questionnaire | email | legal | ui)
└── TranslationTable
    ├── TableHeader: [Key, English Value, Translation, Status, Actions]
    └── TableRow (for each translation)
        ├── Key (monospace, truncated with tooltip)
        ├── English reference value (readonly)
        ├── TranslationInput (inline editable textarea)
        ├── StatusBadge (published=green, draft=yellow, needs_review=orange)
        └── Actions: [Save] [Delete]
```

**Props interfaces**:

```typescript
interface KycTranslationsPageProps {}

interface LanguageSelectorProps {
  value: string;
  onChange: (lang: string) => void;
  languages: { code: string; name: string }[];
}

interface CoverageBarProps {
  total: number;
  translated: number;
  language: string;
}

interface TranslationRowProps {
  translationKey: string;
  englishValue: string;
  translatedValue: string;
  status: "published" | "draft" | "needs_review";
  onSave: (value: string, status: string) => void;
  onDelete: () => void;
}

interface TranslationTableProps {
  items: TranslationOut[];
  englishMap: Record<string, string>;
  onSave: (key: string, value: string, status: string) => void;
  onDelete: (key: string) => void;
  isLoading: boolean;
}
```

**Components:**

- `frontend/src/pages/admin/KycTranslationsPage.tsx` — Translation management
- `frontend/src/hooks/useKycTranslations.ts` — Translation lookup hook
- `frontend/src/api/endpoints/kyc-i18n.ts` — API client

**Route in `App.tsx`:**

```tsx
const KycTranslationsPage = lazy(() => import("@/pages/admin/KycTranslationsPage"));
<Route path="admin/kyc/translations" element={<KycTranslationsPage />} />
```

### 4.12 Seed Data

The `scripts/local-ddb-seed.py` script will be extended to seed baseline translations for `es` and `fr` covering the most critical keys (status names, common questionnaire labels, legal notice). This ensures dev/test environments have enough translations to exercise the localization code paths.

---

## 5. Observability

### 5.1 Metrics

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `kyc_translation_lookup_total` | Counter | `language`, `outcome=(hit|miss|fallback)` | Translation lookup results |
| `kyc_translation_batch_size` | Histogram | `language` | Number of keys per batch translate call |
| `kyc_translation_coverage_pct` | Gauge | `language` | Current coverage percentage per language |
| `kyc_localized_email_sent_total` | Counter | `language`, `event_type` | Localized emails dispatched |
| `kyc_translation_admin_edits_total` | Counter | `language`, `action=(create|update|delete)` | Admin translation modifications |

### 5.2 Logging

| Log Event | Level | Fields | Trigger |
|-----------|-------|--------|---------|
| `translation.fallback` | WARNING | `key`, `requested_language`, `fallback_language` | Requested translation missing, fell back to English |
| `translation.missing_all` | WARNING | `key`, `requested_language` | Translation missing in all languages (using key as display) |
| `translation.batch_partial` | INFO | `language`, `requested_count`, `found_count` | Batch translate had partial coverage |
| `translation.admin_edit` | INFO | `admin_sub`, `language`, `key`, `action` | Admin creates/updates/deletes a translation |
| `translation.bulk_import` | INFO | `admin_sub`, `language`, `imported_count`, `error_count` | Bulk import completed |

### 5.3 Alerting

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| Low translation coverage | Coverage below 60% for any P0 language (es, fr) | Warning | Notify admin to add missing translations |
| High fallback rate | > 30% of translation lookups fall back to English in 1 hour | Warning | Check for missing translations in affected language |
| Translation service errors | > 5 DynamoDB errors in translation lookups in 5 minutes | Critical | Check DDB table health and provisioned capacity |

---

## 6. Rollout Plan

### 6.1 Feature Flags

| Flag | Environment Variable | Default | Description |
|------|---------------------|---------|-------------|
| `I18N_ENABLED` | `I18N_ENABLED` | `true` | Master switch for all i18n features |
| `I18N_KYC_LOCALIZATION_ENABLED` | `I18N_KYC_LOCALIZATION_ENABLED` | `false` | Enable KYC-specific localization (off by default until translations seeded) |
| `I18N_RTL_ENABLED` | `I18N_RTL_ENABLED` | `true` | Enable RTL language support (Arabic) |
| `I18N_ADMIN_MANAGEMENT_ENABLED` | `I18N_ADMIN_MANAGEMENT_ENABLED` | `true` | Enable admin translation management UI |

### 6.2 Phased Rollout

**Phase 1: Infrastructure (Days 1-2)**
- Create `kyc_translations` DDB table
- Implement `KycI18nService` with translate/batch/resolve
- Add admin CRUD endpoints
- Seed es/fr baseline translations
- Feature flag: `I18N_KYC_LOCALIZATION_ENABLED=false`

**Phase 2: Admin UI (Days 3-4)**
- Build KycTranslationsPage
- Implement bulk import/export
- Coverage reporting
- Internal testing by admins to populate translations

**Phase 3: User-facing localization (Days 5-6)**
- Wire questionnaire localization
- Wire email notification localization
- Wire legal notice localization
- Feature flag: `I18N_KYC_LOCALIZATION_ENABLED=true` for 10% of users

**Phase 4: Full rollout (Days 7-8)**
- Ramp to 100% of users
- Monitor fallback rates and coverage metrics
- Address any edge cases (RTL layout issues, text overflow)

---

## 7. Performance Considerations

### 7.1 Latency Targets

| Operation | Target | Strategy |
|-----------|--------|----------|
| Single translation lookup | < 5ms | DDB GetItem with consistent reads |
| Batch translate (50 keys) | < 20ms | DDB BatchGetItem (single round trip) |
| Questionnaire localization | < 30ms | Batch translate all keys + merge |
| Coverage report (all languages) | < 200ms | Query per language (parallelized) |

### 7.2 Caching Strategy

| Cache Layer | TTL | Scope | Invalidation |
|-------------|-----|-------|-------------|
| In-memory service cache | 5 minutes | Per-language translation map | On admin PUT/DELETE, invalidate affected language |
| React Query (frontend) | 10 minutes | Per `useKycTranslations(lang)` hook | Manual invalidation via query key |
| HTTP cache headers | 60 seconds | GET /translations/{language} | `Cache-Control: public, max-age=60` |

### 7.3 Pagination

- `list_translations` uses DDB Query with `Limit` parameter and cursor-based pagination via `LastEvaluatedKey`.
- Default limit: 100 items per page.
- Maximum limit: 500 items per page.
- Coverage report computes on the full key set (no pagination needed -- typically < 500 keys).

---

## 8. E2E Test Plan

**Test file**: `frontend/e2e/kyc-i18n.spec.ts`
**Total**: ~24 tests across 6 sections (225-230)

### Section 225: Translation CRUD API (5 tests)

```typescript
test("225.1 Admin creates a translation for key in Spanish", async ({ page }) => {
  // PUT /v1/kyc/i18n/admin/translations/es/kyc.status.approved
  // Body: { value: "Aprobado", context: "KYC case status" }
  // Expect 200
});

test("225.2 Admin lists translations for a language with prefix filter", async ({ page }) => {
  // GET /admin/translations/es?prefix=kyc.status
  // Expect items array with the created translation
});

test("225.3 Get translation for missing key falls back to English", async ({ page }) => {
  // Create English translation, do NOT create Spanish
  // GET /translations/es?prefix=kyc.test_fallback
  // Expect English value returned
});

test("225.4 Admin deletes a translation", async ({ page }) => {
  // DELETE /admin/translations/es/kyc.status.approved
  // GET -> key no longer in results
});

test("225.5 Non-admin cannot modify translations", async ({ page }) => {
  // Alice (USER) PUT translation -> 403
});
```

### Section 226: Questionnaire & Legal Notice Localization (4 tests)

```typescript
test("226.1 Questionnaire returned in user's locale", async ({ page }) => {
  // Seed Spanish translations for questionnaire title and labels
  // GET /questionnaire/{slug}/localized?lang=es
  // Expect title and labels in Spanish
});

test("226.2 Legal notice returned in French", async ({ page }) => {
  // Seed French legal notice translation
  // GET /legal-notice/v1?lang=fr
  // Expect French text
});

test("226.3 Unsupported locale falls back to English", async ({ page }) => {
  // GET /questionnaire/{slug}/localized?lang=xx
  // Expect English content (fallback)
});

test("226.4 Coverage report shows percentage per language", async ({ page }) => {
  // Seed some es translations, none for de
  // GET /admin/coverage
  // Expect es.pct > 0, de.pct == 0
});
```

### Section 227: Translation Admin UI (3 tests)

```typescript
test("227.1 Admin sees translation editor with language selector", async ({ page }) => {
  // Navigate to /admin/kyc/translations
  // Expect language dropdown, key list table
});

test("227.2 Admin edits a translation inline", async ({ page }) => {
  // Click on a key row, modify value, save
  // Expect updated value in the list
});

test("227.3 Coverage progress bar reflects translation completeness", async ({ page }) => {
  // Expect progress indicator showing coverage percentage for selected language
});
```

### Section 228: Bulk Import/Export API (4 tests)

```typescript
test("228.1 Admin bulk imports translations for a language", async ({ page }) => {
  // POST /admin/translations/es/bulk-import with 5 key-value pairs
  // Expect imported=5, skipped=0
});

test("228.2 Bulk import with duplicate keys updates existing", async ({ page }) => {
  // Import same keys with different values
  // GET translations -> values are updated
});

test("228.3 Export translations returns complete JSON", async ({ page }) => {
  // GET /admin/translations/es/export
  // Expect JSON map with all keys for the language
});

test("228.4 Bulk import with empty value skips entry", async ({ page }) => {
  // POST bulk-import with one empty value
  // Expect skipped=1
});
```

### Section 229: Edge Cases & Fallback Behavior (4 tests)

```typescript
test("229.1 Translation with HTML entities is stored safely", async ({ page }) => {
  // PUT translation with value containing <script> tags
  // GET -> value is stored as-is (frontend will escape)
  // Verify no XSS in admin list rendering
});

test("229.2 Very long translation value accepted up to 10000 chars", async ({ page }) => {
  // PUT translation with 10000-char legal notice text
  // Expect 200
});

test("229.3 Translation value exceeding 10000 chars rejected", async ({ page }) => {
  // PUT with 10001-char value -> 422
});

test("229.4 Concurrent admin edits last-write-wins", async ({ page }) => {
  // Two rapid PUTs to same key with different values
  // GET -> returns the last written value
});
```

### Section 230: Locale Resolution & RTL (4 tests)

```typescript
test("230.1 Accept-Language header used when profile locale not set", async ({ page }) => {
  // Set Alice profile locale to null
  // Send request with Accept-Language: fr
  // Expect French translations returned
});

test("230.2 Profile locale takes precedence over Accept-Language", async ({ page }) => {
  // Set Alice profile locale to 'es'
  // Send request with Accept-Language: fr
  // Expect Spanish translations returned
});

test("230.3 Unsupported Accept-Language falls back to default", async ({ page }) => {
  // Send request with Accept-Language: zz
  // Expect English translations returned
});

test("230.4 RTL language (Arabic) includes direction metadata", async ({ page }) => {
  // Seed Arabic translation
  // GET questionnaire localized with lang=ar
  // Expect response or questionnaire to indicate RTL direction
});
```

---

## 9. Security Considerations

### 9.1 XSS Prevention

Translation values are stored as plain text and rendered by React JSX, which auto-escapes HTML. The admin UI uses standard React rendering, so malicious HTML in translation values is rendered as literal text, not executed. No `dangerouslySetInnerHTML` is used for translation display.

### 9.2 Access Control

- Read endpoints (translations, questionnaire, legal notice) require `require_ui_session` -- any authenticated user can read translations.
- Write endpoints (PUT, DELETE, bulk-import) require `require_admin_session` -- only admins can modify translations.
- Coverage report is admin-only.

### 9.3 Input Validation

- Translation values: max 10,000 characters (accommodates legal notice text).
- Translation keys: max 500 characters, validated to start with `kyc.`.
- Language codes: validated against `i18n_supported_locales` setting.
- Bulk import: max 500 entries per request.

---

## 10. File Change Summary

| File | Change Type | Description |
|------|-------------|-------------|
| `app/services/kyc_i18n.py` | **New** | Translation lookup, localization, coverage reporting |
| `app/routers/kyc_i18n.py` | **New** | Translation CRUD, localized questionnaire/legal notice endpoints |
| `app/core/settings.py` | Modify | Add `kyc_translations_table_name` setting |
| `app/core/tables.py` | Modify | Add `kyc_translations` table handle |
| `app/main.py` | Modify | Register `kyc_i18n_router` |
| `app/models.py` | Modify | Add translation request/response Pydantic models |
| `scripts/local-ddb-init.py` | Modify | Add `kyc_translations` table definition |
| `scripts/local-ddb-seed.py` | Modify | Seed baseline es/fr translations |
| `app/routers/kyc_cases.py` | Modify | Add `?lang=` param to questionnaire endpoint; localize emails |
| `app/services/alerts.py` | Modify | Accept `locale` param in email sending |
| `app/services/alert_email_templates.py` | Modify | Support localized template lookup |
| `frontend/src/api/endpoints/kyc-i18n.ts` | **New** | API client functions |
| `frontend/src/hooks/useKycTranslations.ts` | **New** | Translation hook for components |
| `frontend/src/pages/admin/KycTranslationsPage.tsx` | **New** | Translation management UI |
| `frontend/src/App.tsx` | Modify | Add `/admin/kyc/translations` route |
| `frontend/e2e/kyc-i18n.spec.ts` | **New** | 24 E2E tests across sections 225-230 |

---

## Codebase References

| Reference | File | Line(s) | Status |
|-----------|------|---------|--------|
| i18n settings | `app/core/settings.py` | 1405-1409 | Exists |
| Translations table | `app/core/settings.py` | 1404 | Exists (`translations_table_name`) |
| `start_kyc_questionnaire()` | `app/routers/kyc_cases.py` | 625 | Exists |
| `KycSignatureStatusOut` | `app/contracts/kyc_cases_contract.py` | 160 | Exists |
| `write_alert()` | `app/services/alerts.py` | 355 | Exists |
| `send_alert_email()` | `app/services/alerts.py` | 458 | Exists |
| Alert email templates | `app/services/alert_email_templates.py` | -- | Exists |
| Questionnaire repository | `app/services/questionnaires_repository.py` | -- | Exists |
| Profile service | `app/services/profile.py` | -- | Exists (ticket incorrectly references `user_profile.py`) |
| `app/services/kyc_i18n.py` | -- | -- | Does NOT exist — new implementation required |
| `app/routers/kyc_i18n.py` | -- | -- | Does NOT exist — new router required |

---

## Testing Strategy

### Unit Tests (`tests/test_kyc_i18n.py`)
**Framework**: pytest + moto (DynamoDB/S3 mock)

| # | Test Function | What It Verifies |
|---|--------------|-----------------|
| 1 | `test_translate_returns_value_for_language` | Translate returns value for language |
| 2 | `test_translate_falls_back_to_english` | Translate falls back to english |
| 3 | `test_translate_batch_multiple_keys` | Translate batch multiple keys |
| 4 | `test_set_translation_stores_in_ddb` | Set translation stores in ddb |
| 5 | `test_delete_translation_removes` | Delete translation removes |
| 6 | `test_coverage_report_calculates_pct` | Coverage report calculates pct |
| 7 | `test_resolve_locale_profile_first` | Resolve locale profile first |
| 8 | `test_resolve_locale_accept_language_fallback` | Resolve locale accept language fallback |
| 9 | `test_localize_questionnaire_replaces_labels` | Localize questionnaire replaces labels |
| 10 | `test_localize_email_substitutes_variables` | Localize email substitutes variables |

### Integration Tests

1. Full endpoint flow: create, read, update, delete with FastAPI TestClient + mocked DDB
2. Auth enforcement: verify 401 without session, 403 for wrong role
3. Validation: 422 for malformed requests, 404 for missing resources
4. Cross-service: verify DDB writes are consistent across tables
5. SSE/real-time: verify events published on mutations (where applicable)

### E2E Tests (`frontend/e2e/kyc-i18n.spec.ts`)
**Auth**: `injectAuth(page, identity)` for cookie auth; `apiPost(page, identity, path, body)` for CSRF-protected requests.

**Total**: ~24 tests covering API CRUD, auth enforcement (401/403), validation (422), negative cases (404/409), and UI interactions.

**Negative/Edge Tests**: 401 without auth, 403 for wrong role, 404 for missing resources, 409 for conflicts, 422 for validation errors.

### Test Data Requirements
- Test users: Alice (USER), Bob (USER), Root (ROOT), Charlie (ADMIN) from `e2e_admin_session_setup.py`
- Session seeding: `python3 e2e_admin_session_setup.py` before test run

### CI/Pipeline
- Feature flags: `I18N_KYC_LOCALIZATION_ENABLED=true`, `I18N_ENABLED=true`
- Tests run serially (single Playwright worker, `workers: 1`)
- Retry safety: 1 retry configured; tests use unique timestamps (`Date.now()`) for isolation
- Run: `cd frontend && npx playwright test e2e/<spec-file>`

---

## Dependencies & Merge Safety

### Depends On

| Ticket | What It Provides | Hard/Soft |
|--------|-----------------|-----------|
| KYC-017 | Document Signing Template Library for template localization | Soft |
| KYC-013 | User Self-Service Portal for localized UI | Soft |

### Depended On By

No downstream dependents identified.

### Merge Strategy
**Feature-flag-gated -- I18N_KYC_LOCALIZATION_ENABLED=false by default. Translation infrastructure is additive; no existing code modified until flag enabled.**

### Merge Checklist
- [ ] Feature flags configured in `.env.local`: I18N_KYC_LOCALIZATION_ENABLED=true, I18N_ENABLED=true
- [ ] Service file created/modified: `app/services/kyc_i18n.py`
- [ ] No endpoint prefix conflicts with existing routers
- [ ] E2E tests pass: `cd frontend && npx playwright test frontend/e2e/kyc-i18n.spec.ts`
- [ ] Unit tests pass: `.venv/bin/pytest tests/test_kyc_i18n.py`
