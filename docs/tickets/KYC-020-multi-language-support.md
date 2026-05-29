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

The platform already has a foundational i18n infrastructure (`app/core/settings.py`, lines 1405-1409): `i18n_default_locale` (default "en"), `i18n_supported_locales` ("en,es,fr"), and `i18n_enabled`/`i18n_rtl_enabled`/`i18n_admin_management_enabled` flags. However, this infrastructure is not wired into the KYC system at all.

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

## 2. Current State Analysis

### 2.1 i18n Settings (`app/core/settings.py`, lines 1405-1409)

```python
i18n_default_locale: str = os.environ.get("I18N_DEFAULT_LOCALE", "en")
i18n_supported_locales: str = os.environ.get("I18N_SUPPORTED_LOCALES", "en,es,fr")
i18n_enabled: bool = os.environ.get("I18N_ENABLED", "1") not in ("0", "false", "False")
i18n_rtl_enabled: bool = os.environ.get("I18N_RTL_ENABLED", "1") not in ("0", "false", "False")
i18n_admin_management_enabled: bool = os.environ.get("I18N_ADMIN_MANAGEMENT_ENABLED", "1") not in ("0", "false", "False")
```

These settings exist but are not consumed by any KYC code path.

### 2.2 Questionnaire System (`app/services/questionnaires_repository.py`)

The questionnaire repository stores questionnaire definitions with `title`, `description`, and question `label`/`hint` fields -- all stored as plain strings with no language dimension. The KYC integration (`app/routers/kyc_cases.py`, line 625, `start_kyc_questionnaire`) binds a questionnaire to a case by slug, but the slug lookup returns the English-only version.

### 2.3 Alert/Email System (`app/services/alerts.py`)

The `write_alert` function (line 355) accepts `title` and `details` as plain strings. The `send_alert_email` function (line 458) sends emails with hard-coded English subject/body patterns. Alert email templates (`app/services/alert_email_templates.py`) have English-only templates.

### 2.4 Signature Packet Legal Notices

The `KycSignatureStatusOut` (`app/contracts/kyc_cases_contract.py`, line 160) has a `legal_notice_version` field and `legal_notice_accepted` flag. The legal notice text is currently hard-coded in the frontend signing page, not served from the backend or localized.

### 2.5 User Profile Locale

User profiles can store a `locale` field (e.g., `"es"`, `"fr"`), but this field is not currently used by any KYC code path. The profile is accessible via `app/services/user_profile.py`.

---

## 3. Technical Design

### 3.1 New DynamoDB Table: `kyc_translations`

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

### 3.2 Translation Key Naming Convention

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

### 3.3 New Service: `app/services/kyc_i18n.py`

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

### 3.4 Router Endpoints

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
```

### 3.5 Integration Points

**Questionnaire localization**: Modify `start_kyc_questionnaire` in `app/routers/kyc_cases.py` (line 625) to accept an optional `?lang=` parameter. Before returning the questionnaire to the user, pass it through `kyc_i18n_svc.localize_questionnaire()`.

**Email notification localization**: Modify alert-sending code paths in KYC (case status transitions, decision notifications) to resolve the user's locale and call `kyc_i18n_svc.localize_email()` before `send_alert_email()`.

**Admin case detail**: Extend `_build_admin_case_detail` (line 345) to include `applicant_language` derived from the user's profile locale. The admin UI shows this alongside the case.

**Document signing legal notice**: The frontend signing page fetches the localized legal notice via `GET /v1/kyc/i18n/legal-notice/{version}?lang={lang}` instead of using a hard-coded English string.

### 3.6 Frontend Changes

**Translation fetching**: Add a `useKycTranslations(lang)` React Query hook that fetches and caches translations for the user's locale. Components use `t("kyc.status.under_review")` helper to look up translated strings.

**Admin translation management**: Add a translation editor panel in the admin area:
- Language selector dropdown
- Key list with search/filter
- Inline editing of translation values
- Coverage progress bars per language
- Bulk import/export (JSON format)

**Components:**

- `frontend/src/pages/admin/KycTranslationsPage.tsx` — Translation management
- `frontend/src/hooks/useKycTranslations.ts` — Translation lookup hook
- `frontend/src/api/endpoints/kyc-i18n.ts` — API client

**Route in `App.tsx`:**

```tsx
const KycTranslationsPage = lazy(() => import("@/pages/admin/KycTranslationsPage"));
<Route path="admin/kyc/translations" element={<KycTranslationsPage />} />
```

### 3.7 Seed Data

The `scripts/local-ddb-seed.py` script will be extended to seed baseline translations for `es` and `fr` covering the most critical keys (status names, common questionnaire labels, legal notice). This ensures dev/test environments have enough translations to exercise the localization code paths.

---

## 4. E2E Test Plan

**Test file**: `frontend/e2e/kyc-i18n.spec.ts`
**Total**: ~12 tests across 3 sections (225-227)

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

---

## 5. File Change Summary

| File | Change Type | Description |
|------|-------------|-------------|
| `app/services/kyc_i18n.py` | **New** | Translation lookup, localization, coverage reporting |
| `app/routers/kyc_i18n.py` | **New** | Translation CRUD, localized questionnaire/legal notice endpoints |
| `app/core/settings.py` | Modify | Add `kyc_translations_table_name` setting |
| `app/core/tables.py` | Modify | Add `kyc_translations` table handle |
| `app/main.py` | Modify | Register `kyc_i18n_router` |
| `scripts/local-ddb-init.py` | Modify | Add `kyc_translations` table definition |
| `scripts/local-ddb-seed.py` | Modify | Seed baseline es/fr translations |
| `app/routers/kyc_cases.py` | Modify | Add `?lang=` param to questionnaire endpoint; localize emails |
| `app/services/alerts.py` | Modify | Accept `locale` param in email sending |
| `app/services/alert_email_templates.py` | Modify | Support localized template lookup |
| `frontend/src/api/endpoints/kyc-i18n.ts` | **New** | API client functions |
| `frontend/src/hooks/useKycTranslations.ts` | **New** | Translation hook for components |
| `frontend/src/pages/admin/KycTranslationsPage.tsx` | **New** | Translation management UI |
| `frontend/src/App.tsx` | Modify | Add `/admin/kyc/translations` route |
| `frontend/e2e/kyc-i18n.spec.ts` | **New** | 12 E2E tests across sections 225-227 |
