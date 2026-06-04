# PLATFORM-003: Multi-Language / i18n Support — Investigation & Implementation Write-up

> Type: feature | Priority: Medium | Status: Partially implemented (backend i18n module + router exist; frontend not yet migrated)

## 1. Summary & Classification

Every user-facing string in the platform is currently hardcoded in English: navigation labels in `frontend/src/components/layout/Sidebar.tsx`, form placeholders, toast messages, error strings in `HTTPException` calls, and alert titles in `write_alert()`. There is no locale detection, no translation key system, and no right-to-left layout support. PLATFORM-003 introduces a `react-i18next`-based frontend translation layer with lazy-loaded JSON bundles, a backend `translate()` function backed by per-locale JSON files, a `locale` field on user profiles, and an admin translation management UI with completeness tracking. The backend i18n module and router already exist; the largest remaining work is migrating ~200 React component files to replace hardcoded strings with `t()` calls.

- **Type**: Feature
- **Priority**: Medium
- **User personas affected**: non-English-speaking users (primary beneficiaries), creators with international audiences, platform admins (translation management)
- **Cross-references**: SECOPS-007 (dev/prod parity — translations served from files in both modes; DDB Local in dev for admin overrides)

---

## 2. Current-State Investigation

### 2.1 Backend i18n module (exists)

`app/i18n/__init__.py` exists and exports:
- `translate(key, locale, **kwargs)` — key lookup with fallback to English and `str.format()` interpolation
- `get_user_locale_from_request(request)` — reads from `request.state.auth_context["locale"]` or `Accept-Language` header

Translation JSON files live under `app/i18n/translations/`: `en.json`, `es.json`, `fr.json` are confirmed present.

`app/routers/i18n.py` is registered in `app/main.py` (line 210, 656) with prefix `/ui/i18n`. It exposes:
- `GET /ui/i18n/locales` — list available locales
- `GET /ui/i18n/translations/{locale}` — serve merged (file + DDB override) translations
- `GET /ui/i18n/user-locale` — read user's locale from profile
- `POST /ui/i18n/save-locale` — persist locale choice to profile

Settings at `app/core/settings.py` (lines 1839, 1842): `translations_table_name`, `i18n_enabled`, plus confirmed entries for `i18n_default_locale`, `i18n_supported_locales`, `i18n_rtl_enabled`, `i18n_admin_management_enabled`.

### 2.2 Frontend (not yet migrated)

`react-helmet-async` is installed (`frontend/package.json:59`) but `react-i18next`, `i18next`, `i18next-browser-languagedetector`, and `i18next-http-backend` are **not** present in `package.json`. No `useTranslation()` call exists in any source file. No `i18n/config.ts` has been created.

`frontend/src/components/layout/Sidebar.tsx` (lines 68–137): all navigation labels are English string literals. Same in `AppShell.tsx`, `MobileNav.tsx`, and all page components.

Date formatting uses ad-hoc `toLocaleDateString()` without locale parameter. Currency uses template literals (`$${(cents/100).toFixed(2)}`).

No `dir="rtl"` logic exists anywhere in the frontend.

### 2.3 Profile data model

`empty_profile()` in `app/services/profile.py` (line 189): the `locale` field does **not** currently exist. The existing `languages` field stores an array of spoken language strings (e.g., `["English", "Spanish"]`) — a different concept than UI locale. Adding a `locale` field (type S, IETF BCP 47 tag) requires only a schema-less DDB attribute addition; `normalize_profile_payload()` (line 146) and `apply_profile_update()` (line 294) need updating to accept and persist it.

### 2.4 DDB translations table

The `translations` table is defined in `scripts/local-ddb-init.py` with a `ByStatus` GSI. Admin-managed overrides stored as:
```
PK: LOCALE#{locale}   SK: KEY#{namespace}.{key}
value, status, updated_by, updated_at, source_value
```

### 2.5 Gaps remaining

1. `react-i18next` and companion packages not installed in frontend
2. `frontend/src/i18n/config.ts` not created
3. No `I18nextProvider` or `RTLProvider` wrapping the app
4. No `LanguageSwitcher` component
5. ~200 component files still use hardcoded English strings
6. ~100 Tailwind directional classes (`pl-`, `pr-`, `text-left`) not yet converted to logical equivalents
7. `locale` field not on profile model
8. Backend error messages not yet using `translate()` calls

---

## 3. Gap / Threat Analysis

### 3.1 Translation injection (XSS)

Admin-managed translations go through a web form to DDB and then are served to the frontend as JSON. If a malicious admin writes `<script>alert(1)</script>` into a translation value, it could execute in other users' browsers. Mitigations:
- Strip HTML tags from translation values on DDB write in the admin endpoint.
- `react-i18next` with `escapeValue: false` is safe only because React's JSX escapes all interpolated values by default. This assumption must be documented and preserved — never use `dangerouslySetInnerHTML` with `t()` output.

### 3.2 Locale validation

The `locale` field accepted via `PATCH /ui/profile` must be validated against `I18N_SUPPORTED_LOCALES`. Unrestricted locale values could cause file-path traversal if the backend constructs a file path from the locale parameter (`app/i18n/translations/{locale}.json`). The `translate()` function should only read from a whitelist of known locales.

### 3.3 Translation completeness debt

Shipping with incomplete translations (e.g., Arabic at 40% completeness) means some UI elements fall back to English mid-page for Arabic users. The `i18n_missing_key_total` metric and admin completeness dashboard allow tracking and prioritising translation work.

### 3.4 RTL layout regressions

Converting ~100 Tailwind directional classes to logical equivalents (`pl-4` → `ps-4`) is error-prone. Any missed instance causes visual misalignment for RTL users. The RTL QA pass (Arabic locale) must be part of the acceptance checklist.

### 3.5 Code sites that must change

| File | Change |
|---|---|
| `frontend/package.json` | Add react-i18next + i18next + plugins |
| `frontend/src/i18n/config.ts` | New — i18next configuration |
| `frontend/src/i18n/locales/en/translation.json` | New — ~400 key English source file |
| `frontend/src/main.tsx` | Import i18n config; wrap in `I18nextProvider` + `Suspense` |
| `frontend/src/components/layout/RTLProvider.tsx` | New — `dir=rtl` manager |
| `frontend/src/components/shared/LanguageSwitcher.tsx` | New — locale selector dropdown |
| `frontend/src/utils/format.ts` | New — `Intl`-based date/currency/relative-time formatters |
| ~200 `frontend/src/**/*.tsx` | Replace hardcoded strings with `t()` calls |
| ~100 Tailwind classes across components | `pl-*` → `ps-*`, `pr-*` → `pe-*`, etc. |
| `app/services/profile.py` (lines 146, 189, 294) | Add `locale` field to profile model |
| `app/routers/*/` (error messages) | Replace `HTTPException` English strings with `translate(key, locale)` |
| `app/services/alerts.py` (alert titles) | Use `translate()` for `title=` argument in `write_alert()` calls |
| `scripts/local-ddb-init.py` | `translations` table (confirmed exists) |
| `app/core/settings.py` | Settings confirmed at lines 1839–1847 |

---

## 4. Proposed Design / Fix

### 4.1 Frontend i18n bootstrap

```typescript
// frontend/src/i18n/config.ts
i18n
  .use(HttpBackend)          // loads /ui/i18n/translations/{lng} lazily
  .use(LanguageDetector)     // checks localStorage then navigator.language
  .use(initReactI18next)
  .init({
    fallbackLng: "en",
    supportedLngs: ["en", "es", "de", "fr", "pt", "ar", "he", "zh", "ja", "ko", "ru"],
    backend: { loadPath: "/ui/i18n/translations/{{lng}}" },
    detection: { order: ["localStorage", "navigator"], caches: ["localStorage"] },
    interpolation: { escapeValue: false },   // React escapes by default
    react: { useSuspense: true },
  });
```

The `/ui/i18n/translations/{locale}` backend endpoint returns `Cache-Control: max-age=3600` with an `ETag` derived from the JSON hash, so subsequent visits serve from browser cache.

### 4.2 RTL support

```typescript
// frontend/src/components/layout/RTLProvider.tsx
const RTL_LOCALES = new Set(["ar", "he", "fa", "ur"]);

export function RTLProvider({ children }) {
  const { i18n } = useTranslation();
  const isRTL = RTL_LOCALES.has(i18n.language?.split("-")[0] ?? "");
  useEffect(() => {
    document.documentElement.dir = isRTL ? "rtl" : "ltr";
    document.documentElement.lang = i18n.language || "en";
  }, [i18n.language, isRTL]);
  return <>{children}</>;
}
```

Tailwind logical property migration:

| Directional | Logical |
|---|---|
| `pl-4` | `ps-4` |
| `pr-4` | `pe-4` |
| `ml-auto` | `ms-auto` |
| `text-left` | `text-start` |
| `text-right` | `text-end` |
| `left-0` | `start-0` |

For icon flipping in RTL: `<ChevronRight className="rtl:rotate-180" />` (Tailwind `rtl:` modifier).

### 4.3 Locale-aware formatting

```typescript
// frontend/src/utils/format.ts
export function formatCurrency(cents: number, currency = "USD"): string {
  return new Intl.NumberFormat(i18n.language, { style: "currency", currency })
    .format(cents / 100);
}
```

This replaces all `$${(cents/100).toFixed(2)}` template literals across the codebase.

### 4.4 Backend error message translation

```python
# Before: raise HTTPException(429, "Too many login attempts; try again later")
# After:
from app.i18n import translate, get_user_locale_from_request
locale = get_user_locale_from_request(request)
raise HTTPException(429, translate("errors.too_many_login_attempts", locale))
```

The `translate()` function in `app/i18n/__init__.py` already handles fallback: if the key is missing in the requested locale, it returns the English string; if the key is missing entirely, it returns the key itself.

### 4.5 Admin translation management

Admin endpoints use `require_admin_or_root` from `app/auth/policy.py` (line 67). Key endpoints:
- `GET /ui/admin/i18n/locales` — completeness stats per locale
- `PUT /ui/admin/i18n/translations/{locale}/{key}` — update one key
- `POST /ui/admin/i18n/translations/{locale}/bulk` — bulk upload from JSON
- `GET /ui/admin/i18n/missing/{locale}` — list untranslated keys

DDB override items take precedence over static JSON files; backend caches the merged result in-memory for 1 hour.

### 4.6 Dev/Prod parity (SECOPS-007)

- Translation JSON files are part of the source tree (`app/i18n/translations/`). No AWS service is needed to serve them.
- Admin-managed DDB overrides use DDB Local in dev, real DDB in prod — same code path.
- The `/ui/i18n/translations/{locale}` endpoint is public (no auth), so it works identically in both environments.
- `i18next-http-backend` in the frontend fetches from the same Vite proxy path (`/ui/i18n/…` → backend), so dev and prod use the same loading mechanism.

### 4.7 Alternatives considered

- **vue-i18n or @lingui/react**: React-specific libraries with different APIs. `react-i18next` is chosen for its 10M+ weekly npm downloads, concurrent-mode support, and first-class Vite compatibility.
- **Crowdin / Lokalise for translation management**: Third-party SaaS adds cost and dependency. The DDB-backed admin management UI is sufficient for initial scale.
- **Compile-time static bundle per locale**: Faster initial load but requires a build per locale. Rejected in favour of runtime lazy-loading, which allows adding new locales without rebuild.

---

## 5. Testing, Verification & Rollout

### 5.1 pytest unit tests (tests/test_i18n.py)

| # | Test | What to assert |
|---|---|---|
| 1 | `test_translate_english` | Known key returns English value |
| 2 | `test_translate_spanish` | Key with Spanish translation returns Spanish value |
| 3 | `test_translate_fallback` | Missing Spanish key falls back to English |
| 4 | `test_translate_interpolation` | `translate("errors.rate_limited", "es", seconds=30)` substitutes `{{seconds}}` |
| 5 | `test_translate_missing_key` | Completely unknown key returns the key string |
| 6 | `test_locale_from_profile` | Profile locale in `request.state.auth_context` takes priority over `Accept-Language` |
| 7 | `test_locale_from_header` | `Accept-Language: de` returns `"de"` when no profile locale |
| 8 | `test_locale_validation` | Invalid locale `"zz"` rejected with 400 on profile update |

### 5.2 Playwright E2E tests (frontend/e2e/i18n.spec.ts)

20 tests across 5 sections:

- Section A (4): Locale detection — default English; switch to Spanish via settings; persists after reload; `Accept-Language` respected for new users.
- Section B (5): Translation rendering — Spanish login page strings; Spanish empty state; translated 429 error message; pluralization (`"1 comentario"` vs `"5 comentarios"`); English fallback for incomplete locale.
- Section C (3): RTL — Arabic sets `dir=rtl` on `<html>`; sidebar on right; back to English restores `dir=ltr`.
- Section D (4): Date/currency formatting — German date format; German currency format; Spanish relative time; billing page locale-aware amounts.
- Section E (4): Admin translation management — list locales with completeness; update a translation; bulk upload; missing translations list.

Auth: `injectAuth(page, "alice")` for locale switching tests; root identity for admin management tests.

### 5.3 Manual QA steps

1. Set profile locale to Arabic in settings.
2. Reload the application; verify `<html dir="rtl">` in DevTools Elements.
3. Navigate to the messages page; verify sidebar appears on the right.
4. Trigger a rate-limit 429 (rapid login attempts); verify error text is in Arabic.
5. Set locale to German; navigate to billing; verify amounts show European number format.

### 5.4 Observability

Metrics (`app/metrics.py`):
- `i18n_locale_active{locale}` (gauge) — active users per locale
- `i18n_missing_key_total{locale, key}` (counter) — untranslated keys encountered

Alert: `rate(i18n_missing_key_total[5m]) > 50` → warning (deploy shipped untranslated strings).

### 5.5 Rollout plan (phased)

| Phase | Duration | Scope | Rollback |
|---|---|---|---|
| 1 | 3 days | Install react-i18next; create `en.json`; wrap App; no visible change | Remove import |
| 2 | 5 days | Migrate all component strings to `t()`; RTL class conversion | Revert component changes |
| 3 | 3 days | Backend `translate()` for error messages + alerts; `locale` on profile | Remove `translate()` calls |
| 4 | 3 days | Admin translation management UI; `ar.json` + `es.json` initial files | Remove admin router |

**Effort**: L (12–16 days as estimated). Phase 2 (string migration) is the largest effort item — `i18next-parser` can automate key extraction from components, reducing manual work.
