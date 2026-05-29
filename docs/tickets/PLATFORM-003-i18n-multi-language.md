# PLATFORM-003: Multi-Language / i18n Support

**Ticket**: PLATFORM-003
**Author**: Engineering
**Status**: Proposed
**Date**: 2026-05-27
**Priority**: Medium
**Estimated effort**: 12-16 days

---

## 1. Executive Summary

The entire platform UI is English-only. Every user-facing string -- navigation labels, form placeholders, error messages, toast notifications, empty states, button text -- is hardcoded directly in React components. The backend returns English-only error messages, alert titles, and notification text. This limits the platform's addressable market to English-speaking users and prevents adoption by international creator communities where audiences expect native-language experiences.

This design introduces a comprehensive internationalization (i18n) layer spanning both the React frontend (using `react-i18next` with lazy-loaded JSON translation bundles) and the Python backend (a simple `translate()` function backed by JSON files). The frontend uses the `Intl` API for locale-aware date, time, currency, and pluralization formatting. Right-to-left (RTL) support is achieved by replacing directional Tailwind classes (`pl-`, `pr-`, `text-left`) with logical equivalents (`ps-`, `pe-`, `text-start`) and adding an `RTLProvider` that sets `dir="rtl"` on the HTML element for Arabic, Hebrew, and other RTL languages. User locale preferences are stored in the profile table and synced to the backend for server-side translations of error messages, alerts, and email templates.

The rollout is phased: Phase 1 adds the i18n framework and English source file; Phase 2 migrates all hardcoded strings and adds RTL support; Phase 3 adds backend translations; Phase 4 adds an admin translation management UI with completeness tracking. Initial translations for non-English locales can be bootstrapped via machine translation and refined by human translators.

---

## 2. Detailed Problem Analysis

### 2.1 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| User (Spanish) | I want to use the platform in my native language. | Switch locale to `es`; all navigation, buttons, and messages display in Spanish. |
| User (Arabic) | I want the layout to be right-to-left. | Switch to `ar`; HTML dir=rtl; sidebar on right; text aligned right. |
| User (German) | I want dates and currency to match my locale conventions. | Dates show "27. Mai 2026"; currency shows "1.234,56 $". |
| User | I want my language preference to persist across sessions. | Set locale in settings; reload; locale is still active. |
| User | I want to fall back to English for untranslated strings. | If a Spanish translation is missing, the English string is shown instead. |
| Creator | I want my error messages to be in my preferred language. | Trigger a 429 rate limit; error text is in Spanish if locale=es. |
| Admin | I want to see which locales have complete translations. | Admin dashboard shows 95% for Spanish, 40% for Arabic, etc. |
| Admin | I want to update a translation without a code deployment. | Edit a string in the admin UI; it takes effect within 1 hour (cache TTL). |

### 2.2 Pain Points

1. **Market limitation**: ~60% of internet users are non-English speakers. The English-only UI prevents organic growth in international markets.
2. **Creator localization**: Creators in non-English markets (Latin America, Middle East, Southeast Asia) report that their audiences abandon the platform due to English-only navigation.
3. **Date/currency confusion**: European and Asian users see US-formatted dates (`05/27/2026`) and currency (`$1,234.56`) which are confusing or ambiguous in their locales.
4. **RTL layout breaks**: Arabic and Hebrew users attempting to use the platform experience misaligned text, reversed icons, and broken form layouts.
5. **Error message opacity**: Backend error messages like "Too many login attempts; try again later" are unintelligible to non-English users, leading to support tickets.

### 2.3 Competitive Analysis

| Platform | i18n Approach |
|----------|---------------|
| Shopify | React-i18next, 20+ languages, RTL support, merchant-configurable translations |
| Patreon | Custom i18n, 6 languages, no RTL, no admin translation management |
| OnlyFans | English-only (a competitive gap this ticket addresses) |
| Twitch | React-intl, 28 languages, full RTL, community translation program |
| Discord | Custom i18n, 30+ languages, crowdsourced translations via Crowdin |

### 2.4 Current State Analysis

#### Frontend (React)
- Every `.tsx` file contains inline English strings. There is no i18n library, no translation key system, no locale detection.
- Components like `Sidebar.tsx` (navigation labels), `AppShell.tsx` (header), `MobileNav.tsx` (mobile navigation), `Login.tsx`, `Register.tsx`, and all page components use hardcoded text.
- Date formatting uses manual `toLocaleDateString()` or `new Date().toISOString()` without locale awareness.
- Currency formatting uses template literals: `$${(cents / 100).toFixed(2)}`.
- Tailwind classes use directional utilities: `pl-4`, `pr-2`, `ml-auto`, `text-left`, `text-right`.

#### Backend (Python/FastAPI)
- Error messages in `HTTPException` calls are English strings: `"Cannot tip your own message"`, `"Too many login attempts; try again later"`.
- Alert titles in `write_alert()` calls are English: `"Broadcast starting in 15 minutes"`.
- The `app/services/profile.py` profile table stores `display_name`, `first_name`, `last_name`, `description`, `birthday`, `gender`, `location`, `displayed_email`, `displayed_telephone_number`, `mailing_address`, `languages`, `profile_photo_url`, `cover_photo_url` but no `locale` field. <!-- CORRECTED: was "display_name, bio, avatar_url, timezone". The actual fields are defined in `empty_profile()` at line 189. There is no `bio` (it's `description`), no `avatar_url` (it's `profile_photo_url`), and no `timezone` field exists. -->

#### Gaps
1. No i18n library installed (frontend or backend)
2. No translation key system
3. No locale detection or preference storage
4. No RTL support
5. No locale-aware date/time/currency formatting
6. No admin translation management
7. No pluralization framework (only `count === 1 ? "item" : "items"` patterns)

---

## 3. Technical Architecture

### 3.1 System Diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│                      Frontend (React/Vite)                            │
│                                                                      │
│  main.tsx ── import "./i18n/config" ── initializes i18next           │
│    │                                                                  │
│    ├── <I18nextProvider> wraps entire app                             │
│    ├── <RTLProvider> sets dir=rtl/ltr on <html>                      │
│    └── <Suspense> shows LoadingSpinner during translation fetch       │
│                                                                      │
│  i18n/config.ts:                                                     │
│    ├── i18next-browser-languagedetector (localStorage → navigator)   │
│    ├── i18next-http-backend (loads from /ui/i18n/translations/{lng}) │
│    └── Fallback: English                                             │
│                                                                      │
│  All components:                                                     │
│    ├── const { t } = useTranslation();                               │
│    ├── {t("nav.messages")} instead of "Messages"                     │
│    └── formatDate(ts), formatCurrency(cents) use Intl API            │
│                                                                      │
│  LanguageSwitcher (settings page):                                   │
│    ├── Dropdown → i18n.changeLanguage(locale)                        │
│    └── PATCH /ui/profile { locale } → persist to backend             │
│                                                                      │
└──────────────────┬───────────────────────────────────────────────────┘
                   │ GET /ui/i18n/translations/{locale}
                   │ (cached with ETag + Cache-Control: max-age=3600)
┌──────────────────▼───────────────────────────────────────────────────┐
│                     FastAPI Backend (:8000)                           │
│                                                                      │
│  app/i18n/__init__.py:                                               │
│    ├── _translations: Dict[str, Dict[str, str]]  (loaded at startup)│
│    ├── translate(key, locale, **kwargs) → string                     │
│    └── get_user_locale(request) → locale string                      │
│                                                                      │
│  app/i18n/translations/:                                             │
│    ├── en.json (source of truth, ~400 keys)                          │
│    ├── es.json (Spanish)                                             │
│    ├── de.json (German)                                              │
│    ├── ar.json (Arabic)                                              │
│    └── ... (other locales)                                           │
│                                                                      │
│  Usage in routers:                                                   │
│    locale = get_user_locale(request)                                 │
│    raise HTTPException(429, translate("errors.rate_limited", locale)) │
│                                                                      │
│  app/services/profile.py:                                            │
│    └── profiles table: added "locale" field (S)                      │
│                                                                      │
│  app/routers/admin_i18n.py:                                          │
│    └── Translation CRUD (DDB translations table)                     │
│                                                                      │
│  DDB: translations table (admin-managed overrides)                   │
│    PK: LOCALE#{locale}                                               │
│    SK: KEY#{namespace}.{key}                                         │
│    Value, status, source_value                                       │
└──────────────────────────────────────────────────────────────────────┘
```

### 3.2 Locale Resolution Priority

1. **User profile `locale` field** (highest priority, stored in DDB)
2. **Browser `Accept-Language` header** (for unauthenticated pages)
3. **`localStorage` `i18nextLng` key** (frontend-only, set by language switcher)
4. **`navigator.language`** (browser default)
5. **Fallback: `en`** (always available)

### 3.3 Translation Layering

Frontend translations load from two sources in order:
1. **Static JSON files** bundled in the frontend build (fast, offline-capable)
2. **Backend API endpoint** `/ui/i18n/translations/{locale}` (dynamic, admin-editable)

The backend endpoint merges static file translations with admin-managed DDB translations, with DDB values taking precedence. This allows admins to fix translation issues without a code deployment.

---

## 4. Data Model Deep Dive

### 4.1 Modified: `profiles` table

Add `locale` attribute to the existing profile item:

| Attribute | Type | Description |
|-----------|------|-------------|
| `locale` | S | IETF BCP 47 language tag (e.g., `en`, `es`, `de`, `ar`, `zh-CN`) |

No schema change needed -- DynamoDB is schema-less. The `locale` field is simply added to the profile item in `app/services/profile.py`. Default is `null` (falls back to browser language detection).

**Example profile item:**
```json
{
  "user_sub": "alice-sub-001",
  "display_name": "Alice",
  "description": "Content creator",
  "profile_photo_url": "https://...",
  "locale": "es"
}
```
<!-- CORRECTED: was "bio" (actually `description`), "avatar_url" (actually `profile_photo_url`), "timezone" (does not exist in profile). See `empty_profile()` at app/services/profile.py:189. -->

### 4.2 New Table: `translations` (admin-managed)

| Attribute | Type | Description |
|-----------|------|-------------|
| `pk` | S | `LOCALE#{locale}` (e.g., `LOCALE#es`) |
| `sk` | S | `KEY#{namespace}.{key}` (e.g., `KEY#common.save`, `KEY#errors.rate_limited`) |
| `value` | S | Translated string |
| `status` | S | `draft`, `approved`, `needs_review` |
| `updated_by` | S | Admin user sub who last edited |
| `updated_at` | N | Unix timestamp |
| `source_value` | S | English source string (for reference when translating) |

### 4.3 Table Definition for local-ddb-init.py

```python
TableDef(
    _resolve_table_name(S.translations_table_name, "translations"),
    "pk",
    "sk",
    gsi=[
        {"index_name": "ByStatus", "partition_key": "status", "sort_key": "pk"},
    ],
),
```

### 4.4 Example DynamoDB Items

**Translation item (approved):**
```json
{
  "pk": "LOCALE#es",
  "sk": "KEY#common.save",
  "value": "Guardar",
  "status": "approved",
  "updated_by": "root.admin@testdev.local",
  "updated_at": 1748361600,
  "source_value": "Save"
}
```

**Translation item (needs review):**
```json
{
  "pk": "LOCALE#ar",
  "sk": "KEY#messages.compose",
  "value": "اكتب رسالة...",
  "status": "needs_review",
  "updated_by": "root.admin@testdev.local",
  "updated_at": 1748361600,
  "source_value": "Type a message..."
}
```

### 4.5 Access Patterns Table

| Access Pattern | Table | Key Condition | Notes |
|----------------|-------|---------------|-------|
| Get all translations for a locale | `translations` | PK = `LOCALE#{locale}` | Range query; returns all keys for one locale |
| Get single translation | `translations` | PK = `LOCALE#{locale}`, SK = `KEY#{key}` | Single-item get |
| Update a translation | `translations` | PK = `LOCALE#{locale}`, SK = `KEY#{key}` | Update with condition |
| List translations needing review | `translations` GSI `ByStatus` | PK = `needs_review` | Admin dashboard filter |
| Count translations per locale (completeness) | `translations` | PK = `LOCALE#{locale}`, Count | Use `Select=COUNT` on query |
| Get user's locale preference | `profiles` | PK = `user_sub` | Single-item get (existing table) |

---

## 5. API Contract Design

### 5.1 User Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| PATCH | `/ui/profile` (existing) | `require_ui_session` | Add `locale` field to profile update | <!-- VERIFIED: require_ui_session at app/services/sessions.py:283; profile update logic in app/services/profile.py:283 (apply_profile_update) -->
| GET | `/ui/i18n/locales` | None (public) | List available locales with display names |
| GET | `/ui/i18n/translations/{locale}` | None (public) | Get all translations for a locale |

### 5.2 Admin Endpoints (admin role via require_ui_session) <!-- CORRECTED: `require_admin_session` does not exist. Use `require_ui_session` and check `ctx["role"]` for admin/root privileges. -->

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/ui/admin/i18n/locales` | Admin | List locales with translation completeness stats |
| POST | `/ui/admin/i18n/locales` | Admin | Add a new locale |
| GET | `/ui/admin/i18n/translations/{locale}` | Admin | Get all translations for a locale (with metadata) |
| PUT | `/ui/admin/i18n/translations/{locale}/{key}` | Admin | Update a single translation |
| POST | `/ui/admin/i18n/translations/{locale}/bulk` | Admin | Bulk upload translations (JSON) |
| GET | `/ui/admin/i18n/missing/{locale}` | Admin | List keys missing in a locale |
| POST | `/ui/admin/i18n/translations/{locale}/{key}/approve` | Admin | Mark translation as approved |
| DELETE | `/ui/admin/i18n/locales/{locale}` | Admin | Remove a locale |

### 5.3 Get Translations (GET /ui/i18n/translations/{locale})

**Response (200):**
```json
{
  "locale": "es",
  "translations": {
    "common.save": "Guardar",
    "common.cancel": "Cancelar",
    "common.loading": "Cargando...",
    "nav.messages": "Mensajes",
    "nav.feed": "Noticias",
    "errors.rate_limited": "Demasiadas solicitudes. Intente de nuevo en {{seconds}} segundos."
  },
  "last_updated_at": 1700000000
}
```

**Caching**: Responses include `ETag` (hash of translations JSON) and `Cache-Control: max-age=3600`. The `i18next-http-backend` plugin respects these headers and avoids redundant fetches.

### 5.4 List Available Locales (GET /ui/i18n/locales)

**Response (200):**
```json
{
  "locales": [
    { "code": "en", "name": "English", "native_name": "English", "rtl": false },
    { "code": "es", "name": "Spanish", "native_name": "Espanol", "rtl": false },
    { "code": "de", "name": "German", "native_name": "Deutsch", "rtl": false },
    { "code": "ar", "name": "Arabic", "native_name": "العربية", "rtl": true },
    { "code": "he", "name": "Hebrew", "native_name": "עברית", "rtl": true },
    { "code": "zh", "name": "Chinese", "native_name": "中文", "rtl": false },
    { "code": "ja", "name": "Japanese", "native_name": "日本語", "rtl": false },
    { "code": "ko", "name": "Korean", "native_name": "한국어", "rtl": false },
    { "code": "ru", "name": "Russian", "native_name": "Русский", "rtl": false },
    { "code": "fr", "name": "French", "native_name": "Francais", "rtl": false },
    { "code": "pt", "name": "Portuguese", "native_name": "Portugues", "rtl": false }
  ]
}
```

### 5.5 Admin Locales with Completeness (GET /ui/admin/i18n/locales)

**Response (200):**
```json
{
  "locales": [
    { "code": "en", "total_keys": 400, "translated": 400, "approved": 400, "needs_review": 0, "completeness": 100.0 },
    { "code": "es", "total_keys": 400, "translated": 380, "approved": 350, "needs_review": 30, "completeness": 95.0 },
    { "code": "ar", "total_keys": 400, "translated": 160, "approved": 100, "needs_review": 60, "completeness": 40.0 }
  ],
  "source_key_count": 400
}
```

### 5.6 Update Single Translation (PUT /ui/admin/i18n/translations/{locale}/{key})

**Request:**
```json
{
  "value": "Guardar cambios",
  "status": "approved"
}
```

**Response (200):**
```json
{
  "ok": true,
  "locale": "es",
  "key": "common.save",
  "value": "Guardar cambios",
  "status": "approved"
}
```

### 5.7 Bulk Upload (POST /ui/admin/i18n/translations/{locale}/bulk)

**Request:**
```json
{
  "translations": {
    "common.save": "Guardar",
    "common.cancel": "Cancelar",
    "common.loading": "Cargando..."
  },
  "status": "draft"
}
```

**Response (200):**
```json
{
  "ok": true,
  "locale": "es",
  "imported": 3,
  "skipped": 0
}
```

### 5.8 Rate Limits

- Translation GET endpoints are public and cached. Rate limited to 100 requests/minute per IP (standard).
- Admin endpoints are rate limited to 60 requests/minute per admin user.
- Bulk upload limited to 10 requests/minute per admin (each can contain up to 1000 keys).

---

## 6. Frontend i18n Implementation

### 6.1 Package Installation

```bash
cd frontend && npm install react-i18next i18next i18next-browser-languagedetector i18next-http-backend
```

### 6.2 i18n Configuration

```typescript
// frontend/src/i18n/config.ts
import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import LanguageDetector from "i18next-browser-languagedetector";
import HttpBackend from "i18next-http-backend";

i18n
  .use(HttpBackend)
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    fallbackLng: "en",
    supportedLngs: ["en", "es", "de", "fr", "pt", "ar", "he", "zh", "ja", "ko", "ru"],
    ns: ["translation"],
    defaultNS: "translation",
    detection: {
      order: ["localStorage", "navigator"],
      lookupLocalStorage: "i18nextLng",
      caches: ["localStorage"],
    },
    backend: {
      loadPath: "/ui/i18n/translations/{{lng}}",
      parse: (data: string) => {
        const parsed = JSON.parse(data);
        return parsed.translations || parsed;
      },
    },
    interpolation: {
      escapeValue: false, // React already escapes
    },
    react: {
      useSuspense: true,
    },
  });

export default i18n;
```

### 6.3 App Integration

```typescript
// frontend/src/main.tsx
import "./i18n/config";  // Initialize before rendering
import { Suspense } from "react";

function App() {
  return (
    <Suspense fallback={<LoadingSpinner />}>
      <RTLProvider>
        <RouterProvider router={router} />
      </RTLProvider>
    </Suspense>
  );
}
```

### 6.4 Translation Key Structure

Namespace-based flat key structure (not nested objects):

```json
{
  "common.save": "Save",
  "common.cancel": "Cancel",
  "common.delete": "Delete",
  "common.loading": "Loading...",
  "common.error": "Something went wrong",
  "common.retry": "Try again",
  "common.noResults": "No results found",

  "nav.dashboard": "Dashboard",
  "nav.messages": "Messages",
  "nav.feed": "Newsfeed",
  "nav.files": "Files",
  "nav.calendar": "Calendar",
  "nav.contacts": "Contacts",
  "nav.settings": "Settings",
  "nav.billing": "Billing",
  "nav.shop": "Shop",
  "nav.signing": "Signing",
  "nav.projects": "Projects",
  "nav.tickets": "Tickets",
  "nav.security": "Security",
  "nav.broadcasts": "Broadcasts",
  "nav.admin": "Admin",

  "auth.login": "Log In",
  "auth.register": "Create Account",
  "auth.logout": "Log Out",
  "auth.forgotPassword": "Forgot password?",
  "auth.email": "Email address",
  "auth.password": "Password",

  "messages.compose": "Type a message...",
  "messages.send": "Send",
  "messages.noConversations": "No conversations yet",
  "messages.encrypted": "Encrypted message",
  "messages.expired": "This message has expired",
  "messages.viewOnce": "Tap to view once",
  "messages.locked": "Locked message",
  "messages.unlock": "Unlock for {{price}}",
  "messages.scheduled": "Scheduled for {{date}}",

  "billing.balance": "Balance",
  "billing.deposit": "Deposit",
  "billing.history": "Billing History",
  "billing.paymentMethods": "Payment Methods",

  "feed.createPost": "Create Post",
  "feed.comments_one": "{{count}} comment",
  "feed.comments_other": "{{count}} comments",

  "errors.notFound": "Page not found",
  "errors.unauthorized": "Please log in to continue",
  "errors.rateLimited": "Too many requests. Please try again in {{seconds}} seconds.",
  "errors.serverError": "Server error. Please try again later."
}
```

**Pluralization**: i18next uses `_one`, `_other` suffixes for English. For languages with more complex plural rules (Arabic: 6 forms, Polish: 3 forms), i18next uses ICU-compatible suffixes (`_zero`, `_one`, `_two`, `_few`, `_many`, `_other`).

### 6.5 Component Migration Example

Before:
```tsx
<Button>Save</Button>
<p>No conversations yet</p>
<span>{count === 1 ? "1 comment" : `${count} comments`}</span>
```

After:
```tsx
import { useTranslation } from "react-i18next";

const { t } = useTranslation();
<Button>{t("common.save")}</Button>
<p>{t("messages.noConversations")}</p>
<span>{t("feed.comments", { count })}</span>
```

### 6.6 RTL Provider

```typescript
// frontend/src/components/layout/RTLProvider.tsx
import { useEffect } from "react";
import { useTranslation } from "react-i18next";

const RTL_LOCALES = new Set(["ar", "he", "fa", "ur"]);

export function RTLProvider({ children }: { children: React.ReactNode }) {
  const { i18n } = useTranslation();
  const isRTL = RTL_LOCALES.has(i18n.language?.split("-")[0] ?? "");

  useEffect(() => {
    document.documentElement.dir = isRTL ? "rtl" : "ltr";
    document.documentElement.lang = i18n.language || "en";
  }, [i18n.language, isRTL]);

  return <>{children}</>;
}
```

### 6.7 RTL Tailwind Migration

Replace directional utilities with logical equivalents:

| Before (directional) | After (logical) |
|----------------------|-----------------|
| `pl-4` | `ps-4` |
| `pr-4` | `pe-4` |
| `ml-auto` | `ms-auto` |
| `mr-2` | `me-2` |
| `text-left` | `text-start` |
| `text-right` | `text-end` |
| `border-l` | `border-s` |
| `border-r` | `border-e` |
| `rounded-l` | `rounded-s` |
| `rounded-r` | `rounded-e` |
| `left-0` | `start-0` |
| `right-0` | `end-0` |

For cases where logical properties are insufficient (e.g., icons that should flip in RTL), use the `rtl:` modifier:
```html
<ChevronRight className="rtl:rotate-180" />
```

### 6.8 Date/Time/Currency Formatting

```typescript
// frontend/src/utils/format.ts
import i18n from "@/i18n/config";

export function formatDate(date: Date | number): string {
  const d = typeof date === "number" ? new Date(date * 1000) : date;
  return new Intl.DateTimeFormat(i18n.language, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(d);
}

export function formatCurrency(cents: number, currency: string = "USD"): string {
  return new Intl.NumberFormat(i18n.language, {
    style: "currency",
    currency,
  }).format(cents / 100);
}

export function formatRelativeTime(seconds: number): string {
  const rtf = new Intl.RelativeTimeFormat(i18n.language, { numeric: "auto" });
  if (Math.abs(seconds) < 60) return rtf.format(Math.round(seconds), "second");
  if (Math.abs(seconds) < 3600) return rtf.format(Math.round(seconds / 60), "minute");
  if (Math.abs(seconds) < 86400) return rtf.format(Math.round(seconds / 3600), "hour");
  return rtf.format(Math.round(seconds / 86400), "day");
}
```

### 6.9 LanguageSwitcher Component

```typescript
// frontend/src/components/shared/LanguageSwitcher.tsx
// Dropdown in the settings page (profile section)
// Shows locale name in native script (e.g., "Espanol", "العربية")
// On change:
//   1. i18n.changeLanguage(locale) — immediate UI update
//   2. PATCH /ui/profile { locale } — persist to backend
//   3. localStorage.setItem("i18nextLng", locale) — persist locally
```

---

## 7. Backend i18n Implementation

### 7.1 Translation Module

```python
# app/i18n/__init__.py
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

_translations: Dict[str, Dict[str, str]] = {}
_TRANSLATIONS_DIR = Path(__file__).parent / "translations"

def _load_translations():
    """Load all translation JSON files on startup."""
    for path in _TRANSLATIONS_DIR.glob("*.json"):
        locale = path.stem
        with open(path) as f:
            _translations[locale] = json.load(f)

def translate(key: str, locale: str = "en", **kwargs: Any) -> str:
    """Look up a translation key for the given locale.

    Falls back to English if the key is missing in the requested locale.
    Supports interpolation: translate("errors.rate_limited", locale, seconds=30)
    """
    strings = _translations.get(locale, _translations.get("en", {}))
    template = strings.get(key) or _translations.get("en", {}).get(key) or key
    try:
        return template.format(**kwargs) if kwargs else template
    except (KeyError, IndexError):
        return template

def get_user_locale(request) -> str:
    """Extract locale from user profile or Accept-Language header."""
    ctx = getattr(request.state, "auth_context", None)
    if ctx and ctx.get("locale"):
        return ctx["locale"]
    accept = request.headers.get("accept-language", "en")
    primary = accept.split(",")[0].split(";")[0].strip().split("-")[0]
    return primary if primary in _translations else "en"
```

### 7.2 Usage in Error Responses

```python
# Replace:
raise HTTPException(429, "Too many login attempts; try again later")

# With:
from app.i18n import translate, get_user_locale
locale = get_user_locale(request)
raise HTTPException(429, translate("errors.too_many_login_attempts", locale))
```

### 7.3 Usage in Alerts

```python
from app.i18n import translate

locale = get_user_locale_by_sub(item["user_id"])
write_alert(
    item["user_id"],
    event="broadcast_reminder",
    outcome="pending",
    title=translate("alerts.broadcast_starting_in", locale, duration=label),
    details={...},
)
```

---

## 8. Security & Privacy Considerations

### 8.1 Translation Injection

User-provided translations (via admin UI) must be sanitized before rendering:
- Strip HTML tags from translation values on write (prevent XSS via admin translation UI).
- React already escapes interpolated values (`escapeValue: false` in i18next config is safe because React's JSX escapes by default).
- Backend translations used in `HTTPException` detail strings are plain text, not HTML.

### 8.2 Locale Validation

- The `locale` field in the profile update is validated against `I18N_SUPPORTED_LOCALES`.
- Invalid locale values are rejected with 400.
- The `Accept-Language` header is parsed defensively; unparseable values fall back to `en`.

### 8.3 Translation Key Enumeration

The `GET /ui/i18n/translations/{locale}` endpoint is public (no auth required) to allow the frontend to load translations before login. This means all translation keys and values are publicly accessible. This is acceptable because translations are not sensitive data.

### 8.4 Admin Translation Tampering

Admin translation management requires `require_ui_session` with admin role check. <!-- CORRECTED: was `require_admin_session`, which does not exist. --> The `updated_by` field provides an audit trail. Bulk uploads are limited in size to prevent denial-of-service.

---

## 9. Performance & Scalability

### 9.1 Bundle Size Impact

- `react-i18next`: ~8KB gzipped
- `i18next`: ~15KB gzipped
- `i18next-browser-languagedetector`: ~3KB gzipped
- `i18next-http-backend`: ~2KB gzipped
- English translation JSON (~400 keys): ~10KB gzipped
- **Total impact**: ~38KB gzipped (acceptable for a feature of this scope)

### 9.2 Translation Loading

- Initial load: ~10KB for the user's active locale (single HTTP request).
- Cached with `Cache-Control: max-age=3600` and `ETag`. Subsequent visits serve from browser cache.
- Fallback locale (English) is loaded only if a key is missing in the active locale (lazy, on-demand).

### 9.3 DDB Query Costs

- **Get translations for a locale**: 1 DDB query, typically returns 400 items (~50KB). Cost: ~6 RCU (eventually consistent, 400 items at ~100 bytes each).
- **Cached at the HTTP level**: The backend caches the merged translation response in-memory with a 1-hour TTL. DDB is queried at most once per locale per hour.
- **Profile locale read**: The `locale` field is on the existing profile item, already fetched during authentication. No additional DDB read.

### 9.4 Known Bottlenecks

- **String migration scope**: ~200 React component files need to be modified to replace hardcoded strings with `t()` calls. This is the largest effort item. Automated extraction tools (`i18next-parser`) can generate the key file, but manual review is needed to ensure correct key names and interpolation.
- **RTL CSS migration**: ~100 Tailwind class instances need to be changed from directional to logical. This can be partially automated with a regex find-replace, but each change needs visual verification.

---

## 10. Migration & Rollback Plan

### 10.1 Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `I18N_ENABLED` | `true` | Master flag; when false, all i18n endpoints return English only |
| `I18N_RTL_ENABLED` | `true` | RTL support; when false, `dir` attribute is always `ltr` |
| `I18N_ADMIN_MANAGEMENT_ENABLED` | `true` | Admin translation management UI |

### 10.2 Phased Rollout

| Phase | Duration | Scope | Rollback |
|-------|----------|-------|----------|
| 1 | 3 days | Install i18next, create config, add English source file, wrap App | Remove `i18n/config.ts` import |
| 2 | 5 days | Migrate all component strings to `t()` calls; RTL class migration | Revert component changes |
| 3 | 3 days | Backend `translate()` module; locale on profile; translated error messages | Remove `translate()` calls |
| 4 | 3 days | Admin translation management UI; DDB translations table | Remove admin router |

Each phase is independently deployable and revertable. Phase 1 has zero UI change (English strings are the same). Phase 2 changes UI text sources but not visible content (if translations are 100% matching).

### 10.3 Rollback Steps

1. Set `I18N_ENABLED=false`. All translation endpoints return English.
2. Frontend detects English-only responses and renders correctly (English is the fallback).
3. No data loss (translations in DDB are preserved for when the feature is re-enabled).

---

## 11. Testing Strategy

### 11.1 Unit Tests (pytest)

| Test | Module | Description |
|------|--------|-------------|
| `test_translate_english` | `i18n/__init__.py` | English key returns English value |
| `test_translate_spanish` | `i18n/__init__.py` | Spanish key returns Spanish value |
| `test_translate_fallback` | `i18n/__init__.py` | Missing Spanish key falls back to English |
| `test_translate_interpolation` | `i18n/__init__.py` | `translate("x", "en", seconds=30)` substitutes correctly |
| `test_translate_missing_key` | `i18n/__init__.py` | Completely missing key returns the key itself |
| `test_get_user_locale_from_profile` | `i18n/__init__.py` | Profile locale takes priority over Accept-Language |
| `test_get_user_locale_from_header` | `i18n/__init__.py` | Accept-Language used when no profile locale |
| `test_get_user_locale_fallback` | `i18n/__init__.py` | Unsupported locale falls back to `en` |
| `test_locale_validation` | `models.py` | Invalid locale codes rejected |

### 11.2 E2E Test Matrix

**File**: `frontend/e2e/i18n.spec.ts`

**Section A: Locale Detection & Switching (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | Default locale is English | Page loads with English text in nav and headings |
| 2 | User can switch locale to Spanish | Change profile locale; verify nav labels change |
| 3 | Locale persists across page reloads | Set locale; reload; verify still Spanish |
| 4 | Browser Accept-Language is respected for new users | Set browser language header; verify locale |

**Section B: Translation Rendering (5 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 5 | Login page renders translated strings | Switch to Spanish; verify "Iniciar sesion" etc. |
| 6 | Messages page renders translated empty state | Verify Spanish empty state text |
| 7 | Error messages are translated | Trigger 429; verify Spanish error message |
| 8 | Pluralization works correctly | Verify "1 comentario" vs "5 comentarios" |
| 9 | Missing translation falls back to English | Request incomplete locale; verify English fallback |

**Section C: RTL Support (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 10 | Arabic locale sets dir=rtl on HTML element | Switch to Arabic; verify attribute |
| 11 | Sidebar renders on the right for RTL | Verify CSS layout direction |
| 12 | Switching back to English restores dir=ltr | Switch from Arabic to English; verify |

**Section D: Date/Time/Currency Formatting (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 13 | Date formatting respects locale | German locale shows "27. Mai 2026" |
| 14 | Currency formatting respects locale | German shows "1.234,56 $" |
| 15 | Relative time formatting respects locale | Spanish shows "hace 5 minutos" |
| 16 | Billing page amounts use locale-aware formatting | Navigate to billing; verify formatted amounts |

**Section E: Admin Translation Management (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 17 | Admin can list all locales with completeness | GET locales returns percentage |
| 18 | Admin can update a translation | PUT translation; verify GET returns updated value |
| 19 | Admin can bulk upload translations | POST bulk; verify all keys present |
| 20 | Admin can view missing translations | GET missing for incomplete locale |

---

## 12. Monitoring & Alerting

### 12.1 Metrics to Track

| Metric | Type | Description |
|--------|------|-------------|
| `i18n_locale_active` | Gauge | Number of active users per locale |
| `i18n_translation_load_total` | Counter | Translation bundle loads, labeled by `locale` and `source` (cache/api) |
| `i18n_translation_load_latency_ms` | Histogram | Time to load translation bundle |
| `i18n_missing_key_total` | Counter | Missing translation keys encountered, labeled by `locale` and `key` |
| `i18n_locale_switch_total` | Counter | Language switches performed by users |
| `i18n_admin_edit_total` | Counter | Admin translation edits |

### 12.2 Dashboard Queries

- **Locale distribution**: `i18n_locale_active` by locale -- shows international user base composition.
- **Translation coverage**: `100 - (i18n_missing_key_total / total_keys)` per locale -- identifies under-translated locales.
- **Translation load performance**: `histogram_quantile(0.95, i18n_translation_load_latency_ms)` -- P95 should be <500ms.

### 12.3 Alert Thresholds

| Alert | Condition | Severity |
|-------|-----------|----------|
| Missing key spike | `rate(i18n_missing_key_total[5m]) > 50` | Warning (likely a deploy with untranslated strings) |
| Translation load failures | Translation endpoint 5xx rate > 1% | Warning |
| RTL layout regression | Manual QA flag (no automated metric) | Info |

---

## 13. Open Questions & Risks

### 13.1 Unresolved Decisions

1. **Translation extraction tooling**: Should we use `i18next-parser` to scan React components and auto-extract translatable strings? This prevents drift between code and translation files but adds build complexity.

2. **Machine translation bootstrap**: Should we use an LLM or machine translation API to generate initial translations for all locales? This accelerates initial rollout but requires human review for quality.

3. **Per-tenant locale defaults**: In a multi-tenant deployment, should each tenant configure a default locale and restrict available locales? Important for white-label deployments.

4. **SSR implications**: If server-side rendering is ever added, the `i18next-http-backend` approach would need to be replaced with a synchronous file-based backend on the server.

5. **Translation versioning**: Should translations be versioned so that a frontend rollback also rolls back translation changes?

6. **Content translation**: This ticket covers UI chrome translation only. User-generated content (messages, posts, bios) is not translated. A future ticket could add auto-translation via an LLM service.

### 13.2 Technical Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Incomplete string migration (hardcoded English visible after deploy) | High | Medium | Automated extraction tool + manual review pass |
| RTL layout breaks (CSS not fully converted) | Medium | Medium | Dedicated RTL QA pass with Arabic locale |
| Translation loading delay (FOUC with English then switching) | Low | Low | Suspense fallback + cached translations |
| Pluralization errors in complex languages | Medium | Low | Use ICU plural rules from i18next; test with Arabic, Polish |

### 13.3 Dependency Risks

- **react-i18next**: Well-maintained library (>10M weekly npm downloads). Low risk.
- **i18next-browser-languagedetector**: Depends on browser APIs (`navigator.language`, `localStorage`). Works in all target browsers.
- **Tailwind logical properties**: Requires Tailwind CSS v3.3+ (already in use). The `ps-`, `pe-`, `ms-`, `me-` utilities are first-class features.

---

## 14. Settings / Configuration

### 14.1 New Settings (app/core/settings.py)

```python
# i18n
translations_table_name: str = os.environ.get("TRANSLATIONS_TABLE_NAME", "translations")
i18n_default_locale: str = os.environ.get("I18N_DEFAULT_LOCALE", "en")
i18n_supported_locales: str = os.environ.get("I18N_SUPPORTED_LOCALES", "en,es,de,fr,pt,ar,he,zh,ja,ko,ru")
i18n_admin_management_enabled: bool = os.environ.get("I18N_ADMIN_MANAGEMENT_ENABLED", "1") not in ("0", "false", "False")
i18n_enabled: bool = os.environ.get("I18N_ENABLED", "1") not in ("0", "false", "False")
i18n_rtl_enabled: bool = os.environ.get("I18N_RTL_ENABLED", "1") not in ("0", "false", "False")
```

### 14.2 New Table Handles (app/core/tables.py)

```python
translations: Any

# In T initialization:
translations=ddb.Table(S.translations_table_name),
```

---

## 15. Implementation Timeline

| Day | Task | Deliverable |
|-----|------|-------------|
| 1 | Install npm packages; create `frontend/src/i18n/config.ts` | i18n framework |
| 1 | Create English source file `frontend/src/i18n/locales/en/translation.json` (~400 keys) | Source translations |
| 2 | Wrap App in `I18nextProvider` + `Suspense`; create `RTLProvider` | App integration |
| 2 | Create `LanguageSwitcher` component; add to settings page | UI switcher |
| 3-5 | Migrate all component strings to `t()` calls (est. ~200 files, ~1200 strings) | String migration |
| 5 | Replace directional Tailwind classes with logical equivalents | RTL support |
| 6 | Create `frontend/src/utils/format.ts` with locale-aware formatters | Formatting |
| 6 | Replace all manual date/currency formatting with utility functions | Format migration |
| 7 | Create `app/i18n/__init__.py` with `translate()` function | Backend i18n |
| 7 | Create `app/i18n/translations/en.json` (~100 backend keys) | Backend translations |
| 8 | Add `locale` field to profile; add `Accept-Language` parsing to auth context | Locale detection |
| 8 | Replace hardcoded error messages and alert titles with `translate()` calls | Backend migration |
| 9 | Add DDB `translations` table; create `app/routers/admin_i18n.py` | Admin API |
| 9 | Create `AdminTranslationsPage.tsx` with completeness dashboard | Admin UI |
| 10 | Create Spanish (`es.json`) and Arabic (`ar.json`) translation files | Initial translations |
| 11-12 | Write E2E tests (`i18n.spec.ts`, 20 tests) | Test suite |
| 13 | RTL QA pass with Arabic locale; fix layout regressions | QA |
| 14 | Add settings; create `.env.local.example` entries | Configuration |
| 15-16 | Integration testing; performance validation; documentation | Ship |

---

## 16. Dependencies

| Dependency | Reason |
|------------|--------|
| `react-i18next` + `i18next` | Frontend internationalization framework |
| `i18next-browser-languagedetector` | Automatic locale detection from browser |
| `i18next-http-backend` | Dynamic translation loading from backend API |
| `app/services/profile.py` | Store user locale preference |
| `app/core/settings.py` | Configuration for supported locales |
| Tailwind CSS v3.3+ | Logical property utilities for RTL |

---

## 17. Acceptance Criteria

1. User can switch language via settings page; all navigation, buttons, and messages update immediately.
2. Arabic locale sets `dir=rtl` on HTML element and reverses layout direction.
3. Dates display in locale-appropriate format (e.g., German: "27. Mai 2026").
4. Currency amounts display in locale-appropriate format (e.g., German: "1.234,56 $").
5. Pluralization works correctly for English and at least one complex-plural language.
6. Missing translations fall back to English gracefully.
7. Locale preference persists across sessions (stored in profile).
8. Backend error messages are translated when user locale is known.
9. Admin can view translation completeness and update translations without code deployment.
10. All 20 E2E tests pass.
11. Feature can be disabled via `I18N_ENABLED=false`.

---

## Appendix: Codebase Citations

| Reference | File | Line(s) | Status |
|-----------|------|---------|--------|
| Profile fields (`empty_profile()`) | `app/services/profile.py` | 199 | VERIFIED: fields are `display_name`, `first_name`, `middle_name`, `last_name`, `title`, `description`, `birthday`, `gender`, `location`, `displayed_email`, `displayed_telephone_number`, `mailing_address`, `languages`, `profile_photo_url`, `cover_photo_url` |
| `bio` field in profile | N/A | N/A | CORRECTED: does not exist; the field is `description` |
| `avatar_url` field in profile | N/A | N/A | CORRECTED: does not exist; the field is `profile_photo_url` |
| `timezone` field in profile | N/A | N/A | CORRECTED: does not exist in `empty_profile()` or elsewhere in `profile.py` |
| `get_profile()` | `app/services/profile.py` | 220 | VERIFIED |
| `apply_profile_update()` | `app/services/profile.py` | 294 | VERIFIED |
| `normalize_profile_payload()` | `app/services/profile.py` | 146 | VERIFIED (would need to be extended to accept `locale` field) |
| `languages` field in profile | `app/services/profile.py` | 199 | VERIFIED (this is spoken languages, not locale -- different concept) |
| `T.profile` table handle | `app/core/tables.py` | 29, 113 | VERIFIED |
| `require_ui_session` | `app/services/sessions.py` | 283 | VERIFIED |
| `require_admin_session` | N/A | N/A | CORRECTED: does not exist; use `require_ui_session` + role check |
| `get_authenticated_user` → `AuthenticatedUser` | `app/auth/deps.py` | 126, 184 | VERIFIED |
| `TableDef` dataclass | `scripts/local-ddb-init.py` | 29 | VERIFIED |
| `_resolve_table_name()` | `scripts/local-ddb-init.py` | 38 | VERIFIED |
| i18n settings | `app/core/settings.py` | 1404-1409 | VERIFIED: `translations_table_name` (1404), `i18n_default_locale` (1405), `i18n_supported_locales` (1406), `i18n_enabled` (1407), `i18n_rtl_enabled` (1408), `i18n_admin_management_enabled` (1409) — these ALL exist |
| i18n router | `app/routers/i18n.py` | exists | VERIFIED: registered in main.py:459 with prefix "/ui/i18n"; has `list_locales`, `get_translations`, `get_user_locale`, `save_user_locale` endpoints |
| translations DDB table | `scripts/local-ddb-init.py` | exists | VERIFIED: translations table defined in local-ddb-init.py |
| i18n JSON files | `app/i18n/` | exists | VERIFIED: en.json, es.json, fr.json |
| Sidebar navigation | `frontend/src/components/layout/Sidebar.tsx` | exists | VERIFIED (hardcoded English navigation labels) |
| `AppShell.tsx` | `frontend/src/components/layout/AppShell.tsx` | exists | VERIFIED |
| `MobileNav.tsx` | `frontend/src/components/layout/MobileNav.tsx` | exists | VERIFIED |
