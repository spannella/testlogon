---
id: AND-114
title: Locale switch + RTL readiness
milestone: M2
epic: E16
priority: P2
size: M
depends_on: [AND-112]
blocks: []
status: reviewed
reviewed_on: 2026-06-06
---

# AND-114 — Locale switch + RTL readiness

## 1. Overview & Goal

This ticket delivers two coupled capabilities for the TestLogon native Android app
(`com.testlogon.android`, branch `android-port`, module `android/`):

1. **In-app locale override** — a user-selectable display language that takes effect
   immediately and persists across process death, independent of the device system
   language. The override drives Android's per-app language preference
   (`AppCompatDelegate.setApplicationLocales` / the `androidx.core` AppLocales API), so
   the OS reloads localized resources from the catalogs ported in AND-112.
2. **RTL layout readiness** — an audit and remediation pass ensuring the app renders
   correctly under right-to-left layout direction (Arabic, Hebrew, and the Android
   developer pseudo-locale `ar-XB`), backed by automated and instrumented checks on the
   key screens so RTL regressions are caught in CI.

The ticket is typed **Test** in the backlog: the primary deliverable is verification
(automated RTL checks + locale-switch tests) plus the thin UI/persistence plumbing
required to make that verification meaningful. It is **not** a translation effort —
catalogs are owned by AND-112 — nor a full settings redesign.

**Goal (testable):** Selecting a locale in the in-app picker re-renders the visible UI
in that language without a manual app restart; the chosen locale survives a cold start;
and the enumerated key screens pass an automated RTL audit (no clipped, mirrored-wrong,
or hard-`left`/`right`-anchored content) under a forced RTL locale.

## 2. Context & References

- **Backlog source:** AND-114 — "Locale switch + RTL readiness", Type Test, Priority P2,
  Deps AND-112. Scope: *In-app locale override; RTL layout audit.* Acceptance:
  *Switching locale updates UI; key screens pass RTL check.*
- **Dependency — AND-112 (Port locale catalogs):** converts the web reference app's
  i18next files (`frontend/src/i18n/locales`) into Android resource qualifiers
  (`res/values/`, `res/values-ar/`, `res/values-he/`, …) with default-locale fallback.
  AND-114 consumes those `strings.xml` catalogs; it must not define new copy beyond the
  picker UI strings.
- **Web reference (verified):** the frontend uses **react-i18next** for the runtime
  (`src/i18n/index.ts` bundles `en`/`es`/`fr` statically; `LanguageDetector` persists the
  chosen language in `localStorage` key `i18nextLng`). The `LanguageSwitcher`
  (`src/components/shared/LanguageSwitcher.tsx`) calls `i18n.changeLanguage(locale)` for an
  instant switch AND, **best-effort**, persists the preference to the backend via
  `saveUserLocale` → `PUT /ui/i18n/locale` (`src/api/endpoints/i18n.ts`). RTL is applied by
  `RTLProvider` (`src/components/layout/RTLProvider.tsx`) setting `document.documentElement.dir`
  via `isRTLLocale` (RTL set = `{ar, he, fa, ur}`). The backend additionally exposes
  `GET /ui/i18n/locales`, `GET /ui/i18n/translations/{locale}`, and `GET /ui/i18n/locale`.
  **This ticket deliberately diverges**: it replicates the *behavior* (instant switch,
  persistence, RTL) using platform-native per-app locales + AND-112's bundled catalogs rather
  than a JS i18n runtime or live backend translation fetch. The optional server-side
  preference sync is discussed in §5.
- **Platform docs (authoritative for approach):** AndroidX per-app language preferences
  (`AppCompatDelegate.setApplicationLocales`, `LocaleManagerCompat`,
  `locales_config.xml`), and Compose `LocalLayoutDirection` / `CompositionLocalProvider`.
- **Stack constraints:** Kotlin 2.0.21, Compose + Material 3, single-Activity
  Navigation-Compose, Hilt (KSP), DataStore for prefs, minSdk 24 / targetSdk 35,
  AGP 8.7.3, Gradle 8.9. Module layering `app -> feature-* -> core-*`.

## 3. Functional Requirements

FR-1. The app SHALL provide an in-app language picker listing **System default** plus
every locale for which a catalog exists (initially `en` default, plus at least the two
locales loaded by AND-112, expected `ar` and `he`).

FR-2. Selecting a locale SHALL apply it immediately: visible Compose UI re-renders in the
chosen language with no manual restart. (The platform performs an Activity recreation;
the user perceives an in-place language change.)

FR-3. "System default" SHALL clear the override and follow the device language, falling
back to the app default (`en`) when the device language has no catalog.

FR-4. The selected locale SHALL persist across cold start and OS-initiated process death,
and SHALL be the single source of truth on next launch.

FR-5. Layout direction SHALL be derived from the resolved locale (RTL for `ar`/`he`),
not hardcoded; the app SHALL honor `android:supportsRtl="true"` and use start/end
(not left/right) semantics throughout the key screens.

FR-6. **Key screens** in scope for the RTL audit are: Login (username/password), MFA
challenge (TOTP/SMS/email), the authenticated landing / "me" screen, the primary list
screen (Paging), a media/detail screen, and the Settings/language-picker screen itself.

FR-7. The RTL audit SHALL be enforced by automated checks (see §11) that fail the build
on regression, satisfying the "key screens pass RTL check" acceptance bullet.

FR-8. Numeric, date, and back-navigation affordances on key screens SHALL mirror
correctly under RTL (e.g., the nav-up chevron points end-ward; lists scroll naturally).

## 4. Technical Design

### 4.1 Module placement

- Persistence + locale-application logic lives in **`core-data`** (DataStore already
  resides here per the layering rules) as a `LocalePreferenceRepository`.
- The picker UI lives in **`feature-settings`** (or the existing settings feature module;
  if none exists yet, add a `feature-settings` module that depends on `core-data` +
  `core-ui`).
- The `MainActivity` (in `app`) wires the AndroidX AppCompat locale API and exposes
  the resolved `LayoutDirection` to Compose.

### 4.2 Persistence + repository (core-data)

```kotlin
// core-data/src/main/kotlin/com/testlogon/android/core/data/locale/LocalePreferenceRepository.kt
package com.testlogon.android.core.data.locale

import androidx.core.os.LocaleListCompat
import kotlinx.coroutines.flow.Flow

/** Single source of truth for the user's in-app language override. */
interface LocalePreferenceRepository {
    /** Persisted BCP-47 tag, or null when following the system default. */
    val selectedLocaleTag: Flow<String?>

    /** Persist the override (null == system default) AND apply it via AppCompat. */
    suspend fun setLocale(tag: String?)
}
```

```kotlin
@Singleton
class DataStoreLocalePreferenceRepository @Inject constructor(
    @ApplicationContext private val context: Context,
    private val dataStore: DataStore<Preferences>,   // shared app prefs DataStore
) : LocalePreferenceRepository {

    private object Keys { val LOCALE_TAG = stringPreferencesKey("ui_locale_tag") }

    override val selectedLocaleTag: Flow<String?> =
        dataStore.data.map { it[Keys.LOCALE_TAG]?.takeIf(String::isNotBlank) }

    override suspend fun setLocale(tag: String?) {
        dataStore.edit { prefs ->
            if (tag.isNullOrBlank()) prefs.remove(Keys.LOCALE_TAG)
            else prefs[Keys.LOCALE_TAG] = tag
        }
        val locales = if (tag.isNullOrBlank()) LocaleListCompat.getEmptyLocaleList()
                      else LocaleListCompat.forLanguageTags(tag)
        // AppCompat persists to its own backing store and triggers Activity recreation.
        withContext(Dispatchers.Main) { AppCompatDelegate.setApplicationLocales(locales) }
    }
}
```

> **Persistence strategy note:** `AppCompatDelegate.setApplicationLocales` is itself
> durable (backed by the framework `LocaleManager` on API 33+, and by AppCompat's own
> storage on 24–32). The DataStore copy is the app-level source of truth used to render
> the picker's selected state and to re-apply on first launch in case the AppCompat store
> and our prefs ever diverge. On API 33+ this also reflects changes the user makes in
> *Settings → Apps → TestLogon → Language*.

### 4.3 Applying the locale at startup

```kotlin
// app/src/main/kotlin/com/testlogon/android/MainActivity.kt
@AndroidEntryPoint
class MainActivity : AppCompatActivity() {   // AppCompatActivity required for the API
    @Inject lateinit var localeRepo: LocalePreferenceRepository

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            // Derive layout direction from the resolved configuration locale.
            val locale = LocalConfiguration.current.locales[0]
            val direction = if (TextUtilsCompat.getLayoutDirectionFromLocale(locale)
                    == View.LAYOUT_DIRECTION_RTL) LayoutDirection.Rtl else LayoutDirection.Ltr
            CompositionLocalProvider(LocalLayoutDirection provides direction) {
                TestLogonTheme { AppNavHost() }
            }
        }
    }
}
```

A one-time reconciliation runs in `Application.onCreate` (or via an `AndroidStartup`
initializer): read `selectedLocaleTag` synchronously (first emission) and, if AppCompat's
current locales differ, call `setApplicationLocales` to converge.

### 4.4 Per-app language config

`res/xml/locales_config.xml` enumerates supported locales (drives the system Settings
language entry on API 33+):

```xml
<locale-config xmlns:android="http://schemas.android.com/apk/res/android">
    <locale android:name="en"/>
    <locale android:name="ar"/>
    <locale android:name="he"/>
</locale-config>
```

Referenced from `AndroidManifest.xml`:
`<application android:supportsRtl="true" android:localeConfig="@xml/locales_config" …>`.
For AGP 8.7 with per-app languages, also declare
`androidResources { generateLocaleConfig = true }` *or* maintain the file manually — this
ticket maintains it manually to keep it in lockstep with AND-112's catalog set.

### 4.5 Picker UI (feature-settings)

```kotlin
data class LanguagePickerUiState(
    val options: List<LocaleOption> = emptyList(),  // includes SYSTEM_DEFAULT sentinel
    val selectedTag: String? = null,                // null == system default
)
data class LocaleOption(val tag: String?, val displayName: String) // endonym label

@HiltViewModel
class LanguagePickerViewModel @Inject constructor(
    private val repo: LocalePreferenceRepository,
) : ViewModel() {
    val uiState: StateFlow<LanguagePickerUiState> = /* combine catalog list + selectedTag */
    fun onSelect(tag: String?) = viewModelScope.launch { repo.setLocale(tag) }
}
```

The composable `LanguagePickerScreen` renders a single-choice radio list. Display names
use the **endonym** (`Locale.forLanguageTag(tag).getDisplayName(thatLocale)`) so each
language is shown in its own script.

## 5. API Contract

**No backend interaction in the chosen design — but note this is a deliberate divergence
from the web reference, not the absence of a backend contract.** (CORRECTED: the original
spec asserted "no backend interaction" as if no i18n endpoints existed. They do — see below.)

**What the backend actually offers (verified, OpenAPI tag `i18n`):**
- `GET /ui/i18n/locales` (op `list_locales_ui_i18n_locales_get`) — public, no params;
  returns available locales with display names. Frontend type `LocalesResponse` =
  `{ locales: LocaleInfo[] }`, `LocaleInfo = { code, name, native_name, rtl }`
  (`src/api/endpoints/i18n.ts`). Note the per-locale `rtl: boolean` flag.
- `GET /ui/i18n/translations/{locale}` (op `get_translations_..._get`) — public; returns
  `{ locale, translations: Record<string,string> }`; merges static JSON with admin DDB
  overrides, falls back to English for missing keys.
- `GET /ui/i18n/locale` (op `get_user_locale_ui_i18n_locale_get`) — authed; returns the
  user's saved locale (`UserLocaleResponse = { locale }`). Optional params:
  `user_sub` (query), `X-SESSION-ID` / `X-IMPERSONATION-TOKEN` (headers).
- `PUT /ui/i18n/locale` (op `save_user_locale_ui_i18n_locale_put`) — authed; the web
  `LanguageSwitcher` calls this **best-effort** (failures are swallowed; localStorage is the
  real source of truth client-side). Frontend sends body `{ locale }` with
  `Content-Type: application/json` and reads `{ ok, locale }`. Same optional params as the
  GET. Error responses use `422 HTTPValidationError` (FastAPI standard). The OpenAPI marks
  the success body untyped (`{}`); the `{ ok, locale }` shape is the *frontend's* declared
  contract, not server-guaranteed.

**Why AND-114 stays client-side anyway:** the Android port localizes via platform per-app
locales + AND-112's compiled `strings.xml` catalogs, so it does **not** fetch translation
bundles at runtime and does **not** require a network round-trip to switch language. It
therefore does not depend on cookie/CSRF/session flows for the core feature. All of the web
transport (auth `Authorization: Bearer`, `ui_csrf` cookie → `X-CSRF-Token` header,
`credentials: include`; see `src/api/client.ts`) is irrelevant to the chosen design.

**Optional server-preference sync (out of scope, flagged):** mirroring the web's best-effort
`PUT /ui/i18n/locale` so a user's language follows them across web/Android would require the
authenticated networking stack and is intentionally deferred (see OQ-3). For now the FastAPI
`detail` mapping continues to surface server strings as-is and only client-owned copy is
localized.

## 6. Data & State Management

- **Persisted state:** one DataStore key `ui_locale_tag: String?` (BCP-47, e.g. `"ar"`),
  plus AppCompat's own locale store. Absence/blank == follow system default.
- **In-memory UI state:** `LanguagePickerUiState` exposed as `StateFlow` from the
  ViewModel, per the project's `StateFlow<UiState>` convention.
- **Derived state:** `LayoutDirection` is derived from `LocalConfiguration` at composition
  time — never persisted, never set independently of the locale. This guarantees direction
  and language can never desync.
- **Resolution order on launch:** (1) DataStore `ui_locale_tag` if present →
  (2) else AppCompat current application locales (system-set on API 33+) →
  (3) else system default → catalog fallback to `en` (AND-112 provides default fallback
  for missing keys).
- **Available options** are computed from the catalog set declared in
  `locales_config.xml`; this list MUST equal the locales shipped by AND-112. A debug
  assertion verifies the two sets match.

## 7. Error Handling & Resilience

- **Unsupported persisted tag** (e.g., a catalog removed since it was saved): on launch,
  if `ui_locale_tag` is not in `locales_config.xml`, clear it and fall back to system
  default; log at WARN. The app never crashes on a stale tag.
- **DataStore read failure:** `selectedLocaleTag` flow catches `IOException` and emits
  `null` (system default) so the app remains usable; AppCompat's store still applies any
  previously set locale.
- **Activity recreation glitch:** because applying a locale recreates the Activity,
  Compose Navigation state must restore via `rememberSaveable`/saved-state; the audit in
  §11 includes a test that the user lands back on the same destination after a switch from
  a deep screen.
- **No network involvement** means no timeout/backoff/offline concerns for this ticket;
  those resilience patterns belong to the networking tickets and are unaffected.

## 8. Security & Privacy

- The locale tag is a low-sensitivity user preference; it is stored in the app's private
  DataStore (no plaintext export, no logging of PII).
- No new permissions, no network egress, no change to cookie/CSRF/session handling.
- Telemetry (if enabled) records only the coarse locale tag (e.g., `ar`), never combined
  with account identifiers in a way that fingerprints a user beyond existing analytics.
- Changing locale does **not** clear or alter the persistent cookie jar or session state.

## 9. Accessibility & i18n

This ticket *is* the i18n/RTL hardening ticket. Requirements:

- **RTL semantics:** all key-screen layouts use `start`/`end`, `paddingStart`/`End`,
  `Arrangement.Start`, and Compose `Modifier` directional variants — no `left`/`right`.
- **Mirroring:** directional icons (back/forward chevrons, progress, send) set
  `android:autoMirrored="true"` (or `ImageVector.autoMirror`) so they flip under RTL;
  intentionally non-mirrored glyphs (e.g., brand logo, media play affordance per Material
  guidance) are explicitly exempted and documented in the audit.
- **TextAlign:** body text uses `TextAlign.Start` (resolves per direction), not
  `TextAlign.Left`.
- **TalkBack:** every picker option exposes a content description and selected state;
  reading order is correct under RTL.
- **Endonym labels** in the picker for self-identifiable language names.
- **Touch targets** for picker rows ≥ 48dp; respects Dynamic Type / font scaling without
  truncation in RTL.

## 10. Telemetry & Logging

- Emit one analytics event `settings_locale_changed { from: String?, to: String? }`
  (tags only) through the existing telemetry abstraction, if present; otherwise log at
  DEBUG only.
- Log at INFO when an override is applied on startup and at WARN when a stale/unsupported
  tag is discarded.
- No verbose logging of full configuration objects; never log catalog contents.
- The RTL audit harness emits a per-screen pass/fail summary in test output for CI
  triage.

## 11. Testing Strategy

The Test deliverable is the core of this ticket. Three layers:

**A. Unit (core-testing + Robolectric/JUnit):**
- `DataStoreLocalePreferenceRepositoryTest` — set/clear round-trips; blank/null treated as
  system default; flow emits expected sequence; stale-tag discard logic.
- `LanguagePickerViewModelTest` — options include system-default sentinel and exactly the
  AND-112 catalog locales; `onSelect` delegates to repo; `uiState` reflects selection.

**B. Compose UI / RTL screenshot tests (key screens, FR-6):**
- For each key screen, a parameterized test renders under `LayoutDirection.Ltr` and
  `Rtl` (and locales `en`, `ar`, `he`) using `createComposeRule` with a forced
  `CompositionLocalProvider(LocalLayoutDirection provides Rtl)`.
- RTL assertions: (1) no horizontally clipped/overlapping nodes (bounds within parent);
  (2) leading nav/back affordance is on the *end* side under RTL; (3) snapshot/screenshot
  comparison (Paparazzi or `roborazzi`) against approved RTL golden images. Golden
  mismatch fails the build → satisfies "key screens pass RTL check".

**C. Instrumented (androidTest, Espresso + UiAutomator):**
- `LocaleSwitchInstrumentedTest` — open picker, select `ar`, assert a known on-screen
  string equals the `values-ar` catalog value and that `resources.configuration` layout
  direction is RTL, *without* a manual relaunch (covers FR-2).
- `LocalePersistenceInstrumentedTest` — select `he`, kill+relaunch the process, assert the
  locale and direction persist (covers FR-4).
- Run the matrix additionally against the pseudo-locale `ar-XB` (RTL pseudo) in CI to
  catch hardcoded-direction regressions early.

**Coverage gate:** new code in `core-data/locale` and `feature-settings` language picker
≥ 80% line coverage; all key screens have an RTL golden.

## 12. Dependencies & Sequencing

- **Depends on AND-112 (Port locale catalogs):** the picker enumerates and switches among
  the locales AND-112 ships; RTL string content (`values-ar`, `values-he`) must exist for
  the audit to be meaningful. AND-114 MUST land after AND-112.
- **Transitive:** AND-112 depends on AND-111 (i18n/string-resource foundation); AND-114
  inherits that ordering.
- **Soft prerequisites already assumed present:** single-Activity Navigation-Compose host,
  `TestLogonTheme`, shared DataStore in `core-data`, `core-testing` harness, and the
  screenshot-test tooling (Paparazzi/roborazzi) configured in the Gradle convention
  plugins. If screenshot tooling is absent, add it as part of this ticket.
- **Blocks:** none currently in the source backlog.

## 13. Risks & Open Questions

- **R1 — API-version split:** per-app locales behave differently on API 33+ (framework
  `LocaleManager`, system Settings entry) vs 24–32 (AppCompat shim, Activity recreation).
  Mitigation: rely solely on `AppCompatDelegate.setApplicationLocales` + `LocaleListCompat`
  which abstract the split; test on an API 24 and an API 35 emulator.
- **R2 — Activity recreation losing nav/scroll state.** Mitigation: `rememberSaveable`
  audit + the recreation test in §11C.
- **R3 — Screenshot-test flakiness** (font rendering across machines). Mitigation: pin a
  test device/AGP image, use threshold-tolerant comparison, or use Paparazzi (host-side,
  deterministic).
- **OQ-1:** Exact locale set from AND-112 — confirmed to include `ar` and `he`? The
  picker and `locales_config.xml` must match AND-112's final shipped catalogs.
  *(Verification note: the web reference bundles only `en`/`es`/`fr` — all LTR — in
  `src/i18n/index.ts`; it ships NO RTL catalog. RTL locales `{ar, he, fa, ur}` exist only in
  the `isRTLLocale` predicate and as backend-served bundles. So "AND-112 ships `ar`/`he`" is
  an unverified cross-ticket assumption, not something the reference app demonstrates. The
  RTL audit can still proceed using the `ar-XB` pseudo-locale even if no real RTL catalog
  lands, but the picker's real-locale list must be reconciled with AND-112's actual output.)*
- **OQ-2:** Does the product want the picker inside an existing Settings screen or a
  standalone entry? Assumed inside `feature-settings`.
- **OQ-3:** Should the Android client mirror the web's best-effort server-side preference
  sync via `PUT /ui/i18n/locale` (and/or send an `Accept-Language` hint for server-localized
  errors)? The web app DOES persist locale server-side best-effort and exposes
  `GET/PUT /ui/i18n/locale` + `GET /ui/i18n/locales`/`/translations/{locale}`. Out of scope
  here; flagged for a future networking ticket once the authed transport lands.

## 14. Acceptance Criteria

AC-1. (Backlog) Selecting a locale in the in-app picker updates the visible UI to that
language without a manual app restart — verified by `LocaleSwitchInstrumentedTest`.

AC-2. (Backlog) Each key screen (FR-6) passes the automated RTL check (no clipped/
mis-anchored content; directional icons mirror; goldens match) under `ar`/`he`/`ar-XB`.

AC-3. The chosen locale persists across cold start and process death; "System default"
clears the override and follows the device language with `en` fallback —
`LocalePersistenceInstrumentedTest` green.

AC-4. `locales_config.xml` and the picker option list both equal the AND-112 catalog set;
the consistency assertion passes.

AC-5. No `left`/`right` directional layout attributes remain on key screens (lint/grep
check in CI is clean); `android:supportsRtl="true"` is set.

AC-6. Unit + UI + instrumented suites in §11 pass in CI; new locale code ≥ 80% coverage.

## 15. Definition of Done

- All §14 acceptance criteria met and demonstrated in CI on API 24 and API 35 emulators.
- `LocalePreferenceRepository` + DataStore impl, `LanguagePickerViewModel`/Screen,
  `MainActivity` direction wiring, `locales_config.xml`, and manifest `supportsRtl`/
  `localeConfig` merged to `android-port`.
- RTL golden images committed for all key screens; screenshot tooling configured in the
  Gradle convention plugins.
- Package names are exactly `com.testlogon.android.*`.
- Code reviewed; lint/ktlint/detekt clean; no new permissions; no network changes.
- Spec deviations (if any) recorded in the PR description; OQ-1 confirmed against AND-112
  before merge.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. OpenAPI pointers use
`METHOD /path`; frontend pointers use `path: symbol`; Android-framework choices are labelled
`framework ref`.

1. **Claim:** The web reference exposes language selection via i18next.
   **VERDICT: Verified (and augmented).** It uses **react-i18next** with statically bundled
   `en`/`es`/`fr` and a `localStorage` detector (key `i18nextLng`).
   **SOURCE:** `src/i18n/index.ts` (SUPPORTED_LOCALES, `i18n.init` with LanguageDetector);
   `src/components/shared/LanguageSwitcher.tsx: handleChange` (`i18n.changeLanguage`).

2. **Claim (original §5):** "Not applicable — no backend interaction … does not call FastAPI."
   **VERDICT: Corrected.** The backend DOES expose i18n endpoints and the web app DOES call
   them (best-effort preference save). The *chosen Android design* is client-side, but the
   "no backend contract exists" framing was wrong.
   **SOURCE:** OpenAPI `GET /ui/i18n/locales`, `GET /ui/i18n/translations/{locale}`,
   `GET /ui/i18n/locale`, `PUT /ui/i18n/locale` (tag `i18n`);
   `src/api/endpoints/i18n.ts` (`getLocales`, `getTranslations`, `getUserLocale`,
   `saveUserLocale`); `src/components/shared/LanguageSwitcher.tsx: saveLocale.mutate`.

3. **Claim:** Saving a locale to the backend is `PUT /ui/i18n/locale` with body `{ locale }`
   and returns `{ ok, locale }`.
   **VERDICT: Verified (frontend contract).** Server success body is untyped (`{}`) in the
   OpenAPI; the `{ ok, locale }` shape is the frontend's declared type. Errors → `422
   HTTPValidationError`. Optional params `user_sub` (query), `X-SESSION-ID`,
   `X-IMPERSONATION-TOKEN` (headers).
   **SOURCE:** `src/api/endpoints/i18n.ts: saveUserLocale`; OpenAPI
   `PUT /ui/i18n/locale` (op `save_user_locale_ui_i18n_locale_put`, params + 422).

4. **Claim:** Available locales are returned with `code`, `name`, `native_name`, and an
   `rtl` boolean flag.
   **VERDICT: Verified.**
   **SOURCE:** `src/api/endpoints/i18n.ts: LocaleInfo`; OpenAPI `GET /ui/i18n/locales`.

5. **Claim:** The web app applies RTL by switching `document.dir` based on locale, using an
   RTL locale set of `{ar, he, fa, ur}`.
   **VERDICT: Verified.**
   **SOURCE:** `src/components/layout/RTLProvider.tsx`; `src/i18n/index.ts: isRTLLocale`
   (`RTL_LOCALES`).

6. **Claim (FR-1/§6/OQ-1):** AND-112 ships `ar` and `he` catalogs, which the picker
   enumerates.
   **VERDICT: Unverified-assumption.** The reference app bundles only `en`/`es`/`fr` (all
   LTR) and ships no RTL catalog; `ar`/`he` appear only in the `isRTLLocale` predicate and
   as backend-served bundles. Cross-ticket dependency on AND-112's actual output.
   **SOURCE:** `src/i18n/index.ts: SUPPORTED_LOCALES` (no ar/he); AND-112 output not present
   in this repo.

7. **Claim:** The web transport uses `Authorization: Bearer <token>`, the `ui_csrf` cookie
   echoed as the `X-CSRF-Token` header, and `credentials: include`.
   **VERDICT: Verified** (relevant only if the optional server sync is later adopted).
   **SOURCE:** `src/api/client.ts: api` (Authorization header; `getCookie("ui_csrf")` →
   `X-CSRF-Token`; `credentials: "include"`).

8. **Claim:** A network failure on a backend call surfaces as a thrown error (web shows a
   toast; `ApiError(0, "Network error")`).
   **VERDICT: Verified.** Relevant to the optional-sync flaky-host path only; the core
   Android feature performs no network I/O.
   **SOURCE:** `src/api/client.ts` (catch around `fetch` → `ApiError(0, "Network error")`).

9. **Claim:** In-app per-app language is applied via
   `AppCompatDelegate.setApplicationLocales(LocaleListCompat)`, which persists durably
   (framework `LocaleManager` on API 33+, AppCompat storage on 24–32) and recreates the
   Activity.
   **VERDICT: Verified (framework ref).**
   **SOURCE:** framework ref —
   https://developer.android.com/guide/topics/resources/app-languages
   and https://developer.android.com/reference/androidx/appcompat/app/AppCompatDelegate#setApplicationLocales(androidx.core.os.LocaleListCompat)

10. **Claim:** `locales_config.xml` + manifest `android:localeConfig` drive the system
    Settings per-app language entry on API 33+; `generateLocaleConfig` is the AGP
    alternative.
    **VERDICT: Verified (framework ref).**
    **SOURCE:** framework ref —
    https://developer.android.com/guide/topics/resources/app-languages#sample-config

11. **Claim:** Layout direction is derived from the resolved locale via
    `TextUtilsCompat.getLayoutDirectionFromLocale` / Compose `LocalLayoutDirection` and
    `LocalConfiguration.current.locales[0]`.
    **VERDICT: Verified (framework ref).**
    **SOURCE:** framework refs —
    https://developer.android.com/reference/androidx/core/text/TextUtilsCompat ,
    https://developer.android.com/develop/ui/compose/architecture/compositionlocal

12. **Claim:** `ar-XB` is a built-in RTL pseudo-locale usable to force RTL in tests/CI
    without a real RTL catalog.
    **VERDICT: Verified (framework ref).**
    **SOURCE:** framework ref —
    https://developer.android.com/guide/topics/resources/pseudolocales

13. **Claim (§9):** Directional icons should set `autoMirrored` to flip under RTL;
    certain glyphs are intentionally exempt.
    **VERDICT: Verified (framework ref).**
    **SOURCE:** framework ref —
    https://developer.android.com/guide/topics/resources/localization#mirror-layouts
    (and Material guidance on bidirectionality).

### Corrections made

- **§5 (API Contract):** Replaced the blanket "Not applicable — no backend interaction"
  with an accurate statement: the backend exposes a full `i18n` endpoint group
  (`GET /ui/i18n/locales`, `GET /ui/i18n/translations/{locale}`, `GET`/`PUT /ui/i18n/locale`)
  and the web app calls them (best-effort preference save). Documented exact paths, the
  `{ locale }` request / `{ ok, locale }` response shapes, optional params, and the `422
  HTTPValidationError` error shape, while preserving the (legitimate) rationale that the
  Android port stays client-side by design.
- **§2 (References):** Corrected the vague "exposes language selection via i18next" to the
  verified mechanism (react-i18next + `localStorage` + best-effort `PUT /ui/i18n/locale`,
  RTL via `document.dir`), and labelled the Android approach as a deliberate divergence.
- **OQ-1 (§13):** Annotated that the reference ships no RTL catalog (only `en`/`es`/`fr`),
  so the `ar`/`he` availability is an unverified AND-112 dependency.
- **OQ-3 (§13):** Rewrote to reflect that server-side locale persistence already exists in
  the web app (rather than implying only an `Accept-Language` question).

### Open assumptions

- **AND-112 catalog set (`ar`/`he`):** unverifiable from the reference app (it bundles only
  LTR `en`/`es`/`fr`); depends on AND-112's final output. Must be reconciled before merge.
- **Server success body of `PUT /ui/i18n/locale`:** OpenAPI declares it untyped (`{}`); the
  `{ ok, locale }` shape is taken from the frontend's TS type, not server-guaranteed.
- **Android framework API behaviors** (Activity recreation, durable locale storage split
  across API levels, pseudo-locale rendering) are cited to official docs, not exercised in
  this repo; confirmed on-device/emulator by the §17 instrumented cases.

## 17. Test Plan

Test IDs `TC-AND-114-NN`. Targets: **JVM** = JVM unit/Robolectric (no device);
**emu35** = headless AVD `test35` (x86_64, API 35); **device** = physical Samsung Galaxy
A15 5G (SM-A156U, API 34, arm64-v8a). RTL/locale behavior is not hardware-sensitive, so most
instrumented cases run on **emu35**; a small set runs additionally on **device** to cover the
API-34-vs-35 split (R1) and the arm64 ABI.

- **TC-AND-114-01 — Repo set/clear round-trip (happy path).**
  Type: unit. Target: JVM (Robolectric for AppCompat).
  Preconditions: in-memory/test DataStore; AppCompat test shadow.
  Steps: call `setLocale("ar")`; collect `selectedLocaleTag`; call `setLocale(null)`; collect again.
  Expected: emits `"ar"` then `null`; `AppCompatDelegate.setApplicationLocales` invoked with
  `forLanguageTags("ar")` then `getEmptyLocaleList()`.
  Traces: AC-3, AC-6.

- **TC-AND-114-02 — Blank/whitespace tag treated as system default (validation).**
  Type: unit. Target: JVM.
  Preconditions: test DataStore.
  Steps: `setLocale("   ")`; read flow.
  Expected: stored key removed; flow emits `null`; empty locale list applied.
  Traces: AC-3.

- **TC-AND-114-03 — Stale/unsupported persisted tag discarded on launch (error/resilience).**
  Type: unit. Target: JVM.
  Preconditions: DataStore seeded with `ui_locale_tag="xx"` not present in `locales_config.xml`.
  Steps: run startup reconciliation.
  Expected: tag cleared, falls back to system default, WARN logged, no crash.
  Traces: AC-3, AC-4.

- **TC-AND-114-04 — DataStore read failure falls back to system default (error/resilience).**
  Type: unit. Target: JVM.
  Preconditions: DataStore stub throws `IOException` on read.
  Steps: collect `selectedLocaleTag`.
  Expected: flow catches `IOException`, emits `null`; app remains usable.
  Traces: AC-3, AC-6.

- **TC-AND-114-05 — ViewModel option list equals AND-112 catalog set + system-default sentinel.**
  Type: unit. Target: JVM.
  Preconditions: fake catalog provider returning the `locales_config.xml` set.
  Steps: read `uiState.options`; call `onSelect("he")`.
  Expected: options = system-default sentinel + exactly the catalog locales (endonym labels);
  `onSelect` delegates to repo; `selectedTag` reflects selection.
  Traces: AC-1, AC-4, AC-6.

- **TC-AND-114-06 — Picker → repo wiring & immediate selected-state (Compose-UI).**
  Type: Compose-UI. Target: emu35 (createComposeRule).
  Preconditions: `LanguagePickerScreen` with fake VM.
  Steps: tap the `ar` radio row.
  Expected: single-choice selection moves to `ar`; `repo.setLocale("ar")` called once;
  selected row exposes selected semantics.
  Traces: AC-1.

- **TC-AND-114-07 — Per-screen RTL golden audit, LTR vs RTL × {en, ar, he} (Compose-UI).**
  Type: Compose-UI (screenshot, Paparazzi/roborazzi). Target: JVM (host-side, deterministic) — falls back to emu35 if roborazzi.
  Preconditions: golden images committed; key screens per FR-6 (Login, MFA, landing/me, list,
  media/detail, settings/picker).
  Steps: render each screen under `LocalLayoutDirection = Ltr` and `Rtl` for each locale.
  Expected: (a) no horizontally clipped/overlapping nodes (bounds within parent);
  (b) leading nav/back affordance on the end side under RTL; (c) goldens match within threshold.
  Traces: AC-2, AC-5, AC-6.

- **TC-AND-114-08 — `ar-XB` pseudo-locale forces RTL with no real catalog (Compose-UI/instrumented).**
  Type: instrumented. Target: emu35.
  Preconditions: app built with pseudolocales enabled; `ar-XB` applied.
  Steps: apply `ar-XB`, render key screens.
  Expected: layout direction RTL; no hardcoded `left`/`right` anchoring regressions surface;
  bracketed pseudo-strings visible (confirms resource resolution path).
  Traces: AC-2, AC-5.

- **TC-AND-114-09 — Live locale switch re-renders without manual restart (instrumented, happy path).**
  Type: instrumented (Espresso/UiAutomator). Target: emu35.
  Preconditions: app on landing screen, locale = system default (`en`).
  Steps: open picker, select `ar`.
  Expected: a known on-screen string equals the `values-ar` value and
  `resources.configuration` layout direction is RTL, with no manual relaunch (Activity
  auto-recreated).
  Traces: AC-1.

- **TC-AND-114-10 — Locale persists across process death (instrumented, persistence).**
  Type: instrumented. Target: emu35.
  Preconditions: locale set to `he`.
  Steps: kill the process, relaunch cold.
  Expected: resolved locale and RTL direction persist on next launch from the single source of
  truth.
  Traces: AC-3.

- **TC-AND-114-11 — Activity recreation preserves nav/scroll state (instrumented, resilience).**
  Type: instrumented. Target: emu35.
  Preconditions: navigate to a deep list screen, scroll to a known item.
  Steps: switch locale from the deep screen.
  Expected: after recreation the user lands on the same destination with scroll/nav state
  restored (`rememberSaveable`).
  Traces: AC-1, AC-3.

- **TC-AND-114-12 — API-34 (arm64) vs API-35 per-app locale parity (instrumented, R1).**
  Type: instrumented. Target: **device** (Samsung A15 5G, API 34, arm64) AND emu35 (API 35).
  MUST run on the physical device: validates the API-33+ framework `LocaleManager` path and
  the arm64 ABI, distinct from the x86_64/API-35 emulator.
  Preconditions: same APK installed on both.
  Steps: set `ar` in-app on each; cold-restart; on API 33+ also set the locale via
  Settings → Apps → TestLogon → Language and re-open.
  Expected: identical applied locale + RTL on both; on API 33+ the system Settings entry is
  present (driven by `locales_config.xml`) and reflects/round-trips the choice.
  Traces: AC-2, AC-3, AC-4.

- **TC-AND-114-13 — Accessibility: TalkBack reads picker rows with selected state & RTL order.**
  Type: instrumented (a11y). Target: device (real TalkBack engine preferred) or emu35 with
  accessibility checks.
  Preconditions: picker open under `ar`.
  Steps: enable accessibility checks (`AccessibilityChecks`/TalkBack); traverse the radio list.
  Expected: each row has a content description and announces selected/not-selected; touch
  targets ≥ 48dp; reading order correct under RTL; no contrast/label violations.
  Traces: AC-2, AC-6.

- **TC-AND-114-14 — No `left`/`right` directional attrs on key screens (lint/grep gate, security/quality).**
  Type: unit (static-analysis gate in CI). Target: JVM/CI.
  Preconditions: CI lint + repo grep over key-screen sources.
  Steps: run lint/ktlint + a grep for `paddingLeft/Right`, `TextAlign.Left/Right`,
  `android:layout_..._toLeftOf`, hardcoded `Alignment` left/right; assert
  `android:supportsRtl="true"` present.
  Expected: zero hits; `supportsRtl` true; build fails on any hit.
  Traces: AC-5, AC-6.

### Coverage matrix

| Acceptance criterion (§14) | Covered by |
| --- | --- |
| AC-1 (instant switch, no restart) | TC-05, TC-06, TC-09, TC-11 |
| AC-2 (key screens pass RTL audit; icons mirror; goldens) | TC-07, TC-08, TC-12, TC-13 |
| AC-3 (persist across cold start/process death; system-default + `en` fallback) | TC-01, TC-02, TC-03, TC-04, TC-10, TC-11, TC-12 |
| AC-4 (`locales_config.xml` == picker == AND-112 set) | TC-03, TC-05, TC-12 |
| AC-5 (no left/right attrs; `supportsRtl=true`) | TC-07, TC-08, TC-14 |
| AC-6 (suites pass in CI; ≥80% coverage on new locale code) | TC-01, TC-04, TC-05, TC-07, TC-13, TC-14 |

> Note: there is no app-network path in the chosen design, so the classic flaky-dev-host /
> offline case is **N/A** for the core feature. It would apply only to the deferred optional
> server-sync (`PUT /ui/i18n/locale`); if that is implemented, add a contract/MockWebServer
> case asserting graceful best-effort behavior on `422`/network failure (mirroring the web's
> swallowed-error path, `ApiError(0, "Network error")`).
