---
id: AND-114
title: Locale switch + RTL readiness
milestone: M2
epic: E16
priority: P2
size: M
status: draft
depends_on: [AND-112]
blocks: []
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
- **Web reference:** the frontend exposes language selection via i18next; this ticket
  replicates the *behavior* (instant switch, persistence) using platform-native
  per-app locales rather than a JS i18n runtime.
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

**Not applicable — no backend interaction.** Locale selection is fully client-side and
persisted on-device; it does not call FastAPI, does not send an `Accept-Language` header
change to the backend, and does not depend on cookie/CSRF/session flows. The session and
networking contracts remain owned by their respective tickets. If server-side
localization of error `detail` payloads is ever required, that is out of scope here and
would be a future networking ticket; for now the FastAPI `detail` mapping continues to
surface server strings as-is and only client-owned copy is localized.

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
- **OQ-2:** Does the product want the picker inside an existing Settings screen or a
  standalone entry? Assumed inside `feature-settings`.
- **OQ-3:** Should the backend receive an `Accept-Language` hint for server-localized
  errors? Out of scope here; flagged for a future networking ticket.

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
