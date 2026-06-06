---
id: AND-081
title: Appearance/theme settings
milestone: M2
epic: E11
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-019]
blocks: []
---

# AND-081 — Appearance/theme settings

## 1. Overview & Goal

Deliver a user-facing **Appearance** settings screen that lets the user choose
the app theme — **Light**, **Dark**, or **System** — and toggle **dynamic
(Material You) color** on supported devices. The selection is **persisted across
process death** in DataStore and **applied immediately** to the whole app: when
the user taps a choice, the entire UI (including system bars) re-themes without a
restart, and the choice survives killing and relaunching the app.

AND-019 already established `TestLogonTheme(darkTheme, dynamicColor, content)` and
its static light/dark `ColorScheme`s, but it hard-wired `darkTheme` to
`isSystemInDarkTheme()` and `dynamicColor` to a compile-time `true`. AND-019
explicitly deferred the in-app override to "a separate ticket that would pass an
override into `darkTheme`." **This is that ticket.** AND-081 introduces:

1. A persisted `ThemePreferences` model (mode + dynamic-color flag) backed by
   DataStore.
2. An `AppThemeController` / `AppThemeViewModel` that exposes the preference as a
   `StateFlow` and resolves it into the `darkTheme`/`dynamicColor` booleans the
   single-Activity app shell feeds into `TestLogonTheme`.
3. An `AppearanceSettingsScreen` (Compose + Material 3) with a
   `AppearanceSettingsViewModel` for reading and mutating the preference.

The goal is strictly local on-device preference plumbing and one screen. As a
**deliberate scope decision**, AND-081 does **not** sync the theme to the
backend, does not add custom palettes/fonts, and does not modify the AND-019
color tokens.

> **Correction (review 2026-06-06):** an earlier draft claimed there is "no
> `/ui/preferences` write for theme" as if no such contract existed. That is
> factually wrong about the platform. The backend **does** expose a theme
> preference contract and the **web client actively uses it**: the web app
> persists the `system|light|dark` choice both to `localStorage` (zustand
> `persist`, for instant application) **and** to the server via a debounced,
> fire-and-forget `PATCH /ui/settings/preferences` with body field `theme`
> (`PreferencesPatchReq.theme`, enum `system|light|dark`), and re-hydrates it on
> startup via `GET /ui/settings/preferences` (`{ preferences: { theme, ... } }`).
> See `src/stores/uiStore.ts: setTheme/loadServerPreferences` and
> `src/api/endpoints/preferences.ts`. AND-081 is therefore *choosing* local-only
> behavior (offline-instant, no dependency on the unreliable dev backend), **not**
> reflecting an absence of a backend contract. The "dynamic color (Material You)"
> flag genuinely has **no** backend field — it is an Android-only concept; the
> web equivalent is `accent_color`/`custom_accent_hex` via the same endpoint and
> the separate `/ui/theme` customization API (PLATFORM-013). A future roaming
> ticket (see §13) could map `mode` onto `PreferencesPatchReq.theme`.

## 2. Context & References

- **New module:** `feature-settings` (Android library, namespace
  `com.testlogon.android.feature.settings`). If the settings hub module already
  exists from AND-077 (Settings hub IA), this ticket adds the `appearance`
  package to it rather than creating a new module; the screen is reached from the
  settings hub's "Appearance" row.
- **Depends on AND-019** (Material 3 theme): consumes `TestLogonTheme`,
  `LightColors`/`DarkColors`, and the dynamic-color gate. Hard prerequisite.
- **Adjacent (not a hard dep):**
  - AND-077 Settings hub IA owns the navigation row that launches this screen.
  - AND-078 Preferences API DTOs / server-synced preferences are a *separate*
    concern; theme is intentionally device-local (see §6, §13).
  - The single-Activity app shell (Navigation-Compose host) owns wrapping
    content in `TestLogonTheme` and must be updated to read this preference.
- **Stack:** Kotlin 2.0.21, Jetpack Compose + Material 3, Hilt DI (KSP),
  Coroutines/Flow, **DataStore Preferences** for persistence, single-Activity
  Navigation-Compose. minSdk 24, compileSdk/targetSdk 35, JDK 17, AGP 8.7.3.
- **Web reference:** the web client handles appearance in
  `src/pages/settings/Appearance.tsx` (three-card Light/Dark/System picker) +
  `src/components/ThemeProvider.tsx` (applies the `dark` class; for `system` it
  uses `window.matchMedia("(prefers-color-scheme: dark)")`). There is **no UI
  parity requirement**. There *is*, however, a shared backend contract for the
  theme value (corrected from an earlier draft): the web client syncs `theme`
  via `PATCH /ui/settings/preferences` and loads it via
  `GET /ui/settings/preferences`. AND-081 intentionally does not consume that
  contract (local-only by design); the contract is documented here so the
  decision is explicit and a later roaming ticket can pick it up.
- **Dynamic color availability:** Android 12+ (API 31+) only; gated identically
  to AND-019. On API 24–30 the dynamic-color toggle is hidden/disabled.

## 3. Functional Requirements

1. **FR-1 Theme modes.** Provide a three-way choice: `LIGHT`, `DARK`, `SYSTEM`.
   `SYSTEM` follows the OS night-mode setting via `isSystemInDarkTheme()`.
2. **FR-2 Dynamic color toggle.** Provide a boolean "Use dynamic color
   (Material You)" toggle. On API < 31 the control is hidden and the resolved
   value is forced `false`.
3. **FR-3 Persistence.** Both the mode and dynamic-color flag are persisted in
   DataStore and restored on next launch and after process death.
4. **FR-4 Immediate application.** Selecting a mode or toggling dynamic color
   re-themes the entire app immediately (no restart, no navigation away
   required), because the app shell observes the preference as a `StateFlow`.
5. **FR-5 Defaults.** First-run defaults: mode = `SYSTEM`, dynamicColor =
   `true` (matching AND-019's default intent). Defaults apply if DataStore is
   empty or unreadable.
6. **FR-6 Single source of truth.** The app shell derives `TestLogonTheme`'s
   `darkTheme` and `dynamicColor` arguments solely from the resolved
   preference; no screen sets theme directly.
7. **FR-7 Screen UI.** `AppearanceSettingsScreen` shows a single-select group
   (radio rows) for the three modes and a switch row for dynamic color, all
   themed and labeled, reachable from the settings hub.
8. **FR-8 Reflect current state.** The screen always shows the currently
   persisted selection (selected radio, switch position) sourced from the same
   `StateFlow`, so it stays consistent if changed elsewhere.
9. **FR-9 No flash on cold start.** The persisted theme must be read before /
   synchronously enough at startup that the app does not visibly flash the wrong
   theme on launch (see §4 startup strategy).

## 4. Technical Design

### Package layout

```
core-data/src/main/java/com/testlogon/android/core/data/theme/
  ThemeMode.kt                 // enum LIGHT/DARK/SYSTEM
  ThemePreferences.kt          // data class { mode, dynamicColor }
  ThemePreferencesRepository.kt// DataStore-backed read/write

feature-settings/src/main/java/com/testlogon/android/feature/settings/appearance/
  AppearanceSettingsScreen.kt
  AppearanceSettingsViewModel.kt

app/src/main/java/com/testlogon/android/app/theme/
  AppThemeState.kt             // resolves preference -> darkTheme/dynamicColor
  (wiring inside MainActivity / app shell composable)
```

The repository lives in `core-data` (not the feature) because the **app shell**
must read it at startup, and a feature module must not be a dependency of `app`'s
theme bootstrap. `feature-settings` also depends on `core-data` to mutate it.

### Model

```kotlin
enum class ThemeMode { LIGHT, DARK, SYSTEM }

data class ThemePreferences(
    val mode: ThemeMode = ThemeMode.SYSTEM,
    val dynamicColor: Boolean = true,
)
```

### Repository (DataStore)

```kotlin
class ThemePreferencesRepository @Inject constructor(
    private val dataStore: DataStore<Preferences>,   // app-scoped, Hilt-provided
) {
    private object Keys {
        val MODE = stringPreferencesKey("appearance_theme_mode")
        val DYNAMIC = booleanPreferencesKey("appearance_dynamic_color")
    }

    val preferences: Flow<ThemePreferences> = dataStore.data
        .catch { e -> if (e is IOException) emit(emptyPreferences()) else throw e }
        .map { prefs ->
            ThemePreferences(
                mode = prefs[Keys.MODE]
                    ?.let { runCatching { ThemeMode.valueOf(it) }.getOrNull() }
                    ?: ThemeMode.SYSTEM,
                dynamicColor = prefs[Keys.DYNAMIC] ?: true,
            )
        }

    suspend fun setMode(mode: ThemeMode) {
        dataStore.edit { it[Keys.MODE] = mode.name }
    }

    suspend fun setDynamicColor(enabled: Boolean) {
        dataStore.edit { it[Keys.DYNAMIC] = enabled }
    }
}
```

A Hilt module provides a single app-scoped `DataStore<Preferences>` (file
`appearance.preferences_pb`, or the shared app DataStore if one already exists).

### Resolving preference into theme inputs (app shell)

```kotlin
@Composable
fun AppRoot(themePrefs: ThemePreferences) {
    val darkTheme = when (themePrefs.mode) {
        ThemeMode.LIGHT  -> false
        ThemeMode.DARK   -> true
        ThemeMode.SYSTEM -> isSystemInDarkTheme()
    }
    val dynamicColor = themePrefs.dynamicColor &&
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S

    TestLogonTheme(darkTheme = darkTheme, dynamicColor = dynamicColor) {
        // NavHost / app content
    }
}
```

`MainActivity` collects the preference and passes it down:

```kotlin
setContent {
    val prefs by themePreferencesRepository.preferences
        .collectAsStateWithLifecycle(initialValue = ThemePreferences())
    AppRoot(themePrefs = prefs)
}
```

**No-flash startup (FR-9):** the Activity installs `installSplashScreen()` and
holds the splash via `setKeepOnScreenCondition` until the first `ThemePreferences`
value has emitted (a `MutableStateFlow<Boolean> themeLoaded`), so the first
real frame is already correctly themed. Because emission is fast, this adds no
perceptible delay; the fallback default (`SYSTEM`/dynamic-on) matches AND-019's
prior behavior, so even a missed read degrades gracefully.

### Screen ViewModel

```kotlin
@HiltViewModel
class AppearanceSettingsViewModel @Inject constructor(
    private val repo: ThemePreferencesRepository,
) : ViewModel() {

    val uiState: StateFlow<ThemePreferences> = repo.preferences
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000),
                 ThemePreferences())

    val dynamicColorSupported: Boolean =
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S

    fun onModeSelected(mode: ThemeMode) = viewModelScope.launch { repo.setMode(mode) }
    fun onDynamicColorChanged(enabled: Boolean) =
        viewModelScope.launch { repo.setDynamicColor(enabled) }
}
```

### Screen UI

```kotlin
@Composable
fun AppearanceSettingsScreen(
    onBack: () -> Unit,
    viewModel: AppearanceSettingsViewModel = hiltViewModel(),
) {
    val prefs by viewModel.uiState.collectAsStateWithLifecycle()
    Scaffold(topBar = { /* TopAppBar title="Appearance", back nav */ }) { pad ->
        Column(Modifier.padding(pad).selectableGroup()) {
            ThemeMode.entries.forEach { mode ->
                ThemeModeRow(
                    mode = mode,
                    selected = prefs.mode == mode,
                    onSelect = { viewModel.onModeSelected(mode) },
                )
            }
            if (viewModel.dynamicColorSupported) {
                DynamicColorRow(
                    checked = prefs.dynamicColor,
                    onCheckedChange = viewModel::onDynamicColorChanged,
                )
            }
        }
    }
}
```

Mode rows use `Modifier.selectable(role = Role.RadioButton)`; the dynamic-color
row uses `Modifier.toggleable(role = Role.Switch)`. Labels are string resources
(§9). The screen consumes `MaterialTheme` tokens only — no hard-coded colors.

## 5. API Contract

**No network contract is *exercised* by this ticket — by design.** AND-081
stores the theme preference **device-locally in DataStore** and makes **no**
FastAPI calls. This is a scope decision, not an absence of a contract.

For accuracy, the relevant backend contract that exists but is **deliberately
not used** here is:

| Method | Path | Req schema | Resp (200) | Notes |
|--------|------|-----------|-----------|-------|
| `GET`  | `/ui/settings/preferences` | — | `{ preferences: UiPreferences }` (untyped `200:` in OpenAPI index; web types it via `UiPreferences`) | reads `theme` etc. |
| `PATCH`| `/ui/settings/preferences` | `PreferencesPatchReq` (all fields optional; `theme` enum `system\|light\|dark`) | `200:` (no body schema) | web sends `{ theme }`, debounced 500 ms, fire-and-forget |

There is also a separate per-user **theme customization** API (PLATFORM-013):
`GET/PUT/PATCH/DELETE /ui/theme` with `ThemeConfigResponse`/`ThemeConfigPatchReq`
(accent palette, etc.) — likewise out of scope for AND-081.

If this ticket *did* call the backend, it would go through the standard transport
(AND-011/012/013): `Authorization: Bearer` + cookies (`credentials: include`),
CSRF header **`X-CSRF-Token`** sourced from the **`ui_csrf`** cookie on non-GET
requests, and a single automatic refresh via `POST /ui/session/refresh` on 401
(verified in `src/api/client.ts`). None of that plumbing is touched here because
no request is made.

Server-synced user preferences are owned by **AND-078** (Preferences API DTOs),
which wraps exactly the `/ui/settings/preferences` contract above. If product
later wants theme to roam across devices, a follow-up ticket would map this
preference onto the AND-078 payload (`PreferencesPatchReq.theme`); that is
explicitly out of scope here, and theme is deliberately kept local to guarantee
instant offline application (the dev backend at `http://18.222.237.167:8000` is
unreliable and must never block applying a theme).

The only "contract" this ticket exposes is its Kotlin surface:
`ThemePreferencesRepository.preferences: Flow<ThemePreferences>`,
`setMode(ThemeMode)`, `setDynamicColor(Boolean)`, and the `ThemeMode` enum.

## 6. Data & State Management

- **Persistent store:** DataStore Preferences. Keys:
  `appearance_theme_mode` (String, one of `LIGHT`/`DARK`/`SYSTEM`) and
  `appearance_dynamic_color` (Boolean). No Room, no network cache.
- **In-memory state:** `ThemePreferencesRepository.preferences` is the single
  cold `Flow`. Two consumers collect it:
  1. The **app shell** (`MainActivity`) — drives `TestLogonTheme` arguments
     app-wide. Collected with `collectAsStateWithLifecycle`.
  2. The **settings screen** — via `AppearanceSettingsViewModel.uiState`
     (`StateFlow<ThemePreferences>`, `WhileSubscribed`).
  Because both read the same DataStore-backed flow, a write from the screen
  immediately propagates to the shell (FR-4) and the screen reflects external
  changes (FR-8).
- **Defaults / resolution:** empty or unreadable store → `ThemePreferences()`
  (`SYSTEM`, dynamic on). `SYSTEM` mode resolution to dark/light happens in the
  shell composable via `isSystemInDarkTheme()`, so OS night-mode changes
  recompose the theme automatically without writing DataStore.
- **Threading:** all writes are `suspend` on `viewModelScope` (Dispatchers.IO
  under the hood of DataStore). No main-thread disk I/O.

## 7. Error Handling & Resilience

- **DataStore read failure:** the `Flow` `.catch` swallows `IOException` and
  emits `emptyPreferences()`, yielding defaults; the app remains usable and
  themed. Non-IO exceptions are rethrown (programmer error, surfaced in tests).
- **Corrupt/unknown mode string:** `ThemeMode.valueOf` is wrapped in
  `runCatching`; an unrecognized value falls back to `SYSTEM` rather than
  crashing (forward/backward compatibility if the enum changes).
- **Write failure:** a failed `dataStore.edit` is caught in the ViewModel; since
  the UI is driven by the persisted flow (not optimistic local state), a failed
  write simply leaves the previous selection shown — no inconsistent UI. (A
  brief snackbar on persistent write failure is acceptable but optional.)
- **API-level gating:** dynamic color resolved value is `&&`-gated by
  `SDK_INT >= S`, so even if a stale DataStore value says `dynamicColor = true`
  on an API 24–30 device, the static scheme is used and the toggle is hidden.
- **No network resilience needed:** there is no backend call, so timeouts /
  backoff / offline-stale states (relevant elsewhere) do not apply here.

## 8. Security & Privacy

No security-sensitive surface. The preference contains no credentials, cookies,
CSRF tokens, PII, or account identifiers — only an enum and a boolean describing
UI appearance. It is stored in the app's private DataStore file (app-sandboxed,
not world-readable) and is never transmitted to the backend, so it cannot leak
over the plaintext-HTTP dev host. Dynamic color reads only the platform-derived
tonal palette (same as AND-019), never the wallpaper image, and requires no
permission. No new Android permissions are declared.

## 9. Accessibility & i18n

- **i18n:** all user-facing strings are `string` resources in
  `feature-settings` — `appearance_title`, `appearance_mode_light`,
  `appearance_mode_dark`, `appearance_mode_system`, `appearance_dynamic_color`,
  `appearance_dynamic_color_subtitle`. No hard-coded display strings.
- **Selection semantics:** mode rows use `Modifier.selectable(..., role =
  Role.RadioButton)` within a `selectableGroup()`; the dynamic-color row uses
  `Modifier.toggleable(..., role = Role.Switch)`, so TalkBack announces each
  control's role and selected/checked state correctly. Tap targets are full-row
  and ≥48.dp tall.
- **Contrast & dynamic type:** screen uses AND-019 `MaterialTheme` tokens and
  `sp`-based typography, so it inherits WCAG-AA contrast and scales with the
  system font-size setting.
- **Disabled affordance:** on API < 31 the dynamic-color row is omitted (not
  shown disabled) to avoid an unexplained inert control; an optional caption may
  state dynamic color requires Android 12+.

## 10. Telemetry & Logging

Lightweight and privacy-safe. On a confirmed preference write, emit one debug
event capturing only the **non-PII** new values, e.g.
`Telemetry.event("appearance_changed", mapping = {"mode": mode.name,
"dynamic_color": enabled})`, routed through the app's existing telemetry
abstraction (the same one used by AND-052 auth telemetry; reuse, do not invent a
new logger). No raw user data is logged. The theme resolution path in the app
shell remains silent (runs every recomposition; must stay allocation-light, per
AND-019 §10). No analytics on read.

## 11. Testing Strategy

### Repository unit tests (`core-testing` + DataStore test harness)

Use a temporary `DataStore<Preferences>` over a `TemporaryFolder` and a test
`CoroutineScope`:

```kotlin
@Test fun default_when_empty_is_system_and_dynamic_on() = runTest {
    assertEquals(ThemePreferences(ThemeMode.SYSTEM, true), repo.preferences.first())
}

@Test fun setMode_persists_and_emits() = runTest {
    repo.setMode(ThemeMode.DARK)
    assertEquals(ThemeMode.DARK, repo.preferences.first().mode)
}

@Test fun setDynamicColor_persists() = runTest {
    repo.setDynamicColor(false)
    assertEquals(false, repo.preferences.first().dynamicColor)
}

@Test fun unknown_mode_string_falls_back_to_system() = runTest {
    rawDataStore.edit { it[stringPreferencesKey("appearance_theme_mode")] = "PLAID" }
    assertEquals(ThemeMode.SYSTEM, repo.preferences.first().mode)
}
```

### ViewModel tests

Assert `uiState` reflects the repo, and that `onModeSelected` / 
`onDynamicColorChanged` write through to the repo (fake/real temp DataStore).
Assert `dynamicColorSupported` matches `SDK_INT` (via Robolectric SDK config).

### Compose UI tests (`createComposeRule`, Robolectric on CI)

- Renders three radio rows + (on API 31) a switch row; selected row matches the
  persisted mode.
- Tapping "Dark" calls the VM and the row becomes selected
  (`assertIsSelected`); toggling dynamic color flips `assertIsOn`/`assertIsOff`.
- **Immediate-application test:** host `AppRoot` with a real temp-DataStore repo,
  capture `MaterialTheme.colorScheme.background`, write `DARK`, recompose, and
  assert the background equals the AND-019 dark value `Color(0xFF1A1C1E)` —
  proving FR-4/FR-6 end-to-end without a restart.

### CI

All tests run under `testDebugUnitTest` (Robolectric) via AND-008/AND-050; no
device farm required. Persistence-across-restart (FR-3) is covered by reading the
flow from a fresh repository instance over the same DataStore file.

## 12. Dependencies & Sequencing

- **Depends on AND-019** (hard): consumes `TestLogonTheme` and its color tokens;
  this ticket changes how `darkTheme`/`dynamicColor` are supplied to it.
- **Coordinates with AND-077** (Settings hub IA): the hub provides the
  "Appearance" navigation row and route to this screen. If AND-077 lands first,
  wire the route there; otherwise expose a public destination/route constant
  this ticket defines for the hub to link.
- **Requires app-shell change:** `MainActivity` / `AppRoot` must collect the
  preference and pass resolved args to `TestLogonTheme`. This is part of this
  ticket's deliverable.
- **Independent of AND-078** (server preferences) and all network tickets — no
  backend dependency.
- **DataStore dependency:** `androidx.datastore:datastore-preferences` must be in
  the version catalog; add it if not already present (likely added by an earlier
  prefs ticket — reuse the existing entry).
- **Blocks:** nothing strictly; it is a P1 enhancement consumed by users via the
  settings hub.

## 13. Risks & Open Questions

- **Cold-start theme flash.** If the persisted preference is read asynchronously
  after first frame, users could see a one-frame wrong theme. Mitigation: splash
  keep-on-screen until first emission (§4); default fallback equals prior
  behavior so worst case is benign. *Open question: is a synchronous first read
  (blocking ≤ a few ms) acceptable instead of the splash gate?*
- **Shared vs. dedicated DataStore.** If a shared app DataStore already exists
  (from another prefs ticket), reuse it to avoid multiple instances over one
  file (DataStore forbids multiple instances per file). *Open question: which
  module owns the canonical `DataStore<Preferences>` provider?*
- **Local-only theme.** Theme does not roam across devices. *Open question: does
  product want theme synced via AND-078 later?* Current decision: local-only for
  instant, offline-safe application.
- **Dynamic color default on API < 31.** Stored `dynamicColor = true` is inert on
  older devices; handled by SDK gating. No risk, noted for clarity.
- **Mode enum evolution.** Adding modes later is safe (unknown → `SYSTEM`
  fallback), but removing a stored value name would need a migration; acceptable
  given a stable 3-value set.

## 14. Acceptance Criteria

1. An **Appearance** screen exists in `feature-settings`, reachable from the
   settings hub, offering Light / Dark / System single-select and (API 31+) a
   dynamic-color switch. (FR-1, FR-2, FR-7)
2. Selecting a mode or toggling dynamic color **re-themes the entire app
   immediately** with no restart and no navigation required. (FR-4, FR-6)
3. The selection **persists** across process death and relaunch, verified by
   reading the preference from a fresh repository instance. (FR-3)
4. First-run defaults are **System** mode and dynamic color **on**; empty/
   unreadable DataStore yields these defaults. (FR-5)
5. `darkTheme` and `dynamicColor` passed to `TestLogonTheme` are derived solely
   from the persisted preference (with `SYSTEM` → `isSystemInDarkTheme()` and
   dynamic color gated to `SDK_INT >= 31`). (FR-6, FR-2)
6. The screen always reflects the currently persisted state on entry and when it
   changes elsewhere. (FR-8)
7. No visible wrong-theme flash on cold start. (FR-9)
8. Repository, ViewModel, and Compose UI tests pass under `testDebugUnitTest`,
   including the end-to-end "write DARK → `MaterialTheme.colorScheme.background ==
   0xFF1A1C1E`" assertion. (§11)
9. No network calls are made; no AND-019 color tokens are modified; no
   hard-coded colors/strings introduced.

## 15. Definition of Done

- All Section 14 acceptance criteria met and demonstrably true.
- Code merged to branch `android-port`:
  - `core-data/.../theme/` (model + `ThemePreferencesRepository` + Hilt
    DataStore module),
  - `feature-settings/.../appearance/` (screen + ViewModel + strings),
  - app-shell wiring in `MainActivity`/`AppRoot` consuming the preference.
- `:core-data`, `:feature-settings`, and `:app` `assembleDebug`, `lintDebug`,
  and `testDebugUnitTest` green locally and on CI (AND-008 / AND-050).
- Preference persists across app restart; theme applies instantly on change
  (manually verified on an API 31+ device and an API 24–30 device/emulator).
- Dynamic-color control hidden on API < 31; static schemes used there.
- All user-facing text is in string resources; accessibility roles
  (RadioButton / Switch) and ≥48.dp tap targets verified.
- One redacted telemetry event on preference change, routed through the existing
  telemetry abstraction; no PII logged.
- Brief KDoc on `ThemePreferencesRepository`, `ThemeMode`, and the app-shell
  resolution helper documenting defaults and the API-31 dynamic-color gate.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer.

1. **"Web persists theme locally for instant application."** VERDICT: **Verified.**
   SOURCE: `src/stores/uiStore.ts` — `useUiStore` is wrapped in zustand
   `persist({ name: "ui-store", partialize: … theme … })`; `setTheme` calls
   `set({ theme })` immediately.
2. **"Web ALSO syncs the theme choice to the backend."** VERDICT: **Corrected**
   (the spec originally claimed no `/ui/preferences` write for theme / no shared
   backend contract). SOURCE: `src/stores/uiStore.ts: setTheme` →
   `debouncedSyncToServer({ theme })` → `src/api/endpoints/preferences.ts:
   patchPreferences` → `PATCH /ui/settings/preferences`.
3. **Backend theme contract path/method.** VERDICT: **Verified.** SOURCE: OpenAPI
   `GET /ui/settings/preferences` (op `ui_get_preferences_…`) and
   `PATCH /ui/settings/preferences` (op `ui_update_preferences_…`, req
   `PreferencesPatchReq`).
4. **`PreferencesPatchReq.theme` enum is exactly `system|light|dark`.** VERDICT:
   **Verified.** SOURCE: `components.schemas.PreferencesPatchReq.theme.anyOf[0].enum`
   in `openapi.pretty.json` (= `["system","light","dark"]`); mirrored in
   `src/api/endpoints/preferences.ts: UiPreferences.theme`.
5. **`GET /ui/settings/preferences` response shape `{ preferences: {...} }`.**
   VERDICT: **Verified (frontend) / partially Unverified (OpenAPI).** SOURCE:
   `src/api/endpoints/preferences.ts: getPreferences` reads
   `resp.preferences`. The OpenAPI index lists the 200 response as empty
   (`resp=200:` with no schema), so the wrapper key is verified only from the
   frontend, not the server schema.
6. **"Dynamic color (Material You) has no backend field."** VERDICT: **Verified.**
   SOURCE: `PreferencesPatchReq` fields are `theme, sidebar_collapsed,
   accent_color, custom_accent_hex, font_size, density, high_contrast`
   (openapi.pretty.json) — no Material-You / dynamic-color field; the web colour
   concept is `accent_color`/`custom_accent_hex` instead.
7. **Web "system" mode follows OS via prefers-color-scheme.** VERDICT:
   **Verified.** SOURCE: `src/components/ThemeProvider.tsx` —
   `window.matchMedia("(prefers-color-scheme: dark)")` + `change` listener for
   `theme === "system"`. (Android analogue `isSystemInDarkTheme()` is the correct
   parallel — framework ref:
   https://developer.android.com/develop/ui/compose/designsystems/material3#dynamic.)
8. **CSRF/auth transport (if used): `X-CSRF-Token` from `ui_csrf` cookie; Bearer +
   cookies; one refresh on 401.** VERDICT: **Verified.** SOURCE: `src/api/client.ts`
   — `getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`;
   `Authorization: Bearer`; `credentials: "include"`; `refreshSession()` →
   `POST /ui/session/refresh`. (Confirms the §5 statement; this ticket makes no
   such call.)
9. **A separate per-user theme-customization API exists (`/ui/theme`).** VERDICT:
   **Verified.** SOURCE: OpenAPI `GET/PUT/PATCH/DELETE /ui/theme`
   (`ThemeConfigResponse`, `ThemeConfigPatchReq`); `src/api/endpoints/themeCustomization.ts`.
   Out of scope for AND-081 (noted for accuracy).
10. **Web error/validation envelope.** VERDICT: **Verified.** SOURCE: OpenAPI
    `422:HTTPValidationError` on the preferences endpoints; non-422 errors return
    `detail` (string | array of `{msg}` | object), normalized in
    `src/api/client.ts: normalizeErrorDetail`. (Most platform endpoints also use
    `ErrorEnvelope`, but the `/ui/settings/preferences` ops list only
    `HTTPValidationError`.)
11. **DataStore Preferences for on-device persistence; `.catch(IOException →
    emptyPreferences())`; main-thread-safe.** VERDICT: **Unverified-assumption
    (framework ref).** No Android source tree is in the provided references; this
    is a standard pattern. Framework ref:
    https://developer.android.com/topic/libraries/architecture/datastore.
12. **AND-019 `TestLogonTheme(darkTheme, dynamicColor, content)` exists and dark
    background == `Color(0xFF1A1C1E)`.** VERDICT: **Unverified-assumption.** AND-019
    source is not in the provided references; the signature and the exact hex are
    taken from the spec's own claim about a sibling ticket and must be confirmed
    against the actual AND-019 code before the §11 colour assertion is written.
13. **Dynamic color requires API 31+ (`Build.VERSION_CODES.S`).** VERDICT:
    **Verified (framework ref).** SOURCE:
    https://developer.android.com/develop/ui/compose/designsystems/material3#dynamic
    ("available on Android 12 and above").
14. **Splash hold via `installSplashScreen()` /
    `setKeepOnScreenCondition`.** VERDICT: **Unverified-assumption (framework
    ref).** Standard `androidx.core:core-splashscreen` API; not verifiable from
    the provided sources. Framework ref:
    https://developer.android.com/develop/ui/views/launch/splash-screen.

### Corrections made

- **§1, §2, §5 — backend contract for theme.** Removed/qualified the false claim
  that "there is no `/ui/preferences` write for theme" and "no shared backend
  contract for the theme value." The contract exists
  (`PATCH/GET /ui/settings/preferences`, `PreferencesPatchReq.theme`) and the web
  client uses it (local + debounced server sync). Reframed AND-081 as a
  *deliberate local-only scope decision*, and documented the real contract and
  transport (`X-CSRF-Token` / `ui_csrf` / `POST /ui/session/refresh`) so the
  decision is explicit and a roaming follow-up can adopt it.
- **§2 — web reference detail.** Replaced the vague "frontend has its own
  appearance handling" with the actual files and mechanism
  (`Appearance.tsx`, `ThemeProvider.tsx`, `matchMedia`).
- **§5 — CSRF header name.** Stated explicitly as `X-CSRF-Token` from the
  `ui_csrf` cookie (verified in `client.ts`), in case the ticket is ever
  extended to call the backend.

### Open assumptions

- **AND-019 internals (signature + dark hex `0xFF1A1C1E`).** Not in provided
  references; confirm against AND-019 source before relying on the §11 colour
  assertion (Citation 12).
- **Android-side library behavior** (DataStore `IOException` fallback,
  splash-screen keep-on-screen, Hilt single-DataStore provider, Material You
  gating constants) — standard framework patterns, not verifiable from the
  backend/frontend sources given (Citations 11, 13, 14).
- **`GET /ui/settings/preferences` exact response schema.** OpenAPI lists an
  empty 200 body; the `{ preferences: {...} }` envelope is known only from the
  frontend client (Citation 5). Irrelevant to AND-081 (no call made) but worth
  noting for the roaming follow-up.

## 17. Test Plan

Test IDs `TC-AND-081-NN`. "Traces" link to §14 acceptance criteria (AC-1 … AC-9).
Target legend per the available CI/dev targets: **JVM/Robolectric** (local, no
device), **emulator test35** (API 35 x86_64 headless AVD), **physical A15**
(Samsung SM-A156U, API 34 arm64). Theme/persistence logic is device-independent,
so most cases run JVM/Robolectric; the dynamic-color/Material-You and
ABI/API-version cases must run on real hardware/emulator as noted.

- **TC-AND-081-01 — Repository default when store empty.**
  Type: unit (JVM/Robolectric). Target: JVM/Robolectric.
  Preconditions: fresh temp `DataStore<Preferences>`, no keys written.
  Steps: collect `repo.preferences.first()`.
  Expected: `ThemePreferences(mode = SYSTEM, dynamicColor = true)`.
  Traces: AC-4.

- **TC-AND-081-02 — setMode persists and emits.**
  Type: unit (JVM/Robolectric). Target: JVM/Robolectric.
  Preconditions: temp DataStore.
  Steps: `repo.setMode(DARK)`; then read `repo.preferences.first().mode`; then
  construct a *fresh* repository over the *same* file and read again.
  Expected: both reads return `DARK` (proves emit + cross-instance persistence).
  Traces: AC-3.

- **TC-AND-081-03 — setDynamicColor persists.**
  Type: unit (JVM/Robolectric). Target: JVM/Robolectric.
  Preconditions: temp DataStore.
  Steps: `repo.setDynamicColor(false)`; read back via a fresh repo instance.
  Expected: `dynamicColor == false` after restart-equivalent re-read.
  Traces: AC-3.

- **TC-AND-081-04 — Corrupt/unknown mode string falls back to SYSTEM.**
  Type: unit (JVM/Robolectric). Target: JVM/Robolectric.
  Preconditions: temp DataStore.
  Steps: write raw `appearance_theme_mode = "PLAID"`; collect
  `repo.preferences.first()`.
  Expected: `mode == SYSTEM` (no crash; `runCatching` fallback).
  Traces: AC-4 (defaults/resilience).

- **TC-AND-081-05 — DataStore read IOException yields defaults (offline/flaky
  store path).**
  Type: unit (JVM/Robolectric). Target: JVM/Robolectric.
  Preconditions: a DataStore whose `data` flow throws `IOException` (fake/throwing
  source).
  Steps: collect `repo.preferences.first()`.
  Expected: `.catch` emits `emptyPreferences()` → `ThemePreferences(SYSTEM,
  true)`; flow does not propagate the exception. (Non-IO exceptions, by contrast,
  must rethrow — assert with a separate throwing source.)
  Traces: AC-4.

- **TC-AND-081-06 — ViewModel mirrors repo and writes through.**
  Type: unit (JVM/Robolectric). Target: JVM/Robolectric.
  Preconditions: `AppearanceSettingsViewModel` over a temp-DataStore repo.
  Steps: collect `uiState`; call `onModeSelected(DARK)` and
  `onDynamicColorChanged(false)`; re-read `uiState`.
  Expected: `uiState` transitions to `mode=DARK, dynamicColor=false`; repo
  reflects the same (no optimistic-only state).
  Traces: AC-6, AC-2.

- **TC-AND-081-07 — `dynamicColorSupported` matches SDK_INT (gating).**
  Type: unit (Robolectric SDK config). Target: JVM/Robolectric (parameterize
  `@Config(sdk = [30, 31])`).
  Preconditions: VM constructed under each configured SDK.
  Steps: read `viewModel.dynamicColorSupported`.
  Expected: `false` at API 30, `true` at API 31.
  Traces: AC-5.

- **TC-AND-081-08 — Resolution helper maps preference → theme inputs.**
  Type: unit (Robolectric for `isSystemInDarkTheme`/SDK). Target: JVM/Robolectric.
  Preconditions: drive each `ThemeMode` and both `dynamicColor` values; vary
  OS night-mode and SDK via `@Config`.
  Steps: invoke the AppRoot resolution logic.
  Expected: `LIGHT→darkTheme=false`, `DARK→true`, `SYSTEM→isSystemInDarkTheme()`;
  `dynamicColor` is `pref.dynamicColor && SDK_INT>=31` (so forced `false` at API
  ≤30 even when the stored flag is `true`).
  Traces: AC-5.

- **TC-AND-081-09 — Compose screen renders and reflects persisted state.**
  Type: Compose-UI (Robolectric). Target: JVM/Robolectric (`createComposeRule`).
  Preconditions: repo seeded `mode=DARK` on an API-31 config.
  Steps: render `AppearanceSettingsScreen`; inspect rows.
  Expected: three radio rows present, "Dark" `assertIsSelected()`, others not;
  dynamic-color switch present.
  Traces: AC-1, AC-6.

- **TC-AND-081-10 — Tapping a mode / toggling dynamic color updates UI + store.**
  Type: Compose-UI (Robolectric). Target: JVM/Robolectric.
  Preconditions: temp-DataStore repo, default state.
  Steps: tap "Dark" row, then toggle dynamic-color switch.
  Expected: "Dark" becomes `assertIsSelected()`; switch flips
  `assertIsOn()`/`assertIsOff()`; underlying repo values change accordingly.
  Traces: AC-1, AC-2, AC-6.

- **TC-AND-081-11 — Immediate application end-to-end (no restart).**
  Type: integration/Compose-UI (Robolectric). Target: JVM/Robolectric.
  Preconditions: host `AppRoot` with a real temp-DataStore repo at default.
  Steps: capture `MaterialTheme.colorScheme.background`; write `DARK`;
  recompose; re-read background.
  Expected: background changes to the AND-019 dark value (spec asserts
  `Color(0xFF1A1C1E)` — confirm exact hex against AND-019 source first, see §16
  Citation 12) with no Activity restart.
  Traces: AC-2, AC-8.

- **TC-AND-081-12 — Dynamic-color row hidden below API 31; static schemes used.**
  Type: Compose-UI (Robolectric SDK config). Target: JVM/Robolectric
  (`@Config(sdk = [30])`), then confirmed on **physical A15 (API 34)** for the
  *enabled* path.
  Preconditions: render screen at API 30 then on the device at API 34.
  Steps: API 30 — assert the dynamic-color row does **not** exist; A15 — assert
  it exists and toggling it visibly changes the palette (Material You).
  Expected: row absent + static scheme at API ≤30; present + tonal-palette effect
  on the device. MUST run on the physical device for the real Material-You render.
  Traces: AC-1, AC-5.

- **TC-AND-081-13 — No-flash cold start.**
  Type: instrumented/e2e. Target: **physical A15 (API 34)** (real cold-start
  timing/splash); spot-check on emulator test35 (API 35).
  Preconditions: persist `mode=DARK`; force-stop the app; relaunch cold.
  Steps: launch and capture the first rendered frame (screenshot/UiAutomator or
  trace).
  Expected: first content frame is already dark — no light→dark flash; splash is
  held until first `ThemePreferences` emission. Physical-device run is
  authoritative for real timing; emulator is a fast regression check.
  Traces: AC-7.

- **TC-AND-081-14 — No network traffic on theme change (local-only guarantee).**
  Type: contract/MockWebServer (negative). Target: JVM/Robolectric +
  MockWebServer.
  Preconditions: app wired with a MockWebServer the HTTP client *would* hit;
  enqueue a sentinel response.
  Steps: change mode and toggle dynamic color several times.
  Expected: MockWebServer records **zero** requests (no
  `PATCH /ui/settings/preferences`, no `/ui/theme`), proving the device-local
  design and that the unreliable dev backend can never block theming.
  Traces: AC-9.

- **TC-AND-081-15 — Accessibility semantics & tap targets.**
  Type: Compose-UI / instrumented accessibility. Target: JVM/Robolectric for
  roles; **physical A15** for a TalkBack pass.
  Preconditions: render the screen.
  Steps: assert each mode row exposes `Role.RadioButton` within a
  `selectableGroup` and selected-state semantics; the dynamic-color row exposes
  `Role.Switch` and checked-state; all rows report ≥48.dp height; run one TalkBack
  sweep on the device confirming role + state announcements and no unlabeled
  controls.
  Expected: correct roles/states announced; tap targets ≥48.dp; all labels from
  string resources (no hard-coded text).
  Traces: AC-1, AC-9.

- **TC-AND-081-16 — Private-storage / no-leak check (security).**
  Type: instrumented. Target: **physical A15 (API 34)**.
  Preconditions: set a non-default theme so the prefs file is written.
  Steps: locate the DataStore file under the app's private dir; check it is in
  app-sandboxed storage (not world-readable) and contains only the enum + boolean
  (no credentials/PII); confirm via traffic capture that nothing is transmitted.
  Expected: file is app-private with `MODE_PRIVATE`-equivalent perms; contents are
  appearance-only; zero network egress. No new permissions in the merged manifest.
  Traces: AC-9.

### Coverage matrix (§14 AC → test cases)

| AC | Acceptance criterion (abridged) | Covered by |
|----|--------------------------------|-----------|
| AC-1 | Appearance screen with 3-way select + (API31+) dynamic-color switch | TC-09, TC-10, TC-12, TC-15 |
| AC-2 | Selection re-themes whole app immediately, no restart | TC-06, TC-10, TC-11 |
| AC-3 | Persists across process death / fresh repo instance | TC-02, TC-03 |
| AC-4 | First-run defaults SYSTEM + dynamic-on; empty/unreadable → defaults | TC-01, TC-04, TC-05 |
| AC-5 | `darkTheme`/`dynamicColor` derived from pref; SYSTEM→OS; dynamic gated ≥31 | TC-07, TC-08, TC-12 |
| AC-6 | Screen always reflects persisted state (incl. external change) | TC-06, TC-09, TC-10 |
| AC-7 | No wrong-theme flash on cold start | TC-13 |
| AC-8 | Repo/VM/Compose tests pass incl. write-DARK→background hex assertion | TC-11 (plus TC-01..TC-10 as the suite) |
| AC-9 | No network calls; no token/string/color edits; private storage | TC-14, TC-15, TC-16 |
