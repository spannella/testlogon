---
id: AND-081
title: Appearance/theme settings
milestone: M2
epic: E11
priority: P1
size: M
status: draft
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

The goal is strictly local on-device preference plumbing and one screen. It does
**not** sync the theme to the backend (no `/ui/preferences` write for theme),
does not add custom palettes/fonts, and does not modify the AND-019 color tokens.

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
- **Web reference:** `frontend/` has its own appearance handling; there is no
  parity requirement and no shared backend contract for the theme value.
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

**Not applicable — no network contract.** AND-081 stores the theme preference
**device-locally in DataStore** and makes no FastAPI calls. There is no
`/ui/...` request or response associated with this ticket; cookie/CSRF/refresh
plumbing (AND-011/012/013) is untouched.

Server-synced user preferences are owned by **AND-078** (Preferences API DTOs).
If product later wants theme to roam across devices, a follow-up ticket would map
this preference onto the AND-078 preferences payload; that is explicitly out of
scope here, and theme is deliberately kept local to guarantee instant offline
application (the dev backend at `http://18.222.237.167:8000` is unreliable and
must never block applying a theme).

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
