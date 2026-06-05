---
id: AND-079
title: Media preferences
milestone: M2
epic: E11
priority: P1
size: M
status: draft
depends_on: [AND-078]
blocks: []
---

# AND-079 — Media preferences

## 1. Overview & Goal

Implement the **Media preferences** screen that lets a signed-in user view and
edit their media playback settings — **autoplay**, **data saver**, and
**preferred quality** — backed by the FastAPI `/ui/media/preferences` endpoint.
The screen reads the current preferences on entry, renders them as Material 3
toggles/selectors, and persists every change so it survives process death,
relaunch, and is honored by downstream playback features (Media3/ExoPlayer HLS
in the player feature). The single, testable success condition from the backlog
is: **toggles persist and apply.** "Persist" means a change is written through
the preferences repository to the backend (and mirrored locally for offline
read); "apply" means the saved values are surfaced through a single source of
truth (`MediaPreferences` in `core-model`) that the player and download/data
layers consume.

This ticket owns the **feature UI, ViewModel, and persistence wiring** only.
The transport (Retrofit service, DTOs, error mapping, repository contract) is
delivered by **AND-078 — Preferences API + DTOs** and is consumed here as-is.

## 2. Context & References

- **App / package:** `com.testlogon.android`, module
  `feature-settings-media` (new), depending on `core-data`, `core-model`,
  `core-ui`, `core-network`, `core-testing`.
- **Module layering:** `app -> feature-settings-media -> core-*`. No feature →
  feature dependencies.
- **Stack:** Kotlin 2.0.21, Jetpack Compose + Material 3, Navigation-Compose,
  Hilt (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Room
  2.6 + DataStore. minSdk 24, compileSdk/targetSdk 35, JDK 17, AGP 8.7.3,
  Gradle 8.9.
- **Backend:** FastAPI + DynamoDB; dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable). OpenAPI at `/openapi.json`. Cookie-based auth
  with `ui_csrf` echoed as `X-CSRF-Token`; persistent cookie jar; single
  `POST /ui/session/refresh` retry on 401 (provided by the network/auth core).
- **Web reference:** `frontend/src/api/endpoints/preferences.ts` and shared
  types in `frontend/src/api/types.ts` are the canonical shape reference for the
  preferences payload.
- **Dependencies:**
  - **AND-078** (P0) — provides `MediaPreferencesService`, the
    `MediaPreferencesDto`, error mapping, and `MediaPreferencesRepository`.
    This ticket is blocked on AND-078 being merged.
  - **AND-027** (transitively, via AND-078) — network/auth core (cookie jar,
    CSRF header, `ApiResult<T>`, refresh-on-401).
- **Downstream consumers (not in scope here):** the player feature reads
  `MediaPreferences` to gate autoplay, select a starting HLS variant, and
  enforce data-saver bitrate caps.

## 3. Functional Requirements

FR-1. **Load on entry.** On first composition the screen requests the current
preferences via the repository. While loading, show a full-screen loading
state; on success render the form; on failure show an error state with retry.

FR-2. **Autoplay toggle.** A boolean `Switch` labeled "Autoplay" with a
supporting description ("Automatically start the next item"). Default when
unset by the server: `true`.

FR-3. **Data saver toggle.** A boolean `Switch` labeled "Data saver" with a
supporting description ("Reduce data usage on cellular"). Default: `false`.
When enabled, the effective quality ceiling is `LOW` regardless of the
preferred-quality selection (see FR-5); the quality selector remains visible but
shows an inline note that data saver is capping quality.

FR-4. **Preferred quality selector.** A single-choice control (segmented
buttons or a `RadioButton` group inside a list item) over the enum
`AUTO`, `LOW`, `MEDIUM`, `HIGH`. Default: `AUTO`.

FR-5. **Apply semantics.** The persisted, authoritative value exposed to the
rest of the app is the *resolved* preference: `effectiveQuality = if (dataSaver)
LOW else preferredQuality`. The raw user selection is still stored so toggling
data saver off restores the prior choice.

FR-6. **Persist on change.** Every individual control change immediately
triggers a save (optimistic UI: update the visible state instantly, then call
the repository). No explicit "Save" button. If the save fails, revert the
affected control to the last server-confirmed value and surface a transient
error (snackbar).

FR-7. **Survive relaunch.** After a successful save, killing and relaunching the
app shows the saved values without requiring network (read from local mirror),
and a background refresh reconciles with the server.

FR-8. **Auth-gated.** The screen is only reachable for an authenticated session;
an unauthenticated `401` that survives the core refresh-retry navigates the user
to re-auth (handled by the app-level nav, surfaced here as an `Unauthorized`
Ui error).

## 4. Technical Design

New module `feature-settings-media`. Standard MVVM with a unidirectional
`StateFlow<UiState>`.

**UI state**

```kotlin
sealed interface MediaPrefsUiState {
    data object Loading : MediaPrefsUiState
    data class Ready(
        val prefs: MediaPreferences,
        val isSaving: Boolean = false,
        val isStale: Boolean = false,        // showing local mirror, refresh pending/failed
        val transientError: String? = null,  // snackbar text, cleared after shown
    ) : MediaPrefsUiState
    data class Error(val message: String, val retryable: Boolean) : MediaPrefsUiState
}

sealed interface MediaPrefsEvent {
    data class SetAutoplay(val enabled: Boolean) : MediaPrefsEvent
    data class SetDataSaver(val enabled: Boolean) : MediaPrefsEvent
    data class SetQuality(val quality: VideoQuality) : MediaPrefsEvent
    data object Retry : MediaPrefsEvent
    data object DismissError : MediaPrefsEvent
}
```

**Domain model (in `core-model`, introduced/extended by AND-078)**

```kotlin
enum class VideoQuality { AUTO, LOW, MEDIUM, HIGH }

data class MediaPreferences(
    val autoplay: Boolean = true,
    val dataSaver: Boolean = false,
    val preferredQuality: VideoQuality = VideoQuality.AUTO,
) {
    val effectiveQuality: VideoQuality
        get() = if (dataSaver) VideoQuality.LOW else preferredQuality
}
```

**ViewModel**

```kotlin
@HiltViewModel
class MediaPreferencesViewModel @Inject constructor(
    private val repository: MediaPreferencesRepository,   // from AND-078
) : ViewModel() {

    val uiState: StateFlow<MediaPrefsUiState>

    fun onEvent(event: MediaPrefsEvent)

    // internal: optimistic update + persist, revert on failure
    private fun persist(update: (MediaPreferences) -> MediaPreferences)
}
```

`persist` captures the last server-confirmed `MediaPreferences`, applies
`update` optimistically to the `Ready` state, sets `isSaving = true`, calls
`repository.update(newPrefs)`, and on `ApiResult.Error` restores the captured
value and sets `transientError`. Saves are debounced/serialized through a
`Mutex` (or `MutableSharedFlow` with `conflate`) so rapid toggles don't race;
the last-write-wins value is the one persisted.

**Repository contract (owned by AND-078, listed for reference)**

```kotlin
interface MediaPreferencesRepository {
    fun observe(): Flow<MediaPreferences>          // local mirror, hot
    suspend fun refresh(): ApiResult<MediaPreferences>
    suspend fun update(prefs: MediaPreferences): ApiResult<MediaPreferences>
}
```

The ViewModel `combine`s `repository.observe()` (local source of truth) with an
in-flight load/save signal to build `MediaPrefsUiState`. On `init` it launches
`refresh()`; if `refresh()` fails but a local mirror exists, it renders `Ready`
with `isStale = true` rather than `Error`.

**Composable**

```kotlin
@Composable
fun MediaPreferencesRoute(
    viewModel: MediaPreferencesViewModel = hiltViewModel(),
    onUnauthorized: () -> Unit,
)

@Composable
fun MediaPreferencesScreen(
    state: MediaPrefsUiState,
    onEvent: (MediaPrefsEvent) -> Unit,
    snackbarHostState: SnackbarHostState,
)
```

**Navigation** — register a route in the app nav graph:
`const val MEDIA_PREFS_ROUTE = "settings/media"` with a `composable(MEDIA_PREFS_ROUTE)`
entry that wires `onUnauthorized` to the re-auth destination.

## 5. API Contract

Endpoint (FastAPI), all under the authenticated cookie session with
`X-CSRF-Token` on mutations:

**GET `/ui/media/preferences`** → `200`

```json
{
  "autoplay": true,
  "data_saver": false,
  "preferred_quality": "auto"
}
```

**PUT `/ui/media/preferences`** (full replace; body is the desired state) → `200`
returning the persisted resource (same shape as GET).

```json
// request
{ "autoplay": false, "data_saver": true, "preferred_quality": "high" }
// response
{ "autoplay": false, "data_saver": true, "preferred_quality": "high" }
```

> Confirm method (PUT vs PATCH) and exact field names against `/openapi.json`
> and `frontend/src/api/endpoints/preferences.ts` during AND-078; this spec
> assumes snake_case fields and a lowercase quality enum
> (`auto|low|medium|high`). Moshi adapters in AND-078 must map
> `preferred_quality` ⇄ `VideoQuality`.

**Error shape** (FastAPI `detail`, mapped by core): `string` |
`[{ "msg": "...", "loc": [...] }]` | `{ "code": "...", ... }`. `401` triggers
the single `POST /ui/session/refresh` + retry in the core network layer before
surfacing.

DTOs, the Retrofit `MediaPreferencesService`, and the `ApiResult<T>` mapping are
**owned by AND-078**. This ticket only calls `MediaPreferencesRepository`.

## 6. Data & State Management

- **Single source of truth:** `MediaPreferences` exposed via
  `repository.observe()`. The UI never holds long-lived state independent of the
  repository except the transient optimistic overlay during a save.
- **Local mirror:** AND-078 persists the last-known preferences to **DataStore**
  (Proto or Preferences DataStore keyed `media_prefs`). This ticket relies on
  that mirror for FR-7 (offline read + survive relaunch) and does not add its
  own storage.
- **Defaults:** if neither server nor mirror has a value, fall back to the
  `MediaPreferences()` constructor defaults (autoplay=true, dataSaver=false,
  quality=AUTO).
- **Optimistic update + revert:** ViewModel keeps `lastConfirmed:
  MediaPreferences`; on save failure the visible state reverts to it.
- **Quality/data-saver coupling:** raw `preferredQuality` is always stored;
  `effectiveQuality` is computed, never persisted as a separate field, so the
  user's prior choice is restored when data saver is turned off.
- **Process death:** `uiState` is derived from a hot repository Flow, so
  recreation re-derives state without `SavedStateHandle` gymnastics; the
  in-flight `transientError` is non-critical and may be dropped on recreation.

## 7. Error Handling & Resilience

- **Load failure with no mirror:** `Error(message, retryable = true)` with a
  retry button → `MediaPrefsEvent.Retry` → `refresh()`.
- **Load failure with mirror present:** `Ready(isStale = true)`; show a passive
  "Showing saved settings — couldn't reach server" banner; editing is still
  allowed and each edit attempts a save.
- **Save failure:** revert affected control, show snackbar
  ("Couldn't save — tap to retry"); the snackbar action re-issues the save.
- **Timeouts:** rely on the core OkHttp client (~20s call timeout). GET
  `refresh()` is idempotent and uses the core's **bounded backoff retry**; PUT
  `update()` is a mutation and is **not** auto-retried — only the user-driven
  snackbar retry re-attempts it.
- **401:** handled by core (single refresh + retry); if it still fails, map to
  an `Unauthorized` error and invoke `onUnauthorized()`.
- **Validation (422):** map `detail[].msg` to the snackbar; should not occur for
  a well-formed enum/boolean payload, but is surfaced rather than swallowed.
- **Concurrency:** serialize saves via `Mutex`; conflate rapid toggles so only
  the latest state is sent (last-write-wins).

## 8. Security & Privacy

- All requests ride the **existing cookie session**; no credentials are read or
  stored by this feature. The `ui_csrf` cookie → `X-CSRF-Token` header is
  applied by the core OkHttp interceptor on the `PUT`.
- Preferences contain **no PII** (booleans + an enum); safe to mirror in
  DataStore in plaintext. No need for `EncryptedSharedPreferences`.
- Dev backend is **plaintext HTTP**; cleartext is permitted only for the dev
  flavor via the network-security-config established in core-network. No
  preference values are logged at INFO or above (see §10).
- No new permissions. No third-party SDK calls.

## 9. Accessibility & i18n

- All control labels and descriptions come from `strings.xml`
  (`pref_autoplay_title`, `pref_autoplay_desc`, `pref_data_saver_title`,
  `pref_data_saver_desc`, `pref_quality_title`, `pref_quality_auto/low/medium/high`,
  plus error/banner strings). No hardcoded user-facing text.
- Each `Switch` exposes `contentDescription` and a merged semantics node so
  TalkBack reads "Autoplay, on/off". The quality group uses
  `Modifier.selectableGroup()` with `Role.RadioButton` for correct grouping
  announcements.
- Touch targets ≥ 48dp; respect Dynamic Type / font scaling (no fixed-height
  rows that clip). Color is not the sole signal for the data-saver cap note
  (icon + text).
- Layout is RTL-safe (use start/end paddings). Strings are translatable; quality
  enum values are not localized as tokens, only their display labels.

## 10. Telemetry & Logging

- Emit analytics events through the app's existing analytics abstraction (no new
  SDK): `media_pref_changed` with params `{ field: "autoplay|data_saver|quality",
  value, success: Boolean }`, fired after the save resolves. `media_prefs_viewed`
  on screen entry.
- **Do not log preference values at WARN/ERROR with user identifiers.** Save
  failures log the mapped error category (`network|server|unauthorized|validation`)
  at WARN via the core logger, without the request body.
- Loading/refresh outcomes log at DEBUG only (stripped in release).

## 11. Testing Strategy

**Unit (ViewModel, `core-testing` + Turbine + fake repository):**
- Load success → `Loading` then `Ready` with server values.
- Load failure, no mirror → `Error(retryable=true)`; `Retry` re-invokes `refresh`.
- Load failure, mirror present → `Ready(isStale=true)`.
- `SetAutoplay/SetDataSaver/SetQuality` → optimistic `Ready` update + repository
  `update` called with the new `MediaPreferences`.
- Save failure → state reverts to `lastConfirmed`, `transientError` set.
- Data-saver coupling → `effectiveQuality == LOW` when `dataSaver=true`;
  restoring prior `preferredQuality` when toggled off.
- Rapid toggles → only the latest value persisted (conflation/last-write-wins).

**Repository contract is tested in AND-078** (load/save against MockWebServer);
this ticket adds a thin integration test asserting the screen calls
`update()` with the resolved DTO via a `FakeMediaPreferencesRepository`.

**Compose UI tests (`createAndroidComposeRule`):**
- Loading → spinner shown; Ready → all three controls rendered with server state.
- Toggling each control invokes the corresponding `onEvent`.
- Error state shows retry button; stale state shows the banner.
- Accessibility: `assertIsToggleable`, `assertContentDescriptionEquals`,
  radio-group selection semantics.

**Acceptance test (covers backlog "toggles persist and apply"):** toggle each
control, recreate the activity / re-collect from the repository, assert the new
values are present and `effectiveQuality` reflects them.

## 12. Dependencies & Sequencing

- **Blocked by AND-078** (P0) — must provide `MediaPreferencesRepository`,
  `MediaPreferencesDto`, Moshi enum mapping, DataStore mirror, and `ApiResult`
  error mapping. Begin this ticket only after AND-078's repository interface is
  merged (UI can be stubbed against the interface earlier).
- **Transitive:** AND-027 (network/auth core: cookie jar, CSRF, refresh-on-401).
- **Provides to:** the player feature (autoplay gate, starting HLS variant,
  data-saver bitrate cap) consumes `MediaPreferences.effectiveQuality`; that
  wiring lives in the player ticket, not here.
- Add the nav route registration to the app module as part of this ticket.

## 13. Risks & Open Questions

- **R1 — Endpoint shape unconfirmed.** Method (PUT vs PATCH), field naming, and
  the quality enum domain must be verified against `/openapi.json` and
  `preferences.ts`. *Mitigation:* AND-078 confirms and this spec adapts.
- **R2 — Quality enum mismatch.** Backend may use `1080p/720p`-style tokens
  instead of `auto/low/medium/high`. *Mitigation:* keep `VideoQuality` as the
  domain type and isolate mapping in AND-078's DTO adapter.
- **R3 — Data-saver authority.** Whether the *server* should store
  `effective_quality` or only raw fields. *Open question:* this spec stores only
  raw fields and computes effective client-side; confirm playback feature agrees.
- **R4 — Unreliable dev host** may make optimistic-save UX feel flaky.
  *Mitigation:* optimistic UI + local mirror + snackbar retry already cover this.

## 14. Acceptance Criteria

AC-1. Opening the screen loads current preferences from
`/ui/media/preferences` and renders Autoplay, Data saver, and Preferred quality
controls reflecting server values (or local mirror when offline).
AC-2. Changing any control updates the UI immediately and persists via
`repository.update(...)` (a `PUT /ui/media/preferences` with the full resolved
payload). **(backlog: toggles persist)**
AC-3. After a successful change, killing and relaunching the app shows the saved
values without requiring network. **(backlog: toggles persist)**
AC-4. `MediaPreferences.effectiveQuality` returns `LOW` whenever data saver is
on, and the player/data layer observe the updated value through
`repository.observe()`. **(backlog: toggles apply)**
AC-5. A failed save reverts the affected control to the last confirmed value and
shows a retryable snackbar; a failed initial load with no mirror shows a
retryable error state.
AC-6. All controls are TalkBack-operable with correct on/off and selected
announcements; all user-facing text is from `strings.xml`.
AC-7. No preference values or credentials are logged at WARN/ERROR.

## 15. Definition of Done

- `feature-settings-media` module created, wired into the app nav graph at
  `settings/media`, and consuming `MediaPreferencesRepository` from AND-078.
- ViewModel, UI state/events, and Composables implemented per §4 with optimistic
  save + revert and stale/offline handling.
- Unit, Compose UI, and acceptance tests in §11 pass in CI; line coverage for
  the ViewModel ≥ 80%.
- Strings externalized; accessibility checks (§9) pass; no hardcoded text.
- Analytics events (§10) emitted; no value/credential logging.
- `./gradlew :feature-settings-media:detekt ktlintCheck testDebugUnitTest
  connectedDebugAndroidTest` green; PR merged to `android-port` with the spec
  linked.
