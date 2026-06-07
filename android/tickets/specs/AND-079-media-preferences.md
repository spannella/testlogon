---
id: AND-079
title: Media preferences
milestone: M2
epic: E11
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-078]
blocks: []
---

# AND-079 — Media preferences

## 1. Overview & Goal

> **REVIEW CORRECTION (major):** The original draft described this screen as a
> *media playback* preferences screen (autoplay / data saver / HLS quality
> `auto|low|medium|high`). That is **wrong**. Verified against the backend
> OpenAPI (`GET|PUT /ui/media/preferences`, schemas `MediaPreferencesIn` /
> `MediaPreferencesOut`) and the web reference (`src/api/endpoints/mediaPreferences.ts`,
> `src/pages/calls/MediaSettingsPage.tsx`, `src/api/types.ts`), this endpoint is
> the **WebRTC call media settings** resource: preferred audio/video **devices**,
> default-muted / default-video-off call behavior, and a **call video
> resolution** preference. There is no autoplay, no data-saver, and no HLS
> quality enum on this endpoint. The spec below has been corrected throughout.

Implement the **Media preferences** screen that lets a signed-in user view and
edit their **call media settings** — preferred **microphone**, **camera**, and
**speaker** devices, **start-muted** and **start-with-video-off** defaults, and a
preferred **call video resolution** — backed by the FastAPI
`/ui/media/preferences` endpoint. The screen reads the current preferences on
entry, renders them as Material 3 selectors/toggles, lets the user test devices,
and persists changes so they survive process death and relaunch and are honored
by the WebRTC call feature when joining/starting a call. The single, testable
success condition from the backlog is: **toggles persist and apply.** "Persist"
means the values are written through the preferences repository to the backend
(and mirrored locally for offline read); "apply" means the saved values are
surfaced through a single source of truth (`MediaPreferences` in `core-model`)
that the call/WebRTC layer consumes when configuring local tracks.

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
- **Web reference (corrected):** `frontend/src/api/endpoints/mediaPreferences.ts`
  (the `getMediaPreferences` / `saveMediaPreferences` calls), the screen
  `frontend/src/pages/calls/MediaSettingsPage.tsx`, and the shared DTOs
  `MediaPreferencesIn` / `MediaPreferencesOut` in `frontend/src/api/types.ts` are
  the canonical shape reference for the payload. (The original spec cited
  `preferences.ts`, which is a different, unrelated endpoint.)
- **Dependencies:**
  - **AND-078** (P0) — provides `MediaPreferencesService`, the
    `MediaPreferencesDto`, error mapping, and `MediaPreferencesRepository`.
    This ticket is blocked on AND-078 being merged.
  - **AND-027** (transitively, via AND-078) — network/auth core (cookie jar,
    CSRF header, `ApiResult<T>`, refresh-on-401).
- **Downstream consumers (not in scope here):** the WebRTC call feature reads
  `MediaPreferences` to pick the default capture devices, apply start-muted /
  start-video-off on join, and request the preferred capture resolution.

## 3. Functional Requirements

> **REVIEW CORRECTION:** FR-2..FR-6 below were rewritten to match the verified
> `MediaPreferencesIn` / `MediaPreferencesOut` schema (devices + call-default
> toggles + `video_resolution`). The original autoplay / data-saver / quality-enum
> requirements did not correspond to any field on this endpoint.

FR-1. **Load on entry.** On first composition the screen requests the current
preferences via the repository. While loading, show a full-screen loading
state; on success render the form; on failure show an error state with retry.

FR-2. **Default-muted toggle.** A boolean `Switch` labeled "Start calls muted"
mapping to `default_audio_muted` (server default `false`). Description: "Join
calls with your microphone off."

FR-3. **Default-video-off toggle.** A boolean `Switch` labeled "Start video
calls with camera off" mapping to `default_video_off` (server default `false`).

FR-4. **Preferred device selectors.** Three single-choice selectors backed by
the device enumeration (Android `AudioManager` / `Camera2`/CameraX or the WebRTC
device list provided by the call core): microphone → `preferred_audio_input_id`,
camera → `preferred_video_input_id`, speaker → `preferred_audio_output_id`. Each
is a nullable string device id; `null`/empty means "system default". Device
labels require runtime permissions to populate (see §8); selecting "Default"
persists `null`.

FR-5. **Call video resolution selector.** A single-choice control over the
verified enum `"360" | "480" | "720" | "1080"` (mapping to display labels
"360p (Low)", "480p (Medium)", "720p (HD)", "1080p (Full HD)"), backed by
`video_resolution`. Server default: `"720"`.

FR-6. **Persist (Save).** The web reference batches all fields into a single
`PUT` behind an explicit **"Save Preferences"** button (`saveMediaPreferences`).
This spec follows the same model: edits update local form state; a **Save**
action sends one `PUT` with the full `MediaPreferencesIn` body. *(Decision: keep
explicit Save to mirror web behavior and because device-id changes should not
fire a network call on every dropdown open. Optimistic per-toggle save is an
alternative but is NOT what the web client does — see §13 R3.)* On success show a
confirmation; on failure keep edits in the form and surface a retryable error.

FR-7. **Survive relaunch.** After a successful save, killing and relaunching the
app shows the saved values without requiring network (read from local mirror),
and a background refresh reconciles with the server.

FR-8. **Auth-gated.** The screen is only reachable for an authenticated session;
a `401` that survives the core refresh-retry navigates the user to re-auth
(handled by the app-level nav, surfaced here as an `Unauthorized` Ui error). Note
the OpenAPI declares only `200`/`422` for these operations; `401` is enforced by
the shared session middleware/transport, not declared per-operation.

## 4. Technical Design

New module `feature-settings-media`. Standard MVVM with a unidirectional
`StateFlow<UiState>`.

**UI state**

```kotlin
sealed interface MediaPrefsUiState {
    data object Loading : MediaPrefsUiState
    data class Ready(
        val prefs: MediaPreferences,         // current (possibly edited) form values
        val saved: MediaPreferences,         // last server-confirmed values
        val availableDevices: MediaDevices,  // enumerated mics/cameras/speakers
        val isDirty: Boolean = false,        // form differs from `saved`
        val isSaving: Boolean = false,
        val isStale: Boolean = false,        // showing local mirror, refresh pending/failed
        val transientError: String? = null,  // snackbar text, cleared after shown
    ) : MediaPrefsUiState
    data class Error(val message: String, val retryable: Boolean) : MediaPrefsUiState
}

sealed interface MediaPrefsEvent {
    data class SetDefaultMuted(val enabled: Boolean) : MediaPrefsEvent
    data class SetDefaultVideoOff(val enabled: Boolean) : MediaPrefsEvent
    data class SetMicrophone(val deviceId: String?) : MediaPrefsEvent
    data class SetCamera(val deviceId: String?) : MediaPrefsEvent
    data class SetSpeaker(val deviceId: String?) : MediaPrefsEvent
    data class SetResolution(val resolution: VideoResolution) : MediaPrefsEvent
    data object Save : MediaPrefsEvent
    data object Retry : MediaPrefsEvent
    data object DismissError : MediaPrefsEvent
}
```

**Domain model (in `core-model`, introduced/extended by AND-078)**

```kotlin
// Verified enum from MediaPreferencesIn.video_resolution: "360"|"480"|"720"|"1080"
enum class VideoResolution(val wire: String) {
    P360("360"), P480("480"), P720("720"), P1080("1080");
    companion object { fun fromWire(s: String?) = entries.firstOrNull { it.wire == s } ?: P720 }
}

data class MediaPreferences(
    val preferredAudioInputId: String? = null,   // preferred_audio_input_id
    val preferredVideoInputId: String? = null,   // preferred_video_input_id
    val preferredAudioOutputId: String? = null,  // preferred_audio_output_id
    val defaultAudioMuted: Boolean = false,      // default_audio_muted
    val defaultVideoOff: Boolean = false,        // default_video_off
    val videoResolution: VideoResolution = VideoResolution.P720, // video_resolution, server default "720"
)

// Out-only fields (read, not editable): user_sub (required), updated_at, plus
// ad/affiliate fields (affiliate_link_id, campaign_id, click_url, fill_reason,
// impression_url, is_house_ad, promo_code_id, skip_after_seconds, skip_url) that
// this feature ignores. AND-078 maps only the editable fields into MediaPreferences.

// Locally enumerated capture/playback devices (NOT from the API):
data class MediaDevices(
    val microphones: List<MediaDevice> = emptyList(),
    val cameras: List<MediaDevice> = emptyList(),
    val speakers: List<MediaDevice> = emptyList(),
)
data class MediaDevice(val id: String, val label: String)
```

**ViewModel**

```kotlin
@HiltViewModel
class MediaPreferencesViewModel @Inject constructor(
    private val repository: MediaPreferencesRepository,   // from AND-078
) : ViewModel() {

    val uiState: StateFlow<MediaPrefsUiState>

    fun onEvent(event: MediaPrefsEvent)

    // internal: send the full edited form to the backend on Save
    private fun save()
}
```

Edit events (`SetDefaultMuted`, `SetCamera`, `SetResolution`, …) only mutate the
in-memory `Ready.prefs` and recompute `isDirty = prefs != saved`. The `Save`
event sets `isSaving = true`, calls `repository.update(prefs)` (one `PUT`), and
on `ApiResult.Success` updates `saved` to the server echo and clears `isDirty`;
on `ApiResult.Error` keeps the edited form, clears `isSaving`, and sets
`transientError`. Concurrent saves are guarded by an in-flight flag / `Mutex` so
a second tap while a `PUT` is pending is ignored or queued (last form wins).

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

> **REVIEW CORRECTION:** the payloads below were rewritten to the VERIFIED
> schemas. Operations: `GET /ui/media/preferences`
> (`op=ui_get_media_preferences_…`, resp `200:MediaPreferencesOut`) and
> `PUT /ui/media/preferences` (`op=ui_save_media_preferences_…`,
> req `MediaPreferencesIn`, resp `200:MediaPreferencesOut`). PUT (not PATCH) is
> confirmed. Only `200` and `422:HTTPValidationError` are declared.

**GET `/ui/media/preferences`** → `200` (`MediaPreferencesOut`)

```json
{
  "user_sub": "auth0|abc123",
  "preferred_audio_input_id": null,
  "preferred_video_input_id": null,
  "preferred_audio_output_id": null,
  "default_audio_muted": false,
  "default_video_off": false,
  "video_resolution": "720",
  "updated_at": 0
}
```
(`MediaPreferencesOut` also includes ad/affiliate fields — `affiliate_link_id`,
`campaign_id`, `click_url`, `fill_reason`, `impression_url`, `is_house_ad`,
`promo_code_id`, `skip_after_seconds`, `skip_url` — which this feature ignores.
`user_sub` is the only `required` field.)

**PUT `/ui/media/preferences`** (`MediaPreferencesIn`; full desired state) → `200`
returning `MediaPreferencesOut`.

```json
// request body (MediaPreferencesIn — all fields optional; server defaults apply)
{
  "preferred_audio_input_id": "mic-2",
  "preferred_video_input_id": "cam-1",
  "preferred_audio_output_id": null,
  "default_audio_muted": true,
  "default_video_off": false,
  "video_resolution": "1080"
}
```

`video_resolution` is a string enum constrained to `"360" | "480" | "720" |
"1080"` (default `"720"`). Moshi adapters in AND-078 map `video_resolution` ⇄
`VideoResolution` and the snake_case device-id/boolean fields ⇄ `MediaPreferences`.

**Error shape (422)** = `HTTPValidationError` = `{ "detail": ValidationError[] }`
where `ValidationError = { "loc": (string|int)[], "msg": string, "type": string }`
(verified `components.schemas.HTTPValidationError` / `ValidationError`). `401`
(not declared on these operations but enforced by session middleware) triggers
the single `POST /ui/session/refresh` + one retry in the core network layer
before surfacing.

DTOs, the Retrofit `MediaPreferencesService`, and the `ApiResult<T>` mapping are
**owned by AND-078**. This ticket only calls `MediaPreferencesRepository`.

## 6. Data & State Management

- **Single source of truth (confirmed values):** `MediaPreferences` exposed via
  `repository.observe()`. The editable form overlay (`prefs`) is short-lived and
  collapses back to the confirmed values after a successful Save.
- **Local mirror:** AND-078 persists the last-known preferences to **DataStore**
  (Proto or Preferences DataStore keyed `media_prefs`). This ticket relies on
  that mirror for FR-7 (offline read + survive relaunch) and does not add its
  own storage.
- **Defaults:** if neither server nor mirror has a value, fall back to the
  `MediaPreferences()` constructor defaults (devices=null/default,
  defaultAudioMuted=false, defaultVideoOff=false, videoResolution=P720) — these
  match the verified server defaults.
- **Form vs confirmed:** ViewModel keeps `saved: MediaPreferences` (last server
  echo) and the editable `prefs`; `isDirty = prefs != saved`. On save failure the
  form is preserved (web parity) so the user can retry without re-entering.
- **Device enumeration:** `availableDevices` is sourced locally (Android device
  APIs / WebRTC), NOT from the backend; only the chosen device ids are persisted.
  A persisted device id that is no longer present resolves to "Default" in the UI.
- **Process death:** `uiState` is derived from a hot repository Flow for the
  confirmed values; in-flight edits in the form should be retained via
  `SavedStateHandle` (or saved-on-change) so unsaved edits are not lost on
  recreation. The transient `transientError` is non-critical and may be dropped.

## 7. Error Handling & Resilience

- **Load failure with no mirror:** `Error(message, retryable = true)` with a
  retry button → `MediaPrefsEvent.Retry` → `refresh()`.
- **Load failure with mirror present:** `Ready(isStale = true)`; show a passive
  "Showing saved settings — couldn't reach server" banner; editing is still
  allowed and Save retries the network.
- **Save failure:** keep the edited form, show snackbar
  ("Couldn't save — tap to retry"); the snackbar action / Save button re-issues
  the same `PUT`.
- **Timeouts:** rely on the core OkHttp client (~20s call timeout). GET
  `refresh()` is idempotent and uses the core's **bounded backoff retry**; the
  `PUT` is a mutation and is **not** auto-retried — only user-driven Save/snackbar
  retry re-attempts it (the `PUT` is a full-state replace, so re-sending is safe).
- **401:** handled by core (single refresh + retry); if it still fails, map to
  an `Unauthorized` error and invoke `onUnauthorized()`. (Not declared per-op in
  OpenAPI; enforced by session middleware.)
- **Validation (422 = `HTTPValidationError`):** map `detail[].msg` to the
  snackbar; should not occur for a well-formed payload (booleans + the constrained
  `video_resolution` enum + opaque device-id strings), but is surfaced rather than
  swallowed. An out-of-range `video_resolution` is the most likely trigger.
- **Concurrency:** guard saves with an in-flight flag / `Mutex` so a second Save
  while a `PUT` is pending is ignored or coalesced (last submitted form wins).

## 8. Security & Privacy

- All requests ride the **existing cookie session**; no credentials are read or
  stored by this feature. The `ui_csrf` cookie → `X-CSRF-Token` header is applied
  by the core OkHttp interceptor on the `PUT` (verified: web `client.ts` reads the
  `ui_csrf` cookie and sets `X-CSRF-Token` on every request, `credentials:
  include`). Requests also flow through `X-SESSION-ID` (and optional
  `X-IMPERSONATION-TOKEN`) per the OpenAPI param list; these are supplied by core.
- Preferences contain **no high-sensitivity PII** (booleans, a resolution enum,
  and opaque device-id strings); safe to mirror in DataStore in plaintext. No
  `EncryptedSharedPreferences` required.
- **REVIEW CORRECTION — permissions:** the original "No new permissions" claim is
  inaccurate for the native port. To enumerate real microphone/camera device
  *labels* and to run the camera-preview / mic-level **Test** affordances (parity
  with the web `MediaSettingsPage`), Android requires the runtime permissions
  **`CAMERA`** and **`RECORD_AUDIO`**. Persisting preferences alone (the core
  GET/PUT) needs no permission, but device labels show as generic / "Default"
  until granted, mirroring the web "Grant permission first to see device labels"
  behavior. Handle denial gracefully (still allow saving).
- Dev backend is **plaintext HTTP**; cleartext is permitted only for the dev
  flavor via the network-security-config established in core-network. No
  preference values are logged at INFO or above (see §10).
- No third-party SDK calls.

## 9. Accessibility & i18n

- All control labels and descriptions come from `strings.xml`
  (`pref_start_muted_title/desc`, `pref_video_off_title/desc`, `pref_mic_title`,
  `pref_camera_title`, `pref_speaker_title`, `pref_resolution_title`,
  `pref_resolution_360/480/720/1080`, `pref_device_default`, plus
  permission/error/banner strings). No hardcoded user-facing text.
- Each `Switch` exposes `contentDescription` and a merged semantics node so
  TalkBack reads e.g. "Start calls muted, on/off". The resolution group uses
  `Modifier.selectableGroup()` with `Role.RadioButton` for correct grouping
  announcements; device dropdowns expose the selected device label.
- Touch targets ≥ 48dp; respect Dynamic Type / font scaling (no fixed-height
  rows that clip). Color is not the sole signal for permission/error states
  (icon + text).
- Layout is RTL-safe (use start/end paddings). Strings are translatable;
  resolution enum wire values (`360/480/720/1080`) are not localized as tokens,
  only their display labels ("360p (Low)", etc.).

## 10. Telemetry & Logging

- Emit analytics events through the app's existing analytics abstraction (no new
  SDK): `media_prefs_saved` with params `{ changed_fields:
  [default_audio_muted|default_video_off|mic|camera|speaker|video_resolution],
  success: Boolean }`, fired after the `PUT` resolves. `media_prefs_viewed`
  on screen entry. Do not log raw device ids as analytics values.
- **Do not log preference values at WARN/ERROR with user identifiers.** Save
  failures log the mapped error category (`network|server|unauthorized|validation`)
  at WARN via the core logger, without the request body.
- Loading/refresh outcomes log at DEBUG only (stripped in release).

## 11. Testing Strategy

**Unit (ViewModel, `core-testing` + Turbine + fake repository):**
- Load success → `Loading` then `Ready` with server values (devices/toggles/
  resolution).
- Load failure, no mirror → `Error(retryable=true)`; `Retry` re-invokes `refresh`.
- Load failure, mirror present → `Ready(isStale=true)`.
- Edit events (`SetDefaultMuted/SetDefaultVideoOff/SetMic/SetCamera/SetSpeaker/
  SetResolution`) → `Ready.prefs` updated, `isDirty=true`, no network until `Save`.
- `Save` → `repository.update` called once with the full `MediaPreferences`; on
  success `saved` updated, `isDirty=false`.
- Save failure → form preserved, `isSaving=false`, `transientError` set.
- Concurrent Save while pending → second call ignored/coalesced.

**Repository contract is tested in AND-078** (load/save against MockWebServer);
this ticket adds a thin contract test asserting the screen serializes the full
resolved `MediaPreferencesIn` DTO (snake_case fields, `video_resolution` wire
value) via a `FakeMediaPreferencesRepository` or MockWebServer.

**Compose UI tests (`createAndroidComposeRule`):**
- Loading → spinner shown; Ready → both toggles, three device selectors, and the
  resolution selector rendered with server state.
- Editing each control invokes the corresponding `onEvent`; Save invokes `Save`.
- Error state shows retry button; stale state shows the banner.
- Accessibility: `assertIsToggleable`, `assertContentDescriptionEquals`,
  radio-group selection semantics for resolution.

**Acceptance test (covers backlog "toggles persist and apply"):** edit toggles +
resolution + a device, Save, recreate the activity / re-collect from the
repository, assert the saved values are present.

## 12. Dependencies & Sequencing

- **Blocked by AND-078** (P0) — must provide `MediaPreferencesRepository`,
  `MediaPreferencesDto`, Moshi enum mapping, DataStore mirror, and `ApiResult`
  error mapping. Begin this ticket only after AND-078's repository interface is
  merged (UI can be stubbed against the interface earlier).
- **Transitive:** AND-027 (network/auth core: cookie jar, CSRF, refresh-on-401).
- **Provides to:** the WebRTC call feature consumes `MediaPreferences` (preferred
  capture devices, start-muted / start-video-off, capture resolution) when
  configuring local tracks on join; that wiring lives in the call ticket, not here.
- Add the nav route registration to the app module as part of this ticket.

## 13. Risks & Open Questions

- **R1 — Endpoint shape (RESOLVED in review).** Verified against OpenAPI and the
  web client: `PUT` (not PATCH), snake_case fields, `video_resolution` enum
  `360|480|720|1080`. No further confirmation needed; AND-078 implements as
  specified in §5.
- **R2 — Device enumeration source.** Device ids/labels are produced by Android
  (`AudioManager`, CameraX/Camera2) or the WebRTC device list, NOT the API. *Open
  question:* whether ids persisted by the web client (browser `deviceId`s) are
  meaningfully portable to Android — likely not. *Mitigation:* treat unknown ids
  as "Default"; coordinate id semantics with the call feature.
- **R3 — Save UX: explicit Save vs optimistic.** Web uses an explicit Save
  button with a batched `PUT` (verified in `MediaSettingsPage.tsx`). This spec
  follows that for parity and to avoid per-dropdown network calls. *Open
  question:* product may prefer auto-save per control on mobile; revisit if so.
- **R4 — Unreliable dev host** may make Save feel flaky. *Mitigation:* the `PUT`
  is a full-state idempotent replace, so Save/snackbar retry is safe; local
  mirror keeps the screen usable offline.
- **R5 — Out-only ad fields in `MediaPreferencesOut`.** The response carries
  ad/affiliate fields unrelated to user prefs; AND-078 must not surface or persist
  them. Confirm they are server-managed and never round-tripped on `PUT`.

## 14. Acceptance Criteria

AC-1. Opening the screen loads current preferences from `GET /ui/media/preferences`
(`MediaPreferencesOut`) and renders the Start-muted and Start-video-off toggles,
the microphone/camera/speaker device selectors, and the video-resolution selector
reflecting server values (or local mirror when offline).
AC-2. Editing controls and tapping **Save** persists via `repository.update(...)`
— a single `PUT /ui/media/preferences` carrying the full `MediaPreferencesIn`
body (snake_case fields; `video_resolution` ∈ `360|480|720|1080`). On success the
server echo (`MediaPreferencesOut`) becomes the confirmed state. **(backlog: toggles persist)**
AC-3. After a successful Save, killing and relaunching the app shows the saved
values without requiring network (local mirror). **(backlog: toggles persist)**
AC-4. The saved `MediaPreferences` (devices, start-muted/video-off, resolution)
is observable by the call/WebRTC layer through `repository.observe()` and is the
value used when configuring local tracks. **(backlog: toggles apply)**
AC-5. A failed Save preserves the edited form and shows a retryable snackbar; a
failed initial load with no mirror shows a retryable error state; a load failure
with a mirror shows the stale banner and still allows editing/Save.
AC-6. All controls are TalkBack-operable with correct on/off and selected
announcements; all user-facing text is from `strings.xml`.
AC-7. No preference values, device ids, or credentials are logged at WARN/ERROR.
AC-8. The screen requests `CAMERA`/`RECORD_AUDIO` only for device labels/test
affordances; with permissions denied, the screen still loads and Save still works
(device pickers show "Default").

## 15. Definition of Done

- `feature-settings-media` module created, wired into the app nav graph at
  `settings/media`, and consuming `MediaPreferencesRepository` from AND-078.
- ViewModel, UI state/events, and Composables implemented per §4 with explicit
  Save (batched `PUT`), dirty tracking, and stale/offline handling.
- Unit, Compose UI, and acceptance tests in §11 pass in CI; line coverage for
  the ViewModel ≥ 80%.
- Strings externalized; accessibility checks (§9) pass; no hardcoded text.
- Analytics events (§10) emitted; no value/credential logging.
- `./gradlew :feature-settings-media:detekt ktlintCheck testDebugUnitTest
  connectedDebugAndroidTest` green; PR merged to `android-port` with the spec
  linked.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **Endpoints are `GET` and `PUT /ui/media/preferences`.** — **Verified.**
   OpenAPI index: `GET /ui/media/preferences | op=ui_get_media_preferences_… |
   resp=200:MediaPreferencesOut;422:HTTPValidationError` and `PUT
   /ui/media/preferences | op=ui_save_media_preferences_… | req=MediaPreferencesIn
   | resp=200:MediaPreferencesOut;422:HTTPValidationError`. Web:
   `src/api/endpoints/mediaPreferences.ts` (`api.get`/`api.put`).
2. **Method is PUT, not PATCH.** — **Corrected/Verified.** Original draft hedged
   PUT-vs-PATCH; OpenAPI confirms `PUT`. Source: `PUT /ui/media/preferences`.
3. **This is a WebRTC *call* media-settings resource, not a playback/HLS
   resource.** — **Corrected.** Original draft described autoplay/data-saver/HLS
   quality. Source: schema fields below; `src/pages/calls/MediaSettingsPage.tsx`
   (doc comment: "manage camera/mic/speaker preferences for WebRTC calls"); web
   types comment `Media Preferences (CALL-003)` in `src/api/types.ts`.
4. **`MediaPreferencesIn` fields = `preferred_audio_input_id?`,
   `preferred_video_input_id?`, `preferred_audio_output_id?` (nullable strings),
   `default_audio_muted` (bool, default false), `default_video_off` (bool, default
   false), `video_resolution` (enum, default "720").** — **Corrected/Verified.**
   Source: `components.schemas.MediaPreferencesIn` (openapi.pretty.json);
   `src/api/types.ts: MediaPreferencesIn`.
5. **`video_resolution` enum = `"360" | "480" | "720" | "1080"`, default
   `"720"`.** — **Corrected/Verified.** Original claimed `auto|low|medium|high`.
   Source: `MediaPreferencesIn.video_resolution.enum` (openapi.pretty.json);
   `src/api/types.ts: MediaPreferencesIn`; `MediaSettingsPage.tsx` `<SelectItem>`
   values 360/480/720/1080.
6. **`MediaPreferencesOut` adds `user_sub` (required), `updated_at` (int), and
   ad/affiliate fields (`affiliate_link_id`, `campaign_id`, `click_url`,
   `fill_reason`, `impression_url`, `is_house_ad`, `promo_code_id`,
   `skip_after_seconds`, `skip_url`).** — **Verified.** Source:
   `components.schemas.MediaPreferencesOut` (openapi.pretty.json). The web
   `MediaPreferencesOut` interface omits the ad fields (only reads the editable
   ones) — `src/api/types.ts: MediaPreferencesOut`.
7. **No `autoplay`, no `data_saver`, no `preferred_quality`/`effective_quality`
   fields exist.** — **Corrected.** Source: full `MediaPreferencesIn`/`Out`
   schemas (openapi.pretty.json) — absent. Removed `effectiveQuality` domain logic.
8. **Web reference file is `src/api/endpoints/mediaPreferences.ts` (not
   `preferences.ts`); screen is `src/pages/calls/MediaSettingsPage.tsx`.** —
   **Corrected.** Source: file listing under `reference/src/api/endpoints/` and
   grep of `getMediaPreferences`/`saveMediaPreferences`.
9. **Auth/CSRF: cookie session with `ui_csrf` echoed as `X-CSRF-Token` on all
   requests; `credentials: include`.** — **Verified.** Source: `src/api/client.ts`
   (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`; `credentials:
   "include"`).
10. **Single `POST /ui/session/refresh` + one retry on 401.** — **Verified.**
    Source: `src/api/client.ts` `refreshSession()` (`POST /ui/session/refresh`)
    and the `res.status === 401` branch that refreshes once then retries the
    original request exactly once. OpenAPI: `POST /ui/session/refresh`.
11. **Error shape for 422 = `HTTPValidationError { detail: ValidationError[] }`,
    `ValidationError { loc, msg, type }`.** — **Verified.** Source:
    `components.schemas.HTTPValidationError` and `…ValidationError`
    (openapi.pretty.json). Web `normalizeErrorDetail` reads `detail[].msg` —
    `src/api/client.ts`.
12. **401 is enforced by middleware, not declared per-operation.** — **Verified.**
    Source: the media index lines declare only `200`/`422`; refresh-on-401 is
    handled transport-side in `client.ts`.
13. **Web persistence uses an explicit Save button with one batched `PUT`
    (not per-control optimistic save).** — **Corrected.** Original draft mandated
    optimistic per-toggle save with no Save button. Source:
    `MediaSettingsPage.tsx` `handleSave` → `saveMutation.mutate({...all fields})`
    bound to a single "Save Preferences" `<Button>`.
14. **Device labels require runtime camera/mic permission.** — **Verified
    (web) + framework ref.** Web: `MediaSettingsPage.tsx`
    (`navigator.permissions.query`, "Grant permission first to see device
    labels"). Android equivalent permissions `CAMERA` / `RECORD_AUDIO`: framework
    ref https://developer.android.com/training/permissions/requesting and
    https://developer.android.com/media/camera/camerax (device enumeration).
15. **DataStore for the offline mirror.** — **Unverified-assumption (Android
    design choice).** Not in sources; AND-078's chosen persistence. Framework ref:
    https://developer.android.com/topic/libraries/architecture/datastore.
16. **Nav route `settings/media`.** — **Unverified-assumption.** Web mounts the
    page under `calls/`; the Android route path is a local design choice, not
    derived from any source.

### Corrections made

- **Feature reframed** from media *playback* (autoplay / data-saver / HLS
  quality) to **WebRTC call media settings** (devices + start-muted/video-off +
  call `video_resolution`) — §1, §2, §3, §4, §5, §6, §9, §10, §12, §14 (claims
  3, 7).
- **Quality enum** `auto|low|medium|high` → `360|480|720|1080` string enum;
  removed `effectiveQuality`/data-saver coupling (claims 5, 7).
- **Domain model** `MediaPreferences` rewritten to the verified fields; added
  `VideoResolution` enum and local `MediaDevices` (claims 4, 6).
- **Save model** optimistic-per-control → explicit Save + batched `PUT`,
  preserve-form-on-failure (claim 13).
- **Web reference path** `preferences.ts` → `mediaPreferences.ts` /
  `calls/MediaSettingsPage.tsx` (claim 8).
- **Permissions** "No new permissions" → requires `CAMERA`/`RECORD_AUDIO` for
  device labels/test (claim 14); §8.
- **Error/response detail** clarified to verified `HTTPValidationError` shape and
  `200/422`-only declaration (claims 11, 12).

### Open assumptions

- **DataStore mirror** (claim 15) — implementation detail owned by AND-078, not
  specified by any source.
- **`settings/media` route** (claim 16) — Android nav choice; web uses `calls/`.
- **Device-id portability** — whether persisted device ids are meaningful across
  web/Android is unverifiable from sources (R2); web stores opaque browser
  `deviceId`s. Treat unknown ids as "Default".
- **Ad/affiliate Out fields semantics** — assumed server-managed and never
  round-tripped on `PUT` (R5); not stated in sources.
- **Server defaults when unset** — taken from schema `default` values
  (`false`/`false`/`"720"`); behavior for a brand-new user with no stored row is
  inferred, not documented.

## 17. Test Plan

Test-target legend: **JVM** = local JVM/Robolectric (no device); **emu35** =
headless emulator AVD `test35` (x86_64, API 35); **A15** = physical Samsung
Galaxy A15 5G (SM-A156U, API 34, arm64-v8a) reachable via adb. Hardware
mic/camera cases MUST run on **A15** (the emulator has no real capture devices).

- **TC-AND-079-01** — Type: contract/MockWebServer. Target: JVM.
  Preconditions: MockWebServer enqueues `200` with a `MediaPreferencesOut` body
  (`default_audio_muted=true`, `video_resolution="1080"`, device ids set).
  Steps: open screen → ViewModel calls `GET /ui/media/preferences`. Expected:
  request path/method correct; `X-CSRF-Token` header present from cookie jar;
  `Ready` state maps booleans, device ids, and `video_resolution`→`P1080`.
  Traces: AC-1.
- **TC-AND-079-02** — Type: contract/MockWebServer. Target: JVM.
  Preconditions: loaded `Ready` state. Steps: toggle start-muted, pick resolution
  720, tap Save → assert one `PUT /ui/media/preferences`; inspect recorded body.
  Expected: exactly one `PUT`, JSON is full `MediaPreferencesIn` with snake_case
  keys and `"video_resolution":"720"`; `X-CSRF-Token` set; on `200` echo,
  `isDirty=false`. Traces: AC-2.
- **TC-AND-079-03** — Type: unit. Target: JVM. Preconditions: fake repository.
  Steps: emit edit events without Save. Expected: `Ready.prefs` updates,
  `isDirty=true`, repository `update` NOT called until `Save`. Traces: AC-2.
- **TC-AND-079-04** — Type: integration. Target: emu35. Preconditions: fake
  repository persisting to the DataStore mirror; save succeeds. Steps: edit +
  Save, then simulate process death (`activityScenario.recreate()`) with network
  disabled. Expected: saved values render from the mirror, no network call needed.
  Traces: AC-3.
- **TC-AND-079-05** — Type: unit. Target: JVM. Preconditions: repository
  `observe()` flow. Steps: Save succeeds with new devices/toggles/resolution →
  collect `observe()`. Expected: downstream observer receives the updated
  `MediaPreferences` (the value the call layer would consume). Traces: AC-4.
- **TC-AND-079-06** — Type: contract/MockWebServer. Target: JVM. Preconditions:
  MockWebServer returns `422` with
  `{"detail":[{"loc":["body","video_resolution"],"msg":"value is not a valid
  enumeration member","type":"type_error.enum"}]}`. Steps: Save. Expected: form
  preserved, `isSaving=false`, `transientError` shows the mapped `detail[].msg`;
  no crash. Traces: AC-5.
- **TC-AND-079-07** — Type: contract/MockWebServer. Target: JVM. Preconditions:
  initial `GET` fails (e.g. `500`/timeout) with NO local mirror. Steps: open
  screen. Expected: `Error(retryable=true)`; `Retry` re-issues `GET` and on `200`
  renders `Ready`. Traces: AC-5.
- **TC-AND-079-08** — Type: integration. Target: emu35. Preconditions: mirror has
  values; initial `GET` fails (flaky dev host / offline). Steps: open screen.
  Expected: `Ready(isStale=true)` with the stale banner; editing + Save still
  allowed and Save retries the network. Traces: AC-1, AC-5.
- **TC-AND-079-09** — Type: contract/MockWebServer. Target: JVM. Preconditions:
  authenticated session; first `GET`/`PUT` returns `401`. Steps: trigger request.
  Expected: core issues exactly one `POST /ui/session/refresh` then retries once;
  if retry still `401`, surfaces `Unauthorized` and `onUnauthorized()` is invoked.
  Traces: AC-2, AC-5.
- **TC-AND-079-10** — Type: Compose-UI. Target: emu35. Preconditions: injected
  `Ready` state. Steps: assert both `Switch`es, three device selectors, and the
  resolution radio group render with the injected values; toggling/selecting fires
  the right `onEvent`; tapping Save fires `Save`. Expected: all assertions pass;
  Loading shows a spinner. Traces: AC-1, AC-2.
- **TC-AND-079-11** — Type: Compose-UI (accessibility). Target: emu35.
  Preconditions: `Ready` state. Steps: run semantics assertions —
  `assertIsToggleable` + `assertContentDescriptionEquals` on the toggles,
  `selectableGroup`/`Role.RadioButton` on the resolution group, all visible text
  resolves from `strings.xml` (no hardcoded literals). Expected: passes; TalkBack
  announces on/off and selected resolution. Traces: AC-6.
- **TC-AND-079-12** — Type: instrumented/e2e. Target: **A15 (must)**.
  Preconditions: real device; `CAMERA`+`RECORD_AUDIO` GRANTED. Steps: open screen,
  enumerate devices, run camera preview + mic-level test, pick a non-default
  mic/camera, Save. Expected: real device labels populate; preview/level work;
  `PUT` persists the chosen ids. Rationale for device: emulator lacks real
  capture hardware. Traces: AC-1, AC-2, AC-8.
- **TC-AND-079-13** — Type: instrumented (permissions). Target: **A15 (must)**.
  Preconditions: `CAMERA`/`RECORD_AUDIO` DENIED. Steps: open screen. Expected:
  screen loads, device pickers show "Default" (no labels), test buttons handle
  denial gracefully, and Save still succeeds. Traces: AC-8, AC-5.
- **TC-AND-079-14** — Type: unit/contract. Target: JVM. Preconditions: logger
  spy; Save fails. Steps: trigger save failure and 401 paths. Expected: WARN/ERROR
  logs contain only the mapped error category — no booleans, device ids,
  `video_resolution`, cookies, or `X-CSRF-Token`. Traces: AC-7.

### Coverage matrix

| Acceptance criterion | Covered by |
|---|---|
| AC-1 (load + render real controls) | TC-01, TC-08, TC-10, TC-12 |
| AC-2 (Save → batched PUT persists) | TC-02, TC-03, TC-09, TC-10, TC-12 |
| AC-3 (survive relaunch, no network) | TC-04 |
| AC-4 (observable by call layer) | TC-05 |
| AC-5 (failure handling: save/load/stale/401) | TC-06, TC-07, TC-08, TC-09, TC-13 |
| AC-6 (TalkBack + strings.xml) | TC-11 |
| AC-7 (no value/credential logging) | TC-14 |
| AC-8 (permissions optional; Save works denied) | TC-12, TC-13 |
