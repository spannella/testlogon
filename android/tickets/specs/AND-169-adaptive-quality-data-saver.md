---
id: AND-169
title: Adaptive quality / data-saver
milestone: M4
epic: E23
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-167, AND-079]
blocks: []
---

# AND-169 — Adaptive quality / data-saver

## 1. Overview & Goal

Provide user-facing video quality selection and an automatic data-saver capability for the Media3/ExoPlayer-based HLS player delivered in AND-167 (player surface) and configured via the media preferences store from AND-079 (preferences/settings). The feature lets a user pick a target maximum playback resolution/bitrate (Auto, 1080p, 720p, 480p, 360p, "Data saver / audio-priority") and enforces a hard quality **cap** whenever the device is on a **metered** network (cellular, metered Wi-Fi, or when the OS Data Saver is enabled). The cap constrains ExoPlayer's adaptive (ABR) track selection so it never selects a video rendition above the resolved ceiling, while still allowing ABR to adapt downward freely.

Goal, stated testably: on a metered connection, with default preferences, the player must never render a video track whose height exceeds the configured metered cap (default 480p), and the user's explicit quality choice must persist across app restarts and apply on the next prepared playback. When unmetered, the user's full selection (including Auto) applies.

This ticket owns the quality/data-saver **policy** layer and its UI affordances. It does not own the player UI chrome itself (AND-167) nor the persisted-preferences schema mechanics (AND-079); it consumes both.

## 2. Context & References

- Stack: Kotlin 2.0.21, Jetpack Compose + Material 3, Hilt (KSP), Coroutines/Flow, Media3/ExoPlayer 1.4 for HLS, DataStore for prefs. minSdk 24, compileSdk/targetSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- Module layering: `app -> feature-* -> core-*`. This feature lives primarily in `feature-player` (UI + integration) and `core-data` (policy resolution + connectivity), with a small model addition in `core-model`. Package base: `com.testlogon.android`.
- Upstream dependencies:
  - **AND-167** — Media3/ExoPlayer HLS player surface. Provides `PlayerManager`/`ExoPlayer` instance, `MediaSource` construction, and the player UI (`PlayerScreen`, `PlayerViewModel`). This ticket injects a `TrackSelector` configuration and surfaces a quality menu into that screen.
  - **AND-079** — Media preferences / settings via DataStore. Provides the `MediaPreferences` DataStore and `MediaPreferencesRepository`. This ticket adds two fields (`preferredQuality`, `dataSaverMode`) to that store and reads them.
- Material 3 design references: bottom sheet / dropdown menu component for quality selection.
- Android connectivity: `ConnectivityManager`, `NetworkCapabilities` (`NET_CAPABILITY_NOT_METERED`), and `ConnectivityManager.isActiveNetworkMetered` / `getRestrictBackgroundStatus()` for OS Data Saver.
- No backend interaction is required for this ticket (see §5). Note: a backend media-preferences endpoint pair does exist (`GET`/`PUT /ui/media/preferences`, CALL-003, schemas `MediaPreferencesOut`/`MediaPreferencesIn`), but it carries **WebRTC call** defaults (audio/video device IDs, `default_audio_muted`, `default_video_off`, `video_resolution`), not HLS playback quality, and is intentionally NOT used by this feature (see §5 and §16).

## 3. Functional Requirements

FR-1. **Quality options.** The user can choose from an enumerated set: `AUTO`, `P1080`, `P720`, `P480`, `P360`, `DATA_SAVER`. `AUTO` lets ABR use all renditions (subject to the metered cap). `DATA_SAVER` selects the lowest available video rendition and is the strongest constraint.

FR-2. **Persistence.** The selected quality and a separate boolean "Cap quality on cellular/metered networks" (default `true`) persist via DataStore (AND-079 store) and survive process death and app restart.

FR-3. **Metered cap enforcement.** When the active network is metered OR the OS Data Saver restricts background data, and the metered-cap toggle is enabled, the player must enforce a configurable maximum height (`meteredMaxHeightPx`, default 480) regardless of the user's `AUTO`/high-resolution choice — except that an explicit user choice *lower* than the cap is always honored (the more restrictive of the two wins).

FR-4. **Live application.** Changing the quality selection while playing applies without recreating the player: it updates `TrackSelectionParameters` on the existing `ExoPlayer`, taking effect on the next ABR evaluation (within a few seconds) without restarting playback position.

FR-5. **Network transition handling.** If the network changes from unmetered to metered mid-playback (or Data Saver toggles), the cap is re-resolved and applied live; transitioning back removes the cap (subject to the user's own selection).

FR-6. **Selection UI.** The player exposes a quality affordance (overflow menu item -> Material 3 modal bottom sheet) listing the options with the active one checked, plus a non-interactive caption showing the *effective* resolved ceiling (e.g., "Capped to 480p on mobile data").

FR-7. **Graceful capabilities.** Options above the stream's max available rendition are still selectable but resolve to the highest available; the UI must not crash or block selection when a stream lacks high renditions.

## 4. Technical Design

### 4.1 Model (`core-model`)

```kotlin
package com.testlogon.android.core.model.media

enum class VideoQuality(val maxHeightPx: Int?) {
    AUTO(null),        // no user-imposed ceiling
    P1080(1080),
    P720(720),
    P480(480),
    P360(360),
    DATA_SAVER(0);     // sentinel: lowest available rendition

    companion object { val DEFAULT = AUTO }
}

data class QualityPolicy(
    val userSelection: VideoQuality,
    val capOnMetered: Boolean,
    val meteredMaxHeightPx: Int = 480,
)
```

### 4.2 Connectivity (`core-data`)

```kotlin
package com.testlogon.android.core.data.network

data class NetworkStatus(val isMetered: Boolean, val dataSaverActive: Boolean)

interface ConnectivityObserver {
    /** Emits current status immediately, then on every change. Conflated. */
    fun observe(): Flow<NetworkStatus>
    fun current(): NetworkStatus
}

@Singleton
class ConnectivityObserverImpl @Inject constructor(
    @ApplicationContext private val context: Context,
) : ConnectivityObserver { /* ConnectivityManager.NetworkCallback + callbackFlow */ }
```

`isMetered` is derived from `!NetworkCapabilities.hasCapability(NET_CAPABILITY_NOT_METERED)`; `dataSaverActive` from `getRestrictBackgroundStatus() == RESTRICT_BACKGROUND_STATUS_ENABLED`. The `callbackFlow` registers a `NetworkCallback` and closes the registration on cancellation.

### 4.3 Policy resolver (`core-data`)

```kotlin
package com.testlogon.android.core.data.media

@Singleton
class QualityPolicyResolver @Inject constructor() {
    /** Returns the effective max video height in px, or null for "unbounded (Auto)". */
    fun resolveMaxHeightPx(policy: QualityPolicy, net: NetworkStatus): Int? {
        val metered = net.isMetered || net.dataSaverActive
        val cap = if (metered && policy.capOnMetered) policy.meteredMaxHeightPx else null
        val user = policy.userSelection.maxHeightPx        // null=AUTO, 0=DATA_SAVER
        return listOfNotNull(cap, user)
            .minByOrNull { if (it == 0) Int.MIN_VALUE else it } // 0 (data-saver) wins as most restrictive
    }
}
```

Resolution rule: the **most restrictive** of (user selection, metered cap) wins; `AUTO` contributes no ceiling; `DATA_SAVER` (height 0) maps to "force lowest" and always wins.

### 4.4 Effective-quality flow

A `EffectiveQualityProvider` combines persisted prefs (AND-079) and connectivity into a hot `StateFlow`:

```kotlin
@Singleton
class EffectiveQualityProvider @Inject constructor(
    prefs: MediaPreferencesRepository,            // from AND-079
    connectivity: ConnectivityObserver,
    private val resolver: QualityPolicyResolver,
    @ApplicationScope scope: CoroutineScope,
) {
    val effective: StateFlow<EffectiveQuality> =
        combine(prefs.qualityPolicy, connectivity.observe()) { p, n ->
            EffectiveQuality(
                selection = p.userSelection,
                maxHeightPx = resolver.resolveMaxHeightPx(p, n),
                capped = n.isMetered || n.dataSaverActive,
                forceLowest = p.userSelection == VideoQuality.DATA_SAVER,
            )
        }.stateIn(scope, SharingStarted.WhileSubscribed(5_000),
            EffectiveQuality(VideoQuality.DEFAULT, 480, capped = false, forceLowest = false))
}

data class EffectiveQuality(
    val selection: VideoQuality,
    val maxHeightPx: Int?,
    val capped: Boolean,
    val forceLowest: Boolean,
)
```

### 4.5 Applying to ExoPlayer (`feature-player`)

The player (AND-167) holds an `ExoPlayer`. This ticket adds a binder that maps `EffectiveQuality` to `TrackSelectionParameters`:

```kotlin
fun ExoPlayer.applyQuality(q: EffectiveQuality) {
    val b = trackSelectionParameters.buildUpon()
    when {
        q.forceLowest -> b.setMaxVideoSize(1, 1)               // forces lowest video rendition
        q.maxHeightPx != null -> b.setMaxVideoSize(Int.MAX_VALUE, q.maxHeightPx)
        else -> b.clearVideoSizeConstraints()                   // AUTO, unbounded
    }
    trackSelectionParameters = b.build()
}
```

`setMaxVideoSize(maxW, maxH)` constrains the adaptive `DefaultTrackSelector`; ABR continues to adapt below the ceiling. Using `Int.MAX_VALUE` for width caps purely on height (the resolution axis the UI exposes).

In `PlayerViewModel` (extended from AND-167), collect `EffectiveQualityProvider.effective` and call `player.applyQuality(it)` on each emission, and once again immediately after `player.prepare()` to cover the case where ABR initializes before the first emission.

### 4.6 UI (`feature-player`)

- `QualitySheet(state: QualitySheetState, onSelect: (VideoQuality) -> Unit, onToggleCap: (Boolean) -> Unit, onDismiss: () -> Unit)` — a Material 3 `ModalBottomSheet` with a `RadioButton` row per option, a `Switch` for "Cap quality on mobile data", and a supporting caption rendering the effective ceiling.
- `PlayerScreen` (AND-167) adds an overflow `IconButton` (`Icons.Outlined.HighQuality`, contentDescription = "Video quality") that opens the sheet.
- `PlayerViewModel` exposes `qualitySheet: StateFlow<QualitySheetState>` and intents `onQualitySelected(VideoQuality)` / `onCapToggled(Boolean)` that write through to `MediaPreferencesRepository`.

## 5. API Contract

**No backend interaction for this feature's design.** Quality and data-saver state live entirely on-device (DataStore via AND-079) and in the OS connectivity layer. No `/ui/*` endpoint is called by this feature, and no cookie/CSRF flow (the web client's `ui_csrf` cookie -> `X-CSRF-Token` header transport, verified in `src/api/client.ts`) is exercised. HLS media-segment fetching is performed by Media3/ExoPlayer's own HTTP stack (configured in AND-167), not by the Retrofit/OkHttp app client; on web the analogous manifest URL is loaded directly by HLS.js with a `playback_token` query param (verified in `src/pages/videos/VideoPlayerPage.tsx`), confirming media transport is separate from the JSON API client.

**Caveat (corrected during review):** the earlier "no `/ui/*` endpoints, OpenAPI types … involved" claim was an overstatement. A backend endpoint pair `GET /ui/media/preferences` (resp `MediaPreferencesOut`) and `PUT /ui/media/preferences` (req `MediaPreferencesIn`, resp `MediaPreferencesOut`) DOES exist (CALL-003). Its `MediaPreferencesIn.video_resolution` field is an enum `"360" | "480" | "720" | "1080"`. However, this is the **WebRTC call** media-settings contract (it also carries `preferred_audio_input_id`, `preferred_video_input_id`, `preferred_audio_output_id`, `default_audio_muted`, `default_video_off`), surfaced in the web app's `src/pages/calls/MediaSettingsPage.tsx` — it governs *call camera capture resolution*, not *HLS playback* quality. This ticket deliberately keeps the HLS quality/data-saver preference **local** (DataStore) and does not read or write `/ui/media/preferences`. Naming caution: AND-079's on-device `MediaPreferences` store is a distinct concept from this backend `MediaPreferences*` schema; do not conflate them. Any future server-driven *playback* quality hint would be owned by a separate streaming-metadata ticket.

Note also: the web reference client does **not** persist the user's HLS playback quality choice — it resets to Auto (`currentLevel = -1`) per session and only persists caption settings to `localStorage` (verified in `src/components/shared/MediaPlayer.tsx`). FR-2's cross-restart persistence is therefore a net-new Android behavior, not a port of existing web behavior.

## 6. Data & State Management

DataStore additions (in the AND-079 `MediaPreferences` Proto/Preferences store):

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `media_preferred_quality` | string (enum name) | `AUTO` | Maps to `VideoQuality`; unknown -> `AUTO`. |
| `media_cap_on_metered` | bool | `true` | Drives metered cap. |
| `media_metered_max_height` | int | `480` | Optional power-user override; not surfaced in UI v1. |

`MediaPreferencesRepository` (AND-079) is extended with:

```kotlin
val qualityPolicy: Flow<QualityPolicy>
suspend fun setPreferredQuality(q: VideoQuality)
suspend fun setCapOnMetered(enabled: Boolean)
```

State ownership: `EffectiveQualityProvider` is the single source of truth for resolved quality, scoped `@Singleton` so a single connectivity callback is shared. `PlayerViewModel` holds transient UI state (sheet open/closed). All writes are debounced through DataStore's serialized writes; reads use `WhileSubscribed(5_000)` to avoid leaking the connectivity callback when no player is active. Enum persistence stores `name`; deserialization is forward-compatible (unknown value -> default).

## 7. Error Handling & Resilience

- **Connectivity unavailable / null active network:** treat as `isMetered = false`, `dataSaverActive = false` (fail open to user selection); do not block playback.
- **DataStore read failure / corruption:** `MediaPreferencesRepository` already maps `IOException` to emit defaults (AND-079); this feature inherits that and resolves to `AUTO` + cap `true`.
- **Stream lacks the requested rendition:** `setMaxVideoSize` is a *maximum*, not an exact selection; ExoPlayer falls back to the highest rendition at or below the ceiling, or the only available one. No error surfaced.
- **`forceLowest` with single-rendition stream:** `setMaxVideoSize(1,1)` still resolves to the single available track; playback proceeds.
- **Rapid network flapping:** the connectivity `Flow` is conflated and `EffectiveQuality` emissions are distinct-until-changed before `applyQuality`, preventing churn on the `TrackSelector`.
- **Player not yet created:** emissions are buffered in the `StateFlow`; `applyQuality` is also invoked post-`prepare()`, guaranteeing application.

## 8. Security & Privacy

- No credentials, PII, or auth state are read or written; no network calls leave the device for this feature.
- Reading network metered status and OS Data Saver status requires `ACCESS_NETWORK_STATE` (normal permission, declared in `feature-player` manifest, no runtime prompt). No `ACCESS_WIFI_STATE` or location permission is required or requested.
- Persisted values are non-sensitive enums/booleans; no encryption beyond standard app-private DataStore is needed.
- The feature must not weaken AND-167's player security posture (e.g., it must not alter the media HTTP data source or disable TLS for HLS).

## 9. Accessibility & i18n

- All quality labels and the cap toggle are externalized to `strings.xml` (`R.string.quality_auto`, `quality_1080p`, `quality_data_saver`, `quality_cap_metered_title`, `quality_capped_caption` with a `%1$s` height arg, etc.).
- The overflow action has `contentDescription = stringResource(R.string.cd_video_quality)`.
- Radio rows use `Modifier.selectable(role = Role.RadioButton)`; the cap row uses `Modifier.toggleable(role = Role.Switch)`; selected state is announced by TalkBack.
- The effective-ceiling caption is exposed as live supporting text so screen-reader users hear "Capped to 480p on mobile data."
- Touch targets >= 48dp; respects dynamic font scaling (no fixed-height rows that clip at 200%).
- Resolution numerals ("1080p") are treated as locale-neutral tokens; surrounding sentences are translatable.

## 10. Telemetry & Logging

Telemetry routes through the app analytics abstraction (assumed available from core; if absent, log via `Timber` at DEBUG only):

- `player_quality_changed { from, to, source: "user"|"metered_cap"|"data_saver", network: "metered"|"unmetered" }`
- `player_quality_cap_toggled { enabled: Boolean }`
- `player_quality_capped_applied { ceiling_px, reason: "metered"|"data_saver_os" }` (fired at most once per playback session per ceiling change).

Logging: DEBUG-level `Timber` logs on each resolved `EffectiveQuality` and each `applyQuality` call (resolved ceiling, network status). No bitrate/URL/PII in logs. No telemetry is emitted on transient flapping (debounced/distinct-until-changed).

## 11. Testing Strategy

Unit (`core-data`, `core-testing`):
- `QualityPolicyResolverTest` — table-driven over the matrix {AUTO, P1080, P720, P480, P360, DATA_SAVER} x {metered, unmetered, dataSaverOn} x {capOn, capOff}. Assert: metered+capOn+AUTO -> 480; metered+capOn+P720 -> 480 (cap wins); P360 unmetered -> 360 (user wins); DATA_SAVER always -> forceLowest; unmetered+AUTO -> null.
- `EffectiveQualityProviderTest` — fake `MediaPreferencesRepository` + fake `ConnectivityObserver`; use `Turbine` to assert emissions on prefs change and on network change.
- `ConnectivityObserverImplTest` — Robolectric with shadowed `ConnectivityManager`; assert metered/data-saver mapping.

Player integration (`feature-player`):
- `ExoPlayerQualityBinderTest` (Robolectric) — apply each `EffectiveQuality`; assert resulting `trackSelectionParameters.maxVideoHeight` and (for forceLowest) `maxVideoWidth == 1`.

Compose UI (`createAndroidComposeRule`):
- Sheet shows all options, active one checked; selecting an option invokes `onSelect`; toggling cap invokes `onToggleCap`; caption text reflects capped state.

End-to-end acceptance (instrumented): with a fake `ConnectivityObserver` forced to metered and default prefs, prepare a multi-rendition HLS test stream and assert the selected video format height never exceeds 480 across the first N ABR evaluations (read via `Player.Listener.onTracksChanged`).

## 12. Dependencies & Sequencing

- **Hard depends_on AND-167** (player surface): needs the `ExoPlayer`/`PlayerManager`, `PlayerScreen`, and `PlayerViewModel` to attach the binder and UI. Cannot be verified end-to-end without it.
- **Hard depends_on AND-079** (media preferences/DataStore): needs `MediaPreferencesRepository` and the `MediaPreferences` store to add `preferredQuality` and `capOnMetered`.
- Sequencing: land the `core-model` enum and `core-data` resolver + connectivity observer first (independently unit-testable), then the AND-079 repository extension, then the `feature-player` binder/UI once AND-167 is merged.
- Blocks: none currently recorded.

## 13. Risks & Open Questions

- R-1: `setMaxVideoSize` is a soft ceiling; if a stream's lowest rendition exceeds the cap, the cap cannot be honored. Mitigation: documented behavior (play lowest available); acceptance test uses a stream with a sub-480p rendition.
- R-2: OS Data Saver detection via `getRestrictBackgroundStatus()` reflects *background* restriction and may not always equal user intent for foreground playback. Open question: should foreground playback ignore OS Data Saver and rely only on metered status? Default v1: treat both as triggers (more conservative).
- R-3: Metered Wi-Fi is correctly captured by `NOT_METERED` capability, but some OEMs mis-report. Low risk; acceptable.
- R-4: Interaction with AND-167's `MediaSource` caching/preloading — if AND-167 preloads at full quality before this binder runs, a brief high-quality burst may occur. Mitigation: apply quality before `prepare()` and immediately after.
- OQ-1: Should `media_metered_max_height` be user-configurable in settings v1? Currently hidden; deferred to AND-079 follow-up.

## 14. Acceptance Criteria

- AC-1 (primary): On a metered network with default preferences, the player never renders a video track with height > 480px. Verified via `onTracksChanged` in the instrumented test. (Maps to source acceptance: "Quality cap respected on metered networks.")
- AC-2: The user can select any of the six quality options from the player; the choice persists across app restart (re-open player -> same selection checked).
- AC-3: With cap toggle ON and an explicit `AUTO` selection, switching from unmetered to metered mid-playback drops the rendered height to <= 480 within the next ABR window without restarting playback.
- AC-4: With cap toggle OFF, `AUTO` on metered allows renditions above 480.
- AC-5: `DATA_SAVER` selects the lowest available video rendition on any network.
- AC-6: An explicit selection lower than the metered cap (e.g., P360 on metered with cap 480) results in <= 360px (user choice wins).
- AC-7: The effective-ceiling caption accurately reflects the resolved ceiling and reason.
- AC-8: No crash or block when the stream lacks high renditions; selection still applies as a maximum.

## 15. Definition of Done

- `VideoQuality`/`QualityPolicy` in `core-model`; `ConnectivityObserver`, `QualityPolicyResolver`, `EffectiveQualityProvider` in `core-data` with Hilt bindings.
- `MediaPreferencesRepository` (AND-079) extended with `qualityPolicy`, `setPreferredQuality`, `setCapOnMetered` and DataStore keys/defaults.
- `feature-player` binder (`ExoPlayer.applyQuality`) wired into `PlayerViewModel`; `QualitySheet` + overflow action integrated into `PlayerScreen` (AND-167).
- `ACCESS_NETWORK_STATE` declared; all strings externalized; TalkBack roles set.
- Telemetry events emitted; DEBUG logging in place; no PII.
- Unit tests (resolver matrix, provider, connectivity, binder), Compose UI tests, and the metered-cap instrumented acceptance test all green in CI.
- All AC-1..AC-8 demonstrably pass; code reviewed and merged to `android-port`; ktlint/detekt clean.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer.

1. **Claim:** This feature requires no TestLogon backend interaction; quality/data-saver state is on-device only. **VERDICT: Verified (with correction to overstated wording).** No quality/data-saver endpoint exists in the API index (`reference/openapi.index.txt`; grep for `quality|bitrate|rendition|metered|data_saver` returns only SSE `.../stream` endpoints, none media-quality). The web client implements quality purely client-side via HLS.js. Source: `src/components/shared/MediaPlayer.tsx` (HLS.js level selection); `reference/openapi.index.txt` (no quality endpoint). The §5 wording "no `/ui/*` endpoints … involved" was corrected — see item 2.
2. **Claim (corrected):** "No `/ui/*` endpoints or OpenAPI types are involved." **VERDICT: Corrected.** A backend media-preferences endpoint pair DOES exist: `GET /ui/media/preferences` (resp `200:MediaPreferencesOut`) and `PUT /ui/media/preferences` (req `MediaPreferencesIn`, resp `200:MediaPreferencesOut`), op ids `ui_get_media_preferences…` / `ui_save_media_preferences…`. Its `video_resolution` enum is `"360" | "480" | "720" | "1080"`. It is the WebRTC **call** settings contract, not HLS playback; this ticket intentionally does not use it. Source: OpenAPI `GET /ui/media/preferences`, `PUT /ui/media/preferences`; schemas `MediaPreferencesIn` / `MediaPreferencesOut` in `reference/openapi.pretty.json`; `src/api/types.ts: MediaPreferencesIn` / `MediaPreferencesOut` (lines ~12732–12750, "Media Preferences (CALL-003)"); `src/api/endpoints/mediaPreferences.ts: getMediaPreferences/saveMediaPreferences`; `src/pages/calls/MediaSettingsPage.tsx` (resolution governs call camera capture, default "720").
3. **Claim:** The web client persists the user's HLS playback quality across sessions. **VERDICT: Corrected / Unverified-as-stated → net-new.** The web client does NOT persist playback quality; it resets to Auto (`currentLevel = -1`) each session and only persists CC/subtitle prefs to `localStorage`. FR-2's persistence is therefore a new Android behavior, not a port. Source: `src/components/shared/MediaPlayer.tsx` (`startLevel: -1`, `currentLevel` state, `localStorage` only for `media-player-cc-enabled`/`media-player-cc-language`).
4. **Claim:** Quality model = Auto + discrete heights with labels like "720p"; Auto means ABR over all renditions. **VERDICT: Verified.** Web maps each HLS level to `{height, bitrate, label: \`${height}p\`}` and uses `-1` for Auto. Source: `src/components/shared/MediaPlayer.tsx` (`QualityLevel`, `MANIFEST_PARSED` handler, `QualitySelector` Auto = `onChange(-1)`).
5. **Claim:** HLS media segments are fetched by the player's own HTTP stack, separate from the JSON API client (so this feature does not touch the Retrofit/OkHttp client or CSRF). **VERDICT: Verified.** Web loads the manifest URL directly into HLS.js as `\`${video.hls_manifest_url}?token=${video.playback_token}\``, independent of the `api()` fetch wrapper. Source: `src/pages/videos/VideoPlayerPage.tsx` (`hls_manifest_url` + `playback_token`); `src/components/shared/MediaPlayer.tsx` (`hls.loadSource(src)`).
6. **Claim:** Web app auth/CSRF transport is the `ui_csrf` cookie sent as the `X-CSRF-Token` header (not exercised by this feature). **VERDICT: Verified (and confirmed not used here).** Source: `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`, `credentials: "include"`, 401→`/ui/session/refresh`).
7. **Claim:** Backend validation/error envelope is `422 HTTPValidationError` with a `detail[]` of `{msg,…}`. **VERDICT: Verified (relevant only IF a future variant calls `/ui/media/preferences`).** All `/ui/*` ops list `422:HTTPValidationError`; the client normalizes `detail` arrays via `item.msg`. Source: `reference/openapi.index.txt` (`resp=…;422:HTTPValidationError`); `src/api/client.ts: normalizeErrorDetail`.
8. **Claim:** `ExoPlayer`/`TrackSelectionParameters.Builder.setMaxVideoSize(maxWidth, maxHeight)` constrains adaptive (ABR) selection to a height ceiling. **VERDICT: Verified (framework ref).** `setMaxVideoSize(int, int)` exists on `TrackSelectionParameters.Builder` (Media3 1.4). framework ref: https://developer.android.com/reference/androidx/media3/common/TrackSelectionParameters.Builder#setMaxVideoSize(int,int)
9. **Claim:** `clearVideoSizeConstraints()` removes the size ceiling (used for AUTO). **VERDICT: Verified (framework ref).** Method exists on `TrackSelectionParameters.Builder`. framework ref: https://developer.android.com/reference/androidx/media3/common/TrackSelectionParameters.Builder#clearVideoSizeConstraints()
10. **Claim:** `setMaxVideoSize(1, 1)` forces selection of the lowest available video rendition. **VERDICT: Verified-assumption (framework ref).** Documented idiom — the track selector picks the closest track not exceeding the (1,1) bound, i.e. the smallest; on a single-rendition stream it still selects that track. framework ref: https://developer.android.com/media/media3/exoplayer/track-selection
11. **Claim:** Metered detection via `!NetworkCapabilities.hasCapability(NET_CAPABILITY_NOT_METERED)`. **VERDICT: Verified (framework ref).** `NET_CAPABILITY_NOT_METERED` is a real `NetworkCapabilities` constant; absence ⇒ metered. framework ref: https://developer.android.com/reference/android/net/NetworkCapabilities#NET_CAPABILITY_NOT_METERED
12. **Claim:** OS Data Saver detection via `ConnectivityManager.getRestrictBackgroundStatus() == RESTRICT_BACKGROUND_STATUS_ENABLED`. **VERDICT: Verified (framework ref), with caveat.** API exists; it reflects *background* restriction (see §13 R-2 open question about foreground playback). framework ref: https://developer.android.com/reference/android/net/ConnectivityManager#getRestrictBackgroundStatus()
13. **Claim:** Reading metered/Data-Saver status needs only `ACCESS_NETWORK_STATE` (normal permission, no runtime prompt). **VERDICT: Verified (framework ref).** `ACCESS_NETWORK_STATE` is a normal (install-time) permission. framework ref: https://developer.android.com/reference/android/Manifest.permission#ACCESS_NETWORK_STATE
14. **Claim:** `ConnectivityManager.NetworkCallback` + `callbackFlow` is the correct pattern for live network-change observation. **VERDICT: Verified-assumption (framework ref).** Standard pattern; correctness of registration/unregistration is design-internal and covered by tests. framework ref: https://developer.android.com/reference/android/net/ConnectivityManager.NetworkCallback
15. **Claim:** AND-167 (player surface) and AND-079 (media preferences store) provide `PlayerManager`/`ExoPlayer`/`PlayerScreen`/`PlayerViewModel` and `MediaPreferencesRepository`/`MediaPreferences` DataStore respectively. **VERDICT: Unverified-assumption.** These are sibling Android-port tickets not present in the reference sources (web app + OpenAPI). Cannot be confirmed here; depends on AND-167/AND-079 deliverables.

### Corrections made
- **§frontmatter:** `status: draft` → `status: reviewed`; added `reviewed_on: 2026-06-06`.
- **§2 & §5:** Replaced the absolute "no `/ui/*` endpoints / no backend interaction" wording with an accurate caveat: the backend `GET`/`PUT /ui/media/preferences` (CALL-003, `MediaPreferences*` schemas, `video_resolution` enum) DOES exist but governs WebRTC call settings and is intentionally not used by this HLS-playback feature. Added a naming-collision warning (AND-079 on-device `MediaPreferences` ≠ backend `MediaPreferences*`).
- **§5:** Added the verified fact that the web client does NOT persist HLS playback quality (resets to Auto per session; only CC prefs persist), so FR-2's persistence is net-new Android behavior, and documented the verified `ui_csrf`/`X-CSRF-Token` transport and the `hls_manifest_url`+`playback_token` media path.

### Open assumptions
- **AND-167 / AND-079 surfaces (item 15):** The exact names/signatures of `PlayerManager`, `ExoPlayer` exposure, `PlayerScreen`, `PlayerViewModel`, `MediaPreferencesRepository`, and the AND-079 `MediaPreferences` DataStore are unverifiable from the provided sources (no Android source tree is included; the reference is the web app + OpenAPI). They must be confirmed against the merged AND-167/AND-079 code before implementation.
- **App analytics abstraction (§10):** Existence of a core telemetry sink is assumed; the spec already hedges with a `Timber` DEBUG fallback. Unverifiable here.
- **`@ApplicationScope` CoroutineScope DI qualifier (§4.4):** Assumed available from `core` Hilt setup; unverifiable from references.
- **R-2 (Data Saver foreground semantics):** Whether foreground playback should honor OS Data Saver remains an open product question (§13); the v1 default treats it as a trigger.

## 17. Test Plan

Test target legend: **JVM** = local JVM/Robolectric (no device); **EMU** = headless AVD `test35` (x86_64, API 35); **DEV** = physical Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, API 34, arm64-v8a). Hardware/real-network behavior MUST run on DEV; pure UI/logic suites run on JVM or EMU.

- **TC-AND-169-01 — Resolver matrix (metered cap wins over AUTO).** Type: unit (JVM). Target: `QualityPolicyResolver`. Preconditions: none. Steps: call `resolveMaxHeightPx(QualityPolicy(AUTO, capOnMetered=true, 480), NetworkStatus(isMetered=true, dataSaverActive=false))`. Expected: returns `480`. Also assert metered+capOn+P720 → 480 (cap wins). Traces: AC-1, AC-3.
- **TC-AND-169-02 — Resolver: user choice below cap wins.** Type: unit (JVM). Target: `QualityPolicyResolver`. Steps: `resolveMaxHeightPx(QualityPolicy(P360, capOnMetered=true, 480), metered=true)`. Expected: returns `360` (more restrictive of user vs cap). And P360 unmetered → 360. Traces: AC-6.
- **TC-AND-169-03 — Resolver: DATA_SAVER always forces lowest; AUTO unmetered unbounded; cap-off allows high.** Type: unit (JVM). Target: `QualityPolicyResolver`. Steps: (a) DATA_SAVER on each of {metered, unmetered, dataSaverOn} → resolves to height 0 / forceLowest (most restrictive); (b) AUTO unmetered → `null` (unbounded); (c) AUTO metered with `capOnMetered=false` → `null` (no cap). Expected: as stated. Traces: AC-4, AC-5.
- **TC-AND-169-04 — Resolver: OS Data Saver triggers cap even on unmetered network.** Type: unit (JVM). Target: `QualityPolicyResolver`. Steps: `resolveMaxHeightPx(QualityPolicy(AUTO, capOnMetered=true, 480), NetworkStatus(isMetered=false, dataSaverActive=true))`. Expected: `480` (dataSaverActive counts as metered trigger). Traces: AC-1.
- **TC-AND-169-05 — EffectiveQualityProvider re-emits on prefs and network change.** Type: unit (JVM, Turbine). Target: `EffectiveQualityProvider`. Preconditions: fake `MediaPreferencesRepository` (initial AUTO/cap=true) + fake `ConnectivityObserver` (initial unmetered). Steps: collect `effective`; (1) flip connectivity to metered; (2) change pref to P360. Expected: emission 1 has `maxHeightPx=null, capped=false`; after (1) `maxHeightPx=480, capped=true`; after (2) `maxHeightPx=360`. No duplicate emissions on identical input (distinct-until-changed). Traces: AC-3, AC-6, AC-7.
- **TC-AND-169-06 — ConnectivityObserver maps metered & Data Saver correctly.** Type: unit/Robolectric (JVM). Target: `ConnectivityObserverImpl`. Preconditions: Robolectric shadow `ConnectivityManager`. Steps: shadow network without `NET_CAPABILITY_NOT_METERED` and `getRestrictBackgroundStatus()=RESTRICT_BACKGROUND_STATUS_ENABLED`. Expected: `current()` → `NetworkStatus(isMetered=true, dataSaverActive=true)`; with `NOT_METERED` present and status `DISABLED` → both false. Traces: AC-1, AC-4.
- **TC-AND-169-07 — Null/absent active network fails open.** Type: unit/Robolectric (JVM). Target: `ConnectivityObserverImpl`. Steps: shadow no active network. Expected: `NetworkStatus(isMetered=false, dataSaverActive=false)` (per §7); playback not blocked. Traces: AC-4 (and §7 resilience).
- **TC-AND-169-08 — applyQuality maps EffectiveQuality to TrackSelectionParameters.** Type: integration/Robolectric (JVM or EMU). Target: `ExoPlayer.applyQuality` binder. Steps: build a real `ExoPlayer`; apply (a) `maxHeightPx=480` → assert `trackSelectionParameters.maxVideoHeight == 480`; (b) `forceLowest=true` → assert `maxVideoWidth == 1 && maxVideoHeight == 1`; (c) AUTO (`maxHeightPx=null`) → assert constraints cleared (`maxVideoHeight == Int.MAX_VALUE`). Expected: as stated; position not reset. Traces: AC-2, AC-4, AC-5.
- **TC-AND-169-09 — Metered cap end-to-end on real ABR stream (PRIMARY).** Type: instrumented/e2e. Target: `PlayerViewModel` + binder + multi-rendition HLS test stream. **MUST run on DEV** (real-network HLS/ABR over the cellular/metered path and arm64/API-34 decode behavior; the emulator cannot exercise true cellular metering). Preconditions: default prefs (AUTO, cap=true, 480); fake `ConnectivityObserver` forced metered (or device on real cellular). Steps: prepare a stream with renditions {1080,720,480,360}; play ≥60s; record every `Player.Listener.onTracksChanged` selected video format height. Expected: selected height never exceeds 480 across all ABR evaluations. Traces: AC-1.
- **TC-AND-169-10 — Live network transition unmetered→metered drops height without restart.** Type: instrumented/e2e. Target: `PlayerViewModel` + binder. **Prefer DEV** for real cellular toggle; EMU acceptable with fake `ConnectivityObserver` emitting the transition. Preconditions: AUTO, cap ON; start unmetered playing at >480. Steps: begin playback unmetered (verify height >480 reachable), then emit metered; observe `onTracksChanged` and playback position. Expected: within the next ABR window selected height ≤480; playback position continues (no re-prepare/seek-to-zero). Reverse transition removes cap. Traces: AC-3.
- **TC-AND-169-11 — Single-/low-rendition stream does not crash; cap is a maximum.** Type: instrumented (EMU). Target: binder + player with a stream whose only rendition is ≤480 (and a separate case with a single 720 rendition). Steps: select P360 / DATA_SAVER on each. Expected: no crash; selection applies as a maximum, player falls back to the only/closest available rendition and plays. Traces: AC-8.
- **TC-AND-169-12 — Quality choice persists across process death/app restart.** Type: instrumented (EMU). Target: `MediaPreferencesRepository` DataStore round-trip + player UI. Steps: open player, select P720; kill process (`am kill` / process death); relaunch and reopen player. Expected: P720 row checked on reopen (DataStore persisted `media_preferred_quality`). Traces: AC-2.
- **TC-AND-169-13 — QualitySheet Compose UI: options, selection, cap toggle, effective caption.** Type: Compose-UI (EMU). Target: `QualitySheet` via `createAndroidComposeRule`. Steps: render with state {AUTO active, capped on metered, ceiling 480}; assert all six options present and AUTO checked; click P720 → `onSelect(P720)` invoked; toggle cap → `onToggleCap(false)`; assert caption text reflects "Capped to 480p on mobile data". Expected: callbacks fire; caption matches resolved state. Traces: AC-2, AC-7.
- **TC-AND-169-14 — Accessibility: roles, content descriptions, touch targets, font scale.** Type: Compose-UI / instrumented a11y (EMU; spot-check TalkBack on DEV). Target: `QualitySheet` + `PlayerScreen` overflow action. Steps: assert overflow action has contentDescription `cd_video_quality`; radio rows expose `Role.RadioButton` + selected state; cap row exposes `Role.Switch` toggleable state; all targets ≥48dp; render at 200% font scale and assert no clipped/overlapping rows; verify caption is exposed as supporting text to the a11y tree. Expected: all assertions pass; TalkBack announces selection and "Capped to 480p on mobile data". Traces: AC-7 (and §9).
- **TC-AND-169-15 — Permission posture: only ACCESS_NETWORK_STATE; no runtime prompt; media transport unchanged.** Type: instrumented/manual (DEV). Target: merged manifest + player data source. Steps: inspect merged manifest for `ACCESS_NETWORK_STATE` and absence of `ACCESS_WIFI_STATE`/location; launch feature and confirm no runtime permission dialog appears; confirm HLS still loads over TLS and the binder does not replace/alter AND-167's media `DataSource`. Expected: single normal permission, no prompt, TLS HLS intact (no security regression per §8). Traces: §8 (security), AC-1 supporting.
- **TC-AND-169-16 — Offline / flaky-host resilience.** Type: instrumented (DEV preferred; toggle airplane mode / cellular). Target: `ConnectivityObserver` + provider + player. Steps: with player active, drop the network (airplane mode), rapidly toggle on/off several times. Expected: no crash; `EffectiveQuality` is conflated/distinct-until-changed so `applyQuality` is not churned; on offline, status fails open (not metered) and playback either buffers/recovers per AND-167 without the quality layer throwing; DataStore reads still serve last value. Traces: AC-3, §7 resilience.

### Coverage matrix

| AC (section 14) | Covered by |
|-----------------|-----------|
| AC-1 (metered cap ≤480, default prefs) | TC-01, TC-04, TC-06, TC-09 (primary), TC-15 (supporting) |
| AC-2 (six options selectable; persists across restart) | TC-08, TC-12, TC-13 |
| AC-3 (AUTO + cap, unmetered→metered live drop, no restart) | TC-01, TC-05, TC-10, TC-16 |
| AC-4 (cap OFF allows >480 on metered) | TC-03, TC-06, TC-07, TC-08 |
| AC-5 (DATA_SAVER → lowest on any network) | TC-03, TC-08 |
| AC-6 (explicit choice below cap wins) | TC-02, TC-05 |
| AC-7 (effective-ceiling caption accurate) | TC-05, TC-13, TC-14 |
| AC-8 (no crash/block when stream lacks high renditions) | TC-11 |

(§8 security and §7 resilience, while not numbered ACs, are covered by TC-15 and TC-07/TC-16 respectively.)
