---
id: AND-169
title: Adaptive quality / data-saver
milestone: M4
epic: E23
priority: P1
size: M
status: draft
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
- No backend interaction is required for this ticket (see §5).

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

**Not applicable.** This is a client-only feature with no TestLogon backend interaction. Quality and data-saver state live entirely on-device (DataStore via AND-079) and in the OS connectivity layer. No `/ui/*` endpoints, OpenAPI types, or cookie/CSRF flows are involved. HLS media-segment fetching is performed by Media3/ExoPlayer's own HTTP stack (configured in AND-167), not by the Retrofit/OkHttp app client. Any future server-driven quality hints would be owned by a separate streaming-metadata ticket, not this one.

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
