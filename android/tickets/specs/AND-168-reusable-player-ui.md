---
id: AND-168
title: Reusable player UI
milestone: M4
epic: E23
priority: P0
size: L
status: draft
depends_on: [AND-166]
blocks: [AND-169]
---

# AND-168 — Reusable player UI

## 1. Overview & Goal

Build a reusable, self-contained Jetpack Compose video player UI that wraps the
`PlayerManager`/ExoPlayer integration delivered in AND-166. The output of this
ticket is a single public composable, `VideoPlayer`, plus its supporting control
overlay, state model, and Picture-in-Picture (PiP) plumbing, that any
feature module (watch screen, channel preview, clip detail) can drop in without
re-implementing playback chrome.

The deliverable covers the player *presentation layer only*: transport controls
(play/pause, seek/scrub, volume/mute, fullscreen toggle), buffering and error
states rendered over the video surface, and Android system PiP entry/exit. Media
source construction, HLS specifics, and adaptive-quality selection are explicitly
out of scope and owned by AND-167 and AND-169 respectively.

Success means: a caller passes a `PlayerManager` (or a media item handle) and a
modifier, and gets a fully interactive player with controls, fullscreen, and PiP
that behave correctly across rotation, backgrounding, and playback errors.

## 2. Context & References

- **Repo:** `spannella/testlogon`, Android app under `android/`, branch
  `android-port`. Package base `com.testlogon.android`.
- **Module:** new `feature-player` module (lib) at
  `com.testlogon.android.feature.player`, layered `app -> feature-player ->
  core-ui, core-model`. It must NOT depend on `core-network` directly — media
  source URLs arrive via the calling feature.
- **Upstream dependency (AND-166):** `PlayerManager` wrapper, lifecycle-aware
  `ExoPlayer` release, single-player reuse. This ticket consumes its public API;
  see `com.testlogon.android.feature.player.PlayerManager`.
- **Downstream (AND-169):** Adaptive quality / data-saver adds a quality menu
  hook into the control overlay defined here (a reserved `onQualityClick` slot).
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Media3/ExoPlayer 1.4
  (`androidx.media3:media3-ui` + `media3-exoplayer` + `media3-session`),
  Coroutines/Flow, Hilt (KSP). minSdk 24, compileSdk/targetSdk 35.
- **Web reference:** `frontend/` player chrome (controls layout, scrub behavior)
  is a UX reference only; PiP and Android lifecycle have no web analog.
- **Platform docs:** AndroidX Media3 `PlayerView`/`PlayerControlView`, and the
  `Activity.enterPictureInPictureMode(PictureInPictureParams)` API
  (`onPictureInPictureModeChanged`).

## 3. Functional Requirements

FR-1 **Transport controls overlay.** Render an overlay with: play/pause toggle,
a draggable seek bar (scrubber) with elapsed/duration labels, a 10s rewind and
10s fast-forward affordance, a volume/mute control, and a fullscreen toggle. A
reserved settings/quality affordance slot is rendered only when `onQualityClick`
is non-null (consumed by AND-169).

FR-2 **Auto-hide controls.** Controls fade in on tap/interaction and auto-hide
after a configurable timeout (default 3000 ms) while playing. Controls stay
visible while paused, while buffering, in an error state, or while the user is
actively scrubbing. Any tap toggles visibility.

FR-3 **Scrubbing.** Dragging the seek bar shows a live position preview and a
pause of position updates from the player; on release, `PlayerManager.seekTo` is
called once with the final target. Tapping anywhere on the bar seeks to that
position.

FR-4 **Buffering state.** While the player reports `STATE_BUFFERING`, a
determinate-where-available / indeterminate progress indicator is shown centered
over the surface; the play/pause button is suppressed during initial buffering.

FR-5 **Error state.** On a playback error (`Player.Listener.onPlayerError`),
controls are replaced by an error panel showing a localized message and a Retry
button. Retry re-prepares via `PlayerManager.retry()` and returns to the playing
or paused state. The original `PlaybackException` error code is surfaced to
telemetry but not shown raw to users.

FR-6 **Fullscreen.** The fullscreen toggle flips an immersive mode: the host
Activity hides system bars (via `WindowInsetsControllerCompat`) and the player
fills the window; toggling back restores inset content. Fullscreen state is
hoisted so the caller (or a `FullscreenController`) owns orientation; the
composable only emits `onFullscreenToggle(isFullscreen)`.

FR-7 **Picture-in-Picture.** When supported (`packageManager.hasSystemFeature(
FEATURE_PICTURE_IN_PICTURE)` and API >= 26), a PiP affordance and the home/back
gesture trigger `enterPictureInPictureMode`. In PiP, controls are hidden and only
the video surface is shown; PiP `RemoteAction`s provide play/pause. On exit,
full controls return at the preserved position.

FR-8 **State restoration.** Across configuration changes (rotation, fullscreen
enter/exit), playback position, play/pause state, and controls-visibility are
preserved (player instance reuse comes from AND-166; UI state is hoisted/saved).

FR-9 **Lifecycle.** The composable observes lifecycle: pause on `ON_STOP` unless
in PiP; it does not itself create/destroy the player (AND-166 owns release).

## 4. Technical Design

New module `feature-player`. Public surface:

```kotlin
package com.testlogon.android.feature.player.ui

@Composable
fun VideoPlayer(
    state: PlayerUiState,
    onEvent: (PlayerUiEvent) -> Unit,
    modifier: Modifier = Modifier,
    controlsConfig: PlayerControlsConfig = PlayerControlsConfig(),
    onQualityClick: (() -> Unit)? = null, // AND-169 slot
)
```

`VideoPlayer` hosts the ExoPlayer surface using an `AndroidView` wrapping Media3
`androidx.media3.ui.PlayerView` with `useController = false` (we render our own
Compose controls), or a `SurfaceView` bound to `player.setVideoSurfaceView`. The
Compose overlay is layered in a `Box` above the surface.

```kotlin
@AndroidEntryPoint-free: this is a pure UI module; player is passed in.

data class PlayerUiState(
    val player: Player,                 // from PlayerManager (AND-166)
    val playbackState: PlaybackState,   // Idle, Buffering, Ready, Ended, Error
    val isPlaying: Boolean,
    val positionMs: Long,
    val bufferedPositionMs: Long,
    val durationMs: Long,               // C.TIME_UNSET-safe (>=0 or -1)
    val volume: Float,                  // 0f..1f
    val isMuted: Boolean,
    val isFullscreen: Boolean,
    val isInPip: Boolean,
    val controlsVisible: Boolean,
    val error: PlayerError? = null,
)

sealed interface PlaybackState { object Idle; object Buffering; object Ready; object Ended; data class Error(val e: PlayerError) }

sealed interface PlayerUiEvent {
    object PlayPause : PlayerUiEvent
    data class SeekTo(val positionMs: Long) : PlayerUiEvent
    data class ScrubStart(val positionMs: Long) : PlayerUiEvent
    data class ScrubMove(val positionMs: Long) : PlayerUiEvent
    data class ScrubEnd(val positionMs: Long) : PlayerUiEvent
    data class SetVolume(val volume: Float) : PlayerUiEvent
    object ToggleMute : PlayerUiEvent
    object ToggleFullscreen : PlayerUiEvent
    object EnterPip : PlayerUiEvent
    object ToggleControls : PlayerUiEvent
    object Retry : PlayerUiEvent
}

data class PlayerControlsConfig(
    val autoHideMillis: Long = 3_000L,
    val seekStepMs: Long = 10_000L,
    val showVolume: Boolean = true,
    val showFullscreen: Boolean = true,
    val showPip: Boolean = true,
)
```

State holder bridging the `Player` to `PlayerUiState`:

```kotlin
class PlayerUiStateHolder(
    private val player: Player,
    private val scope: CoroutineScope,
    private val config: PlayerControlsConfig,
) {
    val uiState: StateFlow<PlayerUiState>
    fun onEvent(event: PlayerUiEvent)
    fun dispose()
}

@Composable
fun rememberPlayerUiStateHolder(
    player: Player,
    config: PlayerControlsConfig = PlayerControlsConfig(),
): PlayerUiStateHolder
```

Position polling uses a 250 ms ticking flow that is suspended while scrubbing and
while not `isPlaying`, reading `player.currentPosition` / `bufferedPosition`.
A `Player.Listener` updates `playbackState`, `isPlaying`, `duration`, and errors.

Control composables (internal): `PlayerControlsOverlay`, `ScrubBar`,
`PlayPauseButton`, `VolumeControl`, `FullscreenButton`, `BufferingIndicator`,
`PlayerErrorPanel`. Auto-hide is a `LaunchedEffect(controlsVisible, isPlaying,
isScrubbing)` that issues `delay(autoHideMillis)` then emits `ToggleControls`.

**Fullscreen** is implemented by a `FullscreenController` helper that toggles
`WindowInsetsControllerCompat(window, view).hide(systemBars())` and switches the
player container to fill the window; the host Activity sets requested orientation.

**PiP** is implemented via a `PipController`:

```kotlin
class PipController(private val activity: ComponentActivity) {
    fun isSupported(): Boolean
    fun enterPip(aspectRatio: Rational, sourceRectHint: Rect?, actions: List<RemoteAction>)
    fun updateParams(isPlaying: Boolean)
}
```

The host Activity overrides `onPictureInPictureModeChanged` and pushes the
`isInPip` flag into `PlayerUiState`; `RemoteAction` broadcasts are routed to
`PlayerUiEvent.PlayPause`. Aspect ratio is clamped to PiP's allowed range
(2.39:1..1:2.39).

## 5. API Contract

Not applicable as a network contract. This ticket introduces **no backend
endpoints and no Retrofit calls**; it consumes only an in-process `Player`
instance. Media source URLs (progressive/HLS) and their HTTP fetching are owned
by the calling feature and by AND-167 (HLS). The DataStore-backed media
preferences read by the quality menu are owned by AND-169.

The only "contract" here is the public Compose API and event surface defined in
Section 4 (`VideoPlayer`, `PlayerUiState`, `PlayerUiEvent`,
`PlayerControlsConfig`), which downstream tickets depend on as a stable module
boundary. `onQualityClick` is the reserved extension point for AND-169.

## 6. Data & State Management

- **Source of truth:** the `Player` instance (AND-166). All transport state is
  derived from it via `Player.Listener` callbacks plus a polling flow for
  position. The UI never holds a duplicate "true" position except during an
  active scrub (a transient `scrubPositionMs` override).
- **UI-only state** (hoisted, survives config change via `rememberSaveable`):
  `controlsVisible`, `isFullscreen`, last known `positionMs` for restoration.
  These use a `Saver` for `PlayerUiState`'s restorable subset.
- **No Room, no DataStore** writes in this ticket. (Media prefs persistence is
  AND-169.)
- **Threading:** all `Player` access is on the main thread (ExoPlayer
  requirement); polling flow runs on `Dispatchers.Main.immediate`. Listener
  callbacks are already main-thread.
- **Scrub debounce:** `ScrubMove` only updates the preview overlay; a single
  `SeekTo` is issued on `ScrubEnd`. Position polling resumes after a 200 ms
  settle to avoid the post-seek snap-back flicker.
- **Volume:** mirrors `player.volume`; `ToggleMute` stores the pre-mute volume in
  the holder so unmute restores it.

## 7. Error Handling & Resilience

- **Playback errors:** `onPlayerError(PlaybackException)` maps the error code to
  a `PlayerError` with a localized user message and a `retryable` flag:
  - `ERROR_CODE_IO_*` (network/timeout) -> retryable, "Connection problem".
  - `ERROR_CODE_BEHIND_LIVE_WINDOW` -> auto-recover by `seekToDefaultPosition()`
    + re-prepare, no error panel shown.
  - decoder/format errors -> non-retryable, "This video can't be played".
- **Retry:** `PlayerUiEvent.Retry` calls `PlayerManager.retry()` (re-prepare and
  resume). Given the unreliable dev backend, retry is user-initiated; no
  automatic retry storm. (Network-layer bounded backoff for GETs is AND-016 and
  applies to the media-source fetch layer, not here.)
- **Stale/offline:** if the surface has no media (idle) the player shows a neutral
  poster/empty state rather than an error.
- **Buffering watchdog:** if `STATE_BUFFERING` persists beyond a configurable
  threshold (default 20 s, matching the backend timeout budget) while there is no
  network, surface a soft "Still loading…" hint with a Retry affordance; do not
  auto-fail.
- **PiP/fullscreen guards:** all PiP entry is wrapped in try/catch for
  `IllegalStateException` (e.g., Activity not resumed) and degrades silently to
  in-app fullscreen.

## 8. Security & Privacy

- No credentials, tokens, cookies, or PII are handled by this module. Media URLs
  are passed in already-resolved; the cookie-based session/CSRF stack (AND-011/
  012/013) lives in `core-network` and the calling feature.
- **PiP privacy:** when entering PiP, controls and any text overlays are hidden so
  no sensitive chrome is exposed in the system PiP window.
- **FLAG_SECURE passthrough:** expose a `controlsConfig`-independent boolean
  `secureSurface` so DRM/secure content callers can set the window
  `FLAG_SECURE`; default false. (Actual DRM is out of scope.)
- No logging of media URLs at INFO level (they may carry signed query params);
  URLs are redacted to host-only in logs.

## 9. Accessibility & i18n

- All controls have `contentDescription`/`stateDescription` via Compose
  semantics: play/pause announces "Play"/"Pause"; mute announces state; scrub bar
  exposes `progressBarRangeInfo` with current/duration and supports accessibility
  seek actions (`SemanticsActions` set/adjust progress).
- Minimum touch targets 48dp; controls overlay respects `WindowInsets` (status/
  nav/cutout) when not fullscreen.
- Auto-hide is disabled (controls stay visible) when a screen reader
  (`AccessibilityManager.isTouchExplorationEnabled`) is active.
- All user-facing strings (`Play`, `Pause`, `Fullscreen`, `Picture in picture`,
  `Retry`, error messages, time labels) live in `feature-player/res/values/
  strings.xml` for translation. Time labels use locale-aware formatting
  (`DateUtils.formatElapsedTime` or equivalent), and the scrubber respects RTL
  layout direction.

## 10. Telemetry & Logging

- Emit structured analytics events via the project's analytics abstraction
  (interface injected by caller; this module exposes a `PlayerAnalytics`
  callback in `PlayerControlsConfig`, default no-op):
  - `player_play`, `player_pause`, `player_seek` (delta ms), `player_fullscreen`
    (enter/exit), `player_pip` (enter/exit), `player_error`
    (code, retryable), `player_retry`, `player_rebuffer` (duration ms).
- Logging via Timber: DEBUG for state transitions and control events; WARN for
  recoverable errors; ERROR for non-retryable playback failures. Media URLs
  redacted to host-only (Section 8).
- No PII in any event; events carry only playback metadata (position, duration,
  error code).

## 11. Testing Strategy

- **Unit (JUnit + Turbine, `core-testing`):** `PlayerUiStateHolder` against a
  fake `Player` (Media3 `SimpleBasePlayer`-derived test double or a mock):
  - play/pause toggles map to `Player.play()/pause()`.
  - scrub `Start/Move/End` issues exactly one `seekTo` on end at the final
    position; intermediate moves do not seek.
  - buffering -> `PlaybackState.Buffering`; error -> `Error` with correct
    retryable mapping per error code.
  - auto-hide timing (use a test dispatcher + `advanceTimeBy`).
  - mute/unmute restores prior volume.
- **Compose UI tests (`createAndroidComposeRule`):**
  - controls appear on tap, hide after timeout while playing, stay while paused.
  - tapping play/pause emits `PlayerUiEvent.PlayPause`.
  - error panel shows Retry and emits `Retry`.
  - semantics: play button has correct contentDescription and seek action.
- **PiP/fullscreen instrumented test** (espresso, API 26+ emulator): triggering
  fullscreen hides system bars; `enterPip` enters PiP mode and controls hide;
  PiP unsupported device falls back to fullscreen without crashing.
- **Smoke (consumes AND-166):** a progressive MP4 plays in `VideoPlayer` with
  working controls (extends AND-166's playback test).
- Target: state holder logic >= 85% line coverage; all FRs have at least one test.

## 12. Dependencies & Sequencing

- **Hard dependency:** AND-166 (Media3/ExoPlayer integration, `PlayerManager`,
  lifecycle release, single-player reuse). This ticket cannot start until the
  `Player` surface and `retry()` exist.
- **Transitive:** AND-003 (core module structure) via AND-166.
- **Blocks:** AND-169 (adaptive quality/data-saver) — consumes the
  `onQualityClick` slot and quality menu hook defined here.
- **Coordinates with:** AND-167 (HLS) — no code dependency, but the player UI is
  the consumer of HLS sources; verify controls (live edge indicator for live
  manifests) behave for live `durationMs == C.TIME_UNSET`. A live-stream UI
  affordance (e.g., "LIVE" badge, jump-to-live) is included in this ticket since
  it is pure UI.
- **New Gradle deps:** `androidx.media3:media3-ui:1.4.x`,
  `androidx.media3:media3-session:1.4.x` (for PiP `RemoteAction` plumbing) added
  to `feature-player/build.gradle.kts` via the version catalog.

## 13. Risks & Open Questions

- **R1 (orientation ownership):** Whether the player composable or the host
  Activity owns orientation lock on fullscreen. *Decision:* host owns
  orientation; composable only emits `onFullscreenToggle`. Confirm with app-shell
  owner (AND-022 navigation host).
- **R2 (PiP fragmentation):** PiP behavior varies pre-API 31 (no
  `sourceRectHint` smooth transition, no seamless resize). Mitigation: feature-
  detect and degrade; accept a non-animated transition < API 31.
- **R3 (single-player reuse + PiP):** AND-166 reuses one player; entering PiP from
  one screen and navigating must not release the player. Needs explicit handshake
  with AND-166's lifecycle release logic (do not release while `isInPip`).
- **R4 (live streams):** Exact UX for live manifests (jump-to-live, scrub window)
  depends on AND-167 manifest behavior; LIVE badge included, but jump-to-live
  edge cases may need a follow-up.
- **OQ1:** Does the design need a media-session/notification (background audio)
  now, or is that a separate ticket? Assumed out of scope (UI only).
- **OQ2:** Should the quality slot also host captions/audio-track selection?
  Reserve the slot generically; defer the menu contents to AND-169.

## 14. Acceptance Criteria

AC-1 A caller can render `VideoPlayer(state, onEvent, modifier)` over a
`PlayerManager` player and see working play/pause, scrub/seek, 10s skip, volume/
mute, and fullscreen controls. (maps backlog: "Controls + fullscreen … work")

AC-2 Controls auto-hide after the configured timeout while playing and remain
visible while paused, buffering, scrubbing, erroring, or under TalkBack.

AC-3 Scrubbing issues exactly one `seekTo` on release at the final position, with
a live preview during drag (verified by unit test).

AC-4 Buffering shows a centered indicator; a playback error shows a localized
panel with a Retry that re-prepares and resumes (verified by tests).

AC-5 Fullscreen toggle hides/restores system bars and fills/restores the window;
state survives rotation. (maps backlog: "fullscreen … work")

AC-6 On a PiP-capable device (API >= 26), the player enters Picture-in-Picture,
hides controls, exposes play/pause `RemoteAction`s, and returns to full controls
at the preserved position on exit; on unsupported devices it degrades to
fullscreen without crashing. (maps backlog: "PiP work")

AC-7 A progressive MP4 plays end-to-end through `VideoPlayer` with all controls
in an instrumented smoke test.

AC-8 All interactive controls expose correct accessibility semantics and meet
48dp touch targets; all user-facing strings are externalized.

## 15. Definition of Done

- `feature-player` module compiles; `VideoPlayer` and its public API
  (`PlayerUiState`, `PlayerUiEvent`, `PlayerControlsConfig`, `onQualityClick`
  slot) are stable and documented with KDoc.
- All FR-1..FR-9 implemented; all AC-1..AC-8 met and demonstrated by tests.
- Unit + Compose UI tests pass in CI (AND-050 pipeline); state-holder coverage
  >= 85%.
- ktlint/detekt clean (AND-005); no new lint baseline suppressions for this
  module.
- No `core-network` dependency leaked into `feature-player`; module-layering
  check passes.
- Strings externalized; TalkBack pass-through verified manually on one device.
- PiP and fullscreen verified on an API 35 and an API 26 emulator.
- Reserved `onQualityClick` hook documented for AND-169 handoff; live-stream
  affordance verified against an AND-167 HLS source (or flagged if AND-167 not
  yet merged).
- Telemetry events wired to the injected `PlayerAnalytics` no-op default and
  verified to fire in tests.
- PR merged to `android-port`; ticket references AND-166 dependency satisfied.
