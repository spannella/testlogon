---
id: AND-172
title: Media foundation tests
milestone: M4
epic: E23
priority: P1
size: M
status: draft
depends_on: [AND-167, AND-168]
blocks: []
---

# AND-172 — Media foundation tests

## 1. Overview & Goal

This ticket establishes the automated test foundation for the media stack
delivered in M4/E23: the Media3/ExoPlayer integration (`AND-166`), HLS source
support (`AND-167`), and the reusable Compose player UI with controls,
buffering/error states, and Picture-in-Picture (`AND-168`). The goal is a
durable, **headless-runnable** test suite that locks in the behavior of the
player state machine and its Compose UI so that future refactors (codec
swaps, control redesigns, ExoPlayer version bumps) cannot silently regress
playback.

Concretely this ticket delivers three test layers, all of which must run on a
build agent with no attached display or network:

1. **Player state unit tests** — JVM (Robolectric/local) tests over the
   `PlayerManager` wrapper and the player `StateFlow<PlayerUiState>` reducer,
   driven by a fake `Player` so no real decoder or socket is required.
2. **Player UI tests** — Compose UI tests over `PlayerControls`,
   buffering/error overlays, and the surface composable, asserting that UI
   state renders correctly and that control gestures emit the right player
   intents.
3. **HLS manifest/parsing tests** — offline tests that feed canned HLS
   manifests (master + media playlists) to verify source selection and
   adaptive-track exposure without contacting a live stream.

The deliverable is *only tests and test infrastructure*. No production media
code is changed except where a seam (interface, `@VisibleForTesting` hook, or
clock injection) is strictly required for testability; any such seam is
minimal and called out in §4.

This is a P1 test ticket. Production behavior is owned upstream by `AND-166/167/168`;
this ticket is the regression net under them.

## 2. Context & References

- Repo: `spannella/testlogon`, Android app under `android/`, branch
  `android-port`. Canonical namespace/applicationId base
  `com.testlogon.android`.
- Stack: Kotlin 2.0.21, Jetpack Compose + Material 3, Hilt (KSP),
  Coroutines/Flow, **Media3/ExoPlayer 1.4 (HLS)**, minSdk 24,
  compileSdk/targetSdk 35, JDK 17, Gradle 8.9, AGP 8.7.3.
- Module layering: `app -> feature-* -> core-*`. The media code lives in
  `feature-player` (UI + ViewModel) consuming `core-media` (the `PlayerManager`
  wrapper) and `core-testing` (shared fakes/rules). Tests authored here land
  in `feature-player/src/test`, `feature-player/src/androidTest`, and
  `core-media/src/test`, with reusable fakes promoted into `core-testing`.
- Upstream tickets and their contracts under test:
  - `AND-166` — `PlayerManager` wrapper, lifecycle-aware release, single-player
    reuse; progressive MP4 in a Compose surface.
  - `AND-167` — HLS source support (replaces web `hls.js`), live + VOD
    manifests, adaptive switching.
  - `AND-168` — Controls (play/seek/scrub/volume/fullscreen), buffering/error
    states, PiP.
- Web reference for parity of expected control behavior: `frontend/` player
  components (control affordances, error copy) — used only to align expected
  values in assertions, not exercised at runtime.
- This ticket touches **no backend**; the FastAPI dev host
  (`http://18.222.237.167:8000`) and auth/session flow are out of scope. Media
  URLs in tests are local `file://`/`asset://`/`data:` or fake-served strings.

## 3. Functional Requirements

FR-1. **Headless execution.** The full suite runs via
`./gradlew :feature-player:testDebugUnitTest :core-media:testDebugUnitTest`
(JVM) and `:feature-player:connectedDebugAndroidTest` (instrumented, on a
headless emulator or via Robolectric where feasible). No test requires a
display server, audio output device, or external network.

FR-2. **Player state coverage.** Tests assert the `PlayerUiState` reducer
transitions for: `Idle -> Buffering -> Ready(playing) -> Ready(paused) ->
Ended`, and `* -> Error` from a player error, including recovery back to
`Buffering` on retry.

FR-3. **Position/duration mapping.** Tests assert that `currentPosition`,
`bufferedPosition`, and `duration` from the underlying `Player` are surfaced
into `PlayerUiState` and that an unknown duration
(`C.TIME_UNSET`) maps to a `duration = null` (live) representation.

FR-4. **Control intent mapping.** UI tests assert each control affordance from
`AND-168` emits the correct intent: play/pause toggle, seek-to (tap on
progress bar), scrub (drag), volume/mute, and fullscreen toggle.

FR-5. **Buffering & error overlays.** UI tests assert the buffering spinner is
shown only in `Buffering`, the error overlay (with retry action) is shown only
in `Error`, and neither is shown in `Ready`.

FR-6. **PiP state.** Tests assert the ViewModel/holder exposes the correct
`shouldEnterPip` / aspect-ratio signal for `AND-168`'s PiP path and that
controls are hidden while in PiP.

FR-7. **HLS source selection.** Tests assert a URL ending `.m3u8` (or with HLS
content type) constructs an `HlsMediaSource` path, and that a master manifest
exposes multiple selectable video tracks (adaptive) while a single-rendition
VOD exposes one.

FR-8. **Lifecycle/single-player.** Tests assert `PlayerManager` releases the
underlying player on `ON_STOP`/`ON_DESTROY` and that re-acquiring reuses a
single instance (no leak of multiple `ExoPlayer`s).

FR-9. **Determinism.** All tests use injected clock/dispatcher and a fake
`Player`; no `Thread.sleep`, no real wall-clock waits. Flake rate target: 0
over 50 consecutive CI runs.

## 4. Technical Design

### Test module layout

```
core-testing/
  src/main/kotlin/com/testlogon/android/core/testing/media/
    FakePlayer.kt              // androidx.media3.common.Player test double
    PlayerStateBuilders.kt     // PlayerUiState fixture builders
    MainDispatcherRule.kt      // already exists; reused
core-media/
  src/test/kotlin/com/testlogon/android/core/media/
    PlayerManagerTest.kt
    PlayerUiStateReducerTest.kt
    HlsSourceFactoryTest.kt
feature-player/
  src/test/kotlin/com/testlogon/android/feature/player/
    PlayerViewModelTest.kt
  src/androidTest/kotlin/com/testlogon/android/feature/player/
    PlayerControlsTest.kt
    PlayerScreenOverlaysTest.kt
```

### Production seams required (minimal)

The wrapper from `AND-166` must accept an injectable `Player` factory and clock
so tests can substitute a fake. If not already present, add (in `core-media`,
coordinated with `AND-166`):

```kotlin
fun interface PlayerFactory { fun create(): Player }

@VisibleForTesting
internal class PlayerManager @Inject constructor(
    private val factory: PlayerFactory,
    private val clock: Clock = Clock.System,
)
```

`PlayerViewModel` (from `AND-168`) exposes the state under test:

```kotlin
@HiltViewModel
class PlayerViewModel @Inject constructor(
    private val playerManager: PlayerManager,
) : ViewModel() {
    val uiState: StateFlow<PlayerUiState>
    fun onIntent(intent: PlayerIntent)
}
```

State and intent contracts asserted by tests:

```kotlin
sealed interface PlayerUiState {
    data object Idle : PlayerUiState
    data object Buffering : PlayerUiState
    data class Ready(
        val isPlaying: Boolean,
        val positionMs: Long,
        val bufferedMs: Long,
        val durationMs: Long?,      // null => live / TIME_UNSET
        val volume: Float,
        val isMuted: Boolean,
        val isFullscreen: Boolean,
        val isInPip: Boolean,
    ) : PlayerUiState
    data object Ended : PlayerUiState
    data class Error(val kind: PlayerErrorKind, val canRetry: Boolean) : PlayerUiState
}

sealed interface PlayerIntent {
    data object PlayPause : PlayerIntent
    data class SeekTo(val positionMs: Long) : PlayerIntent
    data class SetVolume(val volume: Float) : PlayerIntent
    data object ToggleMute : PlayerIntent
    data object ToggleFullscreen : PlayerIntent
    data object Retry : PlayerIntent
    data class PipChanged(val inPip: Boolean) : PlayerIntent
}
```

### FakePlayer

`FakePlayer` implements `androidx.media3.common.Player` (extending Media3's
`SimpleBasePlayer` to avoid stubbing ~150 methods). It records added
`MediaItem`s, exposes setters to drive `playbackState`, `isPlaying`,
position/duration, tracks, and a `PlaybackException`, and synchronously
dispatches `Player.Listener` callbacks. This avoids any real renderer/socket.

```kotlin
class FakePlayer : SimpleBasePlayer(Looper.getMainLooper()) {
    fun emitState(@Player.State state: Int)
    fun emitIsPlaying(isPlaying: Boolean)
    fun emitPosition(positionMs: Long, bufferedMs: Long, durationMs: Long)
    fun emitTracks(videoTrackCount: Int)
    fun emitError(error: PlaybackException)
}
```

### Reducer test strategy

`PlayerUiStateReducerTest` drives the reducer/listener directly with a
`FakePlayer`, advances a `TestScope` via `MainDispatcherRule`, and asserts the
emitted `StateFlow` sequence using Turbine.

### HLS test strategy

`HlsSourceFactoryTest` verifies the factory branch that selects
`HlsMediaSource` vs `ProgressiveMediaSource` by URI/content-type, and parses
canned manifests using Media3's `HlsPlaylistParser` to assert variant count
without playback. Manifests live in `core-media/src/test/resources/hls/`.

## 5. API Contract

No HTTP API is exercised by this ticket. Network/auth contracts are owned by
other epics and are not in scope.

The "contract" under test is the **HLS manifest format** consumed by
`AND-167`. Tests assert parsing of fixtures shaped like:

Master playlist (`master.m3u8`):
```
#EXTM3U
#EXT-X-STREAM-INF:BANDWIDTH=800000,RESOLUTION=640x360
360p.m3u8
#EXT-X-STREAM-INF:BANDWIDTH=2400000,RESOLUTION=1280x720
720p.m3u8
```
Expected: parser yields 2 variants; factory exposes 2 adaptive video tracks.

Media playlist VOD (`360p.m3u8`):
```
#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:6
#EXTINF:6.0,
seg0.ts
#EXTINF:6.0,
seg1.ts
#EXT-X-ENDLIST
```
Expected: `#EXT-X-ENDLIST` present => VOD; `durationMs` resolves to a finite
value. A live variant (no `#EXT-X-ENDLIST`) => `durationMs == null`.

## 6. Data & State Management

Tests treat `StateFlow<PlayerUiState>` as the single source of truth and assert
emissions in order using Turbine's `test { ... awaitItem() }`. Each test
constructs an isolated `FakePlayer` + `PlayerManager` + `PlayerViewModel`; no
shared mutable state crosses tests (no static singletons). DataStore/Room are
not involved (no persisted media prefs in this ticket); if `AND-168` persists a
"last volume" pref, that branch is covered with an in-memory fake DataStore
from `core-testing` rather than a real one.

Position/duration mapping rules under test:
- `Player.STATE_BUFFERING -> Buffering`
- `Player.STATE_READY -> Ready(isPlaying = player.isPlaying, ...)`
- `Player.STATE_ENDED -> Ended`
- `duration == C.TIME_UNSET -> Ready.durationMs = null`
- `playerError != null -> Error(kind, canRetry)`

## 7. Error Handling & Resilience

Tests assert the production error path rather than introducing new handling:

- A `PlaybackException` (e.g.
  `ERROR_CODE_IO_NETWORK_CONNECTION_FAILED`) maps to
  `PlayerUiState.Error(kind = Network, canRetry = true)`.
- A source/manifest parse error
  (`ERROR_CODE_PARSING_MANIFEST_MALFORMED`) maps to `Error(kind = Source,
  canRetry = true)`.
- `Retry` intent from `Error` re-prepares the player and transitions back to
  `Buffering` (asserted via `FakePlayer` recording a `prepare()` call).
- Test reliability itself is a resilience concern: a `Timeout` rule (e.g.
  JUnit `@get:Rule val timeout = Timeout.seconds(10)`) wraps each test so a
  hung coroutine fails fast instead of blocking CI. The `TestDispatcher` makes
  all delays virtual, so this timeout should never trigger in healthy runs.

## 8. Security & Privacy

No credentials, cookies, CSRF tokens, or PII are involved. Test media URIs are
local fixtures only; no requests reach the dev backend or any real CDN. No
secrets are committed (manifests/segments are synthetic). Tests must not log
device identifiers or write outside the Gradle build/test output directories.

## 9. Accessibility & i18n

This ticket asserts the a11y contract delivered by `AND-168` rather than
adding UI:
- Compose UI tests locate controls by **semantics/content description**
  (e.g. `onNodeWithContentDescription("Play")`,
  `"Pause"`, `"Enter fullscreen"`, `"Retry"`), which both proves the controls
  carry content descriptions and keeps tests resilient to layout changes.
- Error/buffering copy is asserted via string resources
  (`context.getString(R.string.player_error_retry)`), not hard-coded literals,
  so localized builds keep passing. Any missing content description is a test
  failure, surfacing a11y gaps in upstream tickets.

## 10. Telemetry & Logging

No new telemetry is emitted by tests. If `AND-166/168` emit analytics events
(e.g. `player_error`, `player_started`), tests assert them against a
`FakeAnalytics` recorder from `core-testing` to lock event names/params.
Test output uses JUnit/Gradle reporting; verbose logs are off by default. CI
publishes the HTML report at
`feature-player/build/reports/tests/testDebugUnitTest/index.html` and the
JUnit XML for aggregation.

## 11. Testing Strategy

This ticket *is* the testing strategy for the media foundation. Layers:

**A. Unit (JVM, `src/test`):**
- `PlayerUiStateReducerTest` — FR-2, FR-3, FR-7(duration), error mapping
  (§7). Turbine-asserted emission sequences.
- `PlayerManagerTest` — FR-8: single-player reuse, lifecycle release.
  Drive a `TestLifecycleOwner` to `ON_STOP`/`ON_DESTROY`, assert
  `FakePlayer.released == true` and only one instance created.
- `HlsSourceFactoryTest` — FR-7: source-type selection + variant count from
  canned manifests.
- `PlayerViewModelTest` — FR-4 intent handling at the VM boundary;
  `onIntent(PlayPause)` toggles `playWhenReady` on the fake.

**B. Compose UI (`src/androidTest`, Robolectric where supported):**
- `PlayerControlsTest` — FR-4/FR-5: render `PlayerControls` with seeded
  `PlayerUiState`, perform clicks/drags, assert emitted intents via a captured
  callback; assert overlay visibility per state.
- `PlayerScreenOverlaysTest` — FR-5/FR-6: buffering spinner, error overlay +
  retry, PiP hides controls.

Example UI test:
```kotlin
@Test fun playButton_emitsPlayPause() {
    var intent: PlayerIntent? = null
    composeRule.setContent {
        PlayerControls(state = readyPaused(), onIntent = { intent = it })
    }
    composeRule.onNodeWithContentDescription("Play").performClick()
    assertThat(intent).isEqualTo(PlayerIntent.PlayPause)
}
```

Example reducer test:
```kotlin
@get:Rule val mainRule = MainDispatcherRule()
@Test fun buffering_then_ready_emitsSequence() = runTest {
    val fake = FakePlayer()
    val manager = PlayerManager({ fake }, clock)
    manager.uiState.test {
        assertThat(awaitItem()).isEqualTo(PlayerUiState.Idle)
        fake.emitState(Player.STATE_BUFFERING)
        assertThat(awaitItem()).isEqualTo(PlayerUiState.Buffering)
        fake.emitPosition(0, 5_000, 30_000); fake.emitState(Player.STATE_READY)
        assertThat(awaitItem()).isInstanceOf(PlayerUiState.Ready::class.java)
    }
}
```

**Tooling:** JUnit4, Turbine 1.x, Truth/AssertJ, `kotlinx-coroutines-test`,
`androidx.compose.ui:ui-test-junit4`, Robolectric 4.x, `media3-test-utils`.
Hilt is bypassed in unit tests (direct construction); `HiltAndroidRule` used
only where a graph is unavoidable.

**Coverage target:** branch coverage of the `PlayerUiState` reducer and
intent handler >= 90%; all FRs in §3 have at least one asserting test.

## 12. Dependencies & Sequencing

- **Depends on `AND-167`** (HLS playback) — provides `HlsSourceFactory` /
  source-selection logic and adaptive-track exposure under test.
- **Depends on `AND-168`** (reusable player UI) — provides `PlayerControls`,
  overlays, fullscreen/PiP, and `PlayerViewModel`/`PlayerUiState`/`PlayerIntent`
  contracts.
- **Transitively `AND-166`** (Media3 integration) — provides `PlayerManager`
  and the lifecycle/single-player behavior; `AND-167/168` already depend on it.
- Requires `core-testing` to host `FakePlayer`, fixture builders, and existing
  `MainDispatcherRule`; if `core-testing` lacks a media package, this ticket
  creates `com.testlogon.android.core.testing.media`.
- Coordinate the testability seams in §4 (`PlayerFactory`, injectable clock,
  `@VisibleForTesting` listeners) with `AND-166/168` owners; prefer those
  seams already exist. This ticket does not introduce a new public API for
  production consumers.
- Blocks: nothing directly, but acts as the CI gate that must stay green for
  subsequent media work (offline download, casting) if added later in E23.

## 13. Risks & Open Questions

- **R1: `Player` interface surface.** Implementing `Player` directly is
  brittle across Media3 minor versions; mitigated by extending
  `SimpleBasePlayer`. If 1.4's `SimpleBasePlayer` lacks a needed hook, fall
  back to a Mockito relaxed mock for the few methods used.
- **R2: Compose UI tests under Robolectric.** Some `media3-ui`/`PlayerView`
  paths require an instrumented device. Mitigation: keep the *surface*
  (`AndroidView`/`PlayerSurface`) out of UI tests; test pure-Compose
  `PlayerControls`/overlays, which run under Robolectric.
- **R3: Flaky coroutine timing.** Mitigated by virtual-time `TestDispatcher`
  and no real delays (FR-9).
- **OQ1:** Do `AND-168` controls already expose content descriptions and
  string resources? If not, §9 assertions will fail and that gap must be
  filed back against `AND-168` (this ticket should *not* fix UI a11y itself).
- **OQ2:** Does `AND-166` already inject a `PlayerFactory`/clock? If only a
  concrete `ExoPlayer.Builder` is used, the minimal seam in §4 must be merged
  first.
- **OQ3:** Are analytics events emitted by the media stack? Determines whether
  §10's `FakeAnalytics` assertions are in scope or N/A.

## 14. Acceptance Criteria

AC-1. `./gradlew :feature-player:testDebugUnitTest :core-media:testDebugUnitTest`
passes with **zero failures** on a headless CI agent (no display/network).
AC-2. `./gradlew :feature-player:connectedDebugAndroidTest` (or the Robolectric
equivalent) passes for `PlayerControlsTest` and `PlayerScreenOverlaysTest`.
AC-3. Reducer tests assert the full state sequence
`Idle -> Buffering -> Ready(playing/paused) -> Ended` and `* -> Error -> Retry
-> Buffering` (FR-2, §7).
AC-4. Live vs VOD duration mapping verified: `C.TIME_UNSET -> durationMs ==
null`; finite duration for VOD (FR-3, FR-7).
AC-5. Each control intent (play/pause, seekTo, scrub, volume, mute,
fullscreen, retry) has a passing UI test asserting the emitted
`PlayerIntent` (FR-4).
AC-6. Buffering spinner and error overlay (with retry) visibility verified per
state; controls hidden in PiP (FR-5, FR-6).
AC-7. `PlayerManager` releases the underlying player on `ON_STOP`/`ON_DESTROY`
and reuses a single instance (FR-8).
AC-8. HLS factory selects `HlsMediaSource` for `.m3u8` and exposes the correct
adaptive variant count from canned master/media manifests (FR-7).
AC-9. No test uses `Thread.sleep` or real network; suite is green across 50
consecutive CI runs with 0 flakes (FR-9).
AC-10. Reducer/intent branch coverage >= 90%; controls located by
semantics/content description (§9).

## 15. Definition of Done

- All §14 acceptance criteria met; suite green on `android-port` CI.
- New tests under `core-media/src/test`, `feature-player/src/test`, and
  `feature-player/src/androidTest`; shared fakes (`FakePlayer`,
  fixture builders) in `core-testing` and reused, not duplicated.
- Any production seam added for testability (§4) is minimal,
  `@VisibleForTesting`/internal, reviewed by the `AND-166/168` owners, and
  introduces no behavior change.
- Manifest fixtures committed under `core-media/src/test/resources/hls/`; no
  real media or secrets committed.
- Tests use injected dispatchers/clock and virtual time; no `Thread.sleep`, no
  network, no display dependency.
- Open questions OQ1–OQ3 resolved or filed as follow-up tickets against the
  owning upstream ticket.
- Lint/detekt clean on test sources; JUnit HTML/XML reports produced and wired
  into CI; PR merged to `android-port` with green checks.
