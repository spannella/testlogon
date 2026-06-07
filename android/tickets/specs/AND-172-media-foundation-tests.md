---
id: AND-172
title: Media foundation tests
milestone: M4
epic: E23
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
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

`FakePlayer` extends Media3's abstract `SimpleBasePlayer`
(`androidx.media3.common.SimpleBasePlayer`, which itself implements the
`androidx.media3.common.Player` *interface*) to avoid stubbing ~150 methods. It
records added `MediaItem`s and exposes setters to drive `playbackState`,
`isPlaying`, position/duration, tracks, and a `PlaybackException`. Note the
`SimpleBasePlayer` contract: a subclass holds a mutable `State` and overrides
`getState()`; the `emit*` helpers below mutate that backing state and then call
`SimpleBasePlayer.invalidateState()`, which is what synchronously dispatches the
corresponding `Player.Listener` callbacks on the player's `Looper`. This avoids
any real renderer/socket. (Verification note: `media3-test-utils` ships a
`FakeExoPlayer`/`TestExoPlayerBuilder` but those are oriented at full ExoPlayer
behavior; a hand-rolled `SimpleBasePlayer` subclass is the lighter seam used
here — confirm the chosen base against the pinned Media3 1.4 artifact at build
time, see §16 OA-2.)

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

## 16. Citations & Assumption Audit

This is a test-only ticket that, by design, exercises **no backend HTTP API**.
The OpenAPI index/spec was checked to confirm that claim (see C-0 / V-1). The
load-bearing technical claims are therefore mostly Android-framework
(Media3/ExoPlayer) facts and web-reference parity facts; each is audited below.

1. **Claim:** This ticket touches no backend; auth/session/CSRF are out of
   scope and media URIs are local fixtures (§2, §5, §8).
   **VERDICT: Verified.** No media-playback transport endpoint exists in the
   backend; the only video-adjacent endpoints are metadata/VOD/moderation REST
   calls (e.g. `GET /ui/videos/{video_id}`, `GET /ui/videos/{video_id}/access`),
   none of which this test ticket invokes.
   **SOURCE:** `reference/openapi.index.txt` lines 1994–2056 (`/ui/videos*`,
   `/ui/vod*`); no `*/playback-url`/HLS-manifest endpoint present.

2. **Claim:** The Android player replaces the web client's `hls.js` for HLS
   (§2, §3 FR-7, §5).
   **VERDICT: Verified.** The web reference player imports and drives `hls.js`
   directly (`import Hls from "hls.js"`, `new Hls(...)`, `hls.loadSource`,
   `Hls.Events.MANIFEST_PARSED`).
   **SOURCE:** `src/components/shared/MediaPlayer.tsx` (lines 15, 325–355) — the
   shared adaptive player; also consumed by `src/pages/broadcast/LivePlayer.tsx`.

3. **Claim:** Web player exposes the same control affordances the Android tests
   assert intents for — play/pause, seek bar, volume/mute, fullscreen, PiP
   (§3 FR-4, §9).
   **VERDICT: Verified (parity).** Web custom-controls overlay renders
   play/pause (`media-player-playpause`), seek `<input type=range aria-label="Seek">`,
   mute (`media-player-mute`) + volume (`aria-label="Volume"`), fullscreen
   (`media-player-fullscreen`), and PiP (`media-player-pip`).
   **SOURCE:** `src/components/shared/MediaPlayer.tsx` (lines 695–868).
   **Correction note:** the web player additionally exposes **quality selector**
   (lines 100–162) and **subtitle/CC** controls (lines 789–830). These are NOT
   in the spec's §4 `PlayerIntent` set; that is acceptable for AND-167/168 scope
   but is flagged as an open parity gap (see OA-4) so the upstream UI tickets are
   not silently under-tested.

4. **Claim:** Live = no seek bar / unknown duration; VOD = finite duration +
   seek bar, mapping to `durationMs == null` for live (§3 FR-3, §5, §6).
   **VERDICT: Verified (parity) + framework-correct.** Web gates the seek bar on
   `mode === "vod" && duration > 0` and shows a LIVE badge with no seek bar in
   `mode === "live"`. On Android, an unknown duration surfaces as
   `C.TIME_UNSET`, which the reducer maps to `durationMs = null` — this is the
   documented sentinel for unset time in Media3.
   **SOURCE:** `src/components/shared/MediaPlayer.tsx` (lines 218, 703, 741–750);
   framework ref: `androidx.media3.common.C.TIME_UNSET`
   (https://developer.android.com/reference/androidx/media3/common/C#TIME_UNSET).

5. **Claim:** Error overlay shows a Retry action; buffering overlay is distinct
   from the initial loading overlay (§3 FR-5, §7, §9).
   **VERDICT: Verified (parity).** Web renders a distinct `buffering` overlay
   (`playerState === "buffering"`) separate from the `idle/loading` overlay, and
   an `error` overlay containing a `Retry` button (`media-player-retry`).
   **SOURCE:** `src/components/shared/MediaPlayer.tsx` (lines 651–693).
   **Note:** Android error *copy* (`R.string.player_error_retry`, etc.) is owned
   by AND-168 and is NOT verifiable from the web strings (web copy lives in
   `MediaPlayer.tsx` literals such as "Stream unavailable…" / "Playback failed.
   Please try again." at lines 366/387). See OA-1.

6. **Claim:** `Player` is an interface; `FakePlayer` extends `SimpleBasePlayer`
   to avoid stubbing the whole surface (§4).
   **VERDICT: Verified (framework) — corrected mechanism.** `Player` is an
   interface and `SimpleBasePlayer` is the abstract base intended for custom
   players. **Correction:** a `SimpleBasePlayer` subclass does not "expose
   setters that dispatch listener callbacks" directly; it overrides `getState()`
   over a mutable `State` and calls `invalidateState()` to fan out
   `Player.Listener` callbacks. §4 text was amended to state this.
   **SOURCE:** framework ref
   https://developer.android.com/reference/androidx/media3/common/SimpleBasePlayer
   and https://developer.android.com/reference/androidx/media3/common/Player .

7. **Claim:** `Player.State` constants `STATE_IDLE/STATE_BUFFERING/STATE_READY/
   STATE_ENDED` drive the reducer; `isPlaying`/`playerError` are read from the
   player (§4, §6).
   **VERDICT: Verified (framework).** These four `@Player.State` int constants
   and `isPlaying()` / `getPlayerError()` are part of the `Player` interface.
   **SOURCE:** framework ref
   https://developer.android.com/reference/androidx/media3/common/Player .

8. **Claim:** `PlaybackException` codes `ERROR_CODE_IO_NETWORK_CONNECTION_FAILED`
   and `ERROR_CODE_PARSING_MANIFEST_MALFORMED` map to `Error(Network)` /
   `Error(Source)` (§7).
   **VERDICT: Verified (framework).** Both constants exist on
   `androidx.media3.common.PlaybackException`. (The web equivalent is coarser:
   `Hls.ErrorTypes.NETWORK_ERROR` vs `MEDIA_ERROR` in `MediaPlayer.tsx` lines
   357–393 — parity is conceptual, not 1:1.)
   **SOURCE:** framework ref
   https://developer.android.com/reference/androidx/media3/common/PlaybackException
   ; web parallel `src/components/shared/MediaPlayer.tsx` (lines 357–394).

9. **Claim:** HLS source selection constructs `HlsMediaSource` (vs
   `ProgressiveMediaSource`) and master/media manifests are parseable offline via
   `HlsPlaylistParser` to count variants and detect `#EXT-X-ENDLIST` (§3 FR-7,
   §4, §5).
   **VERDICT: Verified (framework).** `HlsMediaSource`,
   `ProgressiveMediaSource`, and `HlsPlaylistParser` are real Media3 classes;
   `HlsMultivariantPlaylist`/`HlsMediaPlaylist` expose variant lists and the
   `hasEndTag` (`#EXT-X-ENDLIST`) flag. The fixture manifest grammar in §5 is
   valid HLS.
   **SOURCE:** framework refs
   https://developer.android.com/reference/androidx/media3/exoplayer/hls/HlsMediaSource
   and https://developer.android.com/reference/androidx/media3/exoplayer/hls/playlist/HlsPlaylistParser .
   **Assumption:** the *production* class name `HlsSourceFactory` and the
   `PlayerUiState`/`PlayerIntent`/`PlayerManager`/`PlayerFactory` symbol names in
   §4 are owned by AND-166/167/168 and are not present in any provided source
   tree — treated as **Unverified-assumption** (see OA-2/OA-3).

10. **Claim:** PiP exposes `shouldEnterPip`/aspect-ratio and hides controls in
    PiP; lifecycle release on `ON_STOP`/`ON_DESTROY` with single-player reuse
    (§3 FR-6, FR-8).
    **VERDICT: Unverified-assumption (upstream contract).** The web reference
    uses browser PiP (`video.requestPictureInPicture()`,
    `MediaPlayer.tsx` lines 516–528), which does not map to the Android
    `shouldEnterPip`/`ON_STOP` lifecycle model; these are AND-166/168 production
    behaviors not present in the provided sources.
    **SOURCE:** none authoritative; web partial parallel
    `src/components/shared/MediaPlayer.tsx` (lines 516–528). Android lifecycle
    PiP framework ref:
    https://developer.android.com/develop/ui/views/picture-in-picture .

11. **Claim:** Tooling — Turbine, `kotlinx-coroutines-test`,
    `androidx.compose.ui:ui-test-junit4`, Robolectric, `media3-test-utils`;
    `MainDispatcherRule` already exists in `core-testing` (§4, §11).
    **VERDICT: Unverified-assumption.** These are standard, plausible Android
    test artifacts, but the Android repo (`android/`, `core-testing`) is not in
    the provided reference tree, so neither the existing `MainDispatcherRule`
    nor the dependency versions can be confirmed here.
    **SOURCE:** none in provided sources; framework refs are the libraries'
    canonical coordinates.

### Corrections made

- **C-0 (§frontmatter):** `status: draft -> reviewed`; added
  `reviewed_on: 2026-06-06`.
- **C-1 (§4 FakePlayer):** Corrected the `SimpleBasePlayer` usage mechanism —
  a subclass overrides `getState()` and calls `invalidateState()` to dispatch
  listener callbacks; it does not dispatch via bare setters. Clarified that
  `SimpleBasePlayer` implements the `Player` *interface*, and noted
  `media3-test-utils` ships `FakeExoPlayer`/`TestExoPlayerBuilder` as an
  alternative to confirm against the pinned 1.4 artifact. (Citation 6.)
- No factual API/path/method errors were found to correct, because the ticket
  asserts no backend API. Web-reference parity claims (citations 2–5, 8) were
  all confirmed accurate; two **additive** parity gaps (quality selector,
  subtitles/CC) were surfaced as open assumptions rather than spec errors.

### Open assumptions

- **OA-1:** Android control content descriptions and string resources
  (`R.string.player_error_retry`, "Play"/"Pause"/"Enter fullscreen"/"Retry")
  are assumed delivered by AND-168. Not verifiable from sources (web uses
  `data-testid` + literal copy, not Android string resources). Mirrors the
  ticket's own OQ1; §9 assertions fail loudly if the gap exists.
- **OA-2:** Production symbol names and seams (`PlayerManager`, `PlayerFactory`,
  injectable `Clock`, `HlsSourceFactory`, `@VisibleForTesting` listeners) and
  the exact `SimpleBasePlayer` API in Media3 1.4 are assumed from AND-166/167.
  Not in the provided source tree. Mirrors OQ2.
- **OA-3:** The `PlayerUiState` / `PlayerIntent` shapes in §4 are assumed to
  match AND-168's actual ViewModel contract. Unverifiable here; if upstream
  differs, the reducer/UI tests must follow upstream, not this spec.
- **OA-4:** Web parity is broader than the spec's intent set — the web player
  also exposes a **quality/variant selector** and **subtitle/CC** controls
  (`MediaPlayer.tsx` lines 100–162, 789–830). Whether AND-168 ports these (and
  thus whether they need test coverage here) is unconfirmed; if ported, add
  intents + cases. Why open: depends on AND-167/168 scope decisions not in any
  provided source.
- **OA-5:** Test tooling presence/versions (`MainDispatcherRule`, Turbine,
  Robolectric, `media3-test-utils`) assumed; Android repo not provided. Mirrors
  the build-config side of the ticket.

## 17. Test Plan

Test targets per the ticket's CI/dev matrix:
- **JVM/Robolectric** (local, no device) — default for unit + pure-Compose UI.
- **Emulator AVD `test35`** (x86_64, API 35) — instrumented Compose UI/e2e in CI.
- **Physical device** (Samsung Galaxy A15 5G, SM-A156U, arm64-v8a, API 34,
  serial R5CX821TA9R) — used only where real decoder/PiP/ABI behavior matters.

Because the suite is engineered to be headless and decoder-free (FR-9), most
cases run on JVM/Robolectric or the emulator. Two cases are called out as
PHYSICAL-DEVICE-REQUIRED because they validate real PiP system behavior and the
arm64-v8a/API-34 hardware-decoder path that the x86_64/API-35 emulator cannot
faithfully represent.

- **TC-AND-172-01 — Reducer happy-path state sequence**
  Type: unit (JVM/Robolectric).
  Target: `PlayerUiStateReducerTest` over `PlayerManager` + `FakePlayer`.
  Preconditions: `MainDispatcherRule` virtual clock; `FakePlayer` fresh.
  Steps: collect `uiState` via Turbine; emit `STATE_BUFFERING`, then position
  (0, 5_000ms buffered, 30_000ms duration) + `STATE_READY` playing, then pause,
  then `STATE_ENDED`.
  Expected: emissions `Idle -> Buffering -> Ready(isPlaying=true, durationMs=30_000)
  -> Ready(isPlaying=false) -> Ended`, in order, with no extra emissions.
  Traces: AC-3.

- **TC-AND-172-02 — Live vs VOD duration mapping**
  Type: unit (JVM/Robolectric).
  Target: `PlayerUiStateReducerTest`.
  Preconditions: `FakePlayer` in `STATE_READY`.
  Steps: (a) emit duration `C.TIME_UNSET`; (b) emit finite duration 42_000ms.
  Expected: (a) `Ready.durationMs == null` (live); (b) `Ready.durationMs == 42_000`.
  Traces: AC-4.

- **TC-AND-172-03 — Network error mapping**
  Type: unit (JVM/Robolectric).
  Target: `PlayerUiStateReducerTest` (error path, §7).
  Preconditions: player in `Buffering`/`Ready`.
  Steps: emit `PlaybackException(ERROR_CODE_IO_NETWORK_CONNECTION_FAILED)`.
  Expected: `Error(kind = Network, canRetry = true)`.
  Traces: AC-3.

- **TC-AND-172-04 — Manifest parse error mapping**
  Type: unit (JVM/Robolectric).
  Target: `PlayerUiStateReducerTest`.
  Preconditions: player active.
  Steps: emit `PlaybackException(ERROR_CODE_PARSING_MANIFEST_MALFORMED)`.
  Expected: `Error(kind = Source, canRetry = true)`.
  Traces: AC-3.

- **TC-AND-172-05 — Retry recovery transition**
  Type: unit (JVM/Robolectric).
  Target: `PlayerUiStateReducerTest` + `FakePlayer` call recording.
  Preconditions: reducer in `Error(canRetry=true)`.
  Steps: dispatch `PlayerIntent.Retry`.
  Expected: `FakePlayer.prepare()` recorded once and state returns to
  `Buffering` (then `Ready` once `STATE_READY` re-emitted). No duplicate player
  instances created.
  Traces: AC-3.

- **TC-AND-172-06 — HLS source selection + variant count (offline)**
  Type: contract/MockWebServer-style offline (JVM/Robolectric).
  Target: `HlsSourceFactoryTest` parsing canned fixtures in
  `core-media/src/test/resources/hls/`.
  Preconditions: fixtures `master.m3u8` (2 variants), `360p.m3u8` (VOD,
  `#EXT-X-ENDLIST`), and a live media playlist (no end tag).
  Steps: (a) factory given `…/master.m3u8` -> assert it builds an
  `HlsMediaSource` (not `ProgressiveMediaSource`); (b) parse master via
  `HlsPlaylistParser` -> assert 2 adaptive video variants; (c) parse VOD media
  playlist -> `hasEndTag == true` => finite duration; (d) parse live playlist ->
  `hasEndTag == false` => `durationMs == null`.
  Expected: all four assertions pass with no network access.
  Traces: AC-4, AC-8.

- **TC-AND-172-07 — Progressive (MP4) source selection**
  Type: unit (JVM/Robolectric).
  Target: `HlsSourceFactoryTest`.
  Preconditions: none.
  Steps: factory given a `file://…/clip.mp4` (non-`.m3u8`, non-HLS content type).
  Expected: builds a `ProgressiveMediaSource`, not `HlsMediaSource`.
  Traces: AC-8.

- **TC-AND-172-08 — ViewModel intent dispatch (play/pause)**
  Type: unit (JVM/Robolectric).
  Target: `PlayerViewModelTest` over `PlayerViewModel` + `FakePlayer`.
  Preconditions: VM constructed directly (Hilt bypassed).
  Steps: call `onIntent(PlayPause)` from a paused state.
  Expected: `FakePlayer.playWhenReady` toggled true; reverse toggles false.
  Traces: AC-5.

- **TC-AND-172-09 — Control affordances emit correct intents**
  Type: Compose-UI (Robolectric; emulator `test35` in CI for parity).
  Target: `PlayerControlsTest` with captured `onIntent` callback.
  Preconditions: `PlayerControls` rendered with a seeded `Ready(paused)` state.
  Steps: locate by content description and act on each control:
  `onNodeWithContentDescription("Play").performClick()`;
  seek = tap on progress bar (emits `SeekTo`); scrub = `performTouchInput { swipe… }`
  (emits `SeekTo`); volume slider drag (emits `SetVolume`); mute click
  (`ToggleMute`); fullscreen click (`ToggleFullscreen`); retry from error state
  (`Retry`).
  Expected: each interaction emits exactly the matching `PlayerIntent`; every
  control is locatable by content description (no missing a11y label).
  Traces: AC-5, AC-10.

- **TC-AND-172-10 — Overlay visibility per state**
  Type: Compose-UI (Robolectric).
  Target: `PlayerScreenOverlaysTest`.
  Preconditions: render screen with seeded states.
  Steps: render `Buffering`, then `Error`, then `Ready`.
  Expected: buffering spinner visible only in `Buffering`; error overlay + Retry
  visible only in `Error`; neither in `Ready`.
  Traces: AC-6.

- **TC-AND-172-11 — PiP hides controls (state-level)**
  Type: Compose-UI (Robolectric).
  Target: `PlayerScreenOverlaysTest`.
  Preconditions: render `Ready(isInPip = true)` (or dispatch
  `PipChanged(true)`).
  Steps: assert `shouldEnterPip`/aspect-ratio signal exposed and controls
  composable not present.
  Expected: control nodes asserted `doesNotExist()`; PiP signal correct.
  Traces: AC-6.

- **TC-AND-172-12 — Lifecycle release + single-player reuse**
  Type: unit/Robolectric (JVM, `TestLifecycleOwner`).
  Target: `PlayerManagerTest`.
  Preconditions: `PlayerManager` with `PlayerFactory { FakePlayer() }`.
  Steps: acquire player; drive lifecycle `ON_STOP` then `ON_DESTROY`; re-acquire.
  Expected: `FakePlayer.released == true` after stop/destroy; factory invoked
  such that no more than one live instance exists at a time (no `ExoPlayer`
  leak).
  Traces: AC-7.

- **TC-AND-172-13 — Headless suite green, no sleep/network (determinism gate)**
  Type: integration (CI meta-check, JVM + emulator `test35`).
  Target: full `:feature-player` + `:core-media` test tasks.
  Preconditions: build agent with no display/audio device/network.
  Steps: run `./gradlew :feature-player:testDebugUnitTest
  :core-media:testDebugUnitTest` and the Robolectric/instrumented UI tasks;
  static-scan test sources for `Thread.sleep(` and real `OkHttp`/socket usage;
  loop the suite 50x.
  Expected: zero failures; zero `Thread.sleep`/network references; 0 flakes
  across 50 runs; JUnit HTML/XML produced.
  Traces: AC-1, AC-2, AC-9.

- **TC-AND-172-14 — Security: no PII/secrets/network egress from tests**
  Type: manual + integration scan.
  Target: test sources + fixtures + build output.
  Preconditions: tree built.
  Steps: confirm all test media URIs are `file://`/`asset://`/`data:`/fake;
  grep fixtures for real CDN hosts, the dev host `18.222.237.167`, tokens,
  cookies, or device identifiers; confirm tests write only under
  `build/`.
  Expected: no real hosts/secrets/PII committed; no egress; no writes outside
  build dirs.
  Traces: AC-1, AC-9 (and §8).

- **TC-AND-172-15 — Real PiP system behavior (PHYSICAL DEVICE REQUIRED)**
  Type: instrumented/e2e.
  Target: player Activity on the Samsung Galaxy A15 5G (SM-A156U, API 34,
  serial R5CX821TA9R).
  Preconditions: app installed via adb on the physical device; a local/asset
  media source (no network).
  Steps: start playback; trigger PiP (`shouldEnterPip` path / home gesture);
  observe the system PiP window; tap to restore.
  Expected: system enters PiP, custom controls are hidden in the PiP window and
  restored on return; aspect ratio matches the signal. MUST be a physical device
  because real system PiP windowing and the API-34 behavior are not faithfully
  reproduced on the x86_64/API-35 emulator.
  Traces: AC-6.

- **TC-AND-172-16 — Real arm64-v8a decoder/HLS smoke (PHYSICAL DEVICE,
  optional-but-recommended)**
  Type: instrumented/e2e.
  Target: player on the physical A15 (arm64-v8a, API 34).
  Preconditions: a local HLS/MP4 asset bundled with the test apk (no network).
  Steps: prepare + play the asset to `Ready`, scrub, and reach `Ended`.
  Expected: real decoder reaches `Ready`/`Ended` and the reducer surfaces the
  same `PlayerUiState` transitions validated in TC-01/02 on hardware. MUST be a
  physical device to cover the arm64-v8a hardware-decoder path and API-34-vs-35
  differences absent on the x86_64 emulator. (Out of the strict headless AC set;
  a guard-rail against decoder regressions the fakes cannot catch.)
  Traces: AC-3, AC-4 (hardware confirmation).

### Coverage matrix

| §14 Acceptance Criterion | Covered by |
| --- | --- |
| AC-1 (headless JVM suite, zero failures) | TC-13, TC-14 |
| AC-2 (Compose UI tests pass) | TC-09, TC-10, TC-11, TC-13 |
| AC-3 (full state seq + Error + Retry) | TC-01, TC-03, TC-04, TC-05; (TC-16 hw) |
| AC-4 (live vs VOD duration mapping) | TC-02, TC-06; (TC-16 hw) |
| AC-5 (each control intent) | TC-08, TC-09 |
| AC-6 (buffering/error overlays; PiP hides controls) | TC-10, TC-11, TC-15 |
| AC-7 (release on stop/destroy + single instance) | TC-12 |
| AC-8 (HLS factory selection + variant count) | TC-06, TC-07 |
| AC-9 (no sleep/network; 50-run 0-flake) | TC-13, TC-14 |
| AC-10 (>=90% reducer/intent branch coverage; semantics-located controls) | TC-01–05, TC-08, TC-09 |
