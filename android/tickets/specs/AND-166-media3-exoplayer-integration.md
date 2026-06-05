---
id: AND-166
title: Media3/ExoPlayer integration
milestone: M4
epic: E23
priority: P0
size: M
status: draft
depends_on: [AND-003]
blocks: [AND-167, AND-168, AND-171]
---

# AND-166 — Media3/ExoPlayer integration

## 1. Overview & Goal

This ticket establishes the foundational video playback capability for the TestLogon
native Android app by integrating AndroidX Media3 (ExoPlayer) 1.4 and exposing a thin,
testable, lifecycle-aware abstraction over it. The deliverable is a new `core-player`
Kotlin library module (under the `core-*` layer) that owns the Media3 dependency, a
`PlayerManager` wrapper that brokers a single reusable `ExoPlayer` instance, and a minimal
Compose surface that renders that player. The acceptance bar is intentionally narrow and
verifiable: a progressive MP4 must play inside a Compose surface, proven by an
instrumented test.

The goal is foundational plumbing, not product features. HLS/adaptive streaming
(AND-167), the full reusable player UI with controls/overlays (AND-168), and
backend-driven playback URLs (AND-280) are explicitly out of scope and are downstream
consumers of the `PlayerManager` API delivered here. This ticket must produce an API that
those tickets can build on without refactoring: a single source of truth for player
lifecycle, correct resource release across configuration changes and process
backgrounding, and an idiomatic `StateFlow`-based state surface for ViewModels.

Why a single-player wrapper: Media3 `ExoPlayer` instances are expensive (each binds audio
focus, codecs, and surface handles). Creating one per screen leaks codecs on
mid-range minSdk-24 devices and breaks audio focus arbitration. Centralizing creation,
reuse, and release in `PlayerManager` is the architectural decision this ticket exists to
enforce.

## 2. Context & References

- **Repo / branch:** `spannella/testlogon`, Android app in `android/` (monorepo subfolder),
  branch `android-port`.
- **Namespace base:** `com.testlogon.android`. New module namespace:
  `com.testlogon.android.core.player`.
- **Stack:** Kotlin 2.0.21, Jetpack Compose + Material 3, Hilt (KSP), Coroutines/Flow,
  Media3/ExoPlayer 1.4, minSdk 24, compileSdk/targetSdk 35, JDK 17, Gradle 8.9, AGP 8.7.3.
- **Module layering:** `app -> feature-* -> core-*`. `core-player` is a new `core-*`
  module. It depends only on `core-model` (for any shared media value types) and
  `core-testing` (test-only). It must not depend on any `feature-*` module.
- **Upstream dependency:** AND-003 (Core module structure) — provides the module
  scaffolding conventions, version catalog (`gradle/libs.versions.toml`), shared
  `build-logic` convention plugins, and the `core-testing` module that this module reuses.
- **Downstream consumers (blocked by this ticket):** AND-167 (HLS playback), AND-168
  (Reusable player UI), AND-171 (P2 playback enhancement). AND-280 (viewer playback) and
  AND-190 (video detail + player) consume the resulting `PlayerSurface` + `PlayerManager`.
- **Web reference:** the web app uses `hls.js` for streaming; that is replaced by Media3
  in AND-167. There is no progressive-MP4 web analog — this Android wrapper is the
  reference implementation for native playback.
- **Media3 docs basis:** `androidx.media3:media3-exoplayer`,
  `androidx.media3:media3-ui` (PlayerView for the AndroidView interop),
  `androidx.media3:media3-common` (Player interface, `Player.Listener`, `PlaybackException`).

## 3. Functional Requirements

FR-1. Add Media3 1.4 dependencies to the version catalog and to a new `core-player` module.
The module compiles and is consumable by `feature-*` and `app`.

FR-2. Provide `PlayerManager`: a process-scoped (Hilt `@Singleton`) component that lazily
creates exactly one `ExoPlayer` and hands it out for reuse. Repeated `acquire()` calls
return the same underlying instance; the manager never creates a second player while one
is live.

FR-3. `PlayerManager` exposes imperative control: `setMediaItem(uri, autoPlay)`,
`play()`, `pause()`, `seekTo(positionMs)`, `stop()`, and `release()`.

FR-4. `PlayerManager` exposes observable state as `StateFlow<PlayerUiState>` derived from a
`Player.Listener`. State includes playback state (idle/buffering/ready/ended), isPlaying,
current position/duration (sampled), and the last error (if any).

FR-5. Lifecycle-aware release: a `PlayerSurface` Composable observes the host
`LifecycleOwner` and (a) pauses on `ON_STOP`, (b) detaches the surface on `ON_PAUSE`/
`ON_STOP` to free the codec/display, and (c) does **not** destroy the singleton player on
rotation (config change) so playback position survives recreation. The player is fully
released when the owning ViewModel is cleared (`onCleared()`), not on every screen leave.

FR-6. Single-player reuse across surfaces: when a second `PlayerSurface` attaches, the
manager re-parents the same player to the new surface and detaches the previous one (no
double-bind). Only one surface renders the player at a time.

FR-7. A Compose `PlayerSurface(modifier, playerManager)` renders the active player via
`AndroidView` wrapping Media3 `PlayerView`, with default controller chrome **disabled**
(controls are AND-168's responsibility; this surface is bare video).

FR-8. A progressive MP4 (`https`-or-bundled-asset URI) plays end-to-end in `PlayerSurface`,
proven by an instrumented test (the acceptance criterion).

## 4. Technical Design

New module: `android/core-player/`. Files:

- `core-player/build.gradle.kts` — applies the `core` library + Hilt convention plugins
  from AND-003's `build-logic`; namespace `com.testlogon.android.core.player`.
- `PlayerManager.kt`, `PlayerUiState.kt`, `PlayerSurface.kt`, `PlayerModule.kt`.

Hilt provision (player must be tied to `Context` but process-scoped):

```kotlin
@Module
@InstallIn(SingletonComponent::class)
object PlayerModule {
    @Provides @Singleton
    fun providePlayerManager(
        @ApplicationContext context: Context,
        @DefaultDispatcher dispatcher: CoroutineDispatcher,
    ): PlayerManager = DefaultPlayerManager(context, dispatcher)
}
```

Manager contract:

```kotlin
interface PlayerManager {
    val state: StateFlow<PlayerUiState>
    /** Returns the singleton ExoPlayer, creating it on first call (main thread). */
    fun acquire(): Player
    fun setMediaItem(uri: String, autoPlay: Boolean = true)
    fun play()
    fun pause()
    fun seekTo(positionMs: Long)
    fun stop()
    /** Releases the underlying ExoPlayer; next acquire() recreates it. */
    fun release()
}
```

`DefaultPlayerManager` implementation notes:

- Holds `private var exo: ExoPlayer? = null`. `acquire()` is `@MainThread`; it builds via
  `ExoPlayer.Builder(context).setHandleAudioBecomingNoisy(true).build()` and attaches a
  `Player.Listener`. ExoPlayer is **not** thread-safe — all calls run on the application
  main looper; the manager asserts main-thread via `Looper.myLooper() == player.applicationLooper`.
- A `Player.Listener` maps Media3 callbacks (`onPlaybackStateChanged`,
  `onIsPlayingChanged`, `onPlayerError(PlaybackException)`, `onPlaybackParametersChanged`)
  into `MutableStateFlow<PlayerUiState>`.
- Position is not pushed by Media3; the manager exposes a `positionFlow(intervalMs = 500)`
  cold flow used by UI tickers, plus snapshots `player.currentPosition`/`duration` in state
  on discrete events. This keeps the always-on `state` flow cheap.

Surface Composable:

```kotlin
@Composable
fun PlayerSurface(
    playerManager: PlayerManager,
    modifier: Modifier = Modifier,
) {
    val lifecycleOwner = LocalLifecycleOwner.current
    val player = remember(playerManager) { playerManager.acquire() }
    AndroidView(
        modifier = modifier,
        factory = { ctx ->
            PlayerView(ctx).apply {
                useController = false
                setShowBuffering(PlayerView.SHOW_BUFFERING_NEVER)
                this.player = player
            }
        },
        onReset = { it.player = null },
        onRelease = { it.player = null },
    )
    DisposableEffect(lifecycleOwner) {
        val obs = LifecycleEventObserver { _, e ->
            when (e) {
                Lifecycle.Event.ON_STOP -> playerManager.pause()
                else -> Unit
            }
        }
        lifecycleOwner.lifecycle.addObserver(obs)
        onDispose { lifecycleOwner.lifecycle.removeObserver(obs) }
    }
}
```

Config-change survival is automatic because `PlayerManager` is a `@Singleton`: rotation
recreates the Composable, which re-`acquire()`s the same `Player` and rebinds it to a fresh
`PlayerView`. The `onRelease`/`onReset` callbacks null the `player` on the old view to
avoid double-binding (FR-6). Full teardown is owned by the consuming ViewModel:

```kotlin
@HiltViewModel
class SomeVideoViewModel @Inject constructor(
    private val playerManager: PlayerManager,
) : ViewModel() {
    override fun onCleared() { playerManager.release() }
}
```

## 5. API Contract

No backend HTTP API is consumed by this ticket. Playback URL resolution
(`GET /ui/...playback-url`, `POST /ui/.../playback/verify`) and the FastAPI
cookie/CSRF session are owned by AND-280 / AND-167, which supply ready URIs to
`PlayerManager.setMediaItem(uri, ...)`.

The relevant contract here is the **internal module API** (the public surface other modules
depend on):

| Symbol | Signature | Stability |
|---|---|---|
| `PlayerManager` | interface (see §4) | public, stable |
| `PlayerUiState` | data class (see §6) | public, stable |
| `PlayerSurface` | `@Composable (PlayerManager, Modifier)` | public, stable |
| `PlayerModule` | Hilt module | internal |
| `DefaultPlayerManager` | impl | internal |

Test media for the acceptance test is a bundled `androidTest` asset
(`core-player/src/androidTest/assets/sample_progressive.mp4`, a short H.264/AAC clip ≤2 s),
referenced as `asset:///sample_progressive.mp4`, so the test has no network dependency on
the unreliable dev backend (`http://18.222.237.167:8000`).

## 6. Data & State Management

State type:

```kotlin
data class PlayerUiState(
    val playbackState: Playback = Playback.IDLE,   // IDLE, BUFFERING, READY, ENDED
    val isPlaying: Boolean = false,
    val positionMs: Long = 0L,
    val durationMs: Long = C.TIME_UNSET,           // -9_223_372_036_854_775_807 when unknown
    val error: PlayerError? = null,
) {
    enum class Playback { IDLE, BUFFERING, READY, ENDED }
}

data class PlayerError(val code: Int, val message: String, val isRetryable: Boolean)
```

Mapping rules from Media3 to `PlayerUiState.Playback`:
`Player.STATE_IDLE -> IDLE`, `STATE_BUFFERING -> BUFFERING`, `STATE_READY -> READY`,
`STATE_ENDED -> ENDED`.

State ownership: `DefaultPlayerManager` holds the single
`MutableStateFlow<PlayerUiState>`; `state` is its read-only view. ViewModels collect it and
re-expose their own `StateFlow<UiState>` per the project's ViewModel contract — the manager
itself is UI-agnostic and holds no ViewModel reference. No Room/DataStore persistence is
introduced by this ticket; playback position is in-memory only (resume-across-process is a
later concern). DataStore/Room are N/A here and remain owned by `core-data`.

## 7. Error Handling & Resilience

- `onPlayerError(PlaybackException)` populates `PlayerUiState.error`. `PlaybackException.errorCode`
  is surfaced as `PlayerError.code`; `isRetryable` is true for transient codes
  (`ERROR_CODE_IO_NETWORK_CONNECTION_FAILED`, `ERROR_CODE_IO_NETWORK_CONNECTION_TIMEOUT`,
  `ERROR_CODE_BEHIND_LIVE_WINDOW`) and false for source/codec errors
  (`ERROR_CODE_DECODING_FAILED`, `ERROR_CODE_PARSING_*`).
- Retry policy: `PlayerManager` does **not** auto-retry in this ticket beyond Media3's
  built-in `seekToDefaultPosition() + prepare()` exposed via a `retry()` helper. Network
  backoff for HLS is AND-167's concern. Because the dev backend is HTTP-only and flaky,
  the default `DefaultHttpDataSource` is configured with a 20 s connect/read timeout to
  match the project-wide budget, even though this ticket plays a local asset.
- Resilience to lifecycle: pausing on `ON_STOP` and detaching the surface prevents codec
  starvation and "MediaCodec released" crashes when the screen backgrounds. Re-binding on
  return resumes from retained position.
- Double-acquire safety: `acquire()` is idempotent; concurrent surface attaches re-parent
  rather than recreate (FR-6).

## 8. Security & Privacy

- No credentials, cookies, or PII are handled by `core-player`. The cookie-based FastAPI
  session and `X-CSRF-Token` handling live in `core-network` and are not referenced here;
  signed playback URLs (if any) arrive pre-resolved from AND-280.
- Cleartext HTTP: the dev backend is plaintext. This module plays a local asset and does
  not itself open network sockets, so it requires no `usesCleartextTraffic` change; that
  manifest concern is deferred to AND-167 when remote HLS is fetched. The `core-player`
  manifest declares no permissions beyond what Media3 transitively needs.
- No analytics or third-party SDK is added. Media3 is AndroidX (Apache-2.0), no telemetry.

## 9. Accessibility & i18n

- `PlayerView` is configured with `useController = false`, so there are no interactive
  controls to label in this ticket — accessible transport controls are AND-168's scope.
  The bare surface sets a `contentDescription` passed via the Composable
  (`PlayerSurface(..., contentDescription: String?)`) so a containing screen can announce
  "Video player" to TalkBack.
- No user-facing strings ship in `core-player` except an optional default content
  description, which is added to `core-player/src/main/res/values/strings.xml`
  (`player_surface_content_desc`) for translation. All error text shown to users is
  formatted by consumers from `PlayerError.code`, not hardcoded English here.
- RTL: `AndroidView` honors layout direction; no manual mirroring needed for a video frame.

## 10. Telemetry & Logging

- Lightweight logging via the project logger (Timber or the agreed `core-*` logging facade):
  log player creation, release, media-item set, and `onPlayerError` at DEBUG/WARN. No PII
  in logs (log URI scheme/host only, not query strings that may carry tokens).
- An `AnalyticsListener` hook point is left as a TODO seam (`DefaultPlayerManager` accepts
  an optional `AnalyticsListener?`) so AND-167/AND-168 can attach playback-quality metrics
  (rebuffering count, initial-load time) without changing the public API. No metrics are
  emitted in this ticket.

## 11. Testing Strategy

- **Unit (JVM, `test/`):** Map Media3 player states to `PlayerUiState` using a fake
  `Player` / `TestExoPlayerBuilder` from `androidx.media3:media3-test-utils`, plus a
  `RobolectricTestRunner` where a `Looper` is required. Assert: state transitions
  IDLE→BUFFERING→READY→ENDED; `onPlayerError` populates `PlayerError` with correct
  `isRetryable`; `acquire()` returns the same instance twice; `release()` then `acquire()`
  yields a new instance.
- **Instrumented (`androidTest/`, the acceptance test):** `MediaPlaybackTest` launches a
  Compose host containing `PlayerSurface`, calls `setMediaItem("asset:///sample_progressive.mp4")`,
  and uses Compose test + `IdlingResource` (or `runComposeUiTest` with an awaiting
  collector on `state`) to assert `playbackState == READY` then `isPlaying == true` and
  `positionMs` advances > 0 within a timeout. Uses `TestExoPlayerBuilder` with a real
  decoder on device/emulator.
- **Lifecycle test:** drive a `TestLifecycleOwner` to `ON_STOP` and assert the manager
  pauses; recreate the Composable (simulating rotation) and assert the same `Player` is
  rebound and position is preserved.
- Coverage gate: `core-player` participates in the module CI matrix from AND-003;
  instrumented test runs on the emulator job.

## 12. Dependencies & Sequencing

- **Depends on AND-003** (module structure, version catalog, `build-logic` convention
  plugins, `core-testing`). Cannot start until `core-*` scaffolding exists.
- **Blocks AND-167** (HLS playback — adds `media3-exoplayer-hls`, builds on `PlayerManager`),
  **AND-168** (reusable player UI — adds controls atop `PlayerSurface`), and **AND-171**
  (P2 playback enhancement).
- **Version catalog additions** (`gradle/libs.versions.toml`): `media3 = "1.4.1"`, with
  `media3-exoplayer`, `media3-ui`, `media3-common`, and test-only `media3-test-utils`.
- Sequencing within this ticket: (1) catalog + module skeleton, (2) `PlayerManager` + state,
  (3) `PlayerSurface`, (4) tests + bundled asset.

## 13. Risks & Open Questions

- **R1 — Singleton vs. per-screen lifetime.** A process `@Singleton` player risks audio
  leaking between screens if a consumer forgets to `release()` in `onCleared()`. Mitigation:
  document the contract and add a lint/PR-checklist note; consider a future
  `@ViewModelScoped` overload. Open question: should AND-168 own release instead?
- **R2 — minSdk 24 codec variance.** Some API-24 devices lack hardware H.264 high-profile
  decoders. Mitigation: bundle a baseline-profile sample MP4 for the test; document
  recommended encoding for AND-280 source media.
- **R3 — Compose `AndroidView` recomposition.** Incorrect `remember` keys can rebuild
  `PlayerView` and re-bind the player, causing flicker. Mitigation: stable `factory` +
  null-on-release; covered by the rotation test.
- **R4 — media3-test-utils availability on JVM.** If Robolectric cannot host the test
  player, fall back to instrumented-only for state-mapping tests.
- **Open:** Final Media3 patch version (1.4.1 assumed) to confirm against AGP 8.7.3.

## 14. Acceptance Criteria

- AC-1. `core-player` module compiles and is consumed by `app` (and consumable by
  `feature-*`); `./gradlew :core-player:assembleDebug` succeeds.
- AC-2. Media3 1.4 dependencies are declared in the version catalog and used via catalog
  aliases (no hardcoded versions in `build.gradle.kts`).
- AC-3. `PlayerManager` is a Hilt `@Singleton`; two `acquire()` calls return the same
  `Player` instance (unit-tested).
- AC-4. `PlayerManager.state` emits `READY` then `isPlaying = true` with advancing
  `positionMs` when a media item is set and `play()` is invoked.
- AC-5. **A progressive MP4 plays in a Compose `PlayerSurface`, proven by the instrumented
  `MediaPlaybackTest`** (the source ticket's acceptance bar).
- AC-6. Lifecycle: `ON_STOP` pauses playback; rotation preserves the player instance and
  playback position; `onCleared()` releases the player (no leaked codec, verified by
  StrictMode/no "Player not released" warning in logcat).
- AC-7. The player surface renders with default controller chrome disabled.

## 15. Definition of Done

- Code merged to `android-port` with `core-player` module added and wired per AND-003
  conventions; namespace `com.testlogon.android.core.player`.
- All unit and instrumented tests pass in CI, including the acceptance instrumented test
  on the emulator job; bundled `sample_progressive.mp4` asset committed.
- Public API (`PlayerManager`, `PlayerUiState`, `PlayerSurface`) reviewed and documented
  with KDoc; downstream owners (AND-167, AND-168) sign off that the API meets their needs.
- No new lint/detekt regressions; no cleartext or permission additions in this module.
- Logging seam and optional `AnalyticsListener` hook present but emit nothing by default.
- Spec acceptance criteria AC-1…AC-7 all demonstrably met; PR description links this spec.
