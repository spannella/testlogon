---
id: AND-280
title: Viewer playback (HLS)
milestone: M6
epic: E38
priority: P0
size: L
status: draft
depends_on: [AND-278, AND-167]
blocks: []
---

# AND-280 — Viewer playback (HLS)

## 1. Overview & Goal

Deliver the viewer-side live playback experience: given an authenticated, authorized
viewer who opens a broadcast session, the app obtains a signed HLS playback URL from the
backend, verifies the viewer's entitlement, and plays the live stream with adaptive
bitrate switching in a Compose-hosted Media3/ExoPlayer surface. The end-to-end success
criterion from the backlog is unambiguous: **a live stream plays for an authorized
viewer**.

This ticket sits at the intersection of two upstream pieces of work. AND-278 supplies the
broadcast session DTOs and the `/broadcast/sessions` data layer; AND-167 supplies the
reusable Media3 HLS playback primitive (a `MediaSourceFactory` configured for HLS, live +
VOD manifests, adaptive switching) that replaced the web app's `hls.js`. AND-280 is the
*feature* that wires those two together behind a new `playback-url` + `playback/verify`
acquisition flow and a `feature-viewer` screen. It does **not** re-implement the player
core (owned by AND-167) nor the broadcast list/detail (owned by AND-278); it owns the
playback-authorization handshake, the viewer playback screen, and the live-specific UX
(latency target, live-edge seeking, stale/offline handling).

Out of scope: broadcaster/publish path, recording/VOD library browsing, chat/reactions,
DRM (streams are token-authorized cleartext HLS on the dev backend), and picture-in-picture
(tracked separately, not required for the acceptance bar).

## 2. Context & References

- **Repo / module:** `spannella/testlogon`, Android app under `android/`, branch
  `android-port`. New code lands primarily in `:feature-viewer`, with playback-acquisition
  contracts in `:core-network`/`:core-model`/`:core-data`.
- **Namespace / applicationId base:** `com.testlogon.android`. New packages:
  `com.testlogon.android.feature.viewer.*`, `com.testlogon.android.core.network.playback.*`,
  `com.testlogon.android.core.model.playback.*`.
- **Stack:** Kotlin 2.0.21, Jetpack Compose + Material 3, Navigation-Compose (single
  Activity), Hilt (KSP), Coroutines/Flow, Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15,
  Media3/ExoPlayer 1.4 (HLS), Room 2.6, DataStore. minSdk 24, compile/target 35, JDK 17,
  AGP 8.7.3, Gradle 8.9.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (PLAINTEXT HTTP,
  unreliable). OpenAPI at `/openapi.json`. Cookie-based session with `ui_csrf` echoed as
  `X-CSRF-Token`; 401 triggers a single `POST /ui/session/refresh` then retry. Persistent
  cookie jar required.
- **Web reference:** `frontend/src/api/endpoints/*.ts` (playback URL + verify calls),
  `frontend/src/api/types.ts` (shared types), and the prior `hls.js` integration that
  AND-167 supersedes.
- **Upstream tickets:** AND-278 (Broadcast API + DTOs — provides `BroadcastSession`,
  `BroadcastSessionDetail`), AND-167 (HLS playback core — provides the Media3 source
  factory + adaptive switching). AND-280 depends on both.

## 3. Functional Requirements

FR-1. From a broadcast session detail (AND-278), an authorized viewer can navigate to a
**Viewer Playback** screen identified by `sessionId`.

FR-2. On entering the screen, the app requests a playback URL for the session
(`playback-url`) and verifies entitlement (`playback/verify`) before instantiating the
player. The two calls MAY be a single round trip if the backend returns verification
inline; the client must tolerate both shapes (see §5).

FR-3. If verification fails (viewer not authorized, session not live, session ended), the
player is not started and a typed, actionable message is shown (e.g., "This broadcast has
ended", "You don't have access to this broadcast").

FR-4. On success, the screen plays the live HLS stream using the AND-167 player core with
adaptive bitrate switching enabled, defaulting to the live edge.

FR-5. Live UX: show a LIVE indicator when at the live edge; provide a "Go live" affordance
when the user is behind the live edge; show buffering state during stalls; show elapsed/live
position appropriately (no scrub bar seeking past live edge).

FR-6. Playback URLs are signed/time-limited. The screen must refresh the playback URL and
reattach the media source when the URL expires or the player reports a source/auth error
(401/403 on the manifest or a fatal HLS error), without losing screen state.

FR-7. Lifecycle: player pauses and releases the decoder when the screen is backgrounded
(`ON_STOP`) and resumes at the live edge when foregrounded (`ON_START`); the player is fully
released on screen disposal to avoid leaks.

FR-8. Offline/stale: if the network is unavailable or the acquisition calls time out, show
an offline/stale state with a Retry action; do not crash or spin indefinitely.

## 4. Technical Design

**Module placement.** New `:feature-viewer` module (or a `viewer` package within an
existing feature module if `:feature-viewer` already exists from M6 scoping). It depends on
`:core-network`, `:core-model`, `:core-data`, `:core-ui`, and `:core-testing` (test only).
The player core from AND-167 is consumed as a `:core-ui` (or `:core-media`) dependency,
whichever module AND-167 landed it in; this spec assumes a `PlayerFactory`/
`HlsMediaSourceFactory` is injectable via Hilt.

**State contract.** ViewModel exposes `StateFlow<ViewerUiState>`:

```kotlin
sealed interface ViewerUiState {
    data object Loading : ViewerUiState
    data class Ready(
        val sessionId: String,
        val title: String,
        val playback: PlaybackTicket,   // resolved URL + expiry
        val isLive: Boolean,
        val atLiveEdge: Boolean,
        val buffering: Boolean,
    ) : ViewerUiState
    data class Unavailable(val reason: PlaybackUnavailable) : ViewerUiState // not authorized / ended / not live
    data class Error(val message: String, val retryable: Boolean) : ViewerUiState
    data object Offline : ViewerUiState
}

enum class PlaybackUnavailable { NOT_AUTHORIZED, SESSION_ENDED, NOT_STARTED, UNKNOWN }
```

**Domain models** (`:core-model`):

```kotlin
data class PlaybackTicket(
    val url: String,            // HLS manifest (.m3u8) absolute URL
    val type: PlaybackType,     // LIVE | VOD
    val expiresAtEpochMs: Long?,// null = no client-known expiry
    val token: String?,         // opaque, if URL is unsigned and token is a header/query
)
enum class PlaybackType { LIVE, VOD }

data class PlaybackVerification(
    val authorized: Boolean,
    val state: SessionPlaybackState, // LIVE | SCHEDULED | ENDED
    val reason: String?,
)
enum class SessionPlaybackState { LIVE, SCHEDULED, ENDED }
```

**Repository** (`:core-data`), wrapping `:core-network` API in `ApiResult<T>`:

```kotlin
interface PlaybackRepository {
    suspend fun acquirePlayback(sessionId: String): ApiResult<PlaybackTicket>
    suspend fun verifyPlayback(sessionId: String): ApiResult<PlaybackVerification>
}
```

The repository orchestrates verify-then-acquire (or the combined call), maps DTOs to
domain, and surfaces `ApiResult.Error` with the FastAPI `detail` mapping (string |
`[{msg}]` | `{code,...}`) already centralized in `:core-network`.

**ViewModel.**

```kotlin
@HiltViewModel
class ViewerViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val repo: PlaybackRepository,
    private val playerFactory: PlayerFactory,        // from AND-167
    private val clock: Clock,
) : ViewModel() {
    private val sessionId: String = savedStateHandle["sessionId"]!!
    val uiState: StateFlow<ViewerUiState>
    fun start()        // verify + acquire, build Ready
    fun retry()
    fun refreshUrl()   // re-acquire on expiry/auth error, reattach source
    fun onLiveEdgeChanged(atEdge: Boolean)
    fun goLive()
}
```

**Player ownership.** The ExoPlayer instance is created/held in a remembered holder tied
to the composable lifecycle, *not* in the ViewModel, to respect Media3's main-thread and
lifecycle constraints; the ViewModel owns only the acquisition state and the current
`PlaybackTicket`. A `DisposableEffect` + `LifecycleEventObserver` drives play/pause/release.

**Compose UI.**

```kotlin
@Composable
fun ViewerScreen(onBack: () -> Unit, viewModel: ViewerViewModel = hiltViewModel())

@Composable
private fun PlayerSurface(ticket: PlaybackTicket, player: ExoPlayer, modifier: Modifier)
```

`PlayerSurface` hosts Media3's `PlayerView`/`PlayerSurface` (Compose `AndroidView` or the
`androidx.media3.ui.compose` surface), applies the AND-167 `HlsMediaSourceFactory`, sets
`MediaItem.fromUri(ticket.url)`, enables adaptive track selection, and seeks to default
(live edge) on prepare. `Player.Listener` callbacks feed `buffering`, `atLiveEdge`
(via `player.currentLiveOffset` / `isCurrentMediaItemLive`), and fatal-error handling back
to the ViewModel.

**Navigation.** Route `viewer/{sessionId}` registered in the app NavGraph; entered from
the broadcast detail screen (AND-278) with the session id as a path arg.

## 5. API Contract

Exact paths are confirmed against `/openapi.json` at build time; the client tolerates the
two documented shapes below. Both calls are scoped to a session id and ride the cookie
session + `X-CSRF-Token`.

**Acquire playback URL — `POST /broadcast/sessions/{sessionId}/playback-url`**
(GET fallback if OpenAPI exposes it as a query). Treated as idempotent for retry purposes.

Response 200:

```json
{
  "url": "http://18.222.237.167:8000/hls/sess_abc/index.m3u8?sig=...&exp=1733430000",
  "type": "live",
  "expires_at": "2026-06-05T18:00:00Z",
  "token": null
}
```

**Verify entitlement — `POST /broadcast/sessions/{sessionId}/playback/verify`**

Response 200:

```json
{ "authorized": true, "state": "live", "reason": null }
```

Unauthorized / wrong state (HTTP 200 with `authorized:false`, or 403):

```json
{ "authorized": false, "state": "ended", "reason": "broadcast_ended" }
```

**Combined shape tolerance.** If the backend returns verification + URL in a single
`playback` object (`{ "authorized": true, "state": "live", "playback": { "url": ... } }`),
the repository parses both from one response and skips the second call. Retrofit DTOs use
Moshi `@Json` aliases for `expires_at`/`expiresAt` and `state` enums (lowercase strings).

Retrofit interface (`:core-network`):

```kotlin
interface PlaybackApi {
    @POST("broadcast/sessions/{id}/playback-url")
    suspend fun playbackUrl(@Path("id") id: String): Response<PlaybackUrlDto>

    @POST("broadcast/sessions/{id}/playback/verify")
    suspend fun verify(@Path("id") id: String): Response<PlaybackVerifyDto>
}
```

Errors: `401` -> single `POST /ui/session/refresh` + retry (existing OkHttp Authenticator);
`403` -> `Unavailable(NOT_AUTHORIZED)`; `404` -> `Error("Broadcast not found", retryable=false)`;
`409`/state mismatch -> map `state` to `Unavailable`. FastAPI `detail` parsed per the
shared mapper.

## 6. Data & State Management

- **No new Room tables required.** Broadcast session metadata is cached by AND-278; AND-280
  reads it for the title/state but does not own its persistence. Playback tickets are
  short-lived and **never persisted** (signed, expiring) — held only in `ViewerUiState`.
- **Single source of truth:** `StateFlow<ViewerUiState>` in the ViewModel. The composable
  collects with `collectAsStateWithLifecycle()`.
- **Process death:** `sessionId` is restored from `SavedStateHandle`; on restore the screen
  re-runs `start()` to re-acquire a fresh ticket (cheaper and safer than persisting an
  expiring URL).
- **Expiry tracking:** `PlaybackTicket.expiresAtEpochMs` drives a proactive refresh; a
  coroutine schedules `refreshUrl()` ~30s before expiry, and reactive refresh fires on
  player auth/source errors. Refresh reattaches the media source and seeks to live edge,
  preserving `ViewerUiState.Ready` (no full reload flicker).
- **DataStore:** optional persisted preference for last selected quality/auto (read-only
  consumption of AND-167's track-selection prefs if present); no new keys required for the
  acceptance bar.

## 7. Error Handling & Resilience

- **Timeouts:** acquisition calls use the project's ~20s timeout. The combined verify+acquire
  is awaited within a single `withTimeout`-guarded coroutine; timeout -> `Offline` if no
  connectivity, else `Error(retryable=true)`.
- **Retry policy:** bounded backoff retry only for idempotent GET-style acquisition (per
  project rule, idempotent GETs only); `playback/verify` POST is *not* auto-retried beyond
  the single 401-refresh retry. User-initiated `retry()` is always available.
- **Player errors:** `Player.Listener.onPlayerError(PlaybackException)` — for
  `ERROR_CODE_IO_BAD_HTTP_STATUS` (401/403) or `ERROR_CODE_IO_*` on the manifest, call
  `refreshUrl()` once; if refresh also fails, surface `Error(retryable=true)`. Transient
  network blips during live playback rely on Media3's internal buffering/reconnect first.
- **Stale UI:** if the broadcast transitions to `ENDED` (detected via a fatal end-of-stream
  on a live source or a re-verify), show `Unavailable(SESSION_ENDED)` with a back action.
- **Unreliable dev host:** all states (`Loading`, `Buffering`, `Offline`, `Error`) are
  first-class and reachable; no indefinite spinners. A single `refreshUrl()` storm is
  prevented by a debounce/guard flag.

## 8. Security & Privacy

- **Cleartext HTTP:** the dev backend and HLS segments are plaintext `http://`. The dev
  build's `network_security_config.xml` must permit cleartext for `18.222.237.167` only;
  release builds must not ship a blanket cleartext allowance. This is the only sanctioned
  cleartext exception and is documented in the build config.
- **Signed URLs:** playback URLs are time-limited and viewer-scoped. They are not logged in
  full (see §10), not persisted to disk, and not exposed via deep links.
- **Auth:** all calls require the cookie session + `X-CSRF-Token`; the persistent cookie jar
  and 401-refresh Authenticator are reused unchanged. Manifest/segment requests inherit the
  same OkHttp client so cookies/headers ride the HLS data source (Media3 `OkHttpDataSource`
  bridge configured in AND-167).
- **Privacy:** no PII in playback acquisition payloads beyond the session-scoped identity
  already carried by the cookie.

## 9. Accessibility & i18n

- All controls (Back, Retry, Go live, Play/Pause) have `contentDescription`s and meet the
  48dp touch-target minimum; the player surface exposes a labeled control overlay.
- LIVE indicator and error/unavailable copy are localized string resources (no hardcoded
  strings); `PlaybackUnavailable`/`Error` map to distinct resource ids.
- Buffering and live-edge state are announced via `liveRegion` semantics so screen-reader
  users hear "Buffering" / "Live".
- Captions/subtitles: if the HLS manifest carries a text track, Media3 caption styling
  respects the system caption preferences (`CaptionStyleCompat`); rendering them is best-effort
  and not part of the acceptance bar.
- RTL-safe layout via Compose defaults; no fixed left/right paddings.

## 10. Telemetry & Logging

- **Events** (via the project analytics interface, no PII / no full URLs):
  `viewer_playback_requested{sessionId}`, `viewer_playback_verified{authorized,state}`,
  `viewer_playback_started{sessionId,startupMs}`, `viewer_playback_url_refreshed{reason}`,
  `viewer_playback_error{code,retryable}`, `viewer_playback_ended{reason,watchMs}`.
- **Quality of experience:** record startup latency (request -> first frame), rebuffer
  count/duration, and average live offset for diagnosing the unreliable dev host.
- **Logging:** debug logs redact query strings on HLS URLs (log host + path only). No tokens
  or `sig`/`exp` params in logcat. Error logs include `PlaybackException.errorCode` and HTTP
  status only.

## 11. Testing Strategy

- **Unit (`:core-data` / ViewModel, `:core-testing` + Turbine):**
  - Repository maps `PlaybackUrlDto`/`PlaybackVerifyDto` (separate and combined shapes) to
    domain; verifies `expires_at`/`state` parsing and FastAPI `detail` error mapping.
  - ViewModel state machine: `start()` -> `Loading` -> `Ready` on authorized live;
    -> `Unavailable(NOT_AUTHORIZED)` on `authorized:false`; -> `Unavailable(SESSION_ENDED)`
    on `state:ended`; -> `Offline` on no-connectivity; -> `Error(retryable=true)` on timeout.
  - `refreshUrl()` reattaches without leaving `Ready`; refresh-storm guard prevents duplicate
    in-flight refreshes. Expiry scheduler fires before `expiresAtEpochMs`.
- **API contract (MockWebServer):** verify path `POST /broadcast/sessions/{id}/playback-url`
  and `.../playback/verify`, header `X-CSRF-Token` present, 401 -> refresh -> retry happens
  once, 403/404/409 mappings.
- **Compose UI tests:** `ViewerScreen` renders Loading/Ready/Unavailable/Offline/Error;
  Retry invokes `retry()`; Go-live button visible only when behind live edge; semantics/
  contentDescriptions present.
- **Player integration (instrumented, smoke):** with a fake/stub HLS manifest served by
  MockWebServer or a known dev session, assert the player reaches `STATE_READY` and
  `isCurrentMediaItemLive`; assert release on `ON_STOP`/dispose (no leaked player).
- **Acceptance E2E:** authorized viewer opens a live session -> stream plays (manual against
  dev host plus an instrumented happy-path).

## 12. Dependencies & Sequencing

- **Depends on AND-278** (Broadcast API + DTOs): provides `BroadcastSession`/detail models,
  `/broadcast/sessions`, and the navigation entry point. AND-280 consumes session id/title/
  state from it.
- **Depends on AND-167** (HLS playback core): provides the Media3 `HlsMediaSourceFactory` /
  `PlayerFactory`, adaptive switching, live+VOD manifest support, and the OkHttp data-source
  bridge. AND-280 must not duplicate the player core.
- **Blocks:** none recorded in the source bullet (downstream viewer features such as PiP,
  chat, and recordings build on this screen but are out of scope here).
- **Sequencing:** land DTOs/Retrofit (`PlaybackApi`) and `PlaybackRepository` first, then
  ViewModel + state machine with fakes, then the Compose screen wiring to the AND-167 player,
  then instrumented/manual acceptance against the dev host.

## 13. Risks & Open Questions

- **OQ-1:** Exact endpoint verbs/paths and the combined-vs-split response shape must be
  confirmed against `/openapi.json` and `frontend/src/api/endpoints/*.ts`. Client is built to
  tolerate both; confirm before merge.
- **OQ-2:** Are playback URLs signed (query `sig/exp`) or token-header based? This affects
  whether the OkHttp data source needs an extra header vs. raw URL. Default assumption:
  signed query URL.
- **OQ-3:** URL expiry window length (drives the proactive-refresh lead time, currently ~30s).
- **Risk:** unreliable dev host causes flaky live playback; mitigated by buffering states,
  bounded retry, refresh-on-error, and QoE telemetry.
- **Risk:** cleartext HLS segments — must be confined to the dev cleartext allow-list and not
  leak into release config.
- **Risk:** Media3 lifecycle/main-thread misuse causing leaks; mitigated by holding the player
  in the composable (not ViewModel) and explicit release tests.

## 14. Acceptance Criteria

AC-1. An authorized viewer opening a live broadcast session reaches `ViewerUiState.Ready`
and the **live HLS stream plays** with adaptive bitrate switching (satisfies the source
acceptance: "Live stream plays for an authorized viewer").

AC-2. The app calls `playback/verify` and `playback-url` (or the combined call) before
starting the player; an unauthorized or ended session yields `Unavailable` and the player is
not started.

AC-3. On manifest auth/source error or ticket expiry, the client refreshes the URL once and
resumes without leaving `Ready` or losing screen state.

AC-4. Backgrounding pauses/releases the decoder; foregrounding resumes at the live edge;
disposal fully releases the player (no leak in instrumented test).

AC-5. Offline/timeout produces `Offline`/`Error(retryable=true)` with a working Retry — never
an infinite spinner.

AC-6. All listed unit, MockWebServer contract, and Compose UI tests pass; the instrumented
happy-path smoke reaches `STATE_READY` on a live manifest.

AC-7. No tokens or signed-URL query params appear in logs; cleartext is restricted to the dev
host allow-list.

## 15. Definition of Done

- Code merged to `android-port` under `com.testlogon.android.feature.viewer.*` (+ network/
  model/data additions), reviewed and green in CI (build, lint/detekt, unit + instrumented).
- `PlaybackApi`, `PlaybackRepository`, `ViewerViewModel`, `ViewerScreen`, and domain models
  implemented with the signatures in §4–§6.
- All §14 acceptance criteria demonstrably met, including a manual verification of live
  playback against `http://18.222.237.167:8000` for an authorized viewer.
- Telemetry events from §10 emitted and verified; logging redaction confirmed.
- Strings localized; accessibility semantics present; dev cleartext config scoped and
  release config verified clean.
- Open questions OQ-1..OQ-3 resolved or explicitly deferred with follow-up tickets; spec
  updated if endpoint shapes differ from §5.
