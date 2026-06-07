---
id: AND-280
title: Viewer playback (HLS)
milestone: M6
epic: E38
priority: P0
size: L
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-278, AND-167]
blocks: []
---

# AND-280 — Viewer playback (HLS)

## 1. Overview & Goal

Deliver the viewer-side live playback experience: given an authenticated, authorized
viewer who opens a broadcast session, the app obtains a signed HLS playback URL from the
backend (the mint call is itself the entitlement gate — see §5 correction) and plays the
live stream with adaptive bitrate switching in a Compose-hosted Media3/ExoPlayer surface.
The end-to-end success
criterion from the backlog is unambiguous: **a live stream plays for an authorized
viewer**.

This ticket sits at the intersection of two upstream pieces of work. AND-278 supplies the
broadcast session DTOs and the `/broadcast/sessions` data layer; AND-167 supplies the
reusable Media3 HLS playback primitive (a `MediaSourceFactory` configured for HLS, live +
VOD manifests, adaptive switching) that replaced the web app's `hls.js`. AND-280 is the
*feature* that wires those two together behind the `playback-url` acquisition flow
(verified: `POST /broadcast/sessions/{session_id}/playback-url`) and a `feature-viewer`
screen. NOTE (review correction): there is no client-side `playback/verify` call in the
web reference — minting the playback URL *is* the authorization check (it returns the URL
only for an entitled viewer, else an HTTP error). The endpoint `GET /broadcast/playback/verify`
exists but is a server/edge CloudFront-token check (`{valid: boolean}`), not part of the
viewer client contract. See §5 and §16. It does **not** re-implement the player
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
- **Web reference:** `frontend/src/api/endpoints/broadcast.ts` (`mintPlaybackUrl`),
  `frontend/src/pages/broadcast/LivePlayer.tsx` (viewer screen flow), and
  `frontend/src/components/shared/MediaPlayer.tsx` (the `hls.js` integration that AND-167
  supersedes). The web reference does NOT make any `playback/verify` call (verified by
  grep; see §16).
- **Upstream tickets:** AND-278 (Broadcast API + DTOs — provides `BroadcastSession`,
  `BroadcastSessionDetail`), AND-167 (HLS playback core — provides the Media3 source
  factory + adaptive switching). AND-280 depends on both.

## 3. Functional Requirements

FR-1. From a broadcast session detail (AND-278), an authorized viewer can navigate to a
**Viewer Playback** screen identified by `sessionId`.

FR-2. On entering the screen, the app loads session metadata (`GET /broadcast/sessions/{id}`,
from AND-278) for the title/status, then requests a playback URL for the session
(`POST /broadcast/sessions/{id}/playback-url`) before instantiating the player. The mint
call is the entitlement gate: a 200 means the viewer is authorized and yields the signed
URL; a non-2xx (401/403/404/4xx) means the player is not started. (Review correction: there
is no separate client `playback/verify` round trip — see §5/§16.)

FR-3. If the mint call fails because the viewer is not entitled or the session is not
playable (403 not authorized, 404 not found, or the session `status` is not `live`/`ready`),
the player is not started and a typed, actionable message is shown (e.g., "This broadcast has
ended", "You don't have access to this broadcast"). Session non-live/ended state is derived
from the `status` field of `GET /broadcast/sessions/{id}` (`BroadcastSessionStatus`:
`draft|scheduled|provisioning|ready|live|stopping|stopped|cancelled|error`), not from a
verify response.

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
// Review correction: the verified BroadcastPlaybackUrlOut shape is
// { session_id: String, playback_url: String, expires_at: Int (epoch SECONDS) }.
// There is no `type` or `token` field in the response. `type` below is derived
// client-side (LIVE for the live viewer screen); `expiresAtEpochMs` is computed from
// expires_at * 1000.
data class PlaybackTicket(
    val url: String,            // HLS manifest (.m3u8) absolute URL = playback_url
    val type: PlaybackType,     // LIVE | VOD — derived client-side, not from the DTO
    val expiresAtEpochMs: Long?,// = expires_at(sec) * 1000; null = no client-known expiry
)
enum class PlaybackType { LIVE, VOD }

// Review correction: NOT backed by a `playback/verify` call. Entitlement = HTTP status
// of the mint call; playback state is derived from BroadcastSession.status (AND-278).
// Kept as a small domain projection so the ViewModel can map to Unavailable reasons.
data class PlaybackVerification(
    val authorized: Boolean,         // mint call returned 200
    val state: SessionPlaybackState, // mapped from BroadcastSessionStatus
    val reason: String?,             // FastAPI `detail` text when unauthorized
)
enum class SessionPlaybackState { LIVE, SCHEDULED, ENDED }
```

**Repository** (`:core-data`), wrapping `:core-network` API in `ApiResult<T>`:

```kotlin
interface PlaybackRepository {
    // Mints the signed URL; a 200 is itself the entitlement check.
    suspend fun acquirePlayback(sessionId: String): ApiResult<PlaybackTicket>
    // Review correction: there is no /playback/verify client endpoint. This derives a
    // PlaybackVerification from BroadcastSession.status (AND-278) + the mint result,
    // rather than calling a verify API. Kept for the ViewModel's Unavailable mapping.
    suspend fun verifyPlayback(sessionId: String): ApiResult<PlaybackVerification>
}
```

The repository acquires the URL (the mint call is the authorization gate), reads session
`status` from AND-278 to classify SCHEDULED/ENDED, maps DTOs to domain, and surfaces
`ApiResult.Error` with the FastAPI `detail` mapping (string | `[{msg}]` | `{code,...}`)
already centralized in `:core-network` (verified against `normalizeErrorDetail` in
`src/api/client.ts`).

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

**This section was substantially corrected during review.** All paths/shapes below are
verified against `reference/openapi.index.txt`, `reference/openapi.pretty.json`
(`components.schemas.BroadcastPlaybackUrlOut`), and the web client
(`src/api/endpoints/broadcast.ts: mintPlaybackUrl`, `src/pages/broadcast/LivePlayer.tsx`).
All calls ride the cookie session + `X-CSRF-Token` (CSRF = `ui_csrf` cookie echoed as the
`X-CSRF-Token` header — verified in `src/api/client.ts`).

**Acquire playback URL — `POST /broadcast/sessions/{session_id}/playback-url`** (verified;
op `mint_playback_url_route_...`). Optional query param `invite_token` for private/allowlisted
sessions (verified in the OpenAPI params). No request body. The web client treats this as the
single acquisition + authorization call. Treated as idempotent for retry purposes.

Response 200 — schema `BroadcastPlaybackUrlOut` (verified, all three fields required):

```json
{
  "session_id": "sess_abc",
  "playback_url": "http://18.222.237.167:8000/hls/sess_abc/index.m3u8?sig=...",
  "expires_at": 1733430000
}
```

CORRECTIONS vs the original draft: the field is **`playback_url`** (not `url`);
**`expires_at` is an integer epoch in SECONDS** (not an ISO-8601 string); there is **no
`type` field and no `token` field** in the response; and there is **no combined
`{authorized, state, playback}` object** — that shape was fabricated and is removed.

**Verify entitlement — NO client call.** CORRECTION: the original draft's
`POST /broadcast/sessions/{sessionId}/playback/verify` does not exist. The web reference
(grep over `src/`) makes **no** `playback/verify` request at all; entitlement is enforced by
the mint call's HTTP status. The only verify endpoint in the API is
**`GET /broadcast/playback/verify`** (op `verify_playback_token_route_...`), with **query
params `path`, `cf_token`, `cf_expires`** (all required) returning schema
`BroadcastPlaybackTokenVerifyOut` = `{ "valid": boolean }`. This is a CloudFront
signed-token verification helper used at the edge/server, NOT part of the Android viewer
client contract. The Android client SHOULD NOT call it.

**Playback state** is read from `GET /broadcast/sessions/{id}` (AND-278, schema
`BroadcastSessionOut`) via `status` (`BroadcastSessionStatus`:
`draft|scheduled|provisioning|ready|live|stopping|stopped|cancelled|error`). The web client
shows the LIVE badge when `status === "live"`. Map `status` to `SessionPlaybackState`:
`live`→LIVE; `scheduled|provisioning|ready`→SCHEDULED; `stopping|stopped|cancelled|error`→ENDED.

Retrofit interface (`:core-network`) — corrected:

```kotlin
interface PlaybackApi {
    @POST("broadcast/sessions/{id}/playback-url")
    suspend fun playbackUrl(
        @Path("id") id: String,
        @Query("invite_token") inviteToken: String? = null,
    ): Response<PlaybackUrlDto>   // { session_id, playback_url, expires_at: Long(seconds) }
    // No verify(): entitlement = HTTP status of playbackUrl(); session state comes from
    // the AND-278 BroadcastSession API.
}
```

Moshi DTO maps `playback_url` → `url` and `expires_at` (seconds) → `expiresAtEpochMs`
(× 1000) in the repository layer.

Errors (FastAPI `detail` parsed per the shared mapper, verified):
`401` -> single `POST /ui/session/refresh` + one retry (verified in `client.ts`; only when
already authenticated); `403` -> `Unavailable(NOT_AUTHORIZED)` (body carries FastAPI `detail`,
which may be a string, `[{msg}]`, or `{code,...}`; geo-block surfaces `{code:"geo_blocked"}`);
`404` -> `Error("Broadcast not found", retryable=false)`; `422` -> validation error
(`HTTPValidationError`, the documented error for these routes). Session-ended/not-live is
inferred from `BroadcastSession.status`, not an HTTP `409`.

## 6. Data & State Management

- **No new Room tables required.** Broadcast session metadata is cached by AND-278; AND-280
  reads it for the title/state but does not own its persistence. Playback tickets are
  short-lived and **never persisted** (signed, expiring) — held only in `ViewerUiState`.
- **Single source of truth:** `StateFlow<ViewerUiState>` in the ViewModel. The composable
  collects with `collectAsStateWithLifecycle()`.
- **Process death:** `sessionId` is restored from `SavedStateHandle`; on restore the screen
  re-runs `start()` to re-acquire a fresh ticket (cheaper and safer than persisting an
  expiring URL).
- **Expiry tracking:** `PlaybackTicket.expiresAtEpochMs` (= `expires_at` seconds × 1000)
  drives a proactive refresh. CORRECTION: to match the web reference
  (`LivePlayer.tsx`), schedule `refreshUrl()` at **75% of the remaining time** (the web
  client uses `remainingSec * 750` ms and skips scheduling when `remainingSec <= 10`), not a
  fixed ~30s lead. Reactive refresh also fires on player auth/source errors. Refresh
  reattaches the media source and seeks to live edge, preserving `ViewerUiState.Ready` (no
  full reload flicker).
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
  - Repository maps `PlaybackUrlDto` (`{session_id, playback_url, expires_at:Long seconds}`)
    to domain; verifies `playback_url`→url, `expires_at`(sec)→`expiresAtEpochMs`(×1000), and
    FastAPI `detail` error mapping. Session-state classification from `BroadcastSession.status`
    is also unit-tested. (Correction: no `PlaybackVerifyDto`/combined-shape parsing — those
    were removed.)
  - ViewModel state machine: `start()` -> `Loading` -> `Ready` on authorized live;
    -> `Unavailable(NOT_AUTHORIZED)` on `authorized:false`; -> `Unavailable(SESSION_ENDED)`
    on `state:ended`; -> `Offline` on no-connectivity; -> `Error(retryable=true)` on timeout.
  - `refreshUrl()` reattaches without leaving `Ready`; refresh-storm guard prevents duplicate
    in-flight refreshes. Expiry scheduler fires before `expiresAtEpochMs`.
- **API contract (MockWebServer):** verify path/method `POST /broadcast/sessions/{id}/playback-url`
  (single call; no `playback/verify`), header `X-CSRF-Token` present, response field names
  `playback_url`/`expires_at`, 401 -> refresh (`POST /ui/session/refresh`) -> retry happens
  once, 403/404/422 mappings.
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

- **OQ-1 (RESOLVED by review):** Verified — acquisition is a single call,
  `POST /broadcast/sessions/{session_id}/playback-url` returning `BroadcastPlaybackUrlOut`
  `{session_id, playback_url, expires_at}`. There is no client `playback/verify` call and no
  combined-vs-split ambiguity (the combined shape was fabricated). See §5/§16.
- **OQ-2 (RESOLVED by review):** Playback URLs are signed query URLs (the web client passes
  `playback_url` straight to the player with no extra header; `LivePlayer.tsx` /
  `MediaPlayer.tsx`). The OkHttp data source needs no extra auth header for the manifest
  beyond the shared cookie jar. Note: HLS segment fetches use the URL signature; the
  manifest example carries `?sig=...`.
- **OQ-3 (RESOLVED by review):** Expiry is `expires_at` (epoch seconds) returned per mint;
  the web client refreshes at 75% of remaining time. The absolute window length is
  server-controlled and read from each response rather than hardcoded.
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

AC-2. The app calls `POST .../playback-url` (the single acquisition + entitlement call)
before starting the player; an unauthorized (non-2xx) or non-live session (per
`BroadcastSession.status`) yields `Unavailable` and the player is not started. (Corrected:
no separate `playback/verify` client call.)

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

## 16. Citations & Assumption Audit

Sources: OpenAPI index `reference/openapi.index.txt`, OpenAPI spec
`reference/openapi.pretty.json` (`components.schemas.*`), and the web reference under
`reference/src/`. Each claim below is the original spec claim, a VERDICT, and a SOURCE.

1. **Acquire path/method = `POST /broadcast/sessions/{session_id}/playback-url`.**
   VERDICT: Verified. SOURCE: OpenAPI `POST /broadcast/sessions/{session_id}/playback-url`
   (op `mint_playback_url_route_...`); `src/api/endpoints/broadcast.ts: mintPlaybackUrl`
   (`api.post(\`/broadcast/sessions/${id}/playback-url\`)`).

2. **`playback-url` accepts an optional `invite_token` query param.**
   VERDICT: Verified. SOURCE: OpenAPI index line for the route (`params=session_id,invite_token,...`).
   The web `mintPlaybackUrl` does not pass it, so it is optional for public sessions.

3. **Acquire 200 response = `BroadcastPlaybackUrlOut { session_id, playback_url, expires_at }`,
   all required; `expires_at` is integer epoch seconds.**
   VERDICT: Corrected (original draft used `url`, ISO-string `expires_at`, plus `type`/`token`).
   SOURCE: `openapi.pretty.json` `components.schemas.BroadcastPlaybackUrlOut`
   (`playback_url:string`, `expires_at:integer`, `session_id:string`, all in `required`);
   `src/api/endpoints/broadcast.ts: BroadcastPlaybackUrl` (`expires_at: number`);
   `src/pages/broadcast/LivePlayer.tsx` (`setPlaybackUrl(data.playback_url)`,
   `new Date(expiresAt * 1000)` confirms seconds).

4. **Client makes a `POST /broadcast/sessions/{sessionId}/playback/verify` call.**
   VERDICT: Corrected — endpoint does not exist and no client call is made. SOURCE: grep of
   `reference/src/` for `playback/verify|verifyPlayback|cf_token` → no matches;
   `LivePlayer.tsx` performs only `getSession` + `mintPlaybackUrl`. The OpenAPI index has no
   `.../{session_id}/playback/verify` route.

5. **The only verify endpoint = `GET /broadcast/playback/verify` (query `path,cf_token,cf_expires`)
   returning `{ valid: boolean }`; it is an edge CloudFront-token check, not a client call.**
   VERDICT: Verified (server-side helper; Android must not call it). SOURCE: OpenAPI
   `GET /broadcast/playback/verify` (op `verify_playback_token_route_...`, required query
   `path`/`cf_token`/`cf_expires`); `openapi.pretty.json`
   `components.schemas.BroadcastPlaybackTokenVerifyOut = { valid: boolean }` (required).

6. **There is a combined `{ authorized, state, playback:{url} }` response shape to tolerate.**
   VERDICT: Corrected — fabricated; removed. SOURCE: no such schema in `openapi.pretty.json`;
   not present in `src/api/endpoints/broadcast.ts`.

7. **Session status/title comes from `GET /broadcast/sessions/{id}` and is the source of
   live/ended state (`status` enum).**
   VERDICT: Verified. SOURCE: OpenAPI `GET /broadcast/sessions/{session_id}` → `BroadcastSessionOut`;
   `src/api/endpoints/broadcast.ts: BroadcastSessionStatus` (`draft|scheduled|provisioning|ready|
   live|stopping|stopped|cancelled|error`); `LivePlayer.tsx` `isLive = session?.status === "live"`.

8. **CSRF: `ui_csrf` cookie echoed as `X-CSRF-Token` header.**
   VERDICT: Verified. SOURCE: `src/api/client.ts` (`getCookie("ui_csrf")` →
   `headers.set("X-CSRF-Token", csrf)`).

9. **401 triggers a single `POST /ui/session/refresh` then one retry.**
   VERDICT: Verified (with nuance: only when already authenticated; unauthenticated 401
   propagates). SOURCE: `src/api/client.ts` `refreshSession()` posts `/ui/session/refresh`,
   single `refreshPromise`, one retry, logout on retry-401.

10. **FastAPI `detail` mapping handles string | `[{msg}]` | `{code,...}`.**
    VERDICT: Verified. SOURCE: `src/api/client.ts: normalizeErrorDetail` + `mapAuthorizationError`
    (string passthrough, array-of-`{msg}`, object-with-`code`). 403 geo-block surfaces
    `{code:"geo_blocked"}`.

11. **Documented error responses for these routes are `422 HTTPValidationError` (no `409`).**
    VERDICT: Corrected (draft referenced a `409` state mismatch). SOURCE: OpenAPI index — the
    `playback-url` and `sessions/{id}` routes list only `200`/`201`/`202` and
    `422:HTTPValidationError`; 401/403/404 are platform-wide behaviors from `client.ts`, not
    route-specific schemas.

12. **Proactive refresh lead time (~30s before expiry).**
    VERDICT: Corrected to 75%-of-remaining (web behavior). SOURCE: `LivePlayer.tsx`
    (`refreshMs = remainingSec * 750`, skip when `remainingSec <= 10`).

13. **Playback URLs are signed query URLs played directly (no extra auth header on manifest).**
    VERDICT: Verified. SOURCE: `LivePlayer.tsx` passes `playback_url` to `<MediaPlayer src=...>`;
    `MediaPlayer.tsx` loads it via `hls.loadSource(src)` with no auth header injection
    (manifest example carries `?sig=...`).

14. **Web HLS player = `hls.js` with live low-latency config, adaptive (`startLevel:-1`),
    native Safari fallback; AND-167 replaces it with Media3/ExoPlayer.**
    VERDICT: Verified. SOURCE: `src/components/shared/MediaPlayer.tsx` (`import Hls from "hls.js"`,
    `lowLatencyMode: mode==="live"`, `startLevel:-1`, `canPlayType("application/vnd.apple.mpegurl")`).

15. **Cleartext dev host `http://18.222.237.167:8000`.**
    VERDICT: Unverified-assumption (carried from spec/env; not derivable from the reference
    sources, which use a build-time `VITE_API_BASE_URL`). SOURCE: `src/api/client.ts` reads
    `VITE_API_BASE_URL` — the concrete IP is an environment/deployment fact, not in-repo.

16. **Android framework choices (Media3/ExoPlayer for HLS; `PlayerView`/`media3.ui.compose`;
    `collectAsStateWithLifecycle`; `LifecycleEventObserver` for play/pause/release).**
    VERDICT: Unverified-assumption (framework ref — sound Android practice, not checkable
    against backend/web sources). SOURCE (framework ref):
    https://developer.android.com/media/media3/exoplayer/hls and
    https://developer.android.com/develop/ui/compose/lifecycle . Concrete API from AND-167.

### Corrections made

- §1/§2/§5: removed the non-existent client `playback/verify` call; the mint call is the
  entitlement gate. Documented the real `GET /broadcast/playback/verify` as a server/edge
  CloudFront-token helper that the Android client must not call.
- §5: corrected the `BroadcastPlaybackUrlOut` shape — `playback_url` (not `url`),
  `expires_at` integer epoch **seconds** (not ISO string), and removed the fabricated
  `type`, `token`, and combined `{authorized,state,playback}` fields.
- §3 (FR-2/FR-3), §4 (models + `PlaybackRepository`), §11, §14 (AC-2): re-grounded on the
  single-mint flow and on `BroadcastSession.status` as the source of session state.
- §5/§7/§11: corrected the documented error set to `422 HTTPValidationError` (route schema)
  plus the platform 401-refresh / 403 / 404 behaviors; removed the `409` claim.
- §6/§13: corrected the refresh schedule to 75%-of-remaining (matching `LivePlayer.tsx`).
- §13: marked OQ-1..OQ-3 resolved with the verified findings.

### Open assumptions

- **Dev host IP / cleartext exception** (`18.222.237.167:8000`): an environment fact; the
  web reference resolves the base URL from `VITE_API_BASE_URL` at build time, so the literal
  host cannot be confirmed from the repo. Confirm with the backend/ops owner.
- **AND-167 player surface API** (`PlayerFactory` / `HlsMediaSourceFactory` injectable via
  Hilt, OkHttp data-source bridge so cookies ride segment requests): assumed from the
  upstream ticket; not present in these reference sources. Verify against AND-167 on landing.
- **AND-278 DTO/nav surface** (`BroadcastSession`/detail, session-id nav arg): assumed from
  the upstream ticket; the web `BroadcastSession` shape (above) is the closest available
  evidence.
- **Does the signed `playback_url` require the OkHttp cookie jar for segment fetches?** The
  web client relies on the URL signature (`?sig=...`) and `crossOrigin="anonymous"` on the
  `<video>`; whether HLS *segments* additionally need session cookies is not provable from
  the reference. Default assumption: signature alone authorizes segments; cookies still ride
  via the shared client if the data source uses it. Confirm during instrumented playback.

## 17. Test Plan

Test targets: **JVM** = JVM unit/Robolectric (no device); **AVD test35** = headless x86_64
emulator, Android 15 / API 35; **A15** = physical Samsung Galaxy A15 5G (SM-A156U, serial
R5CX821TA9R), Android 14 / API 34, arm64-v8a. Real-network HLS playback and ABI/API-level
differences MUST run on **A15**; deterministic UI/contract suites run on JVM or AVD test35.

- **TC-AND-280-01 — Happy path: mint URL → Ready.**
  Type: unit (ViewModel + repo with fake API). Target: JVM. Preconditions: fake API returns
  `BroadcastSession.status="live"` and `BroadcastPlaybackUrlOut{playback_url, expires_at}`
  (200). Steps: call `start()`; collect `uiState` (Turbine). Expected: `Loading` →
  `Ready(url=playback_url, isLive=true, expiresAtEpochMs=expires_at*1000)`; no
  `playback/verify` request is issued. Traces: AC-1, AC-2.

- **TC-AND-280-02 — Contract: mint request shape + CSRF.**
  Type: contract/MockWebServer. Target: JVM (Robolectric/OkHttp). Preconditions: MockWebServer
  enqueues 200 with `{session_id, playback_url, expires_at}`. Steps: invoke
  `PlaybackApi.playbackUrl(id)`. Expected: recorded request is
  `POST /broadcast/sessions/{id}/playback-url`, header `X-CSRF-Token` present, no body; DTO
  parses `playback_url`→url and `expires_at`(sec)→`expiresAtEpochMs` (×1000). Traces: AC-2.

- **TC-AND-280-03 — Not authorized (403) → Unavailable(NOT_AUTHORIZED).**
  Type: contract/MockWebServer. Target: JVM. Preconditions: MockWebServer returns 403 with
  body `{"detail":"You don't have access to this broadcast"}`. Steps: `start()`. Expected:
  player not started; `Unavailable(NOT_AUTHORIZED)`; `detail` surfaced via the shared mapper.
  Traces: AC-2.

- **TC-AND-280-04 — Session ended / not live → Unavailable(SESSION_ENDED).**
  Type: unit. Target: JVM. Preconditions: session API returns `status="stopped"` (or mint
  returns 404 "Broadcast not found"). Steps: `start()`. Expected: `Unavailable(SESSION_ENDED)`
  (status mapping) or `Error(retryable=false)` for 404; player not started. Traces: AC-2.

- **TC-AND-280-05 — 401 → single refresh → retry succeeds.**
  Type: contract/MockWebServer. Target: JVM. Preconditions: first mint → 401; a
  `POST /ui/session/refresh` → 200; retried mint → 200. Steps: `start()`. Expected: exactly one
  `/ui/session/refresh`, exactly one mint retry, terminal `Ready`; a second consecutive 401
  surfaces auth failure (no infinite loop). Traces: AC-2, AC-5.

- **TC-AND-280-06 — Offline / timeout → Offline or Error(retryable) with working Retry.**
  Type: unit. Target: JVM. Preconditions: API throws connection error (no connectivity) /
  exceeds the ~20s timeout. Steps: `start()`; then `retry()` with API now healthy. Expected:
  `Offline` (no connectivity) or `Error(retryable=true)` (timeout) — never an indefinite
  `Loading`; `retry()` transitions to `Ready`. Traces: AC-5.

- **TC-AND-280-07 — Proactive URL refresh at 75% of remaining; reattach without leaving Ready.**
  Type: unit (virtual clock/`TestScheduler`). Target: JVM. Preconditions: mint returns
  `expires_at = now+120s`; clock injectable. Steps: reach `Ready`; advance virtual time to 75%
  (90s). Expected: `refreshUrl()` fires once at ~90s, re-acquires, stays `Ready` (no
  `Loading` flicker); refresh-storm guard prevents a duplicate in-flight refresh; no schedule
  when remaining ≤ 10s. Traces: AC-3.

- **TC-AND-280-08 — Reactive refresh on manifest auth/source error.**
  Type: unit. Target: JVM. Preconditions: simulate `PlaybackException` with
  `ERROR_CODE_IO_BAD_HTTP_STATUS` (401/403) from the player listener. Steps: deliver the error
  to the ViewModel. Expected: `refreshUrl()` called once and source reattached; if refresh also
  fails → `Error(retryable=true)`; stays in `Ready` on success. Traces: AC-3.

- **TC-AND-280-09 — Compose UI renders all states + Retry/Go-live + a11y semantics.**
  Type: Compose-UI. Target: AVD test35. Preconditions: ViewModel driven through
  Loading/Ready/Unavailable/Offline/Error via a fake. Steps: assert each state's UI; tap
  Retry; toggle behind-live-edge. Expected: Loading spinner, Ready player surface,
  typed Unavailable/Error copy from string resources, Offline+Retry; Retry invokes `retry()`;
  Go-live visible only when behind the live edge; Back/Retry/Go-live/Play-Pause expose
  `contentDescription` and meet 48dp; LIVE/Buffering announced via `liveRegion`. Traces:
  AC-2, AC-5, and §9 accessibility.

- **TC-AND-280-10 — Lifecycle: release on ON_STOP, resume at live edge on ON_START, no leak.**
  Type: instrumented. Target: AVD test35 (LeakCanary/idling assertions). Preconditions:
  player attached on a stub live manifest. Steps: drive `ON_STOP` then `ON_START`, then dispose
  the screen. Expected: decoder/player paused+released on `ON_STOP`, resumes at live edge on
  `ON_START`, fully released on disposal with no retained `ExoPlayer`. Traces: AC-4.

- **TC-AND-280-11 — Player smoke: reaches STATE_READY + isCurrentMediaItemLive (stub manifest).**
  Type: instrumented/e2e. Target: AVD test35 (MockWebServer-served stub HLS). Preconditions:
  a known small live-style `.m3u8` served locally. Steps: build `Ready`, attach source, await
  player state. Expected: player reaches `STATE_READY` and `isCurrentMediaItemLive == true`;
  adaptive track selection enabled. Traces: AC-1, AC-6.

- **TC-AND-280-12 — Real-network live playback against dev host (acceptance E2E).**
  Type: instrumented/e2e + manual. Target: **A15 (physical device REQUIRED)** — real-network
  HLS over cleartext and arm64/API-34 behavior cannot be validated on the x86 emulator.
  Preconditions: authorized viewer signed in; a live session on
  `http://18.222.237.167:8000`. Steps: open the viewer screen for the live session id.
  Expected: mint succeeds, the live HLS stream renders and plays with adaptive bitrate, LIVE
  indicator shown at the live edge. Traces: AC-1, AC-6. (If the dev host is flaky, the buffering/
  refresh paths in TC-06..08 cover degradation; this case asserts the end-to-end bar.)

- **TC-AND-280-13 — Cleartext scoped to dev host; release config clean.**
  Type: instrumented (security). Target: AVD test35 (debug build) + a release-config check.
  Preconditions: debug `network_security_config.xml` permits cleartext for `18.222.237.167`
  only. Steps: attempt a cleartext request to an unlisted host (expect block); inspect the
  release manifest/network config. Expected: cleartext allowed only for the dev host in debug;
  release build has no blanket `cleartextTrafficPermitted`. Traces: AC-7.

- **TC-AND-280-14 — Logging redaction: no tokens / signed-URL params in logs.**
  Type: unit. Target: JVM. Preconditions: log a `PlaybackTicket` URL containing `?sig=...&exp=...`.
  Steps: invoke the logging/redaction path. Expected: logcat shows host+path only; no `sig`,
  `exp`, or `token` query values; error logs include only `errorCode` + HTTP status. Traces: AC-7.

### Coverage matrix

| AC   | Covered by |
|------|------------|
| AC-1 | TC-01, TC-11, TC-12 |
| AC-2 | TC-01, TC-02, TC-03, TC-04, TC-05, TC-09 |
| AC-3 | TC-07, TC-08 |
| AC-4 | TC-10 |
| AC-5 | TC-05, TC-06, TC-09 |
| AC-6 | TC-11, TC-12 |
| AC-7 | TC-13, TC-14 |
