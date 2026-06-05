---
id: AND-194
title: VOD ad-supported
milestone: M4
epic: E26
priority: P2
size: M
status: draft
depends_on: [AND-191, AND-168]
blocks: []
---

# AND-194 — VOD ad-supported

## 1. Overview & Goal

Add ad-supported (AVOD) playback to the TestLogon Android app. When a user opens a
VOD title that is monetized via ads rather than entitlement, the client must open an
**ad-supported playback session** against `POST /ui/vod/ad-supported/{video_id}/session`,
receive a content stream plus an ordered set of **ad breaks** (cue points with their own
ad creative manifests), and play the content with those ad breaks inserted at the correct
positions. The user must not be able to skip a non-skippable ad break by seeking past it,
and resumption/seek behavior must respect already-watched ad breaks.

The goal is a working AVOD flow built on top of the existing reusable player (AND-168) and
VOD catalog/detail surfaces (AND-191): the same ExoPlayer-based `PlayerScreen` is reused,
extended with an ad-break controller that gates the content timeline. This ticket owns the
ad-supported session lifecycle, cue-point scheduling, ad playback state, and the seek/skip
gating policy. It does NOT own the generic player controls (AND-168) or the catalog/detail
list (AND-191); it composes them.

Definition of success: launching an ad-supported title plays the content interleaved with
its ad breaks; pre-roll, mid-roll, and post-roll cue points fire at their scheduled
positions; seeking is constrained per policy; and the session is reported/heartbeated so the
backend can mark ad breaks as watched.

## 2. Context & References

- Source ticket: AND-194 — VOD ad-supported (Type: Feature, Priority: P2, Deps: AND-191, AND-168).
- Reusable player UI (AND-168, P0): provides `PlayerScreen`, controls (play/seek/scrub/
  volume/fullscreen), buffering/error states, and PiP. This ticket extends it with an ad
  overlay and a seek-gating hook.
- VOD catalog/detail (AND-191, P1): provides `vod.ts`-equivalent catalog + detail and the
  navigation entry point. The detail screen routes into the ad-supported player when the
  title's monetization is `ad_supported`.
- Stack: Kotlin 2.0.21, Jetpack Compose + Material 3, single-Activity Navigation-Compose,
  Hilt DI (KSP), Coroutines/Flow, Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15, Room 2.6,
  DataStore, Media3/ExoPlayer 1.4 (HLS), Paging 3. minSdk 24, compileSdk/targetSdk 35.
- Module layering: `app -> feature-vod -> core-*` (`core-network`, `core-model`, `core-ui`,
  `core-data`, `core-testing`). Namespace/applicationId base: `com.testlogon.android`.
- Backend: FastAPI + DynamoDB; dev host `http://18.222.237.167:8000` (plaintext, unreliable).
  OpenAPI at `/openapi.json`. Web reference under `frontend/`; VOD endpoints mirror
  `frontend/src/api/endpoints/vod.ts`; shared types in `frontend/src/api/types.ts`.
- Auth is cookie-based with `ui_csrf` echoed as `X-CSRF-Token`; persistent cookie jar; on
  401 the network layer calls `POST /ui/session/refresh` once then retries. The
  ad-supported session endpoint is an authenticated UI endpoint and rides the same session.

## 3. Functional Requirements

FR-1. From VOD detail (AND-191), when a title's monetization model is `ad_supported`, the
"Play" action navigates to the player route with an `adSupported = true` flag and the
`video_id`.

FR-2. On entering ad-supported playback, the client calls
`POST /ui/vod/ad-supported/{video_id}/session` and receives the content stream URL (HLS),
the DRM/license info (if any), and an ordered list of **ad breaks**, each with: break id,
cue point position (millis offset, or `pre`/`post`), skippable flag + skip-offset, and an
ordered list of ad creatives (each with its own media URL and duration).

FR-3. Playback inserts ad breaks at their cue points:
- Pre-roll break (position `pre` / offset 0) plays before content starts.
- Mid-roll breaks play when content playback position crosses the cue point.
- Post-roll break (position `post`) plays after content reaches end.

FR-4. During an ad break, the content controls (scrub bar, seek, fast-forward) are
disabled. A non-skippable ad cannot be skipped; a skippable ad shows a countdown and a
"Skip Ad" affordance that becomes enabled after `skip_offset_ms`.

FR-5. Seek/skip gating on the content timeline: the user may not seek **forward** past an
unwatched mandatory mid-roll cue point. Seeking to a position beyond an unwatched mandatory
break snaps playback to that break's cue point and plays the break first; after the break
completes, content resumes at the seek target. Backward seeks are unrestricted and do not
replay already-watched breaks.

FR-6. Ad-break completion (or skip, when permitted) is reported via
`POST /ui/vod/ad-supported/{video_id}/session/{session_id}/event` so the backend records
break-watched state. Content-position heartbeats are sent on the same endpoint at a bounded
interval.

FR-7. The player shows clear ad UI affordances: an "Ad" badge, "Ad N of M" within the
current break, and remaining time. Content metadata (title) from AND-191 remains visible.

FR-8. PiP (from AND-168) is allowed during content but the skip control is unavailable in
PiP; on returning to full UI the ad state is preserved.

FR-9. If the session call fails or returns no playable content, an error state is shown with
retry (idempotent retry of the GET-shaped session creation is not safe because it is a POST;
retry re-issues the session create explicitly via user action — see §7).

## 4. Technical Design

New feature code lives in `feature-vod` (module already introduced by AND-191), package
`com.testlogon.android.feature.vod.adsupported`. Models live in `core-model`, the API in
`core-network`, the repository in `core-data`.

### 4.1 Models (`core-model`, Moshi `@JsonClass(generateAdapter = true)`)

```kotlin
package com.testlogon.android.core.model.vod

@JsonClass(generateAdapter = true)
data class AdSupportedSession(
    @Json(name = "session_id") val sessionId: String,
    @Json(name = "video_id") val videoId: String,
    @Json(name = "content_url") val contentUrl: String,        // HLS .m3u8
    @Json(name = "content_duration_ms") val contentDurationMs: Long,
    @Json(name = "ad_breaks") val adBreaks: List<AdBreak>,
    @Json(name = "heartbeat_interval_ms") val heartbeatIntervalMs: Long = 30_000,
)

@JsonClass(generateAdapter = true)
data class AdBreak(
    @Json(name = "break_id") val breakId: String,
    @Json(name = "position") val position: String,             // "pre" | "post" | "mid"
    @Json(name = "cue_point_ms") val cuePointMs: Long,         // 0 for pre, == duration for post
    @Json(name = "skippable") val skippable: Boolean,
    @Json(name = "skip_offset_ms") val skipOffsetMs: Long?,    // null when not skippable
    @Json(name = "ads") val ads: List<AdCreative>,
    @Json(name = "watched") val watched: Boolean = false,
)

@JsonClass(generateAdapter = true)
data class AdCreative(
    @Json(name = "ad_id") val adId: String,
    @Json(name = "media_url") val mediaUrl: String,            // HLS or progressive mp4
    @Json(name = "duration_ms") val durationMs: Long,
    @Json(name = "click_through_url") val clickThroughUrl: String? = null,
)
```

### 4.2 Networking (`core-network`)

```kotlin
interface VodAdSupportedApi {
    @POST("ui/vod/ad-supported/{video_id}/session")
    suspend fun createSession(
        @Path("video_id") videoId: String,
    ): Response<AdSupportedSession>

    @POST("ui/vod/ad-supported/{video_id}/session/{session_id}/event")
    suspend fun reportEvent(
        @Path("video_id") videoId: String,
        @Path("session_id") sessionId: String,
        @Body body: AdSessionEventRequest,
    ): Response<Unit>
}

@JsonClass(generateAdapter = true)
data class AdSessionEventRequest(
    @Json(name = "type") val type: String,          // "heartbeat"|"break_started"|"break_completed"|"break_skipped"|"ad_completed"
    @Json(name = "break_id") val breakId: String? = null,
    @Json(name = "ad_id") val adId: String? = null,
    @Json(name = "position_ms") val positionMs: Long,
)
```

CSRF and cookies are handled by the shared OkHttp interceptors/cookie jar; no per-call auth
work is needed here.

### 4.3 Repository (`core-data`)

```kotlin
interface VodAdSupportedRepository {
    suspend fun startSession(videoId: String): ApiResult<AdSupportedSession>
    suspend fun report(videoId: String, sessionId: String, event: AdSessionEventRequest): ApiResult<Unit>
}
```

`ApiResult<T>` is the project-standard sealed type (`Success`/`Error(detail)`/`Loading`),
with FastAPI `detail` mapping (string | `[{msg}]` | `{code,...}`).

### 4.4 Ad-break scheduling & gating

A pure, unit-testable controller computes which break (if any) must play for a given content
position and seek target. It holds no Android dependencies.

```kotlin
class AdBreakScheduler(initialBreaks: List<AdBreak>) {
    /** Break to play before content reaches/resumes at [targetMs], or null. */
    fun breakDueForSeek(currentMs: Long, targetMs: Long): AdBreak?
    /** Next mid-roll break crossed by linear playback past [positionMs]. */
    fun breakCrossedBy(positionMs: Long): AdBreak?
    fun preRoll(): AdBreak?
    fun postRoll(): AdBreak?
    fun markWatched(breakId: String)
    fun isForwardSeekAllowed(currentMs: Long, targetMs: Long): Boolean
}
```

Gating rule (FR-5): forward seek to `targetMs` is allowed iff there is no unwatched
non-skippable mid-roll break with `cuePointMs in (currentMs, targetMs]`. Otherwise the
earliest such break is returned by `breakDueForSeek`, played, marked watched, and content
then resumes at `targetMs`.

### 4.5 ViewModel & UI

```kotlin
@HiltViewModel
class AdSupportedPlayerViewModel @Inject constructor(
    private val repo: VodAdSupportedRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {
    val uiState: StateFlow<AdSupportedUiState>
    fun onSeekRequested(targetMs: Long)
    fun onSkipAd()
    fun onContentPosition(ms: Long)     // driven by Player.Listener
    fun onAdCompleted()
    fun retry()
}

sealed interface AdSupportedUiState {
    data object Loading : AdSupportedUiState
    data class Error(val message: String) : AdSupportedUiState
    data class Ready(
        val contentUrl: String,
        val phase: PlaybackPhase,                 // Content | Ad
        val currentBreak: AdBreak?,
        val currentAdIndex: Int,                  // 0-based within break
        val adRemainingMs: Long,
        val skipEnabled: Boolean,
        val skipCountdownMs: Long,
        val contentPositionMs: Long,
        val contentDurationMs: Long,
    ) : AdSupportedUiState
}
```

Playback uses one Media3 `ExoPlayer` with two `MediaItem` sources swapped between phases
(content item vs. current ad creative), driving a `Player.Listener`. The Compose layer
reuses AND-168's `PlayerSurface`/controls but binds an `AdOverlay` composable
(`@Composable fun AdOverlay(state: AdSupportedUiState.Ready, onSkip: () -> Unit)`), and
disables the scrub bar / forward-seek controls while `phase == Ad`. Navigation route:
`vod/player/{videoId}?adSupported={bool}`.

## 5. API Contract

Base: `http://18.222.237.167:8000`. All calls carry session cookies + `X-CSRF-Token`.

### 5.1 Create session

`POST /ui/vod/ad-supported/{video_id}/session` — body empty (`{}` acceptable).

200 response:

```json
{
  "session_id": "avod_3f9a",
  "video_id": "vid_1207",
  "content_url": "https://cdn.example/hls/vid_1207/master.m3u8",
  "content_duration_ms": 2640000,
  "heartbeat_interval_ms": 30000,
  "ad_breaks": [
    { "break_id": "br_pre", "position": "pre", "cue_point_ms": 0,
      "skippable": false, "skip_offset_ms": null,
      "ads": [ { "ad_id": "ad_a", "media_url": "https://cdn.example/ads/a.m3u8", "duration_ms": 15000, "click_through_url": "https://advertiser.example" } ] },
    { "break_id": "br_mid1", "position": "mid", "cue_point_ms": 900000,
      "skippable": true, "skip_offset_ms": 5000,
      "ads": [ { "ad_id": "ad_b", "media_url": "https://cdn.example/ads/b.m3u8", "duration_ms": 30000 } ] },
    { "break_id": "br_post", "position": "post", "cue_point_ms": 2640000,
      "skippable": false, "skip_offset_ms": null,
      "ads": [ { "ad_id": "ad_c", "media_url": "https://cdn.example/ads/c.m3u8", "duration_ms": 15000 } ] }
  ]
}
```

Errors: `401` → refresh-and-retry once (handled by interceptor); `403` (no entitlement /
geo) → terminal error; `404` (unknown video) → terminal error; `409` (title not ad
supported) → terminal error with guidance to use the entitled path. Error body follows the
FastAPI `detail` shape.

### 5.2 Report event / heartbeat

`POST /ui/vod/ad-supported/{video_id}/session/{session_id}/event`

```json
{ "type": "break_completed", "break_id": "br_mid1", "ad_id": "ad_b", "position_ms": 900000 }
```

200 → `{}` (ignored). Event reporting is best-effort: failures are logged and retried per
§7 but never block playback. Field `frontend/src/api/types.ts` analogues are
`AdSupportedSession`/`AdBreak`/`AdCreative`; confirm exact field names against
`/openapi.json` during implementation and adjust `@Json` names if the backend differs.

## 6. Data & State Management

- Session state is **in-memory** in the ViewModel for the lifetime of the playback screen; it
  is not persisted to Room (an AVOD session is single-use and server-authoritative). The
  `AdBreakScheduler` holds the mutable watched-set.
- Resume position: last content position is persisted to DataStore keyed by `video_id`
  (`avod_resume_<video_id>` -> Long millis) so re-entry resumes content; on resume, the
  scheduler treats mid-roll breaks at/below the resume position as already-watched only if
  the persisted `watched_breaks` set (also DataStore, a `Set<String>` keyed per video)
  contains them. This prevents replaying ads on backward navigation while honoring FR-5 for
  unwatched forward breaks.
- UI state is exposed as `StateFlow<AdSupportedUiState>` per project convention; the player's
  raw position is collected from a `Player.Listener` and throttled to ~250ms for UI and to
  `heartbeat_interval_ms` for the heartbeat event.
- Configuration changes / process death: `SavedStateHandle` retains `videoId`,
  `adSupported`, and `sessionId`; if `sessionId` is null after restore, the session is
  recreated and the persisted resume position re-applied.
- No Paging is involved here (catalog paging belongs to AND-191).

## 7. Error Handling & Resilience

- The dev backend is plaintext and unreliable: use a ~20s call timeout (shared OkHttp
  config). Session creation is a `POST` and is **not** auto-retried by the idempotent-GET
  backoff policy; on failure the UI shows `AdSupportedUiState.Error` with a "Retry" button
  that re-issues `createSession`.
- 401 handling is delegated to the shared interceptor (single `POST /ui/session/refresh`
  then retry); the ViewModel treats a post-refresh 401 as terminal (re-auth required).
- Ad creative load failure (ExoPlayer `PlaybackException` while `phase == Ad`): skip the
  failed creative, advance to the next ad in the break; if the whole break fails, log,
  report `break_completed` with a degraded flag, and resume content rather than blocking the
  user.
- Content load failure: surface AND-168's player error state with retry.
- Event/heartbeat POSTs are best-effort with a small bounded retry (max 2, exponential, jitter)
  and never block or fail playback.
- Offline/stale: if `createSession` fails with no connectivity, show an explicit offline
  error; do not attempt to fabricate ad breaks.

## 8. Security & Privacy

- All calls use the existing cookie session + `X-CSRF-Token`; no credentials or tokens are
  stored by this feature. The persistent cookie jar is reused; no new auth surface.
- Ad media and `click_through_url` are loaded over their own (HTTPS) URLs; click-through
  opens an external browser via `Intent.ACTION_VIEW` only on explicit user tap.
- No PII is added to event payloads beyond server-issued `session_id`/`video_id`/`ad_id`.
- The plaintext dev host requires `usesCleartextTraffic`/network-security-config already
  established for dev builds (owned by the networking baseline); production must be HTTPS.
- Do not log full media URLs at info level (may contain signed query params); redact in logs.

## 9. Accessibility & i18n

- All ad UI strings are externalized to `strings.xml` (`avod_ad_badge`, `avod_ad_n_of_m`,
  `avod_skip_in`, `avod_skip_ad`, `avod_ad_remaining`, error strings). `avod_ad_n_of_m` uses
  positional args; countdowns use a plurals/duration formatter.
- The "Skip Ad" button has a `contentDescription` and a minimum 48dp touch target; when
  disabled during countdown it is announced as "Skip available in N seconds".
- The "Ad" badge and "Ad N of M" are exposed to TalkBack; ad progress is announced as a live
  region update at break start and on skip-enable.
- Disabled scrub/seek controls during ads are marked non-focusable and announced as
  unavailable during ad playback so screen-reader users understand the gating.
- Layout respects RTL and dynamic font scaling.

## 10. Telemetry & Logging

- Emit analytics events (project analytics facade, no new vendor): `avod_session_start`
  (video_id), `avod_break_start` (break_id, position, skippable), `avod_break_complete`
  (break_id, skipped: bool), `avod_session_error` (code), `avod_skip_used` (break_id).
- These analytics events are distinct from the backend `reportEvent` calls; backend events
  drive server watched-state, analytics drive product metrics.
- Logging via the shared logger at: `debug` for phase transitions and scheduler decisions,
  `warn` for event-report retries, `error` for terminal session/content failures. Media URLs
  redacted (§8). No verbose logging in release builds.

## 11. Testing Strategy

Unit (`core-testing`, JUnit + Turbine + MockWebServer):
- `AdBreakSchedulerTest`: pre/mid/post selection; `breakCrossedBy` linear crossing;
  `isForwardSeekAllowed` true/false; `breakDueForSeek` returns earliest unwatched mandatory
  mid-roll between current and target; skippable breaks do not block forward seek; watched
  breaks do not replay; backward seek never returns a break.
- `AdSupportedPlayerViewModelTest`: Loading→Ready happy path; Loading→Error on session
  failure and successful `retry()`; phase transitions Content↔Ad; skip enabled only after
  `skip_offset_ms`; `onSeekRequested` snaps to break then resumes at target; heartbeat/event
  emission cadence (virtual time).
- Network: `VodAdSupportedApi` parses the §5.1 sample; FastAPI `detail` error mapping for
  string/list/object shapes; 401→refresh→retry path.

Instrumented / Compose:
- `AdOverlay` shows badge, "Ad N of M", countdown→"Skip Ad"; tapping skip calls callback;
  scrub bar disabled while `phase == Ad`.
- Espresso/Compose UI test through VOD detail (AND-191) → ad-supported player launch.

Manual/dev-host: run against `http://18.222.237.167:8000` to validate real cue-point timing
and watched-state persistence across re-entry.

## 12. Dependencies & Sequencing

- **AND-168 (Reusable player UI, P0)** — required: provides `PlayerScreen`, controls,
  buffering/error states, PiP. This ticket cannot ship until the player surface and the
  seek-control hook exist.
- **AND-191 (VOD catalog, P1)** — required: provides VOD detail and the navigation entry
  point that branches into ad-supported playback based on monetization model.
- Transitively depends on the networking/auth baseline (cookie jar, CSRF interceptor,
  401-refresh) and `core-model`/`core-data` plumbing.
- Sequencing: implement models + API + repository → `AdBreakScheduler` (pure, test-first) →
  ViewModel → `AdOverlay` + player integration → analytics/telemetry → wire detail entry.
- Blocks: none recorded in backlog.

## 13. Risks & Open Questions

- Q1: Does the backend expose ad breaks via this dedicated `session` endpoint as modeled, or
  via a standard VAST/VMAP document? The spec assumes a JSON cue-point model; confirm against
  `/openapi.json`. If VAST/VMAP, an IMA-style parser (or Media3 ad-insertion APIs) is needed
  instead — material rework.
- Q2: Server vs. client ad stitching. This spec assumes **client-side** insertion (separate
  content and ad `MediaItem`s). If the backend does server-side ad insertion (SSAI, single
  manifest with markers), gating/skip semantics change and §4.4 must use Media3
  `AdPlaybackState` from manifest interstitials.
- Q3: Exact watched-state semantics on resume — does the server treat re-created sessions as
  fresh (re-serving all breaks) or honor prior watched state? Affects §6 persistence; verify.
- Q4: Skip policy details (does the backend dictate skippability and offset, or is it a fixed
  client policy?) — modeled as server-provided per break; confirm.
- Q5: PiP + ad interaction on minSdk 24 (PiP is 26+) — below 26, PiP is unavailable; ad
  gating must still hold in the normal full-screen path.

## 14. Acceptance Criteria

AC-1. Opening an ad-supported title issues `POST /ui/vod/ad-supported/{video_id}/session`
and enters playback using the returned `content_url` and `ad_breaks` (FR-1, FR-2).

AC-2. A pre-roll break plays before content; mid-roll breaks play when their cue point is
crossed; the post-roll break plays after content end (FR-3) — verified by
`AdBreakSchedulerTest` and an instrumented run.

AC-3. During an ad break, content scrub/forward-seek controls are disabled; a non-skippable
ad cannot be skipped; a skippable ad enables "Skip Ad" exactly after `skip_offset_ms`
(FR-4).

AC-4. Forward-seeking past an unwatched non-skippable mid-roll snaps to the break, plays it,
then resumes at the seek target; backward seeks do not replay watched breaks (FR-5).

AC-5. Break completion/skip and content heartbeats are POSTed to the session `event`
endpoint at the server-provided interval (FR-6); event failures do not interrupt playback
(§7).

AC-6. Session-create failure shows an error state with a working Retry; 401 triggers a single
refresh-retry via the interceptor (§7).

AC-7. Ad UI shows "Ad" badge, "Ad N of M", and remaining/skip countdown, all TalkBack-
accessible and localized (FR-7, §9).

AC-8. The acceptance statement from the backlog holds: an ad-supported session plays with ad
breaks.

## 15. Definition of Done

- Code merged to `android-port` under `feature-vod` (package
  `com.testlogon.android.feature.vod.adsupported`) with models in `core-model`, API in
  `core-network`, repository in `core-data`.
- All unit and Compose/instrumented tests in §11 implemented and passing in CI; no decrease
  in module coverage gate.
- `ktlint`/`detekt` clean; no new lint baseline suppressions for this feature.
- Strings externalized; basic locale + RTL pass; TalkBack pass on the ad overlay.
- Verified against the dev backend `http://18.222.237.167:8000`: pre/mid/post breaks play,
  gating holds, watched-state persists across re-entry.
- `@Json` field names reconciled with `/openapi.json`; any deviations documented in the PR.
- Open questions Q1–Q4 resolved or explicitly deferred with backlog follow-ups before
  release; PR description links AND-168 and AND-191.
- No plaintext media URLs logged at info level in release builds.
