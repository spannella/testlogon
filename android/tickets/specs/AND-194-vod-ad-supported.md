---
id: AND-194
title: VOD ad-supported
milestone: M4
epic: E26
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-191, AND-168]
blocks: []
---

# AND-194 — VOD ad-supported

## 1. Overview & Goal

Add ad-supported (AVOD) playback to the TestLogon Android app. When a user opens a
VOD title that is monetized via ads rather than entitlement, the client must open an
**ad-supported playback session** by calling `POST /ui/vod/ad-supported/{video_id}/start`
(after optionally reading existing session state via
`GET /ui/vod/ad-supported/{video_id}/session`), receive a content stream
(`playback_url`) plus an ordered **ad schedule** (`ad_schedule`, a list of `VodAdBreak`,
each with a single creative), and play the content with those ad breaks inserted at the
correct positions. Crucially, the backend gates continued playback **server-side**: each
required mid-roll break must be reported complete via
`POST /ui/vod/ad-supported/{video_id}/break` before `playback_unlocked` flips true past that
cue point. The user must not be able to skip a mandatory ad break by seeking past it, and
resumption/seek behavior must respect already-completed ad breaks.

> CORRECTED (review 2026-06-06): The original draft modeled a single
> `POST .../session` returning content + breaks. The real backend uses THREE endpoints:
> `GET .../session` (read state), `POST .../start` (begin; returns `playback_url`), and
> `POST .../break` (report break). See §5 and §16.

The goal is a working AVOD flow built on top of the existing reusable player (AND-168) and
VOD catalog/detail surfaces (AND-191): the same ExoPlayer-based `PlayerScreen` is reused,
extended with an ad-break controller that gates the content timeline. This ticket owns the
ad-supported session lifecycle, cue-point scheduling, ad playback state, and the seek/skip
gating policy. It does NOT own the generic player controls (AND-168) or the catalog/detail
list (AND-191); it composes them.

Definition of success: launching an ad-supported title plays the content interleaved with
its ad breaks; pre-roll and mid-roll cue points fire at their scheduled positions (the
backend contract exposes `slot_type` of `pre_roll | mid_roll | overlay` only — there is no
`post_roll`); seeking is constrained per the server gating policy; and each break is reported
complete so the backend marks it watched and unlocks continued playback.

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
  OpenAPI at `/openapi.json`. Web reference under `frontend/`; the ad-supported endpoints
  mirror `src/api/endpoints/vodAdSupported.ts` (VOD-018), shared DTOs in
  `src/api/types.ts` (`VodAdBreak`, `VodAdSupportedSession`, `VodAdSupportedStartResponse`,
  `VodAdBreakReportRequest/Response`), screen behavior in
  `src/pages/vod/VodAdSupportedPage.tsx`.
- Auth is cookie-based with `ui_csrf` echoed as `X-CSRF-Token` (VERIFIED against
  `src/api/client.ts`: reads `ui_csrf` cookie → `X-CSRF-Token` header, sends
  `credentials: "include"`); persistent cookie jar; on 401 the network layer calls
  `POST /ui/session/refresh` once then retries exactly once (VERIFIED, client.ts lines
  ~204-237). If active, an `X-IMPERSONATION-TOKEN` header is also sent. These ad-supported
  endpoints are authenticated UI endpoints and ride the same session. NOTE: the OpenAPI
  index lists `params=video_id,user_sub,X-SESSION-ID,X-IMPERSONATION-TOKEN` for these ops;
  `user_sub`/`X-SESSION-ID` are server-side/session-derived and the web client does not set
  them explicitly — the Android client mirrors the web cookie+CSRF transport.

## 3. Functional Requirements

FR-1. From VOD detail (AND-191), when a title's monetization model is `ad_supported`, the
"Play" action navigates to the player route with an `adSupported = true` flag and the
`video_id`.

FR-2. On entering ad-supported playback, the client calls
`POST /ui/vod/ad-supported/{video_id}/start` (optional body `{resume_position_seconds}`) and
receives `VodAdSupportedStartOut`: `playback_url` (HLS content stream), `manifest_key`,
`mode`, `token_expires_at`, optional `thumbnail_url`, and an ordered `ad_schedule` (list of
`VodAdBreak`). Each `VodAdBreak` carries: `break_id`, `slot_type`
(`pre_roll | mid_roll | overlay`), `position_seconds`, `duration_seconds`, **a single**
creative (`creative_id`, `creative_url`, `creative_type` = `video | image`),
`skip_after_seconds`, `slot_index`, and `completed`. Note: the contract provides ONE creative
per break (not a list), uses **seconds** (not millis), and exposes **no** DRM/license field
and **no** `click_through_url`. `GET /ui/vod/ad-supported/{video_id}/session`
(`VodAdSupportedSessionOut`) may be called first to read existing session state
(`status`, `playback_unlocked`, `next_required_break_id`, `breaks_completed/total`,
`ads_free`); note the GET response does NOT include `playback_url`/`manifest_key` — only
`POST .../start` returns the playback grant.

FR-3. Playback inserts ad breaks at their cue points (by `slot_type`):
- `pre_roll` break (`position_seconds == 0`) plays before content starts.
- `mid_roll` breaks play when content playback position crosses `position_seconds`.
- `overlay` breaks are non-blocking creatives (often `creative_type == image`) shown over
  content; they do not necessarily halt the content timeline.
- There is **no** `post_roll` slot_type in the contract; do not assume an end-of-content
  break (CORRECTED — original draft assumed pre/mid/post). If post-roll is later required it
  is a backend change (Open Question Q1).

FR-4. During an ad break, the content controls (scrub bar, seek, fast-forward) are
disabled. Skippability is derived from `skip_after_seconds` (there is no separate boolean
in the contract): a "Skip Ad" countdown/affordance becomes enabled after
`skip_after_seconds` elapses. Treat `skip_after_seconds >= duration_seconds` (or a sentinel
the backend uses for non-skippable, e.g. very large / equal to duration) as effectively
non-skippable — confirm the backend's non-skippable encoding during integration (Open
Question Q4). (CORRECTED — original draft assumed a `skippable` boolean + `skip_offset_ms`;
neither exists.)

FR-5. Seek/skip gating on the content timeline is **server-authoritative**: the backend
returns `playback_unlocked` and `next_required_break_id`; the client may not seek **forward**
past the cue point of `next_required_break_id` while `playback_unlocked == false`. Seeking to
a position beyond an unwatched mandatory break snaps playback to that break's
`position_seconds` and plays the break first; after the break is reported complete (via
`POST .../break`, which returns the updated `playback_unlocked`/`next_required_break_id`),
content resumes at the seek target. Backward seeks are unrestricted and do not replay breaks
already marked `completed`. The client-side `AdBreakScheduler` (§4.4) mirrors this gating for
responsive UI but the authoritative unlock comes from the `POST .../break` response.

FR-6. Ad-break impression/completion/skip is reported via
`POST /ui/vod/ad-supported/{video_id}/break` with body
`{break_id, event_type}` where `event_type` is `impression | complete | skip` (default
`complete`) — so the backend records break-watched state and recomputes
`playback_unlocked`. (CORRECTED — there is no `/session/{session_id}/event` endpoint and no
`session_id` path param; `session_id` is server-tracked and returned in responses.) NOTE:
the contract exposes **no content-position heartbeat endpoint** for AVOD; the
draft's heartbeat assumption is unverified. If periodic state sync is desired, re-poll
`GET .../session`; do not invent a heartbeat event type (see §16 Open assumptions).

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

Field names below are reconciled with `components.schemas.VodAdBreak` /
`VodAdSupportedSessionOut` / `VodAdSupportedStartOut` in `/openapi.json` (VERIFIED 2026-06-06)
and `src/api/types.ts`. The backend uses **seconds** (Int) and **one creative per break**.

```kotlin
package com.testlogon.android.core.model.vod

// GET /ui/vod/ad-supported/{video_id}/session  -> VodAdSupportedSessionOut
@JsonClass(generateAdapter = true)
data class AdSupportedSession(
    @Json(name = "session_id") val sessionId: String,
    @Json(name = "video_id") val videoId: String,
    @Json(name = "status") val status: String,                 // "active"|"completed"|"abandoned"
    @Json(name = "ad_schedule") val adSchedule: List<AdBreak>,
    @Json(name = "breaks_total") val breaksTotal: Int,
    @Json(name = "breaks_completed") val breaksCompleted: Int,
    @Json(name = "next_required_break_id") val nextRequiredBreakId: String? = null,
    @Json(name = "playback_unlocked") val playbackUnlocked: Boolean,
    @Json(name = "ads_free") val adsFree: Boolean = false,
    @Json(name = "created_at") val createdAt: Long,
    @Json(name = "updated_at") val updatedAt: Long,
)

// POST /ui/vod/ad-supported/{video_id}/start -> VodAdSupportedStartOut
// (superset of the session fields above + the playback grant)
@JsonClass(generateAdapter = true)
data class AdSupportedStartResponse(
    @Json(name = "session_id") val sessionId: String,
    @Json(name = "video_id") val videoId: String,
    @Json(name = "status") val status: String,
    @Json(name = "ad_schedule") val adSchedule: List<AdBreak>,
    @Json(name = "breaks_total") val breaksTotal: Int,
    @Json(name = "breaks_completed") val breaksCompleted: Int,
    @Json(name = "next_required_break_id") val nextRequiredBreakId: String? = null,
    @Json(name = "playback_unlocked") val playbackUnlocked: Boolean,
    @Json(name = "ads_free") val adsFree: Boolean = false,
    @Json(name = "playback_url") val playbackUrl: String,      // HLS .m3u8 (content)
    @Json(name = "manifest_key") val manifestKey: String,
    @Json(name = "mode") val mode: String,
    @Json(name = "thumbnail_url") val thumbnailUrl: String? = null,
    @Json(name = "token_expires_at") val tokenExpiresAt: Long,
    @Json(name = "created_at") val createdAt: Long,
    @Json(name = "updated_at") val updatedAt: Long,
)

@JsonClass(generateAdapter = true)
data class AdBreak(
    @Json(name = "break_id") val breakId: String,
    @Json(name = "slot_type") val slotType: String,           // "pre_roll"|"mid_roll"|"overlay"
    @Json(name = "position_seconds") val positionSeconds: Int, // 0 for pre_roll
    @Json(name = "duration_seconds") val durationSeconds: Int,
    @Json(name = "creative_id") val creativeId: String,
    @Json(name = "creative_url") val creativeUrl: String,      // HLS or image, per creative_type
    @Json(name = "creative_type") val creativeType: String,    // "video"|"image"
    @Json(name = "skip_after_seconds") val skipAfterSeconds: Int,
    @Json(name = "slot_index") val slotIndex: Int,
    @Json(name = "completed") val completed: Boolean = false,
)
```

> CORRECTED: removed `content_url`/`content_duration_ms`/`heartbeat_interval_ms`/`AdCreative`
> list/`cue_point_ms`/`skippable`/`skip_offset_ms`/`ad_id`/`media_url`/`click_through_url`/
> `watched` — none exist in the backend schema. Use seconds and the single-creative shape
> above. Convert to millis only internally for ExoPlayer (`* 1000L`).

### 4.2 Networking (`core-network`)

```kotlin
interface VodAdSupportedApi {
    // Read current session state (no playback grant in this response).
    @GET("ui/vod/ad-supported/{video_id}/session")
    suspend fun getSession(
        @Path("video_id") videoId: String,
    ): Response<AdSupportedSession>

    // Start (or resume) the ad-supported session; returns playback_url + ad_schedule.
    @POST("ui/vod/ad-supported/{video_id}/start")
    suspend fun start(
        @Path("video_id") videoId: String,
        @Body body: AdSupportedStartRequest = AdSupportedStartRequest(),
    ): Response<AdSupportedStartResponse>

    // Report a break impression/complete/skip; returns updated unlock state.
    @POST("ui/vod/ad-supported/{video_id}/break")
    suspend fun reportBreak(
        @Path("video_id") videoId: String,
        @Body body: AdBreakReportRequest,
    ): Response<AdBreakReportResponse>
}

// VodAdSupportedStartIn
@JsonClass(generateAdapter = true)
data class AdSupportedStartRequest(
    @Json(name = "resume_position_seconds") val resumePositionSeconds: Int = 0,
)

// VodAdBreakReportIn  (event_type pattern ^(impression|complete|skip)$, default "complete")
@JsonClass(generateAdapter = true)
data class AdBreakReportRequest(
    @Json(name = "break_id") val breakId: String,
    @Json(name = "event_type") val eventType: String = "complete",
)

// VodAdBreakReportOut
@JsonClass(generateAdapter = true)
data class AdBreakReportResponse(
    @Json(name = "ok") val ok: Boolean,
    @Json(name = "session_id") val sessionId: String,
    @Json(name = "video_id") val videoId: String,
    @Json(name = "break_id") val breakId: String,
    @Json(name = "event_type") val eventType: String,
    @Json(name = "completed") val completed: Boolean,
    @Json(name = "breaks_completed") val breaksCompleted: Int,
    @Json(name = "breaks_total") val breaksTotal: Int,
    @Json(name = "next_required_break_id") val nextRequiredBreakId: String? = null,
    @Json(name = "playback_unlocked") val playbackUnlocked: Boolean,
    @Json(name = "status") val status: String,
)
```

CSRF and cookies are handled by the shared OkHttp interceptors/cookie jar; no per-call auth
work is needed here.

### 4.3 Repository (`core-data`)

```kotlin
interface VodAdSupportedRepository {
    suspend fun getSession(videoId: String): ApiResult<AdSupportedSession>
    suspend fun start(videoId: String, resumePositionSeconds: Int = 0): ApiResult<AdSupportedStartResponse>
    suspend fun reportBreak(
        videoId: String,
        breakId: String,
        eventType: String = "complete",   // "impression" | "complete" | "skip"
    ): ApiResult<AdBreakReportResponse>
}
```

(CORRECTED — there is no `session_id` argument; the server tracks the session per
user+video and returns `session_id` in responses.)

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
mandatory mid-roll break with cue point in `(currentMs, targetMs]`. Otherwise the
earliest such break is returned by `breakDueForSeek`, played, reported `complete`, and
content then resumes at `targetMs`. NOTE on cue units: the controller works in millis for
ExoPlayer convenience, but break cue points arrive from the backend as
`position_seconds` (Int seconds) and skip as `skip_after_seconds` — convert at the
repository/mapper boundary (`* 1000L`). The controller is an optimistic mirror; the
authoritative unlock signal is the `playback_unlocked`/`next_required_break_id` returned by
`POST .../break` (and present on `GET .../session` / `POST .../start`). `markWatched` should
be driven by the `completed` breaks reported by the server, not purely client-side, to stay
consistent across re-entry.

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
Three endpoints (VERIFIED against `openapi.index.txt` lines 2044-2046 and
`src/api/endpoints/vodAdSupported.ts`). All three declare only `200` and
`422:HTTPValidationError` in OpenAPI.

### 5.1 Read session state

`GET /ui/vod/ad-supported/{video_id}/session` → `200: VodAdSupportedSessionOut`. No request
body. Returns current state WITHOUT a playback grant:

```json
{
  "session_id": "avod_3f9a",
  "video_id": "vid_1207",
  "status": "active",
  "ad_schedule": [ /* VodAdBreak[] — same shape as §5.2 */ ],
  "breaks_total": 2,
  "breaks_completed": 0,
  "next_required_break_id": "br_pre",
  "playback_unlocked": false,
  "ads_free": false,
  "created_at": 1733443200,
  "updated_at": 1733443200
}
```

### 5.2 Start session

`POST /ui/vod/ad-supported/{video_id}/start` — body `VodAdSupportedStartIn`
(`{ "resume_position_seconds": 0 }`; all fields optional, `{}` acceptable).

`200: VodAdSupportedStartOut` (superset of the session state plus the playback grant):

```json
{
  "session_id": "avod_3f9a",
  "video_id": "vid_1207",
  "status": "active",
  "playback_url": "https://cdn.example/hls/vid_1207/master.m3u8",
  "manifest_key": "vod/vid_1207/master.m3u8",
  "mode": "ad_supported",
  "thumbnail_url": "https://cdn.example/thumbs/vid_1207.jpg",
  "token_expires_at": 1733446800,
  "breaks_total": 2,
  "breaks_completed": 0,
  "next_required_break_id": "br_pre",
  "playback_unlocked": false,
  "ads_free": false,
  "created_at": 1733443200,
  "updated_at": 1733443200,
  "ad_schedule": [
    { "break_id": "br_pre", "slot_type": "pre_roll", "position_seconds": 0,
      "duration_seconds": 15, "creative_id": "cr_a",
      "creative_url": "https://cdn.example/ads/a.m3u8", "creative_type": "video",
      "skip_after_seconds": 5, "slot_index": 0, "completed": false },
    { "break_id": "br_mid1", "slot_type": "mid_roll", "position_seconds": 900,
      "duration_seconds": 30, "creative_id": "cr_b",
      "creative_url": "https://cdn.example/ads/b.m3u8", "creative_type": "video",
      "skip_after_seconds": 5, "slot_index": 1, "completed": false }
  ]
}
```

Note: `position_seconds`/`duration_seconds`/`skip_after_seconds` are integer **seconds**;
each break has exactly **one** creative; `slot_type` is `pre_roll | mid_roll | overlay`
(no post-roll); `ads_free == true` means an empty/skipped ad schedule ("enjoy ad-free
playback" in the web UI).

Errors: only `422` (validation) is declared in OpenAPI for these endpoints. `401` →
refresh-and-retry once (handled by the shared interceptor, VERIFIED in client.ts). A generic
`403` with `detail.code == "geo_blocked"` is handled app-wide (client.ts) and should surface
as a terminal geo error. `403`/`404`/`409` as AVOD-specific terminal codes are an
UNVERIFIED assumption (not in OpenAPI) — handle defensively but do not rely on them. Error
bodies follow the FastAPI `detail` shape (string | `[{msg,...}]` | `{code,...}`).

### 5.3 Report break (impression / complete / skip)

`POST /ui/vod/ad-supported/{video_id}/break` — body `VodAdBreakReportIn`:

```json
{ "break_id": "br_mid1", "event_type": "complete" }
```

`event_type` ∈ `impression | complete | skip` (regex `^(impression|complete|skip)$`,
default `complete`). `200: VodAdBreakReportOut`:

```json
{
  "ok": true,
  "session_id": "avod_3f9a",
  "video_id": "vid_1207",
  "break_id": "br_mid1",
  "event_type": "complete",
  "completed": true,
  "breaks_completed": 2,
  "breaks_total": 2,
  "next_required_break_id": null,
  "playback_unlocked": true,
  "status": "active"
}
```

The client MUST apply `playback_unlocked` / `next_required_break_id` from this response to
its gating state (server-authoritative). Reporting `complete` (and `impression`/`skip`)
is required to progress; it is not purely best-effort for mandatory breaks because the
backend gates continued playback on it. (CORRECTED — original draft used a non-existent
`/session/{session_id}/event` endpoint with a `type`/`ad_id`/`position_ms` body and a
`heartbeat` event; none exist. There is no heartbeat endpoint.)

## 6. Data & State Management

- Session state is **in-memory** in the ViewModel for the lifetime of the playback screen; it
  is not persisted to Room (an AVOD session is single-use and server-authoritative). The
  `AdBreakScheduler` holds the mutable watched-set.
- Resume position: last content position is persisted to DataStore keyed by `video_id`
  (`avod_resume_<video_id>` -> Long millis) so re-entry resumes content; the saved position
  (converted to seconds) is passed as `resume_position_seconds` to `POST .../start`. The
  authoritative watched-state on resume is the `completed` flag on each `VodAdBreak` returned
  by `GET .../session` / `POST .../start` (and `breaks_completed`/`next_required_break_id`);
  prefer that over a locally-persisted set. A local `Set<String>` of reported breaks may be
  kept only as an optimistic UI cache and reconciled against the server response.
- UI state is exposed as `StateFlow<AdSupportedUiState>` per project convention; the player's
  raw position is collected from a `Player.Listener` and throttled to ~250ms for UI. NOTE:
  there is no AVOD heartbeat endpoint (CORRECTED — `heartbeat_interval_ms` does not exist in
  the contract); if periodic server reconciliation is wanted, re-poll `GET .../session` on a
  client-chosen interval rather than emitting heartbeat events.
- Configuration changes / process death: `SavedStateHandle` retains `videoId`,
  `adSupported`, and `sessionId`; if `sessionId` is null after restore, the session is
  recreated and the persisted resume position re-applied.
- No Paging is involved here (catalog paging belongs to AND-191).

## 7. Error Handling & Resilience

- The dev backend is plaintext and unreliable: use a ~20s call timeout (shared OkHttp
  config). `POST .../start` is a `POST` and is **not** auto-retried by the idempotent-GET
  backoff policy; on failure the UI shows `AdSupportedUiState.Error` with a "Retry" button
  that re-issues `start`. `GET .../session` (read-only) is safe to auto-retry.
- 401 handling is delegated to the shared interceptor (single `POST /ui/session/refresh`
  then retry); the ViewModel treats a post-refresh 401 as terminal (re-auth required).
- Ad creative load failure (ExoPlayer `PlaybackException` while `phase == Ad`): since each
  break has exactly ONE creative, a failed creative fails the whole break. Log it, still
  attempt to report the break (`event_type = complete`) so the server can unlock playback,
  and resume content rather than hard-blocking the user. (CORRECTED — there is no list of
  ads to advance through, and no "degraded flag" in the report payload; only
  `break_id`/`event_type` are accepted.)
- Content load failure: surface AND-168's player error state with retry (the player uses
  `playback_url` from `POST .../start`; note `token_expires_at` — if expired, re-`start`).
- Break-report POSTs for non-mandatory/overlay breaks may be best-effort with a small
  bounded retry (max 2, exponential, jitter); for MANDATORY mid-roll breaks the report
  gates the unlock, so on failure keep the gate closed and retry/surface an error rather
  than silently continuing.
- Offline/stale: if `POST .../start` fails with no connectivity, show an explicit offline
  error; do not attempt to fabricate an ad schedule.

## 8. Security & Privacy

- All calls use the existing cookie session + `X-CSRF-Token`; no credentials or tokens are
  stored by this feature. The persistent cookie jar is reused; no new auth surface.
- Ad creative media (`creative_url`) is loaded over its own (HTTPS) URL. NOTE: the contract
  has **no** `click_through_url` field (CORRECTED), so no advertiser click-through/browser
  intent is in scope for this ticket; if added later it is a backend change.
- No PII is added to report payloads beyond `break_id`/`event_type`; `session_id`/`video_id`
  are server-issued and echoed back.
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
- `AdSupportedPlayerViewModelTest`: Loading→Ready happy path; Loading→Error on `start`
  failure and successful `retry()`; phase transitions Content↔Ad; skip enabled only after
  `skip_after_seconds`; `onSeekRequested` snaps to break then resumes at target; applying
  `playback_unlocked`/`next_required_break_id` from the `POST .../break` response.
- Network: `VodAdSupportedApi` parses the §5.2 `start` and §5.3 `break` samples (seconds,
  single creative, `slot_type`); `event_type` defaults to `complete`; FastAPI `detail` error
  mapping for string/list/object shapes; 401→refresh→retry path.

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

- Q1: RESOLVED by review — the backend exposes a JSON ad schedule (`ad_schedule` of
  `VodAdBreak`), NOT VAST/VMAP, via `GET .../session` + `POST .../start`. No IMA parser is
  needed. Remaining sub-question: whether a true post-roll will ever be served (current
  `slot_type` set is `pre_roll | mid_roll | overlay` only).
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

AC-1. Opening an ad-supported title issues `POST /ui/vod/ad-supported/{video_id}/start`
(optionally preceded by `GET .../session`) and enters playback using the returned
`playback_url` and `ad_schedule` (FR-1, FR-2).

AC-2. A `pre_roll` break plays before content and `mid_roll` breaks play when their
`position_seconds` cue point is crossed (FR-3) — verified by `AdBreakSchedulerTest` and an
instrumented run. (No post-roll exists in the contract.)

AC-3. During an ad break, content scrub/forward-seek controls are disabled; a skippable ad
enables "Skip Ad" exactly after `skip_after_seconds`; a break encoded as non-skippable
cannot be skipped (FR-4).

AC-4. Forward-seeking past an unwatched mandatory mid-roll (the `next_required_break_id`
while `playback_unlocked == false`) snaps to the break, plays it, then resumes at the seek
target; backward seeks do not replay `completed` breaks (FR-5).

AC-5. Break impression/complete/skip is POSTed to
`POST /ui/vod/ad-supported/{video_id}/break` and the response's `playback_unlocked` /
`next_required_break_id` is applied to gating (FR-6). For non-mandatory breaks a report
failure does not hard-block playback (§7). (No heartbeat endpoint exists.)

AC-6. `POST .../start` failure shows an error state with a working Retry; 401 triggers a
single refresh-retry via the interceptor (§7).

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
- Verified against the dev backend `http://18.222.237.167:8000`: pre_roll/mid_roll breaks
  play, server gating (`playback_unlocked`/`next_required_break_id`) holds, and `completed`
  break state persists across re-entry (via `GET .../session`).
- `@Json` field names reconciled with `/openapi.json`; any deviations documented in the PR.
- Open questions Q1–Q4 resolved or explicitly deferred with backlog follow-ups before
  release; PR description links AND-168 and AND-191.
- No plaintext media URLs logged at info level in release builds.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer. Sources:
OpenAPI index = `reference/openapi.index.txt`; OpenAPI spec =
`reference/openapi.pretty.json` (`components.schemas.*`); frontend =
`reference/src/...`.

1. Three AVOD endpoints exist: `GET .../session`, `POST .../start`, `POST .../break`.
   VERIFIED. Source: OpenAPI index lines 2044-2046 (`GET /ui/vod/ad-supported/{video_id}/session`,
   `POST /ui/vod/ad-supported/{video_id}/start`, `POST /ui/vod/ad-supported/{video_id}/break`)
   and `src/api/endpoints/vodAdSupported.ts` (`getSession`/`start`/`reportBreak`).
2. (Original draft) session is created via a single `POST .../session`. CORRECTED — that
   path is `GET` (read state), and there is no combined create-and-play endpoint; starting
   uses `POST .../start`. Source: OpenAPI index line 2045 method=GET; `vodAdSupported.ts`.
3. (Original draft) events go to `POST .../session/{session_id}/event`. CORRECTED — that
   endpoint does not exist; reporting uses `POST .../break` with no `session_id` path param.
   Source: OpenAPI index line 2044 (`.../break`, req=`VodAdBreakReportIn`); `vodAdSupported.ts: reportBreak`.
4. `POST .../start` request schema is `VodAdSupportedStartIn` with optional
   `resume_position_seconds` (Int, default 0). VERIFIED. Source: `VodAdSupportedStartIn`
   (openapi.pretty.json ~82435); `src/api/types.ts: VodAdSupportedStartRequest`.
5. `POST .../start` response `VodAdSupportedStartOut` includes `playback_url`,
   `manifest_key`, `mode`, `token_expires_at`, optional `thumbnail_url`, plus session state
   and `ad_schedule`. VERIFIED. Source: `VodAdSupportedStartOut` (openapi.pretty.json
   ~82448-82550); `src/api/types.ts: VodAdSupportedStartResponse`.
6. `GET .../session` response `VodAdSupportedSessionOut` does NOT include `playback_url`/
   `manifest_key` (only the start response carries the grant). VERIFIED. Source:
   `VodAdSupportedSessionOut` properties (openapi.pretty.json ~82362-82433) vs
   `VodAdSupportedStartOut`.
7. `VodAdBreak` fields: `break_id`, `slot_type`, `position_seconds`, `duration_seconds`,
   `creative_id`, `creative_url`, `creative_type`, `skip_after_seconds`, `slot_index`,
   `completed`. Units are integer **seconds**; ONE creative per break. VERIFIED. Source:
   `VodAdBreak` (openapi.pretty.json ~82213-82271); `src/api/types.ts: VodAdBreak`.
8. (Original draft) break used `cue_point_ms`/`skippable`/`skip_offset_ms` + a list of
   `ads` with `ad_id`/`media_url`/`duration_ms`/`click_through_url`/`watched`. CORRECTED —
   none of those field names exist. Replaced with the verified seconds-based, single-creative
   shape (claim 7). Source: same as claim 7.
9. `slot_type` enum is `pre_roll | mid_roll | overlay` — there is NO `post_roll`.
   VERIFIED. Source: `src/api/types.ts: VodAdBreak.slot_type` literal union; OpenAPI
   `VodAdBreak.slot_type` is `type: string` (no enum constraint there, but the frontend
   union is authoritative for the values served).
10. (Original draft) post-roll break plays after content end. CORRECTED to "no post-roll".
    Source: claim 9.
11. `POST .../break` request `VodAdBreakReportIn` = `{break_id (required), event_type}` with
    `event_type` ∈ `impression|complete|skip` (regex `^(impression|complete|skip)$`, default
    `complete`). VERIFIED. Source: `VodAdBreakReportIn` (openapi.pretty.json ~82272-82291);
    `src/api/types.ts: VodAdBreakReportRequest`.
12. `POST .../break` response `VodAdBreakReportOut` returns `ok`, `completed`,
    `breaks_completed`, `breaks_total`, `next_required_break_id`, `playback_unlocked`,
    `status`, plus echoes. VERIFIED. Source: `VodAdBreakReportOut` (openapi.pretty.json
    ~82292-82360); `src/api/types.ts: VodAdBreakReportResponse`.
13. Playback gating is SERVER-authoritative via `playback_unlocked` /
    `next_required_break_id`, recomputed by `POST .../break`. VERIFIED. Source:
    `VodAdSupportedStartOut`/`VodAdBreakReportOut` fields; `VodAdSupportedPage.tsx`
    (reportMut.onSuccess applies `playback_unlocked`/`next_required_break_id`; description
    comment: "Continued playback is gated until each required ad break is reported complete").
14. `ads_free` flag indicates an empty ad schedule / ad-free playback. VERIFIED. Source:
    `VodAdSupportedSessionOut.ads_free`/`VodAdSupportedStartOut.ads_free`;
    `VodAdSupportedPage.tsx` ("No ads for you — enjoy ad-free playback.").
15. Auth: cookie session with `ui_csrf` cookie echoed as `X-CSRF-Token`; requests send
    cookies (`credentials: "include"`). VERIFIED. Source: `src/api/client.ts` (~lines
    168-171 CSRF, ~183 `credentials: "include"`).
16. On 401, the client refreshes once via `POST /ui/session/refresh` then retries the
    request exactly once. VERIFIED. Source: `src/api/client.ts` `refreshSession()` (~121-130)
    and 401 handler (~194-237).
17. `X-IMPERSONATION-TOKEN` header is sent when impersonation is active. VERIFIED. Source:
    `src/api/client.ts` (~162-165); OpenAPI index params list `X-IMPERSONATION-TOKEN`.
18. These endpoints declare only `200` and `422:HTTPValidationError` in OpenAPI. VERIFIED.
    Source: OpenAPI index lines 2044-2046 (`resp=200:...;422:HTTPValidationError`).
19. (Original draft) `403`/`404`/`409` are AVOD-specific terminal errors. UNVERIFIED-
    assumption — not declared in OpenAPI for these ops. A generic `403` geo-block
    (`detail.code == "geo_blocked"`) IS handled app-wide. Source: claim 18; `src/api/client.ts`
    403 handler (~239-255).
20. (Original draft) `heartbeat_interval_ms` and content-position heartbeats. CORRECTED /
    UNVERIFIED-assumption removed — no such field and no heartbeat endpoint exist. Source:
    OpenAPI index (only the three endpoints, none accept positional heartbeats);
    `VodAdSupportedSessionOut`/`StartOut` have no heartbeat field.
21. (Original draft) `click_through_url` on creatives. CORRECTED — field does not exist.
    Source: `VodAdBreak` schema (claim 7).
22. (Original draft) DRM/license info in the session response. UNVERIFIED-assumption /
    removed — no DRM field in `VodAdSupportedStartOut`/`SessionOut`. Source: claims 5-6.
23. ExoPlayer/Media3 1.4 (HLS) is the playback engine and Compose/Material3 the UI. Framework
    choice (framework ref): Media3 ExoPlayer — https://developer.android.com/media/media3/exoplayer ;
    HLS support — https://developer.android.com/media/media3/exoplayer/hls .
24. PiP requires API 26+ (minSdk 24 → PiP unavailable below 26). VERIFIED (framework ref):
    https://developer.android.com/develop/ui/views/picture-in-picture .

### Corrections made

- Endpoint set rewritten from one `POST .../session` (+ `.../session/{id}/event`) to the real
  `GET .../session`, `POST .../start`, `POST .../break` (claims 1-3, 11-12). §1, §2, §4.2,
  §4.3, §5, §14.
- `VodAdBreak` model rewritten: seconds (not millis), single creative (not a list of `ads`),
  `slot_type`/`slot_index`/`completed`, `skip_after_seconds` (no `skippable` boolean / no
  `skip_offset_ms`), no `click_through_url` (claims 7-8, 21). §4.1, §4.4, FR-2, FR-4.
- Removed non-existent `content_url`/`content_duration_ms`/`heartbeat_interval_ms`/DRM;
  playback comes from `playback_url` on `POST .../start` (claims 5, 20, 22). §4.1, §5, §6.
- Removed post-roll throughout; `slot_type` is pre_roll/mid_roll/overlay only (claims 9-10).
  §1, FR-3, AC-2, §13 Q1.
- Gating reframed as server-authoritative (`playback_unlocked`/`next_required_break_id`)
  with the client scheduler as an optimistic mirror (claim 13). FR-5, §4.4, AC-4, AC-5.
- Error model: only 200/422 declared; 403/404/409 demoted to defensive/unverified, geo-block
  403 kept (claims 18-19). §5, §7.
- Frontend reference path corrected to `src/api/endpoints/vodAdSupported.ts`. §2.

### Open assumptions

- Non-skippable encoding: the contract has only `skip_after_seconds` (Int), no explicit
  non-skippable boolean. How the backend marks a break as non-skippable (large sentinel vs.
  equal to duration) is UNVERIFIED — confirm during integration (§13 Q4). Why unverifiable:
  not expressible in the schema; depends on backend data conventions not in the reference.
- Mid-roll snap-back-then-resume seek UX is a CLIENT policy. The backend only exposes
  gate state; it does not dictate seek snapping. UNVERIFIED against any source as a backend
  requirement — it is a deliberate client design choice. (FR-5.)
- Overlay (`creative_type == image`) rendering/dismissal behavior is not specified by the
  backend; treated as a non-blocking client-side overlay. UNVERIFIED design assumption.
- `token_expires_at` re-`start` behavior (whether an expired grant 401s or 403s) is not
  documented (only 200/422 declared). Assumed: re-issue `POST .../start`. UNVERIFIED.
- AVOD-specific `403`/`404`/`409` terminal semantics (claim 19) — not in OpenAPI.

## 17. Test Plan

IDs `TC-AND-194-NN`. Targets: JVM = local JVM/Robolectric (no device); MWS =
MockWebServer contract; EMU = headless AVD `test35` (x86_64, API 35); DEV = Samsung Galaxy
A15 5G (SM-A156U, serial R5CX821TA9R, API 34, arm64) on the build host via adb. Physical
device is REQUIRED only for real hardware/network behavior; AVOD has no camera/biometric/
WebRTC/Telecom needs, so most cases run on JVM/EMU. DEV is used for real-network HLS, PiP at
API 26+ on real hardware, and arm64-vs-x86 / API-34-vs-35 sanity.

- TC-AND-194-01 — Type: contract/MockWebServer (MWS, JVM). Target: `VodAdSupportedApi`
  Moshi adapters. Preconditions: MWS enqueues the §5.2 `VodAdSupportedStartOut` JSON.
  Steps: call `start("vid_1207")`; assert parsed fields. Expected: `playback_url`,
  `manifest_key`, `mode`, `token_expires_at` parsed; `ad_schedule` has 2 `AdBreak`s with
  `slot_type` pre_roll/mid_roll, `position_seconds` 0/900, single creative each,
  `skip_after_seconds` 5, `completed=false`; request method=POST path
  `/ui/vod/ad-supported/vid_1207/start`. Traces: AC-1.
- TC-AND-194-02 — Type: contract/MockWebServer (MWS, JVM). Target: `getSession` mapping.
  Preconditions: MWS enqueues §5.1 `VodAdSupportedSessionOut` (no playback grant).
  Steps: call `getSession`; assert. Expected: GET method; `playback_unlocked=false`,
  `next_required_break_id="br_pre"`, `breaks_total`/`breaks_completed` parsed; no
  `playback_url` field present. Traces: AC-1.
- TC-AND-194-03 — Type: contract/MockWebServer (MWS, JVM). Target: `reportBreak`.
  Preconditions: MWS enqueues §5.3 `VodAdBreakReportOut`. Steps: call
  `reportBreak("vid_1207","br_mid1","complete")`. Expected: POST to
  `/ui/vod/ad-supported/vid_1207/break`; request body `{break_id, event_type:"complete"}`
  (default applied when omitted); response maps `playback_unlocked=true`,
  `next_required_break_id=null`, `completed=true`. Traces: AC-5.
- TC-AND-194-04 — Type: unit (JVM). Target: `AdBreakScheduler`. Preconditions: schedule with
  pre_roll@0, mid_roll@900s, mid_roll@1800s; none completed. Steps: `preRoll()`;
  `breakCrossedBy` at 901s; `isForwardSeekAllowed(0,1000s)`;
  `breakDueForSeek(0,1000s)`. Expected: preRoll returns the pre_roll break;
  crossing returns mid@900; forward seek across an unwatched mandatory mid is disallowed and
  `breakDueForSeek` returns the earliest such break (mid@900). Traces: AC-2, AC-4.
- TC-AND-194-05 — Type: unit (JVM). Target: `AdBreakScheduler` watched/backward. Preconditions:
  mid@900 marked completed (from server `completed=true`). Steps: `isForwardSeekAllowed(0,1000s)`;
  backward seek `breakDueForSeek(1200s,300s)`. Expected: forward seek now allowed (completed
  break does not gate); backward seek returns null (no replay of completed breaks). Traces: AC-4.
- TC-AND-194-06 — Type: unit (JVM, virtual time). Target: `AdSupportedPlayerViewModel`.
  Preconditions: repo fake returns `start` success then `reportBreak` unlock. Steps: init →
  collect uiState; drive pre_roll; advance time to `skip_after_seconds`; call `onSkipAd`;
  feed `reportBreak` response. Expected: Loading→Ready; phase Ad during pre_roll; skip
  disabled before `skip_after_seconds` and enabled exactly at/after it; after report,
  `playback_unlocked` applied and phase→Content. Traces: AC-3, AC-5.
- TC-AND-194-07 — Type: unit (JVM). Target: ViewModel error + retry. Preconditions: repo
  `start` returns Error first, Success on retry. Steps: init; observe Error; call `retry()`.
  Expected: state Loading→Error(message); `retry()` re-issues `POST .../start` and reaches
  Ready. Traces: AC-6.
- TC-AND-194-08 — Type: contract/MockWebServer (MWS, JVM). Target: 401 refresh-retry.
  Preconditions: MWS enqueues 401 for `.../start`, 200 for `POST /ui/session/refresh`, then
  200 `VodAdSupportedStartOut`. Steps: authenticated client calls `start`. Expected: client
  issues refresh once then retries `start` once and succeeds; total `.../start` attempts = 2.
  Traces: AC-6.
- TC-AND-194-09 — Type: contract/MockWebServer (MWS, JVM). Target: error-shape mapping.
  Preconditions: MWS enqueues 422 with FastAPI `detail` as list `[{msg,loc}]`, then a
  separate 403 with `detail:{code:"geo_blocked",message:...}`. Steps: call `start` for each.
  Expected: 422 maps to a readable validation `ApiResult.Error`; geo 403 maps to a terminal
  geo error; neither crashes Moshi. Traces: AC-6.
- TC-AND-194-10 — Type: unit (JVM). Target: best-effort vs mandatory report policy (§7).
  Preconditions: report fails (network) for a mandatory mid-roll, then for an overlay break.
  Steps: trigger both. Expected: mandatory-break failure keeps the gate closed and surfaces
  retry/error (does not advance content past the cue); overlay/non-mandatory failure is
  retried (max 2) and does not block content. Traces: AC-5.
- TC-AND-194-11 — Type: Compose-UI (EMU). Target: `AdOverlay`. Preconditions: Ready state,
  phase Ad, `currentAdIndex` within break, skip countdown running. Steps: render; advance to
  skip-enable; tap "Skip Ad"; assert scrub bar state. Expected: "Ad" badge + "Ad N of M" +
  remaining time shown; "Skip Ad" disabled then enabled after `skip_after_seconds` and the
  callback fires on tap; scrub/forward-seek controls disabled while phase==Ad. Traces: AC-3,
  AC-7.
- TC-AND-194-12 — Type: Compose-UI accessibility (EMU). Target: `AdOverlay` a11y.
  Preconditions: same Ready/Ad state. Steps: assert semantics. Expected: "Skip Ad" has
  contentDescription and ≥48dp target, announced "Skip available in N seconds" while
  disabled; "Ad"/"Ad N of M" exposed to TalkBack as a live region; disabled scrub control
  marked unavailable/non-focusable; layout passes RTL + large font scale. Traces: AC-7.
- TC-AND-194-13 — Type: instrumented/e2e (DEV physical device). Target: full AVOD flow over
  real network against `http://18.222.237.167:8000`. Preconditions: device on network, signed
  in, an `ad_supported` title. Steps: from VOD detail (AND-191) tap Play → `POST .../start`;
  watch pre_roll; report complete; verify content unlocks; cross a mid_roll cue and report;
  re-enter the title. Expected: real HLS `playback_url` plays; gating
  (`playback_unlocked`/`next_required_break_id`) advances after each `POST .../break`;
  `completed` breaks persist on re-entry via `GET .../session`; runs on arm64/API-34.
  MUST run on DEV (real-network HLS streaming + arm64/API-34 sanity). Traces: AC-1, AC-2,
  AC-4, AC-5, AC-8.
- TC-AND-194-14 — Type: instrumented (DEV physical device, then EMU compare). Target: PiP +
  ad gating. Preconditions: API 26+ device (A15 = API 34). Steps: enter PiP during content;
  trigger a mandatory mid-roll; return to full UI. Expected: skip control unavailable in PiP;
  ad gating still holds (content does not advance past an unreported mandatory break); ad
  state preserved on return. Note: PiP unavailable below API 26 — on such configs verify
  gating still holds in full-screen. Run on DEV for real PiP behavior; EMU for the
  no-PiP/API path. Traces: AC-3, AC-8.
- TC-AND-194-15 — Type: manual (DEV). Target: security/logging + cleartext.
  Preconditions: release-like build, logcat attached. Steps: run a session; inspect logs;
  confirm cleartext dev host reachable only via dev network-security-config. Expected: no
  full `creative_url`/`playback_url` (signed params) logged at info level; only `break_id`/
  `event_type` in report payloads (no PII); cleartext allowed for dev host only. Traces:
  AC-5 (security aspects), §8.

### Coverage matrix

| AC (section 14) | Covered by |
| --- | --- |
| AC-1 (start/session + playback_url/ad_schedule) | TC-01, TC-02, TC-13 |
| AC-2 (pre/mid breaks fire at cue points) | TC-04, TC-13 |
| AC-3 (controls disabled during ad; skip timing) | TC-06, TC-11, TC-14 |
| AC-4 (forward-seek gating; no backward replay) | TC-04, TC-05, TC-13 |
| AC-5 (report break; apply unlock; failure policy) | TC-03, TC-06, TC-10, TC-13, TC-15 |
| AC-6 (start failure retry; 401 refresh-retry; errors) | TC-07, TC-08, TC-09 |
| AC-7 (ad UI badge/N-of-M/countdown; a11y; i18n) | TC-11, TC-12 |
| AC-8 (end-to-end: session plays with ad breaks) | TC-13, TC-14 |
