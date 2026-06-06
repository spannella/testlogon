---
id: AND-190
title: Video detail + player
milestone: M4
epic: E26
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-189, AND-168]
blocks: []
---

# AND-190 — Video detail + player

## 1. Overview & Goal

Deliver the video **detail screen** for the TestLogon native Android app, including a metadata header and inline **HLS playback** of the selected video. A user navigating from the Videos library grid (AND-189) lands on a detail route, sees title/description/runtime/poster metadata fetched from the backend, and can press play to stream the video through the reusable Media3/ExoPlayer player surface delivered in AND-168.

The success bar is concrete: **a video plays from the detail screen.** This ticket owns (a) the `feature-videos` detail route, ViewModel, and Compose UI; (b) the `GET /ui/videos/{video_id}` detail fetch (op `get_video_detail_ui_videos__video_id__get`, resp `VideoDetailOut`) and its mapping into `core-model`; and (c) wiring the resolved HLS playback URL into the reusable player component. **[Corrected: the spec previously said `GET /videos/{id}`; the real path is `GET /ui/videos/{video_id}` per the OpenAPI index and `frontend/src/api/endpoints/videos.ts: getVideoDetail`.]** It does **not** re-implement transport controls, fullscreen, or PiP — those belong to AND-168 and are consumed here.

This screen is the first place the unreliable dev backend (plaintext HTTP, ~20s latency) meets streaming media, so resilient loading, stale/offline states, and graceful playback-error recovery are first-class requirements, not afterthoughts.

## 2. Context & References

- **Repo / module:** `spannella/testlogon`, Android app under `android/`, branch `android-port`. Code lands in `feature-videos` (detail screen, ViewModel) with model/data changes in `core-model` and `core-data`/`core-network`.
- **Namespace:** `com.testlogon.android` everywhere a package appears (e.g. `com.testlogon.android.feature.videos.detail`).
- **Upstream deps:**
  - **AND-189 (Videos library):** owns `videos.ts`-equivalent browse/grid and the navigation action that opens this detail route with a `videoId` argument.
  - **AND-168 (Reusable player UI):** owns the `VideoPlayer` composable + `PlayerController` (play/seek/scrub/volume/fullscreen, buffering/error states, PiP). This ticket passes a media URL/`MediaItem` into that component and observes its state; it must not fork or duplicate player controls.
- **Backend:** FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000` (PLAINTEXT HTTP, unreliable). OpenAPI at `/openapi.json`. Web reference under `frontend/` (`frontend/src/api/endpoints/videos.ts`, `frontend/src/api/client.ts`) is the source of truth for field names. **[Verified during this review: the detail field set is `VideoDetailOut` / the frontend `VideoDetail` interface — see §5 for the corrected DTO.]**
- **Auth:** **Verified against `frontend/src/api/client.ts`:** every request sends (a) the cookie jar (`credentials: "include"`), (b) `X-CSRF-Token` taken from the `ui_csrf` cookie, AND (c) an `Authorization: Bearer <accessToken>` header from the auth store. **[Correction: the original spec described only cookie + `X-CSRF-Token` and omitted the `Authorization: Bearer` header — the Android port must send the bearer token too.]** A single retry occurs on `401`: the client POSTs `/ui/session/refresh` (cookies only) once and replays the original request; if the replay also 401s the session is logged out. The OpenAPI lists `X-SESSION-ID`/`user_sub`/`X-IMPERSONATION-TOKEN` as endpoint params, but the web client does not set `X-SESSION-ID`/`user_sub` directly (server-side dependency-injected); only `X-IMPERSONATION-TOKEN` is set during impersonation (not relevant to this screen). The video detail GET and the HLS manifest request both ride this authenticated session.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, single-Activity Navigation-Compose, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Media3/ExoPlayer 1.4 (HLS), Coil, Room 2.6, DataStore. minSdk 24 / target 35, JDK 17, AGP 8.7.3, Gradle 8.9.

## 3. Functional Requirements

1. **Route & navigation.** A typed route `videos/detail/{videoId}` is reachable from the library grid. The screen reads `videoId: String` from `SavedStateHandle`.
2. **Metadata display.** On entry the screen fetches video detail and renders: poster/thumbnail (`thumbnail_url`, via Coil), title, description, and duration (`duration_seconds`, formatted `H:MM:SS` / `M:SS`), plus available secondary metadata when present: publish date (`published_at`, epoch **seconds** integer → format locale-aware). **[Correction: the original spec listed `view count` and `tags` as secondary metadata; `VideoDetailOut` has neither `view_count` nor `tags`. Available secondary fields instead include `published_at`, `status`, `visibility`, and entitlement flags (`is_entitled`, `access_mode`, `access_reason`). Do not render a view count or tags.]**
3. **Loading state.** While the detail request is in flight, show a skeleton/placeholder for the metadata block and a non-interactive player surface (poster + disabled play affordance).
4. **Playback start.** A play control on the player surface begins HLS streaming using the resolved playback URL. **[Verified against `frontend/src/pages/videos/VideoPlayerPage.tsx`: the playback URL is `hls_manifest_url + "?token=" + playback_token`. BOTH `hls_manifest_url` AND `playback_token` must be non-null; if either is missing there is no playable URL.]** Playback uses the AND-168 `VideoPlayer`; this screen supplies the `MediaItem` and lifecycle ownership only.
5. **Player lifecycle.** The player is created when detail (and thus playback URL) is available, paused on `ON_PAUSE`, and released on `ON_DESTROY` / when navigating away. Playback position survives configuration change (rotation) via saved state.
6. **Error states.** Distinct, recoverable UI for: detail-fetch failure (Retry), no playback URL available (message, no Retry on player), and playback/streaming failure surfaced by the player (Retry re-prepares the `MediaItem`). **[Added per `VideoPlayerPage.tsx`:]** also handle (a) `403` forbidden / not entitled → "You don't have access to this video" (no Retry), distinct from `404` "Video not found"; and (b) a *processing* state when `status` ∈ {`created`, `probing`, `pending_encoding`, `encoding`} → show "This video is still processing" with no play affordance (the manifest is not yet ready).
7. **Offline / stale.** If a cached detail record exists (Room) it renders immediately while a background refresh runs; on hard offline, show the cached metadata with an offline banner and disable play if the manifest cannot be reached.
8. **Back / interruption.** Navigating back, receiving a phone call, or backgrounding pauses playback and preserves position; PiP transitions (owned by AND-168) must not be broken by this screen's lifecycle handling.

## 4. Technical Design

### Package & files (`com.testlogon.android.feature.videos.detail`)
- `VideoDetailRoute.kt` — Navigation entry, hoists ViewModel, collects state.
- `VideoDetailScreen.kt` — Stateless Composable rendering `VideoDetailUiState`.
- `VideoDetailViewModel.kt` — Hilt ViewModel exposing `StateFlow<VideoDetailUiState>`.
- `VideoDetailUiState.kt` — sealed/`data class` UI model.

### Navigation
```kotlin
// core navigation graph (consumed from AND-189's grid item onClick)
const val ARG_VIDEO_ID = "videoId"
const val ROUTE_VIDEO_DETAIL = "videos/detail/{$ARG_VIDEO_ID}"

fun NavController.navigateToVideoDetail(videoId: String) =
    navigate("videos/detail/$videoId")

fun NavGraphBuilder.videoDetailScreen() {
    composable(
        route = ROUTE_VIDEO_DETAIL,
        arguments = listOf(navArgument(ARG_VIDEO_ID) { type = NavType.StringType }),
    ) { VideoDetailRoute() }
}
```

### ViewModel
```kotlin
@HiltViewModel
class VideoDetailViewModel @Inject constructor(
    private val repository: VideoRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {
    private val videoId: String = checkNotNull(savedStateHandle[ARG_VIDEO_ID])

    private val _uiState = MutableStateFlow(VideoDetailUiState())
    val uiState: StateFlow<VideoDetailUiState> = _uiState.asStateFlow()

    init { load() }

    fun load() { /* emit Loading, collect repository.observeVideo(videoId) */ }
    fun retryDetail() = load()
    fun onPlaybackError(error: PlaybackException) { /* set playbackError, allow retry */ }
    fun retryPlayback() { /* bump a re-prepare token consumed by the player */ }
}
```

### Repository (`core-data`)
```kotlin
interface VideoRepository {
    /** Cache-first stream: emits cached detail (if any) then refreshed result. */
    fun observeVideo(id: String): Flow<ApiResult<Video>>
    suspend fun refreshVideo(id: String): ApiResult<Video>
}
```
`VideoRepositoryImpl` reads Room (`VideoEntity`), triggers a network refresh via the videos API, maps DTO → `core-model.Video`, upserts the cache, and emits `ApiResult`. Network errors fall back to cached data with a `stale = true` flag where available.

### Player integration (from AND-168)
The screen owns an ExoPlayer instance scoped to composition and feeds it the resolved URL:
```kotlin
val exoPlayer = rememberExoPlayer() // helper from core-ui / AND-168
LaunchedEffect(state.playbackUrl, state.playbackRetryToken) {
    state.playbackUrl?.let { url ->
        exoPlayer.setMediaItem(MediaItem.fromUri(url))
        exoPlayer.prepare()
    }
}
VideoPlayer(                       // AND-168 component
    player = exoPlayer,
    modifier = Modifier.aspectRatio(16f / 9f),
    onPlayerError = viewModel::onPlaybackError,
)
```
ExoPlayer is built with an `OkHttpDataSource.Factory` wired to the **shared authenticated OkHttp client** (same cookie jar + CSRF interceptor + `Authorization: Bearer` interceptor) so the HLS manifest/segment requests carry the session. Note the manifest URL itself already carries `?token=<playback_token>`; the session headers are belt-and-suspenders for any API-host manifest. The `HlsMediaSource.Factory` is used for `application/vnd.apple.mpegurl` URLs.

### Lifecycle
`LifecycleEventObserver` registered via `DisposableEffect`: `ON_PAUSE` → `pause()`; `ON_DESTROY` → `release()`. Position saved via `rememberSaveable` (`playbackPositionMs`, `playWhenReady`) and restored after `prepare()`.

## 5. API Contract

### Detail fetch
**[Corrected path]** `GET /ui/videos/{video_id}` — op `get_video_detail_ui_videos__video_id__get`, resp `200: VideoDetailOut` / `422: HTTPValidationError`. Authenticated (cookie jar + `X-CSRF-Token` + `Authorization: Bearer`). Idempotent: eligible for bounded backoff retry on transient failures. Verified against the OpenAPI index and `frontend/src/api/endpoints/videos.ts: getVideoDetail`.

Retrofit:
```kotlin
interface VideosApi {
    @GET("ui/videos/{video_id}")
    suspend fun getVideo(@Path("video_id") videoId: String): VideoDetailDto
}
```

Expected 200 response — **verified field shapes** from `components.schemas.VideoDetailOut` and `frontend/src/api/endpoints/videos.ts: VideoDetail` (note: `*_at` fields are **epoch integers**, `duration_seconds` is a **float/number**, NO `view_count`, NO `tags`, NO `playback_url` — the manifest is `hls_manifest_url` paired with `playback_token`):
```json
{
  "video_id": "vid_123",
  "owner_user_id": "usr_42",
  "title": "Intro to TestLogon",
  "description": "Walkthrough of the login flow.",
  "status": "ready",
  "visibility": "public",
  "created_at": 1746100800,
  "updated_at": 1746187200,
  "published_at": 1746100800,
  "duration_seconds": 372.5,
  "thumbnail_url": "http://.../poster.jpg",
  "hls_manifest_url": "http://.../vid_123/master.m3u8",
  "playback_token": "eyJ...",
  "playback_expires_at": 1746190800,
  "is_entitled": true,
  "access_mode": "free",
  "access_reason": "none"
}
```
Required fields per schema: `video_id`, `owner_user_id`, `title`, `status`, `visibility`, `created_at`, `updated_at`. Everything else is nullable/optional.

DTO + mapping (**corrected**):
```kotlin
@JsonClass(generateAdapter = true)
data class VideoDetailDto(
    @Json(name = "video_id") val videoId: String,
    @Json(name = "owner_user_id") val ownerUserId: String,
    val title: String,
    val description: String?,
    val status: String,
    val visibility: String,
    @Json(name = "created_at") val createdAt: Long,
    @Json(name = "updated_at") val updatedAt: Long,
    @Json(name = "published_at") val publishedAt: Long?,        // epoch seconds, NOT ISO string
    @Json(name = "duration_seconds") val durationSeconds: Double?, // float, NOT Int
    @Json(name = "thumbnail_url") val thumbnailUrl: String?,
    @Json(name = "hls_manifest_url") val hlsManifestUrl: String?,  // NOT "playback_url"
    @Json(name = "playback_token") val playbackToken: String?,
    @Json(name = "playback_expires_at") val playbackExpiresAt: Long?,
    @Json(name = "is_entitled") val isEntitled: Boolean = false,
    @Json(name = "access_mode") val accessMode: String?,
    @Json(name = "access_reason") val accessReason: String = "none",
)
fun VideoDetailDto.toDomain(): Video = Video(/* map hls_manifest_url + playback_token → playbackUrl */)
```

**Playback URL resolution (corrected):** the manifest is **inline** in the detail payload — there is **no** separate `GET /videos/{id}/stream` endpoint. Build the playback URL as `hls_manifest_url + "?token=" + playback_token` (verified in `frontend/src/pages/videos/VideoPlayerPage.tsx`). If either `hls_manifest_url` or `playback_token` is null, there is no playable URL. (Open Question 13.1 is now resolved.)

**Error mapping (verified against `frontend/src/api/client.ts` + `VideoPlayerPage.tsx`):** FastAPI `detail` (string | `[{msg}]` | `{code,...}`) is normalized by the `core-network` error mapper (mirrors `normalizeErrorDetail`) into `ApiResult.Error(message, code)`. `404` → "Video not found". `403` → "You don't have access to this video" (entitlement/permission; `detail.code == "geo_blocked"` is a special geo-block sub-case). `422` → `HTTPValidationError` (`detail: [{loc,msg,type}]`). `401` → triggers the single `/ui/session/refresh` + replay handled by the auth interceptor.

## 6. Data & State Management

### UI state
```kotlin
data class VideoDetailUiState(
    val isLoading: Boolean = true,
    val video: Video? = null,
    val playbackUrl: String? = null,
    val isStale: Boolean = false,
    val isOffline: Boolean = false,
    val detailError: UiMessage? = null,     // shows metadata-level Retry
    val playbackError: UiMessage? = null,   // shows player-level Retry
    val playbackRetryToken: Int = 0,        // bump to force re-prepare
)
```

### Domain model (`core-model`)
```kotlin
data class Video(
    val id: String,                  // from video_id
    val ownerUserId: String,
    val title: String,
    val description: String?,
    val status: String,              // ready | encoding | probing | ...
    val visibility: String,
    val durationSeconds: Double?,    // [Corrected] float per schema, not Int
    val thumbnailUrl: String?,
    val playbackUrl: String?,        // derived = hls_manifest_url + "?token=" + playback_token
    val publishedAt: Instant?,       // [Corrected] from epoch-seconds Long, not ISO string
    val isEntitled: Boolean,
    val accessMode: String?,
)
// [Corrected] removed viewCount and tags — not present in VideoDetailOut.
// [Corrected] map publishedAt = Instant.ofEpochSecond(published_at); created/updated similarly if surfaced.
```

### Cache (`core-data`, Room 2.6)
`VideoEntity` keyed by `id` (reuse/extend the entity introduced for AND-189's library list; add detail-only columns such as `description`, `playback_url`, `published_at`). Cache-first read provides instant render + stale fallback. No new DataStore prefs are required for this ticket; playback position is transient (saved instance state only, not persisted).

State emission: `repository.observeVideo(id)` → ViewModel maps `ApiResult<Video>` into `VideoDetailUiState`, setting `isStale`/`isOffline` when emitting cached data after a network failure.

## 7. Error Handling & Resilience

- **Detail GET (idempotent):** ~20s OkHttp timeout; bounded exponential backoff (e.g. 3 attempts, 500ms→2s, jittered) for transient `IOException`/`5xx`/timeout only — never for `4xx`. Implemented in the shared network layer; this ticket relies on it.
- **Cache-first:** cached detail renders immediately; a failed refresh keeps cached content with `isStale = true` and a subtle banner rather than blanking the screen.
- **Offline:** if no connectivity and no cache → full-screen error with Retry. If cache present → render with offline banner; play disabled when the manifest is unreachable.
- **Playback failure:** ExoPlayer `Player.Listener.onPlayerError(PlaybackException)` → `VideoDetailViewModel.onPlaybackError`. Map common codes (e.g. `ERROR_CODE_IO_*`, `ERROR_CODE_BEHIND_LIVE_WINDOW`) to a friendly message; "Retry" re-prepares via `playbackRetryToken`. Avoid infinite auto-retry loops.
- **No playback URL:** when `hls_manifest_url` or `playback_token` is null → show "This video cannot be played right now"; metadata still visible; no player Retry.
- **Not entitled / forbidden (`403`):** show "You don't have access to this video"; metadata may be hidden (the web app treats 403 as a fetch-level error that hides the player). No player Retry. Geo-block sub-case (`detail.code == "geo_blocked"`) surfaces the region message.
- **Processing:** when `status` ∈ {`created`,`probing`,`pending_encoding`,`encoding`} → "This video is still processing"; no play affordance.
- **Not found (`404`):** show "Video not found" (full-screen, with Retry only if it could be transient).
- **401 mid-session:** auth interceptor performs one `/ui/session/refresh` then replays the request; if the replay still 401s, surface a re-auth prompt routed to the session flow (web app logs out on second 401).

## 8. Security & Privacy

- All requests (detail GET + HLS manifest/segments) use the shared OkHttp client with the persistent cookie jar and `X-CSRF-Token` (from `ui_csrf`) so streaming traffic is authenticated and CSRF-consistent.
- Dev backend is **plaintext HTTP**; cleartext is permitted only for the dev host via a scoped `network-security-config` (no app-wide cleartext). Production HLS URLs must be HTTPS.
- No tokens, cookies, or full playback URLs (which may embed signed query params) are written to logs; redact query strings in any player/network log lines.
- No new PII is stored. Cached metadata in Room contains only public video attributes. Playback position is in-memory/instance-state only and not persisted to disk.

## 9. Accessibility & i18n

- All controls (play/Retry/back) have `contentDescription`; the player surface exposes a content description ("Video player: <title>"). Transport-control a11y is owned by AND-168 and inherited.
- Poster image `contentDescription` derived from title; decorative skeletons marked `Modifier.semantics { invisibleToUser() }`.
- Touch targets ≥ 48dp; text honors Dynamic Type / font scaling; layout reflows for landscape and large fonts.
- All user-facing strings (title fallback, error messages, duration units, offline/stale banners) live in `strings.xml` — no hardcoded literals. Duration and dates formatted via locale-aware formatters (`DateUtils` / `java.time` with device locale).
- Color is never the sole signal for error/offline; pair with icon + text. Verify contrast against Material 3 theme.

## 10. Telemetry & Logging

Emit via the shared analytics abstraction (no third-party SDK assumed here):
- `video_detail_viewed` { videoId }
- `video_playback_started` { videoId, startupMs } (time from play tap → first frame / `STATE_READY`)
- `video_playback_error` { videoId, errorCode }
- `video_detail_load_error` { videoId, httpStatus|null, cause }
- `video_detail_served_stale` { videoId } (cache shown after refresh failure)

Logging: structured debug logs gated behind `BuildConfig.DEBUG`; redact URLs/query params and never log cookies/CSRF. ExoPlayer analytics listener may be attached in debug builds only.

## 11. Testing Strategy

**Unit (`core-testing`, JUnit + Turbine + MockWebServer):**
- `VideoDetailViewModel`: emits `Loading → Content` on success; `Content(stale)` on cached+refresh-failure; `detailError` on hard failure with no cache; `retryDetail()` re-issues fetch; `onPlaybackError` sets `playbackError`; `retryPlayback()` bumps `playbackRetryToken`.
- `VideoRepositoryImpl`: cache-first emission order; DTO→domain mapping incl. null/missing fields; 404 mapping.
- DTO Moshi adapter: snake_case mapping, missing optional fields, unknown fields ignored.

**Instrumented / Compose UI tests:**
- Loading skeleton shown then metadata rendered.
- Detail error renders Retry; tapping invokes `retryDetail`.
- Player surface present and play affordance enabled only when `playbackUrl != null`.
- Rotation preserves playback position (saved-state assertion).

**Playback smoke (manual + instrumented where feasible):** with a known-good HLS test stream, verify play → `STATE_READY` → frame; verify pause on background and release on destroy (no leaked player). Acceptance gate "video plays from detail" validated against the dev backend or a stubbed manifest.

## 12. Dependencies & Sequencing

- **Hard deps:** AND-189 (library grid + navigation entry point and base `VideoEntity`/list API) and AND-168 (reusable `VideoPlayer` + controller, buffering/error UI, PiP). Both must be merged before this screen is functionally complete.
- **Transitive:** AND-168 → AND-166 (player core); AND-189 → AND-027, AND-103 (network/list infra). This ticket assumes the shared authenticated OkHttp client, `ApiResult`, and FastAPI error mapper already exist from earlier M-series tickets.
- **Sequencing:** land `VideoDetailDto` + `getVideo` + repository/mapping first (testable in isolation), then wire UI + ViewModel, then integrate the AND-168 player and run the playback smoke gate.
- **Blocks:** none currently recorded.

## 13. Risks & Open Questions

1. **Playback URL shape (OQ — RESOLVED):** The HLS URL is **inline** in `GET /ui/videos/{video_id}` as `hls_manifest_url`, paired with `playback_token`; the playable URL is `hls_manifest_url?token=<playback_token>`. No separate stream endpoint exists. No lazy URL-fetch branch needed. (Verified in OpenAPI `VideoDetailOut` and `frontend/src/pages/videos/VideoPlayerPage.tsx`.)
2. **Field names (OQ — RESOLVED):** Confirmed against `VideoDetailOut`: `duration_seconds` is a **float**, `*_at` are **epoch-second integers**, and there is **no** `view_count` or `tags`. DTO in §5 corrected accordingly.
3. **Authenticated segments:** HLS segment requests must carry session cookies; risk if the CDN/manifest host differs from the API host (cookie scope mismatch). Verify segment host vs cookie domain.
4. **Cleartext dev streaming:** plaintext HTTP HLS on the dev host requires scoped cleartext config; ensure prod path is HTTPS-only.
5. **Unreliable backend:** ~20s latency may cause perceived hangs before playback; startup timeout + clear buffering UI (from AND-168) mitigate.
6. **PiP interplay:** ensure this screen's lifecycle handling does not conflict with AND-168's PiP transitions (don't release the player during PiP).

## 14. Acceptance Criteria

1. Navigating from the videos library (AND-189) opens `videos/detail/{videoId}` and renders title, description, duration, and poster from `GET /ui/videos/{video_id}` (resp `VideoDetailOut`). **[Corrected endpoint path.]**
2. **A video plays from the detail screen** — pressing play streams the HLS source and reaches first-frame/`STATE_READY` against the dev backend (or stubbed manifest in CI).
3. While detail loads, a skeleton + non-interactive player surface is shown; on success it is replaced by metadata + an enabled play control.
4. Detail-fetch failure shows an inline error with a working Retry; cached detail (when present) renders immediately with a stale/offline indicator on refresh failure.
5. Playback errors surface a player-level message with Retry that re-prepares the media item; no playback URL (`hls_manifest_url`/`playback_token` null) → metadata-only with a clear message and no Retry. A `403`/not-entitled response shows "You don't have access to this video", and a video whose `status` is still processing shows a "still processing" message with no play affordance.
6. Player is paused on background and released on destroy with no leaked instances; playback position survives rotation.
7. The detail GET and HLS requests are authenticated (cookie jar + `X-CSRF-Token` + `Authorization: Bearer`); a 401 triggers exactly one `/ui/session/refresh` + replay.
8. No hardcoded user-facing strings; controls are labeled for TalkBack; no cookies/CSRF/URL query params appear in logs.

## 15. Definition of Done

- Code merged to `android-port` under `com.testlogon.android.feature.videos.detail` (+ `core-model`/`core-data` changes), passing CI (lint, detekt, unit + Compose tests).
- All acceptance criteria in §14 verified, including the playback smoke gate.
- `VideoDetailViewModel`, `VideoRepositoryImpl`, and DTO mapping covered by unit tests; key UI states covered by Compose tests.
- DTO/playback-URL Open Questions (§13.1–13.2) resolved against `/openapi.json` and the DTO updated accordingly, or explicitly tracked as a follow-up with a stub fallback.
- Scoped cleartext config confirmed for the dev host only; no app-wide cleartext.
- Telemetry events (§10) emitted and verified in debug; no sensitive data logged.
- Strings externalized; basic TalkBack pass on the detail screen and play control completed.
- No regressions to AND-168 player behavior (controls/fullscreen/PiP) when consumed from this screen.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **Detail endpoint path/method.** Claim: detail is fetched via `GET /ui/videos/{video_id}` (op `get_video_detail_ui_videos__video_id__get`, resp `VideoDetailOut`). **VERDICT: Corrected** (original spec said `GET /videos/{id}`). SOURCE: OpenAPI `GET /ui/videos/{video_id}`; `frontend/src/api/endpoints/videos.ts: getVideoDetail`.
2. **Path parameter name.** Claim: the path param is `video_id`, not `id`. **VERDICT: Corrected.** SOURCE: OpenAPI `GET /ui/videos/{video_id}` (params=video_id); `frontend/src/api/endpoints/videos.ts: getVideoDetail`.
3. **Detail response schema / field names.** Claim: response is `VideoDetailOut` with `video_id`, `owner_user_id`, `title`, `description`, `status`, `visibility`, `created_at`, `updated_at`, `published_at`, `duration_seconds`, `thumbnail_url`, `hls_manifest_url`, `playback_token`, `playback_expires_at`, `is_entitled`, `access_mode`, `access_reason`. **VERDICT: Verified/Corrected.** SOURCE: OpenAPI `components.schemas.VideoDetailOut`; `frontend/src/api/endpoints/videos.ts: VideoDetail`.
4. **`duration_seconds` type.** Claim: it is a float (`number`), not `Int`. **VERDICT: Corrected.** SOURCE: `VideoDetailOut.duration_seconds` (`type: number`); `frontend ... VideoDetail.duration_seconds: number | null`.
5. **Timestamp types.** Claim: `created_at`/`updated_at`/`published_at`/`playback_expires_at` are epoch-second integers, not ISO-8601 strings. **VERDICT: Corrected.** SOURCE: `VideoDetailOut.published_at` (`type: integer`), `created_at`/`updated_at` (`type: integer`); `frontend ... VideoDetail.created_at: number`.
6. **No `view_count` field.** Claim: `VideoDetailOut` has no `view_count`. **VERDICT: Corrected** (spec listed it). SOURCE: `components.schemas.VideoDetailOut` (no such property); `frontend ... VideoDetail` (absent). Note: a separate `POST /ui/videos/{video_id}/view` records views, but counts are not in the detail payload.
7. **No `tags` field.** Claim: `VideoDetailOut` has no `tags`. **VERDICT: Corrected** (spec listed it). SOURCE: `components.schemas.VideoDetailOut` (absent); `frontend ... VideoDetail` (absent).
8. **Playback URL is inline, not a separate endpoint.** Claim: the HLS manifest is inline (`hls_manifest_url`); no `GET /videos/{id}/stream`. **VERDICT: Corrected** (spec hypothesized a separate stream endpoint). SOURCE: `VideoDetailOut.hls_manifest_url`; `frontend/src/pages/videos/VideoPlayerPage.tsx` builds the URL from the detail payload.
9. **Playback URL construction.** Claim: playable URL = `hls_manifest_url + "?token=" + playback_token`, and both must be non-null. **VERDICT: Corrected** (spec used a single `playback_url` field). SOURCE: `frontend/src/pages/videos/VideoPlayerPage.tsx` (`video?.hls_manifest_url && video?.playback_token ? \`${hls_manifest_url}?token=${playback_token}\` : null`).
10. **Auth: cookie + CSRF.** Claim: requests send the cookie jar and `X-CSRF-Token` from the `ui_csrf` cookie. **VERDICT: Verified.** SOURCE: `frontend/src/api/client.ts` (`credentials: "include"`, `getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`).
11. **Auth: bearer header (omitted by spec).** Claim: requests also send `Authorization: Bearer <accessToken>`. **VERDICT: Corrected** (spec omitted this header). SOURCE: `frontend/src/api/client.ts` (`headers.set("Authorization", \`Bearer ${accessToken}\`)`).
12. **401 refresh+retry.** Claim: a single `/ui/session/refresh` POST then one replay of the original request on 401. **VERDICT: Verified.** SOURCE: `frontend/src/api/client.ts` `refreshSession()` + the `if (res.status === 401)` block (single `refreshPromise`, one retry, logout on second 401).
13. **404 message.** Claim: `404` → "Video not found". **VERDICT: Corrected** (spec said "Video not available"). SOURCE: `frontend/src/pages/videos/VideoPlayerPage.tsx` (`status === 404 → "Video not found"`).
14. **403 / not-entitled handling.** Claim: `403` → "You don't have access to this video"; geo-block sub-case via `detail.code == "geo_blocked"`. **VERDICT: Corrected/added** (spec had no 403 case). SOURCE: `frontend/src/pages/videos/VideoPlayerPage.tsx` (`status === 403 → "You don't have access to this video"`); `frontend/src/api/client.ts` 403 handler (`code === "geo_blocked"`).
15. **Processing states gate playback.** Claim: `status` ∈ {`created`,`probing`,`pending_encoding`,`encoding`} means not yet playable. **VERDICT: Verified.** SOURCE: `frontend/src/pages/videos/VideoPlayerPage.tsx` (`isProcessing` check on those statuses).
16. **FastAPI error `detail` shape.** Claim: `detail` may be string | `[{msg}]` | `{code,...}`, normalized by a mapper. **VERDICT: Verified.** SOURCE: `frontend/src/api/client.ts: normalizeErrorDetail`; OpenAPI `422: HTTPValidationError` (`detail: [{loc,msg,type}]`).
17. **Entitlement flags exist.** Claim: `is_entitled`, `access_mode`, `access_reason`, `visibility`, `status` are part of the detail payload. **VERDICT: Verified.** SOURCE: `components.schemas.VideoDetailOut`; `frontend ... VideoDetail`.
18. **Subtitles available (not in scope but adjacent).** Claim: subtitle tracks come from a separate `GET /ui/videos/{video_id}/subtitles`. **VERDICT: Verified** (out of scope for this ticket; noted to avoid mis-mapping). SOURCE: OpenAPI `GET /ui/videos/{video_id}/subtitles`; `frontend/src/pages/videos/VideoPlayerPage.tsx: listSubtitles`.
19. **Android framework choices (Media3/ExoPlayer HLS, OkHttpDataSource, lifecycle release).** Claim: HLS via `HlsMediaSource.Factory` + `OkHttpDataSource.Factory`; release player on `ON_DESTROY`. **VERDICT: Unverified-assumption (framework ref).** SOURCE (framework ref): Media3 ExoPlayer HLS docs — https://developer.android.com/media/media3/exoplayer/hls ; player lifecycle — https://developer.android.com/media/media3/exoplayer/player-events . Not verifiable from backend/frontend sources; consistent with stated stack and AND-168.
20. **Cleartext config for dev host.** Claim: scoped `network-security-config` cleartext for the dev host only. **VERDICT: Unverified-assumption (framework ref).** SOURCE (framework ref): https://developer.android.com/privacy-and-security/security-config . Dev host is plaintext HTTP per §2; scoping is a design choice, not in the sources.

### Corrections made
- §1, §5, §14.1: endpoint path `GET /videos/{id}` → `GET /ui/videos/{video_id}` (resp `VideoDetailOut`).
- §5: path param `id` → `video_id`; Retrofit signature updated.
- §5, §6: DTO/domain field `id` → `video_id`; `playback_url` → `hls_manifest_url` (+ `playback_token`); `durationSeconds` `Int` → `Double`; `publishedAt` ISO-string → epoch-seconds `Long`/`Instant.ofEpochSecond`; removed `view_count` and `tags`; added `owner_user_id`, `status`, `visibility`, `is_entitled`, `access_mode`, `access_reason`.
- §3.2: removed `view count`/`tags` from rendered metadata; clarified `published_at` is epoch seconds.
- §3.4, §5: playback URL is inline and = `hls_manifest_url?token=<playback_token>`; both fields required; no separate stream endpoint (OQ 13.1/13.2 resolved).
- §2 (Auth), §4, §14.7: added the `Authorization: Bearer` header alongside cookie + `X-CSRF-Token`.
- §5, §7: `404` message "Video not available" → "Video not found"; added `403`/not-entitled ("You don't have access to this video"), geo-block sub-case, and processing-state gating.
- §13.1/§13.2: marked RESOLVED.
- Frontmatter: `status: draft` → `reviewed`; added `reviewed_on: 2026-06-06`.

### Open assumptions
- **Media3/ExoPlayer + OkHttpDataSource integration details** (AND-168 surface, `rememberExoPlayer`, HLS factory wiring): not verifiable from backend/frontend; rely on the stated stack and AND-168 contract (framework refs in citations 19).
- **Scoped cleartext `network-security-config`**: a design choice; not present in sources (framework ref, citation 20).
- **Whether HLS segment hosts share the API cookie domain** (§13.3): cannot be confirmed from the OpenAPI/frontend (manifest host is dynamic per video). Carried as a runtime verification item; the `?token=` query param suggests segments may be token-authorized rather than cookie-authorized.
- **Telemetry event names** (§10): no analytics SDK/contract in the sources; names are app-internal proposals, unverifiable.
- **Room cache schema** (`VideoEntity` reuse from AND-189): depends on AND-189, not on these sources; assumption.

## 17. Test Plan

Test-target legend: **JVM** = JVM unit/Robolectric (local, no device); **EMU** = headless emulator AVD `test35` (x86_64, API 35); **DEV** = physical Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, Android 14 / API 34, arm64-v8a). Hardware/real-media cases prefer **DEV**.

- **TC-AND-190-01 — Detail fetch happy path (contract).** Type: contract/MockWebServer. Target: JVM. Preconditions: MockWebServer enqueues `200` `VideoDetailOut` with all required fields + `hls_manifest_url` + `playback_token` + `status:"ready"`. Steps: call `VideosApi.getVideo("vid_123")`; map DTO→domain. Expected: request path is `/ui/videos/vid_123`; carries cookie, `X-CSRF-Token`, and `Authorization: Bearer`; `durationSeconds` parsed as Double; `publishedAt` parsed from epoch seconds; `playbackUrl == hls_manifest_url + "?token=" + playback_token`. Traces: AC-1, AC-7.
- **TC-AND-190-02 — DTO Moshi mapping incl. nulls/unknown (unit).** Type: unit. Target: JVM. Preconditions: JSON with only the 7 required fields present; extra unknown field included; `duration_seconds`, `hls_manifest_url`, `playback_token`, `published_at` absent. Steps: decode with the Moshi adapter. Expected: optional fields → null; unknown field ignored; no exception; `playbackUrl` resolves to null when manifest/token absent. Traces: AC-1, AC-5.
- **TC-AND-190-03 — ViewModel loading→content (unit).** Type: unit (Turbine). Target: JVM. Preconditions: repo emits `ApiResult.Success(Video)` after Loading. Steps: collect `uiState`. Expected: `isLoading=true` first, then `video != null`, `playbackUrl != null`, `isLoading=false`, no errors. Traces: AC-2, AC-3.
- **TC-AND-190-04 — Cache-first stale fallback (unit).** Type: unit (Turbine). Target: JVM. Preconditions: Room has a cached `Video`; network refresh fails (IOException). Steps: collect `observeVideo`. Expected: cached content emitted, `isStale=true` (and `isOffline=true` when no connectivity), screen not blanked; `video_detail_served_stale` telemetry fires. Traces: AC-4.
- **TC-AND-190-05 — 404 maps to "Video not found" (contract).** Type: contract/MockWebServer. Target: JVM. Preconditions: MockWebServer returns `404` `{"detail":"..."}` and no cache. Steps: load detail. Expected: `detailError` message "Video not found"; metadata-level Retry shown; no backoff retry on 4xx. Traces: AC-4.
- **TC-AND-190-06 — 403 not-entitled (contract).** Type: contract/MockWebServer. Target: JVM. Preconditions: MockWebServer returns `403` (and a geo-block variant `{"detail":{"code":"geo_blocked","message":...}}`). Steps: load detail. Expected: message "You don't have access to this video"; player hidden / no play affordance; geo variant surfaces the region message; no player Retry. Traces: AC-5.
- **TC-AND-190-07 — No playback URL / processing state (unit).** Type: unit. Target: JVM. Preconditions: (a) detail with `hls_manifest_url=null`; (b) detail with `status="encoding"`. Steps: map to UI state. Expected: (a) "This video cannot be played right now", metadata visible, no Retry; (b) "This video is still processing", no play affordance. Traces: AC-5.
- **TC-AND-190-08 — 401 single refresh + replay (contract).** Type: contract/MockWebServer. Target: JVM. Preconditions: first GET → `401`; `/ui/session/refresh` → `200`; replay GET → `200`. Steps: load detail. Expected: exactly one `/ui/session/refresh` POST, exactly one replay, success surfaced; a second consecutive `401` triggers re-auth routing (no infinite loop). Traces: AC-7.
- **TC-AND-190-09 — Loading skeleton then metadata (Compose-UI).** Type: Compose-UI. Target: EMU. Preconditions: fake VM emits Loading then Content. Steps: render `VideoDetailScreen`; assert skeleton + non-interactive player surface, then metadata + enabled play control. Expected: skeleton replaced by title/description/duration/poster; play enabled only when `playbackUrl != null`. Traces: AC-3.
- **TC-AND-190-10 — Detail error Retry invokes reload (Compose-UI).** Type: Compose-UI. Target: EMU. Preconditions: VM in `detailError` state. Steps: assert error + Retry; click Retry. Expected: `retryDetail()`/`load()` invoked; state transitions to Loading. Traces: AC-4.
- **TC-AND-190-11 — Rotation preserves playback position (instrumented).** Type: instrumented. Target: EMU. Preconditions: detail loaded, playback started, position advanced. Steps: trigger configuration change (rotate). Expected: `playbackPositionMs`/`playWhenReady` restored via saved state; player re-prepared at saved position. Traces: AC-6.
- **TC-AND-190-12 — Real HLS playback reaches first frame (e2e, MUST be DEV).** Type: instrumented/e2e. Target: **DEV** (real codec/network; arm64 + API 34 differs from emulator). Preconditions: known-good HLS stream (dev backend or stubbed manifest) with valid `hls_manifest_url`+`playback_token`. Steps: open detail, press play. Expected: player reaches `STATE_READY` and renders first frame; startup `video_playback_started` telemetry fired. **Must run on DEV** (hardware codec/network). Traces: AC-2.
- **TC-AND-190-13 — Lifecycle: pause on background, release on destroy, no leak (instrumented, prefer DEV).** Type: instrumented. Target: **DEV** (real backgrounding / incoming-call behavior; emulator acceptable for basic lifecycle). Preconditions: playback active. Steps: send app to background (and simulate an incoming call on DEV); then destroy the screen. Expected: `pause()` on `ON_PAUSE`, position preserved, `release()` on `ON_DESTROY`, no leaked ExoPlayer (assert via leak check / single-instance assertion); PiP transitions from AND-168 not broken (player not released during PiP). Traces: AC-6.
- **TC-AND-190-14 — Playback error → player Retry re-prepares (instrumented).** Type: instrumented. Target: EMU. Preconditions: feed an unreachable/invalid manifest to force `onPlayerError`. Steps: observe player error UI; tap Retry. Expected: `onPlaybackError` sets `playbackError`; Retry bumps `playbackRetryToken` and re-prepares the `MediaItem`; no infinite auto-retry. Traces: AC-5.
- **TC-AND-190-15 — Security: no secrets in logs (instrumented + JVM).** Type: instrumented + unit. Target: EMU (logcat) + JVM. Preconditions: debug build, playback + network active. Steps: exercise load+play; capture logcat and any structured logs. Expected: no cookies, no `X-CSRF-Token`, no `Authorization` value, no `?token=` query string in any log line (query strings redacted). Traces: AC-7, AC-8.
- **TC-AND-190-16 — Accessibility / TalkBack pass (Compose-UI + manual).** Type: Compose-UI + manual. Target: EMU (automated semantics) + DEV (real TalkBack pass). Preconditions: detail loaded. Steps: assert `contentDescription` on play/Retry/back and player surface ("Video player: <title>"), poster description from title, decorative skeletons `invisibleToUser`, touch targets ≥48dp, font-scale reflow; run a TalkBack sweep on DEV. Expected: all controls labeled and reachable; color not sole error signal. Traces: AC-8.

### Coverage matrix
- **AC-1** (navigate + render from `GET /ui/videos/{video_id}`): TC-01, TC-02, TC-03.
- **AC-2** (a video plays / first frame): TC-03, TC-12.
- **AC-3** (loading skeleton → metadata + enabled play): TC-03, TC-09.
- **AC-4** (detail error Retry + cached/stale render): TC-04, TC-05, TC-10.
- **AC-5** (playback error Retry; no-URL/403/processing messaging): TC-06, TC-07, TC-14.
- **AC-6** (pause on background, release on destroy, rotation preserves position): TC-11, TC-13.
- **AC-7** (authenticated detail + HLS; single 401 refresh+retry): TC-01, TC-08, TC-12, TC-15.
- **AC-8** (no hardcoded strings; TalkBack labels; no secrets in logs): TC-15, TC-16.
