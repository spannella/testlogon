---
id: AND-190
title: Video detail + player
milestone: M4
epic: E26
priority: P1
size: M
status: draft
depends_on: [AND-189, AND-168]
blocks: []
---

# AND-190 — Video detail + player

## 1. Overview & Goal

Deliver the video **detail screen** for the TestLogon native Android app, including a metadata header and inline **HLS playback** of the selected video. A user navigating from the Videos library grid (AND-189) lands on a detail route, sees title/description/runtime/poster metadata fetched from the backend, and can press play to stream the video through the reusable Media3/ExoPlayer player surface delivered in AND-168.

The success bar is concrete: **a video plays from the detail screen.** This ticket owns (a) the `feature-videos` detail route, ViewModel, and Compose UI; (b) the `GET /videos/{id}` detail fetch and its mapping into `core-model`; and (c) wiring the resolved HLS playback URL into the reusable player component. It does **not** re-implement transport controls, fullscreen, or PiP — those belong to AND-168 and are consumed here.

This screen is the first place the unreliable dev backend (plaintext HTTP, ~20s latency) meets streaming media, so resilient loading, stale/offline states, and graceful playback-error recovery are first-class requirements, not afterthoughts.

## 2. Context & References

- **Repo / module:** `spannella/testlogon`, Android app under `android/`, branch `android-port`. Code lands in `feature-videos` (detail screen, ViewModel) with model/data changes in `core-model` and `core-data`/`core-network`.
- **Namespace:** `com.testlogon.android` everywhere a package appears (e.g. `com.testlogon.android.feature.videos.detail`).
- **Upstream deps:**
  - **AND-189 (Videos library):** owns `videos.ts`-equivalent browse/grid and the navigation action that opens this detail route with a `videoId` argument.
  - **AND-168 (Reusable player UI):** owns the `VideoPlayer` composable + `PlayerController` (play/seek/scrub/volume/fullscreen, buffering/error states, PiP). This ticket passes a media URL/`MediaItem` into that component and observes its state; it must not fork or duplicate player controls.
- **Backend:** FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000` (PLAINTEXT HTTP, unreliable). OpenAPI at `/openapi.json`. Web reference under `frontend/` (`frontend/src/api/endpoints/videos.ts`, `frontend/src/api/types.ts`) is the source of truth for field names; confirm the exact detail field set against `/openapi.json` during implementation (see Open Questions).
- **Auth:** cookie-based session (`/ui/session/*`) with `ui_csrf` echoed as `X-CSRF-Token`; persistent cookie jar; one `/ui/session/refresh` retry on 401. The video detail GET and the HLS manifest request both ride this authenticated session.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, single-Activity Navigation-Compose, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Media3/ExoPlayer 1.4 (HLS), Coil, Room 2.6, DataStore. minSdk 24 / target 35, JDK 17, AGP 8.7.3, Gradle 8.9.

## 3. Functional Requirements

1. **Route & navigation.** A typed route `videos/detail/{videoId}` is reachable from the library grid. The screen reads `videoId: String` from `SavedStateHandle`.
2. **Metadata display.** On entry the screen fetches video detail and renders: poster/thumbnail (Coil), title, description, duration (formatted `H:MM:SS` / `M:SS`), and any available secondary metadata (publish date, view count, tags) when present in the payload.
3. **Loading state.** While the detail request is in flight, show a skeleton/placeholder for the metadata block and a non-interactive player surface (poster + disabled play affordance).
4. **Playback start.** A play control on the player surface begins HLS streaming using the resolved playback URL. Playback uses the AND-168 `VideoPlayer`; this screen supplies the `MediaItem` and lifecycle ownership only.
5. **Player lifecycle.** The player is created when detail (and thus playback URL) is available, paused on `ON_PAUSE`, and released on `ON_DESTROY` / when navigating away. Playback position survives configuration change (rotation) via saved state.
6. **Error states.** Distinct, recoverable UI for: detail-fetch failure (Retry), no playback URL available (message, no Retry on player), and playback/streaming failure surfaced by the player (Retry re-prepares the `MediaItem`).
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
ExoPlayer is built with an `OkHttpDataSource.Factory` wired to the **shared authenticated OkHttp client** (same cookie jar + CSRF interceptor) so the HLS manifest/segment requests carry the session. The `HlsMediaSource.Factory` is used for `application/vnd.apple.mpegurl` URLs.

### Lifecycle
`LifecycleEventObserver` registered via `DisposableEffect`: `ON_PAUSE` → `pause()`; `ON_DESTROY` → `release()`. Position saved via `rememberSaveable` (`playbackPositionMs`, `playWhenReady`) and restored after `prepare()`.

## 5. API Contract

### Detail fetch
`GET /videos/{id}` — authenticated (cookies + `X-CSRF-Token`). Idempotent: eligible for bounded backoff retry on transient failures.

Retrofit:
```kotlin
interface VideosApi {
    @GET("videos/{id}")
    suspend fun getVideo(@Path("id") id: String): VideoDetailDto
}
```

Expected 200 response (field names to be confirmed against `/openapi.json` / `frontend/src/api/types.ts`):
```json
{
  "id": "vid_123",
  "title": "Intro to TestLogon",
  "description": "Walkthrough of the login flow.",
  "duration_seconds": 372,
  "thumbnail_url": "https://.../poster.jpg",
  "playback_url": "https://.../vid_123/master.m3u8",
  "published_at": "2026-05-01T12:00:00Z",
  "view_count": 1042,
  "tags": ["auth", "demo"]
}
```

DTO + mapping:
```kotlin
@JsonClass(generateAdapter = true)
data class VideoDetailDto(
    val id: String,
    val title: String,
    val description: String?,
    @Json(name = "duration_seconds") val durationSeconds: Int?,
    @Json(name = "thumbnail_url") val thumbnailUrl: String?,
    @Json(name = "playback_url") val playbackUrl: String?,
    @Json(name = "published_at") val publishedAt: String?,
    @Json(name = "view_count") val viewCount: Long?,
    val tags: List<String>?,
)
fun VideoDetailDto.toDomain(): Video = Video(/* ... */)
```

**Playback URL resolution:** prefer `playback_url` from the detail payload. If the backend instead exposes a separate manifest endpoint (e.g. `GET /videos/{id}/stream` returning `{ "playback_url": "..." }` or a redirect), `VideoRepository` resolves it lazily on play; this branch is gated behind the OpenAPI confirmation in Open Questions.

**Error mapping:** FastAPI `detail` (string | `[{msg}]` | `{code,...}`) is normalized by the existing `core-network` error mapper into `ApiResult.Error(message, code)`. `404` → "Video not available". `401` → triggers the single `/ui/session/refresh` + retry handled by the auth interceptor.

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
    val id: String,
    val title: String,
    val description: String?,
    val durationSeconds: Int?,
    val thumbnailUrl: String?,
    val playbackUrl: String?,
    val publishedAt: Instant?,
    val viewCount: Long?,
    val tags: List<String>,
)
```

### Cache (`core-data`, Room 2.6)
`VideoEntity` keyed by `id` (reuse/extend the entity introduced for AND-189's library list; add detail-only columns such as `description`, `playback_url`, `published_at`). Cache-first read provides instant render + stale fallback. No new DataStore prefs are required for this ticket; playback position is transient (saved instance state only, not persisted).

State emission: `repository.observeVideo(id)` → ViewModel maps `ApiResult<Video>` into `VideoDetailUiState`, setting `isStale`/`isOffline` when emitting cached data after a network failure.

## 7. Error Handling & Resilience

- **Detail GET (idempotent):** ~20s OkHttp timeout; bounded exponential backoff (e.g. 3 attempts, 500ms→2s, jittered) for transient `IOException`/`5xx`/timeout only — never for `4xx`. Implemented in the shared network layer; this ticket relies on it.
- **Cache-first:** cached detail renders immediately; a failed refresh keeps cached content with `isStale = true` and a subtle banner rather than blanking the screen.
- **Offline:** if no connectivity and no cache → full-screen error with Retry. If cache present → render with offline banner; play disabled when the manifest is unreachable.
- **Playback failure:** ExoPlayer `Player.Listener.onPlayerError(PlaybackException)` → `VideoDetailViewModel.onPlaybackError`. Map common codes (e.g. `ERROR_CODE_IO_*`, `ERROR_CODE_BEHIND_LIVE_WINDOW`) to a friendly message; "Retry" re-prepares via `playbackRetryToken`. Avoid infinite auto-retry loops.
- **No playback URL:** show "This video cannot be played right now"; metadata still visible; no player Retry.
- **401 mid-session:** auth interceptor performs one `/ui/session/refresh` then retries; if it still fails, surface a re-auth prompt routed to the session flow.

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

1. **Playback URL shape (OQ):** Is the HLS URL inline in `GET /videos/{id}` (`playback_url`) or via a separate stream/signed-URL endpoint? Confirm against `/openapi.json` and `frontend/src/api/endpoints/videos.ts`. Resolution may add a lazy URL-fetch branch in the repository.
2. **Field names (OQ):** Exact detail field names/types (`duration_seconds` vs `durationMs`, presence of `view_count`/`tags`) must be confirmed; DTO above is provisional.
3. **Authenticated segments:** HLS segment requests must carry session cookies; risk if the CDN/manifest host differs from the API host (cookie scope mismatch). Verify segment host vs cookie domain.
4. **Cleartext dev streaming:** plaintext HTTP HLS on the dev host requires scoped cleartext config; ensure prod path is HTTPS-only.
5. **Unreliable backend:** ~20s latency may cause perceived hangs before playback; startup timeout + clear buffering UI (from AND-168) mitigate.
6. **PiP interplay:** ensure this screen's lifecycle handling does not conflict with AND-168's PiP transitions (don't release the player during PiP).

## 14. Acceptance Criteria

1. Navigating from the videos library (AND-189) opens `videos/detail/{videoId}` and renders title, description, duration, and poster from `GET /videos/{id}`.
2. **A video plays from the detail screen** — pressing play streams the HLS source and reaches first-frame/`STATE_READY` against the dev backend (or stubbed manifest in CI).
3. While detail loads, a skeleton + non-interactive player surface is shown; on success it is replaced by metadata + an enabled play control.
4. Detail-fetch failure shows an inline error with a working Retry; cached detail (when present) renders immediately with a stale/offline indicator on refresh failure.
5. Playback errors surface a player-level message with Retry that re-prepares the media item; no playback URL → metadata-only with a clear message and no Retry.
6. Player is paused on background and released on destroy with no leaked instances; playback position survives rotation.
7. The detail GET and HLS requests are authenticated (cookies + `X-CSRF-Token`); a 401 triggers exactly one refresh+retry.
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
