---
id: AND-189
title: Videos library
milestone: M4
epic: E26
priority: P1
size: M
status: draft
depends_on: [AND-027, AND-103]
blocks: [AND-190]
---

# AND-189 — Videos library

## 1. Overview & Goal

Deliver the Videos library: a browsable, paginated grid of video entries that mirrors the web reference module `videos.ts`. The screen lets an authenticated user scroll a catalog of videos rendered as poster/thumbnail tiles and tap any tile to open its detail screen. This ticket owns the list/browse surface only — the grid, its data layer (`VideosApi`, `VideosRepository`, `VideosViewModel`), paging, thumbnail loading, and navigation handoff into video detail. Playback, the detail screen body, and player chrome are out of scope and are owned by the Media foundation tickets (AND-166/AND-167/AND-168) and the downstream video-detail ticket (AND-190).

Success means: when a signed-in user opens the Videos tab, a grid of video thumbnails renders from `GET /videos`, pages load on scroll, loading/empty/error/offline states are correct, and tapping a tile navigates to `videos/detail/{videoId}` with the selected id.

## 2. Context & References

- Module: `feature-videos` (new), layered `app -> feature-videos -> core-*`. Consumes `core-network`, `core-model`, `core-ui`, `core-data`, `core-testing`.
- Namespace / applicationId base: `com.testlogon.android`. Feature package: `com.testlogon.android.feature.videos`.
- Web reference module: `frontend/src/api/endpoints/videos.ts` (browse/grid) and shared types in `frontend/src/api/types.ts`. The Android `VideoSummary`/`VideoListResponse` shapes are ported from those types.
- Backend: FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext, unreliable). OpenAPI at `/openapi.json`. Cookie-based auth with `X-CSRF-Token` echo and single 401 refresh-retry are provided transparently by the `core-network` OkHttp stack (cookie jar AND-011, CSRF interceptor AND-012, 401 authenticator AND-013, idempotent-GET retry/backoff AND-016).
- Dependencies:
  - **AND-027 (AuthApi / session endpoints)** — establishes the authenticated session and the shared Retrofit/OkHttp stack this feature's `VideosApi` is built on. Required so `GET /videos` is sent with a valid session cookie + CSRF header.
  - **AND-103 (Feed media thumbnails)** — provides the Coil image-loading conventions (placeholders, aspect handling, data-saver respect, scroll cancellation) reused by the grid tiles.
- Reused building blocks: `ApiResult<T>` (AND-018), FastAPI `detail` error mapping (AND-015), state composables Loading/Empty/Error/Offline (AND-021), Navigation host & routes (AND-022), authenticated nav graph (AND-024), Paging 3.

## 3. Functional Requirements

FR-1. A `VideosScreen` composable renders a vertically scrolling grid (`LazyVerticalGrid`) of video tiles. Default span count: 2 in portrait, 3 in landscape/`WindowWidthSizeClass.Expanded`.
FR-2. Each tile shows the video thumbnail (Coil), title (max 2 lines, ellipsized), and a duration badge overlaid bottom-right when `durationSec` is present.
FR-3. The list is paged via Paging 3 (`Pager` + `PagingSource`/`RemoteMediator`-free network `PagingSource`). Next page loads automatically as the user nears the end of the grid.
FR-4. Initial load shows a full-screen loading state; subsequent page loads show an in-grid footer spinner.
FR-5. Empty result (zero videos) renders the shared Empty state with copy "No videos yet".
FR-6. Tapping a tile invokes `onOpenVideo(videoId: String)` which navigates to route `videos/detail/{videoId}`.
FR-7. Pull-to-refresh (Material 3 `PullToRefreshBox`) re-fetches page 1 and invalidates the pager.
FR-8. Error on initial load shows the shared Error state with a Retry action; error on append shows an inline retry footer.
FR-9. Offline / backend-unreachable on initial load shows the shared Offline state; if cached data exists it is shown with a stale banner (delegated to cache hooks where available; otherwise Offline state).
FR-10. The screen is reachable from the authenticated nav graph (entry registered, but the bottom-nav slot decision is owned by AND-024; this ticket registers the `videos` route and detail route).

## 4. Technical Design

### Module & package layout
```
feature-videos/
  src/main/kotlin/com/testlogon/android/feature/videos/
    data/    VideosApi.kt, VideosRepository.kt, VideosPagingSource.kt, dto/VideoDto.kt
    domain/  VideoSummary.kt
    ui/      VideosScreen.kt, VideoTile.kt, VideosViewModel.kt, VideosUiState.kt
    nav/     VideosNavigation.kt
```

### Retrofit API
```kotlin
interface VideosApi {
    @GET("videos")
    suspend fun listVideos(
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int = 24,
        @Query("sort") sort: String? = null,   // e.g. "recent"
    ): Response<VideoListResponse>
}
```

### DTOs (Moshi)
```kotlin
@JsonClass(generateAdapter = true)
data class VideoListResponse(
    @Json(name = "items") val items: List<VideoDto>,
    @Json(name = "next_cursor") val nextCursor: String? = null,
    @Json(name = "total") val total: Int? = null,
)

@JsonClass(generateAdapter = true)
data class VideoDto(
    @Json(name = "id") val id: String,
    @Json(name = "title") val title: String?,
    @Json(name = "thumbnail_url") val thumbnailUrl: String?,
    @Json(name = "duration_sec") val durationSec: Int? = null,
    @Json(name = "is_locked") val isLocked: Boolean = false,
    @Json(name = "view_count") val viewCount: Int? = null,
    @Json(name = "created_at") val createdAt: String? = null,
)
```

### Domain model & mapper
```kotlin
data class VideoSummary(
    val id: String,
    val title: String,
    val thumbnailUrl: String?,
    val durationSec: Int?,
    val isLocked: Boolean,
)

fun VideoDto.toDomain(): VideoSummary = VideoSummary(
    id = id,
    title = title.orEmpty(),
    thumbnailUrl = thumbnailUrl,
    durationSec = durationSec,
    isLocked = isLocked,
)
```

### PagingSource (cursor-based)
```kotlin
class VideosPagingSource(
    private val api: VideosApi,
    private val sort: String?,
) : PagingSource<String, VideoSummary>() {

    override suspend fun load(
        params: LoadParams<String>
    ): LoadResult<String, VideoSummary> = try {
        val resp = api.listVideos(
            cursor = params.key,
            limit = params.loadSize.coerceAtMost(48),
            sort = sort,
        )
        if (!resp.isSuccessful) {
            LoadResult.Error(HttpStatusException(resp.code()))
        } else {
            val body = resp.body() ?: VideoListResponse(emptyList())
            LoadResult.Page(
                data = body.items.map { it.toDomain() },
                prevKey = null,
                nextKey = body.nextCursor,
            )
        }
    } catch (e: IOException) {
        LoadResult.Error(e)
    }

    override fun getRefreshKey(state: PagingState<String, VideoSummary>): String? = null
}
```

### Repository
```kotlin
class VideosRepository @Inject constructor(
    private val api: VideosApi,
) {
    fun pagedVideos(sort: String? = null): Flow<PagingData<VideoSummary>> =
        Pager(
            config = PagingConfig(
                pageSize = 24,
                prefetchDistance = 8,
                initialLoadSize = 24,
                enablePlaceholders = false,
            ),
            pagingSourceFactory = { VideosPagingSource(api, sort) },
        ).flow
}
```

### ViewModel
```kotlin
@HiltViewModel
class VideosViewModel @Inject constructor(
    private val repository: VideosRepository,
) : ViewModel() {
    private val sort = MutableStateFlow<String?>(null)

    val videos: Flow<PagingData<VideoSummary>> =
        sort.flatMapLatest { repository.pagedVideos(it) }
            .cachedIn(viewModelScope)
}
```
The grid consumes `videos.collectAsLazyPagingItems()`; the `LoadState` exposed by `LazyPagingItems.loadState` drives the Loading/Empty/Error/Offline mapping in section 7. No separate `StateFlow<UiState>` is required because Paging 3 owns list state; a thin `VideosUiState` (sealed) is still provided for non-list errors (e.g., refresh failures surfaced to a snackbar).

### Compose UI
```kotlin
@Composable
fun VideosScreen(
    onOpenVideo: (videoId: String) -> Unit,
    viewModel: VideosViewModel = hiltViewModel(),
)

@Composable
private fun VideoTile(
    video: VideoSummary,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
)
```
`VideoTile` uses Coil `AsyncImage` with placeholder/error drawables and `contentScale = ContentScale.Crop`, a 16:9 aspect ratio box, the title below, and a duration badge formatted `mm:ss` / `h:mm:ss`. Thumbnail loading follows AND-103 conventions including data-saver respect and request cancellation on scroll (handled by Coil + Paging recycling).

### Navigation
```kotlin
object VideosRoutes {
    const val LIBRARY = "videos"
    const val DETAIL = "videos/detail/{videoId}"
    fun detail(videoId: String) = "videos/detail/$videoId"
}

fun NavGraphBuilder.videosGraph(navController: NavController) {
    composable(VideosRoutes.LIBRARY) {
        VideosScreen(onOpenVideo = { id -> navController.navigate(VideosRoutes.detail(id)) })
    }
    // videos/detail composable destination registered here is a stub owned by AND-190.
}
```

## 5. API Contract

Primary endpoint (browse/grid):

`GET /videos?cursor={cursor}&limit={limit}&sort={sort}`

Auth: session cookie + `X-CSRF-Token` header (injected by core-network). Idempotent GET — eligible for bounded backoff retry (AND-016) with ~20s timeout.

Success `200`:
```json
{
  "items": [
    {
      "id": "vid_01HZX...",
      "title": "Intro to TestLogon",
      "thumbnail_url": "https://cdn.example/v/01hzx/poster.jpg",
      "duration_sec": 372,
      "is_locked": false,
      "view_count": 1420,
      "created_at": "2026-05-01T12:00:00Z"
    }
  ],
  "next_cursor": "eyJwayI6...",
  "total": 137
}
```
- `next_cursor` is `null`/absent on the final page (terminal append).
- `items` may be empty array → Empty state.

Error `401`: triggers the core-network authenticator (single `POST /ui/session/refresh` then one retry). If refresh fails, propagates as auth error → routed to login by auth-gated routing (AND-025).

Error `4xx/5xx`: body conforms to FastAPI `detail` which is mapped by AND-015's mapper to a user-facing message:
```json
{ "detail": "Not found" }
{ "detail": [ { "msg": "value_error", "loc": ["query","limit"] } ] }
{ "detail": { "code": "rate_limited" } }
```

Exact path, query parameter names, and field names must be reconciled against `/openapi.json` and `frontend/src/api/endpoints/videos.ts` before merge; if the backend uses offset paging (`page`/`page_size`) instead of cursor, swap the `PagingSource` key type to `Int` accordingly. This is the only open contract question (see section 13).

## 6. Data & State Management

- Network → `VideoListResponse`/`VideoDto` (Moshi) → `VideoSummary` (domain) → `LazyPagingItems<VideoSummary>` in UI. Paging 3 holds list state; `cachedIn(viewModelScope)` survives configuration changes.
- No bespoke persistence in this ticket. Disk caching of the grid for offline/stale is delegated to the cache-repository SWR pattern (AND-116/AND-117) when that lands; until then, offline = Offline state with no rows. A `// TODO(AND-116): wire Room-backed RemoteMediator` marker is left in `VideosRepository`.
- Coil supplies in-memory + disk thumbnail caching; no Room rows are written by this ticket.
- Sort selection (`sort: String?`) is held in a `MutableStateFlow` in the ViewModel; changing it re-creates the pager via `flatMapLatest`. Default `null` (server default order).
- Span count derives from `WindowWidthSizeClass` (Material 3 adaptive), not persisted.

## 7. Error Handling & Resilience

Map `LazyPagingItems.loadState` to shared state composables (AND-021):

| Condition | Detection | UI |
|---|---|---|
| Initial load | `loadState.refresh is LoadState.Loading` | Full-screen `LoadingState` |
| Empty | `refresh is NotLoading` && `itemCount == 0` | `EmptyState("No videos yet")` |
| Initial network/timeout error (IOException) | `refresh is LoadState.Error` && error is `IOException` | `OfflineState` + Retry → `retry()` |
| Initial HTTP error | `refresh is LoadState.Error` && `HttpStatusException` | `ErrorState(mappedDetail)` + Retry → `retry()` |
| Append loading | `append is LoadState.Loading` | footer spinner item |
| Append error | `append is LoadState.Error` | inline footer "Couldn't load more" + Retry → `retry()` |

- Timeouts: 20s (core-network default). Idempotent GET retried with bounded backoff (AND-016) before surfacing an error.
- 401: handled transparently by the authenticator; one refresh + retry, then auth error.
- Pull-to-refresh maps failures to a non-blocking snackbar while keeping existing rows.
- All `LoadResult.Error` carries the original throwable so the mapper can distinguish transport vs HTTP vs validation.

## 8. Security & Privacy

- All requests ride the authenticated cookie jar; no tokens are logged. `VideosApi` adds no auth headers itself — it relies on the shared OkHttp stack (cookies + `X-CSRF-Token`).
- `thumbnail_url` may be a signed CDN URL; do not log full URLs at info level (truncate query string in telemetry, section 10).
- `is_locked` videos still render a tile (poster + lock affordance) but the detail/playback gating (paywall/entitlement) is enforced downstream (AND-177/AND-101 patterns, AND-190). This ticket must pass `isLocked` through so detail can gate.
- No PII is collected or stored by this screen. Dev backend is plaintext HTTP; cleartext is permitted only for the dev flavor's base URL (per AND-006 network-security-config), not release.

## 9. Accessibility & i18n

- Every `VideoTile` has a `contentDescription` = title (and ", locked" suffix when `isLocked`); decorative duration badge text is included in the tile semantics, not a separate focus stop.
- Touch targets ≥ 48dp; tile click target spans the full tile.
- Grid supports TalkBack linear traversal in row-major order; the append spinner has `contentDescription = "Loading more videos"`.
- All user-visible strings (`No videos yet`, `Retry`, `Couldn't load more`, `Loading more videos`) live in `feature-videos` `strings.xml` and route through the i18n plumbing (AND-111). Duration formatting uses locale-aware number formatting; layout is RTL-safe (badge uses start/end, not left/right).
- Respects system font scaling (titles use `bodyMedium`, no fixed sp where avoidable) and `Theme` from AND-019.

## 10. Telemetry & Logging

- Log via the shared redacting logger. Events:
  - `videos_library_opened`
  - `videos_page_loaded` { page_index, item_count, duration_ms }
  - `videos_load_error` { stage: refresh|append, kind: io|http|validation, http_status? }
  - `video_tile_tapped` { video_id, position }
- Thumbnail URLs are logged host+path only (query string stripped). No cookies, CSRF tokens, or signed query params in any log line.
- Network call timing is captured by the OkHttp logging interceptor (AND-009) at BODY level in dev, BASIC in release.

## 11. Testing Strategy

Unit / repository (core-testing + MockWebServer harness AND-046):
- `VideosApi` path/verb/query test: asserts request line `GET /videos?limit=24` (and with cursor/sort) — MockWebServer.
- `VideoDto.toDomain()` mapping incl. null title → empty string, missing `duration_sec` → null.
- `VideosPagingSource.load`: first page returns `Page` with `nextKey = next_cursor`; terminal page returns `nextKey = null`; HTTP 500 returns `LoadResult.Error`; IOException returns `LoadResult.Error`.
- `VideosRepository.pagedVideos` emits expected `PagingData` (AsyncPagingDataDiffer snapshot).
- `detail` error mapping reuse test for 404/422 bodies (AND-015).

Compose UI (instrumented, AND-051):
- Grid renders N tiles from a fake pager; titles + duration badges present.
- Empty response → Empty state visible.
- Error refresh → Error/Offline state + Retry button; tapping Retry calls `retry()`.
- Tapping a tile invokes `onOpenVideo` with the correct id (verified via test nav/lambda).
- Append spinner shown while appending.

Acceptance gate: a deterministic MockWebServer fixture (`videos_page1.json`, `videos_page2.json`, `videos_empty.json`) drives the "Library renders + opens detail" acceptance.

## 12. Dependencies & Sequencing

- **Hard deps (must land first):** AND-027 (AuthApi/session stack so authenticated `GET /videos` works), AND-103 (Coil thumbnail conventions). Transitively requires core-network stack AND-009..AND-018, theme AND-019, state composables AND-021, nav host AND-022/AND-024, and Paging 3 wiring.
- **Soft deps (graceful-degradation TODOs, not blockers):** AND-116/AND-117 (offline/SWR cache for stale grid), AND-006 (dev cleartext base URL config).
- **Blocks:** AND-190 (video detail screen) consumes the `videos/detail/{videoId}` route and `videoId` arg defined here; AND-166/AND-167/AND-168 (player) are reached through that detail screen.
- Sequence: API+DTO+mapper → PagingSource+Repository → ViewModel → Screen/Tile → nav registration → tests.

## 13. Risks & Open Questions

- **R1 (contract): pagination shape.** Cursor (`next_cursor`) is assumed; backend may use offset (`page`/`page_size`). Resolve against `/openapi.json` and `videos.ts` before merge; isolated to `VideosPagingSource` key type + query params.
- **R2: field names.** `thumbnail_url`, `duration_sec`, `is_locked` are assumed snake_case; confirm against OpenAPI. Adapters localize any change.
- **R3: unreliable dev host.** 20s timeouts + retry mean slow first paint; mitigated by skeleton loading and bounded backoff. Acceptance fixtures use MockWebServer so CI is deterministic.
- **R4: locked content rendering.** Whether locked videos appear in the library list or are filtered server-side is unconfirmed; default is to render with a lock badge and gate at detail.
- **Open Q1:** Does `/videos` require any default `sort`, or is server order stable enough for paging without it?
- **Open Q2:** Is there a separate "my videos" vs "all videos" scope, or a single feed? Assumed single feed for this ticket.

## 14. Acceptance Criteria

AC-1. Opening the Videos route renders a grid of video thumbnails from `GET /videos` (2 columns portrait, 3 expanded). *(Satisfies backlog "Library renders".)*
AC-2. Scrolling past the prefetch threshold loads the next page via `next_cursor`; the terminal page stops appending with no error.
AC-3. Tapping any tile navigates to `videos/detail/{videoId}` passing the correct `videoId`. *(Satisfies backlog "opens detail".)*
AC-4. Loading, Empty ("No videos yet"), Error+Retry, Offline, and append-error+retry states each render under their conditions (verified by tests in section 11).
AC-5. Thumbnails load with placeholders and are cancelled on scroll/recycle per AND-103.
AC-6. `VideosApi` request line, verb, and query params match the verified contract (MockWebServer test green).
AC-7. No cookies, CSRF tokens, or signed thumbnail query strings appear in logs.
AC-8. All listed unit and Compose UI tests pass in CI.

## 15. Definition of Done

- `feature-videos` module created under `com.testlogon.android.feature.videos`, wired into the authenticated nav graph; `videos` route resolves and `videos/detail/{videoId}` route is registered (detail body stub deferred to AND-190).
- `VideosApi`, `VideoDto`/`VideoListResponse`, `VideoSummary` + mapper, `VideosPagingSource`, `VideosRepository`, `VideosViewModel`, `VideosScreen`, `VideoTile` implemented as specified and provided via Hilt (KSP).
- All acceptance criteria (section 14) met; unit + Compose UI tests (section 11) added and green on CI (AND-050/AND-051).
- Lint/detekt/ktlint clean (AND-005); no new cleartext-traffic exposure in release; strings externalized for i18n.
- Telemetry events emitted with redaction verified.
- Contract assumptions (R1/R2) reconciled against `/openapi.json` and `videos.ts`, or documented as a follow-up if the endpoint is not yet final.
- Code reviewed and merged to `android-port`.
