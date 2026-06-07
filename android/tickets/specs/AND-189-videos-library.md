---
id: AND-189
title: Videos library
milestone: M4
epic: E26
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-027, AND-103]
blocks: [AND-190]
---

# AND-189 — Videos library

## 1. Overview & Goal

Deliver the Videos library: a browsable, paginated grid of video entries that mirrors the web reference module `videos.ts`. The screen lets an authenticated user scroll a catalog of videos rendered as poster/thumbnail tiles and tap any tile to open its detail screen. This ticket owns the list/browse surface only — the grid, its data layer (`VideosApi`, `VideosRepository`, `VideosViewModel`), paging, thumbnail loading, and navigation handoff into video detail. Playback, the detail screen body, and player chrome are out of scope and are owned by the Media foundation tickets (AND-166/AND-167/AND-168) and the downstream video-detail ticket (AND-190).

Success means: when a signed-in user opens the Videos tab, a grid of video thumbnails renders from `GET /ui/videos`, pages load on scroll, loading/empty/error/offline states are correct, and tapping a tile navigates to `videos/detail/{videoId}` with the selected id.

> **Reviewer note (scope clarification):** The verified backend endpoint `GET /ui/videos` is described in OpenAPI as *"List the caller's own videos (paginated, filterable)."* The web reference call `listMyVideos` (`src/api/endpoints/videos.ts`) targets exactly this endpoint. So the "library" surface in this ticket is the caller's **own** videos list. There is **no** public `GET /videos` endpoint. If a public/all-videos browse grid is intended instead, the correct endpoints are `GET /ui/videos/public` (`VideoListOut`) or `GET /ui/videos/gallery` (`GalleryListOut`); see §16 Open assumptions. This spec is written against `GET /ui/videos`, matching the web `videos.ts` browse call.

## 2. Context & References

- Module: `feature-videos` (new), layered `app -> feature-videos -> core-*`. Consumes `core-network`, `core-model`, `core-ui`, `core-data`, `core-testing`.
- Namespace / applicationId base: `com.testlogon.android`. Feature package: `com.testlogon.android.feature.videos`.
- Web reference module: `src/api/endpoints/videos.ts` — the browse/grid call is `listMyVideos` → `GET /ui/videos`. DTO types (`VideoListItem`, `VideoListResponse`) are defined inline in that file (NOT in `src/api/types.ts`). The Android `VideoSummary`/`VideoListResponse` shapes are ported from `videos.ts`.
- Backend: FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext, unreliable). OpenAPI at `/openapi.json`. Auth (verified against `src/api/client.ts`): the web client sends `credentials: "include"` (cookies) **and** an `Authorization: Bearer <accessToken>` header from its auth store, plus the `X-CSRF-Token` header read from the `ui_csrf` cookie; on a 401 it refreshes once via `POST /ui/session/refresh` and retries the original request once. The Android `core-network` OkHttp stack provides the equivalent transparently (cookie jar AND-011, CSRF interceptor AND-012 — note the CSRF source cookie is `ui_csrf`, 401 authenticator AND-013 → `POST /ui/session/refresh`, idempotent-GET retry/backoff AND-016). Whether the Android client mirrors the web `Authorization: Bearer` header or relies solely on the session cookie is an AND-027 decision (see §16 Open assumptions).
- Dependencies:
  - **AND-027 (AuthApi / session endpoints)** — establishes the authenticated session and the shared Retrofit/OkHttp stack this feature's `VideosApi` is built on. Required so `GET /ui/videos` is sent with a valid session cookie + CSRF header (and, if mirroring web, the `Authorization: Bearer` header).
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
    // CORRECTED: path is "ui/videos" (the web `listMyVideos` browse call), not "videos".
    // CORRECTED: no `sort` query param exists on this endpoint. Supported query params per
    //   OpenAPI are limit, cursor, status, visibility (plus infra-injected user_sub/headers).
    // CORRECTED: server `limit` default is 50 (min 1, max 200); we pass an explicit page size.
    @GET("ui/videos")
    suspend fun listVideos(
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int = 24,        // app page size; server default 50, max 200
        @Query("status") status: String? = null,
        @Query("visibility") visibility: String? = null,
    ): Response<VideoListResponse>
}
```

### DTOs (Moshi)
```kotlin
// CORRECTED to match VideoListOut / VideoListItem (OpenAPI + src/api/endpoints/videos.ts):
//   - pagination field is `cursor` (NOT `next_cursor`); there is NO `total` field.
//   - item id field is `video_id` (NOT `id`); `title` is REQUIRED (non-null) by contract.
//   - duration field is `duration_seconds` and is a NUMBER (float, e.g. 372.0), not `duration_sec` Int.
//   - `created_at`/`updated_at` are epoch SECONDS as integers (NOT ISO-8601 strings).
//   - there is NO `is_locked` and NO `view_count` field on this endpoint (see §16 / R4).
@JsonClass(generateAdapter = true)
data class VideoListResponse(
    @Json(name = "items") val items: List<VideoDto>,
    @Json(name = "cursor") val cursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class VideoDto(
    @Json(name = "video_id") val videoId: String,
    @Json(name = "title") val title: String,
    @Json(name = "status") val status: String,
    @Json(name = "visibility") val visibility: String,
    @Json(name = "created_at") val createdAt: Long,      // epoch seconds
    @Json(name = "updated_at") val updatedAt: Long,      // epoch seconds
    @Json(name = "thumbnail_url") val thumbnailUrl: String? = null,
    @Json(name = "duration_seconds") val durationSeconds: Double? = null,
    @Json(name = "width") val width: Int? = null,
    @Json(name = "height") val height: Int? = null,
    @Json(name = "file_size_bytes") val fileSizeBytes: Long? = null,
    @Json(name = "review_status") val reviewStatus: String? = null,
    @Json(name = "owner_user_id") val ownerUserId: String? = null,
)
```

### Domain model & mapper
```kotlin
data class VideoSummary(
    val id: String,
    val title: String,
    val thumbnailUrl: String?,
    val durationSec: Int?,          // rounded from duration_seconds for the mm:ss badge
    val isLocked: Boolean,          // NOTE: not provided by GET /ui/videos; derived locally
)

// CORRECTED: source fields are video_id / duration_seconds (Double). There is no
// is_locked on this endpoint; gating belongs to the detail/access endpoints
// (GET /ui/videos/{video_id}/access -> VodAccessOut, and VideoDetailOut.is_entitled,
// access_mode, access_reason). For the list tile we default isLocked = false and let the
// detail screen (AND-190) resolve entitlement. `title` is required by contract so no
// null-coalescing is strictly needed, but we keep orEmpty() as a defensive guard.
fun VideoDto.toDomain(): VideoSummary = VideoSummary(
    id = videoId,
    title = title,
    thumbnailUrl = thumbnailUrl,
    durationSec = durationSeconds?.roundToInt(),
    isLocked = false,
)
```

### PagingSource (cursor-based)
```kotlin
class VideosPagingSource(
    private val api: VideosApi,
    private val status: String? = null,
    private val visibility: String? = null,
) : PagingSource<String, VideoSummary>() {

    override suspend fun load(
        params: LoadParams<String>
    ): LoadResult<String, VideoSummary> = try {
        val resp = api.listVideos(
            cursor = params.key,
            limit = params.loadSize.coerceAtMost(200),  // server hard max is 200
            status = status,
            visibility = visibility,
        )
        if (!resp.isSuccessful) {
            LoadResult.Error(HttpStatusException(resp.code()))
        } else {
            val body = resp.body() ?: VideoListResponse(emptyList())
            LoadResult.Page(
                data = body.items.map { it.toDomain() },
                prevKey = null,
                nextKey = body.cursor,   // CORRECTED: response field is `cursor`
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
    // CORRECTED: filter is by `status`/`visibility` (real query params), not a non-existent `sort`.
    fun pagedVideos(status: String? = null, visibility: String? = null): Flow<PagingData<VideoSummary>> =
        Pager(
            config = PagingConfig(
                pageSize = 24,
                prefetchDistance = 8,
                initialLoadSize = 24,
                enablePlaceholders = false,
            ),
            pagingSourceFactory = { VideosPagingSource(api, status, visibility) },
        ).flow
}
```

### ViewModel
```kotlin
@HiltViewModel
class VideosViewModel @Inject constructor(
    private val repository: VideosRepository,
) : ViewModel() {
    // CORRECTED: was `sort` (no such param); the endpoint supports status/visibility filters.
    private val filter = MutableStateFlow<String?>(null)   // null = server default order/scope

    val videos: Flow<PagingData<VideoSummary>> =
        filter.flatMapLatest { repository.pagedVideos(status = it) }
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

Primary endpoint (browse/grid) — **VERIFIED** against OpenAPI `GET /ui/videos` (op `list_own_videos_ui_videos_get`, resp `200:VideoListOut`) and `src/api/endpoints/videos.ts: listMyVideos`:

`GET /ui/videos?cursor={cursor}&limit={limit}&status={status}&visibility={visibility}`

> **CORRECTIONS:** path is `/ui/videos` (not `/videos`); there is no `sort` query param (supported: `limit`, `cursor`, `status`, `visibility`, plus infra-injected `user_sub` + `X-SESSION-ID`/`X-IMPERSONATION-TOKEN` headers); `limit` server default is **50**, min 1, max **200** (not 24/48). This endpoint lists the **caller's own** videos.

Auth: session cookie + `X-CSRF-Token` header (sourced from the `ui_csrf` cookie) — injected by core-network; web additionally sends `Authorization: Bearer`. Idempotent GET — eligible for bounded backoff retry (AND-016) with ~20s timeout.

Success `200` (schema `VideoListOut`, items `VideoListItem`):
```json
{
  "items": [
    {
      "video_id": "vid_01HZX...",
      "title": "Intro to TestLogon",
      "status": "ready",
      "visibility": "public",
      "created_at": 1746100800,
      "updated_at": 1746100800,
      "thumbnail_url": "https://cdn.example/v/01hzx/poster.jpg",
      "duration_seconds": 372.0,
      "width": 1920,
      "height": 1080,
      "file_size_bytes": 88123456,
      "review_status": "approved",
      "owner_user_id": "usr_01..."
    }
  ],
  "cursor": "eyJwayI6..."
}
```
- **CORRECTED field shapes:** id field is `video_id`; pagination field is `cursor` (NOT `next_cursor`); there is **NO** `total` field; `duration_seconds` is a number (float); `created_at`/`updated_at` are epoch-second integers; required fields are `video_id`, `title`, `status`, `visibility`, `created_at`, `updated_at`; there is **NO** `is_locked` and **NO** `view_count`.
- `cursor` is `null`/absent on the final page (terminal append).
- `items` may be empty array → Empty state.

Error `401`: triggers the core-network authenticator (single `POST /ui/session/refresh` then one retry). If refresh fails, propagates as auth error → routed to login by auth-gated routing (AND-025).

Error `422` (VERIFIED schema `HTTPValidationError`): `detail` is an **array** of `ValidationError` objects with required fields `loc` (array of string|int), `msg` (human message), `type` (error code). e.g. an out-of-range `limit`:
```json
{ "detail": [ { "loc": ["query", "limit"], "msg": "Input should be less than or equal to 200", "type": "less_than_equal" } ] }
```
Other `4xx/5xx`: body conforms to FastAPI `detail`, mapped by AND-015's mapper to a user-facing message. The web `normalizeErrorDetail` (`src/api/client.ts`) handles three `detail` shapes — string, array (joins `msg` values), and object (with a `code`-based mapper, e.g. `geo_blocked` on 403); the Android mapper should mirror these:
```json
{ "detail": "Not found" }
{ "detail": [ { "loc": ["query","limit"], "msg": "...", "type": "..." } ] }
{ "detail": { "code": "geo_blocked", "message": "..." } }
```

> **CONTRACT RESOLVED:** path/params/fields above are reconciled against `/openapi.json` and `src/api/endpoints/videos.ts`. Pagination is **cursor-based** (`String` key), confirmed — there is no offset (`page`/`page_size`) paging, so R1 is closed. See §16 for the full audit.

## 6. Data & State Management

- Network → `VideoListResponse`/`VideoDto` (Moshi) → `VideoSummary` (domain) → `LazyPagingItems<VideoSummary>` in UI. Paging 3 holds list state; `cachedIn(viewModelScope)` survives configuration changes.
- No bespoke persistence in this ticket. Disk caching of the grid for offline/stale is delegated to the cache-repository SWR pattern (AND-116/AND-117) when that lands; until then, offline = Offline state with no rows. A `// TODO(AND-116): wire Room-backed RemoteMediator` marker is left in `VideosRepository`.
- Coil supplies in-memory + disk thumbnail caching; no Room rows are written by this ticket.
- Filter selection (`status`/`visibility: String?`) is held in a `MutableStateFlow` in the ViewModel; changing it re-creates the pager via `flatMapLatest`. Default `null` (server default scope/order). *(CORRECTED: the endpoint exposes `status`/`visibility` filters, not a `sort` param.)*
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
- Locked/entitlement state is **not** exposed by `GET /ui/videos` (no `is_locked` field). Gating is resolved at the detail layer via `GET /ui/videos/{video_id}/access` (`VodAccessOut`) and `VideoDetailOut` fields (`is_entitled`, `access_mode`, `access_reason`). The list tile renders a poster for every item; `VideoSummary.isLocked` defaults to `false` here and the paywall/entitlement gating is enforced downstream (AND-177/AND-101 patterns, AND-190). *(CORRECTED: was stated as a list-response field.)*
- No PII is collected or stored by this screen. Dev backend is plaintext HTTP; cleartext is permitted only for the dev flavor's base URL (per AND-006 network-security-config), not release.

## 9. Accessibility & i18n

- Every `VideoTile` has a `contentDescription` = title (the ", locked" suffix only applies once entitlement is wired in AND-190; this list defaults `isLocked = false`); decorative duration badge text is included in the tile semantics, not a separate focus stop.
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
- `VideosApi` path/verb/query test: asserts request line `GET /ui/videos?limit=24` (and with `cursor`/`status`/`visibility`) — MockWebServer.
- `VideoDto.toDomain()` mapping incl. `duration_seconds` (Double) → rounded Int, missing `duration_seconds` → null, `video_id` → `id`.
- `VideosPagingSource.load`: first page returns `Page` with `nextKey = cursor`; terminal page (`cursor` null/absent) returns `nextKey = null`; HTTP 500 returns `LoadResult.Error`; IOException returns `LoadResult.Error`.
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

- **Hard deps (must land first):** AND-027 (AuthApi/session stack so authenticated `GET /ui/videos` works), AND-103 (Coil thumbnail conventions). Transitively requires core-network stack AND-009..AND-018, theme AND-019, state composables AND-021, nav host AND-022/AND-024, and Paging 3 wiring.
- **Soft deps (graceful-degradation TODOs, not blockers):** AND-116/AND-117 (offline/SWR cache for stale grid), AND-006 (dev cleartext base URL config).
- **Blocks:** AND-190 (video detail screen) consumes the `videos/detail/{videoId}` route and `videoId` arg defined here; AND-166/AND-167/AND-168 (player) are reached through that detail screen.
- Sequence: API+DTO+mapper → PagingSource+Repository → ViewModel → Screen/Tile → nav registration → tests.

## 13. Risks & Open Questions

- **R1 (contract): pagination shape — RESOLVED.** Pagination is cursor-based; the response field is `cursor` (not `next_cursor`) and is `null`/absent on the final page. Verified against OpenAPI `VideoListOut` and `src/api/endpoints/videos.ts: VideoListResponse`. There is no offset paging. `VideosPagingSource` key type is `String`.
- **R2: field names — RESOLVED.** Verified item fields are `video_id`, `title`, `status`, `visibility`, `created_at`/`updated_at` (epoch-second integers), `thumbnail_url`, `duration_seconds` (Double), `width`, `height`, `file_size_bytes`, `review_status`, `owner_user_id`. There is **no** `is_locked`, `view_count`, `duration_sec`, or `total`. Verified against OpenAPI `VideoListItem`/`VideoListOut`.
- **R3: unreliable dev host.** 20s timeouts + retry mean slow first paint; mitigated by skeleton loading and bounded backoff. Acceptance fixtures use MockWebServer so CI is deterministic.
- **R4: locked content rendering.** The list endpoint exposes no lock/entitlement field, so the library cannot render a per-tile lock badge from list data; gating is resolved at detail (`GET /ui/videos/{video_id}/access`, `VideoDetailOut.is_entitled`). Tiles render uniformly; `isLocked` defaults to `false`.
- **Open Q1 — RESOLVED:** No `sort` param exists on `GET /ui/videos`; server returns its own order. The endpoint does accept `status` and `visibility` filters (both optional). Paging relies on server order + `cursor`.
- **Open Q2 — RESOLVED (per OpenAPI):** `GET /ui/videos` is documented as *"List the caller's own videos"* — i.e. the **my videos** scope, which is the scope the web `listMyVideos` browse call uses. An "all/public videos" scope is a different endpoint (`GET /ui/videos/public` → `VideoListOut`, or `GET /ui/videos/gallery` → `GalleryListOut`). This ticket targets the caller's-own-videos feed; if product wants a public catalog, see §16 Open assumptions.

## 14. Acceptance Criteria

AC-1. Opening the Videos route renders a grid of video thumbnails from `GET /ui/videos` (2 columns portrait, 3 expanded). *(Satisfies backlog "Library renders".)*
AC-2. Scrolling past the prefetch threshold loads the next page via the response `cursor`; the terminal page (null/absent `cursor`) stops appending with no error.
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
- Contract assumptions (R1/R2) reconciled against `/openapi.json` and `src/api/endpoints/videos.ts` — **done** in this review (cursor paging + `VideoListItem` fields verified; see §16).
- Code reviewed and merged to `android-port`.

## 16. Citations & Assumption Audit

Each key technical claim, with VERDICT and an exact SOURCE pointer.

1. **Browse/grid endpoint is `GET /ui/videos`** (not `GET /videos`). VERDICT: Corrected. SOURCE: OpenAPI `GET /ui/videos` (op `list_own_videos_ui_videos_get`, resp `200:VideoListOut`); `src/api/endpoints/videos.ts: listMyVideos` (`api.get<VideoListResponse>("/ui/videos", p)`).
2. **HTTP method is GET, idempotent.** VERDICT: Verified. SOURCE: OpenAPI `GET /ui/videos`.
3. **Query params: `limit`, `cursor`, `status`, `visibility` (optional); no `sort`.** VERDICT: Corrected (removed `sort`; added `status`/`visibility`). SOURCE: OpenAPI `GET /ui/videos` parameters block; `src/api/endpoints/videos.ts: listMyVideos` (sends `limit`, `cursor`, `status`).
4. **`limit` default 50, min 1, max 200.** VERDICT: Corrected (spec said default 24 / cap 48). SOURCE: OpenAPI `GET /ui/videos` → `limit` schema `{default:50, minimum:1, maximum:200}`.
5. **Response schema is `VideoListOut` = `{ items: VideoListItem[], cursor?: string|null }`; pagination field is `cursor`, NOT `next_cursor`; no `total`.** VERDICT: Corrected. SOURCE: OpenAPI `components.schemas.VideoListOut` (required `["items"]`); `src/api/endpoints/videos.ts: VideoListResponse`.
6. **Item id field is `video_id` (not `id`).** VERDICT: Corrected. SOURCE: OpenAPI `components.schemas.VideoListItem` (required includes `video_id`); `src/api/endpoints/videos.ts: VideoListItem`.
7. **Duration field is `duration_seconds` (number/float), not `duration_sec` (Int).** VERDICT: Corrected. SOURCE: OpenAPI `VideoListItem.duration_seconds` (`anyOf number|null`); `src/api/endpoints/videos.ts: VideoListItem.duration_seconds`.
8. **`created_at`/`updated_at` are epoch-second integers, not ISO-8601 strings; both required.** VERDICT: Corrected. SOURCE: OpenAPI `VideoListItem` (`created_at`/`updated_at` `type:integer`, in `required`); `src/api/endpoints/videos.ts` (`created_at: number`, `updated_at: number`).
9. **`title` is required (non-null) by contract.** VERDICT: Corrected (spec assumed nullable title → empty string). SOURCE: OpenAPI `VideoListItem.required` includes `title`. (Defensive `orEmpty()` retained but not contractually needed.)
10. **There is NO `is_locked` and NO `view_count` field on the list response.** VERDICT: Corrected. SOURCE: OpenAPI `VideoListItem` properties (full set: `video_id,title,status,visibility,created_at,updated_at,duration_seconds,width,height,thumbnail_url,file_size_bytes,review_status,owner_user_id`); `src/api/endpoints/videos.ts: VideoListItem`.
11. **Pagination is cursor-based (String key), not offset (`page`/`page_size`).** VERDICT: Verified (closes R1). SOURCE: OpenAPI `GET /ui/videos` params (`cursor` only, no `page`/`page_size`); `VideoListOut.cursor`.
12. **Endpoint returns the caller's OWN videos (the "my videos" scope).** VERDICT: Verified (closes Open Q2). SOURCE: OpenAPI `GET /ui/videos` description: "List the caller's own videos (paginated, filterable)."
13. **CSRF: header `X-CSRF-Token`, sourced from cookie `ui_csrf`.** VERDICT: Verified + clarified (cookie name added). SOURCE: `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`).
14. **401 handling: refresh once via `POST /ui/session/refresh`, then retry the original request once; on repeat 401 → logout/auth error.** VERDICT: Verified. SOURCE: `src/api/client.ts: refreshSession()` (`POST /ui/session/refresh`) and the 401 branch in `api()` (single `refreshPromise` then one `retryRes` fetch).
15. **Web client sends `Authorization: Bearer <accessToken>` in addition to cookies (`credentials: include`) and an optional `X-IMPERSONATION-TOKEN`.** VERDICT: Verified (spec called auth purely "cookie-based"). SOURCE: `src/api/client.ts` (`headers.set("Authorization", \`Bearer ${accessToken}\`)`; `credentials: "include"`; `X-IMPERSONATION-TOKEN`).
16. **422 error body = `HTTPValidationError { detail: ValidationError[] }`, `ValidationError = { loc:(string|int)[], msg:string, type:string }` (all required).** VERDICT: Corrected (spec's example used `{msg:"value_error"}` shape; `type` carries the code, `msg` the human text). SOURCE: OpenAPI `components.schemas.HTTPValidationError` + `components.schemas.ValidationError`.
17. **General error `detail` is mapped from three shapes (string | array-of-msg | object-with-`code`, incl. 403 `geo_blocked`).** VERDICT: Verified. SOURCE: `src/api/client.ts: normalizeErrorDetail()` and the 403 `geo_blocked` branch.
18. **Locked/entitlement state is resolved at detail, not list (`GET /ui/videos/{video_id}/access` → `VodAccessOut`; `VideoDetailOut.is_entitled`/`access_mode`/`access_reason`).** VERDICT: Verified. SOURCE: OpenAPI `GET /ui/videos/{video_id}/access` (resp `VodAccessOut`); `src/api/endpoints/videos.ts: VideoDetail` (`is_entitled`, `access_mode`, `access_reason`).
19. **Detail endpoint exists for the AND-190 handoff: `GET /ui/videos/{video_id}` → `VideoDetailOut`.** VERDICT: Verified. SOURCE: OpenAPI `GET /ui/videos/{video_id}` (op `get_video_detail_ui_videos__video_id__get`); `src/api/endpoints/videos.ts: getVideoDetail`.
20. **Framework: `LazyVerticalGrid` + `WindowWidthSizeClass` adaptive span counts.** VERDICT: Unverified-assumption (framework ref). SOURCE: framework ref — Jetpack Compose `LazyVerticalGrid` (developer.android.com/develop/ui/compose/lists#lazy-grids) and Material 3 adaptive `WindowSizeClass` (developer.android.com/develop/ui/compose/layouts/adaptive/use-window-size-classes).
21. **Framework: Paging 3 `Pager`/`PagingSource` + `collectAsLazyPagingItems()` + `cachedIn`.** VERDICT: Unverified-assumption (framework ref). SOURCE: framework ref — Paging 3 (developer.android.com/topic/libraries/architecture/paging/v3-overview).
22. **Framework: Material 3 `PullToRefreshBox` for pull-to-refresh.** VERDICT: Unverified-assumption (framework ref). SOURCE: framework ref — Compose Material 3 pull-to-refresh (developer.android.com/develop/ui/compose/components/pull-to-refresh).
23. **Framework: Coil `AsyncImage` for thumbnails (per AND-103 conventions).** VERDICT: Unverified-assumption (framework ref + internal dep). SOURCE: framework ref — Coil (coil-kt.github.io/coil/compose/); internal AND-103.

### Corrections made
- Endpoint path `GET /videos` → `GET /ui/videos` (§1 Overview, §2, §5, §12, §14 AC-1, §15, Retrofit interface).
- Removed non-existent `sort` query param everywhere; replaced with the real `status`/`visibility` filters (Retrofit API, PagingSource, Repository, ViewModel, §6, §13 Open Q1).
- `limit` default/cap corrected to server values (default 50, max 200); app page size stays 24 but coerces to ≤200.
- Pagination field `next_cursor` → `cursor`; removed `total` (DTO, PagingSource `nextKey`, §5 JSON, §11, §14 AC-2).
- `VideoDto` rewritten to the real `VideoListItem` shape: `video_id`, required `title`/`status`/`visibility`, epoch-second `created_at`/`updated_at` (Long), `duration_seconds` (Double), `width`/`height`, `file_size_bytes`, `review_status`, `owner_user_id`. Removed `id`, `duration_sec`, `is_locked`, `view_count`, `total`.
- Mapper updated (`videoId`→`id`, `duration_seconds?.roundToInt()`, `isLocked=false`); `isLocked` documented as not-from-list (gating at detail).
- §8 locked-content claim corrected (no list-level lock field; entitlement resolved via access/detail endpoints).
- §5 error block corrected to the real `HTTPValidationError`/`ValidationError` shape and the web `normalizeErrorDetail` behavior.
- Auth description expanded: CSRF cookie `ui_csrf`, web `Authorization: Bearer`, 401 refresh via `POST /ui/session/refresh`.
- R1/R2/Open Q1/Open Q2 marked RESOLVED with sources; §15 DoD updated.

### Open assumptions
- **Library scope (my-videos vs public catalog).** This spec targets `GET /ui/videos` (caller's own videos), matching the web `videos.ts` browse call. If product actually wants a public/all-videos catalog grid, the endpoint must change to `GET /ui/videos/public` (`VideoListOut`, same item shape — low-cost swap) or `GET /ui/videos/gallery` (`GalleryListOut` — different shape, larger change). Unverifiable from sources because the ticket text ("Videos library … browse/grid") does not state the scope; flagged for product confirmation before merge.
- **Android auth transport (Bearer vs cookie-only).** Web sends both a session cookie and `Authorization: Bearer`. Whether the Android `core-network` stack uses Bearer, cookie-only, or both is owned by AND-027 and not determinable from these sources.
- **Thumbnail URL signing/expiry.** `thumbnail_url` may be a signed CDN URL; its TTL/signing scheme is not described in OpenAPI. Telemetry strips query strings defensively. Unverifiable here.
- **`status`/`visibility` enum values.** OpenAPI types them as free-form `string`; the concrete allowed values (e.g. `ready`, `public`) are not enumerated in the schema. Treated as opaque strings.
- **Default server ordering stability for cursor paging.** No `sort` param exists; server order is assumed stable enough for cursor paging (Open Q1). Not formally guaranteed by the spec sources.
- **Adaptive/Paging/Coil framework choices** (rows 20-23) are standard Jetpack/Coil patterns, not backend-verifiable; cited as framework refs.

## 17. Test Plan

Test targets: **JVM** = JVM unit/Robolectric (local, no device); **emu35** = headless emulator AVD `test35` (x86_64, API 35); **A15** = physical Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, API 34, arm64-v8a). Contract tests use MockWebServer (AND-046). UI tests use Compose test rule (AND-051).

- **TC-AND-189-01 — Happy-path request line & query params.** Type: contract/MockWebServer. Target: JVM. Preconditions: MockWebServer enqueues `videos_page1.json` (200, `VideoListOut` with `cursor`). Steps: call `VideosApi.listVideos(cursor=null, limit=24)`; capture `RecordedRequest`. Expected: method `GET`, path `/ui/videos?limit=24` (no `sort` param present); `Accept: application/json`. Traces: AC-1, AC-6.
- **TC-AND-189-02 — DTO deserialization & mapping.** Type: unit. Target: JVM. Preconditions: `videos_page1.json` fixture with `video_id`, `duration_seconds: 372.0`, epoch `created_at`, and one item missing `duration_seconds`. Steps: deserialize to `VideoListResponse`; map each via `toDomain()`. Expected: `id == video_id`; `durationSec == 372`; missing `duration_seconds` → `null`; `isLocked == false`; no crash on absent `width`/`review_status`. Traces: AC-1, AC-6.
- **TC-AND-189-03 — PagingSource first page → cursor key.** Type: unit/contract. Target: JVM. Preconditions: MockWebServer returns page1 with `"cursor":"C2"`. Steps: `VideosPagingSource.load(Refresh, key=null)`. Expected: `LoadResult.Page` with `data.size == N`, `prevKey == null`, `nextKey == "C2"`. Traces: AC-2.
- **TC-AND-189-04 — PagingSource terminal page.** Type: unit/contract. Target: JVM. Preconditions: page2 fixture with `cursor` null/absent. Steps: `load(Append, key="C2")`. Expected: `LoadResult.Page` with `nextKey == null` (append stops, no error). Traces: AC-2.
- **TC-AND-189-05 — HTTP error → LoadResult.Error.** Type: contract/MockWebServer. Target: JVM. Preconditions: MockWebServer returns 500. Steps: `load(Refresh)`. Expected: `LoadResult.Error` carrying `HttpStatusException(500)`. Traces: AC-4.
- **TC-AND-189-06 — 422 validation error shape mapping.** Type: contract/MockWebServer. Target: JVM. Preconditions: 422 body `{"detail":[{"loc":["query","limit"],"msg":"Input should be less than or equal to 200","type":"less_than_equal"}]}`. Steps: trigger via mapper (AND-015) over the response. Expected: mapper extracts `msg` text ("Input should be less than or equal to 200"); classified as `validation`; surfaced to Error state, not a crash. Traces: AC-4, AC-6.
- **TC-AND-189-07 — IOException/offline → Offline state.** Type: contract/MockWebServer + unit. Target: JVM. Preconditions: MockWebServer set to disconnect (`SocketPolicy.DISCONNECT_AT_START`) or no body. Steps: `load(Refresh)`; map `LoadState.Error(IOException)` per §7. Expected: `LoadResult.Error(IOException)`; UI maps to `OfflineState` + Retry. Traces: AC-4.
- **TC-AND-189-08 — Flaky dev-host retry then success.** Type: contract/MockWebServer. Target: JVM. Preconditions: MockWebServer enqueues one transport failure/timeout then a 200 page1 (idempotent-GET backoff AND-016 active). Steps: `load(Refresh)`. Expected: request retried within bounded backoff; final result is `LoadResult.Page` (first paint succeeds after the flaky attempt). Traces: AC-1, AC-4.
- **TC-AND-189-09 — Grid renders tiles (happy path UI).** Type: Compose-UI (instrumented). Target: emu35. Preconditions: fake pager emits N `VideoSummary` (titles + durations). Steps: set `VideosScreen` content; assert tiles. Expected: N tiles shown; titles visible (≤2 lines, ellipsized); duration badge `mm:ss` shown when `durationSec != null`; 2 columns in portrait. Traces: AC-1.
- **TC-AND-189-10 — Empty / Error+Retry / append states.** Type: Compose-UI (instrumented). Target: emu35. Preconditions: fake pagers for (a) empty refresh, (b) error refresh, (c) appending. Steps: render each. Expected: (a) `EmptyState` "No videos yet"; (b) Error/Offline state + Retry button that invokes `retry()`; (c) footer spinner with `contentDescription` "Loading more videos". Traces: AC-2, AC-4.
- **TC-AND-189-11 — Tile tap navigates with correct id.** Type: Compose-UI (instrumented). Target: emu35. Preconditions: `VideosScreen(onOpenVideo = capture)`. Steps: tap the first tile (`video_id = "vid_X"`). Expected: `onOpenVideo("vid_X")` invoked once; route resolves to `videos/detail/vid_X`. Traces: AC-3.
- **TC-AND-189-12 — No secrets in logs (security).** Type: integration. Target: JVM (Robolectric for logger) or emu35. Preconditions: redacting logger + OkHttp logging interceptor at BODY (dev); response carries `Set-Cookie`, request carries `X-CSRF-Token`, item `thumbnail_url` has a signed `?sig=...` query. Steps: perform a paged load; capture log output. Expected: no cookie values, no `X-CSRF-Token` value, no signed query string in logs (thumbnail logged host+path only). Traces: AC-7.
- **TC-AND-189-13 — Accessibility (TalkBack semantics).** Type: Compose-UI (instrumented, accessibility). Target: A15 (physical device — exercises real TalkBack/accessibility services and font scaling, which the emulator approximates poorly). Preconditions: grid with ≥4 tiles; system font scale set large. Steps: enable accessibility checks / TalkBack; traverse. Expected: each tile has `contentDescription == title`; touch targets ≥48dp; row-major linear traversal; append spinner announces "Loading more videos"; layout holds at large font scale (no clipping). Traces: AC-1, AC-4.
- **TC-AND-189-14 — End-to-end library renders + opens detail (acceptance gate).** Type: instrumented/e2e. Target: A15 (physical device — real-network/arm64-v8a, API-34 path; validates the actual shipping ABI vs the x86_64 emulator). Preconditions: signed-in session; MockWebServer (or staged backend) serving `videos_page1.json` → scroll → `videos_page2.json` → terminal. Steps: open Videos tab; scroll to trigger append; tap a tile. Expected: grid renders from `GET /ui/videos`; page 2 appends via `cursor`; terminal page stops cleanly; tapping a tile navigates to `videos/detail/{videoId}`. Traces: AC-1, AC-2, AC-3, AC-8.

### Coverage matrix
| AC | Covered by |
|---|---|
| AC-1 (grid renders from `GET /ui/videos`) | TC-01, TC-02, TC-08, TC-09, TC-13, TC-14 |
| AC-2 (cursor append + terminal stop) | TC-03, TC-04, TC-10, TC-14 |
| AC-3 (tile tap → detail route w/ id) | TC-11, TC-14 |
| AC-4 (Loading/Empty/Error/Offline/append-error states) | TC-05, TC-06, TC-07, TC-08, TC-10, TC-13 |
| AC-5 (thumbnail placeholders + scroll cancellation, AND-103) | TC-09 (visual), TC-13 (semantics) — primarily delegated to AND-103 suite |
| AC-6 (request line/verb/params match contract) | TC-01, TC-02, TC-06 |
| AC-7 (no secrets in logs) | TC-12 |
| AC-8 (unit + Compose UI tests green in CI) | all TCs (gate = TC-14) |
