---
id: AND-191
title: VOD catalog
milestone: M4
epic: E26
priority: P1
size: L
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-027]
blocks: []
---

# AND-191 — VOD catalog

## 1. Overview & Goal

Deliver the Video-On-Demand (VOD) browsing experience for the TestLogon native
Android client: a **catalog list** of on-demand titles and a **detail** screen
for a single title. The catalog is the primary entry point users have for
discovering recorded/library content; the detail screen surfaces the metadata,
artwork, and the play affordance required to hand off to the player feature
(owned downstream).

This ticket maps the web reference modules `reference/src/api/endpoints/vod.ts`
(detail + own/public video lists) and `reference/src/api/endpoints/gallery.ts`
(the actual public catalog/browse the web `GalleryPage` renders) onto the Android
module layering: a typed Retrofit `VodApi` in `core-network`,
domain models in `core-model`, a repository + Paging source in `core-data`, and
a `feature-vod` Compose feature exposing two routes (`vod_catalog`,
`vod_detail/{vodId}`). Playback start (resolving a stream URL and launching
Media3/ExoPlayer) is explicitly **out of scope** here and is owned by the player
ticket; this ticket only wires the "Play" CTA to a navigation callback.

Goal (testable): **VOD list and detail render** from live/mocked backend data,
with paging, loading, empty, offline/stale, and error states, and the detail
"Play" action emits a navigation event carrying the resolved `vodId`.

## 2. Context & References

- **Repo / branch:** `spannella/testlogon`, Android app under `android/`,
  branch `android-port`.
- **Namespace:** `com.testlogon.android`. Feature package:
  `com.testlogon.android.feature.vod`. API package:
  `com.testlogon.android.core.network.api`.
- **Web reference:** `reference/src/api/endpoints/vod.ts` (detail =
  `getVideoDetail`, lists = `listOwnVideos`/`listPublicVideos`) and
  `reference/src/api/endpoints/gallery.ts` (`browseGallery`/`searchGallery`, the
  category/search-capable catalog used by `reference/src/pages/gallery/GalleryPage.tsx`).
  Detail screen behavior mirrors `reference/src/pages/gallery/VideoDetailPage.tsx`.
  NOTE (correction): VOD type definitions live inline in `vod.ts`/`gallery.ts`, not in
  `reference/src/api/types.ts`. The authoritative wire contract is the backend OpenAPI
  spec (`components.schemas.VideoListOut`, `VideoListItem`, `VideoDetailOut`,
  `GalleryListOut`, `GallerySearchOut`).
- **Dev backend:** `http://18.222.237.167:8000` — PLAINTEXT HTTP, unreliable dev
  host. Design for ~20s timeouts, bounded backoff retry for idempotent GETs
  only, and offline/stale UI states.
- **Dependency:** AND-027 (AuthApi / session endpoints) provides the shared
  authenticated transport. CORRECTION: per `reference/src/api/client.ts`, the web
  client sends `Authorization: Bearer <accessToken>` PLUS `X-CSRF-Token` (read
  from the `ui_csrf` cookie) PLUS cookies (`credentials: "include"`), and an
  optional `X-IMPERSONATION-TOKEN`. The OpenAPI also lists `X-SESSION-ID` and
  `X-IMPERSONATION-TOKEN` as accepted headers on these endpoints. So this is NOT
  purely cookie-based: AND-027 must supply the bearer token, CSRF header, and
  cookie jar. VOD endpoints are session-gated and reuse that authenticated
  client; this ticket does not re-implement auth. The 401 path is a single
  `POST /ui/session/refresh` then retry (matches `refreshSession` in
  `client.ts`).
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Navigation-Compose, Hilt
  (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Room 2.6,
  DataStore, Coil, Paging 3. minSdk 24 / target 35, JDK 17, AGP 8.7.3.

## 3. Functional Requirements

1. **Catalog list (`vod_catalog`):**
   - Display a vertically scrolling, paged grid/list of VOD titles. Each cell
     shows poster art (Coil), title, and a short subtitle (year/duration/rating
     when present).
   - Support pull-to-refresh and incremental page loads via Paging 3.
   - Optional `category`/`query` filter passthrough. CORRECTION: `category` and
     `q` are NOT params on the plain list endpoints (`/ui/videos`,
     `/ui/videos/public` accept only `limit`,`cursor` [+`status`,`visibility` for
     the own-videos list]). Category browse maps to `GET /ui/videos/gallery`
     (`category`,`limit`,`cursor`) and free-text search to
     `GET /ui/videos/gallery/search` (`q`,`limit`,`cursor`). Default (no filter)
     can use either the gallery browse with no category or `/ui/videos/public`.
   - States: initial load (skeletons), populated, empty ("No titles available"),
     append-loading footer, append-error footer with retry, full-screen error
     with retry, and **stale banner** when serving cached data while offline.
2. **Detail (`vod_detail/{vodId}`):**
   - Render artwork (`thumbnail_url`; there is no separate hero/poster field),
     title, synopsis/description, and metadata chips. CORRECTION: `VideoDetailOut`
     does NOT include `year`, `rating`, or `genres`. Available chip-able fields
     are `duration_seconds`, `review_status`, `visibility`, `status`, and
     resolution (`width`x`height`). The web `VideoDetailPage` shows only
     title, description, and a `review_status` badge.
   - A primary **Play** button that invokes `onPlay(vodId)` navigation callback.
   - States: loading, loaded, not-found (404 → "Title unavailable"), error with
     retry, stale/offline.
3. **Navigation:** Tapping a catalog cell navigates to `vod_detail/{vodId}`.
4. **No write operations** in this ticket (no favorites/resume-write).
   CORRECTION: there is no `resume_position_seconds` on `VideoDetailOut`, so
   resume position is N/A for this ticket (the field exists only on an unrelated
   schema). The web detail page additionally fires `recordView`, `like`, and
   comments calls — all explicitly OUT of scope here.

## 4. Technical Design

### Module placement

```
core-model/   VodSummary, VodDetail, VodImage, VodPage
core-network/ VodApi, VodDto/VodDetailDto + Moshi adapters
core-data/    VodRepository, VodCatalogPagingSource, VodDao (cache)
feature-vod/  VodCatalogScreen, VodDetailScreen, ViewModels, nav graph
app/          registers vodGraph in NavHost
```

### Domain models (`core-model`)

```kotlin
// CORRECTED to match VideoListItem / VideoDetailOut. Backend id field is
// `video_id` (not `id`); artwork is `thumbnail_url` (no poster/hero); there is
// no year/rating/genres/resume on these schemas. duration_seconds is a float
// (number) on the wire, mapped to Double? then rendered.
data class VodSummary(
    val id: String,          // <- video_id
    val title: String,
    val thumbnailUrl: String?,
    val durationSeconds: Double?,
    val status: String,      // required on wire
    val visibility: String,  // required on wire
)

data class VodDetail(
    val id: String,          // <- video_id
    val title: String,
    val description: String?,
    val thumbnailUrl: String?,
    val durationSeconds: Double?,
    val width: Int?,
    val height: Int?,
    val status: String,
    val visibility: String,
    val reviewStatus: String?,
    val hlsManifestUrl: String?,    // present on VideoDetailOut (player ticket consumes)
    val playbackToken: String?,
)

data class VodPage(val items: List<VodSummary>, val cursor: String?) // field is `cursor`, not next_cursor
```

### Retrofit API (`core-network`)

```kotlin
// CORRECTED paths. Real endpoints are under /ui/videos. The plain list and the
// gallery (category/search) catalogs are distinct backend endpoints/envelopes.
interface VodApi {
    // Default/public catalog -> VideoListOut { items, cursor }
    @GET("ui/videos/public")
    suspend fun getPublicCatalog(
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int = 30,
    ): Response<VideoListOutDto>

    // Category browse -> GalleryListOut { videos, categories, cursor }
    @GET("ui/videos/gallery")
    suspend fun browseGallery(
        @Query("category") category: String? = null,
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int = 30,
    ): Response<GalleryListOutDto>

    // Free-text search -> GallerySearchOut { videos, cursor }
    @GET("ui/videos/gallery/search")
    suspend fun searchGallery(
        @Query("q") query: String,
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int = 30,
    ): Response<GallerySearchOutDto>

    // Detail -> VideoDetailOut
    @GET("ui/videos/{video_id}")
    suspend fun getDetail(@Path("video_id") videoId: String): Response<VideoDetailOutDto>
}
```

Calls are wrapped with the shared `safeApiCall { }` helper returning
`ApiResult<T>` (Success / NetworkError / HttpError(code, detail) /
Unauthorized). FastAPI `detail` is normalized via the shared
`DetailErrorAdapter` (string | `[{msg}]` | `{code,...}`).

### Repository & Paging (`core-data`)

```kotlin
class VodCatalogPagingSource(
    private val api: VodApi,
    private val category: String?,
    private val query: String?,
) : PagingSource<String, VodSummary>() {
    override suspend fun load(params: LoadParams<String>): LoadResult<String, VodSummary>
    override fun getRefreshKey(state: PagingState<String, VodSummary>): String? = null
}

interface VodRepository {
    fun catalog(category: String?, query: String?): Flow<PagingData<VodSummary>>
    suspend fun detail(id: String): ApiResult<VodDetail>
    fun cachedDetail(id: String): Flow<VodDetail?>   // Room-backed, for stale UI
}
```

`VodRepositoryImpl` builds the `Pager(PagingConfig(pageSize = 30,
prefetchDistance = 10, initialLoadSize = 30))` and maps DTO → domain. Detail
results are written to Room (`VodDao.upsert`) so a subsequent offline open shows
stale content with a banner.

### Presentation (`feature-vod`)

```kotlin
@HiltViewModel
class VodCatalogViewModel @Inject constructor(
    private val repo: VodRepository,
) : ViewModel() {
    val pager: Flow<PagingData<VodSummary>> =
        repo.catalog(category = null, query = null).cachedIn(viewModelScope)
}

@HiltViewModel
class VodDetailViewModel @Inject constructor(
    private val repo: VodRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {
    private val vodId: String = checkNotNull(savedStateHandle["vodId"])
    private val _state = MutableStateFlow<VodDetailUiState>(VodDetailUiState.Loading)
    val state: StateFlow<VodDetailUiState> = _state.asStateFlow()
    fun load() { /* emit cached first, then refresh */ }
    fun retry() = load()
}

sealed interface VodDetailUiState {
    data object Loading : VodDetailUiState
    data class Content(val detail: VodDetail, val stale: Boolean) : VodDetailUiState
    data object NotFound : VodDetailUiState
    data class Error(val message: String) : VodDetailUiState
}
```

Composables:

```kotlin
@Composable fun VodCatalogScreen(
    onVodClick: (String) -> Unit,
    viewModel: VodCatalogViewModel = hiltViewModel(),
)

@Composable fun VodDetailScreen(
    onBack: () -> Unit,
    onPlay: (vodId: String) -> Unit,
    viewModel: VodDetailViewModel = hiltViewModel(),
)
```

Catalog uses `collectAsLazyPagingItems()` inside a `LazyVerticalGrid`
(`GridCells.Adaptive(160.dp)`), reading `loadState.refresh`/`.append` for the
state matrix. Detail uses `LaunchedEffect(Unit) { viewModel.load() }` and a
`when (state)` render.

### Navigation graph

```kotlin
fun NavGraphBuilder.vodGraph(nav: NavController) {
    composable("vod_catalog") {
        VodCatalogScreen(onVodClick = { id -> nav.navigate("vod_detail/$id") })
    }
    composable(
        route = "vod_detail/{vodId}",
        arguments = listOf(navArgument("vodId") { type = NavType.StringType }),
    ) {
        VodDetailScreen(
            onBack = { nav.popBackStack() },
            onPlay = { id -> nav.navigate("player/$id") }, // route owned by player ticket
        )
    }
}
```

## 5. API Contract

Base URL `http://18.222.237.167:8000/`. Endpoints are session-gated; the
authenticated `OkHttpClient` from AND-027 attaches the `Authorization: Bearer`
token, the `X-CSRF-Token` header, and session cookies (and forwards
`X-SESSION-ID`/`X-IMPERSONATION-TOKEN` where applicable). All four endpoints
below are idempotent GETs (retry-eligible).

> CORRECTION: the previously-claimed `GET /vod` and `GET /vod/{id}` do NOT exist.
> Verified field shapes below are from OpenAPI `components.schemas` and the
> frontend endpoint modules.

**GET `/ui/videos/public`** — default catalog page (resp `VideoListOut`).
**GET `/ui/videos`** — own-videos list (same envelope; adds `status`,`visibility`
filters). Query for both: `cursor?`, `limit?`. Envelope:

```json
{
  "items": [
    {
      "video_id": "vid_abc123",
      "title": "Sample Title",
      "status": "ready",
      "visibility": "public",
      "created_at": 1717600000,
      "updated_at": 1717600000,
      "duration_seconds": 5400.0,
      "width": 1920,
      "height": 1080,
      "thumbnail_url": "http://.../thumb.jpg",
      "file_size_bytes": 123456,
      "review_status": "approved",
      "owner_user_id": "usr_1"
    }
  ],
  "cursor": "eyJvZmZzZXQiOjMwfQ=="
}
```

Required item fields: `video_id`,`title`,`status`,`visibility`,`created_at`,
`updated_at`. The pagination field is **`cursor`** (nullable), not `next_cursor`;
`cursor == null` terminates pagination.

**GET `/ui/videos/gallery`** — category browse (resp `GalleryListOut`:
`{ videos: GalleryVideoItem[], categories: [{slug,label}], cursor? }`).
**GET `/ui/videos/gallery/search`** — search (resp `GallerySearchOut`:
`{ videos: GalleryVideoItem[], cursor? }`, requires `q`). `GalleryVideoItem`
fields: `video_id`,`title`,`description?`,`thumbnail_url?`,`duration_seconds?`,
`category?`,`tags[]`,`view_count`,`like_count`,`comment_count`,`owner_user_id`,
`price_cents?`,`access_mode?`,`created_at`,`published_at?`.

**GET `/ui/videos/{video_id}`** — detail (resp `VideoDetailOut`). Required:
`video_id`,`owner_user_id`,`title`,`status`,`visibility`,`created_at`,
`updated_at`. Representative (trimmed) response:

```json
{
  "video_id": "vid_abc123",
  "owner_user_id": "usr_1",
  "title": "Sample Title",
  "description": "Long synopsis...",
  "status": "ready",
  "visibility": "public",
  "created_at": 1717600000,
  "updated_at": 1717600000,
  "duration_seconds": 5400.0,
  "width": 1920,
  "height": 1080,
  "thumbnail_url": "http://.../thumb.jpg",
  "review_status": "approved",
  "hls_manifest_url": "http://.../master.m3u8",
  "playback_token": "...",
  "playback_expires_at": 1717603600
}
```

There are NO `hero_url`/`poster_url`/`year`/`rating`/`genres`/
`resume_position_seconds` fields on `VideoDetailOut` (the detail object also
carries many monetization/DRM/ads fields out of scope here).

Errors: `401` (session expired) → client triggers single
`POST /ui/session/refresh` then retries (verified in `client.ts`; endpoint
verified in OpenAPI); `404` → `VodDetailUiState.NotFound` (note the web page
treats a missing body as not-found — see VideoDetailPage); `403` → permission/
geo-block (web reads `detail.code == "geo_blocked"`); `422`/`4xx` `detail`
normalized via `DetailErrorAdapter` (string | `[{msg}]` | `{code,...}` — matches
`normalizeErrorDetail`); `5xx`/timeout/`IOException` → retryable error / stale
fallback. DTO `@Json(name=...)` annotations are the single point of wire-naming
adaptation — domain models do not change.

## 6. Data & State Management

- **Paging:** Paging 3 with cursor keys; the response `cursor` field
  (CORRECTED from `next_cursor`) being `null` terminates pagination.
  `pageSize = 30`, `prefetchDistance = 10`.
- **Cache (Room 2.6):** `VodEntity` (detail) and optionally `VodSummaryEntity`
  for last-seen catalog page, keyed by `id`. Used only to render stale content
  offline; not a Paging `RemoteMediator` in this ticket (catalog offline shows
  first cached page best-effort, otherwise the offline error state).
- **Prefs (DataStore):** none required for this ticket beyond inherited base
  URL; no VOD-specific writes.
- **UI state:** Catalog state derived from `LazyPagingItems.loadState`. Detail
  exposes `StateFlow<VodDetailUiState>`. The `stale` boolean drives a Material 3
  banner above content.
- **Mapping layer:** `VodMappers.kt` in `core-data` converts DTO ↔ domain ↔
  entity. `durationSeconds` formatted to `H:MM` via a UI-layer formatter, not
  stored.

## 7. Error Handling & Resilience

- **Timeouts:** inherit ~20s call/read/connect timeouts from the shared OkHttp
  config.
- **Retry:** bounded exponential backoff (max 3 attempts, base 500ms, jitter)
  for the two idempotent GETs only, via the shared retry interceptor; no retries
  on 4xx except the single 401→refresh→retry path.
- **Offline/stale:** when the network call fails and Room has a cached detail,
  emit `Content(detail, stale = true)` with a "Showing saved info — offline"
  banner. Catalog refresh failure with no data shows full-screen error + Retry;
  append failure shows footer error + Retry.
- **Empty vs error:** empty list (200 with `items: []`) → empty state, never
  treated as error.
- **404 detail:** distinct NotFound state, no retry button.

## 8. Security & Privacy

- All requests ride the authenticated session from AND-027. CORRECTION: that
  session is `Authorization: Bearer <token>` + `X-CSRF-Token` (from `ui_csrf`) +
  cookies, not cookies alone. No credentials are handled or stored in this
  feature.
- Dev backend is plaintext HTTP; `usesCleartextTraffic` is permitted only for
  the dev `network_security_config` host scoped to `18.222.237.167`. No catalog
  data is persisted beyond the non-sensitive Room cache; no PII in VOD payloads.
- No deep-link parameters are trusted for auth; `vodId` is treated as an opaque
  string and URL-path-encoded on navigation.
- Coil image loads reuse the authenticated OkHttp client if artwork URLs are
  session-gated; otherwise the default loader.

## 9. Accessibility & i18n

- All strings in `feature-vod/src/main/res/values/strings.xml`
  (`vod_catalog_title`, `vod_empty`, `vod_play`, `vod_offline_banner`,
  `vod_error_retry`, `vod_not_found`). No hardcoded UI strings.
- Poster/hero images supply `contentDescription` = title (decorative-only hero
  marked `null` when title is shown adjacently to avoid duplicate readout).
- Play button is a `Button` with min 48dp touch target and explicit
  `contentDescription`/text. Catalog cells are single focusable nodes with
  merged semantics (`Modifier.semantics(mergeDescendants = true)`).
- Supports dynamic type and dark theme via Material 3 tokens. Duration/year
  formatted with locale-aware formatters; RTL-safe layouts.

## 10. Telemetry & Logging

- Analytics events via the shared analytics facade (no PII): `vod_catalog_view`,
  `vod_detail_view {vodId}`, `vod_play_tapped {vodId}`,
  `vod_catalog_load_error {stage: refresh|append, httpCode?}`.
- Logging via the shared `Logger` (Timber-backed); network logging through the
  shared OkHttp `HttpLoggingInterceptor` (BODY in debug, NONE in release). Do
  not log full image URLs at INFO. Paging load failures logged at WARN with
  endpoint + code.

## 11. Testing Strategy

- **Unit (core-network):** `VodApi` against **MockWebServer** — verify paths
  (`/ui/videos/public`, `/ui/videos/gallery`, `/ui/videos/gallery/search`,
  `/ui/videos/{video_id}`), query params, `Authorization`/`X-CSRF-Token` header
  pass-through, and DTO deserialization for full + minimal (null optionals)
  payloads, plus 404/422/500 mapping. (Mirrors AND-027's MockWebServer
  convention.)
- **Unit (core-data):** `VodCatalogPagingSource.load` returns correct
  `Page`/`nextKey` for first/subsequent/last pages and `LoadResult.Error` on
  failure; repository stale-fallback emits cached detail with `stale = true`.
- **Unit (feature-vod):** `VodDetailViewModel` state transitions
  Loading→Content / →NotFound / →Error / →stale, using a fake repo and
  `Turbine`.
- **Compose UI tests:** `VodCatalogScreen` renders items, empty state, and
  retry; tapping a cell invokes `onVodClick`. `VodDetailScreen` renders content
  and Play tap invokes `onPlay(vodId)`. Use `core-testing` fakes; paging tested
  with `PagingData.from(...)`.
- **Acceptance probe:** instrumented smoke test verifying list and detail render
  end-to-end against MockWebServer fixtures.

## 12. Dependencies & Sequencing

- **Depends on AND-027** (AuthApi / session endpoints): provides the
  authenticated `OkHttpClient`, persistent cookie jar, CSRF header, and 401→
  refresh authenticator that `VodApi` reuses. Implementation cannot integration-
  test against the live backend until AND-027 is merged, but `VodApi` +
  MockWebServer tests can proceed in parallel.
- **Blocks (informational):** the VOD player/playback ticket consumes the
  `onPlay(vodId)` navigation contract and `vod_detail/{vodId}` route defined
  here. The `player/{id}` route is referenced but owned downstream.
- Requires the shared `safeApiCall`/`ApiResult`, `DetailErrorAdapter`, Paging,
  and Coil infra modules to be present (core-network/core-data baseline).

## 13. Risks & Open Questions

- **Wire-shape drift:** RESOLVED during review — field names/envelopes verified
  against OpenAPI (`VideoListOut`/`VideoListItem`/`VideoDetailOut`/`GalleryListOut`)
  and the frontend `vod.ts`/`gallery.ts`. Residual risk only if the backend
  changes; mitigation: isolate all naming in DTO `@Json` annotations. See §16.
- **Pagination contract:** CONFIRMED cursor-based — response field is `cursor`
  (string|null). `PagingSource` key type is `String`. (If it were offset/limit
  the key would change to `Int`; kept localized to `VodCatalogPagingSource`.)
- **Catalog source choice:** OPEN — the source ticket says "vod.ts catalog", but
  the web `GalleryPage` actually browses via `/ui/videos/gallery`(+search) while
  `vod.ts` exposes `/ui/videos`(own)+`/ui/videos/public`. This spec wires both
  but the canonical default catalog endpoint for the app needs product sign-off.
- **Artwork auth:** unknown whether `thumbnail_url` requires the session; verify
  and switch Coil loader accordingly (web `<img>` loads it without auth headers,
  suggesting public/pre-signed URLs).
- **Resume position:** CONFIRMED absent from `VideoDetailOut`; N/A this ticket.
- **Player route name:** `player/{id}` is a placeholder pending the player
  ticket's final route.

## 14. Acceptance Criteria

1. **VOD list renders:** `vod_catalog` loads a paged grid of titles from
   `/ui/videos/public` (or `/ui/videos/gallery` when a category is selected) with
   thumbnail, title, and a subtitle (duration); scrolling fetches subsequent
   pages until the response `cursor` is null. (Source acceptance: "VOD list …
   render.")
2. **VOD detail renders:** `vod_detail/{vodId}` loads `/ui/videos/{video_id}` and
   shows artwork (`thumbnail_url`), title, description, available metadata chips
   (duration, review_status, resolution), and an enabled Play button. (Source
   acceptance: "VOD … detail render.")
3. Tapping a catalog cell navigates to the correct detail route with the right
   `vodId`; tapping Play invokes `onPlay(vodId)`.
4. Catalog shows empty, refresh-error+retry, append-error+retry, and offline/
   stale states correctly; detail shows loading, NotFound (404), error+retry,
   and stale states.
5. `VodApi` MockWebServer tests pass: paths/verbs/queries/DTOs match contract.
6. No hardcoded user-facing strings; images have content descriptions; Play
   target ≥ 48dp.

## 15. Definition of Done

- `VodApi`, DTOs, domain models, `VodRepository`, `VodCatalogPagingSource`,
  Room cache, both ViewModels, and both Compose screens implemented under
  `com.testlogon.android` packages and wired into the app NavHost via
  `vodGraph`.
- All unit/Compose/MockWebServer tests in §11 written and green in CI;
  acceptance criteria §14 demonstrably met against MockWebServer fixtures and,
  once AND-027 is merged, the dev backend.
- Lint/detekt/ktlint clean; no new cleartext exceptions beyond the scoped dev
  host; strings externalized; accessibility checks pass.
- Code reviewed and merged to `android-port`; ticket links the player ticket as
  the consumer of the `onPlay`/`vod_detail` contract.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the authoritative source pointer.

1. **Catalog endpoint is `GET /vod`.** VERDICT: Corrected → `GET /ui/videos/public`
   (default) and `GET /ui/videos` (own list). SOURCE: OpenAPI `GET /ui/videos/public`
   (op `list_public_videos…`) and `GET /ui/videos` (op `list_own_videos…`);
   `src/api/endpoints/vod.ts: listPublicVideos / listOwnVideos`.
2. **Detail endpoint is `GET /vod/{id}`.** VERDICT: Corrected → `GET /ui/videos/{video_id}`.
   SOURCE: OpenAPI `GET /ui/videos/{video_id}` (op `get_video_detail…`);
   `src/api/endpoints/vod.ts: getVideoDetail`.
3. **Category/`q` filters are params on the catalog endpoint.** VERDICT: Corrected →
   only on the gallery endpoints: `GET /ui/videos/gallery` (`category`) and
   `GET /ui/videos/gallery/search` (`q`); the plain list endpoints accept only
   `limit`,`cursor` (+`status`,`visibility` for own). SOURCE: OpenAPI index
   `params=` for those four rows; `src/api/endpoints/gallery.ts: browseGallery / searchGallery`;
   `src/pages/gallery/GalleryPage.tsx`.
4. **Catalog envelope is `{ items, next_cursor }`.** VERDICT: Corrected → `VideoListOut`
   = `{ items: VideoListItem[], cursor: string|null }`; pagination field is `cursor`.
   SOURCE: OpenAPI `components.schemas.VideoListOut`; `src/api/endpoints/vod.ts: VideoListResponse`.
5. **List item fields `id, poster_url, year, rating`.** VERDICT: Corrected →
   `VideoListItem` has `video_id, title, status, visibility, created_at, updated_at`
   (required) + nullable `duration_seconds (number), width, height, thumbnail_url,
   file_size_bytes, review_status, owner_user_id`. No `id`, `poster_url`, `year`,
   `rating`. SOURCE: OpenAPI `components.schemas.VideoListItem`.
6. **Detail fields `hero_url, poster_url, year, rating, genres,
   resume_position_seconds`.** VERDICT: Corrected → none of these exist on
   `VideoDetailOut`. Real fields include `video_id, owner_user_id, title (req),
   description, status, visibility, created_at, updated_at, duration_seconds, width,
   height, thumbnail_url, review_status, hls_manifest_url, playback_token,
   playback_expires_at, renditions, …`. SOURCE: OpenAPI
   `components.schemas.VideoDetailOut` (required list incl. `owner_user_id`);
   `src/api/endpoints/vod.ts: VideoDetailResponse`; `src/pages/gallery/VideoDetailPage.tsx`
   (renders title, description, thumbnail, review_status badge only).
7. **Auth is cookie-based session + `X-CSRF-Token`.** VERDICT: Corrected → web client
   sends `Authorization: Bearer <accessToken>` + `X-CSRF-Token` (from `ui_csrf`
   cookie) + cookies (`credentials: include`) + optional `X-IMPERSONATION-TOKEN`;
   OpenAPI also accepts `X-SESSION-ID`. SOURCE: `src/api/client.ts` (header
   assembly, lines ~157-171); OpenAPI index `params=` showing `X-SESSION-ID,
   X-IMPERSONATION-TOKEN` on `/ui/videos*`.
8. **401 → single `POST /ui/session/refresh` then retry.** VERDICT: Verified.
   SOURCE: `src/api/client.ts: refreshSession` + 401 branch; OpenAPI
   `POST /ui/session/refresh` (op `ui_session_refresh…`).
9. **Error `detail` normalization (string | `[{msg}]` | `{code,...}`).** VERDICT:
   Verified. SOURCE: `src/api/client.ts: normalizeErrorDetail`; 403 `geo_blocked`
   handling in `client.ts`; `HTTPValidationError` (422) on every `/ui/videos*` row.
10. **404 maps to NotFound.** VERDICT: Verified (behavioral) → web treats absent
    detail body as not-found ("Video not found"). SOURCE:
    `src/pages/gallery/VideoDetailPage.tsx` (`if (!video) …`).
11. **Both catalog + detail are idempotent GETs (retry-eligible).** VERDICT: Verified.
    SOURCE: OpenAPI method column = `GET` for all four endpoints.
12. **Gallery browse/search envelope `{ videos, categories?, cursor? }`.** VERDICT:
    Verified. SOURCE: `src/api/endpoints/gallery.ts: GalleryListResponse /
    GallerySearchResponse`; OpenAPI `GalleryListOut`, `GallerySearchOut`.
13. **`duration_seconds` is an integer.** VERDICT: Corrected → it is `number`
    (float) on the wire; map to `Double?`. SOURCE: OpenAPI `VideoListItem.duration_seconds`
    / `VideoDetailOut.duration_seconds` (`type: number`).
14. **Stack/tooling (Kotlin 2.0.21, Compose+M3, Paging 3, Coil, Retrofit/OkHttp/Moshi,
    Room, Hilt, minSdk 24/target 35).** VERDICT: Unverified-assumption (inherited
    from AND-027 baseline; not checkable from backend/frontend sources). SOURCE:
    framework ref — Paging 3 cursor PagingSource
    (https://developer.android.com/topic/libraries/architecture/paging/v3-paged-data),
    Compose testing (https://developer.android.com/jetpack/compose/testing).
15. **`onPlay`/`player/{id}` route owned downstream.** VERDICT: Unverified-assumption
    (forward reference to an unwritten player ticket; `hls_manifest_url`/`playback_token`
    on `VideoDetailOut` are the likely inputs). SOURCE: OpenAPI `VideoDetailOut`
    (hls/token fields); player route not present in this repo.

### Corrections made

- Endpoints rewritten from non-existent `GET /vod` and `GET /vod/{id}` to the real
  `GET /ui/videos/public`, `GET /ui/videos`, `GET /ui/videos/gallery`,
  `GET /ui/videos/gallery/search`, and `GET /ui/videos/{video_id}` (§2, §4, §5, §11, §14).
- Pagination field corrected `next_cursor` → `cursor` (§4, §5, §6, §13, §14).
- Removed fabricated fields (`poster_url`, `hero_url`, `year`, `rating`, `genres`,
  `resume_position_seconds`, `id`) and replaced with verified `video_id`,
  `thumbnail_url`, `status`, `visibility`, `width/height`, `review_status`,
  `hls_manifest_url`, `playback_token`; domain models updated (§3, §4, §5).
- Auth description corrected to `Authorization: Bearer` + `X-CSRF-Token` + cookies
  (+`X-SESSION-ID`/`X-IMPERSONATION-TOKEN`), not cookie-only (§2, §5, §8).
- `category`/`q` filters re-homed onto the gallery endpoints (§3, §5).
- `duration_seconds` type corrected Int → Double (float) (§4).
- Web reference path corrected: VOD types live in `vod.ts`/`gallery.ts`, not
  `api/types.ts` (§2, §13).

### Open assumptions

- **Canonical default catalog endpoint** (`/ui/videos/public` vs `/ui/videos/gallery`):
  unresolved — source ticket says "vod.ts catalog" but the web catalog UI is the
  gallery. Needs product decision (cannot be inferred from sources).
- **Artwork auth:** whether `thumbnail_url` is session-gated is not stated in the
  sources; web loads it via a plain `<img>` (suggesting public/pre-signed), but the
  Android Coil loader choice should be confirmed at integration.
- **Android stack/versions:** inherited from AND-027; not verifiable against the
  backend/frontend sources in this repo (framework refs only).
- **Player route (`player/{id}`) and `onPlay` contract:** depends on an unwritten
  downstream ticket; placeholder.
- **Live-backend reachability:** dev host `18.222.237.167:8000` is described as
  flaky/plaintext; not reachable/verifiable from this review environment.

## 17. Test Plan

Acceptance criteria referenced are §14 items AC-1..AC-6. Test targets: JVM =
JVM/Robolectric unit (no device); EMU = headless emulator AVD `test35`
(x86_64, API 35); DEVICE = physical Samsung Galaxy A15 5G (SM-A156U, API 34,
arm64-v8a). Most cases are device-agnostic and run on EMU for speed; cases noting
DEVICE must run there for real-hardware/ABI fidelity.

- **TC-AND-191-01 — Catalog happy path (contract).** Type: contract/MockWebServer.
  Target: JVM. Preconditions: MockWebServer enqueues a `VideoListOut` page with 2
  items (`cursor` set) then a final page (`cursor: null`). Steps: call
  `VodApi.getPublicCatalog()` for page 1, then page 2 with returned `cursor`.
  Expected: request paths are `/ui/videos/public` with `limit`/`cursor` query
  params; DTO deserializes (`video_id`,`title`,`thumbnail_url`,`duration_seconds`);
  second page `cursor == null` terminates. Traces: AC-1, AC-5.
- **TC-AND-191-02 — Detail happy path (contract).** Type: contract/MockWebServer.
  Target: JVM. Preconditions: enqueue a `VideoDetailOut` 200 with required fields +
  `description`,`thumbnail_url`,`review_status`,`hls_manifest_url`. Steps: call
  `VodApi.getDetail("vid_abc123")`. Expected: path `/ui/videos/vid_abc123`; DTO →
  `VodDetail` maps `video_id→id`, no crash on absent year/rating/genres. Traces:
  AC-2, AC-5.
- **TC-AND-191-03 — Minimal/null-optional payloads (contract).** Type:
  contract/MockWebServer. Target: JVM. Preconditions: list item and detail with
  only required fields (all nullables omitted). Steps: deserialize both. Expected:
  `thumbnailUrl/durationSeconds/width/height/reviewStatus` map to null without
  error; UI-safe. Traces: AC-1, AC-2, AC-5.
- **TC-AND-191-04 — Auth headers pass-through (contract).** Type:
  contract/MockWebServer. Target: JVM. Preconditions: client configured with the
  AND-027 auth interceptor injecting `Authorization: Bearer` + `X-CSRF-Token`.
  Steps: issue a catalog GET; inspect `RecordedRequest`. Expected: both headers
  present; verifies §8 security claim, not cookie-only. Traces: AC-5.
- **TC-AND-191-05 — 401 → refresh → retry.** Type: contract/MockWebServer. Target:
  JVM. Preconditions: enqueue 401, then 200 for `POST /ui/session/refresh`, then
  200 for the retried GET. Steps: call detail; let authenticator run. Expected:
  exactly one refresh POST, original request retried once, success returned; a
  second 401 surfaces Unauthorized (no infinite loop). Traces: AC-5.
- **TC-AND-191-06 — Error mapping 404/422/500.** Type: contract/MockWebServer.
  Target: JVM. Preconditions: enqueue 404, then a 422 `HTTPValidationError`
  (`detail:[{msg}]`), then 500. Steps: call detail/catalog for each. Expected: 404
  → `VodDetailUiState.NotFound` (no retry); 422 detail normalized via
  `DetailErrorAdapter` to a message; 500 → retryable `HttpError`. Traces: AC-4,
  AC-5.
- **TC-AND-191-07 — PagingSource keys.** Type: unit. Target: JVM. Preconditions:
  fake `VodApi` returning page→cursor→null. Steps: invoke
  `VodCatalogPagingSource.load` for refresh/append/last. Expected: `LoadResult.Page`
  with correct `nextKey` (= response `cursor`), `nextKey == null` on last page,
  `LoadResult.Error` on thrown failure. Traces: AC-1, AC-4.
- **TC-AND-191-08 — Detail ViewModel state machine + stale fallback.** Type: unit.
  Target: JVM (Turbine). Preconditions: fake repo. Steps: drive
  Loading→Content; Loading→NotFound (404); Loading→Error; network-fail-with-cache
  → `Content(stale=true)`. Expected: each transition emitted in order; stale flag
  set only when cached detail served offline. Traces: AC-2, AC-4.
- **TC-AND-191-09 — Catalog Compose states.** Type: Compose-UI. Target: EMU.
  Preconditions: `PagingData.from(...)` fakes for populated / empty /
  refresh-error / append-error. Steps: render `VodCatalogScreen`; assert grid
  items, "No titles available" empty text, full-screen retry, footer retry; tap a
  cell. Expected: states render; cell tap invokes `onVodClick(video_id)`. Traces:
  AC-1, AC-3, AC-4.
- **TC-AND-191-10 — Detail Compose + Play callback.** Type: Compose-UI. Target:
  EMU. Preconditions: fake repo returns a `VodDetail`. Steps: render
  `VodDetailScreen`; assert title/description/thumbnail/chips; tap Play. Expected:
  content renders; `onPlay(vodId)` invoked with the correct id; NotFound/error/stale
  variants render their UI. Traces: AC-2, AC-3, AC-4.
- **TC-AND-191-11 — Offline/stale + flaky-dev-host path.** Type: integration.
  Target: EMU (airplane mode / MockWebServer with `SocketPolicy` disconnect).
  Preconditions: detail previously cached in Room; network forced to fail/timeout.
  Steps: open detail offline. Expected: cached content shown with the
  "Showing saved info — offline" banner (`stale=true`); catalog with no cache shows
  full-screen error + Retry; bounded backoff retries only idempotent GETs. Traces:
  AC-4.
- **TC-AND-191-12 — Accessibility checks.** Type: Compose-UI (instrumented).
  Target: EMU. Preconditions: catalog + detail rendered. Steps: run accessibility
  assertions / `onNodeWithContentDescription`; check Play touch target and
  semantics merge on cells; toggle large font + dark theme. Expected: thumbnails
  have title `contentDescription`; Play ≥ 48dp with label; no hardcoded strings
  (all from `strings.xml`); layout survives dynamic type/RTL. Traces: AC-2, AC-6.
- **TC-AND-191-13 — Cleartext scoping (security).** Type: instrumented. Target:
  EMU. Preconditions: `network_security_config` scoping cleartext to
  `18.222.237.167`. Steps: attempt a plaintext request to the dev host (allowed)
  and to an arbitrary other cleartext host (blocked). Expected: dev host permitted;
  other cleartext blocked by policy; no global `usesCleartextTraffic`. Traces: AC-6
  (security hardening supporting the DoD).
- **TC-AND-191-14 — End-to-end smoke on physical hardware (ABI/API fidelity).**
  Type: instrumented/e2e. Target: DEVICE (must run on SM-A156U — arm64-v8a, API 34,
  to catch arm64-vs-x86 and API-34-vs-35 differences vs the emulator). Preconditions:
  app built; MockWebServer (or live dev backend once AND-027 merged) serving catalog
  + detail. Steps: launch app → open catalog → scroll to trigger a page append →
  tap a title → detail renders → tap Play. Expected: list and detail render on the
  real device, paging append succeeds, navigation carries the right `vodId`, Play
  fires `onPlay`. Traces: AC-1, AC-2, AC-3.

### Coverage matrix

| AC (§14) | Covered by |
| --- | --- |
| AC-1 list renders/paging | TC-01, TC-03, TC-07, TC-09, TC-14 |
| AC-2 detail renders | TC-02, TC-03, TC-08, TC-10, TC-12, TC-14 |
| AC-3 navigation + Play callback | TC-09, TC-10, TC-14 |
| AC-4 empty/error/offline/stale/NotFound states | TC-06, TC-07, TC-08, TC-09, TC-10, TC-11 |
| AC-5 MockWebServer contract (paths/verbs/queries/DTOs) | TC-01, TC-02, TC-03, TC-04, TC-05, TC-06 |
| AC-6 a11y / strings / 48dp / security | TC-12, TC-13 |
