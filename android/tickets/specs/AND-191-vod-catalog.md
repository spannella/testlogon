---
id: AND-191
title: VOD catalog
milestone: M4
epic: E26
priority: P1
size: L
status: draft
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

This ticket maps the web reference module `frontend/src/api/endpoints/vod.ts`
onto the Android module layering: a typed Retrofit `VodApi` in `core-network`,
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
- **Web reference:** `frontend/src/api/endpoints/vod.ts` (catalog + detail call
  shapes) and shared `frontend/src/api/types.ts` (VOD type definitions). The
  authoritative wire contract is `GET /openapi.json` on the dev backend.
- **Dev backend:** `http://18.222.237.167:8000` — PLAINTEXT HTTP, unreliable dev
  host. Design for ~20s timeouts, bounded backoff retry for idempotent GETs
  only, and offline/stale UI states.
- **Dependency:** AND-027 (AuthApi / session endpoints) provides the
  cookie-based session + `X-CSRF-Token` plumbing and the shared `OkHttpClient` /
  persistent cookie jar. VOD endpoints are session-gated and reuse that
  authenticated client; this ticket does not re-implement auth.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Navigation-Compose, Hilt
  (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Room 2.6,
  DataStore, Coil, Paging 3. minSdk 24 / target 35, JDK 17, AGP 8.7.3.

## 3. Functional Requirements

1. **Catalog list (`vod_catalog`):**
   - Display a vertically scrolling, paged grid/list of VOD titles. Each cell
     shows poster art (Coil), title, and a short subtitle (year/duration/rating
     when present).
   - Support pull-to-refresh and incremental page loads via Paging 3.
   - Optional `category`/`query` filter passthrough (query params), defaulting to
     unfiltered catalog.
   - States: initial load (skeletons), populated, empty ("No titles available"),
     append-loading footer, append-error footer with retry, full-screen error
     with retry, and **stale banner** when serving cached data while offline.
2. **Detail (`vod_detail/{vodId}`):**
   - Render hero artwork, title, synopsis/description, and metadata chips
     (duration, release year, rating, genres).
   - A primary **Play** button that invokes `onPlay(vodId)` navigation callback.
   - States: loading, loaded, not-found (404 → "Title unavailable"), error with
     retry, stale/offline.
3. **Navigation:** Tapping a catalog cell navigates to `vod_detail/{vodId}`.
4. **No write operations** in this ticket (no favorites/resume-write). Resume
   position display is best-effort read-only if the API returns it; otherwise N/A.

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
data class VodSummary(
    val id: String,
    val title: String,
    val posterUrl: String?,
    val durationSeconds: Int?,
    val year: Int?,
    val rating: String?,
)

data class VodDetail(
    val id: String,
    val title: String,
    val description: String?,
    val heroUrl: String?,
    val posterUrl: String?,
    val durationSeconds: Int?,
    val year: Int?,
    val rating: String?,
    val genres: List<String>,
    val resumePositionSeconds: Int?,
)

data class VodPage(val items: List<VodSummary>, val nextCursor: String?)
```

### Retrofit API (`core-network`)

```kotlin
interface VodApi {
    @GET("vod")
    suspend fun getCatalog(
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int = 30,
        @Query("category") category: String? = null,
        @Query("q") query: String? = null,
    ): Response<VodCatalogResponseDto>

    @GET("vod/{id}")
    suspend fun getDetail(@Path("id") id: String): Response<VodDetailDto>
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
authenticated `OkHttpClient` from AND-027 attaches session cookies and the
`X-CSRF-Token` header. Both endpoints are idempotent GETs (retry-eligible).

**GET `/vod`** — catalog page.

Query: `cursor?`, `limit` (default 30), `category?`, `q?`.

200 response (representative; reconcile against `/openapi.json` and
`frontend/src/api/types.ts` during implementation):

```json
{
  "items": [
    {
      "id": "vod_abc123",
      "title": "Sample Title",
      "poster_url": "http://.../poster.jpg",
      "duration_seconds": 5400,
      "year": 2024,
      "rating": "TV-14"
    }
  ],
  "next_cursor": "eyJvZmZzZXQiOjMwfQ=="
}
```

**GET `/vod/{id}`** — detail.

```json
{
  "id": "vod_abc123",
  "title": "Sample Title",
  "description": "Long synopsis...",
  "hero_url": "http://.../hero.jpg",
  "poster_url": "http://.../poster.jpg",
  "duration_seconds": 5400,
  "year": 2024,
  "rating": "TV-14",
  "genres": ["Drama", "Thriller"],
  "resume_position_seconds": 120
}
```

Errors: `401` (session expired) → client triggers single
`POST /ui/session/refresh` then retries (shared AND-027 authenticator); `404` →
`VodDetailUiState.NotFound`; `422`/`4xx` `detail` normalized via
`DetailErrorAdapter`; `5xx`/timeout/`IOException` → retryable error / stale
fallback. If actual field names differ from the above, DTO `@Json(name=...)`
annotations are the single point of adaptation — domain models do not change.

## 6. Data & State Management

- **Paging:** Paging 3 with cursor keys; `next_cursor == null` terminates
  pagination. `pageSize = 30`, `prefetchDistance = 10`.
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

- All requests ride the authenticated session from AND-027 (cookies +
  `X-CSRF-Token`). No credentials handled in this feature.
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
  (`/vod`, `/vod/{id}`), query params, header pass-through, and DTO
  deserialization for full + minimal (null optionals) payloads, plus 404/422/500
  mapping. (Mirrors AND-027's MockWebServer convention.)
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

- **Wire-shape drift:** the JSON above is inferred from `vod.ts`/`types.ts`;
  exact field names, pagination style (cursor vs offset/page), and the catalog
  envelope must be confirmed against `/openapi.json`. Mitigation: isolate all
  naming in DTO `@Json` annotations.
- **Pagination contract:** if the backend uses offset/limit rather than cursor,
  `PagingSource` key type changes to `Int`; design keeps this localized to
  `VodCatalogPagingSource`.
- **Artwork auth:** unknown whether image URLs require the session; verify and
  switch Coil loader accordingly.
- **Resume position:** presence of `resume_position_seconds` unconfirmed;
  treated as nullable/best-effort and not blocking.
- **Player route name:** `player/{id}` is a placeholder pending the player
  ticket's final route.

## 14. Acceptance Criteria

1. **VOD list renders:** `vod_catalog` loads a paged grid of titles from `/vod`
   with poster, title, subtitle; scrolling fetches subsequent pages until
   `next_cursor` is null. (Source acceptance: "VOD list … render.")
2. **VOD detail renders:** `vod_detail/{vodId}` loads `/vod/{id}` and shows hero,
   title, description, metadata chips, and an enabled Play button. (Source
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
