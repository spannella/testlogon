---
id: AND-201
title: Gallery browsing
milestone: M4
epic: E27
priority: P2
size: M
status: draft
depends_on: [AND-103]
blocks: []
---

# AND-201 — Gallery browsing

## 1. Overview & Goal

Provide a media **gallery browsing** experience in the native Android client: a scrollable, lazily-loaded **grid** of gallery items and a full-screen **lightbox** (pager) for viewing a single item with swipe-to-navigate, pinch/double-tap zoom, and metadata. The gallery surfaces media collections returned by the TestLogon backend (galleries owned by, or visible to, the authenticated user) and reuses the Coil-based image loading, placeholder, aspect-ratio, and data-saver behavior delivered in **AND-103 (Feed media thumbnails)**.

Goal of this ticket: ship a `feature-gallery` module whose `GalleryScreen` renders a paginated grid and whose `LightboxScreen` opens from a grid tap, with a `GalleryViewModel` exposing `StateFlow<GalleryUiState>` backed by a `GalleryRepository` over the gallery REST endpoints. Success = "Gallery renders + lightbox opens" verified by instrumented and unit tests, with graceful offline/stale/empty/error states given the unreliable dev backend.

Out of scope (named, owned elsewhere): uploads/creation of galleries, deletion/edit, video playback inside the lightbox via Media3/ExoPlayer (the lightbox renders images; video items show a poster + a "play" affordance that defers to the player feature), sharing/download, and gallery comments. This ticket renders and navigates existing image media only.

## 2. Context & References

- **Repo / module:** `spannella/testlogon`, monorepo subfolder `android/`, branch `android-port`. New module `feature-gallery` under the `app -> feature-* -> core-*` layering. Namespace `com.testlogon.android.feature.gallery` (canonical base `com.testlogon.android`).
- **Web reference:** `frontend/src/api/endpoints/gallery.ts` (authoritative for endpoint paths, query params, and response shapes), shared types in `frontend/src/api/types.ts`. Mirror its pagination, sort, and item fields. The OpenAPI document at `<base>/openapi.json` is the schema source of truth; reconcile any divergence in favor of OpenAPI and note it in §13.
- **Upstream dependency:** **AND-103** — Coil loading, `placeholder`/`error` drawables, aspect handling, and data-saver respect. AND-201 consumes the shared `core-ui` Coil components and the app-wide `ImageLoader`; it does not re-implement them.
- **Transitive dependency:** AND-103 depends on **AND-019** (network/image plumbing); AND-201 assumes that stack is present.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, single-Activity Navigation-Compose, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Room 2.6 (cache), DataStore (prefs), Coil, Paging 3. minSdk 24 / compile+target 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (PLAINTEXT, unreliable). Cookie-based session + `ui_csrf` echoed as `X-CSRF-Token`; on 401 a single `POST /ui/session/refresh` then retry. Use ~20s timeouts and bounded backoff for idempotent GETs only.

## 3. Functional Requirements

- **FR-1 Grid render.** On entering the Gallery destination, display a `LazyVerticalGrid` of gallery item thumbnails. Default to **3 columns** in portrait, **5** in landscape/`WindowWidthSizeClass.Expanded`; cells are square-cropped 1:1 thumbnails using the AND-103 Coil component.
- **FR-2 Pagination.** Load items page-by-page via Paging 3; auto-append the next page when the user scrolls near the end. Show an append-spinner footer while loading and an inline retry footer on append error.
- **FR-3 Lightbox open.** Tapping a grid cell opens the full-screen lightbox at that item's index. The lightbox is a `HorizontalPager` over the currently loaded items; horizontal swipe moves between items.
- **FR-4 Lightbox gestures.** Each lightbox page supports pinch-to-zoom (1x–4x) and double-tap to toggle 1x↔2x, with pan when zoomed; swiping between pages is disabled while zoomed in (>1x).
- **FR-5 Lightbox chrome.** Single tap toggles an overlay showing item title/caption, index ("3 / 27"), and a close (back) control. System back and the close control both dismiss the lightbox back to the grid, preserving grid scroll position.
- **FR-6 Empty / stale / offline states.** Render a distinct empty state (no items), a stale banner (serving cached data while a refresh is in flight or failed), and an offline/error full-screen state with retry. Pull-to-refresh re-fetches page 1.
- **FR-7 Video items (degraded).** Items with `type == "video"` render their poster thumbnail in the grid and, in the lightbox, the poster plus a centered play affordance that emits a navigation event (player feature owns playback; not implemented here).
- **FR-8 Data-saver respect.** Honor the data-saver preference from AND-103 (request smaller thumbnail variants; defer full-resolution lightbox loads until the page is the active pager page).

## 4. Technical Design

New module `feature-gallery` with packages `ui`, `viewmodel`, `data`, `data.remote`, `data.local`, `di`, `nav`.

**Navigation (`nav/GalleryNav.kt`):** type-safe routes registered into the app `NavGraphBuilder`.

```kotlin
@Serializable data object GalleryRoute
@Serializable data class LightboxRoute(val galleryId: String, val startIndex: Int)

fun NavGraphBuilder.galleryGraph(navController: NavController) {
    composable<GalleryRoute> { GalleryScreen(onItemClick = { gid, idx ->
        navController.navigate(LightboxRoute(gid, idx)) }) }
    composable<LightboxRoute> { LightboxScreen(onClose = { navController.popBackStack() }) }
}
```

**ViewModel (`viewmodel/GalleryViewModel.kt`):**

```kotlin
@HiltViewModel
class GalleryViewModel @Inject constructor(
    private val repo: GalleryRepository,
    savedState: SavedStateHandle,
) : ViewModel() {
    val pagedItems: Flow<PagingData<GalleryItem>> =
        repo.itemsPager(galleryId).cachedIn(viewModelScope)
    private val _uiState = MutableStateFlow(GalleryUiState())
    val uiState: StateFlow<GalleryUiState> = _uiState.asStateFlow()
    fun onRefresh() { /* trigger header refresh + page-1 reload */ }
    fun onRetry() { /* re-emit pager / refresh */ }
}
```

**Repository (`data/GalleryRepository.kt`):** exposes `itemsPager(galleryId: String): Flow<PagingData<GalleryItem>>` built from a `Pager(PagingConfig(pageSize = 30, prefetchDistance = 12, initialLoadSize = 60))` whose `PagingSource` (`GalleryPagingSource`) calls `GalleryApi.listItems(...)` and maps cursor pagination. A `RemoteMediator` backing a Room `gallery_item` table is **optional for this ticket** (provides offline/stale support per FR-6); if deferred, the in-memory pager plus a single cached page snapshot in Room satisfies the stale banner. Mapping from DTO to domain via `core-model`.

**Compose UI (`ui/GalleryScreen.kt`, `ui/LightboxScreen.kt`):**

```kotlin
@Composable fun GalleryScreen(onItemClick: (String, Int) -> Unit, vm: GalleryViewModel = hiltViewModel())
@Composable fun LightboxScreen(onClose: () -> Unit, vm: GalleryViewModel = hiltViewModel())

@Composable private fun GalleryGrid(items: LazyPagingItems<GalleryItem>, columns: Int, onItemClick: (Int) -> Unit)
@Composable private fun LightboxPager(items: LazyPagingItems<GalleryItem>, startIndex: Int, onClose: () -> Unit)
@Composable private fun ZoomableImage(item: GalleryItem, zoomEnabled: Boolean, onTap: () -> Unit)
```

`GalleryGrid` uses `LazyVerticalGrid(GridCells.Fixed(columns))` and `items.itemKey { it.id }`. Column count derives from `currentWindowAdaptiveInfo().windowSizeClass`. Grid cells reuse the AND-103 `NetworkImage`/`MediaThumbnail` composable. `ZoomableImage` implements zoom via `graphicsLayer { scaleX/scaleY/translation }` driven by `Modifier.pointerInput` (`detectTransformGestures`, `detectTapGestures`). Lightbox state (current page, overlay visibility, per-page zoom) is hoisted into `rememberSaveable` so it survives config change. Status/navigation bars are hidden in the lightbox via `WindowInsetsControllerCompat` and restored on dispose.

**DI (`di/GalleryModule.kt`):** binds `GalleryRepository`, provides `GalleryApi` via the shared authenticated Retrofit from `core-network`.

## 5. API Contract

All paths relative to base `http://18.222.237.167:8000`. Cookie session + `X-CSRF-Token` header are applied by the shared `core-network` OkHttp interceptors; the gallery API declares no auth itself. Reconcile exact paths/fields against `frontend/src/api/endpoints/gallery.ts` and `/openapi.json` at implementation time; the shapes below are the working contract.

**List galleries** (used if a gallery picker is needed; primary flow may deep-link a single `galleryId`):
`GET /ui/galleries?limit=30&cursor=<opaque>`

**List items in a gallery (primary):**
`GET /ui/galleries/{gallery_id}/items?limit=30&cursor=<opaque>&sort=created_desc`

Response 200:
```json
{
  "items": [
    {
      "id": "itm_01H...",
      "gallery_id": "gal_01H...",
      "type": "image",
      "title": "Sunset over the bay",
      "caption": "Shot on the pier",
      "thumb_url": "https://cdn.../itm_01H..._thumb.jpg",
      "full_url": "https://cdn.../itm_01H..._full.jpg",
      "width": 4032,
      "height": 3024,
      "created_at": "2026-05-30T18:22:05Z"
    }
  ],
  "next_cursor": "eyJrIjoi..."
}
```
`next_cursor` is `null`/absent on the last page. `type` ∈ `{"image","video"}`; video items additionally carry `poster_url` and `playback_url` (the latter consumed only by the player feature, not this ticket).

**Single item (lightbox deep-link / refresh):**
`GET /ui/galleries/{gallery_id}/items/{item_id}` → the item object above.

**Retrofit (`data/remote/GalleryApi.kt`):**
```kotlin
interface GalleryApi {
    @GET("ui/galleries/{id}/items")
    suspend fun listItems(
        @Path("id") galleryId: String,
        @Query("cursor") cursor: String?,
        @Query("limit") limit: Int = 30,
        @Query("sort") sort: String = "created_desc",
    ): GalleryItemsPageDto
}
```
All gallery calls are **idempotent GETs** → eligible for bounded backoff retry. Errors are surfaced via the shared `ApiResult<T>` and the FastAPI `detail` mapper (`string | [{msg}] | {code,...}`).

## 6. Data & State Management

**Domain (`core-model`):**
```kotlin
data class GalleryItem(
    val id: String, val galleryId: String, val type: MediaType,
    val title: String?, val caption: String?,
    val thumbUrl: String, val fullUrl: String,
    val posterUrl: String?, val width: Int, val height: Int,
    val createdAt: Instant,
)
enum class MediaType { IMAGE, VIDEO, UNKNOWN }
```

**UI state:**
```kotlin
data class GalleryUiState(
    val isRefreshing: Boolean = false,
    val isStale: Boolean = false,
    val errorMessage: String? = null,
    val columns: Int = 3,
)
```
List content is driven separately by `LazyPagingItems<GalleryItem>` (`collectAsLazyPagingItems()`); `GalleryUiState` carries only header/banner/error and layout state. `combinedLoadStates` from Paging drives the initial loading spinner, the empty state (`refresh is NotLoading && itemCount == 0`), append spinner/retry footer, and the error full-screen.

**Caching/persistence:** Optional Room `gallery_item` table keyed by `(galleryId, id)` with `position` for ordering, written by a `RemoteMediator` to enable stale/offline. DataStore holds the data-saver flag (owned by AND-103) and the last-viewed gallery id. Coil's disk cache (from AND-103) serves images offline. Lightbox transient state (page index, zoom, overlay) lives in `rememberSaveable`, not the ViewModel.

## 7. Error Handling & Resilience

- **Timeouts/retry:** Inherit ~20s OkHttp timeouts; GET item-list/single-item calls are retried with bounded exponential backoff (max 2 retries, jitter) inside the shared interceptor. The `PagingSource` returns `LoadResult.Error` on exhaustion; the UI shows full-screen error (refresh) or footer retry (append).
- **401:** Handled centrally — single `POST /ui/session/refresh` then one retry; persistent 401 emits a session-expired signal routed to the auth flow (not handled inline here).
- **Stale-while-error:** If a refresh fails but cached items exist (Room/Coil), show the cached grid plus a dismissible "Showing saved gallery" stale banner (`isStale = true`); do not blank the screen.
- **Malformed/partial items:** Items missing `thumb_url`/`full_url` map to a broken-media placeholder cell and are still selectable (lightbox shows the error drawable); never crash. `type` outside the enum maps to `UNKNOWN` and renders as a generic placeholder.
- **Image load failure:** Defer to AND-103 placeholder/error drawables; lightbox provides a tap-to-retry on the failed full-resolution image.
- **Empty:** Distinct empty state ("No media in this gallery yet"), not an error.

## 8. Security & Privacy

- No new auth surface; all requests ride the existing cookie jar + `X-CSRF-Token` from `core-network`. Do not log cookies, CSRF tokens, or full media URLs (which may contain signed query params) at info level.
- Treat `full_url`/`thumb_url` as potentially signed/expiring; do not persist them beyond the Coil/Room cache TTL and re-fetch the item on cache miss to obtain fresh URLs.
- The dev backend is plaintext HTTP; the cleartext exception is configured app-wide (AND-019). Production builds must use HTTPS and `usesCleartextTraffic=false`; this ticket adds no cleartext config of its own.
- No PII is collected or stored by the gallery beyond what the API returns; captions/titles are user-authored content shown as-is (rendered as plain text, no HTML interpretation, to avoid injection in `Text`).

## 9. Accessibility & i18n

- Every grid cell and lightbox image has a `contentDescription` derived from `title`/`caption`, falling back to a localized "Gallery image" string; decorative chrome uses `null` descriptions.
- Lightbox controls (close, play affordance) have ≥48dp touch targets and labeled `Role.Button` semantics; the index indicator is announced via `liveRegion`.
- Pinch/double-tap zoom is supplemented by an accessible alternative: TalkBack users can open the lightbox and use system magnification; swipe navigation works with TalkBack's standard gestures (pager pages are individually focusable).
- All user-visible strings live in `feature-gallery/src/main/res/values/strings.xml`; counts ("{n} / {total}") use plural/format resources. Layout is RTL-safe (grid and pager honor layout direction). Respects system font scale and dynamic Material 3 color.

## 10. Telemetry & Logging

- Analytics events via the shared `core-ui`/`core-data` telemetry sink: `gallery_opened {galleryId}`, `gallery_page_loaded {page, count}`, `lightbox_opened {galleryId, index}`, `lightbox_swiped {fromIndex, toIndex}`, `lightbox_zoomed {scale_bucket}`, `gallery_load_error {stage: refresh|append, code}`.
- Logging via the shared `Logger` at `debug` for load states and `warn` for handled errors; never log full URLs or tokens. Paging load-state transitions logged at `debug` behind a build-config flag.
- No third-party analytics SDK added by this ticket; events flow into whatever sink `core-data` provides (no-op in tests).

## 11. Testing Strategy

**Unit (JVM, `core-testing` + Turbine + MockWebServer):**
- `GalleryPagingSourceTest`: first page, cursor follow, last-page (`next_cursor == null`), HTTP 500 → `LoadResult.Error`, 401→refresh→retry path (mocked interceptor).
- `GalleryRepositoryTest`: DTO→`GalleryItem` mapping incl. video/poster, malformed item handling, stale fallback when refresh fails with cache present.
- `GalleryViewModelTest`: `uiState` transitions for refresh/retry; column count from window size; FastAPI `detail` variants mapped to `errorMessage`.

**Instrumented / Compose (`createAndroidComposeRule`, Coil test `ImageLoader` with fake engine):**
- `GalleryScreenTest`: **grid renders** N cells from a seeded `PagingData`; empty, error+retry, and stale-banner states; column count flips with window size; **tapping a cell invokes `onItemClick(galleryId, index)`** (satisfies "Gallery renders").
- `LightboxScreenTest`: **lightbox opens** at the correct start index; swipe advances page and index indicator; tap toggles chrome; double-tap toggles zoom and disables paging while zoomed; close/back returns to grid (satisfies "lightbox opens").
- Coil interactions stubbed via an injected test `ImageLoader`; no real network. Optional MockWebServer end-to-end test for `listItems` happy path.

Coverage target: ViewModel + repository + paging source ≥80% line coverage.

## 12. Dependencies & Sequencing

- **Depends on AND-103** (Coil image loading, placeholders, aspect handling, data-saver) — hard dependency; the grid/lightbox reuse its `MediaThumbnail`/`NetworkImage` composable and shared `ImageLoader`. Transitively depends on **AND-019** (network/image stack).
- Requires `core-network` authenticated Retrofit/OkHttp (cookie jar, CSRF, refresh-on-401), `core-model`, `core-ui`, `core-data`, `core-testing` to be in place.
- **Blocks:** nothing in the source bullets. A future video-playback-in-lightbox ticket (Media3/ExoPlayer) and gallery upload/edit tickets will build on this module; reference them when created.
- **Sequencing within ticket:** (1) module scaffold + DI + Retrofit `GalleryApi`; (2) repository + paging source + tests; (3) `GalleryViewModel` + state; (4) `GalleryScreen` grid; (5) `LightboxScreen` pager + gestures; (6) error/empty/stale/offline states; (7) a11y + telemetry; (8) instrumented tests.

## 13. Risks & Open Questions

- **Endpoint shape unverified locally** — `frontend/src/api/endpoints/gallery.ts` and `/openapi.json` were not available in this workspace; the §5 paths/fields (`/ui/galleries/{id}/items`, `cursor`, `next_cursor`) are the assumed contract and **must be reconciled against OpenAPI before implementation**. Offset vs cursor pagination is the highest-risk unknown.
- **Single gallery vs. multiple** — unclear whether the app deep-links one `galleryId` or needs a gallery list/picker first. Spec supports both (`GET /ui/galleries`); confirm UX entry point.
- **Video in lightbox** — deferred to the player feature; need confirmation that a poster + deferred-play affordance is acceptable for M4, or whether inline ExoPlayer is required.
- **Offline depth** — whether full Room `RemoteMediator` persistence is required for M4 or whether Coil disk cache + single-page snapshot suffices for the stale banner.
- **Signed URL expiry** — TTL of `thumb_url`/`full_url` is unknown; affects how long cached items remain loadable and re-fetch strategy.
- **Unreliable dev host** — flaky timeouts may surface as frequent error/stale states in QA; ensure tests use deterministic fakes, not the live host.

## 14. Acceptance Criteria

- **AC-1 (source: "Gallery renders"):** Navigating to the Gallery destination displays a multi-column grid of thumbnails loaded from `GET /ui/galleries/{id}/items`, with placeholders during load (AND-103) and correct column count for portrait/landscape. Verified by `GalleryScreenTest` rendering seeded `PagingData`.
- **AC-2 (source: "lightbox opens"):** Tapping a grid cell opens a full-screen lightbox at that item's index showing the full-resolution image; horizontal swipe navigates between items and the index indicator updates. Verified by `LightboxScreenTest`.
- **AC-3:** Pull-to-refresh reloads page 1; scrolling to the end auto-appends the next page; append errors show a retry footer that recovers on tap.
- **AC-4:** Empty, offline/error (full-screen retry), and stale-banner states each render correctly and are distinguishable.
- **AC-5:** Lightbox supports pinch (1x–4x) and double-tap zoom; paging is disabled while zoomed; single tap toggles chrome; system back and close return to the grid with scroll position preserved.
- **AC-6:** Video items show poster + play affordance in the lightbox without crashing and emit the deferred-play event.
- **AC-7:** A 401 triggers a single `session/refresh`+retry transparently; persistent failure surfaces the session-expired signal, not a crash or blank grid.
- **AC-8:** All grid/lightbox images carry meaningful `contentDescription`; controls are ≥48dp and TalkBack-navigable.

## 15. Definition of Done

- `feature-gallery` module merged on `android-port` under `com.testlogon.android.feature.gallery`, wired into the app nav graph and Hilt graph.
- All §14 acceptance criteria pass; unit + instrumented tests green in CI; ViewModel/repository/paging coverage ≥80%.
- No new lint or detekt violations; Compose previews exist for grid (loading/loaded/empty/error/stale) and lightbox.
- No cookies/CSRF/tokens/signed URLs logged; cleartext config unchanged (no new cleartext rules added by this ticket).
- Strings externalized and RTL/font-scale verified; data-saver preference honored.
- §5 API contract reconciled against `/openapi.json` and `frontend/src/api/endpoints/gallery.ts`, with any divergence resolved and §13 open questions either closed or filed as follow-up tickets.
- Builds with JDK 17 / AGP 8.7.3 / Gradle 8.9, minSdk 24 / target 35; runs against the dev backend `http://18.222.237.167:8000` with graceful degradation under timeout.
