---
id: AND-201
title: Gallery browsing
milestone: M4
epic: E27
priority: P2
size: M
depends_on: [AND-103]
blocks: []
status: reviewed
reviewed_on: 2026-06-06
---

# AND-201 — Gallery browsing

## 1. Overview & Goal

> **Reviewer correction (2026-06-06):** The authoritative sources (`reference/src/pages/gallery/GalleryPage.tsx`, `reference/src/api/endpoints/gallery.ts`, OpenAPI `GET /ui/videos/gallery`) show that "Gallery browsing" in TestLogon is a **video gallery** — a grid of published *videos*, not a generic image gallery. There is no `/ui/galleries/{id}/items` endpoint, no `gallery_id`, and no pinch-zoom image lightbox. The "lightbox" in the web client is a **video detail page** (`/gallery/{video_id}`) that records a view and shows title/metadata/like/comments. This spec has been corrected throughout to match; the original image-lightbox framing is preserved only where the gesture/zoom UX still applies to the poster image, and is flagged. See §16 for the full audit.

Provide a **video gallery browsing** experience in the native Android client: a scrollable, lazily-loaded **grid** of published video cards (poster thumbnail + title + view/like/comment counts + duration/PPV badges) and, on tap, a full-screen **video detail** destination showing the poster, metadata, and engagement (view count, like, comments). The gallery surfaces published videos returned by the TestLogon backend (`GET /ui/videos/gallery`, with category filtering, search, and a "For You" feed) and reuses the Coil-based image loading, placeholder, aspect-ratio, and data-saver behavior delivered in **AND-103 (Feed media thumbnails)** for the poster thumbnails.

Goal of this ticket: ship a `feature-gallery` module whose `GalleryScreen` renders a paginated grid (Browse + Search + categories; "For You" may be a follow-up) and whose `VideoDetailScreen` opens from a grid tap, with a `GalleryViewModel` exposing `StateFlow<GalleryUiState>` backed by a `GalleryRepository` over the gallery REST endpoints. Success = "Gallery renders + detail opens" verified by instrumented and unit tests, with graceful offline/stale/empty/error states given the unreliable dev backend.

Out of scope (named, owned elsewhere): publishing/unpublishing videos to the gallery (`POST /ui/videos/{id}/gallery/publish|unpublish`), actual video playback (Media3/ExoPlayer — the detail screen renders the poster + a "play" affordance that defers to the player/VOD feature), recording views / like toggling / comments CRUD on the detail screen (these `POST /ui/videos/{id}/view|like|comments` calls exist and are exercised by the web detail page, but are deferred to a follow-up engagement ticket; this ticket renders them read-only or not at all), sharing/download, and the messaging "conversation gallery" (`GET /messaging/conversations/{id}/gallery`, a separate feature). This ticket renders and navigates the published video gallery only.

## 2. Context & References

- **Repo / module:** `spannella/testlogon`, monorepo subfolder `android/`, branch `android-port`. New module `feature-gallery` under the `app -> feature-* -> core-*` layering. Namespace `com.testlogon.android.feature.gallery` (canonical base `com.testlogon.android`).
- **Web reference:** `reference/src/api/endpoints/gallery.ts` (authoritative for endpoint paths, query params, and response shapes — `browseGallery`, `searchGallery`, `getGalleryCategories`), `reference/src/pages/gallery/GalleryPage.tsx` (grid + tabs + category pills + search behavior), `reference/src/pages/gallery/GalleryVideoCard.tsx` (card layout: poster, duration badge, PPV price badge, view/like/comment counts, tags), and `reference/src/pages/gallery/VideoDetailPage.tsx` (the "lightbox"/detail screen). Mirror its pagination, category, and item fields. The OpenAPI document at `<base>/openapi.json` is the schema source of truth; verified against OpenAPI `GET /ui/videos/gallery` → `GalleryListOut`, `GET /ui/videos/gallery/search` → `GallerySearchOut`, `GET /ui/videos/gallery/categories` → `CategoriesOut`, item schema `GalleryVideoItem`.
- **Upstream dependency:** **AND-103** — Coil loading, `placeholder`/`error` drawables, aspect handling, and data-saver respect. AND-201 consumes the shared `core-ui` Coil components and the app-wide `ImageLoader`; it does not re-implement them.
- **Transitive dependency:** AND-103 depends on **AND-019** (network/image plumbing); AND-201 assumes that stack is present.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, single-Activity Navigation-Compose, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Room 2.6 (cache), DataStore (prefs), Coil, Paging 3. minSdk 24 / compile+target 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (PLAINTEXT, unreliable). Auth (verified against `reference/src/api/client.ts`): `Authorization: Bearer <accessToken>` from the auth store **plus** cookie-based session (`credentials: include`) **plus** `ui_csrf` cookie echoed as `X-CSRF-Token`; optional `X-IMPERSONATION-TOKEN` when impersonating. On 401 (only when already authenticated) a single `POST /ui/session/refresh` then one retry; a 401 on retry triggers logout/`session_expired`. (OpenAPI additionally lists `X-SESSION-ID` / `user_sub` params on these routes; the web client does not send `X-SESSION-ID`, relying on the cookie + Bearer instead — treat as a server-side alternate.) Use ~20s timeouts and bounded backoff for idempotent GETs only.

## 3. Functional Requirements

- **FR-1 Grid render.** On entering the Gallery destination, display a `LazyVerticalGrid` of video cards. Web renders 1/2/3/4 columns responsively (`grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4`, `GalleryPage.tsx`). Android default: **2 columns** in portrait, **4** in landscape/`WindowWidthSizeClass.Expanded`. Each card uses a **16:9 (`aspect-video`) poster** (NOT square 1:1 — corrected; `GalleryVideoCard.tsx` uses `aspect-video`) loaded via the AND-103 Coil component, with a duration badge (bottom-right, `mm:ss`/`h:mm:ss` from `duration_seconds`), an optional PPV price badge (top-right, when `price_cents > 0`), title (2-line clamp), category label, view/like/comment counts, and up to 3 tags.
- **FR-2 Pagination.** The video gallery uses **cursor pagination** (`GalleryListOut.cursor` / `GallerySearchOut.cursor` — field name is `cursor`, the *next-page* cursor; there is no `next_cursor` on these routes). The web page currently requests a single page of `limit: 48` and does not infinite-scroll, but the `cursor` field exists, so Android loads page-by-page via Paging 3, auto-appending the next page when the user scrolls near the end. Show an append-spinner footer while loading and an inline retry footer on append error. (Verify whether the backend actually returns a non-null `cursor`; if it never paginates in practice, a single-page load satisfies the contract — flagged in §13/§16.)
- **FR-3 Categories & search.** Render category pills from `GalleryListOut.categories` (the active-tab "Browse" view); tapping a pill re-queries `browseGallery({category})`. A search field queries `searchGallery({q})` (`GET /ui/videos/gallery/search?q=`); active search clears the category filter (mirrors `GalleryPage.tsx`). The "For You" tab (`GET /ui/videos/gallery/for-you`) is optional for this ticket and may be a follow-up; if included it is a separate paged list.
- **FR-4 Detail open ("lightbox").** Tapping a grid card opens the full-screen **video detail** destination for that `video_id` (web route `/gallery/{video_id}`, `VideoDetailPage.tsx`). This is **not** a swipe-between-items pinch-zoom image lightbox (corrected). The detail screen shows the poster (16:9, `object-contain`), title, description, view count, a like button, and a comments section. System back and an explicit "Back to Gallery" control return to the grid, preserving grid scroll position.
- **FR-5 Detail engagement (read-mostly for M4).** The detail screen displays view count, like state, and comments. The underlying calls — `POST /ui/videos/{id}/view`, `POST/GET /ui/videos/{id}/like`, `GET/POST/DELETE /ui/videos/{id}/comments` — exist and are used by the web detail page. For this ticket, recording a view on open MAY be wired; like-toggle and comment CRUD are **deferred to a follow-up engagement ticket** and rendered read-only (or omitted) here to keep scope to "browse + open". (Flagged in §13.)
- **FR-6 Empty / stale / offline states.** Render a distinct empty state (no videos — web copy: "No videos found" / "No videos have been published to the gallery yet" / search variant "Try a different search term."), a stale banner (serving cached data while a refresh is in flight or failed), and an offline/error full-screen state with retry. Pull-to-refresh re-fetches the first page / current category.
- **FR-7 Poster + play affordance.** Every gallery item is a video. The grid shows the poster thumbnail; the detail screen shows the poster plus a centered **play** affordance that emits a navigation event to the player/VOD feature (playback not implemented here). There is no `type` discriminator on `GalleryVideoItem` — all items are videos (corrected; the original "type ∈ {image,video}" enum does not exist).
- **FR-8 Data-saver respect.** Honor the data-saver preference from AND-103 (request smaller poster variants where available; defer the full poster load on the detail screen until visible).

## 4. Technical Design

New module `feature-gallery` with packages `ui`, `viewmodel`, `data`, `data.remote`, `data.local`, `di`, `nav`.

**Navigation (`nav/GalleryNav.kt`):** type-safe routes registered into the app `NavGraphBuilder`.

```kotlin
@Serializable data object GalleryRoute
@Serializable data class VideoDetailRoute(val videoId: String)

fun NavGraphBuilder.galleryGraph(navController: NavController) {
    composable<GalleryRoute> { GalleryScreen(onItemClick = { videoId ->
        navController.navigate(VideoDetailRoute(videoId)) }) }
    composable<VideoDetailRoute> { VideoDetailScreen(onClose = { navController.popBackStack() }) }
}
```
(Corrected: the web client navigates by `video_id` — `/gallery/{video_id}` in `GalleryVideoCard.tsx`/`VideoDetailPage.tsx` — not by `(galleryId, startIndex)`. There is no gallery id.)

**ViewModel (`viewmodel/GalleryViewModel.kt`):**

```kotlin
@HiltViewModel
class GalleryViewModel @Inject constructor(
    private val repo: GalleryRepository,
    savedState: SavedStateHandle,
) : ViewModel() {
    // Cursor-paged videos for the active category/search query.
    val pagedItems: Flow<PagingData<GalleryVideoItem>> =
        repo.videosPager(category = null, query = null).cachedIn(viewModelScope)
    private val _uiState = MutableStateFlow(GalleryUiState())
    val uiState: StateFlow<GalleryUiState> = _uiState.asStateFlow()
    fun onRefresh() { /* trigger header refresh + page-1 reload */ }
    fun onRetry() { /* re-emit pager / refresh */ }
}
```

**Repository (`data/GalleryRepository.kt`):** exposes `videosPager(category: String?, query: String?): Flow<PagingData<GalleryVideoItem>>` built from a `Pager(PagingConfig(pageSize = 48, prefetchDistance = 12, initialLoadSize = 48))` (web uses `limit: 48`) whose `PagingSource` (`GalleryPagingSource`) calls `GalleryApi.browseGallery(...)` or `GalleryApi.searchGallery(...)` and follows the `cursor` field (not `next_cursor`) for the next key; a null/absent `cursor` terminates pagination. Categories are fetched separately via `GalleryApi.categories()` (or read from the first browse page's `categories` field). A `RemoteMediator` backing a Room `gallery_video` table is **optional for this ticket** (provides offline/stale support per FR-6); if deferred, the in-memory pager plus a single cached page snapshot in Room satisfies the stale banner. Mapping from DTO to domain via `core-model`.

**Compose UI (`ui/GalleryScreen.kt`, `ui/LightboxScreen.kt`):**

```kotlin
@Composable fun GalleryScreen(onItemClick: (String) -> Unit, vm: GalleryViewModel = hiltViewModel())
@Composable fun VideoDetailScreen(onClose: () -> Unit, vm: VideoDetailViewModel = hiltViewModel())

@Composable private fun GalleryGrid(items: LazyPagingItems<GalleryVideoItem>, columns: Int, onItemClick: (String) -> Unit)
@Composable private fun GalleryVideoCard(item: GalleryVideoItem, onClick: () -> Unit)   // poster + duration/PPV badges + counts + tags
@Composable private fun CategoryPills(categories: List<GalleryCategory>, selected: String?, onSelect: (String?) -> Unit)
```

`GalleryGrid` uses `LazyVerticalGrid(GridCells.Fixed(columns))` and `items.itemKey { it.videoId }` (key is `video_id`). Column count derives from `currentWindowAdaptiveInfo().windowSizeClass`. Cards reuse the AND-103 `NetworkImage`/`MediaThumbnail` composable for the **16:9 poster** and render the duration badge, optional PPV price badge, title, category, view/like/comment counts, and tags (mirroring `GalleryVideoCard.tsx`). `VideoDetailScreen` is a scrollable detail view (poster + metadata + engagement), navigated to by `video_id`; it is **not** a `HorizontalPager`/pinch-zoom image lightbox (corrected). If a poster zoom affordance is desired it can be a single-image `graphicsLayer`/`detectTransformGestures` viewer, but cross-item swipe and per-page zoom state from the original design do not apply since detail is a single video.

**DI (`di/GalleryModule.kt`):** binds `GalleryRepository`, provides `GalleryApi` via the shared authenticated Retrofit from `core-network`.

## 5. API Contract

All paths relative to base `http://18.222.237.167:8000`. Auth headers (Bearer + cookie + `X-CSRF-Token`, see §2) are applied by the shared `core-network` OkHttp interceptors; the gallery API declares no auth in its own signatures. **All paths below are verified against OpenAPI (`reference/openapi.index.txt`) and `reference/src/api/endpoints/gallery.ts`.**

> **Correction:** The previously specified `GET /ui/galleries`, `GET /ui/galleries/{gallery_id}/items`, and `GET /ui/galleries/{gallery_id}/items/{item_id}` **do not exist** in the backend. The real endpoints are under `/ui/videos/gallery`. The response wrapper field is `cursor` (not `next_cursor`), items are `GalleryVideoItem` (videos, not generic media), and there is no `gallery_id`, `type`, `thumb_url`/`full_url`, `caption`, `width`/`height`, or per-item GET.

**Browse gallery (primary):**
`GET /ui/videos/gallery?category=<slug>&limit=48&cursor=<opaque>` → `GalleryListOut`
(op `browse_gallery_endpoint`; params `category, limit, cursor, user_sub, X-SESSION-ID, X-IMPERSONATION-TOKEN`; `category` optional.)

```json
{
  "videos": [
    {
      "video_id": "vid_01H...",
      "title": "Sunset over the bay",
      "description": "Shot on the pier",
      "thumbnail_url": "https://cdn.../vid_01H..._thumb.jpg",
      "duration_seconds": 154.0,
      "category": "travel",
      "tags": ["beach", "golden-hour"],
      "view_count": 1203,
      "like_count": 88,
      "comment_count": 12,
      "owner_user_id": "usr_01H...",
      "price_cents": 0,
      "access_mode": "free",
      "created_at": 1717091525,
      "published_at": 1717095000
    }
  ],
  "categories": [ { "slug": "travel", "label": "Travel" } ],
  "cursor": "eyJrIjoi..."
}
```
Required item fields per OpenAPI `GalleryVideoItem`: `video_id`, `title`, `owner_user_id`. All other fields are optional/defaulted (`view_count`/`like_count`/`comment_count`/`created_at` default `0`; `tags` array; `thumbnail_url`, `duration_seconds`, `category`, `price_cents`, `access_mode`, `description`, `published_at` nullable). `created_at`/`published_at` are **Unix epoch integers** (seconds), not ISO strings (corrected). `categories` is a list of `{slug,label}` objects (typed in `gallery.ts`; OpenAPI types it loosely as `array<object>`). `cursor` is `null`/absent on the last page.

**Search gallery:**
`GET /ui/videos/gallery/search?q=<text>&limit=48&cursor=<opaque>` → `GallerySearchOut` `{ videos: GalleryVideoItem[], cursor?: string }` (no `categories`). `q` is required.

**Categories:**
`GET /ui/videos/gallery/categories` → `CategoriesOut` `{ categories: GalleryCategory[] }`.

**For You (optional / follow-up):**
`GET /ui/videos/gallery/for-you?limit=&cursor=` → `ForYouResponse`.

**Video detail ("lightbox"):** the web detail page fetches via `getVideoDetail(videoId)` from `reference/src/api/endpoints/vod.ts` (VOD feature), **not** a gallery endpoint. This ticket either reuses the AND VOD detail API or passes the already-loaded `GalleryVideoItem` to the detail screen and lazily fetches full detail. (Flagged in §13/§16 — confirm the exact VOD detail route/owner.)

**Retrofit (`data/remote/GalleryApi.kt`):**
```kotlin
interface GalleryApi {
    @GET("ui/videos/gallery")
    suspend fun browseGallery(
        @Query("category") category: String?,
        @Query("cursor") cursor: String?,
        @Query("limit") limit: Int = 48,
    ): GalleryListDto                       // { videos, categories, cursor }

    @GET("ui/videos/gallery/search")
    suspend fun searchGallery(
        @Query("q") query: String,
        @Query("cursor") cursor: String?,
        @Query("limit") limit: Int = 48,
    ): GallerySearchDto                     // { videos, cursor }

    @GET("ui/videos/gallery/categories")
    suspend fun categories(): CategoriesDto // { categories }
}
```
All gallery browse/search/category calls are **idempotent GETs** → eligible for bounded backoff retry. Errors are surfaced via the shared `ApiResult<T>` and the FastAPI `detail` mapper. Verified `detail` shapes from `reference/src/api/client.ts: normalizeErrorDetail`: `detail` may be a `string`, an array of `{msg}` validation items (FastAPI 422 / `HTTPValidationError`), or an object carrying a `code` (e.g. `role_required_scope`, `geo_blocked`, `helpdesk_*`). 422 (`HTTPValidationError`) is the documented error for all four gallery routes.

## 6. Data & State Management

**Domain (`core-model`):** (corrected to mirror OpenAPI `GalleryVideoItem` / `gallery.ts`)
```kotlin
data class GalleryVideoItem(
    val videoId: String,                 // required
    val title: String,                   // required
    val ownerUserId: String,             // required
    val description: String? = null,
    val thumbnailUrl: String? = null,    // nullable — show "No thumbnail" placeholder
    val durationSeconds: Double? = null, // OpenAPI: number
    val category: String? = null,
    val tags: List<String> = emptyList(),
    val viewCount: Int = 0,
    val likeCount: Int = 0,
    val commentCount: Int = 0,
    val priceCents: Int? = null,         // PPV badge when > 0
    val accessMode: String? = null,
    val createdAt: Long = 0,             // Unix epoch seconds
    val publishedAt: Long? = null,       // Unix epoch seconds
)
data class GalleryCategory(val slug: String, val label: String)
```
There is **no** `MediaType`/`type` enum and no separate image/video discriminator — every gallery item is a video (corrected).

**UI state:**
```kotlin
data class GalleryUiState(
    val isRefreshing: Boolean = false,
    val isStale: Boolean = false,
    val errorMessage: String? = null,
    val columns: Int = 2,                  // 2 portrait / 4 expanded (corrected)
    val selectedCategory: String? = null,
    val searchQuery: String? = null,
    val categories: List<GalleryCategory> = emptyList(),
)
```
List content is driven separately by `LazyPagingItems<GalleryVideoItem>` (`collectAsLazyPagingItems()`); `GalleryUiState` carries header/banner/error, layout, category/search filter, and category-pill state. `combinedLoadStates` from Paging drives the initial loading spinner, the empty state (`refresh is NotLoading && itemCount == 0`), append spinner/retry footer, and the error full-screen.

**Caching/persistence:** Optional Room `gallery_video` table keyed by `video_id` with `position` (and a `(category, position)` index) for ordering, written by a `RemoteMediator` to enable stale/offline. DataStore holds the data-saver flag (owned by AND-103) and the last-selected category. Coil's disk cache (from AND-103) serves posters offline. Detail-screen transient UI state lives in `rememberSaveable`, not the ViewModel.

## 7. Error Handling & Resilience

- **Timeouts/retry:** Inherit ~20s OkHttp timeouts; GET item-list/single-item calls are retried with bounded exponential backoff (max 2 retries, jitter) inside the shared interceptor. The `PagingSource` returns `LoadResult.Error` on exhaustion; the UI shows full-screen error (refresh) or footer retry (append).
- **401:** Handled centrally — single `POST /ui/session/refresh` then one retry; persistent 401 emits a session-expired signal routed to the auth flow (not handled inline here).
- **Stale-while-error:** If a refresh fails but cached items exist (Room/Coil), show the cached grid plus a dismissible "Showing saved gallery" stale banner (`isStale = true`); do not blank the screen.
- **Malformed/partial items:** Items missing `thumbnail_url` (nullable) render a "No thumbnail" placeholder card (mirrors `GalleryVideoCard.tsx`) and remain tappable; never crash. Items missing required fields (`video_id`/`title`/`owner_user_id`) are dropped during DTO→domain mapping rather than rendered broken.
- **Image (poster) load failure:** Defer to AND-103 placeholder/error drawables; detail screen provides tap-to-retry on the failed poster.
- **422 / validation errors:** `searchGallery` with a malformed/empty `q` may yield a 422 `HTTPValidationError`; map via `normalizeErrorDetail` (array of `{msg}`) to a user-facing message, not a crash.
- **Empty:** Distinct empty state — "No videos found" with sub-copy "No videos have been published to the gallery yet." (browse) or "Try a different search term." (search) — not an error.

## 8. Security & Privacy

- No new auth surface; all requests ride the existing Bearer token + cookie jar + `X-CSRF-Token` from `core-network`. Do not log cookies, CSRF tokens, Bearer/impersonation tokens, or full media URLs (which may contain signed query params) at info level.
- Treat `thumbnail_url` as potentially signed/expiring; do not persist it beyond the Coil/Room cache TTL and re-fetch the gallery page on cache miss to obtain fresh URLs.
- **PPV / access mode:** `price_cents`/`access_mode` indicate paid (PPV) videos. The gallery only browses metadata + poster; do not assume entitlement. Actual playback gating is the player/VOD feature's responsibility — this ticket must not expose paid content beyond the poster/metadata the API already returns.
- The dev backend is plaintext HTTP; the cleartext exception is configured app-wide (AND-019). Production builds must use HTTPS and `usesCleartextTraffic=false`; this ticket adds no cleartext config of its own.
- No PII is collected or stored by the gallery beyond what the API returns; titles/descriptions/tags are user-authored content shown as-is (rendered as plain text, no HTML interpretation, to avoid injection in `Text`).

## 9. Accessibility & i18n

- Every grid card poster and the detail poster has a `contentDescription` derived from `title` (and `description` where helpful), falling back to a localized "Gallery video" string; decorative chrome (badges already conveyed in text, etc.) uses `null` descriptions. Count chips (views/likes/comments) and duration/PPV badges carry text-equivalent descriptions.
- Detail controls (back/close, play affordance, like) have ≥48dp touch targets and labeled `Role.Button` semantics.
- The poster-zoom affordance (if implemented) is supplemented by system magnification for TalkBack users; category pills and search are standard focusable controls.
- All user-visible strings live in `feature-gallery/src/main/res/values/strings.xml`; view/like/comment counts use plural/format resources and the web `formatCount` convention (1.2K / 3.4M). Layout is RTL-safe (grid and detail honor layout direction). Respects system font scale and dynamic Material 3 color.

## 10. Telemetry & Logging

- Analytics events via the shared `core-ui`/`core-data` telemetry sink: `gallery_opened {category?}`, `gallery_page_loaded {category?, count}`, `gallery_category_selected {slug}`, `gallery_searched {queryLen}` (do not log raw query text as PII), `video_detail_opened {videoId}`, `gallery_load_error {stage: refresh|append|search, code}`. (Corrected from the original lightbox swipe/zoom events, which no longer apply.)
- Logging via the shared `Logger` at `debug` for load states and `warn` for handled errors; never log full URLs or tokens. Paging load-state transitions logged at `debug` behind a build-config flag.
- No third-party analytics SDK added by this ticket; events flow into whatever sink `core-data` provides (no-op in tests).

## 11. Testing Strategy

**Unit (JVM, `core-testing` + Turbine + MockWebServer):**
- `GalleryPagingSourceTest`: first page, `cursor` follow, last-page (`cursor == null`), HTTP 500 → `LoadResult.Error`, 401→refresh→retry path (mocked interceptor).
- `GalleryRepositoryTest`: DTO→`GalleryVideoItem` mapping incl. nullable `thumbnail_url`/`duration_seconds` and epoch `created_at`; default counts; malformed/required-field-missing item handling; stale fallback when refresh fails with cache present; category list extraction.
- `GalleryViewModelTest`: `uiState` transitions for refresh/retry, category selection, search query change; column count from window size; FastAPI `detail` variants (string / `[{msg}]` 422 / `{code}`) mapped to `errorMessage`.

**Instrumented / Compose (`createAndroidComposeRule`, Coil test `ImageLoader` with fake engine):**
- `GalleryScreenTest`: **grid renders** N video cards from seeded `PagingData` (poster, title, counts, duration/PPV badges); empty, error+retry, and stale-banner states; column count flips with window size; category pill selection re-queries; search submits; **tapping a card invokes `onItemClick(videoId)`** (satisfies "Gallery renders").
- `VideoDetailScreenTest`: **detail opens** for the tapped `video_id` showing poster, title, metadata, and counts; play affordance emits the deferred-play event; back/close returns to grid (satisfies "detail opens").
- Coil interactions stubbed via an injected test `ImageLoader`; no real network. Optional MockWebServer end-to-end test for `browseGallery`/`searchGallery` happy path.

Coverage target: ViewModel + repository + paging source ≥80% line coverage.

## 12. Dependencies & Sequencing

- **Depends on AND-103** (Coil image loading, placeholders, aspect handling, data-saver) — hard dependency; the grid/lightbox reuse its `MediaThumbnail`/`NetworkImage` composable and shared `ImageLoader`. Transitively depends on **AND-019** (network/image stack).
- Requires `core-network` authenticated Retrofit/OkHttp (cookie jar, CSRF, refresh-on-401), `core-model`, `core-ui`, `core-data`, `core-testing` to be in place.
- **Blocks:** nothing in the source bullets. A future video-playback-in-lightbox ticket (Media3/ExoPlayer) and gallery upload/edit tickets will build on this module; reference them when created.
- **Sequencing within ticket:** (1) module scaffold + DI + Retrofit `GalleryApi`; (2) repository + paging source + tests; (3) `GalleryViewModel` + state; (4) `GalleryScreen` grid; (5) `LightboxScreen` pager + gestures; (6) error/empty/stale/offline states; (7) a11y + telemetry; (8) instrumented tests.

## 13. Risks & Open Questions

- **Endpoint shape — RESOLVED in this review.** §5 now reflects the verified contract: `GET /ui/videos/gallery` (+ `/search`, `/categories`) → `GalleryListOut`/`GallerySearchOut`/`CategoriesOut` with `GalleryVideoItem` items and a `cursor` next-page field. The original `/ui/galleries/{id}/items` design was fictional.
- **Cursor actually paginates?** — the web page requests a single `limit:48` page and never reads `cursor` for a next page. It is unknown whether the backend returns a non-null `cursor` to drive infinite scroll, or whether 48 is effectively the whole gallery. Build the Paging source to follow `cursor` but tolerate a single-page result.
- **Detail screen API owner** — the web detail page fetches full video detail via `getVideoDetail` in `vod.ts` (a separate VOD feature), not a gallery endpoint, and uses `view`/`like`/`comments` POSTs. Confirm whether AND-201's detail screen owns those calls or defers to the VOD/engagement feature; this spec defers like/comments and treats detail as browse-only.
- **Video playback** — deferred to the player feature; confirm that a poster + deferred-play affordance is acceptable for M4, or whether inline ExoPlayer is required.
- **Offline depth** — whether full Room `RemoteMediator` persistence is required for M4 or whether Coil disk cache + single-page snapshot suffices for the stale banner.
- **Signed URL expiry** — TTL of `thumbnail_url` is unknown; affects how long cached posters remain loadable and the re-fetch strategy.
- **PPV/access semantics** — meaning of `access_mode` values and how `price_cents` gates browse vs. playback is unconfirmed; this ticket shows the PPV badge but assumes no entitlement.
- **Unreliable dev host** — flaky timeouts may surface as frequent error/stale states in QA; ensure tests use deterministic fakes, not the live host.

## 14. Acceptance Criteria

- **AC-1 (source: "Gallery renders"):** Navigating to the Gallery destination displays a multi-column grid of video cards loaded from `GET /ui/videos/gallery`, with poster placeholders during load (AND-103), duration/PPV badges and view/like/comment counts, and correct column count for portrait/landscape (2 / 4). Verified by `GalleryScreenTest` rendering seeded `PagingData`.
- **AC-2 (source: "lightbox opens" → video detail):** Tapping a grid card opens the full-screen video detail destination for that `video_id`, showing the poster, title, description, and metadata/counts; system back and the "Back to Gallery" control return to the grid. Verified by `VideoDetailScreenTest`.
- **AC-3:** Pull-to-refresh reloads the first page / current category; if the backend returns a non-null `cursor`, scrolling to the end auto-appends the next page and append errors show a retry footer that recovers on tap; a single-page gallery (null `cursor`) renders without an append footer.
- **AC-4:** Empty (browse + search variants), offline/error (full-screen retry), and stale-banner states each render correctly and are distinguishable.
- **AC-5:** Category pills filter the grid via `browseGallery({category})`; the search field queries `GET /ui/videos/gallery/search?q=` and active search clears the category filter (mirrors web behavior).
- **AC-6:** The detail screen shows poster + a centered play affordance without crashing and emits the deferred-play event for the player/VOD feature.
- **AC-7:** A 401 (while authenticated) triggers a single `POST /ui/session/refresh`+retry transparently; persistent failure surfaces the session-expired signal (logout), not a crash or blank grid.
- **AC-8:** All grid/detail posters carry meaningful `contentDescription`; controls (back, play, like, category pills) are ≥48dp and TalkBack-navigable.

## 15. Definition of Done

- `feature-gallery` module merged on `android-port` under `com.testlogon.android.feature.gallery`, wired into the app nav graph and Hilt graph.
- All §14 acceptance criteria pass; unit + instrumented tests green in CI; ViewModel/repository/paging coverage ≥80%.
- No new lint or detekt violations; Compose previews exist for grid (loading/loaded/empty/error/stale), video card (with/without thumbnail, PPV), and video detail.
- No cookies/CSRF/tokens/signed URLs logged; cleartext config unchanged (no new cleartext rules added by this ticket).
- Strings externalized and RTL/font-scale verified; data-saver preference honored.
- §5 API contract reconciled against `/openapi.json` (`GET /ui/videos/gallery` etc.) and `reference/src/api/endpoints/gallery.ts` — done in this review (see §16); remaining §13 open questions (cursor pagination behavior, detail-API owner, PPV semantics) either closed or filed as follow-up tickets.
- Builds with JDK 17 / AGP 8.7.3 / Gradle 8.9, minSdk 24 / target 35; runs against the dev backend `http://18.222.237.167:8000` with graceful degradation under timeout.

## 16. Citations & Assumption Audit

Each key technical claim with VERDICT (Verified / Corrected / Unverified-assumption) and SOURCE.

1. **Browse endpoint is `GET /ui/videos/gallery` (not `GET /ui/galleries/{id}/items`).** VERDICT: Corrected. SOURCE: OpenAPI `GET /ui/videos/gallery` (op `browse_gallery_endpoint`, resp `200:GalleryListOut`); `src/api/endpoints/gallery.ts: browseGallery` ("/ui/videos/gallery"); `src/pages/gallery/GalleryPage.tsx`.
2. **Search endpoint is `GET /ui/videos/gallery/search?q=` → `GallerySearchOut`.** VERDICT: Verified. SOURCE: OpenAPI `GET /ui/videos/gallery/search` (op `search_gallery_endpoint`); `src/api/endpoints/gallery.ts: searchGallery`.
3. **Categories endpoint is `GET /ui/videos/gallery/categories` → `CategoriesOut`.** VERDICT: Verified. SOURCE: OpenAPI `GET /ui/videos/gallery/categories`; `src/api/endpoints/gallery.ts: getGalleryCategories`.
4. **"For You" feed `GET /ui/videos/gallery/for-you` → `ForYouResponse`.** VERDICT: Verified (scoped out / optional). SOURCE: OpenAPI `GET /ui/videos/gallery/for-you`; `src/pages/videos/ForYouTab.tsx` (used by GalleryPage tab).
5. **Items are videos (`GalleryVideoItem`), not generic media; no `gallery_id`/`type`/`thumb_url`/`full_url`/`caption`/`width`/`height`.** VERDICT: Corrected. SOURCE: OpenAPI `components.schemas.GalleryVideoItem` (fields `video_id`,`title`,`owner_user_id` required; `thumbnail_url`,`duration_seconds`,`category`,`tags`,`view_count`,`like_count`,`comment_count`,`price_cents`,`access_mode`,`created_at`,`published_at`,`description`); `src/api/endpoints/gallery.ts: GalleryVideoItem`.
6. **Item navigation key is `video_id` via route `/gallery/{video_id}`.** VERDICT: Corrected (was `(galleryId, startIndex)`). SOURCE: `src/pages/gallery/GalleryVideoCard.tsx` (`Link to={`/gallery/${video.video_id}`}`); `src/pages/gallery/VideoDetailPage.tsx` (`useParams videoId`).
7. **Pagination field is `cursor` (next-page), not `next_cursor`.** VERDICT: Corrected. SOURCE: OpenAPI `GalleryListOut.cursor` / `GallerySearchOut.cursor`; `src/api/endpoints/gallery.ts: GalleryListResponse.cursor`. (`next_cursor` only exists on the unrelated `GalleryPageOut` for the messaging conversation gallery — `GET /messaging/conversations/{id}/gallery`.)
8. **`created_at`/`published_at` are Unix epoch integers (seconds), not ISO 8601 strings.** VERDICT: Corrected. SOURCE: OpenAPI `GalleryVideoItem.created_at`/`published_at` (`type: integer`); `src/pages/messages` and `src/pages/gallery/VideoDetailPage.tsx` (`new Date(c.created_at * 1000)`).
9. **`categories` is a list of `{slug,label}`.** VERDICT: Verified. SOURCE: `src/api/endpoints/gallery.ts: GalleryCategory`; OpenAPI types it loosely as `array<object additionalProperties true>` (frontend is the tighter contract). Verdict notes a minor schema looseness.
10. **The "lightbox" is a scrollable video **detail** page (poster + metadata + like + comments), not a swipe/pinch-zoom image pager.** VERDICT: Corrected. SOURCE: `src/pages/gallery/VideoDetailPage.tsx` (no HorizontalPager, no zoom; renders poster `object-contain`, engagement bar, comments). Original FR-3/FR-4/FR-5 lightbox-gesture claims removed/flagged.
11. **Detail fetches full video via `getVideoDetail` from `vod.ts` (VOD feature), not a gallery endpoint.** VERDICT: Verified. SOURCE: `src/pages/gallery/VideoDetailPage.tsx` (`import { getVideoDetail } from "@/api/endpoints/vod"`). Exact VOD route deferred — see Open assumptions.
12. **Engagement calls exist: `POST /ui/videos/{id}/view`, `POST/GET /ui/videos/{id}/like`, `GET/POST/DELETE /ui/videos/{id}/comments`.** VERDICT: Verified (deferred out of this ticket). SOURCE: `src/api/endpoints/gallery.ts: recordView/toggleLike/checkLike/addVideoComment/listVideoComments/deleteVideoComment`.
13. **Web requests `limit: 48`; single page, no infinite scroll in the page.** VERDICT: Verified. SOURCE: `src/pages/gallery/GalleryPage.tsx` (`browseGallery({ category, limit: 48 })`, `searchGallery({ q, limit: 48 })`). Whether `cursor` ever returns non-null = unverified (Open assumptions).
14. **Card layout: 16:9 poster (`aspect-video`), duration badge (mm:ss/h:mm:ss), PPV price badge when `price_cents > 0`, view/like/comment counts (formatCount K/M), up to 3 tags, "No thumbnail" placeholder when `thumbnail_url` absent.** VERDICT: Corrected (was square 1:1). SOURCE: `src/pages/gallery/GalleryVideoCard.tsx`.
15. **Web grid columns: 1/2/3/4 responsive.** VERDICT: Verified (Android adapted to 2/4). SOURCE: `src/pages/gallery/GalleryPage.tsx` (`grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4`). Android column counts (2 portrait / 4 expanded) = design choice.
16. **Empty-state copy: "No videos found" + "No videos have been published to the gallery yet." / "Try a different search term."** VERDICT: Verified. SOURCE: `src/pages/gallery/GalleryPage.tsx`.
17. **Auth = `Authorization: Bearer <accessToken>` + cookies (`credentials: include`) + `X-CSRF-Token` from `ui_csrf` cookie + optional `X-IMPERSONATION-TOKEN`.** VERDICT: Corrected (spec omitted Bearer + impersonation). SOURCE: `src/api/client.ts` (lines building headers in `api<T>`).
18. **401 handling: single `POST /ui/session/refresh` then one retry; only when already authenticated; retry-401 → logout `session_expired`.** VERDICT: Verified. SOURCE: `src/api/client.ts: refreshSession` + 401 branch.
19. **Error `detail` shapes: `string` | `[{msg}]` (422 `HTTPValidationError`) | `{code,...}` (e.g. `role_required_scope`, `geo_blocked`).** VERDICT: Verified. SOURCE: `src/api/client.ts: normalizeErrorDetail`/`mapAuthorizationError`; OpenAPI `resp ...;422:HTTPValidationError` on all four gallery routes.
20. **OpenAPI also lists `X-SESSION-ID`/`user_sub` params on gallery routes.** VERDICT: Verified-but-unused-by-web. SOURCE: OpenAPI index params for `browse_gallery_endpoint` etc.; web client (`client.ts`) does not send `X-SESSION-ID` (relies on cookie+Bearer). Treated as server-side alternate; Android follows the web client.
21. **Two distinct "galleries" exist; this ticket = video gallery, NOT the messaging conversation gallery.** VERDICT: Verified (disambiguation). SOURCE: OpenAPI `GET /messaging/conversations/{id}/gallery` → `GalleryPageOut`/`GalleryItemOut` (file attachments: `conversation_id`,`message_id`,`file_name`,`content_type`,`size`); distinct from `GalleryVideoItem`. `src/pages/messages/ConversationGallery.tsx`.
22. **Stack choices (Paging 3 cursor `PagingSource`, `LazyVerticalGrid`/`GridCells.Fixed`, `WindowSizeClass`, Coil, Compose nav type-safe routes).** VERDICT: Unverified-assumption (framework ref). SOURCE: framework ref — Android Paging 3 (`developer.android.com/topic/libraries/architecture/paging/v3-paged-data`), `LazyVerticalGrid` (`developer.android.com/develop/ui/compose/lists`), WindowSizeClass (`developer.android.com/develop/ui/compose/layouts/adaptive`). Reasonable defaults, not dictated by sources.

### Corrections made
- §1, §3 (FR-1..FR-8), §4, §5, §6, §7, §9, §10, §11, §13, §14: re-modeled from a generic image gallery (`/ui/galleries/{id}/items`, `GalleryItem`, image lightbox with pinch/zoom/pager) to the actual **video gallery** (`/ui/videos/gallery` + search/categories, `GalleryVideoItem`, video **detail** screen).
- Pagination field `next_cursor` → `cursor` (the `next_cursor` shape belongs to the unrelated messaging conversation gallery).
- Navigation key `(galleryId, startIndex)` → `videoId`; route `/gallery/{video_id}`.
- Timestamps ISO string → Unix epoch seconds (integer).
- Card aspect 1:1 square → 16:9 (`aspect-video`); added duration/PPV badges and counts; default columns 3/5 → 2/4.
- Auth description: added `Authorization: Bearer` token and `X-IMPERSONATION-TOKEN` (spec previously listed only cookie + CSRF).
- Telemetry events: removed lightbox swipe/zoom/index events; added category/search/detail events.
- Removed the non-existent `type ∈ {image,video}` enum, `poster_url`/`playback_url`, per-item GET, and `GET /ui/galleries` list endpoint.

### Open assumptions
- **Does `cursor` ever return non-null?** Unverifiable from sources — the web page only ever requests one `limit:48` page and never reads `cursor` for a follow-up. The Paging source must follow `cursor` but tolerate single-page galleries.
- **Exact VOD detail route/owner.** `VideoDetailPage.tsx` calls `getVideoDetail` from `vod.ts`, which was not opened in this review; the precise endpoint and whether AND-201 owns it vs. the VOD feature is unconfirmed. This ticket defers detail-fetch ownership and like/comment CRUD.
- **`access_mode` value set & PPV gating semantics.** Not defined in the gallery sources; badge shown, entitlement assumed false.
- **`thumbnail_url` TTL / signing.** Unknown; affects offline cache validity and re-fetch.
- **Android column counts (2/4), Paging config (pageSize 48), and Room/RemoteMediator depth.** Design choices, not dictated by the backend/web sources.

## 17. Test Plan

Test targets: **JVM** = JVM unit/Robolectric (local). **Emulator** = headless AVD `test35` (x86_64, API 35). **Device** = physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). Most cases here are network/UI and run on JVM or Emulator; a few are noted for the Device where ABI/API-34 behavior or real-network matters. No case in this ticket strictly requires camera/biometrics/WebRTC/FCM/Telecom hardware (gallery is browse + detail only).

- **TC-AND-201-01** — Type: contract/MockWebServer (JVM). Target: `GalleryPagingSource` + `GalleryApi.browseGallery`. Preconditions: MockWebServer returns a valid `GalleryListOut` page (videos[], categories[], `cursor:"c2"`). Steps: load first page; then load page keyed by `cursor`. Expected: first `LoadResult.Page` has the videos, `nextKey="c2"`; second request sends `?cursor=c2`. Traces: AC-1, AC-3.
- **TC-AND-201-02** — Type: contract/MockWebServer (JVM). Target: `GalleryPagingSource` last page. Preconditions: response with `cursor: null` (absent). Steps: load page. Expected: `LoadResult.Page.nextKey == null`; no append footer requested. Traces: AC-3.
- **TC-AND-201-03** — Type: unit (JVM). Target: `GalleryRepository` DTO→`GalleryVideoItem` mapping. Preconditions: JSON with nullable `thumbnail_url`/`duration_seconds`, integer epoch `created_at`, default counts, item missing required `video_id`. Steps: map page. Expected: nulls preserved; `created_at` kept as epoch Long; counts default 0; the required-field-missing item is dropped (not a crash). Traces: AC-1.
- **TC-AND-201-04** — Type: contract/MockWebServer (JVM). Target: `GalleryApi.searchGallery`. Preconditions: server returns `GallerySearchOut` (videos, cursor; no categories). Steps: call with `q="bay"`. Expected: request path `ui/videos/gallery/search?q=bay&limit=48`; response parsed; no categories field required. Traces: AC-5.
- **TC-AND-201-05** — Type: unit (JVM). Target: `GalleryViewModel` error mapping. Preconditions: API yields 422 `HTTPValidationError` (`detail:[{msg:"..."}]`), then a `{code:"role_required"}` 403, then a plain-string detail. Steps: trigger each. Expected: `uiState.errorMessage` is the joined `msg` for 422, the mapped permission copy for the code, and the raw string otherwise (matches `normalizeErrorDetail`). Traces: AC-4, AC-7.
- **TC-AND-201-06** — Type: unit (JVM). Target: `GalleryViewModel` category/search state. Preconditions: seeded categories. Steps: select a category pill, then submit a search. Expected: selecting category sets `selectedCategory` and re-queries `browseGallery(category)`; submitting search sets `searchQuery`, clears `selectedCategory` (mirrors web). Traces: AC-5.
- **TC-AND-201-07** — Type: contract/MockWebServer (JVM). Target: 401 refresh-and-retry interceptor. Preconditions: first GET → 401 while authenticated; `POST /ui/session/refresh` → 200; retried GET → 200. Steps: load first page. Expected: exactly one refresh, one retry, page returned; with refresh→401, a `session_expired` signal (logout) and no crash. Traces: AC-7.
- **TC-AND-201-08** — Type: Compose-UI (Emulator). Target: `GalleryScreen` grid render. Preconditions: seeded `PagingData` of N `GalleryVideoItem` via test `ImageLoader`. Steps: render. Expected: N video cards visible with poster, title, view/like/comment counts; duration badge when `duration_seconds>0`; PPV badge when `price_cents>0`; "No thumbnail" placeholder when `thumbnail_url` null. Traces: AC-1.
- **TC-AND-201-09** — Type: Compose-UI (Emulator). Target: `GalleryScreen` adaptive columns. Preconditions: seeded grid; compact then expanded window size. Steps: set `WindowWidthSizeClass` compact → expanded. Expected: 2 columns compact, 4 columns expanded. Traces: AC-1.
- **TC-AND-201-10** — Type: Compose-UI (Emulator). Target: `GalleryScreen` empty/error/stale. Preconditions: paging `LoadState` driven to (a) NotLoading+empty, (b) refresh Error, (c) cached items + refresh Error. Steps: render each. Expected: (a) "No videos found" empty copy (browse vs. search variant), (b) full-screen error + retry that recovers on tap, (c) cached grid + dismissible stale banner (no blank screen). Traces: AC-3, AC-4.
- **TC-AND-201-11** — Type: Compose-UI (Emulator). Target: grid tap → navigation. Preconditions: seeded grid. Steps: tap a card. Expected: `onItemClick(videoId)` invoked with that item's `video_id`. Traces: AC-2.
- **TC-AND-201-12** — Type: Compose-UI (Emulator). Target: `VideoDetailScreen`. Preconditions: detail destination for a seeded `video_id`. Steps: render; tap play affordance; press back. Expected: poster + title + description + counts shown; play affordance emits the deferred-play event; back/"Back to Gallery" pops to the grid with scroll position preserved. Traces: AC-2, AC-6.
- **TC-AND-201-13** — Type: Compose-UI accessibility (Emulator). Target: grid + detail semantics. Preconditions: seeded data. Steps: assert semantics. Expected: each poster has a meaningful `contentDescription` (from title, fallback "Gallery video"); back/play/like/category-pill controls expose `Role.Button` and ≥48dp touch targets; decorative chrome has null description. Traces: AC-8.
- **TC-AND-201-14** — Type: instrumented/e2e (Device — physical Galaxy A15, API 34/arm64). Target: live browse against dev host with flaky-network/offline handling. Preconditions: app pointed at `http://18.222.237.167:8000` (cleartext exception present); toggle airplane mode mid-test. Steps: open Gallery online (real poster loads via Coil), then go offline and pull-to-refresh. Expected: online grid renders; offline shows stale banner over Coil-cached posters or full-screen retry, never a crash/ANR; recovers on reconnect. Run on Device to exercise real arm64 build, API-34 cleartext/network behavior, and real timeout/flakiness (not deterministic on emulator). Traces: AC-1, AC-3, AC-4.
- **TC-AND-201-15** — Type: manual (Device). Target: data-saver + RTL + font scale. Preconditions: enable system data-saver, switch locale to an RTL pseudo-locale, max font scale. Steps: browse gallery + open a detail. Expected: smaller poster variants/deferred loads honored; grid + detail mirror correctly in RTL; text scales without truncation/overlap. Traces: AC-1, AC-8.

### Coverage matrix
- **AC-1** (grid renders from `GET /ui/videos/gallery`): TC-01, TC-03, TC-08, TC-09, TC-14, TC-15.
- **AC-2** (tap → video detail by `video_id`): TC-11, TC-12.
- **AC-3** (refresh / cursor append / append-retry): TC-01, TC-02, TC-10, TC-14.
- **AC-4** (empty / error / stale states): TC-05, TC-10, TC-14.
- **AC-5** (categories + search): TC-04, TC-06.
- **AC-6** (poster + deferred-play affordance): TC-12.
- **AC-7** (401 refresh+retry / session-expired): TC-05, TC-07.
- **AC-8** (a11y: contentDescription, ≥48dp, TalkBack): TC-13, TC-15.
