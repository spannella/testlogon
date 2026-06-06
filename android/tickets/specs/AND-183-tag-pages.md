---
id: AND-183
title: Tag pages
milestone: M4
epic: E25
priority: P2
size: M
depends_on: [AND-182]
blocks: []
status: reviewed
reviewed_on: 2026-06-06
---

# AND-183 — Tag pages

## 1. Overview & Goal

This ticket delivers the **tag listing page**: a dedicated, paged content screen that
shows all content associated with a single tag. A tag page is reached from a tappable tag
chip on the Discover screen (AND-182), from tag chips rendered on content detail/feed
items, and directly from outside the app via an Android **App Link** of the form
`https://testlogon.com/discover/tags/{tag}` (and the matching plaintext/dev host). The
screen is a Paging 3 vertical grid mirroring the web reference route `discover/tags/:tag`.

The goal is a self-contained `feature-tags` module that:

1. Resolves a `tag` slug from either an in-app navigation argument or a deep/App Link.
2. Loads a paged list of content items filtered by that tag from the discovery API.
3. Renders the items in a Material 3 lazy grid with loading, empty, error/offline, and
   stale states, and navigates into the existing content detail destination on tap.

Success is defined by the backlog acceptance bullet — **"Tag page loads content."** — made
concrete by the testable criteria in §14.

## 2. Context & References

- **Web reference route:** `discover/tags/:tag`. The web Discover/tag data layer lives in
  `frontend/src/api/endpoints/discovery.ts` (introduced for AND-182); shared response
  types are in `frontend/src/api/types.ts`. This ticket reuses the discovery endpoint with
  a `tag` filter rather than introducing a new endpoint family.
- **Upstream dependency AND-182 (Discover screen):** establishes `feature-discover`, the
  `discovery.ts`-equivalent `DiscoveryApi`/`DiscoveryRepository` in `core-data`, the
  `ContentCard` composable, and the curated/discover grid pattern. AND-183 consumes those
  building blocks; the tag chip that opens this page is added to Discover here.
- **Transitive dependencies via AND-182:** AND-027 (content card / content model) and
  AND-103 (paging + grid scaffolding).
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext HTTP,
  unreliable). OpenAPI at `/openapi.json`. Cookie-based session with `ui_csrf` echoed as
  `X-CSRF-Token`; persistent cookie jar and single `POST /ui/session/refresh`-on-401 retry
  are provided by `core-network` (AND-001..AND-010 auth stack). Discover/tag content is
  served under the `/ui/discover*` surface.
- **Module layering:** `app -> feature-tags -> core-* (core-network, core-model, core-ui,
  core-data, core-testing)`. Namespace/applicationId base: `com.testlogon.android`.

## 3. Functional Requirements

FR-1. A tag page MUST be openable from in-app navigation with route
`discover/tags/{tag}`, where `{tag}` is a URL-encoded tag slug.

FR-2. A tag page MUST be openable from an external **App Link**
`https://testlogon.com/discover/tags/{tag}` (verified `autoVerify` link) and from the dev
plaintext host as a non-verified deep link. The `{tag}` path segment MUST be URL-decoded
before use.

FR-3. The screen MUST display the resolved tag name in the top app bar title (prefixed with
`#`, e.g. `#kotlin`).

FR-4. On entry the screen MUST request the first page of tag-filtered content and render a
responsive grid (2 columns in portrait compact width, 3 columns in expanded/landscape) of
`ContentCard`s reused from AND-182.

FR-5. The grid MUST support **infinite scroll pagination** (Paging 3): subsequent pages are
fetched as the user nears the end of the list; a footer loading indicator is shown while
appending and a footer retry affordance on append failure.

FR-6. Tapping a content item MUST navigate to the existing post detail destination
(`posts/{postId}`) owned by the feed/post-detail feature, passing the `post_id`. (Corrected:
the web reference route is `posts/:postId` → `PostDetailPage`, not `content/{contentId}`;
items are `FeedPost` keyed by `post_id`, not a generic content id. See
`src/App.tsx: posts/:postId` and `src/pages/discover/TagPage.tsx`.)

FR-7. The screen MUST present distinct UI states: initial loading (shimmer placeholders),
loaded with content, **empty** (tag resolved but no content), and **error/offline**
(retryable). It MUST support pull-to-refresh that re-requests page 1.

FR-8. When cached content for the tag exists but the network is unavailable, the screen MUST
render cached items with a **stale** banner rather than a blank error state.

FR-9. Tag slugs are treated case-insensitively for display normalization but passed to the
API exactly as received (decoded) to match backend behavior.

## 4. Technical Design

New module **`feature-tags`** (Gradle module `:feature:tags`, namespace
`com.testlogon.android.feature.tags`). Layering: depends on `core-model`, `core-data`,
`core-ui`, `core-network` (transitively), `core-testing` (test only). Hilt + KSP.

### Navigation

```kotlin
// com.testlogon.android.feature.tags.nav
object TagsRoutes {
    const val TAG_ARG = "tag"
    const val PATTERN = "discover/tags/{tag}"
    fun route(tag: String): String = "discover/tags/${Uri.encode(tag)}"
}

fun NavGraphBuilder.tagPageScreen(
    onContentClick: (contentId: String) -> Unit,
    onBack: () -> Unit,
) {
    composable(
        route = TagsRoutes.PATTERN,
        arguments = listOf(navArgument(TagsRoutes.TAG_ARG) { type = NavType.StringType }),
        deepLinks = listOf(
            navDeepLink { uriPattern = "https://testlogon.com/discover/tags/{tag}" },
            navDeepLink { uriPattern = "http://18.222.237.167:8000/discover/tags/{tag}" },
        ),
    ) { TagPageRoute(onContentClick = onContentClick, onBack = onBack) }
}
```

### App Link registration (app module manifest)

```xml
<activity android:name="com.testlogon.android.MainActivity" android:exported="true">
    <intent-filter android:autoVerify="true">
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="https" android:host="testlogon.com"
              android:pathPrefix="/discover/tags/" />
    </intent-filter>
</activity>
```

A `/.well-known/assetlinks.json` entry (SHA-256 of the signing cert) is required on
`testlogon.com` for verification; this is tracked as an open question (§13) since it is a
server-side artifact. The dev plaintext host is registered without `autoVerify`.

### ViewModel & state

```kotlin
@HiltViewModel
class TagPageViewModel @Inject constructor(
    private val discoveryRepository: DiscoveryRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    val tag: String = checkNotNull(savedStateHandle.get<String>(TagsRoutes.TAG_ARG))
        .let { Uri.decode(it) }

    private val refreshTrigger = MutableStateFlow(0L)

    val uiState: StateFlow<TagPageUiState> = ...      // header/empty/stale meta
    val content: Flow<PagingData<ContentItem>> =
        refreshTrigger.flatMapLatest {
            discoveryRepository.tagContentPager(tag)   // Pager<...>.flow
        }.cachedIn(viewModelScope)

    fun refresh() { refreshTrigger.value = SystemClock.elapsedRealtime() }
}

data class TagPageUiState(
    val tag: String,
    val titleDisplay: String,          // "#$tag"
    val isStale: Boolean = false,
    val headerError: ApiError? = null, // non-paging header errors only
)
```

`TagPageRoute` collects `content` via `collectAsLazyPagingItems()` and renders
`TagPageScreen` (stateless). Grid built on `LazyVerticalGrid(GridCells.Fixed(columns))`
reusing `ContentCard` from `core-ui`/`feature-discover`. `LoadState.Refresh`,
`LoadState.Append`, and `LoadState.Prepend` drive shimmer / footer-spinner / footer-retry.

### Repository / paging source

```kotlin
interface DiscoveryRepository {
    fun tagContentPager(tag: String): Flow<PagingData<ContentItem>>
}

class TagPagingSource(
    private val api: DiscoveryApi,
    private val tag: String,
) : PagingSource<String, ContentItem>() {  // String = opaque cursor
    override suspend fun load(params: LoadParams<String>): LoadResult<String, ContentItem>
}
```

The `PagingSource` keys off the backend's opaque `next_cursor` (verified present in the
web DTO `TagDiscoverResponse.next_cursor`). Page size = 24. The backend `limit` query
param has a documented **maximum of 50** (default 20) per `GET /ui/discover/tags/{tag}`, so
`pageSize`/`initialLoadSize` MUST stay ≤ 50; 24 is within range.
`Pager(PagingConfig(pageSize = 24, initialLoadSize = 24, prefetchDistance = 6))`.

Note: the web reference (`src/pages/discover/TagPage.tsx`) does a single non-paged fetch
(`getPostsByTag(tag, 50)`) and renders a vertical list, not a grid; it does not follow
`next_cursor`, pull-to-refresh, or show a stale/offline banner. The paged grid, infinite
scroll, pull-to-refresh, and stale-banner behaviors in this spec are Android-port
enhancements built on the same endpoint, not a 1:1 mirror of current web behavior.

## 5. API Contract

Tag content uses the existing discovery endpoint **`GET /ui/discover/tags/{tag}`**
(verified: OpenAPI op `discover_tag_ui_discover_tags__tag__get`, params `tag` (path),
`limit` (query, default 20, **min 1 / max 50**), `cursor` (query, nullable string); web
caller `src/api/endpoints/discovery.ts: getPostsByTag`). The endpoint returns "posts tagged
with a specific hashtag, newest first."

```kotlin
interface DiscoveryApi {
    @GET("ui/discover/tags/{tag}")
    suspend fun getTagContent(
        @Path("tag") tag: String,
        @Query("limit") limit: Int = 24,   // 1..50; web default is 20
        @Query("cursor") cursor: String? = null,
    ): Response<TagContentResponse>
}
```

Request: `GET /ui/discover/tags/kotlin?limit=24` (no cursor for page 1), cookies +
`X-CSRF-Token: <ui_csrf>` attached by the shared OkHttp interceptors. (Verified: the web
`client.ts` sets `X-CSRF-Token` from the `ui_csrf` cookie on **all** requests including GET,
and also sends `credentials: include`. Note the web client additionally sends an
`Authorization: Bearer` header from its auth store; the Android cookie-session stack is owned
by AND-001..AND-010 and out of scope here — see §16 open assumptions.)

Response `200` (corrected — the field is **`posts`**, not `items`, and items are
**`FeedPost`** objects, not the previously assumed generic content shape):

```json
{
  "tag": "kotlin",
  "posts": [
    {
      "post_id": "post_01H...",
      "author_id": "usr_01H...",
      "body": "Intro to Coroutines",
      "image_urls": ["https://.../img.jpg"],
      "video": {
        "video_id": "vid_01H...",
        "title": "Intro to Coroutines",
        "thumbnail_url": "https://.../thumb.jpg",
        "duration_seconds": 612
      }
    }
  ],
  "next_cursor": "eyJwayI6..."   // null/absent on last page
}
```

Source for the response shape: `src/api/endpoints/discovery.ts: TagDiscoverResponse`
(`{ tag: string; posts: FeedPost[]; next_cursor?: string }`) and
`src/api/types.ts: FeedPost` (`post_id`, `author_id`, `body`, optional `video { video_id,
title, thumbnail_url, duration_seconds, ... }`, `image_urls`, etc.). `FeedPost` is a rich
type — the Android `ContentItem` domain model maps only the fields the card needs
(`post_id`, display title/body, thumbnail from `video.thumbnail_url` or first `image_urls`,
kind/duration from `video`).

Errors: the OpenAPI spec documents only **`200`** and **`422` HTTPValidationError** for this
endpoint — there is **no documented `404`** for an unknown tag. (Corrected: the prior
"`404` unknown tag" claim is not supported by the sources; an unknown/empty tag returns
`200` with an empty `posts` array — the web `TagPage` renders its empty state purely from
`posts.length === 0`.) `422` is the FastAPI validation envelope (`detail: [{loc,msg,type}]`),
mapped by the shared `errorBodyToApiError(...)` into `ApiError`; FastAPI `detail` may also be
a string or object on other surfaces. `next_cursor == null` ends pagination (`nextKey =
null`).

DTO → domain mapping lives in `core-data`:

```kotlin
@JsonClass(generateAdapter = true)
data class TagContentResponse(
    @Json(name = "tag") val tag: String,
    @Json(name = "posts") val posts: List<FeedPostDto>,
    @Json(name = "next_cursor") val nextCursor: String?,
)
fun TagContentResponse.toDomain(): TagPage   // maps FeedPostDto -> ContentItem
```

## 6. Data & State Management

- **Source of truth:** `PagingData<ContentItem>` from `tagContentPager(tag)`, cached in
  `viewModelScope` so config changes/back-stack returns don't refetch.
- **Caching (Room, optional read-through):** a `RemoteMediator<String, ContentItemEntity>`
  may back the pager with a `tag_content` Room table keyed by `(tag, contentId, position)`
  to satisfy FR-8 (stale offline render). MVP may ship network-only paging with stale-banner
  driven purely by `LoadState` + last-good cache; the RemoteMediator path is the preferred
  design and is recommended if AND-103 scaffolding already provides it. State of this choice
  is recorded in §13.
- **Prefs (DataStore):** none required for this screen.
- **State exposure:** ViewModel exposes `StateFlow<TagPageUiState>` (header meta) plus the
  separate `Flow<PagingData<ContentItem>>`. Loading/empty/error for the list itself are
  derived from `LazyPagingItems.loadState` in the composable, not duplicated in
  `UiState`, to avoid divergence.
- **Process death:** `tag` survives via `SavedStateHandle`; paging restarts from page 1,
  which is acceptable and consistent with web behavior.

## 7. Error Handling & Resilience

- **Timeouts/retries:** GETs are idempotent — rely on `core-network`'s bounded-backoff
  retry for idempotent GETs and ~20s timeout. No client-side retry for non-GET (none here).
- **401:** transparent single `POST /ui/session/refresh` then retry, handled by the shared
  authenticator; the screen never implements this itself.
- **Initial load failure (`LoadState.Refresh is Error`):** full-screen retryable error
  (or stale cache + banner per FR-8 when cache exists).
- **Append failure (`LoadState.Append is Error`):** inline footer with message + Retry
  button calling `lazyItems.retry()`; existing items stay visible.
- **Unknown/empty tag:** the endpoint returns `200` with an empty `posts` array (no `404`
  is documented; corrected from the prior draft). This renders the empty state with
  "No posts tagged #<tag> yet" copy (matches web `TagPage`). A `422` (malformed `tag`/params)
  maps to the retryable error state.
- **Offline:** detected via load error type / connectivity; render stale cache when present,
  else offline empty state with Retry.
- **Pull-to-refresh:** `refresh()` bumps trigger → new `PagingSource`; spinner via
  `PullToRefreshBox` tied to `LoadState.Refresh is Loading`.

## 8. Security & Privacy

- All requests ride the existing cookie-based session and `X-CSRF-Token` header from the
  persistent cookie jar; this screen adds no new credential handling.
- The `{tag}` path segment is URL-decoded then re-encoded via `Uri.encode` when constructing
  in-app routes; raw deep-link input is never concatenated into requests without going
  through Retrofit `@Path` encoding, preventing path-injection.
- App Link `autoVerify` requires the server-published `assetlinks.json`; until verified,
  links open via the chooser. No secrets are embedded in the manifest.
- Deep-link entry MUST respect auth gating: an unauthenticated cold-start deep link routes
  through the existing auth gate (AND auth stack) and resumes to the tag page post-login; it
  must not bypass session establishment.
- No PII is logged; tag slugs are non-sensitive but treated as user input for sanitization.

## 9. Accessibility & i18n

- All strings (`#%1$s` title format, empty/error/stale copy, "Retry") live in
  `feature-tags` `strings.xml`; no hardcoded UI text. Pseudolocale-tested.
- `ContentCard` carries `contentDescription` (title + kind/duration) reused from AND-182.
- Touch targets ≥ 48dp; grid items focusable and TalkBack-navigable in reading order.
- The footer Retry button and stale banner are announced; loading state uses
  `Modifier.semantics { stateDescription = "Loading" }`.
- Grid column count adapts to font scale / width size class; supports landscape and large
  fonts without clipping.
- RTL supported via standard Compose layout (no hardcoded start/end).

## 10. Telemetry & Logging

Emit via the shared analytics interface (no PII):

- `tag_page_open` { tag, source: "discover" | "deeplink" | "applink" | "content" }.
- `tag_page_load_result` { tag, result: "success" | "empty" | "error", item_count,
  latency_ms }.
- `tag_page_paginate` { tag, page_index, result }.
- `tag_content_click` { tag, post_id, position }.
- `tag_page_refresh` { tag }.

Logging uses the app `Logger` at DEBUG for load/cursor transitions and WARN for mapped
`ApiError`s; raw response bodies are not logged in release builds.

## 11. Testing Strategy

**Unit (JVM, `core-testing` + Turbine + MockWebServer):**
- `TagPagingSource.load` — page 1 (null cursor), next page (cursor forwarded),
  last page (`next_cursor` null → `nextKey == null`), HTTP error → `LoadResult.Error`,
  `422` validation mapping, and empty-`posts` (200) → empty page.
- `TagContentResponse.toDomain()` field mapping (`posts` → `ContentItem`, `post_id`,
  thumbnail from `video.thumbnail_url`/`image_urls`) incl. null `next_cursor` and empty
  `posts`.
- `TagPageViewModel` — `tag` decoded from `SavedStateHandle`; `refresh()` re-emits a new
  `PagingData`; `titleDisplay == "#$tag"`.
- FastAPI `detail` variants (string / list / object) → correct `ApiError`.

**UI (Compose, `createAndroidComposeRule`, fake repository emitting `PagingData`):**
- Loading shimmer → loaded grid; item tap invokes `onContentClick` with id.
- Empty state for empty `posts`; error state + Retry triggers reload; append error footer.
- Stale banner shown when offline-with-cache.
- Column count 2 (compact) vs 3 (expanded) via test config.

**Instrumented / integration:**
- App Link intent test: launch `https://testlogon.com/discover/tags/kotlin` →
  `TagPageScreen` with title `#kotlin` and decoded tag; URL-encoded tag (`c%2B%2B`)
  decodes to `c++`.
- MockWebServer-backed end-to-end page load + pagination.

Coverage target consistent with repo gate (≥ 80% line in `feature-tags` domain/VM).

## 12. Dependencies & Sequencing

- **Hard dependency:** AND-182 (Discover screen) — provides `DiscoveryApi`/repository,
  `ContentCard`, grid pattern, and the tag chip entry point. Cannot start the data layer
  before AND-182's `discovery.ts`-equivalent exists.
- **Transitive:** AND-027 (content model/card), AND-103 (paging/grid scaffolding) via
  AND-182.
- **Auth stack** (cookie jar, CSRF, refresh-on-401) assumed complete from M0/M1.
- **Blocks:** none recorded in backlog.
- **Sequencing:** (1) extend `DiscoveryApi` + DTOs + `TagPagingSource` in `core-data`;
  (2) `TagPageViewModel` + state; (3) `TagPageScreen`/`TagPageRoute` UI; (4) nav graph +
  manifest App Link + Discover tag-chip wiring; (5) tests + assetlinks coordination.

## 13. Risks & Open Questions

- **Exact endpoint shape: RESOLVED.** Confirmed `GET /ui/discover/tags/{tag}` with
  `limit` (1..50, default 20) + nullable `cursor`, returning `{ tag, posts: FeedPost[],
  next_cursor? }` (OpenAPI `discover_tag_ui_discover_tags__tag__get`;
  `src/api/endpoints/discovery.ts: getPostsByTag`/`TagDiscoverResponse`). The cursor is an
  opaque string (`next_cursor`), not a page offset. The only remaining unknown is the exact
  internal cursor encoding (server-opaque — treat as a black box).
- **assetlinks.json:** App Link verification depends on a server artifact on `testlogon.com`
  not owned by this module/app. Risk: unverified links fall back to chooser. Owner/ticket
  for publishing `assetlinks.json` is an open question to resolve with backend/infra.
- **Offline cache (FR-8):** RemoteMediator+Room vs network-only. If AND-103 did not provide
  RemoteMediator scaffolding, MVP ships network-only with degraded stale support; full
  offline caching may spin out into a follow-up.
- **Dev host reliability:** plaintext `18.222.237.167:8000` flakiness can make pagination
  tests nondeterministic; rely on MockWebServer for CI.
- **Tag canonicalization:** server case/normalization rules for slugs are unconfirmed;
  current design passes the decoded slug verbatim.

## 14. Acceptance Criteria

AC-1. Navigating to `discover/tags/{tag}` (in-app) renders `TagPageScreen` with title
`#<tag>` and loads page 1 content. **(maps backlog: "Tag page loads content.")**

AC-2. Launching App Link `https://testlogon.com/discover/tags/<tag>` from outside the app
opens the tag page with the correctly URL-decoded tag and loads its content.

AC-3. Scrolling to the end fetches and appends the next page using `next_cursor`; pagination
stops cleanly when `next_cursor` is null with no footer spinner.

AC-4. Tapping a content item navigates to `posts/{postId}` with the correct `post_id`.

AC-5. Empty (unknown/empty tag → `200` with empty `posts`), full-screen error+Retry
(incl. `422`), append-error footer+Retry, and offline-stale-banner states each render under
their respective conditions.

AC-6. Pull-to-refresh re-requests page 1 and resets the list.

AC-7. Grid shows 2 columns in compact width and 3 in expanded; all items are
TalkBack-accessible with content descriptions.

AC-8. Unit + UI + the App Link instrumented test pass in CI; `feature-tags` meets the
coverage gate.

## 15. Definition of Done

- `:feature:tags` module created under `com.testlogon.android.feature.tags`, wired into the
  app nav graph; builds with Gradle 8.9 / AGP 8.7.3 / JDK 17, compileSdk/targetSdk 35.
- `DiscoveryApi.getTagContent`, DTOs, `toDomain()`, `TagPagingSource`, and
  `DiscoveryRepository.tagContentPager` implemented and unit-tested against the confirmed
  `/openapi.json` shape.
- `TagPageViewModel` exposes `StateFlow<TagPageUiState>` + `Flow<PagingData<ContentItem>>`;
  `TagPageScreen` renders all states from §7 with reused `ContentCard`.
- App Link intent-filter (`autoVerify`) + dev-host deep link registered; Discover tag chips
  navigate via `TagsRoutes.route(tag)`; deep links respect the auth gate.
- All strings externalized/localized; a11y checks pass; telemetry events from §10 emitted.
- Unit, Compose UI, and App Link instrumented tests green in CI; coverage gate met; lint &
  detekt clean.
- §13 open questions (endpoint shape, assetlinks ownership, offline-cache scope) resolved or
  explicitly deferred with linked follow-up tickets. Code reviewed and merged to
  `android-port`.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **Tag content endpoint is `GET /ui/discover/tags/{tag}`.** — **Verified.**
   OpenAPI `GET /ui/discover/tags/{tag}` (op `discover_tag_ui_discover_tags__tag__get`);
   frontend `src/api/endpoints/discovery.ts: getPostsByTag`.
2. **Query params are `limit` and `cursor`; path param `tag`.** — **Verified.** OpenAPI
   `GET /ui/discover/tags/{tag}` params: `tag` (path, required, string), `limit` (query,
   default 20, min 1, max 50), `cursor` (query, nullable string).
3. **`limit` default 20, max 50 (spec uses 24).** — **Corrected/clarified.** Spec previously
   stated `limit = 24` with no bound; 24 is valid (≤ 50) but the web default is 20 and the
   web TagPage requests 50. Source: OpenAPI param schema (`maximum: 50, default: 20`);
   `src/pages/discover/TagPage.tsx: getPostsByTag(tag!, 50)`.
4. **Response field is `posts` (array of `FeedPost`), not `items`.** — **Corrected.** Prior
   draft used `items` with an invented `{id,title,thumbnail_url,kind,duration_seconds,tags}`
   shape. Source: `src/api/endpoints/discovery.ts: TagDiscoverResponse`
   (`{ tag; posts: FeedPost[]; next_cursor? }`); `src/api/types.ts: FeedPost`
   (`post_id`, `author_id`, `body`, `image_urls?`, `video?{ video_id, title,
   thumbnail_url?, duration_seconds? }`, ...). The OpenAPI `200` schema itself is empty
   (`{}`), so the field shape is taken from the frontend contract (authoritative for the
   web client).
5. **Item identifier is `post_id`, not a generic `id`/`contentId`.** — **Corrected.** Source:
   `src/api/types.ts: FeedPost.post_id`; `src/pages/discover/TagPage.tsx`
   (`key={post.post_id}`).
6. **Pagination cursor field is `next_cursor` (opaque string), null/absent on last page.** —
   **Verified.** Source: `src/api/endpoints/discovery.ts: TagDiscoverResponse.next_cursor`;
   OpenAPI `cursor` param is a nullable string (not a numeric offset).
7. **Post detail destination is `posts/{postId}`, not `content/{contentId}`.** —
   **Corrected.** Source: `src/App.tsx` route `posts/:postId` → `PostDetailPage`. No
   `content/:contentId` route exists in the reference app.
8. **Web route for the tag page is `discover/tags/:tag`.** — **Verified.**
   `src/App.tsx` route `discover/tags/:tag` → `TagPage`.
9. **GET requests carry `X-CSRF-Token` (from `ui_csrf` cookie) plus cookies.** —
   **Verified.** `src/api/client.ts`: reads `getCookie("ui_csrf")` and sets
   `X-CSRF-Token` on every request (no method guard); all fetches use
   `credentials: "include"`.
10. **401 triggers a single `POST /ui/session/refresh` then one retry.** — **Verified.**
    `src/api/client.ts: refreshSession()` (`POST /ui/session/refresh`) and the single
    de-duplicated retry path on `res.status === 401`.
11. **Endpoint returns "posts tagged with a specific hashtag, newest first."** —
    **Verified.** OpenAPI `description` for `GET /ui/discover/tags/{tag}`.
12. **Unknown tag returns `404`.** — **Corrected (claim removed).** OpenAPI documents only
    `200` and `422 HTTPValidationError` for this endpoint; no `404`. The web `TagPage`
    renders its empty state from `posts.length === 0` (a `200` with empty `posts`), with no
    `404` handling. Sources: OpenAPI responses block; `src/pages/discover/TagPage.tsx`.
13. **Web tag page is a single non-paged fetch rendered as a vertical list.** —
    **Verified.** `src/pages/discover/TagPage.tsx` calls `getPostsByTag(tag, 50)` once and
    maps `posts` into `PostCard`s; no infinite scroll, pull-to-refresh, grid, or stale
    banner. The Android grid/paging/refresh/stale features are deliberate enhancements
    (noted in §4).
14. **Tag chips link to `/discover/tags/{tag}` from Discover and PostCard.** — **Verified.**
    `src/pages/discover/DiscoverPage.tsx` and `src/pages/feed/PostCard.tsx`
    (`to={`/discover/tags/${tag}`}`). Note: web `Link` does **not** URL-encode the tag in
    the route, but the API caller `getPostsByTag` uses `encodeURIComponent(tag)` — the
    Android design's decode-then-`@Path`-encode approach (FR-9, §8) is consistent.
15. **FastAPI validation error envelope is `detail: [{loc,msg,type}]` (`422`).** —
    **Verified.** OpenAPI `422` references `components.schemas.HTTPValidationError`; web
    `normalizeErrorDetail` handles string/object/array `detail` shapes.
16. **Android framework choices: Paging 3 (`PagingSource`/`Pager`/`cachedIn`),
    `LazyVerticalGrid`, `PullToRefreshBox`, `RemoteMediator`, Navigation Compose deep
    links, App Links `autoVerify` + `assetlinks.json`, Hilt+KSP.** —
    **Unverified-assumption (framework ref).** Standard Android APIs, not derivable from the
    backend/frontend sources. Refs: Paging 3
    (https://developer.android.com/topic/libraries/architecture/paging/v3-overview),
    App Links / Digital Asset Links
    (https://developer.android.com/training/app-links/verify-android-applinks),
    Navigation Compose deep links
    (https://developer.android.com/jetpack/compose/navigation#deeplinks),
    Material3 pull-to-refresh
    (https://developer.android.com/jetpack/compose/components/pull-to-refresh).

### Corrections made

- **Response shape:** `items` → `posts`; element type changed from an invented content DTO
  to `FeedPost` (item id `post_id`; thumbnail/duration sourced from nested `video`/
  `image_urls`). (§5, §11, FR-6)
- **Detail navigation target:** `content/{contentId}` → `posts/{postId}` with `post_id`.
  (FR-6, AC-4, §10 telemetry `content_id` → `post_id`)
- **`404` unknown-tag handling removed:** unknown/empty tag is a `200` with empty `posts`
  → empty state; the real documented error is `422`. (§5, §7, AC-5, §11)
- **`limit` bound documented:** default 20 / max 50; clarified 24 is in range and that the
  param order in the Retrofit signature places `limit` before the optional `cursor`. (§4, §5)
- **Endpoint-shape open question (§13) marked resolved** and tightened to "opaque cursor
  encoding" only.
- **Web-vs-Android behavior divergence called out** (web is single-shot list; Android adds
  grid/paging/refresh/stale). (§4)
- **Frontmatter:** `status: draft` → `reviewed`; added `reviewed_on: 2026-06-06`.

### Open assumptions

- **`200` response field shape:** the OpenAPI `200` schema is empty (`{}`); the `posts`/
  `FeedPost`/`next_cursor` shape is taken from the frontend TypeScript contract, which is
  authoritative for the web client but not formally pinned in OpenAPI. Confirm field names
  against a live response during implementation.
- **Android cookie-session vs Bearer token:** the web client sends `Authorization: Bearer`
  in addition to cookies + CSRF. This spec assumes the Android `core-network` stack
  (AND-001..AND-010) provides the equivalent session transport; the exact Android auth
  header strategy is owned by those tickets and is unverifiable from this ticket's sources.
- **`assetlinks.json` on `testlogon.com`:** required for App Link `autoVerify`; a
  server-side artifact not present in these sources. Until published, links fall back to the
  chooser (tracked in §13).
- **Tag canonicalization / case rules:** server normalization of tag slugs is not described
  in the sources; design passes the decoded slug verbatim (tracked in §13).
- **Offline/stale cache (FR-8):** depends on whether AND-103 supplies `RemoteMediator`/Room
  scaffolding; not determinable here (tracked in §13).
- **Dev plaintext host deep link:** `http://18.222.237.167:8000/discover/tags/{tag}` is a
  development convenience; its routability and cleartext-traffic config are environment
  assumptions, not verified from sources.

## 17. Test Plan

Test target legend (CI/dev): **JVM** = JVM unit/Robolectric (no device); **EMU** = headless
emulator AVD `test35` (x86_64, Android 15 / API 35); **DEV** = physical Samsung Galaxy A15 5G
(SM-A156U, serial R5CX821TA9R, Android 14 / API 34, arm64-v8a). Prefer **DEV** for real
hardware/behavior; use **EMU** for fast instrumented/UI suites.

- **TC-AND-183-01** — Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: MockWebServer enqueues `200` for `GET /ui/discover/tags/kotlin?limit=24`
  with body `{ "tag":"kotlin","posts":[<1 FeedPost with video>], "next_cursor":"c1" }`.
  Steps: invoke `DiscoveryApi.getTagContent("kotlin")`; map via `toDomain()`.
  Expected: request path/query exactly `/ui/discover/tags/kotlin?limit=24` (no `cursor`);
  parsed `posts[0].post_id` and `next_cursor == "c1"`; domain `ContentItem` thumbnail from
  `video.thumbnail_url`, duration 612. Traces: AC-1.
- **TC-AND-183-02** — Type: unit (JVM). Target: JVM.
  Preconditions: fake `DiscoveryApi` returning page 1 (`next_cursor="c1"`) then page 2
  (`next_cursor=null`). Steps: drive `TagPagingSource.load` for refresh then append.
  Expected: page-1 load sends `cursor=null`; append forwards `cursor=c1`; final page yields
  `LoadResult.Page(nextKey=null)` so paging stops. Traces: AC-3.
- **TC-AND-183-03** — Type: unit (JVM). Target: JVM.
  Preconditions: API returns `200` with `posts: []`, `next_cursor: null`. Steps: load page 1.
  Expected: `LoadResult.Page(data=[], nextKey=null)`; ViewModel/UI derive **empty** state;
  no crash, no `404` path. Traces: AC-5.
- **TC-AND-183-04** — Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: MockWebServer returns `422` with
  `{"detail":[{"loc":["query","tag"],"msg":"...","type":"..."}]}`. Steps: load page 1.
  Expected: `LoadResult.Error`; `errorBodyToApiError` produces an `ApiError` with the `422`
  message (list-`detail` variant handled); maps to full-screen retryable error, not empty.
  Traces: AC-5.
- **TC-AND-183-05** — Type: unit (JVM). Target: JVM.
  Preconditions: `SavedStateHandle` seeded with URL-encoded `tag` `c%2B%2B`. Steps:
  construct `TagPageViewModel`. Expected: `tag == "c++"` (decoded); `titleDisplay == "#c++"`;
  `refresh()` emits a new `PagingData`. Traces: AC-2, AC-6.
- **TC-AND-183-06** — Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: capture outbound request headers; `ui_csrf` cookie present in jar; enqueue
  one `401` then (after `POST /ui/session/refresh`) a `200`. Steps: load page 1.
  Expected: GET carries `X-CSRF-Token` + session cookie; on `401` exactly one
  `POST /ui/session/refresh` then a single retry that succeeds; mirrors web `client.ts`.
  Traces: AC-1.
- **TC-AND-183-07** — Type: Compose-UI. Target: EMU.
  Preconditions: fake repository emits `PagingData` with `LoadState.Refresh=Loading` then
  loaded items. Steps: render `TagPageScreen`; advance. Expected: shimmer placeholders →
  populated grid; title shows `#<tag>`. Traces: AC-1, AC-7.
- **TC-AND-183-08** — Type: Compose-UI. Target: EMU.
  Preconditions: fake repo emits one loaded item with known `post_id`; `onContentClick`
  captured. Steps: tap the card. Expected: `onContentClick("post_…")` invoked once with the
  item's `post_id` (the value used to build `posts/{postId}`). Traces: AC-4.
- **TC-AND-183-09** — Type: Compose-UI. Target: EMU.
  Preconditions: fake repo emits empty `posts` (empty state), and a variant with
  `LoadState.Refresh=Error` (full-screen error), and a variant with `LoadState.Append=Error`
  (footer). Steps: render each; tap Retry where shown. Expected: empty copy
  "No posts tagged #<tag> yet"; full-screen Retry calls `refresh()`/`retry()`; append footer
  shows message + Retry calling `lazyItems.retry()` while existing items stay visible.
  Traces: AC-5.
- **TC-AND-183-10** — Type: Compose-UI. Target: EMU.
  Preconditions: fake repo simulates offline-with-cache (cached items + stale flag). Steps:
  render. Expected: cached grid renders with a **stale banner** (not a blank error); banner
  is announced to TalkBack. Traces: AC-5.
- **TC-AND-183-11** — Type: Compose-UI. Target: EMU.
  Preconditions: render under compact width config, then expanded/landscape config. Steps:
  measure grid. Expected: 2 columns (compact) and 3 columns (expanded); adapts to font
  scale without clipping. Traces: AC-7.
- **TC-AND-183-12** — Type: Compose-UI (accessibility). Target: DEV (real TalkBack on the
  physical device for authoritative screen-reader behavior; EMU acceptable for the
  semantics-tree assertions). Preconditions: loaded grid; TalkBack enabled.
  Steps: traverse items, footer Retry, stale banner. Expected: each `ContentCard` exposes a
  `contentDescription` (title + kind/duration); touch targets ≥ 48dp; loading exposes
  `stateDescription="Loading"`; reading order is top-to-bottom, left-to-right; RTL mirrors.
  Traces: AC-7.
- **TC-AND-183-13** — Type: instrumented/e2e (App Link). Target: DEV (real App Link/intent
  resolution on hardware; EMU may be used for the URL-decode assertion).
  Preconditions: app installed; fire `VIEW` intent
  `https://testlogon.com/discover/tags/c%2B%2B` from outside the app (e.g. `adb shell am
  start -a android.intent.action.VIEW -d`). Steps: observe launched screen.
  Expected: `TagPageScreen` opens with decoded tag `c++`, title `#c++`, and loads its
  content; an unauthenticated cold start routes through the auth gate first and resumes to
  the tag page post-login (does not bypass session). Traces: AC-2.
- **TC-AND-183-14** — Type: integration (MockWebServer-backed e2e). Target: EMU.
  Preconditions: in-process MockWebServer serves page 1 (`next_cursor=c1`) and page 2
  (`next_cursor=null`); app pointed at it. Steps: open tag page, scroll to end, then
  pull-to-refresh. Expected: append fetches page 2 with `cursor=c1`; footer spinner clears
  and no spinner once `next_cursor=null`; pull-to-refresh re-requests page 1 (`cursor=null`)
  and resets the list. Traces: AC-3, AC-6.
- **TC-AND-183-15** — Type: manual. Target: DEV.
  Preconditions: device on the flaky dev host `http://18.222.237.167:8000` (cleartext).
  Steps: open a tag page; toggle airplane mode mid-scroll; restore network and Retry.
  Expected: transient host failures surface the retryable error / stale path (not a crash);
  Retry recovers; cleartext dev-host deep link resolves as a non-verified link. (Confirms
  arm64 / API-34 real-network behavior the emulator cannot reproduce.) Traces: AC-5.

### Coverage matrix

| Acceptance criterion | Covered by |
| --- | --- |
| AC-1 (in-app load + `#tag` title, page 1) | TC-01, TC-06, TC-07 |
| AC-2 (App Link, URL-decoded tag) | TC-05, TC-13 |
| AC-3 (append via `next_cursor`, clean stop) | TC-02, TC-14 |
| AC-4 (tap → `posts/{postId}` with `post_id`) | TC-08 |
| AC-5 (empty / error+Retry / append-error / stale; `422`) | TC-03, TC-04, TC-09, TC-10, TC-15 |
| AC-6 (pull-to-refresh resets to page 1) | TC-05, TC-14 |
| AC-7 (2/3-col grid; TalkBack a11y) | TC-07, TC-11, TC-12 |
| AC-8 (unit + UI + App Link instrumented green; coverage) | TC-01..TC-14 (suite) |
