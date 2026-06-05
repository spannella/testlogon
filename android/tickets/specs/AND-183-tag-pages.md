---
id: AND-183
title: Tag pages
milestone: M4
epic: E25
priority: P2
size: M
status: draft
depends_on: [AND-182]
blocks: []
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

FR-6. Tapping a content item MUST navigate to the existing content detail destination
(`content/{contentId}`) owned by the content/detail feature, passing the content id.

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

The `PagingSource` keys off the backend's opaque `next_cursor`. Page size = 24.
`Pager(PagingConfig(pageSize = 24, initialLoadSize = 24, prefetchDistance = 6))`.

## 5. API Contract

Tag content reuses the discovery surface with a `tag` filter. Confirm exact shape against
`/openapi.json` and `frontend/src/api/endpoints/discovery.ts` during implementation; the
contract below is the agreed target.

```kotlin
interface DiscoveryApi {
    @GET("ui/discover/tags/{tag}")
    suspend fun getTagContent(
        @Path("tag") tag: String,
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int = 24,
    ): Response<TagContentResponse>
}
```

Request: `GET /ui/discover/tags/kotlin?limit=24` (no cursor for page 1), cookies +
`X-CSRF-Token: <ui_csrf>` attached by the shared OkHttp interceptors.

Response `200`:

```json
{
  "tag": "kotlin",
  "items": [
    {
      "id": "ct_01H...",
      "title": "Intro to Coroutines",
      "thumbnail_url": "https://.../thumb.jpg",
      "kind": "video",
      "duration_seconds": 612,
      "tags": ["kotlin", "android"]
    }
  ],
  "next_cursor": "eyJwayI6..."   // null/absent on last page
}
```

Error `404` (unknown tag) and FastAPI error envelope — `detail` may be a string,
`[{msg}]`, or `{code,...}` — mapped by the shared `errorBodyToApiError(...)` into
`ApiError`. A `404` is surfaced to the user as the empty/"tag not found" state, not a hard
crash. `next_cursor == null` ends pagination (`nextKey = null`).

DTO → domain mapping lives in `core-data`:

```kotlin
@JsonClass(generateAdapter = true)
data class TagContentResponse(
    @Json(name = "tag") val tag: String,
    @Json(name = "items") val items: List<ContentItemDto>,
    @Json(name = "next_cursor") val nextCursor: String?,
)
fun TagContentResponse.toDomain(): TagPage
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
- **404 unknown tag:** mapped to empty state with "No content for #<tag>" copy.
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
- `tag_content_click` { tag, content_id, position }.
- `tag_page_refresh` { tag }.

Logging uses the app `Logger` at DEBUG for load/cursor transitions and WARN for mapped
`ApiError`s; raw response bodies are not logged in release builds.

## 11. Testing Strategy

**Unit (JVM, `core-testing` + Turbine + MockWebServer):**
- `TagPagingSource.load` — page 1 (null cursor), next page (cursor forwarded),
  last page (`next_cursor` null → `nextKey == null`), HTTP error → `LoadResult.Error`,
  404 mapping.
- `TagContentResponse.toDomain()` field mapping incl. null `next_cursor` and empty `items`.
- `TagPageViewModel` — `tag` decoded from `SavedStateHandle`; `refresh()` re-emits a new
  `PagingData`; `titleDisplay == "#$tag"`.
- FastAPI `detail` variants (string / list / object) → correct `ApiError`.

**UI (Compose, `createAndroidComposeRule`, fake repository emitting `PagingData`):**
- Loading shimmer → loaded grid; item tap invokes `onContentClick` with id.
- Empty state for empty `items`; error state + Retry triggers reload; append error footer.
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

- **Exact endpoint shape:** whether tag content is `GET /ui/discover/tags/{tag}` or a
  `GET /ui/discover?tag=` filter, and whether the cursor field is `next_cursor` vs page
  offset — must be confirmed against `/openapi.json` and `discovery.ts`. Contract in §5 is
  the assumed target; adjust DTO/`PagingSource` keying accordingly.
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

AC-4. Tapping a content item navigates to `content/{contentId}` with the correct id.

AC-5. Empty (incl. 404 unknown tag), full-screen error+Retry, append-error footer+Retry,
and offline-stale-banner states each render under their respective conditions.

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
