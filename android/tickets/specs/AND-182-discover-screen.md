---
id: AND-182
title: Discover screen
milestone: M4
epic: E25
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-027, AND-103]
blocks: []
---

# AND-182 — Discover screen

## 1. Overview & Goal

The Discover screen is the content-discovery surface of the TestLogon Android app: a
curated, scrollable grid of recommended creators and posts that lets an authenticated
user browse beyond their own feed and navigate into the detail surfaces those items own
(post detail, public profile). This ticket delivers the full vertical slice for that
surface — the network binding (`DiscoveryApi`, modeled on the web reference
`frontend/src/api/endpoints/discovery.ts`), the repository, the `DiscoverViewModel`
exposing a `StateFlow<DiscoverUiState>`, and the Compose grid UI with image loading,
loading/empty/error/offline states, and outbound navigation.

The goal is a screen that, against the live dev backend, **renders curated discover
content and navigates** to the destinations each card targets. Scope is deliberately
read-only: this ticket does not implement the interaction actions (like, bookmark, follow)
that the cards may surface affordances for — those are owned by the feed-interaction epic
(AND-173..AND-181) and the profile epic. Discover here renders entry points only.

> **REVIEW CORRECTION (2026-06-06):** The original draft assumed a single `discovery`
> GET returning a server-defined `sections` array of heterogeneous post/creator items.
> The authoritative web reference (`src/api/endpoints/discovery.ts`) and the OpenAPI spec
> show this is **not** how discover works. Discover is composed of **several distinct
> `/ui/discover/*` endpoints** (`/suggested`, `/trending`, `/trending-tags`, `/search`,
> plus `/tags/{tag}` and `/profile/{user_id}`), each returning its own shape; the
> "sections" are a **client-side composition** the web page builds, not a server payload.
> The main grid renders **creator/user cards only** (`DiscoveryUser`) plus trending-tag
> chips — posts appear only on the tag-detail sub-route. Navigation targets a profile by
> `user_id` (there is no "u/identifier"). There is no `is_locked`/paywall concept on
> discover items. All sections below have been corrected accordingly; see §16 for the
> full audit. The Android section model may still aggregate these endpoints into a
> client-side `DiscoverSection` list — that remains a sound design — but the DTOs, paths,
> and field names in §4–§5 are corrected to match the real contract.

This is a `feature-discover` module deliverable in the `app -> feature-* -> core-*`
layering. It reuses the Coil image stack and aspect/placeholder handling standardized in
AND-103 and the session/cookie plumbing exercised by AND-027.

## 2. Context & References

- **Backend:** FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000` (PLAINTEXT HTTP,
  unreliable). OpenAPI at `/openapi.json`. Discover endpoints are the canonical source of
  truth; confirm exact paths/shapes against `/openapi.json` and the web reference before
  finalizing DTOs.
- **Web reference:** `frontend/src/api/endpoints/discovery.ts` (endpoint surface this
  ticket ports), `frontend/src/api/types.ts` (shared DTO shapes for curated sections,
  creators, and posts).
- **Upstream tickets:**
  - **AND-027** — `AuthApi`/session endpoints; establishes the cookie jar, CSRF header,
    and 401-refresh authenticator that all authenticated Discover calls ride on.
  - **AND-103** — Feed media thumbnails; provides the Coil loading conventions
    (placeholders, aspect handling, data-saver respect, scroll cancellation) this screen
    reuses for card imagery.
- **Sibling reference:** AND-098 (Feed list, Paging 3) and AND-099 (post item composable)
  for list/grid and card composition patterns; AND-100 (post detail) and AND-073 (public
  profile) for navigation targets.
- **Namespace:** `com.testlogon.android` everywhere a package appears.

## 3. Functional Requirements

FR-1. The Discover screen is reachable from the authenticated navigation graph
(AND-024) via route `discover`. It is one of the destinations available from the bottom
navigation / More hub.

FR-2. On first composition the screen loads curated discover content from the backend and
renders it as a responsive grid of cards. **CORRECTED:** Curated content is composed
**client-side** from several independent endpoints — "Suggested For You"
(`GET /ui/discover/suggested`), "Trending Creators" (`GET /ui/discover/trending`), and
"Trending Tags" (`GET /ui/discover/trending-tags`) — rather than a single server-defined
`sections` payload. Each client-defined section has a fixed title and an ordered list of
items. On the main grid, item cards are **creators/profiles** (`DiscoveryUser`); trending
tags render as tappable chips. (Post cards are not part of the main grid in the web
reference; they appear only on the tag-detail sub-route — see FR-4/FR-9.)

FR-3. Each card displays its primary image (post thumbnail or creator avatar/cover) using
the AND-103 Coil conventions: placeholder while loading, crossfade in, correct aspect
ratio, request cancellation on scroll-off, and data-saver respect.

FR-4. Tapping a **creator** card navigates to the public profile (`profile/{userId}`,
owned by AND-073). **CORRECTED:** the route argument is the backend `user_id`, not a
"u/identifier". Tapping a **post** card (tag-detail sub-route only) navigates to post
detail (`post/{postId}`, owned by AND-100). Tapping a **trending tag** chip navigates to
the tag-detail sub-route (FR-9). Navigation passes only the identifier; target screens own
their own data loading.

FR-5. Pull-to-refresh re-fetches curated content and replaces the rendered grid.

FR-6. The screen renders distinct states: Loading (initial), Content, Empty (curated set
is empty), Error (recoverable, with Retry), and Offline/Stale (no connectivity; show last
cached content if available with a stale banner, else the offline state). State
composables are reused from AND-021.

FR-7. **CORRECTED / DESCOPED:** The original draft assumed discover items carry an
`is_locked` flag and render a lock affordance. No discover endpoint shape
(`DiscoveryUser`, `DiscoveryProfile`, `CreatorSuggestionsResponse`) exposes a lock/paywall
field, and the main grid renders creators (not posts). The lock-affordance behavior is
therefore **out of scope** for this ticket. If post cards on the tag-detail sub-route
(`FeedPost`) carry an access/lock field (AND-098 owns the `FeedPost` shape), detail-side
paywall handling remains owned by AND-101 and Discover never gates navigation — but no
discover-specific lock UI is built here.

FR-9. Tapping a trending-tag chip opens the tag-detail sub-route, which calls
`GET /ui/discover/tags/{tag}` and renders the returned `FeedPost[]` as post cards.
Whether the tag-detail surface ships in this ticket or is split to a follow-up is an open
question (see R6); the main creator grid is the committed scope for the "renders +
navigates" acceptance gate.

FR-8. Scroll position is preserved across configuration changes and across
backgrounding within process lifetime.

## 4. Technical Design

Module `feature-discover`, package `com.testlogon.android.feature.discover`.

### 4.1 Domain & UI state

```kotlin
// core-model (com.testlogon.android.core.model.discover) — shared, network-free
data class DiscoverSection(
    val id: String,
    val title: String,
    val items: List<DiscoverItem>,
)

sealed interface DiscoverItem {
    val id: String
    // CORRECTED: the live discover grid is creator-centric. The web reference renders
    // only DiscoveryUser cards on the main surface; post cards appear only inside the
    // tag-detail sub-route (/ui/discover/tags/{tag} -> FeedPost[]).
    data class Creator(
        override val id: String,        // == userId (stable key)
        val userId: String,             // CORRECTED: backend field is user_id; profile nav uses this
        val displayName: String,        // display_name
        val profilePhotoUrl: String?,   // CORRECTED: profile_photo_url (was avatarUrl)
        val description: String?,       // CORRECTED: description (was tagline)
        val followerCount: Int,         // follower_count
        val isFollowing: Boolean,       // is_following (rendered as affordance only; follow action out of scope)
    ) : DiscoverItem
    // Post cards are out of the main-grid scope but modeled for the tag-detail sub-route
    // (and future expansion). Fields mirror core-model FeedPost (AND-098), NOT the
    // fabricated post_id/thumbnail_url/is_locked shape in the original draft.
    data class Post(
        override val id: String,        // post id
        val postId: String,
        val thumbnailUrl: String?,      // derived from FeedPost media (see AND-098 types)
        val title: String?,
        val authorDisplayName: String?,
        val aspectRatio: Float?,        // width/height when media dims available; null => fallback
    ) : DiscoverItem
}
```

> **CORRECTION:** The original `Creator` used `userIdentifier`/`avatarUrl`/`coverUrl`/
> `tagline`; none of those exist in the contract. The real `DiscoveryUser` fields are
> `user_id`, `display_name`, `profile_photo_url`, `description`, `follower_count`,
> `is_following`, `is_followed_by`, `is_mutual` (the full `DiscoveryProfile` adds
> `cover_photo_url`, `location`, `following_count`). The original `Post` carried a
> backend-defined `is_locked` flag that does not exist on any discover shape.

```kotlin
// feature-discover
sealed interface DiscoverUiState {
    data object Loading : DiscoverUiState
    data class Content(
        val sections: List<DiscoverSection>,
        val isRefreshing: Boolean = false,
        val isStale: Boolean = false,   // served from cache while offline/unreachable
    ) : DiscoverUiState
    data object Empty : DiscoverUiState
    data class Error(val message: String, val retryable: Boolean = true) : DiscoverUiState
    data object Offline : DiscoverUiState   // no cache and no connectivity
}

sealed interface DiscoverNavEvent {
    data class OpenPost(val postId: String) : DiscoverNavEvent
    data class OpenProfile(val userId: String) : DiscoverNavEvent   // CORRECTED: was userIdentifier
}
```

### 4.2 ViewModel

```kotlin
@HiltViewModel
class DiscoverViewModel @Inject constructor(
    private val repository: DiscoverRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow<DiscoverUiState>(DiscoverUiState.Loading)
    val uiState: StateFlow<DiscoverUiState> = _uiState.asStateFlow()

    private val _navEvents = Channel<DiscoverNavEvent>(Channel.BUFFERED)
    val navEvents: Flow<DiscoverNavEvent> = _navEvents.receiveAsFlow()

    init { load() }

    fun load() { /* collect repository.discover(forceRefresh=false), map ApiResult */ }
    fun refresh() { /* forceRefresh=true; set isRefreshing on existing Content */ }
    fun retry() = load()

    fun onItemClick(item: DiscoverItem) {
        viewModelScope.launch {
            _navEvents.send(when (item) {
                is DiscoverItem.Post -> DiscoverNavEvent.OpenPost(item.postId)
                is DiscoverItem.Creator -> DiscoverNavEvent.OpenProfile(item.userId)  // CORRECTED
            })
        }
    }
}
```

Mapping rules: `ApiResult.Success` with non-empty sections → `Content`; success with no
items → `Empty`; `ApiResult.Failure` while cached content exists → `Content(isStale=true)`;
failure with no cache and offline → `Offline`; other failures → `Error`. The grid is a
single flat `LazyVerticalGrid` (Paging is intentionally **not** used — discover is a
bounded curated set, not an infinite stream; AND-098 owns paginated lists).

### 4.3 Repository

The repository fans out to the per-section endpoints (`getSuggested`, `getTrending`,
`getTrendingTags`) concurrently, maps each via `DiscoverMapper`, and assembles the
client-side `List<DiscoverSection>` (sections with empty item lists are omitted). Search is
a separate query-driven call (see §4.4 search affordance). Partial failure policy: if at
least one section succeeds, emit `Success` with the available sections; if all fail, emit
`Failure` (mapped to `Error`/`Offline`/stale per §7).

```kotlin
interface DiscoverRepository {
    fun discover(forceRefresh: Boolean): Flow<ApiResult<List<DiscoverSection>>>
    fun search(query: String): Flow<ApiResult<DiscoverSection>>   // creator search results
}

@Singleton
class DefaultDiscoverRepository @Inject constructor(
    private val api: DiscoveryApi,
    private val mapper: DiscoverMapper,
    @IoDispatcher private val io: CoroutineDispatcher,
) : DiscoverRepository
```

For M4 the repository performs an in-memory cache of the last successful result (held in
the `@Singleton`) so stale content is available after a transient failure; durable Room
caching is out of scope here and is layered later by the cache epic (AND-115/AND-116) if
needed — note this explicitly rather than duplicating cache logic.

### 4.4 Compose UI

```kotlin
@Composable
fun DiscoverRoute(
    onOpenPost: (String) -> Unit,
    onOpenProfile: (String) -> Unit,
    viewModel: DiscoverViewModel = hiltViewModel(),
)

@Composable
fun DiscoverScreen(
    state: DiscoverUiState,
    onItemClick: (DiscoverItem) -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
)
```

`DiscoverRoute` collects `uiState` with `collectAsStateWithLifecycle()` and consumes
`navEvents` in a `LaunchedEffect`, dispatching to the `onOpenPost`/`onOpenProfile` lambdas
wired by the nav graph. The grid uses `LazyVerticalGrid(GridCells.Adaptive(minSize = 160.dp))`
with section headers spanning the full row (`item(span = { GridItemSpan(maxLineSpan) })`).
Cards: `PostDiscoverCard` and `CreatorDiscoverCard`, both leaning on the AND-103
`MediaThumbnail` composable for imagery. Pull-to-refresh via Material 3
`PullToRefreshBox`. `rememberLazyGridState()` preserves scroll across recomposition;
`rememberSaveable` is unnecessary since the grid set is reloaded but scroll index is held
via the standard `LazyGridState` saver.

## 5. API Contract

> **REVIEW CORRECTION (2026-06-06):** This section was rewritten against the authoritative
> sources. There is **no** `discovery` GET and **no** `DiscoverFeedDto`/server `sections`.
> The web client (`src/api/endpoints/discovery.ts`) calls **multiple** `/ui/discover/*`
> endpoints and composes the page client-side. The OpenAPI response schemas for these
> endpoints are **empty/inline** (`"schema": {}`), so the **typed contract is the frontend
> TS interface**, treated as authoritative here. Verified against
> `openapi.index.txt` lines 1423–1430 and `src/api/endpoints/discovery.ts`.

Endpoints port `frontend/src/api/endpoints/discovery.ts`. All calls are authenticated GETs
riding the cookie jar + `X-CSRF-Token` (AND-027) and are eligible for idempotent-GET
retry/backoff (AND-016). All paths are under the `/ui/discover/` prefix (verified — the
original bare `discovery` path was wrong).

Verified endpoint surface (OpenAPI `GET /ui/discover/...`; all params `limit` capped at 50):

| Web fn (`discovery.ts`) | Method + path | Params | Response (TS, authoritative) |
|---|---|---|---|
| `getSuggestedUsers` | `GET /ui/discover/suggested` | `limit` (default 12, ≤50) | `DiscoverySearchResponse` |
| `getTrendingCreators` | `GET /ui/discover/trending` | `limit` (default 20, ≤50) | `DiscoverySearchResponse` |
| `searchDiscoverUsers` | `GET /ui/discover/search` | `q` (req, 1–64 chars), `limit` (def 20, ≤50), `cursor?` | `DiscoverySearchResponse` |
| `getTrendingTags` | `GET /ui/discover/trending-tags` | `limit` (default 20, ≤50) | `TrendingTagsResponse` |
| `getPostsByTag` | `GET /ui/discover/tags/{tag}` | `limit`, `cursor?` | `TagDiscoverResponse` |
| `getDiscoveryProfile` | `GET /ui/discover/profile/{user_id}` | path `user_id` | `DiscoveryProfile` |
| `reindexSelf` | `POST /ui/discover/reindex` | — | (untyped) |

> NB: OpenAPI also exposes `GET /ui/discover/creators` → `CreatorSuggestionsResponse`
> (`{creators: CreatorSuggestionItem[], source}`), but the web Discover page does **not**
> use it — it uses `/suggested` and `/trending`. Do **not** port `/creators` for this
> screen unless product re-scopes; noted as an available-but-unused endpoint.

```kotlin
interface DiscoveryApi {
    @GET("ui/discover/suggested")
    suspend fun getSuggested(@Query("limit") limit: Int = 12): Response<DiscoverySearchResponseDto>

    @GET("ui/discover/trending")
    suspend fun getTrending(@Query("limit") limit: Int = 20): Response<DiscoverySearchResponseDto>

    @GET("ui/discover/search")
    suspend fun search(
        @Query("q") q: String,
        @Query("limit") limit: Int = 20,
        @Query("cursor") cursor: String? = null,
    ): Response<DiscoverySearchResponseDto>

    @GET("ui/discover/trending-tags")
    suspend fun getTrendingTags(@Query("limit") limit: Int = 20): Response<TrendingTagsResponseDto>

    // tag-detail sub-route (FR-9) — ships with the tag surface if in scope (see R6)
    @GET("ui/discover/tags/{tag}")
    suspend fun getPostsByTag(
        @Path("tag") tag: String,
        @Query("limit") limit: Int = 20,
        @Query("cursor") cursor: String? = null,
    ): Response<TagDiscoverResponseDto>
}
```

Response shapes (corrected to match `discovery.ts` exactly; Moshi):

```kotlin
@JsonClass(generateAdapter = true)
data class DiscoverySearchResponseDto(
    val items: List<DiscoveryUserDto>,
    @Json(name = "next_cursor") val nextCursor: String? = null,
    @Json(name = "total_estimate") val totalEstimate: Int = 0,
)

@JsonClass(generateAdapter = true)
data class DiscoveryUserDto(
    @Json(name = "user_id") val userId: String,
    @Json(name = "display_name") val displayName: String,
    @Json(name = "profile_photo_url") val profilePhotoUrl: String? = null,
    val description: String? = null,
    @Json(name = "follower_count") val followerCount: Int = 0,
    @Json(name = "is_following") val isFollowing: Boolean = false,
    @Json(name = "is_followed_by") val isFollowedBy: Boolean = false,
    @Json(name = "is_mutual") val isMutual: Boolean = false,
)

@JsonClass(generateAdapter = true)
data class TrendingTagsResponseDto(val tags: List<TrendingTagDto>)

@JsonClass(generateAdapter = true)
data class TrendingTagDto(
    val tag: String,
    val count: Int,
    @Json(name = "last_used_at") val lastUsedAt: String,
)

// tag-detail sub-route; FeedPost shape is owned by AND-098 (reuse its DTO/mapper)
@JsonClass(generateAdapter = true)
data class TagDiscoverResponseDto(
    val tag: String,
    val posts: List<FeedPostDto>,                       // reuse AND-098 FeedPostDto
    @Json(name = "next_cursor") val nextCursor: String? = null,
)
```

Example real `/ui/discover/suggested` (and `/trending`, `/search`) payload:

```json
{
  "items": [
    {
      "user_id": "u_ava",
      "display_name": "Ava",
      "profile_photo_url": "https://.../a.jpg",
      "description": "Daily drops",
      "follower_count": 1280,
      "is_following": false,
      "is_followed_by": true,
      "is_mutual": false
    }
  ],
  "next_cursor": "eyJ...",
  "total_estimate": 42
}
```

`DiscoverMapper` maps `DiscoveryUserDto` → `DiscoverItem.Creator` (no `type` discriminator
exists on these endpoints — the original discriminator-on-`type` logic was based on the
fabricated heterogeneous payload and is removed). The repository aggregates the per-section
endpoint results into the client-side `List<DiscoverSection>` the UI consumes. `aspectRatio`
applies only to tag-detail post cards (derived from `FeedPost` media dims, AND-098).

Error bodies on these endpoints: validation failures (e.g. `q` too long, `limit` > 50)
return **HTTP 422 `HTTPValidationError`** = `{ "detail": [ ValidationError ] }` where each
`ValidationError` is `{ loc: [string|int], msg: string, type: string }` (verified:
`components.schemas.HTTPValidationError` / `ValidationError`). Other failures use the
generic FastAPI `detail` shape (string | `[{msg}]` | `{code,...}`), decoded by the shared
error mapper (AND-015) into `ApiResult.Failure`.

## 6. Data & State Management

- Single source of truth: `DiscoverViewModel.uiState: StateFlow<DiscoverUiState>`.
- Navigation modeled as one-shot effects via a `Channel`/`receiveAsFlow` (not state), so a
  config change does not re-trigger navigation.
- In-memory last-success cache lives in the `@Singleton` repository to back the stale path;
  it is cleared on logout (AND-032 wiring) to avoid cross-account leakage.
- No DataStore/Room writes in this ticket. Durable offline caching, TTL, and eviction are
  explicitly deferred to AND-116/AND-118; this ticket only consumes connectivity status
  from AND-017 to choose between `Offline` and `Content(isStale=true)`.
- Grid scroll state held by `LazyGridState` (survives recomposition and config change via
  its built-in `Saver`).

## 7. Error Handling & Resilience

- Dev host is plaintext and unreliable: OkHttp call timeout ~20s (AND-009), bounded
  exponential backoff retry on the idempotent discover GET only (AND-016).
- `ApiResult.Failure` taxonomy mapped per AND-015/AND-018:
  - Network/timeout with cached content → `Content(isStale=true)` + non-blocking stale
    banner offering refresh.
  - Network/timeout with no cache and no connectivity → `Offline` (AND-021 offline state,
    Retry).
  - HTTP 4xx/5xx with no cache → `Error(message, retryable)`; `detail` mapped to a
    user-readable string; Retry calls `retry()`.
  - 401 → handled transparently by the refresh authenticator (AND-013): on 401 it performs
    a single `POST /ui/session/refresh` then retries the original request once (verified in
    `src/api/client.ts`). A second 401 after refresh surfaces as auth failure (web calls
    `logout("session_expired")`) and defers to global re-auth routing (AND-025), not a
    local error state.
- Partial/malformed items are skipped, not fatal; a section with zero valid items after
  filtering is omitted; if all sections are empty → `Empty`.
- Refresh failures while showing `Content` keep existing content and show a transient
  snackbar; they never blank the screen.

## 8. Security & Privacy

- All requests authenticated via the persistent cookie jar (AND-011) + `X-CSRF-Token`
  echo (AND-012). **CLARIFICATION (verified against `src/api/client.ts`):** the web client
  ALSO sends `Authorization: Bearer <accessToken>` from its auth store on every call (and
  `X-IMPERSONATION-TOKEN` when impersonating). The Android port's auth stack (AND-027)
  owns header/cookie injection; this screen handles no tokens *directly*, but the
  underlying client does attach a Bearer token in addition to the cookie + CSRF — the spec
  should not claim cookie-only transport.
- No PII is logged. Telemetry uses opaque ids (section id, item id) only; no display names,
  taglines, or URLs in logs.
- Cleartext HTTP to the dev host is permitted only via the dev flavor's network-security
  config (established in AND-006/AND-009); release builds must not reach a cleartext host.
- In-memory cache cleared on logout to prevent showing one user's curated content to the
  next session.
- Coil image requests inherit the authenticated OkHttp client only where signed/cookie'd
  media URLs require it; public CDN URLs use the standard loader (per AND-103).

## 9. Accessibility & i18n

- All section titles and visible labels come from string resources / server-provided text;
  no hardcoded UI strings (i18n plumbing AND-111, catalogs AND-112). RTL-ready layouts
  (AND-114): use start/end paddings, mirror chevrons.
- Cards expose `contentDescription`: creator cards → "Creator: {displayName}, {follower
  count} followers"; tag chips → "Tag: #{tag}"; post cards (tag-detail) → "Post: {title} by
  {author}". (CORRECTED — "Locked" announcement removed; no lock affordance, see FR-7.)
- Touch targets ≥ 48dp; section headers are `heading()` semantics for TalkBack
  navigation.
- Grid supports large font scaling without truncation breaking layout (titles max 2 lines,
  ellipsized).
- Pull-to-refresh has an accessible "Refresh" action; the stale banner is announced as a
  status (`liveRegion = Polite`).

## 10. Telemetry & Logging

- Events (via the app analytics facade, redacted per AND-052 conventions):
  - `discover_view` — screen entered.
  - `discover_load` — `{ result: success|error|stale|offline, section_count, item_count, latency_ms }`.
  - `discover_refresh` — `{ result }`.
  - `discover_item_click` — `{ item_type: post|creator, section_id, position }`.
- Debug logging via the shared logger (no PII). Network logging is the OkHttp logging
  interceptor at body level in dev only (AND-009).

## 11. Testing Strategy

- **Unit (core-testing + MockWebServer, AND-046):**
  - `DiscoveryApi` decodes `DiscoverySearchResponseDto` (items + `next_cursor` +
    `total_estimate`) and `TrendingTagsResponseDto` fixtures; snake_case field mapping
    (`user_id`, `profile_photo_url`, etc.) verified. (CORRECTED — no `DiscoverFeedDto`/
    heterogeneous-`type` decoding; that shape does not exist.)
  - `DiscoverMapper`: `DiscoveryUserDto` → `Creator` field mapping, null-field tolerance,
    empty-section omission, tag → chip mapping. (Lock-flag test removed — no such field.)
  - `DefaultDiscoverRepository`: success → sections; failure with cache → stale; failure
    without cache + offline → offline classification; cache cleared on logout.
  - `DiscoverViewModel`: state transitions Loading→Content/Empty/Error/Offline; `refresh`
    sets `isRefreshing`; `onItemClick` emits correct `DiscoverNavEvent`; nav event not
    re-emitted on re-subscription.
- **Compose UI tests (AND-048 harness):**
  - Loading shows spinner; Content shows section headers + cards; Empty/Error/Offline
    render their respective composables; Retry invokes `retry()`.
  - Tapping a creator card invokes `onOpenProfile(userId)` (CORRECTED — was
    `userIdentifier`); tapping a post card on the tag-detail sub-route invokes
    `onOpenPost(postId)` (verified via test lambdas).
  - Stale banner appears when `isStale = true`.
- **Instrumented smoke (optional, AND-051):** against MockWebServer, scroll preserves
  position across recreation.
- Acceptance gate: "Discover renders + navigates" verified by the two navigation UI tests
  plus a manual run against the dev backend.

## 12. Dependencies & Sequencing

- **Hard deps (from backlog):**
  - **AND-027** — session endpoints / authenticated request plumbing. Discover GETs are
    authenticated and require the cookie jar + CSRF + refresh stack.
  - **AND-103** — feed media thumbnails; provides the Coil `MediaThumbnail` conventions
    reused by cards.
- **Implicit infra deps (already in M0–M2):** AND-010 (Retrofit/Moshi), AND-015
  (error mapping), AND-016 (GET retry), AND-018 (`ApiResult`), AND-021 (state
  composables), AND-024 (authenticated nav graph), AND-017 (connectivity).
- **Navigation targets (must exist or be stubbed):** AND-100 (post detail route
  `post/{postId}`), AND-073 (public profile route `profile/{userIdentifier}`). If a target
  is not yet merged, wire to a placeholder destination behind the same route so navigation
  is testable; replace when the owner ticket lands.
- **Blocks:** none declared.

## 13. Risks & Open Questions

- **R1 — Endpoint shape (RESOLVED in review).** Confirmed: `discovery.ts` exposes
  **multiple** `/ui/discover/*` endpoints, not a single bounded GET; the page is composed
  client-side. *Is discover paginated?* **Partially yes** — `/search` and `/tags/{tag}`
  return `next_cursor` and accept `cursor`; `/suggested`, `/trending`, `/trending-tags` are
  bounded (`limit`-capped, no cursor). The main creator grid stays a bounded
  `LazyVerticalGrid` (no Paging). **Open follow-up:** infinite-scroll for search results
  and tag-detail posts may warrant Paging 3 (reuse AND-098) — out of scope here.
- **R2 — Item heterogeneity.** Backend may add item types (e.g. "collection", "event").
  Mitigation: discriminator-based mapping that drops unknowns; UI degrades gracefully.
- **R3 — Locked content navigation (RESOLVED/DESCOPED).** No discover endpoint exposes a
  lock/paywall field, and the main grid renders creators not posts. The lock-affordance
  question is moot for this ticket; any paywall handling lives on post detail (AND-101) via
  the tag-detail sub-route's `FeedPost` items only.
- **R4 — Unreliable dev host** inflates perceived load times; the stale path and 20s
  timeout mitigate, but empty-vs-error classification depends on connectivity signal
  fidelity (AND-017).
- **R5 — Image auth.** Whether discover media URLs require the cookie'd OkHttp client is
  unconfirmed; default to AND-103 behavior and revisit if 401s appear on images.
- **R6 — Tag-detail sub-route scope.** The web Discover page renders trending-tag chips
  that link to a tag-detail view (`/ui/discover/tags/{tag}` → `FeedPost[]`). Open question:
  does this ticket ship the tag-detail surface (post grid + cursor paging) or only the
  chips that deep-link to a follow-up screen? The committed acceptance gate (renders +
  navigates) is satisfied by the creator grid + profile navigation; tag-detail is the most
  likely scope-creep risk. *Recommend: chips ship here; tag-detail post grid is a
  follow-up unless product insists otherwise.*

## 14. Acceptance Criteria

AC-1. Navigating to `discover` in the authenticated graph loads curated content from the
backend and renders a grid of section headers and post/creator cards. *(Backlog: "Discover
renders".)*

AC-2. Tapping a post card navigates to post detail with the correct `postId`; tapping a
creator card navigates to the public profile with the correct `userIdentifier`. *(Backlog:
"navigates".)*

AC-3. Card imagery loads with placeholders, correct aspect handling, and is cancelled on
scroll-off, per AND-103.

AC-4. The screen renders correct states for Loading, Content, Empty, Error (with working
Retry), and Offline/Stale; failures while content is shown never blank the screen.

AC-5. Pull-to-refresh re-fetches and replaces content; `isRefreshing` reflected in UI.

AC-6. All UI tests in §11 pass; discover GET decoding and ViewModel transitions are
MockWebServer-tested.

AC-7. No PII in logs; in-memory cache cleared on logout.

## 15. Definition of Done

- `feature-discover` module created under `com.testlogon.android.feature.discover` with
  `DiscoveryApi`, DTOs + `DiscoverMapper`, `DiscoverRepository`/`DefaultDiscoverRepository`,
  `DiscoverViewModel`, and `DiscoverRoute`/`DiscoverScreen` plus card composables.
- Hilt bindings (KSP) wired; module registered in the authenticated nav graph at route
  `discover` with `onOpenPost`/`onOpenProfile` callbacks connected to the real or stubbed
  targets.
- All §11 unit and Compose UI tests written and green in CI (AND-050/AND-051).
- Endpoint paths/shapes verified against `/openapi.json` and `discovery.ts`; cleartext-dev
  config respected, release build cannot reach a cleartext host.
- Telemetry events emitted and redacted; lint/detekt/ktlint clean (AND-005).
- Manual verification against `http://18.222.237.167:8000`: Discover renders and navigates
  to post detail and public profile.
- Spec deviations (especially endpoint shape) reconciled and documented in the PR; code
  reviewed and merged to `android-port`.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. Sources:
`openapi.index.txt` (OpenAPI index), `openapi.pretty.json` (`components.schemas.*`), and
frontend paths under `reference/src/`.

1. **Discover is a single `discovery` GET returning a server `sections` array.**
   VERDICT: **Corrected (false).** No such endpoint exists. SOURCE: `openapi.index.txt`
   lines 1423–1430 list only `/ui/discover/{creators,profile,reindex,search,suggested,
   tags,trending,trending-tags}`; `src/api/endpoints/discovery.ts` calls these individually
   and `src/pages/discover/DiscoverPage.tsx` composes sections client-side.

2. **Endpoint path prefix is `/ui/discover/...` (not bare `discovery`).**
   VERDICT: **Corrected.** SOURCE: `GET /ui/discover/suggested` etc. in
   `openapi.index.txt` lines 1427/1429/1426; `src/api/endpoints/discovery.ts:
   getSuggestedUsers` (`"/ui/discover/suggested"`).

3. **Main grid is suggested + trending creators + trending tags, composed client-side.**
   VERDICT: **Verified.** SOURCE: `src/pages/discover/DiscoverPage.tsx` (`getSuggestedUsers`,
   `getTrendingCreators`, `getTrendingTags` queries; "Suggested For You" / "Trending
   Creators" / "Trending Tags" cards).

4. **Items on the main grid are creators (`DiscoveryUser`), not heterogeneous post/creator
   cards with a `type` discriminator.** VERDICT: **Corrected.** SOURCE:
   `src/api/endpoints/discovery.ts: DiscoverySearchResponse.items: DiscoveryUser[]`;
   `DiscoverPage.tsx: UserCard`.

5. **`DiscoverySearchResponse` shape = `{ items, next_cursor?, total_estimate }`.**
   VERDICT: **Verified.** SOURCE: `src/api/endpoints/discovery.ts: DiscoverySearchResponse`.

6. **Creator/user field names: `user_id`, `display_name`, `profile_photo_url`,
   `description`, `follower_count`, `is_following`, `is_followed_by`, `is_mutual`** (not
   `user_identifier`/`avatar_url`/`cover_url`/`tagline`). VERDICT: **Corrected.** SOURCE:
   `src/api/endpoints/discovery.ts: DiscoveryUser`.

7. **Profile navigation key is `user_id`** (no "u/identifier"). VERDICT: **Corrected.**
   SOURCE: `src/api/endpoints/discovery.ts: getDiscoveryProfile(userId)` →
   `/ui/discover/profile/${userId}`; OpenAPI path param `user_id` (`openapi.index.txt`
   line 1424; `openapi.pretty.json` operation `discover_profile_*`, path param "User Id").
   The Android nav route arg name (`profile/{userId}`) is owned by AND-073 — *unverified
   assumption* that AND-073's route arg equals this `user_id` (cross-ticket).

8. **Discover items carry an `is_locked`/paywall flag.** VERDICT: **Corrected (false).**
   SOURCE: no lock field on `DiscoveryUser`/`DiscoveryProfile`
   (`src/api/endpoints/discovery.ts`) or `CreatorSuggestionsResponse`/`CreatorSuggestionItem`
   (`openapi.pretty.json` line 24833).

9. **Discover is paginated.** VERDICT: **Corrected/refined.** `/search` and `/tags/{tag}`
   accept `cursor` and return `next_cursor`; `/suggested`, `/trending`, `/trending-tags`
   are bounded `limit`-capped (≤50). SOURCE: `openapi.pretty.json` operations
   `discover_search_*` (params `q,limit,cursor`), `discover_tag_*` (`tag,limit,cursor`),
   `discover_trending_*`/`discover_suggested_*` (`limit` only); `discovery.ts` signatures.

10. **Trending tags shape = `{ tags: [{ tag, count, last_used_at }] }`; tag-detail =
    `{ tag, posts: FeedPost[], next_cursor? }`.** VERDICT: **Verified.** SOURCE:
    `src/api/endpoints/discovery.ts: TrendingTagsResponse`, `TrendingTag`,
    `TagDiscoverResponse` (imports `FeedPost` from `@/api/types`).

11. **Auth/transport = persistent cookie jar + `X-CSRF-Token` from `ui_csrf` cookie.**
    VERDICT: **Verified.** SOURCE: `src/api/client.ts` (`getCookie("ui_csrf")` →
    `headers.set("X-CSRF-Token", csrf)`; `credentials: "include"`).

12. **"No tokens/credentials handled directly; cookie-only transport."** VERDICT:
    **Corrected/clarified.** The client also sends `Authorization: Bearer <accessToken>`
    (and `X-IMPERSONATION-TOKEN` when impersonating). SOURCE: `src/api/client.ts` (auth
    store `accessToken` → `Authorization: Bearer`).

13. **401 handling = single `POST /ui/session/refresh` then one retry; second 401 →
    logout/global re-auth.** VERDICT: **Verified.** SOURCE: `src/api/client.ts:
    refreshSession()` (`/ui/session/refresh`, POST) and the 401 retry block
    (`logout("session_expired")` on retry 401).

14. **Validation errors return HTTP 422 `HTTPValidationError` =
    `{ detail: [{ loc, msg, type }] }`.** VERDICT: **Verified.** SOURCE:
    `openapi.pretty.json` `components.schemas.HTTPValidationError` (line 37133) +
    `ValidationError` (line 80337); each discover op lists `422: HTTPValidationError`
    (`openapi.index.txt` lines 1424/1426/1427/1428/1429/1430). The generic
    string|`[{msg}]`|`{code,...}` `detail` normalization is in `src/api/client.ts:
    normalizeErrorDetail`.

15. **`GET /ui/discover/creators` → `CreatorSuggestionsResponse` exists but is unused by
    the Discover page.** VERDICT: **Verified.** SOURCE: `openapi.index.txt` line 1423;
    schema `openapi.pretty.json` line 24833; absent from `discovery.ts`/`DiscoverPage.tsx`.

16. **Param limits: `q` 1–64 chars, `limit` default/max per endpoint (max 50).** VERDICT:
    **Verified.** SOURCE: `openapi.pretty.json` `discover_search_*` (`q` minLength 1
    maxLength 64; `limit` max 50), `discover_suggested_*` (default 12), `discover_trending_*`
    (default 20).

17. **Coil/`MediaThumbnail` conventions reused from AND-103; offline/state composables from
    AND-021/AND-017; `LazyVerticalGrid`/`PullToRefreshBox` choices.** VERDICT:
    **Unverified-assumption (framework/cross-ticket).** Not checkable from the OpenAPI/
    frontend sources (Android-side and sibling tickets). Material 3 `PullToRefreshBox` and
    `LazyVerticalGrid` are standard Compose APIs (framework ref:
    developer.android.com/jetpack/compose/lists, .../components/pull-to-refresh).

### Corrections made

- **Endpoint surface:** replaced the fictional single `GET discovery`/`DiscoverFeedDto`
  with the real seven `/ui/discover/*` endpoints; rewrote §5 with verified paths, params,
  and TS-authoritative DTOs (claims 1, 2, 9, 16).
- **Path prefix:** `discovery` → `ui/discover/...` (claim 2).
- **Item model:** main grid is creator-only `DiscoveryUser`; removed the
  `type`-discriminated heterogeneous payload and the `unknown-type-dropped` logic; posts
  confined to the tag-detail sub-route (claims 3, 4).
- **Field names:** `DiscoverItem.Creator` and DTOs corrected to `user_id`,
  `display_name`, `profile_photo_url`, `description`, `follower_count`, `is_following`,
  etc. (claim 6); nav key `userIdentifier` → `userId` in FR-4, the nav event, ViewModel,
  and §11 (claim 7).
- **Lock/paywall:** FR-7 descoped, R3 resolved, accessibility "Locked" announcement
  removed (claim 8).
- **Auth clarification:** §8 now notes the Bearer token + impersonation header in addition
  to cookie+CSRF (claim 12); §7 401 path pinned to `POST /ui/session/refresh` + single
  retry (claim 13).
- **Pagination:** R1 resolved; §5 documents which endpoints are cursor-paged (claim 9).
- **Error shape:** §5 now cites the exact `HTTPValidationError`/`ValidationError` 422 shape
  (claim 14).
- **Tests:** §11 unit cases updated to decode the real DTOs (claim 4/6).

### Open assumptions

- **AND-073 profile route arg = backend `user_id`** — assumed; AND-073 is a separate
  ticket not in these sources. Verify when AND-073 lands (claim 7).
- **AND-100 post-detail route `post/{postId}` and AND-098 `FeedPost`/`FeedPostDto` shape**
  — assumed/owned elsewhere; the tag-detail post mapping depends on AND-098's `FeedPost`,
  which is not re-validated here.
- **Coil/image-auth, state composables, connectivity signal (AND-103/021/017)** — Android
  internal contracts; not verifiable from OpenAPI/frontend. Default to AND-103 behavior;
  revisit image-auth if 401s appear on media (R5).
- **Whether the tag-detail post surface ships in this ticket (R6)** — product decision; the
  contract is verified but the scope boundary is not.
- **In-memory `@Singleton` cache + logout-clear wiring (AND-032)** — Android design choice,
  not in scope of the verifiable sources.

## 17. Test Plan

Test targets: **JVM** = local JVM/Robolectric unit; **MWS** = MockWebServer
contract; **emu35** = headless AVD `test35` (x86_64, API 35); **device** = physical
Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). Discover is a read-only, network +
Compose feature with no camera/biometric/WebRTC/push dependency, so most cases run on JVM
or emu35; the physical device is used only for real-network/offline behavior against the
flaky cleartext dev host and for the API-34/arm64 ABI smoke.

- **TC-AND-182-01 — Happy path: grid renders composed sections.**
  Type: contract/MockWebServer (JVM + MWS).
  Target: `DiscoveryApi` + `DefaultDiscoverRepository` + `DiscoverViewModel`.
  Preconditions: MWS returns 200 for `/ui/discover/suggested`, `/ui/discover/trending`,
  `/ui/discover/trending-tags` with non-empty `items`/`tags` fixtures.
  Steps: construct ViewModel; collect `uiState`.
  Expected: terminal state `Content` with sections "Suggested For You", "Trending
  Creators", "Trending Tags" populated; creator fields map from `user_id`/`display_name`/
  `profile_photo_url`/`follower_count`.
  Traces: AC-1, AC-6.

- **TC-AND-182-02 — DTO decoding / snake_case mapping.**
  Type: unit (JVM).
  Target: Moshi adapters for `DiscoverySearchResponseDto`/`DiscoveryUserDto`/
  `TrendingTagsResponseDto`.
  Preconditions: JSON fixture matching the §5 example (with `next_cursor`,
  `total_estimate`, `is_followed_by`, `is_mutual`).
  Steps: decode fixture.
  Expected: all snake_case fields populated; absent optional fields default
  (`profile_photo_url`=null, `total_estimate`=0); no `type`/`is_locked`/`post_id` fields
  referenced.
  Traces: AC-1, AC-6.

- **TC-AND-182-03 — Creator card navigation passes `user_id`.**
  Type: Compose-UI (emu35).
  Target: `DiscoverScreen` + `onItemClick`/nav lambda.
  Preconditions: `Content` state with a `Creator(userId="u_ava")`.
  Steps: tap the creator card; capture `onOpenProfile`.
  Expected: `onOpenProfile("u_ava")` invoked exactly once; not `userIdentifier`.
  Traces: AC-2.

- **TC-AND-182-04 — Tag chip navigation (and post-card nav if tag-detail in scope).**
  Type: Compose-UI (emu35).
  Target: trending-tag chip → tag-detail; post card → `onOpenPost`.
  Preconditions: `Content` with `TrendingTag(tag="art")`; tag-detail fixture from
  `/ui/discover/tags/art` returning `posts` (`FeedPost`).
  Steps: tap chip; on tag-detail tap a post card.
  Expected: tag chip routes to tag-detail; post card invokes `onOpenPost(postId)`.
  (If R6 descopes tag-detail to a follow-up, assert the chip emits the deep-link only.)
  Traces: AC-2.

- **TC-AND-182-05 — Empty state.**
  Type: contract/MockWebServer (JVM + MWS).
  Target: repository → ViewModel mapping.
  Preconditions: all section endpoints return 200 with empty `items`/`tags`.
  Steps: load.
  Expected: terminal state `Empty` (all sections omitted → no content).
  Traces: AC-4.

- **TC-AND-182-06 — Recoverable error + Retry.**
  Type: contract/MockWebServer (JVM + MWS) and Compose-UI (emu35) for the Retry tap.
  Target: ViewModel + `DiscoverScreen`.
  Preconditions: all section endpoints return HTTP 500 with no prior cache.
  Steps: load → assert `Error(retryable=true)`; render screen; tap Retry; MWS now returns 200.
  Expected: first state `Error` with user-readable message; Retry calls `retry()` →
  transitions to `Content`.
  Traces: AC-4.

- **TC-AND-182-07 — 422 validation error on search.**
  Type: contract/MockWebServer (JVM + MWS).
  Target: `DiscoveryApi.search` + error mapper.
  Preconditions: MWS returns 422 `HTTPValidationError`
  `{"detail":[{"loc":["query","q"],"msg":"...","type":"string_too_long"}]}` for an over-64-char `q`.
  Steps: invoke search with a 65-char query.
  Expected: `ApiResult.Failure` carrying the normalized `detail[].msg`; no crash on the
  array `detail` shape.
  Traces: AC-4, AC-6.

- **TC-AND-182-08 — Stale cache path (transient failure with prior success).**
  Type: contract/MockWebServer (JVM + MWS).
  Target: `@Singleton` in-memory cache in repository.
  Preconditions: one successful load cached; then a refresh where endpoints fail
  (timeout/5xx) while cache exists.
  Steps: `load()` success → `refresh()` failing.
  Expected: state stays `Content(isStale=true)`; existing content not blanked; stale banner
  flagged.
  Traces: AC-4, AC-5.

- **TC-AND-182-09 — Offline (no cache, no connectivity).**
  Type: integration (device — real airplane-mode toggle preferred).
  Target: ViewModel + AND-017 connectivity signal.
  Preconditions: fresh process, no cached content, device offline.
  Steps: open Discover.
  Expected: terminal state `Offline` (AND-021 offline composable with Retry); no stale
  content shown. MUST run on **device** to exercise real radio/connectivity transitions
  (emu connectivity is simulated); a JVM variant with a faked connectivity provider covers
  the classification logic.
  Traces: AC-4.

- **TC-AND-182-10 — Flaky cleartext dev host end-to-end.**
  Type: instrumented/e2e (device).
  Target: full stack against `http://18.222.237.167:8000`.
  Preconditions: dev flavor build (cleartext network-security config), authenticated
  session; physical device on real network.
  Steps: launch app → navigate to `discover`; if the host stalls, confirm 20s call timeout
  + bounded backoff then graceful state (stale/offline/error, never ANR/blank).
  Expected: Discover renders real curated content and navigates to a profile; transient
  host failures degrade gracefully. MUST run on **device** (real flaky network + API-34/
  arm64 ABI smoke).
  Traces: AC-1, AC-2, AC-4.

- **TC-AND-182-11 — Pull-to-refresh.**
  Type: Compose-UI (emu35).
  Target: `PullToRefreshBox` + `refresh()`/`isRefreshing`.
  Preconditions: `Content` state.
  Steps: trigger pull-to-refresh; MWS returns updated content.
  Expected: `isRefreshing=true` shown during fetch then false; grid replaced with new
  content; refresh failure shows transient snackbar without blanking (per §7).
  Traces: AC-5.

- **TC-AND-182-12 — Nav events not re-emitted on re-subscription (config change).**
  Type: unit (JVM).
  Target: `DiscoverViewModel` `Channel`/`receiveAsFlow` nav events + `LazyGridState`
  scroll retention.
  Preconditions: emit one `OpenProfile`; simulate new collector (recreation).
  Steps: collect `navEvents`, trigger click, re-collect.
  Expected: event delivered exactly once; not redelivered to the new collector; scroll
  index preserved via `LazyGridState` saver.
  Traces: AC-2, AC-4.

- **TC-AND-182-13 — Security: cleartext blocked in release; cache cleared on logout; no PII.**
  Type: unit + instrumented (JVM for logout/PII; emu35 for release-config assertion).
  Target: network-security config, `@Singleton` cache clear (AND-032), logger redaction.
  Preconditions: release flavor build; a populated discover cache; logout fixture.
  Steps: (a) attempt cleartext request from release build → expect blocked; (b) trigger
  logout → assert in-memory cache cleared so next session cannot read prior creators;
  (c) inspect emitted logs/telemetry for display names/URLs/taglines.
  Expected: release build cannot reach a cleartext host; cache empty post-logout; logs
  contain only opaque ids (section/item id), no PII.
  Traces: AC-7.

- **TC-AND-182-14 — Accessibility (TalkBack, targets, font scaling, RTL).**
  Type: Compose-UI / instrumented (emu35; spot-check on device with real TalkBack).
  Target: `DiscoverScreen` semantics.
  Preconditions: `Content` state.
  Steps: assert section headers expose `heading()` semantics; creator card
  `contentDescription` = "Creator: {displayName}, {n} followers"; tag chip "Tag: #{tag}";
  touch targets ≥ 48dp; titles ellipsize at large font scale without layout break; RTL
  mirrors chevrons/start-end padding; stale banner announced as `liveRegion = Polite`.
  Expected: all semantics/measurements pass; real-TalkBack spot-check announces cards
  correctly on **device**.
  Traces: AC-3, AC-4.

### Coverage matrix

| Acceptance criterion | Covered by |
|---|---|
| AC-1 (loads + renders grid) | TC-01, TC-02, TC-10 |
| AC-2 (post/creator navigation) | TC-03, TC-04, TC-10, TC-12 |
| AC-3 (imagery: placeholder/aspect/cancel) | TC-14 (+ AND-103 `MediaThumbnail` suite, inherited) |
| AC-4 (Loading/Content/Empty/Error/Offline; never blank) | TC-05, TC-06, TC-07, TC-08, TC-09, TC-10, TC-12, TC-14 |
| AC-5 (pull-to-refresh + isRefreshing) | TC-08, TC-11 |
| AC-6 (UI tests pass; GET decode + VM transitions MWS-tested) | TC-01, TC-02, TC-06, TC-07 |
| AC-7 (no PII in logs; cache cleared on logout) | TC-13 |
