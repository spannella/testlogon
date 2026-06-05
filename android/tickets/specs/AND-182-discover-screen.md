---
id: AND-182
title: Discover screen
milestone: M4
epic: E25
priority: P1
size: M
status: draft
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
renders it as a responsive grid of cards. Curated content is organized into one or more
**sections** (e.g. "Trending", "Recommended creators", "New posts"); each section has a
title and an ordered list of items. Items are heterogeneous: a card is either a **post**
or a **creator/profile**.

FR-3. Each card displays its primary image (post thumbnail or creator avatar/cover) using
the AND-103 Coil conventions: placeholder while loading, crossfade in, correct aspect
ratio, request cancellation on scroll-off, and data-saver respect.

FR-4. Tapping a **post** card navigates to post detail (`post/{postId}`, owned by
AND-100). Tapping a **creator** card navigates to the public profile
(`profile/{userIdentifier}`, owned by AND-073). Navigation passes only the identifier;
target screens own their own data loading.

FR-5. Pull-to-refresh re-fetches curated content and replaces the rendered grid.

FR-6. The screen renders distinct states: Loading (initial), Content, Empty (curated set
is empty), Error (recoverable, with Retry), and Offline/Stale (no connectivity; show last
cached content if available with a stale banner, else the offline state). State
composables are reused from AND-021.

FR-7. Locked/paywalled post cards render a lock affordance (visual only) and still
navigate to post detail, which owns the paywall display (AND-101). Discover does not
gate navigation.

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
    data class Post(
        override val id: String,
        val postId: String,
        val thumbnailUrl: String?,
        val title: String?,
        val authorDisplayName: String?,
        val isLocked: Boolean,
        val aspectRatio: Float?,   // width/height; null => fallback square
    ) : DiscoverItem
    data class Creator(
        override val id: String,
        val userIdentifier: String,   // the "u/identifier" used by public profile
        val displayName: String,
        val avatarUrl: String?,
        val coverUrl: String?,
        val tagline: String?,
    ) : DiscoverItem
}
```

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
    data class OpenProfile(val userIdentifier: String) : DiscoverNavEvent
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
                is DiscoverItem.Creator -> DiscoverNavEvent.OpenProfile(item.userIdentifier)
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

```kotlin
interface DiscoverRepository {
    fun discover(forceRefresh: Boolean): Flow<ApiResult<List<DiscoverSection>>>
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

Endpoints port `frontend/src/api/endpoints/discovery.ts`; confirm against `/openapi.json`.
All calls are authenticated GETs riding the cookie jar + `X-CSRF-Token` (AND-027) and are
eligible for idempotent-GET retry/backoff (AND-016).

```kotlin
interface DiscoveryApi {
    @GET("discovery")
    suspend fun getDiscover(
        @Query("cursor") cursor: String? = null,
    ): Response<DiscoverFeedDto>
}
```

Expected response shape (`DiscoverFeedDto`, Moshi):

```json
{
  "sections": [
    {
      "id": "trending",
      "title": "Trending",
      "items": [
        {
          "type": "post",
          "id": "p_abc123",
          "post_id": "abc123",
          "thumbnail_url": "https://.../t.jpg",
          "title": "Behind the scenes",
          "author_display_name": "Ava",
          "is_locked": false,
          "width": 1080,
          "height": 1350
        },
        {
          "type": "creator",
          "id": "c_u_ava",
          "user_identifier": "ava",
          "display_name": "Ava",
          "avatar_url": "https://.../a.jpg",
          "cover_url": "https://.../c.jpg",
          "tagline": "Daily drops"
        }
      ]
    }
  ]
}
```

```kotlin
@JsonClass(generateAdapter = true)
data class DiscoverFeedDto(val sections: List<DiscoverSectionDto>)

@JsonClass(generateAdapter = true)
data class DiscoverSectionDto(
    val id: String,
    val title: String,
    val items: List<DiscoverItemDto>,
)

@JsonClass(generateAdapter = true)
data class DiscoverItemDto(
    val type: String,           // "post" | "creator"
    val id: String,
    @Json(name = "post_id") val postId: String? = null,
    @Json(name = "thumbnail_url") val thumbnailUrl: String? = null,
    val title: String? = null,
    @Json(name = "author_display_name") val authorDisplayName: String? = null,
    @Json(name = "is_locked") val isLocked: Boolean = false,
    val width: Int? = null,
    val height: Int? = null,
    @Json(name = "user_identifier") val userIdentifier: String? = null,
    @Json(name = "display_name") val displayName: String? = null,
    @Json(name = "avatar_url") val avatarUrl: String? = null,
    @Json(name = "cover_url") val coverUrl: String? = null,
    val tagline: String? = null,
)
```

`DiscoverMapper` discriminates on `type`; unknown `type` values are dropped (forward
compatibility) and logged. `aspectRatio = width/height` when both present. Error bodies use
the FastAPI `detail` shape (string | `[{msg}]` | `{code,...}`) and are decoded by the
shared error mapper (AND-015) into `ApiResult.Failure`. If `/openapi.json` reveals the
discover surface is split (e.g. separate curated-sections and trending endpoints) rather
than a single `discovery` GET, expand `DiscoveryApi` accordingly and aggregate in the
repository — the section model above is the stable contract for the UI either way.

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
  - 401 → handled transparently by the refresh authenticator (AND-013); a second 401 after
    refresh surfaces as auth failure and defers to global re-auth routing (AND-025), not a
    local error state.
- Partial/malformed items are skipped, not fatal; a section with zero valid items after
  filtering is omitted; if all sections are empty → `Empty`.
- Refresh failures while showing `Content` keep existing content and show a transient
  snackbar; they never blank the screen.

## 8. Security & Privacy

- All requests authenticated via the persistent cookie jar (AND-011) + `X-CSRF-Token`
  echo (AND-012); no tokens or credentials handled directly here.
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
- Cards expose `contentDescription`: post cards → "Post: {title} by {author}", creator
  cards → "Creator: {displayName}"; the lock affordance announces "Locked".
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
  - `DiscoveryApi` decodes the curated JSON fixture into `DiscoverFeedDto`; mixed
    post/creator items map correctly; unknown `type` dropped.
  - `DiscoverMapper`: aspect ratio computation, lock flag, null-field tolerance, empty
    section omission.
  - `DefaultDiscoverRepository`: success → sections; failure with cache → stale; failure
    without cache + offline → offline classification; cache cleared on logout.
  - `DiscoverViewModel`: state transitions Loading→Content/Empty/Error/Offline; `refresh`
    sets `isRefreshing`; `onItemClick` emits correct `DiscoverNavEvent`; nav event not
    re-emitted on re-subscription.
- **Compose UI tests (AND-048 harness):**
  - Loading shows spinner; Content shows section headers + cards; Empty/Error/Offline
    render their respective composables; Retry invokes `retry()`.
  - Tapping a post card invokes `onOpenPost(postId)`; tapping a creator card invokes
    `onOpenProfile(userIdentifier)` (verified via test lambdas).
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

- **R1 — Endpoint shape uncertainty.** `discovery.ts` may expose multiple endpoints or a
  cursor-paginated curated feed rather than a single bounded GET. Mitigation: verify
  `/openapi.json` before implementation; keep the section model stable and aggregate in the
  repository. *Open: is discover paginated?* If yes, escalate to a Paging 3 follow-up
  (reuse AND-098 patterns) — out of scope for this ticket's bounded grid.
- **R2 — Item heterogeneity.** Backend may add item types (e.g. "collection", "event").
  Mitigation: discriminator-based mapping that drops unknowns; UI degrades gracefully.
- **R3 — Locked content navigation.** Confirm product intent that locked posts still
  navigate to detail (paywall shown there per AND-101) vs. opening a paywall sheet from
  Discover. *Open question for product.* Current design: navigate to detail.
- **R4 — Unreliable dev host** inflates perceived load times; the stale path and 20s
  timeout mitigate, but empty-vs-error classification depends on connectivity signal
  fidelity (AND-017).
- **R5 — Image auth.** Whether discover media URLs require the cookie'd OkHttp client is
  unconfirmed; default to AND-103 behavior and revisit if 401s appear on images.

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
