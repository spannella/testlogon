---
id: AND-098
title: Feed list (Paging 3)
milestone: M2
epic: E14
priority: P0
size: M
status: draft
depends_on: [AND-097]
blocks: [AND-099]
---

# AND-098 — Feed list (Paging 3)

## 1. Overview & Goal

Build the scrollable newsfeed surface for the TestLogon Android app: a Paging 3
backed list that loads the authenticated user's feed page-by-page from the
FastAPI backend, supports pull-to-refresh, and renders inline loading and error
footers for append (pagination) and prepend states. This ticket owns the
**Paging source, the `PagingData<FeedPost>` stream, the `LazyColumn` host,
and the load-state UI scaffolding**. It does **not** own the visual rendering of
an individual post (that is AND-099 — Post item composable) nor media thumbnail
loading (AND-103). Here we render a minimal placeholder row so the list is
exercisable end-to-end against the live backend; AND-099 will replace that row.

Success means: a signed-in user opens the Feed tab, sees the first page load,
can scroll to trigger infinite append of subsequent pages, can pull-to-refresh to
reset to page one, and sees a retriable error footer when the (unreliable) dev
backend times out or fails mid-pagination.

## 2. Context & References

- **Module:** `feature-feed` (new), depending on `core-network`, `core-model`,
  `core-data`, `core-ui`, `core-testing`. Namespace
  `com.testlogon.android.feature.feed`.
- **Upstream (AND-097):** provides `FeedApi` (Retrofit), the `FeedPost` /
  `FeedPageDto` Moshi DTOs incl. paywall/locked metadata, and
  `FeedRepository`. This ticket consumes that repository's paged endpoint; it
  must not redefine DTOs or the Retrofit interface.
- **Downstream (AND-099):** `PostItem(post: FeedPost)` composable replaces the
  placeholder row introduced here. **AND-103** layers Coil thumbnails into that
  item.
- **Auth:** the feed is a cookie-authenticated surface. All requests ride the
  persistent cookie jar + `X-CSRF-Token` header established by the session stack
  (AND-027 et al.). On `401`, the OkHttp authenticator/interceptor performs a
  single `POST /ui/session/refresh` then retries — Paging code must treat the
  post-refresh failure as a terminal `LoadState.Error`, not loop.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable). OpenAPI at `/openapi.json`. Web reference:
  `frontend/src/api/endpoints/newsfeed.ts`, types in
  `frontend/src/api/types.ts`.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Paging 3 (`paging-runtime` +
  `paging-compose`), Hilt (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 /
  Moshi 1.15. minSdk 24, compile/target 35.

## 3. Functional Requirements

FR-1. **Initial load.** On entering the Feed screen the list issues a `REFRESH`
load for the first page; a full-screen centered progress indicator shows while
`loadState.refresh is LoadState.Loading` and the list is empty.

FR-2. **Infinite scroll (append).** As the user scrolls near the end, Paging 3
requests the next page via the cursor/offset returned by the previous page. A
footer row shows a small spinner while `loadState.append is LoadState.Loading`.

FR-3. **Append error footer.** If an append fails (timeout/5xx/network), a footer
row shows an error message and a **Retry** button that calls `retry()`. The
already-loaded items remain visible and scrollable.

FR-4. **Refresh error.** If the initial/refresh load fails on an empty list, a
full-screen error state with a **Retry** button is shown. If refresh fails while
items are already present (e.g. during pull-to-refresh), existing items remain
and a transient error is surfaced (snackbar via shared host) without clearing the
list.

FR-5. **Pull-to-refresh.** A Material 3 `PullToRefreshBox` wraps the list; the
gesture invokes `refresh()` on the `LazyPagingItems`. The indicator reflects
`loadState.refresh is LoadState.Loading`.

FR-6. **Empty state.** When refresh completes successfully and
`itemCount == 0 && loadState.append.endOfPaginationReached`, show a non-error
empty state ("Your feed is empty").

FR-7. **End of pagination.** When the backend returns no `next_cursor`, no
further append requests are made and no footer is shown.

FR-8. **Placeholder row.** Each item renders a temporary `FeedRowPlaceholder`
exposing the post id and a one-line text snippet, sufficient for manual/automated
verification until AND-099 lands. Locked/paywall posts (AND-097 metadata) render
a "Locked" badge in the placeholder so the flag is visibly plumbed through.

FR-9. **State preservation.** Scroll position and the `PagingData` stream survive
configuration changes and back-stack navigation within the session
(`cachedIn(viewModelScope)`).

## 4. Technical Design

### 4.1 Layering

```
FeedScreen (Composable)            feature-feed/ui
  -> FeedViewModel (Hilt)          feature-feed/ui
       -> FeedRepository (AND-097) core-data
            -> FeedPagingSource    feature-feed/data   (this ticket)
                 -> FeedApi        core-network (AND-097)
```

### 4.2 PagingSource

The backend feed is cursor-paginated (opaque `next_cursor`). We implement a
`PagingSource<String, FeedPost>` keyed by cursor.

```kotlin
class FeedPagingSource(
    private val repository: FeedRepository,
) : PagingSource<String, FeedPost>() {

    override suspend fun load(
        params: LoadParams<String>,
    ): LoadResult<String, FeedPost> = when (
        val result = repository.getFeedPage(
            cursor = params.key,           // null => first page
            limit = params.loadSize,
        )
    ) {
        is ApiResult.Success -> LoadResult.Page(
            data = result.data.items,
            prevKey = null,                // forward-only feed
            nextKey = result.data.nextCursor, // null at end-of-feed
        )
        is ApiResult.Failure -> LoadResult.Error(result.toThrowable())
    }

    // Forward-only cursor feed cannot resume from an arbitrary anchor;
    // invalidation restarts at page one.
    override fun getRefreshKey(state: PagingState<String, FeedPost>): String? = null
}
```

`FeedRepository.getFeedPage` (defined in AND-097) returns
`ApiResult<FeedPageDto>` where `FeedPageDto.items: List<FeedPost>` and
`nextCursor: String?`. `ApiResult.toThrowable()` is a shared helper in
`core-network` that converts a typed failure (network/timeout/http+detail) into a
`FeedException` carrying a user-facing message and an `isRetryable` flag.

### 4.3 Pager / ViewModel

```kotlin
@HiltViewModel
class FeedViewModel @Inject constructor(
    private val repository: FeedRepository,
) : ViewModel() {

    val feed: Flow<PagingData<FeedPost>> = Pager(
        config = PagingConfig(
            pageSize = 20,
            initialLoadSize = 20,      // one page; dev host is slow
            prefetchDistance = 5,
            enablePlaceholders = false,
        ),
        pagingSourceFactory = { FeedPagingSource(repository) },
    ).flow.cachedIn(viewModelScope)
}
```

`pageSize == initialLoadSize` (no 3x initial multiplier) to keep the first paint
fast against a ~20s-timeout host. `enablePlaceholders = false` because total feed
size is unknown.

### 4.4 Compose host

```kotlin
@Composable
fun FeedScreen(
    viewModel: FeedViewModel = hiltViewModel(),
    onPostClick: (postId: String) -> Unit,
)

@Composable
private fun FeedList(
    items: LazyPagingItems<FeedPost>,
    onPostClick: (String) -> Unit,
    modifier: Modifier = Modifier,
)
```

`FeedScreen` collects via `viewModel.feed.collectAsLazyPagingItems()`, wraps a
`PullToRefreshBox` whose `isRefreshing` is derived from
`items.loadState.refresh`, and dispatches to one of: full-screen loading,
full-screen retriable error, empty state, or `FeedList`. `FeedList` is a
`LazyColumn` with:

- `items(count = items.itemCount, key = items.itemKey { it.id }, ...)` rendering
  `FeedRowPlaceholder(post)`.
- A trailing `item { }` that switches on `items.loadState.append`:
  `Loading -> FooterLoading()`, `Error -> FooterError(onRetry = items::retry)`.

```kotlin
@Composable private fun FeedRowPlaceholder(post: FeedPost, onClick: () -> Unit)
@Composable private fun FooterLoading()
@Composable private fun FooterError(message: String, onRetry: () -> Unit)
@Composable private fun FeedEmpty()
@Composable private fun FeedFullScreenError(message: String, onRetry: () -> Unit)
```

### 4.5 Hilt wiring

`FeedRepository` is bound in AND-097's `core-data` module. This ticket adds no new
binding beyond `@HiltViewModel`; `FeedPagingSource` is constructed by the factory
lambda, not injected, so its lifetime matches each `Pager` invalidation.

## 5. API Contract

This ticket **consumes** the endpoint defined and tested in AND-097; the
authoritative DTOs live there. Documented here for the paging contract only.

**Request** — `GET /ui/feed` (cursor pagination; confirm exact path/params
against `/openapi.json` and `frontend/src/api/endpoints/newsfeed.ts` during
AND-097):

```
GET /ui/feed?limit=20
GET /ui/feed?limit=20&cursor=<opaque-next-cursor>
Cookie: <session cookies>
X-CSRF-Token: <ui_csrf value>
```

**Response 200** (`FeedPageDto`):

```json
{
  "items": [
    {
      "id": "post_01HZ...",
      "author": { "id": "usr_123", "display_name": "Jane", "avatar_url": "https://..." },
      "text": "hello world",
      "media": [{ "id": "med_1", "type": "image", "url": "https://...", "thumb_url": "https://..." }],
      "created_at": "2026-06-04T18:22:11Z",
      "locked": false,
      "paywall": { "required": false, "tier": null }
    }
  ],
  "next_cursor": "eyJvZmZzZXQiOjIwfQ==",
  "has_more": true
}
```

- `next_cursor == null` (or `has_more == false`) => `nextKey = null` =>
  `endOfPaginationReached`.
- Paging maps `items -> List<FeedPost>`, `next_cursor -> nextKey`.

**Error responses.** FastAPI `detail` may be `string | [{msg}] | {code,...}`;
mapping is owned by `core-network` (`ApiResult` + `detail` mapper). Relevant to
this ticket: `401` triggers the single-refresh-then-retry interceptor; a
persisting `401`, any `5xx`, or a socket/timeout becomes `LoadResult.Error` with
a retryable `FeedException`.

## 6. Data & State Management

- **Source of truth:** `Flow<PagingData<FeedPost>>` from `Pager`, `cachedIn`
  `viewModelScope` so re-collection on recomposition/navigation does not refetch.
- **Load state:** consumed in UI via `LazyPagingItems.loadState`
  (`CombinedLoadStates` for `refresh`/`append`/`prepend`). No separate
  `StateFlow<UiState>` is needed for list content; a small
  `StateFlow<FeedScreenEvent>` (snackbar messages for non-empty refresh failures)
  may be added if a shared snackbar host is wired — otherwise emit via the
  collected load state.
- **Keys:** `items.itemKey { it.id }` for stable diffing and scroll retention.
- **Caching:** No Room mediation in this ticket (online-only paging). A
  `RemoteMediator` backed by Room is explicitly out of scope and deferred; if
  offline feed caching is later required it becomes a separate ticket in E14.
- **Pagination params:** `cursor: String?`, `limit = pageSize = 20`. Forward-only;
  `prevKey` always `null`.

## 7. Error Handling & Resilience

- **Timeouts:** OkHttp call timeout ~20s (configured in `core-network`). A
  timeout surfaces as `LoadResult.Error`.
- **Retry semantics:** Feed GETs are idempotent, so the shared bounded-backoff
  retry interceptor for idempotent GETs applies at the network layer. Paging
  `retry()` re-invokes `load()` and is wired to the footer/full-screen Retry
  buttons.
- **Append failure:** keep loaded items; show `FooterError` with Retry. Never
  clear the list on append failure.
- **Refresh failure with content present:** do not clear; surface a transient
  error (snackbar) and leave existing items.
- **Refresh failure on empty list:** full-screen retriable error.
- **401 loop guard:** rely on the interceptor's single-refresh contract; if the
  retried request still `401`s, treat as terminal error (do not retry in Paging,
  to avoid hammering the dev host).
- **Stale/offline:** with no network, `load()` returns Error immediately;
  full-screen or footer error per state above. Offline cached display is
  out-of-scope (see §6).
- **Empty vs error disambiguation:** empty state only when refresh is
  `NotLoading`, `endOfPaginationReached`, and `itemCount == 0`.

## 8. Security & Privacy

- All feed requests are cookie-authenticated over the persistent cookie jar with
  the `X-CSRF-Token` header echoed from the `ui_csrf` cookie; this ticket adds no
  new auth handling and must not bypass the shared OkHttp client.
- No session tokens, cookies, or post bodies are logged (see §10).
- Dev backend is **plaintext HTTP**; this is a known dev-only posture. Production
  builds must use HTTPS; `usesCleartextTraffic` is gated to debug/dev flavors in
  the build config (owned by network/build tickets, noted here for compliance).
- Paywall/locked content: this ticket only plumbs the `locked`/`paywall` flags
  into the placeholder badge; it must not fetch or expose locked media. Gating UX
  is downstream (AND-099+).
- No PII is persisted to disk by this ticket (no Room mediator).

## 9. Accessibility & i18n

- All user-facing strings (loading, error, retry, empty) are
  `stringResource`-backed in `feature-feed/res/values/strings.xml`; no hardcoded
  literals. Keys: `feed_loading`, `feed_empty`, `feed_error_generic`,
  `feed_retry`, `feed_locked_badge`.
- Retry buttons have a min 48x48dp touch target and a content description.
- The footer spinner sets `Modifier.semantics { contentDescription = ... }`
  ("Loading more posts").
- Pull-to-refresh is operable via the standard accessibility refresh action.
- List supports TalkBack linear navigation; placeholder row exposes a merged
  semantics node with the post snippet.
- RTL: layout uses start/end padding; no hardcoded left/right.

## 10. Telemetry & Logging

- Structured debug logs (Timber, debug builds only): `feed_refresh_start`,
  `feed_refresh_result{success,count,durationMs}`,
  `feed_append_start{cursorPresent}`, `feed_append_result{success,count}`,
  `feed_load_error{type,httpStatus}`. **No post text, author, cookies, or
  cursors values** are logged (cursors may be opaque but are treated as
  sensitive; log only presence boolean).
- Analytics events (if the app analytics facade from core is available):
  `feed_viewed`, `feed_pull_refresh`, `feed_append_retry`,
  `feed_load_failed{stage,errorType}`. Counts only; no content.
- Load-state transitions are observable in tests via the `LoadState` API; no
  bespoke telemetry surface is required for acceptance.

## 11. Testing Strategy

**Unit — `FeedPagingSource` (core-testing + JUnit + Turbine/coroutines-test):**
- `load` with `key == null` and a success page returns `LoadResult.Page` with
  correct `data`, `prevKey == null`, `nextKey == next_cursor`.
- `next_cursor == null` => `nextKey == null` (end of pagination).
- Repository `ApiResult.Failure` => `LoadResult.Error` with a retryable
  `FeedException`.
- `getRefreshKey` returns null.

**Integration — repository + MockWebServer (core-network test rig):**
- Two-page sequence (`next_cursor` then null) drives append then
  `endOfPaginationReached`.
- A `503`/timeout mid-sequence yields `LoadState.Error` on append; a subsequent
  `retry()` with a `200` recovers and appends.
- `401` then (post-refresh) `200` succeeds; persistent `401` => terminal error.

**Paging differ test:** use `AsyncPagingDataDiffer` (or
`PagingData.asSnapshot { }`) to assert the realized list for the two-page
sequence equals the concatenated items.

**Compose UI (`createComposeRule`):**
- Initial loading shows full-screen progress (empty list).
- Loaded list shows N placeholder rows; locked post shows the Locked badge.
- Append-error footer shows Retry; tapping it invokes `retry()` (verified via
  fake `LazyPagingItems` / test repository).
- Empty result shows empty state, not error.
- Pull-to-refresh gesture triggers a refresh load (verified via repository call
  count).

**Manual / live backend (acceptance):** against
`http://18.222.237.167:8000`, signed in: first page loads, scroll appends
subsequent pages, pull-to-refresh resets to page one, induced failure shows
retriable footer.

## 12. Dependencies & Sequencing

- **Hard dependency — AND-097 (Feed API + DTOs):** must land first; provides
  `FeedApi`, `FeedRepository.getFeedPage`, `FeedPost`, `FeedPageDto`, and the
  `locked`/`paywall` metadata this ticket plumbs.
- **Transitive:** AND-027 (auth/session stack) and the `core-network`
  `ApiResult` + cookie/CSRF + refresh interceptor must be in place (they are, by
  M1).
- **Blocks — AND-099 (Post item composable):** replaces `FeedRowPlaceholder`
  with the real `PostItem`. The placeholder API (`FeedRowPlaceholder(post,
  onClick)`) and the `key`/click contract are designed to be drop-in
  replaceable.
- **Adjacent — AND-103 (media thumbnails):** depends on AND-099, not directly on
  this ticket.
- **Sequencing:** AND-097 -> **AND-098** -> AND-099 -> AND-103.

## 13. Risks & Open Questions

- **OQ-1 (path/params):** exact feed endpoint path and pagination param names
  (`cursor` vs `after`, `limit` vs `page_size`) are owned by AND-097 — confirm
  against `/openapi.json` and `newsfeed.ts`. This spec assumes
  `GET /ui/feed?limit=&cursor=`.
- **OQ-2 (pagination style):** assumes opaque-cursor forward-only. If the backend
  is offset/page-number based, swap `PagingSource<String, _>` for
  `PagingSource<Int, _>` and implement `getRefreshKey` accordingly — small,
  contained change.
- **Risk-1 (flaky dev host):** ~20s timeouts make manual acceptance slow and
  intermittently failing; mitigate via the network retry interceptor and clear
  retriable error UI. Do not add unbounded Paging-level retries.
- **Risk-2 (duplicate items on refresh):** if the backend re-orders/inserts
  between pages, cursor paging can show dupes; `itemKey { it.id }` dedupes in the
  differ but visual gaps are possible — acceptable for M2.
- **OQ-3 (snackbar host):** whether a shared Scaffold snackbar host exists for
  non-empty refresh-failure messaging, or whether this screen owns one. Default
  to a screen-local host if none is provided.

## 14. Acceptance Criteria

AC-1. Against the dev backend, a signed-in user sees the first feed page load,
then **infinite scroll appends** subsequent pages until `next_cursor` is null
(no further requests after end-of-pagination). *(maps to source Acceptance:
"Infinite scroll … work against backend")*

AC-2. **Pull-to-refresh** resets the list to page one and shows a refresh
indicator while loading. *(maps to: "refresh work against backend")*

AC-3. An append failure shows a footer with a **Retry** control that, on tap,
re-attempts and (on success) appends the next page; existing items are never
cleared on append failure.

AC-4. A refresh failure on an empty list shows a full-screen retriable error; on
a non-empty list it preserves items and surfaces a transient error.

AC-5. A successful empty feed shows the empty state, distinct from the error
state.

AC-6. `locked`/`paywall` metadata from AND-097 is visibly reflected (Locked
badge) in the placeholder row.

AC-7. Scroll position and loaded pages survive configuration change and
in-session back navigation (no refetch on return), verified by `cachedIn`
behavior.

AC-8. Unit tests for `FeedPagingSource` (success/end/error), an
`asSnapshot`/differ two-page test, and Compose tests for loading/error/empty/
retry all pass; MockWebServer integration covers the 401-refresh and
timeout-retry paths.

## 15. Definition of Done

- `feature-feed` module created with `FeedPagingSource`, `FeedViewModel`,
  `FeedScreen` + `FeedList` and load-state composables; package
  `com.testlogon.android.feature.feed`.
- Consumes AND-097's `FeedRepository.getFeedPage`; no DTO/Retrofit duplication.
- All FR-1..FR-9 implemented; AC-1..AC-8 verified.
- All user-facing strings externalized; a11y semantics and touch targets in
  place.
- No sensitive data logged; uses the shared cookie/CSRF OkHttp client only.
- Unit + integration + Compose tests added and green in CI; `./gradlew :feature-feed:test :feature-feed:connectedDebugAndroidTest` (or instrumented equivalent) passes.
- `FeedRowPlaceholder` documented as the AND-099 replacement point (KDoc +
  `// TODO(AND-099)`).
- Lint/detekt clean; merged to `android-port` with a passing review against this
  spec.
