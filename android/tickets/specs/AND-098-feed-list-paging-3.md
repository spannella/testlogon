---
id: AND-098
title: Feed list (Paging 3)
milestone: M2
epic: E14
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
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
  `FeedPageDto` Moshi DTOs incl. lock metadata (`lock_type`,
  `unlock_price_cents`, `unlocked`, `lock_expired`, `unlock_limit_reached` — see
  §16; there is no `locked`/`paywall` field), and `FeedRepository`. This ticket
  consumes that repository's paged endpoint; it must not redefine DTOs or the
  Retrofit interface.
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
verification until AND-099 lands. Locked posts render a "Locked" badge in the
placeholder so the flag is visibly plumbed through. **Correction (see §16):** the
backend `FeedPost` has **no** `locked`/`paywall` fields. Lock state is derived
from `lock_type` (`"fixed_price" | "tip_lottery"`) plus `unlock_price_cents`,
with `unlocked: bool` indicating the viewer has access and `lock_expired` /
`unlock_limit_reached` as further qualifiers. The badge shows when
`lock_type != null && unlocked != true`. AND-097's Kotlin DTO must model these
real fields, not a synthetic `locked`/`paywall` pair.

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

**Request** — `GET /feed` (cursor pagination). **Corrected (see §16):** the path
is `GET /feed`, **not** `/ui/feed`. Verified against the OpenAPI index
(`GET /feed | op=view_feed_feed_get`) and the web client
(`frontend/src/api/endpoints/newsfeed.ts: getFeed` -> `api.get("/feed", ...)`).

Available query params per OpenAPI: `limit, cursor, author_id, q, from, to,
has_media` (plus `user_sub` and the `X-SESSION-ID` / `X-IMPERSONATION-TOKEN`
headers used by the session/impersonation stack). The web client sends
`cursor, author_id, q, from, to, has_media` and **does not send `limit`** — the
server applies a default page size. This Android ticket MAY send `limit` (it is a
documented param) but must tolerate the server ignoring it; do not rely on
`limit` to bound a page exactly.

```
GET /feed
GET /feed?cursor=<opaque-next-cursor>
GET /feed?limit=20&cursor=<opaque-next-cursor>   # limit is optional/advisory
Cookie: <session cookies>          # credentials: "include"
X-CSRF-Token: <ui_csrf cookie value>
Authorization: Bearer <access token>   # web client also attaches the bearer token
```

**Response 200.** The OpenAPI declares no response schema for `GET /feed`
(`resp=200:` with an empty schema name), so the only authoritative shape is the
web client's declared type
(`frontend/src/api/endpoints/newsfeed.ts`): `{ items: FeedPost[]; next_cursor?:
string }`. **Corrected (see §16):** there is **no `has_more` field**; end of
pagination is signalled solely by an absent/empty `next_cursor`.

The real `FeedPost` shape (`frontend/src/api/types.ts: FeedPost`) differs
substantially from the draft below — the fields shown earlier (`id`, nested
`author`, `text`, `media[]`, `locked`, `paywall`) were a fabricated guess and are
**Corrected** here. Authoritative key fields:

```json
{
  "items": [
    {
      "post_id": "post_01HZ...",
      "author_id": "usr_123",
      "body": "hello world",
      "image_urls": ["https://..."],
      "video": null,
      "created_at": "2026-06-04T18:22:11Z",
      "like_count": 0,
      "comment_count": 0,
      "lock_type": "fixed_price",
      "unlock_price_cents": 500,
      "unlocked": false,
      "lock_expired": false,
      "unlock_limit_reached": false
    }
  ],
  "next_cursor": "eyJvZmZzZXQiOjIwfQ=="
}
```

- `post_id` (not `id`), `author_id` is a flat string (not a nested `author`
  object; display name/avatar are resolved elsewhere), `body` (not `text`),
  media is `image_urls: string[]` / `image_variants` / `video` (not `media[]`).
- `next_cursor == null`/absent => `nextKey = null` => `endOfPaginationReached`.
- Paging maps `items -> List<FeedPost>`, `next_cursor -> nextKey`.
- These DTOs are owned/modelled by AND-097; this ticket only consumes them. The
  shapes above are the contract AND-097's Moshi DTOs must match.

**Error responses.** The only declared non-200 response for `GET /feed` is `422
HTTPValidationError` (`{ "detail": [ { "loc": [...], "msg": "...", "type":
"..." } ] }`, schemas `HTTPValidationError`/`ValidationError`). For other codes
FastAPI returns `{ "detail": ... }` where `detail` may be a string or an object;
mapping is owned by `core-network` (`ApiResult` + `detail` mapper). Relevant to
this ticket: `401` triggers the single-refresh-then-retry flow (`POST
/ui/session/refresh`); a persisting `401`, any `5xx`, or a socket/timeout becomes
`LoadResult.Error` with a retryable `FeedException`.

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
- Locked content: this ticket only plumbs the lock flags (`lock_type`,
  `unlocked`, etc. — see §16) into the placeholder badge; it must not fetch or
  expose locked media. Gating UX is downstream (AND-099+).
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
  lock metadata this ticket plumbs (`lock_type`/`unlocked`/etc. — see §16).
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

- **OQ-1 (path/params): RESOLVED (see §16).** The endpoint is
  `GET /feed?cursor=<opaque>` (param name `cursor`); `limit` is a documented but
  optional/advisory param the web client omits. The earlier assumption of
  `GET /ui/feed` was wrong and has been corrected throughout. Remaining
  AND-097-owned detail: the exact server default page size when `limit` is
  omitted (unverified — not in the OpenAPI response schema).
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

AC-6. Lock metadata from AND-097 is visibly reflected (Locked badge) in the
placeholder row. **Corrected (see §16):** lock state derives from the real
`FeedPost` fields `lock_type` + `unlock_price_cents` + `unlocked` (and
`lock_expired` / `unlock_limit_reached`), not from non-existent `locked`/`paywall`
fields. Badge shows when `lock_type != null && unlocked != true`.

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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer.

1. **Feed endpoint is `GET /ui/feed`.** VERDICT: **Corrected** -> actual path is
   `GET /feed`. SOURCE: OpenAPI `GET /feed | op=view_feed_feed_get`
   (openapi.index.txt:265); frontend `src/api/endpoints/newsfeed.ts: getFeed`
   (`api.get("/feed", ...)`). No `GET /ui/feed` route exists in the index.

2. **HTTP method is GET.** VERDICT: **Verified.** SOURCE: OpenAPI `GET /feed`
   (openapi.index.txt:265); `src/api/endpoints/newsfeed.ts: getFeed` uses
   `api.get`.

3. **Pagination param is `cursor` (opaque, forward-only).** VERDICT: **Verified.**
   SOURCE: OpenAPI `GET /feed ... params=limit,cursor,author_id,q,from,to,...`
   (openapi.index.txt:265); `src/api/endpoints/newsfeed.ts: FeedQueryParams`
   (`cursor?: string`) and `getFeed` query building.

4. **Request sends `limit=20`.** VERDICT: **Corrected / partly unverified** ->
   `limit` is a valid OpenAPI query param but the web client does **not** send it
   (`getFeed` only forwards `cursor, author_id, q, from, to, has_media`). Sending
   `limit` is allowed; the server default page size when omitted is not in the
   spec. SOURCE: openapi.index.txt:265 (param list) vs `src/api/endpoints/
   newsfeed.ts: getFeed` (no `limit` in query).

5. **Response 200 shape is `{ items, next_cursor }`.** VERDICT: **Verified (frontend
   only).** SOURCE: `src/api/endpoints/newsfeed.ts: getFeed` return type
   `{ items: FeedPost[]; next_cursor?: string }`. NOTE: OpenAPI declares no 200
   response schema for `GET /feed` (`resp=200:` empty), so the frontend type is
   the only authoritative shape.

6. **Response includes a `has_more` boolean.** VERDICT: **Corrected** -> no such
   field. End-of-pagination is signalled by absent/empty `next_cursor` only.
   SOURCE: `src/api/endpoints/newsfeed.ts: getFeed` type
   (`{ items; next_cursor? }`, no `has_more`).

7. **`FeedPost` fields are `id`, nested `author{}`, `text`, `media[]`,
   `created_at`, `locked`, `paywall`.** VERDICT: **Corrected** -> real fields are
   `post_id`, `author_id` (flat string), `body`, `image_urls[]` /
   `image_variants` / `video`, `created_at`, `like_count`, `comment_count`. There
   are no `id`/`author`/`text`/`media`/`locked`/`paywall` fields. SOURCE:
   `src/api/types.ts: FeedPost` (lines ~2181-2270).

8. **Locked/paywall is expressed via `locked` + `paywall{required,tier}`.**
   VERDICT: **Corrected** -> lock state is `lock_type`
   (`"fixed_price" | "tip_lottery"`), `unlock_price_cents`, `unlocked` (viewer
   has access), `lock_expired`, `unlock_limit_reached`, plus tip-lottery fields
   (`lottery_*`). SOURCE: `src/api/types.ts: FeedPost` (lock fields at lines
   ~2207-2225).

9. **Auth is cookie + `X-CSRF-Token` from the `ui_csrf` cookie.** VERDICT:
   **Verified.** SOURCE: `src/api/client.ts` (`credentials: "include"`,
   `const csrf = getCookie("ui_csrf"); headers.set("X-CSRF-Token", csrf)`, lines
   ~124-170). NOTE: the web client **also** attaches `Authorization: Bearer
   <accessToken>` (client.ts:158-159) and optional `X-IMPERSONATION-TOKEN`; the
   feed is bearer+cookie+CSRF, not cookie-only. Whether the Android client uses a
   bearer token or pure cookie session is an AND-097/AND-027 decision (see Open
   assumptions).

10. **On 401, a single `POST /ui/session/refresh` then one retry; persistent 401
    is terminal.** VERDICT: **Verified.** SOURCE: `src/api/client.ts:
    refreshSession` (`fetch(withApiBase("/ui/session/refresh"), { method: "POST",
    credentials: "include" })`, line 122) and the 401 handler that refreshes once
    (guarded by `refreshPromise`) then retries and logs out on a second 401
    (lines 194-228); OpenAPI `POST /ui/session/refresh |
    op=ui_session_refresh_ui_session_refresh_post` (openapi.index.txt:1847).

11. **422 error body is FastAPI `{ detail: [{ loc, msg, type }] }`.** VERDICT:
    **Verified.** SOURCE: OpenAPI `resp=...;422:HTTPValidationError`
    (openapi.index.txt:265); schemas `HTTPValidationError` -> `detail:
    ValidationError[]` and `ValidationError{ loc, msg, type }`
    (openapi.pretty.json:37133, 80337).

12. **Network error (offline) surfaces distinctly from HTTP errors.** VERDICT:
    **Verified (web behavior).** SOURCE: `src/api/client.ts` catch block throws
    `ApiError(0, "Network error", err)` on fetch rejection (lines 185-189). The
    Android equivalent is an `IOException`/timeout mapped to a retryable
    `FeedException` (this ticket's §7).

13. **Paging 3 (`PagingSource` / `Pager` / `LazyPagingItems` / `cachedIn` /
    `collectAsLazyPagingItems`).** VERDICT: **Unverified-assumption (framework
    ref).** Sound use of AndroidX Paging 3 APIs; not derivable from backend/
    frontend sources. SOURCE: framework ref —
    https://developer.android.com/topic/libraries/architecture/paging/v3-overview
    and https://developer.android.com/develop/ui/compose/lists#large-datasets
    (paging-compose `collectAsLazyPagingItems`).

14. **Material 3 `PullToRefreshBox` for pull-to-refresh.** VERDICT:
    **Unverified-assumption (framework ref).** SOURCE: framework ref —
    https://developer.android.com/reference/kotlin/androidx/compose/material3/pulltorefresh/package-summary

15. **`PagingData.asSnapshot { }` / `AsyncPagingDataDiffer` for tests.** VERDICT:
    **Unverified-assumption (framework ref).** SOURCE: framework ref —
    https://developer.android.com/topic/libraries/architecture/paging/test

16. **Dev backend `http://18.222.237.167:8000`, plaintext, ~20s timeouts,
    unreliable.** VERDICT: **Unverified-assumption** (operational fact stated in
    the ticket; not checkable from the static sources here).

### Corrections made

- §5 request path `GET /ui/feed` -> `GET /feed` (claims 1, 2).
- §5 added that `limit` is optional/advisory and omitted by the web client
  (claim 4).
- §5 response: removed `has_more`; end-of-page is `next_cursor` absence (claim 6).
- §5 `FeedPost` JSON example rewritten to real fields: `post_id`, `author_id`,
  `body`, `image_urls`/`video`, `like_count`/`comment_count`, and the real lock
  fields (claims 7, 8).
- §5 error section: pinned the canonical `422 HTTPValidationError` array shape
  (claim 11).
- FR-8, AC-6, §2, §8, §12: replaced non-existent `locked`/`paywall` with the real
  lock fields (`lock_type` + `unlock_price_cents` + `unlocked` + `lock_expired` +
  `unlock_limit_reached`) (claim 8).
- §13 OQ-1 marked RESOLVED with the corrected path/param facts.
- Frontmatter: `status: reviewed`, added `reviewed_on: 2026-06-06`.

### Open assumptions

- **Server default page size when `limit` is omitted** — not in the OpenAPI 200
  schema (it is empty) and the web client omits `limit`; AND-097 must confirm
  empirically against the dev host.
- **Android auth mode (bearer vs pure cookie session).** The web client sends
  `Authorization: Bearer` + `ui_csrf` CSRF + session cookies. This spec assumes
  the Android session stack (AND-027/AND-097) presents an equivalent authenticated
  identity; whether it uses a bearer token, a cookie jar, or both is owned by
  those tickets and not re-verified here.
- **`X-SESSION-ID` / `X-IMPERSONATION-TOKEN` headers** appear on `GET /feed`'s
  param list. Impersonation is not in scope; whether the Android app must send
  `X-SESSION-ID` is an AND-027 concern (unverified here).
- **Cursor opacity / stability across refresh** — assumed opaque and forward-only
  (matches `FeedQueryParams.cursor: string`); the server's re-ordering behavior
  between pages (§13 Risk-2) cannot be verified statically.
- Paging 3 / Compose / Material 3 API choices (claims 13-15) are framework-doc
  assumptions, not contract-derived.

## 17. Test Plan

Test IDs `TC-AND-098-NN`. Targets: **JVM** = JVM/Robolectric local (no device);
**emu test35** = headless AVD `test35` (x86_64, API 35); **device A15** =
physical Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, API 34, arm64-v8a).
Most cases are device-agnostic; the live-backend acceptance and ABI/API-skew
cases note their target explicitly.

**TC-AND-098-01 — PagingSource first page success**
- Type: unit (JVM).
- Target: `FeedPagingSource.load`.
- Preconditions: fake `FeedRepository.getFeedPage` returns
  `ApiResult.Success(FeedPageDto(items=[3 posts], nextCursor="c2"))`.
- Steps: call `load(LoadParams.Refresh(key=null, loadSize=20, ...))`.
- Expected: `LoadResult.Page` with `data` = the 3 posts, `prevKey == null`,
  `nextKey == "c2"`.
- Traces: AC-1, AC-8.

**TC-AND-098-02 — PagingSource end-of-pagination**
- Type: unit (JVM).
- Target: `FeedPagingSource.load` + `getRefreshKey`.
- Preconditions: repo returns `Success(FeedPageDto(items=[2], nextCursor=null))`.
- Steps: call `load` with `key="c2"`; also call `getRefreshKey(state)`.
- Expected: `LoadResult.Page` with `nextKey == null` (=> `endOfPaginationReached`
  in the differ); `getRefreshKey` returns `null`.
- Traces: AC-1, AC-8.

**TC-AND-098-03 — PagingSource maps failure to retryable error**
- Type: unit (JVM).
- Target: `FeedPagingSource.load`.
- Preconditions: repo returns `ApiResult.Failure` (timeout).
- Steps: call `load`.
- Expected: `LoadResult.Error` carrying a `FeedException` with
  `isRetryable == true`; loaded data is unchanged.
- Traces: AC-3, AC-8.

**TC-AND-098-04 — Two-page differ snapshot (happy path)**
- Type: contract/MockWebServer (JVM + MockWebServer).
- Target: `Pager` flow via `FeedRepository` over Retrofit/OkHttp.
- Preconditions: MockWebServer enqueues page 1
  `{ "items": [...20], "next_cursor": "c2" }` then page 2
  `{ "items": [...5] }` (no `next_cursor`). Server asserts requests hit
  **`/feed`** with `cursor` absent then `cursor=c2`.
- Steps: collect `pager.flow` and call `PagingData.asSnapshot { scrollTo(24) }`.
- Expected: realized list == 25 concatenated items in order; only two HTTP calls;
  second request path/query exactly `/feed?cursor=c2` (no `has_more` consumed);
  no third request after the no-`next_cursor` page.
- Traces: AC-1, AC-8.

**TC-AND-098-05 — Append failure then retry recovers**
- Type: contract/MockWebServer (JVM + MockWebServer).
- Target: `Pager` append + `LazyPagingItems.retry()` semantics.
- Preconditions: page 1 -> 200 with `next_cursor="c2"`; first `cursor=c2` request
  -> `503` (then a timeout variant in a second run); next `cursor=c2` request ->
  200 with 5 items, no `next_cursor`.
- Steps: load page 1; trigger append (fails -> `LoadState.Error` on append);
  invoke `retry()`.
- Expected: append surfaces `LoadState.Error` while the 20 page-1 items remain;
  after `retry()` the 5 items append and state becomes `NotLoading` /
  `endOfPaginationReached`. List never cleared.
- Traces: AC-3, AC-8.

**TC-AND-098-06 — 401 triggers single refresh + retry; persistent 401 terminal**
- Type: contract/MockWebServer (JVM + MockWebServer, with the core-network refresh
  interceptor wired).
- Target: OkHttp 401-refresh interceptor + Paging error mapping.
- Preconditions: Scenario A — `/feed` -> 401, `POST /ui/session/refresh` -> 200,
  retried `/feed` -> 200. Scenario B — `/feed` -> 401, refresh -> 200, retried
  `/feed` -> 401 again.
- Steps: load the first page under each scenario.
- Expected: A — exactly one refresh call, then a successful page (data shown). B —
  one refresh, one retry, then a terminal `LoadState.Error` (retryable
  `FeedException`); Paging does **not** loop or issue further refreshes.
- Traces: AC-4, AC-8; verifies §7 401 loop-guard.

**TC-AND-098-07 — 422 validation error mapping**
- Type: contract/MockWebServer (JVM + MockWebServer).
- Target: `core-network` detail mapper -> `FeedException` via PagingSource.
- Preconditions: `/feed` -> `422 { "detail": [ { "loc": ["query","cursor"],
  "msg": "invalid cursor", "type": "value_error" } ] }`.
- Steps: load first page.
- Expected: `LoadResult.Error` with a user-facing message derived from
  `detail[0].msg`; not retried as if transient unless policy marks it retryable
  (assert the mapper reads the array shape, not a bare string).
- Traces: AC-4, AC-8.

**TC-AND-098-08 — Offline / no network -> immediate error state**
- Type: contract/MockWebServer (JVM) for the unit path; integration on **device
  A15** for the real radio-off path.
- Target: `FeedPagingSource` + `FeedScreen` error rendering.
- Preconditions: JVM — repo/transport throws `IOException` immediately. Device —
  enable airplane mode on the A15 before entering Feed.
- Steps: enter Feed with an empty list.
- Expected: refresh fails fast -> full-screen retriable error (empty list); on
  restoring connectivity + Retry, the first page loads. MUST run the radio path on
  **device A15** (real connectivity transitions; emulator airplane mode is
  simulated).
- Traces: AC-4; §7 stale/offline.

**TC-AND-098-09 — Flaky dev-host timeout, then Retry succeeds (live)**
- Type: integration / manual (live backend) on **emu test35** (CI) and spot-check
  on **device A15**.
- Target: end-to-end `FeedScreen` against `http://18.222.237.167:8000`.
- Preconditions: signed-in session; OkHttp call timeout ~20s.
- Steps: open Feed; if the initial/append call times out, observe the error UI;
  tap Retry.
- Expected: timeout yields a retriable footer (append) or full-screen error
  (empty); Retry re-issues the request and (on a healthy response) loads/appends.
  No unbounded Paging-level retries hammering the host.
- Traces: AC-1, AC-3, AC-4; §13 Risk-1.

**TC-AND-098-10 — Initial loading shows full-screen progress (empty list)**
- Type: Compose-UI (emu test35 or Robolectric).
- Target: `FeedScreen` refresh-loading branch.
- Preconditions: fake `LazyPagingItems`/repo with `refresh = LoadState.Loading`,
  `itemCount == 0`.
- Steps: render `FeedScreen`.
- Expected: a centered full-screen progress indicator with content description
  (string `feed_loading`); no list rows, no footer.
- Traces: AC-1; FR-1.

**TC-AND-098-11 — Loaded list renders rows; Locked badge on locked post**
- Type: Compose-UI (emu test35 or Robolectric).
- Target: `FeedList` / `FeedRowPlaceholder`.
- Preconditions: fake items: one unlocked post (`lock_type=null`) and one locked
  post (`lock_type="fixed_price"`, `unlocked=false`).
- Steps: render; query nodes by post id snippet.
- Expected: N placeholder rows shown; the locked post shows the Locked badge
  (string `feed_locked_badge`), the unlocked one does not. Asserts the **real**
  lock-field logic (`lock_type != null && unlocked != true`), not `locked`.
- Traces: AC-6; FR-8.

**TC-AND-098-12 — Append-error footer Retry invokes retry()**
- Type: Compose-UI (emu test35 or Robolectric).
- Target: `FooterError` + `LazyPagingItems::retry` wiring.
- Preconditions: fake items with loaded rows and `append = LoadState.Error`.
- Steps: assert footer error + Retry button present; perform click.
- Expected: existing rows still visible; clicking Retry calls `retry()` (verified
  via a spy/fake); button is >= 48x48dp with a content description.
- Traces: AC-3; FR-3; §9 a11y.

**TC-AND-098-13 — Empty vs error disambiguation; pull-to-refresh fires refresh**
- Type: Compose-UI (emu test35 or Robolectric).
- Target: `FeedScreen` empty branch + `PullToRefreshBox`.
- Preconditions: (a) refresh `NotLoading`, `endOfPaginationReached`,
  `itemCount == 0`; (b) a fake repo counting calls.
- Steps: (a) render and assert empty state, not error; (b) perform the
  pull-to-refresh swipe / accessibility refresh action.
- Expected: (a) empty-state text (`feed_empty`), no error/Retry; (b) refresh()
  invoked exactly once (repo call count increments); indicator reflects
  `refresh is Loading`.
- Traces: AC-2, AC-5; FR-5, FR-6; §9 accessibility refresh action.

**TC-AND-098-14 — State preservation across config change + back navigation**
- Type: instrumented/e2e on **device A15** (real rotation + Activity recreation);
  may also run on emu test35.
- Target: `cachedIn(viewModelScope)` + scroll retention.
- Preconditions: live or fixture-backed Feed with >= 2 loaded pages; scrolled
  partway.
- Steps: rotate the device (config change), then navigate to another tab and back.
- Expected: no refetch on return (assert call count unchanged / via Timber
  `feed_refresh_start` not re-emitted), same items, scroll position retained.
  Rotation MUST be exercised on **device A15** for a real recreation cycle and to
  catch arm64/API-34 behavior; emu test35 covers the API-35 variant.
- Traces: AC-7; FR-9.

### Coverage matrix

| AC  | Covered by |
|-----|------------|
| AC-1 (initial load + infinite append to end) | TC-01, TC-02, TC-04, TC-09, TC-10 |
| AC-2 (pull-to-refresh resets + indicator) | TC-13 |
| AC-3 (append-error footer Retry; items kept) | TC-03, TC-05, TC-09, TC-12 |
| AC-4 (refresh-fail: empty=full-screen, non-empty=transient; 401) | TC-06, TC-07, TC-08, TC-09 |
| AC-5 (empty state distinct from error) | TC-13 |
| AC-6 (lock metadata -> Locked badge) | TC-11 |
| AC-7 (state survives config change + back nav) | TC-14 |
| AC-8 (unit + differ + Compose + MockWebServer 401/timeout) | TC-01, TC-02, TC-03, TC-04, TC-05, TC-06, TC-07, TC-10, TC-11, TC-12, TC-13 |
