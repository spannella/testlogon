---
id: AND-102
title: Feed ViewModel + state
milestone: M2
epic: E14
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-097]
blocks: [AND-098]
---

# AND-102 — Feed ViewModel + state

## 1. Overview & Goal

This ticket delivers the presentation-layer state machine for the newsfeed: a Hilt-injected
`FeedViewModel` that owns the feed's paging stream, refresh lifecycle, and the consolidated
error/offline/empty/loaded surface that the Compose UI (AND-098) binds to. The ViewModel sits
in `feature-feed` and consumes the `FeedRepository` and Paging `PagingSource`/`Pager` produced
by AND-097.

The goal is a fully unit-tested, deterministic state holder. AND-097 owns the network DTOs,
mapping (including locked/paywall metadata), and the repository; AND-098 owns the actual
LazyColumn, item composables, and footer rendering. AND-102 is the seam between them: it
exposes a single `StateFlow<FeedUiState>` plus a `Flow<PagingData<FeedItemUi>>`, translates
Paging's `CombinedLoadStates` and `ApiResult` failures into typed UI states, drives
pull-to-refresh, and distinguishes offline (no connectivity / unreachable dev host) from
genuine server errors. Per the backlog, the explicit acceptance bar is that **this state is
unit-tested**, so the design prioritizes testability: no Android framework dependencies in the
ViewModel, an injectable `CoroutineDispatcher`, and a fake repository in `core-testing`.

## 2. Context & References

- **Backlog (authoritative):** AND-102 — *Feed ViewModel + state*. Type: Feature · Priority:
  P0 · Deps: AND-097. Scope: "Paging state, refresh, error/offline." Acceptance: "State
  unit-tested."
- **Upstream dependency — AND-097 (Feed API + DTOs):** provides `newsfeed.ts`-equivalent
  endpoints/DTOs (posts, media, paywall flags) and `FeedRepository`. This ticket binds to the
  repository's `pagingData()` / `Pager` and its `ApiResult`-returning calls. The web reference is
  `src/api/endpoints/newsfeed.ts` (note: the file is named `newsfeed.ts`, but its `getFeed` call
  hits **`GET /feed`**, not `/ui/newsfeed`) with shared types in `src/api/types.ts: FeedPost`.
- **Downstream — AND-098 (Feed list / Paging 3):** consumes `FeedViewModel` to render the list,
  refresh control, and pagination loading/error footers. AND-098 owns all Composables; AND-102
  owns no UI.
- **Module layering:** `app -> feature-feed -> core-*` (`core-network`, `core-model`,
  `core-data`, `core-ui`, `core-testing`). ViewModels expose `StateFlow<UiState>`; networking
  uses typed `ApiResult<T>` with FastAPI `detail` mapping (string | `[{msg}]` | `{code,...}`).
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext, unreliable).
  Design for ~20s timeouts, bounded backoff retry on idempotent GETs, and offline/stale UI.
  OpenAPI at `/openapi.json`. Auth (per `reference/src/api/client.ts`) is cookie-based
  (`credentials: include`) **plus** an `Authorization: Bearer <accessToken>` header, with a
  `X-CSRF-Token` header populated from the `ui_csrf` cookie on every request; an optional
  `X-IMPERSONATION-TOKEN` is added when impersonating. On 401 the web client calls
  `POST /ui/session/refresh` once then retries (owned by core-network, transparent here).
- **Package base:** `com.testlogon.android`. Feature package: `com.testlogon.android.feature.feed`.

## 3. Functional Requirements

FR-1 **Paging stream.** Expose `pagingFlow: Flow<PagingData<FeedItemUi>>` sourced from the
repository's `Pager`, `cachedIn(viewModelScope)` so it survives configuration changes and
recomposition.

FR-2 **Consolidated screen state.** Expose `uiState: StateFlow<FeedUiState>` derived from
Paging `CombinedLoadStates` plus connectivity. It must collapse Paging's multi-axis load state
into one of: `Loading` (initial refresh, no cached items), `Content` (≥1 item; may carry a
non-blocking append/banner sub-state), `Empty` (refresh succeeded, zero items), `Error`
(refresh failed, server/transport error), `Offline` (refresh failed due to no connectivity or
host unreachable).

FR-3 **Pull-to-refresh.** Provide `fun refresh()` that triggers a Paging refresh and sets a
transient `isRefreshing` flag, cleared when the refresh `LoadState` settles
(`NotLoading`/`Error`).

FR-4 **Append/prepend state surfacing.** Surface trailing-page `append` load state
(`Loading`/`Error`/`endReached`) so AND-098 can render footers, without losing already-loaded
items. Append errors must never replace `Content` with a full-screen `Error`.

FR-5 **Retry.** Provide `fun retry()` that re-attempts the failed load. For an initial-refresh
failure it re-drives refresh; for an append failure it calls Paging's `retry()`.

FR-6 **Offline vs error discrimination.** Classify a failed load as `Offline` when the cause is
connectivity loss or host-unreachable (`UnknownHostException`, `ConnectException`,
`SocketTimeoutException` with no connectivity), otherwise `Error` with a user-facing message
mapped from FastAPI `detail`.

FR-7 **Stale-while-error.** If items are already present (from Room cache via AND-097's
repository) and a refresh fails, remain in `Content` and emit a one-shot `FeedEvent.RefreshFailed`
banner rather than discarding content.

FR-8 **One-shot events.** Expose `events: SharedFlow<FeedEvent>` (e.g. `RefreshFailed`,
`ScrollToTop`) for transient UI effects that must not replay on recomposition.

FR-9 **Deterministic testability.** No `android.*` imports in the ViewModel; inject
`CoroutineDispatcher` (or use the repository abstraction) and `ConnectivityObserver` so all
states are reachable in `runTest`.

## 4. Technical Design

Module `feature-feed`, package `com.testlogon.android.feature.feed`.

```kotlin
@HiltViewModel
class FeedViewModel @Inject constructor(
    private val repository: FeedRepository,            // from AND-097
    private val connectivity: ConnectivityObserver,    // core-data
    @IoDispatcher private val io: CoroutineDispatcher, // core-data Qualifier
) : ViewModel() {

    private val refreshTrigger = MutableStateFlow(0L)

    val pagingFlow: Flow<PagingData<FeedItemUi>> =
        repository.feedPagingData()                    // Pager(...).flow
            .map { it.map(FeedItemUi::from) }          // DTO->Ui mapping
            .cachedIn(viewModelScope)

    private val _loadStates = MutableStateFlow(FeedLoadSnapshot.INITIAL)
    private val _refreshing = MutableStateFlow(false)
    private val _events = MutableSharedFlow<FeedEvent>(extraBufferCapacity = 4)
    val events: SharedFlow<FeedEvent> = _events.asSharedFlow()

    val uiState: StateFlow<FeedUiState> =
        combine(_loadStates, _refreshing, connectivity.status) { snap, refreshing, net ->
            reduce(snap, refreshing, net)
        }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), FeedUiState.Loading)

    /** Called by the UI from a LaunchedEffect that collects items.loadState. */
    fun onLoadStates(states: CombinedLoadStates, itemCount: Int) {
        _loadStates.value = FeedLoadSnapshot.from(states, itemCount)
        if (states.refresh !is LoadState.Loading) _refreshing.value = false
        if (states.refresh is LoadState.Error && itemCount > 0) {
            _events.tryEmit(FeedEvent.RefreshFailed)
        }
    }

    fun refresh() { _refreshing.value = true; refreshTrigger.value = System.nanoTime() }
    fun retry() { /* delegate to LazyPagingItems.retry() via event or refresh() */ }
}
```

State and event model in `core-model` (or feature-local `model/`):

```kotlin
sealed interface FeedUiState {
    data object Loading : FeedUiState
    data class Content(
        val isRefreshing: Boolean,
        val append: AppendState,   // Idle | Loading | Error(msg) | EndReached
    ) : FeedUiState
    data object Empty : FeedUiState
    data class Error(val message: String, val canRetry: Boolean = true) : FeedUiState
    data object Offline : FeedUiState
}

sealed interface AppendState {
    data object Idle : AppendState
    data object Loading : AppendState
    data class Error(val message: String) : AppendState
    data object EndReached : AppendState
}

sealed interface FeedEvent {
    data object RefreshFailed : FeedEvent
    data object ScrollToTop : FeedEvent
}
```

Reduction logic (`reduce`) is a pure function over `(FeedLoadSnapshot, isRefreshing,
NetworkStatus)` so it is exhaustively unit-testable in isolation:

```kotlin
internal fun reduce(
    snap: FeedLoadSnapshot,
    isRefreshing: Boolean,
    net: NetworkStatus,
): FeedUiState = when {
    snap.refresh is LoadStateLite.Loading && snap.itemCount == 0 -> FeedUiState.Loading
    snap.refresh is LoadStateLite.Error && snap.itemCount == 0 ->
        if (net == NetworkStatus.Unavailable || snap.refresh.offline) FeedUiState.Offline
        else FeedUiState.Error(snap.refresh.message ?: GENERIC_ERROR)
    snap.itemCount == 0 && snap.refresh is LoadStateLite.NotLoading && snap.endReached ->
        FeedUiState.Empty
    else -> FeedUiState.Content(
        isRefreshing = isRefreshing,
        append = snap.append.toAppendState(),
    )
}
```

`FeedLoadSnapshot` is a framework-free projection of `CombinedLoadStates` (mapping each
`LoadState` to a `LoadStateLite` that carries an `offline: Boolean` and a mapped `message`).
This indirection is what keeps `reduce` and the ViewModel free of `androidx.paging.LoadState`
in the unit-test classpath where convenient, and lets tests drive every branch directly.

`ConnectivityObserver` (in `core-data`) exposes `val status: Flow<NetworkStatus>` backed by
`ConnectivityManager.NetworkCallback`; a fake implementation lives in `core-testing`.

Error classification helper (`core-network` provides `ApiError`; this maps it to offline):

```kotlin
internal fun Throwable.isOffline(): Boolean = this is java.net.UnknownHostException ||
    this is java.net.ConnectException || this is java.net.SocketTimeoutException
```

## 5. API Contract

This ticket performs **no direct HTTP calls** — all network access is owned by `FeedRepository`
(AND-097) and the core-network OkHttp/Retrofit/Moshi stack. The ViewModel consumes the
repository's `Pager`/`ApiResult` only. The contract is documented here for traceability because
AND-102's error/offline reduction depends on the response and error shapes AND-097 surfaces.

Upstream endpoint (owned by AND-097), GET, idempotent (eligible for bounded-backoff retry).
**Corrected** against the OpenAPI index (`GET /feed`, op `view_feed_feed_get`) and the web
client `reference/src/api/endpoints/newsfeed.ts: getFeed`. The path is **`/feed`**, not
`/ui/newsfeed`. The `limit` query param **is** accepted by the backend (index lists
`params=limit,cursor,author_id,q,from,to,has_media,...`), but the web client does **not** send
`limit` — it relies on the server default; AND-097 may send `limit` if it chooses. Headers are
set by the transport layer (cookies + `X-CSRF-Token` + `Authorization: Bearer`), not by this
ticket:

```
GET /feed?cursor=<opaque|absent>[&limit=<n>][&author_id=&q=&from=&to=&has_media=]
Cookie: <session>; ui_csrf=<token>
X-CSRF-Token: <token>
Authorization: Bearer <accessToken>
```

Expected 200 page shape (the `/feed` 200 response has **no named schema** in OpenAPI; the
authoritative shape is the web type `{ items: FeedPost[]; next_cursor?: string }` from
`reference/src/api/endpoints/newsfeed.ts` + `reference/src/lib/feedPagination.ts`). **Corrected**
— the prior example invented `id`/`author`/`text`/`media`/`paywall`/`has_more`, none of which
exist. Real `FeedPost` fields (`reference/src/api/types.ts: FeedPost`) are flat:

```json
{
  "items": [
    {
      "post_id": "post_01HXYZ",
      "author_id": "u_42",
      "created_at": "2026-06-01T12:00:00Z",
      "body": "…",
      "image_urls": ["https://…"],
      "lock_type": "fixed_price",
      "unlock_price_cents": 499,
      "unlocked": false,
      "unlock_limit_reached": false,
      "lock_expired": false,
      "like_count": 0,
      "comment_count": 0
    }
  ],
  "next_cursor": "eyJ0cyI6MTcxN30="
}
```

Notes on the corrected shape:
- The unique id is **`post_id`** (used for dedup in `feedPagination.ts: mergeFeedPages`), not `id`.
- The author is a flat **`author_id: string`**, not a nested `author` object; display name/avatar
  are resolved elsewhere, not on `FeedPost`.
- Body text is **`body`** (with `body_plain`/`body_markdown`/`body_rich` variants), not `text`.
- Media is **`image_urls?: string[]`** / `image_variants` / `video?: {...}`, not a `media[]`
  array of `{type,url,locked}`.
- There is **no `paywall` object and no `tier`**. Lock/paywall is flat:
  `lock_type` (`"fixed_price" | "tip_lottery"`), `unlock_price_cents`, `unlocked`,
  `unlock_limit_reached`, `lock_expired`. These pass through to AND-098 unchanged.
- **Terminal/end-reached signal is the absence of `next_cursor`** (the web client uses
  `getNextPageParam: (lastPage) => lastPage.next_cursor` in `useFeedTimelineQuery.ts`). There is
  **no `has_more`** on the feed response. (This resolves the Section 13 open question.)

FastAPI error envelope (mapped to a user message by core-network's `detail` mapper / the web
client's `normalizeErrorDetail` in `client.ts`; consumed here only as `ApiError.message`). All
three forms below are handled by `normalizeErrorDetail`:

```json
{ "detail": "rate limited" }
{ "detail": [{ "msg": "invalid cursor", "loc": ["query","cursor"] }] }
{ "detail": { "code": "FEED_UNAVAILABLE", "message": "feed temporarily down" } }
```

Feed-specific error code (verified, `useFeedTimelineQuery.ts: isInvalidCursorError`): a stale
cursor returns **`{ "detail": { "code": "invalid_cursor" } }`**; the web client recovers by
refetching the first page with no cursor. AND-097/AND-102 should mirror this: on an
`invalid_cursor` refresh failure, drive a cursorless refresh rather than surfacing `Error`.
A hard network failure (offline/DNS) surfaces from `client.ts` as `ApiError(status=0, "Network
error")` — the `status == 0` signal is a reliable offline discriminator alongside the
exception-type check in `Throwable.isOffline()`.

The ViewModel never parses these directly; it receives a resolved `message: String` via the
Paging `LoadState.Error.error` (an `ApiError`) and routes it to `FeedUiState.Error`.

## 6. Data & State Management

- **Single source of truth:** `uiState: StateFlow<FeedUiState>` and
  `pagingFlow: Flow<PagingData<FeedItemUi>>`. The UI collects both; it must not derive screen
  state independently from `LazyPagingItems.loadState` — it instead forwards
  `combinedLoadStates`/`itemCount` to `onLoadStates(...)` so the ViewModel is the reducer.
- **Caching:** Pagination/stale data is provided by AND-097's repository (Room-backed
  `RemoteMediator` or in-memory `PagingSource`). AND-102 adds no persistence; it only applies
  `cachedIn(viewModelScope)` so the stream survives rotation.
- **Scope & lifecycle:** all flows run in `viewModelScope`; `stateIn` uses
  `SharingStarted.WhileSubscribed(5_000)` to keep state warm across brief UI detachment without
  leaking. `MutableSharedFlow` for events uses a small buffer (capacity 4, no replay) so events
  fire once.
- **Refresh state:** `isRefreshing` is ViewModel-owned (not derived from Paging alone) so the
  pull-to-refresh spinner is controllable and clears deterministically when the refresh
  `LoadState` settles.
- **Mapping:** `FeedItemUi.from(dto)` is a pure mapper; paywall/locked flags pass through
  unchanged for AND-098 to render lock overlays. No business logic about unlocking lives here.

## 7. Error Handling & Resilience

- **Initial failure, no cache:** `refresh` `LoadState.Error` + `itemCount == 0` →
  `FeedUiState.Error(message)` (server/transport) or `FeedUiState.Offline` (connectivity). UI
  shows a full-screen retryable state.
- **Append failure:** surfaced as `AppendState.Error(message)` inside `Content`; existing items
  remain. `retry()` calls Paging's append retry. Never escalates to full-screen error.
- **Stale-while-error:** refresh failure with `itemCount > 0` keeps `Content` and emits a
  one-shot `FeedEvent.RefreshFailed` for a transient banner/snackbar (FR-7).
- **Offline classification:** driven by `NetworkStatus.Unavailable` from `ConnectivityObserver`
  and/or `Throwable.isOffline()`; covers the unreliable plaintext dev host
  (`SocketTimeoutException` under ~20s timeouts).
- **Retry/backoff:** bounded-backoff retry for the idempotent feed GET is implemented in
  core-network/AND-097; the ViewModel exposes only user-initiated `retry()` and does not loop.
- **401 handling:** transparent to this layer — the OkHttp authenticator calls
  `POST /ui/session/refresh` once and retries; a persistent failure surfaces as an
  `ApiError`/`LoadState.Error` and is reduced to `Error` (auth) here.
- **No silent swallowing:** every `LoadState.Error` resolves to a visible state or a logged
  event.

## 8. Security & Privacy

- No credential or token handling in this ticket; session cookies and `ui_csrf`/`X-CSRF-Token`
  live in the persistent cookie jar (core-network). The ViewModel must never log cookie or CSRF
  values.
- Paywall/locked metadata is honored as opaque flags; the ViewModel performs no client-side
  bypass of the flat lock fields (`lock_type`, `unlock_price_cents`, `unlocked`,
  `unlock_limit_reached`, `lock_expired` — there is no `paywall.locked` field; see Section 16)
  and surfaces locked items unchanged so the UI gates media access.
- Logged error messages are the user-safe `ApiError.message`; raw exception stack traces are
  logged only at `Log.DEBUG` and never include request bodies, auth headers, or PII (author
  names, text). Telemetry payloads (Section 10) carry only error category and load-state keys.

## 9. Accessibility & i18n

- The ViewModel emits **state keys**, not display strings, for the structural states
  (`Loading`/`Empty`/`Offline`); AND-098 maps these to localized `stringResource` values and
  applies semantics (`liveRegion` for refresh/error announcements, retry button labels).
- Server-originated `Error.message` is shown as-is (FastAPI English `detail`); a fallback
  `GENERIC_ERROR` resource is used when `message` is null so no raw key is ever displayed.
- No hardcoded user-facing English in `feature-feed`'s ViewModel; the only constants are
  resource ids/keys. All counts/dates formatting is deferred to the UI layer for locale
  correctness.

## 10. Telemetry & Logging

- Inject an `Analytics` abstraction (core-data) and emit structured events: `feed_refresh`
  (`{source: pull|auto}`), `feed_refresh_result` (`{result: success|error|offline,
  item_count}`), `feed_append_result` (`{result, page_index}`), `feed_retry`
  (`{scope: refresh|append}`). No PII in any property.
- Logging via a tagged logger (`"FeedVM"`): state transitions at `DEBUG`, classified errors at
  `WARN` with category + sanitized message. Logging must be a no-op/injectable interface so
  unit tests assert emissions without Logcat.
- Optional `FeedUiState` transition trace behind a debug `BuildConfig` flag for QA.

## 11. Testing Strategy

This is the ticket's explicit acceptance bar ("State unit-tested"). All tests are JVM unit tests
in `feature-feed/src/test` using JUnit, `kotlinx-coroutines-test` (`runTest`,
`StandardTestDispatcher`), Turbine for `StateFlow`/`SharedFlow`, and a `FakeFeedRepository` +
`FakeConnectivityObserver` from `core-testing`.

Coverage of `reduce(...)` (pure, exhaustive):
- Loading: refresh=Loading, itemCount=0 → `Loading`.
- Error (server): refresh=Error(non-offline), itemCount=0, net=Available → `Error(message)`.
- Offline by network: refresh=Error, net=Unavailable → `Offline`.
- Offline by exception: refresh=Error(offline=true) → `Offline` even when net=Available.
- Empty: refresh=NotLoading, itemCount=0, endReached → `Empty`.
- Content + append idle/loading/error/endReached permutations.
- Stale-while-error: refresh=Error, itemCount>0 → stays `Content`.

Coverage of `FeedViewModel`:
- `pagingFlow` maps DTO→`FeedItemUi` and preserves paywall flags (via `asSnapshot`).
- `refresh()` sets `isRefreshing=true`, then clears when `onLoadStates` reports settled refresh.
- Refresh failure with existing items emits exactly one `FeedEvent.RefreshFailed` (Turbine).
- `retry()` after refresh failure re-drives refresh / append retry as appropriate.
- Connectivity change from Unavailable→Available while in `Offline` re-derives state.
- `WhileSubscribed` timeout: state retained within window, recomputed after.

Non-goals for tests: no Compose UI tests (AND-098), no real network (AND-097 integration).
Target ≥90% line coverage on `FeedViewModel` + `reduce`.

## 12. Dependencies & Sequencing

- **Depends on AND-097** (Feed API + DTOs): requires `FeedRepository.feedPagingData()`,
  `FeedItemUi`/DTO mapping with paywall flags, and `ApiError`. Hard blocker — AND-102 cannot
  compile its real `Pager` binding without it (a temporary `FakeFeedRepository` allows parallel
  start of `reduce`/state tests).
- **Blocks AND-098** (Feed list / Paging 3): the LazyColumn, refresh control, and footers bind
  to `uiState`, `pagingFlow`, `events`, `refresh()`, `retry()`, and `onLoadStates(...)`.
- **Transitive:** core-network (ApiResult/detail mapping, cookie jar, 401 refresh), core-data
  (`ConnectivityObserver`, dispatchers, Analytics), core-model (state types), core-testing
  (fakes, Turbine helpers), Hilt/KSP, Paging 3.
- Sequencing: land the pure `reduce` + state model and its tests first (no AND-097 needed),
  then wire the real repository once AND-097 merges, then hand off to AND-098.

## 13. Risks & Open Questions

- **Paging LoadState ↔ UiState mapping fidelity:** `CombinedLoadStates` has refresh/prepend/
  append axes plus mediator vs source states when a `RemoteMediator` is used (AND-097's choice).
  Risk that mediator and source disagree; mitigation: `FeedLoadSnapshot.from` must prefer
  mediator refresh when present. *Open: does AND-097 use `RemoteMediator` (Room) or in-memory
  `PagingSource`?*
- **Unreliable dev host:** ~20s timeouts make `SocketTimeoutException` common; must be
  classified Offline, not Error, to avoid alarming UX. Confirm timeout config lives in
  core-network OkHttp client.
- **Refresh spinner double-source:** owning `isRefreshing` separately from Paging risks drift;
  reconcile strictly in `onLoadStates`. *Open: adopt Material3 `PullToRefreshState` (AND-098)
  fully, or keep VM-owned flag?* Current design keeps VM-owned for testability.
- **Empty vs end-reached:** distinguishing genuine empty feed from "first page, more coming"
  requires a terminal signal from AND-097. *Resolved (see Section 16):* the `/feed` page exposes
  **no `has_more`**; the terminal signal is the **absence of `next_cursor`** (web parity:
  `useFeedTimelineQuery.ts` uses `getNextPageParam: (lastPage) => lastPage.next_cursor`). AND-097's
  `PagingSource.LoadResult.Page.nextKey` must be `null` when `next_cursor` is absent so Paging
  reports `append.endOfPaginationReached`; `reduce` maps that to `endReached`.
- **Event replay:** ensure no `RefreshFailed` replay on rotation; verified by `replay=0`
  SharedFlow.

## 14. Acceptance Criteria

AC-1 `FeedViewModel` exists in `com.testlogon.android.feature.feed`, is `@HiltViewModel`, and
exposes `uiState: StateFlow<FeedUiState>`, `pagingFlow: Flow<PagingData<FeedItemUi>>`,
`events: SharedFlow<FeedEvent>`, and `refresh()`/`retry()`/`onLoadStates(...)`.

AC-2 Paging load states reduce correctly to `Loading`, `Content` (with append sub-state),
`Empty`, `Error`, and `Offline`, with offline distinguished from server error per Section 6.

AC-3 `refresh()` toggles `isRefreshing` and clears it deterministically when the refresh load
state settles; pull-to-refresh against the dev backend works through AND-098.

AC-4 A refresh failure with existing items keeps `Content` and emits exactly one
`FeedEvent.RefreshFailed`; with no items it yields `Error`/`Offline`.

AC-5 **State is unit-tested** (backlog acceptance): `reduce` is exhaustively covered and
`FeedViewModel` tests pass under `runTest` using `core-testing` fakes (≥90% coverage on the VM +
reducer), with no `android.*` runtime dependency in the test path.

AC-6 No HTTP, persistence, or Composable is introduced in this ticket; all network/mapping is
delegated to AND-097 and all rendering to AND-098.

## 15. Definition of Done

- Code merged to `android-port` under `android/feature-feed`; package `com.testlogon.android.
  feature.feed`; builds with Gradle 8.9 / AGP 8.7.3 / Kotlin 2.0.21 / JDK 17.
- `FeedViewModel`, `FeedUiState`, `AppendState`, `FeedEvent`, `FeedLoadSnapshot`, and `reduce`
  implemented with KDoc on public API; Hilt graph compiles (KSP) and the VM is constructable in
  `app`.
- Unit test suite green in CI; coverage thresholds met; ktlint/detekt clean.
- No user-facing strings hardcoded in the VM; telemetry/logging routed through injectable
  abstractions with no PII/secret leakage.
- Public surface reviewed and accepted by the AND-098 owner as the binding contract; open
  questions in Section 13 resolved or explicitly deferred with owners.
- Spec reviewed; ticket moved from `draft` to ready/merged.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the authoritative source pointer.

1. **Feed endpoint path is `GET /feed`.** VERDICT: Corrected (spec said `GET /ui/newsfeed`).
   SOURCE: OpenAPI `GET /feed` (op `view_feed_feed_get`); `src/api/endpoints/newsfeed.ts: getFeed`
   (`api.get("/feed", ...)`).
2. **HTTP method is GET and the call is idempotent (retry-eligible).** VERDICT: Verified.
   SOURCE: OpenAPI `GET /feed`; `src/api/endpoints/newsfeed.ts: getFeed`.
3. **`cursor` query param exists (opaque pagination key).** VERDICT: Verified.
   SOURCE: OpenAPI `GET /feed` params include `cursor`; `src/api/endpoints/newsfeed.ts:
   FeedQueryParams.cursor`.
4. **`limit` query param exists.** VERDICT: Corrected/clarified. The backend accepts `limit`
   (OpenAPI `GET /feed` `params=limit,cursor,...`), but the web client does **not** send it
   (no `limit` in `getFeed`/`buildFeedRequestParams`); the original `limit=20` was an unverified
   assumption about a default. SOURCE: OpenAPI `GET /feed`; `src/hooks/useFeedTimelineQuery.ts:
   buildFeedRequestParams`.
5. **200 response shape is `{ items: FeedPost[]; next_cursor?: string }`.** VERDICT: Corrected.
   The `/feed` 200 has no named schema in OpenAPI (`resp=200:` is empty), so the web type is the
   contract. SOURCE: `src/api/endpoints/newsfeed.ts: getFeed` return type;
   `src/lib/feedPagination.ts: FeedPage`.
6. **Post unique id field is `post_id` (not `id`).** VERDICT: Corrected.
   SOURCE: `src/api/types.ts: FeedPost.post_id`; `src/lib/feedPagination.ts: mergeFeedPages`
   (dedups on `post.post_id`).
7. **Author is a flat `author_id: string`, not a nested `author{id,display_name,avatar_url}`.**
   VERDICT: Corrected. SOURCE: `src/api/types.ts: FeedPost.author_id`.
8. **Body text field is `body` (not `text`).** VERDICT: Corrected.
   SOURCE: `src/api/types.ts: FeedPost.body` (+ `body_plain`/`body_markdown`/`body_rich`).
9. **Media is `image_urls: string[]` / `image_variants` / `video{...}`, not a `media[]` array of
   `{type,url,locked}`.** VERDICT: Corrected. SOURCE: `src/api/types.ts: FeedPost.image_urls`,
   `FeedPost.image_variants`, `FeedPost.video`.
10. **No `paywall` object and no `tier`; lock metadata is flat (`lock_type`,
    `unlock_price_cents`, `unlocked`, `unlock_limit_reached`, `lock_expired`).** VERDICT:
    Corrected. SOURCE: `src/api/types.ts: FeedPost` (fields `lock_type`, `unlock_price_cents`,
    `unlocked`, `unlock_limit_reached`, `lock_expired`).
11. **Terminal/end-reached signal is the absence of `next_cursor`; there is no `has_more` on the
    feed page.** VERDICT: Corrected (resolves Section 13 open question). SOURCE:
    `src/hooks/useFeedTimelineQuery.ts` (`getNextPageParam: (lastPage) => lastPage.next_cursor`);
    `src/api/endpoints/newsfeed.ts: getFeed` return type (no `has_more`). (`has_more` exists only
    on unrelated responses, e.g. `types.ts: GroupFeedResponse`.)
12. **CSRF: an `X-CSRF-Token` header is sent, sourced from the `ui_csrf` cookie.** VERDICT:
    Verified. SOURCE: `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token",
    csrf)`).
13. **Transport is cookie-based AND additionally sends `Authorization: Bearer <accessToken>`.**
    VERDICT: Corrected/expanded (spec said only "cookie-based"). SOURCE: `src/api/client.ts`
    (`credentials: "include"` + `headers.set("Authorization", \`Bearer ${accessToken}\`)`).
14. **On 401 the client calls `POST /ui/session/refresh` once, then retries.** VERDICT: Verified.
    SOURCE: OpenAPI `POST /ui/session/refresh` (op `ui_session_refresh_ui_session_refresh_post`);
    `src/api/client.ts: refreshSession` + the 401 branch.
15. **FastAPI `detail` can be a string, an array of `{msg,loc}`, or an object `{code,message}`,
    all collapsed to one user message.** VERDICT: Verified. SOURCE: `src/api/client.ts:
    normalizeErrorDetail` (handles string / array-of-`{msg}` / object).
16. **Stale-cursor error code is `invalid_cursor`; web recovers by refetching page one without a
    cursor.** VERDICT: Verified (the spec's §5 example used a generic 422 `{msg:"invalid cursor"}`
    which is also valid, but the feed-specific signal is `detail.code == "invalid_cursor"`).
    SOURCE: `src/hooks/useFeedTimelineQuery.ts: isInvalidCursorError` + the catch-and-refetch
    fallback.
17. **A hard network failure surfaces as `ApiError(status=0, "Network error")`.** VERDICT:
    Verified. SOURCE: `src/api/client.ts` (catch around `fetch` → `throw new ApiError(0, "Network
    error", err)`).
18. **422 is the validation error response with schema `HTTPValidationError`.** VERDICT: Verified.
    SOURCE: OpenAPI `GET /feed` `resp=...;422:HTTPValidationError`.
19. **AND-102 makes no direct HTTP calls; all network/mapping is owned by AND-097 / core-network.**
    VERDICT: Unverified-assumption (architectural decision local to this Android port; no
    web/OpenAPI source applies). Internally consistent with the layering in §2/§12.
20. **`offline` classification via `UnknownHostException`/`ConnectException`/
    `SocketTimeoutException`.** VERDICT: Unverified-assumption (JVM/OkHttp behavior, not in the
    web sources). Reasonable; the web equivalent is the `ApiError(status=0)` path (claim 17).
    framework ref: OkHttp surfaces these `java.net.*` exceptions on transport failure
    (https://square.github.io/okhttp/).
21. **Hilt `@HiltViewModel`, `viewModelScope`, `stateIn(WhileSubscribed)`, `cachedIn`,
    Paging 3 `CombinedLoadStates`/`LoadState`, Turbine/`runTest` testing.** VERDICT:
    Unverified-assumption / framework ref (Android framework choices, not derivable from the
    backend/web sources). framework ref: Paging
    (https://developer.android.com/topic/libraries/architecture/paging/v3-overview), ViewModel
    StateFlow (https://developer.android.com/topic/libraries/architecture/viewmodel),
    Hilt (https://developer.android.com/training/dependency-injection/hilt-android).

### Corrections made

- §2: auth description expanded to cookie + `Authorization: Bearer` + `X-CSRF-Token` (from
  `ui_csrf` cookie) + optional `X-IMPERSONATION-TOKEN` (claims 12, 13); web-reference note that
  `newsfeed.ts` actually calls `GET /feed` (claim 1).
- §5: endpoint path `/ui/newsfeed` → **`/feed`** (claim 1); clarified `limit` is server-side, not
  a client-sent `limit=20` (claim 4); response JSON rewritten to the real flat `FeedPost` shape —
  `post_id`/`author_id`/`body`/`image_urls`/flat lock fields, removed fictional
  `id`/`author`/`text`/`media[]`/`paywall`/`has_more` (claims 5–11); added the real
  `invalid_cursor` recovery contract (claim 16) and the `status=0` offline signal (claim 17).
- §8: removed reference to non-existent `paywall.locked`; replaced with the real flat lock fields
  (claim 10).
- §13: "Empty vs end-reached" open question resolved — terminal signal is absence of `next_cursor`,
  no `has_more` (claim 11).
- Frontmatter: `status: draft` → `status: reviewed`; added `reviewed_on: 2026-06-06`.

### Open assumptions

- All Android-stack choices (Hilt, Paging 3, coroutines/Turbine, `ConnectivityObserver`,
  dispatcher injection) are not verifiable against the backend OpenAPI or the React web app —
  they are deliberate native-port decisions (claims 19, 21). Verified only against Android
  framework docs (framework refs above).
- Offline classification by `java.net.*` exception type (claim 20) cannot be verified from the
  web sources (the browser fetch surfaces a single opaque network error → `ApiError(status=0)`).
  The Android mapping is an assumption to validate on-device against the unreliable dev host.
- Whether AND-097 implements the feed via a Room `RemoteMediator` or an in-memory `PagingSource`
  is still open (Section 13); it changes which `CombinedLoadStates` axis (`mediator` vs `source`)
  `FeedLoadSnapshot.from` must prefer. Not resolvable from these sources — owned by AND-097.
- The server-side default page size for `/feed` (when `limit` is omitted) is not documented in
  the OpenAPI index and is not asserted here.

## 17. Test Plan

All cases trace to Section 14 acceptance criteria. The ticket's acceptance bar is "State
unit-tested," so the core is JVM unit/Robolectric (no device). Device/emulator cases are included
for the end-to-end refresh/offline behavior that AC-3 references "through AND-098"; mark each with
its required target. Test targets: JVM = local JVM unit (JUnit + `kotlinx-coroutines-test` +
Turbine + `core-testing` fakes); Emulator = AVD `test35` (API 35); Device = Samsung Galaxy A15
5G (SM-A156U, API 34, arm64-v8a).

- **TC-AND-102-01 — reduce: initial loading.** Type: unit (JVM). Target: `reduce(...)`.
  Preconditions: `FakeFeedRepository` not needed (pure function). Steps: call `reduce(snap{refresh=Loading,
  itemCount=0}, isRefreshing=false, net=Available)`. Expected: `FeedUiState.Loading`. Traces: AC-2.
- **TC-AND-102-02 — reduce: server error, no cache.** Type: unit (JVM). Target: `reduce`.
  Preconditions: none. Steps: `reduce(snap{refresh=Error(offline=false,message="rate limited"),
  itemCount=0}, false, net=Available)`. Expected: `FeedUiState.Error("rate limited",
  canRetry=true)`, NOT `Offline`. Traces: AC-2, AC-4.
- **TC-AND-102-03 — reduce: offline by connectivity.** Type: unit (JVM). Target: `reduce`.
  Preconditions: none. Steps: `reduce(snap{refresh=Error, itemCount=0}, false,
  net=Unavailable)`. Expected: `FeedUiState.Offline`. Traces: AC-2.
- **TC-AND-102-04 — reduce: offline by exception even when net=Available.** Type: unit (JVM).
  Target: `reduce` + `Throwable.isOffline()`. Preconditions: none. Steps: build snapshot from a
  `LoadState.Error(SocketTimeoutException())` (and/or `ApiError(status=0)`) with `itemCount=0`,
  `net=Available`; reduce. Expected: `FeedUiState.Offline` (offline flag wins). Traces: AC-2.
- **TC-AND-102-05 — reduce: empty feed.** Type: unit (JVM). Target: `reduce`. Preconditions:
  none. Steps: `reduce(snap{refresh=NotLoading, itemCount=0, endReached=true}, false, Available)`
  — endReached derived from absent `next_cursor` (see §16 claim 11). Expected: `FeedUiState.Empty`.
  Traces: AC-2.
- **TC-AND-102-06 — reduce: content with append permutations.** Type: unit (JVM). Target:
  `reduce`/`AppendState`. Preconditions: none. Steps: with `itemCount>0` and `refresh=NotLoading`,
  drive `append` = Idle, Loading, Error("…"), EndReached. Expected: `FeedUiState.Content` in all
  four, with matching `AppendState`; append Error never escalates to full-screen `Error`. Traces:
  AC-2, AC-4 (append-error containment).
- **TC-AND-102-07 — reduce: stale-while-error.** Type: unit (JVM). Target: `reduce`.
  Preconditions: none. Steps: `reduce(snap{refresh=Error, itemCount=5}, false, Available)`.
  Expected: stays `FeedUiState.Content` (does not become `Error`/`Offline`). Traces: AC-4.
- **TC-AND-102-08 — refresh() toggles and clears isRefreshing.** Type: unit (JVM). Target:
  `FeedViewModel.refresh()` + `onLoadStates`. Preconditions: VM built with `FakeFeedRepository`,
  `FakeConnectivityObserver`, `StandardTestDispatcher`; collect `uiState` via Turbine in
  `runTest`. Steps: call `refresh()`; assert `isRefreshing=true` in emitted `Content`; then call
  `onLoadStates(states{refresh=NotLoading}, itemCount=3)`. Expected: `isRefreshing` clears to
  false deterministically. Traces: AC-1, AC-3.
- **TC-AND-102-09 — refresh failure with items emits exactly one RefreshFailed event.** Type:
  unit (JVM). Target: `FeedViewModel.events`. Preconditions: VM with items already loaded
  (itemCount>0); Turbine on `events`. Steps: `onLoadStates(states{refresh=Error}, itemCount=4)`.
  Expected: exactly one `FeedEvent.RefreshFailed`; `uiState` remains `Content`; no replay on a
  second collector (replay=0). Traces: AC-4, AC-1.
- **TC-AND-102-10 — retry() re-drives refresh vs append retry.** Type: unit (JVM). Target:
  `FeedViewModel.retry()`. Preconditions: fake repo records refresh invocations. Steps: after an
  initial-refresh failure (itemCount=0) call `retry()` → asserts a refresh is re-driven; after an
  append failure call `retry()` → asserts append retry path (event/flag) taken, not a full
  refresh. Expected: correct path per failure type. Traces: AC-1, AC-2.
- **TC-AND-102-11 — connectivity Unavailable→Available recomputes state.** Type: unit (JVM).
  Target: `uiState` combine over `connectivity.status`. Preconditions: VM in `Offline`
  (refresh=Error + net=Unavailable). Steps: `FakeConnectivityObserver.emit(Available)` then
  settle a successful refresh. Expected: `uiState` leaves `Offline` and re-derives `Content`/`Empty`.
  Traces: AC-2, AC-3.
- **TC-AND-102-12 — pagingFlow maps DTO→FeedItemUi preserving lock flags.** Type: unit (JVM,
  Paging `asSnapshot`/`AsyncPagingDataDiffer`). Target: `FeedViewModel.pagingFlow`.
  Preconditions: fake repo emits `PagingData` of `FeedPost` with `lock_type="fixed_price"`,
  `unlock_price_cents=499`, `unlocked=false`. Steps: snapshot `pagingFlow`. Expected: emitted
  `FeedItemUi` carries `post_id`, `author_id`, `body`, and the flat lock fields unchanged (no
  client-side unlock; see §16 claims 6–10). Traces: AC-2, AC-6.
- **TC-AND-102-13 — invalid_cursor refresh recovery.** Type: contract/MockWebServer. Target:
  `FeedRepository` wiring as consumed by the VM (AND-097 seam) + `reduce`. Preconditions:
  MockWebServer scripted: first paged request → `400/422` with body
  `{"detail":{"code":"invalid_cursor"}}`, retry with no `cursor` → `200 {items:[…],
  next_cursor:null}`. Steps: drive a refresh from a stale cursor. Expected: cursorless refetch
  succeeds and VM lands in `Content`/`Empty` rather than `Error` (web parity, §16 claim 16).
  Traces: AC-2, AC-4. Note: runs headless; no device needed.
- **TC-AND-102-14 — flaky/offline dev host classified as Offline, not Error.** Type:
  instrumented/e2e. Target: full VM→repo→network against the real plaintext dev host
  `http://18.222.237.167:8000`. Preconditions: app installed; toggle airplane mode / block the
  host to force `SocketTimeoutException`/unreachable under the ~20s timeout. Steps: open feed with
  no cache and no connectivity; observe state; restore connectivity and `retry()`. Expected:
  `FeedUiState.Offline` (not `Error`) while down; recovers to `Content` after restore. **MUST run
  on the physical device** (SM-A156U) — real radio/airplane-mode + arm64/API-34 timeout behavior
  against the unreliable host; emulator NAT does not reproduce real connectivity loss faithfully.
  Traces: AC-2, AC-3.
- **TC-AND-102-15 — Compose binding + accessibility of structural states.** Type: Compose-UI /
  instrumented. Target: the AND-098 screen bound to this VM (state keys → localized strings +
  semantics). Preconditions: test host Composable collecting `uiState`/`pagingFlow`/`events` and
  forwarding `onLoadStates`. Steps: drive Loading/Empty/Offline/Error/Content; with TalkBack
  semantics assert each structural state exposes a non-empty content description / `liveRegion`
  announcement and the retry control has an accessible label; pull-to-refresh shows/clears the
  spinner. Expected: every state is announced; no raw resource keys shown; retry reachable by
  a11y services. Target: Emulator `test35` is sufficient (no special hardware); may also run on
  the device. Traces: AC-3, AC-2 (state surface). Note: this validates AND-102's contract as
  consumed by AND-098, not AND-102 code directly.
- **TC-AND-102-16 — no android.* in unit test classpath / coverage threshold.** Type: unit
  (JVM). Target: `FeedViewModel` + `reduce` test suite. Preconditions: CI runs `:feature-feed:test`
  with no Robolectric/Android runtime on the reducer/VM tests. Steps: run the suite + JaCoCo.
  Expected: suite green with no `android.*` runtime dependency on the pure paths; ≥90% line
  coverage on `FeedViewModel` + `reduce`. Traces: AC-5, AC-6.

### Coverage matrix

| Acceptance criterion | Covered by |
| --- | --- |
| AC-1 (VM exists, exposes uiState/pagingFlow/events/refresh/retry/onLoadStates) | TC-08, TC-09, TC-10, TC-12 |
| AC-2 (load states reduce to Loading/Content/Empty/Error/Offline; offline vs error) | TC-01, TC-02, TC-03, TC-04, TC-05, TC-06, TC-11, TC-12, TC-13, TC-14, TC-15 |
| AC-3 (refresh toggles/clears isRefreshing; pull-to-refresh works through AND-098) | TC-08, TC-11, TC-14, TC-15 |
| AC-4 (refresh failure w/ items keeps Content + one RefreshFailed; no items → Error/Offline) | TC-02, TC-06, TC-07, TC-09, TC-13 |
| AC-5 (state unit-tested; reduce exhaustive; ≥90% coverage; no android.* runtime) | TC-01…TC-12, TC-16 |
| AC-6 (no HTTP/persistence/Composable introduced; delegated to AND-097/AND-098) | TC-12, TC-15, TC-16 |
