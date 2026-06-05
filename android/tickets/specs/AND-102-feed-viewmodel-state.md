---
id: AND-102
title: Feed ViewModel + state
milestone: M2
epic: E14
priority: P0
size: M
status: draft
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
  repository's `pagingData()` / `Pager` and its `ApiResult`-returning calls. The web reference
  is `frontend/src/api/endpoints/newsfeed.ts` with shared types in `frontend/src/api/types.ts`.
- **Downstream — AND-098 (Feed list / Paging 3):** consumes `FeedViewModel` to render the list,
  refresh control, and pagination loading/error footers. AND-098 owns all Composables; AND-102
  owns no UI.
- **Module layering:** `app -> feature-feed -> core-*` (`core-network`, `core-model`,
  `core-data`, `core-ui`, `core-testing`). ViewModels expose `StateFlow<UiState>`; networking
  uses typed `ApiResult<T>` with FastAPI `detail` mapping (string | `[{msg}]` | `{code,...}`).
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext, unreliable).
  Design for ~20s timeouts, bounded backoff retry on idempotent GETs, and offline/stale UI.
  OpenAPI at `/openapi.json`. Auth is cookie-based with `X-CSRF-Token`; on 401 the network layer
  calls `POST /ui/session/refresh` once then retries (owned by core-network, transparent here).
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

Upstream endpoint (owned by AND-097), GET, idempotent (eligible for bounded-backoff retry):

```
GET /ui/newsfeed?cursor=<opaque|null>&limit=20
Cookie: <session>; ui_csrf=<token>
X-CSRF-Token: <token>
```

Expected 200 page shape (mapped to `FeedItemUi` upstream; abbreviated):

```json
{
  "items": [
    {
      "id": "post_01HXYZ",
      "author": { "id": "u_42", "display_name": "…", "avatar_url": "https://…" },
      "created_at": "2026-06-01T12:00:00Z",
      "text": "…",
      "media": [{ "type": "image", "url": "https://…", "locked": false }],
      "paywall": { "locked": true, "tier": "vip", "unlock_price_cents": 499 }
    }
  ],
  "next_cursor": "eyJ0cyI6MTcxN30=",
  "has_more": true
}
```

FastAPI error envelope (mapped to a user message by core-network's `detail` mapper; consumed
here only as `ApiError.message`):

```json
{ "detail": "rate limited" }
{ "detail": [{ "msg": "invalid cursor", "loc": ["query","cursor"] }] }
{ "detail": { "code": "FEED_UNAVAILABLE", "message": "feed temporarily down" } }
```

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
- Paywall/locked metadata is honored as opaque flags; the ViewModel performs no
  client-side bypass of `paywall.locked` and surfaces locked items unchanged so the UI gates
  media access.
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
  requires `has_more`/`endReached` from AND-097. *Open: confirm the page exposes a terminal
  signal mappable to `endReached`.*
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
