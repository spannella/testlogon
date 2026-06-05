---
id: AND-219
title: Purchase history + search
milestone: M5
epic: E30
priority: P1
size: M
status: draft
depends_on: [AND-218]
blocks: []
---

# AND-219 — Purchase history + search

## 1. Overview & Goal

Deliver the user-facing **Purchase History** screen for the TestLogon native Android app: a
chronological, paginated list of the signed-in user's prior purchases with a full-text search
field that filters/queries that history. The screen consumes the typed purchases data layer
delivered by AND-218 (`PurchasesRepository`, models, and `ApiResult<T>` mappings) and renders it
through a Compose + Material 3 UI backed by a Hilt-injected `ViewModel` exposing
`StateFlow<PurchaseHistoryUiState>`.

The goal is a production-quality list experience that: (a) renders the authenticated user's
purchases newest-first with infinite scroll via Paging 3; (b) supports server-backed full-text
search with debounce and an empty/cleared state; (c) degrades gracefully against the unreliable
plaintext dev backend (loading, empty, error-with-retry, and stale/offline states); and (d) is
fully testable with deterministic fakes from `core-testing`.

Out of scope: the purchase **detail** screen navigation target (owned by a later detail ticket;
this screen only emits a navigation event with the purchase id), receipt rendering/PDF, refunds,
and the network/mapping layer itself (owned by AND-218).

## 2. Context & References

- **Module:** new feature module `feature-purchases` (layer: `app -> feature-purchases ->
  core-*`). It depends on `core-model`, `core-data`, `core-ui`, and `core-network` (transitively).
- **Upstream (AND-218):** provides `core-data`/`core-network` purchases plumbing — the Retrofit
  `PurchasesApi`, Moshi DTOs, `core-model` domain types, and `PurchasesRepository` with
  `ApiResult<T>` and FastAPI `detail` error mapping. This ticket **does not** define DTOs or
  endpoints from scratch; it consumes them. Endpoint shapes below restate AND-218's contract for
  reference only.
- **Web reference:** `frontend/src/api/endpoints/purchases.ts` (list/detail/search) and shared
  types in `frontend/src/api/types.ts`. Mirror field names and pagination semantics from there;
  confirm exact response keys against `/openapi.json` on the dev host before finalizing DTOs in
  AND-218.
- **Auth:** all calls are cookie-based and ride the persistent cookie jar + `X-CSRF-Token`
  header established by the session stack; on `401` the OkHttp authenticator performs a single
  `POST /ui/session/refresh` and retries. This screen assumes an authenticated session and
  surfaces a re-auth-required state if refresh ultimately fails.
- **Backend:** FastAPI + DynamoDB at dev host `http://18.222.237.167:8000` (PLAINTEXT, unreliable).
  Use ~20s timeouts, bounded backoff retry for idempotent GETs only.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Navigation-Compose, Hilt (KSP), Paging 3,
  Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Room 2.6, Coil. minSdk 24,
  compile/target 35, JDK 17, namespace base `com.testlogon.android`.

## 3. Functional Requirements

FR-1. **History list.** On entry, load page 1 of the current user's purchases sorted newest-first
(by `purchasedAt` descending). Each row shows: merchant/item title, formatted amount + currency,
formatted purchase date, and status badge (e.g. `COMPLETED`, `PENDING`, `REFUNDED`). Tapping a row
emits a navigation event carrying the purchase id.

FR-2. **Infinite scroll.** The list pages forward automatically as the user scrolls within
`PREFETCH_DISTANCE` of the end, using Paging 3 with the backend's cursor/offset pagination.

FR-3. **Full-text search.** A pinned search field at the top filters history by free text against
merchant/item/description fields server-side. Input is debounced (300 ms); a query of length 0
returns the unfiltered history; whitespace-only queries are treated as empty. Submitting via the
IME action triggers an immediate (non-debounced) query.

FR-4. **State coverage.** The screen distinguishes and renders: initial loading (skeleton/spinner),
content, append-loading (footer spinner), empty-history, empty-search-results (distinct copy and a
"Clear search" affordance), refreshing, error (full-screen with Retry) and append-error (inline
footer Retry), and offline/stale (cached content with a banner).

FR-5. **Pull-to-refresh.** A Material 3 pull-to-refresh re-fetches page 1 for the active query.

FR-6. **Search state preservation.** The active query survives configuration change (saved in
`SavedStateHandle`) and re-applies on return to the screen.

FR-7. **Clearable input.** A trailing clear (✕) icon resets the query to empty and returns the
full history.

## 4. Technical Design

Package root: `com.testlogon.android.feature.purchases`.

### Navigation

```kotlin
// nav/PurchasesNav.kt
const val PURCHASE_HISTORY_ROUTE = "purchases/history"

fun NavGraphBuilder.purchaseHistoryScreen(
    onPurchaseClick: (purchaseId: String) -> Unit,
    onReauthRequired: () -> Unit,
) {
    composable(PURCHASE_HISTORY_ROUTE) {
        PurchaseHistoryRoute(
            onPurchaseClick = onPurchaseClick,
            onReauthRequired = onReauthRequired,
        )
    }
}
```

### ViewModel + UI state

```kotlin
@Immutable
data class PurchaseHistoryUiState(
    val query: String = "",
    val isRefreshing: Boolean = false,
    val isStale: Boolean = false,        // serving cached/offline data
    val reauthRequired: Boolean = false,
)

sealed interface PurchaseHistoryEvent {
    data class OpenPurchase(val purchaseId: String) : PurchaseHistoryEvent
    object ReauthRequired : PurchaseHistoryEvent
}

@HiltViewModel
class PurchaseHistoryViewModel @Inject constructor(
    private val repository: PurchasesRepository,   // from AND-218
    private val savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val queryFlow: StateFlow<String> =
        savedStateHandle.getStateFlow(KEY_QUERY, "")

    val uiState: StateFlow<PurchaseHistoryUiState> = /* combine query + refresh + stale */

    // Paging stream re-built whenever the (debounced) query changes.
    val pagingItems: Flow<PagingData<Purchase>> = queryFlow
        .map { it.trim() }
        .distinctUntilChanged()
        .debounce { if (it.isEmpty()) 0L else SEARCH_DEBOUNCE_MS }
        .flatMapLatest { q -> repository.purchasesPagingFlow(query = q) }
        .cachedIn(viewModelScope)

    private val _events = MutableSharedFlow<PurchaseHistoryEvent>(extraBufferCapacity = 1)
    val events: SharedFlow<PurchaseHistoryEvent> = _events.asSharedFlow()

    fun onQueryChange(value: String) { savedStateHandle[KEY_QUERY] = value }
    fun onClearQuery() { savedStateHandle[KEY_QUERY] = "" }
    fun onSubmitSearch() { /* force immediate refresh of current query */ }
    fun onPurchaseClick(id: String) { _events.tryEmit(PurchaseHistoryEvent.OpenPurchase(id)) }
    fun onRefresh() { /* toggles isRefreshing; LazyPagingItems.refresh() in UI */ }

    companion object {
        const val KEY_QUERY = "purchase_query"
        const val SEARCH_DEBOUNCE_MS = 300L
        const val PAGE_SIZE = 20
        const val PREFETCH_DISTANCE = 5
    }
}
```

`repository.purchasesPagingFlow(query)` is provided by AND-218 (`PagingSource`/`RemoteMediator`
over `PurchasesApi`). This ticket assumes that signature exists; if AND-218 ships only
non-paged list/search calls, this ticket adds the `PagingSource` inside `feature-purchases`
(`PurchasesPagingSource` calling `repository.getPurchases(query, cursor, PAGE_SIZE)`), keeping the
repository untouched. The chosen path is recorded as an open question (§13, OQ-1).

### Composables

```kotlin
@Composable
fun PurchaseHistoryRoute(
    onPurchaseClick: (String) -> Unit,
    onReauthRequired: () -> Unit,
    viewModel: PurchaseHistoryViewModel = hiltViewModel(),
)

@Composable
fun PurchaseHistoryScreen(
    uiState: PurchaseHistoryUiState,
    items: LazyPagingItems<Purchase>,
    onQueryChange: (String) -> Unit,
    onClearQuery: () -> Unit,
    onSubmitSearch: () -> Unit,
    onRefresh: () -> Unit,
    onPurchaseClick: (String) -> Unit,
)

@Composable private fun PurchaseSearchBar(query: String, onQueryChange: (String) -> Unit,
    onClear: () -> Unit, onSubmit: () -> Unit)
@Composable private fun PurchaseRow(item: Purchase, onClick: () -> Unit)
@Composable private fun PurchaseRowPlaceholder()   // skeleton
@Composable private fun EmptyHistory()
@Composable private fun EmptySearchResults(query: String, onClear: () -> Unit)
@Composable private fun StaleBanner()
```

The Route collects `pagingItems.collectAsLazyPagingItems()`, observes `uiState`, and consumes
`events` in a `LaunchedEffect` to invoke the navigation lambdas. List rendering uses `LazyColumn`
with `items(count = items.itemCount, key = items.itemKey { it.id })`; load states drive
header/footer composables via `items.loadState`. The Material 3
`PullToRefreshBox` wraps the list and is bound to `uiState.isRefreshing` + `items.refresh()`.

Date/amount formatting uses shared helpers from `core-ui` (`rememberCurrencyFormatter`,
`rememberDateFormatter`) to keep locale handling consistent.

## 5. API Contract

This screen calls no endpoints directly; all I/O goes through `PurchasesRepository` (AND-218).
The underlying HTTP contract it relies on (restated from AND-218 / `purchases.ts`; verify against
`/openapi.json`):

**List + search** (single endpoint; absent `q` returns full history):

```
GET /ui/purchases?limit=20&cursor=<opaque>&q=<urlencoded text>
Cookies: session + ui_csrf      Header: X-CSRF-Token: <ui_csrf>
```

Response `200`:

```json
{
  "items": [
    {
      "id": "pur_01HXYZ...",
      "title": "Pro Plan — Annual",
      "merchant": "TestLogon",
      "amount": 4900,
      "currency": "USD",
      "status": "COMPLETED",
      "purchased_at": "2026-05-31T18:22:04Z",
      "description": "Annual subscription renewal"
    }
  ],
  "next_cursor": "eyJwayI6...",
  "total": 137
}
```

- `amount` is an integer in the currency's minor unit (cents); the UI formats it. `status` is one
  of `COMPLETED | PENDING | REFUNDED | FAILED` (treat unknown values as a neutral badge).
  `next_cursor` is `null`/absent on the last page (terminates Paging append).
- Pagination is cursor-based via `next_cursor`/`cursor`. If AND-218's final contract is
  offset-based (`offset`/`limit`), the `PagingSource` keys on offset instead — no UI change.

**Error `4xx/5xx`** — FastAPI `detail` mapped by AND-218 into `ApiResult.Error` (string |
`[{msg}]` | `{code,...}`). `401` is handled by the OkHttp authenticator (single
`POST /ui/session/refresh` then retry); a persistent `401` surfaces as `reauthRequired`.

## 6. Data & State Management

- **Source of truth:** the Paging 3 `Flow<PagingData<Purchase>>` is the list source of truth;
  `PurchaseHistoryUiState` carries only cross-cutting flags (query, refreshing, stale, reauth).
- **Search query:** stored in `SavedStateHandle` (`KEY_QUERY`) so it survives process death and
  config change (FR-6). The Paging flow is rebuilt via `flatMapLatest` on debounced query changes;
  `cachedIn(viewModelScope)` preserves scroll position across config change for an unchanged query.
- **Caching / offline (Room 2.6):** the unfiltered history (`q` empty) is cached by AND-218's
  `RemoteMediator` into a Room `purchases` table for offline/stale reads. When the network read
  fails but cached rows exist, the screen serves cache and sets `isStale = true` (FR-4, §7).
  **Search queries (`q` non-empty) are network-only** (not cached) — an offline search shows the
  offline/error state rather than partial local results. This boundary is intentional and noted in
  §13 (OQ-2).
- **Mapping:** DTO→domain mapping (`PurchaseDto.toDomain()`) lives in `core-data` (AND-218). The
  domain `Purchase` type (in `core-model`) is what the UI consumes:

```kotlin
data class Purchase(
    val id: String,
    val title: String,
    val merchant: String,
    val amountMinor: Long,
    val currency: String,
    val status: PurchaseStatus,
    val purchasedAt: Instant,
    val description: String?,
)
enum class PurchaseStatus { COMPLETED, PENDING, REFUNDED, FAILED, UNKNOWN }
```

## 7. Error Handling & Resilience

- **Timeouts/retry:** inherited from the shared OkHttp client (~20s call timeout; bounded
  exponential backoff for idempotent GETs only). Paging `LoadState.Error` is the surfaced result
  of exhausted retries.
- **Initial-load error:** `loadState.refresh is LoadState.Error` with zero items → full-screen
  error view with a Retry button calling `items.retry()`. The mapped FastAPI `detail` message is
  shown when human-readable; otherwise a generic "Couldn't load purchases" string.
- **Append error:** `loadState.append is LoadState.Error` → inline footer with a Retry row
  (`items.retry()`), list content preserved.
- **Empty vs. empty-search:** when `refresh` is `NotLoading` and `itemCount == 0`, render
  `EmptyHistory()` if `query` is blank, else `EmptySearchResults(query)` with a Clear action.
- **Offline/stale:** if AND-218's mediator yields cached data while the remote read failed, set
  `isStale = true` and show a dismissible `StaleBanner()` ("Showing saved data — couldn't reach
  server"). Pull-to-refresh re-attempts.
- **Reauth:** repeated `401` after the single refresh attempt → repository returns an auth error;
  ViewModel emits `ReauthRequired`, Route calls `onReauthRequired()` to route to the sign-in flow.
- **Debounce safety:** `flatMapLatest` cancels the in-flight query when the text changes, so stale
  responses cannot overwrite newer results.

## 8. Security & Privacy

- No new credentials or tokens are handled here; the screen relies entirely on the existing cookie
  jar + `X-CSRF-Token` mechanism. No auth material is logged.
- Purchase data is PII/financial. Do **not** log purchase titles, amounts, descriptions, or ids in
  release builds. Telemetry (§10) emits only counts and non-identifying enums.
- Disable screenshotting consideration: not required by this ticket, but the screen must not write
  purchase content to any external/world-readable storage; Room DB stays in app-private storage.
- All traffic is plaintext HTTP against the dev host (known limitation of the dev environment); the
  network security config permitting cleartext is owned by the build/networking tickets, not here.
  Production builds must use HTTPS (tracked outside this ticket).

## 9. Accessibility & i18n

- All strings live in `feature-purchases/src/main/res/values/strings.xml`; no hardcoded UI text.
  Includes search hint, clear-button `contentDescription`, empty/error copy, status badge labels,
  and stale banner.
- Status badges and amount/date use text, not color alone; badges meet 3:1 contrast and carry
  semantic content descriptions (e.g., "Status: Refunded").
- Search field exposes IME `Search` action and a labeled clear icon; touch targets ≥ 48dp.
- Currency and dates are formatted via locale-aware formatters (`NumberFormat.getCurrencyInstance`
  /`java.time` with the device locale); amounts respect the purchase's own `currency` code.
- List rows are single semantics nodes with a merged content description summarizing title,
  amount, date, and status for TalkBack. Supports dynamic font scaling and RTL layouts.

## 10. Telemetry & Logging

Via the shared analytics interface (from `core-ui`/`core-data`):

- `purchase_history_viewed` — `{ source }`.
- `purchase_search_performed` — `{ query_length: Int, result_count: Int }` (length only; never the
  query text).
- `purchase_row_opened` — `{ position: Int }` (no id/amount).
- `purchase_history_load_error` — `{ phase: "refresh"|"append", error_kind }`.
- `purchase_history_stale_shown` — `{}`.

Debug-only `Timber` logs may include load states and result counts; release logging strips all
purchase content per §8.

## 11. Testing Strategy

Use `core-testing` fakes; no live dev-host calls in CI.

- **ViewModel unit tests** (`PurchaseHistoryViewModelTest`, JUnit + Turbine + coroutines test
  dispatcher): query debounce (300 ms) collapses rapid input to a single repository call; blank
  query bypasses debounce and clears filter; `SavedStateHandle` restores query; `onPurchaseClick`
  emits `OpenPurchase`; persistent auth error emits `ReauthRequired`.
- **Paging tests:** with a `FakePurchasesRepository` backed by an in-memory list, assert
  newest-first ordering, page size 20, append termination on null `next_cursor`, and that search
  filters results. Use `AsyncPagingDataDiffer` or snapshot the `PagingData`.
- **Compose UI tests** (`createAndroidComposeRule`): each state renders the correct node —
  loading skeleton, content rows, empty-history, empty-search (with Clear), refresh-error +
  Retry, append-error + Retry, stale banner. Typing into the search field and asserting filtered
  rows; clear icon resets list. Accessibility assertions for content descriptions.
- **Snapshot/screenshot tests** (Paparazzi or Roborazzi, if configured): row, empty, and error
  states in light/dark.
- **Coverage target:** ViewModel + paging logic ≥ 85% line coverage; all FRs mapped to at least
  one test.

## 12. Dependencies & Sequencing

- **Depends on AND-218** (Purchases API — P0): repository, DTOs, `core-model` `Purchase` type,
  `ApiResult` mapping, and (ideally) the paging flow. This ticket is blocked until AND-218's
  repository surface is merged. If the paging flow is not in AND-218's scope, this ticket adds the
  `PagingSource` locally (OQ-1) — no change to AND-218's blocking status.
- **Transitively depends on** AND-027 (AND-218's own dependency: networking/session foundation)
  for the cookie jar, CSRF header, and `401` refresh authenticator.
- **Module/DI:** new `feature-purchases` Gradle module wired into `app`'s Hilt graph and
  Navigation-Compose graph; the host wires `onPurchaseClick`→detail route (later ticket) and
  `onReauthRequired`→sign-in.
- **Blocks:** the purchase detail screen ticket (consumes the navigation event/id emitted here).

## 13. Risks & Open Questions

- **OQ-1 (Paging ownership):** Does AND-218 expose `purchasesPagingFlow(query)`, or only flat
  list/search calls? Resolution determines whether the `PagingSource` lives in `core-data` or
  `feature-purchases`. Default: implement locally if absent.
- **OQ-2 (Search offline behavior):** Confirm search is network-only (no local FTS over the Room
  cache). Default per §6: search is network-only; only the unfiltered history is cached.
- **OQ-3 (Pagination style):** cursor (`next_cursor`) vs. offset — verify against `/openapi.json`
  / `purchases.ts`. UI is agnostic; only the `PagingSource` key changes.
- **Risk — flaky dev backend:** intermittent failures/timeouts make manual QA noisy; mitigated by
  retry/backoff, stale-cache fallback, and CI running against fakes only.
- **Risk — server search semantics:** ranking/field coverage of `q` is backend-defined and may
  differ from user expectation; the UI shows whatever the server returns and does no client-side
  reordering.
- **Risk — large histories:** very long histories rely on Paging + stable keys for performance;
  ensure `itemKey` uses `id` to avoid recomposition churn.

## 14. Acceptance Criteria

- AC-1. The Purchase History screen renders the authenticated user's purchases newest-first with
  title, formatted amount+currency, date, and status badge (satisfies "History renders").
- AC-2. Scrolling loads additional pages automatically (Paging 3, page size 20) and stops at the
  last page (null `next_cursor`).
- AC-3. Entering text in the search field filters/queries history server-side with 300 ms debounce;
  IME Search submits immediately; clearing the field restores the full history (satisfies
  "searchable").
- AC-4. Distinct, correct UI for: initial loading, content, append loading, empty-history,
  empty-search-results (with Clear), refresh error (Retry), append error (Retry), and offline/stale
  (banner over cached data).
- AC-5. The active search query survives configuration change and process death.
- AC-6. Tapping a row emits a navigation event carrying the purchase id; a persistent `401`
  (post-refresh) routes to the re-auth flow.
- AC-7. No purchase content (titles, amounts, ids, descriptions) appears in release logs or
  telemetry payloads.
- AC-8. ViewModel/paging unit tests and Compose state tests pass in CI against `core-testing`
  fakes; ViewModel/paging coverage ≥ 85%.

## 15. Definition of Done

- `feature-purchases` module builds (`./gradlew :feature-purchases:assembleDebug`) and is wired
  into the app's Hilt + Navigation graphs; namespace under `com.testlogon.android.feature.purchases`.
- All 15 functional requirements (FR-1..FR-7) and acceptance criteria (AC-1..AC-8) implemented and
  verified.
- Unit, paging, and Compose UI tests added and green in CI; lint and Detekt/ktlint pass with no new
  warnings; coverage gate met.
- All user-visible strings externalized; TalkBack pass on the list, search, and empty/error states;
  RTL and font-scaling spot-checked.
- No hardcoded endpoints or secrets in the feature module; all I/O via `PurchasesRepository`.
- Open questions OQ-1..OQ-3 resolved (or explicitly deferred with the chosen default documented in
  code/PR).
- PR reviewed and merged to `android-port`; demo against the dev host shows render + search and
  graceful degradation when the host is slow/unavailable.
