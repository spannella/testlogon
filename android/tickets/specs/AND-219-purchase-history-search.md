---
id: AND-219
title: Purchase history + search
milestone: M5
epic: E30
priority: P1
size: M
depends_on: [AND-218]
blocks: []
status: reviewed
reviewed_on: 2026-06-06
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
- **Web reference:** `src/api/endpoints/purchases.ts` (`listTransactions`, `searchTransactions`,
  `getTransaction`) and shared types in `src/api/types.ts` (`PurchaseTransactionSummary`,
  `PurchaseTransactionInfo`). Mirror field names from there; verified against `openapi.pretty.json`
  schema `PurchaseTransactionInfo`. **Correction:** field names and pagination differ substantially
  from the original draft — see §5 and §16.
- **Auth:** calls ride the persistent cookie jar + `X-CSRF-Token` header (sourced from the
  `ui_csrf` cookie) established by the session stack. **Correction:** the web client (`client.ts`)
  is *not* purely cookie-based — it also attaches an `Authorization: Bearer <accessToken>` header
  when an access token is present; the Android port must replicate whichever transport AND-218/
  AND-027 standardize on. On `401` for an authenticated user the client performs a single
  `POST /ui/session/refresh` (verified: `POST /ui/session/refresh`) and retries once; a persistent
  `401` logs out. This screen assumes an authenticated session and surfaces a re-auth-required
  state if refresh ultimately fails.
- **Backend:** FastAPI + DynamoDB at dev host `http://18.222.237.167:8000` (PLAINTEXT, unreliable).
  Use ~20s timeouts, bounded backoff retry for idempotent GETs only.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Navigation-Compose, Hilt (KSP), Paging 3,
  Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Room 2.6, Coil. minSdk 24,
  compile/target 35, JDK 17, namespace base `com.testlogon.android`.

## 3. Functional Requirements

FR-1. **History list.** On entry, load the current user's purchases sorted newest-first (by
`created_at` descending — **corrected:** there is no `purchasedAt` field). Each row shows: the
purchase title (**corrected:** there is no `title` field — use `description`, falling back to
`"Order ${id.take(8)}"` as the web client does), formatted amount + currency, formatted date
(from `created_at`), and status badge. Observed status values are lowercase `pending | completed
| cancelled | reverted` (**corrected** from `COMPLETED/PENDING/REFUNDED`). Tapping a row emits a
navigation event carrying the purchase id (`txn_id`).

FR-2. **Infinite scroll.** *(Corrected — feasibility-gated.)* The backend list/search endpoints
return a **bare array with no cursor/offset paging** (only a `limit` param; web uses `limit: 50`).
True infinite scroll is **not implementable** against the current contract. Until AND-218/backend
expose real pagination, the screen loads a single capped page (`limit`, default 50) and renders it
in a `LazyColumn` (no append). If/when cursor or offset paging is added server-side, re-introduce
Paging 3 keyed on that mechanism. Tracked in §13 OQ-3 and §16. The acceptance criterion AC-2 is
amended accordingly.

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

**CORRECTED against `openapi.index.txt` + `purchases.ts`.** There is **no** single
`/ui/purchases` endpoint and **no** envelope/cursor pagination. List and search are **two
separate GET endpoints**, each returning a **bare JSON array** of summaries with **no
`next_cursor`/`total`**; the only pagination control is a `limit` query param.

**List** (full history, optional server-side `status` filter):

```
GET /ui/purchase-history/transactions?limit=50&status=<UPPERCASE status>
Cookies: session + ui_csrf      Header: X-CSRF-Token: <ui_csrf>
op = ui_list_transactions ; params = limit, status
```

**Search** (free-text; separate endpoint — NOT the same path with a `q` param):

```
GET /ui/purchase-history/transactions/search?q=<urlencoded text>&limit=50
op = ui_search_transactions ; params = q, limit
```

Response `200` for both (bare array of `PurchaseTransactionSummary`):

```json
[
  {
    "txn_id": "txn_01HXYZ...",
    "created_at": 1748715724,
    "updated_at": 1748715724,
    "status": "completed",
    "amount": 49.0,
    "currency": "USD",
    "merchant_id": "mrc_abc",
    "external_ref": "ext-123",
    "description": "Annual subscription renewal"
  }
]
```

- **Corrected field names** (verified `PurchaseTransactionSummary`/`PurchaseTransactionInfo`):
  the id is **`txn_id`** (not `id`); there is **no `title`** field (web renders
  `description ?? "Order " + txn_id[:8]`); there is **no `merchant`** field — only
  **`merchant_id`** (optional). Other fields: `external_ref?`, `description?`.
- **`amount` is a decimal `number` in major currency units**, NOT integer minor units/cents. The
  web client formats it directly via `Intl.NumberFormat({style:'currency'})`
  (`formatCurrency(amount, currency)`); the Android port must format the decimal as-is (do NOT
  divide by 100). The domain model should carry a `BigDecimal`/`Double` amount, not
  `amountMinor: Long` (see §6 correction).
- **`created_at`/`updated_at` are integer epoch SECONDS** (web does `new Date(ts * 1000)`), NOT an
  ISO-8601 `purchased_at` string. There is no `purchased_at` field. Newest-first sort keys on
  `created_at` descending.
- **`status` is a free-form string**, observed lowercase: `pending | completed | cancelled |
  reverted` (web `statusVariant`/`STATUS_FILTERS`). It is **not** `COMPLETED|PENDING|REFUNDED|FAILED`
  — there is no `REFUNDED`/`FAILED`; the lifecycle uses `cancelled`/`reverted`. Treat unknown values
  as a neutral badge. The `status` filter sent to the **list** endpoint is uppercased by the web
  client (`statusFilter.toUpperCase()`); search results are status-filtered **client-side**.
- **Pagination:** none beyond `limit`. The endpoints return a single capped page (web uses
  `limit: 50`). **This invalidates the Paging-3 cursor/offset design** in §4/§6 — see §6 and §16
  for the corrected approach (single-shot list capped at `limit`, or AND-218 must add real
  pagination before infinite scroll is possible).

**Error `4xx/5xx`** — FastAPI `detail` mapped by AND-218 into `ApiResult.Error`. Verified against
`client.ts: normalizeErrorDetail`: `detail` may be a string, an array of `{msg}` objects
(422 validation), or an object `{code, ...}` (e.g. `role_required_scope`, `geo_blocked`). `401` for
an authenticated user triggers a single `POST /ui/session/refresh` then one retry; a persistent
`401` surfaces as `reauthRequired`. The list/search ops also document `400/401/403/429` responses.

## 6. Data & State Management

> **Design correction (no server pagination):** the §5 verification shows the endpoints return a
> bare array with no cursor/offset, so the Paging-3 design below is **not feasible as written**.
> Recommended replacement until backend pagination exists: a single `StateFlow<List<Purchase>>`
> (capped at `limit`) as the list source of truth; keep the `flatMapLatest`/debounce on query and
> the Room cache for the unfiltered list. The Paging-specific bullets are retained below for the
> future state and annotated.

- **Source of truth (corrected):** a `StateFlow<List<Purchase>>` (capped list) — **not** a Paging 3
  `Flow<PagingData<Purchase>>` — given the non-paged contract. `PurchaseHistoryUiState` carries only
  cross-cutting flags (query, refreshing, stale, reauth). (Paging 3 returns here only if AND-218/
  backend add real pagination.)
- **Search query:** stored in `SavedStateHandle` (`KEY_QUERY`) so it survives process death and
  config change (FR-6). The list flow is rebuilt via `flatMapLatest` on debounced query changes
  (verified web debounce is 300 ms); empty/whitespace query routes to the **list** endpoint, a
  non-empty query routes to the **search** endpoint.
- **Caching / offline (Room 2.6):** the unfiltered history (empty query → list endpoint) is cached
  into a Room `purchases` table for offline/stale reads. When the network read fails but cached rows
  exist, the screen serves cache and sets `isStale = true` (FR-4, §7). **Note:** a `RemoteMediator`
  is a paging construct; with the non-paged contract use a simple "fetch list → upsert into Room →
  observe Room" write-through cache instead. This caching layer is AND-218's responsibility (OQ-1).
  **Search queries (`q` non-empty) are network-only** (not cached) — an offline search shows the
  offline/error state rather than partial local results. This boundary is intentional and noted in
  §13 (OQ-2).
- **Mapping:** DTO→domain mapping (`PurchaseDto.toDomain()`) lives in `core-data` (AND-218). The
  domain `Purchase` type (in `core-model`) is what the UI consumes:

**CORRECTED** to match the verified DTO (`PurchaseTransactionSummary`). The id is `txn_id`, there
is no `title`/`merchant`, `amount` is a decimal in major units, and `created_at` is epoch seconds:

```kotlin
data class Purchase(
    val id: String,            // maps from txn_id
    val description: String?,  // there is no `title`; UI falls back to "Order ${id.take(8)}"
    val merchantId: String?,   // maps from merchant_id (optional); no `merchant` field exists
    val externalRef: String?,  // maps from external_ref (optional)
    val amount: BigDecimal,    // decimal MAJOR units (NOT minor/cents); format as-is
    val currency: String,
    val status: PurchaseStatus,
    val createdAt: Instant,    // maps from created_at (epoch SECONDS -> Instant.ofEpochSecond)
    val updatedAt: Instant,    // maps from updated_at (epoch seconds)
)
// status is a free-form string from the server; map known lowercase values, keep UNKNOWN fallback.
enum class PurchaseStatus { PENDING, COMPLETED, CANCELLED, REVERTED, UNKNOWN }
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
- **List/repository tests (corrected — no Paging):** with a `FakePurchasesRepository` backed by an
  in-memory list, assert newest-first ordering by `created_at`, that the `limit` is honored (default
  50), that an empty query hits the list endpoint and a non-empty query hits the search endpoint,
  and that the returned array is rendered without an append spinner. (Add `AsyncPagingDataDiffer`-
  based paging tests only if/when backend pagination lands.)
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
- **OQ-2 (Search offline behavior):** **Resolved by verification.** Search is a distinct endpoint
  (`/ui/purchase-history/transactions/search`) and is network-only; only the unfiltered list is
  cached. Web confirms separate `searchTransactions` call (`purchases.ts`) and client-side status
  filtering of search results.
- **OQ-3 (Pagination style):** **Resolved by verification — there is NO pagination.** Both list and
  search endpoints return a bare array with only a `limit` param; no `next_cursor`, no `offset`, no
  `total` (verified `openapi.index.txt` + `purchases.ts`). Infinite scroll (FR-2/AC-2) is gated on
  the backend adding pagination; until then the screen renders one capped page.
- **Risk — flaky dev backend:** intermittent failures/timeouts make manual QA noisy; mitigated by
  retry/backoff, stale-cache fallback, and CI running against fakes only.
- **Risk — server search semantics:** ranking/field coverage of `q` is backend-defined and may
  differ from user expectation; the UI shows whatever the server returns and does no client-side
  reordering.
- **Risk — large histories:** very long histories rely on Paging + stable keys for performance;
  ensure `itemKey` uses `id` to avoid recomposition churn.

## 14. Acceptance Criteria

- AC-1. The Purchase History screen renders the authenticated user's purchases newest-first (by
  `created_at` desc) with the title (`description`, fallback `"Order {txn_id[:8]}"`), formatted
  amount+currency (decimal major units), date, and status badge (`pending|completed|cancelled|
  reverted`, unknown→neutral). (Satisfies "History renders".) (Corrected field/sort names.)
- AC-2. *(Corrected — gated on backend.)* The screen loads a single capped page (`limit`, default
  50) since the endpoints expose no cursor/offset paging. When real pagination is added server-side,
  scrolling loads additional pages automatically and stops at the last page. The current contract is
  validated by rendering the full returned array without an append spinner.
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. Sources: OpenAPI =
`reference/openapi.index.txt` / `reference/openapi.pretty.json`; frontend = `reference/src/...`.

1. **List endpoint is `GET /ui/purchases?...&q=...` (single endpoint, optional `q`).** —
   **Corrected.** No such endpoint. Real list endpoint is `GET /ui/purchase-history/transactions`
   (params `limit`, `status`). Source: OpenAPI `GET /ui/purchase-history/transactions`
   (op `ui_list_transactions`); frontend `src/api/endpoints/purchases.ts: listTransactions`.
2. **Search is the same endpoint with a `q` param.** — **Corrected.** Search is a *separate*
   endpoint `GET /ui/purchase-history/transactions/search` (params `q`, `limit`). Source: OpenAPI
   `GET /ui/purchase-history/transactions/search` (op `ui_search_transactions`); frontend
   `src/api/endpoints/purchases.ts: searchTransactions`.
3. **Response is an envelope `{items, next_cursor, total}`.** — **Corrected.** Both endpoints
   return a **bare JSON array** of `PurchaseTransactionSummary`; no `items`, `next_cursor`, or
   `total`. Source: frontend return type `api.get<PurchaseTransactionSummary[]>` in
   `src/api/endpoints/purchases.ts`; OpenAPI list/search `resp=200:` carries no schema (untyped
   array body).
4. **Item id field is `id` (`pur_...`).** — **Corrected.** Field is **`txn_id`**. Source:
   `src/api/types.ts: PurchaseTransactionSummary.txn_id`; OpenAPI schema
   `PurchaseTransactionInfo.txn_id` (required).
5. **Item has a `title` field.** — **Corrected.** No `title`. Web renders
   `description ?? "Order " + txn_id.slice(0,8)`. Source: `src/pages/purchases/PurchaseHistory.tsx`
   (row render); `src/api/types.ts: PurchaseTransactionSummary` (no `title`).
6. **Item has a `merchant` field.** — **Corrected.** Only `merchant_id` (optional). Source:
   `src/api/types.ts: PurchaseTransactionSummary.merchant_id`; OpenAPI
   `PurchaseTransactionInfo.merchant_id`.
7. **`amount` is an integer in minor units (cents).** — **Corrected.** `amount` is a decimal
   `number` in major units; formatted directly with `Intl.NumberFormat({style:'currency'})`. Source:
   OpenAPI `PurchaseTransactionInfo.amount` (`type: number`); `src/pages/purchases/PurchaseHistory.tsx:
   formatCurrency(txn.amount, ...)`.
8. **Purchase date field is `purchased_at` (ISO-8601 string).** — **Corrected.** Field is
   `created_at`, an integer **epoch seconds** (also `updated_at`). Web: `new Date(ts * 1000)`.
   Source: OpenAPI `PurchaseTransactionInfo.created_at` (`type: integer`);
   `src/pages/purchases/PurchaseHistory.tsx: formatDate(ts) => new Date(ts*1000)`.
9. **`status` is the enum `COMPLETED | PENDING | REFUNDED | FAILED`.** — **Corrected.** `status` is
   a free-form string; observed lowercase `pending | completed | cancelled | reverted`. No
   `REFUNDED`/`FAILED`. Source: OpenAPI `PurchaseTransactionInfo.status` (`type: string`, no enum);
   frontend `src/pages/purchases/PurchaseHistory.tsx: STATUS_FILTERS` / `statusVariant`.
10. **Pagination is cursor-based (`next_cursor`/`cursor`) or offset.** — **Corrected.** No
    pagination of any kind; only a `limit` param (web uses 50). Source: OpenAPI list/search
    `params=limit,...` (no `cursor`/`offset`); frontend `listTransactions({limit})` /
    `searchTransactions(q, limit)`.
11. **CSRF uses header `X-CSRF-Token` from the `ui_csrf` cookie.** — **Verified.** Source:
    `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`).
12. **On 401, a single `POST /ui/session/refresh` is performed, then one retry; persistent 401
    logs out / surfaces reauth.** — **Verified.** Source: `src/api/client.ts: refreshSession()`
    (`POST /ui/session/refresh`) and the 401 handling block (single shared `refreshPromise`, one
    retry, `logout("session_expired")` on repeat 401); OpenAPI `POST /ui/session/refresh`
    (op `ui_session_refresh`).
13. **All calls are purely cookie-based.** — **Corrected (partial).** The web client also attaches
    `Authorization: Bearer <accessToken>` when an access token is present, in addition to the cookie
    jar + CSRF header. Source: `src/api/client.ts` (`headers.set("Authorization", \`Bearer ...\`)`).
    Android transport must match whatever AND-218/AND-027 standardize on.
14. **FastAPI `detail` may be string | `[{msg}]` | `{code,...}`.** — **Verified.** Source:
    `src/api/client.ts: normalizeErrorDetail` (handles string, array-of-`{msg}`, and object with
    `code` via `mapAuthorizationError`); OpenAPI `HTTPValidationError` (422) is the `[{msg}]` shape.
15. **List/search also document `400/401/403/429`.** — **Verified.** Source: OpenAPI list/search
    `resp=...;400;401;403;429`.
16. **Search is network-only; only unfiltered history is cached (OQ-2).** — **Verified** (separate
    search endpoint; no local FTS in web). Source: `src/api/endpoints/purchases.ts` (distinct
    `searchTransactions`); `src/pages/purchases/PurchaseHistory.tsx` (search results filtered by
    status client-side, not cached).
17. **Search debounce is 300 ms.** — **Verified.** Source:
    `src/pages/purchases/PurchaseHistory.tsx` (`setTimeout(... 300)`); matches spec `SEARCH_DEBOUNCE_MS`.
18. **`PurchasesRepository.purchasesPagingFlow(query)` exists in AND-218 (OQ-1).** —
    **Unverified-assumption.** AND-218 is not in the reference sources; cannot confirm any
    repository surface. Given §16.10 (no server pagging), a paging flow is also unlikely to be
    correct. Source: none (cross-ticket dependency).
19. **Telemetry/analytics interface from `core-ui`/`core-data`.** — **Unverified-assumption.**
    Android-only infra, not in reference sources. Source: none.
20. **Compose + Material 3 `PullToRefreshBox`, Paging 3, Hilt, Navigation-Compose stack choices.** —
    **Unverified-assumption (framework refs).** Standard AndroidX libraries; correct as a tooling
    choice but the *infinite-scroll* use of Paging 3 is contradicted by §16.10. Framework refs:
    `https://developer.android.com/jetpack/compose` (Material 3 / pull-to-refresh),
    `https://developer.android.com/topic/libraries/architecture/paging/v3-overview` (Paging 3).

### Corrections made

- §2: corrected web-reference paths to `src/api/endpoints/purchases.ts` (`listTransactions`,
  `searchTransactions`); flagged that the web client is not purely cookie-based (adds bearer token).
- §5: replaced the fictitious `GET /ui/purchases` single endpoint + envelope/cursor response with
  the two real endpoints (`/ui/purchase-history/transactions` and `.../search`), the bare-array
  response, and corrected every field name (`txn_id`, no `title`, `merchant_id`, decimal `amount`,
  epoch-seconds `created_at`, free-string `status` values, no pagination).
- §3 FR-1: corrected sort field (`created_at`), title fallback, and status values. FR-2: corrected
  infinite scroll to be feasibility-gated (no server pagination → single capped page).
- §6: corrected the domain model (`txn_id`→`id`, `BigDecimal amount`, `createdAt/updatedAt`,
  `merchantId`/`externalRef`, status enum `PENDING|COMPLETED|CANCELLED|REVERTED|UNKNOWN`), and
  replaced Paging/`RemoteMediator` source-of-truth with a capped `StateFlow<List<Purchase>>` +
  write-through Room cache.
- §11: corrected the "paging tests" bullet to list/repository tests (no Paging, `limit`-based).
- §13: resolved OQ-2 (search network-only) and OQ-3 (no pagination) against the sources.
- §14: corrected AC-1 (fields/sort/status) and AC-2 (single capped page, infinite scroll gated).

### Open assumptions

- **AND-218 repository surface** (`PurchasesRepository`, `purchasesPagingFlow`, DTO mapping,
  `ApiResult`): unverifiable — AND-218 is a separate ticket not present in the reference sources.
  Given the non-paged contract, a `purchasesPagingFlow` is unlikely to be the right surface.
- **Android infra** (Hilt analytics interface, `core-ui` formatters, `core-testing` fakes, network
  security config / cleartext, Room schema): not in the reference sources; assumed per platform
  conventions.
- **Bearer-vs-cookie transport** for the Android client: the web sends both; which one AND-027/
  AND-218 standardize on for native is unverifiable here.
- **`X-CSRF-Token` requirement for GETs:** the web client attaches it on every request including
  GETs, but whether the backend *enforces* CSRF on GETs is not determinable from these sources.

## 17. Test Plan

Test targets: **JVM** = JVM unit/Robolectric (local, no device); **emu** = headless AVD `test35`
(x86_64, API 35); **device** = physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). All
networked cases use `core-testing` fakes / MockWebServer — never the live dev host in CI.

- **TC-AND-219-01 — Happy-path list render.** Type: Compose-UI. Target: emu. Preconditions: fake
  repository returns 3 `PurchaseTransactionSummary` rows with distinct `created_at`. Steps: launch
  `PurchaseHistoryScreen`; wait for content. Expected: rows render newest-first by `created_at`,
  each showing title (`description`, else `"Order {txn_id[:8]}"`), amount formatted as decimal
  currency (e.g. `$49.00`, not `$0.49`), date from `created_at*1000`, and the correct status badge.
  Traces: AC-1.

- **TC-AND-219-02 — Single-page (no pagination) contract.** Type: contract/MockWebServer. Target:
  JVM. Preconditions: MockWebServer returns a bare JSON array (not an envelope) of N rows for
  `GET /ui/purchase-history/transactions?limit=50`. Steps: invoke the list call through the data
  layer. Expected: request path/params match exactly; the whole array maps to domain models; no
  attempt to read `next_cursor`/`items`/`total`; no append/second page request is issued. Traces:
  AC-1, AC-2.

- **TC-AND-219-03 — Field mapping correctness.** Type: unit. Target: JVM. Preconditions: a fixture
  with `txn_id`, `amount: 49.0`, `created_at: 1748715724`, `status: "completed"`, `merchant_id`,
  no `title`. Steps: map DTO→`Purchase`. Expected: `id == txn_id`, `amount == 49.00` BigDecimal
  (not divided by 100), `createdAt == Instant.ofEpochSecond(1748715724)`, `status == COMPLETED`,
  `merchantId` set, title fallback applied. Traces: AC-1.

- **TC-AND-219-04 — Search uses the search endpoint with debounce.** Type: unit (Turbine +
  test dispatcher). Target: JVM. Preconditions: fake repo records calls. Steps: emit "p","pr","pro"
  within < 300 ms via `onQueryChange`; advance virtual clock 300 ms. Expected: exactly one search
  call to `/ui/purchase-history/transactions/search?q=pro`; the empty/initial state used the *list*
  endpoint, not search. Traces: AC-3.

- **TC-AND-219-05 — Clear/blank query restores full list.** Type: unit. Target: JVM. Preconditions:
  active query "pro". Steps: call `onClearQuery()` (or set whitespace). Expected: no debounce delay
  for empty; the *list* endpoint is queried (not search with empty `q`); whitespace-only treated as
  empty. Traces: AC-3.

- **TC-AND-219-06 — IME Search submits immediately.** Type: Compose-UI. Target: emu. Preconditions:
  query typed but debounce not yet elapsed. Steps: perform IME `Search` action on the field.
  Expected: an immediate (non-debounced) search query for the current text; results render. Field
  exposes the `Search` IME action. Traces: AC-3.

- **TC-AND-219-07 — State coverage: empty-history vs empty-search vs error vs stale.** Type:
  Compose-UI. Target: emu. Preconditions: parameterized fakes. Steps: drive each state. Expected:
  empty list + blank query → `EmptyHistory`; empty list + non-blank query → `EmptySearchResults`
  with a working "Clear search"; load failure with zero items → full-screen error + Retry calling
  the reload; cached rows after a failed network read → `StaleBanner` over content. (Note: with no
  server pagination there is no append-error/append-loading footer to assert.) Traces: AC-4.

- **TC-AND-219-08 — Validation/error shape mapping (422 + 4xx).** Type: contract/MockWebServer.
  Target: JVM. Preconditions: MockWebServer returns 422 with `{"detail":[{"msg":"..."}]}`, and a
  separate 400 with `{"detail":"Bad request"}`, and a 403 with `{"detail":{"code":"role_required"}}`.
  Steps: trigger a load for each. Expected: error mapping yields a human-readable message from each
  shape (array-of-`{msg}` joined, string passthrough, coded-object mapped/neutralized); generic
  fallback "Couldn't load purchases" when not human-readable. Traces: AC-4.

- **TC-AND-219-09 — 401 single refresh then retry; persistent 401 → reauth.** Type:
  contract/MockWebServer. Target: JVM. Preconditions: list returns 401, then `POST
  /ui/session/refresh` returns 200, then list returns 200 (case A); and list 401 → refresh 401
  (case B). Steps: load. Expected: case A → exactly one refresh, one retry, success rendered;
  case B → no infinite loop, repository surfaces auth error, ViewModel emits `ReauthRequired`,
  Route invokes `onReauthRequired`. Traces: AC-6.

- **TC-AND-219-10 — Search-query survives config change & process death.** Type: instrumented.
  Target: emu. Preconditions: query "pro" entered. Steps: rotate device, then simulate process
  death/restore via `SavedStateHandle` (`KEY_QUERY`). Expected: query restored to "pro" and
  re-applied (search re-issued). Traces: AC-5.

- **TC-AND-219-11 — Row tap emits navigation event with `txn_id`.** Type: unit. Target: JVM.
  Steps: call `onPurchaseClick("txn_123")`; collect `events`. Expected: a single
  `OpenPurchase("txn_123")` event; Route invokes `onPurchaseClick("txn_123")`. Traces: AC-6.

- **TC-AND-219-12 — No PII/financial data in release logs or telemetry.** Type: unit. Target: JVM.
  Preconditions: telemetry sink captures events; release log config. Steps: perform view, search,
  row-open, and an error. Expected: `purchase_search_performed` carries only `query_length` +
  `result_count` (never query text); `purchase_row_opened` carries only `position` (no id/amount);
  no log line contains a title, amount, `txn_id`, or description. Traces: AC-7.

- **TC-AND-219-13 — Flaky-host / offline → stale cache then recovery.** Type: instrumented. Target:
  device (real network on/off toggling exercises arm64/API-34 OkHttp behavior the emulator does
  not). Preconditions: a prior successful list cached in Room. Steps: disable connectivity; open
  screen; then re-enable and pull-to-refresh. Expected: while offline, cached rows render with
  `StaleBanner` and `isStale=true`; an offline *search* (network-only) shows the error/offline
  state, not stale partial results; on reconnect, pull-to-refresh re-fetches and clears the banner.
  Traces: AC-4.

- **TC-AND-219-14 — Accessibility (TalkBack, touch targets, RTL, font scale).** Type: Compose-UI /
  instrumented. Target: emu (logic) + device (real TalkBack pass). Preconditions: rows + search +
  empty/error states. Steps: assert each row is a merged semantics node describing title, amount,
  date, status; status badge has a content description (e.g. "Status: Refunded") and is not
  color-only; clear icon has a `contentDescription`; touch targets ≥ 48dp; verify largest font
  scale and RTL layout do not clip. Run a real TalkBack sweep on the device. Traces: AC-1, AC-4.

- **TC-AND-219-15 — Coverage gate.** Type: unit. Target: JVM. Steps: run the ViewModel + data-layer
  suite with coverage. Expected: ViewModel + list/mapping logic ≥ 85% line coverage; build fails if
  below. Traces: AC-8.

### Coverage matrix

| Acceptance criterion | Covered by |
| --- | --- |
| AC-1 (render newest-first, fields, badge) | TC-01, TC-02, TC-03, TC-14 |
| AC-2 (paging / single capped page) | TC-02 (and TC-01) |
| AC-3 (debounced server search, IME submit, clear restores) | TC-04, TC-05, TC-06 |
| AC-4 (state coverage: empty/empty-search/error/stale) | TC-07, TC-08, TC-13 |
| AC-5 (query survives config change & process death) | TC-10 |
| AC-6 (row tap nav event; persistent 401 → reauth) | TC-09, TC-11 |
| AC-7 (no PII in logs/telemetry) | TC-12 |
| AC-8 (tests pass; coverage ≥ 85%) | TC-15 (plus all unit/contract TCs) |
