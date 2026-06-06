---
id: AND-356
title: Syndicates
milestone: M7
epic: E46
priority: P2
size: M
status: draft
depends_on:
  - AND-027
blocks:
  - AND-357
  - AND-361
---

# AND-356 — Syndicates

## 1. Overview & Goal

Syndicates are member-owned collectives in TestLogon that pool revenue from member
creators and distribute it according to a configured revenue-split policy. A syndicate
exposes three read surfaces in the web reference app under `/ui/syndicates/*`: a
**feed** of syndicate activity, a **treasury** view of the shared balance and
ledger, and a **revenue-split** view of each member's allocation. This ticket ports
those read surfaces to the native Android app as a new `feature-syndicates` module.

The goal is a working, read-only **Syndicate overview** screen on Android: the user
can open a syndicate they belong to and see its feed, treasury summary, and
revenue-split breakdown, backed by Retrofit + Repository + a Hilt-injected
`StateFlow<SyndicateOverviewUiState>` ViewModel. Write actions (joining, proposing
splits, treasury payouts) and the open-licensing flow are explicitly out of scope and
are owned by downstream tickets (AND-357 open licensing; later E46 write tickets).

This is a **P2 Feature**, sized **M**: three DTO clusters and three sub-views, no
media/WebRTC, no upload, but real paging on the feed and money formatting in the
treasury/split views. It depends only on `AuthApi` (AND-027) for the authenticated
cookie session and CSRF wiring; it consumes the same `core-network` / `core-data` /
`core-ui` plumbing as every other feature module.

## 2. Context & References

- **Web reference**: `frontend/src/api/endpoints/syndicates.ts` (feed/treasury/
  revenue-split calls), shared types in `frontend/src/api/types.ts`. The web app's
  `/ui/syndicates/:id` overview page and its `treasury` and `revenue-split` tabs are
  the visual and behavioral source of truth.
- **OpenAPI**: `http://18.222.237.167:8000/openapi.json` — confirm exact path
  parameters, query params, and response field names for the `/ui/syndicates/*`
  operations before finalizing DTOs. The dev host is plaintext HTTP and unreliable;
  design for ~20s timeouts and stale/offline UI (see §7).
- **Dependency AND-027 (AuthApi)**: provides the authenticated cookie session,
  persistent cookie jar, `ui_csrf` → `X-CSRF-Token` echo, and the single
  `POST /ui/session/refresh`-then-retry on 401. Syndicate calls ride that session;
  this ticket adds **no** auth logic.
- **Sibling tickets**: AND-353/354 (orgs), AND-355 (groups) — same E46 pattern; reuse
  their member-row and role-badge composables from `core-ui` where they exist.
  AND-361 owns the shared Orgs/syndicates ViewModel state extraction and AND-362 owns
  the consolidated repo+UI test suite; this ticket ships its own focused tests too.
- **Stack**: Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Retrofit 2.11 / OkHttp
  4.12 / Moshi 1.15, Room 2.6 (cache), Paging 3, Coil. minSdk 24 / target 35, JDK 17.
- **Layering**: `app → feature-syndicates → core-network, core-model, core-ui,
  core-data, core-testing`. ViewModels expose `StateFlow<UiState>`; network results
  are wrapped in the typed `ApiResult<T>`.

## 3. Functional Requirements

FR-1 — **Entry & navigation.** A `syndicate/{syndicateId}` Navigation-Compose route
opens the overview. `syndicateId` is a non-empty `String`. Entry points are deep
links from org/profile surfaces; this ticket only registers the route and a stub
"My syndicates" list entry behind a known id for manual testing.

FR-2 — **Overview tabs.** The overview hosts three tabs — **Feed**, **Treasury**,
**Revenue split** — within a single `SyndicateOverviewScreen`. The header shows
syndicate name, member count, and the current user's role badge.

FR-3 — **Feed.** A reverse-chronological, **Paging 3** list of `SyndicateFeedItem`
(post/announcement/treasury-event/member-event). Each row shows actor, timestamp
(relative), and a typed body. Pull-to-refresh re-fetches page 1. Read-only: no
compose box, no reactions.

FR-4 — **Treasury.** Shows balance (formatted currency), pending-in / pending-out
totals, and a paged ledger of `TreasuryEntry` (credit/debit, amount, memo, timestamp,
counterparty). Amounts render with the syndicate's currency code. Read-only.

FR-5 — **Revenue split.** Shows the active split policy: split mode
(`equal | weighted | tiered`), effective date, and a list of `RevenueSplitMember`
rows (member, share basis-points, computed percentage, last-period payout). The
percentages must sum to 100% (±0.01% tolerance); if the API total deviates, show a
non-blocking "split mismatch" banner. Read-only.

FR-6 — **States.** Every tab independently renders Loading / Content / Empty / Error
/ Offline-stale. A successful fetch is cached (Room) and re-shown with a "stale"
indicator when offline or when a refresh fails.

FR-7 — **Authz fallback.** If the API returns 403 (not a member), the screen shows a
"You are not a member of this syndicate" empty-state, not a generic error.

FR-8 (**acceptance anchor**) — **Syndicate overview renders.** Given a member user and
a valid `syndicateId`, the overview screen loads and renders the header plus all three
tabs with live data, with no crash and no unhandled error.

## 4. Technical Design

New module `feature-syndicates` (namespace `com.testlogon.android.feature.syndicates`).
Package layout:

```
com.testlogon.android.feature.syndicates
 ├─ data/   SyndicateApi, SyndicateRepository(+Impl), dto/, SyndicateFeedPagingSource,
 │          TreasuryLedgerPagingSource, cache/ (Room entities + DAO)
 ├─ domain/ models (SyndicateOverview, SyndicateFeedItem, TreasurySummary,
 │          TreasuryEntry, RevenueSplitPolicy, RevenueSplitMember)
 ├─ ui/     SyndicateOverviewScreen, FeedTab, TreasuryTab, RevenueSplitTab,
 │          SyndicateOverviewViewModel, SyndicateOverviewUiState
 └─ di/     SyndicateModule (Hilt)
```

ViewModel:

```kotlin
@HiltViewModel
class SyndicateOverviewViewModel @Inject constructor(
    private val repo: SyndicateRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {
    private val syndicateId: String = checkNotNull(savedStateHandle["syndicateId"])

    val uiState: StateFlow<SyndicateOverviewUiState> = /* see §6 */

    val feed: Flow<PagingData<SyndicateFeedItem>> =
        repo.feedPager(syndicateId).cachedIn(viewModelScope)
    val ledger: Flow<PagingData<TreasuryEntry>> =
        repo.ledgerPager(syndicateId).cachedIn(viewModelScope)

    fun refresh()                                  // re-fetches header + treasury + split
    fun selectTab(tab: SyndicateTab)
}

enum class SyndicateTab { FEED, TREASURY, REVENUE_SPLIT }
```

Repository:

```kotlin
interface SyndicateRepository {
    suspend fun getOverview(syndicateId: String): ApiResult<SyndicateOverview>
    suspend fun getTreasury(syndicateId: String): ApiResult<TreasurySummary>
    suspend fun getRevenueSplit(syndicateId: String): ApiResult<RevenueSplitPolicy>
    fun feedPager(syndicateId: String): Flow<PagingData<SyndicateFeedItem>>
    fun ledgerPager(syndicateId: String): Flow<PagingData<TreasuryEntry>>
    fun observeOverviewCache(syndicateId: String): Flow<SyndicateOverview?>
}
```

Header/treasury/split are single GETs cached in Room; feed and ledger use Paging 3
`PagingSource`s with cursor or page tokens (see §5). The repo maps `ApiResult.Success`
into domain models and writes the overview/treasury/split snapshots into the cache
table on each success so offline-stale (FR-6) can be served.

Compose: `SyndicateOverviewScreen(syndicateId, onBack)` collects `uiState` with
`collectAsStateWithLifecycle()`, renders a `Scaffold` + `TabRow`, and hosts the three
tab composables. `FeedTab`/`TreasuryTab` use `LazyColumn` + `items(lazyPagingItems)`
with append/refresh state handling. Currency formatting via a `core-ui`
`MoneyFormatter(currencyCode)` (java `NumberFormat.getCurrencyInstance` keyed by ISO
4217). Relative timestamps via existing `core-ui` `RelativeTime`.

Hilt: `SyndicateModule` provides the `SyndicateApi` from the shared authenticated
Retrofit instance (from `core-network`) and binds `SyndicateRepositoryImpl`.

## 5. API Contract

All paths are under the authenticated `/ui` surface and ride the cookie session +
`X-CSRF-Token`. **Confirm exact shapes against `/openapi.json` before merge** — the
field names below reflect the web `syndicates.ts` reference and may need adjustment.

```kotlin
interface SyndicateApi {
    @GET("ui/syndicates/{id}")
    suspend fun getSyndicate(@Path("id") id: String): Response<SyndicateOverviewDto>

    @GET("ui/syndicates/{id}/feed")
    suspend fun getFeed(
        @Path("id") id: String,
        @Query("cursor") cursor: String?,
        @Query("limit") limit: Int = 20,
    ): Response<PageDto<SyndicateFeedItemDto>>

    @GET("ui/syndicates/{id}/treasury")
    suspend fun getTreasury(@Path("id") id: String): Response<TreasurySummaryDto>

    @GET("ui/syndicates/{id}/treasury/ledger")
    suspend fun getLedger(
        @Path("id") id: String,
        @Query("cursor") cursor: String?,
        @Query("limit") limit: Int = 20,
    ): Response<PageDto<TreasuryEntryDto>>

    @GET("ui/syndicates/{id}/revenue-split")
    suspend fun getRevenueSplit(@Path("id") id: String): Response<RevenueSplitPolicyDto>
}
```

Representative responses:

```json
// GET /ui/syndicates/{id}
{
  "id": "syn_8fa2",
  "name": "Aurora Collective",
  "member_count": 12,
  "viewer_role": "member",          // owner | admin | member
  "currency": "USD"
}
```
```json
// GET /ui/syndicates/{id}/feed?limit=20
{
  "items": [
    {"id":"f_01","type":"announcement","actor":{"id":"u_1","display_name":"Mara"},
     "created_at":"2026-06-04T18:22:09Z","body":"June payout posted."},
    {"id":"f_02","type":"treasury_event","actor":null,
     "created_at":"2026-06-04T18:20:00Z","body":"Credit +$1,204.50 from royalties"}
  ],
  "next_cursor": "eyJvIjoyMH0="
}
```
```json
// GET /ui/syndicates/{id}/treasury
{
  "currency":"USD","balance_minor":4820150,
  "pending_in_minor":120400,"pending_out_minor":50000,
  "as_of":"2026-06-05T00:00:00Z"
}
```
```json
// GET /ui/syndicates/{id}/revenue-split
{
  "mode":"weighted","effective_at":"2026-06-01T00:00:00Z","currency":"USD",
  "members":[
    {"member_id":"u_1","display_name":"Mara","share_bps":4000,
     "last_payout_minor":160200},
    {"member_id":"u_2","display_name":"Devin","share_bps":3500,
     "last_payout_minor":140100},
    {"member_id":"u_3","display_name":"Priya","share_bps":2500,
     "last_payout_minor":100050}
  ],
  "total_bps":10000
}
```

Money is integer **minor units** (`*_minor`) + a `currency` ISO code; the app converts
to major units only at the formatting boundary. `share_bps` is basis points
(10000 = 100%). `PageDto<T>` = `{ items: List<T>, next_cursor: String? }`. Errors use
FastAPI `detail` (string | `[{msg}]` | `{code,...}`) mapped by `core-network`'s shared
error mapper into `ApiResult.Failure`.

## 6. Data & State Management

UI state:

```kotlin
data class SyndicateOverviewUiState(
    val selectedTab: SyndicateTab = SyndicateTab.FEED,
    val header: HeaderState = HeaderState.Loading,
    val treasury: TabContent<TreasurySummary> = TabContent.Loading,
    val split: TabContent<RevenueSplitPolicy> = TabContent.Loading,
    val isStale: Boolean = false,         // served from cache while offline/refresh-failed
)

sealed interface HeaderState {
    data object Loading : HeaderState
    data class Ready(val syndicate: SyndicateOverview) : HeaderState
    data object NotAMember : HeaderState  // 403
    data class Error(val message: String) : HeaderState
}

sealed interface TabContent<out T> {
    data object Loading : TabContent<Nothing>
    data class Content<T>(val value: T) : TabContent<T>
    data object Empty : TabContent<Nothing>
    data class Error(val message: String) : TabContent<Nothing>
}
```

`uiState` is built with `stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000),
SyndicateOverviewUiState())`. On init and on `refresh()`, the VM launches the three
single GETs concurrently (`coroutineScope { async {} }`) and folds each `ApiResult`
into the corresponding state slot. Feed and ledger paging are independent
`Flow<PagingData<…>>` exposed directly and collected by the tabs.

Caching (Room, in `feature-syndicates/data/cache`): one `syndicate_overview` snapshot
table keyed by `syndicateId` storing the serialized header + treasury + split JSON +
`fetched_at`. On a failed refresh while a snapshot exists, the VM emits the cached
value with `isStale = true`. Feed/ledger pages are **not** persisted across launches
in this ticket (in-memory Paging only); a `RemoteMediator` is deferred to AND-361/362
if needed. `revenue-split` totals are validated client-side: if `total_bps != 10000`
(or the summed member bps deviates >1 bp), set a `splitMismatch` flag surfaced as a
banner (FR-5).

## 7. Error Handling & Resilience

- **Timeouts**: rely on `core-network`'s ~20s OkHttp call timeout; all five operations
  are idempotent GETs, so the shared **bounded backoff retry** (e.g. up to 2 retries,
  jittered) applies. No retries are added here beyond that policy.
- **401**: handled transparently by the AND-027 interceptor (single
  `POST /ui/session/refresh` then retry); the VM never sees a recoverable 401.
- **403**: mapped to `HeaderState.NotAMember` and per-tab `Empty` with the
  not-a-member copy (FR-7) — never a red error.
- **Network failure / 5xx after retries**: if a cache snapshot exists, show cached
  content with the stale indicator (FR-6); otherwise show per-tab `Error` with a
  Retry action that calls `refresh()`.
- **Paging append errors**: surfaced via `LazyPagingItems.loadState.append` as an
  inline retry footer; refresh errors via `loadState.refresh` as a full-tab error with
  retry. The dev host being unreliable, append failures must never crash or clear the
  already-loaded list.
- **Malformed money / missing currency**: default to `USD` formatting and log a
  warning; never throw from the formatter.

## 8. Security & Privacy

- All requests are authenticated through the existing cookie jar + `X-CSRF-Token`
  echo from AND-027; this module stores **no** credentials and adds no new auth state.
- The dev backend is **plaintext HTTP**; the network security config already permits
  cleartext for the dev host only. No syndicate data may be written to external/shared
  storage. The Room cache lives in app-private storage; no financial figures are placed
  in logs (see §10).
- Treasury and revenue-split figures are sensitive financial data: exclude this
  screen's content from screenshots is **not** required by the ticket, but ledger/split
  rows must not be included in crash-report breadcrumbs or analytics payloads.
- No PII beyond display names is rendered; member ids are opaque and not logged.

## 9. Accessibility & i18n

- All tabs, rows, and the role badge expose `contentDescription` / merged semantics;
  the `TabRow` uses Material 3 tab semantics with selected-state announced.
- Money is formatted with locale- and currency-aware `NumberFormat`; never hand-concat
  a `$`. Percentages use the locale's percent format. Relative timestamps use the
  shared localized `RelativeTime` helper.
- All user-facing strings (tab labels, empty/error/stale/not-a-member copy, "split
  mismatch" banner) live in `feature-syndicates/src/main/res/values/strings.xml`; no
  hardcoded literals in composables. Layouts tolerate RTL and font scaling up to 200%
  (rows wrap, no fixed heights that clip text).
- Touch targets ≥48dp; color is not the sole signal for credit vs debit (use +/- and
  an icon).

## 10. Telemetry & Logging

- Emit screen-view `syndicate_overview_opened` (`syndicate_id` hashed) and tab-select
  `syndicate_tab_selected` (`tab`) via the shared analytics interface in `core-data`.
- Emit `syndicate_load_error` with `endpoint`, `http_status`, and mapped error code on
  failures (no response bodies, no amounts).
- Debug-only `Timber` logs for request/response **status and timing**; never log
  `*_minor` amounts, balances, payouts, or full ledger/feed bodies.
- One counter `syndicate_split_mismatch` when client-side bps validation fails, to
  catch backend split drift.

## 11. Testing Strategy

- **Repository (unit, MockWebServer in `core-testing`)**: each of the five endpoints —
  success maps to domain model; FastAPI `detail` variants map to `ApiResult.Failure`;
  403 surfaces as not-a-member; `*_minor` → major conversion is exact; `next_cursor`
  is threaded; cache snapshot is written on success and served (stale) on subsequent
  failure.
- **Paging (unit)**: `SyndicateFeedPagingSource` / `TreasuryLedgerPagingSource` return
  correct `LoadResult.Page` keys, terminal page when `next_cursor == null`, and
  `LoadResult.Error` on failure without clearing prior pages.
- **ViewModel (unit, Turbine)**: init populates header/treasury/split slots; concurrent
  fold is correct; `refresh()` re-emits Loading→Content; offline path yields
  `isStale = true`; split-mismatch flag set when `total_bps != 10000`.
- **Compose UI (`createAndroidComposeRule`)**: overview renders header + three tabs;
  tab switching swaps content; empty/error/not-a-member/stale states render their copy;
  **the acceptance test asserts FR-8 — overview renders all three tabs with stubbed
  live data and no crash.**
- **Money/format (unit)**: `MoneyFormatter` for USD/EUR/JPY (zero-decimal) and a
  missing-currency fallback.

## 12. Dependencies & Sequencing

- **Hard dependency**: AND-027 (AuthApi / session endpoints) — required for the
  authenticated session, cookie jar, CSRF, and 401-refresh behavior. Also relies on
  the already-delivered `core-network`, `core-model`, `core-ui`, `core-data`,
  `core-testing` modules and the Hilt/Navigation baselines (AND-004 and app shell).
- **Blocks**: AND-357 (Syndicate open licensing — registers/lists against the
  syndicate established here) and AND-361 (Orgs/syndicates ViewModel state extraction;
  AND-362 consolidated tests build on these repos/VMs).
- **Soft reuse**: member-row, role-badge, and empty/error scaffolding from AND-353/354/
  355 if merged first; otherwise add minimal local versions and promote to `core-ui`
  later.
- **Sequencing**: land DTOs + `SyndicateApi` + repository (MockWebServer-tested) first,
  then paging sources, then ViewModel, then Compose tabs and the acceptance test.

## 13. Risks & Open Questions

- **OQ-1**: Exact `/ui/syndicates/*` paths, pagination scheme (cursor vs `page`/`offset`),
  and field names must be confirmed from `/openapi.json`; the contract in §5 is derived
  from the web reference and is provisional.
- **OQ-2**: Is `revenue-split` a single active policy or a history? This ticket renders
  the active policy only; history is deferred.
- **OQ-3**: Does the feed paginate by cursor or timestamp, and are treasury-event feed
  items duplicated in the ledger? If so, the feed renders them as activity, the ledger
  as the authoritative record — no dedup needed.
- **OQ-4**: Currency handling for multi-currency syndicates (one `currency` per
  syndicate is assumed). If ledger entries can carry mixed currencies, the treasury
  summary's single balance is ambiguous — flag back to backend.
- **Risk**: unreliable dev host makes manual verification flaky; mitigated by
  MockWebServer-driven tests for all acceptance-relevant paths.
- **Risk**: backend split totals may not sum to 10000 bps; handled non-blockingly via
  the mismatch banner + telemetry rather than failing the screen.

## 14. Acceptance Criteria

- AC-1 (**ticket acceptance**): With a member user and a valid `syndicateId`, opening
  `syndicate/{syndicateId}` renders the header (name, member count, role badge) and the
  Feed, Treasury, and Revenue-split tabs with live data, no crash, no unhandled error.
- AC-2: Feed and treasury ledger paginate (load page 2 on scroll) and surface inline
  append-retry on failure without clearing loaded items.
- AC-3: Treasury balance, pending in/out, and revenue-split payouts render from
  `*_minor` integers correctly formatted in the syndicate's currency.
- AC-4: Revenue-split member percentages derive from `share_bps`; a mismatch banner
  shows when `total_bps != 10000` (±1 bp).
- AC-5: 403 renders the not-a-member empty state, not a generic error.
- AC-6: Offline/refresh-failure with a prior snapshot shows cached content with a stale
  indicator; with no snapshot, shows a per-tab error with working Retry.
- AC-7: Endpoint request/verb/path/body shapes match §5 and are verified by
  MockWebServer tests; all string content is externalized to resources.

## 15. Definition of Done

- `feature-syndicates` module exists with the package layout in §4, wired into
  `settings.gradle.kts` and the `app` module, namespace
  `com.testlogon.android.feature.syndicates`.
- `SyndicateApi`, `SyndicateRepository(+Impl)`, the two Paging sources, the Room cache,
  the ViewModel, and the four composables are implemented and Hilt-wired.
- The `syndicate/{syndicateId}` route is registered with a stub entry for manual
  testing.
- Unit (repo/paging/VM/format) and Compose acceptance tests in §11 are green in CI;
  the FR-8/AC-1 acceptance test passes.
- ktlint/detekt clean; no hardcoded user-facing strings; no financial values in logs.
- All §14 acceptance criteria met; §13 open questions either resolved against
  `/openapi.json` or recorded as follow-ups on AND-357/AND-361.
- Code reviewed and merged to `android-port`.
