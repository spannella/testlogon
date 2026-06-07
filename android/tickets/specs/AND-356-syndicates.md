---
id: AND-356
title: Syndicates
milestone: M7
epic: E46
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
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
**feed** of syndicate posts, a **treasury** view of the shared balance and ledger, and
a **revenue-split** view of the active split config (mode + weighting; per-member payout
allocations are computed server-side at split execution, not on the config). This ticket
ports those read surfaces to the native Android app as a new `feature-syndicates` module.

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
- **Dependency AND-027 (AuthApi)**: provides the authenticated session, the
  persistent cookie jar, the `ui_csrf` → `X-CSRF-Token` echo, and the single
  `POST /ui/session/refresh`-then-retry on 401. Syndicate calls ride that session;
  this ticket adds **no** auth logic.
  - **CORRECTION (auth transport)**: the web client (`src/api/client.ts`) sends
    **three** auth signals, not just a cookie: `Authorization: Bearer <accessToken>`
    (from the auth store), the `X-CSRF-Token` header (value read from the `ui_csrf`
    cookie), and `credentials: "include"` (cookie jar). It also conditionally sends
    `X-IMPERSONATION-TOKEN` for staff impersonation (not used by this ticket). The
    OpenAPI operation params instead list `user_sub, X-SESSION-ID,
    X-IMPERSONATION-TOKEN`. AND-027 must therefore supply the Bearer token + CSRF +
    cookies as an OkHttp interceptor; whether the backend ultimately keys on the
    Bearer/cookie or on `X-SESSION-ID`/`user_sub` is an **open assumption** to confirm
    with AND-027 (see §16 Open assumptions). The 401 → `POST /ui/session/refresh` →
    single-retry behavior is **verified** in `src/api/client.ts`.
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
syndicate name, member count, and the current user's role badge. (The web reference
app's detail page actually hosts more tabs — Members, Plans, Revenue, Treasury,
Advertising, Open Licensing, plus admin-only Requests/Audit — so this is a deliberately
**reduced read-only subset**, not a 1:1 mirror; see §16.) The role badge is **derived**:
"admin" when `admin_user_id == current userId`, else "member" (the backend exposes no
`viewer_role` field; per-member roles come from `GET /ui/syndicates/{id}/members`).

FR-3 — **Feed.** A reverse-chronological, **Paging 3** list of syndicate **posts**
(`SyndicatePostOut`). Each row shows author (name/avatar), timestamp (relative, from
the integer-epoch `created_at`), and the post `text` (and optional `image_url`). The
backend feed returns plain posts only — there is **no** typed
post/announcement/treasury-event/member-event discriminator and no `body`/`actor`
field, so do not model those. Pull-to-refresh re-fetches page 1. Read-only: no compose
box, no reactions (reaction/comment/tip counts may be shown but are not interactive).

FR-4 — **Treasury.** Shows balance and **total deposited / total disbursed** (all from
`*_cents` integers), and a paged ledger of treasury entries
(`SyndicateTreasuryLedgerEntryOut`: `direction` credit|debit, `amount_cents`, `reason`,
`ts`, `counterparty_user_id`). The backend does **not** expose pending-in/pending-out
or an `as_of` field. Amounts render with the syndicate's `currency` code (lowercase ISO
in the API; normalize to upper for `NumberFormat`). Read-only.

FR-5 — **Revenue split.** Shows the active split **config** (`SplitConfigOut`): split
`mode` (`equal | weighted | performance` — **not** "tiered"), `platform_fee_bps`,
`performance_metric`/`performance_window_days` (for performance mode), `updated_at`,
`updated_by`, and — in `weighted` mode — the `weights_bps` map (user_id → basis points,
10000 = 100%). There is no per-member payout array on the config; the optional
`GET …/revenue-split/{id}/my-earnings` (`MemberEarningsOut`) provides the viewer's
earnings if shown. In `weighted` mode the displayed weights should sum to ~10000 bps; if
the summed `weights_bps` deviates >1 bp from 10000, show a non-blocking "split mismatch"
banner. In `equal`/`performance` mode `weights_bps` may be empty (no mismatch check).
Read-only.

FR-6 — **States.** Every tab independently renders Loading / Content / Empty / Error
/ Offline-stale. A successful fetch is cached (Room) and re-shown with a "stale"
indicator when offline or when a refresh fails.

FR-7 — **Authz fallback.** If the API returns 403, the screen shows a "You are not a
member of this syndicate" empty-state, not a generic error. **Note**: the feed
(`SyndicateFeedOut`) carries an `is_member` boolean and the profile carries one too, so
non-membership may surface as `is_member == false` (and reduced/empty content) rather
than an HTTP 403 on every endpoint. Treat **both** signals — an HTTP 403 *and* an
`is_member == false` response — as the not-a-member state. (Whether each of the five
endpoints actually returns 403 vs 200-with-`is_member:false` for non-members is an
**unverified assumption**; see §16.)

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
4217). **The API returns currency codes lowercase (e.g. `"usd"`); uppercase before
constructing the `Currency`/`NumberFormat`.** Money fields are integer **cents**
(`*_cents`), divided by 100 (or by the currency's fraction-digit count for zero-decimal
currencies such as JPY) at the formatting boundary. Relative timestamps come from
**integer epoch-seconds** fields (`created_at`, `ts`, `updated_at`), not ISO-8601
strings; convert via the existing `core-ui` `RelativeTime` (seconds → millis ×1000).

Hilt: `SyndicateModule` provides the `SyndicateApi` from the shared authenticated
Retrofit instance (from `core-network`) and binds `SyndicateRepositoryImpl`.

## 5. API Contract

All paths are under the authenticated `/ui` surface and ride the session described in
§2. **The paths and field names below have been verified against the OpenAPI index
and the web `syndicates*.ts` reference (2026-06-06 review); the original draft was
substantially wrong and is corrected here.** Key path corrections: feed, treasury, and
revenue-split do **not** live under `/ui/syndicates/{id}/...`; they live under
**distinct prefixes** — `/ui/syndicates/feed/{id}`, `/ui/syndicates/treasury/{id}`, and
`/ui/syndicates/revenue-split/{id}/config`. See §16 for the per-claim audit.

```kotlin
interface SyndicateApi {
    // Overview header. NOTE: this op has NO declared response schema in OpenAPI
    // (resp=200: with no body schema). Shape below is inferred from the web
    // `getSyndicate` usage (SyndicateOut) and is an UNVERIFIED assumption.
    @GET("ui/syndicates/{id}")
    suspend fun getSyndicate(@Path("id") id: String): Response<SyndicateOverviewDto>

    // Feed. Real path is /ui/syndicates/feed/{id}; envelope is SyndicateFeedOut
    // { posts, next_cursor, is_member } — NOT { items, next_cursor }.
    @GET("ui/syndicates/feed/{id}")
    suspend fun getFeed(
        @Path("id") id: String,
        @Query("cursor") cursor: String?,
        @Query("limit") limit: Int = 20,
    ): Response<SyndicateFeedDto>

    // Treasury balance. Real path is /ui/syndicates/treasury/{id};
    // resp = SyndicateTreasuryBalanceOut.
    @GET("ui/syndicates/treasury/{id}")
    suspend fun getTreasury(@Path("id") id: String): Response<TreasuryBalanceDto>

    // Treasury ledger. Real path is /ui/syndicates/treasury/{id}/ledger;
    // envelope is SyndicateTreasuryLedgerOut { entries, cursor, has_more }.
    @GET("ui/syndicates/treasury/{id}/ledger")
    suspend fun getLedger(
        @Path("id") id: String,
        @Query("cursor") cursor: String?,
        @Query("limit") limit: Int = 20,
    ): Response<TreasuryLedgerDto>

    // Revenue-split config. Real path is /ui/syndicates/revenue-split/{id}/config;
    // resp = SplitConfigOut. There is NO per-member share/payout array here.
    @GET("ui/syndicates/revenue-split/{id}/config")
    suspend fun getRevenueSplit(@Path("id") id: String): Response<SplitConfigDto>

    // OPTIONAL (per-viewer earnings, if the split tab shows the viewer's payout):
    // GET /ui/syndicates/revenue-split/{id}/my-earnings -> MemberEarningsOut.
}
```

Representative responses (verified field shapes):

```json
// GET /ui/syndicates/{id}  — NO OpenAPI schema; inferred from web SyndicateOut.
// The web header reads: name, description, status, member_count, admin_user_id.
// There is NO `viewer_role`/`currency`/`id` field on the header in the web code;
// role is derived (isAdmin = admin_user_id == current userId) and per-member roles
// come from GET /ui/syndicates/{id}/members (SyndicateMemberOut.role: admin|member).
{
  "syndicate_id": "syn_8fa2",
  "name": "Aurora Collective",
  "description": "…",
  "status": "active",
  "member_count": 12,
  "admin_user_id": "u_1"
}
```
```json
// GET /ui/syndicates/feed/{id}?limit=20  — SyndicateFeedOut
// Items are POSTS (SyndicatePostOut). There is NO post `type`
// (announcement/treasury_event/...) and NO `body`/`actor` field; the text field is
// `text`, timestamps are integer epoch seconds.
{
  "posts": [
    {"post_id":"p_01","author_id":"u_1","author_name":"Mara","author_avatar":"",
     "text":"June payout posted.","image_url":"","syndicate_id":"syn_8fa2",
     "visibility":"public","created_at":1717525329,"comment_count":0,
     "reaction_counts":{},"tip_total_cents":0}
  ],
  "next_cursor": "eyJvIjoyMH0=",
  "is_member": true
}
```
```json
// GET /ui/syndicates/treasury/{id}  — SyndicateTreasuryBalanceOut
// Money is `*_cents`; there is NO pending_in/pending_out and NO `as_of` ISO string.
// `updated_at` is integer epoch seconds. `currency` defaults to "usd" (lowercase).
{
  "syndicate_id":"syn_8fa2","currency":"usd","balance_cents":4820150,
  "total_deposited_cents":12044050,"total_disbursed_cents":7223900,
  "updated_at":1717545600
}
```
```json
// GET /ui/syndicates/treasury/{id}/ledger  — SyndicateTreasuryLedgerOut
// Envelope is { entries, cursor, has_more }. Entry money is `amount_cents`,
// memo is `reason`, timestamp is `ts` (epoch seconds), direction is credit|debit.
{
  "entries":[
    {"entry_id":"e_01","direction":"credit","amount_cents":120450,"currency":"usd",
     "actor_user_id":"u_1","counterparty_user_id":"","reason":"royalties","ts":1717525200}
  ],
  "cursor":"eyJvIjoyMH0=","has_more":true
}
```
```json
// GET /ui/syndicates/revenue-split/{id}/config  — SplitConfigOut
// mode is equal|weighted|performance (NOT "tiered"). Per-member shares are a
// `weights_bps` MAP keyed by user_id (only populated when mode == weighted), NOT a
// member array. There is NO `effective_at`/`currency`/`total_bps`/per-member
// `last_payout` here. `updated_at` is integer epoch seconds.
{
  "mode":"weighted","platform_fee_bps":1500,
  "weights_bps":{"u_1":4000,"u_2":3500,"u_3":2500},
  "performance_metric":"","performance_window_days":30,
  "updated_at":1717200000,"updated_by":"u_1"
}
```

Money is integer **cents** (`*_cents`, not `*_minor`) + a `currency` code (often
lowercase ISO, e.g. `"usd"`); the app converts to major units only at the formatting
boundary (web divides by 100). `weights_bps` values are basis points (10000 = 100%) and
sum to ~10000 only in `weighted` mode; in `equal`/`performance` mode the map may be
empty (split is computed server-side at execution time). The feed envelope is
`{ posts, next_cursor, is_member }`; the ledger envelope is
`{ entries, cursor, has_more }` — **these two paging envelopes differ from each other**,
so do not share one `PageDto<T>`. Errors use FastAPI `detail`
(string | `[{msg}]` | `{code,...}`); validation failures return **422
HTTPValidationError** (`{ "detail": [{ "loc":[…], "msg":…, "type":… }] }`), mapped by
`core-network`'s shared error mapper into `ApiResult.Failure`.

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
if needed. `revenue-split` totals are validated client-side only in **`weighted`** mode: sum the
`weights_bps` map values and if the sum deviates >1 bp from 10000, set a `splitMismatch`
flag surfaced as a banner (FR-5). (The backend has no `total_bps` field; the earlier
draft's `total_bps != 10000` check was based on a non-existent field.) In
`equal`/`performance` mode skip the check (`weights_bps` may be empty).

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
  403/`is_member:false` surfaces as not-a-member; `*_cents` → major conversion is exact;
  the cursor token is threaded (feed `next_cursor`; ledger `cursor`+`has_more`); cache
  snapshot is written on success and served (stale) on subsequent failure.
- **Paging (unit)**: `SyndicateFeedPagingSource` / `TreasuryLedgerPagingSource` return
  correct `LoadResult.Page` keys, terminal page when the feed's `next_cursor == null`
  (resp. when the ledger's `has_more == false`), and `LoadResult.Error` on failure
  without clearing prior pages.
- **ViewModel (unit, Turbine)**: init populates header/treasury/split slots; concurrent
  fold is correct; `refresh()` re-emits Loading→Content; offline path yields
  `isStale = true`; split-mismatch flag set when summed `weights_bps` deviates >1 bp from 10000 in
  `weighted` mode.
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

- **OQ-1 (RESOLVED in 2026-06-06 review)**: `/ui/syndicates/*` paths, the cursor-based
  pagination scheme, and field names are now confirmed against the OpenAPI index/spec
  and the web reference (see §5 and §16). The remaining unknowns are the overview-header
  shape (overview GET has no OpenAPI response schema) and the exact auth-header keying —
  both tracked as Open assumptions in §16.
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
- AC-3: Treasury balance, total deposited/disbursed, and ledger amounts render from
  `*_cents` integers correctly formatted in the syndicate's currency (currency code
  upper-cased; zero-decimal currencies handled).
- AC-4: In `weighted` mode, revenue-split member percentages derive from the
  `weights_bps` map; a mismatch banner shows when the summed `weights_bps` deviates >1 bp
  from 10000. In `equal`/`performance` mode no mismatch check runs.
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer. Sources are the
OpenAPI index (`reference/openapi.index.txt`), the OpenAPI spec
(`reference/openapi.pretty.json`, `components.schemas.<Name>`), or frontend files under
`reference/src/`. Android framework choices are labeled "framework ref".

1. **Overview path is `GET /ui/syndicates/{id}`.** VERDICT: Verified (path).
   SOURCE: OpenAPI `GET /ui/syndicates/{syndicate_id}` (op `get_syndicate_…`); frontend
   `src/api/endpoints/syndicates.ts: getSyndicate`.
2. **Overview response shape (`id`, `name`, `member_count`, `viewer_role`,
   `currency`).** VERDICT: Corrected → Unverified-assumption. SOURCE: OpenAPI
   `GET /ui/syndicates/{syndicate_id}` declares **no response schema** (`resp=200:` with
   no body); the web `getSyndicate` is typed `SyndicateOut`, a type **imported but not
   defined** in `src/api/types.ts` (only referenced in `src/api/endpoints/syndicates.ts`).
   The web detail page (`src/pages/syndicates/SyndicateDetailPage.tsx`) reads `.name`,
   `.description`, `.status`, `.member_count`, `.admin_user_id` — there is **no
   `viewer_role`/`currency`/`id`**. Corrected the header DTO to those fields; the exact
   shape remains an open assumption.
3. **Role badge values `owner | admin | member`.** VERDICT: Corrected. SOURCE:
   `src/pages/syndicates/SyndicateDetailPage.tsx` derives `isAdmin = syndicate.admin_user_id
   === userId`; per-member roles come from `SyndicateMemberOut.role` (default `"member"`,
   else `"admin"`) — OpenAPI `components.schemas.SyndicateMemberOut`. There is **no
   "owner"** role and no `viewer_role` field. Corrected to admin/member with derived badge.
4. **Feed path is `GET /ui/syndicates/{id}/feed`.** VERDICT: Corrected. SOURCE: real path
   is `GET /ui/syndicates/feed/{syndicate_id}` (OpenAPI op `get_feed_…`; frontend
   `src/api/endpoints/syndicateFeed.ts: getSyndicateFeed`).
5. **Feed envelope `{ items, next_cursor }`.** VERDICT: Corrected. SOURCE:
   `components.schemas.SyndicateFeedOut` = `{ posts: SyndicatePostOut[], next_cursor:
   string|null, is_member: bool }`; frontend `src/api/types.ts: SyndicateFeed`. Envelope
   field is `posts`, not `items`.
6. **Feed items are typed `post|announcement|treasury_event|member_event` with
   `actor`/`body`/ISO `created_at`.** VERDICT: Corrected. SOURCE:
   `components.schemas.SyndicatePostOut` — fields are `post_id`, `author_id`,
   `author_name`, `author_avatar`, `text`, `image_url`, `created_at` (integer epoch),
   `comment_count`, `reaction_counts`, `tip_total_cents`, `visibility`, `syndicate_id`.
   No `type`/`actor`/`body`. Corrected feed model to plain posts.
7. **Treasury path is `GET /ui/syndicates/{id}/treasury`.** VERDICT: Corrected. SOURCE:
   real path is `GET /ui/syndicates/treasury/{syndicate_id}` (OpenAPI op `get_balance_…`;
   frontend `src/api/endpoints/syndicateTreasury.ts: getTreasuryBalance`).
8. **Treasury fields `balance_minor`, `pending_in_minor`, `pending_out_minor`, `as_of`.**
   VERDICT: Corrected. SOURCE: `components.schemas.SyndicateTreasuryBalanceOut` =
   `balance_cents`, `currency`, `syndicate_id`, `total_deposited_cents`,
   `total_disbursed_cents`, `updated_at` (int epoch). No pending fields, no `as_of`;
   money suffix is `_cents` not `_minor`. Web `src/pages/syndicates/SyndicateTreasuryTab.tsx`
   formats via `cents / 100`.
9. **Ledger path is `GET /ui/syndicates/{id}/treasury/ledger`.** VERDICT: Corrected.
   SOURCE: real path is `GET /ui/syndicates/treasury/{syndicate_id}/ledger` (OpenAPI op
   `list_ledger_…`; frontend `src/api/endpoints/syndicateTreasury.ts: getTreasuryLedger`).
10. **Ledger envelope `{ items, next_cursor }` and entry fields
    `amount/memo/timestamp/counterparty`.** VERDICT: Corrected. SOURCE:
    `components.schemas.SyndicateTreasuryLedgerOut` = `{ entries, cursor, has_more }`;
    `components.schemas.SyndicateTreasuryLedgerEntryOut` = `entry_id`, `direction`
    (credit|debit), `amount_cents`, `currency`, `actor_user_id`, `counterparty_user_id`,
    `reason`, `ts` (int epoch). Memo→`reason`, timestamp→`ts`, paging via `cursor`+`has_more`.
11. **Revenue-split path is `GET /ui/syndicates/{id}/revenue-split`.** VERDICT: Corrected.
    SOURCE: real path is `GET /ui/syndicates/revenue-split/{syndicate_id}/config` (OpenAPI
    op `get_config_…revenue_split…`; frontend
    `src/api/endpoints/syndicateRevenueSplit.ts: getSplitConfig`).
12. **Split response: `mode` ∈ `equal|weighted|tiered`, `effective_at`, `currency`,
    `members[]` with `share_bps`/`last_payout_minor`, `total_bps`.** VERDICT: Corrected.
    SOURCE: `components.schemas.SplitConfigOut` = `mode` (default `equal`),
    `platform_fee_bps` (default 1500), `weights_bps` (map user_id→int), `performance_metric`,
    `performance_window_days`, `updated_at`, `updated_by`; frontend `src/api/types.ts:
    SplitConfig` + `SplitMode = "equal" | "weighted" | "performance"`. No `tiered`, no
    `effective_at`, no `total_bps`, no per-member array/`last_payout` on the config.
    Per-member payout data lives in `MemberEarningsOut` via `GET …/revenue-split/{id}/my-earnings`.
13. **Money is integer minor units, app converts at the formatting boundary.** VERDICT:
    Verified (concept) / Corrected (naming). SOURCE: all money fields are `*_cents`
    integers (schemas above); `src/pages/syndicates/SyndicateTreasuryTab.tsx` divides by
    100. Conversion-at-boundary is correct; field naming corrected `_minor`→`_cents`.
14. **`weights_bps`/share are basis points (10000 = 100%).** VERDICT: Verified. SOURCE:
    `src/api/types.ts` comment "percentages are integer basis points (10000 = 100%)";
    `SplitConfigOut.weights_bps` integers, `SplitDistributionOut.percentage_bps`.
15. **Currency code is ISO and may be lowercase.** VERDICT: Verified. SOURCE:
    `SyndicateTreasuryBalanceOut.currency` and `SplitExecutionOut.currency` default
    `"usd"` (lowercase) — must upper-case for `java.util.Currency`/`NumberFormat`.
16. **Auth = cookie session + `X-CSRF-Token` echo only.** VERDICT: Corrected. SOURCE:
    `src/api/client.ts` sends `Authorization: Bearer <accessToken>` + `X-CSRF-Token`
    (from `ui_csrf` cookie) + `credentials: "include"` + optional `X-IMPERSONATION-TOKEN`.
    OpenAPI params list `user_sub, X-SESSION-ID, X-IMPERSONATION-TOKEN`. Corrected to a
    Bearer+CSRF+cookie interceptor (owned by AND-027); exact server keying is an open
    assumption (see below).
17. **401 → single `POST /ui/session/refresh` then retry.** VERDICT: Verified. SOURCE:
    `src/api/client.ts` `refreshSession()` + the de-duped `refreshPromise` + single retry
    in `api()`.
18. **FastAPI error `detail` shapes (string | `[{msg}]` | `{code,...}`); 422
    HTTPValidationError on validation.** VERDICT: Verified. SOURCE:
    `src/api/client.ts: normalizeErrorDetail`; every syndicate op in the OpenAPI index
    lists `resp=...;422:HTTPValidationError`; `components.schemas.HTTPValidationError` /
    `ValidationError` (`{detail:[{loc,msg,type}]}`).
19. **Paging 3 + Repository + Hilt + StateFlow + Compose/Material 3 stack.** VERDICT:
    Unverified-assumption (framework ref — sound but project-internal, no source in this
    repo). SOURCE: framework ref — Paging 3, Hilt, Compose, `collectAsStateWithLifecycle`,
    `cachedIn(viewModelScope)` are standard AndroidX patterns; the `core-network`/`core-ui`
    helpers (`ApiResult`, `MoneyFormatter`, `RelativeTime`) are assumed from sibling
    tickets and not present in this reference repo.

### Corrections made
- Auth (§2): added Bearer-token + CSRF + cookie transport; flagged server keying as open.
- §5 paths: feed `/ui/syndicates/feed/{id}`, treasury `/ui/syndicates/treasury/{id}`,
  ledger `/ui/syndicates/treasury/{id}/ledger`, split `/ui/syndicates/revenue-split/{id}/config`.
- §5 envelopes: feed `{posts,next_cursor,is_member}`; ledger `{entries,cursor,has_more}`
  (no shared `PageDto`).
- §5/§3/§4 money: `*_minor` → `*_cents`; removed non-existent treasury `pending_in/out`
  and `as_of`; added `total_deposited_cents`/`total_disbursed_cents`.
- §3/§4/§5 feed: removed typed `type`/`actor`/`body`; modeled plain `SyndicatePostOut`
  (`text`, epoch `created_at`).
- §3/§5/§6/§11/AC-4: split `mode` `tiered`→`performance`; removed `total_bps`/`effective_at`/
  per-member-`last_payout`; mismatch check now sums `weights_bps` in `weighted` mode only.
- §3/§4 role: badge derived from `admin_user_id`/`SyndicateMemberOut.role`; removed
  invented `viewer_role` and "owner".
- §4: timestamps are integer epoch-seconds (×1000 for millis); currency upper-cased.
- §13 OQ-1 marked resolved.

### Open assumptions
- **Overview header DTO** — overview GET has no OpenAPI response schema and `SyndicateOut`
  is undefined in the reference `types.ts`; header fields inferred from page usage. Confirm
  exact JSON against a live `GET /ui/syndicates/{id}` or the backend model.
- **Auth header keying** — web sends Bearer+CSRF+cookies; OpenAPI params name
  `user_sub`/`X-SESSION-ID`. Which the server actually authenticates on (and whether the
  Android client must send `X-SESSION-ID`/`user_sub`) must be confirmed with AND-027.
- **Non-member behavior per endpoint** — unclear whether each of the five GETs returns
  HTTP 403 or 200-with-`is_member:false` for non-members (feed/profile expose `is_member`).
  Handle both; confirm against backend.
- **Ledger `limit`/`cursor` query params** — index lists `cursor,limit` for the ledger;
  the web `getTreasuryLedger` sends only `limit` (no cursor threading in the web client),
  so cursor-based append is assumed valid but not exercised by the reference app.
- **`core-network`/`core-ui` helpers** (`ApiResult`, `MoneyFormatter`, `RelativeTime`,
  the 20s timeout + backoff policy) — assumed delivered by prior tickets; not in this repo.

## 17. Test Plan

Test target legend: **JVM** = local JVM/Robolectric unit (no device); **emu35** =
headless AVD `test35` (x86_64, API 35); **A15** = physical Samsung Galaxy A15 5G
(SM-A156U, arm64-v8a, API 34). MockWebServer (MWS) runs in JVM/Robolectric. This ticket
is read-only networked UI with no camera/biometrics/WebRTC/push, so most cases run on
JVM or emu35; the physical device is used only for the real-network/offline and
ABI/API-34 confirmation cases.

- **TC-AND-356-01** — Type: contract/MockWebServer (JVM). Target: `SyndicateRepositoryImpl`
  + `SyndicateApi`. Preconditions: MWS queued with verified §5 bodies for the five GETs.
  Steps: call `getOverview`/`getTreasury`/`getRevenueSplit` and drain `feedPager`/`ledgerPager`
  first page. Expected: each returns `ApiResult.Success` mapped to the domain model with
  the **corrected paths** (`/ui/syndicates/feed/{id}`, `/ui/syndicates/treasury/{id}`,
  `/ui/syndicates/treasury/{id}/ledger`, `/ui/syndicates/revenue-split/{id}/config`),
  verified via recorded request path/verb=GET. Traces: AC-1, AC-7.

- **TC-AND-356-02** — Type: unit (JVM). Target: treasury/ledger/split mappers +
  `MoneyFormatter`. Preconditions: sample `balance_cents=4820150`, `currency="usd"`,
  ledger `amount_cents`, split `weights_bps`. Steps: map and format. Expected: `*_cents`
  → major via /100, currency upper-cased to USD ("$48,201.50"); JPY (zero-decimal) and
  EUR format correctly; missing/blank currency falls back to USD without throwing; epoch
  `ts`/`created_at` convert correctly. Traces: AC-3.

- **TC-AND-356-03** — Type: unit (JVM). Target: revenue-split mismatch logic. Preconditions:
  three `SplitConfigOut` fixtures — weighted summing 10000; weighted summing 9990;
  `equal` with empty `weights_bps`. Steps: run validation. Expected: no banner for the
  10000 case; `splitMismatch=true` for 9990 (>1 bp); no check/banner for `equal`. Confirms
  the corrected `weights_bps`-sum rule (not the removed `total_bps`). Traces: AC-4.

- **TC-AND-356-04** — Type: unit (JVM). Target: `SyndicateFeedPagingSource`. Preconditions:
  MWS returns `SyndicateFeedOut` page 1 with `next_cursor`, page 2 with `next_cursor=null`.
  Steps: load both. Expected: `LoadResult.Page` keyed on `next_cursor`; terminal page when
  `next_cursor==null`; envelope read from `posts` (not `items`). Traces: AC-2, AC-7.

- **TC-AND-356-05** — Type: unit (JVM). Target: `TreasuryLedgerPagingSource`. Preconditions:
  MWS returns `SyndicateTreasuryLedgerOut` with `entries`+`cursor`+`has_more=true`, then
  `has_more=false`. Steps: load both; second load fails. Expected: pages keyed on `cursor`,
  terminal when `has_more==false`, `LoadResult.Error` on failure without clearing prior
  pages (uses `entries`/`has_more`, not `items`/`next_cursor`). Traces: AC-2, AC-7.

- **TC-AND-356-06** — Type: contract/MockWebServer (JVM). Target: error mapping.
  Preconditions: MWS returns 422 `HTTPValidationError` (`{detail:[{loc,msg,type}]}`),
  a 500, and a string-`detail` 400. Steps: call each GET. Expected: each maps to
  `ApiResult.Failure` with the normalized message (mirrors `normalizeErrorDetail`); no
  crash, no leaked raw body. Traces: AC-6, AC-7.

- **TC-AND-356-07** — Type: contract/MockWebServer (JVM). Target: not-a-member handling.
  Preconditions: (a) overview GET returns 403; (b) feed GET returns 200 with
  `is_member=false` and empty `posts`. Steps: load overview in both setups. Expected:
  **both** yield `HeaderState.NotAMember` and per-tab not-a-member empty copy (not a red
  error), per the corrected dual-signal rule. Traces: AC-5.

- **TC-AND-356-08** — Type: unit (Turbine, JVM). Target: `SyndicateOverviewViewModel`.
  Preconditions: fake repo. Steps: collect `uiState` on init and after `refresh()`.
  Expected: concurrent fold populates header/treasury/split slots; `refresh()` re-emits
  Loading→Content; `selectTab` updates `selectedTab`. Traces: AC-1.

- **TC-AND-356-09** — Type: unit (Turbine, JVM). Target: offline-stale path. Preconditions:
  repo with a cached snapshot; refresh fails (IOException). Steps: seed cache, force a
  failed refresh. Expected: VM emits cached content with `isStale=true`; with **no**
  snapshot, emits per-tab `Error` exposing a working Retry that re-calls `refresh()`.
  Traces: AC-6.

- **TC-AND-356-10** — Type: Compose-UI (`createAndroidComposeRule`, emu35). Target:
  `SyndicateOverviewScreen` (acceptance). Preconditions: stubbed repo returns valid
  overview/feed/treasury/split. Steps: launch route `syndicate/{id}`, assert header
  (name, member count, derived role badge) + all three tabs render; switch tabs. Expected:
  header + Feed/Treasury/Revenue-split render with stubbed data, tab switch swaps content,
  **no crash / no unhandled error** (FR-8). Traces: AC-1.

- **TC-AND-356-11** — Type: Compose-UI (emu35). Target: per-tab state rendering +
  accessibility. Preconditions: stub Loading/Empty/Error/not-a-member/stale states.
  Steps: render each; run a semantics/contentDescription assertion pass; verify money uses
  `NumberFormat` (no hand-concatenated `$`), credit/debit shows +/- and icon (not color
  alone), tabs expose selected-state semantics, touch targets ≥48dp, layout survives 200%
  font scale. Expected: each state shows its externalized string copy and passes the a11y
  assertions. Traces: AC-3, AC-5, AC-6, AC-7.

- **TC-AND-356-12** — Type: Compose-UI (emu35). Target: append-error footer. Preconditions:
  feed page 1 ok, page 2 fails (MWS). Steps: scroll to trigger append. Expected: inline
  append-retry footer shown; already-loaded items remain; retry succeeds and appends.
  Traces: AC-2, AC-6.

- **TC-AND-356-13** — Type: instrumented/e2e (**A15 physical device — required**). Target:
  real-network + offline behavior against the flaky plaintext dev host. Preconditions:
  device on a real network; cleartext permitted for dev host; valid member session.
  Steps: open the syndicate online (populate cache), enable airplane mode, re-open / pull
  to refresh, restore network and retry. Expected: online load succeeds within the ~20s
  timeout; offline shows cached content with the stale indicator (or a per-tab Error+Retry
  when no cache); retry recovers. MUST run on the physical device for real radio/offline
  transitions and real-host latency (emulator cannot reproduce the flaky-host behavior).
  Traces: AC-1, AC-6.

- **TC-AND-356-14** — Type: instrumented (**A15 physical device — required for ABI/API
  parity**). Target: arm64-v8a / API-34 build of `feature-syndicates`. Preconditions: app
  installed on the A15 (API 34, arm64) vs CI emu35 (API 35, x86_64). Steps: run the
  TC-10 acceptance flow on the A15. Expected: overview renders identically; no
  Moshi/KSP/Paging ABI or API-level (34 vs 35) regressions. Confirms the x86_64-emulator
  suite generalizes to the shipped arm64/API-34 target. Traces: AC-1, AC-7.

### Coverage matrix

| Acceptance criterion | Covered by |
| --- | --- |
| AC-1 (overview renders, all tabs, no crash) | TC-01, TC-08, TC-10, TC-13, TC-14 |
| AC-2 (feed/ledger paginate + append-retry) | TC-04, TC-05, TC-12 |
| AC-3 (`*_cents` money formatting in currency) | TC-02, TC-11 |
| AC-4 (split % from `weights_bps`; mismatch banner) | TC-03 |
| AC-5 (403/non-member → not-a-member empty state) | TC-07, TC-11 |
| AC-6 (offline-stale vs per-tab error + Retry) | TC-06, TC-09, TC-11, TC-12, TC-13 |
| AC-7 (paths/verbs/shapes verified; strings externalized) | TC-01, TC-04, TC-05, TC-06, TC-11, TC-14 |
