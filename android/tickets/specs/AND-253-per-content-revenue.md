---
id: AND-253
title: Per-content revenue
milestone: M6
epic: E34
priority: P1
size: M
status: draft
depends_on: [AND-251, AND-255, AND-256, AND-016, AND-018, AND-021]
blocks: []
---

# AND-253 — Per-content revenue

## 1. Overview & Goal

Port the web `perContentRevenue.ts` table/sort view to the native Android app as a
per-content revenue screen inside the Earnings (E34) area. The screen lists each
piece of content owned by the authenticated creator with its revenue broken down by
source (tips, unlocks, subscriptions, ads, VOD) and a total, all in cents from the
backend rendered as currency. The list is sortable by any revenue column and by
publish date, filterable by date range and content type, and pages through a cursor.

The goal of this ticket is a working, real-data list/table screen — `Per-content
revenue renders` — backed by the existing earnings API layer from AND-251 and
reusing the shared finance chart only for the (optional) per-item detail sparkline
owned downstream. This ticket owns: the `feature-earnings` per-content list screen,
its ViewModel, the Retrofit endpoint methods + DTOs specific to content revenue, the
repository read path, sort/filter UI controls, Paging 3 wiring, and tests proving
the list renders and sorts.

Out of scope: the earnings dashboard totals and time-series charts (AND-252), the
reusable chart composable itself (AND-255), the engagement-rate metrics (AND-254),
and CSV export. Export endpoint is named here but its UI is deferred.

## 2. Context & References

- Web reference: `frontend/src/api/endpoints/perContentRevenue.ts` (table/sort
  source of truth for column set and sort keys), shared types in
  `frontend/src/api/types.ts`.
- Backend (OpenAPI `/openapi.json` on dev host `http://18.222.237.167:8000`):
  - `GET /ui/analytics/content-revenue` → `ContentRevenueListOut`
  - `GET /ui/analytics/content-revenue/{content_id}` → `ContentRevenueDetailOut`
  - `GET /ui/analytics/content-revenue/export` (JSON; UI deferred)
- Module layering: `app -> feature-earnings -> core-*`. New code lands in
  `feature-earnings` and `core-network`/`core-model`/`core-data`.
- Namespace: `com.testlogon.android` everywhere a package appears.
- Upstream tickets: AND-251 (Earnings API + DTOs — established `EarningsApi`,
  Moshi adapters, `ApiResult` mapping), AND-255 (reusable chart — used only by the
  optional detail view), AND-256 (Earnings ViewModel — owns the shared range
  selection state this screen subscribes to), AND-016 (retry/backoff for idempotent
  GETs), AND-018 (`ApiResult<T>`), AND-021 (loading/empty/error/offline state
  composables).

## 3. Functional Requirements

FR-1. Display a scrollable list of content revenue rows. Each row shows: title
(falling back to `content_id` when empty), content type, published date, and the
total revenue formatted as currency from `total_cents` + `currency`.

FR-2. Each row is expandable (or tappable to a detail) to reveal the per-source
breakdown: tips, unlocks, subscriptions, ads, VOD. Breakdown values are derived from
the `*_cents` fields. Zero-value sources are shown as the formatted zero (e.g.
`$0.00`), not hidden.

FR-3. A header summary shows `total_items` and `total_revenue_cents` (formatted) for
the current filter window, sourced from `ContentRevenueListOut`.

FR-4. Sort controls let the user pick `sort_by` ∈ {`total_cents`, `tips_cents`,
`unlocks_cents`, `subscriptions_cents`, `ads_cents`, `vod_cents`, `published_at`} and
`sort_order` ∈ {`asc`, `desc`}. Default is `total_cents` / `desc`. Changing sort
re-queries from the first page (cursor reset).

FR-5. Filter controls: optional date range (`from_date`, `to_date` as ISO `YYYY-MM-DD`
strings) and optional `content_type`. The date range defaults to the range selected
in the shared earnings range state (AND-256); if none, no range params are sent.
Changing any filter resets paging.

FR-6. Pagination: load `limit=50` (max 200) per page using `cursor`/`next_cursor`.
Append on scroll-to-end. When `next_cursor` is null, stop paging.

FR-7. State coverage (AND-021): full-screen loading on first load, empty state when
`items` is empty, inline append-error for page failures, error/offline state for
first-load failures with retry, and a stale banner when serving cached data.

FR-8. Currency formatting: all `_cents` integers are divided by 100 and formatted
with the list `currency` (default `USD`) using a locale-aware formatter.

## 4. Technical Design

New module path: `feature-earnings` (created/extended under AND-252/AND-256). This
ticket adds the per-content list slice.

Package root: `com.testlogon.android.feature.earnings.percontent`.

```kotlin
// core-model: domain models (currency-agnostic, cents preserved)
data class ContentRevenue(
    val contentId: String,
    val contentType: String,        // "post", "video", ...
    val title: String,
    val publishedAtEpochSec: Long,  // 0 when unknown
    val tipsCents: Long,
    val unlocksCents: Long,
    val subscriptionsCents: Long,
    val adsCents: Long,
    val vodCents: Long,
    val totalCents: Long,
)

data class ContentRevenuePage(
    val items: List<ContentRevenue>,
    val totalItems: Int,
    val totalRevenueCents: Long,
    val currency: String,           // ISO 4217, default "USD"
    val nextCursor: String?,
)

enum class RevenueSortKey(val apiValue: String) {
    TOTAL("total_cents"), TIPS("tips_cents"), UNLOCKS("unlocks_cents"),
    SUBSCRIPTIONS("subscriptions_cents"), ADS("ads_cents"),
    VOD("vod_cents"), PUBLISHED("published_at");
}
enum class SortOrder(val apiValue: String) { ASC("asc"), DESC("desc") }

data class ContentRevenueQuery(
    val fromDate: String? = null,   // YYYY-MM-DD
    val toDate: String? = null,
    val contentType: String? = null,
    val sortBy: RevenueSortKey = RevenueSortKey.TOTAL,
    val sortOrder: SortOrder = SortOrder.DESC,
)
```

ViewModel exposes a single `StateFlow<UiState>` per the layering rule and drives a
Paging 3 `Flow<PagingData<ContentRevenue>>` keyed on the active query.

```kotlin
// feature-earnings/.../percontent/PerContentRevenueViewModel.kt
@HiltViewModel
class PerContentRevenueViewModel @Inject constructor(
    private val repo: ContentRevenueRepository,
    private val earningsRange: EarningsRangeStore, // from AND-256
) : ViewModel() {

    data class UiState(
        val query: ContentRevenueQuery = ContentRevenueQuery(),
        val totalItems: Int = 0,
        val totalRevenueCents: Long = 0,
        val currency: String = "USD",
        val isStale: Boolean = false,
    )

    val uiState: StateFlow<UiState>
    val items: Flow<PagingData<ContentRevenue>> // cachedIn(viewModelScope)

    fun onSortChange(key: RevenueSortKey, order: SortOrder)
    fun onContentTypeChange(type: String?)
    fun onDateRangeChange(from: String?, to: String?)
    fun refresh()
}
```

Paging source resets by emitting a new query into a `MutableStateFlow<ContentRevenueQuery>`
and using `flatMapLatest { Pager(...).flow }`. The header summary (`totalItems`,
`totalRevenueCents`, `currency`) is captured from the first page's
`ContentRevenueListOut` and pushed into `uiState`.

```kotlin
class ContentRevenuePagingSource(
    private val api: ContentRevenueApi,
    private val query: ContentRevenueQuery,
    private val onHeader: (ContentRevenuePage) -> Unit,
) : PagingSource<String, ContentRevenue>() {
    override suspend fun load(
        params: LoadParams<String>
    ): LoadResult<String, ContentRevenue>
    override fun getRefreshKey(state: PagingState<String, ContentRevenue>): String? = null
}
```

Repository (core-data) wraps the API in `ApiResult<T>` for non-paged needs and
exposes the `Pager`. Idempotent GETs are eligible for AND-016 retry/backoff.

```kotlin
interface ContentRevenueRepository {
    fun pager(query: ContentRevenueQuery): Pager<String, ContentRevenue>
    suspend fun detail(
        contentId: String, from: String?, to: String?
    ): ApiResult<ContentRevenueDetail>
}
```

UI: `PerContentRevenueScreen(state, items: LazyPagingItems<ContentRevenue>, onEvent)`
using `LazyColumn`, a sticky header row with sort chips/menu, a filter bar, and
`ContentRevenueRow` composables. Append/refresh states come from
`items.loadState` mapped onto AND-021 state composables.

## 5. API Contract

Primary list call (idempotent GET, retry-eligible):

`GET /ui/analytics/content-revenue?from_date=&to_date=&sort_by=&sort_order=&content_type=&limit=&cursor=&user_sub=`

Query params: `from_date`/`to_date` (ISO date string, optional), `sort_by`
(default `total_cents`), `sort_order` (default `desc`), `content_type` (optional),
`limit` (1–200, default 50), `cursor` (opaque, optional), `user_sub` (optional).
Auth rides on cookies + `X-CSRF-Token` per AND-012/AND-013; `X-SESSION-ID` /
`X-IMPERSONATION-TOKEN` headers are optional and not sent by this client.

Response `200` (`ContentRevenueListOut`):

```json
{
  "items": [
    {
      "content_id": "ct_123",
      "content_type": "video",
      "title": "Behind the scenes",
      "published_at": 1717200000,
      "tips_cents": 4500,
      "unlocks_cents": 12000,
      "subscriptions_cents": 8000,
      "ads_cents": 350,
      "vod_cents": 2200,
      "total_cents": 27050
    }
  ],
  "total_items": 137,
  "total_revenue_cents": 1894322,
  "next_cursor": "eyJvZmZzZXQiOjUwfQ==",
  "currency": "USD"
}
```

Detail call (used by optional per-item view; chart owned by AND-255):

`GET /ui/analytics/content-revenue/{content_id}?from_date=&to_date=&user_sub=`
→ `200` `ContentRevenueDetailOut` = list-item fields plus
`time_series: ContentRevenueTimeSeriesPoint[]` (`{date, tips_cents, unlocks_cents,
subscriptions_cents, ads_cents, vod_cents, total_cents}`) and `currency`.

Export (deferred UI): `GET /ui/analytics/content-revenue/export?from_date=&to_date=&user_sub=`
returns JSON; not wired in this ticket.

Errors: `422` returns `HTTPValidationError` (`detail: [{msg, ...}]`) mapped via the
FastAPI `detail` mapper from AND-015. `401` triggers the AND-013 single
refresh-and-retry.

```kotlin
// core-network: Retrofit
interface ContentRevenueApi {
    @GET("ui/analytics/content-revenue")
    suspend fun list(
        @Query("from_date") fromDate: String?,
        @Query("to_date") toDate: String?,
        @Query("sort_by") sortBy: String = "total_cents",
        @Query("sort_order") sortOrder: String = "desc",
        @Query("content_type") contentType: String?,
        @Query("limit") limit: Int = 50,
        @Query("cursor") cursor: String?,
    ): ContentRevenueListDto

    @GET("ui/analytics/content-revenue/{content_id}")
    suspend fun detail(
        @Path("content_id") contentId: String,
        @Query("from_date") fromDate: String?,
        @Query("to_date") toDate: String?,
    ): ContentRevenueDetailDto
}

@JsonClass(generateAdapter = true)
data class ContentRevenueItemDto(
    @Json(name = "content_id") val contentId: String,
    @Json(name = "content_type") val contentType: String = "post",
    val title: String = "",
    @Json(name = "published_at") val publishedAt: Long = 0,
    @Json(name = "tips_cents") val tipsCents: Long = 0,
    @Json(name = "unlocks_cents") val unlocksCents: Long = 0,
    @Json(name = "subscriptions_cents") val subscriptionsCents: Long = 0,
    @Json(name = "ads_cents") val adsCents: Long = 0,
    @Json(name = "vod_cents") val vodCents: Long = 0,
    @Json(name = "total_cents") val totalCents: Long = 0,
)

@JsonClass(generateAdapter = true)
data class ContentRevenueListDto(
    val items: List<ContentRevenueItemDto> = emptyList(),
    @Json(name = "total_items") val totalItems: Int = 0,
    @Json(name = "total_revenue_cents") val totalRevenueCents: Long = 0,
    @Json(name = "next_cursor") val nextCursor: String? = null,
    val currency: String = "USD",
)
```

## 6. Data & State Management

- Paging: Paging 3 with `String` cursor key. `LoadParams.key` carries the
  `cursor`; first load passes `null`. `nextCursor` becomes the next page key;
  `prevKey` is always `null` (forward-only cursor paging).
- Single source of UI truth: `uiState: StateFlow<UiState>` (query + header
  summary + stale flag) plus the `cachedIn` paging flow. The two are independent
  flows; the screen combines them.
- Query change semantics: any sort/filter mutation creates a new `ContentRevenueQuery`
  emitted into the query `MutableStateFlow`, which invalidates the pager and resets
  to the first page; header summary is reset and repopulated from the first page.
- Cache (AND-045 pattern, optional but in scope for stale UX): persist the first
  page of the default query in Room (`content_revenue_cache` table keyed by a hash
  of the query) via DataStore-tracked `cachedAt`. On first-load network failure,
  serve cached items and set `isStale = true`. Cache TTL soft-expires at 1 hour;
  expired cache is still shown with the stale banner until fresh data arrives.

```kotlin
@Entity(tableName = "content_revenue_cache")
data class ContentRevenueCacheEntity(
    @PrimaryKey val queryHash: String,
    val payloadJson: String, // serialized ContentRevenueListDto first page
    val cachedAtEpochMs: Long,
)
```

- Mapping: cents are kept as `Long` end-to-end; formatting to currency happens only
  at the composable boundary via a `CurrencyFormatter(currency)` helper using
  `NumberFormat.getCurrencyInstance` seeded by the response `currency`.

## 7. Error Handling & Resilience

- Timeouts: rely on the OkHttp ~20s timeouts from AND-009 against the unreliable
  dev host.
- Retry: list/detail are idempotent GETs → eligible for AND-016 bounded backoff
  retry. Paging append failures surface as `LoadState.Error` with an inline retry
  affordance (`items.retry()`); they do not clear loaded pages.
- First-load failure: show AND-021 error/offline state with a retry button that
  calls `items.refresh()`.
- `401`: handled transparently by the AND-013 authenticator (single
  `POST /ui/session/refresh` then retry); a second `401` propagates as an auth
  error and the screen defers to the app's auth-gated routing (AND-025).
- `422`: mapped via AND-015 `detail` mapper to a user-facing message; typically
  indicates a bad `sort_by`/date param — log and fall back to defaults.
- Offline: if connectivity probe (AND-017) reports offline, attempt cache; if no
  cache, show offline state without firing the request.

## 8. Security & Privacy

- No new auth surface. All calls are cookie-authenticated through the shared OkHttp
  client with the persistent cookie jar (AND-011) and CSRF header (AND-012). The
  `user_sub` query param is NOT sent by this client (server scopes to the session
  identity); it exists only for admin/impersonation flows we do not expose.
- Revenue figures are sensitive financial data: never log row values or totals in
  release builds (see §10). Cache entries live in app-private storage only; no
  external sharing. Plaintext HTTP to the dev host is a known dev-only condition,
  not a release configuration.
- No PII beyond content titles is stored; cache is cleared on logout via the
  existing AND-032 logout cleanup hook (register `content_revenue_cache` for purge).

## 9. Accessibility & i18n

- All sort/filter controls are real, focusable Material 3 components with
  `contentDescription`/`stateDescription` (e.g. selected sort chip announces
  "Sorted by Total, descending"). Sort direction toggle has a distinct label.
- Currency and dates are locale-formatted; cents are never shown as raw integers.
  Date strings sent to the API stay ISO `YYYY-MM-DD` regardless of display locale.
- All user-facing strings (column headers, source labels, empty/error copy) live in
  `feature-earnings` `strings.xml`; no hard-coded UI text. Source labels: Tips,
  Unlocks, Subscriptions, Ads, VOD, Total.
- Row breakdown is reachable and readable by TalkBack as a grouped semantics node
  per content item; tap targets ≥ 48dp. Table supports text scaling without
  truncating totals (numbers right-aligned, ellipsize the title only).

## 10. Telemetry & Logging

- Debug-only logging via the shared logger: screen open, query changes (sort/filter
  keys only — never values), page load latency, and load-state transitions.
- Emit lightweight analytics events (if the app analytics sink exists): 
  `per_content_revenue_viewed`, `per_content_revenue_sorted{key, order}`,
  `per_content_revenue_filtered{has_range, content_type}`. No monetary values in
  event payloads.
- Network logging uses the AND-009 OkHttp logging interceptor at `BASIC` in
  release and `BODY` only in debug; financial response bodies must not appear in
  release logs.

## 11. Testing Strategy

Unit / repository (core-testing + MockWebServer harness from AND-046):
- DTO → domain mapping for all `*_cents` fields, `published_at`, currency default.
- `ContentRevenuePagingSource.load`: first page returns items + `next_cursor`;
  follow-up page uses cursor; null `next_cursor` ends paging; HTTP error →
  `LoadResult.Error`.
- Query→params: sort key/order, date range, content_type, limit clamping to 200,
  cursor reset on query change.
- `422` body mapped through AND-015 mapper; `401` retried once via authenticator.
- Stale path: network failure with cached first page yields `isStale = true`.

ViewModel:
- `onSortChange`/`onContentTypeChange`/`onDateRangeChange` invalidate paging and
  reset header summary; defaults are `total_cents`/`desc`.
- Header summary (`totalItems`, `totalRevenueCents`, `currency`) is populated from
  the first page.

Compose UI tests (AND-048 pattern):
- List renders rows with formatted total currency (the acceptance: "Per-content
  revenue renders").
- Sort chip selection changes announced sort state and triggers a refetch (assert
  via fake repo).
- Empty, first-load error (retry), and append-error (inline retry) states render.
- Row expansion reveals all five source breakdown labels with formatted values.

## 12. Dependencies & Sequencing

- Hard deps: AND-251 (Earnings API base, Moshi, `ApiResult`/`detail` mapping reuse),
  AND-256 (shared earnings range store this screen subscribes to), AND-255 (chart —
  required only for the optional per-item detail sparkline; the list itself does not
  need it). Also relies on AND-016 (retry), AND-018 (`ApiResult`), AND-021 (state
  composables), AND-011/012/013 (cookie/CSRF/refresh), AND-009 (timeouts).
- Sequencing: implement after AND-251 and AND-256. Can land in parallel with
  AND-252 (dashboard) since they consume different endpoints; both live in
  `feature-earnings`. If AND-255 slips, ship the list without the detail sparkline
  (gate the sparkline behind chart availability).
- Blocks: none declared in backlog.

## 13. Risks & Open Questions

- R1: OpenAPI exposes both `/ui/analytics/content-revenue` and a trailing-slash
  variant with identical schemas. Use the non-slash path; confirm the dev host does
  not 307-redirect (which would drop the cookie/CSRF headers). Mitigation: set
  OkHttp `followRedirects(false)` is already the AND-009 default — verify and handle.
- R2: `published_at` is an epoch integer (seconds) defaulting to 0; rows with 0 must
  render "Unknown" rather than 1970. Confirmed handling in §3/§4.
- R3: `sort_by` accepts an arbitrary string server-side (no enum in schema). We
  constrain to the known column set client-side; an unknown server-added column
  would be ignored until added to `RevenueSortKey`.
- R4: Cursor opacity — `next_cursor` is base64-ish and treated as opaque; do not
  parse. Open question: is the cursor stable across sort changes? Assume no; reset
  on any query change.
- R5: `total_cents` is server-provided, not recomputed client-side; if it diverges
  from the sum of sources, display the server total and log a debug warning.

## 14. Acceptance Criteria

AC-1. The per-content revenue screen renders a list of content items with formatted
total currency from `total_cents`/`currency` for a real (or mocked-real) response
from `GET /ui/analytics/content-revenue` — satisfying the backlog acceptance
"Per-content revenue renders".
AC-2. Sorting by any of {total, tips, unlocks, subscriptions, ads, VOD, published}
in asc/desc re-queries with the correct `sort_by`/`sort_order` and resets paging;
default is `total_cents`/`desc`.
AC-3. Date-range and content-type filters apply the correct query params and reset
paging; empty range sends no date params.
AC-4. Pagination loads additional pages via `cursor`/`next_cursor` and stops when
`next_cursor` is null.
AC-5. Header shows formatted `total_revenue_cents` and `total_items`.
AC-6. Loading, empty, first-load error (with retry), append error (inline retry),
and stale states each render per AND-021.
AC-7. Each row exposes the five-source breakdown with formatted (incl. zero) values.
AC-8. Unit, repository (MockWebServer), and Compose UI tests in §11 pass in CI.

## 15. Definition of Done

- Code merged to `android-port` under `feature-earnings`
  (`com.testlogon.android.feature.earnings.percontent`) plus `ContentRevenueApi` +
  DTOs in `core-network`, domain models in `core-model`, repository/cache in
  `core-data`.
- All §14 acceptance criteria verified; all §11 tests written and green in CI.
- No release-build logging of monetary values; cookie/CSRF/refresh reuse confirmed
  (no new auth code).
- ktlint/detekt clean (AND-005); builds on JDK 17 / AGP 8.7.3 / Gradle 8.9.
- Strings externalized; TalkBack pass on list + row breakdown; text-scaling sane.
- Cache registered for logout purge (AND-032); stale banner verified against a
  simulated network failure on the unreliable dev host.
- Spec deviations (e.g. detail sparkline deferred if AND-255 slips) noted in the PR
  description.
