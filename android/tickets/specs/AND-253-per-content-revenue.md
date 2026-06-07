---
id: AND-253
title: Per-content revenue
milestone: M6
epic: E34
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
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
  - Verified: the backend `sort_by` is a free-form string (default `total_cents`)
    and `sort_order` default `desc` per `GET /ui/analytics/content-revenue`. NOTE
    (divergence from web reference): the web `ContentRevenuePage.tsx` exposes only a
    4-key subset (`total_cents`, `tips_cents`, `unlocks_cents`, `published_at`). The
    Android client deliberately offers the full 7-key set; this is a valid superset
    because the server accepts any column name, but it is NOT mirrored 1:1 from the
    web app. See §16.

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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the authoritative source pointer.

1. **List endpoint is `GET /ui/analytics/content-revenue` → `ContentRevenueListOut`.**
   VERDICT: Verified. SOURCE: OpenAPI `GET /ui/analytics/content-revenue`
   (op `list_content_revenue_ui_analytics_content_revenue_get`, resp
   `200:ContentRevenueListOut`); frontend `src/api/endpoints/perContentRevenue.ts:
   getContentRevenueList` (`BASE = "/ui/analytics/content-revenue"`).
2. **A trailing-slash variant `GET /ui/analytics/content-revenue/` exists with the
   identical schema (R1).** VERDICT: Verified. SOURCE: OpenAPI
   `GET /ui/analytics/content-revenue/` (op
   `list_content_revenue_ui_analytics_content_revenue__get`, resp
   `200:ContentRevenueListOut`). The non-slash path is the one the web client uses.
3. **Detail endpoint `GET /ui/analytics/content-revenue/{content_id}` →
   `ContentRevenueDetailOut`.** VERDICT: Verified. SOURCE: OpenAPI
   `GET /ui/analytics/content-revenue/{content_id}`; frontend
   `src/api/endpoints/perContentRevenue.ts: getContentRevenueDetail`.
4. **Export endpoint `GET /ui/analytics/content-revenue/export` returns JSON (no typed
   schema); UI deferred.** VERDICT: Verified (UI-deferred is a scoping decision).
   SOURCE: OpenAPI `GET /ui/analytics/content-revenue/export`
   (resp `200:` — empty schema, i.e. untyped body; params `from_date,to_date,user_sub`);
   frontend `src/api/endpoints/perContentRevenue.ts: contentRevenueExportUrl`.
5. **List query params: `from_date`, `to_date`, `sort_by` (default `total_cents`),
   `sort_order` (default `desc`), `content_type`, `limit` (1–200, default 50),
   `cursor`, `user_sub`.** VERDICT: Verified. SOURCE: OpenAPI
   `GET /ui/analytics/content-revenue` params block — `limit` schema has
   `minimum:1, maximum:200, default:50`; `sort_by` default `total_cents`; `sort_order`
   default `desc`.
6. **`sort_by` is a free-form string server-side (no enum) (R3); we constrain to a
   known set client-side.** VERDICT: Verified. SOURCE: OpenAPI `sort_by` schema is
   `{type: string, default: total_cents}` with no `enum`.
7. **`ContentRevenueListOut` fields: `items[]`, `total_items`, `total_revenue_cents`,
   `next_cursor` (nullable string), `currency` (default `USD`).** VERDICT: Verified.
   SOURCE: `components.schemas.ContentRevenueListOut`; frontend
   `src/api/types.ts: ContentRevenueListResponse`. Note: the list item schema is named
   `ContentRevenueItem` (not `...Out`); the Android `ContentRevenueItemDto` maps it.
8. **List item fields: `content_id` (required), `content_type` (default `post`),
   `title` (default ``), `published_at` (integer, default 0), `tips_cents`,
   `unlocks_cents`, `subscriptions_cents`, `ads_cents`, `vod_cents`, `total_cents`
   (all integer, default 0).** VERDICT: Verified. SOURCE:
   `components.schemas.ContentRevenueItem`; frontend `src/api/types.ts:
   ContentRevenueItem`.
9. **`published_at` is an epoch integer in seconds defaulting to 0 (R2).** VERDICT:
   Verified for type/default; **seconds granularity is an assumption.** SOURCE: schema
   says `integer, default 0` (no unit). The spec's example `1717200000` is plausibly
   seconds (≈2024-06-01) rather than ms; frontend `fmtDate(item.published_at)` formats
   it but does not disambiguate the unit in the inspected region. Treated as seconds;
   see Open assumptions.
10. **Detail response = list-item fields + `time_series:
    ContentRevenueTimeSeriesPoint[]` + `currency`; time-series point =
    `{date, tips_cents, unlocks_cents, subscriptions_cents, ads_cents, vod_cents,
    total_cents}`.** VERDICT: Verified. SOURCE:
    `components.schemas.ContentRevenueDetailOut` and
    `components.schemas.ContentRevenueTimeSeriesPoint` (point requires `date`, a
    string); frontend `src/api/types.ts: ContentRevenueDetailResponse`,
    `ContentRevenueTimeSeriesPoint`.
11. **`422` returns `HTTPValidationError` (`detail: [{msg, ...}]`).** VERDICT:
    Verified. SOURCE: OpenAPI all four content-revenue ops list
    `422:HTTPValidationError`; `components.schemas.HTTPValidationError`.
12. **Auth rides on cookies + `X-CSRF-Token`.** VERDICT: Verified.
    SOURCE: frontend `src/api/client.ts` — `credentials: "include"` and
    `headers.set("X-CSRF-Token", csrf)` where `csrf = getCookie("ui_csrf")`.
    (Correction: CSRF cookie name is specifically `ui_csrf`.)
13. **`401` triggers a single refresh-and-retry via `POST /ui/session/refresh`.**
    VERDICT: Verified. SOURCE: frontend `src/api/client.ts: refreshSession` →
    `fetch(withApiBase("/ui/session/refresh"))`, single-flight `refreshPromise`, one
    retry then propagate; a second `401` throws "Authentication required".
14. **`user_sub` query param is NOT sent by the client (server scopes to session;
    admin/impersonation only).** VERDICT: Verified. SOURCE: frontend
    `src/api/endpoints/perContentRevenue.ts: toQuery` builds no `user_sub` key; OpenAPI
    marks `user_sub` `required:false`.
15. **`X-SESSION-ID` / `X-IMPERSONATION-TOKEN` headers are optional and not sent.**
    VERDICT: Verified (optional in schema); not-sent is the client's choice. SOURCE:
    OpenAPI params for the list op include both as optional headers; frontend client
    sets neither.
16. **Web reference exposes only a 4-key sort subset; Android offers all 7.** VERDICT:
    Corrected/clarified (was implied as a straight web port). SOURCE: frontend
    `src/pages/analytics/ContentRevenuePage.tsx` `SORT_OPTIONS` =
    `total_cents, tips_cents, unlocks_cents, published_at`. The Android superset is
    valid because `sort_by` is free-form server-side (claim 6).
17. **`next_cursor` is opaque and nullable; null ends paging (R4).** VERDICT: Verified.
    SOURCE: `ContentRevenueListOut.next_cursor` `anyOf: [string, null]`; frontend
    `src/api/types.ts: ContentRevenueListResponse.next_cursor: string | null`. Cursor
    stability across sort changes is unspecified — see Open assumptions.
18. **Currency formatting via `NumberFormat.getCurrencyInstance` seeded by response
    `currency`.** VERDICT: Verified as a reasonable Android equivalent (framework ref:
    https://developer.android.com/reference/java/text/NumberFormat#getCurrencyInstance()).
    Web parallel: `Intl.NumberFormat(..., {style:"currency"})` in
    `src/pages/analytics/ContentRevenuePage.tsx: fmtMoney`.
19. **Paging 3 / Hilt / Compose / Room / DataStore framework choices.** VERDICT:
    Unverified-assumption (not derivable from backend/frontend sources). Framework
    refs: Paging 3 https://developer.android.com/topic/libraries/architecture/paging/v3-overview ;
    Hilt https://developer.android.com/training/dependency-injection/hilt-android ;
    Compose Lazy lists https://developer.android.com/develop/ui/compose/lists ;
    Room https://developer.android.com/training/data-storage/room .
20. **OkHttp `followRedirects(false)` prevents a 307 from dropping cookie/CSRF (R1).**
    VERDICT: Unverified-assumption (AND-009 internal default; not in the provided
    sources). Framework ref:
    https://square.github.io/okhttp/3.x/okhttp/okhttp3/OkHttpClient.Builder.html#followRedirects-boolean- .

### Corrections made

- FR-4 / AC-2: noted the Android 7-key sort set is a deliberate superset of the web
  app's 4-key set (web exposes only `total_cents`, `tips_cents`, `unlocks_cents`,
  `published_at`). Valid because backend `sort_by` is a free-form string. (Claim 16.)
- §8 / §5: clarified the CSRF cookie name is specifically `ui_csrf` (the header
  remains `X-CSRF-Token`). (Claim 12.)
- §5: clarified that the list item schema is named `ContentRevenueItem` in OpenAPI
  (the list wrapper is `ContentRevenueListOut`); the Android `ContentRevenueItemDto`
  is the local mapping. No field-shape change required. (Claim 7.)
- No endpoint paths, HTTP methods, or response field names in the body were factually
  wrong; the body's API contract matches the OpenAPI and frontend sources.

### Open assumptions

- `published_at` unit (seconds vs milliseconds): the schema declares only
  `integer`/`default 0` with no unit, and the inspected frontend region does not
  disambiguate. Spec assumes **seconds** (`publishedAtEpochSec`). If the server emits
  ms, the "Unknown for 0" rule still holds but non-zero formatting would be wrong —
  confirm against a live response (Claim 9).
- Cursor stability across sort/filter changes (R4): not specified in OpenAPI. Spec
  assumes instability and resets paging on any query change — safe default but
  unverifiable from sources (Claim 17).
- AND-0xx internal contracts (AND-009 timeouts/`followRedirects(false)`, AND-011/012/
  013 cookie/CSRF/refresh wiring, AND-015 `detail` mapper, AND-016 retry, AND-021
  state composables, AND-032 logout purge, AND-045 cache pattern, AND-046/048 test
  harnesses): treated as established by upstream tickets; not present in the OpenAPI or
  frontend reference, so they are unverified here (dependency assumptions).
- Android framework selections (Paging 3, Hilt, Compose, Room, DataStore): design
  choices, not contract-derivable; cited as framework refs in claims 18–20.

## 17. Test Plan

Test targets: **JVM** (JVM unit/Robolectric, no device), **AVD test35** (headless
x86_64 emulator, Android 15/API 35, CI), **A15** (physical Samsung Galaxy A15 5G,
SM-A156U, serial R5CX821TA9R, Android 14/API 34, arm64-v8a). Use the physical device
only where real hardware/behavior matters; for this data/list screen nearly everything
runs on JVM or the emulator, with one ABI/API-level confidence run on A15.

- **TC-AND-253-01** — Type: unit (JVM). Target: JVM. DTO→domain mapping.
  Preconditions: a `ContentRevenueListDto` JSON fixture with one fully-populated item
  and one item omitting all optional fields. Steps: deserialize via Moshi; map to
  `ContentRevenue`/`ContentRevenuePage`. Expected: all six `*_cents` + `total_cents`
  map as `Long`; `published_at` → `publishedAtEpochSec`; missing `content_type`→`post`,
  missing `title`→``, missing `currency`→`USD`, missing fields default to 0; `next_cursor`
  null preserved. Traces: AC-1, AC-7.
- **TC-AND-253-02** — Type: contract/MockWebServer. Target: JVM (MockWebServer harness
  AND-046). Happy-path list call. Preconditions: MockWebServer enqueues a 200
  `ContentRevenueListOut` with 50 items + `next_cursor`. Steps: call
  `ContentRevenueApi.list` with defaults. Expected: request path
  `/ui/analytics/content-revenue`, method GET; query has `sort_by=total_cents`,
  `sort_order=desc`, `limit=50`, and **no** `user_sub`/`from_date`/`to_date`/
  `content_type`/`cursor` keys; response parses to 50 items. Traces: AC-1, AC-2.
- **TC-AND-253-03** — Type: contract/MockWebServer. Target: JVM. Sort/filter →
  query params. Preconditions: MockWebServer 200. Steps: issue queries varying
  `sortBy` over all 7 keys, `sortOrder` asc/desc, `contentType="video"`, `fromDate`/
  `toDate` set and unset. Expected: each emits exact param names/values; with empty
  range, **no** `from_date`/`to_date` keys present; `limit` clamps to 200 when a larger
  value is requested. Traces: AC-2, AC-3.
- **TC-AND-253-04** — Type: unit (JVM). Target: JVM. PagingSource pagination.
  Preconditions: fake `ContentRevenueApi` returning page 1 (`next_cursor="c1"`), page 2
  (`next_cursor=null`). Steps: `load` with key null then "c1". Expected: page 1
  `LoadResult.Page` `nextKey="c1"`/`prevKey=null`; page 2 `nextKey=null` (paging stops);
  header callback fired once from first page. Traces: AC-4, AC-5.
- **TC-AND-253-05** — Type: unit (JVM). Target: JVM. Query change resets paging &
  header. Preconditions: ViewModel with fake repo. Steps: load defaults, then call
  `onSortChange(TIPS, ASC)`. Expected: a new `ContentRevenueQuery` is emitted, pager
  invalidated (re-load from cursor=null), `uiState` header summary reset then
  repopulated from the new first page. Traces: AC-2, AC-5.
- **TC-AND-253-06** — Type: contract/MockWebServer. Target: JVM. 422 validation error
  shape. Preconditions: MockWebServer enqueues 422 `HTTPValidationError`
  (`{"detail":[{"loc":["query","sort_by"],"msg":"...","type":"..."}]}`). Steps: call
  list with a bad `sort_by`. Expected: AND-015 `detail` mapper yields a user-facing
  message; client falls back to defaults; no crash. Traces: AC-6.
- **TC-AND-253-07** — Type: contract/MockWebServer. Target: JVM. 401 single
  refresh-and-retry. Preconditions: enqueue 401, then 200 for
  `POST /ui/session/refresh`, then 200 for the retried list. Steps: call list while
  "authenticated". Expected: exactly one refresh to `/ui/session/refresh`, list
  retried once and succeeds; a second consecutive 401 propagates as an auth error
  (defers to AND-025 routing). Traces: AC-6.
- **TC-AND-253-08** — Type: unit (JVM). Target: JVM. Append-error preserves pages.
  Preconditions: fake API returns page 1 ok then throws on page 2. Steps: load page 1,
  scroll triggers page 2. Expected: `LoadState.Error` for append, loaded page-1 items
  retained, `items.retry()` re-attempts the failed page only. Traces: AC-6.
- **TC-AND-253-09** — Type: integration (JVM/Robolectric). Target: JVM. Offline +
  stale cache path (flaky-dev-host). Preconditions: AND-017 probe reports offline;
  Room `content_revenue_cache` holds a first-page payload for the default query hash.
  Steps: open screen offline. Expected: cached items served, `isStale=true` (stale
  banner), and **no** network request fired; on reconnect+refresh, fresh data replaces
  cache and clears stale flag. Traces: AC-6.
- **TC-AND-253-10** — Type: Compose-UI. Target: AVD test35. List renders with
  formatted currency. Preconditions: fake repo returns a page with known cents (e.g.
  `total_cents=27050`, `currency=USD`). Steps: render `PerContentRevenueScreen`.
  Expected: rows show titles and `$270.50`; header shows formatted
  `total_revenue_cents`/`total_items`; a `published_at=0` row shows "Unknown" not 1970.
  Traces: AC-1, AC-5.
- **TC-AND-253-11** — Type: Compose-UI. Target: AVD test35. Sort interaction +
  breakdown expansion. Preconditions: fake repo records queries. Steps: select a sort
  chip; assert announced sort state and a refetch with new `sort_by`/`sort_order`;
  expand a row. Expected: refetch occurs from first page; expanded row shows all five
  source labels (Tips, Unlocks, Subscriptions, Ads, VOD) with formatted values,
  including `$0.00` for zero sources. Traces: AC-2, AC-7.
- **TC-AND-253-12** — Type: Compose-UI. Target: AVD test35. State coverage. Steps:
  drive fake `loadState` into loading (first load), empty (`items` empty), first-load
  error (retry button calls `items.refresh()`), append error (inline retry). Expected:
  each AND-021 state composable renders and the retry affordances invoke the right
  action. Traces: AC-6.
- **TC-AND-253-13** — Type: Compose-UI (accessibility). Target: AVD test35. TalkBack /
  semantics + text scaling. Steps: assert sort chip `stateDescription` (e.g. "Sorted by
  Total, descending"); each row breakdown is one grouped semantics node; tap targets
  ≥48dp; set font scale to 2.0 and assert totals are not truncated (title ellipsizes
  only). Expected: all assertions pass. Traces: AC-2, AC-6, AC-7.
- **TC-AND-253-14** — Type: instrumented/e2e. Target: **A15 (physical device — MUST)**.
  Real-device ABI/API confidence + security. Rationale: validate arm64-v8a / API 34
  vs the emulator's x86_64 / API 35, plus on-device privacy behavior. Preconditions:
  release-type build with logging at BASIC; logged-in session. Steps: open the screen
  against a mock/staging backend, scroll/paginate, then inspect logcat. Expected: list
  renders and paginates on arm64-v8a/API 34; **no monetary values or row/total figures
  appear in release logs**; cache file lives in app-private storage only; logout purges
  `content_revenue_cache` (AND-032). Traces: AC-1, AC-4.

### Coverage matrix

| AC (section 14) | Covered by |
| --- | --- |
| AC-1 (list renders, formatted total) | TC-01, TC-02, TC-10, TC-14 |
| AC-2 (sort re-queries + reset, defaults) | TC-02, TC-03, TC-05, TC-11, TC-13 |
| AC-3 (filters apply, empty range sends no dates) | TC-03 |
| AC-4 (cursor paging, stop on null) | TC-04, TC-14 |
| AC-5 (header total/items formatted) | TC-04, TC-05, TC-10 |
| AC-6 (loading/empty/first-error/append-error/stale) | TC-06, TC-07, TC-08, TC-09, TC-12, TC-13 |
| AC-7 (five-source breakdown incl. zero) | TC-01, TC-11, TC-13 |
| AC-8 (unit + MockWebServer + Compose tests green) | TC-01..TC-13 (all) |
