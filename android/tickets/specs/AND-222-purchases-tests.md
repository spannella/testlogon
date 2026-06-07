---
id: AND-222
title: Purchases tests
milestone: M5
epic: E30
priority: P2
size: M
depends_on: [AND-221]
blocks: []
status: reviewed
reviewed_on: 2026-06-06
---

# AND-222 — Purchases tests

## 1. Overview & Goal

This ticket delivers the automated test suite that locks down the Purchases feature
of the TestLogon native Android port: the `core-data` purchases repository
(AND-218 mapping + AND-219 search), the `feature-purchases` `PurchasesViewModel`
(AND-221 state + Paging 3), and the Compose UI for purchase history, search, and
order detail/tracking (AND-219 / AND-220). It is a **Test-type** ticket (Priority
P2); the sole backlog acceptance is **"Pass"**. Concretely, that means a green,
deterministic, offline (no live backend) suite covering:

- **Repository / mapping unit tests** — `ApiResult<T>` success and failure paths,
  FastAPI `detail` error mapping, DTO → domain model mapping, and search query
  passthrough.
- **ViewModel unit tests** — `StateFlow<UiState>` transitions (Loading → Content →
  Empty → Error → Stale), search debounce, retry, and `PagingData` emission using
  Paging 3 test helpers, run on a `StandardTestDispatcher` with Turbine.
- **Compose UI tests** — history list rendering, paging append/loading footer,
  search filtering, empty/error/offline states, and order-detail rendering with a
  working tracking link (AND-220).

The goal is to make the Purchases feature regression-safe before M5 ships, with no
dependency on the unreliable dev backend at runtime. This spec defines *which* tests
exist, *what* fixtures they use, and the *pass bar*; it does not change production
code except for adding test-only seams (fakes, test tags) where they are missing.

## 2. Context & References

- **Repo / module:** `spannella/testlogon`, branch `android-port`, Android app under
  `android/`. Tests live in the modules under test:
  - `android/core-data/src/test/java/com/testlogon/android/core/data/purchases/`
  - `android/feature-purchases/src/test/java/com/testlogon/android/feature/purchases/`
  - `android/feature-purchases/src/androidTest/java/com/testlogon/android/feature/purchases/`
- **Stack:** Kotlin 2.0.21, JUnit4, Coroutines test (`kotlinx-coroutines-test`),
  Turbine (Flow assertions), MockK, Truth (assertions), Paging 3 test
  (`androidx.paging:paging-testing`), OkHttp `MockWebServer`, Hilt testing,
  Compose UI test (`createAndroidComposeRule`), Robolectric (for JVM-side Compose
  where feasible). JDK 17, AGP 8.7.3, Gradle 8.9.
- **Shared test infra:** the `core-testing` module provides `MainDispatcherRule`,
  fixture loaders, and a shared Moshi instance; this ticket extends it with
  purchases fixtures and a `FakePurchasesRepository`.
- **Upstream tickets (authoritative requirements under test):**
  - AND-218 — Purchases API (`purchases` list/detail/search mapping). **P0.**
  - AND-219 — Purchase history + search (history list, full-text search). **P1.**
  - AND-220 — Order detail + tracking (detail, items, tracking link). **P1.**
  - AND-221 — Purchases ViewModel (state + paging). **P1.** *Direct dependency.*
- **Backend:** FastAPI + DynamoDB; OpenAPI at `/openapi.json`; web reference under
  `frontend/` (`frontend/src/api/endpoints/purchases.ts`,
  `frontend/src/api/types.ts`). Tests **must not** hit the live dev host
  (`http://18.222.237.167:8000`); all network is served by `MockWebServer` or fakes.

## 3. Functional Requirements

FR-1. **Repository success mapping.** Given a recorded `GET /ui/purchase-history/transactions`
200 body (a **bare JSON array** of `PurchaseTransactionSummary`, not a paged envelope),
the repository returns `ApiResult.Success<List<Purchase>>` whose fields match the DTO
(`txn_id`, `created_at`, `updated_at`, `status`, `amount`, `currency`, optional
`merchant_id`, `external_ref`, `description`).
**[CORRECTED]** The earlier draft named the endpoint `GET /ui/purchases` and fields
`id/merchant/total/orderedAt/itemCount`; the real contract is
`GET /ui/purchase-history/transactions` returning `PurchaseTransactionSummary[]` with the
fields listed above. `amount` is a JSON `number` (decimal major units, e.g. `42.99`) — **not**
integer minor units — and `created_at`/`updated_at` are Unix epoch **seconds** integers.
There is no `item_count` field on the summary.

FR-2. **Repository error mapping.** For 400/401/422/500 responses and for
non-`200` FastAPI `detail` shapes (`string`, `[{msg}]`, `{code,...}`), the repository
returns `ApiResult.Error` with a normalized message/code (asserted per shape).

FR-3. **Detail mapping (AND-220).** `GET /ui/purchase-history/transactions/{txn_id}` maps
`PurchaseTransactionInfo` including the optional `shipping` object
(`carrier`, `tracking_number`, `tracking_url`, `status`, `shipped_at`, `delivered_at`,
`carrier_events[]`); a null/absent `shipping` yields `shipping == null` (no crash).
**[CORRECTED]** The earlier draft assumed `GET /ui/purchases/{id}` with an inline `items`
array and a `tracking` object. The real detail DTO is `PurchaseTransactionInfo` (extends
`PurchaseTransactionSummary`) and carries **no line-items array**; tracking lives under the
`shipping` field (carrier_tracking fields), and order line items are fetched separately via
the cart endpoint when `metadata.cart_id` is present (see §5). A dedicated
`GET /ui/purchase-history/transactions/{txn_id}/tracking` (`CarrierTrackingView`) also exists.

FR-4. **Search passthrough (AND-219).** A non-blank query reaches the **dedicated search
endpoint** `GET /ui/purchase-history/transactions/search` as the `q` query parameter,
URL-encoded; blank/whitespace queries do not issue a search request (the screen falls back to
the plain list endpoint). **[CORRECTED]** Search is its own endpoint, not a `q` param on the
list endpoint. The `status` filter is applied **client-side** to search results (server-side
`status` param is only honored by the list endpoint).

FR-5. **ViewModel state machine (AND-221).** Assert the ordered `UiState` emissions
for: initial load success (Loading → Content), empty result (Loading → Empty), error
(Loading → Error with retryable flag), retry (Error → Loading → Content), and stale
cache (Stale shown when cached data exists but refresh fails).

FR-6. **Paging.** The ViewModel exposes `Flow<PagingData<PurchaseUi>>`; tests assert
the materialized first page contents, refresh, and append using
`AsyncPagingDataDiffer` / `PagingData` test helpers.
**[CORRECTED — contract caveat]** The backend list endpoint is **not paginated**: it returns
a bare array and accepts only `limit` (default 50 in the web client) and `status`. There is no
`page`/`page_size`/`total` envelope server-side. Any Paging 3 wiring in AND-221 is therefore a
client-only construct over a single bounded fetch (`limit`), so paging tests assert in-memory
list materialization over the fixture; **append/next-page tests against a server cursor are not
applicable** unless AND-221 introduces a synthetic `limit`-window pager. If AND-221 does not use
Paging 3, the paging tests are `@Ignore`d with that note rather than asserting a non-existent
server contract.

FR-7. **Search debounce.** Rapid query changes collapse to a single repository call
after the debounce window (e.g., 300 ms) on a controlled test dispatcher.

FR-8. **History UI (AND-219).** The history screen renders a row per item, shows a
loading footer during append, renders an empty state for zero results, and filters
the visible list when a search query is entered.

FR-9. **Detail UI (AND-220).** The detail screen renders merchant, total, item rows,
and a tracking affordance; tapping the tracking link emits the expected
`Intent`/URL (verified via a fake URL handler), and the affordance is absent when
tracking is null.

FR-10. **Resilience UI.** Offline/stale and error states render with a visible Retry
control whose click invokes the ViewModel retry path.

FR-11. **Determinism.** No test depends on wall-clock time, real network, or device
locale; all use injected dispatchers, `MockWebServer`, and fixed fixtures.

## 4. Technical Design

Tests are organized by layer. Production code under test is treated as the contract
defined by AND-218..AND-221; this ticket adds only test sources and minimal test
seams.

**Test seams added (if not already present):**

```kotlin
// core-testing
class FakePurchasesRepository : PurchasesRepository {
    var listResult: ApiResult<List<Purchase>> = ApiResult.Success(emptyList())
    var detailResult: ApiResult<PurchaseDetail> = ApiResult.Success(samplePurchaseDetail())
    val searchQueries = mutableListOf<String>()
    fun pagingSource(items: List<Purchase>): PagingSource<Int, Purchase>
}

// stable Compose test tags consumed by androidTest
object PurchasesTestTags {
    const val HISTORY_LIST = "purchases_history_list"
    const val SEARCH_FIELD = "purchases_search_field"
    const val EMPTY_STATE  = "purchases_empty_state"
    const val ERROR_STATE  = "purchases_error_state"
    const val RETRY_BUTTON = "purchases_retry_button"
    const val TRACKING_LINK = "purchase_tracking_link"
}
```

**Repository unit tests** use `MockWebServer` wired to the real Retrofit/Moshi
service so DTO mapping and `detail` parsing are exercised end-to-end (no mocked JSON
parser):

```kotlin
@RunWith(JUnit4::class)
class PurchasesRepositoryTest {
    private val server = MockWebServer()
    private lateinit var repo: PurchasesRepository

    @Before fun setUp() { /* build Retrofit against server.url("/") */ }
    @After  fun tearDown() { server.shutdown() }

    @Test fun list_maps_success() = runTest { /* enqueue fixture; assert Success */ }
    @Test fun list_maps_detail_string_error() = runTest { /* 400 {"detail":"bad"} */ }
    @Test fun list_maps_detail_array_error() = runTest { /* 422 [{"msg":...}] */ }
    @Test fun search_sends_q_param() = runTest { /* assert recordedRequest path */ }
}
```

**ViewModel unit tests** inject `FakePurchasesRepository` and a
`StandardTestDispatcher`, using `MainDispatcherRule` from `core-testing` and Turbine:

```kotlin
class PurchasesViewModelTest {
    @get:Rule val mainRule = MainDispatcherRule()

    @Test fun emits_loading_then_content() = runTest {
        val vm = PurchasesViewModel(fakeRepo, savedState)
        vm.uiState.test {
            assertThat(awaitItem()).isInstanceOf(UiState.Loading::class.java)
            assertThat(awaitItem()).isInstanceOf(UiState.Content::class.java)
        }
    }

    @Test fun search_is_debounced() = runTest { /* type 3x, advanceTimeBy(300) */ }
    @Test fun paging_first_page() = runTest {
        val items = vm.pagingFlow.asSnapshot()  // paging-testing
        assertThat(items).hasSize(20)
    }
}
```

**Compose UI tests** use `createAndroidComposeRule` (Hilt test runner) feeding a
fake-backed ViewModel and asserting via test tags + semantics. Paging UI tests pass
`PagingData.from(fixtureList)` collected as `collectAsLazyPagingItems()`.

## 5. API Contract

This is a test ticket; it defines **no new endpoints**. It pins the existing
contract owned by AND-218/AND-220 via recorded fixtures, asserting the client matches
the server shape. Reference paths and shapes exercised:

> **[CORRECTED]** The paths, the response envelope, and the field names below were all wrong
> in the draft. Verified shapes (OpenAPI `components.schemas` + `src/api/endpoints/purchases.ts`
> + `src/api/types.ts`) follow.

- **List / history:** `GET /ui/purchase-history/transactions?limit={n}&status={STATUS}` →
  a **bare array** of `PurchaseTransactionSummary` (no `items`/`page`/`total` wrapper):
  ```json
  [
    { "txn_id": "txn_123", "created_at": 1746100800, "updated_at": 1746187200,
      "status": "COMPLETED", "amount": 42.99, "currency": "USD",
      "merchant_id": "merch_acme", "external_ref": "PO-7781", "description": "Acme order" }
  ]
  ```
  `limit` defaults to 50 in the web client; `status` is an uppercase enum
  (`PENDING`, `COMPLETED`, `CANCELLED`, `REVERTED`, `CANCEL_REQUESTED`, `CANCEL_DENIED`).
- **Search:** `GET /ui/purchase-history/transactions/search?q={query}&limit={n}` →
  same `PurchaseTransactionSummary[]` array. `status` filtering of search results is
  **client-side**.
- **Detail (AND-220):** `GET /ui/purchase-history/transactions/{txn_id}` →
  `PurchaseTransactionInfo` (extends the summary; **no inline line-items array**):
  ```json
  { "txn_id": "txn_123", "created_at": 1746100800, "updated_at": 1746187200,
    "status": "COMPLETED", "amount": 42.99, "currency": "USD",
    "buyer_id": "user_9", "version": 3,
    "shipping": { "carrier": "ups", "tracking_number": "1Z999",
                  "tracking_url": "https://track/1Z999", "status": "in_transit",
                  "shipped_at": 1746100900, "carrier_events": [] },
    "completed_at": 1746187200, "metadata": { "cart_id": "cart_55" } }
  ```
  Order line items are fetched **separately** via `GET /ui/shoppingcart/carts/{cart_id}`
  (`getCartItems`) only when `metadata.cart_id` is a string; item prices there are in
  **cents** (`unit_price_cents`, `line_total_cents`). The tracking affordance is shown when
  `shipping.tracking_number` is present and links to `shipping.tracking_url`; it is absent when
  `shipping`/`tracking_number` is null.
- **Error envelope:** any non-2xx returns FastAPI `{"detail": ...}` in one of three
  shapes (`string`, `[{ "msg": "..." }]`, `{ "code": "...", ... }`); tests assert all
  three normalize through the shared error mapper. **[VERIFIED]** — matches
  `normalizeErrorDetail` in `src/api/client.ts` (handles string, array-of-`{msg}`, and
  object-with-`code`). Observed error statuses on these endpoints: `400/401/403/422/429`
  (note **429** and **403**, in addition to those the draft listed).
- **Auth/CSRF:** purchases endpoints require the cookie session (`credentials: include`) plus a
  bearer `Authorization` header and the `X-CSRF-Token` header sourced from the `ui_csrf` cookie.
  The 401→`POST /ui/session/refresh`→retry-once behavior is owned by `core-network` and tested
  in its own suite; here it is **out of scope** except one ViewModel test asserting a 401
  surfaces as a recoverable error (not a crash). **[VERIFIED]** against `src/api/client.ts`
  (`X-CSRF-Token` from `ui_csrf`, single refresh via `POST /ui/session/refresh`, one retry).

Fixtures stored at
`feature-purchases/src/test/resources/fixtures/purchases_*.json`.

## 6. Data & State Management

The suite asserts the `UiState` contract produced by AND-221:

```kotlin
sealed interface PurchasesUiState {
    data object Loading : PurchasesUiState
    data class Content(val isRefreshing: Boolean) : PurchasesUiState  // list via paging flow
    data object Empty : PurchasesUiState
    data class Stale(val lastUpdated: Instant) : PurchasesUiState
    data class Error(val message: String, val retryable: Boolean) : PurchasesUiState
}
```

- **Paging:** `Flow<PagingData<PurchaseUi>>` is asserted with `asSnapshot { }` and
  `AsyncPagingDataDiffer`; Room-backed `RemoteMediator` (cache) is faked so tests do
  not require a real database — though a Robolectric in-memory Room instance is used
  for one mapping round-trip test to confirm cache entity ↔ domain parity.
- **Search state:** the query string lives in `SavedStateHandle`; a test asserts the
  query survives a simulated process-death (new ViewModel built from the same
  `SavedStateHandle`).
- **Stale rule:** cache present + refresh failure → `Stale`; cache absent + failure →
  `Error`. Both branches have a dedicated test.

No DataStore/preferences state is under test here.

## 7. Error Handling & Resilience

- **Mapping coverage:** explicit tests for 400, 401, 422, 500, malformed JSON, and an
  empty body, each asserting a non-crashing `ApiResult.Error` with a stable message.
- **Timeout/offline:** `MockWebServer` is configured with
  `SocketPolicy.NO_RESPONSE` and a short client timeout (test override) to assert the
  repository surfaces a timeout error rather than hanging; the ViewModel maps it to
  `Error(retryable = true)` or `Stale` per the cache rule.
- **Retry:** a test enqueues `Error` then `Success` and asserts the retry path
  transitions `Error → Loading → Content` and issues exactly one extra request.
- **Backoff:** the bounded-backoff retry policy for idempotent GETs lives in
  `core-network`; this suite asserts only that retries are bounded (no infinite loop)
  by capping the fake at N failures and asserting the ViewModel stops at `Error`.
- All resilience tests run on a virtual-time dispatcher; no real delays.

## 8. Security & Privacy

- Tests must not contain real credentials, cookies, CSRF tokens, or PII. Fixtures use
  synthetic merchants, order ids (`ord_*`), and tracking numbers.
- A lint/test assertion verifies fixture bodies contain no `Set-Cookie` or
  `ui_csrf` values that could be mistaken for live secrets.
- The tracking-link test asserts the app opens the URL via the standard intent path
  and does **not** leak session cookies into the outbound URL (URL is exactly the
  server-provided `tracking_url`).
- No production security behavior is changed; cookie-jar/CSRF handling is verified in
  the `core-network` suite, not here.

## 9. Accessibility & i18n

- **A11y assertions:** UI tests assert content descriptions on the search field,
  retry button, and tracking link via Compose semantics (`onNodeWithContentDescription`
  / `assertHasClickAction`), and that the empty/error states expose readable text
  nodes (not icon-only).
- **i18n:** UI assertions match against string resources resolved through the test
  `Context` (`context.getString(R.string.purchases_empty)`), never hardcoded English,
  so the suite stays locale-safe.
- One test sets a pseudo-locale and confirms the history list still renders (no layout
  crash, tags still present).

## 10. Telemetry & Logging

- No new telemetry is added by this ticket. If AND-221 emits analytics events
  (e.g., `purchases_viewed`, `purchases_search`), a test injects a
  `FakeAnalytics` and asserts the event is logged once per user action with the
  expected non-PII payload (no merchant names or order ids beyond a hashed id).
- Test failures should log the recorded `MockWebServer` request and the last `UiState`
  for diagnosability (custom JUnit rule `DumpStateOnFailure`).

## 11. Testing Strategy

This **is** the testing ticket; the strategy is the deliverable.

- **Frameworks:** JUnit4, `kotlinx-coroutines-test` (`runTest`,
  `StandardTestDispatcher`, `advanceTimeBy`), Turbine, MockK, Truth,
  `androidx.paging:paging-testing`, OkHttp `MockWebServer`, Compose UI test, Hilt
  testing, Robolectric (JVM Compose/Room where it avoids an emulator).
- **Layers & counts (target):**
  - Repository/mapping (JVM): ~12 tests (success, 4 error codes, 3 `detail` shapes,
    detail mapping, null tracking, search param, timeout).
  - ViewModel (JVM): ~10 tests (5 state transitions, paging snapshot, debounce,
    retry, stale vs error, savedState survival).
  - Compose UI (`androidTest`/Robolectric): ~8 tests (history render, append footer,
    empty, error+retry, search filter, detail render, tracking-link tap, tracking
    absent).
- **Coverage gate:** JaCoCo line coverage ≥ 80% for
  `com.testlogon.android.feature.purchases` and
  `com.testlogon.android.core.data.purchases` packages; build fails below threshold.
- **Execution:** `./gradlew :feature-purchases:testDebugUnitTest
  :core-data:testDebugUnitTest :feature-purchases:connectedDebugAndroidTest`
  (Robolectric variant runnable via `testDebugUnitTest` for screens that support it).
- **CI:** runs JVM + Robolectric tests on every PR to `android-port`; instrumented
  tests run on the managed-device / emulator job. No test touches the dev host.

## 12. Dependencies & Sequencing

- **Hard dependency:** AND-221 (Purchases ViewModel — state + paging) must be merged;
  its public `PurchasesViewModel`, `PurchasesUiState`, and paging flow are the
  primary subjects under test.
- **Transitive (must exist for full coverage):** AND-218 (repository + mapping),
  AND-219 (history + search UI), AND-220 (order detail + tracking UI). If AND-219/220
  UI is not yet merged, the corresponding Compose UI tests are written but marked
  `@Ignore` with the blocking ticket id and enabled when that screen lands.
- **Shared infra:** `core-testing` must expose `MainDispatcherRule` and the fixture
  loader; this ticket extends `core-testing` with `FakePurchasesRepository` and
  purchases fixtures (small, additive change).
- **Blocks:** nothing downstream depends on this ticket (it is a leaf test ticket);
  however the M5 release gate requires this suite green.

## 13. Risks & Open Questions

- **R1 — Paging test flakiness.** Paging 3 differ tests can be timing-sensitive.
  Mitigation: use `asSnapshot { }` and a controlled dispatcher; avoid `Thread.sleep`.
- **R2 — Compose-on-JVM limits.** Some detail/tracking interactions may need a real
  emulator (intent dispatch). Mitigation: split UI tests — pure rendering via
  Robolectric, intent/tracking via instrumented `androidTest`.
- **R3 — Contract drift.** Recorded fixtures can diverge from the live FastAPI schema.
  Mitigation: a `@Ignore`-able contract test that, when run with a flag, validates a
  fixture against `/openapi.json` (manual, not in PR CI given the unreliable host).
- **OQ1 — Field for amount:** ~~is monetary `total` an integer in minor units (cents)?~~
  **RESOLVED (corrected):** the field is `amount`, a JSON `number` in **decimal major units**
  (the web client passes it straight into `Intl.NumberFormat` currency, e.g. `42.99`). It is
  **not** an integer/cents value. (Note: the separate cart line-items DTO *does* use cents —
  `unit_price_cents`/`line_total_cents` — so the mapper must not conflate the two.)
  Source: OpenAPI `PurchaseTransactionSummary.amount: number`; `src/pages/purchases/
  PurchaseHistory.tsx: formatCurrency(txn.amount, txn.currency)`.
- **OQ2 — Search semantics:** **RESOLVED (corrected):** search is **server-side via a dedicated
  endpoint** `GET /ui/purchase-history/transactions/search?q=` (not a `q` param on the list
  endpoint). The web client additionally applies the `status` chip **client-side** to search
  results. Source: `src/api/endpoints/purchases.ts: searchTransactions`;
  `src/pages/purchases/PurchaseHistory.tsx`.
- **OQ3 — Stale vs Empty precedence** when cache is empty and refresh succeeds with
  zero items — assumed `Empty`; confirm with AND-221. **STILL OPEN** — `PurchasesUiState` is
  defined by AND-221, which is not in the verifiable sources here; this is a ViewModel-internal
  contract, not a backend/web one.

## 14. Acceptance Criteria

AC-1. `:core-data:testDebugUnitTest` and `:feature-purchases:testDebugUnitTest` pass
with all repository, mapping, and ViewModel tests green (FR-1..FR-7).

AC-2. Repository tests assert success mapping plus all three FastAPI `detail` error
shapes and 400/401/422/500 normalization (FR-1, FR-2), via `MockWebServer`.

AC-3. Detail mapping test covers items array and both present and null `tracking`
without crashing (FR-3).

AC-4. ViewModel tests assert the full `UiState` ordering for load/empty/error/retry/
stale and that search is debounced to a single call (FR-5, FR-7), using Turbine on a
test dispatcher.

AC-5. A paging test materializes the first page and asserts contents/size and
refresh/append (FR-6) using `paging-testing`.

AC-6. Compose UI tests render history (rows + append footer), empty, and error+retry
states, filter on search, and render order detail with a tracking link that, on tap,
opens the exact server-provided `tracking_url`; the link is absent when tracking is
null (FR-8, FR-9, FR-10).

AC-7. No test reads from the network at `18.222.237.167:8000`; all network is
`MockWebServer`/fakes (FR-11).

AC-8. JaCoCo line coverage ≥ 80% for the two target packages; the Gradle verification
task enforces it.

AC-9. Suite is deterministic: 10 consecutive local runs pass with zero flakes; no
`Thread.sleep`, real clock, or device-locale dependence.

## 15. Definition of Done

- All tests in §11 implemented under the paths in §2 and passing locally and in CI on
  branch `android-port`.
- `FakePurchasesRepository`, purchases fixtures, and `PurchasesTestTags` added to
  `core-testing` / `feature-purchases` and reused (no duplicated fakes).
- JaCoCo gate (≥80% for purchases packages) wired into the module Gradle config and
  green.
- Any UI test blocked by an unmerged AND-219/AND-220 screen is `@Ignore`d with a TODO
  citing the blocking ticket; all enable-able tests are enabled.
- Open questions OQ1–OQ3 resolved or recorded as follow-up against AND-218/AND-221.
- No production behavior changed beyond additive test seams (test tags, fakes); diff
  reviewed and approved; CI green on PR to `android-port`.

## 16. Citations & Assumption Audit

Each key technical claim, its verification verdict, and an exact source pointer.

1. **List/history endpoint is `GET /ui/purchase-history/transactions`.**
   VERDICT: **Corrected** (draft said `GET /ui/purchases`).
   SOURCE: OpenAPI `GET /ui/purchase-history/transactions`
   (`op=ui_list_transactions_...`); `src/api/endpoints/purchases.ts: listTransactions`.

2. **List response is a bare `PurchaseTransactionSummary[]` array (no `items`/`page`/`page_size`/`total` envelope).**
   VERDICT: **Corrected**.
   SOURCE: `src/api/endpoints/purchases.ts: listTransactions` (`api.get<PurchaseTransactionSummary[]>`);
   `src/api/types.ts: PurchaseTransactionSummary`.

3. **List query params are `limit` (web default 50) and `status` (uppercase enum); no `page`/`page_size`/`q`.**
   VERDICT: **Corrected**.
   SOURCE: OpenAPI `GET /ui/purchase-history/transactions | params=limit,status,...`;
   `src/pages/purchases/PurchaseHistory.tsx` (`listTransactions({ limit: 50, status: ...toUpperCase() })`).

4. **Summary DTO fields: `txn_id`, `created_at`, `updated_at`, `status`, `amount`, `currency`, `merchant_id?`, `external_ref?`, `description?`.**
   VERDICT: **Corrected** (draft said `id/merchant/total/orderedAt/itemCount`; there is no `item_count`).
   SOURCE: `src/api/types.ts: PurchaseTransactionSummary`; OpenAPI schema `PurchaseTransactionSummary`.

5. **`amount` is a decimal `number` in major units (e.g. 42.99), NOT integer minor units.**
   VERDICT: **Corrected** (resolves OQ1).
   SOURCE: OpenAPI `PurchaseTransactionSummary.amount: {type: number}`;
   `src/pages/purchases/PurchaseHistory.tsx: formatCurrency` passes `txn.amount` directly to `Intl.NumberFormat({style:"currency"})`.

6. **`created_at`/`updated_at` are Unix epoch SECONDS integers.**
   VERDICT: **Corrected** (draft used ISO-8601 `ordered_at`).
   SOURCE: OpenAPI `created_at: {type: integer}`; `src/pages/purchases/*.tsx: formatDate(ts) => new Date(ts * 1000)`.

7. **Search is a dedicated server endpoint `GET /ui/purchase-history/transactions/search?q=&limit=`, not a `q` param on list.**
   VERDICT: **Corrected** (resolves OQ2).
   SOURCE: OpenAPI `GET /ui/purchase-history/transactions/search | params=q,limit,...`;
   `src/api/endpoints/purchases.ts: searchTransactions`.

8. **Search `status` chip is applied client-side to search results.**
   VERDICT: **Verified**.
   SOURCE: `src/pages/purchases/PurchaseHistory.tsx` (`isSearchMode && statusFilter !== "all" ? transactions.filter(...) : transactions`).

9. **Search debounce window is ~300 ms.**
   VERDICT: **Verified** (web reference uses 300 ms).
   SOURCE: `src/pages/purchases/PurchaseHistory.tsx` (`setTimeout(() => setDebouncedQuery(value), 300)`).

10. **Detail endpoint is `GET /ui/purchase-history/transactions/{txn_id}` returning `PurchaseTransactionInfo`.**
    VERDICT: **Corrected** (draft said `GET /ui/purchases/{id}`).
    SOURCE: OpenAPI `GET /ui/purchase-history/transactions/{txn_id} | resp=200:PurchaseTransactionInfo`;
    `src/api/endpoints/purchases.ts: getTransaction`.

11. **Detail has NO inline line-items array; tracking is under the `shipping` object (`carrier`, `tracking_number`, `tracking_url`, ...).**
    VERDICT: **Corrected** (draft had `items[]` and a top-level `tracking` object).
    SOURCE: `src/api/types.ts: PurchaseTransactionInfo` (extends summary, adds `shipping?: PurchaseShipping`, `metadata`, etc.) and `PurchaseShipping`.

12. **Order line items are fetched separately via the cart endpoint `GET /ui/shoppingcart/carts/{cart_id}` when `metadata.cart_id` is present; item prices there are in cents.**
    VERDICT: **Verified**.
    SOURCE: `src/pages/purchases/TransactionDetail.tsx` (`CartItemsCard`, `getCartItems`, `unit_price_cents/100`, gated on `metadata.cart_id`).

13. **Tracking affordance shows when `shipping.tracking_number` present and links to `shipping.tracking_url`; absent when null.**
    VERDICT: **Corrected** (draft keyed visibility off a null `tracking` object).
    SOURCE: `src/pages/purchases/TransactionDetail.tsx` (anchor on `shipping.tracking_url`, `data-testid="tracking-link"`, guarded by `txn.shipping.tracking_number`).

14. **A separate `GET /ui/purchase-history/transactions/{txn_id}/tracking` (`CarrierTrackingView`) exists.**
    VERDICT: **Verified** (informational; not the primary path the detail screen reads).
    SOURCE: OpenAPI `GET /ui/purchase-history/transactions/{txn_id}/tracking`; `src/api/types.ts: CarrierTrackingView`.

15. **FastAPI error `detail` normalizes from three shapes: `string`, `[{msg}]`, `{code,...}`.**
    VERDICT: **Verified**.
    SOURCE: `src/api/client.ts: normalizeErrorDetail` / `mapAuthorizationError` (handles string, array-of-`{msg}`, object-with-`code`).

16. **Observed error statuses on purchases endpoints include 400/401/403/422/429.**
    VERDICT: **Corrected** (draft listed only 400/401/422/500; real index shows 403 and 429, and 500 is not enumerated).
    SOURCE: OpenAPI `GET /ui/purchase-history/transactions | resp=200:;422:HTTPValidationError;400;401;403;429`.

17. **Auth: cookie session (`credentials: include`) + bearer `Authorization` + `X-CSRF-Token` header sourced from the `ui_csrf` cookie.**
    VERDICT: **Verified**.
    SOURCE: `src/api/client.ts` (sets `Authorization: Bearer`, reads `getCookie("ui_csrf")`, sets `X-CSRF-Token`, `credentials: "include"`).

18. **401 triggers a single `POST /ui/session/refresh` then one retry of the original request.**
    VERDICT: **Verified**.
    SOURCE: `src/api/client.ts: refreshSession` (`POST /ui/session/refresh`) and the single-retry block in `api<T>`.

19. **All transaction-state actions (complete/revert/cancel request/respond, shipping) return `PurchaseTransactionInfo`; statuses are uppercase (`PENDING`, `COMPLETED`, `CANCELLED`, `REVERTED`, `CANCEL_REQUESTED`, `CANCEL_DENIED`).**
    VERDICT: **Verified** (out of test scope but corrects the draft's lowercase `shipped` example).
    SOURCE: OpenAPI `.../complete|/revert|/cancel/request|/cancel/respond|/shipping` (`resp=200:PurchaseTransactionInfo`); `src/pages/purchases/TransactionDetail.tsx: statusVariant` (uppercase cases).

20. **Android test stack/frameworks (JUnit4, kotlinx-coroutines-test, Turbine, MockK, Truth, `androidx.paging:paging-testing`, OkHttp MockWebServer, Compose UI test, Hilt testing, Robolectric).**
    VERDICT: **Unverified-assumption** (no Android sources in the reference tree; these are standard, framework ref).
    SOURCE: framework ref — Android testing docs (developer.android.com/training/testing), Turbine (cashapp.github.io/turbine), Paging test (developer.android.com/topic/libraries/architecture/paging/test).

21. **Dev host `http://18.222.237.167:8000`.**
    VERDICT: **Unverified-assumption** — not present in OpenAPI or frontend sources (the web client uses `VITE_API_BASE_URL`, `src/api/client.ts`); treat the literal IP as a deployment detail to confirm with infra.

22. **`PurchasesUiState` machine (Loading/Content/Empty/Stale/Error), Paging 3 usage, `SavedStateHandle` query persistence, stale-vs-empty rule.**
    VERDICT: **Unverified-assumption** — owned by AND-221, which is not in the verifiable sources. Tests assert against AND-221's public API as documented in §6; flag for confirmation against the merged ViewModel.

### Corrections made

- C-1 List endpoint: `GET /ui/purchases` → `GET /ui/purchase-history/transactions` (#1).
- C-2 List response shape: paged `{items,page,page_size,total}` envelope → **bare array** (#2).
- C-3 List query params: `page/page_size/q` → `limit/status` (#3).
- C-4 Summary DTO field names: `id/merchant/total/ordered_at/item_count` → `txn_id/.../amount/created_at` (no item count) (#4, #6).
- C-5 Money units: integer minor-units (cents) → decimal `number` major units (OQ1) (#5).
- C-6 Search: `q` param on list → dedicated `/search` endpoint; status filter is client-side (OQ2) (#7, #8).
- C-7 Detail endpoint: `GET /ui/purchases/{id}` → `GET /ui/purchase-history/transactions/{txn_id}` (#10).
- C-8 Detail shape: inline `items[]` + `tracking` object → no items array; tracking under `shipping`; items via separate cart fetch on `metadata.cart_id` (#11, #12).
- C-9 Tracking link visibility keyed on `shipping.tracking_number`/`tracking_url`, not a null `tracking` object (#13).
- C-10 Error statuses: added 403/429, removed unverified 500 (#16).
- C-11 Status enum casing corrected to uppercase; example `"shipped"` was not a valid txn status (#19).
- C-12 Paging caveat: backend is non-paginated; paging tests reframed as client-side over a `limit` window (FR-6).

### Open assumptions

- OA-1 (#20): Android test-stack library versions/availability — no Android module in the reference tree; standard framework choices, confirm against the repo's `gradle/libs.versions.toml`.
- OA-2 (#21): the literal dev-host IP `18.222.237.167:8000` is not in any provided source; the web client only references `VITE_API_BASE_URL`. Confirm with infra/CI config.
- OA-3 (#22): the entire `PurchasesUiState` contract, Paging 3 usage, and stale-vs-empty precedence (OQ3) are owned by AND-221 and unverifiable here; tests pin AND-221's public API and must be revalidated when it merges.

## 17. Test Plan

IDs `TC-AND-222-NN`. "Traces" links to §14 acceptance criteria. Targets: JVM = JVM
unit/Robolectric (local, no device); emulator = headless AVD `test35` (x86_64, API 35);
physical = Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). Repository/ViewModel/mapping
cases are pure JVM and never need a device; instrumented intent/browser-launch and ABI/API-skew
cases prefer the physical device.

- **TC-AND-222-01 — List success mapping (happy path).**
  Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: `MockWebServer` wired to the real Retrofit/Moshi purchases service; fixture
  `purchases_list_ok.json` is a **bare array** of `PurchaseTransactionSummary`.
  Steps: enqueue 200 with the fixture; call `repo.listTransactions(limit=50)`.
  Expected: `ApiResult.Success<List<Purchase>>`; first item maps `txn_id`, `amount` (42.99 as
  decimal — not /100), `currency`, `status`, `created_at` (epoch seconds), optional
  `merchant_id`/`external_ref`/`description`; recorded request path is
  `/ui/purchase-history/transactions?limit=50`.
  Traces: AC-1, AC-2.

- **TC-AND-222-02 — Error `detail` shape normalization (3 shapes + status codes).**
  Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: service as above.
  Steps: parameterized — enqueue (400, `{"detail":"bad"}`), (422, `{"detail":[{"msg":"x"}]}`),
  (403, `{"detail":{"code":"role_required"}}`), (429, `{"detail":"slow down"}`), (401 body),
  malformed JSON, and an empty body.
  Expected: each yields `ApiResult.Error` (never a crash) with a stable normalized message
  matching the `normalizeErrorDetail` rules; the `{code}` case maps to a human message.
  Traces: AC-2.

- **TC-AND-222-03 — Search passthrough to the dedicated endpoint.**
  Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: service as above.
  Steps: call `repo.searchTransactions("ac me & co")`; inspect recorded request.
  Expected: request hits `/ui/purchase-history/transactions/search` with URL-encoded
  `q=ac+me+%26+co` (or `%20`); blank/whitespace query issues **no** request.
  Traces: AC-2, AC-4.

- **TC-AND-222-04 — Detail mapping incl. `shipping` present and null.**
  Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: fixtures `purchase_detail_with_shipping.json` and `purchase_detail_no_shipping.json`.
  Steps: enqueue each 200; call `repo.getTransaction("txn_123")`.
  Expected: maps `PurchaseTransactionInfo`; with shipping present, `shipping.carrier/tracking_number/tracking_url`
  populated; with shipping absent, `shipping == null` and **no crash**; no `items[]` expected on
  the DTO.
  Traces: AC-3.

- **TC-AND-222-05 — Timeout / offline surfaces a retryable error.**
  Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: `MockWebServer` with `SocketPolicy.NO_RESPONSE`; short client timeout override.
  Steps: call `repo.listTransactions()`.
  Expected: `ApiResult.Error` (timeout/IO) within the test timeout, no hang; ViewModel maps to
  `Error(retryable=true)` or `Stale` per the cache rule.
  Traces: AC-2, AC-7 (no live host).

- **TC-AND-222-06 — ViewModel state ordering: load/empty/error/retry.**
  Type: unit (JVM, Turbine + `StandardTestDispatcher`). Target: JVM.
  Preconditions: `FakePurchasesRepository`; `MainDispatcherRule`.
  Steps: drive success → assert `Loading→Content`; empty array → `Loading→Empty`;
  error result → `Loading→Error(retryable)`; then `retry()` with success → `Error→Loading→Content`,
  asserting exactly one extra repo call.
  Expected: emissions match the ordered `PurchasesUiState` sequence.
  Traces: AC-4.

- **TC-AND-222-07 — ViewModel stale-vs-empty and savedState survival.**
  Type: unit (JVM). Target: JVM.
  Preconditions: fake with seeded cache; `SavedStateHandle`.
  Steps: (a) cache present + refresh failure → assert `Stale`; cache absent + failure → assert
  `Error`. (b) Set a search query, rebuild the ViewModel from the same `SavedStateHandle`
  (simulated process death), assert query restored.
  Expected: stale/empty branches and query persistence hold.
  Note: OQ3 (zero-item success precedence) is asserted as `Empty` per §6 assumption; revisit if
  AND-221 differs.
  Traces: AC-4.

- **TC-AND-222-08 — Search debounce collapses rapid input to one call.**
  Type: unit (JVM, virtual time). Target: JVM.
  Preconditions: fake recording `searchQueries`; controlled dispatcher.
  Steps: emit 3 query changes within <300 ms, then `advanceTimeBy(300)`.
  Expected: exactly one `searchTransactions` call with the final query string; no `Thread.sleep`.
  Traces: AC-4, AC-9.

- **TC-AND-222-09 — Paging / list materialization.**
  Type: unit (JVM, `paging-testing`). Target: JVM.
  Preconditions: fake `PagingData.from(fixtureList)` (or `asSnapshot`); list sized to `limit`.
  Steps: collect `pagingFlow.asSnapshot { }`.
  Expected: snapshot equals the fixture order/contents/size. Because the backend is
  **non-paginated** (bare array bounded by `limit`), there is no server cursor; a server-driven
  append assertion is N/A and, if AND-221 lacks Paging 3, this case is `@Ignore`d with that note.
  Traces: AC-5.

- **TC-AND-222-10 — History UI: rows, loading footer, empty state, search filter.**
  Type: Compose-UI (Robolectric where feasible, else emulator). Target: emulator (or JVM/Robolectric).
  Preconditions: fake-backed ViewModel; `PurchasesTestTags`.
  Steps: render with fixture list → assert a node per item under `HISTORY_LIST`; drive append/fetching
  → assert loading footer; render empty result → assert `EMPTY_STATE` with readable text;
  type a query → assert filtered visible rows.
  Expected: all states render with the expected tags/content.
  Traces: AC-6.

- **TC-AND-222-11 — Detail UI: render + tracking link present/absent.**
  Type: Compose-UI rendering (Robolectric/emulator). Target: emulator (or JVM/Robolectric).
  Preconditions: detail fixtures with and without `shipping.tracking_number`.
  Steps: render detail; assert merchant/amount/status/created render; with tracking present assert
  `TRACKING_LINK` exists and `assertHasClickAction()`; with tracking absent assert `TRACKING_LINK`
  does not exist.
  Expected: tracking affordance visibility keyed on `shipping.tracking_number`.
  Traces: AC-6.

- **TC-AND-222-12 — Tracking link opens the exact server URL (real intent dispatch).**
  Type: instrumented/e2e (intent capture). Target: **physical device (SM-A156U)** — real
  `ACTION_VIEW` browser launch behavior; fall back to emulator only if no device.
  Preconditions: Espresso-Intents (`Intents.init()`) or fake URL handler; detail with
  `tracking_url="https://track/1Z999"`.
  Steps: tap `TRACKING_LINK`.
  Expected: an `ACTION_VIEW` intent with `data == tracking_url` exactly (no appended session
  cookies/tokens, no host rewrite). MUST run on the physical device when validating the real
  chooser/Custom-Tabs path.
  Traces: AC-6, plus security (no cookie leak in URL).

- **TC-AND-222-13 — Resilience UI: offline/error renders Retry that invokes ViewModel retry.**
  Type: Compose-UI (Robolectric/emulator). Target: emulator (or JVM/Robolectric).
  Preconditions: fake forced to error; spy/record retry invocation.
  Steps: render → assert `ERROR_STATE` + `RETRY_BUTTON` (readable text, not icon-only);
  click `RETRY_BUTTON`.
  Expected: ViewModel retry path invoked once; on subsequent success state transitions to content.
  Traces: AC-6.

- **TC-AND-222-14 — Accessibility: content descriptions, readable states, pseudo-locale.**
  Type: Compose-UI a11y (Robolectric/emulator). Target: emulator (or JVM/Robolectric).
  Preconditions: a11y assertions enabled; strings resolved via `context.getString(...)`.
  Steps: assert content descriptions on search field, retry button, tracking link
  (`onNodeWithContentDescription` / `assertHasClickAction`); assert empty/error expose text nodes;
  set a pseudo-locale and assert the list still renders with tags intact.
  Expected: no icon-only controls; no hardcoded English; no layout crash under pseudo-locale.
  Traces: AC-6, AC-9.

- **TC-AND-222-15 — No live-host network + ABI/API-skew smoke.**
  Type: instrumented/e2e. Target: **physical device (SM-A156U, arm64-v8a, API 34)** AND emulator
  (`test35`, x86_64, API 35) to catch ABI/API-34-vs-35 differences.
  Preconditions: network monitoring/strict-mode or a guard that fails on any connection to
  `18.222.237.167:8000`.
  Steps: run the instrumented purchases suite on both targets.
  Expected: zero connections to the dev host (all served by `MockWebServer`/fakes); suite passes
  identically on arm64/API-34 and x86_64/API-35.
  Traces: AC-7, AC-9.

### Coverage matrix

| §14 Acceptance Criterion | Covered by |
| --- | --- |
| AC-1 (core-data + feature unit tests green) | TC-01, TC-06..TC-09 |
| AC-2 (success + 3 detail error shapes + status codes via MockWebServer) | TC-01, TC-02, TC-03, TC-05 |
| AC-3 (detail items/tracking present+null, no crash) | TC-04, TC-11 |
| AC-4 (UiState ordering + debounce via Turbine) | TC-06, TC-07, TC-08, TC-03 |
| AC-5 (paging first page contents/size, refresh/append) | TC-09 |
| AC-6 (Compose history/empty/error+retry/search/detail+tracking) | TC-10, TC-11, TC-12, TC-13 |
| AC-7 (no live-host network) | TC-05, TC-15 |
| AC-8 (JaCoCo ≥80% for the two packages) | Enforced by Gradle gate; exercised by TC-01..TC-14 |
| AC-9 (deterministic, no sleep/clock/locale) | TC-08, TC-14, TC-15 |
