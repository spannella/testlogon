---
id: AND-222
title: Purchases tests
milestone: M5
epic: E30
priority: P2
size: M
status: draft
depends_on: [AND-221]
blocks: []
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

FR-1. **Repository success mapping.** Given a recorded `GET /ui/purchases` 200 body,
the repository returns `ApiResult.Success<List<Purchase>>` whose fields match the DTO
(id, merchant, total, currency, status, orderedAt, itemCount).

FR-2. **Repository error mapping.** For 400/401/422/500 responses and for
non-`200` FastAPI `detail` shapes (`string`, `[{msg}]`, `{code,...}`), the repository
returns `ApiResult.Error` with a normalized message/code (asserted per shape).

FR-3. **Detail mapping (AND-220).** `GET /ui/purchases/{id}` maps items array and the
optional `tracking` object (carrier, trackingNumber, trackingUrl); a null tracking
object yields `tracking == null` (no crash).

FR-4. **Search passthrough (AND-219).** A non-blank query reaches the API as the `q`
query parameter, URL-encoded; blank/whitespace queries do not issue a search request.

FR-5. **ViewModel state machine (AND-221).** Assert the ordered `UiState` emissions
for: initial load success (Loading → Content), empty result (Loading → Empty), error
(Loading → Error with retryable flag), retry (Error → Loading → Content), and stale
cache (Stale shown when cached data exists but refresh fails).

FR-6. **Paging.** The ViewModel exposes `Flow<PagingData<PurchaseUi>>`; tests assert
the materialized first page contents, refresh, and append using
`AsyncPagingDataDiffer` / `PagingData` test helpers.

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

- **List / history:** `GET /ui/purchases?page={n}&page_size={s}&q={query}` →
  ```json
  { "items": [
      { "id": "ord_123", "merchant": "Acme", "total": 4299, "currency": "USD",
        "status": "shipped", "ordered_at": "2026-05-01T12:00:00Z", "item_count": 3 }
    ],
    "page": 1, "page_size": 20, "total": 57 }
  ```
- **Detail (AND-220):** `GET /ui/purchases/{id}` →
  ```json
  { "id": "ord_123", "merchant": "Acme", "total": 4299, "currency": "USD",
    "status": "shipped", "ordered_at": "2026-05-01T12:00:00Z",
    "items": [ { "sku": "SKU1", "name": "Widget", "qty": 2, "unit_price": 1500 } ],
    "tracking": { "carrier": "UPS", "tracking_number": "1Z999",
                  "tracking_url": "https://track/1Z999" } }
  ```
- **Error envelope:** any non-2xx returns FastAPI `{"detail": ...}` in one of three
  shapes (`string`, `[{ "msg": "..." }]`, `{ "code": "...", ... }`); tests assert all
  three normalize through the shared error mapper.
- **Auth/CSRF:** purchases endpoints require the cookie session + `X-CSRF-Token`
  header. The 401→`POST /ui/session/refresh`→retry behavior is owned by `core-network`
  and tested in its own suite; here it is **out of scope** except one ViewModel test
  asserting a 401 surfaces as a recoverable error (not a crash).

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
- **OQ1 — Field for `total`:** is monetary `total` an integer in minor units (cents)
  or a decimal string? Spec assumes minor-units integer per the JSON above; confirm
  against AND-218 mapping.
- **OQ2 — Search semantics:** does AND-219 search call `GET /ui/purchases?q=` server
  side, or filter cached client side? Tests target the server `q` param per AND-218;
  adjust if AND-219 is client-side only.
- **OQ3 — Stale vs Empty precedence** when cache is empty and refresh succeeds with
  zero items — assumed `Empty`; confirm with AND-221.

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
