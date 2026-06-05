---
id: AND-209
title: Catalog tests
milestone: M5
epic: E28
priority: P2
size: M
status: draft
depends_on: [AND-204, AND-205, AND-206, AND-207, AND-208]
blocks: []
---

# AND-209 — Catalog tests

## 1. Overview & Goal

This ticket delivers the automated test suite that locks down the behaviour of the
M5 Catalog/Shop feature stack. The catalog feature was implemented across
AND-204 (Catalog API + DTOs), AND-205 (category browse + paging), AND-206
(product detail + add-to-cart), AND-207 (full-text search), and AND-208
(Browse/Detail/Search ViewModels). None of those tickets owned a comprehensive,
regression-grade test corpus; their acceptance criteria asserted only that the
happy path "maps", "renders", or is "unit-tested" at a minimal level. AND-209
closes that gap.

The goal is twofold, as stated in the source backlog scope ("Repo + UI tests"):

1. **Repository / data-layer tests** — JVM unit tests over `CatalogRepository`,
   the Retrofit `CatalogApi` (via OkHttp `MockWebServer`), Moshi DTO
   adapters, the `ApiResult<T>` mapping path, the Room cache DAO, and the
   Paging 3 `PagingSource`. These run on the local JVM (`testDebugUnitTest`).
2. **UI tests** — Compose UI tests (`androidx.compose.ui.test`) over the
   `CatalogBrowseScreen`, `ProductDetailScreen`, and `CatalogSearchScreen`
   composables, driven by fake/stubbed ViewModel state, asserting render,
   pagination, loading/empty/error states, and add-to-cart interaction.

Definition of success: the suite compiles, runs green in CI on the
`android-port` branch, exercises the full set of catalog UiState branches, and
fails deterministically when a catalog regression is introduced. The backlog
acceptance is simply **"Pass."** — interpreted here as: all new tests pass, and
the catalog modules' line coverage meets the threshold defined in §14.

This is a test-only ticket. It introduces **no production code changes** beyond
the minimum required to make catalog classes testable (e.g. constructor
injection seams, `@VisibleForTesting` accessors). Any such seam must be
non-behavioural.

## 2. Context & References

- Repo: `spannella/testlogon`, Android app under `android/`, branch
  `android-port`. Namespace/applicationId base `com.testlogon.android`.
- Module layering under test: `feature-catalog` (Compose screens + ViewModels
  from AND-205/206/207/208) → `core-data` (`CatalogRepository`, Room cache) →
  `core-network` (`CatalogApi`, `ApiResult`, error mapping) → `core-model`
  (catalog DTOs/domain models from AND-204). Shared test utilities live in
  `core-testing`.
- Stack relevant here: Kotlin 2.0.21, Coroutines/Flow, Hilt (KSP), Retrofit
  2.11 + OkHttp 4.12 + Moshi 1.15, Room 2.6, Paging 3, Jetpack Compose +
  Material 3. JDK 17, AGP 8.7.3, Gradle 8.9.
- Web reference for catalog payload shapes and search semantics: FastAPI
  OpenAPI at `http://18.222.237.167:8000/openapi.json`; web API layer
  `frontend/src/api/endpoints/*.ts` (catalog/shop endpoints) and shared types
  `frontend/src/api/types.ts`. These are the source of truth for the JSON
  fixtures captured in §5.
- Upstream tickets owning the code under test: AND-204, AND-205, AND-206,
  AND-207, AND-208. This ticket depends on all five being merged.
- Auth/session and global networking concerns (cookie jar, CSRF header, 401
  refresh) are NOT re-tested here — they are owned by the core-network/auth
  tickets. Catalog tests assume an authenticated `OkHttpClient` and only assert
  catalog-specific request/response handling.

## 3. Functional Requirements

The test suite MUST cover the following observable behaviours of the catalog
feature. Each is a contract the tests assert, not new functionality.

**Repository / data layer**

- FR-1: `CatalogApi` issues `GET /catalog/categories`, `GET /catalog/items`
  (paged, category-filtered), `GET /catalog/items/{itemId}`, and
  `GET /catalog/search` with the correct path, query params, and headers.
- FR-2: Moshi correctly deserialises catalog category, item-summary, and
  item-detail payloads, including nullable/optional fields (description, SKU,
  media list, sale price) and snake_case → camelCase mapping.
- FR-3: `CatalogRepository` returns `ApiResult.Success` on 2xx, and maps 4xx/5xx
  and FastAPI `detail` shapes (string | `[{msg}]` | `{code,...}`) to
  `ApiResult.Error` with the correct message/code.
- FR-4: The Room catalog cache is written on successful fetch and read back as a
  stale fallback when the network call fails; cache freshness/TTL behaviour is
  asserted.
- FR-5: The Paging 3 `CatalogPagingSource` returns `LoadResult.Page` with
  correct `nextKey`/`prevKey`, terminates paging when the backend returns the
  last page, and surfaces `LoadResult.Error` on failure.
- FR-6: Search maps query text to the `q` param and returns matching items;
  empty result sets and blank queries are handled per AND-207.

**UI layer**

- FR-7: `CatalogBrowseScreen` renders category headers and an item grid from
  `Browse` success state, shows a loading indicator for the loading state, an
  empty state for zero items, and an error state with a retry affordance.
- FR-8: Browse paginates: scrolling to the end of the grid triggers an append
  load and renders additional items (asserted against `PagingData` fed through a
  test `Pager`).
- FR-9: `ProductDetailScreen` renders name, price (and sale price when
  present), description, and media; the **Add to cart** button is enabled for
  in-stock items, invokes the ViewModel callback, and reflects success.
- FR-10: `CatalogSearchScreen` renders results for a non-empty query, shows an
  empty/"no results" state, and debounces/forwards query input to the
  ViewModel.
- FR-11: All three screens expose stable `testTag` identifiers and meaningful
  content descriptions used by the tests (and accessibility — see §9).

## 4. Technical Design

### 4.1 Source sets and locations

- JVM unit tests (repo, API, DTO, ViewModel): `core-data/src/test/...`,
  `core-network/src/test/...`, `feature-catalog/src/test/...` under package
  `com.testlogon.android.<module>.catalog`.
- Compose UI tests: `feature-catalog/src/androidTest/...` under
  `com.testlogon.android.feature.catalog`, using a Robolectric-backed
  unit-test variant where feasible to keep the suite JVM-runnable, with a
  device/emulator `androidTest` variant for the full Compose surface.

### 4.2 Repository / network tests

Use OkHttp `MockWebServer` to drive a real Retrofit `CatalogApi` instance so
that path, query, headers, and Moshi mapping are all exercised end-to-end at the
network seam.

```kotlin
class CatalogApiTest {
    private val server = MockWebServer()
    private lateinit var api: CatalogApi

    @Before fun setUp() {
        server.start()
        val moshi = Moshi.Builder().build()
        api = Retrofit.Builder()
            .baseUrl(server.url("/"))
            .client(OkHttpClient.Builder().build())
            .addConverterFactory(MoshiConverterFactory.create(moshi))
            .build()
            .create(CatalogApi::class.java)
    }

    @After fun tearDown() = server.shutdown()

    @Test fun `items request sends category and page params`() = runTest {
        server.enqueue(MockResponse().setBody(Fixtures.ITEMS_PAGE_1))
        api.getItems(categoryId = "cat_1", page = 1, pageSize = 20)
        val req = server.takeRequest()
        assertEquals("/catalog/items?category_id=cat_1&page=1&page_size=20",
            req.path)
    }
}
```

`CatalogRepository` tests use a fake `CatalogApi` (hand-written or MockK) plus an
in-memory Room database (`Room.inMemoryDatabaseBuilder(...).allowMainThreadQueries()`)
to assert success mapping, error mapping, and stale-cache fallback:

```kotlin
@Test fun `network failure falls back to cached items`() = runTest {
    dao.upsertItems(cachedItems)
    fakeApi.itemsResult = ApiResult.Error(ApiError.Network)
    val result = repository.items(categoryId = "cat_1").first()
    assertEquals(cachedItems, (result as ApiResult.Success).data)
}
```

`CatalogPagingSource` is tested directly via `PagingSource.load(...)` with
`Refresh`/`Append` params, asserting `LoadResult.Page` keys and the terminal
`nextKey == null` case.

### 4.3 ViewModel tests

ViewModels from AND-208 expose `StateFlow<UiState>`. Tests use a fake repository
and Turbine to assert state transitions. A `MainDispatcherRule` swaps
`Dispatchers.Main` for a `StandardTestDispatcher`.

```kotlin
@get:Rule val mainRule = MainDispatcherRule()

@Test fun `browse emits Loading then Content`() = runTest {
    fakeRepo.categories = ApiResult.Success(sampleCategories)
    val vm = CatalogBrowseViewModel(fakeRepo, savedState)
    vm.uiState.test {
        assertIs<CatalogBrowseUiState.Loading>(awaitItem())
        assertIs<CatalogBrowseUiState.Content>(awaitItem())
        cancelAndIgnoreRemainingEvents()
    }
}
```

### 4.4 Compose UI tests

Screens are tested in isolation by passing pre-built UiState (or a fake
ViewModel) rather than wiring Hilt. `PagingData` is supplied via
`flowOf(PagingData.from(items))` and collected with `collectAsLazyPagingItems()`.

```kotlin
@get:Rule val composeRule = createComposeRule()

@Test fun browse_rendersGrid_andPaginates() {
    val items = (1..40).map { sampleItem("item_$it") }
    composeRule.setContent {
        CatalogBrowseScreen(
            state = CatalogBrowseUiState.Content(categories),
            items = flowOf(PagingData.from(items)).collectAsLazyPagingItems(),
            onItemClick = {}, onRetry = {},
        )
    }
    composeRule.onNodeWithTag("catalog_grid").assertIsDisplayed()
    composeRule.onNodeWithTag("catalog_grid")
        .performScrollToNode(hasTestTag("item_40"))
    composeRule.onNodeWithTag("item_40").assertIsDisplayed()
}
```

### 4.5 Test utilities (core-testing)

Add to `core-testing`: `MainDispatcherRule`, `Fixtures` (JSON constants from
§5), `FakeCatalogApi`, `FakeCatalogRepository`, and `sampleItem(...)` /
`sampleCategory(...)` builders. These are shared so AND-21x feature tests can
reuse them.

## 5. API Contract

This ticket consumes — it does not define — the catalog API contract (owned by
AND-204). The fixtures below are captured verbatim from the dev backend and used
as `MockWebServer` bodies and Moshi deserialisation inputs. Shapes must match
`/openapi.json` and `frontend/src/api/types.ts`.

`GET /catalog/categories` → `200`:

```json
{ "categories": [
  { "id": "cat_1", "name": "Laptops", "item_count": 42, "image_url": null }
] }
```

`GET /catalog/items?category_id=cat_1&page=1&page_size=20` → `200`:

```json
{
  "items": [
    { "id": "item_1", "name": "TL Pro 14", "sku": "TLP14",
      "price_cents": 199900, "sale_price_cents": 179900,
      "thumbnail_url": "http://18.222.237.167:8000/media/i1.jpg",
      "in_stock": true }
  ],
  "page": 1, "page_size": 20, "total": 42, "has_next": true
}
```

`GET /catalog/items/item_1` → `200`:

```json
{ "id": "item_1", "name": "TL Pro 14", "sku": "TLP14",
  "description": "14-inch dev laptop.", "price_cents": 199900,
  "sale_price_cents": 179900, "in_stock": true,
  "media": [ { "type": "image", "url": "http://.../i1.jpg" } ] }
```

`GET /catalog/search?q=pro&page=1` → `200`: same item-summary array shape as
`/catalog/items`. Empty: `{ "items": [], "page": 1, "page_size": 20,
"total": 0, "has_next": false }`.

Error fixtures (FastAPI `detail`) used to test mapping:
`{"detail":"Category not found"}` (string),
`{"detail":[{"msg":"field required","loc":["query","q"]}]}` (array),
`{"detail":{"code":"RATE_LIMITED"}}` (object). Status codes tested: 400, 401,
404, 422, 500, and a simulated timeout/socket failure.

## 6. Data & State Management

The suite asserts the catalog state machines defined upstream rather than
introducing new state. State types under test (from AND-208):

- `CatalogBrowseUiState`: `Loading | Content(categories) | Empty | Error(message,
  retryable)`, plus a `LazyPagingItems<CatalogItem>` stream whose
  `loadState.refresh/append` is `Loading | NotLoading | Error`.
- `ProductDetailUiState`: `Loading | Content(item, addToCartState) | Error`,
  where `addToCartState` is `Idle | InProgress | Added | Failed`.
- `CatalogSearchUiState`: `Idle | Loading | Results(items) | Empty(query) |
  Error`.

Tests verify the persisted/cached layer: Room `CatalogDao` upsert + query, and
`SavedStateHandle` restoration of the selected `categoryId` and search `query`
across ViewModel re-creation. DataStore prefs are not in scope for catalog and
are noted as N/A here. Paging `nextKey` derivation from `has_next`/`page` is
asserted in the `PagingSource` tests.

## 7. Error Handling & Resilience

Because the dev backend is unreliable, the suite explicitly exercises failure
and degraded paths, not just the happy path:

- Mapped HTTP errors (400/401/404/422/500) → correct `ApiResult.Error` subtype
  and user-facing message from the `detail` shape (§5).
- Timeout / `SocketTimeoutException` and `IOException` → `ApiError.Network`,
  surfaced as a retryable error UiState.
- Stale-cache fallback (FR-4): on network failure with a populated Room cache,
  the repository returns cached data and signals staleness; tested explicitly.
- Bounded retry for idempotent GETs: the test asserts that a transient 5x/IO
  failure on a GET is retried per the configured policy and that retries are
  bounded (no infinite loop) — using `MockWebServer` enqueueing fail-then-200.
- Compose: error UiState renders an error message + **Retry** button, and
  tapping Retry invokes the callback exactly once (`verify(exactly = 1)`).
- Paging append error renders an inline retry footer without discarding loaded
  items.

The 401→`/ui/session/refresh`→retry flow is owned by core-network and is NOT
re-tested here; catalog tests treat 401 as a plain mapped error.

## 8. Security & Privacy

No new attack surface. The suite asserts a few security-relevant contracts:

- Catalog requests carry no credentials in URLs/query strings (assert
  `MockWebServer` recorded request paths contain no tokens/passwords).
- `X-CSRF-Token` header presence on any non-GET catalog calls is left to the
  shared OkHttp interceptor tests; catalog GETs are CSRF-exempt and asserted to
  send no body.
- Test fixtures contain only synthetic data (no real user PII or live
  credentials); the `spannella@gmail.com` account or any real session cookie
  MUST NOT appear in fixtures or committed `MockWebServer` recordings.
- Logging assertions confirm no PII/payload bodies are logged at non-debug
  levels (cross-checked against §10).

## 9. Accessibility & i18n

UI tests double as accessibility regression tests:

- Each interactive node (item card, add-to-cart button, retry button, search
  field) MUST have a non-empty `contentDescription`; tests assert via
  `onNodeWithContentDescription(...)` and `assertHasClickAction()`.
- Touch targets: assert key controls meet the 48dp minimum
  (`assertHeightIsAtLeast(48.dp)` / `assertWidthIsAtLeast(48.dp)`).
- i18n: tests reference string resources by id, not hard-coded literals where
  practical, and assert no raw user-facing string is hard-coded in catalog
  composables (lint `HardcodedText` enforced in CI; a spot-check test reads from
  `R.string`). Pricing is asserted to be formatted via a locale-aware formatter
  (cents → currency), not string concatenation.

## 10. Telemetry & Logging

This ticket does not add analytics. It adds two test-side guarantees:

- A fake/test `AnalyticsLogger` is injected so screen-view and add-to-cart
  events emitted by the catalog feature (if present from AND-205/206) are
  asserted to fire with the expected event name and params, and to NOT include
  PII.
- A test verifies that repository/network logging is gated behind
  `BuildConfig.DEBUG` and that response bodies are not logged in release-mode
  config. If catalog code emits no telemetry, this section is satisfied by the
  PII-absence assertions in §8 and noted as minimal; event instrumentation
  proper is owned by the analytics ticket.

## 11. Testing Strategy

This IS the testing ticket; the strategy is the deliverable.

- **Frameworks:** JUnit4, MockK, OkHttp `MockWebServer`, Turbine
  (Flow/StateFlow assertions), `kotlinx-coroutines-test` (`runTest`,
  `StandardTestDispatcher`), Room in-memory DB, Paging 3
  `androidx.paging:paging-testing`, Compose `createComposeRule` /
  `createAndroidComposeRule`, optionally Robolectric to run Compose tests on the
  JVM. Hilt is bypassed in tests via direct constructor injection of fakes.
- **Test pyramid for catalog:** majority JVM unit tests (DTO, repo, API,
  ViewModel, paging source); a focused set of Compose UI tests per screen;
  no end-to-end against the live backend (the dev host is unreliable —
  `MockWebServer` only).
- **Determinism:** virtual time via test dispatchers; no real delays; no network;
  fixed fixtures. Tests must be order-independent and pass under
  `--rerun-tasks`.
- **Test matrix (representative):**
  - DTO: full payload, minimal payload (nulls), malformed JSON → error.
  - Repo: success, each error shape, timeout, stale-cache fallback, bounded
    retry.
  - PagingSource: refresh, append, terminal page, error.
  - Browse VM/UI: loading, content, empty, error+retry, pagination append.
  - Detail VM/UI: content with/without sale price, add-to-cart success/failure,
    out-of-stock disabled button.
  - Search VM/UI: results, empty query, no-results, error, debounce.
- **CI:** `./gradlew :core-data:testDebugUnitTest :core-network:testDebugUnitTest
  :feature-catalog:testDebugUnitTest` plus the Compose test task; run on the
  `android-port` CI workflow. Coverage via Jacoco/Kover for catalog modules.

## 12. Dependencies & Sequencing

- **Depends on (must be merged first):** AND-204 (DTOs/API), AND-205 (browse +
  paging UI), AND-206 (detail UI + add-to-cart), AND-207 (search), AND-208
  (ViewModels). The source backlog lists the direct dependency as **AND-208**;
  the transitive set above is required because the suite exercises all of them.
- **Reuses:** `core-testing` shared utilities (extended here with catalog
  fakes/fixtures). If `core-testing` lacks `MainDispatcherRule`/`MockWebServer`
  scaffolding, this ticket adds it (reusable downstream).
- **Blocks:** nothing functionally, but it is the quality gate for M5/E28; the
  catalog feature should not be considered "done" until AND-209 is green.
- **Sequencing:** land after AND-205/206/207/208 stabilise; if any of those
  expose insufficient test seams, raise minimal non-behavioural follow-ups
  rather than blocking.

## 13. Risks & Open Questions

- **Risk:** Compose UI tests are slow/flaky on emulators. *Mitigation:* prefer
  Robolectric-on-JVM for the Compose surface; reserve device tests for a smoke
  subset.
- **Risk:** Catalog screens may not yet expose `testTag`s. *Mitigation:* add
  non-behavioural `Modifier.testTag(...)` in feature-catalog as part of this
  ticket.
- **Risk:** Exact JSON field names may drift from the captured fixtures.
  *Mitigation:* fixtures derived from `/openapi.json`; a contract test diffs DTO
  field expectations against a checked-in OpenAPI snippet.
- **Open question:** Does the backend paginate via `page`/`page_size` or a
  cursor token? Fixtures assume offset paging per AND-205; confirm against
  `/openapi.json` before finalising `PagingSource` key tests.
- **Open question:** Does add-to-cart belong to a cart endpoint (M6) or a local
  stub in M5? Detail add-to-cart tests assert the AND-206 behaviour as merged;
  adjust if it is a no-op stub.
- **Open question:** Coverage threshold value — proposed 80% line for catalog
  modules; confirm with team CI policy.

## 14. Acceptance Criteria

- AC-1: New tests exist for `CatalogApi`, `CatalogRepository`, catalog DTO
  Moshi adapters, `CatalogDao`, `CatalogPagingSource`, and the three catalog
  ViewModels, covering the matrix in §11.
- AC-2: Compose UI tests exist for `CatalogBrowseScreen`, `ProductDetailScreen`,
  and `CatalogSearchScreen` covering loading/content/empty/error + the
  interactions in FR-7..FR-11.
- AC-3: All new tests pass locally and in CI on `android-port`
  (`testDebugUnitTest` for the three modules + the Compose test task) — backlog
  acceptance **"Pass."**
- AC-4: Error-path coverage includes each FastAPI `detail` shape, timeout/IO,
  stale-cache fallback, and bounded GET retry (§7).
- AC-5: Tests are deterministic (virtual time, no network, no real delays) and
  pass under `--rerun-tasks` and in randomised order.
- AC-6: Catalog-module line coverage ≥ 80% (or the team-agreed threshold),
  reported via Kover/Jacoco.
- AC-7: No production behaviour change; only test code and non-behavioural test
  seams (`testTag`, `@VisibleForTesting`) are added.
- AC-8: No real PII/credentials in fixtures or recordings.

## 15. Definition of Done

- All §14 acceptance criteria met and verified in CI.
- Test code reviewed and merged to `android-port`; CI green.
- Shared catalog test utilities (`FakeCatalogApi`, `FakeCatalogRepository`,
  `Fixtures`, `MainDispatcherRule`) added to `core-testing` and documented in
  KDoc for reuse.
- Coverage report published in CI artifacts; threshold gate enabled.
- Any test seams added to production catalog modules are reviewed as
  non-behavioural and lint-clean (`HardcodedText`, accessibility lint pass).
- Open questions in §13 resolved or filed as follow-up tickets; fixtures
  reconciled against the live `/openapi.json`.
- Ticket linked to AND-204..AND-208 as the M5/E28 catalog quality gate and
  marked done.
