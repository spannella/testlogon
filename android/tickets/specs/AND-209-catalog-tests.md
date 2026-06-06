---
id: AND-209
title: Catalog tests
milestone: M5
epic: E28
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
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

- FR-1: `CatalogApi` issues `GET /ui/catalog/categories`,
  `GET /ui/catalog/categories/{category_id}/items` (paged), and
  `GET /ui/catalog/items/search` with the correct path, query params, and
  headers. **[CORRECTED]** The original draft listed `/catalog/categories`,
  `/catalog/items?category_id=`, `/catalog/items/{itemId}`, and
  `/catalog/search`. None of those exist. All catalog routes are under the
  `/ui/catalog/` prefix; items are a sub-resource of a category (not a top-level
  `/items` collection with a `category_id` query filter); and there is **no
  standalone item-detail endpoint** — the web client derives item detail from the
  category-items list (see §4.2 / §16). Paging uses `page_size` + `next_token`
  (cursor), not `page`/`page_size` (offset) — see FR-5 and §16.
- FR-2: Moshi correctly deserialises catalog category and item payloads,
  including nullable/optional fields (`description`, `stock_count`,
  `stock_updated_at`, `position`, `creator_id`) and snake_case → camelCase
  mapping. **[CORRECTED]** There is no `sku`, no `media` list, and no
  `sale_price` on the item payload (see §16). Items carry `image_urls: string[]`
  (not `media[{type,url}]`), `stock_status: string` ("unlimited" | "low_stock" |
  "out_of_stock"), `low_stock_threshold`, and `attributes` (free-form object).
- FR-3: `CatalogRepository` returns `ApiResult.Success` on 2xx, and maps 4xx/5xx
  and FastAPI `detail` shapes (string | `[{msg}]` | `{code,...}`) to
  `ApiResult.Error` with the correct message/code.
- FR-4: The Room catalog cache is written on successful fetch and read back as a
  stale fallback when the network call fails; cache freshness/TTL behaviour is
  asserted.
- FR-5: The Paging 3 `CatalogPagingSource` returns `LoadResult.Page` with the
  `nextKey` derived from the response `next_token` (cursor paging) and
  `prevKey = null`, terminates paging when `next_token` is absent/null, and
  surfaces `LoadResult.Error` on failure. **[CORRECTED]** The backend uses
  cursor paging (`page_size` + `next_token`), not offset paging; there is no
  `page`/`total`/`has_next` in the list responses (`CatalogCategoryListOut` /
  `CatalogItemListOut` expose only `items` + nullable `next_token`). This
  resolves the §13 open question.
- FR-6: Search maps query text to the `q` param on
  `GET /ui/catalog/items/search` and returns matching items (`CatalogItemListOut`
  shape); empty result sets and blank queries are handled per AND-207. The web
  client only fires the search query when `q.trim().length > 0` (blank query =>
  no request); the Android client should mirror this.

**UI layer**

- FR-7: `CatalogBrowseScreen` renders category headers and an item grid from
  `Browse` success state, shows a loading indicator for the loading state, an
  empty state for zero items, and an error state with a retry affordance.
- FR-8: Browse paginates: scrolling to the end of the grid triggers an append
  load and renders additional items (asserted against `PagingData` fed through a
  test `Pager`).
- FR-9: `ProductDetailScreen` renders name, price (formatted via a locale-aware
  currency formatter from `price_cents`/`currency`), description, attributes, and
  the `image_urls` gallery; a stock badge appears for `stock_status ==
  "low_stock"` ("Only N left!") and `"out_of_stock"` ("Out of Stock"). The **Add
  to cart** button is disabled when `stock_status == "out_of_stock"` (and while a
  request is in flight), invokes the ViewModel callback, and reflects success.
  **[CORRECTED]** "Sale price when present" is unverified — the item payload has
  no `sale_price_cents` field (a separate admin sale-scheduling endpoint exists,
  `POST /ui/catalog/products/{product_id}/sale`, but it does not surface on the
  item DTO). "In stock" is a `stock_status` string, not a boolean `in_stock`.
  Add-to-cart is NOT a catalog endpoint: the web client ensures an active cart
  (`GET`/`POST /ui/shoppingcart/carts`) then `POST
  /ui/shoppingcart/carts/{cart_id}/items` (or `.../items/catalog`); see §16.
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

    // CORRECTED: items are a sub-resource of a category; paging is cursor-based
    // (page_size + next_token), not offset (page/page_size). Verified against
    // openapi.index GET /ui/catalog/categories/{category_id}/items and
    // frontend src/api/endpoints/cart.ts: getCategoryItems.
    @Test fun `items request sends category path and page_size`() = runTest {
        server.enqueue(MockResponse().setBody(Fixtures.ITEMS_PAGE_1))
        api.getCategoryItems(categoryId = "cat_1", pageSize = 50, nextToken = null)
        val req = server.takeRequest()
        assertEquals("/ui/catalog/categories/cat_1/items?page_size=50",
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
AND-204). The fixtures below are corrected to match the authoritative sources
(OpenAPI `components.schemas.CatalogCategoryListOut` / `CatalogCategoryOut` /
`CatalogItemListOut` / `CatalogItemOut`, and `frontend/src/api/types.ts`
`CatalogCategory` / `CatalogItem` / `PaginatedList<T>`). They are used as
`MockWebServer` bodies and Moshi deserialisation inputs.

> **[CORRECTED — §16/1..6]** Every fixture below was rewritten. The original draft
> used a non-existent `/catalog/*` prefix, offset paging
> (`page`/`page_size`/`total`/`has_next`), a `categories` wrapper field, and item
> fields (`id`, `sku`, `sale_price_cents`, `thumbnail_url`, `in_stock`, `media[]`)
> that do not exist in the backend schema. The real list wrapper is
> `{ "items": [...], "next_token": <str|null> }`; the real item id field is
> `item_id`; stock is a `stock_status` string + `stock_count`.

`GET /ui/catalog/categories?page_size=50` → `200` (`CatalogCategoryListOut`):

```json
{ "items": [
  { "category_id": "cat_1", "name": "Laptops", "description": "Portable dev rigs",
    "creator_id": "u_1", "created_at": "2026-01-02T10:00:00Z" }
], "next_token": null }
```

`GET /ui/catalog/categories/cat_1/items?page_size=50` → `200`
(`CatalogItemListOut`; items are `CatalogItemOut`):

```json
{
  "items": [
    { "item_id": "item_1", "category_id": "cat_1", "name": "TL Pro 14",
      "description": "14-inch dev laptop.", "price_cents": 199900,
      "currency": "USD",
      "image_urls": ["http://18.222.237.167:8000/media/i1.jpg"],
      "attributes": { "ram": "32GB" },
      "stock_count": 3, "stock_status": "low_stock", "low_stock_threshold": 5,
      "stock_updated_at": "2026-06-01T00:00:00Z", "position": 0,
      "creator_id": "u_1",
      "created_at": "2026-01-02T10:00:00Z", "updated_at": "2026-06-01T00:00:00Z" }
  ],
  "next_token": "eyJvZmZzZXQiOjUwfQ"
}
```

There is **no item-detail endpoint**; the web client renders detail by fetching
the category-items list and selecting the matching `item_id` (see §16,
`ProductDetail.tsx`). Android may mirror this or add a detail fetch, but no
`GET .../items/{itemId}` route exists to test against. Minimal/null-field fixture
for Moshi: an item with `description`, `stock_count`, `stock_updated_at`,
`position`, `creator_id` all `null` and `image_urls`/`attributes` empty — note
`category_id, item_id, name, price_cents, currency, image_urls, attributes,
created_at, updated_at` are **required** per the schema.

`GET /ui/catalog/items/search?q=pro&page_size=50` → `200`: same
`CatalogItemListOut` shape as the items list. Empty: `{ "items": [],
"next_token": null }`.

Error fixtures (FastAPI `detail`) used to test mapping:
`{"detail":"Category not found"}` (string),
`{"detail":[{"loc":["query","q"],"msg":"field required","type":"value_error.missing"}]}`
(FastAPI `HTTPValidationError` array — the real shape includes `loc`, `msg`, and
`type`; the original draft omitted `type`), `{"detail":{"code":"RATE_LIMITED"}}`
(object). Status codes tested: 400, 401, 403, 404, 422, 429, 500, and a simulated
timeout/socket failure. **[VERIFIED]** The OpenAPI index documents `400, 401,
403, 429` in addition to `422:HTTPValidationError` on the catalog GET routes
(`GET /ui/catalog/categories`, `.../items`, `.../items/search`), so 403 and 429
are added to the matrix here.

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
- CSRF/auth transport is owned by the shared OkHttp interceptor tests, not
  re-tested here. **[CORRECTED/clarified]** The web client
  (`src/api/client.ts`) sets the `X-CSRF-Token` header from the `ui_csrf` cookie
  on **every** request whenever that cookie is present — it is NOT gated to
  non-GET methods, so catalog GETs are not "CSRF-exempt". Authentication is an
  `Authorization: Bearer <token>` header (plus optional `X-IMPERSONATION-TOKEN`),
  not pure cookie-session. The server additionally accepts `X-SESSION-ID` and
  `X-API-Key` (see OpenAPI `params` on the catalog routes). Catalog GETs are
  asserted to send no request body.
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
- **RESOLVED (was open question):** Pagination is **cursor-based** (`page_size` +
  `next_token`), confirmed against OpenAPI (`CatalogItemListOut` /
  `CatalogCategoryListOut` expose only `items` + nullable `next_token`) and
  `frontend/src/api/endpoints/cart.ts`. `PagingSource` key tests use `next_token`
  as the cursor; terminal page = `next_token` null/absent. The offset assumption
  in earlier drafts is wrong.
- **RESOLVED (was open question):** Add-to-cart is a **cart endpoint**, not a
  catalog one. The web client (`ProductDetail.tsx`) ensures an active cart then
  calls `POST /ui/shoppingcart/carts/{cart_id}/items` (`ShoppingCartItemIn`); a
  catalog-typed variant `POST /ui/shoppingcart/carts/{cart_id}/items/catalog`
  (`CatalogCartItemIn`: `category_id`, `item_id`, `quantity`) also exists. If
  AND-206 stubs cart locally in M5, detail tests assert the stub's contract; the
  full cart flow is M6. The button is gated by `stock_status == "out_of_stock"`,
  not a boolean `in_stock`.
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer. Sources:
OpenAPI index = `reference/openapi.index.txt`; OpenAPI schemas =
`reference/openapi.pretty.json` (`components.schemas.<Name>`); frontend = paths
under `reference/src/`.

1. **Catalog endpoints live under `/ui/catalog/...`, not `/catalog/...`.**
   VERDICT: Corrected. SOURCE: OpenAPI `GET /ui/catalog/categories`,
   `GET /ui/catalog/categories/{category_id}/items`,
   `GET /ui/catalog/items/search`; frontend
   `src/api/endpoints/cart.ts: getCategories / getCategoryItems / searchCatalogItems`.
2. **Items are a sub-resource of a category (`/categories/{id}/items`), not a
   top-level `/items` collection filtered by a `category_id` query param.**
   VERDICT: Corrected. SOURCE: OpenAPI
   `GET /ui/catalog/categories/{category_id}/items`;
   `src/api/endpoints/cart.ts: getCategoryItems`.
3. **Pagination is cursor-based: `page_size` + `next_token` (no
   `page`/`total`/`has_next`).** VERDICT: Corrected. SOURCE: OpenAPI schemas
   `CatalogItemListOut` / `CatalogCategoryListOut` (only `items` + nullable
   `next_token`); `src/api/types.ts: PaginatedList<T>` (`items`, `next_token`);
   `src/api/endpoints/cart.ts: getCategories(pageSize, nextToken)`.
4. **List wrapper field is `items` (categories list is also `items`, not
   `categories`).** VERDICT: Corrected. SOURCE: OpenAPI `CatalogCategoryListOut`
   (`items`); frontend `src/pages/shop/Catalog.tsx` (`categoriesQuery.data?.items`).
5. **Category fields: `category_id`, `name`, `description?`, `creator_id?`,
   `created_at` — no `id`, `item_count`, or `image_url`.** VERDICT: Corrected.
   SOURCE: OpenAPI `CatalogCategoryOut`; `src/api/types.ts: CatalogCategory`.
6. **Item fields: `item_id`, `category_id`, `name`, `description?`,
   `price_cents`, `currency`, `image_urls: string[]`, `attributes: object`,
   `stock_count?`, `stock_status: string`, `low_stock_threshold`,
   `stock_updated_at?`, `position?`, `creator_id?`, `created_at`, `updated_at` —
   no `id`, `sku`, `sale_price_cents`, `thumbnail_url`, `in_stock`, or
   `media[{type,url}]`.** VERDICT: Corrected. SOURCE: OpenAPI `CatalogItemOut`
   (required: `category_id, item_id, name, price_cents, currency, image_urls,
   attributes, created_at, updated_at`); `src/api/types.ts: CatalogItem`.
7. **No standalone item-detail endpoint exists; web detail derives the item from
   the category-items list by matching `item_id`.** VERDICT: Corrected. SOURCE:
   absence of any `GET /ui/catalog/.../items/{item_id}` in OpenAPI index;
   `src/pages/shop/ProductDetail.tsx` (`getCategoryItems(...).items.find(i => i.item_id === itemId)`).
8. **Stock gating is a `stock_status` string ("unlimited" | "low_stock" |
   "out_of_stock"), and add-to-cart is disabled when `out_of_stock`.** VERDICT:
   Corrected (was `in_stock` boolean). SOURCE: OpenAPI `CatalogItemOut.stock_status`
   (default "unlimited"); `src/pages/shop/ProductDetail.tsx`
   (`disabled={... item.stock_status === "out_of_stock"}`, low_stock/out_of_stock
   badges).
9. **Add-to-cart is a shopping-cart endpoint, not catalog: ensure active cart
   (`GET`/`POST /ui/shoppingcart/carts`) then `POST
   /ui/shoppingcart/carts/{cart_id}/items` (`ShoppingCartItemIn`); a catalog
   variant `.../items/catalog` (`CatalogCartItemIn`: category_id, item_id,
   quantity) also exists.** VERDICT: Corrected. SOURCE: OpenAPI
   `POST /ui/shoppingcart/carts/{cart_id}/items`,
   `POST /ui/shoppingcart/carts/{cart_id}/items/catalog`, schema `CatalogCartItemIn`;
   `src/pages/shop/ProductDetail.tsx: addToCartMutation` + `src/api/endpoints/cart.ts: addCartItem`.
10. **Search uses `q` on `GET /ui/catalog/items/search`; blank query fires no
    request.** VERDICT: Verified/Corrected (path corrected, semantics verified).
    SOURCE: OpenAPI `GET /ui/catalog/items/search` (`params=q,page_size,next_token`);
    `src/pages/shop/Catalog.tsx` (`enabled: search.trim().length > 0`);
    `src/api/endpoints/cart.ts: searchCatalogItems`.
11. **FastAPI validation error shape is `{"detail":[{"loc","msg","type"}]}`
    (422 = `HTTPValidationError`).** VERDICT: Corrected (draft omitted `type`).
    SOURCE: OpenAPI `422:HTTPValidationError` on the catalog routes; standard
    FastAPI `ValidationError` shape.
12. **Catalog GET routes also document 400/401/403/429 responses.** VERDICT:
    Verified. SOURCE: OpenAPI index lines for `GET /ui/catalog/categories`,
    `.../items`, `.../items/search`
    (`resp=200:...;422:HTTPValidationError;400;401;403;429`).
13. **CSRF header is `X-CSRF-Token` from the `ui_csrf` cookie, applied to all
    requests (not just non-GET); auth is `Authorization: Bearer` (+
    `X-IMPERSONATION-TOKEN`); server also accepts `X-SESSION-ID` / `X-API-Key`.**
    VERDICT: Corrected (draft claimed GET = CSRF-exempt). SOURCE:
    `src/api/client.ts` (sets `X-CSRF-Token` whenever `ui_csrf` cookie present;
    `Authorization: Bearer`; `X-IMPERSONATION-TOKEN`); OpenAPI route
    `params=...,X-SESSION-ID,X-IMPERSONATION-TOKEN,X-API-Key`.
14. **Session refresh on 401 is `POST /ui/session/refresh`, retried once, then
    logout.** VERDICT: Verified (and confirmed out of scope for catalog tests).
    SOURCE: `src/api/client.ts: refreshSession()` → `/ui/session/refresh`.
15. **Price formatting is locale-aware currency from cents (`price_cents/100`).**
    VERDICT: Verified. SOURCE: `src/pages/shop/ProductDetail.tsx: formatPrice`
    (`Intl.NumberFormat(..., { style: "currency", currency }).format(cents/100)`).
16. **Android test stack choices (Compose UI test, MockWebServer, Turbine,
    Robolectric, Paging `paging-testing`, instrumented vs Robolectric trade-off).**
    VERDICT: Unverified-assumption (framework choice, not derivable from backend/
    frontend sources). SOURCE (framework ref): AndroidX Compose testing
    (https://developer.android.com/jetpack/compose/testing), Paging testing
    (https://developer.android.com/topic/libraries/architecture/paging/test),
    MockWebServer (https://github.com/square/okhttp/tree/master/mockwebserver).

### Corrections made

- §FR-1 / §4.2 / §5: rewrote all endpoint paths to the `/ui/catalog/` prefix;
  items are `/categories/{id}/items`; removed the non-existent
  `/catalog/items/{itemId}` detail endpoint.
- §FR-2 / §5: replaced item fixture fields — `id`→`item_id`; removed `sku`,
  `sale_price_cents`, `thumbnail_url`, `in_stock`, `media[]`; added `currency`,
  `image_urls[]`, `attributes`, `stock_status`, `stock_count`,
  `low_stock_threshold`, `position`, timestamps. Categories: `id`→`category_id`,
  removed `item_count`/`image_url`.
- §FR-5 / §6 / §13: changed paging from offset (`page`/`has_next`/`total`) to
  cursor (`page_size`/`next_token`); resolved the corresponding open question.
- §FR-6 / §5: search path corrected to `/ui/catalog/items/search`.
- §FR-9 / §13: corrected add-to-cart to the shopping-cart endpoints, stock gating
  to `stock_status`, and flagged sale-price rendering as unverified.
- §5: corrected the list wrapper to `{items, next_token}` and the 422 `detail`
  array element to include `type`; added 403/429 to the error matrix.
- §8: corrected CSRF claim (header applied to all requests, not non-GET-only;
  auth is bearer-based) and added the real auth/session headers.

### Open assumptions

- **Sale price on the product screen (FR-9).** Unverified: `CatalogItemOut` has
  no `sale_price_cents`; the only sale-related route is the admin
  `POST /ui/catalog/products/{product_id}/sale` (`CatalogSaleIn`/`CatalogSaleOut`)
  which does not surface a sale price on the item DTO. If AND-206 renders a sale
  price, it must derive it elsewhere; tests should not assume an item-level sale
  field until AND-206 source confirms it.
- **Item-detail navigation/source in the Android app.** Web reuses the category
  list and `.find(item_id)`; whether the Android port adds a dedicated detail
  fetch is an internal design choice (no backend detail endpoint exists). Tested
  per AND-206 as merged.
- **Room cache / TTL / stale-fallback (FR-4) and `ApiResult`/`ApiError`
  taxonomy.** Unverified against sources: these are Android-internal abstractions
  defined by AND-204; no backend/frontend equivalent. Tested against the upstream
  Kotlin contracts, not the OpenAPI/frontend.
- **Coverage threshold (80%).** Unverified: team CI policy, not in any source.
- **Analytics/telemetry events (§10).** Unverified: depends on whether
  AND-205/206 emit events; no source confirms event names/params.
- **Android framework/test-library choices (§16/16).** Assumptions per Android
  docs, not backend contracts.

## 17. Test Plan

Test targets: **JVM** = JVM unit/Robolectric (local, no device); **emu35** =
headless emulator AVD `test35` (x86_64, API 35); **A15** = physical Samsung
Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). Catalog has no camera/biometric/
WebRTC/FCM/Telecom surface, so the physical device is needed only for the
ABI/API-level differential smoke (TC-AND-209-13). All IDs trace to §14 ACs.

- **TC-AND-209-01** — Type: contract/MockWebServer (JVM). Target: JVM. Target
  under test: `CatalogApi.getCategoryItems` + `getCategories` + `searchCatalogItems`.
  Preconditions: MockWebServer up; Retrofit/Moshi `CatalogApi`. Steps: enqueue
  `ITEMS_PAGE_1`; call `getCategoryItems("cat_1", pageSize=50, nextToken=null)`;
  read recorded request. Expected: path == `/ui/catalog/categories/cat_1/items?page_size=50`,
  method GET, no body; search call hits `/ui/catalog/items/search?q=pro&page_size=50`;
  categories hits `/ui/catalog/categories?page_size=50`. Traces: AC-1.
- **TC-AND-209-02** — Type: unit (JVM). Target: JVM. Under test: Moshi adapters
  for `CatalogItemOut`/`CatalogCategoryOut`/`CatalogItemListOut`. Preconditions:
  fixtures from §5. Steps: deserialise full item fixture, then the minimal/null
  fixture (description/stock_count/position null, empty image_urls/attributes).
  Expected: all fields map (snake_case→camelCase); `item_id`/`category_id`
  populated; `image_urls` is a list; `stock_status` string; nullable fields
  null without error; required-field-missing JSON throws. Traces: AC-1.
- **TC-AND-209-03** — Type: unit (JVM). Target: JVM. Under test:
  `CatalogRepository` success mapping. Preconditions: fake `CatalogApi` returns
  200 list. Steps: call `repository.items("cat_1").first()`. Expected:
  `ApiResult.Success` with mapped domain items; cache written (assert DAO upsert).
  Traces: AC-1.
- **TC-AND-209-04** — Type: unit (JVM). Target: JVM. Under test: error mapping
  for each FastAPI `detail` shape + status. Preconditions: fake/MockWebServer
  enqueues 400 string-detail, 422 `[{loc,msg,type}]`, 404 string, object
  `{code}`, 401, 403, 429, 500. Steps: invoke repo per case. Expected: each maps
  to the correct `ApiResult.Error` subtype/message/code; 422 surfaces the `msg`;
  object detail surfaces `code`. Traces: AC-1, AC-4.
- **TC-AND-209-05** — Type: unit/contract (JVM). Target: JVM. Under test:
  timeout/IO + stale-cache fallback (FR-4) + bounded retry (§7). Preconditions:
  Room pre-seeded with cached items; MockWebServer set to socket-timeout then
  (separately) fail-then-200. Steps: (a) network throws → repo returns cached
  data flagged stale; (b) transient 500/IO then 200 → repo retries within bound
  and succeeds; assert retry count is bounded (no infinite loop). Expected: (a)
  `ApiResult.Success(cached, stale=true)` or documented stale signal; (b) success
  after ≤N retries. Traces: AC-4. (Offline/flaky-host path.)
- **TC-AND-209-06** — Type: unit (JVM). Target: JVM. Under test:
  `CatalogPagingSource` cursor paging. Preconditions: fake api returns page with
  `next_token="t2"`, then a page with `next_token=null`. Steps: call `load(Refresh)`
  then `load(Append, key="t2")`. Expected: first `LoadResult.Page(nextKey="t2",
  prevKey=null)`; second `LoadResult.Page(nextKey=null)` (terminal); api failure →
  `LoadResult.Error`. Traces: AC-1, AC-4.
- **TC-AND-209-07** — Type: unit (JVM, Turbine). Target: JVM. Under test:
  `CatalogBrowseViewModel` / `ProductDetailViewModel` / `CatalogSearchViewModel`
  state transitions. Preconditions: fake repo; `MainDispatcherRule`. Steps: drive
  success, empty, error; for detail drive add-to-cart Idle→InProgress→Added and
  →Failed; for search drive blank-query (Idle, no request), results, no-results.
  Expected: emitted `UiState` sequences match §6; `SavedStateHandle` restores
  `categoryId`/`query` after VM re-creation. Traces: AC-1.
- **TC-AND-209-08** — Type: Compose-UI (Robolectric/JVM; full run on emu35).
  Target: JVM then emu35. Under test: `CatalogBrowseScreen` render +
  loading/empty/error. Steps: set Content state then Loading then Empty then
  Error; assert grid/loading-indicator/empty-text/error+Retry via `testTag`.
  Expected: each branch renders its node; tapping Retry invokes callback exactly
  once. Traces: AC-2.
- **TC-AND-209-09** — Type: Compose-UI (emu35). Target: emu35. Under test: Browse
  pagination append. Preconditions: `PagingData` of 40 items via test `Pager`.
  Steps: scroll grid to `item_40`. Expected: append load triggers and `item_40`
  is displayed; append error renders inline retry footer without dropping loaded
  items. Traces: AC-2.
- **TC-AND-209-10** — Type: Compose-UI (emu35). Target: emu35. Under test:
  `ProductDetailScreen`. Steps: render in-stock item → Add-to-cart enabled,
  tapping invokes callback and reflects success; render `stock_status ==
  "out_of_stock"` → button disabled + "Out of Stock" label/badge; render
  `low_stock` → "Only N left!" badge; assert price formatted via locale
  currency (e.g. `$1,999.00`). Expected: matches FR-9 / §16/8,15. Traces: AC-2.
- **TC-AND-209-11** — Type: Compose-UI (emu35). Target: emu35. Under test:
  `CatalogSearchScreen`. Steps: enter non-empty query → results render; clear to
  blank → no request fired + Idle; query with no matches → "no results" empty
  state; debounce: rapid input forwards a single debounced query. Expected:
  matches FR-10 / §16/10. Traces: AC-2.
- **TC-AND-209-12** — Type: Compose-UI accessibility (Robolectric/JVM + emu35).
  Target: JVM then emu35. Under test: a11y of all three screens. Steps: assert
  each interactive node (item card, add-to-cart, retry, search field) has a
  non-empty `contentDescription` and `assertHasClickAction()`; assert key
  controls `assertHeightIsAtLeast(48.dp)`/`assertWidthIsAtLeast(48.dp)`; assert no
  hard-coded user-facing strings (reads from `R.string`). Expected: all pass.
  Traces: AC-2, AC-7.
- **TC-AND-209-13** — Type: instrumented/e2e differential (A15 — MUST run on the
  physical device). Target: A15 (arm64-v8a, API 34); compare against emu35
  (x86_64, API 35). Under test: catalog browse→detail→add-to-cart smoke against
  MockWebServer to catch arm64-vs-x86 ABI and API-34-vs-35 behaviour differences
  (Moshi/Paging/Compose). Steps: run the browse+detail Compose suite on A15.
  Expected: identical pass/render results on both targets; no ABI- or
  API-level-specific failures. Traces: AC-3, AC-5. (Physical device required for
  the real arm64/API-34 surface.)
- **TC-AND-209-14** — Type: contract/security (JVM). Target: JVM. Under test:
  no-secrets-in-URL + no-PII-in-fixtures + determinism. Steps: assert recorded
  MockWebServer paths contain no token/password/cookie and catalog GETs carry no
  body; grep fixtures for `spannella@gmail.com`/real cookies (must be absent);
  run suite under `--rerun-tasks` and randomised order. Expected: no secrets in
  URLs; no real PII; deterministic green. Traces: AC-5, AC-8. (Coverage gate
  AC-6 is enforced by the Kover/Jacoco CI threshold, not a single TC.)

### Coverage matrix

| §14 AC | Covered by |
| --- | --- |
| AC-1 (repo/API/DTO/DAO/PagingSource/VM tests) | TC-01, TC-02, TC-03, TC-04, TC-06, TC-07 |
| AC-2 (Compose UI for 3 screens, FR-7..11) | TC-08, TC-09, TC-10, TC-11, TC-12 |
| AC-3 (pass locally + CI) | TC-13 (+ all TCs are the CI suite) |
| AC-4 (error/timeout/stale-cache/bounded-retry) | TC-04, TC-05, TC-06 |
| AC-5 (deterministic, no network/delays, rerun/random) | TC-13, TC-14 |
| AC-6 (coverage ≥ threshold) | Kover/Jacoco gate (all TCs contribute; no single TC) |
| AC-7 (no behaviour change; only test seams) | TC-12 (testTag/a11y seams non-behavioural) |
| AC-8 (no real PII/credentials) | TC-14 |
