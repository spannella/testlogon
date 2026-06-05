---
id: AND-217
title: Cart/checkout tests
milestone: M5
epic: E29
priority: P1
size: M
status: draft
depends_on: [AND-210, AND-211, AND-212, AND-213, AND-214]
blocks: []
---

# AND-217 — Cart/checkout tests

## 1. Overview & Goal

This ticket delivers the automated test suite that guards the M5 cart and
checkout flow on the native Android port. It is a pure **Test** ticket
(Type: Test, Priority: P1): it produces no shippable user feature, but it
locks down the behaviour built in AND-210 (Cart API + DTOs), AND-211 (Cart
screen), AND-212 (Cart search/items), AND-213 (Checkout session) and
AND-214 (Address / shipping). The backlog acceptance for AND-217 is simply
"Pass" — the suite must be green and meaningful.

The goal is two coverage tiers:

1. **Repo tests** — JVM unit tests for `CartRepository` and
   `CheckoutRepository` in `core-data`, the cart/checkout API services in
   `core-network`, and the Moshi DTO ↔ domain mappers in `core-model`.
   These assert payload mapping, `ApiResult<T>` success/error translation,
   FastAPI `detail` decoding, idempotent-GET retry/backoff, and the
   `POST /ui/session/refresh`-on-401 path.
2. **UI tests** — Compose instrumented tests for `CartScreen` and the
   checkout review step, asserting add/update-qty/remove, totals
   recomputation, empty state, in-cart search filtering, and the
   cart → checkout-session → review transition.

A concrete, non-negotiable outcome is a documented coverage floor (>= 80%
line coverage on the `feature-cart` and `feature-checkout` ViewModel +
repository packages) verified in CI, so regressions in the dependency
tickets fail the build rather than reaching QA against the unreliable dev
backend.

## 2. Context & References

- Repo `spannella/testlogon`, Android app under `android/`, branch
  `android-port`. Namespace / applicationId base
  `com.testlogon.android`.
- Stack: Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow,
  Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Room 2.6, DataStore, Paging 3.
  minSdk 24, compile/target 35, JDK 17, Gradle 8.9, AGP 8.7.3.
- Module layering `app -> feature-* -> core-*`. Shared test infrastructure
  lives in **`core-testing`** (fakes, dispatcher rules, MockWebServer
  helpers, Compose test rule factories).
- Subjects under test (owned by their tickets):
  - AND-210 — `core-network` `CartApiService`, `core-model` cart DTOs.
  - AND-211 — `feature-cart` `CartViewModel` + `CartScreen`.
  - AND-212 — in-cart item/SKU search.
  - AND-213 — `CheckoutApiService.createSession` (`/ui/checkout/session`)
    + order review screen.
  - AND-214 — address entry/select + shipping options applied to order.
- Web reference: `frontend/src/api/endpoints/cart.ts`, checkout endpoints,
  and `frontend/src/api/types.ts` are the canonical shapes the Android DTOs
  mirror; tests assert parity with these.
- Backend FastAPI + DynamoDB; dev host `http://18.222.237.167:8000`
  (plaintext, unreliable). **All AND-217 tests run against MockWebServer
  or fakes — never the live dev host** — so the suite is deterministic.
- OpenAPI at `/openapi.json` is the source for golden JSON fixtures.

## 3. Functional Requirements

FR-1. Provide a JVM unit-test source set covering `CartRepository`,
`CheckoutRepository`, `CartApiService`, `CheckoutApiService`, and all
cart/checkout/address DTO mappers.

FR-2. Provide a `androidTest` (instrumented) source set covering
`CartScreen` and the checkout review screen using
`createAndroidComposeRule` / `createComposeRule`.

FR-3. Tests must assert, at minimum:
- Cart payload deserialization → domain model (AND-210), including line
  items, per-line `quantity`, `unit_price`, `line_total`, and cart-level
  `subtotal` / `tax` / `shipping` / `grand_total`.
- Add item, update quantity, remove item; totals recompute and persist
  across recomposition (AND-211).
- Empty-cart state renders the empty placeholder and a disabled checkout
  CTA (AND-211).
- In-cart search filters the visible line items by item name / SKU and
  restores the full list when cleared (AND-212).
- Checkout session creation maps the response and advances UI to the order
  review state; checkout CTA is disabled while the request is in flight
  (AND-213).
- Selecting/entering an address and a shipping option updates the order
  totals and is reflected in the review summary (AND-214).

FR-4. Resilience-path tests: 20s timeout surfaces a timeout UI state;
bounded backoff retry fires for idempotent `GET /ui/cart` only and NOT for
`POST /ui/checkout/session`; a single `POST /ui/session/refresh` is
attempted on a 401 and the original request is retried exactly once.

FR-5. Error-mapping tests: FastAPI `detail` in all three shapes
(`string`, `[{msg}]`, `{code,...}`) maps to the typed error surfaced by
`ApiResult.Error`.

FR-6. The suite runs in CI via `./gradlew testDebugUnitTest` (repo) and
`./gradlew connectedDebugAndroidTest` (UI) and gates the merge.

FR-7. JaCoCo coverage report is produced and the configured floor enforced.

## 4. Technical Design

Tests are co-located with the modules that own the subjects; AND-217 adds
test source only (no `main` changes except, if needed, narrowly-scoped
`@VisibleForTesting` constructors already exposed by dependency tickets).

### Shared infrastructure (`core-testing`)

```kotlin
// core-testing/src/main/kotlin/com/testlogon/android/core/testing/
class MainDispatcherRule(
    private val dispatcher: TestDispatcher = StandardTestDispatcher(),
) : TestWatcher() {
    override fun starting(d: Description) = Dispatchers.setMain(dispatcher)
    override fun finished(d: Description) = Dispatchers.resetMain()
}

object MockBackend {
    fun retrofit(server: MockWebServer): Retrofit            // Moshi + OkHttp wired like prod
    fun enqueueJson(server: MockWebServer, code: Int, body: String, headers: Map<String,String> = emptyMap())
    fun loadFixture(name: String): String                    // reads test/resources/fixtures/<name>.json
}

class FakeCartRepository(
    initial: Cart = Cart.empty(),
) : CartRepository {
    val cart = MutableStateFlow(initial)
    var failNext: TlError? = null
    override fun observeCart(): Flow<Cart> = cart
    override suspend fun setQuantity(lineId: String, qty: Int): ApiResult<Cart>
    override suspend fun removeLine(lineId: String): ApiResult<Cart>
}
```

### Repo unit tests (`core-data`, `core-network`, `core-model`)

```kotlin
// core-network/src/test/kotlin/.../CartApiServiceTest.kt
class CartApiServiceTest {
    @get:Rule val main = MainDispatcherRule()
    private lateinit var server: MockWebServer
    private lateinit var api: CartApiService

    @Test fun `getCart maps line items and totals`() = runTest { ... }
    @Test fun `getCart retries idempotent GET on 503 then succeeds`() = runTest { ... }
    @Test fun `getCart surfaces Timeout after 20s read timeout`() = runTest { ... }
    @Test fun `401 triggers single session refresh then retry`() = runTest { ... }
    @Test fun `detail as list of msg maps to validation error`() = runTest { ... }
}

// core-data/src/test/kotlin/.../CheckoutRepositoryTest.kt
class CheckoutRepositoryTest {
    @Test fun `createSession returns Success and review model`() = runTest { ... }
    @Test fun `createSession does NOT retry on 503 (non-idempotent POST)`() = runTest { ... }
    @Test fun `address and shipping apply to totals`() = runTest { ... }
}
```

`runTest` + `MainDispatcherRule` give virtual time so the 20s timeout and
backoff windows are asserted without real waiting. The OkHttp client used
by `MockBackend.retrofit` is configured with the production interceptor
chain (cookie jar, CSRF header, refresh-on-401 authenticator) so those
behaviours are exercised end-to-end against MockWebServer.

### UI instrumented tests (`feature-cart`, `feature-checkout`)

ViewModels are driven through a `FakeCartRepository` / `FakeCheckoutRepository`
injected via a Hilt test module (`@TestInstallIn` replacing the production
bindings), so UI tests never touch the network.

```kotlin
// feature-cart/src/androidTest/kotlin/.../CartScreenTest.kt
@HiltAndroidTest
class CartScreenTest {
    @get:Rule(order = 0) val hilt = HiltAndroidRule(this)
    @get:Rule(order = 1) val compose = createAndroidComposeRule<HiltTestActivity>()

    @Test fun emptyCart_showsPlaceholder_andDisablesCheckout()
    @Test fun increaseQuantity_updatesLineTotal_andGrandTotal()
    @Test fun removeLine_removesRow_andRecomputesTotals()
    @Test fun search_filtersLines_bySkuAndName()
    @Test fun checkoutCta_navigatesToReview_andDisablesWhileLoading()
}
```

Assertions use semantics matchers (`onNodeWithText`,
`onNodeWithContentDescription`, `onNodeWithTag`) and `assertIsEnabled()` /
`assertIsNotEnabled()`. Test tags (`cart_line_<id>`, `cart_grand_total`,
`checkout_cta`, `cart_search_field`) are expected to already exist from the
feature tickets; AND-217 files a fast-follow if any are missing.

## 5. API Contract

AND-217 does not define new endpoints; it consumes the contracts owned by
AND-210/213/214 and pins them via golden fixtures captured from
`/openapi.json` and the web reference. The contracts exercised:

`GET /ui/cart` → 200:

```json
{
  "cart_id": "c_01HZ...",
  "lines": [
    {"line_id": "l_1", "sku": "SKU-001", "name": "Widget",
     "quantity": 2, "unit_price": 9.99, "line_total": 19.98}
  ],
  "subtotal": 19.98, "tax": 1.65, "shipping": 0.0, "grand_total": 21.63
}
```

`PATCH /ui/cart/lines/{line_id}` body `{"quantity": 3}` → 200 returns the
updated cart (same shape). `DELETE /ui/cart/lines/{line_id}` → 200 returns
the cart.

`POST /ui/checkout/session` body
`{"cart_id":"c_01HZ...","file_bundle":"..."}` → 200:

```json
{
  "session_id": "cs_01J...",
  "status": "requires_payment",
  "review": {"lines": [...], "subtotal": 19.98, "tax": 1.65,
             "shipping": 5.0, "grand_total": 26.63},
  "address": null, "shipping_option": null
}
```

Error fixtures (asserted by FR-5), all under FastAPI `detail`:

```json
{"detail": "Cart is empty"}
{"detail": [{"loc": ["body","quantity"], "msg": "must be >= 1"}]}
{"detail": {"code": "checkout_locked", "message": "..."}}
```

All four request paths above are mounted on MockWebServer with a
`Dispatcher` that matches method+path, returning the corresponding fixture
and (for resilience tests) `503` / socket-stall / `401` responses.

## 6. Data & State Management

Tests assert the dependency tickets' state contracts, they do not own them:

- `CartViewModel` exposes `StateFlow<CartUiState>` where
  `CartUiState = Loading | Empty | Content(cart, query, filteredLines) |
  Error(TlError) | Offline(staleCart)`. Tests use Turbine
  (`viewModel.uiState.test { ... }`) to assert the emitted sequence on each
  action.
- Totals are recomputed server-authoritatively (the PATCH/DELETE responses
  carry new totals); UI tests assert the rendered `grand_total` equals the
  fixture value, not a client-side sum, to catch mapping drift.
- Stale-cart persistence (Room cache from AND-210) is verified by an
  in-memory Room database test: write a cart, simulate `GET /ui/cart`
  failure, assert `Offline(staleCart)` is emitted from cache.
- Cookie jar + CSRF: a persistent-cookie test asserts that a `Set-Cookie`
  (`ui_csrf`) from `GET /ui/cart` is echoed as `X-CSRF-Token` on the
  subsequent `PATCH`, using `server.takeRequest()` header inspection.

## 7. Error Handling & Resilience

The suite is the primary enforcement point for the project resilience
rules. Specific cases:

- **Timeout**: MockWebServer `socketPolicy = NO_RESPONSE` (or throttled
  body) → repository emits `ApiResult.Error(TlError.Timeout)` after the
  ~20s read timeout; with `runTest` virtual time this completes instantly.
- **Idempotent retry**: `GET /ui/cart` returns `503` then `200`; assert the
  repository performs exactly one retry (bounded backoff) and succeeds.
  Assert via `server.requestCount == 2`.
- **No retry for non-idempotent**: `POST /ui/checkout/session` returns
  `503`; assert `requestCount == 1` and `ApiResult.Error` is returned.
- **Refresh-on-401**: first call → `401`; `POST /ui/session/refresh` → `200`;
  retried original → `200`. Assert the refresh endpoint was hit exactly
  once and a second 401 does NOT loop (caps at one refresh).
- **detail mapping** (FR-5): three fixtures → `TlError.Message`,
  `TlError.Validation(field→msg)`, `TlError.Coded(code)` respectively.
- **Offline/stale**: failure with a populated Room cache → `Offline` UI
  state with stale banner; failure with empty cache → `Error` state.

## 8. Security & Privacy

No new attack surface. Test-specific concerns:

- Fixtures contain only synthetic data (no real PII, no real credentials).
  Usernames/passwords used to set up authenticated MockWebServer state are
  literal test constants.
- No plaintext traffic to the real dev host from tests; MockWebServer binds
  to localhost. The cleartext-traffic allowance for the dev host is not
  required by this module's test config.
- The CSRF echo and refresh-on-401 behaviours are explicitly tested
  (Section 7) so security regressions in the auth chain are caught here.
- No secrets in fixtures or CI logs; MockWebServer dumps are not persisted.

## 9. Accessibility & i18n

As a test ticket, AND-217's contribution is to **assert** accessibility,
not implement it:

- UI tests assert content descriptions exist on icon-only controls
  (quantity +/- buttons, remove, clear-search) via
  `onNodeWithContentDescription`, failing if a control is unlabeled.
- Assert the empty-state placeholder and checkout CTA expose readable text
  through merged semantics.
- i18n: assert no hard-coded user-facing literals leak into totals
  formatting by checking currency rendering goes through the formatter
  (test in `en-US` locale; a `de-DE` smoke variant validates locale-aware
  number formatting if the formatter is locale-driven). Full i18n coverage
  is owned by the feature tickets, not AND-217.

## 10. Telemetry & Logging

- If AND-216 (cart abandonment events) lands before this suite, add a
  contract test asserting no abandonment event is emitted on a successful
  checkout transition and that the analytics sink is a `FakeAnalytics`
  during tests (never the real pipeline). If AND-216 is not yet merged,
  this is out of scope and remains owned by AND-216.
- Tests assert no PII is logged: a `FakeLogger` captures log calls and the
  suite asserts cart `line_id`/`sku` may appear but address fields do not.
- CI publishes the JaCoCo HTML/XML report and the Gradle test HTML report
  as build artifacts; flaky-test retries are disabled in CI to keep signal
  honest (max 0 reruns).

## 11. Testing Strategy

This ticket *is* the testing strategy for the cart/checkout slice.

Layers and tools:
- **Unit (JVM)**: JUnit4, `kotlinx-coroutines-test` (`runTest`,
  `StandardTestDispatcher`), Turbine for Flow, MockWebServer for the
  network boundary, Truth/AssertJ for assertions, Moshi for fixture
  parsing. Located in each module's `src/test`.
- **Instrumented (UI)**: Compose UI Test, Hilt testing
  (`HiltAndroidRule`, `@TestInstallIn`), `HiltTestActivity`. Located in
  `feature-*/src/androidTest`. Run on an API 34 emulator in CI.
- **Fakes over mocks** where state matters (`FakeCartRepository`); MockK
  only for narrow interaction verification.

Representative matrix:

| Area | Case | Tier |
|---|---|---|
| DTO map | full cart, empty cart, missing optional fields | unit |
| Cart edit | +qty / -qty to 0 / remove last line | unit + UI |
| Search | name hit, SKU hit, no match, clear | unit + UI |
| Checkout | create session success, review render | unit + UI |
| Address | apply address+shipping updates totals | unit + UI |
| Resilience | timeout, GET retry, POST no-retry, 401 refresh | unit |
| Errors | three `detail` shapes | unit |
| Offline | stale cache emitted on failure | unit |

Exit criteria: all tests green; JaCoCo line coverage >= 80% on
`feature-cart`, `feature-checkout` ViewModel + repository packages and
their `core-*` mappers; zero CI reruns required.

## 12. Dependencies & Sequencing

- **Depends on**: AND-210 (DTOs/API to test), AND-211 (Cart screen +
  ViewModel + test tags), AND-212 (in-cart search), AND-213 (checkout
  session), AND-214 (address/shipping). The backlog lists Deps: AND-213;
  in practice the suite cannot be fully written until 210/211/212/214 are
  also merged, so it is sequenced last in M5/E29 for this slice. Partial
  authoring may begin per-subject as each dependency merges.
- **Transitive**: AND-211→AND-210→AND-027; AND-213→AND-211/AND-227.
- **Uses**: `core-testing` infrastructure (must expose
  `MainDispatcherRule`, `MockBackend`, Hilt test activity). If any helper
  is missing, this ticket adds it to `core-testing`.
- **Blocks**: nothing directly, but a green suite is the merge gate for any
  follow-up refactor of the cart/checkout code (e.g. AND-216 analytics).

## 13. Risks & Open Questions

- R1: Test tags / content descriptions may be missing on feature screens →
  UI assertions become brittle text matches. Mitigation: file fast-follow
  tickets to add `testTag`s; prefer semantics over raw text.
- R2: Exact totals semantics (client sum vs server-authoritative) must be
  confirmed against AND-210's mapper. Open question: does PATCH always
  return recomputed totals, or must the client recompute? Tests assume
  server-authoritative; confirm with the AND-210 owner.
- R3: `/ui/checkout/session` "file-bundle" parameter shape is
  under-specified in the backlog; capture the real request body from
  `/openapi.json` before pinning the fixture (AND-213 owns the contract).
- R4: Emulator flakiness in CI for `connectedDebugAndroidTest`. Mitigation:
  pinned AVD image, disabled animations (`@get:Rule disableAnimations`),
  generous idling via Compose's auto-sync.
- R5: AND-216 telemetry timing — if it merges after this suite, telemetry
  assertions (Section 10) are deferred and owned by AND-216.

## 14. Acceptance Criteria

AC-1. `./gradlew testDebugUnitTest` passes with the repo tests described in
FR-1/FR-3/FR-4/FR-5 present and green.

AC-2. `./gradlew connectedDebugAndroidTest` passes with the UI tests in
FR-2/FR-3 present and green on the CI emulator.

AC-3. Cart DTO mapping test asserts line items and all totals fields
deserialize correctly, including an empty-cart fixture.

AC-4. UI tests prove add / update-qty / remove change line and grand
totals and persist across recomposition; empty cart shows the placeholder
and a disabled checkout CTA.

AC-5. In-cart search test filters by name and SKU and restores on clear.

AC-6. Checkout test proves `POST /ui/checkout/session` success advances to
the review state with mapped totals, and the CTA is disabled while loading.

AC-7. Address/shipping test proves selection updates review totals.

AC-8. Resilience tests prove: 20s timeout → Timeout error; one retry for
`GET /ui/cart`; zero retries for `POST /ui/checkout/session`; exactly one
`POST /ui/session/refresh` on 401 then retry.

AC-9. Error-mapping tests prove all three FastAPI `detail` shapes map to
the correct typed `ApiResult.Error`.

AC-10. JaCoCo report is generated and line coverage >= 80% on the named
packages; the build fails below the floor.

AC-11. No test touches the live dev host (`18.222.237.167:8000`); all I/O
is MockWebServer or fakes.

## 15. Definition of Done

- All AC-1…AC-11 met and verified in CI on branch `android-port`.
- Test source added under the correct `src/test` / `src/androidTest` sets
  in `core-network`, `core-data`, `core-model`, `feature-cart`,
  `feature-checkout`; fixtures under `src/test/resources/fixtures/`.
- `core-testing` exposes any new shared helper used here.
- JaCoCo coverage gate wired into the Gradle verification task and CI
  workflow; report published as an artifact.
- No flaky reruns required (CI rerun count = 0); animations disabled for
  instrumented tests.
- No new `main`-source behaviour added beyond test-only visibility shims;
  no secrets or real PII in fixtures.
- Code reviewed and merged; the suite is the merge gate for subsequent
  cart/checkout changes.
