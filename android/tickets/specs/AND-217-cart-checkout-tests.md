---
id: AND-217
title: Cart/checkout tests
milestone: M5
epic: E29
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
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
   `POST /ui/session/refresh`-on-401 path. (`/ui/session/refresh` verified
   in `openapi.index.txt` and `src/api/client.ts: refreshSession`.)
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
  - AND-213 — checkout/review screen. **CORRECTION:** the web reference
    checkout flow does NOT call `POST /ui/checkout/session`. `Checkout.tsx`
    reuses the cart endpoints — `GET /ui/shoppingcart/carts/{cart_id}/items`,
    `GET /ui/shoppingcart/carts/{cart_id}/total`, and
    `POST /ui/shoppingcart/carts/{cart_id}/purchase` (`purchaseCart`). A
    `POST /ui/checkout/session` endpoint (`UnifiedCheckoutSessionIn` →
    `UnifiedCheckoutSessionOut`) does exist in the API but is unused by this
    slice's web client; tests should target the purchase flow the web app
    actually uses unless the AND-213 owner confirms a session-based design.
  - AND-214 — **UNVERIFIED:** no address entry or shipping-option selection
    appears anywhere in the cart/checkout web reference; `CartPurchaseIn`
    has only `promo_code` / `promo_code_id`. The real post-cart feature is
    promo-code validation (`Checkout.tsx`, SHOP-002). Treat address/shipping
    as an unconfirmed assumption pending the AND-214 owner.
- Web reference: `frontend/src/api/endpoints/cart.ts` (cart AND checkout both
  use this file — there is no separate checkout endpoints module) and
  `frontend/src/api/types.ts` are the canonical shapes the Android DTOs
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
- Cart items deserialization → domain model (AND-210). **CORRECTION:**
  items come from `ShoppingCartItemsOut` = `{cart_id, items: [...]}`; each
  item (`ShoppingCartItemOut` / web `CartItem`) is keyed by `sku` (there is
  no `line_id`) with integer **cents** fields `unit_price_cents` and
  `line_total_cents`, plus `quantity`, `name`, `updated_at`, and optional
  `image_url` / `category_id` / `item_id`. The cart total is a SEPARATE
  endpoint `GET /ui/shoppingcart/carts/{cart_id}/total` →
  `ShoppingCartTotalOut` = `{cart_id, total_cents: int, currency}`. There is
  no `subtotal` / `tax` / `shipping` / `grand_total` breakdown and no
  float-dollar fields in the API.
- Add item, update quantity, remove item (by `sku`); after a mutation the
  client re-fetches items AND total (server-authoritative) and the rendered
  total reflects the new value across recomposition (AND-211). Quantity uses
  `PATCH .../items/{sku}` body `{"quantity": n}` (`ShoppingCartUpdateQtyIn`,
  integer 0–1000); the web UI clamps the decrement to a floor of 1 and uses
  `DELETE .../items/{sku}` for removal.
- Empty-cart state renders the empty placeholder ("Cart is empty") and a
  disabled checkout CTA (AND-211).
- In-cart search (AND-212). **UNVERIFIED:** the web Cart page has no in-cart
  line filter. A catalog search endpoint `GET
  /ui/shoppingcart/carts/items/search?q=&limit=` exists but searches the
  catalog to ADD items, not to filter the current cart. Confirm the AND-212
  scope (in-cart filter vs. catalog search) with its owner before pinning.
- Checkout/review maps cart items + total and advances UI to the review
  state; the place-order CTA is disabled while the purchase is in flight and
  when no payment method is selected or the cart is empty (AND-213, per
  `Checkout.tsx`). The actual commit is `POST
  /ui/shoppingcart/carts/{cart_id}/purchase` (`CartPurchaseIn`) returning
  `ShoppingCartPurchaseOut` with `order_id`.
- Promo-code application updates the displayed total (AND-214 scope as
  actually implemented in the web ref, SHOP-002): a validated promo's
  `final_price_cents` / `discount_cents` replaces the cart total in the
  review summary. **NOTE:** this supersedes the original "address + shipping"
  claim, which is unverified (see Section 2).

FR-4. Resilience-path tests: 20s timeout surfaces a timeout UI state;
bounded backoff retry fires for idempotent GETs only — e.g.
`GET /ui/shoppingcart/carts/{cart_id}/items` and `.../total` — and NOT for
the non-idempotent `POST .../purchase`. **NOTE:** the purchase endpoint
accepts an `X-Idempotency-Key` header (verified in `openapi.index.txt`), so
the "POST is never safe to retry" rule is a deliberate client-side policy,
not a server constraint; if AND-213 opts to send an idempotency key, the
no-retry assertion should be revisited. A single `POST /ui/session/refresh`
is attempted on a 401 (only when already authenticated) and the original
request is retried exactly once (`src/api/client.ts`).

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
`/openapi.json` and the web reference. **The previous draft of this section
listed `/ui/cart`, `/ui/cart/lines/{line_id}`, and a `review`/`address`/
`shipping` checkout-session body that do not exist.** The real contracts,
verified against `openapi.index.txt`, `openapi.pretty.json`, and
`src/api/endpoints/cart.ts` / `src/api/types.ts`, are below. All monetary
fields are **integer cents**, not float dollars.

`GET /ui/shoppingcart/carts/{cart_id}/items` → 200 (`ShoppingCartItemsOut`):

```json
{
  "cart_id": "c_01HZ...",
  "items": [
    {"sku": "SKU-001", "name": "Widget", "quantity": 2,
     "unit_price_cents": 999, "line_total_cents": 1998,
     "updated_at": "2026-06-01T00:00:00Z",
     "image_url": null, "category_id": null, "item_id": null}
  ]
}
```

`GET /ui/shoppingcart/carts/{cart_id}/total` → 200 (`ShoppingCartTotalOut`):

```json
{"cart_id": "c_01HZ...", "total_cents": 1998, "currency": "USD"}
```

(There is no `subtotal`/`tax`/`shipping`/`grand_total` — the only total the
API returns is `total_cents`.)

`PATCH /ui/shoppingcart/carts/{cart_id}/items/{sku}` body `{"quantity": 3}`
(`ShoppingCartUpdateQtyIn`, integer 0–1000) → 200 (`ShoppingCartItemOut`,
the updated line). `DELETE /ui/shoppingcart/carts/{cart_id}/items/{sku}`
(optional `?decrement=` query) → 200 (`OkResp`). After either, the client
re-fetches items + total rather than reading recomputed totals from the
mutation response.

`POST /ui/shoppingcart/carts/{cart_id}/purchase` body (`CartPurchaseIn`,
optional `{"promo_code": "...", "promo_code_id": "..."}`; accepts an
`X-Idempotency-Key` header) → 200 (`ShoppingCartPurchaseOut`):

```json
{
  "cart_id": "c_01HZ...", "order_id": "o_01J...",
  "purchased_at": "2026-06-05T00:00:00Z",
  "purchased_total_cents": 1998, "currency": "USD",
  "discount_cents": 0, "promo_code_id": null
}
```

(For reference only — UNUSED by this slice's web client — a unified
`POST /ui/checkout/session` exists: `UnifiedCheckoutSessionIn` requires
`source` ∈ {cart,direct,subscription_action} and accepts optional `cart_id`,
`sku`, `quantity`, `billing_model`, `product_type`; it returns
`UnifiedCheckoutSessionOut` = `{checkout_session_id, order_id, source,
status: "pending_payment", line_items}`. There is no `session_id`, `review`,
`address`, or `shipping_option`, and no `file_bundle` field on the request.)

Error fixtures (asserted by FR-5), all under FastAPI `detail` — the three
shapes the web client's `normalizeErrorDetail` actually handles
(`src/api/client.ts`):

```json
{"detail": "Cart is empty"}
{"detail": [{"loc": ["body","quantity"], "msg": "must be >= 1"}]}
{"detail": {"code": "role_required", "message": "..."}}
```

(The object form is decoded by `code` in the web client's
`mapAuthorizationError`; a `{code,message}` validation/business error such as
`role_required` is the realistic shape — `checkout_locked` from the prior
draft is illustrative only and unverified.)

All request paths above are mounted on MockWebServer with a `Dispatcher`
that matches method+path, returning the corresponding fixture and (for
resilience tests) `503` / socket-stall / `401` responses.

## 6. Data & State Management

Tests assert the dependency tickets' state contracts, they do not own them:

- `CartViewModel` exposes `StateFlow<CartUiState>` where
  `CartUiState = Loading | Empty | Content(cart, query, filteredLines) |
  Error(TlError) | Offline(staleCart)`. Tests use Turbine
  (`viewModel.uiState.test { ... }`) to assert the emitted sequence on each
  action.
- Totals are server-authoritative. **CORRECTION:** the PATCH/DELETE
  responses do NOT carry cart-level totals; the web client re-fetches `GET
  .../total` (`ShoppingCartTotalOut.total_cents`) after every mutation
  (`Cart.tsx` invalidates both the `cart-items` and `cart-total` queries).
  UI tests assert the rendered total equals the `total_cents` fixture (in
  cents, formatted via the currency formatter), not a client-side sum, to
  catch mapping drift.
- Stale-cart persistence (Room cache from AND-210) is verified by an
  in-memory Room database test: write a cart, simulate `GET /ui/cart`
  failure, assert `Offline(staleCart)` is emitted from cache.
- Cookie jar + CSRF (verified, `src/api/client.ts`): a persistent-cookie
  test asserts that a `Set-Cookie` (`ui_csrf`) from `GET
  /ui/shoppingcart/carts/{cart_id}/items` is echoed as the `X-CSRF-Token`
  header on the subsequent `PATCH`, using `server.takeRequest()` header
  inspection. Note the web client attaches `X-CSRF-Token` to ALL requests
  when the `ui_csrf` cookie is present (not only mutating ones), and also
  sends `Authorization: Bearer <token>`; auth-state headers `X-SESSION-ID` /
  `X-IMPERSONATION-TOKEN` appear in the OpenAPI param lists.

## 7. Error Handling & Resilience

The suite is the primary enforcement point for the project resilience
rules. Specific cases:

- **Timeout**: MockWebServer `socketPolicy = NO_RESPONSE` (or throttled
  body) → repository emits `ApiResult.Error(TlError.Timeout)` after the
  ~20s read timeout; with `runTest` virtual time this completes instantly.
- **Idempotent retry**: `GET /ui/shoppingcart/carts/{cart_id}/items`
  returns `503` then `200`; assert the repository performs exactly one retry
  (bounded backoff) and succeeds. Assert via `server.requestCount == 2`.
- **No retry for non-idempotent**: `POST
  /ui/shoppingcart/carts/{cart_id}/purchase` returns `503`; assert
  `requestCount == 1` and `ApiResult.Error` is returned. (Client policy —
  the endpoint does accept `X-Idempotency-Key`; see FR-4.)
- **Refresh-on-401**: first call → `401`; `POST /ui/session/refresh` → `200`;
  retried original → `200`. Assert the refresh endpoint was hit exactly
  once and a second 401 does NOT loop (the web client logs out rather than
  re-refreshing; verified `src/api/client.ts`).
- **detail mapping** (FR-5): three fixtures → `TlError.Message`,
  `TlError.Validation(field→msg)`, `TlError.Coded(code)` respectively
  (mirrors `normalizeErrorDetail`: string passthrough, array-of-`{msg}`
  join, object-with-`code` mapping).
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
  formatting by checking currency rendering goes through the formatter. The
  web ref formats with `Intl.NumberFormat("en-US", {style:"currency",
  currency})` applied to `cents / 100` (`Cart.tsx` / `Checkout.tsx`
  `formatCents`); the Android equivalent must divide integer cents by 100
  and format via the currency formatter. Test in `en-US`; a `de-DE` smoke
  variant validates locale-aware number formatting if the formatter is
  locale-driven. Full i18n coverage is owned by the feature tickets.

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
- R3: RESOLVED during review — the cart/checkout web flow does not use
  `/ui/checkout/session` at all; it commits via `POST
  /ui/shoppingcart/carts/{cart_id}/purchase` (`CartPurchaseIn`). The
  separate `UnifiedCheckoutSessionIn` has no `file_bundle` field (it has
  `source`/`cart_id`/`sku`/`quantity`/`billing_model`/`product_type`). If
  AND-213 deliberately adopts the session API, re-pin against
  `UnifiedCheckoutSessionOut`; otherwise pin the purchase contract.
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

AC-3. Cart items DTO mapping test asserts each `sku`-keyed line
(`unit_price_cents`, `line_total_cents`, `quantity`) and the separate
`total_cents` deserialize correctly, including an empty-cart fixture.

AC-4. UI tests prove add / update-qty (by `sku`) / remove change the line
and the re-fetched cart total and persist across recomposition; empty cart
shows the placeholder ("Cart is empty") and a disabled checkout CTA.

AC-5. Cart-search test (SCOPE PENDING — confirm in-cart filter vs. catalog
`GET /ui/shoppingcart/carts/items/search`): filters by name and SKU and
restores on clear.

AC-6. Checkout test proves `POST /ui/shoppingcart/carts/{cart_id}/purchase`
success advances to the confirmed/review state with mapped totals (cents),
and the place-order CTA is disabled while loading / with no payment method.

AC-7. Promo-code test proves applying a validated promo updates the review
total (`final_price_cents`). (Supersedes the unverified address/shipping
claim — see Sections 2/3.)

AC-8. Resilience tests prove: 20s timeout → Timeout error; one retry for
`GET /ui/shoppingcart/carts/{cart_id}/items`; zero retries for `POST
.../purchase`; exactly one `POST /ui/session/refresh` on 401 then retry.

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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **Cart items endpoint is `GET /ui/shoppingcart/carts/{cart_id}/items`**
   (not `GET /ui/cart`). VERDICT: Corrected. SOURCE: OpenAPI `GET
   /ui/shoppingcart/carts/{cart_id}/items` (op
   `ui_list_items...`, resp `ShoppingCartItemsOut`);
   `src/api/endpoints/cart.ts: getCartItems`.
2. **Cart total is a separate endpoint `GET
   /ui/shoppingcart/carts/{cart_id}/total` → `{cart_id, total_cents,
   currency}`** with no subtotal/tax/shipping/grand_total breakdown.
   VERDICT: Corrected. SOURCE: OpenAPI `GET
   /ui/shoppingcart/carts/{cart_id}/total` (resp `ShoppingCartTotalOut`);
   schema `ShoppingCartTotalOut` (`openapi.pretty.json`);
   `src/api/endpoints/cart.ts: getCartTotal`, `src/api/types.ts: CartTotal`.
3. **Monetary fields are integer cents** (`unit_price_cents`,
   `line_total_cents`, `total_cents`), not float dollars (`unit_price`,
   `line_total`, `subtotal`...). VERDICT: Corrected. SOURCE:
   `src/api/types.ts: CartItem`, `CartTotal`; schema `ShoppingCartItemOut`.
4. **Cart lines are keyed by `sku`, there is no `line_id`.** VERDICT:
   Corrected. SOURCE: `src/api/types.ts: CartItem` (no `line_id` field);
   `src/pages/shop/Cart.tsx` (`key={item.sku}`, mutations by `item.sku`).
5. **Quantity update is `PATCH /ui/shoppingcart/carts/{cart_id}/items/{sku}`
   body `{"quantity": int}` (`ShoppingCartUpdateQtyIn`, 0–1000).** VERDICT:
   Corrected (was `PATCH /ui/cart/lines/{line_id}`). SOURCE: OpenAPI `PATCH
   /ui/shoppingcart/carts/{cart_id}/items/{sku}` (req
   `ShoppingCartUpdateQtyIn`); schema `ShoppingCartUpdateQtyIn`;
   `src/api/endpoints/cart.ts: updateCartItemQty`.
6. **Item removal is `DELETE /ui/shoppingcart/carts/{cart_id}/items/{sku}`
   (optional `?decrement=`) → `OkResp`.** VERDICT: Corrected (was `DELETE
   /ui/cart/lines/{line_id}`). SOURCE: OpenAPI `DELETE
   /ui/shoppingcart/carts/{cart_id}/items/{sku}` (params include
   `decrement`); `src/api/endpoints/cart.ts: removeCartItem`.
7. **Mutations do NOT return cart-level totals; the client re-fetches items
   + total.** VERDICT: Corrected (was "PATCH/DELETE responses carry new
   totals"). SOURCE: `src/pages/shop/Cart.tsx` (updateQty/remove mutations
   invalidate both `cart-items` and `cart-total` queries).
8. **Checkout commit is `POST /ui/shoppingcart/carts/{cart_id}/purchase`
   (`CartPurchaseIn` = optional `promo_code`/`promo_code_id`) →
   `ShoppingCartPurchaseOut` (`order_id`, `purchased_total_cents`, ...).**
   VERDICT: Corrected (was `POST /ui/checkout/session`). SOURCE: OpenAPI
   `POST /ui/shoppingcart/carts/{cart_id}/purchase` (req `CartPurchaseIn`,
   param `X-Idempotency-Key`, resp `ShoppingCartPurchaseOut`); schema
   `CartPurchaseIn`; `src/api/endpoints/cart.ts: purchaseCart`;
   `src/pages/shop/Checkout.tsx: purchaseMutation`.
9. **`POST /ui/checkout/session` exists but is unused by the cart/checkout
   web client; its request is `UnifiedCheckoutSessionIn` (required `source`;
   no `file_bundle`) and response `UnifiedCheckoutSessionOut`
   (`checkout_session_id`, `order_id`, `source`, `status:"pending_payment"`,
   `line_items` — no `session_id`/`review`/`address`/`shipping_option`).**
   VERDICT: Corrected. SOURCE: OpenAPI `POST /ui/checkout/session` (req
   `UnifiedCheckoutSessionIn`, resp `UnifiedCheckoutSessionOut`); schemas
   `UnifiedCheckoutSessionIn`/`UnifiedCheckoutSessionOut`
   (`openapi.pretty.json`); absence in `src/pages/shop/Checkout.tsx`.
10. **No address/shipping selection exists in the cart/checkout web flow;
    the real post-cart feature is promo-code validation.** VERDICT:
    Corrected → Unverified-assumption (original AND-214 claim cannot be
    confirmed). SOURCE: `src/pages/shop/Checkout.tsx` (promo + payment
    method only, no address/shipping); schema `CartPurchaseIn` (only
    `promo_code`/`promo_code_id`).
11. **Refresh-on-401: single `POST /ui/session/refresh`, original request
    retried exactly once, no refresh loop (logout on second 401), and only
    when already authenticated.** VERDICT: Verified. SOURCE: OpenAPI `POST
    /ui/session/refresh`; `src/api/client.ts` (`refreshSession`, single
    `refreshPromise`, single retry, `logout("session_expired")`).
12. **CSRF: `ui_csrf` cookie echoed as the `X-CSRF-Token` header on
    requests.** VERDICT: Verified (with refinement: sent on ALL requests
    when the cookie is present, plus `Authorization: Bearer`). SOURCE:
    `src/api/client.ts` (`getCookie("ui_csrf")` →
    `headers.set("X-CSRF-Token", csrf)`).
13. **FastAPI `detail` has three handled shapes — string, array of `{msg}`,
    object with `code`.** VERDICT: Verified. SOURCE: `src/api/client.ts:
    normalizeErrorDetail` + `mapAuthorizationError` (object-by-`code`);
    `client.errorMapping.test.ts`.
14. **422 `HTTPValidationError` is the validation error response for cart
    mutations and purchase.** VERDICT: Verified. SOURCE: OpenAPI resp
    `422:HTTPValidationError` on the cart items/purchase ops.
15. **Currency rendering divides integer cents by 100 and formats via
    `Intl.NumberFormat` (en-US default).** VERDICT: Verified (Android must
    mirror: cents/100 through a currency formatter). SOURCE:
    `src/pages/shop/Cart.tsx` / `Checkout.tsx` `formatCents`.
16. **In-cart search by name/SKU (AND-212).** VERDICT: Unverified-
    assumption. SOURCE: web Cart page has no in-cart filter
    (`src/pages/shop/Cart.tsx`); the only search is catalog item search
    (OpenAPI `GET /ui/shoppingcart/carts/items/search` params `q,limit`),
    which adds items rather than filtering the cart.
17. **Cart status string is `"OPEN"` (uppercase).** VERDICT: Verified.
    SOURCE: `src/pages/shop/Cart.tsx` (`c.status === "OPEN"`); schema
    `ShoppingCartSummary.status`.
18. **Purchase POST treated as non-retryable by client policy though the
    server accepts `X-Idempotency-Key`.** VERDICT: Verified (header exists;
    no-retry is a deliberate client choice). SOURCE: OpenAPI `POST
    .../purchase` param `X-Idempotency-Key`.
19. **Android stack / build choices (Compose, Hilt, Retrofit/OkHttp/Moshi,
    JaCoCo, MockWebServer, Turbine, `runTest`/`StandardTestDispatcher`,
    `createAndroidComposeRule`, `@TestInstallIn`).** VERDICT: Unverified-
    assumption (not derivable from backend/frontend sources; standard
    Android testing stack). SOURCE (framework refs):
    https://developer.android.com/jetpack/compose/testing ,
    https://developer.android.com/training/dependency-injection/hilt-testing
    , https://github.com/square/okhttp/tree/master/mockwebserver ,
    https://developer.android.com/kotlin/coroutines/test .
20. **Physical-device vs emulator targeting for instrumented tests.**
    VERDICT: Unverified-assumption (CI/dev infra choice). SOURCE: ticket
    test-targets brief (emulator AVD `test35` API 35; Samsung A15 SM-A156U
    API 34) — no hardware-only behaviour in this slice, so the emulator is
    sufficient; one device run validates API-34/arm64 parity.

### Corrections made

- §2/§3/§5/§14: replaced the non-existent `GET /ui/cart`,
  `PATCH|DELETE /ui/cart/lines/{line_id}` with the real
  `/ui/shoppingcart/carts/{cart_id}/items[/{sku}]` + `/total` endpoints
  (items keyed by `sku`, integer-cents fields).
- §5/§14/§13-R3: replaced the fictional `POST /ui/checkout/session` body
  (`file_bundle`, `review`, `address`, `shipping_option`,
  `status:"requires_payment"`, `session_id`) — the slice commits via `POST
  .../purchase` (`CartPurchaseIn` → `ShoppingCartPurchaseOut`); documented
  the real `UnifiedCheckoutSession*` shapes for reference.
- §3/§6: corrected totals model — separate `total_cents` endpoint,
  re-fetched after mutations (not returned by PATCH/DELETE), formatted from
  cents.
- §2/§3/§14 (AC-7): replaced unverifiable address/shipping (AND-214) with
  the promo-code feature the web ref actually implements; flagged the
  original as an open assumption.
- §3/§14 (AC-5): flagged in-cart search (AND-212) as scope-pending vs. the
  catalog search endpoint.
- §4/§7/§8: corrected resilience/CSRF endpoint paths and noted purchase
  `X-Idempotency-Key`, refresh-only-when-authenticated, and CSRF-on-all-
  requests refinements.

### Open assumptions

- **AND-214 address/shipping** — unverifiable: nothing in the cart/checkout
  web reference or `CartPurchaseIn` supports address or shipping selection.
  Confirm scope with the AND-214 owner; tests are written against the
  promo-code flow until then.
- **AND-212 in-cart search** — unverifiable as an in-cart filter; the only
  matching API is catalog item search. Confirm whether AND-212 filters the
  current cart client-side or searches the catalog.
- **AND-213 design (purchase vs. unified session)** — the web ref uses
  `purchase`; `/ui/checkout/session` exists but is unused here. Confirm
  which contract AND-213 ships before pinning fixtures.
- **Android stack & coverage floor (80%)** — framework/process choices not
  derivable from the backend/frontend; standard Android references cited.
- **Idempotency-key usage on purchase** — server supports
  `X-Idempotency-Key`; whether AND-213 sends one (and thus whether the
  POST-no-retry rule holds) is unconfirmed.

## 17. Test Plan

IDs `TC-AND-217-NN`. "Traces" links to Section-14 acceptance criteria. All
network I/O is MockWebServer or fakes (AC-11); no live dev host. Unless a
case is marked physical-device-required, JVM/Robolectric or the headless
emulator AVD `test35` (API 35) is used; one parity case runs on the Samsung
Galaxy A15 5G (SM-A156U, API 34, arm64-v8a).

**TC-AND-217-01 — Cart items + total DTO mapping (happy path)**
- Type: unit (JVM). Target: JVM unit/Robolectric (local).
- Preconditions: `ShoppingCartItemsOut` and `ShoppingCartTotalOut` golden
  fixtures (cents) under `src/test/resources/fixtures/`.
- Steps: Enqueue items fixture for `GET .../items` and total fixture for
  `GET .../total`; call `CartRepository.getItems`/`getTotal`.
- Expected: each item maps `sku`, `quantity`, `unit_price_cents`,
  `line_total_cents`; total maps `total_cents`/`currency`; no float fields.
- Traces: AC-3.

**TC-AND-217-02 — Empty-cart fixture maps to empty state**
- Type: unit (JVM). Target: JVM unit (local).
- Preconditions: `{cart_id, items: []}` items fixture; total `0`.
- Steps: Deserialize; map to `CartUiState`.
- Expected: `Empty` state; no exceptions; total renders as zero-cents
  currency.
- Traces: AC-3, AC-4.

**TC-AND-217-03 — Update quantity by SKU re-fetches items + total**
- Type: contract/MockWebServer (JVM). Target: JVM unit (local).
- Preconditions: MockWebServer `Dispatcher` for `PATCH .../items/{sku}`
  (returns updated line) plus refreshed `GET .../items` and `.../total`.
- Steps: Call `setQuantity(sku, 3)`; inspect `server.takeRequest()`.
- Expected: PATCH path is `/ui/shoppingcart/carts/{cart_id}/items/{sku}`,
  body `{"quantity":3}`; repository then GETs items + total and surfaces the
  re-fetched `total_cents` (not a client sum).
- Traces: AC-4.

**TC-AND-217-04 — Remove line by SKU updates total**
- Type: contract/MockWebServer (JVM). Target: JVM unit (local).
- Preconditions: Dispatcher for `DELETE .../items/{sku}` → `OkResp`, then
  reduced items + total.
- Steps: Call `removeLine(sku)`.
- Expected: DELETE path correct; subsequent total reflects removal; success
  `ApiResult`.
- Traces: AC-4.

**TC-AND-217-05 — Three FastAPI `detail` shapes map to typed errors**
- Type: unit (JVM). Target: JVM unit (local).
- Preconditions: three fixtures — `"Cart is empty"`,
  `[{"loc":...,"msg":"must be >= 1"}]`, `{"code":"role_required",...}`.
- Steps: Enqueue each as the error body; call the repository.
- Expected: `TlError.Message` / `TlError.Validation(field→msg)` /
  `TlError.Coded(code)` respectively, matching `normalizeErrorDetail`.
- Traces: AC-9.

**TC-AND-217-06 — Idempotent GET retried once on 503 then 200**
- Type: contract/MockWebServer (JVM, virtual time). Target: JVM unit.
- Preconditions: `GET .../items` enqueued `503` then `200`.
- Steps: Call `getItems` under `runTest` + `MainDispatcherRule`.
- Expected: exactly one retry (`server.requestCount == 2`); `Success`.
- Traces: AC-8.

**TC-AND-217-07 — Non-idempotent purchase POST not retried on 503**
- Type: contract/MockWebServer (JVM). Target: JVM unit.
- Preconditions: `POST .../purchase` enqueued `503`.
- Steps: Call `CheckoutRepository.purchase(cartId)`.
- Expected: `requestCount == 1`; `ApiResult.Error`; no second attempt.
  (Documents the client no-retry policy despite `X-Idempotency-Key`.)
- Traces: AC-8.

**TC-AND-217-08 — 20s read timeout surfaces Timeout (virtual time)**
- Type: contract/MockWebServer (JVM). Target: JVM unit.
- Preconditions: `GET .../items` with `socketPolicy = NO_RESPONSE`.
- Steps: Call under `runTest` virtual time advancing past 20s.
- Expected: `ApiResult.Error(TlError.Timeout)`; completes instantly in
  virtual time.
- Traces: AC-8.

**TC-AND-217-09 — Single session refresh on 401 then one retry**
- Type: contract/MockWebServer (JVM). Target: JVM unit.
- Preconditions: original request `401`; `POST /ui/session/refresh` `200`;
  retried original `200`. A second 401 variant verifies logout (no loop).
- Steps: Call the repository while "authenticated".
- Expected: `/ui/session/refresh` hit exactly once; original retried once →
  success; second-401 variant does NOT loop (logout/Error).
- Traces: AC-8.

**TC-AND-217-10 — CSRF cookie echoed as X-CSRF-Token header**
- Type: contract/MockWebServer (JVM). Target: JVM unit.
- Preconditions: `GET .../items` responds `Set-Cookie: ui_csrf=...`.
- Steps: Perform GET then a `PATCH .../items/{sku}`; inspect requests.
- Expected: the PATCH carries `X-CSRF-Token: <ui_csrf>` (and
  `Authorization: Bearer`), via the production interceptor chain.
- Traces: AC-8 (security path), AC-11.

**TC-AND-217-11 — Offline/stale cache vs. empty cache on GET failure**
- Type: integration (Robolectric + in-memory Room). Target: JVM/Robolectric.
- Preconditions: Room cache populated with a prior cart; `GET .../items`
  fails (503/timeout). Second variant: empty cache.
- Steps: Trigger load; observe `CartUiState` via Turbine.
- Expected: populated cache → `Offline(staleCart)` with stale banner; empty
  cache → `Error`.
- Traces: AC-8, AC-11.

**TC-AND-217-12 — Cart screen: empty state + disabled checkout CTA**
- Type: Compose-UI (instrumented). Target: emulator AVD `test35`.
- Preconditions: `FakeCartRepository` empty; Hilt `@TestInstallIn`.
- Steps: Launch `CartScreen`; assert placeholder + CTA.
- Expected: "Cart is empty" placeholder shown; checkout CTA
  `assertIsNotEnabled()`.
- Traces: AC-4, AC-2.

**TC-AND-217-13 — Cart screen: qty +/- and remove update totals across recomposition**
- Type: Compose-UI (instrumented). Target: emulator AVD `test35`.
- Preconditions: `FakeCartRepository` with two lines; total updates on
  mutate.
- Steps: Tap `+`, `-`, and remove; rotate/recompose.
- Expected: line total and cart total (cents-formatted) reflect server
  values; values survive recomposition; `-` clamps at qty 1 (remove via
  trash control).
- Traces: AC-4, AC-2.

**TC-AND-217-14 — Checkout/purchase: success advances to confirmed + CTA disabled while loading**
- Type: Compose-UI (instrumented). Target: emulator AVD `test35`.
- Preconditions: `FakeCheckoutRepository` returns `ShoppingCartPurchaseOut`
  after a delay; a payment method is selected.
- Steps: Open checkout; tap Place Order; confirm dialog.
- Expected: CTA `assertIsNotEnabled()` while in flight; on success the
  confirmed/review state shows the mapped `order_id` and cents total; CTA
  also disabled when no payment method / empty cart.
- Traces: AC-6, AC-2.

**TC-AND-217-15 — Promo code application updates review total**
- Type: Compose-UI (instrumented). Target: emulator AVD `test35`.
- Preconditions: `FakeCheckoutRepository`/fake promo validation returning a
  valid promo (`discount_cents`, `final_price_cents`).
- Steps: Expand promo, enter code, Apply.
- Expected: review total switches to `final_price_cents` (cents-formatted);
  invalid-code variant shows the error and leaves total unchanged.
- Traces: AC-7, AC-2.

**TC-AND-217-16 — Accessibility: icon-only controls are labeled**
- Type: Compose-UI (instrumented, a11y). Target: emulator AVD `test35`.
- Preconditions: cart with one line.
- Steps: Query `onNodeWithContentDescription` for qty +/- and remove;
  assert merged-semantics text on placeholder/CTA.
- Expected: every icon-only control has a non-empty content description;
  test fails if any is unlabeled.
- Traces: AC-4 (a11y), AC-2.

**TC-AND-217-17 — In-cart search (SCOPE-PENDING) filters by name/SKU and restores**
- Type: Compose-UI (instrumented). Target: emulator AVD `test35`.
- Preconditions: cart with multiple lines; assumes an in-cart filter exists
  (see §16 open assumption — may be re-scoped to catalog search).
- Steps: Type a name, then a SKU, then clear.
- Expected: visible lines filter on each query and restore on clear. If
  AND-212 is catalog search, this becomes a catalog `GET .../items/search?q`
  contract test instead.
- Traces: AC-5, AC-2.

**TC-AND-217-18 — Device parity: API-34 / arm64 instrumented smoke**
- Type: instrumented/e2e. Target: PHYSICAL DEVICE (Samsung Galaxy A15 5G,
  SM-A156U, API 34, arm64-v8a) — MUST run on the device to validate
  arm64/API-34 vs. emulator x86_64/API-35 parity.
- Preconditions: app installed via adb on serial `R5CX821TA9R`; fakes wired.
- Steps: Run the cart + checkout instrumented suite (TC-12…16).
- Expected: identical pass results to the emulator; no ABI/API-level
  divergence (number/currency formatting, Compose rendering).
- Traces: AC-2, AC-4, AC-6.

**TC-AND-217-19 — JaCoCo coverage floor enforced**
- Type: manual/CI gate. Target: CI build server (JVM).
- Preconditions: coverage verification task wired into Gradle.
- Steps: Run `./gradlew testDebugUnitTest jacocoTestCoverageVerification`.
- Expected: report produced; build fails if line coverage < 80% on the
  `feature-cart`/`feature-checkout` ViewModel + repository packages and the
  `core-*` mappers.
- Traces: AC-10.

**TC-AND-217-20 — No live dev-host traffic**
- Type: manual/CI guard. Target: CI (JVM + instrumented).
- Preconditions: tests bound to MockWebServer (localhost) / fakes.
- Steps: Inspect test config and (optionally) a network-deny rule; grep test
  output for `18.222.237.167`.
- Expected: zero connections to `18.222.237.167:8000`; all I/O local.
- Traces: AC-11.

### Coverage matrix

| AC | Covered by |
|---|---|
| AC-1 (repo tests green) | TC-01…11, 19 |
| AC-2 (UI tests green) | TC-12…18 |
| AC-3 (DTO mapping incl. empty) | TC-01, TC-02 |
| AC-4 (add/qty/remove + empty/disabled CTA) | TC-02, TC-03, TC-04, TC-12, TC-13, TC-16, TC-18 |
| AC-5 (cart search) | TC-17 (scope-pending) |
| AC-6 (purchase success + CTA disabled) | TC-14, TC-18 |
| AC-7 (promo updates total) | TC-15 |
| AC-8 (timeout/retry/no-retry/refresh) | TC-06, TC-07, TC-08, TC-09, TC-10, TC-11 |
| AC-9 (three detail shapes) | TC-05 |
| AC-10 (JaCoCo floor) | TC-19 |
| AC-11 (no live dev host) | TC-10, TC-11, TC-20 |
