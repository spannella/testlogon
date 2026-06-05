---
id: AND-227
title: Checkout session billing
milestone: M5
epic: E31
priority: P0
size: L
status: draft
depends_on: [AND-225]
blocks: [AND-236]
---

# AND-227 — Checkout session billing

## 1. Overview & Goal

Deliver the end-to-end **purchase completion** flow: turning a selected product (or a cart) into a
server-created checkout session, driving an on-device Stripe payment to a terminal state, and
reconciling the resulting order to a confirmed paid status the app can trust. This is the capstone of
the M5 commerce / E31 billing epic — the first ticket that makes money actually move.

AND-227 wires `POST /ui/billing/checkout_session` (the backend `UnifiedCheckoutSession` endpoint) to
the Stripe `PaymentSheet` launcher from **AND-225**. The endpoint creates `order_id` +
`checkout_session_id` in `pending_payment` status; the app obtains the PaymentIntent `client_secret`,
presents `PaymentSheet`, and on a `Completed` result reconciles the order to paid via the
server-authoritative payment record. The deliverable is a `feature-billing` checkout screen +
`CheckoutViewModel` exposing `StateFlow<CheckoutUiState>`, a `core-data` `CheckoutRepository`, and the
DTOs/state machine modeling the session → pay → confirm flow.

Acceptance bar: **a real purchase completes against the dev backend in Stripe test mode** — create a
session for a known SKU/cart, pay with test card `4242 4242 4242 4242`, and see the order reach a
confirmed paid state surfaced as a success screen. The 3DS/SCA card (`4000 0025 0000 3155`) must also
be exercisable to confirm the `requires_action` branch.

Out of scope: the cart screen (AND-211), address/shipping (AND-214), payment-methods management
(AND-224), and the subscribe flow (AND-236, which builds on this checkout).

## 2. Context & References

- **Stack:** Kotlin 2.0.21, Jetpack Compose + Material 3, single-Activity Navigation-Compose, Hilt
  (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Paging 3. minSdk 24,
  compileSdk/targetSdk 35, JDK 17, Gradle 8.9, AGP 8.7.3.
- **Module layering:** `app -> feature-billing -> core-*`. The checkout screen + ViewModel live in
  `feature-billing`; `CheckoutRepository`, DTOs, and the `BillingApi` extension live in
  `core-data`/`core-model`; the `StripePaymentLauncher`/`PaymentResult` are reused from AND-225
  (`core-ui`/`core-model`).
- **Namespace / applicationId base:** `com.testlogon.android` — used for all packages and the Stripe
  return-URL scheme (`com.testlogon.android.stripe://payment_return`, defined in AND-225).
- **Auth:** cookie-based session, `ui_csrf` echoed as `X-CSRF-Token` on mutating calls; persistent
  cookie jar; single `POST /ui/session/refresh` retry on 401 by the OkHttp authenticator. All
  `/ui/billing/*` calls ride this session.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext HTTP,
  unreliable — design for ~20s timeouts, bounded backoff for idempotent GETs only, offline/stale UI).
  OpenAPI at `/openapi.json`. Error `detail` is `string | [{msg}] | {code,...}`.
- **Authoritative endpoint:** `POST /ui/billing/checkout_session`
  (`operationId: create_checkout_session_ui_billing_checkout_session_post`,
  schemas `UnifiedCheckoutSessionIn` → `UnifiedCheckoutSessionOut`). See §5 for verified shapes pulled
  from the dev `/openapi.json`.
- **Upstream dependency — AND-225 (Stripe Android SDK integration):** provides
  `StripePaymentService`, `StripePaymentLauncher` / `rememberStripePaymentLauncher`,
  `PaymentResult` sealed type, `PaymentConfiguration` bootstrap, and the
  `GET /ui/billing/payment_intents/{id}` reconciliation call. AND-227 **consumes** all of these.
- **Web reference:** `frontend/src/api/endpoints/billing.ts` (`createCheckoutSession`) and
  `frontend/src/api/types.ts` for the canonical `UnifiedCheckoutSession*` field names and the
  `source`/`billing_model`/`product_type` enums.

## 3. Functional Requirements

FR-1. From an entry point (a "Buy" / "Checkout" CTA with a SKU or `cart_id`), the app creates a
checkout session via `POST /ui/billing/checkout_session` and receives `{order_id, checkout_session_id,
status: "pending_payment", source, line_items[]}`.

FR-2. The app obtains the PaymentIntent `client_secret` for the session and presents Stripe
`PaymentSheet` (AND-225 launcher). The session ↔ PaymentIntent linkage is resolved either from the
checkout response (if it carries a `client_secret`/`payment_intent_id` in `line_items`/scope) or via a
follow-up `POST /ui/billing/payment_intents` keyed by `order_id` (see §5, R2).

FR-3. On `PaymentResult.Completed`, the app reconciles the order with the server (poll
`GET /ui/billing/payment_intents/{id}` until `succeeded`, and/or `GET /ui/billing/payments` for the
matching `order_id`) and only then shows a success screen reporting a confirmed purchase.

FR-4. The flow is modeled as an explicit state machine surfaced through `StateFlow<CheckoutUiState>`:
`Idle → CreatingSession → AwaitingPayment → ConfirmingPayment → Succeeded | Failed | Canceled`.

FR-5. `PaymentResult.Canceled` returns the user to the pre-payment state (order remains
`pending_payment`) with a non-error message and a "Try again" affordance; it does **not** create a
duplicate session unless the user re-initiates.

FR-6. `PaymentResult.Failed` (declined card, network, SCA failure) maps to `CheckoutUiState.Failed`
with a user-facing message derived from the FastAPI/Stripe error, plus retry.

FR-7. The 3DS/`requires_action` path is handled in-sheet by PaymentSheet (test card
`4000 0025 0000 3155`); the app treats post-3DS `succeeded` identically to the non-3DS path.

FR-8. Support all three `source` values for session creation — `cart` (with `cart_id`), `direct`
(with `sku` + `product_type` + `billing_model` + `quantity`), and `subscription_action` — though
AND-227's acceptance focuses on `cart` and `direct` one-time purchases (`subscription_action` is fully
exercised by AND-236).

FR-9. Guard against double-charge: a session creation in flight or an order already `paid` must not be
re-submitted; the "Pay" button is disabled while `CreatingSession`/`AwaitingPayment`/`ConfirmingPayment`.

FR-10. Operate fully in **Stripe test mode**; no production keys.

## 4. Technical Design

**Screen + navigation.** A `CheckoutScreen` composable in `feature-billing` is reached via a
Navigation-Compose route `checkout?source={source}&sku={sku}&cartId={cartId}`. It renders state from
`CheckoutViewModel` and hosts the PaymentSheet launcher at the screen root (per AND-225 R4, register
before `STARTED`).

```kotlin
// feature-billing/.../checkout/CheckoutScreen.kt
@Composable
fun CheckoutScreen(viewModel: CheckoutViewModel = hiltViewModel()) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val launcher = rememberStripePaymentLauncher(onResult = viewModel::onPaymentResult)
    LaunchedEffect(Unit) { viewModel.events.collect { ev ->
        if (ev is CheckoutEvent.PresentSheet) launcher.present(ev.clientSecret, ev.config)
    } }
    when (state) { /* Idle, Creating, AwaitingPayment, Confirming, Succeeded, Failed, Canceled */ }
}
```

**ViewModel + state.**

```kotlin
// feature-billing/.../checkout/CheckoutViewModel.kt
@HiltViewModel
class CheckoutViewModel @Inject constructor(
    private val repo: CheckoutRepository,
    private val paymentService: StripePaymentService, // AND-225
    savedState: SavedStateHandle,
) : ViewModel() {
    private val _uiState = MutableStateFlow<CheckoutUiState>(CheckoutUiState.Idle)
    val uiState: StateFlow<CheckoutUiState> = _uiState.asStateFlow()
    private val _events = Channel<CheckoutEvent>(Channel.BUFFERED)
    val events = _events.receiveAsFlow()

    fun startCheckout(req: CheckoutRequest) { /* CreatingSession -> create -> emit PresentSheet */ }
    fun onPaymentResult(result: PaymentResult) { /* map -> confirm or fail/cancel */ }
    fun retry() { /* re-enter from Failed/Canceled */ }
}

sealed interface CheckoutUiState {
    data object Idle : CheckoutUiState
    data object CreatingSession : CheckoutUiState
    data class AwaitingPayment(val session: CheckoutSession) : CheckoutUiState
    data class ConfirmingPayment(val orderId: String) : CheckoutUiState
    data class Succeeded(val orderId: String, val receipt: PaymentRecord?) : CheckoutUiState
    data class Failed(val message: String, val retryable: Boolean) : CheckoutUiState
    data class Canceled(val session: CheckoutSession) : CheckoutUiState
}

sealed interface CheckoutEvent {
    data class PresentSheet(val clientSecret: String, val config: PaymentSheet.Configuration) : CheckoutEvent
}
```

**Repository.** `CheckoutRepository` in `core-data` orchestrates the three backend calls and exposes
typed `ApiResult<T>`:

```kotlin
// core-data/.../billing/CheckoutRepository.kt
interface CheckoutRepository {
    suspend fun createSession(req: CheckoutRequest): ApiResult<CheckoutSession>
    suspend fun resolveClientSecret(session: CheckoutSession): ApiResult<String>
    suspend fun confirmOrder(orderId: String, paymentIntentId: String): ApiResult<PaymentRecord>
}

class CheckoutRepositoryImpl @Inject constructor(
    private val billingApi: BillingApi,            // AND-223 / AND-225
    private val paymentService: StripePaymentService,
) : CheckoutRepository {
    override suspend fun createSession(req: CheckoutRequest) =
        billingApi.createCheckoutSession(req.toDto()).toApiResult { it.toDomain() }

    override suspend fun resolveClientSecret(session: CheckoutSession): ApiResult<String> {
        session.clientSecret?.let { return ApiResult.Success(it) } // if endpoint already returned it
        return paymentService.createPaymentIntent(
            CreatePaymentIntentRequest(amount = session.amountCents, currency = session.currency,
                intentContext = mapOf("order_id" to session.orderId))
        ).map { it.clientSecret ?: error("missing client_secret") }
    }

    override suspend fun confirmOrder(orderId: String, paymentIntentId: String): ApiResult<PaymentRecord> =
        // GET reconciliation; bounded backoff is allowed (idempotent GET)
        paymentService.fetchPaymentIntent(paymentIntentId).flatMap { pi ->
            if (pi.status == "succeeded") billingApi.listPayments().toApiResult { dto ->
                dto.payments.first { it.orderId == orderId }.toDomain()
            } else ApiResult.Failure(BillingError.NotConfirmed(pi.status))
        }
}
```

**Confirmation polling.** After `Completed`, `confirmOrder` polls `fetchPaymentIntent` with bounded
backoff (3 attempts, jittered, ~20s cap) because Stripe → backend reconciliation may lag the in-sheet
result. `requires_action`/`processing` mid-poll → keep waiting up to the cap, then surface a "payment
processing, check Purchases" non-failure terminal state.

**Domain models (core-model).**

```kotlin
data class CheckoutSession(
    val orderId: String, val checkoutSessionId: String, val source: CheckoutSource,
    val status: String, val lineItems: List<LineItem>,
    val amountCents: Long, val currency: String,
    val clientSecret: String? = null, val paymentIntentId: String? = null,
)
enum class CheckoutSource { CART, DIRECT, SUBSCRIPTION_ACTION }
data class CheckoutRequest(
    val source: CheckoutSource, val cartId: String? = null, val sku: String? = null,
    val productType: String? = null, val billingModel: String? = null, val quantity: Int = 1,
)
```

**Hilt wiring.** A `@Binds` for `CheckoutRepository` in a `feature-billing` or `core-data`
`@Module @InstallIn(SingletonComponent::class)`; `StripePaymentService`/launcher come from AND-225's
`PaymentModule`.

**Flow (happy path).**
1. CTA → `startCheckout(req)` → `CreatingSession`.
2. `POST /ui/billing/checkout_session` → `{order_id, checkout_session_id, status:"pending_payment"}`.
3. `resolveClientSecret` → `client_secret` → emit `PresentSheet` → `AwaitingPayment`.
4. PaymentSheet, test card `4242…` → `PaymentResult.Completed`.
5. `ConfirmingPayment` → `confirmOrder` polls → `status:"succeeded"` + matching payment record.
6. `Succeeded(orderId, receipt)` → success screen.

## 5. API Contract

All shapes below are verified against the dev `/openapi.json`.

**Create checkout session — `POST /ui/billing/checkout_session`** (`UnifiedCheckoutSessionIn` →
`UnifiedCheckoutSessionOut`). Session cookies + `X-CSRF-Token: <ui_csrf>` required (mutating POST).

Request (`source: "direct"` example):
```json
{
  "source": "direct",
  "sku": "bundle_demo_001",
  "product_type": "file_bundle",
  "billing_model": "one_time",
  "quantity": 1,
  "scope": {},
  "pricing_ref": {}
}
```
Request (`source: "cart"` example): `{ "source": "cart", "cart_id": "cart_abc", "quantity": 1 }`

Response `200` (`UnifiedCheckoutSessionOut`):
```json
{
  "order_id": "ord_123",
  "checkout_session_id": "cs_456",
  "source": "direct",
  "line_items": [ { "sku": "bundle_demo_001", "amount_cents": 500, "currency": "usd", "qty": 1 } ],
  "status": "pending_payment"
}
```
`UnifiedCheckoutSessionIn` enums (from schema): `source ∈ {cart, direct, subscription_action}` (required);
`product_type ∈ {file_bundle, api_package, internal_api_package}`;
`billing_model ∈ {one_time, rental, subscription, credit_pack}`; `quantity` 1..1000.
`UnifiedCheckoutSessionOut` required keys: `order_id`, `checkout_session_id`, `source`;
`status` defaults to `"pending_payment"`; `line_items` is `array<object>` (shape is per-product —
parse defensively, see R2). Optional query/header params (`user_sub`, `X-SESSION-ID`,
`X-IMPERSONATION-TOKEN`) are **not** sent by the app; the cookie session is authoritative.

**Resolve PaymentIntent — `POST /ui/billing/payment_intents`** (from AND-225). Sent only if the
checkout response did not already carry a `client_secret`. Body keyed by order:
```json
{ "amount": 500, "currency": "usd", "intent_context": { "order_id": "ord_123" } }
```
Response carries `payment_intent_id`, `client_secret`, `status` (see AND-225 §5).

**Reconcile — `GET /ui/billing/payment_intents/{payment_intent_id}`** (idempotent; bounded backoff):
```json
{ "payment_intent_id": "pi_3Q...", "status": "succeeded", "amount": 500, "currency": "usd" }
```

**Receipt lookup — `GET /ui/billing/payments?limit=50`** (idempotent). Returns the user's recent
payments; the client filters for the one whose order matches `order_id` to build the receipt.

**Retrofit (extends `BillingApi`):**
```kotlin
@POST("ui/billing/checkout_session")
suspend fun createCheckoutSession(@Body body: UnifiedCheckoutSessionIn): Response<UnifiedCheckoutSessionOut>

@GET("ui/billing/payments")
suspend fun listPayments(@Query("limit") limit: Int = 50): Response<PaymentsListDto>
```

**DTOs (Moshi):**
```kotlin
@JsonClass(generateAdapter = true)
data class UnifiedCheckoutSessionIn(
    val source: String,
    @Json(name = "cart_id") val cartId: String? = null,
    val sku: String? = null,
    @Json(name = "product_type") val productType: String? = null,
    @Json(name = "billing_model") val billingModel: String? = null,
    val quantity: Int = 1,
    val scope: Map<String, Any?> = emptyMap(),
    @Json(name = "pricing_ref") val pricingRef: Map<String, Any?> = emptyMap(),
)

@JsonClass(generateAdapter = true)
data class UnifiedCheckoutSessionOut(
    @Json(name = "order_id") val orderId: String,
    @Json(name = "checkout_session_id") val checkoutSessionId: String,
    val source: String,
    @Json(name = "line_items") val lineItems: List<Map<String, Any?>> = emptyList(),
    val status: String = "pending_payment",
)
```

## 6. Data & State Management

- **Single source of truth:** `CheckoutViewModel` owns `StateFlow<CheckoutUiState>`; the screen is a
  pure projection. One-shot side effects (presenting the sheet, navigation) go through a `Channel`
  collected with lifecycle awareness, never re-emitted on config change.
- **No `client_secret` persistence.** The `client_secret` lives in-memory inside the
  `AwaitingPayment`/event payload only and is never written to Room/DataStore/logs (security
  anti-pattern; mirrors AND-225 §6/§8).
- **Order/session survival across process death:** `orderId` and `checkoutSessionId` may be stashed in
  `SavedStateHandle` so that on restore the app can *reconcile* (re-run `confirmOrder`) rather than
  re-create — avoiding a duplicate charge. The `client_secret` is **not** restored; if a sheet was mid
  flight at death, the app re-checks order status instead of re-presenting blindly.
- **No Room cache for sessions** — checkout sessions/orders are server-authoritative and short-lived.
  Purchase history is owned by the Purchases feature (AND-218), not this ticket.
- **Idempotency:** session creation and PaymentIntent creation are **non-idempotent POSTs** — never
  auto-retry on timeout. Only the GET reconciliation (`payment_intents/{id}`, `payments`) uses bounded
  backoff. The "Pay"/"Checkout" button is disabled in all non-terminal states (FR-9) to prevent
  double submission.

## 7. Error Handling & Resilience

- **Unreliable dev host:** all calls use the shared ~20s OkHttp timeout. POSTs (create session, create
  intent) are not retried — failure → `CheckoutUiState.Failed(retryable=true)`. GET reconciliation
  uses 3-attempt jittered backoff.
- **FastAPI `detail` mapping:** reuse the shared mapper for `string | [{msg}] | {code,...}` to build
  user-facing messages (e.g. "This item is no longer available"); never show raw JSON. A `409`/`410`
  on session create (cart changed / SKU gone) → non-retryable `Failed` directing the user back to cart.
- **Stripe result mapping (via AND-225 `PaymentResult`):**
  - `Completed` → `ConfirmingPayment` → reconcile.
  - `Canceled` → `Canceled(session)`; order stays `pending_payment`; no error toast.
  - `Failed(msg)` → `Failed(msg, retryable=true)`; log the non-PII Stripe error code only.
- **Reconciliation lag / `processing`:** if the PaymentIntent is still `processing`/`requires_action`
  after the backoff cap, show a terminal "Payment processing — we'll confirm shortly; see Purchases"
  state (success-ish, not a failure) and do not re-charge.
- **Partial failure (paid but confirm failed):** if `PaymentSheet` reported `Completed` but
  `confirmOrder` keeps failing on transport, treat as *paid-pending-confirm*, surface a recoverable
  message with a "Refresh" action that re-polls — never silently mark as failed (the user may have been
  charged).
- **Not-initialized Stripe / blank key:** propagated from AND-225 as `PaymentResult.Failed`; rendered
  as `Failed("Payment is not available")`, no crash.
- **Offline:** if `createSession` fails with no connectivity, render an offline `Failed` state with
  retry; nothing is charged.

## 8. Security & Privacy

- **No raw PAN/CVV in app code.** Card entry is exclusively inside Stripe's PaymentSheet (inherited
  from AND-225). Keeps the app in SAQ-A-EP scope, not SAQ-D.
- **No secret key on device** — only the `pk_test_...` publishable key. Session and PaymentIntent
  creation (secret-key operations) are backend-only.
- **`client_secret` handling:** sensitive — in-memory only, never logged, never persisted to
  Room/DataStore/SavedStateHandle.
- **CSRF/session:** every mutating POST (`checkout_session`, `payment_intents`) carries
  `X-CSRF-Token: <ui_csrf>`; session cookies stay HttpOnly in the persistent jar; 401 → one
  `POST /ui/session/refresh` retry by the authenticator.
- **Transport caveat:** dev backend is plaintext HTTP, so session/order/`client_secret` traverse
  cleartext in dev — acceptable for **test-mode keys only**. Prod build types must block cleartext via
  `network-security-config`; call this out in the PR.
- **Double-charge prevention is a security/financial control,** not just UX: the disabled-button guard
  (FR-9) plus reconcile-don't-recreate on restore (§6) prevent duplicate charges.
- **Logging:** payment/checkout logs include `order_id`, `checkout_session_id`, `payment_intent_id`,
  `status` only — never `client_secret`, publishable key, amounts tied to identity, or card data.

## 9. Accessibility & i18n

- The custom checkout screen (summary, line items, totals, Pay button, status states) must be fully
  TalkBack-navigable: line items grouped with content descriptions, the Pay button labeled with the
  amount ("Pay $5.00"), and loading/confirming states announced via `liveRegion` semantics.
- PaymentSheet itself is Stripe-owned with built-in a11y, dynamic type, and localized strings —
  inherited, not re-implemented.
- All app-side strings (titles, status messages, error copy, "Try again", "Pay") live in
  `feature-billing`/`core-ui` `strings.xml`; none hard-coded.
- **Currency/amount formatting** is locale-aware via `NumberFormat.getCurrencyInstance`, keyed off the
  DTO `currency` and `amount_cents` (divide by 100) — never string-concatenated.
- Verify the screen honors system dark theme via the app's Material 3 theme and respects large font /
  display scaling without truncating totals.

## 10. Telemetry & Logging

- Emit structured analytics (PII-free, no `client_secret`):
  `checkout_session_created` `{order_id, source, item_count}`,
  `checkout_payment_presented` `{order_id}`,
  `checkout_result` `{order_id, result: succeeded|canceled|failed|processing, error_code?}`,
  `checkout_confirm_latency_ms` `{order_id, attempts}`.
- Stripe SDK emits its own analytics (left enabled in test mode).
- Project logger: `DEBUG` for flow tracing in dev builds only; `INFO`/`WARN` for outcomes; secrets
  never logged at any level. Reconciliation backoff attempts logged at `DEBUG` with attempt count.

## 11. Testing Strategy

**Unit (core-testing, JVM):**
- `CheckoutRepositoryTest`: mocked `BillingApi`/`StripePaymentService`. Assert `createSession` maps
  `UnifiedCheckoutSessionOut` → `CheckoutSession`; `resolveClientSecret` returns the embedded secret
  when present and falls back to `createPaymentIntent` otherwise; `confirmOrder` returns success only
  on `succeeded` + matching payment record. Assert POSTs are not retried on timeout; GET reconcile is.
- `CheckoutViewModelTest`: drive the state machine through every transition —
  `Idle→CreatingSession→AwaitingPayment→ConfirmingPayment→Succeeded`, plus `Canceled`, `Failed`,
  not-initialized, and the paid-but-confirm-failed recoverable path. Use a `TestDispatcher` + Turbine
  on `uiState`/`events`. Assert the Pay button guard (no duplicate `createSession` while in flight).
- DTO Moshi round-trip tests for `UnifiedCheckoutSessionIn/Out` against fixtures copied from the web
  reference / `/openapi.json` shapes, including the enum values and a sparse `line_items`.
- Error-mapping tests for FastAPI `detail` variants → user-facing copy.

**Instrumentation / integration (gated, live dev backend + Stripe test mode):**
- **Happy path:** create a `direct` session for a known test SKU → present PaymentSheet → enter
  `4242 4242 4242 4242` → assert `CheckoutUiState.Succeeded` and that `payment_intents/{id}.status ==
  "succeeded"` and a matching `payments` record exists. This directly proves acceptance.
- **3DS path:** same with `4000 0025 0000 3155` → complete in-sheet 3DS → `Succeeded`.
- **Cart path:** create a `cart` session from a seeded cart → pay → `Succeeded`.
- **Cancel/decline:** dismiss the sheet → `Canceled` (order still `pending_payment`); use a decline
  test card → `Failed` with retry.
- Compose UI tests assert each `CheckoutUiState` renders the correct surface and the Pay button is
  disabled during non-terminal states.

**CI:** unit + Compose tests run on every build; live-backend integration is manual/nightly-gated due
to dev-host unreliability and the Stripe network dependency.

## 12. Dependencies & Sequencing

- **Depends on AND-225** (Stripe Android SDK integration): consumes `StripePaymentService`,
  `StripePaymentLauncher`/`rememberStripePaymentLauncher`, `PaymentResult`, `PaymentConfiguration`
  bootstrap, and the `payment_intents` create/fetch endpoints + DTOs. **Hard blocker.**
- **Transitively depends on AND-223** (Billing API + DTOs — `BillingApi`, `ApiResult` mapping) and the
  auth/session foundation (cookie jar, `X-CSRF-Token`, 401 refresh) and the network stack
  (Retrofit/OkHttp/Moshi).
- **Soft-coordinates with AND-211** (cart screen — supplies the `cart_id` for `source:"cart"`) and
  **AND-218** (purchases API — owns post-purchase history/receipt listing). AND-227 can be built and
  tested via the `direct` source without the cart UI present.
- **Blocks AND-236** (Subscribe flow): the subscription checkout uses this same
  `checkout_session` → PaymentSheet → reconcile pipeline with `source:"subscription_action"` /
  `billing_model:"subscription"`.
- **Coordinates with AND-231** (redirect/return handler): if any test path requires an external 3DS
  redirect, AND-231 owns the return-URL intent-filter; AND-227's in-sheet test cards do not require it.

## 13. Risks & Open Questions

- **R1 — Session→PaymentIntent linkage:** `UnifiedCheckoutSessionOut` does **not** declare a
  `client_secret`/`payment_intent_id` field in the schema (only `order_id`, `checkout_session_id`,
  `source`, `line_items`, `status`). It is unclear whether the secret is embedded in a `line_items`
  entry, returned by a separate call, or created by the app via `payment_intents` keyed on `order_id`.
  **Mitigation:** `resolveClientSecret` tries the embedded value first, then falls back to
  `createPaymentIntent(intent_context={order_id})`; verify the real linkage against a live response and
  with the backend owner before finalizing. **Open question — owner: backend.**
- **R2 — `line_items` is untyped (`array<object>`):** amount/currency live inside it but the per-item
  shape is product-dependent. **Mitigation:** parse defensively into `Map<String,Any?>`, derive
  `amountCents`/`currency` with null-safe fallbacks (and a fallback `GET` if absent). Open: is there a
  session-level total field, or must the app sum line items?
- **R3 — Reconciliation lag:** Stripe→backend status propagation may trail the in-sheet `Completed`
  result, causing `processing` on first poll. **Mitigation:** bounded backoff + a `processing`
  terminal-but-non-failure state.
- **R4 — Double-charge on process death mid-payment:** **Mitigation:** persist only `order_id`,
  reconcile-not-recreate on restore (§6). Open: does the backend dedupe a re-created session for the
  same cart/SKU, or could it produce a second order?
- **R5 — Decline/SCA test-card behavior on the dev backend:** confirm the dev Stripe account is in
  test mode and that declined/3DS cards round-trip correctly through this backend.
- **Q1 — Receipt source:** is `GET /ui/billing/payments` the right receipt source for the success
  screen, or does AND-218 expose a dedicated order/receipt endpoint to use instead?

## 14. Acceptance Criteria

AC-1. A `direct` checkout session is created via `POST /ui/billing/checkout_session` for a known test
SKU and returns `{order_id, checkout_session_id, status:"pending_payment"}` parsed into
`CheckoutSession`.

AC-2. Presenting `PaymentSheet` for the session and paying with Stripe test card
`4242 4242 4242 4242` yields `PaymentResult.Completed` and the ViewModel transitions to
`ConfirmingPayment`.

AC-3. Reconciliation (`GET /ui/billing/payment_intents/{id}`) reports `status == "succeeded"` and a
matching `payments` record is found, producing `CheckoutUiState.Succeeded` and a success screen
(**proves "a purchase completes via Stripe (test)"**).

AC-4. A `cart` checkout session (`source:"cart"`, `cart_id`) completes the same flow to `Succeeded`.

AC-5. The 3DS test card `4000 0025 0000 3155` completes in-sheet authentication and also reaches
`Succeeded`.

AC-6. `PaymentResult.Canceled` returns to `Canceled(session)` with the order still `pending_payment`
and no duplicate session created; a decline maps to `Failed(retryable=true)` with a user-facing
message and retry.

AC-7. The Pay/Checkout action is disabled during `CreatingSession`/`AwaitingPayment`/`ConfirmingPayment`,
and on process-death restore the app reconciles by `order_id` rather than re-creating the session
(no double charge).

AC-8. No `client_secret` and no card data appear in any log output; mutating POSTs carry
`X-CSRF-Token`; POSTs are never auto-retried.

AC-9. Unit tests (repository, ViewModel state machine, DTO round-trip, error mapping) and Compose UI
tests pass in CI; the gated live integration test is documented and runnable.

## 15. Definition of Done

- All Acceptance Criteria (AC-1…AC-9) met; the test-mode purchase round-trip is recorded/screenshotted
  in the PR (including the 3DS variant).
- Code merged to `android-port` in `com.testlogon.android.feature.billing.checkout` /
  `…core.data.billing` / `…core.model` packages, respecting `app -> feature-billing -> core-*` layering.
- `CheckoutViewModel`, `CheckoutUiState`, `CheckoutRepository`, and the `checkout_session` DTOs are
  documented with KDoc; the `subscription_action` extension points are noted for AND-236.
- Reuses AND-225's `StripePaymentLauncher`/`PaymentResult` without re-implementing payment plumbing or
  depending on Stripe types in `feature-billing` ViewModel code.
- No production Stripe keys committed; `pk_test_...` from BuildConfig (debug) only; security review
  records the cleartext-dev caveat and confirms prod cleartext is blocked.
- Double-charge guards (button disable + reconcile-not-recreate) verified by test.
- Unit + Compose tests green in CI; gated live integration smoke documented. No new lint/detekt
  regressions. PR links AND-225/AND-223 and lists AND-236 as the downstream follow-up.
