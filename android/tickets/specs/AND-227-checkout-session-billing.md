---
id: AND-227
title: Checkout session billing
milestone: M5
epic: E31
priority: P0
size: L
depends_on: [AND-225]
blocks: [AND-236]
status: reviewed
reviewed_on: 2026-06-06
---

# AND-227 — Checkout session billing

## 1. Overview & Goal

Deliver the end-to-end **purchase completion** flow: turning a selected product (or a cart) into a
server-created checkout session, driving an on-device Stripe payment to a terminal state, and
reconciling the resulting order to a confirmed paid status the app can trust. This is the capstone of
the M5 commerce / E31 billing epic — the first ticket that makes money actually move.

AND-227 wires `POST /ui/billing/checkout_session` to a Stripe payment flow completed on-device.
**[CORRECTED — see §5 and §16]** The verified contract for `POST /ui/billing/checkout_session` is
request `BillingCheckoutReq` `{amount_cents (required), currency?, description?}` → response
`{session_id, url}` — i.e. a **hosted Stripe Checkout URL**, NOT an in-app PaymentSheet
`client_secret`. The `UnifiedCheckoutSessionIn/Out` shapes (with `order_id`/`checkout_session_id`/
`line_items`/`status`) belong to a *different* endpoint, `POST /ui/checkout/session`, and there is
**no `payment_intents` endpoint anywhere in the backend OpenAPI**. The original PaymentSheet +
`client_secret` + `payment_intents` reconciliation design below was written against the wrong
endpoint; until the backend owner resolves which endpoint AND-227 must target (see §13 R1, §16 Open
assumptions), treat the hosted-Checkout redirect (Custom Tabs + return-URL deep link, AND-231) as the
verified path and the PaymentSheet path as a contingent design requiring `/ui/checkout/session` plus a
not-yet-existing intent mechanism. The deliverable is a `feature-billing` checkout screen +
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
  (`operationId: create_checkout_session_ui_billing_checkout_session_post`). **[CORRECTED]** Per the
  OpenAPI index (line 1175) its request schema is `BillingCheckoutReq` and it declares **no response
  schema** (`resp=200:`); per the frontend (`src/api/endpoints/billing.ts: createCheckoutSession`) the
  response is `{ session_id, url }`. The `UnifiedCheckoutSessionIn` → `UnifiedCheckoutSessionOut`
  schemas referenced throughout this spec actually belong to `POST /ui/checkout/session`
  (`operationId: ui_create_checkout_session_ui_checkout_session_post`, index line 1327). See §5 and
  §16 for the corrected shapes pulled from the dev `/openapi.json`.
- **Upstream dependency — AND-225 (Stripe Android SDK integration):** provides
  `StripePaymentService`, `StripePaymentLauncher` / `rememberStripePaymentLauncher`,
  `PaymentResult` sealed type, `PaymentConfiguration` bootstrap, and the
  `GET /ui/billing/payment_intents/{id}` reconciliation call. AND-227 **consumes** all of these.
- **Web reference:** `src/api/endpoints/billing.ts` (`createCheckoutSession` → posts `BillingCheckoutReq`
  to `/ui/billing/checkout_session`, returns `{session_id, url}`) and `src/api/types.ts`
  (`BillingCheckoutReq`). **[CORRECTED]** The web client does NOT call `/ui/checkout/session` or use
  `UnifiedCheckoutSession*` anywhere; the `source`/`billing_model`/`product_type` enums are only
  defined on the unrelated `UnifiedCheckoutSessionIn` schema. `createCheckoutSession` is not invoked
  from any `*.tsx` page in the reference, so there is no web precedent for an in-app PaymentSheet
  consumer — the `{url}` is a hosted-Checkout redirect target.

## 3. Functional Requirements

FR-1. From an entry point (a "Buy" / "Checkout" CTA with an amount, and a SKU or `cart_id` for
context), the app creates a checkout session via `POST /ui/billing/checkout_session`. **[CORRECTED]**
The verified response is `{session_id, url}` (frontend `createCheckoutSession`), NOT `{order_id,
checkout_session_id, status, source, line_items[]}`. The `{order_id, ...}` shape (`UnifiedCheckoutSessionOut`)
is only returned by `POST /ui/checkout/session`. The app must use whichever endpoint the backend owner
confirms (see §13 R1); for the verified `/ui/billing/checkout_session` path the deliverable is the
`{session_id, url}` hosted-Checkout response.

FR-2. **[CORRECTED — contingent]** There is **no `payment_intents` endpoint in the backend OpenAPI**
(verified: `payment_intent` matches 0 entries in the index), so "obtain the PaymentIntent
`client_secret` for the session" is not supported by `/ui/billing/checkout_session`, whose `{url}` is a
hosted Stripe Checkout page. To complete payment on-device against the verified contract, open `url` in
a Chrome Custom Tab and detect completion via the Stripe return URL deep link (AND-231). The Stripe
`PaymentSheet` + `client_secret` design is only viable if AND-225 actually exposes a PaymentIntent
creation/fetch mechanism and the backend exposes a `client_secret`-bearing endpoint — neither is
verifiable here (see §16 Open assumptions).

FR-3. On payment completion, the app reconciles the order with the server. **[CORRECTED]** Reconcile
via `GET /ui/billing/payments` (the only verified read; response `{items: LedgerEntry[]}`) and/or the
purchases history (AND-218); there is **no `GET /ui/billing/payment_intents/{id}`** to poll. Only after
a matching paid record is found does the app show a confirmed-purchase success screen.

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

**Repository.** `CheckoutRepository` in `core-data` orchestrates the backend calls and exposes typed
`ApiResult<T>`. **[CORRECTED]** The code block below is the *original* design against the
non-existent `payment_intents` endpoints and the wrong `{payments:[...]}` shape; it is retained for
context but must be reworked once §13 R1 is resolved: `resolveClientSecret`/`fetchPaymentIntent` have
no backend to call, `listPayments()` returns `{items: LedgerEntry[]}` (use `it.items`, not
`it.payments`), and `LedgerEntry` has no declared `orderId`/`status` to match/branch on.

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

**[SECTION CORRECTED]** Shapes below are verified against the dev `/openapi.json`
(`reference/openapi.index.txt`, `reference/openapi.pretty.json`) and the web client
(`reference/src/api/endpoints/billing.ts`, `reference/src/api/types.ts`). The original §5 conflated two
distinct endpoints; both are documented here so the team can choose.

**(A) Verified contract — `POST /ui/billing/checkout_session`** (the ticket-scoped path). Request
schema `BillingCheckoutReq`; **no declared response schema** in OpenAPI (`resp=200:`). The web client
types the response as `{ session_id, url }` (a hosted Stripe Checkout URL). Session cookies +
`X-CSRF-Token: <ui_csrf>` required (mutating POST).

Request (`BillingCheckoutReq`):
```json
{ "amount_cents": 500, "currency": "usd", "description": "bundle_demo_001 x1" }
```
`amount_cents` is the only required field; `currency` and `description` are `string | null`.

Response `200` (web-client-typed; not declared in OpenAPI):
```json
{ "session_id": "cs_test_...", "url": "https://checkout.stripe.com/c/pay/cs_test_..." }
```
On-device completion: open `url` in a Chrome Custom Tab; observe the Stripe return-URL deep link
(`com.testlogon.android.stripe://payment_return`, AND-225/AND-231) to detect success/cancel; then
reconcile via the payments read (below). There is **no `client_secret` and no PaymentSheet path** for
this endpoint.

**(B) Alternate endpoint (NOT what the ticket path resolves to) — `POST /ui/checkout/session`**
(`UnifiedCheckoutSessionIn` → `UnifiedCheckoutSessionOut`, index line 1327). If the backend owner
confirms AND-227 should target this richer endpoint instead, the shapes are:

Request (`source: "direct"` example):
```json
{ "source": "direct", "sku": "bundle_demo_001", "product_type": "file_bundle",
  "billing_model": "one_time", "quantity": 1, "scope": {}, "pricing_ref": {} }
```
Request (`source: "cart"` example): `{ "source": "cart", "cart_id": "cart_abc", "quantity": 1 }`

Response `200` (`UnifiedCheckoutSessionOut`):
```json
{ "order_id": "ord_123", "checkout_session_id": "cs_456", "source": "direct",
  "line_items": [ { } ], "status": "pending_payment" }
```
`UnifiedCheckoutSessionIn` (verified from schema): `source ∈ {cart, direct, subscription_action}`
(**only required field**); `product_type ∈ {file_bundle, api_package, internal_api_package}`;
`billing_model ∈ {one_time, rental, subscription, credit_pack}`; `quantity` default 1, range 1..1000;
plus `cart_id`, `sku`, `scope` (object), `pricing_ref` (object), and **`subscription_plan`** (object,
omitted by the original DTO). `UnifiedCheckoutSessionOut` required keys: `order_id`,
`checkout_session_id`, `source`; `status` defaults to `"pending_payment"`; `line_items` is
`array<object>` with `additionalProperties: true` (no `amount_cents`/`currency`/`sku`/`qty` declared —
parse defensively, see R2). Optional query/header params (`user_sub`, `X-SESSION-ID`,
`X-IMPERSONATION-TOKEN`) are **not** sent by the app; the cookie session is authoritative.

**Resolve PaymentIntent / `POST /ui/billing/payment_intents` — [DOES NOT EXIST].** Verified: zero
`payment_intent` path entries in the OpenAPI index. This block from the original spec is removed; do
not implement it. (AND-225 must be re-verified — there is no backend endpoint to back it.)

**Reconcile / `GET /ui/billing/payment_intents/{id}` — [DOES NOT EXIST].** Removed for the same
reason. Reconcile via the payments read below (or AND-218 purchases history).

**Receipt / reconcile lookup — `GET /ui/billing/payments?limit=50`** (idempotent; index line 1191).
**[CORRECTED]** Web client (`getPayments`) types the response as `{ items: LedgerEntry[] }`, NOT
`{ payments: [...] }`. `LedgerEntry` declares `{ sk, type, amount_cents, state, reason?, ts }` plus an
open `[key: string]: unknown` — there is **no declared `order_id`, `status`, or `payment_intent_id`**
field. Filtering a payment by `order_id` and reading a `succeeded` `status` is therefore an unverified
assumption (see §16); the declared terminal field is `state`, not `status`.

**Retrofit (extends `BillingApi`):**
```kotlin
// Verified ticket-scoped endpoint:
@POST("ui/billing/checkout_session")
suspend fun createCheckoutSession(@Body body: BillingCheckoutReq): Response<CheckoutSessionDto>

@GET("ui/billing/payments")
suspend fun listPayments(@Query("limit") limit: Int = 50): Response<PaymentsListDto>

// Alternate endpoint, only if backend owner redirects the ticket here:
// @POST("ui/checkout/session")
// suspend fun createUnifiedSession(@Body body: UnifiedCheckoutSessionIn): Response<UnifiedCheckoutSessionOut>
```

**DTOs (Moshi):**
```kotlin
@JsonClass(generateAdapter = true)
data class BillingCheckoutReq(
    @Json(name = "amount_cents") val amountCents: Long,
    val currency: String? = null,
    val description: String? = null,
)

// Web-client-typed response of /ui/billing/checkout_session (no OpenAPI schema declared):
@JsonClass(generateAdapter = true)
data class CheckoutSessionDto(
    @Json(name = "session_id") val sessionId: String,
    val url: String,
)

@JsonClass(generateAdapter = true)
data class PaymentsListDto(
    val items: List<Map<String, Any?>> = emptyList(), // LedgerEntry: sk,type,amount_cents,state,reason?,ts,+open
)

// Alternate-endpoint DTOs (use only if targeting /ui/checkout/session):
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
    @Json(name = "subscription_plan") val subscriptionPlan: Map<String, Any?>? = null,
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

- **R1 — [ELEVATED/CORRECTED] Wrong endpoint + no PaymentIntent path:** Verified against OpenAPI +
  frontend: `POST /ui/billing/checkout_session` takes `BillingCheckoutReq` and returns `{session_id,
  url}` (hosted Stripe Checkout), and **no `payment_intents` endpoint exists** in the backend. The
  `UnifiedCheckoutSessionIn/Out` schemas this spec was built on belong to a different endpoint,
  `POST /ui/checkout/session`. There is therefore no `client_secret` to drive PaymentSheet on the
  ticket-scoped path. **Mitigation / decision needed (BLOCKER, owner: backend):** (a) confirm whether
  AND-227 targets `/ui/billing/checkout_session` (hosted-Checkout redirect via Custom Tabs + return-URL
  deep link, no PaymentSheet) or `/ui/checkout/session` (richer order/session object, but still no
  documented `client_secret` source); and (b) re-verify AND-225 — if it truly created/fetched
  PaymentIntents, identify which backend endpoint backed it, because none is in the current OpenAPI.
  Until resolved, the verified hosted-Checkout flow is the only implementable path.
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **`POST /ui/billing/checkout_session` exists and is the ticket-scoped path.** VERIFIED.
   Source: OpenAPI `POST /ui/billing/checkout_session` (index line 1175, op
   `create_checkout_session_ui_billing_checkout_session_post`); `src/api/endpoints/billing.ts:
   createCheckoutSession`.
2. **Its request schema is `BillingCheckoutReq` = `{amount_cents (required int), currency?, description?}`.**
   CORRECTED (spec said `UnifiedCheckoutSessionIn`). Source: OpenAPI `req=BillingCheckoutReq` (index
   line 1175); `components.schemas.BillingCheckoutReq` (pretty.json — required `["amount_cents"]`);
   `src/api/types.ts: BillingCheckoutReq`.
3. **Its response is `{session_id, url}` (hosted Stripe Checkout URL), not `{order_id,
   checkout_session_id, line_items, status}`.** CORRECTED. Source: OpenAPI declares no response schema
   (`resp=200:`, index line 1175); `src/api/endpoints/billing.ts: createCheckoutSession` →
   `api.post<{ session_id: string; url: string }>(...)`.
4. **`UnifiedCheckoutSessionIn`/`UnifiedCheckoutSessionOut` belong to `POST /ui/checkout/session`, a
   different endpoint.** CORRECTED (spec attributed them to `/ui/billing/checkout_session`). Source:
   OpenAPI `POST /ui/checkout/session | req=UnifiedCheckoutSessionIn | resp=200:UnifiedCheckoutSessionOut`
   (index line 1327, op `ui_create_checkout_session_ui_checkout_session_post`).
5. **`UnifiedCheckoutSessionIn` enums/fields:** `source ∈ {cart,direct,subscription_action}` (only
   required); `product_type ∈ {file_bundle,api_package,internal_api_package}`; `billing_model ∈
   {one_time,rental,subscription,credit_pack}`; `quantity` default 1, 1..1000; also `cart_id`, `sku`,
   `scope`, `pricing_ref`, **`subscription_plan`**. VERIFIED (enums correct; spec's DTO omitted
   `subscription_plan` — corrected). Source: `components.schemas.UnifiedCheckoutSessionIn` (pretty.json
   lines 76999–77099).
6. **`UnifiedCheckoutSessionOut` required keys `order_id`, `checkout_session_id`, `source`; `status`
   default `pending_payment`; `line_items` is `array<object>` with `additionalProperties: true` (no
   declared per-item fields).** VERIFIED. Source: `components.schemas.UnifiedCheckoutSessionOut`
   (pretty.json lines 77101–77140).
7. **`UnifiedCheckoutSessionOut` declares no `client_secret`/`payment_intent_id`.** VERIFIED (spec R1).
   Source: same schema as #6.
8. **A `POST /ui/billing/payment_intents` (create) and `GET /ui/billing/payment_intents/{id}`
   (reconcile) endpoint exist (claimed from AND-225).** CORRECTED — they do **not** exist anywhere in
   the backend. Source: `payment_intent` matches 0 entries in `openapi.index.txt` (the only
   `payment_intent_id` usages are response *fields* of `charge-once`/`pay-balance`/`wallet/deposit`, not
   a PaymentIntent CRUD endpoint — `src/api/endpoints/billing.ts:68,71,92`).
9. **`GET /ui/billing/payments` exists, idempotent, `limit` query param.** VERIFIED. Source: OpenAPI
   `GET /ui/billing/payments | params=limit,...` (index line 1191); `src/api/endpoints/billing.ts:
   getPayments`.
10. **`GET /ui/billing/payments` returns `{items: LedgerEntry[]}`, not `{payments:[...]}`.** CORRECTED.
    Source: `src/api/endpoints/billing.ts: getPayments` → `api.get<{ items: LedgerEntry[] }>(...)`.
11. **`LedgerEntry` shape = `{sk, type, amount_cents, state, reason?, ts}` + open map; no declared
    `order_id`/`status`/`payment_intent_id`.** VERIFIED. Source: `src/api/types.ts: LedgerEntry`
    (lines 648–656).
12. **Auth: cookie session + `ui_csrf` echoed as `X-CSRF-Token` on mutating calls.** VERIFIED. Source:
    `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`, lines 168–170;
    `credentials: "include"`, lines 124/183/220).
13. **401 → single `POST /ui/session/refresh` retry by the transport.** VERIFIED. Source:
    `src/api/client.ts: refreshSession` (`/ui/session/refresh`, line 122) + single-flight retry on
    401 (lines 191–224).
14. **Optional `user_sub`/`X-SESSION-ID`/`X-IMPERSONATION-TOKEN` params are not needed (cookie session
    authoritative).** VERIFIED as optional. Source: OpenAPI `params=` column on the billing endpoints
    (index lines 1175, 1191) lists them as optional; web client sends none of them.
15. **No web `*.tsx` page consumes `createCheckoutSession`; the `{url}` is a redirect target.**
    VERIFIED. Source: 0 `.tsx` matches for `createCheckoutSession`/`checkout_session` in `src/pages/`
    (grep). No in-app PaymentSheet precedent in the reference.
16. **Stripe PaymentSheet / `rememberStripePaymentLauncher` / `PaymentResult` API.** UNVERIFIED-ASSUMPTION
    (out of repo). Stripe Android `PaymentSheet` requires a PaymentIntent/SetupIntent `client_secret`
    (framework ref: https://docs.stripe.com/payments/accept-a-payment?platform=android) — but no
    backend endpoint supplies one (see #8), so the launcher cannot be driven on the verified path.
17. **Chrome Custom Tabs for hosted-Checkout redirect + return-URL deep link.** UNVERIFIED-ASSUMPTION
    (proposed mitigation; depends on AND-231 owning the intent-filter). Framework ref:
    https://developer.chrome.com/docs/android/custom-tabs.
18. **`NumberFormat.getCurrencyInstance` for locale-aware amount formatting; TalkBack/`liveRegion`
    semantics.** VERIFIED as framework guidance. Framework ref:
    https://developer.android.com/reference/java/text/NumberFormat#getCurrencyInstance() and
    https://developer.android.com/develop/ui/compose/accessibility.

### Corrections made
- §1, §2, §3 (FR-1/2/3), §5, §4 (repository note), §13 R1: request schema `UnifiedCheckoutSessionIn` →
  `BillingCheckoutReq` for `/ui/billing/checkout_session` (claim #2).
- Response shape for `/ui/billing/checkout_session`: `{order_id,checkout_session_id,line_items,status}`
  → `{session_id, url}` hosted-Checkout URL (claim #3).
- Clarified `UnifiedCheckoutSessionIn/Out` belong to the separate `POST /ui/checkout/session` (claim #4);
  documented both endpoints in §5 (A)/(B) so the team can choose.
- Removed the non-existent `payment_intents` create/reconcile endpoints from FR-2/FR-3 and §5; flagged
  AND-225 for re-verification (claim #8).
- `GET /ui/billing/payments` response `{payments:[...]}` → `{items: LedgerEntry[]}`; corrected the repo
  filter (`it.items` not `it.payments`) and removed reliance on a payment `order_id`/`status`
  (claims #10/#11).
- Added missing `subscription_plan` field to the `UnifiedCheckoutSessionIn` DTO (claim #5).
- Frontmatter: `status: draft` → `reviewed`; added `reviewed_on: 2026-06-06`.

### Open assumptions
- **Which endpoint AND-227 must use** (`/ui/billing/checkout_session` hosted redirect vs
  `/ui/checkout/session` unified session). Unresolvable from the sources — both exist; the ticket scope
  names the former but the original design assumed the latter's shape. Owner: backend.
- **How a Stripe `client_secret` is obtained on-device.** No backend endpoint returns one for these
  flows (claim #8), so the entire PaymentSheet design (FR-2, FR-4 `AwaitingPayment`, §4 ViewModel/repo)
  is contingent. If AND-225's `payment_intents` calls were real, the backing endpoint is missing from
  the current OpenAPI snapshot and must be re-located.
- **Reconciling a payment to an `order_id`.** `LedgerEntry` declares no `order_id`/`status`; the
  hosted-Checkout `{session_id}` is the only correlation key, and whether `payments` rows carry it is
  unverifiable (open `[key: string]: unknown`). Owner: backend / AND-218.
- **Whether the dev Stripe account is in test mode and round-trips decline/3DS cards** (spec R5).
  Cannot be verified from static sources — requires the live dev backend.
- **Session-level total / amount for display.** Neither endpoint returns a typed total; `BillingCheckoutReq`
  is amount-in (caller supplies it). The amount shown must come from the cart/SKU upstream (AND-211/AND-218).

## 17. Test Plan

Test target legend: **JVM** = JVM unit/Robolectric (local, no device); **EMU** = headless emulator AVD
`test35` (x86_64, API 35); **DEV** = physical Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R,
Android 14 / API 34, arm64-v8a) on the build host via adb. Cases needing real Custom Tabs / Stripe
return-URL deep-link handling, real network round-trips, and the arm64/API-34 reality are marked
**MUST run on DEV**. Several cases trace to *contingent* ACs (the AC presumes the corrected-away
PaymentSheet/`payment_intents` design); those are written against the **verified** hosted-Checkout
contract and the AC is annotated "(contingent — see §16)".

- **TC-AND-227-01 — Create-session request/response contract (happy path).**
  Type: contract/MockWebServer. Target: JVM. Preconditions: MockWebServer returns `200
  {"session_id":"cs_test_1","url":"https://checkout.stripe.com/c/pay/cs_test_1"}` for
  `POST /ui/billing/checkout_session`. Steps: call `createCheckoutSession(BillingCheckoutReq(500,"usd",
  "demo"))`; capture the recorded request. Expected: request body is `{"amount_cents":500,
  "currency":"usd","description":"demo"}` (snake_case), `X-CSRF-Token` header present; response parses
  to `CheckoutSessionDto(sessionId="cs_test_1", url=...)`. Traces: AC-1.

- **TC-AND-227-02 — `BillingCheckoutReq`/`CheckoutSessionDto`/`PaymentsListDto` Moshi round-trip.**
  Type: unit. Target: JVM. Preconditions: fixtures copied from §5(A) and the `LedgerEntry` shape.
  Steps: serialize/deserialize each DTO; deserialize a `payments` fixture `{"items":[{"sk":"...",
  "type":"charge","amount_cents":500,"state":"paid","ts":1}]}`. Expected: `amount_cents` ↔ `amountCents`
  mapping holds; `PaymentsListDto.items` is populated; unknown/extra keys do not throw (defensive map).
  Traces: AC-1, AC-3, AC-9.

- **TC-AND-227-03 — CSRF + no-auto-retry on mutating POST.**
  Type: contract/MockWebServer. Target: JVM. Preconditions: MockWebServer first responds `500`/timeout
  to the create POST. Steps: invoke create; inspect dispatched requests. Expected: exactly **one**
  `POST /ui/billing/checkout_session` (no automatic retry of the non-idempotent POST); the request
  carried `X-CSRF-Token: <ui_csrf>`; result maps to `Failed(retryable=true)`. Traces: AC-8.

- **TC-AND-227-04 — 401 triggers a single session refresh then replays.**
  Type: contract/MockWebServer. Target: JVM. Preconditions: create POST returns `401` once, refresh
  endpoint returns `200`, replayed create returns `200`. Steps: invoke create. Expected: one
  `POST /ui/session/refresh`, then the create succeeds; no infinite refresh loop. Traces: AC-8.

- **TC-AND-227-05 — ViewModel state machine, verified hosted-Checkout happy path.**
  Type: unit. Target: JVM (TestDispatcher + Turbine). Preconditions: fake repo returns a
  `CheckoutSessionDto` then a matching paid `payments` record. Steps: `startCheckout(req)`; simulate the
  return-URL success callback; let reconcile resolve. Expected: `uiState` emits
  `Idle → CreatingSession → AwaitingPayment → ConfirmingPayment → Succeeded`; a `PresentSheet`/open-URL
  event is emitted exactly once. Traces: AC-2 (contingent — see §16), AC-3 (contingent), AC-9.

- **TC-AND-227-06 — Double-submit guard + reconcile-not-recreate on restore.**
  Type: unit. Target: JVM. Preconditions: ViewModel in `CreatingSession`/`AwaitingPayment`/
  `ConfirmingPayment`; `SavedStateHandle` seeded with the prior `session_id`. Steps: call
  `startCheckout` again while in-flight; then recreate the ViewModel from `SavedStateHandle`. Expected:
  the second `startCheckout` is a no-op (no duplicate create POST); on restore the VM reconciles by the
  persisted `session_id` and never re-creates a session (no double charge); `client_secret`/URL not
  restored. Traces: AC-7.

- **TC-AND-227-07 — Cancel and decline mapping.**
  Type: unit. Target: JVM. Preconditions: fake payment result source. Steps: feed a Canceled outcome,
  then a declined/failed outcome. Expected: Canceled → `Canceled(...)`, no error toast, retry
  affordance, no duplicate session; decline → `Failed(retryable=true)` with a user-facing (non-raw)
  message. Traces: AC-6.

- **TC-AND-227-08 — FastAPI `detail` error-shape mapping.**
  Type: unit. Target: JVM. Preconditions: create POST returns `409`/`422` with `detail` as each of
  `string`, `[{msg}]`, `{code,...}`. Steps: invoke create; inspect mapped message. Expected: each
  variant yields a clean user-facing string (never raw JSON); `409`/`410` → non-retryable `Failed`
  routing back to cart. Traces: AC-6, AC-8.

- **TC-AND-227-09 — Paid-but-confirm-failed recoverable state.**
  Type: unit. Target: JVM. Preconditions: return-URL reports success but the `payments` reconcile read
  keeps failing on transport. Steps: drive completion then fail reconcile past the backoff cap.
  Expected: terminal *paid-pending-confirm* recoverable state with a "Refresh" re-poll action; never
  silently `Failed` (user may be charged); GET reconcile used bounded jittered backoff (POSTs did not).
  Traces: AC-3 (contingent), AC-7.

- **TC-AND-227-10 — No secrets in logs.**
  Type: unit. Target: JVM (capture logger). Preconditions: run the full flow with a stub `url`/
  `session_id`. Steps: assert captured log output. Expected: logs contain only `session_id`/`state`/
  `order` identifiers; no `url` query secret, no `client_secret`, no publishable key, no card data at
  any level. Traces: AC-8.

- **TC-AND-227-11 — Checkout screen renders each state + Pay button gating (Compose).**
  Type: Compose-UI. Target: EMU (fast, headless API 35). Preconditions: VM driven through each
  `CheckoutUiState`. Steps: set each state; assert the surface and the Pay/Checkout button. Expected:
  correct surface per state; the action is **disabled** in `CreatingSession`/`AwaitingPayment`/
  `ConfirmingPayment` and enabled only in terminal/idle states. Traces: AC-7, AC-9.

- **TC-AND-227-12 — Accessibility: TalkBack labels, amount label, liveRegion, dark/large-font.**
  Type: instrumented (accessibility). Target: DEV (MUST run on DEV — real TalkBack + display scaling).
  Preconditions: success and confirming states populated. Steps: enable TalkBack; traverse; set largest
  font + dark theme. Expected: Pay button announces the formatted amount (e.g. "Pay $5.00" via
  `NumberFormat.getCurrencyInstance`); loading/confirming announced via `liveRegion`; line items grouped
  with content descriptions; totals not truncated under large font; honors dark theme. Traces: AC-9.

- **TC-AND-227-13 — End-to-end test-mode purchase over the live dev backend (verified hosted-Checkout).**
  Type: instrumented/e2e (gated, manual/nightly). Target: DEV (MUST run on DEV — real plaintext-HTTP
  dev host `http://18.222.237.167:8000`, real Custom Tab, real Stripe return-URL deep link, arm64/API
  34). Preconditions: dev Stripe in test mode; valid session cookie + `ui_csrf`. Steps:
  `startCheckout` → `POST /ui/billing/checkout_session` → open `url` in a Custom Tab → pay with
  `4242 4242 4242 4242` → return via `com.testlogon.android.stripe://payment_return` → reconcile via
  `GET /ui/billing/payments`. Expected: `CheckoutUiState.Succeeded`, a matching paid record in
  `payments.items`; screenshot captured. **Proves "a purchase completes via Stripe (test)".** Traces:
  AC-1, AC-3, AC-9.

- **TC-AND-227-14 — 3DS/SCA card e2e (live).**
  Type: instrumented/e2e (gated). Target: DEV (MUST run on DEV — in-page 3DS challenge in the Custom
  Tab requires a real browser/WebView). Preconditions: as TC-13. Steps: same flow with
  `4000 0025 0000 3155`; complete the 3DS challenge in the Custom Tab. Expected: post-authentication
  the flow reconciles to `Succeeded` identically to the non-3DS path. Traces: AC-5 (contingent on
  in-app PaymentSheet; on the verified hosted path 3DS is handled by the Stripe Checkout page).

- **TC-AND-227-15 — Cart-source session e2e (live).**
  Type: instrumented/e2e (gated). Target: DEV. Preconditions: a seeded cart; backend confirmed to
  accept the cart source on whichever endpoint §16 resolves to. Steps: create a cart-context session →
  pay `4242…` → reconcile. Expected: `Succeeded`. Note: on the verified `/ui/billing/checkout_session`
  contract there is no `cart_id` field (it is amount-in); a true cart source requires
  `/ui/checkout/session` (`source:"cart"`), so this case is **blocked on the §16 endpoint decision**.
  Traces: AC-4 (contingent — see §16).

- **TC-AND-227-16 — Offline / flaky-dev-host create failure.**
  Type: instrumented. Target: DEV (MUST run on DEV — toggle real airplane mode / radio; exercises the
  ~20s timeout against the unreliable plaintext host). Preconditions: device offline (or host
  unreachable). Steps: invoke `startCheckout`. Expected: bounded ~20s timeout → offline `Failed` state
  with retry; **no** auto-retry of the POST; nothing charged; recovery on reconnect via the retry
  affordance. Traces: AC-6, AC-8.

### Coverage matrix
- **AC-1** (create session → parsed): TC-01, TC-02, TC-13.
- **AC-2** (pay → `ConfirmingPayment`; contingent): TC-05.
- **AC-3** (reconcile succeeded → `Succeeded`; contingent reconcile shape): TC-02, TC-05, TC-09, TC-13.
- **AC-4** (cart source → `Succeeded`; blocked on §16): TC-15.
- **AC-5** (3DS card → `Succeeded`): TC-14.
- **AC-6** (cancel / decline mapping): TC-07, TC-08, TC-16.
- **AC-7** (button gating + reconcile-not-recreate): TC-06, TC-09, TC-11.
- **AC-8** (no secrets in logs; CSRF; no POST auto-retry): TC-03, TC-04, TC-08, TC-10, TC-16.
- **AC-9** (unit + Compose green; gated live documented): TC-02, TC-05, TC-09, TC-11, TC-12, TC-13.
