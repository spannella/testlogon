---
id: AND-213
title: "Checkout session"
milestone: M5
epic: E29
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-211, AND-227]
blocks: [AND-214, AND-217]
---

# AND-213 — Checkout session

## 1. Overview & Goal

This ticket implements the **checkout session** step of the purchase flow: the transition
from an editable cart (AND-211) to a server-created, immutable **order-review** state that
can proceed to payment (AND-227). The user taps "Checkout" on the cart, the app calls
`POST /ui/checkout/session` to materialize a checkout session from the current cart
(including any file-bundle line items), and lands on an **Order Review** screen that
displays the server-confirmed line items and the session identifier that
the billing step will consume.

> **[CORRECTED — see §16]** The authoritative endpoint `POST /ui/checkout/session`
> (op `ui_create_checkout_session_ui_checkout_session_post`) takes `UnifiedCheckoutSessionIn`
> and returns `UnifiedCheckoutSessionOut`, whose fields are
> `checkout_session_id`, `order_id`, `source`, `status` (default `"pending_payment"`), and
> `line_items` (an array of free-form objects). The OpenAPI response schema does **not**
> contain `subtotal`/`tax`/`shipping`/`discount`/`total`/`currency`/`expires_at`. The original
> draft's "server-computed totals block" and the `Money`/expiry response fields are therefore
> **unverified assumptions** about the contents of `line_items[]`; treat totals as derived from
> `line_items` or fetched separately (e.g. `GET /ui/shoppingcart/carts/{cart_id}/total`,
> `ShoppingCartTotalOut`) until the `line_items` element shape is confirmed with the backend.

The goal is a single, testable seam — `CheckoutRepository.createSession(...)` returning
`ApiResult<CheckoutSession>` — plus a `feature-checkout` `CheckoutSessionViewModel` /
`OrderReviewScreen` pair that renders the session and exposes a "Proceed to payment"
action. Creating a checkout session **snapshots** the cart on the server: the server returns
the resolved `line_items` plus a `checkout_session_id`/`order_id`/`status`. The client must
render server-returned values rather than recomputing them. (Totals presentation depends on
the `line_items[]` element shape, which is `additionalProperties: true` in OpenAPI and is an
**unverified assumption** here — see §16.)

Scope is limited to *creating the session and proceeding to payment*. The actual Stripe
payment, billing session, and purchase completion are **AND-227** (`/ui/billing/checkout_session`).
Address entry / shipping selection that mutates an existing session is **AND-214**.
Cart mutation, totals on the cart screen, and the cart DTOs are **AND-211 / AND-210**. This
ticket consumes the cart state from AND-211 and hands the created session id to AND-227.

## 2. Context & References

- **Module:** `feature-checkout` (UI + ViewModel) over `core-data` (repository) with domain
  models in `core-model`. Repository interface in
  `com.testlogon.android.core.data.checkout`; domain types in
  `com.testlogon.android.core.model.checkout`; Retrofit API + DTOs in
  `com.testlogon.android.core.network.checkout`.
- **Depends on (blocking):**
  - **AND-211** — Cart screen: source of the cart whose contents seed the session, and the
    "Checkout" entry point that navigates here. AND-211 in turn brings AND-210's cart DTOs
    (`cart.ts`) and cart totals.
  - **AND-227** — Checkout session billing (`/ui/billing/checkout_session`, complete payment
    via Stripe test): this ticket's `CheckoutSession.id` is the input AND-227 consumes to
    create the Stripe payment. The contract for what AND-227 needs (session id + payment
    state) is co-designed here.
- **Blocks:**
  - **AND-214** — Address / shipping: applies an address/shipping option to the order; it
    mutates the session created here and re-reads totals.
  - **AND-217** — Cart/checkout tests: repo + UI tests covering this flow.
- **Infra reused (not blocking the data shape):** AND-018 (`ApiResult`/`apiCall`/`flatMap`),
  AND-015 (FastAPI `detail` → `ApiError`), AND-016 (retry/backoff for idempotent GETs only),
  AND-009 (OkHttp ~20s timeouts + logging), AND-011/AND-012/AND-013 (cookie jar, CSRF
  header, 401→refresh→retry), AND-021 (loading/empty/error/offline state composables),
  AND-019/AND-020 (Material 3 theme + input composables), AND-022 (nav host).
- **Stack:** Kotlin 2.0.21, Jetpack Compose + Material 3, single-Activity Navigation-Compose,
  Hilt (KSP), Coroutines/Flow, Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15, Room 2.6 (cache
  only, not used to persist sessions here), DataStore (prefs). minSdk 24, compileSdk/
  targetSdk 35, JDK 17.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext,
  unreliable). OpenAPI at `/openapi.json`. Web reference under `frontend/` (cart/checkout
  endpoints in `frontend/src/api/endpoints/*.ts`, types in `frontend/src/api/types.ts`).
  Auth is cookie-based; the checkout endpoints require an authenticated session, so the
  cookie jar + CSRF header + 401-refresh stack (AND-011/012/013) must be active.

## 3. Functional Requirements

1. Define a repository method:
   `suspend fun createSession(request: CheckoutSessionRequest): ApiResult<CheckoutSession>`
   in `interface CheckoutRepository` (`core-data`).
2. `createSession` calls `POST /ui/checkout/session` with the current cart reference (cart
   id and/or the client cart fingerprint) and any file-bundle selection, wrapped in
   `apiCall { }` so transport failures fold to `ApiResult.NetworkError` and HTTP error
   bodies fold to `ApiResult.Failure(ApiError)` (AND-015/AND-018).
3. The created session is **authoritative**: the response (`UnifiedCheckoutSessionOut`) carries
   `checkout_session_id`, `order_id`, `source`, a `status` string (default `"pending_payment"`),
   and `line_items[]`. The Order Review UI renders the server values verbatim — the client never
   recomputes amounts.
   **[CORRECTED — see §16]** The top-level `subtotal`/`tax`/`shipping`/`discount`/`total`/
   `currency` response fields asserted by the original draft do **not** exist in
   `UnifiedCheckoutSessionOut`; any monetary presentation must be derived from `line_items[]`
   (free-form objects, shape unconfirmed) or from a separate cart-total call.
4. **File-bundle support:** the unified endpoint signals a bundle via the request field
   `product_type: "file_bundle"` on `UnifiedCheckoutSessionIn`. A dedicated endpoint
   `POST /ui/checkout/session/file-bundle` (`FileBundleCheckoutSessionIn` →
   `FileBundleCheckoutSessionOut`) also exists for the single-SKU bundle purchase/rental case
   (request: `sku`, `date_start`, `date_end`, `access_mode`; response: `checkout_session_id`,
   `order_id`, `status`, `sku`, `amount_cents`, `currency`, `access_mode`).
   **[CORRECTED — see §16]** Neither schema contains `is_bundle`, `bundle_contents[]`, or
   per-file `file_id`/`name`/`size_bytes`; the original draft's expandable "included files"
   model is an **unverified assumption** with no backing in the OpenAPI spec.
5. On the Cart screen "Checkout" action, navigate to the `order_review` route and trigger
   `createSession`. The Order Review screen shows: loading while creating, the line items +
   totals on success, and a "Proceed to payment" primary action.
6. "Proceed to payment" navigates to the billing route owned by AND-227, passing
   `CheckoutSession.id`. This ticket does NOT call Stripe or `/ui/billing/checkout_session`.
7. The session should be **idempotent to re-entry**: re-creating a session from the same cart
   (e.g. on screen recreation / process death restore) must not double-charge or create
   orphan orders.
   **[CORRECTED — see §16]** `POST /ui/checkout/session` exposes **no** idempotency parameter
   in OpenAPI, and `UnifiedCheckoutSessionIn` has no idempotency field. The only checkout-family
   endpoint that accepts an idempotency header is `POST /ui/shoppingcart/carts/{cart_id}/purchase`,
   which uses **`X-Idempotency-Key`** (note the `X-` prefix). The client must therefore guard
   re-entry by reusing an in-flight `checkout_session_id` in `SavedStateHandle` rather than
   relying on a server-honored key on this endpoint; sending `X-Idempotency-Key` here is a
   best-effort hint pending backend confirmation (R3).
8. Empty-cart guard: if the cart is empty, the Checkout action is disabled and the Order
   Review route is not reachable; if reached directly with an empty cart, show the empty
   state (AND-021) and route back to cart.
9. Stale-cart guard: if the server rejects the session because the cart changed since the
   client last read it (price change / item unavailable), surface a recoverable error that
   sends the user back to the cart to review (Section 7).

## 4. Technical Design

Package layout:
- `com.testlogon.android.core.model.checkout` — `CheckoutSession`, `CheckoutLineItem`,
  `BundleContent`, `Money`, `CheckoutSessionRequest`, `CheckoutStatus`.
- `com.testlogon.android.core.data.checkout` — `CheckoutRepository`,
  `CheckoutRepositoryImpl`, `CheckoutDataModule` (Hilt binding).
- `com.testlogon.android.core.network.checkout` — `CheckoutApi`, request/response DTOs +
  Moshi adapters (consumed here; co-owned with AND-227 for the billing half).
- `com.testlogon.android.feature.checkout` — `CheckoutSessionViewModel`, `OrderReviewScreen`,
  `OrderReviewUiState`, nav wiring.

Domain types (in `core-model`, framework-free). **Note [§16]:** the `Money`-typed totals and
`expiresAtEpochSec` on `CheckoutSession`, and the per-file `BundleContent` list, are a *client
projection*; they are not present as named fields in `UnifiedCheckoutSessionOut` and must be
populated by parsing `line_items[]` (shape unconfirmed) or from a separate cart-total call.
Until confirmed, the mapper must tolerate their absence (nullable / empty defaults).

```kotlin
package com.testlogon.android.core.model.checkout

data class Money(val amountMinor: Long, val currency: String) // e.g. 1299, "USD"

enum class CheckoutStatus { OPEN, REQUIRES_PAYMENT, COMPLETED, EXPIRED, CANCELED, UNKNOWN }

data class BundleContent(
    val fileId: String,
    val name: String,
    val sizeBytes: Long?,
)

data class CheckoutLineItem(
    val sku: String,
    val name: String,
    val quantity: Int,
    val unitPrice: Money,
    val lineTotal: Money,
    val isBundle: Boolean,
    val bundleContents: List<BundleContent> = emptyList(),
)

data class CheckoutSession(
    val id: String,
    val status: CheckoutStatus,
    val lineItems: List<CheckoutLineItem>,
    val subtotal: Money,
    val tax: Money,
    val shipping: Money?,      // null until AND-214 applies a shipping option
    val discount: Money?,
    val total: Money,
    val expiresAtEpochSec: Long?,
)

data class CheckoutSessionRequest(
    val cartId: String?,            // server cart id from AND-210/211 if available
    val idempotencyKey: String,     // client-generated UUID, stable across retries
)
```

Wire DTOs (in `core-network`). **[CORRECTED — see §16]** The DTOs below now mirror the actual
OpenAPI schemas `UnifiedCheckoutSessionIn` / `UnifiedCheckoutSessionOut`. The response's
`line_items` is `array<object>` with `additionalProperties: true` (no documented element
schema), so it is modeled as `List<Map<String, Any?>>` and the line-item/Money/bundle DTOs from
the original draft are retained only as a *proposed* client projection pending the backend
confirming the element shape (R2).

```kotlin
// Request — required: source ("cart" | "direct" | "subscription_action")
@JsonClass(generateAdapter = true)
data class UnifiedCheckoutSessionInDto(
    val source: String,                                   // REQUIRED
    @Json(name = "cart_id") val cartId: String? = null,
    @Json(name = "product_type") val productType: String? = null, // "file_bundle" | "api_package" | "internal_api_package"
    @Json(name = "billing_model") val billingModel: String? = null, // "one_time"|"rental"|"subscription"|"credit_pack"
    val sku: String? = null,
    val quantity: Int = 1,                                // 1..1000
    @Json(name = "pricing_ref") val pricingRef: Map<String, Any?>? = null,
    val scope: Map<String, Any?>? = null,
    @Json(name = "subscription_plan") val subscriptionPlan: Map<String, Any?>? = null,
)

// Response — required: order_id, checkout_session_id, source
@JsonClass(generateAdapter = true)
data class UnifiedCheckoutSessionOutDto(
    @Json(name = "checkout_session_id") val checkoutSessionId: String,
    @Json(name = "order_id") val orderId: String,
    val source: String,
    val status: String = "pending_payment",
    @Json(name = "line_items") val lineItems: List<Map<String, Any?>> = emptyList(),
)
```

For the dedicated bundle endpoint `POST /ui/checkout/session/file-bundle`:

```kotlin
@JsonClass(generateAdapter = true)
data class FileBundleCheckoutSessionInDto(
    val sku: String,                                      // 1..128
    @Json(name = "date_start") val dateStart: String,     // REQUIRED
    @Json(name = "date_end") val dateEnd: String,         // REQUIRED
    @Json(name = "access_mode") val accessMode: String,   // "purchase" | "rental"
)

@JsonClass(generateAdapter = true)
data class FileBundleCheckoutSessionOutDto(
    @Json(name = "checkout_session_id") val checkoutSessionId: String,
    @Json(name = "order_id") val orderId: String,
    val status: String,
    val sku: String,
    @Json(name = "amount_cents") val amountCents: Int,
    val currency: String,
    @Json(name = "access_mode") val accessMode: String,
)
```

`CheckoutApi` (Retrofit; the `Idempotency-Key` is supplied per-call):

```kotlin
interface CheckoutApi {
    // [CORRECTED] Header is X-Idempotency-Key (matching the cart/purchase endpoint
    // convention) and is best-effort only — this endpoint declares no idempotency param.
    @POST("ui/checkout/session")
    suspend fun createSession(
        @Header("X-Idempotency-Key") idempotencyKey: String,
        @Body body: UnifiedCheckoutSessionInDto,
    ): UnifiedCheckoutSessionOutDto

    @POST("ui/checkout/session/file-bundle")
    suspend fun createFileBundleSession(
        @Body body: FileBundleCheckoutSessionInDto,
    ): FileBundleCheckoutSessionOutDto
}
```

Repository:

```kotlin
package com.testlogon.android.core.data.checkout

interface CheckoutRepository {
    suspend fun createSession(request: CheckoutSessionRequest): ApiResult<CheckoutSession>
}

class CheckoutRepositoryImpl @Inject constructor(
    private val api: CheckoutApi,
) : CheckoutRepository {

    override suspend fun createSession(
        request: CheckoutSessionRequest,
    ): ApiResult<CheckoutSession> = apiCall {
        api.createSession(
            idempotencyKey = request.idempotencyKey,
            body = UnifiedCheckoutSessionInDto(
                source = "cart",            // REQUIRED by UnifiedCheckoutSessionIn
                cartId = request.cartId,
            ),
        )
    }.map { it.toDomain() }
}
```

`toDomain()` maps `status` strings to `CheckoutStatus` (unknown → `UNKNOWN`, never crash),
and each `MoneyDto` to `Money`. The mapper enforces currency consistency (all line items +
totals share one currency; mismatch → mapped to a `Failure(code="currency_mismatch")` rather
than rendered).

ViewModel + UI state (`feature-checkout`):

```kotlin
sealed interface OrderReviewUiState {
    data object Loading : OrderReviewUiState
    data class Ready(val session: CheckoutSession) : OrderReviewUiState
    data class Error(val error: ApiError, val recoverable: Boolean) : OrderReviewUiState
    data object Offline : OrderReviewUiState
    data object EmptyCart : OrderReviewUiState
}

@HiltViewModel
class CheckoutSessionViewModel @Inject constructor(
    private val repo: CheckoutRepository,
    private val cart: CartRepository,           // from AND-210/211
    savedState: SavedStateHandle,
) : ViewModel() {
    private val _state = MutableStateFlow<OrderReviewUiState>(OrderReviewUiState.Loading)
    val state: StateFlow<OrderReviewUiState> = _state.asStateFlow()

    // idempotencyKey is generated once and survives process death via SavedStateHandle
    private val idempotencyKey: String =
        savedState["idem_key"] ?: UUID.randomUUID().toString().also { savedState["idem_key"] = it }

    fun start() { /* guard empty cart, then createSession(...) into _state */ }
    fun retry() { start() }
    // Proceed-to-payment is exposed as a one-shot nav event carrying session.id.
}
```

The `OrderReviewScreen` composable renders the line-item list (bundles expandable via a
`bundle_contents` sub-list), a totals block (subtotal / tax / shipping / discount / total),
and a sticky "Proceed to payment" button enabled only when state is `Ready`. Loading/empty/
error/offline use the AND-021 state composables.

Hilt binding:

```kotlin
@Module @InstallIn(SingletonComponent::class)
abstract class CheckoutDataModule {
    @Binds @Singleton
    abstract fun bindCheckoutRepository(impl: CheckoutRepositoryImpl): CheckoutRepository
}
```

## 5. API Contract

Endpoint consumed: **`POST /ui/checkout/session`** (op
`ui_create_checkout_session_ui_checkout_session_post`; authenticated). **[VERIFIED]** The web
client (`src/api/client.ts`) authenticates with the cookie session (`credentials: "include"`),
sets `X-CSRF-Token` from the `ui_csrf` cookie, and adds `Authorization: Bearer <accessToken>`;
the OpenAPI params additionally list `user_sub`, `X-SESSION-ID`, and `X-IMPERSONATION-TOKEN`.
The AND-011/AND-012 cookie-jar + CSRF interceptors supply the cookie + `X-CSRF-Token`.

Request headers: `Content-Type: application/json`, `X-CSRF-Token: <ui_csrf>` (interceptor),
and **best-effort** `X-Idempotency-Key: <uuid>` (client; not a declared param on this
endpoint — see §16 / R3).

Request body — schema **`UnifiedCheckoutSessionIn`**, **required field `source`**:

```json
{ "source": "cart", "cart_id": "cart_01HXY..." }
```

Optional fields: `product_type` (`file_bundle`|`api_package`|`internal_api_package`),
`billing_model` (`one_time`|`rental`|`subscription`|`credit_pack`), `sku`, `quantity` (1..1000,
default 1), `pricing_ref` (object), `scope` (object), `subscription_plan` (object).
**[CORRECTED]** `source` is mandatory — the original `{ "cart_id": "..." }`-only body would
fail 422. (Whether the cart is also derivable from the session cookie when `cart_id` is omitted
is still unconfirmed — R1.)

Representative success (`200`) — schema **`UnifiedCheckoutSessionOut`**:

```json
{
  "checkout_session_id": "cs_01J2ABC...",
  "order_id": "ord_01J2ABC...",
  "source": "cart",
  "status": "pending_payment",
  "line_items": [
    { "sku": "SKU-TEE-001", "quantity": 2 },
    { "sku": "BNDL-DOCS-01", "quantity": 1 }
  ]
}
```
→ `ApiResult.Success(CheckoutSession(id="cs_01J2ABC...", status=...))`.
**[CORRECTED]** Response key is `checkout_session_id` (not `id`); there is also an `order_id`;
default `status` is `"pending_payment"` (not `"open"`); `line_items[]` elements are free-form
objects (`additionalProperties: true`) with **no** documented `unit_price`/`line_total`/
`is_bundle`/`bundle_contents` fields; and there are **no** top-level `subtotal`/`tax`/
`shipping`/`discount`/`total`/`currency`/`expires_at` fields. The example element fields above
are illustrative only.

File-bundle alternative — **`POST /ui/checkout/session/file-bundle`**
(`FileBundleCheckoutSessionIn` → `FileBundleCheckoutSessionOut`):

```json
// request
{ "sku": "BNDL-DOCS-01", "date_start": "2026-06-06", "date_end": "2026-07-06", "access_mode": "rental" }
// response
{ "checkout_session_id": "cs_...", "order_id": "ord_...", "status": "pending_payment",
  "sku": "BNDL-DOCS-01", "amount_cents": 4900, "currency": "USD", "access_mode": "rental" }
```

Error responses (folded by `apiCall`/AND-015 into `ApiResult.Failure(ApiError)`):

- **422 Unprocessable Entity** — validation. **[VERIFIED]** Schema `HTTPValidationError`:
  `detail` is a list of `ValidationError { loc, msg, type }` (all three required):
  ```json
  { "detail": [ { "loc": ["body","source"], "msg": "field required", "type": "value_error.missing" } ] }
  ```
  → `Failure(ApiError(status=422, message=first msg))`. The web client joins the `msg` values
  (`normalizeErrorDetail` in `src/api/client.ts`).
- **401 Unauthorized** — session expired → AND-013 authenticator runs `POST /ui/session/refresh`
  once and retries; persistent 401 → `Failure(ApiError(status=401))` → route to login.
  **[VERIFIED]** matches `src/api/client.ts` (single refresh via `/ui/session/refresh`, one
  retry, then logout).
- **409 Conflict (`cart_stale`)** — **[UNVERIFIED ASSUMPTION]** the OpenAPI spec lists only
  `200`/`422` for this endpoint; no `409` or `cart_stale` code appears in the spec or frontend.
  The client should handle a generic non-2xx (`detail` string or `{code,message}` object, per
  `normalizeErrorDetail`) defensively, but the specific `409 cart_stale` contract is an
  assumption pending backend confirmation.
- **5xx / timeout / unreachable host** → `ApiResult.NetworkError(isTimeout)`.

This is a **non-idempotent POST**; AND-016 backoff retry does NOT apply automatically. Because
the endpoint declares no idempotency parameter, a *manual* retry is made safe primarily by
reusing the in-flight `checkout_session_id` (SavedStateHandle); the `X-Idempotency-Key` header
is sent best-effort. Endpoint verbs/paths/DTO shapes were validated against
`reference/openapi.index.txt` / `openapi.pretty.json` and are re-asserted via MockWebServer
(AND-217) before merge.

## 6. Data & State Management

- `CheckoutSession` and its children are immutable value types carried in
  `StateFlow<OrderReviewUiState>`; safe across recomposition and configuration change.
- **No Room persistence of the session.** A checkout session is server-authoritative and
  short-lived (`expires_at`); the client holds it in ViewModel memory only. Re-entry
  re-creates it via the idempotency key rather than caching.
- **Idempotency key** is generated once per checkout attempt and persisted in
  `SavedStateHandle` so it survives process death; the same key is reused on retry and on
  ViewModel recreation, guaranteeing the server returns the *same* session instead of a new
  order. The key is rotated only when the user navigates back to the cart and re-initiates
  checkout (a genuinely new attempt).
- **Cart source of truth** remains AND-210/211; this ticket reads the cart id/fingerprint but
  does not mutate the cart. Money is stored as integer **minor units** (`amountMinor`) to
  avoid floating-point error; formatting to a localized currency string happens only at the
  UI layer.
- The created `CheckoutSession.id` is the hand-off value to AND-227 and (later) AND-214; it
  is passed as a navigation argument, not stored globally.

## 7. Error Handling & Resilience

- **Timeouts:** OkHttp ~20s (AND-009) against the flaky dev host; `SocketTimeoutException` →
  `NetworkError(isTimeout=true)` → "Server is slow, tap retry" with a manual retry that
  reuses the idempotency key.
- **No automatic backoff retry** (AND-016 is GET-only). Retry is user-initiated; idempotency
  ensures no duplicate sessions/orders.
- **Stale cart (409 `cart_stale`):** **[UNVERIFIED — see §16]** the `409`/`cart_stale` contract
  is not in OpenAPI for this endpoint. The client maps any such non-2xx defensively to a
  recoverable error; the Order Review screen shows "Your cart changed" and offers "Back to cart"
  (the only safe action) rather than a blind retry. Confirm the real status/code with the backend.
- **Item unavailable / price changed:** same recoverable path; the server is authoritative,
  so the client never silently proceeds with a stale total.
- **401:** AND-013 single refresh+retry; on persistent failure, clear the in-flight session
  and route to login (the session creation is abandoned, not retried client-side).
- **Empty cart:** guarded before the network call (`EmptyCart` state, route back to cart).
- **Currency mismatch in response:** fail-closed to `Failure(code="currency_mismatch")`
  rather than render a wrong total.
- **Offline:** if the connectivity probe (AND-017) reports offline, show the `Offline` state
  with retry rather than firing a doomed request.
- `CancellationException` propagates (structured concurrency; AND-018 `apiCall` re-throws).

## 8. Security & Privacy

- All checkout calls require the authenticated cookie session + `X-CSRF-Token` (`ui_csrf`),
  added by AND-011/AND-012; this ticket adds no auth handling of its own. **[VERIFIED]** against
  `src/api/client.ts` (cookie `credentials: "include"` + `X-CSRF-Token` from `ui_csrf` +
  `Authorization: Bearer`); the OpenAPI also accepts `X-SESSION-ID`/`X-IMPERSONATION-TOKEN`.
- **No payment data** is handled here — no card numbers, no Stripe tokens (that is AND-227).
  This screen only displays prices and a session id.
- **No PII or price-amount logging** at non-debug levels. The OkHttp logging interceptor
  (AND-009) runs at `BASIC` for `checkout/session` so request/response bodies (which include
  the cart contents and totals) do not reach Logcat in release-style builds.
- The `Idempotency-Key` is a client-generated UUID with no embedded user data; it is not a
  secret but is excluded from telemetry payloads to avoid correlating sessions across logs.
- `session.id` (`cs_...`) is treated as a capability-bearing reference passed only via
  in-app navigation, never written to logs or shared storage.
- Cleartext HTTP to the dev host is a known dev-only posture (network security config permits
  cleartext for the dev flavor only); production must be HTTPS (R3).

## 9. Accessibility & i18n

- All static labels ("Order review", "Subtotal", "Tax", "Shipping", "Discount", "Total",
  "Proceed to payment", "Back to cart", bundle "Included files") are string resources;
  no hardcoded UI English.
- **Currency/number formatting** uses `NumberFormat.getCurrencyInstance(locale)` driven off
  the response `currency` code, so amounts render correctly per locale; minor-unit integers
  are converted at format time. RTL layouts supported via Compose defaults.
- Line items and totals are exposed with merged semantics so TalkBack reads
  "Logo Tee, quantity 2, 39.98 dollars" as one node; the bundle expander has a
  `contentDescription` reflecting expanded/collapsed state and the included-file count.
- The "Proceed to payment" button has a minimum 48dp touch target and a disabled-state
  semantic when not `Ready`. Totals use sufficient color contrast (Material 3 theme,
  AND-019) and do not rely on color alone.
- Error/empty/offline copy comes from the shared AND-021 state composables (already
  localized).

## 10. Telemetry & Logging

- Emit structured, **no-PII** events via the AND-009 Timber/analytics seam:
  - `checkout_session_create` with `outcome`
    (`created|stale|validation_error|unauthorized|network_error`), `http_status` (on
    failure), `error_code`, `item_count`, `has_bundle` (bool), `is_timeout`.
  - `checkout_proceed_to_payment` when the user taps proceed (fields: `item_count`,
    `has_bundle`).
- **Never log:** prices/amounts, `cart_id`, `session.id`, `Idempotency-Key`, file names in
  bundle contents, or raw response bodies.
- Item count and `has_bundle` are categorical funnel signals (cart → checkout → payment),
  not secrets, and are safe to record.
- The data layer depends only on the injected logger seam; `core-model` stays framework-free.

## 11. Testing Strategy

Repository unit tests (`core-data/src/test`, JUnit + Truth + coroutines-test; `CheckoutApi`
faked or MockK-stubbed — transport is exercised by the MockWebServer suite below and AND-217):
- Success mapping: full `UnifiedCheckoutSessionOut` → `CheckoutSession` with `id` taken from
  `checkout_session_id`, `order_id` retained, `status` string mapped (default
  `"pending_payment"`), and `line_items[]` projected. Any client-derived totals/bundle contents
  default to null/empty when absent (see §16 corrections).
- Unknown/unmapped `status` string → `CheckoutStatus.UNKNOWN` (no crash).
- Currency mismatch across any derived amounts → `Failure(code="currency_mismatch")`.
- Generic recoverable conflict (assumed `409 cart_stale`, unverified) → `Failure(recoverable)`.
- `422` list `detail` of `{loc,msg,type}` → `Failure(status=422, message=first msg)` (AND-015).
- `SocketTimeoutException` → `NetworkError(isTimeout=true)`; generic `IOException` →
  `NetworkError(isTimeout=false)`; `CancellationException` re-thrown.

MockWebServer contract tests (complement AND-217):
- `createSession` issues `POST /ui/checkout/session` carrying header `X-Idempotency-Key`
  (recorded request asserted) and body containing `"source":"cart"` plus `cart_id`.
- A repeated call with the same idempotency key is sent with the same header value.

ViewModel tests (`feature-checkout/src/test`, with a fake `CheckoutRepository`):
- Empty cart → `OrderReviewUiState.EmptyCart`, no network call.
- Happy path → `Loading` then `Ready(session)`.
- `409 cart_stale` → `Error(recoverable=true)`; retry reuses the same idempotency key
  (asserted via the fake recording the request).
- Offline (AND-017 fake) → `Offline`.
- Process-death restore (rebuild ViewModel with the same `SavedStateHandle`) reuses the
  persisted idempotency key.

Compose UI tests (`feature-checkout/src/androidTest`, owned jointly with AND-217):
- `Ready` state renders all line items, expandable bundle, and totals; "Proceed to payment"
  enabled.
- Tapping "Proceed to payment" emits a nav event carrying `session.id`.
- Empty/error/offline states render the correct AND-021 composable and recovery action.

Security/log test: a captured `createSession` log at `BASIC` contains no price amounts,
`session.id`, or `Idempotency-Key`.

Gradle gates: `:core-data:test`, `:core-model:test`, `:feature-checkout:test`,
`:feature-checkout:connectedDebugAndroidTest`; ktlint/detekt (AND-005) green.

## 12. Dependencies & Sequencing

- **Requires (blocking):**
  - **AND-211** — Cart screen + cart state (and transitively AND-210 cart DTOs) to seed the
    session and provide the "Checkout" entry point.
  - **AND-227** — Billing/checkout-session step that consumes `CheckoutSession.id`; the
    hand-off contract (session id + status) is co-frozen with this ticket. (Per the backlog,
    AND-213 lists AND-227 as a dependency; in practice the two are co-developed — this ticket
    must agree the session-id hand-off shape with AND-227 before merge.)
- **Infra (should be landed for real-host correctness):** AND-018, AND-015, AND-009,
  AND-011/012/013, AND-017, AND-021, AND-022. The repository compiles and unit-tests against
  the faked `CheckoutApi` without all of them, but end-to-end checkout needs the auth +
  resilience stack active.
- **Enables / blocks:** AND-214 (address/shipping mutates this session), AND-217 (repo + UI
  tests for cart/checkout).
- **Sequencing:** Land after AND-211 (and in coordination with AND-227); freeze
  `CheckoutSession`/`CheckoutSessionRequest` shapes and notify AND-214 and AND-227 owners on
  merge. AND-217 follows to add the full test matrix.

## 13. Risks & Open Questions

- **R1 — Cart reference shape.** **[PARTIALLY RESOLVED]** `UnifiedCheckoutSessionIn` accepts an
  optional `cart_id` and a **required** `source` (use `"cart"`). Whether the cart is derivable
  from the session cookie when `cart_id` is omitted is still unconfirmed. Mitigation: always
  send `source:"cart"` + `cart_id` and verify cookie-derivation with the backend.
- **R2 — File-bundle representation.** **[RESOLVED — CORRECTED]** The OpenAPI schemas
  (`UnifiedCheckoutSessionOut`, `FileBundleCheckoutSessionOut`) contain **no** `is_bundle` /
  `bundle_contents` / `file_id` fields. Bundle is signaled on the request via
  `product_type:"file_bundle"`, and a dedicated `/ui/checkout/session/file-bundle` endpoint
  exists for single-SKU bundle purchase/rental. The "expandable included-files" UI has no
  backend support; descope it or fetch file membership from another endpoint (open question).
- **R3 — Idempotency support.** **[RESOLVED — CORRECTED]** `/ui/checkout/session` declares **no**
  idempotency parameter. Only `POST /ui/shoppingcart/carts/{cart_id}/purchase` accepts
  `X-Idempotency-Key`. Re-entry safety therefore relies on reusing the stored in-flight
  `checkout_session_id`; sending `X-Idempotency-Key` here is best-effort. Confirm dedupe
  semantics with the backend owner.
- **R4 — Session expiry UX.** `expires_at` handling (what to show if the user lingers past
  expiry, then taps proceed) — assumed to surface as a recoverable error from AND-227's
  call. Confirm whether this ticket must proactively show a countdown (currently out of
  scope).
- **Q1 — Status vocabulary.** **[PARTIALLY RESOLVED]** `UnifiedCheckoutSessionOut.status` is a
  free `string` with documented **default `"pending_payment"`** (no enum). The original draft's
  `open`/`requires_payment`/`completed`/`expired`/`canceled` set is an assumption; unknowns map
  to `UNKNOWN` defensively. Confirm the real value set with the backend.
- **Q2 — Shipping/tax before address.** `shipping` is `null` until AND-214 applies an address;
  whether `tax` is also provisional pre-address is unconfirmed. The UI labels pre-address
  totals as "estimated" if so (pending confirmation).

## 14. Acceptance Criteria

1. `CheckoutRepository.createSession(CheckoutSessionRequest): ApiResult<CheckoutSession>`
   exists in `com.testlogon.android.core.data.checkout`, bound via Hilt to
   `CheckoutRepositoryImpl`.
2. `CheckoutSession`, `CheckoutLineItem`, `BundleContent`, `Money`, `CheckoutStatus`, and
   `CheckoutSessionRequest` exist in `com.testlogon.android.core.model.checkout` and are
   framework-free (no Retrofit/Moshi types leak through the repository interface).
3. `createSession` issues `POST /ui/checkout/session` with body `{"source":"cart", "cart_id":...}`
   and a best-effort `X-Idempotency-Key` header (asserted via MockWebServer recorded request).
4. A representative `UnifiedCheckoutSessionOut` success response maps to
   `Success(CheckoutSession)` with `id`←`checkout_session_id`, `order_id` retained, `status`
   mapped, and `line_items[]` projected; client-derived totals/bundle data default safely when
   absent (tested per Section 11). (File-bundle single-SKU flow uses
   `/ui/checkout/session/file-bundle`.)
5. **Checkout creates a session and proceeds to payment:** from the Cart screen, "Checkout"
   navigates to Order Review, which renders the created session; "Proceed to payment" emits a
   nav event carrying `CheckoutSession.id` to the AND-227 route.
6. Empty cart is guarded (no session created; `EmptyCart` state + route back to cart).
7. `409 cart_stale` is recoverable → user is routed back to the cart; manual retry reuses the
   persisted idempotency key (no duplicate session/order).
8. Failure mapping: `422`→`Failure`, persistent `401`→login route, timeout/IO→`NetworkError`,
   unknown `status`→`UNKNOWN`, currency mismatch→`Failure(code="currency_mismatch")`;
   `CancellationException` re-thrown.
9. No prices, `session.id`, `cart_id`, or `Idempotency-Key` appear in logs (security test
   green).
10. `:core-data:test`, `:core-model:test`, `:feature-checkout:test`, and the Compose UI tests
    pass; ktlint/detekt (AND-005) pass.

## 15. Definition of Done

- `CheckoutRepository`/`CheckoutRepositoryImpl`, `CheckoutApi` + DTOs, the `core-model`
  domain types, the Hilt binding, and the `feature-checkout` `CheckoutSessionViewModel` +
  `OrderReviewScreen` are implemented, compile, and are merged to `android-port`.
- Unit, MockWebServer, ViewModel, Compose UI, and no-PII-logging tests from Section 11 pass
  via the Gradle gates in Section 14; AND-217 will extend, not replace, this baseline.
- DTO field names and the `status` vocabulary are verified against `/openapi.json` /
  `frontend/src/api/types.ts`; R1–R4 / Q1–Q2 are resolved or filed as follow-ups before
  AND-214 and AND-227 integration.
- `CheckoutSession`/`CheckoutSessionRequest` shapes and the `session.id` hand-off are frozen
  and the AND-214 and AND-227 owners are notified.
- Public types and the idempotency/retry rule (Section 6/7) are documented in KDoc; no
  Retrofit/OkHttp types leak through the `CheckoutRepository` interface (verified by
  inspection).
- ktlint/detekt (AND-005) pass on new files; code reviewed and approved.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer. Sources: OpenAPI index
(`reference/openapi.index.txt`), OpenAPI full spec (`reference/openapi.pretty.json`,
`components.schemas.<Name>`), and frontend (`reference/src/...`).

1. **Endpoint `POST /ui/checkout/session` exists and is the checkout-session creator.**
   VERIFIED. OpenAPI `POST /ui/checkout/session`
   (op `ui_create_checkout_session_ui_checkout_session_post`),
   `req=UnifiedCheckoutSessionIn | resp=200:UnifiedCheckoutSessionOut;422:HTTPValidationError`.
2. **Request schema fields / required `source`.** CORRECTED (draft sent `cart_id` only).
   VERIFIED shape: `components.schemas.UnifiedCheckoutSessionIn` — required `source`
   (`cart|direct|subscription_action`); optional `cart_id`, `product_type`
   (`file_bundle|api_package|internal_api_package`), `billing_model`
   (`one_time|rental|subscription|credit_pack`), `sku`, `quantity` (1..1000, default 1),
   `pricing_ref`, `scope`, `subscription_plan`.
3. **Response identifier field.** CORRECTED (draft used `id`). VERIFIED:
   `components.schemas.UnifiedCheckoutSessionOut` → required `checkout_session_id`, `order_id`,
   `source`; plus `status` (string, default `"pending_payment"`) and `line_items`
   (`array<object>`, `additionalProperties: true`).
4. **Response carries top-level `subtotal/tax/shipping/discount/total/currency/expires_at`
   and per-line `unit_price/line_total`.** CORRECTED → none of these fields exist in
   `UnifiedCheckoutSessionOut`. Source: `components.schemas.UnifiedCheckoutSessionOut`.
5. **Status vocabulary `open/requires_payment/completed/expired/canceled`.** CORRECTED to
   UNVERIFIED-ASSUMPTION. `UnifiedCheckoutSessionOut.status` is a free string with default
   `"pending_payment"` (no enum). Source: `components.schemas.UnifiedCheckoutSessionOut`.
6. **File-bundle modeled as `is_bundle` + `bundle_contents[]` of `{file_id,name,size_bytes}`
   on the unified line item.** CORRECTED → no such fields anywhere. Bundle is signaled via
   request `product_type:"file_bundle"`; a dedicated endpoint exists. Sources:
   `UnifiedCheckoutSessionIn.product_type`, OpenAPI
   `POST /ui/checkout/session/file-bundle`, `components.schemas.FileBundleCheckoutSessionIn`
   (`sku,date_start,date_end,access_mode`) / `FileBundleCheckoutSessionOut`
   (`checkout_session_id,order_id,status,sku,amount_cents,currency,access_mode`).
7. **Idempotency via an `Idempotency-Key` header on `/ui/checkout/session`.** CORRECTED →
   the endpoint declares no idempotency param. The cart purchase endpoint uses
   **`X-Idempotency-Key`**. Sources: OpenAPI
   `POST /ui/checkout/session` (params: `user_sub,X-SESSION-ID,X-IMPERSONATION-TOKEN` only),
   `POST /ui/shoppingcart/carts/{cart_id}/purchase` (params include `X-Idempotency-Key`).
8. **Auth = cookie session + `X-CSRF-Token` (`ui_csrf`).** VERIFIED. `src/api/client.ts`:
   `fetch(..., credentials: "include")`, `headers.set("X-CSRF-Token", getCookie("ui_csrf"))`,
   `Authorization: Bearer <accessToken>`. OpenAPI also lists `X-SESSION-ID`,
   `X-IMPERSONATION-TOKEN`, `user_sub` params.
9. **401 → single `POST /ui/session/refresh` then one retry, else logout.** VERIFIED.
   `src/api/client.ts: refreshSession()` and the 401 branch in `api<T>()`.
10. **422 error shape `detail: [{loc,msg,type}]`.** VERIFIED (draft omitted `type`).
    `components.schemas.HTTPValidationError` → `detail: array<ValidationError>`;
    `components.schemas.ValidationError` requires `loc,msg,type`. Client join logic:
    `src/api/client.ts: normalizeErrorDetail`.
11. **`409 cart_stale` recoverable error contract.** UNVERIFIED-ASSUMPTION. OpenAPI lists only
    `200;422` for `POST /ui/checkout/session`; no `409`/`cart_stale` in spec or frontend.
12. **Web reference app calls `/ui/checkout/session`.** CORRECTED/clarified → it does **not**;
    the frontend only calls `/ui/billing/checkout_session` (`src/api/endpoints/billing.ts:
    createCheckoutSession`, returning `{session_id,url}`). `/ui/checkout/session` is therefore
    unexercised by the web client and its `line_items[]` element shape cannot be confirmed from
    the frontend.
13. **Cart totals are available from a separate endpoint.** VERIFIED (supporting the
    derive-totals recommendation). OpenAPI `GET /ui/shoppingcart/carts/{cart_id}/total`
    → `ShoppingCartTotalOut`.
14. **AND-227 endpoint is `/ui/billing/checkout_session`.** VERIFIED. OpenAPI
    `POST /ui/billing/checkout_session` (`req=BillingCheckoutReq`); frontend
    `src/api/endpoints/billing.ts: createCheckoutSession`.
15. **Money carried as integer minor units (`amount_cents`).** VERIFIED for the file-bundle
    response (`FileBundleCheckoutSessionOut.amount_cents: integer`, `currency: string`).
    For the unified line items the minor-unit shape is an assumption (claim 4).
16. **Framework choice: `@Header` per-call + Moshi + Retrofit suspend (Android).** framework
    ref — Retrofit docs (https://square.github.io/retrofit/),
    Moshi codegen (https://github.com/square/moshi#codegen). Not backend-verifiable.

### Corrections made
- C1: Request body must include required `source:"cart"` (was `cart_id`-only) — would 422.
  (§3, §4-request, §5, §14.3)
- C2: Response id field is `checkout_session_id` (+ `order_id`), not `id`. (§4-DTO, §5, §11, §14.4)
- C3: Removed claim of top-level `subtotal/tax/shipping/discount/total/currency/expires_at`
  and per-line `unit_price/line_total` — not in schema; modeled `line_items` as
  `List<Map<String,Any?>>` with totals as a client projection. (§1, §3, §4, §5, §11)
- C4: Default `status` is `"pending_payment"` (was `"open"`); status is a free string. (§3,§4,§5,§Q1)
- C5: Removed the `is_bundle`/`bundle_contents`/`file_id` bundle model; documented the real
  `product_type:"file_bundle"` signal and the dedicated `/ui/checkout/session/file-bundle`
  endpoint. (§3.4, §4-DTO, §5, §13-R2)
- C6: Idempotency header renamed to best-effort `X-Idempotency-Key`; re-entry safety re-anchored
  on reusing the stored `checkout_session_id`. (§3.7, §4-api, §5, §6, §7, §13-R3, §14.3)
- C7: 422 example now includes the required `type` field. (§5)
- C8: Marked `409 cart_stale` as an unverified assumption (defensive handling only). (§5, §7, §13-R1)

### Open assumptions (unverifiable from the provided sources)
- A1: The element shape of `UnifiedCheckoutSessionOut.line_items[]` (it is
  `additionalProperties: true`); cannot confirm SKU/name/qty/price keys — backend or a sample
  payload needed. The web app never calls this endpoint.
- A2: Whether `/ui/checkout/session` honors any idempotency/dedupe (no param declared).
- A3: The full `status` value set beyond default `"pending_payment"`.
- A4: Existence/shape of a `409 cart_stale` (or any stale-cart) error on this endpoint.
- A5: Whether `cart_id` may be omitted (cart derived from session cookie).
- A6: Session `expires_at`/expiry UX (R4) — no expiry field in the response schema.
- A7: Tax provisional-before-address behavior (Q2) — no tax field in the response schema.

## 17. Test Plan

Test targets: **JVM** = JVM/Robolectric local; **emu35** = headless AVD `test35` (x86_64,
API 35); **A15** = physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). Cases that do
not need hardware run on emu35 in CI; ABI/API-specific behavior is called out for A15.

- **TC-AND-213-01** — Type: contract/MockWebServer. Target: JVM. Preconditions: MockWebServer
  enqueues `200` `UnifiedCheckoutSessionOut` with `checkout_session_id`, `order_id`, `source`,
  `status:"pending_payment"`, `line_items`. Steps: call
  `CheckoutRepositoryImpl.createSession(req(source=cart, cartId="cart_1"))`; capture the recorded
  request. Expected: request is `POST /ui/checkout/session`; body JSON has `"source":"cart"` and
  `"cart_id":"cart_1"`; header `X-Idempotency-Key` present; result `Success` with
  `id=="checkout_session_id"`. Traces: AC-3, AC-4.
- **TC-AND-213-02** — Type: unit. Target: JVM. Preconditions: a decoded
  `UnifiedCheckoutSessionOutDto` (normal + bundle-style line items). Steps: run `toDomain()`.
  Expected: `CheckoutSession.id` from `checkout_session_id`, `status` mapped, `line_items`
  projected, missing totals/bundle data default to null/empty without crashing. Traces: AC-4, AC-8.
- **TC-AND-213-03** — Type: unit. Target: JVM. Preconditions: response `status:"weird_value"`.
  Steps: map. Expected: `CheckoutStatus.UNKNOWN`, no exception. Traces: AC-8.
- **TC-AND-213-04** — Type: contract/MockWebServer. Target: JVM. Preconditions: enqueue `422`
  with `{"detail":[{"loc":["body","source"],"msg":"field required","type":"value_error.missing"}]}`.
  Steps: call `createSession`. Expected: `Failure(ApiError(status=422, message="field required"))`
  (first `msg`), per AND-015. Traces: AC-8.
- **TC-AND-213-05** — Type: contract/MockWebServer. Target: JVM. Preconditions: enqueue a
  conflict (assumed `409 {"detail":{"code":"cart_stale",...}}`; also test a `409` with a plain
  string `detail`). Steps: call `createSession`. Expected: `Failure` flagged recoverable; the
  ViewModel routes back to cart. (Marks A4 dependency.) Traces: AC-7.
- **TC-AND-213-06** — Type: unit. Target: JVM. Preconditions: stub `CheckoutApi` to throw
  `SocketTimeoutException`, then generic `IOException`, then `CancellationException`. Steps: call
  `createSession` for each. Expected: `NetworkError(isTimeout=true)`, `NetworkError(isTimeout=false)`,
  and re-thrown `CancellationException` respectively. Traces: AC-8.
- **TC-AND-213-07** — Type: integration. Target: JVM (Robolectric/coroutines-test). Preconditions:
  enqueue `401`, then a valid `200` on retry; AND-013 authenticator + `POST /ui/session/refresh`
  active. Steps: call `createSession`. Expected: exactly one refresh + one retry, then `Success`;
  a persistent `401` yields `Failure(status=401)` and a login-route signal. Traces: AC-8.
- **TC-AND-213-08** — Type: unit. Target: JVM. Preconditions: derived line-item/total amounts
  carry mixed currencies. Steps: map. Expected: `Failure(code="currency_mismatch")`, nothing
  rendered. Traces: AC-8.
- **TC-AND-213-09** — Type: unit (ViewModel). Target: JVM. Preconditions: fake `CartRepository`
  reports empty cart. Steps: `viewModel.start()`. Expected: state `EmptyCart`; **no** network
  call made (assert on fake repo). Traces: AC-6.
- **TC-AND-213-10** — Type: unit (ViewModel). Target: JVM. Preconditions: fake repo returns
  `Success`; then simulate process death by rebuilding the ViewModel with the same
  `SavedStateHandle`; trigger retry. Expected: `Loading`→`Ready`; the persisted idempotency key
  (and any in-flight `checkout_session_id`) is reused on retry — fake records identical
  `X-Idempotency-Key` and no second distinct session created. Traces: AC-7.
- **TC-AND-213-11** — Type: unit (ViewModel). Target: JVM. Preconditions: AND-017 connectivity
  fake reports offline. Steps: `start()`. Expected: state `Offline`, no request fired; retry when
  back online succeeds. Traces: AC-8. (Real flaky-dev-host/offline behavior also exercised on A15
  in TC-14.)
- **TC-AND-213-12** — Type: Compose-UI. Target: emu35. Preconditions: ViewModel in `Ready` with a
  normal + bundle-style line item. Steps: render `OrderReviewScreen`. Expected: all line items and
  the totals block render; "Proceed to payment" is **enabled**; empty/error/offline states render
  the correct AND-021 composable when injected. Traces: AC-5, AC-6.
- **TC-AND-213-13** — Type: Compose-UI (accessibility). Target: emu35. Preconditions: `Ready`
  state. Steps: run with semantics/TalkBack assertions and a touch-target check. Expected: line
  item exposes merged semantics (e.g. "name, quantity N, amount"); "Proceed to payment" has a
  >=48dp target and a disabled semantic when not `Ready`; bundle expander `contentDescription`
  reflects expanded/collapsed + count; labels come from string resources. Traces: AC-5.
- **TC-AND-213-14** — Type: instrumented/e2e. Target: **A15 (physical — required)**. Rationale:
  real cleartext HTTP to the flaky dev host `http://18.222.237.167:8000`, real radio
  offline/timeout transitions, and arm64-v8a/API-34 transport behavior differ from the x86_64/
  API-35 emulator. Preconditions: authenticated cookie session; a non-empty server cart. Steps:
  from Cart tap "Checkout"; observe Order Review; tap "Proceed to payment"; also toggle airplane
  mode mid-request to exercise timeout/offline. Expected: real `200` renders the session; proceed
  emits a nav event carrying `checkout_session_id` to the AND-227 route; offline/timeout shows the
  retry path and a reused key on manual retry (no duplicate order). Traces: AC-5, AC-7, AC-8.
- **TC-AND-213-15** — Type: instrumented (security/permission). Target: emu35. Preconditions:
  CSRF/cookie interceptors active; Logcat captured at the configured `BASIC` level. Steps: run a
  `createSession` round-trip. Expected: outgoing request carries the session cookie +
  `X-CSRF-Token`; captured logs contain **no** price amounts, `checkout_session_id`, `cart_id`, or
  `X-Idempotency-Key`, and no raw response body. Traces: AC-9.
- **TC-AND-213-16** — Type: manual. Target: A15. Preconditions: real signed-out session. Steps:
  let the session expire, then attempt checkout. Expected: single silent refresh; if refresh
  fails, user is routed to login and the in-flight session is abandoned (not retried). Traces: AC-8.

### Coverage matrix

| AC (§14) | Covered by |
|---|---|
| AC-1 (repository method exists/bound) | TC-01 (exercises the method); inspection |
| AC-2 (framework-free domain types) | inspection (no test asserts framework leakage) |
| AC-3 (POST + body `source`/`cart_id` + `X-Idempotency-Key`) | TC-01 |
| AC-4 (success maps `UnifiedCheckoutSessionOut`) | TC-01, TC-02 |
| AC-5 (checkout→review→proceed nav with session id) | TC-12, TC-13, TC-14 |
| AC-6 (empty-cart guard) | TC-09, TC-12 |
| AC-7 (recoverable conflict + reused key, no dup order) | TC-05, TC-10, TC-14 |
| AC-8 (failure mapping: 422/401/timeout/IO/unknown/currency/cancel) | TC-03, TC-04, TC-06, TC-07, TC-08, TC-11, TC-16 |
| AC-9 (no PII/secrets in logs) | TC-15 |
| AC-10 (gradle gates + lint green) | TC-01..TC-13, TC-15 in CI; ktlint/detekt gate |
