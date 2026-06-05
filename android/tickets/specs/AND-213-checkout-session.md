---
id: AND-213
title: "Checkout session"
milestone: M5
epic: E29
priority: P0
size: M
status: draft
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
displays the server-confirmed line items, computed totals, and the session identifier that
the billing step will consume.

The goal is a single, testable seam — `CheckoutRepository.createSession(...)` returning
`ApiResult<CheckoutSession>` — plus a `feature-checkout` `CheckoutSessionViewModel` /
`OrderReviewScreen` pair that renders the session and exposes a "Proceed to payment"
action. Creating a checkout session **snapshots** the cart on the server: prices, taxes,
shipping placeholders, and the file-bundle composition are computed server-side and returned
authoritatively, so the client must render server totals rather than recomputing them.

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
3. The created session is **authoritative**: the response carries server-computed
   `line_items[]`, `subtotal`, `tax`, `shipping`, `discount`, `total`, `currency`, and a
   `status`. The Order Review UI renders these values verbatim — the client never recomputes
   the total.
4. **File-bundle support:** cart line items that represent a file bundle (a grouping of
   downloadable assets sold as one SKU) are sent and rendered as a single bundle line item
   with an expandable list of included files (`bundle_contents[]`). The session response
   preserves bundle grouping.
5. On the Cart screen "Checkout" action, navigate to the `order_review` route and trigger
   `createSession`. The Order Review screen shows: loading while creating, the line items +
   totals on success, and a "Proceed to payment" primary action.
6. "Proceed to payment" navigates to the billing route owned by AND-227, passing
   `CheckoutSession.id`. This ticket does NOT call Stripe or `/ui/billing/checkout_session`.
7. The session must be **idempotent to re-entry**: re-creating a session from the same cart
   (e.g. on screen recreation / process death restore) must not double-charge or create
   orphan orders. The client sends an `Idempotency-Key` header and/or reuses an in-flight
   session id (see Section 6/7).
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

Domain types (in `core-model`, framework-free):

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

Wire DTOs (in `core-network`; field names confirmed against `/openapi.json` and
`frontend/src/api/types.ts` before merge):

```kotlin
@JsonClass(generateAdapter = true)
data class CheckoutSessionRequestDto(
    @Json(name = "cart_id") val cartId: String? = null,
)

@JsonClass(generateAdapter = true)
data class MoneyDto(
    @Json(name = "amount") val amountMinor: Long,
    @Json(name = "currency") val currency: String,
)

@JsonClass(generateAdapter = true)
data class CheckoutLineItemDto(
    val sku: String,
    val name: String,
    val quantity: Int,
    @Json(name = "unit_price") val unitPrice: MoneyDto,
    @Json(name = "line_total") val lineTotal: MoneyDto,
    @Json(name = "is_bundle") val isBundle: Boolean = false,
    @Json(name = "bundle_contents") val bundleContents: List<BundleContentDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class BundleContentDto(
    @Json(name = "file_id") val fileId: String,
    val name: String,
    @Json(name = "size_bytes") val sizeBytes: Long? = null,
)

@JsonClass(generateAdapter = true)
data class CheckoutSessionDto(
    val id: String,
    val status: String,
    @Json(name = "line_items") val lineItems: List<CheckoutLineItemDto> = emptyList(),
    val subtotal: MoneyDto,
    val tax: MoneyDto,
    val shipping: MoneyDto? = null,
    val discount: MoneyDto? = null,
    val total: MoneyDto,
    @Json(name = "expires_at") val expiresAt: Long? = null,
)
```

`CheckoutApi` (Retrofit; the `Idempotency-Key` is supplied per-call):

```kotlin
interface CheckoutApi {
    @POST("ui/checkout/session")
    suspend fun createSession(
        @Header("Idempotency-Key") idempotencyKey: String,
        @Body body: CheckoutSessionRequestDto,
    ): CheckoutSessionDto
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
            body = CheckoutSessionRequestDto(cartId = request.cartId),
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

Endpoint consumed: **`POST /ui/checkout/session`** (authenticated; cookies + `X-CSRF-Token`
added by AND-011/AND-012 interceptors).

Request headers: `Content-Type: application/json`, `Idempotency-Key: <uuid>` (client),
`X-CSRF-Token: <ui_csrf>` (interceptor).

Request body:

```json
{ "cart_id": "cart_01HXY..." }
```

(If the backend derives the cart from the session cookie rather than an explicit id, the
body may be `{}`; confirm against `/openapi.json` — see Section 13 R1.)

Representative success (`200`/`201`) with a normal item and a file bundle:

```json
{
  "id": "cs_01J2ABC...",
  "status": "open",
  "line_items": [
    {
      "sku": "SKU-TEE-001", "name": "Logo Tee", "quantity": 2,
      "unit_price": { "amount": 1999, "currency": "USD" },
      "line_total": { "amount": 3998, "currency": "USD" },
      "is_bundle": false
    },
    {
      "sku": "BNDL-DOCS-01", "name": "Onboarding File Bundle", "quantity": 1,
      "unit_price": { "amount": 4900, "currency": "USD" },
      "line_total": { "amount": 4900, "currency": "USD" },
      "is_bundle": true,
      "bundle_contents": [
        { "file_id": "f_1", "name": "guide.pdf", "size_bytes": 184320 },
        { "file_id": "f_2", "name": "templates.zip", "size_bytes": 920000 }
      ]
    }
  ],
  "subtotal": { "amount": 8898, "currency": "USD" },
  "tax":      { "amount": 712,  "currency": "USD" },
  "shipping": null,
  "discount": null,
  "total":    { "amount": 9610, "currency": "USD" },
  "expires_at": 1764979200
}
```
→ `ApiResult.Success(CheckoutSession(id="cs_01J2ABC...", status=OPEN, ...))`.

Error responses (folded by `apiCall`/AND-015 into `ApiResult.Failure(ApiError)`):

- **409 Conflict** — cart changed / item unavailable (stale cart):
  ```json
  { "detail": { "code": "cart_stale", "message": "Cart changed; please review." } }
  ```
  → `Failure(ApiError(status=409, code="cart_stale", ...))`, treated as **recoverable** →
  route user back to cart.
- **422 Unprocessable Entity** — validation (`detail` as list):
  ```json
  { "detail": [ { "loc": ["body","cart_id"], "msg": "field required" } ] }
  ```
  → `Failure(ApiError(status=422, message="field required"))`.
- **401 Unauthorized** — session expired → AND-013 authenticator runs `POST /ui/session/refresh`
  once and retries; persistent 401 → `Failure(ApiError(status=401))` → route to login.
- **5xx / timeout / unreachable host** → `ApiResult.NetworkError(isTimeout)`.

This is a **non-idempotent POST**; AND-016 backoff retry does NOT apply automatically. The
`Idempotency-Key` makes a *manual* retry safe (server returns the same session for the same
key). Endpoint verbs/paths/DTO shapes are validated against `/openapi.json` and MockWebServer
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
- **Stale cart (409 `cart_stale`):** mapped to a recoverable error; the Order Review screen
  shows "Your cart changed" and offers "Back to cart" (the only safe action) rather than a
  blind retry.
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
  added by AND-011/AND-012; this ticket adds no auth handling of its own.
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
- Success mapping: full response (normal item + bundle) → `CheckoutSession` with correct
  `status=OPEN`, ordered line items, bundle `bundleContents` preserved, `shipping=null`,
  `total` mapped verbatim.
- Unknown `status` string → `CheckoutStatus.UNKNOWN` (no crash).
- Currency mismatch across line items/totals → `Failure(code="currency_mismatch")`.
- `409 cart_stale` → `Failure(status=409, code="cart_stale")`.
- `422` list `detail` → `Failure(status=422, message=first msg)` (AND-015).
- `SocketTimeoutException` → `NetworkError(isTimeout=true)`; generic `IOException` →
  `NetworkError(isTimeout=false)`; `CancellationException` re-thrown.

MockWebServer contract tests (complement AND-217):
- `createSession` issues `POST /ui/checkout/session` carrying header `Idempotency-Key`
  (recorded request asserted) and body `{"cart_id":"..."}`.
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

- **R1 — Cart reference shape.** Whether `POST /ui/checkout/session` takes an explicit
  `cart_id` or derives the cart from the session cookie is unconfirmed. Mitigation: model the
  body as `{cart_id?}` and verify against `/openapi.json` / `frontend/src/api/endpoints`
  before merge.
- **R2 — File-bundle representation.** The exact field names for bundle composition
  (`is_bundle` / `bundle_contents` / `file_id`) are assumed. Confirm against
  `frontend/src/api/types.ts`; if the backend nests bundles differently, only the DTO +
  mapper change (domain `CheckoutLineItem` is stable).
- **R3 — Idempotency support.** This ticket assumes the backend honors an `Idempotency-Key`
  header on `/ui/checkout/session`. If it does not, re-entry must instead reuse a stored
  in-flight session id, or the server must be confirmed to dedupe by cart id. Open: verify
  idempotency semantics with the backend owner.
- **R4 — Session expiry UX.** `expires_at` handling (what to show if the user lingers past
  expiry, then taps proceed) — assumed to surface as a recoverable error from AND-227's
  call. Confirm whether this ticket must proactively show a countdown (currently out of
  scope).
- **Q1 — Status vocabulary.** The set of `status` strings (`open`, `requires_payment`, ...)
  must be confirmed against `/openapi.json`; unknowns map to `UNKNOWN` defensively.
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
3. `createSession` issues `POST /ui/checkout/session` with an `Idempotency-Key` header and
   the cart reference body (asserted via MockWebServer recorded request).
4. A representative success response (including a **file-bundle** line item) maps to
   `Success(CheckoutSession)` with server totals rendered verbatim and bundle contents
   preserved (tested per Section 11).
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
