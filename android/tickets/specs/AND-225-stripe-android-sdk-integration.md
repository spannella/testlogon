---
id: AND-225
title: Stripe Android SDK integration
milestone: M5
epic: E31
priority: P0
size: M
depends_on: [AND-223]
blocks: [AND-226, AND-227, AND-236]
status: reviewed
reviewed_on: 2026-06-06
---

# AND-225 — Stripe Android SDK integration

## 1. Overview & Goal

Integrate the official Stripe Android SDK into the TestLogon native app and wire it to the
backend's PaymentIntent-based billing flow so that the app can collect card details and confirm a
payment entirely on-device using Stripe's hosted UI. This ticket delivers the **foundational
payment plumbing** for the E31 Billing epic: SDK dependency, `PaymentConfiguration` bootstrap with
the publishable key, a `core-data` payment service that brokers PaymentIntents through the FastAPI
backend, and a thin `PaymentSheet` launcher exposed to feature modules.

The deliverable is intentionally scoped to **infrastructure plus one provable round-trip**: Stripe
must be initialized at app start, and a test-mode `PaymentIntent` created by the backend must be
confirmable to a terminal `succeeded` state through `PaymentSheet` using a Stripe test card. This
ticket does **not** build the "Add card" UX (AND-226), the cart-driven checkout session
(AND-227), or the billing state machine/error mapping ViewModels (AND-232); it provides the
reusable launcher and result types those tickets consume.

Acceptance, restated as the engineering bar: (1) `PaymentConfiguration.init(...)` runs exactly once
with a publishable key sourced from config, and (2) a backend-issued test PaymentIntent
`client_secret` drives `PaymentSheet` to a confirmed result that the backend reports as paid.

## 2. Context & References

- **Stack:** Kotlin 2.0.21, Jetpack Compose + Material 3, single-Activity Navigation-Compose, Hilt
  (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15. minSdk 24, compileSdk/targetSdk
  35, JDK 17, Gradle 8.9, AGP 8.7.3.
- **Module layering:** `app -> feature-* -> core-*`. New code lands in `core-data` (payment service +
  Hilt module) and `core-model` (result/DTO types). `PaymentSheet` is an Activity-hosted component, so
  the launcher contract is surfaced for feature modules and wired in the single Activity.
- **Namespace / applicationId base:** `com.testlogon.android` (used for all packages, the Stripe
  return-URL scheme, and the `PaymentConfiguration` caller context).
- **Auth:** session-based with `ui_csrf` echoed as `X-CSRF-Token`; persistent cookie jar; single
  `POST /ui/session/refresh` retry on 401. All `/ui/billing/*` calls ride this session. **[CORRECTED]**
  Verified in `src/api/client.ts`: the web client sends `X-CSRF-Token` (from the `ui_csrf` cookie) on
  **every** request, not only mutating ones, and also attaches `Authorization: Bearer <accessToken>` plus
  (when active) `X-IMPERSONATION-TOKEN`; on a 401 for an authenticated user it calls `POST /ui/session/refresh`
  exactly once and retries. The OpenAPI index additionally lists `user_sub`, `X-SESSION-ID`, and
  `X-IMPERSONATION-TOKEN` as params on `/ui/billing/*`. The exact Android header/cookie strategy is owned by
  AND-223; AND-225 only requires that the CSRF header + 401-refresh-retry behavior is applied to the two
  billing calls it makes.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext HTTP,
  unreliable). OpenAPI at `/openapi.json`. Error `detail` is `string | [{msg}] | {code,...}`.
- **Upstream dependency — AND-223 (Billing API + DTOs):** provides `BillingApi` (Retrofit),
  `core-model` billing DTOs, and `ApiResult<T>` mapping. AND-225 **consumes** these; it adds only the
  PaymentIntent-specific request/response DTOs if AND-223 has not already defined them (see §5).
- **Web reference:** `frontend/src/api/endpoints/billing.ts` and `frontend/src/api/types.ts` for the
  canonical `/ui/billing/*` payload shapes and Stripe field names. **[CORRECTED]** Verified against the
  reference app: the publishable key is delivered by `GET /ui/billing/config` (`BillingConfig.publishable_key`,
  see `src/api/types.ts` and `src/pages/billing/BillingOverview.tsx`); a Stripe `client_secret` is returned
  only by the SetupIntent endpoints (`POST /ui/billing/setup-intent/card` / `.../us-bank`,
  `{ client_secret }`); and the charge endpoints (`POST /ui/billing/charge-once`, `pay-balance`,
  `wallet/deposit`) return `{ status, payment_intent_id }` server-side **without** a `client_secret`.
  There is **no** `/ui/billing/payment_intents` resource (see §5). The Stripe field names used by the
  contract are `client_secret`, `publishable_key`, `payment_intent_id`, `status`.
- **Stripe SDK docs:** PaymentSheet integration (`com.stripe:stripe-android`), `PaymentConfiguration`,
  `PaymentSheetResultCallback`.

## 3. Functional Requirements

FR-1. Add the Stripe Android SDK (`com.stripe:stripe-android:20.x`) to the Gradle version catalog and
to `core-data` (transitively available to `app` / feature modules that host PaymentSheet).

FR-2. Initialize Stripe exactly once per process via `PaymentConfiguration.init(context, publishableKey)`
during app startup, before any payment flow can be triggered. The publishable key is read from app
config (BuildConfig / DataStore-backed remote config), never hard-coded into business logic.

FR-3. Provide a `StripePaymentService` in `core-data` that:
  - requests a PaymentIntent `client_secret` from the backend for a given amount/currency/intent
    context, and
  - exposes the publishable key and merchant display name needed to configure PaymentSheet.

FR-4. Provide a reusable, lifecycle-correct `PaymentSheet` launcher (`StripePaymentLauncher`)
registered from a Compose context (`rememberPaymentSheet`) or the host Activity, that presents
PaymentSheet for a `client_secret` and returns a typed `PaymentResult`.

FR-5. Map Stripe's `PaymentSheetResult` (`Completed | Canceled | Failed`) into the app's
`PaymentResult` sealed type so feature/ViewModel code (AND-232) never depends on Stripe types
directly.

FR-6. After a `Completed` result, optionally confirm terminal status with the backend
(`GET /ui/billing/payment_intents/{id}`) so the app's notion of "paid" is server-authoritative, not
solely client-reported.

FR-7. Operate fully in **Stripe test mode**: use a test publishable key (`pk_test_...`) and accept
Stripe test cards (e.g., `4242 4242 4242 4242`). No production keys ship in this ticket.

FR-8. Be safe to call before initialization completes: triggering payment without an initialized
`PaymentConfiguration` must fail with a typed error, not crash.

## 4. Technical Design

> **[CORRECTION — read with §5]** The code sketches below name a `createPaymentIntent` /
> `fetchPaymentIntent` / `PaymentIntentDto` / `getPaymentIntent` API and call
> `sheet.presentWithPaymentIntent(clientSecret, ...)`. Those endpoints/DTOs **do not exist** in the
> verified backend contract (see §5). For the buildable round-trip, substitute the verified surface:
> `getBillingConfig()` (publishable key), `createCardSetupIntent()` -> `client_secret`, and
> `sheet.presentWithSetupIntent(clientSecret, config)` (SetupIntent flow). The service/launcher shapes,
> Hilt wiring, initializer, and `PaymentResult` mapping below remain valid as written; only the endpoint
> names and the `presentWith…` call must follow §5. The illustrative code is retained for structure.

**Module placement.** Service, Hilt module, and DTOs live in `core-data` /`core-model`. The
PaymentSheet launcher is UI-adjacent (needs an `ActivityResultRegistry` owner), so the launcher
helper lives in `core-ui` (or `core-data` UI-less factory + `core-ui` Compose helper). Feature
modules call a single `presentPaymentSheet(...)` entry point.

**Initialization.** A Hilt-injected `StripeInitializer` runs from the `Application.onCreate()`
(or a `Initializer`/`@HiltAndroidApp` startup hook) added in this ticket:

```kotlin
// core-data/.../payment/StripeInitializer.kt
package com.testlogon.android.core.data.payment

class StripeInitializer @Inject constructor(
    @ApplicationContext private val context: Context,
    private val config: PaymentConfigProvider,
) {
    @Volatile private var initialized = false
    fun ensureInitialized() {
        if (initialized) return
        synchronized(this) {
            if (initialized) return
            PaymentConfiguration.init(context, config.publishableKey())
            initialized = true
        }
    }
    fun isInitialized(): Boolean = initialized
}
```

```kotlin
// core-data/.../payment/PaymentConfigProvider.kt
interface PaymentConfigProvider {
    /** pk_test_... in dev; resolved from BuildConfig.STRIPE_PUBLISHABLE_KEY or backend config. */
    fun publishableKey(): String
    fun merchantDisplayName(): String   // "TestLogon"
}
```

**Service.** `StripePaymentService` brokers the PaymentIntent through `BillingApi` (AND-223) and
returns the launch parameters:

```kotlin
// core-data/.../payment/StripePaymentService.kt
interface StripePaymentService {
    suspend fun createPaymentIntent(req: CreatePaymentIntentRequest): ApiResult<PaymentIntentDto>
    suspend fun fetchPaymentIntent(id: String): ApiResult<PaymentIntentDto>
    fun paymentSheetConfig(): PaymentSheet.Configuration
}

class StripePaymentServiceImpl @Inject constructor(
    private val billingApi: BillingApi,
    private val initializer: StripeInitializer,
    private val config: PaymentConfigProvider,
) : StripePaymentService {
    override suspend fun createPaymentIntent(req: CreatePaymentIntentRequest) =
        billingApi.createPaymentIntent(req).toApiResult { it.toDomain() }
    override suspend fun fetchPaymentIntent(id: String) =
        billingApi.getPaymentIntent(id).toApiResult { it.toDomain() }
    override fun paymentSheetConfig(): PaymentSheet.Configuration {
        initializer.ensureInitialized()
        return PaymentSheet.Configuration.Builder(config.merchantDisplayName())
            .allowsDelayedPaymentMethods(false)
            .build()
    }
}
```

**Launcher (Compose).** PaymentSheet requires registration during composition/activity-create:

```kotlin
// core-ui/.../payment/StripePaymentLauncher.kt
@Composable
fun rememberStripePaymentLauncher(
    onResult: (PaymentResult) -> Unit,
): StripePaymentLauncher {
    val sheet = rememberPaymentSheet { result -> onResult(result.toPaymentResult()) }
    return remember(sheet) { StripePaymentLauncher(sheet) }
}

class StripePaymentLauncher internal constructor(private val sheet: PaymentSheet) {
    fun present(clientSecret: String, config: PaymentSheet.Configuration) {
        sheet.presentWithPaymentIntent(clientSecret, config)
    }
}

internal fun PaymentSheetResult.toPaymentResult(): PaymentResult = when (this) {
    is PaymentSheetResult.Completed -> PaymentResult.Completed
    is PaymentSheetResult.Canceled  -> PaymentResult.Canceled
    is PaymentSheetResult.Failed    -> PaymentResult.Failed(error.message, error)
}
```

**Result type (core-model).**

```kotlin
sealed interface PaymentResult {
    data object Completed : PaymentResult
    data object Canceled : PaymentResult
    data class Failed(val message: String?, val cause: Throwable? = null) : PaymentResult
}
```

**Hilt wiring.**

```kotlin
@Module @InstallIn(SingletonComponent::class)
abstract class PaymentModule {
    @Binds abstract fun bindPaymentService(impl: StripePaymentServiceImpl): StripePaymentService
    @Binds abstract fun bindPaymentConfig(impl: BuildConfigPaymentConfigProvider): PaymentConfigProvider
}
```

**Return URL.** Even though PaymentSheet handles most 3DS in-sheet, set a return URL scheme
`com.testlogon.android.stripe://payment_return` on the PaymentSheet configuration so any redirect-based
method or 3DS hand-off returns to the app; register the matching `<intent-filter>` is deferred to the
generic redirect handler (AND-231). For this ticket, the in-sheet test-card flow needs no external
redirect.

**Flow (test round-trip).**
1. App start -> `StripeInitializer.ensureInitialized()`.
2. Caller -> `createPaymentIntent({amount, currency})` -> backend returns `client_secret`.
3. `rememberStripePaymentLauncher` present(`client_secret`, `paymentSheetConfig()`).
4. User enters test card `4242…` -> PaymentSheet confirms -> `Completed`.
5. Optional `fetchPaymentIntent(id)` -> backend `status: "succeeded"`.

## 5. API Contract

PaymentIntents/SetupIntents are created **server-side** (the publishable key alone cannot create them;
the secret key lives on the backend). The app calls the backend, which calls Stripe.

**[MAJOR CORRECTION]** The endpoints `POST /ui/billing/payment_intents` and
`GET /ui/billing/payment_intents/{id}` asserted by the original draft **do not exist** in the backend
OpenAPI (`reference/openapi.index.txt`) nor in the web reference (`src/api/endpoints/billing.ts`). There
is no `payment_intents` resource and no `PaymentIntentDto` schema (`components.schemas` has no such name).
The real contract is:

| Purpose | Endpoint | Request | Response (documented) |
| --- | --- | --- | --- |
| Publishable key + currency | `GET /ui/billing/config` | — | `BillingConfig { publishable_key?: string, currency: string }` |
| Card SetupIntent (returns a usable `client_secret`) | `POST /ui/billing/setup-intent/card` | — (empty body) | `{ client_secret: string }` |
| One-off charge of a saved method | `POST /ui/billing/charge-once` | `StripeChargeReq` | `{ status: string, payment_intent_id: string }` |
| Pay outstanding balance | `POST /ui/billing/pay-balance` | `PayBalanceReq` | `{ status: string, payment_intent_id?: string }` |
| Wallet top-up | `POST /ui/billing/wallet/deposit` | `WalletDepositReq` | `{ status, payment_intent_id, wallet_balance_cents }` |

Consequences for this ticket: (a) the publishable key comes from `GET /ui/billing/config`, **not** from a
per-intent response field; (b) the **only** documented endpoint that returns a Stripe `client_secret` is
`POST /ui/billing/setup-intent/card` — which yields a **SetupIntent** (`seti_..._secret_...`), not a
PaymentIntent. The charge endpoints confirm a PaymentIntent **server-side** and return only its
`payment_intent_id` + `status`; they do **not** hand a PaymentIntent `client_secret` to the client.

**Implication for the provable round-trip.** PaymentSheet's `presentWithPaymentIntent(...)` requires a
PaymentIntent `client_secret`, which **no current backend endpoint exposes**. Two options, both must be
flagged as gaps rather than treated as settled (see §13 R2 and §16 Open assumptions):

1. **Use `presentWithSetupIntent(...)` against `POST /ui/billing/setup-intent/card`** to prove the SDK
   round-trip end-to-end today (this is the verified, existing client-secret path). This shifts the
   "confirm" semantics from "payment succeeded" to "setup succeeded"; AC-4/AC-5 must be reworded
   accordingly, or
2. **Require a backend addition** (a `POST /ui/billing/payment_intents`-style endpoint, or extend
   `charge-once` to return a `client_secret`) before a true PaymentIntent confirmation is testable on
   device. This is a backend dependency that is **not** part of AND-223 as scoped.

This review recommends option (1) for AND-225's "infrastructure + one provable round-trip" and treating
the PaymentIntent variant as deferred to whichever ticket lands the backend endpoint (coordinate with
AND-227 checkout, which uses `POST /ui/billing/checkout_session` returning `{ session_id, url }` — a
redirect/Checkout flow, not in-app PaymentSheet).

**Setup-intent (card) — `POST /ui/billing/setup-intent/card`** (empty body)

Response `200`:
```json
{ "client_secret": "seti_1Q..._secret_abc" }
```

**Charge once — `POST /ui/billing/charge-once`** (req `StripeChargeReq`)

Request (verified field names — note `amount_cents`, not `amount`; **no** `currency` or `intent_context`):
```json
{ "amount_cents": 500, "payment_method_id": "pm_123", "description": "AND-225 smoke", "idempotency_key": "..." }
```
Response `200`:
```json
{ "status": "succeeded", "payment_intent_id": "pi_3Q..." }
```

**Config — `GET /ui/billing/config`**

Response `200`:
```json
{ "publishable_key": "pk_test_...", "currency": "usd" }
```

Headers: session + `X-CSRF-Token: <ui_csrf>` on every request (see §2 correction). On `401`, the OkHttp
authenticator performs one `POST /ui/session/refresh` and retries. Validation errors return `422` with a
FastAPI `HTTPValidationError` body (`{ "detail": [{ "loc", "msg", "type" }] }`).

**DTOs (Moshi) — corrected to verified shapes:**
```kotlin
// GET /ui/billing/config
@JsonClass(generateAdapter = true)
data class BillingConfigDto(
    @Json(name = "publishable_key") val publishableKey: String? = null,
    val currency: String,
)

// POST /ui/billing/setup-intent/card  (and .../us-bank)
@JsonClass(generateAdapter = true)
data class SetupIntentDto(
    @Json(name = "client_secret") val clientSecret: String,
)

// POST /ui/billing/charge-once  — request body is StripeChargeReq
@JsonClass(generateAdapter = true)
data class StripeChargeRequest(
    @Json(name = "amount_cents") val amountCents: Long,       // required, >= 1
    @Json(name = "payment_method_id") val paymentMethodId: String? = null,
    val description: String? = null,
    @Json(name = "idempotency_key") val idempotencyKey: String? = null,
)

// POST /ui/billing/charge-once / pay-balance / wallet/deposit responses
@JsonClass(generateAdapter = true)
data class ChargeResultDto(
    val status: String,
    @Json(name = "payment_intent_id") val paymentIntentId: String? = null,
)
```

**Retrofit (extends AND-223 `BillingApi`) — corrected paths:**
```kotlin
@GET("ui/billing/config")
suspend fun getBillingConfig(): Response<BillingConfigDto>

@POST("ui/billing/setup-intent/card")
suspend fun createCardSetupIntent(): Response<SetupIntentDto>

@POST("ui/billing/charge-once")
suspend fun chargeOnce(@Body body: StripeChargeRequest): Response<ChargeResultDto>
```

> There is **no** `GET .../payment_intents/{id}` to "fetch and confirm status"; server-authoritative
> status for a charge is the `status` field already returned by `charge-once` (Stripe values:
> `requires_payment_method`, `requires_confirmation`, `requires_action`, `processing`, `succeeded`,
> `canceled`). Treat `succeeded` as terminal-paid; `requires_action` means an SCA/3DS step is needed
> (handled in-sheet for PaymentSheet, or via the SetupIntent confirmation flow). Reconciliation by ledger
> (`GET /ui/billing/payments` / `GET /ui/billing/ledger`) is available if a stronger after-the-fact check
> is wanted, but is out of scope for AND-225.

## 6. Data & State Management

- **No Room persistence** in this ticket — PaymentIntents are ephemeral and server-authoritative;
  caching a `client_secret` is a security anti-pattern. The Room cache layer is N/A here.
- **Initialization flag:** `StripeInitializer.initialized` is in-memory only (`@Volatile`),
  re-established each process start. Idempotent and thread-safe via double-checked locking.
- **Publishable key:** **[CORRECTED]** the verified backend source is `GET /ui/billing/config`
  (`BillingConfig.publishable_key`), which is how the web client obtains it
  (`src/pages/billing/BillingOverview.tsx`). The create/charge endpoints do **not** echo a per-intent
  `publishable_key`. For AND-225, `PaymentConfigProvider.publishableKey()` should prefer the value from
  `GET /ui/billing/config` (cached in-memory for the process) and may fall back to a
  `BuildConfig.STRIPE_PUBLISHABLE_KEY` debug default when config is unavailable; a DataStore-backed
  override remains a later option. The `config` field is the authoritative source.
- **Launcher state:** PaymentSheet result is delivered via the ActivityResult callback. The consuming
  ViewModel (AND-232) holds the payment state machine; this ticket only emits a one-shot
  `PaymentResult`. No `StateFlow` is owned here beyond what callers wrap.
- **Idempotency:** PaymentIntent creation is a non-idempotent POST; do **not** auto-retry it on
  timeout (per backoff policy: retries only for idempotent GETs). `fetchPaymentIntent` (GET) may use
  bounded backoff.

## 7. Error Handling & Resilience

- **Unreliable dev host:** all billing calls use the shared ~20s OkHttp timeout. `createPaymentIntent`
  (POST) is **not** retried; surface a typed `ApiResult.Failure` with a retry-by-user affordance.
  `getPaymentIntent` (GET) uses bounded backoff (e.g., 3 attempts, jittered).
- **FastAPI `detail` mapping:** reuse the shared mapper for `string | [{msg}] | {code,...}` to produce
  user-facing messages; never display raw JSON.
- **Stripe results:**
  - `Canceled` -> no error toast; return to caller silently.
  - `Failed(error)` -> map `error.message`; log non-PII Stripe error code.
  - `Completed` -> optimistic success, optionally reconciled via `fetchPaymentIntent`.
- **Not-initialized guard:** `paymentSheetConfig()` calls `ensureInitialized()`; if the publishable key
  is blank/invalid it throws `IllegalStateException` caught and converted to
  `PaymentResult.Failed("Payment is not available")` rather than crashing.
- **Network-during-confirm:** PaymentSheet manages its own confirmation network; a network failure
  yields `PaymentSheetResult.Failed` which maps to `PaymentResult.Failed`.
- **Offline/stale UI:** callers (AND-232) render an offline state if `createPaymentIntent` fails;
  this ticket guarantees the error is typed and non-fatal.

## 8. Security & Privacy

- **No raw PAN/CVV touches app code.** Card entry is exclusively inside Stripe's PaymentSheet; the app
  never reads, logs, or stores card numbers, expiry, or CVV. This keeps the app outside PCI-DSS SAQ-D
  scope (SAQ-A-EP eligible).
- **No secret key on device.** Only the publishable key (`pk_test_...`) ships. PaymentIntent creation
  (which needs the secret key) is backend-only.
- **`client_secret` handling:** treated as sensitive — never logged, never persisted to disk/Room/
  DataStore, passed in-memory to PaymentSheet only.
- **Transport caveat:** dev backend is plaintext HTTP, so the `client_secret` traverses cleartext in
  dev. Acceptable for test-mode keys only; production requires HTTPS (network-security-config must
  forbid cleartext for prod build types). Note this constraint explicitly in the PR.
- **CSRF:** the create POST carries `X-CSRF-Token`; session cookies remain HttpOnly in the persistent
  jar.
- **Logging:** payment logs include `payment_intent_id` and `status` only — no `client_secret`, no
  publishable key, no card data.

## 9. Accessibility & i18n

- PaymentSheet is Stripe-owned and ships its own accessibility (TalkBack labels, focus order, dynamic
  type) and localized strings; we inherit these. No custom payment UI in this ticket, so app-side a11y
  surface is minimal.
- The merchant display name (`"TestLogon"`) and any app-side error strings must be in
  `core-ui`/`strings.xml`, not hard-coded, to support i18n.
- Currency/amount formatting for any app-rendered confirmation uses locale-aware formatting
  (`NumberFormat.getCurrencyInstance`) keyed off the DTO `currency`.
- Verify PaymentSheet honors the system dark theme via the app's Material 3 theme handoff.

## 10. Telemetry & Logging

- Emit structured analytics events (via the app's analytics abstraction):
  `payment_intent_created` `{intent_id, amount, currency}`,
  `payment_sheet_presented` `{intent_id}`,
  `payment_result` `{intent_id, result: completed|canceled|failed, error_code?}`.
- All events exclude PII and the `client_secret`.
- Stripe SDK emits its own internal analytics; no extra config needed. Do not disable it in test mode.
- Use the project logger at `DEBUG` for flow tracing in dev builds only; `INFO`/`WARN` for result
  outcomes; never log secrets at any level.

## 11. Testing Strategy

> **[CORRECTION]** Where this section says `createPaymentIntent` / `fetchPaymentIntent` / `status ==
> "succeeded"`, read the verified surface from §5: `createCardSetupIntent()` for the client-secret +
> `presentWithSetupIntent`, `getBillingConfig()` for the publishable key, and `chargeOnce()` (which
> returns `{ status, payment_intent_id }`) where a real charge is exercised. There is no
> `fetchPaymentIntent` GET. The detailed, corrected case list is in §17.

**Unit (core-testing, JVM):**
- `StripeInitializerTest`: `ensureInitialized()` calls `PaymentConfiguration.init` exactly once across
  concurrent callers (verify with a mocked static / wrapper + threads).
- `StripePaymentServiceTest`: mocked `BillingApi` returns a `PaymentIntentDto`; assert
  `createPaymentIntent` maps to `ApiResult.Success` and `fetchPaymentIntent` maps `status`. Assert POST
  is not retried on timeout; GET is.
- `PaymentResultMappingTest`: `PaymentSheetResult.{Completed,Canceled,Failed}` -> correct
  `PaymentResult`.
- DTO round-trip Moshi tests for `CreatePaymentIntentRequest` / `PaymentIntentDto` against fixture
  JSON copied from web reference shapes.

**Instrumentation / integration:**
- A debug-only smoke screen or instrumented test that: creates a test PaymentIntent via the dev
  backend, presents PaymentSheet, programmatically (or manually documented) enters `4242…`, and asserts
  `PaymentResult.Completed` followed by `fetchPaymentIntent(id).status == "succeeded"`. This directly
  proves the acceptance criterion.
- Error-path test: backend returns 5xx/timeout on create -> `PaymentResult` not produced and typed
  failure surfaced; not-initialized -> `PaymentResult.Failed`.

**CI:** unit tests run in CI; the live-backend integration test is gated (manual/nightly) due to dev
host unreliability and Stripe network dependency.

## 12. Dependencies & Sequencing

- **Depends on AND-223** (Billing API + DTOs): provides `BillingApi`, `ApiResult` mapping, and shared
  billing DTOs. AND-225 extends `BillingApi` with the two PaymentIntent endpoints if AND-223 did not
  already include them.
- **Transitively depends on** the auth/session foundation (cookie jar, CSRF header, 401 refresh) and
  the OkHttp/Retrofit/Moshi network stack (AND-027 lineage).
- **Blocks AND-226** (Add card via Stripe — uses this launcher + SetupIntent variant),
  **AND-227** (Checkout session billing — uses the PaymentSheet launcher to complete a purchase), and
  **AND-236** (Subscribe flow, via AND-227).
- **Coordinates with AND-231** (redirect/return handler) for the Stripe return-URL intent-filter;
  AND-225 defines the scheme, AND-231 owns the manifest registration and routing.
- **Feeds AND-232** (Billing ViewModels + provider error mapping), which consumes `PaymentResult` and
  `ApiResult`.

## 13. Risks & Open Questions

- **R1 — Cleartext dev transport:** `client_secret` over HTTP in dev. Mitigation: test-mode keys only;
  ensure prod network-security-config blocks cleartext. Open: confirm prod base URL/HTTPS timeline.
- **R2 — Backend PaymentIntent endpoint shape:** **[RESOLVED BY REVIEW]** verified against
  `reference/openapi.index.txt` and `src/api/endpoints/billing.ts`: there is **no** `payment_intents`
  endpoint and **no** endpoint that returns a PaymentIntent `client_secret`. The only client-secret source
  is `POST /ui/billing/setup-intent/card` (a SetupIntent). The publishable key comes from
  `GET /ui/billing/config` (it is **not** echoed per-intent and BuildConfig is only a fallback). Open
  follow-up (now a real dependency, not a guess): a true in-app PaymentIntent confirmation requires a new
  backend endpoint that returns a PaymentIntent `client_secret`; until then AND-225 proves the SDK
  round-trip via SetupIntent (see §5).
- **R3 — Stripe SDK version vs minSdk 24 / AGP 8.7.3:** confirm chosen `stripe-android` line supports
  minSdk 24 and Kotlin 2.0.21 / KSP. Mitigation: pin a tested version in the catalog.
- **R4 — PaymentSheet lifecycle:** `rememberPaymentSheet` must be registered before
  `STARTED`; presenting from a deeply nested composable can mis-scope the registry. Mitigation:
  register at the screen-root / Activity level.
- **R5 — 3DS / `requires_action`:** test-card `4242` doesn't trigger 3DS; the SCA path
  (`4000 0025 0000 3155`) is only fully validated in AND-227. Open question: is in-sheet 3DS sufficient
  or is the AND-231 return-handler required for any test path here?
- **Q1 — Merchant/Apple-Pay-equivalent (Google Pay):** out of scope for AND-225; confirm whether Google
  Pay is desired later.

## 14. Acceptance Criteria

AC-1. Stripe Android SDK is added via the version catalog and resolves in `core-data`; the app builds
on `compileSdk 35` / JDK 17 / AGP 8.7.3.

AC-2. `PaymentConfiguration.init(...)` executes exactly once at app start with a publishable key
sourced from config (verified by `StripeInitializerTest` and by a logged init marker, key redacted).

AC-3. **[CORRECTED to verified contract]** The payment service obtains a non-blank Stripe `client_secret`
for a valid request against the dev backend (test mode) via `POST /ui/billing/setup-intent/card`
(`{ client_secret }`), mapped to `ApiResult.Success`. (The original `createPaymentIntent` PaymentIntent
endpoint does not exist; see §5.) The publishable key is obtained via `GET /ui/billing/config`.

AC-4. **[CORRECTED]** Presenting `PaymentSheet` with that `client_secret` and entering Stripe test card
`4242 4242 4242 4242` yields `PaymentResult.Completed`. For the SetupIntent path this is
`presentWithSetupIntent`; if/when a backend PaymentIntent client-secret endpoint exists, the identical
launcher with `presentWithPaymentIntent` must produce the same `Completed` mapping.

AC-5. **[CORRECTED]** Server-authoritative confirmation: for the SetupIntent round-trip, the saved method
appears in `GET /ui/billing/payment-methods` after completion; for a charge path,
`POST /ui/billing/charge-once` returns `status == "succeeded"`. (There is no `fetchPaymentIntent` GET;
status is carried in the charge response — see §5.)

AC-6. `PaymentSheetResult.Canceled` and `…Failed` map to `PaymentResult.Canceled` / `Failed` with no
crash; not-initialized state maps to `PaymentResult.Failed`, not a crash.

AC-7. No card data and no `client_secret` appear in any log output (verified by review + a logging
test/assert).

AC-8. Unit tests for initializer, service mapping, result mapping, and DTO round-trip pass in CI.

## 15. Definition of Done

- All Acceptance Criteria (AC-1…AC-8) met and demonstrated (the test round-trip recorded/screenshotted
  in the PR).
- Code merged to `android-port`, in `com.testlogon.android.core.data.payment` /
  `…core.ui.payment` / `…core.model` packages, behind the established module layering.
- `StripePaymentService`, `StripePaymentLauncher`, `PaymentResult`, and the Hilt `PaymentModule` are
  public/consumable APIs documented with KDoc for downstream tickets (AND-226/227/232).
- Version catalog entry pinned; no production Stripe keys committed; `pk_test_...` sourced from
  BuildConfig (debug) only.
- Unit tests green in CI; gated integration smoke documented and runnable.
- Security review notes the cleartext-dev caveat and confirms prod cleartext is blocked.
- No new lint/detekt regressions; PR description links AND-223 and lists AND-226/227 follow-ups.

## 16. Citations & Assumption Audit

Each claim below is stated, given a VERDICT (Verified / Corrected / Unverified-assumption), and tied to
an exact source pointer.

1. **Claim:** Create PaymentIntent at `POST /ui/billing/payment_intents`. — **VERDICT: Corrected (endpoint
   does not exist).** No such path in `reference/openapi.index.txt` (the `/ui/billing/*` block, lines
   ~1171–1203, has no `payment_intents`) and none in `src/api/endpoints/billing.ts`. No `PaymentIntentDto`
   in `openapi.pretty.json` `components.schemas`.
2. **Claim:** Fetch PaymentIntent at `GET /ui/billing/payment_intents/{id}`. — **VERDICT: Corrected (does
   not exist).** Same sources as #1; there is no per-intent GET. Status reconciliation, if needed, uses
   `GET /ui/billing/payments` (`list_payments_ui_billing_payments_get`) or `GET /ui/billing/ledger`.
3. **Claim:** A backend endpoint returns a Stripe `client_secret`. — **VERDICT: Corrected/clarified.** The
   only documented client-secret source is `POST /ui/billing/setup-intent/card` (a **SetupIntent**) ->
   `{ client_secret }`. Source: OpenAPI `create_card_setup_intent_ui_billing_setup_intent_card_post`;
   `src/api/endpoints/billing.ts: createCardSetupIntent` (`api.post<{ client_secret: string }>`).
4. **Claim:** The publishable key is delivered per-intent in the create response. — **VERDICT: Corrected.**
   The publishable key comes from `GET /ui/billing/config` -> `BillingConfig.publishable_key`. Source:
   `src/api/types.ts: BillingConfig` (`publishable_key?: string; currency: string`);
   `src/pages/billing/BillingOverview.tsx` (renders `config.publishable_key`); OpenAPI
   `billing_config_ui_billing_config_get` (`GET /ui/billing/config`).
5. **Claim:** Create request body is `{ amount, currency, intent_context }`. — **VERDICT: Corrected.** The
   real charge request is `StripeChargeReq { amount_cents (required, >=1), payment_method_id?, description?,
   idempotency_key? }` — field is `amount_cents` not `amount`, and there is no `currency` or
   `intent_context`. Source: `openapi.pretty.json: components.schemas.StripeChargeReq` (lines ~70328–70373);
   `src/api/types.ts: StripeChargeReq`.
6. **Claim:** Charge/create response is `{ payment_intent_id, client_secret, publishable_key, status,
   amount, currency }`. — **VERDICT: Corrected.** `chargeOnce` returns `{ status, payment_intent_id }`
   (no client_secret/publishable_key). Source: `src/api/endpoints/billing.ts: chargeOnce`
   (`api.post<{ status: string; payment_intent_id: string }>`).
7. **Claim:** Stripe PaymentIntent `status` enum (`requires_payment_method` … `succeeded` … `canceled`).
   — **VERDICT: Verified (framework ref).** These are canonical Stripe PaymentIntent statuses; framework ref:
   https://docs.stripe.com/payments/paymentintents/lifecycle . The backend echoes a `status` string in
   charge responses (`src/api/endpoints/billing.ts`).
8. **Claim:** Auth is session-based with `ui_csrf` echoed as `X-CSRF-Token`; single
   `POST /ui/session/refresh` on 401 then retry. — **VERDICT: Verified, with correction.** Source:
   `src/api/client.ts` (`getCookie("ui_csrf")` -> `headers.set("X-CSRF-Token", csrf)` on every request;
   `refreshSession()` calls `POST /ui/session/refresh`; 401 path refreshes once and retries). Correction:
   the header is sent on all requests (not only mutating), and the web client also sends `Authorization:
   Bearer` and `X-IMPERSONATION-TOKEN`; OpenAPI lists `user_sub, X-SESSION-ID, X-IMPERSONATION-TOKEN` params
   on `/ui/billing/*`.
9. **Claim:** FastAPI error `detail` shape is `string | [{msg}] | {code,...}`. — **VERDICT: Verified.**
   Source: `src/api/client.ts: normalizeErrorDetail` (handles `string`, `Array<{msg}>`, and `object`);
   `422` responses use `HTTPValidationError` (`{ detail: [{ loc, msg, type }] }`) per `openapi.index.txt`.
10. **Claim:** Checkout is `POST /ui/billing/checkout_session` returning `{ session_id, url }` (relevant to
    AND-227, not in-app PaymentSheet). — **VERDICT: Verified.** Source: OpenAPI
    `create_checkout_session_ui_billing_checkout_session_post` (req `BillingCheckoutReq`);
    `src/api/endpoints/billing.ts: createCheckoutSession` (`{ session_id: string; url: string }`);
    `src/api/types.ts: BillingCheckoutReq { amount_cents, currency?, description? }`.
11. **Claim:** Web reference paths `frontend/src/api/endpoints/billing.ts` and `.../types.ts` exist and own
    the billing shapes. — **VERDICT: Verified.** Files present and read; billing DTOs at `src/api/types.ts`
    lines ~608–771, endpoints at `src/api/endpoints/billing.ts`.
12. **Claim:** Stripe Android SDK `com.stripe:stripe-android` with `PaymentConfiguration.init`,
    `rememberPaymentSheet`, `PaymentSheetResult { Completed | Canceled | Failed }`, and
    `presentWithSetupIntent` / `presentWithPaymentIntent`. — **VERDICT: Verified (framework ref).** Not
    checkable from backend sources; framework refs: https://docs.stripe.com/payments/accept-a-payment?platform=android
    and https://github.com/stripe/stripe-android (PaymentSheet API). The `20.x` version line and minSdk-24
    compatibility (R3) are unverified-assumptions (see below) — pin a tested version at implementation time.
13. **Claim:** Dev backend `http://18.222.237.167:8000`, plaintext HTTP, OpenAPI at `/openapi.json`. —
    **VERDICT: Unverified-assumption.** Host/port not derivable from the provided reference files; carried
    from the draft. Cleartext-in-dev security caveat (§8/R1) is sound regardless.
14. **Claim:** AND-223 provides `BillingApi`, `ApiResult<T>`, billing DTOs that AND-225 extends. — **VERDICT:
    Unverified-assumption (cross-ticket).** Not present in this repo snapshot; an inter-ticket contract.

### Corrections made

- **C1 (frontmatter):** `status: draft` -> `status: reviewed`; added `reviewed_on: 2026-06-06`.
- **C2 (§2 web reference):** documented that the publishable key comes from `GET /ui/billing/config` and
  that `client_secret` only comes from the SetupIntent endpoint; charge endpoints return only
  `{ status, payment_intent_id }`.
- **C3 (§2 auth):** corrected CSRF to apply on every request; noted Bearer/impersonation headers and the
  `user_sub`/`X-SESSION-ID` params.
- **C4 (§5):** removed the non-existent `POST/GET /ui/billing/payment_intents`; replaced with the verified
  endpoint table, the SetupIntent-vs-PaymentIntent gap, corrected request (`amount_cents`) and response
  (`{ status, payment_intent_id }`) shapes, and corrected Moshi DTOs + Retrofit signatures.
- **C5 (§4):** added a banner mapping the illustrative `createPaymentIntent`/`presentWithPaymentIntent`
  code to the verified `createCardSetupIntent`/`presentWithSetupIntent` surface.
- **C6 (§6):** corrected publishable-key source from BuildConfig-authoritative to
  `GET /ui/billing/config`-authoritative (BuildConfig is fallback only).
- **C7 (§11):** added correction banner aligning the testing surface with §5.
- **C8 (§13 R2):** marked resolved — endpoints verified absent; documented the backend dependency for a true
  PaymentIntent client-secret.
- **C9 (§14):** reworded AC-3/AC-4/AC-5 to the verified SetupIntent/charge contract while preserving IDs.

### Open assumptions

- **OA1 — True PaymentIntent round-trip:** no backend endpoint currently returns a PaymentIntent
  `client_secret`, so `presentWithPaymentIntent` cannot be exercised end-to-end today. AND-225's provable
  round-trip uses the SetupIntent path; the PaymentIntent variant depends on a not-yet-existing backend
  endpoint. (Source of gap: #1, #2, #3 above.)
- **OA2 — Stripe SDK version vs minSdk 24 / Kotlin 2.0.21 / KSP / AGP 8.7.3 (R3):** the `20.x` line claim
  is unverified against the toolchain; pin a tested version. Framework-only, not in sources.
- **OA3 — Dev host / base URL / HTTPS prod timeline (R1):** not derivable from sources (#13); confirm
  externally.
- **OA4 — AND-223 deliverables (`BillingApi`, `ApiResult`):** cross-ticket assumption not present in this
  snapshot (#14).
- **OA5 — Merchant display name `"TestLogon"` and analytics event schema (§10):** app-side conventions, not
  verifiable from backend/web sources.

## 17. Test Plan

Test targets: **JVM** = JVM unit/Robolectric (local, no device); **emu35** = headless emulator AVD `test35`
(x86_64, Android 15 / API 35); **A15** = physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a, serial
R5CX821TA9R). Cases that drive PaymentSheet's real card UI, SCA/3DS, or that must validate arm64/API-34
behavior are marked **MUST run on A15**.

- **TC-AND-225-01 — PaymentConfiguration initialized exactly once (concurrent).**
  Type: unit. Target: JVM. Preconditions: `PaymentConfigProvider.publishableKey()` returns a non-blank
  `pk_test_...`; `PaymentConfiguration.init` is wrapped/mockable. Steps: invoke
  `StripeInitializer.ensureInitialized()` from N concurrent threads. Expected: `PaymentConfiguration.init`
  invoked exactly once; `isInitialized()` true; no exception. Traces: AC-2.

- **TC-AND-225-02 — Publishable key sourced from `GET /ui/billing/config`.**
  Type: contract/MockWebServer. Target: JVM. Preconditions: MockWebServer enqueues
  `200 {"publishable_key":"pk_test_x","currency":"usd"}`. Steps: call `getBillingConfig()` via the Retrofit
  `BillingApi`; resolve `PaymentConfigProvider.publishableKey()`. Expected: request hits
  `GET /ui/billing/config`; provider returns `pk_test_x`; no BuildConfig fallback used. Traces: AC-2, AC-3.

- **TC-AND-225-03 — SetupIntent client_secret happy path (service mapping).**
  Type: contract/MockWebServer. Target: JVM. Preconditions: MockWebServer enqueues
  `200 {"client_secret":"seti_1Q_secret_abc"}` for `POST /ui/billing/setup-intent/card`. Steps: call the
  service method that brokers `createCardSetupIntent()`. Expected: `ApiResult.Success` with non-blank
  `client_secret`; request path/method correct; `X-CSRF-Token` header present. Traces: AC-3.

- **TC-AND-225-04 — Charge-once request/response shape (verified fields).**
  Type: contract/MockWebServer. Target: JVM. Preconditions: enqueue `200 {"status":"succeeded",
  "payment_intent_id":"pi_3Q"}`. Steps: call `chargeOnce(StripeChargeRequest(amountCents=500,
  paymentMethodId="pm_1"))`. Expected: serialized body uses `amount_cents` (not `amount`), contains no
  `currency`/`intent_context`; response maps to `status="succeeded"`, `paymentIntentId="pi_3Q"`. Traces:
  AC-3, AC-5.

- **TC-AND-225-05 — DTO Moshi round-trip for billing shapes.**
  Type: unit. Target: JVM. Preconditions: fixture JSON copied from web reference shapes. Steps: serialize
  `StripeChargeRequest` and parse `BillingConfigDto` / `SetupIntentDto` / `ChargeResultDto`. Expected:
  field-name mapping (`amount_cents`, `payment_intent_id`, `client_secret`, `publishable_key`) round-trips;
  nullable fields tolerate absence. Traces: AC-3, AC-8.

- **TC-AND-225-06 — PaymentSheetResult mapping.**
  Type: unit. Target: JVM. Preconditions: none. Steps: map
  `PaymentSheetResult.{Completed, Canceled, Failed(error)}` via `toPaymentResult()`. Expected: ->
  `PaymentResult.{Completed, Canceled, Failed(message, error)}`; no crash on `Failed`. Traces: AC-4, AC-6.

- **TC-AND-225-07 — Not-initialized guard does not crash.**
  Type: unit. Target: JVM. Preconditions: `publishableKey()` returns blank/invalid so
  `PaymentConfiguration.init` throws. Steps: call `paymentSheetConfig()` (which calls
  `ensureInitialized()`). Expected: `IllegalStateException` is caught and converted to
  `PaymentResult.Failed("Payment is not available")`; process does not crash. Traces: AC-6.

- **TC-AND-225-08 — Create failure on flaky dev host (5xx/timeout) is typed, POST not retried.**
  Type: contract/MockWebServer. Target: JVM. Preconditions: MockWebServer returns `503` then a delayed
  body to simulate timeout for `POST /ui/billing/setup-intent/card`. Steps: invoke the create flow.
  Expected: result is `ApiResult.Failure` (typed, non-fatal); the POST is **not** auto-retried (single
  request observed); no `PaymentResult` emitted. Traces: AC-6.

- **TC-AND-225-09 — 422 validation error mapped via FastAPI detail shapes.**
  Type: contract/MockWebServer. Target: JVM. Preconditions: enqueue `422 {"detail":[{"loc":["body",
  "amount_cents"],"msg":"ensure this value is greater than or equal to 1","type":"value_error"}]}`. Steps:
  call `chargeOnce(amountCents=0)`. Expected: typed failure with a user-facing message derived from
  `detail[].msg`; raw JSON never surfaced. Traces: AC-6.

- **TC-AND-225-10 — 401 triggers single session refresh then retry.**
  Type: contract/MockWebServer. Target: JVM. Preconditions: enqueue `401`, then `200` for
  `POST /ui/session/refresh`, then `200` for the original call. Steps: invoke a billing call. Expected:
  exactly one `POST /ui/session/refresh`; original request retried once and succeeds; no infinite loop.
  Traces: AC-3.

- **TC-AND-225-11 — No client_secret / card data / publishable key in logs.**
  Type: unit. Target: JVM. Preconditions: capture logger output; run create + present + result flow with a
  fake `seti_..._secret_...`. Steps: assert captured logs. Expected: logs contain at most
  `payment_intent_id`/`status`; never `client_secret`, publishable key, PAN/CVV. Traces: AC-7.

- **TC-AND-225-12 — Launcher registered at screen root presents and returns a result (Compose-UI).**
  Type: Compose-UI. Target: emu35 (CI). Preconditions: test host with
  `rememberStripePaymentLauncher`; Stripe SDK in a stubbed/test mode so PaymentSheet can be dismissed.
  Steps: compose the host, trigger `present(clientSecret, config)`, dismiss the sheet. Expected: sheet
  registers before STARTED (no lifecycle/registry crash), and a dismissal maps to
  `PaymentResult.Canceled`. Traces: AC-4, AC-6.

- **TC-AND-225-13 — End-to-end SetupIntent round-trip with test card `4242 4242 4242 4242`.**
  Type: instrumented/e2e. Target: **A15 (MUST run on physical device).** Preconditions: dev backend
  reachable; valid `pk_test_...` from `GET /ui/billing/config`; debug smoke screen. Steps: create SetupIntent
  via `POST /ui/billing/setup-intent/card`; present PaymentSheet (`presentWithSetupIntent`); enter
  `4242 4242 4242 4242`, exp future, any CVC/ZIP; confirm. Expected: `PaymentResult.Completed`; the saved
  method appears in `GET /ui/billing/payment-methods` (server-authoritative). Rationale for A15: drives the
  real PaymentSheet card UI/IME on arm64/API-34. Traces: AC-3, AC-4, AC-5. (Gated: manual/nightly per §11
  due to dev-host/Stripe-network reliability.)

- **TC-AND-225-14 — Offline/no-network during create surfaces typed failure.**
  Type: instrumented. Target: A15 (airplane mode) or emu35 (disabled radio). Preconditions: network off.
  Steps: trigger create flow. Expected: `ApiResult.Failure` (network), PaymentSheet never presented, caller
  can re-try; no crash. A15 preferred to validate real radio-off behavior. Traces: AC-6.

- **TC-AND-225-15 — PaymentSheet accessibility (TalkBack) and dark-theme handoff.**
  Type: manual + Compose-UI assertions. Target: **A15 (MUST run on physical device for TalkBack).**
  Preconditions: TalkBack enabled; system dark theme on. Steps: open PaymentSheet, traverse fields with
  TalkBack; toggle dark mode. Expected: Stripe-provided labels/focus order are announced; sheet honors the
  Material 3 dark theme; app-side strings (merchant name, error copy) come from `strings.xml`. Traces: AC-4.

### Coverage matrix

| Acceptance criterion | Covered by |
| --- | --- |
| AC-1 (SDK added, builds on compileSdk 35 / JDK 17 / AGP 8.7.3) | Build/CI (TC-AND-225-13 exercises the assembled APK on device); no isolated TC — verified by green CI build |
| AC-2 (init exactly once, key from config) | TC-AND-225-01, TC-AND-225-02 |
| AC-3 (service yields non-blank client_secret) | TC-AND-225-02, TC-AND-225-03, TC-AND-225-04, TC-AND-225-05, TC-AND-225-10, TC-AND-225-13 |
| AC-4 (PaymentSheet + `4242` -> Completed) | TC-AND-225-06, TC-AND-225-12, TC-AND-225-13, TC-AND-225-15 |
| AC-5 (server-authoritative confirmation) | TC-AND-225-04, TC-AND-225-13 |
| AC-6 (Canceled/Failed/not-initialized map, no crash) | TC-AND-225-06, TC-AND-225-07, TC-AND-225-08, TC-AND-225-09, TC-AND-225-12, TC-AND-225-14 |
| AC-7 (no card data / client_secret in logs) | TC-AND-225-11 |
| AC-8 (unit tests pass in CI) | TC-AND-225-01, TC-AND-225-04, TC-AND-225-05, TC-AND-225-06, TC-AND-225-07 |
