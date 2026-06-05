---
id: AND-225
title: Stripe Android SDK integration
milestone: M5
epic: E31
priority: P0
size: M
status: draft
depends_on: [AND-223]
blocks: [AND-226, AND-227, AND-236]
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
- **Auth:** cookie-based session with `ui_csrf` echoed as `X-CSRF-Token`; persistent cookie jar;
  single `POST /ui/session/refresh` retry on 401. All `/ui/billing/*` calls ride this session.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext HTTP,
  unreliable). OpenAPI at `/openapi.json`. Error `detail` is `string | [{msg}] | {code,...}`.
- **Upstream dependency — AND-223 (Billing API + DTOs):** provides `BillingApi` (Retrofit),
  `core-model` billing DTOs, and `ApiResult<T>` mapping. AND-225 **consumes** these; it adds only the
  PaymentIntent-specific request/response DTOs if AND-223 has not already defined them (see §5).
- **Web reference:** `frontend/src/api/endpoints/billing.ts` and `frontend/src/api/types.ts` for the
  canonical `/ui/billing/*` payload shapes and Stripe field names (`client_secret`,
  `publishable_key`, `payment_intent_id`, `status`).
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

PaymentIntents are created **server-side** (the publishable key alone cannot create them; the secret
key lives on the backend). The app calls the backend, which calls Stripe. Endpoints below align with
`frontend/src/api/endpoints/billing.ts`; verify exact paths against `/openapi.json` at implementation
time and defer canonical DTO ownership to AND-223 where overlap exists.

**Create PaymentIntent — `POST /ui/billing/payment_intents`**

Request:
```json
{ "amount": 500, "currency": "usd", "intent_context": { "kind": "test", "description": "AND-225 smoke" } }
```
Response `200`:
```json
{
  "payment_intent_id": "pi_3Q...",
  "client_secret": "pi_3Q..._secret_abc",
  "publishable_key": "pk_test_...",
  "status": "requires_payment_method",
  "amount": 500,
  "currency": "usd"
}
```

**Fetch PaymentIntent — `GET /ui/billing/payment_intents/{payment_intent_id}`**

Response `200`:
```json
{ "payment_intent_id": "pi_3Q...", "status": "succeeded", "amount": 500, "currency": "usd" }
```

Headers: session cookies + `X-CSRF-Token: <ui_csrf>` on the POST (mutating). On `401`, the OkHttp
authenticator (from auth foundation) performs one `POST /ui/session/refresh` and retries.

**DTOs (Moshi):**
```kotlin
@JsonClass(generateAdapter = true)
data class CreatePaymentIntentRequest(
    val amount: Long,
    val currency: String,
    @Json(name = "intent_context") val intentContext: Map<String, Any?>? = null,
)

@JsonClass(generateAdapter = true)
data class PaymentIntentDto(
    @Json(name = "payment_intent_id") val paymentIntentId: String,
    @Json(name = "client_secret") val clientSecret: String? = null,
    @Json(name = "publishable_key") val publishableKey: String? = null,
    val status: String,
    val amount: Long? = null,
    val currency: String? = null,
)
```

**Retrofit (extends AND-223 `BillingApi`):**
```kotlin
@POST("ui/billing/payment_intents")
suspend fun createPaymentIntent(@Body body: CreatePaymentIntentRequest): Response<PaymentIntentDto>

@GET("ui/billing/payment_intents/{id}")
suspend fun getPaymentIntent(@Path("id") id: String): Response<PaymentIntentDto>
```

`status` values follow Stripe: `requires_payment_method`, `requires_confirmation`, `requires_action`,
`processing`, `succeeded`, `canceled`. Treat `succeeded` as terminal-paid; `requires_action` means
PaymentSheet must finish 3DS (handled in-sheet).

## 6. Data & State Management

- **No Room persistence** in this ticket — PaymentIntents are ephemeral and server-authoritative;
  caching a `client_secret` is a security anti-pattern. The Room cache layer is N/A here.
- **Initialization flag:** `StripeInitializer.initialized` is in-memory only (`@Volatile`),
  re-established each process start. Idempotent and thread-safe via double-checked locking.
- **Publishable key:** read from `BuildConfig.STRIPE_PUBLISHABLE_KEY` (default provider). A
  DataStore-backed override may supply a backend-issued `publishable_key` later; for AND-225 the
  BuildConfig value is sufficient and the `publishable_key` returned by the create endpoint is the
  authoritative source if present.
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
- **R2 — Backend PaymentIntent endpoint shape:** exact path/field names may differ from web reference.
  Mitigation: verify against `/openapi.json`; keep DTOs tolerant (nullable fields). Open: does the
  backend echo `publishable_key` per-intent or is BuildConfig authoritative?
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

AC-3. `StripePaymentService.createPaymentIntent(...)` returns an `ApiResult.Success<PaymentIntentDto>`
containing a non-blank `client_secret` for a valid request against the dev backend (test mode).

AC-4. Presenting `PaymentSheet` with that `client_secret` and entering Stripe test card
`4242 4242 4242 4242` yields `PaymentResult.Completed`.

AC-5. `fetchPaymentIntent(id)` after completion returns `status == "succeeded"` (server-authoritative
confirmation of the test PaymentIntent).

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
