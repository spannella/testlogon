---
id: AND-226
title: Add card (Stripe)
milestone: M5
epic: E31
priority: P0
size: M
status: draft
depends_on: [AND-225]
blocks: [AND-227]
---

# AND-226 — Add card (Stripe)

## 1. Overview & Goal

Enable an authenticated TestLogon user to add a payment card to their account using Stripe in **test mode**, and have that card appear in the user's list of saved payment methods. This ticket builds directly on the Stripe Android SDK bootstrap delivered in AND-225 (SDK dependency, `PaymentConfiguration` init, and the generic PaymentSheet/PaymentIntent confirmation plumbing).

The functional outcome required by the backlog acceptance criterion is: **"Card adds + appears in methods (test mode)."** Concretely, the user opens an "Add card" entry point from the billing/payment-methods surface, the app obtains a Stripe **SetupIntent** client secret from the FastAPI backend, presents Stripe's hosted card-collection UI (PaymentSheet in setup mode), confirms the SetupIntent (which attaches the resulting `PaymentMethod` to the customer), and on success refreshes the saved-methods list so the new card (brand + last4 + expiry) is shown.

A `SetupIntent` (not a `PaymentIntent`) is the correct primitive here: we are saving a card for future use, not charging it. AND-227 (Checkout session billing) owns the actual purchase/charge flow and reuses the saved methods produced by this ticket. This spec covers card *attach* only; it does not cover charging, default-card selection, or card deletion (out of scope; see §13).

## 2. Context & References

- **Repo / branch:** `spannella/testlogon`, Android app under `android/`, branch `android-port`.
- **Namespace:** `com.testlogon.android` (applicationId base and Kotlin package root).
- **Module placement:** new code lives in `feature-billing` (UI + ViewModel) and `core-data` (repository + DTOs), networking via `core-network`. Layering `app -> feature-billing -> core-*` is preserved; `feature-billing` must not depend on other `feature-*` modules.
- **Upstream dependency — AND-225:** provides the Stripe Android SDK Gradle dependency (`com.stripe:stripe-android`), `PaymentConfiguration.init(context, publishableKey)` at app startup, and a thin wrapper exposing `PaymentSheet`/`PaymentSheet.FlowController` plus `rememberPaymentSheet`. AND-226 consumes those; it must not re-declare the SDK or re-init configuration.
- **Downstream dependency — AND-227:** consumes the saved `PaymentMethod` list and the customer/billing identity established here.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext HTTP, unreliable). OpenAPI at `/openapi.json`. Billing/Stripe endpoints are under the `/ui/billing/*` namespace (sibling to `/ui/billing/checkout_session` referenced by AND-227). Web reference: `frontend/src/api/endpoints/*.ts` and `frontend/src/api/types.ts`.
- **Auth:** cookie-based session with `ui_csrf` cookie echoed as `X-CSRF-Token`; persistent cookie jar; single `/ui/session/refresh` retry on 401 (all provided by `core-network` from earlier milestones). All `/ui/billing/*` calls are authenticated and CSRF-protected.
- **Stripe docs primitive:** SetupIntent + PaymentSheet (setup mode). Publishable key is a Stripe **test** key (`pk_test_...`); the app never sees the secret key.

## 3. Functional Requirements

FR-1. From the Payment Methods screen there is a visible, enabled **"Add card"** action (button) when a session is active.

FR-2. Activating "Add card" triggers a backend call to create a SetupIntent and return its `client_secret` and the ephemeral Customer context needed by PaymentSheet (customer id + ephemeral key secret).

FR-3. The app presents Stripe **PaymentSheet** in setup mode using the returned client secret. The app does **not** build or render any raw card-number/CVC input fields itself — card data is collected exclusively by the Stripe SDK (PCI scope minimization).

FR-4. On PaymentSheet success the SetupIntent is confirmed and the `PaymentMethod` is attached to the customer server-side by Stripe.

FR-5. After a successful attach, the app refreshes the saved payment-methods list via the backend and the newly added card appears with **brand**, **last4**, and **exp month/year**.

FR-6. PaymentSheet **cancellation** returns the user to the Payment Methods screen unchanged, with no error surfaced.

FR-7. PaymentSheet **failure** (declined test card, network error, SDK error) surfaces a non-fatal, dismissible error and leaves the methods list unchanged. The "Add card" action remains usable for retry.

FR-8. While the SetupIntent is being created and while the post-success refresh runs, the UI shows a loading/disabled state preventing duplicate submissions.

FR-9. Test-mode only: the feature is validated with Stripe test cards (`4242 4242 4242 4242` success; `4000 0000 0000 0002` decline; `4000 0025 0000 3155` 3DS authentication required).

## 4. Technical Design

### 4.1 Package layout
```
com.testlogon.android.feature.billing
  ├─ methods/PaymentMethodsScreen.kt
  ├─ methods/PaymentMethodsViewModel.kt
  ├─ methods/PaymentMethodsUiState.kt
  └─ addcard/AddCardController.kt           // PaymentSheet glue
com.testlogon.android.core.data.billing
  ├─ BillingRepository.kt
  ├─ BillingRepositoryImpl.kt
  └─ dto/ (SetupIntentDto, PaymentMethodDto, ...)
com.testlogon.android.core.network.billing
  └─ BillingApi.kt                          // Retrofit interface
```

### 4.2 UiState (StateFlow contract)
```kotlin
data class PaymentMethodsUiState(
    val methods: List<PaymentMethod> = emptyList(),
    val isLoadingMethods: Boolean = false,
    val isPreparingAddCard: Boolean = false,   // SetupIntent create in-flight
    val addCardConfig: AddCardConfig? = null,   // one-shot trigger for PaymentSheet
    val errorMessage: String? = null,           // transient, dismissible
    val isStale: Boolean = false                // showing cached methods (offline)
)

data class AddCardConfig(
    val setupIntentClientSecret: String,
    val customerId: String,
    val ephemeralKeySecret: String,
    val publishableKey: String
)
```

### 4.3 Domain model (`core-model`)
```kotlin
data class PaymentMethod(
    val id: String,            // pm_...
    val brand: String,         // "visa", "mastercard", ...
    val last4: String,         // "4242"
    val expMonth: Int,
    val expYear: Int,
    val isDefault: Boolean
)
```

### 4.4 ViewModel
```kotlin
@HiltViewModel
class PaymentMethodsViewModel @Inject constructor(
    private val repo: BillingRepository
) : ViewModel() {
    val uiState: StateFlow<PaymentMethodsUiState>

    fun loadMethods()                 // idempotent GET, retried w/ backoff
    fun onAddCardClicked()            // -> createSetupIntent, emits addCardConfig
    fun onAddCardConfigConsumed()     // clears one-shot config after launch
    fun onPaymentSheetResult(result: PaymentSheetResult)
    fun onErrorDismissed()
}
```

`onAddCardClicked()` sets `isPreparingAddCard = true`, calls `repo.createSetupIntent()`, and on `ApiResult.Success` emits a non-null `addCardConfig` (plus publishable key from `PaymentConfiguration`/build config). On failure it sets `errorMessage`.

### 4.5 PaymentSheet integration (Compose)
The screen uses the AND-225 wrapper `rememberPaymentSheet { result -> viewModel.onPaymentSheetResult(result) }`. A `LaunchedEffect(uiState.addCardConfig)` consumes the one-shot config and presents the sheet in **setup mode**:
```kotlin
LaunchedEffect(uiState.addCardConfig) {
    val cfg = uiState.addCardConfig ?: return@LaunchedEffect
    PaymentConfiguration.init(context, cfg.publishableKey)
    paymentSheet.presentWithSetupIntent(
        setupIntentClientSecret = cfg.setupIntentClientSecret,
        configuration = PaymentSheet.Configuration.Builder("TestLogon")
            .customer(PaymentSheet.CustomerConfiguration(cfg.customerId, cfg.ephemeralKeySecret))
            .allowsDelayedPaymentMethods(false)
            .build()
    )
    viewModel.onAddCardConfigConsumed()
}
```
`onPaymentSheetResult` maps `PaymentSheetResult.Completed -> loadMethods()` (refresh + clear loading), `Canceled -> clear preparing state silently`, `Failed(e) -> errorMessage`.

### 4.6 Repository
```kotlin
interface BillingRepository {
    suspend fun createSetupIntent(): ApiResult<SetupIntentSession>
    suspend fun getPaymentMethods(): ApiResult<List<PaymentMethod>>
}
```
`createSetupIntent` is a non-idempotent POST → **no automatic retry**. `getPaymentMethods` is a GET → bounded backoff retry (see §7). DTO→domain mapping lives in the impl; results cached to Room.

## 5. API Contract

All endpoints under base `http://18.222.237.167:8000`, authenticated via session cookies + `X-CSRF-Token`. Exact paths confirmed against `/openapi.json` before implementation; assumed shapes below match the `/ui/billing/*` convention used by AND-227.

### 5.1 Create SetupIntent
`POST /ui/billing/setup_intent`
Request body: `{}` (customer derived from session).
Response `200`:
```json
{
  "setup_intent_client_secret": "seti_1Q..._secret_abc",
  "customer_id": "cus_QabcXyz",
  "ephemeral_key_secret": "ek_test_abc123",
  "publishable_key": "pk_test_51..."
}
```

### 5.2 List payment methods
`GET /ui/billing/payment_methods`
Response `200`:
```json
{
  "payment_methods": [
    { "id": "pm_1Q...", "brand": "visa", "last4": "4242",
      "exp_month": 12, "exp_year": 2030, "is_default": true }
  ]
}
```

### 5.3 Retrofit interface
```kotlin
interface BillingApi {
    @POST("ui/billing/setup_intent")
    suspend fun createSetupIntent(): SetupIntentResponseDto

    @GET("ui/billing/payment_methods")
    suspend fun getPaymentMethods(): PaymentMethodsResponseDto
}
```

### 5.4 Error envelope
FastAPI `detail` mapped by the shared `core-network` error mapper to typed `ApiError`: `detail` may be `string`, `[{ "msg": "...", "loc": [...] }]`, or `{ "code": "...", ... }`. Stripe-originated failures returned by the backend (e.g. customer creation failure) arrive as `4xx` with a `detail` string surfaced verbatim to telemetry and a generic user-facing message.

## 6. Data & State Management

- **Source of truth:** `BillingRepository`. The ViewModel holds only derived `PaymentMethodsUiState`.
- **Cache (Room 2.6):** `PaymentMethodEntity` table keyed by `id`. `getPaymentMethods()` emits cache-first then refreshes from network; on network failure with non-empty cache, `isStale = true` and cached rows are shown. This satisfies the offline/stale requirement for the unreliable dev host.
- **No persistence of secrets:** `setup_intent_client_secret`, `ephemeral_key_secret`, and `publishable_key` live only in transient `AddCardConfig` in `UiState` memory and are cleared via `onAddCardConfigConsumed()` immediately after the sheet is presented. They are never written to Room or DataStore.
- **One-shot events:** `addCardConfig` and `errorMessage` are nullable and explicitly cleared after consumption to avoid re-presenting PaymentSheet or re-showing an error on recomposition / config change.
- **Refresh trigger:** a successful `PaymentSheetResult.Completed` is the only path that mutates the methods list; the list is refreshed from the backend (which reflects Stripe's authoritative attach) rather than optimistically inserted, because brand/last4/expiry come from Stripe.

## 7. Error Handling & Resilience

- **Timeouts:** OkHttp call timeout ~20s (inherited from `core-network` for the dev host).
- **Retries:** `getPaymentMethods` (idempotent GET) uses bounded exponential backoff (e.g. 3 attempts, 0.5s→2s, jitter). `createSetupIntent` (POST) is **not** retried automatically to avoid orphan SetupIntents; the user retries via the button.
- **401 handling:** transparent single `POST /ui/session/refresh` + retry, provided by the network layer; on refresh failure the user is routed to re-auth.
- **PaymentSheet results:**
  - `Completed` → refresh methods.
  - `Canceled` → silent; clear `isPreparingAddCard`.
  - `Failed(error)` → set `errorMessage` (mapped: declined card → "Your card was declined.", network → "Network error, please retry.", else → generic), log cause.
- **Duplicate-submit guard:** while `isPreparingAddCard` is true the "Add card" button is disabled.
- **3DS / authentication-required test card:** handled entirely inside PaymentSheet; the app only observes the final `PaymentSheetResult`.
- **Empty/missing fields in DTO:** defensive mapping; a method missing `last4`/`exp_*` is logged and skipped rather than crashing the list.

## 8. Security & Privacy

- **PCI scope:** raw PAN/CVC are never touched by app code; collection is delegated to the Stripe SDK. No card fields are logged, screenshotted, or persisted.
- **Keys:** only the Stripe **publishable test key** reaches the client (from backend or `BuildConfig`); the secret key stays server-side. Ephemeral key secret is short-lived, kept in memory only, and scoped to PaymentSheet.
- **Transport:** dev host is plaintext HTTP (known limitation); production must enforce HTTPS + certificate handling. SetupIntent client secrets transit this channel — flagged as an open risk (§13) inherent to the dev environment, not introduced by this ticket.
- **CSRF:** all `/ui/billing/*` mutations carry `X-CSRF-Token`; the persistent cookie jar supplies the session.
- **Logging redaction:** client secrets, ephemeral keys, and `pm_`/`seti_`/`cus_` ids are redacted (or hashed) before any log/telemetry emission.

## 9. Accessibility & i18n

- "Add card" button has a content description and a minimum 48dp touch target (Material 3).
- Loading state announces via `Modifier.semantics { stateDescription = "Adding card" }`; success/failure announced through a `Snackbar` (live region).
- Payment-method rows expose a single combined semantics label: e.g. "Visa ending in 4242, expires 12/2030".
- All app-owned strings (button label, error messages, list labels) live in `strings.xml` for localization; no hardcoded user-facing text. Stripe PaymentSheet provides its own localized UI.
- Brand/last4/expiry formatting uses locale-aware `String.format`/resource templates; expiry rendered as `MM/yyyy`.

## 10. Telemetry & Logging

Events (via `core-data` analytics abstraction; ids redacted per §8):
- `billing_add_card_started` — user tapped Add card.
- `billing_setup_intent_created` — backend returned client secret (latency ms).
- `billing_add_card_completed` — PaymentSheet `Completed`, plus refreshed method count.
- `billing_add_card_canceled` — PaymentSheet `Canceled`.
- `billing_add_card_failed` — `Failed`/API error, with mapped error category (declined | network | api | sdk).
- `billing_methods_loaded` — list load, `count`, `from_cache: Boolean`.

Logging at `DEBUG` for request lifecycle (no secrets), `WARN`/`ERROR` for failures with redacted Stripe identifiers and the backend `detail` category.

## 11. Testing Strategy

**Unit (core-testing, JUnit + Turbine + MockWebServer):**
- `PaymentMethodsViewModelTest`: `onAddCardClicked` success emits `addCardConfig` + clears `isPreparingAddCard`; failure emits `errorMessage`.
- `onPaymentSheetResult(Completed)` triggers `loadMethods`; `Canceled` is silent; `Failed` maps to correct `errorMessage` category.
- `BillingRepositoryImplTest`: DTO→domain mapping (brand/last4/exp); GET retry/backoff; POST not retried; 401→refresh; cache-first + `isStale` on network failure; defensive skip of malformed method.
- Error-envelope mapping (string / list / object `detail`).

**Instrumented / UI (Compose test rule):**
- Add-card button disabled while `isPreparingAddCard`.
- After a stubbed `Completed` result + stubbed refresh returning a new card, the card row appears with brand+last4+expiry (covers the acceptance criterion).
- Error snackbar shown and dismissible on `Failed`; list unchanged.
- PaymentSheet itself is wrapped/faked at the controller boundary (no real Stripe UI in CI).

**Manual / test-mode E2E (acceptance):**
- Real Stripe test mode: add `4242...` → card appears in methods list. Decline `4000...0002` → error, list unchanged. `4000...3155` → 3DS completes → card appears.

## 12. Dependencies & Sequencing

- **Depends on AND-225** (P0): Stripe SDK present, `PaymentConfiguration` init, PaymentSheet wrapper, publishable test key plumbing. Hard blocker — cannot start UI integration without the SDK wiring.
- **Blocks AND-227** (Checkout session billing): the saved `PaymentMethod` list and customer context produced here are reused by the checkout/charge flow.
- **Backend prerequisite:** `/ui/billing/setup_intent` and `/ui/billing/payment_methods` endpoints must exist and be confirmed in `/openapi.json`. If absent, coordinate with backend; until then mock via MockWebServer for client-side dev.
- **Shared infra:** cookie jar, CSRF interceptor, `ApiResult`, error mapper, Room (`core-network`/`core-data`) — all pre-existing.

## 13. Risks & Open Questions

- **R1 — Endpoint shape unverified:** assumed `/ui/billing/setup_intent` request/response. Mitigation: validate against `/openapi.json` and `frontend/src/api/endpoints` before coding; adjust DTOs.
- **R2 — Plaintext HTTP dev host** transmits Stripe client secrets and ephemeral keys. Acceptable only for the test-mode dev environment; production must use HTTPS. Tracked as environment-level, not blocking this ticket.
- **R3 — Unreliable dev host** may fail `setup_intent` creation intermittently; mitigated by clear retryable error UX (no auto-retry on the POST).
- **R4 — Ephemeral key lifetime:** if the backend does not return an ephemeral key (customer-less SetupIntent), PaymentSheet `customer(...)` config must be omitted and the saved-card-to-customer attach must be guaranteed server-side. Open: confirm backend creates/links the Stripe Customer to the session user.
- **R5 — Default-card / delete / edit:** explicitly out of scope; needs a follow-up ticket.
- **Q1:** Does the backend return `publishable_key` per-request, or is it a static `BuildConfig`/remote-config value? (Affects `AddCardConfig` source.)
- **Q2:** Are multiple cards allowed per user, and is there a default-selection concept the methods list must surface now vs. later?

## 14. Acceptance Criteria

AC-1. In Stripe **test mode**, completing the Add-card flow with `4242 4242 4242 4242` results in the new card appearing in the Payment Methods list with correct brand, last4 (`4242`), and expiry. (Maps to backlog acceptance: "Card adds + appears in methods (test mode).")
AC-2. The app collects card data only through the Stripe SDK; no raw card input field exists in app-owned code.
AC-3. Tapping "Add card" creates a SetupIntent via `POST /ui/billing/setup_intent` and presents PaymentSheet in setup mode using the returned client secret.
AC-4. PaymentSheet cancellation returns to the methods screen with no error and an unchanged list.
AC-5. A declined test card (`4000 0000 0000 0002`) shows a dismissible error and leaves the list unchanged; the button is usable for retry.
AC-6. The methods list loads cache-first and shows a stale indicator when the network fails but cache exists.
AC-7. No Stripe secrets/ids are persisted or logged unredacted.
AC-8. Unit + Compose UI tests in §11 pass in CI without contacting real Stripe.

## 15. Definition of Done

- Code merged to `android-port` under `feature-billing` / `core-data` / `core-network` with package `com.testlogon.android`, respecting module layering.
- `BillingApi`, `BillingRepository`(+Impl), `PaymentMethodsViewModel`, `PaymentMethodsScreen`, `AddCardController`, DTOs, and Room entity implemented per §4–§6.
- Hilt bindings provided (`BillingRepository`, `BillingApi`) via KSP; builds clean on JDK 17 / AGP 8.7.3 / Gradle 8.9.
- All §11 unit and Compose tests written and green in CI; lint/detekt/ktlint pass.
- Manual test-mode E2E (AC-1, AC-4, AC-5, plus 3DS card) verified and recorded.
- Telemetry events from §10 emitted with redaction verified.
- Strings externalized; accessibility labels present (§9).
- `/openapi.json` endpoint shapes confirmed (or deviations documented and DTOs updated).
- Spec open questions Q1/Q2 and risk R4 resolved or explicitly deferred to AND-227 with a note.
