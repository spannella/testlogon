---
id: AND-226
title: Add card (Stripe)
milestone: M5
epic: E31
priority: P0
size: M
depends_on: [AND-225]
blocks: [AND-227]
status: reviewed
reviewed_on: 2026-06-06
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
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext HTTP, unreliable). OpenAPI at `/openapi.json`. Billing/Stripe endpoints are under the `/ui/billing/*` namespace (sibling to `/ui/billing/checkout_session` referenced by AND-227). **CORRECTED:** the billing sub-paths use **hyphens, not underscores** (`/ui/billing/payment-methods`, `/ui/billing/setup-intent/card`), verified against the OpenAPI index. Web reference: `src/api/endpoints/billing.ts` and `src/api/types.ts` (`PaymentMethod`).
- **IMPORTANT — divergence from web reference (verified):** the web client's "Add card" flow in `src/pages/billing/PaymentMethods.tsx` does **NOT** use Stripe PaymentSheet/SetupIntent. It collects raw card fields in its own dialog and `POST`s them to `POST /ui/billing/payment-methods/card` (`AddCardReq`: `card_number`, `cardholder_name?`, `cvc`, `exp_month`, `exp_year`) — the web code itself notes "In production, this form would use Stripe Elements for PCI-compliant card collection." The `POST /ui/billing/setup-intent/card` endpoint exists and returns only `{ client_secret }`; in the web app it is used by the **bank-account** microdeposit flow, not card add. This ticket deliberately chooses the **SetupIntent + PaymentSheet** path (PCI-scope minimization, native best practice) instead of mirroring the web's raw-PAN POST. Consequence: the backend `setup-intent/card` response does NOT today return `customer_id` / `ephemeral_key_secret` / `publishable_key` — see §5/§13. This is a backend coordination item, not a settled contract.
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
    val setupIntentClientSecret: String,        // from { client_secret } (§5.1)
    val customerId: String?,                    // see note: not returned by backend today
    val ephemeralKeySecret: String?,            // see note: not returned by backend today
    val publishableKey: String                  // from BuildConfig/PaymentConfiguration (AND-225) unless backend supplies it
)
```
> **CORRECTION/ASSUMPTION (§5.1):** the backend `setup-intent/card` response verified today returns **only** `client_secret`. `customerId`/`ephemeralKeySecret` are therefore nullable here and gated on the backend dependency in §13. When null, the PaymentSheet `customer(...)` block is omitted (see §4.5). `publishableKey` comes from the AND-225 `PaymentConfiguration` init / `BuildConfig` (the web app never receives it from this endpoint), unless/until the backend returns it per-request (Q1).

### 4.3 Domain model (`core-model`)
```kotlin
data class PaymentMethod(
    val id: String,            // maps from DTO `payment_method_id` (pm_...)
    val methodType: String,    // "card" | "us_bank_account" (DTO `method_type`)
    val brand: String?,        // optional: absent for bank accounts
    val last4: String?,        // optional
    val expMonth: Int?,        // optional
    val expYear: Int?,         // optional
    val priority: Int,         // DTO `priority`
    val label: String?,        // DTO `label`
    val isDefault: Boolean
)
// NOTE: DTO field is `payment_method_id` (NOT `id`); brand/last4/exp_* are nullable.
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
    val builder = PaymentSheet.Configuration.Builder("TestLogon")
        .allowsDelayedPaymentMethods(false)
    // CORRECTED: only attach CustomerConfiguration when the backend actually
    // returned customerId + ephemeralKeySecret (§5.1 returns only client_secret today).
    if (cfg.customerId != null && cfg.ephemeralKeySecret != null) {
        builder.customer(PaymentSheet.CustomerConfiguration(cfg.customerId, cfg.ephemeralKeySecret))
    }
    paymentSheet.presentWithSetupIntent(
        setupIntentClientSecret = cfg.setupIntentClientSecret,
        configuration = builder.build()
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

All endpoints under base `http://18.222.237.167:8000`, authenticated via session cookies + `X-CSRF-Token` (verified: `src/api/client.ts` reads the `ui_csrf` cookie into the `X-CSRF-Token` header and sends `credentials: include`; it also forwards a `Authorization: Bearer` access token and, when impersonating, `X-IMPERSONATION-TOKEN`). Paths below are **corrected** against the OpenAPI index (hyphenated).

### 5.1 Create SetupIntent (card)
`POST /ui/billing/setup-intent/card`  — **CORRECTED path** (was `POST /ui/billing/setup_intent`).
Verified op: `create_card_setup_intent_ui_billing_setup_intent_card_post`; request `req=` (no body); response `200` / `422:HTTPValidationError`. Customer is derived from the session.
Response `200` (verified shape, web client `createCardSetupIntent` in `src/api/endpoints/billing.ts`):
```json
{ "client_secret": "seti_1Q..._secret_abc" }
```
**CORRECTED / UNVERIFIED-ASSUMPTION:** the previously-claimed fields `setup_intent_client_secret`, `customer_id`, `ephemeral_key_secret`, `publishable_key` are **NOT** returned by this endpoint as it exists today — only `client_secret`. PaymentSheet in setup mode **requires** a `CustomerConfiguration(customerId, ephemeralKeySecret)` to attach the saved method to the customer; the current backend does not supply these. This is an **open backend dependency** (see §13 R4/Q1): either (a) the backend is extended to also return `customer_id` + `ephemeral_key_secret` (+ optionally `publishable_key`), or (b) the SetupIntent is confirmed without a `customer(...)` block and server-side logic must guarantee the resulting `PaymentMethod` is attached to the session user. Do not code DTOs to the rich shape until the backend confirms.

### 5.2 List payment methods
`GET /ui/billing/payment-methods`  — **CORRECTED path** (was `GET /ui/billing/payment_methods`).
Verified op: `list_payment_methods_ui_billing_payment_methods_get`; response `200` / `422`.
Response `200` is a **bare JSON array** (verified: `getPaymentMethods` returns `PaymentMethod[]`), **not** an object wrapper:
```json
[
  { "payment_method_id": "pm_1Q...", "method_type": "card", "brand": "visa",
    "last4": "4242", "exp_month": 12, "exp_year": 2030,
    "priority": 0, "is_default": true, "label": "Visa ••4242" }
]
```
**CORRECTED fields** (verified `PaymentMethod` in `src/api/types.ts`): the id field is `payment_method_id` (not `id`); items also carry `method_type` (e.g. `"card"`, `"us_bank_account"`), `priority` (number), optional `label`, `provider`, `provider_method_id`. `brand`/`last4`/`exp_month`/`exp_year` are **optional** (absent for bank accounts) — mapping must be defensive (§7).

### 5.3 Retrofit interface
```kotlin
interface BillingApi {
    @POST("ui/billing/setup-intent/card")
    suspend fun createCardSetupIntent(): SetupIntentResponseDto   // { client_secret }

    @GET("ui/billing/payment-methods")
    suspend fun getPaymentMethods(): List<PaymentMethodDto>       // bare array, not wrapper
}
```

### 5.4 Error envelope
Verified: every billing endpoint declares `422:HTTPValidationError` for validation failures. The web client (`ApiError` in `src/api/client.ts`) normalizes the FastAPI `detail`, which may be a `string` or the `422` array `[{ "msg": "...", "loc": [...], "type": "..." }]` (`HTTPValidationError`/`ValidationError` schemas). The `core-network` error mapper must handle both `detail: string` and the validation-array form (and, defensively, an object `detail`). Stripe-originated failures returned by the backend arrive as `4xx` with a `detail` string surfaced verbatim to telemetry and a generic user-facing message. **Note:** the raw-card endpoint `POST /ui/billing/payment-methods/card` (`AddCardReq`) is the web's add-card path; this ticket does not use it (PCI scope), but its `422` shape is the same envelope.

## 6. Data & State Management

- **Source of truth:** `BillingRepository`. The ViewModel holds only derived `PaymentMethodsUiState`.
- **Cache (Room 2.6):** `PaymentMethodEntity` table keyed by `id`. `getPaymentMethods()` emits cache-first then refreshes from network; on network failure with non-empty cache, `isStale = true` and cached rows are shown. This satisfies the offline/stale requirement for the unreliable dev host.
- **No persistence of secrets:** the SetupIntent `client_secret` (and, if/when the backend supplies them, `ephemeral_key_secret` and `publishable_key`) live only in transient `AddCardConfig` in `UiState` memory and are cleared via `onAddCardConfigConsumed()` immediately after the sheet is presented. They are never written to Room or DataStore.
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

- **R1 — Endpoint shape (now PARTIALLY VERIFIED):** paths corrected to `POST /ui/billing/setup-intent/card` and `GET /ui/billing/payment-methods` (OpenAPI index + `src/api/endpoints/billing.ts`). The `setup-intent/card` **response is verified to return only `{ client_secret }`** — it does NOT supply `customer_id`/`ephemeral_key_secret`/`publishable_key`. Residual risk: the PaymentSheet setup-mode `customer(...)` config cannot be populated from this endpoint as-is. Mitigation: coordinate backend extension (R4/Q1) before implementing the customer-attach path; until then, present PaymentSheet without `customer(...)`.
- **R2 — Plaintext HTTP dev host** transmits Stripe client secrets and ephemeral keys. Acceptable only for the test-mode dev environment; production must use HTTPS. Tracked as environment-level, not blocking this ticket.
- **R3 — Unreliable dev host** may fail `setup_intent` creation intermittently; mitigated by clear retryable error UX (no auto-retry on the POST).
- **R4 — Ephemeral key / customer (CONFIRMED as a gap):** verified that `setup-intent/card` returns only `client_secret`, so today there is NO ephemeral key. PaymentSheet `customer(...)` config must be omitted (see §4.5) and the saved-card-to-customer attach must be guaranteed server-side. **Hard open item:** confirm the backend creates/links the Stripe Customer to the session user and either (a) returns `customer_id`+`ephemeral_key_secret` from this endpoint, or (b) attaches server-side after confirmation. This is the top integration blocker for AC-1.
- **R5 — Default-card / delete / edit:** explicitly out of scope here, **though the backend DOES expose them** (`POST /ui/billing/payment-methods/default`, `DELETE /ui/billing/payment-methods/{id}`, `POST /ui/billing/payment-methods/priority`) and the web `PaymentMethods.tsx` uses them. Deferred to a follow-up ticket; noted so AND-227 can reuse.
- **Q1 (PARTIALLY ANSWERED):** The backend does NOT return `publishable_key` from `setup-intent/card` today (web app never receives it from the endpoint). Treat the publishable test key as a static `BuildConfig`/`PaymentConfiguration` value from AND-225 unless the backend is extended. Note: `GET /ui/billing/config` exists and may carry client config — confirm with backend whether the publishable key belongs there.
- **Q2:** Are multiple cards allowed per user, and is there a default-selection concept the methods list must surface now vs. later?

## 14. Acceptance Criteria

AC-1. In Stripe **test mode**, completing the Add-card flow with `4242 4242 4242 4242` results in the new card appearing in the Payment Methods list with correct brand, last4 (`4242`), and expiry. (Maps to backlog acceptance: "Card adds + appears in methods (test mode).")
AC-2. The app collects card data only through the Stripe SDK; no raw card input field exists in app-owned code.
AC-3. Tapping "Add card" creates a SetupIntent via `POST /ui/billing/setup-intent/card` (CORRECTED path) and presents PaymentSheet in setup mode using the returned `client_secret`.
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

## 16. Citations & Assumption Audit

Each key technical claim with its VERDICT and SOURCE. Sources are exact pointers: OpenAPI `METHOD /path` (from `reference/openapi.index.txt`) and/or schema name (from `reference/openapi.pretty.json`), or a frontend path, or a framework ref.

1. **Create-SetupIntent endpoint is `POST /ui/billing/setup_intent`.** — **Corrected** → actual path is `POST /ui/billing/setup-intent/card` (hyphens; card-specific). Source: OpenAPI `POST /ui/billing/setup-intent/card` (op `create_card_setup_intent_ui_billing_setup_intent_card_post`); `src/api/endpoints/billing.ts: createCardSetupIntent`.
2. **SetupIntent response contains `setup_intent_client_secret`, `customer_id`, `ephemeral_key_secret`, `publishable_key`.** — **Corrected** → endpoint returns ONLY `{ client_secret }`. Source: `src/api/endpoints/billing.ts: createCardSetupIntent` (`api.post<{ client_secret: string }>`); OpenAPI shows `req=`(none) and no rich response schema. The other three fields are an **Unverified-assumption** / open backend dependency (§13 R4, Q1).
3. **List endpoint is `GET /ui/billing/payment_methods` returning `{ payment_methods: [...] }`.** — **Corrected** → path is `GET /ui/billing/payment-methods` (hyphen) and the body is a **bare array** `PaymentMethod[]`. Source: OpenAPI `GET /ui/billing/payment-methods` (op `list_payment_methods_ui_billing_payment_methods_get`); `src/api/endpoints/billing.ts: getPaymentMethods` (`api.get<PaymentMethod[]>`).
4. **PaymentMethod id field is `id`.** — **Corrected** → field is `payment_method_id`. Source: `src/api/types.ts: PaymentMethod` (`payment_method_id: string`); also used as `method.payment_method_id` throughout `src/pages/billing/PaymentMethods.tsx`.
5. **PaymentMethod carries `brand`, `last4`, `exp_month`, `exp_year`, `is_default`.** — **Verified (with correction):** present, but `brand`/`last4`/`exp_month`/`exp_year` are **optional** (absent for `us_bank_account`); the DTO additionally has `method_type`, `priority`, `label`, `provider`, `provider_method_id`. Source: `src/api/types.ts: PaymentMethod`.
6. **Auth is cookie-session with `ui_csrf` echoed as `X-CSRF-Token`.** — **Verified.** Source: `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`, `credentials: "include"`). Note: client also sends `Authorization: Bearer <accessToken>` and `X-IMPERSONATION-TOKEN` when impersonating; OpenAPI billing params list `user_sub, X-SESSION-ID, X-IMPERSONATION-TOKEN`.
7. **Single `/ui/session/refresh` retry on 401.** — **Verified.** Source: `src/api/client.ts: refreshSession` (`POST /ui/session/refresh`) invoked once on `res.status === 401` then the original request is retried; logout on refresh failure.
8. **All `/ui/billing/*` calls are CSRF-protected mutations carrying `X-CSRF-Token`.** — **Verified** (header set unconditionally when the cookie exists; applies to GET and POST). Source: `src/api/client.ts`.
9. **Error envelope `detail` may be string / validation-array / object.** — **Verified for string + array.** Every billing op declares `422:HTTPValidationError`; the validation form is `[{ msg, loc, type }]` (`HTTPValidationError`/`ValidationError` schemas). `src/api/client.ts: ApiError` + `normalizeErrorDetail` normalize `detail`. The object-`detail` variant is an **Unverified-assumption** (defensive only).
10. **The web "Add card" flow uses Stripe PaymentSheet/SetupIntent.** — **Corrected** → the web flow posts RAW card fields to `POST /ui/billing/payment-methods/card` (`AddCardReq`); it does not use PaymentSheet/SetupIntent for cards. Source: `src/pages/billing/PaymentMethods.tsx` (`addCardMutation` → `addCard(...)`), `src/api/endpoints/billing.ts: addCard`, OpenAPI `POST /ui/billing/payment-methods/card` req=`AddCardReq`. This spec intentionally diverges (native PCI-scope minimization).
11. **`AddCardReq` fields are `card_number`, `cardholder_name?`, `cvc`, `exp_month` (1–12), `exp_year` (2000–2100).** — **Verified.** Source: `openapi.pretty.json components.schemas.AddCardReq`.
12. **Default-card / delete / priority are out of scope and unavailable.** — **Corrected (availability):** out of scope here, but the endpoints DO exist: `POST /ui/billing/payment-methods/default` (`SetDefaultReq`), `DELETE /ui/billing/payment-methods/{payment_method_id}`, `POST /ui/billing/payment-methods/priority` (`SetPriorityReq`). Source: OpenAPI index; `src/api/endpoints/billing.ts` (`setDefault`, `removePaymentMethod`, `setPriority`).
13. **A `SetupIntent` (not `PaymentIntent`) is correct for saving a card.** — **Verified (framework ref):** SetupIntent is Stripe's primitive for saving a card for future use without charging. Source: framework ref https://stripe.com/docs/payments/setup-intents and https://docs.stripe.com/payments/accept-a-payment?platform=android (PaymentSheet setup mode).
14. **PaymentSheet setup mode needs `CustomerConfiguration(customerId, ephemeralKeySecret)` to attach to a customer.** — **Verified (framework ref).** Source: framework ref https://docs.stripe.com/payments/accept-a-payment?platform=android (Mobile Payment Element / `PaymentSheet.CustomerConfiguration`). Combined with claim 2, this is the gap driving §13 R4.
15. **Stripe test cards: `4242 4242 4242 4242` (success), `4000 0000 0000 0002` (decline), `4000 0025 0000 3155` (3DS auth required).** — **Verified (framework ref).** Source: framework ref https://docs.stripe.com/testing.
16. **Dev host `http://18.222.237.167:8000`, plaintext HTTP, OpenAPI at `/openapi.json`.** — **Unverified-assumption** (host/URL not present in the supplied reference artifacts; carried from upstream tickets). Documented as environment config to confirm.
17. **AND-225 provides the Stripe SDK, `PaymentConfiguration.init`, and a PaymentSheet/`rememberPaymentSheet` wrapper.** — **Unverified-assumption** (cross-ticket dependency; not checkable from the backend/frontend sources here). Hard dependency tracked in §12.

### Corrections made
- §2, §5.1, §5.3, AC-3: SetupIntent path `setup_intent` → `setup-intent/card`.
- §2, §5.2, §5.3: list path `payment_methods` → `payment-methods`; response wrapper `{ payment_methods: [...] }` → bare `PaymentMethod[]`.
- §5.1, §4.2, §4.5, §6, §13: SetupIntent response reduced to `{ client_secret }`; `customer_id`/`ephemeral_key_secret`/`publishable_key` flagged as not-returned-today; `AddCardConfig.customerId`/`ephemeralKeySecret` made nullable; PaymentSheet `customer(...)` made conditional.
- §4.3: domain `id` documented as mapping from DTO `payment_method_id`; added `methodType`, `priority`, `label`; made `brand`/`last4`/`exp_*` nullable.
- §2: added explicit note that the web reference uses a raw-PAN POST (`payment-methods/card`), not PaymentSheet — divergence is intentional.
- §13 R1/R4/R5/Q1: updated with verified findings; R5 notes default/delete/priority endpoints exist.

### Open assumptions
- **Backend does not currently return customer/ephemeral-key/publishable-key from `setup-intent/card`** — verified absent from the web contract; whether the backend *can* be extended (or attaches server-side) is unconfirmed (blocks the customer-attach path; §13 R4, Q1). Cannot be resolved from the supplied sources — needs backend owner.
- **Object-form `detail` error body** — handled defensively but not observed in the verified schemas (only string + `422` array confirmed).
- **Dev host URL / plaintext HTTP** — not present in supplied artifacts; carried from upstream.
- **AND-225 deliverables (SDK, `PaymentConfiguration`, PaymentSheet wrapper)** — cross-ticket; unverifiable here.
- **Whether the session user is auto-mapped to a Stripe Customer** — required for AC-1 to succeed; unconfirmed (ties to R4).

## 17. Test Plan

Test target legend (CI/dev): **JVM** = JVM unit/Robolectric (local, no device); **emu35** = headless emulator AVD `test35` (x86_64, Android 15 / API 35); **A15** = physical Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, Android 14 / API 34, arm64-v8a). Stripe runs in **test mode** throughout; no real charges.

- **TC-AND-226-01 — Happy path: SetupIntent created, PaymentSheet succeeds, card appears**
  Type: integration (Compose-UI + fake repo) on emu35. Target: emu35.
  Preconditions: active session; repo stubbed so `createCardSetupIntent` → `client_secret`, PaymentSheet result faked at controller boundary to `Completed`, post-refresh `getPaymentMethods` returns one card (`payment_method_id`, brand `visa`, last4 `4242`, exp 12/2030).
  Steps: open Payment Methods; tap "Add card"; controller emits `Completed`; observe refresh.
  Expected: a row renders "Visa", "•••• 4242", "Expires 12/2030"; loading cleared; no error.
  Traces: AC-1, AC-3.
- **TC-AND-226-02 — Contract: createCardSetupIntent request/response (MockWebServer)**
  Type: contract/MockWebServer. Target: JVM.
  Preconditions: MockWebServer enqueues `200 {"client_secret":"seti_..._secret_..."}`.
  Steps: call `BillingApi.createCardSetupIntent()`.
  Expected: request is `POST /ui/billing/setup-intent/card` with empty/no body, `X-CSRF-Token` header present; DTO parses `client_secret`; no assumption of `customer_id`/`ephemeral_key_secret`/`publishable_key`.
  Traces: AC-3, AC-7.
- **TC-AND-226-03 — Contract: getPaymentMethods parses a BARE ARRAY with optional fields**
  Type: contract/MockWebServer. Target: JVM.
  Preconditions: enqueue `200` with a JSON array containing one `card` (full fields) and one `us_bank_account` (no `brand`/`last4`/`exp_*`).
  Steps: call `BillingApi.getPaymentMethods()`; map to domain.
  Expected: request is `GET /ui/billing/payment-methods`; both items parse; bank item maps with null brand/last4/exp; id taken from `payment_method_id`; `method_type`/`priority`/`label` populated; no crash.
  Traces: AC-1, AC-6.
- **TC-AND-226-04 — Unit: onAddCardClicked success/failure state transitions**
  Type: unit (JUnit + Turbine). Target: JVM.
  Preconditions: fake repo: success returns session; failure returns `ApiResult` error.
  Steps: invoke `onAddCardClicked()` for each case.
  Expected: success → `isPreparingAddCard` toggles true→false and a non-null `addCardConfig` emitted; failure → `errorMessage` set, `isPreparingAddCard` false, no `addCardConfig`.
  Traces: AC-3, AC-5.
- **TC-AND-226-05 — Unit: PaymentSheet result mapping**
  Type: unit. Target: JVM.
  Preconditions: ViewModel with fake repo.
  Steps: feed `Completed`, `Canceled`, `Failed(declined)`, `Failed(network)`, `Failed(other)`.
  Expected: `Completed` → `loadMethods()` invoked; `Canceled` → silent, `isPreparingAddCard` cleared, no error; `Failed` → mapped `errorMessage` ("Your card was declined." / "Network error, please retry." / generic), list unchanged.
  Traces: AC-4, AC-5.
- **TC-AND-226-06 — Unit: error-envelope mapping (string + 422 array)**
  Type: unit. Target: JVM.
  Preconditions: error mapper under test.
  Steps: feed `{"detail":"customer create failed"}` and `{"detail":[{"msg":"...","loc":["body"],"type":"..."}]}` (and, defensively, an object `detail`).
  Expected: string → surfaced category/message; array → validation category extracted from first `msg`; object → falls back without throwing.
  Traces: AC-5, AC-7.
- **TC-AND-226-07 — Unit: POST not retried, GET retried with backoff**
  Type: unit (MockWebServer + virtual time). Target: JVM.
  Preconditions: `setup-intent/card` enqueued to fail; `payment-methods` enqueued fail,fail,success.
  Steps: call `createSetupIntent()` then `getPaymentMethods()`.
  Expected: SetupIntent POST issued exactly once (no auto-retry — avoid orphan intents); GET retried up to 3 attempts with backoff then succeeds.
  Traces: AC-5, AC-6.
- **TC-AND-226-08 — Unit: cache-first + isStale on network failure (offline/flaky dev host)**
  Type: unit/Robolectric (Room in-memory). Target: JVM.
  Preconditions: Room seeded with one cached method; network `getPaymentMethods` throws (host down).
  Steps: call `getPaymentMethods()`.
  Expected: cached rows emitted, `isStale = true`, no crash, no error toast that hides data. With empty cache + network failure → error surfaced, empty list.
  Traces: AC-6.
- **TC-AND-226-09 — Compose-UI: duplicate-submit guard + loading semantics**
  Type: Compose-UI. Target: emu35.
  Preconditions: state with `isPreparingAddCard = true`.
  Steps: render; attempt to tap "Add card".
  Expected: button disabled; second tap does not trigger a second `createSetupIntent`; loading state announced (`stateDescription = "Adding card"`).
  Traces: AC-3, AC-8.
- **TC-AND-226-10 — Compose-UI: error snackbar shown, dismissible, list unchanged; retry enabled**
  Type: Compose-UI. Target: emu35.
  Preconditions: state with one existing method; inject `Failed`/error.
  Steps: render; observe snackbar; dismiss; re-tap "Add card".
  Expected: dismissible Snackbar (live region) shown; method list unchanged; "Add card" usable again for retry.
  Traces: AC-4, AC-5, AC-8.
- **TC-AND-226-11 — Compose-UI: accessibility (no raw card field; combined semantics labels; 48dp target)**
  Type: Compose-UI (a11y assertions). Target: emu35.
  Preconditions: methods list with one card.
  Steps: assert no app-owned card-number/CVC input nodes exist; assert row exposes a single combined label e.g. "Visa ending in 4242, expires 12/2030"; assert "Add card" has content description and ≥48dp touch target.
  Expected: assertions pass; no raw PAN/CVC widgets in app code.
  Traces: AC-2, AC-7.
- **TC-AND-226-12 — Security: secrets/ids never persisted or logged unredacted**
  Type: unit + instrumented. Target: JVM (log capture) + emu35 (Room/DataStore inspection).
  Preconditions: run an add-card flow with a known `client_secret`/`pm_`/`cus_`-style value.
  Steps: capture all log/telemetry output; dump Room and DataStore.
  Expected: no `client_secret`/`ephemeral_key`/`pm_`/`seti_`/`cus_` value appears unredacted in logs or storage; `AddCardConfig` cleared after `onAddCardConfigConsumed()`.
  Traces: AC-7.
- **TC-AND-226-13 — Instrumented e2e: real Stripe test-mode add card (success / decline / 3DS)**
  Type: instrumented/e2e (manual-assisted). Target: **A15 (physical device — MUST)**.
  Rationale: real PaymentSheet brings up Stripe's SDK UI and the 3DS/authentication webview/biometric prompt; exercise on real arm64-v8a / API 34 hardware to catch ABI- and API-level differences vs the x86_64/API-35 emulator and to validate real 3DS challenge handling.
  Preconditions: backend SetupIntent path live (incl. resolution of R4 customer/ephemeral-key gap) OR documented customer-less attach; test publishable key configured.
  Steps: (a) add `4242 4242 4242 4242` → confirm; (b) add `4000 0000 0000 0002` → expect decline; (c) add `4000 0025 0000 3155` → complete 3DS challenge.
  Expected: (a) card appears in methods (brand/last4/expiry correct); (b) dismissible error, list unchanged, retry possible; (c) 3DS completes inside PaymentSheet, card appears.
  Traces: AC-1, AC-4, AC-5.
- **TC-AND-226-14 — Manual: flaky/offline dev host during SetupIntent creation**
  Type: manual. Target: A15 (toggle airplane mode / point at unreachable host) — emu35 acceptable as fallback.
  Preconditions: methods list cached.
  Steps: enable airplane mode (or kill dev host); tap "Add card".
  Expected: SetupIntent create fails gracefully with a retryable, dismissible error (no auto-retry on the POST); cached methods still shown with stale indicator; no crash; restoring network + retry succeeds.
  Traces: AC-5, AC-6.

### Coverage matrix
| AC | Covered by |
| --- | --- |
| AC-1 (card adds + appears, test mode) | TC-01, TC-03, TC-13 |
| AC-2 (card data only via Stripe SDK; no raw field) | TC-11 |
| AC-3 (`POST /ui/billing/setup-intent/card` + PaymentSheet setup mode) | TC-01, TC-02, TC-04, TC-09 |
| AC-4 (cancellation → no error, list unchanged) | TC-05, TC-10, TC-13 |
| AC-5 (declined card → dismissible error, list unchanged, retry) | TC-04, TC-05, TC-06, TC-07, TC-10, TC-13, TC-14 |
| AC-6 (cache-first + stale indicator on network failure) | TC-03, TC-07, TC-08, TC-14 |
| AC-7 (no secrets/ids persisted or logged unredacted) | TC-02, TC-06, TC-11, TC-12 |
| AC-8 (unit + Compose UI tests pass in CI without real Stripe) | TC-09, TC-10, TC-11 |
