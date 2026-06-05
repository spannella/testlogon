---
id: AND-229
title: CCBill flow
milestone: M5
epic: E31
priority: P1
size: M
status: draft
depends_on: [AND-231]
blocks: []
---

# AND-229 — CCBill flow

## 1. Overview & Goal

CCBill is a hosted, redirect-based payment provider: the actual card-entry / 3-D Secure
form is rendered by CCBill on its own web domain, not inside the app. This ticket
implements the Android side of the **CCBill "frontend OAuth" flow** — the handshake that
obtains a CCBill authorization/checkout URL from our backend
(`/api/billing/ccbill/frontend-oauth`), opens that URL in a **Chrome Custom Tab**, lets the
user complete payment on CCBill's hosted page, and then receives the result back via the
deep-link return handler shipped in **AND-231**.

Goal: from a billing surface (add-payment-method or checkout), the user taps "Pay with
CCBill", the app requests a frontend-OAuth authorization URL, launches it in a Custom Tab
(in-app browser with our cookie session shared via the system browser, not a `WebView`),
and on return routes deterministically to **success / cancel / failure**. Because the dev
backend is plaintext HTTP and unreliable, and a live CCBill sandbox may be unavailable in
CI/dev, this ticket also ships a **dev mock** provider that simulates the entire redirect
round-trip without leaving the app, so the flow is testable end-to-end on an emulator.

Non-goals: the deep-link return URL parsing/routing itself (owned by **AND-231**), generic
billing DTO mapping (**AND-223**), the checkout-session creation flow (**AND-227**), the
ViewModel/error-mapping layer for the billing screens (**AND-232**), payment-method list UI,
and any other provider (PayPal, US bank micro-deposits — AND-230). This ticket owns only the
CCBill-specific authorization-URL fetch, the Custom Tab launch, and wiring the AND-231 return
into a CCBill result.

## 2. Context & References

- **Module:** `feature-billing` (the billing feature module from E31). CCBill-specific
  provider logic lives in `core-data` (`com.testlogon.android.core.data.billing.ccbill`);
  the Retrofit endpoint and DTOs live in `core-network` / `core-model`. The Custom Tab
  launcher utility lives in `core-ui` (`com.testlogon.android.core.ui.browser`).
- **Package base:** `com.testlogon.android` exactly (e.g.
  `com.testlogon.android.core.data.billing.ccbill.CcbillRepository`).
- **Depends on:**
  - **AND-231 — Payment redirect/return handler (P0):** owns the deep-link intent filter,
    the return-URL scheme/host, and the `PaymentReturn` sealed result
    (`Success` / `Cancel` / `Failure`) that this ticket consumes. AND-229 supplies the
    `state` / `correlationId` it expects back and reacts to the routed result. AND-229 is
    blocked on AND-231 and must not duplicate URL parsing.
  - **AND-022 — Deep-link / app-links infra** (transitive, via AND-231): registers the
    return scheme in the manifest.
- **Related (not hard deps):** AND-223 (billing DTOs), AND-227 (checkout session) — a
  CCBill purchase typically follows a checkout-session create; this ticket accepts an
  optional `checkoutSessionId` but does not create one.
- **Backend reference:** FastAPI route `GET/POST /api/billing/ccbill/frontend-oauth`
  (see `/openapi.json`). Web reference: `frontend/src/api/endpoints/billing.ts` (CCBill
  helpers) and shared types in `frontend/src/api/types.ts`. Dev backend
  `http://18.222.237.167:8000` (plaintext, flaky — design for ~20 s timeouts).
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Retrofit 2.11 / OkHttp 4.12 /
  Moshi 1.15, AndroidX Browser (`androidx.browser:browser`, Custom Tabs), Coroutines/Flow,
  DataStore. minSdk 24 / compileSdk/targetSdk 35, JDK 17.

## 3. Functional Requirements

FR-1. Provide a "Pay with CCBill" entry action that, given an optional `checkoutSessionId`
and a `flowType` (`ADD_PAYMENT_METHOD` | `PURCHASE`), fetches a CCBill authorization URL
from the backend.

FR-2. The fetch must send the authenticated cookie session **and** the `X-CSRF-Token`
header (state-changing call). It must generate a cryptographically random opaque `state`
value, persist it (DataStore), and pass it to the backend so it round-trips back on return —
this binds the return to the originating request (CSRF/replay protection on the redirect).

FR-3. On a successful fetch, open the returned `authorization_url` in a **Chrome Custom Tab**
launched from the host Activity. The app must share the OS browser's cookie context (Custom
Tabs, not `WebView`) so CCBill's hosted page and our backend's redirect chain work.

FR-4. If no Custom Tabs-capable browser is available, fall back to a plain
`Intent.ACTION_VIEW` to the same URL; if that also fails, surface a recoverable error.

FR-5. The Custom Tab return is handled by **AND-231**'s deep-link handler, which emits a
`PaymentReturn`. This ticket maps that into a `CcbillResult` after validating the returned
`state` equals the persisted value. A mismatched/missing `state` → `Failure(StateMismatch)`.

FR-6. Route results: `Success` → confirm with backend (re-poll payment/session status) and
report success; `Cancel` → return to the billing screen unchanged; `Failure` → show a
retryable error. Cancellation is also inferred if the user dismisses the Custom Tab without
any return deep-link (detected via Activity lifecycle resume with no pending return after a
grace period) → treated as `Cancel`.

FR-7. **Dev mock:** when the dev-mock flag is enabled, the provider must NOT hit CCBill.
Instead it returns a synthetic `authorization_url` pointing at an in-app mock screen that
lets a tester choose Success / Cancel / Failure, then emits the same `PaymentReturn` deep
link as the real provider. The mock is selectable at runtime (debug builds) and forced on in
instrumented tests.

FR-8. The flow must be idempotent against double-taps: while a CCBill flow is in
`Launching`/`AwaitingReturn`, repeated entry actions are ignored.

## 4. Technical Design

**Provider abstraction (core-data):**

```kotlin
package com.testlogon.android.core.data.billing.ccbill

enum class CcbillFlowType { ADD_PAYMENT_METHOD, PURCHASE }

data class CcbillAuthorization(
    val authorizationUrl: String,
    val state: String,
    val correlationId: String,
)

sealed interface CcbillResult {
    data class Success(val correlationId: String, val paymentMethodId: String?) : CcbillResult
    data object Cancelled : CcbillResult
    data class Failure(val reason: CcbillFailure, val message: String?) : CcbillResult
}

enum class CcbillFailure { STATE_MISMATCH, NETWORK, BACKEND, BROWSER_UNAVAILABLE, UNKNOWN }

interface CcbillProvider {
    suspend fun authorize(
        flowType: CcbillFlowType,
        checkoutSessionId: String?,
    ): ApiResult<CcbillAuthorization>

    /** Validates state + maps an AND-231 PaymentReturn into a CcbillResult. */
    suspend fun resolve(returnResult: PaymentReturn): CcbillResult
}
```

Two implementations bound by Hilt with a runtime selector:

```kotlin
@Singleton
class RealCcbillProvider @Inject constructor(
    private val api: BillingApi,
    private val csrf: CsrfTokenProvider,
    private val stateStore: CcbillStateStore,   // DataStore-backed
) : CcbillProvider

@Singleton
class MockCcbillProvider @Inject constructor(
    private val stateStore: CcbillStateStore,
) : CcbillProvider
```

```kotlin
@Module @InstallIn(SingletonComponent::class)
object CcbillModule {
    @Provides @Singleton
    fun provideCcbillProvider(
        flags: FeatureFlags,
        real: Provider<RealCcbillProvider>,
        mock: Provider<MockCcbillProvider>,
    ): CcbillProvider = if (flags.ccbillDevMock) mock.get() else real.get()
}
```

**Custom Tab launcher (core-ui):**

```kotlin
package com.testlogon.android.core.ui.browser

class CustomTabLauncher @Inject constructor() {
    /** @return true if a Custom Tab launched; false if no handler. */
    fun launch(activity: Activity, url: Uri): Boolean {
        return try {
            CustomTabsIntent.Builder()
                .setShowTitle(true)
                .setUrlBarHidingEnabled(true)
                .build()
                .launchUrl(activity, url)
            true
        } catch (e: ActivityNotFoundException) {
            activity.runCatching {
                startActivity(Intent(Intent.ACTION_VIEW, url))
            }.isSuccess
        }
    }
}
```

**Orchestration:** A `CcbillFlowController` (in `feature-billing`) holds the in-flight state
machine and is driven by the billing ViewModel (AND-232 owns the ViewModel itself; this
ticket exposes the controller + provider it calls):

```
Idle --start()--> FetchingUrl --ok--> Launching --launched--> AwaitingReturn
   FetchingUrl --err--> Error
   AwaitingReturn --PaymentReturn--> Resolving --> Success | Cancelled | Failure
   AwaitingReturn --(resumed, no return, grace elapsed)--> Cancelled
```

The controller exposes `StateFlow<CcbillFlowState>`. The pending `state` + `correlationId`
survive process death via `CcbillStateStore` (DataStore), because the Custom Tab can move the
app to background and the OS may reclaim it before return.

## 5. API Contract

Endpoint: `POST /api/billing/ccbill/frontend-oauth` (idempotent fetch is a POST because it
creates a server-side authorization session; not retried as a blind GET).

Request headers: cookie session + `X-CSRF-Token: <ui_csrf>`; `Content-Type: application/json`.

Request body:

```json
{
  "flow_type": "add_payment_method",
  "checkout_session_id": "cs_01H...",
  "state": "b3f1...64hex",
  "return_url": "testlogon://billing/return"
}
```

`checkout_session_id` is nullable (omitted for `add_payment_method`). `return_url` is the
deep link registered by AND-231/AND-022.

Success `200`:

```json
{
  "authorization_url": "https://api.ccbill.com/wap-frontflex/flexforms/...?...&state=b3f1...",
  "correlation_id": "ccb_01H...",
  "expires_at": "2026-06-05T18:40:00Z"
}
```

Retrofit:

```kotlin
interface BillingApi {
    @POST("api/billing/ccbill/frontend-oauth")
    suspend fun ccbillFrontendOauth(
        @Header("X-CSRF-Token") csrf: String,
        @Body body: CcbillOauthRequest,
    ): Response<CcbillOauthResponse>
}

@JsonClass(generateAdapter = true)
data class CcbillOauthRequest(
    @Json(name = "flow_type") val flowType: String,
    @Json(name = "checkout_session_id") val checkoutSessionId: String?,
    @Json(name = "state") val state: String,
    @Json(name = "return_url") val returnUrl: String,
)

@JsonClass(generateAdapter = true)
data class CcbillOauthResponse(
    @Json(name = "authorization_url") val authorizationUrl: String,
    @Json(name = "correlation_id") val correlationId: String,
    @Json(name = "expires_at") val expiresAt: String?,
)
```

Return deep link (produced by CCBill → our backend → AND-231 handler), e.g.
`testlogon://billing/return?provider=ccbill&status=success&state=b3f1...&correlation_id=ccb_01H...`.
AND-231 parses this into `PaymentReturn`; AND-229 only reads `provider == "ccbill"`,
`status`, `state`, `correlation_id`.

Optional confirmation (on `Success`) reuses AND-227/AND-223 status endpoints (e.g.
`GET /ui/billing/checkout_session/{id}` or `GET /api/billing/payment-methods`) — not
redefined here; owned by those tickets. Error `detail` follows the standard FastAPI mapping
(string | `[{msg}]` | `{code,...}`).

## 6. Data & State Management

- **`CcbillStateStore` (DataStore Preferences):** persists `pending_state`,
  `pending_correlation_id`, `pending_flow_type`, `pending_checkout_session_id`,
  `started_at_epoch_ms`. Written before launching the Custom Tab; cleared on terminal result
  or on expiry (> 15 min stale → discard, treat any late return as expired).
- **`state` generation:** `SecureRandom` → 32 bytes → hex. Compared with constant-time
  equality on return.
- **Flow state** (`CcbillFlowState`: `Idle | FetchingUrl | Launching | AwaitingReturn |
  Resolving | Done(result)`) is in-memory `StateFlow` in the controller; rehydrated from
  DataStore to `AwaitingReturn` after process death if a non-expired pending record exists.
- No Room usage in this ticket (no list/cache entity); the resulting payment method /
  entitlement is persisted by the owning billing repository (AND-223/AND-227), not here.

## 7. Error Handling & Resilience

- **Fetch failures:** wrap in `ApiResult`. Timeouts use the global ~20 s OkHttp timeout. The
  OAuth fetch is a POST (state-changing) → **no** automatic retry; surface a
  `Failure(NETWORK)` with a manual "Try again". A single transparent `POST
  /ui/session/refresh`-then-retry applies only via the shared 401 interceptor (AND-031
  convention), not a CCBill-specific retry.
- **Browser unavailable:** `CustomTabLauncher.launch` returns false → `Failure(BROWSER_UNAVAILABLE)`
  with a message to install/enable a browser.
- **State mismatch / missing state on return:** `Failure(STATE_MISMATCH)` — never treat as
  success.
- **User-dismissed tab (no deep link):** detected on Activity `onResume` while
  `AwaitingReturn`; after a short grace window (e.g. 1.5 s) with no pending return → `Cancelled`.
- **Expired pending record:** late return after 15 min → `Failure(UNKNOWN)` ("session
  expired, restart payment").
- **Flaky dev host:** all UI states are explicit; the screen shows an offline/error banner
  on fetch failure and keeps the entry CTA enabled for retry.

## 8. Security & Privacy

- Card data is **never** entered in-app — it lives only on CCBill's hosted page; the app
  handles no PAN/CVV (PCI scope minimized to redirect-only).
- Use **Custom Tabs**, not `WebView`, so cookies/credentials are not injected into an in-app
  web context and the session is the system browser's.
- The opaque `state` (CSRF/replay binding) is generated with `SecureRandom`, single-use,
  expires in 15 min, and is validated with constant-time comparison.
- `X-CSRF-Token` is mandatory on the OAuth POST; cookie jar is the shared persistent jar.
- The `return_url` scheme is app-private (registered by AND-022/AND-231); the handler must
  reject returns whose `state` is unknown so a forged deep link cannot drive a fake success.
- Do not log `authorization_url` query params, `state`, or `correlation_id` at non-debug
  levels (they are flow-binding secrets).

## 9. Accessibility & i18n

- Custom Tab UI itself is the system browser's responsibility (already accessible).
- The in-app entry CTA, mock screen, error/cancel banners, and progress indicators carry
  `contentDescription`/semantics, meet 4.5:1 contrast and 48 dp touch targets, and announce
  busy/result state changes to TalkBack (live region on the result banner).
- All user-facing strings (`"Pay with CCBill"`, error/cancel/success copy, mock-screen
  labels) live in `strings.xml` — no hardcoded literals. RTL-safe layouts.

## 10. Telemetry & Logging

Structured events (no secrets):

- `billing_ccbill_start` { flow_type }
- `billing_ccbill_url_fetched` { ok, latency_ms }
- `billing_ccbill_tab_launched` { fallback_action_view: bool }
- `billing_ccbill_return` { status, state_valid: bool }
- `billing_ccbill_result` { result: success|cancel|failure, reason }

Logs use the app logger; at INFO log only `correlation_id` (treated as low-sensitivity id is
acceptable internally but redact in shareable logs); never log `state` or full URLs except at
DEBUG. Mock provider tags events with `mock: true`.

## 11. Testing Strategy

- **Unit (core-testing, JVM):**
  - `RealCcbillProvider.authorize` builds the correct request (flow_type mapping, return_url,
    persisted state) and maps `200`/error → `ApiResult`. MockWebServer for the endpoint.
  - `resolve` validates state: matching → `Success`; mismatch/missing → `Failure(STATE_MISMATCH)`;
    `status=cancel` → `Cancelled`; `status=failure` → `Failure(BACKEND)`.
  - Expiry: pending record > 15 min → expired result.
  - `state` generator: 64-hex, distinct across calls.
- **`CustomTabLauncher`** unit: `ActivityNotFoundException` triggers `ACTION_VIEW` fallback;
  both failing → returns false.
- **Controller** state-machine tests: double-tap ignored while in-flight; process-death
  rehydration from DataStore → `AwaitingReturn`.
- **Instrumented (mock provider forced on):** full round-trip — tap CTA → mock screen →
  choose Success/Cancel/Failure → assert routed `CcbillResult` and final UI state. This
  satisfies the "CCBill flow completes + returns" acceptance without a live CCBill sandbox.
- **Integration with AND-231:** feed representative return deep links through AND-231's parser
  into `resolve`, asserting correct mapping.

## 12. Dependencies & Sequencing

- **Hard dep:** AND-231 (return handler + `PaymentReturn` type + return scheme). AND-229
  cannot complete until AND-231's deep-link routing exists; AND-229 must consume, not
  reimplement, it.
- **Soft deps:** AND-223 (billing DTOs/`BillingApi` module), AND-227 (checkout session that
  supplies `checkout_session_id`), AND-232 (billing ViewModel that drives the controller and
  maps errors to UI). Add `androidx.browser:browser` to the version catalog if not present.
- **Sequencing:** land after AND-231; expose `CcbillProvider` + `CcbillFlowController` so
  AND-232 can bind them. The dev mock lets AND-229 be developed/tested before a CCBill
  sandbox is provisioned.

## 13. Risks & Open Questions

- **R1:** Exact backend request/response field names for `/api/billing/ccbill/frontend-oauth`
  are inferred; confirm against `/openapi.json` and `frontend/src/api/endpoints/billing.ts`
  (esp. whether `state`/`return_url` are client-supplied or server-generated). If
  server-generated, drop client `state` gen and validate the server's echoed value instead.
- **R2:** Whether CCBill's hosted flow honors our app-private `return_url` scheme directly or
  redirects through a backend HTTPS return that then 302s to the deep link (more likely);
  AND-231 must register the actual scheme either way.
- **R3:** Cancel detection via lifecycle is heuristic; if AND-231 emits an explicit cancel
  deep link, prefer that and drop the grace-window heuristic.
- **R4:** Custom Tab does not share cookies with the app's OkHttp jar — confirm the backend
  redirect chain re-establishes session via its own cookies (it should, since CCBill →
  backend return is server-to-server / browser-cookie based).
- **OQ:** Does `add_payment_method` require a prior checkout session, or is it standalone?

## 14. Acceptance Criteria

- AC-1. Tapping "Pay with CCBill" calls `POST /api/billing/ccbill/frontend-oauth` with the
  cookie session, `X-CSRF-Token`, correct `flow_type`, `return_url`, and a freshly generated
  persisted `state`. (Verified: MockWebServer asserts request shape.)
- AC-2. On `200`, the returned `authorization_url` opens in a Custom Tab; if no Custom
  Tabs browser exists, falls back to `ACTION_VIEW`. (Instrumented + unit.)
- AC-3. A return deep link with matching `state` and `status=success` resolves to
  `CcbillResult.Success` and routes the UI to a success state; `status=cancel` → `Cancelled`;
  `status=failure` → `Failure`. (Tested via AND-231 returns.)
- AC-4. A return with a missing/mismatched `state` resolves to `Failure(STATE_MISMATCH)` and
  is never treated as success. (Tested.)
- AC-5. With the dev-mock flag on, the entire flow completes in-app (no network to CCBill),
  exercising Success/Cancel/Failure paths. (Instrumented.)
- AC-6. Pending `state`/`correlation_id` survive process death; a return after relaunch still
  resolves correctly. (Tested.)
- AC-7. Double-tapping the CTA while a flow is in-flight does not start a second flow.
- AC-8. Overall: "CCBill flow completes + returns" — verified end-to-end against the mock and,
  where a sandbox is available, against the real provider.

## 15. Definition of Done

- `CcbillProvider` (real + mock), `CcbillFlowController`, `CustomTabLauncher`, `BillingApi`
  CCBill method + DTOs, and `CcbillStateStore` implemented under `com.testlogon.android.*`
  with the package layering above (core-network/core-model/core-data/core-ui).
- Hilt binding selects mock vs real by `FeatureFlags.ccbillDevMock`; mock forced on in
  instrumented tests.
- All AC-1…AC-8 covered by passing unit + instrumented tests in `core-testing`.
- No hardcoded user-facing strings; a11y semantics on all in-app surfaces.
- No secrets (`state`, full authorization URL) logged above DEBUG.
- Consumes AND-231's `PaymentReturn` without reimplementing deep-link parsing.
- Lint/ktlint/detekt clean; builds on the `android-port` branch (`android/` module);
  reviewed and merged; telemetry events emitting as specified.
