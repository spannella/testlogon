---
id: AND-229
title: CCBill flow
milestone: M5
epic: E31
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
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
- **Backend reference:** FastAPI route `POST /api/billing/ccbill/frontend-oauth`
  (op `get_frontend_oauth_api_billing_ccbill_frontend_oauth_post`; OpenAPI declares it
  POST-only, NOT `GET/POST` — corrected). Per OpenAPI it takes **no request body**
  (`requestBody` absent) and only the standard params `user_sub` (query, optional),
  `X-SESSION-ID` (header), `X-IMPERSONATION-TOKEN` (header); its 200 response schema is
  **untyped/empty** (`{}`) — see §5 and §16. **There is no web reference for this exact
  endpoint:** `src/api/endpoints/billing.ts` does NOT call `frontend-oauth` (it only does
  `createCheckoutSession` → `POST /ui/billing/checkout_session` → `{ session_id, url }`),
  so the request/response field names below are **unverified assumptions** to confirm with
  the backend team. Shared types in `src/api/types.ts` reference CCBill only as a provider
  enum value (`provider: "stripe" | "ccbill" | "paypal" | "unknown"`). Dev backend
  `http://18.222.237.167:8000` (plaintext, flaky — design for ~20 s timeouts).
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Retrofit 2.11 / OkHttp 4.12 /
  Moshi 1.15, AndroidX Browser (`androidx.browser:browser`, Custom Tabs), Coroutines/Flow,
  DataStore. minSdk 24 / compileSdk/targetSdk 35, JDK 17.

## 3. Functional Requirements

FR-1. Provide a "Pay with CCBill" entry action that, given an optional `checkoutSessionId`
and a `flowType` (`ADD_PAYMENT_METHOD` | `PURCHASE`), fetches a CCBill authorization URL
from the backend.

FR-2. The fetch must send the authenticated session. **Verification note:** the web client
(`src/api/client.ts`) attaches, on every request, an `Authorization: Bearer <accessToken>`
header (from the auth store), the cookie session (`credentials: "include"`), and an
`X-CSRF-Token` header read from the `ui_csrf` cookie when present; the OpenAPI for this
endpoint additionally documents an optional `X-SESSION-ID` header and `user_sub` query param.
The Android client must replicate whichever of these the dev backend actually enforces —
treat `X-SESSION-ID` (documented) and `X-CSRF-Token` (sent by web on all mutations) as the
authoritative pair and confirm with backend (see §16, Open assumptions). It must generate a
cryptographically random opaque `state`
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

Endpoint: `POST /api/billing/ccbill/frontend-oauth` (verified POST-only in OpenAPI index,
line 21). Idempotent fetch as a POST because it creates a server-side authorization session;
not retried as a blind GET.

> **VERIFICATION (critical):** The OpenAPI spec for this operation declares **no request
> body** and an **empty/untyped 200 response schema** (`schema: {}`). The request and response
> shapes documented below are therefore **unverified assumptions** inferred from CCBill's
> hosted-flow conventions — they are NOT confirmed by OpenAPI or the web client (which does not
> call this endpoint at all). The only params OpenAPI documents are `user_sub` (query),
> `X-SESSION-ID` and `X-IMPERSONATION-TOKEN` (headers). **Confirm the real contract with the
> backend team before implementing the Retrofit DTOs** (see §16, Open assumptions OA-1/OA-2).
> If the backend in fact generates `state`/`return_url` server-side and ignores a client body,
> drop the client `state` generation and validate the server's echoed value instead (see R1).

Request headers (assumed): `X-SESSION-ID` (session) + `X-CSRF-Token: <ui_csrf>` (web sends
this on all mutations) + `Content-Type: application/json`; optional `user_sub` query param.

Request body (ASSUMED — not in OpenAPI):

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

Success `200` (ASSUMED body — OpenAPI 200 schema is empty `{}`, so these field names are
unverified):

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

Optional confirmation (on `Success`) reuses AND-227/AND-223 status endpoints — not redefined
here; owned by those tickets. **Correction:** there is no `GET /ui/billing/checkout_session/{id}`
in the OpenAPI index (only `POST /ui/billing/checkout_session`). The verified confirmation
read is `GET /ui/billing/payment-methods` (op `list_payment_methods_ui_billing_payment_methods_get`,
index line 1185). Error responses are `422 HTTPValidationError`; the `detail` field follows the
standard FastAPI mapping (string | `[{msg, loc, type}]` | `{code, ...}`), which the web client's
`normalizeErrorDetail` (`src/api/client.ts`) handles for all three shapes — verified.

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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer.

1. **Endpoint is `POST /api/billing/ccbill/frontend-oauth`.** VERDICT: **Verified.**
   SOURCE: OpenAPI `POST /api/billing/ccbill/frontend-oauth`
   (op `get_frontend_oauth_api_billing_ccbill_frontend_oauth_post`), index line 21.
2. **Method is POST (not `GET/POST`).** VERDICT: **Corrected** (§2 said "GET/POST").
   SOURCE: OpenAPI defines only a `post` operation for this path; `openapi.pretty.json`
   line 87826.
3. **Request body shape `{flow_type, checkout_session_id, state, return_url}`.**
   VERDICT: **Unverified-assumption** (likely wrong). SOURCE: OpenAPI declares the
   operation with **no `requestBody`** (index `req=` empty; `openapi.pretty.json`
   lines 87825–87902 contain only `parameters` + `responses`, no `requestBody`). No web
   caller exists to confirm field names.
4. **Response 200 `{authorization_url, correlation_id, expires_at}`.**
   VERDICT: **Unverified-assumption.** SOURCE: OpenAPI 200 content schema is empty
   (`"schema": {}`), `openapi.pretty.json` line 87882. Field names are inferred, not defined.
5. **Auth: cookie session + `X-CSRF-Token` header.** VERDICT: **Corrected / partially
   verified.** The web client sends `Authorization: Bearer`, cookie (`credentials:"include"`)
   AND `X-CSRF-Token` (from the `ui_csrf` cookie) on every request. SOURCE:
   `src/api/client.ts` lines 156–171 (`Authorization` 156–160, `ui_csrf`→`X-CSRF-Token`
   168–171, `credentials:"include"` 183). However this *endpoint's* OpenAPI documents
   `X-SESSION-ID`/`X-IMPERSONATION-TOKEN` headers + `user_sub` query, NOT `X-CSRF-Token`
   (index line 21). Corrected §2/§5 to list `X-SESSION-ID` as the documented auth header.
6. **"Web reference: `billing.ts` (CCBill helpers)".** VERDICT: **Corrected.** SOURCE:
   `src/api/endpoints/billing.ts` — no `ccbill`/`frontend-oauth` symbol exists; the nearest
   redirect-style flow is `createCheckoutSession` → `api.post("/ui/billing/checkout_session")`
   returning `{ session_id, url }` (line 76–77). There is NO web client for the CCBill
   frontend-oauth endpoint.
7. **CCBill is a known provider value.** VERDICT: **Verified.** SOURCE: `src/api/types.ts`
   line 3163 `provider: "stripe" | "ccbill" | "paypal" | "unknown"`.
8. **Confirmation read `GET /ui/billing/checkout_session/{id}`.** VERDICT: **Corrected.**
   SOURCE: no such path in OpenAPI; only `POST /ui/billing/checkout_session` (index line
   1175). Verified confirmation read is `GET /ui/billing/payment-methods` (index line 1185).
9. **Error shape: `detail` = string | `[{msg}]` | `{code,...}`; 422 = HTTPValidationError.**
   VERDICT: **Verified.** SOURCE: OpenAPI `resp=...;422:HTTPValidationError` (index line 21);
   `src/api/client.ts` `normalizeErrorDetail` lines 66–102 handles all three shapes.
10. **401 → single transparent refresh via `POST /ui/session/refresh` then retry.**
    VERDICT: **Verified.** SOURCE: `src/api/client.ts` `refreshSession` lines 121–130 and
    401 handler lines 194–237; OpenAPI `POST /ui/session/refresh` (index line 1847).
11. **A backend CCBill mock exists.** VERDICT: **Verified** (server-side, distinct from the
    in-app dev mock this ticket ships). SOURCE: OpenAPI `POST /mock/ccbill/ccbill-auth/oauth/token`
    (index line 423) and `/mock/ccbill/*` family (index lines 423–426); also
    `POST /api/billing/payment-methods/ccbill-token` (`SavePaymentTokenIn`, index line 32) for
    persisting the resulting token.
12. **`SavePaymentTokenIn` = `{payment_token_id (req), label?, make_default=true}`.**
    VERDICT: **Verified** (relevant to the optional post-success token save).
    SOURCE: `openapi.pretty.json` lines 64612–64640.
13. **Use Chrome Custom Tabs (AndroidX Browser), not WebView, to share the system browser
    session.** VERDICT: **Verified (framework ref).** SOURCE: framework ref —
    https://developer.android.com/develop/ui/views/layout/webapps/customtabs and
    `androidx.browser.customtabs.CustomTabsIntent`.
14. **`Intent.ACTION_VIEW` fallback when no Custom Tabs provider exists.**
    VERDICT: **Verified (framework ref).** SOURCE: framework ref —
    https://developer.android.com/reference/android/content/Intent#ACTION_VIEW
    (and `ActivityNotFoundException` on `startActivity`).
15. **`SecureRandom` for the opaque `state`.** VERDICT: **Verified (framework ref).**
    SOURCE: framework ref — https://developer.android.com/reference/java/security/SecureRandom.
16. **DataStore Preferences for pending-state persistence across process death.**
    VERDICT: **Verified (framework ref).** SOURCE: framework ref —
    https://developer.android.com/topic/libraries/architecture/datastore.

### Corrections made

- **§2 Backend reference:** "GET/POST" → POST-only; flagged that the endpoint has no request
  body and an untyped 200 schema; corrected the false "web reference in billing.ts (CCBill
  helpers)" claim (no such web caller); noted the documented auth header is `X-SESSION-ID`.
- **§2 / FR-2:** rewrote the auth description to match `client.ts` (Bearer + cookie +
  `X-CSRF-Token` from `ui_csrf`) plus the OpenAPI-documented `X-SESSION-ID`.
- **§5 API Contract:** added a verification banner that the request body and response field
  names are unverified assumptions (not present in OpenAPI); marked the JSON blocks "ASSUMED".
- **§5:** removed the non-existent `GET /ui/billing/checkout_session/{id}` confirmation path;
  pointed confirmation at the verified `GET /ui/billing/payment-methods`; confirmed the error
  `detail`/422 shape against `client.ts` and OpenAPI.

### Open assumptions

- **OA-1 (request body).** Whether `/api/billing/ccbill/frontend-oauth` accepts a JSON body at
  all, and if so its fields, is **unverifiable** from the sources: OpenAPI declares no
  `requestBody` and no web client calls it. Must be confirmed with backend before coding the
  Retrofit DTO. Ties to R1.
- **OA-2 (response fields).** The 200 schema is empty (`{}`); `authorization_url`,
  `correlation_id`, `expires_at` names are inferred. Unverifiable from sources; confirm with
  backend. Ties to R1.
- **OA-3 (client vs server `state`/`return_url`).** Because there is no documented body, it is
  unknown whether `state`/`return_url` are client-supplied or server-generated; if
  server-generated, drop client `state` gen (R1).
- **OA-4 (return-URL scheme/transport).** Whether CCBill 302s directly to the app-private
  scheme or via an HTTPS backend return is owned by AND-231 and not determinable here (R2).
- **OA-5 (CSRF enforcement).** OpenAPI does not list `X-CSRF-Token` as a parameter for this
  endpoint though the web client always sends it; whether the dev backend enforces it for
  this route is unverifiable from the index/spec.
- **OA-6 (Custom Tab cookie sharing).** Whether the backend redirect chain re-establishes the
  session via the system-browser cookie jar (vs the app's OkHttp jar) is a runtime/backend
  behavior not determinable from these sources (R4).

## 17. Test Plan

Test-target legend: **JVM** = local JVM/Robolectric (no device); **EMU** = headless AVD
`test35` (x86_64, API 35) on the CI build server; **DEVICE** = physical Samsung Galaxy A15 5G
(SM-A156U, API 34, arm64-v8a) on the build host via adb.

- **TC-AND-229-01 — Authorize request shape (happy path).**
  Type: contract/MockWebServer (JVM). Target: `RealCcbillProvider.authorize`.
  Preconditions: MockWebServer enqueues `200` with the assumed body
  (`authorization_url`, `correlation_id`, `expires_at`); valid session + CSRF stubbed.
  Steps: call `authorize(PURCHASE, checkoutSessionId="cs_…")`; capture the recorded request.
  Expected: `POST /api/billing/ccbill/frontend-oauth`; `X-CSRF-Token` and session header
  present; body (per the assumed contract) carries `flow_type=purchase`, the
  `checkout_session_id`, a 64-hex `state`, and the AND-231 `return_url`; the same `state` is
  written to `CcbillStateStore` before returning `ApiResult.Success`.
  NOTE: assertions on body fields are gated on OA-1/OA-2; if backend confirms no body, this TC
  asserts the documented `user_sub`/`X-SESSION-ID` params instead. Traces: AC-1.

- **TC-AND-229-02 — `add_payment_method` omits checkout_session_id.**
  Type: contract/MockWebServer (JVM). Target: `RealCcbillProvider.authorize`.
  Preconditions: MockWebServer `200`. Steps: `authorize(ADD_PAYMENT_METHOD, null)`.
  Expected: `flow_type=add_payment_method`; `checkout_session_id` omitted/null; persisted
  `state` set. Traces: AC-1.

- **TC-AND-229-03 — Fetch error maps to Failure(NETWORK)/Failure(BACKEND).**
  Type: contract/MockWebServer (JVM). Target: `RealCcbillProvider.authorize`.
  Preconditions: MockWebServer enqueues `422 HTTPValidationError` (`detail:[{msg,loc,type}]`),
  then a `500`, then a socket-timeout. Steps: call authorize for each.
  Expected: `422`/`500` → `ApiResult` error surfaced as `Failure(BACKEND)`; timeout →
  `Failure(NETWORK)`; **no automatic retry** of the POST; persisted `state` cleared/unused on
  failure; `detail` parsed via the FastAPI shapes. Traces: AC-1, and §7 resilience.

- **TC-AND-229-04 — Custom Tab launch on success.**
  Type: instrumented/Compose-UI (EMU). Target: `CustomTabLauncher.launch` + entry CTA.
  Preconditions: a Custom Tabs-capable browser installed (default on AVD); mock provider
  returns a synthetic `authorization_url`. Steps: tap "Pay with CCBill"; intercept the
  launched intent (Espresso-Intents). Expected: a `CustomTabsIntent` `ACTION_VIEW` to the
  authorization URL is launched; controller transitions `FetchingUrl→Launching→AwaitingReturn`;
  `launch` returns true. Traces: AC-2.

- **TC-AND-229-05 — No browser → ACTION_VIEW fallback, then Failure(BROWSER_UNAVAILABLE).**
  Type: unit (JVM, Robolectric). Target: `CustomTabLauncher.launch`.
  Preconditions: stub `launchUrl` to throw `ActivityNotFoundException`; (a) `ACTION_VIEW`
  succeeds; (b) `ACTION_VIEW` also throws. Steps: call `launch`.
  Expected: (a) falls back to `Intent.ACTION_VIEW`, returns true; (b) returns false →
  controller emits `Failure(BROWSER_UNAVAILABLE)`. Traces: AC-2.

- **TC-AND-229-06 — Return with matching state + status routes correctly.**
  Type: integration with AND-231 (JVM). Target: `CcbillProvider.resolve`.
  Preconditions: persisted `state=S`, `correlation_id=C`. Steps: feed AND-231 `PaymentReturn`
  built from `testlogon://billing/return?provider=ccbill&status=success&state=S&correlation_id=C`
  (then `status=cancel`, then `status=failure`). Expected: success→`CcbillResult.Success(C,…)`;
  cancel→`Cancelled`; failure→`Failure(BACKEND,…)`; pending record cleared each time.
  Traces: AC-3.

- **TC-AND-229-07 — State mismatch/missing never succeeds.**
  Type: unit (JVM). Target: `CcbillProvider.resolve`.
  Preconditions: persisted `state=S`. Steps: feed returns with `status=success` and (a)
  `state=WRONG`, (b) no `state`. Expected: both → `Failure(STATE_MISMATCH)`; never `Success`;
  comparison is constant-time. Traces: AC-4.

- **TC-AND-229-08 — Dev-mock full round-trip (Success/Cancel/Failure).**
  Type: instrumented/e2e (EMU). Target: mock provider + `CcbillFlowController` + UI.
  Preconditions: `FeatureFlags.ccbillDevMock=true` (forced in instrumented tests); offline /
  no CCBill reachability. Steps: tap CTA → in-app mock screen → choose each of
  Success/Cancel/Failure. Expected: same `PaymentReturn` deep link emitted as real provider;
  controller resolves to `Success` / `Cancelled` / `Failure`; final UI state matches; events
  tagged `mock:true`. Satisfies "completes + returns" without a live sandbox. Traces: AC-5, AC-8.

- **TC-AND-229-09 — Process-death rehydration.**
  Type: instrumented (EMU). Target: `CcbillFlowController` + `CcbillStateStore`.
  Preconditions: in `AwaitingReturn` with a non-expired pending record in DataStore. Steps:
  simulate process death (kill + recreate the controller); deliver the matching return deep
  link. Expected: controller rehydrates to `AwaitingReturn` and resolves to `Success`; pending
  record cleared. Traces: AC-6.

- **TC-AND-229-10 — Expired pending record.**
  Type: unit (JVM). Target: `CcbillFlowController`/`resolve`.
  Preconditions: pending record with `started_at_epoch_ms` > 15 min ago. Steps: deliver a
  late matching return. Expected: `Failure(UNKNOWN)` ("session expired"); record discarded;
  not treated as success. Traces: AC-4 (security), §7.

- **TC-AND-229-11 — Double-tap idempotency.**
  Type: unit/state-machine (JVM). Target: `CcbillFlowController`.
  Preconditions: controller in `Launching`/`AwaitingReturn`. Steps: invoke `start()` again.
  Expected: second invocation ignored (no second authorize call, no second Custom Tab launch).
  Traces: AC-7.

- **TC-AND-229-12 — User-dismissed tab inferred as Cancel.**
  Type: instrumented (EMU). Target: `CcbillFlowController` lifecycle handling.
  Preconditions: in `AwaitingReturn`. Steps: return to the app (Activity `onResume`) with no
  return deep link; wait past the ~1.5 s grace window. Expected: result resolves to
  `Cancelled`; entry CTA re-enabled. Traces: AC-3 (cancel), §7. NOTE: if AND-231 emits an
  explicit cancel deep link (R3), prefer TC-06's cancel path and downgrade this heuristic test.

- **TC-AND-229-13 — Security: no secrets logged; CSRF/session attached.**
  Type: contract/MockWebServer + log capture (JVM). Target: `RealCcbillProvider` + logger.
  Preconditions: logger at INFO. Steps: run authorize + resolve; inspect captured logs and the
  recorded request. Expected: `state`, full `authorization_url`, query params NOT logged above
  DEBUG; `X-CSRF-Token` / `X-SESSION-ID` present on the request; WebView is never instantiated
  (Custom Tabs only). Traces: AC-1, §8.

- **TC-AND-229-14 — Real-provider sandbox + accessibility (physical device).**
  Type: manual/instrumented (**DEVICE — required**). Target: end-to-end on real hardware.
  Preconditions: a real CCBill sandbox URL reachable; Custom Tabs browser on the A15;
  TalkBack available. MUST run on the **physical Samsung A15 (API 34, arm64-v8a)** to exercise
  the real system-browser Custom Tab + cookie/redirect chain and the arm64/API-34-vs-AVD-API-35
  path (emulator x86 cannot validate real browser cookie sharing / OA-6). Steps: tap CTA →
  complete payment in the real Custom Tab → return; with TalkBack on, traverse the entry CTA,
  progress, and result banner. Expected: flow completes and routes to `Success`; the result
  banner announces as a live region; CTA/mock controls have `contentDescription`, ≥48 dp
  targets, 4.5:1 contrast. Traces: AC-2, AC-8, §9.

### Coverage matrix

| Acceptance criterion (§14) | Covered by |
| --- | --- |
| AC-1 (request shape: path, CSRF/session, flow_type, return_url, persisted state) | TC-01, TC-02, TC-03, TC-13 |
| AC-2 (200 → Custom Tab; fallback to ACTION_VIEW) | TC-04, TC-05, TC-14 |
| AC-3 (matching state: success/cancel/failure routing) | TC-06, TC-12 |
| AC-4 (missing/mismatched state → Failure(STATE_MISMATCH); never success) | TC-07, TC-10 |
| AC-5 (dev-mock full flow in-app, all branches) | TC-08 |
| AC-6 (state/correlation survive process death) | TC-09 |
| AC-7 (double-tap does not start a second flow) | TC-11 |
| AC-8 (overall: completes + returns; real where sandbox available) | TC-08, TC-14 |
