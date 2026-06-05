---
id: AND-228
title: PayPal (Custom Tabs)
milestone: M5
epic: E31
priority: P1
size: M
status: draft
depends_on: [AND-231]
blocks: []
---

# AND-228 — PayPal (Custom Tabs)

## 1. Overview & Goal

Provide a PayPal payment/authorization flow for the TestLogon Android app by launching the
PayPal-hosted approval URL in an Android **Custom Tab** (Chrome Custom Tabs / `androidx.browser`)
rather than an embedded `WebView`, and returning the user to the app via the deep-link return
handler owned by **AND-231**. PayPal does not ship a maintained first-party native Android Checkout
SDK for arbitrary FastAPI backends; the supported and PCI-safe integration for a redirect-style
provider is the browser-redirect (PayPal "approve" URL) pattern. Custom Tabs preserves the user's
PayPal browser session/cookies, shows the verified TLS origin in the address bar, and keeps PayPal
credentials out of our process.

The deliverable is a `feature-payments` PayPal sub-flow: a `PayPalLauncher` that opens the approval
URL, a `PayPalViewModel` that creates the order/approval intent against the backend and observes the
deep-link return, and a dev-only `/mock/paypal` approval page so the full round trip is testable
without live PayPal credentials.

**Done when:** initiating PayPal checkout opens a Custom Tab to the PayPal (or `/mock/paypal`)
approval URL, the user approves, the browser redirects to our return deep link, the app captures the
order, and the user lands back in the app in an **authenticated + paid** terminal state.

## 2. Context & References

- **Repo:** `spannella/testlogon`, Android app under `android/`, branch `android-port`.
- **Namespace / applicationId base:** `com.testlogon.android`.
- **Feature module:** `feature-payments` (PayPal sub-package `feature-payments/.../paypal/`).
- **Depends on AND-231 (Payment redirect/return handler):** owns the deep-link return URLs
  (`testlogon://payments/return`), the success/cancel/failure routing, and the single-Activity
  `onNewIntent` plumbing. AND-228 **consumes** that contract; it does not redefine deep links.
- **Sibling billing tickets (context, not deps):** AND-223 (billing API DTOs), AND-225/226
  (Stripe SDK / add-card) — Stripe is a separate provider; PayPal here is redirect-only.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Navigation-Compose, Hilt (KSP), Coroutines/Flow,
  Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, DataStore. Custom Tabs via `androidx.browser:browser`.
- **Backend:** FastAPI + DynamoDB. Dev backend `http://18.222.237.167:8000` (PLAINTEXT HTTP,
  unreliable). Cookie + `ui_csrf`/`X-CSRF-Token` auth, 401→`/ui/session/refresh` once. OpenAPI at
  `/openapi.json`; confirm exact PayPal route shapes there before implementation.
- **Web reference:** `frontend/src/api/endpoints/*.ts` (PayPal create/capture calls), `types.ts`.

## 3. Functional Requirements

FR-1. From a payment context (cart checkout, tip, paywall unlock, subscription) the user can select
**PayPal** as the method and tap **Pay with PayPal**.

FR-2. Tapping it calls the backend to create a PayPal order/approval intent, returning an
`approval_url` (PayPal-hosted, or `/mock/paypal` in dev) and an `order_id`.

FR-3. The app opens `approval_url` in a **Custom Tab** using the system default browser that
supports the Custom Tabs service; if none is available, fall back to a plain
`Intent.ACTION_VIEW`. Never use an in-app `WebView` for the PayPal credential page.

FR-4. On PayPal approval, PayPal (or `/mock/paypal`) redirects the browser to the return deep link
(`testlogon://payments/return?provider=paypal&order_id=...&status=success|cancel`). AND-231 routes
this back into the single Activity; AND-228 registers a handler keyed on `provider=paypal`.

FR-5. On `status=success`, the app calls the backend **capture** endpoint with `order_id` and
transitions to a terminal `Paid` state, surfacing the order/entitlement result.

FR-6. On `status=cancel` (user backed out of the Custom Tab, or PayPal cancel URL) the app returns
to the payment screen in a `Cancelled` state with retry affordance — not an error.

FR-7. If the user dismisses the Custom Tab without any redirect (Activity resumes with no pending
return), the flow resolves to `Cancelled` after a resume-without-return reconciliation check.

FR-8. The flow is **idempotent**: re-entering the screen with an already-captured `order_id` shows
the existing paid result rather than re-capturing.

FR-9. **Dev mock:** when the active flavor/host is dev, the backend returns `/mock/paypal` as the
approval URL; the page exposes Approve and Cancel actions that redirect to the return deep link, so
the entire flow is exercisable end-to-end without PayPal sandbox credentials.

FR-10. The launched URL must be HTTPS for live PayPal; the dev `/mock/paypal` URL may be the
plaintext dev host. The launcher must not block on dev plaintext.

## 4. Technical Design

Module `feature-payments`, package `com.testlogon.android.feature.payments.paypal`.

### 4.1 Launcher

```kotlin
class PayPalLauncher @Inject constructor() {
    /** Opens [approvalUrl] in a Custom Tab; returns false if no browser handled it. */
    fun launch(context: Context, approvalUrl: String): Boolean {
        val uri = approvalUrl.toUri()
        val intent = CustomTabsIntent.Builder()
            .setShowTitle(true)
            .setUrlBarHidingEnabled(false)   // keep verified origin visible
            .setShareState(CustomTabsIntent.SHARE_STATE_OFF)
            .build()
        intent.intent.addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP)
        return runCatching { intent.launchUrl(context, uri) }.isSuccess
            .also { if (!it) launchFallback(context, uri) }
    }
    private fun launchFallback(context: Context, uri: Uri): Boolean =
        runCatching { context.startActivity(Intent(Intent.ACTION_VIEW, uri)) }.isSuccess
}
```

`CustomTabsIntent.launchUrl` is launched from the host Activity context (SINGLE_TOP) so the return
deep link re-enters the same task and reaches `onNewIntent` (AND-231).

### 4.2 ViewModel & state

```kotlin
sealed interface PayPalUiState {
    data object Idle : PayPalUiState
    data object CreatingOrder : PayPalUiState              // POST create order
    data class ReadyToApprove(val orderId: String, val approvalUrl: String) : PayPalUiState
    data object AwaitingApproval : PayPalUiState           // Custom Tab open
    data object Capturing : PayPalUiState                  // POST capture
    data class Paid(val orderId: String, val captureId: String) : PayPalUiState
    data object Cancelled : PayPalUiState
    data class Failed(val error: UiError, val retryable: Boolean) : PayPalUiState
}

@HiltViewModel
class PayPalViewModel @Inject constructor(
    private val repo: PayPalRepository,
    private val savedState: SavedStateHandle,
) : ViewModel() {
    val uiState: StateFlow<PayPalUiState>

    fun startCheckout(request: PayPalCheckoutRequest)     // -> CreatingOrder -> ReadyToApprove
    fun onApprovalLaunched()                              // -> AwaitingApproval
    fun onReturn(result: PaymentReturn)                  // from AND-231 handler
    fun onResumedWithoutReturn()                         // reconcile dangling AwaitingApproval
    fun retry()
}
```

`PaymentReturn` is the AND-231 model (`provider`, `orderId`, `status`, raw query). `onReturn`
branches: `success`→`capture(orderId)`; `cancel`→`Cancelled`. `onResumedWithoutReturn` is invoked
from the screen's `ON_RESUME` only while `AwaitingApproval`; it queries order status once
(idempotent GET) — if PayPal-approved it captures, else `Cancelled`. `orderId` is persisted in
`SavedStateHandle` so a process death during the Custom Tab session can still reconcile on return.

### 4.3 Return wiring

AND-231 exposes a `PaymentReturnDispatcher` (shared singleton) that emits `PaymentReturn` for the
matched deep link. The PayPal screen collects it filtered on `provider == "paypal"`:

```kotlin
LaunchedEffect(Unit) {
    dispatcher.returns.filter { it.provider == "paypal" }.collect(vm::onReturn)
}
```

### 4.4 Repository

```kotlin
interface PayPalRepository {
    suspend fun createOrder(req: PayPalCheckoutRequest): ApiResult<PayPalOrder>
    suspend fun captureOrder(orderId: String): ApiResult<PayPalCapture>
    suspend fun getOrder(orderId: String): ApiResult<PayPalOrder>   // idempotent GET, reconcile
}
```

Network goes through the shared OkHttp stack (cookie jar, CSRF interceptor, 401-refresh
authenticator). `createOrder`/`captureOrder` are **POST (non-idempotent)** → no auto-retry.
`getOrder` is a GET → eligible for the bounded backoff (AND-016).

## 5. API Contract

Confirm exact paths/field names against `/openapi.json` and `frontend/src/api/endpoints` before
coding; shapes below are the working contract.

**Create order** — `POST /api/payments/paypal/orders` (cookie auth + `X-CSRF-Token`)
```json
// request
{ "context": "cart", "context_id": "cart_123", "amount": 1999, "currency": "USD" }
// response 200
{ "order_id": "PP-ORDER-abc", "status": "CREATED",
  "approval_url": "https://www.paypal.com/checkoutnow?token=...",
  "expires_at": "2026-06-05T18:00:00Z" }
// dev response: "approval_url": "http://18.222.237.167:8000/mock/paypal?order_id=PP-ORDER-abc"
```

**Capture order** — `POST /api/payments/paypal/orders/{order_id}/capture`
```json
// response 200
{ "order_id": "PP-ORDER-abc", "capture_id": "PP-CAP-xyz", "status": "COMPLETED",
  "entitlement": { "kind": "cart_paid", "ref_id": "order_789" } }
// 409 if already captured -> treat as success (idempotent), parse existing capture_id
```

**Get order** — `GET /api/payments/paypal/orders/{order_id}` → same shape as create, `status` ∈
`CREATED|APPROVED|COMPLETED|VOIDED`.

**Dev mock** — `GET /mock/paypal?order_id=...` serves Approve/Cancel buttons that 302 to
`testlogon://payments/return?provider=paypal&order_id=...&status=success|cancel`.

**Errors:** FastAPI `detail` mapped via AND-015 (`string | [{msg}] | {code,...}`) into `UiError`.

## 6. Data & State Management

- **In-memory:** `PayPalUiState` via `StateFlow` in `PayPalViewModel`.
- **`SavedStateHandle`:** persist `orderId` + `phase` flag so a Custom-Tab-induced process death is
  recoverable; on recreation while a pending order exists, call `getOrder` to reconcile.
- **No Room persistence** for PayPal order state in this ticket — orders are short-lived and the
  backend is the source of truth; the entitlement/paid result flows into the owning feature's cache
  (cart/billing) which is out of scope here.
- **DataStore:** none specific to PayPal. Selected-method preference (if any) belongs to the billing
  payment-method picker, not this ticket.
- Terminal `Paid` result is emitted upward via the screen's result callback / nav result so the
  initiating flow (cart/tip/paywall) refreshes its own state.

## 7. Error Handling & Resilience

- **No browser available:** Custom Tab launch fails → `ACTION_VIEW` fallback; if that also fails →
  `Failed(retryable=true)` with "No browser available to complete PayPal".
- **Create-order failure / timeout (~20s):** surface `Failed`; POST is **not** auto-retried,
  user-initiated `retry()` re-creates the order.
- **Capture timeout / 5xx on unreliable dev host:** keep `orderId`; show `Failed(retryable=true)`;
  retry calls `getOrder` first (idempotent) and only re-captures if not yet `COMPLETED`.
- **Capture 409 already-captured:** parse existing capture and resolve to `Paid` (idempotent FR-8).
- **User dismisses Custom Tab (no redirect):** `onResumedWithoutReturn` → single `getOrder` →
  `Cancelled` (or `Paid` if it actually completed in-browser).
- **401 mid-flow:** handled transparently by the 401-refresh authenticator (AND-013); a failed
  refresh propagates as auth error and routes to login (auth-gated routing, AND-025).
- **Stale/expired approval URL (`expires_at` passed):** re-create order rather than launch a dead
  URL.
- **Malformed return query:** missing/invalid `order_id` or `status` → `Failed`, logged (redacted).

## 8. Security & Privacy

- **No WebView for PayPal credentials** — Custom Tabs only, so PayPal login/2FA stays in the
  browser sandbox; the app cannot read the PayPal session. This is the core PCI/credential-isolation
  reason for the ticket.
- **No PAN / card / PayPal credentials** ever touch the app process; we hold only opaque
  `order_id`/`capture_id`.
- **CSRF:** create/capture POSTs carry `X-CSRF-Token` from the `ui_csrf` cookie (AND-012).
- **Return deep link is untrusted input:** the app never trusts the *amount/paid status* from the
  return query; it always re-verifies via backend `capture`/`getOrder`. The query is used only to
  route and to identify the `order_id` (which must match the one we created — verified against
  `SavedStateHandle`).
- **Live URLs must be HTTPS;** reject non-HTTPS approval URLs in non-dev flavors. Dev `/mock/paypal`
  plaintext is permitted only on the dev host.
- **Logging redaction:** never log full approval URLs (may carry tokens), `capture_id`, or query
  params beyond `provider`/`status` and a hashed/truncated `order_id`.

## 9. Accessibility & i18n

- All actions ("Pay with PayPal", "Retry", "Cancelled") use string resources (i18n plumbing
  AND-111/112); no hardcoded strings; RTL-safe (AND-114).
- The Pay-with-PayPal button has a meaningful `contentDescription` and ≥48dp touch target; loading
  states (`CreatingOrder`, `Capturing`) announce via `Modifier.semantics { stateDescription = ... }`.
- The brief in-app "Opening PayPal…" / "Completing payment…" status uses Material 3 progress with
  TalkBack-friendly live-region semantics.
- Custom Tab UI accessibility is owned by the browser; we only ensure the in-app handoff and return
  states are accessible. Color is not the sole signal for success/cancel/failure (icon + text).

## 10. Telemetry & Logging

Events (redacted, via the app's analytics/log facade; reuse AND-052 redaction conventions):

- `paypal_checkout_started` { context }
- `paypal_order_created` { order_id_hash, dev_mock: Boolean }
- `paypal_tab_launched` { fallback: Boolean }
- `paypal_return_received` { status }
- `paypal_capture_result` { result: completed|failed|already_captured }
- `paypal_cancelled` { reason: user_cancel|tab_dismissed }
- `paypal_failed` { stage: create|capture|launch, mapped_error_code }

Logs at DEBUG only in dev builds; production logs omit URLs and IDs except truncated `order_id`.

## 11. Testing Strategy

**Unit (JVM, `core-testing` + MockWebServer, AND-046):**
- `PayPalViewModel`: `startCheckout` happy path → `ReadyToApprove`; create failure → `Failed`
  (no retry of POST); `onReturn(success)` → `Capturing` → `Paid`; `onReturn(cancel)` → `Cancelled`;
  capture 409 → `Paid`; `onResumedWithoutReturn` while `AwaitingApproval` reconciles via `getOrder`.
- `PayPalRepository` contract tests against MockWebServer: create/capture/get JSON shapes, `detail`
  error mapping, 401→refresh→retry once, capture POST not auto-retried, getOrder retried.
- Return-query parsing: malformed/missing `order_id`/`status`, `order_id` mismatch → `Failed`.
- `SavedStateHandle` reconciliation: simulated process death restores `orderId` and resolves.

**Instrumented / Compose UI (AND-051):**
- Launcher: fake `CustomTabsIntent` / shadow to assert Custom Tab attempted and `ACTION_VIEW`
  fallback when no browser handles it.
- End-to-end against `/mock/paypal` (MockWebServer serving the mock approve/cancel redirects):
  tap Pay → tab launch intent → inject return Intent → assert `Paid` / `Cancelled` UI.
- Verifies the **acceptance**: "PayPal flow returns to app authenticated/paid."

**CI:** runs under existing unit (AND-050) and instrumented headless-emulator (AND-051) jobs.

## 12. Dependencies & Sequencing

- **Hard dependency: AND-231** (deep-link return handler). AND-228 cannot capture/reconcile without
  AND-231's `testlogon://payments/return` registration and `PaymentReturnDispatcher`. Sequence:
  AND-231 → AND-228.
- **Transitive infra (already landed in M1):** OkHttp/cookie jar (AND-011), CSRF (AND-012),
  401-refresh (AND-013), ApiResult (AND-018), error mapping (AND-015), retry/backoff (AND-016),
  Navigation host (AND-022).
- **New dependency:** add `androidx.browser:browser` to `feature-payments` build (version via
  version catalog; pinned by the project's BOM/catalog policy from AND-001/006).
- **Blocks:** none listed; the initiating payment surfaces (cart checkout AND-213, tips, paywall
  unlock AND-177) consume the PayPal result but are not formal blockers of this ticket.

## 13. Risks & Open Questions

- **OQ-1:** Exact backend PayPal routes/field names — confirm `POST /api/payments/paypal/orders`,
  capture path, and `approval_url`/`order_id` keys against `/openapi.json` and the web client.
- **OQ-2:** Does the backend already implement `/mock/paypal`, or must it be added server-side as
  part of this ticket's dev support? Confirm with backend; if missing, file/own a small backend PR.
- **OQ-3:** Return URL scheme/host — assumed `testlogon://payments/return` owned by AND-231; align
  on `provider`/`order_id`/`status` query param names.
- **Risk:** Custom Tab return can land in `onNewIntent` *or* trigger Activity recreation depending
  on launch mode; reconciliation via `getOrder` + `SavedStateHandle` mitigates missed returns.
- **Risk:** Unreliable dev host may drop the capture POST after PayPal already approved → mitigated
  by getOrder-before-recapture idempotency.
- **Risk:** Some devices have no Custom-Tabs-capable browser → `ACTION_VIEW` fallback covered.
- **OQ-4:** Currency/amount source of truth (passed from cart vs. derived server-side) — prefer
  server-side authoritative amount; client passes only `context`/`context_id`.

## 14. Acceptance Criteria

AC-1. Selecting PayPal and tapping Pay creates a backend order and opens the `approval_url` in a
**Custom Tab** (not a WebView); when no Custom-Tabs browser exists, an `ACTION_VIEW` fallback opens.

AC-2. In dev, the approval URL is `/mock/paypal`; its Approve action redirects to the return deep
link and the app ends in a **`Paid`** state with `order_id` + `capture_id`; the user remains
**authenticated**. (Maps to source acceptance: "PayPal flow returns to app authenticated/paid.")

AC-3. The mock Cancel action (and dismissing the Custom Tab without a redirect) returns the user to
the payment screen in a **`Cancelled`** state with a retry option — not an error.

AC-4. A successful return triggers a backend **capture**; the app never marks paid from the return
query alone. A capture `409 already-captured` resolves to `Paid` (idempotent).

AC-5. Re-entering the flow with an already-captured `order_id` shows the existing paid result without
re-capturing.

AC-6. Create/capture failures and timeouts (~20s) surface a retryable error; POST capture is not
auto-retried, and retry reconciles via `getOrder` before re-capturing.

AC-7. No PayPal credentials, card data, or full approval URLs appear in logs; live approval URLs are
HTTPS.

AC-8. Unit + instrumented tests (including the full `/mock/paypal` round trip) pass in CI.

## 15. Definition of Done

- [ ] `PayPalLauncher`, `PayPalViewModel`, `PayPalRepository`/impl, DTOs/adapters implemented in
      `feature-payments` under `com.testlogon.android.feature.payments.paypal`.
- [ ] `androidx.browser:browser` added via version catalog; Custom Tab launch + `ACTION_VIEW`
      fallback working on a device/emulator.
- [ ] Wired to AND-231 `PaymentReturnDispatcher`, filtered on `provider == "paypal"`.
- [ ] Create/capture/get endpoints integrated through the shared OkHttp stack (cookie + CSRF +
      401-refresh); error `detail` mapped via AND-015.
- [ ] `/mock/paypal` dev round trip produces authenticated `Paid` state end-to-end.
- [ ] Idempotency (409 + already-captured re-entry) and cancel/dismiss reconciliation handled.
- [ ] All strings externalized; key actions/states accessible (TalkBack, ≥48dp, RTL).
- [ ] Telemetry events emitted with redaction; no sensitive data in logs.
- [ ] Unit + Compose/instrumented tests added and green in CI (AND-050/051).
- [ ] Lint/detekt/ktlint clean (AND-005); code reviewed and merged to `android-port`.
