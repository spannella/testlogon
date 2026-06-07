---
id: AND-228
title: PayPal (Custom Tabs)
milestone: M5
epic: E31
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
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
  unreliable). Auth (verified against `src/api/client.ts`): cookie session (`credentials: include`)
  **plus** an `Authorization: Bearer <accessToken>` header, with CSRF via `X-CSRF-Token` read from
  the `ui_csrf` cookie; 401 triggers a single `POST /ui/session/refresh` then one retry. OpenAPI at
  `/openapi.json`; confirm exact PayPal route shapes there before implementation.
  > CORRECTION: the original draft described auth as "cookie + ui_csrf" only; the web client also
  > attaches a Bearer token (and `X-IMPERSONATION-TOKEN` for admin impersonation). The Android stack
  > already injects these via its OkHttp interceptors, so no behavior change — but the spec text now
  > matches the real client.
- **Web reference:** `frontend/src/api/endpoints/billing.ts` and `types.ts`. NOTE (verified): the
  web client does **not** implement a consumer PayPal *redirect/approval-URL checkout*. Its only
  PayPal usage is payment-method vaulting (`POST /api/billing/payment-methods/paypal/setup-token`
  + `.../exchange-token`) and `POST /api/billing/subscribe-monthly`. There is no web "create order"
  → `approval_url` → "capture" flow to mirror; AND-228's redirect UX is therefore an
  **Android-specific design**, not a port of existing web behavior. See §16.

## 3. Functional Requirements

FR-1. From a payment context (cart checkout, tip, paywall unlock, subscription) the user can select
**PayPal** as the method and tap **Pay with PayPal**.

FR-2. Tapping it calls the backend to create a PayPal order/approval intent, returning an
`approval_url` (PayPal-hosted, or a dev mock approval page) and an `order_id`.
> CORRECTION/BLOCKER: no such create-order endpoint exists today (see §5 BACKEND GAP). FR-2 is
> blocked on the backend adding a create-order route; the `approval_url`/`order_id` fields are an
> unverified assumption until then.

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

Network goes through the shared OkHttp stack (cookie jar + `Authorization: Bearer` + CSRF
interceptor + 401-refresh authenticator; see §2 corrected auth model). `captureOrder` maps to the
**verified** `POST /api/billing/paypal/capture-order` with body `{order_id, idempotency_key}`.
`createOrder`/`getOrder` map to **endpoints that do not yet exist** (§5 BACKEND GAP) and are
provisional. `createOrder`/`captureOrder` are **POST** → no client auto-retry; capture safety comes
from the verified `idempotency_key`, not from a GET. `getOrder` (if added) would be a GET → eligible
for bounded backoff (AND-016); if it is not added, reconciliation falls back to a re-`captureOrder`
with the same `idempotency_key`.

## 5. API Contract

> **MAJOR CORRECTION (verified against `openapi.index.txt` / `openapi.pretty.json` and
> `src/api/endpoints/billing.ts`).** The endpoint paths/shapes in the original draft were invented
> and do **not** exist on the backend. There is **no** `/api/payments/paypal/*` namespace (0
> matches), no backend "create order" endpoint that returns an `approval_url`, no "get order"
> endpoint, and no browser-facing `/mock/paypal` approve page. The only PayPal order-capture endpoint
> that exists is `POST /api/billing/paypal/capture-order`. The `/mock/paypal/*` routes that DO exist
> are server-side mocks of *PayPal's own REST API* (`/mock/paypal/v2/checkout/orders[/{id}/capture]`,
> oauth2, vault) consumed by the FastAPI backend — they are NOT an in-browser approval page that
> redirects to a deep link. The corrected contract below reflects the real backend; gaps that the
> backend must still provide are called out as **BACKEND GAP** and tracked in §13 / §16.

**Capture order — VERIFIED.** `POST /api/billing/paypal/capture-order`
(op `capture_order_api_billing_paypal_capture_order_post`). Auth: shared OkHttp stack (cookie +
`Authorization: Bearer` + `X-CSRF-Token`; optional `x-user-id` header). Request schema
`CaptureOrderIn` — note `order_id` is in the **body**, not the path:
```json
// request  (schema: CaptureOrderIn — required: order_id; optional: idempotency_key)
{ "order_id": "PP-ORDER-abc", "idempotency_key": "and228-<uuid>" }
// response 200: UNTYPED in OpenAPI (schema: {}) — exact fields (capture_id / status /
// entitlement) are NOT specified by the contract. Treat the field names below as an UNVERIFIED
// assumption and confirm with backend before binding the Moshi DTO.
{ "order_id": "PP-ORDER-abc", "capture_id": "PP-CAP-xyz", "status": "COMPLETED" }
```
The `idempotency_key` field (verified present on `CaptureOrderIn`) is the supported idempotency
mechanism; send a stable key per order so a retried capture POST is safe even though POSTs are not
auto-retried client-side.

**Create order / approval URL — BACKEND GAP (does not exist yet).** No backend endpoint returns a
PayPal `approval_url` + `order_id`. FR-2 cannot be satisfied against the current API. Options to
resolve in §13/OQ: (a) backend adds a create-order endpoint (e.g. under `/api/billing/paypal/...`)
returning `{ order_id, approval_url }`, mirroring the PayPal Orders v2 `create` + the `payer-action`
HATEOAS link; or (b) reuse the existing PayPal-API mock router behind a thin app endpoint. Until one
exists, the create-order path/fields in this spec are an **unverified assumption** and MUST be
confirmed before implementation.

**Get order (reconcile) — BACKEND GAP (does not exist yet).** No `GET .../paypal/orders/{id}` route
exists. The `onResumedWithoutReturn`/process-death reconciliation in §4.2/§7 depends on an
idempotent order-status GET; it must be added backend-side or reconciliation must instead rely on a
safe re-`capture-order` using the `idempotency_key` (capture is the only verified PayPal order
endpoint). The repository's `getOrder` is therefore provisional pending OQ-2.

**Dev mock approval page — BACKEND GAP.** A browser-facing `GET /mock/paypal` page that renders
Approve/Cancel and 302-redirects to
`testlogon://payments/return?provider=paypal&order_id=...&status=success|cancel` does **not** exist
(the existing `/mock/paypal/*` routes are JSON PayPal-API mocks). FR-9 requires the backend to add
this dev-only HTML page, or the app's instrumented tests must stub the redirect themselves. Tracked
as OQ-2.

**Subscription context (verified, for completeness).** `POST /api/billing/subscribe-monthly`
(schema `app__routers__paypal__SubscribeMonthlyIn` = `{ plan_id="monthly", paypal_plan_id?,
idempotency_key? }`) exists for the subscription paywall context; its 200 response is also untyped
(`schema: {}`).

**Errors — VERIFIED.** FastAPI returns `{ "detail": ... }` where `detail` is
`string | [{msg,...}] | {code,...}` (confirmed by `normalizeErrorDetail` in `src/api/client.ts`,
incl. `code`-keyed authorization errors like `role_required_scope` and `geo_blocked`). Validation
(422) uses `HTTPValidationError` (`{ detail: [{loc, msg, type}] }`). Map via AND-015 into `UiError`.

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

- **OQ-1 (RESOLVED by review — now a blocker):** Backend PayPal routes were verified. Only
  `POST /api/billing/paypal/capture-order` (body `CaptureOrderIn = {order_id, idempotency_key?}`)
  exists. `POST /api/payments/paypal/orders` and `GET .../orders/{id}` do **not** exist (0 matches),
  and no endpoint returns an `approval_url`. Backend must add a create-order (and ideally
  get-order) endpoint before AND-228 can ship FR-2/FR-5 end-to-end. Capture response is untyped in
  OpenAPI — confirm `capture_id`/`status` field names with backend.
- **OQ-2 (RESOLVED by review — now a blocker):** The backend does **not** implement a browser-facing
  `/mock/paypal` approval page. The existing `/mock/paypal/v2/checkout/orders[...]`, `/v1/oauth2`,
  `/v3/vault` routes mock PayPal's *own REST API* (JSON) for backend integration tests — not an
  Approve/Cancel HTML page that 302s to the deep link. This dev page must be added server-side
  (own a small backend PR), or instrumented tests must stub the redirect locally.
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

## 16. Citations & Assumption Audit

Each key technical claim, its VERDICT, and the exact source pointer.

1. **Capture endpoint is `POST /api/billing/paypal/capture-order`.** — **Corrected** (draft said
   `POST /api/payments/paypal/orders/{order_id}/capture`). Source: OpenAPI
   `POST /api/billing/paypal/capture-order` (op `capture_order_api_billing_paypal_capture_order_post`).
2. **Capture request body = `CaptureOrderIn` with required `order_id` (in body) + optional
   `idempotency_key`.** — **Corrected** (draft put `order_id` in the path and had no idempotency
   key). Source: `components.schemas.CaptureOrderIn` (`openapi.pretty.json` ~L14546).
3. **Capture 200 response shape (`capture_id`, `status`, `entitlement`).** — **Unverified-assumption.**
   Source: OpenAPI 200 for `/api/billing/paypal/capture-order` has `schema: {}` (untyped); no response
   model published. Field names must be confirmed with backend.
4. **`POST /api/payments/paypal/orders` create-order endpoint returning `approval_url` + `order_id`.**
   — **Corrected (does not exist / BACKEND GAP).** Source: `grep '/api/payments/paypal'` over
   `openapi.index.txt` = 0 matches; no schema contains `approval_url`. FR-2 is blocked on this.
5. **`GET /api/payments/paypal/orders/{order_id}` get-order/reconcile endpoint.** — **Corrected (does
   not exist / BACKEND GAP).** Source: `openapi.index.txt` (no such route). Reconciliation must use
   re-capture with `idempotency_key` unless backend adds a status GET.
6. **Browser-facing dev `GET /mock/paypal` Approve/Cancel page that 302s to the return deep link.** —
   **Corrected (does not exist / BACKEND GAP).** Source: OpenAPI `/mock/paypal/*` routes are JSON
   mocks of PayPal's REST API (`POST /mock/paypal/v2/checkout/orders`,
   `.../orders/{order_id}/capture`, `/v1/oauth2/token`, `/v3/vault/*`), not an HTML approval page.
7. **Auth = cookie session + `Authorization: Bearer` + CSRF header `X-CSRF-Token` read from the
   `ui_csrf` cookie.** — **Corrected** (draft omitted the Bearer token; CSRF detail itself was
   correct). Source: `src/api/client.ts` (`api()` sets `Authorization: Bearer ${accessToken}` L158-160,
   `X-CSRF-Token` from `getCookie("ui_csrf")` L168-171, `credentials: "include"` L183).
8. **401 → single `POST /ui/session/refresh` then one retry.** — **Verified.** Source:
   `src/api/client.ts` `refreshSession()` L121-130 (`POST /ui/session/refresh`) + single-flight retry
   L194-237; OpenAPI `POST /ui/session/refresh`.
9. **Error `detail` shape = `string | [{msg,...}] | {code,...}` mapped to `UiError` (AND-015).** —
   **Verified.** Source: `src/api/client.ts: normalizeErrorDetail` L66-102 (string / array-of-`{msg}` /
   object-with-`code` incl. `geo_blocked`); 422 uses `components.schemas.HTTPValidationError`.
10. **Web client has no consumer PayPal redirect/approval checkout to port.** — **Verified.** Source:
    `src/api/endpoints/billing.ts` (no PayPal order/approval/capture calls); web PayPal usage is only
    vaulting (`POST /api/billing/payment-methods/paypal/setup-token` + `.../exchange-token`, schemas
    `SetupTokenIn`/`ExchangeTokenIn`) and `POST /api/billing/subscribe-monthly`
    (`app__routers__paypal__SubscribeMonthlyIn`).
11. **Return deep link `testlogon://payments/return?provider=paypal&order_id=...&status=...` and
    `PaymentReturnDispatcher`.** — **Unverified-assumption** (owned by AND-231, not in these sources).
    No source available here; depends on AND-231's contract.
12. **Custom Tabs via `androidx.browser` (`CustomTabsIntent`), with `ACTION_VIEW` fallback; no
    WebView for credentials.** — **Verified (framework ref).** Android Custom Tabs guide:
    https://developer.chrome.com/docs/android/custom-tabs and
    https://developer.android.com/develop/ui/views/layout/webapps/overview-of-android-custom-tabs.
13. **`FLAG_ACTIVITY_SINGLE_TOP` / single-Activity `onNewIntent` re-entry for the return.** —
    **Verified (framework ref).** https://developer.android.com/reference/android/app/Activity#onNewIntent(android.content.Intent)
    and `Intent.FLAG_ACTIVITY_SINGLE_TOP`.
14. **Dev backend is plaintext HTTP at `http://18.222.237.167:8000` and unreliable.** —
    **Unverified-assumption** (environment fact, not in OpenAPI/frontend sources). Carried from the
    program's shared infra notes.

### Corrections made
- §2: Auth model expanded to include `Authorization: Bearer` + impersonation header (was "cookie +
  ui_csrf" only). [#7]
- §2: Added verified note that the web client has no consumer PayPal redirect checkout to mirror;
  AND-228's redirect UX is Android-specific design. [#10]
- §5: Replaced the entire invented `/api/payments/paypal/*` contract. Capture corrected to
  `POST /api/billing/paypal/capture-order` with body `{order_id, idempotency_key?}`; create-order,
  get-order, and the `/mock/paypal` approval page flagged as BACKEND GAPs; capture response marked
  untyped/unverified; idempotency moved from "GET before re-capture" to the verified
  `idempotency_key`. [#1-#6]
- §4.4: Repository corrected — only `captureOrder` maps to a real endpoint; `createOrder`/`getOrder`
  are provisional pending backend work; capture safety via `idempotency_key`. [#1-#5]
- FR-2: Marked blocked pending the create-order backend endpoint. [#4]
- §13 OQ-1 / OQ-2: Reframed from open questions to resolved findings + blockers. [#4-#6]
- §5 errors: Pinned to the verified `normalizeErrorDetail` shape and `HTTPValidationError`. [#9]

### Open assumptions
- **Capture 200 fields** (`capture_id`, `status`, `entitlement`) — unverifiable: OpenAPI response is
  untyped (`schema: {}`). [#3]
- **`409 already-captured` behavior** (AC-4) — unverifiable: not declared in OpenAPI (only 200/422
  documented for capture); the idempotent-409 handling is an assumption to confirm with backend.
- **Create-order / get-order endpoints and `approval_url`** — do not exist; the entire redirect
  contract is an assumption pending a backend PR (OQ-1/OQ-2). [#4][#5][#6]
- **AND-231 deep-link/dispatcher contract** — owned elsewhere; not verifiable from provided sources.
  [#11]
- **Dev host plaintext/unreliability** — environment fact, not in sources. [#14]

## 17. Test Plan

Test target legend: **JVM** = local JVM/Robolectric unit (no device); **MWS** =
contract test with MockWebServer on the JVM; **emu(test35)** = headless emulator AVD `test35`
(x86_64, Android 15 / API 35); **device(A15)** = physical Samsung Galaxy A15 5G (SM-A156U, serial
`R5CX821TA9R`, Android 14 / API 34, arm64-v8a). Custom Tabs hand-off + real-browser redirect behavior
is hardware/OEM-browser dependent, so the true end-to-end redirect case **must** run on device(A15);
emu(test35) covers fast UI/intent assertions where the redirect is injected.

- **TC-AND-228-01** — Type: contract/MockWebServer (MWS). Target: `PayPalRepository.captureOrder`.
  Preconditions: MWS returns 200 for `POST /api/billing/paypal/capture-order`. Steps: call
  `captureOrder("PP-ORDER-abc")`; capture the recorded request. Expected: request method=POST, path
  `/api/billing/paypal/capture-order`, JSON body contains `order_id` **and** a stable
  `idempotency_key`; `Authorization: Bearer`, `X-CSRF-Token`, and cookie headers present; result is
  `ApiResult.Success`. Traces: AC-4, AC-7.
- **TC-AND-228-02** — Type: unit (JVM). Target: `PayPalViewModel.startCheckout` happy path.
  Preconditions: fake repo returns a `createOrder` success with `order_id` + `approval_url`. Steps:
  call `startCheckout(req)`. Expected: state transitions `CreatingOrder → ReadyToApprove(orderId,
  approvalUrl)`. (Depends on the create-order BACKEND GAP, §5 #4 — until that lands, run against the
  fake.) Traces: AC-1.
- **TC-AND-228-03** — Type: unit (JVM). Target: `PayPalViewModel.onReturn(success)`. Preconditions:
  state `AwaitingApproval`, fake repo capture→`COMPLETED`. Steps: emit
  `PaymentReturn(provider="paypal", orderId, status="success")`. Expected: `Capturing → Paid(orderId,
  captureId)`; capture called exactly once. Traces: AC-2, AC-4.
- **TC-AND-228-04** — Type: unit (JVM). Target: `PayPalViewModel.onReturn(cancel)` and tab-dismiss.
  Preconditions: state `AwaitingApproval`. Steps: (a) emit `status="cancel"`; (b) separately, trigger
  `onResumedWithoutReturn` with a fake reconcile result of not-completed. Expected: both resolve to
  `Cancelled` (not `Failed`), retry affordance available; no false capture. Traces: AC-3.
- **TC-AND-228-05** — Type: contract/MockWebServer (MWS). Target: capture `409 already-captured`
  handling. Preconditions: MWS returns 409 with a body carrying the existing capture. Steps: call
  `captureOrder`. Expected: repo/VM resolve to `Paid` (idempotent), not error. NOTE: 409 shape is an
  open assumption (§16) — assert against the agreed contract once confirmed. Traces: AC-4, AC-5.
- **TC-AND-228-06** — Type: unit (JVM). Target: idempotent re-entry. Preconditions:
  `SavedStateHandle` holds an already-captured `orderId`; fake reconcile returns `COMPLETED`. Steps:
  recreate the screen/VM. Expected: shows existing `Paid` result without issuing a new capture.
  Traces: AC-5.
- **TC-AND-228-07** — Type: contract/MockWebServer (MWS). Target: error mapping + 401 refresh.
  Preconditions: MWS first returns 401, then 200 after a `POST /ui/session/refresh`; a separate case
  returns 422 `HTTPValidationError` and a `{detail:{code:"..."}}` 403. Steps: call `captureOrder`.
  Expected: exactly one `/ui/session/refresh` then one retried capture (single-flight); 422/403 map
  through AND-015 into a `UiError` matching `normalizeErrorDetail` semantics. Traces: AC-6, AC-7.
- **TC-AND-228-08** — Type: unit (JVM). Target: timeout / unreliable-dev-host capture path.
  Preconditions: fake repo throws timeout (~20s) on capture. Steps: call capture; then `retry()`.
  Expected: `Failed(retryable=true)`; POST not auto-retried; `retry()` re-captures with the **same**
  `idempotency_key` (verified mechanism; get-order does not exist). Traces: AC-6.
- **TC-AND-228-09** — Type: unit (JVM). Target: malformed/forged return query. Preconditions: state
  `AwaitingApproval` with known `orderId` in `SavedStateHandle`. Steps: feed returns with missing
  `status`, missing `order_id`, and an `order_id` that mismatches the saved one. Expected: each →
  `Failed` (or ignored for mismatch); never captures on an unmatched/forged `order_id`; event logged
  redacted. Traces: AC-4, AC-7 (security).
- **TC-AND-228-10** — Type: instrumented (emu(test35)). Target: `PayPalLauncher` Custom Tab intent +
  fallback. Preconditions: (a) a Custom-Tabs-capable browser present; (b) test variant with no
  handling browser. Steps: call `launch(context, url)`; inspect the launched `Intent`/shadow.
  Expected: (a) `CustomTabsIntent` with `SHARE_STATE_OFF`, title shown, URL-bar-hiding disabled,
  `FLAG_ACTIVITY_SINGLE_TOP`; (b) falls back to `ACTION_VIEW`; if both fail →
  `Failed(retryable=true)`. Traces: AC-1.
- **TC-AND-228-11** — Type: instrumented/e2e — **MUST run on device(A15)**. Target: full redirect
  round trip. Preconditions: device(A15) has Chrome (Custom Tabs); backend create-order + dev mock
  approval page available (BACKEND GAP — otherwise stub the 302 with a local intent on device). Steps:
  tap **Pay with PayPal** → Custom Tab opens approval URL → tap Approve in-browser → browser 302s to
  `testlogon://payments/return?...status=success` → app `onNewIntent` → capture. Expected: app lands
  in `Paid` and the user is still **authenticated**; back-press/dismiss before approval lands in
  `Cancelled`. Rationale for device: real OEM browser + cross-app deep-link return + task re-entry
  cannot be faithfully reproduced on the emulator. Traces: AC-2, AC-3, AC-8.
- **TC-AND-228-12** — Type: Compose-UI (emu(test35)). Target: payment screen states. Preconditions:
  VM driven through `CreatingOrder/Capturing/Paid/Cancelled/Failed` via fake. Steps: render each.
  Expected: progress shown for loading states; `Paid`/`Cancelled`/`Failed` each use icon **plus**
  text (color not sole signal); retry visible for `Cancelled`/`Failed`. Traces: AC-3, AC-6.
- **TC-AND-228-13** — Type: Compose-UI accessibility (emu(test35)). Target: a11y of the PayPal
  button + status. Preconditions: payment screen rendered. Steps: assert semantics. Expected:
  "Pay with PayPal" has a meaningful `contentDescription`, touch target ≥48dp, loading states expose
  `stateDescription` live-region text for TalkBack; all strings come from resources (no hardcoded
  literals); layout is RTL-safe. Traces: AC-1, AC-2, AC-3.
- **TC-AND-228-14** — Type: unit + instrumented log-capture (JVM, spot-check on device(A15)). Target:
  redaction + HTTPS enforcement. Preconditions: telemetry/log facade captured; a non-dev flavor.
  Steps: run create→launch→capture; in non-dev, attempt to launch a non-HTTPS `approval_url`.
  Expected: no full `approval_url`, no `capture_id`, no PayPal credentials in logs (only
  `provider`/`status` + hashed/truncated `order_id`); non-HTTPS approval URL rejected in non-dev
  flavor; dev plaintext `/mock/paypal` permitted only on the dev host. Traces: AC-7.

### Coverage matrix
| AC | Covered by |
| --- | --- |
| AC-1 (Custom Tab open + ACTION_VIEW fallback) | TC-02, TC-10, TC-13 |
| AC-2 (dev mock → Paid, still authenticated) | TC-03, TC-11, TC-13 |
| AC-3 (cancel/dismiss → Cancelled w/ retry) | TC-04, TC-11, TC-12, TC-13 |
| AC-4 (capture from return; never paid from query; 409→Paid) | TC-01, TC-03, TC-05, TC-09 |
| AC-5 (idempotent re-entry of captured order) | TC-05, TC-06 |
| AC-6 (failures/timeout retryable; POST not auto-retried; reconcile) | TC-07, TC-08, TC-12 |
| AC-7 (no secrets in logs; HTTPS live URLs) | TC-01, TC-07, TC-09, TC-14 |
| AC-8 (unit + instrumented incl. round trip pass in CI) | TC-10, TC-11 (+ all JVM/MWS cases run in CI) |
