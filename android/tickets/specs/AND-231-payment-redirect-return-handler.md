---
id: AND-231
title: Payment redirect/return handler
milestone: M5
epic: E31
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-022]
blocks: [AND-228, AND-229]
---

# AND-231 — Payment redirect/return handler

## 1. Overview & Goal

Redirect-based payment providers (PayPal, CCBill, and any future hosted-checkout
provider) take the user out of the app into an external browser surface — a Chrome
Custom Tab — complete authorization there, and then bounce the user back into the
app via an HTTP(S) return URL. This ticket builds the single, provider-agnostic
**return handler** that catches those inbound deep links, parses the redirect
result, classifies it as success / cancel / failure, correlates it with the
in-flight payment intent, and routes the navigation graph to the correct
destination state.

The goal is one canonical entry point and one state machine. AND-228 (PayPal) and
AND-229 (CCBill) consume this handler — they only supply provider-specific begin
flows and return-URL templates; they do not reimplement parsing or routing.
Without this ticket those provider tickets have no defined way to re-enter the app,
so AND-231 is P0 and a hard blocker for both.

Out of scope: launching the Custom Tab, creating the checkout/billing session,
in-app SDK payments (Stripe — AND-225/226), and order-detail rendering. This
ticket owns *return ingestion and routing only*.

## 2. Context & References

- Stack/conventions per project context: Kotlin 2.0.21, Compose + Material 3,
  single-Activity Navigation-Compose, Hilt (KSP), Coroutines/Flow, Moshi 1.15.
  Namespace/applicationId base `com.testlogon.android`.
- **AND-022 — Navigation host & routes** (dependency): provides the single-Activity
  `NavHost`, typed route definitions, and the `NavController` this handler routes
  through. The return handler plugs into that host; it does not create its own.
- **AND-228 — PayPal (Custom Tabs)** (blocked by this): redirect via Custom Tabs,
  `/mock/paypal` dev endpoint. Provides the PayPal `provider` id and return path.
- **AND-229 — CCBill flow** (blocked by this): `/api/billing/ccbill/frontend-oauth`
  via Custom Tabs, dev mock. Provides the CCBill `provider` id and return path.
- **AND-227 — Checkout session billing** / **AND-213 — Checkout session**: create
  the payment session whose `intent_id` this handler correlates against, and own
  the post-return order/entitlement reconciliation call.
- Backend: FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext,
  unreliable; ~20s timeouts, bounded backoff for idempotent GETs only). Cookie +
  `ui_csrf`/`X-CSRF-Token` auth; persistent cookie jar (AND-011/012/013). Web
  reference: `frontend/src/api/endpoints/*.ts` (verified: `src/api/client.ts` reads
  the `ui_csrf` cookie into `X-CSRF-Token`, sends `credentials: "include"`, and does a
  single 401 refresh-and-retry). NOTE: the web app does **not** implement a
  redirect/return deep-link handler (no checkout/return route exists in
  `src/pages/*` or `src/api/endpoints/*`); return-URL ingestion is a mobile-only
  concern, so the inbound return-URI shape (§5) is an app-defined assumption, not a
  web contract.

## 3. Functional Requirements

FR-1. The app MUST register an Android App Link / deep link for a dedicated return
host+path that external payment providers redirect to, and MUST route inbound
intents matching it to the return handler regardless of cold/warm/hot start.

FR-2. The handler MUST parse the return URI into a typed `PaymentReturn` carrying:
provider id, payment `intent_id`, outcome (`SUCCESS` | `CANCEL` | `FAILURE` |
`UNKNOWN`), optional provider transaction/token id, and optional error code/message.

FR-3. Outcome classification MUST be driven by the return path segment
(`/success`, `/cancel`, `/failure`) and corroborated by query params
(`status`, `error`, `token`, `intent`). Path takes precedence; ambiguous or
unrecognized returns classify as `UNKNOWN` and route to a recoverable error state.

FR-4. The handler MUST correlate the returned `intent_id` against the
locally-persisted in-flight intent (stored when the Custom Tab was launched). A
mismatch or absent in-flight intent MUST NOT crash and MUST route to a
"stale/expired payment" state rather than falsely confirming a purchase.

FR-5. On `SUCCESS`, the handler MUST NOT trust the redirect alone as proof of
payment. It MUST mark the intent `RETURNED_SUCCESS` and hand off to the checkout
verification flow (AND-227) which confirms entitlement server-side; the route
shown is the verification/confirmation destination, not a hardcoded "paid" screen.

FR-6. On `CANCEL`, route back to the originating checkout/cart screen with the
intent cleared and a non-blocking "payment cancelled" message.

FR-7. On `FAILURE`/`UNKNOWN`, route to a payment-error state offering retry
(re-launch provider) and back-to-cart, surfacing any provider error message.

FR-8. Each return MUST be processed **exactly once**. Re-delivery of the same
intent (Custom Tab re-foreground, process recreation, duplicate intent) MUST be
idempotent and MUST NOT re-trigger navigation or double-verify.

FR-9. Provider registration MUST be data-driven: adding a provider (AND-228/229)
is supplying a `PaymentProvider` descriptor (id + return path prefix), not editing
the parser.

## 4. Technical Design

Module placement: `feature-billing` (consumes `core-data`, `core-model`,
`core-ui`, `core-network`). The deep-link entry is wired in `app` against the
AND-022 `NavHost`.

### 4.1 Deep-link registration

Single-Activity app. The launcher Activity (`MainActivity` from AND-022) declares
an intent filter for the return URL. Use Android App Links (`autoVerify`) on the
production host with an `http`/`https` fallback to a custom scheme for the dev
mock host, which cannot serve `assetlinks.json`.

```xml
<!-- app/src/main/AndroidManifest.xml, inside <activity android:name=".MainActivity"> -->
<intent-filter android:autoVerify="true">
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="https"
          android:host="@string/payment_return_host"
          android:pathPrefix="/app/billing/return" />
</intent-filter>
<intent-filter>
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="testlogon" android:host="billing" />
</intent-filter>
```

`launchMode="singleTop"` (already set by AND-022); inbound VIEW intents arrive via
`onNewIntent` when the Custom Tab returns to a running task.

### 4.2 Models

```kotlin
// core-model
enum class PaymentOutcome { SUCCESS, CANCEL, FAILURE, UNKNOWN }

data class PaymentProvider(val id: String, val returnPathPrefix: String)

data class PaymentReturn(
    val provider: String,
    val intentId: String?,
    val outcome: PaymentOutcome,
    val providerRef: String?,      // token / transaction id
    val errorCode: String?,
    val errorMessage: String?,
    val rawUri: String,
)

sealed interface PaymentReturnRoute {
    data class Verify(val intentId: String) : PaymentReturnRoute          // -> AND-227
    data class Cancelled(val intentId: String?) : PaymentReturnRoute      // -> cart/checkout
    data class Failed(val intentId: String?, val message: String?) : PaymentReturnRoute
    data object Stale : PaymentReturnRoute                                // no/mismatched intent
}
```

### 4.3 Parser

```kotlin
// feature-billing
class PaymentReturnParser @Inject constructor(
    private val providers: Set<@JvmSuppressWildcards PaymentProvider>,
) {
    fun parse(uri: Uri): PaymentReturn?   // null if not a billing-return URI
}
```

Algorithm: confirm host/scheme matches a registered return; resolve `provider`
from path segment after the prefix; derive `outcome` from the trailing path
segment (`success|cancel|failure`), falling back to `status`/`error` query params,
else `UNKNOWN`; extract `intent` (intentId), `token`/`tx` (providerRef), `error`
(errorCode), `error_description` (errorMessage). Providers are injected as a Hilt
`@IntoSet` multibinding so AND-228/229 each contribute one descriptor.

### 4.4 In-flight intent store + handler

```kotlin
// core-data — DataStore-backed
data class InFlightPayment(
    val intentId: String, val provider: String, val originRoute: String,
    val createdAtEpochMs: Long,
)

interface PaymentIntentStore {
    suspend fun put(p: InFlightPayment)
    suspend fun get(): InFlightPayment?
    suspend fun clear()
    suspend fun markConsumed(intentId: String): Boolean // false if already consumed
}

class PaymentReturnHandler @Inject constructor(
    private val parser: PaymentReturnParser,
    private val store: PaymentIntentStore,
    private val clock: Clock,
) {
    /** Pure decision: parse + correlate + classify. No navigation side effects. */
    suspend fun handle(uri: Uri): PaymentReturnRoute?
}
```

`handle` returns `null` for non-billing URIs (let other deep-link handlers run —
e.g. AND-061 magic link). For billing URIs it: dedupes via
`store.markConsumed(intentId)` (idempotency, FR-8); validates the in-flight intent
exists, matches, and is not expired (TTL 15 min via `clock`); maps outcome ->
`PaymentReturnRoute`. `SUCCESS` with a valid matching intent -> `Verify`; valid
intent + `CANCEL` -> `Cancelled`; `FAILURE`/`UNKNOWN` -> `Failed`; no/mismatched/
expired/already-consumed intent -> `Stale`.

### 4.5 Wiring into the NavHost (AND-022)

```kotlin
@Composable
fun rememberPaymentReturnConnector(nav: NavController): (Uri) -> Boolean
```

`MainActivity` forwards `intent.data` (cold start) and `onNewIntent` (warm) to a
`MutableSharedFlow<Uri>` collected in the host composable; the connector calls
`handler.handle`, and on a non-null route issues a typed `nav.navigate(...)` to the
AND-022 routes (`Verify`/`Cancelled`/`Failed`/`Stale`). Returns `true` if the URI
was a billing return (consumed), `false` otherwise.

## 5. API Contract

This ticket does **not** define new backend endpoints — it ingests provider HTTP
redirects and routes to existing flows. Two contracts are relevant:

**Inbound return URI (provider -> app)**, the shape this handler parses:

```
https://<payment_return_host>/app/billing/return/<provider>/success?intent=ck_9f3...&token=EC-2X...&status=COMPLETED
https://<payment_return_host>/app/billing/return/<provider>/cancel?intent=ck_9f3...
https://<payment_return_host>/app/billing/return/<provider>/failure?intent=ck_9f3...&error=card_declined&error_description=...
testlogon://billing/<provider>/success?intent=ck_9f3...   (dev mock fallback)
```

**Downstream verification (owned by AND-227)**, invoked by the `Verify` route after
a `SUCCESS`. Documented here only to fix the boundary; this ticket calls it but
does not implement it.

> CORRECTION (review 2026-06-06): the previously documented endpoint
> `POST /ui/billing/checkout_session/{intent_id}/confirm` returning
> `{intent_id, status:"paid", order_id, entitlement_granted}` **does not exist** in
> the backend OpenAPI. There is no `{...}/confirm` sub-route under
> `/ui/billing/checkout_session`, and no `intent_id`/`entitlement_granted` fields
> anywhere in the checkout schemas. The real backend surface is:
>
> - `POST /ui/billing/checkout_session` — op `create_checkout_session_ui_billing_checkout_session_post`,
>   req `BillingCheckoutReq`, resp `200` (web client types it `{ session_id, url }`).
>   **Create only — there is no confirm verb on this path.**
> - `POST /ui/checkout/session` — op `ui_create_checkout_session_ui_checkout_session_post`,
>   req `UnifiedCheckoutSessionIn`, resp `200: UnifiedCheckoutSessionOut`. The session
>   object is keyed by **`checkout_session_id`** and **`order_id`** (not `intent_id`),
>   with `status` (default `"pending_payment"`), `source` (`cart|direct|subscription_action`),
>   and `line_items`. There is **no** `entitlement_granted` boolean and **no** `"paid"`
>   literal in the schema.
> - `POST /api/billing/paypal/capture-order` — op `capture_order_api_billing_paypal_capture_order_post`,
>   req `CaptureOrderIn { order_id (required), idempotency_key? }`. This is the actual
>   server-side proof-of-payment step for PayPal; it is keyed on PayPal **`order_id`**.
>
> The exact confirm/verify wiring is AND-227's to finalize; AND-231 only defines a
> thin `CheckoutConfirmClient` interface and must key it on the
> server-issued **`checkout_session_id` / `order_id`**, not a fabricated `intent_id`.
> Treat the prior endpoint as removed.

Illustrative (post-correction) verify call and the real error envelope:

```
POST /api/billing/paypal/capture-order        # PayPal; CCBill uses its own backend step
X-CSRF-Token: <ui_csrf cookie value>          # verified: client sets X-CSRF-Token from ui_csrf cookie
Body: { "order_id": "<paypal order id>", "idempotency_key": "<dedupe key>" }
200 -> capture result (provider-shaped; AND-227 maps to entitlement)
4xx -> { "detail": <string | [{ "msg": "..." }] | { "code": "...", ... }> }
422 -> HTTPValidationError  { "detail": [ { "loc": [...], "msg": "...", "type": "..." } ] }
```

Error `detail` mapping follows AND-015 (string | `[{msg}]` | `{code,...}`) — VERIFIED
against `src/api/client.ts: normalizeErrorDetail` (handles all three shapes) and the
`HTTPValidationError` schema. 422 is the only documented error code on these ops in
the OpenAPI index; the prior `402 payment_failed` / `404 "unknown checkout session"`
literals were unverified and are not in the spec.

> NOTE on terminology: this spec's internal `intentId` (the `PaymentReturn.intentId`
> / `InFlightPayment.intentId` field, and the `?intent=` query param) is a
> **client-side correlation token chosen by this app**, not a backend field. It must
> be populated from the backend's `checkout_session_id`/`order_id` when the Custom
> Tab is launched (writer in AND-228/229). The name is retained for internal models
> but does NOT correspond to any backend `intent_id`.

## 6. Data & State Management

- **In-flight intent**: persisted in DataStore (`PaymentIntentStore`) the moment a
  Custom Tab is launched (writer lives in AND-228/229; schema owned here). Survives
  process death so a cold-start return still correlates. Single in-flight intent at
  a time; launching a new one overwrites the prior (and clears its consumed flag).
- **Consumed set**: a small DataStore set of consumed `intentId`s (bounded, last
  N=20, LRU) backing `markConsumed` for idempotency across process recreation.
- **UI state**: the handler is side-effect-free and returns a `PaymentReturnRoute`;
  navigation is performed by the connector. Destination screens (`Verify` shows a
  loading state driven by AND-227's `StateFlow<CheckoutUiState>`; `Cancelled`/
  `Failed`/`Stale` are existing billing-error composables from `core-ui`,
  AND-021). No new long-lived ViewModel state introduced by this ticket beyond the
  store.
- **TTL**: in-flight intents older than 15 min classify as `Stale`.

## 7. Error Handling & Resilience

- **Malformed/foreign URI**: `parse` returns `null` -> `handle` returns `null` ->
  connector returns `false`; never throws. Other deep-link handlers get their turn.
- **Missing/mismatched/expired intent**: route `Stale`; never report success.
- **Already-consumed intent** (double delivery, FR-8): `markConsumed` returns
  `false` -> handler returns `null` (no re-navigation). The first delivery's route
  already drove navigation.
- **`UNKNOWN` outcome**: treated as `Failed` with a generic recoverable message;
  retry re-launches the provider via the origin route.
- **Network during verification** is AND-227's concern, but the `Verify`
  destination must tolerate the unreliable dev host: ~20s timeout, bounded backoff
  retry on the idempotent confirm GET-style poll, and an offline/stale fallback so
  a return that lands while offline shows "confirming when reconnected" rather than
  an error. (Resilience primitives from AND-016/017.)
- **CSRF/401**: confirmation rides the existing cookie jar + CSRF interceptor
  (AND-012) and 401 single-refresh authenticator (AND-013); no special handling
  here.

## 8. Security & Privacy

- **Redirect is not proof of payment** (FR-5): a `SUCCESS` return only triggers
  server-side verification. Entitlement is granted by the backend, never inferred
  client-side from a URL. This blocks the trivial "open the success URL manually"
  spoof.
- **Intent correlation** binds a return to a locally-created, server-issued
  `intent_id`; unsolicited or forged returns with no matching in-flight intent are
  `Stale`. Combined with single-use consumption this limits replay.
- **App Links `autoVerify`** on the production host prevents other apps from
  hijacking the production return URL. The dev custom-scheme fallback is
  inherently weaker and MUST be gated to the dev/debug flavor only (AND-006) — it
  is not declared in the release manifest.
- **No card data** transits this handler; only opaque provider tokens/refs appear
  in the URI. These are dropped after correlation and not logged in the clear
  (see §10). Return URIs may be logged only with `intent`/`token`/`error` values
  redacted.
- TLS is enforced for the production return host; the plaintext dev host is
  confined to dev flavor.

## 9. Accessibility & i18n

- This ticket adds no significant net-new UI; it routes to existing billing
  destinations. The three terminal states it can land on
  (cancelled/failed/stale) reuse `core-ui` state composables (AND-021) which carry
  their own `contentDescription`s and Material 3 contrast/touch-target compliance.
- All user-facing strings introduced (cancelled/failed/stale titles, retry and
  back-to-cart action labels, "confirming payment" loading copy) MUST be in
  `strings.xml` via the i18n plumbing (AND-111), no hardcoded literals, RTL-safe.
  Provider-supplied `error_description` is shown verbatim and labelled as a
  provider message (not localized).
- A focus/announcement MUST fire on arrival at the result screen so screen-reader
  users learn the payment outcome on return from the Custom Tab.

## 10. Telemetry & Logging

- Emit structured events via the existing telemetry sink (pattern from AND-052):
  `payment_return_received` (provider, outcome, has_intent: Bool,
  intent_match: Bool), `payment_return_routed` (route name),
  `payment_return_stale` (reason: no_intent | mismatch | expired | consumed).
- **Redaction**: never log full return URIs, `intent_id`, `token`, or
  `error_description` values. Log provider id, outcome enum, and boolean
  correlation flags only. `intent_id` may appear hashed/truncated for support
  correlation.
- Debug-flavor `okhttp` logging stays at headers level for the confirm call
  (AND-009); no query-param leakage.

## 11. Testing Strategy

Acceptance is "returns route to correct state (tested)", so routing coverage is
the core deliverable.

Unit (JVM, `core-testing`):
- `PaymentReturnParserTest`: success/cancel/failure path parsing per provider;
  query-param extraction; path-vs-param precedence; unknown path -> `UNKNOWN`;
  foreign URI -> `null`; custom-scheme dev fallback.
- `PaymentReturnHandlerTest` (fake `PaymentIntentStore` + fixed `Clock`):
  - SUCCESS + matching intent -> `Verify(intentId)`.
  - CANCEL + matching intent -> `Cancelled`.
  - FAILURE / UNKNOWN -> `Failed`.
  - no in-flight intent -> `Stale`.
  - mismatched intentId -> `Stale`.
  - expired (> TTL) intent -> `Stale`.
  - duplicate delivery (already consumed) -> `null` (idempotency, FR-8).

Instrumented / Compose (AND-051 emulator):
- Manifest deep-link resolves: fire a VIEW `Intent` with each return URI and assert
  the NavController current destination (`Verify`/`Cancelled`/`Failed`/`Stale`).
- Cold-start return: launch Activity with `intent.data` set, assert routing.
- `onNewIntent` warm return after a simulated Custom Tab round-trip.

Fixtures: reuse MockWebServer harness (AND-046) to stub the AND-227 confirm
response for the `Verify` path; provider descriptors supplied via a test Hilt
module. No dependency on the live dev host.

## 12. Dependencies & Sequencing

- **Depends on AND-022** (Navigation host & routes): supplies `MainActivity`,
  `NavHost`, `NavController`, typed routes the connector navigates to. Hard
  prerequisite — the connector cannot wire without it.
- Soft/contract dependencies (interfaces only, this ticket lands first): AND-227
  (confirm endpoint for the `Verify` route — define a thin client interface here,
  AND-227 implements), AND-021/AND-111 (state composables + strings),
  AND-006 (flavor gating of the dev scheme), AND-011/012/013 (cookie/CSRF/refresh),
  AND-052 (telemetry redaction pattern).
- **Blocks AND-228 (PayPal)** and **AND-229 (CCBill)**: both contribute a
  `PaymentProvider` descriptor + return-URL template and rely entirely on this
  handler for re-entry/routing. Neither can be completed before AND-231 merges.
- Sequencing: AND-022 -> **AND-231** -> {AND-228, AND-229} (parallel) -> AND-227
  verification wiring exercised end-to-end.

## 13. Risks & Open Questions

- **App Links verification on dev host**: the plaintext dev host
  (`18.222.237.167:8000`) cannot host `.well-known/assetlinks.json`, so production
  uses verified App Links while dev uses the unverified custom scheme. Risk: drift
  between flavors. Mitigation: identical parser path; only the manifest
  scheme/host differs by flavor. *Open: confirmed production return host name?*
- **Provider return-URL shape unknown** until AND-228/229: actual PayPal/CCBill
  query-param names (`token` vs `PayerID`, CCBill `transactionId`) may differ from
  assumed. Mitigation: parser is param-tolerant and provider-keyed; param mapping
  can be pushed into the `PaymentProvider` descriptor if they diverge.
- **Custom Tab cancellation without redirect**: user backs out of the Custom Tab
  without the provider issuing a cancel URL — no inbound intent fires. Detection
  belongs to AND-228/229 (lifecycle `onResume` with an unconsumed in-flight
  intent). *Open: does this handler expose a "resumed without return" hook, or do
  provider tickets poll the store directly?* Proposed: expose
  `store.get()` for provider lifecycle checks; routing stays here.
- **Single in-flight intent** assumption: concurrent checkouts unsupported.
  Acceptable for current UX (one active checkout); revisit if multi-cart lands.

## 14. Acceptance Criteria

AC-1. A provider return URI for each outcome routes to the correct destination,
verified by automated test: SUCCESS -> verification (`Verify`); CANCEL ->
originating checkout with cancel message; FAILURE/UNKNOWN -> recoverable payment
error. (Directly satisfies the source acceptance: "Returns route to correct state
(tested).")

AC-2. A SUCCESS return with no/mismatched/expired in-flight intent routes to
`Stale` and never grants entitlement client-side; entitlement is granted only by
the server-side confirm (AND-227).

AC-3. Duplicate delivery of the same return (warm re-foreground or post-process-
death) navigates exactly once; the second delivery is a no-op (idempotency test
passes).

AC-4. Deep links resolve on cold start (`intent.data`), warm start
(`onNewIntent`), and after process recreation, each asserted via instrumented test.

AC-5. Adding a provider is a `PaymentProvider` `@IntoSet` binding + return path —
no parser edits — demonstrated by the test-only provider used in the suite.

AC-6. A non-billing deep link is not consumed by this handler (`handle` -> null),
leaving other deep-link routes (e.g. magic link AND-061) functional.

AC-7. No `intent_id`, token, or full return URI appears in logs; telemetry events
carry only provider, outcome, and boolean correlation flags.

## 15. Definition of Done

- `PaymentReturnParser`, `PaymentReturnHandler`, `PaymentIntentStore`
  (DataStore impl), models, Hilt multibinding, and the `rememberPaymentReturnConnector`
  wiring into the AND-022 `NavHost` are implemented under
  `com.testlogon.android.feature.billing` and merged to `android-port`.
- Manifest intent filters (verified App Links for prod host; dev custom scheme
  gated to dev/debug flavor) are in place and the dev scheme is absent from the
  release manifest.
- Unit + instrumented tests from §11 pass in CI (AND-050/051); routing,
  idempotency, correlation, TTL, and cold/warm/process-death cases covered.
- User-facing strings are externalized (AND-111); result screens reuse `core-ui`
  state composables with accessibility announcements on arrival.
- Telemetry events emit with redaction verified; no PII/secret leakage in logs.
- A thin `CheckoutConfirmClient` interface for the `Verify` route is defined for
  AND-227 to implement; the contract boundary is documented in code.
- ktlint/detekt (AND-005) clean; no new lint baseline suppressions.
- PR description records open questions from §13 and links AND-228/AND-229 as the
  consuming tickets.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer.

1. **Downstream verification endpoint is `POST /ui/billing/checkout_session/{intent_id}/confirm`.**
   VERDICT: **Corrected** — endpoint does not exist. SOURCE: OpenAPI index has only
   `POST /ui/billing/checkout_session` (op `create_checkout_session_ui_billing_checkout_session_post`,
   req `BillingCheckoutReq`) with no `{id}/confirm` sub-route; no path matching
   `checkout_session/.../confirm` exists. Replaced in §5.

2. **Confirm response shape `{intent_id, status:"paid", order_id, entitlement_granted:true}`.**
   VERDICT: **Corrected** — no such schema. SOURCE: `components.schemas.UnifiedCheckoutSessionOut`
   (openapi.pretty.json) has `checkout_session_id`, `order_id`, `source`
   (`cart|direct|subscription_action`), `status` (default `"pending_payment"`),
   `line_items`; required = `[order_id, checkout_session_id, source]`. No
   `intent_id`, no `entitlement_granted`, no `"paid"` literal.

3. **Real server-side proof-of-payment / verify surface.** VERDICT: **Verified**
   (replacement). SOURCE: OpenAPI `POST /ui/checkout/session` (req `UnifiedCheckoutSessionIn`,
   resp `200:UnifiedCheckoutSessionOut`) and `POST /api/billing/paypal/capture-order`
   (op `capture_order_api_billing_paypal_capture_order_post`, req `CaptureOrderIn`).
   `components.schemas.CaptureOrderIn` = `{ order_id (required, string), idempotency_key? }`.

4. **CCBill begin flow `POST /api/billing/ccbill/frontend-oauth`.** VERDICT: **Verified.**
   SOURCE: OpenAPI index `POST /api/billing/ccbill/frontend-oauth`
   (op `get_frontend_oauth_api_billing_ccbill_frontend_oauth_post`).

5. **PayPal dev mock endpoint exists (`/mock/paypal`).** VERDICT: **Verified.**
   SOURCE: OpenAPI index `POST /mock/paypal/v2/checkout/orders` and
   `POST /mock/paypal/v2/checkout/orders/{order_id}/capture`; CCBill mock
   `POST /mock/ccbill/transactions/payment-tokens/{payment_token_id}`.

6. **Auth is cookie + `ui_csrf` cookie copied to `X-CSRF-Token` header; persistent
   cookie jar.** VERDICT: **Verified.** SOURCE: `src/api/client.ts` lines 167-171
   (`getCookie("ui_csrf")` -> `headers.set("X-CSRF-Token", csrf)`) and `credentials: "include"`
   (lines 124, 183, 220).

7. **401 single-refresh-and-retry authenticator (AND-013).** VERDICT: **Verified.**
   SOURCE: `src/api/client.ts` lines 194-237 (single shared `refreshPromise`, one
   retry, `logout("session_expired")` on second 401).

8. **Error `detail` mapping is string | `[{msg}]` | `{code,...}` (AND-015).**
   VERDICT: **Verified.** SOURCE: `src/api/client.ts: normalizeErrorDetail`
   (lines 66-96 handle string, array-of-`{msg}`, and `{msg}`/`{code}` object) and
   `components.schemas.HTTPValidationError` (`detail: [{loc,msg,type}]`).

9. **`402 payment_failed` and `404 "unknown checkout session"` confirm errors.**
   VERDICT: **Corrected / Unverified-assumption (removed).** SOURCE: the billing/checkout
   ops in the OpenAPI index declare only `200` and `422:HTTPValidationError`; no
   `402`/`404` documented. Literal error bodies were invented; removed from §5.

10. **The web app implements a redirect/return deep-link handler we can mirror.**
    VERDICT: **Unverified-assumption (corrected to "no web reference").** SOURCE:
    no checkout/return route in `src/pages/*`, no return endpoint in
    `src/api/endpoints/*` (grep for `return_url`/`redirect`/`capture` finds only KYC,
    SSO/ACS, Google Drive, and Jira OAuth flows). Return ingestion is mobile-only.

11. **Inbound return URI shape `…/app/billing/return/<provider>/{success|cancel|failure}`
    with `intent`/`token`/`status`/`error`/`error_description` params.** VERDICT:
    **Unverified-assumption.** SOURCE: none — not a backend or web contract; defined
    by this app and to be finalized by AND-228/229 (already flagged in §13). Parser
    is param-tolerant by design.

12. **`PaymentReturn.intentId` / `?intent=` correlates a backend payment `intent_id`.**
    VERDICT: **Corrected (terminology).** SOURCE: backend keys sessions by
    `checkout_session_id`/`order_id` (`UnifiedCheckoutSessionOut`, `CaptureOrderIn`);
    there is no backend `intent_id`. The field is an app-local correlation token that
    must be seeded from `checkout_session_id`/`order_id`. Noted in §5 and §2.

13. **Android: single-Activity `singleTop` receives warm deep links via `onNewIntent`;
    cold start via `intent.data`; App Links use `autoVerify` + `assetlinks.json`.**
    VERDICT: **Verified (framework ref).** SOURCE:
    https://developer.android.com/training/app-links (Android App Links / Digital
    Asset Links) and https://developer.android.com/guide/components/activities/tasks-and-back-stack
    (`singleTop` / `onNewIntent`).

14. **Hilt `@IntoSet` multibinding for data-driven provider registration.** VERDICT:
    **Verified (framework ref).** SOURCE:
    https://dagger.dev/dev-guide/multibindings (`@IntoSet`).

15. **DataStore survives process death for cold-start correlation.** VERDICT:
    **Verified (framework ref).** SOURCE: https://developer.android.com/topic/libraries/architecture/datastore.

### Corrections made

- **§5**: removed the non-existent `POST /ui/billing/checkout_session/{intent_id}/confirm`
  endpoint and its fabricated `{status:"paid", entitlement_granted}` 200 body and
  `402`/`404` error literals. Replaced with the real backend surface
  (`POST /ui/billing/checkout_session` create-only; `POST /ui/checkout/session` ->
  `UnifiedCheckoutSessionOut`; `POST /api/billing/paypal/capture-order` ->
  `CaptureOrderIn`) and the real 422/`detail` error envelope.
- **§5 / §2**: clarified that the app's `intentId` correlation token is client-defined
  and must be seeded from `checkout_session_id`/`order_id`; there is no backend
  `intent_id`.
- **§2**: noted the web app has no redirect/return handler, so the inbound return-URI
  shape is an app-defined assumption rather than a mirrored web contract.

### Open assumptions

- **Inbound return-URI path/param scheme** (claims 11): unverifiable — defined by
  this app + AND-228/229; no backend/web source. Already an §13 open question.
- **Production return host name** (`@string/payment_return_host`): unverifiable from
  sources; §13 open question.
- **Provider-specific query param names** (PayPal `token`/`PayerID`, CCBill
  `transactionId`): unknown until AND-228/229; parser is param-tolerant. §13.
- **Exact AND-227 confirm/verify call** keyed on `checkout_session_id` vs PayPal
  `order_id`: boundary owned by AND-227; this ticket defines only the
  `CheckoutConfirmClient` interface.
- **Custom Tab cancel-without-redirect detection**: belongs to AND-228/229 lifecycle;
  §13 open question.

## 17. Test Plan

IDs `TC-AND-231-NN`. "Traces" links to §14 acceptance criteria. Targets per the
CI/dev matrix: JVM/Robolectric (local), emulator AVD `test35` (API 35 x86_64), or
the physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). Deep-link/Custom-Tab
round-trip cases that exercise the real browser handoff are noted as physical-device.

- **TC-AND-231-01** — Type: unit (JVM, `PaymentReturnParserTest`). Target: JVM/Robolectric.
  Preconditions: two test `PaymentProvider` descriptors registered. Steps: parse
  success/cancel/failure return URIs for each provider (path-driven outcome) plus the
  `testlogon://billing/...` dev-scheme variant. Expected: `PaymentReturn` with correct
  `provider`, `outcome`, `intentId` (from `?intent=`), `providerRef` (`token`/`tx`).
  Traces: AC-1, AC-5.

- **TC-AND-231-02** — Type: unit (JVM). Target: JVM/Robolectric. Preconditions: provider
  registered. Steps: parse URI where path says `/success` but `?status=FAILED`/`?error=`
  present (path-vs-param precedence); parse unrecognized trailing segment with no
  decisive params. Expected: path wins -> `SUCCESS`; undecidable -> `UNKNOWN`.
  Traces: AC-1.

- **TC-AND-231-03** — Type: unit (JVM). Target: JVM/Robolectric. Preconditions: provider
  registered. Steps: parse a foreign/non-billing URI (e.g. magic-link host) and a
  malformed URI. Expected: `parse` returns `null`; `handle` returns `null`; connector
  returns `false` (not consumed); no throw. Traces: AC-6.

- **TC-AND-231-04** — Type: unit (JVM, `PaymentReturnHandlerTest`, fake `PaymentIntentStore`
  + fixed `Clock`). Target: JVM/Robolectric. Preconditions: in-flight intent stored,
  matching `intentId`, within TTL. Steps: `handle(successUri)`. Expected:
  `PaymentReturnRoute.Verify(intentId)`; `markConsumed` returns true once. Traces: AC-1.

- **TC-AND-231-05** — Type: unit (JVM). Target: JVM/Robolectric. Preconditions: matching
  in-flight intent. Steps: `handle(cancelUri)` then `handle(failureUri)` and
  `handle(unknownUri)`. Expected: `Cancelled(intentId)`; `Failed(...)` for failure and
  unknown (UNKNOWN treated as Failed with generic message). Traces: AC-1.

- **TC-AND-231-06** — Type: unit (JVM). Target: JVM/Robolectric. Preconditions: vary store
  state. Steps: `handle(successUri)` with (a) no in-flight intent, (b) mismatched
  `intentId`, (c) intent older than 15-min TTL (advance fake `Clock`). Expected: every
  case routes `Stale`; never `Verify`; entitlement never inferred client-side.
  Traces: AC-2.

- **TC-AND-231-07** — Type: unit (JVM, idempotency). Target: JVM/Robolectric.
  Preconditions: matching in-flight intent. Steps: call `handle(successUri)` twice with
  the same `intentId`. Expected: first -> `Verify`; second -> `null` (already consumed),
  no re-navigation; `markConsumed` returns false on the second call. Traces: AC-3.

- **TC-AND-231-08** — Type: contract/MockWebServer. Target: JVM/Robolectric (no live host).
  Preconditions: MockWebServer stubs the AND-227 confirm/capture call; CSRF cookie
  present. Steps: drive the `Verify` route's `CheckoutConfirmClient` against a 200
  capture response keyed on `order_id`/`checkout_session_id`; then against a 422
  `HTTPValidationError` (`detail:[{loc,msg,type}]`); then a `{detail:{code,...}}` body.
  Expected: request carries `X-CSRF-Token` and cookies; 200 -> confirmation state; error
  bodies map via the AND-015 string|`[{msg}]`|`{code}` normalizer to a user message; no
  fabricated `entitlement_granted`/`"paid"` assumptions. Traces: AC-1, AC-2.

- **TC-AND-231-09** — Type: instrumented/e2e (deep-link resolution). Target: emulator
  `test35`. Preconditions: app installed; intent filters from §4.1 present. Steps: fire a
  VIEW `Intent` for each return URI (success/cancel/failure/unknown) and assert the
  `NavController` current destination is `Verify`/`Cancelled`/`Failed`/`Failed`
  respectively. Expected: each resolves to the correct route. Traces: AC-1, AC-4.

- **TC-AND-231-10** — Type: instrumented/e2e (lifecycle). Target: emulator `test35`.
  Preconditions: in-flight intent persisted in DataStore. Steps: (a) cold start launching
  `MainActivity` with `intent.data` set to a success return; (b) warm `onNewIntent` after
  the task is already running; (c) kill+restart the process (`am kill`) then deliver the
  return. Expected: all three route correctly using the persisted intent; process-death
  case still correlates. Traces: AC-3, AC-4.

- **TC-AND-231-11** — Type: instrumented/e2e (provider extensibility). Target: emulator
  `test35`. Preconditions: a test-only `PaymentProvider` `@IntoSet` binding added via a
  test Hilt module, no parser source edits. Steps: fire that provider's return URIs.
  Expected: routed correctly purely from the descriptor. Traces: AC-5.

- **TC-AND-231-12** — Type: instrumented/e2e (real Custom Tab round-trip + flaky/offline
  host). Target: **physical device (SM-A156U)** — MUST run on hardware because it
  exercises the real browser Custom Tab handoff and `onNewIntent` re-entry; also toggle
  airplane mode for the offline leg. Preconditions: dev flavor pointing at the dev mock;
  in-flight intent stored. Steps: launch Custom Tab to the dev mock, complete to a success
  return, land back in app; repeat with the device offline at return time and the dev host
  unreachable/slow (~20s). Expected: success returns route to `Verify`; while offline the
  `Verify` destination shows "confirming when reconnected" (bounded backoff, no error
  crash), then reconciles on reconnect. Traces: AC-1, AC-4.

- **TC-AND-231-13** — Type: instrumented/manual (security/spoof + flavor gating). Target:
  **physical device (SM-A156U)** for the App Links autoVerify check (real Digital Asset
  Links verification needs a device + network); flavor-gating assertion can also run on
  emulator. Steps: (a) attempt to "confirm" by hand-crafting a success return URI with no
  matching in-flight intent -> assert `Stale`, no entitlement; (b) build the release
  variant and assert the `testlogon://billing` custom-scheme intent filter is absent from
  the merged release manifest while verified App Links remain; (c) verify the prod host
  filter has `autoVerify="true"`. Expected: spoofed success cannot grant entitlement; dev
  scheme absent in release. Traces: AC-2, AC-7.

- **TC-AND-231-14** — Type: Compose-UI + accessibility. Target: emulator `test35` (TalkBack
  assertions via Espresso/Compose a11y; spot-check on physical device). Preconditions:
  navigate to each terminal state (`Cancelled`/`Failed`/`Stale`) and the `Verify` loading
  state. Steps: assert each result screen fires a focus/announcement on arrival, exposes
  `contentDescription`s, meets Material 3 touch-target/contrast, and uses externalized
  strings (no hardcoded literals; provider `error_description` shown verbatim, labelled as
  a provider message). Expected: screen-reader announces the outcome on return; a11y checks
  pass. Traces: AC-1.

- **TC-AND-231-15** — Type: unit (telemetry redaction). Target: JVM/Robolectric.
  Preconditions: fake telemetry sink + log capture. Steps: run `handle` across
  success/stale paths and inspect emitted events and logs. Expected:
  `payment_return_received`/`_routed`/`_stale` carry only provider, outcome enum, and
  boolean correlation flags; no full return URI, no `intentId`/`token`/`error_description`
  in clear (intent may appear hashed/truncated only). Traces: AC-7.

### Coverage matrix

| AC (§14) | Covered by |
| --- | --- |
| AC-1 (each outcome routes correctly, tested) | TC-01, TC-02, TC-04, TC-05, TC-08, TC-09, TC-12, TC-14 |
| AC-2 (no/mismatched/expired intent -> Stale, no client-side entitlement) | TC-06, TC-08, TC-13 |
| AC-3 (duplicate delivery navigates exactly once) | TC-07, TC-10 |
| AC-4 (cold / warm / process-death deep links) | TC-09, TC-10, TC-12 |
| AC-5 (provider add = `@IntoSet` binding, no parser edits) | TC-01, TC-11 |
| AC-6 (non-billing deep link not consumed) | TC-03 |
| AC-7 (no PII/secret in logs; redacted telemetry) | TC-13, TC-15 |
