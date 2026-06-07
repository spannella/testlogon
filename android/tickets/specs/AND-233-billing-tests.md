---
id: AND-233
title: Billing tests
milestone: M5
epic: E31
priority: P1
size: M
depends_on: [AND-227, AND-231]
blocks: []
status: reviewed
reviewed_on: 2026-06-06
---

# AND-233 — Billing tests

## 1. Overview & Goal

This ticket delivers the automated test suite that locks down the billing
subsystem of the TestLogon native Android port. It is a **Test** ticket
(Priority **P1**); it ships no production behavior of its own. Its goal is to
guarantee that the two highest-risk billing surfaces — the **billing repository**
that drives Stripe checkout-session creation/confirmation (AND-227) and the
**deep-link redirect/return handler** that routes redirect-provider results back
into the app (AND-231) — behave correctly across success, cancel, failure,
timeout, and malformed-input paths.

Concretely, this ticket adds:

1. JVM unit tests for `BillingRepository` (in `core-data`) covering the
   `POST /ui/billing/checkout_session` create flow (verified to exist; request
   body `BillingCheckoutReq = {amount_cents, currency?, description?}`, response
   `{session_id, url}`), mapped `ApiResult<T>` outcomes, FastAPI `detail` error
   mapping, and retry/timeout policy.
   **Correction:** the original draft described a `create + confirm` flow with
   an `idempotency_key`. There is **no** in-app confirm endpoint
   (`/ui/billing/checkout_session/{id}/confirm` does not exist in the backend
   OpenAPI or the web reference) and **no** `Idempotency-Key` in the verified
   contract. Checkout is a redirect-to-hosted-page model: the caller opens the
   returned `url`; the final result arrives back via the AND-231 redirect/return
   deep link, not via an in-app confirm call. `confirmCheckoutSession` and the
   `idempotency-key` test surface are retained below only as **unverified,
   AND-227-pending** behaviors and are flagged as such (see §16).
2. JVM unit tests for the redirect-return parser/router (`PaymentReturnParser`
   + the `paymentReturn` Navigation-Compose deep-link wiring from AND-231)
   covering success/cancel/failure classification from `testlogon://` return
   URIs, including tampered/ambiguous inputs.
3. A small set of `MockWebServer`-backed integration tests that exercise the
   repository against canned `/ui/billing/checkout_session` responses, including
   401→`/ui/session/refresh`→retry, CSRF header propagation, and the ~20s
   timeout budget against the unreliable dev backend.

The single acceptance bar from the backlog is **"Pass."** — i.e. the suite is
green and runs in CI. This spec defines exactly what "pass" must mean so the
test suite is not vacuous.

## 2. Context & References

- **Package base:** `com.testlogon.android` everywhere a package appears.
- **Module under test:** `core-data` (`BillingRepository`, DTO↔domain mapping,
  `ApiResult`) and `app` / `feature-billing` (the deep-link route from AND-231).
- **Test module:** shared fakes, `MockWebServer` helpers, and dispatcher rules
  live in `core-testing` and are reused here.
- **AND-227 (Checkout session billing, P0, dep AND-225):** owns the production
  `BillingRepository.createCheckoutSession(...)` / `confirmCheckoutSession(...)`
  code and `/ui/billing/checkout_session`. This ticket tests it; it does not
  modify it except to add `@VisibleForTesting` seams if strictly required.
- **AND-231 (Payment redirect/return handler, P0, dep AND-022):** owns the
  `testlogon://pay/return` deep-link intent filter, `PaymentReturnParser`, and
  the success/cancel/failure routing. This ticket tests that routing.
- **AND-232 (Billing ViewModels + error mapping, P0):** owns the payment state
  machine and provider error mapping; **ViewModel-level unit tests are out of
  scope here and belong to AND-232.** This ticket stays at the repository +
  deep-link layer to avoid duplication. Where a test would assert ViewModel
  state, it is named here and deferred to AND-232.
- **AND-228/AND-229 (PayPal/CCBill Custom Tabs):** both consume AND-231's
  return handler. Their provider-specific return URIs are included as
  parameterized parser fixtures so the router is proven generic, but the
  PayPal/CCBill *feature* tests are owned by those tickets.
- **Stack:** Kotlin 2.0.21, Coroutines/Flow, Retrofit 2.11 + OkHttp 4.12 +
  Moshi 1.15, Hilt (KSP), JUnit4, MockWebServer, Turbine (Flow assertions),
  Truth/`assertk`, `kotlinx-coroutines-test`. JDK 17, AGP 8.7.3, Gradle 8.9.
- **Backend:** FastAPI + DynamoDB; cookie-based session + `ui_csrf` cookie
  echoed as `X-CSRF-Token`. Dev host `http://18.222.237.167:8000` is plaintext
  and unreliable — all tests run against `MockWebServer`, never the live host.
- **Web reference:** `src/api/endpoints/billing.ts` (`createCheckoutSession`)
  for the checkout-session request/response shape; `src/api/types.ts`
  (`BillingCheckoutReq`) for the request type; `src/api/client.ts` for the
  CSRF/401-refresh/error-mapping transport contract verified in §16.

## 3. Functional Requirements

This being a test ticket, "functional requirements" are the behaviors the suite
must assert. The suite **must fail** if any of the following regress.

**FR-1 — Checkout-session creation (happy path).** Given valid input,
`BillingRepository.createCheckoutSession` returns
`ApiResult.Success(CheckoutSession)` with the parsed `sessionId` and `url`, and
issues exactly one `POST /ui/billing/checkout_session`.
**Correction (verified):** the response body is `{session_id, url}` only — there
is **no** `client_secret`, `checkout_session_id`, or `publishable_key` in the
checkout-session response (source: `src/api/endpoints/billing.ts:
createCheckoutSession` returns `{ session_id, url }`). The Stripe
`publishable_key` is delivered separately by `GET /ui/billing/config`
(`BillingConfig.publishable_key`), not by this endpoint. The request body is
`BillingCheckoutReq = {amount_cents:int (required), currency?:string,
description?:string}` (source: `components.schemas.BillingCheckoutReq`), not the
`provider`/`price_id`/`return_url` body the draft described.

**FR-2 — CSRF + cookies.** The create request carries the `X-CSRF-Token` header
sourced from the `ui_csrf` cookie, and the persistent cookie jar's cookies are
attached. **Verified** against `src/api/client.ts` (`getCookie("ui_csrf")` →
`headers.set("X-CSRF-Token", csrf)`). **Correction:** the web client sets
`X-CSRF-Token` on **every** request when the cookie is present, not only on
mutating requests; the test should assert presence on the POST without asserting
absence on hypothetical GETs.

**FR-3 — Confirmation status mapping.** *(Unverified — AND-227-pending.)* The
draft asserted `confirmCheckoutSession` maps backend `status` values
(`"requires_action" | "processing" | "succeeded" | "canceled" | "failed"`) to a
`PaymentStatus` enum 1:1. **None of this is verifiable** against the sources: no
`confirm` endpoint, no `PaymentStatus`/status enum, and no such status string set
exists in the backend OpenAPI or the web reference. The only `status` field on a
checkout-type response is `UnifiedCheckoutSessionOut.status`, a free-form string
defaulting to `"pending_payment"` (source:
`components.schemas.UnifiedCheckoutSessionOut`), and that is a different endpoint
(`POST /ui/checkout/session`). If AND-227 introduces a status-bearing
confirm/poll surface, this FR's enum and mapping table must be re-derived from
whatever AND-227 actually ships; until then this FR is an open assumption (see
§16) and its tests are written against fixtures clearly marked as provisional.

**FR-4 — Error mapping.** FastAPI `detail` in all three shapes — `string`,
`[{msg,...}]`, `{code,...}` — maps to `ApiResult.Error`. **Verified** against
`src/api/client.ts: normalizeErrorDetail`: a `string` is used verbatim; an array
joins the `msg` fields with `", "`; an object is mapped **by `code` to canned UX
copy** for a known code set (`role_required_scope`, `role_required`,
`helpdesk_*`, etc.) and otherwise — **including unknown codes** — falls back to
the generic message. **Correction:** the web mapper does **not** read a `.message`
field off an arbitrary `{code, message}` object (confirmed by
`src/api/client.errorMapping.test.ts`: "does not leak raw object payload for
unknown structures" returns the fallback). The Android port may choose to surface
`detail.message`/`detail.code` for unknown object detail (a richer behavior), but
that is an **intentional divergence from the web client**, not a mirror of it,
and the test must encode whichever AND-227/AND-232 mapper ships. HTTP 4xx/5xx
without a parseable body maps to a generic `ApiResult.Error` carrying the status
code (web uses `res.statusText` as the fallback message).

**FR-5 — 401 refresh-once.** A `401` on a create call triggers exactly one
`POST /ui/session/refresh`; on refresh success the original call is retried once
and may succeed; on refresh failure the result is `ApiResult.Error(Unauthorized)`
and no further retry occurs. **Verified** against `src/api/client.ts`
(`refreshSession()` → `POST /ui/session/refresh`; single refresh guarded by a
shared `refreshPromise`; one retry of the original request; refresh failure →
`logout("session_expired")` + `ApiError(401)`) and the OpenAPI index
(`POST /ui/session/refresh | resp=200:`). Note the web client only attempts
refresh when the user was already authenticated; an unauthenticated 401
propagates directly — the Android repository test should mirror this guard.

**FR-6 — Timeout & retry policy.** A non-responding create call surfaces
`ApiResult.Error` within the configured call-timeout budget. **POST is not
retried for network errors** (non-idempotent); only the documented 401-refresh
retry applies. **Correction:** the no-network-retry behavior is a reasonable
Android design choice (the web client also does not auto-retry POSTs on network
error — `src/api/client.ts` throws `ApiError(0, "Network error")` immediately),
but the specific **~20s** call-timeout constant
(`BillingNetwork.CALL_TIMEOUT_SECONDS == 20L`) is an **unverified, Android-side
design value** — it is not derivable from the backend or web sources and is owned
by AND-227's OkHttp config. The `Idempotency-Key` header claim is **unverified**:
no `Idempotency-Key` is sent by the web client (`src/api/client.ts` sets no such
header) and no backend operation in the OpenAPI index documents one. The
idempotency-key tests below are therefore conditional on AND-227 actually adding
such a header; if it does not, the related cases are dropped, not failed.

> **Verification note for FR-7..FR-11 (redirect-return parsing).** The
> `testlogon://pay/return` custom-scheme deep link, its query-param names, and
> the success/cancel/failure synonym sets are an **Android-internal convention
> owned by AND-231** and have **no web-reference counterpart** — the web client
> redirects to a hosted page and reads results server-side, so these cannot be
> verified against the OpenAPI spec or `src/`. They are recorded as
> AND-231-owned assumptions in §16. The one cross-checkable fact is that the
> create response field is `session_id` (verified, `src/api/endpoints/
> billing.ts`), so a `session_id` return param is contract-consistent.

**FR-7 — Redirect-return success routing.** A return URI of the form
`testlogon://pay/return?status=success&session_id=<id>` parses to
`PaymentReturn.Success(sessionId)`.

**FR-8 — Redirect-return cancel routing.** `...?status=cancel` (and provider
synonyms `canceled`/`cancelled`) parses to `PaymentReturn.Cancelled`.

**FR-9 — Redirect-return failure routing.** `...?status=failure` (synonyms
`failed`/`error`), or a return missing required params, parses to
`PaymentReturn.Failed(reason)`.

**FR-10 — Robust parsing.** Unknown/empty `status`, missing `session_id` on a
`success`, wrong scheme/host, and duplicated query keys all classify as
`PaymentReturn.Failed` (fail-closed) rather than throwing.

**FR-11 — Provider genericity.** PayPal (AND-228) and CCBill (AND-229) return
URIs that carry their own param names (e.g. `paymentId`, `token`, `PayerID` for
PayPal; `subscription_id` for CCBill) are normalized by the parser and routed
identically. Parameterized fixtures prove this.

## 4. Technical Design

### 4.1 Test source layout

```
core-data/src/test/java/com/testlogon/android/core/data/billing/
    BillingRepositoryTest.kt            # FR-1..FR-3, error mapping unit-level
    BillingRepositoryNetworkTest.kt     # FR-4..FR-6 via MockWebServer
    BillingErrorMappingTest.kt          # FastAPI detail matrix (parameterized)
app/src/test/java/com/testlogon/android/billing/
    PaymentReturnParserTest.kt          # FR-7..FR-11 (parameterized)
core-testing/src/main/java/com/testlogon/android/core/testing/
    MainDispatcherRule.kt               # existing
    BillingFixtures.kt                  # NEW: JSON fixtures + URI builders
    MockBackend.kt                      # existing MockWebServer wrapper, extended
```

### 4.2 Production seams required

The tests must run without touching the network and without Robolectric where
avoidable. `PaymentReturnParser` (AND-231) must therefore be a **pure Kotlin
function over a parsed URI representation**, not coupled to `android.net.Uri`.
If AND-231 ships it coupled to `android.net.Uri`, this ticket adds a thin pure
overload that accepts the decoded components:

```kotlin
// owned by AND-231; signature this ticket asserts against
data class ReturnUri(
    val scheme: String,
    val host: String,
    val path: String,
    val query: Map<String, List<String>>,
)

object PaymentReturnParser {
    fun parse(uri: ReturnUri): PaymentReturn
}

sealed interface PaymentReturn {
    data class Success(val sessionId: String, val provider: PaymentProvider) : PaymentReturn
    data object Cancelled : PaymentReturn
    data class Failed(val reason: String, val code: String? = null) : PaymentReturn
}
```

If only the `android.net.Uri` overload exists, `PaymentReturnParserTest` runs
under Robolectric (`@RunWith(RobolectricTestRunner::class)`); the pure-overload
path is preferred for speed and is recorded as an open question for AND-231.

### 4.3 Repository under test

```kotlin
interface BillingRepository {
    // VERIFIED contract: req BillingCheckoutReq, resp { session_id, url }.
    suspend fun createCheckoutSession(
        request: CheckoutSessionRequest, // = BillingCheckoutReq(amountCents, currency?, description?)
    ): ApiResult<CheckoutSession>        // = CheckoutSession(sessionId, url)

    // UNVERIFIED / AND-227-pending: no confirm endpoint or PaymentStatus enum
    // exists in the backend OpenAPI or the web reference. Keep only if AND-227
    // ships it; tests for it are provisional (see §16).
    suspend fun confirmCheckoutSession(
        sessionId: String,
    ): ApiResult<PaymentStatus>
}
```

`BillingRepositoryTest` constructs the real repository implementation with a
Retrofit service pointed at a `MockWebServer` `baseUrl`, a real Moshi instance,
and a fake `CsrfTokenProvider`/cookie jar from `core-testing`. No mocking of the
HTTP client; only the server is faked, so Moshi parsing and OkHttp interceptors
(CSRF, refresh, idempotency) are exercised end-to-end at the repository boundary.

### 4.4 Coroutine + flow harness

`MainDispatcherRule` installs a `StandardTestDispatcher`. Suspend-function
results are awaited with `runTest`. The ~20s timeout assertions use
`MockWebServer` `SocketPolicy.NO_RESPONSE` combined with `advanceTimeBy` so the
test does not actually wait 20 seconds — the OkHttp call timeout is injected as
a short value via a test-only `OkHttpClient` whose timeout is asserted to equal
the production constant (`BillingNetwork.CALL_TIMEOUT_SECONDS == 20L`).

## 5. API Contract

This ticket asserts the contract owned by AND-227; it does not define new
endpoints. The shapes below are **corrected to match the authoritative sources**
(OpenAPI `components.schemas.BillingCheckoutReq` and
`src/api/endpoints/billing.ts: createCheckoutSession`). The fixtures encode these
verified shapes.

**Create — `POST /ui/billing/checkout_session`** — VERIFIED
(`POST /ui/billing/checkout_session | req=BillingCheckoutReq`).

Request body (`BillingCheckoutReq`; only `amount_cents` is required):
```json
{
  "amount_cents": 1999,
  "currency": "usd",
  "description": "TestLogon order"
}
```
Headers: `X-CSRF-Token: <ui_csrf>`, `Content-Type: application/json`, plus
session cookies. (No `Idempotency-Key` — none is sent by the web client or
documented in the OpenAPI spec.)

Success `200` (`src/api/endpoints/billing.ts` types the response as
`{ session_id: string; url: string }`):
```json
{
  "session_id": "cs_test_abc",
  "url": "https://checkout.stripe.com/c/pay/cs_test_abc"
}
```

> **Corrected.** The original draft showed `provider`/`price_id`/`return_url`/
> `idempotency_key` in the request and `checkout_session_id`/`client_secret`/
> `publishable_key`/`status`/`redirect_url` in the response — **none of those
> fields exist** in the verified contract. The Stripe `publishable_key` is
> served by `GET /ui/billing/config` (`BillingConfig.publishable_key`), and the
> hosted-checkout `url` is the single redirect handle. The flow is: create →
> open `url` in a browser/Custom Tab → result returns via the AND-231
> `testlogon://pay/return` deep link.

**Confirm — `POST /ui/billing/checkout_session/{id}/confirm`** — **DOES NOT
EXIST (Corrected).** No such path appears in the OpenAPI index and the web
reference exposes no confirm call. Retained only as an AND-227-pending
possibility; see FR-3 and §16. The richer, status-bearing checkout surface that
*does* exist is a **different** endpoint, `POST /ui/checkout/session`
(`req=UnifiedCheckoutSessionIn`, `resp=UnifiedCheckoutSessionOut` whose
`status` is a free string defaulting to `"pending_payment"`), out of scope for
AND-233 unless AND-227 adopts it.

**Error responses** (all three FastAPI `detail` shapes — shapes VERIFIED against
`src/api/client.ts: normalizeErrorDetail`; the array example uses a real billing
field name):
```json
{ "detail": "Card declined." }
```
```json
{ "detail": [ { "loc": ["body","amount_cents"], "msg": "field required", "type": "value_error.missing" } ] }
```
```json
{ "detail": { "code": "role_required_scope", "required_scope": "billing_support" } }
```
> Note: the object form maps **by `code`** (the web mapper recognizes
> `role_required_scope`, `role_required`, `helpdesk_*`, …) and falls back to a
> generic message for unknown codes; it does not read a free-form `message`
> field (verified by `src/api/client.errorMapping.test.ts`). The standard
> FastAPI 422 validation error is `HTTPValidationError` (the array shape), which
> is the `422` response declared for `POST /ui/billing/checkout_session`.

**Refresh — `POST /ui/session/refresh`** — VERIFIED (`resp=200:`). `200` sets new
cookies; non-2xx triggers logout in the web client.

## 6. Data & State Management

- **No Room/DataStore writes are introduced** by this ticket. If
  `BillingRepository` persists a pending-session marker to DataStore/Room
  (per AND-227), the test injects an in-memory fake from `core-testing` and
  asserts the marker is written on create and cleared on terminal status.
- **Domain models asserted:** `CheckoutSession(sessionId, url)` — **corrected**
  to the verified `{session_id, url}` response (the draft's `clientSecret`/
  `publishableKey`/`status`/`redirectUrl` fields do not exist on this endpoint;
  source `src/api/endpoints/billing.ts`). The `PaymentStatus` enum and its
  exhaustive-`when`/mapping-table test are **deferred/unverified**: no such enum
  or status set exists in the sources (see FR-3, §16). If AND-227 introduces it,
  the enum coverage test is added then against the actual values.
- **State machine assertions are deferred to AND-232.** Where this suite would
  assert a `UiState` transition (e.g. `Idle → Loading → AwaitingAction`), it
  instead asserts the repository result feeding that transition; the transition
  itself is owned by AND-232's `BillingViewModelTest`.

## 7. Error Handling & Resilience

Resilience is the *subject under test*. The suite must prove:

- **R-1 (FR-4):** parameterized matrix over the three `detail` shapes × {400,
  402, 409, 422, 500} produces the correct `ApiResult.Error.message` and `code`.
- **R-2 (FR-5):** a scripted `MockWebServer` `Dispatcher` returns `401` then
  `200`, with an interposed `200` on `/ui/session/refresh`; the test asserts the
  request sequence is `create → refresh → create` and the final result is
  `Success`. A second case returns `401` on refresh and asserts a single
  refresh attempt with `Error(Unauthorized)`.
- **R-3 (FR-6):** `SocketPolicy.NO_RESPONSE` on create yields
  `ApiResult.Error` of network/timeout type with **zero** automatic POST
  retries (asserted via `server.requestCount == 1`, excluding the refresh path).
- **R-4 (idempotency):** the `Idempotency-Key` sent on the original create and
  on the post-refresh retry are byte-identical (`takeRequest()` header compare).
- **R-5 (fail-closed parsing, FR-10):** malformed return URIs never throw;
  asserted with `assertThat { parser.parse(bad) }.doesNotThrowAnyException()`
  and a `Failed` result.

## 8. Security & Privacy

- Tests must assert that **no secret/session material is logged**: the suite
  captures the OkHttp logging interceptor output (test-installed `BUFFER`-level
  logger) and asserts that the `Cookie`/`Set-Cookie` session values, the
  `X-CSRF-Token` value, and the checkout `session_id`/`url` (which embeds the
  Stripe checkout session id) do not appear in cleartext in redacted log lines.
  **Corrected:** the draft named `client_secret`/`publishable_key`/
  `Idempotency-Key` — these fields are not present on the verified checkout
  response/headers, so the redaction targets are updated to the values that
  actually transit (session cookie, CSRF token, checkout id/url). The
  `publishable_key` from `GET /ui/billing/config` is by Stripe's design a
  publishable (non-secret) value and is not treated as secret.
- Tests assert `X-CSRF-Token` is present on the billing POST (verified behavior,
  `src/api/client.ts`). Whether an **absent** CSRF value is rejected before send
  is an AND-227 interceptor design choice and is asserted only if that
  interceptor exists (unverified — see §16).
- Fixtures use only Stripe **test-mode** identifiers (`pk_test_`, `cs_test_`).
  No real keys, PANs, or live cookies enter the repo. The dev backend
  (`18.222.237.167`) is never contacted from tests.

## 9. Accessibility & i18n

Not applicable — this ticket adds no UI. Accessibility and string localization
for billing screens are owned by the billing feature tickets (AND-227/AND-232)
and the global a11y/i18n tickets. The one i18n-adjacent assertion here: error
messages surfaced from FastAPI `detail` are passed through **unmodified** (not
hardcoded English), so localized backend messages render verbatim; the test
asserts a non-ASCII `detail` string round-trips intact.

## 10. Telemetry & Logging

No new telemetry is emitted by this ticket. The suite **verifies** telemetry
contracts owned upstream where cheaply observable: if AND-232 emits a
`billing_checkout_result` analytics event via an injected `AnalyticsLogger`,
the repository tests pass a fake logger and assert it is **not** invoked at the
repository layer (telemetry belongs to the ViewModel layer). CI publishes the
JUnit XML and a JaCoCo coverage report for `core-data/.../billing/**` and the
`PaymentReturnParser`; coverage is reported, not gated, in this ticket.

## 11. Testing Strategy

This *is* the deliverable. Frameworks: JUnit4, `kotlinx-coroutines-test`,
MockWebServer, Turbine (only if a `Flow` is exposed), Truth/`assertk`,
optionally Robolectric for the `Uri` overload.

**Unit (pure):**
- `PaymentReturnParserTest` — `@Parameterized` table of ~20 URIs covering FR-7..
  FR-11, including Stripe, PayPal, and CCBill synonyms, mixed case, URL-encoded
  values, missing params, wrong scheme/host, duplicate keys.
- `BillingErrorMappingTest` — `@Parameterized` over the `detail` shape × status
  matrix (FR-4 / R-1).

**Repository (MockWebServer):**
- `BillingRepositoryTest` — FR-1..FR-3, FR-2 (header/cookie assertions via
  `takeRequest()`), redirect-provider variant.
- `BillingRepositoryNetworkTest` — R-2 (401 refresh-once, both branches), R-3
  (timeout/no-retry), R-4 (idempotency-key stability).

**Determinism:** all suspend tests use `runTest` + `StandardTestDispatcher`;
no real delays; `MockWebServer` started/stopped in `@Before`/`@After`. Target
total runtime < 10s on CI. Tests are hermetic (no network, no device).

**What "Pass" means (acceptance gate):** every test above is implemented and
green; the matrix tests have non-trivial cases (≥3 per `detail` shape); the
parser table has ≥1 case per `PaymentReturn` subtype per provider; the suite is
wired into `./gradlew :core-data:testDebugUnitTest :app:testDebugUnitTest` and
the CI workflow.

## 12. Dependencies & Sequencing

- **Hard deps:** **AND-227** (checkout-session billing code + endpoints) and
  **AND-231** (`PaymentReturnParser` + deep-link route) must be merged first —
  there is nothing to test otherwise.
- **Soft / parallel:** **AND-232** (ViewModels + error mapping) shares the
  error-mapping subject; coordinate so the FastAPI `detail` mapping lives in one
  place (`core-network` mapper) and is tested once here at the repository
  boundary, with ViewModel-state tests in AND-232.
- **Reuses:** `core-testing` `MockBackend`/`MainDispatcherRule` (from the
  testing-infra ticket). Extends `core-testing` with `BillingFixtures`.
- **Consumers downstream:** AND-228 (PayPal) and AND-229 (CCBill) rely on the
  parser genericity proven here; their feature tests build on these fixtures.
- **Sequencing:** land after AND-227/AND-231; before AND-228/AND-229 feature
  completion so the shared return-handler contract is locked.

## 13. Risks & Open Questions

- **R1 — Parser coupling to `android.net.Uri`.** If AND-231 does not expose a
  pure overload, tests need Robolectric, slowing CI. *Mitigation:* request the
  `ReturnUri` pure overload in AND-231 (Section 4.2). **Open question for
  AND-231 owner.**
- **R2 — Confirm endpoint path. RESOLVED (negative).** Verified against the
  backend OpenAPI index and the web reference: **no confirm endpoint exists** for
  `/ui/billing/checkout_session`, and there is no `PaymentStatus`/status enum.
  Checkout is hosted-redirect + AND-231 return deep link. The
  `confirmCheckoutSession`/FR-3 surface is now an explicit AND-227-pending
  assumption (see §16), not a fixture-pinning question. If AND-227 later adds a
  confirm/poll surface, re-open as a linked change.
- **R3 — Idempotency-Key ownership.** Whether the key is generated in the
  repository or an interceptor affects where R-4 asserts. *Mitigation:* assert
  observable header behavior, not the generation site.
- **R4 — Error-mapping double-ownership with AND-232.** Risk of duplicated or
  divergent mapping tests. *Mitigation:* single mapper in `core-network`; this
  ticket tests it, AND-232 references it.
- **R5 — Return-URI synonym set.** Provider status synonyms
  (`cancel/canceled/cancelled`, `failure/failed/error`) must match what AND-228/
  AND-229 actually emit. *Mitigation:* derive the synonym table from the web
  reference + provider docs and keep it in one constant.

## 14. Acceptance Criteria

1. `:core-data:testDebugUnitTest` and `:app:testDebugUnitTest` pass with the new
   suites included; no tests are `@Ignore`d.
2. `PaymentReturnParserTest` proves FR-7..FR-11 with parameterized cases for
   Stripe, PayPal, and CCBill return URIs, including ≥4 fail-closed malformed
   cases that classify as `Failed` without throwing.
3. `BillingRepositoryTest` proves FR-1/FR-2 against `MockWebServer`, asserting
   the request method/path (`POST /ui/billing/checkout_session`), the
   `BillingCheckoutReq` body, the `X-CSRF-Token` header, cookie attachment, and
   the parsed `CheckoutSession(sessionId, url)`. (FR-3 confirm/`PaymentStatus`
   mapping is covered only if AND-227 ships it; otherwise its case is dropped, see
   §16/§17.)
4. `BillingErrorMappingTest` proves FR-4 across all three FastAPI `detail` shapes
   × ≥5 status codes, with the correct mapped message (verbatim string; joined
   `msg` array; code-mapped or fallback for object form per
   `normalizeErrorDetail`).
5. `BillingRepositoryNetworkTest` proves FR-5 (401→refresh→retry, both
   branches) and FR-6/R-3 (timeout with zero POST retries). The R-4 idempotency
   case is included only if AND-227 emits an `Idempotency-Key` header (unverified;
   §16).
6. Security assertions (Section 8) pass: no session cookie / `X-CSRF-Token` /
   checkout `session_id`/`url` value appears in captured log output; only
   test-mode identifiers are used; no test contacts `18.222.237.167`.
7. Suite is hermetic and deterministic (no real network/sleeps), runs < 10s, and
   is wired into the CI workflow.

## 15. Definition of Done

- All Section 14 criteria met and verified in CI.
- New test files live under the paths in Section 4.1 with package base
  `com.testlogon.android`; shared fixtures added to `core-testing`
  (`BillingFixtures.kt`).
- No production code changed except minimal, reviewed `@VisibleForTesting`
  seams (and, if accepted, the AND-231 pure `parse(ReturnUri)` overload tracked
  as a linked change).
- JaCoCo coverage report for `billing/**` and `PaymentReturnParser` is published
  as a CI artifact (reported, not gated).
- Open questions R1–R2 are resolved or filed as linked issues against AND-231/
  AND-227.
- PR targets branch `android-port`, references AND-233/AND-227/AND-231, and is
  reviewed and merged with green CI.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. Sources:
**OAPI-IDX** = `reference/openapi.index.txt`; **OAPI** = `reference/openapi.pretty.json`
(`components.schemas.<Name>`); frontend paths are under `reference/src/`.

1. **Create endpoint is `POST /ui/billing/checkout_session`.** VERIFIED.
   OAPI-IDX `POST /ui/billing/checkout_session | op=create_checkout_session... | req=BillingCheckoutReq`; `src/api/endpoints/billing.ts: createCheckoutSession`.
2. **Create request body = `BillingCheckoutReq {amount_cents:int (required), currency?:string, description?:string}`.** CORRECTED (draft had `provider`/`price_id`/`return_url`/`idempotency_key`).
   OAPI `components.schemas.BillingCheckoutReq`; `src/api/types.ts: BillingCheckoutReq`.
3. **Create success response = `{ session_id:string, url:string }`.** CORRECTED (draft had `checkout_session_id`/`client_secret`/`publishable_key`/`status`/`redirect_url`).
   `src/api/endpoints/billing.ts: createCheckoutSession` (`api.post<{ session_id: string; url: string }>`).
4. **Stripe `publishable_key` is served by `GET /ui/billing/config`, not by the checkout response.** VERIFIED.
   OAPI-IDX `GET /ui/billing/config`; `src/api/types.ts: BillingConfig.publishable_key`.
5. **A confirm endpoint `POST /ui/billing/checkout_session/{id}/confirm` exists.** CORRECTED — **does not exist**. No such path in OAPI-IDX (only `.../payment-issues/{incident_id}/confirm-and-retry` and unrelated `confirm` paths); no confirm call in `src/api/endpoints/billing.ts`.
6. **A `PaymentStatus` enum with values `requires_action|processing|succeeded|canceled|failed` (FR-3).** CORRECTED → Unverified-assumption. No such enum/value set anywhere. The only checkout `status` is `UnifiedCheckoutSessionOut.status`, a free string default `"pending_payment"` on a different endpoint. OAPI `components.schemas.UnifiedCheckoutSessionOut`; OAPI-IDX `POST /ui/checkout/session`.
7. **CSRF: `X-CSRF-Token` header sourced from the `ui_csrf` cookie (FR-2).** VERIFIED (with nuance: applied to **all** requests, not only mutating).
   `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`).
8. **401 → exactly one `POST /ui/session/refresh` → retry original once; refresh failure → Unauthorized, no further retry (FR-5).** VERIFIED.
   `src/api/client.ts: refreshSession`/`api` (shared `refreshPromise`, single retry, `logout("session_expired")` on failure); OAPI-IDX `POST /ui/session/refresh | resp=200:`.
9. **Refresh is attempted only if the user was already authenticated.** VERIFIED.
   `src/api/client.ts` (`if (!useAuthStore.getState().isAuthenticated) { throw ApiError(401, ...) }`).
10. **FastAPI `detail` has three shapes — `string`, `[{msg,...}]`, `{code,...}` — and maps to a message (FR-4).** VERIFIED, with CORRECTION: object form maps **by `code`** to canned copy and falls back to the generic message for unknown codes; it does **not** read a free-form `.message`.
    `src/api/client.ts: normalizeErrorDetail` / `mapAuthorizationError`; `src/api/client.errorMapping.test.ts` ("does not leak raw object payload").
11. **422 validation body is `HTTPValidationError` (the array shape) on the create endpoint.** VERIFIED. OAPI-IDX `POST /ui/billing/checkout_session | ... resp=200:;422:HTTPValidationError`.
12. **No-network-retry for POST is consistent with the web client.** VERIFIED. `src/api/client.ts` throws `ApiError(0, "Network error")` immediately on `fetch` rejection (no retry loop).
13. **`Idempotency-Key` request header on create/retry (FR-6, R-4, §5 headers).** Unverified-assumption. No `Idempotency-Key` set in `src/api/client.ts`; no operation documents it in OAPI-IDX.
14. **~20s call-timeout constant `BillingNetwork.CALL_TIMEOUT_SECONDS == 20L` (§4.4, FR-6).** Unverified-assumption — Android/AND-227 OkHttp design value, not derivable from backend or web sources.
15. **`testlogon://pay/return` deep-link scheme/host/params and status synonym sets (FR-7..FR-11, R5).** Unverified-assumption (AND-231-owned Android convention; the web app uses hosted-redirect + server-side return, so no `src/` counterpart). The `session_id` return param is contract-consistent with claim 3.
16. **PayPal/CCBill provider return param names (`paymentId`/`token`/`PayerID`; `subscription_id`) (FR-11).** Unverified-assumption — provider/AND-228/AND-229-owned; the repo contains only **mock** PayPal routes (`POST /mock/paypal/v2/checkout/orders[/{order_id}/capture]`, OAPI-IDX), not the real return-URI shapes.
17. **CSRF-absent requests are rejected before send (§8).** Unverified-assumption — depends on an AND-227 interceptor not present in the web client.
18. **JVM/Robolectric/MockWebServer/Compose framework choices and the API-34 vs API-35 targets.** Framework ref: Android testing fundamentals — https://developer.android.com/training/testing/fundamentals ; Robolectric — https://robolectric.org/ ; OkHttp `MockWebServer` — https://square.github.io/okhttp/#mockwebserver .

### Corrections made

- §1, §3 (FR-1), §5, §6: create **request** body corrected to `BillingCheckoutReq {amount_cents, currency?, description?}` (was `provider/price_id/return_url/idempotency_key`).
- §1, §3 (FR-1), §4.3, §5, §6: create **response** corrected to `{session_id, url}` (was `checkout_session_id/client_secret/publishable_key/status/redirect_url`); `publishable_key` re-sourced to `GET /ui/billing/config`.
- §1, §3 (FR-3), §4.3, §5, §6, §13 (R2): the **confirm endpoint** and **`PaymentStatus` enum** removed/demoted — neither exists in the sources; marked AND-227-pending.
- §3 (FR-2), §8: CSRF clarified — set on all requests, present-on-POST asserted; redaction targets corrected to session cookie / CSRF token / checkout `session_id`/`url` (was non-existent `client_secret`/`publishable_key`/`Idempotency-Key`).
- §3 (FR-4), §5: object-`detail` mapping corrected to code-based-with-fallback (no `.message` extraction); array example field changed to the real `amount_cents`.
- §3 (FR-6), §5: `Idempotency-Key` demoted to unverified/conditional.
- §14 (AC 3/5/6): re-scoped to verified shapes; idempotency/confirm cases made conditional.
- Frontmatter: `status: reviewed`, `reviewed_on: 2026-06-06`.

### Open assumptions

- **A1 — Confirm/poll surface & `PaymentStatus` (claims 5, 6).** Unverifiable: no endpoint/enum in sources. Why: AND-227 may add one post-spec; until then, FR-3 fixtures are provisional and the case is `@Ignore`-free only if the surface ships.
- **A2 — `Idempotency-Key` header (claim 13).** Unverifiable: absent from web client and OpenAPI. Why: it is an Android-side reliability choice owned by AND-227; tested only if present.
- **A3 — 20s call-timeout constant (claim 14).** Unverifiable design value owned by AND-227's OkHttp config.
- **A4 — `testlogon://pay/return` scheme/params and status synonyms (claim 15).** Unverifiable: Android-only convention owned by AND-231 (no web analogue).
- **A5 — Real PayPal/CCBill return-URI param names (claim 16).** Unverifiable from this repo (only mock PayPal routes exist); owned by AND-228/AND-229 + provider docs.
- **A6 — Pre-send CSRF rejection (claim 17).** Unverifiable: depends on an AND-227 interceptor not in the web client.

## 17. Test Plan

Test IDs `TC-AND-233-NN`. Targets: **JVM** = JVM unit/Robolectric (local, no device);
**EMU** = headless emulator AVD `test35` (x86_64, API 35); **DEVICE** = physical
Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). This ticket is repository +
pure-parser logic with no UI and no hardware dependency, so every case runs on
**JVM** (and is ABI-neutral); EMU/DEVICE notes are given only where an instrumented
variant adds value. `Traces:` link to the §14 acceptance criteria (AC-1..AC-7).

- **TC-AND-233-01 — Create checkout session, happy path.**
  Type: contract/MockWebServer. Target: JVM.
  Preconditions: `MockWebServer` enqueues `200 {"session_id":"cs_test_abc","url":"https://checkout.stripe.com/c/pay/cs_test_abc"}`; valid `ui_csrf` cookie + session cookie in the jar.
  Steps: call `createCheckoutSession(BillingCheckoutReq(amountCents=1999, currency="usd", description="x"))`; capture the request via `takeRequest()`.
  Expected: result is `ApiResult.Success(CheckoutSession(sessionId="cs_test_abc", url="https://checkout.stripe.com/c/pay/cs_test_abc"))`; request was `POST /ui/billing/checkout_session`; JSON body has `amount_cents=1999`; `server.requestCount == 1`.
  Traces: AC-3.

- **TC-AND-233-02 — CSRF header + cookie attachment on create.**
  Type: contract/MockWebServer. Target: JVM.
  Preconditions: jar holds `ui_csrf=tok123` and a session cookie; enqueue `200`.
  Steps: call create; inspect recorded request headers.
  Expected: `X-CSRF-Token: tok123` present; `Cookie` header carries the session cookie; `Content-Type: application/json`.
  Traces: AC-3, AC-6.

- **TC-AND-233-03 — FastAPI `detail` mapping matrix.**
  Type: unit (parameterized). Target: JVM.
  Preconditions: a fake/real error mapper fed canned bodies.
  Steps: parameterize over {string `"Card declined."`; array `[{loc,msg:"field required",type}]`; object `{code:"role_required_scope",required_scope:"billing_support"}`; object `{code:"unknown_x"}`} × status {400,402,409,422,500}.
  Expected: string → verbatim; array → joined `msg` ("field required"); known code → canned copy containing "billing support"; unknown code → generic fallback (not raw payload); each carries the HTTP status.
  Traces: AC-4.

- **TC-AND-233-04 — Unparseable/empty error body.**
  Type: contract/MockWebServer. Target: JVM.
  Preconditions: enqueue `500` with empty body and `503` with HTML body.
  Steps: call create twice.
  Expected: `ApiResult.Error` with the status code and a generic fallback message; no exception thrown.
  Traces: AC-4.

- **TC-AND-233-05 — 401 → refresh → retry → success.**
  Type: contract/MockWebServer. Target: JVM.
  Preconditions: scripted `Dispatcher`: create→`401`, `/ui/session/refresh`→`200` (Set-Cookie), create→`200`; user state = authenticated.
  Steps: call create.
  Expected: request sequence is exactly `POST /ui/billing/checkout_session` → `POST /ui/session/refresh` → `POST /ui/billing/checkout_session`; final result `Success`; refresh attempted once.
  Traces: AC-5.

- **TC-AND-233-06 — 401 → refresh fails → Unauthorized, no extra retry.**
  Type: contract/MockWebServer. Target: JVM.
  Preconditions: create→`401`, refresh→`401`.
  Steps: call create.
  Expected: `ApiResult.Error(Unauthorized)`; exactly one refresh attempt; no second create; logout/session-expired signal emitted.
  Traces: AC-5.

- **TC-AND-233-07 — Unauthenticated 401 does not trigger refresh.**
  Type: contract/MockWebServer. Target: JVM.
  Preconditions: user state = not authenticated; create→`401`.
  Steps: call create.
  Expected: `ApiResult.Error(Unauthorized)`; **no** `/ui/session/refresh` request; `server.requestCount == 1`.
  Traces: AC-5.

- **TC-AND-233-08 — Timeout / no-response → error, zero POST retries.**
  Type: contract/MockWebServer (offline/flaky-host path). Target: JVM.
  Preconditions: create dispatched with `SocketPolicy.NO_RESPONSE`; test OkHttp uses a short injected call timeout; `runTest` + `advanceTimeBy`.
  Steps: call create; await.
  Expected: `ApiResult.Error` of network/timeout type within the budget; `server.requestCount == 1` (no auto-retry of the POST); test wall-clock << 20s.
  Traces: AC-5, AC-7.

- **TC-AND-233-09 — Offline / connection-refused mapping.**
  Type: contract/MockWebServer (offline path). Target: JVM.
  Preconditions: server started then `shutdown()` before the call (or `SocketPolicy.DISCONNECT_AT_START`).
  Steps: call create.
  Expected: `ApiResult.Error` network type (analogous to the web `ApiError(0, "Network error")`); no crash; no retry.
  Traces: AC-5, AC-7.

- **TC-AND-233-10 — Redirect-return parser, parameterized classification (fail-closed).**
  Type: unit (parameterized). Target: JVM (Robolectric only if forced onto the `android.net.Uri` overload — prefer the pure `ReturnUri` overload).
  Preconditions: `PaymentReturnParser` (pure overload) available.
  Steps: table of ≥20 `ReturnUri`s: `status=success&session_id=cs_1`; `status=cancel|canceled|cancelled`; `status=failure|failed|error`; PayPal-style `token`/`PayerID`/`paymentId`; CCBill `subscription_id`; mixed case; URL-encoded; missing `session_id` on success; unknown/empty `status`; wrong scheme/host; duplicate query keys.
  Expected: success→`Success(sessionId)`; cancel synonyms→`Cancelled`; failure synonyms / missing-required / malformed→`Failed(reason)`; **no case throws** (assert `doesNotThrowAnyException`); ≥4 malformed cases classify `Failed`; ≥1 case per subtype per provider.
  Traces: AC-2.
  Note: assertions on the deep-link scheme/synonyms are provisional per §16 A4/A5.

- **TC-AND-233-11 — Deep-link route end-to-end on device (return Intent).**
  Type: instrumented/e2e. Target: **DEVICE** (must run on the physical SM-A156U; secondary EMU `test35` run for API-35 parity). MUST run on device because real custom-tab return + `Intent`/`PackageManager` deep-link resolution and the Custom Tabs round-trip are hardware/OS-path dependent (API-34 arm64 vs API-35 x86 differences).
  Preconditions: app installed; AND-231 intent filter for `testlogon://pay/return` present; AND-233 builds merged.
  Steps: `adb shell am start -a android.intent.action.VIEW -d "testlogon://pay/return?status=success&session_id=cs_test_abc"`; observe routing.
  Expected: the activity resolves the deep link and the app routes to the success destination with `sessionId=cs_test_abc`; cancel/failure URIs route to their destinations; no other app captures the scheme.
  Traces: AC-2.
  Note: this is verification scaffolding for AND-231's filter; AND-233's own gate is the JVM parser test (TC-10).

- **TC-AND-233-12 — Security: no secret/session material in logs.**
  Type: contract/MockWebServer. Target: JVM.
  Preconditions: test-installed `BUFFER`-level OkHttp logger capturing to a buffer; jar with `ui_csrf` + session cookie; enqueue `200` create.
  Steps: call create; read captured log text.
  Expected: the session-cookie value, `X-CSRF-Token` value, and checkout `session_id`/`url` do **not** appear in cleartext (redacted); only test-mode ids (`cs_test_`) used; no request targeted `18.222.237.167`.
  Traces: AC-6.

- **TC-AND-233-13 — i18n: non-ASCII `detail` round-trips verbatim.**
  Type: unit. Target: JVM.
  Preconditions: enqueue `402 {"detail":"Carte refusée — solde insuffisant"}`.
  Steps: call create; read `ApiResult.Error.message`.
  Expected: the message equals the backend string byte-for-byte (no hardcoded English substitution), proving pass-through localization.
  Traces: AC-4.

- **TC-AND-233-14 — Hermeticity & runtime gate.**
  Type: integration (CI meta). Target: JVM (CI).
  Preconditions: `./gradlew :core-data:testDebugUnitTest :app:testDebugUnitTest`.
  Steps: run the full new suite with no network access.
  Expected: all cases green, none `@Ignore`d (except AND-227-pending confirm/idempotency cases, which are **absent** rather than ignored); total runtime < 10s; JaCoCo report for `billing/**` + `PaymentReturnParser` produced as an artifact.
  Traces: AC-1, AC-7.

> **Conditional cases (only if AND-227 ships the surface — see §16 A1/A2):**
> *TC-AND-233-C1* confirm-status mapping (each `PaymentStatus` value 1:1) and
> *TC-AND-233-C2* `Idempotency-Key` stability across the 401-refresh retry
> (`takeRequest()` header byte-compare). These are **not** part of the AND-233
> green gate until the corresponding production contract exists; until then they
> are tracked, not authored, to avoid asserting a fabricated contract.

### Coverage matrix

| §14 AC | Covered by |
| --- | --- |
| AC-1 (suites pass, none ignored) | TC-14 |
| AC-2 (parser FR-7..FR-11, ≥4 fail-closed) | TC-10, TC-11 |
| AC-3 (FR-1/FR-2: method/path/CSRF/cookies/parsed model) | TC-01, TC-02 |
| AC-4 (FR-4: detail matrix × statuses) | TC-03, TC-04, TC-13 |
| AC-5 (FR-5 both branches; FR-6/R-3 timeout no-retry) | TC-05, TC-06, TC-07, TC-08, TC-09 |
| AC-6 (no secret material logged; test-mode ids; no dev host) | TC-02, TC-12 |
| AC-7 (hermetic, deterministic, <10s, CI-wired) | TC-08, TC-09, TC-14 |
