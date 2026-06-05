---
id: AND-233
title: Billing tests
milestone: M5
epic: E31
priority: P1
size: M
status: draft
depends_on: [AND-227, AND-231]
blocks: []
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
   `/ui/billing/checkout_session` create + confirm flow, mapped `ApiResult<T>`
   outcomes, FastAPI `detail` error mapping, retry/timeout policy, and
   idempotency-key behavior.
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
- **Web reference:** `frontend/src/api/endpoints/*.ts` for the checkout-session
  request/response shape; `frontend/src/api/types.ts` for shared types.

## 3. Functional Requirements

This being a test ticket, "functional requirements" are the behaviors the suite
must assert. The suite **must fail** if any of the following regress.

**FR-1 — Checkout-session creation (happy path).** Given valid input,
`BillingRepository.createCheckoutSession` returns
`ApiResult.Success(CheckoutSession)` with the parsed `clientSecret`,
`checkoutSessionId`, and `publishableKey`, and issues exactly one
`POST /ui/billing/checkout_session`.

**FR-2 — CSRF + cookies.** The create/confirm requests carry the `X-CSRF-Token`
header sourced from the `ui_csrf` cookie, and the persistent cookie jar's
cookies are attached.

**FR-3 — Confirmation status mapping.** `confirmCheckoutSession` maps backend
`status` values (`"requires_action" | "processing" | "succeeded" | "canceled"
| "failed"`) to the domain `PaymentStatus` enum 1:1.

**FR-4 — Error mapping.** FastAPI `detail` in all three shapes — `string`,
`[{msg,...}]`, `{code,...}` — maps to `ApiResult.Error` with the correct
human-readable message and optional machine `code`. HTTP 4xx/5xx without a
parseable body maps to a generic `ApiResult.Error` with the status code.

**FR-5 — 401 refresh-once.** A `401` on a create/confirm call triggers exactly
one `POST /ui/session/refresh`; on refresh success the original call is retried
once and may succeed; on refresh failure the result is
`ApiResult.Error(Unauthorized)` and no further retry occurs.

**FR-6 — Timeout & retry policy.** A non-responding create call surfaces
`ApiResult.Error` within the ~20s budget. **POST is not retried for network
errors** (non-idempotent); only the documented 401-refresh retry applies.
Idempotency is protected by an `Idempotency-Key` header that is **stable across
the 401 retry** for a given attempt.

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
    suspend fun createCheckoutSession(
        request: CheckoutSessionRequest,
    ): ApiResult<CheckoutSession>

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
endpoints. The fixtures encode these shapes.

**Create — `POST /ui/billing/checkout_session`**

Request body:
```json
{
  "provider": "stripe",
  "price_id": "price_test_123",
  "return_url": "testlogon://pay/return",
  "idempotency_key": "f0c1...uuid"
}
```
Headers: `X-CSRF-Token: <ui_csrf>`, `Content-Type: application/json`,
`Idempotency-Key: <same uuid>`, plus session cookies.

Success `200`:
```json
{
  "checkout_session_id": "cs_test_abc",
  "client_secret": "cs_test_abc_secret_xyz",
  "publishable_key": "pk_test_...",
  "status": "requires_action",
  "redirect_url": null
}
```

For redirect providers (PayPal/CCBill), `redirect_url` is a non-null https URL
and `client_secret` may be null — a fixture variant covers this.

**Confirm — `POST /ui/billing/checkout_session/{id}/confirm`** (path per AND-227)

Success `200`:
```json
{ "status": "succeeded" }
```

`status` ∈ `requires_action | processing | succeeded | canceled | failed`.

**Error responses** (all three FastAPI `detail` shapes asserted):
```json
{ "detail": "Card declined." }
```
```json
{ "detail": [ { "loc": ["body","price_id"], "msg": "field required", "type": "value_error.missing" } ] }
```
```json
{ "detail": { "code": "payment_intent_authentication_failure", "message": "Authentication required." } }
```

**Refresh — `POST /ui/session/refresh`** — `200` (sets new cookies) or `401`.

## 6. Data & State Management

- **No Room/DataStore writes are introduced** by this ticket. If
  `BillingRepository` persists a pending-session marker to DataStore/Room
  (per AND-227), the test injects an in-memory fake from `core-testing` and
  asserts the marker is written on create and cleared on terminal status.
- **Domain models asserted:** `CheckoutSession(checkoutSessionId, clientSecret,
  publishableKey, status, redirectUrl)` and `PaymentStatus` enum. Tests assert
  exhaustive `when` coverage of the enum via a "no else branch" compile-time
  guarantee plus a value-by-value mapping table test.
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

- Tests must assert that **no secret material is logged**: the suite captures
  the OkHttp logging interceptor output (test-installed `BUFFER`-level logger)
  and asserts `client_secret`, `publishable_key`, and `Idempotency-Key` values
  do not appear in redacted log lines (AND-227/AND-232 are expected to redact;
  if they do not, this test fails and surfaces the gap).
- Tests assert `X-CSRF-Token` is present on all mutating billing requests and
  absent values cause the request to be rejected before send (if the production
  interceptor enforces this).
- Fixtures use only Stripe **test-mode** identifiers (`pk_test_`, `cs_test_`,
  `price_test_`). No real keys, PANs, or live cookies enter the repo. The dev
  backend is never contacted from tests.

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
- **R2 — Confirm endpoint path.** AND-227's exact confirm path
  (`/ui/billing/checkout_session/{id}/confirm` vs a status `GET`) must be
  confirmed against `/openapi.json`; fixtures pin whichever ships. **Open
  question.**
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
3. `BillingRepositoryTest` proves FR-1..FR-3 against `MockWebServer`, asserting
   the request method/path, `X-CSRF-Token` header, cookie attachment, and parsed
   `CheckoutSession`/`PaymentStatus` mapping.
4. `BillingErrorMappingTest` proves FR-4 across all three FastAPI `detail` shapes
   × ≥5 status codes, with correct message and `code`.
5. `BillingRepositoryNetworkTest` proves FR-5 (401→refresh→retry, both
   branches), FR-6/R-3 (timeout with zero POST retries), and R-4 (stable
   `Idempotency-Key` across the refresh retry).
6. Security assertions (Section 8) pass: no `client_secret`/`publishable_key`/
   `Idempotency-Key` appears in captured log output; only test-mode identifiers
   are used; no test contacts `18.222.237.167`.
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
