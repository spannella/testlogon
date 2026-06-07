---
id: AND-232
title: Billing ViewModels + error mapping
milestone: M5
epic: E31
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-223, AND-015]
blocks: [AND-227, AND-230, AND-231, AND-233]
---

# AND-232 — Billing ViewModels + error mapping

## 1. Overview & Goal

This ticket delivers the presentation-layer logic for the TestLogon billing feature on the native Android port: the ViewModels that drive every billing/checkout screen and the payment **state machine** that orchestrates the multi-step purchase flow, plus a billing-specific **provider error-mapping** layer that translates raw FastAPI and payment-provider (Stripe, US-bank/ACH, redirect-PSP) failures into stable, user-facing, screen-ready state.

The goal is a deterministic, fully unit-tested set of `androidx.lifecycle.ViewModel` classes in `feature-billing` that:

- Expose a `StateFlow<UiState>` per screen, consuming the typed `ApiResult<T>` from the billing repository (AND-223) without ever touching Retrofit, Moshi, or Android UI APIs directly.
- Model the payment lifecycle as an explicit, exhaustive `sealed interface PaymentState` so that the redirect/return handler (AND-231) and Compose screens reconcile against a single source of truth.
- Map provider errors using the shared `ApiError` / `normalizeErrorDetail` machinery from AND-015, extended with a billing decline-code dictionary, producing localizable messages and a recoverability classification (retryable, fatal, requires-action, requires-new-method).

Out of scope: the Retrofit service and DTOs (AND-223), the actual checkout-session creation call (AND-227), the deep-link/return parsing (AND-231), Compose UI composition, and the integration/repository tests harness (AND-233). This ticket owns only ViewModels, the state machine, and the billing error mapper.

## 2. Context & References

- **Module**: `feature-billing` (layering `app -> feature-billing -> core-*`). New code lives under `com.testlogon.android.feature.billing.vm`, `...feature.billing.state`, and `...feature.billing.error`.
- **Upstream deps**:
  - **AND-223 — Billing API + DTOs**: provides `BillingRepository`, billing DTOs, and the `/ui/billing/*` + `/api/billing/*` mappings. This ticket depends on its repository interface and domain models.
  - **AND-015 — API error model & detail mapping**: provides `ApiError(status, detail, body)`, `normalizeErrorDetail(...)`, and the FastAPI `detail` shape handling (`string | [{msg}] | {code,...}`) plus auth-code messages (`role_required`, `geo_blocked`). This ticket reuses and extends it; it does **not** re-implement it.
- **Downstream consumers**: AND-227 (checkout completion) and AND-231 (redirect return) drive transitions through the state machine defined here; AND-230 (US bank microdeposits) reuses the verification sub-state; AND-233 tests the wiring.
- **Web reference**: `src/api/endpoints/billing.ts` (endpoint calls, response shapes), `src/api/types.ts` (DTO field names, e.g. `BillingCheckoutReq`), and `src/api/client.ts` (auth/CSRF/refresh transport, `normalizeErrorDetail`). NOTE (review): the web client has **no dedicated "checkout reducer" / state machine** — the multi-step `PaymentState` machine in this ticket is an Android-native addition with no direct web counterpart (see §16 Open assumptions).
- **Backend**: FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext, unreliable). OpenAPI at `/openapi.json`. Stripe is the primary PSP; redirect PSPs and US-bank/ACH are secondary.
- **Stack**: Kotlin 2.0.21, Coroutines/Flow, Hilt (KSP), Compose/Material 3 (consumers only). JDK 17.

## 3. Functional Requirements

FR-1. Provide a `CheckoutViewModel` that loads the billing context (current plan, available payment methods, pricing) via the repository and exposes it as `StateFlow<CheckoutUiState>`.

FR-2. Provide a `PaymentViewModel` (or a `PaymentStateHolder` injected into `CheckoutViewModel`) owning the `PaymentState` machine and the `submit`, `confirm`, `onProviderReturn`, `onActionCompleted`, `cancel`, and `retry` intents.

FR-3. The state machine MUST be exhaustive and explicit. Every transition MUST be a pure function `reduce(state, event): PaymentState` so it is unit-testable without coroutines.

FR-4. The machine MUST support three completion topologies: (a) **inline confirm** (Stripe card confirmed server-side → terminal `Succeeded`), (b) **requires-action** (3DS/SCA → `RequiresAction(actionUrl)` awaiting `onActionCompleted`), and (c) **redirect** (external PSP → `RedirectPending(returnToken)` resolved by AND-231 via `onProviderReturn`).

FR-5. The machine MUST support **US-bank/microdeposit** verification as a distinct `AwaitingMicrodeposits` state (consumed by AND-230) and **cancel** from any non-terminal state → `Cancelled`.

FR-6. Every failure MUST pass through `BillingErrorMapper` and surface as `Failed(error: BillingError)` carrying a `recoverability` classification and a user-facing message; the UI offers retry only when `recoverability == Retryable`.

FR-7. ViewModels MUST debounce/guard duplicate submits (no double-charge): a submit while `state is InProgress | RequiresAction | RedirectPending | AwaitingMicrodeposits` is a no-op.

FR-8. ViewModels MUST emit one-shot side-effects (navigate-to-redirect, show-snackbar) via a `Channel`/`SharedFlow` `effects` stream, distinct from the `StateFlow` state, so re-collection on config change does not replay them.

FR-9. State MUST survive process death where feasible: the current `PaymentState` discriminant + the in-flight `checkoutSessionId`/`returnToken` are persisted via `SavedStateHandle`.

## 4. Technical Design

### 4.1 Package layout

```
feature-billing/src/main/kotlin/com/testlogon/android/feature/billing/
  vm/CheckoutViewModel.kt
  vm/PaymentViewModel.kt
  state/PaymentState.kt
  state/PaymentEvent.kt
  state/PaymentReducer.kt
  error/BillingError.kt
  error/BillingErrorMapper.kt
  error/DeclineCode.kt
```

### 4.2 State machine

```kotlin
sealed interface PaymentState {
    data object Idle : PaymentState
    data class Submitting(val methodId: String) : PaymentState
    data class Confirming(val sessionId: String) : PaymentState
    data class RequiresAction(val sessionId: String, val actionUrl: String) : PaymentState
    data class RedirectPending(val sessionId: String, val returnToken: String, val redirectUrl: String) : PaymentState
    data class AwaitingMicrodeposits(val setupIntentId: String) : PaymentState   // AND-230; verify keyed on setup_intent_id (corrected per §5/§16)
    data class Succeeded(val sessionId: String, val receiptId: String?) : PaymentState
    data class Failed(val error: BillingError, val sessionId: String?) : PaymentState
    data object Cancelled : PaymentState
}

sealed interface PaymentEvent {
    data class Submit(val methodId: String) : PaymentEvent
    data class SessionCreated(val sessionId: String, val next: NextAction) : PaymentEvent
    data object ActionCompleted : PaymentEvent
    data class ProviderReturn(val token: String, val outcome: ReturnOutcome) : PaymentEvent  // AND-231
    data class Confirmed(val receiptId: String?) : PaymentEvent
    data class Errored(val error: BillingError) : PaymentEvent
    data object Cancel : PaymentEvent
    data object Retry : PaymentEvent
}

enum class NextAction { CONFIRM_INLINE, REQUIRES_ACTION, REDIRECT, MICRODEPOSITS }
enum class ReturnOutcome { SUCCESS, CANCEL, FAILURE }
```

`PaymentReducer.reduce(state, event)` is pure and total. Illegal transitions return the current state unchanged and emit a logged invariant warning (never throw in production; throw in `debug`/tests via an assertion hook). Terminal states (`Succeeded`, `Cancelled`) accept only `Retry` (→ `Idle`).

### 4.3 ViewModels

```kotlin
@HiltViewModel
class PaymentViewModel @Inject constructor(
    private val repo: BillingRepository,          // AND-223
    private val mapper: BillingErrorMapper,
    private val reducer: PaymentReducer,
    private val savedState: SavedStateHandle,
    @IoDispatcher private val io: CoroutineDispatcher,
) : ViewModel() {

    val state: StateFlow<PaymentState>
    val effects: SharedFlow<PaymentEffect>

    fun submit(methodId: String)
    fun onActionCompleted()
    fun onProviderReturn(token: String, outcome: ReturnOutcome)   // called by AND-231
    fun cancel()
    fun retry()
    private fun dispatch(event: PaymentEvent)   // reduce + run side effects
}

sealed interface PaymentEffect {
    data class LaunchRedirect(val url: String) : PaymentEffect
    data class LaunchAction(val url: String) : PaymentEffect
    data class ShowMessage(val text: UiText) : PaymentEffect
    data object NavigateToReceipt : PaymentEffect
}
```

`dispatch` runs the reducer synchronously, publishes the new state, then performs the matching async work (repo calls) on `io`, feeding results back as new events. Async work is launched in `viewModelScope` and uses structured cancellation so `cancel()` aborts an in-flight network call. The duplicate-submit guard (FR-7) is enforced in `submit()` before dispatch.

### 4.4 Error mapper

```kotlin
data class BillingError(
    val message: UiText,
    val recoverability: Recoverability,
    val declineCode: DeclineCode?,
    val rawDetailCode: String?,
    val httpStatus: Int?,
)

enum class Recoverability { RETRYABLE, FATAL, REQUIRES_ACTION, REQUIRES_NEW_METHOD }

class BillingErrorMapper @Inject constructor(
    private val core: ErrorDetailNormalizer,   // from AND-015
) {
    fun map(result: ApiResult.Failure): BillingError
    fun map(error: ApiError): BillingError
}
```

The mapper first delegates to AND-015's `normalizeErrorDetail` to extract a `{code, msg}`/string, then consults `DeclineCode.fromProvider(...)` for billing-specific provider codes (`card_declined`, `insufficient_funds`, `expired_card`, `incorrect_cvc`, `processing_error`, `authentication_required`, `microdeposits_pending`). Classification rules: timeouts/5xx/`processing_error` → `RETRYABLE`; `authentication_required` → `REQUIRES_ACTION`; `card_declined`/`insufficient_funds`/`expired_card`/`incorrect_cvc` → `REQUIRES_NEW_METHOD`; everything else (validation, auth-context, `geo_blocked`) → `FATAL`. `UiText` is a string-resource wrapper so messages are localizable (Section 9).

> Review note: the AND-015 codes consumed here — `geo_blocked` (403 object detail), `role_required`/`role_required_scope`/`role_required_admin_profile_type`, and the FastAPI `string | [{msg}] | {code,...}` detail forms — are VERIFIED in `src/api/client.ts` (`normalizeErrorDetail`, `mapAuthorizationError`). The billing **decline-code dictionary** (`card_declined`, `insufficient_funds`, `expired_card`, `incorrect_cvc`, `processing_error`, `authentication_required`, `microdeposits_pending`) is an UNVERIFIED assumption — none of these strings appear in the backend OpenAPI or web source. Treat the dictionary as a client-owned contract to be pinned with the backend (R4), with a tolerant `UNKNOWN → FATAL` fallback.

## 5. API Contract

This ticket does not define endpoints; it **consumes** the `BillingRepository` surface from AND-223. The repository methods this ViewModel binds against (signatures owned by AND-223, reproduced for clarity):

```kotlin
interface BillingRepository {
    suspend fun loadCheckoutContext(): ApiResult<CheckoutContext>
    suspend fun createCheckoutSession(req: CheckoutSessionRequest): ApiResult<CheckoutSession>  // AND-227
    suspend fun confirmSession(sessionId: String): ApiResult<PaymentResult>
    suspend fun pollSession(sessionId: String): ApiResult<PaymentResult>
    suspend fun verifyMicrodeposits(setupIntentId: String, amounts: List<Int>): ApiResult<PaymentResult>  // AND-230
}
```

Underlying endpoints (VERIFIED against OpenAPI index + `src/api/endpoints/billing.ts`):

- `POST /ui/billing/checkout_session` — VERIFIED (op `create_checkout_session_ui_billing_checkout_session_post`, req `BillingCheckoutReq`). Web wrapper `createCheckoutSession` returns `{ session_id, url }`.
- `POST /ui/billing/us-bank/verify-microdeposits` — VERIFIED (op `verify_microdeposits_ui_billing_us_bank_verify_microdeposits_post`, req `VerifyMicrodepositsReq`). **CORRECTION**: the request is keyed on `setup_intent_id` (string, required) plus `amounts: int[]` (and optional `descriptor_code`) — NOT a `session_id`. The repository `verifyMicrodeposits` therefore takes a `setupIntentId`, not a `sessionId`.
- **CORRECTION — `loadCheckoutContext` has no single backend endpoint.** `GET /ui/billing/context` does **not** exist. The web client composes checkout context from `GET /ui/billing/config` (`getConfig`), `GET /ui/billing/settings` (`getSettings`), and `GET /ui/billing/payment-methods` (`getPaymentMethods`). AND-223 owns whatever aggregation `CheckoutContext` represents; treat the single-endpoint assumption as removed.
- **CORRECTION — `confirmSession` / `pollSession` endpoints do not exist.** There is no `POST /ui/billing/checkout_session/{id}/confirm` and no `GET /ui/billing/checkout_session/{id}` in the backend. The nearest real confirm/retry surface is `POST /ui/billing/payment-issues/{incident_id}/confirm-and-retry` and `.../retry-automatic-payment` (incident-keyed, not session-keyed). The `confirmSession`/`pollSession` repository methods are **unverified upstream assumptions** owned by AND-223/AND-227; if they cannot be backed by a real endpoint they must be redesigned around the incident/issue endpoints. This ViewModel binds to the repository signatures regardless.

Transport (VERIFIED against `src/api/client.ts`): requests carry `Authorization: Bearer <accessToken>`, the `X-CSRF-Token` header echoed from the `ui_csrf` cookie, and (when impersonating) `X-IMPERSONATION-TOKEN`; cookies ride via `credentials: include`. On a 401 for an authenticated user the client performs exactly one `POST /ui/session/refresh` (VERIFIED endpoint) then retries the original request once — this ViewModel does not handle refresh.

**CORRECTION — checkout-session response has no `next_action`/`return_token`/`status`.** The VERIFIED web contract is simply:

```json
{ "session_id": "cs_123", "url": "https://psp.example/checkout/cs_123" }
```

The `{ status, next_action: { type, url, return_token } }` shape and the `NextAction`/`ReturnOutcome` topology selector are **NOT present in the backend or web contract** (the only `next_action` field in the reference source belongs to an unrelated iCloud-files wizard). They are an Android-native modeling assumption (see §16 Open assumptions). The redirect-vs-inline-vs-action decision is, per the verified contract, currently expressed only as the presence of a hosted-checkout `url`; any richer `next_action` discriminant must be pinned with AND-223/AND-227 before relying on it.

A FastAPI error surfaces as `ApiResult.Failure(ApiError(status, detail, body))`. VERIFIED `detail` shapes (`src/api/client.ts: normalizeErrorDetail`): a plain `string`, a `422` validation array `{ "detail": [{ "loc", "msg", "type" }] }` (schema `HTTPValidationError` → `ValidationError`), or an object `{ "code", ... }` (e.g. `geo_blocked`, `role_required`/`role_required_scope`). **The provider-decline object below is an UNVERIFIED assumption** — no `card_declined`/`decline_code`/`insufficient_funds` string appears anywhere in the backend spec or web source:

```json
{ "detail": { "code": "card_declined", "decline_code": "insufficient_funds",
              "message": "Your card has insufficient funds." } }
```

## 6. Data & State Management

- **Single source of truth**: `PaymentState` (`StateFlow`, `WhileSubscribed(5_000)`), seeded from `SavedStateHandle` keys `pmt_state_kind`, `pmt_session_id`, `pmt_return_token`.
- `CheckoutUiState` is a separate `StateFlow` holding screen chrome: `data class CheckoutUiState(val loading: Boolean, val context: CheckoutContext?, val error: BillingError?, val payment: PaymentState)`. It combines the repo context flow with `PaymentViewModel.state`.
- **Effects** (`PaymentEffect`) flow over a `MutableSharedFlow(extraBufferCapacity = 1, replay = 0)` so they fire exactly once.
- **Process death**: on restore, a non-terminal persisted state triggers a single `pollSession(sessionId)` to reconcile with the backend before re-rendering, preventing a stuck spinner. Redirect tokens are persisted so AND-231's `onProviderReturn` can match after process death. (Review caveat: `pollSession` has no verified backend GET endpoint — see §5/§16; the reconcile path depends on AND-223 providing a real status-read surface, e.g. an incident/payment-issue read.)
- No Room/DataStore writes here; caching of context is AND-223's concern.

## 7. Error Handling & Resilience

- All repository failures route through `BillingErrorMapper`; the ViewModel never surfaces a raw `Throwable` or `ApiError`.
- **Timeouts/transient** (`SocketTimeout`, 502/503/504, `processing_error`) → `RETRYABLE`; the Failed state exposes a retry affordance backed by `retry()`. Given the unreliable dev host (~20s timeouts), retries are **manual** for the charge path (non-idempotent POST must never auto-retry to avoid double charges). Only the idempotent `pollSession`/`loadCheckoutContext` GETs use the network layer's bounded backoff.
- **Idempotency**: `CheckoutSessionRequest` carries a client-generated idempotency key (UUID held in `SavedStateHandle`) so a user-initiated retry after an ambiguous timeout reuses the same key.
- **Requires-action / redirect**: a timeout while awaiting return does not fail the purchase; `onProviderReturn`/`pollSession` remain authoritative.
- Illegal state transitions are swallowed in release (logged) and asserted in test/debug.
- Cancellation: `cancel()` cancels the in-flight job and reduces to `Cancelled`; no charge is assumed cancelled server-side unless the PSP confirms it (UI message reflects this ambiguity for `RedirectPending`).

## 8. Security & Privacy

- No PAN/card data ever transits or is held by these ViewModels; only opaque `methodId`, `sessionId`, and `returnToken` strings. Raw card entry is delegated to the PSP redirect/SDK (out of scope).
- `BillingError.rawDetailCode` and logs MUST NOT include amounts tied to identity, full card numbers, or `return_token` values in plaintext beyond last-4/masked forms. The mapper strips provider raw blobs from user-facing `UiText`.
- CSRF/session handling is the network layer's responsibility; this ticket asserts it never logs cookie or `X-CSRF-Token` values.
- `SavedStateHandle` persistence stores only non-sensitive identifiers (session id, token, state kind); no credentials.

## 9. Accessibility & i18n

- All user-facing strings are `UiText` references to `strings.xml` resource ids (e.g. `R.string.billing_err_card_declined`); no hardcoded English in ViewModels. Decline-code → resource mapping lives in `DeclineCode` and is enumerated for translation.
- Plurals/currency formatting is deferred to the Compose layer via `UiText.Plural`/`UiText.Args`; the ViewModel passes structured args, not formatted strings, so locale formatting happens at render time.
- State changes that matter to assistive tech (success, failure, requires-action) are exposed as distinct state discriminants so the UI can announce them via `liveRegion` — no accessibility logic in the ViewModel itself, but the state contract enables it.

## 10. Telemetry & Logging

- Emit structured analytics events at each terminal/branch transition: `billing_submit`, `billing_requires_action`, `billing_redirect`, `billing_succeeded`, `billing_failed`(with `recoverability`, `declineCode`, `httpStatus`), `billing_cancelled`. Use the app's analytics abstraction (injected `Analytics` interface) — no direct vendor calls.
- No PII/PAN in event params; only enums, codes, and masked ids.
- Debug logging via `Timber`-style tag `BillingVM`; transition logs include `from`/`to`/`event` names only. Release builds strip verbose transition logs.

## 11. Testing Strategy

Per the ticket's sole acceptance bullet ("Unit-tested"), unit tests are the deliverable.

- **Reducer tests** (`PaymentReducerTest`): exhaustive table-driven coverage of `(state, event) → state` for all four topologies, terminal-state guards, illegal-transition no-ops, and cancel-from-each-state. Pure, no coroutines.
- **ViewModel tests** (`PaymentViewModelTest`): use `kotlinx-coroutines-test` `StandardTestDispatcher`, a fake `BillingRepository` (from `core-testing`) returning scripted `ApiResult`s, and Turbine for `state`/`effects` assertions. Cover: happy inline confirm, requires-action → completed, redirect → `onProviderReturn(SUCCESS|CANCEL|FAILURE)`, microdeposits, duplicate-submit guard (FR-7), one-shot effect non-replay (FR-8), `SavedStateHandle` restore + reconcile poll (FR-9), cancel aborts in-flight job.
- **Mapper tests** (`BillingErrorMapperTest`): representative FastAPI bodies (`string`, `[{msg}]`, `{code,...}`), each Stripe/ACH decline code → expected `Recoverability` + resource id, timeout/5xx → `RETRYABLE`, `geo_blocked`/validation → `FATAL`. Verifies reuse of AND-015 normalizer (no duplicated logic).
- Coverage target: 90%+ line coverage on `state/`, `error/`, `vm/` packages. Tests run on JVM (no instrumentation). Repository/redirect integration tests are AND-233.

## 12. Dependencies & Sequencing

- **Blocked by**: AND-223 (repository + DTOs must exist to compile against) and AND-015 (error normalizer to extend). Both are P0 in M5/M1.
- **Blocks / enables**: AND-227 (checkout completion drives `submit`/`Confirmed`), AND-231 (redirect return calls `onProviderReturn`), AND-230 (microdeposit verify uses `AwaitingMicrodeposits`), AND-233 (billing tests build on these contracts).
- **Sequencing**: land the `state/` + `error/` packages first (pure, no async), then the ViewModels. Coordinate the `PaymentEvent.ProviderReturn` signature with AND-231 before merge to avoid churn; coordinate `NextAction`/`CheckoutSession.next_action` field names with AND-223/AND-227.

## 13. Risks & Open Questions

- **R1**: `next_action.type` enum values from the backend are not yet pinned in `/openapi.json` for redirect PSPs — confirm exact strings with AND-223; mismatch breaks `NextAction` mapping. Mitigation: tolerant parsing with an `UNKNOWN → FATAL` fallback.
- **R2**: Double-charge on ambiguous POST timeout — mitigated by client idempotency key (Section 7); requires backend to honor it (open question for FastAPI team).
- **R3**: Redirect return after process death — depends on AND-231 persisting/matching `return_token`; contract agreed here but implementation lands there.
- **R4**: Decline-code taxonomy may diverge between Stripe and ACH/US-bank; `DeclineCode` enum may need extension when AND-230 lands. Open question: canonical list owned by backend or client?
- **R5**: Whether `confirmSession` is truly idempotent for retry — assumed not; treated as manual-retry only.

## 14. Acceptance Criteria

- AC-1: `PaymentReducer.reduce` is pure and total; all `(state, event)` pairs covered by unit tests, including illegal-transition no-ops and cancel-from-every-non-terminal-state.
- AC-2: All four completion topologies (inline confirm, requires-action, redirect, microdeposits) reach `Succeeded` via their correct paths in unit tests with a fake repository.
- AC-3: `onProviderReturn` with `SUCCESS`/`CANCEL`/`FAILURE` routes to `Succeeded`/`Cancelled`/`Failed` respectively (parity with AND-231 contract), unit-tested.
- AC-4: Duplicate `submit()` while in a non-terminal in-flight state is a verified no-op (no second repo call).
- AC-5: `BillingErrorMapper` maps representative FastAPI `detail` shapes and provider decline codes to the expected `Recoverability` + localizable message resource id, unit-tested; reuses AND-015's `normalizeErrorDetail`.
- AC-6: One-shot `PaymentEffect`s fire exactly once and are not replayed on re-collection (Turbine-verified).
- AC-7: `SavedStateHandle` restore of a non-terminal state triggers exactly one reconcile poll, unit-tested.
- AC-8: No ViewModel surfaces a raw `Throwable`/`ApiError`; every failure is a `Failed(BillingError)`.
- AC-9: JVM unit-test suite passes with ≥90% line coverage on `state/`, `error/`, `vm/`.

## 15. Definition of Done

- Code merged to `android-port` under `feature-billing` with package base `com.testlogon.android`, building under AGP 8.7.3 / Gradle 8.9 / JDK 17, Kotlin 2.0.21, Hilt (KSP).
- All Section 14 acceptance criteria met; CI green (`./gradlew :feature-billing:testDebugUnitTest`), ktlint/detekt clean.
- No Android-framework or Retrofit imports in `vm/`, `state/`, `error/` (verified by an architecture/import lint rule).
- All user-facing strings externalized to `strings.xml`; no hardcoded literals in ViewModels.
- Public ViewModel/state/event/mapper signatures reviewed and agreed with owners of AND-227, AND-231, AND-230, AND-233.
- KDoc on the state machine and mapper; reviewer sign-off; ticket linked to AND-223 and AND-015.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. Sources: OpenAPI index `reference/openapi.index.txt`, OpenAPI spec `reference/openapi.pretty.json` (`components.schemas.<Name>`), and frontend `reference/src/*`.

1. **Checkout-session creation endpoint** `POST /ui/billing/checkout_session` (req `BillingCheckoutReq`). VERDICT: Verified. SOURCE: OpenAPI `POST /ui/billing/checkout_session` (op `create_checkout_session_ui_billing_checkout_session_post`); `src/api/endpoints/billing.ts: createCheckoutSession`.
2. **Checkout-session response shape `{ session_id, url }`** (no `status`/`next_action`/`return_token`). VERDICT: Corrected (spec had a richer `next_action`/`return_token` object). SOURCE: `src/api/endpoints/billing.ts: createCheckoutSession` return type `{ session_id: string; url: string }`.
3. **`next_action.type ∈ confirm_inline | requires_action | redirect | microdeposits` discriminant** on the checkout response. VERDICT: Unverified-assumption (absent from backend + web). SOURCE: no match in `openapi.pretty.json` or `src/api/**` for billing; only an unrelated `next_action` in `src/api/endpoints/files.ts` (iCloud wizard). Mitigated by R1's tolerant `UNKNOWN → FATAL` parsing.
4. **`BillingCheckoutReq` = `{ amount_cents (int, required), currency?, description? }`**. VERDICT: Verified. SOURCE: `components.schemas.BillingCheckoutReq` (openapi.pretty.json); `src/api/types.ts: BillingCheckoutReq`.
5. **Client-generated idempotency key inside `CheckoutSessionRequest`**. VERDICT: Unverified-assumption. SOURCE: not a field of `BillingCheckoutReq` (schema has only `amount_cents/currency/description`); no idempotency header logic in `src/api/client.ts`. Owned/honored by backend per R2 (open).
6. **Microdeposit verification endpoint** `POST /ui/billing/us-bank/verify-microdeposits` (req `VerifyMicrodepositsReq`). VERDICT: Verified. SOURCE: OpenAPI `POST /ui/billing/us-bank/verify-microdeposits` (op `verify_microdeposits_ui_billing_us_bank_verify_microdeposits_post`); `src/api/endpoints/billing.ts: verifyMicrodeposits`.
7. **Microdeposit verify is keyed on `setup_intent_id` (+ `amounts: int[]`, `descriptor_code?`), not `session_id`.** VERDICT: Corrected (spec method took `sessionId`). SOURCE: `components.schemas.VerifyMicrodepositsReq` (required `setup_intent_id`); `src/api/endpoints/billing.ts: verifyMicrodeposits` (`{ setup_intent_id, amounts: [number, number] }`).
8. **`GET /ui/billing/context` (single checkout-context endpoint).** VERDICT: Corrected (endpoint does not exist). SOURCE: no `/ui/billing/context` in `openapi.index.txt`; web composes context from `GET /ui/billing/config`, `GET /ui/billing/settings`, `GET /ui/billing/payment-methods` (`src/api/endpoints/billing.ts: getConfig/getSettings/getPaymentMethods`).
9. **`POST /ui/billing/checkout_session/{id}/confirm` and `GET /ui/billing/checkout_session/{id}` (confirm/poll).** VERDICT: Corrected (neither exists). SOURCE: absent from `openapi.index.txt`; nearest real surface `POST /ui/billing/payment-issues/{incident_id}/confirm-and-retry` and `.../retry-automatic-payment`. `confirmSession`/`pollSession` remain unverified upstream (AND-223/AND-227).
10. **Auth/transport: `Authorization: Bearer`, `X-CSRF-Token` echoed from `ui_csrf` cookie, cookie credentials, optional `X-IMPERSONATION-TOKEN`.** VERDICT: Verified. SOURCE: `src/api/client.ts` (lines ~157-171 set headers; `credentials: include`).
11. **On 401 (authenticated) the client does one `POST /ui/session/refresh` then retries once.** VERDICT: Verified. SOURCE: `src/api/client.ts: refreshSession` + 401 branch; OpenAPI `POST /ui/session/refresh` (op `ui_session_refresh_ui_session_refresh_post`).
12. **FastAPI `detail` shapes handled: `string | [{msg}] | {code,...}`.** VERDICT: Verified. SOURCE: `src/api/client.ts: normalizeErrorDetail`; 422 `HTTPValidationError = { detail: [ValidationError{loc,msg,type}] }` (`components.schemas.HTTPValidationError`/`ValidationError`).
13. **Auth/permission codes `geo_blocked`, `role_required` (+ `role_required_scope`, `role_required_admin_profile_type`) classified `FATAL`.** VERDICT: Verified. SOURCE: `src/api/client.ts: mapAuthorizationError` and the 403 `geo_blocked` branch.
14. **`ApiError(status, detail, body)` model reused from AND-015.** VERDICT: Verified. SOURCE: `src/api/client.ts: class ApiError`.
15. **Billing decline-code dictionary (`card_declined`, `insufficient_funds`, `expired_card`, `incorrect_cvc`, `processing_error`, `authentication_required`, `microdeposits_pending`) and the `{code, decline_code, message}` error body.** VERDICT: Unverified-assumption. SOURCE: zero matches for these strings in `openapi.pretty.json` or `src/api/**`. Client-owned contract pending backend (R4).
16. **No web "checkout reducer"/state machine to mirror; `PaymentState` machine is Android-native.** VERDICT: Corrected (§2 implied web parity). SOURCE: no reducer/state-machine in `src/api/endpoints/billing.ts` or billing pages; web wrappers are stateless one-shot calls.
17. **ViewModel framework choices: `androidx.lifecycle.ViewModel`, `SavedStateHandle`, `StateFlow`/`SharedFlow`, `viewModelScope`, Hilt `@HiltViewModel`.** VERDICT: Verified (framework ref). SOURCE: framework ref https://developer.android.com/topic/libraries/architecture/viewmodel and https://developer.android.com/topic/libraries/architecture/viewmodel/viewmodel-savedstate ; Hilt https://developer.android.com/training/dependency-injection/hilt-jetpack#viewmodels .

### Corrections made

- §5: removed non-existent `GET /ui/billing/context`; documented context is composed from `config` + `settings` + `payment-methods` (cite 8).
- §5: removed non-existent `POST .../checkout_session/{id}/confirm` and `GET .../checkout_session/{id}`; flagged `confirmSession`/`pollSession` as unverified upstream (cite 9).
- §5: corrected checkout-session response to the real `{ session_id, url }`; demoted `next_action`/`status`/`return_token` to an Android-native assumption (cites 2, 3).
- §5 + §4.2 + repo interface: corrected microdeposit verification to be keyed on `setup_intent_id` (not `session_id`); renamed `AwaitingMicrodeposits.sessionId` → `setupIntentId` and `verifyMicrodeposits(setupIntentId, …)` (cites 6, 7).
- §5: flagged the `{code, decline_code, message}` decline body as unverified; kept the verified `string | [{msg}] | {code}` shapes (cites 12, 15).
- §4.4: added a verified-vs-assumed split for AND-015 codes vs the decline dictionary (cites 13, 15).
- §2: corrected web-reference paths (dropped the `frontend/` prefix; pointed at real files) and noted there is no web checkout reducer (cite 16).
- §6: added caveat that the reconcile `pollSession` has no verified backend GET endpoint (cite 9).

### Open assumptions

- **AO-1 (cite 3):** the checkout `next_action` discriminant and the four-topology selector are not in any verified source; the redirect/inline/action branch is currently inferable only from presence of a hosted-checkout `url`. Cannot be verified — backend has not pinned it (R1). Mitigation: tolerant parsing, `UNKNOWN → FATAL`.
- **AO-2 (cite 5):** client idempotency key is not part of `BillingCheckoutReq` nor any header in the web client; backend honoring it is an open question (R2).
- **AO-3 (cite 9):** `confirmSession`/`pollSession` have no backing endpoint; the inline-confirm terminal path and process-death reconcile poll depend on AND-223/AND-227 supplying a real status surface (possibly the payment-issues/incident endpoints).
- **AO-4 (cite 15):** the provider decline-code taxonomy is unconfirmed; canonical ownership (backend vs client) is unresolved (R4).
- **AO-5:** `return_token` / redirect-return matching is owned by AND-231 and not present in the verified checkout contract; persistence/matching is a cross-ticket assumption.

## 17. Test Plan

All cases are JVM/Robolectric unit tests per the ticket's sole acceptance bullet ("Unit-tested") — this ticket owns ViewModels, the reducer, and the mapper with **no Android-framework, Retrofit, or real-network surface** (see §15). No case here requires an emulator or the physical device; repository/redirect integration and any device behavior are AND-233/AND-231. Test targets are called out per case; the device/emulator note is included for completeness and to mark which (none) require hardware.

Test-target legend: **JVM** = local JVM unit (kotlinx-coroutines-test + Turbine + fake `BillingRepository` from `core-testing`); **Robolectric** = JVM with `SavedStateHandle` shadow.

- **TC-AND-232-01** — Reducer exhaustiveness & purity.
  - Type: unit. Target: JVM (no device). Preconditions: pure `PaymentReducer`.
  - Steps: table-drive `reduce(state, event)` over every `PaymentState × PaymentEvent` pair, including terminal-state guards (`Succeeded`/`Cancelled` accept only `Retry → Idle`) and illegal transitions.
  - Expected: every legal pair yields the specified next state; illegal pairs return the input state unchanged and trip the debug assertion hook (no throw in release). Function is deterministic with no coroutine/IO.
  - Traces: AC-1.
- **TC-AND-232-02** — Inline-confirm happy path to `Succeeded`.
  - Type: unit. Target: JVM. Preconditions: fake repo scripted so `createCheckoutSession` returns `ApiResult.Success(CheckoutSession(session_id="cs_1", url=...))` and the confirm path resolves successfully.
  - Steps: `submit(methodId)`; advance dispatcher; feed `SessionCreated(CONFIRM_INLINE)` then `Confirmed(receiptId)`.
  - Expected: state transitions `Idle → Submitting → Confirming → Succeeded(sessionId="cs_1", receiptId)`; a `NavigateToReceipt` effect is emitted once.
  - Traces: AC-2, AC-8.
- **TC-AND-232-03** — Requires-action (3DS/SCA) path to `Succeeded`.
  - Type: unit. Target: JVM. Preconditions: fake repo returns a session whose mapped `NextAction == REQUIRES_ACTION` (Android-native shape per AO-1).
  - Steps: `submit`; on `SessionCreated(REQUIRES_ACTION)` assert `RequiresAction(actionUrl)` + a single `LaunchAction(url)` effect; call `onActionCompleted()`; resolve to `Confirmed`.
  - Expected: `Idle → Submitting → RequiresAction → Confirming → Succeeded`; `LaunchAction` fires exactly once.
  - Traces: AC-2, AC-6.
- **TC-AND-232-04** — Redirect PSP path resolved via `onProviderReturn(SUCCESS|CANCEL|FAILURE)`.
  - Type: unit. Target: JVM. Preconditions: fake repo session maps to `NextAction == REDIRECT`.
  - Steps: `submit`; assert `RedirectPending` + single `LaunchRedirect(url)`; then run three sub-cases: `onProviderReturn(token, SUCCESS)`, `(token, CANCEL)`, `(token, FAILURE)`.
  - Expected: routes to `Succeeded`, `Cancelled`, and `Failed(BillingError)` respectively (parity with AND-231).
  - Traces: AC-2, AC-3, AC-8.
- **TC-AND-232-05** — Microdeposits path keyed on `setup_intent_id`.
  - Type: unit. Target: JVM. Preconditions: fake repo `verifyMicrodeposits(setupIntentId, amounts)` returns success.
  - Steps: drive to `AwaitingMicrodeposits(setupIntentId)`; call verify with two integer amounts; resolve.
  - Expected: state carries `setupIntentId` (NOT a session id); verify is invoked with `setupIntentId` + `amounts: List<Int>`; reaches `Succeeded`. Confirms the §7/§16 correction.
  - Traces: AC-2.
- **TC-AND-232-06** — Duplicate-submit guard (no double charge).
  - Type: unit. Target: JVM. Preconditions: fake repo `createCheckoutSession` suspends (in-flight).
  - Steps: call `submit()`; while state ∈ {`Submitting`,`RequiresAction`,`RedirectPending`,`AwaitingMicrodeposits`}, call `submit()` again.
  - Expected: second `submit()` is a no-op; fake repo records exactly one `createCheckoutSession` call.
  - Traces: AC-4.
- **TC-AND-232-07** — One-shot effects fire exactly once (no replay on re-collection).
  - Type: unit. Target: JVM (Turbine). Preconditions: effects over `MutableSharedFlow(replay=0, extraBufferCapacity=1)`.
  - Steps: trigger an effect (e.g. `LaunchRedirect`); collect via Turbine; cancel and re-collect `effects`.
  - Expected: effect observed once on first collection; re-collection receives no replayed item; `state` re-collection still yields current state.
  - Traces: AC-6.
- **TC-AND-232-08** — `SavedStateHandle` restore triggers exactly one reconcile.
  - Type: unit. Target: Robolectric (SavedStateHandle). Preconditions: handle pre-seeded with a non-terminal `pmt_state_kind` + `pmt_session_id`.
  - Steps: construct the ViewModel; advance dispatcher.
  - Expected: exactly one reconcile call (`pollSession`, per AO-3 stand-in) is made; terminal restored states make zero reconcile calls. Asserts single-poll behavior.
  - Traces: AC-7.
- **TC-AND-232-09** — Mapper: FastAPI detail shapes → message.
  - Type: unit. Target: JVM. Preconditions: real shapes from sources.
  - Steps: feed `ApiError` bodies: (a) `detail` = plain string; (b) 422 `{ "detail": [{ "loc":["body","amount_cents"], "msg":"field required", "type":"value_error.missing" }] }` (`HTTPValidationError`); (c) `{ "detail": { "code":"geo_blocked", "message":"…" } }`; (d) `{ "detail": { "code":"role_required_scope", "required_scope":"billing_support" } }`.
  - Expected: messages match `normalizeErrorDetail`/`mapAuthorizationError` outputs; (c) and (d) classify `FATAL`; no duplicated normalization logic (AND-015 reused).
  - Traces: AC-5, AC-8.
- **TC-AND-232-10** — Mapper: decline codes → `Recoverability` + resource id.
  - Type: unit. Target: JVM. Preconditions: decline dictionary (AO-4, assumption-backed).
  - Steps: map `card_declined`/`insufficient_funds`/`expired_card`/`incorrect_cvc` → `REQUIRES_NEW_METHOD`; `authentication_required` → `REQUIRES_ACTION`; `processing_error` → `RETRYABLE`; `microdeposits_pending` → (state, not fatal); an unknown code → `FATAL` (UNKNOWN fallback).
  - Expected: each maps to the documented `Recoverability` and a non-null `UiText` string-resource id; unknown codes do not crash and resolve `FATAL`.
  - Traces: AC-5.
- **TC-AND-232-11** — Transient/offline failures → `RETRYABLE` and manual retry only.
  - Type: unit. Target: JVM. Preconditions: fake repo returns `ApiResult.Failure` for `ApiError(0, "Network error")` (offline/flaky dev host), `ApiError(503)`, `ApiError(504)`, and `processing_error`.
  - Steps: submit; observe `Failed`; call `retry()`.
  - Expected: each maps to `Recoverability.RETRYABLE`; UI-facing retry affordance present; the non-idempotent POST charge path is NOT auto-retried (only `retry()` triggers a new attempt) — guards against double charge on the unreliable host.
  - Traces: AC-5, AC-8.
- **TC-AND-232-12** — Cancel from any non-terminal state aborts in-flight work.
  - Type: unit. Target: JVM. Preconditions: fake repo `createCheckoutSession`/confirm suspends.
  - Steps: drive to an in-flight non-terminal state; call `cancel()`.
  - Expected: state → `Cancelled`; the in-flight `viewModelScope` job is cancelled (structured cancellation); no further repo result is applied; for `RedirectPending`, the cancel message reflects server-side ambiguity.
  - Traces: AC-1, AC-8.
- **TC-AND-232-13** — Security: no PAN / secrets / raw blobs leak.
  - Type: unit. Target: JVM. Preconditions: spy `Analytics` + log capture.
  - Steps: drive failure and success flows with synthetic payloads; inspect emitted analytics params, `BillingError.message`/`rawDetailCode`, and transition logs.
  - Expected: only enums/codes/masked ids present; no card numbers, no `ui_csrf`/`X-CSRF-Token`/cookie values, no full `return_token`; mapper strips provider raw blobs from user-facing `UiText`; `SavedStateHandle` holds only non-sensitive ids.
  - Traces: AC-8.
- **TC-AND-232-14** — Accessibility/i18n contract: state discriminants + `UiText`, no hardcoded strings.
  - Type: unit. Target: JVM. Preconditions: ktlint/detekt + an import/arch lint rule, plus reflective scan.
  - Steps: assert every user-facing `BillingError.message` is a `UiText` resource reference (not a raw `String`); assert distinct discriminants exist for success/failure/requires-action so the UI can announce via `liveRegion`; assert no `android.*`/Retrofit imports in `vm/`,`state/`,`error/`.
  - Expected: zero hardcoded English literals in ViewModels; all decline-code → resource mappings enumerated; arch-import rule passes.
  - Traces: AC-5, AC-9.

### Coverage matrix

| AC | Covered by |
|----|-----------|
| AC-1 (reducer pure/total, illegal no-ops, cancel-from-each) | TC-01, TC-12 |
| AC-2 (all four topologies reach Succeeded) | TC-02, TC-03, TC-04, TC-05 |
| AC-3 (`onProviderReturn` SUCCESS/CANCEL/FAILURE routing) | TC-04 |
| AC-4 (duplicate-submit no-op) | TC-06 |
| AC-5 (mapper shapes + decline codes + resource ids; reuse AND-015) | TC-09, TC-10, TC-11, TC-14 |
| AC-6 (one-shot effects, no replay) | TC-03, TC-07 |
| AC-7 (restore → exactly one reconcile) | TC-08 |
| AC-8 (no raw Throwable/ApiError; always `Failed(BillingError)`) | TC-02, TC-04, TC-09, TC-11, TC-12, TC-13 |
| AC-9 (≥90% coverage on state/error/vm; JVM suite) | TC-01–TC-14 (aggregate), TC-14 (arch/import) |
