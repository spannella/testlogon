---
id: AND-232
title: Billing ViewModels + error mapping
milestone: M5
epic: E31
priority: P0
size: M
status: draft
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
- **Web reference**: `frontend/src/api/endpoints/billing.ts` (flow ordering, error keys), `frontend/src/api/types.ts` (DTO field names), and the web checkout reducer for state parity.
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
    data class AwaitingMicrodeposits(val sessionId: String) : PaymentState   // AND-230
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

## 5. API Contract

This ticket does not define endpoints; it **consumes** the `BillingRepository` surface from AND-223. The repository methods this ViewModel binds against (signatures owned by AND-223, reproduced for clarity):

```kotlin
interface BillingRepository {
    suspend fun loadCheckoutContext(): ApiResult<CheckoutContext>
    suspend fun createCheckoutSession(req: CheckoutSessionRequest): ApiResult<CheckoutSession>  // AND-227
    suspend fun confirmSession(sessionId: String): ApiResult<PaymentResult>
    suspend fun pollSession(sessionId: String): ApiResult<PaymentResult>
    suspend fun verifyMicrodeposits(sessionId: String, amounts: List<Int>): ApiResult<PaymentResult>  // AND-230
}
```

Underlying endpoints (for reference; mapping owned upstream): `GET /ui/billing/context`, `POST /ui/billing/checkout_session`, `POST /ui/billing/checkout_session/{id}/confirm`, `GET /ui/billing/checkout_session/{id}`, `POST /ui/billing/us-bank/verify-microdeposits`. All ride the cookie session + `X-CSRF-Token` (`ui_csrf` echo); on 401 the network layer performs one `POST /ui/session/refresh` then retries — this ViewModel does not handle refresh.

Representative `CheckoutSession` next-action shape the ViewModel maps to `NextAction`:

```json
{ "session_id": "cs_123", "status": "requires_action",
  "next_action": { "type": "redirect", "url": "https://psp.example/r/abc",
                   "return_token": "rt_789" } }
```

`type` ∈ `confirm_inline | requires_action | redirect | microdeposits`. A FastAPI error during any call surfaces as `ApiResult.Failure(ApiError(...))`, e.g.:

```json
{ "detail": { "code": "card_declined", "decline_code": "insufficient_funds",
              "message": "Your card has insufficient funds." } }
```

## 6. Data & State Management

- **Single source of truth**: `PaymentState` (`StateFlow`, `WhileSubscribed(5_000)`), seeded from `SavedStateHandle` keys `pmt_state_kind`, `pmt_session_id`, `pmt_return_token`.
- `CheckoutUiState` is a separate `StateFlow` holding screen chrome: `data class CheckoutUiState(val loading: Boolean, val context: CheckoutContext?, val error: BillingError?, val payment: PaymentState)`. It combines the repo context flow with `PaymentViewModel.state`.
- **Effects** (`PaymentEffect`) flow over a `MutableSharedFlow(extraBufferCapacity = 1, replay = 0)` so they fire exactly once.
- **Process death**: on restore, a non-terminal persisted state triggers a single `pollSession(sessionId)` to reconcile with the backend before re-rendering, preventing a stuck spinner. Redirect tokens are persisted so AND-231's `onProviderReturn` can match after process death.
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
