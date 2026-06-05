---
id: AND-230
title: US bank + microdeposits
milestone: M5
epic: E31
priority: P2
size: M
status: draft
depends_on: [AND-223]
blocks: []
---

# AND-230 — US bank + microdeposits

## 1. Overview & Goal

Deliver the native Android flow for paying with a **US bank account (ACH)** verified
by **microdeposits**. The web reference exposes a single confirmation endpoint,
`/ui/billing/us-bank/verify-microdeposits`, that takes the two small deposit
amounts (or a Stripe-issued descriptor code) the customer received in their bank
statement and verifies the previously-created bank payment method so it becomes
chargeable.

This ticket covers the **second, asynchronous half** of the US-bank lifecycle: a
user has already initiated a bank-account add (which puts the payment method into a
`requires_microdeposit_verification` / `pending` state and triggers the backend to
send 1–2 microdeposits), and now — typically 1–2 business days later — returns to
enter the amounts and complete verification. On success the bank account becomes a
usable, optionally-default payment method.

The deliverable is, within `feature-billing`:

1. A `VerifyMicrodepositsScreen` (Compose, Material 3) reachable from a pending
   US-bank entry in the payment-methods list (AND-224) and from a verification
   deep link.
2. A `VerifyMicrodepositsViewModel : ViewModel` exposing
   `StateFlow<VerifyMicrodepositsUiState>` and a typed result event.
3. A `core-data` `UsBankRepository` call plus the `BillingApi` method, DTOs, and
   domain models for the verify endpoint (built on the AND-223 contract).
4. Error mapping for the bank-specific failure cases (wrong amounts, too many
   attempts, already verified, expired).

Acceptance bar (from backlog): **microdeposit verification works (test)** — against
the dev backend, entering the correct amounts for a pending test bank account
transitions it to `verified`/usable and the UI reflects success; entering wrong
amounts surfaces a typed, retryable error with a remaining-attempts count.

Out of scope: initiating the bank-account add / collecting routing+account number
(owned by the payment-methods management ticket AND-224 and the Stripe
`us_bank_account` collection in AND-225/AND-226), charging the verified account
(AND-227 checkout), and the generic redirect/return handler (AND-231).

## 2. Context & References

- **Stack:** Kotlin 2.0.21, Jetpack Compose + Material 3, single-Activity
  Navigation-Compose, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 /
  Moshi 1.15, Room 2.6, DataStore. minSdk 24, compileSdk/targetSdk 35, JDK 17,
  Gradle 8.9, AGP 8.7.3.
- **Module layering:** `app -> feature-billing -> core-*`. The screen + ViewModel
  live in `feature-billing` (`com.testlogon.android.feature.billing.usbank`); the
  `UsBankRepository`, DTOs, and `BillingApi` method live in
  `core-data` / `core-network` (`com.testlogon.android.core.network.billing`);
  domain models in `core-model` (`com.testlogon.android.core.model.billing`).
- **Namespace / applicationId base:** `com.testlogon.android` — used for all
  packages and for the verification deep-link host (see §4.5).
- **Auth:** cookie-based session; `ui_csrf` echoed as `X-CSRF-Token` on the
  mutating verify POST; persistent cookie jar; single `POST /ui/session/refresh`
  retry on 401 handled by the inherited OkHttp authenticator. This ticket adds no
  auth logic.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable — ~20s timeouts; the verify POST is **not**
  auto-retried; offline/stale UI states). OpenAPI at `/openapi.json`. Error
  `detail` is `string | [{msg}] | {code,...}`.
- **Authoritative endpoint:** `POST /ui/billing/us-bank/verify-microdeposits`
  (scope per backlog). Verify exact `operationId`, request schema, and response
  schema against `/openapi.json` and `frontend/src/api/endpoints/billing.ts`
  during implementation; §5 shapes are provisional until reconciled.
- **Upstream dependency — AND-223 (Billing API + DTOs):** provides the
  authenticated `Retrofit` singleton, `BillingApi` interface, `ApiResult<T>`,
  the shared FastAPI error mapper, Moshi codegen conventions, the `Money` value
  type, and the MockWebServer test harness. This ticket extends those, it does not
  re-create them.
- **Sibling — AND-224 (payment methods management):** owns the list screen that
  shows a pending US-bank entry and routes into this flow, and the refresh of the
  list after verification succeeds.

## 3. Functional Requirements

FR-1. From the payment-methods list (AND-224), a US-bank method in a pending /
`requires_verification` state shows a "Verify" affordance that navigates to
`VerifyMicrodepositsScreen`, passing the payment-method id.

FR-2. The screen supports the two backend-supported verification modes, branched
on what the pending method advertises (a `verificationMethod` field):
  - **amounts** — two numeric amount fields (USD cents, 0–99 each), e.g. `32` and
    `45` for $0.32 and $0.45.
  - **descriptor_code** — a single 6-character code field (Stripe `SM####`-style
    statement descriptor). If the backend exposes only one mode, render only that.

FR-3. The Verify button is enabled only when input is structurally valid (two
amounts in `0..99`, or a non-blank descriptor code of expected length). Submitting
calls the endpoint with the payment-method id and the entered values.

FR-4. On `200`/success the screen shows a success state ("Bank account verified"),
emits a one-shot result event so the caller (AND-224 list / deep-link entry) can
refresh, and offers navigation back. If the response indicates the method became
the default or is now chargeable, surface that.

FR-5. On a wrong-amounts failure the screen stays on the form, shows an inline
error, and — when the backend returns it — shows the **remaining attempts** count.
When attempts are exhausted (terminal), the form is disabled and the user is told
to re-add the bank account.

FR-6. Handle the non-happy lifecycle states: already-verified (treat as success /
idempotent), verification expired (terminal, prompt re-add), and microdeposits not
yet arrived (informational — "deposits can take 1–2 business days").

FR-7. A verification deep link (`com.testlogon.android://billing/us-bank/verify?pm={id}`)
opens the screen directly for the given payment method, so a "verify your bank
account" email/notification can route users in. Deep-link routing is delegated to
the navigation graph; resolution against the redirect handler (AND-231) is reused
only for parsing if already present, otherwise a local deep-link route is declared.

FR-8. The screen is fully usable offline-aware: if the device is offline or the
host times out, show a retryable error rather than a spinner that never resolves.

## 4. Technical Design

### 4.1 Domain models (`core-model`)

```kotlin
package com.testlogon.android.core.model.billing

enum class MicrodepositVerificationMethod { AMOUNTS, DESCRIPTOR_CODE, UNKNOWN }

enum class UsBankVerificationState {
    REQUIRES_VERIFICATION,   // deposits sent, awaiting amounts/code
    PENDING_DEPOSITS,        // deposits not yet posted to the bank
    VERIFIED,                // chargeable
    VERIFICATION_FAILED,     // attempts exhausted / wrong too many times
    EXPIRED,                 // window elapsed; must re-add
    UNKNOWN,
}

/** Input the user supplies, in exactly one of the two shapes. */
sealed interface MicrodepositInput {
    data class Amounts(val firstCents: Int, val secondCents: Int) : MicrodepositInput
    data class DescriptorCode(val code: String) : MicrodepositInput
}

data class UsBankVerificationResult(
    val paymentMethodId: String,
    val state: UsBankVerificationState,
    val isDefault: Boolean,
    val attemptsRemaining: Int?,   // null when backend does not report
)
```

### 4.2 DTOs + `BillingApi` extension (`core-network`)

Extends the AND-223 `BillingApi` (same authenticated Retrofit, same Moshi codegen).

```kotlin
package com.testlogon.android.core.network.billing

@JsonClass(generateAdapter = true)
data class VerifyMicrodepositsRequestDto(
    @Json(name = "payment_method_id") val paymentMethodId: String,
    // Exactly one of the following groups is non-null, matching verification_method:
    @Json(name = "amounts") val amounts: List<Int>? = null,        // [32, 45] = $0.32,$0.45 (cents)
    @Json(name = "descriptor_code") val descriptorCode: String? = null, // "SM12AB"
)

@JsonClass(generateAdapter = true)
data class VerifyMicrodepositsResponseDto(
    @Json(name = "payment_method_id") val paymentMethodId: String,
    @Json(name = "state") val state: String,                  // verified|requires_verification|...
    @Json(name = "is_default") val isDefault: Boolean = false,
    @Json(name = "attempts_remaining") val attemptsRemaining: Int? = null,
)

// added to the existing BillingApi interface:
@POST("ui/billing/us-bank/verify-microdeposits")
suspend fun verifyMicrodeposits(
    @Body body: VerifyMicrodepositsRequestDto,
): VerifyMicrodepositsResponseDto
```

Mapper (total, never throws; unknown `state` → `UNKNOWN`):

```kotlin
internal fun VerifyMicrodepositsResponseDto.toDomain() = UsBankVerificationResult(
    paymentMethodId = paymentMethodId,
    state = state.toUsBankVerificationState(),
    isDefault = isDefault,
    attemptsRemaining = attemptsRemaining,
)
```

### 4.3 Repository (`core-data`)

```kotlin
package com.testlogon.android.core.data.billing

class UsBankRepository @Inject constructor(
    private val billingApi: BillingApi,
    private val errorMapper: ApiErrorMapper,   // shared, from AND-223/AND-027
) {
    suspend fun verifyMicrodeposits(
        paymentMethodId: String,
        input: MicrodepositInput,
    ): ApiResult<UsBankVerificationResult> = runCatchingApi(errorMapper) {
        billingApi.verifyMicrodeposits(input.toRequestDto(paymentMethodId)).toDomain()
    }
}

private fun MicrodepositInput.toRequestDto(pmId: String) = when (this) {
    is MicrodepositInput.Amounts ->
        VerifyMicrodepositsRequestDto(pmId, amounts = listOf(firstCents, secondCents))
    is MicrodepositInput.DescriptorCode ->
        VerifyMicrodepositsRequestDto(pmId, descriptorCode = code)
}
```

`runCatchingApi` is the shared helper that turns thrown exceptions / non-2xx into
`ApiResult.Error(ApiError)`.

### 4.4 ViewModel + UI state (`feature-billing`)

```kotlin
package com.testlogon.android.feature.billing.usbank

data class VerifyMicrodepositsUiState(
    val paymentMethodId: String,
    val method: MicrodepositVerificationMethod,
    val firstCents: String = "",
    val secondCents: String = "",
    val descriptorCode: String = "",
    val isSubmitting: Boolean = false,
    val attemptsRemaining: Int? = null,
    val error: UiError? = null,           // mapped, user-facing
    val isFormDisabled: Boolean = false,  // true when terminal failure/expired
    val info: VerifyInfo? = null,         // e.g. PENDING_DEPOSITS notice
) {
    val canSubmit: Boolean get() = !isSubmitting && !isFormDisabled && inputValid()
}

sealed interface VerifyEvent {
    data class Verified(val paymentMethodId: String, val isDefault: Boolean) : VerifyEvent
}

@HiltViewModel
class VerifyMicrodepositsViewModel @Inject constructor(
    private val repo: UsBankRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {
    private val pmId: String = checkNotNull(savedStateHandle["pm"])
    val uiState: StateFlow<VerifyMicrodepositsUiState>
    private val _events = Channel<VerifyEvent>(Channel.BUFFERED)
    val events = _events.receiveAsFlow()

    fun onFirstCentsChange(v: String) { /* digit-only, max 2 */ }
    fun onSecondCentsChange(v: String) { /* digit-only, max 2 */ }
    fun onDescriptorCodeChange(v: String) { /* alphanumeric, max len */ }
    fun submit() { /* build MicrodepositInput, call repo, reduce result */ }
    fun dismissError() { }
}
```

Result reduction maps `UsBankVerificationResult.state`:
`VERIFIED` → emit `VerifyEvent.Verified`, show success; `REQUIRES_VERIFICATION`
after a submit with `attemptsRemaining` set → inline wrong-amounts error;
`VERIFICATION_FAILED`/`EXPIRED` → terminal disabled form; `PENDING_DEPOSITS` →
informational notice.

### 4.5 Navigation + Compose

`VerifyMicrodepositsScreen(state, onFirst, onSecond, onCode, onSubmit, onDone)` is a
stateless composable driven by `uiState`. Two route entries in the billing nav
graph:

- In-app: `route = "billing/us-bank/verify/{pm}"`, arg `pm: String`.
- Deep link: `deepLink = "com.testlogon.android://billing/us-bank/verify?pm={pm}"`.

The amounts mode renders two `OutlinedTextField`s with a leading `$0.` prefix and a
`KeyboardType.NumberPassword` (digits only); the descriptor mode renders a single
uppercase code field. A primary `Button("Verify")` is gated on `state.canSubmit`.

## 5. API Contract

Path relative to dev base `http://18.222.237.167:8000`. Cookie auth; the POST
carries the `X-CSRF-Token` header injected by the shared interceptor.

| Verb | Path | Body | Response |
|------|------|------|----------|
| POST | `/ui/billing/us-bank/verify-microdeposits` | `VerifyMicrodepositsRequestDto` | `VerifyMicrodepositsResponseDto` |

Request (amounts mode):

```json
{ "payment_method_id": "pm_usbank_7a3", "amounts": [32, 45] }
```

Request (descriptor-code mode):

```json
{ "payment_method_id": "pm_usbank_7a3", "descriptor_code": "SM12AB" }
```

Success `200`:

```json
{
  "payment_method_id": "pm_usbank_7a3",
  "state": "verified",
  "is_default": true,
  "attempts_remaining": null
}
```

Wrong-amounts failure — backend may return `400`/`402`/`422` with the FastAPI
`detail` envelope (reconcile actual status against `/openapi.json`):

```json
{ "detail": { "code": "microdeposits_amounts_incorrect", "message": "Amounts do not match", "attempts_remaining": 2 } }
```

Other relevant statuses (handled, tested): `409` already verified (treat as
idempotent success — re-fetch state), `410`/`code:"verification_expired"`
(terminal, prompt re-add), `429`/`code:"too_many_attempts"` (terminal),
`404` unknown payment method, `401` (handled by the inherited refresh-and-retry
authenticator). The string and list `detail` shapes are also accepted by the
shared mapper. **All field names, the wrong-amounts HTTP status, and whether
`attempts_remaining` arrives inside `detail` vs. the top-level body are provisional
and MUST be confirmed against `/openapi.json` and `billing.ts`** (OQ-1).

## 6. Data & State Management

- **Transient by design.** No new Room entity or DataStore key is introduced. The
  ViewModel holds `VerifyMicrodepositsUiState` in a `StateFlow`; entered amounts /
  code live only in `SavedStateHandle`-backed UI state and are never persisted.
- **Source of truth** for the payment method's verification state is the server;
  this screen does not cache it. On success it emits `VerifyEvent.Verified` and the
  payment-methods list (AND-224) re-fetches `/ui/billing/payment-methods` so the
  pending entry refreshes to verified/default. If a `core-data` payment-method
  Room mirror exists from AND-224, the repository invalidates/updates that row on
  success rather than this ticket adding its own cache.
- **Process death:** `pm` id and the in-progress text fields are restored from
  `SavedStateHandle`; no submit is auto-replayed.

## 7. Error Handling & Resilience

- The verify POST is **mutating and is not auto-retried** by the OkHttp retry
  policy (which is restricted to idempotent GETs). A failed/timed-out submit
  returns `ApiResult.Error` and the user retries explicitly via the button.
- **~20s timeout** per attempt given the unreliable host; on `IOException` /
  timeout show a generic retryable "Couldn't reach the server" error, not a stuck
  spinner (`isSubmitting` always resets in a `finally`).
- **Typed mapping** via the shared `ApiErrorMapper`: the bank-specific `code`
  values are mapped to a `UsBankError` enum
  (`AMOUNTS_INCORRECT`, `TOO_MANY_ATTEMPTS`, `EXPIRED`, `ALREADY_VERIFIED`,
  `NOT_FOUND`, `GENERIC`) so the ViewModel can choose retryable vs. terminal UI and
  read `attempts_remaining`.
- **Idempotency:** `409 already_verified` is reduced to the success path (the goal
  state is reached), preventing a confusing error if the user double-submits or
  returns after a prior success.
- **Mapper resilience:** unknown `state` → `UNKNOWN` (rendered as a safe generic
  error prompting refresh), never a crash.

## 8. Security & Privacy

- **No PAN / no full bank number.** This screen never sees or stores the routing or
  account number — only the user-known microdeposit amounts (cents) or the
  statement descriptor code, plus the opaque `payment_method_id`. Those amounts and
  the descriptor code are low-sensitivity but still MUST NOT be logged (see §10).
- **CSRF:** the POST relies on the `ui_csrf` cookie echoed as `X-CSRF-Token` by the
  shared interceptor; no token handling is added here.
- **Transport:** dev backend is plaintext HTTP; production must be HTTPS via the
  app's network-security-config (separate infra ticket). This ticket adds no
  cleartext exemption.
- **Deep link safety:** the `pm` parameter is treated as an opaque server id;
  the screen makes no trust decision on it beyond passing it to the authenticated
  endpoint, which authorizes against the session. A malformed/foreign `pm` simply
  yields a `404`/authorization error.

## 9. Accessibility & i18n

- All inputs and the Verify button carry `contentDescription` / `semantics`; the
  two amount fields announce as "first deposit amount, dollars and cents" and
  "second deposit amount". Inline errors use `liveRegion` so TalkBack announces
  wrong-amounts feedback and remaining attempts.
- Touch targets ≥ 48dp; the form is keyboard-navigable with an IME "Done" action
  on the last field that triggers `submit()` when `canSubmit`.
- **i18n:** all user-facing copy ("Verify your bank account", "Amounts don't
  match", "{n} attempts remaining", "Deposits can take 1–2 business days",
  "Bank account verified") lives in `strings.xml` with plurals for the attempts
  count. The descriptor/amount values themselves are USD-cents and are displayed
  with a `$0.` prefix; no locale currency formatting is needed for the 2-digit
  cent inputs, but the success summary money (if shown) uses `Money` +
  `NumberFormat.getCurrencyInstance(locale)` per the AND-223 convention.

## 10. Telemetry & Logging

- Emit `feature-billing` analytics events (via the shared analytics interface, not
  the network layer): `usbank_verify_opened`, `usbank_verify_submitted`,
  `usbank_verify_succeeded`, `usbank_verify_failed{code}` — with `payment_method_id`
  but **never** the entered amounts or descriptor code.
- The shared `HttpLoggingInterceptor` runs at `BASIC` (not `BODY`) for this path so
  the request body (amounts/code) is not logged; if `BODY` is ever needed in debug,
  a redactor strips `amounts`/`descriptor_code`.
- Mapper warnings (unknown `state`) log at `WARN` with the field name only, no
  values.

## 11. Testing Strategy

Acceptance is "microdeposit verification works (test)" — verified at three layers.

1. **DTO/mapper unit tests** (`core-network`, JVM): round-trip
   `VerifyMicrodepositsRequestDto` for both modes; deserialize success and each
   failure fixture; assert unknown `state` → `UNKNOWN`; assert
   `attempts_remaining` parses from both top-level and `detail` shapes once OQ-1 is
   resolved.
2. **Repository / `BillingApi` MockWebServer tests:** enqueue success and each
   error fixture; assert request path `/ui/billing/us-bank/verify-microdeposits`,
   verb POST, body JSON (`amounts` vs `descriptor_code`), and presence of
   `X-CSRF-Token`; assert each maps to the expected `ApiResult` / `UsBankError`.
3. **ViewModel tests** (`core-testing` rules, Turbine on `uiState`/`events`):
   - valid input enables `canSubmit`; invalid (amount > 99, blank code) disables it;
   - success → `VerifyEvent.Verified` emitted, success state set;
   - wrong amounts → inline error + `attemptsRemaining` decremented, form still
     enabled;
   - attempts exhausted / expired → `isFormDisabled = true`, terminal copy;
   - `409 already_verified` → success path;
   - timeout/offline → retryable error, `isSubmitting` reset.
4. **Compose UI test** (`createAndroidComposeRule`): enter `32`/`45`, tap Verify
   against a MockWebServer success → success node shown; wrong-amounts fixture →
   error + attempts text shown; verify deep-link route resolves with `pm` arg.
5. **Live/manual verification (documented, non-CI):** against
   `http://18.222.237.167:8000` with a Stripe test US bank account
   (`account_number 000123456789`, `routing 110000000`) put into pending state,
   submit the test microdeposit amounts (Stripe test mode posts deterministic
   amounts, commonly `32`/`45` — confirm from the dev backend) and confirm the
   method becomes verified; capture sanitized fixtures.

Fixtures under `core-network/src/test/resources/billing/usbank/*.json`.

## 12. Dependencies & Sequencing

- **Depends on AND-223 (Billing API + DTOs):** the authenticated Retrofit, the
  `BillingApi` interface this ticket extends, `ApiResult`, the shared
  `ApiErrorMapper`, `Money`, Moshi conventions, and the MockWebServer harness. This
  is the only hard dependency named in the backlog.
- **Soft sibling — AND-224 (payment methods management):** provides the entry point
  (the "Verify" affordance on a pending US-bank row) and the list refresh after
  success. If AND-224 lands first, wire its row action to this route; if this lands
  first, expose the route + deep link and AND-224 links to it. The flow is
  independently testable via its deep link, so it is **not** blocked by AND-224.
- **Optional reuse — AND-231 (redirect/return handler):** if the deep-link parsing
  utility exists, reuse it to read the `pm` query param; otherwise declare a local
  `navDeepLink`. Not a hard dependency.
- **Blocks:** nothing in the current backlog.

## 13. Risks & Open Questions

- **OQ-1 (response shape):** Confirm against `/openapi.json` + `billing.ts`: the
  exact request schema (is it `amounts: [int,int]` in cents, or `amounts: [str]`,
  or separate `first_amount`/`second_amount`?), whether `descriptor_code` mode
  exists, the HTTP status for wrong amounts, and whether `attempts_remaining`
  arrives top-level or inside `detail`. The §5 shapes are provisional.
- **OQ-2 (verification method discovery):** How does the pending payment method
  advertise which mode (`amounts` vs `descriptor_code`) to render? Expected via a
  `verification_method` field on the payment-method DTO (AND-224). If absent,
  default to amounts mode and file a backend request.
- **OQ-3 (initiation ownership):** Confirm that adding the bank account +
  triggering microdeposits is fully owned by AND-224/AND-225 and that this endpoint
  is verify-only. If initiation also lives behind a `/ui/billing/us-bank/*` route,
  scope it out explicitly.
- **Risk — dev-host flakiness:** the unreliable host may make the manual test
  intermittent; mitigated by the deterministic MockWebServer suite carrying the
  CI acceptance weight, with the live run as confirmation only.
- **Risk — Stripe test deposit amounts:** the exact test microdeposit values
  depend on the backend/Stripe configuration; confirm before writing the manual
  test script.

## 14. Acceptance Criteria

1. `BillingApi.verifyMicrodeposits` exists, POSTs to
   `/ui/billing/us-bank/verify-microdeposits` with the correct body for both input
   modes, and carries `X-CSRF-Token` — proven by MockWebServer tests.
2. `VerifyMicrodepositsRequestDto` / `VerifyMicrodepositsResponseDto` and the
   `UsBankVerificationResult` domain model + total `toDomain()` mapper exist;
   unknown `state` → `UNKNOWN`; fixtures deserialize with all fields asserted.
3. `UsBankRepository.verifyMicrodeposits` returns
   `ApiResult<UsBankVerificationResult>` and maps bank-specific error codes to the
   `UsBankError` enum, including `attempts_remaining`.
4. `VerifyMicrodepositsViewModel` exposes `StateFlow<VerifyMicrodepositsUiState>`:
   correct amounts → success state + `VerifyEvent.Verified`; wrong amounts → inline
   error with remaining attempts and a still-usable form; exhausted/expired →
   disabled form with terminal copy; `409 already_verified` → success.
5. `VerifyMicrodepositsScreen` renders the correct mode, gates Verify on valid
   input, and shows success/error/info states; reachable in-app and via the
   `com.testlogon.android://billing/us-bank/verify?pm={id}` deep link.
6. Timeout/offline yields a retryable error and never a stuck spinner.
7. No amounts or descriptor code are logged or sent to analytics; events carry only
   ids/codes.
8. The full test suite (DTO/mapper, MockWebServer/repo, ViewModel, Compose UI)
   passes in CI; the documented live run verifies a real pending test bank account
   reaches `verified`.

## 15. Definition of Done

- All §14 acceptance criteria met and CI green.
- Code lives under the exact `com.testlogon.android.*` packages above; no Retrofit/
  Moshi types leak into `core-model`.
- OQ-1/OQ-2/OQ-3 resolved against `/openapi.json` + `billing.ts`, with final field
  names, the wrong-amounts status, and `attempts_remaining` location reflected in
  the DTOs and reduction logic; sanitized fixtures committed under
  `core-network/src/test/resources/billing/usbank/`.
- All user-facing copy is in `strings.xml` (with attempts-count plurals); TalkBack
  announces errors via `liveRegion`; targets ≥ 48dp.
- `HttpLoggingInterceptor` confirmed not to log the verify request body; analytics
  confirmed free of amounts/code.
- Ktlint/Detekt pass; KSP generates Moshi adapters with no warnings; KDoc on the
  new `BillingApi` method, repository, and ViewModel describes the flow for AND-224
  to wire without re-reading the backend.
- Reviewed and merged to branch `android-port`.
