---
id: AND-230
title: US bank + microdeposits
milestone: M5
epic: E31
priority: P2
size: M
depends_on: [AND-223]
blocks: []
status: reviewed
reviewed_on: 2026-06-06
---

# AND-230 — US bank + microdeposits

## 1. Overview & Goal

Deliver the native Android flow for paying with a **US bank account (ACH)** verified
by **microdeposits**. The web reference exposes a single confirmation endpoint,
`POST /ui/billing/us-bank/verify-microdeposits`, that takes a Stripe
`setup_intent_id` plus the two small deposit amounts (in cents) the customer
received in their bank statement and verifies the previously-created bank setup so
the resulting payment method becomes chargeable.

> **[CORRECTED — verified against sources]** The endpoint identifies the pending
> bank by the **Stripe `setup_intent_id`**, *not* by a `payment_method_id`
> (confirmed: OpenAPI `VerifyMicrodepositsReq.setup_intent_id` is the only required
> field; `src/api/endpoints/billing.ts: verifyMicrodeposits` posts
> `{ setup_intent_id, amounts: [number, number] }`). The request schema also accepts
> an optional `descriptor_code`, but the **web client never sends it** — the only
> verified UI mode is the two-amounts mode. The 200 response is an open string map
> (`object` with `additionalProperties: string`, i.e. `{ "status": "..." }`), *not*
> a structured `{ state, is_default, attempts_remaining }` object. The Android
> identifier model, response model, and descriptor-code/attempts-remaining behavior
> in the sections below are amended accordingly; see §16 for the full audit.

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
- **Auth:** cookie-based session; `ui_csrf` echoed as `X-CSRF-Token`; persistent
  cookie jar; single `POST /ui/session/refresh` retry on 401 handled by the
  inherited OkHttp authenticator. This ticket adds no auth logic. *(Verified
  against `src/api/client.ts`: the web client sets `X-CSRF-Token` from the
  `ui_csrf` cookie on **every** request — not only mutating ones — and also adds an
  `Authorization: Bearer <accessToken>` header from its auth store. The Android
  app's cookie-session-only model is a deliberate port choice inherited from
  AND-223; the verify call MUST still carry `X-CSRF-Token`.)*
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable — ~20s timeouts; the verify POST is **not**
  auto-retried; offline/stale UI states). OpenAPI at `/openapi.json`. Error
  `detail` is `string | [{msg}] | {code,...}`.
- **Authoritative endpoint (verified):** `POST /ui/billing/us-bank/verify-microdeposits`,
  `operationId = verify_microdeposits_ui_billing_us_bank_verify_microdeposits_post`,
  `req = VerifyMicrodepositsReq`, `resp = 200: object{additionalProperties:string};
  422: HTTPValidationError` (OpenAPI index line 1200 / pretty.json
  `/ui/billing/us-bank/verify-microdeposits`). An identical `/api/...` twin exists
  (index line 49); the **`/ui/...`** path is the one the web client uses
  (`src/api/endpoints/billing.ts`). Request schema: `setup_intent_id` (string,
  **required**), `amounts` (`int[] | null`), `descriptor_code` (`string | null`).
  The only documented error is `422 HTTPValidationError`; no bank-specific error
  schema exists. §5 has been reconciled to these shapes; remaining unknowns are
  flagged as assumptions in §16.
- **Upstream dependency — AND-223 (Billing API + DTOs):** provides the
  authenticated `Retrofit` singleton, `BillingApi` interface, `ApiResult<T>`,
  the shared FastAPI error mapper, Moshi codegen conventions, the `Money` value
  type, and the MockWebServer test harness. This ticket extends those, it does not
  re-create them.
- **Sibling — AND-224 (payment methods management):** owns the list screen that
  shows a pending US-bank entry and routes into this flow, and the refresh of the
  list after verification succeeds.

## 3. Functional Requirements

FR-1. A pending US-bank verification is keyed by the Stripe **`setup_intent_id`**
returned from the bank setup-intent step (AND-224/AND-225), not by a server
`payment_method_id`. The entry point (a "Verify bank account" affordance on the
payment-methods screen and/or a deep link) navigates to `VerifyMicrodepositsScreen`,
passing the `setup_intent_id`.

> **[CORRECTED]** The web reference does NOT surface the pending bank as a row in
> the payment-methods list keyed by `payment_method_id`. The `PaymentMethod` DTO
> (`src/api/types.ts: PaymentMethod`) has no verification/pending fields. Instead
> the web stores a `PendingBank { setup_intent_id, account_last4, routing_last4 }`
> record in `localStorage` (`src/pages/billing/PaymentMethods.tsx`) and re-opens the
> verify step from it. The Android port should mirror this: persist the pending
> `setup_intent_id` (see §6) and route the verify screen by `setup_intent_id`.

FR-2. **Only the amounts mode is verified as in-use.** The screen renders two
numeric amount fields (USD **cents, 1–99 each**, i.e. $0.01–$0.99), e.g. `32` and
`45` for $0.32 and $0.45.

> **[CORRECTED]** There is no `verificationMethod`/`verification_method` field on any
> DTO to branch on (not in `PaymentMethod`, not in any OpenAPI schema). The backend
> `VerifyMicrodepositsReq` accepts an optional `descriptor_code`, but the web client
> **never sends it** (`src/api/endpoints/billing.ts` posts only
> `{ setup_intent_id, amounts }`). Treat amounts mode as the sole supported mode;
> descriptor-code support is an **unverified backend capability** — do not build the
> UI for it without a confirmed contract (see §16 Open assumptions). Also note the
> valid cent range is **1–99** (web `parseDollarsToCents` rejects 0 and >0.99), not
> 0–99.

FR-3. The Verify button is enabled only when input is structurally valid (two
amounts in `1..99`). Submitting calls the endpoint with the `setup_intent_id` and
`amounts: [first, second]`.

FR-4. On `200`/success the screen shows a success state ("Bank account verified"),
clears the persisted pending record, emits a one-shot result event so the caller
(payment-methods screen / deep-link entry) can refresh the payment-methods list,
and offers navigation back.

> **[CORRECTED]** The success response is `{ "status": "..." }` (a string map) and
> does **not** report `is_default` or chargeability (OpenAPI 200 =
> `object{additionalProperties:string}`; web treats any 200 as success and just
> toasts "Bank account verified and added"). Do not promise the user a
> default/chargeable signal from this response; the payment-methods refresh after
> success is the source of truth for default status.

FR-5. On a failure the screen stays on the form and shows an inline, retryable
error mapped from the response `detail` (string / `[{msg}]` / `{code,message}`).

> **[CORRECTED — unverified attempts/lifecycle behavior]** The backend exposes
> **no** documented "wrong amounts" status, no `attempts_remaining`, and no terminal
> "attempts exhausted" code — the only declared error response is
> `422 HTTPValidationError` (`detail: ValidationError[]`). The web client surfaces
> failures generically (`toast.error(err.message)`) with no remaining-attempts
> count. Therefore: render a generic retryable error for non-2xx; treat any
> "remaining attempts", `409`/`410`/`429` lifecycle handling, and form-disable-on-
> exhaustion as **speculative** until the backend contract is confirmed (OQ-1, §16).

FR-6. Show an informational hint that "deposits can take 1–2 business days." Any
richer lifecycle handling (already-verified-idempotent, verification-expired) is
**best-effort only** and gated on the response/error actually carrying such a
signal.

> **[CORRECTED — unverified]** None of `already_verified`, `verification_expired`,
> or a "deposits not yet arrived" state appears in OpenAPI or the frontend. The
> 1–2-business-days copy is a safe static UI hint (the web add-bank dialog uses
> similar wording). Do not build branch logic keyed on lifecycle codes that the
> contract does not define.

FR-7. A verification deep link
(`com.testlogon.android://billing/us-bank/verify?sid={setup_intent_id}`) opens the
screen directly for the given pending setup intent, so a "verify your bank account"
email/notification can route users in. Deep-link routing is delegated to the
navigation graph; resolution against the redirect handler (AND-231) is reused only
for parsing if already present, otherwise a local deep-link route is declared.

> **[CORRECTED]** The deep-link parameter is the `setup_intent_id` (renamed from the
> earlier `pm={id}`), consistent with FR-1 and the verify request body. There is no
> verified server `payment_method_id` to deep-link by at verification time.

FR-8. The screen is fully usable offline-aware: if the device is offline or the
host times out, show a retryable error rather than a spinner that never resolves.

## 4. Technical Design

> **[CORRECTION BANNER — applies to all of §4]** The code sketches below were
> written against an assumed `payment_method_id` + rich-response contract. Per the
> verified sources, apply these overrides everywhere in §4:
> 1. The request/identifier key is **`setup_intent_id`** (string, required), not
>    `payment_method_id`. Rename `paymentMethodId`/`pmId`/`pm` → `setupIntentId`/`sid`
>    in the DTO, repository, ViewModel, and nav args.
> 2. `VerifyMicrodepositsRequestDto` has fields `setup_intent_id` (required),
>    `amounts: List<Int>?`, `descriptor_code: String?` (optional, **not used by the
>    verified UI**). For amounts mode send `{ setup_intent_id, amounts:[a,b] }`.
> 3. The 200 body is a `Map<String, String>` (e.g. `{ "status": "verified" }`).
>    Model the response as `Map<String,String>` (or a tiny
>    `VerifyMicrodepositsResponseDto(status: String?)`) — there is **no** `state`,
>    `is_default`, or `attempts_remaining` field. `isDefault` must come from a
>    subsequent payment-methods fetch, not this response. `UsBankVerificationResult`
>    should carry only what is real: `setupIntentId` and a derived success flag;
>    keep `attemptsRemaining`/`state` only as nullable "unverified extension" fields
>    that default to null/UNKNOWN.
> 4. The success/error reduction is: HTTP 200 → success; any non-2xx → generic
>    retryable error from mapped `detail`. Lifecycle/attempts branching is
>    speculative (see §16).

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
    val setupIntentId: String,     // CORRECTED: keyed by setup_intent_id, not pm id
    val state: UsBankVerificationState,
    val isDefault: Boolean,        // NOT from verify response; from later pm fetch
    val attemptsRemaining: Int?,   // unverified extension; null in practice
)
```

### 4.2 DTOs + `BillingApi` extension (`core-network`)

Extends the AND-223 `BillingApi` (same authenticated Retrofit, same Moshi codegen).

```kotlin
package com.testlogon.android.core.network.billing

// CORRECTED to match OpenAPI VerifyMicrodepositsReq.
@JsonClass(generateAdapter = true)
data class VerifyMicrodepositsRequestDto(
    @Json(name = "setup_intent_id") val setupIntentId: String,      // REQUIRED
    @Json(name = "amounts") val amounts: List<Int>? = null,         // [32, 45] = $0.32,$0.45 (cents)
    @Json(name = "descriptor_code") val descriptorCode: String? = null, // optional; UNUSED by verified UI
)

// CORRECTED: OpenAPI 200 = object{additionalProperties:string} (web: { status }).
// There is NO state / is_default / attempts_remaining in the response.
@JsonClass(generateAdapter = true)
data class VerifyMicrodepositsResponseDto(
    @Json(name = "status") val status: String? = null,   // e.g. "verified"; treat any 200 as success
)
// (Equivalently the call may be typed `Map<String, String>` and read `["status"]`.)

// added to the existing BillingApi interface:
@POST("ui/billing/us-bank/verify-microdeposits")
suspend fun verifyMicrodeposits(
    @Body body: VerifyMicrodepositsRequestDto,
): VerifyMicrodepositsResponseDto
```

Mapper (total, never throws; unknown/absent `status` → `UNKNOWN`):

```kotlin
// CORRECTED: the response carries only an optional status string. setupIntentId is
// carried through from the request; isDefault/attemptsRemaining are NOT in the
// response (left null/false here, resolved by a later payment-methods fetch).
internal fun VerifyMicrodepositsResponseDto.toDomain(setupIntentId: String) =
    UsBankVerificationResult(
        setupIntentId = setupIntentId,
        state = status.toUsBankVerificationState(),  // "verified" → VERIFIED, else UNKNOWN
        isDefault = false,
        attemptsRemaining = null,
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

- In-app: `route = "billing/us-bank/verify/{sid}"`, arg `sid: String` (the
  `setup_intent_id`). *(CORRECTED from `{pm}`.)*
- Deep link: `deepLink = "com.testlogon.android://billing/us-bank/verify?sid={sid}"`.
  *(CORRECTED from `?pm={pm}`.)*

The amounts mode renders two `OutlinedTextField`s with a leading `$0.` prefix and a
`KeyboardType.NumberPassword` (digits only); the descriptor mode renders a single
uppercase code field. A primary `Button("Verify")` is gated on `state.canSubmit`.

## 5. API Contract

Path relative to dev base `http://18.222.237.167:8000`. Cookie auth; the POST
carries the `X-CSRF-Token` header injected by the shared interceptor.

| Verb | Path | Body | Response |
|------|------|------|----------|
| POST | `/ui/billing/us-bank/verify-microdeposits` | `VerifyMicrodepositsRequestDto` | `VerifyMicrodepositsResponseDto` |

Request (verified amounts mode — `VerifyMicrodepositsReq`):

```json
{ "setup_intent_id": "seti_1ABCdef", "amounts": [32, 45] }
```

Request (descriptor-code mode — schema-permitted but **unused by the web client**,
unverified):

```json
{ "setup_intent_id": "seti_1ABCdef", "descriptor_code": "SM12AB" }
```

Success `200` — `object` with `additionalProperties: string` (verified):

```json
{ "status": "verified" }
```

Failure — the **only documented** error response is `422 HTTPValidationError`
(verified: OpenAPI `responses.422 = HTTPValidationError`):

```json
{ "detail": [ { "loc": ["body", "amounts"], "msg": "field required", "type": "value_error.missing" } ] }
```

> **[CORRECTED — the earlier rich error taxonomy is unverified]** The OpenAPI spec
> declares no `400`/`402`/`409`/`410`/`429` responses for this operation, no
> `code:"microdeposits_amounts_incorrect"` / `verification_expired` /
> `too_many_attempts` / `already_verified`, and no `attempts_remaining` field
> anywhere (grepped across `openapi.pretty.json` and `reference/src/` — zero hits).
> The web client (`src/pages/billing/PaymentMethods.tsx: handleVerify`) treats any
> thrown `ApiError` generically via `toast.error(err.message)`. The shared mapper
> still accepts the `detail` shapes `string | [{msg}] | {code,message}`
> (`src/api/client.ts: normalizeErrorDetail`), so the Android error mapper should
> map a wrong-amounts rejection to a **generic retryable** error from `detail`,
> NOT to fabricated bank-specific codes. `401` is handled by the inherited
> refresh-and-retry authenticator (verified: `src/api/client.ts` refresh path).
> Any attempts-count / lifecycle behavior remains an **open backend question**
> (OQ-1) and must not be assumed implemented.

## 6. Data & State Management

- **Transient by design.** No new Room entity or DataStore key is introduced for
  the entered amounts. The ViewModel holds `VerifyMicrodepositsUiState` in a
  `StateFlow`; entered amounts live only in `SavedStateHandle`-backed UI state and
  are never persisted.

> **[CORRECTED / NOTE]** The web reference DOES persist the *pending* state across
> sessions: a `PendingBank { setup_intent_id, account_last4, routing_last4 }` is
> stored in `localStorage` (`src/pages/billing/PaymentMethods.tsx`) so the user can
> close the dialog and return days later to verify. The Android equivalent (a small
> DataStore/Prefs `pending-bank` record holding the `setup_intent_id`, NOT the
> amounts) is the natural home for this and is owned by the bank-add flow
> (AND-224/AND-225); this verify screen consumes the `setup_intent_id` from that
> record or the deep link. Only the **amounts** are transient and unpersisted.
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
- **Typed mapping** via the shared `ApiErrorMapper`. **[CORRECTED]** Because none of
  the bank-specific codes (`microdeposits_amounts_incorrect`, `too_many_attempts`,
  `verification_expired`, `already_verified`) nor `attempts_remaining` exist in the
  verified contract (only `422 HTTPValidationError`), the `UsBankError` enum should
  start minimal — e.g. `VALIDATION` (422), `NOT_FOUND` (404, if returned),
  `NETWORK`, `GENERIC` — and the mapper falls back to a generic retryable error
  built from `detail`. The richer enum values may be added later **iff** a backend
  contract surfaces them; until then they are dead branches and must not gate UI.
- **Idempotency:** *(unverified)* re-submitting after a prior success may simply
  re-return `200`; the contract defines no `409 already_verified`. Treat a 200 as
  success regardless. Do not implement a `409`→success special case absent a
  confirmed contract.
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

- **OQ-1 (response/request shape) — PARTIALLY RESOLVED.** Verified against
  `openapi.pretty.json` + `src/api/endpoints/billing.ts`: request is
  `{ setup_intent_id (required), amounts: int[] (cents), descriptor_code: string? }`;
  success 200 is `object{additionalProperties:string}` (`{ "status": ... }`).
  **Still open:** the actual HTTP status/`detail` shape returned for *incorrect*
  amounts (only `422 HTTPValidationError` is documented; Stripe-driven mismatches
  likely surface as a different runtime status not captured in OpenAPI), and
  whether any `attempts_remaining` is ever returned (no evidence it is). Treat as a
  generic retryable error until confirmed against the live dev backend.
- **OQ-2 (verification method discovery) — RESOLVED (negative).** There is **no**
  `verification_method` field on the `PaymentMethod` DTO or any schema, and the web
  client only ever uses amounts mode. Render amounts mode only; do not build
  descriptor-code UI without a confirmed backend contract.
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
   `/ui/billing/us-bank/verify-microdeposits` with the verified body
   `{ setup_intent_id, amounts:[a,b] }`, and carries `X-CSRF-Token` — proven by
   MockWebServer tests. *(CORRECTED: `setup_intent_id` body; amounts mode only —
   descriptor-code is not a required mode.)*
2. `VerifyMicrodepositsRequestDto` / `VerifyMicrodepositsResponseDto` and the
   `UsBankVerificationResult` domain model + total `toDomain()` mapper exist; the
   200 string-map response (`{ "status": ... }`) deserializes, a `"verified"`
   status maps to success, and an absent/unknown status → `UNKNOWN` without
   crashing. *(CORRECTED: response is a string map, not a structured object.)*
3. `UsBankRepository.verifyMicrodeposits` returns
   `ApiResult<UsBankVerificationResult>` and maps bank-specific error codes to the
   `UsBankError` enum, including `attempts_remaining`.
4. `VerifyMicrodepositsViewModel` exposes `StateFlow<VerifyMicrodepositsUiState>`:
   correct amounts (HTTP 200) → success state + `VerifyEvent.Verified`; a non-2xx
   rejection → inline retryable error mapped from `detail`, with the form still
   usable. *(CORRECTED: remaining-attempts / exhausted-terminal / `409
   already_verified` branches are unverified and not required by this AC; implement
   them only if a confirmed contract surfaces them.)*
5. `VerifyMicrodepositsScreen` renders the amounts mode, gates Verify on valid
   input (two cents in 1–99), and shows success/error/info states; reachable in-app
   and via the
   `com.testlogon.android://billing/us-bank/verify?sid={setup_intent_id}` deep
   link. *(CORRECTED deep-link param: `sid`.)*
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

## 16. Citations & Assumption Audit

Each key technical claim with its VERDICT and exact SOURCE pointer.

1. **Endpoint path & method:** `POST /ui/billing/us-bank/verify-microdeposits`.
   **Verified.** OpenAPI index line 1200 `POST /ui/billing/us-bank/verify-microdeposits`
   (op `verify_microdeposits_ui_billing_us_bank_verify_microdeposits_post`);
   `src/api/endpoints/billing.ts: verifyMicrodeposits`. (An `/api/...` twin also
   exists: index line 49.)
2. **Request body identifier is `setup_intent_id` (required), NOT
   `payment_method_id`.** **Corrected.** OpenAPI
   `components.schemas.VerifyMicrodepositsReq` (`required: [setup_intent_id]`);
   `src/api/endpoints/billing.ts: verifyMicrodeposits` posts
   `{ setup_intent_id, amounts: [number, number] }`;
   `src/pages/billing/PaymentMethods.tsx` derives `setup_intent_id` from the
   setup-intent `client_secret`.
3. **Request `amounts` is `int[]` (cents).** **Verified.**
   `VerifyMicrodepositsReq.amounts = (array<integer> | null)`; web sends
   `[cents1, cents2]`.
4. **Request `descriptor_code` exists but is unused by the web UI.** **Corrected**
   (spec treated it as a first-class branchable mode). OpenAPI
   `VerifyMicrodepositsReq.descriptor_code = (string | null)`, optional; no
   reference in `src/` posts it (grep `descriptor_code` → only the spec/Android side).
5. **Success 200 response is a string map (`{ "status": ... }`), NOT
   `{ payment_method_id, state, is_default, attempts_remaining }`.** **Corrected.**
   OpenAPI `responses.200.schema = object{ additionalProperties: { type: string } }`;
   `src/api/endpoints/billing.ts` types it `{ status: string }`.
6. **`verification_method` field used to choose amounts vs descriptor mode.**
   **Corrected (does not exist).** `src/api/types.ts: PaymentMethod` has only
   `{ payment_method_id, method_type, label?, brand?, last4?, exp_month?, exp_year?,
   priority, provider?, provider_method_id?, is_default }`; no verification field in
   any OpenAPI schema.
7. **Valid amount range is cents 1–99 ($0.01–$0.99).** **Corrected** (spec said
   0–99). `src/pages/billing/PaymentMethods.tsx: parseDollarsToCents` rejects `<0`,
   `>0.99`, and `0`.
8. **CSRF: `X-CSRF-Token` from the `ui_csrf` cookie on the verify POST.**
   **Verified** (with nuance). `src/api/client.ts` sets `X-CSRF-Token` from the
   `ui_csrf` cookie on **every** request (not only mutating ones) and also adds
   `Authorization: Bearer <accessToken>`; the Android cookie-session port omits the
   bearer header (inherited AND-223 choice) but keeps CSRF.
9. **401 → single `POST /ui/session/refresh` retry.** **Verified.**
   `src/api/client.ts: refreshSession` / the 401 branch (single in-flight
   `refreshPromise`, one retry, then `logout("session_expired")`).
10. **Only documented error response is `422 HTTPValidationError`.** **Verified.**
    OpenAPI `.../verify-microdeposits.post.responses = { 200, 422 }`;
    `HTTPValidationError.detail = ValidationError[]`.
11. **Bank-specific error codes `microdeposits_amounts_incorrect`,
    `too_many_attempts`, `verification_expired`, `already_verified` and an
    `attempts_remaining` field.** **Unverified-assumption (no evidence; likely
    fabricated).** Grep of `openapi.pretty.json` and `reference/src/` for each token
    → zero matches. Web error handling is generic
    (`src/pages/billing/PaymentMethods.tsx: handleVerify` → `toast.error`).
12. **`409 already_verified` → idempotent success; `410`/`429` terminal lifecycle.**
    **Unverified-assumption.** No such statuses declared for this operation in
    OpenAPI.
13. **`detail` envelope shape `string | [{msg}] | {code,...}` is parsed by the
    shared mapper.** **Verified.** `src/api/client.ts: normalizeErrorDetail` handles
    string, `[{msg}]`, and object-with-`code`/`msg`.
14. **Pending bank is persisted client-side for return-later verification.**
    **Verified (web model).** `src/pages/billing/PaymentMethods.tsx`:
    `localStorage` key `billing-pending-bank` holding
    `{ setup_intent_id, account_last4, routing_last4 }`. (Android: persist
    `setup_intent_id`, not amounts.)
15. **Stripe test bank values (`account 000123456789`, `routing 110000000`).**
    **Verified (as web placeholders).** `src/pages/billing/PaymentMethods.tsx`
    input placeholders. The deterministic test *microdeposit amounts* (e.g. 32/45)
    are **Unverified-assumption** — not present in sources; confirm against the dev
    backend/Stripe test mode.
16. **Android framework choices** (Compose/Material 3 screen, `@HiltViewModel`,
    `StateFlow`, `Channel` one-shot events, `SavedStateHandle`, Nav-Compose route +
    `navDeepLink`). **Verified — framework ref:**
    https://developer.android.com/jetpack/compose ,
    https://developer.android.com/training/dependency-injection/hilt-android ,
    https://developer.android.com/kotlin/flow/stateflow-and-sharedflow ,
    https://developer.android.com/guide/navigation/navigation-deep-link . These are
    standard port choices, not backend claims.

### Corrections made

- §1, §2, §5, §14: identifier corrected from `payment_method_id` →
  **`setup_intent_id`** (required field of `VerifyMicrodepositsReq`).
- §1, §4, §5, §14: success response corrected from a structured object to a
  **string map `{ "status": ... }`**; removed reliance on `state`/`is_default`/
  `attempts_remaining` from the verify response.
- §3 FR-2 / §13 OQ-2: removed the non-existent `verification_method`-based mode
  branching; **amounts mode is the only verified mode**; descriptor-code demoted to
  an unverified backend capability.
- §3 FR-3 / FR-5: amount range corrected `0..99` → **`1..99`**; wrong-amounts
  handling changed from a fabricated typed error w/ remaining-attempts to a
  **generic retryable error from `detail`**.
- §3 FR-7, §4.5: deep-link/nav param corrected `pm`/`{pm}` → **`sid`/{setup_intent_id}`**.
- §6: noted the web's **persisted pending-bank record** (the spec wrongly implied
  nothing is persisted).
- §7: `UsBankError` enum trimmed to verifiable values; removed the `409→success`
  special case.
- Frontmatter: `status: reviewed`, added `reviewed_on: 2026-06-06`.

### Open assumptions

- **Wrong/incorrect-amounts runtime status & body.** OpenAPI documents only
  `422 HTTPValidationError`; a Stripe-side amount mismatch almost certainly returns
  *something* at runtime, but its status/shape is not captured in any source. Why
  unverifiable: not in OpenAPI, and the web client only logs `err.message`
  generically. **Action:** probe the live dev backend (manual test) and record the
  real shape before finalizing the error mapper.
- **`attempts_remaining` / attempt-limit semantics.** No evidence anywhere.
  Treated as non-existent; UI must not depend on it.
- **Deterministic Stripe test microdeposit amounts.** Not in sources; must be
  confirmed against the dev/Stripe test configuration.
- **`is_default` / chargeability after verification.** Not in the verify response;
  must be read from a subsequent `GET /ui/billing/payment-methods` fetch.
- **Whether the backend ever supports `descriptor_code` end-to-end.** Schema-present
  but unused by web; no confirmation it is wired. Do not build the UI for it.

## 17. Test Plan

IDs `TC-AND-230-NN`. Test targets per the CI/dev matrix: **JVM/Robolectric**
(local, no device), **emulator AVD `test35`** (x86_64, API 35), **physical device**
Samsung Galaxy A15 5G (SM-A156U, serial `R5CX821TA9R`, API 34, arm64-v8a). This
ticket is a Compose form + Retrofit call with no camera/biometric/WebRTC/FCM
surface, so most cases run JVM or emulator; the physical device is used only where
real-network/ABI behavior matters.

- **TC-AND-230-01 — Request serialization (amounts mode).**
  Type: contract/MockWebServer. Target: JVM/Robolectric (MockWebServer).
  Preconditions: `BillingApi` wired to a MockWebServer base URL; auth interceptor
  injects `X-CSRF-Token`. Steps: call
  `verifyMicrodeposits(setupIntentId="seti_1ABCdef", Amounts(32,45))`; enqueue a 200
  `{ "status": "verified" }`. Expected: recorded request is `POST
  /ui/billing/us-bank/verify-microdeposits`, JSON body
  `{"setup_intent_id":"seti_1ABCdef","amounts":[32,45]}` (no `descriptor_code` /
  no `payment_method_id`), header `X-CSRF-Token` present. Traces: AC-1.

- **TC-AND-230-02 — Success response deserialization & mapping.**
  Type: unit. Target: JVM. Preconditions: Moshi adapters generated. Steps:
  deserialize `{ "status": "verified" }`; run `toDomain("seti_1ABCdef")`. Expected:
  `UsBankVerificationResult(setupIntentId="seti_1ABCdef", state=VERIFIED,
  isDefault=false, attemptsRemaining=null)`. Traces: AC-2.

- **TC-AND-230-03 — Unknown/absent status maps to UNKNOWN (mapper totality).**
  Type: unit. Target: JVM. Preconditions: none. Steps: deserialize `{}` and
  `{ "status": "weird" }`; map each. Expected: no throw; `state == UNKNOWN`. Traces:
  AC-2.

- **TC-AND-230-04 — Repository wraps 200 into `ApiResult.Success`.**
  Type: contract/MockWebServer. Target: JVM/Robolectric. Preconditions: MockWebServer.
  Steps: enqueue 200 `{ "status": "verified" }`; call
  `UsBankRepository.verifyMicrodeposits`. Expected:
  `ApiResult.Success(UsBankVerificationResult(state=VERIFIED))`. Traces: AC-3, AC-2.

- **TC-AND-230-05 — 422 validation error maps to a generic retryable error.**
  Type: contract/MockWebServer. Target: JVM/Robolectric. Preconditions: MockWebServer.
  Steps: enqueue `422 {"detail":[{"loc":["body","amounts"],"msg":"field
  required","type":"value_error.missing"}]}`; call the repository. Expected:
  `ApiResult.Error` whose message derives from `detail[].msg` ("field required");
  mapped `UsBankError == VALIDATION` (or `GENERIC`); error is retryable. Traces:
  AC-3, AC-4.

- **TC-AND-230-06 — ViewModel happy path emits `Verified` and clears pending.**
  Type: unit (Turbine on `uiState`/`events`). Target: JVM. Preconditions: repo
  faked to return success. Steps: set fields `32`/`45`, assert `canSubmit==true`,
  call `submit()`. Expected: `isSubmitting` toggles true→false; success UI state;
  one `VerifyEvent.Verified(setupIntentId, isDefault=false)` emitted; persisted
  pending-bank record cleared. Traces: AC-4, AC-1.

- **TC-AND-230-07 — Input validation gates Verify (range 1–99, digit-only).**
  Type: unit. Target: JVM. Preconditions: fresh VM. Steps: try `""`, `0`, `100`,
  `1a` in each amount field; then `1`/`99`. Expected: `canSubmit==false` for
  empty/`0`/`>99`/non-digit and for a single filled field; `true` only when both are
  in `1..99`; non-digit/over-length input is rejected at `onChange`. Traces: AC-4,
  AC-5.

- **TC-AND-230-08 — Wrong-amounts rejection keeps the form usable.**
  Type: unit (Turbine). Target: JVM. Preconditions: repo faked to return
  `ApiResult.Error` (simulating the live mismatch response; see Open assumptions).
  Steps: submit `11`/`22`. Expected: inline retryable error shown; `isSubmitting`
  reset to false; form still enabled (`isFormDisabled==false`); NO fabricated
  attempts-remaining value asserted. Traces: AC-4.

- **TC-AND-230-09 — Offline / host timeout yields retryable error, not a stuck
  spinner.** Type: integration/MockWebServer. Target: JVM/Robolectric.
  Preconditions: MockWebServer set to no-response / socket policy
  `NO_RESPONSE`, OkHttp read timeout ~20s (shortened in test). Steps: `submit()`;
  await timeout. Expected: `ApiResult.Error` (IOException) → "Couldn't reach the
  server" retryable error; `isSubmitting` reset in `finally`; re-tapping Verify
  re-issues the request. Traces: AC-6.

- **TC-AND-230-10 — Verify-only POST is not auto-retried.**
  Type: contract/MockWebServer. Target: JVM/Robolectric. Preconditions: MockWebServer
  enqueues a single 503 then a 200. Steps: `submit()` once. Expected: exactly **one**
  request hits the server (mutating POST excluded from the idempotent-GET retry
  policy); the 503 surfaces as an error, not silently retried. Traces: AC-6, AC-1.

- **TC-AND-230-11 — Compose: end-to-end success against MockWebServer.**
  Type: Compose-UI. Target: emulator AVD `test35` (API 35). Preconditions:
  `createAndroidComposeRule`, MockWebServer enqueues 200 `{ "status": "verified" }`.
  Steps: enter `32` and `45`, tap "Verify". Expected: success node ("Bank account
  verified") shown; Verify button disabled during submit; recorded request body
  `{"setup_intent_id":...,"amounts":[32,45]}`. Traces: AC-5, AC-4, AC-1.

- **TC-AND-230-12 — Compose: deep link resolves the `sid` arg.**
  Type: instrumented/e2e. Target: emulator AVD `test35`. Preconditions: nav graph
  with the `navDeepLink`. Steps:
  `adb shell am start -a android.intent.action.VIEW -d
  "com.testlogon.android://billing/us-bank/verify?sid=seti_1ABCdef"`. Expected:
  `VerifyMicrodepositsScreen` opens with `setupIntentId == "seti_1ABCdef"`; a
  malformed/missing `sid` routes to a safe error/empty state, not a crash. Traces:
  AC-5.

- **TC-AND-230-13 — Accessibility (TalkBack semantics & touch targets).**
  Type: Compose-UI (a11y assertions). Target: emulator AVD `test35`. Preconditions:
  screen rendered. Steps: assert content descriptions ("first deposit amount,
  dollars and cents" / "second deposit amount"), Verify button has a click action
  and ≥48dp target; trigger an error and assert the inline error node is a
  `liveRegion`; assert IME "Done" on the last field invokes submit when valid.
  Expected: all semantics present; error announced. Traces: AC-5, AC-4.

- **TC-AND-230-14 — No-leak logging/analytics (security/privacy).**
  Type: unit. Target: JVM. Preconditions: in-memory log + fake analytics sink;
  `HttpLoggingInterceptor` at `BASIC`. Steps: run a submit through the stack.
  Expected: neither captured logs nor analytics events
  (`usbank_verify_submitted`/`_failed`) contain the entered amounts or any
  `descriptor_code`; events carry only `setup_intent_id` / error code. Traces: AC-7.

- **TC-AND-230-15 — Live verification on the physical device (manual, non-CI).**
  Type: manual / instrumented-e2e. Target: **physical device** Galaxy A15 5G
  (SM-A156U, `R5CX821TA9R`) — uses the real flaky plaintext-HTTP dev host
  (`http://18.222.237.167:8000`) over real Wi-Fi/cellular, exercising the real ~20s
  timeout and arm64/API-34 path that the x86/API-35 emulator does not. Preconditions:
  a Stripe test US bank (`account 000123456789`, routing `110000000`) put into
  pending state via the add-bank flow, yielding a real `setup_intent_id`; airplane-
  mode toggle available to exercise the offline path on real radios. Steps: open the
  verify screen via deep link with that `setup_intent_id`; (a) submit the known test
  microdeposit amounts → confirm 200 success and the payment-methods list refreshes
  to show the verified bank; (b) submit wrong amounts → confirm a retryable error;
  (c) enable airplane mode, submit → confirm the retryable "couldn't reach server"
  state and no stuck spinner. Capture and sanitize the real success/error JSON as
  fixtures and **record the real wrong-amounts HTTP status/shape** to resolve the
  Open assumption in §16. Traces: AC-8, AC-6, AC-4.

### Coverage matrix

| AC (§14) | Covered by |
|----------|-----------|
| AC-1 (API method/body/CSRF) | TC-01, TC-06, TC-10, TC-11 |
| AC-2 (DTOs + total mapper, UNKNOWN) | TC-02, TC-03, TC-04 |
| AC-3 (repository → `ApiResult` + error mapping) | TC-04, TC-05 |
| AC-4 (ViewModel state/events; success & error) | TC-05, TC-06, TC-07, TC-08, TC-11, TC-13, TC-15 |
| AC-5 (screen renders/gates; in-app + deep link) | TC-07, TC-11, TC-12, TC-13 |
| AC-6 (timeout/offline retryable, no stuck spinner) | TC-09, TC-10, TC-15 |
| AC-7 (no amounts/code in logs or analytics) | TC-14 |
| AC-8 (full suite green + live run verifies real bank) | TC-01…TC-14 (suite), TC-15 (live) |
