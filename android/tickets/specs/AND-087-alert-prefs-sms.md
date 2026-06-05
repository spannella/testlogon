---
id: AND-087
title: "Alert prefs: SMS"
milestone: M2
epic: E12
priority: P1
size: M
status: draft
depends_on: [AND-078]
blocks: [AND-088]
---

# AND-087 — Alert prefs: SMS

## 1. Overview & Goal

This ticket delivers the **SMS alert-target management** capability: the ability for an
authenticated user to **add**, **verify (confirm)**, and **remove** an SMS destination used to
receive product/security alerts. It is the SMS-channel slice of epic E12 (Alert preferences) and
feeds the unified alert-preferences screen (AND-088).

An SMS alert target is a verified phone number. Adding one is a two-step **begin → confirm**
exchange: the client submits a raw phone number to `POST /ui/alerts/sms/begin`, the backend
dispatches a one-time verification code and returns a **masked** destination plus cooldown/expiry
hints; the user then submits the received code to `POST /ui/alerts/sms/confirm`, which marks the
target verified. Removal is a single `POST /ui/alerts/sms/remove`. The current set of SMS targets
and their verification state is read from `GET /ui/alerts/sms_prefs`.

Scope is the **data + repository layer** plus a **thin verification ViewModel/UI** to drive the
begin/confirm/remove flow within `feature-settings` (epic E12), strictly distinct from the MFA SMS
factor (AND-035): an alert target is a *delivery destination*, not an authentication factor, and
uses the `/ui/alerts/*` namespace, not `/ui/mfa/*`. This ticket owns the `SmsAlertRepository`
seam, its DTOs/adapters, the domain result types, and a self-contained add/verify/remove flow
exposing `StateFlow<SmsAlertUiState>`. The richer combined alert dashboard that lists SMS
alongside email/push is owned by AND-088, which consumes this repository.

Success = a user can add an SMS target, receive and confirm a code, see it listed as verified,
and remove it — all round-tripped through the repository to the API and proven by unit and UI
tests. This is the explicit acceptance gate: **"Add/verify/remove SMS alert target (tested)."**

## 2. Context & References

- **Repo / module:** `spannella/testlogon`, monorepo subfolder `android/`, branch `android-port`.
  New code spans `core-network` (DTOs + `SmsAlertApi`), `core-model` (domain results),
  `core-data` (`SmsAlertRepository`), and `feature-settings` (verify flow ViewModel + screens).
- **Namespace:** `com.testlogon.android` everywhere a package appears. Specifically:
  `com.testlogon.android.core.network.alerts`, `com.testlogon.android.core.model.alerts`,
  `com.testlogon.android.core.data.alerts`, `com.testlogon.android.feature.settings.alerts.sms`.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Navigation-Compose, Hilt (KSP),
  Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, DataStore (last-known-good cache),
  minSdk 24 / compileSdk-targetSdk 35, JDK 17, Gradle 8.9 / AGP 8.7.3.
- **Depends on (blocking):**
  - **AND-078 (Preferences API + DTOs):** establishes the preferences endpoint/DTO/repository
    pattern, the `ApiResult<T>` flow conventions, and the `PreferencesApi` Retrofit/Moshi base
    this ticket mirrors. AND-087 adds the `/ui/alerts/sms/*` + `/ui/alerts/sms_prefs` surface and
    `SmsAlertRepository` following AND-078's layering; it does **not** re-implement transport,
    error mapping, or the cache pattern.
- **Blocks:**
  - **AND-088 (unified Alert preferences screen):** consumes `SmsAlertRepository` and the
    `SmsAlertTarget` model to render the SMS section within the combined channels UI and reuses
    the begin/confirm/remove flow exposed here.
- **Related (not blocking):** AND-035 (MFA SMS begin/verify — sibling *shape*, different
  endpoint namespace and semantics; the masked-destination + cooldown idioms are reused for
  consistency), AND-020 (OTP input composable, reused for code entry), AND-021 (loading/empty/
  error/offline state composables), AND-015 (FastAPI `detail` → `ApiError` mapping), AND-018
  (`ApiResult`/`ApiError`, `map`/`flatMap`), AND-009 (~20s timeouts, redacted logging),
  AND-011/AND-012/AND-013 (cookie jar, CSRF header, 401→refresh — all transport-owned),
  AND-016 (GET-only retry/backoff — applies to the `sms_prefs` GET, excludes the POSTs).
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext, unreliable;
  ~20s timeouts, bounded backoff on idempotent GETs only, offline/stale UI). OpenAPI at
  `/openapi.json`. Web reference: `frontend/src/api/endpoints/*.ts` (alerts endpoints),
  shared types `frontend/src/api/types.ts`. Auth is cookie-based; the user is already
  authenticated when reaching this surface.

## 3. Functional Requirements

FR-1. The user can view the current list of SMS alert targets via `GET /ui/alerts/sms_prefs`,
each carrying a server-masked destination (e.g. `+1•••••1234`), a stable target id, and a
`verified` flag.

FR-2. The user can **add** an SMS target by submitting a raw phone number; the repository calls
`POST /ui/alerts/sms/begin`, which dispatches a verification code and returns the masked
destination, the target id, code `expires_in`, and `resend_available_in`.

FR-3. The user can **confirm** a pending target by submitting the received code; the repository
calls `POST /ui/alerts/sms/confirm` with the target id + code. On success the target becomes
`verified`.

FR-4. The user can **resend** a verification code — a re-invocation of `begin` for the same
number, gated by the backend-supplied `resend_available_in` cooldown.

FR-5. The user can **remove** any SMS target (verified or pending) via
`POST /ui/alerts/sms/remove` with the target id; the list refreshes to exclude it.

FR-6. Adding a number is **not idempotent** (it dispatches an SMS); confirm consumes a single-use
code; remove mutates state. None of the three POSTs are auto-retried. Only the `sms_prefs` GET is
eligible for AND-016 backoff retry.

FR-7. Phone-number input is normalized client-side to E.164-ish (`+` + digits, strip spaces/
dashes/parens) before submission; the repository trims and forwards. Server is the authority on
validity; client validation is advisory only (non-empty, leading `+` or digits).

FR-8. The confirm code is trimmed; a blank code short-circuits to a `sms_code_invalid` failure
with **no** network call.

FR-9. State (`SmsAlertUiState`) survives rotation and process death via `SavedStateHandle`
(pending target id, masked destination, resend cooldown deadline); the raw phone number and code
are transient and never persisted.

FR-10. Errors are surfaced inline with stable machine-readable codes so the UI can key localized
copy: `sms_code_invalid`, `sms_resend_throttled`, `sms_target_not_found`, `sms_already_verified`,
`sms_invalid_number`, plus generic transport/HTTP failures.

## 4. Technical Design

Layering: `feature-settings` → `core-data` (`SmsAlertRepository`) → `core-network`
(`SmsAlertApi` Retrofit + DTOs) and `core-model` (domain results). No Retrofit/Moshi type leaks
through the repository interface.

### Domain models (`core-model`, framework-free)

```kotlin
package com.testlogon.android.core.model.alerts

/** A single SMS alert destination as known to the backend. */
data class SmsAlertTarget(
    val id: String,            // stable server target id, e.g. "sat_91ab2c"
    val maskedNumber: String,  // server-masked, e.g. "+1•••••1234"; pass through verbatim
    val verified: Boolean,
)

/** Outcome of a begin/resend dispatch for an SMS alert target. */
data class SmsAlertBeginResult(
    val targetId: String,                  // pending target id to use on confirm
    val sentTo: String,                    // server-masked destination
    val expiresInSeconds: Int,             // code TTL (countdown)
    val resendAvailableInSeconds: Int,     // 0 = resend immediately allowed
)

/** Outcome of a confirm. */
sealed interface SmsAlertConfirmResult {
    data class Verified(val target: SmsAlertTarget) : SmsAlertConfirmResult
    /** Code accepted but server reports it was already verified (idempotent re-confirm). */
    data object AlreadyVerified : SmsAlertConfirmResult
}
```

### Repository (`core-data`)

```kotlin
package com.testlogon.android.core.data.alerts

interface SmsAlertRepository {
    suspend fun listTargets(): ApiResult<List<SmsAlertTarget>>
    suspend fun begin(rawNumber: String): ApiResult<SmsAlertBeginResult>
    suspend fun confirm(targetId: String, code: String): ApiResult<SmsAlertConfirmResult>
    suspend fun resend(targetId: String): ApiResult<SmsAlertBeginResult>
    suspend fun remove(targetId: String): ApiResult<Unit>
}
```

```kotlin
@Singleton
class SmsAlertRepositoryImpl @Inject constructor(
    private val api: SmsAlertApi,
    private val errorMapper: ApiErrorMapper,   // AND-015
) : SmsAlertRepository {

    override suspend fun listTargets(): ApiResult<List<SmsAlertTarget>> =
        safeApiCall { api.smsPrefs() }.map { it.targets.map(SmsTargetDto::toDomain) }

    override suspend fun begin(rawNumber: String): ApiResult<SmsAlertBeginResult> {
        val normalized = PhoneNormalizer.normalize(rawNumber)
        if (normalized.isBlank()) {
            return ApiResult.Failure(ApiError(0, "sms_invalid_number", "Enter a phone number"))
        }
        return safeApiCall { api.begin(SmsBeginReq(normalized)) }
            .map { it.toBeginResult() }
            .remapBeginCodes()           // 429 -> sms_resend_throttled, 422 -> sms_invalid_number
    }

    override suspend fun confirm(targetId: String, code: String): ApiResult<SmsAlertConfirmResult> {
        val trimmed = code.trim()
        if (trimmed.isEmpty()) {
            return ApiResult.Failure(ApiError(0, "sms_code_invalid", "Enter the code we sent you"))
        }
        return safeApiCall { api.confirm(SmsConfirmReq(targetId, trimmed)) }
            .flatMap { it.toConfirmResult() }   // verified=false -> sms_code_invalid
            .remapConfirmCodes()                // 404/410 -> sms_target_not_found
    }

    override suspend fun resend(targetId: String): ApiResult<SmsAlertBeginResult> =
        safeApiCall { api.resend(SmsResendReq(targetId)) }
            .map { it.toBeginResult() }
            .remapBeginCodes()

    override suspend fun remove(targetId: String): ApiResult<Unit> =
        safeApiCall { api.remove(SmsRemoveReq(targetId)) }
            .map { }
            .remapRemoveCodes()                 // 404 -> sms_target_not_found
}
```

Notes:
- `safeApiCall`, `map`, `flatMap`, `ApiResult`, `ApiError` are AND-018; `ApiErrorMapper` is
  AND-015. The `remap*` extensions are small local helpers normalizing FastAPI `detail.code`
  values into this ticket's stable taxonomy without losing `status`/`retryAfterSeconds`.
- A `200` confirm with `verified == false` is **never** reported as success — it maps to
  `Failure(code="sms_code_invalid")` (fail-closed, mirroring AND-035).
- `PhoneNormalizer.normalize` strips whitespace/dashes/parens, keeps a single leading `+` and
  digits; it does not validate against a region table (server authoritative).

### ViewModel + UI (`feature-settings`)

```kotlin
package com.testlogon.android.feature.settings.alerts.sms

sealed interface SmsAlertUiState {
    data object Loading : SmsAlertUiState
    data class Targets(
        val targets: List<SmsAlertTarget>,
        val isStale: Boolean = false,
    ) : SmsAlertUiState
    data class AddingNumber(val input: String, val error: String? = null) : SmsAlertUiState
    data class Verifying(
        val targetId: String,
        val sentTo: String,
        val resendInSeconds: Int,     // ticking countdown
        val codeError: String? = null,
        val submitting: Boolean = false,
    ) : SmsAlertUiState
    data class Error(val message: String, val isOffline: Boolean) : SmsAlertUiState
}

@HiltViewModel
class SmsAlertViewModel @Inject constructor(
    private val repository: SmsAlertRepository,
    private val savedState: SavedStateHandle,
) : ViewModel() {
    val uiState: StateFlow<SmsAlertUiState>
    fun onAdd(rawNumber: String)
    fun onSubmitCode(code: String)
    fun onResend()
    fun onRemove(targetId: String)
    fun onRefresh()
}
```

Route (added to the settings nav graph; also entered from AND-088):

```kotlin
const val SMS_ALERTS_ROUTE = "settings/alerts/sms"

fun NavGraphBuilder.smsAlertScreen(onNavigateUp: () -> Unit) {
    composable(SMS_ALERTS_ROUTE) { SmsAlertRoute(onNavigateUp = onNavigateUp) }
}
```

The resend countdown is a UI concern: the ViewModel seeds `resendInSeconds` from
`resendAvailableInSeconds` and ticks it down with a coroutine `while` loop; the repository never
tracks time. Code entry reuses the OTP composable (AND-020); states reuse AND-021 composables.
Hilt binding: `@Binds SmsAlertRepositoryImpl -> SmsAlertRepository` in a `core-data` alerts module.

## 5. API Contract

All requests `Content-Type: application/json`. Cookies + `X-CSRF-Token` (`ui_csrf`) are added by
interceptors (AND-011/AND-012), not this repository. Errors are folded by `safeApiCall`/AND-015.

**List** — `GET /ui/alerts/sms_prefs` (idempotent; AND-016 retry eligible)
Success `200`:
```json
{ "targets": [
  { "id": "sat_91ab2c", "masked_number": "+1•••••1234", "verified": true },
  { "id": "sat_77de01", "masked_number": "+44•••••789",  "verified": false }
] }
```
→ `Success([SmsAlertTarget("sat_91ab2c","+1•••••1234",true), SmsAlertTarget("sat_77de01","+44•••••789",false)])`

**Begin** — `POST /ui/alerts/sms/begin` (non-idempotent; dispatches SMS)
Request:
```json
{ "number": "+15551231234" }
```
Success `200`:
```json
{ "target_id": "sat_77de01", "sent_to": "+1•••••1234", "expires_in": 300, "resend_available_in": 30 }
```
→ `Success(SmsAlertBeginResult("sat_77de01","+1•••••1234",300,30))`
Invalid number `422`:
```json
{ "detail": [ { "loc": ["body","number"], "msg": "invalid phone number" } ] }
```
→ `Failure(ApiError(status=422, code="sms_invalid_number", message="invalid phone number"))`
Resend throttled `429`:
```json
{ "detail": { "code": "alert_resend_throttled", "retry_after": 22 } }
```
→ `Failure(ApiError(status=429, code="sms_resend_throttled", retryAfterSeconds=22))`

**Confirm** — `POST /ui/alerts/sms/confirm` (non-idempotent; consumes code)
Request:
```json
{ "target_id": "sat_77de01", "code": "482915" }
```
Success — verified:
```json
{ "verified": true, "target": { "id": "sat_77de01", "masked_number": "+1•••••1234", "verified": true } }
```
→ `Success(SmsAlertConfirmResult.Verified(SmsAlertTarget("sat_77de01","+1•••••1234",true)))`
Rejected — HTTP 200, `verified=false`:
```json
{ "verified": false, "detail": "Invalid or expired code", "attempts_remaining": 2 }
```
→ `Failure(ApiError(status=200, code="sms_code_invalid", message="Invalid or expired code", attemptsRemaining=2))`
Bad/expired code `400`: `{ "detail": { "code": "alert_invalid_code", "attempts_remaining": 1 } }`
→ `Failure(ApiError(status=400, code="sms_code_invalid", attemptsRemaining=1))`
Target gone `404`/`410`: → `Failure(ApiError(status=404|410, code="sms_target_not_found"))`
Already verified `409`: `{ "detail": { "code": "alert_already_verified" } }`
→ `Success(SmsAlertConfirmResult.AlreadyVerified)` (treated as benign success on re-confirm).

**Remove** — `POST /ui/alerts/sms/remove` (non-idempotent)
Request: `{ "target_id": "sat_77de01" }` → Success `200`/`204` → `Success(Unit)`.
Not found `404`: → `Failure(ApiError(status=404, code="sms_target_not_found"))`.

**Common failures:** `422` validation → `Failure(status=422)` (generic unless on `begin` number
field); `5xx`/unreachable/timeout → `ApiResult.NetworkError(isTimeout)`. Verbs, paths, headers
mirror `frontend/src/api/endpoints/*.ts`; confirm against `/openapi.json` (see R1–R3).

## 6. Data & State Management

- **Read cache (last-known-good):** the `sms_prefs` list is cached to **DataStore** (per AND-078
  pattern) keyed by `user_sub` so the list renders offline as **stale** (FR-7-style banner via
  AND-021). The repository writes the cache on a successful `listTargets()` and reads it as a
  fallback when the GET fails with a `NetworkError`. Cache holds only masked numbers + ids +
  verified flags — no raw numbers, no codes.
- **No persistence of secrets:** the raw phone number and the confirmation code are transient,
  held only on the coroutine frame and (for in-progress UI) in `SmsAlertUiState`; never written
  to Room/DataStore. The pending `targetId`, masked `sentTo`, and the resend deadline (an
  absolute `elapsedRealtime` ms) are saved to `SavedStateHandle` so the verify screen survives
  process death and the countdown resumes correctly.
- **Optimistic removal (optional):** `onRemove` may optimistically drop the target from the
  `Targets` list and roll back on failure; the canonical list is re-fetched after a successful
  remove to reconcile.
- `SmsAlertTarget`, `SmsAlertBeginResult`, `SmsAlertConfirmResult` are immutable value types,
  safe to carry in `StateFlow`. The repository is `@Singleton` and stateless beyond the injected
  `SmsAlertApi` and the DataStore handle.
- Session/CSRF cookies are persisted by the OkHttp cookie jar (AND-011) as a side effect of the
  calls; this repository neither reads nor writes cookies.

## 7. Error Handling & Resilience

- **No retry on the three POSTs.** `begin`/`confirm`/`remove` are state-mutating and
  non-idempotent (begin dispatches an SMS and resets cooldown; confirm consumes a single-use
  code; remove deletes). AND-016 backoff applies **only** to the `sms_prefs` GET. Each POST
  issues exactly one network attempt; `NetworkError` is surfaced for a manual user retry — and
  for `confirm` the user must re-enter a *fresh* code.
- **Timeouts:** OkHttp ~20s (AND-009) against the flaky dev host; `SocketTimeoutException` folds
  to `NetworkError(isTimeout=true)` so the UI shows "server is slow" copy distinct from offline.
- **Wrong/expired code:** both HTTP `200 verified=false` and a `400 alert_invalid_code` normalize
  to `ApiError(code="sms_code_invalid")`, carrying `attemptsRemaining` when present. The UI keeps
  the user on the code screen, clears the field, surfaces remaining attempts, and does **not**
  abandon the pending target.
- **Resend throttled (`429`):** mapped to `code="sms_resend_throttled"` with `retryAfterSeconds`;
  the UI disables the resend control until the cooldown elapses. No auto-retry.
- **Target gone (`404`/`410`):** mapped to `code="sms_target_not_found"`; the UI re-fetches the
  list and returns to the targets view (the pending verification is terminal).
- **Already verified (`409`):** mapped to a benign `SmsAlertConfirmResult.AlreadyVerified` so a
  duplicate confirm does not surface as an error.
- **Invalid number (`422` on begin):** mapped to `code="sms_invalid_number"`; shown inline under
  the number field, keeping the user on the add step.
- **401 on `/ui/alerts/*`:** a genuine session-expiry 401 here **does** trigger AND-013's single
  `session/refresh` + retry (unlike MFA endpoints) because the user holds a completed session.
  This is left entirely to the transport authenticator; no special handling in this repository.
- **Blank-code / blank-number guards:** short-circuit to `sms_code_invalid` / `sms_invalid_number`
  with no network call.
- `CancellationException` propagates unchanged (structured concurrency; AND-018 rethrows).

## 8. Security & Privacy

- **Code handling:** the confirmation code is passed straight into the request body and never
  logged, stored, or placed in `ApiError`/result types. It lives only on the call frame and the
  transient verify UI state; not retained after the call returns.
- **Raw phone number:** submitted only on `begin`/`resend`; never persisted to DataStore/Room,
  never logged, never put in telemetry. Only the **server-masked** `masked_number`/`sent_to`
  values (`+1•••••1234`) are cached/displayed, passed through verbatim, never reconstructed.
- **Target id:** persisted to `SavedStateHandle` for flow continuity only; never logged or sent
  to telemetry.
- **No request/response body logging** for `/ui/alerts/sms/*`. The OkHttp logging interceptor
  (AND-009) MUST run at `BASIC` or redact `/ui/alerts/sms/*` so neither the raw number, the code,
  nor the masked destination reaches Logcat (verified in Section 11).
- Cleartext HTTP to the dev host is a known dev-only posture (network security config permits
  cleartext for the dev flavor only); codes/numbers traverse the wire unencrypted **in dev only** —
  production must enforce HTTPS (build-config owned upstream).
- `ApiError.message` carries server `detail` only as a diagnostic fallback and must never echo
  the submitted code or the full destination.

## 9. Accessibility & i18n

- The OTP entry affordance, content descriptions, and "incorrect code" announcements are owned by
  AND-020 (reused). The number field uses `KeyboardType.Phone` and an explicit content
  description; the verify screen announces the masked destination via TalkBack ("code sent to
  +1•••••1234").
- The resend countdown is rendered as a polite **live region** announcing remaining seconds and
  the enabled/disabled state of the resend control; "Verified" and "Removed" outcomes are
  announced via live-region/snackbar.
- All user-facing copy is sourced from string resources keyed off the stable `ApiError.code`
  values (`sms_code_invalid`, `sms_resend_throttled`, `sms_target_not_found`,
  `sms_invalid_number`) so the UI shows **localized** strings rather than server English; raw
  `ApiError.message` is a diagnostic fallback only.
- Masked numbers are server-localized/server-masked; displayed verbatim (no client reformatting),
  RTL-safe via Compose bidi defaults. Touch targets ≥ 48dp; switches/buttons have role semantics.

## 10. Telemetry & Logging

Structured events via the analytics/Timber seam (AND-009), with **no PII / no secrets**:
- `alert_sms_begin` — `is_resend`, `outcome` (`sent | throttled | invalid_number | failure |
  network_error`), `http_status` (on failure), `retry_after_seconds` (on throttle), `is_timeout`.
- `alert_sms_confirm` — `outcome` (`verified | already_verified | rejected | target_not_found |
  failure | network_error`), `http_status`, `error_code`, `attempts_remaining` (when present),
  `is_timeout`.
- `alert_sms_remove` — `outcome` (`removed | not_found | failure | network_error`), `http_status`.
- `alert_sms_list` — `outcome` (`loaded | stale | network_error`), `target_count` (on success),
  `is_timeout`.

**Never log:** the raw number, the masked destination, the code, the `target_id`, cookie values,
or raw request/response bodies for these endpoints. The repository depends on no Android logging
API directly beyond the injected logger seam, keeping `core-model` framework-free.

## 11. Testing Strategy

Unit tests in `core-data/src/test` (JUnit, Truth, coroutines-test). `SmsAlertApi` is faked / a
MockK stub returning canned responses or HTTP/IO failures so this ticket tests **branching and
mapping**, with a small MockWebServer pair for request-shape.

Mapping / branch tests:
- `smsPrefs` two-target response → ordered `List<SmsAlertTarget>` with masks + verified flags.
- `begin` success → `SmsAlertBeginResult(targetId, sentTo, expiresInSeconds, resendAvailableInSeconds)`;
  `resend_available_in` absent → defaults `0`.
- `begin` `429 alert_resend_throttled retry_after=22` → `Failure(code="sms_resend_throttled",
  status=429, retryAfterSeconds=22)`.
- `begin` `422` number field → `Failure(code="sms_invalid_number", status=422)`.
- `confirm` `verified=true` → `Verified(target.verified==true)`.
- `confirm` `200 verified=false detail="Invalid…" attempts_remaining=2` →
  `Failure(status=200, code="sms_code_invalid", message="Invalid…", attemptsRemaining=2)`.
- `confirm` `400 alert_invalid_code attempts_remaining=1` →
  `Failure(code="sms_code_invalid", attemptsRemaining=1)`.
- `confirm` `404`/`410` → `Failure(code="sms_target_not_found")`.
- `confirm` `409 alert_already_verified` → `Success(AlreadyVerified)`.
- `remove` `200`/`204` → `Success(Unit)`; `remove` `404` → `Failure(code="sms_target_not_found")`.
- Transport: timeout → `NetworkError(isTimeout=true)`; generic IO → `NetworkError(false)`;
  `CancellationException` re-thrown (`assertFailsWith`).

Input-guard tests:
- `confirm(id, "  ")` → `Failure(code="sms_code_invalid")` with **no** API call (fake not invoked).
- `begin(" ")` → `Failure(code="sms_invalid_number")` with **no** API call.
- `begin("+1 (555) 123-1234")` → request body `{"number":"+15551231234"}` (normalized; recorded
  request asserted via MockWebServer).

Cache tests (`core-data`, with a fake DataStore):
- successful `listTargets()` writes cache; subsequent `listTargets()` on `NetworkError` returns
  cached targets flagged stale; cache contains no raw number/code substrings.

Security test:
- with the OkHttp logging interceptor attached, captured logs of `begin`/`confirm`/`remove`
  contain none of the raw number, code, masked destination, or `target_id` substrings.

UI tests (`feature-settings/src/androidTest`, Compose test rule, fake repository):
- Add → enter number → begin success shows the code (Verifying) screen with masked destination.
- Enter correct code → confirm success → target appears as **verified** in the list.
- Enter wrong code → inline "incorrect code" error, field cleared, still on verify screen.
- Resend disabled during cooldown, enabled when countdown hits 0.
- Remove a target → it disappears from the list (acceptance round-trip proven).

DI smoke test: `@HiltAndroidTest` resolves `SmsAlertRepository` (bound to `SmsAlertRepositoryImpl`)
with all five methods callable.

## 12. Dependencies & Sequencing

- **Requires (blocking):** **AND-078** — preferences endpoint/DTO/repository pattern, `ApiResult`
  flow conventions, `ApiErrorMapper`, and DataStore cache pattern that this ticket mirrors for the
  `/ui/alerts/sms/*` surface.
- **Strongly related (needed for end-to-end correctness, not strictly compile-time blocking):**
  AND-018 (`ApiResult`/`map`/`flatMap`), AND-015 (`detail` → `ApiError`, `retry_after`/
  `attempts_remaining`), AND-011/AND-012/AND-013 (cookie jar, CSRF, 401→refresh), AND-009
  (timeouts/redacted logging), AND-016 (GET-only retry for `sms_prefs`), AND-020 (OTP composable),
  AND-021 (state composables). The repository compiles and unit-tests via the faked `SmsAlertApi`
  without the transport interceptors.
- **Enables / blocks:** **AND-088** (unified Alert preferences screen) consumes
  `SmsAlertRepository` + `SmsAlertTarget` and embeds the begin/confirm/remove flow.
- **Sequencing:** Land after AND-078; before AND-088. Coordinate the `sms_*` `ApiError.code`
  taxonomy with the email/push alert-channel owners (sibling E12 tickets) so AND-088 keys
  consistent localized copy across channels.

## 13. Risks & Open Questions

- **R1 — Endpoint/field names.** Assumes `GET /ui/alerts/sms_prefs` returns `{targets:[{id,
  masked_number,verified}]}` and `begin` returns `{target_id, sent_to, expires_in,
  resend_available_in}`. Verify exact verbs, paths, and field names against `/openapi.json` and
  `frontend/src/api/endpoints/*.ts` before merge; adjust DTOs/adapters if they differ.
- **R2 — Confirm key.** Assumes `confirm` keys the pending target by `target_id` returned from
  `begin`. If the backend instead keys confirm by the raw/normalized number, change
  `SmsConfirmReq` and the flow's continuation accordingly.
- **R3 — Wrong-code signalling (200 vs 4xx).** Spec handles both `200 verified=false` and a
  `400 alert_invalid_code`. Confirm which the dev host uses and whether `attempts_remaining` is
  populated, so the AND-015 remap is correct.
- **R4 — Already-verified semantics.** Treating `409 alert_already_verified` as benign success
  assumes re-confirm of an already-verified target is idempotent; confirm the code string and
  whether the server returns the target payload.
- **R5 — Resend throttle source.** Assumes throttle is signalled on `begin` (and `resend`) with
  `detail.code == alert_resend_throttled` + `retry_after`. Confirm the code string and whether a
  separate `/resend` endpoint exists or resend is just a re-`begin`.
- **Q1 — Target cap.** Is there a maximum number of SMS targets per account? If so, surface a
  `sms_target_limit` error code and a friendly limit message (likely a follow-up).
- **Q2 — Verified-target use.** Out of scope here: which alert categories actually deliver to a
  verified SMS target is owned by AND-088 / the wider E12 prefs matrix.

## 14. Acceptance Criteria

1. `SmsAlertRepository` exists in `com.testlogon.android.core.data.alerts` with `listTargets`,
   `begin`, `confirm`, `resend`, `remove`, implemented in `SmsAlertRepositoryImpl` (Hilt-bound),
   leaking only `core-model` types (no Retrofit/Moshi types in the interface).
2. Domain types `SmsAlertTarget`, `SmsAlertBeginResult`, and `sealed SmsAlertConfirmResult`
   (`Verified` | `AlreadyVerified`) exist in `com.testlogon.android.core.model.alerts`.
3. **Add (tested):** `begin(number)` calls `POST /ui/alerts/sms/begin` with a normalized
   `{"number"}` body (asserted via MockWebServer) and returns `SmsAlertBeginResult`.
4. **Verify (tested):** `confirm(targetId, code)` calls `POST /ui/alerts/sms/confirm` with
   `{"target_id","code"}` (code trimmed); `verified=true` → `Verified`, `verified=false`/4xx
   bad-code → `Failure(code="sms_code_invalid")`, `409` → `AlreadyVerified`.
5. **Remove (tested):** `remove(targetId)` calls `POST /ui/alerts/sms/remove` with
   `{"target_id"}` → `Success(Unit)`; `404` → `Failure(code="sms_target_not_found")`.
6. `listTargets()` calls `GET /ui/alerts/sms_prefs`, maps to `List<SmsAlertTarget>`, caches to
   DataStore, and returns cached targets flagged stale on `NetworkError`.
7. Resend works: `resend` re-dispatches; `429` → `Failure(code="sms_resend_throttled",
   retryAfterSeconds=…)`. `422` on begin number → `Failure(code="sms_invalid_number")`.
8. Transport/HTTP failures pass through: IO/timeout → `NetworkError`; HTTP error →
   `Failure(ApiError)`; `CancellationException` re-thrown. Blank code → `sms_code_invalid`,
   blank number → `sms_invalid_number`, both with no network call.
9. A `feature-settings` SMS-alert flow (`SmsAlertViewModel` + screens) exposes
   `StateFlow<SmsAlertUiState>`, surviving rotation/process death, and drives add→verify→remove;
   Compose UI tests prove the round-trip (add, verify, list-as-verified, remove).
10. No raw number, code, masked destination, or `target_id` appears in logs (security test green).
11. `./gradlew :core-data:test :core-model:test :feature-settings:test` green; instrumented UI
    tests green; ktlint/detekt (AND-005) pass.

## 15. Definition of Done

- `SmsAlertApi` + DTOs/adapters (`core-network.alerts`), `SmsAlertRepository`/Impl
  (`core-data.alerts`), the `core-model.alerts` result types, and the `feature-settings`
  add/verify/remove flow are implemented, compile, and are merged to `android-port`.
- Unit tests cover every begin/confirm/remove/list branch, the resend-throttle map, every remap
  and failure-passthrough case, the input guards, the normalization request-shape, and the cache
  fallback (Section 11); UI tests cover the add→verify→remove round-trip; all pass via the Gradle
  invocations in AC-11.
- Public types, the begin→confirm→remove contract, and the `sms_*` `ApiError.code` taxonomy are
  documented in KDoc; AND-088 is notified that `SmsAlertRepository`/`SmsAlertTarget` are frozen
  for consumption.
- No Retrofit/OkHttp/Moshi types leak through `SmsAlertRepository` (verified by signature
  inspection). No raw number/code/`target_id`/masked-destination logging (security test green).
- ktlint/detekt (AND-005) pass on new files; code reviewed. Risks R1–R5 and Q1–Q2 either resolved
  against `/openapi.json` / `frontend/src/api/endpoints` or filed as follow-ups before AND-088
  integration.
