---
id: AND-087
title: "Alert prefs: SMS"
milestone: M2
epic: E12
priority: P1
size: M
depends_on: [AND-078]
blocks: [AND-088]
status: reviewed
reviewed_on: 2026-06-06
---

# AND-087 — Alert prefs: SMS

## 1. Overview & Goal

This ticket delivers the **SMS alert-target management** capability: the ability for an
authenticated user to **add**, **verify (confirm)**, and **remove** an SMS destination used to
receive product/security alerts. It is the SMS-channel slice of epic E12 (Alert preferences) and
feeds the unified alert-preferences screen (AND-088).

An SMS alert target is a verified phone number. Adding one is a two-step **begin → confirm**
exchange: the client submits a raw phone number (field **`phone`**) to `POST /ui/alerts/sms/begin`,
the backend dispatches a one-time verification code and returns a **`challenge_id`** plus a masked
**`sent_to`** destination; the user then submits the received code to `POST /ui/alerts/sms/confirm`
keyed by that **`challenge_id`** (not a target id), which marks the number verified. Removal is a
single `POST /ui/alerts/sms/remove`, keyed by the **`phone`** string (not a target id). The current
set of confirmed SMS numbers is read from `GET /ui/alerts/sms_prefs`, which returns an
`AlertPreferences` object whose **`sms_numbers: string[]`** holds the configured numbers (plain
strings as returned by the server — there is **no** per-target id or `verified` flag in the
contract).

> **REVIEW NOTE (corrected, AND-087 review 2026-06-06):** the authoritative contract differs
> materially from the original draft. Verified against OpenAPI (`AlertSmsBeginReq`,
> `AlertSmsConfirmReq`, `AlertSmsRemoveReq`, `AlertPreferences`) and the web client
> (`src/api/endpoints/alerts.ts`, `src/pages/alerts/AlertPrefs.tsx`). Key field/shape names below
> were corrected throughout; the begin response carries only `challenge_id` + `sent_to` (no
> `expires_in`/`resend_available_in`), confirm/remove return the full `AlertPreferences`, and
> `sms_prefs` returns `{ sms_numbers: string[], ... }` — not a `targets` array. See §16 for the
> full audit.

Scope is the **data + repository layer** plus a **thin verification ViewModel/UI** to drive the
begin/confirm/remove flow within `feature-settings` (epic E12), strictly distinct from the MFA SMS
factor (AND-035): an alert target is a *delivery destination*, not an authentication factor, and
uses the `/ui/alerts/*` namespace, not `/ui/mfa/*`. This ticket owns the `SmsAlertRepository`
seam, its DTOs/adapters, the domain result types, and a self-contained add/verify/remove flow
exposing `StateFlow<SmsAlertUiState>`. The richer combined alert dashboard that lists SMS
alongside email/push is owned by AND-088, which consumes this repository.

Success = a user can add an SMS number, receive and confirm a code, see it listed in
`sms_numbers`, and remove it — all round-tripped through the repository to the API and proven by unit and UI
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
    `SmsAlertNumber` model to render the SMS section within the combined channels UI and reuses
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

FR-1. The user can view the current list of confirmed SMS numbers via `GET /ui/alerts/sms_prefs`,
which returns an `AlertPreferences` object; the configured numbers are the strings in
**`sms_numbers: string[]`**. **CORRECTED:** the contract does NOT expose a per-target stable id or
a `verified` flag — `sms_numbers` lists numbers that are already confirmed. (Whether the strings
are server-masked vs. full E.164 is **unverified** from the sources; treat them as opaque
server-formatted display strings — see §16 OA-7.)

FR-2. The user can **add** an SMS number by submitting a raw phone number; the repository calls
`POST /ui/alerts/sms/begin` with body **`{ "phone": ... }`** (CORRECTED from `{ "number" }`),
which dispatches a verification code and returns **`{ challenge_id, sent_to }`** only.
**CORRECTED:** the begin response carries NO `target_id`, NO `expires_in`, and NO
`resend_available_in` (those were draft assumptions and are removed; see §16 OA-2).

FR-3. The user can **confirm** a pending number by submitting the received code; the repository
calls `POST /ui/alerts/sms/confirm` with body **`{ "challenge_id", "code" }`** (CORRECTED from
`{ "target_id", "code" }`). On success the backend returns the updated `AlertPreferences` and the
number now appears in `sms_numbers`.

FR-4. The user can **resend** a verification code by re-invoking `begin` for the same number.
**CORRECTED:** there is NO dedicated resend endpoint and NO server-supplied `resend_available_in`
cooldown in the contract; "resend" is simply a second `POST /ui/alerts/sms/begin` with the same
`phone`. Any client cooldown is a UI-only nicety, not backed by a server field (see §16 OA-5).

FR-5. The user can **remove** any configured SMS number via `POST /ui/alerts/sms/remove` with body
**`{ "phone": ... }`** (CORRECTED from `{ "target_id" }`); the call returns the updated
`AlertPreferences` and the list refreshes to exclude it.

FR-6. Adding a number is **not idempotent** (it dispatches an SMS); confirm consumes a single-use
code; remove mutates state. None of the three POSTs are auto-retried. Only the `sms_prefs` GET is
eligible for AND-016 backoff retry.

FR-7. Phone-number input is normalized client-side to E.164-ish (`+` + digits, strip spaces/
dashes/parens) before submission; the repository trims and forwards. Server is the authority on
validity; client validation is advisory only (non-empty, leading `+` or digits).

FR-8. The confirm code is trimmed; a blank code short-circuits to a `sms_code_invalid` failure
with **no** network call.

FR-9. State (`SmsAlertUiState`) survives rotation and process death via `SavedStateHandle`
(pending `challenge_id`, normalized `pendingPhone`, masked destination, client resend-cooldown
deadline); the raw input phone number and code are transient and never persisted.

FR-10. Errors are surfaced inline with stable machine-readable codes so the UI can key localized
copy. **VERIFIED codes:** `sms_code_invalid` (any confirm error), `sms_invalid_number` (`422` on
begin/remove). **UNVERIFIED/defensive codes** (not in the contract, mapped only if the dev host
emits them): `sms_resend_throttled`, `sms_target_not_found`. The draft `sms_already_verified` code
is dropped (no `409` in the contract; benign duplicates are absorbed by the refreshed
`sms_numbers`). Plus generic transport/HTTP failures.

## 4. Technical Design

Layering: `feature-settings` → `core-data` (`SmsAlertRepository`) → `core-network`
(`SmsAlertApi` Retrofit + DTOs) and `core-model` (domain results). No Retrofit/Moshi type leaks
through the repository interface.

### Domain models (`core-model`, framework-free)

> **REVIEW NOTE:** the model below was corrected to match the real contract. A configured SMS
> number is just a **string** in `AlertPreferences.sms_numbers` (no id, no `verified` flag); the
> add flow is keyed by a `challenge_id` from begin; confirm/remove return the full
> `AlertPreferences`. The original `SmsAlertTarget(id, maskedNumber, verified)` and the
> `expires_in`/`resend_available_in`/`target_id` fields were unverified draft assumptions and have
> been removed.

```kotlin
package com.testlogon.android.core.model.alerts

/**
 * A single configured SMS alert number as known to the backend.
 * CORRECTED: derived from AlertPreferences.sms_numbers (a plain string). There is no server
 * target id and no separate verified flag — presence in sms_numbers means confirmed.
 */
data class SmsAlertNumber(
    val displayNumber: String, // the server-returned string from sms_numbers; pass through verbatim
)

/**
 * Outcome of a begin (or resend = re-begin) dispatch.
 * CORRECTED: begin returns ONLY { challenge_id, sent_to }. No expires_in / resend_available_in.
 */
data class SmsAlertBeginResult(
    val challengeId: String,  // pending challenge id to use on confirm (was incorrectly target_id)
    val sentTo: String,       // server-masked destination shown to the user
)

/**
 * Outcome of a confirm. CORRECTED: confirm returns the updated AlertPreferences, so success
 * yields the refreshed number list. (200 verified=false / 409 already-verified shapes from the
 * draft are UNVERIFIED — see §16 OA-4/OA-6 — and are NOT relied on here.)
 */
data class SmsAlertConfirmResult(
    val numbers: List<SmsAlertNumber>, // refreshed sms_numbers after confirm
)
```

### Repository (`core-data`)

```kotlin
package com.testlogon.android.core.data.alerts

interface SmsAlertRepository {
    suspend fun listNumbers(): ApiResult<List<SmsAlertNumber>>           // GET sms_prefs -> sms_numbers
    suspend fun begin(rawNumber: String): ApiResult<SmsAlertBeginResult> // body { phone }
    suspend fun confirm(challengeId: String, code: String): ApiResult<SmsAlertConfirmResult> // body { challenge_id, code }
    suspend fun resend(rawNumber: String): ApiResult<SmsAlertBeginResult> // CORRECTED: re-begin by phone, NOT by id
    suspend fun remove(rawNumber: String): ApiResult<Unit>               // CORRECTED: body { phone }, NOT { target_id }
}
```

> **CORRECTED signatures:** `listTargets`→`listNumbers`; `confirm` is keyed by `challengeId`;
> `resend` and `remove` take the **phone** string (the contract has no per-target id). `resend`
> is literally a second `begin` (no `/resend` endpoint exists).

```kotlin
@Singleton
class SmsAlertRepositoryImpl @Inject constructor(
    private val api: SmsAlertApi,
    private val errorMapper: ApiErrorMapper,   // AND-015
) : SmsAlertRepository {

    override suspend fun listNumbers(): ApiResult<List<SmsAlertNumber>> =
        // CORRECTED: sms_prefs returns AlertPreferences; read sms_numbers (may be null -> empty)
        safeApiCall { api.smsPrefs() }.map { it.smsNumbers.orEmpty().map(::SmsAlertNumber) }

    override suspend fun begin(rawNumber: String): ApiResult<SmsAlertBeginResult> {
        val normalized = PhoneNormalizer.normalize(rawNumber)
        if (normalized.isBlank()) {
            return ApiResult.Failure(ApiError(0, "sms_invalid_number", "Enter a phone number"))
        }
        // CORRECTED: request body is { phone }, response is { challenge_id, sent_to }
        return safeApiCall { api.begin(AlertSmsBeginReq(phone = normalized)) }
            .map { it.toBeginResult() }
            .remapBeginCodes()           // 422 -> sms_invalid_number (only documented error)
    }

    override suspend fun confirm(challengeId: String, code: String): ApiResult<SmsAlertConfirmResult> {
        val trimmed = code.trim()
        if (trimmed.isEmpty()) {
            return ApiResult.Failure(ApiError(0, "sms_code_invalid", "Enter the code we sent you"))
        }
        // CORRECTED: body { challenge_id, code }; success returns AlertPreferences
        return safeApiCall { api.confirm(AlertSmsConfirmReq(challengeId = challengeId, code = trimmed)) }
            .map { SmsAlertConfirmResult(it.smsNumbers.orEmpty().map(::SmsAlertNumber)) }
            .remapConfirmCodes()                // see §16 OA-3/OA-4 for unverified error shapes
    }

    override suspend fun resend(rawNumber: String): ApiResult<SmsAlertBeginResult> =
        // CORRECTED: resend == re-begin by phone (no /resend endpoint, no resend DTO)
        begin(rawNumber)

    override suspend fun remove(rawNumber: String): ApiResult<Unit> =
        // CORRECTED: body { phone }; returns AlertPreferences (ignored -> Unit)
        safeApiCall { api.remove(AlertSmsRemoveReq(phone = rawNumber)) }
            .map { }
            .remapRemoveCodes()
}
```

Notes:
- `safeApiCall`, `map`, `flatMap`, `ApiResult`, `ApiError` are AND-018; `ApiErrorMapper` is
  AND-015. The `remap*` extensions are small local helpers normalizing FastAPI `detail.code`
  values into this ticket's stable taxonomy without losing `status`/`retryAfterSeconds`.
- **UNVERIFIED (kept as defensive handling):** the original draft assumed a `200` confirm body
  with `verified == false`. The real confirm success body is `AlertPreferences` (no `verified`
  field). Treat confirm success strictly by HTTP 2xx; a wrong/expired code is expected to surface
  as a 4xx (the web client treats any confirm error as "Invalid or expired code"). If the dev host
  ever returns a 200 with the number *absent* from `sms_numbers`, fail closed to
  `sms_code_invalid`. See §16 OA-4.
- `PhoneNormalizer.normalize` strips whitespace/dashes/parens, keeps a single leading `+` and
  digits; it does not validate against a region table (server authoritative).

### ViewModel + UI (`feature-settings`)

```kotlin
package com.testlogon.android.feature.settings.alerts.sms

sealed interface SmsAlertUiState {
    data object Loading : SmsAlertUiState
    data class Numbers(                          // CORRECTED: was Targets(List<SmsAlertTarget>)
        val numbers: List<SmsAlertNumber>,
        val isStale: Boolean = false,
    ) : SmsAlertUiState
    data class AddingNumber(val input: String, val error: String? = null) : SmsAlertUiState
    data class Verifying(
        val challengeId: String,        // CORRECTED: was targetId
        val pendingPhone: String,       // normalized phone, kept so "resend" can re-begin
        val sentTo: String,
        val resendInSeconds: Int,       // CLIENT-ONLY countdown (no server cooldown field; see §16 OA-5)
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
    fun onResend()                  // re-begins with the pendingPhone held in Verifying state
    fun onRemove(phone: String)     // CORRECTED: keyed by phone string, not target id
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

The resend countdown is a **purely UI** concern: **CORRECTED** — there is no server
`resend_available_in` field, so the ViewModel seeds `resendInSeconds` from a **client constant**
(e.g. 30s) and ticks it down with a coroutine `while` loop; the repository never tracks time and
the server is not consulted for the cooldown. Code entry reuses the OTP composable (AND-020); states reuse AND-021 composables.
Hilt binding: `@Binds SmsAlertRepositoryImpl -> SmsAlertRepository` in a `core-data` alerts module.

## 5. API Contract

All requests `Content-Type: application/json`. Cookies + `X-CSRF-Token` (read from the `ui_csrf`
cookie) + `Authorization: Bearer <token>` are added by interceptors (AND-011/AND-012), not this
repository. **VERIFIED** against `src/api/client.ts` (CSRF header `X-CSRF-Token` ← `ui_csrf` cookie,
`credentials: include`, Bearer from auth store, 401 → `POST /ui/session/refresh` → single retry).
The OpenAPI additionally lists `user_sub`, `X-SESSION-ID` and `X-IMPERSONATION-TOKEN` params on
these ops; impersonation is admin-only and out of scope for this user-facing flow. Errors are
folded by `safeApiCall`/AND-015.

> **REVIEW NOTE:** the OpenAPI only documents `resp=200` and `resp=422:HTTPValidationError` for all
> four ops. The specific `400`/`404`/`409`/`410`/`429` error bodies and codes below were draft
> assumptions; they are retained ONLY as defensive remap targets and are explicitly marked
> **UNVERIFIED** here and in §16. Field names/shapes for the happy paths are VERIFIED.

**List** — `GET /ui/alerts/sms_prefs` (idempotent; AND-016 retry eligible)
Success `200` → `AlertPreferences` (**VERIFIED** `types.ts: AlertPreferences`):
```json
{ "sms_event_types": ["security","billing"], "sms_numbers": ["+1•••••1234", "+44•••••789"], "...": "other channels present" }
```
→ `Success([SmsAlertNumber("+1•••••1234"), SmsAlertNumber("+44•••••789")])` (read `sms_numbers`;
absent/null ⇒ empty list). **CORRECTED:** no `targets` array, no per-number id, no `verified` flag.

**Begin** — `POST /ui/alerts/sms/begin` (non-idempotent; dispatches SMS)
Request (**VERIFIED** `AlertSmsBeginReq` requires `phone`):
```json
{ "phone": "+15551231234" }
```
Success `200` (**VERIFIED** `endpoints/alerts.ts: alertSmsBegin` resp type):
```json
{ "challenge_id": "chl_77de01", "sent_to": "+1•••••1234" }
```
→ `Success(SmsAlertBeginResult(challengeId="chl_77de01", sentTo="+1•••••1234"))`
Validation `422` (**VERIFIED** HTTPValidationError; on the `phone` body field):
```json
{ "detail": [ { "loc": ["body","phone"], "msg": "..." } ] }
```
→ `Failure(ApiError(status=422, code="sms_invalid_number", message=<msg>))`
*(No `429`/throttle is in the contract — **UNVERIFIED**; if the dev host returns it, remap to
`sms_resend_throttled`, otherwise resend is ungated server-side.)*

**Confirm** — `POST /ui/alerts/sms/confirm` (non-idempotent; consumes code)
Request (**VERIFIED** `AlertSmsConfirmReq` requires `challenge_id`, `code`):
```json
{ "challenge_id": "chl_77de01", "code": "482915" }
```
Success `200` → updated `AlertPreferences` (**VERIFIED** `alertSmsConfirm` resp = `AlertPreferences`):
```json
{ "sms_numbers": ["+1•••••1234"], "...": "..." }
```
→ `Success(SmsAlertConfirmResult(numbers=[SmsAlertNumber("+1•••••1234")]))`
Wrong/expired code: **CORRECTED/UNVERIFIED** — the contract documents only `422`; the web client
treats *any* confirm error as "Invalid or expired code" (`AlertPrefs.tsx` `onError`). Defensive
remap: any 4xx (e.g. `400`/`410`) → `Failure(code="sms_code_invalid")`; `422` body-validation →
`Failure(status=422, code="sms_code_invalid")`. The draft's `200 verified=false`,
`attempts_remaining`, and `409 alert_already_verified` shapes are **UNVERIFIED** (§16 OA-4/OA-6).

**Remove** — `POST /ui/alerts/sms/remove` (non-idempotent)
Request (**VERIFIED** `AlertSmsRemoveReq` requires `phone`): `{ "phone": "+15551231234" }`
→ Success `200` returns updated `AlertPreferences` → `Success(Unit)`. **CORRECTED:** keyed by
`phone`, not `target_id`. A `404 sms_target_not_found` is **UNVERIFIED** (contract documents only
`422`); defensive remap retained.

**Common failures:** `422` validation → `Failure(status=422)` (mapped to `sms_invalid_number` on
begin/remove `phone`, `sms_code_invalid` on confirm); `5xx`/unreachable/timeout →
`ApiResult.NetworkError(isTimeout)`. Verbs/paths/bodies **VERIFIED** against
`src/api/endpoints/alerts.ts` and the OpenAPI index/schemas (see §16).

## 6. Data & State Management

- **Read cache (last-known-good):** the `sms_prefs` list is cached to **DataStore** (per AND-078
  pattern) keyed by `user_sub` so the list renders offline as **stale** (FR-7-style banner via
  AND-021). The repository writes the cache on a successful `listNumbers()` and reads it as a
  fallback when the GET fails with a `NetworkError`. **CORRECTED:** the cache holds only the
  server-returned `sms_numbers` strings (no per-target ids, no `verified` flags exist in the
  contract) — no raw input numbers, no codes.
- **No persistence of secrets:** the raw phone number and the confirmation code are transient,
  held only on the coroutine frame and (for in-progress UI) in `SmsAlertUiState`; never written
  to Room/DataStore. The pending `challengeId`, the normalized `pendingPhone` (needed so "resend"
  can re-begin), masked `sentTo`, and the resend deadline (an
  absolute `elapsedRealtime` ms) are saved to `SavedStateHandle` so the verify screen survives
  process death and the countdown resumes correctly.
- **Optimistic removal (optional):** `onRemove` may optimistically drop the target from the
  `Targets` list and roll back on failure; the canonical list is re-fetched after a successful
  remove to reconcile.
- `SmsAlertNumber`, `SmsAlertBeginResult`, `SmsAlertConfirmResult` are immutable value types,
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
- **Wrong/expired code (CORRECTED — defensive):** the contract documents only `422` for confirm;
  the web client treats **any** confirm error as "Invalid or expired code". So normalize **any**
  confirm 4xx (and `422`) to `ApiError(code="sms_code_invalid")`. `attemptsRemaining` and the draft
  `200 verified=false` / `400 alert_invalid_code` shapes are **UNVERIFIED** (§16 OA-4) — carry
  `attemptsRemaining` only if present, never depend on it. The UI keeps the user on the code
  screen, clears the field, and does **not** abandon the pending challenge.
- **Resend throttle (UNVERIFIED):** no `429`/throttle is in the contract and there is no
  `resend_available_in` field. IF the dev host returns `429`, remap to
  `code="sms_resend_throttled"` with `retryAfterSeconds` from any `retry_after`; otherwise resend
  (= re-`begin`) is ungated server-side and the cooldown is client-only (§16 OA-5).
- **Target/number gone (UNVERIFIED):** the draft `404`/`410` → `sms_target_not_found` is NOT in the
  contract (only `422`). Retained as a defensive remap; if encountered, re-fetch the list and
  return to the numbers view. Do not assume it occurs.
- **Already verified (UNVERIFIED):** the draft `409 alert_already_verified` is NOT in the contract.
  Since confirm returns the full `AlertPreferences`, a benign duplicate is naturally handled by the
  refreshed `sms_numbers`; no special `AlreadyVerified` branch is required (§16 OA-6).
- **Invalid number (`422` on begin, VERIFIED):** the only documented begin error; mapped to
  `code="sms_invalid_number"`; shown inline under the number field, keeping the user on the add
  step.
- **401 on `/ui/alerts/*` (VERIFIED):** a session-expiry 401 triggers a single
  `POST /ui/session/refresh` + one retry — confirmed in `src/api/client.ts` (the web client does
  this for every authenticated call, not just non-MFA). Left entirely to the transport
  authenticator (AND-013); no special handling in this repository.
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
- `alert_sms_confirm` — `outcome` (`verified | rejected | failure | network_error`),
  `http_status`, `error_code`, `attempts_remaining` (only if the dev host actually returns it),
  `is_timeout`. (CORRECTED: dropped `already_verified`/`target_not_found` from the default set —
  unverified; emit only if encountered.)
- `alert_sms_remove` — `outcome` (`removed | failure | network_error`), `http_status`.
- `alert_sms_list` — `outcome` (`loaded | stale | network_error`), `number_count` (on success),
  `is_timeout`.

**Never log:** the raw number, the masked destination, the code, the `challenge_id`, cookie values,
or raw request/response bodies for these endpoints. The repository depends on no Android logging
API directly beyond the injected logger seam, keeping `core-model` framework-free.

## 11. Testing Strategy

Unit tests in `core-data/src/test` (JUnit, Truth, coroutines-test). `SmsAlertApi` is faked / a
MockK stub returning canned responses or HTTP/IO failures so this ticket tests **branching and
mapping**, with a small MockWebServer pair for request-shape.

> **REVIEW NOTE:** corrected to the real contract — `sms_numbers: string[]`, begin →
> `{challenge_id, sent_to}`, confirm/remove → `AlertPreferences`. Tests for the unverified
> `429`/`404`/`410`/`409`/`200-verified=false` shapes are kept ONLY as defensive-remap tests and
> labelled as such.

Mapping / branch tests:
- `smsPrefs` `AlertPreferences{sms_numbers:[a,b]}` → ordered `List<SmsAlertNumber>` preserving
  order; `sms_numbers` absent/null → empty list.
- `begin` success `{challenge_id, sent_to}` → `SmsAlertBeginResult(challengeId, sentTo)`.
- `begin` `422` on `phone` field → `Failure(code="sms_invalid_number", status=422)` (VERIFIED).
- `begin` `429` (defensive/unverified) → `Failure(code="sms_resend_throttled", status=429,
  retryAfterSeconds=<retry_after if present>)` — test guards the remap path only.
- `confirm` success → `SmsAlertConfirmResult(numbers from AlertPreferences.sms_numbers)`.
- `confirm` any 4xx (e.g. `400`/`422`) → `Failure(code="sms_code_invalid")`; `attemptsRemaining`
  carried only if present (defensive; the shape itself is unverified).
- `confirm` `404`/`410` (defensive) → `Failure(code="sms_target_not_found")`.
- `remove` `200` returns `AlertPreferences` → `Success(Unit)`; `remove` `404` (defensive) →
  `Failure(code="sms_target_not_found")`.
- `resend(phone)` delegates to `begin(phone)` (same request body `{phone}`, same result).
- Transport: timeout → `NetworkError(isTimeout=true)`; generic IO → `NetworkError(false)`;
  `CancellationException` re-thrown (`assertFailsWith`).

Input-guard tests:
- `confirm(id, "  ")` → `Failure(code="sms_code_invalid")` with **no** API call (fake not invoked).
- `begin(" ")` → `Failure(code="sms_invalid_number")` with **no** API call.
- `begin("+1 (555) 123-1234")` → request body `{"phone":"+15551231234"}` (CORRECTED key;
  normalized; recorded request asserted via MockWebServer).

Cache tests (`core-data`, with a fake DataStore):
- successful `listNumbers()` writes cache; subsequent `listNumbers()` on `NetworkError` returns
  cached numbers flagged stale; cache contains no raw input number/code substrings.

Security test:
- with the OkHttp logging interceptor attached, captured logs of `begin`/`confirm`/`remove`
  contain none of the raw input number, the code, the masked destination, or the `challenge_id`.

UI tests (`feature-settings/src/androidTest`, Compose test rule, fake repository):
- Add → enter number → begin success shows the code (Verifying) screen with masked destination.
- Enter correct code → confirm success → number appears in the list.
- Enter wrong code → inline "incorrect code" error, field cleared, still on verify screen.
- Resend disabled during (client) cooldown, enabled when countdown hits 0.
- Remove a number → it disappears from the list (acceptance round-trip proven).

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
  `SmsAlertRepository` + `SmsAlertNumber` and embeds the begin/confirm/remove flow.
- **Sequencing:** Land after AND-078; before AND-088. Coordinate the `sms_*` `ApiError.code`
  taxonomy with the email/push alert-channel owners (sibling E12 tickets) so AND-088 keys
  consistent localized copy across channels.

## 13. Risks & Open Questions

- **R1 — Endpoint/field names. RESOLVED (this review).** `GET /ui/alerts/sms_prefs` returns
  `AlertPreferences` with `sms_numbers: string[]` (NOT `{targets:[...]}`); `begin` returns
  `{challenge_id, sent_to}` (NOT `{target_id, sent_to, expires_in, resend_available_in}`). DTOs and
  the domain model were corrected accordingly. Source: OpenAPI schemas + `endpoints/alerts.ts`.
- **R2 — Confirm key. RESOLVED.** Confirm is keyed by **`challenge_id`** (from begin), with body
  `{challenge_id, code}` — verified in `AlertSmsConfirmReq` and `alertSmsConfirm`. Not the raw
  number, not a target id.
- **R3 — Wrong-code signalling (200 vs 4xx). PARTIALLY RESOLVED / still open on the dev host.** The
  contract documents only `422` for confirm. The web client treats *any* confirm error as "Invalid
  or expired code"; we therefore remap any confirm 4xx → `sms_code_invalid`. The exact bad-code
  status and whether `attempts_remaining` is populated remain **unverifiable from the sources** —
  confirm against the live dev host (`POST /ui/alerts/sms/confirm` with a bad code).
- **R4 — Already-verified semantics. RESOLVED (removed).** No `409 alert_already_verified` exists in
  the contract; confirm returns the full `AlertPreferences`, so a benign duplicate is absorbed by
  the refreshed `sms_numbers`. The `AlreadyVerified` branch was dropped.
- **R5 — Resend throttle source. RESOLVED (no throttle in contract).** There is NO `/resend`
  endpoint and NO `resend_available_in`/`429` in the contract — "resend" is a second
  `POST /ui/alerts/sms/begin` with the same `phone`. Any cooldown is client-only. A server `429`
  remap is retained defensively but is unverified.
- **Q1 — Number cap.** Is there a maximum number of SMS numbers per account? Not expressed in the
  contract; if the server enforces one it surfaces (likely) as a `422`. Surface a friendly limit
  message if observed (follow-up).
- **Q2 — Number use.** Out of scope here: which alert categories deliver to a confirmed SMS number
  (the `sms_event_types` array on `AlertPreferences`) is owned by AND-088 / the wider E12 prefs
  matrix.

## 14. Acceptance Criteria

1. `SmsAlertRepository` exists in `com.testlogon.android.core.data.alerts` with `listNumbers`,
   `begin`, `confirm`, `resend`, `remove`, implemented in `SmsAlertRepositoryImpl` (Hilt-bound),
   leaking only `core-model` types (no Retrofit/Moshi types in the interface).
2. Domain types `SmsAlertNumber`, `SmsAlertBeginResult(challengeId, sentTo)`, and
   `SmsAlertConfirmResult(numbers)` exist in `com.testlogon.android.core.model.alerts`. (CORRECTED:
   no `SmsAlertTarget`, no `Verified`/`AlreadyVerified` variants — the contract has no per-number id
   or `verified` flag.)
3. **Add (tested):** `begin(number)` calls `POST /ui/alerts/sms/begin` with a normalized
   `{"phone":...}` body (CORRECTED key; asserted via MockWebServer) and returns
   `SmsAlertBeginResult(challengeId, sentTo)`.
4. **Verify (tested):** `confirm(challengeId, code)` calls `POST /ui/alerts/sms/confirm` with
   `{"challenge_id","code"}` (CORRECTED keys; code trimmed); HTTP 2xx → `SmsAlertConfirmResult`
   built from the returned `AlertPreferences.sms_numbers`; any 4xx bad-code →
   `Failure(code="sms_code_invalid")`.
5. **Remove (tested):** `remove(phone)` calls `POST /ui/alerts/sms/remove` with `{"phone":...}`
   (CORRECTED key) → `Success(Unit)`; a `404` (defensive/unverified) →
   `Failure(code="sms_target_not_found")`.
6. `listNumbers()` calls `GET /ui/alerts/sms_prefs`, maps `AlertPreferences.sms_numbers` to
   `List<SmsAlertNumber>`, caches to DataStore, and returns cached numbers flagged stale on
   `NetworkError`.
7. Resend works: `resend(phone)` re-invokes `begin(phone)` (no `/resend` endpoint). `422` on begin
   `phone` → `Failure(code="sms_invalid_number")`. IF a `429` is returned (unverified) it maps to
   `Failure(code="sms_resend_throttled", retryAfterSeconds=…)`.
8. Transport/HTTP failures pass through: IO/timeout → `NetworkError`; HTTP error →
   `Failure(ApiError)`; `CancellationException` re-thrown. Blank code → `sms_code_invalid`,
   blank number → `sms_invalid_number`, both with no network call.
9. A `feature-settings` SMS-alert flow (`SmsAlertViewModel` + screens) exposes
   `StateFlow<SmsAlertUiState>`, surviving rotation/process death, and drives add→verify→remove;
   Compose UI tests prove the round-trip (add, verify, list-includes-number, remove).
10. No raw input number, code, masked destination, or `challenge_id` appears in logs (security test
    green).
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
  documented in KDoc; AND-088 is notified that `SmsAlertRepository`/`SmsAlertNumber` are frozen
  for consumption.
- No Retrofit/OkHttp/Moshi types leak through `SmsAlertRepository` (verified by signature
  inspection). No raw number/code/`challenge_id`/masked-destination logging (security test green).
- ktlint/detekt (AND-005) pass on new files; code reviewed. Risks R1–R5 and Q1–Q2 either resolved
  against `/openapi.json` / `frontend/src/api/endpoints` or filed as follow-ups before AND-088
  integration.

## 16. Citations & Assumption Audit

Each key technical claim, its VERDICT, and an exact SOURCE pointer. OpenAPI references are to
`reference/openapi.index.txt` (METHOD /path lines) and `reference/openapi.pretty.json`
(`components.schemas.<Name>`). Frontend references are to `reference/src/...`.

1. **Endpoints exist:** `POST /ui/alerts/sms/begin`, `POST /ui/alerts/sms/confirm`,
   `POST /ui/alerts/sms/remove`, `GET /ui/alerts/sms_prefs`. **Verified.** Source: OpenAPI index
   lines `POST /ui/alerts/sms/begin` (op `alert_sms_add_begin_...`), `.../confirm`, `.../remove`,
   `GET /ui/alerts/sms_prefs` (op `get_sms_prefs_...`); frontend `src/api/endpoints/alerts.ts:
   alertSmsBegin / alertSmsConfirm / alertSmsRemove / getSmsPrefs`.
2. **Begin request body is `{ phone }`** (NOT `{ number }`). **Corrected.** Source: OpenAPI
   `components.schemas.AlertSmsBeginReq` (required: `phone`); `src/api/endpoints/alerts.ts:
   alertSmsBegin` posts `{ phone }`.
3. **Begin response is `{ challenge_id, sent_to }` only** (NOT `{ target_id, sent_to, expires_in,
   resend_available_in }`). **Corrected.** Source: `src/api/endpoints/alerts.ts: alertSmsBegin`
   typed `<{ challenge_id: string; sent_to: string }>`; `src/pages/alerts/AlertPrefs.tsx`
   `setSmsPending({ challengeId: d.challenge_id, sentTo: d.sent_to })`. OpenAPI declares the 200
   body untyped (`resp=200:` empty), so the field set comes from the frontend contract.
4. **Confirm request body is `{ challenge_id, code }`** (NOT `{ target_id, code }`); **confirm
   success returns the full `AlertPreferences`** (NOT `{ verified, target }`). **Corrected.**
   Source: OpenAPI `AlertSmsConfirmReq` (required: `challenge_id`, `code`);
   `src/api/endpoints/alerts.ts: alertSmsConfirm` posts `{ challenge_id, code }` and is typed
   `<AlertPreferences>`.
5. **Remove request body is `{ phone }`** (NOT `{ target_id }`); returns `AlertPreferences`.
   **Corrected.** Source: OpenAPI `AlertSmsRemoveReq` (required: `phone`);
   `src/api/endpoints/alerts.ts: alertSmsRemove` posts `{ phone }`, typed `<AlertPreferences>`.
6. **`GET /ui/alerts/sms_prefs` returns `AlertPreferences` with `sms_numbers: string[]`** (NOT
   `{ targets: [{id, masked_number, verified}] }`; there is no per-number id and no `verified`
   flag). **Corrected.** Source: `src/api/types.ts: AlertPreferences` (`sms_event_types?`,
   `sms_numbers?`, …); `src/api/endpoints/alerts.ts: getSmsPrefs` typed `<AlertPreferences>`;
   `src/pages/alerts/AlertPrefs.tsx` `configuredSmsNumbers = smsPrefs.data?.sms_numbers ?? []`.
7. **`sms_numbers` entries are opaque server strings; whether they are masked or full E.164 is not
   determinable from the sources.** **Unverified-assumption.** Source: `types.ts: AlertPreferences`
   types them as `string[]` with no format annotation; no page reformats them. Treated as
   display-only, pass-through.
8. **No dedicated resend endpoint / no server resend cooldown.** **Verified (absence).** Source:
   OpenAPI index has no `/ui/alerts/sms/resend`; no `AlertSmsResendReq` schema; grep for
   `resend` in `src/api/endpoints/alerts.ts` returns nothing. "Resend" = re-`begin`.
9. **Auth/CSRF/transport:** cookie session (`credentials: include`), CSRF header `X-CSRF-Token`
   sourced from the `ui_csrf` cookie, plus `Authorization: Bearer <token>` from the auth store.
   **Verified.** Source: `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token",
   csrf)`; `Authorization` Bearer; `credentials: "include"`). NOTE: the spec previously omitted the
   Bearer header — added.
10. **401 handling = single `POST /ui/session/refresh` then one retry.** **Verified.** Source:
    `src/api/client.ts` (refreshSession posts `/ui/session/refresh`, then re-issues the original
    request once; logout on a second 401). Applies to all authenticated calls, not just non-MFA.
11. **OpenAPI documents only `200` and `422:HTTPValidationError` for all four ops.** **Verified.**
    Source: OpenAPI index lines for the four ops (`resp=200:;422:HTTPValidationError`). Therefore
    every non-422 error code below is an assumption (see OA-3/OA-4/OA-5/OA-6 open items).
12. **Web client treats any confirm error as "Invalid or expired code".** **Verified.** Source:
    `src/pages/alerts/AlertPrefs.tsx` `smsConfirmMut … onError: () => toast.error("Invalid or
    expired code")`. Justifies remapping any confirm 4xx → `sms_code_invalid`.
13. **Web UI gates the code field at 6 digits.** **Verified.** Source:
    `src/pages/alerts/AlertPrefs.tsx` (`disabled={smsCode.length < 6 …}`). Confirms a 6-digit OTP.
14. **Android framework choices** (Compose/Material3, Hilt+KSP, Retrofit/OkHttp/Moshi, DataStore,
    `SavedStateHandle`, MockWebServer, Robolectric, Compose UI test). **Unverified-assumption /
    framework ref** — these are platform conventions inherited from AND-078, not derivable from the
    backend/frontend sources. Framework refs: developer.android.com/jetpack/compose,
    developer.android.com/training/dependency-injection/hilt-android,
    square.github.io/retrofit, square.github.io/okhttp/features/testing (MockWebServer),
    developer.android.com/topic/libraries/architecture/datastore,
    developer.android.com/guide/fragments/saving-state (SavedStateHandle).

### Corrections made

- C1. Begin request key `number` → **`phone`** (OA-2). Affected: §1, §3 FR-2, §4 impl/DTO, §5, §11,
  §14 AC-3.
- C2. Begin response `{target_id, sent_to, expires_in, resend_available_in}` → **`{challenge_id,
  sent_to}`** (OA-3); dropped `expires_in`/`resend_available_in`. Affected: §1, §3 FR-2, §4 model,
  §5, §11, §14 AC-2.
- C3. Confirm request `{target_id, code}` → **`{challenge_id, code}`**; confirm/remove responses are
  the full **`AlertPreferences`**, not `{verified, target}` / 204 (OA-4/OA-5). Affected: §1, §3,
  §4, §5, §14 AC-4/AC-5.
- C4. Remove request `{target_id}` → **`{phone}`** (OA-5). Affected: §3 FR-5, §4, §5, §14 AC-5.
- C5. `sms_prefs` `{targets:[…]}` → **`AlertPreferences.sms_numbers: string[]`**; removed per-number
  id and `verified` flag throughout (OA-6). Affected: §1, §3 FR-1, §4 model/UI state, §5, §6 cache,
  §14 AC-2/AC-6.
- C6. Domain model `SmsAlertTarget(id, maskedNumber, verified)` → **`SmsAlertNumber(displayNumber)`**;
  `SmsAlertBeginResult` slimmed to `(challengeId, sentTo)`; `SmsAlertConfirmResult` → a data class
  carrying refreshed `numbers` (dropped `Verified`/`AlreadyVerified` sealed variants). Repository
  `listTargets`→`listNumbers`; `confirm` keyed by `challengeId`; `resend`/`remove` keyed by
  `phone`. Affected: §4, §6, §7, §10, §11, §14 AC-1/AC-2.
- C7. Resend: removed dedicated `/resend` endpoint + `SmsResendReq` + server `resend_available_in`
  cooldown; resend = re-`begin(phone)`; cooldown is client-only (OA-8). Affected: §3 FR-4, §4, §5,
  §7, §14 AC-7.
- C8. Error taxonomy: `429 sms_resend_throttled`, `404/410 sms_target_not_found`, `409
  sms_already_verified`, `200 verified=false`, `attempts_remaining` are NOT in the contract;
  demoted to **defensive/unverified** remaps and `sms_already_verified` dropped (OA-11). Affected:
  §3 FR-10, §5, §7, §10, §11.
- C9. Auth: added the missing `Authorization: Bearer` header note; confirmed `X-CSRF-Token`/`ui_csrf`
  and 401→refresh→retry (OA-9/OA-10). Affected: §5.

### Open assumptions

- OA-A. **Format of `sms_numbers` strings** (masked vs full E.164) — unverifiable; `types.ts` types
  them only as `string[]`. Risk: low (pass-through display); confirm against live dev host.
- OA-B. **Confirm bad-code status + `attempts_remaining`** — only `422` is in the contract; the
  exact 4xx and any attempt counter are unverifiable from the sources. Handled by remapping any
  confirm 4xx → `sms_code_invalid`. Confirm on the live host (R3).
- OA-C. **Server resend throttling (`429`)** — not in the contract; if it exists the remap is ready,
  but the cooldown is otherwise client-only (R5).
- OA-D. **Remove/confirm "not found" (`404`/`410`)** — not in the contract; defensive remap only.
- OA-E. **Per-account SMS-number cap** — not expressed; likely surfaces as `422` if enforced (Q1).
- OA-F. **All Android framework/library choices** — conventions from AND-078, not derivable from the
  backend/frontend sources (see citation 14). Treated as project-standard, not independently
  verified here.
- OA-G. **`X-SESSION-ID` / `user_sub` params** listed on the ops in the OpenAPI index — their exact
  population on Android is owned by the AND-011/AND-013 transport layer, not this ticket; assumed
  handled by interceptors.

## 17. Test Plan

Test targets: **JVM** = local JUnit/Robolectric (no device); **emulator** = headless AVD `test35`
(x86_64, API 35); **device** = physical Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, API
34, arm64-v8a). This ticket is data/repository + a thin Compose flow with no camera/biometric/push/
WebRTC/Telecom surface, so most cases run on JVM or emulator; physical-device runs are called out
only where ABI/API-level reality matters.

- **TC-AND-087-01 — Begin happy path + request shape.**
  Type: contract/MockWebServer (JVM).
  Target: JVM.
  Preconditions: MockWebServer enqueues `200 {"challenge_id":"chl_1","sent_to":"+1•••••1234"}`.
  Steps: call `repository.begin("+1 (555) 123-1234")`; capture the recorded request.
  Expected: request is `POST /ui/alerts/sms/begin`, body exactly `{"phone":"+15551231234"}`
  (normalized, **`phone`** key); result `Success(SmsAlertBeginResult("chl_1","+1•••••1234"))`.
  Traces: AC-3, AC-7.

- **TC-AND-087-02 — Begin validation `422` on phone.**
  Type: contract/MockWebServer (JVM).
  Target: JVM.
  Preconditions: enqueue `422 {"detail":[{"loc":["body","phone"],"msg":"invalid phone number"}]}`.
  Steps: `repository.begin("+1555")`.
  Expected: `Failure(ApiError(status=422, code="sms_invalid_number", message≈"invalid phone
  number"))`. Traces: AC-7.

- **TC-AND-087-03 — Blank-number guard (no network).**
  Type: unit (JVM).
  Target: JVM.
  Preconditions: MockK `SmsAlertApi` that fails the test if `begin` is invoked.
  Steps: `repository.begin("   ")`.
  Expected: `Failure(code="sms_invalid_number")`; **no** API call made. Traces: AC-8.

- **TC-AND-087-04 — Confirm happy path → refreshed numbers.**
  Type: contract/MockWebServer (JVM).
  Target: JVM.
  Preconditions: enqueue `200 {"sms_numbers":["+1•••••1234"]}` (an `AlertPreferences`).
  Steps: `repository.confirm("chl_1","482915")`; capture request.
  Expected: request body exactly `{"challenge_id":"chl_1","code":"482915"}` (**`challenge_id`**
  key, trimmed code); result `Success(SmsAlertConfirmResult(numbers=[SmsAlertNumber("+1•••••1234")]))`.
  Traces: AC-4.

- **TC-AND-087-05 — Confirm wrong/expired code (any 4xx → `sms_code_invalid`).**
  Type: contract/MockWebServer (JVM).
  Target: JVM.
  Preconditions: enqueue `400 {"detail":"Invalid or expired code"}` (and a parameterized variant for
  `422`).
  Steps: `repository.confirm("chl_1","000000")`.
  Expected: `Failure(code="sms_code_invalid")`; `attemptsRemaining` populated only if the body
  carries it (never required). Defensive mapping per OA-B. Traces: AC-4, AC-8.

- **TC-AND-087-06 — Blank-code guard (no network).**
  Type: unit (JVM).
  Target: JVM.
  Preconditions: MockK API that fails if `confirm` is invoked.
  Steps: `repository.confirm("chl_1","   ")`.
  Expected: `Failure(code="sms_code_invalid")`; no API call. Traces: AC-8.

- **TC-AND-087-07 — Remove happy path + request shape.**
  Type: contract/MockWebServer (JVM).
  Target: JVM.
  Preconditions: enqueue `200 {"sms_numbers":[]}`.
  Steps: `repository.remove("+15551231234")`; capture request.
  Expected: request body exactly `{"phone":"+15551231234"}` (**`phone`** key); result
  `Success(Unit)`. Traces: AC-5.

- **TC-AND-087-08 — Resend delegates to begin.**
  Type: unit (JVM).
  Target: JVM.
  Preconditions: spy/fake API recording calls; `begin` returns success.
  Steps: `repository.resend("+15551231234")`.
  Expected: exactly one `POST /ui/alerts/sms/begin` with `{"phone":"+15551231234"}` (no `/resend`
  endpoint hit); same `SmsAlertBeginResult` shape. Traces: AC-7.

- **TC-AND-087-09 — List maps `sms_numbers` + offline stale cache (flaky-host path).**
  Type: integration (JVM, fake DataStore + MockWebServer).
  Target: JVM.
  Preconditions: first response `200 {"sms_numbers":["+1•••••1234","+44•••••789"]}`; second call
  the server is made to drop/timeout (simulating the flaky dev host) → `NetworkError`.
  Steps: call `listNumbers()` twice.
  Expected: first → `Success([SmsAlertNumber("+1•••••1234"), SmsAlertNumber("+44•••••789")])`
  in order and cache written; second → cached numbers returned flagged **stale**; cache file
  contains no raw input number or code substring. Traces: AC-6.

- **TC-AND-087-10 — Transport failures + cancellation.**
  Type: unit (JVM, coroutines-test).
  Target: JVM.
  Preconditions: fake API throwing `SocketTimeoutException`, generic `IOException`, and
  `CancellationException` across parameterized runs.
  Steps: invoke `begin`/`confirm`/`remove`/`listNumbers`.
  Expected: timeout → `NetworkError(isTimeout=true)`; generic IO → `NetworkError(false)`;
  `CancellationException` rethrown (`assertFailsWith`). Traces: AC-8.

- **TC-AND-087-11 — Security: no secrets in logs.**
  Type: contract/MockWebServer (JVM) with the OkHttp logging interceptor attached.
  Target: JVM.
  Preconditions: interceptor at BASIC (or redacting `/ui/alerts/sms/*`); capture log output.
  Steps: run `begin`/`confirm`/`remove` with a known raw number, code, masked destination, and
  `challenge_id`.
  Expected: captured logs contain none of: the raw input number, the code, the masked destination,
  or the `challenge_id`. Traces: AC-10.

- **TC-AND-087-12 — Repository contract purity + Hilt DI smoke.**
  Type: integration (`@HiltAndroidTest`, Robolectric/JVM).
  Target: JVM (Robolectric) or emulator.
  Preconditions: app Hilt graph.
  Steps: resolve `SmsAlertRepository`; reflectively inspect its method signatures.
  Expected: bound to `SmsAlertRepositoryImpl`; all five methods (`listNumbers`, `begin`, `confirm`,
  `resend`, `remove`) callable; no Retrofit/OkHttp/Moshi type appears in any signature. Traces:
  AC-1, AC-2.

- **TC-AND-087-13 — Compose add→verify→list→remove round-trip + a11y.**
  Type: Compose-UI / instrumented (fake repository).
  Target: emulator (`test35`).
  Preconditions: fake repo: `begin`→`SmsAlertBeginResult("chl_1","+1•••••1234")`, `confirm`→numbers
  containing the new number, `remove`→empty.
  Steps: enter number → tap Add → Verifying screen shows masked `sent_to`; enter correct 6-digit
  code → tap Verify → number appears in the list; enter a wrong code (separate flow) → inline
  "incorrect code", field cleared, still on verify screen; tap Remove → number disappears. Assert
  TalkBack semantics: number field has a content description + `KeyboardType.Phone`; the masked
  destination and resend countdown are announced via a polite live region; touch targets ≥ 48dp.
  Expected: all transitions and accessibility semantics hold. Traces: AC-9, AC-4, AC-5.

- **TC-AND-087-14 — State survives rotation/process death; client resend cooldown.**
  Type: instrumented (fake repository).
  Target: emulator (`test35`).
  Preconditions: enter Verifying state (challengeId, pendingPhone, sentTo, resend deadline saved to
  `SavedStateHandle`).
  Steps: trigger recreation (rotation, then `StateRestorationTester` / process-death simulation);
  observe resend control; let the client countdown reach 0.
  Expected: Verifying screen restored with the same `sentTo` and a correctly-resumed countdown; raw
  number and code are NOT restored (transient); resend disabled during cooldown, enabled at 0, and
  tapping it re-invokes `begin(pendingPhone)`. Traces: AC-9, AC-7.

- **TC-AND-087-15 — ABI/API-level sanity on physical hardware.**
  Type: instrumented/e2e.
  Target: **physical device (SM-A156U, arm64-v8a, API 34)** — MUST run here, not the x86_64/API-35
  emulator, to catch arm64 Moshi/codegen or API-34-vs-35 `SavedStateHandle`/DataStore differences.
  Preconditions: app installed on the device against a mock/stub backend (no real SMS dispatched).
  Steps: run the add→verify→remove flow end-to-end on-device.
  Expected: identical behavior to the emulator run (TC-13); no arm64-only crash, no API-34
  serialization regression. Traces: AC-9, AC-11.

### Coverage matrix (section-14 AC → covering TCs)

| AC | Covered by |
|----|-----------|
| AC-1 (repository exists, core-model-only) | TC-12 |
| AC-2 (domain types) | TC-04, TC-09, TC-12 |
| AC-3 (begin `{phone}` + result) | TC-01 |
| AC-4 (confirm `{challenge_id,code}`; success/bad-code) | TC-04, TC-05, TC-13 |
| AC-5 (remove `{phone}`; not-found) | TC-07, TC-13 |
| AC-6 (list → `sms_numbers`, cache stale) | TC-09 |
| AC-7 (resend = re-begin; `422`/`429`) | TC-01, TC-02, TC-08, TC-14 |
| AC-8 (transport passthrough; blank guards) | TC-03, TC-05, TC-06, TC-10 |
| AC-9 (feature-settings flow, rotation, round-trip) | TC-13, TC-14, TC-15 |
| AC-10 (no secrets in logs) | TC-11 |
| AC-11 (Gradle suites + instrumented + lint green) | TC-13, TC-15 (and all JVM TCs run by `:core-*:test`) |
