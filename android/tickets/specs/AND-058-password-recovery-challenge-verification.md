---
id: AND-058
title: "Password recovery: challenge verification"
milestone: M2
epic: E08
priority: P1
size: M
status: draft
depends_on: [AND-057]
blocks: [AND-059]
---

# AND-058 — Password recovery: challenge verification

## 1. Overview & Goal

AND-057 owns the recovery *start* step: the user submits a username, the backend
returns a `challenge_id`, the available `required_factors`, and a delivery
medium/destination, and the UI advances to a factor-selection / code-entry
screen. AND-058 owns the *middle* step of the unauthenticated password-recovery
flow: **verifying the chosen recovery challenge factor**. This ticket implements
the begin/verify round-trips for each supported factor variant —
email, SMS, TOTP, and any backup/recovery code path — and drives the recovery
state machine from "factor selected" to "challenge passed, ready to set a new
password".

The recovery flow is **unauthenticated**: there is no logged-in session and no
`ui_csrf` cookie from a finalized session. The only shared secret binding the
steps together is the `challenge_id` minted by AND-057. The goal of AND-058 is a
correct, resilient, fully testable factor-verification layer that, on success,
hands a verified `challenge_id` (and any returned recovery token / `code`) to
AND-059, which performs `/ui/password-recovery/confirm`.

Done means: for each challenge variant, a `begin` call (where applicable) issues
the code/prompt, a `verify` call validates the user-entered code, success
advances the UI to the confirm step, and every failure mode (wrong code,
expired challenge, rate-limited, network/offline, unreliable-host timeout) is
mapped to a deterministic UI state. Each path is covered by tests.

## 2. Context & References

- **Epic E08** — Password recovery (M2).
- **Upstream AND-057** (`password-recovery-start`) — owns the Recovery screen
  scaffold, `RecoveryViewModel` creation, and `/ui/password-recovery/start`.
  AND-058 extends the *same* feature module and ViewModel rather than creating a
  parallel one.
- **Downstream AND-059** (`password-recovery-confirm-new-password`) — consumes
  the verified `challenge_id` and password-strength rules; owns
  `/ui/password-recovery/confirm`. AND-058 must NOT implement password setting.
- **Module:** `feature-auth` (recovery lives alongside login/MFA), depending on
  `core-network`, `core-model`, `core-ui`, `core-data`, `core-testing`.
- **Namespace / applicationId base:** `com.testlogon.android`.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable). OpenAPI at `/openapi.json`. FastAPI `detail`
  error shapes: `string | [{msg}] | {code,...}`.
- **Web reference:** `frontend/src/api/endpoints/*.ts` (recovery endpoint
  wrappers) and `frontend/src/api/types.ts` for the canonical request/response
  shapes; mirror field names exactly in Moshi models.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Retrofit 2.11 /
  OkHttp 4.12 / Moshi 1.15, Coroutines/Flow, DataStore. minSdk 24,
  compile/targetSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.

## 3. Functional Requirements

FR-1. Given a `challenge_id` and a selected factor from AND-057's start
response, the user can trigger a `begin` for factors that require delivery
(`email`, `sms`). TOTP and recovery-code paths skip `begin` (no code is sent;
the user already possesses the code).

FR-2. After `begin`, the UI shows the masked delivery destination (e.g.
`j•••@example.com`, `+1 ••• ••• 4321`) returned by start/begin and a code-entry
field with a numeric keyboard.

FR-3. The user enters a code and submits a `verify` for the active factor. On
HTTP 200 with a passing verification, the flow advances to the AND-059 confirm
step, passing through the (now-verified) `challenge_id` plus any
`recovery_token`/`code` echoed by the backend.

FR-4. The user can request a **resend** for `email`/`sms` (re-invokes `begin`),
gated by a client-side cooldown (default 30s) to avoid hammering the unreliable
host.

FR-5. The user can **switch factor** (return to factor selection) without
losing the `challenge_id`, provided the challenge has not expired.

FR-6. Each variant must independently pass and fail correctly:
- `POST /ui/password-recovery/challenge/email/begin` + `/email/verify`
- `POST /ui/password-recovery/challenge/sms/begin` + `/sms/verify`
- `POST /ui/password-recovery/challenge/totp/verify`
- `POST /ui/password-recovery/challenge/recovery/verify` (backup recovery code)

FR-7. Wrong/expired/rate-limited codes surface a specific inline error and keep
the user on the code-entry screen with the field cleared (wrong code) or routed
back to start (expired challenge).

FR-8. The submit button is disabled while the code is empty/too short or while a
verify request is in flight. Verification is idempotent only at the UI level
(double-tap guarded); `verify` itself is a non-idempotent POST and is **never**
auto-retried.

## 4. Technical Design

### 4.1 Layering

```
feature-auth/recovery/
  RecoveryChallengeRoute.kt        // Compose route (collects state, wires callbacks)
  RecoveryChallengeScreen.kt       // stateless Composable
  RecoveryViewModel.kt             // shared with AND-057/AND-059 (extended here)
  RecoveryUiState.kt               // sealed state incl. challenge sub-states
core-network/auth/
  PasswordRecoveryApi.kt           // Retrofit interface (extended)
  PasswordRecoveryRepository.kt    // ApiResult<T> wrapper
core-model/auth/
  RecoveryChallengeModels.kt       // Moshi DTOs
```

### 4.2 Factor model

```kotlin
enum class RecoveryFactor { EMAIL, SMS, TOTP, RECOVERY }

val RecoveryFactor.requiresBegin: Boolean
    get() = this == RecoveryFactor.EMAIL || this == RecoveryFactor.SMS

val RecoveryFactor.pathSegment: String
    get() = when (this) {
        RecoveryFactor.EMAIL -> "email"
        RecoveryFactor.SMS -> "sms"
        RecoveryFactor.TOTP -> "totp"
        RecoveryFactor.RECOVERY -> "recovery"
    }
```

### 4.3 Retrofit interface

```kotlin
interface PasswordRecoveryApi {
    // AND-057 owns: @POST("ui/password-recovery/start")

    @POST("ui/password-recovery/challenge/{factor}/begin")
    suspend fun beginChallenge(
        @Path("factor") factor: String,
        @Body body: RecoveryChallengeBeginRequest,
    ): Response<RecoveryChallengeBeginResponse>

    @POST("ui/password-recovery/challenge/{factor}/verify")
    suspend fun verifyChallenge(
        @Path("factor") factor: String,
        @Body body: RecoveryChallengeVerifyRequest,
    ): Response<RecoveryChallengeVerifyResponse>
}
```

`{factor}` is `email|sms|totp|recovery`. `totp` has no `begin` route; calling
`requiresBegin == false` short-circuits before any begin request.

### 4.4 Repository

```kotlin
class PasswordRecoveryRepository @Inject constructor(
    private val api: PasswordRecoveryApi,
    private val errorMapper: ApiErrorMapper, // maps FastAPI detail shapes
) {
    suspend fun begin(
        factor: RecoveryFactor,
        challengeId: String,
    ): ApiResult<RecoveryChallengeBeginResponse> =
        if (!factor.requiresBegin) ApiResult.Success(RecoveryChallengeBeginResponse.None)
        else safeApiCall(errorMapper) {
            api.beginChallenge(factor.pathSegment, RecoveryChallengeBeginRequest(challengeId))
        }

    suspend fun verify(
        factor: RecoveryFactor,
        challengeId: String,
        code: String,
    ): ApiResult<RecoveryChallengeVerifyResponse> =
        safeApiCall(errorMapper) {
            api.verifyChallenge(
                factor.pathSegment,
                RecoveryChallengeVerifyRequest(challengeId = challengeId, code = code.trim()),
            )
        }
}
```

`safeApiCall` returns `ApiResult.Success | ApiResult.Error(AppError)` and never
throws; `AppError` carries a typed `kind` (see §7).

### 4.5 ViewModel

```kotlin
@HiltViewModel
class RecoveryViewModel @Inject constructor(
    private val repo: PasswordRecoveryRepository,
    private val clock: Clock,
) : ViewModel() {

    private val _state = MutableStateFlow<RecoveryUiState>(RecoveryUiState.Loading)
    val state: StateFlow<RecoveryUiState> = _state.asStateFlow()

    fun selectFactor(factor: RecoveryFactor) { /* set active factor, begin if needed */ }
    fun onCodeChange(code: String) { /* update field, validate length */ }
    fun resendCode() { /* re-begin, enforce cooldown */ }
    fun verify() { /* guard in-flight; call repo.verify; on success emit Verified */ }
    fun switchFactor() { /* return to factor selection, keep challengeId */ }
}
```

### 4.6 State machine

`FactorSelect → (begin)? → CodeEntry → (verify) → Verified → [hand off to AND-059]`.
Expired challenge from any node → `RestartRequired` (route back to AND-057
start). The `challenge_id` is the single carried token across all transitions.

## 5. API Contract

Base URL `http://18.222.237.167:8000/`. All recovery endpoints are
unauthenticated POSTs with JSON bodies. No `X-CSRF-Token` is sent (no UI
session). Confirm exact shapes against `/openapi.json` and
`frontend/src/api/types.ts` before merge.

### 5.1 Begin (email / sms only)

`POST /ui/password-recovery/challenge/email/begin`
`POST /ui/password-recovery/challenge/sms/begin`

Request:
```json
{ "challenge_id": "chl_8f2a1c..." }
```

Response 200:
```json
{
  "challenge_id": "chl_8f2a1c...",
  "delivery_medium": "EMAIL",
  "destination": "j•••@example.com",
  "expires_at": "2026-06-05T18:42:00Z",
  "resend_available_in": 30
}
```

### 5.2 Verify (all factors)

`POST /ui/password-recovery/challenge/{email|sms|totp|recovery}/verify`

Request:
```json
{ "challenge_id": "chl_8f2a1c...", "code": "482913" }
```

Response 200 (passed):
```json
{
  "challenge_id": "chl_8f2a1c...",
  "verified": true,
  "next": "confirm",
  "recovery_token": "rcv_...optional..."
}
```

Response 200/4xx (failed code) — FastAPI `detail`:
```json
{ "detail": [{ "msg": "Invalid or expired code." }] }
```
or `{ "detail": { "code": "challenge_expired" } }` or a bare
`{ "detail": "Too many attempts." }`. The mapper handles all three.

Status codes consumed: 200 (verified true/false per `verified`), 400/422
(invalid code / validation), 404/410 (`challenge_expired` → `RestartRequired`),
429 (`rate_limited` → cooldown + inline message), 5xx / timeout (transient).

DTOs:
```kotlin
@JsonClass(generateAdapter = true)
data class RecoveryChallengeBeginRequest(@Json(name = "challenge_id") val challengeId: String)

@JsonClass(generateAdapter = true)
data class RecoveryChallengeBeginResponse(
    @Json(name = "challenge_id") val challengeId: String?,
    @Json(name = "delivery_medium") val deliveryMedium: String?,
    @Json(name = "destination") val destination: String?,
    @Json(name = "expires_at") val expiresAt: String?,
    @Json(name = "resend_available_in") val resendAvailableIn: Int?,
) { companion object { val None = RecoveryChallengeBeginResponse(null, null, null, null, null) } }

@JsonClass(generateAdapter = true)
data class RecoveryChallengeVerifyRequest(
    @Json(name = "challenge_id") val challengeId: String,
    @Json(name = "code") val code: String,
)

@JsonClass(generateAdapter = true)
data class RecoveryChallengeVerifyResponse(
    @Json(name = "challenge_id") val challengeId: String,
    @Json(name = "verified") val verified: Boolean,
    @Json(name = "next") val next: String?,
    @Json(name = "recovery_token") val recoveryToken: String?,
)
```

## 6. Data & State Management

### 6.1 UI state

```kotlin
sealed interface RecoveryUiState {
    data object Loading : RecoveryUiState
    data class FactorSelect(
        val challengeId: String,
        val factors: List<RecoveryFactor>,
    ) : RecoveryUiState
    data class CodeEntry(
        val challengeId: String,
        val factor: RecoveryFactor,
        val maskedDestination: String?,
        val code: String = "",
        val submitting: Boolean = false,
        val resendCooldownSec: Int = 0,
        val inlineError: String? = null,
    ) : RecoveryUiState
    data class Verified(
        val challengeId: String,
        val recoveryToken: String?,
    ) : RecoveryUiState
    data class RestartRequired(val reason: String) : RecoveryUiState
}
```

`code` length validation: numeric factors (email/sms/totp) require 6 digits;
`recovery` accepts the backend's backup-code format (length ≥ 8, alphanumeric).
Submit enabled only when length-valid and `!submitting`.

### 6.2 Persistence

The `challenge_id`, active `factor`, and `expires_at` are held in
`SavedStateHandle` so process death during code entry does not lose the
challenge. **No secrets** (entered code, `recovery_token`) are persisted to disk
or DataStore — they live only in in-memory state and `SavedStateHandle` for the
transient code string is acceptable but cleared on success/failure. The
`recovery_token` is passed in-memory to AND-059 via the nav back-stack /
ViewModel scope, never written to Room or DataStore.

### 6.3 Cooldown

`resend_available_in` (or default 30s) drives a `tickerFlow` that decrements
`resendCooldownSec` once per second on the ViewModel scope; resend is disabled
while `> 0`.

## 7. Error Handling & Resilience

```kotlin
enum class AppErrorKind {
    INVALID_CODE, CHALLENGE_EXPIRED, RATE_LIMITED,
    NETWORK_OFFLINE, TIMEOUT, SERVER, UNKNOWN
}
```

Mapping:
- `verified == false` or 400/422 → `INVALID_CODE` → inline "That code didn't
  match. Check it and try again."; clear the `code` field; stay on `CodeEntry`.
- 404/410 or `detail.code == "challenge_expired"` → `CHALLENGE_EXPIRED` →
  `RestartRequired` → route to AND-057 start with a one-line banner.
- 429 / `rate_limited` → `RATE_LIMITED` → disable submit, set
  `resendCooldownSec` from `Retry-After` (fallback 60s), inline "Too many
  attempts. Wait {n}s."
- `IOException`/no connectivity → `NETWORK_OFFLINE` → snackbar with **Retry**;
  no auto-retry (POST).
- 20s timeout (OkHttp `callTimeout = 20s`, applied to recovery client) →
  `TIMEOUT` → "The server is taking too long. Try again." with manual retry.
- 5xx → `SERVER`.

Resilience rules specific to the unreliable dev host:
- `callTimeout`/`readTimeout` = 20s; `connectTimeout` = 10s.
- **No automatic retry on `begin` or `verify`** — both mutate challenge state on
  the server (a code send and an attempt counter); auto-retry could burn the
  attempt budget or send duplicate SMS. Backoff retry is reserved for idempotent
  GETs elsewhere; not applicable here.
- Double-submit guard: `verify()` early-returns if `state.submitting`.

## 8. Security & Privacy

- Flow is unauthenticated; the `challenge_id` is the sole capability token and
  must be treated as a bearer secret in memory.
- Dev backend is plaintext HTTP (transport insecure by environment). Production
  config must use HTTPS; the network module enforces a cleartext allowlist
  scoped to the dev host only via `network_security_config.xml` — recovery
  codes/tokens must never traverse cleartext in production builds.
- Entered codes and `recovery_token` are excluded from logs (see §10), excluded
  from `toString()` of state via redaction, and never persisted to Room/DataStore.
- Code field uses `KeyboardType.NumberPassword` for numeric factors to suppress
  keyboard suggestion/learning; `recovery` uses `KeyboardType.Password`.
- Disable screenshots on the recovery code screen is optional; recommend
  `FLAG_SECURE` on the Activity window while a recovery code is on screen
  (coordinate with single-Activity owner; deferred if it conflicts with other
  screens — track as open question OQ-3).
- No user enumeration leakage: error copy for invalid code is identical
  regardless of whether the destination exists (backend already abstracts this).

## 9. Accessibility & i18n

- All strings in `feature-auth` `strings.xml`; no hardcoded copy. Keys:
  `recovery_code_title`, `recovery_code_sent_to`, `recovery_code_hint`,
  `recovery_resend`, `recovery_resend_in`, `recovery_switch_factor`,
  `recovery_error_invalid_code`, `recovery_error_expired`,
  `recovery_error_rate_limited`, `recovery_error_network`,
  `recovery_error_timeout`.
- Code field: `contentDescription` / `semantics` label; inline error wired via
  `Modifier.semantics { error(message) }` so TalkBack announces it.
- Resend cooldown announced as a live region (`liveRegion = Polite`) when it
  changes from disabled→enabled.
- Masked destination read in full to TalkBack (the mask itself is the content;
  no PII expansion).
- Touch targets ≥ 48dp; submit and resend buttons meet Material 3 minimums.
- Plurals for `recovery_resend_in` (seconds) via `<plurals>`.

## 10. Telemetry & Logging

- Events (no PII, no codes): `recovery_challenge_begin` `{factor}`,
  `recovery_challenge_verify_attempt` `{factor}`,
  `recovery_challenge_verify_result` `{factor, outcome=passed|invalid|expired|rate_limited|error}`,
  `recovery_challenge_resend` `{factor}`,
  `recovery_challenge_switch_factor` `{from, to}`.
- Logging: `Timber` at DEBUG for state transitions; request/response bodies are
  **never** logged at INFO+; OkHttp `HttpLoggingInterceptor` set to `HEADERS`
  (not `BODY`) for the recovery client, or `NONE` in release. A redacting
  interceptor strips `code` and `recovery_token` if body logging is ever
  enabled.
- Error events carry the mapped `AppErrorKind`, never raw `detail`.

## 11. Testing Strategy

Acceptance demands each challenge path passes/fails correctly (tested).

- **Repository unit tests** (`core-testing` + MockWebServer, JUnit5, Turbine):
  for each factor `{email, sms, totp, recovery}`:
  - verify success (200 `verified=true`) → `ApiResult.Success` with token.
  - verify wrong code (200 `verified=false` and 422 `detail[].msg`) →
    `AppErrorKind.INVALID_CODE`.
  - expired (410 `detail.code=challenge_expired`) → `CHALLENGE_EXPIRED`.
  - rate-limited (429 + `Retry-After`) → `RATE_LIMITED` with cooldown parsed.
  - timeout (`MockWebServer` no response / `SocketPolicy`) → `TIMEOUT`.
  - `begin` for email/sms hits the correct path; `totp`/`recovery` never call
    `begin` (verify-only) — assert request path and count.
- **ViewModel tests** (`MainDispatcherRule`, fake repo): state transitions
  FactorSelect→CodeEntry→Verified; invalid-code clears field and stays;
  expired→RestartRequired; double-tap `verify()` issues one call; resend
  cooldown ticks and gates resend.
- **Path-matrix test** parameterized over all four factors asserting the exact
  URL `ui/password-recovery/challenge/{factor}/verify` (and begin where
  applicable).
- **Compose UI tests** (`createAndroidComposeRule`): submit disabled until
  6-digit code; inline error rendered and announced; resend disabled during
  cooldown.
- **No live calls** to `18.222.237.167` in CI; MockWebServer only. One optional
  manual smoke checklist against the dev host documented in the PR.
- Coverage gate: every `AppErrorKind` branch exercised; every factor path
  exercised pass and fail.

## 12. Dependencies & Sequencing

- **Depends on AND-057** — requires the Recovery screen scaffold,
  `RecoveryViewModel`, `PasswordRecoveryApi`/`Repository` skeleton, and a valid
  `challenge_id` + `required_factors` from `/ui/password-recovery/start`. This
  ticket extends those artifacts; it does not create a second ViewModel.
- **Transitively depends on AND-030** (via AND-057) — base auth/network module
  and `ApiResult`/error-mapper plumbing.
- **Blocks AND-059** — confirm-new-password consumes the verified
  `challenge_id` and `recovery_token` produced here. The `Verified` state
  contract (`challengeId`, `recoveryToken`) is the integration surface.
- Sequence: AND-057 → **AND-058** → AND-059. Land behind the existing recovery
  nav graph; no flag needed beyond the E08 entry point gate from AND-057.

## 13. Risks & Open Questions

- **OQ-1:** Exact `verify` failure contract — does the backend return 200 with
  `verified:false`, or a 4xx with `detail`? Code handles both; confirm via
  `/openapi.json` and `frontend/src/api/endpoints` to drop the dead branch.
- **OQ-2:** Does `recovery` (backup code) use the `/challenge/recovery/verify`
  path or a distinct `/recovery` endpoint? Source scope lists both `/totp/verify`
  and `/recovery`; resolve whether `/recovery` is a sibling endpoint vs. the
  `recovery` factor segment. Default implementation treats it as the
  `recovery` factor segment; adjust if OpenAPI shows a flat `/recovery` route.
- **OQ-3:** `FLAG_SECURE` interaction with the single-Activity host (§8).
- **Risk:** Unreliable dev host causes flaky manual testing — mitigated by
  MockWebServer-only CI and explicit timeout/offline UI states.
- **Risk:** Attempt-budget exhaustion from accidental retries — mitigated by the
  no-auto-retry rule and double-submit guard.
- **Risk:** Token leakage in logs/state dumps — mitigated by redaction (§8/§10).

## 14. Acceptance Criteria

AC-1. For each factor `email`, `sms`, `totp`, `recovery`, a correct code yields
HTTP 200 `verified:true` and advances the UI to the AND-059 confirm step,
carrying the verified `challenge_id` (and `recovery_token` when present).
*(tested)*

AC-2. For each factor, an incorrect code surfaces the invalid-code inline error,
clears the field, and keeps the user on the code-entry screen. *(tested)*

AC-3. `email`/`sms` begin issues a delivery and shows the masked destination;
`totp`/`recovery` never call `begin`. *(tested — path/count assertions)*

AC-4. An expired challenge (404/410/`challenge_expired`) routes to
`RestartRequired` (back to AND-057 start) with a banner. *(tested)*

AC-5. Rate-limited (429) disables submit and shows a cooldown derived from
`Retry-After`. *(tested)*

AC-6. Network-offline and 20s-timeout each produce their distinct manual-retry
state with no automatic retry of the POST. *(tested)*

AC-7. Resend is gated by the cooldown; double-tapping submit issues exactly one
`verify` request. *(tested)*

AC-8. No code or `recovery_token` appears in logs or persisted storage; verified
by a redaction/logging test and code review.

## 15. Definition of Done

- All four challenge variants implemented (begin where applicable + verify) and
  wired into the existing `RecoveryViewModel` / nav graph from AND-057.
- Retrofit interface, Moshi DTOs, and repository merged in `core-network` /
  `core-model`, field names verified against `/openapi.json` and
  `frontend/src/api/types.ts`.
- All §14 acceptance criteria pass in CI (unit + ViewModel + Compose tests via
  MockWebServer; no live host calls).
- `Verified` state contract documented and consumed-readily by AND-059;
  integration handoff confirmed with AND-059 owner.
- All strings localized; accessibility (TalkBack error/live-region, 48dp
  targets) verified.
- Telemetry events emitted with no PII; logging interceptor scoped to
  `HEADERS`/`NONE` with redaction in place.
- Lint, detekt, and ktlint clean; no new cleartext-traffic exposure beyond the
  scoped dev-host allowlist.
- Open questions OQ-1/OQ-2 resolved or explicitly deferred with the chosen
  default documented in the PR description; reviewed and merged to
  `android-port`.
