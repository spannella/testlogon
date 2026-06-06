---
id: AND-037
title: Recovery code flow
milestone: M1
epic: E05
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-033]
blocks: []
---

# AND-037 — Recovery code flow

## 1. Overview & Goal

This ticket delivers the user-facing recovery-code path within the MFA challenge flow: a way for a user who has lost access to a primary second factor (their authenticator app, phone, or email) to satisfy an outstanding factor by redeeming a one-time backup recovery code. The work covers (a) a `useRecoveryCode(factor, code)` entry point in the MFA feature layer that wraps `MfaApiClient.useRecovery` (delivered by AND-033), (b) a Compose UI affordance — a "Use a recovery code" link surfaced on each per-factor challenge screen — and the dedicated recovery-entry screen it opens, and (c) the ViewModel state, validation, error mapping, and navigation needed to either advance the challenge (more factors remaining) or hand off to finalize when the recovery code completes authentication.

The scope is intentionally narrow. AND-037 does **not** define the `MfaApi`/DTOs (AND-033 owns the network surface), does **not** own the factor-sequencing repository that decides which factor screen to show next (shared MFA orchestration, consumed here), and does **not** own `POST /ui/session/finalize` (AND-027). It adds exactly one new flow on top of those: the recovery-code redemption affordance and screen. Success means a user on any TOTP/SMS/email challenge screen can tap "Use a recovery code," enter a valid code for that factor, and have the backend accept it — advancing or completing the challenge identically to a normal factor verification — with the path covered by an instrumented test asserting a valid recovery code passes the factor.

## 2. Context & References

- **Repo / module:** `spannella/testlogon`, branch `android-port`, app under `android/`. Code lands primarily in `:feature-auth` (`android/feature-auth/src/main/kotlin/com/testlogon/android/feature/auth/mfa/recovery/`) and consumes `:core-network` types from AND-033.
- **Stack:** Kotlin 2.0.21, Jetpack Compose + Material 3, Navigation-Compose (single-Activity), Hilt (KSP), Coroutines/Flow. minSdk 24, compileSdk/targetSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- **Upstream dependency:**
  - **AND-033** — MFA API + DTOs. Provides `MfaApiClient.useRecovery(factor: RecoveryFactor, challengeId: String, code: String): ApiResult<MfaVerifyResp>`, the `RecoveryFactor` enum (`TOTP("totp")`, `SMS("sms")`, `EMAIL("email")`), `MfaVerifyResp`, and `ApiErrorMapper` normalization. This ticket calls that client exclusively and never touches Retrofit directly.
    - **[CORRECTED — response shape]** The backend `MfaVerifyResp` is **`{ status: String, session_id: String?, required_factors: List<String>, passed: Map<String, Boolean>, remaining_factors: List<String> }`** (verified against frontend `src/api/types.ts: MfaVerifyResp` and `useRecoveryCode` usage in `src/pages/Login.tsx`). It does **not** contain `verified`, `challengeId`, or `authComplete` fields as earlier drafts of this spec assumed. **Completion is derived as `remaining_factors.isEmpty()`** — there is no `authComplete` boolean. The challenge id is **not** echoed back; this layer must reuse the `challengeId` it already holds. AND-033's `MfaVerifyResp` DTO must mirror these wire fields; if AND-033 exposes a derived `authComplete`/`verified` convenience, it must compute it from `remaining_factors`/`status`, not from a wire field.
- **Cross-cutting (assumed merged):** persistent cookie jar + `CsrfInterceptor` (AND-010/AND-021), single-`401`→refresh `Authenticator`, ~20s OkHttp timeouts, `ApiResult<T>` + `ApiError` (AND-026/AND-027), and the shared MFA challenge state (`challengeId`, ordered `requiredFactors`, current factor) produced after `POST /ui/session/start`.
- **Backend:** FastAPI + DynamoDB; dev host `http://18.222.237.167:8000` (plaintext, unreliable). Contract source: `/openapi.json`. Web reference: `frontend/src/api/endpoints/*.ts`, `frontend/src/api/types.ts`.
- **Sibling factor flows (parallel, share patterns):** AND-034 (TOTP), AND-035 (SMS), AND-036 (email). The recovery affordance is hosted on the screens those tickets build; this ticket defines the contract for that affordance (a callback/nav route) so siblings can wire it.

## 3. Functional Requirements

FR-1. Expose a feature-layer entry function `useRecoveryCode(factor: RecoveryFactor, code: String)` on `RecoveryViewModel`, delegating to `MfaApiClient.useRecovery(factor, challengeId, code)` with the active `challengeId` injected from the shared MFA challenge state (callers never pass the challenge id).

FR-2. Provide a UI affordance — a text/link button labeled "Use a recovery code" — on every per-factor challenge screen (TOTP/SMS/email). Tapping it navigates to the recovery-entry screen, passing the current `factor`.

FR-3. The recovery-entry screen presents a single masked-but-editable code field, contextual help text ("Enter one of the backup codes you saved when setting up two-factor authentication"), a primary "Verify" action, and a back affordance returning to the originating factor screen.

FR-4. Client-side validation: trim surrounding whitespace, normalize the entered code (lowercase, collapse internal spaces to the canonical hyphenated form, e.g. `AB12 CD34 EF56` → `ab12-cd34-ef56`), and disable the "Verify" action until the normalized code is non-empty and matches the expected length/charset (`^[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$`). Validation failures are surfaced inline and never call the network.

FR-5. On a `200` response, branch on **`remaining_factors.isEmpty()`** (the backend has no `authComplete` field — see Section 2 correction): if empty, emit a navigation effect to finalize (handing the satisfied challenge to AND-027's `finalize` flow); otherwise, emit a navigation effect back into the factor sequence using `remaining_factors` so the next pending factor screen is shown. The `passed` map should be applied to the shared challenge store as well.

FR-6. On error, surface a localized, user-readable message inline; the screen stays on the recovery field so the user can retry. **[UNVERIFIED — error taxonomy]** The structured error codes (`mfa_invalid_code` with `attempts_remaining`, `mfa_challenge_expired`, `mfa_resend_throttled`) are **not** declared in the OpenAPI spec (`POST /ui/mfa/recovery/{factor}` declares only `200` and `422 HTTPValidationError`) and are **not** referenced anywhere in the frontend client; the web reference treats all non-2xx error bodies as an opaque `detail` string (`src/api/client.ts: normalizeErrorDetail` / `ApiError`). Treat these codes as assumptions to confirm against AND-033 / a live backend; the mapping below is a best-effort design. When a structured `code` is present, prefer the code-specific handling; otherwise fall back to rendering the normalized `detail` string inline. `422` (the one documented error) must always be handled (FastAPI validation array → first `msg`).

FR-7. The recovery call is a single, non-idempotent attempt — no automatic retry, no backoff (it is a state-mutating POST).

FR-8. While the request is in flight the "Verify" action shows a loading state and the field is disabled, preventing double submission.

## 4. Technical Design

All new code lives under `com.testlogon.android.feature.auth.mfa.recovery`. The screen follows the project MVI-ish convention: `RecoveryViewModel` exposes `StateFlow<RecoveryUiState>` plus a one-shot `Channel`/`Flow` of `RecoveryEffect` for navigation.

**State, intent, effect:**

```kotlin
package com.testlogon.android.feature.auth.mfa.recovery

import com.testlogon.android.core.network.auth.RecoveryFactor

data class RecoveryUiState(
    val factor: RecoveryFactor,
    val code: String = "",
    val isValid: Boolean = false,
    val isSubmitting: Boolean = false,
    val error: RecoveryError? = null,
    val attemptsRemaining: Int? = null,
)

sealed interface RecoveryError {
    data class Message(val text: String) : RecoveryError          // generic localized message
    data class InvalidCode(val attemptsRemaining: Int?) : RecoveryError
    data object Throttled : RecoveryError                          // 429
    data object NetworkUnavailable : RecoveryError
}

sealed interface RecoveryEffect {
    data class AdvanceToNextFactor(val remainingFactors: List<String>, val challengeId: String) : RecoveryEffect
    data class ProceedToFinalize(val challengeId: String) : RecoveryEffect
    data object ChallengeExpired : RecoveryEffect                  // route back to credentials
}
```

**ViewModel:**

```kotlin
@HiltViewModel
class RecoveryViewModel @Inject constructor(
    private val mfaApiClient: MfaApiClient,                 // AND-033
    private val challengeStore: MfaChallengeStore,          // shared MFA state (challengeId, factors)
    private val errorPresenter: MfaErrorPresenter,          // maps ApiError.code -> string res id
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val factor: RecoveryFactor =
        RecoveryFactor.valueOf(savedStateHandle.get<String>(ARG_FACTOR)!!.uppercase())

    private val _state = MutableStateFlow(RecoveryUiState(factor = factor))
    val state: StateFlow<RecoveryUiState> = _state.asStateFlow()

    private val _effects = Channel<RecoveryEffect>(Channel.BUFFERED)
    val effects: Flow<RecoveryEffect> = _effects.receiveAsFlow()

    fun onCodeChanged(raw: String) {
        val normalized = normalizeRecoveryCode(raw)
        _state.update { it.copy(code = normalized, isValid = RECOVERY_REGEX.matches(normalized), error = null) }
    }

    fun useRecoveryCode() {
        val s = _state.value
        if (!s.isValid || s.isSubmitting) return
        val challengeId = challengeStore.current?.challengeId
            ?: run { viewModelScope.launch { _effects.send(RecoveryEffect.ChallengeExpired) }; return }
        viewModelScope.launch {
            _state.update { it.copy(isSubmitting = true, error = null) }
            when (val r = mfaApiClient.useRecovery(factor, challengeId, s.code)) {
                is ApiResult.Success -> handleVerified(r.value, challengeId)
                is ApiResult.HttpError -> handleHttpError(r.error)
                is ApiResult.NetworkError ->
                    _state.update { it.copy(isSubmitting = false, error = RecoveryError.NetworkUnavailable) }
            }
        }
    }

    private suspend fun handleVerified(resp: MfaVerifyResp, challengeId: String) {
        challengeStore.applyVerifyResult(resp)              // applies resp.passed + remaining_factors
        _state.update { it.copy(isSubmitting = false) }
        // Completion is derived from remaining_factors, NOT an authComplete flag (no such wire field).
        if (resp.remainingFactors.isEmpty()) _effects.send(RecoveryEffect.ProceedToFinalize(challengeId))
        else _effects.send(RecoveryEffect.AdvanceToNextFactor(resp.remainingFactors, challengeId))
    }

    private suspend fun handleHttpError(e: ApiError) {
        when (e.code) {
            "mfa_invalid_code" -> _state.update {
                it.copy(isSubmitting = false, attemptsRemaining = e.attemptsRemaining,
                        error = RecoveryError.InvalidCode(e.attemptsRemaining))
            }
            "mfa_challenge_expired" -> { _state.update { it.copy(isSubmitting = false) }; _effects.send(RecoveryEffect.ChallengeExpired) }
            "mfa_resend_throttled"  -> _state.update { it.copy(isSubmitting = false, error = RecoveryError.Throttled) }
            else -> _state.update { it.copy(isSubmitting = false, error = RecoveryError.Message(errorPresenter.message(e))) }
        }
    }

    companion object {
        const val ARG_FACTOR = "factor"
        val RECOVERY_REGEX = Regex("^[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$")
    }
}
```

**Normalization helper** (pure, unit-testable):

```kotlin
internal fun normalizeRecoveryCode(raw: String): String =
    raw.trim().lowercase().replace(Regex("[\\s_]+"), "-").replace(Regex("-{2,}"), "-")
```

**Affordance contract (consumed by AND-034/035/036).** Each factor screen renders:

```kotlin
@Composable
fun UseRecoveryCodeLink(onClick: () -> Unit, modifier: Modifier = Modifier) {
    TextButton(onClick = onClick, modifier = modifier.semantics { role = Role.Button }) {
        Text(stringResource(R.string.mfa_use_recovery_code))
    }
}
```

The host factor screen wires `onClick = { navController.navigate(MfaRoute.Recovery(currentFactor.name.lowercase())) }`.

**Recovery screen + navigation:**

```kotlin
@Composable
fun RecoveryRoute(
    vm: RecoveryViewModel = hiltViewModel(),
    onAdvance: (remaining: List<String>, challengeId: String) -> Unit,
    onFinalize: (challengeId: String) -> Unit,
    onChallengeExpired: () -> Unit,
    onBack: () -> Unit,
) {
    val state by vm.state.collectAsStateWithLifecycle()
    LaunchedEffect(Unit) {
        vm.effects.collect {
            when (it) {
                is RecoveryEffect.AdvanceToNextFactor -> onAdvance(it.remainingFactors, it.challengeId)
                is RecoveryEffect.ProceedToFinalize  -> onFinalize(it.challengeId)
                RecoveryEffect.ChallengeExpired      -> onChallengeExpired()
            }
        }
    }
    RecoveryScreen(state, vm::onCodeChanged, vm::useRecoveryCode, onBack)
}
```

The composable destination is added to the existing auth `NavGraphBuilder` (owned by AND-031/auth-nav): `composable("mfa/recovery/{factor}") { ... }`, with `factor` as a `navArgument` of type `StringType`. The `RecoveryViewModel` reads it from `SavedStateHandle`. No new module is introduced; this work extends `:feature-auth`.

## 5. API Contract

This ticket introduces no new endpoints; it consumes the AND-033 recovery contract.

**Recovery redemption** — `POST /ui/mfa/recovery/{factor}` (verified: OpenAPI `POST /ui/mfa/recovery/{factor}`, op `ui_recovery_factor_...`, `req=RecoveryReq`; frontend `src/api/endpoints/auth.ts: useRecoveryCode`). Session + `ui_csrf` cookies and the `X-CSRF-Token` header are attached automatically by the shared OkHttp chain (verified: `src/api/client.ts` reads the `ui_csrf` cookie and sets `X-CSRF-Token` on every request).

**[CORRECTED — `{factor}` path segment]** The OpenAPI declares `{factor}` as a free-form string param and `RecoveryReq.factor` defaults to `"totp"`. The web reference passes the literal segment **`recovery`** (its `activeMfa` value), i.e. it calls `POST /ui/mfa/recovery/recovery` with the `recovery_code` (`src/pages/Login.tsx`: `useRecoveryCode(activeMfa, …)` where `activeMfa === "recovery"`). The path segment therefore does **not** appear to scope the code to a specific challenged factor on the server. This contradicts this spec's design of passing the challenged factor (`totp|sms|email`) — see R3. Confirm with AND-033/backend which segment the server expects; if the backend ignores `{factor}` or expects `recovery`, change the call to pass a fixed `"recovery"` segment (and the affordance need not thread the current factor for the path, only for back-navigation).

**[CORRECTED — request field name]** The request body field is **`recovery_code`**, not `code` (verified: OpenAPI `components.schemas.RecoveryReq` → `{ challenge_id (req), recovery_code (req), factor (optional, default "totp") }`; frontend `src/api/types.ts: RecoveryReq` and `Login.tsx` body `{ challenge_id, recovery_code }`). This resolves R1. `RECOVERY_REGEX`/`normalizeRecoveryCode` apply to the value sent as `recovery_code`.

Request:
```json
{ "challenge_id": "chl_7af3c2e1", "recovery_code": "ab12-cd34-ef56" }
```

Response `200` (`MfaVerifyResp`) — factor satisfied, more factors pending:
```json
{ "status": "mfa_required", "session_id": null, "required_factors": ["totp","sms"], "passed": {"totp": true}, "remaining_factors": ["sms"] }
```

Response `200` (`MfaVerifyResp`) — last factor satisfied (derive completion from empty `remaining_factors`):
```json
{ "status": "ok", "session_id": null, "required_factors": ["totp"], "passed": {"totp": true}, "remaining_factors": [] }
```
**[CORRECTED — response shape]** There is no `verified`, `auth_complete`, or echoed `challenge_id` field (verified: `src/api/types.ts: MfaVerifyResp` and `Login.tsx`, which gates finalize on `resp.remaining_factors.length === 0`). The exact `status` string values (`"ok"`, `"mfa_required"`, etc.) are **unverified** — the web app keys off `remaining_factors`, so this layer should too. Note the web app, after `remaining_factors` empties, performs `sessionFinalize` itself; here AND-037 only emits `ProceedToFinalize` and AND-027 owns the finalize call.

Error bodies:
- **`422` validation (the only error documented in OpenAPI)** → FastAPI `HTTPValidationError`: `{ "detail": [{ "loc": ["body","recovery_code"], "msg": "field required", "type": "missing" }] }`. The client normalizes the array to its first `msg` (verified: `src/api/client.ts: normalizeErrorDetail`).
- **[UNVERIFIED]** `mfa_invalid_code` (+`attempts_remaining`), `mfa_challenge_expired`, `mfa_resend_throttled`/`429` structured codes — **not** declared in OpenAPI and **not** handled in the frontend (which renders `ApiError.detail` as an opaque string). Retained as a best-effort design contingent on AND-033 confirmation; if absent, all such errors fall back to the normalized `detail` string shown inline.
- `401` → handled upstream by the refresh-and-retry `Authenticator` (verified: `src/api/client.ts` refreshes via `POST /ui/session/refresh` once, then retries); a persistent failure propagates as `HttpError` and routes to `ChallengeExpired`.

Finalize (`POST /ui/session/finalize`) and `GET /ui/me` are owned by AND-027; this ticket only emits the `ProceedToFinalize` effect that hands control to that flow.

## 6. Data & State Management

- **Transient screen state:** `RecoveryUiState` held in `RecoveryViewModel.state` (`StateFlow`), recreated per screen instance. The entered code lives only in this in-memory state and the Compose `TextField`; it is never written to Room or DataStore.
- **Shared challenge state:** `MfaChallengeStore` (owned by the shared MFA orchestration consumed here) holds the active `challengeId` and ordered `requiredFactors`/`remainingFactors`. This ticket **reads** `current.challengeId` and **calls** `applyVerifyResult(resp)` to update remaining factors after a successful recovery; it does not own the store's persistence.
- **No new persistence:** no Room tables, no DataStore keys. Recovery codes are secrets and are deliberately not persisted (Section 8).
- **Process death:** `factor` survives via `SavedStateHandle` (nav arg). The in-progress `code` is intentionally **not** restored across process death — on recreation the field is empty and the user re-enters, avoiding a secret sitting in saved-instance-state. This is a deliberate trade-off documented in Section 13 (R2).
- **State transitions:** `Idle → Editing (onCodeChanged) → Submitting (useRecoveryCode) → {Success→effect | Error→Editing}`. The `isValid` flag is derived purely from `RECOVERY_REGEX.matches(code)`.

## 7. Error Handling & Resilience

- **Validation before network:** invalid-format codes never reach the network; the "Verify" action is disabled until `isValid`.
- **Single attempt:** recovery is a non-idempotent POST — exactly one network attempt, no backoff/retry (consistent with AND-033 Section 7). Retry is user-driven only.
- **Error mapping:** `ApiError.code` drives behaviour: `mfa_invalid_code` → inline error + `attemptsRemaining` (stay on screen); `mfa_challenge_expired` → `ChallengeExpired` effect (back to credentials, since the whole MFA session is dead); `mfa_resend_throttled`/`429` → `Throttled` inline message (recovery has no resend, but the backend may rate-limit attempts); any other `HttpError` → generic localized message via `MfaErrorPresenter`.
- **Network failure / timeout:** `ApiResult.NetworkError` → `RecoveryError.NetworkUnavailable` inline ("Couldn't reach the server. Check your connection and try again."), field re-enabled for retry. ~20s timeout inherited from the shared OkHttp client.
- **401:** transparently handled by the shared `Authenticator` (single refresh + retry). A surviving 401 surfaces as an `HttpError` and is treated as challenge-expired.
- **Double-submit guard:** `isSubmitting` short-circuits re-entry into `useRecoveryCode()` and disables the field/button.
- **Dev host instability:** flaky `5xx`/timeouts map to `NetworkError`-style inline retry messaging; no crash, no silent hang.

## 8. Security & Privacy

- **Codes are secrets.** The recovery code (and `challenge_id`) are never logged. OkHttp body logging for `/ui/mfa/**` remains capped at `Level.BASIC` (enforced by AND-033/network config); this ticket must not add any `Log.*`/println of the code, request body, or `challenge_id`.
- **No persistence of codes:** the code is held only in `RecoveryUiState`/the `TextField` and is dropped on navigation away and on process death (not saved to `SavedStateHandle`). No Room/DataStore writes.
- **Input field hardening:** the code field uses `KeyboardOptions(autoCorrect = false, capitalization = KeyboardCapitalization.None, keyboardType = KeyboardType.Ascii)` and disables predictive text (`IME_FLAG_NO_PERSONALIZED_LEARNING`) so codes are not retained by the keyboard/clipboard learning. The field is not a `PasswordVisualTransformation` by default (users typically read codes off paper), but visibility is a UI choice; the value is still treated as secret in logs/telemetry.
- **Cleartext in dev only:** the dev backend is plaintext HTTP, so codes traverse the wire unencrypted in dev. Release builds must reject cleartext (manifest/network-security-config, owned by the build tickets); flagged here.
- **CSRF:** the mandatory `X-CSRF-Token` header is supplied automatically; no manual handling needed in this layer.

## 9. Accessibility & i18n

- **All user-facing strings localized** in `feature-auth` `strings.xml`: `mfa_use_recovery_code` ("Use a recovery code"), `mfa_recovery_title`, `mfa_recovery_help`, `mfa_recovery_field_label`, `mfa_recovery_verify`, plus error strings (`mfa_error_invalid_recovery`, `mfa_error_invalid_recovery_attempts` with a `%d` plural via `plurals`, `mfa_error_challenge_expired`, `mfa_error_throttled`, `mfa_error_network`). No hardcoded UI text.
- **TalkBack:** the affordance has `Role.Button` and a descriptive label; the code field has `contentDescription`/label association; inline errors are exposed via `Modifier.semantics { error(text) }` and announced through `liveRegion = LiveRegionMode.Assertive` so screen-reader users hear validation/verify failures. The loading state announces "Verifying."
- **Touch targets** ≥ 48dp; the "Use a recovery code" link meets minimum target size.
- **Dynamic type / RTL:** layout uses Material 3 components and `start/end` padding, honoring font scaling and RTL.
- **Focus:** entering the recovery screen moves focus to the code field; the IME action is `Done`/`Go` wired to `useRecoveryCode()`.

## 10. Telemetry & Logging

Emit via the shared analytics façade — **no codes, no `challenge_id`, no PII**:
- `mfa_recovery_open { factor }` — affordance tapped / screen shown.
- `mfa_recovery_attempt { factor }` — verify pressed (after client validation passes).
- `mfa_recovery_result { factor, verified, auth_complete }` — on `200`.
- `mfa_recovery_error { factor, code }` — `code` is the non-secret `ApiError.code` enum (`mfa_invalid_code`, etc.) or `network`.

Logging: on error, log only the mapped `ApiError.code` and HTTP status, never the body. These events feed the auth-funnel dashboards owned by the telemetry ticket; AND-037 only emits.

## 11. Testing Strategy

Unit + ViewModel tests in `:feature-auth` (JVM, `core-testing` harness, `MfaApiClient` faked or MockWebServer-backed); one instrumented/Compose UI test for the affordance→pass path.

1. **Acceptance — valid code passes the factor (primary):** with a fake `MfaApiClient` returning `MfaVerifyResp(status="ok", remainingFactors=[], passed={...true})`, call `useRecoveryCode()` with a valid normalized code and assert a `ProceedToFinalize` effect is emitted and `challengeStore.applyVerifyResult` was invoked. A second case with `remainingFactors=["sms"]` asserts an `AdvanceToNextFactor("sms")` effect. (Completion is derived from empty `remaining_factors`, not an `authComplete` flag — see Section 5.) (Maps to source AC: "Valid recovery code passes the factor (tested).")
2. **Path/body via MockWebServer:** enqueue `200`; invoke through the real `MfaApiClient`; assert `RecordedRequest.path == /ui/mfa/recovery/<segment>` and body `{ "challenge_id": ..., "recovery_code": ... }` exactly (field is `recovery_code`, not `code`). The exact `<segment>` (`recovery` per the web reference vs the challenged factor) is the open R3 item; pin the test to whatever AND-033 finalizes.
3. **Normalization:** parametrized test for `normalizeRecoveryCode` (`"AB12 CD34 EF56"`, `"ab12_cd34_ef56"`, `" ab12-cd34-ef56 "`) all → `"ab12-cd34-ef56"`; `isValid` true only for the canonical form.
4. **Validation gate:** `useRecoveryCode()` with an invalid/empty code makes **zero** network calls and emits no effect.
5. **Error mapping:** enqueue `400 mfa_invalid_code {attempts_remaining:2}` → state `InvalidCode(2)`, stays on screen, no effect; `400 mfa_challenge_expired` → `ChallengeExpired` effect; `429` → `Throttled`; `NetworkError` → `NetworkUnavailable`.
6. **Double-submit guard:** invoking `useRecoveryCode()` twice while `isSubmitting` records exactly one request.
7. **No-secret guarantee:** assert no log/analytics payload contains the code or `challenge_id` (capture analytics events, assert keys).
8. **Compose UI test:** render a host factor screen, tap "Use a recovery code", assert navigation to the recovery destination; on the recovery screen, type a valid code, tap Verify (fake client success), assert finalize/advance callback fired; TalkBack semantics assertions for the affordance and error live-region.
9. **Coverage:** ≥85% line coverage on `RecoveryViewModel` and `normalizeRecoveryCode`.

## 12. Dependencies & Sequencing

- **Blocked by:** AND-033 (`MfaApiClient.useRecovery`, `RecoveryFactor`, `MfaVerifyResp`, `ApiErrorMapper`). Must merge first.
- **Implicit shared deps (assumed merged):** AND-026/AND-027 (`ApiResult`/`ApiError`, finalize flow), AND-031/auth-nav (the auth `NavGraph` this screen is added to), AND-010/AND-021 (cookie jar + CSRF), and the shared `MfaChallengeStore` produced by session-start. If the recovery affordance must appear on the TOTP/SMS/email screens, AND-034/035/036 host it; the affordance composable + nav route defined here let those tickets wire `onClick` without further changes. AND-037 can be built against a temporary standalone host screen if siblings lag.
- **Blocks:** none directly; it completes the MFA factor-flow set in epic E05 (M1).
- **Sequencing:** AND-033 → **AND-037** (in parallel with AND-034/035/036). Final integration of the affordance onto live factor screens happens as those sibling tickets land.
- **No new third-party dependencies** — all libraries already on the classpath.

## 13. Risks & Open Questions

- **R1 — Recovery code wire format:** **[PARTIALLY RESOLVED]** the request field name is confirmed to be **`recovery_code`** (OpenAPI `RecoveryReq`, frontend `RecoveryReq`/`Login.tsx`) — Section 5 corrected. The **code format itself remains unverified**: neither OpenAPI (`recovery_code` is a plain `string`, no pattern) nor the frontend (a free-text input with only a non-empty `.trim()` check, `Login.tsx`) constrains it to `xxxx-xxxx-xxxx`. The web app applies **no** normalization or format regex. **Risk:** the spec's strict `RECOVERY_REGEX` (`^[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$`) and lowercasing/hyphen normalization could reject server-valid codes the web client would accept. Recommend relaxing the client gate to a lenient non-empty/charset check (or making normalization opt-in) until the true format is confirmed with AND-033/backend.
- **R2 — Code not restored across process death:** deliberate (avoid secret in saved state); UX accepts re-entry. If product wants restoration, it must use `EncryptedSavedStateHandle` or similar — out of scope here.
- **R3 — `{factor}` semantics for recovery:** **[EVIDENCE FOUND]** the web reference passes the literal segment **`recovery`** (`Login.tsx`: `useRecoveryCode("recovery", …)`), and `RecoveryReq.factor` is an optional body field defaulting to `"totp"`. This strongly suggests recovery codes are **global**, not scoped to the challenged factor, and that the path segment should be a fixed `recovery` rather than `totp|sms|email`. This spec's design (passing the current factor as the segment) likely needs to change to a fixed `recovery` segment. Confirm the exact contract with AND-033/backend before implementation; the affordance still needs the current factor only for back-navigation, not for the request path.
- **R4 — Attempt throttling / lockout:** `attempts_remaining` exhaustion behaviour (hard lockout? back to credentials?) is unspecified; current design surfaces the count and lets the server reject further attempts. Confirm lockout copy/route with product.
- **R5 — Affordance placement:** whether the link appears on all three factor screens or only when recovery is configured for the account. Assumed always-shown; the server rejects with `mfa_invalid_code` if recovery is unconfigured. Confirm.

## 14. Acceptance Criteria

AC-1. A valid recovery code passes the challenged factor: submitting a correctly-formatted, server-accepted code yields a successful `MfaVerifyResp` (the challenged factor present in `passed`) and the flow advances — `ProceedToFinalize` when `remaining_factors` is empty, else `AdvanceToNextFactor(remaining_factors)` — verified by automated test. (Maps to source AC: "Valid recovery code passes the factor (tested).")

AC-2. `useRecoveryCode(factor, code)` is exposed on `RecoveryViewModel` and delegates to `MfaApiClient.useRecovery(factor, challengeId, code)`, injecting `challengeId` from shared challenge state (never passed by callers).

AC-3. A "Use a recovery code" affordance is present on the per-factor challenge screens and navigates to the recovery-entry screen carrying the current `factor`; the recovery screen renders a code field, help text, and a Verify action.

AC-4. Client validation normalizes input and disables Verify until the code matches the expected format; invalid input makes zero network calls.

AC-5. Errors map correctly: `mfa_invalid_code` shows an inline error with `attemptsRemaining` and stays on screen; `mfa_challenge_expired` routes back to credentials; `429` and network failures show retryable inline messages; the request is never auto-retried.

AC-6. No recovery code or `challenge_id` appears in logs or analytics payloads; the code is not persisted to Room/DataStore/SavedStateHandle.

AC-7. Accessibility: affordance and field have correct roles/labels, errors are announced via a live region, touch targets ≥48dp, and all strings are localized.

## 15. Definition of Done

- `RecoveryViewModel`, `RecoveryUiState`/`RecoveryError`/`RecoveryEffect`, `RecoveryScreen`/`RecoveryRoute`, `UseRecoveryCodeLink`, and `normalizeRecoveryCode` implemented under `com.testlogon.android.feature.auth.mfa.recovery`, Hilt-wired, with the nav destination registered in the auth graph.
- Affordance contract (composable + nav route) exposed so AND-034/035/036 can host it; wired onto at least the available factor screens.
- Wire format (R1/R3) verified against `/openapi.json`; `RECOVERY_REGEX` and DTO field names finalized.
- Tests from Section 11 pass with ≥85% coverage on the ViewModel and normalization; the primary "valid recovery code passes the factor" test is green; CI green.
- Secret-handling/logging constraints (Sections 8/10) implemented and asserted by test.
- All user-facing strings localized; TalkBack/a11y checks pass.
- No new dependencies; module layering preserved (`:feature-auth` → `:core-network`/`:core-*` only; no direct Retrofit use).
- KDoc on `RecoveryViewModel.useRecoveryCode` documenting the no-retry, secret-handling, and challenge-id-injection contract.
- Code reviewed and merged to `android-port`.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **Endpoint is `POST /ui/mfa/recovery/{factor}`.** — **Verified.** OpenAPI `POST /ui/mfa/recovery/{factor}` (op `ui_recovery_factor_ui_mfa_recovery__factor__post`, `req=RecoveryReq`, `params=factor`); frontend `src/api/endpoints/auth.ts: useRecoveryCode` (`api.post<MfaVerifyResp>(\`/ui/mfa/recovery/${factor}\`, body)`).
2. **HTTP method is POST.** — **Verified.** Same OpenAPI line and `api.post` in `src/api/endpoints/auth.ts: useRecoveryCode`.
3. **Request body field for the code is `recovery_code` (not `code`).** — **Corrected.** OpenAPI `components.schemas.RecoveryReq` (`recovery_code` required); frontend `src/api/types.ts: RecoveryReq` and `src/pages/Login.tsx` body `{ challenge_id, recovery_code }`. Spec originally said `code`.
4. **Request body shape is `{ challenge_id (req), recovery_code (req), factor (optional, default "totp") }`.** — **Verified.** OpenAPI `components.schemas.RecoveryReq`; frontend `src/api/types.ts: RecoveryReq`.
5. **Response is `MfaVerifyResp`.** — **Verified.** `src/api/endpoints/auth.ts: useRecoveryCode` returns `MfaVerifyResp`. (OpenAPI index lists `resp=200:` with no named schema, but the frontend types name it.)
6. **`MfaVerifyResp` shape is `{ status, session_id?, required_factors[], passed{}, remaining_factors[] }`.** — **Corrected.** `src/api/types.ts: MfaVerifyResp`. Spec originally claimed `{ verified, challengeId, remainingFactors, authComplete }` — none of `verified`/`challengeId`/`authComplete` exist.
7. **Auth completion is derived from `remaining_factors.isEmpty()`, not an `authComplete` field.** — **Corrected.** `src/pages/Login.tsx` (`if (resp.remaining_factors.length === 0) { sessionFinalize(...) }`). Spec originally branched on `MfaVerifyResp.authComplete`.
8. **Response does not echo `challenge_id`; client reuses the held id.** — **Verified.** `MfaVerifyResp` (`src/api/types.ts`) has no `challenge_id`; `Login.tsx` reuses its local `challengeId` for `sessionFinalize`.
9. **CSRF: `X-CSRF-Token` header sourced from the `ui_csrf` cookie, attached automatically.** — **Verified.** `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`).
10. **Session/auth uses cookies (`credentials: "include"`).** — **Verified.** `src/api/client.ts` (`fetch(url, { ..., credentials: "include" })`).
11. **401 → single refresh-and-retry, then propagate.** — **Verified.** `src/api/client.ts` refreshes once via `POST /ui/session/refresh` (`req=` empty, confirmed in OpenAPI index) and retries the original request a single time; a surviving 401 logs out. Matches the spec's `Authenticator` description; the spec's "routes to `ChallengeExpired` on persistent 401" is an Android-side design choice (reasonable).
12. **`POST /ui/session/finalize` exists and takes `{ challenge_id (req), remember_device (default false) }`.** — **Verified.** OpenAPI `POST /ui/session/finalize` (`req=UiSessionFinalizeReq`); `components.schemas.UiSessionFinalizeReq`; `src/pages/Login.tsx` (`sessionFinalize({ challenge_id, remember_device })`). (Owned by AND-027; cited only for the handoff.)
13. **Shared challenge state originates from `POST /ui/session/start` returning `required_factors`/`challenge_id`.** — **Verified.** OpenAPI `POST /ui/session/start` → `UiSessionStartResp` with `{ auth_required (req), challenge_id?, required_factors[], session_id? }` (`components.schemas.UiSessionStartResp`).
14. **`{factor}` path segment: web client passes `recovery` (global code), not the challenged factor.** — **Corrected / Open.** `src/pages/Login.tsx` (`useRecoveryCode(activeMfa, …)` with `activeMfa === "recovery"`); OpenAPI `RecoveryReq.factor` is optional default `"totp"`. Spec's design of passing `totp|sms|email` contradicts the reference; flagged for AND-033 confirmation (R3).
15. **Error taxonomy `mfa_invalid_code`/`mfa_challenge_expired`/`mfa_resend_throttled` with `attempts_remaining`/`retry_after`.** — **Unverified-assumption.** OpenAPI declares only `200` and `422 HTTPValidationError` for this endpoint; no MFA error codes appear in `src/api/client.ts` (the only structured codes handled are `role_*`/`helpdesk_*`/`geo_blocked`) and `Login.tsx` shows `ApiError.detail` as an opaque string. Treated as best-effort design.
16. **Error transport is FastAPI `{ "detail": ... }`, with arrays (422) normalized to the first `msg`.** — **Verified.** `src/api/client.ts: normalizeErrorDetail` (string passthrough, array→joined `msg`, object→mapped) and `ApiError { status, detail, body }`. The spec's `ApiErrorMapper`/`MfaErrorPresenter` are Android equivalents (design).
17. **Recovery code is a free-text string with no server-declared format/pattern; web app does no normalization (only `.trim()` non-empty).** — **Verified.** OpenAPI `RecoveryReq.recovery_code` is a bare `string` (no `pattern`); `src/pages/Login.tsx` enables submit on `recoveryCode.trim()` only (no regex). The spec's strict `^[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$` is **unverified** and risks over-rejecting (R1).
18. **Single, non-idempotent attempt; no auto-retry (it is a state-mutating POST).** — **Verified (consistent).** The web reference performs one POST per submit with no retry loop (`src/pages/Login.tsx`); aligns with the spec.
19. **The feature entry point name `useRecoveryCode`.** — **Verified (naming parity).** Frontend export `src/api/endpoints/auth.ts: useRecoveryCode` matches the ticket's `useRecoveryCode(factor, code)` scope item.
20. **Android framework choices (Compose + Material 3, Navigation-Compose single-Activity, Hilt+KSP, `collectAsStateWithLifecycle`, `SavedStateHandle` nav args, TalkBack semantics/live region, ≥48dp targets, `IME_FLAG_NO_PERSONALIZED_LEARNING`).** — **Unverified-assumption (framework ref).** Not derivable from backend/frontend sources; standard Android guidance: Compose state collection (framework ref: developer.android.com/jetpack/compose/state), navigation args (developer.android.com/jetpack/compose/navigation), accessibility/touch targets and live regions (developer.android.com/develop/ui/compose/accessibility), and IME personalized-learning flag (developer.android.com/reference/android/view/inputmethod/EditorInfo#IME_FLAG_NO_PERSONALIZED_LEARNING). Accepted as reasonable platform conventions.

### Corrections made

- **C1 (Sec 2, 5):** Request code field `code` → **`recovery_code`** (OpenAPI `RecoveryReq`, frontend types). Resolves R1's field-name question.
- **C2 (Sec 2, 4, 5, 6, 11, 14):** `MfaVerifyResp` shape corrected to `{ status, session_id?, required_factors[], passed{}, remaining_factors[] }`; removed nonexistent `verified`/`challengeId`/`authComplete` fields.
- **C3 (Sec 4, 5, FR-5, AC-1):** Completion now derived from `remaining_factors.isEmpty()` instead of an `authComplete` boolean; ViewModel `handleVerified` updated.
- **C4 (Sec 5, R3):** Documented that the web client uses the path segment `recovery` (global code), contradicting the per-factor segment design — flagged for confirmation.
- **C5 (Sec 5, FR-6):** Marked the structured MFA error-code taxonomy as unverified (OpenAPI only declares `200`/`422`; frontend treats errors as opaque `detail` strings); added a fallback-to-`detail`-string path and ensured `422` is always handled.
- **C6 (R1):** Flagged the strict client-side `RECOVERY_REGEX`/normalization as a risk of over-rejecting (server/web impose no format); recommended a lenient gate.

### Open assumptions

- **Recovery code format** (`xxxx-xxxx-xxxx`, charset, hyphenation, case) — unverifiable: no server pattern, web app does no normalization. Implementation should not gate stricter than the server until confirmed.
- **`{factor}` path segment value** — evidence points to a fixed `recovery`, but the authoritative backend expectation (does it read/ignore the segment? require `recovery`?) is not provable from the sources alone (R3).
- **Structured MFA error codes & fields** (`mfa_invalid_code`, `attempts_remaining`, `mfa_challenge_expired`, `mfa_resend_throttled`, `retry_after`, `429`) — not in OpenAPI or frontend; depend on AND-033/live backend. The only documented error is `422`.
- **`status` string enum values** (`"ok"` vs `"mfa_required"`, etc.) — unverified; design keys off `remaining_factors` instead, so this is non-blocking.
- **Android framework/lib behavior** — accepted via official Android docs (framework refs above), not project sources.
- **Dev backend behavior** (`http://18.222.237.167:8000` flakiness/cleartext) — environmental claim from the spec, not independently verifiable here; treated as a known dev condition.

## 17. Test Plan

Test targets: **JVM** = local JVM unit/Robolectric (no device); **emulator** = headless AVD `test35` (x86_64, API 35); **device** = physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). Most cases are JVM/MockWebServer or run fine on the emulator; the physical device is reserved for real on-device IME/keyboard-personalization, TalkBack, and arm64/API-34 confirmation.

- **TC-AND-037-01 — Happy path, last factor (finalize).** Type: unit (JVM, fake `MfaApiClient`). Target: JVM. Preconditions: `MfaChallengeStore.current.challengeId = "chl_x"`; fake returns `MfaVerifyResp(status="ok", required_factors=["totp"], passed={"totp":true}, remaining_factors=[])`. Steps: `onCodeChanged("ab12-cd34-ef56")`; `useRecoveryCode()`; collect effects. Expected: `applyVerifyResult` invoked; exactly one `ProceedToFinalize("chl_x")` effect; `isSubmitting` ends `false`; no error. Traces: AC-1, AC-2.
- **TC-AND-037-02 — Happy path, more factors remaining (advance).** Type: unit (JVM). Target: JVM. Preconditions: fake returns `remaining_factors=["sms"]`, `passed={"totp":true}`. Steps: valid code → `useRecoveryCode()`. Expected: one `AdvanceToNextFactor(remaining=["sms"], "chl_x")` effect; store updated; no `ProceedToFinalize`. Traces: AC-1.
- **TC-AND-037-03 — Contract: path + body via MockWebServer.** Type: contract/MockWebServer (JVM). Target: JVM. Preconditions: real `MfaApiClient` against MockWebServer; enqueue `200` valid `MfaVerifyResp`. Steps: invoke recovery with `challengeId="chl_x"`, code `"ab12-cd34-ef56"`. Expected: `RecordedRequest.method=="POST"`; path matches the finalized recovery segment; JSON body is exactly `{ "challenge_id": "chl_x", "recovery_code": "ab12-cd34-ef56" }` (asserts field name `recovery_code`, not `code`); `X-CSRF-Token` header present. Traces: AC-2.
- **TC-AND-037-04 — CSRF + cookies attached.** Type: contract/MockWebServer (JVM). Target: JVM. Preconditions: cookie jar seeded with session + `ui_csrf` cookies; enqueue `200`. Steps: invoke recovery. Expected: `RecordedRequest` carries the session cookie and `X-CSRF-Token` equal to the `ui_csrf` value; no header manually set by this layer. Traces: AC-2, (security) AC-6.
- **TC-AND-037-05 — Client validation gate blocks network.** Type: unit (JVM). Target: JVM. Preconditions: spy/fake `MfaApiClient`. Steps: `onCodeChanged("")` then `useRecoveryCode()`; also `onCodeChanged("zz")` (too short) then `useRecoveryCode()`. Expected: `isValid==false`; **zero** client calls; no effect emitted; inline-disabled state. (If R1 relaxation lands, update the regex under test accordingly.) Traces: AC-4.
- **TC-AND-037-06 — Normalization helper.** Type: unit (JVM, parametrized). Target: JVM. Preconditions: none. Steps: `normalizeRecoveryCode` over `"AB12 CD34 EF56"`, `"ab12_cd34_ef56"`, `" ab12-cd34-ef56 "`, `"ab12--cd34  ef56"`. Expected: all → `"ab12-cd34-ef56"`; `RECOVERY_REGEX.matches` true only for canonical form. Note: this asserts the *assumed* format (R1, unverified) — keep in sync if the gate is relaxed. Traces: AC-4.
- **TC-AND-037-07 — 422 validation error (documented error path).** Type: contract/MockWebServer (JVM). Target: JVM. Preconditions: enqueue `422` with `{ "detail": [{ "loc": ["body","recovery_code"], "msg": "field required", "type": "missing" }] }`. Steps: invoke recovery (bypassing client gate, e.g. forced). Expected: state shows an inline generic message derived from the first `msg`; stays on screen; no navigation effect; `isSubmitting==false`. Traces: AC-5.
- **TC-AND-037-08 — Assumed structured errors (invalid/expired/throttled).** Type: contract/MockWebServer (JVM). Target: JVM. Preconditions: enqueue, in turn, `mfa_invalid_code {attempts_remaining:2}`, `mfa_challenge_expired`, `429 mfa_resend_throttled`. Steps: invoke recovery for each. Expected: invalid → `RecoveryError.InvalidCode(2)`, stays on screen; expired → `ChallengeExpired` effect; throttled → `RecoveryError.Throttled`. **Because these codes are unverified (§16 #15), the test must also assert the fallback:** an unrecognized error `code`/plain `detail` string maps to `RecoveryError.Message(detail)` inline. Traces: AC-5.
- **TC-AND-037-09 — Offline / flaky dev-host network failure.** Type: contract/MockWebServer (JVM). Target: JVM. Preconditions: MockWebServer set to drop the connection / `SocketPolicy.DISCONNECT_AT_START` or enqueue `503` then timeout. Steps: invoke recovery. Expected: `ApiResult.NetworkError` → `RecoveryError.NetworkUnavailable`; field re-enabled; no crash, no hang; no navigation effect. Traces: AC-5.
- **TC-AND-037-10 — Double-submit guard.** Type: unit (JVM). Target: JVM. Preconditions: fake client suspends (controllable). Steps: valid code; call `useRecoveryCode()` twice before the first completes. Expected: exactly one client invocation / one recorded request; second call short-circuits on `isSubmitting`. Traces: AC-5.
- **TC-AND-037-11 — No-secret guarantee (logs + analytics).** Type: unit (JVM) + Robolectric log capture. Target: JVM. Preconditions: capture analytics events and any `Log.*`. Steps: run success + each error path with code `"ab12-cd34-ef56"`, `challengeId="chl_x"`. Expected: no captured log line or analytics payload value contains the code or the `challenge_id`; analytics events carry only `{factor, code(=ApiError.code|network), verified, auth_complete-derived}` keys; no Room/DataStore/`SavedStateHandle` write of the code. Traces: AC-6.
- **TC-AND-037-12 — Affordance navigation + recovery screen render (Compose-UI).** Type: Compose-UI (emulator AVD `test35`). Target: emulator. Preconditions: host factor screen with `UseRecoveryCodeLink`; test NavHost. Steps: assert link has `Role.Button` + label `mfa_use_recovery_code`; click it; assert navigation to `mfa/recovery/{factor}`; assert code field, help text, and Verify action are present; type a valid code (fake success) and tap Verify; assert advance/finalize callback fired. Expected: all assertions pass. Traces: AC-3, AC-1.
- **TC-AND-037-13 — Accessibility: roles, labels, live-region error announcement.** Type: Compose-UI / instrumented a11y (device — physical Galaxy A15 with TalkBack for real announcement behavior). Target: device. Preconditions: recovery screen; enqueue an error response. Steps: enable TalkBack; verify the affordance and field expose correct `contentDescription`/role; trigger an inline error and assert it is exposed via `semantics { error(...) }` with `liveRegion = Assertive`; verify touch targets ≥48dp and focus moves to the code field on entry. Expected: error is announced; semantics correct; targets meet size. Must run on the **physical device** for genuine TalkBack delivery (emulator TalkBack is unreliable). Traces: AC-7.
- **TC-AND-037-14 — Secret-input keyboard hardening on real IME.** Type: instrumented (device — physical Galaxy A15). Target: device. Preconditions: recovery screen focused. Steps: confirm the code field sets `autoCorrect=false`, `KeyboardCapitalization.None`, `KeyboardType.Ascii`, and `IME_FLAG_NO_PERSONALIZED_LEARNING`; type a code and verify it is not offered as a learned suggestion/clipboard candidate afterward. Expected: no predictive learning/autocorrect of the code. Requires the **physical device** because emulator soft-IMEs do not faithfully reproduce personalized-learning behavior. Traces: AC-6, AC-7.

### Coverage matrix

| Acceptance criterion (Sec 14) | Covered by |
| --- | --- |
| AC-1 (valid code passes; advance/finalize) | TC-01, TC-02, TC-12 |
| AC-2 (entry point delegates; challengeId injected; correct call) | TC-01, TC-03, TC-04 |
| AC-3 (affordance + recovery screen UI) | TC-12 |
| AC-4 (validation/normalization gates network) | TC-05, TC-06 |
| AC-5 (error mapping; no auto-retry; throttle/network) | TC-07, TC-08, TC-09, TC-10 |
| AC-6 (no secret in logs/analytics/persistence) | TC-04, TC-11, TC-14 |
| AC-7 (accessibility: roles/labels/live region/targets/localization) | TC-12, TC-13, TC-14 |
