---
id: AND-037
title: Recovery code flow
milestone: M1
epic: E05
priority: P1
size: M
status: draft
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
  - **AND-033** — MFA API + DTOs. Provides `MfaApiClient.useRecovery(factor: RecoveryFactor, challengeId: String, code: String): ApiResult<MfaVerifyResp>`, the `RecoveryFactor` enum (`TOTP("totp")`, `SMS("sms")`, `EMAIL("email")`), `MfaVerifyResp(verified, challengeId, remainingFactors, authComplete)`, and `ApiErrorMapper` normalization. This ticket calls that client exclusively and never touches Retrofit directly.
- **Cross-cutting (assumed merged):** persistent cookie jar + `CsrfInterceptor` (AND-010/AND-021), single-`401`→refresh `Authenticator`, ~20s OkHttp timeouts, `ApiResult<T>` + `ApiError` (AND-026/AND-027), and the shared MFA challenge state (`challengeId`, ordered `requiredFactors`, current factor) produced after `POST /ui/session/start`.
- **Backend:** FastAPI + DynamoDB; dev host `http://18.222.237.167:8000` (plaintext, unreliable). Contract source: `/openapi.json`. Web reference: `frontend/src/api/endpoints/*.ts`, `frontend/src/api/types.ts`.
- **Sibling factor flows (parallel, share patterns):** AND-034 (TOTP), AND-035 (SMS), AND-036 (email). The recovery affordance is hosted on the screens those tickets build; this ticket defines the contract for that affordance (a callback/nav route) so siblings can wire it.

## 3. Functional Requirements

FR-1. Expose a feature-layer entry function `useRecoveryCode(factor: RecoveryFactor, code: String)` on `RecoveryViewModel`, delegating to `MfaApiClient.useRecovery(factor, challengeId, code)` with the active `challengeId` injected from the shared MFA challenge state (callers never pass the challenge id).

FR-2. Provide a UI affordance — a text/link button labeled "Use a recovery code" — on every per-factor challenge screen (TOTP/SMS/email). Tapping it navigates to the recovery-entry screen, passing the current `factor`.

FR-3. The recovery-entry screen presents a single masked-but-editable code field, contextual help text ("Enter one of the backup codes you saved when setting up two-factor authentication"), a primary "Verify" action, and a back affordance returning to the originating factor screen.

FR-4. Client-side validation: trim surrounding whitespace, normalize the entered code (lowercase, collapse internal spaces to the canonical hyphenated form, e.g. `AB12 CD34 EF56` → `ab12-cd34-ef56`), and disable the "Verify" action until the normalized code is non-empty and matches the expected length/charset (`^[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$`). Validation failures are surfaced inline and never call the network.

FR-5. On a `200` response, branch on `MfaVerifyResp.authComplete`: if `true`, emit a navigation effect to finalize (handing the satisfied challenge to AND-027's `finalize` flow); if `false`, emit a navigation effect back into the factor sequence using `remainingFactors` so the next pending factor screen is shown.

FR-6. On error (`400 mfa_invalid_code`, `400 mfa_challenge_expired`, `422` validation, `429` throttle), surface a localized, user-readable message inline; for `mfa_invalid_code` show remaining attempts when `attemptsRemaining` is present. The screen stays on the recovery field so the user can retry (except `mfa_challenge_expired`, which routes back to credentials — see Section 7).

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
        challengeStore.applyVerifyResult(resp)              // updates remaining factors / completion
        _state.update { it.copy(isSubmitting = false) }
        if (resp.authComplete) _effects.send(RecoveryEffect.ProceedToFinalize(challengeId))
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

**Recovery redemption** — `POST /ui/mfa/recovery/{factor}` where `{factor}` ∈ `totp | sms | email`. Session + `ui_csrf` cookies and the `X-CSRF-Token` header are attached automatically by the shared OkHttp chain.

Request:
```json
{ "challenge_id": "chl_7af3c2e1", "code": "ab12-cd34-ef56" }
```

Response `200` — factor satisfied, more factors pending:
```json
{ "verified": true, "challenge_id": "chl_7af3c2e1", "remaining_factors": ["sms"], "auth_complete": false }
```

Response `200` — last factor satisfied, ready for finalize:
```json
{ "verified": true, "challenge_id": "chl_7af3c2e1", "remaining_factors": [], "auth_complete": true }
```

Error bodies (FastAPI `detail` polymorph, normalized by `ApiErrorMapper`):
- `400` invalid/used recovery code → `{ "detail": { "code": "mfa_invalid_code", "attempts_remaining": 2 } }`
- `400` expired challenge → `{ "detail": { "code": "mfa_challenge_expired" } }`
- `422` validation → `{ "detail": [{ "loc": ["body","code"], "msg": "field required", "type": "value_error.missing" }] }`
- `429` throttled → `{ "detail": { "code": "mfa_resend_throttled", "retry_after": 22 } }`
- `401` → handled upstream by the refresh-and-retry `Authenticator`; a persistent failure propagates as `HttpError` and routes to `ChallengeExpired`.

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

1. **Acceptance — valid code passes the factor (primary):** with a fake `MfaApiClient` returning `MfaVerifyResp(verified=true, remainingFactors=[], authComplete=true)`, call `useRecoveryCode()` with a valid normalized code and assert a `ProceedToFinalize` effect is emitted and `challengeStore.applyVerifyResult` was invoked. A second case with `remainingFactors=["sms"], authComplete=false` asserts an `AdvanceToNextFactor("sms")` effect. (Maps to source AC: "Valid recovery code passes the factor (tested).")
2. **Path/body via MockWebServer:** enqueue `200`; invoke through the real `MfaApiClient`; assert `RecordedRequest.path == /ui/mfa/recovery/totp` (for `RecoveryFactor.TOTP`) and body `{challenge_id, code}` exactly.
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

- **R1 — Recovery code wire format:** the canonical format (`xxxx-xxxx-xxxx`, base32-ish) and the request field name (`code` vs `recovery_code`) are reconstructed from the AND-033 contract; confirm against `/openapi.json` and `frontend/src/api/endpoints`. If the field is `recovery_code` or codes are unhyphenated, adjust `RECOVERY_REGEX`/`normalizeRecoveryCode` and the AND-033 DTO accordingly. The regex/validation must not be stricter than the server or valid codes will be blocked client-side — keep the gate lenient (length/charset) if the format is uncertain.
- **R2 — Code not restored across process death:** deliberate (avoid secret in saved state); UX accepts re-entry. If product wants restoration, it must use `EncryptedSavedStateHandle` or similar — out of scope here.
- **R3 — `{factor}` semantics for recovery:** does the backend require the recovery code be scoped to the currently-challenged factor, or is a single recovery code global (any `{factor}` accepts it)? Current design passes the current factor as the path segment. Confirm; if global, pass a canonical factor or a dedicated `recovery` segment.
- **R4 — Attempt throttling / lockout:** `attempts_remaining` exhaustion behaviour (hard lockout? back to credentials?) is unspecified; current design surfaces the count and lets the server reject further attempts. Confirm lockout copy/route with product.
- **R5 — Affordance placement:** whether the link appears on all three factor screens or only when recovery is configured for the account. Assumed always-shown; the server rejects with `mfa_invalid_code` if recovery is unconfigured. Confirm.

## 14. Acceptance Criteria

AC-1. A valid recovery code passes the challenged factor: submitting a correctly-formatted, server-accepted code yields `MfaVerifyResp.verified == true` and the flow advances — `ProceedToFinalize` when `authComplete`, else `AdvanceToNextFactor(remainingFactors)` — verified by automated test. (Maps to source AC: "Valid recovery code passes the factor (tested).")

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
