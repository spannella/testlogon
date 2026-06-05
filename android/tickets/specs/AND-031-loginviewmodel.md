---
id: AND-031
title: LoginViewModel
milestone: M1
epic: E04
priority: P0
size: M
status: draft
depends_on: [AND-028, AND-030]
blocks: [AND-034, AND-035, AND-036]
---

# AND-031 — LoginViewModel

## 1. Overview & Goal

`LoginViewModel` is the presentation-layer orchestrator for the email/password login
screen. It owns a single `StateFlow<LoginUiState>`, exposes intent-style entry points
for the Compose screen (AND-030), drives the credential submission through
`AuthRepository.login(...)` (AND-028), and maps the typed repository result into a
one-shot navigation effect: either *MFA required* (continue the challenge in the MFA
feature, E05) or *authenticated* (route to home). It is also responsible for the
loading/disabled lifecycle of the submit control and for surfacing typed,
human-readable errors without leaking transport details.

The goal of this ticket is the ViewModel only: state shape, intent handlers, the
result→navigation/error mapping, and exhaustive unit-test coverage of the state
machine. The screen composable, the repository, the API DTOs, and the MFA verify
flows are owned by adjacent tickets and are consumed — not implemented — here.

Module: `feature-auth` (depends on `core-data` for `AuthRepository`, `core-model`
for typed results, `core-ui` for `UiText`). Package:
`com.testlogon.android.feature.auth.login`.

## 2. Context & References

- **AND-028** `AuthRepository: session start + branching` — provides
  `suspend fun login(username, password): ApiResult<LoginResult>` where
  `LoginResult` is `Authenticated` or `MfaRequired(challengeId, factors)`. This is
  the sole collaborator the ViewModel calls.
- **AND-030** `Login screen UI` — the Compose screen that renders `LoginUiState`,
  forwards text edits and the submit click as intents, and consumes the navigation
  effect. Field-level validation (non-empty, email shape) lives partly in the UI;
  the ViewModel enforces the canonical gate for `submitEnabled`.
- **AND-029** `getMe + auth state store` — after `Authenticated`, the auth-state
  store is hydrated. The ViewModel does *not* call `getMe()` itself; it emits the
  `NavigateHome` effect and lets the post-login coordinator / `RootViewModel`
  refresh `me`. (If sequencing changes, see Open Questions §13.)
- **AND-033..036** MFA flows — downstream consumers of the `NavigateToMfa`
  effect; this ticket only hands them `challengeId` + `factors`.
- Backend session start: `POST /ui/session/start` with
  `{challenge_context:{username,password}}` → `{auth_required, challenge_id,
  required_factors[]}`. Cookie + `ui_csrf`/`X-CSRF-Token` handling is internal to
  `core-network` and `AuthRepository`; the ViewModel is transport-agnostic.
- Web reference: `frontend/src/api/endpoints/session.ts` (login submit + branch),
  `frontend/src/api/types.ts` (`SessionStartResponse`).

## 3. Functional Requirements

FR-1. Expose immutable UI state as `val uiState: StateFlow<LoginUiState>` seeded
with `LoginUiState()` (empty, idle, submit disabled).

FR-2. Accept user input intents that update field values and clear any transient
error: `onUsernameChange(String)`, `onPasswordChange(String)`,
`onTogglePasswordVisibility()`.

FR-3. Compute `submitEnabled` reactively: true iff `username` is non-blank, a
syntactically plausible email, `password` is non-blank, and `status != Submitting`.

FR-4. `onSubmit()` is idempotent while a request is in flight — a second call while
`status == Submitting` is a no-op (debounce double-tap).

FR-5. On submit: set `status = Submitting` (disables submit, shows progress), clear
prior `error`, then call `AuthRepository.login(username.trim(), password)`.

FR-6. Map `ApiResult.Success(LoginResult.MfaRequired)` → emit a one-shot
`LoginEffect.NavigateToMfa(challengeId, factors)` and return `status` to `Idle`.

FR-7. Map `ApiResult.Success(LoginResult.Authenticated)` → emit one-shot
`LoginEffect.NavigateHome`; keep `status = Submitting` until the screen is torn down
(prevents a re-enabled button flashing during navigation), or reset to `Idle` if the
effect is buffered — see §6.

FR-8. Map `ApiResult.Failure` → set `status = Idle` and `error = UiText` derived from
the typed error (invalid credentials, network/timeout, server). Submit re-enables so
the user can retry.

FR-9. `onErrorShown()` clears `error` after the screen consumes it (e.g. snackbar).

FR-10. Navigation is delivered as effects, never as state, so config changes /
recomposition cannot replay a navigation.

## 4. Technical Design

```kotlin
package com.testlogon.android.feature.auth.login

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.auth.LoginResult
import com.testlogon.android.core.model.auth.MfaFactor
import com.testlogon.android.core.data.auth.AuthRepository
import com.testlogon.android.core.ui.text.UiText
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class LoginViewModel @Inject constructor(
    private val authRepository: AuthRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(LoginUiState())
    val uiState: StateFlow<LoginUiState> = _uiState.asStateFlow()

    // One-shot navigation/effects. extraBufferCapacity guarantees non-suspending tryEmit.
    private val _effects = MutableSharedFlow<LoginEffect>(
        replay = 0,
        extraBufferCapacity = 1,
        onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )
    val effects: SharedFlow<LoginEffect> = _effects.asSharedFlow()

    fun onUsernameChange(value: String) = _uiState.update {
        it.copy(username = value, error = null)
    }

    fun onPasswordChange(value: String) = _uiState.update {
        it.copy(password = value, error = null)
    }

    fun onTogglePasswordVisibility() = _uiState.update {
        it.copy(passwordVisible = !it.passwordVisible)
    }

    fun onErrorShown() = _uiState.update { it.copy(error = null) }

    fun onSubmit() {
        val snapshot = _uiState.value
        if (snapshot.status == LoginStatus.Submitting || !snapshot.submitEnabled) return
        _uiState.update { it.copy(status = LoginStatus.Submitting, error = null) }
        viewModelScope.launch {
            when (val result = authRepository.login(snapshot.username.trim(), snapshot.password)) {
                is ApiResult.Success -> handleSuccess(result.data)
                is ApiResult.Failure -> _uiState.update {
                    it.copy(status = LoginStatus.Idle, error = result.error.toLoginUiText())
                }
            }
        }
    }

    private fun handleSuccess(result: LoginResult) = when (result) {
        is LoginResult.MfaRequired -> {
            _uiState.update { it.copy(status = LoginStatus.Idle) }
            _effects.tryEmit(LoginEffect.NavigateToMfa(result.challengeId, result.factors))
        }
        LoginResult.Authenticated -> {
            // Keep Submitting so the button stays disabled through the nav transition.
            _effects.tryEmit(LoginEffect.NavigateHome)
        }
    }
}
```

Design notes:

- **Single source of truth.** All visible state is `LoginUiState`; `submitEnabled` is
  a *derived* property computed inside the data class so the ViewModel never stores a
  stale flag.
- **Effects over state for navigation.** `MutableSharedFlow(replay=0)` with a 1-slot
  buffer lets the screen collect effects in a lifecycle-aware `repeatOnLifecycle`
  block without replaying on rotation. `tryEmit` is non-suspending and safe because
  buffer + `DROP_OLDEST` guarantee it never returns false for our single-effect
  cadence.
- **No threading concerns in the ViewModel.** `AuthRepository.login` is `suspend`
  and switches to `Dispatchers.IO` internally (core-data convention); the ViewModel
  stays on the main dispatcher via `viewModelScope`.
- **Validation source of truth.** Email-shape validation uses
  `android.util.Patterns.EMAIL_ADDRESS` wrapped behind a `pure` Kotlin predicate in
  `core-ui` (`EmailValidator.isPlausible(String): Boolean`) so it is unit-testable on
  the JVM without Robolectric. The data class calls that predicate.

## 5. API Contract

No new endpoint is defined or called directly by this ticket. The ViewModel invokes
`AuthRepository.login(...)` (AND-028), which owns the
`POST /ui/session/start` call. For reference, the repository consumes:

Request body:
```json
{ "challenge_context": { "username": "user@example.com", "password": "•••••" } }
```

Response (200) mapped by AND-028 into `LoginResult`:
```json
{ "auth_required": true, "challenge_id": "chl_7f3a…", "required_factors": ["totp", "sms"] }
```
- `auth_required == false` (or no factors) → `LoginResult.Authenticated`.
- `auth_required == true` with `required_factors` → `LoginResult.MfaRequired`.

The ViewModel depends only on these `core-model` shapes (defined by AND-028):
```kotlin
sealed interface LoginResult {
    data object Authenticated : LoginResult
    data class MfaRequired(val challengeId: String, val factors: List<MfaFactor>) : LoginResult
}
enum class MfaFactor { TOTP, SMS, EMAIL, RECOVERY }
```
Endpoint/DTO ownership: `POST /ui/session/start` → AND-028; MFA endpoints
(`/ui/mfa/{totp|sms|email}/begin|verify`) → AND-033.

## 6. Data & State Management

```kotlin
data class LoginUiState(
    val username: String = "",
    val password: String = "",
    val passwordVisible: Boolean = false,
    val status: LoginStatus = LoginStatus.Idle,
    val error: UiText? = null,
) {
    val isSubmitting: Boolean get() = status == LoginStatus.Submitting
    val submitEnabled: Boolean
        get() = status != LoginStatus.Submitting &&
            username.isNotBlank() &&
            EmailValidator.isPlausible(username.trim()) &&
            password.isNotBlank()
}

enum class LoginStatus { Idle, Submitting }

sealed interface LoginEffect {
    data class NavigateToMfa(val challengeId: String, val factors: List<MfaFactor>) : LoginEffect
    data object NavigateHome : LoginEffect
}
```

State management rules:

- `_uiState` is updated only via `MutableStateFlow.update { }` to avoid lost-update
  races between input intents and the submit coroutine.
- **No persistence.** Login inputs are deliberately *not* written to
  `SavedStateHandle` or DataStore — passwords must never be persisted. On process
  death the form resets to empty; this is acceptable and intentional (see §8). The
  authenticated session itself is persisted by the cookie jar + DataStore auth store
  (AND-029), not here.
- **Effect collection.** The screen collects `effects` inside
  `viewLifecycleOwner.repeatOnLifecycle(STARTED)`; when paused it stops collecting and
  the buffered effect (if any) is delivered on resume. Because a successful login is
  terminal for this screen, at most one navigation effect is ever in flight.
- The `Authenticated` path leaves `status = Submitting`; the screen is removed from
  back-stack on `NavigateHome`, so the disabled button never reappears. If the nav
  graph keeps the screen alive, the destination's `LaunchedEffect` calls a `reset()`
  intent (covered by §13 open question).

## 7. Error Handling & Resilience

The ViewModel maps `ApiResult.Failure` (typed by `core-network`'s FastAPI `detail`
mapper: `string | [{msg}] | {code,...}`) into `UiText` via an extension:

```kotlin
private fun ApiResult.Failure.toLoginUiText(): UiText = when (val e = error) {
    is ApiError.Unauthorized      -> UiText.Res(R.string.login_error_invalid_credentials)
    is ApiError.Validation        -> UiText.Dynamic(e.firstMessage)               // [{msg}]
    is ApiError.Network,
    is ApiError.Timeout           -> UiText.Res(R.string.login_error_network)
    is ApiError.Server            -> UiText.Res(R.string.login_error_server)
    is ApiError.Unknown           -> UiText.Res(R.string.login_error_generic)
}
```

Resilience:

- **Timeouts.** The dev backend (`http://18.222.237.167:8000`) is plaintext and
  unreliable; OkHttp call timeout (~20s) is configured in `core-network` (AND-018).
  A timeout surfaces as `ApiError.Timeout` → network message, submit re-enabled.
- **No automatic retry.** `POST /ui/session/start` is non-idempotent; the bounded
  backoff retry policy applies only to idempotent GETs. The ViewModel therefore
  performs exactly one attempt per `onSubmit()` and relies on the user to retry.
- **401 refresh** is handled by the OkHttp authenticator in `core-network` (single
  `POST /ui/session/refresh` then retry). On a fresh login there is no session yet,
  so an `Unauthorized` here means genuinely bad credentials, surfaced as such.
- **Double-submit guard** (FR-4) prevents duplicate session-start calls on rapid
  taps.
- **Cancellation.** A pending login is cancelled automatically when `viewModelScope`
  is cleared; no manual `Job` tracking is required.

## 8. Security & Privacy

- The `password` field lives only in in-memory `LoginUiState`; it is never logged,
  never written to `SavedStateHandle`, DataStore, Room, or crash reports.
- Logging must redact credentials: the submit log line records only
  `username.length`/domain and never the password or full email at non-debug levels.
- `toString()` of `LoginUiState` is overridden (or `password` excluded) so accidental
  state logging cannot leak the secret.
- Compose `TextField` for password uses `PasswordVisualTransformation`; the
  `passwordVisible` toggle is UI-only and does not change what is stored.
- The session cookie + `ui_csrf` are managed by the persistent cookie jar in
  `core-network`; the ViewModel holds no tokens.
- No PII is emitted in telemetry beyond a hashed/length-only username (§10).

## 9. Accessibility & i18n

- The ViewModel emits all user-facing strings as `UiText` (string-resource or
  validated-dynamic), never hard-coded English, so the screen resolves them with the
  current locale. Error keys: `login_error_invalid_credentials`,
  `login_error_network`, `login_error_server`, `login_error_generic`.
- `submitEnabled` / `isSubmitting` drive the screen's content description and
  `Modifier.semantics { disabled() }` state for TalkBack (implemented in AND-030);
  the ViewModel guarantees these flags are always consistent so assistive tech reads
  the correct enabled/busy state.
- Errors are surfaced as state (`error: UiText?`) rather than transient toasts so a
  screen reader can announce them via `liveRegion`.
- No locale-specific parsing of credentials; `username.trim()` removes only
  surrounding whitespace.

## 10. Telemetry & Logging

Events emitted via the `core-data` analytics abstraction (no PII):

| Event | When | Properties |
|-------|------|-----------|
| `login_submit` | `onSubmit()` accepted | `username_domain`, `username_len` |
| `login_mfa_required` | `MfaRequired` mapped | `factor_count`, `factors` (enum names) |
| `login_success` | `Authenticated` mapped | — |
| `login_failure` | `ApiResult.Failure` | `error_type` (enum), `http_status?` |

- Debug `Timber` logs at `onSubmit`/result with redacted username; release builds
  strip verbose logs. No password, no `challenge_id` value in analytics (only
  factor metadata) to avoid correlating a challenge across systems.

## 11. Testing Strategy

Pure-JVM unit tests (no Robolectric) under
`feature-auth/src/test/.../login/LoginViewModelTest.kt`, using
`kotlinx-coroutines-test` (`StandardTestDispatcher` + `Turbine` for flows) and a fake
`AuthRepository` from `core-testing`.

```kotlin
class FakeAuthRepository(var loginResult: ApiResult<LoginResult>) : AuthRepository {
    var calls = 0
    override suspend fun login(username: String, password: String): ApiResult<LoginResult> {
        calls++; return loginResult
    }
}
```

Required cases (each asserts state transitions and/or emitted effect):

1. Initial state is empty, `Idle`, `submitEnabled == false`.
2. `onUsernameChange` + `onPasswordChange` with valid email/non-blank → `submitEnabled == true`.
3. Invalid email (`"foo"`) keeps `submitEnabled == false`.
4. Blank password keeps `submitEnabled == false`.
5. `onSubmit` sets `status == Submitting` and `submitEnabled == false` while in flight.
6. Success `Authenticated` → emits `NavigateHome` and `error == null`.
7. Success `MfaRequired` → emits `NavigateToMfa(challengeId, factors)`, `status` back to `Idle`.
8. Failure `Unauthorized` → `status == Idle`, `error == invalid_credentials`, submit re-enabled.
9. Failure `Timeout`/`Network` → network error mapped.
10. Failure `Validation` (`[{msg}]`) → `UiText.Dynamic(firstMsg)`.
11. Double `onSubmit` while `Submitting` → repository called exactly once (`calls == 1`).
12. `onErrorShown` clears `error`.
13. Any input change after a failure clears `error`.
14. `username` is trimmed before being passed to the repository.

Coverage gate: 100% of `LoginViewModel` branches and the `toLoginUiText` mapper.

## 12. Dependencies & Sequencing

- **Hard deps (must merge first):** AND-028 (`AuthRepository.login` + `LoginResult`),
  AND-030 (screen that hosts the ViewModel and renders `LoginUiState`).
- **Transitive:** AND-018 (OkHttp/Retrofit + cookie jar/CSRF), AND-027 (`AuthApi`),
  AND-020/AND-023 (core-ui scaffolding) arrive via the above.
- **Blocks / enables:** AND-034/035/036 (MFA verify flows) consume the
  `NavigateToMfa` effect; AND-029's auth store hydration follows `NavigateHome`.
- Develop alongside AND-030: the screen and ViewModel share `LoginUiState`,
  `LoginEffect`, and `LoginStatus`, which this ticket defines.

## 13. Risks & Open Questions

- **R1 — `getMe` ordering.** Does the ViewModel emit `NavigateHome` immediately, or
  await `getMe()` so home renders with `me` populated? Current design emits
  immediately and lets `RootViewModel`/post-login coordinator (AND-029) fetch `me`.
  *Decision needed* before AND-029 lands; if home must not render without `me`, add a
  `status = Finalizing` and call a repository `awaitSession()` here.
- **R2 — Authenticated-with-no-MFA realism.** Backend may always require ≥1 factor; if
  so the `Authenticated` branch is dead for normal users but must remain for
  recovery/passwordless paths. Keep the branch + test.
- **R3 — Effect buffering on rotation.** `DROP_OLDEST` with buffer=1 is safe for a
  single terminal effect; revisit if future requirements add concurrent effects.
- **R4 — Email-only usernames.** Web allows email; confirm backend doesn't accept
  bare usernames. If it does, relax `EmailValidator` to a non-blank check.

## 14. Acceptance Criteria

- AC-1. `LoginViewModel` exposes `StateFlow<LoginUiState>` and a `SharedFlow`/channel
  of `LoginEffect`; navigation is delivered only as one-shot effects.
- AC-2. `submitEnabled` is true exactly when username is a plausible email,
  password is non-blank, and no submit is in flight; otherwise false. (unit-tested)
- AC-3. While a login request is in flight, `isSubmitting == true` and
  `submitEnabled == false`; a second `onSubmit` does not issue a second request.
  (unit-tested)
- AC-4. `MfaRequired` result emits `NavigateToMfa(challengeId, factors)`;
  `Authenticated` result emits `NavigateHome`. (unit-tested)
- AC-5. Each `ApiResult.Failure` variant maps to the correct `UiText`, leaves
  `status == Idle`, and re-enables submit. (unit-tested)
- AC-6. Errors clear on next input change and on `onErrorShown()`. (unit-tested)
- AC-7. Password is never persisted or logged in plaintext.
- AC-8. All state transitions in §11 are covered by passing unit tests with 100%
  branch coverage of the ViewModel and error mapper.

## 15. Definition of Done

- Code merged to `android-port` under
  `feature-auth/src/main/java/com/testlogon/android/feature/auth/login/` with
  `LoginViewModel`, `LoginUiState`, `LoginStatus`, `LoginEffect`, and the
  `toLoginUiText` mapper.
- `@HiltViewModel` wiring compiles with KSP; ViewModel resolvable via
  `hiltViewModel()` in the AND-030 screen.
- `LoginViewModelTest` (cases 1–14) green in CI; branch coverage gate met.
- No password/credential appears in any log, `toString`, or analytics payload
  (verified by a test asserting `LoginUiState.toString()` excludes `password`).
- ktlint/detekt clean; no new public API in `core-*` modules (all new types live in
  `feature-auth` except shared `LoginResult`/`MfaFactor` owned by AND-028).
- Manual smoke against the dev backend: valid creds with MFA → MFA route; valid
  creds without MFA → home; bad creds → invalid-credentials error; airplane mode →
  network error, submit re-enabled.
- Spec open questions R1/R4 resolved or explicitly deferred with an owner.
