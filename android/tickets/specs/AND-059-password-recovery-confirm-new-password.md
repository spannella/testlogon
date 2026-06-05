---
id: AND-059
title: "Password recovery: confirm new password"
milestone: M2
epic: E08
priority: P1
size: M
status: draft
depends_on: [AND-058]
blocks: []
---

# AND-059 — Password recovery: confirm new password

## 1. Overview & Goal

This ticket implements the final step of the password-recovery flow: after a user
has verified a recovery challenge (AND-058), they submit a new password. The screen
collects the new password (with confirmation), validates it against client-side
strength rules, and POSTs it to `/ui/password-recovery/confirm` together with the
recovery context produced by the preceding challenge step.

The goal is a self-contained Compose screen plus its ViewModel that:

- Accepts `username`, `code`, `new_password`, and `challenge_id` (the first three
  carried in from AND-058, the `new_password` collected here).
- Enforces password strength rules locally before enabling submit.
- Calls the confirm endpoint, maps FastAPI errors to user-facing messages, and on
  success routes the user to the login screen so they can sign in with the new
  password.

The acceptance bar is end-to-end: a new password is set on the backend and the user
can subsequently authenticate with it. The cookie-based login flow itself
(`/ui/session/start` → MFA → finalize) is owned by the auth feature; this ticket only
guarantees the password is changed and verifies login succeeds in an integration
test.

## 2. Context & References

- **Epic E08** — Password recovery. Sequence: AND-057 (initiate / username entry) →
  AND-058 (challenge verification: email / sms / totp / recovery code) → **AND-059
  (confirm new password)**.
- **Module placement:** `feature-recovery` (created in AND-057). This ticket adds the
  confirm screen, ViewModel, UI state, and the repository method that wraps the API.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext
  HTTP, unreliable). OpenAPI at `/openapi.json`. The confirm route is part of the
  unauthenticated recovery namespace `/ui/password-recovery/*`; unlike the session
  routes it does **not** require an authenticated cookie, but it does participate in
  the CSRF scheme (the `ui_csrf` cookie is set on the first recovery call and echoed
  as `X-CSRF-Token`).
- **Web reference:** `frontend/src/api/endpoints/passwordRecovery.ts` (confirm call
  shape) and `frontend/src/api/types.ts` (request/response types). Mirror field names
  exactly.
- **Core deps:** `core-network` (Retrofit/OkHttp/Moshi, persistent cookie jar, CSRF
  interceptor, `ApiResult<T>`), `core-model` (DTOs + domain models), `core-ui`
  (text-field components, password-strength meter), `core-data` (recovery repository).
- **Upstream contract:** AND-058 must hand AND-059 a verified `RecoveryContext`
  (`username`, `challengeId`, `code`) via the navigation back stack / saved state.
  This is the sole functional dependency.

## 3. Functional Requirements

FR-1. The screen renders two secure text fields: **New password** and **Confirm
password**, each with a show/hide toggle.

FR-2. A live password-strength meter and rule checklist updates on every keystroke.
Rules (client-side, must mirror backend policy):

- minimum length 12 characters;
- at least one uppercase, one lowercase, one digit, one symbol from
  `!@#$%^&*()-_=+[]{};:,.?`;
- not equal to the `username` (case-insensitive);
- no run of 3+ identical consecutive characters (e.g. `aaa`).

FR-3. The **Set password** button is enabled only when: all strength rules pass, the
two fields match, and no request is in flight.

FR-4. On submit, the ViewModel POSTs to `/ui/password-recovery/confirm` with
`{username, code, new_password, challenge_id}`.

FR-5. On HTTP 200 the screen shows a brief success confirmation and navigates to the
login route (`route_login`), passing the `username` so the email field is prefilled.
The recovery back stack is popped (the recovery graph is removed so Back does not
re-enter it).

FR-6. On a recoverable validation error (e.g. password rejected by server policy, or
expired/invalid `challenge_id`), the inline error is shown; for an expired/invalid
challenge the user is offered a "Start over" action that pops back to AND-057.

FR-7. Inputs are preserved across configuration changes (rotation) via
`SavedStateHandle`; the entered passwords are **not** persisted to disk.

FR-8. If `RecoveryContext` is missing (deep-link / process death without saved
state), the screen shows an error state and routes back to recovery start.

## 4. Technical Design

Package root: `com.testlogon.android.feature.recovery.confirm`.

### UI state

```kotlin
data class ConfirmPasswordUiState(
    val newPassword: String = "",
    val confirmPassword: String = "",
    val showNewPassword: Boolean = false,
    val showConfirmPassword: Boolean = false,
    val rules: PasswordRuleResults = PasswordRuleResults(),
    val passwordsMatch: Boolean = false,
    val isSubmitEnabled: Boolean = false,
    val isSubmitting: Boolean = false,
    val errorMessage: String? = null,           // inline, non-blocking
    val fatal: ConfirmFatal? = null,            // missing context / expired challenge
    val result: ConfirmResult? = null,          // one-shot navigation signal
)

data class PasswordRuleResults(
    val minLength: Boolean = false,
    val hasUpper: Boolean = false,
    val hasLower: Boolean = false,
    val hasDigit: Boolean = false,
    val hasSymbol: Boolean = false,
    val notUsername: Boolean = false,
    val noTripleRepeat: Boolean = false,
) {
    val allPass: Boolean get() =
        minLength && hasUpper && hasLower && hasDigit &&
        hasSymbol && notUsername && noTripleRepeat
}

enum class ConfirmFatal { MISSING_CONTEXT, CHALLENGE_EXPIRED }

sealed interface ConfirmResult {
    data class Success(val username: String) : ConfirmResult
}
```

### Validation

```kotlin
object PasswordPolicy {
    const val MIN_LENGTH = 12
    private val SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?".toSet()

    fun evaluate(password: String, username: String): PasswordRuleResults =
        PasswordRuleResults(
            minLength = password.length >= MIN_LENGTH,
            hasUpper = password.any(Char::isUpperCase),
            hasLower = password.any(Char::isLowerCase),
            hasDigit = password.any(Char::isDigit),
            hasSymbol = password.any { it in SYMBOLS },
            notUsername = password.isNotEmpty() &&
                !password.equals(username, ignoreCase = true),
            noTripleRepeat = !Regex("(.)\\1\\1").containsMatchIn(password),
        )
}
```

`PasswordPolicy` lives in `core-ui` (or `core-model` if reused by other features) so
the same rules drive the meter and the submit gate. The server remains the source of
truth; the client rules are a UX pre-filter only.

### ViewModel

```kotlin
@HiltViewModel
class ConfirmPasswordViewModel @Inject constructor(
    private val recoveryRepository: RecoveryRepository,
    private val savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val context: RecoveryContext? = savedStateHandle.toRecoveryContext()
    private val _uiState = MutableStateFlow(initialState(context))
    val uiState: StateFlow<ConfirmPasswordUiState> = _uiState.asStateFlow()

    fun onNewPasswordChange(value: String) { /* recompute rules + gate */ }
    fun onConfirmPasswordChange(value: String) { /* recompute match + gate */ }
    fun onToggleNewVisibility() { /* ... */ }
    fun onToggleConfirmVisibility() { /* ... */ }
    fun onSubmit() { /* launch confirm */ }
    fun onErrorConsumed() { _uiState.update { it.copy(errorMessage = null) } }
    fun onResultConsumed() { _uiState.update { it.copy(result = null) } }
}
```

`onSubmit` guards on `isSubmitEnabled && !isSubmitting`, sets `isSubmitting = true`,
calls the repository, and on success emits `ConfirmResult.Success(username)`. The
passwords are held only in `_uiState` (in-memory) and in `SavedStateHandle` for
rotation; they are cleared from state on success before navigation.

### Composable

```kotlin
@Composable
fun ConfirmPasswordRoute(
    onSuccess: (username: String) -> Unit,
    onStartOver: () -> Unit,
    viewModel: ConfirmPasswordViewModel = hiltViewModel(),
)

@Composable
fun ConfirmPasswordScreen(
    state: ConfirmPasswordUiState,
    onNewPasswordChange: (String) -> Unit,
    onConfirmPasswordChange: (String) -> Unit,
    onToggleNewVisibility: () -> Unit,
    onToggleConfirmVisibility: () -> Unit,
    onSubmit: () -> Unit,
)
```

`ConfirmPasswordRoute` collects state with `collectAsStateWithLifecycle()`, consumes
`result`/`fatal` one-shot signals via `LaunchedEffect`, and invokes the navigation
lambdas. Navigation is wired in the recovery `NavGraphBuilder` extension; on success
it calls `navController.navigate(route_login) { popUpTo(route_recovery_graph) { inclusive = true } }`.

## 5. API Contract

**Endpoint:** `POST /ui/password-recovery/confirm`

Authentication: none (recovery namespace). CSRF: `X-CSRF-Token` header echoing the
`ui_csrf` cookie set during AND-058; supplied automatically by the shared CSRF
interceptor in `core-network`.

Request body:

```json
{
  "username": "jdoe",
  "code": "482915",
  "new_password": "Str0ng!Passw0rd",
  "challenge_id": "chal_7f3a9c20"
}
```

Retrofit interface (in `core-network`, extending the recovery API added by AND-057):

```kotlin
interface PasswordRecoveryApi {
    @POST("ui/password-recovery/confirm")
    suspend fun confirm(
        @Body body: ConfirmPasswordRequest,
    ): Response<ConfirmPasswordResponse>
}

@JsonClass(generateAdapter = true)
data class ConfirmPasswordRequest(
    @Json(name = "username") val username: String,
    @Json(name = "code") val code: String,
    @Json(name = "new_password") val newPassword: String,
    @Json(name = "challenge_id") val challengeId: String,
)

@JsonClass(generateAdapter = true)
data class ConfirmPasswordResponse(
    @Json(name = "status") val status: String? = null,   // e.g. "ok"
    @Json(name = "username") val username: String? = null,
)
```

Success — HTTP 200:

```json
{ "status": "ok", "username": "jdoe" }
```

Error — FastAPI `detail` is mapped via the shared `detail` decoder
(`string | [{msg,...}] | {code,...}`):

```json
{ "detail": "Password does not meet policy requirements." }
```
```json
{ "detail": [{ "loc": ["body","new_password"], "msg": "string too short", "type": "value_error" }] }
```
```json
{ "detail": { "code": "challenge_expired", "message": "Recovery challenge has expired." } }
```

Status mapping:

| HTTP | Meaning | UI behavior |
|------|---------|-------------|
| 200  | Password set | success → navigate to login |
| 400 / 422 | Policy / validation failure | inline `errorMessage` from `detail` |
| 401 / 403 | Invalid CSRF or rejected | inline error + offer "Start over" |
| 404 / 410 | `challenge_id` expired/unknown | `fatal = CHALLENGE_EXPIRED` |
| 5xx / IOException / timeout | Server / network | inline retryable error |

Field names MUST be verified against `/openapi.json` and
`frontend/src/api/endpoints/passwordRecovery.ts` before merge; this contract is the
expected shape pending that confirmation (see Open Questions).

## 6. Data & State Management

- **No Room/DataStore persistence.** Recovery is a transient flow; the new password
  is never written to disk. The cache layer is N/A for this ticket.
- **In-flight inputs** live in `MutableStateFlow<ConfirmPasswordUiState>` and are
  mirrored to `SavedStateHandle` keys (`new_password`, `confirm_password`,
  visibility flags) so rotation/process-death restores the form. These keys are
  cleared on success.
- **RecoveryContext** (`username`, `challengeId`, `code`) is passed from AND-058 as
  navigation arguments and read via `SavedStateHandle`:

```kotlin
data class RecoveryContext(val username: String, val challengeId: String, val code: String)

fun SavedStateHandle.toRecoveryContext(): RecoveryContext? {
    val u = get<String>("username") ?: return null
    val c = get<String>("challenge_id") ?: return null
    val k = get<String>("code") ?: return null
    return RecoveryContext(u, c, k)
}
```

- **Repository** (`core-data`):

```kotlin
interface RecoveryRepository {
    suspend fun confirmNewPassword(
        username: String, code: String, newPassword: String, challengeId: String,
    ): ApiResult<Unit>
}
```

The implementation calls `PasswordRecoveryApi.confirm`, folds the `Response` into
`ApiResult` via the shared `apiCall { }` helper, and discards the body (mapping to
`Unit`) — only the username already in context is needed downstream.

## 7. Error Handling & Resilience

- **Idempotency:** `confirm` is a state-mutating POST and is **not** idempotent, so
  it is excluded from the automatic backoff-retry policy (which applies to GETs
  only). Retry is user-initiated via a "Try again" affordance on transient failures.
- **Timeouts:** inherits the global ~20s OkHttp call timeout for the unreliable dev
  host. A timeout surfaces as a retryable inline error, not a fatal.
- **No session refresh:** the recovery namespace is unauthenticated, so the
  `401 → /ui/session/refresh → retry` flow does NOT apply here. A 401/403 indicates a
  CSRF/state problem and is treated as "Start over."
- **Expired challenge:** 404/410 or `detail.code == "challenge_expired"` sets
  `fatal = CHALLENGE_EXPIRED`; the UI offers "Start over" which pops to AND-057.
- **Missing context:** if `RecoveryContext` is null at construction the screen renders
  the `MISSING_CONTEXT` fatal state immediately (no network call).
- **Double-submit guard:** `isSubmitting` disables the button and ignores repeat
  `onSubmit` calls.
- **Server vs client policy drift:** a server rejection on a password the client
  accepted is shown verbatim from `detail`; the client never silently rewrites it.

## 8. Security & Privacy

- Passwords are handled as `String` in `UiState` (Compose `TextField` requires it);
  they are never logged, never written to Room/DataStore, and are cleared from
  `UiState` and `SavedStateHandle` on success.
- Text fields use `KeyboardOptions(keyboardType = KeyboardType.Password)` and
  `PasswordVisualTransformation()` when hidden; `autoCorrect = false`.
- Disable autofill save prompts for the temporary recovery `code` field; the new
  password fields should expose `ContentType.NewPassword` semantics so the platform
  offers to save the new credential.
- The dev backend is plaintext HTTP: the new password transits unencrypted on the dev
  host. This is acceptable for dev only; production requires HTTPS (tracked at the
  network-config level, not this ticket). Add a code comment flagging the cleartext
  caveat.
- CSRF: the `X-CSRF-Token` header must be present; the screen relies on the shared
  interceptor and must NOT construct or store the token itself.
- No password material appears in telemetry, crash reports, or breadcrumbs.

## 9. Accessibility & i18n

- All strings (`Set password`, field labels, rule descriptions, error messages,
  "Start over", success text) are in `strings.xml`; no hardcoded UI text.
- Each strength rule row has `contentDescription` stating pass/fail (e.g.
  "At least 12 characters: met"), and the overall meter exposes its level via
  semantics. Rule status is conveyed by icon + text, never color alone.
- Show/hide toggles have `contentDescription` ("Show password" / "Hide password")
  that updates with state.
- Targets are ≥48dp; the form is reachable and operable via TalkBack and an external
  keyboard (logical focus order: new → confirm → submit).
- On submit failure, the inline error is announced via a live region.
- Layout supports font scaling and RTL.

## 10. Telemetry & Logging

Emit via the shared analytics interface (no PII, no password/code values):

- `recovery_confirm_viewed`
- `recovery_confirm_submitted`
- `recovery_confirm_succeeded`
- `recovery_confirm_failed` with `reason` ∈
  `{policy, validation, challenge_expired, network, server, csrf}`.

Logging: ViewModel/repository use the project logger at `debug` for flow transitions
and `warn` for mapped errors. Request/response bodies for `/ui/password-recovery/*`
are redacted in the OkHttp logging interceptor so `new_password` and `code` never
reach logcat.

## 11. Testing Strategy

**Unit — `PasswordPolicy` (`core-testing` + JUnit):**
- each rule independently pass/fail; boundary at exactly 12 chars; symbol set
  membership; case-insensitive username equality; triple-repeat detection
  (`aab` passes, `aaa` fails).

**Unit — ViewModel (`MainDispatcherRule`, fake `RecoveryRepository`, Turbine):**
- submit gate toggles only when rules pass AND passwords match AND not submitting;
- success emits `ConfirmResult.Success(username)` and clears password state;
- 400/422 → inline `errorMessage` from decoded `detail` (all three `detail` shapes);
- 404/410 / `challenge_expired` → `fatal = CHALLENGE_EXPIRED`;
- null context → `fatal = MISSING_CONTEXT`, no repo call;
- double `onSubmit` triggers exactly one repository call.

**Repository (MockWebServer):**
- request body field names/JSON match the contract (`username`, `code`,
  `new_password`, `challenge_id`);
- `X-CSRF-Token` header sent;
- 200 → `ApiResult.Success`; error codes → mapped `ApiResult.Error`.

**Compose UI (`createAndroidComposeRule`):**
- button disabled until valid; rule checklist reflects input;
- show/hide toggles flip visual transformation;
- error and fatal states render their actions.

**Integration (acceptance):** drive AND-058 → AND-059 against the dev backend (or a
MockWebServer scripted full flow): confirm a new password, then exercise the login
path (`/ui/session/start` with the new credentials) and assert `auth_required`/
finalize success — proving the password was actually changed and is usable. This is
the gating end-to-end test for the ticket.

## 12. Dependencies & Sequencing

- **Hard dependency:** AND-058 (challenge verification) — supplies the verified
  `RecoveryContext` (`username`, `challengeId`, `code`) and establishes the `ui_csrf`
  cookie. AND-059 cannot be exercised without it.
- **Transitively:** AND-057 (recovery initiate / feature-recovery module + nav graph).
- **Infrastructure already in place:** `core-network` (cookie jar, CSRF interceptor,
  `apiCall`/`ApiResult`, Moshi), `core-ui` (secure text field, password meter
  component), Hilt graph.
- **Blocks:** nothing downstream within E08 (this is the terminal step).
- Login is invoked only by the integration test; the auth feature owns its own tickets
  and is not modified here.

## 13. Risks & Open Questions

- **R1 — exact server policy rules.** Client rules must match backend policy or users
  hit confusing server rejections. Mitigation: verify against `/openapi.json` and the
  auth service; treat server `detail` as authoritative. *Open: confirm minimum length
  and required character classes from backend config.*
- **R2 — confirm request schema.** The field set (`username`, `code`, `new_password`,
  `challenge_id`) is from the backlog scope; verify whether the server expects `code`
  here or only `challenge_id` once the challenge is verified. *Open: validate against
  `frontend/src/api/endpoints/passwordRecovery.ts`.*
- **R3 — unreliable plaintext dev host.** Flaky/timeout responses on confirm; the
  user-initiated retry on a non-idempotent POST could double-apply. Risk is low
  (idempotent in effect — same password) but flagged.
- **R4 — challenge TTL.** Time between AND-058 verification and confirm may exceed the
  challenge TTL, producing `challenge_expired`. Handled via "Start over."
- **R5 — autofill behavior** for the new credential varies by device/IME; verify the
  save prompt appears post-success.

## 14. Acceptance Criteria

- AC-1. Given a valid `RecoveryContext` and a password satisfying all strength rules
  entered identically in both fields, submitting POSTs to
  `/ui/password-recovery/confirm` with `{username, code, new_password, challenge_id}`
  and `X-CSRF-Token`; on 200 the app navigates to login with the username prefilled.
- AC-2. The user can then log in with the new password (verified by the integration
  test driving the session-start flow to a successful `auth_required`/finalize).
- AC-3. The **Set password** button is disabled whenever any rule fails, the fields
  differ, or a request is in flight.
- AC-4. Server policy rejection (400/422) shows the decoded `detail` message inline
  without leaving the screen; all three `detail` shapes are handled.
- AC-5. An expired/invalid `challenge_id` shows the expired state with a working
  "Start over" that returns to recovery initiation.
- AC-6. Missing `RecoveryContext` shows the missing-context state and routes back to
  recovery start without a network call.
- AC-7. Passwords are never logged, never persisted to disk, and are cleared from
  state on success; recovery request bodies are redacted in network logs.
- AC-8. Inputs survive rotation; the screen passes TalkBack and keyboard-navigation
  checks; all strings are externalized.

## 15. Definition of Done

- Code merged to `android-port` under `feature-recovery`
  (`com.testlogon.android.feature.recovery.confirm`) with the repository/API additions
  in `core-data`/`core-network`.
- All unit, repository (MockWebServer), and Compose UI tests green in CI; the
  AND-058 → AND-059 → login integration test passes against the dev backend (or a
  fully scripted MockWebServer flow).
- `PasswordPolicy` shared between the meter and submit gate; no duplicated rule logic.
- ktlint/detekt clean; no new build warnings; KSP/Hilt builds with JDK 17, AGP
  8.7.3, Gradle 8.9.
- Strings externalized and TalkBack-verified; redaction of recovery bodies confirmed
  in logcat.
- Request/response field names confirmed against `/openapi.json` and the web
  reference; any deviation from Section 5 reconciled before merge.
- PR description links AND-057/AND-058 and notes the plaintext-HTTP dev caveat.
