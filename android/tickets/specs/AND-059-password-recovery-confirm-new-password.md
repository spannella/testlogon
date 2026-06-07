---
id: AND-059
title: "Password recovery: confirm new password"
milestone: M2
epic: E08
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
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

> **Correction (review AND-059):** the confirm request field for the verification
> code is **`confirmation_code`**, not `code`. Verified against OpenAPI schema
> `PasswordRecoveryConfirmReq` and `src/api/types.ts: PasswordRecoveryConfirmReq` /
> `src/api/endpoints/auth.ts: passwordRecoveryConfirm`. The body shape is
> `{username, confirmation_code, new_password, challenge_id?}` with `challenge_id`
> **optional** (only `username`, `confirmation_code`, `new_password` are required).
> All field-name references below have been corrected accordingly.

The goal is a self-contained Compose screen plus its ViewModel that:

- Accepts `username`, `confirmation_code`, `new_password`, and (optional)
  `challenge_id` (the first carried in from AND-057/058, the `confirmation_code`
  and `challenge_id` from AND-058, the `new_password` collected here).
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
  the CSRF scheme: the web client reads the `ui_csrf` cookie and echoes it as the
  `X-CSRF-Token` header on **every** request (verified in `src/api/client.ts`:
  `getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`). *Exactly which
  recovery response sets the `ui_csrf` cookie is server-side and not visible in the
  OpenAPI/frontend sources — treated as an unverified assumption; the Android CSRF
  interceptor must send the header whenever the cookie is present, mirroring the web
  client.*
- **Web reference:** `src/api/endpoints/auth.ts: passwordRecoveryConfirm` (confirm
  call shape — there is **no** `passwordRecovery.ts`; the recovery calls live in
  `auth.ts`) and `src/api/types.ts: PasswordRecoveryConfirmReq` / `OkResp`
  (request/response types). The confirm screen flow is in
  `src/pages/PasswordRecovery.tsx`. Mirror field names exactly. *(Correction: the
  spec previously cited `frontend/src/api/endpoints/passwordRecovery.ts`, which does
  not exist.)*
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

> **Unverified-assumption (review AND-059):** the specific rules below (12-char
> minimum, four character classes, not-username, no-triple-repeat) are **not**
> confirmed by any authoritative source. The web reference (`PasswordRecovery.tsx`)
> enforces only `new_password >= 8 chars` client-side, and the OpenAPI
> `PasswordRecoveryConfirmReq.new_password` is an unconstrained `string` (no
> minLength/pattern). The backend policy is the source of truth and is not exposed in
> the available sources. **Recommendation:** keep the richer client meter as a UX
> pre-filter ONLY (do not block submit on rules the server may not enforce), or
> reduce the hard submit-gate to the web-verified `>= 8` and surface the rest as
> advisory. Treat server `detail` as authoritative (see §7). The rules as written:

Rules (client-side, advisory pre-filter — must be reconciled with backend policy):

- minimum length 12 characters;
- at least one uppercase, one lowercase, one digit, one symbol from
  `!@#$%^&*()-_=+[]{};:,.?`;
- not equal to the `username` (case-insensitive);
- no run of 3+ identical consecutive characters (e.g. `aaa`).

FR-3. The **Set password** button is enabled only when: all strength rules pass, the
two fields match, and no request is in flight.

FR-4. On submit, the ViewModel POSTs to `/ui/password-recovery/confirm` with
`{username, confirmation_code, new_password, challenge_id}` (field name corrected:
`confirmation_code`, not `code`; `challenge_id` is optional per the schema).

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

**Verified contract (OpenAPI `PasswordRecoveryConfirmReq` + `src/api/types.ts`):**
required fields are `username`, `confirmation_code`, `new_password`; `challenge_id`
is **optional/nullable**. The success response is `OkResp = { "ok": boolean }`
(`src/api/endpoints/auth.ts: passwordRecoveryConfirm` returns `OkResp`; OpenAPI 200
is a free-form `object` with `additionalProperties: true`). The previously-documented
`{status, username}` response shape was **not** verified by any source and has been
corrected to `OkResp`.

Request body:

```json
{
  "username": "jdoe",
  "confirmation_code": "482915",
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
    ): Response<OkResponse>
}

@JsonClass(generateAdapter = true)
data class ConfirmPasswordRequest(
    @Json(name = "username") val username: String,
    @Json(name = "confirmation_code") val confirmationCode: String,
    @Json(name = "new_password") val newPassword: String,
    // optional per schema; omit (null) if the verified challenge did not return one
    @Json(name = "challenge_id") val challengeId: String? = null,
)

// Success response is OkResp = { "ok": boolean }; no username is returned.
@JsonClass(generateAdapter = true)
data class OkResponse(
    @Json(name = "ok") val ok: Boolean = false,
)
```

Success — HTTP 200:

```json
{ "ok": true }
```

Error — FastAPI `detail` is mapped via the shared `detail` decoder
(`string | [{loc,msg,type}] | {code,message,...}`). The decoder mirrors the web
client's `normalizeErrorDetail` (verified in `src/api/client.ts`), which handles all
three shapes plus an object-with-`code` branch (`mapAuthorizationError`):

```json
{ "detail": "Password does not meet policy requirements." }
```
```json
{ "detail": [{ "loc": ["body","new_password"], "msg": "string too short", "type": "value_error" }] }
```
```json
{ "detail": { "code": "challenge_expired", "message": "Recovery challenge has expired." } }
```

> **Verification note:** Only the **422 array** shape is documented in the OpenAPI for
> this endpoint (`HTTPValidationError = { detail: ValidationError[] }`, where
> `ValidationError = { loc, msg, type }`, all required). The string-`detail` and
> object-`detail` (`{code,message}`) shapes are FastAPI `HTTPException` runtime
> conventions — **not** declared in the OpenAPI for `/ui/password-recovery/confirm`
> — but the web `normalizeErrorDetail` decodes them, so handling all three remains
> the correct defensive design. Treat the non-422 shapes as unverified-but-consistent
> with the web contract.

Status mapping:

| HTTP | Meaning | UI behavior |
|------|---------|-------------|
| 200  | Password set | success → navigate to login |
| 400 / 422 | Policy / validation failure | inline `errorMessage` from `detail` |
| 401 / 403 | Invalid CSRF or rejected | inline error + offer "Start over" |
| 404 / 410 | `challenge_id` expired/unknown | `fatal = CHALLENGE_EXPIRED` |
| 5xx / IOException / timeout | Server / network | inline retryable error |

> **Verification note on status codes:** the OpenAPI declares **only `200` and `422`**
> for `POST /ui/password-recovery/confirm`. The `400/401/403/404/410` rows are
> defensive mappings (FastAPI may raise `HTTPException` with these at runtime, and the
> web `client.ts` has explicit `401`/`403` branches) but are **not** documented for
> this route. Keep the mappings, but the only contractually-guaranteed error code here
> is `422`; a server policy rejection most likely arrives as `422` (validation) or a
> string-`detail` error. The client should map by family and fall back to an inline
> retryable error for anything undocumented.

Field names have been **verified** against the OpenAPI schema
`PasswordRecoveryConfirmReq` and `src/api/endpoints/auth.ts: passwordRecoveryConfirm`
/ `src/api/types.ts: PasswordRecoveryConfirmReq` (see §16). The earlier reference to
`frontend/src/api/endpoints/passwordRecovery.ts` was incorrect — that file does not
exist; the recovery calls live in `auth.ts`.

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
        username: String,
        confirmationCode: String,        // serialized as wire field "confirmation_code"
        newPassword: String,
        challengeId: String? = null,     // optional per schema
    ): ApiResult<Unit>
}
```

> Internal domain naming may keep `code` (as carried from AND-058's `RecoveryContext`),
> but the **wire field is `confirmation_code`** — the Moshi `@Json(name = ...)` mapping
> in `ConfirmPasswordRequest` is what guarantees the correct JSON key.

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
- request body field names/JSON match the verified contract (`username`,
  `confirmation_code`, `new_password`, optional `challenge_id`);
- success body deserializes as `OkResp` (`{ "ok": true }`);
- `X-CSRF-Token` header sent (when `ui_csrf` cookie present);
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
  auth service; treat server `detail` as authoritative. *Open (still unverified): the
  OpenAPI `new_password` field is an unconstrained `string`, and the web client
  enforces only `>= 8 chars` (`PasswordRecovery.tsx`). The 12-char + character-class +
  no-triple-repeat rules in FR-2 are NOT confirmed by any source — confirm the actual
  backend policy before hard-gating submit on them (see §16 Open assumptions).*
- **R2 — confirm request schema. RESOLVED (review AND-059).** Verified field set is
  `username`, `confirmation_code`, `new_password` (required) + `challenge_id`
  (optional). Source: OpenAPI `PasswordRecoveryConfirmReq`, `src/api/types.ts:
  PasswordRecoveryConfirmReq`, and `src/pages/PasswordRecovery.tsx` (which sends all
  four). The web sends both `confirmation_code` and `challenge_id`; Android should do
  the same when `challenge_id` is available.
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
  `/ui/password-recovery/confirm` with
  `{username, confirmation_code, new_password, challenge_id?}` and `X-CSRF-Token`
  (when the `ui_csrf` cookie is present); on 200 (`{ "ok": true }`) the app navigates
  to login with the username prefilled.
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **Endpoint is `POST /ui/password-recovery/confirm`.** — **Verified.**
   OpenAPI `POST /ui/password-recovery/confirm`
   (op=`password_recovery_confirm_ui_password_recovery_confirm_post`);
   `src/api/endpoints/auth.ts: passwordRecoveryConfirm`.
2. **Request field for the verification code is `confirmation_code` (NOT `code`).** —
   **Corrected.** OpenAPI schema `PasswordRecoveryConfirmReq.confirmation_code`;
   `src/api/types.ts: PasswordRecoveryConfirmReq`; `src/pages/PasswordRecovery.tsx`
   (sends `confirmation_code`). The spec's `code` was wrong.
3. **Required request fields are `username`, `confirmation_code`, `new_password`;
   `challenge_id` is optional/nullable.** — **Corrected.** OpenAPI
   `PasswordRecoveryConfirmReq.required = [username, confirmation_code, new_password]`;
   `challenge_id` typed `anyOf [string, null]`; `src/api/types.ts` shows
   `challenge_id?: string`. The spec implied `challenge_id` was required.
4. **Success response is `OkResp = { "ok": boolean }`, NOT `{status, username}`.** —
   **Corrected.** `src/api/endpoints/auth.ts: passwordRecoveryConfirm` returns
   `OkResp`; `src/api/types.ts: OkResp = { ok: boolean }`; OpenAPI 200 schema is a
   free-form object (`additionalProperties: true`, no declared fields). No `username`
   is returned; the Android screen must take `username` from the in-memory
   `RecoveryContext`, not the response.
5. **Web reference file is `src/api/endpoints/auth.ts` (`passwordRecoveryConfirm`),
   not `passwordRecovery.ts`.** — **Corrected.** No `passwordRecovery.ts` exists;
   recovery calls are in `auth.ts`. Confirm screen behavior is in
   `src/pages/PasswordRecovery.tsx`.
6. **CSRF: `X-CSRF-Token` header echoes the `ui_csrf` cookie on every request.** —
   **Verified.** `src/api/client.ts`: `getCookie("ui_csrf")` →
   `headers.set("X-CSRF-Token", csrf)`. (Which response *sets* the `ui_csrf` cookie is
   server-side — see Open assumptions.)
7. **Recovery namespace is unauthenticated; no session-refresh-on-401 applies.** —
   **Verified.** `src/api/client.ts`: the 401 refresh/retry path runs only
   `if (useAuthStore.getState().isAuthenticated)`; an unauthenticated 401 propagates
   directly via `ApiError(401, ...)`. Recovery has no stored access token.
8. **Network/offline error surfaces as a transport failure (not an HTTP code).** —
   **Verified.** `src/api/client.ts`: a `fetch` throw → `throw new ApiError(0,
   "Network error", err)`. Android equivalent: `IOException`/`SocketTimeout` →
   retryable inline error.
9. **`detail` decoding handles `string | [{loc,msg,type}] | {code,message}`.** —
   **Verified (frontend) / partially-verified (OpenAPI).** `src/api/client.ts:
   normalizeErrorDetail` (+ `mapAuthorizationError`) handles all three; OpenAPI
   declares only the **array** form for this route
   (`HTTPValidationError = { detail: ValidationError[] }`,
   `ValidationError = { loc, msg, type }` all required). String/object shapes are
   FastAPI runtime conventions, not declared for this endpoint.
10. **Documented response codes for confirm are only `200` and `422`.** —
    **Verified.** OpenAPI index line for `/ui/password-recovery/confirm`:
    `resp=200:;422:HTTPValidationError`. The `400/401/403/404/410` mappings in §5 are
    defensive (and `client.ts` has 401/403 branches generally) but are **not**
    documented for this route → Corrected to label them defensive/unverified.
11. **Password strength rules (12 chars, 4 char-classes, not-username,
    no-triple-repeat).** — **Unverified-assumption.** No source confirms them. Web
    enforces only `new_password.min(8)` (`src/pages/PasswordRecovery.tsx`); OpenAPI
    `new_password` is an unconstrained `string`. Backend policy not exposed.
12. **AC-2 login verification uses `POST /ui/session/start` (+ finalize).** —
    **Verified (endpoints).** OpenAPI `POST /ui/session/start`
    (req=`UiSessionStartReq`, resp `UiSessionStartResp`) and
    `POST /ui/session/finalize`; `src/api/types.ts: SessionStartResp`
    (`auth_required`, `required_factors`, optional `challenge_id`/`session_id`). The
    exact post-confirm login sequence/factors are owned by the auth feature.
13. **Web confirm flow shows inline `err.detail` on error and stays on-screen; shows a
    success state on success.** — **Verified.** `src/pages/PasswordRecovery.tsx:
    handleConfirm` (`setError(err.detail ...)` on `ApiError`, `setStep("success")` on
    success).
14. **Compose / Hilt / Retrofit-Moshi / SavedStateHandle implementation choices.** —
    **Framework ref (not contract).** Compose state hoisting + `SavedStateHandle`:
    https://developer.android.com/topic/libraries/architecture/viewmodel/viewmodel-savedstate ;
    `PasswordVisualTransformation`:
    https://developer.android.com/reference/kotlin/androidx/compose/ui/text/input/PasswordVisualTransformation ;
    autofill `ContentType.NewPassword`:
    https://developer.android.com/develop/ui/compose/text/autofill .

### Corrections made

- **C1.** `code` → **`confirmation_code`** in the request body, Retrofit DTO, FR-1/FR-4,
  §5 JSON, AC-1, and the MockWebServer test (claims 2). Internal domain naming may keep
  `code`, but the wire key is `confirmation_code`.
- **C2.** Success response **`{status, username}` → `OkResp { ok }`**; removed the
  assumption that the server echoes `username`; screen now sources `username` from
  `RecoveryContext` (claim 4).
- **C3.** `challenge_id` reclassified from required to **optional/nullable** in the DTO,
  §5, FR-1, and AC-1 (claim 3).
- **C4.** Web-reference path **`frontend/src/api/endpoints/passwordRecovery.ts` →
  `src/api/endpoints/auth.ts: passwordRecoveryConfirm`** (claim 5), in §2/§5.
- **C5.** Status-code table annotated: only `200`/`422` are documented; the other rows
  are explicitly labeled defensive/unverified (claim 10).
- **C6.** FR-2 strength rules + R1 annotated as **unverified assumptions** (web enforces
  only `min(8)`); recommended making them advisory rather than a hard submit gate
  (claim 11).
- **C7.** §5 error-shape block annotated: only the 422 array shape is OpenAPI-declared
  (claim 9).

### Open assumptions (could not be verified from the available sources)

- **OA-1 — Backend password policy.** The real strength policy (min length, required
  classes) is not in the OpenAPI (unconstrained `string`) or the web client (which only
  checks `>= 8`). Why: backend config/business logic is not in the provided sources.
  Action: confirm with the auth service before hard-gating submit on the FR-2 rules.
- **OA-2 — Which recovery response sets `ui_csrf`.** The header-echo behavior is
  verified, but the `Set-Cookie` source is server-side and not in OpenAPI/frontend.
  Why: cookies are emitted by the backend, not described in the spec. Action: confirm
  the cookie is present after AND-058; otherwise confirm will fail CSRF.
- **OA-3 — Non-422 error codes (400/401/403/404/410) for confirm.** Not documented for
  this route; the `challenge_expired`/object-`detail` shape is a defensive convention.
  Why: only 200/422 are declared. Action: capture a real expired-challenge response
  from the dev host to confirm the actual status/shape.
- **OA-4 — Username prefill into login.** The web app does not pass `username` into the
  login screen after success; this is an Android UX decision, not a verified web
  behavior. Why: `PasswordRecovery.tsx` shows a static success card. Action: acceptable
  as a design choice; not a contract.
- **OA-5 — Autofill "save new credential" prompt.** Device/IME-dependent (R5). Why:
  platform behavior, not in sources. Action: verify on the physical device.

## 17. Test Plan

Test target legend: **JVM** = JVM unit/Robolectric (local, no device);
**emu(test35)** = headless AVD `test35`, x86_64, API 35, in CI;
**device(A15)** = physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a).
Hardware/real-network cases prefer **device(A15)**.

- **TC-AND-059-01 — PasswordPolicy rule evaluation (unit).**
  Type: unit. Target: JVM. Preconditions: `PasswordPolicy.evaluate` available.
  Steps: parameterized inputs exercising each rule independently — length boundary
  (11 fail / 12 pass), each class present/absent, symbol-set membership for the full
  `!@#$%^&*()-_=+[]{};:,.?` set, case-insensitive username equality (`JDOE` vs `jdoe`),
  triple-repeat (`aab` passes, `aaa` fails). Expected: each `PasswordRuleResults` flag
  matches the expectation; `allPass` true only when all flags true.
  Traces: AC-3. *(Note: rules are unverified — see OA-1; test the implemented policy,
  not a backend contract.)*

- **TC-AND-059-02 — Submit gate logic (unit/ViewModel).**
  Type: unit. Target: JVM (Robolectric for `SavedStateHandle`), Turbine,
  `MainDispatcherRule`, fake `RecoveryRepository`. Preconditions: valid
  `RecoveryContext`. Steps: type a rule-passing password in both fields → assert
  `isSubmitEnabled = true`; make fields differ → `false`; clear a rule →`false`; set
  `isSubmitting = true` → `false`. Expected: gate true only when all rules pass AND
  passwords match AND not submitting. Traces: AC-3.

- **TC-AND-059-03 — Happy-path confirm + navigation (ViewModel).**
  Type: unit. Target: JVM, fake repo returning `ApiResult.Success(Unit)`.
  Preconditions: valid context, valid matching passwords. Steps: `onSubmit()`.
  Expected: exactly one `confirmNewPassword(username, confirmationCode, newPassword,
  challengeId)` call; on success `result = ConfirmResult.Success(username)`,
  `isSubmitting=false`, and password fields cleared from `UiState` + `SavedStateHandle`.
  Traces: AC-1, AC-7.

- **TC-AND-059-04 — Request body & headers on the wire (contract/MockWebServer).**
  Type: contract/MockWebServer. Target: JVM. Preconditions: MockWebServer enqueues
  `200 {"ok":true}`; `ui_csrf` cookie seeded in the cookie jar. Steps: call repository
  `confirmNewPassword(...)`. Expected: recorded request path `=
  /ui/password-recovery/confirm`, method `POST`; JSON body keys are exactly
  `username`, `confirmation_code`, `new_password`, `challenge_id` (no `code` key);
  `X-CSRF-Token` header equals the cookie value; response deserializes as `OkResp`
  and folds to `ApiResult.Success`. Traces: AC-1, AC-7.

- **TC-AND-059-05 — 422 validation error, all decoder shapes (contract + unit).**
  Type: contract/MockWebServer + unit. Target: JVM. Preconditions: MockWebServer.
  Steps: enqueue (a) `422 {"detail":[{"loc":["body","new_password"],"msg":"string too
  short","type":"value_error"}]}`, (b) `400 {"detail":"Password does not meet policy
  requirements."}`, (c) `{"detail":{"code":"challenge_expired","message":"..."}}`.
  Submit for each. Expected: (a)+(b) → inline `errorMessage` = decoded `detail` text,
  screen retained; (c) → `fatal = CHALLENGE_EXPIRED`. The array case joins `msg`
  values; the object case maps `message`/`code`. Traces: AC-4, AC-5.

- **TC-AND-059-06 — Expired/invalid challenge → Start over (ViewModel/UI).**
  Type: unit + Compose-UI. Target: JVM + emu(test35). Preconditions: repo returns the
  `challenge_expired` error (or 404/410). Steps: submit; then tap "Start over".
  Expected: `fatal = CHALLENGE_EXPIRED` state renders with a working "Start over"
  action that invokes the pop-to-recovery-start nav lambda. Traces: AC-5.

- **TC-AND-059-07 — Missing RecoveryContext (ViewModel/UI).**
  Type: unit + Compose-UI. Target: JVM + emu(test35). Preconditions: empty
  `SavedStateHandle` (no `username`/`code`/`challenge_id`). Steps: construct ViewModel /
  open screen. Expected: `fatal = MISSING_CONTEXT` immediately; **no** repository/network
  call is made; UI shows the missing-context state and routes to recovery start.
  Traces: AC-6.

- **TC-AND-059-08 — Double-submit guard (unit).**
  Type: unit. Target: JVM, fake repo with a suspending/delayed success. Steps: call
  `onSubmit()` twice before the first completes. Expected: exactly one repository call;
  button disabled while `isSubmitting`. Traces: AC-3.

- **TC-AND-059-09 — Flaky dev host / offline / timeout (contract + device).**
  Type: contract/MockWebServer + instrumented. Target: JVM (MockWebServer:
  `SocketPolicy.NO_RESPONSE` / disconnect for timeout & connection drop) and a
  confirming run on **device(A15)** with the radio off (airplane mode) hitting the real
  dev host. Steps: submit while the host is unreachable / mid-timeout. Expected:
  transport failure maps to a **retryable inline error** (not a fatal, not a wrong-code
  crash); `isSubmitting` resets; a user-initiated "Try again" re-issues exactly one
  POST. Must run on device(A15) for the real airplane-mode/network-loss behavior.
  Traces: AC-1 (resilience aspect).

- **TC-AND-059-10 — Compose UI: gating, toggles, checklist (Compose-UI).**
  Type: Compose-UI. Target: emu(test35) (`createAndroidComposeRule`). Steps: enter
  partial then full passwords; toggle show/hide on each field. Expected: "Set password"
  disabled until valid then enabled; rule checklist rows update per keystroke;
  show/hide flips the visual transformation and the toggle `contentDescription`
  updates. Traces: AC-3, AC-8.

- **TC-AND-059-11 — Security: redaction & no-persistence (unit + instrumented).**
  Type: unit + instrumented. Target: JVM (logging interceptor redaction assertion) +
  device(A15) (filesystem/SavedState inspection). Steps: submit with a known password;
  capture OkHttp interceptor output; trigger success; inspect `SavedStateHandle` and any
  app storage. Expected: `new_password`/`confirmation_code` never appear in logcat
  (recovery bodies redacted); no password written to Room/DataStore/disk; password
  state cleared from `UiState` + `SavedStateHandle` after success. Traces: AC-7.

- **TC-AND-059-12 — Rotation / process-death input restore (instrumented).**
  Type: instrumented. Target: emu(test35). Steps: enter both passwords + toggle
  visibility; rotate the device / simulate process death + restore. Expected: entered
  text and visibility flags restored from `SavedStateHandle`; no crash; password not
  leaked to disk during save. Traces: AC-8, AC-7.

- **TC-AND-059-13 — Accessibility: TalkBack, focus order, live-region error
  (instrumented/manual).**
  Type: instrumented + manual. Target: device(A15) with TalkBack on. Steps: navigate the
  form with TalkBack and an external keyboard; trigger a submit error. Expected: each
  rule row announces pass/fail (status by icon+text, not color alone); toggles announce
  state; logical focus order new → confirm → submit; targets ≥48dp; the inline error is
  announced via a live region; all strings externalized. Run on device(A15) for real
  TalkBack behavior. Traces: AC-8.

- **TC-AND-059-14 — End-to-end acceptance: confirm then log in (integration/e2e).**
  Type: integration/e2e. Target: device(A15) against the dev backend (fallback: fully
  scripted MockWebServer for CI). Preconditions: a recoverable account; AND-057→AND-058
  run to produce a verified `RecoveryContext` + `ui_csrf` cookie. Steps: confirm a new
  password (POST `/ui/password-recovery/confirm` → `{"ok":true}`); then drive
  `POST /ui/session/start` with the username + new password and complete finalize.
  Expected: confirm returns 200; the subsequent session-start succeeds
  (`auth_required`/finalize path), proving the password was actually changed and is
  usable. Prefer device(A15) for real-network + arm64/API-34 behavior. Traces: AC-1,
  AC-2.

### Coverage matrix

| Acceptance criterion | Covered by |
|----------------------|------------|
| AC-1 (POST shape + nav to login on 200) | TC-04, TC-03, TC-09, TC-14 |
| AC-2 (login with new password) | TC-14 |
| AC-3 (submit gate disabled states) | TC-01, TC-02, TC-08, TC-10 |
| AC-4 (policy/validation `detail` shapes inline) | TC-05 |
| AC-5 (expired challenge → Start over) | TC-05(c), TC-06 |
| AC-6 (missing context, no network call) | TC-07 |
| AC-7 (no log/persist; cleared on success; redaction) | TC-03, TC-04, TC-11, TC-12 |
| AC-8 (rotation, TalkBack/keyboard, externalized strings) | TC-10, TC-12, TC-13 |
