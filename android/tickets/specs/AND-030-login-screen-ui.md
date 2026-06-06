---
id: AND-030
title: Login screen UI
milestone: M1
epic: E04
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-020, AND-023]
blocks: [AND-031, AND-053, AND-057, AND-060, AND-063]
---

# AND-030 — Login screen UI

## 1. Overview & Goal

Build the stateless Login screen for the TestLogon native Android app: the first
interactive surface a logged-out user sees and the start destination of the
unauthenticated navigation graph (AND-023). The screen presents an
email/password form with inline validation, a show/hide password affordance,
links to recovery and registration, an entry point for overriding the server
base URL, a submit button gated on validity, and a region for surfacing
server/network errors.

This ticket is strictly the **presentation layer**: the Composable screen, its
hoisted `LoginUiState`, an event/callback surface, and the local validation
logic. It does **not** own the network call, cookie/CSRF handling, or the
MFA-vs-home branching decision — those belong to `LoginViewModel` (AND-031)
which consumes `AuthRepository` (AND-028). The goal is a fully UI-testable,
preview-driven screen whose behavior and information architecture (IA) match the
web reference login page (`frontend/`), wired into the nav graph and ready for
the ViewModel to drop in behind it.

Definition of success: a Compose UI test drives the form end-to-end (typing,
toggling, error rendering, submit-enable) against a fake state holder with no
network, and the rendered IA is verified to match the web login screen.

## 2. Context & References

- **Module:** `feature-auth` (Gradle module `:feature-auth`), package
  `com.testlogon.android.feature.auth.login`.
- **Depends on:**
  - **AND-020** — Core input composables (`AppButton`, `AppTextField` with
    error/helper, `PasswordField` with show/hide). The Login screen composes
    these rather than raw Material 3 widgets.
  - **AND-023** — Unauthenticated nav graph. Login is the start destination;
    this screen exposes navigation callbacks the graph binds.
- **Consumed by (blocks):**
  - **AND-031** — `LoginViewModel` provides the real `StateFlow<LoginUiState>`
    and `onSubmit` handler; replaces the fake holder used in this ticket's tests.
  - **AND-053 / AND-057 / AND-060 / AND-063** — recovery, register, magic-link,
    and related auth surfaces reached via this screen's navigation callbacks.
- **Backend (informational, owned downstream):** cookie-based auth begins at
  `POST /ui/session/start` with `{challenge_context:{username,password}}`.
  OpenAPI at `http://18.222.237.167:8000/openapi.json`.
- **Web reference:** `frontend/src/api/endpoints/*.ts` (auth endpoints) and the
  web login route for IA parity (field order, labels, link placement, error
  presentation).
- **Stack:** Kotlin 2.0.21, Jetpack Compose + Material 3, Hilt (KSP),
  Navigation-Compose, minSdk 24 / target 35, JDK 17.

## 3. Functional Requirements

FR-1 **Email/username field.** Single-line text field, keyboard type `Email`,
autofill hint `emailAddress`/`username`, IME action `Next`. Label and helper
match web copy. The backend field is `username`; the UI labels it per web (email).

FR-2 **Password field.** Uses `PasswordField` (AND-020) with a trailing
show/hide toggle (default obscured), keyboard type `Password`, autofill hint
`password`, IME action `Done` which triggers submit when the form is valid.

FR-3 **Inline validation.**
- Email/username: non-blank; if it contains `@`, must match a basic email
  pattern (`android.util.Patterns.EMAIL_ADDRESS`). Otherwise treated as a
  non-empty username.
- Password: non-blank.
- **[Corrected — divergence from web]** The web reference performs *only*
  non-blank validation on both fields (`credentialsSchema = z.object({ username:
  z.string().min(1), password: z.string().min(1) })` in
  `src/pages/Login.tsx`); it does **not** apply any email-format check. The
  `@`-conditional `EMAIL_ADDRESS` check above is an intentional Android-only
  hardening, not web parity. Keep it permissive (only validates format when `@`
  is present) so usernames are still accepted, and treat the "matches web
  behavior" AC as "non-blank gating identical; Android adds a stricter
  client-side email check." See §16 C3.
- Errors render beneath the offending field. Field-level errors appear on blur
  or on submit attempt, not on first keystroke (avoid premature error noise).

FR-4 **Submit gating.** The submit button is enabled only when both fields pass
local validation **and** the screen is not in a loading state. Tapping submit
(or password IME `Done`) invokes `onSubmit(email, password)`.

FR-5 **Loading state.** While `isSubmitting` is true: button shows a progress
indicator and is disabled, fields are read-only/disabled, navigation links are
disabled. No spinner-blocking full-screen overlay.

FR-6 **Server/network error display.** A dismissible error banner (or inline
form error) renders `state.formError` text when present. Distinguishes
credential errors (e.g., "Invalid email or password") from
network/offline/timeout states with appropriate copy and a Retry affordance for
retryable errors.

FR-7 **Recovery & register links.** Two text-link affordances invoking
`onForgotPassword()` and `onRegister()`. Placement/labels match web IA.

FR-8 **Server-URL entry point.** A discoverable but secondary affordance
(overflow/settings icon or "Advanced" expander) opening a base-URL editor,
invoking `onEditServerUrl()`. The screen displays the current effective base URL
(passed in `state.serverUrlLabel`) but does not itself persist it (DataStore
persistence is owned by the server-config ticket; this screen only triggers the
flow and reflects the value). **[Corrected — divergence from web]** The web
login (`src/pages/Login.tsx`) has **no** editable server-URL affordance; it
renders a static "Security reminder" block showing the current hostname
(`VITE_PUBLIC_HOSTNAME ?? window.location.hostname`) with an HTTPS-verification
tooltip. The base URL is fixed at build time via `VITE_API_BASE_URL`
(`src/api/client.ts`). The server-URL entry point is therefore an Android-only
addition required because the mobile client must target a configurable backend;
it is **not** a web-IA element. See §16 C4.

FR-9 **IA parity.** Field order, primary/secondary action hierarchy, and link
labels match the web login page so the two clients are recognizably the same
product. **[Clarified]** Verified web IA (`src/pages/Login.tsx`): brand header
("Welcome back" / "Sign in to your account to continue"), an error banner, the
Email field (label "Email", placeholder "Enter your email"), the Password field
with the **"Forgot password?" link inline at the top-right of the password
label** (linking to `/password-recovery`) and an Eye/EyeOff show-hide toggle, a
full-width "Sign in" primary button, then secondary "Email link" / "Security
key" buttons, and a bottom "Don't have an account? Register" link
(`/register`). Parity excludes two Android-only deltas: the server-URL entry
point (FR-8, not on web) and the stricter email-format validation (FR-3). The
web's "Email link", "Security key", and SSO affordances are out of scope for
this ticket (owned by AND-060 and later auth tickets). See §16 C4/C5.

## 4. Technical Design

The screen follows the project's stateless-screen + state-holder pattern. The
public route-level composable reads state from a `StateFlow` and forwards
callbacks; the inner composable is pure (state in, events out) and is what UI
tests and previews exercise.

```kotlin
package com.testlogon.android.feature.auth.login

// Route-level entry; bound by the unauthenticated nav graph (AND-023).
@Composable
fun LoginRoute(
    onNavigateToMfa: (challengeId: String) -> Unit,
    onNavigateToHome: () -> Unit,
    onForgotPassword: () -> Unit,
    onRegister: () -> Unit,
    onEditServerUrl: () -> Unit,
    viewModel: LoginViewModel = hiltViewModel(), // provided by AND-031
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    // Navigation side-effects are consumed from one-shot events emitted by the
    // ViewModel (AND-031). This ticket only renders state + forwards intents.
    LoginScreen(
        state = state,
        onEmailChange = viewModel::onEmailChange,
        onPasswordChange = viewModel::onPasswordChange,
        onTogglePasswordVisibility = viewModel::onTogglePasswordVisibility,
        onSubmit = viewModel::onSubmit,
        onDismissError = viewModel::onDismissError,
        onForgotPassword = onForgotPassword,
        onRegister = onRegister,
        onEditServerUrl = onEditServerUrl,
    )
}

// Stateless, fully testable/previewable screen. This is the deliverable of AND-030.
@Composable
fun LoginScreen(
    state: LoginUiState,
    onEmailChange: (String) -> Unit,
    onPasswordChange: (String) -> Unit,
    onTogglePasswordVisibility: () -> Unit,
    onSubmit: () -> Unit,
    onDismissError: () -> Unit,
    onForgotPassword: () -> Unit,
    onRegister: () -> Unit,
    onEditServerUrl: () -> Unit,
)
```

State and validation contracts owned by this ticket (the ViewModel in AND-031
populates and mutates them):

```kotlin
@Immutable
data class LoginUiState(
    val email: String = "",
    val password: String = "",
    val isPasswordVisible: Boolean = false,
    val emailError: FieldError? = null,
    val passwordError: FieldError? = null,
    val formError: FormError? = null,
    val isSubmitting: Boolean = false,
    val serverUrlLabel: String = "",
) {
    val isSubmitEnabled: Boolean
        get() = !isSubmitting &&
            email.isNotBlank() && password.isNotBlank() &&
            emailError == null && passwordError == null
}

enum class FieldError { Required, InvalidEmail }

sealed interface FormError {
    val message: String
    val retryable: Boolean
    data class Credentials(override val message: String) : FormError { override val retryable = false }
    data class Network(override val message: String) : FormError { override val retryable = true }
    data class Server(override val message: String) : FormError { override val retryable = true }
}
```

Pure validation lives in a stateless helper so both the screen (for IME/submit
gating) and the ViewModel (AND-031) share one source of truth:

```kotlin
object LoginValidator {
    fun validateEmail(raw: String): FieldError? = when {
        raw.isBlank() -> FieldError.Required
        '@' in raw && !Patterns.EMAIL_ADDRESS.matcher(raw).matches() -> FieldError.InvalidEmail
        else -> null
    }
    fun validatePassword(raw: String): FieldError? =
        if (raw.isBlank()) FieldError.Required else null
}
```

Layout: a `Column` inside a `Scaffold`, vertically scrollable
(`verticalScroll`) and `imePadding()`-aware so the keyboard never occludes the
submit button. Composition order top-to-bottom: app/brand header, optional error
banner, email field, password field, recovery link, primary submit button,
register link, server-URL/advanced affordance. **[Corrected]** On web the
"Forgot password?" recovery link sits inline at the **top-right of the password
field's label row**, not as a standalone row beneath the field; mirror that
placement for IA parity (the standalone-below ordering above is acceptable only
if the inline placement is infeasible with AND-020 components). See §16 C5. Uses `core-ui` theme tokens
(spacing, typography) so it matches the rest of the app. `@Preview` functions
cover empty, filled-valid, validation-error, submitting, and form-error states.

## 5. API Contract

**N/A for this ticket.** The Login screen issues no network calls. The auth API
contract — `POST /ui/session/start` (op `ui_session_start_ui_session_start_post`,
req schema `UiSessionStartReq`, resp `200:UiSessionStartResp` / `422:
HTTPValidationError`) with body
`{"challenge_context":{"username":"<email>","password":"<pw>"}}` returning
`{"auth_required":bool,"challenge_id":string|null,"required_factors":[string],"session_id":string|null}`
— is owned by **AND-028** (`AuthRepository`) and surfaced to this screen
exclusively through `LoginViewModel` (**AND-031**). This spec only defines the
in-process contract between screen and state holder (Section 4) and the error
mapping the ViewModel must populate (Section 7).

**[Corrected]** Two prior inaccuracies in this section are fixed: (a) the
response schema also carries **`session_id`** (nullable) — the web's no-MFA
"login complete" branch checks `!resp.auth_required && resp.session_id` before
calling `GET /ui/me` (`src/pages/Login.tsx: handleCredentials`), so AND-028/031
must surface it; the earlier omission is corrected. (b) `challenge_context` is an
**untyped free-form object** in the OpenAPI schema (`UiSessionStartReq.
challenge_context: {type: object, additionalProperties: true}`) — the
`{username,password}` shape is the convention used by the web client, not a
typed contract. (c) The `POST /ui/session/refresh` "retry on 401" does **not**
apply to the login request itself: the web transport only refreshes-and-retries
on 401 for *already-authenticated* requests; an unauthenticated 401 (wrong
password on login) propagates straight to the caller as `ApiError` with the
normalized `detail` (`src/api/client.ts`, the `if (!useAuthStore.getState().
isAuthenticated) { ...throw }` branch). For this screen that means a credential
failure is a direct error, never a silent refresh. Auth transport details:
session is **cookie-based** (`fetch(..., {credentials:"include"})`); CSRF is read
from the **`ui_csrf` cookie** and sent as the **`X-CSRF-Token`** request header
on every call (`src/api/client.ts: getCookie("ui_csrf")`).

## 6. Data & State Management

- **Single source of truth:** `StateFlow<LoginUiState>` from `LoginViewModel`
  (AND-031). The screen is stateless and renders the latest snapshot via
  `collectAsStateWithLifecycle()`.
- **Local UI state:** only ephemeral focus/blur tracking and IME state live in
  the composition (`remember`); all durable form state is hoisted into
  `LoginUiState`.
- **Configuration changes / process death:** because state is held in the
  ViewModel's `SavedStateHandle`-backed flow (AND-031), email text and visibility
  survive rotation. Password is intentionally **not** restored across process
  death (security; see Section 8). This ticket ensures the screen re-renders
  correctly from any restored `LoginUiState`.
- **Server URL:** `serverUrlLabel` is read-only input to the screen; persistence
  (DataStore prefs) and the editor dialog are external. The screen reflects the
  current value and triggers `onEditServerUrl()`.
- **Validation timing:** errors are derived state computed by the ViewModel from
  `LoginValidator` on blur/submit; the screen never silently mutates state.

## 7. Error Handling & Resilience

The screen renders errors; it does not classify network failures (that mapping
is in AND-028/AND-031). Required rendering behavior:

- `FormError.Credentials` → non-retryable inline form error, focus returns to
  email field, password is cleared by the ViewModel; no Retry button.
- `FormError.Network` → retryable banner with a Retry action that re-invokes
  `onSubmit`; copy reflects the unreliable plaintext dev host and ~20s timeout
  reality ("Couldn't reach the server. Check your connection and try again.").
- `FormError.Server` → retryable banner with generic server-error copy.
- Field errors (`Required`, `InvalidEmail`) render under the field and clear as
  soon as the field becomes valid on subsequent edits.
- Submit is disabled while `isSubmitting`, preventing duplicate requests; the
  password IME `Done` action is a no-op when `!isSubmitEnabled`.
- Error banner is dismissible via `onDismissError`; dismissing clears
  `formError` without altering field contents.
- FastAPI `detail` shapes (`string | [{msg}] | {code,...}`) are normalized to a
  user-facing `FormError.message` upstream; this screen only displays the string.
  **[Verified]** This matches the web `normalizeErrorDetail` helper
  (`src/api/client.ts`), which collapses a string detail, a `[{msg}]` validation
  array (422 `HTTPValidationError`), and `{code,...}` objects into one string.
- **[Verified]** Error-source mapping the ViewModel must honor: a credential
  failure is an `ApiError(401, detail)` (the web falls back to "Invalid
  credentials. Please try again." when `detail` is empty); an offline/DNS/
  transport failure is `ApiError(0, "Network error")` (`status === 0`) and maps
  to `FormError.Network`; any other non-2xx (5xx) maps to `FormError.Server`.

## 8. Security & Privacy

- Password field uses `PasswordVisualTransformation` by default and a deliberate
  show/hide toggle; the field carries the `password` autofill hint.
- Password is **excluded** from any `SavedStateHandle`/`rememberSaveable`
  persistence so it is not written to disk on process death.
- No credentials are logged. Telemetry (Section 10) records only event names and
  non-PII flags; `email`/`password` values are never included in logs or
  analytics.
- The screen reflects but does not validate transport security. Because the dev
  backend is plaintext HTTP, the server-URL editor (downstream) must warn on
  non-HTTPS; this screen passes through whatever label it is given.
- `android:autofillHints` configured so the platform credential manager / autofill
  can populate fields; no custom credential storage in this ticket.
- Consider `FLAG_SECURE` for the auth flow window is deferred to a global policy
  ticket; not enabled here.

## 9. Accessibility & i18n

- All strings sourced from `strings.xml` (`feature-auth` resources); no
  hard-coded user-facing text. Keys: `login_title`, `login_email_label`,
  `login_password_label`, `login_submit`, `login_forgot_password`,
  `login_register`, `login_server_url`, `login_error_credentials`,
  `login_error_network`, `login_error_required`, `login_error_invalid_email`.
- Every interactive element has a `contentDescription`/semantics; the show/hide
  toggle announces its current state ("Show password" / "Hide password").
- Field errors are associated with their fields via `semantics { error(...) }`
  so TalkBack announces them; the form-error banner uses a `liveRegion` so it is
  read when it appears.
- Touch targets ≥ 48dp; supports dynamic font scaling (sp units, no fixed
  heights that clip at large scale); content scrolls under the IME.
- Color is not the sole error signal (icon + text). Verified against Material 3
  contrast in both light and dark themes.
- RTL-safe layout (use start/end, not left/right).

## 10. Telemetry & Logging

- Emit screen-view event `auth_login_view` on first composition.
- Emit `auth_login_submit` on submit with non-PII property
  `email_format` (`email` | `username`) — never the value.
- Emit `auth_login_validation_error` with `field` and `reason` enums.
- Emit `auth_login_error_shown` with `error_type` (`credentials` | `network` |
  `server`).
- Emit `auth_login_link_tap` with `target` (`forgot` | `register` |
  `server_url`).
- Logging via the project's structured logger at `debug`/`info`; no PII, no
  credentials, no full URLs containing tokens. The actual analytics dispatch is
  invoked from the ViewModel (AND-031); this ticket defines the event surface
  and ensures callbacks fire at the right interaction points.

## 11. Testing Strategy

**Compose UI tests** (`feature-auth` androidTest, `createComposeRule`, fake
state — no network, no Hilt):
- Typing into email/password updates rendered values via the supplied callbacks.
- Submit button disabled when either field blank; enabled when both valid.
- Submit disabled and progress shown when `isSubmitting = true`; fields/links
  disabled.
- Invalid email (`a@b`) surfaces `InvalidEmail` error under the email field.
- `FormError.Credentials` renders non-retryable error, no Retry button.
- `FormError.Network` renders banner with working Retry that re-invokes
  `onSubmit`.
- Show/hide toggle flips `PasswordVisualTransformation` and updates the toggle's
  accessibility label.
- Recovery/register/server-URL affordances invoke the correct callbacks.
- IME `Done` on password triggers `onSubmit` only when valid.

**Unit tests** (JVM, `core-testing`):
- `LoginValidator.validateEmail` / `validatePassword` truth tables (blank,
  username, valid email, malformed email).
- `LoginUiState.isSubmitEnabled` derivation across representative combinations.

**IA parity check:** a documented screenshot comparison (Compose `@Preview` /
Paparazzi-style or manual) against the web login screen verifying field order,
action hierarchy, and link labels — satisfying "matches web behavior/IA".

**Accessibility test:** TalkBack semantics assertions (error announcement, live
region, toggle state) in the UI test suite.

## 12. Dependencies & Sequencing

- **Blocked by:**
  - **AND-020** (core input composables) — must land first; the screen composes
    `AppTextField`, `PasswordField`, `AppButton`.
  - **AND-023** (unauthenticated nav graph) — provides the route registration
    and navigation callback wiring (Login as start destination).
- **Blocks / unblocks:**
  - **AND-031** (`LoginViewModel`) — consumes `LoginUiState`/`LoginValidator`
    and replaces the fake state holder; the navigation side-effects (MFA vs
    home) are realized there.
  - **AND-053, AND-057, AND-060, AND-063** — auth surfaces reached from this
    screen's links.
- **Sequencing:** implement the stateless `LoginScreen` + `LoginUiState` +
  `LoginValidator` + previews + UI tests against a fake holder now; `LoginRoute`
  with `hiltViewModel()` is finalized in AND-031. Server-URL persistence and the
  editor dialog are external and stubbed via `onEditServerUrl()`.

## 13. Risks & Open Questions

- **R1 — IA drift from web.** Web login may evolve; lock IA against the current
  `frontend/` login at implementation time and capture a reference screenshot.
- **R2 — email vs username labeling.** Backend field is `username`; web labels
  it "email". Confirm exact web copy to avoid mismatched expectations. *Open:
  does the web accept non-email usernames?* Validation here is permissive
  (only validates format when `@` present).
- **R3 — server-URL ownership boundary.** This screen triggers but does not
  persist the base URL; ensure the downstream config ticket exists and the HTTPS
  warning lives there. *Open: which ticket owns DataStore base-URL persistence?*
- **R4 — autofill behavior on minSdk 24** varies; verify autofill hints degrade
  gracefully on older devices.
- **R5 — password restoration policy.** Confirmed: password not restored across
  process death; revisit only if UX explicitly requests it.

## 14. Acceptance Criteria

AC-1 Valid input (non-blank email/username + non-blank password, valid email
format when `@` present) enables the submit button; invalid/blank input keeps it
disabled. (UI-tested.)

AC-2 Field-level validation errors surface under the correct field on blur/submit
and clear when corrected. (UI-tested.)

AC-3 Server/network/credential errors surface via the form-error banner/inline
error with correct retryable behavior; network errors offer a working Retry.
(UI-tested.)

AC-4 Show/hide password toggle works and announces its state; password obscured
by default. (UI-tested.)

AC-5 Recovery, register, and server-URL entry-point affordances invoke their
callbacks; current server-URL label is displayed. (UI-tested.)

AC-6 Loading state disables the form and shows progress; no duplicate submits.
(UI-tested.)

AC-7 Screen behavior and IA (field order, action hierarchy, labels) match the
web login reference. (Verified via screenshot/IA comparison.)

AC-8 No credentials are logged or persisted across process death.

## 15. Definition of Done

- `LoginScreen`, `LoginRoute`, `LoginUiState`, `FieldError`/`FormError`, and
  `LoginValidator` implemented in `:feature-auth` under
  `com.testlogon.android.feature.auth.login`, composing AND-020 components and
  registered as the start destination in the AND-023 graph.
- All strings externalized; full a11y semantics (error association, live region,
  toggle state, 48dp targets, dynamic type, RTL).
- `@Preview`s for empty, valid, field-error, submitting, and form-error states
  render correctly in light and dark themes.
- Compose UI tests (Section 11) and `LoginValidator`/`isSubmitEnabled` unit
  tests pass in CI; IA parity check documented.
- No PII/credential logging; password excluded from saved state.
- Telemetry event surface wired at the defined interaction points.
- Builds clean with project toolchain (Kotlin 2.0.21, AGP 8.7.3, JDK 17),
  passes lint/detekt, and is reviewed and merged to `android-port`.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. OpenAPI
pointers cite the index file (`reference/openapi.index.txt`) and schema names in
`reference/openapi.pretty.json` (`components.schemas.<Name>`). Frontend pointers
are `reference/src/...`.

1. **Login submit hits `POST /ui/session/start`.** Verified.
   OpenAPI `POST /ui/session/start | op=ui_session_start_ui_session_start_post |
   req=UiSessionStartReq | resp=200:UiSessionStartResp;422:HTTPValidationError`;
   frontend `src/api/endpoints/auth.ts: sessionStart` →
   `api.post("/ui/session/start", body)`.

2. **Request body is `{challenge_context:{username,password}}`.** Verified
   (shape is a convention, not a typed field). `src/pages/Login.tsx:
   handleCredentials` sends `sessionStart({challenge_context:{username,
   password}})`; `src/api/types.ts: SessionStartReq` =
   `{challenge_context?: Record<string, unknown>}`; OpenAPI
   `components.schemas.UiSessionStartReq.challenge_context` =
   `{type:object, additionalProperties:true}` (untyped).

3. **Response fields `auth_required`, `challenge_id`, `required_factors`, and
   `session_id`.** Verified / Corrected. OpenAPI
   `components.schemas.UiSessionStartResp` = `auth_required` (boolean, required),
   `challenge_id` (string|null), `required_factors` (string[]), `session_id`
   (string|null). `src/api/types.ts: SessionStartResp` matches. **Correction
   C1:** the prior spec omitted `session_id`; the web no-MFA branch uses it
   (`if (!resp.auth_required && resp.session_id)` in `src/pages/Login.tsx`).

4. **CSRF: `ui_csrf` cookie sent as `X-CSRF-Token` header; cookie-based
   session.** Verified. `src/api/client.ts`:
   `const csrf = getCookie("ui_csrf"); if (csrf) headers.set("X-CSRF-Token",
   csrf);` and every `fetch` uses `credentials:"include"`.

5. **Refresh-on-401 retry via `POST /ui/session/refresh`.** Verified for
   authenticated requests / Corrected for login. OpenAPI `POST
   /ui/session/refresh | op=ui_session_refresh_..._post | resp=200:`.
   `src/api/client.ts` refreshes-and-retries only when
   `useAuthStore.getState().isAuthenticated` is true; an unauthenticated 401
   (login failure) throws `ApiError` directly. **Correction C2:** §5 previously
   implied refresh applies to the login call; it does not.

6. **Post-login identity via `GET /ui/me` returning `user_sub`.** Verified.
   OpenAPI `GET /ui/me | op=ui_me_ui_me_get | resp=200:;422:
   HTTPValidationError`; `src/api/endpoints/auth.ts: getMe`;
   `src/api/types.ts: MeResp` = `{user_sub, session_id, ip}`.

7. **Error `detail` normalization (`string | [{msg}] | {code,...}`).**
   Verified. `src/api/client.ts: normalizeErrorDetail` handles all three; 422
   bodies use OpenAPI `components.schemas.HTTPValidationError`
   (`detail: [{loc,msg,type}]`).

8. **Network/offline failure surfaces as `ApiError(0, "Network error")`.**
   Verified. `src/api/client.ts` `catch (err) { ... throw new ApiError(0,
   "Network error", err) }` around the `fetch`.

9. **Credential failure copy fallback "Invalid credentials. Please try
   again."** Verified. `src/pages/Login.tsx: handleCredentials` catch:
   `setError(err.detail || "Invalid credentials. Please try again.")`.

10. **Web field is `username`; UI label is "Email".** Verified.
    `src/pages/Login.tsx`: `<Label htmlFor="username">Email</Label>`,
    `<Input id="username" autoComplete="username" placeholder="Enter your
    email" />`; the request key is `username`.

11. **Web validation is non-blank only on both fields (no email-format
    check).** Verified → drives Correction C3. `src/pages/Login.tsx`:
    `credentialsSchema = z.object({username: z.string().min(1, "Email is
    required"), password: z.string().min(1, "Password is required")})`.

12. **Show/hide password toggle with announced state.** Verified.
    `src/pages/Login.tsx`: button `aria-label={showPassword ? "Hide password" :
    "Show password"}`, Eye/EyeOff icons, `type={showPassword ? "text" :
    "password"}`.

13. **"Forgot password?" link → `/password-recovery`, placed inline at the
    password label's top-right.** Verified → drives Correction C5.
    `src/pages/Login.tsx`: `<Link to="/password-recovery">Forgot password?</Link>`
    inside the password `<Label>` row.

14. **"Register" link → `/register`, at the card footer bottom.** Verified.
    `src/pages/Login.tsx`: `<Link to="/register">Register</Link>`.

15. **Loading state disables fields and shows a spinner on the submit button.**
    Verified. `src/pages/Login.tsx`: inputs `disabled={loading}`, submit
    `disabled={loading}` with `<Loader2 className="animate-spin" />`.

16. **Web login has no editable server-URL affordance; base URL is build-time
    `VITE_API_BASE_URL`.** Verified → drives Correction C4. `src/api/client.ts`:
    `API_BASE_URL = import.meta.env.VITE_API_BASE_URL`; `src/pages/Login.tsx`
    renders a read-only "Security reminder" hostname
    (`VITE_PUBLIC_HOSTNAME ?? window.location.hostname`) with an HTTPS tooltip.

17. **Compose stateless-screen + hoisted-state pattern.** Unverified-assumption
    (project convention, no source artifact to verify against here); aligns with
    Android guidance on state hoisting — framework ref:
    https://developer.android.com/develop/ui/compose/state#state-hoisting.

18. **`collectAsStateWithLifecycle()` for lifecycle-aware state collection.**
    Unverified-assumption / framework ref:
    https://developer.android.com/topic/libraries/architecture/coroutines#statef​low-lifecycle
    (lifecycle-aware Flow collection in Compose).

19. **`android.util.Patterns.EMAIL_ADDRESS` for the Android-only email check.**
    Framework ref:
    https://developer.android.com/reference/android/util/Patterns#EMAIL_ADDRESS.

20. **Autofill hints (`emailAddress`/`username`/`password`) degrade on minSdk
    24.** Unverified-assumption (R4); framework ref:
    https://developer.android.com/guide/topics/text/autofill-optimize.

### Corrections made

- **C1 (§5):** Added the `session_id` (nullable) response field, omitted before;
  the web uses it to detect a completed no-MFA login. Source: claim 3.
- **C2 (§5):** Clarified that `POST /ui/session/refresh` 401-retry applies only
  to authenticated requests, **not** to the login call (unauthenticated 401
  propagates directly). Source: claim 5.
- **C3 (§3 FR-3, §14 AC-1):** Noted that the web does **non-blank-only**
  validation; the `@`-conditional `EMAIL_ADDRESS` check is an intentional
  Android-only enhancement, not web parity. Source: claim 11.
- **C4 (§3 FR-8/FR-9, §14 AC-7):** Flagged the server-URL entry point as an
  Android-only addition absent from the web login; qualified the "matches web
  IA" claims accordingly. Source: claim 16.
- **C5 (§3 FR-9, §4 layout):** Corrected the recovery-link placement to inline
  at the password label's top-right (web), not a standalone row below the field.
  Source: claim 13.

### Open assumptions

- **OA-1 (R2):** Whether the backend accepts non-email usernames. The OpenAPI
  `challenge_context` is untyped (`additionalProperties:true`) and the web only
  requires non-blank, so non-email usernames are *plausibly* accepted but not
  provable from these sources. Validation here stays permissive.
- **OA-2 (R3):** Which downstream ticket owns DataStore base-URL persistence and
  the HTTPS-warning. Not resolvable from frontend/OpenAPI; an Android-side
  product decision.
- **OA-3:** Exact `strings.xml` copy and Material 3 theme tokens (§9) — no
  authoritative source in this reference set; lock against web copy at build
  time and capture a reference screenshot (R1).
- **OA-4 (R4):** Autofill-hint behavior on minSdk 24 devices — must be verified
  on-device; framework docs do not guarantee identical behavior across API
  levels.
- **OA-5:** The ~20s dev-host timeout and "unreliable plaintext dev host"
  characterization (§7) reflect operational knowledge of the test backend
  (`http://18.222.237.167:8000`), not a documented contract; treat as an
  environment assumption.

## 17. Test Plan

Test cases for the AND-030 deliverable (the stateless `LoginScreen` +
`LoginUiState` + `LoginValidator`), driven against a fake state holder — no
network, no Hilt — per §11. IDs trace to the §14 acceptance criteria.

- **TC-AND-030-01 — Submit gating truth table.** Type: unit (JVM).
  Preconditions: `LoginUiState` defaults; `LoginValidator` available.
  Steps: evaluate `isSubmitEnabled` and the validators across (blank email,
  blank password), (valid username, blank password), (valid email, valid
  password), (`isSubmitting=true` with both valid). Expected: enabled only when
  both non-blank, no field errors, and `!isSubmitting`; disabled in every other
  row. Traces: AC-1, AC-6.

- **TC-AND-030-02 — Email validator behavior (incl. Android-only format
  check).** Type: unit (JVM). Preconditions: `LoginValidator`. Steps: call
  `validateEmail` with `""`, `"alice"` (username, no `@`), `"a@b.com"`,
  `"a@b"` (malformed). Expected: `Required`, `null`, `null`, `InvalidEmail`
  respectively — confirming the permissive `@`-conditional rule (Android-only
  per §16 C3; web would accept `"a@b"`). Traces: AC-1, AC-2.

- **TC-AND-030-03 — Typing updates rendered values.** Type: Compose-UI
  (`createComposeRule`, fake holder). Preconditions: empty `LoginScreen`.
  Steps: perform text input on the email and password nodes; host re-renders
  state from the `onEmailChange`/`onPasswordChange` callbacks. Expected: fields
  display the typed text; password obscured by default. Traces: AC-1, AC-4.

- **TC-AND-030-04 — Submit enabled/disabled in UI.** Type: Compose-UI.
  Preconditions: fake holder reflecting validity. Steps: render with one field
  blank (assert submit `isNotEnabled`), then with both valid (assert
  `isEnabled`); tap submit. Expected: `onSubmit` invoked only in the valid
  state. Traces: AC-1.

- **TC-AND-030-05 — Field-level validation error rendering/clearing.** Type:
  Compose-UI. Preconditions: fake holder with `emailError=InvalidEmail` for
  input `a@b`. Steps: render; assert the error text appears under the email
  field with `semantics{error(...)}`; update holder to `emailError=null`;
  assert error removed. Expected: error shows under the correct field on
  submit/blur and clears when corrected. Traces: AC-2.

- **TC-AND-030-06 — Credential error is non-retryable.** Type: Compose-UI.
  Preconditions: `formError = FormError.Credentials("Invalid email or
  password")`. Steps: render. Expected: error banner/inline shows the message;
  **no** Retry control present; (per §7) focus returns to email and password is
  cleared by the holder. Traces: AC-3.

- **TC-AND-030-07 — Network error is retryable with working Retry.** Type:
  Compose-UI. Preconditions: `formError = FormError.Network("Couldn't reach the
  server. Check your connection and try again.")` (the flaky/offline dev-host
  path; underlying transport is `ApiError(0,...)` per §16 claim 8). Steps:
  render; assert banner + Retry; tap Retry. Expected: Retry re-invokes
  `onSubmit`. Traces: AC-3.

- **TC-AND-030-08 — Server error is retryable, generic copy.** Type:
  Compose-UI. Preconditions: `formError = FormError.Server(...)` (maps from a
  5xx / non-2xx normalized `detail`). Steps: render. Expected: banner with
  generic server copy and a Retry action. Traces: AC-3.

- **TC-AND-030-09 — Show/hide password toggle + accessibility label.** Type:
  Compose-UI (+ accessibility assertions). Preconditions: filled password,
  obscured. Steps: assert toggle node announces "Show password"; click; assert
  text becomes visible and the toggle announces "Hide password". Expected:
  transformation flips and the toggle's semantics label updates. Traces: AC-4.

- **TC-AND-030-10 — Navigation/link & server-URL callbacks fire.** Type:
  Compose-UI. Preconditions: `serverUrlLabel="http://18.222.237.167:8000"`.
  Steps: tap the recovery link, the register link, and the server-URL
  affordance. Expected: `onForgotPassword`, `onRegister`, and
  `onEditServerUrl` invoked respectively; the server-URL label is displayed.
  Traces: AC-5.

- **TC-AND-030-11 — Loading state disables form, prevents duplicate submit.**
  Type: Compose-UI. Preconditions: `isSubmitting=true`. Steps: render; assert
  submit shows progress and `isNotEnabled`, fields/links disabled; attempt
  password IME `Done`. Expected: no `onSubmit` while submitting; no duplicate
  requests. Traces: AC-6.

- **TC-AND-030-12 — IME `Done` submits only when valid.** Type: Compose-UI.
  Preconditions: invalid form then valid form. Steps: trigger IME `Done` on the
  password field in each state. Expected: no-op when `!isSubmitEnabled`;
  invokes `onSubmit` when valid. Traces: AC-1, AC-6.

- **TC-AND-030-13 — No credential persistence across process death.** Type:
  instrumented. Preconditions: email + password entered. Steps: trigger
  config-change/process-death restore from the ViewModel's
  `SavedStateHandle`-backed state (AND-031 harness); inspect restored state and
  saved-state bundle. Expected: email/visibility restored; **password not**
  present in saved state; logcat/analytics contain no credential values.
  Traces: AC-8.

- **TC-AND-030-14 — IA parity & accessibility audit.** Type: manual
  (screenshot/IA comparison) + Compose-UI a11y assertions. Preconditions:
  `@Preview`/Paparazzi renders in light & dark vs `src/pages/Login.tsx`.
  Steps: compare brand header, field order (Email → Password), inline
  top-right "Forgot password?", primary "Sign in", bottom "Register"; verify
  the server-URL affordance is documented as an Android-only addition; assert
  error `liveRegion`, ≥48dp targets, dynamic-type scaling, and non-color error
  signaling (icon+text). Expected: IA matches web within documented deltas
  (server-URL, stricter email check); a11y assertions pass. Traces: AC-7,
  AC-2, AC-3.

### Coverage matrix

| AC | Covered by |
|----|------------|
| AC-1 (submit gating on validity) | TC-01, TC-02, TC-03, TC-04, TC-12 |
| AC-2 (field errors surface & clear) | TC-02, TC-05, TC-14 |
| AC-3 (form/network/credential errors, retry) | TC-06, TC-07, TC-08, TC-14 |
| AC-4 (show/hide toggle, obscured default) | TC-03, TC-09 |
| AC-5 (recovery/register/server-URL callbacks + label) | TC-10 |
| AC-6 (loading disables, no duplicate submit) | TC-01, TC-11, TC-12 |
| AC-7 (IA parity with web) | TC-14 |
| AC-8 (no credential logging/persistence) | TC-13 |
