---
id: AND-060
title: Passwordless / magic-link: start
milestone: M2
epic: E08
priority: P2
size: M
status: draft
depends_on: [AND-030]
blocks: []
---

# AND-060 — Passwordless / magic-link: start

## 1. Overview & Goal

This ticket implements the **start (request) half of the passwordless / magic-link
sign-in flow** for the TestLogon native Android app. The user enters their email
address, the app calls `POST /ui/passwordless/start`, and the screen transitions
to a **"check your email" confirmation state** that displays the server-returned
`sent_to` destination and an opportunity to resend (with cooldown) or change the
address. It sits in epic **E08 (alternative sign-in surfaces)**, milestone **M2**.

Scope is deliberately bounded to the **start/dispatch** leg. The link the user
receives is opened out-of-band (web / deep link) and **completing** the
passwordless session (token consumption → `GET /ui/me`) is **not** owned here; it
is a downstream "passwordless complete / deep-link" ticket (see Section 12). This
ticket delivers: a stateless Compose screen with two phases (email entry →
confirmation), a `@HiltViewModel` driving a `StateFlow<PasswordlessStartUiState>`,
a thin repository method `startPasswordless(email)` over a Retrofit `AuthApi`
call, DTO→domain mapping, error normalization (FastAPI `detail`), resend cooldown,
and full test coverage.

Definition of success: from the Login screen's "Sign in with a link" affordance
(AND-030), a user enters an email, taps Send, and the screen shows a confirmation
state naming the masked `sent_to`; a resend control is gated by a cooldown timer;
all paths are unit/Compose-tested with no live backend.

## 2. Context & References

- **Repo / module:** `spannella/testlogon`, monorepo subfolder `android/`, branch
  `android-port`. Code lands in `feature-auth` (screen + ViewModel + UI state +
  repository method) and consumes `core-network` (`AuthApi`, persistent cookie jar,
  CSRF interceptor, `ApiResult`/`ApiErrorMapper`), `core-model` (domain types),
  and `core-ui` (input + state composables). Package base:
  `com.testlogon.android`; this feature's package is
  `com.testlogon.android.feature.auth.passwordless`.
- **Depends on — AND-030 (Login screen UI):** the passwordless flow is reached from
  a navigation affordance on Login (`onPasswordlessSignIn()` style callback) and
  reuses the AND-020 core input composables (`AppTextField`, `AppButton`) and the
  AND-021 state composables (loading/error/offline). The email validation helper
  pattern mirrors `LoginValidator`.
- **Consumes (informational, not redefined):**
  - **AND-018** `ApiResult<T>` typed result.
  - **AND-015** `ApiErrorMapper` for the FastAPI `detail` (`string | [{msg}] |
    {code,...}`) normalization.
  - **AND-011 / AND-012 / AND-013** persistent cookie jar, CSRF interceptor, and
    401-refresh authenticator wire automatically under `AuthApi`.
  - **AND-016** bounded-backoff retry policy (applies to the idempotent dispatch).
- **Backend:** FastAPI + DynamoDB; dev host `http://18.222.237.167:8000` is
  plaintext HTTP and unreliable — design for ~20s timeouts, offline/stale UI, and
  resend. OpenAPI at `/openapi.json`. Web reference under `frontend/`
  (`frontend/src/api/endpoints/*.ts`, `frontend/src/api/types.ts`) is the
  canonical source for exact field names; reconcile before merge (Section 13).
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow,
  Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15, minSdk 24 / compile+target 35, JDK 17,
  AGP 8.7.3.

## 3. Functional Requirements

FR-1 **Email entry.** A single-line email field (keyboard type `Email`, autofill
hint `emailAddress`, IME action `Done`) with inline validation: non-blank and
matching `Patterns.EMAIL_ADDRESS`. Submit is gated on validity and on not being
in flight.

FR-2 **Start dispatch.** Tapping the primary button (or IME `Done` when valid)
invokes the ViewModel, which calls `AuthRepository.startPasswordless(email)`
→ `POST /ui/passwordless/start`. While in flight the button shows progress and
the field is disabled.

FR-3 **Confirmation state.** On success the screen switches to a "check your
email" phase that renders the server-provided `sent_to` (masked, e.g.
`j•••@example.com`) using a parameterized string. It shows guidance copy
("Open the link we sent to {address} to finish signing in"), a **Resend** control,
and a **"Use a different email"** action that returns to the entry phase.

FR-4 **Resend with cooldown.** Resend re-invokes start for the same email but is
locally blocked while a cooldown timer (`resendSecondsLeft > 0`) is active; no
network call is made during cooldown. The default cooldown is 30s, overridden by a
server `resend_after`/`Retry-After` value when present. The control displays the
remaining seconds.

FR-5 **Change email.** "Use a different email" resets to the entry phase
preserving the previously typed address (so the user can correct a typo), clears
any error, and stops the cooldown ticker.

FR-6 **Error surfacing.** Network/timeout failures show a retryable inline/banner
error (copy reflecting the unreliable plaintext dev host). 4xx/422 validation or
policy errors (e.g., unknown/unverified account, rate limit) surface mapped,
user-facing copy. The server is the source of truth for whether an unknown email
is revealed; the client must not assume enumeration behavior (Section 8).

FR-7 **No silent success ambiguity.** The confirmation state is shown only on a
`2xx`; a failed start never advances to confirmation.

FR-8 **Out of scope (explicit).** Consuming the magic link / deep link, exchanging
the token, finalizing the session, and `GET /ui/me` are **not** in this ticket.

## 4. Technical Design

Standard stateless-screen + state-holder pattern. The route-level composable reads
state from a `StateFlow` and forwards intents; the inner composable is pure and is
what previews + UI tests exercise.

```kotlin
package com.testlogon.android.feature.auth.passwordless

// Route-level entry; bound by the unauthenticated nav graph (AND-023), reached
// from the Login screen affordance (AND-030).
@Composable
fun PasswordlessStartRoute(
    onBack: () -> Unit,
    viewModel: PasswordlessStartViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    PasswordlessStartScreen(
        state = state,
        onEmailChange = viewModel::onEmailChange,
        onSubmit = viewModel::onSubmit,
        onResend = viewModel::onResend,
        onChangeEmail = viewModel::onChangeEmail,
        onDismissError = viewModel::onDismissError,
        onBack = onBack,
    )
}

// Stateless, fully testable/previewable. The deliverable surface of AND-060.
@Composable
fun PasswordlessStartScreen(
    state: PasswordlessStartUiState,
    onEmailChange: (String) -> Unit,
    onSubmit: () -> Unit,
    onResend: () -> Unit,
    onChangeEmail: () -> Unit,
    onDismissError: () -> Unit,
    onBack: () -> Unit,
)
```

ViewModel and domain result:

```kotlin
@HiltViewModel
class PasswordlessStartViewModel @Inject constructor(
    private val repo: AuthRepository,        // gains startPasswordless (this ticket)
    private val clock: Clock,                // injectable for cooldown tests
    savedState: SavedStateHandle,
) : ViewModel() {
    private val _uiState = MutableStateFlow(PasswordlessStartUiState())
    val uiState: StateFlow<PasswordlessStartUiState> = _uiState.asStateFlow()

    fun onEmailChange(value: String) { /* update + clear field error */ }
    fun onSubmit() { dispatch(isResend = false) }
    fun onResend() { if (_uiState.value.canResend) dispatch(isResend = true) }
    fun onChangeEmail() { /* -> Phase.Entry, keep email, stop ticker */ }
    fun onDismissError() { /* clear formError */ }

    private fun dispatch(isResend: Boolean) { /* validate -> Sending -> repo -> Confirm/error */ }
}

// core-model
data class PasswordlessStarted(
    val sentTo: String,                 // masked destination from server
    val resendAfterSeconds: Int = 30,
    val expiresInSeconds: Int? = null,
)
```

Repository addition (interface from AND-028 family; method added here):

```kotlin
interface AuthRepository {
    // ...existing session/MFA methods...
    suspend fun startPasswordless(email: String): ApiResult<PasswordlessStarted>
}

@Singleton
class AuthRepositoryImpl @Inject constructor(
    private val api: AuthApi,
    private val errorMapper: ApiErrorMapper,
) : AuthRepository {
    override suspend fun startPasswordless(email: String): ApiResult<PasswordlessStarted> =
        safeApiCall(errorMapper) { api.passwordlessStart(PasswordlessStartReq(email)).toDomain() }
}

private fun PasswordlessStartResp.toDomain() = PasswordlessStarted(
    sentTo = sentTo,
    resendAfterSeconds = resendAfter ?: 30,
    expiresInSeconds = expiresIn,
)
```

Cooldown is driven by a `viewModelScope` ticker decrementing `resendSecondsLeft`
once per second from `resendAfterSeconds` to 0 (using the injected `clock`/test
dispatcher). Layout: `Scaffold` + scrollable `Column` with `imePadding()`; the
entry phase shows the email field + primary button; the confirmation phase swaps to
an icon/header, the masked-destination copy, resend, and change-email actions.
`@Preview`s cover: empty entry, valid entry, sending, confirmation, confirmation
with active cooldown, and error.

## 5. API Contract

One endpoint owned by this ticket. `POST`, JSON, riding the persistent cookie jar;
the `X-CSRF-Token` header is injected by the `core-network` CSRF interceptor
(AND-012) — not set manually. Because this is a session-bootstrapping request, the
401-refresh authenticator (AND-013) is generally a no-op here.

### `POST /ui/passwordless/start`

Request:
```json
{ "email": "user@example.com" }
```
Response `200`:
```json
{ "sent_to": "u•••@example.com", "resend_after": 30, "expires_in": 900 }
```

Notes:
- `sent_to` is the **masked** destination the server actually dispatched to. The
  client treats it as opaque display text (never unmasks/stores the raw address
  beyond the user's own input).
- `resend_after` / `Retry-After` (header) drive the cooldown when present;
  fallback 30s.
- Some backends return `202 Accepted` for an async dispatch; treat any `2xx` as
  success. To avoid account enumeration the backend may return `200` even for an
  unknown email — the client therefore shows confirmation on any `2xx` and does not
  branch on existence.

### Error responses (FastAPI `detail`, polymorphic)

`detail` is `string | [{msg, type, loc}] | {code, ...}`; `ApiErrorMapper`
(AND-015) normalizes all three into `ApiError(code?, message)`.

- `422` invalid email format → validation array → inline field error.
- `429` rate-limited → honor `Retry-After`/`retry_after` into cooldown; disable
  resend; show throttle copy.
- `400/404` policy errors (only if the backend chooses to reveal) → mapped form
  error; copy must not be phrased so as to confirm/deny account existence beyond
  what the server already exposes.

Exact field names (`sent_to` vs `masked_email`, `resend_after` vs `retry_after`,
presence of `expires_in`) and the request key (`email`) are reconciled against
`/openapi.json` and `frontend/src/api/types.ts` before merge (Section 13). Moshi
`@Json(name="...")` snake_case mapping is used on the DTOs.

```kotlin
// core-network DTOs (Moshi)
@JsonClass(generateAdapter = true)
data class PasswordlessStartReq(@Json(name = "email") val email: String)

@JsonClass(generateAdapter = true)
data class PasswordlessStartResp(
    @Json(name = "sent_to") val sentTo: String,
    @Json(name = "resend_after") val resendAfter: Int? = null,
    @Json(name = "expires_in") val expiresIn: Int? = null,
)

interface AuthApi {
    @POST("ui/passwordless/start")
    suspend fun passwordlessStart(@Body body: PasswordlessStartReq): PasswordlessStartResp
}
```

## 6. Data & State Management

- **Single source of truth:** `StateFlow<PasswordlessStartUiState>` from the
  ViewModel; the screen is stateless and renders via
  `collectAsStateWithLifecycle()`.
- **No Room persistence.** The dispatch is ephemeral. The only durable artifacts
  are the session/CSRF cookies in `core-network`'s persistent cookie jar (AND-011),
  not owned here.
- **Process death / rotation:** the typed `email` and current phase are restored
  from `SavedStateHandle`-backed state so the confirmation view survives rotation.
  An in-flight network call is not resumed across process death; on restore in
  `Sending`, the ViewModel falls back to the prior stable phase.

```kotlin
@Immutable
data class PasswordlessStartUiState(
    val phase: Phase = Phase.Entry,        // Entry, Sending, Confirmation
    val email: String = "",
    val emailError: FieldError? = null,    // Required | InvalidEmail
    val sentTo: String? = null,            // masked destination (Confirmation)
    val resendSecondsLeft: Int = 0,
    val formError: FormError? = null,      // retryable network/server | non-retryable policy
) {
    val isSubmitEnabled: Boolean
        get() = phase != Phase.Sending && email.isNotBlank() && emailError == null
    val canResend: Boolean
        get() = phase == Phase.Confirmation && resendSecondsLeft == 0
}

enum class Phase { Entry, Sending, Confirmation }
```

State transitions: `Entry --onSubmit(valid)--> Sending --2xx--> Confirmation`
(start cooldown ticker) `--error--> Entry` (with `formError`).
`Confirmation --onResend(canResend)--> Sending --2xx--> Confirmation` (restart
ticker). `Confirmation --onChangeEmail--> Entry` (keep email, stop ticker, clear
error). Errors are transient and cleared on edit/`onDismissError`.

## 7. Error Handling & Resilience

- **Timeouts:** OkHttp call timeout ~20s (project default for the unreliable dev
  host). Transport failure → `ApiResult.NetworkError` → retryable banner ("Couldn't
  reach the server. Check your connection and try again.") with a Retry that
  re-invokes the same dispatch.
- **Idempotent dispatch / retry:** `passwordlessStart` is idempotent-by-design (a
  retry simply triggers another link), so the bounded-backoff retry policy
  (AND-016) may apply to transient transport failures, but **never** auto-retry on
  a `4xx` and never auto-resend on `429`.
- **Throttle (429):** set `resendSecondsLeft` from `Retry-After`/`retry_after`,
  disable resend, no retry.
- **Validation (422):** map to the email field error; no network re-attempt until
  the user edits.
- **Offline:** if dispatch fails entirely while in `Entry`, render the AND-021
  offline/error state with a Retry action; there is no cached fallback.
- **Cancellation:** in-flight dispatch and the cooldown ticker are tied to
  `viewModelScope`; navigating away cancels cleanly.
- **No double-dispatch:** submit/resend are disabled while `phase == Sending`.

`FormError` mirrors AND-030's model (`Network`/`Server` retryable, a
non-retryable policy/credential variant) so copy and Retry behavior are consistent
across the auth area.

## 8. Security & Privacy

- **Account enumeration:** the screen shows the confirmation state on any `2xx`
  regardless of whether the email exists, so the client does not become an
  enumeration oracle. Error copy for `4xx` is generic and must not assert account
  existence beyond what the server response already discloses.
- **Masked destination:** `sent_to` is masked server-side; the client never
  attempts to unmask or persist a full address beyond the value the user typed.
- **No secrets logged or persisted.** The email is treated as PII: excluded from
  analytics values and from any non-debug logging; not written to disk beyond the
  rotation-scoped `SavedStateHandle`.
- **Transport:** the dev host is plaintext HTTP (acceptable for dev only).
  Production must enforce HTTPS via the `network_security_config` owned by
  core-network setup; this feature uses the injected base URL and hardcodes no IP.
- **CSRF/cookies:** the request rides the existing cookie jar + `X-CSRF-Token`
  interceptor; this ticket introduces no new credential handling.
- **No magic-link token handling here** — token consumption (the sensitive part)
  is owned by the downstream complete/deep-link ticket, which must validate the
  token server-side and never log it.

## 9. Accessibility & i18n

- All user-facing strings live in `feature-auth/src/main/res/values/strings.xml`
  as parameterized resources — no concatenation. Keys (proposed):
  `passwordless_title`, `passwordless_email_label`, `passwordless_submit`,
  `passwordless_confirm_title`, `passwordless_confirm_body` (formatted with
  `{address}`), `passwordless_resend`, `passwordless_resend_in` (plurals/format,
  "Resend in {n}s"), `passwordless_change_email`, `passwordless_error_invalid_email`,
  `passwordless_error_required`, `passwordless_error_network`,
  `passwordless_error_throttled`.
- The email field has `KeyboardType.Email`, `autofillHints = listOf("emailAddress")`,
  and a localized `contentDescription`.
- The field error is associated via `semantics { error(...) }`; the form-error
  banner uses `Modifier.semantics { liveRegion = LiveRegion.Assertive }`; the
  resend countdown uses `LiveRegion.Polite`.
- The phase change to Confirmation is announced (live region / focus move to the
  confirmation header) so TalkBack users learn the email was sent.
- Touch targets ≥48dp; the resend control exposes a disabled state with an
  accessible reason ("available in {n} seconds"). Supports dynamic font scaling
  (sp units, scrollable content under IME). Color is never the sole error signal
  (icon + text). RTL-safe (start/end). Verified in light and dark Material 3 themes.

## 10. Telemetry & Logging

Structured analytics events (no PII; email is never a property value):

- `passwordless_start_view` on first composition.
- `passwordless_start_submit` `{result: ok|error, error_code?}`.
- `passwordless_resend` `{cooldown_blocked: bool, result: ok|error, error_code?}`.
- `passwordless_change_email` (user returned to entry).
- `passwordless_error_shown` `{error_type: network|server|validation|throttled}`.

Debug-level Timber logs may record phase transitions and HTTP status codes but
**must redact** the email and `sent_to`. Any OkHttp logging interceptor runs at
`BASIC` level in debug builds only. The actual analytics dispatch is invoked from
the ViewModel at the defined interaction points.

## 11. Testing Strategy

**Unit (JUnit + Turbine + MockK, fixtures in `core-testing`):**

1. `startPasswordless` success maps `PasswordlessStartResp` → `PasswordlessStarted`
   (masked `sentTo`, `resendAfter` default 30 when null).
2. `422` validation → `ApiResult.HttpError` with mapped message; `429` →
   cooldown sourced from `Retry-After`/`retry_after`.
3. `IOException` → `ApiResult.NetworkError` (single surface; no auto-retry on 4xx).
4. Client validation: blank/malformed email → `emailError`, **no** network call
   (MockK `wasNot Called`).
5. Resend during cooldown (`resendSecondsLeft > 0`) performs **no** network call.
6. Treats `202` like `200` (both advance to Confirmation).

**ViewModel state tests (Turbine, injected `Clock`/test dispatcher):** intent
sequence `onEmailChange → onSubmit` drives `Entry → Sending → Confirmation`;
cooldown ticker decrements to 0 then enables resend; `onChangeEmail` returns to
`Entry` preserving email; error path returns to `Entry` with `formError`.

**Contract tests (MockWebServer):** success, validation, throttled (429 +
`Retry-After`) fixtures; assert request body JSON key (`email`) and presence of the
`X-CSRF-Token` header.

**Compose UI tests (`createComposeRule`, fake state — no Hilt/network):**
- Submit disabled for blank/invalid email, enabled when valid.
- `Sending` shows progress and disables submit/field.
- `Confirmation` renders the masked `sent_to` via the formatted string.
- Resend disabled with countdown when `resendSecondsLeft > 0`; enabled at 0 and
  invokes `onResend`.
- "Use a different email" invokes `onChangeEmail` and returns to entry.
- `FormError.Network` renders a retryable banner with a working Retry.
- TalkBack semantics: field error association, confirmation announcement, resend
  disabled reason.

Coverage target: repository + mapper ≥ 90% line; every acceptance bullet backed by
a named test.

## 12. Dependencies & Sequencing

- **Depends on AND-030 (Login screen UI)** — provides the navigation entry point
  ("Sign in with a link") and the reusable core input/state composables and email
  validation pattern. Hard prerequisite for the user-reachable flow.
- **Consumes (must exist):** AND-018 (`ApiResult`), AND-015 (`ApiErrorMapper`),
  AND-011/012/013 (cookie jar, CSRF, refresh), AND-016 (retry policy), AND-020/021
  (UI components), AND-023 (unauthenticated nav graph for route registration). If
  the `AuthApi`/repository scaffolding lags, stub `passwordlessStart` behind the
  interface to unblock TDD.
- **Blocks:** the magic-link **complete / deep-link** ticket (downstream, E08) that
  consumes the emitted link to finalize the session and call `GET /ui/me`. That
  ticket — not this one — owns token exchange and `intent-filter`/`nav deep link`
  wiring. (No blocked AND-### id is listed in the backlog; recorded as empty
  `blocks` and flagged in Section 13.)
- **Sequencing:** implement the stateless screen + `PasswordlessStartUiState` +
  previews + UI tests against a fake holder, plus the repository method + DTOs +
  contract tests, in parallel; wire `PasswordlessStartRoute` with `hiltViewModel()`
  once the ViewModel lands.

## 13. Risks & Open Questions

- **R1 — Exact wire shape.** Field names (`email` request key; `sent_to` vs
  `masked_email`; `resend_after` vs `retry_after`; presence of `expires_in`) and
  the success status (`200` vs `202`) are assumed from sibling MFA flows and must
  be confirmed against `/openapi.json` and `frontend/src/api/types.ts`. *Open: does
  the endpoint exist exactly at `/ui/passwordless/start`?* The web reference was not
  available in this workspace at spec time.
- **R2 — Enumeration policy.** Whether the backend returns `200` for unknown emails
  (enumeration-safe) or a `4xx`. The client defaults to confirm-on-`2xx`; verify
  the backend's behavior and align copy.
- **R3 — Completion ownership.** The magic-link consume/finalize ticket is implied
  but not enumerated in the backlog. Confirm its AND-### id and update `blocks`.
- **R4 — Resend cap.** Backlog does not specify a max-resend count; defer to server
  enforcement (429) unless product specifies otherwise.
- **R5 — Cooldown vs delivery latency.** On the flaky dev host, email delivery may
  exceed the cooldown ("link never arrived"); mitigated by resend + clear copy, but
  E2E reliability on the dev host is not guaranteed.
- **R6 — Deep-link entry.** If passwordless eventually returns to the app via a deep
  link, the manifest `intent-filter` and nav graph deep-link must be coordinated
  with the complete ticket; out of scope here.

## 14. Acceptance Criteria

AC-1 **Start triggers send (tested).** Submitting a valid email issues
`POST /ui/passwordless/start` with `{ "email": ... }` and, on `2xx`, transitions to
the confirmation phase. Verified by unit + MockWebServer + Compose tests.
(Directly satisfies the backlog acceptance bullet.)

AC-2 **Confirmation shows `sent_to` (tested).** The confirmation state renders the
server-returned masked `sent_to` via a parameterized string; a failed start never
reaches confirmation.

AC-3 **Validation gates the network.** Blank/malformed email shows an inline field
error and makes no network call; submit is disabled until valid.

AC-4 **Resend + cooldown.** Resend re-dispatches only when the cooldown has
elapsed; a resend attempt during cooldown makes no network call; `429`/`Retry-After`
updates the cooldown. Tested.

AC-5 **Change email.** "Use a different email" returns to entry, preserves the typed
address, and stops the cooldown ticker.

AC-6 **Error handling.** Network/timeout failures show a retryable error with a
working Retry; `422`/`429`/policy errors surface mapped, non-enumerating copy.

AC-7 **No PII leakage.** Email and `sent_to` are never logged (debug redaction
asserted) and not persisted beyond rotation-scoped saved state.

AC-8 **A11y.** Field error is announced and associated; confirmation transition is
announced; resend disabled state exposes an accessible reason; targets ≥48dp;
dynamic type and RTL respected.

## 15. Definition of Done

- `PasswordlessStartScreen`, `PasswordlessStartRoute`,
  `PasswordlessStartUiState`/`Phase`, and `PasswordlessStartViewModel` implemented
  in `:feature-auth` under `com.testlogon.android.feature.auth.passwordless`,
  composing AND-020/021 components and registered in the AND-023 nav graph, reached
  from the AND-030 Login affordance.
- `AuthRepository.startPasswordless` + `PasswordlessStartReq`/`Resp` DTOs +
  DTO→domain mapper + `ApiErrorMapper` handling for the three `detail` shapes, wired
  via Hilt (KSP) over the existing `AuthApi`/cookie/CSRF stack.
- Cooldown/resend logic with an injectable clock/dispatcher.
- All strings externalized; full a11y semantics (error association, confirmation
  announcement, resend reason, 48dp targets, dynamic type, RTL); `@Preview`s for
  empty/valid/sending/confirmation/cooldown/error in light and dark themes.
- All Section 11 tests written and green; repository/mapper coverage ≥ 90%; CI
  passes on `android-port`.
- No PII/credential logging; no hardcoded dev IP or secrets; wire field names
  reconciled against `/openapi.json` (R1 resolved or explicitly noted).
- Builds clean with the project toolchain (Kotlin 2.0.21, AGP 8.7.3, JDK 17),
  passes lint/detekt, reviewed, and merged. PR references AND-060 and links the
  downstream magic-link complete ticket once identified.
