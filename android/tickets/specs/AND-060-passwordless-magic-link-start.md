---
id: AND-060
title: Passwordless / magic-link: start
milestone: M2
epic: E08
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-030]
blocks: []
---

# AND-060 — Passwordless / magic-link: start

## 1. Overview & Goal

This ticket implements the **start (request) half of the passwordless / magic-link
sign-in flow** for the TestLogon native Android app. The user enters their
**username or email** (the request key is `username`, per the verified contract;
the web client labels the field "Username or email"), the app calls
`POST /ui/passwordless/start`, and the screen transitions to a **"check your email"
confirmation state**. **CORRECTION (verified):** the server-returned `sent_to` is a
**list of strings** (`string[]`), not a single masked string, and the success body
also carries a required `status` string. There is **no** `resend_after`/`expires_in`
in the verified response (see Sections 5/16). The web reference does not render
`sent_to` at all — it confirms using the user's own typed input — so this app
treats `sent_to` as optional supplementary display. The screen offers an
opportunity to resend (client-side cooldown) or change the address. It sits in
epic **E08 (alternative sign-in surfaces)**, milestone **M2**.

Scope is deliberately bounded to the **start/dispatch** leg. The link the user
receives is opened out-of-band (web / deep link) and **completing** the
passwordless session (token consumption via `POST /ui/passwordless/verify` with
`{ "token": ... }`, then `GET /ui/me`) is **not** owned here; it is a downstream
"passwordless complete / deep-link" ticket (see Section 12). This
ticket delivers: a stateless Compose screen with two phases (email entry →
confirmation), a `@HiltViewModel` driving a `StateFlow<PasswordlessStartUiState>`,
a thin repository method `startPasswordless(email)` over a Retrofit `AuthApi`
call, DTO→domain mapping, error normalization (FastAPI `detail`), resend cooldown,
and full test coverage.

Definition of success: from the Login screen's "Sign in with a link" affordance
(AND-030), a user enters a username/email, taps Send, and the screen shows a
confirmation state (naming the address the user typed; optionally echoing the
server `sent_to[]` if present); a resend control is gated by a **client-side**
cooldown timer (the server provides no cooldown hint — see Section 5/16); all paths
are unit/Compose-tested with no live backend.

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

FR-1 **Identifier entry.** A single-line field accepting **username or email**
(the verified request key is `username`; the web client labels it "Username or
email"). Keyboard type `Email`, autofill hint `emailAddress`, IME action `Done`.
Inline validation is **non-blank only** by default; an email-shaped value MAY be
additionally checked with `Patterns.EMAIL_ADDRESS`, but because a bare username is
valid the client must **not** hard-block non-email input. (The web client gates
only on non-blank: `if (!magicEmail.trim()) return`.) Submit is gated on non-blank
and on not being in flight.

FR-2 **Start dispatch.** Tapping the primary button (or IME `Done` when valid)
invokes the ViewModel, which calls `AuthRepository.startPasswordless(email)`
→ `POST /ui/passwordless/start`. While in flight the button shows progress and
the field is disabled.

FR-3 **Confirmation state.** On success (`200` with `status` present) the screen
switches to a "check your email" phase. **CORRECTION (verified):** the primary
`{address}` shown is the **user's own typed input** (mirroring the web client,
which renders `magicEmail`); the server `sent_to` is a **`string[]`** and is
optional, used only to optionally enrich the confirmation when present (it is not
guaranteed masked). It shows guidance copy ("Open the link we sent to {address} to
finish signing in"), a **Resend** control, and a **"Use a different email"** action
that returns to the entry phase.

FR-4 **Resend with cooldown.** Resend re-invokes start for the same identifier but
is locally blocked while a cooldown timer (`resendSecondsLeft > 0`) is active; no
network call is made during cooldown. **CORRECTION (verified):** the verified
`PasswordlessStartResp` has **no** `resend_after` field, so the cooldown is a
**purely client-side** 30s default. A server `Retry-After` header (or `429`) is
**unverified** (not in the OpenAPI `responses` for this op — only `200`/`422` are
documented); if such a header/status is ever observed at runtime the client MAY
honor it, but this is an assumption, not a contract (see Sections 7/16). The
control displays the remaining seconds.

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

// core-model — shaped to the VERIFIED contract:
//   PasswordlessStartResp { status: string (required), sent_to: string[] }
data class PasswordlessStarted(
    val status: String,                 // required success status string
    val sentTo: List<String> = emptyList(), // server destinations (NOT guaranteed masked)
    // No resendAfter / expiresIn: not present in the verified response.
    // Client cooldown default lives in the ViewModel, not the domain type.
)
```

Repository addition (interface from AND-028 family; method added here):

```kotlin
interface AuthRepository {
    // ...existing session/MFA methods...
    suspend fun startPasswordless(identifier: String): ApiResult<PasswordlessStarted>
}

@Singleton
class AuthRepositoryImpl @Inject constructor(
    private val api: AuthApi,
    private val errorMapper: ApiErrorMapper,
) : AuthRepository {
    // Param is the identifier (username OR email); mapped to the `username` wire key.
    override suspend fun startPasswordless(identifier: String): ApiResult<PasswordlessStarted> =
        safeApiCall(errorMapper) {
            api.passwordlessStart(PasswordlessStartReq(username = identifier)).toDomain()
        }
}

private fun PasswordlessStartResp.toDomain() = PasswordlessStarted(
    status = status,
    sentTo = sentTo ?: emptyList(),
)
```

Cooldown is driven by a `viewModelScope` ticker decrementing `resendSecondsLeft`
once per second from a **client-side** default (30s; the server returns no cooldown
hint) to 0 (using the injected `clock`/test dispatcher). Layout: `Scaffold` +
scrollable `Column` with `imePadding()`; the
entry phase shows the email field + primary button; the confirmation phase swaps to
an icon/header, the masked-destination copy, resend, and change-email actions.
`@Preview`s cover: empty entry, valid entry, sending, confirmation, confirmation
with active cooldown, and error.

## 5. API Contract

One endpoint owned by this ticket. `POST`, JSON, riding the persistent cookie jar;
the `X-CSRF-Token` header is injected by the `core-network` CSRF interceptor
(AND-012) — not set manually. Because this is a session-bootstrapping request, the
401-refresh authenticator (AND-013) is generally a no-op here.

### `POST /ui/passwordless/start`  *(verified against OpenAPI + frontend)*

Request (`PasswordlessStartReq`, `username` **required**):
```json
{ "username": "user@example.com" }
```
Response `200` (`PasswordlessStartResp`, `status` **required**, `sent_to` is an array):
```json
{ "status": "sent", "sent_to": ["u***@example.com"] }
```

Notes (corrected to the verified contract):
- **Request key is `username`, NOT `email`.** Verified: OpenAPI
  `components.schemas.PasswordlessStartReq` (single required prop `username`) and
  `src/api/endpoints/auth.ts: passwordlessStart` → `passwordlessStart({ username })`
  in `src/pages/Login.tsx`.
- **`sent_to` is `string[]`** (array), and `status` (string) is required. Verified:
  OpenAPI `components.schemas.PasswordlessStartResp` and
  `src/api/types.ts: PasswordlessStartResp`. The masking and the value's contents
  are not specified by the schema; treat each element as opaque display text. The
  web client does **not** render `sent_to` at all (it echoes the typed input), so
  consuming `sent_to` is optional enrichment.
- **No `resend_after`, no `expires_in`** in the verified response. Cooldown is
  client-side (Section 7).
- **Only `200` and `422` are documented** in the OpenAPI `responses` for this op.
  A `202`-async variant and `2xx`-for-unknown-email enumeration safety are
  **unverified assumptions** (the schema neither confirms nor denies); the client
  still shows confirmation on `2xx` defensively, but this is not a documented
  contract.

### Error responses

The **only documented error is `422`** (`HTTPValidationError`). Verified:
`detail` is an array of `ValidationError` objects, each with required `loc`
(array of string|int), `msg` (string), and `type` (string). `ApiErrorMapper`
(AND-015) normalizes this into `ApiError(code?, message)` and maps to the field
error.

- `422` → validation array → inline field error.
- `429` rate-limit + `Retry-After`, and `400/404` policy errors: **UNVERIFIED** —
  not present in the OpenAPI `responses` for this op. The client may handle them
  defensively (generic mapped copy), but they are assumptions, not contract
  (Section 16). FastAPI's global handler can still emit a `string` or
  `{detail: ...}` shape for unexpected statuses, so `ApiErrorMapper` should remain
  tolerant of `string | [{msg,type,loc}] | {detail}`.

The request key (`username`) and response shape are reconciled and **confirmed**
against the OpenAPI spec and `src/api/types.ts` (Section 13/16). Moshi
`@Json(name="...")` snake_case mapping is used on the DTOs.

```kotlin
// core-network DTOs (Moshi) — shaped to the VERIFIED contract
@JsonClass(generateAdapter = true)
data class PasswordlessStartReq(@Json(name = "username") val username: String)

@JsonClass(generateAdapter = true)
data class PasswordlessStartResp(
    @Json(name = "status") val status: String,          // required
    @Json(name = "sent_to") val sentTo: List<String>? = null, // array; may be absent/empty
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
    val identifier: String = "",           // username OR email (wire key: `username`)
    val identifierError: FieldError? = null, // Required (InvalidEmail optional/soft)
    val sentTo: List<String> = emptyList(), // server `sent_to[]`, optional enrichment
    val resendSecondsLeft: Int = 0,
    val formError: FormError? = null,      // retryable network/server | non-retryable policy
) {
    // Confirmation copy uses `identifier` (the typed value), matching the web client;
    // `sentTo` is only rendered when non-empty.
    val isSubmitEnabled: Boolean
        get() = phase != Phase.Sending && identifier.isNotBlank() && identifierError == null
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
- **Throttle (429) — UNVERIFIED (not in OpenAPI for this op):** if a `429` with
  `Retry-After` is ever returned, set `resendSecondsLeft` from it, disable resend,
  no retry. This is defensive handling only; the documented contract has no `429`.
- **Validation (422) — verified:** map the `HTTPValidationError` (`detail[]` of
  `{loc,msg,type}`) to the identifier field error; no network re-attempt until the
  user edits.
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
  regardless of whether the account exists, so the client does not become an
  enumeration oracle. **Note (unverified):** whether the backend is actually
  enumeration-safe (always `200`) is not expressed by the OpenAPI schema — only
  `200`/`422` are documented; the web client treats any non-error as "sent". Error
  copy for any `4xx` is generic and must not assert account existence beyond what
  the server response already discloses.
- **Destination display:** `sent_to` is a `string[]` whose masking is **not**
  guaranteed by the schema. The client renders the user's own typed identifier as
  the primary confirmation text and treats `sent_to` elements (if shown) as opaque;
  it never persists a full address beyond the value the user typed.
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
   (`status` carried; `sentTo` mapped from `string[]`, null → empty list).
2. `422` validation (`HTTPValidationError`: `detail[]` of `{loc,msg,type}`) →
   `ApiResult.HttpError` with mapped message. (`429`/`Retry-After` cooldown is
   defensive/unverified — covered as an optional case, not contract.)
3. `IOException` → `ApiResult.NetworkError` (single surface; no auto-retry on 4xx).
4. Client validation: blank identifier → `identifierError`, **no** network call
   (MockK `wasNot Called`). A bare (non-email) username is accepted, not blocked.
5. Resend during cooldown (`resendSecondsLeft > 0`) performs **no** network call.
6. Request body serializes the **`username`** key (asserted in contract tests).

**ViewModel state tests (Turbine, injected `Clock`/test dispatcher):** intent
sequence `onEmailChange → onSubmit` drives `Entry → Sending → Confirmation`;
cooldown ticker decrements to 0 then enables resend; `onChangeEmail` returns to
`Entry` preserving email; error path returns to `Entry` with `formError`.

**Contract tests (MockWebServer):** success (`200` with `status` + `sent_to[]`),
validation (`422` `HTTPValidationError`) fixtures (plus an optional defensive `429`
+ `Retry-After` fixture); assert request body JSON key is **`username`** and the
`X-CSRF-Token` header is present.

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

- **R1 — Exact wire shape — RESOLVED (verified 2026-06-06).** The endpoint exists
  exactly at `POST /ui/passwordless/start`. Verified shapes: request key is
  **`username`** (not `email`); response is **`{ status: string (required),
  sent_to: string[] }`** — there is **no** `resend_after`/`retry_after` and **no**
  `expires_in`; only `200`/`422` are documented. Source: OpenAPI
  `components.schemas.PasswordlessStartReq`/`PasswordlessStartResp` and
  `src/api/types.ts`. The spec body has been corrected throughout (see Section 16).
- **R2 — Enumeration policy — partially open.** The OpenAPI schema documents only
  `200`/`422`, and the web client treats any non-error as "sent", consistent with
  enumeration-safety, but the schema does not explicitly guarantee `200` for
  unknown accounts. The client defaults to confirm-on-`2xx`; runtime verification
  against the dev host is still advisable. (Unverified — see Section 16.)
- **R3 — Completion ownership — clarified.** The downstream consume/finalize step
  is `POST /ui/passwordless/verify` (`PasswordlessVerifyReq { token }` →
  `PasswordlessVerifyResp { status, session_id?, auth_required, challenge_id?,
  required_factors[] }`), after which the web client calls `GET /ui/me`
  (`src/pages/MagicLinkVerify.tsx`). The corresponding AND-### id is still not
  enumerated in the backlog; confirm and update `blocks`.
- **R4 — Resend cap.** Backlog does not specify a max-resend count; defer to server
  enforcement (429) unless product specifies otherwise.
- **R5 — Cooldown vs delivery latency.** On the flaky dev host, email delivery may
  exceed the cooldown ("link never arrived"); mitigated by resend + clear copy, but
  E2E reliability on the dev host is not guaranteed.
- **R6 — Deep-link entry.** If passwordless eventually returns to the app via a deep
  link, the manifest `intent-filter` and nav graph deep-link must be coordinated
  with the complete ticket; out of scope here.

## 14. Acceptance Criteria

AC-1 **Start triggers send (tested).** Submitting a non-blank identifier issues
`POST /ui/passwordless/start` with `{ "username": ... }` and, on `2xx`, transitions
to the confirmation phase. Verified by unit + MockWebServer + Compose tests.
(Directly satisfies the backlog acceptance bullet.)

AC-2 **Confirmation shown (tested).** On success the confirmation state renders the
typed identifier via a parameterized string (and optionally the server `sent_to[]`
when present); a failed start never reaches confirmation.

AC-3 **Validation gates the network.** Blank identifier shows an inline field error
and makes no network call; submit is disabled until non-blank. A bare username
(non-email) is accepted.

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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. OpenAPI =
`reference/openapi.pretty.json` (schemas under `components.schemas`) and
`reference/openapi.index.txt`; frontend = `reference/src/`.

1. **Endpoint exists at `POST /ui/passwordless/start`.** VERIFIED.
   OpenAPI `POST /ui/passwordless/start` (op `passwordless_start_ui_passwordless_start_post`);
   `src/api/endpoints/auth.ts: passwordlessStart` → `api.post("/ui/passwordless/start", body)`.
2. **HTTP method is POST, JSON body.** VERIFIED. OpenAPI path `post` with
   `requestBody.required: true`; `src/api/endpoints/auth.ts` uses `api.post`.
3. **Request key is `username` (required), NOT `email`.** CORRECTED (spec said
   `email`). OpenAPI `components.schemas.PasswordlessStartReq` (single required prop
   `username`); `src/api/types.ts: PasswordlessStartReq { username: string }`;
   `src/pages/Login.tsx` calls `passwordlessStart({ username: magicEmail.trim() })`.
4. **Response `sent_to` is `string[]` (array), not a single masked string.**
   CORRECTED. OpenAPI `components.schemas.PasswordlessStartResp.sent_to` =
   `{type: array, items: {type: string}}`; `src/api/types.ts: PasswordlessStartResp
   { status: string; sent_to: string[] }`.
5. **Response carries a required `status` string.** CORRECTED (spec omitted it).
   OpenAPI `PasswordlessStartResp.required: ["status"]`; `src/api/types.ts`.
6. **Response has NO `resend_after`/`retry_after` and NO `expires_in`.** CORRECTED
   (spec invented both). OpenAPI `PasswordlessStartResp` has only `status` +
   `sent_to`; absent from `src/api/types.ts`.
7. **`sent_to` is guaranteed masked.** CORRECTED → UNVERIFIED-ASSUMPTION. The
   schema (OpenAPI `PasswordlessStartResp.sent_to.items: {type: string}`) says
   nothing about masking; the web client never renders it. Spec now treats it as
   opaque, optional.
8. **Documented success/error statuses are exactly `200` and `422`.** VERIFIED.
   OpenAPI path `responses` keys = `200` (PasswordlessStartResp), `422`
   (HTTPValidationError); index line `resp=200:PasswordlessStartResp;422:HTTPValidationError`.
9. **`202`-async success variant.** UNVERIFIED-ASSUMPTION (spec asserted it). Not in
   OpenAPI `responses`. Client still treats any `2xx` as success defensively.
10. **`429` rate-limit with `Retry-After` drives the cooldown.** CORRECTED →
    UNVERIFIED-ASSUMPTION. No `429` in OpenAPI `responses` for this op; no
    `resend_after` in the body. Cooldown is now specified as client-side (30s).
11. **`400/404` policy errors.** UNVERIFIED-ASSUMPTION. Not in OpenAPI `responses`.
12. **`422` body is FastAPI `HTTPValidationError`** (`detail: ValidationError[]`,
    each required `loc: (string|int)[]`, `msg: string`, `type: string`). VERIFIED.
    OpenAPI `components.schemas.HTTPValidationError` and `components.schemas.ValidationError`.
13. **CSRF via `X-CSRF-Token` header injected by transport (not set manually).**
    VERIFIED for the web contract. `src/api/client.ts` reads cookie `ui_csrf` and
    sets header `X-CSRF-Token`; Android equivalent is the AND-012 interceptor
    (assumed analogous, not re-checked here).
14. **Request rides cookies / credentials included.** VERIFIED (web).
    `src/api/client.ts` uses `credentials: "include"` on fetch.
15. **Web client gates submit on non-blank only (no email-format hard block).**
    VERIFIED. `src/pages/Login.tsx handleMagicLink`: `if (!magicEmail.trim()) return`;
    button `disabled={loading || !magicEmail.trim()}`; field label "Username or email".
16. **Web confirmation echoes the user's typed input, not `sent_to`.** VERIFIED.
    `src/pages/Login.tsx` renders `{magicEmail}` in the "We sent a sign-in link to …"
    copy; `sent_to` is unused on this screen.
17. **Downstream completion = `POST /ui/passwordless/verify` then `GET /ui/me`.**
    VERIFIED. OpenAPI `POST /ui/passwordless/verify`
    (`PasswordlessVerifyReq { token }` → `PasswordlessVerifyResp { status,
    session_id?, auth_required, challenge_id?, required_factors[] }`);
    `src/pages/MagicLinkVerify.tsx` calls `passwordlessVerify({ token })` then `getMe`.
18. **Android framework choices** (Compose Material 3, Hilt, Retrofit/Moshi,
    `collectAsStateWithLifecycle`, `SavedStateHandle`, Compose `semantics`
    error/liveRegion). UNVERIFIED here (framework ref) — not checkable against the
    backend/frontend sources; standard AndroidX APIs assumed correct per project
    stack (Section 2).

### Corrections made

- Request key `email` → **`username`** (Sections 1, 3, 4, 5, 6, 11, 14).
- `sent_to` typed `String` (masked) → **`List<String>`** (optional, masking not
  guaranteed); confirmation copy now uses the user's typed identifier (Sections 1,
  3, 4, 5, 6, 8).
- Removed invented `resend_after`/`Retry-After` server cooldown and `expires_in`;
  cooldown is now **client-side 30s**; domain type `PasswordlessStarted` reshaped to
  `{ status, sentTo: List<String> }` (Sections 1, 3, 4, 5, 7).
- Added required `status` field to the response DTO/domain (Sections 4, 5, 11).
- `202`/`429`/`400`/`404` downgraded from asserted contract to **defensive,
  unverified** handling (only `200`/`422` documented) (Sections 5, 7, 8, 11).
- `422` error shape pinned to verified `HTTPValidationError`/`ValidationError`
  (Sections 5, 7, 11).
- R1 marked RESOLVED; R3 enriched with the verified `verify` contract (Section 13).
- Email-format hard validation softened to non-blank to allow bare usernames
  (Sections 3, 11, 14).

### Open assumptions

- **Enumeration safety** (always `200` for unknown accounts): not expressed by the
  schema; consistent with web behavior but unverified at runtime (R2).
- **`202`/`429`/`400`/`404` runtime behavior**: undocumented; handled defensively
  only. A live `Retry-After` header, if it ever appears, would be honored but is not
  contractually guaranteed.
- **`sent_to` masking and cardinality**: schema allows any/empty array of arbitrary
  strings; client must not assume a single masked email.
- **Android-side CSRF/cookie/refresh interceptors (AND-011/012/013)** behave
  identically to the web `client.ts`: assumed, not re-verified in this review (those
  tickets own it).
- **Framework/API correctness** (Compose, Hilt, Retrofit, AndroidX semantics):
  framework ref; not verifiable from the provided sources.

## 17. Test Plan

Test target legend: **JVM** = JVM unit/Robolectric (local, no device); **EMU** =
headless emulator AVD `test35` (x86_64, API 35) for CI UI/instrumented; **DEVICE** =
physical Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, Android 14 / API 34,
arm64-v8a). This ticket is pure networking + Compose UI with no camera/biometrics/
push/WebRTC, so almost everything runs on JVM or EMU; one ABI/API-skew smoke is
called out for DEVICE.

- **TC-AND-060-01 — Happy-path mapping (unit).** Type: unit (JVM). Target:
  `AuthRepositoryImpl.startPasswordless` + `toDomain`. Preconditions: MockK `AuthApi`
  returns `PasswordlessStartResp(status="sent", sentTo=["u***@example.com"])`.
  Steps: call `startPasswordless("user@example.com")`. Expected:
  `ApiResult.Success(PasswordlessStarted(status="sent", sentTo=["u***@example.com"]))`;
  request built with `PasswordlessStartReq(username="user@example.com")`. Traces: AC-1, AC-2.

- **TC-AND-060-02 — `sent_to` absent/empty maps to empty list (unit).** Type: unit
  (JVM). Target: `toDomain`. Preconditions: response `{status:"sent"}` (no `sent_to`).
  Steps: map. Expected: `sentTo == emptyList()`, no crash; `status` preserved.
  Traces: AC-2.

- **TC-AND-060-03 — Request serializes `username` key + CSRF header
  (contract/MockWebServer).** Type: contract (JVM, MockWebServer). Target: `AuthApi`
  + OkHttp stack. Preconditions: MockWebServer enqueues `200`
  `{"status":"sent","sent_to":["u***@x.com"]}`; CSRF cookie present. Steps: invoke
  `passwordlessStart`. Expected: recorded request path `POST /ui/passwordless/start`,
  body JSON `{"username":"..."}` (NOT `email`), header `X-CSRF-Token` present,
  `Content-Type: application/json`. Traces: AC-1.

- **TC-AND-060-04 — `422` validation maps to field error
  (contract/MockWebServer).** Type: contract (JVM). Target: repository +
  `ApiErrorMapper`. Preconditions: MockWebServer returns `422`
  `{"detail":[{"loc":["body","username"],"msg":"value is not a valid email address","type":"value_error"}]}`.
  Steps: invoke start. Expected: `ApiResult.HttpError(422, mappedMessage)`; ViewModel
  surfaces `identifierError`; phase stays `Entry`; never reaches `Confirmation`.
  Traces: AC-3, AC-6, AC-2.

- **TC-AND-060-05 — Network failure surfaces retryable error (unit + contract).**
  Type: unit/contract (JVM). Target: repository + ViewModel. Preconditions: API
  throws `IOException` (or MockWebServer `setBodyDelay` beyond call timeout). Steps:
  submit. Expected: `ApiResult.NetworkError`; `formError = Network` (retryable);
  Retry re-invokes the same dispatch; no auto-retry on 4xx. Traces: AC-6.

- **TC-AND-060-06 — Flaky/offline dev-host path (integration).** Type: integration
  (JVM/Robolectric, MockWebServer simulating ~20s timeout then success on retry).
  Target: ViewModel + retry policy (AND-016). Preconditions: first dispatch times
  out, Retry succeeds. Steps: submit → observe Network error → tap Retry. Expected:
  bounded-backoff applies to transport failure only; second attempt reaches
  `Confirmation`; no duplicate in-flight calls. Traces: AC-6, AC-1.

- **TC-AND-060-07 — Client validation gates the network (unit).** Type: unit (JVM).
  Target: ViewModel. Preconditions: MockK repo. Steps: `onEmailChange("")` (blank)
  then `onSubmit()`; separately `onEmailChange("alice")` (bare username) then
  `onSubmit()`. Expected: blank → `identifierError = Required`, repo `wasNot Called`;
  bare username → **accepted**, repo IS called (no email-format hard block).
  Traces: AC-3.

- **TC-AND-060-08 — Resend cooldown blocks network (unit, injected clock).** Type:
  unit (JVM, test dispatcher + injected `Clock`). Target: ViewModel. Preconditions:
  in `Confirmation` with `resendSecondsLeft = 30`. Steps: `onResend()` immediately,
  then advance virtual time to 0 and `onResend()` again. Expected: first resend makes
  **no** network call (`canResend == false`); after countdown reaches 0,
  `canResend == true` and resend dispatches once. Traces: AC-4.

- **TC-AND-060-09 — Defensive `429`/`Retry-After` cooldown (contract, OPTIONAL/
  unverified).** Type: contract (JVM, MockWebServer). Target: repository +
  ViewModel. Preconditions: MockWebServer returns `429` with `Retry-After: 60`
  (NOTE: undocumented behavior; defensive only). Steps: submit. Expected: if handled,
  `resendSecondsLeft` set from `Retry-After`, resend disabled, no auto-retry; if not
  handled, falls through to generic mapped error. Test asserts no crash either way.
  Traces: AC-4, AC-6.

- **TC-AND-060-10 — State machine + cooldown ticker (unit, Turbine).** Type: unit
  (JVM, Turbine + injected clock). Target: ViewModel `StateFlow`. Preconditions:
  repo returns success. Steps: `onEmailChange(valid) → onSubmit`; observe; advance
  ticker; `onChangeEmail`. Expected: `Entry → Sending → Confirmation`; ticker
  decrements to 0 enabling resend; `onChangeEmail` returns to `Entry` preserving
  `identifier`, stops ticker, clears error. Traces: AC-1, AC-4, AC-5.

- **TC-AND-060-11 — Confirmation renders identifier; failure never confirms
  (Compose-UI).** Type: Compose-UI (EMU). Target: `PasswordlessStartScreen` (fake
  state). Preconditions: state `Confirmation(identifier="alice@x.com", sentTo=["a***@x.com"])`.
  Steps: assert confirmation copy shows the identifier; render `sentTo` only when
  non-empty; then render a `formError` state and assert the screen is NOT in
  Confirmation. Expected: matches FR-3/FR-7. Traces: AC-2, AC-7-adjacent.

- **TC-AND-060-12 — Submit enable/disable + Sending lockout (Compose-UI).** Type:
  Compose-UI (EMU). Target: stateless screen. Preconditions: drive states blank /
  valid / `Sending`. Steps: assert submit disabled when blank, enabled when
  non-blank, and field+submit disabled with progress shown in `Sending`. Expected:
  matches FR-1/FR-2 and no double-dispatch. Traces: AC-1, AC-3.

- **TC-AND-060-13 — Accessibility semantics (Compose-UI / instrumented).** Type:
  Compose-UI + TalkBack assertions (EMU). Target: stateless screen. Preconditions:
  error state + cooldown-active confirmation. Steps: assert field error is associated
  via `semantics { error(...) }`; form-error banner is `liveRegion = Assertive`;
  confirmation transition announced; resend disabled exposes accessible reason
  ("available in {n} seconds"); touch targets ≥48dp; dynamic font scaling and RTL
  render without truncation/overlap. Expected: all pass. Traces: AC-8.

- **TC-AND-060-14 — No-PII redaction (unit/instrumented).** Type: unit (JVM) +
  optional instrumented log capture. Target: ViewModel/analytics + Timber tree.
  Preconditions: debug build, analytics fake. Steps: run a full submit→confirm flow.
  Expected: identifier and `sent_to` never appear as analytics property values nor in
  non-redacted logs; not persisted beyond `SavedStateHandle`. Traces: AC-7.

- **TC-AND-060-15 — ABI/API-skew smoke (instrumented/e2e, DEVICE).** Type:
  instrumented (DEVICE — physical A15, arm64-v8a, API 34). Target: full feature on
  real hardware. Preconditions: app installed on SM-A156U; MockWebServer or dev host
  reachable. Steps: run the happy-path submit→confirmation and one error path.
  Expected: identical behavior to EMU (API 35 / x86_64); no arm64-vs-x86 or
  API-34-vs-35 regressions (Moshi codegen, Compose rendering). MUST run on the
  physical device to catch ABI/API-level differences; EMU run is the baseline.
  Traces: AC-1, AC-2, AC-6.

### Coverage matrix

| AC | Description | Covered by |
|----|-------------|------------|
| AC-1 | Start triggers `POST …/start` with `username`, advances on 2xx | TC-01, TC-03, TC-06, TC-10, TC-12, TC-15 |
| AC-2 | Confirmation shown; failure never confirms | TC-01, TC-02, TC-04, TC-11, TC-15 |
| AC-3 | Validation gates network; bare username accepted | TC-04, TC-07, TC-12 |
| AC-4 | Resend + cooldown; defensive Retry-After | TC-08, TC-09, TC-10 |
| AC-5 | Change email returns to entry, preserves input, stops ticker | TC-10 |
| AC-6 | Error handling (network/422/throttle), retryable | TC-04, TC-05, TC-06, TC-09, TC-15 |
| AC-7 | No PII leakage (logs/analytics/persistence) | TC-14, TC-11 (state only) |
| AC-8 | Accessibility (error assoc, announce, reason, 48dp, dynamic type, RTL) | TC-13 |
