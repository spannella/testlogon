---
id: AND-054
title: "Registration: confirm + resend"
milestone: M2
epic: E08
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-053]
blocks: [AND-055]
---

# AND-054 — Registration: confirm + resend

## 1. Overview & Goal

This ticket delivers the **registration confirmation step** of the TestLogon native Android
sign-up flow. After AND-053 (`Registration: start`) submits `POST /ui/register/start` and the
backend responds with `verification_required = true` plus `delivery_medium` and (optionally)
`delivery_destination` (email or SMS), the user lands on a **Confirm code** screen. There they
enter the one-time verification code that was sent to their address/phone, the app calls
`POST /ui/register/confirm` (keyed on the registrant's `email` + `confirmation_code`), and on
success the account is activated. The screen also offers a **Resend** action backed by
`POST /ui/register/resend` so a user who never received the code (or whose code expired) can
request a new one without restarting registration.

> **Review note (AND-054):** This spec was re-verified against the backend OpenAPI
> (`/ui/register/confirm`, `/ui/register/resend`, `/ui/register/start`) and the web reference
> (`src/api/types.ts`, `src/api/endpoints/auth.ts`, `src/pages/Register.tsx`). The original draft
> mis-stated the request/response field names and invented backend-driven cooldown/expiry fields.
> The real contract keys confirm/resend on **`email`** (there is no `registration_id`/`challenge_id`),
> and the backend returns **no** `code_length`, `expires_at`, or `resend_cooldown_seconds`. All such
> claims are corrected inline below; see §16 for the full audit.

Scope of AND-054:

- The `RegisterConfirmScreen` Compose UI (OTP entry, resend with cooldown, inline errors,
  masked destination hint, expiry timer).
- `RegisterConfirmViewModel` exposing `StateFlow<RegisterConfirmUiState>` and one-shot events.
- `AuthApi`/`RegisterRepository` additions for `confirm` and `resend`, with DTOs and
  `ApiResult<T>` mapping (FastAPI `detail` handling).
- Navigation wiring from the start screen into confirm, and from confirm onward on success.

Out of scope (and their owners): the register **start** screen and `RegisterStartResp` mapping
(AND-053); debounced **email availability** check (AND-055); cookie jar, CSRF interceptor,
401-refresh authenticator, and `ApiResult` plumbing (AND-011/012/013/018 — consumed, not built
here); the reusable `OtpInput` composable (AND-020 — composed, not re-implemented). Successful
confirmation does **not** itself establish a logged-in session here; what happens after
activation (auto-login vs. route to login) is defined in §3 FR-8 and §5.

## 2. Context & References

- **Module:** `feature-auth`, package root `com.testlogon.android.feature.auth.register`.
  Depends on `core-ui` (`com.testlogon.android.core.ui`), `core-model`
  (`com.testlogon.android.core.model`), `core-network`
  (`com.testlogon.android.core.network`), `core-data` (`com.testlogon.android.core.data`).
- **Dependencies:**
  - **AND-053** — Registration: start. Owns `RegisterRoute.Start`, the start request, and the
    `RegisterStartResp` shape. **Corrected (verified against `RegisterStartResp` schema and
    `src/api/types.ts: RegisterStartResp`):** the real fields are `status` (string),
    `verification_required` (bool, default false), `delivery_medium` (nullable string),
    `delivery_destination` (nullable string), and `session_id` (nullable string). There is **no**
    `registration_id`/`challenge_id`, **no** `code_length`, **no** `expires_at`, and **no**
    `resend_cooldown_seconds` — those were draft inventions. AND-054 receives `email` (entered at
    start), `delivery_medium`, and `delivery_destination` as the confirm route's typed nav
    arguments and renders/uses them. The OTP length and any cooldown/expiry behavior are
    **client-side conventions only** (see §13, §16 Open assumptions), not backend-provided.
  - **AND-020** — Core input composables: `OtpInput` (N-digit entry + paste/auto-advance),
    `AppButton`, error text styles.
  - **AND-018** — `ApiResult<T>` / error types.
  - **AND-015** — FastAPI `detail` mapping (`string | [{msg}] | {code,...}`).
- **Web reference (corrected paths):** `src/api/endpoints/auth.ts` (`registerConfirm`,
  `registerResend`, `registerEmailCheck`, `registerStart` — there is no separate `register.ts`),
  `src/api/types.ts` (`RegisterConfirmReq/Resp`, `RegisterResendReq/Resp`, `delivery_method` enum
  `"email" | "sms"`), and `src/pages/Register.tsx` (the confirm/resend UX lives in the `"verify"`
  step of this single page — there is no dedicated confirm component). **Note:** the web client
  does **not** implement a resend cooldown timer or an expiry countdown; the Resend button is
  merely disabled while the request is in flight. The cooldown/expiry UX in this Android spec is a
  net-new client convention (§13, §16), not UX parity.
- **Backend:** FastAPI dev host `http://18.222.237.167:8000` (PLAINTEXT HTTP, unreliable dev
  host). OpenAPI at `/openapi.json`. Confirm/resend are **non-idempotent POSTs** (see §7 for
  retry policy). Registration is pre-auth: there is no authenticated session yet, but the
  `ui_csrf` cookie must still be echoed as `X-CSRF-Token` (handled
  by AND-012; the persistent cookie jar of AND-011 carries it). **Verified** against
  `src/api/client.ts`: every request reads the `ui_csrf` cookie into the `X-CSRF-Token` header and
  sends cookies via `credentials: "include"`. **Correction:** the web 401-refresh path only fires
  when the user is *already authenticated*; an unauthenticated 401 propagates directly. The Android
  AND-013 authenticator must therefore not try to refresh during registration (see §7).
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Navigation-Compose (single Activity), Hilt
  (KSP), Coroutines/Flow, Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15. minSdk 24 / target 35.

## 3. Functional Requirements

FR-1 **Entry & context display.** On entering the confirm screen with the start response args,
display the delivery channel (`delivery_medium`) and the `delivery_destination` hint (e.g.
`We sent a code via email to j••@example.com`). **Corrected:** the field is
`delivery_destination` (not `destination`), and it is **nullable** — the backend does not
guarantee a value, so when it is null/absent the client falls back to a generic message ("We sent
a verification code to your email."), matching `src/pages/Register.tsx`. **Unverified
assumption:** that `delivery_destination` is masked. The web client renders it verbatim and there
is no schema/code evidence of masking; the client must therefore treat it as potentially
sensitive (display only, never log) rather than assume it is pre-masked.

FR-2 **OTP entry.** Render the AND-020 `OtpInput`. Length is `uiState.codeLength`
(**client-side default 6 — unverified**, the backend does not return `code_length`; the web
`confirmation_code` field is a free-form string with no fixed length, and its `OtpInput`
defaults to 6 boxes). Paste and auto-advance are provided by AND-020. When the field reaches full
length, auto-submit (FR-3) **unless** `isSubmitting == true`. Because length is not backend-bound,
also allow explicit Confirm even if the entered length differs, defensively (see §13).

FR-3 **Confirm.** A primary `AppButton` ("Confirm") is enabled only when entered length ==
`codeLength` and `isSubmitting == false`. Tapping (or auto-submit) calls `onConfirm(code)`,
which invokes `POST /ui/register/confirm`. While in flight the button shows an inline spinner
and is disabled.

FR-4 **Wrong code → error.** A `4xx` confirm response (invalid/expired/mismatched code) clears
the OTP field, keeps the user on the screen, and surfaces a localized inline error below the
field mapped from the backend `detail` (see §5). The screen must distinguish at minimum:
invalid code, expired code, and too-many-attempts/locked.

FR-5 **Resend with cooldown.** A "Resend code" action calls `onResend()` →
`POST /ui/register/resend` with `{ email, delivery_method }` (see §5). On success it shows a
transient confirmation ("New code sent") and refreshes the displayed `delivery_destination` from
`RegisterResendResp.delivery_destination`/`delivery_medium`. **Corrected:** the resend cooldown
is a **purely client-side convention** — the backend response contains **no**
`resend_cooldown_seconds` and **no** `expires_at` (verified against `RegisterResendResp`:
`{status, delivery_medium?, delivery_destination?}`). The web reference (`Register.tsx
handleResend`) has **no** cooldown timer at all; it only disables the button while the request is
in flight. This Android spec adds a UI-side cooldown (default 30s) as a usability/anti-spam
measure: it is disabled and shows a live countdown from a client-chosen `resendCooldownSeconds`
default, driven by a UI ticker derived from an absolute `resendAvailableAtEpochMs`, re-enabling at
0; the countdown survives configuration changes (state in the ViewModel). If the backend later
enforces a server-side cooldown via 429 + `Retry-After`, treat the server value as authoritative
(§13).

FR-6 **Expiry timer.** **Corrected to optional/client-only.** The backend returns **no**
`expires_at` on start, confirm, or resend (verified against `RegisterStartResp`,
`RegisterConfirmResp`, `RegisterResendResp`), and the web client shows no expiry countdown. The
expiry timer is therefore **deferred / best-effort**: only if a future `expires_at` is added to
the start/resend response should the client show "Code expires in mm:ss" and, on expiry, disable
Confirm and surface "This code has expired — resend". For M2 the field is absent, so the expiry
UI is not rendered; do not block Confirm on a non-existent expiry. (See §13, §16.)

FR-7 **Loading / offline / error surfaces.** Use the AND-021 state composables for full-screen
states where appropriate; inline surfaces for field-level errors. A network failure on confirm
or resend shows a retryable inline error (it does **not** clear a valid entered code on a pure
network/timeout failure, only on a server-rejected code per FR-4).

FR-8 **Success → continuation.** **Corrected against `RegisterConfirmResp`
(`{status, session_id?, mfa_setup?, sms_phone?}`) and `Register.tsx handleConfirm`.** There is no
`confirmed` or `session_started` boolean. On `200` confirm:
- The response carries `status` (string), an optional `session_id`, an optional `mfa_setup`
  string array (e.g. `["sms","totp"]`), and an optional `sms_phone`.
- **Session established** is determined by **`session_id != null`** (not a boolean flag). When a
  `session_id` is present, the backend has logged the user in (the web client immediately calls
  `GET /ui/me` and treats the user as authenticated).
- **MFA setup follow-on:** when `session_id` is present **and** `mfa_setup` is non-empty, the user
  selected MFA enrollment at start and must complete SMS/TOTP enrollment before entering the app
  (web routes to an `"mfa"` step). For M2 AND-054 scope, emit `RegisterConfirmEvent.Authenticated`
  carrying `mfaSetup`/`smsPhone` so the nav graph can route to the (separate) MFA-setup
  destination when `mfaSetup` is non-empty, or straight to the authenticated graph when it is
  empty. (The MFA-setup screens themselves are out of scope here — note for AND-053/the MFA epic.)
- **No session:** when `session_id` is null, emit `RegisterConfirmEvent.Confirmed`; navigate to
  the Login screen (`LoginRoute`) with a one-shot success message ("Account confirmed — please
  sign in") and the email prefilled. **Note:** the email is the value the user entered (it is *not*
  returned by `RegisterConfirmResp`); carry it via nav args, not the response.
- **Default for M2:** the web flow with `verification_required` confirms then typically returns a
  `session_id` (auto-login). Implement both branches; gate on `session_id` presence rather than a
  fabricated flag.

FR-9 **Back / cancel.** System back returns to the start screen (AND-053). Re-entering start and
re-submitting begins a fresh registration; the confirm screen does not silently reuse a stale
`registration_id`.

## 4. Technical Design

Single-Activity Navigation-Compose. The confirm destination is a typed route carrying the
minimum context produced by AND-053:

```kotlin
// feature-auth/navigation
sealed interface RegisterRoute {
    @Serializable data object Start : RegisterRoute
    @Serializable data class Confirm(
        // CORRECTED: confirm/resend are keyed on the registrant's email — there is no
        // registration_id/challenge_id in the backend contract. Email is entered at start
        // (AND-053) and is NOT returned by any register response, so it MUST be carried here.
        val email: String,
        val deliveryMedium: String?,        // "email" | "sms" | null (RegisterStartResp.delivery_medium)
        val deliveryDestination: String?,   // nullable hint (RegisterStartResp.delivery_destination)
        // MFA flags chosen at start; needed so resend can re-send the SAME request shape
        // (RegisterResendReq carries enable_sms_mfa/enable_totp_mfa/phone).
        val enableSmsMfa: Boolean = false,
        val enableTotpMfa: Boolean = false,
        val phone: String? = null,
        // CLIENT-ONLY conventions (not backend-provided): OTP length + resend cooldown.
        val codeLength: Int = 6,
        val resendCooldownSeconds: Int = 30,
    ) : RegisterRoute
}

fun NavGraphBuilder.registerGraph(navController: NavController) {
    composable<RegisterRoute.Confirm> {
        val vm: RegisterConfirmViewModel = hiltViewModel()
        val state by vm.uiState.collectAsStateWithLifecycle()
        LaunchedEffect(Unit) {
            vm.events.collect { ev ->
                when (ev) {
                    is RegisterConfirmEvent.Confirmed ->
                        navController.navigate(LoginRoute(prefillEmail = ev.email)) {
                            popUpTo(RegisterRoute.Start) { inclusive = true }
                        }
                    is RegisterConfirmEvent.Authenticated ->
                        // mfaSetup non-empty ⇒ route to MFA-setup destination first
                        // (out of scope here); otherwise straight to the authed graph.
                        navController.navigate(
                            if (ev.mfaSetup.isEmpty()) AuthenticatedGraph else MfaSetupRoute(ev.smsPhone)
                        ) {
                            popUpTo(0) { inclusive = true }
                        }
                }
            }
        }
        RegisterConfirmScreen(
            state      = state,
            onCodeChange = vm::onCodeChange,
            onConfirm  = vm::onConfirm,
            onResend   = vm::onResend,
            onBack     = navController::navigateUp,
        )
    }
}
```

```kotlin
// feature-auth/register
@Composable
fun RegisterConfirmScreen(
    state: RegisterConfirmUiState,
    onCodeChange: (String) -> Unit,
    onConfirm: (String) -> Unit,
    onResend: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
)
```

```kotlin
@HiltViewModel
class RegisterConfirmViewModel @Inject constructor(
    private val repo: RegisterRepository,
    savedStateHandle: SavedStateHandle,            // typed RegisterRoute.Confirm args
    private val clock: Clock,                       // injectable for tests
) : ViewModel() {

    private val args = savedStateHandle.toRoute<RegisterRoute.Confirm>()
    private val _uiState = MutableStateFlow(RegisterConfirmUiState.from(args))
    val uiState: StateFlow<RegisterConfirmUiState> = _uiState.asStateFlow()

    private val _events = Channel<RegisterConfirmEvent>(Channel.BUFFERED)
    val events: Flow<RegisterConfirmEvent> = _events.receiveAsFlow()

    fun onCodeChange(code: String)
    fun onConfirm(code: String)
    fun onResend()
}
```

The cooldown/expiry tickers are 1s `flow { while … emit; delay(1000) }` collected in the
ViewModel scope and folded into `uiState` (remaining seconds derived from absolute epoch
targets so they recompute correctly after process death / config change).

## 5. API Contract

Two endpoints, both `POST`, both Moshi-mapped, both returning `ApiResult<T>`. The `ui_csrf`
cookie → `X-CSRF-Token` header and cookie jar are applied by core-network interceptors
(AND-011/012); this ticket only defines payloads.

```kotlin
// core-network: AuthApi (register surface)
interface RegisterApi {
    @POST("/ui/register/confirm")
    suspend fun confirm(@Body body: RegisterConfirmReq): Response<RegisterConfirmResp>

    @POST("/ui/register/resend")
    suspend fun resend(@Body body: RegisterResendReq): Response<RegisterResendResp>
}
```

> **CORRECTED — the entire contract below was wrong in the draft.** Verified against OpenAPI
> schemas `RegisterConfirmReq/Resp`, `RegisterResendReq/Resp` and the web DTOs in
> `src/api/types.ts`. There is **no** `registration_id`/`challenge_id`, **no** `code` field
> (it's `confirmation_code`), **no** `confirmed`/`session_started`/`sent` booleans, **no**
> `expires_at`/`resend_cooldown_seconds`. Confirm/resend are keyed on **`email`**. The
> `delivery_method` enum is **lowercase** `"email"`/`"sms"`.

**Confirm — request (`RegisterConfirmReq`; required: `email`, `confirmation_code`):**
```json
{ "email": "jane@example.com", "confirmation_code": "123456" }
```

**Confirm — success `200` (`RegisterConfirmResp`; required: `status`):**
```json
{ "status": "confirmed", "session_id": "sess_...", "mfa_setup": ["totp"], "sms_phone": null }
```
`session_id` present ⇒ auto-logged-in; `mfa_setup` non-empty ⇒ MFA enrollment follow-on (FR-8).
`status` is a free-form string; do not assume specific values beyond presence.

**Resend — request (`RegisterResendReq`; required: `email`):**
```json
{ "email": "jane@example.com", "delivery_method": "email",
  "phone": null, "enable_sms_mfa": false, "enable_totp_mfa": false }
```
`delivery_method` defaults to `"email"`; the web client forwards the MFA flags/phone captured at
start (`Register.tsx handleResend`).

**Resend — success `200` (`RegisterResendResp`; required: `status`):**
```json
{ "status": "sent", "delivery_medium": "email", "delivery_destination": "j••@example.com" }
```
No `expires_at`, no cooldown field — see FR-5/FR-6.

```kotlin
@JsonClass(generateAdapter = true)
data class RegisterConfirmReq(
    val email: String,
    @Json(name = "confirmation_code") val confirmationCode: String,
)
@JsonClass(generateAdapter = true)
data class RegisterConfirmResp(
    val status: String,
    @Json(name = "session_id") val sessionId: String? = null,
    @Json(name = "mfa_setup") val mfaSetup: List<String>? = null,
    @Json(name = "sms_phone") val smsPhone: String? = null,
)
@JsonClass(generateAdapter = true)
data class RegisterResendReq(
    val email: String,
    @Json(name = "delivery_method") val deliveryMethod: String = "email",  // "email" | "sms"
    val phone: String? = null,
    @Json(name = "enable_sms_mfa") val enableSmsMfa: Boolean = false,
    @Json(name = "enable_totp_mfa") val enableTotpMfa: Boolean = false,
)
@JsonClass(generateAdapter = true)
data class RegisterResendResp(
    val status: String,
    @Json(name = "delivery_medium") val deliveryMedium: String? = null,
    @Json(name = "delivery_destination") val deliveryDestination: String? = null,
)
```

**Error mapping (per AND-015).** **Corrected/grounded:** the OpenAPI declares only `200` and
`422 HTTPValidationError` for both endpoints; no `400`/`404`/`410`/`429` is documented. FastAPI's
validation failure is **`422`** (not `400`), with `detail` = a **list** of
`[{ "msg": "...", "type": "...", "loc": [...] }]`. Business errors come back as `4xx` with
`detail` either a **string** (the web reads `err.detail` verbatim and shows it — see
`Register.tsx handleConfirm`/`handleResend` and `normalizeErrorDetail` in `client.ts`) or an
**object** `{ "code": "...", ... }`. The specific `code` strings below (`invalid_code`,
`expired_code`, etc.) are **unverified assumptions** — they are not in the OpenAPI or web source;
implement the mapping defensively and fall back to showing the server `detail` string when no
known code matches (this is exactly what the web client does).

| HTTP / detail.code (assumed)         | UiError                          | User message                                   |
|--------------------------------------|----------------------------------|------------------------------------------------|
| 422 (validation list)                | `InvalidCode`                    | First `detail[].msg`, e.g. "Confirmation code is required" |
| 4xx, code `invalid_code` / unknown   | `InvalidCode`                    | server `detail` string, fallback "That code isn't correct. Check and try again."|
| 4xx, code `expired_code` *(assumed)* | `ExpiredCode`                    | server `detail`, fallback "This code has expired — resend a new one."    |
| 429 *(assumed; not documented)*      | `Locked(retryAfter)`             | server `detail`, fallback "Too many attempts. Try again in N min."       |
| 4xx, code `registration_not_found` *(assumed)* | `SessionExpired`       | server `detail`, fallback "Registration expired — please start over."    |
| 5xx / timeout / IO / status 0        | `Network`                        | "Couldn't reach the server. Try again."        |

`Locked` reads `Retry-After` (header or `detail`) **if present**; `SessionExpired` emits an event
that pops to start (FR-9). When the server returns a `detail` string the client **prefers it
verbatim** for parity with the web client, only substituting a localized fallback when `detail` is
absent.

## 6. Data & State Management

> **Corrected fields:** `email` is **non-null** (required to call confirm/resend); `delivery`
> values are lowercase `"email"/"sms"`; `maskedDestination` renamed to `deliveryDestination`
> (nullable, not guaranteed masked). `expiresAtEpochMs` is **null in M2** (backend returns no
> expiry); the expiry ticker is dormant unless a future `expires_at` appears.

```kotlin
data class RegisterConfirmUiState(
    val email: String,                    // required; entered at start, carried via nav args
    val delivery: String?,                // "email" | "sms" | null (delivery_medium)
    val deliveryDestination: String?,     // nullable hint; treat as sensitive, may be unmasked
    val code: String = "",
    val codeLength: Int = 6,              // client default; not backend-provided
    val isSubmitting: Boolean = false,
    val isResending: Boolean = false,
    val resendAvailableAtEpochMs: Long = 0L,   // 0 => available; client-side cooldown only
    val expiresAtEpochMs: Long? = null,        // null in M2 (no backend expiry)
    val resendCountdownSeconds: Int = 0,        // derived by ticker
    val expiryCountdownSeconds: Int? = null,    // derived by ticker; null when no expiry
    val error: RegisterConfirmError? = null,
    val transientMessage: String? = null,       // "New code sent"
) {
    // expiryCountdownSeconds == null (no expiry) must NOT block Confirm.
    val canConfirm get() = code.length == codeLength && !isSubmitting && expiryCountdownSeconds != 0
    val canResend  get() = resendCountdownSeconds == 0 && !isResending
    companion object { fun from(args: RegisterRoute.Confirm): RegisterConfirmUiState = … }
}

sealed interface RegisterConfirmEvent {
    // No session_id ⇒ route to Login (carry email for prefill).
    data class Confirmed(val email: String) : RegisterConfirmEvent
    // session_id present ⇒ logged in. mfaSetup non-empty ⇒ route to MFA-setup first.
    data class Authenticated(val mfaSetup: List<String>, val smsPhone: String?) : RegisterConfirmEvent
}
```

**Persistence:** none beyond `SavedStateHandle` (the typed nav args) and in-memory ViewModel
state. No Room, no DataStore — registration is transient. The OTP code is never persisted to
disk and is cleared from state on success and on FR-4 server rejection. Absolute epoch targets
(`resendAvailableAtEpochMs`, `expiresAtEpochMs`) are derived from the start/resend responses so
cooldown/expiry recompute correctly across config change and process death (they live in
`SavedStateHandle` as primitives).

`RegisterRepository` (single suspend surface) wraps `RegisterApi` and returns `ApiResult`:

```kotlin
class RegisterRepository @Inject constructor(private val api: RegisterApi, private val errorMapper: ApiErrorMapper) {
    suspend fun confirm(req: RegisterConfirmReq): ApiResult<RegisterConfirmResp>
    suspend fun resend(req: RegisterResendReq): ApiResult<RegisterResendResp>
}
```

## 7. Error Handling & Resilience

- **Timeouts:** rely on the OkHttp client (AND-009, ~20s) for this unreliable dev host. Confirm
  and resend each surface a `Network` error on timeout/IO without clearing a valid code (FR-7).
- **No auto-retry on POST.** `/ui/register/confirm` and `/ui/register/resend` are
  non-idempotent; the bounded-backoff retry of AND-016 applies only to idempotent GETs and must
  **not** wrap these calls. The user retries explicitly (Confirm button / Resend).
- **Double-submit guard:** `isSubmitting` / `isResending` gate the actions; concurrent calls are
  ignored. Auto-submit (FR-2) is suppressed while `isSubmitting`.
- **401 handling:** registration is pre-auth; a 401 is not expected. **Corrected (per
  `client.ts`):** the web client only attempts a session refresh on 401 *when already
  authenticated*; an unauthenticated 401 propagates straight to the caller. The Android AND-013
  authenticator must mirror this — do **not** trigger a refresh for the register endpoints (no
  session exists). A 401/403 here maps to `SessionExpired` → pop to start, with no refresh loop.
- **Stale registration:** `registration_not_found` (FR-9 / §5) routes back to start with a clear
  message; the confirm screen never silently swallows it.
- **CSRF:** if the `ui_csrf` cookie was lost, a CSRF rejection maps to `SessionExpired` (start
  over) — the confirm screen cannot mint a CSRF token itself.

## 8. Security & Privacy

- The OTP code and full destination address/phone are never logged, never persisted to disk,
  and never written to analytics. Only the backend-provided **masked** destination is held in
  state/UI.
- The confirm screen marks the OTP entry as sensitive: no autofill of arbitrary content (SMS
  OTP autofill via the AND-020 component's `autofillType = SmsOtpCode` is permitted and
  preferred), and `OtpInput` should not surface the code in IME suggestion history.
- All traffic to the dev host is plaintext HTTP (dev only); production must be HTTPS. The cookie
  jar (AND-011) must not persist the `ui_csrf`/session cookies in plaintext beyond app-private
  storage; no special handling is added here beyond what core-network provides.
- No PII is included in telemetry events (§10) — only delivery channel and outcome enums.

## 9. Accessibility & i18n

- All strings live in `strings.xml` (`registration_confirm_*`), no hard-coded copy. Masked
  destination, cooldown ("Resend in %1\\$ds"), and expiry ("Expires in %1\\$s") use plurals/
  format args.
- `OtpInput` exposes a single logical edit field with a `contentDescription` ("Verification
  code, N digits"); per-digit boxes are not individually focus-announced as separate fields.
- Errors are associated with the field via `semantics { error(message) }` and announced via a
  `liveRegion = Assertive` status node so TalkBack reads invalid/expired code on appearance.
- Live countdowns use `liveRegion = Polite` and are throttled (announce on change, not every
  second) to avoid TalkBack spam.
- Touch targets ≥ 48dp; supports dynamic font scaling and dark theme via Material 3 (AND-019).
- Confirm button reflects `enabled` state to accessibility; disabled-with-reason is conveyed in
  the helper text, not by color alone.

## 10. Telemetry & Logging

Structured events via the app's analytics facade (no PII):

| Event                          | Properties                                      |
|--------------------------------|-------------------------------------------------|
| `register_confirm_shown`       | `delivery`                                       |
| `register_confirm_submitted`   | `delivery`                                       |
| `register_confirm_succeeded`   | `delivery`, `session_started` (derived: `session_id != null`), `mfa_required` (`mfa_setup` non-empty) |
| `register_confirm_failed`      | `delivery`, `error` (enum: invalid/expired/locked/network) |
| `register_resend_tapped`       | `delivery`                                        |
| `register_resend_succeeded`    | `delivery`                                        |
| `register_resend_failed`       | `delivery`, `error`                               |

Network logging uses the OkHttp logging interceptor (AND-009) at `BODY` only in debug builds;
the confirm/resend request bodies (which contain the code) must be redacted or the interceptor
restricted to non-`/register/confirm` paths in debug. No code value appears in Logcat.

## 11. Testing Strategy

**Unit (`RegisterConfirmViewModel`, JVM, `core-testing` + MockWebServer AND-046):**
- Correct code → `confirm` 200 with `session_id=null` → emits `Confirmed(email)`; with
  `session_id` present and empty `mfa_setup` → emits `Authenticated(mfaSetup=[])`; with
  `session_id` present and non-empty `mfa_setup` → emits `Authenticated(mfaSetup=[...])`.
- Wrong code → 4xx with `detail` string (or 422 validation list) → `error = InvalidCode` showing
  the server `detail`, code field cleared, stays on screen (covers acceptance "wrong code shows
  error").
- Expired code → 4xx code `expired_code` *(assumed mapping)* → `ExpiredCode`. (No expiry timer in
  M2; do not assert on a countdown.)
- `429` *(assumed; undocumented)* with `Retry-After` → `Locked` with parsed retry seconds.
- Resend success → cooldown set, `resendCountdownSeconds` counts down to 0 then `canResend`
  true; `transientMessage = "New code sent"` (covers "resend works").
- Resend during cooldown is a no-op; double-submit guarded by `isSubmitting`.
- Timeout/IO on confirm → `Network` error and code **not** cleared.
- Cooldown/expiry derived correctly from absolute epoch after simulated config change
  (re-create ViewModel from `SavedStateHandle`) using an injected fake `Clock`.

**Repository contract tests (AND-047 pattern):** verify `RegisterConfirmReq`/`RegisterResendReq`
JSON shapes and `detail` → `RegisterConfirmError` mapping for string / list / object variants.

**Compose UI tests (AND-048 pattern):**
- Entering full-length code triggers confirm; success navigates to login with success banner.
- Wrong code shows the inline error and clears the field.
- Resend disabled with visible countdown, re-enables at 0.
- Confirm disabled when code incomplete or expired.

All tests run in CI (AND-050). MockWebServer fixtures live alongside the AND-046 harness.

## 12. Dependencies & Sequencing

- **Hard dep — AND-053** (Registration: start): provides the start screen, the
  `RegisterStartResp` fields that become this screen's nav args, and the `RegisterRoute` graph
  this ticket extends. Must merge first.
- **Consumes:** AND-020 (`OtpInput`/`AppButton`), AND-021 (state composables), AND-018
  (`ApiResult`), AND-015 (`detail` mapping), AND-011/012/013 (cookie jar, CSRF, refresh),
  AND-009 (OkHttp timeouts), AND-019 (theme), AND-022 (nav host).
- **Blocks — AND-055** (email availability check) builds on the same register flow/screens and
  conventions established here; AND-055 also depends on AND-053 but should land after AND-054 to
  reuse the register API surface and error mapping.
- **Sequencing:** AND-053 → AND-054 → AND-055.

## 13. Risks & Open Questions

- **Correlation key — RESOLVED.** Verified: confirm/resend are keyed on **`email`** +
  `confirmation_code`/`delivery_method`. There is no `registration_id`/`challenge_id` anywhere in
  the contract. The email must be carried from the start screen via nav args (it is not returned
  by any register response).
- **Auto-login on confirm — RESOLVED (mechanism).** `/ui/register/confirm` returns an optional
  `session_id`; when present the user is logged in (the web client then calls `GET /ui/me`).
  Implementation gates on `session_id` presence (FR-8). **Still open:** whether the dev backend
  always returns a `session_id` for the `verification_required` path, or sometimes omits it
  (route-to-login). Both branches are implemented.
- **MFA follow-on — open.** `RegisterConfirmResp.mfa_setup` can request SMS/TOTP enrollment after
  confirm. The enrollment screens are out of AND-054 scope; this ticket only emits the event with
  `mfaSetup`/`sms_phone`. Confirm routing/ownership with the MFA epic.
- **Cooldown source of truth:** the backend currently returns **no** cooldown/expiry fields, so
  the client cooldown is purely advisory. If the backend later enforces a server-side cooldown via
  429 + `Retry-After`, treat the server value as authoritative when present.
- **SMS OTP autofill:** SMS Retriever / autofill reliability on the plaintext dev host is
  untested; if it misbehaves, fall back to manual entry only.
- **Code length:** assumed 6 — **client-side default only**; the backend returns no `code_length`
  and the web `confirmation_code` is a free-form string. Confirm the backend doesn't vary length by
  channel before hard-coding 6; the Confirm button should degrade gracefully if the real code
  length differs (allow manual submit).

## 14. Acceptance Criteria

AC-1 Entering the **correct** code and tapping Confirm calls `POST /ui/register/confirm` with
`{email, confirmation_code}`, the account is confirmed, and the app navigates onward (to Login
with a success message when `session_id` is absent, or to the authenticated graph — via MFA-setup
when `mfa_setup` is non-empty — when `session_id` is present).
*(Backlog: "Correct code confirms account.")*

AC-2 **Resend** invokes `POST /ui/register/resend`, shows a "New code sent" confirmation, and
starts/refreshes the cooldown timer; the action is disabled during cooldown and re-enables at 0.
*(Backlog: "resend works.")*

AC-3 Entering a **wrong/expired** code shows a clear inline error (invalid vs. expired vs.
locked, mapped from `detail`), clears the field, and keeps the user on the confirm screen.
*(Backlog: "wrong code shows error.")*

AC-4 The screen shows the `delivery_destination` hint when the backend provides one (falling back
to a generic message when it is null), and Confirm is disabled when the code is incomplete. A live
expiry countdown is shown **only if** the backend supplies `expires_at` (absent in M2 — see
FR-6/§16); its absence must not block Confirm.

AC-5 Confirm/resend never auto-retry (non-idempotent POSTs); timeouts surface a retryable
network error without clearing a valid entered code.

AC-6 No OTP code or unmasked destination appears in logs, telemetry, or persistent storage.

AC-7 All listed unit, repository-contract, and Compose UI tests pass in CI.

## 15. Definition of Done

- `RegisterConfirmScreen`, `RegisterConfirmViewModel`, `RegisterConfirmUiState`/`Event`/`Error`,
  and the `RegisterRoute.Confirm` nav wiring implemented under
  `com.testlogon.android.feature.auth.register`.
- `RegisterApi.confirm`/`resend` + DTOs added to `core-network`; `RegisterRepository` returns
  `ApiResult<T>` with `detail` mapping (AND-015).
- All strings externalized; TalkBack and dynamic-font verified per §9.
- Telemetry events emitted per §10 with no PII; network logging redacts the code.
- Unit, repository-contract, and Compose UI tests (per §11) added and green in CI (AND-050).
- All §14 acceptance criteria demonstrably met against the dev backend
  (`http://18.222.237.167:8000`) or MockWebServer fixtures.
- Code passes lint/detekt/ktlint (AND-005); merged to `android-port`.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer. Sources: **OAPI** =
`reference/openapi.index.txt` / `reference/openapi.pretty.json` (`components.schemas.<Name>`);
**FE** = `reference/src/...`.

1. **Endpoint `POST /ui/register/confirm` exists.** Verdict: **Verified.** Source: OAPI
   `POST /ui/register/confirm | op=register_confirm_... | req=RegisterConfirmReq | resp=200:RegisterConfirmResp;422:HTTPValidationError`; FE `src/api/endpoints/auth.ts: registerConfirm`.
2. **Endpoint `POST /ui/register/resend` exists.** Verdict: **Verified.** Source: OAPI
   `POST /ui/register/resend | req=RegisterResendReq | resp=200:RegisterResendResp;422:HTTPValidationError`; FE `src/api/endpoints/auth.ts: registerResend`.
3. **Both are POST.** Verdict: **Verified.** Source: OAPI index lines above (method column = POST).
4. **Confirm request fields are `email` + `confirmation_code`** (NOT `registration_id`/`challenge_id`/`code`).
   Verdict: **Corrected.** Source: OAPI `RegisterConfirmReq` (`required: [email, confirmation_code]`);
   FE `src/api/types.ts: RegisterConfirmReq` and `src/pages/Register.tsx: handleConfirm`.
5. **Confirm response fields are `status` (req'd), `session_id?`, `mfa_setup?: string[]`, `sms_phone?`**
   (NOT `confirmed`/`session_started`/`email`). Verdict: **Corrected.** Source: OAPI
   `RegisterConfirmResp` (`required: [status]`); FE `src/api/types.ts: RegisterConfirmResp`.
6. **Session-established is signalled by `session_id != null`, not a `session_started` boolean.**
   Verdict: **Corrected.** Source: FE `src/pages/Register.tsx: handleConfirm` (`if (resp.session_id) { ... getMe(); login(...) }`).
7. **`mfa_setup` drives an MFA-enrollment follow-on (SMS/TOTP) after confirm.** Verdict: **Verified.**
   Source: FE `src/pages/Register.tsx: handleConfirm` (`mfaSetup.length > 0 → setStep("mfa")`) and the `"mfa"` step block.
8. **Confirm response does NOT return the user's email.** Verdict: **Verified** (so email must be
   carried via nav args). Source: OAPI `RegisterConfirmResp` (no `email` property); FE same.
9. **Resend request fields are `email` (req'd) + `delivery_method` ("email"|"sms", default "email") + `phone?` + `enable_sms_mfa` + `enable_totp_mfa`** (NOT `registration_id`/`delivery`).
   Verdict: **Corrected.** Source: OAPI `RegisterResendReq` (`required: [email]`, `delivery_method` enum/default);
   FE `src/api/types.ts: RegisterResendReq` and `src/pages/Register.tsx: handleResend`.
10. **Resend response fields are `status` (req'd), `delivery_medium?`, `delivery_destination?`**
    (NOT `sent`/`delivery`/`destination`/`expires_at`/`resend_cooldown_seconds`). Verdict: **Corrected.**
    Source: OAPI `RegisterResendResp` (`required: [status]`); FE `src/api/types.ts: RegisterResendResp`.
11. **`delivery_method`/medium enum values are lowercase `"email"`/`"sms"`** (NOT `"EMAIL"`/`"SMS"`).
    Verdict: **Corrected.** Source: OAPI `RegisterResendReq.delivery_method.enum = ["email","sms"]`; FE same.
12. **Start response (`RegisterStartResp`) fields are `status`, `verification_required`, `delivery_medium?`, `delivery_destination?`, `session_id?`**
    (NOT `delivery`/`destination`/`registration_id`/`challenge_id`/`code_length`/`expires_at`/`resend_cooldown_seconds`).
    Verdict: **Corrected.** Source: OAPI `RegisterStartResp`; FE `src/api/types.ts: RegisterStartResp`.
13. **No `code_length` is backend-provided; OTP length (6) is a client default.** Verdict: **Corrected
    (unverified default).** Source: absence in OAPI `RegisterStartResp`/`RegisterConfirmReq`; FE `confirmation_code` is a plain string (`confirmSchema` in `Register.tsx`).
14. **No backend resend cooldown / `expires_at`; the web client has no cooldown or expiry timer.**
    Verdict: **Corrected.** Source: absence in OAPI `RegisterResendResp`/`RegisterStartResp`/`RegisterConfirmResp`;
    FE `src/pages/Register.tsx: handleResend` (button disabled only while `resendLoading`, no timer).
15. **`delivery_destination` is not guaranteed masked.** Verdict: **Unverified-assumption (treat as
    sensitive).** Source: OAPI `RegisterResendResp.delivery_destination` is a nullable string with no mask
    semantics; FE renders it verbatim (`Register.tsx` deliveryInfo). No masking found.
16. **CSRF: `ui_csrf` cookie echoed as `X-CSRF-Token`, cookies sent on every request.** Verdict: **Verified.**
    Source: FE `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`, `credentials: "include"`).
17. **401-refresh does NOT fire for unauthenticated requests** (so no refresh during registration).
    Verdict: **Corrected.** Source: FE `src/api/client.ts` (`if (res.status === 401) { ... if (!isAuthenticated) throw ApiError(401, ...) }`).
18. **Error `detail` shape is `string | [{msg,type,loc}] | {code,...}`; validation failures are HTTP 422.**
    Verdict: **Verified / partially corrected (422 not 400).** Source: OAPI both endpoints `resp=...;422:HTTPValidationError`;
    FE `src/api/client.ts: normalizeErrorDetail` (string / array-of-`{msg}` / object-`{code}`).
19. **The web client shows the raw `detail` string to the user on confirm/resend errors.** Verdict:
    **Verified.** Source: FE `src/pages/Register.tsx: handleConfirm`/`handleResend` (`err.detail || fallback`).
20. **Specific business error codes `invalid_code`/`expired_code`/`too_many_attempts`/`registration_not_found` and HTTP 410/429/404 mappings.**
    Verdict: **Unverified-assumption.** Source: none — not present in OAPI (only 200/422) or FE. Implemented defensively with `detail`-string fallback.
21. **Web persists pending registration in `localStorage` (`register-pending`).** Verdict: **Verified**
    (informational; Android intentionally uses `SavedStateHandle` instead). Source: FE `src/pages/Register.tsx` (`REGISTER_STORAGE_KEY`).
22. **`/ui/register/check` is the email-availability endpoint (AND-055 scope).** Verdict: **Verified**
    (clarifies it is not part of confirm/resend). Source: OAPI `POST /ui/register/check | req=RegisterEmailCheckReq | resp=200:RegisterEmailCheckResp`; FE `auth.ts: registerEmailCheck`.
23. **Framework: Navigation-Compose typed routes via `@Serializable` + `toRoute`/`SavedStateHandle`.**
    Verdict: **Verified (framework ref).** Source: Android docs — https://developer.android.com/guide/navigation/design/type-safety
24. **Framework: SMS OTP autofill via `autofillType = SmsOtpCode`.** Verdict: **Unverified-assumption
    on this host (framework exists).** Framework ref: https://developer.android.com/identity/sms-otp-autofill ; reliability over plaintext HTTP dev host untested.
25. **Framework: cookie persistence in app-private storage (OkHttp cookie jar, AND-011).** Verdict:
    **Verified (framework ref).** Source: OkHttp docs — https://square.github.io/okhttp/features/calls/#cookies ; FE parity via `credentials: "include"` (`client.ts`).

### Corrections made

- §1/§2/§4/§5/§6/§13/§14: removed `registration_id`/`challenge_id` correlation keys; confirm/resend
  are keyed on **`email`** (+ `confirmation_code` / `delivery_method`). [Citations 4, 9, 12]
- §5: confirm request field `code` → **`confirmation_code`**. [Citation 4]
- §5/§6/§8(FR-8)/§10/§11/§14: confirm response `confirmed`/`session_started`/`email` →
  **`status` + `session_id?` + `mfa_setup?` + `sms_phone?`**; session detected via `session_id != null`;
  added MFA-setup follow-on. [Citations 5, 6, 7, 8]
- §5: resend request `{registration_id, delivery}` → **`{email, delivery_method, phone?, enable_sms_mfa, enable_totp_mfa}`**;
  resend response `{sent, delivery, destination, expires_at, resend_cooldown_seconds}` →
  **`{status, delivery_medium?, delivery_destination?}`**. [Citations 9, 10]
- §1/§2/§3(FR-1): `delivery`/`destination`/`maskedDestination` → **`delivery_medium`/`delivery_destination`** (nullable, not guaranteed masked). [Citations 12, 15]
- §3(FR-5/FR-6)/§6: backend-driven cooldown/expiry fields removed; cooldown is a client-only convention,
  expiry deferred (no backend `expires_at`). [Citation 14]
- §2(enum): delivery values lowercased `"email"`/`"sms"`. [Citation 11]
- §2/§7: 401-refresh does not run for unauthenticated register calls. [Citation 17]
- §5/§11: validation error is HTTP **422** (list of `{msg}`), not 400; show server `detail` verbatim
  with localized fallback. [Citations 18, 19]
- §2: web reference paths corrected to `src/api/endpoints/auth.ts` + `src/pages/Register.tsx`
  (no `register.ts`, no separate confirm component). [Citations 1, 2]

### Open assumptions

- **OTP code length = 6** — client default; backend exposes no `code_length` and `confirmation_code`
  is a free-form string. Why unverifiable: not in OAPI or FE. Mitigation: allow manual submit if length differs. [Citation 13]
- **Resend cooldown (30s) and any expiry countdown** — net-new client UX; backend returns neither.
  Why unverifiable: fields absent from all register responses. Reconcile with server `Retry-After` if a 429 cooldown is later added. [Citation 14]
- **`delivery_destination` is masked** — assumed for display, but unconfirmed; treat as sensitive. [Citation 15]
- **Business error codes / HTTP 410/429/404 mappings** — assumed; OAPI documents only 200/422.
  Why unverifiable: not in sources. Mitigation: defensive mapping with `detail`-string fallback. [Citation 20]
- **Confirm always returns `session_id` for the verification path** — partially open; both
  session and route-to-login branches implemented. [Citation 6]
- **MFA-setup screen ownership/routing** — `mfa_setup` follow-on exists but its screens are out of
  AND-054 scope; routing target (`MfaSetupRoute`) must be confirmed with the MFA epic. [Citation 7]
- **SMS OTP autofill reliability over the plaintext dev host** — untested. [Citation 24]

## 17. Test Plan

Test targets: **JVM** = local JVM unit/Robolectric; **MWS** = JVM + MockWebServer (contract);
**EMU** = headless emulator AVD `test35` (x86_64, API 35); **DEV** = physical Samsung Galaxy A15 5G
(SM-A156U, serial R5CX821TA9R, API 34, arm64-v8a). Most cases are device-agnostic UI/logic and run on
**EMU** in CI; cases that exercise real SMS OTP autofill / IME / real-network behavior are flagged
**must run on DEV**.

- **TC-AND-054-01 — Confirm happy path, no session (route to Login).**
  Type: unit (JVM, MWS). Target: `RegisterConfirmViewModel` + `RegisterRepository`.
  Preconditions: VM seeded from `RegisterRoute.Confirm(email="jane@example.com", deliveryMedium="email", ...)`.
  Steps: enqueue `200 {"status":"confirmed","session_id":null}`; call `onConfirm("123456")`.
  Expected: request body is exactly `{"email":"jane@example.com","confirmation_code":"123456"}`;
  emits `Confirmed(email="jane@example.com")`; `isSubmitting` returns to false. Traces: AC-1.

- **TC-AND-054-02 — Confirm happy path, session established, no MFA.**
  Type: unit (JVM, MWS). Target: `RegisterConfirmViewModel`.
  Preconditions: as 01. Steps: enqueue `200 {"status":"ok","session_id":"sess_1","mfa_setup":[]}`; `onConfirm`.
  Expected: emits `Authenticated(mfaSetup=[], smsPhone=null)`. Traces: AC-1.

- **TC-AND-054-03 — Confirm happy path, session + MFA setup required.**
  Type: unit (JVM, MWS). Target: `RegisterConfirmViewModel`.
  Steps: enqueue `200 {"status":"ok","session_id":"sess_1","mfa_setup":["totp"],"sms_phone":null}`; `onConfirm`.
  Expected: emits `Authenticated(mfaSetup=["totp"], smsPhone=null)` (nav layer routes to MFA-setup). Traces: AC-1.

- **TC-AND-054-04 — Wrong code → inline error, field cleared, stays on screen.**
  Type: contract/MWS (JVM). Target: `RegisterRepository` + VM.
  Steps: enqueue `400 {"detail":"That code isn't correct."}`; `onConfirm("000000")`.
  Expected: `error = InvalidCode` carrying the server `detail` string; `code == ""`; no nav event;
  `isSubmitting` false. Traces: AC-3.

- **TC-AND-054-05 — Validation error (422 list) mapped to first message.**
  Type: contract/MWS (JVM). Target: `RegisterRepository` (`detail` mapper, AND-015).
  Steps: enqueue `422 {"detail":[{"msg":"Confirmation code is required","type":"value_error","loc":["body","confirmation_code"]}]}`; `onConfirm("")`.
  Expected: `error = InvalidCode` with message "Confirmation code is required"; field cleared. Traces: AC-3, AC-7.

- **TC-AND-054-06 — `detail` shape variants map correctly (string / list / object).**
  Type: unit (JVM). Target: `ApiErrorMapper` → `RegisterConfirmError`.
  Steps: feed `"plain string"`, `[{"msg":"m"}]`, `{"code":"expired_code"}` (assumed) error bodies.
  Expected: string→message verbatim; list→joined `msg`; object with known `code`→typed error,
  unknown→fallback to `detail`/generic. Traces: AC-3, AC-7.

- **TC-AND-054-07 — 429 too-many-attempts → Locked with Retry-After (assumed mapping).**
  Type: contract/MWS (JVM). Target: VM + repository.
  Steps: enqueue `429` with header `Retry-After: 120` and `{"detail":"Too many attempts"}`; `onConfirm`.
  Expected: `error = Locked(retryAfter=120)`; message shows server `detail` or fallback with minutes. Traces: AC-3, AC-5.

- **TC-AND-054-08 — Resend happy path (request shape + transient confirmation).**
  Type: contract/MWS (JVM). Target: VM + repository.
  Preconditions: cooldown elapsed (`canResend == true`). Steps: enqueue
  `200 {"status":"sent","delivery_medium":"email","delivery_destination":"j••@example.com"}`; `onResend()`.
  Expected: request body `{"email":"jane@example.com","delivery_method":"email","phone":null,"enable_sms_mfa":false,"enable_totp_mfa":false}`;
  `transientMessage == "New code sent"`; `deliveryDestination` refreshed from response. Traces: AC-2.

- **TC-AND-054-09 — Resend cooldown ticker (client-side) + config-change survival.**
  Type: unit (JVM, injected fake `Clock`). Target: `RegisterConfirmViewModel`.
  Steps: trigger successful resend → `resendAvailableAtEpochMs = now+30s`; advance clock; recreate VM
  from `SavedStateHandle` mid-countdown. Expected: `canResend == false` while remaining>0,
  `resendCountdownSeconds` counts to 0 then `canResend == true`; remaining is recomputed correctly
  after recreation (derived from absolute epoch). Traces: AC-2.

- **TC-AND-054-10 — Double-submit / resend-during-cooldown guards.**
  Type: unit (JVM). Target: VM. Steps: call `onConfirm` twice rapidly (in-flight); call `onResend`
  during cooldown. Expected: second confirm ignored while `isSubmitting`; resend no-op while
  `canResend == false`; exactly one network call each. Traces: AC-5.

- **TC-AND-054-11 — Timeout/offline on confirm preserves entered code (no auto-retry).**
  Type: contract/MWS (JVM). Target: VM + repository. Steps: MWS `SocketPolicy.NO_RESPONSE` (or
  disconnect) on confirm with `code="123456"`. Expected: `error = Network`; `code == "123456"`
  (NOT cleared); no retry attempted (single request recorded). Traces: AC-5.

- **TC-AND-054-12 — CSRF header echoed; 401 does not trigger refresh on pre-auth register call.**
  Type: contract/MWS (JVM). Target: core-network interceptor chain + repository.
  Preconditions: cookie jar holds `ui_csrf=abc`. Steps: enqueue `200`; assert outgoing
  `X-CSRF-Token: abc`. Then enqueue `401`; `onConfirm`. Expected: header present on confirm;
  on 401 the request does **not** loop through a session refresh (no `/ui/session/refresh` call) and
  maps to `SessionExpired` → pop-to-start event. Traces: AC-5, AC-6 (transport security).

- **TC-AND-054-13 — Compose UI: full-length entry auto-submits; success shows banner / navigates.**
  Type: Compose-UI (EMU). Target: `RegisterConfirmScreen` with fake VM.
  Steps: type 6 digits; success state → `Confirmed`. Expected: Confirm enabled at length 6, spinner
  while submitting, success banner / nav callback fired; Confirm disabled when code incomplete.
  Traces: AC-1, AC-4.

- **TC-AND-054-14 — Compose UI: wrong code error surface + field cleared; resend countdown visible.**
  Type: Compose-UI (EMU). Target: `RegisterConfirmScreen`.
  Steps: drive state `error=InvalidCode`; then `resendCountdownSeconds>0`. Expected: inline error text
  shown below field, OTP cleared, Resend disabled with visible countdown re-enabling at 0. Traces: AC-2, AC-3.

- **TC-AND-054-15 — Accessibility: error live-region + OTP contentDescription + touch targets.**
  Type: Compose-UI / instrumented a11y (EMU; TalkBack smoke on **DEV**). Target: `RegisterConfirmScreen`.
  Steps: assert OTP node has merged `contentDescription` ("Verification code, N digits"); error node has
  `semantics { error(...) }` + assertive live region; countdown uses polite live region; tap targets ≥48dp.
  Expected: all present; on **DEV** TalkBack announces the error on appearance. Traces: AC-3, AC-4 (a11y).

- **TC-AND-054-16 — Security: OTP code & destination absent from logs/telemetry; redacted body logging.**
  Type: unit + instrumented (JVM for telemetry; EMU/Logcat scan). Target: analytics facade + OkHttp logging interceptor config.
  Steps: perform confirm/resend with code; capture emitted telemetry props and (debug) Logcat.
  Expected: telemetry carries only `delivery`/outcome enums (no `confirmation_code`, no raw destination);
  `register/confirm` request body redacted/omitted from `BODY` logging. Traces: AC-6.

- **TC-AND-054-17 — Real SMS OTP autofill + on-device IME behavior.**
  Type: instrumented/e2e — **must run on DEV** (real telephony/IME; emulator cannot deliver real SMS
  retriever broadcasts reliably). Target: `OtpInput` (AND-020) on the confirm screen.
  Preconditions: device reachable via adb; trigger resend so a code SMS arrives.
  Steps: observe autofill suggestion / SMS Retriever populate the field; verify no code persists in IME
  suggestion history. Expected: code auto-fills (or graceful manual fallback if unsupported on host);
  no code leaks to IME history. Traces: AC-6 (and validates FR-2/§8 autofill assumption).

### Coverage matrix

| Acceptance criterion (§14) | Covered by |
|----------------------------|------------|
| AC-1 Correct code confirms + navigates (session vs login vs MFA) | TC-01, TC-02, TC-03, TC-13 |
| AC-2 Resend works, transient confirmation, cooldown enable/disable | TC-08, TC-09, TC-14 |
| AC-3 Wrong/invalid/expired code shows mapped inline error, clears field, stays | TC-04, TC-05, TC-06, TC-07, TC-14, TC-15 |
| AC-4 Masked/destination hint + expiry handling; Confirm disabled when incomplete/expired | TC-13, TC-14, TC-15 |
| AC-5 No auto-retry; timeout keeps valid code; guards | TC-07, TC-10, TC-11, TC-12 |
| AC-6 No OTP/unmasked destination in logs/telemetry/storage | TC-12, TC-16, TC-17 |
| AC-7 Unit/contract/Compose tests pass in CI | TC-01…TC-16 (all CI-runnable; TC-17 is DEV-only e2e) |
