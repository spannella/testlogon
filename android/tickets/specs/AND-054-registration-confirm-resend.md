---
id: AND-054
title: "Registration: confirm + resend"
milestone: M2
epic: E08
priority: P1
size: M
status: draft
depends_on: [AND-053]
blocks: [AND-055]
---

# AND-054 — Registration: confirm + resend

## 1. Overview & Goal

This ticket delivers the **registration confirmation step** of the TestLogon native Android
sign-up flow. After AND-053 (`Registration: start`) submits `POST /ui/register/start` and the
backend responds with `verification_required = true` plus a chosen `delivery` channel (email or
SMS), the user lands on a **Confirm code** screen. There they enter the one-time verification
code that was sent to their address/phone, the app calls `POST /ui/register/confirm`, and on
success the account is activated. The screen also offers a **Resend** action backed by
`POST /ui/register/resend` so a user who never received the code (or whose code expired) can
request a new one without restarting registration.

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
    `RegisterStartResp` shape (`verification_required`, `delivery`, masked `destination`,
    optional `registration_id`/`challenge_id`, optional `code_length`, `expires_at`,
    `resend_cooldown_seconds`). AND-054 receives these values as the confirm route's typed nav
    arguments and renders/uses them.
  - **AND-020** — Core input composables: `OtpInput` (N-digit entry + paste/auto-advance),
    `AppButton`, error text styles.
  - **AND-018** — `ApiResult<T>` / error types.
  - **AND-015** — FastAPI `detail` mapping (`string | [{msg}] | {code,...}`).
- **Web reference:** `frontend/src/api/endpoints/register.ts` (`confirm`, `resend`),
  `frontend/src/api/types.ts` (`RegisterConfirmReq/Resp`, delivery enum). Use the web confirm
  component for UX parity (cooldown copy, masked destination, error wording).
- **Backend:** FastAPI dev host `http://18.222.237.167:8000` (PLAINTEXT HTTP, unreliable dev
  host). OpenAPI at `/openapi.json`. Confirm/resend are **non-idempotent POSTs** (see §7 for
  retry policy). Registration is pre-auth: there is no authenticated session yet, but the
  `ui_csrf` cookie set by `/ui/register/start` must still be echoed as `X-CSRF-Token` (handled
  by AND-012; the persistent cookie jar of AND-011 carries it).
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Navigation-Compose (single Activity), Hilt
  (KSP), Coroutines/Flow, Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15. minSdk 24 / target 35.

## 3. Functional Requirements

FR-1 **Entry & context display.** On entering the confirm screen with the start response args,
display the delivery channel and a masked destination hint (e.g. `Code sent to •••• 4821`
for SMS, `Code sent to j••@example.com` for email). The mask comes from the backend
`destination`; the client never reconstructs or stores the raw address.

FR-2 **OTP entry.** Render the AND-020 `OtpInput`. Length is `uiState.codeLength` (default 6).
Paste and auto-advance are provided by AND-020. When the field reaches full length, auto-submit
(FR-3) **unless** `isSubmitting == true`.

FR-3 **Confirm.** A primary `AppButton` ("Confirm") is enabled only when entered length ==
`codeLength` and `isSubmitting == false`. Tapping (or auto-submit) calls `onConfirm(code)`,
which invokes `POST /ui/register/confirm`. While in flight the button shows an inline spinner
and is disabled.

FR-4 **Wrong code → error.** A `4xx` confirm response (invalid/expired/mismatched code) clears
the OTP field, keeps the user on the screen, and surfaces a localized inline error below the
field mapped from the backend `detail` (see §5). The screen must distinguish at minimum:
invalid code, expired code, and too-many-attempts/locked.

FR-5 **Resend with cooldown.** A "Resend code" action calls `onResend()` →
`POST /ui/register/resend`. After a successful resend (and on first entry) it is disabled and
shows a live countdown from `resendCooldownSeconds` (default 30s) driven by a UI-side ticker;
at 0 it re-enables. The countdown survives configuration changes (state is in the ViewModel,
ticker derived from an absolute `resendAvailableAtEpochMs`). A successful resend refreshes
`expiresAtEpochMs`/cooldown from the resend response and shows a transient confirmation
("New code sent").

FR-6 **Expiry timer.** If `expiresAtEpochMs` is present, show "Code expires in mm:ss". On
expiry, disable Confirm and surface "This code has expired — resend".

FR-7 **Loading / offline / error surfaces.** Use the AND-021 state composables for full-screen
states where appropriate; inline surfaces for field-level errors. A network failure on confirm
or resend shows a retryable inline error (it does **not** clear a valid entered code on a pure
network/timeout failure, only on a server-rejected code per FR-4).

FR-8 **Success → continuation.** On `200` confirm:
- If the confirm response indicates an authenticated session was established
  (`session_started = true`, i.e. backend set session cookies), emit
  `RegisterConfirmEvent.Authenticated`; the nav graph routes to the authenticated graph.
- Otherwise emit `RegisterConfirmEvent.Confirmed`; navigate to the Login screen
  (`LoginRoute`) with a one-shot success message ("Account confirmed — please sign in") and the
  email prefilled where available. Default assumption for M2 is the **non-session** path
  (route to login); the session path is implemented defensively and gated on the response flag.

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
        val registrationId: String?,   // backend correlation id, if provided
        val challengeId: String?,       // alternative correlation key
        val delivery: String,           // "EMAIL" | "SMS"
        val maskedDestination: String,
        val codeLength: Int = 6,
        val expiresAtEpochMs: Long? = null,
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
                    RegisterConfirmEvent.Confirmed ->
                        navController.navigate(LoginRoute(prefillEmail = state.email)) {
                            popUpTo(RegisterRoute.Start) { inclusive = true }
                        }
                    RegisterConfirmEvent.Authenticated ->
                        navController.navigate(AuthenticatedGraph) {
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

**Confirm — request:**
```json
{ "registration_id": "reg_8f3...", "code": "123456" }
```
If the backend keys on `challenge_id` instead, send that field; the DTO carries both nullable
and serializes only the one provided.

**Confirm — success `200`:**
```json
{ "confirmed": true, "session_started": false, "email": "jane@example.com" }
```

**Resend — request:**
```json
{ "registration_id": "reg_8f3...", "delivery": "EMAIL" }
```

**Resend — success `200`:**
```json
{
  "sent": true,
  "delivery": "EMAIL",
  "destination": "j••@example.com",
  "expires_at": "2026-06-05T18:42:00Z",
  "resend_cooldown_seconds": 30
}
```

```kotlin
@JsonClass(generateAdapter = true)
data class RegisterConfirmReq(
    @Json(name = "registration_id") val registrationId: String? = null,
    @Json(name = "challenge_id") val challengeId: String? = null,
    val code: String,
)
@JsonClass(generateAdapter = true)
data class RegisterConfirmResp(
    val confirmed: Boolean,
    @Json(name = "session_started") val sessionStarted: Boolean = false,
    val email: String? = null,
)
@JsonClass(generateAdapter = true)
data class RegisterResendReq(
    @Json(name = "registration_id") val registrationId: String? = null,
    @Json(name = "challenge_id") val challengeId: String? = null,
    val delivery: String,
)
@JsonClass(generateAdapter = true)
data class RegisterResendResp(
    val sent: Boolean,
    val delivery: String,
    val destination: String? = null,
    @Json(name = "expires_at") val expiresAt: String? = null,
    @Json(name = "resend_cooldown_seconds") val resendCooldownSeconds: Int = 30,
)
```

**Error mapping (per AND-015).** FastAPI `detail` may be a string, a list of
`[{ "msg": "...", "type": "...", "loc": [...] }]`, or `{ "code": "...", ... }`. Map to
`RegisterConfirmError`:

| HTTP / code                         | UiError                          | User message                                   |
|-------------------------------------|----------------------------------|------------------------------------------------|
| 400 `invalid_code` / mismatch       | `InvalidCode`                    | "That code isn't correct. Check and try again."|
| 410 / `expired_code`                | `ExpiredCode`                    | "This code has expired — resend a new one."    |
| 429 / `too_many_attempts`           | `Locked(retryAfter)`             | "Too many attempts. Try again in N min."       |
| 404 / `registration_not_found`      | `SessionExpired`                 | "Registration expired — please start over."    |
| 5xx / timeout / IO                  | `Network`                        | "Couldn't reach the server. Try again."        |

`Locked` reads `Retry-After` (header or `detail`); `SessionExpired` emits an event that pops to
start (FR-9).

## 6. Data & State Management

```kotlin
data class RegisterConfirmUiState(
    val email: String?,
    val delivery: String,                 // "EMAIL" | "SMS"
    val maskedDestination: String,
    val code: String = "",
    val codeLength: Int = 6,
    val isSubmitting: Boolean = false,
    val isResending: Boolean = false,
    val resendAvailableAtEpochMs: Long = 0L,   // 0 => available
    val expiresAtEpochMs: Long? = null,
    val resendCountdownSeconds: Int = 0,        // derived by ticker
    val expiryCountdownSeconds: Int? = null,    // derived by ticker
    val error: RegisterConfirmError? = null,
    val transientMessage: String? = null,       // "New code sent"
) {
    val canConfirm get() = code.length == codeLength && !isSubmitting && expiryCountdownSeconds != 0
    val canResend  get() = resendCountdownSeconds == 0 && !isResending
    companion object { fun from(args: RegisterRoute.Confirm): RegisterConfirmUiState = … }
}

sealed interface RegisterConfirmEvent {
    data object Confirmed : RegisterConfirmEvent
    data object Authenticated : RegisterConfirmEvent
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
- **401 handling:** registration is pre-auth; a 401 is not expected. If one occurs, the
  AND-013 authenticator's single refresh will fail (no session) and the error maps to
  `SessionExpired` → pop to start, rather than looping.
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
| `register_confirm_succeeded`   | `delivery`, `session_started`                    |
| `register_confirm_failed`      | `delivery`, `error` (enum: invalid/expired/locked/network) |
| `register_resend_tapped`       | `delivery`                                        |
| `register_resend_succeeded`    | `delivery`                                        |
| `register_resend_failed`       | `delivery`, `error`                               |

Network logging uses the OkHttp logging interceptor (AND-009) at `BODY` only in debug builds;
the confirm/resend request bodies (which contain the code) must be redacted or the interceptor
restricted to non-`/register/confirm` paths in debug. No code value appears in Logcat.

## 11. Testing Strategy

**Unit (`RegisterConfirmViewModel`, JVM, `core-testing` + MockWebServer AND-046):**
- Correct code → `confirm` 200 with `session_started=false` → emits `Confirmed`; with
  `session_started=true` → emits `Authenticated`.
- Wrong code → 400 `invalid_code` → `error = InvalidCode`, code field cleared, stays on screen
  (covers acceptance "wrong code shows error").
- Expired code → 410 → `ExpiredCode`, Confirm disabled.
- `too_many_attempts` 429 with `Retry-After` → `Locked` with parsed retry seconds.
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

- **Correlation key:** unconfirmed whether the backend keys confirm/resend on `registration_id`
  or reuses `challenge_id`. The DTOs carry both nullable; confirm against `/openapi.json` before
  implementation and drop the unused field.
- **Auto-login on confirm:** whether `/ui/register/confirm` sets session cookies
  (`session_started`) or always requires a subsequent login is unconfirmed. Implementation
  handles both (FR-8) but defaults to route-to-login; verify the real response.
- **Cooldown source of truth:** if the backend enforces resend cooldown server-side and returns
  429 on early resend, the client must reconcile its UI ticker with a server `Retry-After`.
  Treat the server value as authoritative when present.
- **SMS OTP autofill:** SMS Retriever / autofill reliability on the plaintext dev host is
  untested; if it misbehaves, fall back to manual entry only.
- **Code length:** assumed 6 from `code_length`/default; confirm the backend doesn't vary length
  by channel.

## 14. Acceptance Criteria

AC-1 Entering the **correct** code and tapping Confirm calls `POST /ui/register/confirm`, the
account is confirmed, and the app navigates onward (to Login with a success message, or to the
authenticated graph when `session_started = true`). *(Backlog: "Correct code confirms account.")*

AC-2 **Resend** invokes `POST /ui/register/resend`, shows a "New code sent" confirmation, and
starts/refreshes the cooldown timer; the action is disabled during cooldown and re-enables at 0.
*(Backlog: "resend works.")*

AC-3 Entering a **wrong/expired** code shows a clear inline error (invalid vs. expired vs.
locked, mapped from `detail`), clears the field, and keeps the user on the confirm screen.
*(Backlog: "wrong code shows error.")*

AC-4 The screen shows the masked destination and (when provided) a live expiry countdown;
Confirm is disabled when the code is incomplete or expired.

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
