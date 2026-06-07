---
id: AND-048
title: "Compose UI tests: login"
milestone: M1
epic: E07
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-031, AND-046]
blocks: [AND-049]
---

# AND-048 — Compose UI tests: login

## 1. Overview & Goal

This ticket delivers the instrumented Jetpack Compose UI test suite for the TestLogon
login screen (`feature-auth`). The suite exercises the `LoginScreen` composable wired to a
real `LoginViewModel` (AND-031) backed by an in-memory `AuthRepository` fake or a
`MockWebServer`-driven `Retrofit` stack (AND-046). It must validate three behavior
classes end-to-end at the UI layer:

1. **Happy path** — entering a valid username/password and tapping submit drives the
   screen through `loading` and emits the correct navigation effect (MFA-required vs.
   home) based on the backend response.
2. **Client-side validation** — empty/invalid fields keep the submit button disabled and
   render inline field errors; the network layer is never invoked.
3. **Server-error rendering** — `401`/`422`/`5xx`/timeout responses from
   `POST /ui/session/start` surface as the correct user-visible error banner text and
   re-enable the form for retry.

The goal is a deterministic, headless-capable regression net that pins the login UI's
observable contract so later refactors (theming, navigation, MFA work in AND-049) cannot
silently break the primary authentication entry point. The suite is the UI-layer
counterpart to the `LoginViewModel` unit tests (AND-031) and `AuthRepository` contract
tests (AND-047); it does not re-verify repository logic, only that the composable renders
and reacts to `LoginUiState` correctly.

Out of scope: MFA-screen UI tests (AND-049 owns TOTP/SMS), repository wire-level
contract assertions (AND-047), and screenshot/pixel-diff testing.

## 2. Context & References

- **Repo / module**: `spannella/testlogon`, branch `android-port`, app under `android/`.
  Tests live in the `feature-auth` module: `android/feature-auth/src/androidTest/...`.
- **Namespace**: `com.testlogon.android.feature.auth` (applicationId base
  `com.testlogon.android`).
- **Subject under test**: `LoginScreen` (AND-030) + `LoginViewModel` /
  `LoginUiState` (AND-031).
- **Test harness**: `core-testing` `MockWebServer` harness + captured JSON fixtures
  (AND-046).
- **Web reference for IA/behavior parity**: `frontend/src/api/endpoints/*.ts`,
  `frontend/src/api/types.ts`, and the web login page flow.
- **Backend**: FastAPI dev host `http://18.222.237.167:8000` (PLAINTEXT, unreliable —
  used only to *capture* fixtures, never hit live from tests). Endpoint of record:
  `POST /ui/session/start`. OpenAPI at `/openapi.json`.
- **Stack**: Kotlin 2.0.21, Compose + Material 3, Navigation-Compose, Hilt (KSP),
  Coroutines/Flow. Test tooling: `androidx.compose.ui:ui-test-junit4`,
  `createAndroidComposeRule` / `createComposeRule`, `androidx.test.ext:junit`,
  Hilt testing (`HiltAndroidRule`, `@HiltAndroidTest`), `okhttp3:mockwebserver`,
  `app.cash.turbine` for flow assertions where needed.
- **Upstream dependencies**: AND-031 (LoginViewModel + StateFlow contract), AND-046
  (MockWebServer harness + fixtures). **Blocks**: AND-049 reuses the test harness
  patterns and `semantics` test tags established here.

## 3. Functional Requirements

FR-1 **Happy path → home.** Given fields populated with a valid username/password and a
stubbed `POST /ui/session/start` returning `auth_required=false` **with a non-null
`session_id`** (single-factor / no MFA required), when the user taps **Sign in**, the
test asserts a transient loading state then a successful `GET /ui/me`, then a
`LoginEffect.NavigateToHome` is emitted. **[CORRECTED]** The web reference
(`src/pages/Login.tsx`) takes the no-MFA branch on `!auth_required && resp.session_id` and
calls `getMe()` directly — there is **no** `/ui/session/finalize` call on the no-MFA path
(finalize runs only after an MFA factor is verified). The original draft's "followed by a
successful finalize" was incorrect; the no-MFA fixture must therefore carry a non-null
`session_id`.

FR-2 **Happy path → MFA.** Given valid credentials and a `start` response with
`auth_required=true` and `required_factors=["totp"]`, tapping **Sign in** emits
`LoginEffect.NavigateToMfa(challengeId, requiredFactors)`. The test asserts the effect
payload carries the `challenge_id` from the fixture.

FR-3 **Loading + disabled.** While the request is in flight, the submit control shows a
busy indicator and is disabled; all input fields are disabled (no double submit). After
terminal state, controls re-enable.

FR-4 **Validation — empty.** With either field empty, **Sign in** is disabled and tapping
it (if forced) performs no network call. The MockWebServer dispatcher must record zero
requests.

FR-5 **Validation — required (non-empty) fields.** **[CORRECTED]** The web reference
(`src/pages/Login.tsx`) validates credentials with a Zod schema of `username: min(1,
"Email is required")` and `password: min(1, "Password is required")` — i.e. it only
enforces **non-empty**; it does **not** apply an email-format regex. The original draft's
"invalid email format ... 'Enter a valid email'" is therefore an unverified Android-only
assumption, not web parity. This suite asserts the *required* behavior: a blank/whitespace
value renders the inline "required" field error and keeps submit disabled; correcting the
field clears the error and enables submit (assuming the other field is valid). If AND-031
deliberately adds stricter email-format validation beyond web parity, that is a separate
product decision and must be confirmed against the AND-031 `LoginViewModel` contract before
asserting an email-format message.

FR-6 **Show/hide password.** Toggling the visibility affordance flips the password field
between masked and plain text (asserted via semantics / `EditableText`).

FR-7 **Server error — 401 invalid credentials.** A `401` from `start` renders the
mapped error banner ("Invalid username or password") and re-enables the form. No
navigation effect is emitted.

FR-8 **Server error — 422 validation detail.** A `422` with FastAPI
`detail: [{msg, loc, type}]` (response schema `HTTPValidationError`) renders the mapped
message in the error region. **[NOTE]** The web `normalizeErrorDetail`
(`src/api/client.ts`) maps an array `detail` by collecting every item's `msg` and joining
them with `", "` — it does **not** take only the first `msg`. For single-item fixtures
(the common case) this is equivalent to "the first msg", but the assertion should accept
the joined form. If AND-031's mapper instead surfaces only the first/field-mapped message,
assert that; either way assert the *rendered* string, not the mapper internals.

FR-9 **Server error — 5xx / timeout / offline.** A `503`, a delayed response exceeding
the client timeout, and a connection drop each render a generic
recoverable error ("Something went wrong. Try again." / offline copy) and re-enable
retry.

FR-10 **All assertions are header-less and deterministic** — no real network, no sleeps;
synchronization uses Compose's `waitUntil` / idling, and MockWebServer enqueued responses.

## 4. Technical Design

### Test module layout

```
android/feature-auth/src/androidTest/kotlin/com/testlogon/android/feature/auth/login/
  LoginScreenHappyPathTest.kt
  LoginScreenValidationTest.kt
  LoginScreenServerErrorTest.kt
  support/
    LoginScreenRobot.kt          // screen-driver (robot pattern)
    LoginTestTags.kt             // shared semantics tag constants (mirrors prod tags)
    FakeLoginNavigator.kt        // captures emitted LoginEffect(s)
```

### Composable test entry point

Tests render the composable directly (not the full NavHost) to isolate the screen.
The production `LoginScreen` is assumed (per AND-030) to expose a stateless overload:

```kotlin
@Composable
fun LoginScreen(
    state: LoginUiState,
    onUsernameChange: (String) -> Unit,
    onPasswordChange: (String) -> Unit,
    onTogglePasswordVisibility: () -> Unit,
    onSubmit: () -> Unit,
    onNavigateRecovery: () -> Unit,
    onNavigateRegister: () -> Unit,
)
```

and a stateful `LoginRoute(viewModel: LoginViewModel = hiltViewModel(), onEffect: (LoginEffect) -> Unit)`.

Most UI tests drive `LoginRoute` with a real `LoginViewModel` so state transitions
(loading/disabled/error) are produced by production code rather than hand-fed. Validation
tests that need precise control over `LoginUiState` may render the stateless `LoginScreen`
with explicit state objects.

### Rule setup (Hilt + MockWebServer)

```kotlin
@HiltAndroidTest
class LoginScreenServerErrorTest {

    @get:Rule(order = 0) val hiltRule = HiltAndroidRule(this)
    @get:Rule(order = 1) val composeRule = createAndroidComposeRule<HiltTestActivity>()

    @Inject lateinit var server: MockWebServer          // provided by core-testing test module
    @Inject lateinit var viewModelFactory: LoginViewModel.Factory

    private val effects = mutableListOf<LoginEffect>()

    @Before fun setUp() {
        hiltRule.inject()
    }

    @After fun tearDown() { server.shutdown() }

    private fun launch(dispatcher: Dispatcher? = null) {
        dispatcher?.let { server.dispatcher = it }
        composeRule.setContent {
            TestLogonTheme {
                LoginRoute(onEffect = { effects += it })
            }
        }
    }
}
```

The `core-testing` harness (AND-046) supplies a Hilt `@TestInstallIn` module that replaces
`NetworkModule`'s base URL with `server.url("/")` and installs a fresh in-memory cookie
jar per test, plus `enqueue*()`/`Dispatcher` builders that return the captured fixtures.

### Robot pattern

```kotlin
class LoginScreenRobot(private val rule: ComposeContentTestRule) {
    fun typeUsername(v: String) = apply {
        rule.onNodeWithTag(LoginTestTags.USERNAME).performTextReplacement(v)
    }
    fun typePassword(v: String) = apply {
        rule.onNodeWithTag(LoginTestTags.PASSWORD).performTextReplacement(v)
    }
    fun toggleVisibility() = apply {
        rule.onNodeWithTag(LoginTestTags.PASSWORD_TOGGLE).performClick()
    }
    fun submit() = apply { rule.onNodeWithTag(LoginTestTags.SUBMIT).performClick() }

    fun assertSubmitEnabled(enabled: Boolean) = apply {
        rule.onNodeWithTag(LoginTestTags.SUBMIT)
            .assert(if (enabled) isEnabled() else isNotEnabled())
    }
    fun assertError(text: String) = apply {
        rule.onNodeWithTag(LoginTestTags.ERROR_BANNER).assertTextContains(text, substring = true)
    }
    fun assertLoading() = apply {
        rule.onNodeWithTag(LoginTestTags.PROGRESS).assertIsDisplayed()
    }
    fun awaitIdle() = apply { rule.waitForIdle() }
}
```

`LoginTestTags` constants must be referenced by the production composable via
`Modifier.testTag(...)`; this ticket adds those tags to AND-030's composable if missing
(small, coordinated edit) so tests are robust to copy/string changes.

### Synchronization

No `Thread.sleep`. Loading-state assertions use a MockWebServer response with a small
`setBodyDelay` and `composeRule.waitUntil(timeoutMillis = 5_000) { progress is displayed }`.
Effect/terminal assertions use `composeRule.waitUntil { effects.isNotEmpty() }` or
`waitUntilExactlyOneExists(...)`. Coroutine dispatchers are overridden to the
test `StandardTestDispatcher` via the `core-testing` `MainDispatcherRule` where the
ViewModel uses an injected `CoroutineDispatcher`.

## 5. API Contract

This is a test ticket; it does not define new endpoints. It *consumes* the existing
`POST /ui/session/start` contract via stubbed MockWebServer responses using AND-046
fixtures. The shapes the tests must reproduce:

**Request** (`application/json`, with `X-CSRF-Token` header echoing `ui_csrf` cookie):
```json
{ "challenge_context": { "username": "alice@example.com", "password": "hunter2" } }
```
Verified: backend schema `UiSessionStartReq` has a single `challenge_context` object
(`additionalProperties: true`, optional) — username/password are passed as free-form keys
inside it, exactly as the web client does (`src/pages/Login.tsx` builds
`challenge_context: { username, password }`). CSRF header verified in `src/api/client.ts`
(reads `ui_csrf` cookie → sets `X-CSRF-Token`; uses `credentials: "include"`).

**Response — no MFA (FR-1)** `200`: **[CORRECTED — `session_id` is required for the
no-MFA branch]**
```json
{ "auth_required": false, "challenge_id": null, "required_factors": [], "session_id": "sess_9a2c..." }
```
The backend `UiSessionStartResp` schema includes a nullable `session_id` field (omitted in
the original draft). The web no-MFA branch is gated on `!auth_required && resp.session_id`,
so a fixture without `session_id` would NOT trigger NavigateToHome. The fixture must carry
a non-null `session_id`.

**Response — MFA required (FR-2)** `200`:
```json
{ "auth_required": true, "challenge_id": "chal_7f3a...", "required_factors": ["totp"] }
```

**Response — invalid credentials (FR-7)** `401`:
```json
{ "detail": "Invalid username or password" }
```

**Response — validation (FR-8)** `422`:
```json
{ "detail": [ { "loc": ["body","challenge_context","username"], "msg": "field required", "type": "missing" } ] }
```

**Response — server error (FR-9)** `503`:
```json
{ "detail": { "code": "service_unavailable", "message": "temporarily unavailable" } }
```
**[UNVERIFIED ASSUMPTION]** `POST /ui/session/start` in the OpenAPI index declares only
`200:UiSessionStartResp` and `422:HTTPValidationError`; no 503 body schema is documented
for this path. The object-shaped `{detail:{code,message}}` is plausible (the web
`normalizeErrorDetail` + `mapAuthorizationError` handle object-detail, and other endpoints
e.g. `/api/vnc/session` use an `ErrorEnvelope` for 5xx), but the exact 503 body for this
endpoint is not pinned by the sources. For the UI test it does not matter: any unmapped 5xx
must surface the generic recoverable banner, so the fixture body shape is non-load-bearing
here.

Fixtures are stored under `core-testing/src/main/resources/fixtures/auth/` and loaded by
filename (e.g. `session_start_no_mfa.json`). The tests must NOT hardcode JSON inline where
a fixture exists; this keeps shapes aligned with the live backend per AND-046.

The error-mapping under test is the production `detail` mapper (string | `[{msg}]` |
`{code,...}`) reached through `LoginViewModel`; tests assert the *rendered* string, not the
mapper internals (that is AND-047's concern at the repository layer).

## 6. Data & State Management

The `LoginUiState` contract (owned by AND-031) the tests observe:

```kotlin
data class LoginUiState(
    val username: String = "",
    val password: String = "",
    val passwordVisible: Boolean = false,
    val usernameError: String? = null,
    val passwordError: String? = null,
    val isSubmitEnabled: Boolean = false,
    val isLoading: Boolean = false,
    val errorBanner: String? = null,
)

sealed interface LoginEffect {
    data object NavigateToHome : LoginEffect
    data class NavigateToMfa(val challengeId: String, val factors: List<String>) : LoginEffect
}
```

Tests assert against the *projection* of this state into Compose semantics (enabled state,
displayed text, masked/plain field) and against captured `LoginEffect`s, never against the
StateFlow directly inside UI tests (StateFlow transitions are AND-031's unit-test scope).
A `FakeLoginNavigator` / lambda collects effects into a list with thread-safe append on the
main dispatcher.

No persistence is exercised: DataStore and the Room cache are not involved in login UI
rendering. The cookie jar is the in-memory test jar from AND-046, reset per test to
guarantee isolation. Test data: a single canonical valid credential pair and a small set
of invalid inputs declared as constants in `support/`.

## 7. Error Handling & Resilience

The suite's purpose is partly to *prove* error handling, so resilience here means test
determinism and faithful failure simulation:

- **401 path**: enqueue 401 fixture → assert banner text + `assertSubmitEnabled(true)` +
  zero emitted effects.
- **422 path**: enqueue 422 fixture → assert first `msg` (or field-mapped) renders.
- **5xx path**: enqueue 503 → assert generic recoverable banner.
- **Timeout path**: use `MockResponse().setBodyDelay(25, SECONDS)` against the production
  ~20s OkHttp timeout, OR (preferred for speed) inject a shortened timeout (e.g. 2s) via a
  test `NetworkConfig` override so the timeout branch is reached in well under the JUnit
  per-test budget. Assert offline/timeout banner + re-enabled form.
- **Connection drop**: `MockResponse().setSocketPolicy(DISCONNECT_AT_START)` → assert
  generic error.
- **Idempotency / retry**: login `POST` is non-idempotent and must NOT auto-retry; the test
  for the 5xx path asserts the dispatcher received exactly one `/ui/session/start` request.
- Flakiness controls: every wait is bounded by an explicit `timeoutMillis`; no real clock
  sleeps; each test shuts down its MockWebServer in `@After`; Hilt scopes are per-test.

## 8. Security & Privacy

- Test credentials are synthetic (`alice@example.com` / `hunter2`) — no real secrets in the
  repo. CI secret scanning must not flag fixtures.
- The password-visibility test confirms that the default state is **masked**
  (`PasswordVisualTransformation`), guarding against accidental plaintext exposure
  regressions.
- Tests assert no credential values appear in any banner/error text (regression guard
  against echoing input back into error UI).
- MockWebServer binds to localhost only; no traffic leaves the device/emulator. The live
  plaintext dev host is never contacted by tests.
- CSRF/cookie behavior is exercised indirectly (the harness installs `ui_csrf`); a focused
  assertion verifies the recorded request carries the `X-CSRF-Token` header when a CSRF
  cookie is present, protecting the cookie-based auth contract at the UI integration level.

## 9. Accessibility & i18n

- All robot lookups prefer `onNodeWithTag` for stability but the suite includes at least
  one assertion per interactive control that a non-empty `contentDescription` /
  accessible label exists (submit button, password-visibility toggle), enforcing a11y
  labeling on the login screen.
- Error banner must have a `LiveRegion` semantics (`liveRegion = Polite`); a test asserts
  the error node carries `SemanticsProperties.LiveRegion` so screen readers announce
  failures.
- i18n: assertions match against string resources resolved through the test
  `Context` (`composeRule.activity.getString(R.string.login_error_invalid_credentials)`)
  rather than literal English, so the suite stays valid under localization.

## 10. Telemetry & Logging

No production telemetry is added by this ticket. The tests verify that the login flow does
not crash or log credentials, but they do not assert analytics events (login analytics, if
any, are out of scope and would be a separate ticket). Test-run diagnostics: on failure,
attach the Compose semantics tree dump via `composeRule.onRoot().printToLog("LoginTest")`
inside a `TestWatcher` rule for CI triage, and dump the MockWebServer `RecordedRequest`
queue. CI publishes the standard instrumented-test JUnit XML and the AndroidTest HTML
report as build artifacts.

## 11. Testing Strategy

This ticket *is* the test deliverable. Coverage matrix (one `@Test` per row unless noted):

| Class | Test | Maps to |
|---|---|---|
| HappyPath | `validCredentials_noMfa_emitsNavigateToHome` | FR-1 |
| HappyPath | `validCredentials_mfaRequired_emitsNavigateToMfaWithChallengeId` | FR-2 |
| HappyPath | `submitInFlight_showsProgress_disablesForm` | FR-3 |
| Validation | `emptyFields_submitDisabled_noNetworkCall` | FR-4 |
| Validation | `blankField_showsRequiredFieldError_submitDisabled` | FR-5 |
| Validation | `correctingField_clearsError_enablesSubmit` | FR-5 |
| Validation | `togglePasswordVisibility_revealsAndMasks` | FR-6 |
| ServerError | `unauthorized401_showsInvalidCredentialsBanner_reenablesForm` | FR-7 |
| ServerError | `validation422_showsDetailMessage` | FR-8 |
| ServerError | `serverError503_showsGenericBanner_singleRequest` | FR-9 |
| ServerError | `timeout_showsOfflineBanner_reenablesForm` | FR-9 |
| ServerError | `connectionDrop_showsGenericBanner` | FR-9 |
| Security/a11y | `passwordMaskedByDefault_andErrorBannerIsLiveRegion` | §8/§9 |

**Execution**: instrumented (`androidTest`) on an emulator. Must run headlessly in CI via a
managed/headless device — Gradle Managed Devices
(`./gradlew feature-auth:pixel6api35DebugAndroidTest`) or an emulator started with
`-no-window -no-audio -gpu swiftshader_indirect`. Target wall-clock < 90s for the suite.
**Determinism gates**: no `Thread.sleep`; all waits bounded; each test fully isolated
(fresh Hilt component, fresh MockWebServer, fresh cookie jar). Run the suite 3x in CI
(or with a flaky-test retrier set to 0 retries for the gate) to catch nondeterminism
before merge.

## 12. Dependencies & Sequencing

- **Hard upstream**: AND-031 (`LoginViewModel`, `LoginUiState`, `LoginEffect` contract) and
  AND-046 (MockWebServer harness + auth fixtures in `core-testing`). Cannot start until both
  expose stable APIs. Transitively relies on AND-030 (`LoginScreen` composable) for the
  rendered UI and its `testTag`s.
- **Coordinated edit**: may add `Modifier.testTag` and `liveRegion` semantics to AND-030's
  composable; coordinate with the AND-030 owner so tags are part of the production source.
- **Downstream**: AND-049 (MFA UI tests) reuses this suite's robot/harness conventions and
  `HiltTestActivity`; establish those patterns cleanly here.
- **Build**: requires `feature-auth` `androidTest` dependencies wired (compose-ui-test,
  hilt-android-testing + KSP test processor, mockwebserver, turbine) and a Gradle Managed
  Device configured in the module's `android.testOptions`.

## 13. Risks & Open Questions

- **R1 — Stateless overload availability.** If AND-030 ships only a stateful `LoginRoute`
  without a stateless `LoginScreen(state, ...)`, validation tests must instead drive state
  through the real ViewModel, which is slightly less precise. *Mitigation*: request the
  stateless overload from AND-030 (standard Compose practice).
- **R2 — Timeout test duration.** Honoring the real ~20s OkHttp timeout makes the timeout
  test slow. *Resolution (proposed)*: inject a shortened timeout via test `NetworkConfig`.
  **Open question**: is the OkHttp timeout configurable through Hilt (AND-028 network
  module)? If not, AND-046/AND-028 must expose it.
- **R3 — Error string mapping ownership.** Exact banner copy for 422/5xx depends on the
  `detail` mapper + string resources. Tests assert via `R.string.*`; **open question**:
  are all login error strings defined as resources, or are some inline? Inline strings must
  be moved to resources.
- **R4 — Semantics for password masking.** Asserting masked vs. plain reliably depends on
  `EditableText`/`Text` semantics exposed by the `TextField`'s `VisualTransformation`.
  *Mitigation*: assert via `SemanticsProperties.Password` flag and the toggle's
  `contentDescription` state if raw text is not exposed.
- **R5 — Managed device image availability in CI.** AOSP/Google system image for api35 must
  be cached in CI to avoid long downloads. *Mitigation*: pre-warm image in CI base image.

## 14. Acceptance Criteria

AC-1 All login UI tests in the coverage matrix (§11) pass **headlessly** in CI on an
api35 emulator / Gradle Managed Device with no display attached.

AC-2 Happy path: a valid submission with the `no_mfa` fixture emits exactly one
`LoginEffect.NavigateToHome`; with the `mfa_required` fixture emits exactly one
`LoginEffect.NavigateToMfa` carrying the fixture's `challenge_id` and
`required_factors`.

AC-3 Validation: empty/invalid input keeps **Sign in** disabled and produces **zero**
recorded `/ui/session/start` requests; inline field errors appear and clear on correction.

AC-4 Server errors: 401, 422, 503, timeout, and connection-drop each render the correct
mapped banner (asserted via string resources) and leave the form re-enabled for retry; the
5xx case asserts exactly one outbound request (no auto-retry on the non-idempotent POST).

AC-5 The suite is deterministic: contains no `Thread.sleep`, all waits are bounded, each
test is isolated (fresh Hilt component + MockWebServer + cookie jar), and the suite passes
on 3 consecutive CI runs.

AC-6 Loading state: during an in-flight request the progress indicator is displayed and the
submit control + inputs are disabled; after the terminal state they re-enable.

AC-7 Security/a11y guards pass: password field masked by default; error banner is a polite
live region; interactive controls expose accessible labels; no credential value appears in
any rendered error text.

## 15. Definition of Done

- All §11 tests implemented under
  `android/feature-auth/src/androidTest/kotlin/com/testlogon/android/feature/auth/login/`,
  green locally and in CI headlessly.
- Required `testTag`/`liveRegion`/a11y-label semantics present in the production
  `LoginScreen` (coordinated with AND-030); no test-only forks of production UI.
- Robot, test tags, and `HiltTestActivity` harness placed in reusable `support/` (and/or
  `core-testing`) so AND-049 can consume them.
- Fixtures referenced by file from `core-testing` (AND-046); no divergent inline JSON for
  shapes that have a fixture.
- `feature-auth` Gradle config includes the androidTest dependencies and a Managed Device;
  `./gradlew feature-auth:<managedDevice>DebugAndroidTest` runs the suite headlessly.
- CI publishes JUnit XML + AndroidTest HTML report; suite wall-clock under ~90s; passes 3
  consecutive runs.
- Code reviewed and merged to `android-port`; open questions R2/R3 resolved or filed as
  follow-up tickets against AND-028/AND-046/AND-030.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **Endpoint of record is `POST /ui/session/start`.** VERIFIED.
   OpenAPI `POST /ui/session/start` (op=`ui_session_start_ui_session_start_post`,
   req=`UiSessionStartReq`, resp=`200:UiSessionStartResp;422:HTTPValidationError`).
   Frontend `src/api/endpoints/auth.ts: sessionStart` → `api.post<SessionStartResp>("/ui/session/start", body)`.

2. **Request body shape: `{ challenge_context: { username, password } }`.** VERIFIED.
   Schema `UiSessionStartReq` = single property `challenge_context` (`type: object`,
   `additionalProperties: true`, not in `required`). Frontend `src/pages/Login.tsx` builds
   `sessionStart({ challenge_context: { username: data.username, password: data.password } })`.
   Frontend DTO `src/api/types.ts: SessionStartReq` = `{ challenge_context?: Record<string, unknown> }`.

3. **Response shape includes `auth_required`, `challenge_id?`, `required_factors`, `session_id?`.** VERIFIED / CORRECTED.
   Schema `UiSessionStartResp`: `auth_required` (bool, required), `challenge_id` (string|null),
   `required_factors` (string[]), `session_id` (string|null). Frontend `src/api/types.ts: SessionStartResp`
   matches. The draft's response examples omitted `session_id` — corrected (see §5).

4. **No-MFA happy path goes straight to `GET /ui/me` (no finalize) and is gated on `session_id`.** CORRECTED.
   Frontend `src/pages/Login.tsx`: `if (!resp.auth_required && resp.session_id) { const me = await getMe(); login(...); navigate("/"); return; }`.
   No `sessionFinalize` call on this branch. The draft FR-1 ("followed by a successful finalize")
   was wrong. `GET /ui/me` verified in OpenAPI (`GET /ui/me`, op=`ui_me_ui_me_get`) and
   `src/api/endpoints/auth.ts: getMe` → `api.get<MeResp>("/ui/me")`.

5. **`/ui/session/finalize` exists and is used only after MFA verification.** VERIFIED.
   OpenAPI `POST /ui/session/finalize` (req=`UiSessionFinalizeReq` = `{ challenge_id (required), remember_device? }`).
   Frontend `src/api/endpoints/auth.ts: sessionFinalize`; invoked in `src/pages/Login.tsx` only in the
   MFA-verify flow, not the no-MFA flow.

6. **MFA path: `auth_required=true`, `challenge_id`, `required_factors` carried to next screen.** VERIFIED.
   `src/pages/Login.tsx`: `setChallengeId(resp.challenge_id ?? null); setRequiredFactors(resp.required_factors);`
   then factor selection (`factors.includes("totp")` etc.). Matches `UiSessionStartResp`.

7. **CSRF: client echoes `ui_csrf` cookie into `X-CSRF-Token` header; uses cookie credentials.** VERIFIED.
   `src/api/client.ts`: `const csrf = getCookie("ui_csrf"); if (csrf) headers.set("X-CSRF-Token", csrf);`
   and every request uses `credentials: "include"`.

8. **401 on the login (unauthenticated) path propagates directly — no refresh/retry.** VERIFIED.
   `src/api/client.ts` 401 handler: `if (!useAuthStore.getState().isAuthenticated) { ...throw new ApiError(401, normalizeErrorDetail(...)) }`.
   Auto-refresh+retry only runs when already authenticated. Supports the "single request, no auto-retry"
   assertion for the login 401/5xx tests.

9. **Error `detail` mapping handles string | array-of-`{msg}` | object.** VERIFIED (with nuance).
   `src/api/client.ts: normalizeErrorDetail` — string → as-is; array → maps each item's `msg` and
   `join(", ")` (ALL messages, not just the first); object → `mapAuthorizationError` / `msg`.
   Draft FR-8 "first msg" is approximate; for single-item 422 fixtures it is equivalent. Noted inline.

10. **422 response schema is FastAPI `HTTPValidationError` (`detail: [{loc,msg,type}]`).** VERIFIED.
    OpenAPI `POST /ui/session/start` resp `422:HTTPValidationError` (standard FastAPI validation shape).

11. **Client-side credential validation is non-empty only (no email-format regex).** CORRECTED.
    `src/pages/Login.tsx`: `z.object({ username: z.string().min(1, "Email is required"), password: z.string().min(1, "Password is required") })`.
    Draft FR-5 "invalid email format / 'Enter a valid email'" is not web parity; rewritten to assert
    required-field behavior (see §5/§11). Any stricter Android validation is an AND-031 product decision.

12. **503 / generic 5xx body shape `{detail:{code,message}}`.** UNVERIFIED-ASSUMPTION.
    OpenAPI documents only `200`/`422` for `POST /ui/session/start`; no 5xx body schema for this path.
    Object-detail is consistent with `mapAuthorizationError` and with `ErrorEnvelope` used by other
    endpoints (e.g. `POST /api/vnc/session`), but not pinned for this endpoint. Non-load-bearing for the
    UI test (any unmapped 5xx → generic banner).

13. **Password show/hide toggle exists with accessible label in the web reference.** VERIFIED.
    `src/pages/Login.tsx`: password `Input type={showPassword ? "text" : "password"}` with a toggle
    button `aria-label={showPassword ? "Hide password" : "Show password"}`. Supports FR-6 + a11y intent
    (the Compose equivalent is `PasswordVisualTransformation` + `contentDescription`, an Android mapping).

14. **Compose/instrumented test framework choices** (createAndroidComposeRule, `waitUntil`,
    `onNodeWithTag`, `assertIsDisplayed`, `liveRegion` semantics, `printToLog`). UNVERIFIED-ASSUMPTION
    (framework ref). Not derivable from backend/frontend sources; these are standard AndroidX Compose
    testing APIs. Framework refs: developer.android.com/jetpack/compose/testing and
    developer.android.com/develop/ui/compose/accessibility (LiveRegion semantics).

15. **MockWebServer behaviors** (`setBodyDelay`, `setSocketPolicy(DISCONNECT_AT_START)`, `Dispatcher`,
    `RecordedRequest`). UNVERIFIED-ASSUMPTION (framework ref). OkHttp `mockwebserver` library APIs;
    framework ref: square.github.io/okhttp/ (MockWebServer). Correct as standard usage.

16. **Hilt test wiring** (`HiltAndroidRule`, `@HiltAndroidTest`, `@TestInstallIn` to swap base URL to
    `server.url("/")`). UNVERIFIED-ASSUMPTION (framework ref). Standard Hilt testing; depends on AND-046
    actually exposing the documented `@TestInstallIn` module. Framework ref:
    developer.android.com/training/dependency-injection/hilt-testing.

### Corrections made

- **FR-1 / §5 no-MFA fixture:** removed the false "finalize" step; the no-MFA branch calls `GET /ui/me`
  directly and is gated on a non-null `session_id`. Added `session_id` to the no-MFA response fixture and
  to the §5 response schema notes (per `UiSessionStartResp` + `src/pages/Login.tsx`).
- **FR-5 / §11:** changed "invalid email format" validation to "required (non-empty)" to match the web
  Zod schema (`min(1)` only); renamed the matrix test to `blankField_showsRequiredFieldError_submitDisabled`.
- **FR-8:** noted that `normalizeErrorDetail` joins ALL array `msg` values with `", "` (not only the first).
- **§5 request:** annotated as verified against `UiSessionStartReq` + `src/pages/Login.tsx`.

### Open assumptions

- **OA-1 — 503/5xx body shape for `/ui/session/start`** is undocumented in OpenAPI (only 200/422 listed).
  Treated as non-load-bearing: tests assert the generic banner for any unmapped 5xx regardless of body.
- **OA-2 — AND-031 `LoginUiState`/`LoginEffect` field names** (e.g. `errorBanner`, `NavigateToMfa(challengeId, factors)`)
  cannot be verified from backend/frontend sources; they are owned by AND-031 and assumed stable per that ticket.
- **OA-3 — A stateless `LoginScreen(state, ...)` overload + production `testTag`/`liveRegion` semantics**
  depend on AND-030; not verifiable here (mirrors draft R1/R4).
- **OA-4 — Exact Android-side error-banner copy / `R.string.*` keys** depend on AND-031 string resources,
  not the sources; tests resolve via `R.string.*` rather than literals (mirrors draft R3).
- **OA-5 — Whether OkHttp timeout is Hilt-configurable for the timeout test** depends on AND-028/AND-046
  (mirrors draft R2).
- **OA-6 — Stricter Android email-format validation**, if AND-031 adds it beyond web parity, is an
  unconfirmed product decision; do not assert an email-format message until confirmed.

## 17. Test Plan

All cases are instrumented Compose-UI tests unless noted. Default target: **headless emulator AVD
`test35` (API 35)** in CI, which satisfies AC-1 (no display attached). None of these cases exercise
camera, biometrics, FCM, WebRTC, Telecom, or real-network streaming, so the **physical Samsung Galaxy
A15 (API 34) is not required** for functional correctness — its only added value here is the optional
ABI/API-skew smoke (TC-AND-048-13). MockWebServer binds to localhost; no live host is contacted.

Acceptance Criteria referenced are from §14 (AC-1..AC-7).

- **TC-AND-048-01 — No-MFA happy path → NavigateToHome.**
  Type: contract/MockWebServer + Compose-UI. Target: emulator `test35`.
  Preconditions: Hilt base URL swapped to `server.url("/")`; fresh in-memory cookie jar with `ui_csrf`;
  enqueue `session_start_no_mfa.json` (`auth_required:false`, non-null `session_id`) for
  `POST /ui/session/start`, then a 200 `me` fixture for `GET /ui/me`.
  Steps: render `LoginRoute`; type valid username + password; tap **Sign in**;
  `waitUntil { effects.isNotEmpty() }`.
  Expected: exactly one `LoginEffect.NavigateToHome`; dispatcher recorded one `/ui/session/start`
  then one `/ui/me`; **no** `/ui/session/finalize` request. Traces: AC-2.

- **TC-AND-048-02 — MFA-required happy path → NavigateToMfa carries challenge_id + factors.**
  Type: contract/MockWebServer + Compose-UI. Target: emulator `test35`.
  Preconditions: enqueue `session_start_mfa_required.json` (`auth_required:true`,
  `challenge_id:"chal_..."`, `required_factors:["totp"]`).
  Steps: render `LoginRoute`; type valid credentials; tap **Sign in**; await effect.
  Expected: exactly one `LoginEffect.NavigateToMfa` whose `challengeId` and `factors` equal the
  fixture's `challenge_id` / `required_factors`. Traces: AC-2.

- **TC-AND-048-03 — In-flight loading disables form, then re-enables.**
  Type: Compose-UI (timing). Target: emulator `test35`.
  Preconditions: enqueue no-MFA response with a small `setBodyDelay`.
  Steps: type valid credentials; tap **Sign in**; `waitUntil` progress is displayed; assert SUBMIT +
  USERNAME + PASSWORD disabled; let response complete; await terminal.
  Expected: progress shown and inputs/submit disabled during flight; controls re-enable after terminal
  state. Traces: AC-6.

- **TC-AND-048-04 — Empty fields: submit disabled, zero network calls.**
  Type: Compose-UI + contract. Target: emulator `test35`.
  Preconditions: dispatcher recording enabled; no responses needed.
  Steps: render with both fields empty; assert SUBMIT disabled; force a click on SUBMIT.
  Expected: SUBMIT `isNotEnabled`; MockWebServer `requestCount == 0`. Traces: AC-3.

- **TC-AND-048-05 — Blank/whitespace field shows required-field error; correction clears + enables.**
  Type: Compose-UI. Target: emulator `test35`.
  Preconditions: render stateless `LoginScreen` with explicit state OR drive `LoginRoute` VM.
  Steps: type a valid password, leave username blank (or whitespace); assert inline "required" error and
  SUBMIT disabled; type a valid username; assert error cleared and SUBMIT enabled.
  Expected: required error appears for the blank field, clears on correction, submit toggles accordingly.
  (No email-format assertion — web parity is non-empty only.) Traces: AC-3.

- **TC-AND-048-06 — Password show/hide toggle flips masked/plain.**
  Type: Compose-UI (semantics). Target: emulator `test35`.
  Preconditions: render screen; type a password.
  Steps: assert field masked by default (`SemanticsProperties.Password` / no plain `EditableText`); tap
  PASSWORD_TOGGLE; assert plain text exposed; tap again; assert masked.
  Expected: visibility toggles correctly; default is masked. Traces: AC-7.

- **TC-AND-048-07 — 401 invalid credentials banner; form re-enabled; no effect; single request.**
  Type: contract/MockWebServer + Compose-UI. Target: emulator `test35`.
  Preconditions: enqueue 401 `{ "detail": "Invalid username or password" }`.
  Steps: type valid-format credentials; tap **Sign in**; await banner.
  Expected: ERROR_BANNER shows the mapped invalid-credentials string (resolved via `R.string.*`);
  SUBMIT re-enabled; zero `LoginEffect`s; dispatcher recorded exactly one `/ui/session/start` (no
  auto-retry). Traces: AC-4.

- **TC-AND-048-08 — 422 validation detail renders mapped message.**
  Type: contract/MockWebServer + Compose-UI. Target: emulator `test35`.
  Preconditions: enqueue 422 `HTTPValidationError` fixture
  `{ "detail": [ { "loc":["body","challenge_context","username"], "msg":"field required", "type":"missing" } ] }`.
  Steps: submit valid-format credentials; await banner.
  Expected: ERROR_BANNER contains the mapped `msg` (joined form accepted for multi-item); form
  re-enabled; no effect. Traces: AC-4.

- **TC-AND-048-09 — 503 generic recoverable banner; exactly one request (no auto-retry).**
  Type: contract/MockWebServer + Compose-UI. Target: emulator `test35`.
  Preconditions: enqueue a single 503 response.
  Steps: submit; await banner.
  Expected: generic recoverable banner (`R.string` generic error); SUBMIT re-enabled; dispatcher
  recorded exactly one `/ui/session/start`. Traces: AC-4.

- **TC-AND-048-10 — Timeout path renders offline/recoverable banner; form re-enabled.**
  Type: contract/MockWebServer + Compose-UI. Target: emulator `test35`.
  Preconditions: shortened OkHttp timeout via test `NetworkConfig` (preferred) and a `setBodyDelay`
  exceeding it; OR a long delay against the real timeout (slower).
  Steps: submit; `waitUntil` (bounded) banner appears.
  Expected: timeout/offline banner; SUBMIT re-enabled. Traces: AC-4, AC-5.

- **TC-AND-048-11 — Connection drop (offline) renders generic banner.**
  Type: contract/MockWebServer + Compose-UI. Target: emulator `test35`.
  Preconditions: `MockResponse().setSocketPolicy(DISCONNECT_AT_START)`.
  Steps: submit; await banner.
  Expected: generic error banner (the web layer maps a transport failure to a network error);
  SUBMIT re-enabled. Traces: AC-4.

- **TC-AND-048-12 — Security/a11y guards.**
  Type: Compose-UI (semantics, a11y). Target: emulator `test35`.
  Preconditions: render screen; trigger a 401 to populate the error banner.
  Steps: assert password masked by default; assert ERROR_BANNER node carries
  `SemanticsProperties.LiveRegion == Polite`; assert SUBMIT and PASSWORD_TOGGLE expose non-empty
  `contentDescription`/label; assert no typed credential substring (`hunter2`) appears in any rendered
  banner/error text.
  Expected: all assertions pass. Traces: AC-7.

- **TC-AND-048-13 — CSRF header propagation on submit.**
  Type: contract/MockWebServer. Target: emulator `test35`.
  Preconditions: seed the in-memory cookie jar with `ui_csrf=<value>`; enqueue no-MFA + me responses.
  Steps: submit valid credentials; inspect the `RecordedRequest` for `/ui/session/start`.
  Expected: request carries header `X-CSRF-Token: <value>` matching the cookie (mirrors
  `src/api/client.ts`). Traces: AC-2 (transport correctness of the happy path).

- **TC-AND-048-14 — Headless determinism / ABI-API skew smoke.**
  Type: instrumented/e2e (suite-level). Target: PRIMARY headless emulator `test35` (API 35, x86_64) for
  the gate; ALSO run once on the PHYSICAL Samsung Galaxy A15 (SM-A156U, API 34, arm64-v8a) to catch
  arm64-vs-x86 / API-34-vs-35 differences. (This is the only case where the physical device adds value;
  it MUST run on the device for the ABI/API-skew check.)
  Preconditions: full `feature-auth` androidTest suite; no display attached for the emulator run.
  Steps: run the suite headlessly 3 consecutive times on `test35`; run once on the A15.
  Expected: green on all 3 headless runs (no `Thread.sleep`, all waits bounded, per-test isolation) and
  green on the A15. Traces: AC-1, AC-5.

### Coverage matrix (§14 AC → TC)

| Acceptance criterion | Covered by |
|---|---|
| AC-1 (passes headlessly on api35) | TC-AND-048-14 (and all cases run on `test35`) |
| AC-2 (happy path: one NavigateToHome / one NavigateToMfa with payload) | TC-AND-048-01, TC-AND-048-02, TC-AND-048-13 |
| AC-3 (validation: disabled + zero requests; errors appear/clear) | TC-AND-048-04, TC-AND-048-05 |
| AC-4 (401/422/503/timeout/drop banners; re-enable; 5xx single request) | TC-AND-048-07, TC-AND-048-08, TC-AND-048-09, TC-AND-048-10, TC-AND-048-11 |
| AC-5 (determinism; isolation; 3 consecutive runs) | TC-AND-048-10, TC-AND-048-14 |
| AC-6 (loading shows progress + disables, then re-enables) | TC-AND-048-03 |
| AC-7 (masked default; live-region banner; a11y labels; no credential leak) | TC-AND-048-06, TC-AND-048-12 |
