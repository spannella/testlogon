---
id: AND-049
title: "Compose UI tests: MFA"
milestone: M1
epic: E07
priority: P0
size: M
status: draft
depends_on: [AND-040, AND-046]
blocks: []
---

# AND-049 — Compose UI tests: MFA

## 1. Overview & Goal

Deliver an instrumented Jetpack Compose UI test suite that exercises the multi-factor
authentication (MFA) step of the cookie-based login flow end-to-end at the UI layer. The
suite drives the real `MfaRoute`/`MfaScreen` Composable wired to a real `MfaViewModel`
(AND-040) and a real `AuthRepository`, with only the network boundary faked via the
`MockWebServer` harness and JSON fixtures from AND-046. The two flows in scope are the
**TOTP** factor and the **SMS** factor, including the **wrong-code error** path for each.

The goal is a deterministic, hermetic, headless-capable test target that asserts the
observable UI contract: which factor selector/inputs render, what the user types, which
endpoints are hit with which payloads, how success navigates onward, and how a rejected
code surfaces an inline error without losing the entered challenge. This ticket adds *only
tests and test infrastructure*; it does not modify production MFA code. If the tests reveal
a production defect, the fix is filed against AND-040 (state machine) or the MFA screen
ticket, not absorbed here.

Success is defined narrowly and verifiably: `./gradlew :feature-auth:connectedDebugAndroidTest`
(or the Robolectric-backed `testDebugUnitTest` variant, see §4) passes with no network
access, no flakiness across 20 consecutive runs, and the four canonical cases (TOTP-OK,
TOTP-wrong, SMS-OK, SMS-wrong) green.

## 2. Context & References

- App module: `android/feature-auth` (test source set `src/androidTest` and/or
  `src/test` per §4), package `com.testlogon.android.feature.auth`.
- Production collaborators under test:
  - `MfaViewModel` (AND-040) — state machine over `challengeId` / `requiredFactors` /
    `remainingFactors`; emits `StateFlow<MfaUiState>`; nav-on-success.
  - `MfaScreen` / `MfaRoute` Composables — TOTP and SMS factor UIs.
  - `AuthRepository` (AND-028/AND-038) — `mfaBegin`/`mfaVerify`/`finalize`.
- Test infrastructure (AND-046): `core-testing` `MockWebServerRule`, `enqueueFixture(...)`,
  and captured fixtures under `core-testing/src/main/resources/fixtures/auth/`.
- Sibling/parallel test tickets for consistency of conventions: AND-047 (AuthRepository
  contract tests), AND-048 (Compose UI tests: login).
- Backend reference: FastAPI `POST /ui/mfa/{totp|sms|email}/begin|verify`, `POST
  /ui/session/finalize`, error `detail` shapes; OpenAPI at `/openapi.json`. Web reference
  `frontend/src/api/endpoints/*.ts`.
- Stack: Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Navigation-Compose, Coroutines,
  Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, minSdk 24, compileSdk/targetSdk 35, JDK 17,
  AGP 8.7.3, Gradle 8.9.

## 3. Functional Requirements

The suite MUST assert the following observable behaviors. Each maps to one or more tests in
§11.

FR-1 **Factor rendering.** Given a challenge whose `required_factors` contains `"totp"`,
the TOTP entry UI (6-digit code field tagged `mfa_totp_code`, submit button tagged
`mfa_submit`) renders. Given `"sms"`, the SMS UI renders with a "request/resend code"
affordance (`mfa_sms_send`) and a code field (`mfa_sms_code`).

FR-2 **TOTP happy path.** Entering a valid 6-digit code and tapping submit issues
`POST /ui/mfa/totp/verify`, then `POST /ui/session/finalize`, and the screen emits a
navigation event to the post-auth destination (asserted via a fake `onAuthenticated`
nav callback, not a real graph traversal).

FR-3 **TOTP wrong-code error.** A rejected code (`verify` returns 4xx with an error
`detail`) renders an inline, human-readable error message bound to the code field, leaves
the user on the MFA screen, keeps `challengeId` intact, re-enables the submit button, and
does NOT call `finalize`.

FR-4 **SMS begin → verify happy path.** Tapping send issues `POST /ui/mfa/sms/begin`
(carrying `challenge_id`); on success a code field becomes enabled; entering the delivered
code and submitting issues `POST /ui/mfa/sms/verify` then `finalize`, then navigates.

FR-5 **SMS wrong-code error.** Same contract as FR-3 for the SMS factor, including that a
prior successful `begin` is not re-issued on a verify retry (resend is explicit).

FR-6 **Input validation gating.** Submit is disabled / no network call is made until the
code field meets the length constraint (6 digits for TOTP). Validation is the screen's, but
the test asserts the *effect* (button enabled state + absence of a recorded request).

FR-7 **CSRF/header propagation is observable at the boundary.** Because verify/begin are
state-changing POSTs, the recorded request MUST carry the `X-CSRF-Token` header sourced
from the `ui_csrf` cookie (seeded by the fixture). The suite asserts header presence on at
least one verify request to guard against regressions in the OkHttp interceptor chain.

FR-8 **Headless execution.** All tests run without a connected device when executed via the
Robolectric-backed Compose unit-test path (preferred CI mode) and also pass on an emulator
via `connectedDebugAndroidTest`.

## 4. Technical Design

**Execution strategy.** Use **Robolectric + Compose `createComposeRule()`** in the
`src/test` (JVM unit) source set as the primary, headless CI target, and keep the same
tests source-compatible with `createAndroidComposeRule<ComponentActivity>()` in
`src/androidTest` for on-device runs. To avoid duplication, place the shared test bodies in
a common abstract base and provide thin subclasses per runner, or gate the rule factory
behind a small `composeRule` helper. Primary CI gate is the Robolectric variant so that
"pass headlessly" (AC) is satisfied without an emulator.

```kotlin
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = HiltTestApplication::class)
class MfaTotpUiTest {
    @get:Rule(order = 0) val hiltRule = HiltAndroidRule(this)
    @get:Rule(order = 1) val server = MockWebServerRule()      // from core-testing (AND-046)
    @get:Rule(order = 2) val compose = createComposeRule()
}
```

**Subject under test.** Render the real screen against a real ViewModel:

```kotlin
private fun setMfaContent(
    challenge: PendingChallenge,
    onAuthenticated: () -> Unit = {},
) {
    compose.setContent {
        TestLogonTheme {
            MfaRoute(
                viewModel = mfaViewModel,            // Hilt-injected, real
                onAuthenticated = onAuthenticated,   // fake nav sink
                onBack = {},
            )
        }
    }
}
```

The ViewModel and `AuthRepository` are the production implementations, obtained either via
Hilt test injection (replacing only the OkHttp `baseUrl` with `server.url("/")` through a
`@TestInstallIn` network module override in `core-testing`) or via direct construction in
the test where Hilt graph setup is disproportionate. Preferred: Hilt + `@TestInstallIn`
override of `NetworkModule.provideBaseUrl()` so the entire interceptor/cookie-jar chain
(including CSRF) is real.

**Idle synchronization.** Rely on Compose's auto-sync; disable it only where a MockWebServer
dispatcher introduces latency, using `compose.mainClock.autoAdvance` and
`compose.waitUntil { ... }` keyed on node existence rather than fixed sleeps. No
`Thread.sleep`. Coroutines run on a real dispatcher driving real OkHttp against the local
MockWebServer, so assertions wait on UI state via `waitUntil`/`assertExists`.

**Node addressing.** Address nodes by stable `Modifier.testTag(...)` constants, not by
localized text, to keep tests i18n-stable. Introduce a shared `MfaTestTags` object in the
test source set mirroring the tags the screen already exposes:

```kotlin
object MfaTestTags {
    const val TotpCode = "mfa_totp_code"
    const val SmsCode  = "mfa_sms_code"
    const val SmsSend  = "mfa_sms_send"
    const val Submit   = "mfa_submit"
    const val Error    = "mfa_error"
}
```

If a required tag is missing on the production screen, this ticket adds the `testTag`
(non-behavioral) to the screen and notes it in §13; no logic changes.

**Request assertion helper.** Wrap `MockWebServer.takeRequest(timeout)` in a helper that
returns a parsed `RecordedRequest` and exposes JSON-body matchers:

```kotlin
fun RecordedRequest.bodyJson(): Map<String, Any?>
fun MockWebServerRule.takeRequestOrFail(path: String, timeoutMs: Long = 5_000): RecordedRequest
```

## 5. API Contract

This ticket consumes (does not define) the MFA endpoints; the canonical contract is owned
by AND-038/AND-040. The fixtures (AND-046) MUST match these shapes. The suite asserts
outbound requests and feeds canned responses.

`POST /ui/mfa/totp/verify` — request body:
```json
{ "challenge_id": "chg_abc123", "code": "123456" }
```
Success `200`:
```json
{ "auth_required": true, "remaining_factors": [], "next": "finalize" }
```
Rejected `400`/`401` (error `detail` mapping — string | array | object):
```json
{ "detail": "Invalid verification code" }
```
or
```json
{ "detail": [{ "msg": "code is invalid", "loc": ["body","code"] }] }
```
or
```json
{ "detail": { "code": "mfa_invalid", "message": "Invalid code" } }
```

`POST /ui/mfa/sms/begin` — request body `{ "challenge_id": "chg_abc123" }`; success `200`
`{ "sent": true, "expires_in": 300 }`.

`POST /ui/mfa/sms/verify` — request `{ "challenge_id": "chg_abc123", "code": "654321" }`;
success/rejection shapes identical to TOTP verify.

`POST /ui/session/finalize` — empty/`{}` body; success `200` `{ "authenticated": true }`,
sets session cookie. Followed in production by `GET /ui/me` (the test enqueues a minimal
`me` fixture so the post-auth callback fires).

All POSTs carry header `X-CSRF-Token: <value of ui_csrf cookie>` and the persistent cookie
jar's `Cookie` header; the fixture for the preceding step seeds `Set-Cookie: ui_csrf=...`.

## 6. Data & State Management

The tests observe `MfaViewModel`'s `StateFlow<MfaUiState>` indirectly through rendered UI,
and directly in a small number of white-box assertions where UI cannot reveal a field
(e.g., that `challengeId` survives a wrong-code error). Expected state model (from AND-040):

```kotlin
data class MfaUiState(
    val challengeId: String,
    val activeFactor: Factor,            // Totp | Sms | Email
    val remainingFactors: List<Factor>,
    val code: String = "",
    val smsSent: Boolean = false,
    val isSubmitting: Boolean = false,
    val error: String? = null,           // mapped FastAPI detail
    val navEvent: MfaNavEvent? = null,    // Authenticated | NextFactor
)
```

Seed state is established by constructing/injecting a `PendingChallenge` (id
`"chg_abc123"`, `requiredFactors=[Totp]` or `[Sms]`) as the ViewModel's start input, the
same way the login → MFA navigation supplies it in production. No Room/DataStore writes are
exercised here beyond what `AuthRepository` does internally; DataStore uses a test-scoped
in-memory/`tmp` file via the AND-046 harness. The cookie jar is the production persistent
jar pointed at a temp file, cleared in `@Before`.

Assertions on state transitions: `idle → submitting → (authenticated | error)` for verify;
`idle → smsSending → smsSent(true) → submitting → ...` for SMS. The wrong-code case asserts
terminal `error != null`, `isSubmitting == false`, `challengeId` unchanged, `navEvent == null`.

## 7. Error Handling & Resilience

The suite is itself a resilience guard for the production error path, and must be robust
against the unreliable-backend design without coupling to real network behavior.

- **Wrong-code mapping (core assertion):** enqueue each of the three `detail` variants and
  assert a single, non-empty, human-readable string renders in the `mfa_error` node. This
  pins the FastAPI `detail` → UI mapping (string | `[{msg}]` | `{code,message}`).
- **No-finalize-on-failure:** after a rejected verify, assert MockWebServer received NO
  request to `/ui/session/finalize` (drain queue and assert path mismatch / `takeRequest`
  timeout).
- **Retry after error:** assert the user can correct the code and a second verify succeeds;
  for SMS, assert `begin` is NOT re-sent on the verify retry.
- **Determinism:** MockWebServer `Dispatcher` keyed by method+path returns fixtures
  synchronously; no real timeouts/backoff are exercised here (those belong to the repository
  contract tests, AND-047). Tests must not depend on wall-clock or network reachability.
- **401 refresh path is out of scope** for the MFA verify happy/error cases and is covered
  in AND-047; if a verify fixture returns 401 the test treats it as the wrong-code/rejection
  branch only when the fixture omits a refresh trigger.

## 8. Security & Privacy

- The MFA `code` is test-only synthetic data; no real secrets. Fixtures contain no live
  cookies or tokens — `ui_csrf`/session values are placeholder strings.
- The suite asserts the `X-CSRF-Token` header is present and equals the seeded `ui_csrf`
  cookie value on state-changing POSTs (FR-7), guarding the CSRF protection from silent
  regression.
- Assert that the entered code is not echoed into any rendered error string verbatim (the
  error node shows the server message, not the user's secret) — a lightweight privacy guard.
- MockWebServer binds to localhost loopback only; no external network. No PLAINTEXT-HTTP dev
  host (`18.222.237.167:8000`) is contacted from tests.

## 9. Accessibility & i18n

- All node selection uses `testTag` semantics, never localized strings, so the suite stays
  green under translation (consistent with AND-048).
- Add one a11y-oriented assertion: the code fields expose a non-empty
  `contentDescription`/`SemanticsProperties.Text` and the submit button is
  `assertHasClickAction()` and `assertIsEnabled()/assertIsNotDisabled()` as appropriate.
- Assert the error message is announced via a node carrying a `liveRegion` semantics
  property (Material 3 supporting text / `Modifier.semantics { liveRegion = Polite }`) so
  TalkBack reads code rejections. If the production screen lacks this, file under AND-040 and
  mark the assertion `@Ignore("AND-040")` with a tracking note rather than weakening it.

## 10. Telemetry & Logging

No production telemetry is added by this ticket. Test-side observability only:

- On failure, dump the full MockWebServer request log and the last `MfaUiState` via a JUnit
  `TestWatcher` in `core-testing` to make CI failures diagnosable.
- Capture a Compose semantics tree dump (`compose.onRoot().printToString()`) into the test
  failure message on assertion error.
- No analytics SDK is invoked; if `MfaViewModel` emits analytics events, the test injects a
  no-op/fake sink to keep runs hermetic.

## 11. Testing Strategy

Test classes in `feature-auth/src/test/.../auth/mfa/` (Robolectric primary) with mirror
subclasses in `src/androidTest` if on-device coverage is enabled in CI.

`MfaTotpUiTest`:
- `totp_validCode_verifiesThenFinalizes_navigatesAuthenticated()` (FR-2)
- `totp_wrongCode_showsInlineError_staysOnScreen_noFinalize()` (FR-3)
- `totp_wrongCode_detailVariants_allMapToError()` — parameterized over string/array/object
  `detail` (FR-3, §7)
- `totp_shortCode_submitDisabled_noRequest()` (FR-6)
- `totp_verify_sendsCsrfHeader()` (FR-7)
- `totp_recoverAfterError_secondAttemptSucceeds()` (§7 retry)

`MfaSmsUiTest`:
- `sms_send_issuesBeginWithChallengeId_enablesCodeField()` (FR-4)
- `sms_validCode_verifiesThenFinalizes_navigates()` (FR-4)
- `sms_wrongCode_showsInlineError_noFinalize_noBeginResend()` (FR-5)
- `sms_resend_issuesSecondBegin()` (FR-5 explicit resend)

Shared base `MfaUiTestBase` holds the Hilt/MockWebServer/compose rules, `setMfaContent`,
tag constants, and request helpers. Fixtures referenced by stable names:
`mfa_totp_verify_ok.json`, `mfa_verify_invalid.json`, `mfa_verify_invalid_array.json`,
`mfa_verify_invalid_object.json`, `mfa_sms_begin_ok.json`, `mfa_sms_verify_ok.json`,
`finalize_ok.json`, `me_min.json` (provided/extended via AND-046).

Quality bars:
- 0 `Thread.sleep`; all waits via `waitUntil`/idling.
- Each test ≤ 3s on Robolectric.
- Flake gate: `--rerun-tasks` 20x in CI must be 20/20 green (documented in PR).
- Coverage target: every `MfaUiState`-affecting branch reachable from TOTP/SMS UI is hit.

## 12. Dependencies & Sequencing

- **Hard depends on AND-040** (`MfaViewModel` state machine) — the subject under test; tests
  cannot be authored until its public state/events and the `MfaRoute`/`MfaScreen` signatures
  are stable.
- **Hard depends on AND-046** (`MockWebServer` harness + fixtures) — provides
  `MockWebServerRule`, `@TestInstallIn` network override, and the auth fixtures; this ticket
  extends the fixture set with the MFA-specific JSON listed in §11.
- **Soft alignment with AND-048** (login UI tests) — reuse the same Robolectric/Hilt/compose
  rule conventions, base class pattern, and tag-based addressing to keep the test target
  uniform.
- **Soft alignment with AND-047** (repository contract tests) — avoid duplicating
  network-resilience/refresh coverage here; this ticket stays at the UI contract layer.
- Sequencing: land after AND-040 and AND-046 merge; can land before or concurrently with
  AND-047/AND-048. **Blocks:** none.

## 13. Risks & Open Questions

- **R1 Missing testTags on production screen.** If `MfaScreen` lacks the tags in §4, this
  ticket adds non-behavioral `testTag` modifiers. Risk: scope creep into AND-040. Mitigation:
  keep changes purely additive and tag-only; flag in PR.
- **R2 Robolectric Compose stability.** Some Material 3 / animation paths can be flaky under
  Robolectric. Mitigation: `mainClock` control, disable animations via test theme, fall back
  to `connectedAndroidTest` for any irreducibly device-only assertion.
- **R3 Hilt + MockWebServer baseUrl wiring** depends on AND-046 exposing a `@TestInstallIn`
  override. Open question: does AND-046 provide that, or must this ticket add it? Assume it
  provides the override; if not, this ticket adds it to `core-testing` (additive).
- **R4 SMS UX shape.** Whether SMS uses an explicit "send" affordance vs. auto-begin on
  screen entry affects FR-4. Open question for AND-040; tests target the explicit-send
  contract and will adjust if the screen auto-begins.
- **R5 `email` factor** is explicitly out of scope (ticket scope names TOTP + SMS only);
  email-factor UI tests, if needed, are a follow-up.

## 14. Acceptance Criteria

AC-1 The MFA Compose UI test suite passes **headlessly** (Robolectric `testDebugUnitTest`)
with no network/emulator, satisfying the source AC.
AC-2 TOTP happy path test asserts `verify` → `finalize` request order and an `Authenticated`
nav callback fires (FR-2).
AC-3 TOTP wrong-code test asserts an inline error renders, screen is retained, `finalize` is
NOT called, and submit re-enables (FR-3); all three FastAPI `detail` variants map to a
non-empty error message.
AC-4 SMS flow test asserts `begin` (with `challenge_id`) enables the code field, then
`verify` → `finalize` → navigation (FR-4).
AC-5 SMS wrong-code test asserts inline error, no `finalize`, and no implicit `begin` resend
(FR-5).
AC-6 At least one verify request is asserted to carry the `X-CSRF-Token` header equal to the
seeded `ui_csrf` cookie (FR-7).
AC-7 Validation gating test confirms no network request is issued for an under-length TOTP
code (FR-6).
AC-8 Suite is deterministic: 20/20 green across reruns; zero `Thread.sleep`.

## 15. Definition of Done

- New test classes `MfaTotpUiTest`, `MfaSmsUiTest`, and base `MfaUiTestBase` added under
  `android/feature-auth/src/test/java/com/testlogon/android/feature/auth/mfa/` (and mirrored
  androidTest subclasses if on-device CI is enabled).
- MFA-specific fixtures added/extended in `core-testing` per §11 and confirmed to match live
  backend shapes captured in AND-046.
- `./gradlew :feature-auth:testDebugUnitTest` green headlessly in CI; `connectedDebugAndroidTest`
  green on the reference emulator.
- 20-run flake check documented as passing in the PR description.
- Any added production `testTag`s are tag-only and reviewed; no MFA logic changed under this
  ticket.
- All four canonical cases (TOTP-OK, TOTP-wrong, SMS-OK, SMS-wrong) green; CSRF and
  no-finalize-on-failure guards in place.
- Code review approved; CI gate wired so the MFA UI suite runs on every PR touching
  `feature-auth` or `core-network`/`core-data` auth code.
