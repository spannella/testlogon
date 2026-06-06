---
id: AND-049
title: "Compose UI tests: MFA"
milestone: M1
epic: E07
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
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
- Backend reference (verified against OpenAPI index): `POST /ui/mfa/totp/verify`,
  `POST /ui/mfa/sms/begin`, `POST /ui/mfa/sms/verify`, `POST /ui/session/finalize`,
  `GET /ui/me`. NOTE: there is **no** `POST /ui/mfa/totp/begin` — TOTP has only `verify`
  (SMS and email have `begin`+`verify`). Error `detail` shapes are normalized by the web
  client (`normalizeErrorDetail`, see §7); OpenAPI at `/openapi.json`. Web reference
  `frontend/src/api/endpoints/auth.ts` and `src/api/types.ts`. See §16 for full citations.
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

`POST /ui/mfa/totp/verify` — request body (`TotpVerifyReq`; **CORRECTED** — the field is
`totp_code`, NOT `code`):
```json
{ "challenge_id": "chg_abc123", "totp_code": "123456" }
```
Success `200` (`MfaVerifyResp`; **CORRECTED** — there is no `auth_required`/`next` field;
the web client routes to finalize when `remaining_factors` is empty):
```json
{ "status": "ok", "session_id": "sess_x", "required_factors": ["totp"],
  "passed": { "totp": true }, "remaining_factors": [] }
```
Rejected (error `detail` mapping — string | array | object). NOTE: OpenAPI documents only
`422:HTTPValidationError` (array-of-`ValidationError` with `msg`/`loc`/`type`) for these
endpoints; the string and object `detail` variants are app-level error bodies observed via
the web client's `normalizeErrorDetail`. A wrong code surfaces as a non-200 with a `detail`:
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

`POST /ui/mfa/sms/begin` — request body `SmsBeginReq` `{ "challenge_id": "chg_abc123" }`;
success `200` returns `ChallengeResp` (**CORRECTED** — not `{sent, expires_in}`):
```json
{ "challenge_id": "chg_abc123", "sent_to": ["+1******1234"] }
```

`POST /ui/mfa/sms/verify` — request `SmsVerifyReq`
`{ "challenge_id": "chg_abc123", "code": "654321" }` (SMS verify DOES use `code`, unlike
TOTP); success returns `MfaVerifyResp` (same shape as TOTP verify) and rejection shapes
are identical to TOTP verify.

`POST /ui/session/finalize` — request body `UiSessionFinalizeReq` (**CORRECTED** — NOT an
empty/`{}` body; it carries the `challenge_id`, with optional `remember_device`):
```json
{ "challenge_id": "chg_abc123", "remember_device": false }
```
Success `200` returns `SessionFinalizeResp` (**CORRECTED** — not `{authenticated: true}`):
```json
{ "status": "ok", "session_id": "sess_x", "required_factors": ["totp"],
  "passed": { "totp": true } }
```
and sets the session cookie. The web client calls `finalize` only after a `verify` whose
`remaining_factors` is empty (see `src/pages/Login.tsx`). Followed in production by
`GET /ui/me` (the test enqueues a minimal `me` fixture so the post-auth callback fires).

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

## 16. Citations & Assumption Audit

Each key technical claim with VERDICT and SOURCE pointer. Sources: OpenAPI index
(`reference/openapi.index.txt`), OpenAPI full spec (`reference/openapi.pretty.json`,
`components.schemas.<Name>`), or frontend paths under `reference/src/`.

1. **`POST /ui/mfa/totp/verify` exists.** VERDICT: Verified. SOURCE: OpenAPI
   `POST /ui/mfa/totp/verify` (op `ui_totp_verify_ui_mfa_totp_verify_post`, req
   `TotpVerifyReq`); frontend `src/api/endpoints/auth.ts: verifyTotp`.
2. **`POST /ui/mfa/sms/begin` exists.** VERDICT: Verified. SOURCE: OpenAPI
   `POST /ui/mfa/sms/begin` (req `SmsBeginReq`); `src/api/endpoints/auth.ts: beginSms`.
3. **`POST /ui/mfa/sms/verify` exists.** VERDICT: Verified. SOURCE: OpenAPI
   `POST /ui/mfa/sms/verify` (req `SmsVerifyReq`); `src/api/endpoints/auth.ts: verifySms`.
4. **`POST /ui/session/finalize` exists.** VERDICT: Verified. SOURCE: OpenAPI
   `POST /ui/session/finalize` (req `UiSessionFinalizeReq`);
   `src/api/endpoints/auth.ts: sessionFinalize`.
5. **`GET /ui/me` exists for the post-auth callback.** VERDICT: Verified. SOURCE: OpenAPI
   `GET /ui/me` (op `ui_me_ui_me_get`).
6. **There is NO `POST /ui/mfa/totp/begin`.** VERDICT: Corrected (spec §2 implied a
   `totp/.../begin`). SOURCE: OpenAPI index — TOTP login factor has only `.../totp/verify`;
   only `sms` and `email` have `begin`. No `ui_totp_begin` op exists.
7. **TOTP verify request field is `totp_code` (not `code`).** VERDICT: Corrected (spec §5
   said `code`). SOURCE: OpenAPI `components.schemas.TotpVerifyReq` =
   `{challenge_id, totp_code}` (both required); frontend `src/pages/Login.tsx`
   (`verifyTotp({ challenge_id, totp_code: ... })`); `src/api/types.ts: TotpVerifyReq`.
8. **SMS verify request field IS `code`.** VERDICT: Verified. SOURCE:
   `components.schemas.SmsVerifyReq` = `{challenge_id, code}`; `src/api/types.ts: SmsVerifyReq`.
9. **SMS begin request body is `{challenge_id}`.** VERDICT: Verified. SOURCE:
   `components.schemas.SmsBeginReq`; `src/api/types.ts: SmsBeginReq`.
10. **SMS begin success returns `ChallengeResp {challenge_id, sent_to?}` (not
    `{sent, expires_in}`).** VERDICT: Corrected (spec §5). SOURCE:
    `src/api/endpoints/auth.ts: beginSms` (typed `api.post<ChallengeResp>`);
    `src/api/types.ts: ChallengeResp`. OpenAPI 200 has no body schema (`resp=200:`), so the
    field shape is taken from the frontend contract.
11. **Verify success returns `MfaVerifyResp {status, session_id?, required_factors, passed,
    remaining_factors}` (not `{auth_required, remaining_factors, next}`).** VERDICT:
    Corrected (spec §5). SOURCE: `src/api/endpoints/auth.ts: verifyTotp/verifySms` (typed
    `MfaVerifyResp`); `src/api/types.ts: MfaVerifyResp`. OpenAPI 200 has no body schema.
12. **`finalize` request carries `challenge_id` (+ optional `remember_device`), not an empty
    body.** VERDICT: Corrected (spec §5). SOURCE: `components.schemas.UiSessionFinalizeReq` =
    `{challenge_id (required), remember_device (default false)}`;
    `src/api/types.ts: SessionFinalizeReq`; `src/pages/Login.tsx`
    (`sessionFinalize({ challenge_id })`).
13. **`finalize` success returns `SessionFinalizeResp {status, session_id?, required_factors,
    passed}` (not `{authenticated: true}`).** VERDICT: Corrected (spec §5). SOURCE:
    `src/api/types.ts: SessionFinalizeResp`; `src/api/endpoints/auth.ts: sessionFinalize`.
14. **Routing to `finalize` is gated on `remaining_factors` being empty (not on a `next`
    field).** VERDICT: Corrected (spec §5 referenced `"next": "finalize"`). SOURCE:
    `src/pages/Login.tsx` (`if (resp.remaining_factors.length === 0) { ... sessionFinalize ... }`).
15. **State-changing requests carry `X-CSRF-Token` sourced from the `ui_csrf` cookie.**
    VERDICT: Verified. SOURCE: `src/api/client.ts` lines 167-170 — reads `getCookie("ui_csrf")`
    and sets `headers.set("X-CSRF-Token", csrf)`. NOTE: the web client sets the header on
    ALL requests when the cookie is present (not only POSTs); the FR-7 assertion on POSTs is
    a valid subset.
16. **Error `detail` has three shapes (string | array-of-`{msg,loc}` | object) collapsed to
    one human-readable string.** VERDICT: Verified. SOURCE: `src/api/client.ts:
    normalizeErrorDetail` (string → as-is; array → join `.msg` by ", "; object →
    `mapAuthorizationError` then `.msg`). The array variant matches OpenAPI
    `components.schemas.HTTPValidationError.detail` = array of `ValidationError {msg, loc,
    type}` (the 422 shape). NOTE: the object variant in the web client is the geo-block
    `{code, message}` style via `mapAuthorizationError`; a generic `{code, message}` MFA
    error is an assumption (see Open assumptions).
17. **Wrong-code rejection is a non-200 with a `detail` body.** VERDICT:
    Unverified-assumption (HTTP status). SOURCE: OpenAPI documents only `422` for these ops;
    the frontend reads `err.detail` for any non-ok status (`src/pages/Login.tsx:
    setError(err.detail || ...)`). The exact code (400 vs 401 vs 422) for a bad MFA code is
    not pinned by the sources; tests should not assert a specific status, only the rejection
    branch + rendered error.
18. **MockWebServer / Robolectric + Compose test harness, `@TestInstallIn` baseUrl override,
    Hilt test injection.** VERDICT: Unverified-assumption (Android-side; depends on AND-046).
    SOURCE: framework ref — Compose testing
    (https://developer.android.com/develop/ui/compose/testing), Robolectric
    (https://robolectric.org), Hilt testing
    (https://developer.android.com/training/dependency-injection/hilt-testing),
    OkHttp MockWebServer (https://square.github.io/okhttp/features/https/#mockwebserver).
19. **`MfaViewModel` / `MfaUiState` / `MfaRoute` signatures and the `PendingChallenge` seed
    (§4, §6).** VERDICT: Unverified-assumption. SOURCE: owned by AND-040; no Android source in
    this repo to verify against. Treated as the contract this ticket targets.
20. **Production `testTag` constants (`mfa_totp_code`, `mfa_sms_code`, `mfa_sms_send`,
    `mfa_submit`, `mfa_error`) (§4).** VERDICT: Unverified-assumption. SOURCE: defined by this
    ticket against the (unseen) AND-040 screen; added tag-only if missing (R1).
21. **No PLAINTEXT dev host (`18.222.237.167:8000`) is contacted; MockWebServer is loopback
    only (§8).** VERDICT: Unverified-assumption (test-design intent; the dev host string is not
    present in the verified sources). SOURCE: ticket-internal design constraint.

### Corrections made

- §2: removed the implied `POST /ui/mfa/totp/begin`; clarified TOTP has only `verify` while
  SMS/email have `begin`+`verify`; corrected the endpoint enumeration and reference paths.
- §5: TOTP verify field `code` → `totp_code` (per `TotpVerifyReq`).
- §5: TOTP/SMS verify success body `{auth_required, remaining_factors, next}` → `MfaVerifyResp`
  `{status, session_id?, required_factors, passed, remaining_factors}`.
- §5: SMS begin success body `{sent, expires_in}` → `ChallengeResp {challenge_id, sent_to?}`.
- §5: `finalize` empty/`{}` body → `UiSessionFinalizeReq {challenge_id, remember_device?}`.
- §5: `finalize` success `{authenticated: true}` → `SessionFinalizeResp {status, session_id?,
  required_factors, passed}`.
- §5: routing-to-finalize is driven by empty `remaining_factors`, not a `next` field; added the
  caveat that error status codes are not pinned (OpenAPI documents only 422).

### Open assumptions

- **Exact rejection HTTP status for a bad MFA code** — sources document only 422 for these
  ops; 400/401 are app-level and unspecified. Tests assert the rejection branch + error text,
  not a status code.
- **Object-shaped `detail` for MFA errors** (`{code, message}`) — observed only for geo-block
  in the web client; whether MFA emits this exact shape is unconfirmed. Fixtures for the
  object variant are a defensive assumption.
- **All Android-side types** (`MfaViewModel`, `MfaUiState`, `MfaRoute`, `PendingChallenge`,
  `AuthRepository.mfaBegin/mfaVerify/finalize`, `MfaNavEvent`) — owned by AND-040; no Android
  source available in this reference repo to verify against.
- **AND-046 harness details** (`MockWebServerRule`, `@TestInstallIn` baseUrl override,
  `enqueueFixture`) — assumed available; if absent this ticket adds them (R3).
- **Production `testTag`s present on `MfaScreen`** — assumed; added tag-only if missing (R1).
- **`liveRegion` semantics on the error node** (§9) — assumed; if absent, filed under AND-040
  and the assertion is `@Ignore`-tracked, not weakened.

## 17. Test Plan

Test IDs `TC-AND-049-NN`. Types: unit | contract/MockWebServer | Compose-UI |
instrumented/e2e | manual. Test targets: **JVM/Robolectric** (local, headless — primary CI
gate); **emulator `test35`** (API 35 x86_64, headless KVM); **physical device** (Samsung
Galaxy A15 5G, SM-A156U, serial R5CX821TA9R, API 34 arm64-v8a). The MFA UI suite is
loopback-only and hardware-independent, so the primary gate is Robolectric; the emulator
mirror exists for on-device parity and the physical device is used only for the ABI/API
parity smoke (TC-13) and an a11y/TalkBack manual check (TC-12).

**TC-AND-049-01 — TOTP factor renders for `required_factors=["totp"]`**
- Type: Compose-UI (Robolectric).
- Target: JVM/Robolectric.
- Preconditions: ViewModel seeded with `PendingChallenge(id="chg_abc123",
  requiredFactors=[Totp])`; MockWebServer up; no requests enqueued.
- Steps: render `MfaRoute`; query nodes by tag.
- Expected: `mfa_totp_code` field and `mfa_submit` button exist; no SMS send affordance;
  no network request recorded.
- Traces: AC-1.

**TC-AND-049-02 — TOTP happy path: verify → finalize → navigate**
- Type: Compose-UI + contract/MockWebServer.
- Target: JVM/Robolectric (mirror on emulator `test35`).
- Preconditions: enqueue `mfa_totp_verify_ok.json` (`MfaVerifyResp` with
  `remaining_factors:[]`), then `finalize_ok.json` (`SessionFinalizeResp status:"ok"`), then
  `me_min.json`; fake `onAuthenticated` sink.
- Steps: type a valid 6-digit code into `mfa_totp_code`; tap `mfa_submit`;
  `waitUntil` the nav sink fires.
- Expected: request 1 = `POST /ui/mfa/totp/verify` with body
  `{challenge_id:"chg_abc123", totp_code:"<typed>"}`; request 2 = `POST /ui/session/finalize`
  with body containing `challenge_id:"chg_abc123"`; order verify-before-finalize; the
  `onAuthenticated` callback fires exactly once.
- Traces: AC-2.

**TC-AND-049-03 — TOTP wrong code: inline error, stays, no finalize, submit re-enables**
- Type: Compose-UI + contract/MockWebServer.
- Target: JVM/Robolectric.
- Preconditions: enqueue `mfa_verify_invalid.json` (string `detail:"Invalid verification
  code"`, non-200).
- Steps: type a code; tap submit; `waitUntil` `mfa_error` exists.
- Expected: `mfa_error` shows a non-empty message; still on MFA screen
  (`mfa_totp_code` exists); `mfa_submit` re-enabled; white-box: `challengeId` unchanged,
  `navEvent==null`; MockWebServer received NO `/ui/session/finalize` (queue drained, path
  mismatch / `takeRequest` timeout). Do not assert a specific HTTP status (see §16 #17).
- Traces: AC-3.

**TC-AND-049-04 — TOTP error `detail` variants all map to a non-empty message**
- Type: Compose-UI (parameterized) + contract/MockWebServer.
- Target: JVM/Robolectric.
- Preconditions: three runs enqueuing `mfa_verify_invalid.json` (string),
  `mfa_verify_invalid_array.json` (`[{msg,loc}]`, the 422/`HTTPValidationError` shape), and
  `mfa_verify_invalid_object.json` (`{code, message}`).
- Steps: per variant, submit a code; `waitUntil` `mfa_error`.
- Expected: each variant renders a single non-empty human-readable string in `mfa_error`
  (string as-is; array → joined `.msg`; object → mapped message); no `finalize` call.
- Traces: AC-3.

**TC-AND-049-05 — TOTP validation gating: under-length code issues no request**
- Type: Compose-UI.
- Target: JVM/Robolectric.
- Preconditions: ViewModel seeded TOTP; MockWebServer with no responses enqueued.
- Steps: type a 5-digit code; inspect `mfa_submit`; attempt tap.
- Expected: `mfa_submit` is disabled (or tapping is a no-op); MockWebServer records ZERO
  requests; no `mfa_error`.
- Traces: AC-7.

**TC-AND-049-06 — Verify request carries `X-CSRF-Token` from `ui_csrf` cookie**
- Type: contract/MockWebServer.
- Target: JVM/Robolectric.
- Preconditions: a preceding fixture seeds `Set-Cookie: ui_csrf=<placeholder>`; then enqueue
  `mfa_totp_verify_ok.json`.
- Steps: drive a successful TOTP verify; capture the recorded verify request.
- Expected: the `/ui/mfa/totp/verify` request header `X-CSRF-Token` is present and equals the
  seeded `ui_csrf` value; the `Cookie` header carries `ui_csrf`. Guards the OkHttp
  interceptor/cookie-jar chain.
- Traces: AC-6.

**TC-AND-049-07 — TOTP recover after error: second attempt succeeds**
- Type: Compose-UI + contract/MockWebServer.
- Target: JVM/Robolectric.
- Preconditions: enqueue rejection, then `mfa_totp_verify_ok.json`, `finalize_ok.json`,
  `me_min.json`.
- Steps: submit a wrong code → see `mfa_error`; correct the code; submit again;
  `waitUntil` nav sink fires.
- Expected: first request rejected with error shown; after correction, a second
  `/ui/mfa/totp/verify` then `/ui/session/finalize` are sent and `onAuthenticated` fires;
  error cleared.
- Traces: AC-2, AC-3.

**TC-AND-049-08 — SMS begin enables code field (carries `challenge_id`)**
- Type: Compose-UI + contract/MockWebServer.
- Target: JVM/Robolectric.
- Preconditions: ViewModel seeded `requiredFactors=[Sms]`; enqueue `mfa_sms_begin_ok.json`
  (`ChallengeResp {challenge_id, sent_to}`).
- Steps: tap `mfa_sms_send`; `waitUntil` `mfa_sms_code` becomes enabled.
- Expected: a single `POST /ui/mfa/sms/begin` with body `{challenge_id:"chg_abc123"}`;
  `mfa_sms_code` enabled afterward.
- Traces: AC-4.

**TC-AND-049-09 — SMS happy path: begin → verify → finalize → navigate**
- Type: Compose-UI + contract/MockWebServer.
- Target: JVM/Robolectric (mirror on emulator `test35`).
- Preconditions: enqueue `mfa_sms_begin_ok.json`, `mfa_sms_verify_ok.json`
  (`MfaVerifyResp remaining_factors:[]`), `finalize_ok.json`, `me_min.json`.
- Steps: tap `mfa_sms_send`; type delivered code into `mfa_sms_code`; tap `mfa_submit`;
  `waitUntil` nav sink.
- Expected: requests in order `sms/begin` → `sms/verify` (body
  `{challenge_id:"chg_abc123", code:"<typed>"}`) → `session/finalize` (body with
  `challenge_id`); `onAuthenticated` fires once.
- Traces: AC-4.

**TC-AND-049-10 — SMS wrong code: error, no finalize, no implicit begin resend**
- Type: Compose-UI + contract/MockWebServer.
- Target: JVM/Robolectric.
- Preconditions: enqueue `mfa_sms_begin_ok.json`, then `mfa_verify_invalid.json`.
- Steps: tap send; type a wrong code; submit; `waitUntil` `mfa_error`.
- Expected: `mfa_error` non-empty; no `/ui/session/finalize`; exactly ONE `/ui/mfa/sms/begin`
  was sent (verify retry does not re-issue begin); `challengeId` intact; submit re-enabled.
- Traces: AC-5.

**TC-AND-049-11 — SMS explicit resend issues a second begin**
- Type: Compose-UI + contract/MockWebServer.
- Target: JVM/Robolectric.
- Preconditions: enqueue two `mfa_sms_begin_ok.json` responses.
- Steps: tap `mfa_sms_send`; after enable, tap resend (`mfa_sms_send` again).
- Expected: exactly TWO `POST /ui/mfa/sms/begin` requests recorded; no `verify`/`finalize`.
- Traces: AC-5.

**TC-AND-049-12 — Accessibility: code field semantics, error live-region, submit semantics**
- Type: Compose-UI (Robolectric) for static semantics; manual TalkBack verification on
  physical device for the announcement.
- Target: JVM/Robolectric for the semantics assertions; **physical device (SM-A156U)** for
  the manual TalkBack pass (real screen-reader announcement of a code rejection cannot be
  faithfully verified on Robolectric/emulator).
- Preconditions: TOTP rendered; for the manual part, TalkBack enabled on the device.
- Steps: assert `mfa_totp_code` exposes non-empty content description/text; `mfa_submit`
  `assertHasClickAction()` and correct enabled state; trigger a wrong-code error and assert
  the `mfa_error` node carries `liveRegion = Polite`. Manual: with TalkBack on, submit a
  wrong code and confirm the rejection is spoken.
- Expected: semantics assertions pass; TalkBack speaks the error. If production lacks
  `liveRegion`, the automated part is `@Ignore("AND-040")` and the gap is filed, not weakened.
- Traces: AC-3 (a11y facet).

**TC-AND-049-13 — ABI/API parity smoke on physical device**
- Type: instrumented/e2e.
- Target: **physical device (SM-A156U, API 34, arm64-v8a)** — required to catch
  arm64-vs-x86 / API-34-vs-35 differences vs the x86_64/API-35 emulator gate.
- Preconditions: app + MFA suite installable; MockWebServer reachable on loopback.
- Steps: run the canonical four cases (TOTP-OK, TOTP-wrong, SMS-OK, SMS-wrong) on the device.
- Expected: all four green on arm64-v8a / API 34, matching Robolectric/emulator results; no
  ABI- or API-level-specific failures.
- Traces: AC-1, AC-2, AC-3, AC-4, AC-5.

**TC-AND-049-14 — Determinism / no-network / flake gate**
- Type: integration (CI harness).
- Target: JVM/Robolectric.
- Preconditions: network access disabled in the test environment; suite uses MockWebServer
  loopback only.
- Steps: run `:feature-auth:testDebugUnitTest` 20× (`--rerun-tasks`); scan for `Thread.sleep`.
- Expected: 20/20 green; zero `Thread.sleep` in the suite; no external host (incl. the dev
  host `18.222.237.167:8000`) contacted.
- Traces: AC-1, AC-8.

### Coverage matrix

| Acceptance criterion | Covered by |
|---|---|
| AC-1 (headless render + suite passes) | TC-01, TC-13, TC-14 |
| AC-2 (TOTP verify→finalize + nav) | TC-02, TC-07, TC-13 |
| AC-3 (TOTP wrong code: error, no finalize, re-enable, detail variants) | TC-03, TC-04, TC-07, TC-12, TC-13 |
| AC-4 (SMS begin enables field, verify→finalize→nav) | TC-08, TC-09, TC-13 |
| AC-5 (SMS wrong code: error, no finalize, no implicit resend; explicit resend) | TC-10, TC-11, TC-13 |
| AC-6 (verify carries `X-CSRF-Token` = `ui_csrf`) | TC-06 |
| AC-7 (validation gating: no request on under-length code) | TC-05 |
| AC-8 (deterministic 20/20, no `Thread.sleep`) | TC-14 |
