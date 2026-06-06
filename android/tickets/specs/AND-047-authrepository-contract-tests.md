---
id: AND-047
title: AuthRepository contract tests
milestone: M1
epic: E07
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-028, AND-038, AND-046]
blocks: []
---

# AND-047 — AuthRepository contract tests

## 1. Overview & Goal

This ticket delivers the full contract-test suite for `AuthRepository`, the
`core-data` component that orchestrates the cookie-based authentication flow
against the FastAPI backend (`POST /ui/session/start` → MFA `begin`/`verify` →
`POST /ui/session/finalize` → `GET /ui/me`, plus `refresh` and `logout`). The
goal is to pin every code path of the repository to the **real wire shapes** of
the backend so that regressions in branching logic, factor sequencing, CSRF/
cookie handling, the 401-refresh-once retry, and FastAPI `detail` error mapping
are caught at the JVM unit-test layer before they reach the UI.

These are **contract tests**, not pure unit tests: they exercise the production
`AuthRepository` + production Retrofit/OkHttp/Moshi stack against a
`MockWebServer` (from AND-046) serving fixtures captured from the live dev
backend. They assert the typed `ApiResult<T>` / sealed `LoginResult` outputs as
well as the exact bytes the repository puts on the wire (request paths, bodies,
`X-CSRF-Token` header, cookie echo). No backend, emulator, or network is
required; the suite is hermetic and deterministic.

Out of scope: the repository implementation itself (AND-028/AND-038), the
MockWebServer harness and fixture capture (AND-046), and any ViewModel/Compose
tests (owned by the feature-auth tickets). This ticket only adds test sources
under `core-data/src/test/`.

## 2. Context & References

- **Repo / module:** `spannella/testlogon`, branch `android-port`, monorepo
  subfolder `android/`. Tests live in module `core-data`
  (`android/core-data/src/test/java/com/testlogon/android/core/data/auth/`).
- **System under test:** `com.testlogon.android.core.data.auth.AuthRepository`
  and its `Impl`, built across AND-028 (session start + branching) and
  AND-038 (finalize + multi-factor sequencing).
- **Test infrastructure:** `core-testing` `MockWebServer` harness and JSON
  fixtures from **AND-046** (`com.testlogon.android.core.testing.*`).
- **Backend reference:** FastAPI dev host `http://18.222.237.167:8000`
  (PLAINTEXT, unreliable — used only for fixture capture, never in CI).
  `OpenAPI` at `/openapi.json`. Web reference flow in
  `frontend/src/api/endpoints/*.ts` and `frontend/src/api/types.ts`.
- **Auth model:** cookie-based session + `ui_csrf` cookie echoed as the
  `X-CSRF-Token` header; on `401` the client performs `POST /ui/session/refresh`
  once, then retries the original request. Persistent cookie jar required.
- **Stack:** Kotlin 2.0.21, Retrofit 2.11, OkHttp 4.12 (+ `mockwebserver`),
  Moshi 1.15, Coroutines/Flow, JUnit4, kotlinx-coroutines-test, Truth/AssertJ,
  JDK 17. Pure JVM (`src/test/`) — Robolectric not required.

## 3. Functional Requirements

The suite MUST provide deterministic coverage of every `AuthRepository` path:

- **FR-1 Login, no MFA.** `login()` against a `session/start` response with
  `auth_required=false` (or empty `required_factors`) returns
  `LoginResult.Authenticated`, and the repository proceeds to / exposes the
  finalized session per AND-028.
- **FR-2 Login, MFA required.** `session/start` with `auth_required=true` and a
  non-empty `required_factors` returns `LoginResult.MfaRequired(challengeId,
  factors)` with the challenge id and factor list parsed exactly.
- **FR-3 Each factor begin/verify.** `sms` and `email` factors each have a
  `begin` (`POST /ui/mfa/{sms,email}/begin`, body `{challenge_id}`) and a
  `verify` test; **`totp` has no login-flow `begin` endpoint** — it goes straight
  to `verify` (`POST /ui/mfa/totp/verify`). [CORRECTED: the prior draft claimed a
  `begin` for all three factors; the OpenAPI index has no `/ui/mfa/totp/begin`
  and `Login.tsx` calls `verifyTotp` directly. The only `totp/.../begin` route is
  `/ui/mfa/totp/devices/begin`, which is device enrollment, not login.] `verify`
  returning empty `remaining_factors` advances to finalize; non-empty
  `remaining_factors` advances to the next factor (covers FR-5).
- **FR-4 Finalize.** After factors pass, `POST /ui/session/finalize` (body
  `{challenge_id (required), remember_device}` with `remember_device` true and
  false) yields a finalize response `{status, session_id?, required_factors,
  passed}`; `GET /ui/me` is parsed into the user model. [CORRECTED: finalize body
  must include the required `challenge_id` — the prior draft sent only
  `{remember_device}`; see `UiSessionFinalizeReq` and `Login.tsx` line 224.]
- **FR-5 Multi-factor sequencing.** A challenge requiring two factors in
  sequence (e.g. `["totp","sms"]`) reaches an authenticated session, asserting
  ordering and that finalize is called exactly once at the end.
- **FR-6 Refresh.** A `401` on a session-scoped call triggers exactly one `POST
  /ui/session/refresh` followed by a retry of the original request; success
  after refresh returns the original typed result.
- **FR-7 Logout.** `logout()` calls the logout endpoint and clears the cookie
  jar; subsequent calls send no stale session cookie.
- **FR-8 Error mapping.** FastAPI `detail` in all three shapes — `string`,
  `[{msg,...}]`, `{code,...}` — maps to the typed `ApiResult.Error` /
  `LoginResult.Error` model; HTTP 5xx, malformed JSON, and timeout map to the
  expected error categories.
- **FR-9 CSRF / cookies.** Every state-changing request carries the
  `X-CSRF-Token` header equal to the current `ui_csrf` cookie value; the
  persistent cookie jar replays `Set-Cookie` values on subsequent requests.
- **FR-10 Determinism.** All tests use a virtual-time test dispatcher and a
  fixed clock; no `Thread.sleep`, no real wall-clock backoff, no network. The
  suite passes repeatably under `--rerun-tasks` and parallel execution.

## 4. Technical Design

Tests are JUnit4 classes under
`core-data/src/test/java/com/testlogon/android/core/data/auth/`. Each class
builds a real `AuthRepositoryImpl` wired to a real Retrofit/OkHttp client whose
`baseUrl` is the `MockWebServer` URL, so the production serialization and
interceptor code is exercised end to end.

A shared base centralizes setup via the AND-046 harness:

```kotlin
abstract class AuthRepositoryTest {
    @get:Rule val mainDispatcherRule = MainDispatcherRule() // core-testing

    protected lateinit var server: MockWebServer
    protected lateinit var harness: AuthTestHarness     // from AND-046
    protected lateinit var repository: AuthRepository

    @Before fun setUp() {
        harness = AuthTestHarness()                     // starts MockWebServer
        server = harness.server
        repository = harness.buildAuthRepository(
            scheduler = TestCoroutineScheduler(),       // virtual time
        )
    }

    @After fun tearDown() = harness.shutdown()

    protected fun enqueue(fixture: String, code: Int = 200) =
        server.enqueue(harness.jsonResponse(fixture, code))
}
```

`AuthTestHarness.buildAuthRepository(...)` constructs the production object graph
(the same bindings Hilt provides in app code): an `OkHttpClient` with the real
`CsrfInterceptor`, the `PersistentCookieJar`, and the `SessionAuthenticator`
that performs the refresh-once retry, plus the Moshi converter and the
`ApiResult` adapter. Coroutine entry points are driven with `runTest { ... }`
from `kotlinx-coroutines-test` so virtual time advances backoff/timeout logic
without real delay.

Request assertions read `server.takeRequest()` to verify method, path, decoded
body JSON (via Moshi or a structural JSON matcher), and headers. Response
fixtures are loaded by name from `core-testing` resources captured against the
live backend (AND-046), guaranteeing the shapes match production.

Representative test classes:

- `LoginContractTest` — FR-1, FR-2 (branching).
- `FactorContractTest` — FR-3 (`totp`/`sms`/`email` begin+verify, parameterized).
- `FinalizeSequencingContractTest` — FR-4, FR-5, `remember_device`.
- `SessionRefreshContractTest` — FR-6 (401 → refresh → retry).
- `LogoutContractTest` — FR-7.
- `ErrorMappingContractTest` — FR-8 (`detail` string/array/object, 5xx, malformed).
- `CsrfCookieContractTest` — FR-9.

Example sequencing test:

```kotlin
@Test fun multiFactor_totp_then_sms_reaches_authenticated_session() = runTest {
    enqueue("session_start_mfa_totp_sms.json")        // auth_required, 2 factors
    enqueue("mfa_totp_verify_remaining_sms.json")     // TOTP: no begin
    enqueue("mfa_sms_begin.json");  enqueue("mfa_sms_verify_complete.json")
    enqueue("session_finalize_ok.json"); enqueue("me_ok.json")

    val start = repository.login("alice", "pw") as LoginResult.MfaRequired
    // TOTP has no begin; SMS does. verify bodies differ: totp_code vs code.
    repository.verifyFactor(start.challengeId, Factor.TOTP, "123456")
    repository.beginFactor(start.challengeId, Factor.SMS)
    repository.verifyFactor(start.challengeId, Factor.SMS, "654321")
    val result = repository.finalize(start.challengeId, rememberDevice = true)

    assertThat(result).isInstanceOf(ApiResult.Success::class.java)
    assertThat(server.takeRequest().path).isEqualTo("/ui/session/start")
    // ...assert ordering of subsequent paths (/ui/mfa/totp/verify,
    // /ui/mfa/sms/begin, /ui/mfa/sms/verify, /ui/session/finalize);
    // assert the totp verify body uses "totp_code"; finalize requested once.
}
```

## 5. API Contract

This ticket asserts (does not define) the contract. The endpoints and shapes
the tests pin, matching the live backend captured by AND-046:

- `POST /ui/session/start` — body `{"challenge_context":{"username","password"}}`
  (backend schema `UiSessionStartReq.challenge_context` is an open object,
  `additionalProperties:true`; the web client puts `username`/`password` inside)
  → `UiSessionStartResp` `{"auth_required":bool,"challenge_id":string|null,
  "required_factors":[string],"session_id":string|null}`. Only `auth_required`
  is required. [CORRECTED: added `session_id` — the no-MFA branch in `Login.tsx`
  keys off `!auth_required && session_id`.]
- `POST /ui/mfa/sms/begin` and `POST /ui/mfa/email/begin` — body
  `{"challenge_id":string}` (`SmsBeginReq`/`EmailBeginReq`) → `ChallengeResp`
  `{"challenge_id":string,"sent_to":[string]?}`. **There is no
  `/ui/mfa/totp/begin`** (TOTP login has verify only). [CORRECTED.]
- `POST /ui/mfa/totp/verify` — body `{"challenge_id":string,"totp_code":string}`
  (`TotpVerifyReq`; the TOTP field is **`totp_code`, not `code`**).
- `POST /ui/mfa/sms/verify` / `POST /ui/mfa/email/verify` — body
  `{"challenge_id":string,"code":string}` (`SmsVerifyReq`/`EmailVerifyReq`).
- All three verifies → `MfaVerifyResp` `{"status":string,"session_id":string?,
  "required_factors":[string],"passed":{string:bool},"remaining_factors":
  [string]}` (empty `remaining_factors` ⇒ ready to finalize). [CORRECTED: the
  prior draft modelled verify as only `{remaining_factors}`.]
- `POST /ui/session/finalize` — body `{"challenge_id":string (required),
  "remember_device":bool (default false)}` (`UiSessionFinalizeReq`) →
  `SessionFinalizeResp` `{"status":"ok"|"pending","session_id":string?,
  "required_factors":[string],"passed":{string:bool}}` plus `Set-Cookie` session
  + `ui_csrf`. [CORRECTED: `challenge_id` is required in the body.]
- `GET /ui/me` → `MeResp` `{"user_sub":string,"session_id":string,"ip":string}`.
  [CORRECTED: the prior draft claimed `{id, username, …}`; the real shape has no
  `username`/`id` — it is `user_sub`/`session_id`/`ip`.]
- `POST /ui/session/refresh` → `200` with refreshed cookies (no request body).
  The web client's `StatusResp` shape `{status}` is the documented body; the
  Android refresh-once path treats it as success/failure by status only.
- `POST /ui/session/logout` → `200` (`StatusResp` `{status}`); session cookies
  cleared. [CORRECTED: the OpenAPI index documents `200`, not `204`; logout is
  POST with no request body.]

Error responses tested for `detail`:
`{"detail":"Invalid credentials"}` (string),
`{"detail":[{"loc":[...],"msg":"...","type":"..."}]}` (422 array, the FastAPI
`HTTPValidationError`/`ValidationError` shape — verified),
`{"detail":{"code":"role_required_scope","required_scope":"...","message":"..."}}`
(object). [CORRECTED: the prior draft used a placeholder `{"code":"MFA_REQUIRED"}`;
the real object-detail codes the web client maps (`client.ts`
`mapAuthorizationError`) are `role_required`, `role_required_scope`,
`role_required_admin_profile_type`, `helpdesk_*`, and the `geo_blocked` 403 form
`{"code":"geo_blocked","message":...}`. The exact set of object-`detail` codes
returned by the *auth* endpoints is an unverified assumption — see §16.] Each
fixture is a byte-for-byte capture; tests assert both the parsed typed error and
that the repository never throws.

## 6. Data & State Management

The repository owns auth/session state; these tests assert that state is
correctly mutated and surfaced, but persist nothing of their own:

- **Cookie jar:** a real `PersistentCookieJar` backed by an in-memory store
  injected by the harness (no DataStore/Room I/O in `src/test/`). Tests assert
  the jar holds the session + `ui_csrf` cookies after finalize and is empty
  after logout.
- **Typed results:** `LoginResult` (`Authenticated` | `MfaRequired(challengeId,
  factors)` | `Error`) and `ApiResult<T>` (`Success` | `Error`) are asserted
  structurally via Truth/AssertJ — no string matching on `toString()`.
- **Challenge state:** the in-flight `challenge_id` and `remaining_factors`
  threading between begin/verify/finalize is verified through the sequence of
  request bodies, confirming the repository carries the id forward.
- **No global state leakage:** each test gets a fresh harness, fresh cookie jar,
  and fresh repository in `@Before`; `@After` shuts down `MockWebServer`. Room
  and DataStore are out of scope here and owned by their feature tickets.

## 7. Error Handling & Resilience

- **Refresh-once invariant (FR-6):** enqueue `401`, then a `refresh` `200`, then
  the retried call `200`. Assert exactly three `takeRequest()` entries in order
  (original → refresh → retry) and that a *second* consecutive `401` does **not**
  loop — it surfaces `ApiResult.Error` after a single refresh attempt.
- **Unauthenticated-401 guard:** the web client (`client.ts`) only attempts a
  refresh when the user is already authenticated; a `401` from `session/start`
  (e.g. wrong password on the login screen) propagates directly with **no**
  refresh attempt. Tests assert that a `401` on `login()`/`session/start` yields
  a typed credential error and issues **no** `POST /ui/session/refresh`. [Confirm
  the Android `SessionAuthenticator` mirrors this guard — see §16 open
  assumption; if it refreshes unconditionally this assertion must change.]
- **Timeouts:** simulate via `MockResponse().setSocketPolicy(NO_RESPONSE)` (or
  `setBodyDelay`) and advance virtual time past the ~20s read timeout; assert a
  `timeout`-category error. No real waiting occurs.
- **Bounded retry / GET idempotency:** for idempotent GETs (e.g. `/ui/me`)
  assert bounded backoff retry happens; for non-idempotent POSTs assert **no**
  automatic retry beyond the single refresh.
- **Malformed / empty body:** enqueue invalid JSON and empty `200` bodies;
  assert a parse/`unexpected`-category error, never an uncaught exception.
- **5xx:** assert mapping to a server-error category distinct from the
  client-error `detail` mapping.
- **Determinism guard:** a test asserts the suite uses the virtual scheduler
  (no real elapsed time) so resilience paths run in milliseconds.

## 8. Security & Privacy

- **CSRF (FR-9):** assert every state-changing request includes
  `X-CSRF-Token` equal to the current `ui_csrf` cookie; assert it is **absent/
  not stale** before any session is established and updated when the backend
  rotates `ui_csrf`.
- **Cookie scope:** assert session cookies are sent only to the `MockWebServer`
  origin and are cleared on logout; a regression that leaks cookies after logout
  fails FR-7.
- **No secrets in fixtures:** fixtures captured in AND-046 must use synthetic
  users/codes; this ticket adds an assertion-free convention check that
  passwords/codes used in tests are obvious dummies (`"pw"`, `"123456"`).
- **Plaintext dev host:** never contacted by the suite. CI runs fully offline;
  any accidental real-network call (non-MockWebServer host) is a test failure.

## 9. Accessibility & i18n

Not applicable — this ticket adds JVM unit/contract tests with no UI surface.
Accessibility and string localization are owned by the feature-auth Compose
tickets (login/MFA screens). The one i18n-adjacent concern these tests pin is
that error **mapping** produces stable typed `code`/category values (not
hard-coded user-facing English), so downstream UI can localize; user-facing
copy itself is asserted in the feature-layer tests, not here.

## 10. Telemetry & Logging

No production telemetry is added by this ticket. Tests assert two
logging-adjacent invariants relevant to privacy and debuggability:

- The repository/interceptors do **not** log credentials, MFA codes, cookie
  values, or the `X-CSRF-Token` at any level — verified by capturing the test
  OkHttp logger output and asserting these substrings are absent.
- Failures emit a stable, machine-readable error category usable by upstream
  analytics; tests assert the category/`code` rather than free-text messages.
  CI surfaces results via the standard Gradle/JUnit XML reports.

## 11. Testing Strategy

- **Framework:** JUnit4 + `kotlinx-coroutines-test` (`runTest`,
  `TestCoroutineScheduler`, `MainDispatcherRule`), Truth or AssertJ, OkHttp
  `MockWebServer`. Run via `./gradlew :core-data:testDebugUnitTest`.
- **Style:** contract tests through the production Retrofit/Moshi/OkHttp stack;
  no mocking of the HTTP client or serializer. Mock only at the socket
  (`MockWebServer`) and clock/dispatcher boundaries.
- **Fixtures:** loaded by name from AND-046 `core-testing` resources; one
  fixture per backend response shape (no inline JSON literals for happy paths).
- **Coverage matrix (maps to FRs):** login no-MFA, login MFA, totp/sms/email
  begin+verify, single-factor finalize, multi-factor sequence, `remember_device`
  true/false, refresh-once retry, double-401 no-loop, logout + jar clear, CSRF
  header presence/rotation, `detail` string/array/object, 5xx, malformed, empty,
  timeout. Each row is an independent test method.
- **Request assertions:** every test that mutates state asserts method, path,
  body JSON, and `X-CSRF-Token`/`Cookie` headers via `takeRequest()`.
- **Determinism (FR-10):** no `Thread.sleep`; virtual time only; fixed clock;
  fresh server/jar per test. Suite must pass under `--rerun-tasks` and parallel
  workers. Coverage gate: all `AuthRepositoryImpl` public functions and every
  `LoginResult`/`ApiResult` branch hit at least once (verified via JaCoCo report
  on `auth` package, target ≥ 90% line / 100% of public functions).

## 12. Dependencies & Sequencing

- **Depends on AND-028** (session start + branching) and **AND-038** (finalize +
  multi-factor sequencing) — the `AuthRepository` surface under test; this
  ticket cannot complete until those public APIs are stable.
- **Depends on AND-046** (MockWebServer harness + fixtures) — supplies
  `AuthTestHarness`, the cookie-jar test wiring, and the captured JSON fixtures;
  contract tests are meaningless without live-matching fixtures.
- **Blocks:** nothing formally, but acts as the regression gate for any
  subsequent change to auth repository behavior and for the feature-auth
  ViewModel tickets that build on `AuthRepository`. Recommended sequencing:
  land AND-028 → AND-038 → AND-046 → AND-047, with AND-047 added to the required
  CI checks on `android-port`.

## 13. Risks & Open Questions

- **Fixture drift:** the dev backend is unreliable and may change shapes; if
  AND-046 fixtures lag the live API the contract tests pin stale shapes. Mitigate
  with a periodic (manual) fixture re-capture and a comment in each fixture
  recording capture date + endpoint.
- **Exact refresh semantics:** confirm with AND-028/AND-038 authors whether
  refresh is driven by an OkHttp `Authenticator` or an interceptor — assertion
  count for `takeRequest()` depends on this. Open question: does `refresh` itself
  carry/rotate `ui_csrf`?
- **Logout endpoint path/method:** `POST /ui/session/logout` vs another path —
  verify against `/openapi.json` / `frontend` before finalizing fixtures.
- **`remember_device` side effects:** does the backend set a long-lived device
  cookie that must persist across logout? Clarify so FR-7 assertions are correct.
- **Parallel test execution:** ensure each test owns its own `MockWebServer`
  instance (no shared port) to keep the suite safe under Gradle parallelism.

## 14. Acceptance Criteria

- **AC-1:** Tests exist and pass for login no-MFA (FR-1) and login MFA-required
  (FR-2), asserting the correct `LoginResult` branch.
- **AC-2:** `totp`, `sms`, and `email` each have begin+verify tests (FR-3),
  including a verify that returns non-empty `remaining_factors`.
- **AC-3:** Single-factor and multi-factor (≥2 factors) sequences each reach an
  authenticated session with finalize called exactly once (FR-4, FR-5), covering
  `remember_device` true and false.
- **AC-4:** Refresh path: a single `401` triggers exactly one `refresh` + retry;
  a second consecutive `401` does not loop and surfaces a typed error (FR-6).
- **AC-5:** Logout calls the logout endpoint and empties the cookie jar; no
  session cookie is sent afterward (FR-7).
- **AC-6:** Error mapping covers `detail` as string, `[{msg}]`, and `{code}`,
  plus 5xx, malformed, empty, and timeout — each mapping to the expected typed
  error category without throwing (FR-8).
- **AC-7:** Every state-changing request asserts `X-CSRF-Token` matches the
  current `ui_csrf` cookie and the cookie jar replays session cookies (FR-9).
- **AC-8:** All `AuthRepository` public paths are covered and the suite is
  deterministic — passes repeatably under `--rerun-tasks` and parallel
  execution with no real network or wall-clock delay (FR-10).

## 15. Definition of Done

- All test classes in §4 implemented under
  `core-data/src/test/java/com/testlogon/android/core/data/auth/`, consuming the
  AND-046 harness and fixtures, with all AC-1…AC-8 satisfied.
- `./gradlew :core-data:testDebugUnitTest` is green locally and in CI on
  `android-port`; the task is added to the required PR checks.
- JaCoCo report shows 100% of `AuthRepositoryImpl` public functions and ≥90% of
  the `auth` package lines covered; uncovered lines justified in the PR.
- No `Thread.sleep`, no real-network calls, no shared mutable state between
  tests; suite passes under `--rerun-tasks` and parallel workers.
- No credentials/codes/cookies/CSRF tokens appear in test logs (asserted).
- Code reviewed and merged; open questions in §13 either resolved or filed as
  follow-up tickets referenced from the PR.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the authoritative source pointer.
OpenAPI pointers are `METHOD /path` and/or `components.schemas.<Name>` in
`reference/openapi.pretty.json` / `reference/openapi.index.txt`. Frontend
pointers are paths under `reference/src/`.

1. **`POST /ui/session/start` exists; req `UiSessionStartReq`, resp
   `UiSessionStartResp`.** VERDICT: Verified. SOURCE: OpenAPI `POST
   /ui/session/start` (`op=ui_session_start_...`); `src/api/endpoints/auth.ts:
   sessionStart`.
2. **`session/start` request body is `{challenge_context:{username,password}}`.**
   VERDICT: Verified (with nuance). SOURCE: `schemas.UiSessionStartReq`
   (`challenge_context` is an open object, `additionalProperties:true` — backend
   does not type `username`/`password`); the web client places them inside per
   `src/pages/Login.tsx:138-143` and `src/api/types.ts: SessionStartReq`.
3. **`session/start` response fields:
   `auth_required`(req), `challenge_id`?, `required_factors`[], `session_id`?.**
   VERDICT: Corrected (added `session_id`; only `auth_required` required). SOURCE:
   `schemas.UiSessionStartResp`; `src/api/types.ts: SessionStartResp`; no-MFA
   branch uses `!auth_required && session_id` in `src/pages/Login.tsx:145`.
4. **TOTP login has a `begin` endpoint.** VERDICT: Corrected — FALSE. There is no
   `/ui/mfa/totp/begin`; TOTP login is verify-only. SOURCE: `openapi.index.txt`
   (only `POST /ui/mfa/totp/verify` and the unrelated `POST
   /ui/mfa/totp/devices/begin`); `src/pages/Login.tsx:201` calls `verifyTotp`
   directly with no begin.
5. **SMS/email login each have a `begin`, body `{challenge_id}`.** VERDICT:
   Verified. SOURCE: OpenAPI `POST /ui/mfa/sms/begin` (`req=SmsBeginReq`), `POST
   /ui/mfa/email/begin` (`req=EmailBeginReq`); `schemas.SmsBeginReq`,
   `schemas.EmailBeginReq`; `src/api/endpoints/auth.ts: beginSms/beginEmail`.
6. **TOTP verify body field is `totp_code` (not `code`).** VERDICT: Corrected.
   SOURCE: `schemas.TotpVerifyReq` (`{challenge_id, totp_code}`, both required);
   `src/api/types.ts: TotpVerifyReq`; `src/pages/Login.tsx:201`.
7. **SMS/email verify body field is `code`.** VERDICT: Verified. SOURCE:
   `schemas.SmsVerifyReq`, `schemas.EmailVerifyReq` (`{challenge_id, code}`);
   `src/api/types.ts: SmsVerifyReq/EmailVerifyReq`.
8. **Verify response shape.** VERDICT: Corrected — it is `MfaVerifyResp`
   `{status, session_id?, required_factors[], passed{}, remaining_factors[]}`, not
   just `{remaining_factors}`. Empty `remaining_factors` ⇒ finalize. SOURCE:
   `src/api/types.ts: MfaVerifyResp`; `src/pages/Login.tsx:222`. (Verify
   endpoints have an untyped `resp=200:` in the OpenAPI index, so the field
   contract is sourced from the frontend types — see open assumptions.)
9. **`POST /ui/session/finalize` body requires `challenge_id` plus optional
   `remember_device` (default false).** VERDICT: Corrected — prior draft sent
   only `{remember_device}`. SOURCE: `schemas.UiSessionFinalizeReq` (required:
   `challenge_id`); `src/api/types.ts: SessionFinalizeReq`;
   `src/pages/Login.tsx:224-226`.
10. **`finalize` response shape.** VERDICT: Corrected — `SessionFinalizeResp`
    `{status:"ok"|"pending", session_id?, required_factors[], passed{}}`. SOURCE:
    `src/api/types.ts: SessionFinalizeResp`. (OpenAPI `resp=200:` untyped — see
    open assumptions.)
11. **`GET /ui/me` returns a user object.** VERDICT: Corrected — shape is
    `MeResp` `{user_sub, session_id, ip}`, NOT `{id, username, …}`. SOURCE:
    OpenAPI `GET /ui/me`; `src/api/types.ts: MeResp`; `src/pages/Login.tsx:147-148`
    reads `me.user_sub`.
12. **`POST /ui/session/refresh` — no request body, 200 on success.** VERDICT:
    Verified. SOURCE: OpenAPI `POST /ui/session/refresh` (`req=` empty,
    `resp=200:` only, no 422); `src/api/client.ts:121-130` posts with no body;
    `src/api/endpoints/auth.ts: refreshSession`.
13. **`POST /ui/session/logout` — POST, no body, returns 200.** VERDICT:
    Corrected — prior draft said `204`/`200`; index documents `200`. SOURCE:
    OpenAPI `POST /ui/session/logout`; `src/api/endpoints/auth.ts: logout`
    (`StatusResp`, no body).
14. **CSRF: `X-CSRF-Token` header equals the `ui_csrf` cookie value on
    state-changing requests.** VERDICT: Verified. SOURCE: `src/api/client.ts:168-171`
    (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`), applied to all
    methods via the shared `api()` wrapper.
15. **401 → single refresh → retry once; second consecutive 401 does not loop.**
    VERDICT: Verified. SOURCE: `src/api/client.ts:194-237` (single
    `refreshPromise`, one retry; retry-401 calls `logout("session_expired")` and
    throws — no loop).
16. **Unauthenticated 401 (login) does NOT trigger refresh.** VERDICT: Verified
    (web behavior). SOURCE: `src/api/client.ts:196-203` (`if
    (!isAuthenticated) … throw` before any refresh). Whether the Android
    `SessionAuthenticator` replicates this guard is an open assumption.
17. **FastAPI `detail` shapes: string, array `[{loc,msg,type}]`, object.**
    VERDICT: Verified for string + array; object codes Unverified for auth
    endpoints. SOURCE: `schemas.HTTPValidationError` → `schemas.ValidationError`
    (array form); `src/api/client.ts:66-101` `normalizeErrorDetail` handles
    string, array (`item.msg`), and object (`item.msg` / `mapAuthorizationError`).
    Object-`detail` codes seen in code: `role_required*`, `helpdesk_*`,
    `geo_blocked` — none are auth-login-specific, hence the object-detail example
    is illustrative.
18. **Cookie-based session with persistent cookie jar; cookies replayed on
    subsequent requests; cleared on logout.** VERDICT: Verified for the web
    transport (`credentials:"include"` throughout `src/api/client.ts`); the
    Android `PersistentCookieJar`/clear-on-logout behavior is an
    implementation-side assumption owned by AND-028/AND-038 (see open
    assumptions).
19. **Stack/framework choices (Retrofit 2.11, OkHttp 4.12 + `mockwebserver`,
    Moshi, `kotlinx-coroutines-test` `runTest`/`TestCoroutineScheduler`, OkHttp
    `Authenticator` for refresh).** VERDICT: Unverified-assumption (framework
    ref). SOURCE (framework ref): OkHttp `mockwebserver`
    https://square.github.io/okhttp/4.x/mockwebserver/okhttp3.mockwebserver/-mock-web-server/
    ; OkHttp `Authenticator` https://square.github.io/okhttp/4.x/okhttp/okhttp3/-authenticator/
    ; coroutines test https://kotlinlang.org/api/kotlinx.coroutines/kotlinx-coroutines-test/
    . Not asserted against backend sources; depends on AND-028/038/046 choices.

### Corrections made

- **TOTP has no login `begin` endpoint** (FR-3, §5, example test, fixtures list):
  removed the claimed `POST /ui/mfa/totp/begin`; TOTP login is verify-only.
- **TOTP verify field name** `code` → `totp_code` (§5, example test).
- **Finalize body** `{remember_device}` → `{challenge_id (required),
  remember_device}` (FR-4, §5, example test signature).
- **`GET /ui/me` shape** `{id, username, …}` → `{user_sub, session_id, ip}`
  (FR-4, §5).
- **`session/start` response** gained `session_id` and the note that only
  `auth_required` is required (FR-1/§5).
- **Verify/finalize response shapes** expanded to the real `MfaVerifyResp` /
  `SessionFinalizeResp` (§5) rather than `{remaining_factors}` only.
- **Logout status** `204`/`200` → `200` (POST, no body) (§5).
- **Object-`detail` example** `{code:"MFA_REQUIRED"}` replaced with a real
  mapped code (`role_required_scope`), with a note that the auth-endpoint object
  codes are unverified (§5).
- **Added the unauthenticated-401 guard** behavior to §7 (no refresh on login
  401).

### Open assumptions

- **Verify/finalize/me JSON field contracts beyond what the frontend types
  declare.** The OpenAPI index lists `resp=200:` (untyped) for the verify,
  finalize, logout, and `/ui/me` operations, so the exact response fields are
  taken from `src/api/types.ts` rather than the schema registry. Fixtures from
  AND-046 (captured live) are the tie-breaker; if they diverge, the live capture
  wins and §5 must be re-amended.
- **Object-form `detail` codes returned by auth endpoints.** The web client maps
  several object codes, but none are demonstrably emitted by the login/MFA
  routes. The object-`detail` test must use a fixture captured from a real auth
  error (AND-046) or be marked illustrative.
- **Refresh mechanism on Android (OkHttp `Authenticator` vs interceptor) and the
  unauthenticated-401 guard.** Drives the exact `takeRequest()` count and whether
  a login 401 triggers refresh. Owned by AND-028/AND-038; confirm before pinning
  assertion counts (mirrors §13).
- **Whether `refresh` rotates `ui_csrf`/session cookies and whether
  `remember_device` sets a long-lived device cookie surviving logout.** Not
  derivable from the OpenAPI spec or frontend source (server-side `Set-Cookie`
  behavior); must be observed from captured fixtures (mirrors §13).
- **Read timeout value (~20s) and bounded-retry/backoff policy.** Implementation
  detail of the AND-028/046 OkHttp client; not in the sources reviewed here.
- **Stack/library versions** (Retrofit/OkHttp/Moshi/coroutines-test) — framework
  refs only; assumed from the spec, not verified against a build file in these
  sources.

## 17. Test Plan

Test-target legend (per the ticket's CI/dev inventory): **JVM** = JVM
unit/Robolectric, local no device; **emu35** = headless emulator AVD `test35`
(x86_64, API 35); **A15** = physical Samsung Galaxy A15 5G (SM-A156U, API 34,
arm64-v8a, serial R5CX821TA9R). This ticket is a JVM-only contract suite
(`core-data/src/test/`), so the substantive cases run on **JVM**; two optional
cases note where the same suite is sanity-run on a device/emulator for ABI/API
parity.

- **TC-AND-047-01** — Login, no MFA (happy path).
  Type: contract/MockWebServer. Target: JVM.
  Preconditions: harness up; fixtures `session_start_no_mfa.json`
  (`auth_required=false`, non-null `session_id`) and `me_ok.json` (`{user_sub,
  session_id, ip}`) enqueued.
  Steps: call `repository.login("alice","pw")`; capture `takeRequest()` for each
  call.
  Expected: returns `LoginResult.Authenticated`; request 1 = `POST
  /ui/session/start` with body `challenge_context.username/password`; request 2 =
  `GET /ui/me`; `MeResp` parsed (`user_sub` populated, no `username` field).
  Traces: AC-1.
- **TC-AND-047-02** — Login, MFA required (branching).
  Type: contract/MockWebServer. Target: JVM.
  Preconditions: `session_start_mfa.json` (`auth_required=true`, `challenge_id`
  set, `required_factors=["totp"]`).
  Steps: call `login(...)`.
  Expected: returns `LoginResult.MfaRequired(challengeId, ["totp"])` with the id
  and factor list parsed exactly; no finalize/me requested.
  Traces: AC-1.
- **TC-AND-047-03** — Per-factor begin+verify (parameterized totp/sms/email).
  Type: contract/MockWebServer. Target: JVM.
  Preconditions: a verified-fixture per factor; for sms/email a `begin` fixture
  (`ChallengeResp`) and a verify fixture (`MfaVerifyResp` with empty
  `remaining_factors`); for totp a verify fixture only (no begin).
  Steps: for sms/email call `beginFactor` then `verifyFactor`; for totp call
  `verifyFactor` directly.
  Expected: SMS/email issue `POST /ui/mfa/{sms,email}/begin` then
  `.../verify` with body `{challenge_id, code}`; TOTP issues **only** `POST
  /ui/mfa/totp/verify` with body `{challenge_id, totp_code}` (asserts the
  `totp_code` field name and that **no** `/ui/mfa/totp/begin` is sent); empty
  `remaining_factors` ⇒ advances to finalize.
  Traces: AC-2.
- **TC-AND-047-04** — Verify returns non-empty `remaining_factors` (advance to
  next factor).
  Type: contract/MockWebServer. Target: JVM.
  Preconditions: `mfa_totp_verify_remaining_sms.json`
  (`remaining_factors=["sms"]`).
  Steps: verify TOTP; inspect repository state / next required call.
  Expected: repository does **not** call finalize; surfaces the next factor
  (`sms`) carrying the same `challenge_id`.
  Traces: AC-2, AC-3.
- **TC-AND-047-05** — Single-factor finalize with `remember_device` true and
  false.
  Type: contract/MockWebServer. Target: JVM.
  Preconditions: start(MFA, `["totp"]`) → totp verify (empty remaining) →
  `session_finalize_ok.json` (`status:"ok"`) → `me_ok.json`. Run once per
  `remember_device` value.
  Steps: drive the flow; capture the finalize request body.
  Expected: `POST /ui/session/finalize` body = `{challenge_id:<from start>,
  remember_device:<true|false>}`; returns `ApiResult.Success`; finalize sent
  exactly once.
  Traces: AC-3.
- **TC-AND-047-06** — Multi-factor sequence (`["totp","sms"]`) reaches
  authenticated session.
  Type: contract/MockWebServer. Target: JVM.
  Preconditions: fixtures for start(2 factors) → totp verify
  (`remaining=["sms"]`) → sms begin → sms verify (empty) → finalize → me.
  Steps: run the full sequence.
  Expected: request order is `/ui/session/start`, `/ui/mfa/totp/verify`,
  `/ui/mfa/sms/begin`, `/ui/mfa/sms/verify`, `/ui/session/finalize`, `/ui/me`;
  finalize called exactly once; result `Authenticated`.
  Traces: AC-3.
- **TC-AND-047-07** — Refresh-once: single 401 → refresh → retry succeeds.
  Type: contract/MockWebServer. Target: JVM.
  Preconditions: a session-scoped call (e.g. `/ui/me`) enqueued as `401`, then
  `POST /ui/session/refresh` `200`, then the retried call `200`. Repository in
  authenticated state.
  Steps: invoke the session call.
  Expected: exactly three `takeRequest()` in order (original → `POST
  /ui/session/refresh` (no body) → retry); returns the original typed result.
  Traces: AC-4.
- **TC-AND-047-08** — Double-401 does not loop.
  Type: contract/MockWebServer. Target: JVM.
  Preconditions: `401`, refresh `200`, retry `401`.
  Steps: invoke the session call.
  Expected: exactly one refresh attempt; surfaces `ApiResult.Error`
  (auth-required category); no third request beyond the single retry; no infinite
  loop.
  Traces: AC-4.
- **TC-AND-047-09** — Unauthenticated 401 on login does not refresh.
  Type: contract/MockWebServer. Target: JVM.
  Preconditions: repository unauthenticated; `session/start` enqueued as `401`
  with `{"detail":"Invalid credentials"}`.
  Steps: call `login("alice","wrong")`.
  Expected: returns a typed credential `LoginResult.Error`; **no** `POST
  /ui/session/refresh` is issued (assert only the single `session/start` request).
  Traces: AC-4, AC-6.
- **TC-AND-047-10** — Logout clears the cookie jar.
  Type: contract/MockWebServer. Target: JVM.
  Preconditions: authenticated state with session + `ui_csrf` cookies in the jar;
  logout enqueued `200` (`StatusResp`).
  Steps: call `logout()`; then issue any follow-up request.
  Expected: `POST /ui/session/logout` (no body) sent; cookie jar empty
  afterward; the follow-up request carries **no** session/`ui_csrf` cookie.
  Traces: AC-5.
- **TC-AND-047-11** — Error mapping: `detail` string / array / object + 5xx /
  malformed / empty / timeout.
  Type: contract/MockWebServer. Target: JVM.
  Preconditions: fixtures — `{"detail":"Invalid credentials"}` (400/401);
  `{"detail":[{"loc":[...],"msg":"...","type":"..."}]}` (422); an object-`detail`
  fixture (captured/illustrative); `500`; invalid-JSON `200`; empty `200`;
  `MockResponse().setSocketPolicy(NO_RESPONSE)` for timeout (advance virtual
  time past the read timeout).
  Steps: drive a call per fixture.
  Expected: string→message error; array→joined `msg` error
  (matches `normalizeErrorDetail`); object→mapped/typed code; 5xx→server-error
  category distinct from 4xx; malformed/empty→parse/unexpected category;
  timeout→timeout category. Repository never throws; each yields `ApiResult.Error`
  / `LoginResult.Error`.
  Traces: AC-6.
- **TC-AND-047-12** — CSRF header equals current `ui_csrf`; cookie replay +
  rotation.
  Type: contract/MockWebServer. Target: JVM.
  Preconditions: finalize sets `Set-Cookie: ui_csrf=v1` and a session cookie; a
  later response rotates `Set-Cookie: ui_csrf=v2`.
  Steps: perform a state-changing request after finalize, then another after the
  rotation.
  Expected: the first state-changing request's `X-CSRF-Token` = `v1` and equals
  the jar's `ui_csrf`; before any session is established, no stale CSRF header is
  sent; after rotation the header = `v2`; the persistent jar replays the session
  cookie on subsequent requests.
  Traces: AC-7.
- **TC-AND-047-13** — Determinism / no-network / no-wall-clock.
  Type: unit + contract/MockWebServer. Target: JVM.
  Preconditions: full suite; virtual-time dispatcher and fixed clock wired via
  the harness.
  Steps: run the suite under `--rerun-tasks` and with Gradle parallel workers;
  assert each test owns its own `MockWebServer`; scan for `Thread.sleep` /
  real-network hosts.
  Expected: suite passes repeatably; no real elapsed time (resilience paths run
  in ms via virtual time); any non-MockWebServer host call fails the test.
  Traces: AC-8.
- **TC-AND-047-14** — No secrets in logs (security/privacy).
  Type: contract/MockWebServer. Target: JVM.
  Preconditions: OkHttp logging interceptor output captured to a buffer; run a
  login + verify + finalize flow with dummy creds (`"pw"`, `"123456"`).
  Steps: execute the flow; inspect captured log output.
  Expected: log output contains none of: the password, MFA codes, cookie values,
  or the `X-CSRF-Token` value. Convention check asserts test creds are obvious
  dummies.
  Traces: AC-7, AC-8.
- **TC-AND-047-15** — ABI/API parity sanity run (optional, CI gate hardening).
  Type: instrumented/e2e (suite re-run). Target: emu35 **and** A15.
  Preconditions: the `:core-data` unit suite is runnable as an
  instrumented/connected check; MockWebServer bound to localhost on-device.
  Steps: run the contract suite on emu35 (x86_64/API 35) and on the physical A15
  (arm64-v8a/API 34).
  Expected: identical pass results across ABIs/API levels — guards against
  Moshi/OkHttp/JSON behavior differing between x86_64 and arm64-v8a or API 34 vs
  35. MUST include the **physical A15** run because arm64-vs-x86 ABI parity
  cannot be exercised on the x86_64 emulator alone.
  Traces: AC-8.

### Coverage matrix (AC → TC)

| Acceptance criterion | Covered by |
| --- | --- |
| AC-1 (login no-MFA / MFA branch) | TC-01, TC-02 |
| AC-2 (totp/sms/email begin+verify; non-empty remaining) | TC-03, TC-04 |
| AC-3 (single + multi-factor finalize once; remember_device t/f) | TC-04, TC-05, TC-06 |
| AC-4 (single 401 refresh+retry; no loop; login-401 no refresh) | TC-07, TC-08, TC-09 |
| AC-5 (logout clears jar; no stale cookie) | TC-10 |
| AC-6 (detail string/array/object + 5xx/malformed/empty/timeout) | TC-09, TC-11 |
| AC-7 (CSRF matches ui_csrf; cookie replay/rotation) | TC-12, TC-14 |
| AC-8 (full coverage + determinism + no network/wall-clock) | TC-13, TC-14, TC-15 |
