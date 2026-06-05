---
id: AND-047
title: AuthRepository contract tests
milestone: M1
epic: E07
priority: P0
size: M
status: draft
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
- **FR-3 Each factor begin/verify.** `totp`, `sms`, and `email` factors each have
  a `begin` and `verify` test; `verify` returning empty `remaining_factors`
  advances to finalize; non-empty `remaining_factors` advances to the next
  factor (covers FR-5).
- **FR-4 Finalize.** After factors pass, `POST /ui/session/finalize` (with
  `remember_device` true and false) yields an authenticated session; `GET
  /ui/me` is parsed into the user model.
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
    enqueue("mfa_totp_begin.json"); enqueue("mfa_totp_verify_remaining_sms.json")
    enqueue("mfa_sms_begin.json");  enqueue("mfa_sms_verify_complete.json")
    enqueue("session_finalize_ok.json"); enqueue("me_ok.json")

    val start = repository.login("alice", "pw") as LoginResult.MfaRequired
    repository.verifyFactor(start.challengeId, Factor.TOTP, "123456")
    repository.verifyFactor(start.challengeId, Factor.SMS, "654321")
    val result = repository.finalize(rememberDevice = true)

    assertThat(result).isInstanceOf(ApiResult.Success::class.java)
    assertThat(server.takeRequest().path).isEqualTo("/ui/session/start")
    // ...assert ordering of subsequent paths; finalize requested exactly once
}
```

## 5. API Contract

This ticket asserts (does not define) the contract. The endpoints and shapes
the tests pin, matching the live backend captured by AND-046:

- `POST /ui/session/start` — body `{"challenge_context":{"username","password"}}`
  → `{"auth_required":bool,"challenge_id":string|null,"required_factors":[string]}`.
- `POST /ui/mfa/{totp|sms|email}/begin` — body `{"challenge_id":string}` →
  factor-specific begin payload (e.g. masked destination for sms/email).
- `POST /ui/mfa/{totp|sms|email}/verify` — body
  `{"challenge_id":string,"code":string}` →
  `{"remaining_factors":[string]}` (empty ⇒ ready to finalize).
- `POST /ui/session/finalize` — body `{"remember_device":bool}` → session
  established (`Set-Cookie` session + `ui_csrf`).
- `GET /ui/me` → user object (id, username, …) per `frontend` types.
- `POST /ui/session/refresh` → `200` with refreshed cookies (no body needed).
- `POST /ui/session/logout` (logout) → `204`/`200`; session cookies cleared.

Error responses tested for `detail`:
`{"detail":"Invalid credentials"}` (string),
`{"detail":[{"loc":[...],"msg":"...","type":"..."}]}` (422 array),
`{"detail":{"code":"MFA_REQUIRED","message":"..."}}` (object). Each fixture is a
byte-for-byte capture; tests assert both the parsed typed error and that the
repository never throws.

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
