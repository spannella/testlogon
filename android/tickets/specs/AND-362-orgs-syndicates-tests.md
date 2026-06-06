---
id: AND-362
title: Orgs/syndicates tests
milestone: M7
epic: E46
priority: P2
size: M
status: draft
depends_on: [AND-361, AND-353, AND-356, AND-354]
blocks: []
---

# AND-362 — Orgs/syndicates tests

## 1. Overview & Goal

This ticket delivers the **test suite** for the orgs/syndicates feature surface:
the repositories (`OrgRepository` from AND-353, `SyndicateRepository` from
AND-356), the presentation layer (the six ViewModels seeded by AND-361), and the
Compose screens (AND-354). The backlog scope is explicitly **"Repo + UI tests"**
and the acceptance is **"Pass"**.

AND-361 already shipped a complete *ViewModel* unit-test suite using repository
fakes. This ticket does **not** re-implement those; it **extends** the suite in
two directions the upstream ticket explicitly deferred:

1. **Repository (integration-style) tests** for `OrgRepository` and
   `SyndicateRepository`, driven by **MockWebServer** so the full
   Retrofit/OkHttp/Moshi stack — JSON (snake_case) deserialization, FastAPI
   `detail` error mapping to `AppError`, the `X-CSRF-Token` echo, the 401 →
   `POST /ui/session/refresh` → retry authenticator path, ~20s timeouts and
   bounded backoff for idempotent GETs — is exercised end to end below the
   ViewModel.
2. **UI (instrumentation/Robolectric Compose) tests** for the AND-354 org and
   syndicate screens, asserting that each `UiState` (`Loading`/`Empty`/`Error`/
   `Stale`/`Success`) renders correctly, that user gestures dispatch the right
   `*Action`, that one-shot `OrgEvent`s surface as snackbars, and that role
   gating hides/disables management controls.

Goal: a green, deterministic, CI-runnable test set that guards the entire
orgs/syndicates vertical against regression, with no real network access and no
flakiness from the unreliable dev backend.

## 2. Context & References

- **Modules under test**
  - `core-data` (repositories) — `com.testlogon.android.core.data.repository.OrgRepository`,
    `SyndicateRepository` (AND-353/AND-356).
  - `feature-orgs` (state + UI) — `com.testlogon.android.feature.orgs.*`
    (ViewModels from AND-361, Compose screens from AND-354).
- **Test infrastructure module:** `core-testing`
  (`com.testlogon.android.core.testing`) — provides `MainDispatcherRule`,
  `FakeOrgRepository`/`FakeSyndicateRepository`, JSON fixture loaders, and a
  `mockWebServer()` helper. This ticket may add shared helpers here.
- **Upstream specs:** AND-361 (ViewModels + their unit-test seed — Section 11
  there enumerates the existing cases this ticket builds on), AND-353
  (`OrgRepository`, `/ui/orgs/*`), AND-356 (`SyndicateRepository`,
  `/ui/syndicates/*`), AND-354 (Compose screens — the UI test target).
- **Web reference (fixture source of truth):** `frontend/src/api/endpoints/orgs.ts`,
  `frontend/src/api/endpoints/syndicates.ts`, `frontend/src/api/types.ts`.
  Recorded JSON fixtures must match these field names and the live
  `/openapi.json` schema.
- **Conventions:** ViewModels expose `StateFlow<UiState>`; repositories return
  `ApiResult<T>`; FastAPI `detail` is `string | [{msg}] | {code,...}`. The dev
  backend `http://18.222.237.167:8000` is PLAINTEXT and unreliable — **no test
  in this ticket touches it**; all HTTP is served by an in-process MockWebServer.

## 3. Functional Requirements

**Repository tests (FR-R\*)**

- FR-R1 **Happy-path deserialization.** For each GET (`/ui/orgs`,
  `/ui/orgs/{id}`, `/ui/orgs/{id}/members`, `/ui/orgs/{id}/invites`,
  `/ui/syndicates`, `/ui/syndicates/{id}`) a recorded 200 fixture deserializes
  into the correct `core-model` type with all fields (incl. snake_case →
  camelCase, enums, nested `treasury`/`revenue_split`) mapped.
- FR-R2 **Mutation requests.** `invite` (POST), `revokeInvite` (DELETE),
  `changeMemberRole` (PATCH), `removeMember` (DELETE) send the correct method,
  path, JSON body, and the `X-CSRF-Token` header, and map their responses to
  `ApiResult.Success`.
- FR-R3 **Error mapping.** 400/422 (`detail` array), 401, 403, 404, 409, 500,
  and malformed-JSON responses each map to the correct
  `ApiResult.Failure(AppError.*)` variant with a non-empty message.
- FR-R4 **CSRF.** Requests echo the `ui_csrf` cookie value as `X-CSRF-Token` on
  unsafe methods (POST/PATCH/DELETE).
- FR-R5 **401 refresh-retry.** A first request returning 401 triggers exactly
  one `POST /ui/session/refresh`; on refresh success the original request is
  retried once and succeeds; on refresh failure the call yields
  `AppError.Unauthorized` and the original request is **not** retried again.
- FR-R6 **Timeout + bounded retry.** An idempotent GET that times out / returns
  503 is retried per the configured bounded backoff and ultimately yields
  `AppError.Network`; a mutation (POST/PATCH/DELETE) is **not** retried.

**UI tests (FR-U\*)**

- FR-U1 Each screen renders its `Loading` (progress), `Empty` (empty-state
  copy), `Error` (message + Retry button), and `Success` states from a supplied
  `UiState`, asserted by test tag / semantics.
- FR-U2 **Stale** state renders cached content plus a dismissible error banner;
  the list is still present.
- FR-U3 Gestures dispatch actions: pull-to-refresh → `Refresh`; Retry tap →
  `Retry`; role dropdown selection → `ChangeRole`; remove tap (after confirm) →
  `RemoveMember`; invite submit → `SendInvite`.
- FR-U4 **Role gating UI:** when `callerRole` is `MEMBER`/`VIEWER`, management
  controls (change-role, remove, invite) are absent or disabled.
- FR-U5 **Events → UI:** `OrgEvent.ActionFailed`/`NotAuthorized`/`InviteSent`/
  `RoleChanged` surface as the expected snackbar text.
- FR-U6 **Inline validation:** an invalid email in the invite field shows the
  `emailError` string and disables submit.
- FR-U7 Syndicate detail renders overview + treasury (locale-formatted balance)
  + revenue-split rows; no mutation controls exist.

## 4. Technical Design

### 4.1 Source sets & toolchain

- **Repository tests:** `core-data/src/test` (local JVM, Robolectric not
  required) — JUnit4, `kotlinx-coroutines-test` (`runTest`,
  `StandardTestDispatcher`), `okhttp3.mockwebserver.MockWebServer`, real Moshi +
  Retrofit instances built by a test factory mirroring the production
  `core-network` config (timeouts shortened for tests).
- **UI tests:** `feature-orgs/src/test` using **Robolectric +
  `createComposeRule()`** so screen tests run on the JVM in CI without a device,
  driven by fake ViewModels (or directly by passing `UiState` to stateless
  composables). A small `feature-orgs/src/androidTest` smoke set covers the
  navigation/Hilt wiring on-device.
- ViewModel unit tests from AND-361 remain in `feature-orgs/src/test` and are
  run by the same Gradle task; this ticket only adds the repository and UI sets.

### 4.2 Repository test harness

```kotlin
package com.testlogon.android.core.data.repository

@RunWith(JUnit4::class)
class OrgRepositoryTest {

    @get:Rule val mainDispatcherRule = MainDispatcherRule()
    private lateinit var server: MockWebServer
    private lateinit var repository: OrgRepository

    @Before fun setUp() {
        server = MockWebServer().apply { start() }
        repository = TestNetwork.orgRepository(server.url("/"))   // real Moshi/Retrofit/OkHttp
    }

    @After fun tearDown() = server.shutdown()

    private fun enqueueJson(code: Int, fixture: String) =
        server.enqueue(MockResponse().setResponseCode(code).setBody(loadFixture(fixture)))

    @Test fun `listOrgs maps 200 body to Org list`() = runTest {
        enqueueJson(200, "orgs/list_200.json")
        val result = repository.listOrgs()
        assertThat(result).isInstanceOf(ApiResult.Success::class.java)
        val orgs = (result as ApiResult.Success).data
        assertThat(orgs).hasSize(2)
        assertThat(orgs[0].myRole).isEqualTo(OrgRole.ADMIN)
        assertThat(server.takeRequest().path).isEqualTo("/ui/orgs")
    }

    @Test fun `422 detail array maps to Validation error`() = runTest {
        enqueueJson(422, "errors/detail_array_422.json")
        val result = repository.invite("org_123", "bad", OrgRole.MEMBER)
        assertThat(result).isInstanceOf(ApiResult.Failure::class.java)
        assertThat((result as ApiResult.Failure).error).isInstanceOf(AppError.Validation::class.java)
    }

    @Test fun `changeMemberRole sends PATCH with CSRF header and body`() = runTest {
        server.enqueue(csrfSeededResponse())                     // sets ui_csrf cookie
        enqueueJson(200, "orgs/member_patched_200.json")
        repository.listOrgs()                                    // seed cookie jar
        repository.changeMemberRole("org_123", "mem_9", OrgRole.ADMIN)
        val patch = server.takeRequest()                        // skip the seed request in real test
        assertThat(patch.method).isEqualTo("PATCH")
        assertThat(patch.getHeader("X-CSRF-Token")).isNotEmpty()
        assertThat(patch.body.readUtf8()).contains("\"role\":\"admin\"")
    }
}
```

`TestNetwork` is a test factory in `core-testing` that builds the exact OkHttp
client used in production (cookie jar, CSRF interceptor, auth authenticator,
backoff interceptor) but with sub-second timeouts and the MockWebServer base URL,
so the repository code path is identical to production.

### 4.3 401 refresh-retry test

```kotlin
@Test fun `401 triggers single refresh then retry`() = runTest {
    server.enqueue(MockResponse().setResponseCode(401))                 // 1: original -> 401
    server.enqueue(MockResponse().setResponseCode(200).setBody("{}"))   // 2: /ui/session/refresh
    enqueueJson(200, "orgs/list_200.json")                              // 3: retried original
    val result = repository.listOrgs()
    assertThat(result).isInstanceOf(ApiResult.Success::class.java)
    assertThat(server.requestCount).isEqualTo(3)
    assertThat(server.takeRequest().path).isEqualTo("/ui/orgs")
    assertThat(server.takeRequest().path).isEqualTo("/ui/session/refresh")
    assertThat(server.takeRequest().path).isEqualTo("/ui/orgs")
}

@Test fun `repeated 401 after refresh yields Unauthorized without loop`() = runTest {
    server.enqueue(MockResponse().setResponseCode(401))
    server.enqueue(MockResponse().setResponseCode(200).setBody("{}")) // refresh ok
    server.enqueue(MockResponse().setResponseCode(401))              // retry still 401
    val result = repository.listOrgs()
    assertThat((result as ApiResult.Failure).error).isInstanceOf(AppError.Unauthorized::class.java)
    assertThat(server.requestCount).isEqualTo(3)                     // no infinite refresh
}
```

### 4.4 Compose UI test harness

Screens are tested as **stateless composables** that take `UiState` + lambdas, so
the test controls state deterministically without a real ViewModel:

```kotlin
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class OrgMembersScreenTest {

    @get:Rule val composeRule = createComposeRule()

    @Test fun error_state_shows_retry_and_dispatches_action() {
        var action: OrgMembersAction? = null
        composeRule.setContent {
            OrgMembersScreen(
                state = OrgMembersUiState(orgId = "org_123", error = "Network error"),
                onAction = { action = it },
            )
        }
        composeRule.onNodeWithText("Network error").assertIsDisplayed()
        composeRule.onNodeWithTag("retry_button").performClick()
        assertThat(action).isEqualTo(OrgMembersAction.Retry)
    }

    @Test fun viewer_role_hides_management_controls() {
        composeRule.setContent {
            OrgMembersScreen(
                state = OrgMembersUiState(
                    orgId = "org_123", callerRole = OrgRole.VIEWER,
                    members = persistentListOf(member("mem_9")),
                ),
                onAction = {},
            )
        }
        composeRule.onNodeWithTag("change_role_mem_9").assertDoesNotExist()
        composeRule.onNodeWithTag("remove_member_mem_9").assertDoesNotExist()
    }

    @Test fun stale_state_shows_banner_and_keeps_list() {
        composeRule.setContent {
            OrgMembersScreen(
                state = OrgMembersUiState(
                    orgId = "org_123", isStale = true, error = "Refresh failed",
                    members = persistentListOf(member("mem_9")),
                ),
                onAction = {},
            )
        }
        composeRule.onNodeWithTag("stale_banner").assertIsDisplayed()
        composeRule.onNodeWithText("Jo").assertIsDisplayed()
    }
}
```

Event-to-snackbar tests render the stateful `…Route` composable with a fake
ViewModel that emits a chosen `OrgEvent` and assert the snackbar text node.

### 4.5 Determinism

All coroutines run on the injected test dispatcher; MockWebServer responses are
enqueued up-front; no `Thread.sleep` or real delays. Backoff is driven through
`runTest`'s virtual time so retry tests complete instantly.

## 5. API Contract

This ticket defines **no new endpoints**. It pins the contract of the endpoints
owned by AND-353/AND-356 via recorded JSON fixtures (`core-testing` resources,
mirrored from `frontend/src/api/types.ts` and `/openapi.json`). Fixtures used:

```jsonc
// orgs/list_200.json  (GET /ui/orgs)
[ { "id": "org_123", "name": "Acme", "slug": "acme", "plan": "pro",
    "member_count": 12, "my_role": "admin" },
  { "id": "org_777", "name": "Empty Co", "slug": "empty", "plan": "free",
    "member_count": 1, "my_role": "owner" } ]

// orgs/members_200.json  (GET /ui/orgs/{id}/members)
[ { "id": "mem_9", "user_id": "u_42", "display_name": "Jo", "email": "jo@x.io",
    "role": "member", "joined_at": "2026-05-01T10:00:00Z" } ]

// orgs/invite_created_201.json  (POST /ui/orgs/{id}/invites)
{ "id": "inv_3", "email": "new@x.io", "role": "member", "status": "pending",
  "invited_at": "2026-06-01T09:00:00Z" }

// syndicates/detail_200.json  (GET /ui/syndicates/{id})
{ "id": "syn_7", "name": "North Split", "my_role": "member",
  "treasury": { "balance": 14250, "currency": "USD" },
  "revenue_split": [ { "user_id": "u_42", "display_name": "Jo", "share_bps": 4000 } ] }

// errors/detail_array_422.json  (FastAPI validation)
{ "detail": [ { "loc": ["body","email"], "msg": "value is not a valid email",
                "type": "value_error.email" } ] }

// errors/detail_string_403.json
{ "detail": "Not authorized" }

// errors/detail_code_409.json
{ "detail": { "code": "ALREADY_MEMBER", "message": "User already a member" } }
```

Request-side assertions verify method, path, JSON body keys (snake_case:
`{"email":"...","role":"member"}` for invite; `{"role":"admin"}` for role
change), and presence of `X-CSRF-Token` on unsafe methods. A **contract-drift
guard** test deserializes every fixture into its model and fails if an unknown
non-nullable field appears, prompting a fixture/schema refresh against
`/openapi.json`.

## 6. Data & State Management

This ticket holds no application state. Test-side data:

- **Fixtures:** JSON under `core-testing/src/main/resources/fixtures/...`, loaded
  via `loadFixture(name): String`.
- **Builders:** factory funcs (`org()`, `member()`, `invite()`,
  `syndicateDetail()`, `…UiState`) in `core-testing` so each test declares only
  the fields it cares about.
- **Fakes (reused from AND-361):** `FakeOrgRepository` /
  `FakeSyndicateRepository` with programmable `ApiResult` queues and call-count
  recording — used by the UI/event tests.
- UI tests assert against **stable test tags** (`Modifier.testTag(...)`) and
  semantics; tags are part of the AND-354 screen contract and are enumerated in
  a shared `OrgTestTags` object so screen and test stay in sync.

State assertions on ViewModels use **Turbine** (`viewModel.state.test { … }`)
exactly as in AND-361; this ticket adds coverage only where AND-361 left gaps
(e.g. interaction with the real error-mapping path is covered at the repo level
instead).

## 7. Error Handling & Resilience

The suite's purpose is largely to *prove* the production error handling, so the
tests themselves must be robust:

- **No real network / no dev host:** every HTTP test uses MockWebServer; a CI
  guard (lint rule / test that asserts no `OkHttpClient` points at
  `18.222.237.167`) prevents accidental live calls.
- **Virtual time for retries:** backoff/timeout tests use `runTest` advancing
  virtual time; real wall-clock delays are forbidden to keep tests <1s.
- **Negative-path coverage is mandatory**, not optional: every `AppError`
  variant (`Validation`, `Unauthorized`, `Forbidden`, `NotFound`, `Conflict`,
  `Server`, `Network`, `Unknown`/parse error) has at least one repository test.
- **Flake controls:** MockWebServer `enqueue` order is deterministic;
  `takeRequest(timeout)` uses a bounded timeout so a missing request fails fast
  rather than hanging CI.
- UI tests use `composeRule.waitForIdle()` / `waitUntil` for recomposition
  rather than fixed sleeps.

## 8. Security & Privacy

- Tests use **synthetic data only** (`jo@x.io`, `org_123`); no real user PII,
  credentials, or cookies are committed in fixtures.
- A dedicated test asserts the **CSRF echo** (`X-CSRF-Token` matches the
  `ui_csrf` cookie) and that the cookie jar persists across requests — locking in
  the security behaviour of `core-network`.
- A **PII-in-logs** test (extending AND-361 AC-8) asserts the fake `Logger`/
  `Analytics` never receives emails or user ids in payloads during repo+UI
  flows.
- No secrets, tokens, or real session cookies appear in fixtures or test config;
  the test base URL is always the local MockWebServer.

## 9. Accessibility & i18n

- **Semantics assertions:** UI tests assert content descriptions / merged
  semantics for icon-only controls (remove member, role dropdown) and that the
  Retry/Refresh affordances are reachable by `onNodeWithContentDescription`.
- **String-resource check:** a test scans rendered screens for the expected
  `@StringRes`-sourced strings (resolved via `context.getString`) to guard
  against hard-coded English in AND-354 screens.
- **Locale formatting:** a syndicate-detail test sets the test locale and asserts
  the treasury `balance` (14250 / `USD`) renders with locale-aware currency
  formatting (e.g. `$142.50` if minor-unit, per the AND-354 formatting contract)
  — verifying the ViewModel exposes raw numbers and the screen formats them.
- **Large-font / RTL** smoke: one Robolectric config runs a key screen under a
  larger font scale and an RTL locale to catch truncation/layout asserts where
  feasible.

## 10. Telemetry & Logging

- Tests inject **fake** `Logger` and `Analytics` (recording lists) and assert
  the events defined in AND-361 §10 fire on the right paths:
  `org_list_loaded {count}`, `org_member_role_changed {orgId, role}`,
  `org_invite_sent {role}`, `syndicate_detail_loaded {id}`, and `*_failed
  {errorCode}` on failure.
- Assertions verify **payload hygiene**: recorded analytics maps contain no
  `email`/`user_id`/response-body keys (see §8).
- The test runner emits standard JUnit XML; CI surfaces per-module pass/fail and
  coverage. No production telemetry backend is contacted.

## 11. Testing Strategy

This *is* the test ticket; the strategy is its deliverable.

**Layers & tasks**

| Layer | Source set | Runner | Gradle task |
|-------|-----------|--------|-------------|
| Repository | `core-data/src/test` | JUnit4 + MockWebServer | `:core-data:testDebugUnitTest` |
| ViewModel (extend AND-361) | `feature-orgs/src/test` | JUnit4 + Turbine + fakes | `:feature-orgs:testDebugUnitTest` |
| Compose UI | `feature-orgs/src/test` | Robolectric + ComposeRule | `:feature-orgs:testDebugUnitTest` |
| On-device smoke | `feature-orgs/src/androidTest` | AndroidJUnit4 + Hilt | `:feature-orgs:connectedDebugAndroidTest` |

**Required repository cases:** FR-R1…FR-R6 above — at minimum: each GET happy
path; each mutation (method/path/body/CSRF); 422 array, 403 string, 409 code-obj,
404, 500, malformed-JSON error mappings; 401→refresh→retry success; 401→refresh
fail→Unauthorized (no loop); GET timeout/503 bounded retry → Network; mutation
not retried; contract-drift guard.

**Required UI cases:** FR-U1…FR-U7 — Loading/Empty/Error/Stale/Success render per
screen (org list, org detail/members, invite, syndicate list, syndicate detail);
gesture→action dispatch; role-gating visibility; event→snackbar; invalid-email
validation; locale currency formatting; one a11y semantics test per screen.

**Coverage goal:** repository public methods 100% of branches (success +
every error variant); UI tests cover every state branch of every screen and
every action dispatch. Combined with AND-361's ViewModel suite, the
orgs/syndicates vertical reaches full branch coverage of its public surface.

**CI:** all unit/Robolectric tasks run on every PR; `connectedDebugAndroidTest`
smoke runs on the nightly device job. The suite must be green and stable across
3 consecutive CI runs (flake gate) before merge.

## 12. Dependencies & Sequencing

- **Depends on (hard):** AND-361 (ViewModels + seed unit tests — the backlog's
  listed dependency). Transitively and necessarily also **AND-353**
  (`OrgRepository`, the repo-test target), **AND-356** (`SyndicateRepository`),
  and **AND-354** (Compose screens, the UI-test target). All four must be merged
  before this ticket can be fully realized; AND-354 in particular gates the UI
  half — if AND-354 lands after, this ticket may be split so repo tests land
  first.
- **Transitively depends on** AND-027 (auth/session + base networking that the
  401-refresh and CSRF tests assert) via AND-353/356, and on `core-testing`
  helpers (`MainDispatcherRule`, fakes, fixture loader, `TestNetwork`).
- **Blocks:** none directly; it is a quality gate for the M7/E46
  orgs/syndicates milestone sign-off.
- **Sequencing:** add `core-testing` helpers (`TestNetwork`, builders, fixtures)
  → write repository tests against AND-353/356 → write UI tests against AND-354
  → wire all into CI. If AND-354 slips, ship repository + ViewModel tests behind
  this id and track UI tests as a follow-up note in the PR.

## 13. Risks & Open Questions

- **R1 — AND-354 timing.** UI tests cannot be written before the screens exist.
  Mitigation: gate UI tests on AND-354; land repo tests independently if needed
  and note the split in the PR.
- **R2 — Test-tag contract.** UI tests depend on stable `testTag`s from AND-354.
  Mitigation: define `OrgTestTags` jointly with AND-354 and reference it from
  both screens and tests so a rename breaks compilation, not silently the test.
- **R3 — Authenticator/CSRF location.** The 401-refresh and CSRF logic live in
  `core-network` (AND-027). If `TestNetwork` doesn't faithfully reproduce that
  client, repo tests give false confidence. Mitigation: build `TestNetwork` by
  reusing the production OkHttp module with overridden base URL/timeouts, not a
  hand-rolled client.
- **R4 — Robolectric parity.** Some Compose behaviours differ under Robolectric;
  mitigate with a thin on-device `androidTest` smoke set for high-risk screens.
- **OQ1 — Currency minor units.** Is `treasury.balance` 14250 cents ($142.50) or
  whole units? Confirm against `/openapi.json` for the §9 format assertion.
- **OQ2 — Split sum.** If `share_bps` should sum to 10000, add a non-failing UI
  assertion; otherwise omit. Confirm with backend.

## 14. Acceptance Criteria

- AC-1 `:core-data:testDebugUnitTest` includes `OrgRepositoryTest` and
  `SyndicateRepositoryTest` covering FR-R1…FR-R6, all green, using MockWebServer
  and the production-equivalent OkHttp/Retrofit/Moshi stack.
- AC-2 Every `AppError` variant has at least one repository test mapping a real
  HTTP/JSON response (incl. all three FastAPI `detail` shapes) to the expected
  failure.
- AC-3 The 401 path is proven: exactly one `POST /ui/session/refresh` then one
  retry on success; no refresh loop on repeated 401; mutations are not
  auto-retried while idempotent GETs are (per bounded backoff).
- AC-4 CSRF: unsafe-method requests carry `X-CSRF-Token` equal to the `ui_csrf`
  cookie; a cookie-jar persistence test passes.
- AC-5 Compose UI tests render Loading/Empty/Error/Stale/Success for each
  orgs/syndicates screen (FR-U1/FR-U2/FR-U7) and pass under Robolectric in CI.
- AC-6 Gesture→action dispatch, role-gating visibility, event→snackbar, and
  invalid-email inline validation are each asserted (FR-U3…FR-U6).
- AC-7 No test contacts the dev backend or any real network; a guard test/lint
  enforces this. Fixtures contain only synthetic data.
- AC-8 No PII appears in any asserted log/analytics payload across repo+UI flows.
- AC-9 The full suite (repository + ViewModel + UI) is green and stable across 3
  consecutive CI runs (no flakes) — satisfying the backlog acceptance "Pass".

## 15. Definition of Done

- All acceptance criteria met; code merged to `android-port`.
- Modules compile with Kotlin 2.0.21 / AGP 8.7.3 / JDK 17; Hilt KSP graph
  resolves for the `androidTest` smoke set.
- `:core-data:testDebugUnitTest` and `:feature-orgs:testDebugUnitTest` green
  locally and in CI; `:feature-orgs:connectedDebugAndroidTest` smoke green on the
  nightly device job.
- New shared test helpers (`TestNetwork`, fixture loader, builders, `OrgTestTags`
  reference) live in `core-testing` and are reused by both modules — no
  duplicated harness code.
- `ktlint`/`detekt` clean on test sources; no disabled/`@Ignore`d tests left in;
  no `Thread.sleep` or real network in any test.
- Branch coverage of the orgs/syndicates repository and screen public surfaces
  meets the agreed threshold (target 100% of error/state branches per §11).
- PR links AND-361/AND-353/AND-356/AND-354 as dependencies, records OQ1/OQ2
  resolutions (currency minor units, split sum) confirmed against
  `/openapi.json`, and notes any UI-test split if AND-354 timing required it.
