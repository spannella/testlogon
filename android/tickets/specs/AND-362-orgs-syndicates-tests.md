---
id: AND-362
title: Orgs/syndicates tests
milestone: M7
epic: E46
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
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

- FR-R1 **Happy-path deserialization.** For each GET — orgs: `GET /ui/orgs`,
  `GET /ui/orgs/{org_id}`, `GET /ui/orgs/{org_id}/members`,
  `GET /ui/orgs/invites/pending` (there is **no** `GET /ui/orgs/{id}/invites`);
  syndicates: `GET /ui/syndicates` (returns `SyndicateUserEntry[]`),
  `GET /ui/syndicates/{syndicate_id}`, `GET /ui/syndicates/{syndicate_id}/members`,
  and the separate treasury/split endpoints
  `GET /ui/syndicates/treasury/{syndicate_id}` (`SyndicateTreasuryBalanceOut`) and
  `GET /ui/syndicates/revenue-split/{syndicate_id}/config` (`SplitConfigOut`) — a
  recorded 200 fixture deserializes into the correct `core-model` type with all
  fields (incl. snake_case → camelCase, enums) mapped. **Corrected:** treasury
  and revenue-split are *separate endpoints*, not a nested `treasury`/`revenue_split`
  block on the syndicate-detail body (see §5 and §16).
- FR-R2 **Mutation requests.** Org: `inviteMember`
  (POST `/ui/orgs/{org_id}/members/invite`, body `{email, org_role}`),
  `changeMemberRole` (PATCH `/ui/orgs/{org_id}/members/{member_sub}/role`, body
  `{org_role}`), `removeMember` (DELETE `/ui/orgs/{org_id}/members/{member_sub}`).
  Syndicate: `inviteMember` (POST `/ui/syndicates/{syndicate_id}/invite`, body
  `{user_id}`), `removeMember` (**POST** `/ui/syndicates/{syndicate_id}/remove/{user_id}`,
  **not** DELETE). Each sends the correct method, path, JSON body, and the
  `X-CSRF-Token` header, and maps its response to `ApiResult.Success`.
  **Corrected:** there is no `revokeInvite` DELETE endpoint in the contract; org
  invites are accepted/declined via POST `/ui/orgs/invites/{invite_id}/accept|decline`
  (see §16).
- FR-R3 **Error mapping.** 400/422 (`detail` array), 401, 403, 404, 409, 500,
  and malformed-JSON responses each map to the correct
  `ApiResult.Failure(AppError.*)` variant with a non-empty message.
- FR-R4 **CSRF.** Requests echo the `ui_csrf` cookie value as `X-CSRF-Token`.
  **Corrected:** the web client (`src/api/client.ts`) sets `X-CSRF-Token`
  whenever the `ui_csrf` cookie is present — on **every** method, not only
  POST/PATCH/DELETE. The Android port should mirror this (header on all requests
  when the cookie exists); the security value is still strongest on unsafe
  methods, so assert it there at minimum and also assert it is present on GETs.
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
        val result = repository.inviteMember("org_123", "bad", OrgRole.MEMBER)
        assertThat(result).isInstanceOf(ApiResult.Failure::class.java)
        assertThat((result as ApiResult.Failure).error).isInstanceOf(AppError.Validation::class.java)
    }

    @Test fun `changeMemberRole sends PATCH with CSRF header and body`() = runTest {
        server.enqueue(csrfSeededResponse())                     // sets ui_csrf cookie
        enqueueJson(200, "orgs/member_patched_200.json")
        repository.listOrgs()                                    // seed cookie jar
        // member is identified by member_sub (user_sub), not an opaque mem_* id
        repository.changeMemberRole("org_123", "u_42", OrgRole.ADMIN)
        val patch = server.takeRequest()                        // skip the seed request in real test
        assertThat(patch.method).isEqualTo("PATCH")
        assertThat(patch.path).isEqualTo("/ui/orgs/org_123/members/u_42/role")
        assertThat(patch.getHeader("X-CSRF-Token")).isNotEmpty()
        // request body uses org_role (per OrgMemberRoleUpdateReq), NOT role
        assertThat(patch.body.readUtf8()).contains("\"org_role\":\"admin\"")
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

> **Corrected from prior draft.** The earlier fixture block used field names that
> do not exist in the contract (`id`/`my_role`/`role` on orgs, ISO-string
> `joined_at`, an `invited_at` on the invite, and a nested
> `treasury`/`revenue_split` block with a `share_bps` field). The fixtures below
> are aligned to `OrgOut`/`OrgMemberOut`/`OrgInviteOut`
> (`src/api/endpoints/orgs.ts`), `SyndicateMemberOut`/`SyndicateTreasuryBalanceOut`/
> `SplitConfigOut` (OpenAPI `components.schemas`), and the live endpoints. See §16.

```jsonc
// orgs/list_200.json  (GET /ui/orgs -> OrgOut[])
// org_role enum for management actions is admin|member|viewer; "owner" is a
// status/ownership concept (transfer-ownership), not a settable members role.
[ { "org_id": "org_123", "name": "Acme", "description": "", "slug": "acme",
    "owner_user_sub": "u_1", "status": "active", "plan": "pro",
    "member_count": 12, "storage_used_bytes": 0, "storage_limit_bytes": 0,
    "billing_mode": "central", "created_at": 1746000000, "updated_at": 1746000000,
    "org_role": "admin" },
  { "org_id": "org_777", "name": "Empty Co", "description": "", "slug": "empty",
    "owner_user_sub": "u_42", "status": "active", "plan": "free",
    "member_count": 1, "storage_used_bytes": 0, "storage_limit_bytes": 0,
    "billing_mode": "central", "created_at": 1746000000, "updated_at": 1746000000,
    "org_role": "viewer" } ]

// orgs/members_200.json  (GET /ui/orgs/{org_id}/members -> OrgMemberOut[])
// members are keyed by user_sub; joined_at is an epoch number, not ISO.
[ { "user_sub": "u_42", "org_role": "member", "status": "active",
    "joined_at": 1746090000, "storage_used_bytes": 0, "last_active_at": 1746090000 } ]

// orgs/invite_created_201.json  (POST /ui/orgs/{org_id}/members/invite -> OrgInviteOut)
{ "invite_id": "inv_3", "org_id": "org_123", "org_name": "Acme",
  "email": "new@x.io", "org_role": "member", "status": "pending",
  "invited_by": "u_1", "created_at": 1748768400, "expires_at": 1749373200 }

// syndicates/detail_200.json  (GET /ui/syndicates/{syndicate_id} -> SyndicateOut)
// NOTE: treasury & revenue split are SEPARATE endpoints (below), not nested here.
{ "syndicate_id": "syn_7", "name": "North Split", "role": "member" }

// syndicates/members_200.json  (GET /ui/syndicates/{syndicate_id}/members -> SyndicateMemberOut[])
[ { "user_id": "u_42", "display_name": "Jo", "role": "member", "joined_at": 1746090000 } ]

// syndicates/treasury_200.json  (GET /ui/syndicates/treasury/{syndicate_id} -> SyndicateTreasuryBalanceOut)
// balance is in CENTS (resolves OQ1): 1425000 cents = $14,250.00.
{ "syndicate_id": "syn_7", "balance_cents": 1425000, "total_deposited_cents": 1425000,
  "total_disbursed_cents": 0, "currency": "USD", "updated_at": 1748768400 }

// syndicates/split_config_200.json  (GET /ui/syndicates/revenue-split/{syndicate_id}/config -> SplitConfigOut)
// shares are weights_bps (user_id -> basis points), platform_fee_bps default 1500.
{ "mode": "weighted", "performance_metric": "", "performance_window_days": 30,
  "platform_fee_bps": 1500, "updated_at": 1748768400, "updated_by": "u_1",
  "weights_bps": { "u_42": 4000, "u_43": 6000 } }

// errors/detail_array_422.json  (FastAPI HTTPValidationError — documented shape)
{ "detail": [ { "loc": ["body","email"], "msg": "value is not a valid email",
                "type": "value_error.email" } ] }

// errors/detail_string_403.json  (handled by normalizeErrorDetail string branch)
{ "detail": "Not authorized" }

// errors/detail_code_409.json  (handled by normalizeErrorDetail object branch)
{ "detail": { "code": "ALREADY_MEMBER", "message": "User already a member" } }
```

Request-side assertions verify method, path, JSON body keys (snake_case:
`{"email":"...","org_role":"member"}` for org invite; `{"org_role":"admin"}` for
role change; `{"user_id":"..."}` for syndicate invite), and presence of
`X-CSRF-Token` on unsafe methods. A **contract-drift
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
- **Locale formatting:** a syndicate-detail/treasury test sets the test locale and
  asserts the treasury `balance_cents` (e.g. `1425000` / `USD`) renders with
  locale-aware currency formatting (`$14,250.00`; balance is in **cents** —
  confirmed against `SyndicateTreasuryBalanceOut`, resolving OQ1) — verifying the
  ViewModel exposes raw cents and the screen divides by 100 + formats them.
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
- **OQ1 — Currency minor units. RESOLVED.** `SyndicateTreasuryBalanceOut.balance_cents`
  is in **cents** (the field is literally `balance_cents`; deposit/disburse use
  `amount_cents`). The §9 assertion uses cents → divide by 100 for display.
- **OQ2 — Split sum. RESOLVED (re-scoped).** Revenue split is exposed as
  `SplitConfigOut.weights_bps` (a `user_id -> basis-points` map) plus a separate
  `platform_fee_bps` (default 1500). There is no `share_bps` array field. Member
  weights need not sum to 10000 (they are relative weights normalized at split
  execution, after `platform_fee_bps` is taken off the top); do **not** assert a
  10000 sum. If a UI invariant check is desired, assert weights are non-negative
  and that the rendered member percentages sum to ~100% of the *post-fee* pool.

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

## 16. Citations & Assumption Audit

Each key technical claim with its VERDICT and exact SOURCE pointer. Sources are
the backend OpenAPI (`METHOD /path` and/or `components.schemas.<Name>`), the
frontend reference app, or a framework reference URL.

1. **`GET /ui/orgs` lists orgs.** VERIFIED.
   Source: OpenAPI `GET /ui/orgs` (op `list_orgs_ui_orgs_get`);
   `src/api/endpoints/orgs.ts: listOrgs`.
2. **`GET /ui/orgs/{org_id}` org detail.** VERIFIED.
   Source: OpenAPI `GET /ui/orgs/{org_id}`; `src/api/endpoints/orgs.ts: getOrg`.
3. **`GET /ui/orgs/{org_id}/members` member list.** VERIFIED.
   Source: OpenAPI `GET /ui/orgs/{org_id}/members`;
   `src/api/endpoints/orgs.ts: listMembers`.
4. **Org invites are read at `GET /ui/orgs/invites/pending`; there is no
   `GET /ui/orgs/{id}/invites`.** CORRECTED (spec FR-R1 listed
   `/ui/orgs/{id}/invites`). Source: OpenAPI `GET /ui/orgs/invites/pending`
   (`list_pending_invites…`); `src/api/endpoints/orgs.ts: listPendingInvites`.
   No `…/{org_id}/invites` GET exists in the index.
5. **Invite a member: `POST /ui/orgs/{org_id}/members/invite` with body
   `{email, org_role}`.** CORRECTED (spec said `POST /ui/orgs/{id}/invites` /
   body `{email, role}`). Source: OpenAPI `POST /ui/orgs/{org_id}/members/invite`
   req `OrgMemberInviteReq`; schema `OrgMemberInviteReq` has `email` (required)
   and `org_role` (default "member", pattern `^(admin|member|viewer)$`);
   `src/api/endpoints/orgs.ts: inviteMember`.
6. **Change member role: `PATCH /ui/orgs/{org_id}/members/{member_sub}/role`
   with body `{org_role}`.** CORRECTED (spec said
   `PATCH /ui/orgs/{id}/members/{member}` body `{role}`). Source: OpenAPI
   `PATCH /ui/orgs/{org_id}/members/{member_sub}/role` req
   `OrgMemberRoleUpdateReq` (required `org_role`, pattern `^(admin|member|viewer)$`);
   `src/api/endpoints/orgs.ts: changeMemberRole`.
7. **Remove member: `DELETE /ui/orgs/{org_id}/members/{member_sub}`.** VERIFIED
   (method DELETE is correct). Source: OpenAPI
   `DELETE /ui/orgs/{org_id}/members/{member_sub}`;
   `src/api/endpoints/orgs.ts: removeMember`. Note the path param is `member_sub`
   (a user_sub), not an opaque `mem_*` id.
8. **There is no `revokeInvite` DELETE endpoint.** CORRECTED (spec FR-R2 listed
   `revokeInvite (DELETE)`). Source: index has only
   `POST /ui/orgs/invites/{invite_id}/accept` and
   `POST /ui/orgs/invites/{invite_id}/decline` (`src/api/endpoints/orgs.ts:
   acceptInvite/declineInvite`); no invite-DELETE route.
9. **Org member DTO fields.** CORRECTED (spec fixture used `id`/`user_id`/
   `display_name`/`email`/`role`/ISO `joined_at`). Actual `OrgMemberOut`:
   `user_sub`, `org_role`, `status`, `joined_at` (epoch number),
   `storage_used_bytes`, `last_active_at?` — no `display_name`/`email`/`role`.
   Source: `src/api/endpoints/orgs.ts: OrgMemberOut`.
10. **Org DTO fields.** CORRECTED (spec fixture used `id`/`my_role`). Actual
    `OrgOut` keys include `org_id`, `slug`, `owner_user_sub`, `status`, `plan`,
    `member_count`, `org_role?` — the caller's role field is `org_role`, not
    `my_role`, and the id is `org_id`. Source: `src/api/endpoints/orgs.ts: OrgOut`.
11. **Org invite DTO fields.** CORRECTED (spec used `id`/`role`/`invited_at`).
    Actual `OrgInviteOut`: `invite_id`, `org_id`, `org_name`, `email`,
    `org_role`, `status`, `invited_by`, `created_at`, `expires_at`, `token?`.
    Source: `src/api/endpoints/orgs.ts: OrgInviteOut`.
12. **Org role enum for invite/role-change is `admin|member|viewer`; `owner`
    is not a settable role.** VERIFIED/CLARIFIED (spec fixture used
    `my_role:"owner"`). Source: regex `^(admin|member|viewer)$` on
    `OrgMemberInviteReq.org_role` and `OrgMemberRoleUpdateReq.org_role`;
    ownership change is `POST /ui/orgs/{org_id}/transfer-ownership`
    (`OrgTransferOwnershipReq.new_owner_user_sub`).
13. **`GET /ui/syndicates` returns `SyndicateUserEntry[]` (membership entries),
    not `SyndicateOut[]`.** CORRECTED/CLARIFIED. Source: OpenAPI
    `GET /ui/syndicates` (`list_my_syndicates…`);
    `src/api/endpoints/syndicates.ts: listMySyndicates` typed
    `SyndicateUserEntry[]`. `SyndicateOut` is the single-detail/discover shape.
14. **`GET /ui/syndicates/{syndicate_id}` syndicate detail.** VERIFIED.
    Source: OpenAPI `GET /ui/syndicates/{syndicate_id}`;
    `src/api/endpoints/syndicates.ts: getSyndicate`.
15. **Treasury is a SEPARATE endpoint, not a nested `treasury` block.**
    CORRECTED (spec fixture nested `treasury` under syndicate detail). Source:
    OpenAPI `GET /ui/syndicates/treasury/{syndicate_id}` resp
    `SyndicateTreasuryBalanceOut`.
16. **Treasury balance is in cents (`balance_cents`).** CORRECTED + resolves OQ1
    (spec used `balance: 14250` whole-units ambiguity). Source: schema
    `SyndicateTreasuryBalanceOut` fields `balance_cents`, `total_deposited_cents`,
    `total_disbursed_cents`, `currency`, `updated_at` (all `*_cents` integers).
17. **Revenue split is a SEPARATE endpoint exposing `weights_bps` (a
    `user_id->bps` map) + `platform_fee_bps`, not a `revenue_split` array of
    `{share_bps}`.** CORRECTED + resolves OQ2. Source: OpenAPI
    `GET /ui/syndicates/revenue-split/{syndicate_id}/config` resp
    `SplitConfigOut` (props `mode`, `weights_bps`, `platform_fee_bps` default
    1500, …); distribution rows use `SplitDistributionOut.percentage_bps`.
18. **Syndicate member DTO fields.** CORRECTED (spec used `display_name` +
    `share_bps`). Actual `SyndicateMemberOut`: `user_id` (required),
    `display_name`, `role`, `joined_at` (epoch integer). Source: schema
    `SyndicateMemberOut`; `src/api/endpoints/syndicates.ts: listMembers`.
19. **Syndicate invite: `POST /ui/syndicates/{syndicate_id}/invite` body
    `{user_id}` (invites an existing user, not by email).** CORRECTED/CLARIFIED.
    Source: OpenAPI `POST /ui/syndicates/{syndicate_id}/invite` req
    `SyndicateInviteIn`; `src/api/endpoints/syndicates.ts: inviteMember`.
20. **Syndicate remove member is `POST /ui/syndicates/{syndicate_id}/remove/{user_id}`,
    NOT a DELETE.** CORRECTED (spec FR-R2 grouped removeMember as DELETE).
    Source: OpenAPI `POST /ui/syndicates/{syndicate_id}/remove/{user_id}`;
    `src/api/endpoints/syndicates.ts: removeMember`.
21. **Auth/session refresh on 401: a single `POST /ui/session/refresh`, then one
    retry of the original; on repeated 401 the client logs out (no loop).**
    VERIFIED. Source: `src/api/client.ts` (`refreshSession`, the `refreshPromise`
    single-flight guard, single retry, `logout("session_expired")` on retry-401);
    OpenAPI `POST /ui/session/refresh` (resp 200).
22. **CSRF: `X-CSRF-Token` header is set from the `ui_csrf` cookie.** VERIFIED
    with a CORRECTION to scope: the web client sets it on **every** request when
    the cookie is present (not only on unsafe methods, as spec FR-R4 implied).
    Source: `src/api/client.ts` (`const csrf = getCookie("ui_csrf"); if (csrf)
    headers.set("X-CSRF-Token", csrf)` — unconditional on method).
23. **FastAPI `detail` has three shapes (string | array-of-`{msg}` | object with
    `code`/`message`).** VERIFIED. Source: `src/api/client.ts:
    normalizeErrorDetail` (string branch, array `.msg` branch, object/`code`
    branch via `mapAuthorizationError`). Documented `422` shape is
    `HTTPValidationError` (`detail: [{loc,msg,type}]`) in OpenAPI.
24. **Network/offline error surfaces distinctly.** VERIFIED (web). Source:
    `src/api/client.ts` `catch` around `fetch` throws `ApiError(0, "Network
    error")`. Android equivalent is `AppError.Network` from an `IOException` —
    UNVERIFIED-ASSUMPTION for the exact Android mapping (depends on AND-027/353
    code not present in these sources).
25. **`Authorization: Bearer <token>` is the primary auth, with
    `X-IMPERSONATION-TOKEN` when impersonating; server-side dep params are
    `user_sub`, `X-SESSION-ID`, `X-IMPERSONATION-TOKEN`.** VERIFIED.
    Source: `src/api/client.ts` (sets `Authorization` from `useAuthStore`,
    `X-IMPERSONATION-TOKEN` from impersonation store); OpenAPI `params=` column on
    every `/ui/orgs/*` and `/ui/syndicates/*` row.
26. **Robolectric + `createComposeRule()` runs Compose UI tests on the JVM
    without a device.** VERIFIED (framework ref). Source (framework ref):
    https://developer.android.com/develop/ui/compose/testing and
    https://robolectric.org/ — using `@Config(sdk=[34])` to match the device API.
27. **`bounded backoff / ~20s timeout / retry idempotent GET only, not
    mutations`.** UNVERIFIED-ASSUMPTION. The web client does NOT implement
    automatic retry/backoff for 503/timeout (it only retries once after a 401
    refresh). This is an Android-port design choice owned by AND-027/AND-353
    `core-network`, not visible in these reference sources — test it against the
    actual Android interceptor, not the web client.

### Corrections made

- FR-R1: removed nonexistent `GET /ui/orgs/{id}/invites`; named real GETs;
  split treasury & revenue-split into their own endpoints (cites 4, 15, 17).
- FR-R2 + §4.2 code: org invite path → `…/members/invite`, body
  `{email, org_role}`; role-change path → `…/members/{member_sub}/role`, body
  `{org_role}` (was `{role}`); removed `revokeInvite (DELETE)`; syndicate remove
  member is POST not DELETE (cites 5, 6, 8, 20).
- §4.2 test: member identified by `user_sub` (`u_42`), not `mem_9`; asserts the
  corrected path and `"org_role":"admin"` body key.
- FR-R4 + §5 assertion line: CSRF header is set on all methods, not only unsafe;
  body key for role change is `org_role` (cites 22, 6).
- §5 fixtures rewritten to real DTOs: `OrgOut`/`OrgMemberOut`/`OrgInviteOut`
  field names, epoch (not ISO) timestamps, `org_role` not `my_role`/`role`,
  separate treasury (`balance_cents`) and split (`weights_bps`) fixtures (cites
  9, 10, 11, 15, 16, 17, 18).
- §9 + §13 OQ1: treasury balance is cents (`balance_cents`); display divides by
  100 (cites 16).
- §13 OQ2: revenue split is `weights_bps` map + `platform_fee_bps`, no
  `share_bps`, no mandatory 10000 sum (cites 17).

### Open assumptions

- **Android `AppError` mapping & variant names** (`Validation`, `Unauthorized`,
  `Forbidden`, `NotFound`, `Conflict`, `Server`, `Network`, `Unknown`): not
  defined in the reference sources (they live in AND-027/AND-353 Android code).
  The web `ApiError(status, detail)` is the closest contract; the per-status →
  `AppError` mapping is assumed and must be validated against the real
  `core-network` code.
- **Bounded backoff / timeout / retry policy** (FR-R6): not present in the web
  client; an Android-port design decision (see citation 27). Tests must assert
  the actual interceptor behavior once AND-353/AND-027 land.
- **`X-CSRF-Token` exact header name on Android**: assumed identical to web; the
  Android `core-network` interceptor naming is unverified here.
- **AND-354 test tags / `OrgTestTags` and screen composition** (which fields land
  on which screen, e.g. whether treasury+split are aggregated on one
  syndicate-detail screen): owned by AND-354, not in these sources — UI tests
  depend on that contract (R2).

## 17. Test Plan

Test target legend: **JVM** = local JVM unit/Robolectric (no device);
**emu35** = headless emulator AVD `test35` (x86_64, API 35) in CI;
**A15** = physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a) on the
build host. This ticket is a test suite with no hardware-dependent behavior
(no camera/biometric/WebRTC/FCM/Telecom), so the vast majority runs on JVM;
a small on-device smoke set runs on the physical device to validate the
arm64/API-34 build and real Hilt/Compose wiring that Robolectric can mask.

- **TC-AND-362-01 — listOrgs happy path deserialization.**
  Type: contract/MockWebServer. Target: JVM (`:core-data:testDebugUnitTest`).
  Preconditions: `TestNetwork` repo on MockWebServer; `orgs/list_200.json`
  enqueued (200). Steps: call `repository.listOrgs()`; capture request. Expected:
  `ApiResult.Success` with 2 orgs; `org_id`, `slug`, `member_count`, `org_role`
  mapped (snake→camel); first org `org_role == ADMIN`; request path `/ui/orgs`,
  method GET. Traces: AC-1.

- **TC-AND-362-02 — each org GET deserializes (detail, members, pending
  invites).** Type: contract/MockWebServer. Target: JVM. Preconditions: fixtures
  `orgs/detail_200.json`, `orgs/members_200.json`, `orgs/invites_pending_200.json`.
  Steps: call `getOrg`, `listMembers`, `listPendingInvites`; assert each request
  path/method. Expected: Success; member maps to `user_sub`/`org_role`/`joined_at`
  (epoch); pending-invite path is `/ui/orgs/invites/pending` (NOT
  `/ui/orgs/{id}/invites`). Traces: AC-1.

- **TC-AND-362-03 — syndicate GETs incl. separate treasury & split.**
  Type: contract/MockWebServer. Target: JVM. Preconditions: fixtures
  `syndicates/detail_200.json`, `syndicates/members_200.json`,
  `syndicates/treasury_200.json`, `syndicates/split_config_200.json`. Steps: call
  detail, members, treasury, split-config repo methods; assert paths. Expected:
  Success; treasury path `/ui/syndicates/treasury/{id}` →
  `balance_cents=1425000`; split path `/ui/syndicates/revenue-split/{id}/config`
  → `weights_bps` map + `platform_fee_bps=1500`; member `user_id`/`role`/
  `joined_at` mapped. Traces: AC-1.

- **TC-AND-362-04 — org mutations send correct method/path/body + CSRF.**
  Type: contract/MockWebServer. Target: JVM. Preconditions: cookie-seeding
  response sets `ui_csrf`; success fixtures enqueued. Steps: seed cookie via a
  GET; call `inviteMember("org_123","new@x.io",MEMBER)`,
  `changeMemberRole("org_123","u_42",ADMIN)`,
  `removeMember("org_123","u_42")`; inspect each recorded request. Expected:
  invite → `POST /ui/orgs/org_123/members/invite`, body
  `{"email":"new@x.io","org_role":"member"}`; role → `PATCH
  /ui/orgs/org_123/members/u_42/role`, body `{"org_role":"admin"}`; remove →
  `DELETE /ui/orgs/org_123/members/u_42`; every unsafe request carries
  `X-CSRF-Token` == seeded `ui_csrf`. Traces: AC-1, AC-4.

- **TC-AND-362-05 — syndicate mutations method/path/body.**
  Type: contract/MockWebServer. Target: JVM. Preconditions: success fixtures.
  Steps: call syndicate `inviteMember("syn_7","u_99")` and
  `removeMember("syn_7","u_99")`. Expected: invite → `POST
  /ui/syndicates/syn_7/invite`, body `{"user_id":"u_99"}`; remove → **POST**
  `/ui/syndicates/syn_7/remove/u_99` (NOT DELETE); both succeed. Traces: AC-1.

- **TC-AND-362-06 — error mapping covers every AppError variant + 3 detail
  shapes.** Type: contract/MockWebServer. Target: JVM. Preconditions: fixtures
  `errors/detail_array_422.json`, `errors/detail_string_403.json`,
  `errors/detail_code_409.json`, plus bare 400/404/500 and a malformed-JSON 200.
  Steps: enqueue each in turn and invoke an appropriate repo call. Expected:
  422→`AppError.Validation` (message from `.msg`), 403 string→`Forbidden`
  (message "Not authorized"), 409 object→`Conflict` (message "User already a
  member"), 404→`NotFound`, 500→`Server`, malformed JSON→`Unknown`/parse error;
  every failure has a non-empty message. Traces: AC-2.

- **TC-AND-362-07 — 401 → single refresh → retry succeeds.**
  Type: contract/MockWebServer. Target: JVM. Preconditions: enqueue 401, then 200
  for `/ui/session/refresh`, then `orgs/list_200.json`. Steps: call `listOrgs()`;
  inspect `requestCount` and the three paths in order. Expected: `ApiResult.Success`;
  exactly 3 requests; order `/ui/orgs`, `/ui/session/refresh`, `/ui/orgs`. Traces:
  AC-3.

- **TC-AND-362-08 — repeated 401 after refresh → Unauthorized, no loop.**
  Type: contract/MockWebServer. Target: JVM. Preconditions: enqueue 401, 200
  (refresh), 401. Steps: call `listOrgs()`. Expected:
  `ApiResult.Failure(AppError.Unauthorized)`; exactly 3 requests (no further
  refresh); refresh attempted only once. Traces: AC-3.

- **TC-AND-362-09 — flaky-host/offline + bounded retry policy.**
  Type: contract/MockWebServer (virtual time). Target: JVM. Preconditions:
  enqueue 503/timeout responses for a GET; separately a mutation that 503s.
  Steps: under `runTest` virtual time, call `listOrgs()` (idempotent GET) and a
  mutation; advance time. Expected: GET is retried per the configured bounded
  backoff then yields `AppError.Network`; the mutation is **not** auto-retried;
  no wall-clock sleep; test completes <1s. NOTE: per §16 citation 27 the retry
  policy is an Android-port assumption — this case also *pins* that policy once
  implemented. Traces: AC-3, AC-9.

- **TC-AND-362-10 — no-live-network guard + synthetic-data guard.**
  Type: unit. Target: JVM. Preconditions: none. Steps: run the guard test/lint
  that scans built OkHttp clients and fixtures. Expected: no client base URL
  equals `18.222.237.167`; all fixtures contain only synthetic emails/ids
  (`jo@x.io`, `org_123`, `u_42`); test fails fast if a real host or PII appears.
  Traces: AC-7.

- **TC-AND-362-11 — CSRF echo + cookie-jar persistence across requests.**
  Type: contract/MockWebServer. Target: JVM. Preconditions: first response sets
  `Set-Cookie: ui_csrf=...`. Steps: make a GET (seeds jar), then a POST mutation;
  assert the POST carries `X-CSRF-Token` equal to the cookie and that the cookie
  persists across the second request. Expected: header present and equal; jar
  retains cookie. Per §16 citation 22, header is sent on all methods — also
  assert it appears on the GET. Traces: AC-4.

- **TC-AND-362-12 — screen state rendering (Loading/Empty/Error/Stale/Success)
  per screen.** Type: Compose-UI (Robolectric). Target: JVM (emu35 optional).
  Preconditions: stateless screens (org list, org members, invite, syndicate
  list, syndicate detail) fed explicit `UiState`. Steps: set each state; query by
  test tag/semantics. Expected: Loading shows progress; Empty shows empty copy;
  Error shows message + `retry_button`; Stale shows `stale_banner` + retained
  list; Success shows rows. Traces: AC-5.

- **TC-AND-362-13 — gesture→action dispatch, role-gating, event→snackbar,
  invalid-email validation.** Type: Compose-UI (Robolectric). Target: JVM.
  Preconditions: stateless screens + lambda capture; stateful `…Route` with a
  fake VM emitting events. Steps: pull-to-refresh, Retry tap, role-dropdown
  select, remove-after-confirm, invite submit; render with `callerRole=VIEWER`;
  emit `InviteSent`/`NotAuthorized`; type an invalid email. Expected: actions
  `Refresh`/`Retry`/`ChangeRole`/`RemoveMember`/`SendInvite` dispatched; VIEWER
  hides change-role/remove/invite controls; snackbar text matches; invalid email
  shows `emailError` and disables submit. Traces: AC-6.

- **TC-AND-362-14 — accessibility + locale currency formatting.**
  Type: Compose-UI (Robolectric). Target: JVM. Preconditions: icon-only controls
  have content descriptions; treasury fixture `balance_cents=1425000`. Steps:
  query `onNodeWithContentDescription` for remove/role/Retry; set test locale and
  render treasury. Expected: each icon-only control reachable by content
  description; balance renders `$14,250.00` (cents/100, locale-aware); large-font
  + RTL smoke shows no truncation assert failure. Traces: AC-5, AC-6.

- **TC-AND-362-15 — no-PII-in-telemetry across repo + UI flows.**
  Type: integration. Target: JVM. Preconditions: fake `Logger`/`Analytics`
  recording lists injected. Steps: drive a representative repo call and a UI
  flow; inspect recorded payloads. Expected: events fire
  (`org_list_loaded{count}`, `org_member_role_changed{orgId,role}`,
  `org_invite_sent{role}`, `syndicate_detail_loaded{id}`, `*_failed{errorCode}`)
  but no payload contains `email`/`user_sub`/`user_id`/raw response-body keys.
  Traces: AC-8.

- **TC-AND-362-16 — on-device smoke (Hilt graph + nav + arm64/API-34 build).**
  Type: instrumented/e2e. Target: **A15 physical device (required)** — runs the
  arm64-v8a build on API 34 to catch ABI/API differences the x86_64/API-35
  emulator and Robolectric mask. Preconditions: `:feature-orgs:connectedDebug
  AndroidTest` deployed to serial `R5CX821TA9R`; backend stubbed/MockWebServer in
  process (no dev host). Steps: launch org list → open org detail/members →
  open syndicate detail; assert screens compose and Hilt KSP graph resolves on
  device. Expected: navigation + DI wiring succeed on real hardware; no crash;
  smoke passes on the nightly device job. Traces: AC-5, AC-9.

### Coverage matrix (section-14 AC → TCs)

| AC | Covered by |
|----|-----------|
| AC-1 (repo GET/mutation suite, prod-equivalent stack) | TC-01, TC-02, TC-03, TC-04, TC-05 |
| AC-2 (every AppError variant + 3 detail shapes) | TC-06 |
| AC-3 (401 refresh once + retry; no loop; GET-only bounded retry) | TC-07, TC-08, TC-09 |
| AC-4 (CSRF header == ui_csrf; cookie-jar persistence) | TC-04, TC-11 |
| AC-5 (Compose Loading/Empty/Error/Stale/Success per screen) | TC-12, TC-14, TC-16 |
| AC-6 (gesture→action, role-gating, event→snackbar, email validation) | TC-13, TC-14 |
| AC-7 (no live network; synthetic-only fixtures) | TC-10 |
| AC-8 (no PII in log/analytics payloads) | TC-15 |
| AC-9 (full suite green + stable across 3 CI runs) | TC-09, TC-16 (+ all run in the flake gate) |
