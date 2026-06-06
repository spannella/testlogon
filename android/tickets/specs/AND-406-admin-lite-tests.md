---
id: AND-406
title: Admin-lite tests
milestone: M8
epic: E53
priority: P2
size: M
status: draft
depends_on: [AND-403]
blocks: []
---

# AND-406 — Admin-lite tests

## 1. Overview & Goal

AND-406 is a **Test** ticket. It delivers the automated test suite that proves the
"admin-lite" surface shipped by AND-403 (read-only admin alerts/dashboards) and its
sibling AND-404 (read-only email/SMS dashboards) is correctly **role-gated** and
strictly **read-only** on Android. No production behavior is added by this ticket;
its only deliverables are tests, fixtures, and any narrow test-only seams (fakes,
fixtures, robot helpers) required to exercise the feature deterministically.

The goal is twofold and falls directly out of the backlog scope ("Role-gating +
read-only tests") and acceptance ("Pass"):

1. **Role-gating coverage** — verify that the admin-lite entry points and screens are
   reachable only when the authenticated principal (from `GET /ui/me`) carries an
   admin role/scope, and are hidden or hard-blocked (with a 403/empty state) for
   non-admins.
2. **Read-only coverage** — verify that the feature performs only idempotent `GET`
   requests, exposes no mutation affordances (no buttons/menus that POST/PUT/PATCH/
   DELETE), and degrades gracefully (loading / stale / offline / error) against the
   unreliable dev backend, consistent with AND-403's "no mutations" constraint.

"Pass" is interpreted as: the new test source set compiles and the full suite
(`testDebugUnitTest` for JVM tests, `connectedDebugAndroidTest`/Robolectric for
Compose UI tests) is green in CI with the coverage gates in §11 met.

## 2. Context & References

- **Module under test:** `feature-admin` (the admin-lite feature module created by
  AND-403), layered `app -> feature-admin -> core-*`. Tests live in that module's
  `src/test` (JVM/Robolectric) and `src/androidTest` (instrumented) source sets.
- **Namespace:** `com.testlogon.android.feature.admin` and
  `com.testlogon.android.feature.admin.test`.
- **Depends on AND-403** (provides `AdminAlertsViewModel`, `AdminAlertsScreen`,
  `AdminRepository`, the `AdminRoute` graph entry, and the role-gate composable).
  AND-404 (email/SMS dashboards) shares the same gate and repository; where AND-404
  has merged before this ticket, its screens are included in the same suite, otherwise
  they are deferred to AND-404's own DoD.
- **Auth/role source:** cookie-based session (AND auth stack). The principal and its
  roles come from `GET /ui/me`; `core-data` exposes a `SessionRepository` /
  `currentUser: StateFlow<UserSession?>` consumed by the gate.
- **Backend:** FastAPI dev host `http://18.222.237.167:8000` (plaintext, unreliable).
  Tests MUST NOT hit the live host; all network is faked via OkHttp `MockWebServer`
  or repository-level fakes. OpenAPI at `/openapi.json`; web reference under
  `frontend/src/api/endpoints/*.ts`.
- **Shared test infra:** `core-testing` (MainDispatcherRule, `MockWebServer`
  builders, Moshi adapters, `TestData` fixtures, Hilt test runner).
- **Reference web behavior:** the web app's admin views are read-only and role-gated;
  parity is the bar for these tests.

## 3. Functional Requirements

The suite MUST assert the following observable behaviors of the admin-lite feature.

**FR-1 Role-gating (positive).** When `currentUser` has an admin role
(e.g. `roles` contains `"admin"` or `scopes` contains `"admin:read"`), the admin
entry point is exposed and `AdminAlertsScreen` renders the alerts/metrics content.

**FR-2 Role-gating (negative).** When `currentUser` is non-admin (standard user),
the admin entry point is **not** present in navigation, and direct navigation to the
`admin` route resolves to a blocked state (an `AdminUiState.Forbidden` / 403 empty
state), never the data content.

**FR-3 Role-gating (unauthenticated/null).** When `currentUser` is `null` (no
session), the gate routes to login/blocked and never issues admin GETs.

**FR-4 Read-only — no mutating calls.** Across all admin-lite flows, the only HTTP
methods issued are `GET`. The suite asserts on recorded `MockWebServer` requests that
no `POST/PUT/PATCH/DELETE` is sent to any `/ui/admin/*` path.

**FR-5 Read-only — no mutation UI.** `AdminAlertsScreen` (and dashboard screens when
in scope) expose no controls with mutation semantics: no "acknowledge", "resolve",
"delete", "edit", "resend", "send test" buttons; lists/cards render as display-only.
The suite asserts these nodes do not exist.

**FR-6 Loading/empty/error/stale states.** The suite verifies the ViewModel emits
`Loading -> Success(content)`, `Loading -> Empty`, `Loading -> Error(message)`, and a
`Stale` path (cached data shown when refresh fails) consistent with the offline/stale
requirements of the project.

**FR-7 CSRF/session interplay (read path).** A `401` on an admin GET triggers exactly
one `POST /ui/session/refresh` followed by a single retry of the original GET; a
second `401` surfaces an auth error and does not loop.

## 4. Technical Design

This is a test-authoring ticket; "design" means the test architecture, the seams used,
and the helper/robot APIs introduced. No app-layer production logic changes except,
if strictly necessary, widening visibility (`internal` + `@VisibleForTesting`) or
adding `testTag`s to admin composables.

### 4.1 Source sets & frameworks

- **JVM unit tests** (`feature-admin/src/test`): JUnit4, kotlinx-coroutines-test
  (`runTest`, `StandardTestDispatcher`), Turbine for `StateFlow`/`Flow` assertions,
  MockK for collaborators, OkHttp `MockWebServer` + Moshi for repository wiring.
- **Compose UI tests** (`feature-admin/src/test`, Robolectric) and/or
  (`feature-admin/src/androidTest`, instrumented): `createComposeRule()` /
  `createAndroidComposeRule()`, `composeTestRule.onNodeWithTag(...)`, Hilt test app
  via `core-testing`'s `HiltTestRunner`.

### 4.2 Key test types & signatures

```kotlin
package com.testlogon.android.feature.admin

// ---- ViewModel unit tests ----
class AdminAlertsViewModelTest {
    @get:Rule val mainDispatcherRule = MainDispatcherRule()

    private lateinit var server: MockWebServer
    private lateinit var repository: AdminRepository
    private val session = MutableStateFlow<UserSession?>(null)

    @Before fun setUp() { /* start MockWebServer, build Retrofit, fake SessionRepository */ }
    @After fun tearDown() { server.shutdown() }

    @Test fun `admin user loads alerts -> Success`() = runTest { /* FR-1, FR-6 */ }
    @Test fun `non-admin user -> Forbidden, no GET issued`() = runTest { /* FR-2, FR-4 */ }
    @Test fun `null session -> NotAuthenticated, no GET issued`() = runTest { /* FR-3 */ }
    @Test fun `empty alerts payload -> Empty`() = runTest { /* FR-6 */ }
    @Test fun `5xx on alerts -> Error and prior cache shown as Stale`() = runTest { /* FR-6 */ }
    @Test fun `401 then refresh then retry -> single refresh`() = runTest { /* FR-7 */ }
}

// ---- Repository unit tests ----
class AdminRepositoryTest {
    @Test fun `getAlerts maps detail string error`() = runTest { /* ApiResult.Error */ }
    @Test fun `getAlerts maps detail array msg error`() = runTest { /* [{msg}] */ }
    @Test fun `repository issues only GET on admin paths`() = runTest { /* FR-4 */ }
}
```

```kotlin
// ---- Compose role-gating + read-only UI tests ----
@RunWith(AndroidJUnit4::class)
class AdminAlertsScreenTest {
    @get:Rule val composeTestRule = createComposeRule()

    @Test fun adminState_rendersAlertsContent() { /* FR-1, FR-5 */ }
    @Test fun forbiddenState_rendersBlockedAndNoContent() { /* FR-2 */ }
    @Test fun screen_hasNoMutationAffordances() { /* FR-5 */ }
    @Test fun errorState_showsRetryForGet() { /* FR-6: retry is a GET, not a mutation */ }
}
```

### 4.3 Test seams introduced

- `AdminTestData` (in module test source): JSON fixtures + typed builders
  (`adminAlert(...)`, `userSession(roles = listOf("admin"))`, etc.).
- `AdminRobot` (Compose robot/page-object): `assertAlertsVisible()`,
  `assertBlocked()`, `assertNoMutationButtons()`, `clickRetry()`.
- `testTag` constants object `AdminTestTags` (added to AND-403 composables if absent):
  `ALERTS_LIST`, `BLOCKED_STATE`, `ERROR_RETRY`, `STALE_BANNER`.
- A `FakeSessionRepository` (or reuse from `core-testing`) driving `currentUser`.

No production runtime dependency is added; all new artifacts are `testImplementation` /
`androidTestImplementation` scoped.

## 5. API Contract

This ticket adds no endpoints; it asserts against the contract owned by AND-403/AND-404.
The suite stubs these responses via `MockWebServer`. Representative shapes the tests
encode as fixtures:

`GET /ui/admin/alerts` (admin, 200):
```json
{
  "items": [
    { "id": "al_01", "severity": "warning", "title": "Queue backlog",
      "metric": "email.queue.depth", "value": 1240, "ts": "2026-06-05T12:00:00Z" }
  ],
  "next_cursor": null
}
```

`GET /ui/admin/alerts` (non-admin, 403):
```json
{ "detail": "Not authorized" }
```

FastAPI `detail` variants the error mapper must handle (asserted in repo tests):
`{"detail": "string"}`, `{"detail": [{"msg": "..."}]}`, `{"detail": {"code": "forbidden"}}`.

401 refresh path (FR-7): first `GET /ui/admin/alerts` -> `401`; client issues
`POST /ui/session/refresh` (echoing `X-CSRF-Token` from the `ui_csrf` cookie) -> `204`;
retries the original `GET` -> `200`. The suite asserts exactly: GET, POST refresh, GET.

When AND-404 is in scope, the same patterns apply to
`GET /ui/admin/email/dashboard/*` and `GET /ui/admin/sms/dashboard/*` (read-only).

## 6. Data & State Management

The tests assert the `AdminUiState` contract from AND-403:

```kotlin
sealed interface AdminUiState {
    data object Loading : AdminUiState
    data class Success(val alerts: List<AdminAlert>, val stale: Boolean = false) : AdminUiState
    data object Empty : AdminUiState
    data object Forbidden : AdminUiState          // role gate / 403
    data object NotAuthenticated : AdminUiState   // null session
    data class Error(val message: String) : AdminUiState
}
```

- **StateFlow assertions** use Turbine: e.g. `viewModel.uiState.test { assertEquals(Loading, awaitItem()); assertEquals(Success(...), awaitItem()) }`.
- **Role data** flows from the faked `SessionRepository.currentUser: StateFlow<UserSession?>`;
  the gate combines it with the fetch. Tests flip the session value to drive FR-1/2/3.
- **Stale path:** repository returns cached `AdminAlert`s (Room/`core-data` fake) while a
  refresh fails; ViewModel emits `Success(..., stale = true)` and UI shows `STALE_BANNER`.
- No DataStore writes are exercised (read-only feature). Tests assert prefs are untouched.

## 7. Error Handling & Resilience

The suite explicitly covers the resilience requirements of the unreliable dev backend:

- **Timeout (~20s):** `MockWebServer` enqueues a delayed/no-response body; the
  repository's OkHttp client (test-configured with a short timeout to keep tests fast)
  surfaces `ApiResult.Error` -> `AdminUiState.Error`. Asserted via Turbine.
- **Bounded retry for idempotent GETs:** test that a transient `503` on the GET is
  retried up to the configured bound and then surfaces `Error`; mutating verbs are never
  retried (n/a here since none are issued).
- **401 single-refresh-then-retry** (FR-7), with anti-loop assertion (two 401s do not
  cause a second refresh).
- **Offline:** simulate `IOException`/no connectivity; assert `Error` (or `Stale` if
  cache present) and that the retry control re-issues a GET only.
- **Malformed JSON / unexpected `detail` shape:** assert mapper does not crash and yields
  a human-readable `Error.message`.

## 8. Security & Privacy

- **Role enforcement is the core security assertion** (FR-2/FR-3): tests prove the
  client never fetches admin data nor renders admin content without an admin principal.
  Client-side gating is defense-in-depth; tests also assert the client honors a server
  `403` even if a future bug exposed the entry point.
- **No mutation surface** (FR-4/FR-5) limits blast radius: tests guarantee admin-lite
  cannot change server state from mobile, matching AND-405's scope decision (full admin
  out of scope).
- **No secrets/PII in fixtures or logs:** fixtures use synthetic data; tests assert no
  cookie values, CSRF tokens, or session identifiers are written to logs.
- **CSRF header presence:** the refresh path test asserts `X-CSRF-Token` is sent on the
  `POST /ui/session/refresh` request.
- No plaintext production host is contacted by any test (MockWebServer only).

## 9. Accessibility & i18n

Accessibility/i18n are owned by AND-403/AND-404 for production behavior; this ticket adds
assertions to lock them in:

- **Content descriptions / semantics:** the blocked state, error state, and alert items
  expose non-empty semantics; tests use `onNodeWithContentDescription`/`assertHasClickAction`
  only on the legitimate retry control.
- **String resources:** tests assert visible copy is resolved from `stringResource`
  (no hardcoded literals leaking into the composable under test) by matching resource
  ids/values, supporting localization.
- **Touch target / state announcement** checks are out of scope here beyond presence of
  semantics; deeper a11y audits remain with the feature tickets.

## 10. Telemetry & Logging

- The suite asserts (via a fake analytics sink injected by `core-data`/`core-ui`) that
  an admin screen view event is emitted on `Success` and a gate-denied event on
  `Forbidden`, if AND-403 defines these; otherwise this is a no-op assertion documented
  as owned by AND-403.
- Tests assert **no sensitive payloads** (alert contents beyond ids, user identifiers)
  are passed to the analytics/log sinks.
- Test output uses standard JUnit reporting; flaky-test quarantine via `@Ignore` is
  prohibited for these gating tests (a denied/failing gate test must fail the build).

## 11. Testing Strategy

This section is the heart of the ticket.

**Layers & counts (minimums):**
- `AdminAlertsViewModelTest` — 6 cases (FR-1..FR-3, FR-6 success/empty/error, FR-7).
- `AdminRepositoryTest` — 4 cases (mapping of 3 `detail` shapes + GET-only assertion).
- `AdminAlertsScreenTest` (Compose) — 4 cases (FR-1, FR-2, FR-5, FR-6 retry).
- If AND-404 merged: add parity ViewModel + screen cases for email/SMS dashboards.

**GET-only verification (FR-4):** after each ViewModel/repository flow, drain
`MockWebServer.takeRequest()` and assert every recorded `RecordedRequest.method == "GET"`
for `/ui/admin/*` (refresh `POST` to `/ui/session/refresh` is the only allowed non-GET).

**No-mutation-UI verification (FR-5):** assert absence of nodes:
`composeTestRule.onAllNodesWithTag(AdminTestTags.MUTATION_ACTION).assertCountEquals(0)`
and explicit `onNodeWithText("Delete"/"Resolve"/"Send", ...).assertDoesNotExist()`.

**Determinism:** `MainDispatcherRule` + `StandardTestDispatcher`; no real delays; OkHttp
client built with sub-second timeouts in tests. No reliance on the live dev host.

**Coverage gate:** the `feature-admin` module's admin-lite classes
(`AdminAlertsViewModel`, `AdminRepository`, the gate composable) must reach >= 85% line
coverage (Jacoco verification task), enforced in CI.

**CI commands:**
```
./gradlew :feature-admin:testDebugUnitTest
./gradlew :feature-admin:connectedDebugAndroidTest   # or Robolectric: testDebugUnitTest with robolectric
./gradlew :feature-admin:jacocoTestCoverageVerification
```

## 12. Dependencies & Sequencing

- **Depends on AND-403** (read-only admin alerts/dashboards) — provides the ViewModel,
  screen, repository, route, and role gate under test. This ticket cannot start until
  AND-403's classes exist and stabilize.
- **Soft dependency on AND-404** (email/SMS dashboards): if merged before this ticket,
  its read-only screens are included; otherwise parity tests are owned by AND-404 DoD.
- **Aligns with AND-405** (scope decision): tests encode that no full-admin/mutation
  capability exists on mobile.
- **Consumes `core-testing`** (MainDispatcherRule, MockWebServer builders, Hilt test
  runner) and `core-data` fakes (`FakeSessionRepository`).
- **Blocks:** nothing directly (`blocks: []`); however it is part of the M8 epic E53
  exit criteria for the admin-lite milestone.

## 13. Risks & Open Questions

- **R1 — Role model shape unknown.** AND-403 may model admin via `roles: List<String>`,
  `scopes`, or a boolean. Mitigation: gate tests target the gate's public predicate
  (`isAdmin(session)`), not a specific field; confirm the actual shape from `GET /ui/me`
  / `frontend/src/api/types.ts` before finalizing fixtures. **Open question:** which
  exact claim denotes admin?
- **R2 — Admin endpoint paths unconfirmed.** `/ui/admin/alerts` is assumed; verify
  against `/openapi.json` and AND-403's implementation. Fixtures must match real paths.
- **R3 — Missing `testTag`s.** AND-403 composables may lack tags; mitigation is a small
  `@VisibleForTesting`/tag PR, coordinated with AND-403's owner.
- **R4 — AND-404 timing** (see §12): scope of this suite depends on merge order.
- **R5 — Refresh/CSRF behavior** lives in `core-network`; if the interceptor is shared,
  FR-7 may be better covered there. Open question: does FR-7 belong here or in the
  core-network suite? Default: assert end-to-end here, no duplication of interceptor
  internals.

## 14. Acceptance Criteria

The backlog acceptance is "Pass". Concretely, this ticket is accepted when:

- **AC-1** New test classes compile and run in CI; `:feature-admin:testDebugUnitTest`
  and the Compose UI tests are **green**.
- **AC-2** FR-1/FR-2/FR-3 are each covered by at least one passing test (admin sees
  content; non-admin blocked with no admin GET; null session blocked with no admin GET).
- **AC-3** FR-4 verified: across all admin flows, only `GET` requests hit `/ui/admin/*`
  (asserted on recorded requests).
- **AC-4** FR-5 verified: no mutation affordances exist in admin-lite screens (asserted
  via absent nodes).
- **AC-5** FR-6 verified: Loading/Success/Empty/Error/Stale states each asserted.
- **AC-6** FR-7 verified: single refresh-then-retry on 401, with anti-loop assertion.
- **AC-7** Jacoco coverage for admin-lite classes >= 85%, gate passes in CI.
- **AC-8** No test contacts the live dev host; all network via MockWebServer/fakes.

## 15. Definition of Done

- All §14 acceptance criteria met and verified in CI on branch `android-port`.
- Tests added under `android/feature-admin/src/test` and/or `src/androidTest` using
  `com.testlogon.android.feature.admin.*` packages.
- Any production touch (visibility widening, `testTag`s) is minimal, reviewed, and
  approved by the AND-403 owner; no behavior change.
- New test dependencies are `testImplementation`/`androidTestImplementation` only.
- Coverage gate wired into the module's Gradle verification and CI pipeline.
- Suite is deterministic (no live network, no real sleeps); zero flaky/quarantined
  gating tests.
- PR links AND-403 (and AND-404 if in scope); open questions R1/R2/R5 resolved or
  explicitly deferred with owners noted.
- Code review approved; CI green; merged to `android-port`.
