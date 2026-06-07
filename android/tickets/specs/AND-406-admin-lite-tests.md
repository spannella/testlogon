---
id: AND-406
title: Admin-lite tests
milestone: M8
epic: E53
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
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
   reachable only when the authenticated principal carries an admin role, and are
   hidden or hard-blocked (with a 403/empty state) for non-admins.
   > CORRECTION (verified against `src/lib/adminCapabilities.ts`): the web client does
   > NOT derive admin status from `GET /ui/me` fields. It parses the **JWT `role`
   > claim** of the access token (`getRoleFromAccessToken`) plus an `admin_profile`
   > object (`type: "general" | "scoped"`, `scopes: AdminScope[]`). The admin-lite
   > predicate is `canAccessGeneralAdminControls(token)`: `role === "root"` → allow;
   > else require `role === "admin"` AND `admin_profile.type === "general"`. `GET /ui/me`
   > returns an untyped 200 body (no response schema in OpenAPI) and may surface the
   > same claims, but the gate's source of truth is the token. The Android gate should
   > mirror this; fixtures must drive `role`/`admin_profile`, not a `roles: ["admin"]`
   > / `scopes: ["admin:read"]` list (the latter shapes are fabricated — see §16).
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
- **Auth/role source:** cookie-based session (AND auth stack). The admin predicate in
  the web reference is computed from the **access-token JWT claims** (`role`,
  `admin_profile`) via `src/lib/adminCapabilities.ts`, NOT from `GET /ui/me` fields
  (corrected — see §16). `core-data` exposes a `SessionRepository` /
  `currentUser: StateFlow<UserSession?>`; the Android `UserSession` must therefore carry
  the `role`/`admin_profile` claims so the gate can replicate
  `canAccessGeneralAdminControls`. `GET /ui/me` exists (200, untyped body) but its exact
  fields are unverified.
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

**FR-1 Role-gating (positive).** When `currentUser` satisfies the admin predicate —
i.e. `role == "root"`, OR (`role == "admin"` AND `admin_profile.type == "general"`),
matching the web reference's `canAccessGeneralAdminControls` — the admin entry point is
exposed and the admin dashboard screen renders the metrics content.
(CORRECTED: earlier draft asserted `roles` contains `"admin"` / `scopes` contains
`"admin:read"`; those shapes do not exist in the reference — the real model is the
JWT `role` + `admin_profile`. See §16.)

**FR-2 Role-gating (negative).** When `currentUser` is non-admin (standard user),
the admin entry point is **not** present in navigation, and direct navigation to the
`admin` route resolves to a blocked state (an `AdminUiState.Forbidden` / 403 empty
state), never the data content.

**FR-3 Role-gating (unauthenticated/null).** When `currentUser` is `null` (no
session), the gate routes to login/blocked and never issues admin GETs.

**FR-4 Read-only — no mutating calls.** Across all admin-lite flows, the only HTTP
methods issued are `GET` (plus the single allowed `POST /ui/session/refresh` on a 401,
see FR-7). The suite asserts on recorded `MockWebServer` requests that no
`POST/PUT/PATCH/DELETE` is sent to the **read-only admin paths the Android client
calls** (`/ui/admin/email/dashboard/*`, `/ui/admin/sms/dashboard/*`).
> NOTE (verified against `src/api/endpoints/adminMessagingDashboards.ts`): the
> `/ui/admin/*` namespace is NOT globally GET-only on the backend — it also exposes
> `POST/DELETE /ui/admin/{email,sms}/suppressed`, `POST /ui/admin/sms/send-test`, and
> `PATCH .../notifications/templates/*`. The earlier blanket claim "no non-GET to any
> `/ui/admin/*` path" was therefore imprecise. The assertion must scope to the
> dashboard endpoints the admin-lite feature actually issues, and additionally assert
> the feature NEVER constructs requests to those mutation paths.

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
The suite stubs these responses via `MockWebServer`. The fixtures encode the **real**
read-only admin-lite endpoints (corrected — see §16).

> CORRECTION: there is **no `GET /ui/admin/alerts` endpoint** in the backend OpenAPI or
> the web reference. The earlier draft's alerts payload (`items[].{id,severity,title,
> metric,value,ts}`, `next_cursor`) was fabricated. The admin-lite read-only surface is
> the email/SMS delivery-health dashboards. (General user-facing alerts DO exist at
> `GET /ui/alerts`, but that is not an admin endpoint.)

`GET /ui/admin/email/dashboard/stats?days=7` (admin, 200 → `EmailDashboardStats`):
```json
{
  "sent": 1280, "delivered": 1240, "bounced": 22, "complained": 3, "failed": 15,
  "suppressed": 7, "total": 1280, "delivery_rate": 0.969, "bounce_rate": 0.017,
  "complaint_rate": 0.002, "period_days": 7
}
```

`GET /ui/admin/sms/dashboard/stats?days=7` (admin, 200 → `SmsDashboardStats`):
```json
{
  "sent": 540, "delivered": 511, "failed": 29, "total": 540, "total_segments": 712,
  "estimated_cost_usd": 4.98, "suppressed_numbers": 4, "delivery_rate": 0.946,
  "failure_rate": 0.054, "period_days": 7
}
```

Also in scope (read-only): `GET /ui/admin/{email,sms}/dashboard/timeseries?days=` →
`DashboardTimeseriesOut` (`{channel, period_days, points[]}`) and
`.../email/dashboard/bounce-domains` / `.../sms/dashboard/failure-types?days=&limit=`
→ `DashboardBreakdownOut` (`{channel, dimension, items[].{key,label,count}}`).
(Schema names per the OpenAPI index are the `*Out` variants; the web TS aliases drop the
`Out` suffix.)

Non-admin / insufficient-scope response (403). The real FastAPI `detail` for admin
gating is a **structured object with a `code`** (verified against
`src/api/client.errorMapping.test.ts`), e.g.:
```json
{ "detail": { "code": "role_required_admin_profile_type",
              "required_admin_profile_type": "general", "actual_role": "admin" } }
```
or `{ "detail": { "code": "role_required_scope", "required_scope": "billing_support",
"actual_role": "admin" } }`. (The earlier `{"detail": {"code": "forbidden"}}` was a
plausible placeholder, not the real code.)

FastAPI `detail` variants the error mapper must handle (asserted in repo tests, all
verified against `normalizeErrorDetail` in `src/api/client.ts`):
`{"detail": "string"}`, `{"detail": [{"msg": "..."}]}`, and `{"detail": {"code": "..."}}`
(object form, mapped by `mapAuthorizationError`; unknown codes fall back to the default
message, never leaking the raw object).

401 refresh path (FR-7): first dashboard `GET` -> `401`; client issues
`POST /ui/session/refresh` -> **`200`** (verified: OpenAPI `POST /ui/session/refresh`
declares only a `200` empty-body response; the earlier `204` was wrong); retries the
original `GET` -> `200`. The suite asserts exactly: GET, POST refresh, GET.
> CSRF nuance (verified against `src/api/client.ts`): the generic `api()` wrapper sets
> `X-CSRF-Token` from the `ui_csrf` cookie on **every** request, but the dedicated
> `refreshSession()` helper issues the refresh `POST` with only `method` +
> `credentials: "include"` and does NOT explicitly set `X-CSRF-Token`. So on web the
> CSRF token rides on the cookie for refresh, not an echoed header. The Android client
> may legitimately attach `X-CSRF-Token` to all requests via an interceptor; the test
> should assert the cookie/CSRF is *carried* on refresh, not hard-require the header on
> that specific call (see §8 correction).

When AND-404 is in scope, the same read-only patterns apply to all the
`GET /ui/admin/email/dashboard/*` and `GET /ui/admin/sms/dashboard/*` endpoints above.

## 6. Data & State Management

The tests assert the `AdminUiState` contract from AND-403. NOTE (see §16): the
`Success(val alerts: List<AdminAlert>, ...)` shape below is illustrative of AND-403's
model name; the **actual read-only content is delivery-health dashboard stats**
(`EmailDashboardStats` / `SmsDashboardStats` / timeseries / breakdown), not an "alert"
list — there is no `/ui/admin/alerts` endpoint. The Success payload type must match
whatever AND-403 actually defines for the dashboards; treat `AdminAlert` here as a
placeholder pending AND-403's concrete DTOs.

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
- **CSRF presence on refresh:** the refresh path test asserts the session/CSRF context is
  carried on the `POST /ui/session/refresh` request. NOTE (corrected, see §16): the web
  reference's `refreshSession()` does NOT explicitly attach an `X-CSRF-Token` header — it
  relies on the `ui_csrf` cookie travelling with `credentials: "include"`. If the Android
  network stack attaches `X-CSRF-Token` globally via an interceptor, asserting its
  presence is fine; if it mirrors the web's dedicated refresh path, assert the cookie is
  present instead. Do not over-specify a header the reference does not send.
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

- **R1 — Role model shape — RESOLVED.** Verified against `src/lib/adminCapabilities.ts`:
  admin is denoted by JWT `role` (`"root"`/`"admin"`) + `admin_profile.type`
  (`"general"`/`"scoped"`) and `admin_profile.scopes` (`auth_support` | `billing_support`
  | `content_moderation`). Admin-lite gate = `canAccessGeneralAdminControls`. Gate tests
  still target the public predicate, but fixtures now drive `role`/`admin_profile`, NOT a
  `roles: ["admin"]` / `scopes: ["admin:read"]` list. **Open question reduced to:** does
  the Android `UserSession` source these claims from the JWT (mirroring web) or from
  `GET /ui/me`? Confirm with AND-403's owner.
- **R2 — Admin endpoint paths — RESOLVED.** `/ui/admin/alerts` does NOT exist; corrected
  to the verified read-only dashboards `GET /ui/admin/{email,sms}/dashboard/{stats,
  timeseries,bounce-domains|failure-types}` (OpenAPI index + `adminMessagingDashboards.ts`).
  Fixtures updated in §5 accordingly.
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
- **AC-3** FR-4 verified: across all admin-lite flows, the only methods issued to the
  read-only dashboard paths (`/ui/admin/{email,sms}/dashboard/*`) are `GET`, and the
  feature never issues requests to the namespace's mutation paths
  (`.../suppressed`, `.../send-test`, `.../notifications/templates/*`); the only allowed
  non-GET is `POST /ui/session/refresh` on a 401 (asserted on recorded requests).
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the authoritative source pointer.

1. **Admin role model = JWT `role` + `admin_profile`** (not `roles: ["admin"]` /
   `scopes: ["admin:read"]`). VERDICT: **Corrected.** SOURCE:
   `src/lib/adminCapabilities.ts` (`getRoleFromAccessToken`,
   `getAdminProfileFromAccessToken`, `canAccessGeneralAdminControls`);
   `src/api/endpoints/adminRoles.ts` (`AdminProfileType = "general"|"scoped"`,
   `AdminScope = "auth_support"|"billing_support"|"content_moderation"`).
2. **Admin-lite gate predicate = `role=="root"` OR (`role=="admin"` AND
   `admin_profile.type=="general"`).** VERDICT: **Verified.** SOURCE:
   `src/lib/adminCapabilities.ts: canAccessGeneralAdminControls`.
3. **Role/admin status is derived from the access-token JWT claims, not from
   `GET /ui/me` fields.** VERDICT: **Corrected** (spec §1/§2 said roles "come from
   `GET /ui/me`"). SOURCE: `src/lib/adminCapabilities.ts: parseJwtClaims`.
4. **`GET /ui/me` exists.** VERDICT: **Verified.** SOURCE: OpenAPI
   `GET /ui/me` (op=`ui_me_ui_me_get`). Its 200 response body is **untyped**
   (`schema: {}`) — exact fields are an **Unverified-assumption** (see Open assumptions).
5. **`GET /ui/admin/alerts` endpoint exists.** VERDICT: **Corrected — endpoint does not
   exist.** No such path in OpenAPI index or web reference. SOURCE: absence in
   `reference/openapi.index.txt`; `src/api/endpoints/adminMessagingDashboards.ts` (real
   read-only admin-lite endpoints).
6. **Real read-only admin-lite endpoints.** VERDICT: **Verified/Corrected.** SOURCE:
   OpenAPI `GET /ui/admin/email/dashboard/stats` (resp `EmailDashboardStatsOut`),
   `.../email/dashboard/timeseries` & `.../sms/dashboard/timeseries`
   (`DashboardTimeseriesOut`), `.../email/dashboard/bounce-domains` &
   `.../sms/dashboard/failure-types` (`DashboardBreakdownOut`),
   `GET /ui/admin/sms/dashboard/stats` (`SmsDashboardStatsOut`); web aliases in
   `src/api/endpoints/adminMessagingDashboards.ts`.
7. **Dashboard response field shapes.** VERDICT: **Verified.** SOURCE:
   `src/api/types.ts: EmailDashboardStats` (sent/delivered/bounced/complained/failed/
   suppressed/total/delivery_rate/bounce_rate/complaint_rate/period_days),
   `SmsDashboardStats`, `DashboardTimeseries`{channel,period_days,points[]},
   `DashboardBreakdown`{channel,dimension,items[].{key,label,count}}.
8. **`/ui/admin/*` is globally GET-only (no mutations).** VERDICT: **Corrected — the
   namespace contains mutations.** SOURCE: OpenAPI
   `POST /ui/admin/email/suppressed`, `POST /ui/admin/sms/suppressed`;
   `src/api/endpoints/adminMessagingDashboards.ts` (`addEmailSuppression` POST,
   `removeEmailSuppression` DELETE, `sendTestSms` POST `.../sms/send-test`,
   `updateNotificationTemplate` PATCH). FR-4/AC-3 rescoped to the dashboard GET paths.
9. **The web email/SMS admin page is fully read-only.** VERDICT: **Corrected —
   partially false.** SOURCE: `src/pages/admin/EmailSmsDashboardPage.tsx` includes a
   Templates tab and `MessagingTemplatesPanel`/suppression controls (mutations). The
   Android admin-lite port is a deliberate **read-only subset**; "parity" is parity with
   the dashboard *reads* only, not the full web page.
10. **401 → single `POST /ui/session/refresh` → one retry of original GET; second 401
    does not loop (logs out).** VERDICT: **Verified.** SOURCE: `src/api/client.ts`
    (`api()` 401 branch, `refreshPromise`, single retry, `logout("session_expired")`).
11. **`POST /ui/session/refresh` returns `204`.** VERDICT: **Corrected → `200`.**
    SOURCE: OpenAPI `POST /ui/session/refresh` declares only a `200` (empty schema)
    response; `src/api/client.ts: refreshSession` treats any `res.ok` as success.
12. **CSRF: `X-CSRF-Token` is taken from the `ui_csrf` cookie.** VERDICT: **Verified.**
    SOURCE: `src/api/client.ts` lines ~167-171 (`getCookie("ui_csrf")` →
    `headers.set("X-CSRF-Token", csrf)` in the generic `api()` wrapper).
13. **The refresh request echoes `X-CSRF-Token` as a header.** VERDICT: **Corrected —
    not on the refresh call.** SOURCE: `src/api/client.ts: refreshSession` issues the
    `POST` with only `method` + `credentials:"include"`; CSRF rides on the cookie. §5/§8
    softened accordingly.
14. **FastAPI 403 admin `detail` is a structured object with a `code`.** VERDICT:
    **Verified (and concrete codes corrected).** SOURCE:
    `src/api/client.errorMapping.test.ts` (`role_required_scope`,
    `role_required_admin_profile_type`, `helpdesk_*`); `src/api/client.ts:
    mapAuthorizationError`. (Spec's placeholder `{"code":"forbidden"}` replaced.)
15. **Error mapper handles `detail` as string, array-of-`{msg}`, and object-with-`code`,
    falling back to a default message for unknown shapes (no raw-object leak).**
    VERDICT: **Verified.** SOURCE: `src/api/client.ts: normalizeErrorDetail`
    (string / `Array.isArray` / `mapAuthorizationError` / `msg` / fallback);
    `src/api/client.errorMapping.test.ts` ("does not leak raw object payload").
16. **General user alerts at `GET /ui/alerts` (distinct from admin).** VERDICT:
    **Verified** (context only; not used by this ticket). SOURCE: OpenAPI
    `GET /ui/alerts` (op=`list_alerts_ui_alerts_get`).
17. **Test frameworks (JUnit4, kotlinx-coroutines-test, Turbine, MockK, OkHttp
    MockWebServer, Compose `createComposeRule`/`createAndroidComposeRule`, Robolectric,
    Hilt test runner, Jacoco).** VERDICT: **Unverified-assumption** (framework choices,
    no repo to confirm). SOURCE (framework ref): MockWebServer
    https://github.com/square/okhttp/tree/master/mockwebserver ; Compose testing
    https://developer.android.com/develop/ui/compose/testing ; Robolectric
    https://robolectric.org/ ; Turbine https://github.com/cashapp/turbine .

### Corrections made

- §1/§2/§3 FR-1: admin role model corrected from `roles`/`scopes` strings to the JWT
  `role` + `admin_profile` model (`canAccessGeneralAdminControls`); role source corrected
  to the access-token JWT, not `GET /ui/me` fields. (Claims 1-3)
- §5: removed the fabricated `GET /ui/admin/alerts` contract and replaced it with the
  real `EmailDashboardStats`/`SmsDashboardStats`/timeseries/breakdown dashboard endpoints
  and shapes. (Claims 5-7)
- §5/§6: noted that the Success content is dashboard stats, not an "alert" list;
  `AdminAlert` treated as a placeholder for AND-403's real DTO. (Claims 5-7, 9)
- §3 FR-4 / §14 AC-3: rescoped "no non-GET to any `/ui/admin/*`" to the dashboard GET
  paths the feature calls, because the namespace contains mutations. (Claim 8)
- §5: `POST /ui/session/refresh` response corrected `204` → `200`. (Claim 11)
- §5/§8: CSRF claim corrected — the web refresh call does not echo `X-CSRF-Token`; it
  relies on the `ui_csrf` cookie. (Claims 12-13)
- §5: 403 `detail` example corrected from `{"code":"forbidden"}` to the real
  `role_required_admin_profile_type` / `role_required_scope` object shapes. (Claim 14)
- §13: R1 and R2 marked RESOLVED with the verified facts.

### Open assumptions

- **`GET /ui/me` response field names** — its 200 body is untyped in OpenAPI
  (`schema: {}`); we cannot confirm whether it surfaces `role`/`admin_profile`. The web
  gate uses the JWT, so this does not block the gate, but any fixture modelling `/ui/me`
  fields is unverified. (Why: no response schema; no `/ui/me` consumer found pinning the
  shape.)
- **AND-403's concrete Android types** (`AdminUiState`, `AdminAlertsViewModel`,
  `AdminRepository`, `AdminRoute`, gate composable, `testTag`s) — AND-403 source is not
  in this repo snapshot; their exact signatures are assumed. (Why: dependency not yet
  materialised; R3.)
- **`UserSession` claim source on Android** — whether the Android session carries the
  JWT claims or re-fetches `/ui/me` is an AND-403 decision (R1 residual). (Why: AND-403
  not available.)
- **Whether AND-404 (email/SMS dashboards) has merged** — determines suite scope (R4).
- **All test-framework/tooling selections** (claim 17) — no Android module in the
  reference to confirm; standard AOSP/Jetpack tooling assumed.

## 17. Test Plan

Test targets: **JVM** = JVM unit/Robolectric (local, no device); **emu35** = headless
emulator AVD `test35` (x86_64, API 35); **A15** = physical Samsung Galaxy A15 5G
(SM-A156U, API 34, arm64-v8a). This is a pure-software, network-faked test ticket: no
camera/biometric/FCM/WebRTC/Telecom behavior is exercised, so the **physical device is
not required**; instrumented cases run on **emu35** in CI. One case (TC-AND-406-13) is
flagged to also run on **A15** purely for arm64-vs-x86 / API-34-vs-35 ABI sanity.

- **TC-AND-406-01 — Admin user loads dashboard → Success**
  Type: unit (ViewModel + MockWebServer) · Target: JVM ·
  Preconditions: `FakeSessionRepository.currentUser` = session with `role="admin"`,
  `admin_profile.type="general"`; MockWebServer enqueues `200` `EmailDashboardStats`.
  Steps: construct ViewModel; collect `uiState` with Turbine; trigger load.
  Expected: emits `Loading` → `Success(stats, stale=false)`; recorded request is
  `GET /ui/admin/email/dashboard/stats`. Traces: AC-2, AC-5.
- **TC-AND-406-02 — Root user is admin-allowed**
  Type: unit · Target: JVM · Preconditions: session `role="root"` (no admin_profile).
  Steps: evaluate the gate predicate / load.
  Expected: predicate true; dashboard GET issued; `Success`. Traces: AC-2.
- **TC-AND-406-03 — Non-admin (standard user) blocked, no admin GET**
  Type: unit · Target: JVM · Preconditions: session `role="user"` (or admin with
  `admin_profile.type="scoped"` lacking general). Steps: navigate/load admin route.
  Expected: `uiState == Forbidden`; **zero** requests recorded by MockWebServer
  (`takeRequest` times out / count 0). Traces: AC-2, AC-3.
- **TC-AND-406-04 — Null session blocked, no admin GET**
  Type: unit · Target: JVM · Preconditions: `currentUser = null`. Steps: load.
  Expected: `uiState == NotAuthenticated`; no admin GET issued. Traces: AC-2, AC-3.
- **TC-AND-406-05 — Server 403 honored even if entry point leaked**
  Type: contract/MockWebServer · Target: JVM · Preconditions: admin session but server
  returns `403` with `{"detail":{"code":"role_required_admin_profile_type",
  "required_admin_profile_type":"general","actual_role":"admin"}}`. Steps: load.
  Expected: state becomes `Forbidden`/`Error` with a mapped, non-raw message; no retry
  loop; no content rendered. Traces: AC-2, AC-4.
- **TC-AND-406-06 — Empty dashboard payload → Empty**
  Type: unit · Target: JVM · Preconditions: `200` with all-zero stats (or empty
  timeseries `points: []`). Steps: load.
  Expected: `Loading` → `Empty`. Traces: AC-5.
- **TC-AND-406-07 — GET-only across all admin-lite flows (read-only)**
  Type: contract/MockWebServer · Target: JVM · Preconditions: admin session; drive every
  dashboard fetch (email+sms stats, timeseries, breakdown). Steps: run all flows; drain
  recorded requests. Expected: every recorded method to `/ui/admin/*/dashboard/*` is
  `GET`; no request is ever made to `.../suppressed`, `.../send-test`, or
  `.../notifications/templates/*`. Traces: AC-3.
- **TC-AND-406-08 — Repository maps the three `detail` shapes**
  Type: unit · Target: JVM · Preconditions: MockWebServer returns, in turn, `403`
  `{"detail":"plain string"}`, `422` `{"detail":[{"msg":"field required"}]}`, and `403`
  object `{"detail":{"code":"role_required_scope","required_scope":"billing_support"}}`.
  Steps: call repository per shape. Expected: each yields `ApiResult.Error` with a
  human-readable message (string passthrough; array → joined msgs; object → mapped/coded
  or default); unknown object never leaks raw JSON. Traces: AC-5.
- **TC-AND-406-09 — 401 → single refresh (200) → one retry; anti-loop**
  Type: contract/MockWebServer · Target: JVM · Preconditions: admin session; enqueue
  GET→`401`, `POST /ui/session/refresh`→`200`, GET→`200`. Steps: load; inspect recorded
  sequence. Expected: exactly `GET`, `POST /ui/session/refresh`, `GET`; `Success`. Then a
  second variant where the retried GET is also `401`: expected exactly ONE refresh, then
  an auth `Error` (no second refresh, no loop). Traces: AC-6.
- **TC-AND-406-10 — CSRF/session carried on refresh**
  Type: contract/MockWebServer · Target: JVM · Preconditions: `ui_csrf` cookie present in
  the client cookie jar; force a 401→refresh. Steps: capture the recorded
  `POST /ui/session/refresh`. Expected: the request carries the CSRF context (cookie
  present; and `X-CSRF-Token` header present **iff** the Android stack attaches it
  globally — do not require it on the dedicated refresh call per §16 claim 13).
  Traces: AC-6, AC-8.
- **TC-AND-406-11 — Timeout / offline → Error (or Stale if cache)**
  Type: contract/MockWebServer · Target: JVM · Preconditions: OkHttp client built with
  sub-second timeout; MockWebServer enqueues a no-response/`SocketPolicy.NO_RESPONSE`
  body (and a separate `IOException`/disconnect case). Steps: load with no cache, then
  with a seeded cache. Expected: no-cache → `Error`; cache present → `Success(stale=true)`
  with `STALE_BANNER`; the only outbound method remains `GET`. Traces: AC-5, AC-8.
- **TC-AND-406-12 — Transient 503 retried for idempotent GET then Error**
  Type: contract/MockWebServer · Target: JVM · Preconditions: enqueue N×`503` exceeding
  the retry bound. Steps: load. Expected: GET retried up to the configured bound then
  surfaces `Error`; no mutating verb ever retried (none issued). Traces: AC-5, AC-8.
- **TC-AND-406-13 — Admin dashboard renders content (Compose)**
  Type: Compose-UI / instrumented · Target: **emu35** (CI) AND **A15** (arm64/API-34
  ABI sanity) · Preconditions: admin `AdminUiState.Success(stats)`. Steps: set content;
  `onNodeWithTag(AdminTestTags.ALERTS_LIST)` (dashboard content tag) asserted displayed.
  Expected: stats content visible; `BLOCKED_STATE` does not exist. MUST run on A15 at
  least once to catch arm64-vs-x86 / API-34-vs-35 rendering differences; routine CI runs
  on emu35. Traces: AC-1, AC-2.
- **TC-AND-406-14 — Forbidden state renders block, no content (Compose)**
  Type: Compose-UI · Target: emu35 · Preconditions: `AdminUiState.Forbidden`. Steps: set
  content. Expected: `BLOCKED_STATE` displayed; dashboard content tag does not exist.
  Traces: AC-2, AC-4.
- **TC-AND-406-15 — No mutation affordances in admin-lite screen (Compose, security)**
  Type: Compose-UI · Target: emu35 · Preconditions: `Success` state. Steps: assert
  `onAllNodesWithTag(AdminTestTags.MUTATION_ACTION).assertCountEquals(0)`, and
  `onNodeWithText("Delete"|"Resolve"|"Send"|"Resend"|"Acknowledge", substring=true)
  .assertDoesNotExist()`; the only clickable control is the GET retry. Expected: no
  mutation node exists; retry has a click action that re-issues a `GET`. Traces: AC-4.
- **TC-AND-406-16 — Error state retry re-issues a GET (Compose)**
  Type: Compose-UI + MockWebServer · Target: emu35 · Preconditions: `Error` state, then
  enqueue `200` for the retry. Steps: click `ERROR_RETRY`. Expected: a single new
  `GET` recorded (no POST/PUT/PATCH/DELETE); state transitions to `Success`.
  Traces: AC-4, AC-5.
- **TC-AND-406-17 — Accessibility semantics on blocked/error/content (Compose, a11y)**
  Type: Compose-UI · Target: emu35 · Preconditions: render each of `Forbidden`, `Error`,
  `Success`. Steps: assert non-empty content descriptions/semantics on the blocked state,
  error state, and dashboard items; assert visible copy resolves via `stringResource`
  (resource id/value match, no hardcoded literal); assert `assertHasClickAction` only on
  the legitimate retry control. Expected: semantics present; localized strings used.
  Traces: AC-4.
- **TC-AND-406-18 — No live host / no secret leakage (security)**
  Type: unit + integration · Target: JVM · Preconditions: full suite run. Steps: assert
  no test resolves/contacts `18.222.237.167` (all base URLs point at MockWebServer);
  assert injected fake analytics/log sink received no cookie values, CSRF tokens, or
  session identifiers, and only synthetic fixture data. Expected: zero live-host
  contact; zero secret/PII in logs. Traces: AC-8.

### Coverage matrix (section-14 AC → covering TCs)

- **AC-1** (compiles + suite green): TC-13, TC-14 (and implicitly all — compilation gate).
- **AC-2** (FR-1/2/3 gating): TC-01, TC-02, TC-03, TC-04, TC-05, TC-13, TC-14.
- **AC-3** (GET-only to admin paths): TC-01, TC-03, TC-04, TC-07.
- **AC-4** (no mutation affordances): TC-05, TC-14, TC-15, TC-16, TC-17.
- **AC-5** (Loading/Success/Empty/Error/Stale): TC-01, TC-06, TC-08, TC-11, TC-12, TC-16.
- **AC-6** (single refresh-then-retry + anti-loop): TC-09, TC-10.
- **AC-7** (Jacoco ≥85%): no single TC — emergent from TC-01..TC-18 breadth; enforced by
  `:feature-admin:jacocoTestCoverageVerification` (see §11). Add targeted cases if a class
  falls below the gate.
- **AC-8** (no live host; MockWebServer/fakes only): TC-10, TC-11, TC-12, TC-18.
