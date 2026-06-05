---
id: AND-242
title: Subscriptions/fan-club tests
milestone: M5
epic: E32
priority: P2
size: M
status: draft
depends_on: [AND-241]
blocks: []
---

# AND-242 — Subscriptions/fan-club tests

## 1. Overview & Goal

This ticket delivers the **automated test suite** for the Subscriptions and Fan-club
feature of the TestLogon Android app. It is a pure test ticket: it adds **repository
(integration-style) tests** and **UI (Compose instrumentation/Robolectric) tests** that
together pin the behavior produced by the upstream feature tickets — the
`SubscriptionsRepository`/`SubscriptionsApi` + DTOs (AND-234), the ViewModels and
`EntitlementResolver` (AND-241), and the Compose screens that render that state (the
subscriptions/fan-club screen tickets AND-235, AND-236, AND-237, AND-240).

The backlog scope is "Repo + UI tests" with acceptance "Pass." Concretely, this means:

- **Repo tests** that exercise `SubscriptionsRepository` against a `MockWebServer` with
  recorded FastAPI JSON fixtures, asserting correct request construction (path, query,
  `X-CSRF-Token` header, cookie), DTO→domain mapping, `ApiResult` success/failure mapping,
  timeout/retry behavior for idempotent GETs, and the 401→refresh→retry path.
- **UI tests** that exercise the Compose subscriptions/fan-club screens with a fake
  ViewModel/state (or real ViewModel + fake repository) over `createComposeRule`,
  asserting that `Loading`/`Content`/`Empty`/`Error`/`isStale` states render correctly,
  that entitlement-driven CTAs (`SUBSCRIBE`/`UPGRADE`/`CURRENT`/`MANAGE`) appear, and that
  user actions emit the right callbacks/navigation events.

Success means the suite compiles, runs deterministically (no live network, fixed clock,
controlled dispatchers), covers the behaviors below, and **passes green** in CI under the
project's Gradle tasks. This ticket adds **no production code** beyond test sources and
shared test fixtures/fakes promoted into `core-testing`.

## 2. Context & References

- **Repo:** `spannella/testlogon`, Android app under `android/`, branch `android-port`.
- **Namespace / applicationId base:** `com.testlogon.android`.
- **Module under test:** `feature-subscriptions`
  (`com.testlogon.android.feature.subscriptions.*`), plus the repository surface it
  consumes from `core-network`/`core-data` (`SubscriptionsRepository`, `SubscriptionsApi`,
  `core-model` DTOs). Shared fakes/fixtures live in `core-testing`.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow,
  Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15, Room 2.6, DataStore. minSdk 24,
  compile/targetSdk 35, JDK 17, Gradle 8.9, AGP 8.7.3.
- **Test stack:** JUnit4, `kotlinx-coroutines-test` (`StandardTestDispatcher`,
  `runTest`), Turbine (`StateFlow`/flow assertions), `MockWebServer` (OkHttp), Truth or
  AssertJ assertions, MockK for fakes, **Robolectric** for fast JVM-side Compose UI tests,
  and Compose UI test (`androidx.compose.ui.test`,
  `createComposeRule`/`createAndroidComposeRule`). Optional `:connectedDebugAndroidTest`
  on-device run for the same Compose tests.
- **Dependencies:** AND-241 (ViewModels + `EntitlementResolver` + `Fake...` fakes) is the
  direct dependency; AND-234 supplies the repository/DTOs the repo tests target. The
  screen tickets (AND-235 browse, AND-236 subscribe/checkout entry, AND-237 manage/cancel,
  AND-240 fan-club tiers/members) own the Composables these UI tests drive. Where a screen
  is not yet merged, this ticket tests the screens that exist and leaves clearly-marked
  `@Ignore("blocked by AND-2xx")` placeholders so the suite stays green.
- **Web reference:** `frontend/src/api/endpoints/subscriptions.ts` and
  `frontend/src/api/types.ts` are the source of truth for the JSON fixtures used by the
  repo tests.
- **Backend:** FastAPI + DynamoDB; dev host `http://18.222.237.167:8000` is plaintext and
  unreliable. **No test in this ticket hits the live host.** All HTTP goes through
  `MockWebServer`; the unreliable host motivates explicit timeout/stale-path tests.

## 3. Functional Requirements

FR-1 **Repository request contract tests.** Verify each repository method issues the
correct HTTP request: method, path, query params, `X-CSRF-Token` header echoed from the
`ui_csrf` cookie, and that the persistent cookie jar attaches session cookies.

FR-2 **Repository mapping tests.** Verify DTO→domain mapping from recorded JSON fixtures
for tiers, subscriptions, and fan-club tiers, including status enums (`ACTIVE`,
`PAST_DUE`, `CANCELED`, `EXPIRED`), `price_cents`/`currency`/`period`, perks, and
`renews_at` parsing to `Instant`.

FR-3 **Repository error/`ApiResult` tests.** Verify FastAPI `detail` shapes
(`string | [{msg}] | {code,...}`), HTTP `401`/`404`/`5xx`, timeouts, and malformed JSON
all map to the correct `ApiResult.Failure(AppError)` variant.

FR-4 **Resilience tests.** Verify ~20s timeout enforcement, bounded-backoff retry on
**idempotent GETs only**, no retry on non-GET, and the 401→`POST /ui/session/refresh`
(once)→retry path including the "refresh also fails" terminal case.

FR-5 **EntitlementResolver coverage backstop.** Re-assert (or extend) the
`EntitlementResolver` verdict matrix at the suite level so entitlement behavior is pinned
even if AND-241's unit tests are refactored, including fail-closed `Unknown`.

FR-6 **UI state rendering tests.** For each subscriptions/fan-club screen, verify that
`Loading` shows a progress indicator, `Content` shows the list, `Empty` shows the
empty-state copy, `Error` shows the message + retry affordance (when `retryable`), and
`isStale`/`isRefreshing` show the stale banner / refresh indicator.

FR-7 **UI entitlement/CTA tests.** Verify tier rows render the correct CTA per
entitlement (`SUBSCRIBE`/`UPGRADE`/`CURRENT`/`MANAGE`) and that premium-gated affordances
are hidden/locked when entitlement resolves to `Denied`/`RequiresUpgrade`/`Unknown`.

FR-8 **UI interaction tests.** Verify clicking a CTA, pull-to-refresh, and retry invoke
the expected ViewModel function / navigation callback, asserted via fakes / recorded
events.

FR-9 **Determinism.** All tests run with a `TestDispatcher`, a fixed `Clock`, and
`MockWebServer` — no wall-clock sleeps, no live network, stable across runs.

FR-10 **CI integration.** The suite runs under documented Gradle tasks and is green; it
does not flake on the unreliable dev host because it never contacts it.

## 4. Technical Design

Test sources live under the feature and core-testing modules:

```
feature-subscriptions/
  src/test/kotlin/com/testlogon/android/feature/subscriptions/
    repository/SubscriptionsRepositoryTest.kt        // MockWebServer repo tests
    repository/SubscriptionsErrorMappingTest.kt
    repository/SubscriptionsRefreshRetryTest.kt
    entitlement/EntitlementResolverMatrixTest.kt
    viewmodel/SubscriptionTiersViewModelTest.kt       // extends AND-241 coverage
    ui/SubscriptionTiersScreenTest.kt                 // Robolectric Compose
    ui/MySubscriptionsScreenTest.kt
    ui/FanClubScreenTest.kt
  src/test/resources/fixtures/                        // recorded JSON
    tiers_ok.json, subscriptions_me.json, fanclub_tiers_ok.json,
    detail_string.json, detail_list.json, detail_obj.json
core-testing/
  src/main/kotlin/com/testlogon/android/core/testing/
    FakeSubscriptionsRepository.kt   // promoted from AND-241 if not already
    MockWebServerRule.kt
    MainDispatcherRule.kt
    FixedClock.kt
    ComposeStateFakes.kt             // canned UiState builders
```

**Repo test harness.** A JUnit `TestRule` wraps `MockWebServer`, builds the real OkHttp
client (with the project cookie jar + CSRF interceptor) and Retrofit/Moshi exactly as the
production DI module does, pointed at `mockWebServer.url("/")`:

```kotlin
class MockWebServerRule : TestWatcher() {
    val server = MockWebServer()
    fun retrofit(moshi: Moshi, client: OkHttpClient): Retrofit =
        Retrofit.Builder()
            .baseUrl(server.url("/"))
            .addConverterFactory(MoshiConverterFactory.create(moshi))
            .client(client).build()
    override fun starting(d: Description) = server.start()
    override fun finished(d: Description) = server.shutdown()
}
```

```kotlin
@RunWith(JUnit4::class)
class SubscriptionsRepositoryTest {
    @get:Rule val mws = MockWebServerRule()
    @get:Rule val main = MainDispatcherRule()

    private lateinit var repo: SubscriptionsRepository

    @Before fun setUp() {
        val client = testOkHttp(cookieJar = TestCookieJar(), csrf = "csrf-abc")
        val api = mws.retrofit(testMoshi(), client).create(SubscriptionsApi::class.java)
        repo = SubscriptionsRepositoryImpl(api, ioDispatcher = main.dispatcher,
            clock = FixedClock("2026-06-05T00:00:00Z"))
    }

    @Test fun getTiers_success_mapsDtoToDomain() = runTest {
        mws.server.enqueue(MockResponse().setResponseCode(200)
            .setBody(readFixture("tiers_ok.json")))
        val result = repo.getTiers("creator_42")
        val req = mws.server.takeRequest()
        assertThat(req.path).isEqualTo("/ui/subscriptions/tiers?creator_id=creator_42")
        assertThat(req.getHeader("X-CSRF-Token")).isEqualTo("csrf-abc")
        assertThat(result).isInstanceOf(ApiResult.Success::class.java)
        val tiers = (result as ApiResult.Success).data
        assertThat(tiers.single().id).isEqualTo("tier_gold")
        assertThat(tiers.single().priceCents).isEqualTo(999)
    }
}
```

**UI test harness.** Compose tests run on Robolectric (`@Config(sdk=[34])`,
`RobolectricTestRunner`) with `createComposeRule()`, driving the **stateful** screen
composable backed by a real ViewModel + `FakeSubscriptionsRepository`, or the **stateless**
screen composable fed a canned `UiState`. Nodes are located by stable `testTag`s the
screen tickets must expose (see §6) and by text resolved from `R.string`.

```kotlin
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class SubscriptionTiersScreenTest {
    @get:Rule val compose = createComposeRule()

    @Test fun content_rendersTierRows_andCorrectCta() {
        val state = subscriptionTiersContent(
            rows = listOf(tierRow("tier_gold", owned = true, cta = TierCta.CURRENT),
                          tierRow("tier_plat", owned = false, cta = TierCta.UPGRADE)))
        compose.setContent { TestLogonTheme {
            SubscriptionTiersScreen(state = state, onCta = {}, onRefresh = {}, onRetry = {})
        } }
        compose.onNodeWithTag("tier_row_tier_gold").assertIsDisplayed()
        compose.onNodeWithTag("cta_tier_gold").assertTextEquals("Current plan")
        compose.onNodeWithTag("cta_tier_plat").assertTextEquals("Upgrade")
    }

    @Test fun error_retryable_showsRetry_andInvokesCallback() {
        var retried = false
        compose.setContent { TestLogonTheme {
            SubscriptionTiersScreen(
                state = subscriptionTiersError("Couldn't reach the server.", retryable = true),
                onCta = {}, onRefresh = {}, onRetry = { retried = true })
        } }
        compose.onNodeWithText("Couldn't reach the server.").assertIsDisplayed()
        compose.onNodeWithTag("retry_button").performClick()
        assertThat(retried).isTrue()
    }
}
```

**Determinism controls.** `MainDispatcherRule` swaps `Dispatchers.Main` with a
`StandardTestDispatcher`; the repository receives that dispatcher as its `@IoDispatcher`.
Time is injected via a `FixedClock` so `renews_at`-relative logic and timeout assertions
are reproducible (timeout assertions use `MockWebServer`'s `setBodyDelay` +
virtual-time advance rather than real sleeps).

## 5. API Contract

This ticket defines **no new endpoints**; it asserts the existing contract owned by
AND-234. The repo tests exercise these upstream paths through `MockWebServer`:

- `GET /ui/subscriptions/tiers?creator_id={id}` → `200` `{ "tiers": [...] }`.
- `GET /ui/subscriptions/me` → `200` `{ "subscriptions": [...] }`.
- `GET /ui/fan-club/{creatorId}/tiers` → `200` `{ "tiers": [...] }` (fan-club shape).
- `POST /ui/session/refresh` → `200` (sets refreshed cookies) used by the 401-retry test.

Fixtures (recorded from the web reference shapes; mirror `frontend/src/api/types.ts`):

```json
// tiers_ok.json
{ "tiers": [
  { "id": "tier_gold", "name": "Gold", "price_cents": 999, "currency": "USD",
    "period": "MONTH", "perks": ["hd", "chat"] },
  { "id": "tier_plat", "name": "Platinum", "price_cents": 1999, "currency": "USD",
    "period": "MONTH", "perks": ["hd", "chat", "vault"] }
] }
```

```json
// subscriptions_me.json
{ "subscriptions": [
  { "id": "sub_123", "tier_id": "tier_gold", "status": "ACTIVE",
    "renews_at": "2026-07-01T00:00:00Z", "auto_renew": true }
] }
```

FastAPI error fixtures the error-mapping test enumerates:

```json
{ "detail": "Subscription not found" }                       // detail_string.json
{ "detail": [ { "loc": ["query","creator_id"], "msg": "field required" } ] } // detail_list.json
{ "detail": { "code": "TIER_GONE", "message": "Tier removed" } }            // detail_obj.json
```

Each is enqueued with the matching status (`404`, `422`, `409`) and the test asserts the
resulting `AppError`/`ApiResult.Failure` variant and that the human message is taken from
the right field (top-level string, first `msg`, or `code`/`message`). N/A: no production
DTO/endpoint is introduced here.

## 6. Data & State Management

Tests assert state, they do not own it. The relevant artifacts:

- **UiState builders** (`ComposeStateFakes.kt`, in `core-testing`): pure factory functions
  (`subscriptionTiersContent(...)`, `subscriptionTiersError(...)`,
  `mySubscriptionsEmpty()`, `fanClubContent(...)`) returning the AND-241 `UiState` data
  classes so UI tests don't depend on a live ViewModel.
- **`FakeSubscriptionsRepository`** (promoted/shared from AND-241): returns scripted
  `ApiResult` sequences keyed per method (success, timeout, 401, 5xx, empty, slow) so
  ViewModel-through-screen tests can drive every branch.
- **Stable `testTag` contract** (this ticket's primary cross-team requirement on the screen
  tickets): the UI tests require these tags, which the screen tickets MUST apply —
  `tiers_screen`, `tier_row_{tierId}`, `cta_{tierId}`, `subscriptions_list`,
  `subscription_row_{subId}`, `fanclub_screen`, `loading_indicator`, `empty_state`,
  `error_state`, `retry_button`, `stale_banner`, `refresh_indicator`. If a tag is missing,
  the failing UI test is the signal; tests are written against this agreed contract.
- **No persistence under test by this ticket directly:** any Room/DataStore cache lives in
  AND-234; if AND-234 caches, a repo test asserts the cache-hit path returns
  `isStale = true`/cached data on a subsequent failure, otherwise that case is `@Ignore`d
  with a reference to the owning ticket.

State assertions use Turbine for `StateFlow` sequences in ViewModel-level tests and
`compose.onNode...().assert...()` for rendered state. A `FixedClock` keeps any
date-relative UI (e.g., "renews in N days") deterministic.

## 7. Error Handling & Resilience

This is a focus area, since the dev host is unreliable. Tests explicitly cover:

- **Timeout:** enqueue a response with `setBodyDelay(25, SECONDS)` against a 20s client
  timeout (driven via virtual time) → assert `ApiResult.Failure(AppError.Timeout)` and,
  in the UI, an `error_state` with `retryable = true`.
- **Bounded-backoff retry (GET only):** enqueue `503, 503, 200` for an idempotent GET →
  assert exactly the configured number of attempts and a final `Success`; assert the
  `takeRequest()` count matches the retry budget. For a non-GET (e.g., a cancel mutation
  if present from AND-237), enqueue `503` → assert **no retry** (single request).
- **401 → refresh → retry:** enqueue `401` for the GET, then `200` for
  `POST /ui/session/refresh`, then `200` for the retried GET → assert the final `Success`
  and that refresh was called **once**. Separately enqueue `401` then a failing refresh →
  assert `ApiResult.Failure(AppError.Auth)` and no infinite loop.
- **Malformed JSON / wrong shape:** enqueue invalid body → assert
  `AppError.Unknown`/parse failure, never a crash.
- **Stale-while-revalidate (UI):** render `Content` then a failed `refresh()` →
  assert prior rows remain displayed and `stale_banner` appears (content not discarded).
- **Partial failure (UI):** tiers success + subs failure → assert tier rows render with
  `SUBSCRIBE` CTA and `stale_banner` visible (entitlement unknown), no blocking error.

All timing uses `TestDispatcher` virtual time / `MockWebServer` delays; **no real
sleeps**, so resilience tests stay fast and deterministic.

## 8. Security & Privacy

- **CSRF assertion:** repo tests assert the `X-CSRF-Token` header is present and equals
  the `ui_csrf` cookie value on every state-changing request and on GETs per the project
  contract; a negative test asserts behavior when the cookie is absent.
- **Cookie jar:** a `TestCookieJar` verifies session cookies set by an earlier
  (`Set-Cookie`) response are attached to subsequent requests, proving the persistent jar
  wiring without persisting anything to disk in tests.
- **No real credentials/secrets** appear in fixtures or test code; fixtures use synthetic
  ids (`creator_42`, `sub_123`) and a dummy CSRF token.
- **No live host:** because nothing contacts `18.222.237.167`, no real session data,
  cookies, or PII is exercised; the plaintext-HTTP risk is irrelevant in CI.
- **Fail-closed verification:** §11's entitlement matrix includes the assertion that
  `Unknown`/error resolves to denied so a security regression (network failure granting
  access) is caught by a test, not in production.
- No PII is written to logs by the tested code; a test asserts the `Logger` fake receives
  no subscription contents/identity on the failure path (see §10).

## 9. Accessibility & i18n

- **A11y assertions in UI tests:** key interactive nodes (CTA buttons, retry,
  pull-to-refresh) are asserted to have non-empty content descriptions / merged semantics
  and to be reachable via `onNodeWithContentDescription`; tappable targets are asserted
  `assertHasClickAction()`. A focus/semantics smoke test verifies the error state exposes
  its message to the semantics tree (screen-reader visible).
- **i18n:** UI tests resolve expected text through `context.getString(R.string.…)` rather
  than hardcoded literals, proving the screens use resources and that no string is
  hardcoded. A test runs at least one screen under a non-default locale
  (`@Config(qualifiers = "fr")`) to assert strings resolve from resources (not that
  translations exist, but that the lookup path is locale-driven) and that currency/date
  formatting uses locale-aware formatters (raw `price_cents`/`currency` formatted at
  render).
- These are test-side assertions; the actual contrast/touch-target compliance is owned by
  the screen tickets — this ticket's UI tests are where regressions surface.

## 10. Telemetry & Logging

- Tests inject **fake** `Analytics` and `Logger` (from `core-testing`) and assert
  emitted events on the relevant paths: `subscriptions_tiers_viewed { creatorId, tierCount }`
  on successful content, `subscriptions_load_failed { errorType, retryable }` on the error
  path, `subscription_cta_clicked { tierId, cta }` on CTA tap, and
  `entitlement_resolved { key, verdict }` (sampled) — asserting payload fields and that
  **no user id / subscription contents** are included.
- A logging test asserts the `Logger` fake records `WARN` on `Failure`/stale fallback and
  that no log entry contains subscription payloads or identity (privacy backstop for §8).
- Telemetry assertions are exact-match against the fake's recorded list; tests fail if a
  new event is added without being covered, keeping the analytics contract pinned.
- The test infrastructure itself logs nothing to production sinks; fakes are in-memory.

## 11. Testing Strategy

This ticket **is** the testing strategy; the matrix:

**Repository (JVM, MockWebServer):**
- `getTiers` / `getMySubscriptions` / `getFanClubTiers`: request path/query/header/cookie
  correctness; success DTO→domain mapping incl. enums, money, `Instant`.
- Error mapping: `detail` string/list/obj × `404`/`422`/`409`/`5xx`; malformed JSON;
  empty body.
- Resilience: timeout; GET retry budget (`503,503,200`); no-retry on non-GET;
  401→refresh→retry (success + refresh-fails); single-refresh invariant.

**EntitlementResolver (pure, suite backstop):**
- Matrix over {no subs, active at tier, higher owned, lower owned, lapsed, multiple} ×
  {`Tier`, `Content`, `FanClub`} keys → exact verdicts incl. `RequiresUpgrade(minTier)`
  and fail-closed `Unknown`. 100% branch coverage asserted.

**ViewModel (Turbine):**
- `Loading→Content`; empty→`isEmpty`; tiers-ok/subs-fail→`isStale`+`SUBSCRIBE`;
  full failure→`Error(retryable)`; `refresh()` keeps data + `isRefreshing`; `retry()`
  recovers; cancellation on `onCleared`. (Complements AND-241; deduplicated where AND-241
  already covers.)

**UI (Robolectric Compose; optional connected):**
- Per screen: `Loading`/`Content`/`Empty`/`Error`/`isStale`/`isRefreshing` rendering;
  CTA-per-entitlement; gated affordance hidden on `Denied`/`Unknown`; CTA/refresh/retry
  callbacks fired; a11y semantics; locale lookup.

**Tooling & tasks:**
- Unit + Robolectric: `./gradlew :feature-subscriptions:testDebugUnitTest`.
- Optional on-device Compose: `./gradlew :feature-subscriptions:connectedDebugAndroidTest`.
- Lint/static: `./gradlew :feature-subscriptions:lint detekt`.
- **No test contacts the live backend.** Flake budget: zero; CI re-run must be
  deterministic. Coverage gate: 100% `EntitlementResolver` branches, ≥85% line coverage of
  repository + ViewModels (Jacoco), UI tests cover every documented state per screen.
- Screens not yet merged → `@Ignore("blocked by AND-2xx")` so the suite is green now and
  the ignores are removed as the screen tickets land.

## 12. Dependencies & Sequencing

- **Depends on AND-241** (ViewModels + `EntitlementResolver`): supplies the state types,
  resolver, and `FakeSubscriptionsRepository`/fakes that the repo, ViewModel, and UI tests
  build on. Must merge first.
- **Targets AND-234** (Subscriptions API + DTOs): the repo tests exercise
  `SubscriptionsRepository`/`SubscriptionsApi` and the `core-model` DTOs; their field
  names/enum values define the fixtures.
- **Drives the screen tickets** AND-235 (browse), AND-236 (subscribe/checkout entry),
  AND-237 (manage/cancel), AND-240 (fan-club tiers/members): the UI tests require their
  Composables and the `testTag` contract in §6. Tests for unmerged screens are `@Ignore`d
  until those land.
- Transitively relies on `core-network` (AND-027 lineage) for the cookie jar / CSRF
  interceptor / `ApiResult`, and on `core-testing` for shared rules and fakes.
- Sequencing: AND-234 → AND-241 → **AND-242**, with the screen tickets landing in parallel
  and their `@Ignore`s lifted as merged. This ticket **blocks nothing** (leaf test ticket)
  but is a release gate for the subscriptions feature.

## 13. Risks & Open Questions

- **R1 — `testTag` contract drift:** UI tests depend on tags the screen tickets must add.
  Mitigation: publish the §6 tag list as the shared contract; coordinate with AND-235/237/240
  owners; failing tag lookups are the early-warning signal. **Open question:** confirm tag
  naming with the screen owners.
- **R2 — DTO field names / enum spellings** (`price_cents` vs `priceCents`, status enum
  casing) come from AND-234's Moshi config; fixtures must match exactly. Mitigation: derive
  fixtures from AND-234's adapter tests / the web `types.ts`.
- **R3 — Retry budget value** for idempotent GETs is set by `core-network`; the retry-count
  assertion must read the configured constant, not hardcode a number, to avoid brittleness.
- **R4 — Robolectric vs on-device Compose parity:** some Compose APIs (pull-to-refresh,
  animations) behave differently under Robolectric. Mitigation: prefer semantics/tag
  assertions over pixel/animation timing; mark device-only cases for
  `connectedDebugAndroidTest`.
- **R5 — Caching path ownership:** whether a stale-cache repo test belongs here or in
  AND-234 depends on where the Room cache lives. Assumption: assert the cache-hit path here
  only if AND-234 exposes it; otherwise `@Ignore` referencing AND-234.
- **R6 — Unmerged screens** make some UI tests temporarily `@Ignore`d; risk that ignores
  are forgotten. Mitigation: each `@Ignore` names its blocking ticket and a lint/CI check
  flags lingering ignores past those tickets' merge.

## 14. Acceptance Criteria

- AC-1: Repo tests exist under `feature-subscriptions/src/test/.../repository/` using
  `MockWebServer`, asserting request path/query, `X-CSRF-Token` header, cookie attachment,
  and DTO→domain mapping for tiers, subscriptions, and fan-club tiers.
- AC-2: Error-mapping tests cover FastAPI `detail` as `string`/`[{msg}]`/`{code,...}`
  across `404`/`422`/`409`/`5xx`, malformed JSON, and empty body → correct
  `ApiResult.Failure(AppError)` variants.
- AC-3: Resilience tests prove ~20s timeout handling, bounded-backoff retry on idempotent
  GET only (asserted request count), no retry on non-GET, and 401→refresh(once)→retry
  including the refresh-fails terminal case.
- AC-4: `EntitlementResolver` matrix is asserted with 100% branch coverage incl.
  fail-closed `Unknown`.
- AC-5: UI tests (Robolectric Compose) for each merged subscriptions/fan-club screen assert
  `Loading`/`Content`/`Empty`/`Error`/`isStale`/`isRefreshing` rendering and the correct
  CTA per entitlement.
- AC-6: UI interaction tests assert CTA, refresh, and retry invoke the expected
  callbacks/navigation events; a11y semantics and locale-driven string lookup are asserted.
- AC-7: Telemetry tests assert the documented events/payloads fire on the right paths and
  contain no PII/subscription contents.
- AC-8: No test contacts the live dev host; the suite is deterministic and passes:
  `./gradlew :feature-subscriptions:testDebugUnitTest` green. Tests for unmerged screens
  are `@Ignore`d with the blocking AND-### named.

## 15. Definition of Done

- Test sources and shared fixtures/fakes merged to `android-port` under
  `feature-subscriptions` (test source sets) and `core-testing`, building with Kotlin
  2.0.21 / AGP 8.7.3 / JDK 17.
- `./gradlew :feature-subscriptions:lint detekt testDebugUnitTest` is **green** in CI;
  optional `:connectedDebugAndroidTest` documented and passing on the reference emulator
  (API 34).
- Coverage gates met: 100% `EntitlementResolver` branches; ≥85% line coverage of repository
  + ViewModels (Jacoco report attached to the PR); every documented UI state covered.
- The `testTag` contract (§6) is agreed with and applied by the screen tickets, or the
  corresponding tests are `@Ignore`d with the blocking AND-### and tracked.
- Fixtures match AND-234's actual DTO field names/enums (verified against its adapter
  tests / web `types.ts`); retry budget read from the `core-network` constant, not
  hardcoded.
- No live-network calls anywhere in the suite; runs are deterministic across at least three
  consecutive CI executions (zero flake).
- PR description links AND-241 (dependency), AND-234 (repo/DTO target), and the screen
  tickets (AND-235/236/237/240) it drives, and lists any remaining `@Ignore`s with their
  blocking tickets.
