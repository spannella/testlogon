---
id: AND-242
title: Subscriptions/fan-club tests
milestone: M5
epic: E32
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
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
- **Web reference:** `src/api/endpoints/subscriptions.ts`, `src/api/endpoints/fan-club.ts`,
  `src/api/types.ts`, and `src/api/client.ts` are the source of truth for the endpoint
  paths, JSON fixtures, and auth/CSRF transport used by the repo tests. **CORRECTED
  (review AND-242):** subscription endpoints live under `/api/...` and additionally send an
  `X-User-Id` header (`subscriptions.ts: userIdHeader`); fan-club tier endpoints live under
  `/ui/fan-club/...`. Both paths flow through the same `client.ts: api()` wrapper, so the
  `X-CSRF-Token` (from the `ui_csrf` cookie) and `Authorization: Bearer` headers are added
  to every request, `/api` and `/ui` alike.
- **Backend:** FastAPI + DynamoDB; dev host `http://18.222.237.167:8000` is plaintext and
  unreliable. **No test in this ticket hits the live host.** All HTTP goes through
  `MockWebServer`; the unreliable host motivates explicit timeout/stale-path tests.

## 3. Functional Requirements

FR-1 **Repository request contract tests.** Verify each repository method issues the
correct HTTP request: method, path, query params, `X-CSRF-Token` header echoed from the
`ui_csrf` cookie, and that the persistent cookie jar attaches session cookies.

FR-2 **Repository mapping tests.** Verify DTO→domain mapping from recorded JSON fixtures
for plans, subscriptions, and fan-club tiers. **CORRECTED (review AND-242)** to the real
field names: `status` is a free-form **string** (mapped to a domain enum with an
`Unknown`/else branch — the backend declares no enum, so `ACTIVE`/`PAST_DUE`/`CANCELED`/
`EXPIRED` are conventional values, not schema-fixed), `price_cents`/`currency`/`interval`
(string cadence, e.g. `"month"` — not `period: "MONTH"`), fan-club `benefits` (not
`perks`), and **epoch-integer** timestamps `current_period_end`/`start_at` parsed to
`Instant` (there is no ISO `renews_at` field).

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

    // NOTE (review AND-242): path/fields corrected to the real contract — plans live at
    // GET /api/creators/{creatorId}/plans (bare array), id field is plan_id, money is
    // price_cents, billing cadence is `interval` (string), not `period`.
    @Test fun getPlans_success_mapsDtoToDomain() = runTest {
        mws.server.enqueue(MockResponse().setResponseCode(200)
            .setBody(readFixture("plans_ok.json")))
        val result = repo.getPlans("creator_42")
        val req = mws.server.takeRequest()
        assertThat(req.path).isEqualTo("/api/creators/creator_42/plans")
        assertThat(req.method).isEqualTo("GET")
        assertThat(req.getHeader("X-CSRF-Token")).isEqualTo("csrf-abc")
        assertThat(result).isInstanceOf(ApiResult.Success::class.java)
        val plans = (result as ApiResult.Success).data
        assertThat(plans.first().planId).isEqualTo("plan_gold")
        assertThat(plans.first().priceCents).isEqualTo(999)
        assertThat(plans.first().interval).isEqualTo("month")
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
AND-234. **CORRECTED (review AND-242):** the original draft listed three endpoints
(`GET /ui/subscriptions/tiers`, `GET /ui/subscriptions/me`, `GET /ui/fan-club/{creatorId}/tiers`)
that **do not exist** in the backend OpenAPI or the web reference client. The real paths
the web client uses — and therefore the contract the repo tests must pin — are:

- **Purchasable subscription plans** (a creator's "tiers"):
  `GET /api/creators/{creatorId}/plans` → `200` **bare array** `[SubscriptionPlan, …]`
  (web: `subscriptions.ts: listPlans`; public, no `X-User-Id`). There is **no**
  `{ "tiers": [...] }` envelope.
- **My subscriptions:** `GET /api/subscriptions?include_summary=true` → `200` **bare array**
  `[SubscriptionOut, …]` (web: `subscriptions.ts: listSubscriptions`; sends `X-User-Id`).
  There is **no** `/ui/subscriptions/me` and **no** `{ "subscriptions": [...] }` envelope.
  (A cookie-session variant `GET /ui/billing/subscriptions` also exists; the repo under
  test targets the `/api/subscriptions` path the web `subscriptions.ts` uses.)
- **Fan-club tiers (creator-managed, current user's club):** `GET /ui/fan-club/tiers` →
  `200` **bare array** `[TierOut, …]` (web: `fan-club.ts: listTiers`). The creator-scoped
  **public** variant is `GET /api/creators/{creatorId}/tiers` (web: `fan-club.ts: getPublicTiers`).
  Fan-club tier members: `GET /ui/fan-club/tiers/{tierId}/members`.
- **Cancel** (non-GET, for the no-retry test): `POST /api/subscriptions/{subId}/cancel`
  with body `{ cancel_at_period_end?, reason? }` → `200 SubscriptionOut`
  (web: `subscriptions.ts: cancelSubscription`).
- `POST /ui/session/refresh` → `200` (sets refreshed cookies) used by the 401-retry test.
  **Verified** (OpenAPI `POST /ui/session/refresh`; web `client.ts: refreshSession`,
  `auth.ts` line 60). Note the request body is empty.

Fixtures must mirror the **actual** field names in `reference/src/api/types.ts` (verified
against OpenAPI `components.schemas.SubscriptionOut`). Key corrections vs. the original
draft fixtures: the plan/subscription id field is `plan_id`/`subscription_id` (not `id`),
a subscription references its plan via `plan_id` (not `tier_id`), pricing uses `interval`
(a string e.g. `"month"`, not `period: "MONTH"`), `status` is a free-form **string** (the
DTO declares no enum — `ACTIVE`/`PAST_DUE`/etc. are conventional values, not schema-fixed),
timestamps are **epoch integers** (`current_period_end`, `start_at`, `created_at`, not an
ISO `renews_at`), and plans/fan-club tiers carry `benefits`/no `perks` field.

```json
// plans_ok.json  — GET /api/creators/{creatorId}/plans  (bare array of SubscriptionPlan)
[
  { "plan_id": "plan_gold", "creator_id": "creator_42", "name": "Gold",
    "price_cents": 999, "currency": "USD", "interval": "month", "status": "active",
    "created_at": 1750000000, "updated_at": 1750000000 },
  { "plan_id": "plan_plat", "creator_id": "creator_42", "name": "Platinum",
    "price_cents": 1999, "currency": "USD", "interval": "month", "status": "active",
    "created_at": 1750000000, "updated_at": 1750000000 }
]
```

```json
// subscriptions_me.json  — GET /api/subscriptions  (bare array of SubscriptionOut)
[
  { "subscription_id": "sub_123", "plan_id": "plan_gold", "creator_id": "creator_42",
    "subscriber_id": "user_7", "interval": "month", "provider": "ccbill",
    "provider_subscription_id": "ext_1", "status": "active", "start_at": 1748736000,
    "current_period_end": 1751328000, "cancel_at_period_end": false,
    "price_cents": 999, "currency": "USD", "auto_renew": true,
    "created_at": 1748736000, "updated_at": 1748736000 }
]
```

```json
// fanclub_tiers_ok.json  — GET /ui/fan-club/tiers  (bare array of TierOut)
[
  { "tier_id": "tier_gold", "creator_id": "creator_42", "plan_id": "plan_gold",
    "name": "Gold", "level": 1, "color": "#FFD700", "badge_emoji": "⭐",
    "benefits": [{ "kind": "chat", "label": "Member chat" }],
    "member_count": 12, "sort_order": 1, "active": true,
    "created_at": 1750000000, "updated_at": 1750000000 }
]
```

FastAPI error fixtures the error-mapping test enumerates (all three `detail` shapes are
**verified** against `client.ts: normalizeErrorDetail`, which handles string, `[{msg}]`,
and `{code,…}`):

```json
{ "detail": "Subscription not found" }                       // detail_string.json
{ "detail": [ { "loc": ["query","creator_id"], "msg": "field required", "type": "value_error.missing" } ] } // detail_list.json (real FastAPI 422 / HTTPValidationError → ValidationError items)
{ "detail": { "code": "TIER_GONE", "message": "Tier removed" } }            // detail_obj.json
```

`detail_list.json` is the canonical FastAPI `422` shape (OpenAPI `HTTPValidationError`
whose `detail` is an array of `ValidationError{loc,msg,type}`). The string and `{code,…}`
shapes are app-raised `HTTPException` bodies (e.g. `404`/`409`). Each is enqueued with the
matching status (`404`, `422`, `409`) and the test asserts the resulting
`AppError`/`ApiResult.Failure` variant and that the human message is taken from the right
field (top-level string, first `msg`, or `code`/`message`). N/A: no production
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
  contract; a negative test asserts behavior when the cookie is absent. **Verified** against
  `client.ts` (lines 168–171: `X-CSRF-Token` set from the `ui_csrf` cookie on every request).
- **Auth headers (review AND-242 addition):** `client.ts` also adds
  `Authorization: Bearer <accessToken>` when the auth store holds a token, and the
  subscription endpoints additionally send `X-User-Id` (`subscriptions.ts: userIdHeader`).
  Repo tests assert `X-User-Id` is present on `/api/subscriptions*` calls and absent on the
  public `GET /api/creators/{id}/plans` call (which the web client issues with no user id).
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict (Verified / Corrected / Unverified-assumption), and
the exact source pointer.

1. **"Subscription tiers come from `GET /ui/subscriptions/tiers?creator_id={id}` returning
   `{tiers:[...]}`."** — **Corrected.** No such path exists. Purchasable plans are
   `GET /api/creators/{creatorId}/plans` returning a **bare `SubscriptionPlan[]`**.
   Source: `src/api/endpoints/subscriptions.ts: listPlans`; OpenAPI has no
   `/ui/subscriptions/tiers` entry (grep of `openapi.index.txt`).
2. **"My subscriptions come from `GET /ui/subscriptions/me` returning `{subscriptions:[...]}`."**
   — **Corrected.** Real path is `GET /api/subscriptions` (optional `include_summary`),
   returning a **bare `SubscriptionOut[]`**. Source: `src/api/endpoints/subscriptions.ts:
   listSubscriptions`; OpenAPI `GET /api/subscriptions` (op
   `list_subscriptions_api_subscriptions_get`). A cookie-session sibling
   `GET /ui/billing/subscriptions` also exists (OpenAPI line 1199) but is not the path the
   web `subscriptions.ts` uses.
3. **"Fan-club tiers come from `GET /ui/fan-club/{creatorId}/tiers` returning `{tiers:[...]}`."**
   — **Corrected.** Real path is `GET /ui/fan-club/tiers` returning a **bare `TierOut[]`**;
   the public creator-scoped variant is `GET /api/creators/{creatorId}/tiers`. Source:
   `src/api/endpoints/fan-club.ts: listTiers` / `getPublicTiers`; OpenAPI
   `GET /ui/fan-club/tiers` (op `api_list_tiers_ui_fan_club_tiers_get`) and
   `GET /ui/fan-club/tiers/{tier_id}/members`.
4. **"`POST /ui/session/refresh` is used for the 401→refresh→retry path."** — **Verified.**
   Source: OpenAPI `POST /ui/session/refresh` (op `ui_session_refresh_ui_session_refresh_post`);
   `src/api/client.ts: refreshSession` (line 122) and `src/api/endpoints/auth.ts` (line 60).
   Request body is empty.
5. **"401 → refresh once → retry; if retry is still 401, log out; refresh is single-flight."**
   — **Verified.** Source: `src/api/client.ts` lines 194–237 (`refreshPromise` single-flight
   guard, one retry, `logout("session_expired")` on retry 401).
6. **"`X-CSRF-Token` header is sent from the `ui_csrf` cookie on every request."** —
   **Verified.** Source: `src/api/client.ts` lines 168–171.
7. **"Subscription `/api` calls additionally send `X-User-Id`; the public plans call sends
   none."** — **Verified.** Source: `src/api/endpoints/subscriptions.ts: userIdHeader`,
   `subGet`/`subPost` (send it) vs. `listPlans` (uses bare `api.get`, no user id).
8. **"An `Authorization: Bearer` token is attached when present."** — **Verified.** Source:
   `src/api/client.ts` lines 157–160.
9. **"FastAPI `detail` appears as `string`, `[{msg}]`, or `{code,...}` and the human
   message is taken from the right field."** — **Verified.** Source:
   `src/api/client.ts: normalizeErrorDetail` (lines 66–102, handles all three) and the
   `mapAuthorizationError` `{code,...}` branch. The `[{...}]` form is the OpenAPI
   `HTTPValidationError` → `ValidationError{loc,msg,type}` (schemas at lines 37133 / 80337).
10. **"`422` is the FastAPI validation status with `detail: [ValidationError]`."** —
    **Verified.** Source: OpenAPI — every subscription/fan-club op lists
    `422:HTTPValidationError`; `HTTPValidationError.detail` is `array<ValidationError>`.
11. **"Subscription/plan DTO money field is `price_cents` and currency `currency`."** —
    **Verified.** Source: `src/api/types.ts: SubscriptionPlan`/`SubscriptionOut`; OpenAPI
    `components.schemas.SubscriptionOut` (`price_cents: integer`, `currency: string`).
12. **"Billing cadence field is `period` with values like `MONTH`."** — **Corrected.** The
    field is `interval` (a free string, e.g. `"month"`). Source: `src/api/types.ts:
    SubscriptionPlan.interval` / `SubscriptionOut.interval`; OpenAPI `SubscriptionOut.interval`
    (`type: string`).
13. **"Subscription id is `id`, plan reference is `tier_id`, renewal time is ISO `renews_at`."**
    — **Corrected.** Ids are `subscription_id` / `plan_id`; there is no `tier_id` on a
    subscription; renewal is `current_period_end` as an **epoch integer**. Source:
    `src/api/types.ts: SubscriptionOut`; OpenAPI `SubscriptionOut` required list
    (lines 71116–71133) and `current_period_end: integer`.
14. **"`status` is an enum (`ACTIVE`/`PAST_DUE`/`CANCELED`/`EXPIRED`)."** —
    **Corrected / Unverified-assumption.** The DTO declares `status` as a plain `string`
    with no `enum` constraint (OpenAPI `SubscriptionOut.status: {type: string}`;
    `types.ts: status: string`). Tests must map via an enum with a fail-safe `Unknown`
    branch; the specific value spellings are an unverified backend convention.
15. **"Fan-club tier carries `perks`."** — **Corrected.** `TierOut` has `benefits:
    TierBenefit[]` (plus `level`, `color`, `badge_emoji`, `member_count`, `active`);
    pricing lives on the linked plan via `plan_id`, not on the tier. Source:
    `src/api/types.ts: TierOut`.
16. **"Cancel (a non-GET mutation, used for the no-retry test) exists."** — **Verified.**
    `POST /api/subscriptions/{subscription_id}/cancel` → `200 SubscriptionOut`. Source:
    `src/api/endpoints/subscriptions.ts: cancelSubscription`; OpenAPI
    `POST /api/subscriptions/{subscription_id}/cancel`.
17. **"Network/offline failures surface as a distinct error (not a crash)."** — **Verified
    (web analogue).** `client.ts` lines 185–189 throw `ApiError(0, "Network error")` on
    `fetch` rejection; the Android repo's `AppError.Network`/`Timeout` mapping is the
    parallel. The dev host (`http://18.222.237.167:8000`) being flaky/plaintext motivates
    the timeout/offline tests but is never contacted (Verified: scope says MockWebServer only).
18. **"Robolectric Compose tests run at `@Config(sdk=[34])`."** — **Verified (framework ref).**
    Robolectric supports API-34 and the project compiles to SDK 35; running UI tests at
    sdk 34 matches the physical Galaxy A15 (API 34). framework ref:
    https://robolectric.org/configuring/ and
    https://developer.android.com/jetpack/compose/testing.
19. **"Determinism via `StandardTestDispatcher` + `MainDispatcherRule` + `FixedClock`."** —
    **Verified (framework ref).** framework ref:
    https://developer.android.com/kotlin/coroutines/test and
    https://github.com/cashapp/turbine.
20. **"`MockWebServer` is the HTTP test double for repo tests."** — **Verified
    (framework ref).** framework ref: https://github.com/square/okhttp/tree/master/mockwebserver.

### Corrections made

- §5 API Contract rewritten: replaced the three non-existent endpoints with the real ones
  (`GET /api/creators/{id}/plans`, `GET /api/subscriptions`, `GET /ui/fan-club/tiers`,
  `POST /api/subscriptions/{id}/cancel`); removed the `{tiers:[...]}`/`{subscriptions:[...]}`
  envelopes (responses are bare arrays); rewrote all three JSON fixtures to the real field
  names (`plan_id`/`subscription_id`, `interval`, epoch-integer timestamps, `benefits`);
  added the real FastAPI `422` `ValidationError{loc,msg,type}` item to `detail_list.json`.
- §4 repo-test example: corrected the asserted path, method, and mapped fields
  (`getTiers`→`getPlans`, `/ui/subscriptions/tiers?...`→`/api/creators/creator_42/plans`,
  `id`→`planId`, added `interval`).
- §2 web-reference bullet: pointed at the correct files and documented the `/api` vs `/ui`
  split and that `X-User-Id` + `X-CSRF-Token` + `Authorization` all apply.
- §8 Security: cited `client.ts` line numbers for CSRF; added the `X-User-Id`/`Bearer`
  header assertions.
- FR-2: corrected the field-name list (`interval` not `period`, `benefits` not `perks`,
  epoch ints not `renews_at`, `status` is a string).
- Frontmatter: `status: reviewed`, added `reviewed_on: 2026-06-06`.

### Open assumptions

- **Status value spellings** (`ACTIVE`/`PAST_DUE`/`CANCELED`/`EXPIRED`): the DTO types
  `status` as an unconstrained `string`, so the exact set is unverifiable from OpenAPI or
  `types.ts`. Tests assert the mapping path with a fail-safe `Unknown` branch rather than a
  fixed enum set. (Why: no enum in the schema; backend convention only.)
- **`EntitlementResolver` verdict matrix, domain `ApiResult`/`AppError` variants, retry
  budget constant, and `testTag` names**: these are Android-side artifacts owned by AND-241 /
  AND-234 / `core-network` / the screen tickets, not present in the web reference or OpenAPI.
  They are assumed per the upstream tickets; tests read the retry-budget constant rather than
  hardcoding it (R3). (Why: client-app internals, no authoritative source in this repo set.)
- **Room/DataStore caching / stale-while-revalidate path**: whether the repo exposes a
  cache-hit path is owned by AND-234; the related test is `@Ignore`d if absent (R5). (Why:
  not determinable from the reference sources.)
- **Telemetry event names/payloads** (`subscriptions_tiers_viewed`, etc.): an Android-side
  analytics contract with no web/OpenAPI counterpart; assumed per this ticket's §10. (Why:
  client-only.)

## 17. Test Plan

Test target legend — **JVM**: JVM unit/Robolectric, local, no device. **EMU**: headless
emulator AVD `test35` (x86_64, API 35). **DEV**: physical Samsung Galaxy A15 5G (SM-A156U,
serial R5CX821TA9R, API 34, arm64-v8a). This is a pure test ticket with no camera/biometric/
push/WebRTC/Telecom surface, so almost everything runs JVM (Robolectric/MockWebServer) in
CI; the only device-relevant cases are the on-device Compose parity run (real API-34/arm64
vs. emulator API-35/x86_64) — those PREFER the physical DEV device.

- **TC-AND-242-01** — Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: `MockWebServerRule`, `TestCookieJar`, CSRF cookie `ui_csrf=csrf-abc`,
  `X-User-Id` absent. Steps: enqueue `200` `plans_ok.json`; call
  `repo.getPlans("creator_42")`; `takeRequest()`. Expected: request is
  `GET /api/creators/creator_42/plans`, `X-CSRF-Token=csrf-abc` present, **no** `X-User-Id`;
  result is `ApiResult.Success` with `plans[0].planId="plan_gold"`, `priceCents=999`,
  `interval="month"`. Traces: AC-1.
- **TC-AND-242-02** — Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: authenticated user (`X-User-Id=user_7`), CSRF cookie set. Steps: enqueue
  `200` `subscriptions_me.json`; call `repo.getMySubscriptions(includeSummary=true)`;
  `takeRequest()`. Expected: `GET /api/subscriptions?include_summary=true`,
  `X-User-Id=user_7` and `X-CSRF-Token` present; mapped to bare list with
  `subscription_id="sub_123"`, `plan_id="plan_gold"`, `current_period_end` parsed from epoch
  `1751328000` to the right `Instant`, `auto_renew=true`. Traces: AC-1.
- **TC-AND-242-03** — Type: contract/MockWebServer (JVM). Target: JVM. Preconditions: as
  above. Steps: enqueue `200` `fanclub_tiers_ok.json`; call `repo.getFanClubTiers()`;
  `takeRequest()`. Expected: `GET /ui/fan-club/tiers`; bare `TierOut[]` mapped with
  `tier_id="tier_gold"`, `level=1`, `benefits` size 1, `memberCount=12`, `active=true`; no
  `perks` field expected. Traces: AC-1.
- **TC-AND-242-04** — Type: contract/MockWebServer (JVM). Target: JVM. Preconditions:
  prior `Set-Cookie: sid=...` response recorded in `TestCookieJar`. Steps: make a first
  request that returns `Set-Cookie`; make a second request; inspect the second
  `takeRequest()`. Expected: session cookie from response 1 is attached to request 2,
  proving persistent-jar wiring; no cookie persisted to disk. Traces: AC-1.
- **TC-AND-242-05** — Type: contract/MockWebServer (JVM). Target: JVM. Preconditions:
  error fixtures present. Steps: parametrized — enqueue (`404`,`detail_string.json`),
  (`422`,`detail_list.json`), (`409`,`detail_obj.json`), (`500`, empty), (`200`, malformed
  JSON body). Expected: each maps to the correct `ApiResult.Failure(AppError…)` variant; the
  human message is the top-level string / first `msg` / `code`+`message` respectively; `500`
  → server error variant; malformed body → parse-failure variant, **never a crash**.
  Traces: AC-2.
- **TC-AND-242-06** — Type: contract/MockWebServer (JVM). Target: JVM. Preconditions:
  ~20s client timeout, virtual time. Steps: enqueue a response with `setBodyDelay(25s)`;
  advance virtual time past the timeout; call an idempotent GET. Expected:
  `ApiResult.Failure(AppError.Timeout)` (no real sleep); a subsequent UI render of this
  state is `error_state` with `retryable=true`. Traces: AC-3.
- **TC-AND-242-07** — Type: contract/MockWebServer (JVM). Target: JVM. Preconditions:
  retry budget read from the `core-network` constant (not hardcoded). Steps: (a) GET — enqueue
  `503,503,200`; (b) non-GET cancel `POST /api/subscriptions/sub_123/cancel` — enqueue `503`.
  Expected: (a) exactly N attempts per the configured budget then final `Success`,
  `takeRequest()` count matches; (b) **single** request, no retry, `Failure`. Traces: AC-3.
- **TC-AND-242-08** — Type: contract/MockWebServer (JVM). Target: JVM. Preconditions:
  authenticated, refresh wired to `POST /ui/session/refresh`. Steps: (a) enqueue `401` for
  the GET, `200` for refresh, `200` for the retried GET; (b) enqueue `401` for the GET then a
  failing refresh (`401`). Expected: (a) final `Success`, refresh requested **exactly once**,
  retried GET carries refreshed cookies; (b) terminal `ApiResult.Failure(AppError.Auth)`, no
  infinite loop, no second refresh. Traces: AC-3.
- **TC-AND-242-09** — Type: unit (JVM, pure). Target: JVM. Preconditions: `FixedClock`,
  `EntitlementResolver`. Steps: drive the verdict matrix over {no subs, active at tier,
  higher owned, lower owned, lapsed, multiple} × {Tier, Content, FanClub} keys, plus the
  network-failure/unknown input. Expected: each cell yields the exact verdict incl.
  `RequiresUpgrade(minTier)` and **fail-closed `Unknown`** (network failure ⇒ denied); 100%
  branch coverage. Traces: AC-4.
- **TC-AND-242-10** — Type: Compose-UI (Robolectric, JVM). Target: JVM `@Config(sdk=[34])`.
  Preconditions: stateless screen + canned `UiState`. Steps: render each of
  `Loading`/`Content`/`Empty`/`Error(retryable)`/`isStale`/`isRefreshing`. Expected: correct
  node per state — `loading_indicator`, populated `tiers_screen`/`subscriptions_list`,
  `empty_state` copy, `error_state` + `retry_button`, `stale_banner`, `refresh_indicator`.
  Traces: AC-5.
- **TC-AND-242-11** — Type: Compose-UI (Robolectric, JVM). Target: JVM. Preconditions:
  content state with mixed entitlements. Steps: render tier rows where one is owned/current,
  one upgradeable, one not owned, and one gated by `Denied`/`Unknown`. Expected:
  `cta_{tierId}` shows `Current plan`/`Upgrade`/`Subscribe` correctly and gated affordances
  are hidden/locked on `Denied`/`RequiresUpgrade`/`Unknown`. Traces: AC-5.
- **TC-AND-242-12** — Type: Compose-UI (Robolectric, JVM). Target: JVM. Preconditions:
  callbacks captured via fakes. Steps: `performClick()` on a CTA, trigger pull-to-refresh,
  click `retry_button`; also assert a11y — interactive nodes `assertHasClickAction()`, have
  non-empty content descriptions, error message is in the semantics tree; resolve copy via
  `context.getString(R.string.…)` and re-run one screen under `@Config(qualifiers="fr")` to
  prove locale-driven lookup and locale-aware currency/date formatting of `price_cents`.
  Expected: each interaction fires the expected ViewModel/nav callback once; a11y + locale
  assertions pass. Traces: AC-6.
- **TC-AND-242-13** — Type: integration (ViewModel via Turbine + Fake repo, JVM). Target:
  JVM. Preconditions: `FakeSubscriptionsRepository` scripted; fake `Analytics`/`Logger`.
  Steps: drive `Loading→Content`; tiers-ok + subs-fail → `isStale`+`SUBSCRIBE`; full failure
  → `Error(retryable)`; `refresh()` keeps prior rows + `isRefreshing` and shows
  `stale_banner` (stale-while-revalidate). Expected: exact `StateFlow` sequence; on success
  `subscriptions_tiers_viewed{creatorId,tierCount}` fires, on error
  `subscriptions_load_failed{errorType,retryable}` fires, on CTA
  `subscription_cta_clicked{tierId,cta}` fires — **no user id / subscription contents** in
  any payload; `Logger` records `WARN` on failure/stale with no PII. Traces: AC-7.
- **TC-AND-242-14** — Type: instrumented/e2e Compose parity (on-device). Target: **DEV
  (physical Galaxy A15, API 34, arm64-v8a) — MUST run on the physical device**; EMU
  `test35` (API 35, x86_64) as the secondary CI lane. Preconditions:
  `:feature-subscriptions:connectedDebugAndroidTest`, MockWebServer still the HTTP double
  (no live host). Steps: run the §17 Compose suite (states + CTA + interaction) on hardware.
  Expected: identical pass results to Robolectric — confirms real-device Compose parity for
  pull-to-refresh/animation behavior (R4) and API-34/arm64 vs. API-35/x86_64 ABI parity; no
  network reaches `18.222.237.167`. Traces: AC-5, AC-6, AC-8.

### Coverage matrix

| AC (section 14) | Covering test case(s) |
| --- | --- |
| AC-1 (repo request + mapping: plans, subs, fan-club, CSRF, cookie) | TC-01, TC-02, TC-03, TC-04 |
| AC-2 (error mapping: detail string/list/obj, 404/422/409/5xx, malformed, empty) | TC-05 |
| AC-3 (timeout, GET-only retry, no-retry non-GET, 401→refresh-once→retry incl. refresh-fails) | TC-06, TC-07, TC-08 |
| AC-4 (EntitlementResolver matrix, 100% branch, fail-closed Unknown) | TC-09 |
| AC-5 (UI state rendering + CTA per entitlement) | TC-10, TC-11, TC-14 |
| AC-6 (UI interactions, a11y semantics, locale lookup) | TC-12, TC-14 |
| AC-7 (telemetry events/payloads, no PII) | TC-13 |
| AC-8 (no live host, deterministic, `testDebugUnitTest` green; on-device documented) | TC-06, TC-07, TC-08, TC-14 (all suites; no case contacts the dev host) |
