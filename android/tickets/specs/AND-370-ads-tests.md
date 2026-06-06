---
id: AND-370
title: Ads tests
milestone: M8
epic: E47
priority: P2
size: M
status: draft
depends_on: [AND-369]
blocks: []
---

# AND-370 — Ads tests

## 1. Overview & Goal

AND-370 delivers the automated test suite for the entire Ads / Monetization epic (E47). It is a pure **Test** ticket: it adds no production behavior and ships no user-facing screens. Its goal is to lock down the contract and UI behavior of the ads feature surface built across AND-363 through AND-369 so the feature can ship in milestone M8 with confidence and so regressions in later milestones are caught in CI.

Concretely, this ticket provides two test layers for the ads feature module(s):

1. **Repository / data-layer tests** ("Repo tests") — JVM unit tests that verify `core-network`/`core-data` ads repositories correctly call the cookie-based `/ui/ads/*` endpoints, map FastAPI DTOs into `core-model` domain types, surface `ApiResult<T>` success/error states, and handle the unreliable dev backend (timeouts, 401 refresh-once, malformed `detail`).
2. **UI tests** — Compose instrumentation/Robolectric tests that verify the ads screens (campaign analytics dashboard, content boost create/detail, sponsorship inbox/deal detail, ad billing/deposit) render each `UiState` (Loading / Content / Empty / Error / Offline-Stale) correctly and that user actions drive the `ViewModel` as specified.

"Acceptance: Pass" from the backlog means: the suite is green in CI on the `android-port` branch, runs hermetically (no live calls to `http://18.222.237.167:8000`), and asserts the behaviors enumerated in Section 14.

## 2. Context & References

- Repo: `spannella/testlogon`, Android app in `android/`, branch `android-port`.
- Namespace / applicationId base: `com.testlogon.android`.
- Test module: `core-testing` provides shared fakes, fixtures, dispatchers, and the `MockWebServer` harness consumed here. No new module is created; tests live alongside the code under test.
- Source-of-truth feature tickets covered by this suite:
  - AND-363 — Ads accounts API: `/ui/ads/accounts*` DTOs (accounts, billing, campaigns read).
  - AND-364 — Content boost: `contentBoost.ts` parity; boost a post (create/detail), budget + payment.
  - AND-365 — Sponsorship inbox: `sponsorshipDeals.ts` parity; offer inbox.
  - AND-366 — Sponsorship manage / deal detail: accept/decline/negotiate.
  - AND-367 — Ad billing / deposit: account billing + deposit (read + deposit).
  - AND-368 — Ad analytics (read): campaign analytics dashboards.
  - AND-369 — Ads ViewModels: `StateFlow<UiState>` for all ads screens (**direct dependency**).
- Web reference for endpoint parity: `frontend/src/api/endpoints/contentBoost.ts`, `frontend/src/api/endpoints/sponsorshipDeals.ts`, `frontend/src/api/endpoints/ads*.ts`; shared types `frontend/src/api/types.ts`. Backend OpenAPI at `/openapi.json`.
- Auth model under test: cookie-based session + `ui_csrf` cookie echoed as `X-CSRF-Token`; on 401 the client calls `POST /ui/session/refresh` once then retries. The suite must assert these mechanics for ads calls.

## 3. Functional Requirements

FR-1. **Repo tests** exist for every ads repository introduced by AND-363/364/365/366/367/368:
- `AdsAccountsRepository`, `ContentBoostRepository`, `SponsorshipRepository`, `AdBillingRepository`, `AdAnalyticsRepository`.

FR-2. Each repo test asserts (a) the correct HTTP method + path + query, (b) request body JSON shape for writes, (c) presence of `X-CSRF-Token` header on mutating requests, (d) successful DTO→domain mapping, and (e) error mapping into typed `ApiResult.Error`.

FR-3. Repo tests cover the **resilience** paths: read timeout (~20s budget, simulated), bounded retry on idempotent GET only, single `/ui/session/refresh` on 401 then retry, and the three FastAPI `detail` shapes (`string`, `[{msg}]`, `{code,...}`).

FR-4. **UI tests** exist for each ads screen produced in E47 and render each declared `UiState`. Minimum screens: Campaign Analytics dashboard (AND-368), Content Boost create + detail (AND-364), Sponsorship inbox (AND-365) + deal detail (AND-366), Ad billing + deposit (AND-367).

FR-5. UI tests assert user interactions are wired to ViewModel intents: e.g., tapping "Boost" submits with the entered budget; "Accept"/"Decline"/"Negotiate" on a deal calls the corresponding ViewModel function; "Deposit" submits the amount; pull-to-refresh re-invokes the loader.

FR-6. UI tests assert the Error and Offline/Stale states show the mapped message and a retry affordance, and that retry re-triggers the load.

FR-7. The suite is **hermetic**: all network is served by `MockWebServer`; ViewModels in UI tests are driven by fake repositories from `core-testing`. No test touches the live dev host.

FR-8. The suite runs in CI via Gradle and reports pass/fail per module.

## 4. Technical Design

### Module & source-set layout

```
core-network/src/test/java/com/testlogon/android/network/ads/        # repo tests (JVM, MockWebServer)
core-data/src/test/java/com/testlogon/android/data/ads/              # mapper/cache tests (JVM)
feature-ads/src/test/java/com/testlogon/android/feature/ads/         # ViewModel tests (JVM, Robolectric-free)
feature-ads/src/androidTest/java/com/testlogon/android/feature/ads/  # Compose UI tests
```

UI tests use the Compose test rule. Default execution path is **Robolectric** (`@RunWith(RobolectricTestRunner::class)` + `createComposeRule()`) so they run on the JVM in CI without an emulator; the same test bodies are device-compatible via `createAndroidComposeRule`.

### Shared test infrastructure (in `core-testing`)

```kotlin
// MockWebServer-backed Retrofit/OkHttp builder mirroring prod config
class ApiTestHarness {
    val server = MockWebServer()
    val cookieJar = InMemoryCookieJar()            // mirrors prod persistent jar
    fun retrofit(): Retrofit                        // Moshi, 20s timeouts, CSRF + refresh interceptors
    fun enqueueJson(code: Int, body: String, vararg headers: Pair<String, String>)
    fun enqueueDelay(seconds: Long)                 // for timeout assertions
    fun takeRequest(): RecordedRequest
}

object AdsFixtures {                                 // canonical JSON payloads
    val ACCOUNTS_OK: String
    val CAMPAIGN_ANALYTICS_OK: String
    val BOOST_CREATE_OK: String
    val SPONSORSHIP_INBOX_OK: String
    val DEAL_DETAIL_OK: String
    val BILLING_OK: String
    val DETAIL_STRING_ERR: String                   // {"detail":"not allowed"}
    val DETAIL_LIST_ERR: String                     // {"detail":[{"msg":"bad"}]}
    val DETAIL_OBJ_ERR: String                      // {"detail":{"code":"X"}}
}

class FakeAdsRepositories : ... {                    // emits scripted ApiResult/Flow for UI tests
    var nextState: UiState
}

@get:Rule val mainDispatcherRule = MainDispatcherRule()  // StandardTestDispatcher
```

### Repo test pattern (example)

```kotlin
@RunWith(JUnit4::class)
class ContentBoostRepositoryTest {
    private lateinit var harness: ApiTestHarness
    private lateinit var repo: ContentBoostRepository

    @Before fun setUp() {
        harness = ApiTestHarness()
        repo = ContentBoostRepositoryImpl(harness.retrofit().create(AdsApi::class.java))
    }

    @Test fun `createBoost posts budget and maps response`() = runTest {
        harness.cookieJar.seed("ui_csrf", "csrf-abc")
        harness.enqueueJson(200, AdsFixtures.BOOST_CREATE_OK)

        val result = repo.createBoost(postId = "p1", BoostRequest(budgetCents = 5000, currency = "USD"))

        val req = harness.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/ui/ads/boosts", req.path)
        assertEquals("csrf-abc", req.getHeader("X-CSRF-Token"))
        assertThat(result).isInstanceOf(ApiResult.Success::class.java)
        assertEquals(BoostStatus.PENDING, (result as ApiResult.Success).data.status)
    }

    @Test fun `401 triggers single refresh then retry`() = runTest {
        harness.enqueueJson(401, """{"detail":"expired"}""")
        harness.enqueueJson(200, """{}""")            // POST /ui/session/refresh
        harness.enqueueJson(200, AdsFixtures.ACCOUNTS_OK) // retried GET
        val result = repo.getAccounts()
        assertEquals("/ui/session/refresh", harness.takeRequest(skip = 1).path)
        assertThat(result).isInstanceOf(ApiResult.Success::class.java)
    }
}
```

### UI test pattern (example)

```kotlin
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class SponsorshipInboxScreenTest {
    @get:Rule val compose = createComposeRule()

    @Test fun `error state shows message and retry`() {
        val fake = FakeAdsRepositories().apply {
            nextState = SponsorshipInboxUiState.Error("not allowed")
        }
        val vm = SponsorshipInboxViewModel(fake, mainDispatcherRule.dispatcher)
        compose.setContent { SponsorshipInboxScreen(state = vm.uiState.collectAsState().value, onRetry = vm::load) }

        compose.onNodeWithText("not allowed").assertIsDisplayed()
        compose.onNodeWithTag("retry").assertIsDisplayed().performClick()
        assertTrue(fake.loadCalled)
    }
}
```

## 5. API Contract

This ticket consumes (does not define) the ads contract owned by AND-363/364/367/368. The endpoints the **repo tests** stub via `MockWebServer` are:

| Method | Path | Used by | Notes |
|---|---|---|---|
| GET | `/ui/ads/accounts` | AdsAccountsRepository | idempotent; retry-eligible |
| GET | `/ui/ads/accounts/{id}/billing` | AdBillingRepository | read |
| GET | `/ui/ads/accounts/{id}/campaigns` | AdsAccountsRepository | read |
| GET | `/ui/ads/campaigns/{id}/analytics` | AdAnalyticsRepository | read, dashboard |
| POST | `/ui/ads/boosts` | ContentBoostRepository | create; requires `X-CSRF-Token` |
| GET | `/ui/ads/boosts/{id}` | ContentBoostRepository | detail |
| GET | `/ui/ads/sponsorships` | SponsorshipRepository | inbox |
| GET | `/ui/ads/sponsorships/{id}` | SponsorshipRepository | deal detail |
| POST | `/ui/ads/sponsorships/{id}/respond` | SponsorshipRepository | accept/decline/negotiate; CSRF |
| POST | `/ui/ads/accounts/{id}/deposit` | AdBillingRepository | deposit; CSRF |

> Exact paths must be reconciled against `/openapi.json` and `frontend/src/api/endpoints/*.ts` during implementation; if a feature ticket finalized a different path, the fixture and assertion are updated to match. Representative fixtures:

```json
// BOOST_CREATE_OK
{ "id": "b_123", "post_id": "p1", "budget_cents": 5000, "currency": "USD",
  "status": "pending", "created_at": "2026-06-05T00:00:00Z" }
```
```json
// SPONSORSHIP_INBOX_OK
{ "items": [ { "id": "d_1", "advertiser": "Acme", "amount_cents": 250000,
  "status": "offered" } ], "next_cursor": null }
```
```json
// CAMPAIGN_ANALYTICS_OK
{ "impressions": 10234, "clicks": 412, "ctr": 0.04, "spend_cents": 80000,
  "series": [ { "date": "2026-06-01", "impressions": 1200 } ] }
```

Error fixtures cover all three FastAPI `detail` variants (string, list-of-`{msg}`, object-with-`code`).

## 6. Data & State Management

The suite asserts the `UiState` contracts produced by AND-369. Each ads ViewModel exposes `StateFlow<UiState>`; tests verify the state machine for representative screens:

```kotlin
sealed interface SponsorshipInboxUiState {
    data object Loading : SponsorshipInboxUiState
    data class Content(val deals: List<SponsorshipDeal>, val stale: Boolean) : SponsorshipInboxUiState
    data object Empty : SponsorshipInboxUiState
    data class Error(val message: String) : SponsorshipInboxUiState
}
```

State assertions performed:
- Initial collect emits `Loading`.
- Success with non-empty list → `Content(stale=false)`; empty list → `Empty`.
- Cache-hit while network fails → `Content(stale=true)` (offline/stale path), verified against a `FakeAdsRepositories` seeded from Room.
- Error → `Error(mapped message)`.
- `runTest` + `MainDispatcherRule` (StandardTestDispatcher) control coroutine ordering; `Turbine` (`.test { }`) asserts the exact emission sequence.

DataStore prefs and Room cache mappers introduced for ads (e.g., last-viewed account) get focused mapper tests in `core-data` confirming DTO↔entity↔domain round-trips.

## 7. Error Handling & Resilience

The suite is the primary place these behaviors are proven:

- **Timeout**: `enqueueDelay(21)` against a 20s OkHttp read timeout → repo returns `ApiResult.Error` of network/timeout kind, no crash.
- **Bounded retry, GET only**: a GET that 503s twice then 200s is retried and succeeds; a POST that 503s is **not** retried (assert exactly one recorded request) — guards against duplicate boosts/deposits.
- **401 refresh-once**: assert `/ui/session/refresh` is called exactly once and the original request is retried once; a second 401 surfaces an auth error (no infinite loop).
- **CSRF**: mutating requests carry `X-CSRF-Token` matching the `ui_csrf` cookie; tests fail if header is absent.
- **Malformed `detail`**: all three shapes map to a non-null human-readable message; an unparseable body maps to a generic fallback string, never throws.

## 8. Security & Privacy

- Tests must contain **no real credentials, cookies, or tokens**. CSRF/cookie values are obvious fakes (`csrf-abc`).
- The suite must never point at `http://18.222.237.167:8000`; a CI guard/assert fails the build if a base URL other than the `MockWebServer` localhost URL is configured in test.
- Tests assert that the cookie jar is the mechanism carrying auth (no Authorization bearer header is added) and that secrets are not logged by the OkHttp logging interceptor at the test log level.
- No PII fixtures: advertiser/user names in fixtures are synthetic.

## 9. Accessibility & i18n

Although a test ticket, the UI tests enforce a11y/i18n hygiene on the ads screens:
- Assert interactive elements expose content descriptions / merged semantics (use `onNodeWithContentDescription` for icon-only actions like the boost/deposit buttons).
- Assert user-visible strings are resolved from string resources (tests read expected text via `context.getString(R.string.ads_...)`) rather than hardcoded literals, so the screens are localizable.
- Touch targets and focus order are out of scope here and remain the responsibility of the feature tickets; this suite only catches missing semantics that would break TalkBack on the asserted nodes.

## 10. Telemetry & Logging

- No production telemetry is added by this ticket.
- The suite verifies that any analytics/telemetry calls emitted by ads ViewModels (if introduced by AND-369) are routed through a `FakeAnalytics` and asserts the expected event keys are recorded (e.g., `ads_boost_submitted`, `ads_deposit_submitted`) without firing real network.
- Test logging: failures must print the `RecordedRequest` path/body and the resulting `ApiResult` to aid CI triage; OkHttp logging interceptor is set to `BASIC` in the test harness to avoid leaking bodies in shared logs.

## 11. Testing Strategy

This ticket *is* the testing strategy for E47. Composition:

- **Repo unit tests (JVM, MockWebServer)** — one class per repository. Cover happy path, each error `detail` shape, timeout, retry policy (GET vs POST), 401 refresh-once, CSRF header. Frameworks: JUnit4, `kotlinx-coroutines-test` (`runTest`), MockWebServer, Truth/AssertJ, Moshi.
- **Mapper tests (JVM)** — DTO→domain and entity round-trips in `core-data`.
- **ViewModel tests (JVM)** — Turbine over `StateFlow<UiState>`; assert full emission order against fake repos; cover empty/error/stale.
- **Compose UI tests (Robolectric, JVM-runnable)** — one class per screen; assert each state renders and each action invokes the ViewModel; assert error+retry.
- **Determinism** — `StandardTestDispatcher` + `MainDispatcherRule`; no `Thread.sleep`; `MockWebServer` enqueue ordering; idempotent, parallel-safe.
- **Coverage target** — ads repositories and ViewModels ≥ 80% line coverage (advisory gate via JaCoCo, not blocking unless CI configures it).
- **Execution** — `./gradlew :core-network:testDebugUnitTest :core-data:testDebugUnitTest :feature-ads:testDebugUnitTest :feature-ads:testDebugUnitTest --tests "*ads*"`; Compose Robolectric tests run under `testDebugUnitTest`. Optional device run via `connectedDebugAndroidTest`.

## 12. Dependencies & Sequencing

- **Hard dependency: AND-369** (Ads ViewModels) — UI/ViewModel tests need the `StateFlow<UiState>` types and ViewModel constructors to assert against. This ticket starts once AND-369 merges.
- **Transitive (code under test must exist):** AND-363 (DTOs/API), AND-364 (boost), AND-365/366 (sponsorship), AND-367 (billing/deposit), AND-368 (analytics). Each must be merged before its corresponding test class is meaningful; partial landing is acceptable if test classes are added incrementally per merged feature.
- **Infra reuse:** `core-testing` `ApiTestHarness`, `MainDispatcherRule`, and fixtures established by earlier milestones (M1–M7 test tickets). This ticket adds ads-specific `AdsFixtures` and `FakeAdsRepositories` to `core-testing`.
- **Blocks:** nothing structurally, but it gates the E47 "done" criteria and the M8 release sign-off.

## 13. Risks & Open Questions

- **R1 — Endpoint path drift.** Exact `/ui/ads/*` paths and JSON keys are not in the backlog text; they come from `/openapi.json` and `frontend/`. Mitigation: derive fixtures from the live OpenAPI/web client at implementation time; centralize paths in `AdsApi` so a path change is one edit.
- **R2 — Payment/deposit semantics.** Whether deposit/boost involve a payment intent (Stripe-style two-step) affects request shape and idempotency assertions. Open question for AND-364/367 owners: is there a client-generated idempotency key? If so, retry-suppression tests must also assert the key is reused.
- **R3 — Compose-on-Robolectric flakiness.** Some Compose APIs misbehave under Robolectric. Mitigation: pin Robolectric/Compose versions used elsewhere in the repo; fall back to `androidTest` for any screen that proves unstable.
- **R4 — ViewModel shape uncertainty.** Final `UiState` sealed hierarchies depend on AND-369; this spec's signatures are representative. Tests must track AND-369's actual types.
- **Open question:** Does sponsorship "negotiate" open a sub-flow (counter-offer screen) requiring its own UI test, or is it a single POST? Assumed single POST until AND-366 confirms.

## 14. Acceptance Criteria

AC-1. Repo unit tests exist for `AdsAccountsRepository`, `ContentBoostRepository`, `SponsorshipRepository`, `AdBillingRepository`, `AdAnalyticsRepository` and pass.
AC-2. For each mutating endpoint, a test asserts the request carries `X-CSRF-Token` equal to the `ui_csrf` cookie value.
AC-3. A test proves bounded retry occurs for an idempotent GET and does **not** occur for a POST (exactly one recorded POST).
AC-4. A test proves a 401 triggers exactly one `POST /ui/session/refresh` followed by one retry of the original ads request.
AC-5. Tests cover all three FastAPI `detail` shapes plus an unparseable body, each producing a non-null mapped message with no thrown exception.
AC-6. A timeout test (delay > read timeout) yields `ApiResult.Error` and no crash.
AC-7. ViewModel tests assert the full `StateFlow<UiState>` emission order for at least the Sponsorship inbox and Content boost screens, including Empty and Error.
AC-8. Compose UI tests exist for Campaign analytics, Content boost (create + detail), Sponsorship inbox, Deal detail, and Ad billing/deposit; each renders Loading, Content, and Error, and Error shows a working retry.
AC-9. UI tests assert primary actions (Boost, Accept/Decline/Negotiate, Deposit, Refresh) invoke the corresponding ViewModel function with the expected arguments.
AC-10. The entire suite is hermetic: no request reaches `18.222.237.167`; a guard fails the build otherwise.
AC-11. The suite passes in CI on `android-port` via the documented Gradle commands.

## 15. Definition of Done

- All Section 14 acceptance criteria met and the ads test suite is green in CI on `android-port`.
- `AdsFixtures` and `FakeAdsRepositories` added to `core-testing` and reused (no duplicated fixtures across modules).
- Test paths/fixtures reconciled against `/openapi.json` and `frontend/src/api/endpoints/*.ts`; any deviation documented inline.
- Tests run hermetically and deterministically (no live host, no `Thread.sleep`, parallel-safe).
- No secrets, real cookies, or PII in fixtures; CI base-URL guard in place.
- New test code passes lint/detekt; no production code changed except minor visibility/test-hook adjustments (documented in the PR).
- PR reviewed and merged; coverage report generated for ads repositories and ViewModels (≥ 80% advisory).
