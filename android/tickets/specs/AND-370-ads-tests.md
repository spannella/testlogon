---
id: AND-370
title: Ads tests
milestone: M8
epic: E47
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
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
- Auth model under test: cookie-based session + `ui_csrf` cookie echoed as `X-CSRF-Token`; on 401 the client calls `POST /ui/session/refresh` once then retries. The suite must assert these mechanics for ads calls. **[Corrected]** Per the web reference (`src/api/client.ts`), `X-CSRF-Token` is attached to **every** request (GET included), not only mutating ones, and the client *also* sets `Authorization: Bearer <accessToken>` when an access token is present in the auth store — i.e. transport uses cookie session **and** a bearer header in parallel (see §8 correction). The single-refresh-then-retry-once behavior and the exact `POST /ui/session/refresh` path are verified.

## 3. Functional Requirements

FR-1. **Repo tests** exist for every ads repository introduced by AND-363/364/365/366/367/368:
- `AdsAccountsRepository`, `ContentBoostRepository`, `SponsorshipRepository`, `AdBillingRepository`, `AdAnalyticsRepository`.

FR-2. Each repo test asserts (a) the correct HTTP method + path + query, (b) request body JSON shape for writes, (c) presence of `X-CSRF-Token` header on mutating requests, (d) successful DTO→domain mapping, and (e) error mapping into typed `ApiResult.Error`.

FR-3. Repo tests cover the **resilience** paths: read timeout (~20s budget, simulated), bounded retry on idempotent GET only, single `/ui/session/refresh` on 401 then retry, and the three FastAPI `detail` shapes (`string`, `[{msg}]`, `{code,...}`).

FR-4. **UI tests** exist for each ads screen produced in E47 and render each declared `UiState`. Minimum screens: Campaign Analytics dashboard (AND-368), Content Boost create + detail (AND-364), Sponsorship inbox (AND-365) + deal detail (AND-366), Ad billing + deposit (AND-367).

FR-5. UI tests assert user interactions are wired to ViewModel intents: e.g., tapping "Boost" submits with the entered budget; "Accept"/"Decline"/"Negotiate" on a deal calls the corresponding ViewModel function (which maps to the **distinct** `/accept`, `/reject`, and `/counter` endpoints respectively — there is no single `/respond` endpoint); "Deposit" submits the amount; pull-to-refresh re-invokes the loader.

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

        // [Corrected] real request body: content_type/content_id/budget_cents/duration_seconds (ContentBoostCreate)
        val result = repo.createBoost(
            BoostRequest(contentType = "post", contentId = "p1", budgetCents = 5000, durationSeconds = 86_400),
        )

        val req = harness.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/ui/ads/boost", req.path)   // [Corrected] singular /ui/ads/boost, not /ui/ads/boosts
        assertEquals("csrf-abc", req.getHeader("X-CSRF-Token"))
        assertThat(result).isInstanceOf(ApiResult.Success::class.java)
        // ContentBoostOut.status is a free-form string; createBoost returns 200 (not 201)
        assertEquals("pending", (result as ApiResult.Success).data.status)
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

This ticket consumes (does not define) the ads contract owned by AND-363/364/367/368. Note: the ads UI client uses the cookie-session `/ui/ads/*` surface; a separate machine-facing `/api/v1/ads/*` surface also exists in the backend but is **not** the contract under test here (verified in `openapi.index.txt`). The endpoints the **repo tests** stub via `MockWebServer` are:

The table below has been **reconciled against `openapi.index.txt` and the web reference**; corrected cells are flagged. Note every `/ui/ads/*` op also accepts `user_sub`, `X-SESSION-ID`, and `X-IMPERSONATION-TOKEN` params/headers server-side — the Android client relies on the cookie session + bearer + CSRF instead and does not send these explicitly, so tests assert on the cookie/CSRF/bearer transport only.

| Method | Path | Used by | Notes |
|---|---|---|---|
| GET | `/ui/ads/accounts` | AdsAccountsRepository | idempotent; retry-eligible. Returns a **bare JSON array** (`AdAccount[]`), not an envelope |
| GET | `/ui/ads/accounts/{account_id}/billing` | AdBillingRepository | read; `?limit=` query; returns `AdBillingEntry[]` |
| GET | `/ui/ads/accounts/{account_id}/campaigns` | AdsAccountsRepository | read; returns `Campaign[]` |
| GET | `/ui/ads/analytics/summary` | AdAnalyticsRepository | **[Corrected]** dashboard analytics is a query-param endpoint `?account_id=&campaign_id=&days=`, **not** `/ui/ads/campaigns/{id}/analytics` (which does not exist). Companion reads: `/ui/ads/analytics/timeseries`, `/ui/ads/analytics/breakdown` |
| POST | `/ui/ads/boost` | ContentBoostRepository | **[Corrected]** create boost is **singular** `/ui/ads/boost`, not `/ui/ads/boosts`; req `ContentBoostCreate`, resp **200** `ContentBoostOut`; requires `X-CSRF-Token` |
| GET | `/ui/ads/boost/{boost_id}` | ContentBoostRepository | **[Corrected]** detail at `/ui/ads/boost/{boost_id}` (singular); resp `ContentBoostOut` |
| GET | `/ui/ads/sponsorships` | SponsorshipRepository | inbox; `?status=&role=` query; returns a **bare array** `SponsorshipDeal[]` |
| GET | `/ui/ads/sponsorships/{deal_id}` | SponsorshipRepository | deal detail; resp `SponsorshipDeal` |
| POST | `/ui/ads/sponsorships/{deal_id}/accept` | SponsorshipRepository | **[Corrected]** accept is its own endpoint; there is **no** `/respond` endpoint |
| POST | `/ui/ads/sponsorships/{deal_id}/reject` | SponsorshipRepository | **[Corrected]** "decline" is `reject` (body `{reason}`); CSRF |
| POST | `/ui/ads/sponsorships/{deal_id}/counter` | SponsorshipRepository | **[Corrected]** "negotiate" is `counter` (req `SponsorshipCounterRequest`: `compensation_cents`, `note`); CSRF |
| POST | `/ui/ads/accounts/{account_id}/deposit` | AdBillingRepository | deposit; req `AdDepositIn` (`amount_cents`, optional `payment_method_id`), resp **200** `{ok, entry_id, new_balance_cents}`; CSRF |

> Verified against `reference/openapi.index.txt` and `reference/src/api/endpoints/{contentBoost,sponsorshipDeals,ads}.ts`. Corrected fixtures (field names taken from `components.schemas`):

```json
// BOOST_CREATE_OK  — [Corrected] ContentBoostOut: boost_id/content_id (not id/post_id),
// no currency, timestamps are integer epochs (not ISO strings)
{ "boost_id": "b_123", "owner_sub": "u_1", "content_type": "post", "content_id": "p1",
  "budget_cents": 5000, "spent_cents": 0, "remaining_cents": 5000, "duration_seconds": 86400,
  "starts_at": 1749081600, "ends_at": 1749168000, "status": "pending", "created_at": 1749081600 }
```
```json
// SPONSORSHIP_INBOX_OK  — [Corrected] endpoint returns a bare array (no items/next_cursor envelope);
// money field is compensation_cents (not amount_cents)
[ { "id": "d_1", "advertiser_account_id": "acc_1", "creator_sub": "u_2", "content_type": "post",
    "compensation_cents": 250000, "status": "proposed" } ]
```
```json
// CAMPAIGN_ANALYTICS_OK  — representative summary payload from GET /ui/ads/analytics/summary;
// exact AdAnalyticsSummary shape (KPIs + period comparison) is finalized by AND-368, so treat
// the inner key names as an unverified assumption and reconcile at implementation time
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
- **CSRF**: requests carry `X-CSRF-Token` matching the `ui_csrf` cookie; tests fail if header is absent. **[Note]** The web client sets this header on **all** requests (GET included), not just mutations — so while AC-2 only mandates the assertion on mutating endpoints, the harness should also confirm the header is present on at least one GET to match web parity.
- **Malformed `detail`**: all three shapes map to a non-null human-readable message; an unparseable body maps to a generic fallback string, never throws.

## 8. Security & Privacy

- Tests must contain **no real credentials, cookies, or tokens**. CSRF/cookie values are obvious fakes (`csrf-abc`).
- The suite must never point at `http://18.222.237.167:8000`; a CI guard/assert fails the build if a base URL other than the `MockWebServer` localhost URL is configured in test.
- **[Corrected]** Tests assert that the cookie jar carries the session, but the web reference (`src/api/client.ts`) shows the client *does* also add `Authorization: Bearer <accessToken>` whenever an access token is present, so the Android transport is expected to send **both** the session cookie and (when available) a bearer header — tests should assert the bearer header is present when the auth store holds a token and absent (cookie-only) when it does not, rather than asserting "no bearer ever". Tests also assert secrets are not logged by the OkHttp logging interceptor at the test log level.
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
- **Open question (partially resolved):** Sponsorship "negotiate" maps to a single `POST /ui/ads/sponsorships/{deal_id}/counter` with body `SponsorshipCounterRequest` (`compensation_cents`, `note`) — confirmed against the web client and OpenAPI. Whether the UI presents a dedicated counter-offer screen (and thus needs its own Compose-UI test) vs. an inline dialog is still an AND-366 presentation decision; the contract-level test is unaffected either way.

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

## 16. Citations & Assumption Audit

Each key technical claim with its verdict and an exact source pointer. Sources: OpenAPI index = `reference/openapi.index.txt`; OpenAPI schemas = `reference/openapi.pretty.json` (`components.schemas.<Name>`); frontend = `reference/src/...`.

1. **Ads UI endpoints live under `/ui/ads/*`.** VERIFIED. Source: OpenAPI index lines 784–880 (`GET /ui/ads/accounts` … `GET /ui/ads/why/{creative_id}`); frontend `src/api/endpoints/ads.ts`.
2. **A separate `/api/v1/ads/*` surface exists but is NOT the contract under test.** VERIFIED. Source: OpenAPI index lines 94–109 (`/api/v1/ads/account`, `/api/v1/ads/campaigns`, …). The UI client never calls these.
3. **Create boost path is `POST /ui/ads/boost` (singular), resp 200 `ContentBoostOut`, req `ContentBoostCreate`.** CORRECTED (spec said `POST /ui/ads/boosts`). Source: OpenAPI index line 810 `POST /ui/ads/boost | op=create_boost | req=ContentBoostCreate | resp=200:ContentBoostOut`; frontend `src/api/endpoints/contentBoost.ts: create` → `api.post("/ui/ads/boost", body)`.
4. **Boost detail path is `GET /ui/ads/boost/{boost_id}` (singular).** CORRECTED (spec said `/ui/ads/boosts/{id}`). Source: OpenAPI index line 811; `src/api/endpoints/contentBoost.ts: get`.
5. **`ContentBoostCreate` fields: `content_type`, `content_id`, `budget_cents`, `duration_seconds` (all required).** CORRECTED (spec fixture used `post_id`, `currency`). Source: `openapi.pretty.json` schema `ContentBoostCreate` (lines ~18931–18964).
6. **`ContentBoostOut` fields: `boost_id`, `owner_sub`, `content_type`, `content_id`, `budget_cents`, `spent_cents`, `remaining_cents`, `duration_seconds`, `starts_at`, `ends_at`, `status`, `created_at` — timestamps are integer epochs; no `currency`.** CORRECTED (spec fixture used `id`, `post_id`, `currency`, ISO `created_at`). Source: `openapi.pretty.json` schema `ContentBoostOut` (lines ~18981–19048).
7. **Boost list returns envelope `ContentBoostListOut { boosts: ContentBoostOut[] }`.** VERIFIED. Source: OpenAPI index line 809; schema `ContentBoostListOut` (lines ~18965–18980).
8. **Campaign analytics dashboard is a query-param endpoint `GET /ui/ads/analytics/summary?account_id=&campaign_id=&days=`, not `GET /ui/ads/campaigns/{id}/analytics`.** CORRECTED. Source: OpenAPI index line 807 (`analytics_summary_endpoint`); no `campaigns/{id}/analytics` path exists in the index. Companions: index lines 805 (breakdown), 808 (timeseries). Frontend `src/api/endpoints/ads.ts: getAnalyticsSummary/getAnalyticsTimeseries/getAnalyticsBreakdown`.
9. **Sponsorship inbox `GET /ui/ads/sponsorships` returns a bare `SponsorshipDeal[]` array (no `{items,next_cursor}` envelope); query params `status`, `role`.** CORRECTED (spec fixture used an envelope). Source: OpenAPI index line 866 (`params=status,role`); frontend `src/api/endpoints/sponsorshipDeals.ts: listSponsorshipDeals` → `api.get<SponsorshipDeal[]>`.
10. **Sponsorship deal detail `GET /ui/ads/sponsorships/{deal_id}`.** VERIFIED. Source: OpenAPI index line 870; `sponsorshipDeals.ts: getSponsorshipDeal`.
11. **Sponsorship responses are separate endpoints `/accept`, `/reject`, `/counter` (plus `/cancel`, `/complete`, `/submit-content`); there is NO `/respond` endpoint.** CORRECTED (spec listed a single `POST .../{id}/respond`). Source: OpenAPI index lines 871 (accept), 876 (reject), 874 (counter), 872 (cancel), 873 (complete), 877 (submit-content); frontend `sponsorshipDeals.ts: acceptSponsorshipDeal/rejectSponsorshipDeal/counterSponsorshipDeal`.
12. **"Decline" = `reject` (`POST /ui/ads/sponsorships/{deal_id}/reject`, body `{reason}`); "Negotiate" = `counter` (`POST .../counter`, req `SponsorshipCounterRequest` = `compensation_cents`, `note`).** CORRECTED. Source: `sponsorshipDeals.ts: rejectSponsorshipDeal/counterSponsorshipDeal`; schema `SponsorshipCounterRequest` (`openapi.pretty.json` lines ~68985–69008).
13. **Deposit `POST /ui/ads/accounts/{account_id}/deposit`, req `AdDepositIn` (`amount_cents` required, optional `payment_method_id`), resp 200 `{ok, entry_id, new_balance_cents}`.** VERIFIED. Source: OpenAPI index line 794; schema `AdDepositIn` (`openapi.pretty.json` lines ~1071–1093); frontend `ads.ts: depositAdFunds`.
14. **Billing history `GET /ui/ads/accounts/{account_id}/billing?limit=` → `AdBillingEntry[]`; campaigns `GET /ui/ads/accounts/{account_id}/campaigns` → `Campaign[]`.** VERIFIED. Source: OpenAPI index lines 787, 789; frontend `ads.ts: getAdBillingHistory/listCampaigns`.
15. **Accounts list `GET /ui/ads/accounts` returns a bare array `AdAccount[]`.** VERIFIED. Source: OpenAPI index line 784; frontend `ads.ts: listMyAdAccounts` → `api.get<AdAccount[]>`.
16. **401 handling: client calls `POST /ui/session/refresh` exactly once then retries the original request once; a failed refresh / second 401 logs out (no loop).** VERIFIED. Source: `src/api/client.ts` `refreshSession()` (line ~121, `fetch("/ui/session/refresh", {method:"POST"})`) and the 401 block (lines ~194–237) which guards with a single shared `refreshPromise` and retries once.
17. **CSRF: `X-CSRF-Token` is taken from the `ui_csrf` cookie and sent on EVERY request (not only mutations).** CORRECTED/CLARIFIED (spec implied mutating-only). Source: `src/api/client.ts` lines ~167–171 (`const csrf = getCookie("ui_csrf"); if (csrf) headers.set("X-CSRF-Token", csrf)`), executed for all methods.
18. **Transport also sends `Authorization: Bearer <accessToken>` when an access token is present — i.e. cookie session AND bearer in parallel.** CORRECTED (spec §8 claimed "no Authorization bearer header is added"). Source: `src/api/client.ts` lines ~157–160.
19. **Error `detail` normalization handles three shapes — string, list of `{msg}` objects, and object with `code` (authorization codes) — and falls back to a default string otherwise (never throws).** VERIFIED. Source: `src/api/client.ts: normalizeErrorDetail` (lines ~66–102) and `mapAuthorizationError` (lines ~34–64).
20. **Offline/network failure surfaces a distinct error (`ApiError(0, "Network error")`) rather than an HTTP status error.** VERIFIED. Source: `src/api/client.ts` catch block lines ~185–189. Android equivalent: maps `IOException`/timeout to `ApiResult.Error` of network kind.
21. **Idempotency key for boost/deposit retry-suppression.** UNVERIFIED-ASSUMPTION. Neither the OpenAPI schemas (`ContentBoostCreate`, `AdDepositIn`) nor the frontend send a client-generated idempotency key; retry-suppression for POSTs relies on "do not retry non-idempotent methods" rather than a key (see Open assumptions).
22. **Robolectric + Compose test rule (`createComposeRule`) runs Compose UI tests on the JVM in CI.** VERIFIED (framework ref). Source: https://developer.android.com/develop/ui/compose/testing and https://robolectric.org/ . Device variant uses `createAndroidComposeRule` (same framework ref).
23. **MockWebServer is the supported hermetic HTTP test double for OkHttp/Retrofit.** VERIFIED (framework ref). Source: https://github.com/square/okhttp/tree/master/mockwebserver .
24. **`StateFlow`/coroutine ordering via `kotlinx-coroutines-test` (`runTest`, `StandardTestDispatcher`) and Turbine for emission assertions.** VERIFIED (framework ref). Source: https://developer.android.com/kotlin/coroutines/test and https://github.com/cashapp/turbine .

### Corrections made

- §2 / §7 / §8 / §16-17,18: CSRF is sent on all requests (not mutations only), and an `Authorization: Bearer` header is sent alongside the cookie session when a token exists (§8 previously claimed no bearer is ever added).
- §4 repo-test example: boost create path `/ui/ads/boosts` → `/ui/ads/boost`; request body changed to `ContentBoostCreate` fields (`content_type`/`content_id`/`budget_cents`/`duration_seconds`); status assertion changed to a string ("pending") and noted resp is 200.
- §5 table: corrected boost create/detail paths to singular `/ui/ads/boost[/{boost_id}]`; replaced non-existent `/ui/ads/campaigns/{id}/analytics` with `/ui/ads/analytics/summary` (query-param); replaced the single `/respond` row with the real `/accept`, `/reject`, `/counter` endpoints; clarified accounts/sponsorship list shapes are bare arrays; spelled out deposit request/response shape.
- §5 fixtures: `BOOST_CREATE_OK` rebuilt to the real `ContentBoostOut` shape (`boost_id`, `content_id`, integer-epoch timestamps, no `currency`); `SPONSORSHIP_INBOX_OK` changed from envelope to bare array and `amount_cents`→`compensation_cents`.
- §13: "negotiate" open question resolved to `POST .../counter`.

### Open assumptions

- **AdAnalyticsSummary inner field names** (`impressions`, `clicks`, `ctr`, `spend_cents`, `series[...]`): the analytics-summary response body is untyped in the OpenAPI index (`resp=200:` with no named schema) and AND-368 owns the final DTO; the analytics fixture keys remain a representative assumption pending AND-368.
- **Idempotency key for boost/deposit:** not present in current schemas or the web client; if AND-364/367 later introduce one, the POST retry-suppression tests (TC-AND-370-04) must additionally assert the key is reused across the (suppressed) retry. Marked open because it cannot be confirmed from current sources.
- **Final `UiState` sealed hierarchies and ViewModel constructor signatures** depend on AND-369 (not yet present in the reference sources); the §4/§6 signatures are representative and tests must track AND-369's actual types.
- **`X-SESSION-ID` / `user_sub` / `X-IMPERSONATION-TOKEN` params** appear on every `/ui/ads/*` op in the OpenAPI index but the web client does not send them (it relies on the session cookie + bearer); assumed the Android client follows web parity and omits them. Reconcile if AND-363 says otherwise.

## 17. Test Plan

Test target legend: **JVM** = local JVM unit/Robolectric (no device); **emu35** = headless emulator AVD `test35` (x86_64, API 35); **device** = physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). This suite is hermetic and ViewModel/Compose-centric, so almost everything runs JVM/emu35; the physical device is only relevant for the optional real-device parity smoke (no camera/biometrics/WebRTC/FCM surface in this ticket).

| ID | Type | Target | Summary |
|---|---|---|---|
| TC-AND-370-01 | contract/MockWebServer | JVM | Boost create happy path |
| TC-AND-370-02 | contract/MockWebServer | JVM | Sponsorship accept/reject/counter endpoint mapping |
| TC-AND-370-03 | contract/MockWebServer | JVM | CSRF header on mutating + GET requests |
| TC-AND-370-04 | contract/MockWebServer | JVM | Retry policy: GET retried, POST not |
| TC-AND-370-05 | contract/MockWebServer | JVM | 401 → single refresh → retry once |
| TC-AND-370-06 | contract/MockWebServer | JVM | FastAPI `detail` shapes + unparseable body |
| TC-AND-370-07 | contract/MockWebServer | JVM | Read timeout → ApiResult.Error, no crash |
| TC-AND-370-08 | unit | JVM | Bearer + cookie transport assertion |
| TC-AND-370-09 | unit (Turbine) | JVM | Sponsorship inbox StateFlow emission order |
| TC-AND-370-10 | unit (Turbine) | JVM | Content boost StateFlow incl. Empty/Error |
| TC-AND-370-11 | Compose-UI | JVM (Robolectric) | Each screen renders Loading/Content/Error + retry |
| TC-AND-370-12 | Compose-UI | JVM (Robolectric) | Primary actions invoke ViewModel with args |
| TC-AND-370-13 | Compose-UI (a11y) | JVM (Robolectric) | Semantics/content descriptions + string-resource text |
| TC-AND-370-14 | integration (guard) | JVM | Hermetic base-URL guard fails on non-localhost |
| TC-AND-370-15 | instrumented/e2e | device | API-34 arm64 parity smoke of UI suite |

---

**TC-AND-370-01 — Boost create happy path**
- Type: contract/MockWebServer. Target: JVM.
- Preconditions: `ApiTestHarness` with `ui_csrf=csrf-abc` seeded; `ContentBoostRepositoryImpl` over `AdsApi`.
- Steps: enqueue `200` `AdsFixtures.BOOST_CREATE_OK`; call `repo.createBoost(content_type="post", content_id="p1", budget_cents=5000, duration_seconds=86400)`; `takeRequest()`.
- Expected: request is `POST /ui/ads/boost`; JSON body has exactly `content_type/content_id/budget_cents/duration_seconds`; result is `ApiResult.Success` with `boost_id="b_123"`, `status="pending"`, mapped integer-epoch timestamps.
- Traces: AC-1.

**TC-AND-370-02 — Sponsorship accept/reject/counter endpoint mapping**
- Type: contract/MockWebServer. Target: JVM.
- Preconditions: harness with CSRF seeded; `SponsorshipRepositoryImpl`.
- Steps: for each action call `repo.accept("d_1")`, `repo.reject("d_1","spam")`, `repo.counter("d_1", compensation_cents=300000, note="more")`; enqueue `200` each; `takeRequest()` per call.
- Expected: paths are `POST /ui/ads/sponsorships/d_1/accept`, `.../reject` (body `{reason:"spam"}`), `.../counter` (body `{compensation_cents:300000,note:"more"}`); no `/respond` path is ever produced; each returns `ApiResult.Success<SponsorshipDeal>`.
- Traces: AC-1, AC-9.

**TC-AND-370-03 — CSRF header present**
- Type: contract/MockWebServer. Target: JVM.
- Preconditions: harness seeds cookie `ui_csrf=csrf-abc`.
- Steps: perform one mutating call (`createBoost`) and one GET (`getAccounts`); inspect both recorded requests.
- Expected: both carry `X-CSRF-Token: csrf-abc` matching the cookie (web parity: header on GET too); test fails if header missing on either.
- Traces: AC-2.

**TC-AND-370-04 — Retry policy (GET retried, POST not)**
- Type: contract/MockWebServer. Target: JVM.
- Preconditions: harness with bounded-retry interceptor.
- Steps: (a) enqueue `503,503,200(ACCOUNTS_OK)` then `getAccounts()`; (b) enqueue `503` once then `createBoost()`.
- Expected: (a) succeeds after retries (3 recorded GETs, final `Success`); (b) exactly **one** recorded POST and an `ApiResult.Error` (no duplicate boost). If an idempotency key is later added (see §16 Open assumptions), also assert it is identical across any suppressed retry.
- Traces: AC-3.

**TC-AND-370-05 — 401 refresh-once then retry**
- Type: contract/MockWebServer. Target: JVM.
- Preconditions: authenticated state (token present in fake auth store).
- Steps: enqueue `401{"detail":"expired"}`, then `200{}` (for `POST /ui/session/refresh`), then `200 ACCOUNTS_OK` (retried GET); call `getAccounts()`. Also a second case: `401` then refresh `200` then `401` again.
- Expected: exactly one `POST /ui/session/refresh`; original request retried exactly once → `Success`. Second case: surfaces an auth `ApiResult.Error`, no infinite loop, no third attempt.
- Traces: AC-4.

**TC-AND-370-06 — FastAPI `detail` shapes + unparseable body**
- Type: contract/MockWebServer. Target: JVM.
- Preconditions: harness; error-mapping mirrors `normalizeErrorDetail`.
- Steps: enqueue, across calls, `400 DETAIL_STRING_ERR` (`{"detail":"not allowed"}`), `422 DETAIL_LIST_ERR` (`{"detail":[{"msg":"bad"}]}`), `403 DETAIL_OBJ_ERR` (`{"detail":{"code":"role_required"}}`), and `500` with a non-JSON body.
- Expected: each yields `ApiResult.Error` with a non-null human-readable message ("not allowed"; "bad"; the mapped role-required sentence; and a generic fallback for the unparseable body); no exception thrown for any case.
- Traces: AC-5.

**TC-AND-370-07 — Read timeout → error, no crash**
- Type: contract/MockWebServer. Target: JVM.
- Preconditions: harness configured with the prod-equivalent read timeout.
- Steps: `enqueueDelay(readTimeout + 1s)`; call an idempotent GET inside `runTest`.
- Expected: returns `ApiResult.Error` of network/timeout kind; no crash; no leaked coroutine. (This is the flaky-dev-host/offline path proven hermetically.)
- Traces: AC-6.

**TC-AND-370-08 — Bearer + cookie transport**
- Type: unit (interceptor). Target: JVM.
- Preconditions: harness with pluggable auth store.
- Steps: (a) token present → perform a GET; (b) token absent → perform a GET.
- Expected: (a) request carries both the session cookie and `Authorization: Bearer <token>`; (b) request carries the cookie only and no `Authorization` header. (Corrects the prior "no bearer" assumption.)
- Traces: AC-2, AC-10.

**TC-AND-370-09 — Sponsorship inbox StateFlow order**
- Type: unit (Turbine). Target: JVM.
- Preconditions: `FakeAdsRepositories`; `MainDispatcherRule` (StandardTestDispatcher).
- Steps: drive ViewModel with (i) non-empty list, (ii) empty list, (iii) repo error, (iv) cache-hit while network fails.
- Expected emission orders: (i) `Loading → Content(stale=false)`; (ii) `Loading → Empty`; (iii) `Loading → Error(mapped)`; (iv) `Loading → Content(stale=true)`.
- Traces: AC-7.

**TC-AND-370-10 — Content boost StateFlow incl. Empty/Error**
- Type: unit (Turbine). Target: JVM.
- Preconditions: as above for the boost ViewModel(s).
- Steps: drive create-success, create-error, and list-empty scenarios.
- Expected: full emission order asserted including `Loading`, terminal `Content`/`Empty`/`Error`; submit success transitions to the expected post-submit state.
- Traces: AC-7, AC-9.

**TC-AND-370-11 — Screen state rendering + retry**
- Type: Compose-UI. Target: JVM (Robolectric `@Config(sdk=[34])`).
- Preconditions: `createComposeRule`; fake-backed ViewModels per screen (Campaign analytics, Content boost create + detail, Sponsorship inbox, Deal detail, Ad billing/deposit).
- Steps: for each screen render Loading, Content, then Error; locate the error message and tap the `retry` tagged node.
- Expected: each state renders its expected nodes; Error shows the mapped message and a retry affordance; tapping retry re-invokes the loader (`loadCalled == true`).
- Traces: AC-8.

**TC-AND-370-12 — Primary actions invoke ViewModel with args**
- Type: Compose-UI. Target: JVM (Robolectric).
- Preconditions: fake ViewModels recording invocations/args.
- Steps: enter a budget and tap "Boost"; tap Accept / Decline / Negotiate on a deal; enter an amount and tap "Deposit"; pull-to-refresh.
- Expected: "Boost" calls create with the entered `budget_cents` (and `content_type`/`content_id`); Accept→accept fn, Decline→reject fn, Negotiate→counter fn; "Deposit" calls deposit with `amount_cents`; refresh re-invokes the loader.
- Traces: AC-9.

**TC-AND-370-13 — Accessibility & i18n hygiene**
- Type: Compose-UI (a11y). Target: JVM (Robolectric).
- Preconditions: rendered ads screens.
- Steps: query icon-only actions (boost/deposit) via `onNodeWithContentDescription`; compare visible labels against `context.getString(R.string.ads_*)`.
- Expected: every interactive node exposes a content description / merged semantics (TalkBack-readable); user-visible strings resolve from string resources, not hardcoded literals.
- Traces: AC-8, AC-9.

**TC-AND-370-14 — Hermetic base-URL guard**
- Type: integration (guard). Target: JVM.
- Preconditions: CI guard reads the test base URL.
- Steps: run the guard with the MockWebServer localhost URL (pass) and with `http://18.222.237.167:8000` (fail).
- Expected: build/test passes only for the localhost MockWebServer URL; any non-localhost URL (esp. the dev host) fails the build; assert no socket connects to `18.222.237.167`.
- Traces: AC-10.

**TC-AND-370-15 — Physical-device parity smoke (API 34 / arm64)**
- Type: instrumented/e2e. Target: **device** (SM-A156U, API 34, arm64-v8a) — MUST run on the physical device (not emu35) to catch arm64-vs-x86 ABI and API-34-vs-35 differences for the Compose ads screens.
- Preconditions: app installed via adb on serial `R5CX821TA9R`; fakes/MockWebServer wired for instrumented run (still hermetic — no live host).
- Steps: run a representative subset of the Compose-UI suite (`connectedDebugAndroidTest`) covering one render path and one action per ads screen.
- Expected: subset passes on the physical device with identical assertions to the Robolectric run; no ABI/runtime divergence. (Emulator `test35` runs the full Compose suite in CI; this case is the device-parity backstop.)
- Traces: AC-8, AC-9, AC-11.

### Coverage matrix

| AC | Covered by |
|---|---|
| AC-1 (repo tests exist & pass) | TC-AND-370-01, -02 (and the per-repo pattern applied to all five repositories) |
| AC-2 (CSRF == cookie on mutations) | TC-AND-370-03, -08 |
| AC-3 (retry GET yes / POST no) | TC-AND-370-04 |
| AC-4 (single refresh + one retry) | TC-AND-370-05 |
| AC-5 (three detail shapes + unparseable) | TC-AND-370-06 |
| AC-6 (timeout → Error, no crash) | TC-AND-370-07 |
| AC-7 (StateFlow emission order) | TC-AND-370-09, -10 |
| AC-8 (Compose screens render states + retry) | TC-AND-370-11, -13, -15 |
| AC-9 (actions invoke ViewModel w/ args) | TC-AND-370-02, -10, -12, -13, -15 |
| AC-10 (hermetic; guard fails otherwise) | TC-AND-370-08, -14 |
| AC-11 (suite passes in CI) | TC-AND-370-15 (device) + all JVM/emu35 cases via the documented Gradle commands |
