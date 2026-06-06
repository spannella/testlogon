---
id: AND-402
title: Webhooks/analytics tests
milestone: M8
epic: E52
priority: P2
size: M
status: draft
depends_on: [AND-401]
blocks: []
---

# AND-402 — Webhooks/analytics tests

## 1. Overview & Goal

This ticket delivers the **automated test suite** for the M8 webhooks and analytics
surfaces of the TestLogon native Android app (`com.testlogon.android`). It is a
**Test** ticket (Type: Test, Priority: P2): it adds no production behaviour, ships no
new screens or endpoints, and introduces no domain code. Its sole deliverable is a
rigorous, green, CI-runnable test layer over code that already exists or is delivered
by upstream tickets — specifically the webhooks repository/ViewModels (AND-398,
AND-401) and the analytics dashboards repository/ViewModel (AND-399, AND-401).

The source backlog scope is "Repo + UI tests" with acceptance "Pass." We interpret
this as: (a) **repository-layer tests** (MockWebServer-backed) pinning the HTTP
contract — verbs, paths, query params, bodies, the `X-CSRF-Token` header, DTO→domain
mapping, caching, retry/refresh, FastAPI `detail` error mapping — for both
`WebhooksRepository` and `AnalyticsRepository`; and (b) **UI tests** proving the
Compose screens and ViewModels render the canonical states
(loading / content / empty / error+stale) from deterministic fixtures. "Pass" means
the suite is deterministic and green in CI, with no live dev-host dependence (all
network mocked).

The goal: make AND-398 ("webhooks render"), AND-399 ("analytics render"), and the
"unit-tested" bar of AND-401 **independently verifiable and regression-protected** by
a suite that runs without network access.

## 2. Context & References

- **Scope under test:**
  - `feature-webhooks` — `com.testlogon.android.feature.webhooks` (AND-398): list,
    detail, light-create screens + their ViewModels; `WebhooksRepository`,
    `WebhooksApi`, `Webhook` model.
  - `feature-analytics` — `com.testlogon.android.feature.analytics.dashboards`
    (AND-399): dashboards screen + `AnalyticsViewModel`; `AnalyticsRepository`,
    `AnalyticsService`, `AnalyticsDashboard` model.
  - `AND-401` consolidates/finalizes the webhooks + analytics **ViewModels** (state);
    this ticket is its direct dependency and the consumer of that state surface.
- **Web reference:** `frontend/src/api/endpoints/webhooks.ts`,
  `frontend/src/api/endpoints/analytics.ts`, shared `frontend/src/api/types.ts`. Test
  fixtures mirror these field names; any divergence the tests catch is a real bug.
- **OpenAPI:** `/openapi.json` on `http://18.222.237.167:8000` is authoritative for
  shapes. Fixture JSON is derived from it / the web reference and pinned in-repo so the
  suite never touches the live (plaintext, unreliable) dev host.
- **Stack under test:** Kotlin 2.0.21, Jetpack Compose + Material 3, Hilt (KSP),
  Coroutines/Flow, Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15, Room 2.6, DataStore.
  minSdk 24, compileSdk/targetSdk 35, JDK 17, Gradle 8.9, AGP 8.7.3.
- **Test stack:** JUnit4, `kotlinx-coroutines-test` (`StandardTestDispatcher` +
  `runTest`), Turbine, OkHttp `MockWebServer`, Truth/AssertK, Robolectric for JVM-side
  Compose where viable, and `androidx.compose.ui.test`
  (`createComposeRule` / `createAndroidComposeRule`). `core-testing` provides fakes.
- **Layering:** tests live with the module they cover (`feature-*/src/test`,
  `feature-*/src/androidTest`, `core-data/src/test`); shared fakes/fixtures in
  `core-testing`. ViewModels expose `StateFlow<UiState>`; repos return `ApiResult<T>`.

## 3. Functional Requirements

FR-1 — **Webhooks repository contract tests.** Using `MockWebServer`, assert
`GET /ui/webhooks`, `GET /ui/webhooks/{id}`, and `POST /ui/webhooks` issue the correct
method/path; the POST carries the JSON body `{ "url", "events" }` and an
`X-CSRF-Token` header; responses deserialize per §5; cache-then-network and
write-through-on-create behaviour holds; GETs retry on transient failure and POST never
auto-retries.

FR-2 — **Analytics repository contract tests.** Assert
`GET /ui/analytics/dashboard?start&end&granularity=day` and (where used)
`GET /ui/analytics/breakdown?...dimension&limit` issue correct method/path/query
params; DTO→domain mapping including seconds→duration and fraction→percent; cache-first
emits stale-then-fresh; bounded backoff retries 5xx then succeeds; the prior-window
delta path (embedded `previous` vs fallback second GET) is exercised.

FR-3 — **Auth/CSRF/refresh reuse tests.** A `401` response from any GET triggers
exactly one `POST /ui/session/refresh` then a retry of the original request (the
AND-027 interceptor path), verified by recorded `MockWebServer` requests. The CSRF
header presence on unsafe methods is asserted.

FR-4 — **Error mapping tests.** The shared `ApiErrorMapper` maps all three FastAPI
`detail` shapes (`string`, `[{ "msg": ... }]`, `{ "code": ..., ... }`) to the typed
error, for both features. 422 on `POST /ui/webhooks` maps a `loc`-targeted `url` error
to the field-level form error.

FR-5 — **ViewModel state-machine tests (Turbine).** Webhooks: `Loading → Content /
Empty / Error` for the list; create-form `canSubmit` gating (invalid URL, no events,
valid); submit-success triggers list refresh; submit-failure populates `submitError`.
Analytics: default range `LAST_28`; `RangeSelected` persists the preset and re-queries;
success populates tiles + both series + breakdowns + delta; empty payload → `isEmpty`;
error → `error`; `Refresh` toggles `isRefreshing`. An injected `Clock` makes
start/end query params deterministic.

FR-6 — **Compose UI tests.** Webhooks: list renders rows from fake state (the
"webhooks render" acceptance), empty-state shows the create CTA, detail shows the event
list, create disables submit until valid. Analytics: loading shows skeletons, success
renders tile labels + breakdown rows + chart text-summaries, empty shows empty copy,
error shows a working Retry, and the stale banner appears when `isStale` (the
"analytics render" acceptance).

FR-7 — **Determinism / no-live-network.** No test performs a real network call to the
dev host; every test uses `MockWebServer`, in-memory Room, fakes, and `TestDispatcher`.
The suite is order-independent and free of `Thread.sleep`/wall-clock dependence.

FR-8 — **Coverage gate.** Repository and ViewModel paths for both features meet the
project line-coverage threshold; the build fails if it drops below the configured bar.

## 4. Technical Design

No production module is created. Tests are added to existing modules:

```
core-testing/src/main/java/com/testlogon/android/core/testing/
  fakes/FakeWebhooksRepository.kt
  fakes/FakeAnalyticsRepository.kt
  fixtures/WebhookFixtures.kt
  fixtures/AnalyticsFixtures.kt
  rules/MainDispatcherRule.kt
  net/MockBackend.kt                 // MockWebServer + Retrofit/OkHttp builder

core-data/src/test/.../webhooks/DefaultWebhooksRepositoryTest.kt
core-data/src/test/.../analytics/AnalyticsRepositoryImplTest.kt
core-network/src/test/.../ApiErrorMapperTest.kt
core-network/src/test/.../CsrfRefreshInterceptorTest.kt

feature-webhooks/src/test/.../WebhooksListViewModelTest.kt
feature-webhooks/src/test/.../WebhookDetailViewModelTest.kt
feature-webhooks/src/test/.../CreateWebhookViewModelTest.kt
feature-webhooks/src/androidTest/.../WebhooksScreensTest.kt
feature-analytics/src/test/.../AnalyticsViewModelTest.kt
feature-analytics/src/androidTest/.../AnalyticsScreenTest.kt
```

**Coroutine/Flow harness.** A reusable JUnit rule swaps the main dispatcher:

```kotlin
class MainDispatcherRule(
    val dispatcher: TestDispatcher = StandardTestDispatcher(),
) : TestWatcher() {
    override fun starting(d: Description) = Dispatchers.setMain(dispatcher)
    override fun finished(d: Description) = Dispatchers.resetMain()
}
```

ViewModels are constructed with the test dispatcher and an injected `Clock` (e.g.
`Clock.fixed(Instant.parse("2026-06-05T00:00:00Z"), ZoneOffset.UTC)`) so analytics
`start`/`end` resolve deterministically. `StateFlow` assertions use Turbine
`.test { ... }`.

**MockWebServer harness.** A shared builder wires a Retrofit pointed at the mock,
through the real OkHttp client config (timeouts, retry policy, CSRF/refresh
interceptor) so repository tests exercise production interceptors, not stubs:

```kotlin
object MockBackend {
    fun start(): MockWebServer
    fun retrofit(server: MockWebServer, moshi: Moshi, cookieJar: CookieJar): Retrofit
    fun enqueueJson(server: MockWebServer, code: Int, bodyResId: String)
}
```

**Room in tests.** Repository tests build an in-memory Room DB
(`Room.inMemoryDatabaseBuilder(...).allowMainThreadQueries().build()`) so the
cache-then-network and stale-fallback branches are real, not mocked. DataStore prefs
(analytics range) use a temp-file-backed `PreferenceDataStoreFactory` per test, torn
down in `@After`.

**Fakes.** `FakeWebhooksRepository` / `FakeAnalyticsRepository` implement the
production interfaces with programmable `ApiResult`/`Flow` outcomes, used by ViewModel
and Compose tests so they need no MockWebServer; repository contract tests use the real
implementations against MockWebServer.

**Compose UI.** Screen tests drive the **stateless** Composables with fixture
`UiState` directly (`composeRule.setContent { WebhooksListScreen(state, onEvent = {}) }`)
to assert each state; a thin VM-backed nav test (`createAndroidComposeRule`) covers the
list → create → back → refreshed-list round-trip via the fake repository.

## 5. API Contract

This ticket defines **no** new endpoints; it pins the contracts owned by AND-398 and
AND-399 via fixtures and assertions. The shapes the tests assert against:

**Webhooks list** — `GET /ui/webhooks` → 200:

```json
{ "webhooks": [
  { "id": "wh_01HX...", "url": "https://example.com/hooks/tl",
    "events": ["session.finalized", "mfa.verified"], "active": true,
    "secret_set": true, "created_at": "2026-05-12T18:04:11Z" } ] }
```

**Webhook detail** — `GET /ui/webhooks/{id}` → 200 (single object, list-element shape);
404 → not-found path.

**Webhook create** — `POST /ui/webhooks`, body `{ "url", "events" }` → 201|200 with the
created `WebhookDto` (server `id`, `created_at`, `secret_set:true`, optional one-time
`secret`). Tests assert both 200 and 201 are accepted and that the request carried
`X-CSRF-Token`.

**Analytics dashboard** —
`GET /ui/analytics/dashboard?start=YYYY-MM-DD&end=YYYY-MM-DD&granularity=day` → 200:

```json
{ "range": { "start": "2026-05-09", "end": "2026-06-05" },
  "summary": { "views": 184320, "watch_time_seconds": 9421800,
    "unique_viewers": 51240, "subscribers_net": 1372, "engagement_rate": 0.0613 },
  "previous": { "views": 161002, "watch_time_seconds": 8730500,
    "unique_viewers": 49110, "subscribers_net": 980, "engagement_rate": 0.0588 },
  "timeseries": [ { "date": "2026-05-09", "views": 6210,
    "watch_time_seconds": 318400, "unique_viewers": 2110 } ] }
```

**Analytics breakdown** —
`GET /ui/analytics/breakdown?start&end&dimension={content|source}&limit=10` → 200 with
an `items` array (`content`: `id,label,views,watch_time_seconds`; `source`:
`id,label,views,share`). Tests cover both dimensions and the combined-payload variant
(breakdowns embedded, second call skipped) if that is the confirmed contract.

**Error envelope** — FastAPI `detail`: `string` | `[{ "msg": ... }]` (422) |
`{ "code": ..., ... }`. Fixtures exist for each shape and for `401/403/404/422/500/503`.
All fixtures are resources under `core-testing` (`fixtures/`) loaded by filename; tests
do not hand-build JSON inline beyond small error bodies.

## 6. Data & State Management

- **Fixtures as source of truth.** `WebhookFixtures` and `AnalyticsFixtures` expose
  typed builders (`webhook(id=..., active=...)`, `dashboard(views=...)`) plus the raw
  JSON resources of §5, keeping VM/UI tests and repo tests on the same canonical data.
- **In-memory Room** verifies cache writes: after a successful `GET /ui/webhooks`, the
  test asserts `WebhooksDao.observeAll()` emits the upserted rows with a `fetched_at`;
  after `create`, write-through (`upsertAll(listOf(new))`) is asserted before the
  refresh. Analytics asserts one `analytics_dashboard` row per `rangePreset` with
  `fetchedAt`, and that an older `fetchedAt` (beyond the 15-min TTL) is served as
  **stale** while a refresh runs.
- **DataStore range pref** (analytics) is asserted: `RangeSelected(LAST_7)` persists,
  and a fresh ViewModel seeded from the same DataStore restores `LAST_7`.
- **State assertions.** Webhooks list `UiState` ∈ `{Loading, Content(items,isStale,
  isRefreshing), Empty, Error(message,retryable)}`; create `Form` fields
  (`urlError`, `submitError`, `canSubmit`). Analytics `AnalyticsUiState`
  (`isLoading`, `isRefreshing`, `range`, `tiles`, `viewsSeries`, `watchTimeSeries`,
  `topContent`, `trafficSources`, `isStale`, `error`, derived `isEmpty`). Each test
  asserts the **full emitted sequence** via Turbine, not just the terminal value.

## 7. Error Handling & Resilience

This ticket **verifies** the resilience behaviour the features implement:

- **Timeouts:** enqueue `SocketPolicy.NO_RESPONSE`, assert the call fails within the
  call-timeout bound and yields `Error` (with cache → `stale`), not a hang; a shortened
  test client timeout keeps CI fast while exercising the branch.
- **Retry:** GETs — `503,503,200` returns `200` via bounded backoff; assert recorded
  request count equals attempts. POST — `503` yields **no** retry (single request) and
  `Error`/`submitError`.
- **401 refresh:** `401` → `200` for `POST /ui/session/refresh` → original `200`;
  assert three ordered requests and success. Double `401` asserts the re-auth signal
  (no infinite loop).
- **Offline fallback:** seed Room, disconnect, assert cached data with `isStale = true`;
  empty cache → `Error(retryable)`.
- **Partial failure (analytics):** dashboard `200` + breakdown `500` → tiles/charts
  render with an inline breakdown error, page not blocked.
- **Malformed/empty JSON:** a sparse fixture parses to defaults (0 / empty) and
  surfaces as `Empty`, never a crash.

The suite itself is resilient: zero live-host dependence, fixed `Clock`, virtual time,
in-memory persistence, `@After` teardown of MockWebServer/Room/DataStore.

## 8. Security & Privacy

- **Redaction tests.** A logging test captures the test logger output during a list +
  create flow and asserts that webhook `url`, any `secret`, and full webhook ids do not
  appear (only a short id prefix may). For analytics, asserts raw metric values and full
  response bodies are not logged above debug level. This regression-guards AND-398 §10
  and AND-399 §10.
- **Secret one-time handling.** A create test with a `secret` in the response asserts it
  is exposed once to the UI state but never written to Room/DataStore (assert the cached
  entity and any prefs contain no `secret`).
- **No real credentials.** Tests use synthetic cookies/CSRF tokens in the mock cookie
  jar; no real session, account, or PII is embedded in fixtures.
- **Cleartext.** Tests run against `MockWebServer` (localhost) and never the plaintext
  dev host; the suite adds no cleartext-domain config. A test asserts client-side URL
  validation rejects non-`https://` webhook target URLs (AND-398 FR-4).
- **Logout clear.** A test invokes the session-clear hook and asserts the webhooks and
  analytics Room caches are emptied (AND-399 §8).

## 9. Accessibility & i18n

Accessibility is **asserted**, not implemented, here:

- **Compose semantics tests.** Webhook rows expose a merged `contentDescription`
  ("Webhook to {url}, {n} events, {active|disabled}"); analytics KPI tiles read
  "{metric}, {value}, up/down {n} percent"; each analytics chart card exposes a
  text-summary semantics node (`onNodeWithContentDescription` / `assertExists`).
- **No-hardcoded-strings check.** UI tests reference string resources by id, not raw
  literals; a lint/test asserts `feature-webhooks` and `feature-analytics` have no
  hardcoded user-facing text (relies on the project lint baseline).
- **Touch targets / roles.** Tests assert `FilterChip` event selectors and date-range
  chips are individually focusable with the correct role (`Role.Checkbox` /
  `role = Tab`) and ≥ 48dp (`assertTouchHeightIsEqualTo`/`assertHeightIsAtLeast`).
- **i18n formatting.** Repository/VM tests assert locale-aware formatting paths
  (duration `h m`, fraction→percent, signed delta) are exercised by mapper assertions;
  the up/down affordance is verified as not color-only (icon + sign present in state).

## 10. Telemetry & Logging

- **Analytics-event assertions.** A fake/spy tracker injected into the ViewModels
  captures emitted events; tests assert `webhooks_list_viewed` (with `count`),
  `webhook_detail_viewed`, `webhook_create_started/succeeded/failed` (with mapped
  `error_code`), and `analytics_dashboard_viewed` (with `range` only, no metric
  values) fire with the correct properties and no PII/secret payloads.
- **Log redaction assertions.** Covered in §8 — the captured-log test doubles as the
  telemetry-redaction guard.
- **Test logging itself** is minimal; failures surface via assertion messages
  referencing the fixture and the diffed state, not raw response bodies.

## 11. Testing Strategy

This ticket *is* the testing strategy; the matrix below is the deliverable.

**Repository (JVM, MockWebServer + in-memory Room):**
- `DefaultWebhooksRepositoryTest`: list path/verb; detail; create body + `X-CSRF-Token`;
  201 and 200 both accepted; DTO→`Webhook` mapping (incl. `created_at`→`Instant`);
  cache-then-network; write-through on create; GET retry (`503,503,200`); POST no-retry;
  offline-stale fallback; 401→refresh→retry (3 requests); 422 `loc=url`→field error;
  404 detail.
- `AnalyticsRepositoryImplTest`: dashboard query params from fixed `Clock`; DTO→domain
  (seconds→duration, fraction→percent); cache-first stale-then-fresh; TTL staleness;
  backoff `503→200`; no retry on `400`; embedded `previous` vs fallback second-window
  GET delta; breakdown content/source mapping; combined-payload variant; partial
  breakdown failure.
- `ApiErrorMapperTest`: three `detail` shapes → typed error; unknown shape fallback.
- `CsrfRefreshInterceptorTest`: CSRF header attached to unsafe methods; single refresh
  on 401; re-auth signal on double 401.

**ViewModel (JVM, Turbine + `TestDispatcher`):**
- `WebhooksListViewModelTest`: `Loading→Content/Empty/Error`; refresh sets
  `isRefreshing`.
- `CreateWebhookViewModelTest`: `canSubmit` gating; submit success → list refresh;
  failure → `submitError`; `urlError` on invalid URL.
- `WebhookDetailViewModelTest`: cached-entry vs network fetch; 404 not-found state.
- `AnalyticsViewModelTest`: default `LAST_28`; `RangeSelected` persists + re-queries;
  success populates tiles/series/breakdowns/delta; empty→`isEmpty`; error→`error`;
  `Refresh` toggles `isRefreshing`; deterministic query params via `Clock`.

**Compose UI (`createComposeRule` / `createAndroidComposeRule`, Robolectric where
viable):**
- `WebhooksScreensTest`: list rows render (primary "webhooks render"); empty-state CTA;
  detail event list; create submit disabled-until-valid; nav round-trip
  list→create→back→refreshed.
- `AnalyticsScreenTest`: loading skeletons; success tiles/breakdowns/chart-summaries
  (primary "analytics render"); empty copy; error Retry re-queries; stale banner;
  range-chip selection updates values; a11y semantics + 48dp targets.

**Shared:** `core-testing` fixtures + fakes + `MainDispatcherRule` + `MockBackend`.

**CI:** `./gradlew testDebugUnitTest connectedDebugAndroidTest` (or Robolectric
`testDebugUnitTest` for screen tests where the project runs Compose on the JVM); a
coverage task gates the merge.

## 12. Dependencies & Sequencing

- **Hard dependency: AND-401** (Webhooks/analytics ViewModels — state). This ticket
  tests that ViewModel surface and must follow it. The depends-on graph also pulls in
  AND-398 (webhooks list/view/create), AND-399 (analytics dashboards), and transitively
  AND-027 (AuthApi: cookie jar, CSRF/refresh interceptor) and AND-255 (charts), since
  the tests assert behaviour those tickets own.
- **Implicit:** `ApiResult<T>`, `ApiErrorMapper`, base Retrofit/Moshi/OkHttp config,
  Room infrastructure, and `core-testing` scaffolding (`MainDispatcherRule`,
  `MockBackend`, fakes) — added/extended here where missing.
- **Blocks:** none recorded. Acts as the regression gate that lets AND-398/AND-399/
  AND-401 be marked done with confidence.
- **Sequencing within ticket:** (1) `core-testing` harness (rule, `MockBackend`,
  fixtures, fakes); (2) `ApiErrorMapper` + interceptor tests; (3) repository contract
  tests (both features); (4) ViewModel state tests; (5) Compose UI/state-render tests;
  (6) coverage gate + CI wiring.

## 13. Risks & Open Questions

- **OQ-1 (upstream API shapes).** Field names/paths for webhooks (`url` vs
  `target_url`, `events` vs `event_types`) and analytics (combined vs split payload,
  `previous` block presence) are still open in AND-398/AND-399 (their §13). Tests are
  written against the documented fixtures; when those tickets resolve their OQs, the
  fixtures (single source) are updated and the suite re-pins the real contract.
- **OQ-2 (Compose test runtime).** Whether screen tests run as Robolectric JVM tests or
  on-device `connectedAndroidTest` affects CI time and `createComposeRule` vs
  `createAndroidComposeRule`. Default: Robolectric for state-render assertions, one
  instrumented test for the nav round-trip.
- **R1 (flaky timing).** Real-timeout and retry tests risk flakiness; mitigated by
  `TestDispatcher` virtual time, shortened client timeouts in tests, and explicit
  request-count assertions rather than sleeps.
- **R2 (AND-401 state-API drift).** If AND-401 renames/reshapes the `UiState` types,
  these tests break first (by design). The risk is churn if AND-402 lands before
  AND-401 stabilizes — hence the hard dependency ordering.
- **R3 (coverage threshold).** Setting the gate too high on hard-to-reach branches
  (e.g., double-401 re-auth) could block merges; the threshold targets repo + VM line
  coverage and excludes generated/DTO code.

## 14. Acceptance Criteria

AC-1 — **Suite passes.** `testDebugUnitTest` and the Compose UI tests for
`feature-webhooks`, `feature-analytics`, `core-data`, and `core-network` run green in
CI with zero flakes across repeated runs. *(Maps to source acceptance: "Pass.")*

AC-2 — **Webhooks render (UI).** A Compose test renders the webhooks list from a
fixture and asserts a row per webhook with URL, event summary, and status; the
empty-state test asserts a working "Create webhook" CTA.

AC-3 — **Analytics render (UI).** A Compose test renders the dashboards screen from a
seeded fixture and asserts KPI tile labels/values, both time-series chart summaries,
and breakdown rows; loading/empty/error/stale variants each assert their distinct UI.

AC-4 — **HTTP contract pinned.** MockWebServer tests assert correct verbs/paths/query
params/bodies for all §5 endpoints; the webhooks `POST` and unsafe methods carry
`X-CSRF-Token`; a `401` triggers exactly one refresh-and-retry (verified by recorded
requests).

AC-5 — **Mapping + errors.** DTO→domain mapping (incl. seconds→duration,
fraction→percent, `created_at`→`Instant`) and all three FastAPI `detail` shapes are
asserted; 422 `loc=url` maps to the form field error.

AC-6 — **Caching + resilience.** Cache-then-network, write-through on create, GET
retry / POST no-retry, TTL staleness, and offline-stale-vs-empty-cache branches are
each covered by a passing test.

AC-7 — **ViewModel state machines.** Turbine tests assert the full emitted sequences
for both features' ViewModels, including create-form gating and analytics range
persistence with a fixed `Clock`.

AC-8 — **Security/a11y/telemetry guards.** Tests assert no webhook URL/secret in logs,
secret never persisted, non-`https` URLs rejected, logout clears caches, semantics
content-descriptions + 48dp targets exist, and telemetry events fire with correct
(PII-free) properties.

AC-9 — **No live network.** A suite-wide check (or review) confirms no test contacts
`18.222.237.167`; everything is mocked/in-memory and deterministic.

## 15. Definition of Done

- `core-testing` harness extended: `MainDispatcherRule`, `MockBackend`,
  `Webhook`/`Analytics` fixtures (typed builders + JSON resources), and
  `FakeWebhooksRepository`/`FakeAnalyticsRepository`.
- Repository contract tests (`DefaultWebhooksRepositoryTest`,
  `AnalyticsRepositoryImplTest`), error/interceptor tests (`ApiErrorMapperTest`,
  `CsrfRefreshInterceptorTest`), ViewModel tests, and Compose UI tests all implemented
  and green per §11.
- All ACs (§14) demonstrably met; the suite is deterministic and runs without the dev
  host.
- Coverage gate configured for the webhooks + analytics repository and ViewModel paths
  and passing.
- No new production/domain code added; no cleartext domains; no secrets, cookies, CSRF
  tokens, or response bodies logged in release (asserted).
- Lint/detekt/ktlint clean; builds on Gradle 8.9 / AGP 8.7.3 / JDK 17, compileSdk 35,
  minSdk 24.
- CI invokes the suite (`testDebugUnitTest` + the chosen Compose test path) on
  `android-port`; code reviewed and merged.
