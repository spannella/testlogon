---
id: AND-402
title: Webhooks/analytics tests
milestone: M8
epic: E52
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
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
contract — verbs, paths, query params, bodies, the `X-CSRF-Token` header (the web
client sets it from the `ui_csrf` cookie on **every** request, not only unsafe
methods — see §16), DTO→domain mapping, caching, retry/refresh, FastAPI `detail`
error mapping — for both
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
`GET /ui/webhooks`, `GET /ui/webhooks/{endpoint_id}`, and `POST /ui/webhooks` issue the
correct method/path; the POST carries the JSON body `{ "url", "event_types" }`
(CORRECTED — the create request schema `WebhookEndpointCreateReq` uses `event_types`,
not `events`; `url` + `event_types` are the only required fields) and an
`X-CSRF-Token` header; responses deserialize per §5; cache-then-network and
write-through-on-create behaviour holds; GETs retry on transient failure and POST never
auto-retries. (CORRECTED — list path param is `endpoint_id`, not `id`.)

FR-2 — **Analytics repository contract tests.** Assert the real analytics surface —
there is **no** `/ui/analytics/dashboard` and **no** `/ui/analytics/breakdown` endpoint
(CORRECTED, see §16). The web client (`src/api/endpoints/analytics.ts`) composes a
dashboard from discrete GETs: `GET /ui/analytics/overview`, `/ui/analytics/views`,
`/ui/analytics/revenue`, `/ui/analytics/subscribers`, `/ui/analytics/top-content`,
`/ui/analytics/audience`, plus `POST /ui/analytics/refresh`. Each takes
`?from_date=YYYY-MM-DD&to_date=YYYY-MM-DD` (CORRECTED — params are `from_date`/`to_date`,
not `start`/`end`; `granularity` is optional on views/revenue/subscribers, not the
fixed `day` the draft claimed). Tests assert correct method/path/query params from a
fixed `Clock`; DTO→domain mapping including watch-time seconds→duration and
cents→currency (revenue/top-content values are integer `*_cents`, not fractions — there
is no fraction→percent on these tiles); cache-first emits stale-then-fresh; bounded
backoff retries 5xx then succeeds. There is **no** embedded `previous`/prior-window
delta block in `AnalyticsOverviewOut` (CORRECTED); any period-over-period comparison the
ViewModel shows must be derived by a second windowed GET, and the test exercises that
path only if AND-399 confirms it (otherwise the delta tile is unverified — §16).

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
AND-399 via fixtures and assertions. The shapes below were **re-verified against the
backend OpenAPI and the web reference** during this review and several were corrected;
the audit trail is in §16.

**Webhooks list** — `GET /ui/webhooks` → 200. CORRECTED: the response is a **bare JSON
array** of `WebhookEndpointOut`, not an envelope object with a `webhooks` key
(`src/api/endpoints/webhooks.ts: listWebhookEndpoints` returns `WebhookEndpointOut[]`):

```json
[
  { "endpoint_id": "wh_01HX...", "url": "https://example.com/hooks/tl",
    "event_types": ["session.finalized", "mfa.verified"], "enabled": true,
    "signature_version": "v2", "secret": null,
    "created_at": 1747073051, "updated_at": 1747073051,
    "failure_count": 0, "circuit_consecutive_failures": 0 } ]
```

Field corrections vs the draft: `endpoint_id` (not `id`), `event_types` (not `events`),
`enabled` (not `active`); **no** `secret_set` field (the schema exposes a nullable
`secret`); `created_at`/`updated_at` are **integer epoch seconds**, not ISO-8601 strings,
so the DTO→domain mapping is epoch-seconds→`Instant` (CORRECTED from the draft's
`created_at`→`Instant` ISO assumption). Only `endpoint_id` and `url` are required.

**Webhook detail** — `GET /ui/webhooks/{endpoint_id}` → 200 `WebhookEndpointOut` (the
same element shape). The OpenAPI declares only `200:WebhookEndpointOut` and
`422:HTTPValidationError` for this op; a **404** is **not** declared in the spec
(UNVERIFIED — the not-found branch is an assumption; test it defensively but treat the
exact status as an open item, §16).

**Webhook create** — `POST /ui/webhooks`, body `WebhookEndpointCreateReq`
`{ "url", "event_types" }` (optional: `description`, `signature_version` (`v1|v2|both`,
default `v2`), `circuit_failure_threshold` (3–100), `retry_policy`) → **201** with the
created `WebhookEndpointOut` (server `endpoint_id`, epoch `created_at`, optional one-time
`secret`). CORRECTED: the OpenAPI declares **201 only** — the draft's "201|200, both
accepted" is wrong; the test asserts **201** is the success status (a lenient client may
also accept 200, but 201 is the contract). The request must carry `X-CSRF-Token`.

**Analytics dashboard** — CORRECTED: there is **no single `/ui/analytics/dashboard`
endpoint** and **no `/ui/analytics/breakdown` endpoint**. The dashboard is assembled
client-side from discrete GETs, each taking `?from_date&to_date` (and optional
`granularity` on the time-series ones):

- `GET /ui/analytics/overview` → `AnalyticsOverviewOut`:

```json
{ "period_views": 184320, "period_revenue_cents": 9421800,
  "period_new_subscribers": 1372, "total_subscribers": 51240,
  "top_content": [ { "content_id": "c_01", "content_type": "video",
    "title": "Sample", "views": 6210, "revenue_cents": 318400,
    "engagement_rate": 0.0613 } ], "currency": "USD" }
```

  There is **no** `range`, `summary`, `previous`, or top-level `timeseries` block, and
  no top-level `engagement_rate` fraction (CORRECTED — the draft's payload was
  fabricated). `engagement_rate` exists only per `AnalyticsTopContentItem`.
- `GET /ui/analytics/views` → `AnalyticsViewsOut`: `{ time_series:[{date, views,
  unique_viewers, watch_time_seconds}], total_views, total_watch_time_seconds }`.
- `GET /ui/analytics/revenue` → `AnalyticsRevenue`: `{ total_cents, breakdown{...},
  time_series:[{date, total_cents, tips_cents, ...}], currency }` (all `*_cents`).
- `GET /ui/analytics/subscribers` → `{ time_series:[{date, new, churned, net, total}],
  current_total, net_change }`.
- `GET /ui/analytics/top-content` → `{ items: AnalyticsTopContentItem[], total_items }`.
- `GET /ui/analytics/audience` → `{ countries:[{code,name,viewers,percentage}],
  devices:[{type,viewers,percentage}] }`.
- `POST /ui/analytics/refresh` → `AnalyticsRefreshOut` (the manual-refresh action).

**Analytics breakdown** — CORRECTED: there is no generic `dimension`/`share` breakdown
endpoint. The equivalent surfaces are **top-content** (revenue/engagement per content
item, values in `revenue_cents` — not a `share` fraction) and **audience**
(`countries`/`devices`, each with an integer `viewers` and a `percentage`). Tests cover
these two real surfaces; the draft's `{content|source}` dimension + `share`/`limit`
combined-payload variant does **not** exist and is removed.

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
  validation rejects non-`https://` webhook target URLs (AND-398 FR-4). NOTE: this is a
  **client-side** rule — `WebhookEndpointCreateReq.url` is an unconstrained string in the
  OpenAPI (no `format`/pattern), so the https-only requirement is an app/AND-398
  decision, not a backend-enforced contract (§16).
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
- `DefaultWebhooksRepositoryTest`: list path/verb (bare-array response); detail
  (`{endpoint_id}`); create body `{url, event_types}` + `X-CSRF-Token`; **201** success
  status; DTO→`Webhook` mapping (incl. epoch-seconds `created_at`→`Instant`);
  cache-then-network; write-through on create; GET retry (`503,503,200`); POST no-retry;
  offline-stale fallback; 401→refresh→retry (3 requests); 422 `loc=["body","url"]`→field
  error; detail not-found branch (status defensive — see §16 open item).
- `AnalyticsRepositoryImplTest`: per-endpoint query params (`from_date`/`to_date`) from
  fixed `Clock`; DTO→domain (watch-time seconds→duration, cents→currency string);
  cache-first stale-then-fresh; TTL staleness; backoff `503→200`; no retry on `400`;
  multi-call dashboard assembly (overview + views + revenue + subscribers + top-content
  + audience) and partial failure of one sub-call not blocking the rest. (No
  `dashboard`/`breakdown` endpoints, no embedded `previous` delta — see §5/§16.)
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

- **OQ-1 (upstream API shapes) — RESOLVED during this review.** The field names/paths
  are now pinned against the backend OpenAPI and the web client (§5, §16): webhooks use
  `url` + `event_types` with `endpoint_id`/`enabled` (not `events`/`id`/`active`); the
  list is a bare array; create returns 201. Analytics is **split** across discrete
  per-metric endpoints (overview/views/revenue/subscribers/top-content/audience) with
  `from_date`/`to_date` params — there is **no** combined `dashboard` payload and **no**
  `previous` delta block. The remaining genuinely-open items are tracked in §16 (Open
  assumptions): the webhook-detail not-found status, and whether AND-399 derives a
  period-over-period delta via a second windowed GET.
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. Sources: backend
OpenAPI index (`openapi.index.txt`), full spec (`openapi.pretty.json`,
`components.schemas.<Name>`), the web reference under `src/`, or an Android docs URL
(labelled `framework ref`).

1. **Webhooks list endpoint = `GET /ui/webhooks`.** Verified.
   OpenAPI `GET /ui/webhooks` (op `list_webhook_endpoints_ui_webhooks_get`);
   `src/api/endpoints/webhooks.ts: listWebhookEndpoints`.
2. **List response is a bare `WebhookEndpointOut[]` array, not `{ "webhooks": [...] }`.**
   Corrected (draft claimed an envelope). `src/api/endpoints/webhooks.ts:
   listWebhookEndpoints` returns `api.get<WebhookEndpointOut[]>("/ui/webhooks")`.
3. **Create endpoint = `POST /ui/webhooks`, body `WebhookEndpointCreateReq`, → 201.**
   Corrected (draft said "201|200 both accepted"). OpenAPI
   `POST /ui/webhooks | req=WebhookEndpointCreateReq | resp=201:;422:HTTPValidationError`;
   `src/api/endpoints/webhooks.ts: createWebhookEndpoint`.
4. **Create body field is `event_types` (+ `url`), not `events`.** Corrected.
   `components.schemas.WebhookEndpointCreateReq` required `["url","event_types"]`
   (optional `description`, `signature_version` `^(v1|v2|both)$` default `v2`,
   `circuit_failure_threshold` 3–100, `retry_policy`).
5. **`WebhookEndpointOut` identifier is `endpoint_id`, not `id`.** Corrected.
   `components.schemas.WebhookEndpointOut` required `["endpoint_id","url"]`.
6. **Active flag is `enabled` (boolean, default true), not `active`; no `secret_set`
   field — `secret` is a nullable string.** Corrected.
   `components.schemas.WebhookEndpointOut.enabled` / `.secret`.
7. **`created_at`/`updated_at` are integer epoch seconds, not ISO-8601 strings; mapping
   is epoch→`Instant`.** Corrected (draft mapped `created_at`(ISO)→`Instant`).
   `components.schemas.WebhookEndpointOut.created_at` (`type: integer`, default 0).
8. **Webhook detail = `GET /ui/webhooks/{endpoint_id}` → `WebhookEndpointOut`; path
   param is `endpoint_id`.** Corrected (draft used `{id}`).
   OpenAPI `GET /ui/webhooks/{endpoint_id} | resp=200:WebhookEndpointOut;422`;
   `src/api/endpoints/webhooks.ts: getWebhookEndpoint`.
9. **Webhook detail 404 not-found path.** Unverified-assumption. The OpenAPI op declares
   only `200:WebhookEndpointOut` and `422:HTTPValidationError`; no 404 is documented.
   Treat the not-found status as defensive (see Open assumptions).
10. **Event types come from `GET /ui/webhooks/event-types` → `{ event_types: [...] }`.**
    Verified. OpenAPI `GET /ui/webhooks/event-types`;
    `src/api/endpoints/webhooks.ts: listWebhookEventTypes`.
11. **No `/ui/analytics/dashboard` endpoint exists.** Corrected (draft's central claim).
    No such path in `openapi.index.txt`; the web client has no `getAnalyticsDashboard`.
    Dashboard is composed from discrete GETs in `src/api/endpoints/analytics.ts`.
12. **No `/ui/analytics/breakdown` endpoint exists.** Corrected.
    No such path in `openapi.index.txt` under `/ui/analytics/*` (the only `breakdown`
    is `/ui/ads/analytics/breakdown`, a different ads surface). Equivalent real surfaces
    are top-content and audience.
13. **Analytics endpoints used: overview / views / revenue / subscribers / top-content /
    audience, + `POST /ui/analytics/refresh`.** Verified.
    OpenAPI `GET /ui/analytics/overview` (`AnalyticsOverviewOut`), `/views`
    (`AnalyticsViewsOut`), `/revenue` (`AnalyticsRevenueOut`), `/subscribers`
    (`AnalyticsSubscribersOut`), `/top-content` (`AnalyticsTopContentOut`), `/audience`
    (`AnalyticsAudienceOut`), `POST /ui/analytics/refresh` (`AnalyticsRefreshOut`);
    `src/api/endpoints/analytics.ts`.
14. **Analytics query params are `from_date`/`to_date` (+ optional `granularity`), not
    `start`/`end`/`granularity=day`.** Corrected.
    OpenAPI params on each `/ui/analytics/*` op; `src/api/types.ts:
    AnalyticsDateRangeParams` (`from_date?`, `to_date?`, `granularity?`).
15. **`AnalyticsOverviewOut` has no `summary`/`previous`/`timeseries`/top-level
    `engagement_rate` (fraction).** Corrected (draft's payload was fabricated).
    `components.schemas.AnalyticsOverviewOut` = `{ period_views, period_revenue_cents,
    period_new_subscribers, total_subscribers, top_content[], currency }`;
    `src/api/types.ts: AnalyticsOverview`.
16. **Revenue/top-content monetary values are integer `*_cents`; mapping is
    cents→currency, not fraction→percent.** Corrected (draft asserted fraction→percent).
    `src/api/types.ts: AnalyticsRevenue` (`total_cents`, `*_cents`),
    `AnalyticsTopContentItem.revenue_cents`.
17. **Watch time is `watch_time_seconds`; seconds→duration mapping is valid.** Verified.
    `src/api/types.ts: AnalyticsViewsTimeSeriesItem.watch_time_seconds`,
    `AnalyticsViews.total_watch_time_seconds`.
18. **`engagement_rate` exists only per top-content item (a fraction).** Verified.
    `src/api/types.ts: AnalyticsTopContentItem.engagement_rate`; a standalone
    `GET /ui/analytics/engagement` (`EngagementRateOut`) also exists.
19. **Period-over-period delta tile.** Unverified-assumption. No `previous` block in any
    analytics schema; any delta must be a second windowed GET. Whether AND-399 does this
    is an AND-399 decision, not in the backend contract.
20. **`X-CSRF-Token` header from the `ui_csrf` cookie.** Verified, with nuance.
    `src/api/client.ts` sets `X-CSRF-Token` whenever the `ui_csrf` cookie exists — on
    **every** request including GETs, not only unsafe methods (the draft implied
    unsafe-only). Tests may still focus assertions on POST but should not assume GETs
    omit it.
21. **401 → single `POST /ui/session/refresh` → retry original once; double-401 →
    logout/re-auth.** Verified. `src/api/client.ts: refreshSession` and the 401 branch
    (shared in-flight `refreshPromise`; retry once; on retry-401
    `useAuthStore.logout("session_expired")`).
22. **FastAPI `detail` has three shapes: string | `[{msg}]` | object with `code`/`msg`;
    422 maps a `loc`-targeted field error.** Verified. `src/api/client.ts:
    normalizeErrorDetail` + `mapAuthorizationError` (handles string, array-of-`{msg}`,
    and object-with-`code`); 422 bodies are `HTTPValidationError` whose items carry
    `loc`/`msg` (OpenAPI `components.schemas.HTTPValidationError` /
    `ValidationError.loc`).
23. **`Authorization: Bearer <accessToken>` + `X-IMPERSONATION-TOKEN` (when
    impersonating) are the web auth headers; the client does not set `X-SESSION-ID`.**
    Verified. `src/api/client.ts` header block. NOTE: OpenAPI lists `X-SESSION-ID` /
    `X-IMPERSONATION-TOKEN` / `user_sub` as op params, but `X-SESSION-ID` is
    cookie/session-derived server-side, not sent explicitly by the web client — the
    Android transport should mirror the web client.
24. **Webhook `url` https-only validation is client-side.** Verified as client-side.
    `components.schemas.WebhookEndpointCreateReq.url` is an unconstrained `string` (no
    `format`/pattern), so https-only is an app/AND-398 rule, not backend-enforced.
25. **Stack/test-tooling choices (Compose UI test, Robolectric, MockWebServer,
    coroutines-test).** Verified — framework refs:
    Compose testing `https://developer.android.com/develop/ui/compose/testing`;
    `kotlinx-coroutines-test`
    `https://developer.android.com/kotlin/coroutines/test`;
    Robolectric `https://robolectric.org/`.
26. **Headless emulator vs physical device targeting.** Verified — framework ref:
    `adb` device selection `https://developer.android.com/tools/adb`. Physical device on
    host: Samsung Galaxy A15 5G (SM-A156U, serial `R5CX821TA9R`, Android 14 / API 34,
    arm64-v8a); CI AVD `test35` (x86_64, API 35).

### Corrections made

- §1, §3 (FR-1): webhook create body `events` → `event_types`; list path param
  `{id}` → `{endpoint_id}`.
- §3 (FR-2), §5, §11: removed the non-existent `/ui/analytics/dashboard` and
  `/ui/analytics/breakdown` endpoints; replaced with the real per-metric endpoints and
  `from_date`/`to_date` params (was `start`/`end`/`granularity=day`).
- §5 (webhooks): list response `{ "webhooks": [...] }` → bare array; `id` → `endpoint_id`;
  `active` → `enabled`; removed `secret_set`; `created_at` ISO string → integer epoch
  seconds; create "201|200 both accepted" → **201**.
- §5 (analytics): replaced the fabricated `summary`/`previous`/`timeseries`/
  `engagement_rate` dashboard payload with the verified `AnalyticsOverviewOut` and
  sibling schemas; removed the `{content|source}` + `share` breakdown variant.
- §3/§11: analytics mapping "fraction→percent" → "cents→currency" for monetary tiles
  (watch-time seconds→duration retained, which is correct).
- §1, §8: clarified `X-CSRF-Token` is sent on all requests, and that https-only URL
  validation is client-side.
- §13: OQ-1 marked resolved with the pinned shapes.

### Open assumptions

- **Webhook-detail not-found status (claim 9).** OpenAPI documents no 404 for
  `GET /ui/webhooks/{endpoint_id}`; the not-found UI branch is tested defensively but the
  exact status code is unconfirmed — depends on AND-398's server behaviour.
- **Period-over-period delta (claim 19).** No backend `previous` block; whether AND-399
  computes a delta via a second windowed GET is an upstream design decision, not a
  verifiable contract. The delta test is gated on AND-399 confirming it.
- **ViewModel state surface (range presets `LAST_7`/`LAST_28`, `UiState` shape, telemetry
  event names).** Owned by AND-401/AND-398/AND-399; not derivable from the backend or web
  reference (the web client uses raw `from_date`/`to_date`, not named presets). Tests pin
  whatever AND-401 ships; these break-first if AND-401 reshapes the state API (§13 R2).
- **`X-SESSION-ID` transport on Android (claim 23).** The web client relies on cookies;
  how the Android client supplies session identity (cookie jar vs explicit header) is an
  AND-027 decision and assumed to mirror the web cookie-based flow.

## 17. Test Plan

Test targets: **JVM** = JVM unit/Robolectric (local, no device); **AVD test35** =
headless emulator (x86_64, API 35) on the CI build server; **physical** = Samsung Galaxy
A15 5G (SM-A156U, serial `R5CX821TA9R`, Android 14 / API 34, arm64-v8a) on the build
host. This is a test-only ticket with all network mocked, so most cases run on JVM; UI
cases run on AVD test35 (or Robolectric on JVM). A physical-device case is included only
where real ABI/API behaviour matters.

- **TC-AND-402-01 — Webhooks list happy path + DTO mapping.**
  Type: contract/MockWebServer. Target: JVM (`DefaultWebhooksRepositoryTest`).
  Preconditions: MockBackend started; in-memory Room empty; `WebhookFixtures` list
  resource loaded.
  Steps: enqueue 200 with a bare `WebhookEndpointOut[]`; call `repo.list()`.
  Expected: exactly one `GET /ui/webhooks`; result maps `endpoint_id`, `url`,
  `event_types`, `enabled`, epoch `created_at`→`Instant`; rows upserted to
  `WebhooksDao` with a `fetched_at`. No `webhooks` envelope expected.
  Traces: AC-4, AC-5, AC-6.

- **TC-AND-402-02 — Webhook create: body, CSRF, 201.**
  Type: contract/MockWebServer. Target: JVM (`DefaultWebhooksRepositoryTest`).
  Preconditions: synthetic `ui_csrf` cookie in the mock cookie jar.
  Steps: enqueue **201** with the created `WebhookEndpointOut`; call
  `repo.create(url, eventTypes)`.
  Expected: one `POST /ui/webhooks`; recorded body JSON has keys `url` and
  `event_types` (no `events`); `X-CSRF-Token` header present; 201 treated as success;
  write-through upsert occurs before the list refresh.
  Traces: AC-4, AC-6.

- **TC-AND-402-03 — Webhook create 422 maps `loc=["body","url"]` to field error.**
  Type: contract/MockWebServer. Target: JVM (`DefaultWebhooksRepositoryTest` +
  `ApiErrorMapperTest`).
  Preconditions: 422 `HTTPValidationError` fixture with
  `detail:[{loc:["body","url"], msg:"invalid url"}]`.
  Steps: enqueue 422; call `repo.create(...)`.
  Expected: POST issued once (no retry); error maps to a field-level `urlError`, not a
  generic banner; the `msg` string is surfaced.
  Traces: AC-5.

- **TC-AND-402-04 — GET retry vs POST no-retry.**
  Type: contract/MockWebServer. Target: JVM (`DefaultWebhooksRepositoryTest`).
  Preconditions: shortened test client timeouts.
  Steps: (a) enqueue `503,503,200` then call `repo.list()`; (b) enqueue `503` then call
  `repo.create()`.
  Expected: (a) succeeds; recorded request count = 3 via bounded backoff; (b) exactly
  **one** `POST` recorded, result is `Error`/`submitError`.
  Traces: AC-6.

- **TC-AND-402-05 — 401 → single refresh → retry (interceptor).**
  Type: contract/MockWebServer. Target: JVM (`CsrfRefreshInterceptorTest`).
  Preconditions: authenticated session state.
  Steps: enqueue `401` for `GET /ui/webhooks`, then `200` for
  `POST /ui/session/refresh`, then `200` for the retried GET.
  Expected: exactly three ordered requests (`GET 401`, `POST /ui/session/refresh`,
  `GET 200`); final result success. Double-401 variant: second 401 emits the re-auth/
  logout signal with no infinite loop. CSRF header asserted present on the POST.
  Traces: AC-4.

- **TC-AND-402-06 — FastAPI `detail` shape mapping (all three).**
  Type: unit. Target: JVM (`ApiErrorMapperTest`).
  Preconditions: three fixtures — string detail; `[{msg}]`; `{code, ...}`.
  Steps: feed each to `ApiErrorMapper`.
  Expected: each maps to the typed error with the human message; the `{code}` shape
  honours known codes (e.g. `role_required_scope`); unknown shape → fallback message.
  Traces: AC-5.

- **TC-AND-402-07 — Analytics multi-endpoint dashboard assembly + params.**
  Type: contract/MockWebServer. Target: JVM (`AnalyticsRepositoryImplTest`).
  Preconditions: fixed `Clock` (`2026-06-05T00:00:00Z`); fixtures for overview/views/
  revenue/subscribers/top-content/audience.
  Steps: enqueue 200 for each; call `repo.loadDashboard(range)`.
  Expected: one GET per endpoint to `/ui/analytics/{overview,views,revenue,subscribers,
  top-content,audience}` each carrying `from_date`/`to_date` derived from the `Clock`
  (no `start`/`end`); mapping yields watch-time seconds→duration and `*_cents`→currency;
  no request to a (non-existent) `/ui/analytics/dashboard` or `/ui/analytics/breakdown`.
  Traces: AC-4, AC-5.

- **TC-AND-402-08 — Analytics partial sub-call failure does not block the page.**
  Type: contract/MockWebServer. Target: JVM (`AnalyticsRepositoryImplTest`).
  Preconditions: as TC-07.
  Steps: enqueue 200 for overview/views/revenue/subscribers/top-content and **500** for
  audience.
  Expected: tiles + charts from the successful calls render; audience surfaces an inline
  section error; the overall load is not failed/blocked.
  Traces: AC-3, AC-6.

- **TC-AND-402-09 — Cache-first stale-then-fresh + TTL + offline.**
  Type: contract/MockWebServer + Room. Target: JVM (`AnalyticsRepositoryImplTest`).
  Preconditions: in-memory Room seeded with a dashboard row whose `fetchedAt` is beyond
  the 15-min TTL.
  Steps: (a) call load → assert stale emission then fresh after network 200;
  (b) simulate offline (`SocketPolicy.NO_RESPONSE` / disconnect) with cache present →
  assert cached data with `isStale=true`; (c) empty cache + offline → `Error(retryable)`.
  Expected: emission order via Turbine matches; no hang within the call-timeout bound.
  Traces: AC-6.

- **TC-AND-402-10 — ViewModel state machines (Turbine).**
  Type: unit. Target: JVM (`WebhooksListViewModelTest`, `CreateWebhookViewModelTest`,
  `AnalyticsViewModelTest`) with `MainDispatcherRule` + fakes + fixed `Clock`.
  Preconditions: `FakeWebhooksRepository`/`FakeAnalyticsRepository` programmable.
  Steps: drive list `Loading→Content/Empty/Error`; create-form `canSubmit` gating
  (invalid URL, no event types, valid) and submit-success→list-refresh /
  submit-failure→`submitError`; analytics `RangeSelected` persists to DataStore +
  re-queries, `Refresh` toggles `isRefreshing`, empty payload→`isEmpty`, error→`error`.
  Expected: full emitted sequences match; DataStore round-trip restores the saved range
  in a fresh ViewModel.
  Traces: AC-7.

- **TC-AND-402-11 — Webhooks Compose render (primary "webhooks render").**
  Type: Compose-UI. Target: AVD test35 (or Robolectric on JVM).
  Preconditions: stateless screens driven with fixture `UiState`.
  Steps: set content with a non-empty list state; with empty state; with detail state;
  with create-form state.
  Expected: a row per webhook showing URL, event-count summary, and enabled/disabled
  status; empty state shows a working "Create webhook" CTA; detail shows the event list;
  create submit disabled until URL valid + ≥1 event type.
  Traces: AC-2.

- **TC-AND-402-12 — Analytics Compose render incl. stale/empty/error (primary
  "analytics render").**
  Type: Compose-UI. Target: AVD test35 (or Robolectric on JVM).
  Preconditions: fixture states for loading/success/empty/error/stale.
  Steps: render each variant; tap Retry in the error state.
  Expected: loading shows skeletons; success shows KPI tile labels/values + both
  time-series chart text-summaries + top-content/audience rows; empty shows empty copy;
  error shows a Retry that re-queries; stale banner appears when `isStale`.
  Traces: AC-3.

- **TC-AND-402-13 — Accessibility semantics + touch targets.**
  Type: Compose-UI (instrumented). Target: AVD test35.
  Preconditions: real semantics tree (instrumented, not pure JVM).
  Steps: query merged `contentDescription` on webhook rows and KPI tiles; assert chip
  roles and heights.
  Expected: webhook row reads "Webhook to {url}, {n} events, {enabled|disabled}"; KPI
  tile reads "{metric}, {value}, up/down {n} percent" with a non-color-only up/down
  affordance; event `FilterChip`s and date chips are individually focusable with the
  correct role and ≥48dp (`assertHeightIsAtLeast(48.dp)`).
  Traces: AC-8, AC-3.

- **TC-AND-402-14 — Security guards: no secret/URL in logs, secret not persisted,
  https-only, logout clears caches.**
  Type: unit + contract. Target: JVM (repository + logging tests).
  Preconditions: test logger capture; create response containing a one-time `secret`.
  Steps: run a list+create flow; inspect captured logs; inspect Room/DataStore;
  attempt to create with an `http://` URL; invoke the session-clear hook.
  Expected: logs contain no webhook `url`, no `secret`, no full `endpoint_id`
  (short prefix only); the `secret` reaches UI state once but is never written to
  Room/DataStore; `http://` URL is rejected client-side before any request; logout
  empties both webhooks and analytics caches.
  Traces: AC-8.

- **TC-AND-402-15 — Determinism / no-live-network + ABI/API parity smoke.**
  Type: instrumented/e2e. Target: **physical** (Samsung A15 5G, arm64-v8a, API 34) —
  MUST run on the physical device to confirm the suite behaves identically on real
  arm64-v8a / API 34 hardware vs the x86_64 / API 35 emulator (no JVM-only assumptions,
  no x86-specific timing).
  Preconditions: app test APK installed via `adb -s R5CX821TA9R`.
  Steps: run the instrumented subset (nav round-trip list→create→back→refreshed via the
  fake repository) and a network-egress assertion.
  Expected: no test contacts `18.222.237.167`; suite is order-independent and green;
  results match the AVD test35 run (no ABI/API divergence).
  Traces: AC-1, AC-9.

### Coverage matrix

| Acceptance criterion (§14) | Covered by |
| --- | --- |
| AC-1 — Suite passes / green / no flakes | TC-15 (+ all TCs are members of the suite) |
| AC-2 — Webhooks render (UI) | TC-11 |
| AC-3 — Analytics render (UI) | TC-08, TC-12, TC-13 |
| AC-4 — HTTP contract pinned (verbs/paths/params/CSRF/401) | TC-01, TC-02, TC-05, TC-07 |
| AC-5 — Mapping + errors (DTO→domain, `detail` shapes, 422 field) | TC-01, TC-03, TC-06, TC-07 |
| AC-6 — Caching + resilience (cache/retry/TTL/offline) | TC-01, TC-02, TC-04, TC-08, TC-09 |
| AC-7 — ViewModel state machines | TC-10 |
| AC-8 — Security/a11y/telemetry guards | TC-13, TC-14 |
| AC-9 — No live network | TC-15 |
