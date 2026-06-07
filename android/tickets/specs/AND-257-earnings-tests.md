---
id: AND-257
title: Earnings tests
milestone: M6
epic: E34
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-256, AND-251]
blocks: []
---

# AND-257 — Earnings tests

## 1. Overview & Goal

This ticket delivers the automated test suite for the Earnings feature of the
TestLogon native Android app (`com.testlogon.android`). The Earnings feature
comprises three production layers built in upstream tickets: the network/DTO
layer (`AND-251`, `earnings.ts`-equivalent Retrofit service plus Moshi DTOs for
the summary, time-series, quick-stats, and transactions payloads), the
repository layer that maps DTOs to domain models and exposes `ApiResult<T>`
flows, and the `EarningsViewModel` (`AND-256`) that owns date-range / preset
selection and `StateFlow<EarningsUiState>`.

> REVIEW NOTE (2026-06-06): The web reference at
> `reference/src/api/endpoints/earnings.ts` exposes exactly three GETs —
> `/ui/earnings/summary`, `/ui/earnings/transactions`, `/ui/earnings/quick-stats`.
> There is **no** `/ui/earnings/series` endpoint. The time series is returned
> *inside* `EarningsSummaryOut.time_series`. Amounts are in **cents** (`*_cents`),
> not "minor units". The server takes `from_date`/`to_date` (YYYY-MM-DD) +
> `granularity` (day|week|month), **not** a `range` enum. See §16 for the full
> audit; the original §4.1/§5 signatures below have been corrected accordingly.

The goal of `AND-257` is **not** to add product behavior but to lock the
behavior of those layers with fast, deterministic tests so regressions are
caught in CI. Concretely we deliver: (a) **repository/unit tests** covering DTO
deserialization, DTO→domain mapping, range parameterization, FastAPI `detail`
error mapping, and the offline/stale paths; and (b) **UI/instrumentation
tests** covering `EarningsViewModel` state transitions and the Compose
`EarningsScreen` rendering for each `EarningsUiState` variant plus the range
selector interaction. The single acceptance bar from the backlog is **"Pass"**:
the suite must be green and run under CI as part of the `feature-earnings`
module's `test` and `connectedAndroidTest` (or Robolectric) checks.

## 2. Context & References

- **Backlog ticket:** `AND-257 — Earnings tests`, Type: Test, Priority: P2,
  Deps: `AND-256`. Scope: "Repo + UI tests." Acceptance: "Pass."
- **Upstream feature tickets under test:**
  - `AND-251` — Earnings API + DTOs (`summary`, `series`).
  - `AND-256` — Earnings ViewModel (range selection, state).
  - `AND-251` transitively depends on `AND-027` (core-network/Retrofit/OkHttp +
    cookie jar + CSRF interceptor + `ApiResult` plumbing).
- **Module:** `feature-earnings` (layer: `app -> feature-earnings -> core-*`).
  Tests in this ticket live in `feature-earnings/src/test` (JVM/Robolectric) and
  `feature-earnings/src/androidTest` (instrumented Compose), using shared fakes
  from `core-testing`.
- **Web reference:** `src/api/endpoints/earnings.ts` and shared types
  in `src/api/types.ts` define the canonical request/response shapes
  mirrored by the Kotlin DTOs; the FastAPI source of truth is
  `/openapi.json` on the dev backend `http://18.222.237.167:8000` (plaintext
  HTTP, unreliable dev host). VERIFIED against `openapi.index.txt` /
  `openapi.pretty.json`: schemas `EarningsSummaryOut`, `TimeSeriesPoint`,
  `EarningsBreakdown`, `EarningsQuickStatsOut`, `EarningsTransactionsOut`,
  `EarningsTransactionOut`.
- **Auth context:** Earnings endpoints are authenticated and ride the
  cookie-based session (`ui_csrf` cookie echoed as `X-CSRF-Token`, single
  `POST /ui/session/refresh` retry on 401). VERIFIED against
  `src/api/client.ts`: the wrapper reads the `ui_csrf` cookie, sets the
  `X-CSRF-Token` header, sends `credentials: "include"`, and on a 401 (only when
  already authenticated) performs **one** de-duplicated `POST /ui/session/refresh`
  then retries the original request once; a second 401 logs the user out (no
  loop). It also forwards `Authorization: Bearer <accessToken>` and, when active,
  `X-IMPERSONATION-TOKEN`. Tests use a stubbed `MockWebServer` and never hit the
  live backend.

## 3. Functional Requirements

The test suite (the deliverable) must verify the following production behaviors.
Each is testable and maps to assertions below.

- **FR-1 (Summary mapping):** A well-formed `GET /ui/earnings/summary` JSON body
  deserializes into `EarningsSummaryDto` (`total_cents`, `breakdown`,
  `time_series`, `transaction_count`, `currency`) and maps to the
  `EarningsSummary` domain model with cent-precision totals, the category
  breakdown, and the time series preserved. (CORRECTED: server has no
  `delta_pct_from_prev` and no `period_start`/`period_end` on summary; amounts
  are `*_cents`, not `*_minor`.)
- **FR-2 (Time-series mapping):** The `time_series` array nested inside
  `EarningsSummaryOut` deserializes into `List<TimeSeriesPoint>` — each point has
  `date` (string, required) plus per-category cents (`total`, `subscriptions`,
  `tips`, `unlocks`, `vod_purchases`, `other`) — mapped to
  `List<EarningsPoint>` ordered by `date` ascending. (CORRECTED: there is no
  separate `/ui/earnings/series` endpoint and no `amount_minor` field.)
- **FR-3 (Range parameterization):** The repository translates a UI preset
  (`7d`, `30d`, `90d`, `1y`, `All`) into the correct `from_date`/`to_date`
  (`YYYY-MM-DD`, UTC; `All` omits both) plus `granularity` (`day`|`week`|`month`,
  default `day`) query parameters. (CORRECTED: the server accepts
  `from_date`/`to_date`/`granularity`/`from_ts`/`to_ts`, NOT a `range` enum;
  the web client computes dates client-side via `daysAgo(n)`.)
- **FR-4 (ViewModel range selection):** Selecting a new preset/granularity via
  `onRangeSelected` re-fetches and produces the expected ordered
  `StateFlow<EarningsUiState>` emissions (Loading → Success), and rapid
  selections cancel the in-flight request (latest-wins).
- **FR-5 (Error mapping):** A FastAPI `detail` payload maps to a typed
  `ApiError`, and the ViewModel surfaces `EarningsUiState.Error` with a
  user-facing message. NOTE: the documented OpenAPI error for these endpoints is
  **422 `HTTPValidationError`** with `detail: [{loc, msg, type}]` (array form).
  The string form (`detail: "..."`) and object form (`detail: {code, message}`)
  are handled by the web client's `normalizeErrorDetail` (e.g. 403
  `{code: ...}`), so the Android `ApiError` mapper must accept all three; only
  the array form is contract-guaranteed for earnings.
- **FR-6 (Offline/stale):** Android-only behavior NOT present in the web client.
  With no network and a cached prior payload, the ViewModel emits
  `Success(isStale = true)`; with no cache it emits `Error(offline = true)`.
  (UNVERIFIED against backend/web — this is an Android product decision from
  AND-256; see §16 Open assumptions.)
- **FR-7 (Resilience):** A 401 triggers exactly one `POST /ui/session/refresh`
  then one retry (VERIFIED in `src/api/client.ts`). The bounded-backoff retry on
  a transient 503 for idempotent GETs is an Android `core-network` policy NOT
  present in the web client (UNVERIFIED; see §16).
- **FR-8 (Screen rendering):** `EarningsScreen` renders the loading skeleton,
  the populated chart + summary, the empty state, the error state with retry,
  and the stale banner — one Compose test per state — and the range chips are
  selectable and reflect `selectedRange`.

## 4. Technical Design

### 4.1 Production surface under test (as built by AND-251/256)

The tests are written against these signatures. They are reproduced here so the
test code compiles against the agreed contract; if upstream signatures drift,
the tests are the failing tripwire.

> CORRECTED to match `EarningsSummaryOut` / `TimeSeriesPoint` / `EarningsBreakdown`
> in the OpenAPI spec and `src/api/types.ts`. The previous draft used
> `totalMinor`/`amountMinor`/`deltaPctFromPrev`/`period*` and an `EarningsRange`
> enum — none of which exist in the backend contract.

```kotlin
// core-model
data class EarningsBreakdown(            // EarningsBreakdown
    val subscriptionsCents: Long = 0,
    val tipsCents: Long = 0,
    val unlocksCents: Long = 0,
    val vodPurchasesCents: Long = 0,
    val otherCents: Long = 0,
)
data class EarningsSummary(              // EarningsSummaryOut
    val totalCents: Long,
    val currency: String,               // ISO-4217, default "USD"
    val transactionCount: Int,
    val breakdown: EarningsBreakdown,
    val series: List<EarningsPoint>,    // from EarningsSummaryOut.time_series
)
data class EarningsPoint(               // TimeSeriesPoint
    val date: String,                   // "YYYY-MM-DD" (required); server returns a string, not Instant
    val totalCents: Long = 0,
    val subscriptionsCents: Long = 0,
    val tipsCents: Long = 0,
    val unlocksCents: Long = 0,
    val vodPurchasesCents: Long = 0,
    val otherCents: Long = 0,
)
// UI presets map to from_date/to_date; the server has NO range enum.
enum class EarningsPreset { DAYS_7, DAYS_30, DAYS_90, YEAR_1, ALL }

// feature-earnings (repository)
interface EarningsRepository {
    suspend fun summary(
        preset: EarningsPreset,
        granularity: String = "day",    // "day" | "week" | "month"
    ): ApiResult<EarningsSummary>
    suspend fun quickStats(): ApiResult<EarningsQuickStats>   // EarningsQuickStatsOut
    suspend fun transactions(
        preset: EarningsPreset,
        limit: Int = 50,
        cursor: String? = null,
    ): ApiResult<EarningsTransactionsPage>                    // EarningsTransactionsOut
}

// feature-earnings (viewmodel)
sealed interface EarningsUiState {
    data object Loading : EarningsUiState
    data class Success(
        val summary: EarningsSummary,
        val series: List<EarningsPoint>,   // == summary.series; surfaced for the chart
        val selectedPreset: EarningsPreset,
        val granularity: String = "day",
        val isStale: Boolean = false,
    ) : EarningsUiState
    data object Empty : EarningsUiState
    data class Error(val message: String, val offline: Boolean = false) : EarningsUiState
}
class EarningsViewModel @Inject constructor(
    private val repo: EarningsRepository,
) : ViewModel() {
    val uiState: StateFlow<EarningsUiState>
    fun onRangeSelected(preset: EarningsPreset)
    fun onGranularitySelected(granularity: String)
    fun retry()
}
```

### 4.2 Test architecture

- **Repository / mapping tests (JVM, `src/test`):** Use **JUnit4**,
  **MockWebServer (OkHttp 4.12)**, the real Moshi 1.15 adapters and the real
  Retrofit `EarningsApi`, so deserialization and query-param construction are
  exercised end-to-end against canned HTTP. Fixtures are JSON files in
  `feature-earnings/src/test/resources/fixtures/earnings/`. Use
  `kotlinx-coroutines-test` `runTest` + `StandardTestDispatcher`.
- **ViewModel tests (JVM, `src/test`):** Inject a `FakeEarningsRepository`
  (in `core-testing`) implementing `EarningsRepository` with programmable
  `ApiResult` outcomes and emission delays. Collect `uiState` with **Turbine**
  to assert ordered emissions. Replace `Dispatchers.Main` via
  `MainDispatcherRule` (JUnit `TestRule` wrapping `Dispatchers.setMain`).
- **UI tests (`src/androidTest` or Robolectric `src/test`):** Use
  `createComposeRule()` and drive `EarningsScreen(state, onRangeSelected, onRetry)`
  directly with each `EarningsUiState`, asserting via `onNodeWithTag` /
  `onNodeWithText`. Prefer Robolectric-backed Compose tests so the suite runs on
  CI without an emulator; keep one true instrumented smoke test for the chart
  (Media3 is not used here, only Compose canvas / Coil-free).

### 4.3 Determinism

- Fix the clock: inject a `Clock.fixed(...)` (or a `TimeProvider` fake) so the
  preset→`from_date`/`to_date` math is deterministic for `7d` etc. Tests assert
  exact `YYYY-MM-DD` UTC dates in the recorded request URL (matching the web
  client's `daysAgo(n)`/`isoDate(new Date())` logic — note web uses local-time
  `Date`; the Android impl must pin to UTC to be deterministic).
- No real network, no real DataStore/Room: use in-memory Room
  (`Room.inMemoryDatabaseBuilder`) for the stale-cache test and a temp-folder
  DataStore where needed.

## 5. API Contract

This is a **test** ticket; it does not define new endpoints. It validates the
contract owned by `AND-251`. The DTO/endpoint truth is reproduced here as the
basis for fixtures.

> CORRECTED: bodies below are the REAL shapes from `EarningsSummaryOut`,
> `TimeSeriesPoint`, `EarningsQuickStatsOut`, `EarningsTransactionsOut` in
> `openapi.pretty.json` and `src/api/types.ts`. The prior draft's
> `total_minor`/`amount_minor`/`delta_pct_from_prev`/`period_*`/`points` and the
> `?range=...`/`/ui/earnings/series` calls do not exist.

`GET /ui/earnings/summary?from_date=2026-05-07&to_date=2026-06-06&granularity=day`
(auth required; cookies + `X-CSRF-Token`) → `EarningsSummaryOut`:
```json
{
  "total_cents": 1284500,
  "currency": "USD",
  "transaction_count": 312,
  "breakdown": {
    "subscriptions": 800000,
    "tips": 250000,
    "unlocks": 150000,
    "vod_purchases": 80000,
    "other": 4500
  },
  "time_series": [
    { "date": "2026-05-07", "total": 41000, "subscriptions": 30000, "tips": 8000, "unlocks": 2000, "vod_purchases": 1000, "other": 0 },
    { "date": "2026-05-08", "total": 38500, "subscriptions": 28000, "tips": 7500, "unlocks": 2000, "vod_purchases": 1000, "other": 0 }
  ]
}
```

`GET /ui/earnings/quick-stats` → `EarningsQuickStatsOut`:
```json
{
  "today_cents": 12000,
  "this_week_cents": 84000,
  "this_month_cents": 312000,
  "all_time_cents": 9450000,
  "pending_payout_cents": 50000,
  "currency": "USD"
}
```

`GET /ui/earnings/transactions?from_date=2026-05-07&to_date=2026-06-06&limit=50&cursor=...`
→ `EarningsTransactionsOut`:
```json
{
  "items": [
    { "entry_id": "txn_1", "ts": 1746576000, "amount_cents": 5000, "reason": "Tip from @fan", "category": "tips", "currency": "USD", "meta": {} }
  ],
  "next_cursor": "eyJvZmZzZXQiOjUwfQ"
}
```
Note: `entry_id`, `ts` (Unix seconds, integer), and `amount_cents` are the only
**required** fields on `EarningsTransactionOut`; `reason`/`category`/`currency`
default to `""`/`""`/`"USD"`, `meta` is a free-form object. `next_cursor` is
nullable (absent/`null` ⇒ no more pages).

`All` preset request: omit `from_date`/`to_date` entirely (the web client passes
`undefined`). The server also accepts `from_ts`/`to_ts` (Unix seconds) as an
alternative to the date strings; the web client uses the date strings.

FastAPI error body — the contract-documented form for these endpoints is **422
`HTTPValidationError`**:
```json
{ "detail": [ { "loc": ["query", "from_date"], "msg": "invalid date", "type": "value_error" } ] }
```
The Android `ApiError` mapper must also tolerate the string form
(`{ "detail": "..." }`) and the object/code form
(`{ "detail": { "code": "geo_blocked", "message": "..." } }`) because
`src/api/client.ts::normalizeErrorDetail` handles all three (e.g. 401/403). Only
the array form is OpenAPI-guaranteed for earnings.

Tests assert: query params per preset/granularity, header presence
(`X-CSRF-Token` echoing `ui_csrf`), and that each error body maps to the expected
`ApiError` subtype.

## 6. Data & State Management

The suite verifies the data/state contract rather than introducing it.

- **DTO→domain:** Moshi adapters parse all `*_cents`/`total_cents`/`amount_cents`
  fields as `Long` (no float rounding); the per-category breakdown fields
  default to `0` when absent (server defaults). The `date` field stays a
  `String` (`YYYY-MM-DD`) — there is no ISO-8601 instant on these payloads.
  Test asserts absent breakdown categories map to `0`, not crash. (CORRECTED:
  no `delta_pct_from_prev`/`*_minor`/`Instant` fields exist.)
- **Ordering:** `EarningsSummaryDto.time_series` → `List<EarningsPoint>` sorted
  by `date` ascending (lexicographic on `YYYY-MM-DD` == chronological); test
  feeds out-of-order points and asserts sorting.
- **State emissions:** For each `onRangeSelected`, Turbine asserts the emission
  sequence and the terminal `selectedPreset` equals the requested preset. The
  latest-wins test enqueues a slow first response and a fast second selection
  and asserts the first never reaches `Success`.
- **Stale/cache:** Repository returns cached series with `isStale = true` when
  the network call fails but a Room row exists. Test seeds in-memory Room, fails
  the `MockWebServer` response (or `enqueue` socket disconnect), asserts
  `Success(isStale = true)`.
- **Empty:** `time_series = []` and `total_cents = 0` → `EarningsUiState.Empty`.
  (Matches the web client, which renders "No revenue data for this period" /
  "No earnings yet" when the series/breakdown are empty.)

## 7. Error Handling & Resilience

Tested production behaviors (assertions in repository/ViewModel tests):

- **Timeout:** `MockWebServer` `setBodyDelay(25, SECONDS)` against a ~20s
  OkHttp read timeout → `ApiResult.Failure(NetworkError.Timeout)` →
  `Error(offline = false)` (or stale if cache present). Test uses a shortened
  timeout client to keep the suite fast.
- **401 → refresh once:** Enqueue `401`, then `200` for `session/refresh`, then
  `200` for the retried earnings GET. Assert exactly **one** refresh request was
  recorded (`server.requestCount` / dispatcher path assertions) and the final
  result is `Success`. A second `401` must surface as `Error` (no infinite
  loop).
- **Bounded backoff:** Enqueue `503` twice then `200` for the idempotent GET;
  assert success after retries and that retry count does not exceed the
  configured cap. POST-equivalent (none here) is N/A. NOTE: this 503 retry policy
  is an Android `core-network` behavior — the web `src/api/client.ts` has **no**
  503 retry (only the single 401→refresh). Verify the policy exists in AND-027
  before asserting; otherwise this test guards Android-only code (see §16).
- **Malformed JSON:** Body with wrong types → `ApiResult.Failure(ParseError)`,
  not a crash.
- **detail mapping:** Parameterized JUnit test (`@Parameterized` or a
  table-driven loop) over the three `detail` shapes (array `[{loc,msg,type}]`,
  string, and `{code,message}` object) asserting the mapped `ApiError` — mirrors
  `src/api/client.ts::normalizeErrorDetail`. The array form is the
  OpenAPI-documented 422 for earnings; the other two are defensively supported.

## 8. Security & Privacy

- Tests assert the `X-CSRF-Token` header is present and equals the `ui_csrf`
  cookie value on outgoing earnings requests (validates the
  `AND-027` CSRF interceptor is in the chain for this feature).
- Tests assert the persistent cookie jar replays the session cookie on the
  series request after the summary request (same `MockWebServer` instance).
- No secrets, real credentials, or production hosts appear in fixtures or test
  config; the dev host `18.222.237.167` is never contacted. Fixture amounts are
  synthetic.
- Logging assertions confirm no PII/auth cookies are emitted at non-debug log
  levels (see §10).

## 9. Accessibility & i18n

- **A11y (UI tests):** Each Compose state test asserts meaningful semantics:
  range chips expose `Role.RadioButton`/`selected` state and a
  `contentDescription`; the retry button is reachable via `onNodeWithText`/
  merged semantics; the chart container has a `stateDescription` summarizing
  total + range for TalkBack. Test asserts touch targets via tagged nodes (size
  validated in the manual/instrumented smoke check).
- **i18n:** Tests assert no hardcoded user-facing strings in `EarningsScreen`
  by resolving via `stringResource`; currency/amounts formatted through a
  locale-aware formatter. A `Locale.GERMANY` UI test asserts the amount renders
  with locale grouping/decimal separators and the `currency` field's symbol,
  guarding against `String.format` hardcoding. NOTE: this is an Android
  *improvement* over the web reference, which hardcodes `en-US` and a literal
  `$` prefix (`formatCents` does `\`$${(cents/100).toLocaleString("en-US", ...)}\``
  in `EarningsPage.tsx`). The Android formatter must divide cents by 100 and
  honor the `currency` field (default `"USD"`) rather than assuming USD.

## 10. Telemetry & Logging

- A `FakeAnalytics` (from `core-testing`) is injected; tests assert the
  ViewModel logs `earnings_range_selected { range }` on selection and
  `earnings_load_failed { reason }` on error, and does **not** double-log on
  latest-wins cancellation.
- A test installs a capturing `Timber`/log tree and asserts that error paths log
  at `WARN`/`ERROR` without including cookie values or full response bodies
  containing the session.

## 11. Testing Strategy

This ticket *is* the testing strategy deliverable. Concrete test classes:

- `feature-earnings/src/test/.../EarningsApiMappingTest.kt`
  — MockWebServer + real Moshi/Retrofit: FR-1, FR-2, FR-3, malformed JSON.
- `feature-earnings/src/test/.../EarningsErrorMappingTest.kt`
  — parameterized FastAPI `detail` (FR-5), timeout, 401-refresh, 503-backoff
  (FR-7).
- `feature-earnings/src/test/.../EarningsRepositoryStaleTest.kt`
  — in-memory Room cache, offline/stale (FR-6).
- `feature-earnings/src/test/.../EarningsViewModelTest.kt`
  — Turbine + Fake repo + `MainDispatcherRule`: FR-4, state ordering,
  latest-wins, Empty, retry, telemetry (FR-4/§10).
- `feature-earnings/src/androidTest/.../EarningsScreenTest.kt` (or Robolectric)
  — Compose rule, one test per `EarningsUiState`, range chip selection, a11y
  semantics, German-locale formatting (FR-8, §9).

Tooling: JUnit4, `kotlinx-coroutines-test`, Turbine, MockWebServer, Truth (or
JUnit assertions), Compose UI Test, Robolectric (for JVM Compose), Room
in-memory. All wired via `core-testing` dependencies and `KSP` test processors
where Hilt test injection is used (`@HiltAndroidTest` only for the instrumented
smoke test; ViewModel tests construct the VM directly to stay fast).

Coverage target: every public method of `EarningsRepository` and
`EarningsViewModel` and every `EarningsUiState` branch exercised. No flakiness:
all time and dispatchers are controlled; no `Thread.sleep`; no real I/O.

## 12. Dependencies & Sequencing

- **Hard deps:** `AND-256` (ViewModel + state) and, transitively, `AND-251`
  (API + DTOs) must be merged — they provide the types under test. `AND-027`
  provides `core-network`, the cookie jar, CSRF interceptor, and `ApiResult`.
- **Shared infra:** `core-testing` must expose `MainDispatcherRule`,
  `FakeEarningsRepository`, `FakeAnalytics`, and the in-memory Room/DataStore
  helpers; if any are missing, add them in `core-testing` as part of this ticket
  (they are reusable across feature test suites).
- **Sequencing:** Land after `AND-256`. This ticket blocks nothing functionally
  but gates the milestone-`M6` Earnings epic (`E34`) "done" definition by
  proving the feature is regression-protected.

## 13. Risks & Open Questions

- **R-1 (signature drift):** RESOLVED during this review (2026-06-06). Field
  names confirmed against `openapi.pretty.json` and `src/api/types.ts`: amounts
  are `*_cents`; summary returns `total_cents`/`currency`/`transaction_count`/
  `breakdown`/`time_series`; series points are `TimeSeriesPoint{date, total,
  subscriptions, tips, unlocks, vod_purchases, other}`. There is **no**
  `EarningsRange` enum or `/ui/earnings/series` endpoint — the prior draft's
  field/endpoint names were wrong and have been corrected. Mitigation retained:
  a contract test that diffs fixture keys against the committed OpenAPI snapshot.
- **R-2 (granularity ownership):** RESOLVED. `granularity` is a **client-chosen**
  query param (`day`|`week`|`month`, default `day`), driven by a UI selector in
  `EarningsPage.tsx`; the server groups the `time_series` accordingly. FR-3
  asserts the client sends the selected value verbatim.
- **R-3 (refresh semantics):** "Single refresh on 401" location (interceptor in
  `core-network` vs repository) determines where the refresh-once test asserts.
  Assume `core-network` (`AND-027`); adjust if implemented per-feature.
- **R-4 (Robolectric vs emulator):** If Compose chart rendering needs a real GPU
  canvas, demote the chart test to instrumented-only and keep state/semantics
  tests on Robolectric.

## 14. Acceptance Criteria

The backlog acceptance is "Pass." Operationalized as testable criteria:

- **AC-1:** `./gradlew :feature-earnings:testDebugUnitTest` passes with all
  classes in §11 present and green; zero ignored/flaky tests.
- **AC-2:** `./gradlew :feature-earnings:connectedDebugAndroidTest` (or the
  Robolectric Compose task) passes for `EarningsScreenTest`.
- **AC-3:** Repository tests prove FR-1, FR-2, FR-3 (per-range query params,
  including `CUSTOM` `from`/`to`) and ascending series ordering.
- **AC-4:** Error tests prove FR-5 (all three `detail` shapes), timeout, 401→
  single-refresh→retry with exactly one refresh request, and bounded 503
  backoff (FR-7).
- **AC-5:** ViewModel tests prove ordered `Loading→Success` emissions per range,
  latest-wins cancellation, `Empty`, `Error`, and `retry()` recovery (FR-4).
- **AC-6:** Stale/offline tests prove `Success(isStale=true)` with cache and
  `Error(offline=true)` without (FR-6).
- **AC-7:** UI tests prove rendering of every `EarningsUiState`, range-chip
  selection reflecting `selectedRange`, a11y semantics, and German-locale amount
  formatting (FR-8, §9).
- **AC-8:** Security assertions confirm `X-CSRF-Token` echoes `ui_csrf` and the
  cookie jar replays the session (§8).
- **AC-9:** Suite is hermetic: no live network, controlled clock/dispatchers, no
  `Thread.sleep`; CI run is green.

## 15. Definition of Done

- All test classes in §11 implemented under `com.testlogon.android` package
  paths in `feature-earnings`, compiling against the merged `AND-256`/`AND-251`
  signatures.
- AC-1 through AC-9 satisfied; suite green locally and in CI on the
  `android-port` branch.
- Required `core-testing` fakes/rules added or confirmed present and reused (no
  duplication in `feature-earnings`).
- Fixtures stored under `src/test/resources/fixtures/earnings/` and validated
  against `/openapi.json` (R-1 closed or explicitly deferred with an owner).
- No new lint/Detekt violations; KSP test processors build cleanly; no live dev
  host contacted.
- Open questions R-1..R-4 resolved or filed as follow-up tickets and linked.
- Code reviewed and merged to `android/feature-earnings`; CI badge green.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer. Sources:
OpenAPI = `reference/openapi.index.txt` / `reference/openapi.pretty.json`
(`components.schemas.<Name>`); frontend = `reference/src/...`.

1. **Earnings endpoints are `GET /ui/earnings/summary`, `/transactions`,
   `/quick-stats`.** VERIFIED. OpenAPI `GET /ui/earnings/summary`
   (op=`earnings_summary_ui_earnings_summary_get`), `GET /ui/earnings/transactions`,
   `GET /ui/earnings/quick-stats`; frontend `src/api/endpoints/earnings.ts`
   (`getEarningsSummary`, `getEarningsTransactions`, `getEarningsQuickStats`).
2. **A `GET /ui/earnings/series` endpoint exists.** CORRECTED → does not exist.
   No such path in `openapi.index.txt`; the time series is `EarningsSummaryOut.time_series`.
3. **Summary response fields = `total_cents`, `currency`, `transaction_count`,
   `breakdown`, `time_series`.** VERIFIED. OpenAPI schema `EarningsSummaryOut`;
   frontend `src/api/types.ts: EarningsSummary` (note: the TS type omits
   `time_series`, but the server schema and `EarningsPage.tsx` (`summary.time_series`)
   confirm it is present).
4. **Summary has `total_minor`, `delta_pct_from_prev`, `period_start`,
   `period_end`.** CORRECTED → none exist. Amounts are `*_cents` (integer); no
   delta/period fields on `EarningsSummaryOut`. Source: OpenAPI `EarningsSummaryOut`.
5. **Series point = `TimeSeriesPoint{date (required string), total, subscriptions,
   tips, unlocks, vod_purchases, other}` (all cents).** VERIFIED. OpenAPI schema
   `TimeSeriesPoint`; frontend usage in `EarningsPage.tsx::RevenueChart`.
6. **Series point has `period_start` + `amount_minor`.** CORRECTED → it has
   `date` + per-category `*` cents; no `period_start`/`amount_minor`. Source:
   OpenAPI `TimeSeriesPoint`.
7. **Breakdown = `EarningsBreakdown{subscriptions, tips, unlocks, vod_purchases,
   other}` (cents, default 0).** VERIFIED. OpenAPI `EarningsBreakdown`; frontend
   `src/api/types.ts: EarningsBreakdown`.
8. **Quick-stats = `EarningsQuickStatsOut{today_cents, this_week_cents,
   this_month_cents, all_time_cents, pending_payout_cents, currency}`.** VERIFIED.
   OpenAPI `EarningsQuickStatsOut`; frontend `EarningsPage.tsx` reads
   `qs.today_cents`/`this_week_cents`/`this_month_cents`/`all_time_cents`.
9. **Transactions = `EarningsTransactionsOut{items: EarningsTransactionOut[],
   next_cursor: string|null}`; item required fields `entry_id, ts, amount_cents`.**
   VERIFIED. OpenAPI `EarningsTransactionsOut` + `EarningsTransactionOut`;
   frontend `src/api/types.ts: EarningsTransactionsResp`/`EarningsTransaction` and
   the cursor pagination in `EarningsPage.tsx` (`limit:"50"`, `getNextPageParam`).
10. **Summary query params = `from_date`/`to_date` (YYYY-MM-DD), `granularity`
    (day|week|month, default day), `from_ts`/`to_ts` (Unix seconds).** VERIFIED.
    OpenAPI `GET /ui/earnings/summary` parameter list; frontend
    `src/api/endpoints/earnings.ts` sends `from_date`/`to_date`/`granularity`.
11. **The client sends a `range` enum (`DAY_7`/`DAY_30`/`DAY_90`/`YEAR_1`/`CUSTOM`)
    with `from`/`to`.** CORRECTED → no `range` param exists. The web client uses
    UI presets (`7d`/`30d`/`90d`/`1y`/`All`) computed to `from_date`/`to_date` via
    `daysAgo(n)`/`isoDate()`; `All` omits the dates. Source:
    `EarningsPage.tsx` (`PRESETS`, `daysAgo`, `fromDate`/`toDate`) + OpenAPI params.
12. **`granularity` is a client-chosen value (day/week/month).** VERIFIED.
    `EarningsPage.tsx` `<Select>` `setGranularity`; OpenAPI param default `"day"`.
13. **Amounts are cents; UI divides by 100 and formats hardcoded `en-US`/`$`.**
    VERIFIED. `EarningsPage.tsx::formatCents` = `\`$${(cents/100).toLocaleString("en-US", ...)}\``.
    (Android improves this to locale-aware + `currency` field — §9.)
14. **CSRF: `ui_csrf` cookie echoed as `X-CSRF-Token` header.** VERIFIED.
    `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`).
15. **401 → single de-duplicated `POST /ui/session/refresh` then one retry;
    second 401 logs out (no loop).** VERIFIED. `src/api/client.ts`
    (`refreshPromise` guard, `refreshSession()` POSTs `/ui/session/refresh`,
    single retry, `logout("session_expired")` on retry 401). Refresh only fires
    when `isAuthenticated`.
16. **Network/transport error surfaces distinctly (offline path).** VERIFIED
    (web equivalent). `src/api/client.ts` catch → `ApiError(0, "Network error")`.
17. **A transient-503 bounded-backoff retry exists.** UNVERIFIED-assumption.
    No 503 retry in `src/api/client.ts`; this is an assumed `core-network`
    (AND-027) policy. framework ref for retry pattern:
    https://square.github.io/okhttp/recipes/ (custom Interceptor).
18. **Error `detail` appears as string | `[{loc,msg,type}]` | `{code,message}`.**
    VERIFIED (handling) / partially verified (shape). `src/api/client.ts::normalizeErrorDetail`
    handles all three; OpenAPI documents only the **422 `HTTPValidationError`**
    array form (`components.schemas.HTTPValidationError` → `ValidationError[]`) for
    the earnings endpoints. The string/object forms are real elsewhere (401/403)
    but not in the earnings 4xx contract.
19. **Offline-stale (`Success(isStale=true)` from Room cache) / `Error(offline=true)`.**
    UNVERIFIED-assumption. No web equivalent (web uses react-query without an
    offline/stale flag on this page). Android product behavior from AND-256.
20. **Telemetry events `earnings_range_selected`/`earnings_load_failed`.**
    UNVERIFIED-assumption. No analytics event names appear in the web reference;
    these are Android-internal and owned by AND-256.
21. **DI/test framework choices (Hilt, Robolectric Compose, Turbine,
    MockWebServer, in-memory Room).** Framework refs (not in backend/frontend):
    Compose test — https://developer.android.com/jetpack/compose/testing ;
    Robolectric — https://robolectric.org/ ;
    MockWebServer — https://github.com/square/okhttp/tree/master/mockwebserver ;
    Room in-memory — https://developer.android.com/training/data-storage/room/testing-db ;
    coroutines test — https://kotlinlang.org/api/kotlinx.coroutines/kotlinx-coroutines-test/ .
22. **Auth/transport also forwards `Authorization: Bearer` + `X-IMPERSONATION-TOKEN`.**
    VERIFIED. `src/api/client.ts` (Bearer from `useAuthStore`, impersonation
    header when active). Earnings endpoints also expose optional `user_sub`,
    `X-SESSION-ID`, `X-IMPERSONATION-TOKEN` params in OpenAPI.

### Corrections made

- Endpoint surface: removed the non-existent `GET /ui/earnings/series`; the time
  series lives in `EarningsSummaryOut.time_series`. Added the real
  `/ui/earnings/quick-stats` and `/ui/earnings/transactions` endpoints (§1, §2, §5).
- Money units: every `*_minor`/`totalMinor`/`amountMinor` changed to `*_cents`
  (server uses integer cents) — §3, §4.1, §5, §6.
- Summary shape: dropped `delta_pct_from_prev`, `period_start`, `period_end`;
  added `breakdown`, `transaction_count`, `time_series` (§3 FR-1, §4.1, §5).
- Series point shape: `period_start`/`amount_minor` → `date` (string) +
  per-category cents; ordering key changed from `periodStart` to `date` (§3 FR-2, §6).
- Range model: replaced the fictitious `range`/`CUSTOM` enum with UI presets that
  compute `from_date`/`to_date` (YYYY-MM-DD) + client `granularity` (§3 FR-3,
  §4.1, §4.3, §5); `selectedRange` → `selectedPreset` in `Success` state and
  `onRangeSelected(EarningsPreset)` (§4.1, §6).
- Error contract: clarified the OpenAPI-documented form is 422 array
  `HTTPValidationError`; string/object forms supported defensively (§3 FR-5, §5, §7).
- i18n: noted the web hardcodes `en-US`/`$`; Android must be locale + `currency`
  aware (§9).
- Resolved R-1 (field/endpoint names confirmed) and R-2 (granularity is
  client-chosen) in §13.
- Frontend path prefix corrected from `frontend/src/...` to `src/...` (§2).

### Open assumptions

- **Offline / stale-cache behavior (FR-6, §6, item 19):** No backend or web
  source confirms `isStale`/`offline` semantics; the web client has no such
  concept. Treated as Android product behavior introduced in AND-256 — tests
  guard the Android contract, not a backend behavior. Confirm with AND-256 owner.
- **503 bounded-backoff retry (FR-7, §7, item 17):** Not present in the web
  client; assumed to live in `core-network` (AND-027). If AND-027 does not
  implement GET retry, TC covering it must be skipped or moved to AND-027.
- **Analytics event names (§10, item 20):** `earnings_range_selected` /
  `earnings_load_failed` are unverifiable from the provided sources; owned by
  AND-256's ViewModel. Names may differ — assert against the actual constants.
- **Refresh interceptor location (R-3):** Web does it in the fetch wrapper; the
  Android equivalent is assumed in `core-network` (AND-027). The exact assertion
  point (interceptor vs repository) depends on AND-027.
- **Currency beyond USD:** Every schema defaults `currency` to `"USD"`; no source
  exercises a non-USD value. The German-locale test fixes a synthetic non-USD
  `currency` to prove the formatter is not hardcoded — an Android-side guard, not
  a verified backend scenario.

## 17. Test Plan

Test target legend: **JVM** = JVM unit/Robolectric (local, no device);
**Emulator** = headless AVD `test35` (x86_64, API 35); **Device** = physical
Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). This is a pure
test/repo+UI ticket with no camera/biometric/FCM/WebRTC/Telecom/streaming
surface, so almost everything runs JVM/Robolectric; one real-device case exists
only to validate arm64 / API-34 parity of the Compose chart render.

- **TC-AND-257-01** — Summary happy-path mapping.
  Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: `EarningsApiMappingTest`; MockWebServer up; fixture
  `summary_30d.json` (real `EarningsSummaryOut` shape, cents).
  Steps: enqueue 200 + fixture; call `repo.summary(DAYS_30, "day")`.
  Expected: `ApiResult.Success`; `totalCents`/`transactionCount`/`currency`
  preserved; `breakdown.*Cents` mapped; `series` non-empty with `date` + cents;
  recorded request path is `/ui/earnings/summary` with `granularity=day`.
  Traces: AC-3.

- **TC-AND-257-02** — Per-preset query parameterization (date math).
  Type: contract/MockWebServer (JVM), parameterized over `7d/30d/90d/1y/All`.
  Target: JVM. Preconditions: `Clock.fixed(2026-06-06T00:00:00Z)`.
  Steps: for each preset, enqueue 200; call `repo.summary(preset)`; inspect
  recorded URL query.
  Expected: `7d`→`from_date=2026-05-30&to_date=2026-06-06`; `30d`→`from_date=2026-05-07`;
  `90d`→`from_date=2026-03-08`; `1y`→`from_date=2025-06-06`; `All`→ no
  `from_date`/`to_date` params; `granularity` echoed verbatim. Dates are UTC.
  Traces: AC-3.

- **TC-AND-257-03** — Time-series ordering + cents precision.
  Type: unit (JVM). Target: JVM.
  Preconditions: fixture with out-of-order `time_series` dates and large cent
  values (e.g. 2_147_500_000).
  Steps: deserialize via real Moshi; map to domain.
  Expected: points sorted ascending by `date`; cent values exact `Long` (no
  float rounding); absent breakdown categories default to `0`.
  Traces: AC-3.

- **TC-AND-257-04** — Quick-stats + transactions (cursor pagination) mapping.
  Type: contract/MockWebServer (JVM). Target: JVM.
  Steps: enqueue `EarningsQuickStatsOut` then page-1 `EarningsTransactionsOut`
  with `next_cursor`, then page-2 with `next_cursor=null`; call
  `repo.quickStats()` and `repo.transactions(...)` twice using the returned cursor.
  Expected: quick-stats `*_cents` fields mapped; page-1 carries `next_cursor` and
  the 2nd request URL includes `cursor=<that value>` + `limit=50`; page-2 maps
  `next_cursor=null` ⇒ no further page.
  Traces: AC-3.

- **TC-AND-257-05** — FastAPI `detail` error mapping (all three shapes).
  Type: unit (JVM), parameterized. Target: JVM.
  Preconditions: `EarningsErrorMappingTest`.
  Steps: feed (a) 422 `{detail:[{loc,msg,type}]}`, (b) 400 `{detail:"..."}`,
  (c) 403 `{detail:{code:"geo_blocked",message:"..."}}`.
  Expected: each maps to the typed `ApiError` with the human message resolved
  (array → joined `msg`s; string → as-is; object → `message`/code mapping),
  mirroring `normalizeErrorDetail`. No crash on unknown shapes (falls back).
  Traces: AC-4.

- **TC-AND-257-06** — Malformed JSON ⇒ ParseError, no crash.
  Type: contract/MockWebServer (JVM). Target: JVM.
  Steps: enqueue 200 with `total_cents:"oops"` / truncated body.
  Expected: `ApiResult.Failure(ParseError)`; no exception escapes the repository.
  Traces: AC-4, AC-9.

- **TC-AND-257-07** — 401 → single refresh → retry success; second 401 ⇒ Error.
  Type: contract/MockWebServer (JVM). Target: JVM.
  Steps: (path A) enqueue 401, then 200 for `POST /ui/session/refresh`, then 200
  for the retried GET; assert success and that exactly one `/ui/session/refresh`
  request was recorded and the earnings GET ran twice. (path B) enqueue 401,
  refresh 200, then 401 again ⇒ assert terminal `Error` and no further refresh
  (no loop).
  Expected: as above; refresh count == 1 in both paths.
  Traces: AC-4, AC-8.

- **TC-AND-257-08** — Timeout & transient-503 backoff.
  Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: short-timeout OkHttp client.
  Steps: (a) `setBodyDelay` beyond read timeout ⇒ assert
  `Failure(NetworkError.Timeout)`. (b) IF AND-027 implements GET retry: enqueue
  503,503,200 ⇒ assert success with retry count ≤ cap; ELSE assert a single 503
  surfaces as `Failure` and mark the backoff sub-case skipped (see §16 open
  assumption, item 17).
  Traces: AC-4, AC-9.

- **TC-AND-257-09** — CSRF header + cookie-jar replay.
  Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: cookie jar seeded with `ui_csrf=<v>` + session cookie (AND-027
  chain in use).
  Steps: issue summary then transactions against the same MockWebServer.
  Expected: both recorded requests carry `X-CSRF-Token: <v>` equal to the
  `ui_csrf` cookie, and the session cookie is replayed on the 2nd request.
  Traces: AC-8.

- **TC-AND-257-10** — ViewModel state ordering + latest-wins + retry.
  Type: unit (JVM, Turbine + `MainDispatcherRule`). Target: JVM.
  Preconditions: `FakeEarningsRepository` with programmable delays.
  Steps: collect `uiState`; call `onRangeSelected(DAYS_7)` (slow) then quickly
  `onRangeSelected(DAYS_30)` (fast); then force an error and call `retry()`.
  Expected: emissions `Loading → Success(selectedPreset=DAYS_30)`; the slow first
  fetch never emits `Success` (cancelled, latest-wins); terminal
  `Success.selectedPreset == DAYS_30`; after error, `retry()` ⇒ `Loading → Success`.
  Traces: AC-5.

- **TC-AND-257-11** — Empty vs offline/stale states.
  Type: unit + Room-in-memory (JVM/Robolectric). Target: JVM.
  Steps: (a) repo returns `time_series=[]` + `total_cents=0` ⇒ assert `Empty`.
  (b) seed in-memory Room cache, fail the network (socket disconnect) ⇒ assert
  `Success(isStale=true)`. (c) no cache + network fail ⇒ assert `Error(offline=true)`.
  Expected: as above. (b)/(c) guard Android-only behavior — see §16 open assumption 19.
  Traces: AC-5, AC-6.

- **TC-AND-257-12** — Compose render per `EarningsUiState` + retry action + a11y.
  Type: Compose-UI (Robolectric). Target: JVM (Robolectric).
  Preconditions: `createComposeRule()`; drive `EarningsScreen(state, ...)` directly.
  Steps: render each of Loading / Success(populated) / Empty / Error /
  Success(isStale) ; tap the Error retry button; inspect semantics.
  Expected: loading skeleton, chart+summary, empty copy, error+retry, stale
  banner each present (`onNodeWithTag`/`onNodeWithText`); retry invokes
  `onRetry`; preset chips expose selectable/`Role.RadioButton` semantics with
  the selected chip marked; chart container exposes a `stateDescription` (total +
  preset) for TalkBack.
  Traces: AC-7, AC-2.

- **TC-AND-257-13** — Locale-aware currency formatting (non-USD / German).
  Type: Compose-UI (Robolectric). Target: JVM (Robolectric).
  Preconditions: `Locale.GERMANY`; `Success` with `currency="EUR"`,
  `total_cents=1284500`.
  Steps: render; read the formatted total node.
  Expected: renders `12.845,00` grouping/decimal with the EUR symbol (not
  `$12,845.00`); proves cents/100 division and `currency`-driven formatting (no
  hardcoded `en-US`/`$`). Traces: AC-7.

- **TC-AND-257-14** — Real-device Compose chart smoke (arm64 / API 34 parity).
  Type: instrumented/e2e. Target: **Device (MUST run on SM-A156U)** — validates
  the Compose canvas chart on arm64-v8a / API 34 vs the API-35 emulator;
  `@HiltAndroidTest` smoke.
  Preconditions: app installed on device R5CX821TA9R via adb; seeded `Success`
  state with a non-trivial `time_series`.
  Steps: launch `EarningsScreen`; assert the chart node renders and preset-chip
  selection updates `selectedPreset`; capture a screenshot artifact.
  Expected: chart composes without GPU/canvas errors on the physical device;
  selection works. (Run on Device, not Emulator, to catch arm64/API-34 deltas;
  if it also passes on `test35` keep both, else keep the device run authoritative.)
  Traces: AC-2, AC-7.

### Coverage matrix

| Acceptance criterion (§14) | Covered by |
| --- | --- |
| AC-1 (unit suite green, classes present) | TC-01..TC-11 (all JVM unit/contract) |
| AC-2 (Compose/instrumented task green) | TC-12, TC-14 |
| AC-3 (FR-1/2/3: mapping, per-preset params, ordering) | TC-01, TC-02, TC-03, TC-04 |
| AC-4 (FR-5/7: detail shapes, timeout, 401 refresh, 503 backoff) | TC-05, TC-06, TC-07, TC-08 |
| AC-5 (FR-4: ordered emissions, latest-wins, Empty, Error, retry) | TC-10, TC-11 |
| AC-6 (FR-6: stale-with-cache, offline-without) | TC-11 |
| AC-7 (FR-8/§9: render each state, chip selection, a11y, locale) | TC-12, TC-13, TC-14 |
| AC-8 (CSRF echoes ui_csrf; cookie replay; refresh count) | TC-07, TC-09 |
| AC-9 (hermetic: no live net, controlled clock/dispatchers, no sleep) | TC-02, TC-06, TC-08, TC-10 (all use fakes/fixed clock/test dispatchers) |
