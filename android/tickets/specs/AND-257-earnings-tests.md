---
id: AND-257
title: Earnings tests
milestone: M6
epic: E34
priority: P2
size: M
status: draft
depends_on: [AND-256, AND-251]
blocks: []
---

# AND-257 — Earnings tests

## 1. Overview & Goal

This ticket delivers the automated test suite for the Earnings feature of the
TestLogon native Android app (`com.testlogon.android`). The Earnings feature
comprises three production layers built in upstream tickets: the network/DTO
layer (`AND-251`, `earnings.ts`-equivalent Retrofit service plus Moshi DTOs for
the summary and series payloads), the repository layer that maps DTOs to domain
models and exposes `ApiResult<T>` flows, and the `EarningsViewModel`
(`AND-256`) that owns range selection and `StateFlow<EarningsUiState>`.

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
- **Web reference:** `frontend/src/api/endpoints/earnings.ts` and shared types
  in `frontend/src/api/types.ts` define the canonical request/response shapes
  mirrored by the Kotlin DTOs; the FastAPI source of truth is
  `/openapi.json` on the dev backend `http://18.222.237.167:8000` (plaintext
  HTTP, unreliable dev host).
- **Auth context:** Earnings endpoints are authenticated and ride the
  cookie-based session (`ui_csrf` echoed as `X-CSRF-Token`, single
  `POST /ui/session/refresh` retry on 401). Tests use a stubbed `MockWebServer`
  and never hit the live backend.

## 3. Functional Requirements

The test suite (the deliverable) must verify the following production behaviors.
Each is testable and maps to assertions below.

- **FR-1 (Summary mapping):** A well-formed `GET /ui/earnings/summary` JSON body
  deserializes into `EarningsSummaryDto` and maps to the `EarningsSummary`
  domain model with currency minor-units, totals, and deltas preserved.
- **FR-2 (Series mapping):** A well-formed `GET /ui/earnings/series` body
  deserializes into `EarningsSeriesDto` and maps to `List<EarningsPoint>`
  ordered by `periodStart` ascending.
- **FR-3 (Range parameterization):** The repository sends the correct
  `range`/`from`/`to`/`granularity` query parameters for each
  `EarningsRange` value (`DAY_7`, `DAY_30`, `DAY_90`, `YEAR_1`, `CUSTOM`).
- **FR-4 (ViewModel range selection):** Selecting a new range via
  `onRangeSelected` re-fetches and produces the expected ordered
  `StateFlow<EarningsUiState>` emissions (Loading → Success), and rapid
  selections cancel the in-flight request (latest-wins).
- **FR-5 (Error mapping):** FastAPI `detail` in all three shapes
  (`string` | `[{msg}]` | `{code,...}`) maps to a typed `ApiError`, and the
  ViewModel surfaces `EarningsUiState.Error` with a user-facing message.
- **FR-6 (Offline/stale):** With no network and a cached prior payload, the
  ViewModel emits `Success(isStale = true)`; with no cache it emits
  `Error(offline = true)`.
- **FR-7 (Resilience):** A 401 triggers exactly one `session/refresh` then one
  retry; a transient 503 on an idempotent GET triggers bounded backoff retry.
- **FR-8 (Screen rendering):** `EarningsScreen` renders the loading skeleton,
  the populated chart + summary, the empty state, the error state with retry,
  and the stale banner — one Compose test per state — and the range chips are
  selectable and reflect `selectedRange`.

## 4. Technical Design

### 4.1 Production surface under test (as built by AND-251/256)

The tests are written against these signatures. They are reproduced here so the
test code compiles against the agreed contract; if upstream signatures drift,
the tests are the failing tripwire.

```kotlin
// core-model
data class EarningsSummary(
    val totalMinor: Long,
    val currency: String,          // ISO-4217, e.g. "USD"
    val deltaPctFromPrev: Double?,
    val periodStart: Instant,
    val periodEnd: Instant,
)
data class EarningsPoint(val periodStart: Instant, val amountMinor: Long)
enum class EarningsRange { DAY_7, DAY_30, DAY_90, YEAR_1, CUSTOM }

// feature-earnings (repository)
interface EarningsRepository {
    suspend fun summary(range: EarningsRange, from: Instant? = null, to: Instant? = null): ApiResult<EarningsSummary>
    fun seriesStream(range: EarningsRange): Flow<ApiResult<List<EarningsPoint>>>
}

// feature-earnings (viewmodel)
sealed interface EarningsUiState {
    data object Loading : EarningsUiState
    data class Success(
        val summary: EarningsSummary,
        val series: List<EarningsPoint>,
        val selectedRange: EarningsRange,
        val isStale: Boolean = false,
    ) : EarningsUiState
    data object Empty : EarningsUiState
    data class Error(val message: String, val offline: Boolean = false) : EarningsUiState
}
class EarningsViewModel @Inject constructor(
    private val repo: EarningsRepository,
) : ViewModel() {
    val uiState: StateFlow<EarningsUiState>
    fun onRangeSelected(range: EarningsRange)
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

- Fix the clock: inject a `Clock.fixed(...)` (or a `TimeProvider` fake) so
  `range`→`from`/`to` math is deterministic for `DAY_7` etc. Tests assert exact
  ISO-8601 instants in the recorded request URL.
- No real network, no real DataStore/Room: use in-memory Room
  (`Room.inMemoryDatabaseBuilder`) for the stale-cache test and a temp-folder
  DataStore where needed.

## 5. API Contract

This is a **test** ticket; it does not define new endpoints. It validates the
contract owned by `AND-251`. The DTO/endpoint truth is reproduced here as the
basis for fixtures.

`GET /ui/earnings/summary?range=DAY_30` (auth required; cookies + `X-CSRF-Token`):
```json
{
  "currency": "USD",
  "total_minor": 1284500,
  "delta_pct_from_prev": 12.4,
  "period_start": "2026-05-06T00:00:00Z",
  "period_end": "2026-06-05T00:00:00Z"
}
```

`GET /ui/earnings/series?range=DAY_30&granularity=day`:
```json
{
  "currency": "USD",
  "granularity": "day",
  "points": [
    { "period_start": "2026-05-06T00:00:00Z", "amount_minor": 41000 },
    { "period_start": "2026-05-07T00:00:00Z", "amount_minor": 38500 }
  ]
}
```

`CUSTOM` range request: `?range=CUSTOM&from=2026-01-01T00:00:00Z&to=2026-03-01T00:00:00Z`.

FastAPI error body (tested in all three `detail` shapes), e.g. 422:
```json
{ "detail": [ { "loc": ["query", "from"], "msg": "field required", "type": "value_error.missing" } ] }
```
and `{ "detail": "range and from/to are mutually exclusive" }` and
`{ "detail": { "code": "EARNINGS_RANGE_INVALID", "message": "unknown range" } }`.

Tests assert: query params per range, header presence (`X-CSRF-Token`), and that
each error body maps to the expected `ApiError` subtype.

## 6. Data & State Management

The suite verifies the data/state contract rather than introducing it.

- **DTO→domain:** Moshi adapters parse `total_minor`/`amount_minor` as `Long`
  (no float rounding), `delta_pct_from_prev` as nullable `Double`, ISO-8601 →
  `Instant` via a registered `InstantAdapter`. Test asserts a `null`
  `delta_pct_from_prev` maps to `null`, not `0.0`.
- **Ordering:** `EarningsSeriesDto.points` → `List<EarningsPoint>` sorted by
  `periodStart` ascending; test feeds out-of-order points and asserts sorting.
- **State emissions:** For each `onRangeSelected`, Turbine asserts the emission
  sequence and the terminal `selectedRange` equals the requested range. The
  latest-wins test enqueues a slow first response and a fast second selection
  and asserts the first never reaches `Success`.
- **Stale/cache:** Repository returns cached series with `isStale = true` when
  the network call fails but a Room row exists. Test seeds in-memory Room, fails
  the `MockWebServer` response (or `enqueue` socket disconnect), asserts
  `Success(isStale = true)`.
- **Empty:** `points = []` and a zero summary → `EarningsUiState.Empty`.

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
  configured cap. POST-equivalent (none here) is N/A.
- **Malformed JSON:** Body with wrong types → `ApiResult.Failure(ParseError)`,
  not a crash.
- **detail mapping:** Parameterized JUnit test (`@Parameterized` or a
  table-driven loop) over the three `detail` shapes asserting the mapped
  `ApiError`.

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
  with locale grouping/decimal separators and the configured currency symbol,
  guarding against `String.format` hardcoding.

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

- **R-1 (signature drift):** Exact field names (`total_minor` vs `totalMinor`,
  `points` vs `series`) and the `EarningsRange` enum values are inferred from
  `frontend/src/api/types.ts` and `AND-251`. **Open:** confirm against
  `/openapi.json`; align fixtures before merge. Mitigation: a contract test that
  diffs fixture keys against the committed OpenAPI snapshot.
- **R-2 (granularity ownership):** Whether `granularity` is client- or
  server-derived per range affects FR-3 assertions. **Open:** confirm with
  `AND-251` owner.
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
