---
id: AND-256
title: Earnings ViewModel
milestone: M6
epic: E34
priority: P1
size: M
depends_on: [AND-251]
blocks: []
status: reviewed
reviewed_on: 2026-06-06
---

# AND-256 — Earnings ViewModel

## 1. Overview & Goal

This ticket delivers the presentation-layer state holder for the Earnings feature: `EarningsViewModel`. It owns the user-selectable reporting **range** (e.g. 7D / 30D / 90D / YTD / ALL), drives loading of the earnings **summary** and **time-series** payloads through the repository introduced in AND-251, and exposes a single, immutable `EarningsUiState` as a `StateFlow` for the Compose screen (built in a downstream ticket) to render.

The goal is a fully unit-tested ViewModel that:

- Models range selection as first-class UI state and re-fetches when the range changes.
- Coordinates two backend calls (summary + series) per range, collapsing them into one coherent UI state.
- Surfaces loading, success, empty, error, offline, and stale variants without leaking Retrofit/Room types upward.
- Survives configuration changes and process-death-light scenarios (range persisted via `SavedStateHandle`).
- Tolerates the unreliable plaintext dev backend (timeouts, transient 5xx, 401 refresh) by delegating resilience to the repository and reflecting the resulting `ApiResult<T>` in state.

This ViewModel is the consumer of AND-251's API/DTO/repository work and the producer of state for the Earnings screen ticket. It contains **no Compose UI** and **no Android framework I/O** beyond `ViewModel`, `SavedStateHandle`, and coroutine scope.

## 2. Context & References

- **Module / package:** `feature-earnings`, package `com.testlogon.android.feature.earnings`. The ViewModel lives at `com.testlogon.android.feature.earnings.EarningsViewModel`; UI-state types under `com.testlogon.android.feature.earnings.state`.
- **Layering:** `app -> feature-earnings -> core-* (core-model, core-data, core-network, core-ui, core-testing)`. The ViewModel depends only on `core-model` (domain types) and the repository interface exported by AND-251 (resident in `core-data` or `feature-earnings/data` per AND-251's decision). It must not depend on `core-network` Retrofit services directly.
- **Upstream — AND-251 (Earnings API + DTOs, P0):** provides `EarningsApi` (Retrofit), DTOs for the summary and series endpoints, DTO→domain mappers, and `EarningsRepository` returning `ApiResult<T>`. AND-251 mirrors the web reference `frontend/src/api/endpoints/earnings.ts`. This ticket consumes that repository; it does not define endpoints itself (see §5).
- **Web reference:** `src/api/endpoints/earnings.ts` (CORRECTED: `from_date`/`to_date`/`granularity` summary call — *not* a `range` param — plus separate `quick-stats` and paginated `transactions` calls), shared types in `src/api/types.ts`, screen behavior in `src/pages/earnings/EarningsPage.tsx`. The Android range enum maps the web app's client-side presets (`7d/30d/90d/1y/All`) to a lookback-day window; state shape should be semantically consistent with that selector.
- **Auth/session:** cookie-based session with `X-CSRF-Token` echo and a single `POST /ui/session/refresh` on 401, all handled inside the OkHttp/auth stack (AND-027) beneath the repository. The ViewModel never touches cookies or CSRF.
- **Patterns:** ViewModels expose `StateFlow<UiState>`; typed `ApiResult<T>`; FastAPI `detail` mapping (`string | [{msg}] | {code,...}`) performed in `core-network`/repository, surfaced here as a domain `UiError`.

## 3. Functional Requirements

FR-1 **Range model.** Define `EarningsRange` enum with cases `SEVEN_DAYS`, `THIRTY_DAYS`, `NINETY_DAYS`, `ONE_YEAR`, `ALL`, each carrying the lookback day count used to compute the query window and a stable, translatable label key. Default range is `THIRTY_DAYS`.
> **[CORRECTED]** The backend earnings endpoints do **not** accept a `range` wire token. Verified against `GET /ui/earnings/summary` (OpenAPI) and `src/api/endpoints/earnings.ts`: the summary endpoint is parameterized by `from_date`/`to_date` (`YYYY-MM-DD`, UTC) plus a `granularity` (`day|week|month`), not by a `7d/30d/...` token. The web app (`src/pages/earnings/EarningsPage.tsx`) holds a client-side preset list `[7d, 30d, 90d, 1y, All] → days [7, 30, 90, 365, null]` and computes `from_date = daysAgo(days)` / `to_date = today` (or both `undefined` for "All"). There is **no `ytd` option** in the web client; the year preset is a rolling 365-day window labelled `1y`. The Android enum therefore carries a `lookbackDays: Int?` (null = ALL = unbounded, both dates omitted), and AND-251's repository/mappers are responsible for turning that into `from_date`/`to_date` strings. The `EarningsRange` cases map to: `SEVEN_DAYS`=7, `THIRTY_DAYS`=30, `NINETY_DAYS`=90, `ONE_YEAR`=365, `ALL`=null.

FR-2 **Initial load.** On first collection of `uiState`, the ViewModel loads summary + series for the current (restored or default) range exactly once. It must not re-trigger a load purely because a new collector subscribes.

FR-3 **Range selection.** `onRangeSelected(range: EarningsRange)` updates the selected range immediately (so the chip/segmented control reflects the choice synchronously), persists it to `SavedStateHandle`, and triggers a fresh load for that range. Selecting the already-selected range is a no-op for fetching unless the current state is an error/empty (then it acts as retry).

FR-4 **Combined fetch.** The UI state reaches `Content` only when the load succeeds; on failure state is `Error`.
> **[CORRECTED]** There is **no separate "series" endpoint.** Verified against `EarningsSummaryOut` (OpenAPI) and `src/api/types.ts: EarningsSummary`: the time series is an embedded `time_series: TimeSeriesPoint[]` field of the single `GET /ui/earnings/summary` response, alongside `breakdown`, `total_cents`, `transaction_count`, and `currency`. So summary **and** series arrive from **one** call. The web app (`EarningsPage.tsx`) reads `summary.time_series` and `summary.breakdown` from that one `getEarningsSummary` result. Consequently the two-concurrent-calls/partial-success machinery is **not** required for summary+series — a single summary fetch yields both, and there is no summary-ok/series-failed partial case. (The web client does issue two *other* independent calls — `getEarningsQuickStats` → `GET /ui/earnings/quick-stats` and a paginated `getEarningsTransactions` → `GET /ui/earnings/transactions` — but those are out of this ViewModel's scope as defined; see §13 R1/R6.) Retained for design flexibility: if AND-251 still surfaces summary and quick-stats as two repository methods, the concurrent-fetch + last-write-wins logic in §4.2 applies to *those* two; partial-success policy (one ok / one failed) is then the open question in §13 R2.

FR-5 **Refresh.** `refresh()` re-fetches the current range. While refreshing with existing content present, expose `isRefreshing = true` and keep the previously loaded content visible (no full-screen spinner).

FR-6 **Loading states.** First load with no prior content → full `Loading`. Range change with prior content → `Loading` (content may be cleared since it belongs to a different range). Refresh of same range → content retained + `isRefreshing`.

FR-7 **Empty state.** When both calls succeed but the series is empty and summary indicates no earnings activity, state is `Content` with `isEmpty = true` so the screen can show an empty placeholder rather than an error.

FR-8 **Staleness.** If the repository returns cached/stale data (offline or after a failed network refresh fallback), state is `Content` with `isStale = true` and an optional `lastUpdated` epoch-millis timestamp.

FR-9 **Error retry.** `retry()` re-issues the last attempted load (same range) and is the action wired to an error-state retry button.

FR-10 **Cancellation.** A new range selection or refresh while a fetch is in flight cancels the prior fetch coroutine so a slow earlier response cannot overwrite newer state (last-write-wins by request generation, see §6).

FR-11 **No UI in ViewModel.** No `Context`, `Composable`, formatting of currency/dates, or string resource resolution in the ViewModel — only enum/keys/raw domain values; formatting is the screen's responsibility.

## 4. Technical Design

### 4.1 Types

```kotlin
package com.testlogon.android.feature.earnings.state

// CORRECTED: enum carries a lookback day count (null = ALL/unbounded), NOT a
// server "range" token — the backend takes from_date/to_date + granularity.
// `key` is a stable, locale-independent identifier persisted in SavedStateHandle.
enum class EarningsRange(val key: String, val lookbackDays: Int?, val labelKey: String) {
    SEVEN_DAYS("7d", 7, "earnings_range_7d"),
    THIRTY_DAYS("30d", 30, "earnings_range_30d"),
    NINETY_DAYS("90d", 90, "earnings_range_90d"),
    ONE_YEAR("1y", 365, "earnings_range_1y"),     // rolling 365d; web labels this "1y" (no YTD)
    ALL("all", null, "earnings_range_all");        // null lookback -> omit from_date/to_date

    companion object {
        val DEFAULT = THIRTY_DAYS
        fun fromKey(value: String?): EarningsRange =
            entries.firstOrNull { it.key == value } ?: DEFAULT
    }
}

data class EarningsUiState(
    val range: EarningsRange = EarningsRange.DEFAULT,
    val phase: Phase = Phase.Loading,
    val summary: EarningsSummary? = null,   // core-model (AND-251)
    val series: List<EarningsPoint> = emptyList(), // core-model (AND-251)
    val isRefreshing: Boolean = false,
    val isStale: Boolean = false,
    val isEmpty: Boolean = false,
    val lastUpdated: Long? = null,          // epoch millis, when known
    val error: UiError? = null
) {
    sealed interface Phase {
        data object Loading : Phase
        data object Content : Phase
        data object ErrorState : Phase
    }
}
```

`EarningsSummary`, `EarningsPoint`, and `UiError` are domain types owned by `core-model`/`core-network` (delivered or extended by AND-251 / AND-027). This ticket consumes them and does **not** redefine wire DTOs.

### 4.2 ViewModel

```kotlin
package com.testlogon.android.feature.earnings

@HiltViewModel
class EarningsViewModel @Inject constructor(
    private val repository: EarningsRepository,      // from AND-251
    private val savedStateHandle: SavedStateHandle,
    @Dispatcher(IO) private val ioDispatcher: CoroutineDispatcher // injectable for tests
) : ViewModel() {

    private val selectedRange: StateFlow<EarningsRange> =
        savedStateHandle.getStateFlow(KEY_RANGE, EarningsRange.DEFAULT.key)
            .map(EarningsRange::fromKey)
            .stateIn(viewModelScope, SharingStarted.Eagerly, EarningsRange.DEFAULT)

    private val _internal = MutableStateFlow(InternalState())
    private var loadJob: Job? = null
    private var requestGen = 0L

    val uiState: StateFlow<EarningsUiState> =
        combine(selectedRange, _internal) { range, internal ->
            internal.toUiState(range)
        }.stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5_000),
            initialValue = EarningsUiState()
        )

    init { load(EarningsRange.fromKey(savedStateHandle[KEY_RANGE]), reason = LoadReason.INITIAL) }

    fun onRangeSelected(range: EarningsRange) {
        if (range == selectedRange.value && _internal.value.phase != InternalPhase.ERROR) {
            // already selected and healthy -> no-op
            if (_internal.value.phase == InternalPhase.CONTENT) return
        }
        savedStateHandle[KEY_RANGE] = range.key
        load(range, reason = LoadReason.RANGE_CHANGE)
    }

    fun refresh() = load(selectedRange.value, reason = LoadReason.REFRESH)
    fun retry() = load(selectedRange.value, reason = LoadReason.RETRY)

    private fun load(range: EarningsRange, reason: LoadReason) {
        val gen = ++requestGen
        loadJob?.cancel()
        loadJob = viewModelScope.launch {
            _internal.update { it.beginLoad(reason) }
            // CORRECTED: summary + time_series come from ONE endpoint
            // (GET /ui/earnings/summary -> EarningsSummaryOut{ breakdown, time_series, ... }).
            // The repository derives from_date/to_date from range.lookbackDays and
            // returns the summary (with embedded series) as a single ApiResult.
            val summaryRes = withContext(ioDispatcher) { repository.getSummary(range) }
            if (gen != requestGen) return@launch // superseded; drop result
            _internal.update { it.applyResult(summaryRes) }
        }
    }

    companion object { const val KEY_RANGE = "earnings_range" }
}
```

`InternalState`/`InternalPhase`/`LoadReason` are private mapping helpers; `beginLoad` decides whether to clear content (range change/initial) or retain it (refresh), `applyResult` folds the single `ApiResult<EarningsSummary>` (summary with embedded series + breakdown) into success/error/empty/stale. `requestGen` + the `gen != requestGen` guard implement FR-10 (last-write-wins, stale results discarded). `loadJob?.cancel()` cancels the in-flight network work. (If AND-251 instead splits into two repository methods — e.g. summary + quick-stats — restore the `async`/`await` pair and a two-arg `applyResults`; the public ViewModel API is unchanged.)

### 4.3 Concurrency & dispatchers

Repository suspend functions run on the injected `ioDispatcher` (Hilt-qualified `@Dispatcher(IO)`); the fold/state update runs on the main-immediate scope of `viewModelScope`. Tests inject `StandardTestDispatcher`/`UnconfinedTestDispatcher` via the constructor so no static dispatcher rule is needed. `SharingStarted.WhileSubscribed(5_000)` keeps the shared state alive across short config-change gaps without re-running `init` logic; the actual initial fetch is kicked in `init`, guarded so it runs once.

## 5. API Contract

This ViewModel issues **no HTTP directly**. All network access is via `EarningsRepository`, owned by **AND-251**, which defines the Retrofit `EarningsApi`, DTOs, mappers, and error mapping. The contract relevant here is the repository surface this ticket consumes:

```kotlin
interface EarningsRepository {                 // defined by AND-251
    // CORRECTED: one call returns summary WITH embedded time series + breakdown.
    // Implementation derives from_date/to_date (YYYY-MM-DD UTC) from range.lookbackDays
    // (ALL -> omit both) and passes granularity (default "day").
    suspend fun getSummary(range: EarningsRange): ApiResult<EarningsSummary>
}
```

For traceability (authoritative paths verified against the OpenAPI index and `src/api/endpoints/earnings.ts`):

- **`GET /ui/earnings/summary`** → `200: EarningsSummaryOut` / `422: HTTPValidationError`. Query params: `from_date` (`YYYY-MM-DD`, UTC), `to_date` (`YYYY-MM-DD`, UTC), `granularity` (`day|week|month`, default `day`), plus `from_ts`/`to_ts` (Unix-seconds alternatives), `user_sub`. **No `range` token param exists.**
- (Out of this ViewModel's scope but part of the feature: `GET /ui/earnings/quick-stats` → `EarningsQuickStatsOut`, and `GET /ui/earnings/transactions` → `EarningsTransactionsOut`, cursor-paginated. See §13 R6.)

Actual wire success shape (`EarningsSummaryOut`, verified — all monetary values are **integer cents**, not floats):

```jsonc
// GET /ui/earnings/summary -> EarningsSummaryOut
{
  "total_cents": 123456,
  "currency": "USD",
  "transaction_count": 87,
  "breakdown": { "subscriptions": 90000, "tips": 20000, "unlocks": 8000, "vod_purchases": 5456, "other": 0 },
  "time_series": [
    { "date": "2026-05-01", "total": 4210, "tips": 1000, "subscriptions": 3000, "unlocks": 210, "vod_purchases": 0, "other": 0 },
    { "date": "2026-05-02", "total": 0,    "tips": 0,    "subscriptions": 0,    "unlocks": 0,   "vod_purchases": 0, "other": 0 }
  ]
}
```

> **[CORRECTED]** The earlier draft's shapes were wrong: there is **no** `delta_pct` and **no** `as_of` field; `total` is `total_cents` (integer cents, not a `1234.56` float); the series item key is `date` (a `"YYYY-MM-DD"` string, **not** an epoch `t`) and the per-point amount is split across `total`/`tips`/`subscriptions`/`unlocks`/`vod_purchases`/`other` integer-cent fields, not a single `value`. Domain types in §4.1 (`EarningsSummary`, `EarningsPoint`) must be defined by AND-251 to mirror these fields (notably integer-cent amounts; formatting to currency happens in the screen, see FR-11). The `lastUpdated`/`as_of` concept (§4.1) has no server source — see §6 and §13 R4.

These are idempotent GETs, making them eligible for the bounded backoff retry policy in `core-network`. The ViewModel treats the response purely through the mapped domain types; any change to wire shape is absorbed by AND-251's mappers.

## 6. Data & State Management

- **Single source of truth:** `uiState: StateFlow<EarningsUiState>`, derived by `combine(selectedRange, _internal)`. Range lives in `SavedStateHandle` (key `earnings_range`, stored as the enum `key` string, e.g. `"30d"`) so it survives config change and light process death; the rest of the state is recomputed on restore by re-fetching (with stale cache fill from Room via AND-251 if available).
- **Request generation:** monotonic `requestGen: Long`. Each `load()` increments it and captures `gen`; results from a superseded generation are dropped (FR-10). Combined with `loadJob.cancel()`, this guarantees last-write-wins.
- **State transition rules:**
  - INITIAL / RANGE_CHANGE: `phase=Loading`, `summary=null`, `series=[]`, `isRefreshing=false`.
  - REFRESH / RETRY with prior content: keep `summary`/`series`, set `isRefreshing=true`, `phase` stays `Content`.
  - `ApiResult.Success` → `phase=Content`, populate data, `isEmpty = summary.totalCents == 0 && summary.timeSeries.isEmpty()` (CORRECTED: the server has no `isZeroActivity` flag; "empty" is derived from `total_cents == 0` and an empty `time_series`, matching the web app, which renders "No revenue data for this period" / "No earnings yet" when the series is empty / breakdown has no positive entries), `isStale = result.fromCache`, `lastUpdated = result.fetchedAtMillis` (client-side fetch time; CORRECTED: `EarningsSummaryOut` carries **no** server `as_of`/`generated_at` timestamp, so `lastUpdated` is the local fetch/cache time supplied by AND-251's `ApiResult`, or `null` if unavailable).
  - `ApiResult.Error` (and no usable cache) → `phase=ErrorState`, `error=mapped`, content cleared on range change but retained on a failed refresh (so the user keeps seeing prior data with an inline error message + `isStale`).
- **Caching:** read-through cache is AND-251's responsibility (Room). This ViewModel only reads the `fromCache`/`stale` flag the repository returns and reflects it as `isStale`.

## 7. Error Handling & Resilience

- The unreliable plaintext dev host (`http://18.222.237.167:8000`) means timeouts (~20s) and transient 5xx are expected. Retry/backoff for idempotent GETs and the single 401→`/ui/session/refresh`→retry are handled in `core-network`/repository (AND-027/AND-251); the ViewModel consumes the final `ApiResult`.
- `ApiResult.Error` is mapped to a `UiError` carrying a category (`Network`, `Timeout`, `Auth`, `Server`, `Unknown`) and a translatable message key, derived from the FastAPI `detail` shape (`string | [{msg}] | {code,...}`) already normalized upstream. The ViewModel does not parse `detail` itself.
- **Offline / stale fallback:** if the repository returns cached data with `fromCache=true`, surface `Content(isStale=true)` rather than an error, so the screen shows data with a "showing saved data" affordance.
- **Failed refresh with content present:** retain content, set `error` (non-blocking inline), keep `isStale` if the shown data is cached; do not blank the screen.
- **Cancellation safety:** `CancellationException` from `loadJob.cancel()` propagates normally and is never converted to a `UiError`. The `gen` guard prevents a late `await` from a cancelled (but not yet cancelled-checked) coroutine from mutating state.
- **No infinite spinners:** because the repository enforces the ~20s timeout, the ViewModel will always transition out of `Loading`; a test asserts this via a delayed fake.

## 8. Security & Privacy

- No credentials, cookies, or CSRF tokens are handled here; session/cookie jar + `X-CSRF-Token` live in the OkHttp stack (AND-027). The ViewModel must never log raw responses or earnings figures.
- Earnings amounts are user-financial data: do not place them in analytics events, crash breadcrumbs, or non-redacted logs (see §10). `UiError` messages must not embed server-provided PII/amounts.
- `SavedStateHandle` stores only the non-sensitive range token (`"30d"` etc.), which is safe to persist in the saved-instance bundle.
- Transport is plaintext **only** for the dev host; cleartext is restricted via network-security-config to that host (owned by AND-027). No security regression is introduced by this ticket.

## 9. Accessibility & i18n

- The ViewModel exposes **label keys** (`earnings_range_7d`, …), never resolved strings, so the screen owns localization and RTL. No hardcoded user-facing text in the ViewModel.
- Range tokens are locale-independent wire values; YTD/ALL boundaries are computed server-side, so no client date-locale logic lives here.
- Empty/stale/error are modeled as explicit state fields (`isEmpty`, `isStale`, `error`) so the screen can provide distinct, screen-reader-friendly announcements and a clearly labeled retry control (FR-9). No content-description work is in scope for this ticket; that belongs to the Earnings screen ticket.

## 10. Telemetry & Logging

- Optional, behind the app's logging facade (no `android.util.Log` of payloads). Recommended events (names only; emission may be deferred to the screen ticket if no logger is injected): `earnings_range_selected{range}`, `earnings_load_started{range,reason}`, `earnings_load_succeeded{range,from_cache}`, `earnings_load_failed{range,error_category}`.
- **Redaction:** event payloads carry only the range token, a boolean `from_cache`, and an `error_category` enum — never amounts, currency totals, or raw `detail` strings.
- If a logger is not injected in this ticket, the ViewModel exposes the data needed (range, reason, error category) so a thin telemetry decorator can be added without changing the public API.

## 11. Testing Strategy

Pure JVM unit tests (`feature-earnings/src/test`), using `core-testing` utilities, `kotlinx-coroutines-test` (`runTest`, `StandardTestDispatcher`), Turbine for `StateFlow` assertions, and a hand-written `FakeEarningsRepository`. No Robolectric/instrumentation required (`SavedStateHandle` is constructed directly).

```kotlin
@Test fun initialLoad_emitsLoadingThenContent_forDefaultRange()
@Test fun rangeSelected_persistsToSavedStateHandle_andRefetches()
@Test fun rangeSelected_sameHealthyRange_isNoOp()
@Test fun rangeSelected_inErrorState_actsAsRetry()
@Test fun summarySucceeds_emptySeriesAndZeroTotal_setsIsEmptyTrue()
@Test fun summaryFails_emitsErrorState()   // single-call model; no series sub-call
@Test fun refresh_withContent_setsIsRefreshing_andKeepsContent()
@Test fun failedRefresh_withPriorContent_retainsContent_andSetsError()
@Test fun repositoryReturnsCache_setsIsStaleTrue_notError()
@Test fun rapidRangeSwitch_dropsStaleResult_lastWriteWins()   // gen guard
@Test fun slowCall_doesNotHangState_transitionsOutOfLoading()
@Test fun savedRange_isRestoredOnConstruction()
@Test fun errorMapping_timeoutCategory_isSurfaced()
@Test fun cancellation_doesNotProduceUiError()
```

The `rapidRangeSwitch` test uses a `FakeEarningsRepository` whose `getSummary` for the first range delays past the second selection, then asserts the final `uiState.range` and content correspond to the **second** range only (FR-10). Coverage target: all public functions and every `Phase`/flag transition branch exercised; CI gate ≥ 85% line coverage for `EarningsViewModel` and its private mapping helpers.

## 12. Dependencies & Sequencing

- **Hard dependency — AND-251 (Earnings API + DTOs, P0):** must provide `EarningsRepository` + domain types (`EarningsSummary`, `EarningsPoint`) and error mapping before this ticket can compile against real types. If AND-251 is in flight, develop against the `FakeEarningsRepository` and the agreed interface signature, then swap.
- **Transitive — AND-027:** OkHttp/auth/cookie/CSRF/retry stack underpinning the repository (already a dep of AND-251). Not directly referenced here.
- **Hilt wiring:** requires `@Dispatcher(IO)` qualifier + dispatcher module and the `EarningsRepository` Hilt binding (provided by AND-251's data module). This ticket adds only the `@HiltViewModel` annotation and constructor injection.
- **Blocks:** the Earnings **screen** ticket (Compose UI consuming `uiState` + calling `onRangeSelected/refresh/retry`) — that downstream ticket owns §9 content-descriptions, currency/date formatting, and the range selector composable. (Exact screen AND-id to be confirmed in the M6/E34 backlog; this ticket should be listed as its `depends_on`.)

## 13. Risks & Open Questions

- **R1 — Repository shape mismatch:** AND-251 may expose one combined `getEarnings(range)` instead of two calls. Mitigation: `load()` is the only affected code; public API unchanged. Confirm with AND-251 owner before merge.
- **R2 — Partial success policy:** v1 treats one-of-two failures as full `Error`. Open question: should summary render while series shows an inline chart error? Deferred; revisit with the screen ticket.
- **R3 — Range semantics (RESOLVED):** Verified — the API expects explicit `from_date`/`to_date` (`YYYY-MM-DD`, UTC) computed client-side, **not** a server-side `range` token, and there is no YTD option (web uses a rolling `1y`/365-day window). The enum therefore carries `lookbackDays` and AND-251 computes the UTC date window (web uses `daysAgo(n)`/today; "All" omits both dates). Timezone note: web computes from local `new Date()` then `toISOString().slice(0,10)`, so the day boundary is effectively local-clock → UTC-date; Android should match (use the device clock; AND-251 owns the exact `from_date` derivation). No client i18n of the range itself is needed.
- **R4 — Stale flag availability:** `isStale`/`fromCache` depends on AND-251's `ApiResult`/repository exposing a cache provenance flag. If absent, `isStale` is always false until AND-251 adds it; tracked as a follow-up.
- **R5 — Unreliable dev host** can make manual QA flaky; rely on fakes for deterministic tests and accept that live smoke testing may intermittently show stale/error states (expected by design).
- **R6 — Quick-stats & transactions scope:** The web Earnings screen also renders quick-stat cards (`GET /ui/earnings/quick-stats`) and a cursor-paginated transactions table (`GET /ui/earnings/transactions`). This ViewModel as specified models only the summary (+ embedded series + breakdown). Open question for the M6/E34 backlog: should `EarningsViewModel` also own quick-stats and transaction pagination, or do those get separate ViewModels/tickets? If folded in, the single-`getSummary` `load()` becomes a concurrent summary+quick-stats fetch (re-enabling the §4.2 `async`/`await` + partial-success path) and transactions get their own paging flow. Confirm with the screen ticket owner before AND-251's repository surface is frozen.

## 14. Acceptance Criteria

AC-1 `EarningsViewModel` is unit-tested (the source ticket's sole acceptance bullet) with the suite in §11 passing and ≥ 85% line coverage on the ViewModel.
AC-2 `EarningsRange` enum exists with five cases and correct `lookbackDays` (`7/30/90/365/null`) and stable keys (`7d/30d/90d/1y/all`); default is `THIRTY_DAYS`. (CORRECTED from the draft's `ytd`/`all` wire tokens — the backend has no range token; keys map to a from/to date window via AND-251.)
AC-3 `uiState: StateFlow<EarningsUiState>` is exposed; on first subscription it loads default (or restored) range and emits `Loading` → `Content` (or `ErrorState`).
AC-4 `onRangeSelected(range)` updates `uiState.range` synchronously, persists the enum `key` to `SavedStateHandle`, and re-fetches; selecting the same healthy range is a no-op.
AC-5 Summary fetch (with embedded series + breakdown): success → `Content`; failure (no cache) → `ErrorState` with a categorized `UiError`. (CORRECTED: single summary call, not concurrent summary+series; see §4.4/§5.)
AC-6 `refresh()` retains existing content and sets `isRefreshing=true`; a failed refresh with prior content keeps content and sets `error`.
AC-7 Empty payloads yield `Content(isEmpty=true)`; cached/offline data yields `Content(isStale=true)` rather than `ErrorState`.
AC-8 Rapid range switches never let an earlier slow response overwrite newer state (last-write-wins verified by test).
AC-9 No Compose, `Context`, string-resource, currency/date-formatting, or cookie/CSRF code in the ViewModel; only domain types and label keys are exposed.
AC-10 Saved range is restored after re-construction (config-change simulation test passes).

## 15. Definition of Done

- Code merged to `android-port` under `android/feature-earnings/`, package `com.testlogon.android.feature.earnings`, building with Kotlin 2.0.21 / AGP 8.7.3 / JDK 17 / Gradle 8.9.
- `EarningsViewModel`, `EarningsRange`, `EarningsUiState` (+ `Phase`, `UiError` usage) implemented per §4; Hilt-injectable via `@HiltViewModel` with constructor `EarningsRepository`, `SavedStateHandle`, and qualified IO dispatcher.
- All §11 unit tests implemented and green in CI; ktlint/detekt clean; no new Lint errors.
- No direct Retrofit/OkHttp/Room/Compose imports in the ViewModel; verified by a module-boundary check (or review).
- Public API documented with KDoc; `depends_on: AND-251` recorded and the downstream Earnings screen ticket updated to depend on AND-256.
- Manual smoke against dev backend confirms range switching triggers refetch and that timeout/offline produces an error/stale state (not a hang), acknowledging dev-host flakiness.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer.

1. **Earnings summary endpoint is `GET /ui/earnings/summary`.** VERDICT: Verified. SOURCE: OpenAPI `GET /ui/earnings/summary` (op=`earnings_summary_ui_earnings_summary_get`, resp `200:EarningsSummaryOut;422:HTTPValidationError`); `src/api/endpoints/earnings.ts: getEarningsSummary`.
2. **Summary endpoint takes `from_date`/`to_date` (YYYY-MM-DD UTC) + `granularity` (day|week|month), NOT a `range` token.** VERDICT: Corrected (draft claimed a `7d/30d/90d/ytd/all` wire token). SOURCE: OpenAPI `GET /ui/earnings/summary` params `from_date,to_date,granularity,from_ts,to_ts,user_sub`; `src/api/endpoints/earnings.ts: getEarningsSummary` params `{from_date?,to_date?,granularity?}`.
3. **Time series is embedded in the summary response (`EarningsSummaryOut.time_series`), with NO separate "series" endpoint.** VERDICT: Corrected (draft posited a separate series GET + two concurrent calls). SOURCE: OpenAPI schema `EarningsSummaryOut.time_series: TimeSeriesPoint[]`; `src/api/types.ts: EarningsSummary`; `src/pages/earnings/EarningsPage.tsx` reads `summary.time_series`.
4. **`EarningsSummaryOut` fields: `total_cents`(int), `currency`, `transaction_count`(int), `breakdown`(EarningsBreakdown), `time_series`(TimeSeriesPoint[]) — no `delta_pct`, no `as_of`.** VERDICT: Corrected (draft claimed `{total:1234.56, currency, delta_pct, as_of}`). SOURCE: OpenAPI `components.schemas.EarningsSummaryOut`; `src/api/types.ts: EarningsSummary`.
5. **`TimeSeriesPoint` fields: `date`(string "YYYY-MM-DD", required) + integer-cent `total/tips/subscriptions/unlocks/vod_purchases/other` — NOT `{t:epoch, value:float}`.** VERDICT: Corrected. SOURCE: OpenAPI `components.schemas.TimeSeriesPoint`; rendered in `src/pages/earnings/EarningsPage.tsx: RevenueChart` (uses `pt.date`, `pt.tips`, etc.).
6. **`EarningsBreakdown` = `{subscriptions, tips, unlocks, vod_purchases, other}` (integer cents).** VERDICT: Verified. SOURCE: OpenAPI `components.schemas.EarningsBreakdown`; `src/api/types.ts: EarningsBreakdown`.
7. **Web presets are client-side: `[7d, 30d, 90d, 1y, All] → days [7, 30, 90, 365, null]`; default 30; "All" omits both dates; year is a rolling 365d (no YTD).** VERDICT: Corrected (draft had a `YEAR_TO_DATE`/`ytd` case). SOURCE: `src/pages/earnings/EarningsPage.tsx` (`PRESETS`, `daysAgo`, `activePreset` default 30, `fromDate`/`toDate` undefined when preset days is null).
8. **Default range is 30 days.** VERDICT: Verified. SOURCE: `src/pages/earnings/EarningsPage.tsx` `useState<number|null>(30)`.
9. **Empty state is derived (no server `isZeroActivity` flag): empty `time_series` / zero totals.** VERDICT: Corrected (draft referenced `summary.isZeroActivity`). SOURCE: `EarningsSummaryOut` has no such field; `src/pages/earnings/EarningsPage.tsx` shows "No revenue data for this period" when `chartData.length===0` and "No earnings yet" when no positive breakdown entries.
10. **Auth: cookie-based session, `X-CSRF-Token` set from the `ui_csrf` cookie, single `POST /ui/session/refresh` on 401 then one retry.** VERDICT: Verified. SOURCE: `src/api/client.ts` (`getCookie("ui_csrf")` → `X-CSRF-Token`; `credentials:"include"`; `refreshSession()` POSTs `/ui/session/refresh`; single-flight `refreshPromise`; retries original request once); OpenAPI `POST /ui/session/refresh` (op=`ui_session_refresh_ui_session_refresh_post`, `200`).
11. **The ViewModel handles no cookies/CSRF/refresh (all in the OkHttp/auth stack).** VERDICT: Verified (design choice consistent with the web client centralizing this in `client.ts`). SOURCE: `src/api/client.ts` performs all auth/CSRF/refresh transport-side; AND-027 owns the Android equivalent.
12. **Error/validation shape: `422 HTTPValidationError`; FastAPI `detail` is `string | [{msg,...}] | {code,...}` and is normalized upstream.** VERDICT: Verified. SOURCE: OpenAPI `422:HTTPValidationError` on all three earnings endpoints; `src/api/client.ts: normalizeErrorDetail` (handles string, `[{msg}]`, and object-with-`code` via `mapAuthorizationError`).
13. **401→refresh→retry, and 403 = permission/geo-block handling, both transport-side.** VERDICT: Verified. SOURCE: `src/api/client.ts` 401 and 403 branches (403 `code === "geo_blocked"`, `role_required*` mapping).
14. **Sibling endpoints exist for the feature: `GET /ui/earnings/quick-stats` (`EarningsQuickStatsOut`) and `GET /ui/earnings/transactions` (`EarningsTransactionsOut`, cursor-paginated, `limit≤200`).** VERDICT: Verified (noted as out-of-scope for this ViewModel — see §13 R6). SOURCE: OpenAPI `GET /ui/earnings/quick-stats`, `GET /ui/earnings/transactions`; `src/api/endpoints/earnings.ts`; `src/api/types.ts: EarningsTransactionsResp`.
15. **Money is integer cents end-to-end; formatting (cents→currency) happens in the screen.** VERDICT: Verified. SOURCE: all `*_cents`/`TimeSeriesPoint` int fields in OpenAPI; `src/pages/earnings/EarningsPage.tsx: formatCents` divides by 100 in the UI layer (consistent with FR-11).
16. **`StateFlow<UiState>` ViewModel pattern, `SavedStateHandle` for range persistence, Hilt `@HiltViewModel`, injected IO dispatcher.** VERDICT: Unverified-assumption (Android framework/architecture choices, not derivable from backend or web sources). SOURCE: framework ref — Android Architecture (UI layer / ViewModel + StateFlow): https://developer.android.com/topic/architecture/ui-layer ; SavedStateHandle: https://developer.android.com/topic/libraries/architecture/viewmodel/viewmodel-savedstate ; Hilt + ViewModel: https://developer.android.com/training/dependency-injection/hilt-jetpack .
17. **Coroutine concurrency: `viewModelScope`, last-write-wins via request generation + `loadJob.cancel()`, `kotlinx-coroutines-test` for tests.** VERDICT: Unverified-assumption (Android framework choice). SOURCE: framework ref — Coroutines on Android / testing: https://developer.android.com/kotlin/coroutines and https://developer.android.com/kotlin/coroutines/test .
18. **~20s timeout + bounded backoff retry for idempotent GETs and the single 401 refresh live in `core-network`/AND-027.** VERDICT: Unverified-assumption (no timeout/retry policy is expressed in OpenAPI or the web `fetch` client; the web client has no explicit timeout). SOURCE: not present in sources — owned by AND-027/AND-251; the web `client.ts` performs no retry/backoff beyond the single 401 retry.
19. **Read-through Room cache and a `fromCache`/stale provenance flag on `ApiResult`.** VERDICT: Unverified-assumption (no caching is visible in the web client; web uses TanStack Query in-memory caching only). SOURCE: not present in sources — depends on AND-251 (tracked as §13 R4). Web `EarningsPage.tsx` uses `useQuery`/`useInfiniteQuery` (memory cache, not Room).
20. **`lastUpdated` is a client-side fetch/cache time, not a server timestamp.** VERDICT: Corrected (draft mapped it to `summary.as_of`, which does not exist). SOURCE: `EarningsSummaryOut` has no timestamp field (OpenAPI); see claim 4.

### Corrections made

- **Range model (FR-1, §4.1, §2, AC-2):** replaced the non-existent `7d/30d/90d/ytd/all` server "range" wire token with an enum carrying `lookbackDays` (7/30/90/365/null); dropped `YEAR_TO_DATE`/`ytd` in favor of `ONE_YEAR`/`1y` (rolling 365d) to match the web client; AND-251 derives `from_date`/`to_date`.
- **Endpoint/transport (FR-4, §5):** removed the imaginary separate "series" GET and the two-concurrent-call requirement; the single `GET /ui/earnings/summary` returns summary + embedded `time_series` + breakdown. Repository surface reduced to one `getSummary(range)`; `load()` now does a single fetch. Two-call machinery retained only as a contingency if AND-251 splits summary/quick-stats.
- **Wire shapes (§5, §6, §4.1 derivations):** corrected field names — `total_cents`/`transaction_count`/`breakdown`/`time_series`; `TimeSeriesPoint{date(string), total/tips/subscriptions/unlocks/vod_purchases/other}` (integer cents); removed `delta_pct`, `as_of`, `t`, `value`.
- **Derived state (§6):** `isEmpty` from `total_cents==0 && time_series.isEmpty()`; `lastUpdated` from client fetch time (no server `as_of`).
- **§13 R3** marked RESOLVED (explicit date window confirmed); **R6** added for quick-stats/transactions scope.
- **Tests (§11):** renamed `getSeries`/two-call tests to the single-call model.
- **Frontmatter:** removed duplicate `status: draft`; set `status: reviewed`, added `reviewed_on: 2026-06-06`.

### Open assumptions

- **Timeout/backoff/retry policy (~20s, bounded backoff):** not expressed in OpenAPI or the web `fetch` client (which sets no explicit timeout and no GET retry); owned by AND-027/AND-251. Cannot be verified from the provided sources.
- **Room read-through cache + `fromCache`/stale provenance flag on `ApiResult`:** absent from sources (web uses TanStack Query in-memory caching, not Room); depends on AND-251 (§13 R4). `isStale`/`lastUpdated` are no-ops until AND-251 supplies them.
- **Android architecture choices** (StateFlow/SavedStateHandle/Hilt/coroutine cancellation, request-generation last-write-wins): framework conventions, not backend-derived; cited to Android developer docs (claims 16–17).
- **Domain types `EarningsSummary`/`EarningsPoint`/`UiError` exact Kotlin shape:** defined by AND-251/AND-027; this ticket assumes they mirror the verified wire fields (integer cents, string `date`).
- **`X-SESSION-ID`/`user_sub`/`X-IMPERSONATION-TOKEN` params** appear on the OpenAPI earnings endpoints but the web client sends auth via cookie + `Authorization: Bearer` + `X-IMPERSONATION-TOKEN` header (`client.ts`), not `X-SESSION-ID`. Assumption: the Android auth stack (AND-027) mirrors the web client's cookie/bearer scheme; the `X-SESSION-ID` header is not used by the reference web client and is treated as not-required.

## 17. Test Plan

All cases target `EarningsViewModel` and its private mapping helpers via a hand-written `FakeEarningsRepository` unless stated. JVM/Robolectric cases need no device. IDs trace to §14 Acceptance Criteria.

- **TC-AND-256-01 — Initial load happy path.** Type: unit (JVM, `runTest`+Turbine). Target: `EarningsViewModel.uiState`. Preconditions: empty `SavedStateHandle`; fake returns a successful `EarningsSummary` (non-empty `time_series`, `total_cents>0`) for the default 30d window. Steps: construct VM; collect `uiState`. Expected: emits `Phase.Loading` then `Phase.Content` with `range=THIRTY_DAYS`, populated `summary`+`series`, `isRefreshing=false`, `isEmpty=false`, `error=null`. Traces: AC-1, AC-3.

- **TC-AND-256-02 — Enum/key/lookback correctness.** Type: unit (JVM). Target: `EarningsRange`. Preconditions: none. Steps: assert five cases with keys `7d/30d/90d/1y/all` and `lookbackDays` `7/30/90/365/null`; `DEFAULT==THIRTY_DAYS`; `fromKey("90d")==NINETY_DAYS`; `fromKey(null)==DEFAULT`; `fromKey("ytd")==DEFAULT` (unknown → default). Expected: all assertions pass. Traces: AC-2.

- **TC-AND-256-03 — Range selection persists key and refetches with correct window.** Type: unit (JVM). Target: `onRangeSelected`. Preconditions: VM at default content. Steps: call `onRangeSelected(NINETY_DAYS)`; inspect `SavedStateHandle[KEY_RANGE]` and the range/lookback passed to the fake. Expected: `uiState.range==NINETY_DAYS` synchronously; `SavedStateHandle["earnings_range"]=="90d"`; fake `getSummary` invoked with a range whose `lookbackDays==90`. Traces: AC-4.

- **TC-AND-256-04 — Same healthy range is a no-op; same range while errored acts as retry.** Type: unit (JVM). Target: `onRangeSelected`. Preconditions: (a) VM in `Content` for 30d; (b) VM in `ErrorState` for 30d. Steps: call `onRangeSelected(THIRTY_DAYS)` in each. Expected: (a) no new fetch (fake call count unchanged); (b) a fresh fetch is issued. Traces: AC-4, AC-3.

- **TC-AND-256-05 — Summary success with embedded series → Content (single-call model).** Type: contract/MockWebServer (via real Retrofit `EarningsApi` + repository if available, else unit with realistic fake). Target: repository `getSummary` → VM. Preconditions: MockWebServer enqueues a verified `EarningsSummaryOut` JSON (`total_cents`, `breakdown`, `time_series[{date,...}]`). Steps: trigger load; assert request path `/ui/earnings/summary` with `from_date`/`to_date`/`granularity` query params (no `range` param). Expected: `Phase.Content`; series mapped from `time_series`; breakdown present; one HTTP call only (no series endpoint). Traces: AC-5, AC-3.

- **TC-AND-256-06 — Empty payload → Content(isEmpty=true).** Type: unit (JVM). Target: `applyResult`. Preconditions: fake returns success with empty `time_series` and `total_cents==0`. Steps: load. Expected: `Phase.Content`, `isEmpty=true`, `error=null` (not `ErrorState`). Traces: AC-7.

- **TC-AND-256-07 — Summary failure (no cache) → ErrorState with categorized UiError.** Type: contract/MockWebServer. Target: error mapping path. Preconditions: MockWebServer returns `422` with `HTTPValidationError` body `{"detail":[{"loc":["query","from_date"],"msg":"invalid date","type":"value_error"}]}`, and a second scenario returns `500`. Steps: load each. Expected: `Phase.ErrorState`; `UiError.category` = validation/`Server` respectively; message derived from normalized `detail` (the `msg` string), never raw payload. Traces: AC-5.

- **TC-AND-256-08 — Refresh keeps content and sets isRefreshing; failed refresh retains content + sets error.** Type: unit (JVM, Turbine). Target: `refresh`. Preconditions: VM in `Content`. Steps: (a) call `refresh()` with a delayed success; (b) call `refresh()` that fails. Expected: (a) during flight `isRefreshing=true` with prior `summary`/`series` still visible and `Phase` stays `Content`; settles to refreshed content, `isRefreshing=false`; (b) content retained, `error!=null`, no full-screen `Loading`/`ErrorState` blanking. Traces: AC-6.

- **TC-AND-256-09 — Offline/stale fallback → Content(isStale=true), not error.** Type: unit (JVM). Target: stale mapping. Preconditions: fake returns success flagged `fromCache=true` (and a network error underneath). Steps: load while "offline". Expected: `Phase.Content`, `isStale=true`, `error=null`, `lastUpdated` reflects cache time when provided. Note: gated on AND-251 exposing `fromCache` (§13 R4); until then assert default `isStale=false`. Traces: AC-7, AC-6.

- **TC-AND-256-10 — Rapid range switch: last-write-wins.** Type: unit (JVM, `StandardTestDispatcher`). Target: `requestGen`/`loadJob.cancel()`. Preconditions: fake delays `getSummary` for 7d past a subsequent 90d selection; 90d resolves fast. Steps: `onRangeSelected(SEVEN_DAYS)` then immediately `onRangeSelected(NINETY_DAYS)`; advance time. Expected: final `uiState.range==NINETY_DAYS` and content is 90d's; the late 7d result is dropped (never observed in terminal state). Traces: AC-8.

- **TC-AND-256-11 — Slow call never hangs in Loading.** Type: unit (JVM). Target: timeout handling surfaced via repository. Preconditions: fake `getSummary` returns `ApiResult.Error(Timeout)` after a delay (simulating the ~20s transport timeout). Steps: load; advance time. Expected: state transitions out of `Loading` to `ErrorState(category=Timeout)`; no indefinite spinner. Traces: AC-3, AC-5.

- **TC-AND-256-12 — Saved range restored on reconstruction (config change).** Type: unit (JVM). Target: `SavedStateHandle` restore. Preconditions: `SavedStateHandle` seeded with `{"earnings_range":"90d"}`. Steps: construct a new VM with that handle; collect `uiState`. Expected: initial `range==NINETY_DAYS`; initial load uses the 90d window. Traces: AC-10, AC-4.

- **TC-AND-256-13 — Cancellation does not produce a UiError; no PII/amounts logged.** Type: unit (JVM). Target: cancellation safety + redaction. Preconditions: in-flight load; a new range selection cancels it. Steps: trigger overlap (as TC-10) and inspect that no `error` is emitted from the cancelled job; assert any emitted telemetry/log payload contains only `range`/`reason`/`from_cache`/`error_category` and no amounts or raw `detail`. Expected: `CancellationException` not converted to `UiError`; redaction holds (§8/§10). Traces: AC-8, AC-9 (security/privacy).

- **TC-AND-256-14 — Architecture boundary / no UI leakage (security & purity check).** Type: unit + static (Robolectric not required; a module-boundary/ArchUnit-style or detekt import check). Target: `EarningsViewModel` package. Preconditions: built module. Steps: assert no imports of Compose, `android.content.Context`, Retrofit/OkHttp/Room, or cookie/CSRF APIs in the ViewModel; assert it exposes only domain types + `labelKey`s. Expected: check passes. Traces: AC-9.

- **TC-AND-256-15 — Flaky-dev-host live smoke (manual / instrumented).** Type: manual (and optional instrumented/e2e). Target: full stack against `http://18.222.237.167:8000`. Preconditions: signed-in session; cleartext permitted for dev host (AND-027 network-security-config). Steps: open Earnings, switch ranges, toggle airplane mode mid-load, observe a transient 5xx/timeout. Expected: range switch refetches; offline/timeout yields stale-or-error state (never a hang); a 401 triggers one `POST /ui/session/refresh` + retry. Device: **must run on the physical Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, API 34/arm64)** for real-network airplane-mode toggling and true cleartext-to-remote-host behavior; the headless `test35` emulator may be used for a non-network functional pass but cannot validate real radio offline transitions or arm64/API-34 transport quirks. Traces: AC-3, AC-6, AC-7.

### Coverage matrix

| AC | Covered by |
|----|-----------|
| AC-1 (unit-tested, ≥85% coverage) | TC-01 (plus the whole suite TC-01..14) |
| AC-2 (enum cases/keys/lookback, default) | TC-02 |
| AC-3 (uiState exposed; Loading→Content/Error on first subscription) | TC-01, TC-04, TC-05, TC-11, TC-15 |
| AC-4 (onRangeSelected sync update + persist + refetch; same-range no-op) | TC-03, TC-04, TC-12 |
| AC-5 (success→Content; failure→ErrorState w/ category) | TC-05, TC-07, TC-11 |
| AC-6 (refresh retains content + isRefreshing; failed refresh keeps content+error) | TC-08, TC-09, TC-15 |
| AC-7 (empty→isEmpty; cached/offline→isStale, not error) | TC-06, TC-09, TC-15 |
| AC-8 (last-write-wins on rapid switch) | TC-10, TC-13 |
| AC-9 (no Compose/Context/CSRF/formatting; domain+label keys only) | TC-13, TC-14 |
| AC-10 (saved range restored after reconstruction) | TC-12 |
