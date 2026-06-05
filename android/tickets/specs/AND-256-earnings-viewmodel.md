---
id: AND-256
title: Earnings ViewModel
milestone: M6
epic: E34
priority: P1
size: M
status: draft
depends_on: [AND-251]
blocks: []
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
- **Web reference:** `frontend/src/api/endpoints/earnings.ts` (range param + summary/series calls), shared types in `frontend/src/api/types.ts`. The Android range enum and state shape should be semantically consistent with the web app's range selector.
- **Auth/session:** cookie-based session with `X-CSRF-Token` echo and a single `POST /ui/session/refresh` on 401, all handled inside the OkHttp/auth stack (AND-027) beneath the repository. The ViewModel never touches cookies or CSRF.
- **Patterns:** ViewModels expose `StateFlow<UiState>`; typed `ApiResult<T>`; FastAPI `detail` mapping (`string | [{msg}] | {code,...}`) performed in `core-network`/repository, surfaced here as a domain `UiError`.

## 3. Functional Requirements

FR-1 **Range model.** Define `EarningsRange` enum with cases `SEVEN_DAYS`, `THIRTY_DAYS`, `NINETY_DAYS`, `YEAR_TO_DATE`, `ALL`, each carrying the wire token expected by AND-251's API (`"7d"`, `"30d"`, `"90d"`, `"ytd"`, `"all"`) and a stable, translatable label key. Default range is `THIRTY_DAYS`.

FR-2 **Initial load.** On first collection of `uiState`, the ViewModel loads summary + series for the current (restored or default) range exactly once. It must not re-trigger a load purely because a new collector subscribes.

FR-3 **Range selection.** `onRangeSelected(range: EarningsRange)` updates the selected range immediately (so the chip/segmented control reflects the choice synchronously), persists it to `SavedStateHandle`, and triggers a fresh load for that range. Selecting the already-selected range is a no-op for fetching unless the current state is an error/empty (then it acts as retry).

FR-4 **Combined fetch.** Summary and series are fetched concurrently for the selected range. The UI state reaches `Content` only when both succeed; if either fails, state is `Error` (with the failing call identified). Partial success (one ok, one failed) is treated as `Error` for v1 to avoid showing inconsistent data; the open question in §13 tracks a future partial-content design.

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

enum class EarningsRange(val wire: String, val labelKey: String) {
    SEVEN_DAYS("7d", "earnings_range_7d"),
    THIRTY_DAYS("30d", "earnings_range_30d"),
    NINETY_DAYS("90d", "earnings_range_90d"),
    YEAR_TO_DATE("ytd", "earnings_range_ytd"),
    ALL("all", "earnings_range_all");

    companion object {
        val DEFAULT = THIRTY_DAYS
        fun fromWire(value: String?): EarningsRange =
            entries.firstOrNull { it.wire == value } ?: DEFAULT
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
        savedStateHandle.getStateFlow(KEY_RANGE, EarningsRange.DEFAULT.wire)
            .map(EarningsRange::fromWire)
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

    init { load(EarningsRange.fromWire(savedStateHandle[KEY_RANGE]), reason = LoadReason.INITIAL) }

    fun onRangeSelected(range: EarningsRange) {
        if (range == selectedRange.value && _internal.value.phase != InternalPhase.ERROR) {
            // already selected and healthy -> no-op
            if (_internal.value.phase == InternalPhase.CONTENT) return
        }
        savedStateHandle[KEY_RANGE] = range.wire
        load(range, reason = LoadReason.RANGE_CHANGE)
    }

    fun refresh() = load(selectedRange.value, reason = LoadReason.REFRESH)
    fun retry() = load(selectedRange.value, reason = LoadReason.RETRY)

    private fun load(range: EarningsRange, reason: LoadReason) {
        val gen = ++requestGen
        loadJob?.cancel()
        loadJob = viewModelScope.launch {
            _internal.update { it.beginLoad(reason) }
            val summaryDef = async(ioDispatcher) { repository.getSummary(range.wire) }
            val seriesDef  = async(ioDispatcher) { repository.getSeries(range.wire) }
            val summaryRes = summaryDef.await()
            val seriesRes  = seriesDef.await()
            if (gen != requestGen) return@launch // superseded; drop result
            _internal.update { it.applyResults(summaryRes, seriesRes) }
        }
    }

    companion object { const val KEY_RANGE = "earnings_range" }
}
```

`InternalState`/`InternalPhase`/`LoadReason` are private mapping helpers; `beginLoad` decides whether to clear content (range change/initial) or retain it (refresh), `applyResults` folds the two `ApiResult<T>` values into success/error/empty/stale. `requestGen` + the `gen != requestGen` guard implement FR-10 (last-write-wins, stale results discarded). `loadJob?.cancel()` cancels the in-flight network work.

### 4.3 Concurrency & dispatchers

Repository suspend functions run on the injected `ioDispatcher` (Hilt-qualified `@Dispatcher(IO)`); the fold/state update runs on the main-immediate scope of `viewModelScope`. Tests inject `StandardTestDispatcher`/`UnconfinedTestDispatcher` via the constructor so no static dispatcher rule is needed. `SharingStarted.WhileSubscribed(5_000)` keeps the shared state alive across short config-change gaps without re-running `init` logic; the actual initial fetch is kicked in `init`, guarded so it runs once.

## 5. API Contract

This ViewModel issues **no HTTP directly**. All network access is via `EarningsRepository`, owned by **AND-251**, which defines the Retrofit `EarningsApi`, DTOs, mappers, and error mapping. The contract relevant here is the repository surface this ticket consumes:

```kotlin
interface EarningsRepository {                 // defined by AND-251
    suspend fun getSummary(range: String): ApiResult<EarningsSummary>
    suspend fun getSeries(range: String): ApiResult<List<EarningsPoint>>
}
```

For traceability, the underlying endpoints (authoritative definition + exact paths in AND-251 / `frontend/src/api/endpoints/earnings.ts` / `/openapi.json`) are the earnings summary and series GETs, parameterized by the `range` wire token (`7d|30d|90d|ytd|all`). Expected success shapes the ViewModel relies on (mapped to domain by AND-251):

```jsonc
// summary (domain after mapping): totals + deltas
{ "total": 1234.56, "currency": "USD", "delta_pct": 4.2, "as_of": 1717545600000 }
// series (domain after mapping): ordered points
[ { "t": 1715990400000, "value": 42.10 }, { "t": 1716076800000, "value": 0.0 } ]
```

`range` is sent as a query parameter on idempotent GETs, making them eligible for the bounded backoff retry policy in `core-network`. The ViewModel treats the JSON purely through the mapped domain types; any change to wire shape is absorbed by AND-251's mappers. If AND-251's repository signature differs (e.g. a single combined call), this ViewModel adapts its `load()` to one `await` — the public ViewModel API in §4.2 is unaffected.

## 6. Data & State Management

- **Single source of truth:** `uiState: StateFlow<EarningsUiState>`, derived by `combine(selectedRange, _internal)`. Range lives in `SavedStateHandle` (key `earnings_range`, stored as the wire string) so it survives config change and light process death; the rest of the state is recomputed on restore by re-fetching (with stale cache fill from Room via AND-251 if available).
- **Request generation:** monotonic `requestGen: Long`. Each `load()` increments it and captures `gen`; results from a superseded generation are dropped (FR-10). Combined with `loadJob.cancel()`, this guarantees last-write-wins.
- **State transition rules:**
  - INITIAL / RANGE_CHANGE: `phase=Loading`, `summary=null`, `series=[]`, `isRefreshing=false`.
  - REFRESH / RETRY with prior content: keep `summary`/`series`, set `isRefreshing=true`, `phase` stays `Content`.
  - Both `ApiResult.Success` → `phase=Content`, populate data, `isEmpty = summary.isZeroActivity && series.isEmpty()`, `isStale = anyResult.fromCache`, `lastUpdated = summary.asOf ?: now`.
  - Any `ApiResult.Error` (and no usable cache) → `phase=ErrorState`, `error=mapped`, content cleared on range change but retained on a failed refresh (so the user keeps seeing prior data with an inline error message + `isStale`).
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
@Test fun bothCallsSucceed_emptySeriesAndZeroSummary_setsIsEmptyTrue()
@Test fun summaryFails_seriesSucceeds_emitsErrorState()
@Test fun refresh_withContent_setsIsRefreshing_andKeepsContent()
@Test fun failedRefresh_withPriorContent_retainsContent_andSetsError()
@Test fun repositoryReturnsCache_setsIsStaleTrue_notError()
@Test fun rapidRangeSwitch_dropsStaleResult_lastWriteWins()   // gen guard
@Test fun slowCall_doesNotHangState_transitionsOutOfLoading()
@Test fun savedRange_isRestoredOnConstruction()
@Test fun errorMapping_timeoutCategory_isSurfaced()
@Test fun cancellation_doesNotProduceUiError()
```

The `rapidRangeSwitch` test uses a `FakeEarningsRepository` whose `getSeries` for the first range delays past the second selection, then asserts the final `uiState.range` and content correspond to the **second** range only (FR-10). Coverage target: all public functions and every `Phase`/flag transition branch exercised; CI gate ≥ 85% line coverage for `EarningsViewModel` and its private mapping helpers.

## 12. Dependencies & Sequencing

- **Hard dependency — AND-251 (Earnings API + DTOs, P0):** must provide `EarningsRepository` + domain types (`EarningsSummary`, `EarningsPoint`) and error mapping before this ticket can compile against real types. If AND-251 is in flight, develop against the `FakeEarningsRepository` and the agreed interface signature, then swap.
- **Transitive — AND-027:** OkHttp/auth/cookie/CSRF/retry stack underpinning the repository (already a dep of AND-251). Not directly referenced here.
- **Hilt wiring:** requires `@Dispatcher(IO)` qualifier + dispatcher module and the `EarningsRepository` Hilt binding (provided by AND-251's data module). This ticket adds only the `@HiltViewModel` annotation and constructor injection.
- **Blocks:** the Earnings **screen** ticket (Compose UI consuming `uiState` + calling `onRangeSelected/refresh/retry`) — that downstream ticket owns §9 content-descriptions, currency/date formatting, and the range selector composable. (Exact screen AND-id to be confirmed in the M6/E34 backlog; this ticket should be listed as its `depends_on`.)

## 13. Risks & Open Questions

- **R1 — Repository shape mismatch:** AND-251 may expose one combined `getEarnings(range)` instead of two calls. Mitigation: `load()` is the only affected code; public API unchanged. Confirm with AND-251 owner before merge.
- **R2 — Partial success policy:** v1 treats one-of-two failures as full `Error`. Open question: should summary render while series shows an inline chart error? Deferred; revisit with the screen ticket.
- **R3 — Range semantics (YTD/ALL):** assumed server-computed from the `range` token. If the API instead expects explicit `from`/`to` epoch params, the enum gains date computation and i18n/timezone concerns. Confirm against `/openapi.json` / `earnings.ts`.
- **R4 — Stale flag availability:** `isStale`/`fromCache` depends on AND-251's `ApiResult`/repository exposing a cache provenance flag. If absent, `isStale` is always false until AND-251 adds it; tracked as a follow-up.
- **R5 — Unreliable dev host** can make manual QA flaky; rely on fakes for deterministic tests and accept that live smoke testing may intermittently show stale/error states (expected by design).

## 14. Acceptance Criteria

AC-1 `EarningsViewModel` is unit-tested (the source ticket's sole acceptance bullet) with the suite in §11 passing and ≥ 85% line coverage on the ViewModel.
AC-2 `EarningsRange` enum exists with five cases and correct wire tokens (`7d/30d/90d/ytd/all`); default is `THIRTY_DAYS`.
AC-3 `uiState: StateFlow<EarningsUiState>` is exposed; on first subscription it loads default (or restored) range and emits `Loading` → `Content` (or `ErrorState`).
AC-4 `onRangeSelected(range)` updates `uiState.range` synchronously, persists the wire token to `SavedStateHandle`, and re-fetches; selecting the same healthy range is a no-op.
AC-5 Concurrent summary+series fetch: both success → `Content`; either failure (no cache) → `ErrorState` with a categorized `UiError`.
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
