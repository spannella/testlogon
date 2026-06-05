---
id: AND-095
title: ViewModels (activity/saved/achievements)
milestone: M2
epic: E13
priority: P1
size: M
status: draft
depends_on: [AND-091, AND-092, AND-093]
blocks: []
---

# AND-095 — ViewModels (activity/saved/achievements)

## 1. Overview & Goal

This ticket delivers the presentation-layer state holders for three M2 profile screens: the **Activity feed** (AND-091), **Saved / bookmarks** (AND-092), and **Achievements** (AND-093). Screens AND-091/092/093 deliver Compose UI and the underlying API/repository wiring; AND-095 owns the ViewModels that sit between them — exposing immutable `StateFlow<UiState>`, driving Paging 3 streams, mediating user intents (refresh, unsave, retry), and translating `ApiResult<T>` into testable, deterministic UI states.

The goal is three Hilt-injected ViewModels in their respective `feature-*` modules, each unit-tested in isolation against fake repositories, with no Android framework dependencies in the test path. The acceptance bar from the backlog is explicit and minimal: **"Unit-tested."** Concretely this means every public state transition (loading → content, loading → empty, loading → error, optimistic unsave + rollback, pagination append/error) is covered by a JUnit test using `kotlinx-coroutines-test` and Turbine, with deterministic virtual-time scheduling and no real network or disk I/O.

Out of scope: the Composable screens themselves, navigation routes, the Retrofit service/DTO definitions, and the repository implementations — those belong to AND-091/092/093. AND-095 consumes those repository interfaces and is the integration seam that makes the screens testable without instrumentation.

## 2. Context & References

- **Repo / branch:** `spannella/testlogon`, Android app under `android/`, branch `android-port`.
- **Namespace:** `com.testlogon.android` everywhere a package appears.
- **Module layering:** `app -> feature-* -> core-*`. ViewModels live in `feature-activity`, `feature-saved`, `feature-achievements`. They depend on `core-data` (repository interfaces, `ApiResult<T>`), `core-model` (domain models), and `core-ui` (shared `UiState` contracts) only. They MUST NOT depend on `core-network` (Retrofit) directly.
- **Stack:** Kotlin 2.0.21, Hilt (KSP), Coroutines/Flow, Paging 3, StateFlow-based MVI-lite. Tests use `core-testing` (Turbine, `MainDispatcherRule`, fakes).
- **Upstream tickets:**
  - AND-091 — Activity feed: `activityFeed.ts` parity, paged screen. Provides `ActivityRepository`.
  - AND-092 — Saved / bookmarks: `bookmarks.ts`/saved API + unsave. Provides `SavedRepository`.
  - AND-093 — Achievements: `achievements.ts` (earned/locked + progress). Provides `AchievementsRepository`.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext, unreliable). Cookie-based session (see AND-027 auth). OpenAPI at `/openapi.json`. Web reference under `frontend/src/api/endpoints/{activityFeed,bookmarks,achievements}.ts` and `frontend/src/api/types.ts` is the source of truth for field names; align Moshi `@Json` names to it during repo work (AND-091/092/093) — this ticket consumes the resulting domain models.

## 3. Functional Requirements

**FR-1 (Activity feed — paged).** `ActivityViewModel` exposes a `Flow<PagingData<ActivityItem>>` cached in `viewModelScope` and a separate `StateFlow<ActivityScreenState>` carrying the screen-level chrome (refreshing flag, terminal error banner derived from `LoadState`). It supports pull-to-refresh by re-triggering the pager.

**FR-2 (Saved — list + unsave).** `SavedViewModel` exposes `StateFlow<SavedUiState>` over a non-paged-or-paged saved list and an `onUnsave(id)` intent that performs an **optimistic** removal: the item disappears immediately, the repository unsave call is issued, and on failure the item is restored and a one-shot error event is emitted. Re-saving is out of scope (AND-092 backlog: "unsave").

**FR-3 (Achievements — earned/locked + progress).** `AchievementsViewModel` exposes `StateFlow<AchievementsUiState>` containing two partitions — `earned` and `locked` — where each locked item carries `progress: Float` in `[0f, 1f]` and `progressLabel: String` (e.g. "3/10"). It is a single GET load with refresh; no pagination required.

**FR-4 (Common intents).** All three expose `refresh()` and `retry()`. Loading is shown only when there is no existing content (initial load); refresh over existing content sets a `isRefreshing` flag without clearing the list.

**FR-5 (Lifecycle safety).** All flows are exposed as `StateFlow`/cached `PagingData` so configuration changes (rotation) do not re-fetch. `stateIn` uses `SharingStarted.WhileSubscribed(5_000)`.

**FR-6 (Determinism for test).** No ViewModel may read time, randomness, or dispatchers except via injected abstractions, so unit tests are fully deterministic.

## 4. Technical Design

### 4.1 Shared UiState contract (`core-ui`)

```kotlin
sealed interface UiState<out T> {
    data object Loading : UiState<Nothing>
    data class Content<T>(val data: T, val isRefreshing: Boolean = false) : UiState<T>
    data object Empty : UiState<Nothing>
    data class Error(val message: UiText, val retryable: Boolean = true) : UiState<Nothing>
}
```

One-shot effects (transient error after optimistic failure) use a `Channel`-backed flow, not state:

```kotlin
sealed interface UiEvent { data class ShowError(val message: UiText) : UiEvent }
```

### 4.2 Activity (`feature-activity`)

```kotlin
@HiltViewModel
class ActivityViewModel @Inject constructor(
    private val repo: ActivityRepository,            // from AND-091, core-data
    @IoDispatcher private val io: CoroutineDispatcher,
) : ViewModel() {

    private val refreshTrigger = MutableStateFlow(0)

    val items: Flow<PagingData<ActivityItem>> =
        refreshTrigger.flatMapLatest { repo.activityFeedPager() }
            .cachedIn(viewModelScope)

    private val _screen = MutableStateFlow(ActivityScreenState())
    val screen: StateFlow<ActivityScreenState> = _screen.asStateFlow()

    fun onLoadState(states: CombinedLoadStates) { /* maps refresh/append LoadState -> banner/refreshing */ }
    fun refresh() { refreshTrigger.update { it + 1 } }
}

data class ActivityScreenState(
    val isRefreshing: Boolean = false,
    val terminalError: UiText? = null,
)
```

`repo.activityFeedPager(): Flow<PagingData<ActivityItem>>` is provided by AND-091 (a `Pager` over a `PagingSource` backed by the cursor/offset paged endpoint). The ViewModel does not own the `PagingConfig` (it lives in the repo) but `onLoadState` is the single place where `LoadState.Error` is mapped to a user-facing banner via `ApiErrorMapper`.

### 4.3 Saved (`feature-saved`)

```kotlin
@HiltViewModel
class SavedViewModel @Inject constructor(
    private val repo: SavedRepository,               // from AND-092
    @IoDispatcher private val io: CoroutineDispatcher,
) : ViewModel() {

    private val _state = MutableStateFlow<SavedUiState>(UiState.Loading)
    val state: StateFlow<SavedUiState> = _state.asStateFlow()

    private val _events = Channel<UiEvent>(Channel.BUFFERED)
    val events = _events.receiveAsFlow()

    init { load() }

    fun refresh() = load(isRefresh = true)
    fun retry() = load()

    fun onUnsave(id: String) {
        val current = (_state.value as? UiState.Content)?.data ?: return
        val removed = current.firstOrNull { it.id == id } ?: return
        _state.value = UiState.Content(current - removed)        // optimistic
        viewModelScope.launch {
            when (val r = repo.unsave(id)) {
                is ApiResult.Success -> { /* keep removed; emit empty if list now empty */
                    if ((_state.value as UiState.Content).data.isEmpty()) _state.value = UiState.Empty
                }
                is ApiResult.Failure -> {                          // rollback
                    _state.value = UiState.Content(restore(current, removed))
                    _events.send(UiEvent.ShowError(r.error.toUiText()))
                }
            }
        }
    }

    private fun load(isRefresh: Boolean = false) { /* Loading unless content exists; collect repo.saved() */ }
}

typealias SavedUiState = UiState<List<SavedItem>>
```

### 4.4 Achievements (`feature-achievements`)

```kotlin
@HiltViewModel
class AchievementsViewModel @Inject constructor(
    private val repo: AchievementsRepository,         // from AND-093
) : ViewModel() {
    private val _state = MutableStateFlow<UiState<AchievementsData>>(UiState.Loading)
    val state: StateFlow<UiState<AchievementsData>> = _state.asStateFlow()
    init { load() }
    fun refresh() = load(isRefresh = true)
    fun retry() = load()
    private fun load(isRefresh: Boolean = false) { /* repo.achievements() -> partition earned/locked */ }
}

data class AchievementsData(val earned: List<Achievement>, val locked: List<LockedAchievement>)
data class LockedAchievement(val achievement: Achievement, val progress: Float, val progressLabel: String)
```

### 4.5 DI

`@IoDispatcher` qualifier is provided by `core-data`'s `DispatchersModule`. In tests it is overridden with the test scheduler's `StandardTestDispatcher`. No ViewModel constructs its own `CoroutineScope`; all background work uses `viewModelScope`.

## 5. API Contract

AND-095 does **not** define HTTP endpoints — those are owned by AND-091/092/093. The ViewModels consume repository interfaces from `core-data`, which are the contract for this ticket:

```kotlin
interface ActivityRepository { fun activityFeedPager(): Flow<PagingData<ActivityItem>> }

interface SavedRepository {
    fun saved(): Flow<ApiResult<List<SavedItem>>>
    suspend fun unsave(id: String): ApiResult<Unit>
}

interface AchievementsRepository {
    suspend fun achievements(): ApiResult<AchievementsData>
}
```

For reference, the repositories (AND-091/092/093) front these endpoints; field names mirror `frontend/src/api/types.ts`:

- `GET /api/activity?cursor=<c>&limit=20` → `{ "items": [{ "id": "...", "type": "like|comment|follow|post", "actor": {...}, "target": {...}, "created_at": "ISO-8601" }], "next_cursor": "..."|null }`
- `GET /api/saved?limit=50` → `{ "items": [{ "id": "...", "saved_at": "ISO-8601", "post": {...} }] }`
- `DELETE /api/saved/{id}` → `204` (empty body) on success.
- `GET /api/achievements` → `{ "earned": [{ "id": "...", "title": "...", "icon_url": "...", "earned_at": "ISO-8601" }], "locked": [{ "id": "...", "title": "...", "icon_url": "...", "progress": 0.3, "progress_label": "3/10" }] }`

The unsave `DELETE` is non-idempotent-GET, so it gets **no** automatic backoff retry (per project policy: bounded backoff for idempotent GETs only); the optimistic-rollback path handles its failure.

## 6. Data & State Management

- **Source of truth:** the ViewModel's `MutableStateFlow` (Saved, Achievements) and the cached `PagingData` flow (Activity). UI is a pure function of these.
- **Caching:** `cachedIn(viewModelScope)` for Activity; Saved/Achievements rely on the repo's Room/DataStore cache (AND-098 / AND-092 wiring). The ViewModel does not cache directly.
- **Refresh semantics:** `isRefreshing` flag preserves existing content; only an initial empty load shows `UiState.Loading`.
- **Empty vs Content:** an empty successful list maps to `UiState.Empty`. After the last item is unsaved, Saved transitions Content → Empty.
- **Sharing:** any `repo` flow folded into state via `stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), UiState.Loading)`.
- **Optimistic state:** Saved holds the removed item locally for the duration of the network call to enable rollback; this is transient and never persisted.

## 7. Error Handling & Resilience

- **`ApiResult.Failure` mapping:** all failures flow through `ApiErrorMapper.toUiText(error)` (core-data), which already handles the FastAPI `detail` union (`string` | `[{msg}]` | `{code,...}`). The ViewModel decides placement, not formatting.
- **Initial load error:** `UiState.Error(message, retryable = true)`; `retry()` re-issues the load.
- **Refresh-over-content error:** keep content, emit `UiEvent.ShowError` (snackbar), clear `isRefreshing`. Never blank a populated screen on refresh failure (dev host is unreliable; ~20s timeouts expected).
- **Paging errors (Activity):** mapped from `CombinedLoadStates`. `refresh` error with no items → screen `terminalError`; `append` error → handled by the screen's footer retry (`retry()` calls the pager's `retry`, surfaced by AND-091).
- **Optimistic unsave failure:** rollback + `ShowError`; state is exactly restored (item reinserted at original index via `restore()`).
- **Timeouts/offline:** surfaced as `ApiResult.Failure(NetworkError)` by the repo; mapped to a "You're offline / try again" `UiText`. No retry storm — single user-driven retry only.

## 8. Security & Privacy

- ViewModels handle no credentials, tokens, or cookies — the cookie jar and `X-CSRF-Token` handling live in `core-network` (AND-027). The ViewModel layer never sees session material.
- No PII is logged. Telemetry events (Section 10) carry only counts, durations, and outcome enums — never item content, actor names, or ids beyond an opaque achievement key.
- The `DELETE /api/saved/{id}` mutation requires the CSRF header; that is enforced transparently by the OkHttp interceptor, so the ViewModel cannot accidentally omit it.
- Process-death: state is not restored across process death in this ticket (lists re-fetch from cache); no sensitive data is written to `SavedStateHandle`.

## 9. Accessibility & i18n

- All user-facing strings are `UiText` (string-resource refs or formatted resources), never hard-coded literals in the ViewModel — keeps the layer translatable and testable.
- `progressLabel` ("3/10") is produced by the repo/formatter using locale-aware number formatting (AND-093); the ViewModel passes it through unchanged. `progress: Float` drives the accessible `progressBarRangeInfo` on the screen.
- Empty/error messages resolve to localized strings on the screen side; the ViewModel only chooses which `UiText` key applies. No layout, contrast, or font concerns at this layer (owned by the screens).

## 10. Telemetry & Logging

- Inject `Analytics` (core-data). Emit on outcome transitions only:
  - `activity_feed_loaded { item_count, from_cache, duration_ms }`
  - `saved_loaded { item_count }`, `saved_unsave { result: success|failure }`
  - `achievements_loaded { earned_count, locked_count }`
  - `screen_load_error { screen, error_kind }`
- Use a no-op `Analytics` fake in unit tests; assert event emission as part of state-transition tests where it is load-bearing.
- Logging via `Timber` at `debug` for state transitions in debug builds only; no logging in release. Never log response bodies.

## 11. Testing Strategy

This is the core of the ticket. Tests live in each feature module's `test/` source set (pure JVM JUnit, no Robolectric needed).

- **Harness:** `MainDispatcherRule` (core-testing) installs a `StandardTestDispatcher`; `runTest {}` drives virtual time; **Turbine** asserts `StateFlow`/event emissions; `app.cash.turbine` `test {}` blocks with `awaitItem()`.
- **Paging tests (Activity):** use `PagingData` test utilities — build a `Pager` over a fake `PagingSource`, collect via `.asSnapshot { }` (paging-testing artifact) to assert items and `LoadState` mapping. Assert `onLoadState` produces the right `ActivityScreenState`.
- **Fakes:** `FakeSavedRepository` / `FakeAchievementsRepository` / `FakeActivityRepository` with programmable success/failure/empty responses and a controllable suspension point to test optimistic windows.

Required cases (each a JUnit `@Test`):

1. Saved: Loading → Content(non-empty) on success.
2. Saved: Loading → Empty on success-empty.
3. Saved: Loading → Error(retryable) on failure; `retry()` → Content.
4. Saved: refresh-over-content failure keeps Content, emits `ShowError`, `isRefreshing=false`.
5. Saved: `onUnsave` optimistically removes immediately (assert state before network resolves).
6. Saved: `onUnsave` failure restores exact prior list + emits `ShowError`.
7. Saved: unsave last item → Content → Empty.
8. Achievements: Content partitions earned/locked; locked `progress` in `[0,1]`, `progressLabel` passed through.
9. Achievements: error + `retry()` recovery.
10. Activity: pager emits items; `refresh()` re-triggers `flatMapLatest`.
11. Activity: `LoadState.Error` on initial → `terminalError` set; append error → no terminalError.
12. Common: `WhileSubscribed` does not re-fetch on resubscribe within 5s window.

Coverage target: 100% of ViewModel branches (the layer is small and pure).

## 12. Dependencies & Sequencing

- **Hard deps (must merge first):** AND-091 (`ActivityRepository` + pager), AND-092 (`SavedRepository` + `unsave`), AND-093 (`AchievementsRepository` + `AchievementsData`). These define the repository interfaces and domain models this ticket binds to.
- **Transitive:** AND-027 (cookie auth / network), AND-098 (cache layer) underpin the repos but are not directly referenced here.
- **Blocks:** the AND-091/092/093 screens cannot be fully wired/tested end-to-end until their ViewModel exists; in practice the screen PR and this VM PR may co-develop, but the VM contract here is authoritative.
- **Sequencing note:** if AND-091/092/093 land repos behind feature flags or stubs, AND-095 can proceed against the interfaces and fakes immediately; only the final DI binding (`@Binds` repo impl) waits on the real implementations.

## 13. Risks & Open Questions

- **R1 — Paging error surfacing split:** mapping `CombinedLoadStates` to both a top banner (refresh) and a footer (append) risks double-reporting. Mitigation: `onLoadState` owns refresh errors only; append/retry delegated to the screen's `LazyPagingItems`.
- **R2 — Optimistic rollback index:** restoring an unsaved item to its original position requires capturing the index, not just the item. `restore()` must reinsert at the captured index. **Open:** is list order server-defined (saved_at desc)? If so, reinsert by re-sorting rather than by index. Confirm with AND-092.
- **R3 — Achievements progress shape:** does the backend always send `progress_label`, or must the client derive it from `current/target`? **Open** — confirm against `/openapi.json` during AND-093; if derived, formatting moves to the repo, VM unchanged.
- **R4 — Saved paging vs full list:** backlog implies a simple list; if the saved set is large, AND-092 may make it paged, which would change `SavedViewModel` to mirror the Activity design. Assume non-paged until AND-092 says otherwise.
- **R5 — Unreliable dev host:** ~20s timeouts may make tests flaky if they touch real time; mitigated entirely by virtual-time `runTest` + fakes.

## 14. Acceptance Criteria

- **AC-1:** Three `@HiltViewModel` classes exist in `feature-activity`, `feature-saved`, `feature-achievements` under `com.testlogon.android.*`, each exposing immutable `StateFlow` (and cached `PagingData` for Activity).
- **AC-2:** Saved `onUnsave(id)` is optimistic: state reflects removal before the network call resolves (asserted in test), and rolls back exactly on failure with a one-shot error event.
- **AC-3:** Achievements state partitions `earned`/`locked` with `progress ∈ [0f,1f]` and a `progressLabel`.
- **AC-4:** Activity exposes a `cachedIn(viewModelScope)` `PagingData` flow that survives resubscription and re-triggers on `refresh()`.
- **AC-5:** Initial-load Loading/Content/Empty/Error transitions hold for all three; refresh-over-content failures preserve content and emit a snackbar event.
- **AC-6 (backlog: "Unit-tested"):** All 12 required test cases (Section 11) pass via `./gradlew :feature-activity:testDebugUnitTest :feature-saved:testDebugUnitTest :feature-achievements:testDebugUnitTest`, fully deterministic, no network/disk, no flakiness over 20 consecutive runs.
- **AC-7:** No ViewModel depends on `core-network`, Retrofit, Android `View`/`Context`, real dispatchers, time, or randomness.

## 15. Definition of Done

- Code merged to `android-port`; modules build with Gradle 8.9 / AGP 8.7.3 / JDK 17.
- All unit tests green in CI; branch-coverage of ViewModel classes ≥ 95% (target 100%).
- `detekt`/`ktlint` clean; no new lint warnings introduced.
- DI bindings (`@Binds` for the three repositories) resolve at compile time (Hilt component validation passes) once AND-091/092/093 impls are present; against fakes during development.
- Telemetry events emitted as specified and verified by at least one assertion.
- No hard-coded user-facing strings (all `UiText`).
- Open questions R2/R3/R4 either resolved in-PR or filed as follow-ups referencing the owning ticket (AND-092/AND-093).
- PR description links AND-091/092/093 and notes the consumed repository interfaces.
