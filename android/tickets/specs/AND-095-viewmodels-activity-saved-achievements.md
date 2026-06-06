---
id: AND-095
title: ViewModels (activity/saved/achievements)
milestone: M2
epic: E13
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
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
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext, unreliable). OpenAPI at `/openapi.json`. **Auth (corrected):** the web client (`src/api/client.ts`) sends `Authorization: Bearer <accessToken>` from its auth store plus an `X-CSRF-Token` header read from the `ui_csrf` cookie; the backend additionally accepts an `X-SESSION-ID` header (and optional `X-IMPERSONATION-TOKEN`) on these `/ui/*` endpoints. On a `401` the web client refreshes once via `POST /ui/session/refresh` and retries. This is NOT a pure "cookie-based session" as the prior draft stated; the Android equivalent (AND-027 network layer) must reproduce the Bearer + CSRF + session-id transport. This is transparent to AND-095 (the VM layer never sees credentials) but the citation is corrected here. Web reference under `src/api/endpoints/{activityFeed,bookmarks,achievements}.ts` and `src/api/types.ts` is the source of truth for field names; align Moshi `@Json` names to it during repo work (AND-091/092/093) — this ticket consumes the resulting domain models.

## 3. Functional Requirements

**FR-1 (Activity feed — paged).** `ActivityViewModel` exposes a `Flow<PagingData<ActivityItem>>` cached in `viewModelScope` and a separate `StateFlow<ActivityScreenState>` carrying the screen-level chrome (refreshing flag, terminal error banner derived from `LoadState`). It supports pull-to-refresh by re-triggering the pager.

**FR-2 (Saved — list + unsave).** `SavedViewModel` exposes `StateFlow<SavedUiState>` over the saved list and an `onUnsave(contentType, contentId)` intent (the backend keys bookmarks by the (`content_type`,`content_id`) pair, not a single `id`) that performs an **optimistic** removal: the item disappears immediately, the repository unsave call is issued, and on failure the item is restored and a one-shot error event is emitted. Re-saving is out of scope (AND-092 backlog: "unsave"). Note: `GET /ui/bookmarks` is cursor-paged server-side; whether the VM treats it as a flat list or a Paging stream is an AND-092 decision (see R4, now resolved to "paged on the wire").

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

    // NOTE: a saved item has no single `id`; it is keyed by (contentType, contentId).
    // SavedItem is expected (AND-092) to expose both; the VM passes them through to unsave().
    fun onUnsave(contentType: String, contentId: String) {
        val current = (_state.value as? UiState.Content)?.data ?: return
        val removed = current.firstOrNull {
            it.contentType == contentType && it.contentId == contentId
        } ?: return
        _state.value = UiState.Content(current - removed)        // optimistic
        viewModelScope.launch {
            when (val r = repo.unsave(contentType, contentId)) {
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
    // Composite key: the backend deletes by (content_type, content_id), not a single id.
    suspend fun unsave(contentType: String, contentId: String): ApiResult<Unit>
}

interface AchievementsRepository {
    suspend fun achievements(): ApiResult<AchievementsData>
}
```

For reference, the repositories (AND-091/092/093) front these endpoints. The paths and shapes below are **corrected against the backend OpenAPI index and `src/api/types.ts`** — the prior draft's `/api/*` paths and field names were invented and are wrong. Real contracts:

- **Activity:** `GET /ui/activity/feed?cursor=<c>&limit=<n>` → `ActivityFeedResponse` (schema `ActivityFeedResponse`, TS alias `ActivityFeedPageResponse`):
  `{ "items": [ActivityOut], "next_cursor": string|null, "total_unread": int }`.
  `ActivityOut`/`ActivityItem` fields: `activity_id` (string), `actor_id` (string), `activity_type` (string), `target_type` (string), `target_id` (string), `metadata` (object), `created_at` (**Unix epoch number, NOT ISO-8601**), `read` (bool). There is no nested `actor{}`/`target{}` object and no top-level `id`/`type` — those were fabricated. (A filtered variant `GET /ui/activity/feed/filter?activity_type=..` also exists; AND-091 chooses which the pager uses.)
- **Saved (bookmarks):** `GET /ui/bookmarks?limit=<n>&cursor=<c>&content_type=..&collection_id=..` → `BookmarkListResponse`:
  `{ "bookmarks": [BookmarkItem], "next_cursor": string?, "total_count": int }`. Note the array key is **`bookmarks`**, not `items`. `BookmarkItem` fields: `content_type` ("post"|"video"), `content_id` (string), `collection_id` (string), `created_at` (ISO-8601 string), `content_preview` ({author_id, author_display_name?, body_snippet?, image_url?, like_count?}). **There is no single `id` field** — a saved item is identified by the (`content_type`, `content_id`) pair. The endpoint is **cursor-paged** (resolves R4: the saved set IS paged server-side).
- **Unsave:** `DELETE /ui/bookmarks/{content_type}/{content_id}` → `200` with body `{ "ok": true }` (NOT `204`/empty, and NOT `/api/saved/{id}`). Because the key is composite, `SavedRepository.unsave` must take `content_type` + `content_id`, not a single `id` (see corrected interface below).
- **Achievements:** there is **no single endpoint returning `{earned, locked}`** — that shape was fabricated. The real surface is:
  - `GET /ui/achievements` → `{ "achievements": [UserAchievement], "total_points": int, "achievement_count": int }` (the user's earned achievements; `displayed`/`category` query filters).
  - `GET /ui/achievements/earned` → same `{achievements, total_points, achievement_count}` shape.
  - `GET /ui/achievements/progress` → `{ "progress": [AchievementProgress] }`.
  `UserAchievement` fields: `achievement_id`, `label` (**not `title`**), `description`, `icon_url`, `rarity`, `points`, `unlocked_at` (epoch, **not `earned_at`**), `trigger_event`, `displayed`. `AchievementProgress` fields: `metric_key`, `current_value`, `last_updated_at`, `last_updated_date`, `highest_value`, `streak_anchor_date?`, `next_threshold?` (number|null), `next_achievement?` ({achievement_id,label,rarity,points}|null). **There is no `progress` float or `progress_label` string on the wire** (resolves R3): the client must DERIVE `progress = current_value / next_threshold` (clamped to `[0f,1f]`) and `progressLabel = "current_value/next_threshold"`, and must derive the "locked" partition by joining `/ui/achievements/definitions` (or progress metrics) against earned `achievement_id`s. This derivation belongs in the AND-093 repository; the VM consumes the resulting `AchievementsData`. (Definitions: `GET /ui/achievements/definitions?active_only=..` → `{definitions: [AchievementDefinition]}` with `achievement_id`, `label`, `description`, `icon_url`, `rarity`, `threshold`, `points`, `metric_key`, ...)

The unsave `DELETE` is a mutation, so it gets **no** automatic backoff retry (per project policy: bounded backoff for idempotent GETs only); the optimistic-rollback path handles its failure.

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
- The `DELETE /ui/bookmarks/{content_type}/{content_id}` mutation requires the `X-CSRF-Token` header (web client reads it from the `ui_csrf` cookie; see `src/api/client.ts`); that is enforced transparently by the OkHttp interceptor (AND-027), so the ViewModel cannot accidentally omit it. The same interceptor attaches `Authorization: Bearer` and `X-SESSION-ID`.
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
- **R3 — Achievements progress shape:** ~~does the backend always send `progress_label`?~~ **RESOLVED (this review):** the backend does **not** send `progress` or `progress_label`. `GET /ui/achievements`/`/earned` return `{achievements, total_points, achievement_count}` (no locked partition); `GET /ui/achievements/progress` returns `AchievementProgress` with `current_value` + `next_threshold`. The client must DERIVE `progress = current_value/next_threshold` (clamped) and the label, and must synthesize the `earned`/`locked` partition by joining definitions/progress against earned ids. Formatting/derivation lives in the AND-093 repo; the VM is unchanged and still consumes `AchievementsData`.
- **R4 — Saved paging vs full list:** **RESOLVED (this review):** `GET /ui/bookmarks` is cursor-paged on the wire (`next_cursor` + `total_count`). AND-092 should decide whether `SavedViewModel` mirrors the Activity Paging design or flattens the first page into a list; the optimistic-unsave logic in §4.3 is written for the list form and would need a Paging-aware variant if AND-092 goes paged.
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the authoritative source. AND-095 is a presentation-layer ticket, so most claims are about the upstream API/web contract that the consumed repositories front; those are verified directly against the backend OpenAPI and the web reference app.

1. **Activity feed endpoint is `GET /ui/activity/feed` (cursor/limit paged).** VERDICT: Corrected (draft said `GET /api/activity`). SOURCE: OpenAPI `GET /ui/activity/feed` (op `get_activity_feed_ui_activity_feed_get`, resp `200:ActivityFeedResponse`, params `cursor,limit,...`); `src/api/endpoints/activityFeed.ts: getActivityFeed`.
2. **Activity response shape: `{items, next_cursor, total_unread}`.** VERDICT: Corrected (draft omitted `total_unread`). SOURCE: OpenAPI schema `ActivityFeedResponse`; `src/api/types.ts: ActivityFeedPageResponse`.
3. **Activity item fields: `activity_id, actor_id, activity_type, target_type, target_id, metadata, created_at (epoch number), read`.** VERDICT: Corrected (draft invented `id`, `type`, nested `actor{}`/`target{}`, and ISO `created_at`). SOURCE: OpenAPI schema `ActivityOut`; `src/api/types.ts: ActivityItem`.
4. **Saved list endpoint is `GET /ui/bookmarks`, cursor-paged.** VERDICT: Corrected (draft said `GET /api/saved?limit=50`, non-paged). SOURCE: OpenAPI `GET /ui/bookmarks` (op `list_bookmarks_ui_bookmarks_get`, params `limit,cursor,content_type,collection_id,...`); `src/api/endpoints/bookmarks.ts: getBookmarks`.
5. **Saved response shape: `{bookmarks, next_cursor?, total_count}` (array key is `bookmarks`, not `items`).** VERDICT: Corrected. SOURCE: `src/api/endpoints/bookmarks.ts: BookmarkListResponse`.
6. **A saved item is keyed by (`content_type`, `content_id`); there is no single `id`.** VERDICT: Corrected (draft used `id` and `saved_at`/`post`). SOURCE: `src/api/endpoints/bookmarks.ts: BookmarkItem` (fields `content_type, content_id, collection_id, created_at, content_preview`).
7. **Unsave endpoint is `DELETE /ui/bookmarks/{content_type}/{content_id}` returning `200 {ok:true}`.** VERDICT: Corrected (draft said `DELETE /api/saved/{id}` → `204`). SOURCE: OpenAPI `DELETE /ui/bookmarks/{content_type}/{content_id}` (op `delete_bookmark_ui_bookmarks__content_type___content_id__delete`, resp `200`); `src/api/endpoints/bookmarks.ts: removeBookmark`.
8. **`SavedRepository.unsave` must accept (contentType, contentId), and `onUnsave` likewise.** VERDICT: Corrected (consequence of #6/#7; draft used `unsave(id)`/`onUnsave(id)`). SOURCE: derived from `src/api/endpoints/bookmarks.ts: removeBookmark(contentType, contentId)`.
9. **Achievements: no single endpoint returns `{earned, locked}`.** VERDICT: Corrected (draft fabricated a combined `{earned, locked}` response). SOURCE: OpenAPI `GET /ui/achievements`, `GET /ui/achievements/earned`, `GET /ui/achievements/progress`, `GET /ui/achievements/definitions`; `src/api/endpoints/achievements.ts`.
10. **`GET /ui/achievements` → `{achievements: UserAchievement[], total_points, achievement_count}`.** VERDICT: Corrected. SOURCE: `src/api/endpoints/achievements.ts: getMyAchievements`; OpenAPI `GET /ui/achievements`.
11. **`UserAchievement` uses `label` (not `title`) and `unlocked_at` epoch (not `earned_at`).** VERDICT: Corrected. SOURCE: `src/api/types.ts: UserAchievement`.
12. **Wire has no `progress: float` / `progress_label`; client must derive from `AchievementProgress.current_value` and `next_threshold`/definition `threshold`.** VERDICT: Corrected (resolves R3). SOURCE: `src/api/types.ts: AchievementProgress` and `AchievementDefinition`; OpenAPI `GET /ui/achievements/progress`.
13. **Auth transport is `Authorization: Bearer <token>` + `X-CSRF-Token` (from `ui_csrf` cookie) + `X-SESSION-ID`; on 401 refresh once via `POST /ui/session/refresh`.** VERDICT: Corrected (draft said "cookie-based session"; CSRF header name was right, transport description was not). SOURCE: `src/api/client.ts` (Authorization header set from `useAuthStore`, `X-CSRF-Token` from `getCookie("ui_csrf")`, `refreshSession()` → `/ui/session/refresh`); OpenAPI header param `X-SESSION-ID` on `/ui/*` ops.
14. **FastAPI error `detail` is a union: `string` | `[{msg,...}]` | `{code,...}` (incl. authorization codes), mapped by `ApiErrorMapper`.** VERDICT: Verified. SOURCE: `src/api/client.ts: normalizeErrorDetail` / `mapAuthorizationError`; OpenAPI `HTTPValidationError` (array of `{loc,msg,type}`) as the `422` response across these ops.
15. **422 is the validation error response for these endpoints.** VERDICT: Verified. SOURCE: OpenAPI index `resp=...;422:HTTPValidationError` on `GET /ui/activity/feed`, `GET /ui/bookmarks`, `DELETE /ui/bookmarks/...`, `GET /ui/achievements`.
16. **DELETE (mutation) gets no automatic backoff; bounded backoff is GET-only.** VERDICT: Unverified-assumption (project retry policy not in the provided sources; consistent with idempotency reasoning). SOURCE: none authoritative — internal policy claim.
17. **Hilt/KSP, Paging 3, StateFlow, `cachedIn(viewModelScope)`, `SharingStarted.WhileSubscribed(5_000)`, `kotlinx-coroutines-test`, Turbine.** VERDICT: Verified (framework refs). SOURCE: framework ref — Android Jetpack `androidx.lifecycle.viewModelScope` / `StateFlow.stateIn` (developer.android.com/topic/architecture/ui-layer/state-production), Paging 3 `cachedIn` (developer.android.com/topic/libraries/architecture/paging/v3-paged-data), `paging-testing` `asSnapshot` (developer.android.com/reference/kotlin/androidx/paging/testing/package-summary), Turbine (github.com/cashapp/turbine).
18. **VM never sees credentials / no `core-network` dependency; CSRF enforced by interceptor.** VERDICT: Verified (architectural, consistent with web client where transport concerns live entirely in `client.ts`). SOURCE: `src/api/client.ts` (all auth/CSRF centralized in transport); AND-027 (Android equivalent, referenced not provided).

### Corrections made

- Frontmatter: `status: draft` → `reviewed`; added `reviewed_on: 2026-06-06`.
- §2: replaced "Cookie-based session" with the verified Bearer + `X-CSRF-Token` (`ui_csrf` cookie) + `X-SESSION-ID` transport and the 401→`/ui/session/refresh` retry.
- §3 FR-2: `onUnsave(id)` → `onUnsave(contentType, contentId)`; noted bookmarks are cursor-paged.
- §4.3: `onUnsave` now matches/removes by (`contentType`,`contentId`) and calls `repo.unsave(contentType, contentId)`.
- §5: rewrote the endpoint reference block — corrected all four paths (`/ui/activity/feed`, `/ui/bookmarks`, `/ui/bookmarks/{content_type}/{content_id}`, `/ui/achievements*`), response shapes (`items`+`total_unread`; `bookmarks`+`total_count`; `{achievements,...}`), field names (`activity_id`/`actor_id`/`created_at` epoch; `content_type`/`content_id`; `label`/`unlocked_at`), the `200 {ok:true}` unsave response, and the achievements derivation note; corrected `SavedRepository.unsave` to a composite-key signature.
- §7: error `detail` union claim verified (no change beyond confirmation).
- §8: `DELETE /api/saved/{id}` → `DELETE /ui/bookmarks/{content_type}/{content_id}`; clarified Bearer/X-SESSION-ID also attached.
- §13: R3 and R4 marked RESOLVED with the verified findings.

### Open assumptions

- **Retry policy (claim #16):** "bounded backoff for idempotent GETs only" is an internal engineering policy not present in OpenAPI or the web client; left as an explicit assumption to confirm with the AND-027/core-network owner.
- **`earned`/`locked` partitioning algorithm:** the backend exposes earned achievements, progress, and definitions separately but no precomputed "locked" set. The exact join (definitions minus earned, ordered by `sort_order`, progress via `current_value/threshold`) is an AND-093 repository decision; assumed here, not dictated by any single endpoint.
- **`SavedItem`/`ActivityItem`/`Achievement` domain model field names:** these are Android domain models owned by AND-091/092/093 (mapped from the DTOs above). Their exact Kotlin property names (`contentType`, `contentId`, etc.) are assumed to mirror the corrected DTO fields; the VM code in §4 depends on that mapping.
- **Saved as flat list vs Paging stream (R4):** wire is paged; whether `SavedViewModel` uses Paging 3 or a flattened first page is unresolved pending AND-092. The §4.3 optimistic-unsave design assumes a flat `List<SavedItem>`.

## 17. Test Plan

Test IDs `TC-AND-095-NN`. All ViewModel logic is pure JVM (no Android framework on the test path per AC-7), so the default target is **JVM unit/Robolectric (local, no device)** using `runTest` + `MainDispatcherRule` (`StandardTestDispatcher`) + Turbine + fake repositories. Cases that assert the *repository↔HTTP* contract (real paths/fields/error shapes corrected in §5/§16) are written as **contract/MockWebServer** tests at the repo seam so the VM's assumptions about `ApiResult`/domain shapes are anchored to the real wire format; these can run JVM-local (MockWebServer needs no device). Instrumented/Compose-UI/physical-device cases are noted where they add value, but for this ticket they are thin — the heavy hardware targets (camera, biometrics, FCM, WebRTC) are not exercised by these three read/list ViewModels.

- **TC-AND-095-01** — Type: unit (JVM). Target: JVM unit, no device. Preconditions: `FakeSavedRepository.saved()` emits `ApiResult.Success(non-empty list)`. Steps: construct `SavedViewModel`; collect `state` via Turbine; advance virtual time. Expected: `Loading` → `Content(list, isRefreshing=false)`; `saved_loaded{item_count=N}` emitted. Traces: AC-1, AC-5.
- **TC-AND-095-02** — Type: unit (JVM). Target: JVM unit. Preconditions: `saved()` emits `Success(emptyList)`. Steps: construct VM; collect `state`. Expected: `Loading` → `Empty`. Traces: AC-5.
- **TC-AND-095-03** — Type: unit (JVM). Target: JVM unit. Preconditions: `saved()` emits `Failure` then, after `retry()`, `Success(list)`. Steps: collect `state`; assert error; call `retry()`; advance time. Expected: `Loading` → `Error(retryable=true)` → (on retry) `Loading`-suppressed → `Content`. Traces: AC-5.
- **TC-AND-095-04** — Type: unit (JVM). Target: JVM unit. Preconditions: VM already in `Content(list)`; `refresh()` triggers a `Failure`. Steps: call `refresh()`; collect `state` + `events`. Expected: content preserved, `isRefreshing` toggles true→false, one `UiEvent.ShowError` emitted, list never blanked. Traces: AC-5.
- **TC-AND-095-05** — Type: unit (JVM). Target: JVM unit. Preconditions: VM in `Content(list of ≥2)`; `FakeSavedRepository.unsave` has a controllable suspension point (not yet resumed). Steps: call `onUnsave(contentType, contentId)`; assert `state` BEFORE the suspended call resolves. Expected: removed item is absent from `Content` immediately (optimistic), network call still in flight. Traces: AC-2.
- **TC-AND-095-06** — Type: unit (JVM). Target: JVM unit. Preconditions: as 05, but `unsave` resolves to `ApiResult.Failure`. Steps: call `onUnsave`; resume failure; collect `state` + `events`. Expected: prior list restored exactly (item back at original index/order), one `UiEvent.ShowError`; `saved_unsave{result=failure}`. Traces: AC-2.
- **TC-AND-095-07** — Type: unit (JVM). Target: JVM unit. Preconditions: VM in `Content(single item)`; `unsave` resolves `Success`. Steps: `onUnsave` the last item. Expected: `Content` → `Empty`; `saved_unsave{result=success}`. Traces: AC-2, AC-5.
- **TC-AND-095-08** — Type: contract/MockWebServer. Target: JVM unit (MockWebServer, no device). Preconditions: MockWebServer enqueues a real-shape `DELETE /ui/bookmarks/{content_type}/{content_id}` → `200 {"ok":true}`; SavedRepository under test. Steps: call `repo.unsave("post","abc")`; capture the recorded request. Expected: request method `DELETE`, path `/ui/bookmarks/post/abc`, returns `ApiResult.Success(Unit)`; carries `X-CSRF-Token` (if interceptor wired). Verifies the §5/§16 path correction. Traces: AC-2.
- **TC-AND-095-09** — Type: contract/MockWebServer. Target: JVM unit (MockWebServer). Preconditions: enqueue real `GET /ui/bookmarks` body `{"bookmarks":[{content_type,content_id,...}],"next_cursor":null,"total_count":1}` and a real `GET /ui/activity/feed` body `{"items":[{activity_id,actor_id,activity_type,created_at:<epoch>,...}],"next_cursor":null,"total_unread":0}`. Steps: invoke repo mappers. Expected: DTOs parse with corrected field names (`bookmarks`/`content_id`; `activity_id`/`created_at` as epoch), surfacing as domain models the VM consumes. Guards against regression to the fabricated shapes. Traces: AC-1.
- **TC-AND-095-10** — Type: contract/MockWebServer. Target: JVM unit (MockWebServer). Preconditions: enqueue `422` with body `{"detail":[{"loc":["query","limit"],"msg":"value is not a valid integer","type":"int_parsing"}]}` and separately `{"detail":"some message"}` and `{"detail":{"code":"role_required"}}`. Steps: call a GET repo method; map via `ApiErrorMapper`/`normalizeErrorDetail` equivalent. Expected: each `detail` union variant maps to a non-empty `UiText`; VM surfaces `UiState.Error`. Validates the real error shape (§16 #14/#15). Traces: AC-5.
- **TC-AND-095-11** — Type: unit (JVM). Target: JVM unit. Preconditions: `FakeAchievementsRepository.achievements()` returns `Success(AchievementsData(earned, locked))` where locked items carry derived `progress` and `progressLabel`. Steps: construct `AchievementsViewModel`; collect `state`. Expected: `Loading` → `Content` partitioned into `earned`/`locked`; every locked `progress ∈ [0f,1f]`; `progressLabel` passed through unchanged; `achievements_loaded{earned_count,locked_count}`. Traces: AC-3, AC-5.
- **TC-AND-095-12** — Type: unit (JVM). Target: JVM unit. Preconditions: `achievements()` returns `Failure` then `Success` after `retry()`. Steps: collect `state`; assert `Error`; `retry()`. Expected: `Error(retryable=true)` → `Content`. Traces: AC-5.
- **TC-AND-095-13** — Type: unit (JVM, paging). Target: JVM unit (`paging-testing` `asSnapshot`). Preconditions: `FakeActivityRepository.activityFeedPager()` returns a `Pager` over a fake `PagingSource` with two pages. Steps: collect `items` via `asSnapshot`; then call `refresh()` and re-snapshot. Expected: items emitted in order across pages; `refresh()` re-triggers `flatMapLatest` and re-collects (new snapshot); flow is `cachedIn(viewModelScope)` (survives a second collector without re-loading the source within scope). Traces: AC-1, AC-4.
- **TC-AND-095-14** — Type: unit (JVM, paging). Target: JVM unit. Preconditions: fake `PagingSource` returns `LoadResult.Error` on initial load, then a separate scenario where it succeeds on refresh but errors on append. Steps: feed `CombinedLoadStates` into `onLoadState`; inspect `ActivityScreenState`. Expected: refresh `LoadState.Error` with zero items → `terminalError` set; append `LoadState.Error` → `terminalError` stays null (footer/`retry()` handles append). Traces: AC-5.
- **TC-AND-095-15** — Type: unit (JVM). Target: JVM unit. Preconditions: VM exposes state via `stateIn(... WhileSubscribed(5_000) ...)`; repo counts invocations. Steps: subscribe, cancel, resubscribe within the 5s virtual-time window. Expected: repo `saved()`/`achievements()` is NOT re-invoked on resubscribe inside the window; re-invoked after it elapses. Traces: AC-4, AC-7.
- **TC-AND-095-16** — Type: unit (JVM). Target: JVM unit. Preconditions: VM constructed with an injected `StandardTestDispatcher`; reflection/inspection over the class. Steps: assert no use of `System.currentTimeMillis`, `Dispatchers.IO` literal, `Random`, or `Context`/`View` types in the VM module's compiled classes (lint/detekt rule or a simple JVM reflection check); run the full suite 20× headless. Expected: no Android/`core-network` types on the test classpath; 20 consecutive green runs (no flakiness). Traces: AC-6, AC-7.
- **TC-AND-095-17** — Type: Compose-UI / accessibility (instrumented). Target: headless emulator AVD `test35` (API 35) — covers the thin UI seam that consumes VM state; physical device not required (no camera/biometrics/FCM/WebRTC here). Preconditions: a minimal test host Composable binds `AchievementsViewModel.state` and a `LazyColumn` for Saved. Steps: drive VM to `Content`; assert each locked achievement node exposes `progressBarRangeInfo` matching `progress`; assert empty/error states expose a content description; verify a saved-row "unsave" action has an accessibility action label. Expected: semantics present, `progress` mapped to `progressBarRangeInfo(current, 0f..1f)`, error/empty have non-empty descriptions. Traces: AC-3, AC-5. (May run on emulator `test35`; no physical-device dependency.)

Note on physical device: none of these cases *require* the Samsung Galaxy A15 (SM-A156U). They are deterministic JVM/Robolectric or emulator-only. If AND-091/092/093 later add real-network or push-driven refresh of these screens, an integration/e2e variant of TC-13/TC-15 should run on the physical device to exercise the flaky dev host and arm64/API-34 path; that is out of scope for AND-095's "unit-tested" bar.

### Coverage matrix

| Acceptance criterion (§14) | Covered by |
| --- | --- |
| AC-1 (three VMs, immutable StateFlow / cached PagingData) | TC-01, TC-09, TC-13 |
| AC-2 (optimistic unsave + exact rollback + one-shot event) | TC-05, TC-06, TC-07, TC-08 |
| AC-3 (achievements earned/locked, progress∈[0,1], progressLabel) | TC-11, TC-17 |
| AC-4 (cachedIn PagingData survives resubscription, re-triggers on refresh; WhileSubscribed) | TC-13, TC-15 |
| AC-5 (Loading/Content/Empty/Error transitions; refresh-over-content preserves content + snackbar) | TC-02, TC-03, TC-04, TC-07, TC-10, TC-11, TC-12, TC-14, TC-17 |
| AC-6 (all required unit cases pass, deterministic, no flakiness over 20 runs) | TC-16 (+ the full TC-01..15 suite) |
| AC-7 (no core-network/Retrofit/View/Context/real time/randomness) | TC-15, TC-16 |
