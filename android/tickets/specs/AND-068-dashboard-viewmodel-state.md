---
id: AND-068
title: Dashboard ViewModel + state
milestone: M2
epic: E09
priority: P0
size: M
status: draft
depends_on: [AND-065]
blocks: [AND-069]
---

# AND-068 — Dashboard ViewModel + state

## 1. Overview & Goal

This ticket implements the presentation layer for the Dashboard screen of the
TestLogon native Android app: a `DashboardViewModel` that exposes a single
`StateFlow<DashboardUiState>` and a small set of one-shot side effects. The
ViewModel orchestrates the `DashboardRepository` delivered by AND-065, maps the
repository's `ApiResult<Dashboard>` into discrete, render-ready UI states
(loading, content, empty, error, offline-stale), and handles user-driven
refresh events (pull-to-refresh and retry).

The goal is a deterministic, fully unit-tested state machine. The Compose layer
(AND-066 for the happy path, AND-069 for empty/error/offline composables and the
headless UI test) consumes this `StateFlow` and renders accordingly. No
Composables, navigation, or networking code are introduced here beyond what is
needed to drive and observe state. The dev backend
(`http://18.222.237.167:8000`) is plaintext HTTP and unreliable, so the state
model must first-class represent slow loads (~20s timeout), transient failures,
and serving stale cached content while offline.

Success is measured by: (a) every modeled state transition is reachable and
covered by a unit test using a fake repository and a `TestDispatcher`, and (b)
the public surface is stable enough for AND-066/AND-069 to bind against without
churn.

## 2. Context & References

- **Module:** `feature-dashboard` (depends on `core-data`, `core-model`,
  `core-ui`, `core-testing`). Package root `com.testlogon.android.feature.dashboard`.
- **Upstream (AND-065):** provides `DashboardRepository`, the `Dashboard` domain
  model in `com.testlogon.android.core.model`, `DashboardApi`, and DTO→domain
  mapping. This ticket consumes the repository interface only.
- **Downstream (AND-066):** Dashboard content Composable + screen scaffolding
  binds to `DashboardUiState`.
- **Downstream (AND-069):** empty/error/offline Composables and the headless
  Compose UI test; this ticket must expose the states those Composables render.
- **Web reference:** `frontend/src/api/endpoints/dashboard.ts` and
  `frontend/src/api/types.ts` define the payload shape mirrored by AND-065's
  domain model. Web has no offline/stale concept; that is Android-specific.
- **Shared conventions:** ViewModels expose `StateFlow<UiState>`; the typed
  `ApiResult<T>` lives in `core-network`; FastAPI `detail` mapping
  (`string | [{msg}] | {code,...}`) is normalized into a user-facing message by
  the `core-network` error mapper, surfaced here as `DashboardError`.
- **Auth:** session is cookie-based and managed by `core-network` (cookie jar,
  `X-CSRF-Token`, single `/ui/session/refresh` on 401). This ViewModel does not
  perform auth itself; it reacts to an `Unauthorized` `ApiResult` by emitting a
  re-auth side effect.

## 3. Functional Requirements

FR-1. On first composition, the ViewModel loads the dashboard automatically
(via `init`/`load()`), emitting `Loading` then a terminal state.

FR-2. The ViewModel exposes exactly one observable state:
`val uiState: StateFlow<DashboardUiState>`.

FR-3. State variants the consumer can render:
- `Loading` — initial or refresh-from-empty load in progress.
- `Content(dashboard, isStale, isRefreshing)` — data available; `isStale=true`
  means it came from cache while offline/refresh failed; `isRefreshing=true`
  means a background refresh is running over existing content.
- `Empty(isRefreshing)` — load succeeded but the payload has no renderable
  sections/items.
- `Error(error, canRetry)` — load failed and there is no cached content to show.
- `Offline(cached, error)` — no network and cached content exists; a specialized
  `Content` with `isStale=true`. (Implemented as `Content` with `isStale`; see
  Technical Design — `Offline` is modeled as a flag, not a separate sealed
  subtype, to keep the consumer's branching minimal. The frontmatter and
  acceptance refer to it conceptually as the "offline" state.)

FR-4. Refresh events:
- `onRefresh()` — user pull-to-refresh. If content exists, sets
  `isRefreshing=true` while keeping content visible; on success replaces
  content; on failure keeps content and sets `isStale=true` (plus a transient
  message side effect).
- `onRetry()` — from an `Error`/`Empty` state; behaves like a fresh `load()`
  showing `Loading`.

FR-5. Refresh de-duplication: concurrent refresh requests collapse to one
in-flight load; new requests while loading are ignored (job cancellation +
`isRefreshing` guard).

FR-6. On `ApiResult.Unauthorized` after the network layer's single refresh
attempt has failed, emit a `DashboardEffect.RequireReauth` one-shot effect and
move to `Error(SessionExpired, canRetry=false)`.

FR-7. State survives configuration changes (ViewModel scope) and does not reload
on rotation if content is already present.

FR-8. Slow loads: a load in `Loading` longer than 20s is allowed to complete or
fail per the network timeout; the ViewModel does not impose a shorter deadline
but must surface the resulting `Error`/`Offline` cleanly.

## 4. Technical Design

Package: `com.testlogon.android.feature.dashboard`.

### 4.1 UI state model

```kotlin
data class DashboardUiState(
    val phase: Phase = Phase.Loading,
    val dashboard: Dashboard? = null,   // core-model domain type (AND-065)
    val isRefreshing: Boolean = false,  // background refresh over content
    val isStale: Boolean = false,       // content served from cache (offline)
    val error: DashboardError? = null,  // present only when phase == Error
) {
    enum class Phase { Loading, Content, Empty, Error }

    val isOffline: Boolean get() = isStale && dashboard != null
    val canRetry: Boolean get() = phase == Phase.Error || phase == Phase.Empty
}
```

A single immutable data class (rather than a sealed hierarchy) is used so the
content fields persist across refresh transitions (e.g. show stale content while
`isRefreshing`). `Phase` enumerates the mutually exclusive top-level renders.

```kotlin
sealed interface DashboardError {
    val retryable: Boolean
    data class Network(val message: String) : DashboardError { override val retryable = true }
    data class Server(val code: Int, val message: String) : DashboardError { override val retryable = true }
    data object SessionExpired : DashboardError { override val retryable = false }
    data class Unknown(val message: String) : DashboardError { override val retryable = true }
}
```

### 4.2 Side effects (one-shot)

```kotlin
sealed interface DashboardEffect {
    data object RequireReauth : DashboardEffect
    data class ShowMessage(val text: String) : DashboardEffect // e.g. "Refresh failed — showing saved data"
}
```

Exposed as `val effects: Flow<DashboardEffect>` backed by a
`Channel(Channel.BUFFERED)` consumed by the screen via
`LaunchedEffect`/`collect`. Effects are not part of `StateFlow` to avoid
replay-on-rotation.

### 4.3 ViewModel

```kotlin
@HiltViewModel
class DashboardViewModel @Inject constructor(
    private val repository: DashboardRepository,         // AND-065
    @Dispatcher(IO) private val ioDispatcher: CoroutineDispatcher,
) : ViewModel() {

    private val _uiState = MutableStateFlow(DashboardUiState())
    val uiState: StateFlow<DashboardUiState> = _uiState.asStateFlow()

    private val _effects = Channel<DashboardEffect>(Channel.BUFFERED)
    val effects: Flow<DashboardEffect> = _effects.receiveAsFlow()

    private var loadJob: Job? = null

    init { load(fromUser = false) }

    fun onRefresh() = load(fromUser = true)
    fun onRetry() = load(fromUser = true)

    private fun load(fromUser: Boolean) {
        if (loadJob?.isActive == true) return            // FR-5 de-dup
        loadJob = viewModelScope.launch(ioDispatcher) {
            _uiState.update { it.startLoad() }
            when (val result = repository.getDashboard(forceRefresh = fromUser)) {
                is ApiResult.Success    -> _uiState.update { it.toContentOrEmpty(result.data, stale = false) }
                is ApiResult.Cached     -> _uiState.update { it.toContentOrEmpty(result.data, stale = true) }
                is ApiResult.Unauthorized -> { _effects.send(RequireReauth); _uiState.update { it.toError(SessionExpired) } }
                is ApiResult.Error      -> reduceFailure(result)
            }
        }
    }
}
```

`startLoad()`, `toContentOrEmpty()`, `toError()` are pure private extension
functions on `DashboardUiState` (the reducer), making transitions trivially unit
testable in isolation. `reduceFailure` decides between `Error` (no cached
content) and stale `Content` + `ShowMessage` (cached content present) per FR-4.

The reducer's emptiness check delegates to a domain predicate
`Dashboard.isEmpty()` (defined in core-model by AND-065, or a local extension if
not yet present): true when there are no sections or all sections have zero
items.

### 4.4 Repository contract assumed from AND-065

```kotlin
interface DashboardRepository {
    suspend fun getDashboard(forceRefresh: Boolean): ApiResult<Dashboard>
}
```

`ApiResult` (core-network) is assumed to carry a `Cached` variant for
offline/stale reads; if AND-065 ships only `Success/Error/Unauthorized`, this
ticket adds a `Cached` member to `ApiResult` in `core-network` and the repo
returns it when serving from Room while the network call failed. This is the one
upstream dependency to confirm (see Risks).

### 4.5 Hilt wiring

The ViewModel is `@HiltViewModel`; no new module is required beyond the
`@Dispatcher(IO)` qualifier already provided by `core-data`. The repository is
bound by AND-065's module.

## 5. API Contract

This ticket introduces **no new network calls**. All HTTP is owned by AND-065
(`DashboardApi.getDashboard()` → `GET /ui/dashboard`, mapped from
`frontend/src/api/endpoints/dashboard.ts`). For reference, the upstream payload
the domain model derives from is shaped roughly as:

```json
{
  "sections": [
    { "id": "continue", "title": "Continue watching",
      "items": [ { "id": "...", "title": "...", "thumbnail_url": "...", "deep_link": "/watch/..." } ] }
  ],
  "generated_at": "2026-06-05T12:00:00Z"
}
```

The ViewModel consumes the already-mapped `Dashboard` domain object, not this
JSON. Error normalization (FastAPI `detail`: `string | [{msg}] | {code,...}`)
is performed by the `core-network` error mapper before reaching the repository;
this ticket only maps the resulting `ApiResult.Error(throwable, httpCode?,
message)` into `DashboardError` (Network for IO/timeout, Server for 5xx, Unknown
otherwise; 401 surfaces as `Unauthorized`, not `Error`).

## 6. Data & State Management

- **Single source of truth:** `_uiState: MutableStateFlow<DashboardUiState>`,
  exposed read-only. Started eagerly (default `MutableStateFlow`); no
  `stateIn`/sharing needed since it is hot and owned by the ViewModel.
- **No DataStore/Room access here.** Caching is the repository's concern;
  `ApiResult.Cached` is the only signal of staleness this layer reads.
- **Transition table:**

  | From            | Event                | To                                   |
  |-----------------|----------------------|--------------------------------------|
  | Loading         | Success(non-empty)   | Content(stale=false)                 |
  | Loading         | Success(empty)       | Empty                                |
  | Loading         | Cached(non-empty)    | Content(stale=true) + ShowMessage    |
  | Loading         | Error                | Error                                |
  | Loading         | Unauthorized         | Error(SessionExpired) + RequireReauth|
  | Content         | onRefresh            | Content(isRefreshing=true)           |
  | Content+refresh | Success              | Content(stale=false, refreshing=false)|
  | Content+refresh | Error                | Content(stale=true) + ShowMessage    |
  | Empty/Error     | onRetry              | Loading                              |

- **Refresh semantics:** `isRefreshing` toggles only when content already
  exists; otherwise the screen shows the full-screen `Loading` phase.
- **Effects** are not persisted state; they are consumed once.

## 7. Error Handling & Resilience

- Network/timeout (the ~20s OkHttp timeout against the unreliable dev host)
  → `DashboardError.Network`. If cached content exists, prefer stale `Content`
  over `Error`.
- 5xx → `DashboardError.Server(code, message)`, retryable.
- 401 after the network layer's single `POST /ui/session/refresh` retry has
  failed → `Unauthorized` → `SessionExpired` + `RequireReauth`.
- Bounded backoff for the idempotent `GET` is the repository's/OkHttp
  interceptor's responsibility (AND-065 / core-network); the ViewModel performs
  no retry loop of its own beyond user-initiated `onRetry`.
- Coroutine cancellation: `loadJob` is cancelled and superseded only via the
  in-flight guard; `CancellationException` is never converted to an error state.
- All repository calls are wrapped by `ApiResult`; no raw `try/catch` for
  expected failures. Unexpected throwables from the reducer are caught and mapped
  to `DashboardError.Unknown`.

## 8. Security & Privacy

- No credentials, tokens, or cookies are handled here; the cookie jar and CSRF
  header live in `core-network`. The ViewModel must never log dashboard item
  contents, deep links, or user identifiers.
- `RequireReauth` carries no sensitive payload; it only signals navigation to the
  auth flow.
- No PII is placed in `DashboardError` messages beyond the server-supplied,
  already-sanitized `detail` text.
- Plaintext HTTP is a known dev-environment constraint owned by network config
  (cleartext permitted only for the dev host); not in scope here.

## 9. Accessibility & i18n

- This ticket produces no Composables, so it owns no `contentDescription` or
  focus behavior; that is AND-066/AND-069.
- All user-facing strings emitted via `DashboardEffect.ShowMessage` and the
  human-readable parts of `DashboardError` must be resolved from
  `core-ui`/`feature-dashboard` `strings.xml` resources by the consumer, NOT
  hard-coded in the ViewModel. The ViewModel therefore exposes message *types*
  (`DashboardError` subtypes, semantic effects) and lets the screen map them to
  localized strings, or accepts a `@StringRes`-style resolver. Concretely,
  `ShowMessage` should carry a `@StringRes` id rather than literal text:

  ```kotlin
  data class ShowMessage(@StringRes val resId: Int) : DashboardEffect
  ```

  This keeps the ViewModel locale-agnostic and testable.

## 10. Telemetry & Logging

- Log state transitions at `Timber.d` with a stable tag `"DashboardVM"`:
  load start, terminal phase, stale flag, and error class name only (never
  payload contents).
- Emit one analytics event per terminal load via the `core-data` analytics
  abstraction (if available): `dashboard_loaded{source=network|cache, empty,
  duration_ms}` and `dashboard_load_failed{error_type}`. If the analytics
  facade is not yet present, gate behind an injected no-op `Analytics` interface
  so this ticket does not block on it.
- No verbose logging in release builds (Timber release tree is no-op per app
  config).

## 11. Testing Strategy

Unit tests are the core deliverable (acceptance criterion). Use JUnit4,
`kotlinx-coroutines-test` (`StandardTestDispatcher` + `runTest`), Turbine for
`StateFlow`/`Flow` assertions, and a hand-written `FakeDashboardRepository`
(`core-testing`) that returns scripted `ApiResult` values.

Test cases (in `DashboardViewModelTest`):
1. `init emits Loading then Content` for a non-empty `Success`.
2. `Success with empty payload → Empty`.
3. `Cached result → Content with isStale=true and ShowMessage effect`.
4. `Error with no prior content → Error(canRetry=true)`.
5. `onRefresh over Content sets isRefreshing then clears on success`.
6. `onRefresh failure keeps Content, sets isStale, emits ShowMessage`.
7. `Unauthorized → Error(SessionExpired) + RequireReauth effect`.
8. `onRetry from Error re-enters Loading then resolves`.
9. `concurrent onRefresh calls collapse to one repository invocation` (assert
   call count == 1 via the fake).
10. `state is unchanged on rotation` — re-collecting `uiState` yields the same
    terminal value (no extra repo call).

Reducer functions (`startLoad`, `toContentOrEmpty`, `toError`) get direct,
dispatcher-free unit tests to pin the transition table in Section 6.

Turbine pattern:

```kotlin
viewModel.uiState.test {
    assertEquals(Phase.Loading, awaitItem().phase)
    advanceUntilIdle()
    assertEquals(Phase.Content, awaitItem().phase)
    cancelAndIgnoreRemainingEvents()
}
```

The Compose state-rendering UI test is explicitly out of scope and owned by
AND-069.

## 12. Dependencies & Sequencing

- **Depends on AND-065** (`DashboardRepository`, `Dashboard` domain model,
  `ApiResult` with a `Cached` variant). Must merge first.
- **Blocks AND-069** (state composables + headless UI test) and is consumed by
  **AND-066** (content screen). Both bind to `DashboardUiState`/`DashboardEffect`.
- Transitive: `core-network` (`ApiResult`, error mapper), `core-testing`
  (fakes, test dispatcher rule), `core-data` (`@Dispatcher(IO)`,
  optional analytics).
- No Gradle/build changes beyond existing `feature-dashboard` test deps
  (Turbine, coroutines-test) which should already be present from `core-testing`
  conventions; add them to `feature-dashboard/build.gradle.kts` if missing.

## 13. Risks & Open Questions

- **R1 (must confirm):** Does AND-065's `ApiResult` include a `Cached` variant?
  If not, the offline/stale state (FR-3, FR-4) cannot be distinguished from a
  fresh `Success`. Resolution: add `ApiResult.Cached<T>` to `core-network` and
  have the repository emit it on cache-fallback. Coordinate with AND-065 owner.
- **R2:** `Dashboard.isEmpty()` location — owned by core-model (preferred) or a
  local extension. Default to a local extension to avoid blocking; migrate later.
- **R3:** Whether `RequireReauth` should also clear cached content. Default: no
  (preserve last-known content behind the re-auth prompt); revisit with auth flow
  owner.
- **R4:** Analytics facade availability (Section 10) — gated behind a no-op to
  avoid a hard dependency.
- **OQ:** Should pull-to-refresh while already `isStale` show a distinct
  indicator vs. a normal refresh? Deferred to AND-066/AND-069 UI design.

## 14. Acceptance Criteria

- AC-1 (from backlog): All modeled state transitions are unit-tested; the test
  suite in `DashboardViewModelTest` passes deterministically with
  `StandardTestDispatcher`.
- AC-2: `DashboardViewModel.uiState` is a `StateFlow<DashboardUiState>` exposing
  Loading, Content, Empty, and Error phases plus the `isStale`/`isRefreshing`
  flags representing offline and refresh-in-progress.
- AC-3: `onRefresh()` and `onRetry()` exist; concurrent refreshes collapse to a
  single repository call (verified by call-count assertion).
- AC-4: A `Cached`/offline result produces stale content (not an error) and a
  `ShowMessage` effect; an `Unauthorized` result produces `SessionExpired` plus a
  `RequireReauth` effect.
- AC-5: No Composables, no direct HTTP, and no Room/DataStore access are added in
  this ticket; the ViewModel depends only on `DashboardRepository`.
- AC-6: User-facing message strings are referenced by `@StringRes` id, not
  literals, keeping the ViewModel locale-agnostic.

## 15. Definition of Done

- `DashboardUiState`, `DashboardError`, `DashboardEffect`, and
  `DashboardViewModel` implemented in
  `com.testlogon.android.feature.dashboard` exactly as specified.
- All ten unit tests plus reducer tests written and green in CI; line coverage
  of the ViewModel + reducers ≥ 85%.
- Public API (`uiState`, `effects`, `onRefresh`, `onRetry`) reviewed and agreed
  with AND-066/AND-069 owners so downstream binding requires no changes.
- `./gradlew :feature-dashboard:testDebugUnitTest ktlintCheck detekt` passes;
  no new lint/detekt suppressions added.
- No hard-coded user-facing strings; no payload/PII logging.
- Code reviewed and merged to `android-port`; AND-069 unblocked.
