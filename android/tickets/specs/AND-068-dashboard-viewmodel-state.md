---
id: AND-068
title: Dashboard ViewModel + state
milestone: M2
epic: E09
priority: P0
size: M
depends_on: [AND-065]
blocks: [AND-069]
status: reviewed
reviewed_on: 2026-06-06
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
- **Web reference:** `frontend/src/api/endpoints/dashboard.ts` (`getDashboardSummary`
  → `GET /ui/dashboard/summary`, `refreshDashboard` → `POST /ui/dashboard/refresh`)
  and `frontend/src/api/types.ts` (`DashboardSummary`) define the payload shape
  mirrored by AND-065's domain model. CORRECTION: the dedicated summary endpoint
  exists, but the web's main `frontend/src/pages/Dashboard.tsx` screen does NOT
  call it — it aggregates several independent endpoints (conversations, billing
  balance, files, alerts, carts, calendar) with React Query. AND-065's repository
  is assumed to back the single-call `/ui/dashboard/summary` contract; if AND-065
  instead aggregates, the same `ApiResult<Dashboard>` surface still applies and
  this ViewModel is unchanged. Web has no offline/stale concept; that is
  Android-specific.
- **Shared conventions:** ViewModels expose `StateFlow<UiState>`; the typed
  `ApiResult<T>` lives in `core-network`; FastAPI `detail` mapping
  (`string | [{msg}] | {code,...}`) is normalized into a user-facing message by
  the `core-network` error mapper, surfaced here as `DashboardError`.
- **Auth:** managed by `core-network`. Per the web client
  (`frontend/src/api/client.ts`) auth is a combination of an `Authorization:
  Bearer <accessToken>` header AND a cookie jar, with a CSRF token read from the
  `ui_csrf` cookie and sent as the `X-CSRF-Token` request header (CORRECTION: the
  earlier draft implied purely cookie-based session; it is Bearer + cookie +
  CSRF). On a 401 the web client performs exactly one de-duplicated `POST
  /ui/session/refresh` then retries the original request once; a second 401 logs
  out. The dashboard endpoints additionally accept `X-SESSION-ID` and
  `X-IMPERSONATION-TOKEN` parameters per the OpenAPI index. This ViewModel does
  not perform auth itself; it reacts to an `Unauthorized` `ApiResult` (i.e. a 401
  that survived the single refresh+retry) by emitting a re-auth side effect.

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
not yet present). CORRECTION: the real `DashboardSummary` has no `sections`;
emptiness must be defined against its actual fields — e.g. true when there is no
meaningful activity to render: `top_content`, `active_broadcasts`, and
`recent_milestones` are all empty AND `today_earnings_cents == 0 &&
period_views == 0 && period_revenue_cents == 0 && total_subscribers == 0`. The
exact predicate is AND-065's to own; this ViewModel only calls `isEmpty()`.

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

This ticket introduces **no new network calls**. All HTTP is owned by AND-065,
mapped from `frontend/src/api/endpoints/dashboard.ts`.

CORRECTION (verified against OpenAPI + frontend): there is **no** `GET
/ui/dashboard` endpoint. The real, verified endpoints are:
- `GET /ui/dashboard/summary` (op `dashboard_summary_ui_dashboard_summary_get`)
  → `200: DashboardSummary`; `422: HTTPValidationError`. Frontend:
  `getDashboardSummary()`.
- `POST /ui/dashboard/refresh` (op `dashboard_refresh_ui_dashboard_refresh_post`)
  → `200: { ok: boolean; message: string; refreshed_at: number }`;
  `422: HTTPValidationError`. Frontend: `refreshDashboard()`. AND-065 may wire
  `forceRefresh=true` to POST this before re-reading the summary.

CORRECTION: the earlier draft's `{sections:[{items:[{thumbnail_url, deep_link}]}],
generated_at: ISO-string}` payload is **wrong** — no such shape exists. The real
`DashboardSummary` (verified at `src/api/types.ts: DashboardSummary`) is a flat
creator-analytics object:

```json
{
  "today_earnings_cents": 0,
  "earnings_breakdown": { "subscriptions": 0, "tips": 0, "unlocks": 0, "vod_purchases": 0, "other": 0 },
  "period_views": 0,
  "period_revenue_cents": 0,
  "total_subscribers": 0,
  "top_content": [ { "content_id": "...", "content_type": "...", "title": "...", "views": 0, "revenue_cents": 0 } ],
  "active_broadcasts": [ { "session_id": "...", "status": "...", "name": "...", "started_at": "..." } ],
  "recent_milestones": [ { "milestone_id": "...", "user_id": "...", "metric": "...", "threshold": 0, "current_value": 0, "formatted": "...", "achieved_at": 0, "acknowledged": false } ],
  "currency": "USD",
  "generated_at": 0,
  "warnings": []
}
```

Note `generated_at` and milestone `achieved_at` are **unix-epoch numbers**, not
ISO strings, and there are no `sections`/`items`/`thumbnail_url`/`deep_link`
fields. The "empty" UI state (FR-3, Section 6) must therefore be re-defined in
terms of the real fields (see correction in Section 4.3 below).

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

## 16. Citations & Assumption Audit

Each key technical claim with its verdict and exact source pointer.

1. **Claim:** The dashboard is fetched via `GET /ui/dashboard`.
   **VERDICT: Corrected.** No such endpoint exists. The real read endpoint is
   `GET /ui/dashboard/summary`.
   **SOURCE:** OpenAPI `GET /ui/dashboard/summary` (op
   `dashboard_summary_ui_dashboard_summary_get`); `src/api/endpoints/dashboard.ts:
   getDashboardSummary`.

2. **Claim:** A refresh action maps to a backend call.
   **VERDICT: Verified (and clarified).** `POST /ui/dashboard/refresh` exists,
   returning `{ ok, message, refreshed_at }`.
   **SOURCE:** OpenAPI `POST /ui/dashboard/refresh` (op
   `dashboard_refresh_ui_dashboard_refresh_post`); `src/api/endpoints/dashboard.ts:
   refreshDashboard`.

3. **Claim:** The payload is `{sections:[{items:[{thumbnail_url, deep_link}]}],
   generated_at: ISO-string}`.
   **VERDICT: Corrected.** The real `DashboardSummary` is a flat creator-analytics
   object (`today_earnings_cents`, `earnings_breakdown`, `period_views`,
   `period_revenue_cents`, `total_subscribers`, `top_content[]`,
   `active_broadcasts[]`, `recent_milestones[]`, `currency`, `generated_at`,
   `warnings[]`); `generated_at` is a unix-epoch number, not an ISO string; no
   `sections`/`items`/`thumbnail_url`/`deep_link`.
   **SOURCE:** `src/api/types.ts: DashboardSummary` (and `DashboardEarningsBreakdown`,
   `DashboardTopContentItem`, `DashboardActiveBroadcast`, `DashboardMilestone`).

4. **Claim:** The web client uses this dashboard payload to render its dashboard
   screen.
   **VERDICT: Corrected.** The dedicated `/ui/dashboard/summary` endpoint exists,
   but `src/pages/Dashboard.tsx` does NOT call it — it aggregates conversations,
   billing balance, files, alerts, carts and calendar via separate React Query
   calls. The summary endpoint is the creator-analytics dashboard (CREATOR-003).
   **SOURCE:** `src/pages/Dashboard.tsx` (imports from `messaging`, `billing`,
   `files`, `alerts`, `cart`, `calendar` endpoints; no `dashboard.ts` import).

5. **Claim:** Auth is cookie-based with `X-CSRF-Token` and a single
   `/ui/session/refresh` on 401.
   **VERDICT: Verified (with one correction).** Correction: it is Bearer token +
   cookie + CSRF, not purely cookie-based. CSRF token is read from the `ui_csrf`
   cookie and sent as the `X-CSRF-Token` header; on 401 the client performs one
   de-duplicated `POST /ui/session/refresh` then retries once; second 401 logs out.
   **SOURCE:** `src/api/client.ts` (`getCookie("ui_csrf")` → `X-CSRF-Token`;
   `Authorization: Bearer ${accessToken}`; `refreshSession()` / `refreshPromise`
   single-flight on `res.status === 401`); OpenAPI `POST /ui/session/refresh` (op
   `ui_session_refresh_ui_session_refresh_post`, `req=` empty, `resp=200`).

6. **Claim:** FastAPI `detail` is normalized from `string | [{msg}] | {code,...}`.
   **VERDICT: Verified.** `normalizeErrorDetail` handles a plain string, an array
   of `{msg}` validation items, and an object with a `code`
   (`mapAuthorizationError`); `HTTPValidationError = { detail: ValidationError[] }`
   where `ValidationError` carries `msg`.
   **SOURCE:** `src/api/client.ts: normalizeErrorDetail` / `mapAuthorizationError`;
   OpenAPI `components.schemas.HTTPValidationError` and `ValidationError`.

7. **Claim:** A network/offline failure surfaces distinctly from an HTTP error.
   **VERDICT: Verified (web analog).** The web client throws `ApiError(0,
   "Network error")` on `fetch` rejection (offline/DNS), distinct from non-2xx
   `ApiError(status, detail)`. This justifies mapping IO/timeout →
   `DashboardError.Network` and 5xx → `DashboardError.Server`.
   **SOURCE:** `src/api/client.ts` (catch block → `new ApiError(0, "Network
   error", err)`; `if (!res.ok)` → `new ApiError(res.status, ...)`).

8. **Claim (Android-only):** Offline/stale serving (`ApiResult.Cached`,
   `isStale`, `Offline`).
   **VERDICT: Unverified-assumption.** Intentionally Android-specific; the web
   client has no offline/stale concept and there is no backend signal for it.
   **SOURCE:** none (by design); depends on AND-065 adding `ApiResult.Cached`
   (Risk R1).

9. **Claim:** `StateFlow<UiState>` + Channel-backed one-shot effects consumed via
   `LaunchedEffect`, surviving rotation, with Hilt `@HiltViewModel`.
   **VERDICT: Verified (framework refs).**
   **SOURCE (framework ref):**
   https://developer.android.com/topic/architecture/ui-layer/state-production
   (StateFlow UI state); https://developer.android.com/kotlin/flow#stateflow ;
   https://developer.android.com/training/dependency-injection/hilt-jetpack
   (`@HiltViewModel`); https://developer.android.com/topic/libraries/architecture/coroutines#viewmodelscope
   (`viewModelScope`).

10. **Claim:** `@StringRes`-keyed, locale-agnostic user messages.
    **VERDICT: Verified (framework ref).**
    **SOURCE (framework ref):**
    https://developer.android.com/guide/topics/resources/string-resource and
    https://developer.android.com/guide/topics/resources/localization .

11. **Claim:** ~20s timeout against the unreliable plaintext dev host
    `http://18.222.237.167:8000`.
    **VERDICT: Unverified-assumption.** The host/port and timeout value are not in
    the OpenAPI/frontend sources; the timeout is an OkHttp config choice owned by
    `core-network` (AND-065), not this ticket.
    **SOURCE:** none in references; framework ref
    https://square.github.io/okhttp/recipes/#timeouts-kt-java .

### Corrections made

- §2 Web reference: replaced the vague "payload shape" claim with the real
  endpoints (`GET /ui/dashboard/summary`, `POST /ui/dashboard/refresh`) and noted
  that the web `Dashboard.tsx` page aggregates separate endpoints rather than
  calling the summary endpoint.
- §2 Auth: corrected "cookie-based" to Bearer token + cookie + `X-CSRF-Token`
  (from `ui_csrf` cookie), with the single de-duplicated `POST /ui/session/refresh`
  + one retry on 401; added the `X-SESSION-ID`/`X-IMPERSONATION-TOKEN` params.
- §5 API Contract: corrected the endpoint from the nonexistent `GET /ui/dashboard`
  to `GET /ui/dashboard/summary`, added `POST /ui/dashboard/refresh`, and replaced
  the fabricated `sections/items/thumbnail_url/deep_link` JSON with the real
  `DashboardSummary` shape (noting `generated_at`/`achieved_at` are unix numbers).
- §4.3 Emptiness predicate: redefined `isEmpty()` against the real
  `DashboardSummary` fields (no `sections`).
- Frontmatter: `status: reviewed`, `reviewed_on: 2026-06-06`.

### Open assumptions

- **`ApiResult.Cached` / offline-stale (Risk R1):** unverifiable from backend or
  web sources — it is a deliberate Android addition. Depends on AND-065.
- **`Dashboard` domain model & `getDashboard(forceRefresh)` repository signature:**
  AND-065 deliverables not present in the references; assumed as specified.
- **Dev host `http://18.222.237.167:8000` and the ~20s timeout:** environment/config
  facts not present in OpenAPI or frontend; owned by `core-network`.
- **Mapping of `forceRefresh=true` to `POST /ui/dashboard/refresh` then re-read:**
  plausible but AND-065's choice; not asserted by the references.

## 17. Test Plan

All cases live in `feature-dashboard`. IDs are `TC-AND-068-NN`. Unit/contract
cases are the acceptance deliverable; UI/instrumented cases are listed for the
downstream binding contract and run on the targets noted. Because this ticket
ships no Composables and no networking, the bulk runs as JVM/Robolectric on the
local CI runner; only the integration smoke and accessibility checks touch a
device, and none of this ticket's logic requires the physical device.

- **TC-AND-068-01 — init: Loading → Content (happy path)**
  Type: unit (JVM, `StandardTestDispatcher` + Turbine).
  Test target: JVM unit/Robolectric.
  Preconditions: `FakeDashboardRepository.getDashboard` returns
  `ApiResult.Success(nonEmptyDashboard)`.
  Steps: construct `DashboardViewModel`; collect `uiState`; `advanceUntilIdle()`.
  Expected: first emission `phase == Loading`; terminal `phase == Content`,
  `dashboard != null`, `isStale == false`, `isRefreshing == false`, `error == null`.
  Traces: AC-1, AC-2.

- **TC-AND-068-02 — Success with empty payload → Empty**
  Type: unit (JVM).
  Test target: JVM unit/Robolectric.
  Preconditions: repo returns `ApiResult.Success(dashboard)` where
  `dashboard.isEmpty()` is true (empty `top_content`/`active_broadcasts`/
  `recent_milestones` and all numeric metrics zero, per §4.3 corrected predicate).
  Steps: init; `advanceUntilIdle()`.
  Expected: terminal `phase == Empty`; `canRetry == true`; no `dashboard` content
  rendered.
  Traces: AC-1, AC-2.

- **TC-AND-068-03 — Cached result → stale Content + ShowMessage (offline path)**
  Type: unit (JVM).
  Test target: JVM unit/Robolectric.
  Preconditions: repo returns `ApiResult.Cached(nonEmptyDashboard)`; collect
  `effects`.
  Steps: init; `advanceUntilIdle()`.
  Expected: `phase == Content`, `isStale == true`, `isOffline == true`; exactly
  one `DashboardEffect.ShowMessage(@StringRes)` emitted; no `Error`.
  Traces: AC-2, AC-4, AC-6.

- **TC-AND-068-04 — Error with no prior content → Error(canRetry=true)**
  Type: unit (JVM).
  Test target: JVM unit/Robolectric.
  Preconditions: repo returns `ApiResult.Error(IOException, httpCode=null)`
  (network/timeout — analog of web `ApiError(0, "Network error")`).
  Steps: init; `advanceUntilIdle()`.
  Expected: `phase == Error`, `error is DashboardError.Network`, `canRetry == true`,
  `dashboard == null`. No `ShowMessage`/`RequireReauth`.
  Traces: AC-1, AC-2.

- **TC-AND-068-05 — 5xx Error mapping → DashboardError.Server**
  Type: unit (JVM).
  Test target: JVM unit/Robolectric.
  Preconditions: repo returns `ApiResult.Error(httpCode=503, message="…")` derived
  from a FastAPI `detail` (string form) normalized upstream.
  Steps: init; `advanceUntilIdle()`.
  Expected: `phase == Error`, `error is DashboardError.Server(code=503)`,
  `retryable == true`.
  Traces: AC-1, AC-2.

- **TC-AND-068-06 — onRefresh over Content: isRefreshing then clears on success**
  Type: unit (JVM).
  Test target: JVM unit/Robolectric.
  Preconditions: reach `Content` (per TC-01); script second `getDashboard` to
  suspend, then return `Success(updatedDashboard)`.
  Steps: call `onRefresh()`; assert intermediate `isRefreshing == true` with
  content still visible; resume; `advanceUntilIdle()`.
  Expected: while in flight `phase == Content && isRefreshing == true &&
  dashboard != null`; after success `isRefreshing == false`, `isStale == false`,
  content replaced.
  Traces: AC-3.

- **TC-AND-068-07 — onRefresh failure keeps Content, sets isStale + ShowMessage**
  Type: unit (JVM).
  Test target: JVM unit/Robolectric.
  Preconditions: reach `Content`; script second `getDashboard` to return
  `ApiResult.Error` (or `Cached`).
  Steps: `onRefresh()`; `advanceUntilIdle()`; collect `effects`.
  Expected: `phase == Content` retained, `isStale == true`, `isRefreshing == false`;
  one `ShowMessage(@StringRes)`; no transition to `Error`.
  Traces: AC-3, AC-4.

- **TC-AND-068-08 — Unauthorized → SessionExpired + RequireReauth**
  Type: unit (JVM).
  Test target: JVM unit/Robolectric.
  Preconditions: repo returns `ApiResult.Unauthorized` (i.e. a 401 that survived
  `core-network`'s single `POST /ui/session/refresh` + retry, per `client.ts`);
  collect `effects`.
  Steps: init; `advanceUntilIdle()`.
  Expected: `phase == Error`, `error == DashboardError.SessionExpired`,
  `canRetry == false`; exactly one `DashboardEffect.RequireReauth`. Cached content
  (if any) preserved per Risk R3 default.
  Traces: AC-4. (Security/permission case.)

- **TC-AND-068-09 — onRetry from Error re-enters Loading then resolves**
  Type: unit (JVM).
  Test target: JVM unit/Robolectric.
  Preconditions: reach `Error` (per TC-04); script next `getDashboard` to return
  `Success(nonEmpty)`.
  Steps: `onRetry()`; assert `phase == Loading`; `advanceUntilIdle()`.
  Expected: `Loading` then `Content`; `error == null`.
  Traces: AC-1, AC-2, AC-3.

- **TC-AND-068-10 — Concurrent onRefresh collapses to one repo call (de-dup)**
  Type: unit (JVM).
  Test target: JVM unit/Robolectric.
  Preconditions: `getDashboard` suspends until released; spy/count invocations on
  the fake.
  Steps: call `onRefresh()` three times rapidly before releasing; release;
  `advanceUntilIdle()`.
  Expected: repository invocation count == 1; single terminal state; no duplicate
  effects.
  Traces: AC-3. (FR-5 in-flight guard.)

- **TC-AND-068-11 — Reducer purity / transition table**
  Type: unit (JVM, dispatcher-free).
  Test target: JVM unit/Robolectric.
  Preconditions: none (pure functions `startLoad`, `toContentOrEmpty`, `toError`).
  Steps: drive each row of the §6 transition table directly on
  `DashboardUiState`.
  Expected: each row produces the documented target state; functions have no side
  effects and are deterministic.
  Traces: AC-1, AC-2.

- **TC-AND-068-12 — State survives configuration change (no reload on rotation)**
  Type: unit (JVM) + instrumented confirmation.
  Test target: JVM unit/Robolectric for the StateFlow assertion; optional
  instrumented confirm on headless emulator AVD `test35` (API 35) for real
  ViewModel-retention across rotation.
  Preconditions: reach `Content`; record repo call count.
  Steps: re-collect `uiState` (simulating a new collector after rotation); for the
  instrumented variant, rotate the host Activity.
  Expected: same terminal value re-emitted; repository call count unchanged (no
  extra fetch). Traces: AC-1, AC-2. (FR-7.)

- **TC-AND-068-13 — Contract: repository wired to /ui/dashboard/summary shape**
  Type: contract/MockWebServer.
  Test target: JVM unit/Robolectric (MockWebServer; no device).
  Preconditions: a real `DashboardApi`/repository (AND-065) under test, or a thin
  contract harness, pointed at MockWebServer.
  Steps: enqueue a `200` with a real `DashboardSummary` JSON body (numeric
  `generated_at`, `earnings_breakdown`, `top_content`, etc., per §5); enqueue a
  `422 HTTPValidationError` (`{"detail":[{"msg":"…","loc":[…],"type":"…"}]}`);
  enqueue a `503`; enqueue a `401` then assert exactly one `POST
  /ui/session/refresh` is issued before the single retry.
  Expected: 200 → `ApiResult.Success` with correctly mapped fields; 422/503 →
  `ApiResult.Error` with normalized message; 401-after-failed-refresh →
  `ApiResult.Unauthorized`; request carries the `X-CSRF-Token` header sourced from
  the session cookie. (Guards against regressions to the corrected endpoint/shape.)
  Traces: AC-2, AC-4, AC-5.

- **TC-AND-068-14 — Flaky/offline dev-host integration smoke**
  Type: integration (instrumented).
  Test target: headless emulator AVD `test35` (API 35) for CI; ALSO run once on
  the PHYSICAL DEVICE (Samsung Galaxy A15 5G, SM-A156U, API 34, arm64-v8a) to
  confirm real-network/airplane-mode behavior and API-34-vs-35 / arm64-vs-x86
  parity against the unreliable plaintext dev host `http://18.222.237.167:8000`.
  Preconditions: app built against the dev host; cleartext permitted for that host.
  Steps: (a) cold-load with network up → Content; (b) toggle airplane mode and
  `onRefresh()` → stale Content + ShowMessage (if cache present) or Error (if not);
  (c) restore network and `onRetry()` → Content; (d) induce a slow (~20s) response
  and confirm no shorter client deadline fires.
  Expected: state transitions match §6; offline yields stale/`Error` not a crash;
  cleartext call to the dev host succeeds only because it is allow-listed.
  Traces: AC-1, AC-2, AC-4, AC-5. (MUST include a physical-device run for the
  real-network/airplane-mode and ABI/API-parity portions.)

- **TC-AND-068-15 — Accessibility / @StringRes resolution (downstream binding)**
  Type: Compose-UI (instrumented).
  Test target: headless emulator AVD `test35` (API 35); a minimal harness
  Composable that binds `DashboardUiState`/`DashboardEffect` (formally AND-069,
  exercised here for contract).
  Preconditions: feed Content, Empty, Error, stale/offline states; emit a
  `ShowMessage(resId)`.
  Steps: render each state; resolve `ShowMessage.resId` against `strings.xml`;
  run an accessibility assertion pass (TalkBack/`assertContentDescriptionEquals`,
  touch-target and contrast checks via the Compose a11y test APIs).
  Expected: every `@StringRes` resolves (no missing-resource crash); no hard-coded
  literals leak; states expose content descriptions; no logged payload/PII.
  Traces: AC-6, AC-2. (Accessibility + no-literal-strings security/privacy check.)

### Coverage matrix

| Acceptance criterion | Covered by |
|----------------------|------------|
| AC-1 (all transitions unit-tested, deterministic) | TC-01, TC-02, TC-04, TC-05, TC-09, TC-11, TC-12, TC-14 |
| AC-2 (`StateFlow<DashboardUiState>` Loading/Content/Empty/Error + isStale/isRefreshing) | TC-01, TC-02, TC-03, TC-04, TC-05, TC-09, TC-11, TC-12, TC-13, TC-14, TC-15 |
| AC-3 (`onRefresh`/`onRetry`; concurrent refresh collapses to one call) | TC-06, TC-07, TC-09, TC-10 |
| AC-4 (Cached → stale + ShowMessage; Unauthorized → SessionExpired + RequireReauth) | TC-03, TC-07, TC-08, TC-13, TC-14 |
| AC-5 (no Composables/HTTP/Room added; depends only on repository) | TC-13, TC-14 |
| AC-6 (user-facing strings via `@StringRes`, locale-agnostic) | TC-03, TC-15 |
