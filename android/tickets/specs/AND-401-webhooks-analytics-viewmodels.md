---
id: AND-401
title: Webhooks/analytics ViewModels
milestone: M8
epic: E52
priority: P2
size: M
status: draft
depends_on: [AND-398]
blocks: [AND-402]
---

# AND-401 — Webhooks/analytics ViewModels

## 1. Overview & Goal

This ticket implements the presentation/state layer for the two creator-facing
read surfaces shipped in milestone M8 / epic E52: **Webhooks** (list, detail,
light create — data layer from AND-398) and **Analytics dashboards** (read-only
charts/KPIs — data layer from AND-399). It introduces three Hilt ViewModels —
`WebhooksListViewModel`, `WebhookCreateViewModel`, and `AnalyticsViewModel` —
each exposing a single `StateFlow<UiState>` plus one-shot side effects, and the
immutable UI-state and effect models those ViewModels emit.

No Composables, navigation graphs, DTOs, Retrofit interfaces, or Room/DataStore
code are introduced here. Those belong to AND-398 (webhooks data + screens),
AND-399 (analytics data + screens), and the surrounding feature UI tickets. The
scope of AND-401 is exactly **"State."**: deterministic, fully unit-tested state
machines that map repository `ApiResult<T>` results into render-ready UI states
(loading, content, empty, error, offline-stale, submitting) and handle user
events (initial load, refresh, retry, time-range change, create-submit).

The dev backend (`http://18.222.237.167:8000`) is plaintext HTTP and unreliable;
the state model must first-class represent slow loads (~20s OkHttp timeout),
transient failures, and serving stale cached content while offline for the two
idempotent GET-backed read screens.

Success is measured by: (a) every modeled transition is reachable and covered by
a unit test using fake repositories and a `TestDispatcher`; (b) the public
surfaces (`uiState`, `effects`, intent methods) are stable enough for AND-402
(repo + UI tests) and the E52 screen tickets to bind against without churn.

## 2. Context & References

- **Modules:** `feature-webhooks` and `feature-analytics`, both depending on
  `core-data`, `core-model`, `core-network`, `core-ui`, `core-testing`. Package
  roots `com.testlogon.android.feature.webhooks` and
  `com.testlogon.android.feature.analytics`.
- **Upstream AND-398 (Webhooks config, light):** provides `WebhooksRepository`,
  the `Webhook` / `WebhookCreateRequest` domain models in
  `com.testlogon.android.core.model`, `WebhooksApi`, and DTO→domain mapping for
  `frontend/src/api/endpoints/webhooks.ts`. Consumed here as an interface only.
- **Upstream AND-399 (Analytics dashboards, read):** provides
  `AnalyticsRepository`, the `AnalyticsDashboard` domain model, and mapping for
  `frontend/src/api/endpoints/analytics.ts`. This ticket lists AND-398 as its
  sole hard backlog dependency; the analytics ViewModel additionally consumes
  AND-399's repository contract (see Risks R1 — if AND-399 lands after this
  ticket, the analytics VM is gated behind the interface and stubbed).
- **Downstream AND-402 (Webhooks/analytics tests):** repository + UI tests that
  bind to the states/effects defined here.
- **Web reference:** `frontend/src/api/endpoints/webhooks.ts`,
  `frontend/src/api/endpoints/analytics.ts`, shared types in
  `frontend/src/api/types.ts`. The web app has no offline/stale concept; that is
  Android-specific.
- **Shared conventions:** ViewModels expose `StateFlow<UiState>`; the typed
  `ApiResult<T>` (with a `Cached` variant for stale reads) lives in
  `core-network`; FastAPI `detail` (`string | [{msg}] | {code,...}`) is
  normalized to a user-facing message by the `core-network` error mapper before
  reaching the repository.
- **Auth:** session is cookie-based and managed entirely by `core-network`
  (persistent cookie jar, `X-CSRF-Token` echo, single `POST /ui/session/refresh`
  on 401). These ViewModels perform no auth; they react to an `Unauthorized`
  result by emitting a re-auth side effect.

## 3. Functional Requirements

**Webhooks list (`WebhooksListViewModel`)**

FR-1. On first composition, auto-load the webhook list (`init` → `load()`),
emitting `Loading` then a terminal phase.

FR-2. Exposes `val uiState: StateFlow<WebhooksListUiState>` with phases:
`Loading`, `Content(items, isStale, isRefreshing)`, `Empty(isRefreshing)`,
`Error(error)`.

FR-3. `onRefresh()` (pull-to-refresh) keeps existing content visible with
`isRefreshing=true`; on failure keeps content and sets `isStale=true` plus a
transient `ShowMessage` effect. `onRetry()` from `Error`/`Empty` re-enters
`Loading`.

FR-4. Refresh de-duplication: concurrent loads collapse to one in-flight job
(`loadJob` active-guard).

FR-5. A successful create (signalled by `WebhookCreateViewModel`) triggers a
list reload; exposed as `fun reload()` for the screen to call after create
returns, and the list VM also re-loads on next `onStart`/resume if a
`createdAt` invalidation token differs (optional, see Technical Design).

**Webhook create (`WebhookCreateViewModel`)**

FR-6. Exposes `val uiState: StateFlow<WebhookCreateUiState>` holding editable
form fields (`url`, `events: Set<WebhookEvent>`, `active`), client-side
validation results, and a `submission` phase (`Idle`, `Submitting`,
`Submitted`, `Error`).

FR-7. Client-side validation before submit: `url` must be a syntactically valid
absolute `https`/`http` URL and non-blank; at least one event selected. Invalid
fields surface as `FieldError` without a network call.

FR-8. `onSubmit()` is a one-shot, non-idempotent `POST`; it must not be retried
automatically (see Error Handling). On success emits `WebhookCreateEffect.Created(id)`
and sets phase `Submitted`. Double-submit is prevented by a `Submitting` guard.

**Analytics (`AnalyticsViewModel`)**

FR-9. Exposes `val uiState: StateFlow<AnalyticsUiState>` with the same phase
vocabulary as the webhooks list (`Loading`/`Content`/`Empty`/`Error`) plus the
`isStale`/`isRefreshing` flags and the currently selected `range: AnalyticsRange`.

FR-10. `onRangeChange(range)` re-queries for the new time window
(`LAST_7D`, `LAST_30D`, `LAST_90D`; default `LAST_7D`), showing `isRefreshing`
over existing content rather than a full-screen `Loading` when content exists.

FR-11. Read-only: no analytics mutations exist; only load/refresh/range-change.

**Common**

FR-12. On `ApiResult.Unauthorized` (after the network layer's single refresh
retry failed) emit `…Effect.RequireReauth` and move to
`Error(SessionExpired)` with `canRetry=false`.

FR-13. State survives configuration changes (ViewModel scope); content present
on rotation is not reloaded. Slow loads up to the ~20s timeout complete or fail
without an additional VM-imposed deadline.

## 4. Technical Design

Packages: `com.testlogon.android.feature.webhooks` and
`com.testlogon.android.feature.analytics`. Each `*UiState` is a single immutable
data class (not a sealed hierarchy) so content fields persist across refresh
transitions; a `Phase` enum names the mutually exclusive renders.

### 4.1 Webhooks list state

```kotlin
data class WebhooksListUiState(
    val phase: Phase = Phase.Loading,
    val items: List<Webhook> = emptyList(),   // core-model (AND-398)
    val isRefreshing: Boolean = false,
    val isStale: Boolean = false,
    val error: WebhooksError? = null,
) {
    enum class Phase { Loading, Content, Empty, Error }
    val isOffline: Boolean get() = isStale && items.isNotEmpty()
    val canRetry: Boolean get() = phase == Phase.Error || phase == Phase.Empty
}
```

### 4.2 Webhook create state

```kotlin
data class WebhookCreateUiState(
    val url: String = "",
    val events: Set<WebhookEvent> = emptySet(),
    val active: Boolean = true,
    val fieldErrors: Map<Field, WebhookFieldError> = emptyMap(),
    val submission: Submission = Submission.Idle,
) {
    enum class Field { Url, Events }
    sealed interface Submission {
        data object Idle : Submission
        data object Submitting : Submission
        data class Submitted(val id: String) : Submission
        data class Error(val error: WebhooksError) : Submission
    }
    val canSubmit: Boolean
        get() = submission != Submission.Submitting &&
            url.isNotBlank() && events.isNotEmpty()
}

enum class WebhookFieldError { Blank, MalformedUrl, NoEventsSelected }
```

### 4.3 Analytics state

```kotlin
enum class AnalyticsRange(val apiValue: String) {
    LAST_7D("7d"), LAST_30D("30d"), LAST_90D("90d")
}

data class AnalyticsUiState(
    val phase: Phase = Phase.Loading,
    val dashboard: AnalyticsDashboard? = null,  // core-model (AND-399)
    val range: AnalyticsRange = AnalyticsRange.LAST_7D,
    val isRefreshing: Boolean = false,
    val isStale: Boolean = false,
    val error: AnalyticsError? = null,
) {
    enum class Phase { Loading, Content, Empty, Error }
    val canRetry: Boolean get() = phase == Phase.Error || phase == Phase.Empty
}
```

### 4.4 Error and effect models

```kotlin
sealed interface WebhooksError {
    val retryable: Boolean
    data class Network(val message: String) : WebhooksError { override val retryable = true }
    data class Server(val code: Int, val message: String) : WebhooksError { override val retryable = true }
    data class Validation(val message: String) : WebhooksError { override val retryable = false } // 422 from server
    data object SessionExpired : WebhooksError { override val retryable = false }
    data class Unknown(val message: String) : WebhooksError { override val retryable = true }
}
// AnalyticsError mirrors WebhooksError minus Validation (read-only surface).

sealed interface WebhooksListEffect {
    data object RequireReauth : WebhooksListEffect
    data class ShowMessage(@StringRes val resId: Int) : WebhooksListEffect
}
sealed interface WebhookCreateEffect {
    data class Created(val id: String) : WebhookCreateEffect
    data object RequireReauth : WebhookCreateEffect
    data class ShowMessage(@StringRes val resId: Int) : WebhookCreateEffect
}
sealed interface AnalyticsEffect {
    data object RequireReauth : AnalyticsEffect
    data class ShowMessage(@StringRes val resId: Int) : AnalyticsEffect
}
```

Effects are exposed as `Flow<…Effect>` backed by a `Channel(Channel.BUFFERED)`
via `receiveAsFlow()`, consumed by the screen in a `LaunchedEffect`. They are
deliberately not part of `StateFlow` to avoid replay-on-rotation. All
user-facing strings are referenced by `@StringRes` id, never literals, keeping
the ViewModels locale-agnostic.

### 4.5 ViewModels (shapes)

```kotlin
@HiltViewModel
class WebhooksListViewModel @Inject constructor(
    private val repository: WebhooksRepository,           // AND-398
    @Dispatcher(IO) private val ioDispatcher: CoroutineDispatcher,
) : ViewModel() {
    private val _uiState = MutableStateFlow(WebhooksListUiState())
    val uiState: StateFlow<WebhooksListUiState> = _uiState.asStateFlow()
    private val _effects = Channel<WebhooksListEffect>(Channel.BUFFERED)
    val effects: Flow<WebhooksListEffect> = _effects.receiveAsFlow()
    private var loadJob: Job? = null

    init { load(fromUser = false) }
    fun onRefresh() = load(fromUser = true)
    fun onRetry() = load(fromUser = true)
    fun reload() = load(fromUser = true)

    private fun load(fromUser: Boolean) {
        if (loadJob?.isActive == true) return             // FR-4 de-dup
        loadJob = viewModelScope.launch(ioDispatcher) {
            _uiState.update { it.startLoad() }
            when (val r = repository.getWebhooks(forceRefresh = fromUser)) {
                is ApiResult.Success      -> _uiState.update { it.toContentOrEmpty(r.data, stale = false) }
                is ApiResult.Cached       -> { _uiState.update { it.toContentOrEmpty(r.data, stale = true) }; _effects.send(ShowMessage(R.string.offline_showing_saved)) }
                is ApiResult.Unauthorized -> { _effects.send(RequireReauth); _uiState.update { it.toError(WebhooksError.SessionExpired) } }
                is ApiResult.Error        -> reduceFailure(r)
            }
        }
    }
}
```

```kotlin
@HiltViewModel
class WebhookCreateViewModel @Inject constructor(
    private val repository: WebhooksRepository,
    @Dispatcher(IO) private val ioDispatcher: CoroutineDispatcher,
) : ViewModel() {
    private val _uiState = MutableStateFlow(WebhookCreateUiState())
    val uiState: StateFlow<WebhookCreateUiState> = _uiState.asStateFlow()
    private val _effects = Channel<WebhookCreateEffect>(Channel.BUFFERED)
    val effects: Flow<WebhookCreateEffect> = _effects.receiveAsFlow()

    fun onUrlChange(value: String) { _uiState.update { it.copy(url = value, fieldErrors = it.fieldErrors - Field.Url) } }
    fun onToggleEvent(e: WebhookEvent) { /* add/remove from set */ }
    fun onActiveChange(active: Boolean) { _uiState.update { it.copy(active = active) } }

    fun onSubmit() {
        val errors = validate(_uiState.value)             // FR-7, pure
        if (errors.isNotEmpty()) { _uiState.update { it.copy(fieldErrors = errors) }; return }
        if (_uiState.value.submission == Submission.Submitting) return  // FR-8 guard
        viewModelScope.launch(ioDispatcher) {
            _uiState.update { it.copy(submission = Submission.Submitting) }
            when (val r = repository.createWebhook(_uiState.value.toRequest())) {
                is ApiResult.Success      -> { _uiState.update { it.copy(submission = Submission.Submitted(r.data.id)) }; _effects.send(Created(r.data.id)) }
                is ApiResult.Unauthorized -> { _effects.send(RequireReauth); _uiState.update { it.copy(submission = Submission.Error(WebhooksError.SessionExpired)) } }
                is ApiResult.Error        -> _uiState.update { it.copy(submission = Submission.Error(mapError(r))) }
                is ApiResult.Cached       -> error("create is non-idempotent; Cached not expected")
            }
        }
    }
}
```

`AnalyticsViewModel` mirrors `WebhooksListViewModel` but adds
`fun onRangeChange(range: AnalyticsRange)` which updates `range` then calls
`load(fromUser = false)` with the new range, passing `range.apiValue` to
`repository.getDashboard(range, forceRefresh)`.

`startLoad()`, `toContentOrEmpty()`, `toError()`, `validate()`, `toRequest()`,
and `mapError()` are **pure** functions/extensions so the transition table and
validation are unit-testable without a dispatcher.

### 4.6 Repository contracts assumed upstream

```kotlin
interface WebhooksRepository {                            // AND-398
    suspend fun getWebhooks(forceRefresh: Boolean): ApiResult<List<Webhook>>
    suspend fun getWebhook(id: String): ApiResult<Webhook>
    suspend fun createWebhook(request: WebhookCreateRequest): ApiResult<Webhook>
}
interface AnalyticsRepository {                            // AND-399
    suspend fun getDashboard(range: String, forceRefresh: Boolean): ApiResult<AnalyticsDashboard>
}
```

### 4.7 Hilt wiring

All three are `@HiltViewModel`; no new module is required beyond the
`@Dispatcher(IO)` qualifier provided by `core-data`. Repositories are bound by
AND-398 / AND-399 modules.

## 5. API Contract

This ticket introduces **no new network calls**; all HTTP is owned by AND-398
(webhooks) and AND-399 (analytics) and mirrors the web API layer. Documented
here only as the contract these ViewModels consume (already mapped to domain
objects before reaching the VM).

- `GET /ui/webhooks` → list. Idempotent; eligible for the bounded-backoff retry
  on the core-network interceptor. Web ref: `webhooks.ts#list`.
- `GET /ui/webhooks/{id}` → single. Idempotent.
- `POST /ui/webhooks` → create. **Non-idempotent**, no auto-retry. Body:
  ```json
  { "url": "https://example.com/hook", "events": ["session.started", "mfa.verified"], "active": true }
  ```
  Response `201`:
  ```json
  { "id": "wh_01HF...", "url": "https://example.com/hook", "events": ["session.started","mfa.verified"], "active": true, "created_at": "2026-06-05T12:00:00Z" }
  ```
- `GET /ui/analytics/dashboard?range=7d|30d|90d` → analytics. Idempotent. Web
  ref: `analytics.ts#dashboard`. Response shape (consumed as `AnalyticsDashboard`):
  ```json
  { "range": "7d",
    "kpis": [ { "key": "active_sessions", "label": "Active sessions", "value": 1280, "delta_pct": 4.2 } ],
    "series": [ { "key": "logins", "points": [ { "t": "2026-05-30", "v": 210 } ] } ],
    "generated_at": "2026-06-05T12:00:00Z" }
  ```

All requests ride the cookie jar + `X-CSRF-Token` header injected by
`core-network`. FastAPI `detail` (`string | [{msg}] | {code,...}`) is normalized
by the core-network error mapper into `ApiResult.Error(throwable, httpCode?,
message)`; this ticket maps that into `WebhooksError`/`AnalyticsError`
(`Network` for IO/timeout, `Server` for 5xx, `Validation` for 422 on create,
`Unknown` otherwise; 401 surfaces as `Unauthorized`, not `Error`).

## 6. Data & State Management

- **Single source of truth** per VM: `MutableStateFlow<…UiState>`, exposed
  read-only via `asStateFlow()`. Hot, ViewModel-owned; no `stateIn` needed.
- **No DataStore/Room access here.** Caching/staleness is the repositories'
  concern; `ApiResult.Cached` is the only staleness signal these VMs read.
- **Webhooks-list transition table:**

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

- **Analytics transition table** is identical with the addition that
  `onRangeChange` over `Content` behaves like `onRefresh` (keeps content,
  `isRefreshing=true`) and replaces both `dashboard` and `range` on success.
- **Create state machine:** `Idle → (validate fail) Idle+fieldErrors`;
  `Idle → Submitting → Submitted(id)` / `Submitting → Error`. `Submitting` is a
  hard guard against double submit.
- **Effects** are not persisted state; consumed once.

## 7. Error Handling & Resilience

- Network/timeout against the unreliable dev host (~20s OkHttp timeout) →
  `…Error.Network`. For the two read screens, if cached content exists, prefer
  stale `Content` over `Error`.
- 5xx → `…Error.Server(code, message)`, retryable via user action.
- 422 on create → `WebhooksError.Validation(message)`; surfaced in the create
  `submission` as `Error`, not a field error unless the mapper can attribute it
  to a field.
- 401 after the network layer's single `POST /ui/session/refresh` retry has
  failed → `Unauthorized` → `SessionExpired` + `RequireReauth`.
- Bounded backoff for idempotent GETs is owned by the core-network interceptor
  (AND-016); these VMs add no retry loop beyond user-initiated `onRetry`.
  **`POST /ui/webhooks` is never auto-retried** (non-idempotent) — the create VM
  relies solely on explicit user resubmission.
- Coroutine cancellation: read VMs use the in-flight `loadJob` guard;
  `CancellationException` is never converted into an error state.
- All repository calls are wrapped by `ApiResult`; no raw `try/catch` for
  expected failures. Unexpected throwables in reducers map to `…Error.Unknown`.

## 8. Security & Privacy

- No credentials, tokens, or cookies are handled here; the cookie jar and CSRF
  header live in `core-network`. The VMs must never log webhook URLs/secrets,
  payloads, or analytics figures.
- Webhook target URLs are user-supplied and may contain secrets in query params;
  treat as sensitive — never include in logs or `…Error` messages, and redact in
  any telemetry.
- `RequireReauth` carries no sensitive payload; it only signals navigation to
  the auth flow.
- Plaintext HTTP is a known dev-environment constraint owned by network config
  (cleartext permitted only for the dev host); not in scope here.

## 9. Accessibility & i18n

- This ticket produces no Composables, so it owns no `contentDescription`,
  focus, or touch-target behavior; those belong to the E52 screen tickets and
  AND-402's UI tests.
- All user-facing strings emitted via `…Effect.ShowMessage` carry a
  `@StringRes` id (Section 4.4); human-readable text is resolved by the screen
  from `feature-webhooks`/`feature-analytics` `strings.xml`. `WebhookFieldError`
  and `…Error` subtypes are semantic types mapped to localized strings by the
  consumer, keeping the VMs locale-agnostic and testable.
- `AnalyticsRange` labels are likewise resolved to localized strings in the UI
  layer; the enum only carries the API `apiValue`.

## 10. Telemetry & Logging

- Log transitions at `Timber.d` with stable tags `"WebhooksVM"`,
  `"WebhookCreateVM"`, `"AnalyticsVM"`: load start, terminal phase, stale flag,
  selected range (analytics), and error class name only — never payloads, URLs,
  or values.
- Emit one analytics event per terminal load via the `core-data` analytics
  abstraction if present (gated behind an injected no-op `Analytics` interface so
  this ticket does not block on it): `webhooks_loaded{source, count, empty,
  duration_ms}`, `webhook_created{event_count}` (no URL), `analytics_loaded{range,
  source, duration_ms}`, and `*_load_failed{error_type}`.
- No verbose logging in release builds (Timber release tree is a no-op per app
  config).

## 11. Testing Strategy

Unit tests are the core deliverable and the backlog acceptance criterion
("Unit-tested"). Use JUnit4, `kotlinx-coroutines-test`
(`StandardTestDispatcher` + `runTest`), Turbine for `StateFlow`/`Flow`
assertions, and hand-written fakes in `core-testing`
(`FakeWebhooksRepository`, `FakeAnalyticsRepository`) returning scripted
`ApiResult` values and recording call counts.

`WebhooksListViewModelTest`:
1. `init emits Loading then Content` for non-empty `Success`.
2. `Success empty → Empty`.
3. `Cached → Content(isStale=true) + ShowMessage`.
4. `Error with no prior content → Error(canRetry=true)`.
5. `onRefresh over Content sets isRefreshing then clears on success`.
6. `onRefresh failure keeps Content, sets isStale, emits ShowMessage`.
7. `Unauthorized → Error(SessionExpired) + RequireReauth`.
8. `onRetry from Error re-enters Loading then resolves`.
9. `concurrent onRefresh collapses to one repository call` (call-count == 1).

`WebhookCreateViewModelTest`:
10. `blank url → fieldErrors[Url]=Blank, no network call`.
11. `malformed url → MalformedUrl`; `empty events → NoEventsSelected`.
12. `valid submit → Submitting then Submitted(id) + Created effect`.
13. `double onSubmit while Submitting issues one createWebhook call`.
14. `server 422 → Submission.Error(Validation)`; `401 → RequireReauth`.

`AnalyticsViewModelTest`:
15. `init loads LAST_7D`; `onRangeChange(LAST_30D) re-queries with "30d" and
    sets isRefreshing over content`.
16. transitions mirroring tests 1–9 for the read path.

Pure functions (`validate`, `startLoad`, `toContentOrEmpty`, `toError`,
`mapError`) get direct dispatcher-free tests to pin Sections 6 and 4.2.

Turbine pattern:

```kotlin
viewModel.uiState.test {
    assertEquals(Phase.Loading, awaitItem().phase)
    advanceUntilIdle()
    assertEquals(Phase.Content, awaitItem().phase)
    cancelAndIgnoreRemainingEvents()
}
```

Compose UI tests and repository contract tests are explicitly **out of scope**
and owned by AND-402.

## 12. Dependencies & Sequencing

- **Depends on AND-398** (`WebhooksRepository`, `Webhook`/`WebhookCreateRequest`
  models, `WebhookEvent`). Hard backlog dependency; must merge first.
- **Soft-depends on AND-399** (`AnalyticsRepository`, `AnalyticsDashboard`). If
  AND-399 has not merged, ship the analytics VM against the interface with a
  `core-testing` fake and unblock the webhooks VMs independently (Risk R1).
- **Blocks AND-402** (repo + UI tests) which binds to the states/effects here.
- Transitive: `core-network` (`ApiResult` incl. `Cached`, error mapper),
  `core-testing` (fakes, test dispatcher rule), `core-data` (`@Dispatcher(IO)`,
  optional analytics facade).
- No Gradle/build changes beyond ensuring `feature-webhooks` and
  `feature-analytics` test deps (Turbine, coroutines-test) are present per
  `core-testing` conventions; add to the respective `build.gradle.kts` if
  missing.

## 13. Risks & Open Questions

- **R1 (sequencing):** AND-399 is not a listed dependency but the analytics VM
  needs its repository. Resolution: code against the `AnalyticsRepository`
  interface with a fake; the VM merges independently of AND-399's data layer.
- **R2 (must confirm):** Does `ApiResult` (core-network) include a `Cached`
  variant? Required for the offline/stale read states (FR-3, FR-9). If absent,
  add `ApiResult.Cached<T>` and have repos emit it on cache-fallback — coordinate
  with AND-398/AND-399 owners.
- **R3:** Exact `WebhookEvent` enum membership and the analytics
  KPI/series schema come from AND-398/AND-399 and the live `/openapi.json`;
  verify before finalizing `toRequest()` and the analytics domain mapping.
- **R4:** Whether `RequireReauth` should clear cached read content. Default: no
  (preserve last-known content behind the re-auth prompt); revisit with auth
  owner.
- **R5:** Analytics facade availability (Section 10) — gated behind a no-op to
  avoid a hard dependency.
- **OQ:** Should a successful create optimistically prepend to the list state, or
  always trigger a full `reload()`? Default: `reload()` for correctness; revisit
  if the list screen needs optimistic UX.

## 14. Acceptance Criteria

- AC-1 (from backlog): All modeled state transitions across the three ViewModels
  are unit-tested; the suites pass deterministically with `StandardTestDispatcher`.
- AC-2: `WebhooksListViewModel.uiState` and `AnalyticsViewModel.uiState` are
  `StateFlow<…UiState>` exposing Loading/Content/Empty/Error phases plus
  `isStale`/`isRefreshing`; `AnalyticsUiState` additionally exposes `range` and
  `onRangeChange` re-queries.
- AC-3: `onRefresh()`/`onRetry()` exist on the read VMs and concurrent refreshes
  collapse to a single repository call (verified by call-count assertion).
- AC-4: A `Cached`/offline read produces stale content (not an error) + a
  `ShowMessage` effect; an `Unauthorized` result produces `SessionExpired` +
  `RequireReauth`.
- AC-5: `WebhookCreateViewModel` validates client-side (blank/malformed URL, no
  events) without a network call, guards against double-submit, never
  auto-retries the `POST`, and emits `Created(id)` on success.
- AC-6: No Composables, no direct HTTP, and no Room/DataStore access are added;
  the VMs depend only on `WebhooksRepository`/`AnalyticsRepository`.
- AC-7: User-facing messages are referenced by `@StringRes` id, not literals; no
  webhook URLs/secrets or analytics values are logged.

## 15. Definition of Done

- `WebhooksListUiState`, `WebhookCreateUiState`, `AnalyticsUiState`, the error
  and effect models, and `WebhooksListViewModel`, `WebhookCreateViewModel`,
  `AnalyticsViewModel` implemented under
  `com.testlogon.android.feature.webhooks` and
  `com.testlogon.android.feature.analytics` exactly as specified.
- All listed unit tests plus pure-function tests written and green in CI; line
  coverage of the ViewModels + reducers/validators ≥ 85%.
- Public APIs (`uiState`, `effects`, intent methods) reviewed and agreed with the
  E52 screen owners and AND-402 so downstream binding requires no changes.
- `./gradlew :feature-webhooks:testDebugUnitTest :feature-analytics:testDebugUnitTest ktlintCheck detekt`
  passes; no new lint/detekt suppressions added.
- No hard-coded user-facing strings; no payload/URL/PII logging.
- Code reviewed and merged to `android-port`; AND-402 unblocked.
