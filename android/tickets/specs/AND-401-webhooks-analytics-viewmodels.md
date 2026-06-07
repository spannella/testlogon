---
id: AND-401
title: Webhooks/analytics ViewModels
milestone: M8
epic: E52
priority: P2
size: M
depends_on: [AND-398]
blocks: [AND-402]
status: reviewed
reviewed_on: 2026-06-06
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
  `AnalyticsRepository`, the `AnalyticsDashboard` domain model (an
  Android-side aggregate; see §5 — the backend has **no** single dashboard
  endpoint, the web client composes 6 parallel per-metric calls), and mapping
  for `frontend/src/api/endpoints/analytics.ts`. This ticket lists AND-398 as its
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
fields surface as `FieldError` without a network call. (Note: this URL-format
check is an **Android-side UX safeguard** — the backend `WebhookEndpointCreateReq`
does not constrain `url` format, and the web client has no equivalent client-side
URL validation; the server's only structural rejection is `422` for missing
required fields. Keep the check lenient enough not to block valid endpoints.)

FR-8. `onSubmit()` is a one-shot, non-idempotent `POST`; it must not be retried
automatically (see Error Handling). On success emits `WebhookCreateEffect.Created(id)`
and sets phase `Submitted`. Double-submit is prevented by a `Submitting` guard.

**Analytics (`AnalyticsViewModel`)**

FR-9. Exposes `val uiState: StateFlow<AnalyticsUiState>` with the same phase
vocabulary as the webhooks list (`Loading`/`Content`/`Empty`/`Error`) plus the
`isStale`/`isRefreshing` flags and the currently selected `range: AnalyticsRange`.

FR-10. `onRangeChange(range)` re-queries for the new time window
(`LAST_7D`, `LAST_30D`, `LAST_90D`, `LAST_1Y`; default `LAST_30D` to match the
web client — the backend takes `from_date`/`to_date`, not a `range` token, so
the VM resolves the preset to an ISO date window; see §4.3 correction), showing `isRefreshing`
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
    val description: String = "",                  // maps to required-but-defaulted "description" (default "")
    val events: Set<WebhookEvent> = emptySet(),    // maps to "event_types": List<String>
    val active: Boolean = true,                    // maps to "enabled" on the OUT DTO (not sent on create; server defaults enabled)
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

> **Correction (verified vs OpenAPI):** `WebhookEvent` is **not** a fixed
> server-side enum. The backend `WebhookEndpointCreateReq.event_types` is an
> open `array<string>`; the catalog of valid event-type strings is fetched at
> runtime from `GET /ui/webhooks/event-types` (web ref
> `webhooks.ts: listWebhookEventTypes`, returning `{ event_types: [{ type,
> description }] }`). AND-398 should therefore model `WebhookEvent` as a value
> wrapping the server `type` string (or a `List<WebhookEventType>` loaded from
> that endpoint), not a closed Kotlin `enum`. `toRequest()` emits
> `event_types = events.map { it.type }`. Selecting events in the create form
> requires the event-type catalog be available (AND-398 concern); if the VM is
> given an empty catalog it still validates "at least one selected".

### 4.3 Analytics state

> **Correction (verified vs OpenAPI + web ref):** the backend has **no**
> `range=7d|30d|90d` query parameter and **no** `GET /ui/analytics/dashboard`
> endpoint. Analytics endpoints accept `from_date` / `to_date` (ISO `YYYY-MM-DD`)
> plus optional `granularity` (see `AnalyticsDateRangeParams` in
> `src/api/types.ts`). The web client (`AnalyticsPage.tsx`) renders day-count
> **presets** (`7d`/`30d`/`90d`/`1y`, default **30d**) that it converts to
> `from_date = today - N days`, `to_date = today` client-side. So `AnalyticsRange`
> carries a **day count**, and the repository contract takes a resolved date
> window, not a server range token. Corrected below.

```kotlin
enum class AnalyticsRange(val days: Int) {
    // Web presets: 7/30/90 (+1y). Web default is 30d; this ticket keeps LAST_30D
    // as the default to match the web client (was incorrectly LAST_7D).
    LAST_7D(7), LAST_30D(30), LAST_90D(90), LAST_1Y(365);

    /** Resolve to the (from_date, to_date) ISO window the backend expects. */
    fun window(today: LocalDate): Pair<String, String> =
        today.minusDays(days.toLong()).toString() to today.toString()
}

data class AnalyticsUiState(
    val phase: Phase = Phase.Loading,
    val dashboard: AnalyticsDashboard? = null,  // core-model (AND-399); Android aggregate of the 6 per-metric responses
    val range: AnalyticsRange = AnalyticsRange.LAST_30D,  // matches web default (was LAST_7D)
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
`load(fromUser = false)` with the new range, resolving `range.window(today)` to
`(fromDate, toDate)` and passing them to
`repository.getDashboard(fromDate, toDate, forceRefresh)`. `today` is supplied
via an injected `Clock`/`Provider<LocalDate>` so the resolution is deterministic
under test.

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
    // Corrected: backend takes from_date/to_date, not a range token. The repo
    // fans out the 6 per-metric GETs (overview, revenue, views, subscribers,
    // top-content, audience) and aggregates them into AnalyticsDashboard.
    suspend fun getDashboard(
        fromDate: String, toDate: String, forceRefresh: Boolean,
    ): ApiResult<AnalyticsDashboard>
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

> **Corrected against OpenAPI index + `src/api/endpoints/*.ts` + `types.ts`.**
> The endpoint paths, the create request/response shapes, and the analytics
> endpoint were all wrong in the prior draft. Verified contract follows.

**Webhooks** (web ref `src/api/endpoints/webhooks.ts`; schemas
`WebhookEndpointOut` / `WebhookEndpointCreateReq` in `src/api/types.ts`):

- `GET /ui/webhooks` → list (`200`, bare `WebhookEndpointOut[]` per the web
  client; OpenAPI index shows no named response schema). Idempotent; eligible
  for bounded-backoff retry on the core-network interceptor. Web ref:
  `webhooks.ts: listWebhookEndpoints`.
- `GET /ui/webhooks/{endpoint_id}` → single `WebhookEndpointOut`. Idempotent.
  (Path param is `endpoint_id`, **not** `{id}`.)
- `POST /ui/webhooks` → create. **Non-idempotent**, no auto-retry.
  Request `WebhookEndpointCreateReq` — required: `url`, `event_types`;
  optional (with defaults): `description` (`""`), `signature_version`
  (`"v2"`, pattern `^(v1|v2|both)$`), `circuit_failure_threshold` (3–100),
  `retry_policy`. There is **no** `events` field and **no** `active`/`enabled`
  field on the create request (server defaults the endpoint to enabled). Body:
  ```json
  { "url": "https://example.com/hook",
    "description": "",
    "event_types": ["session.started", "mfa.verified"] }
  ```
  Response `201` `WebhookEndpointOut` (note `endpoint_id`, `event_types`,
  `enabled`, and **epoch-seconds numbers** for timestamps — not ISO strings):
  ```json
  { "endpoint_id": "wh_01HF...", "url": "https://example.com/hook",
    "description": "", "event_types": ["session.started","mfa.verified"],
    "enabled": true, "secret": null, "created_at": 1749124800,
    "updated_at": 1749124800, "last_delivery_at": null, "failure_count": 0,
    "disabled_reason": null, "signature_version": "v2", "circuit_state": null }
  ```
  `204` is used by `DELETE /ui/webhooks/{endpoint_id}`. Valid `event_types`
  strings come from `GET /ui/webhooks/event-types`
  (`{ event_types: [{ type, description }] }`), not a hardcoded enum.

**Analytics** (web ref `src/api/endpoints/analytics.ts`; schemas
`AnalyticsOverview`, `AnalyticsRevenue`, `AnalyticsViews`,
`AnalyticsSubscribers`, `AnalyticsTopContent`, `AnalyticsAudience` in
`src/api/types.ts`):

- There is **no** `GET /ui/analytics/dashboard` and **no** `range` query param.
  The web "dashboard" (`AnalyticsPage.tsx`) is composed from **six parallel
  idempotent GETs**, each taking `from_date`/`to_date` (ISO `YYYY-MM-DD`, plus
  optional `granularity`/`sort_by`):
  - `GET /ui/analytics/overview`  → `AnalyticsOverviewOut`
  - `GET /ui/analytics/revenue`   → `AnalyticsRevenueOut`
  - `GET /ui/analytics/views`     → `AnalyticsViewsOut`
  - `GET /ui/analytics/subscribers` → `AnalyticsSubscribersOut`
  - `GET /ui/analytics/top-content` → `AnalyticsTopContentOut`
  - `GET /ui/analytics/audience`  → `AnalyticsAudienceOut`
  - (`POST /ui/analytics/refresh` exists for a server-side recompute; the read
    VMs do not call it.)
  AND-399's `AnalyticsRepository` aggregates these into the Android-only
  `AnalyticsDashboard`. Real response shapes (excerpt): `AnalyticsOverview`
  = `{ period_views, period_revenue_cents, period_new_subscribers,
  total_subscribers, top_content[], currency }`; `AnalyticsRevenue`
  = `{ total_cents, breakdown{tips,subscriptions,unlocks,vod,ads,calls},
  time_series[], currency }`. There are **no** `kpis`/`series`/`generated_at`
  fields in the backend; those were invented by the prior draft and must be
  derived by AND-399's mapping if the UI wants a KPI/series shape.

All requests ride the cookie jar + `X-CSRF-Token` header (token read from the
`ui_csrf` cookie, web ref `client.ts`) injected by `core-network`. All `/ui/*`
endpoints additionally surface `422:HTTPValidationError` (FastAPI) and the
`*-impersonation`/`X-SESSION-ID` params in the index are admin/impersonation
headers, not user-facing. FastAPI `detail` (`string | [{msg}] | {code,...}`) is
normalized by the core-network error mapper into `ApiResult.Error(throwable,
httpCode?, message)`; this ticket maps that into `WebhooksError`/`AnalyticsError`
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
- **R3 (resolved during review):** verified against OpenAPI + web ref —
  `event_types` is an **open `array<string>`** sourced from
  `GET /ui/webhooks/event-types`, not a fixed enum; and there is **no** backend
  analytics dashboard/KPI/series schema (the web client composes 6 per-metric
  GETs). `toRequest()` emits `event_types` strings; AND-399's mapping must build
  any KPI/series shape itself from `AnalyticsOverview`/`AnalyticsRevenue`/etc.
  See §16 for the full citation list.
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the authoritative source pointer.
Verdicts: **Verified** (matches source), **Corrected** (was wrong, fixed in
place), **Unverified-assumption** (cannot be confirmed from available sources).

1. `GET /ui/webhooks` lists webhook endpoints. **Verified.**
   OpenAPI `GET /ui/webhooks` (op `list_webhook_endpoints_ui_webhooks_get`,
   `resp=200`); `src/api/endpoints/webhooks.ts: listWebhookEndpoints`
   (`api.get<WebhookEndpointOut[]>`).
2. List response is a bare `WebhookEndpointOut[]`. **Verified (web ref).**
   OpenAPI index has no named 200 schema, but `webhooks.ts: listWebhookEndpoints`
   types it `WebhookEndpointOut[]`.
3. Single fetch is `GET /ui/webhooks/{endpoint_id}` → `WebhookEndpointOut`
   (path param is `endpoint_id`, not `{id}`). **Corrected.**
   OpenAPI `GET /ui/webhooks/{endpoint_id}`
   (op `get_webhook_endpoint_...`, `resp=200:WebhookEndpointOut`);
   `webhooks.ts: getWebhookEndpoint`.
4. Create is `POST /ui/webhooks`, request `WebhookEndpointCreateReq`, response
   `201` `WebhookEndpointOut`. **Corrected** (prior draft invented the body).
   OpenAPI `POST /ui/webhooks` (op `create_webhook_endpoint_...`,
   `req=WebhookEndpointCreateReq`, `resp=201;422:HTTPValidationError`);
   `webhooks.ts: createWebhookEndpoint`.
5. Create required fields are `url` + `event_types`; `description` defaults to
   `""`; `signature_version` defaults `"v2"` (`^(v1|v2|both)$`);
   `circuit_failure_threshold` 3–100. **Corrected.**
   `components.schemas.WebhookEndpointCreateReq` (`required: [url, event_types]`)
   in `reference/openapi.pretty.json`; `src/api/types.ts: WebhookEndpointCreateReq`.
6. There is **no** `events` field and **no** `active`/`enabled` field on the
   create request. **Corrected** (prior draft used `events`/`active`).
   Same schema as #5; the OUT DTO uses `enabled`/`event_types`
   (`src/api/types.ts: WebhookEndpointOut`).
7. `WebhookEndpointOut` field names: `endpoint_id`, `event_types`, `enabled`,
   timestamps (`created_at`/`updated_at`/`last_delivery_at`) are **epoch-second
   numbers**, `secret: string|null`. **Corrected** (prior draft used `id`,
   `events`, `active`, and ISO-string `created_at`).
   `src/api/types.ts: WebhookEndpointOut`; `components.schemas.WebhookEndpointOut`.
8. Valid event-type strings come from `GET /ui/webhooks/event-types`
   (`{ event_types: [{ type, description }] }`); `event_types` is an open
   `array<string>`, not a fixed enum. **Corrected** (prior draft assumed a
   `WebhookEvent` enum).
   OpenAPI `GET /ui/webhooks/event-types` (op `list_event_types_...`);
   `webhooks.ts: listWebhookEventTypes`; `src/api/types.ts: WebhookEventType`.
9. `POST /ui/webhooks` is non-idempotent (no auto-retry). **Verified** (it is a
   POST creating a resource; OpenAPI returns `201`). Idempotency policy itself is
   an Android core-network design decision (AND-016).
10. There is **no** `GET /ui/analytics/dashboard` endpoint and **no** `range`
    query param. **Corrected** (prior draft invented both).
    OpenAPI index has no `/ui/analytics/dashboard`; analytics endpoints
    (`/ui/analytics/overview|revenue|views|subscribers|top-content|audience`)
    take `from_date`/`to_date` params. `src/api/endpoints/analytics.ts`.
11. The web "dashboard" is composed from 6 parallel per-metric GETs. **Verified.**
    `src/pages/analytics/AnalyticsPage.tsx` (6 `useQuery` calls to
    `getAnalyticsOverview/Revenue/Views/Subscribers/TopContent/Audience`).
12. Range presets are `7d/30d/90d/1y`, **default 30d**, computed client-side to
    `from_date = today - N days`, `to_date = today`. **Corrected** (prior draft
    said default `LAST_7D` and a server `range` token).
    `AnalyticsPage.tsx` `RANGE_PRESETS` + `daysAgo()` + `fromDate = ... || daysAgo(30)`.
13. Analytics date params are `from_date`/`to_date` (ISO `YYYY-MM-DD`) +
    optional `granularity`/`sort_by`/`limit`. **Verified.**
    `src/api/types.ts: AnalyticsDateRangeParams`; OpenAPI analytics endpoints
    `params=from_date,to_date,...`.
14. Backend analytics responses have **no** `kpis`/`series`/`generated_at`
    fields. **Corrected** (prior draft invented that shape).
    `src/api/types.ts: AnalyticsOverview` (`period_views`,
    `period_revenue_cents`, ...), `AnalyticsRevenue` (`total_cents`, `breakdown`,
    `time_series`, ...); OpenAPI `resp=200:AnalyticsOverviewOut` etc.
15. Session is cookie-based; CSRF via `X-CSRF-Token` header read from the
    `ui_csrf` cookie. **Verified** (header name confirmed; the prior phrase
    "echo" is loose but directionally correct).
    `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`).
16. On 401, a single `POST /ui/session/refresh` retry is attempted, then the
    original request is retried once. **Verified.**
    `src/api/client.ts: refreshSession()` (`method: "POST"`,
    `/ui/session/refresh`) + single-flight `refreshPromise` + one retry; on
    persistent 401 it logs out (`logout("session_expired")`).
17. FastAPI error `detail` is `string | [{msg}] | {code,...}` and `/ui/*`
    endpoints surface `422:HTTPValidationError`. **Verified.**
    OpenAPI `resp=...422:HTTPValidationError` across `/ui/webhooks` and
    `/ui/analytics/*`; `client.ts: normalizeErrorDetail(...detail...)`.
18. `ApiResult` has a `Cached` variant in `core-network`. **Unverified-assumption.**
    Not present in the backend/web sources (the web client has no offline/stale
    concept — stated in §2); it is an Android-only contract owned by AND-016/
    AND-398/AND-399 (tracked as Risk R2). Framework-internal; no external ref.
19. Client-side `https`/`http` URL-format validation in the create form (FR-7).
    **Unverified-assumption / Android-side UX choice.** The backend
    `WebhookEndpointCreateReq.url` has no format constraint
    (`components.schemas.WebhookEndpointCreateReq`), and the web client performs
    no equivalent URL validation (`src/pages/webhooks/*` has no URL regex).
20. Domain id surfaced as `Submission.Submitted(id)` / `Created(id)` maps from
    `WebhookEndpointOut.endpoint_id`. **Verified (source) + assumption (mapping).**
    Source field is `endpoint_id` (`src/api/types.ts`); whether AND-398's domain
    `Webhook` exposes it as `id` is AND-398's mapping decision.
21. ViewModel/Hilt/StateFlow/Channel-effect/Turbine choices. **framework ref.**
    `@HiltViewModel` + `viewModelScope`:
    https://developer.android.com/topic/libraries/architecture/viewmodel ;
    `StateFlow`: https://developer.android.com/kotlin/flow/stateflow-and-sharedflow ;
    one-shot effects via `Channel.receiveAsFlow()`:
    https://kotlinlang.org/api/kotlinx.coroutines/kotlinx-coroutines-core/kotlinx.coroutines.channels/receive-as-flow.html ;
    `StandardTestDispatcher`/`runTest`:
    https://developer.android.com/kotlin/coroutines/test .

### Corrections made

- §2: clarified `AnalyticsDashboard` is an Android-only aggregate; backend has
  no single dashboard endpoint (citations 10–11, 14).
- §4.2: added `description`, annotated `events`→`event_types` and
  `active`→`enabled` mappings; noted `WebhookEvent` is an open-string type
  sourced from `/ui/webhooks/event-types`, not a closed enum (citations 5–8).
- §4.3: replaced `AnalyticsRange(apiValue="7d"...)` with a day-count enum
  (`7/30/90/365`) that resolves to a `from_date`/`to_date` window; default
  changed `LAST_7D`→`LAST_30D` to match web (citations 10–13).
- §4.6: `AnalyticsRepository.getDashboard` signature changed from
  `(range: String, ...)` to `(fromDate, toDate, forceRefresh)`; documented the
  6-call fan-out (citations 10–11, 13).
- §4.5 prose: `onRangeChange` now resolves `range.window(today)` via an injected
  clock rather than passing `range.apiValue` (citation 12–13).
- FR-7: noted https/http URL validation is an Android-side UX safeguard, not a
  backend or web-client constraint (citations 19).
- FR-10: corrected preset list/default and removed the `range` token (cit. 12).
- §5 (API Contract): rewritten — correct paths (`{endpoint_id}`), correct create
  request (`url`/`event_types`/`description`, no `events`/`active`), correct OUT
  shape (`endpoint_id`, epoch-number timestamps), removed the fictitious
  `/ui/analytics/dashboard` + `kpis/series` shape and listed the real 6 analytics
  endpoints and their response schemas; corrected CSRF cookie name (citations 3–17).
- R3: marked resolved with verified findings.

### Open assumptions

- **`ApiResult.Cached`** existence (citation 18): an Android core-network
  contract not derivable from backend/web sources; gated by Risk R2. If absent
  upstream, the offline/stale states (FR-3, FR-9) cannot be implemented as
  specified — must coordinate with AND-016/AND-398/AND-399.
- **Domain model field mapping** (citation 20): whether AND-398 exposes
  `endpoint_id` as `id`, models `WebhookEvent`, and whether AND-399 derives a
  KPI/series shape from the raw per-metric responses are upstream decisions; the
  VM contract here assumes a domain `Webhook` with a stable id and an
  `AnalyticsDashboard` aggregate, but the exact field names are unverifiable
  until those tickets land.
- **Client-side URL validation policy** (citation 19): no source mandates it;
  kept as an Android UX choice. Must remain lenient to avoid rejecting
  server-acceptable URLs.
- **Offline/stale + bounded-backoff retry** semantics: Android-specific, owned
  by core-network (AND-016); not present in web sources.

## 17. Test Plan

All cases are JVM/Robolectric unit tests unless noted; these ViewModels have no
Composables (the "State." scope), so device/emulator UI runs are out of scope
for AND-401 itself and are flagged where a downstream/integration check would
need them (those belong to AND-402). Fakes (`FakeWebhooksRepository`,
`FakeAnalyticsRepository`) and a `StandardTestDispatcher` back every case.

Test targets used:
- **JVM unit/Robolectric** (local, no device) — all VM/reducer/validator cases.
- **Headless emulator AVD `test35`** (API 35) — noted only for the optional
  cross-VM integration smoke that a downstream ticket might run in CI.
- **Physical device (Samsung Galaxy A15 5G, SM-A156U, API 34)** — not required
  for any AND-401 case (no camera/biometrics/FCM/WebRTC/Telecom/streaming here);
  explicitly called out as N/A so reviewers don't expect hardware runs.

- **TC-AND-401-01** — Webhooks list happy path.
  Type: unit. Target: JVM (`WebhooksListViewModel` + `FakeWebhooksRepository`).
  Preconditions: fake scripted to return `ApiResult.Success(listOf(webhookA, webhookB))`.
  Steps: construct VM (auto-`init` load); `advanceUntilIdle`; collect `uiState`
  via Turbine. Expected: first emitted `phase=Loading`, then `phase=Content`
  with `items.size==2`, `isStale==false`, `isRefreshing==false`, `error==null`.
  Traces: AC-1, AC-2.

- **TC-AND-401-02** — Webhooks list empty result.
  Type: unit. Target: JVM. Preconditions: fake returns `Success(emptyList())`.
  Steps: init; `advanceUntilIdle`. Expected: terminal `phase=Empty`,
  `canRetry==true`, no `ShowMessage` effect. Traces: AC-1, AC-2.

- **TC-AND-401-03** — Cached/offline read yields stale content + ShowMessage
  (flaky-dev-host/offline path). Type: unit. Target: JVM.
  Preconditions: fake returns `ApiResult.Cached(listOf(webhookA))` (simulating
  cache-fallback after dev-host timeout). Steps: init; `advanceUntilIdle`;
  collect `uiState` and `effects`. Expected: `phase=Content`, `isStale==true`,
  `isOffline==true`, `items.size==1`; exactly one `WebhooksListEffect.ShowMessage`
  with `R.string.offline_showing_saved`. Traces: AC-4. (Depends on Open
  Assumption: `ApiResult.Cached` exists — see §16.)

- **TC-AND-401-04** — Network error with no prior content.
  Type: unit. Target: JVM. Preconditions: fake returns
  `ApiResult.Error(IOException, httpCode=null)`. Steps: init; `advanceUntilIdle`.
  Expected: `phase=Error`, `error is WebhooksError.Network` with `retryable==true`,
  `canRetry==true`, `items` empty. Traces: AC-1, AC-2.

- **TC-AND-401-05** — Pull-to-refresh keeps content; failure marks stale +
  ShowMessage (offline path over existing content). Type: unit. Target: JVM.
  Preconditions: first call `Success([webhookA])`; second call (forceRefresh)
  `Error(IOException)`. Steps: init → `advanceUntilIdle` (Content); `onRefresh()`;
  assert mid-flight `isRefreshing==true` with content still visible;
  `advanceUntilIdle`. Expected: after failure `phase` stays `Content`,
  `items` unchanged, `isStale==true`, `isRefreshing==false`, one `ShowMessage`.
  Traces: AC-3, AC-4.

- **TC-AND-401-06** — Concurrent refresh de-duplication (in-flight guard).
  Type: unit. Target: JVM. Preconditions: fake with a suspendable/delayed
  `getWebhooks` and a call counter. Steps: init load in flight; call `onRefresh()`
  twice before completion; `advanceUntilIdle`. Expected: `FakeWebhooksRepository.getWebhooks`
  invoked **exactly once for the contended window** (call-count assertion ==1 for
  the concurrent burst). Traces: AC-3.

- **TC-AND-401-07** — Unauthorized → SessionExpired + RequireReauth (security).
  Type: unit. Target: JVM. Preconditions: fake returns `ApiResult.Unauthorized`
  (after core-network's single refresh already failed). Steps: init;
  `advanceUntilIdle`; collect state + effects. Expected: `phase=Error`,
  `error == WebhooksError.SessionExpired` with `canRetry==false`; exactly one
  `WebhooksListEffect.RequireReauth`; cached content (if any) preserved per R4.
  Traces: AC-4.

- **TC-AND-401-08** — Retry from Error re-enters Loading then resolves.
  Type: unit. Target: JVM. Preconditions: first call `Error`, second call
  `Success([webhookA])`. Steps: init → Error; `onRetry()`; assert transient
  `phase=Loading`; `advanceUntilIdle`. Expected: terminal `phase=Content`,
  `error==null`. Traces: AC-1, AC-3.

- **TC-AND-401-09** — Create client-side validation, no network call (security:
  no traffic on invalid input). Type: unit. Target: JVM
  (`WebhookCreateViewModel`). Preconditions: default state (blank url, no events).
  Steps: call `onSubmit()`. Expected: `fieldErrors[Url]==Blank` and
  `fieldErrors[Events]==NoEventsSelected`; `submission==Idle`;
  `FakeWebhooksRepository.createWebhook` call-count==0. Also assert a malformed
  url (`"notaurl"`) → `MalformedUrl`. Traces: AC-5.

- **TC-AND-401-10** — Create happy path → Submitting → Submitted + Created effect,
  with correct request mapping (contract). Type: unit (+ optional
  contract/MockWebServer in AND-402). Target: JVM. Preconditions: valid
  `url="https://example.com/hook"`, `events={session.started}`; fake returns
  `Success(webhook(endpoint_id="wh_1"))`. Steps: set fields; `onSubmit()`;
  observe transient `submission==Submitting`; `advanceUntilIdle`. Expected:
  `submission==Submitted("wh_1")`; one `WebhookCreateEffect.Created("wh_1")`;
  the captured `WebhookCreateRequest` has `event_types==["session.started"]`,
  `description==""`, and **no** `events`/`active` keys (verifies §5/§16
  corrections via `toRequest()`). Traces: AC-5, AC-2.

- **TC-AND-401-11** — Double-submit guard issues a single create call (security:
  no duplicate non-idempotent POST). Type: unit. Target: JVM.
  Preconditions: valid state; fake `createWebhook` delayed. Steps: `onSubmit()`
  then immediately `onSubmit()` again while `Submitting`; `advanceUntilIdle`.
  Expected: `createWebhook` call-count==1; final `submission==Submitted`.
  Traces: AC-5.

- **TC-AND-401-12** — Create server 422 → Validation; 401 → RequireReauth.
  Type: unit (real error shapes). Target: JVM. Preconditions: (a) fake returns
  `ApiResult.Error(httpCode=422, message=<mapped HTTPValidationError detail>)`;
  (b) separate run returns `ApiResult.Unauthorized`. Steps: valid submit in each.
  Expected: (a) `submission==Error(WebhooksError.Validation(msg))`, no auto-retry,
  `createWebhook` call-count==1 (never retried); (b)
  `submission==Error(SessionExpired)` + one `RequireReauth` effect. Traces:
  AC-5, AC-4.

- **TC-AND-401-13** — Analytics init loads default range; `onRangeChange`
  re-queries with the correct date window over existing content. Type: unit.
  Target: JVM (`AnalyticsViewModel` + `FakeAnalyticsRepository`, injected fixed
  `today=2026-06-05`). Preconditions: fake returns `Success(dashboardA)`.
  Steps: init (default `LAST_30D`) → `advanceUntilIdle` (Content); call
  `onRangeChange(LAST_7D)`; assert `isRefreshing==true` over existing content (not
  full Loading); `advanceUntilIdle`. Expected: `range==LAST_7D`; the captured repo
  call used `fromDate=="2026-05-29"`, `toDate=="2026-06-05"` (7-day window — pins
  the §4.3 correction); content replaced. Traces: AC-2.

- **TC-AND-401-14** — Pure-function tests: `validate`, `toContentOrEmpty`,
  `toError`, `mapError`, `AnalyticsRange.window`. Type: unit (dispatcher-free).
  Target: JVM. Preconditions: none. Steps: call each pure fn with representative
  inputs. Expected: `validate` returns the right `WebhookFieldError` map;
  `toContentOrEmpty(emptyList)`→Empty, `(nonEmpty)`→Content; `mapError` maps
  `httpCode` 5xx→Server, IO→Network, 422→Validation, else→Unknown, 401 not
  reachable here (handled as Unauthorized upstream); `LAST_90D.window(2026-06-05)`
  ==`("2026-03-07","2026-06-05")`. Traces: AC-1, AC-7.

- **TC-AND-401-15** — No-PII logging / @StringRes-only messages (security &
  privacy). Type: unit (Robolectric for `@StringRes` resolution + a Timber test
  tree capturing logs). Target: JVM/Robolectric. Preconditions: install a
  capturing Timber tree; submit a create with a secret-bearing url
  (`https://h.example/x?token=SECRET`) that then fails. Steps: run create-error
  and list-error flows. Expected: no captured log line contains the url, the
  token, `event_types` values, or any analytics figure; every emitted
  `ShowMessage` carries an `Int` `@StringRes` id (no string literals). Traces:
  AC-7, AC-6.

### Coverage matrix

| AC   | Covered by |
|------|------------|
| AC-1 | TC-01, TC-02, TC-04, TC-08, TC-14 |
| AC-2 | TC-01, TC-02, TC-04, TC-10, TC-13 |
| AC-3 | TC-05, TC-06, TC-08 |
| AC-4 | TC-03, TC-05, TC-07, TC-12 |
| AC-5 | TC-09, TC-10, TC-11, TC-12 |
| AC-6 | TC-15 (and entire suite uses only repository fakes — no HTTP/Room/DataStore) |
| AC-7 | TC-14, TC-15 |
