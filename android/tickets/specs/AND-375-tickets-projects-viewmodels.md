---
id: AND-375
title: Tickets/projects ViewModels
milestone: M8
epic: E48
priority: P2
size: M
depends_on: [AND-371]
blocks: [AND-372, AND-373, AND-374]
status: reviewed
reviewed_on: 2026-06-06
---

# AND-375 — Tickets/projects ViewModels

## 1. Overview & Goal

This ticket implements the presentation/state layer for the ticket-spaces and
projects feature area of the TestLogon native Android app. It delivers a set of
Hilt-injected `ViewModel`s — `TicketSpacesViewModel`, `TicketListViewModel`,
`TicketThreadViewModel`, `ProjectListViewModel`, and `ProjectDetailViewModel` —
each exposing a single `StateFlow<UiState>` plus one-shot side effects, and each
orchestrating the repositories/APIs delivered by AND-371 (Tickets API) and
AND-374 (Projects API).

The scope, per the backlog, is **State** only: no Composables, no navigation
graph, no networking code beyond consuming the already-built `TicketsApi`/
`ProjectsApi` and their DTO→domain mappers. The deliverable is a set of
deterministic, fully unit-tested state machines that map `ApiResult<T>` into
discrete render-ready states (loading, content, empty, error, offline-stale,
paging-append states) and translate user intents (open space, open ticket,
refresh, retry, load-next-page, open project, open project detail) into state
transitions and effects.

The dev backend (`http://18.222.237.167:8000`) is plaintext HTTP and unreliable,
so each state model must first-class slow loads (~20s timeout), transient
failures, and stale-from-cache content. Success is measured by: (a) every
modeled transition for every ViewModel is reachable and covered by a unit test
using fakes and a `TestDispatcher` (the backlog acceptance: "Unit-tested"); and
(b) the public state surfaces are stable enough for the UI tickets AND-372
(spaces/tickets/thread rendering), AND-373 (reply/members), and AND-374's detail
screen to bind without churn.

## 2. Context & References

- **Module:** `feature-tickets` (and, if projects are split, `feature-projects`;
  this spec assumes a single `feature-tickets` module hosting both, with package
  roots `com.testlogon.android.feature.tickets` and
  `com.testlogon.android.feature.tickets.projects`). Depends on `core-data`,
  `core-model`, `core-network`, `core-ui`, `core-testing`.
- **Upstream AND-371 (Tickets API):** provides `TicketsApi`, `tickets.ts`-mirrored
  DTOs for ticket-spaces, members and messages, and DTO→domain mappers producing
  `TicketSpace`, `Ticket`, `TicketMessage`, `TicketMember` in
  `com.testlogon.android.core.model`. This ticket consumes the resulting
  repository/API interfaces only. **Hard dependency.**
- **Upstream AND-374 (Projects):** provides `ProjectsApi` (`projects.ts`
  list/detail plus Google Drive provider start/callback) and `Project`,
  `ProjectDetail` domain models. AND-374 declares `Deps: AND-027`, parallel to
  AND-371; this ViewModel ticket therefore also soft-depends on AND-374's data
  layer for the projects ViewModels. If AND-374's data layer is not yet merged,
  the projects ViewModels bind to a thin repository interface stubbed in
  `core-testing` (see Risks R1).
- **Downstream AND-372:** spaces list, ticket list, ticket thread Composables
  bind to `TicketSpacesUiState`, `TicketListUiState`, `TicketThreadUiState`.
- **Downstream AND-373:** reply/members UI consumes `TicketThreadViewModel`'s
  reply intent and members state; this ticket exposes the reply/compose state and
  effects AND-373 drives.
- **Web reference:** `frontend/src/api/endpoints/tickets.ts`,
  `frontend/src/api/endpoints/projects.ts`, and `frontend/src/api/types.ts`
  define the payload shapes the AND-371/AND-374 domain models mirror. Web has no
  offline/stale concept; that is Android-specific.
- **Shared conventions:** ViewModels expose `StateFlow<UiState>`; the typed
  `ApiResult<T>` lives in `core-network`. **[Corrected]** The ticket/project
  endpoints document their non-2xx bodies as `ErrorEnvelope { error: { code,
  message, details? } }` (schema `ErrorEnvelope`/`ErrorDetail`), not the bare
  FastAPI `detail` union. The shared web client additionally tolerates a legacy
  `detail` field (`string | [{msg}] | {code,...}`) for endpoints that still use
  it, but for AND-375's surface the `core-network` mapper should read
  `error.code`/`error.message` from `ErrorEnvelope` (falling back to `detail` and
  then `statusText`). Auth is cookie-based and fully owned by `core-network`
  (cookie jar, `X-CSRF-Token` taken from the `ui_csrf` cookie, single
  `/ui/session/refresh` POST retry on 401 — all verified against
  `src/api/client.ts`); these ViewModels react to an `Unauthorized` `ApiResult`
  with a re-auth effect.

## 3. Functional Requirements

FR-1. **Spaces list.** `TicketSpacesViewModel` loads the caller's ticket spaces
on init, emitting `Loading` then a terminal state. Exposes
`val uiState: StateFlow<TicketSpacesUiState>`. Intents: `onRefresh()`,
`onRetry()`, `onSpaceClicked(spaceId)` (emits a `NavigateToTickets(spaceId)`
effect; the VM does not navigate).

FR-2. **Ticket list (per space).** `TicketListViewModel` is constructed with a
`spaceId` (via `SavedStateHandle`) and loads the tickets in that space, with
**Paging 3** support for long lists. Exposes
`val tickets: Flow<PagingData<TicketListItem>>` plus a small
`val uiState: StateFlow<TicketListUiState>` for screen-level state (header,
space metadata, full-screen error/empty before first page). Intents:
`onRefresh()`, `onRetry()`, `onTicketClicked(ticketId)` → `NavigateToThread`
effect, optional `onFilterChanged(status)`.

FR-3. **Ticket thread.** `TicketThreadViewModel` is constructed with **both a
`spaceId` and a `ticketId`** (the detail endpoint is
`GET /ticket-spaces/{spaceId}/tickets/{ticketId}`, not a flat ticket route — both
ids are required `SavedStateHandle` args). It loads the ticket header + messages
and exposes `val uiState: StateFlow<TicketThreadUiState>`. **[Corrected]** The
backend returns `SpaceTicketOut.messages` as an INLINE array inside the single
ticket payload (no per-message `next_cursor`), so messages are NOT independently
paged from this endpoint; the `Flow<PagingData<TicketMessage>>` surface is
retained as an OPTIONAL convenience only if AND-371 chooses to expose a client-
side `PagingData` wrapper, otherwise messages live as a plain
`List<TicketMessage>` field in `TicketThreadUiState`. Members are NOT part of the
ticket payload; they come from the space (`TicketSpaceOut.members`), so the VM
either reuses an already-loaded space or issues
`GET /ticket-spaces/{spaceId}` for member data.
It owns the **reply compose state** consumed by AND-373: `replyDraft`,
`isSending`, `canSend`. Intents: `onReplyDraftChanged(text)`,
`onSendReply()`, `onRetrySend()`, `onRefresh()`, `onRetry()`. (Posting the reply
HTTP call is AND-373's wiring; this ticket defines the intent surface and state
transitions and calls the repository method AND-373 implements; until then it
calls a `TicketRepository.postMessage` stub — see R1.)

FR-4. **Projects list.** `ProjectListViewModel` loads projects on init (paged or
single-shot per `projects.ts`; default single-shot list with optional paging).
Exposes `val uiState: StateFlow<ProjectListUiState>`. Intents: `onRefresh()`,
`onRetry()`, `onProjectClicked(projectId)` → `NavigateToProject` effect.

FR-5. **Project detail.** `ProjectDetailViewModel` is constructed with a
`projectId`, loads `ProjectDetail`, and exposes `val uiState:
StateFlow<ProjectDetailUiState>`. It also exposes the **Google Drive provider
connect** intent surface (`onConnectDrive()` → starts provider auth via
`POST /v1/projects/providers/google_drive/oauth/start`, surfaces an
`OpenUrl(authorization_url)` effect from the `ProviderOAuthStartOut` response; the
callback resolution is AND-374's concern, but the VM models `driveStatus:
DriveConnectState`). Intents: `onRefresh()`, `onRetry()`, `onConnectDrive()`.
**[Assumption — see R7]** the web client uses provider *credential* endpoints
rather than this OAuth-start flow, so the connect UX is unverified against web.

FR-6. **Common state variants.** Each list/detail `UiState` represents:
`Loading`, `Content`, `Empty`, `Error(error, canRetry)`, and a stale flag
(`isStale=true` when served from cache while offline / refresh failed) and a
`isRefreshing` flag for background refresh over visible content.

FR-7. **Refresh de-duplication.** Concurrent refresh/load requests collapse to a
single in-flight repository call per ViewModel (job guard).

FR-8. **Unauthorized.** On `ApiResult.Unauthorized` after `core-network`'s single
`/ui/session/refresh` retry has failed, each ViewModel emits a `RequireReauth`
one-shot effect and moves to `Error(SessionExpired, canRetry=false)` (lists) or
keeps last content behind the prompt (detail), per R3.

FR-9. **Slow loads.** Loads honor the ~20s OkHttp timeout; the ViewModel imposes
no shorter deadline but must surface the resulting `Error`/stale state cleanly
and never hang `Loading` indefinitely (resolved by the network timeout).

FR-10. **Config-change survival.** State survives rotation (ViewModel scope);
present content is not reloaded on rotation. Paging flows are `cachedIn(
viewModelScope)`.

## 4. Technical Design

Package root: `com.testlogon.android.feature.tickets[.projects]`.

### 4.1 Shared UI state shape

A single immutable data class per screen (not a sealed hierarchy) so content
fields persist across refresh transitions. Example for spaces:

```kotlin
data class TicketSpacesUiState(
    val phase: Phase = Phase.Loading,
    val spaces: List<TicketSpace> = emptyList(),   // core-model (AND-371)
    val isRefreshing: Boolean = false,
    val isStale: Boolean = false,                  // served from cache (offline)
    val error: TicketsError? = null,
) {
    enum class Phase { Loading, Content, Empty, Error }
    val isOffline: Boolean get() = isStale && spaces.isNotEmpty()
    val canRetry: Boolean get() = phase == Phase.Error || phase == Phase.Empty
}
```

`TicketThreadUiState`, `ProjectListUiState`, `ProjectDetailUiState` follow the
same `phase + content + isRefreshing + isStale + error` template. The thread
state additionally carries reply/compose fields:

```kotlin
data class TicketThreadUiState(
    val phase: Phase = Phase.Loading,
    val ticket: Ticket? = null,                    // header (AND-371)
    val members: List<TicketMember> = emptyList(),
    val replyDraft: String = "",
    val isSending: Boolean = false,
    val sendError: TicketsError? = null,
    val isRefreshing: Boolean = false,
    val isStale: Boolean = false,
    val error: TicketsError? = null,
) {
    enum class Phase { Loading, Content, Empty, Error }
    val canSend: Boolean get() = replyDraft.isNotBlank() && !isSending
}
```

```kotlin
data class ProjectDetailUiState(
    val phase: Phase = Phase.Loading,
    val project: ProjectDetail? = null,            // core-model (AND-374)
    val driveStatus: DriveConnectState = DriveConnectState.Unknown,
    val isRefreshing: Boolean = false,
    val isStale: Boolean = false,
    val error: TicketsError? = null,
) { enum class Phase { Loading, Content, Empty, Error } }

sealed interface DriveConnectState {
    data object Unknown : DriveConnectState
    data object Disconnected : DriveConnectState
    data object Connecting : DriveConnectState   // auth URL launched, awaiting callback
    data object Connected : DriveConnectState
}
```

### 4.2 Shared error model

```kotlin
sealed interface TicketsError {
    val retryable: Boolean
    data class Network(val message: String) : TicketsError { override val retryable = true }
    data class Server(val code: Int, val message: String) : TicketsError { override val retryable = true }
    data object SessionExpired : TicketsError { override val retryable = false }
    data class Unknown(val message: String) : TicketsError { override val retryable = true }
}
```

`core-network`'s error mapper produces `ApiResult.Error(throwable, httpCode?,
message)`; a single internal `ApiResult.Error.toTicketsError()` maps IO/timeout →
`Network`, 5xx → `Server`, other → `Unknown`. 401 surfaces as
`ApiResult.Unauthorized`, not `Error`.

### 4.3 Side effects (one-shot)

```kotlin
sealed interface TicketsEffect {
    data object RequireReauth : TicketsEffect
    data class ShowMessage(@StringRes val resId: Int) : TicketsEffect
    data class NavigateToTickets(val spaceId: String) : TicketsEffect
    data class NavigateToThread(val ticketId: String) : TicketsEffect
    data class NavigateToProject(val projectId: String) : TicketsEffect
    data class OpenUrl(val url: String) : TicketsEffect            // Drive provider auth
}
```

Exposed as `val effects: Flow<TicketsEffect>` backed by a
`Channel(Channel.BUFFERED)` consumed via `LaunchedEffect`/`collect`. Effects are
intentionally not part of `StateFlow` to avoid replay-on-rotation.

### 4.4 ViewModel skeleton (spaces shown; others analogous)

```kotlin
@HiltViewModel
class TicketSpacesViewModel @Inject constructor(
    private val repository: TicketRepository,            // AND-371
    @Dispatcher(IO) private val io: CoroutineDispatcher,
) : ViewModel() {

    private val _uiState = MutableStateFlow(TicketSpacesUiState())
    val uiState: StateFlow<TicketSpacesUiState> = _uiState.asStateFlow()

    private val _effects = Channel<TicketsEffect>(Channel.BUFFERED)
    val effects: Flow<TicketsEffect> = _effects.receiveAsFlow()

    private var loadJob: Job? = null

    init { load(fromUser = false) }

    fun onRefresh() = load(fromUser = true)
    fun onRetry() = load(fromUser = true)
    fun onSpaceClicked(id: String) {
        viewModelScope.launch { _effects.send(TicketsEffect.NavigateToTickets(id)) }
    }

    private fun load(fromUser: Boolean) {
        if (loadJob?.isActive == true) return            // FR-7 de-dup
        loadJob = viewModelScope.launch(io) {
            _uiState.update { it.startLoad() }
            when (val r = repository.getSpaces(forceRefresh = fromUser)) {
                is ApiResult.Success      -> _uiState.update { it.toContentOrEmpty(r.data, stale = false) }
                is ApiResult.Cached       -> { _uiState.update { it.toContentOrEmpty(r.data, stale = true) }
                                               _effects.send(ShowMessage(R.string.tickets_showing_saved)) }
                is ApiResult.Unauthorized -> { _effects.send(RequireReauth); _uiState.update { it.toError(SessionExpired) } }
                is ApiResult.Error        -> reduceFailure(r)
            }
        }
    }
}
```

`startLoad()`, `toContentOrEmpty()`, `toError()` are **pure private extension
functions** (the reducer) on each `UiState`, making transitions dispatcher-free
and trivially unit-testable. `reduceFailure` chooses `Error` (no cached content)
vs stale `Content` + `ShowMessage` (cached content present).

### 4.5 Paging ViewModels (ticket list, thread messages)

For `TicketListViewModel` and `TicketThreadViewModel` message lists, the paged
flow is derived from `Pager` built on the `core-network`/AND-371 `PagingSource`
(or `RemoteMediator` when Room cache backs it):

```kotlin
private val spaceId: String = checkNotNull(savedStateHandle["spaceId"])

val tickets: Flow<PagingData<TicketListItem>> =
    repository.ticketsPager(spaceId)          // Pager(config).flow from AND-371
        .map { it.map(TicketListItem::from) }
        .cachedIn(viewModelScope)
```

Screen-level `uiState` (header, space metadata, first-load error/empty) is a
separate `StateFlow` driven by a one-shot header fetch; per-page append/refresh
errors are surfaced through Paging's `LoadState` (handled by AND-372's UI), not
this `StateFlow`. The VM still exposes `onRefresh()` which calls a stored
`refresh()` trampoline (set by the screen's `LazyPagingItems`) or simply
re-fetches the header and lets the UI call `lazyItems.refresh()`.

### 4.6 Reply intent (thread)

```kotlin
fun onReplyDraftChanged(text: String) =
    _uiState.update { it.copy(replyDraft = text, sendError = null) }

fun onSendReply() {
    val draft = _uiState.value.replyDraft
    if (draft.isBlank() || _uiState.value.isSending) return
    viewModelScope.launch(io) {
        _uiState.update { it.copy(isSending = true) }
        // POST /ticket-spaces/{spaceId}/tickets/{ticketId}/messages — needs spaceId too
        when (val r = repository.postMessage(spaceId, ticketId, draft)) {   // AND-373 impl
            is ApiResult.Success      -> { _uiState.update { it.copy(isSending = false, replyDraft = "") }
                                           /* AND-372/373 UI triggers messages.refresh() */ }
            is ApiResult.Unauthorized -> { _effects.send(RequireReauth)
                                           _uiState.update { it.copy(isSending = false, sendError = SessionExpired) } }
            is ApiResult.Error        -> _uiState.update { it.copy(isSending = false, sendError = r.toTicketsError()) }
            is ApiResult.Cached       -> Unit  // POST is never served from cache
        }
    }
}
```

### 4.7 Hilt wiring

All five are `@HiltViewModel`. No new module is required: repositories are bound
by AND-371/AND-374 modules; `@Dispatcher(IO)` is provided by `core-data`;
`SavedStateHandle` is injected by Hilt for the arg-carrying VMs.

## 5. API Contract

This ticket introduces **no new network calls**. All HTTP and DTO mapping are
owned by AND-371 (`TicketsApi`) and AND-374 (`ProjectsApi`), mirrored from
`frontend/src/api/endpoints/tickets.ts` and `projects.ts`. The reply POST is
wired by AND-373. For reference, the upstream payloads the consumed domain models
derive from are shaped roughly as:

**[Corrected — verified against OpenAPI index + `src/api/endpoints/tickets.ts`,
`projects.ts`.]** The earlier draft prefixed every path with `/ui/` and invented
a flat `/ui/tickets/{ticketId}`; the real contract is:

```json
// GET /ticket-spaces  (params: cursor,limit)  -> TicketSpaceListEnvelope
{ "items": [ { "space_id": "sp_123", "name": "Support", "owner_sub": "u_x",
               "visibility": "shared", "created_at": 1749124800,
               "updated_at": 1749124800,
               "members": [ { /* SpaceMemberOut */ } ] } ], "next_cursor": null }
// NOTE: no `ticket_count` field; ids are `space_id`; timestamps are integer
// (epoch seconds), NOT ISO strings; the space owns its `members`.

// GET /ticket-spaces/{spaceId}/tickets  (params: status,assignee_sub,cursor,limit)
//   -> SpaceTicketListEnvelope { items: SpaceTicketOut[], next_cursor? }
//   ticket id is `ticket_id`; status enum =
//   open|in_progress|waiting_on_user|done|reopened

// GET /ticket-spaces/{spaceId}/tickets/{ticketId}  -> SpaceTicketEnvelope
//   { "ticket": SpaceTicketOut }
//   SpaceTicketOut carries `messages: SpaceTicketMessage[]` INLINE (no nested
//   paging object, no `next_cursor` for messages) plus `activity[]`. Each
//   message: { message_id, sender_sub, sender_role, body, created_at(int),
//   email_alert_queued_for[] }. The ticket has NO `members` array — members come
//   from the space (TicketSpaceOut.members / SpaceMemberOut).

// POST /ticket-spaces/{spaceId}/tickets/{ticketId}/messages  (AND-373)
//   req SpaceTicketMessageReq { body: string (minLength 1, maxLength 4000) }
//   -> SpaceTicketEnvelope (the updated ticket, messages included)

// GET /v1/projects  (params: limit,cursor,tag,name_query)  -> ProjectListOut
// GET /v1/projects/{projectId}/detail  (params: limit,cursor,status,provider)
//   -> ProjectDetailOut { project: ProjectOut, files: TrackedFileOut[], cursor? }
// POST /v1/projects/providers/google_drive/oauth/start -> ProviderOAuthStartOut
//   { provider, authorization_url, state, expires_at }   // field is
//   `authorization_url`, NOT `auth_url`; method is POST not GET; the endpoint is
//   NOT project-scoped; provider segment is `google_drive` (underscore).
// POST /v1/projects/providers/google_drive/oauth/callback (req ProviderOAuthCallbackIn)
```

**Drive caveat (unverified for the web flow):** the web `projects.ts` does NOT
call `oauth/start`; its provider UI uses the credential endpoints
(`GET/PUT/DELETE /v1/projects/providers/{provider}/credentials`). The
`oauth/start`→`OpenUrl(authorization_url)` flow this VM models exists in the
backend OpenAPI but has no web precedent; treat the connect-via-OAuth UX as an
Android-specific assumption to confirm with AND-374 (see R7).

The ViewModels consume already-mapped domain objects, not this JSON. Error
normalization (`ErrorEnvelope.error.{code,message}`, with legacy `detail`
fallback) is performed by the `core-network` mapper before reaching the
repository; this ticket only maps `ApiResult.Error` → `TicketsError` and treats
401 as `Unauthorized`.

## 6. Data & State Management

- **Single source of truth per VM:** a private `MutableStateFlow<…UiState>`
  exposed read-only via `asStateFlow()`. Hot, owned by the VM; no
  `stateIn`/sharing config needed.
- **Paging:** `tickets`/`messages` are `Flow<PagingData<…>>` `cachedIn(
  viewModelScope)`; refresh/append `LoadState` is owned by Paging, not the
  scalar `StateFlow`.
- **No DataStore/Room access here.** Caching and the `ApiResult.Cached` signal
  are the repository's concern; this layer only reads the `Cached` flag to set
  `isStale`.
- **Representative transition table (lists):**

  | From            | Event              | To                                    |
  |-----------------|--------------------|---------------------------------------|
  | Loading         | Success(non-empty) | Content(stale=false)                  |
  | Loading         | Success(empty)     | Empty                                 |
  | Loading         | Cached(non-empty)  | Content(stale=true) + ShowMessage     |
  | Loading         | Error              | Error                                 |
  | Loading         | Unauthorized       | Error(SessionExpired) + RequireReauth |
  | Content         | onRefresh          | Content(isRefreshing=true)            |
  | Content+refresh | Success            | Content(stale=false, refreshing=false)|
  | Content+refresh | Error              | Content(stale=true) + ShowMessage     |
  | Empty/Error     | onRetry            | Loading                               |

- **Thread reply transitions:** `Idle → (draft non-blank) canSend=true →
  onSendReply → isSending=true → Success(draft cleared) | Error(sendError set)`.
  `onReplyDraftChanged` clears any prior `sendError`.
- **Drive connect:** `Disconnected → onConnectDrive → Connecting +
  OpenUrl(authorization_url) → (callback handled by AND-374) → Connected`. The VM
  moves to `Connecting` only after the start call returns a non-empty
  `authorization_url` (field name `authorization_url`, per `ProviderOAuthStartOut`).

## 7. Error Handling & Resilience

- Network/timeout against the unreliable dev host → `TicketsError.Network`;
  prefer stale `Content` over `Error` when cached content exists.
- 5xx → `TicketsError.Server(code, message)`, retryable.
- 401 after `core-network`'s single `/ui/session/refresh` retry has failed →
  `Unauthorized` → `SessionExpired` + `RequireReauth`.
- Bounded backoff for idempotent `GET`s is owned by `core-network`/AND-016; these
  ViewModels perform no retry loop beyond user-initiated `onRetry`/`onRetrySend`.
- POST reply (`onSendReply`) is **not** retried automatically (non-idempotent);
  failure surfaces `sendError` and the user retries via `onRetrySend()`.
- Coroutine cancellation: each `loadJob` is superseded only via the in-flight
  guard; `CancellationException` is never converted to an error state.
- Paging append failures are surfaced via `LoadState.Error` for the UI to render a
  footer-retry; the scalar `StateFlow` stays in `Content`.
- Unexpected throwables in reducers are caught and mapped to
  `TicketsError.Unknown`.

## 8. Security & Privacy

- No credentials, tokens, or cookies are handled here; the cookie jar and CSRF
  header live in `core-network`. ViewModels must never log message bodies,
  subjects, member identifiers (`sender_sub`/`owner_sub`/`u_…`), project contents,
or Drive `authorization_url`s (which also carry an OAuth `state` secret).
- `RequireReauth` carries no sensitive payload; it only signals navigation to the
  auth flow.
- `OpenUrl(authUrl)` for the Google Drive provider is passed straight to the
  consumer for a Custom Tab launch; the VM does not persist or log it.
- No PII is placed in `TicketsError` messages beyond the server-supplied,
  already-sanitized `detail` text.
- Plaintext HTTP is a known dev-environment constraint owned by network config;
  not in scope here.

## 9. Accessibility & i18n

- This ticket produces **no Composables**, so it owns no `contentDescription`,
  focus order, or touch-target behavior; that is AND-372/AND-373/AND-374 UI.
- All user-facing strings are exposed as `@StringRes` ids — `ShowMessage(@StringRes
  resId: Int)` — never literals, keeping every ViewModel locale-agnostic and
  testable. `TicketsError` exposes semantic subtypes; the consumer maps them to
  localized strings.
- Status/role enums (`ticket.status`, `member.role`) are passed through as domain
  enums, not pre-localized text, so the UI can localize and pluralize
  (`ticket_count`).

## 10. Telemetry & Logging

- Log terminal state transitions at `Timber.d` with stable tags
  (`"TicketSpacesVM"`, `"TicketListVM"`, `"TicketThreadVM"`, `"ProjectListVM"`,
  `"ProjectDetailVM"`): load start, terminal phase, `isStale`, and error class
  name only — never payload contents.
- Emit one analytics event per terminal load via the `core-data` analytics
  facade if present: `tickets_loaded{screen, source=network|cache, empty,
  duration_ms}`, `ticket_reply_sent{ok}`, `project_detail_opened`,
  `drive_connect_started`. Gate behind an injected no-op `Analytics` interface so
  this ticket does not block on the facade.
- No verbose logging in release builds (Timber release tree is a no-op per app
  config).

## 11. Testing Strategy

Unit tests are the sole acceptance criterion ("Unit-tested"). Use JUnit4,
`kotlinx-coroutines-test` (`StandardTestDispatcher` + `runTest`), Turbine for
`StateFlow`/`Flow` assertions, and hand-written fakes in `core-testing`
(`FakeTicketRepository`, `FakeProjectRepository`) returning scripted `ApiResult`
values and a `PagingData` factory for the paged flows.

Per-ViewModel test classes and key cases:

`TicketSpacesViewModelTest`:
1. `init emits Loading then Content` (non-empty Success).
2. `Success empty → Empty`.
3. `Cached → Content isStale=true + ShowMessage effect`.
4. `Error no prior content → Error(canRetry=true)`.
5. `onRefresh over Content sets isRefreshing then clears on success`.
6. `onRefresh failure keeps Content, sets isStale, emits ShowMessage`.
7. `Unauthorized → Error(SessionExpired) + RequireReauth`.
8. `onRetry from Error re-enters Loading then resolves`.
9. `concurrent onRefresh collapses to one repository call` (call-count == 1).
10. `onSpaceClicked emits NavigateToTickets(id)`.

`TicketListViewModelTest`: reads `spaceId` from `SavedStateHandle`; asserts the
`PagingData` flow emits mapped `TicketListItem`s (via `AsyncPagingDataDiffer` or a
`PagingData` collector helper); header `uiState` Loading→Content/Empty/Error;
`onTicketClicked → NavigateToThread`.

`TicketThreadViewModelTest`: header+members load states; `onReplyDraftChanged`
toggles `canSend`; `onSendReply` success clears draft and flips `isSending`;
send failure sets `sendError` and keeps draft; `Unauthorized` on send →
`RequireReauth`; blank draft is a no-op.

`ProjectListViewModelTest`: mirror of spaces (load/empty/error/refresh/retry +
`onProjectClicked → NavigateToProject`).

`ProjectDetailViewModelTest`: detail load states; `onConnectDrive` returns
`auth_url` → `driveStatus=Connecting` + `OpenUrl` effect; start failure leaves
`Disconnected` + `ShowMessage`.

Reducer functions (`startLoad`, `toContentOrEmpty`, `toError`) get direct,
dispatcher-free tests pinning Section 6's table. Turbine pattern:

```kotlin
vm.uiState.test {
    assertEquals(Phase.Loading, awaitItem().phase)
    advanceUntilIdle()
    assertEquals(Phase.Content, awaitItem().phase)
    cancelAndIgnoreRemainingEvents()
}
```

Compose/UI tests are explicitly out of scope (owned by AND-372/AND-373/AND-374).

## 12. Dependencies & Sequencing

- **Depends on AND-371** (`TicketsApi`/`TicketRepository`, `TicketSpace`,
  `Ticket`, `TicketMessage`, `TicketMember`, mappers, `tickets`/`messages`
  pagers, `ApiResult` incl. `Cached`). Must merge first — **hard dependency**.
- **Soft-depends on AND-374** for `ProjectRepository`/`Project`/`ProjectDetail`
  and the Drive start endpoint; if not yet merged, projects ViewModels bind to a
  `core-testing` stub interface and ship behind their tests (R1).
- **Blocks/feeds AND-372** (spaces/ticket/thread UI binds to these states),
  **AND-373** (reply/members intent surface), and **AND-374**'s detail screen.
- Transitive: `core-network` (`ApiResult`, error mapper, Paging integration),
  `core-testing` (fakes, `MainDispatcherRule`/Turbine), `core-data`
  (`@Dispatcher(IO)`, optional analytics), Paging 3 runtime + `paging-testing`.
- Gradle: ensure `feature-tickets/build.gradle.kts` has `androidx.paging:paging-
  runtime`, `paging-common`, `paging-testing`, Turbine, and `coroutines-test`
  test deps (most inherited via `core-testing` conventions; add if missing).

## 13. Risks & Open Questions

- **R1 (must confirm):** AND-374's projects data layer (`ProjectRepository`,
  domain models, Drive start endpoint) may land after this ticket. Resolution:
  define the projects repository interface in `feature-tickets` and a fake in
  `core-testing`, so the projects ViewModels + tests are complete and only need
  the real binding at AND-374 merge. Likewise `TicketRepository.postMessage`
  (AND-373) is referenced before AND-373 wires it.
- **R2:** Does AND-371's `ApiResult` carry a `Cached` variant? If not, offline/
  stale (FR-6) cannot be distinguished from a fresh `Success`. Coordinate to add
  `ApiResult.Cached<T>` in `core-network`.
- **R3:** On `Unauthorized`, should detail VMs preserve last content behind the
  re-auth prompt while list VMs go to `Error`? Default: detail preserves, lists
  error. Revisit with auth-flow owner.
- **R4:** Message ordering / cursor direction for the thread (newest-first vs
  oldest-first) is defined by AND-371's pager; the VM is agnostic but the
  "scroll to newest after reply" behavior is AND-372/AND-373 UI.
- **R5:** Whether ticket list and projects are large enough to need Paging, or a
  single-shot list suffices. Default: Paging for tickets and thread messages;
  single-shot for spaces and projects unless `next_cursor` is present in the
  payloads.
- **R6:** Analytics facade availability — gated behind a no-op `Analytics`.
- **R7 (Drive connect contract):** The web `projects.ts` provider UI uses the
  credential endpoints (`GET/PUT/DELETE /v1/projects/providers/{provider}/
  credentials`), not the `POST /v1/projects/providers/google_drive/oauth/start`
  flow this VM's `onConnectDrive()` models. The OAuth-start endpoint and its
  `ProviderOAuthStartOut { authorization_url, state, expires_at }` response are
  real in the backend OpenAPI, but the connect-via-Custom-Tab UX is unverified
  against any web precedent. Confirm with AND-374 whether Android should drive the
  OAuth-start flow or the credential-upsert flow before finalizing
  `DriveConnectState`.

## 14. Acceptance Criteria

- AC-1 (from backlog): All modeled state transitions for all five ViewModels are
  unit-tested and the suites pass deterministically under `StandardTestDispatcher`.
- AC-2: Each ViewModel exposes exactly one `StateFlow<…UiState>` (plus paged
  `Flow<PagingData<…>>` where applicable) covering Loading, Content, Empty, Error
  phases plus `isStale`/`isRefreshing` flags.
- AC-3: `onRefresh()`/`onRetry()` exist on every list/detail VM; concurrent
  refreshes collapse to a single repository call (verified by call-count).
- AC-4: A `Cached`/offline result yields stale content (not an error) plus a
  `ShowMessage` effect; an `Unauthorized` result yields `SessionExpired` plus a
  `RequireReauth` effect.
- AC-5: `TicketThreadViewModel` exposes the reply compose surface
  (`replyDraft`, `canSend`, `isSending`, `sendError`, `onReplyDraftChanged`,
  `onSendReply`, `onRetrySend`) consumed by AND-373; blank draft is a no-op; send
  failure preserves the draft.
- AC-6: `ProjectDetailViewModel.onConnectDrive()` produces `DriveConnectState.
  Connecting` + `OpenUrl(authorization_url)` (the `ProviderOAuthStartOut.
  authorization_url` field) on a successful start.
- AC-7: No Composables, no direct HTTP, no Room/DataStore access are added; the
  ViewModels depend only on the AND-371/AND-374 repositories.
- AC-8: All user-facing messages are referenced by `@StringRes` id, not literals;
  no payload/PII logging.

## 15. Definition of Done

- `TicketSpacesViewModel`, `TicketListViewModel`, `TicketThreadViewModel`,
  `ProjectListViewModel`, `ProjectDetailViewModel` and their `…UiState`,
  `TicketsError`, `DriveConnectState`, and `TicketsEffect` types implemented in
  `com.testlogon.android.feature.tickets[.projects]` exactly as specified.
- Per-VM unit-test classes plus reducer tests written and green in CI; combined
  line coverage of the ViewModels + reducers ≥ 85%.
- Public state/effect surfaces reviewed and agreed with AND-372/AND-373/AND-374
  owners so downstream binding requires no changes.
- `./gradlew :feature-tickets:testDebugUnitTest ktlintCheck detekt` passes; no new
  lint/detekt suppressions added.
- No hard-coded user-facing strings; no message-body/PII/auth-URL logging.
- Code reviewed and merged to `android-port`; AND-372/AND-373/AND-374 unblocked.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer.

1. **Ticket spaces list endpoint is `GET /ticket-spaces` (no `/ui/` prefix),
   returning `TicketSpaceListEnvelope { items[], next_cursor? }`.** VERDICT:
   Corrected (draft said `GET /ui/ticket-spaces`). SOURCE: OpenAPI
   `GET /ticket-spaces` (op `list_ticket_spaces_ticket_spaces_get`,
   resp `200:TicketSpaceListEnvelope`); `src/api/endpoints/tickets.ts: listTicketSpaces`
   (`api.get("/ticket-spaces")`); schema `TicketSpaceListEnvelope`.
2. **A ticket space has fields `space_id, name, owner_sub, visibility,
   created_at(int), updated_at(int), members[]` — there is NO `ticket_count` and
   timestamps are integer epoch, not ISO strings.** VERDICT: Corrected (draft JSON
   used `id`, `ticket_count`, ISO `updated_at`). SOURCE: schema `TicketSpaceOut`
   (`components.schemas.TicketSpaceOut`).
3. **Tickets-in-space list is `GET /ticket-spaces/{spaceId}/tickets` (params
   `status, assignee_sub, cursor, limit`) → `SpaceTicketListEnvelope`.** VERDICT:
   Corrected (draft said `/ui/ticket-spaces/{spaceId}/tickets`). SOURCE: OpenAPI
   `GET /ticket-spaces/{space_id}/tickets` (op `list_space_tickets_…`);
   `src/api/endpoints/tickets.ts: listSpaceTickets`.
4. **Ticket detail is the nested `GET /ticket-spaces/{spaceId}/tickets/{ticketId}`
   → `SpaceTicketEnvelope { ticket }`; there is NO flat `/ui/tickets/{ticketId}`.
   The thread VM therefore needs both `spaceId` and `ticketId`.** VERDICT:
   Corrected. SOURCE: OpenAPI `GET /ticket-spaces/{space_id}/tickets/{ticket_id}`
   (op `get_space_ticket_…`); `src/api/endpoints/tickets.ts: getSpaceTicket`.
5. **The ticket payload embeds `messages: SpaceTicketMessage[]` INLINE (no nested
   paging / `next_cursor` for messages) and `activity[]`; it has NO `members`
   array.** VERDICT: Corrected (draft modeled paged messages + a per-ticket
   `members` array). SOURCE: schema `SpaceTicketOut` (required incl. `messages`,
   `activity`; no `members`).
6. **A message is `{ message_id, sender_sub, sender_role, body, created_at(int),
   email_alert_queued_for[] }` — not `{ id, author_u/u, role, created_at(ISO) }`.**
   VERDICT: Corrected. SOURCE: schema `SpaceTicketMessage`.
7. **Members belong to the space (`TicketSpaceOut.members: SpaceMemberOut[]`),
   reached via `GET /ticket-spaces/{spaceId}` or the spaces list.** VERDICT:
   Verified/Corrected (relocates the draft's per-ticket members). SOURCE: schema
   `TicketSpaceOut.members`; OpenAPI `GET /ticket-spaces/{space_id}`.
8. **Reply POST is `POST /ticket-spaces/{spaceId}/tickets/{ticketId}/messages`
   with body `SpaceTicketMessageReq { body: string, 1..4000 chars }` →
   `SpaceTicketEnvelope`.** VERDICT: Corrected (draft said
   `POST /ui/tickets/{ticketId}/messages`). SOURCE: OpenAPI
   `POST /ticket-spaces/{space_id}/tickets/{ticket_id}/messages`
   (req `SpaceTicketMessageReq`); `src/api/endpoints/tickets.ts: replyToTicket`
   (`api.post(..., { body })`); schema `SpaceTicketMessageReq` (minLength 1,
   maxLength 4000).
9. **Ticket status enum = `open | in_progress | waiting_on_user | done |
   reopened`.** VERDICT: Verified (draft only showed `open`; now enumerated).
   SOURCE: schema `SpaceTicketStatusReq.status.enum`.
10. **Projects list is `GET /v1/projects` (params `limit, cursor, tag,
    name_query`) → `ProjectListOut`.** VERDICT: Corrected (draft said
    `GET /ui/projects`). SOURCE: OpenAPI `GET /v1/projects` (op
    `list_projects_route_v1_projects_get`); `src/api/endpoints/projects.ts:
    listProjects`.
11. **Project detail is `GET /v1/projects/{projectId}/detail` →
    `ProjectDetailOut { project, files[], cursor? }`.** VERDICT: Corrected (draft
    said `GET /ui/projects/{projectId}`; the flat `GET /v1/projects/{id}` returns
    `ProjectOut`, but the detail screen uses `/detail`). SOURCE: OpenAPI
    `GET /v1/projects/{project_id}/detail`; `src/api/endpoints/projects.ts:
    getProjectDetail`; schema `ProjectDetailOut`.
12. **Drive provider OAuth start is `POST /v1/projects/providers/google_drive/
    oauth/start` → `ProviderOAuthStartOut { provider, authorization_url, state,
    expires_at }`. Method is POST (not GET); path is provider-level (not
    project-scoped); provider segment is `google_drive` (underscore); URL field is
    `authorization_url` (not `auth_url`).** VERDICT: Corrected. SOURCE: OpenAPI
    `POST /v1/projects/providers/google_drive/oauth/start` (op
    `start_google_drive_oauth_…`); schema `ProviderOAuthStartOut`.
13. **The web client's projects provider UI uses credential endpoints
    (`GET/PUT/DELETE /v1/projects/providers/{provider}/credentials`), NOT the
    `oauth/start` flow.** VERDICT: Verified (this is what makes the VM's
    OAuth-start connect UX an assumption — R7). SOURCE: `src/api/endpoints/
    projects.ts: getProviderCredential / upsertProviderCredential /
    deleteProviderCredential`; OpenAPI `.../providers/{provider}/credentials`.
14. **Auth is cookie-based: `credentials: include`, CSRF via `X-CSRF-Token`
    header sourced from the `ui_csrf` cookie, with a single
    `POST /ui/session/refresh` retry on 401.** VERDICT: Verified. SOURCE:
    `src/api/client.ts` (`refreshSession` → `fetch(withApiBase("/ui/session/
    refresh"))`; `getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`;
    `if (res.status === 401) … refreshPromise` single-flight).
15. **Documented error body for ticket/project endpoints is `ErrorEnvelope {
    error: ErrorDetail { code, message, details? } }`, not the bare FastAPI
    `detail` union; the web client also tolerates legacy `detail` (`string |
    [{msg}] | {code,...}`).** VERDICT: Corrected (draft attributed everything to
    FastAPI `detail`). SOURCE: schemas `ErrorEnvelope`, `ErrorDetail`; non-2xx
    `$ref: ErrorEnvelope` on the ticket-space routes (OpenAPI index resp lists);
    legacy handling in `src/api/client.ts: normalizeErrorDetail`.
16. **Validation failures return `422 HTTPValidationError`.** VERDICT: Verified.
    SOURCE: OpenAPI resp `422:HTTPValidationError` on the ticket-space/projects
    routes; schema `HTTPValidationError`.
17. **ViewModels add no networking/DTOs of their own; they consume AND-371/AND-374
    repositories.** VERDICT: Unverified-assumption (scope decision local to the
    Android port; no external source). SOURCE: ticket scope "State" only
    (`specs-src/AND-375.md`); no Android repo present to confirm AND-371/AND-374
    interfaces exist yet.
18. **Framework choices (Hilt `@HiltViewModel`, `StateFlow` + `Channel`
    one-shot effects, `SavedStateHandle` args, Paging 3 `cachedIn`, coroutine
    `TestDispatcher`).** VERDICT: Verified against Android docs (framework ref),
    not the backend. SOURCE (framework ref):
    https://developer.android.com/topic/libraries/architecture/viewmodel ,
    https://developer.android.com/topic/libraries/architecture/coroutines#viewmodelscope ,
    https://developer.android.com/topic/libraries/architecture/paging/v3-paging-data#convert-ui ,
    https://developer.android.com/kotlin/flow/stateflow-and-sharedflow ,
    https://developer.android.com/training/dependency-injection/hilt-jetpack#viewmodels ,
    https://kotlinlang.org/api/kotlinx.coroutines/kotlinx-coroutines-test/ .

### Corrections made

- §2, §5, §7-mapping: error contract changed from FastAPI `detail` union to
  `ErrorEnvelope.error.{code,message}` (legacy `detail` kept as fallback). (#15)
- §5 JSON block fully rewritten: removed the `/ui/` prefix from all ticket
  endpoints; replaced flat `/ui/tickets/{ticketId}` with the nested
  `/ticket-spaces/{spaceId}/tickets/{ticketId}`; fixed space fields (`space_id`,
  integer timestamps, removed `ticket_count`); fixed message fields (`message_id`,
  `sender_sub`, `sender_role`, integer `created_at`); made thread messages inline
  (not paged) and moved members to the space; corrected projects to `/v1/projects`
  and `/v1/projects/{id}/detail`; corrected Drive start to
  `POST /v1/projects/providers/google_drive/oauth/start` with `authorization_url`.
  (#1–#12)
- FR-3 (§3): thread VM now takes `spaceId` + `ticketId`; messages inline; members
  sourced from the space; `PagingData` for messages downgraded to optional. (#4,
  #5, #7)
- FR-5/§6/§8/AC-6: Drive `auth_url` → `authorization_url`; start is a POST. (#12)
- §4.6: `postMessage(spaceId, ticketId, draft)` now carries `spaceId`. (#8)
- Added R7 documenting the OAuth-start-vs-credentials discrepancy. (#13)

### Open assumptions

- **AND-371/AND-374 repository interfaces and an `ApiResult.Cached` variant exist
  as assumed (FR-6, R2).** Why unverifiable: no Android source tree is present in
  the references — only the backend OpenAPI and the web client. The offline/stale
  model and the repository method signatures are Android-port design, not
  confirmable from the given sources.
- **The Drive connect UX uses OAuth-start rather than credential upsert (R7,
  claim #13).** Why unverifiable: the backend exposes both, and the web client
  uses credentials; which one the Android detail screen should drive is an
  AND-374 product decision.
- **Whether `TicketRepository.ticketsPager` / message paging is client-side over
  inline data or server cursor-backed.** Why unverifiable: the tickets list does
  expose `next_cursor` (server paging is possible) but the ticket *detail*
  messages are inline; AND-371's pager design is not in the sources.
- **`@StringRes` / no-PII-logging / analytics-facade conventions.** Why
  unverifiable: project-internal conventions with no authoritative reference file.

## 17. Test Plan

All cases are JVM unit/Robolectric unless noted; this ticket's acceptance is
"Unit-tested" and it produces no Composables, so the bulk runs with no device.
Cases that touch a Compose host or instrumented behavior name the target
explicitly and note emulator vs physical device. Fakes: `FakeTicketRepository`,
`FakeProjectRepository`, `FakeSpaceRepository` (scripted `ApiResult`), a
`PagingData` factory, and `StandardTestDispatcher` + Turbine.

- **TC-AND-375-01 — Spaces happy path.** Type: unit (JVM). Target:
  `TicketSpacesViewModel`. Preconditions: `FakeTicketRepository.getSpaces` →
  `ApiResult.Success(listOf(space))`. Steps: construct VM; collect `uiState` with
  Turbine; `advanceUntilIdle()`. Expected: emits `Phase.Loading` then
  `Phase.Content` with the mapped space, `isStale=false`, `error=null`. Traces:
  AC-1, AC-2.
- **TC-AND-375-02 — Spaces empty.** Type: unit (JVM). Target:
  `TicketSpacesViewModel`. Preconditions: `getSpaces` → `Success(emptyList())`.
  Steps: construct; advance. Expected: terminal `Phase.Empty`, `canRetry=true`.
  Traces: AC-2.
- **TC-AND-375-03 — Cached/offline → stale content + ShowMessage.** Type: unit
  (JVM). Target: `TicketSpacesViewModel`. Preconditions: `getSpaces` →
  `ApiResult.Cached(listOf(space))`. Steps: construct; collect `uiState` and
  `effects`. Expected: `Phase.Content`, `isStale=true`, `isOffline=true`, and a
  `ShowMessage(R.string.tickets_showing_saved)` effect. Traces: AC-4. (Mirrors the
  flaky-dev-host/offline path.)
- **TC-AND-375-04 — Server error (ErrorEnvelope 5xx) → Error, retryable.** Type:
  contract/MockWebServer. Target: `TicketSpacesViewModel` over
  `TicketRepository` backed by MockWebServer. Preconditions: MockWebServer returns
  `500` with body `{"error":{"code":"internal","message":"boom"}}` for
  `GET /ticket-spaces`. Steps: drive a real `getSpaces`; advance. Expected:
  `ApiResult.Error` maps to `TicketsError.Server(500,"boom")`; `uiState`
  `Phase.Error`, `canRetry=true`; the mapper reads `error.message` (NOT the legacy
  `detail`). Traces: AC-2; validates claim #15.
- **TC-AND-375-05 — 422 validation on reply (body too long).** Type:
  contract/MockWebServer. Target: `TicketThreadViewModel.onSendReply`.
  Preconditions: draft of 4001 chars; MockWebServer returns `422
  HTTPValidationError` for
  `POST /ticket-spaces/{spaceId}/tickets/{ticketId}/messages`. Steps: set draft;
  `onSendReply()`; advance. Expected: `isSending` flips true→false, `sendError` is
  set (mapped from the 422 body), the draft is PRESERVED (non-idempotent POST not
  cleared). Traces: AC-5; validates claim #8 (1..4000 bound).
- **TC-AND-375-06 — Unauthorized after refresh exhausted → SessionExpired +
  RequireReauth.** Type: unit (JVM). Target: `TicketSpacesViewModel` (and asserted
  again for a detail VM). Preconditions: `getSpaces` → `ApiResult.Unauthorized`.
  Steps: construct; collect state + effects. Expected: `RequireReauth` effect and
  `Phase.Error` with `TicketsError.SessionExpired` (`canRetry=false`) for the list
  VM; detail VM keeps last content behind the prompt (R3). Traces: AC-4.
- **TC-AND-375-07 — Concurrent refresh de-dup (job guard).** Type: unit (JVM).
  Target: `TicketSpacesViewModel`. Preconditions: `FakeTicketRepository` counts
  `getSpaces` calls and suspends on a gate. Steps: call `onRefresh()` twice before
  releasing the gate; advance. Expected: repository `getSpaces` call-count == 1
  (FR-7). Traces: AC-3.
- **TC-AND-375-08 — Refresh-over-content failure keeps content, sets stale.**
  Type: unit (JVM). Target: `TicketSpacesViewModel`. Preconditions: first
  `getSpaces` → `Success`; second (forced) → `Error` while cached content exists.
  Steps: reach `Content`; `onRefresh()`; advance. Expected: `isRefreshing` toggles
  true→false, content retained, `isStale=true`, a `ShowMessage` is emitted, phase
  stays `Content` (not `Error`). Traces: AC-2, AC-3. (Flaky-dev-host path.)
- **TC-AND-375-09 — Ticket list paging emits mapped items from
  `SpaceTicketListEnvelope`.** Type: unit (JVM, `paging-testing`). Target:
  `TicketListViewModel`. Preconditions: `SavedStateHandle["spaceId"]="sp_1"`;
  fake pager yields two `SpaceTicketOut` pages with a `next_cursor`. Steps: collect
  `tickets` via `AsyncPagingDataDiffer`/snapshot. Expected: items map to
  `TicketListItem` carrying `ticket_id`, `subject`, `status`; second page appends.
  Traces: AC-2; validates claims #3, #9.
- **TC-AND-375-10 — Navigation effects.** Type: unit (JVM). Target: spaces / list
  / project VMs. Preconditions: loaded content. Steps: `onSpaceClicked("sp_1")`,
  `onTicketClicked("tk_1")`, `onProjectClicked("pr_1")`. Expected: exactly
  `NavigateToTickets("sp_1")`, `NavigateToThread("tk_1")`,
  `NavigateToProject("pr_1")` effects; no state mutation. Traces: AC-2.
- **TC-AND-375-11 — Thread loads inline messages + space members; blank draft is a
  no-op.** Type: unit (JVM). Target: `TicketThreadViewModel`. Preconditions:
  `SavedStateHandle["spaceId"]`+`["ticketId"]`; `getSpaceTicket` →
  `Success(SpaceTicketOut with messages[])`; space members available. Steps:
  construct; advance; then `onReplyDraftChanged("")` and `onSendReply()`. Expected:
  `uiState` carries messages as an inline list and members from the space;
  `canSend=false` for blank draft; `onSendReply` with blank draft does NOT call
  `repository.postMessage`. Traces: AC-5; validates claims #4, #5, #7.
- **TC-AND-375-12 — Reply success clears draft; `onReplyDraftChanged` clears prior
  sendError.** Type: unit (JVM). Target: `TicketThreadViewModel`. Preconditions:
  prior failed send left `sendError` set. Steps: `onReplyDraftChanged("ok")`
  (assert `sendError` cleared, `canSend=true`); `onSendReply()` with
  `postMessage(spaceId,ticketId,"ok")` → `Success`. Expected: `isSending`
  true→false, `replyDraft=""`, `sendError=null`. Traces: AC-5; validates claim #8
  (spaceId in signature).
- **TC-AND-375-13 — Drive connect produces Connecting + OpenUrl(authorization_url).**
  Type: unit (JVM). Target: `ProjectDetailViewModel`. Preconditions:
  `FakeProjectRepository.startDriveOAuth` →
  `Success(ProviderOAuthStartOut(authorization_url="https://accounts.google…",
  state="s", expires_at="…"))`. Steps: load detail; `onConnectDrive()`; advance.
  Expected: `driveStatus=Connecting` and an `OpenUrl("https://accounts.google…")`
  effect; start failure instead leaves `Disconnected` + `ShowMessage`. Traces:
  AC-6; validates claim #12.
- **TC-AND-375-14 — No PII/auth-URL logging; @StringRes-only messages.** Type:
  unit (JVM, Robolectric for `Timber` tree). Target: all five VMs. Preconditions:
  a capturing `Timber` test tree; effects carry `@StringRes` ids. Steps: drive
  load/error/cached/reply/connect paths; inspect captured logs and effect
  payloads. Expected: no message bodies, subjects, `sender_sub`/`owner_sub`,
  project contents, or `authorization_url`/`state` appear in any log; every
  `ShowMessage` carries an `Int` res id, never a literal string. Traces: AC-8.
- **TC-AND-375-15 — Effects do not replay across config change (rotation).** Type:
  instrumented/e2e (Compose host wrapping a real VM in a `ViewModelStore`).
  Target: `TicketSpacesViewModel`. **Runs on emulator AVD `test35` (API 35)** —
  no special hardware; physical device not required. Preconditions: a one-shot
  `ShowMessage` already consumed. Steps: recreate the host Activity (rotation);
  re-subscribe to `effects` and `uiState`. Expected: the `Channel`-backed effect
  is NOT re-delivered; `uiState` content is retained without a reload (FR-10).
  Traces: AC-2. Note: a JVM `cachedIn(viewModelScope)` survival check is the unit
  counterpart, but config-change survival is best verified instrumented.

No case in this ticket requires the physical Samsung A15 (SM-A156U): there is no
camera/biometric/FCM/WebRTC/Telecom/HLS or ABI-specific behavior here — it is a
pure JVM/coroutine state layer. TC-AND-375-15 uses the emulator only to exercise
real `ViewModelStore` recreation.

### Coverage matrix

| AC   | Covered by |
|------|------------|
| AC-1 | TC-01, TC-02, TC-03, TC-06, TC-07, TC-08 (deterministic under `StandardTestDispatcher`) |
| AC-2 | TC-01, TC-02, TC-04, TC-08, TC-09, TC-10, TC-15 |
| AC-3 | TC-07, TC-08 |
| AC-4 | TC-03, TC-06 |
| AC-5 | TC-05, TC-11, TC-12 |
| AC-6 | TC-13 |
| AC-7 | (structural — asserted by absence of HTTP/Room in all unit cases; TC-04/TC-05 use repository, not direct HTTP) |
| AC-8 | TC-14 |
