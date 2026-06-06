---
id: AND-375
title: Tickets/projects ViewModels
milestone: M8
epic: E48
priority: P2
size: M
status: draft
depends_on: [AND-371]
blocks: [AND-372, AND-373, AND-374]
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
  `ApiResult<T>` lives in `core-network`; FastAPI `detail` mapping
  (`string | [{msg}] | {code,...}`) is normalized by the `core-network` error
  mapper. Auth is cookie-based and fully owned by `core-network` (cookie jar,
  `X-CSRF-Token`, single `/ui/session/refresh` on 401); these ViewModels react to
  an `Unauthorized` `ApiResult` with a re-auth effect.

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

FR-3. **Ticket thread.** `TicketThreadViewModel` is constructed with a
`ticketId`, loads the ticket header + members + messages (messages paged, newest
or oldest-first per backend), and exposes `val uiState:
StateFlow<TicketThreadUiState>` plus `val messages: Flow<PagingData<TicketMessage>>`.
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
connect** intent surface (`onConnectDrive()` → starts provider auth, surfaces a
`OpenUrl(authUrl)` effect; the callback resolution is AND-374's concern, but the
VM models `driveStatus: DriveConnectState`). Intents: `onRefresh()`,
`onRetry()`, `onConnectDrive()`.

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
        when (val r = repository.postMessage(ticketId, draft)) {   // AND-373 impl
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

```json
// GET /ui/ticket-spaces  -> spaces list
{ "items": [ { "id": "sp_123", "name": "Support", "ticket_count": 12,
               "updated_at": "2026-06-05T12:00:00Z" } ], "next_cursor": null }

// GET /ui/ticket-spaces/{spaceId}/tickets -> paged tickets
{ "items": [ { "id": "tk_1", "subject": "Login fails", "status": "open",
               "last_message_at": "2026-06-05T11:00:00Z" } ], "next_cursor": "..." }

// GET /ui/tickets/{ticketId} -> header + members + messages page
{ "ticket": { "id": "tk_1", "subject": "...", "status": "open" },
  "members": [ { "u": "u_abc", "role": "agent" } ],
  "messages": { "items": [ { "id": "m_1", "author_u": "u_abc",
                 "body": "...", "created_at": "..." } ], "next_cursor": "..." } }

// POST /ui/tickets/{ticketId}/messages  (AND-373)  body: { "body": "..." }

// GET /ui/projects -> list ; GET /ui/projects/{projectId} -> detail
// GET /ui/projects/{projectId}/providers/google-drive/start -> { "auth_url": "..." }
```

The ViewModels consume already-mapped domain objects, not this JSON. Error
normalization (FastAPI `detail`: `string | [{msg}] | {code,...}`) is performed by
the `core-network` mapper before reaching the repository; this ticket only maps
`ApiResult.Error` → `TicketsError` and treats 401 as `Unauthorized`.

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
- **Drive connect:** `Disconnected → onConnectDrive → Connecting + OpenUrl(authUrl)
  → (callback handled by AND-374) → Connected`. The VM moves to `Connecting` only
  after the start call returns an `auth_url`.

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
  subjects, member identifiers (`u_…`), project contents, or Drive `auth_url`s.
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
  Connecting` + `OpenUrl(authUrl)` on a successful start.
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
