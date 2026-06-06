---
id: AND-372
title: Ticket spaces + threads
milestone: M8
epic: E48
priority: P1
size: L
status: draft
depends_on: [AND-371]
blocks: []
---

# AND-372 — Ticket spaces + threads

## 1. Overview & Goal

This ticket delivers the `feature-tickets` UI surface for the TestLogon native
Android port: the three screens that let an authenticated user browse their
ticket **spaces**, drill into a space's **ticket list**, and read a single
ticket's **message thread**. It is the presentation half of the tickets domain;
the data/transport half (Retrofit service, DTOs, repository) is owned by the
dependency ticket AND-371 (Tickets API), which exposes `tickets.ts`-equivalent
endpoints and the ticket-spaces members/messages DTOs.

The goal is a working, navigable read path: **Spaces list → Ticket list →
Ticket thread**, each backed by a Hilt-injected ViewModel that consumes the
AND-371 repository, exposes a `StateFlow<UiState>`, and renders Loading / Empty /
Error / Content states using Compose + Material 3. The minimum acceptance bar is
that spaces and tickets render against the dev backend; thread rendering and
paging round out the feature. Composing/replying to tickets is explicitly **out
of scope** for this ticket (read-only) and is deferred to a future write ticket
in epic E48.

## 2. Context & References

- **Module:** new Gradle module `:feature-tickets` (layer: `app -> feature-* ->
  core-*`). Package root `com.testlogon.android.feature.tickets`.
- **Depends on:** AND-371 (Tickets API) for `TicketsRepository`, the Retrofit
  `TicketsApi` service, and DTO→domain mappers (`TicketSpace`, `Ticket`,
  `TicketMessage`, `SpaceMember`). This ticket MUST NOT define its own DTOs; it
  consumes domain models from `:core-model` and the repository from
  `:core-data`.
- **Transitive deps:** AND-371 depends on AND-027 (core-network/ApiResult).
  Auth is cookie-based and handled globally by the OkHttp stack (session start →
  MFA → finalize → `/ui/me`), so screens here assume an authenticated session
  and surface a 401-driven re-auth signal rather than managing cookies.
- **Web reference:** `frontend/src/api/endpoints/tickets.ts` and
  `frontend/src/api/types.ts` define the canonical field names and the
  spaces/members/messages relationships mirrored here.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (PLAINTEXT HTTP, unreliable). OpenAPI at `/openapi.json`. Design for ~20s
  timeouts, bounded backoff on idempotent GETs, and offline/stale UI states.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Navigation-Compose, Hilt
  (KSP), Coroutines/Flow, Paging 3, Coil. minSdk 24 / target 35.

## 3. Functional Requirements

FR-1. **Spaces list screen.** Display the spaces the current user belongs to as
a scrollable list. Each row shows the space name, an optional description/topic,
member count, and an unread/last-activity indicator when present. Tapping a row
navigates to that space's ticket list.

FR-2. **Ticket list screen.** For a selected `spaceId`, display the space's
tickets, paged. Each row shows ticket title/subject, status (e.g. open /
pending / closed), last-message timestamp (relative, e.g. "3h ago"), and the
last author. Tapping a row navigates to the ticket thread. The screen title is
the space name.

FR-3. **Ticket thread screen.** For a selected `ticketId`, display the ordered
message thread (oldest → newest), each message showing author display name,
relative timestamp, and body text. Messages from the current user are visually
distinguished (alignment/color). The thread auto-scrolls to the newest message
on first load.

FR-4. **State surfaces.** Every screen renders four mutually exclusive states:
`Loading` (initial fetch / shimmer), `Empty` (request succeeded, zero items
with an actionable empty message), `Error` (failure with a Retry affordance and
mapped message), and `Content`.

FR-5. **Pull-to-refresh.** Spaces and ticket-list screens support
pull-to-refresh that re-fetches from network and updates the Room-cached view.

FR-6. **Stale/offline indicator.** When content is served from cache because the
network call failed or timed out, show a non-blocking "Showing saved data" /
"Offline" banner above the list.

FR-7. **Re-auth handoff.** On a terminal 401 (after the global single
`/ui/session/refresh` retry has already failed), the screen emits a navigation
event to the login flow rather than rendering a generic error.

FR-8. **Read-only.** No compose/reply/edit affordances are rendered. Out of
scope; deferred to a future E48 write ticket.

## 4. Technical Design

### 4.1 Module & navigation

`:feature-tickets` exposes a typed nav graph via Navigation-Compose with
type-safe routes (Kotlin `@Serializable` route objects):

```kotlin
@Serializable data object TicketSpacesRoute
@Serializable data class TicketListRoute(val spaceId: String)
@Serializable data class TicketThreadRoute(val ticketId: String, val spaceId: String)

fun NavGraphBuilder.ticketsGraph(
    onOpenSpace: (String) -> Unit,
    onOpenTicket: (spaceId: String, ticketId: String) -> Unit,
    onReauthRequired: () -> Unit,
    onBack: () -> Unit,
)
```

The `app` module wires `ticketsGraph` into the single-Activity
`NavHost`; lambdas translate domain ids into `navController.navigate(...)`
calls. `onReauthRequired` routes to the auth graph.

### 4.2 ViewModels

Three Hilt `@HiltViewModel` ViewModels, each exposing
`StateFlow<UiState>` and a one-shot `Channel`/`SharedFlow` for navigation/effect
events. ViewModels depend only on `TicketsRepository` (from AND-371).

```kotlin
@HiltViewModel
class TicketSpacesViewModel @Inject constructor(
    private val repo: TicketsRepository,
) : ViewModel() {
    val uiState: StateFlow<SpacesUiState>
    fun refresh()
    fun retry()
}

@HiltViewModel
class TicketListViewModel @Inject constructor(
    private val repo: TicketsRepository,
    savedStateHandle: SavedStateHandle, // spaceId
) : ViewModel() {
    val spaceName: StateFlow<String?>
    val tickets: Flow<PagingData<TicketUi>>   // Paging 3
    fun refresh()
}

@HiltViewModel
class TicketThreadViewModel @Inject constructor(
    private val repo: TicketsRepository,
    savedStateHandle: SavedStateHandle, // ticketId
) : ViewModel() {
    val uiState: StateFlow<ThreadUiState>
    fun retry()
}
```

`spaceId`/`ticketId` are read from `SavedStateHandle.toRoute<...>()` so the
ViewModels survive process death.

### 4.3 UI state model

```kotlin
sealed interface SpacesUiState {
    data object Loading : SpacesUiState
    data class Content(
        val spaces: List<SpaceUi>,
        val isRefreshing: Boolean = false,
        val stale: Boolean = false,
    ) : SpacesUiState
    data object Empty : SpacesUiState
    data class Error(val message: String, val retryable: Boolean) : SpacesUiState
}

sealed interface ThreadUiState {
    data object Loading : ThreadUiState
    data class Content(val title: String, val messages: List<MessageUi>, val stale: Boolean) : ThreadUiState
    data object Empty : ThreadUiState
    data class Error(val message: String, val retryable: Boolean) : ThreadUiState
}
```

`SpaceUi`, `TicketUi`, `MessageUi` are screen models mapped from `:core-model`
domain types in a small `TicketsUiMappers.kt`; they pre-compute display strings
(relative time via a `RelativeTime` helper, `isMine` against the current user
id obtained from a `SessionStore`).

### 4.4 Composables

```kotlin
@Composable fun TicketSpacesScreen(viewModel: TicketSpacesViewModel = hiltViewModel(), onOpenSpace: (String) -> Unit)
@Composable fun TicketListScreen(viewModel: TicketListViewModel = hiltViewModel(), onOpenTicket: (String) -> Unit, onBack: () -> Unit)
@Composable fun TicketThreadScreen(viewModel: TicketThreadViewModel = hiltViewModel(), onBack: () -> Unit)
```

Lists use `LazyColumn` with stable `key`s. Ticket list uses
`collectAsLazyPagingItems()` and renders `LoadState` (append spinner, refresh
error item). Shared `LoadingState`, `EmptyState`, `ErrorState`, and
`StaleBanner` composables live in `:core-ui` and are reused here. Pull-to-refresh
uses Material 3 `PullToRefreshBox`. State is collected with
`collectAsStateWithLifecycle()`.

## 5. API Contract

This ticket consumes the endpoints implemented by **AND-371**; it defines no new
network calls. Endpoint paths and shapes below are the contract this UI relies
on (authoritative definition in AND-371 / `frontend/src/api/endpoints/tickets.ts`
/ `/openapi.json`). All are idempotent GETs (eligible for bounded backoff
retry). Auth rides on cookies + `X-CSRF-Token`.

`GET /ui/tickets/spaces` — spaces for the current user:

```json
[
  {
    "space_id": "sp_01H...",
    "name": "Acme Support",
    "topic": "Customer escalations",
    "member_count": 7,
    "unread_count": 2,
    "last_activity_at": "2026-06-04T17:21:09Z"
  }
]
```

`GET /ui/tickets/spaces/{space_id}/tickets?cursor=&limit=20` — paged tickets:

```json
{
  "items": [
    {
      "ticket_id": "tk_01H...",
      "space_id": "sp_01H...",
      "subject": "Cannot log in",
      "status": "open",
      "last_message_at": "2026-06-05T08:02:00Z",
      "last_author": "Jane D."
    }
  ],
  "next_cursor": "eyJrIjoi..."
}
```

`GET /ui/tickets/{ticket_id}` — ticket detail + messages:

```json
{
  "ticket_id": "tk_01H...",
  "subject": "Cannot log in",
  "status": "open",
  "messages": [
    {
      "message_id": "msg_01H...",
      "author_id": "usr_42",
      "author_name": "Jane D.",
      "body": "Still failing after refresh.",
      "created_at": "2026-06-05T08:02:00Z"
    }
  ]
}
```

FastAPI error bodies follow the project `detail` convention (`string` |
`[{msg}]` | `{code,...}`); AND-027's mapper resolves these to `ApiResult.Error`.

## 6. Data & State Management

- **Repository contract (from AND-371):**
  ```kotlin
  interface TicketsRepository {
      fun spaces(): Flow<ApiResult<List<TicketSpace>>>   // Room-backed, network-refreshing
      fun ticketsPager(spaceId: String): Pager<String, Ticket>
      suspend fun space(spaceId: String): ApiResult<TicketSpace>
      suspend fun thread(ticketId: String): ApiResult<TicketThread>
      suspend fun refreshSpaces(): ApiResult<Unit>
  }
  ```
- **Caching:** Room (`:core-data`) is the single source of truth for spaces and
  the thread head; the UI observes Room and network refreshes write through it
  (offline-first). The `stale` flag is set when the latest network refresh
  failed but cached rows exist. Paging uses Paging 3 with a `RemoteMediator`
  (owned by AND-371) keyed on `next_cursor`.
- **State holding:** ViewModels keep state in `StateFlow` produced via
  `stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), Loading)`.
  No business state lives in composables; only `rememberLazyListState`/scroll
  position.
- **Process death:** route args persist via `SavedStateHandle`; cache makes
  re-entry instant. Scroll position survives config changes via `rememberSaveable`
  list state.

## 7. Error Handling & Resilience

- **Timeouts/backoff:** OkHttp client (AND-027) is configured for ~20s
  call timeout; GETs use bounded exponential backoff (e.g. 3 attempts, jitter).
  These screens never retry POSTs (none here).
- **Mapping:** `ApiResult.Error` is mapped to user copy by an
  `errorMessageFor(throwable/detail)` helper: network/timeout → "Couldn't reach
  the server. Showing saved data." (when cache present) or a retryable error
  (when empty); HTTP 4xx with `detail` → the mapped message; 5xx → "Something
  went wrong on our end."
- **Stale-while-error:** if a refresh fails but Room has rows, render
  `Content(stale = true)` with `StaleBanner`; do not blank the screen.
- **401 handling:** the global `Authenticator`/interceptor performs one
  `POST /ui/session/refresh` then retries; a still-401 surfaces as
  `ApiResult.Error(Unauthorized)`, which the ViewModel converts into a
  `NavEvent.ReauthRequired` effect (FR-7), not an inline error.
- **Paging errors:** `LoadState.Error` on refresh shows full-screen error with
  retry (`lazyPagingItems.retry()`); on append shows an inline retry row.
- **Empty vs error:** a 200 with `[]`/`items:[]` is `Empty`, never `Error`.

## 8. Security & Privacy

- No credentials or tokens handled here; the persistent cookie jar and
  `X-CSRF-Token` echo are owned by the network layer (AND-027). This module
  issues only authenticated GETs.
- Ticket bodies and member names are user PII: never logged at INFO+, never
  written to crash breadcrumbs in plaintext (see §10). Coil image requests (if
  avatars exist) reuse the authenticated OkHttp client so cookies are sent;
  no separate cleartext client is created.
- Dev backend is plaintext HTTP; the cleartext exception is build-config gated
  (debug only) by AND-027. This ticket adds no new network-security config.
- No data is exported outside the app; Room DB lives in app-private storage and
  is excluded from auto-backup per project policy.

## 9. Accessibility & i18n

- All strings in `:feature-tickets` `strings.xml`; no hard-coded UI text.
  Relative timestamps formatted via locale-aware `DateUtils.getRelativeTimeSpanString`
  / `java.time` with the device locale.
- Every row, icon button, and state graphic has a `contentDescription`
  (e.g. unread badge announces "2 unread"). Status chips include text, not color
  alone (color + label).
- Touch targets ≥ 48dp; supports dynamic font scaling (no fixed `sp`-defeating
  heights); list items wrap text rather than truncate critical content.
- TalkBack: thread messages announce "author, time, message"; "mine" vs
  "theirs" conveyed via text/semantics, not only alignment. Content state
  transitions use `liveRegion` for the stale/offline banner.
- RTL-safe layouts (start/end paddings, no left/right hardcoding).

## 10. Telemetry & Logging

- Screen views: `tickets_spaces_view`, `tickets_list_view` (with hashed
  `space_id`), `tickets_thread_view` (hashed `ticket_id`) via the project
  analytics facade in `:core-ui`/`:core-data`. IDs are hashed/opaque; no PII
  (no names, no bodies, no subjects) in any event property.
- Performance: log refresh latency and cache-hit/stale outcomes
  (`tickets_refresh_result = {ok|stale|error}`) for the unreliable-host
  diagnostics.
- Errors: `ApiResult.Error` paths log error class + HTTP status + mapped
  category at WARN; never the response body. Debug builds may log full bodies
  behind a `BuildConfig.DEBUG` guard only.
- Paging: emit `tickets_page_append` count for tuning `limit`.

## 11. Testing Strategy

- **ViewModel unit tests** (`:core-testing`, Turbine + coroutines test):
  - Spaces: Loading→Content; Loading→Empty (empty list); Loading→Error
    (retryable) ; refresh sets `isRefreshing`; refresh-fail-with-cache →
    `Content(stale=true)`; 401 → `NavEvent.ReauthRequired`.
  - Thread: ordering oldest→newest; `isMine` resolved against session user id;
    Empty when no messages; retry re-invokes repo.
- **Mapper tests:** DTO→Ui mapping for relative time, status, author; verifies
  field names match AND-371 (`space_id`, `ticket_id`, `last_message_at`, etc.).
- **Paging tests:** `PagingSource`/mediator fake returns two pages; assert
  `next_cursor` chaining and `LoadState.Error` → retry.
- **Compose UI tests** (`createAndroidComposeRule`): each state renders its
  testTag (`loading`, `empty`, `error`, `content`, `staleBanner`); tapping a
  space/ticket invokes the nav lambda with the correct id; Retry calls
  `viewModel.retry()`; pull-to-refresh triggers `refresh()`.
- **Contract test:** a MockWebServer-backed test using the AND-371 service
  decodes the §5 sample JSON to ensure UI assumptions hold against the real
  shapes.
- **Acceptance gate:** an instrumented smoke test against a MockWebServer (and
  optionally the dev host, opt-in) asserting spaces and tickets render
  (FR-1, FR-2) — directly satisfies the ticket's stated acceptance.

## 12. Dependencies & Sequencing

- **Blocked by AND-371** (Tickets API): repository, service, DTOs, mappers, and
  the Paging `RemoteMediator` must land first; this ticket compiles against
  those interfaces. Stub the `TicketsRepository` interface early so UI work can
  proceed in parallel behind a fake.
- **Transitively requires AND-027** (core-network/ApiResult, cookie jar, CSRF,
  401 refresh) via AND-371.
- **Sequencing within this ticket:** (1) module + nav skeleton + fakes; (2)
  Spaces screen + VM (meets minimum acceptance); (3) Ticket list + Paging; (4)
  Thread screen; (5) stale/offline + reauth handoff; (6) a11y/telemetry/tests.
- **Blocks:** none recorded in backlog; a future E48 write/compose ticket will
  build on these screens and reuse the nav routes.

## 13. Risks & Open Questions

- **R1 — Unreliable dev host.** Frequent timeouts could make manual acceptance
  flaky. Mitigation: offline-first cache + MockWebServer-based acceptance test;
  treat dev-host runs as opt-in.
- **R2 — Unconfirmed payload shapes.** §5 shapes are inferred from
  `tickets.ts`/web types; AND-371 is authoritative. If field names differ
  (e.g. `subject` vs `title`, cursor vs offset paging), only the thin
  `TicketsUiMappers` changes. **Open:** confirm exact field names and pagination
  style from `/openapi.json` during AND-371.
- **R3 — "Mine" attribution** requires the current user id; depends on a
  `SessionStore`/`/ui/me` value being available to the module. **Open:** is the
  user id exposed via `:core-data` SessionStore or must we add it?
- **R4 — Unread/last-activity** fields may not exist server-side yet. Mitigation:
  treat as nullable; hide badge when absent.
- **R5 — Thread paging.** Long threads may need paging too; scope here loads the
  thread in one call. **Open:** is `/ui/tickets/{id}` paginated? If so, follow-up
  ticket.

## 14. Acceptance Criteria

AC-1. Launching the tickets tab shows a Loading state, then a list of the
current user's spaces; each row shows name + member count and is tappable.
**(maps to ticket acceptance: spaces render.)**

AC-2. Tapping a space navigates to its ticket list and renders tickets
(subject, status, relative last-message time), paged via Paging 3.
**(maps to ticket acceptance: tickets render.)**

AC-3. Tapping a ticket opens the thread; messages render oldest→newest, the
user's own messages are visually distinct, and the list auto-scrolls to newest.

AC-4. Each screen renders distinct Loading / Empty / Error / Content states;
Error shows a working Retry; a successful empty response shows Empty (not Error).

AC-5. When a refresh fails but cache exists, content stays visible with a
stale/offline banner; pull-to-refresh re-fetches.

AC-6. A terminal 401 routes to the auth flow (no inline error).

AC-7. No compose/reply affordance is present (read-only).

AC-8. ViewModel, mapper, paging, and Compose state tests pass in CI; the
MockWebServer acceptance smoke test for AC-1/AC-2 passes.

## 15. Definition of Done

- `:feature-tickets` module created, wired into the app `NavHost`, builds on
  JDK 17 / AGP 8.7.3 / Gradle 8.9; ktlint/detekt clean.
- All three screens implemented with Hilt ViewModels exposing
  `StateFlow<UiState>`, consuming the AND-371 `TicketsRepository` (no DTOs
  redefined here).
- All §14 acceptance criteria verified; FR-1…FR-8 implemented.
- Unit + Compose + paging + contract + acceptance tests added and green in CI;
  meaningful coverage of the four state surfaces and the stale/reauth paths.
- All user-facing text in `strings.xml`; a11y (contentDescription, 48dp targets,
  TalkBack order, dynamic type, RTL) verified.
- Telemetry events emitted with hashed IDs and zero PII; no response bodies
  logged outside `BuildConfig.DEBUG`.
- No new cleartext/network-security config introduced; reuses AND-027 client.
- Open questions R2/R3/R5 either resolved against AND-371/`/openapi.json` or
  filed as follow-up tickets.
- Code reviewed and merged to `android-port`.
