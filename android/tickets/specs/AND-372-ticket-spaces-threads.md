---
id: AND-372
title: Ticket spaces + threads
milestone: M8
epic: E48
priority: P1
size: L
status: reviewed
reviewed_on: 2026-06-06
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
  Auth is handled globally by the OkHttp stack and (per the web client,
  `src/api/client.ts`) combines an `Authorization: Bearer <accessToken>` header,
  cookie credentials (`credentials: "include"`), and a `X-CSRF-Token` header
  echoed from the `ui_csrf` cookie — it is **not** cookie-only as an earlier draft
  stated. The current user id used for "mine" attribution comes from the same
  session store the web app reads via `useAuthStore.userId` (populated at login;
  `GET /ui/me` exists for hydration). Screens here assume an authenticated
  session and surface a 401-driven re-auth signal rather than managing tokens
  directly. (Correction: the verb chain "session start → MFA → finalize → /ui/me"
  is the login flow owned upstream, not something verified for this surface.)
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
a scrollable list. Each row shows the space name, the `visibility` badge
(`private`/`shared`), and a **member count derived from `members.length`**.
(Correction: the API has no `topic`/`description`, no `member_count`, and no
`unread_count`/`last_activity_at` fields — see §5/§13-R4. The only activity
signal is `updated_at`; an "updated …" relative time MAY be shown in its place.
Any unread badge is deferred until the backend exposes it.) Tapping a row
navigates to that space's ticket list.

FR-2. **Ticket list screen.** For a selected `spaceId`, display the space's
tickets, paged. Each row shows the ticket `subject`, `status` (enum:
`open | in_progress | waiting_on_user | done | reopened` — NOT
open/pending/closed), and a relative timestamp from `updated_at` (e.g. "3h
ago"). (Correction: there is no `last_message_at` or `last_author` field; the
web ticket row shows `owner_sub`/`assigned_to_sub`, so use `owner_sub` — or
`assigned_to_sub` when present — rather than an invented "last author".) Tapping
a row navigates to the ticket thread. The screen title is the space name.

FR-3. **Ticket thread screen.** For a selected `(spaceId, ticketId)`, display
the ordered message thread (oldest → newest) from the embedded
`ticket.messages`, each message showing the author identity (`sender_sub` —
there is no server display name; resolve to a friendly name only if a directory
lookup exists, otherwise render the sub), a relative timestamp from
`created_at`, and body text. Messages from the current user are visually
distinguished (alignment/color) by comparing `sender_sub` to the session user
id (web does the same via `useAuthStore.userId`). The thread auto-scrolls to
the newest message on first load.

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
network calls. The paths/shapes below are **corrected against the authoritative
sources** (`reference/openapi.index.txt`, `reference/openapi.pretty.json`,
`reference/src/api/endpoints/tickets.ts`). An earlier draft used invented
`/ui/tickets/...` paths and fabricated fields (`topic`, `member_count`,
`unread_count`, `last_activity_at`, `last_message_at`, `last_author`,
`author_id`, `author_name`); none of those exist on the backend. All listed
calls are idempotent GETs (eligible for bounded backoff retry). Auth: see §2
(Bearer header + cookie credentials + `X-CSRF-Token`). **All timestamps are
epoch SECONDS (`integer`)**, not ISO-8601 strings; the web client renders them
as `new Date(ts * 1000)`.

`GET /ui/me` (hydrate current user id) and `POST /ui/session/refresh` (401
refresh) are confirmed to exist (`openapi.index.txt` lines 1638, 1847).

`GET /ticket-spaces?cursor=&limit=20` — spaces for the current user
(`TicketSpaceListEnvelope` → `TicketSpaceOut[]`). There is **no** `topic`,
`member_count`, `unread_count`, or `last_activity_at`; member count is derived
from `members.length`, and the only activity signal is `updated_at`:

```json
{
  "items": [
    {
      "space_id": "sp_01H...",
      "owner_sub": "usr_owner",
      "name": "Acme Support",
      "visibility": "private",
      "created_at": 1749057669,
      "updated_at": 1749061669,
      "members": [
        { "space_id": "sp_01H...", "member_sub": "usr_42", "role": "viewer",
          "created_at": 1749057669, "updated_at": 1749057669 }
      ]
    }
  ],
  "next_cursor": "eyJrIjoi..."
}
```

`GET /ticket-spaces/{space_id}/tickets?status=&assignee_sub=&cursor=&limit=20`
— paged tickets (`SpaceTicketListEnvelope` → `SpaceTicketOut[]`). Rows expose
`subject`, `status`, `owner_sub`, `assigned_to_sub`, and `updated_at`
(use `updated_at` for the relative "last activity" time; there is no
`last_message_at` / `last_author`):

```json
{
  "items": [
    {
      "ticket_id": "tk_01H...",
      "space_id": "sp_01H...",
      "subject": "Cannot log in",
      "status": "open",
      "owner_sub": "usr_42",
      "assigned_to_sub": null,
      "created_at": 1749110520,
      "updated_at": 1749110520,
      "version": 1,
      "messages": [],
      "activity": []
    }
  ],
  "next_cursor": "eyJrIjoi..."
}
```

`status` is a free `string` in `SpaceTicketOut`; the writable enum is
`open | in_progress | waiting_on_user | done | reopened` (NOT
open/pending/closed). The list endpoint also accepts a `status` filter param.

`GET /ticket-spaces/{space_id}/tickets/{ticket_id}` — ticket detail + embedded
thread (`SpaceTicketEnvelope` → `SpaceTicketOut`). **Requires BOTH `space_id`
and `ticket_id`** (the old single-id `/ui/tickets/{ticket_id}` does not exist).
Messages are embedded — the thread is **not** separately paginated (resolves
R5). Each message is a `SpaceTicketMessage` with `sender_sub` (not
`author_id`/`author_name`) and `sender_role`; the web client renders the raw
`sender_sub` as the display name (there is no server-provided display name):

```json
{
  "ticket": {
    "ticket_id": "tk_01H...",
    "subject": "Cannot log in",
    "owner_sub": "usr_42",
    "status": "open",
    "assigned_to_sub": null,
    "created_at": 1749110520,
    "updated_at": 1749110520,
    "version": 1,
    "messages": [
      {
        "message_id": "msg_01H...",
        "sender_sub": "usr_42",
        "sender_role": "viewer",
        "body": "Still failing after refresh.",
        "created_at": 1749110520,
        "email_alert_queued_for": []
      }
    ],
    "activity": []
  }
}
```

Error bodies: the OpenAPI declares **`ErrorEnvelope`** =
`{ "error": { "code": string, "message": string, "details"?: object } }` for
4xx/5xx on these routes (codes 400/403/404/409 + `422:HTTPValidationError`).
Note the web client (`client.ts: normalizeErrorDetail`) reads a FastAPI-style
`body.detail` instead; AND-027's mapper must handle the authoritative
`ErrorEnvelope.error.{code,message}` shape (and tolerate `detail`/`[{msg}]` for
422) and resolve to `ApiResult.Error`.

## 6. Data & State Management

- **Repository contract (from AND-371):**
  ```kotlin
  interface TicketsRepository {
      fun spaces(): Flow<ApiResult<List<TicketSpace>>>   // Room-backed, network-refreshing
      fun ticketsPager(spaceId: String): Pager<String, Ticket>
      suspend fun space(spaceId: String): ApiResult<TicketSpace>
      // Ticket detail requires BOTH ids (GET /ticket-spaces/{space_id}/tickets/{ticket_id});
      // the thread is embedded in the ticket, so this returns the full ticket.
      suspend fun ticket(spaceId: String, ticketId: String): ApiResult<Ticket>
      suspend fun refreshSpaces(): ApiResult<Unit>
  }
  ```
  (Correction: the old `thread(ticketId)` single-id signature could not satisfy
  the real two-id endpoint; the `TicketThreadRoute` already carries `spaceId`,
  so the ViewModel passes both. The "thread" is just `Ticket.messages`.)
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
  `errorMessageFor(throwable/error)` helper: network/timeout → "Couldn't reach
  the server. Showing saved data." (when cache present) or a retryable error
  (when empty); HTTP 4xx with an `ErrorEnvelope.error.message` (codes
  400/403/404/409) → the mapped message (fall back to FastAPI `detail`/`[{msg}]`
  for 422); 5xx → "Something went wrong on our end." (Correction: these routes
  return `ErrorEnvelope`, not a bare `detail` string.)
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
- **R2 — Payload shapes [RESOLVED in this review].** Confirmed against
  `openapi.pretty.json` + `tickets.ts`: paths are `/ticket-spaces…` (not
  `/ui/tickets…`); paging is **cursor-based** (`cursor`/`limit` →
  `next_cursor`); `subject` (not `title`) is correct; timestamps are epoch
  seconds (`integer`). Several inferred fields did NOT exist and were removed
  (see §16 corrections). Only the thin `TicketsUiMappers` carries this.
- **R3 — "Mine" attribution [RESOLVED].** The web app compares `sender_sub`
  against `useAuthStore.userId`, so the current user id is a session value
  (`GET /ui/me` exists for hydration). Android needs `:core-data` SessionStore
  to expose the user sub; if absent, AND-371/AND-027 must add it. There is no
  server `isMine`/display-name field — attribution is purely sub-equality and
  the raw sub is the only available "name".
- **R4 — Unread/last-activity [RESOLVED: fields absent].** `TicketSpaceOut` has
  no `unread_count`/`last_activity_at` and `SpaceTicketOut` has no
  `last_message_at`. Use `updated_at` for relative time; hide any unread badge
  until the backend adds it (do not render fabricated counts).
- **R5 — Thread paging [RESOLVED: not paginated].** `GET
  /ticket-spaces/{space_id}/tickets/{ticket_id}` returns the full ticket with
  `messages` embedded — there is no message cursor. Very long threads remain a
  theoretical follow-up, but no paging is needed now.

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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer. Sources:
OpenAPI index = `reference/openapi.index.txt`; OpenAPI spec =
`reference/openapi.pretty.json` (`components.schemas.<Name>`); frontend =
`reference/src/...`.

1. **Spaces list endpoint is `GET /ticket-spaces` (cursor/limit →
   `TicketSpaceListEnvelope`).** VERDICT: Corrected (draft said
   `GET /ui/tickets/spaces`). SOURCE: `GET /ticket-spaces`
   (op=`list_ticket_spaces_ticket_spaces_get`, resp=`TicketSpaceListEnvelope`),
   index L568; `src/api/endpoints/tickets.ts: listTicketSpaces`.
2. **Ticket list endpoint is `GET /ticket-spaces/{space_id}/tickets`
   (params `status,assignee_sub,cursor,limit` → `SpaceTicketListEnvelope`).**
   VERDICT: Corrected (draft said `/ui/tickets/spaces/{space_id}/tickets`).
   SOURCE: `GET /ticket-spaces/{space_id}/tickets`
   (op=`list_space_tickets_...`, resp=`SpaceTicketListEnvelope`), index L573;
   `src/api/endpoints/tickets.ts: listSpaceTickets`.
3. **Ticket detail endpoint is `GET /ticket-spaces/{space_id}/tickets/{ticket_id}`
   and requires BOTH ids → `SpaceTicketEnvelope`.** VERDICT: Corrected (draft
   said single-id `GET /ui/tickets/{ticket_id}`). SOURCE:
   `GET /ticket-spaces/{space_id}/tickets/{ticket_id}` (op=`get_space_ticket_...`,
   resp=`SpaceTicketEnvelope`), index L575;
   `src/api/endpoints/tickets.ts: getSpaceTicket(spaceId, ticketId)`.
4. **List/detail responses are envelopes** (`{items,next_cursor}` for lists;
   `{space}` / `{ticket}` for singletons), not bare arrays/objects. VERDICT:
   Corrected (draft returned a bare `[...]` for spaces and a bare object for
   detail). SOURCE: schemas `TicketSpaceListEnvelope`, `SpaceTicketListEnvelope`,
   `TicketSpaceEnvelope`, `SpaceTicketEnvelope` in `openapi.pretty.json`;
   `tickets.ts: TicketSpaceListEnvelope`, `TicketEnvelope`.
5. **`TicketSpaceOut` fields = `space_id, owner_sub, name, visibility
   (private|shared), created_at, updated_at, members[]`.** VERDICT: Corrected —
   draft's `topic`, `member_count`, `unread_count`, `last_activity_at` do NOT
   exist; member count is `members.length`. SOURCE:
   `components.schemas.TicketSpaceOut`; `tickets.ts: TicketSpace`;
   `src/pages/tickets/TicketSpacesPage.tsx` (renders name + visibility + owner +
   updated, no counts).
6. **`SpaceTicketOut` fields = `ticket_id, subject, owner_sub, status,
   assigned_admin_sub?, assigned_by?, assigned_at?, assigned_to_sub?, space_id?,
   created_at, updated_at, version, messages[], activity[]`.** VERDICT:
   Corrected — draft's `last_message_at` and `last_author` do NOT exist; use
   `updated_at` and `owner_sub`/`assigned_to_sub`. SOURCE:
   `components.schemas.SpaceTicketOut`; `tickets.ts: Ticket`;
   `src/pages/tickets/TicketSpaceDetailPage.tsx: TicketRow`.
7. **`status` enum is `open | in_progress | waiting_on_user | done | reopened`.**
   VERDICT: Corrected — draft said "open / pending / closed". SOURCE:
   `components.schemas.SpaceTicketStatusReq.status.enum`;
   `tickets.ts: TicketStatus / TicketStatusWritable`.
8. **Message fields = `message_id, sender_sub, sender_role, body, created_at,
   email_alert_queued_for[]`.** VERDICT: Corrected — draft's `author_id` /
   `author_name` do NOT exist; identity is `sender_sub`. SOURCE:
   `components.schemas.SpaceTicketMessage`; `tickets.ts: TicketMessage`;
   `TicketSpaceDetailPage.tsx` (renders raw `sender_sub`).
9. **All timestamps are epoch SECONDS (`integer`).** VERDICT: Corrected — draft
   used ISO-8601 strings. SOURCE: `created_at`/`updated_at` typed `integer` in
   `TicketSpaceOut`/`SpaceTicketOut`/`SpaceTicketMessage`;
   `TicketSpacesPage.tsx: fmt = new Date(ts * 1000)`.
10. **Thread is embedded (not separately paginated).** VERDICT: Verified.
    SOURCE: `SpaceTicketOut.messages` is an embedded array; no message-cursor
    endpoint in index L568–L578.
11. **Error bodies are `ErrorEnvelope` = `{error:{code,message,details?}}`.**
    VERDICT: Corrected — draft cited bare FastAPI `detail`. SOURCE:
    `components.schemas.ErrorEnvelope` + `ErrorDetail`; resp codes
    `400/403/404/409:ErrorEnvelope` on index L568–L578. NOTE: the web client
    (`src/api/client.ts: normalizeErrorDetail`) reads `body.detail`, so the
    Android mapper must accept BOTH `ErrorEnvelope` and `detail`/`[{msg}]` (422).
12. **422 validation errors use `HTTPValidationError`.** VERDICT: Verified.
    SOURCE: `422:HTTPValidationError` on all ticket-space routes, index
    L568–L578.
13. **Auth = `Authorization: Bearer <accessToken>` + cookie credentials +
    `X-CSRF-Token` (from `ui_csrf` cookie).** VERDICT: Corrected — draft said
    "cookie-based … X-CSRF-Token" and omitted the Bearer header. SOURCE:
    `src/api/client.ts` (lines ~157–171, 183 `credentials:"include"`).
14. **401 → single `POST /ui/session/refresh` then retry; still-401 → logout.**
    VERDICT: Verified. SOURCE: `src/api/client.ts: refreshSession` /
    401 branch; `POST /ui/session/refresh` index L1847.
15. **`GET /ui/me` exists (current-user hydration).** VERDICT: Verified.
    SOURCE: `GET /ui/me` (op=`ui_me_ui_me_get`), index L1638.
16. **"Mine" attribution = compare `sender_sub` to session user id.** VERDICT:
    Verified (no server `isMine`). SOURCE:
    `TicketSpaceDetailPage.tsx: currentUserSub = useAuthStore(s => s.userId)`.
17. **Paging is cursor-based (`cursor`/`limit` → `next_cursor`).** VERDICT:
    Verified. SOURCE: `params=cursor,limit` index L568/L573; `next_cursor` in
    `TicketSpaceListEnvelope`/`SpaceTicketListEnvelope`.
18. **Write ops (create/reply/assign/status/members) exist but are out of
    scope.** VERDICT: Verified (confirms read-only FR-8). SOURCE: `POST
    /ticket-spaces…/messages|assign|status`, `POST|DELETE …/members`, index
    L569–L578; `tickets.ts: addSpaceTicketMessage` etc.
19. **Compose/Material 3 `PullToRefreshBox`, Paging 3
    `collectAsLazyPagingItems()`, `collectAsStateWithLifecycle()`,
    `SavedStateHandle.toRoute()`.** VERDICT: Unverified-assumption (framework
    choices; not in the backend/frontend sources). SOURCE: framework ref —
    Android docs (developer.android.com/jetpack/compose, /topic/libraries/
    architecture/paging/v3-overview, /guide/navigation/design/type-safety).
20. **Web app uses 15s polling, not pull-to-refresh.** VERDICT: Verified (the
    Android pull-to-refresh + offline-first cache is an intentional platform
    UX divergence, not a contract claim). SOURCE:
    `TicketSpaceDetailPage.tsx: POLL_MS = 15000` + `setInterval`.

### Corrections made

- Endpoint base path `/ui/tickets/*` → `/ticket-spaces/*` (§2, §5, §6) [#1–3].
- Ticket detail now requires `(space_id, ticket_id)`; repo signature
  `thread(ticketId)` → `ticket(spaceId, ticketId)` (§5, §6) [#3].
- Responses are envelopes (`{items,next_cursor}`, `{space}`, `{ticket}`), not
  bare arrays/objects (§5) [#4].
- Removed fabricated fields: `topic`, `member_count`, `unread_count`,
  `last_activity_at`, `last_message_at`, `last_author`, `author_id`,
  `author_name` (§3 FR-1/FR-2/FR-3, §5, §13-R4) [#5, #6, #8].
- Status enum corrected to `open|in_progress|waiting_on_user|done|reopened`
  (§3 FR-2, §5) [#7].
- Timestamps corrected to epoch-seconds integers (§5) [#9].
- Error model corrected to `ErrorEnvelope.error.{code,message}` (with note that
  the mapper must also tolerate the web client's `detail`) (§5, §7) [#11].
- Auth description corrected to Bearer + cookies + CSRF (§2) [#13].
- R2/R3/R4/R5 marked resolved with sources (§13) [#2,#9,#16,#5,#10].

### Open assumptions

- **A1 — All Compose/Paging/Navigation/Hilt framework choices** (§4, §6) are
  Android-side architecture not derivable from backend/frontend; treated as
  design decisions (framework ref only). Why unverifiable: no Android sources in
  the reference set.
- **A2 — `:core-data` SessionStore exposing the current user sub** (for "mine")
  is assumed available; the web reads `useAuthStore.userId`, but the Android
  store is owned by AND-027/AND-371 and not present here. Why: cross-ticket
  dependency, not in this repo.
- **A3 — Offline-first Room caching + `stale` banner + pull-to-refresh** (§4–§7)
  is a deliberate platform divergence from the web app's 15s polling [#20].
  Why unverifiable: it is a new UX requirement, not a contract.
- **A4 — Friendly author/owner display names.** The API exposes only opaque
  subs (`sender_sub`, `owner_sub`); rendering a human name requires a separate
  directory/profile lookup that is out of scope here. Until then the UI shows
  the sub (matching the web app). Why: no name field in any ticket schema.
- **A5 — Telemetry facade, analytics event names, and PII-hashing** (§10) are
  project conventions not represented in the references. Why: internal tooling.

## 17. Test Plan

Test targets: **JVM** = JVM unit/Robolectric (local, no device); **emu35** =
headless emulator AVD `test35` (x86_64, API 35); **A15** = physical Samsung
Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, API 34, arm64-v8a). All cases here
are deterministic and use **MockWebServer** or fakes, so they run on JVM or the
KVM emulator; this read-only ticket has **no** camera/biometric/FCM/WebRTC
behavior, so the physical device is required only for the real-hardware/ABI
sanity check (TC-AND-372-12).

- **TC-AND-372-01** — Type: unit (Turbine). Target: JVM
  (`TicketSpacesViewModel`). Preconditions: fake `TicketsRepository.spaces()`
  emits `ApiResult.Success` with 2 `TicketSpace`. Steps: collect `uiState`.
  Expected: `Loading` → `Content(spaces.size==2, stale=false)`; member count =
  `members.length`. Traces: AC-1.
- **TC-AND-372-02** — Type: unit (Turbine). Target: JVM
  (`TicketSpacesViewModel`). Preconditions: repo emits `Success([])`. Steps:
  collect `uiState`. Expected: `Loading` → `Empty` (never `Error`). Traces:
  AC-4.
- **TC-AND-372-03** — Type: unit (Turbine). Target: JVM
  (`TicketSpacesViewModel`). Preconditions: repo emits `ApiResult.Error`
  (network) with empty cache. Steps: collect `uiState`; call `retry()`; repo now
  succeeds. Expected: `Loading` → `Error(retryable=true)` → `Content`. Traces:
  AC-4.
- **TC-AND-372-04** — Type: unit (Turbine). Target: JVM
  (`TicketSpacesViewModel`). Preconditions: Room has cached spaces; network
  refresh fails (timeout). Steps: trigger `refresh()`. Expected: `isRefreshing`
  toggles true→false; final `Content(stale=true)` (cache stays visible, not
  blanked). Traces: AC-5.
- **TC-AND-372-05** — Type: unit (Turbine). Target: JVM (any ticket VM).
  Preconditions: repo returns terminal `ApiResult.Error(Unauthorized)` (after
  the global single `/ui/session/refresh` retry already failed). Steps: collect
  effect channel. Expected: emits `NavEvent.ReauthRequired`; `uiState` does NOT
  go to inline `Error`. Traces: AC-6.
- **TC-AND-372-06** — Type: unit (Turbine). Target: JVM
  (`TicketThreadViewModel`). Preconditions: fake `ticket(spaceId, ticketId)`
  returns a `Ticket` with 3 messages out of order + one whose
  `sender_sub == sessionUserId`. Steps: collect `uiState`. Expected: messages
  ordered oldest→newest by `created_at`; exactly the matching message has
  `isMine=true`; `Empty` when `messages` is empty. Traces: AC-3, AC-4.
- **TC-AND-372-07** — Type: unit (mapper). Target: JVM (`TicketsUiMappers`).
  Preconditions: domain `TicketSpace`/`Ticket`/`TicketMessage` with epoch-second
  `created_at`/`updated_at`. Steps: map to `SpaceUi`/`TicketUi`/`MessageUi`.
  Expected: relative time computed from `ts * 1000`; status maps the real enum
  (`waiting_on_user` renders a non-crashing label); space member count =
  `members.size`; author falls back to `sender_sub`/`owner_sub` (no
  `author_name` assumed). Traces: AC-1, AC-2, AC-3.
- **TC-AND-372-08** — Type: contract/MockWebServer. Target: JVM/Robolectric
  (AND-371 `TicketsApi` + JSON decoder). Preconditions: MockWebServer enqueues
  the exact §5 sample JSON for `GET /ticket-spaces`,
  `GET /ticket-spaces/{space_id}/tickets`, and
  `GET /ticket-spaces/{space_id}/tickets/{ticket_id}`. Steps: invoke the three
  service methods. Expected: decodes into envelopes (`items`+`next_cursor`,
  `ticket`); `space_id`/`ticket_id`/`subject`/`status`/`sender_sub`/integer
  timestamps populate; unknown/missing optional fields tolerated. Traces: AC-1,
  AC-2, AC-3, AC-8.
- **TC-AND-372-09** — Type: contract/MockWebServer. Target: JVM/Robolectric
  (error mapper). Preconditions: MockWebServer returns `403` with
  `ErrorEnvelope` body `{"error":{"code":"role_required","message":"…"}}`, and a
  separate `422` `HTTPValidationError` body. Steps: call service; map via
  `errorMessageFor`. Expected: 403 → `ApiResult.Error` carrying
  `error.message`; 422 → mapped from `detail`/`[{msg}]`; neither throws on the
  envelope shape. Traces: AC-4.
- **TC-AND-372-10** — Type: contract/MockWebServer (paging). Target:
  JVM/Robolectric (`PagingSource`/`RemoteMediator` fake). Preconditions:
  MockWebServer returns page 1 with `next_cursor="c2"` then page 2 with
  `next_cursor=null`. Steps: load page 1, then append. Expected: second request
  carries `cursor=c2`; append stops when `next_cursor` is null;
  `LoadState.Error` (enqueue a 500) → `retry()` re-requests. Traces: AC-2, AC-8.
- **TC-AND-372-11** — Type: Compose-UI. Target: emu35
  (`createAndroidComposeRule`, fake VMs). Preconditions: drive each state.
  Steps: set Loading/Empty/Error/Content/stale; tap a space row; tap a ticket
  row; tap Retry; pull-to-refresh. Expected: testTags `loading`/`empty`/`error`/
  `content`/`staleBanner` render for their state; row taps invoke the nav lambda
  with the correct `spaceId` then `(spaceId, ticketId)`; Retry calls
  `viewModel.retry()`; pull gesture calls `refresh()`; **no compose/reply
  affordance is present** (assert reply controls absent). Traces: AC-1, AC-2,
  AC-3, AC-4, AC-5, AC-7.
- **TC-AND-372-12** — Type: instrumented/e2e (acceptance smoke) +
  ABI/API sanity. Target: emu35 (CI gate) AND **A15 physical device** (must run
  on hardware for the arm64-v8a / API-34 vs x86_64 / API-35 sanity pass).
  Preconditions: in-process MockWebServer serving §5 spaces + tickets JSON; app
  launched to the tickets tab. Steps: launch → open first space → observe ticket
  list. Expected: spaces render then tickets render (the ticket's stated
  acceptance); identical behavior on emu35 and A15 (no ABI/API regressions, no
  cleartext-policy crash). Traces: AC-1, AC-2, AC-8. NOTE: the
  arm64-vs-x86 / API-34-vs-35 check MUST run on the A15; the CI gate itself runs
  on emu35.
- **TC-AND-372-13** — Type: instrumented (flaky-host/offline). Target: emu35.
  Preconditions: MockWebServer first seeds cache (200), then is configured to
  drop/delay the connection (simulating the unreliable dev host
  `18.222.237.167:8000` timeout). Steps: load once (cache fills) → force a
  refresh while the socket hangs past the ~20s call timeout. Expected: cached
  content stays visible with the "Showing saved data"/offline `StaleBanner`;
  no crash; subsequent successful refresh clears the banner. Traces: AC-5, AC-8
  (R1 mitigation).
- **TC-AND-372-14** — Type: Compose-UI (accessibility). Target: emu35
  (`createAndroidComposeRule` + semantics assertions). Preconditions: Content
  state with one space row, one ticket row, one thread with a "mine" and a
  "theirs" message. Steps: assert semantics. Expected: every row/status chip/
  state graphic has a non-empty `contentDescription`; status conveyed by
  text+color (not color alone); thread messages expose "author, time, message"
  and "mine"/"theirs" via text/semantics (not alignment alone); the stale banner
  is a `liveRegion`; touch targets ≥ 48dp; layout RTL-safe. Traces: AC-3, AC-5.

### Coverage matrix

| AC | Description | Test case(s) |
|----|-------------|--------------|
| AC-1 | Spaces load + render, tappable | TC-01, TC-07, TC-08, TC-11, TC-12 |
| AC-2 | Ticket list renders, paged | TC-07, TC-08, TC-10, TC-11, TC-12 |
| AC-3 | Thread oldest→newest, "mine", autoscroll | TC-06, TC-07, TC-08, TC-11, TC-14 |
| AC-4 | Loading/Empty/Error/Content + Retry; empty≠error | TC-02, TC-03, TC-06, TC-09, TC-11 |
| AC-5 | Stale banner on refresh fail; pull-to-refresh | TC-04, TC-11, TC-13, TC-14 |
| AC-6 | Terminal 401 → auth flow (no inline error) | TC-05 |
| AC-7 | Read-only (no compose/reply) | TC-11 |
| AC-8 | CI tests + MockWebServer smoke green | TC-08, TC-10, TC-12, TC-13 |
