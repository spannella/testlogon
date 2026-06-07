---
id: AND-121
title: Conversation list screen
milestone: M3
epic: E18
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-120, AND-024]
blocks: [AND-122]
---

# AND-121 — Conversation list screen

## 1. Overview & Goal

Deliver the user-facing **conversation list** screen for the messaging area of the
TestLogon Android app: a scrollable list of conversations, each rendered as a row
with an **avatar**, the **other party / title**, a **last-message preview**, a
**relative timestamp**, and an **unread indicator**. The screen supports
**pull-to-refresh** and a first-class **empty state**, and **opens a thread** when a
row is tapped. This is the landing destination of the Messaging tab introduced by the
authenticated nav graph (AND-024) and is the primary entry point into the messaging
epic (E18).

Scope is the **presentation layer for the list**: the Compose screen, its row
composables, the route wiring under the authenticated graph, and a thin
`ConversationListViewModel` shim that exposes a `StateFlow<ConversationListUiState>`
and a `refresh()`/`open(id)` surface. The screen consumes the typed `MessagingApi`
and DTOs from AND-120 to fetch `/messaging/conversations`. Full **Paging 3**
integration, unread aggregation, and sort ordering are owned downstream by AND-122
(Conversation list ViewModel + paging); this ticket establishes the screen contract,
the row UI, the state surfaces, and a single-page fetch so the screen renders real
data end-to-end and AND-122 can swap the data source behind the same `UiState`
without touching Compose.

Success: launching the Messaging tab against the dev backend renders real
conversations sorted newest-first; pulling down refreshes; an account with no
conversations shows the empty state; tapping a row navigates to the thread route with
the correct `conversationId`; loading/error/offline states render via the shared
`core-ui` state composables (AND-021).

## 2. Context & References

- **Module:** new `feature-messaging` module (layer `app -> feature-* -> core-*`).
  Depends on `core-network` (for `MessagingApi`/DTOs from AND-120), `core-model`,
  `core-ui` (theme + state composables), and `core-data` (auth/session state). No
  other feature module is referenced.
- **Package base:** `com.testlogon.android`. All classes in this ticket live under
  `com.testlogon.android.feature.messaging.list` and
  `com.testlogon.android.feature.messaging.nav`.
- **Depends on AND-120 (Messaging API + DTOs):** provides
  `MessagingApi.getConversations(...)`, `ConversationDto`, `MessageDto`,
  `ConversationListResponseDto` and Moshi adapters, validated against fixtures.
  This ticket consumes those types and must not redefine them.
- **Depends on AND-024 (Authenticated nav graph + bottom nav skeleton):** the
  Messaging tab destination and bottom-nav scaffold already exist; this ticket
  registers the list route as that tab's start destination and adds the thread route
  target.
- **Consumes AND-021 (state composables):** `LoadingState`, `EmptyState`,
  `ErrorState(onRetry)`, `OfflineBanner`/`StaleBanner`, and `AppScaffold` are reused
  verbatim — no bespoke spinners or error UI.
- **Consumes AND-018/AND-015 (ApiResult + error mapping):** repository returns
  `ApiResult<T>`; FastAPI `detail` is mapped per the shared `errorMessage()` rules.
- **Blocks AND-122 (ViewModel + paging):** AND-122 replaces the single-page loader
  with a Paging 3 `PagingSource`, unread aggregation, and sort, behind the same
  `ConversationListUiState` contract defined in §6.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext,
  unreliable). OpenAPI at `/openapi.json`. Web reference for shapes:
  `frontend/src/api/endpoints/messaging.ts` and `frontend/src/api/types.ts`.
- **Thread target:** the thread/detail screen is a sibling messaging ticket; this
  ticket only navigates to its route (`messaging/thread/{conversationId}`) and does
  not implement the thread UI.

## 3. Functional Requirements

1. **List rendering.** Display conversations in a `LazyColumn`. Each row shows:
   - **Avatar** (Coil-loaded from `ConversationOut.icon`; circular; initials
     placeholder fallback derived from `title` when null/blank or on load failure).
     CORRECTED: the backend has no `avatar_url`; the only image-ish field on
     `ConversationOut` is `icon` (nullable string). DM avatars are otherwise derived
     from `participants[]` (out of scope for the initials fallback here).
   - **Title** (`ConversationOut.title`, nullable), single line, ellipsized; falls
     back to a derived/placeholder name when null (no `counterpart_name` field
     exists on the backend — CORRECTED).
   - **Last-message preview** (`last_message_preview` top-level, else
     `last_message?.preview`), single line, ellipsized; shows "No messages yet" when
     null. CORRECTED: `MessageOut` exposes no `body` field; use `preview`.
   - **Relative timestamp** (`last_message_at`, else `created_at`) formatted as
     relative-to-now (e.g. "now", "5m", "3h", "Mon", "Apr 2"). CORRECTED: these are
     **integer epoch seconds**, not ISO-8601 strings, and there is no `updated_at`
     field; activity time is `last_message_at` (nullable int) with `created_at`
     (required int) as fallback.
   - **Unread indicator**: a filled badge showing `unread_count` when `> 0`; the
     title and preview render with emphasized weight/color when unread. No badge
     when `unread_count == 0`. (`unread_count` defaults to 0 server-side, so it is
     always present — CORRECTED from "nullable".)
2. **Sort.** Newest-activity-first using `lastActivityAt` (= `last_message_at`, else
   `created_at`). A stable secondary sort by `conversation_id`. (Full
   sort/aggregation hardened in AND-122; this ticket sorts the single fetched page.)
3. **Pull-to-refresh.** A Material 3 pull-to-refresh container wraps the list;
   gesture triggers `viewModel.refresh()` and shows the refresh spinner until the
   call settles. Refresh never clears already-rendered content on failure (stale
   content remains with an error/offline affordance).
4. **Empty state.** When the fetch succeeds with zero conversations, render
   `EmptyState` (icon + "No conversations yet" + supporting text). Distinct from the
   error and loading states.
5. **Loading state.** Initial load (no cached/prior content) renders `LoadingState`.
6. **Error / offline states.** Non-empty failures render `ErrorState(onRetry)` when
   no prior content exists; when prior content exists, keep content and surface a
   `StaleBanner`/`OfflineBanner` plus a snackbar. Offline (no connectivity / health
   probe down) maps to the offline surface, distinct from a server error.
7. **Open thread.** Tapping a row invokes `onOpenConversation(id)` →
   navigates to `messaging/thread/{conversationId}`. Row exposes a click ripple and
   is a single semantic accessibility target.
8. **Lifecycle.** First entry triggers an automatic load; returning to the tab does
   not force a refetch unless data is absent or explicitly refreshed (cache-friendly
   for AND-122).

Out of scope: composing/sending messages, thread UI, real-time updates, search,
archive/mute, multi-page paging (AND-122).

## 4. Technical Design

New `feature-messaging` module. Package roots under
`com.testlogon.android.feature.messaging`.

**State model** (`list/ConversationListUiState.kt`):

```kotlin
data class ConversationRow(
    val id: String,
    val title: String,
    val avatarUrl: String?,
    val preview: String?,        // null -> "No messages yet"
    val timestampEpochMs: Long?, // for relative formatting
    val unreadCount: Int,
) { val isUnread: Boolean get() = unreadCount > 0 }

sealed interface ConversationListUiState {
    data object Loading : ConversationListUiState
    data class Content(
        val rows: List<ConversationRow>,
        val isRefreshing: Boolean = false,
        val staleReason: StaleReason? = null, // non-null => banner over content
    ) : ConversationListUiState
    data object Empty : ConversationListUiState
    data class Error(val message: String, val offline: Boolean) : ConversationListUiState
}

enum class StaleReason { OFFLINE, SERVER_ERROR }
```

**Repository** (`data/ConversationRepository.kt`) — thin in this ticket; replaced/
extended by AND-122:

```kotlin
interface ConversationRepository {
    suspend fun getConversations(limit: Int = 30): ApiResult<List<ConversationRow>>
}

@Singleton
class ConversationRepositoryImpl @Inject constructor(
    private val api: MessagingApi,                 // from AND-120
    @Dispatcher(IO) private val io: CoroutineDispatcher,
) : ConversationRepository {
    override suspend fun getConversations(limit: Int): ApiResult<List<ConversationRow>> =
        withContext(io) {
            // CORRECTED: GET /messaging/conversations returns a BARE JSON ARRAY of
            // ConversationOut (no envelope, no next_cursor). AND-120 must model the
            // success body as List<ConversationDto>, not a ConversationListResponseDto
            // with an `items` field. `limit` is NOT a documented query param on this
            // endpoint (the web client optionally sends `cursor`); client-side `limit`
            // is applied post-fetch as a safety cap until AND-122 adds real paging.
            api.getConversations()                   // ApiResult<List<ConversationDto>>
                .map { list -> list.map(ConversationDto::toRow).sortedRows().take(limit) }
        }
}
```

**Mapping** (`data/ConversationMappers.kt`):

```kotlin
// CORRECTED field names to match backend ConversationOut:
//   id -> conversation_id; no counterpart_name; no avatar_url (use icon);
//   no updated_at (use last_message_at, else created_at);
//   timestamps are epoch SECONDS (Int/Long), so multiply by 1000 for ms;
//   no MessageOut.body (use preview / top-level last_message_preview).
internal fun ConversationDto.toRow(): ConversationRow = ConversationRow(
    id = conversationId,
    title = title?.ifBlank { null } ?: "Conversation",   // derive from participants in AND-122
    avatarUrl = icon,                                     // only image-ish field available
    preview = lastMessagePreview ?: lastMessage?.preview,
    timestampEpochMs = (lastMessageAt ?: createdAt)?.let { it * 1000L },
    unreadCount = unreadCount,                            // server default 0; non-null
)

internal fun List<ConversationRow>.sortedRows(): List<ConversationRow> =
    sortedWith(compareByDescending<ConversationRow> { it.timestampEpochMs ?: 0L }
        .thenBy { it.id })
```

**ViewModel** (`list/ConversationListViewModel.kt`):

```kotlin
@HiltViewModel
class ConversationListViewModel @Inject constructor(
    private val repository: ConversationRepository,
) : ViewModel() {
    private val _state = MutableStateFlow<ConversationListUiState>(Loading)
    val state: StateFlow<ConversationListUiState> = _state.asStateFlow()

    private val _events = MutableSharedFlow<ListEvent>(extraBufferCapacity = 8)
    val events: SharedFlow<ListEvent> = _events.asSharedFlow()

    init { load(initial = true) }

    fun refresh() = load(initial = false)
    fun retry() = load(initial = true)

    private fun load(initial: Boolean) {
        viewModelScope.launch {
            val prior = _state.value as? Content
            if (initial && prior == null) _state.value = Loading
            else if (prior != null) _state.value = prior.copy(isRefreshing = true)
            when (val r = repository.getConversations()) {
                is ApiResult.Success ->
                    _state.value = if (r.data.isEmpty()) Empty
                        else Content(rows = r.data, isRefreshing = false, staleReason = null)
                is ApiResult.Failure -> reduceFailure(r, prior)
            }
        }
    }
}

sealed interface ListEvent { data class OpenThread(val id: String) : ListEvent }
```

`reduceFailure` keeps `prior.rows` with a `staleReason` + emits a snackbar event when
content exists; otherwise emits `Error(message, offline)`.

**Screen** (`list/ConversationListScreen.kt`): stateless `ConversationListScreen`
takes `state`, `onRefresh`, `onRetry`, `onOpenConversation`; the route-level
`ConversationListRoute` collects state with
`collectAsStateWithLifecycle()` and wires the ViewModel + `NavController`.

```kotlin
@Composable
fun ConversationListRoute(
    onOpenConversation: (String) -> Unit,
    viewModel: ConversationListViewModel = hiltViewModel(),
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ConversationListScreen(
    state: ConversationListUiState,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onOpenConversation: (String) -> Unit,
)

@Composable
internal fun ConversationRowItem(row: ConversationRow, onClick: () -> Unit)
```

Pull-to-refresh uses `PullToRefreshBox` (Material3) bound to
`(state as? Content)?.isRefreshing == true`. State dispatch: `Loading` →
`LoadingState`; `Empty` → `EmptyState`; `Error` → `ErrorState`/offline surface;
`Content` → `PullToRefreshBox { LazyColumn { items(rows, key = { it.id }) {...} } }`
with `staleReason` rendered as a top banner.

**Navigation** (`nav/MessagingNavGraph.kt`): registers the list as the Messaging tab
start destination and exposes route constants.

```kotlin
object MessagingRoutes {
    const val LIST = "messaging/list"
    const val THREAD = "messaging/thread/{conversationId}"
    fun thread(id: String) = "messaging/thread/$id"
}

fun NavGraphBuilder.messagingGraph(navController: NavController) {
    composable(MessagingRoutes.LIST) {
        ConversationListRoute(onOpenConversation = { id ->
            navController.navigate(MessagingRoutes.thread(id))
        })
    }
    // thread destination provided by the thread-screen ticket
}
```

**Relative time** (`list/RelativeTime.kt`): `fun formatRelative(epochMs: Long, now:
Long = System.currentTimeMillis()): String` using `java.time` thresholds (<60s "now",
<60m "Nm", <24h "Nh", <7d weekday, else "MMM d"); locale-aware via `Locale.getDefault`.

## 5. API Contract

Consumed via `MessagingApi` (AND-120). Endpoint: `GET /messaging/conversations`
(verified: OpenAPI `op=list_conversations_messaging_conversations_get`).

Request — CORRECTED. OpenAPI documents **no `limit` query param**; the only declared
parameters are headers (`authorization`, `X-SESSION-ID`, `X-API-Key`). The web client
optionally sends a `cursor` query param. Session is carried by cookies + the CSRF
header (verified in `src/api/client.ts`: `ui_csrf` cookie echoed as `X-CSRF-Token`,
plus `Authorization: Bearer <accessToken>` and `credentials: include`):

```
GET /messaging/conversations HTTP/1.1
Cookie: <session cookies + ui_csrf>
X-CSRF-Token: <ui_csrf value>
Authorization: Bearer <accessToken>   # web sends this; Android per AND-011/AND-013
```

This is an **idempotent GET** → eligible for bounded backoff retry (AND-016) and a
~20s timeout (AND-009). On `401`, the OkHttp authenticator performs one
`POST /ui/session/refresh` then retries (AND-013); the screen does not handle 401
directly. (Verified: `POST /ui/session/refresh` exists and `src/api/client.ts`
refreshes once then retries.)

Success `200` response — CORRECTED. The body is a **bare JSON array** of
`ConversationOut` (OpenAPI: `type: array, items: ConversationOut`); there is **no
envelope and no `next_cursor`** on this endpoint. (The web `getConversations` also
defensively accepts an object shape keyed `conversations` — NOT `items`.) Real field
shape (verified against `components.schemas.ConversationOut`):

```json
[
  {
    "conversation_id": "conv_01HX...",
    "type": "dm",
    "status": "active",
    "title": "Ada Lovelace",
    "icon": "https://.../ada.png",
    "created_at": 1749132069,
    "created_by": "user_42",
    "participant_count": 2,
    "unread_count": 2,
    "last_message_at": 1749132069,
    "last_message_preview": "See you at 3?",
    "last_message": {
      "message_id": "msg_01HX...",
      "conversation_id": "conv_01HX...",
      "sender_id": "user_99",
      "kind": "text",
      "preview": "See you at 3?",
      "created_at": 1749132069
    }
  }
]
```

Notes on corrected fields: `conversation_id` (not `id`); `icon` is the only avatar-ish
field (no `avatar_url`); no `counterpart_name`; no `updated_at` (use `last_message_at`
→ `created_at`); timestamps are **integer epoch seconds**; `unread_count` defaults to
`0` (always present); `MessageOut` uses `sender_id` (not `author_id`) and `preview`
(no `body`). Required `ConversationOut` fields: `conversation_id`, `type`,
`created_at`, `created_by`, `participant_count`, `status`.

Empty: `[]` → `Empty` state. (CORRECTED from `{"items": [], "next_cursor": null}`.)

Error mapping (AND-015) — verified against `src/api/client.ts: normalizeErrorDetail`.
FastAPI `detail` may be a `string`, a `[{"msg": ...}]` array, or a structured object
`{"code": ..., "reason": ..., "message": ..., "required_scopes": [...]}`;
`errorMessage(detail)` extracts a user-safe string. `401` is handled by the
authenticator; `403` (e.g. `code=api_entitlement_denied` /
`code=api_key_scope_denied` with `required_scopes:["messager:read"]`), `429`
(`code=api_limit_exceeded`), `5xx`, and parse errors → `Error(message,
offline=false)`; `IOException`/timeout/health-down → `Error(..., offline=true)`.
This endpoint does **not** paginate, so AND-122's multi-page work will require a
different/cursor-bearing source (the documented response carries no cursor).

## 6. Data & State Management

- **Source of truth:** `ConversationListViewModel.state: StateFlow<...>`, collected
  with `collectAsStateWithLifecycle()`. The screen is a pure function of that state.
- **Contract for AND-122:** AND-122 must preserve the `ConversationListUiState`
  hierarchy and the `ConversationRow` shape so it can substitute a Paging 3
  `Flow<PagingData<ConversationRow>>` (wrapped/adapted to the same states) without
  changing `ConversationListScreen`. The `staleReason`, `isRefreshing`, and `key`
  semantics are part of that contract.
- **Caching:** none persisted in this ticket (in-memory `StateFlow` only). Room-based
  offline cache for conversations is downstream (paging/offline tickets). Returning
  to the tab reuses retained ViewModel state; process death re-loads.
- **Identity & diffing:** `LazyColumn` keys on `ConversationRow.id` for stable
  scroll/animation across refresh.
- **Threading:** network + mapping on `Dispatchers.IO` in the repository; state
  emitted on the main-safe `viewModelScope`.
- **Timestamps:** CORRECTED — the backend emits **integer epoch seconds** (verified:
  `ConversationOut.created_at`/`last_message_at` are `type: integer`; the web adapter
  coerces them via `toNum`). Convert seconds→ms at map time (`* 1000`) and format
  relative at render time so rows re-read "now" correctly without storing formatted
  strings.

## 7. Error Handling & Resilience

- **Transient GET failures:** rely on AND-016 bounded backoff (idempotent GET only)
  and AND-009 ~20s timeout. After exhaustion the repository returns
  `ApiResult.Failure`.
- **First-load failure (no content):** `Error(message, offline)` →
  full-screen `ErrorState(onRetry = viewModel::retry)` (server) or offline surface.
- **Refresh failure (content present):** keep existing rows, set
  `staleReason = OFFLINE|SERVER_ERROR`, clear `isRefreshing`, and emit a one-shot
  snackbar ("Couldn't refresh — showing older messages"). The banner stays until a
  successful refresh.
- **Offline detection:** `IOException`/`SocketTimeoutException`/health-probe-down
  (AND-017) → `offline = true` / `StaleReason.OFFLINE`. Distinct copy and icon from
  server errors.
- **401:** never surfaces here; handled by the refresh authenticator (AND-013). If
  refresh ultimately fails, auth-gated routing (AND-025) redirects to login.
- **Avatar load failure:** Coil falls back to the initials placeholder; never blocks
  the row or crashes.
- **Empty vs error:** zero items on a `200` is `Empty`, never `Error`.

## 8. Security & Privacy

- **Transport:** dev backend is plaintext HTTP via the configured base URL and
  cleartext allowance (build-flavor scoped, AND-006). No new network security config
  introduced here. Production base URL must be HTTPS.
- **Session/CSRF:** requests ride the persistent cookie jar (AND-011) and the CSRF
  interceptor echoing `ui_csrf` as `X-CSRF-Token` (AND-012). This screen issues only
  authenticated GETs; no credentials handled in the feature module.
- **No secret logging:** never log cookies, CSRF tokens, message bodies, avatar URLs,
  or full conversation payloads. Telemetry uses counts/durations and opaque ids only
  (see §10). Message previews and titles are PII and must not appear in logs/crash
  reports.
- **Images:** Coil loads avatars over the same OkHttp client/cookie jar; no
  third-party image CDN credentials embedded.

## 9. Accessibility & i18n

- **Row semantics:** each row is one merged semantic node with a content description
  composed of title + unread + relative time, e.g. "Ada Lovelace, 2 unread, 5 minutes
  ago, See you at 3?". `Modifier.semantics(mergeDescendants = true)` with
  `role = Role.Button`.
- **Touch targets:** rows ≥ 56dp tall; tap target ≥ 48dp.
- **Unread:** not color-only — paired with the badge count and bold weight so it is
  perceivable without color; badge exposes `contentDescription`.
- **Avatars:** decorative image gets `contentDescription = null`; identity conveyed by
  the row text.
- **Dynamic type / dark mode:** all type from `MaterialTheme.typography`; layout
  reflows at large font scales (no fixed-height text clipping). Verified light/dark.
- **i18n:** all strings in `feature-messaging/src/main/res/values/strings.xml`
  (`conv_list_empty_title`, `conv_list_empty_body`, `conv_list_error`,
  `conv_list_offline`, `conv_list_no_messages`, `conv_list_refresh_failed`,
  `conv_unread_badge` with plural). Relative time uses locale-aware `java.time`
  formatting; no hard-coded date strings. RTL-safe via start/end paddings.

## 10. Telemetry & Logging

- **Events** (via the shared analytics interface; PII-free):
  - `messaging_list_view` — on first composition.
  - `messaging_list_load` — `{ result: success|error|offline, count: Int,
    duration_ms: Long, refresh: Bool }`.
  - `messaging_list_refresh` — `{ result }`.
  - `messaging_conversation_open` — `{ unread: Bool }` (no conversation id in
    analytics; id stays in-process only).
- **Logging:** `Timber` tag `MessagingList`; debug-level for state transitions and
  load durations. No bodies, titles, ids-with-PII, cookies, or tokens. Errors logged
  with the mapped user-safe message + HTTP status code only.

## 11. Testing Strategy

- **Unit — mappers (`ConversationMappersTest`):** `ConversationDto.toRow` for
  null/blank title fallback, null `lastMessage` → "No messages yet" preview,
  `unread_count` null → 0; `sortedRows()` newest-first with stable id tiebreak.
- **Unit — relative time (`RelativeTimeTest`):** boundary cases (59s→"now", 61s→"1m",
  23h, 25h→weekday, 8d→date) with a fixed `now`.
- **Unit — ViewModel (`ConversationListViewModelTest`)** with a fake repository +
  `MainDispatcherRule`/Turbine:
  - success non-empty → `Loading` → `Content` sorted.
  - success empty → `Empty`.
  - first-load failure → `Error(offline=false)`; `IOException` → `Error(offline=true)`.
  - refresh-with-content failure → content retained, `staleReason` set,
    `isRefreshing` cleared, snackbar event emitted.
  - `retry()` after error re-fetches and recovers.
- **Repository contract (`ConversationRepositoryTest`)** with MockWebServer harness
  (AND-046): canned `/messaging/conversations` fixture → mapped rows; empty fixture;
  500 → `Failure`; verifies query `limit`.
- **Compose UI (`ConversationListScreenTest`):**
  - `Content` renders N rows with title/preview/timestamp; unread badge shows only
    when `unreadCount > 0`.
  - `Empty`/`Loading`/`Error` render the correct `core-ui` surface; Error retry
    callback fires.
  - row click invokes `onOpenConversation(id)` with the correct id.
  - pull-to-refresh gesture invokes `onRefresh` (or assert via `isRefreshing` state).
  - semantics: row content description includes title + unread + time.
- **Fixtures** live in `core-testing`/feature test resources, shared with AND-120.

## 12. Dependencies & Sequencing

- **Hard deps:** **AND-120** (MessagingApi + DTOs — consumed for the fetch) and
  **AND-024** (authenticated nav graph + bottom-nav skeleton — host for the route).
- **Reuses:** AND-021 (state composables), AND-019 (theme), AND-018 (ApiResult),
  AND-015 (error mapping), AND-016 (GET retry), AND-009/AND-011/AND-012/AND-013
  (network/session stack), AND-017 (connectivity/health for offline state).
- **Blocks / hands off to:** **AND-122** (ViewModel + Paging 3, unread aggregation,
  sort) — substitutes the data source behind the `ConversationListUiState` contract
  defined in §6; and the thread/detail screen ticket, which owns the
  `messaging/thread/{conversationId}` destination this screen navigates to.
- **Sequencing:** land after AND-120 + AND-024; the single-page loader here is the
  seam AND-122 replaces. The thread route may be a stub until its ticket lands; the
  list must still navigate to it.

## 13. Risks & Open Questions

- **DTO field names vs OpenAPI — RESOLVED in this review (§16).** Verified against
  `components.schemas.ConversationOut`/`MessageOut` and the web client: `id`→
  `conversation_id`; `counterpart_name` and `avatar_url` do **not** exist (`icon` is
  the only image field); `updated_at` does **not** exist (use `last_message_at` →
  `created_at`); timestamps are epoch **seconds**; the response is a **bare array**
  with **no `next_cursor`**; `MessageOut` uses `sender_id`/`preview` (no
  `author_id`/`body`). `toRow` and the API DTO have been corrected accordingly.
- **Unread semantics.** Whether `unread_count` is server-authoritative or must be
  aggregated client-side is decided in AND-122; this ticket trusts the server value.
- **Pull-to-refresh on stale content.** Confirm desired UX: keep stale rows + banner
  (chosen) vs. clearing to error. Decision: keep content (resilience-first per dev
  backend reliability).
- **Avatar source.** If the backend returns no `avatar_url`, initials fallback is
  used; confirm whether a Gravatar-style derivation is desired (out of scope now).
- **Thread route availability.** If the thread screen ticket lands later, navigation
  targets a placeholder; ensure no crash on an unregistered route (stub composable).
- **Timestamp source field — RESOLVED.** There is no `updated_at`; precedence is
  `last_message_at` → `created_at` (both epoch seconds). Confirmed against OpenAPI.

## 14. Acceptance Criteria

1. **Renders from backend:** with a valid session against the dev backend, the
   Messaging tab loads and displays conversations from `GET /messaging/conversations`,
   each row showing avatar (or initials), title, last-message preview, relative
   timestamp, and an unread badge when `unread_count > 0`. (Source acceptance:
   "Renders conversations from backend".)
2. **Opens a thread:** tapping a row navigates to `messaging/thread/{conversationId}`
   with the tapped conversation's id. (Source acceptance: "opens a thread".)
3. **Sort:** rows are ordered newest-activity-first (verified by unit test on
   `sortedRows()` and a UI assertion on order).
4. **Pull-to-refresh:** the pull gesture triggers a re-fetch and shows the refresh
   spinner; successful refresh updates rows.
5. **Empty state:** an account/response with zero conversations renders the
   `EmptyState` surface, not an error.
6. **Loading/error/offline:** first load shows `LoadingState`; a failed first load
   shows `ErrorState` with a working retry; an offline failure shows the offline
   surface; a failed refresh with existing content keeps the content and shows a
   stale banner + snackbar.
7. **Accessibility:** each row is a single button-role semantic node whose
   description includes title, unread state, and relative time; unread is not
   color-only.
8. **No PII leakage:** message bodies/titles/cookies/CSRF tokens never appear in logs
   or analytics (asserted by review + log inspection).

## 15. Definition of Done

- `feature-messaging` module created and wired into `app`; list route registered as
  the Messaging tab start destination (AND-024) and navigates to the thread route.
- `ConversationListScreen`, `ConversationRowItem`, `ConversationListViewModel`,
  `ConversationRepository(Impl)`, mappers, and relative-time formatter implemented in
  `com.testlogon.android.feature.messaging.*` against AND-120 types.
- All §11 unit, repository-contract (MockWebServer), and Compose UI tests pass in CI
  (AND-008/AND-050); no flaky pull-to-refresh tests.
- ktlint/detekt clean (AND-005); strings externalized; light/dark + large-font
  layouts verified.
- Manual verification against `http://18.222.237.167:8000`: list renders, refresh
  works, empty/error/offline reachable, row tap opens the thread route.
- `ConversationListUiState`/`ConversationRow` contract documented (§6) so AND-122 can
  swap in Paging 3 without changing the Compose layer.
- Spec reviewed; telemetry/logging confirmed PII-free; merged to `android-port`.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the authoritative source pointer.

1. **Endpoint is `GET /messaging/conversations`.** VERIFIED. OpenAPI
   `GET /messaging/conversations` (op `list_conversations_messaging_conversations_get`);
   frontend `src/api/endpoints/messaging.ts: getConversations`.
2. **Success `200` body is a bare JSON array of `ConversationOut` (no envelope, no
   `next_cursor`).** CORRECTED (spec claimed `{items:[], next_cursor}`). OpenAPI
   `GET /messaging/conversations` → `200` schema `{type: array, items:
   ConversationOut}`; frontend `src/api/endpoints/messaging.ts: getConversations`
   ("Backend returns a plain array"; its defensive object shape is keyed
   `conversations`, not `items`).
3. **Request query param `limit=30`.** CORRECTED → removed. OpenAPI declares only
   header params (`authorization`, `X-SESSION-ID`, `X-API-Key`) for this op; the web
   client optionally sends `cursor` (`src/api/endpoints/messaging.ts`). `limit` is now
   documented as a client-side post-fetch cap only.
4. **Conversation id field is `id`.** CORRECTED → `conversation_id`. OpenAPI
   `components.schemas.ConversationOut.conversation_id` (required);
   `src/api/endpoints/messagingAdapter.ts: adaptConversation`.
5. **`counterpart_name` field exists.** CORRECTED → does not exist. Not present in
   `components.schemas.ConversationOut` (fields: `title`, `topic`, `icon`,
   `participants[]`, …). Title fallback must derive from participants (AND-122).
6. **Avatar field is `avatar_url`.** CORRECTED → `icon` (nullable). OpenAPI
   `ConversationOut.icon`; no `avatar_url` in the schema. (`MessageOut.bot_avatar_url`
   exists but is unrelated.)
7. **Activity timestamp field is `updated_at` (ISO-8601 string).** CORRECTED → no
   `updated_at`; use `last_message_at` (nullable int) → `created_at` (required int),
   both **epoch seconds**. OpenAPI `ConversationOut.last_message_at`/`created_at`
   (`type: integer`); `src/api/endpoints/messagingAdapter.ts` coerces via `toNum`.
8. **`unread_count` is nullable.** CORRECTED → integer with server `default: 0`
   (always present). OpenAPI `ConversationOut.unread_count`.
9. **Last-message preview from `last_message.body`/`last_message.preview`.** CORRECTED
   → `MessageOut` has no `body`; use top-level `last_message_preview` else
   `last_message.preview`. OpenAPI `ConversationOut.last_message_preview` and
   `components.schemas.MessageOut` (has `preview`, no `body`/`text` property).
10. **Message author field is `author_id`.** CORRECTED → `sender_id`. OpenAPI
    `components.schemas.MessageOut.sender_id`; `messagingAdapter.ts: adaptMessage`.
11. **CSRF: `ui_csrf` cookie echoed as `X-CSRF-Token` header.** VERIFIED.
    `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`).
12. **401 → one `POST /ui/session/refresh` then retry; screen does not handle 401.**
    VERIFIED. OpenAPI `POST /ui/session/refresh` exists; `src/api/client.ts`
    `refreshSession()` + single retry on 401.
13. **Auth transport rides the cookie jar.** VERIFIED + AUGMENTED. Web uses cookies
    (`credentials: "include"`) AND `Authorization: Bearer <accessToken>`
    (`src/api/client.ts`); backend also accepts `X-SESSION-ID`/`X-API-Key` (OpenAPI
    params). Note added that Bearer is also sent.
14. **Error `detail` may be string / `[{msg}]` array / `{code:...}` object.**
    VERIFIED. `src/api/client.ts: normalizeErrorDetail` + OpenAPI `403`/`429` examples
    (`api_entitlement_denied`, `api_key_scope_denied` w/ `required_scopes`,
    `api_limit_exceeded`); `422` = `HTTPValidationError`.
15. **422 validation error schema.** VERIFIED. OpenAPI `GET /messaging/conversations`
    `422: HTTPValidationError`.
16. **`PullToRefreshBox` is the Material 3 pull-to-refresh API.** Unverified-assumption
    (framework ref). Android docs:
    https://developer.android.com/reference/kotlin/androidx/compose/material3/pulltorefresh/package-summary
    — not verifiable from the backend/frontend sources; standard M3 Compose component.
17. **`collectAsStateWithLifecycle()` for state collection.** Unverified-assumption
    (framework ref). Android docs:
    https://developer.android.com/topic/libraries/architecture/compose#lifecycleawarecollectasstate
18. **Coil for avatar loading over the shared OkHttp client.** Unverified-assumption
    (framework ref). Coil docs: https://coil-kt.github.io/coil/ — framework choice,
    not in scope of the backend/frontend contract.
19. **`messaging/thread/{conversationId}` route target.** Unverified-assumption — the
    thread screen is a sibling ticket; the route string is an internal Android
    navigation contract, not derivable from the backend or web sources.
20. **Telemetry event names / payloads (`messaging_list_*`).** Unverified-assumption —
    internal analytics contract; not present in the backend/frontend sources.

### Corrections made

- §3, §4, §5, §6, §13: response is a **bare array**, not `{items, next_cursor}`; the
  endpoint has **no pagination cursor**.
- §3, §4, §5: field renames — `id`→`conversation_id`, drop `counterpart_name`,
  `avatar_url`→`icon`, drop `updated_at` (use `last_message_at`→`created_at`),
  `author_id`→`sender_id`, drop `MessageOut.body` (use `preview`/`last_message_preview`).
- §3, §4, §6: timestamps are **epoch seconds** (×1000 → ms), not ISO-8601 strings.
- §3: `unread_count` is non-null (server default 0), not nullable.
- §5: removed the `limit` query param (header-only params per OpenAPI; web uses
  `cursor`); documented Bearer token in addition to cookies; enriched the `403`/`429`
  error-shape catalog with real codes.
- Frontmatter: `status: reviewed`, added `reviewed_on: 2026-06-06`.

### Open assumptions

- **Material 3 `PullToRefreshBox`, `collectAsStateWithLifecycle`, Coil** (items 16–18):
  Android-framework choices; correct per current Android docs but outside the
  backend/frontend contract, so not "verified" against the authoritative sources here.
- **Thread route string and analytics event names** (items 19–20): internal Android
  contracts owned by sibling/this ticket; no upstream source to verify against.
- **DM title/avatar derivation from `participants[]`**: the backend returns a
  `participants[]` array but this ticket only renders `title`/`icon`; the precise
  derivation of a counterpart display name/avatar for DMs is deferred to AND-122 and
  is currently an assumption.
- **AND-120 DTO modeling**: this spec assumes AND-120 will model the success body as
  `List<ConversationDto>` matching `ConversationOut`. AND-120 is authoritative; if it
  diverges, the §4 mapper is the only thing to adjust.

## 17. Test Plan

Test target legend: **JVM** = JVM/Robolectric local unit (no device); **MWS** =
contract test with MockWebServer; **EMU** = headless emulator AVD `test35` (x86_64,
API 35); **DEV** = physical Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, API
34, arm64-v8a). This screen has no camera/biometric/WebRTC/FCM/Telecom behavior, so
most instrumented cases run fine on **EMU**; one ABI/API-parity smoke runs on **DEV**.

- **TC-AND-121-01 — Mapper: full ConversationOut → ConversationRow.**
  Type: unit (JVM). Target: `ConversationMappersTest`. Preconditions: a
  `ConversationDto` with `conversation_id`, `title`, `icon`, `last_message_preview`,
  `last_message_at` (epoch s), `unread_count=2`. Steps: call `toRow()`. Expected:
  `id=conversation_id`, `avatarUrl=icon`, `preview=last_message_preview`,
  `timestampEpochMs = last_message_at * 1000`, `unreadCount=2`, `isUnread=true`.
  Traces: AC-1, AC-3.

- **TC-AND-121-02 — Mapper: fallbacks (null title/icon/preview, no last message).**
  Type: unit (JVM). Target: `ConversationMappersTest`. Preconditions: dto with
  `title=null`/blank, `icon=null`, `last_message=null`, `last_message_preview=null`,
  `unread_count=0`, valid `created_at`. Steps: `toRow()`. Expected: `title` falls back
  to placeholder, `avatarUrl=null` (initials path), `preview=null` (→ "No messages
  yet" at render), `timestampEpochMs = created_at*1000`, `unreadCount=0`,
  `isUnread=false`. Traces: AC-1.

- **TC-AND-121-03 — Sort: newest-activity-first with stable id tiebreak.**
  Type: unit (JVM). Target: `ConversationMappersTest`. Preconditions: rows with mixed
  `timestampEpochMs` incl. one null and two equal timestamps. Steps: `sortedRows()`.
  Expected: descending by timestamp (null → oldest), equal timestamps ordered by
  `conversation_id`. Traces: AC-3.

- **TC-AND-121-04 — Relative time boundaries.**
  Type: unit (JVM). Target: `RelativeTimeTest`. Preconditions: fixed `now`. Steps:
  format 59s, 61s, 23h, 25h, 8d offsets. Expected: "now", "1m", "23h", weekday,
  "MMM d". Traces: AC-1.

- **TC-AND-121-05 — Repository contract: array body → mapped rows + correct request.**
  Type: contract/MockWebServer (MWS). Target: `ConversationRepositoryTest`.
  Preconditions: MWS enqueues `200` with a **bare JSON array** fixture (matching §5).
  Steps: call `getConversations()`; capture the recorded request. Expected: rows
  mapped and sorted; recorded request is `GET /messaging/conversations`, carries
  `X-CSRF-Token` and session credentials, and does **not** rely on an `items`
  envelope. Traces: AC-1.

- **TC-AND-121-06 — Repository contract: empty array → empty success (not error).**
  Type: contract/MockWebServer (MWS). Target: `ConversationRepositoryTest`.
  Preconditions: MWS enqueues `200` body `[]`. Steps: `getConversations()`. Expected:
  `ApiResult.Success` with empty list. Traces: AC-5.

- **TC-AND-121-07 — Repository contract: error responses map correctly.**
  Type: contract/MockWebServer (MWS). Target: `ConversationRepositoryTest`.
  Preconditions: MWS enqueues, across runs, `403`
  `{"detail":{"code":"api_key_scope_denied","required_scopes":["messager:read"]}}`,
  `429` `{"detail":{"code":"api_limit_exceeded"}}`, `422` `HTTPValidationError`, and
  `500`. Steps: `getConversations()` each. Expected: `ApiResult.Failure` with a
  user-safe message extracted per the polymorphic `detail` rules; `offline=false`.
  Traces: AC-6.

- **TC-AND-121-08 — ViewModel state machine (happy + empty + error + offline).**
  Type: unit (JVM, Turbine + `MainDispatcherRule`). Target:
  `ConversationListViewModelTest`. Preconditions: fake repository. Steps: drive
  success-nonempty, success-empty, server `Failure`, and `IOException` `Failure` on
  first load. Expected: `Loading→Content(sorted)`; `Loading→Empty`;
  `Loading→Error(offline=false)`; `Loading→Error(offline=true)`. Traces: AC-1, AC-3,
  AC-5, AC-6.

- **TC-AND-121-09 — ViewModel refresh-with-content failure keeps stale content.**
  Type: unit (JVM, Turbine). Target: `ConversationListViewModelTest`. Preconditions:
  prior `Content` state. Steps: `refresh()` with repo returning `IOException` failure.
  Expected: rows retained, `staleReason=OFFLINE`, `isRefreshing=false`, and one
  snackbar `ListEvent` emitted; a subsequent successful `refresh()`/`retry()` clears
  the banner. Traces: AC-4, AC-6.

- **TC-AND-121-10 — Compose: Content renders rows; unread badge gated on count.**
  Type: Compose-UI (EMU). Target: `ConversationListScreenTest`. Preconditions:
  `Content` with one unread (`unreadCount=2`) and one read row. Steps: assert title,
  preview, timestamp text; assert badge present on unread row and absent on read row;
  assert "No messages yet" for a null-preview row. Traces: AC-1.

- **TC-AND-121-11 — Compose: Loading/Empty/Error surfaces + working retry.**
  Type: Compose-UI (EMU). Target: `ConversationListScreenTest`. Preconditions: each
  state in turn. Steps: assert `LoadingState`, `EmptyState`, `ErrorState` render;
  click retry. Expected: correct `core-ui` surface per state; `onRetry` invoked once.
  Traces: AC-5, AC-6.

- **TC-AND-121-12 — Compose: row tap opens thread with correct id; pull-to-refresh.**
  Type: Compose-UI (EMU). Target: `ConversationListScreenTest`. Preconditions:
  `Content` with known ids. Steps: tap a row; perform pull-to-refresh gesture (or
  assert `isRefreshing` spinner from state). Expected: `onOpenConversation(id)` fires
  with the tapped `conversation_id`; `onRefresh` invoked. Traces: AC-2, AC-4.

- **TC-AND-121-13 — Accessibility: row semantics + non-color-only unread.**
  Type: Compose-UI / instrumented (EMU). Target: `ConversationListScreenTest`.
  Preconditions: `Content` with one unread row. Steps: read merged semantics; assert
  `Role.Button`, content description includes title + unread + relative time; assert
  unread is conveyed by badge text/bold weight (not color alone); assert tap target
  ≥ 48dp / row ≥ 56dp. Traces: AC-7.

- **TC-AND-121-14 — Security: no PII/secret leakage in logs or analytics.**
  Type: integration / manual. Target: `ConversationListViewModel` + Timber +
  analytics. Preconditions: capturing Timber tree + fake analytics sink; load real
  conversations. Steps: exercise load/refresh/open; inspect captured logs and analytics
  payloads. Expected: no message previews, titles, cookies, `X-CSRF-Token`/`ui_csrf`,
  Bearer token, or conversation ids in analytics; logs carry only counts/durations,
  mapped messages, and HTTP status. Traces: AC-8.

- **TC-AND-121-15 — End-to-end on physical device (ABI/API parity smoke).**
  Type: instrumented/e2e (DEV — MUST run on the Samsung Galaxy A15 5G, serial
  R5CX821TA9R; arm64-v8a / API 34 vs the emulator's x86_64 / API 35). Preconditions:
  valid session against `http://18.222.237.167:8000`; cleartext dev flavor. Steps:
  open the Messaging tab; observe list render; pull-to-refresh; toggle airplane mode
  and refresh to hit the offline/stale path; tap a row. Expected: real conversations
  render newest-first; refresh works; offline shows the stale banner + snackbar with
  content retained; row tap navigates to `messaging/thread/{conversationId}`; no
  arm64/API-34-specific crash (`java.time` relative formatting, Coil decode). Runs on
  DEV to catch ABI- and API-level differences the x86_64/API-35 emulator can miss.
  Traces: AC-1, AC-2, AC-4, AC-6.

### Coverage matrix

| AC (§14) | Covered by |
| --- | --- |
| AC-1 Renders from backend | TC-01, TC-02, TC-04, TC-05, TC-08, TC-10, TC-15 |
| AC-2 Opens a thread | TC-12, TC-15 |
| AC-3 Sort newest-first | TC-01, TC-03, TC-08 |
| AC-4 Pull-to-refresh | TC-09, TC-12, TC-15 |
| AC-5 Empty state | TC-06, TC-08, TC-11 |
| AC-6 Loading/error/offline | TC-07, TC-08, TC-09, TC-11, TC-15 |
| AC-7 Accessibility | TC-13 |
| AC-8 No PII leakage | TC-14 |
