---
id: AND-121
title: Conversation list screen
milestone: M3
epic: E18
priority: P0
size: M
status: draft
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
   - **Avatar** (Coil-loaded from `ConversationDto.avatarUrl`; circular; initials
     placeholder fallback derived from `title` when null/blank or on load failure).
   - **Title** (`ConversationDto.title`), single line, ellipsized.
   - **Last-message preview** (`lastMessage?.preview` or `lastMessage?.body`
     truncated), single line, ellipsized; shows "No messages yet" when null.
   - **Relative timestamp** (`lastMessage?.createdAt` or
     `conversation.updatedAt`) formatted as relative-to-now (e.g. "now", "5m",
     "3h", "Mon", "Apr 2").
   - **Unread indicator**: a filled badge showing `unreadCount` when `> 0`; the
     title and preview render with emphasized weight/color when unread. No badge
     when `unreadCount == 0`.
2. **Sort.** Newest-activity-first using `lastActivityAt` (last message time, else
   `updatedAt`). A stable secondary sort by `id`. (Full sort/aggregation hardened in
   AND-122; this ticket sorts the single fetched page.)
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
            api.getConversations(limit = limit)      // ApiResult<ConversationListResponseDto>
                .map { dto -> dto.items.map(ConversationDto::toRow).sortedRows() }
        }
}
```

**Mapping** (`data/ConversationMappers.kt`):

```kotlin
internal fun ConversationDto.toRow(): ConversationRow = ConversationRow(
    id = id,
    title = title ?: counterpartName.orEmpty().ifBlank { "Conversation" },
    avatarUrl = avatarUrl,
    preview = lastMessage?.let { it.preview ?: it.body },
    timestampEpochMs = (lastMessage?.createdAt ?: updatedAt)?.toEpochMillisOrNull(),
    unreadCount = unreadCount ?: 0,
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

Consumed via `MessagingApi` (AND-120). Endpoint: `GET /messaging/conversations`.

Request (query params, all optional this ticket uses `limit`):

```
GET /messaging/conversations?limit=30 HTTP/1.1
Cookie: <session cookies + ui_csrf>
X-CSRF-Token: <ui_csrf value>
```

This is an **idempotent GET** → eligible for bounded backoff retry (AND-016) and a
~20s timeout (AND-009). On `401`, the OkHttp authenticator performs one
`POST /ui/session/refresh` then retries (AND-013); the screen does not handle 401
directly.

Success `200` response (shape per AND-120 DTOs; representative):

```json
{
  "items": [
    {
      "id": "conv_01HX...",
      "title": "Ada Lovelace",
      "counterpart_name": "Ada Lovelace",
      "avatar_url": "https://.../ada.png",
      "unread_count": 2,
      "updated_at": "2026-06-05T14:21:09Z",
      "last_message": {
        "id": "msg_01HX...",
        "body": "See you at 3?",
        "preview": "See you at 3?",
        "author_id": "user_99",
        "created_at": "2026-06-05T14:21:09Z"
      }
    }
  ],
  "next_cursor": null
}
```

Empty: `{"items": [], "next_cursor": null}` → `Empty` state.

Error mapping (AND-015): FastAPI `detail` may be a `string`, a `[{"msg": ...}]`
array, or a `{"code": ...}` object; `errorMessage(detail)` extracts a user-safe
string. `401` is handled by the authenticator; `403`/`5xx`/parse errors →
`Error(message, offline=false)`; `IOException`/timeout/health-down →
`Error(..., offline=true)`. Paging (`next_cursor`) is parsed but unused here; AND-122
owns multi-page consumption.

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
- **Timestamps:** server emits ISO-8601 UTC; converted to epoch-ms at map time and
  formatted relative at render time so rows re-read "now" correctly without storing
  formatted strings.

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

- **DTO field names vs OpenAPI.** Exact field names (`counterpart_name`, `preview`,
  `unread_count`, `next_cursor`) are assumed from the web reference; AND-120 is
  authoritative. Confirm against `/openapi.json` and `frontend/src/api/types.ts`
  before merge; adjust `toRow` mapping only.
- **Unread semantics.** Whether `unread_count` is server-authoritative or must be
  aggregated client-side is decided in AND-122; this ticket trusts the server value.
- **Pull-to-refresh on stale content.** Confirm desired UX: keep stale rows + banner
  (chosen) vs. clearing to error. Decision: keep content (resilience-first per dev
  backend reliability).
- **Avatar source.** If the backend returns no `avatar_url`, initials fallback is
  used; confirm whether a Gravatar-style derivation is desired (out of scope now).
- **Thread route availability.** If the thread screen ticket lands later, navigation
  targets a placeholder; ensure no crash on an unregistered route (stub composable).
- **Timestamp source field.** `last_message.created_at` vs `updated_at` precedence
  confirmed with backend; current rule prefers last message time.

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
