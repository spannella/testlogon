---
id: AND-239
title: Fan-club channel messages
milestone: M5
epic: E32
priority: P1
size: L
status: draft
depends_on: [AND-238, AND-126]
blocks: []
---

# AND-239 — Fan-club channel messages

## 1. Overview & Goal

Render, paginate, post, react to, and delete messages within a single fan-club
channel. This ticket implements the message *timeline* for a channel selected
from the channels list (AND-238), reusing the sealed message domain model and
mappers from AND-126. The deliverable is a `:feature-fanclub` screen
(`ChannelMessagesScreen`) plus its `ChannelMessagesViewModel`, repository,
Retrofit service, and Paging 3 wiring against
`/ui/fan-club/channels/{id}/messages` and the associated react/delete endpoints.

Goal: a user who opens a fan-club channel sees the most recent messages
(newest-anchored, scroll-up to load older), can compose and send a text message,
can add/remove an emoji reaction on any message, and can delete their own
messages. Optimistic UI is applied to post/react/delete with rollback on
failure. The screen tolerates the unreliable dev backend (timeouts, 401 refresh,
stale/offline states).

Non-goals (owned elsewhere): rich-media composition (image/video/voice/poll
authoring) is rendered read-only here via AND-126's renderers but **not**
composed in this ticket; channel discovery/tier gating is AND-238; the sealed
model and per-type mappers are AND-126; realtime push/WebSocket delivery is out
of scope (polling/pull-to-refresh only).

## 2. Context & References

- Module layering: `app -> feature-fanclub -> core-* (core-network, core-model,
  core-ui, core-data, core-testing)`. This ticket lives in `:feature-fanclub`
  with the new service in `:core-network` and DTO→domain mappers reused from
  `:core-model` (AND-126).
- Namespace / applicationId base: `com.testlogon.android`. Feature package:
  `com.testlogon.android.feature.fanclub.messages`.
- Stack: Kotlin 2.0.21, Compose + Material 3, Navigation-Compose, Hilt (KSP),
  Coroutines/Flow, Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15, Room 2.6, Paging 3,
  Coil, Media3/ExoPlayer 1.4. minSdk 24 / target 35, JDK 17.
- Backend: FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext,
  unreliable). OpenAPI at `/openapi.json`. Cookie-based session with `ui_csrf`
  echoed as `X-CSRF-Token`; on 401 call `POST /ui/session/refresh` once then
  retry (handled by the shared OkHttp `Authenticator`/interceptor from core auth).
- Web reference: `frontend/src/api/endpoints/*.ts` (fan-club message endpoints)
  and `frontend/src/api/types.ts` (message/reaction shapes). Mirror field names
  and the `detail` error union there.
- Upstream tickets: **AND-238** (channels list) supplies the `channelId` nav arg
  and channel header metadata; **AND-126** supplies `Message` (sealed),
  `MessageReaction`, `MessageAttachment`, and `MessageMapper`.

## 3. Functional Requirements

FR-1 Display a chronological message list for a given `channelId`, newest at the
bottom, with the list initially scrolled to the newest message.

FR-2 Paginate older messages on scroll-to-top using Paging 3 with cursor-based
keys (`before` cursor). Page size 30.

FR-3 Pull-to-refresh re-fetches the newest page and invalidates the pager.

FR-4 Render every message type from AND-126's sealed `Message` model
(text/image/video/file/voice/gif/sticker/poll/countdown/calendar/system) using
existing per-type composables; unknown/future types fall back to a graceful
"Unsupported message" placeholder rather than crashing.

FR-5 Compose and send a **text** message via the composer bar; on send the
message appears optimistically with a `Sending` status, then resolves to `Sent`
or `Failed` (with retry affordance).

FR-6 Add or remove an emoji reaction on any message. Reaction toggles
optimistically; the per-emoji count and the current-user "reacted" flag update
immediately and reconcile with the server response.

FR-7 Delete a message the current user authored (long-press → context menu →
Delete, with a confirm dialog). Deleted messages are removed optimistically and
restored on failure.

FR-8 Show distinct UI states: initial Loading, Empty ("No messages yet"),
Content, append/prepend Loading footer/header, and Error (full-screen for
initial-load failure, inline snackbar for action failures).

FR-9 The composer is disabled with an explanatory hint when the user lacks
post permission in the channel (server returns 403 on send) or when offline.

## 4. Technical Design

Package `com.testlogon.android.feature.fanclub.messages`.

Navigation entry (registered in the feature's nav graph; consumed from AND-238):

```kotlin
const val CHANNEL_ID_ARG = "channelId"
const val CHANNEL_MESSAGES_ROUTE = "fanclub/channels/{$CHANNEL_ID_ARG}/messages"

fun NavGraphBuilder.channelMessagesScreen(onBack: () -> Unit) {
    composable(
        route = CHANNEL_MESSAGES_ROUTE,
        arguments = listOf(navArgument(CHANNEL_ID_ARG) { type = NavType.StringType }),
    ) { ChannelMessagesScreen(onBack = onBack) }
}
```

UI state and intents:

```kotlin
data class ChannelMessagesUiState(
    val channelId: String,
    val isInitialLoading: Boolean = true,
    val isRefreshing: Boolean = false,
    val composerText: String = "",
    val canPost: Boolean = true,
    val isOffline: Boolean = false,
    val initialError: UiError? = null,        // full-screen
    val transientError: UiError? = null,      // snackbar, one-shot
)

sealed interface MessageItemUi {
    val id: String
    data class Real(val message: Message, val sendState: SendState = SendState.Sent) : MessageItemUi {
        override val id get() = message.id
    }
    data class Pending(val localId: String, val text: String,
                       val sendState: SendState) : MessageItemUi {
        override val id get() = localId
    }
}

enum class SendState { Sending, Sent, Failed }
```

ViewModel exposes the paged stream plus the screen state:

```kotlin
@HiltViewModel
class ChannelMessagesViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val repository: ChannelMessagesRepository,
) : ViewModel() {

    private val channelId: String = checkNotNull(savedStateHandle[CHANNEL_ID_ARG])

    val pagedMessages: Flow<PagingData<MessageItemUi>> =
        repository.messagePager(channelId)
            .map { it.map(MessageItemUi::Real) }
            .cachedIn(viewModelScope)

    private val _uiState = MutableStateFlow(ChannelMessagesUiState(channelId))
    val uiState: StateFlow<ChannelMessagesUiState> = _uiState.asStateFlow()

    fun onComposerChange(text: String)
    fun onSend()                                   // optimistic text post
    fun onToggleReaction(messageId: String, emoji: String)
    fun onDelete(messageId: String)
    fun onRefresh()
    fun onRetryPending(localId: String)
    fun consumeTransientError()
}
```

Pending (optimistic) messages and reaction/delete overlays are not stored in the
pager (Paging 3 is server-truthed); instead they are kept in a
`MutableStateFlow<List<MessageItemUi.Pending>>` and a
`MutableStateFlow<Map<String, ReactionOverlay>>` / deleted-id set in the
ViewModel and merged in the Composable layer. On success of a post, the pager is
invalidated (`pagingSource.invalidate()` via `repository.invalidate()`), which
removes the now-confirmed pending entry once the server row appears.

Compose screen:

```kotlin
@Composable
fun ChannelMessagesScreen(onBack: () -> Unit,
                          vm: ChannelMessagesViewModel = hiltViewModel())
```

`LazyColumn(reverseLayout = true)` renders newest-at-bottom; the
`collectAsLazyPagingItems()` `loadState` drives header (prepend = older) and
initial/refresh indicators. Each row delegates to AND-126's
`MessageContent(message)` renderers wrapped in a `MessageBubble` that overlays
the reaction chip row and exposes the long-press context menu. A
`MessageComposer` Material 3 bottom bar holds the text field + send button.

Repository + Paging:

```kotlin
interface ChannelMessagesRepository {
    fun messagePager(channelId: String): Flow<PagingData<Message>>
    suspend fun postText(channelId: String, body: String, clientToken: String): ApiResult<Message>
    suspend fun toggleReaction(channelId: String, messageId: String,
                               emoji: String, add: Boolean): ApiResult<MessageReaction>
    suspend fun deleteMessage(channelId: String, messageId: String): ApiResult<Unit>
    fun invalidate()
}

class ChannelMessagesPagingSource(
    private val service: FanClubMessageService,
    private val channelId: String,
) : PagingSource<String, Message>() {
    override suspend fun load(params: LoadParams<String>): LoadResult<String, Message>
    override fun getRefreshKey(state: PagingState<String, Message>): String? = null
}
```

Pager config: `PagingConfig(pageSize = 30, prefetchDistance = 10,
enablePlaceholders = false, initialLoadSize = 30)`. Cursor (`before`) returned in
the response `next_cursor` field is used as `nextKey`/`prevKey` for older pages;
`load` for the newest anchor passes `before = null`.

## 5. API Contract

Base path `/ui/fan-club/channels/{id}/messages`. All requests carry session
cookies and the `X-CSRF-Token` header (mutations only) via the shared OkHttp
stack. Retries with bounded backoff apply **only** to the idempotent GET.

```kotlin
interface FanClubMessageService {
    @GET("ui/fan-club/channels/{id}/messages")
    suspend fun list(
        @Path("id") channelId: String,
        @Query("before") before: String?,
        @Query("limit") limit: Int = 30,
    ): MessagePageDto

    @POST("ui/fan-club/channels/{id}/messages")
    suspend fun post(
        @Path("id") channelId: String,
        @Body body: PostMessageRequest,
    ): MessageDto

    @PUT("ui/fan-club/channels/{id}/messages/{messageId}/reactions")
    suspend fun react(
        @Path("id") channelId: String,
        @Path("messageId") messageId: String,
        @Body body: ReactionRequest,    // {"emoji": "...", "action": "add"|"remove"}
    ): ReactionDto

    @DELETE("ui/fan-club/channels/{id}/messages/{messageId}")
    suspend fun delete(
        @Path("id") channelId: String,
        @Path("messageId") messageId: String,
    ): Response<Unit>
}
```

GET response (`MessagePageDto`):

```json
{
  "items": [
    {
      "id": "msg_01HZ...",
      "channel_id": "chan_abc",
      "type": "text",
      "author": { "id": "usr_9", "display_name": "Ada", "avatar_url": null },
      "body": "hello channel",
      "attachments": [],
      "reactions": [ { "emoji": "🔥", "count": 3, "reacted": true } ],
      "is_mine": false,
      "created_at": "2026-06-05T12:00:00Z",
      "edited_at": null,
      "deleted": false
    }
  ],
  "next_cursor": "eyJiZWZvcmUiOiJtc2dfMDFIWiJ9",
  "has_more": true
}
```

POST request/response:

```json
// PostMessageRequest
{ "type": "text", "body": "hello", "client_token": "uuid-v4" }
// 201 -> single MessageDto (same shape as items[])
```

`client_token` is a client-generated UUID for idempotency/de-dup so a retried
POST does not create duplicates. React request body:
`{"emoji":"🔥","action":"add"}` → returns the updated
`{"emoji","count","reacted"}`. DELETE → `204 No Content` (or `200` with empty
body; both treated as success).

DTO→domain mapping reuses AND-126's `MessageMapper` for the polymorphic `type`
discriminator (Moshi `PolymorphicJsonAdapterFactory` keyed on `"type"`); this
ticket adds only `MessagePageDto`, `PostMessageRequest`, `ReactionRequest`, and
`ReactionDto`. Error bodies follow the FastAPI `detail` union
(`string | [{msg}] | {code,...}`) decoded by the shared
`ApiResult`/error-mapping layer.

## 6. Data & State Management

- **Source of truth for the timeline:** server, via Paging 3. No Room-backed
  `RemoteMediator` in this ticket (channel timelines change too rapidly to cache
  usefully on the unreliable dev host); offline shows the last in-memory pages
  plus an offline banner. A Room cache table may be added later (tracked as an
  open question, §13) without changing the public `ChannelMessagesRepository`.
- **Optimistic overlays:** pending sends, reaction deltas, and deleted-id set
  live in `ViewModel` `StateFlow`s and are merged with `LazyPagingItems` in the
  Composable so that an invalidation never drops in-flight optimistic state.
- **Reaction reconciliation:** `ReactionOverlay(emoji -> delta:Int, reacted:Boolean?)`
  applied on top of the server `reactions` list; cleared for a message once a
  server response or pager refresh supersedes it.
- **DataStore:** no new prefs needed beyond the existing session; composer draft
  text is held in `SavedStateHandle` so it survives process death per channel.
- **Process death:** `channelId` and `composerText` are restored from
  `SavedStateHandle`; pending un-sent messages are intentionally not persisted
  (lost on process death — acceptable for v1, noted in §13).

## 7. Error Handling & Resilience

- All network calls return `ApiResult<T>`; mapping via the shared error mapper.
- GET timeouts ~20s; bounded exponential backoff (e.g. 3 attempts, 0.5s→2s,
  jitter) on `IOException`/timeout/5xx for the **GET only**. POST/PUT/DELETE are
  surfaced to the user with a manual retry; the `client_token` makes a manual
  POST retry safe.
- 401 on any call → shared OkHttp `Authenticator` performs `POST
  /ui/session/refresh` once then retries the original; a second 401 propagates as
  an auth error that routes to re-login (handled by core auth, not here).
- 403 on POST → set `canPost = false` with hint "You can't post in this
  channel"; disable composer.
- 404 on the channel (deleted/lost access) → full-screen error with Back action.
- Optimistic failures: post → mark `SendState.Failed` with inline Retry;
  reaction/delete → revert overlay and emit one-shot `transientError` snackbar.
- Paging `LoadState.Error` (append/prepend) → inline retry footer/header;
  initial `LoadState.refresh` error → full-screen error with Retry.
- Offline (no connectivity, observed via the core connectivity flow) → show
  offline banner, disable composer/reactions, keep cached pages visible.

## 8. Security & Privacy

- No tokens in code; session is cookie-based via the persistent OkHttp
  `CookieJar` provided by core auth. Mutations send `X-CSRF-Token` from the
  `ui_csrf` cookie.
- Authorization is server-enforced (tier/membership). The client must not
  assume post/delete rights; it reacts to 403 rather than gating purely on
  client state. Delete is offered only when `is_mine == true`, but the server
  remains authoritative.
- No message content or PII written to logs (see §10). Attachment URLs loaded
  via Coil/Media3 inherit the authenticated OkHttp client; no caching of media
  to external storage.
- Dev backend is plaintext HTTP; cleartext is permitted **only** for the dev
  host via the existing network-security-config allow-list — no new cleartext
  exemptions are added by this ticket.

## 9. Accessibility & i18n

- All composables provide `contentDescription`: send button, reaction chips
  (`"<emoji>, <count> reactions, tap to toggle"`), avatar, attachment thumbs.
- Long-press context menu also reachable via a custom accessibility action
  ("Message actions") so delete is operable with TalkBack.
- Touch targets ≥48dp; composer text field supports IME `Send` action and
  large-font / dynamic-type scaling without truncation.
- All user-facing strings in `res/values/strings.xml` (no hardcoded text);
  reaction counts use `plurals`. Timestamps formatted via locale-aware
  `DateUtils`/`java.time` with RTL-safe layout (`Modifier`-level start/end).
- Color contrast for bubbles and the "Sending/Failed" state badges meets WCAG AA.

## 10. Telemetry & Logging

- Analytics events (via the core analytics facade): `fanclub_messages_opened`
  `{channel_id}`, `fanclub_message_sent` `{channel_id, type:"text"}`,
  `fanclub_message_send_failed` `{channel_id, error_code}`,
  `fanclub_reaction_toggled` `{channel_id, emoji, action}`,
  `fanclub_message_deleted` `{channel_id}`,
  `fanclub_messages_load_error` `{channel_id, stage, http_status}`.
- Logging: `Timber` at debug for request lifecycle and Paging `loadState`
  transitions; **never** log message `body`, author PII, cookies, or CSRF token.
  Error logs include HTTP status and mapped error code only.

## 11. Testing Strategy

- **Mappers (reuse + extend, JVM unit):** `MessagePageDto` → `PagingData<Message>`
  including each sealed type round-trips via AND-126's `MessageMapper`; unknown
  `type` maps to the unsupported placeholder (no exception).
- **PagingSource:** fake `FanClubMessageService` returns multi-page fixtures;
  assert cursor threading (`before`/`next_cursor`), `endOfPaginationReached` when
  `has_more=false`, and `LoadResult.Error` on `IOException`.
- **ViewModel (Turbine + coroutine test, `:core-testing`):**
  - `onSend` emits a `Pending`/`Sending` overlay, then invalidates on success.
  - failed post → `SendState.Failed`; `onRetryPending` re-issues with the same
    `client_token`.
  - `onToggleReaction` applies and reconciles the overlay; failure reverts and
    emits `transientError`.
  - `onDelete` removes optimistically; failure restores; success persists.
  - 403 on send → `canPost=false`.
- **Repository:** verifies correct service calls + `ApiResult` mapping for
  success/timeout/401-handled/403/404.
- **Compose UI tests:** list renders content/empty/error states; composer send
  flow; reaction chip toggle; long-press → delete confirm; TalkBack content
  descriptions present (semantics assertions).
- **MockWebServer integration:** end-to-end GET pagination, POST with
  `client_token`, PUT react, DELETE, and the 401→refresh→retry path.
- Coverage gate per repo standard; new code paths must be exercised.

## 12. Dependencies & Sequencing

- **AND-238 (Fan-club channels list, P1):** provides the `channelId` nav arg and
  the entry point into this screen. Hard prerequisite — this screen is only
  reachable from the channels list.
- **AND-126 (Message domain model + mappers, P0):** provides the sealed
  `Message` model, `MessageReaction`/`MessageAttachment`, the Moshi polymorphic
  factory, and per-type renderers reused by `MessageContent`. Hard prerequisite.
- Implicit: core auth cookie jar + 401-refresh interceptor, core connectivity
  flow, core analytics facade, and the shared `ApiResult`/error mapper must be
  available (all landed earlier in M1–M2).
- Sequencing: land DTOs + `FanClubMessageService` + `PagingSource` →
  repository → ViewModel → Compose screen → wire nav from AND-238 → tests.
- Blocks: none currently recorded.

## 13. Risks & Open Questions

- **Reaction API shape unverified:** PUT-with-`action` vs separate POST/DELETE
  endpoints — confirm against `/openapi.json` and `frontend/src/api/endpoints`
  before implementation; service signature may need to split into add/remove.
- **Cursor field name:** `before` / `next_cursor` assumed; verify exact query
  param + response key names from OpenAPI (web reference may use `cursor`).
- **Idempotency token support:** confirm the backend honors `client_token`; if
  not, a retried POST can duplicate — fall back to client-side de-dup by
  `(author,body,created_at)` window.
- **No realtime:** without WebSocket/push, new messages appear only on
  refresh/pagination; product to confirm pull-only is acceptable for M5.
- **Pending message loss on process death** is accepted for v1.
- **Caching:** whether to add a Room `RemoteMediator` for offline timeline is
  deferred; public repository interface designed to absorb it later.

## 14. Acceptance Criteria

AC-1 Opening a channel from the channels list (AND-238) loads its messages,
newest visible at the bottom, within the loading-state contract. *(Acceptance:
"Messages render".)*

AC-2 Scrolling to the top loads older messages page-by-page (size 30) using the
server cursor; loading stops when `has_more=false`.

AC-3 Every AND-126 message type renders without crashing; unknown types show the
unsupported placeholder.

AC-4 Composing and sending text posts via
`POST /ui/fan-club/channels/{id}/messages`; the message appears optimistically
(`Sending`), resolves to `Sent` on 201, or `Failed` with a working Retry that
reuses the same `client_token`. *(Acceptance: "post".)*

AC-5 Tapping a reaction toggles it optimistically; count and `reacted` flag
update immediately and reconcile with the server (`PUT .../reactions`), reverting
on failure. *(Acceptance: "react".)*

AC-6 Long-pressing an own message (`is_mine`) offers Delete with confirm;
on confirm the message is removed and `DELETE .../{messageId}` succeeds (204),
reverting on failure.

AC-7 403 on send disables the composer with a hint; 401 triggers a single
silent refresh-and-retry; initial-load failure shows a full-screen retry;
action failures show a snackbar.

AC-8 No message body, PII, cookies, or CSRF token appear in logs; mutations send
`X-CSRF-Token`.

AC-9 All listed unit, Paging, ViewModel, Compose, and MockWebServer tests pass
in CI.

## 15. Definition of Done

- `ChannelMessagesScreen`, `ChannelMessagesViewModel`, `ChannelMessagesRepository`
  (+ impl), `ChannelMessagesPagingSource`, `FanClubMessageService`, and the new
  DTOs/mappers are implemented in `:feature-fanclub` / `:core-network` under
  `com.testlogon.android.feature.fanclub.messages`, with Hilt bindings.
- Navigation route wired and reachable from AND-238's channels list.
- All FRs and ACs satisfied; all §11 tests written and green in CI; lint/detekt
  clean; no new cleartext exemptions.
- No hardcoded strings; accessibility semantics present and verified with one
  TalkBack pass.
- Telemetry events emitted; no sensitive data logged.
- Code reviewed and merged to `android-port`; spec status moved `draft → done`.
- Open questions in §13 either resolved against `/openapi.json` or explicitly
  ticketed for follow-up before merge.
