---
id: AND-239
title: Fan-club channel messages
milestone: M5
epic: E32
priority: P1
size: L
status: reviewed
reviewed_on: 2026-06-06
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
  **Verified note:** the web client (`src/api/client.ts`) sends `X-CSRF-Token`
  from the `ui_csrf` cookie on **every** request (not just mutations) and *also*
  sends an `Authorization: Bearer <accessToken>` header from its auth store plus
  optional `X-IMPERSONATION-TOKEN`. The OpenAPI params for these endpoints also
  expose `user_sub`, `X-SESSION-ID`, `X-IMPERSONATION-TOKEN`. The Android stack
  should mirror whatever the shared core-auth client already does; sending CSRF
  only on mutations is acceptable but is a divergence from the web reference.
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
enablePlaceholders = false, initialLoadSize = 30)`.

**CORRECTED — pagination contract.** The earlier draft assumed the GET response
is a paged envelope exposing a `next_cursor` field. That is wrong. Verified
against OpenAPI (`GET /ui/fan-club/channels/{channel_id}/messages`, params
`limit, before`) and the web reference (`src/api/endpoints/fan-club.ts:
getChannelMessages` returns `ChannelMessageOut[]`, and `FanClubPage.tsx` sorts
client-side and never paginates): the response body is a **bare JSON array of
`ChannelMessageOut`**, with **no `next_cursor` and no `has_more` field**.
Server-side cursoring *is* supported via the `before` query param (a message id /
opaque cursor) plus `limit` (server default 50, max 200). Therefore the
`PagingSource` must derive the next key itself — use the **oldest item's
`message_id`** in the current page as the `before` for the next (older) page, and
treat `endOfPaginationReached = (page.size < limit)` since there is no server
`has_more` flag. `load` for the newest anchor passes `before = null`.

Because the response is a bare array (`{}`/unschematized in OpenAPI), the
`MessagePageDto { items, next_cursor, has_more }` shape described in §5 must be
replaced with a `List<ChannelMessageOut>` deserialization; see §5 corrections.

## 5. API Contract

Base path `/ui/fan-club/channels/{id}/messages`. All requests carry session
cookies and the `X-CSRF-Token` header (mutations only) via the shared OkHttp
stack. Retries with bounded backoff apply **only** to the idempotent GET.

**CORRECTED service interface** (paths, methods, bodies and return types now match
OpenAPI + the web reference; corrections detailed in §16):

```kotlin
interface FanClubMessageService {
    // GET returns a BARE ARRAY (no envelope). server default limit=50, max=200.
    @GET("ui/fan-club/channels/{channelId}/messages")
    suspend fun list(
        @Path("channelId") channelId: String,
        @Query("before") before: String?,
        @Query("limit") limit: Int = 30,
    ): List<ChannelMessageDto>

    // POST body is ChannelMessageIn { text (required, 1..2000), reply_to_message_id? }
    // NO "type", NO "body", NO "client_token" fields exist server-side.
    @POST("ui/fan-club/channels/{channelId}/messages")
    suspend fun post(
        @Path("channelId") channelId: String,
        @Body body: ChannelMessageIn,            // { text, reply_to_message_id? }
    ): ChannelMessageDto                          // 201 -> single ChannelMessageDto

    // Reaction endpoint is POST .../react (NOT PUT .../reactions).
    // Request body is a free-form object in OpenAPI (additionalProperties:true);
    // exact field names are UNVERIFIED (no web-client usage). See §16 open assumptions.
    @POST("ui/fan-club/channels/{channelId}/messages/{messageId}/react")
    suspend fun react(
        @Path("channelId") channelId: String,
        @Path("messageId") messageId: String,
        @Body body: ReactionRequest,             // ASSUMED {"emoji": "..."} toggle; verify at impl
    ): Response<Unit>                             // response body is unschematized ({})

    // DELETE returns 200 (per OpenAPI), NOT 204. Treat 200/204 + empty body as success.
    @DELETE("ui/fan-club/channels/{channelId}/messages/{messageId}")
    suspend fun delete(
        @Path("channelId") channelId: String,
        @Path("messageId") messageId: String,
    ): Response<Unit>
}
```

**CORRECTED GET response** — a bare array of `ChannelMessageOut` (verified against
`src/api/types.ts: ChannelMessageOut` and `getChannelMessages`). The real DTO
fields differ substantially from the earlier draft (see §16 for the field-by-field
diff):

```json
[
  {
    "message_id": "msg_01HZ...",
    "channel_id": "chan_abc",
    "sender_id": "usr_9",
    "sender_display_name": "Ada",
    "sender_badge": { "tier_name": "Gold", "tier_level": 3, "badge_emoji": "⭐" },
    "text": "hello channel",
    "kind": "text",
    "reply_to_message_id": null,
    "reactions": { "🔥": { "usr_1": true, "usr_2": true } },
    "created_at": 1749124800,
    "deleted": false
  }
]
```

Field notes (all verified against `ChannelMessageOut`):
- `message_id` (NOT `id`); `channel_id`.
- Author is **flat**: `sender_id`, `sender_display_name`, optional
  `sender_badge` (a `MemberBadgeData`). There is **no `author` object** and **no
  `avatar_url`**.
- Message text is `text` (NOT `body`); the type discriminator is `kind` (NOT
  `type`). AND-126's mapper must key its polymorphic factory on **`kind`**.
- `reactions` is `Record<emoji, Record<userId, bool>>` — i.e. a map of emoji →
  map of userId → true. It is **NOT** an array of `{emoji,count,reacted}`. The
  client derives `count = reactions[emoji].size` and `reacted =
  reactions[emoji].containsKey(currentUserSub)`.
- `created_at` is an **epoch integer in seconds** (web does
  `new Date(created_at * 1000)`), NOT an ISO-8601 string.
- `deleted: boolean` exists; there is **no `edited_at`** and **no `attachments`**
  field on this DTO.
- `reply_to_message_id?` is present (reply threading; not composed in this ticket
  but should be carried through the domain model).
- **`is_mine` does not exist server-side.** Derive ownership client-side as
  `sender_id == currentUserSub` to gate the Delete affordance (§8 already says the
  server is authoritative).

**CORRECTED POST request** (`ChannelMessageIn`, verified):

```json
{ "text": "hello", "reply_to_message_id": null }
// 201 -> single ChannelMessageOut (same shape as array items)
```

`text` is required, length 1..2000 (server-enforced `minLength:1, maxLength:2000`
on `ChannelMessageIn.text`). **There is no `type` field and no `client_token`
idempotency token** in the backend schema or the web client — the earlier
`PostMessageRequest { type, body, client_token }` was fabricated. Optimistic
post + manual retry must therefore guard against duplicates **client-side**
(de-dup window on `(sender_id, text, created_at)`, or disable retry after success
confirmation) since the server offers no idempotency key. This is now reflected in
§7 and §13.

**Reaction request** — UNVERIFIED. Endpoint is `POST .../react` and OpenAPI
declares its request body only as a free-form object (`type:object,
additionalProperties:true`) with an unschematized (`{}`) response; the web
reference does **not** call it, so the exact field names and the add/remove toggle
semantics cannot be confirmed from the sources. Assume a single-emoji toggle body
(`{"emoji":"🔥"}`) where one call toggles on/off, and re-verify against a live
`/openapi.json` or backend owner before implementation. DELETE → **200** (per
OpenAPI; treat 200 and 204 with empty body as success).

DTO→domain mapping reuses AND-126's `MessageMapper`, but its polymorphic
discriminator must be keyed on **`kind`** (not `type`). This ticket adds only
`ChannelMessageDto` (the wire form of `ChannelMessageOut`), `ChannelMessageIn`,
and `ReactionRequest`. Error bodies follow the FastAPI `detail` union, decoded by
the shared `ApiResult`/error-mapping layer; verified shapes are
`string | [{ "msg": ... }] | { "code": ..., "required_scope"?: ... }`
(see `src/api/client.ts: normalizeErrorDetail` / `mapAuthorizationError` and the
`HTTPValidationError` schema in OpenAPI).

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
  jitter) on `IOException`/timeout/5xx for the **GET only**. POST/react/DELETE
  are surfaced to the user with a manual retry. **Corrected:** there is no
  server-side `client_token` idempotency key (the earlier draft assumed one), so a
  retried POST that actually reached the server can duplicate. Make manual POST
  retry safe client-side: only offer Retry when the request demonstrably failed
  (network/timeout/5xx with no response), and de-dup on pager refresh by
  `(sender_id, text, created_at)` window. See §13.
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
  client state. Delete is offered only when the message is the current user's
  (derived `sender_id == currentUserSub`, since the DTO has no `is_mine` field),
  but the server remains authoritative.
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
  - failed post → `SendState.Failed`; `onRetryPending` re-issues the same `text`
    (no `client_token` exists; retry only fires for no-response failures).
  - `onToggleReaction` applies and reconciles the overlay; failure reverts and
    emits `transientError`.
  - `onDelete` removes optimistically; failure restores; success persists.
  - 403 on send → `canPost=false`.
- **Repository:** verifies correct service calls + `ApiResult` mapping for
  success/timeout/401-handled/403/404.
- **Compose UI tests:** list renders content/empty/error states; composer send
  flow; reaction chip toggle; long-press → delete confirm; TalkBack content
  descriptions present (semantics assertions).
- **MockWebServer integration:** end-to-end GET pagination (bare-array response,
  `before` threading), POST `ChannelMessageIn`, `POST .../react`, DELETE (200),
  and the 401→refresh→retry path.
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

- **Reaction API shape (PARTIALLY RESOLVED):** verified the endpoint is
  `POST /ui/fan-club/channels/{channel_id}/messages/{message_id}/react` (not a
  PUT `.../reactions`). However its request body is declared in OpenAPI only as a
  free-form object (`additionalProperties:true`) with an unschematized response,
  and the web reference never calls it, so the exact body field names and the
  add/remove toggle semantics remain UNVERIFIED. Confirm with the backend owner
  or a live server before implementation; the single-emoji toggle assumption may
  be wrong.
- **Cursor contract (RESOLVED):** query param is `before` (+ `limit`); the GET
  response is a **bare array with no `next_cursor`/`has_more`**. The PagingSource
  derives the next `before` from the oldest item's `message_id` and ends
  pagination when a page is shorter than `limit`. (Earlier `next_cursor` assumption
  was wrong.)
- **Idempotency token (RESOLVED — none exists):** the backend `ChannelMessageIn`
  has only `text` + `reply_to_message_id`; there is **no `client_token`**. A
  retried POST that reached the server can duplicate, so de-dup is handled
  client-side per §5/§7 (`(sender_id, text, created_at)` window; retry only on
  no-response failures).
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
`POST /ui/fan-club/channels/{channel_id}/messages` with body
`{ text, reply_to_message_id? }` (`ChannelMessageIn`); the message appears
optimistically (`Sending`), resolves to `Sent` on 201, or `Failed` with a working
Retry. (Corrected: there is **no `client_token`** — retry safety is handled
client-side per §5/§7.) *(Acceptance: "post".)*

AC-5 Tapping a reaction toggles it optimistically; the derived count and
`reacted` flag update immediately and reconcile with the server
(`POST .../messages/{message_id}/react`), reverting on failure. (Corrected from
`PUT .../reactions`. `count`/`reacted` are derived from the
`reactions: Map<emoji, Map<userId, bool>>` shape, not server-supplied scalars.)
*(Acceptance: "react".)*

AC-6 Long-pressing an own message (ownership derived as
`sender_id == currentUserSub`, since there is no server `is_mine`) offers Delete
with confirm; on confirm the message is removed and
`DELETE .../messages/{message_id}` succeeds (**200**, treat 200/204 as success),
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. Source kinds:
OpenAPI = `reference/openapi.index.txt` / `reference/openapi.pretty.json`
(`components.schemas.*`); FE = `reference/src/...`; "framework ref" = Android docs.

1. **GET messages endpoint is `GET /ui/fan-club/channels/{channel_id}/messages`
   with query params `before` + `limit`.** VERIFIED.
   Source: OpenAPI `GET /ui/fan-club/channels/{channel_id}/messages`
   (op `api_get_channel_messages_...`, params `channel_id, limit, before`);
   FE `src/api/endpoints/fan-club.ts: getChannelMessages`.

2. **GET response is a paged envelope `{ items, next_cursor, has_more }`.**
   CORRECTED → it is a **bare array** of `ChannelMessageOut` with no cursor/flag
   fields. Source: FE `src/api/types.ts: ChannelMessageOut` + `fan-club.ts:
   getChannelMessages` (returns `ChannelMessageOut[]`); OpenAPI 200 schema is `{}`
   (unschematized). Pagination key derived client-side from oldest `message_id`.

3. **GET default `limit`.** CORRECTED context: server default is **50** (max 200),
   not 30; the Android client may still request `limit=30`. Source: OpenAPI GET
   `limit` schema `default:50, maximum:200, minimum:1`.

4. **Message DTO field names** (`id`, `type`, nested `author{id,display_name,
   avatar_url}`, `body`, `attachments[]`, `reactions:[{emoji,count,reacted}]`,
   `is_mine`, `created_at` ISO string, `edited_at`). CORRECTED → actual fields are
   `message_id`, `channel_id`, `sender_id`, `sender_display_name`,
   `sender_badge?`, `text`, `kind`, `reply_to_message_id?`,
   `reactions: Map<emoji, Map<userId, bool>>`, `created_at` (epoch **seconds**
   integer), `deleted`. No `author` object, no `avatar_url`, no `attachments`, no
   `is_mine`, no `edited_at`. Source: FE `src/api/types.ts: ChannelMessageOut`;
   epoch-seconds confirmed by `src/pages/fan-club/FanClubPage.tsx`
   (`new Date(m.created_at * 1000)`).

5. **Type discriminator is `type`.** CORRECTED → it is `kind`. AND-126's Moshi
   polymorphic factory must key on `kind`. Source: FE `ChannelMessageOut.kind`.

6. **`reactions` is an array of `{emoji,count,reacted}`.** CORRECTED → it is
   `Record<emoji, Record<userId, bool>>`; client derives `count` =
   `reactions[emoji].size`, `reacted` = membership of `currentUserSub`. Source:
   FE `src/api/types.ts: ChannelMessageOut.reactions`.

7. **POST send endpoint `POST /ui/fan-club/channels/{channel_id}/messages`,
   201 → single message.** VERIFIED. Source: OpenAPI POST (op
   `api_send_channel_message_...`, `resp=201`, `req=ChannelMessageIn`);
   FE `fan-club.ts: sendChannelMessage`.

8. **POST request body `{ type, body, client_token }`.** CORRECTED → body is
   `ChannelMessageIn { text (required, 1..2000), reply_to_message_id? }`. No
   `type`, no `body`, **no `client_token`**. Source: OpenAPI
   `components.schemas.ChannelMessageIn` (`text` `minLength:1 maxLength:2000`,
   `required:[text]`); FE `fan-club.ts: sendChannelMessage` posts
   `{ text, reply_to_message_id }`.

9. **Idempotency via `client_token`.** CORRECTED → none exists; retried POST can
   duplicate. De-dup handled client-side. Source: absence in `ChannelMessageIn`
   and in FE send call (citations 7-8).

10. **Reaction endpoint is `PUT .../messages/{messageId}/reactions` with body
    `{emoji, action}` returning `{emoji,count,reacted}`.** CORRECTED (method/path)
    + UNVERIFIED (body/response). Real endpoint:
    `POST /ui/fan-club/channels/{channel_id}/messages/{message_id}/react`.
    Source: OpenAPI POST (op `api_add_reaction_...`). Request body is declared
    only as `type:object, additionalProperties:true` and the 200 response schema
    is `{}`; the web client never calls react, so field names + toggle semantics
    are an unverified assumption (see Open assumptions).

11. **DELETE endpoint `DELETE /ui/fan-club/channels/{channel_id}/messages/{message_id}`,
    success status 204.** PARTIALLY CORRECTED → endpoint VERIFIED; success status
    is **200** per OpenAPI (treat 200/204 as success). Source: OpenAPI DELETE
    (op `api_delete_channel_message_...`, `resp=200`). The web client never calls
    delete, so behavior beyond the status code is unverified.

12. **Auth/CSRF: cookie session, `ui_csrf` echoed as `X-CSRF-Token`, single
    `POST /ui/session/refresh` on 401 then retry.** VERIFIED (with nuance). The
    web client sends `X-CSRF-Token` on **every** request (not mutations-only),
    plus `Authorization: Bearer` and optional `X-IMPERSONATION-TOKEN`; refresh
    failure logs out. Source: FE `src/api/client.ts` (`getCookie("ui_csrf")` →
    `X-CSRF-Token`; `refreshSession()` POSTs `/ui/session/refresh`; 401 retry
    block). OpenAPI also lists `user_sub, X-SESSION-ID, X-IMPERSONATION-TOKEN`
    params on these endpoints.

13. **Error `detail` union `string | [{msg}] | {code,...}`.** VERIFIED. Source:
    FE `src/api/client.ts: normalizeErrorDetail` (handles string / array-of-`{msg}`
    / object) and `mapAuthorizationError` (reads `detail.code`,
    `detail.required_scope`); OpenAPI `HTTPValidationError` / `ValidationError`
    (422 on all four endpoints).

14. **Web behavior: list sorted client-side ascending by `created_at`, polled
    every 5s, no pagination, empty state "No messages yet…".** VERIFIED.
    Source: FE `src/pages/fan-club/FanClubPage.tsx` (`sort((a,b)=>a.created_at -
    b.created_at)`, `refetchInterval: 5000`, empty copy). Confirms §1 non-goal
    "polling/pull-only" is consistent with the reference (no realtime/WebSocket).

15. **Channel header metadata available from AND-238 / `ChannelOut`.** VERIFIED.
    Source: FE `src/api/types.ts: ChannelOut` (`channel_id, name,
    min_tier_level, slowmode_seconds, max_message_length, pinned_message_id,
    last_message_preview, ...`). Note `slowmode_seconds`/`max_message_length`
    exist server-side and may justify client-side composer hints (open assumption).

16. **There is a `PUT /ui/fan-club/channels/{channel_id}/pin/{message_id}` (pin)
    endpoint.** VERIFIED to exist but OUT OF SCOPE for AND-239. Source: OpenAPI
    `op api_pin_message_...`. Noted so it is not confused with the react endpoint.

17. **Paging 3 / `LazyColumn(reverseLayout=true)` / cursor PagingSource choice.**
    Framework choice — reasonable. framework ref:
    https://developer.android.com/topic/libraries/architecture/paging/v3-overview
    and https://developer.android.com/develop/ui/compose/lists . Not contract-bound.

18. **OkHttp `Authenticator` for 401 refresh.** Framework choice consistent with
    the web refresh-once behavior (citation 12). framework ref:
    https://square.github.io/okhttp/recipes/#handling-authentication-kt-java .

### Corrections made

- §4: removed the false `next_cursor`/`has_more` envelope assumption; documented
  bare-array response and client-derived `before` paging + `endOfPagination` rule.
- §5: rewrote the service interface (paths now `{channelId}`/`{messageId}`; GET
  returns `List<ChannelMessageDto>`; POST body `ChannelMessageIn`; react is
  `POST .../react` not `PUT .../reactions`; DELETE success 200 not 204).
- §5: replaced the fabricated GET JSON and `MessageDto` shape with the real
  `ChannelMessageOut` fields (`message_id`, `sender_*`, `text`, `kind`,
  `reactions` map, epoch-seconds `created_at`, `deleted`); removed `author`
  object, `avatar_url`, `attachments`, `is_mine`, `edited_at`.
- §5/§7/§11/§13: removed `client_token` (no backend support); added client-side
  de-dup + retry-only-on-no-response guidance.
- §2: clarified CSRF is sent on all requests by the web client and that Bearer/
  impersonation headers also exist.
- §8: `is_mine` ownership replaced with derived `sender_id == currentUserSub`.
- AC-4/AC-5/AC-6: corrected method/path/status/idempotency claims inline.
- §13: marked the cursor and idempotency open questions resolved; narrowed the
  reaction open question to body/semantics only.

### Open assumptions

- **Reaction request/response contract** — OpenAPI declares the `react` body as a
  free-form object and the response as `{}`; the web client never calls it. The
  `{"emoji": "..."}` single-toggle assumption (and whether one endpoint toggles
  both add+remove, or whether remove needs a separate call/param) is **unverified**.
  Must confirm against a live `/openapi.json` or the backend owner before coding.
- **Delete response body / partial-failure behavior** — only the 200 status is
  known from OpenAPI; the web client never deletes, so any response payload is
  unverified. Treat empty body as success.
- **`current user sub` source** — deriving `reacted`/ownership requires the
  signed-in user's `sub`; assumed available from core-auth session state. The web
  client uses an auth store; the exact Android accessor is unverified here.
- **Slowmode / max-message-length enforcement** — `ChannelOut.slowmode_seconds`
  and `max_message_length` exist; whether the client should pre-enforce them vs.
  rely on server 4xx is a product/UX decision, unverified.
- **403 copy / `canPost` trigger** — server returning 403 on send is assumed
  (standard FastAPI authz); the web client has no fan-club post-permission path to
  confirm the exact status/detail. Reacting to 403 generically is safe.
- **401 silent refresh applies to these endpoints** — verified at the shared
  client level (citation 12); not independently exercised against fan-club routes.

## 17. Test Plan

Test targets: **JVM** = JVM unit/Robolectric (local, no device); **emu35** =
headless AVD `test35` (x86_64, API 35) in CI; **A15** = physical Samsung Galaxy
A15 5G (SM-A156U, serial R5CX821TA9R, API 34, arm64-v8a) on the build host.
Most cases here are non-hardware and run on JVM or emu35; cases requiring real
TalkBack speech / true offline radio behavior / arm64 deserialization sanity are
flagged for **A15**.

- **TC-AND-239-01** — Type: contract/MockWebServer. Target: emu35 (or JVM with
  Robolectric OkHttp). Preconditions: MockWebServer enqueues a JSON **array** of
  3 `ChannelMessageOut` objects (epoch-seconds `created_at`, `kind:"text"`).
  Steps: open channel; let initial `load` run. Expected: 3 messages rendered
  newest-at-bottom; `created_at` parsed from epoch **seconds**; `message_id` used
  as list key; no envelope/`items` field expected. Traces: AC-1, AC-3.

- **TC-AND-239-02** — Type: unit (PagingSource). Target: JVM. Preconditions: fake
  `FanClubMessageService` returns page1 (30 items) then page2 (12 items, < limit).
  Steps: load refresh, then prepend (older) with `before` = oldest `message_id`
  of page1. Expected: `before` threaded from oldest item; second page returns 12;
  `endOfPaginationReached = true` because `size < limit` (no `has_more` field
  exists). Traces: AC-2.

- **TC-AND-239-03** — Type: unit (mapper). Target: JVM. Preconditions: fixtures
  for each AND-126 `kind` plus one unknown `kind:"hologram"`. Steps: map
  `ChannelMessageDto` → domain via `MessageMapper` keyed on **`kind`**; derive
  `reactions` count/`reacted` from the `Map<emoji,Map<userId,bool>>`. Expected:
  every known kind maps; unknown kind → "Unsupported message" placeholder, no
  exception; `count`/`reacted` derived correctly for `currentUserSub`.
  Traces: AC-3, AC-5.

- **TC-AND-239-04** — Type: contract/MockWebServer. Target: emu35. Preconditions:
  POST endpoint returns 201 with a single `ChannelMessageOut`. Steps: type text,
  tap send. Expected: request body is exactly `{ "text": "...",
  "reply_to_message_id": null }` (ChannelMessageIn) — **no** `type`/`body`/
  `client_token`; optimistic `Sending` bubble appears, resolves to `Sent`; pager
  invalidated. Traces: AC-4.

- **TC-AND-239-05** — Type: ViewModel unit (Turbine). Target: JVM.
  Preconditions: service POST throws `IOException` (no response). Steps: `onSend`,
  observe state; then `onRetryPending`. Expected: bubble → `SendState.Failed` with
  Retry; retry re-issues same `text`; no duplicate is created because retry only
  fires on no-response failures (no `client_token` available). Traces: AC-4, AC-7.

- **TC-AND-239-06** — Type: contract/MockWebServer. Target: emu35.
  Preconditions: react endpoint `POST .../messages/{id}/react` returns 200 empty
  body. Steps: tap a reaction chip. Expected: request hits **POST .../react**
  (not PUT .../reactions); optimistic count/`reacted` toggle immediately;
  reconciles on success. (Note: request body asserted loosely — exact field names
  are an open assumption per §16; assert path/method strictly, body leniently.)
  Traces: AC-5.

- **TC-AND-239-07** — Type: ViewModel unit (Turbine). Target: JVM.
  Preconditions: react service returns error. Steps: `onToggleReaction`. Expected:
  optimistic overlay applied then reverted on failure; one-shot `transientError`
  emitted; underlying server `reactions` map unchanged. Traces: AC-5, AC-7.

- **TC-AND-239-08** — Type: Compose-UI. Target: emu35. Preconditions: one message
  with `sender_id == currentUserSub` and one without. Steps: long-press own
  message → context menu → Delete → confirm; service DELETE returns **200**.
  Expected: Delete offered only on the owned message (derived ownership, no
  `is_mine`); on confirm message removed optimistically; 200 treated as success.
  Then long-press the other message → no Delete option. Traces: AC-6, AC-8(authz).

- **TC-AND-239-09** — Type: ViewModel/Repository unit. Target: JVM.
  Preconditions: DELETE returns 500. Steps: `onDelete`. Expected: message removed
  optimistically then **restored**; `transientError` snackbar. Traces: AC-6, AC-7.

- **TC-AND-239-10** — Type: contract/MockWebServer. Target: emu35.
  Preconditions: first send returns 403 with `detail:"You can't post here"`.
  Steps: send. Expected: `canPost=false`; composer disabled with hint; no crash;
  error `detail` decoded via the string-union path. Traces: AC-7.

- **TC-AND-239-11** — Type: integration/MockWebServer. Target: emu35.
  Preconditions: GET returns 401 once, then `POST /ui/session/refresh` returns
  200, then GET retried returns the array. Steps: open channel. Expected: a single
  silent refresh, original request retried once, messages render; a second
  consecutive 401 propagates to re-login (no infinite loop). Traces: AC-7, AC-8.

- **TC-AND-239-12** — Type: instrumented/e2e (true offline). Target: **A15**
  (physical). Rationale: real radio/airplane-mode connectivity transitions behave
  differently from emulator network toggling. Preconditions: messages already
  loaded; enable airplane mode. Steps: observe banner; attempt send + react.
  Expected: offline banner shown; composer + reactions disabled; cached pages stay
  visible; on reconnect, pull-to-refresh re-fetches newest. Traces: AC-1, AC-7.

- **TC-AND-239-13** — Type: contract/MockWebServer. Target: emu35.
  Preconditions: error responses for each `detail` form — `"flat string"`,
  `[{"msg":"too long"}]`, and `{"code":"forbidden","required_scope":"..."}`.
  Steps: trigger send failures. Expected: each maps to a human-readable snackbar
  via the shared error mapper (matches `normalizeErrorDetail`/`mapAuthorizationError`
  behavior); no unhandled JSON-shape crash. Traces: AC-7.

- **TC-AND-239-14** — Type: Compose-UI accessibility + instrumented TalkBack.
  Target: emu35 for semantics assertions; **A15** for one real TalkBack speech
  pass. Preconditions: list with reactions, an owned message, composer.
  Steps: assert `contentDescription` on send button, reaction chips
  ("<emoji>, <count> reactions, tap to toggle"), avatar/attachment; verify the
  "Message actions" custom a11y action exposes Delete without long-press; check
  touch targets ≥48dp and dynamic-type scaling. On A15, run TalkBack and confirm
  Delete is reachable and announced. Traces: AC-6, AC-8(a11y semantics).

- **TC-AND-239-15** — Type: unit (JSON/ABI sanity). Target: **A15** (arm64-v8a,
  API 34) vs emu35 (x86_64, API 35). Preconditions: same `ChannelMessageOut`
  fixture with large epoch-seconds `created_at` and unicode-emoji reaction keys.
  Steps: deserialize + render on both targets. Expected: identical parsing of
  epoch-seconds and emoji `reactions` keys across ABI/API levels; no
  locale/`java.time` divergence. Traces: AC-1, AC-3.

### Coverage matrix

| AC | Description | Covering test cases |
|----|-------------|---------------------|
| AC-1 | Open channel loads messages, newest at bottom, loading contract | TC-01, TC-12, TC-15 |
| AC-2 | Scroll-up paginates older via `before`; stops correctly | TC-02 |
| AC-3 | All `kind`s render; unknown → placeholder, no crash | TC-01, TC-03, TC-15 |
| AC-4 | Send text via correct POST body; optimistic Sending→Sent/Failed+retry | TC-04, TC-05 |
| AC-5 | Reaction toggles via `POST .../react`; derived count/reacted; revert | TC-03, TC-06, TC-07 |
| AC-6 | Long-press own message → Delete confirm (200); revert on failure | TC-08, TC-09, TC-14 |
| AC-7 | 403 disables composer; 401 silent refresh; full-screen vs snackbar | TC-05, TC-07, TC-10, TC-11, TC-12, TC-13 |
| AC-8 | No sensitive data in logs; CSRF on mutations; authz behavior | TC-08, TC-11, TC-14 |
| AC-9 | All unit/Paging/ViewModel/Compose/MockWebServer tests pass in CI | TC-01..TC-15 |
