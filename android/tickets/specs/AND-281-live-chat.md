---
id: AND-281
title: Live chat
milestone: M6
epic: E38
priority: P0
size: L
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-280, AND-143]
blocks: []
---

# AND-281 — Live chat

## 1. Overview & Goal

This ticket delivers the real-time **live chat** experience that sits alongside the
broadcast viewer (AND-280) on the TestLogon Android app (`com.testlogon.android`).
While a viewer watches a live HLS stream, they see a continuously updating chat
feed, can send their own messages, and can react (emoji) to the room or to
individual messages. The backlog acceptance bar is unambiguous: **chat updates live;
send works.**

The deliverable wires two existing pieces of infrastructure together behind a new
`feature-broadcast` chat surface:

1. **AND-143 — SSE client core** supplies the lifecycle-aware `SseClient` that turns
   the broadcast chat stream (`GET broadcast/sessions/{id}/chat/stream`,
   `text/event-stream`) into a cold `Flow<SseEvent>` with bounded reconnect/backoff.
   This ticket owns the *consumer*: subscribing to that stream, parsing the
   broadcast-chat `event`/`data` frames into domain models, and merging them into the
   visible chat list.
2. **AND-280 — Viewer playback (HLS)** supplies the viewer screen and `sessionId`
   navigation context. Live chat is rendered as an overlay/panel composed into (or
   beside) the `ViewerScreen`, scoped to the same `sessionId`.

Concretely this ticket delivers: a `BroadcastChatApi` (send + react POSTs), a
`BroadcastChatRepository` that merges the SSE stream with the send/react mutations,
domain models (`ChatMessage`, `ChatReaction`, `ChatStreamEvent`), a
`LiveChatViewModel` exposing `StateFlow<LiveChatUiState>`, and the Compose chat panel
(`LiveChatPanel`, message list + composer + reaction affordance).

Out of scope (owned elsewhere): the SSE transport itself (AND-143), the HLS player
(AND-280/AND-167), 1:1 / group direct messaging (AND-120–142, a different domain and
endpoint family), persistent chat history / Room caching of broadcast chat (live chat
is ephemeral — see §6), moderation tooling (ban/timeout/delete-others), and slow-mode
enforcement UI (deferred, see §13 OQ-4).

## 2. Context & References

- **Repo / module:** `spannella/testlogon`, Android app under `android/`, branch
  `android-port`. New code lands primarily in `:feature-broadcast` (chat panel,
  `LiveChatViewModel`), with the API seam in `:core-network`, domain models in
  `:core-model`, and the repository in `:core-data`. The chat panel composes into the
  AND-280 `:feature-viewer` `ViewerScreen` (or `feature-broadcast` if AND-280 placed
  the viewer there — this spec consumes whichever module owns the viewer route).
- **Namespace / applicationId base:** `com.testlogon.android`. New packages:
  `com.testlogon.android.feature.broadcast.chat.*`,
  `com.testlogon.android.core.network.broadcast.chat.*`,
  `com.testlogon.android.core.model.broadcast.chat.*`,
  `com.testlogon.android.core.data.broadcast.chat.*`.
- **Stack:** Kotlin 2.0.21, Jetpack Compose + Material 3, single-Activity
  Navigation-Compose, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 + OkHttp 4.12 +
  Moshi 1.15 (codegen, no reflection fallback), Coil (avatars). minSdk 24,
  compile/target 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- **Real-time transport:** AND-143 `SseClient.events(SseRequest): Flow<SseEvent>` in
  `com.testlogon.android.core.network.sse`. It rides the shared persistent cookie jar
  (AND-011), CSRF interceptor (AND-012), and 401-refresh `Authenticator` (AND-013) via
  the `@SseOkHttp` client; it reconnects with jittered backoff and surfaces
  `Open`/`Message`/`Reconnecting`/`Closed(reason)` events.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (PLAINTEXT
  HTTP, unreliable). SSE via `text/event-stream` (`sse-starlette`). Cookie session +
  `ui_csrf` → `X-CSRF-Token`; 401 → single `POST /ui/session/refresh` then retry.
  OpenAPI at `/openapi.json` is the final authority for paths/shapes.
- **Web reference (CORRECTED path):** `frontend/src/api/endpoints/broadcast-chat.ts`
  (chat send/react/history DTOs + functions) and `frontend/src/pages/broadcast/
  BroadcastChat.tsx` (the browser `EventSource` integration — colon-delimited event names,
  `?poll_ms=500`, `getChatHistory(limit:100)` seed — that the native `SseClient`
  reproduces). The chat DTOs live in `broadcast-chat.ts`, not the generic `broadcast.ts`.
- **Upstream tickets:** AND-280 (viewer screen + session id), AND-143 (SSE core).
  Transitively AND-018 (`ApiResult<T>`), AND-015 (FastAPI `detail` mapping), AND-021
  (state composables: loading/empty/error/offline), AND-052 (redacted telemetry).

## 3. Functional Requirements

FR-1. While viewing a live broadcast (`sessionId`), the user sees a **live chat panel**
that connects to the broadcast chat SSE stream and renders incoming messages in
chronological order (newest at the bottom), auto-scrolling to the latest when the user
is already pinned to the bottom.

FR-2. **Chat updates live.** New `chat:message` SSE frames append to the visible list
in real time without a manual refresh, within the latency of the stream. (Event names
are **colon**-delimited — `chat:message` — per the backend `sse-starlette` stream and
`BroadcastChat.tsx`, not dot-delimited; corrected from an earlier draft. The dev stream
is a long-poll-backed SSE that the web client opens with `?poll_ms=500`.)

FR-3. **Send works.** The user types in a composer and sends a text message via
`POST broadcast/sessions/{id}/chat` (request body `BroadcastChatSendIn`:
`{text}` required, `text` ≤ 280 chars; optional `reply_to_message_id`,
`expires_in_seconds`, `lock_price_cents`, `lock_description`). The POST returns the
authoritative `BroadcastChatMessageOut` (`201`). The message is shown **optimistically**
with a `SENDING` state, then reconciled to `SENT` when the server's authoritative copy
arrives (the POST response and/or the `chat:message` SSE echo), or marked `FAILED` with
a retry affordance on error. NOTE (corrected): the backend does **not** accept or
round-trip a `client_id`/nonce (see FR-5) — `BroadcastChatSendIn` has no such field, so
dedup MUST be by server `message_id`. The web reference (`BroadcastChat.tsx`) is in fact
**not** optimistic: it sends, ignores the response body, and lets the SSE echo render the
message; Android adds the optimistic bubble as a UX improvement reconciled on `message_id`.

FR-4. **Reactions.** The user can react to an individual message (long-press → emoji).
A reaction is sent via `POST broadcast/sessions/{id}/chat/{messageId}/react` (singular
`react`, body `BroadcastChatReactIn`: `{emoji, action}` where `action` ∈ `add|remove`,
default `add`; `emoji` ≤ 32 chars). The POST returns `{ok, reactions_counts}`
synchronously (a `Record<emoji,int>` map), and reaction counts also update live from
`chat:reaction` SSE frames (frame shape `{message_id, counts}`); the current user's own
reactions are highlighted from the message's `my_reactions` array.
CORRECTED: there is **no** room-level reaction endpoint
(`POST broadcast/sessions/{id}/reactions` does **not** exist in `/openapi.json`), the
message-reaction path is `.../react` (not `.../reactions`), and the reaction frame
carries a `counts` map (not a per-emoji `{emoji,count,reacted_by_self}` tuple). Room-level
("floating emoji") reactions are therefore **out of scope** for this ticket unless a
backend endpoint is added (see §13 OQ-5).

FR-5. **Idempotent dedup.** Each chat message carries a stable server `message_id`; the
SSE echo of a just-sent message MUST replace (not duplicate) the optimistic local entry.
CORRECTED: the backend exposes **no** `client_id`/nonce on `BroadcastChatSendIn` or on
`BroadcastChatMessageOut`, so the matching key advertised in the original draft does not
exist. Reconciliation MUST instead match the optimistic bubble to the echoed
`BroadcastChatMessageOut` heuristically — by `sender_id == self` + identical `text` +
nearest `created_at` (and then by `message_id` once known) — collapsing the local
`SENDING` entry into the server copy. A client-generated `clientNonce` remains a
**local-only** key for the optimistic list entry (it is never sent to or returned by the
server). See §13 OQ-3 / R-1 for the residual duplicate-render risk this introduces.

FR-6. **Connection state UI.** The panel surfaces the live connection status derived
from `SseEvent`: `Connecting` (before first `Open`), `Live` (after `Open`),
`Reconnecting` (transient drop), and `Offline/Stale` (after `Closed(STALE|...)`),
using the AND-021 state composables. Sending is disabled while not connected (with a
clear reason) but the existing message list remains visible (stale-readable).

FR-7. **Lifecycle.** The SSE subscription is collected under
`repeatOnLifecycle(STARTED)` so it connects when the chat panel/viewer is visible and
disconnects (cancels the `EventSource`) when backgrounded; re-entering reconnects and
resumes the live feed.

FR-8. **Bounded buffer.** The in-memory message list is capped (default 500 most-recent
messages, `MAX_RETAINED`); older messages are evicted to bound memory during long live
sessions (live chat is high-volume and ephemeral).

FR-9. **Empty / first-load.** Before any frame arrives, the panel shows a connecting
state, then an empty state ("Be the first to say something") if the room is silent, not
an indefinite spinner.

FR-10. **Initial backlog.** VERIFIED: the recent-history endpoint **exists** —
`GET broadcast/sessions/{id}/chat?limit=N&before=<cursor>` → `BroadcastChatHistoryOut`
(`{messages: BroadcastChatMessageOut[], has_more: bool, oldest_sort_key: string|null}`).
The panel seeds the list with the last N messages on entry (web uses `limit=100`), then
transitions to the live stream. Pagination is **cursor-based** via `before` +
`oldest_sort_key` (not page-number / `next_page`). OQ-1 is resolved (was "optional";
now confirmed present).

## 4. Technical Design

**Module placement.** API seam + DTOs/mappers in `:core-network`
(`core.network.broadcast.chat`), domain models in `:core-model`
(`core.model.broadcast.chat`), repository in `:core-data`
(`core.data.broadcast.chat`), ViewModel + Compose in the viewer's feature module
(`feature.broadcast.chat`). The feature module depends on `:core-network`,
`:core-model`, `:core-data`, `:core-ui`, and (test) `:core-testing`.

### 4.1 Domain models (`:core-model`)

> CORRECTED to match `BroadcastChatMessageOut` (`/openapi.json`,
> `src/api/endpoints/broadcast-chat.ts: ChatMessage`). The server message is **flat** —
> `message_id`, `sender_id`, `sender_display_name` (there is no nested `author` object,
> no `username`/`avatar_url`/`is_host` on the chat message), `created_at` is an **epoch
> integer** (not an ISO-8601 string → not a `java.time.Instant` parsed from text), and
> reactions arrive as a `reactions_counts` map plus a `my_reactions` array. The original
> draft's `ChatAuthor`/`ChatReaction`/`sentAt: Instant` shapes did not exist on the wire.

```kotlin
package com.testlogon.android.core.model.broadcast.chat

import java.time.Instant

data class ChatMessage(
    val id: String,                 // server message_id; for optimistic msgs == clientNonce until reconciled
    val clientNonce: String?,       // LOCAL-ONLY optimistic key; NOT sent to / returned by server (FR-5)
    val sessionId: String,
    val senderId: String,           // server sender_id (flat; no nested author object)
    val senderDisplayName: String,  // server sender_display_name
    val isSelf: Boolean = false,    // derived: senderId == current viewer
    val isHost: Boolean = false,    // derived (host/broadcaster) — NOT a field on the chat message
    val avatarUrl: String? = null,  // NOT on BroadcastChatMessageOut; resolve separately or omit
    val text: String?,              // nullable on the wire (locked/deleted messages have null text)
    val kind: String = "text",      // server kind (text|tip|lottery|product|...)
    val sentAt: Instant,            // derived from created_at epoch (Instant.ofEpochSecond/Milli)
    val deleted: Boolean = false,
    val reactions: List<ChatReaction> = emptyList(),  // derived from reactions_counts + my_reactions
    val deliveryState: DeliveryState = DeliveryState.SENT,
)

enum class DeliveryState { SENDING, SENT, FAILED }

/** Derived view of the server's reactions_counts map + my_reactions array (no per-emoji
 *  reacted_by_self field exists on the wire — reactedBySelf is computed from my_reactions). */
data class ChatReaction(
    val emoji: String,
    val count: Int,                 // from reactions_counts[emoji]
    val reactedBySelf: Boolean,     // computed: emoji in my_reactions
)

/** A decoded broadcast-chat domain event (parsed from an SseEvent.Message). */
sealed interface ChatStreamEvent {
    data class MessageReceived(val message: ChatMessage) : ChatStreamEvent
    data class MessageDeleted(val messageId: String) : ChatStreamEvent
    // CORRECTED: the chat:reaction frame carries {message_id, counts:Map<emoji,int>} — a
    // whole-message counts map, not a single (emoji,count,reacted_by_self) tuple, and there
    // is no room-level (null messageId) reaction on this stream.
    data class ReactionUpdated(
        val messageId: String,           // always a message id (no room-level on this stream)
        val counts: Map<String, Int>,    // full reactions_counts map from the frame
    ) : ChatStreamEvent
    // chat:unlock frame -> reveal previously-locked text (BCAST-015 Phase D)
    data class MessageUnlocked(val messageId: String, val text: String) : ChatStreamEvent
    data object Unknown : ChatStreamEvent          // unrecognized event name; ignored
}

// NOTE: viewer/presence count is NOT delivered on the chat stream. The web client gets
// it from a SEPARATE EventSource at `GET broadcast/sessions/{id}/stream`
// (src/hooks/useBroadcastStream.ts), owned by AND-280's viewer, not by this ticket. The
// `ViewerCount` event was removed here; if a count is shown it is sourced from that
// viewer stream, not from chat. (See §13 OQ-2.)
```

### 4.2 API seam (`:core-network`)

```kotlin
package com.testlogon.android.core.network.broadcast.chat

import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

interface BroadcastChatApi {

    /** Optional recent-history seed (idempotent GET). OQ-1. */
    @GET("broadcast/sessions/{id}/chat")
    suspend fun history(
        @Path("id") sessionId: String,
        @Query("limit") limit: Int = 50,
    ): Response<ChatHistoryDto>

    /** Send a text message. Returns the authoritative BroadcastChatMessageOut (201). */
    @POST("broadcast/sessions/{id}/chat")
    suspend fun send(
        @Path("id") sessionId: String,
        @Body body: SendChatDto,
    ): Response<ChatMessageDto>

    /** React to a specific message (path is singular `react`). */
    @POST("broadcast/sessions/{id}/chat/{messageId}/react")
    suspend fun reactToMessage(
        @Path("id") sessionId: String,
        @Path("messageId") messageId: String,
        @Body body: ReactionDto,
    ): Response<ReactResultDto>
    // CORRECTED: there is NO room-level POST broadcast/sessions/{id}/reactions endpoint
    // in /openapi.json, so the original `reactToRoom(...)` method was removed.
}

// CORRECTED: BroadcastChatSendIn has NO client_id; it accepts text (req, <=280) plus
// optional reply_to_message_id / expires_in_seconds / lock_price_cents / lock_description.
@JsonClass(generateAdapter = true)
data class SendChatDto(
    val text: String,
    @Json(name = "reply_to_message_id") val replyToMessageId: String? = null,
    @Json(name = "expires_in_seconds") val expiresInSeconds: Int? = null,
    @Json(name = "lock_price_cents") val lockPriceCents: Int? = null,
    @Json(name = "lock_description") val lockDescription: String? = null,
)

// CORRECTED: BroadcastChatReactIn = {emoji, action: add|remove}. The POST returns
// {ok, reactions_counts} synchronously (ReactResultDto), not Unit.
@JsonClass(generateAdapter = true)
data class ReactionDto(val emoji: String, val action: String = "add")

@JsonClass(generateAdapter = true)
data class ReactResultDto(
    val ok: Boolean,
    @Json(name = "reactions_counts") val reactionsCounts: Map<String, Int> = emptyMap(),
)
```

The SSE **stream URL** is not declared on this Retrofit interface (SSE is not a
Retrofit call). It is built from `BuildConfig.API_BASE_URL` +
`broadcast/sessions/{id}/chat/stream` and handed to the AND-143 `SseClient`.

### 4.3 SSE frame parsing

Each `SseEvent.Message(id, event, data)` is mapped to a `ChatStreamEvent` by event
name; `data` is parsed with the shared Moshi instance (codegen DTOs):

CORRECTED event-name catalog (colon-delimited, per `BroadcastChat.tsx`): the chat stream
emits `chat:message`, `chat:delete`, `chat:reaction`, `chat:unlock`, and `chat:lottery`.
There is **no** `chat.message`/`chat.deleted`/`chat.reaction` (dot) name and **no**
`viewer_count`/`presence` event on this stream.

```kotlin
class ChatEventParser @Inject constructor(private val moshi: Moshi) {
    fun parse(event: SseEvent.Message): ChatStreamEvent = when (event.event) {
        "chat:message", "chat:lottery" -> ChatStreamEvent.MessageReceived(
            moshi.adapter(ChatMessageDto::class.java).fromJson(event.data)!!.toDomain())
        "chat:reaction" -> moshi.adapter(ChatReactionEventDto::class.java)   // {message_id, counts}
            .fromJson(event.data)!!.toReactionUpdated()
        "chat:delete"  -> ChatStreamEvent.MessageDeleted(
            moshi.adapter(ChatDeletedDto::class.java).fromJson(event.data)!!.messageId)
        "chat:unlock"  -> moshi.adapter(ChatUnlockDto::class.java)            // {message_id, text}
            .fromJson(event.data)!!.let { ChatStreamEvent.MessageUnlocked(it.messageId, it.text) }
        else -> ChatStreamEvent.Unknown          // forward-compatible; never throws
    }
}
```

Malformed `data` is caught and mapped to `Unknown` (logged at debug, never crashes the
stream — a single bad frame must not tear down a live session).

### 4.4 Repository (`:core-data`)

```kotlin
package com.testlogon.android.core.data.broadcast.chat

interface BroadcastChatRepository {
    /** Cold flow of decoded chat events for a session (wraps SseClient + parser). */
    fun chatEvents(sessionId: String): Flow<ChatStreamEvent>

    /** Optional recent-history seed. */
    suspend fun loadHistory(sessionId: String, limit: Int = 50): ApiResult<List<ChatMessage>>

    /** Send; returns the server message (or ApiResult.Error). */
    suspend fun send(sessionId: String, text: String, clientNonce: String): ApiResult<ChatMessage>

    /** action defaults to "add"; returns the server's reactions_counts map. */
    suspend fun reactToMessage(
        sessionId: String, messageId: String, emoji: String, action: String = "add",
    ): ApiResult<Map<String, Int>>
    // CORRECTED: reactToRoom(...) removed — no room-level reaction endpoint exists.
}
```

`chatEvents` builds the `SseRequest(url = "$base/broadcast/sessions/$sessionId/chat/stream")`,
collects `SseClient.events(...)`, parses `SseEvent.Message` via `ChatEventParser`, and
re-emits lifecycle signals (`Open`/`Reconnecting`/`Closed`) as a connection-status side
channel (see §6). Mutations wrap `BroadcastChatApi` in `ApiResult<T>` with the shared
FastAPI `detail` mapping (AND-015).

### 4.5 ViewModel

```kotlin
@HiltViewModel
class LiveChatViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val repo: BroadcastChatRepository,
    @IoDispatcher private val io: CoroutineDispatcher,
) : ViewModel() {
    private val sessionId: String = savedStateHandle["sessionId"]!!
    val uiState: StateFlow<LiveChatUiState>

    fun onResumeStreaming()                 // (re)start SSE collection; called from repeatOnLifecycle
    fun onComposerTextChange(text: String)
    fun send()                              // optimistic add -> repo.send -> reconcile
    fun retrySend(clientNonce: String)
    fun reactToMessage(messageId: String, emoji: String)
    // CORRECTED: reactToRoom(emoji) removed — no room-level reaction endpoint exists.
    fun onScrolledToBottom(atBottom: Boolean)   // controls auto-scroll/“jump to latest”
}

sealed interface LiveChatUiState {
    data object Connecting : LiveChatUiState
    data class Content(
        val messages: List<ChatMessage>,        // capped at MAX_RETAINED, oldest-first
        val connection: ConnectionStatus,       // LIVE | RECONNECTING | OFFLINE
        val composerText: String,
        val canSend: Boolean,                    // connected && text not blank && not over slow-mode
        val viewerCount: Int?,
        val pinnedToBottom: Boolean,
    ) : LiveChatUiState
    data class Error(val message: String, val retryable: Boolean) : LiveChatUiState
}

enum class ConnectionStatus { LIVE, RECONNECTING, OFFLINE }
```

The ViewModel folds incoming `ChatStreamEvent`s and connection signals into the
`messages`/`connection` fields with a single reducer; `send()` inserts an optimistic
`ChatMessage(deliveryState = SENDING, clientNonce = nonce)` and reconciles by
`clientNonce` (FR-5).

### 4.6 Compose UI

```kotlin
@Composable
fun LiveChatPanel(
    modifier: Modifier = Modifier,
    viewModel: LiveChatViewModel = hiltViewModel(),
)

@Composable
private fun ChatMessageList(
    messages: List<ChatMessage>,
    pinnedToBottom: Boolean,
    onAtBottomChanged: (Boolean) -> Unit,
    onReact: (messageId: String, emoji: String) -> Unit,
)

@Composable
private fun ChatComposer(
    text: String, canSend: Boolean,
    onTextChange: (String) -> Unit, onSend: () -> Unit,
)

@Composable
private fun ConnectionBanner(status: ConnectionStatus, onRetry: () -> Unit)
```

`LiveChatPanel` collects `uiState` via `collectAsStateWithLifecycle()` and drives the
SSE subscription via `LaunchedEffect`/`repeatOnLifecycle(STARTED) { viewModel.onResumeStreaming() }`.
The message list is a `LazyColumn` keyed by `ChatMessage.id` (or `clientNonce` for
optimistic entries), with `reverseLayout = true` for sticky-bottom behavior; a "jump to
latest" FAB appears when the user scrolls up and new messages arrive. The panel renders
as a bottom overlay over the player in portrait and a side panel in landscape.

## 5. API Contract

Base path (dev): `http://18.222.237.167:8000/`. All calls ride the cookie session +
`X-CSRF-Token`. Paths declared without a leading slash. Confirmed against
`/openapi.json` + `frontend/src/api/endpoints/broadcast.ts` before merge (OQ-1/OQ-2).

> NOTE: the §5 shapes below were CORRECTED against `/openapi.json`
> (`components.schemas.BroadcastChat*`) and `src/api/endpoints/broadcast-chat.ts` +
> `src/pages/broadcast/BroadcastChat.tsx`. Field names are **snake_case and flat**; event
> names are **colon-delimited**; there is no `client_id`, no nested `author`, and no
> room-reaction endpoint.

**SSE stream — `GET broadcast/sessions/{id}/chat/stream?poll_ms=500`**
(`Accept: text/event-stream`; query params `after`, `poll_ms`; long-poll-backed SSE via
`sse-starlette`, consumed by AND-143 `SseClient`). Frames (corrected):

```
event: chat:message
data: {"message_id":"cm_01HXA","session_id":"bcs_01HX1","sender_id":"usr_9",
       "sender_display_name":"Mira","text":"hello!","kind":"text",
       "created_at":1749164470,"deleted":false,
       "reactions_counts":{"🔥":3},"my_reactions":[]}

event: chat:reaction
data: {"message_id":"cm_01HXA","counts":{"🔥":12,"❤️":4}}

event: chat:delete
data: {"message_id":"cm_01HXA"}

event: chat:unlock
data: {"message_id":"cm_01HXA","text":"revealed text"}

event: chat:lottery
data: {"message_id":"cm_lot1","kind":"lottery","lottery_id":"lot_1", ...}
```
(Viewer/presence count is NOT on this stream — see §4.3 note. There is no `chat.message`
dot-form and no `viewer_count` frame.)

**Send — `POST broadcast/sessions/{id}/chat`** (req `BroadcastChatSendIn`)

Request (CORRECTED — no `client_id`):
```json
{ "text": "hello!" }
```
Optional fields: `reply_to_message_id`, `expires_in_seconds`, `lock_price_cents`,
`lock_description`. Response `201` — the authoritative `BroadcastChatMessageOut` (same
shape as the `chat:message` frame `data` above: `message_id`, `session_id`, `sender_id`,
`sender_display_name`, `text?`, `kind`, `created_at` (epoch int), `deleted`,
`reactions_counts?`, `my_reactions?`, …). Dedup is by `message_id` (FR-5), not `client_id`.

**React to message — `POST broadcast/sessions/{id}/chat/{messageId}/react`** (singular
`react`; req `BroadcastChatReactIn`) Body `{ "emoji": "🔥", "action": "add" }` (`action` ∈
`add|remove`, default `add`) → `200` with `{ "ok": true, "reactions_counts": {"🔥": 12} }`.
A `chat:reaction` SSE frame (`{message_id, counts}`) also broadcasts the new counts.

**Room reaction — REMOVED.** No `POST broadcast/sessions/{id}/reactions` endpoint exists
in `/openapi.json`; room-level "floating emoji" is out of scope (OQ-5).

**History — `GET broadcast/sessions/{id}/chat?limit=100&before=<oldest_sort_key>`**
(VERIFIED present) → `BroadcastChatHistoryOut`:
```json
{ "messages":[<BroadcastChatMessageOut>...], "has_more": true, "oldest_sort_key": "..." }
```
Idempotent GET, retriable; cursor pagination via `before` ← `oldest_sort_key` (not
page-number / `next_page`).

**Retrofit DTOs** use Moshi `@Json` aliases for the **actual** snake_case fields
(`message_id`, `session_id`, `sender_id`, `sender_display_name`, `created_at`, `deleted`,
`reactions_counts`, `my_reactions`, `reply_to_message_id`, `expires_in_seconds`,
`lock_price_cents`, `lock_description`, `is_unlocked`, `oldest_sort_key`, `has_more`).
`created_at` is an **epoch integer** → convert to `Instant` via
`Instant.ofEpochSecond(...)` (NOT a string parsed by `InstantJsonAdapter`); `text` is
**nullable**. There are no `client_id`/`display_name`/`avatar_url`/`is_host`/`sent_at`/
`reacted_by_self` wire fields.

**Errors:** `401` → single `POST /ui/session/refresh` + retry (AND-013); on a second
`401` the stream is fatal (`Closed(UNAUTHORIZED)`) and the panel routes to
re-auth/offline. `403` (banned/not entitled) → send disabled with a typed message.
`404` (session ended/not found) → `Error("This broadcast has ended", retryable=false)`.
`422`/slow-mode/`429` (`Retry-After`) → transient send failure with retry. FastAPI
`detail` decoded per AND-015.

## 6. Data & State Management

- **Single source of truth:** `StateFlow<LiveChatUiState>` in `LiveChatViewModel`,
  collected with `collectAsStateWithLifecycle()`. The composable holds only transient
  UI (scroll position, emoji-picker open) in `remember`/`rememberSaveable`.
- **Ephemeral, no persistence.** Live broadcast chat is **not** written to Room or
  DataStore — it is high-volume, low-value-after-the-fact, and bounded in memory
  (`MAX_RETAINED = 500`, FR-8). This is a deliberate departure from DM messaging
  (AND-115/116) and is the answer to AND-143's deferred `Last-Event-ID` persistence
  question (Q1) for this consumer: in-memory only.
- **Reducer.** Incoming `ChatStreamEvent` and connection signals fold into the list:
  - `MessageReceived`: if the frame matches an existing `SENDING`/`FAILED` local entry
    (CORRECTED: matched by `senderId == self` + identical `text` + nearest `created_at`,
    since there is no `client_id` on the wire — see FR-5), **replace it** (reconcile to
    `SENT`, adopting the server `message_id`); else append (and evict oldest beyond cap).
    Dedup also guards against a server `message_id` already present.
  - `ReactionUpdated`: replace the target message's reaction map from the frame's `counts`
    map (recompute each `reactedBySelf` from the message's `my_reactions`). No room-level
    reaction case.
  - `MessageUnlocked`: set the target message's `text` and `is_unlocked = true`.
  - `MessageDeleted`: remove by `message_id`.
  - Viewer count is sourced from the separate AND-280 viewer stream, not folded here.
- **Connection status** is carried alongside frames. The repository emits a merged
  flow where SSE lifecycle (`Open` → `LIVE`, `Reconnecting` → `RECONNECTING`,
  `Closed(STALE|UNAUTHORIZED|FATAL_HTTP)` → `OFFLINE`) updates `connection` without
  clearing the already-rendered `messages` (stale-readable).
- **Optimistic send state** lives only in the list as `DeliveryState`; on success it is
  reconciled by the SSE echo or POST response; on failure it flips to `FAILED` with a
  retry that reuses the same `clientNonce` (idempotent re-send).
- **Process death:** `sessionId` restored from `SavedStateHandle`; the chat list is
  *not* restored (ephemeral) — re-entry reconnects and resumes live. `composerText` is
  `rememberSaveable` so an in-progress draft survives rotation.
- **Threading:** SSE collection and parsing run on `Dispatchers.IO` (`flowOn`);
  state updates are marshalled to the main-safe `StateFlow`. No blocking on the main
  thread; `delay`-based backoff is owned by AND-143.

## 7. Error Handling & Resilience

- **Stream drops / reconnect:** owned by AND-143 (jittered exponential backoff 1s→30s,
  `Last-Event-ID` replay, `MAX_CONSECUTIVE_FAILURES = 8` → `Closed(STALE)`). This
  ticket maps those signals to `ConnectionStatus` and keeps the message list visible
  with a "Reconnecting…/Offline — tap to retry" banner (AND-021). Manual retry
  re-collects the cold flow (a fresh subscription).
- **Send failures:** `send()` is a single POST (not auto-retried beyond the AND-013
  401-refresh, since a blind retry of a non-idempotent send could duplicate). On
  timeout/5xx/network error the optimistic entry → `FAILED` with a Retry button that
  re-issues the same `text`. CORRECTED: there is no `client_id` for the server to dedup
  on, so a retry after a request that actually succeeded server-side risks a duplicate;
  enable Retry only after a definite client-side failure (no `2xx`), and reconcile the
  eventual SSE echo by `text`/`created_at`/`message_id` (R-1, OQ-3). On `403`/banned →
  message removed and a typed toast; on `404`/ended → whole panel → `Error(retryable=false)`.
- **Slow-mode / rate limit (`429`):** honor `Retry-After`; disable the composer for the
  cooldown and surface a countdown (best-effort; full slow-mode UI is OQ-4). The send
  is not silently dropped.
- **Bad frames:** a single unparseable `chat:*` frame → `ChatStreamEvent.Unknown`,
  logged at debug, never tears down the stream (§4.3).
- **Unreliable dev host:** drops are the norm; all states (`Connecting`,
  `RECONNECTING`, `OFFLINE`, empty, `Error`) are first-class and reachable — no
  indefinite spinner. A reconnect storm is bounded by AND-143's backoff + cap.
- **Duplicate suppression:** since the wire carries no `client_id` (CORRECTED), dedup is
  by server `message_id` plus the optimistic-reconcile heuristic (`senderId`+`text`+
  `created_at`, FR-5); the optimistic bubble and its SSE echo collapse into one. A small
  residual duplicate window exists on slow networks (R-1).

## 8. Security & Privacy

- **Auth reuse:** both the SSE stream and the send/react POSTs ride the existing
  persistent cookie jar (AND-011), CSRF interceptor (AND-012, `ui_csrf` →
  `X-CSRF-Token` — required for the POST mutations), and 401-refresh `Authenticator`
  (AND-013) via the shared/`@SseOkHttp` clients. No credentials handled here.
- **Cleartext on dev:** chat frames and POST bodies ride plaintext HTTP on the dev host
  — a known, dev-only risk confined to the scoped `network_security_config.xml`
  cleartext allow-list for `18.222.237.167` only; `staging`/`prod` are HTTPS-only.
- **User-generated content:** chat `text` is rendered as plain text (no HTML/markdown
  link execution beyond a safe autolink at most); never interpolated into a WebView or
  evaluated. The sender display name (`sender_display_name`) comes from the server; note
  the chat message carries NO avatar URL field (avatars, if shown, are resolved separately
  — corrected from the original draft's `avatar_url` claim).
- **Logging redaction:** chat message bodies and author identifiers are **not** logged
  in any build (per AND-052). AND-143's debug-only logger may print SSE `data:` at
  `Level.BODY` in debug — flagged as a known debug-only exposure (AND-143 Q2); release
  is unaffected.
- **No new permissions / no secret storage:** uses existing `INTERNET`; nothing
  persisted to disk.

## 9. Accessibility & i18n

- All interactive controls (Send, emoji/react, Retry, jump-to-latest FAB) have
  `contentDescription`s and meet the 48dp touch-target minimum. The composer
  `TextField` has a labeled placeholder.
- Incoming messages and connection-status changes are announced to TalkBack via
  `liveRegion` semantics (polite for new messages, assertive for
  "Reconnecting"/"Offline") so screen-reader users are not stranded on a silent feed.
- All copy ("Be the first to say something", "Reconnecting…", "Offline — tap to
  retry", "Message failed — tap to retry", "Send", host badge, slow-mode countdown) is
  localized string resources (no hardcoded strings); `ConnectionStatus` and send-error
  reasons map to distinct resource ids.
- Emoji reactions are rendered with accessible labels (emoji name where available);
  reaction chips announce "{emoji}, {count}, selected/not selected".
- RTL-safe layout via Compose defaults; the message list and composer use logical
  start/end padding, no fixed left/right.
- Timestamps/viewer counts are localized + timezone-aware (relative "now"/"2m") using
  the shared formatting utilities; no manual string concatenation.

## 10. Telemetry & Logging

- **Events** (via the project analytics interface, AND-052 redaction — no message text,
  no PII):
  `live_chat_connected{sessionId}`, `live_chat_reconnecting{sessionId,attempt}`,
  `live_chat_offline{sessionId,reason}`, `live_chat_message_received{sessionId}` (count
  only / sampled), `live_chat_message_sent{sessionId,ok}`,
  `live_chat_send_failed{sessionId,code}`, `live_chat_reaction_sent{sessionId,target}`.
- **QoE:** time-to-first-message (subscribe → first `chat:message`), reconnect rate,
  and send round-trip latency (POST → SSE echo) for diagnosing the unreliable dev host.
- **Logging:** lifecycle transitions only under tag `LiveChat` (connect/reconnect/
  offline + send ok/fail with HTTP status code) — **never** raw chat `text` or author
  ids. No `println`; reuses AND-143's redacting HTTP logger for the handshake.

## 11. Testing Strategy

- **Unit — `ChatEventParser` (JVM, `:core-testing` + Truth):** each `event` name
  (`chat:message`, `chat:reaction`, `chat:delete`, `chat:unlock`, `chat:lottery`) parses
  to the correct `ChatStreamEvent`; an unknown event and a malformed `data` body both map
  to `Unknown` without throwing. (CORRECTED: colon-delimited names; no `viewer_count`.)
- **Unit — `BroadcastChatRepository`/SSE wiring (MockWebServer):** enqueue a
  `text/event-stream` body of `chat:message` frames; assert `chatEvents()` emits the
  parsed `MessageReceived`s in order (reuses AND-143's `MockWebServer` SSE harness).
  Assert a socket drop → `Reconnecting` signal → resume (delegated to AND-143, asserted
  at the consumer boundary). Assert `send()` issues `POST broadcast/sessions/{id}/chat`
  with `X-CSRF-Token` and a `{text}` body (NO `client_id`), and maps the
  `BroadcastChatMessageOut` response to `ChatMessage`.
- **Unit — `LiveChatViewModel` reducer (Turbine + `runTest`):**
  - **Chat updates live (KEY):** feeding `MessageReceived` events appends them to
    `Content.messages` and sets `connection = LIVE` after `Open`.
  - **Send works (KEY):** `send()` inserts an optimistic `SENDING` entry; the SSE echo
    reconciles it to `SENT` exactly once (CORRECTED: matched by `senderId`+`text`+
    `created_at`/`message_id`, not `client_id`) — no duplicate.
  - Send failure → `FAILED`; `retrySend(nonce)` re-issues the same `text`.
  - `ReactionUpdated` replaces the target message's reaction counts from the frame's
    `counts` map and recomputes `reactedBySelf` from `my_reactions`.
  - `Closed(STALE)` → `connection = OFFLINE` while messages remain; manual retry
    re-subscribes. `canSend` is false while not `LIVE`.
  - `MAX_RETAINED` eviction: feeding > cap messages keeps only the newest `MAX_RETAINED`.
- **API contract (MockWebServer):** verb/path/`X-CSRF-Token`/body for `send`,
  `reactToMessage` (path `.../react`, body `{emoji,action}`), and `history`
  (`limit`/`before` → `BroadcastChatHistoryOut`); `401` → refresh → retry once;
  `403`/`404`/`429`/`422` mappings via AND-015. (CORRECTED: no `reactToRoom` to test.)
- **Compose UI tests:** `LiveChatPanel` renders Connecting/Content/Error;
  typing + Send invokes `send()` and shows the optimistic bubble; Retry on a failed
  message invokes `retrySend`; the connection banner shows for `RECONNECTING`/`OFFLINE`;
  semantics/`contentDescription`s and `liveRegion` present; jump-to-latest appears when
  scrolled up.
- **Acceptance E2E (instrumented + manual):** against a live dev session, two clients —
  one sends, the other sees the message appear live; the sender's optimistic bubble
  reconciles without duplication.

Gating tests: the two KEY ViewModel tests ("chat updates live", "send works") plus the
SSE consumer emit test directly satisfy the backlog acceptance bar.

## 12. Dependencies & Sequencing

- **Depends on AND-280** (Viewer playback — HLS): provides the `ViewerScreen`, the
  `viewer/{sessionId}` route, and the live-session context the chat panel composes into.
- **Depends on AND-143** (SSE client core): provides `SseClient.events(SseRequest)`,
  reconnect/backoff, and the `MockWebServer` SSE test harness reused here. This ticket
  is a *consumer* of AND-143; it adds no transport code.
- **Transitively benefits from** AND-278 (broadcast DTOs / `sessionId` source), AND-018
  (`ApiResult`), AND-015 (error `detail` mapping), AND-021 (state composables), AND-011/
  012/013 (cookie/CSRF/refresh — inherited via shared clients), AND-052 (telemetry
  redaction). These are runtime/shared and need no edits here.
- **Blocks:** none recorded in the source bullet.
- **Build deps:** none new — `okhttp-sse` (AND-143), Retrofit/Moshi/Hilt
  (AND-009/010/004), Turbine + `kotlinx-coroutines-test` + MockWebServer (`:core-testing`)
  are already present.
- **Sequencing within the ticket:** (1) confirm chat stream path, event-name catalog,
  send/react paths, and the history-endpoint existence against `/openapi.json` +
  `broadcast-chat.ts` (OQ-1/OQ-2 — now resolved during review); (2) define `:core-model` chat domain types; (3) DTOs +
  codegen adapters + `ChatEventParser`; (4) `BroadcastChatApi` + Hilt provider;
  (5) `BroadcastChatRepository` (SSE merge + mutations); (6) `LiveChatViewModel` reducer;
  (7) `LiveChatPanel` Compose + wire into the viewer; (8) tests T-parser/repo/VM/UI.

## 13. Risks & Open Questions

- **R-1 Send/echo race & duplicates.** ELEVATED (CORRECTED): the backend exposes no
  `client_id`, so there is no robust dedup key — the optimistic bubble and the SSE echo
  can both render if the heuristic match fails. *Mitigation:* match optimistic→echo on
  `senderId`+`text`+nearest `created_at`, then adopt `message_id`; dedup later frames by
  `message_id`; keep the optimistic window short. Guarded by the "send works" VM test.
  Residual risk accepted unless the backend adds an idempotency key (OQ-3).
- **R-2 High message volume / jank.** A busy room can flood the list and the main
  thread. *Mitigation:* `MAX_RETAINED` cap, keyed `LazyColumn`, parse on IO, and (if
  needed) `conflate()`/batched state updates; reaction frames coalesced by emoji.
- **R-3 Unreliable dev host.** Frequent drops → flickering connection state.
  *Mitigation:* AND-143 backoff + cap; keep messages visible during `RECONNECTING`;
  only show `OFFLINE` after `Closed(STALE)`.
- **R-4 Ephemeral vs. backlog.** A late joiner could see an empty room. *Mitigation:*
  the history endpoint is confirmed to exist (FR-10/OQ-1 resolved), so seed with
  `GET .../chat?limit=100` on entry, then go live.
- **R-5 Slow-mode/abuse not enforced client-side.** Spam protection is largely
  server-side; client only reflects `429`. Full slow-mode UI deferred (OQ-4).
- **OQ-1:** RESOLVED — `GET broadcast/sessions/{id}/chat?limit=N&before=<cursor>` exists
  and returns `BroadcastChatHistoryOut` (`{messages, has_more, oldest_sort_key}`). Seed
  with `limit=100`.
- **OQ-2:** RESOLVED — the stream is the dedicated `.../chat/stream` (query `after`,
  `poll_ms`; web opens with `?poll_ms=500`). Event names are colon-delimited:
  `chat:message`, `chat:reaction`, `chat:delete`, `chat:unlock`, `chat:lottery`. Viewer/
  presence count is on a SEPARATE `.../stream` (AND-280), not this stream.
- **OQ-3:** RESOLVED (negative) — the backend does **not** accept or echo a
  `client_id`/nonce (`BroadcastChatSendIn`/`BroadcastChatMessageOut` have no such field).
  Dedup MUST be by server `message_id` + the optimistic heuristic; residual duplicate
  risk per R-1. *Follow-up:* file a backend ticket if an idempotency key is wanted.
- **OQ-4:** Slow-mode / rate-limit policy — STILL OPEN. The OpenAPI does not document a
  `429`/cooldown contract for chat send; the web client uses a hard-coded 2s client
  cooldown (`BroadcastChat.tsx`). *Default:* mirror a short client cooldown + reactively
  honor any `429`/`Retry-After`.
- **OQ-5:** RESOLVED (partial) — only **message-level** reactions exist
  (`POST .../chat/{id}/react`, `{emoji, action}`). There is NO room-level reaction
  endpoint, so "floating emoji" room reactions are out of scope. Emoji set is not
  server-enumerated; use a small curated picker pending product input.

## 14. Acceptance Criteria

AC-1 (backlog — **chat updates live**). With the chat panel visible on a live session,
`chat:message` SSE frames append to the visible list in real time (asserted via the SSE
consumer emit test + the ViewModel reducer test); the connection shows `LIVE` after the
first `Open`.

AC-2 (backlog — **send works**). Typing and pressing Send issues
`POST broadcast/sessions/{id}/chat` with a `{text}` body (CORRECTED: no `client_id`) and
`X-CSRF-Token`, shows the message optimistically (`SENDING`), and reconciles to `SENT` on
the server echo/`BroadcastChatMessageOut` response **exactly once** (no duplicate; matched
by `senderId`+`text`+`created_at`/`message_id`). Failure → `FAILED` with a working retry
that re-sends the same `text`.

AC-3 Reactions: reacting to a **message** issues `POST .../chat/{id}/react`
(`{emoji, action}`); the POST response `reactions_counts` and incoming `chat:reaction`
frames (`{message_id, counts}`) update counts and the self-highlight (from `my_reactions`)
live. (CORRECTED: no room-level reaction.)

AC-4 Connection lifecycle: the panel maps `Open`/`Reconnecting`/`Closed` to
`LIVE`/`RECONNECTING`/`OFFLINE`, keeps already-rendered messages visible during a drop,
disables sending while not `LIVE`, and offers manual retry on `OFFLINE` — never an
infinite spinner.

AC-5 Lifecycle/leaks: the SSE subscription connects under `repeatOnLifecycle(STARTED)`
and is cancelled on background/dispose (no leaked `EventSource`); re-entry resumes live.

AC-6 Bounded memory: the list never exceeds `MAX_RETAINED`; oldest messages evict.

AC-7 Resilience: a malformed/unknown SSE frame is ignored without tearing down the
stream; `401` triggers one refresh+retry; `403`/`404`/`429` map to the typed states in
§5/§7.

AC-8 Security/privacy: cleartext confined to the dev allow-list; no chat text/author ids
in logs in any build; CSRF header present on all mutations.

AC-9 a11y/i18n: all controls labeled and ≥48dp; new messages and status changes
announced via `liveRegion`; all copy localized; RTL-safe.

AC-10 All §11 unit, contract, and Compose tests pass in CI; the instrumented happy-path
(two clients: one sends, the other receives live) succeeds against the dev host.

## 15. Definition of Done

- Code merged to `android-port` under `com.testlogon.android.feature.broadcast.chat.*`
  (+ `core.network.broadcast.chat`, `core.model.broadcast.chat`,
  `core.data.broadcast.chat`), reviewed and green in CI (build, lint/detekt, unit +
  instrumented).
- `BroadcastChatApi` (+ DTOs, Moshi codegen adapters, Hilt provider), `ChatEventParser`,
  `BroadcastChatRepository`, domain models, `LiveChatViewModel`, and the `LiveChatPanel`
  Compose surface implemented with the signatures in §4.
- The chat panel is wired into the AND-280 viewer (`viewer/{sessionId}`) and subscribes
  to `SseClient` via `repeatOnLifecycle(STARTED)`; ephemeral in-memory list capped at
  `MAX_RETAINED`; no Room/DataStore persistence of chat.
- Optimistic send with `message_id` + heuristic dedup (CORRECTED: no `client_id`),
  FAILED-state retry, and **message-level** reactions (no room reactions) implemented and
  reconciled from SSE frames.
- All §14 acceptance criteria demonstrably met, including a manual two-client live
  verification against `http://18.222.237.167:8000`.
- Telemetry events from §10 emitted with AND-052 redaction; no chat text/author ids in
  logs (verified in review).
- Strings localized; accessibility semantics (`liveRegion`, contentDescriptions, 48dp)
  present; dev cleartext config scoped and release config verified clean.
- Open questions OQ-1..OQ-5 resolved against `/openapi.json` +
  `frontend/src/api/endpoints/broadcast-chat.ts` (+ `BroadcastChat.tsx`) or explicitly
  deferred with follow-up tickets; spec updated if endpoint shapes differ from §5
  (resolved during this review — see §16).

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer. Sources:
OpenAPI index = `reference/openapi.index.txt`; OpenAPI schemas =
`reference/openapi.pretty.json` (`components.schemas.<Name>`); frontend =
`reference/src/...`.

1. **Send endpoint** is `POST /broadcast/sessions/{session_id}/chat`, req
   `BroadcastChatSendIn`, resp `201 BroadcastChatMessageOut`. — **Verified.**
   Source: OpenAPI `POST /broadcast/sessions/{session_id}/chat`
   (op `send_chat_message_route...`); `src/api/endpoints/broadcast-chat.ts: sendChatMessage`.
2. **`BroadcastChatSendIn` fields**: `text` (req, ≤280) + optional `reply_to_message_id`,
   `expires_in_seconds`, `lock_price_cents`, `lock_description`; **no `client_id`**. —
   **Corrected** (draft claimed a `client_id` body field).
   Source: schema `BroadcastChatSendIn`; `broadcast-chat.ts: sendChatMessage` options.
3. **Send-message shape `BroadcastChatMessageOut`** is flat: `message_id`, `session_id`,
   `sender_id`, `sender_display_name`, `text` (nullable), `kind`, `created_at` (epoch
   **integer**), `deleted`, `reactions_counts` (map), `my_reactions` (array), reply/
   lock/tip/lottery fields. No nested `author`, no `username`/`avatar_url`/`is_host`, no
   `sent_at` string, no `client_id`. — **Corrected** (draft used `id`, nested `author`,
   `sent_at` ISO string). Source: schema `BroadcastChatMessageOut`;
   `broadcast-chat.ts: ChatMessage`.
4. **Message-reaction endpoint** is `POST /broadcast/sessions/{session_id}/chat/{message_id}/react`
   (singular `react`), req `BroadcastChatReactIn` `{emoji, action: add|remove}`, resp `200`
   `{ok, reactions_counts}`. — **Corrected** (draft used `.../reactions` and `{emoji}` →
   `Unit`). Source: OpenAPI `POST .../chat/{message_id}/react`
   (op `react_to_chat_message_route...`); schema `BroadcastChatReactIn`;
   `broadcast-chat.ts: reactToChatMessage`.
5. **Room-level reaction endpoint** `POST /broadcast/sessions/{id}/reactions`. —
   **Corrected / removed** (does NOT exist). Source: absence in OpenAPI index (grep of
   `sessions/{session_id}/reactions` and `/react` returns only the message-level route
   and unrelated `messaging`/`posts` reaction routes).
6. **History endpoint** `GET /broadcast/sessions/{session_id}/chat?limit&before` →
   `BroadcastChatHistoryOut` `{messages, has_more, oldest_sort_key}`. — **Corrected**
   (draft labeled it "optional/maybe-absent" and used `{items, next_page}`). Source:
   OpenAPI `GET /broadcast/sessions/{session_id}/chat` (op `get_chat_history_route...`,
   params `session_id,limit,before,...`); schema `BroadcastChatHistoryOut`;
   `broadcast-chat.ts: getChatHistory`.
7. **SSE stream endpoint** `GET /broadcast/sessions/{session_id}/chat/stream`, params
   `after`, `poll_ms` (web opens `?poll_ms=500`); long-poll-backed SSE. — **Verified**
   (path) / **Corrected** (params + long-poll nature added). Source: OpenAPI
   `GET .../chat/stream` (op `broadcast_chat_stream_route...`, params
   `session_id,after,poll_ms,...`); `src/pages/broadcast/BroadcastChat.tsx` (EventSource
   on that URL with `poll_ms=500`).
8. **SSE event names** are colon-delimited: `chat:message`, `chat:reaction`,
   `chat:delete`, `chat:unlock`, `chat:lottery`. — **Corrected** (draft used
   `chat.message`/`chat.reaction`/`chat.deleted`). Source: `BroadcastChat.tsx`
   `es.addEventListener("chat:message"|"chat:delete"|"chat:reaction"|"chat:unlock"|"chat:lottery", …)`.
9. **`chat:reaction` frame shape** is `{message_id, counts: Map<emoji,int>}`. —
   **Corrected** (draft used `{message_id, emoji, count, reacted_by_self}`). Source:
   `BroadcastChat.tsx` reaction handler (`data.counts`); reflected by
   `reactions_counts`/`my_reactions` on `BroadcastChatMessageOut`.
10. **Viewer/presence count** is NOT delivered on the chat stream; it comes from a
    separate `GET /broadcast/sessions/{id}/stream` (AND-280). — **Corrected** (draft
    included a `viewer_count`/`presence` chat event + `ViewerCount` domain event).
    Source: `src/hooks/useBroadcastStream.ts` (EventSource on `.../stream`); chat stream
    handlers in `BroadcastChat.tsx` register no count event.
11. **No `client_id`/nonce round-trip** for optimistic dedup; web client is not even
    optimistic (sends, ignores body, relies on SSE echo). — **Corrected.** Source:
    schemas `BroadcastChatSendIn`/`BroadcastChatMessageOut` (no field);
    `BroadcastChat.tsx: handleSend` ("SSE will deliver the message if successful").
12. **Auth/CSRF**: mutations ride the cookie session + `ui_csrf` cookie →
    `X-CSRF-Token` header; stream uses credentialed request. — **Verified.** Source:
    `src/api/client.ts` (`credentials:"include"`, `getCookie("ui_csrf")` →
    `headers.set("X-CSRF-Token", csrf)`); `BroadcastChat.tsx` EventSource
    `{ withCredentials: true }`.
13. **Validation/errors**: `422 HTTPValidationError` is the documented send/react error;
    `401`-refresh-once is an app-wide convention (AND-013), not chat-specific. — **Verified**
    (422) / **Unverified-assumption** (`403`/`404`/`429`/`Retry-After` specifics for
    chat). Source: OpenAPI resp lists show only `201/200` + `422` for chat routes; no
    `403/404/429` documented → see Open assumptions.
14. **Reaction emoji** length ≤32, `action` pattern `^(add|remove)$` default `add`. —
    **Verified.** Source: schema `BroadcastChatReactIn`.
15. **Framework choices** (Compose `LazyColumn` keyed + `reverseLayout`,
    `collectAsStateWithLifecycle`, `repeatOnLifecycle(STARTED)`,
    `Androidx lifecycle-runtime-compose`). — **Unverified-assumption (framework ref)**;
    standard Android guidance, not derivable from backend/frontend sources. framework ref:
    developer.android.com/jetpack/compose/lists and
    developer.android.com/topic/libraries/architecture/coroutines#lifecycle-aware.

### Corrections made

- C-1 Send body: removed `client_id`; added the real optional fields (#2).
- C-2 Message shape: flat `sender_id`/`sender_display_name`, `created_at` epoch int,
  nullable `text`, `reactions_counts`/`my_reactions`; dropped nested `author`/`avatar`/
  `is_host`/`sent_at` (#3) — updated §4.1 domain model, §5, §6, §8.
- C-3 Reaction endpoint: `.../react` (singular) with `{emoji, action}` → `{ok,
  reactions_counts}` (#4) — §4.2, §5, §14 AC-3.
- C-4 Removed nonexistent room-reaction endpoint and all `reactToRoom` API/repo/VM/FR
  surface (#5) — FR-4, §4.2, §4.4, §4.5, §5, §14 AC-3, §15.
- C-5 History endpoint confirmed present with `limit`/`before` cursor +
  `{messages,has_more,oldest_sort_key}` (#6) — FR-10, §5, OQ-1, R-4.
- C-6 SSE event names → colon-delimited; added `chat:unlock`/`chat:lottery`; removed dot
  forms (#8) — FR-2, §4.3, §5, §10, §11, OQ-2, §14 AC-1.
- C-7 Reaction frame shape → `{message_id, counts}` and domain `ReactionUpdated(counts)`
  (#9) — §4.1, §4.3, §5, §6.
- C-8 Removed `viewer_count`/`ViewerCount` from the chat stream; pointed to AND-280's
  separate stream (#10) — §4.1, §4.3, §5, §6, §9.
- C-9 Dedup strategy reworked from `client_id` to `message_id` + heuristic; R-1 elevated
  (#11) — FR-3, FR-5, §6, §7, §11, R-1, OQ-3, §14 AC-2, §15.
- C-10 Web-reference path fixed to `broadcast-chat.ts` + `BroadcastChat.tsx` — §2, §12, §15.

### Open assumptions

- OA-1 (**send/react error codes**): `403` (banned/muted), `404` (session ended), `429`
  (slow-mode/`Retry-After`) handling is assumed. OpenAPI documents only `201/200`+`422`
  for these routes, so the exact non-`422` error contract is unverifiable from the
  sources; treat as graceful-degradation behavior (AND-015 `detail` mapping). The web
  client only uses a fixed 2s client-side cooldown (`BroadcastChat.tsx`), with no `429`
  handling visible.
- OA-2 (**self/host derivation**): `isSelf` (compare `sender_id` to current user) and
  `isHost`/host badge are derived client-side; the chat message has no `is_host` flag and
  no current-user id is returned on the frame — host identity must come from the AND-280
  session/profile context. Unverifiable from chat sources alone.
- OA-3 (**avatars**): `BroadcastChatMessageOut` has no avatar URL; if avatars are shown
  they must be resolved from a separate profile lookup. Product/source does not specify
  one for live chat; assumed omitted for v1.
- OA-4 (**`Last-Event-ID` replay on the chat stream**): AND-143 supports it generically,
  but the chat stream's cursor is `after`/`poll_ms` (long-poll); whether the server
  honors `Last-Event-ID` here is unverified — assume `after`-based resume.
- OA-5 (**AND-143 `SseClient` signatures**, `@SseOkHttp`, `SseEvent` shape): consumed as
  described by the upstream ticket; not present in these reference sources (different
  repo/module), so taken on faith from AND-143.

## 17. Test Plan

Test target legend: JVM = JVM/Robolectric local (no device); EMU = headless AVD `test35`
(x86_64, API 35) in CI; DEVICE = physical Samsung Galaxy A15 5G (SM-A156U, API 34,
arm64-v8a). MockWebServer (MWS) runs under JVM. Prefer DEVICE only where real hardware/
behavior matters; live chat is network+UI, so most cases are JVM/EMU, with one DEVICE
e2e for real-network SSE drop behavior on cellular.

- **TC-AND-281-01** — Type: unit (JVM). Target: `ChatEventParser`.
  Preconditions: Moshi codegen DTOs wired.
  Steps: feed `SseEvent.Message` with `event="chat:message"` and a valid
  `BroadcastChatMessageOut` JSON (epoch `created_at`, null/non-null `text`).
  Expected: returns `MessageReceived` with mapped `id=message_id`, `senderId`,
  `senderDisplayName`, `sentAt` from epoch, `reactions` from `reactions_counts`.
  Traces: AC-1.
- **TC-AND-281-02** — Type: unit (JVM). Target: `ChatEventParser`.
  Preconditions: none. Steps: feed `chat:reaction` `{message_id, counts}`, `chat:delete`
  `{message_id}`, `chat:unlock` `{message_id, text}`.
  Expected: parse to `ReactionUpdated(counts)`, `MessageDeleted`, `MessageUnlocked`
  respectively, with correct fields. Traces: AC-3, AC-7.
- **TC-AND-281-03** — Type: unit (JVM). Target: `ChatEventParser`.
  Preconditions: none. Steps: feed (a) an unknown event name `foo:bar`, (b) a
  `chat:message` with malformed/truncated JSON.
  Expected: both yield `ChatStreamEvent.Unknown`; no exception thrown; stream not torn
  down. Traces: AC-7.
- **TC-AND-281-04** — Type: contract/MockWebServer (JVM). Target: `BroadcastChatApi.send`
  + repository. Preconditions: MWS enqueues `201` `BroadcastChatMessageOut`.
  Steps: call `send(sessionId, "hello!")`.
  Expected: request is `POST /broadcast/sessions/{id}/chat`, body `{"text":"hello!"}`
  with **no** `client_id`, header `X-CSRF-Token` present; response mapped to `ChatMessage`
  (`id=message_id`, `deliveryState=SENT`). Traces: AC-2, AC-8.
- **TC-AND-281-05** — Type: contract/MockWebServer (JVM). Target:
  `BroadcastChatApi.reactToMessage`. Preconditions: MWS enqueues `200`
  `{"ok":true,"reactions_counts":{"🔥":12}}`.
  Steps: call `reactToMessage(id, msgId, "🔥", "add")`.
  Expected: request path `.../chat/{msgId}/react` (singular), body
  `{"emoji":"🔥","action":"add"}`, `X-CSRF-Token` present; returns counts map.
  Traces: AC-3, AC-8.
- **TC-AND-281-06** — Type: contract/MockWebServer (JVM). Target:
  `BroadcastChatApi.history`. Preconditions: MWS enqueues `BroadcastChatHistoryOut`
  with `has_more=true`, an `oldest_sort_key`, and N messages.
  Steps: call `loadHistory(id, limit=100)`; then call again with `before=oldest_sort_key`.
  Expected: first request `GET .../chat?limit=100`; second carries `before=<cursor>`;
  messages mapped oldest-first; `has_more`/cursor surfaced. Traces: AC-1.
- **TC-AND-281-07** — Type: contract/MockWebServer (JVM). Target: error mapping via
  AND-015. Preconditions: MWS enqueues a `422 HTTPValidationError` (e.g., empty/oversized
  `text`), and (best-effort) `429` with `Retry-After`.
  Steps: call `send` for each.
  Expected: `422` → `ApiResult.Error` with decoded `detail`, optimistic entry → `FAILED`
  retryable; `429` → transient failure honoring `Retry-After` (OA-1). Traces: AC-7.
- **TC-AND-281-08** — Type: contract/MockWebServer (JVM). Target: `chatEvents()` SSE
  consumer. Preconditions: MWS serves a `text/event-stream` body of ordered `chat:message`
  frames (reuses AND-143 harness). Steps: collect `chatEvents(sessionId)` with Turbine.
  Expected: emits `MessageReceived` in frame order; `Open` mapped to `LIVE`. Traces: AC-1.
- **TC-AND-281-09** — Type: unit (JVM, Turbine + `runTest`). Target: `LiveChatViewModel`
  reducer — **chat updates live (KEY)**. Preconditions: fake repo flow.
  Steps: emit `Open`, then several `MessageReceived`.
  Expected: `uiState` becomes `Content` with `connection=LIVE` and messages appended in
  order, newest last. Traces: AC-1, AC-4.
- **TC-AND-281-10** — Type: unit (JVM, Turbine + `runTest`). Target: `LiveChatViewModel`
  — **send works + dedup (KEY)**. Preconditions: fake repo; `send()` returns a server
  message; SSE then echoes the same message.
  Steps: `onComposerTextChange("hi")`; `send()`; then emit the `chat:message` echo for the
  same `senderId`/`text`.
  Expected: optimistic `SENDING` entry appears, then collapses to a single `SENT` entry
  (matched by `senderId`+`text`+`created_at`/`message_id`) — exactly one bubble, no
  duplicate. Traces: AC-2.
- **TC-AND-281-11** — Type: unit (JVM, Turbine). Target: `LiveChatViewModel` — send
  failure/retry + reaction + eviction + offline.
  Steps: (a) make `send()` fail → assert entry `FAILED`, `retrySend` re-sends same `text`;
  (b) emit `ReactionUpdated(counts)` → assert target message counts replaced and
  `reactedBySelf` recomputed from `my_reactions`; (c) feed > `MAX_RETAINED` messages →
  assert list capped to newest `MAX_RETAINED`; (d) emit `Closed(STALE)` → assert
  `connection=OFFLINE`, messages retained, `canSend=false`, manual retry re-subscribes.
  Expected: as above. Traces: AC-2, AC-3, AC-6, AC-4.
- **TC-AND-281-12** — Type: Compose-UI (EMU). Target: `LiveChatPanel`.
  Preconditions: ViewModel fed fake states.
  Steps: render `Connecting`, `Content`, `Error`; type text + tap Send; render a `FAILED`
  message and tap Retry; long-press a message → react.
  Expected: states render correctly; Send invokes `send()` and shows optimistic bubble;
  Retry invokes `retrySend`; reaction invokes `reactToMessage`; `RECONNECTING`/`OFFLINE`
  show the connection banner; never an infinite spinner. Traces: AC-2, AC-3, AC-4, AC-7.
- **TC-AND-281-13** — Type: Compose-UI / accessibility (EMU). Target: `LiveChatPanel`
  semantics. Preconditions: TalkBack semantics assertions.
  Steps: assert all controls (Send, react, Retry, jump-to-latest) have
  `contentDescription` and ≥48dp; assert new-message `liveRegion=polite` and
  connection-change `liveRegion=assertive`; reaction chip announces "{emoji}, {count},
  selected/not"; verify localized strings (no hardcoded). Expected: all present.
  Traces: AC-9.
- **TC-AND-281-14** — Type: integration (JVM/MWS). Target: lifecycle/leak +
  flaky-host/offline path. Preconditions: MWS SSE that opens then drops the socket, then
  accepts a fresh connection. Steps: drive `repeatOnLifecycle(STARTED)` start → background
  (cancel) → foreground (resubscribe); inject a mid-stream socket drop.
  Expected: subscription cancels on background (no leaked collector/EventSource), resumes
  on foreground; drop maps to `RECONNECTING` with messages retained, then `LIVE` on
  resume; only after `Closed(STALE)` → `OFFLINE`. Traces: AC-4, AC-5.
- **TC-AND-281-15** — Type: instrumented/e2e (**DEVICE — physical A15 5G required**).
  Target: full stack against dev host `http://18.222.237.167:8000`.
  Preconditions: two authenticated clients on the same live `sessionId` (one of them the
  physical device on real cellular/Wi-Fi to exercise real SSE long-poll + reconnect on a
  flaky/plaintext host); cleartext allow-list scoped to the dev IP.
  Steps: client A sends a message; observe it on the physical device live; toggle airplane
  mode briefly on the device to force a real drop, then restore.
  Expected: B (device) sees A's message live within stream latency; the device's own
  optimistic send reconciles to a single bubble (no duplicate); during the drop the panel
  shows `RECONNECTING` keeping prior messages, then returns to `LIVE`; cleartext to the
  dev IP works while release config stays HTTPS-only. MUST run on the physical device
  (real-network SSE drop/reconnect + plaintext path; API-34/arm64). Traces: AC-1, AC-2,
  AC-4, AC-8, AC-10.

### Coverage matrix

| AC | Covered by |
|----|-----------|
| AC-1 (chat updates live) | TC-01, TC-06, TC-08, TC-09, TC-15 |
| AC-2 (send works) | TC-04, TC-10, TC-11, TC-12, TC-15 |
| AC-3 (reactions) | TC-02, TC-05, TC-11, TC-12 |
| AC-4 (connection lifecycle) | TC-09, TC-11, TC-12, TC-14, TC-15 |
| AC-5 (lifecycle/leaks) | TC-14 |
| AC-6 (bounded memory) | TC-11 |
| AC-7 (resilience/bad frames/errors) | TC-02, TC-03, TC-07, TC-12 |
| AC-8 (security/CSRF/cleartext) | TC-04, TC-05, TC-15 |
| AC-9 (a11y/i18n) | TC-13 |
| AC-10 (CI suite + e2e two-client) | all unit/contract/UI (TC-01..14) + TC-15 |
