---
id: AND-281
title: Live chat
milestone: M6
epic: E38
priority: P0
size: L
status: draft
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
- **Web reference:** `frontend/src/api/endpoints/broadcast.ts` (chat send/react),
  shared types in `frontend/src/api/types.ts`, and the browser `EventSource`
  integration the native `SseClient` reproduces.
- **Upstream tickets:** AND-280 (viewer screen + session id), AND-143 (SSE core).
  Transitively AND-018 (`ApiResult<T>`), AND-015 (FastAPI `detail` mapping), AND-021
  (state composables: loading/empty/error/offline), AND-052 (redacted telemetry).

## 3. Functional Requirements

FR-1. While viewing a live broadcast (`sessionId`), the user sees a **live chat panel**
that connects to the broadcast chat SSE stream and renders incoming messages in
chronological order (newest at the bottom), auto-scrolling to the latest when the user
is already pinned to the bottom.

FR-2. **Chat updates live.** New `chat.message` SSE frames append to the visible list
in real time without a manual refresh, within the latency of the stream.

FR-3. **Send works.** The user types in a composer and sends a text message via
`POST broadcast/sessions/{id}/chat`. The message is shown **optimistically** with a
`SENDING` state, then reconciled to `SENT` when the server's authoritative copy
arrives (either in the POST response or echoed back over the SSE stream), or marked
`FAILED` with a retry affordance on error.

FR-4. **Reactions.** The user can react to the room (a floating emoji/“tap to react”
affordance) and/or to an individual message (long-press → emoji). A reaction is sent
via `POST broadcast/sessions/{id}/chat/{messageId}/reactions` (message reaction) or
`POST broadcast/sessions/{id}/reactions` (room reaction). Reaction counts on a message
update live from `chat.reaction` SSE frames; the current user's own reactions are
highlighted.

FR-5. **Idempotent dedup.** Each chat message carries a stable server `id`; the SSE
echo of a just-sent message MUST replace (not duplicate) the optimistic local entry,
matched by a client-generated `clientNonce`/`client_id` round-tripped through the send
call and the echoed frame.

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

FR-10. **Initial backlog (optional).** If the backend exposes a recent-history endpoint
(`GET broadcast/sessions/{id}/chat?limit=N`), the panel seeds the list with the last N
messages on entry, then transitions to the live stream; if not exposed, the panel
starts empty and is live-only (reconciled against `/openapi.json`, OQ-1).

## 4. Technical Design

**Module placement.** API seam + DTOs/mappers in `:core-network`
(`core.network.broadcast.chat`), domain models in `:core-model`
(`core.model.broadcast.chat`), repository in `:core-data`
(`core.data.broadcast.chat`), ViewModel + Compose in the viewer's feature module
(`feature.broadcast.chat`). The feature module depends on `:core-network`,
`:core-model`, `:core-data`, `:core-ui`, and (test) `:core-testing`.

### 4.1 Domain models (`:core-model`)

```kotlin
package com.testlogon.android.core.model.broadcast.chat

import java.time.Instant

data class ChatMessage(
    val id: String,                 // server id; for optimistic msgs == clientNonce until reconciled
    val clientNonce: String?,       // set for locally-originated messages; matched against echo
    val sessionId: String,
    val author: ChatAuthor,
    val text: String,
    val sentAt: Instant,
    val reactions: List<ChatReaction> = emptyList(),
    val deliveryState: DeliveryState = DeliveryState.SENT,
)

enum class DeliveryState { SENDING, SENT, FAILED }

data class ChatAuthor(
    val id: String,
    val username: String,           // u-identifier handle
    val displayName: String,
    val avatarUrl: String?,
    val isHost: Boolean = false,    // render host badge
    val isSelf: Boolean = false,    // current viewer authored it
)

data class ChatReaction(
    val emoji: String,
    val count: Int,
    val reactedBySelf: Boolean,
)

/** A decoded broadcast-chat domain event (parsed from an SseEvent.Message). */
sealed interface ChatStreamEvent {
    data class MessageReceived(val message: ChatMessage) : ChatStreamEvent
    data class MessageDeleted(val messageId: String) : ChatStreamEvent
    data class ReactionUpdated(
        val messageId: String?,     // null = room-level reaction
        val emoji: String,
        val count: Int,
        val reactedBySelf: Boolean,
    ) : ChatStreamEvent
    data class ViewerCount(val count: Int) : ChatStreamEvent
    data object Unknown : ChatStreamEvent          // unrecognized event name; ignored
}
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

    /** Send a text message. Carries client_id for echo dedup. */
    @POST("broadcast/sessions/{id}/chat")
    suspend fun send(
        @Path("id") sessionId: String,
        @Body body: SendChatDto,
    ): Response<ChatMessageDto>

    /** React to a specific message. */
    @POST("broadcast/sessions/{id}/chat/{messageId}/reactions")
    suspend fun reactToMessage(
        @Path("id") sessionId: String,
        @Path("messageId") messageId: String,
        @Body body: ReactionDto,
    ): Response<Unit>

    /** Room-level reaction (floating emoji). */
    @POST("broadcast/sessions/{id}/reactions")
    suspend fun reactToRoom(
        @Path("id") sessionId: String,
        @Body body: ReactionDto,
    ): Response<Unit>
}

@JsonClass(generateAdapter = true)
data class SendChatDto(val text: String, @Json(name = "client_id") val clientId: String)

@JsonClass(generateAdapter = true)
data class ReactionDto(val emoji: String)
```

The SSE **stream URL** is not declared on this Retrofit interface (SSE is not a
Retrofit call). It is built from `BuildConfig.API_BASE_URL` +
`broadcast/sessions/{id}/chat/stream` and handed to the AND-143 `SseClient`.

### 4.3 SSE frame parsing

Each `SseEvent.Message(id, event, data)` is mapped to a `ChatStreamEvent` by event
name; `data` is parsed with the shared Moshi instance (codegen DTOs):

```kotlin
class ChatEventParser @Inject constructor(private val moshi: Moshi) {
    fun parse(event: SseEvent.Message): ChatStreamEvent = when (event.event) {
        "chat.message"  -> ChatStreamEvent.MessageReceived(
            moshi.adapter(ChatMessageDto::class.java).fromJson(event.data)!!.toDomain())
        "chat.reaction" -> moshi.adapter(ChatReactionEventDto::class.java)
            .fromJson(event.data)!!.toReactionUpdated()
        "chat.deleted"  -> ChatStreamEvent.MessageDeleted(
            moshi.adapter(ChatDeletedDto::class.java).fromJson(event.data)!!.messageId)
        "viewer_count", "presence" -> moshi.adapter(ViewerCountDto::class.java)
            .fromJson(event.data)!!.let { ChatStreamEvent.ViewerCount(it.count) }
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

    suspend fun reactToMessage(sessionId: String, messageId: String, emoji: String): ApiResult<Unit>
    suspend fun reactToRoom(sessionId: String, emoji: String): ApiResult<Unit>
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
    fun reactToRoom(emoji: String)
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

**SSE stream — `GET broadcast/sessions/{id}/chat/stream`** (`Accept: text/event-stream`,
consumed by AND-143 `SseClient`). Frames:

```
event: chat.message
id: cm_01HXA
data: {"id":"cm_01HXA","client_id":"nonce-7f3","session_id":"bcs_01HX1",
       "author":{"id":"usr_9","username":"mira","display_name":"Mira","avatar_url":null,"is_host":false},
       "text":"hello!","sent_at":"2026-06-05T23:01:10Z"}

event: chat.reaction
id: cr_55
data: {"message_id":"cm_01HXA","emoji":"🔥","count":12,"reacted_by_self":false}

event: viewer_count
data: {"count":1284}

: heartbeat
```

**Send — `POST broadcast/sessions/{id}/chat`**

Request:
```json
{ "text": "hello!", "client_id": "nonce-7f3" }
```
Response `201`/`200` — the authoritative server message (same shape as the
`chat.message` frame `data`):
```json
{ "id":"cm_01HXA", "client_id":"nonce-7f3", "session_id":"bcs_01HX1",
  "author":{ "id":"usr_self","username":"me","display_name":"Me","is_host":false },
  "text":"hello!", "sent_at":"2026-06-05T23:01:10Z" }
```
The `client_id` echo (here and in the SSE frame) is the dedup key (FR-5).

**React to message — `POST broadcast/sessions/{id}/chat/{messageId}/reactions`**
Body `{ "emoji": "🔥" }` → `204`/`200`. The authoritative count arrives via a
`chat.reaction` SSE frame (the POST may return `Unit`).

**Room reaction — `POST broadcast/sessions/{id}/reactions`** → `{ "emoji":"❤️" }` →
`204`. Echoed via a room-level `chat.reaction` (`message_id: null`).

**Optional history — `GET broadcast/sessions/{id}/chat?limit=50`** →
`{ "items":[<ChatMessageDto>...], "next_page": null }` (idempotent GET, retriable).

**Retrofit DTOs** use Moshi `@Json` aliases (`client_id`, `session_id`, `sent_at`,
`display_name`, `avatar_url`, `is_host`, `message_id`, `reacted_by_self`); `sent_at`
parses to `Instant` via the shared `InstantJsonAdapter`.

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
  - `MessageReceived`: if `clientNonce` matches an existing `SENDING`/`FAILED` local
    entry, **replace it** (reconcile to `SENT`); else append (and evict oldest beyond
    cap). Dedup also guards against a server id already present.
  - `ReactionUpdated`: update the target message's `reactions` (or room reaction
    overlay) by emoji, setting count + `reactedBySelf`.
  - `MessageDeleted`: remove by id.
  - `ViewerCount`: update `viewerCount`.
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
  re-issues with the **same `client_id`** (so a server that did persist the first
  attempt dedups). On `403`/banned → message removed and a typed toast; on `404`/ended
  → whole panel → `Error(retryable=false)`.
- **Slow-mode / rate limit (`429`):** honor `Retry-After`; disable the composer for the
  cooldown and surface a countdown (best-effort; full slow-mode UI is OQ-4). The send
  is not silently dropped.
- **Bad frames:** a single unparseable `chat.*` frame → `ChatStreamEvent.Unknown`,
  logged at debug, never tears down the stream (§4.3).
- **Unreliable dev host:** drops are the norm; all states (`Connecting`,
  `RECONNECTING`, `OFFLINE`, empty, `Error`) are first-class and reachable — no
  indefinite spinner. A reconnect storm is bounded by AND-143's backoff + cap.
- **Duplicate suppression:** the `client_id`/server-`id` dedup (FR-5) guarantees the
  optimistic message and its SSE echo never both render.

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
  evaluated. Author handles/avatars come from the server.
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
- **QoE:** time-to-first-message (subscribe → first `chat.message`), reconnect rate,
  and send round-trip latency (POST → SSE echo) for diagnosing the unreliable dev host.
- **Logging:** lifecycle transitions only under tag `LiveChat` (connect/reconnect/
  offline + send ok/fail with HTTP status code) — **never** raw chat `text` or author
  ids. No `println`; reuses AND-143's redacting HTTP logger for the handshake.

## 11. Testing Strategy

- **Unit — `ChatEventParser` (JVM, `:core-testing` + Truth):** each `event` name
  (`chat.message`, `chat.reaction` message- and room-level, `chat.deleted`,
  `viewer_count`) parses to the correct `ChatStreamEvent`; an unknown event and a
  malformed `data` body both map to `Unknown` without throwing.
- **Unit — `BroadcastChatRepository`/SSE wiring (MockWebServer):** enqueue a
  `text/event-stream` body of `chat.message` frames; assert `chatEvents()` emits the
  parsed `MessageReceived`s in order (reuses AND-143's `MockWebServer` SSE harness).
  Assert a socket drop → `Reconnecting` signal → resume (delegated to AND-143, asserted
  at the consumer boundary). Assert `send()` issues `POST broadcast/sessions/{id}/chat`
  with `X-CSRF-Token` and a `client_id` body, and maps the response to `ChatMessage`.
- **Unit — `LiveChatViewModel` reducer (Turbine + `runTest`):**
  - **Chat updates live (KEY):** feeding `MessageReceived` events appends them to
    `Content.messages` and sets `connection = LIVE` after `Open`.
  - **Send works (KEY):** `send()` inserts an optimistic `SENDING` entry; the SSE echo
    with the matching `client_id` reconciles it to `SENT` exactly once (no duplicate).
  - Send failure → `FAILED`; `retrySend(nonce)` re-issues with the same nonce.
  - `ReactionUpdated` updates the target message's reaction count + `reactedBySelf`.
  - `Closed(STALE)` → `connection = OFFLINE` while messages remain; manual retry
    re-subscribes. `canSend` is false while not `LIVE`.
  - `MAX_RETAINED` eviction: feeding > cap messages keeps only the newest `MAX_RETAINED`.
- **API contract (MockWebServer):** verb/path/`X-CSRF-Token`/body for `send`,
  `reactToMessage`, `reactToRoom`, and `history`; `401` → refresh → retry once;
  `403`/`404`/`429` mappings via AND-015.
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
  `broadcast.ts` (OQ-1/OQ-2); (2) define `:core-model` chat domain types; (3) DTOs +
  codegen adapters + `ChatEventParser`; (4) `BroadcastChatApi` + Hilt provider;
  (5) `BroadcastChatRepository` (SSE merge + mutations); (6) `LiveChatViewModel` reducer;
  (7) `LiveChatPanel` Compose + wire into the viewer; (8) tests T-parser/repo/VM/UI.

## 13. Risks & Open Questions

- **R-1 Send/echo race & duplicates.** If the SSE echo arrives before the POST response
  (or the POST omits `client_id`), naive logic double-renders. *Mitigation:* dedup on
  `client_id` then server `id`; reconcile is idempotent. Guarded by the "send works" VM
  test. Requires the backend to round-trip `client_id` (OQ-3).
- **R-2 High message volume / jank.** A busy room can flood the list and the main
  thread. *Mitigation:* `MAX_RETAINED` cap, keyed `LazyColumn`, parse on IO, and (if
  needed) `conflate()`/batched state updates; reaction frames coalesced by emoji.
- **R-3 Unreliable dev host.** Frequent drops → flickering connection state.
  *Mitigation:* AND-143 backoff + cap; keep messages visible during `RECONNECTING`;
  only show `OFFLINE` after `Closed(STALE)`.
- **R-4 Ephemeral vs. backlog.** Starting live-only means a late joiner sees an empty
  room. *Mitigation:* optional history seed (FR-10) if the endpoint exists (OQ-1).
- **R-5 Slow-mode/abuse not enforced client-side.** Spam protection is largely
  server-side; client only reflects `429`. Full slow-mode UI deferred (OQ-4).
- **OQ-1:** Does a `GET broadcast/sessions/{id}/chat?limit=N` history endpoint exist, and
  what is its envelope? *Default:* live-only if absent; confirm via `/openapi.json`.
- **OQ-2:** Confirm the SSE stream path (`.../chat/stream` vs a shared
  `.../events` channel multiplexing chat + presence + viewer-count) and the exact event
  names. *Default:* dedicated `chat/stream` with `chat.message`/`chat.reaction`.
- **OQ-3:** Does the backend echo `client_id` on both the POST response and the
  `chat.message` frame? (Required for FR-5 dedup.) *Default:* assume yes; fall back to
  id-only dedup with a brief optimistic-replace heuristic if not.
- **OQ-4:** Slow-mode / rate-limit policy and whether the server advertises a cooldown
  the client should pre-enforce. *Default:* reactively honor `429`/`Retry-After` only.
- **OQ-5:** Are message- and room-level reactions both supported, and is there a fixed
  emoji set? *Default:* support both; use a small curated picker pending product input.

## 14. Acceptance Criteria

AC-1 (backlog — **chat updates live**). With the chat panel visible on a live session,
`chat.message` SSE frames append to the visible list in real time (asserted via the SSE
consumer emit test + the ViewModel reducer test); the connection shows `LIVE` after the
first `Open`.

AC-2 (backlog — **send works**). Typing and pressing Send issues
`POST broadcast/sessions/{id}/chat` with the `client_id` body and `X-CSRF-Token`, shows
the message optimistically (`SENDING`), and reconciles to `SENT` on the server echo/
response **exactly once** (no duplicate). Failure → `FAILED` with a working retry that
reuses the same `client_id`.

AC-3 Reactions: reacting to a message/room issues the correct POST; incoming
`chat.reaction` frames update counts and the self-highlight live.

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
- Optimistic send with `client_id` dedup, FAILED-state retry, and message/room reactions
  implemented and reconciled from SSE frames.
- All §14 acceptance criteria demonstrably met, including a manual two-client live
  verification against `http://18.222.237.167:8000`.
- Telemetry events from §10 emitted with AND-052 redaction; no chat text/author ids in
  logs (verified in review).
- Strings localized; accessibility semantics (`liveRegion`, contentDescriptions, 48dp)
  present; dev cleartext config scoped and release config verified clean.
- Open questions OQ-1..OQ-5 resolved against `/openapi.json` +
  `frontend/src/api/endpoints/broadcast.ts` (+ `types.ts`) or explicitly deferred with
  follow-up tickets; spec updated if endpoint shapes differ from §5.
