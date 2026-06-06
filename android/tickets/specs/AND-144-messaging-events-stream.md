---
id: AND-144
title: Messaging events stream
milestone: M3
epic: E20
priority: P0
size: L
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-143, AND-123]
blocks: []
---

# AND-144 — Messaging events stream

## 1. Overview & Goal

Real-time delivery of messaging mutations to the Android client. The thread list and any open conversation must reflect server-side changes (new messages, edits, deletions) within seconds of them occurring, without the user manually refreshing. This ticket implements the client-side consumer of the backend Server-Sent Events (SSE) stream exposed at `GET /messaging/events/stream` and the supporting catch-up endpoint `GET /messaging/events`.

The deliverable is a long-lived, lifecycle-aware streaming layer in `core-data` plus its wiring into the messaging feature ViewModels delivered by AND-143 (thread detail) and AND-123 (thread list). Success is defined as: a message sent from another client appears live in both the open thread (AND-143) and the thread list summary (AND-123) without user interaction.

Goal in one line: subscribe once, fan out the three core message event types (`message:new`, `message:edited`, `message:revoked` — **note the colon-delimited names verified against the web client**, see §16) into the existing Room-backed messaging cache, and let Compose UIs re-render reactively off the cache.

> **Reviewer note (terminology correction):** the backend messaging domain is keyed by `conversation_id`, not `thread_id`. The web app and DTOs use "conversation" throughout. This spec previously used "thread" generically; references below to a "thread" mean a **conversation** (`conversation_id`). A `thread_id` field does exist on the `Message` DTO but denotes a *reply sub-thread within* a conversation, which is out of scope here. See §16 for the full audit.

## 2. Context & References

- Repo: `spannella/testlogon`, Android app under `android/`, branch `android-port`.
- Namespace / applicationId base: `com.testlogon.android`.
- Module layering: `app -> feature-messaging -> core-data -> core-network -> core-model`. This ticket lands code in `core-network` (raw SSE client), `core-data` (`MessagingEventsRepository`, dispatch into Room), and `core-model` (event DTOs/domain types). UI changes are confined to consuming existing StateFlows wired by AND-143/AND-123.
- Backend: FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000` is **plaintext HTTP** and unreliable; design for ~20s connect timeouts, bounded backoff reconnection, and visible offline/stale states. OpenAPI at `/openapi.json`.
- Web reference: the actual SSE consumer is `frontend/src/hooks/useMessagingStream.ts` (NOT `endpoints/messaging*.ts`, which only holds REST calls — corrected, see §16). Shared types in `frontend/src/api/types.ts` (`Message` interface). Mirror the **named** SSE event types and the flat (non-enveloped) `data` payloads the web client reads.
- Auth on the SSE request: the web client opens `new EventSource(url, { withCredentials: true })`, i.e. **cookies only**. Browsers cannot set custom headers on an `EventSource`, so there is **no** `X-CSRF-Token` header on the stream request (correction — the previous claim was wrong). CSRF is not required for this idempotent GET. The Android client mirrors this by riding the shared authenticated cookie jar; OkHttp additionally *can* attach the session's `Authorization: Bearer` and/or `X-SESSION-ID` headers, both of which the endpoint accepts as optional (verified in OpenAPI). On `401`, the client performs a single `POST /ui/session/refresh` (verified endpoint) then reconnects — this matches the web `client.ts` refresh-once behavior, though note the web hook itself just reconnects via `onerror` backoff rather than calling refresh.
- Upstream dependencies:
  - **AND-123** — Thread list feature: provides `ThreadListViewModel`, the threads Room table/DAO, and `MessagingRepository` thread summary projection that this ticket updates on events.
  - **AND-143** — Thread detail feature: provides `ThreadDetailViewModel`, the messages Room table/DAO, the message domain model, and the paging source that this ticket invalidates/updates on events.

## 3. Functional Requirements

FR-1. The app maintains at most one active SSE connection to `GET /messaging/events/stream` while a messaging-related screen is in the foreground (thread list or any thread detail). The connection is reference-counted: opened on first subscriber, closed when the last subscriber unsubscribes.

FR-2. On (re)connection the client first issues `GET /messaging/events?after=<token>&limit=<=200` to fetch any events missed while disconnected, applies them in order, advances its resume token, then attaches the live stream. This guarantees no gap between catch-up and live. **Corrections:** the cursor query parameter is named `after` (NOT `since`) for both `/messaging/events` and `/messaging/events/stream` (verified in OpenAPI). `limit` defaults to 50 and is capped at 200 server-side. NOTE: this catch-up-before-live flow is an **Android-side design choice**; the web reference (`useMessagingStream.ts`) does **not** perform a catch-up call and simply relies on a full re-fetch (React Query invalidation) after reconnect. See R2/§16 — confirm `after` semantics and whether the resume token is the SSE `id` with backend before relying on gap-free replay.

FR-3. The client dispatches the three core message event types into the local cache (verified names from `useMessagingStream.ts`):
- `message:new` — insert the message into its conversation; bump the conversation summary (last message preview, timestamp, unread count) in the list.
- `message:edited` — replace the message text/`edited_at`; refresh the conversation summary preview if the edited message was the latest.
- `message:revoked` — soft-delete (tombstone) the message (set `revoked`/`revoked_at`); if it was the latest, recompute the conversation summary preview from the next surviving message. (`message:expired` is treated the same way — disappearing/once-media; in scope as a secondary deletion-like event.)

Forward-compatible: the backend emits many other named events on the same stream (`message:reaction`, `message:viewed`, `conversation_updated`, `typing:update`, `presence:update`, `poll:*`, `helpdesk.*`, `call.*`, `webrtc.*`). This ticket consumes only the three core message events above and safely ignores the rest (FR-6).

FR-4. New messages in the **currently open thread** (AND-143) appear in the visible message list without scroll jump for the user's own read position; new messages in **other threads** update only the thread list (AND-123).

FR-5. Events are idempotent and ordered. Duplicate messages (re-delivery after reconnect / overlapping catch-up) are dropped by `message_id` (the verified stable identifier on the `Message` DTO). Out-of-order arrivals are reconciled per message by comparing `created_at` / `edited_at` / `revoked_at` (epoch-seconds, verified numeric), preferring the latest mutation timestamp for a given `message_id`. **Correction / unverified-assumption:** the spec previously dedup'd by `event_id` and ordered by a per-thread `sequence` — **neither `event_id` nor `sequence` exists in the verified messaging-stream payload** (the web client reads only `conversation_id`, `type`, `message_id`, and message fields). Dedupe/ordering is therefore redefined around `message_id` + timestamps. If the backend later exposes an SSE frame `id` or a sequence field, prefer it; treat that as an open backend confirmation (R2).

FR-6. Unknown event `type` values are logged and skipped, never crash the stream (forward compatibility).

FR-7. The stream pauses on `ON_STOP` (app backgrounded) and resumes on `ON_START`, performing a catch-up (`GET /messaging/events?after=<token>`) on resume.

FR-8. The UI surfaces a non-blocking "reconnecting / offline" indicator when the stream has been disconnected past one backoff cycle; cached content remains visible (stale-while-reconnecting).

## 4. Technical Design

### 4.1 Raw SSE client (`core-network`)

OkHttp has no first-class `EventSource` in the base artifact; use the `okhttp-sse` companion (`com.squareup.okhttp3:okhttp-sse:4.12.0`) over the shared authenticated `OkHttpClient` (same cookie jar, CSRF interceptor, auth-refresh interceptor). SSE responses must not time out on read, so a stream-specific client is derived with `readTimeout(0)`.

```kotlin
// core-network
class MessagingSseClient @Inject constructor(
    @Named("sse") private val client: OkHttpClient,
    @Named("baseUrl") private val baseUrl: HttpUrl,
) {
    /** Cold flow; one HTTP connection per collection. Completes on cancel. */
    fun events(afterToken: String?): Flow<SseEvent> = callbackFlow {
        val url = baseUrl.newBuilder()
            .addPathSegments("messaging/events/stream")
            .apply { if (afterToken != null) addQueryParameter("after", afterToken) } // param is `after`, not `since`
            .build()
        val req = Request.Builder().url(url)
            .header("Accept", "text/event-stream")
            .header("Cache-Control", "no-store")
            .build()
        val factory = EventSources.createFactory(client)
        val source = factory.newEventSource(req, object : EventSourceListener() {
            override fun onEvent(es: EventSource, id: String?, type: String?, data: String) {
                trySend(SseEvent.Data(id, type, data))
            }
            override fun onClosed(es: EventSource) { close() }
            override fun onFailure(es: EventSource, t: Throwable?, r: Response?) {
                close(SseException(r?.code, t))
            }
        })
        awaitClose { source.cancel() }
    }
}

sealed interface SseEvent {
    data class Data(val id: String?, val type: String?, val data: String) : SseEvent
}
class SseException(val httpCode: Int?, cause: Throwable?) : IOException(cause)
```

The `@Named("sse")` client is the app `OkHttpClient` rebuilt via `newBuilder().readTimeout(Duration.ZERO).callTimeout(Duration.ZERO).build()`, preserving interceptors and cookie jar (Hilt `@Provides` in `core-network`).

### 4.2 Repository & dispatch (`core-data`)

```kotlin
@Singleton
class MessagingEventsRepository @Inject constructor(
    private val sse: MessagingSseClient,
    private val eventsApi: MessagingEventsApi,       // Retrofit, for /messaging/events catch-up
    private val messageDao: MessageDao,              // owned by AND-143
    private val threadDao: ThreadDao,                // owned by AND-123
    private val cursorStore: EventCursorStore,       // DataStore
    private val moshi: Moshi,
    private val scope: CoroutineScope,               // @ApplicationScope
) {
    private val subscribers = AtomicInteger(0)
    private var job: Job? = null
    private val _status = MutableStateFlow<StreamStatus>(StreamStatus.Idle)
    val status: StateFlow<StreamStatus> = _status.asStateFlow()

    /** Ref-counted. Call from ViewModel.init; cancel the returned handle in onCleared. */
    fun subscribe(): Subscription {
        if (subscribers.incrementAndGet() == 1) start()
        return Subscription { if (subscribers.decrementAndGet() == 0) stop() }
    }

    private fun start() {
        job = scope.launch {
            connectWithRetry()
        }
    }

    private suspend fun connectWithRetry() {
        var attempt = 0
        while (currentCoroutineContext().isActive) {
            try {
                _status.value = StreamStatus.Connecting
                catchUp()                                   // FR-2
                _status.value = StreamStatus.Live
                attempt = 0
                sse.events(cursorStore.cursor()).collect { ev -> handle(ev) }
            } catch (c: CancellationException) {
                throw c
            } catch (e: SseException) {
                if (e.httpCode == 401 && refreshSession()) continue   // single refresh+retry
                _status.value = StreamStatus.Offline
                delay(backoff(attempt++))
            } catch (e: IOException) {
                _status.value = StreamStatus.Offline
                delay(backoff(attempt++))
            }
        }
    }

    private fun backoff(attempt: Int): Long =
        (1_000L * (1 shl attempt.coerceAtMost(5)))          // 1s..32s
            .coerceAtMost(32_000L)
            .let { it + Random.nextLong(0, 500) }           // jitter
}

fun interface Subscription { fun close() }

enum class StreamStatus { Idle, Connecting, Live, Offline }
```

Dispatch decodes the SSE `data` JSON into a sealed `MessagingEvent`, drops duplicates by `message_id` via a bounded LRU plus a `UNIQUE(message_id)` insert-ignore on a Room `processed_events` table, then mutates the cache in a single transaction.

> **Correction:** the code below was written against an invented enveloped payload with `event_id`/`cursor`/`sequence` fields. Those fields are **not** present in the verified stream contract (see §16). The dedupe key is `message_id`; ordering uses the message's own `created_at`/`edited_at`/`revoked_at` epoch-seconds. The SSE event *name* (`message:new` etc.) arrives as the SSE `type`/`event:` line — the code must discriminate on the OkHttp `SseEvent.Data.type` (the `event:` field), NOT on a `type` field inside `data` (though the web payload often duplicates it there). The `cursor`/`cursorStore.advance(...)` calls are an Android-side resume token (R2, unverified); if no usable token is exposed by the stream, catch-up resume falls back to the newest locally-known `created_at` per conversation.

The illustrative dispatch (field names updated to the verified contract):

```kotlin
private suspend fun handle(ev: SseEvent) {
    if (ev !is SseEvent.Data) return
    // Discriminate on the SSE `event:` name (ev.type), e.g. "message:new".
    val payload = runCatching { adapter.fromJson(ev.data) }.getOrNull() ?: return
    when (val e = payload.toDomain(ev.type)) {
        is MessagingEvent.MessageCreated -> { if (markProcessed(e.message.messageId)) applyCreated(e) } // FR-5 dedupe by message_id
        is MessagingEvent.MessageUpdated -> applyUpdated(e)   // idempotent via edited_at compare
        is MessagingEvent.MessageDeleted -> applyDeleted(e)   // idempotent via revoked_at compare
        is MessagingEvent.Unknown -> Timber.w("Unhandled event ${ev.type}") // FR-6 (reaction/typing/presence/call/etc.)
    }
    cursorStore.advance(ev.id)   // SSE frame id as resume token IF the server sets it (R2, unverified)
}
```

`applyCreated/Updated/Deleted` write to `messageDao` and recompute the affected row in `threadDao` inside `withTransaction { }`. Because both DAOs back Compose via Room `Flow`/`PagingSource`, the open thread (AND-143) and the list (AND-123) recompose automatically — no event needs to cross a ViewModel boundary.

### 4.3 Lifecycle wiring

`ThreadListViewModel` (AND-123) and `ThreadDetailViewModel` (AND-143) each call `repo.subscribe()` in `init` and `subscription.close()` in `onCleared()`. The ref-count keeps one connection while either screen is alive. Background pause/resume (FR-7) is handled by a `DefaultLifecycleObserver` registered against `ProcessLifecycleOwner` in the messaging entry point that cancels/restarts the repository `job`.

## 5. API Contract

> **Section-wide correction.** The frames below were rewritten to the verified contract (`useMessagingStream.ts` + `Message` in `types.ts`). Changes: SSE event names are colon-delimited (`message:new`/`message:edited`/`message:revoked`); the `data` payload is **flat** (no `event_id`/`cursor`/`sequence`/`type`-envelope wrapper required by the client); the conversation key is `conversation_id` (not `thread_id`); message fields are `message_id`/`sender_id`/`text` (not `id`/`author_id`/`body`); timestamps are **epoch-seconds numbers** (not ISO strings); deletion is `revoked`/`revoked_at` (not `deleted`/`deleted_at`). The exact shape of each event's `data` is **not declared in OpenAPI** (the `200` response schema is empty `{}`); fields below are inferred from the web client's reads and the `Message` DTO — flagged unverified-assumption in §16 where the client doesn't read them.

### 5.1 Live stream — `GET /messaging/events/stream`

- Request headers: `Accept: text/event-stream`, session cookies (the web client uses `withCredentials`). Browsers send no CSRF header on EventSource; a native client MAY also send the accepted-but-optional `Authorization` and `X-SESSION-ID` headers.
- Query (all optional, verified in OpenAPI): `after` (resume token), `limit` (default 50, max 200), `poll_ms` (default 1000, min 200, max 5000 — server long-poll interval), `x_request_id` (trace id).
- Response: `200`. The web client consumes it as `text/event-stream` via `EventSource`. (OpenAPI declares the response media type as `application/json` with an empty schema — likely a FastAPI annotation artifact for a `StreamingResponse`; the wire format that the reference client relies on is SSE. R1: confirm with backend. The presence of `poll_ms` indicates the server implements SSE over an internal long-poll.) Representative SSE frames:

```
event: message:new
data: {"type":"message:new","conversation_id":"c_42",
       "message_id":"m_991","sender_id":"u_7","kind":"text","text":"hi",
       "created_at":1749132131}
```

- `event: message:edited` — `data` carries the conversation/message ids plus `edited_at` (epoch-seconds) and the new `text`. (Web client only reads `conversation_id` here and re-fetches.)
- `event: message:revoked` — `data` carries `{"type":"message:revoked","conversation_id":"c_42","message_id":"m_991","revoked_at":<epoch>}` (no full body). `message:expired` is analogous for disappearing media.
- Keep-alive: server emits `:` comment lines and/or periodic heartbeat frames; the web client swallows JSON-parse failures and otherwise ignores event names it doesn't register (FR-6). (Exact heartbeat shape unverified — R3.)
- Errors: `401` (expired session — single refresh + reconnect), `5xx`/connection drop — backoff reconnect. (No `403`/CSRF case applies to this stream since no CSRF header is sent — corrected; see §7.) Validation errors return `422 HTTPValidationError` (verified) for bad query params.

### 5.2 Catch-up — `GET /messaging/events`

```kotlin
interface MessagingEventsApi {
    @GET("messaging/events")
    suspend fun catchUp(
        @Query("after") after: String?,         // param is `after`, not `since` (verified)
        @Query("limit") limit: Int = 200,        // server caps at 200, default 50 (verified)
    ): ApiResult<JsonElement>                     // response schema is empty {} in OpenAPI — shape unverified
}
```

> **Corrections.** (1) Query param is `after`, not `since` (verified in OpenAPI). (2) The `EventPageDto`/`next_cursor`/`has_more`/`events[]` paging envelope was **invented** — no such schema exists in OpenAPI for this endpoint (the `200` response schema is empty `{}`), and the web client never calls `/messaging/events` at all (it relies on REST re-fetch + live SSE). The concrete catch-up response shape is therefore an **open backend question** (R2/R6). The Android client must decode defensively: accept either a JSON array of event objects or an object containing such an array, and derive the next `after` token from the last item (e.g. its frame id / newest `created_at`) — there is no verified `next_cursor`/`has_more`.

The repository pages catch-up until a short page (`< limit`) is returned, applying each event through the same `handle` path, before attaching the live stream. FastAPI `detail` error mapping (string | `[{msg}]` | `{code,...}`, verified via `HTTPValidationError`) reuses the shared `ApiResult` decoder from `core-network`.

## 6. Data & State Management

- **Domain models** (`core-model`):

```kotlin
// Flat SSE `data` payload — fields verified against types.ts `Message` + useMessagingStream reads.
// (Names corrected: conversation_id not thread_id; message_id/sender_id/text not id/author_id/body;
//  epoch-seconds Long timestamps not ISO strings; revoked_at not deleted_at; no event_id/cursor/sequence.)
@JsonClass(generateAdapter = true)
data class MessageEventDataDto(
    @Json(name = "conversation_id") val conversationId: String,
    @Json(name = "message_id") val messageId: String? = null,
    @Json(name = "sender_id") val senderId: String? = null,
    val text: String? = null,
    val kind: String? = null,
    @Json(name = "created_at") val createdAt: Long? = null,   // epoch-seconds
    @Json(name = "edited_at") val editedAt: Long? = null,     // epoch-seconds
    @Json(name = "revoked_at") val revokedAt: Long? = null,   // epoch-seconds
    val type: String? = null,                                  // sometimes mirrored inside data
)

sealed interface MessagingEvent {
    data class MessageCreated(val conversationId: String, val message: Message) : MessagingEvent
    data class MessageUpdated(val conversationId: String, val message: Message) : MessagingEvent
    data class MessageDeleted(val conversationId: String, val messageId: String, val revokedAt: Instant?) : MessagingEvent
    data class Unknown(val type: String) : MessagingEvent
}
```

> Note: the live SSE `message:edited`/`message:revoked` payloads may not carry the *full* `Message`. Like the web client, the safest path for those two is to apply the local mutation if fields are present and otherwise trigger a bounded conversation re-fetch (existing AND-143/AND-123 REST) — never block the stream on a partial payload.

- **Cursor persistence**: `EventCursorStore` over DataStore (`Preferences` key `messaging_event_cursor`). Survives process death so catch-up resumes from the last applied event. `cursor()` read and `advance(cursor)` write are serialized.
- **Dedupe table** (Room, `core-data`):

```kotlin
// Dedupe key is message_id (verified stable id). No event_id exists in the contract (corrected).
@Entity(tableName = "processed_events", indices = [Index(value=["message_id"], unique=true)])
data class ProcessedEventEntity(@PrimaryKey val messageId: String, val seenAt: Long)
```
`@Insert(onConflict = IGNORE)` returns rowId `-1` on duplicate → `markProcessed` returns false. A periodic prune keeps the last ~2,000 rows. (Dedupe applies to `message:new`; edits/revokes are naturally idempotent via timestamp compare below.)
- **Ordering**: there is no server `sequence` field (corrected). `applyUpdated` applies only when incoming `edited_at >= stored.edited_at` (or stored has none); `applyDeleted` applies when incoming `revoked_at >= stored.revoked_at`; both compared on the message's own epoch-seconds timestamps.
- **StateFlow surface**: `MessagingEventsRepository.status: StateFlow<StreamStatus>` is the single observable; ViewModels map it into their existing `UiState` (e.g. `ThreadListUiState.connection`). Message/thread data flows through the existing Room-backed StateFlows/PagingData owned by AND-143/AND-123 — this ticket does not introduce a new content StateFlow.

## 7. Error Handling & Resilience

- Connect/read failures, `5xx`, and abrupt drops trigger exponential backoff with jitter (1s → 32s cap, reset on a clean `Live` transition). Backoff loop is the only reconnect path; no unbounded tight loop.
- `401`: one `POST /ui/session/refresh` attempt, then reconnect; a second consecutive `401` surfaces an auth-required state and stops retrying until the session layer re-authenticates.
- `403`: **not a CSRF case** for this stream (no CSRF header is sent — corrected from prior draft). A `403` here means authorization/policy denial (e.g. revoked session, blocked user). Emit `StreamStatus.Offline`, surface an auth-required state, and do not hot-loop.
- Catch-up failure: keep showing cached content, retry catch-up under the same backoff; the live stream is not attached until a catch-up succeeds (prevents gaps).
- Read timeout disabled (`readTimeout(0)`); liveness is inferred from server `ping` frames — if no frame (data or ping) arrives within 45s, the client proactively cancels and reconnects (idle-watchdog coroutine).
- Malformed `data` JSON or unknown `type`: skip the single frame, keep the connection (FR-6). Cursor is **not** advanced past a frame that failed to decode into a known envelope structure, except unknown-type frames whose envelope parsed (those advance, to avoid a poison-pill stall).
- All mutations are idempotent (dedupe + sequence guard), so replay after reconnect cannot corrupt the cache.
- Retry/backoff applies to this idempotent GET stream only; no message-sending here (sending is AND-143).

## 8. Security & Privacy

- The stream authenticates via the same persistent session cookie jar (mirroring the web client's `EventSource(..., { withCredentials: true })`). **Correction:** no `X-CSRF-Token` is sent on the stream — browsers can't set it on an `EventSource` and the GET is CSRF-exempt; the previous claim was inaccurate. No token (session, CSRF, or bearer) is ever placed in the URL; the optional `Authorization`/`X-SESSION-ID` headers, if used by the native client, ride headers only.
- Dev backend is plaintext HTTP; `usesCleartextTraffic` is gated to the dev `network_security_config.xml` host `18.222.237.167` only (inherited from the network ticket). Production builds require TLS for SSE.
- Message bodies are PII; never log `data` payload contents. Logs may include `event_id`, `type`, `thread_id`, `sequence`, `cursor`, and HTTP status only.
- The `processed_events` table and cursor live in app-private storage; no export. On logout, clear the cursor, `processed_events`, and cancel the stream (hook into the session-clear path).
- No new permissions. Stream runs only in foreground / process-foreground; no background service, avoiding background-data exfiltration surface.

## 9. Accessibility & i18n

- The only UI this ticket adds is the connection indicator. It must expose a `contentDescription` and live-region semantics so screen readers announce reconnect/offline transitions: `Modifier.semantics { liveRegion = LiveRegionMode.Polite }`.
- New strings (`core-ui`/feature-messaging `strings.xml`): `messaging_stream_reconnecting`, `messaging_stream_offline`, `messaging_stream_live` (optional, usually silent). No hard-coded text.
- Live-inserted messages must not steal focus or move the screen-reader cursor; new items are announced politely, not assertively, and the list preserves the user's scroll/focus anchor (FR-4).
- Timestamps on new messages use locale/relative formatting from the shared formatter (owned by AND-143); this ticket adds no new date formatting.

## 10. Telemetry & Logging

- Structured events (analytics façade in `core-data`):
  - `messaging_stream_connected` (attempt count, ms-to-live).
  - `messaging_stream_disconnected` (reason: timeout/io/401/403/5xx, http_code).
  - `messaging_stream_reconnect` (attempt, backoff_ms).
  - `messaging_event_applied` (type, thread_id, sequence) — no body.
  - `messaging_event_dropped` (reason: duplicate | unknown_type | decode_error).
- Timber debug logs mirror the above, redacting payloads.
- A debug-only counter exposes current `StreamStatus`, last cursor, and processed-event count for QA (dev menu).
- No telemetry contains message text, author identifiers beyond opaque ids, or cookies.

## 11. Testing Strategy

- **Unit (core-data)** — JVM, `core-testing` fakes:
  - Dispatch: `created/updated/deleted` mutate `FakeMessageDao`/`FakeThreadDao` correctly, including thread-summary recompute on delete-of-latest.
  - Dedupe: same `event_id` twice applies once.
  - Ordering: lower `sequence` after higher is ignored.
  - Unknown type: skipped, cursor advances, stream survives.
  - Backoff: deterministic via injected `TestScope`/virtual time; verify 1s→32s cap and reset on `Live`.
  - 401 path: one refresh then reconnect; second 401 → auth state.
- **SSE parsing** — `MockWebServer` returning a chunked `text/event-stream` body with multiple frames, comments/pings, and a mid-stream disconnect; assert frames decode and reconnect occurs.
- **Catch-up** — `MockWebServer` paginated `/messaging/events` (`has_more` then terminal), assert all applied in order before live attach and cursor advanced.
- **Lifecycle** — ref-count: two subscribers → one connection; last unsubscribe closes; `ON_STOP`/`ON_START` pause/resume triggers catch-up.
- **Instrumented/UI (Compose)** — with a fake repo emitting events: a `message.created` for the open thread renders a new row (AND-143 list) without scroll jump; a `message.created` for another thread updates the list summary (AND-123). Reconnecting indicator appears on `StreamStatus.Offline`.
- **Coverage gate**: dispatch + reconnect logic ≥ 85% line coverage in `core-data`.

## 12. Dependencies & Sequencing

- **Hard deps (must merge first)**:
  - **AND-123** — thread list ViewModel, `ThreadDao`/threads table, thread-summary projection. This ticket writes to that DAO and surfaces `StreamStatus` in `ThreadListUiState`.
  - **AND-143** — thread detail ViewModel, `MessageDao`/messages table + paging source, `Message` domain model. This ticket inserts/updates/tombstones those rows.
- **Transitive**: the authenticated `OkHttpClient` (cookie jar + CSRF + auth-refresh interceptor) and `ApiResult`/`detail` mapping from the network/session bootstrap tickets.
- **New library**: `com.squareup.okhttp3:okhttp-sse:4.12.0` added to the version catalog and `core-network` build.
- **Sequencing**: land DTOs/domain (`core-model`) → SSE client (`core-network`) → repository + dispatch + Room dedupe (`core-data`) → ViewModel/lifecycle wiring (`feature-messaging`) → UI indicator. This ticket **blocks** nothing currently in backlog but is a prerequisite for any presence/typing-indicator follow-ups on the same stream.

## 13. Risks & Open Questions

- **R1 — SSE vs WebSocket vs long-poll** (partly resolved): the web reference uses `EventSource` over `/messaging/events/stream`, so it is **SSE**, not WebSocket — `okhttp-sse` is the right choice. Caveat: OpenAPI declares the `200` response media type as `application/json` (empty schema) and exposes a `poll_ms` query param, indicating the server implements SSE atop an internal long-poll. Confirm the response really sets `Content-Type: text/event-stream` against the dev host before finalizing the watchdog/timeout (R3).
- **R2 — Resume/cursor semantics** (sharpened): the cursor param is `after` (verified), but the **format and source of the token are unverified** — the messaging-stream `data` carries no `event_id`/`cursor`/`sequence`, and the web client never sends `after` or calls catch-up at all. Confirm with backend: is `after` the SSE frame `id`, a `created_at`, or an opaque token; inclusive vs exclusive; and what `/messaging/events` returns. Until confirmed, the catch-up/gap-free-replay design (FR-2) is provisional.
- **R3 — Keep-alive / ping format**: exact ping frame (comment line vs `event: ping`) determines the idle-watchdog. Verify the 45s watchdog window against server heartbeat interval.
- **R4 — Revoke/edit payload completeness**: does `message:revoked`/`message:edited` include enough (`conversation_id` + `message_id` + `revoked_at`/`edited_at`/`text`) to mutate locally and recompute the conversation summary, or must the client re-fetch? The web client re-fetches the conversation on these events, so the fields beyond `conversation_id` are **unverified**. Android assumes `conversation_id` + `message_id` suffice with a local lookup of the next-latest, falling back to a bounded REST re-fetch when fields are absent.
- **R5 — Dev host instability**: frequent drops may cause indicator flapping; debounce `Offline` display by one backoff cycle (FR-8).
- **R6 — Catch-up volume**: very large gaps after long offline could return many pages; `limit=200` paging bounds memory, but confirm server caps.

## 14. Acceptance Criteria

- AC-1 (primary): a message created by another client appears live in the **open thread** (AND-143) within ~3s, no manual refresh.
- AC-2: the same new message updates the **thread list** summary (last preview + timestamp + unread) for that thread (AND-123) within ~3s.
- AC-3: `message:edited` replaces the message `text` in an open conversation and refreshes the list preview when it was the latest message.
- AC-4: `message:revoked` (and `message:expired`) removes/tombstones the message from the open conversation and recomputes the list preview from the next surviving message when the revoked one was latest.
- AC-5: exactly one SSE connection exists while messaging screens are foregrounded; it closes when all leave; backgrounding pauses and foregrounding resumes with a catch-up.
- AC-6: duplicate events (replay after reconnect / overlapping catch-up) do not double-insert (dedupe by `message_id`); stale mutations with an older `edited_at`/`revoked_at` than the stored row are ignored.
- AC-7: on disconnect, cached content stays visible and a reconnecting/offline indicator appears (accessible, live-region); on recovery the indicator clears and missed events are applied via catch-up.
- AC-8: a single `401` triggers one refresh+reconnect and continues; unknown event types are skipped without breaking the stream.
- AC-9: no message body or cookie appears in any log/telemetry.

## 15. Definition of Done

- Code merged to `android-port` under `com.testlogon.android`, in `core-model`/`core-network`/`core-data`/`feature-messaging` per layering.
- `okhttp-sse:4.12.0` added to the version catalog; `@Named("sse")` client provided with `readTimeout(0)` and shared interceptors/cookie jar.
- All FRs and ACs met and demonstrated against the dev backend `http://18.222.237.167:8000`.
- Unit + MockWebServer + Compose tests pass in CI; dispatch/reconnect coverage ≥ 85%.
- Lifecycle pause/resume, ref-counting, dedupe, ordering, backoff, and single-refresh-on-401 verified by tests.
- Logout clears cursor, `processed_events`, and cancels the stream.
- Telemetry events emitted and payload-redacted; debug status surface available in dev menu.
- New strings localized; connection indicator passes accessibility (TalkBack live-region announcement, no focus theft).
- Open questions R1–R6 resolved or explicitly deferred with backend sign-off recorded in the PR.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer. Sources: OpenAPI index `reference/openapi.index.txt`, OpenAPI spec `reference/openapi.pretty.json`, and frontend files under `reference/src/`.

1. **Endpoint `GET /messaging/events/stream` exists.** VERDICT: Verified. SOURCE: OpenAPI `GET /messaging/events/stream` (op=`events_stream_messaging_events_stream_get`); `src/hooks/useMessagingStream.ts: MESSAGING_STREAM_URL = "/messaging/events/stream"`.
2. **Endpoint `GET /messaging/events` (catch-up) exists.** VERDICT: Verified (endpoint), but its use as a catch-up paging call is an Android design choice not exercised by the web client. SOURCE: OpenAPI `GET /messaging/events` (op=`fetch_events_messaging_events_get`); no caller found in `src/`.
3. **It is SSE (not WebSocket).** VERDICT: Verified (transport), Unverified (declared content-type). SOURCE: `src/hooks/useMessagingStream.ts: new EventSource(MESSAGING_STREAM_URL, { withCredentials: true })`. Caveat: OpenAPI `GET /messaging/events/stream` declares `responses.200.content` = `application/json` with empty schema `{}` and exposes a `poll_ms` param — see assumption O1.
4. **Cursor query param is `since`.** VERDICT: Corrected → it is `after`. SOURCE: OpenAPI `GET /messaging/events/stream` and `GET /messaging/events` both declare query `after` (string|null); no `since` param exists.
5. **Stream query params.** VERDICT: Verified. SOURCE: OpenAPI `GET /messaging/events/stream params = after, limit(default 50,max 200), poll_ms(default 1000,min 200,max 5000), x_request_id, authorization(header), X-SESSION-ID(header)`.
6. **Core message event type names `message.created` / `message.updated` / `message.deleted`.** VERDICT: Corrected → `message:new` / `message:edited` / `message:revoked` (colon-delimited). SOURCE: `src/hooks/useMessagingStream.ts: EVENT_TYPES` and `handleEvent`; `src/hooks/useMessagingStream.test.tsx: dispatchNamedEvent("message:new", { conversation_id: "c-2" })`. The dotted form is used only for the `call.*` / `webrtc.*` namespaces.
7. **Conversation identifier field is `thread_id`.** VERDICT: Corrected → `conversation_id`. SOURCE: `src/hooks/useMessagingStream.ts: data.conversation_id`; `src/api/types.ts: Message.conversation_id` (line ~1100). (`Message.thread_id` exists but is a reply sub-thread id, out of scope.)
8. **Message DTO fields `id` / `author_id` / `body`.** VERDICT: Corrected → `message_id` / `sender_id` / `text`. SOURCE: `src/api/types.ts: interface Message { message_id; conversation_id; sender_id; kind; text? ... }` (lines ~1098-1104).
9. **Message timestamps are ISO-8601 strings.** VERDICT: Corrected → epoch-seconds numbers. SOURCE: `src/api/types.ts: Message.created_at: number, edited_at?: number, revoked_at?: number`; `src/pages/messages/MessageBubble.tsx: new Date(message.created_at * 1000)`.
10. **Deletion modeled as `deleted` boolean / `deleted_at`.** VERDICT: Corrected → `revoked` / `revoked_at` (and `message:expired` for disappearing media). SOURCE: `src/api/types.ts: Message.revoked_at?, revoked_by?` (lines ~1197-1198); `src/hooks/useMessagingStream.ts: "message:revoked", "message:expired"`.
11. **Per-event envelope fields `event_id`, `cursor`, `sequence`.** VERDICT: Corrected/removed → none exist in the messaging-stream contract. SOURCE: `src/hooks/useMessagingStream.ts` reads only `type`, `conversation_id`, `message_id`, `user_id`, `poll_id`, etc.; OpenAPI stream `200` schema is empty `{}`. (`event_id` appears only in client-generated WebRTC signaling, `src/hooks/useRtcPeerConnection.ts` — unrelated.)
12. **Dedupe keyed on `event_id`.** VERDICT: Corrected → keyed on `message_id` (the only stable id present). SOURCE: as #11 + #8.
13. **Catch-up paging envelope `EventPageDto { events[], next_cursor, has_more }`.** VERDICT: Corrected/Unverified-assumption → no such schema in OpenAPI; `/messaging/events` `200` schema is empty `{}` and has no caller in `src/`. SOURCE: OpenAPI `fetch_events_messaging_events_get` responses; grep of `src/` for `next_cursor`/`has_more` on this endpoint returns none (those tokens belong to gallery/feed/devtools paging, not events).
14. **SSE request carries `X-CSRF-Token`.** VERDICT: Corrected → no CSRF header on the stream; cookies only. SOURCE: `src/hooks/useMessagingStream.ts: { withCredentials: true }` (EventSource cannot set custom headers). For non-stream REST the web client does send `X-CSRF-Token` (`src/api/client.ts:168-171`), but that path is not used for the SSE connection.
15. **Auth is cookie-based.** VERDICT: Verified, with addition. SOURCE: `src/api/client.ts: credentials: "include"` and `withCredentials: true`. OpenAPI also accepts optional `authorization` and `X-SESSION-ID` headers on both endpoints (usable by the native client).
16. **`401` triggers a single `POST /ui/session/refresh` then reconnect.** VERDICT: Verified (endpoint + REST behavior); the SSE hook itself reconnects via backoff rather than calling refresh. SOURCE: OpenAPI `POST /ui/session/refresh` (op=`ui_session_refresh_ui_session_refresh_post`); `src/api/client.ts:121-130 refreshSession()` + `:204-221` refresh-once-on-401; `src/hooks/useMessagingStream.ts: es.onerror` backoff.
17. **Reconnect backoff is exponential with a cap.** VERDICT: Verified (web cap is 30s; Android spec uses 32s cap — acceptable, slightly different). SOURCE: `src/hooks/useMessagingStream.ts: MAX_RETRY_DELAY = 30_000; Math.min(1000 * 2^retryCount, MAX_RETRY_DELAY)`. (Broadcast chat uses 15s cap: `src/pages/broadcast/BroadcastChat.tsx`.)
18. **Unknown event types are skipped, stream survives.** VERDICT: Verified. SOURCE: `src/hooks/useMessagingStream.ts: catch {}` around parse and only-registered-listener dispatch.
19. **Validation errors return `HTTPValidationError`.** VERDICT: Verified. SOURCE: OpenAPI both endpoints `resp 422:HTTPValidationError`; `components.schemas.HTTPValidationError`.
20. **Library `com.squareup.okhttp3:okhttp-sse:4.12.0` / OkHttp `EventSources` API.** VERDICT: Verified (framework ref). SOURCE: framework ref — OkHttp SSE companion artifact, `okhttp3.sse.EventSources` / `EventSourceListener` (square.github.io/okhttp). `readTimeout(0)` to disable read timeout: framework ref OkHttp `OkHttpClient.Builder.readTimeout`.
21. **Lifecycle/Compose/Room/Paging mechanics (ProcessLifecycleOwner, Room `Flow`/`PagingSource`, DataStore).** VERDICT: Unverified-assumption (framework ref only; depends on AND-123/AND-143 implementations). SOURCE: framework ref — AndroidX Lifecycle/Room/Paging/DataStore docs (developer.android.com).

### Corrections made

- **Cursor param `since` → `after`** (claims 4; FR-2, FR-7, §4.1 code, §5.1, §5.2).
- **Event names `message.created/updated/deleted` → `message:new/edited/revoked`** (claim 6; §1, FR-3, §5.1, §6, §14 AC-3/AC-4).
- **`thread_id` → `conversation_id`** as the conversation key; clarified `Message.thread_id` is a reply sub-thread (claim 7; §1 reviewer note, FR-3, §5–§6).
- **Message fields `id/author_id/body` → `message_id/sender_id/text`** (claim 8; §5.1, §6).
- **Timestamps ISO string → epoch-seconds number** (claim 9; §5.1, §6).
- **Deletion `deleted/deleted_at` → `revoked/revoked_at`** (+`message:expired`) (claim 10; FR-3, §5.1, §6, §14).
- **Removed invented envelope fields `event_id/cursor/sequence`**; dedupe re-keyed to `message_id`, ordering re-based on `edited_at/revoked_at` (claims 11–12; FR-5, §4.2, §6).
- **Removed invented `EventPageDto`/`next_cursor`/`has_more`**; catch-up response shape marked open (claim 13; §5.2).
- **Removed `X-CSRF-Token` from the SSE request** and reclassified `403` as authz (not CSRF) (claims 14; §2, §5.1, §7, §8).
- **Reconciled risks R1/R2/R4** to reflect SSE-confirmed/`after`-confirmed/payload-unverified state (§13).

### Open assumptions

- **O1 — Stream response content-type.** OpenAPI declares `application/json` (empty schema) with a `poll_ms` param, but the web client consumes it as SSE via `EventSource`. Assumed real wire format is `text/event-stream` over an internal long-poll. WHY unverifiable: OpenAPI omits the streaming media type; must be confirmed against the live dev host (R1/R3).
- **O2 — `after` token semantics.** Inclusive vs exclusive, and whether it is the SSE frame `id`, a `created_at`, or an opaque token. WHY: no caller in `src/` sends `after`; payload exposes no cursor. Confirm with backend (R2).
- **O3 — `/messaging/events` catch-up response shape.** No schema in OpenAPI (empty `{}`), no web caller. WHY: undocumented; decode defensively until confirmed (R6).
- **O4 — Exact per-event `data` payload fields for `message:edited`/`message:revoked`.** Web client only reads `conversation_id` and re-fetches. WHY: backend payload not declared; fields beyond `conversation_id`/`message_id` assumed, with REST re-fetch fallback (R4).
- **O5 — Heartbeat/keep-alive frame shape and interval.** WHY: not in OpenAPI or web source; the 45s idle watchdog window is a guess pending observation against the dev host (R3).
- **O6 — Server caps on catch-up volume after long offline.** `limit` ≤ 200 bounds a page, but total backlog cap is unknown. WHY: not documented (R6).
- **O7 — AND-123/AND-143 internal types** (`MessageDao`, `ThreadDao`/conversation DAO, `Message` domain model, paging sources). WHY: those tickets are upstream deps not present in these sources; assumed per their spec summaries.

## 17. Test Plan

Test target legend: **JVM** = local JVM unit/Robolectric (no device); **emu35** = headless AVD `test35` (x86_64, API 35) in CI; **A15** = physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a) on the build host. Use A15 only where real-hardware/real-network behavior matters.

- **TC-AND-144-01 — Dispatch happy path: `message:new` mutates cache.** Type: unit. Target: JVM (`MessagingEventsRepository` with `FakeMessageDao`/`FakeConversationDao`). Preconditions: empty caches; conversation `c_42` exists. Steps: feed `SseEvent.Data(type="message:new", data={conversation_id:c_42, message_id:m_1, sender_id:u_7, text:"hi", created_at:1749132131})` to `handle`. Expected: one row inserted into message DAO for `c_42`; conversation summary updated (last preview="hi", timestamp=created_at, unread bumped). Traces: AC-1, AC-2.
- **TC-AND-144-02 — `message:edited` updates body + latest preview.** Type: unit. Target: JVM. Preconditions: `m_1` exists in `c_42`, is the latest. Steps: feed `message:edited` for `m_1` with new `text` + `edited_at`. Expected: stored `text` replaced; `edited_at` set; conversation preview refreshed because it was latest. Traces: AC-3.
- **TC-AND-144-03 — `message:revoked` tombstones + recomputes preview.** Type: unit. Target: JVM. Preconditions: `m_2` (latest) and `m_1` (prior) in `c_42`. Steps: feed `message:revoked` for `m_2` with `revoked_at`. Expected: `m_2` flagged revoked/tombstoned; conversation preview recomputed from `m_1`. (Repeat with `message:expired` → same outcome.) Traces: AC-4.
- **TC-AND-144-04 — Dedupe by `message_id`.** Type: unit. Target: JVM. Preconditions: empty. Steps: feed the same `message:new` (`m_1`) twice. Expected: exactly one insert; second `markProcessed(m_1)` returns false; no duplicate row. Traces: AC-6.
- **TC-AND-144-05 — Stale-mutation ordering guard.** Type: unit. Target: JVM. Preconditions: `m_1` stored with `edited_at=200`. Steps: feed `message:edited` for `m_1` with `edited_at=100` (older), then one with `edited_at=300`. Expected: older edit ignored; newer edit applied. Same for `revoked_at`. Traces: AC-6.
- **TC-AND-144-06 — Unknown/other event types are skipped, stream survives.** Type: unit. Target: JVM. Preconditions: live handler. Steps: feed `typing:update`, `presence:update`, `call.invite`, and a malformed-JSON frame in sequence, then a valid `message:new`. Expected: non-core events ignored without throwing; malformed frame swallowed; the following `message:new` still applies; no decode advances a poison cursor. Traces: AC-8.
- **TC-AND-144-07 — Reconnect backoff is exponential, capped, and resets on Live.** Type: unit. Target: JVM (`TestScope` virtual time, injected RNG). Preconditions: stream forced to fail repeatedly. Steps: simulate consecutive IO failures; record delays; then a successful connect. Expected: delays follow 1s→2s→…→32s cap with jitter; on a clean `Live` transition the attempt counter resets to 0. Traces: AC-7.
- **TC-AND-144-08 — Single 401 → one `/ui/session/refresh` → reconnect; second 401 → auth-required.** Type: contract/MockWebServer. Target: JVM + MockWebServer. Preconditions: enqueue stream `401`, then `POST /ui/session/refresh` `200`, then stream `200` with one frame; second scenario: `401` then refresh `200` then `401`. Expected: exactly one refresh POST observed; reconnect succeeds and frame applied; in the second scenario the repo emits an auth-required/`Offline` state and stops retrying. Traces: AC-8.
- **TC-AND-144-09 — SSE wire parsing + mid-stream disconnect.** Type: contract/MockWebServer. Target: JVM + MockWebServer. Preconditions: enqueue a chunked `text/event-stream` body with `event: message:new` + `data:` frames, a `:` comment heartbeat, then close the socket mid-stream. Steps: collect `events()`. Expected: named frames decode to `SseEvent.Data` with correct `type`/`data`; comment/heartbeat ignored; `onClosed`/`onFailure` surfaces and triggers a reconnect. Validates O1 parsing assumption against a controlled server. Traces: AC-1, AC-7.
- **TC-AND-144-10 — Catch-up applied in order before live attach.** Type: contract/MockWebServer. Target: JVM + MockWebServer. Preconditions: enqueue `GET /messaging/events?after=...` returning a page of events (full page then a short page), then the live stream. Steps: subscribe. Expected: all catch-up events applied in order, resume token advanced, and the live stream is only attached after catch-up completes (no gap). Note: assertions tolerate the unverified response shape (O3) — decoder accepts array-or-wrapped-array. Traces: AC-7.
- **TC-AND-144-11 — Ref-counting: two subscribers → one connection; last unsubscribe closes.** Type: integration. Target: JVM (Robolectric) or emu35. Preconditions: MockWebServer counting concurrent connections. Steps: `subscribe()` from two simulated ViewModels, then close both. Expected: exactly one live connection while ≥1 subscriber; connection closed after the last `close()`. Traces: AC-5.
- **TC-AND-144-12 — Lifecycle pause/resume performs catch-up on resume.** Type: instrumented. Target: emu35. Preconditions: app foregrounded with a messaging screen; MockWebServer (or dev host) reachable. Steps: drive `ProcessLifecycleOwner` `ON_STOP` then `ON_START` (background/foreground). Expected: stream paused on stop (no live connection), and on resume a `GET /messaging/events?after=` catch-up fires before re-attaching live. Traces: AC-5, AC-7.
- **TC-AND-144-13 — Live message renders in open conversation without scroll jump; other conversation updates only the list.** Type: Compose-UI. Target: emu35 (fake repo emitting events). Preconditions: thread-detail (AND-143) open at a fixed scroll anchor; list (AND-123) visible. Steps: emit `message:new` for the open conversation, then for a different conversation. Expected: open conversation gains a new row with the user's scroll/read anchor preserved (no jump); list summary updates for the other conversation only. Traces: AC-1, AC-2, AC-4.
- **TC-AND-144-14 — Reconnecting/offline indicator: accessible live-region announcement, content stays visible.** Type: Compose-UI + accessibility. Target: emu35 (assertions) and A15 (TalkBack verification). Preconditions: cached content present. Steps: drive `StreamStatus.Offline`, assert the indicator appears with a non-empty `contentDescription` and `liveRegion = Polite`; verify cached messages remain visible; then drive `Live` and assert the indicator clears. On A15, enable TalkBack and confirm the transition is announced politely and does not steal focus from the message list. MUST run on A15 for the real TalkBack announcement/focus behavior. Traces: AC-7, AC-9 (no-body-in-UI), and accessibility DoD.
- **TC-AND-144-15 — No message body or cookie in logs/telemetry.** Type: unit + manual. Target: JVM (capture Timber/analytics façade) + A15 (logcat spot-check on dev host). Preconditions: instrument log/telemetry sinks. Steps: drive create/edit/revoke + a disconnect; capture all emitted telemetry and logs. Expected: telemetry events (`messaging_event_applied`, `messaging_stream_disconnected`, etc.) contain only `type`/`conversation_id`/`message_id`/`http_code`; no `text`, no cookie/session/bearer values, no full `data` payload anywhere. Traces: AC-9.
- **TC-AND-144-16 — Flaky/offline dev-host resilience and indicator debounce.** Type: instrumented/e2e. Target: A15 (real network against dev host `http://18.222.237.167:8000`). Preconditions: device on real network; dev backend reachable but unstable. Steps: connect, toggle device connectivity (airplane mode on/off) and induce drops. Expected: on drop, cached content stays visible and the offline indicator appears only after one backoff cycle (no flapping, FR-8); on recovery, catch-up applies missed events and the indicator clears. MUST run on A15 for real radio/connectivity-loss behavior (emulator cannot faithfully reproduce cellular drops). Traces: AC-7.

### Coverage matrix

| Acceptance criterion | Covered by |
|---|---|
| AC-1 (new msg live in open conversation) | TC-01, TC-09, TC-13 |
| AC-2 (new msg updates list summary) | TC-01, TC-13 |
| AC-3 (`message:edited` body + preview) | TC-02 |
| AC-4 (`message:revoked` tombstone + preview recompute) | TC-03, TC-13 |
| AC-5 (single connection; close on leave; pause/resume) | TC-11, TC-12 |
| AC-6 (dedupe + ordering guard) | TC-04, TC-05 |
| AC-7 (offline indicator, stale-while-reconnect, catch-up recovery) | TC-07, TC-09, TC-10, TC-12, TC-14, TC-16 |
| AC-8 (single-401 refresh + unknown-type skip) | TC-06, TC-08 |
| AC-9 (no body/cookie in logs/telemetry) | TC-13 (UI), TC-15 |
