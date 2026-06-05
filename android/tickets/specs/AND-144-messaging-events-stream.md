---
id: AND-144
title: Messaging events stream
milestone: M3
epic: E20
priority: P0
size: L
status: draft
depends_on: [AND-143, AND-123]
blocks: []
---

# AND-144 — Messaging events stream

## 1. Overview & Goal

Real-time delivery of messaging mutations to the Android client. The thread list and any open conversation must reflect server-side changes (new messages, edits, deletions) within seconds of them occurring, without the user manually refreshing. This ticket implements the client-side consumer of the backend Server-Sent Events (SSE) stream exposed at `GET /messaging/events/stream` and the supporting catch-up endpoint `GET /messaging/events`.

The deliverable is a long-lived, lifecycle-aware streaming layer in `core-data` plus its wiring into the messaging feature ViewModels delivered by AND-143 (thread detail) and AND-123 (thread list). Success is defined as: a message sent from another client appears live in both the open thread (AND-143) and the thread list summary (AND-123) without user interaction.

Goal in one line: subscribe once, fan out three event types (`message.created`, `message.updated`, `message.deleted`) into the existing Room-backed messaging cache, and let Compose UIs re-render reactively off the cache.

## 2. Context & References

- Repo: `spannella/testlogon`, Android app under `android/`, branch `android-port`.
- Namespace / applicationId base: `com.testlogon.android`.
- Module layering: `app -> feature-messaging -> core-data -> core-network -> core-model`. This ticket lands code in `core-network` (raw SSE client), `core-data` (`MessagingEventsRepository`, dispatch into Room), and `core-model` (event DTOs/domain types). UI changes are confined to consuming existing StateFlows wired by AND-143/AND-123.
- Backend: FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000` is **plaintext HTTP** and unreliable; design for ~20s connect timeouts, bounded backoff reconnection, and visible offline/stale states. OpenAPI at `/openapi.json`.
- Web reference: `frontend/src/api/endpoints/messaging*.ts` (EventSource usage) and shared types in `frontend/src/api/types.ts`. Mirror the event envelope and event-type discriminators from the web client.
- Auth is cookie-based; the SSE request rides the same persistent cookie jar and `X-CSRF-Token` header established by the session layer (AND session bootstrap). On `401`, the client performs a single `POST /ui/session/refresh` then reconnects.
- Upstream dependencies:
  - **AND-123** — Thread list feature: provides `ThreadListViewModel`, the threads Room table/DAO, and `MessagingRepository` thread summary projection that this ticket updates on events.
  - **AND-143** — Thread detail feature: provides `ThreadDetailViewModel`, the messages Room table/DAO, the message domain model, and the paging source that this ticket invalidates/updates on events.

## 3. Functional Requirements

FR-1. The app maintains at most one active SSE connection to `GET /messaging/events/stream` while a messaging-related screen is in the foreground (thread list or any thread detail). The connection is reference-counted: opened on first subscriber, closed when the last subscriber unsubscribes.

FR-2. On (re)connection the client first issues `GET /messaging/events?since=<cursor>` to fetch any events missed while disconnected, applies them in order, advances the cursor, then attaches the live stream from that cursor. This guarantees no gap between catch-up and live.

FR-3. The client dispatches three event types into the local cache:
- `message.created` — insert the message into its thread; bump the thread summary (last message preview, timestamp, unread count) in the list.
- `message.updated` — replace the message body/edited-at; refresh the thread summary preview if the edited message was the latest.
- `message.deleted` — soft-delete (tombstone) the message; if it was the latest, recompute the thread summary preview from the next surviving message.

FR-4. New messages in the **currently open thread** (AND-143) appear in the visible message list without scroll jump for the user's own read position; new messages in **other threads** update only the thread list (AND-123).

FR-5. Events are idempotent and ordered. Duplicate `event_id`s (re-delivery after reconnect) are dropped. Out-of-order arrivals are tolerated via per-thread `sequence` comparison (later sequence wins for the same message).

FR-6. Unknown event `type` values are logged and skipped, never crash the stream (forward compatibility).

FR-7. The stream pauses on `ON_STOP` (app backgrounded) and resumes on `ON_START`, performing a catch-up (`/messaging/events?since=`) on resume.

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
    fun events(sinceCursor: String?): Flow<SseEvent> = callbackFlow {
        val url = baseUrl.newBuilder()
            .addPathSegments("messaging/events/stream")
            .apply { if (sinceCursor != null) addQueryParameter("since", sinceCursor) }
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

Dispatch decodes the `data` JSON into a sealed `MessagingEvent`, drops duplicates via a bounded LRU of seen `event_id`s plus a `UNIQUE(event_id)` insert-ignore on a Room `processed_events` table, then mutates the cache in a single transaction:

```kotlin
private suspend fun handle(ev: SseEvent) {
    if (ev !is SseEvent.Data) return
    val envelope = runCatching { adapter.fromJson(ev.data) }.getOrNull() ?: return
    if (!markProcessed(envelope.eventId)) return            // FR-5 dedupe
    when (val e = envelope.toDomain()) {
        is MessagingEvent.MessageCreated -> applyCreated(e)
        is MessagingEvent.MessageUpdated -> applyUpdated(e)
        is MessagingEvent.MessageDeleted -> applyDeleted(e)
        is MessagingEvent.Unknown -> Timber.w("Unknown event ${envelope.type}") // FR-6
    }
    cursorStore.advance(envelope.cursor)
}
```

`applyCreated/Updated/Deleted` write to `messageDao` and recompute the affected row in `threadDao` inside `withTransaction { }`. Because both DAOs back Compose via Room `Flow`/`PagingSource`, the open thread (AND-143) and the list (AND-123) recompose automatically — no event needs to cross a ViewModel boundary.

### 4.3 Lifecycle wiring

`ThreadListViewModel` (AND-123) and `ThreadDetailViewModel` (AND-143) each call `repo.subscribe()` in `init` and `subscription.close()` in `onCleared()`. The ref-count keeps one connection while either screen is alive. Background pause/resume (FR-7) is handled by a `DefaultLifecycleObserver` registered against `ProcessLifecycleOwner` in the messaging entry point that cancels/restarts the repository `job`.

## 5. API Contract

### 5.1 Live stream — `GET /messaging/events/stream`

- Request headers: `Accept: text/event-stream`, cookies (session + `ui_csrf`), `X-CSRF-Token: <ui_csrf>`.
- Query: `?since=<cursor>` (optional opaque cursor; resume point).
- Response: `200 text/event-stream`. Each SSE frame:

```
id: 01J9...ULID
event: message.created
data: {"event_id":"01J9...","type":"message.created","cursor":"c_8821",
       "thread_id":"th_42","sequence":318,
       "message":{"id":"m_991","thread_id":"th_42","author_id":"u_7",
                  "body":"hi","created_at":"2026-06-05T14:02:11Z",
                  "edited_at":null,"deleted":false}}
```

- `event: message.updated` — `data.message` carries `edited_at` and new `body`.
- `event: message.deleted` — `data` carries `{"event_id","type","cursor","thread_id","sequence","message_id":"m_991","deleted_at":"..."}` (no full body).
- Keep-alive: server emits `:` comment lines / periodic `event: ping`; client ignores them (no `type` match).
- Errors: `401` (expired session — refresh+reconnect), `403` (CSRF mismatch — surface auth error), `5xx`/connection drop — backoff reconnect.

### 5.2 Catch-up — `GET /messaging/events`

```kotlin
interface MessagingEventsApi {
    @GET("messaging/events")
    suspend fun catchUp(
        @Query("since") cursor: String?,
        @Query("limit") limit: Int = 200,
    ): ApiResult<EventPageDto>
}

@JsonClass(generateAdapter = true)
data class EventPageDto(
    val events: List<EventEnvelopeDto>,
    @Json(name = "next_cursor") val nextCursor: String?,
    @Json(name = "has_more") val hasMore: Boolean,
)
```

The repository pages catch-up until `hasMore == false`, applying each envelope through the same `handle` path, before attaching the live stream. FastAPI `detail` error mapping (string | `[{msg}]` | `{code,...}`) reuses the shared `ApiResult` decoder from `core-network`.

## 6. Data & State Management

- **Domain models** (`core-model`):

```kotlin
@JsonClass(generateAdapter = true)
data class EventEnvelopeDto(
    @Json(name = "event_id") val eventId: String,
    val type: String,
    val cursor: String,
    @Json(name = "thread_id") val threadId: String,
    val sequence: Long,
    val message: MessageDto? = null,
    @Json(name = "message_id") val messageId: String? = null,
    @Json(name = "deleted_at") val deletedAt: String? = null,
)

sealed interface MessagingEvent {
    data class MessageCreated(val threadId: String, val seq: Long, val message: Message) : MessagingEvent
    data class MessageUpdated(val threadId: String, val seq: Long, val message: Message) : MessagingEvent
    data class MessageDeleted(val threadId: String, val seq: Long, val messageId: String, val deletedAt: Instant) : MessagingEvent
    data class Unknown(val type: String) : MessagingEvent
}
```

- **Cursor persistence**: `EventCursorStore` over DataStore (`Preferences` key `messaging_event_cursor`). Survives process death so catch-up resumes from the last applied event. `cursor()` read and `advance(cursor)` write are serialized.
- **Dedupe table** (Room, `core-data`):

```kotlin
@Entity(tableName = "processed_events", indices = [Index(value=["event_id"], unique=true)])
data class ProcessedEventEntity(@PrimaryKey val eventId: String, val seenAt: Long)
```
`@Insert(onConflict = IGNORE)` returns rowId `-1` on duplicate → `markProcessed` returns false. A periodic prune keeps the last ~2,000 rows.
- **Ordering**: each message/thread row carries `sequence`; `applyUpdated/Deleted` apply only when incoming `sequence >= stored.sequence`.
- **StateFlow surface**: `MessagingEventsRepository.status: StateFlow<StreamStatus>` is the single observable; ViewModels map it into their existing `UiState` (e.g. `ThreadListUiState.connection`). Message/thread data flows through the existing Room-backed StateFlows/PagingData owned by AND-143/AND-123 — this ticket does not introduce a new content StateFlow.

## 7. Error Handling & Resilience

- Connect/read failures, `5xx`, and abrupt drops trigger exponential backoff with jitter (1s → 32s cap, reset on a clean `Live` transition). Backoff loop is the only reconnect path; no unbounded tight loop.
- `401`: one `POST /ui/session/refresh` attempt, then reconnect; a second consecutive `401` surfaces an auth-required state and stops retrying until the session layer re-authenticates.
- `403` (CSRF): emit `StreamStatus.Offline` and log; treat as auth fault, do not hot-loop.
- Catch-up failure: keep showing cached content, retry catch-up under the same backoff; the live stream is not attached until a catch-up succeeds (prevents gaps).
- Read timeout disabled (`readTimeout(0)`); liveness is inferred from server `ping` frames — if no frame (data or ping) arrives within 45s, the client proactively cancels and reconnects (idle-watchdog coroutine).
- Malformed `data` JSON or unknown `type`: skip the single frame, keep the connection (FR-6). Cursor is **not** advanced past a frame that failed to decode into a known envelope structure, except unknown-type frames whose envelope parsed (those advance, to avoid a poison-pill stall).
- All mutations are idempotent (dedupe + sequence guard), so replay after reconnect cannot corrupt the cache.
- Retry/backoff applies to this idempotent GET stream only; no message-sending here (sending is AND-143).

## 8. Security & Privacy

- The stream uses the same persistent cookie jar and `X-CSRF-Token` header as the rest of the session; no token is placed in the URL.
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

- **R1 — SSE vs WebSocket**: confirm the backend exposes SSE (`text/event-stream`) and not a WebSocket at `/messaging/events/stream`. The web reference uses `EventSource`, implying SSE; verify against `/openapi.json`. If WebSocket, swap `okhttp-sse` for an OkHttp `WebSocketListener` (design otherwise unchanged).
- **R2 — Cursor semantics**: is `since` an inclusive or exclusive opaque cursor, and is it the per-event `cursor` or the SSE `id`? Assumed exclusive, server-issued opaque string. Confirm to avoid replay/gap off-by-one.
- **R3 — Keep-alive / ping format**: exact ping frame (comment line vs `event: ping`) determines the idle-watchdog. Verify the 45s watchdog window against server heartbeat interval.
- **R4 — Delete payload**: does `message.deleted` include enough to recompute thread summary, or must the client query? Spec assumes `thread_id` + `message_id` suffice with local lookup of next-latest.
- **R5 — Dev host instability**: frequent drops may cause indicator flapping; debounce `Offline` display by one backoff cycle (FR-8).
- **R6 — Catch-up volume**: very large gaps after long offline could return many pages; `limit=200` paging bounds memory, but confirm server caps.

## 14. Acceptance Criteria

- AC-1 (primary): a message created by another client appears live in the **open thread** (AND-143) within ~3s, no manual refresh.
- AC-2: the same new message updates the **thread list** summary (last preview + timestamp + unread) for that thread (AND-123) within ~3s.
- AC-3: `message.updated` replaces the message body in an open thread and refreshes the list preview when it was the latest message.
- AC-4: `message.deleted` removes/tombstones the message from the open thread and recomputes the list preview from the next surviving message when the deleted one was latest.
- AC-5: exactly one SSE connection exists while messaging screens are foregrounded; it closes when all leave; backgrounding pauses and foregrounding resumes with a catch-up.
- AC-6: duplicate events (replay after reconnect) do not double-insert; out-of-order lower-`sequence` events are ignored.
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
- Open questions R1–R4 resolved or explicitly deferred with backend sign-off recorded in the PR.
