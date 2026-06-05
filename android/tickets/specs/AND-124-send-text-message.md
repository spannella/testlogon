---
id: AND-124
title: Send text message
milestone: M3
epic: E18
priority: P0
size: M
status: draft
depends_on: [AND-123]
blocks: []
---

# AND-124 — Send text message

## 1. Overview & Goal

Add a text-message composer to the Thread (message list) screen delivered by AND-123, and wire it to the conversation send endpoint `POST /conversations/{id}/messages`. The defining requirement is **optimistic send**: when the user taps Send, the message must appear in the thread immediately as a locally-generated row, the network request fires in the background, and the optimistic row is **reconciled** against the server-acknowledged message when the response arrives. Failed sends must surface a non-destructive failure state with a one-tap **retry** affordance, and must not lose the user's typed text.

Goal of this ticket, restated as a testable outcome: a user can type text, send it, see it render optimistically with a "sending" indicator, and observe the row transition to a confirmed message (server `id`, server `created_at`, "sent" status) on ack — or to a "failed" state with retry on error. The composer state, the optimistic insert, and the reconciliation logic are the deliverables. Read-side history and pagination are owned by AND-123 and are consumed here, not re-implemented.

## 2. Context & References

- **Module:** `feature-messaging` (Gradle module `:feature:messaging`), package `com.testlogon.android.feature.messaging`. The composer and send logic extend the screen and ViewModel introduced by AND-123, not a new screen.
- **Layering:** `feature-messaging` -> `core-network` (Retrofit service, `ApiResult<T>`), `core-model` (DTO/domain), `core-data` (Room cache + repository), `core-ui` (Compose components, theme). No backward dependencies.
- **Backend:** FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000` (plaintext HTTP, unreliable). OpenAPI at `/openapi.json`. Cookie-based auth: session cookies + `ui_csrf` cookie echoed as `X-CSRF-Token`; on `401` the OkHttp authenticator calls `POST /ui/session/refresh` once and retries. A persistent cookie jar is required (established by the core-network/auth tickets).
- **Web reference:** `frontend/src/api/endpoints/conversations.ts` (the `sendMessage` call) and `frontend/src/api/types.ts` (`Message`, `SendMessageRequest`). The Android DTOs in this ticket must mirror those shapes.
- **Dependency AND-123** supplies: `MessagingViewModel`, `MessagingUiState`, the `LazyColumn` reverse-layout thread list, the `Message` domain model, the Room `MessageEntity`/`MessageDao`, and the Paging 3 history source. AND-124 adds the write path.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15, Room 2.6, Paging 3. minSdk 24 / target 35, JDK 17.

## 3. Functional Requirements

FR-1. The Thread screen renders a pinned bottom **composer**: a multiline `TextField` (Material 3 `OutlinedTextField`) plus a Send `IconButton`. The composer sits above the IME and respects `imePadding()` and navigation-bar insets.

FR-2. Send is enabled only when the trimmed draft is non-empty. Whitespace-only drafts are not sendable. Max length 4000 characters (client guard mirroring the backend; over-limit input is rejected with an inline counter/error rather than truncated silently).

FR-3. On Send tap: the draft is cleared from the input immediately, a new optimistic message row is inserted at the bottom of the thread with `status = SENDING`, attributed to the current user (from `GET /ui/me`), with a client-generated `clientId` (UUID) and a local timestamp.

FR-4. The optimistic row is visually distinct while `SENDING` (e.g., reduced alpha or a small progress/clock glyph). It is **not** removed on success; instead it is reconciled in place to the server message (status `SENT`).

FR-5. On send success, the row adopts the server `id`, `created_at`, and any server-normalized `body`. Reconciliation keys on `clientId` so the row does not duplicate when the same message also arrives via history refresh / list poll (AND-123).

FR-6. On send failure (network/timeout/non-2xx), the row transitions to `status = FAILED` and shows a retry control (tap row or an inline "Failed — Retry" affordance). The typed text is preserved in the failed row; retry re-issues the same `POST` with the same `clientId` (idempotency key) and returns the row to `SENDING`.

FR-7. Retry is bounded and **manual** — there is no automatic retry of message sends in this ticket (sends are non-idempotent at the HTTP layer except via `clientId`; auto-retry is out of scope). Multiple failed messages each retry independently.

FR-8. Sending preserves scroll position at the bottom: inserting the optimistic row scrolls the list to the newest message.

FR-9. While a send is in flight, the composer remains usable — the user can type and send additional messages concurrently; each is an independent optimistic row.

## 4. Technical Design

### 4.1 UI state additions

Extend the AND-123 `MessagingUiState`. Optimistic/in-flight rows are not stored in the same immutable list as server history; they are merged at render time so paging from AND-123 stays clean.

```kotlin
data class ComposerState(
    val draft: String = "",
    val isSendEnabled: Boolean = false,
    val charCount: Int = 0,
    val overLimit: Boolean = false,
)

enum class SendStatus { SENDING, SENT, FAILED }

// Domain message extended with optimistic fields (in core-model)
data class Message(
    val id: String?,          // null until acked
    val clientId: String,     // stable, client-generated
    val conversationId: String,
    val authorId: String,
    val body: String,
    val createdAt: Instant,   // local placeholder until acked
    val sendStatus: SendStatus = SendStatus.SENT, // history rows = SENT
)
```

`MessagingUiState` (from AND-123) gains:
```kotlin
data class MessagingUiState(
    val conversationId: String,
    val messages: List<Message>,        // merged history + outbox, render-ready
    val composer: ComposerState = ComposerState(),
    val isLoadingHistory: Boolean = false,
    val historyError: UiError? = null,
)
```

### 4.2 Outbox

In-flight and failed messages live in an **outbox** keyed by `clientId`, held in the ViewModel and mirrored to Room so a process death does not lose a failed/pending send.

```kotlin
@Entity(tableName = "outbox_messages")
data class OutboxMessageEntity(
    @PrimaryKey val clientId: String,
    val conversationId: String,
    val body: String,
    val createdAt: Long,      // epoch millis
    val status: String,       // SENDING | FAILED
    val attemptCount: Int = 0,
)

@Dao
interface OutboxDao {
    @Query("SELECT * FROM outbox_messages WHERE conversationId = :cid ORDER BY createdAt ASC")
    fun observe(cid: String): Flow<List<OutboxMessageEntity>>
    @Upsert suspend fun upsert(e: OutboxMessageEntity)
    @Query("DELETE FROM outbox_messages WHERE clientId = :clientId")
    suspend fun delete(clientId: String)
}
```

The rendered `messages` list is computed as: server history (Paging 3 / cached `MessageEntity`) **left-joined** with the outbox by `clientId`. A confirmed history row supersedes its outbox entry; on supersede the outbox row is deleted. Merge happens in a `combine(...)` flow:

```kotlin
val uiState: StateFlow<MessagingUiState> =
    combine(historyFlow, outboxDao.observe(conversationId), composerFlow) {
        history, outbox, composer ->
        mergeMessages(history, outbox).let { merged ->
            MessagingUiState(conversationId, merged, composer, ...)
        }
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), initial)
```

### 4.3 ViewModel actions

```kotlin
class MessagingViewModel @Inject constructor(
    private val repo: MessageRepository,
    savedState: SavedStateHandle,
) : ViewModel() {
    fun onDraftChange(text: String)
    fun onSendClick()              // builds clientId, enqueues outbox, fires send
    fun onRetry(clientId: String)  // re-fires a FAILED row
}
```

`onSendClick`:
1. `val body = composer.draft.trim()`; ignore if blank or over limit.
2. `val clientId = UUID.randomUUID().toString()`.
3. `outboxDao.upsert(SENDING)` -> clear draft -> trigger scroll-to-bottom.
4. `viewModelScope.launch { send(clientId, body) }`.

`send(clientId, body)`:
```kotlin
when (val r = repo.sendMessage(conversationId, clientId, body)) {
    is ApiResult.Success -> {
        messageDao.upsert(r.data.toEntity())   // becomes SENT history row
        outboxDao.delete(clientId)             // reconciled
    }
    is ApiResult.Error ->
        outboxDao.upsert(failed(clientId, attemptCount + 1))
}
```

### 4.4 Repository

```kotlin
interface MessageRepository {
    suspend fun sendMessage(
        conversationId: String,
        clientId: String,
        body: String,
    ): ApiResult<Message>
}
```
Implementation maps `SendMessageRequest(body, clientId)` -> service call -> `MessageDto.toDomain(sendStatus = SENT)`, wrapped via the shared `apiCall { }` helper that converts exceptions/non-2xx into `ApiResult.Error` and decodes the FastAPI `detail` shape.

### 4.5 Composer Composable

```kotlin
@Composable
fun MessageComposer(
    state: ComposerState,
    onDraftChange: (String) -> Unit,
    onSend: () -> Unit,
    modifier: Modifier = Modifier,
)
```
Rendered inside the Thread `Scaffold` bottomBar with `Modifier.imePadding().navigationBarsPadding()`. The optimistic/failed row rendering is added to the existing message item Composable from AND-123, branching on `Message.sendStatus`.

## 5. API Contract

**Endpoint:** `POST /conversations/{id}/messages` (path param `id` = `conversationId`). Idempotent only via `client_id`; the server treats a repeated `client_id` as the same logical message and returns the existing resource (deduplication). Confirm `client_id` support against `/openapi.json` before implementation; see Open Questions if absent.

**Request headers:** session cookies (auto via cookie jar) + `X-CSRF-Token: <ui_csrf>` (auto via the CSRF interceptor from core-network). `Content-Type: application/json`.

**Request body:**
```json
{ "body": "hello world", "client_id": "7c1f...-uuid" }
```

**Success `201` (or `200`) response:**
```json
{
  "id": "msg_01H...",
  "conversation_id": "conv_01H...",
  "author_id": "usr_01H...",
  "body": "hello world",
  "client_id": "7c1f...-uuid",
  "created_at": "2026-06-05T14:22:31.004Z"
}
```

**Moshi DTO + Retrofit:**
```kotlin
@JsonClass(generateAdapter = true)
data class SendMessageRequest(
    @Json(name = "body") val body: String,
    @Json(name = "client_id") val clientId: String,
)

@JsonClass(generateAdapter = true)
data class MessageDto(
    @Json(name = "id") val id: String,
    @Json(name = "conversation_id") val conversationId: String,
    @Json(name = "author_id") val authorId: String,
    @Json(name = "body") val body: String,
    @Json(name = "client_id") val clientId: String?,
    @Json(name = "created_at") val createdAt: String, // ISO-8601 -> Instant
)

interface ConversationApi {
    @POST("conversations/{id}/messages")
    suspend fun sendMessage(
        @Path("id") conversationId: String,
        @Body request: SendMessageRequest,
    ): Response<MessageDto>
}
```

**Error responses:** FastAPI `detail` mapped by the shared decoder into `UiError`:
- `401` -> authenticator runs `POST /ui/session/refresh` once and retries; second `401` -> `UiError.Unauthorized` (send marked FAILED, surface re-auth).
- `403` -> CSRF/permission; FAILED with non-retryable hint.
- `404` -> conversation gone; FAILED with "conversation unavailable".
- `422` -> `detail: [{msg, loc}]`; FAILED, show first `msg` (e.g., body too long).
- `5xx` / timeout / `IOException` -> FAILED, retryable.

`detail` may be `string | [{msg,...}] | {code,...}`; use the existing `DetailErrorAdapter`.

## 6. Data & State Management

- **Source of truth for confirmed messages:** Room `MessageEntity` (owned by AND-123) + Paging. Confirmed sends are inserted here on ack so they persist and dedupe against history refresh by `clientId`/`id`.
- **Source of truth for unconfirmed messages:** `OutboxMessageEntity` (this ticket), keyed by `clientId`. Survives process death so a FAILED message and its text are recoverable after the app is killed.
- **Draft persistence:** the current `composer.draft` is held in `SavedStateHandle` (key `draft_<conversationId>`) so rotation/process recreation does not lose unsent typing.
- **Merge/dedup rule:** render list = `history ∪ outbox`, deduped by `clientId` (history wins). When a history row with matching `clientId` appears, delete the outbox row (handles the case where the server message also arrives via list poll before the POST response is processed).
- **Ordering:** rows ordered by `createdAt`; optimistic rows use local time and naturally sort to the bottom; on ack the server `created_at` replaces it (ordering may shift slightly — acceptable and tested).
- **Threading:** all DB writes on `Dispatchers.IO`; state exposed as `StateFlow<MessagingUiState>` via `stateIn`.

## 7. Error Handling & Resilience

- **Timeouts:** OkHttp call timeout ~20s (per project dev-host policy). A send exceeding it becomes FAILED, not hung; the UI never blocks on the request.
- **No auto-retry for sends:** sends are user-initiated retries only (FR-7). Idempotency via `client_id` makes a manual retry safe even if the first attempt actually reached the server — the server returns the existing message, which reconciles normally.
- **Offline:** if no connectivity, the optimistic row goes straight to FAILED with a "No connection — Retry" hint; nothing is silently dropped.
- **Refresh-on-401:** handled centrally by the OkHttp authenticator; the send coroutine sees only the post-refresh outcome. A double-401 marks FAILED.
- **Concurrent sends:** independent coroutines per `clientId`; one failure never affects another row.
- **Process death mid-send:** outbox row remains `SENDING`; on next screen load any `SENDING` row older than the timeout window is normalized to `FAILED` (it was never confirmed) so the user can retry. Because retry reuses `client_id`, no duplicate is created server-side.

## 8. Security & Privacy

- Auth/CSRF are transport concerns handled by core-network (cookie jar + `X-CSRF-Token` interceptor + refresh authenticator); this ticket adds no new auth code and must not bypass them.
- Message bodies are user content: do not write them to logcat or telemetry payloads (see §10). The outbox table holds plaintext bodies in the app's private Room DB only.
- The dev backend is plaintext HTTP; this is a known dev-only condition. The release build must use HTTPS and the network-security-config must forbid cleartext for production hosts (owned by the network/build tickets; this ticket inherits it).
- Input is sent verbatim as JSON via Moshi (no string interpolation), so no injection surface is introduced. Rendering uses Compose `Text` (no HTML), so no XSS surface.

## 9. Accessibility & i18n

- Send `IconButton` has `contentDescription = stringResource(R.string.cd_send_message)`; disabled state is announced (not just visually dimmed).
- Composer `TextField` has a labeled placeholder/`semantics` ("Message"); the failed-row retry control exposes `contentDescription` "Retry sending message" and a state description ("Failed to send").
- Optimistic/sending state is conveyed non-visually via `Modifier.semantics { stateDescription = "Sending" }` so it is not color-only.
- All strings in `strings.xml` (no hardcoded literals). Character counter uses locale-aware number formatting. Layout is RTL-safe (use start/end, `imePadding`). Minimum 48dp touch targets for Send and Retry.

## 10. Telemetry & Logging

- Events (via the app analytics facade from core-data; no PII, no message body):
  - `message_send_attempt` { conversationId (hashed), clientIdPresent }
  - `message_send_success` { latencyMs }
  - `message_send_failed` { errorClass, httpStatus }
  - `message_send_retry` { attemptCount }
- Logging: `Timber.d`/`w` for send lifecycle with `clientId` only — **never** the body or raw cookies. Network logging interceptor stays at `BASIC` for release (no bodies) per project policy.

## 11. Testing Strategy

- **Unit — ViewModel (core-testing, `MainDispatcherRule`, Turbine):**
  - Send inserts an optimistic `SENDING` row and clears the draft. (covers Acceptance "appears optimistically")
  - On `ApiResult.Success`, the optimistic row reconciles: `id` populated, `sendStatus == SENT`, outbox entry deleted, no duplicate. (covers "reconciles on ack")
  - On `ApiResult.Error`, row -> `FAILED`, body preserved, retry re-fires with the **same `clientId`** and returns to `SENDING`.
  - Blank/whitespace/over-limit drafts do not send; `isSendEnabled` toggles correctly.
  - Concurrent sends produce independent rows; one failure does not affect another.
  - Merge/dedup: a history row arriving with the same `clientId` removes the outbox row (no duplicate).
- **Repository tests:** MockWebServer returns 201/422/500/timeout; assert correct `ApiResult`, request body JSON (`body`,`client_id`), and `X-CSRF-Token` header presence.
- **DAO tests:** Room in-memory — outbox upsert/delete/observe; `SENDING` normalization to `FAILED` on reload.
- **Compose UI tests:** typing enables Send; tap shows the sending row; failed row shows Retry with correct content descriptions; accessibility assertions on labels.
- All async tests are deterministic (`runTest`, injected `TestDispatcher`); MockWebServer for network; no calls to the live dev host in CI.

## 12. Dependencies & Sequencing

- **Depends on AND-123** (Thread/message list screen): provides the screen scaffold, `MessagingViewModel` base, `Message` domain model, Room `MessageEntity`/`MessageDao`, and the paged history flow this ticket merges with the outbox. Must merge after AND-123.
- **Transitive:** AND-120 (conversation/messaging foundation, via AND-123) and the core-network auth/CSRF/cookie-jar tickets (session, refresh authenticator, CSRF interceptor) must already exist.
- **Blocks:** none recorded in the source bullets. Later messaging features (e.g., attachments, edit/delete, read receipts) build on this composer + outbox but are not listed as dependents here.

## 13. Risks & Open Questions

- **OQ-1:** Does `POST /conversations/{id}/messages` accept and dedupe on `client_id`? If not, idempotent retry is unsafe (duplicate risk). Verify against `/openapi.json` and `frontend/src/api/endpoints/conversations.ts`. Fallback: drop `client_id` from the body, reconcile by `(authorId, body, createdAt)` heuristic, and disable retry-after-uncertain-failure. **Must be resolved before merge.**
- **OQ-2:** Success status code — `200` vs `201`? Handle both via `Response.isSuccessful`.
- **OQ-3:** Exact `created_at` format/precision (ms vs s; `Z` vs offset). Use a tolerant ISO-8601 Moshi adapter.
- **Risk:** ordering jitter when local time differs from server time at reconciliation. Mitigation: replace local time with server time on ack; accept minor reorder; covered by a test.
- **Risk:** unreliable dev host produces frequent FAILED states during manual QA. Mitigation: clear FAILED+Retry UX; MockWebServer for deterministic tests.

## 14. Acceptance Criteria

AC-1. Typing non-empty text enables Send; tapping Send clears the input and immediately shows the message in the thread as a `SENDING` optimistic row attributed to the current user. *(source: "appears optimistically")*

AC-2. On server ack the optimistic row reconciles in place to a confirmed message (server `id`, server `created_at`, `SENT` status) with **no duplicate** row. *(source: "reconciles on ack")* — verified by automated ViewModel test.

AC-3. On send failure the row shows a `FAILED` state with a Retry control; the typed text is preserved; Retry re-sends using the same `client_id` and the row returns to `SENDING`.

AC-4. Blank/whitespace-only drafts cannot be sent; over-limit (>4000 chars) input is blocked with an inline indicator.

AC-5. The optimistic insert scrolls the thread to the newest message; the composer stays above the IME with correct insets.

AC-6. A FAILED/pending message survives process death (persisted in the outbox) and remains retryable; retry does not create a duplicate.

AC-7. Automated tests cover optimistic insert, ack reconciliation, failure+retry, dedup-by-`client_id`, and blank/over-limit guards. *(source: "tested")*

## 15. Definition of Done

- `MessageComposer`, `ComposerState`, outbox (`OutboxMessageEntity`/`OutboxDao`), repository `sendMessage`, and ViewModel `onSendClick`/`onRetry` implemented in `:feature:messaging` under `com.testlogon.android.feature.messaging`, with the Retrofit `ConversationApi.sendMessage` and Moshi DTOs in `:core:network`/`:core:model`.
- Optimistic send + ack reconciliation + manual retry all functional against MockWebServer and manually verified against the dev host.
- All §11 unit, repository, DAO, and Compose UI tests pass in CI; no live-host calls in CI.
- No message bodies in logs or telemetry; `X-CSRF-Token` and cookie-jar paths verified; Detekt/ktlint clean; KSP builds.
- Strings externalized; accessibility content descriptions and state descriptions present; touch targets >= 48dp.
- All ACs in §14 demonstrably met; OQ-1 (`client_id` dedupe) confirmed and reflected in code before merge.
- PR targets the `android-port` branch and references AND-124 and AND-123.
