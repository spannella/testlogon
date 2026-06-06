---
id: AND-124
title: Send text message
milestone: M3
epic: E18
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-123]
blocks: []
---

# AND-124 — Send text message

## 1. Overview & Goal

Add a text-message composer to the Thread (message list) screen delivered by AND-123, and wire it to the conversation send endpoint `POST /messaging/conversations/{conversation_id}/messages` (CORRECTED: the spec previously said `POST /conversations/{id}/messages`; the real backend path has a `/messaging` prefix — verified against OpenAPI `POST /messaging/conversations/{conversation_id}/messages` op `send_text_message`). The defining requirement is **optimistic send**: when the user taps Send, the message must appear in the thread immediately as a locally-generated row, the network request fires in the background, and the optimistic row is **reconciled** against the server-acknowledged message when the response arrives. Failed sends must surface a non-destructive failure state with a one-tap **retry** affordance, and must not lose the user's typed text.

Goal of this ticket, restated as a testable outcome: a user can type text, send it, see it render optimistically with a "sending" indicator, and observe the row transition to a confirmed message (server `message_id`, server `created_at`, "sent" status) on ack — or to a "failed" state with retry on error. The composer state, the optimistic insert, and the reconciliation logic are the deliverables. Read-side history and pagination are owned by AND-123 and are consumed here, not re-implemented.

## 2. Context & References

- **Module:** `feature-messaging` (Gradle module `:feature:messaging`), package `com.testlogon.android.feature.messaging`. The composer and send logic extend the screen and ViewModel introduced by AND-123, not a new screen.
- **Layering:** `feature-messaging` -> `core-network` (Retrofit service, `ApiResult<T>`), `core-model` (DTO/domain), `core-data` (Room cache + repository), `core-ui` (Compose components, theme). No backward dependencies.
- **Backend:** FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000` (plaintext HTTP, unreliable). OpenAPI at `/openapi.json`. Cookie-based auth: session cookies + `ui_csrf` cookie echoed as `X-CSRF-Token`; on `401` the OkHttp authenticator calls `POST /ui/session/refresh` once and retries. A persistent cookie jar is required (established by the core-network/auth tickets).
- **Web reference (CORRECTED):** `src/api/endpoints/messaging.ts` (the `sendTextMessage` call, not `conversations.ts`/`sendMessage`) and `src/api/types.ts` (`Message`, `SendTextMessageReq` — there is no `SendMessageRequest`). The wire request field is `text` (not `body`); the wire `Message`/`MessageOut` fields are `message_id`, `conversation_id`, `sender_id`, `created_at` (epoch integer), `text`, `kind`. The web client deserializes via `adaptMessage` in `src/api/endpoints/messagingAdapter.ts`. The Android DTOs in this ticket must mirror these real shapes.
- **Dependency AND-123** supplies: `MessagingViewModel`, `MessagingUiState`, the `LazyColumn` reverse-layout thread list, the `Message` domain model, the Room `MessageEntity`/`MessageDao`, and the Paging 3 history source. AND-124 adds the write path.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15, Room 2.6, Paging 3. minSdk 24 / target 35, JDK 17.

## 3. Functional Requirements

FR-1. The Thread screen renders a pinned bottom **composer**: a multiline `TextField` (Material 3 `OutlinedTextField`) plus a Send `IconButton`. The composer sits above the IME and respects `imePadding()` and navigation-bar insets.

FR-2. Send is enabled only when the trimmed draft is non-empty. Whitespace-only drafts are not sendable. Max length 4000 characters (client guard mirroring the backend; over-limit input is rejected with an inline counter/error rather than truncated silently).

FR-3. On Send tap: the draft is cleared from the input immediately, a new optimistic message row is inserted at the bottom of the thread with `status = SENDING`, attributed to the current user (from `GET /ui/me`), with a client-generated `clientId` (UUID) and a local timestamp.

FR-4. The optimistic row is visually distinct while `SENDING` (e.g., reduced alpha or a small progress/clock glyph). It is **not** removed on success; instead it is reconciled in place to the server message (status `SENT`).

FR-5. On send success, the row adopts the server `message_id`, `created_at`, and any server-normalized `text`. Reconciliation keys on the locally-held `clientId` (a client-only correlation id — see CORRECTION below; the server does NOT echo it) so the row does not duplicate against its own outbox entry; cross-checking against history refresh / list poll (AND-123) must additionally dedupe by the server `message_id` because the server response is the only place the optimistic row learns its real id.

> CORRECTION (verified against OpenAPI `SendTextMessageIn` and `src/api/types.ts: SendTextMessageReq`): the send endpoint does **not** accept a `client_id`/`client_message_id` in the request, and `MessageOut`/`Message` does **not** return one. `clientId` therefore exists only on the device (outbox primary key + optimistic-row correlation). It is NOT a server idempotency key. This invalidates the original "server dedupes on client_id" premise throughout this spec; see §5, §7, §13 OQ-1 and §16.

FR-6. On send failure (network/timeout/non-2xx), the row transitions to `status = FAILED` and shows a retry control (tap row or an inline "Failed — Retry" affordance). The typed text is preserved in the failed row; retry re-issues the same `POST` (the body carries `text` only — there is no `client_id` to send) and returns the row to `SENDING`. The reused `clientId` keys the local outbox row only; it does NOT make the server request idempotent (see FR-7 and §7 for the duplicate-on-uncertain-failure risk this creates).

FR-7. Retry is bounded and **manual** — there is no automatic retry of message sends in this ticket (sends are non-idempotent at the HTTP layer — CORRECTED: there is no server-side idempotency key, so a retry after an *uncertain* failure, e.g. timeout where the server may have actually persisted the message, can create a duplicate; auto-retry is therefore explicitly out of scope and even manual retry-after-timeout carries duplicate risk — see §7 and OQ-1). Multiple failed messages each retry independently.

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
// NOTE: domain field names below are the Android team's choice; the mapping to the
// real wire shape (verified) is: id <- message_id, authorId <- sender_id,
// body <- text, createdAt <- created_at (epoch INTEGER, not ISO string).
data class Message(
    val id: String?,          // null until acked; wire `message_id`
    val clientId: String,     // stable, client-generated; LOCAL-ONLY (never sent/echoed)
    val conversationId: String,
    val authorId: String,     // wire `sender_id`
    val body: String,         // wire `text`
    val createdAt: Instant,   // local placeholder until acked; wire `created_at` = epoch millis/seconds INTEGER
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
Implementation maps `SendTextMessageRequest(text = body)` (CORRECTED: request field is `text`, and there is NO `client_id` in the request — `clientId` is passed through the repo only to re-key the resulting domain `Message` locally) -> service call -> `MessageDto.toDomain(clientId = clientId, sendStatus = SENT)`, wrapped via the shared `apiCall { }` helper that converts exceptions/non-2xx into `ApiResult.Error` and decodes the FastAPI `detail` shape.

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

**Endpoint (CORRECTED):** `POST /messaging/conversations/{conversation_id}/messages` (path param `conversation_id` = `conversationId`). Op `send_text_message`, request schema `SendTextMessageIn`, success `200:MessageOut`. **The endpoint is NOT idempotent** — verified against `SendTextMessageIn` (no `client_id`/`client_message_id`/idempotency field) and the messages endpoint params (no `Idempotency-Key` header; contrast the *drafts* endpoint `POST .../drafts`, which DOES take an `Idempotency-Key` param). A repeated POST creates a new message server-side. (Original spec claimed dedup via `client_id`; this is false — see OQ-1 fallback, now the mandated design.)

**Request headers:** session cookies (auto via cookie jar) + `X-CSRF-Token: <ui_csrf>` (auto via the CSRF interceptor from core-network). `Content-Type: application/json`.

**Request body (CORRECTED):** the text field is `text` (string, `minLength 1`, `maxLength 4000`), not `body`; no `client_id`. Other `SendTextMessageIn` fields (`reply_to_message_id`, `parent_message_id`, `thread_id`, `view_once`, `expires_in_seconds`, `lock_price_cents`, `tip_amount_cents`, etc.) are optional and out of scope for this ticket.
```json
{ "text": "hello world" }
```

**Success `200` response (`MessageOut`, CORRECTED — was `201` with wrong fields):** required fields are `conversation_id`, `message_id`, `sender_id`, `created_at`, `kind`; `text` is optional (present for text messages). `created_at` is an **integer epoch**, not an ISO-8601 string. There is no `id`, `author_id`, `body`, or `client_id`.
```json
{
  "message_id": "msg_01H...",
  "conversation_id": "conv_01H...",
  "sender_id": "usr_01H...",
  "kind": "text",
  "text": "hello world",
  "created_at": 1749132151004
}
```

**Moshi DTO + Retrofit:**
```kotlin
// CORRECTED DTOs to match SendTextMessageIn / MessageOut.
@JsonClass(generateAdapter = true)
data class SendTextMessageRequest(
    @Json(name = "text") val text: String,   // was `body`; no client_id field exists
)

@JsonClass(generateAdapter = true)
data class MessageDto(
    @Json(name = "message_id") val messageId: String,        // was `id`
    @Json(name = "conversation_id") val conversationId: String,
    @Json(name = "sender_id") val senderId: String,          // was `author_id`
    @Json(name = "kind") val kind: String,                   // required; "text" for this ticket
    @Json(name = "text") val text: String?,                  // was `body`; optional
    @Json(name = "created_at") val createdAt: Long,          // epoch INTEGER, not ISO string
)

interface ConversationApi {
    // CORRECTED path prefix `/messaging`
    @POST("messaging/conversations/{conversationId}/messages")
    suspend fun sendMessage(
        @Path("conversationId") conversationId: String,
        @Body request: SendTextMessageRequest,
    ): Response<MessageDto>
}
```
Note: the OpenAPI lists `authorization`, `X-SESSION-ID`, `X-API-Key` as accepted params on this endpoint, but the web client authenticates purely via session cookies + `X-CSRF-Token` (see §2, `src/api/client.ts`); the Android client mirrors the cookie-based path and does not set those headers.

**Error responses (CORRECTED to documented codes):** OpenAPI documents this endpoint's responses as `200:MessageOut; 400; 401; 403; 422:HTTPValidationError; 429`. FastAPI `detail` mapped by the shared decoder into `UiError`:
- `400` -> bad request; FAILED, non-retryable hint.
- `401` -> authenticator runs `POST /ui/session/refresh` once and retries; second `401` -> `UiError.Unauthorized` (send marked FAILED, surface re-auth). (`POST /ui/session/refresh` verified to exist, `200`, no request body.)
- `403` -> CSRF/permission; FAILED with non-retryable hint.
- `422` -> `HTTPValidationError`, shape `detail: [{loc, msg, type}]`; FAILED, show first `msg` (e.g., text too long / empty — server enforces `minLength 1`, `maxLength 4000` on `text`).
- `429` -> rate limited (the original spec omitted this documented code); FAILED, retryable after backoff hint.
- `404` -> NOT documented for this endpoint; if encountered treat as conversation-gone, FAILED with "conversation unavailable" (unverified — see §16 Open assumptions).
- `5xx` / timeout / `IOException` -> FAILED, retryable (but a timeout retry may duplicate — see §7/OQ-1).

`detail` may be `string | [{msg,...}] | {code,...}`; use the existing `DetailErrorAdapter`.

## 6. Data & State Management

- **Source of truth for confirmed messages:** Room `MessageEntity` (owned by AND-123) + Paging. Confirmed sends are inserted here on ack so they persist and dedupe against history refresh by server `message_id` (CORRECTED: not `clientId` — the server never returns `clientId`; the device stamps its own `clientId` onto the MessageEntity at reconcile time for outbox cleanup only).
- **Source of truth for unconfirmed messages:** `OutboxMessageEntity` (this ticket), keyed by `clientId`. Survives process death so a FAILED message and its text are recoverable after the app is killed.
- **Draft persistence:** the current `composer.draft` is held in `SavedStateHandle` (key `draft_<conversationId>`) so rotation/process recreation does not lose unsent typing.
- **Merge/dedup rule (CORRECTED):** render list = `history ∪ outbox`. Because the server does NOT echo `clientId`, the outbox row learns its server `message_id` only from its own POST response; on `ApiResult.Success` the code inserts the `MessageEntity` (carrying both `message_id` and the locally-attached `clientId`) and deletes the outbox row by `clientId` atomically. Dedup against history refresh / list poll (AND-123) is by server `message_id` (history wins). The original "dedup by clientId against history" only works for rows this device already reconciled (where we stamped clientId onto the MessageEntity); a message arriving purely via poll before our POST returns cannot be matched by clientId and must be deduped by `message_id` once our POST completes — accept a brief transient duplicate window, covered by a test.
- **Ordering:** rows ordered by `createdAt`; optimistic rows use local time and naturally sort to the bottom; on ack the server `created_at` replaces it (ordering may shift slightly — acceptable and tested).
- **Threading:** all DB writes on `Dispatchers.IO`; state exposed as `StateFlow<MessagingUiState>` via `stateIn`.

## 7. Error Handling & Resilience

- **Timeouts:** OkHttp call timeout ~20s (per project dev-host policy). A send exceeding it becomes FAILED, not hung; the UI never blocks on the request.
- **No auto-retry for sends:** sends are user-initiated retries only (FR-7). CORRECTED: there is **no** `client_id` idempotency, so a manual retry is NOT guaranteed safe — if the first attempt actually reached the server (e.g. response lost to a timeout) a retry produces a duplicate server message. Mitigations available with the real contract: (a) keep retry strictly manual so the user owns the duplicate-vs-resend decision; (b) only auto-mark-FAILED on *connect/transport* errors where we are confident the request never landed, and surface uncertain (post-send timeout) failures with explicit "may have sent — retry?" wording; (c) optional best-effort client-side dedup of consecutive identical `text` from the same sender within a short window when reconciling against poll/history. The duplicate risk MUST be resolved/accepted before merge (OQ-1).
- **Offline:** if no connectivity, the optimistic row goes straight to FAILED with a "No connection — Retry" hint; nothing is silently dropped.
- **Refresh-on-401:** handled centrally by the OkHttp authenticator; the send coroutine sees only the post-refresh outcome. A double-401 marks FAILED.
- **Concurrent sends:** independent coroutines per `clientId`; one failure never affects another row.
- **Process death mid-send:** outbox row remains `SENDING`; on next screen load any `SENDING` row older than the timeout window is normalized to `FAILED` (its outcome is unknown) so the user can retry. CORRECTED: retry does NOT reuse a server idempotency key (none exists), so a retry of a send that actually succeeded before process death WILL duplicate. Prefer reconciling such an orphaned `SENDING`/`FAILED` row against a fresh history fetch (match by `text`+`sender_id`+approximate `created_at`) before offering retry, to reduce accidental duplicates.

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
  - Merge/dedup: once a send is reconciled, the inserted history row (matched by server `message_id`) removes the outbox row (no duplicate); a poll-delivered row with the same `message_id` does not double-render.
- **Repository tests:** MockWebServer returns 200/422/429/500/timeout; assert correct `ApiResult`, request body JSON contains exactly `{"text": ...}` (CORRECTED: field is `text`, and NO `client_id` is sent), correct path `/messaging/conversations/{id}/messages`, and `X-CSRF-Token` header presence.
- **DAO tests:** Room in-memory — outbox upsert/delete/observe; `SENDING` normalization to `FAILED` on reload.
- **Compose UI tests:** typing enables Send; tap shows the sending row; failed row shows Retry with correct content descriptions; accessibility assertions on labels.
- All async tests are deterministic (`runTest`, injected `TestDispatcher`); MockWebServer for network; no calls to the live dev host in CI.

## 12. Dependencies & Sequencing

- **Depends on AND-123** (Thread/message list screen): provides the screen scaffold, `MessagingViewModel` base, `Message` domain model, Room `MessageEntity`/`MessageDao`, and the paged history flow this ticket merges with the outbox. Must merge after AND-123.
- **Transitive:** AND-120 (conversation/messaging foundation, via AND-123) and the core-network auth/CSRF/cookie-jar tickets (session, refresh authenticator, CSRF interceptor) must already exist.
- **Blocks:** none recorded in the source bullets. Later messaging features (e.g., attachments, edit/delete, read receipts) build on this composer + outbox but are not listed as dependents here.

## 13. Risks & Open Questions

- **OQ-1 (RESOLVED — answer: NO):** `POST /messaging/conversations/{conversation_id}/messages` does **not** accept or dedupe on `client_id` (verified: `SendTextMessageIn` has no such field; no `Idempotency-Key` param; `MessageOut` does not return it; web `SendTextMessageReq` has no client id). Idempotent retry is therefore **unsafe** (duplicate risk on uncertain failure). Mandated design (the former "fallback"): send `text` only, key the outbox locally by `clientId`, reconcile by server `message_id`, use the `(sender_id, text, created_at)` heuristic for orphan reconciliation, keep retry manual, and word post-timeout retries as uncertain. **Resolved; reflect in code before merge.**
- **OQ-2 (RESOLVED):** Success status is `200` (`200:MessageOut` in OpenAPI), not `201`. Still handle via `Response.isSuccessful` for safety.
- **OQ-3 (RESOLVED):** `created_at` is an **integer epoch**, NOT an ISO-8601 string (verified `MessageOut.created_at: integer`; web `Message.created_at: number`). Parse as a Long and convert to `Instant`; no ISO string adapter is needed for this field. Open: ms-vs-seconds precision is not pinned by the schema (`integer` only) — treat defensively (see §16 Open assumptions).
- **Risk:** ordering jitter when local time differs from server time at reconciliation. Mitigation: replace local time with server time on ack; accept minor reorder; covered by a test.
- **Risk:** unreliable dev host produces frequent FAILED states during manual QA. Mitigation: clear FAILED+Retry UX; MockWebServer for deterministic tests.

## 14. Acceptance Criteria

AC-1. Typing non-empty text enables Send; tapping Send clears the input and immediately shows the message in the thread as a `SENDING` optimistic row attributed to the current user. *(source: "appears optimistically")*

AC-2. On server ack the optimistic row reconciles in place to a confirmed message (server `message_id`, server `created_at`, `SENT` status) with **no duplicate** row. *(source: "reconciles on ack")* — verified by automated ViewModel test.

AC-3. On send failure the row shows a `FAILED` state with a Retry control; the typed text is preserved; Retry re-sends the same `text` (no `client_id` is sent — none exists) and the row returns to `SENDING`. (Duplicate risk on retry-after-uncertain-failure is acknowledged per OQ-1; retry stays manual.)

AC-4. Blank/whitespace-only drafts cannot be sent; over-limit (>4000 chars) input is blocked with an inline indicator.

AC-5. The optimistic insert scrolls the thread to the newest message; the composer stays above the IME with correct insets.

AC-6. A FAILED/pending message survives process death (persisted in the outbox) and remains retryable. CORRECTED: because there is no server idempotency key, "retry does not create a duplicate" cannot be guaranteed for a send that actually succeeded; the AC is met by (a) persistence + retryability and (b) the orphan-reconciliation-before-retry mitigation (§7) plus local dedup-by-`message_id`.

AC-7. Automated tests cover optimistic insert, ack reconciliation, failure+retry, dedup-by-`message_id` (CORRECTED from `client_id`, which the server does not echo), and blank/over-limit guards. *(source: "tested")*

## 15. Definition of Done

- `MessageComposer`, `ComposerState`, outbox (`OutboxMessageEntity`/`OutboxDao`), repository `sendMessage`, and ViewModel `onSendClick`/`onRetry` implemented in `:feature:messaging` under `com.testlogon.android.feature.messaging`, with the Retrofit `ConversationApi.sendMessage` and Moshi DTOs in `:core:network`/`:core:model`.
- Optimistic send + ack reconciliation + manual retry all functional against MockWebServer and manually verified against the dev host.
- All §11 unit, repository, DAO, and Compose UI tests pass in CI; no live-host calls in CI.
- No message bodies in logs or telemetry; `X-CSRF-Token` and cookie-jar paths verified; Detekt/ktlint clean; KSP builds.
- Strings externalized; accessibility content descriptions and state descriptions present; touch targets >= 48dp.
- All ACs in §14 demonstrably met; OQ-1 confirmed (server has **no** `client_id` dedupe — verified) and the no-idempotency-key design + duplicate-risk mitigations reflected in code before merge.
- PR targets the `android-port` branch and references AND-124 and AND-123.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **Send endpoint path is `POST /messaging/conversations/{conversation_id}/messages`.** VERDICT: Corrected (spec said `POST /conversations/{id}/messages`). SOURCE: OpenAPI `POST /messaging/conversations/{conversation_id}/messages` (op `send_text_message`); frontend `src/api/endpoints/messaging.ts: sendTextMessage` (calls `/messaging/conversations/${conversationId}/messages`).
2. **HTTP method is POST.** VERDICT: Verified. SOURCE: OpenAPI `POST /messaging/conversations/{conversation_id}/messages`.
3. **Request body text field is `text` (not `body`), `minLength 1`, `maxLength 4000`.** VERDICT: Corrected. SOURCE: OpenAPI schema `SendTextMessageIn.text` (string, minLength 1, maxLength 4000); `src/api/types.ts: SendTextMessageReq` (`text?: string`).
4. **Request carries NO `client_id`/idempotency key.** VERDICT: Corrected (spec claimed server dedupes on `client_id`). SOURCE: OpenAPI `SendTextMessageIn` (no client_id/client_message_id property; no `Idempotency-Key` in endpoint params — contrast `POST /messaging/conversations/{conversation_id}/drafts` which DOES list `Idempotency-Key`); `src/api/types.ts: SendTextMessageReq` (no client id field).
5. **Success status is `200` with schema `MessageOut` (not `201`).** VERDICT: Corrected. SOURCE: OpenAPI `POST .../messages` resp `200:MessageOut`.
6. **`MessageOut` identity/content fields are `message_id`, `conversation_id`, `sender_id`, `created_at`, `kind` (required) + optional `text` — NOT `id`/`author_id`/`body`/`client_id`.** VERDICT: Corrected. SOURCE: OpenAPI `components.schemas.MessageOut` (required: conversation_id, message_id, sender_id, created_at, kind); `src/api/types.ts: Message` (message_id, sender_id, created_at, text, kind); `src/api/endpoints/messagingAdapter.ts: adaptMessage` (maps message_id/sender_id/text).
7. **`created_at` is an integer epoch, not an ISO-8601 string.** VERDICT: Corrected. SOURCE: OpenAPI `MessageOut.created_at` (`type: integer`); `src/api/types.ts: Message.created_at` (`number`).
8. **Documented error codes for this endpoint: 400, 401, 403, 422 (HTTPValidationError), 429.** VERDICT: Corrected (spec listed 404 and generic 5xx as endpoint-documented; 429 was missing; 404 is not documented). SOURCE: OpenAPI `POST .../messages` resp `200:MessageOut;422:HTTPValidationError;400;401;403;429`.
9. **422 validation error shape is `detail: [{loc, msg, type}]`.** VERDICT: Verified. SOURCE: OpenAPI `components.schemas.HTTPValidationError` / `ValidationError`.
10. **Auth via session cookies; CSRF via `ui_csrf` cookie echoed as `X-CSRF-Token`.** VERDICT: Verified. SOURCE: `src/api/client.ts` (`getCookie("ui_csrf")` -> `headers.set("X-CSRF-Token", csrf)`, `credentials: "include"`).
11. **On 401 the client refreshes once via `POST /ui/session/refresh` then retries; a second 401 is terminal.** VERDICT: Verified. SOURCE: `src/api/client.ts` (`refreshSession()` -> `fetch(withApiBase("/ui/session/refresh"), { credentials: "include" })`, single-flight `refreshPromise`, retry then throw on retry 401); OpenAPI `POST /ui/session/refresh` (resp 200, no request body).
12. **Current user comes from `GET /ui/me`.** VERDICT: Verified (endpoint exists). SOURCE: OpenAPI `GET /ui/me` (op `ui_me`). NOTE: response schema is untyped in the index (`resp=200:`); exact field for the user id on Android is an assumption — see Open assumptions.
13. **Web reference lives in `src/api/endpoints/messaging.ts` (`sendTextMessage`) and `src/api/types.ts` (`Message`, `SendTextMessageReq`).** VERDICT: Corrected (spec cited `endpoints/conversations.ts`, `sendMessage`, `SendMessageRequest`). SOURCE: `src/api/endpoints/messaging.ts`; `src/api/types.ts` (no `conversations.ts` / `SendMessageRequest` exist).
14. **`kind: "text"` discriminator on messages.** VERDICT: Verified. SOURCE: `src/api/types.ts: Message.kind` enum (includes `"text"`); OpenAPI `MessageOut.kind` (required).
15. **Compose Material 3 composer, `imePadding()`/insets, Hilt/Room/Paging stack.** VERDICT: Unverified-assumption (framework/library choices, not contract claims). SOURCE: framework ref — Android `WindowInsets`/`Modifier.imePadding` (developer.android.com/develop/ui/compose/layouts/insets), Room/Paging/Compose docs; consistent with the project stack stated in §2.

### Corrections made
- Endpoint path corrected to `POST /messaging/conversations/{conversation_id}/messages` (added `/messaging` prefix) in §1, §2, §5, §11, DTO `@POST` annotation.
- Request field corrected `body` -> `text` (minLength 1, maxLength 4000); removed `client_id` from the request entirely (§4.4, §5, §11).
- Removed the false "server dedupes/idempotent via `client_id`" premise; `clientId` re-scoped to a device-local outbox key + correlation id; reconciliation/dedup re-keyed to server `message_id`; duplicate-on-uncertain-retry risk surfaced (§1, §3 FR-5/FR-6/FR-7, §6, §7, §13 OQ-1, §14 AC-3/AC-6/AC-7, §15).
- Response/DTO corrected: `id`->`message_id`, `author_id`->`sender_id`, `body`->`text`, added required `kind`, `created_at` String/ISO -> Long/epoch integer; success code `201`->`200` (§4.1 note, §5).
- Error codes corrected to documented set (400/401/403/422/429); flagged 404 as undocumented; added 429 (§5).
- Frontend reference pointers corrected to `messaging.ts`/`sendTextMessage`/`SendTextMessageReq` (§2).
- §13 OQ-1/OQ-2/OQ-3 marked RESOLVED with verified answers.

### Open assumptions
- **`created_at` precision (ms vs seconds).** The schema says only `integer`; the example in §5 assumes ms. Parse defensively (detect magnitude) until confirmed against a live response. WHY: not pinned by OpenAPI or web types.
- **`GET /ui/me` response field for the current user id.** The index shows `resp=200:` with no named schema, so the exact JSON field used to attribute the optimistic row's author is unverified. WHY: untyped response in the provided sources.
- **404 semantics for a missing/inaccessible conversation on the send path.** 404 is not in the documented response set; handling is a defensive assumption. WHY: not documented in OpenAPI.
- **Orphan-reconciliation heuristic `(sender_id, text, created_at)`** to mitigate duplicate sends after uncertain failure/process death. WHY: there is no server idempotency mechanism to verify against; this is a client-side design decision, not a contract.
- **Compose/insets/Hilt/Room/Paging implementation details** are framework choices (see citation 15), not verifiable against backend/web sources.

## 17. Test Plan

IDs `TC-AND-124-NN`. "Traces" links to §14 Acceptance Criteria. Unless a case is marked "PHYSICAL DEVICE", JVM/Robolectric and MockWebServer cases run locally and instrumented/Compose-UI cases run on the headless emulator AVD `test35` (API 35).

- **TC-AND-124-01 — Happy path: optimistic insert + draft clear.** Type: unit (ViewModel, Turbine + `runTest`/`TestDispatcher`). Target: JVM unit/Robolectric. Preconditions: ViewModel with a fake repo that suspends the send; composer draft = "hello". Steps: call `onSendClick()`. Expected: a new row with `sendStatus=SENDING`, `clientId` non-null, `authorId` = current user, local `createdAt`, body "hello"; composer draft cleared and `isSendEnabled=false`; scroll-to-bottom signal emitted. Traces: AC-1, AC-5.
- **TC-AND-124-02 — Ack reconciliation, no duplicate.** Type: unit (ViewModel). Target: JVM unit. Preconditions: fake repo returns `ApiResult.Success(Message(message_id="msg_1", text="hello", created_at=<epoch>))`. Steps: `onSendClick()` then let the send complete. Expected: the SENDING row reconciles in place -> `id=msg_1`, server `createdAt`, `sendStatus=SENT`; outbox entry for that `clientId` deleted; exactly ONE row for the message. Traces: AC-2, AC-7.
- **TC-AND-124-03 — Send failure -> FAILED + retry re-sends `text`.** Type: unit (ViewModel). Target: JVM unit. Preconditions: fake repo returns `ApiResult.Error` (IOException) on first call, `Success` on second. Steps: `onSendClick()`; assert FAILED + text preserved; call `onRetry(clientId)`. Expected: row returns to SENDING then SENT; the retried request body is `{"text":"hello"}` with NO `client_id`; `attemptCount` incremented. Traces: AC-3, AC-7.
- **TC-AND-124-04 — Validation guards: blank/whitespace/over-limit.** Type: unit (ViewModel). Target: JVM unit. Preconditions: fresh composer. Steps: set draft "   " (assert not sendable), "" (not sendable), "a"*4001 (over limit). Expected: `isSendEnabled=false` for blank/whitespace; `overLimit=true` and send blocked at >4000 chars; valid 1..4000 enables send. Traces: AC-4, AC-7.
- **TC-AND-124-05 — Contract: request shape, path, CSRF header (200).** Type: contract/MockWebServer. Target: JVM unit (MockWebServer). Preconditions: Retrofit `ConversationApi` wired with the CSRF interceptor + a cookie jar seeded with `ui_csrf`. MockWebServer enqueues `200` with a valid `MessageOut` (`message_id`,`conversation_id`,`sender_id`,`kind:"text"`,`text`,`created_at` integer). Steps: call `repo.sendMessage(...)`. Expected: recorded request method POST, path `/messaging/conversations/{id}/messages`, JSON body exactly `{"text":"hello"}` (no `client_id`), header `X-CSRF-Token` present and equal to the `ui_csrf` cookie; parsed `ApiResult.Success` with `created_at` decoded as Long. Traces: AC-2, AC-7.
- **TC-AND-124-06 — Contract: 422 validation error mapping.** Type: contract/MockWebServer. Target: JVM unit. Preconditions: MockWebServer enqueues `422` with `{"detail":[{"loc":["body","text"],"msg":"ensure this value has at most 4000 characters","type":"value_error"}]}`. Steps: call `repo.sendMessage(...)`. Expected: `ApiResult.Error` mapped via `DetailErrorAdapter`; first `msg` surfaced; row -> FAILED, non-retryable presentation for validation. Traces: AC-3.
- **TC-AND-124-07 — Contract: 429 rate-limit + 401-refresh path.** Type: contract/MockWebServer. Target: JVM unit. Preconditions: (a) enqueue `429` -> assert FAILED-retryable; (b) enqueue `401`, then a `200` for `/ui/session/refresh`, then `200` `MessageOut` -> assert single refresh + successful retry; (c) enqueue `401` twice -> assert `UiError.Unauthorized`, FAILED. Steps: drive each sub-scenario. Expected: behavior matches §5/§7; refresh called at most once per 401. Traces: AC-3.
- **TC-AND-124-08 — DAO: outbox upsert/delete/observe + SENDING normalization.** Type: integration (Room in-memory). Target: JVM unit/Robolectric. Preconditions: in-memory Room DB. Steps: upsert a SENDING outbox row; observe; delete by `clientId`; insert a stale SENDING row and reload screen logic. Expected: observe emits inserts; delete removes; on reload a SENDING row older than the timeout window is normalized to FAILED. Traces: AC-6.
- **TC-AND-124-09 — Process-death survival + orphan reconciliation.** Type: integration (Room + ViewModel recreate). Target: JVM unit/Robolectric. Preconditions: outbox has a FAILED row persisted; history fetch returns a message matching `(sender_id, text, ~created_at)`. Steps: recreate ViewModel; load history. Expected: the persisted row is still present and retryable; if a matching server `message_id` is found via history, the orphan reconciles (dedupes) instead of offering a duplicate-creating retry. Traces: AC-6.
- **TC-AND-124-10 — Concurrent independent sends.** Type: unit (ViewModel). Target: JVM unit. Preconditions: fake repo fails clientId A, succeeds clientId B. Steps: fire two `onSendClick()` rapidly. Expected: two independent rows; A -> FAILED, B -> SENT; one outcome does not affect the other. Traces: AC-3.
- **TC-AND-124-11 — Compose-UI: enable Send, sending row, failed row + a11y.** Type: Compose-UI. Target: headless emulator AVD `test35`. Preconditions: Compose test rule hosts the Thread screen with a fake ViewModel. Steps: type text (assert Send enabled), tap Send (assert SENDING row visible), drive a FAILED state (assert Retry control). Expected: Send `IconButton` exposes `contentDescription` = cd_send_message and announces disabled state; sending row exposes `stateDescription="Sending"`; retry control exposes `contentDescription="Retry sending message"` and `stateDescription="Failed to send"`; touch targets >= 48dp. Traces: AC-1, AC-3, AC-4 (a11y/accessibility checks).
- **TC-AND-124-12 — Compose-UI: IME insets + scroll-to-bottom.** Type: Compose-UI/instrumented. Target: headless emulator AVD `test35`. Preconditions: Thread screen with a long history. Steps: focus the composer to raise the IME; send a message. Expected: composer stays above the IME (`imePadding`/navigation-bar insets honored, not occluded); list scrolls to the newest row on insert. Traces: AC-5.
- **TC-AND-124-13 — Offline / flaky dev-host path.** Type: instrumented/e2e. Target: PHYSICAL DEVICE (Samsung Galaxy A15 5G, SM-A156U, API 34/arm64) — MUST run on the physical device to exercise real radio/airplane-mode and real OkHttp timeout behavior against the unreliable plaintext dev host. Preconditions: app pointed at the dev host; toggle airplane mode / network loss. Steps: send with no connectivity; then with the dev host timing out (~20s call timeout). Expected: optimistic row goes to FAILED with a "No connection — Retry" / uncertain-timeout hint (no hang, no silent drop); on reconnect, manual Retry succeeds; UI never blocks. Traces: AC-3, AC-6.
- **TC-AND-124-14 — Security: no body/cookie leakage in logs; CSRF/cookie required.** Type: instrumented + manual. Target: PHYSICAL DEVICE for the logcat capture (real release-style logging on API 34); MockWebServer sub-assertion may run on JVM. Preconditions: release-style logging config (interceptor `BASIC`). Steps: send a message; capture logcat/telemetry; inspect outbound request for `X-CSRF-Token` + session cookie. Expected: message `text` and raw cookies never appear in logcat/telemetry (only `clientId`); the send carries `X-CSRF-Token` and session cookie; a request stripped of CSRF/cookie is rejected (403/401) and surfaces FAILED. Traces: AC-3 (security/permission).

### Coverage matrix
- AC-1 (type enables Send; tap clears input + shows SENDING optimistic row): TC-01, TC-11.
- AC-2 (ack reconciliation in place, no duplicate): TC-02, TC-05.
- AC-3 (FAILED + Retry, text preserved, retry re-sends): TC-03, TC-06, TC-07, TC-10, TC-11, TC-13, TC-14.
- AC-4 (blank/whitespace/over-limit blocked): TC-04, TC-11.
- AC-5 (scroll-to-bottom; composer above IME with insets): TC-01, TC-12.
- AC-6 (survives process death; retryable; dedupe mitigations): TC-08, TC-09, TC-13.
- AC-7 (automated coverage of insert/reconcile/failure+retry/dedup-by-`message_id`/guards): TC-02, TC-03, TC-04, TC-05.
