---
id: AND-373
title: Ticket messages / reply
milestone: M8
epic: E48
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-372, AND-126]
blocks: []
---

# AND-373 — Ticket messages / reply

## 1. Overview & Goal

This ticket adds the ability for a **member** to post a message (a reply) into an
open ticket thread inside a space, and to see that reply render immediately in the
thread. AND-372 already delivers the read-only surfaces — the spaces list, the
ticket list inside a space, and the read-only ticket thread that renders the
existing message history. AND-126 already delivers the sealed `Message` domain
model and the loss-free mappers. AND-373 closes the loop on the thread: it makes
the thread **composable**, wiring a reply composer at the bottom of the ticket
thread screen to a `POST` send endpoint, applying optimistic insertion, and
reconciling the server-confirmed message back into the list.

Scope is intentionally narrow: **post messages on tickets, for members.** It is
text-reply only — rich media composition (image/video/voice/poll authoring) is
out of scope and remains a downstream concern; only `Message.Text` is
client-creatable here. The deliverable is a working composer + send pipeline:
ViewModel send action, repository send method, Retrofit endpoint, optimistic UI
state with pending/failed/sent lifecycle, retry-on-failure for the single send,
and exhaustive rendering of the newly posted message via the AND-126 model.

Goal: a member typing a reply in an open ticket thread and tapping send sees the
message appear instantly (optimistic), the request posts to the backend, and on
success the optimistic placeholder is replaced by the canonical server message —
proving the acceptance bar **"reply posts + renders."**

## 2. Context & References

- **Module placement.** UI and ViewModel live in `feature-tickets` under
  `com.testlogon.android.feature.tickets.thread`. The send call extends the
  ticket repository in `core-data`
  (`com.testlogon.android.core.data.tickets.TicketThreadRepository`). The
  Retrofit interface extends `TicketsApi` in `core-network`
  (`com.testlogon.android.core.network.tickets`). The reply uses the AND-126
  `Message.Text` domain type and `MessageMapper` for DTO↔domain conversion.
- **Stack.** Kotlin 2.0.21, Jetpack Compose + Material 3, single-Activity
  Navigation-Compose, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 + OkHttp 4.12 +
  Moshi 1.15, Paging 3 (thread paging owned by AND-372), Room 2.6 cache. minSdk
  24, compileSdk/targetSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- **Depends on AND-372** (ticket spaces + threads): provides the navigation route
  to the thread (`tickets/space/{spaceId}/ticket/{ticketId}`), the
  `TicketThreadViewModel` + `TicketThreadUiState`, the read-only thread
  `LazyColumn`, and the Paging source for historical messages. AND-373 augments,
  not replaces, these.
- **Depends on AND-126** (message domain model + mappers): provides sealed
  `Message`, `Message.Text`, `MessageMeta`, `MessageSender`, and
  `MessageMapper.toDomain/toDto`. The reply is constructed as `Message.Text` and
  rendered by the same exhaustive `when` the thread already uses.
- **Auth/session.** Cookie-based session (see project context). The send is a
  state-changing `POST`; it MUST carry the `ui_csrf` cookie echoed as the
  `X-CSRF-Token` header (the shared OkHttp CSRF interceptor handles this). On
  `401`, the client calls `POST /ui/session/refresh` once then retries the send
  exactly once (interceptor-driven, no double-post — see §7).
- **Backend.** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext, unreliable; ~20s timeouts). OpenAPI at `/openapi.json`. **[VERIFIED
  against `openapi.index.txt:577` and `src/api/endpoints/tickets.ts:162`]** the
  resolved endpoint is `POST /ticket-spaces/{space_id}/tickets/{ticket_id}/messages`
  (op `reply_space_ticket`), request schema `SpaceTicketMessageReq` = `{ "body":
  string }` only, response `200: SpaceTicketEnvelope` (the **whole** ticket, not a
  single message). Error bodies are **`ErrorEnvelope`** (`{ "error": { "code",
  "message", "details"? } }`) for 400/403/404/409 and **`HTTPValidationError`**
  (`{ "detail": [{loc,msg,type}] }`) for 422 — NOT a uniform FastAPI `detail`
  shape; the mapper must handle both (see §5, §7). **The POST is NOT idempotent**
  (no server idempotency key — see R2/§16), so it is excluded from the GET-only
  bounded backoff retry policy (§7).
- **"Members" gating.** Only a user who is a member of the space may post; this is
  enforced **server-side** (403). **[CORRECTED]** There is **no `can_post` field**
  on the ticket/thread response. Membership/role lives on the *space* as
  `space.members[].role` (`viewer | editor | owner`, see `SpaceTicket` /
  `TicketSpaceMember`), fetched via `GET /ticket-spaces/{space_id}`. The web client
  does **not** gate the composer client-side at all (it shows the reply box to any
  viewer and relies on the 403); the Android `canPost` gate is an Android UX
  enhancement derived from `space.members` (current user present with a writable
  role and ticket status ≠ terminal), and is advisory only — never the security
  boundary.

## 3. Functional Requirements

FR-1. The ticket thread screen renders a **reply composer** pinned to the bottom:
a multiline `TextField` (max ~5 visible lines, scrolls beyond), a send
`IconButton`, and an inline error/retry affordance for a failed send.

FR-2. The composer is **enabled only for members** with a writable role. **[CORRECTED:
no `can_post` flag exists]** `canPost` is derived client-side from the space
membership list (`GET /ticket-spaces/{space_id}` → `space.members[].role` ∈
{`editor`, `owner`}; `viewer` and non-members are read-only) plus ticket
`status` (terminal statuses `done` may render the composer disabled). This is an
Android UX affordance only; the server is the authority and a 403 is always
respected (the web client itself does no client-side gating). For non-members or
closed tickets, the composer is hidden (or shown disabled with an explanatory
caption); no send is attempted.

FR-3. The send button is enabled only when the trimmed input is non-empty and no
send is currently in flight for the same draft. Whitespace-only input does not
send. **[VERIFIED]** Input length is capped at **4000 chars** and must be **≥1**
(`SpaceTicketMessageReq.body` `minLength: 1, maxLength: 4000`); show a counter
near the limit. Client-trim then enforce 1..4000 to mirror the server 422.

FR-4. On send, the message is inserted **optimistically** at the bottom of the
thread as a `Message.Text` with a client-generated id and `SendState.Sending`,
and the composer input is cleared immediately.

FR-5. On `200` **[CORRECTED: the endpoint returns 200, not 201]**, the optimistic
message is **replaced** by the canonical server `Message` taken from
`ticket.messages.last()` of the returned `SpaceTicketEnvelope` (mapped via
AND-126), keyed by `message_id` so the list reorders/dedupes correctly (no
duplicate, no flicker).

FR-6. On send failure (network, timeout, non-401 error), the optimistic message
is marked `SendState.Failed` and shows a retry control; tapping retry re-attempts
the same payload (preserving the client id) without retyping.

FR-7. The newly posted/confirmed message **renders** in the thread using the
existing exhaustive `Message` renderer (AND-126/AND-372), proving acceptance.

FR-8. After a successful post, the thread scrolls to reveal the new message if the
user is at/near the bottom; if the user has scrolled up, a "new message" jump
affordance is shown instead of force-scrolling.

FR-9. **[CORRECTED: threaded replies are NOT supported by the backend.]** The
`SpaceTicketMessageReq` schema accepts **`body` only** — there is no
`reply_to_id`/`client_message_id` field, and `SpaceTicketMessage` (the persisted
shape) carries no parent pointer. Ticket threads are therefore **flat**. The
client MUST NOT send a `reply_to_id`; any "reply to" UX would have to be a local
quote prepended into `body`. `replyToId` is dropped from the wire contract for
this milestone (kept only as an optional local-quote affordance if AND-372
exposes one). See R4/§16.

FR-10. The composer draft survives configuration change (rotation) and process
death within the back stack via `SavedStateHandle`.

## 4. Technical Design

### 4.1 ViewModel (`feature-tickets`)

Extend the AND-372 `TicketThreadViewModel` with send capability and a per-message
send-state overlay. The thread list is the union of paged historical messages
(AND-372) and a small in-memory list of optimistic/pending sends.

```kotlin
package com.testlogon.android.feature.tickets.thread

enum class SendState { Sending, Sent, Failed }

@Immutable
data class PendingMessage(
    val clientId: String,          // UUID, also dedupe key
    val message: Message.Text,     // AND-126 domain type
    val state: SendState,
)

@Immutable
data class TicketThreadUiState(
    val ticketId: String,
    val canPost: Boolean,          // member + ticket open
    val composerText: String = "",
    val isSending: Boolean = false,
    val pending: List<PendingMessage> = emptyList(),
    val sendError: UiText? = null, // transient, e.g. snackbar
    // historical messages provided via Pager<Message> from AND-372
)

@HiltViewModel
class TicketThreadViewModel @Inject constructor(
    private val repo: TicketThreadRepository,
    private val savedState: SavedStateHandle,
) : ViewModel() {

    val uiState: StateFlow<TicketThreadUiState>

    fun onComposerChange(text: String)
    fun onSendClick()                       // sends current composerText
    fun onRetry(clientId: String)           // re-sends a Failed PendingMessage
    fun onDismissError()
}
```

`onSendClick()` flow:
1. Read + `trim()` the draft; bail if blank or `!canPost`.
2. Build a `PendingMessage(clientId = UUID.randomUUID().toString(), message =
   buildOptimisticText(...), state = Sending)`; emit it into `pending`; clear
   `composerText`.
3. `viewModelScope.launch { repo.postReply(spaceId, ticketId, draft, clientId)
   }` **[CORRECTED signature: no `replyToId` — flat threads; `clientId` is local
   only]**.
4. On `ApiResult.Success(serverMessage)`: remove the `PendingMessage` and let the
   paged thread show the confirmed message (invalidate the Paging source, or
   prepend the server message into a confirmed-tail buffer keyed by id so the
   thread updates without a full refetch).
5. On `ApiResult.Error`: set that `PendingMessage.state = Failed` and surface a
   non-blocking `sendError`.

`buildOptimisticText` constructs a `Message.Text` with `MessageMeta(id =
MessageId(clientId), conversationId = ticketId, sender = currentUser, sentAt =
Clock.System.now(), replyToId = replyToId)`.

### 4.2 Repository (`core-data`)

```kotlin
package com.testlogon.android.core.data.tickets

// [CORRECTED] backend takes only `body`; clientId is a LOCAL dedupe token (never
// sent — the backend has no idempotency/client-message-id field).
interface TicketThreadRepository {
    suspend fun postReply(
        spaceId: String,
        ticketId: String,
        body: String,
        clientId: String,       // LOCAL optimistic-dedupe key only; NOT sent to backend
    ): ApiResult<Message>
}

class DefaultTicketThreadRepository @Inject constructor(
    private val api: TicketsApi,
) : TicketThreadRepository {

    override suspend fun postReply(
        spaceId: String, ticketId: String, body: String, clientId: String,
    ): ApiResult<Message> = apiCall {
        // Request body is { "body": <text> } only (SpaceTicketMessageReq).
        val envelope = api.postTicketMessage(
            spaceId, ticketId,
            SpaceTicketMessageReq(body = body),
        )
        // [CORRECTED] response is the WHOLE ticket (SpaceTicketEnvelope), NOT a
        // single message. The freshly posted reply is the last item in
        // envelope.ticket.messages (server appends; no per-message echo).
        val newMsgDto = envelope.ticket.messages.last()
        MessageMapper.toDomain(newMsgDto)   // AND-126
    }
}
```

`apiCall { }` is the shared wrapper that maps exceptions/HTTP errors to
`ApiResult.Error`. **[CORRECTED]** the error body is **`ErrorEnvelope`**
(`{ error: { code, message, details? } }`) for 400/403/404/409 and
**`HTTPValidationError`** (`{ detail: [{loc,msg,type}] }`) for 422 — the mapper
must read `error.code`/`error.message` for the former and join `detail[].msg` for
the latter (no single uniform `detail` field). The send is **not** added to the
idempotent-GET retry set.

### 4.3 Composer UI (`feature-tickets`)

```kotlin
@Composable
fun ReplyComposer(
    text: String,
    isSending: Boolean,
    enabled: Boolean,
    onTextChange: (String) -> Unit,
    onSend: () -> Unit,
    modifier: Modifier = Modifier,
)
```

Rendered as the trailing item of the thread `Scaffold`’s bottom bar so it sits
above the IME (use `imePadding()` + `Modifier.navigationBarsPadding()`). The
thread `LazyColumn` (AND-372) appends `pending` messages after the paged items,
each `PendingMessage` rendered with a state chip: a small spinner for `Sending`, a
checkmark for `Sent` (briefly), and an error icon + "Tap to retry" for `Failed`.

### 4.4 Threading the optimistic + paged sources

The thread shows `pagedHistory ++ pendingNotYetConfirmed`. **[CORRECTED: the
backend does NOT accept or echo a `client_message_id`** — `SpaceTicketMessageReq`
takes `body` only and `SpaceTicketMessage` has no such field.] Dedupe therefore
**cannot** rely on a server-echoed token. The reliable strategy here is: the
success response returns the **whole updated ticket** (`ticket.messages`), so on
success remove the `PendingMessage` by its local `clientId` and adopt
`ticket.messages.last()` (the server-appended reply) as the canonical item. If a
separate refresh/poll could also surface the same message, dedupe by
`message_id`; as a last-resort tie-break use the `(sender_sub, body,
created_at±2s)` heuristic. R2 is **resolved**: no client-side idempotency token is
possible, so a manual retry of a silently-succeeded send risks a duplicate post —
mitigate by reconciling against the returned `ticket.messages` before re-enabling
retry.

## 5. API Contract

State-changing send. **[VERIFIED against `openapi.index.txt:577`,
`openapi.pretty.json` schemas `SpaceTicketMessageReq`/`SpaceTicketEnvelope`/
`SpaceTicketMessage`/`SpaceTicketOut`, and `src/api/endpoints/tickets.ts:162`.]**

**Resolved path (CORRECTED):**
`POST /ticket-spaces/{space_id}/tickets/{ticket_id}/messages`
(op `reply_space_ticket`). The earlier `/spaces/{spaceId}/...` and
`/tickets/{ticketId}/messages` candidates were both wrong for the space-scoped
member flow — `ticket-spaces` (hyphen) is the correct collection. Path params are
snake_case `space_id` / `ticket_id`.

Request headers: session cookies + `X-CSRF-Token: <ui_csrf>` (echoed from the
`ui_csrf` cookie; verified in `src/api/client.ts:168`), plus an `Authorization:
Bearer` header when an access token is present (verified `client.ts:158`),
`Content-Type: application/json`.

**Request body (CORRECTED — `body` only, `1..4000` chars):**

```json
{ "body": "Looks good, shipping it." }
```

There is **no** `message_type`, `content`, `reply_to_id`, or `client_message_id`
field. `SpaceTicketMessageReq` has exactly one required property `body`
(`minLength: 1`, `maxLength: 4000`).

**Success `200 OK` (CORRECTED — NOT 201, and NOT a single-message envelope):**
the response is the **entire ticket** (`SpaceTicketEnvelope` = `{ "ticket":
SpaceTicketOut }`). The newly posted reply is appended to `ticket.messages`. A
`SpaceTicketMessage` looks like:

```json
{
  "ticket": {
    "ticket_id": "tkt_42",
    "subject": "Login broken",
    "owner_sub": "usr_7",
    "status": "open",
    "assigned_to_sub": null,
    "created_at": 1717500000,
    "updated_at": 1717599999,
    "version": 5,
    "space_id": "spc_1",
    "messages": [
      {
        "message_id": "msg_01J8Z",
        "sender_sub": "usr_7",
        "sender_role": "owner",
        "body": "Looks good, shipping it.",
        "created_at": 1717599999,
        "email_alert_queued_for": []
      }
    ],
    "activity": []
  }
}
```

Note `created_at`/`updated_at` are **integer epoch seconds** (not ISO-8601
strings), and `SpaceTicketMessage` carries `sender_sub`/`sender_role` (no nested
sender object, no avatar, no `conversation_id`, no `reply_to_id`). The AND-126
mapper must adapt from this flat shape; if AND-126's `MessageDto` expects the
richer shape above, a dedicated `SpaceTicketMessage → Message.Text` mapping is
required (flag for AND-126 reconciliation — see §16 Open assumptions).

Retrofit (CORRECTED):

```kotlin
interface TicketsApi {
    @POST("ticket-spaces/{space_id}/tickets/{ticket_id}/messages")
    suspend fun postTicketMessage(
        @Path("space_id") spaceId: String,
        @Path("ticket_id") ticketId: String,
        @Body body: SpaceTicketMessageReq,
    ): SpaceTicketEnvelope
}

@JsonClass(generateAdapter = true)
data class SpaceTicketMessageReq(
    @Json(name = "body") val body: String,   // 1..4000 chars
)

@JsonClass(generateAdapter = true)
data class SpaceTicketEnvelope(@Json(name = "ticket") val ticket: SpaceTicketDto)

@JsonClass(generateAdapter = true)
data class SpaceTicketMessageDto(
    @Json(name = "message_id") val messageId: String,
    @Json(name = "sender_sub") val senderSub: String,
    @Json(name = "sender_role") val senderRole: String,
    @Json(name = "body") val body: String,
    @Json(name = "created_at") val createdAt: Long,   // epoch seconds
    @Json(name = "email_alert_queued_for") val emailAlertQueuedFor: List<String> = emptyList(),
)
```

**Error responses (CORRECTED).** For 400/403/404/409 the body is **`ErrorEnvelope`**
= `{ "error": { "code": string, "message": string, "details"?: object } }`
(schema `ErrorDetail`). For **422** the body is **`HTTPValidationError`** =
`{ "detail": [{ "loc", "msg", "type" }] }`. Meanings: `403` (not a member / wrong
role), `404` (space/ticket gone), `409` (version/state conflict, e.g. closed
ticket), `422` (empty/too-long `body`), `401` (session expired → refresh+retry
once). The mapper reads `error.message`/`error.code` (envelope) or joins
`detail[].msg` (validation) into a user-facing `UiText`. Note the web client
normalizer reads `body.detail` only (`client.ts:200/262`), so it would fall back
to generic text for an `ErrorEnvelope` body — the Android mapper should handle
**both** shapes explicitly (see §16).

## 6. Data & State Management

- **Source of truth.** **[CORRECTED/CLARIFIED]** The backend returns the full
  message list **embedded** in the ticket (`SpaceTicketOut.messages`) on every
  ticket GET and on every reply POST — there is **no separate paginated messages
  endpoint** (no per-message cursor; only the ticket-list endpoint is cursored).
  So the "historical thread" is whatever AND-372 holds for this ticket; if AND-372
  modeled it as a `Pager<Message>`, that paging is synthetic/local. The simplest
  correct model for AND-373: source of truth = the ticket's `messages` array, and
  on a successful reply, **replace** the in-memory ticket from the returned
  envelope (which already includes the new message). Optimistic sends = `pending:
  List<PendingMessage>` merged at render time and dropped once the returned
  `messages` contains the confirmed item. No new Room table is required.
- **Draft persistence.** `composerText` and the active `replyToId` are stored in
  `SavedStateHandle` so the draft survives rotation/process death (FR-10).
- **Stability.** `PendingMessage`, `Message.Text`, and `TicketThreadUiState` are
  `@Immutable`; lists are `List<T>`. `clientId` is the stable list key for pending
  items; `MessageId` for confirmed items.
- **Dedup contract.** **[CORRECTED: no `client_message_id` round-trips.]** On
  success, remove the in-flight `PendingMessage` by its local `clientId` at the
  moment the returned `ticket.messages` (which now contains the canonical reply)
  becomes visible, so the user never sees two copies. Canonical items are keyed by
  `message_id`.
- **No global state.** Nothing here writes to DataStore/prefs.

## 7. Error Handling & Resilience

- **Send POST is non-idempotent** → it is **excluded** from the bounded
  exponential backoff retry applied to idempotent GETs. A send is attempted once;
  failures surface as a `Failed` `PendingMessage` with explicit, user-driven
  retry (FR-6). Manual retry reuses the same `client_message_id` so a backend that
  honors it deduplicates if the original silently succeeded.
- **Timeout.** OkHttp call/read timeout ~20s (project standard for the unreliable
  dev host). On timeout → `Failed` (do not auto-resend, to avoid duplicate posts).
- **401 (session expired).** The shared auth interceptor performs `POST
  /ui/session/refresh` once and retries the original send once; if refresh fails,
  surface a re-auth prompt and mark the send `Failed`. Refresh+retry happens at
  the OkHttp layer, so the repository sees a single logical attempt.
- **403/409 (not a member / ticket closed).** No retry; mark `Failed` with a
  specific message ("You can no longer post to this ticket") and disable the
  composer (`canPost = false`).
- **422 (validation).** Map `detail` to an inline composer error; keep the draft
  so the user can fix it (re-populate `composerText` from the failed pending item
  on a 422 specifically).
- **Offline.** If no connectivity, fail fast to `Failed` with an offline message;
  the optimistic bubble persists with a retry control rather than being dropped.
- **Malformed success body.** If the `200` `SpaceTicketEnvelope` body fails
  mapping (or `ticket.messages` is empty), treat as a soft success: remove the
  pending bubble and trigger a ticket refresh (`GET /ticket-spaces/{space_id}/
  tickets/{ticket_id}`) to fetch the canonical state rather than crashing.

## 8. Security & Privacy

- **CSRF.** The send is state-changing and MUST include `X-CSRF-Token` from the
  `ui_csrf` cookie; the shared interceptor injects it. A missing token must not
  silently no-op — surface as a `Failed` send.
- **AuthZ.** Membership/post permission is enforced server-side; the client
  gating (`canPost`) is UX only and never the security boundary. A `403` is always
  respected even if the UI thought posting was allowed.
- **No credential exposure.** Auth rides on cookies via the persistent cookie jar;
  no token reaches the ViewModel/repository. The reply body is user content and
  MUST NOT be logged (see §10).
- **Transport.** Dev backend is plaintext HTTP (insecure, dev-only). Production
  cleartext config and the network-security policy are owned by the core-network
  setup ticket; this ticket adds no cleartext exception of its own.
- **Input.** The composer sends raw text; no client-side HTML/markdown execution.
  Rendering of the body uses the existing text renderer (no `WebView`, no eval).

## 9. Accessibility & i18n

- The send `IconButton` has a `contentDescription` (string resource
  `cd_send_reply`) and is excluded from focus order when disabled. The composer
  `TextField` has a labeled placeholder (`hint_write_reply`).
- Send-state chips expose state via `contentDescription` / `stateDescription`
  ("Sending", "Failed to send, double-tap to retry"); the retry target meets the
  48dp touch-target minimum.
- All user-visible strings (hint, send CD, error messages, "ticket closed",
  character-limit counter) live in `feature-tickets/src/main/res/values/strings.xml`
  with no hardcoded literals. Error `detail` text comes from the server and is
  shown verbatim where appropriate.
- The composer respects IME insets (`imePadding`) and is reachable with TalkBack;
  posting via the IME "Send" action is supported in addition to the button.
- Timestamps on the new message are formatted by the existing AND-372/AND-126
  locale-aware formatter; nothing is pre-formatted here.

## 10. Telemetry & Logging

- Emit analytics (via the shared analytics interface, fire-and-forget):
  `ticket_reply_send_attempt` {spaceId, ticketId, hasReplyTo}` on tap;
  `ticket_reply_send_success` {latencyMs}` and `ticket_reply_send_failure`
  {errorClass, httpStatus}` on completion. **No message body, sender PII, or
  media content** is included in any event.
- Logging: no request/response body logging of message content. The reply body
  MUST NOT appear in logcat. Generic failure breadcrumbs (status code, error
  class) only, gated so verbose logging is `BuildConfig.DEBUG`-only. Body
  redaction in the OkHttp logging interceptor is owned by core-network and assumed
  in effect for these paths.

## 11. Testing Strategy

JVM unit tests (`feature-tickets`, `core-data`) + Compose UI tests
(`feature-tickets` androidTest); network via MockWebServer / fake `TicketsApi`.

- **Repository (`DefaultTicketThreadRepositoryTest`).** `postReply` builds the
  correct `SpaceTicketMessageReq` (`{ "body": <text> }` only — no
  message_type/content/reply_to_id/client_message_id), POSTs to
  `ticket-spaces/{space_id}/tickets/{ticket_id}/messages`, and maps the `200`
  `SpaceTicketEnvelope` (taking `ticket.messages.last()`) to `Message.Text` via
  AND-126, returning `ApiResult.Success`. A `403`/`409` (`ErrorEnvelope`) / `422`
  (`HTTPValidationError`) / network failure returns `ApiResult.Error` with the
  correctly-mapped message. Asserts the POST is **not** retried on a 500/timeout.
- **ViewModel (`TicketThreadViewModelTest`, `kotlinx-coroutines-test`).**
  - `onSendClick` with blank/whitespace draft is a no-op.
  - `onSendClick` inserts a `Sending` `PendingMessage`, clears `composerText`, and
    on success removes the pending item (no duplicate vs the confirmed message).
  - On failure the pending item flips to `Failed`; `onRetry(clientId)` re-sends
    with the same `clientId` and on success clears it.
  - `canPost = false` blocks send entirely.
  - Draft survives via `SavedStateHandle` (re-create VM, draft restored).
- **Acceptance test — "reply posts + renders."** End-to-end against MockWebServer:
  type text, tap send, assert (1) optimistic bubble appears immediately, (2) the
  POST hits `ticket-spaces/{space_id}/tickets/{ticket_id}/messages` with body
  `{"body":"…"}` + `X-CSRF-Token` header, (3) the confirmed server message
  (from `ticket.messages`) renders in the thread and the optimistic placeholder is
  gone (no duplicate). This is the ticket's stated acceptance.
- **Compose UI (`ReplyComposerTest`).** Send disabled when empty/while sending;
  enabled with valid text; composer hidden/disabled when `canPost = false`; retry
  affordance shown on `Failed`; content descriptions present.
- **401 refresh path.** A first send returns `401`, interceptor calls
  `/ui/session/refresh`, retries once, succeeds; assert the message renders and
  only one logical send is observed by the ViewModel.
- **Dedupe.** When the returned envelope (or a later refresh) contains the
  confirmed message, assert it is not shown twice (dedupe by `message_id`; pending
  removed by local `clientId`).

## 12. Dependencies & Sequencing

- **Depends on AND-372** (ticket spaces + threads): requires the thread screen,
  navigation route (with `spaceId` + `ticketId`), the `TicketThreadViewModel`
  base, the read-only message `LazyColumn`, and the exhaustive `Message` renderer.
  AND-373 extends these in place. Must land after AND-372.
- **Depends on AND-126** (message domain model + mappers): requires
  `Message.Text`, `MessageMeta`, `MessageMapper.toDomain`/`toDto`, and
  `TextContentDto`. The reply is built and rendered through this model. Must land
  after AND-126.
- **Implicit:** the cookie-jar + CSRF + `session/refresh` auth interceptor from
  the core-network/auth tickets must be wired (assumed available from M1/M2). The
  analytics interface (shared) is assumed present; if not, telemetry degrades to
  no-op.
- **Sequence:** AND-372 → AND-126 → **AND-373**. No tickets in the provided
  backlog are listed as blocked by AND-373.

## 13. Risks & Open Questions

- **R1 — Exact endpoint path & method.** **RESOLVED.** It is `POST
  /ticket-spaces/{space_id}/tickets/{ticket_id}/messages`, status **200**
  (`openapi.index.txt:577`, `tickets.ts:162`). The `/spaces/...` and flat
  `/tickets/{id}/messages` candidates were both wrong for the space member flow
  (the flat one exists but is the admin/helpdesk ticket flow, schema
  `TicketMessageReq`).
- **R2 — `client_message_id` echo / idempotency support.** **RESOLVED (negative).**
  The backend accepts **`body` only** and persists no client token; there is no
  idempotency key. Dedupe uses the returned `ticket.messages` + local `clientId`
  (§4.4). Known residual risk: a manual retry of a silently-succeeded send can
  duplicate — accepted, mitigated by reconciling against returned messages.
- **R3 — Membership / post-permission field.** **RESOLVED.** No `can_post`/
  `is_member` field exists. Membership is `space.members[].role`
  (`viewer|editor|owner`) from `GET /ticket-spaces/{space_id}`; the server
  enforces via 403. Client `canPost` derived from role + ticket `status`, advisory
  only.
- **R4 — Reply-to threading.** **RESOLVED (negative).** Threads are **flat** — no
  `reply_to_id` in request or stored message. FR-9 reduced to an optional
  local-quote-into-`body` affordance.
- **R5 — Composer / Paging interaction.** **DOWNGRADED.** There is no real message
  pagination (messages are embedded in the ticket; §6). Merge the in-memory
  pending list with the ticket's `messages` array; on success replace from the
  returned envelope. Cover with the dedupe test.
- **R6 — Body length / content limits.** **RESOLVED.** `body` is required,
  `minLength 1`, `maxLength 4000` (`SpaceTicketMessageReq`). 422 fires on empty or
  >4000 chars.

## 14. Acceptance Criteria

1. A member viewing an open ticket thread sees a reply composer pinned to the
   bottom; a non-member or closed ticket shows no enabled composer (`canPost`
   gating, enforced server-side regardless).
2. Typing non-empty text and tapping send (or IME Send) **posts** a `text` message
   to the ticket messages endpoint with the correct JSON body and
   `X-CSRF-Token` header.
3. The reply is inserted optimistically as `Message.Text` and, on success, the
   confirmed server message **renders** in the thread via the AND-126 model with
   no duplicate and no placeholder left behind — satisfying "reply posts +
   renders."
4. A failed send marks the message `Failed` with a working retry that re-posts the
   same `body` (reusing the local `clientId` for UI identity — **no**
   `client_message_id` is sent, since the backend has none); whitespace-only input
   never sends; the send button is disabled while a send is in flight.
5. A `401` triggers exactly one `/ui/session/refresh` + retry; `403/409/422` map
   to specific user-facing errors and are not auto-retried; the non-idempotent
   send is excluded from GET backoff retry.
6. The composer draft survives rotation/process death via `SavedStateHandle`.
7. No message body or sender PII is logged or sent in analytics; all user-visible
   strings are in `strings.xml`; send control has a content description.
8. Repository, ViewModel, Compose-composer, the end-to-end "posts + renders"
   acceptance test, the 401-refresh test, and the dedupe test pass in CI.

## 15. Definition of Done

- Code merged to `android-port`: `ReplyComposer` + thread send wiring in
  `feature-tickets` (`com.testlogon.android.feature.tickets.thread`),
  `TicketThreadRepository.postReply` in `core-data`
  (`com.testlogon.android.core.data.tickets`), and `TicketsApi.postTicketMessage`
  + `SpaceTicketMessageReq`/`SpaceTicketEnvelope`/`SpaceTicketMessageDto` in
  `core-network` (`com.testlogon.android.core.network.tickets`).
- Optimistic send lifecycle (Sending → Sent/Failed), retry with stable local
  `clientId`, member/`canPost` gating (role from `space.members`), and
  `SavedStateHandle` draft persistence implemented per §3–§6.
- Send is non-idempotent and excluded from GET backoff retry; 401 refresh+retry,
  CSRF header, and dual error-shape mapping (`ErrorEnvelope` + 422
  `HTTPValidationError`) verified.
- `:feature-tickets:test`, `:feature-tickets:connectedCheck` (or Robolectric),
  and `:core-data:test` green on JDK 17; no new lint/detekt violations; no message
  content logged.
- Open questions R1–R6 are **resolved** against `/openapi.json` and the web
  reference (see §16): path `POST /ticket-spaces/{space_id}/tickets/{ticket_id}/
  messages` @ 200, request `{ "body" }` only, no client/idempotency token, no
  `can_post` field (role from `space.members`), flat threads, body 1..4000. Any
  remaining residual (duplicate-on-retry) is accepted and documented.
- Acceptance test asserting "reply posts + renders" passes; spec reviewed and the
  thread is now writable for members.

## 16. Citations & Assumption Audit

Each key technical claim with VERDICT (Verified / Corrected / Unverified-assumption)
and an exact SOURCE pointer.

1. **Endpoint path & method for posting a member reply.** Claim (original):
   `POST /spaces/{spaceId}/tickets/{ticketId}/messages` or
   `/tickets/{ticketId}/messages`. **VERDICT: Corrected** →
   `POST /ticket-spaces/{space_id}/tickets/{ticket_id}/messages`.
   SOURCE: OpenAPI `POST /ticket-spaces/{space_id}/tickets/{ticket_id}/messages`
   (op `reply_space_ticket`, `openapi.index.txt:577`); `src/api/endpoints/tickets.ts:162`
   (`addSpaceTicketMessage`).
2. **Success status code.** Claim: `201 Created` (or `200`).
   **VERDICT: Corrected** → **`200`** only. SOURCE: `openapi.index.txt:577`
   (`resp=200:SpaceTicketEnvelope`).
3. **Request body shape.** Claim: `{ message_type, content:{text}, reply_to_id,
   client_message_id }`. **VERDICT: Corrected** → `{ "body": string }` only.
   SOURCE: schema `SpaceTicketMessageReq` (`openapi.pretty.json:68461`); the
   single required prop `body`; `tickets.ts:162` sends `{ body }`.
4. **Body length / validation.** Claim: cap 4000 (to confirm). **VERDICT: Verified**
   → `minLength: 1, maxLength: 4000`. SOURCE: `SpaceTicketMessageReq.body`
   (`openapi.pretty.json:68463-68467`).
5. **Success response shape.** Claim: single `MessageDto` envelope with
   `id/conversation_id/sender{}/sent_at/...`. **VERDICT: Corrected** → the **whole
   ticket**: `SpaceTicketEnvelope` = `{ ticket: SpaceTicketOut }`, with the reply
   appended to `ticket.messages`. SOURCE: `SpaceTicketEnvelope`
   (`openapi.pretty.json:68381`), `SpaceTicketOut.messages`
   (`openapi.pretty.json:68533`).
6. **Persisted message field shape.** Claim: `{id, conversation_id, sender{user_id,
   display_name, avatar_url}, sent_at (ISO), edited_at, deleted, reply_to_id,
   message_type, content{text}, client_message_id}`. **VERDICT: Corrected** →
   `SpaceTicketMessage` = `{ message_id, sender_sub, sender_role, body, created_at
   (int epoch), email_alert_queued_for[] }`. No nested sender, no ISO timestamp,
   no reply/content/client fields. SOURCE: `SpaceTicketMessage`
   (`openapi.pretty.json:68420`); mirrored in `tickets.ts:6-13` (`TicketMessage`).
7. **`client_message_id` echo / idempotency.** Claim: backend accepts & echoes a
   client message id for dedupe. **VERDICT: Corrected (negative)** → not supported;
   no such field on request or stored message. SOURCE: `SpaceTicketMessageReq`
   (body-only) + `SpaceTicketMessage` (no client id). Dedupe falls back to returned
   `ticket.messages` + local `clientId` (§4.4).
8. **Threaded replies (`reply_to_id`).** Claim: optional parent id. **VERDICT:
   Corrected (negative)** → threads are flat; no `reply_to_id` anywhere. SOURCE:
   `SpaceTicketMessageReq`, `SpaceTicketMessage` schemas.
9. **`can_post` / membership gating field.** Claim: thread response carries
   `can_post`/membership flag governing the composer. **VERDICT: Corrected** → no
   such field. Membership = `space.members[].role` (`viewer|editor|owner`) on the
   space; server enforces via 403; web client does **no** client-side composer
   gating. SOURCE: `TicketSpaceMember`/`TicketSpace` (`tickets.ts:61-79`);
   `TicketSpaceDetailPage.tsx:121-128,372-373` (composer only disabled on empty
   text / in-flight). `canPost` in this spec is an Android UX derivation
   (Corrected to be labeled advisory).
10. **CSRF header on state-changing send.** Claim: must send `X-CSRF-Token` from
    `ui_csrf` cookie via shared interceptor. **VERDICT: Verified.** SOURCE:
    `src/api/client.ts:168-170` (`getCookie("ui_csrf")` → `X-CSRF-Token`).
11. **Cookie-based session transport.** Claim: cookie session. **VERDICT: Verified
    (with addition)** → cookies via `credentials:"include"` AND an `Authorization:
    Bearer` header when an access token exists. SOURCE: `client.ts:158-159`
    (Authorization), `client.ts:183` (`credentials:"include"`). The spec's
    cookie-only framing is incomplete; Android may need the bearer token too if the
    dev host requires it.
12. **401 → refresh once → retry once.** Claim: `POST /ui/session/refresh` then a
    single retry, interceptor-driven. **VERDICT: Verified.** SOURCE:
    `client.ts:121-130` (`refreshSession` → `/ui/session/refresh`),
    `client.ts:204-236` (single refresh promise, one retry).
13. **Error body shape.** Claim: uniform FastAPI `detail` (string | [{msg}] |
    {code}). **VERDICT: Corrected** → 400/403/404/409 return **`ErrorEnvelope`**
    `{ error: { code, message, details? } }`; only **422** returns
    `HTTPValidationError` `{ detail: [{loc,msg,type}] }`. SOURCE: `openapi.index.txt:577`
    (`resp=...400:ErrorEnvelope;403:...;422:HTTPValidationError`); `ErrorEnvelope`
    (`openapi.pretty.json:31777`), `ErrorDetail` (`openapi.pretty.json:31747`).
14. **Status enum.** Claim: "closed/locked" 409 semantics. **VERDICT: Corrected/
    clarified** → ticket `status` enum is `open | in_progress | waiting_on_user |
    done | reopened` (no "closed"/"locked"); 409 is a conflict (e.g. version/state).
    SOURCE: `SpaceTicketStatusReq.status` enum (`openapi.pretty.json:68593-68599`).
15. **Optimistic concurrency.** New fact: `SpaceTicketOut.version` (integer) is
    present. **VERDICT: Verified** (informational). SOURCE:
    `openapi.pretty.json:68571`. Not required for the simple reply POST but relevant
    if a future edit/conflict path is added.
16. **No separate paginated messages endpoint.** Claim (implicit in §6): historical
    thread is a `Pager<Message>` from a messages page. **VERDICT: Corrected** →
    messages are embedded in `SpaceTicketOut.messages`; only ticket *lists* are
    cursored (`SpaceTicketListEnvelope.next_cursor`). SOURCE: `openapi.index.txt:573`
    (list has `cursor,limit`), `:577`/`:575` (message/ticket return full envelope).
17. **Web app does optimistic insertion.** Claim (implied as the contract): web
    inserts optimistically. **VERDICT: Corrected** → web refetches the ticket on
    success (no optimism); toasts "Reply sent". Android optimism is a deliberate,
    valid enhancement, not a web contract. SOURCE:
    `TicketSpaceDetailPage.tsx:121-128`.
18. **Stack / framework choices** (Compose, Hilt, Retrofit, `SavedStateHandle`,
    `imePadding`, Paging 3). **VERDICT: Unverified-assumption (framework ref)** —
    not derivable from backend/web sources; standard AndroidX. Framework refs:
    `https://developer.android.com/jetpack/compose`,
    `https://developer.android.com/topic/libraries/architecture/saving-states`
    (SavedStateHandle), `https://developer.android.com/develop/ui/compose/touch-input/ime`
    (IME insets / imePadding).

### Corrections made

- §2/§5 endpoint path: `/spaces/...` and `/tickets/{id}/messages` → **`POST
  /ticket-spaces/{space_id}/tickets/{ticket_id}/messages`**; method status `201` →
  **`200`** (citations 1, 2).
- §4.2/§5 request body: rich `{message_type, content, reply_to_id,
  client_message_id}` → **`{ "body" }` only**; removed `PostTicketMessageRequest`/
  `TextContentDto`, added `SpaceTicketMessageReq` (citations 3, 4, 7, 8).
- §4.2/§5/FR-5/§6 response: single `MessageDto` → **whole `SpaceTicketEnvelope`**;
  reply taken from `ticket.messages.last()`; added `SpaceTicketEnvelope`/
  `SpaceTicketMessageDto`; timestamps are epoch ints, sender is `sender_sub`/
  `sender_role` (citations 5, 6).
- §2/FR-2/AC-1/§13-R3: removed the fictional `can_post` field; `canPost` re-grounded
  on `space.members[].role` and labeled advisory (citation 9).
- §2/§4.2/§5/§7/§11: error mapping `FastAPI detail` → **`ErrorEnvelope` (non-422) +
  `HTTPValidationError` (422)** dual handling (citations 13).
- FR-9 / §4.4 / §6 / R2 / R4: removed `reply_to_id` and `client_message_id` from the
  wire contract; dedupe re-grounded on returned `ticket.messages` + local `clientId`
  (citations 7, 8).
- §6/§13-R5/citation 16: clarified there is no message pagination; thread is the
  embedded `messages` array.
- §13 R1–R6 all marked resolved; §15 DoD updated to match.

### Open assumptions

- **AND-126 mapper adaptability** (citation 6): AND-126's `MessageDto`/`Message.Text`
  was specced (in this and sibling tickets) for a richer shape (nested sender, ISO
  `sent_at`, `content{text}`). The real `SpaceTicketMessage` is flatter
  (`sender_sub`, epoch `created_at`). *Why open:* AND-126's actual implemented shape
  is not in the provided sources. Mitigation: add a `SpaceTicketMessage →
  Message.Text` adapter and reconcile with AND-126 before merge.
- **Bearer token requirement on Android** (citation 11): web sends both cookie and
  `Authorization: Bearer`. *Why open:* unclear whether the dev host accepts
  cookie-only or requires the bearer header; verify against the live dev host /
  the M1/M2 auth ticket.
- **`sender_role` value space** for a member reply (e.g. `owner`/`editor`/`viewer`
  vs admin roles). *Why open:* `SpaceTicketMessage.sender_role` is an unconstrained
  string in OpenAPI; exact values for space members are not enumerated in the
  sources.
- **Duplicate-on-retry** (citation 7): with no server idempotency key, a retry of a
  silently-succeeded send can create a second message. *Why open/accepted:* backend
  offers no dedupe; only mitigated client-side by reconciling against returned
  `ticket.messages`.
- **Framework/library choices** (citation 18): standard AndroidX, not verifiable
  against the backend/web sources (framework refs only).

## 17. Test Plan

Test target legend: **JVM** = JVM unit/Robolectric (no device); **MWS** =
contract test with MockWebServer; **Emu35** = headless emulator AVD `test35`
(x86_64, API 35); **Dev** = Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a)
physical device. Most cases here are non-hardware and run on JVM/MWS/Emu35; the
device is reserved for ABI/API-34 and IME/TalkBack realism checks.

- **TC-AND-373-01 — Repository builds correct request & maps 200 envelope** ·
  Type: contract/MockWebServer · Target: `DefaultTicketThreadRepository` (JVM+MWS) ·
  Preconditions: MWS enqueues `200` with a `SpaceTicketEnvelope` whose
  `ticket.messages` last item echoes the sent `body`. · Steps: call
  `postReply(spaceId, ticketId, "hello", clientId)`. · Expected: exactly one
  request to `POST /ticket-spaces/{space_id}/tickets/{ticket_id}/messages`, JSON
  body exactly `{"body":"hello"}` (no other keys), `X-CSRF-Token` header present,
  `Content-Type: application/json`; result `ApiResult.Success(Message.Text)` mapped
  from `ticket.messages.last()` (message_id/body/sender_sub preserved). · Traces:
  AC-2, AC-3.

- **TC-AND-373-02 — Happy path "reply posts + renders" end-to-end** ·
  Type: Compose-UI / instrumented (Emu35) · Target: thread screen + ViewModel +
  fake/MWS `TicketsApi` · Preconditions: member with `editor`/`owner` role, open
  ticket, MWS returns the appended message. · Steps: type "Looks good", tap Send. ·
  Expected: optimistic bubble appears immediately; POST hits `…/messages` with
  `{"body":"Looks good"}`; on 200 the canonical message renders (single copy) and
  the placeholder is gone; composer cleared. · Traces: AC-2, AC-3.

- **TC-AND-373-03 — Whitespace/empty and length-bound validation** ·
  Type: unit + Compose-UI (JVM/Emu35) · Target: ViewModel `onSendClick` + composer
  enablement · Preconditions: `canPost = true`. · Steps: (a) input "   " → tap Send;
  (b) input 0 chars; (c) input 4001 chars. · Expected: (a)(b) no request, send
  button disabled; (c) blocked client-side with counter at limit (mirrors server
  `minLength 1`/`maxLength 4000`). · Traces: AC-4.

- **TC-AND-373-04 — Server 422 validation mapping** · Type: contract/MockWebServer
  (JVM+MWS) · Target: repository error mapper · Preconditions: MWS enqueues `422`
  with `HTTPValidationError` `{"detail":[{"loc":["body","body"],"msg":"String
  should have at least 1 character","type":"string_too_short"}]}`. · Steps: call
  `postReply(...)`. · Expected: `ApiResult.Error` whose user text joins
  `detail[].msg` ("String should have at least 1 character"); draft is preserved for
  edit. · Traces: AC-4, AC-5.

- **TC-AND-373-05 — 403 (not a member / wrong role) ErrorEnvelope mapping** ·
  Type: contract/MockWebServer (JVM+MWS) · Target: repository error mapper +
  ViewModel · Preconditions: MWS enqueues `403`
  `{"error":{"code":"role_required","message":"You don't have permission..."}}`. ·
  Steps: send a reply. · Expected: `ApiResult.Error` reads `error.message` (NOT
  `detail`); pending → `Failed`; `canPost` flips to false; no auto-retry. · Traces:
  AC-1, AC-5.

- **TC-AND-373-06 — 409 conflict mapping, no retry** · Type: contract/MockWebServer
  (JVM+MWS) · Target: repository · Preconditions: MWS enqueues `409`
  `{"error":{"code":"conflict","message":"Ticket no longer accepts replies"}}`. ·
  Steps: send. · Expected: single attempt (no backoff retry), `ApiResult.Error`
  with `error.message`; message marked `Failed`. · Traces: AC-5.

- **TC-AND-373-07 — 401 → refresh once → retry once → success** · Type: contract/
  MockWebServer (JVM+MWS) · Target: OkHttp auth interceptor + repository ·
  Preconditions: MWS enqueues `401`, then expects `POST /ui/session/refresh` (200),
  then a `200` `SpaceTicketEnvelope` on the retried send. · Steps: send once. ·
  Expected: exactly one `/ui/session/refresh`, exactly one resend, message renders;
  the ViewModel observes a single logical send (no double bubble). · Traces: AC-5,
  AC-3.

- **TC-AND-373-08 — Non-idempotent send excluded from GET backoff retry** ·
  Type: unit/contract (JVM+MWS) · Target: OkHttp retry policy + repository ·
  Preconditions: MWS enqueues `500` then `200`. · Steps: send. · Expected: the POST
  is attempted **once** (no automatic backoff retry that GETs receive); result is
  `Failed` after the single `500`; user-driven retry only. · Traces: AC-5, AC-4.

- **TC-AND-373-09 — Failed send → manual retry re-posts same body** · Type: unit +
  Compose-UI (JVM/Emu35) · Target: ViewModel `onRetry` + composer · Preconditions:
  first send fails (network); pending item `Failed`. · Steps: tap retry; MWS now
  returns `200`. · Expected: retry re-posts identical `{"body":...}`, reuses the
  same local `clientId` for UI identity (no `client_message_id` on the wire); on
  success the bubble becomes the canonical message with no duplicate. · Traces:
  AC-4, AC-3.

- **TC-AND-373-10 — Offline / flaky-dev-host fail-fast** · Type: instrumented
  (Dev physical device, airplane mode toggled) · Target: composer + repository on
  real radio · Preconditions: device offline (or dev host unreachable / ~20s
  timeout). · Steps: type, tap Send. · Expected: fails fast to `Failed` with an
  offline message; the optimistic bubble persists with a retry control (not
  dropped); no duplicate post on reconnect+retry. *Must run on the physical device*
  to exercise real connectivity loss/timeout (emulator network shaping is less
  representative). · Traces: AC-4.

- **TC-AND-373-11 — Dedupe: confirmed message not shown twice** · Type: unit
  (JVM) · Target: ViewModel merge logic · Preconditions: optimistic pending item
  in flight; success returns `ticket.messages` containing the new message; a
  subsequent ticket refresh returns the same `message_id`. · Steps: send → success
  → refresh. · Expected: exactly one rendered item for that reply (pending removed
  by `clientId`, canonical keyed by `message_id`). · Traces: AC-3.

- **TC-AND-373-12 — Composer gating by space role** · Type: Compose-UI (Emu35) ·
  Target: composer enablement from `space.members[].role` · Preconditions: load the
  same ticket as (a) `viewer`/non-member and (b) `editor`. · Steps: observe
  composer. · Expected: (a) composer hidden or disabled with caption, no send
  attempted; (b) composer enabled. Server 403 still respected if a viewer somehow
  sends. · Traces: AC-1.

- **TC-AND-373-13 — Draft survives rotation & process death** · Type: instrumented
  (Emu35) · Target: `SavedStateHandle` draft persistence · Preconditions: text
  typed, not sent. · Steps: rotate device; then simulate process death/restore
  (`StateRestorationTester` / kill+restore). · Expected: `composerText` restored
  verbatim. · Traces: AC-6.

- **TC-AND-373-14 — Security & privacy: CSRF required, body never logged** ·
  Type: unit/contract (JVM+MWS) · Target: interceptor + logging config ·
  Preconditions: logging interceptor at app level; MWS capture. · Steps: send a
  reply with a recognizable body token; inspect outgoing headers and captured
  logcat/log sink. · Expected: `X-CSRF-Token` present (send fails as `Failed` if the
  `ui_csrf` cookie is absent — no silent no-op); the message body and `sender_sub`
  do **not** appear in any log line or analytics event (only status/error class).
  · Traces: AC-7.

- **TC-AND-373-15 — Accessibility: TalkBack, content descriptions, touch target,
  IME Send** · Type: instrumented/e2e (Dev physical device) · Target: composer a11y
  · Preconditions: TalkBack enabled. · Steps: navigate to composer; focus Send;
  trigger IME "Send"; inspect state chips on a `Failed` item. · Expected: Send
  `IconButton` exposes `cd_send_reply`, excluded from focus when disabled;
  send-state chips announce "Sending"/"Failed to send, double-tap to retry"; retry
  target ≥ 48dp; IME "Send" action posts. *Run on the physical device* for real
  TalkBack behavior. · Traces: AC-7.

### Coverage matrix

| AC (§14) | Covered by |
| --- | --- |
| AC-1 (composer shown only for members; server-enforced) | TC-05, TC-12 |
| AC-2 (posts `text` to correct endpoint w/ correct body + CSRF) | TC-01, TC-02 |
| AC-3 (optimistic insert; confirmed renders; no dup/placeholder) | TC-01, TC-02, TC-07, TC-09, TC-11 |
| AC-4 (failed→retry same body; whitespace never sends; disabled while sending) | TC-03, TC-04, TC-08, TC-09, TC-10 |
| AC-5 (401 refresh once+retry; 403/409/422 specific, no auto-retry; excluded from GET backoff) | TC-04, TC-05, TC-06, TC-07, TC-08 |
| AC-6 (draft survives rotation/process death) | TC-13 |
| AC-7 (no body/PII logged or in analytics; strings in strings.xml; CD on send; a11y) | TC-14, TC-15 |
