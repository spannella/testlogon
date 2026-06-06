---
id: AND-373
title: Ticket messages / reply
milestone: M8
epic: E48
priority: P1
size: M
status: draft
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
  (plaintext, unreliable; ~20s timeouts). OpenAPI at `/openapi.json`. Confirm the
  exact ticket-message POST path, body, and `detail` error shapes against
  `/openapi.json` and the web reference `frontend/src/api/endpoints/*.ts`
  (tickets/spaces endpoints) + `frontend/src/api/types.ts`. **The POST is NOT
  idempotent**, so it is excluded from the GET-only bounded backoff retry policy
  (§7).
- **"Members" gating.** Only a user who is a member of the space/ticket may post.
  The composer is shown/enabled only when the thread response indicates the
  current user has post permission (`can_post` / membership flag); non-members get
  a read-only thread with no composer.

## 3. Functional Requirements

FR-1. The ticket thread screen renders a **reply composer** pinned to the bottom:
a multiline `TextField` (max ~5 visible lines, scrolls beyond), a send
`IconButton`, and an inline error/retry affordance for a failed send.

FR-2. The composer is **enabled only for members** with post permission on the
ticket. For non-members or closed/locked tickets, the composer is hidden (or
shown disabled with an explanatory caption); no send is attempted.

FR-3. The send button is enabled only when the trimmed input is non-empty and no
send is currently in flight for the same draft. Whitespace-only input does not
send. Input length is capped (default 4000 chars; confirm with backend) with a
counter near the limit.

FR-4. On send, the message is inserted **optimistically** at the bottom of the
thread as a `Message.Text` with a client-generated id and `SendState.Sending`,
and the composer input is cleared immediately.

FR-5. On `200/201`, the optimistic message is **replaced** by the canonical
server `Message` (mapped via AND-126), keyed so the list reorders/dedupes
correctly (no duplicate, no flicker).

FR-6. On send failure (network, timeout, non-401 error), the optimistic message
is marked `SendState.Failed` and shows a retry control; tapping retry re-attempts
the same payload (preserving the client id) without retyping.

FR-7. The newly posted/confirmed message **renders** in the thread using the
existing exhaustive `Message` renderer (AND-126/AND-372), proving acceptance.

FR-8. After a successful post, the thread scrolls to reveal the new message if the
user is at/near the bottom; if the user has scrolled up, a "new message" jump
affordance is shown instead of force-scrolling.

FR-9. A reply MAY target a specific parent message (`replyToId` on
`MessageMeta`); if AND-372's thread surfaces a "reply to" action, the composer
carries the parent id in the send body. If not surfaced this milestone, the field
is sent `null` (flat thread).

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
3. `viewModelScope.launch { repo.postReply(ticketId, draft, replyToId, clientId)
   }`.
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

interface TicketThreadRepository {
    suspend fun postReply(
        ticketId: String,
        body: String,
        replyToId: String?,
        clientId: String,       // idempotency / dedupe token sent to backend if supported
    ): ApiResult<Message>
}

class DefaultTicketThreadRepository @Inject constructor(
    private val api: TicketsApi,
) : TicketThreadRepository {

    override suspend fun postReply(
        ticketId: String, body: String, replyToId: String?, clientId: String,
    ): ApiResult<Message> = apiCall {
        val dto = api.postTicketMessage(
            ticketId,
            PostTicketMessageRequest(
                messageType = "text",
                content = TextContentDto(text = body),
                replyToId = replyToId,
                clientMessageId = clientId,
            ),
        )
        MessageMapper.toDomain(dto)   // AND-126
    }
}
```

`apiCall { }` is the shared wrapper that maps exceptions/HTTP errors to
`ApiResult.Error` with the FastAPI `detail` mapping (string | `[{msg}]` |
`{code,...}`). The send is **not** added to the idempotent-GET retry set.

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

The thread shows `pagedHistory ++ pendingNotYetConfirmed`. To avoid duplicates
when the server message arrives in a later page or refresh, dedupe by
`clientMessageId` (preferred — the server echoes it) or, if the backend does not
echo it, by `(senderId, body, sentAt±2s)` heuristic plus removing the
`PendingMessage` as soon as the success response returns. Prefer echoing
`client_message_id`; flag as Open Question R2 if unsupported.

## 5. API Contract

State-changing send. Exact path/body/response **MUST be confirmed against
`/openapi.json`** before implementation; the shapes below are the contract this
ticket targets and the structure the mapper expects.

`POST /spaces/{spaceId}/tickets/{ticketId}/messages` (or
`/tickets/{ticketId}/messages` per the resolved OpenAPI path).

Request headers: session cookies + `X-CSRF-Token: <ui_csrf>`,
`Content-Type: application/json`.

Request body:

```json
{
  "message_type": "text",
  "content": { "text": "Looks good, shipping it." },
  "reply_to_id": null,
  "client_message_id": "b2f1c0a4-7e2d-4c1b-9b6a-2f0d8e6a1c33"
}
```

Success `201 Created` (or `200`) — a single message envelope, identical in shape
to the AND-126 `MessageDto` consumed elsewhere:

```json
{
  "id": "msg_01J8Z...",
  "conversation_id": "tkt_42",
  "sender": { "user_id": "usr_7", "display_name": "Alice", "avatar_url": null },
  "sent_at": "2026-06-05T12:00:00Z",
  "edited_at": null,
  "deleted": false,
  "reply_to_id": null,
  "message_type": "text",
  "content": { "text": "Looks good, shipping it." },
  "client_message_id": "b2f1c0a4-7e2d-4c1b-9b6a-2f0d8e6a1c33"
}
```

Retrofit:

```kotlin
interface TicketsApi {
    @POST("spaces/{spaceId}/tickets/{ticketId}/messages")
    suspend fun postTicketMessage(
        @Path("spaceId") spaceId: String,
        @Path("ticketId") ticketId: String,
        @Body body: PostTicketMessageRequest,
    ): MessageDto
}

@JsonClass(generateAdapter = true)
data class PostTicketMessageRequest(
    @Json(name = "message_type") val messageType: String,
    @Json(name = "content") val content: TextContentDto,
    @Json(name = "reply_to_id") val replyToId: String?,
    @Json(name = "client_message_id") val clientMessageId: String,
)
```

Error responses follow FastAPI `detail`: `403` (not a member / no post
permission), `404` (ticket/space gone), `409` (ticket closed/locked), `422`
(validation — empty/too-long body), `401` (session expired → refresh+retry once).
The `detail` mapper produces a user-facing `UiText`.

## 6. Data & State Management

- **Source of truth.** Historical thread = Paging 3 `Pager<Message>` from
  AND-372 (Room-backed if AND-372 caches; otherwise network page). Optimistic
  sends = `pending: List<PendingMessage>` held in the ViewModel and merged at
  render time. No new Room table is required for this ticket; on success the
  confirmed message either invalidates the Pager or is buffered into a
  confirmed-tail list keyed by id.
- **Draft persistence.** `composerText` and the active `replyToId` are stored in
  `SavedStateHandle` so the draft survives rotation/process death (FR-10).
- **Stability.** `PendingMessage`, `Message.Text`, and `TicketThreadUiState` are
  `@Immutable`; lists are `List<T>`. `clientId` is the stable list key for pending
  items; `MessageId` for confirmed items.
- **Dedup contract.** On success, remove the `PendingMessage` whose `clientId`
  matches `client_message_id` (or the in-flight token) before/at the moment the
  confirmed message becomes visible, so the user never sees two copies.
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
- **Malformed success body.** If the `201` body fails AND-126 mapping, treat as a
  soft success: remove the pending bubble and trigger a thread refresh to fetch
  the canonical message rather than crashing.

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
  correct `PostTicketMessageRequest` (message_type `text`, content.text,
  reply_to_id, client_message_id), maps a `201` body to `Message.Text` via
  AND-126, and returns `ApiResult.Success`. A `403`/`409`/`422`/network failure
  returns `ApiResult.Error` with the mapped `detail`. Asserts the POST is **not**
  retried on a 500/timeout.
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
  POST hits `…/messages` with the expected JSON + `X-CSRF-Token` header, (3) the
  confirmed server message renders in the thread and the optimistic placeholder is
  gone (no duplicate). This is the ticket's stated acceptance.
- **Compose UI (`ReplyComposerTest`).** Send disabled when empty/while sending;
  enabled with valid text; composer hidden/disabled when `canPost = false`; retry
  affordance shown on `Failed`; content descriptions present.
- **401 refresh path.** A first send returns `401`, interceptor calls
  `/ui/session/refresh`, retries once, succeeds; assert the message renders and
  only one logical send is observed by the ViewModel.
- **Dedupe.** When a refreshed page later contains the confirmed message, assert
  it is not shown twice (dedupe by `client_message_id`).

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

- **R1 — Exact endpoint path & method.** `POST
  /spaces/{spaceId}/tickets/{ticketId}/messages` vs a flatter
  `/tickets/{ticketId}/messages`, and `200` vs `201`. *Mitigation:* resolve from
  `/openapi.json` + `frontend/src/api/endpoints/*.ts` before coding the Retrofit
  signature. *Open.*
- **R2 — `client_message_id` echo / idempotency support.** Optimistic dedupe is
  cleanest if the backend accepts and echoes `client_message_id`. If it does not,
  fall back to the heuristic dedupe + immediate pending removal (§4.4). *Open:*
  confirm backend support; if unsupported, manual retry risks duplicate posts.
- **R3 — Membership / post-permission field.** The exact thread-response field
  governing `canPost` (`can_post`, `is_member`, ticket `status`) is unconfirmed.
  *Mitigation:* enforce server-side and treat client gating as advisory; resolve
  the field from OpenAPI. *Open.*
- **R4 — Reply-to threading.** Whether tickets support threaded replies
  (`reply_to_id`) or are flat is unconfirmed; FR-9 sends `null` if AND-372 exposes
  no reply target. *Open:* confirm thread model with backend/web ref.
- **R5 — Composer / Paging interaction.** Merging an in-memory pending list with a
  `Pager<Message>` without flicker or duplicates needs care (invalidate vs
  buffered tail). *Mitigation:* prefer buffered confirmed-tail keyed by id; cover
  with the dedupe test.
- **R6 — Body length / content limits.** Max length and allowed characters are
  inferred (4000). *Open:* confirm `422` validation rules from OpenAPI.

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
4. A failed send marks the message `Failed` with a working retry that reuses the
   same `client_message_id`; whitespace-only input never sends; the send button is
   disabled while a send is in flight.
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
  + `PostTicketMessageRequest`/`TextContentDto` in `core-network`
  (`com.testlogon.android.core.network.tickets`).
- Optimistic send lifecycle (Sending → Sent/Failed), retry with stable
  `client_message_id`, member/`canPost` gating, and `SavedStateHandle` draft
  persistence implemented per §3–§6.
- Send is non-idempotent and excluded from GET backoff retry; 401 refresh+retry,
  CSRF header, and FastAPI `detail` error mapping verified.
- `:feature-tickets:test`, `:feature-tickets:connectedCheck` (or Robolectric),
  and `:core-data:test` green on JDK 17; no new lint/detekt violations; no message
  content logged.
- Open questions R1–R4 (endpoint path/method, `client_message_id` echo,
  `canPost`/membership field, reply-to threading) resolved against `/openapi.json`
  and the dev host (or explicitly re-ticketed) before merge.
- Acceptance test asserting "reply posts + renders" passes; spec reviewed and the
  thread is now writable for members.
