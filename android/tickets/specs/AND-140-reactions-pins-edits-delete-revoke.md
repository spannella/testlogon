---
id: AND-140
title: Reactions, pins, edits, delete/revoke
milestone: M3
epic: E19
priority: P1
size: L
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-123, AND-120, AND-126, AND-115, AND-116]
blocks: []
---

# AND-140 — Reactions, pins, edits, delete/revoke

## 1. Overview & Goal

This ticket adds the per-message moderation and engagement actions to the Thread
(message list) screen delivered in AND-123: emoji **reactions** (with a reactor
details sheet), **pin/unpin** (with a dedicated pins list), **edit** (with an edit
history viewer), **delete** and **revoke**, and client-side **hide**. These are the
"long-press a message → act on it" interactions familiar from modern chat clients.

The goal is a complete, optimistic, repository-backed action layer that mutates the
in-memory thread state immediately, persists the resulting message state to the Room
cache, and reconciles against the backend response (or rolls back on failure). Every
one of the six actions must (a) update the visible thread, and (b) survive
process death / re-entry because it was written to cache — the acceptance bar for
this ticket is precisely "each action updates the thread + persists (tested)".

Out of scope: composing/sending new messages (AND-124), read receipts (AND-125),
attachment-typed messages (AND-129–139). This ticket operates only on already-rendered
messages and the metadata layered on top of them.

## 2. Context & References

- Depends on **AND-123** (Thread screen + `ThreadViewModel` + `LazyColumn` of messages)
  and **AND-120** (`MessagingApi` + DTOs / `/messaging/conversations/...` base paths).
- Depends on **AND-126** (message domain model + mappers) for the canonical
  `Message` model these actions mutate, and on **AND-115/AND-116** (Room base DAOs +
  SWR cache repository) for persistence.
- Web reference: `frontend/src/api/endpoints/messaging.ts` (reaction/pin/edit/delete
  calls) and shared types in `frontend/src/api/types.ts`. Confirm exact action paths
  and the reaction/edit-history shapes against `/openapi.json` on the dev backend
  (`http://18.222.237.167:8000/openapi.json`) before finalizing DTOs in code.
- Stack/layering per project context: Kotlin 2.0.21, Compose + Material 3, Hilt (KSP),
  Retrofit 2.11/OkHttp 4.12/Moshi 1.15, Room 2.6, Coroutines/Flow. Module home:
  `feature-messaging` (UI + ViewModel) over `core-network`/`core-data`/`core-model`.
  Package base **`com.testlogon.android`** everywhere.

## 3. Functional Requirements

FR-1 **Reactions.** From a message's action menu (long-press) the user opens an emoji
picker; tapping an emoji toggles the current user's reaction for that emoji on that
message. A reaction chip row renders under the message bubble showing each emoji with
its count; the chip is highlighted when the current user has reacted with it. Tapping
an existing chip toggles the current user's reaction. Long-pressing a chip (or tapping
a "see who reacted" affordance) opens a **reaction details** bottom sheet listing
reactors grouped by emoji.

FR-2 **Pin / unpin.** The action menu offers Pin (or Unpin if already pinned). Pinned
messages show a pin indicator in the bubble. A "Pinned messages" entry in the thread
top bar opens a **pins list** sheet/screen showing all pinned messages for the
conversation, newest pin first; tapping one scrolls the thread to that message.

FR-3 **Edit + history.** For messages authored by the current user, Edit opens the
composer pre-filled with the current text; submitting updates the message body and
stamps it as edited ("edited" label). An **edit history** viewer (opened from the
"edited" label or action menu) lists prior revisions with timestamps.

FR-4 **Delete.** For the user's own messages, Delete removes the message after a
confirmation dialog. Deleted messages either disappear or render as a tombstone
("This message was deleted") per backend semantics (see §5); the thread updates and
the change persists.

FR-5 **Revoke.** Revoke (a stronger "unsend"/retract) is offered for the user's own
messages within the backend-allowed window; it retracts the message for all
participants. UI treats it like delete but uses the revoke endpoint and a revoke
tombstone where applicable.

FR-6 **Hide.** [CORRECTED] Hide is a **server-side, per-user** action — not client-local
as originally specified. The backend exposes `POST /messaging/conversations/{cid}/messages/{mid}/hide`
to hide a message for the current user only and `DELETE …/hide` to unhide; a paginated
`GET /messaging/conversations/{cid}/hidden-messages` lists the user's hidden messages.
Verified against OpenAPI (`hide_message_for_me`, `unhide_message_for_me`) and the web
reference (`messaging.ts: hideMessage / unhideMessage / getHiddenMessages`). Hide
suppresses a message from this user's thread view while leaving it visible to other
participants. The client still caches the hidden flag locally for instant/offline UI and
cross-restart persistence, but it MUST reconcile with the server hide endpoints rather
than treating hide as a no-network local-only action. A way to unhide is available from a
small "hidden message" affordance.

FR-7 **Optimism & reconciliation.** All six actions apply optimistically to thread
state, then reconcile with the server response. Non-2xx rolls the change back and
surfaces a transient error. Each successful action's resulting message state is written
to Room. [CORRECTED] Note that hide is NOT a local-only action (see FR-6), so all six
actions are network-backed and subject to rollback on failure.

FR-8 **Permissions/affordance gating.** Edit/Delete/Revoke appear only for messages
authored by the current user (`message.isMine`). Pin appears per conversation policy
exposed by `/config` (AND-120); if unknown, default to allowing pin. Reactions and
Hide are available on any message.

## 4. Technical Design

All new code lives under `feature-messaging` with DTO/API additions in `core-network`
and persistence in `core-data`.

### 4.1 Domain model additions (core-model)

> [CORRECTED] The wire format does NOT send a `reactions[]` array with per-emoji
> `count`/`reacted_by_me`. `MessageOut` carries `reactions_counts: Map<String,Int>`
> (emoji → count) and `my_reactions: List<String>` (emojis the current user reacted with).
> The `Reaction` UI model below is therefore *derived* in the mapper by zipping those two
> fields: `reactedByMe = emoji in my_reactions`. Likewise `MessageLifecycle` is *derived*
> — `MessageOut` has no `state` field; revoked is signalled by a non-null `revoked_at`/
> `revoked_by`, edited by a non-null `edited_at`/`edited_by`, and delete returns an empty
> 200 (no tombstone payload — see §5/§7). `Reactor` uses `user_sub` (the backend's id
> field), not `userId`, and the API also returns `profile_photo_url`.

```kotlin
data class Reaction(val emoji: String, val count: Int, val reactedByMe: Boolean)
// derived in mapper from MessageOut.reactions_counts + my_reactions

data class Reactor(val userSub: String, val displayName: String, val profilePhotoUrl: String?, val emoji: String)
// from ReactionDetailsOut.reactions: Map<emoji, List<ReactionUserOut>>

data class MessageEdit(val revision: Int, val body: String, val editedAt: Instant)
// NOTE: GET …/edits response shape is not pinned in OpenAPI (empty 200 schema) — see §5/§16

// Derived client-side from MessageOut.revoked_at / edited_at (no server `state` field exists)
enum class MessageLifecycle { ACTIVE, EDITED, DELETED, REVOKED }

// Extends the AND-126 Message model (added fields, defaults keep older callers green)
data class Message(
    val id: String,
    val conversationId: String,
    val senderId: String,
    val body: String?,
    val createdAt: Instant,
    val isMine: Boolean,
    val reactions: List<Reaction> = emptyList(),
    val isPinned: Boolean = false,
    val lifecycle: MessageLifecycle = MessageLifecycle.ACTIVE,
    val editedAt: Instant? = null,
    val isHiddenLocal: Boolean = false,
)
```

### 4.2 Repository (core-data)

A `MessageActionsRepository` wraps `MessagingApi` and the Room DAOs. Every method
returns `ApiResult<T>` (AND-018) and applies cache-first writes.

```kotlin
interface MessageActionsRepository {
    // [CORRECTED] react endpoint returns empty 200, not a Message. Re-fetch the message
    // (or apply optimistic counts) and return the locally-reconciled Message.
    suspend fun toggleReaction(conversationId: String, messageId: String, emoji: String, add: Boolean): ApiResult<Message>
    suspend fun reactionDetails(conversationId: String, messageId: String): ApiResult<List<Reactor>>
    // [CORRECTED] pin -> POST …/pin, unpin -> DELETE …/pin; both return MessageControlActionOut
    // (ok/action/updated_at), NOT a Message. Apply pin state to the cached entity locally.
    suspend fun setPinned(conversationId: String, messageId: String, pinned: Boolean): ApiResult<Unit>
    // [CORRECTED] GET …/pins returns ConversationPinOut refs (message_id/pinned_at/…), paginated
    // (cursor/limit). Resolve refs to cached Messages; fetch any not in cache.
    suspend fun pinnedMessages(conversationId: String, cursor: String? = null): ApiResult<List<Message>>
    // [CORRECTED] PATCH body field is `text` (required), not `body`. Returns MessageOut.
    suspend fun editMessage(conversationId: String, messageId: String, text: String): ApiResult<Message>
    suspend fun editHistory(conversationId: String, messageId: String, limit: Int = 50): ApiResult<List<MessageEdit>>
    // [CORRECTED] DELETE …/{mid} ("delete for me") returns empty 200, not a tombstone Message.
    suspend fun deleteMessage(conversationId: String, messageId: String): ApiResult<Unit>
    // [CORRECTED] revoke is DELETE …/{mid}/revoke ("revoke for all"); returns MessageOut.
    suspend fun revokeMessage(conversationId: String, messageId: String): ApiResult<Message>
    // [CORRECTED] hide is server-side: POST …/hide to hide, DELETE …/hide to unhide
    // (MessageControlActionOut). NOT local-only.
    suspend fun setHidden(conversationId: String, messageId: String, hidden: Boolean): ApiResult<Unit>
    suspend fun hiddenMessages(conversationId: String, cursor: String? = null): ApiResult<List<Message>>
}
```

Mutation pattern (illustrated for reactions): read current cached `MessageEntity`,
compute optimistic next state, `dao.upsert(next)` so the thread `Flow` emits, call the
API, on success upsert the server-authoritative mapped message, on `ApiResult.Error`
re-upsert the captured previous entity and return the error for the ViewModel to show.

### 4.3 ViewModel (feature-messaging)

The existing `ThreadViewModel` (AND-123) gains action intents. UI state for the message
list is filtered to drop `isHiddenLocal == true` items (with a separate count of hidden
items to power the "show hidden" affordance). Auxiliary sheets carry their own state.

```kotlin
sealed interface ThreadAction {
    data class ToggleReaction(val messageId: String, val emoji: String) : ThreadAction
    data class OpenReactionDetails(val messageId: String) : ThreadAction
    data class SetPinned(val messageId: String, val pinned: Boolean) : ThreadAction
    data object OpenPinsList : ThreadAction
    data class StartEdit(val messageId: String) : ThreadAction
    data class SubmitEdit(val messageId: String, val body: String) : ThreadAction
    data class OpenEditHistory(val messageId: String) : ThreadAction
    data class Delete(val messageId: String) : ThreadAction
    data class Revoke(val messageId: String) : ThreadAction
    data class SetHidden(val messageId: String, val hidden: Boolean) : ThreadAction
}

data class MessageActionsUiState(
    val reactionDetails: Async<List<Reactor>> = Async.Idle,
    val pinned: Async<List<Message>> = Async.Idle,
    val editHistory: Async<List<MessageEdit>> = Async.Idle,
    val editing: EditTarget? = null,
    val transientError: String? = null,
)

fun onAction(action: ThreadAction)   // dispatches to repo on viewModelScope
```

`onAction` launches on `viewModelScope`; sheet loaders (`reactionDetails`,
`pinnedMessages`, `editHistory`) move their `Async` state through Loading → Success/Error.

### 4.4 Compose UI

- `MessageActionsSheet(message, onAction)` — modal bottom sheet listing applicable
  actions, gated by `message.isMine` and pin policy.
- `EmojiReactionPicker(onPick: (String) -> Unit)` — short curated emoji row plus
  "more".
- `ReactionChipsRow(reactions, onToggle, onLongPress)` — under-bubble chip row.
- `ReactionDetailsSheet(state)`, `PinnedMessagesSheet(state, onJumpTo)`,
  `EditHistorySheet(state)` — read sheets backed by the `Async` fields.
- Edit reuses the AND-124 composer in "edit mode" driven by `editing: EditTarget?`.
- Delete/Revoke each gate behind an `AlertDialog` confirmation.
- Jump-to-pinned uses the AND-123 `LazyListState` (`animateScrollToItem`) keyed by
  message id; if the target isn't in the loaded window, trigger a paged load then scroll.

## 5. API Contract

[CORRECTED] The original §5 paths/methods/shapes were reference-derived guesses and
several were wrong. The block below is now **verified against the backend OpenAPI**
(`reference/openapi.index.txt` + `openapi.pretty.json`) and the web client
(`reference/src/api/endpoints/messaging.ts` + `types.ts`). The AND-120 base is
`/messaging/conversations/{conversation_id}/messages/{message_id}`. The three GET reads
(reactions/details, pins, edits, hidden-messages) are the only idempotent-GET endpoints
eligible for the AND-016 retry policy; everything else is a non-idempotent mutation.

```
# --- VERIFIED endpoints (path | method | request | response) ---
POST   /messaging/conversations/{cid}/messages/{mid}/reactions         ReactIn{emoji, action:"add"|"remove"=add} -> 200 (empty)
GET    /messaging/conversations/{cid}/messages/{mid}/reactions/details  -> ReactionDetailsOut
POST   /messaging/conversations/{cid}/messages/{mid}/pin                -> MessageControlActionOut
DELETE /messaging/conversations/{cid}/messages/{mid}/pin                -> MessageControlActionOut
GET    /messaging/conversations/{cid}/pins                              cursor,limit -> ConversationPinsPageOut
PATCH  /messaging/conversations/{cid}/messages/{mid}                    EditMessageIn{text}  -> MessageOut
GET    /messaging/conversations/{cid}/messages/{mid}/edits              limit -> 200 (shape unpinned in OpenAPI)
DELETE /messaging/conversations/{cid}/messages/{mid}                    -> 200 (empty)  [delete_message_for_me]
DELETE /messaging/conversations/{cid}/messages/{mid}/revoke             -> MessageOut   [revoke_message_for_all]
POST   /messaging/conversations/{cid}/messages/{mid}/hide               -> MessageControlActionOut   [hide_message_for_me]
DELETE /messaging/conversations/{cid}/messages/{mid}/hide               -> MessageControlActionOut   [unhide_message_for_me]
GET    /messaging/conversations/{cid}/hidden-messages                   cursor,limit -> HiddenMessagesResp{items:Message[],next_cursor}
```

Corrections vs the original draft:
- Reaction toggle is ONE endpoint (`POST …/reactions` with `action` add/remove); there is
  no `DELETE …/reactions/{emoji}`. The response is an empty 200, **not** a Message.
- Reaction details is `GET …/reactions/**details**`, not `GET …/reactions`.
- Unpin is `DELETE …/pin`, not `POST …/unpin`. Pin/unpin return `MessageControlActionOut`,
  not a Message.
- Pins list returns pin **refs** (`ConversationPinOut`), not Messages, and is cursor-paginated.
- Edit request field is `text` (required), not `body`.
- Revoke is `DELETE …/{mid}/revoke`, not `POST …/{mid}/revoke`.
- Delete returns an empty 200 (no tombstone payload).
- Hide is server-side (see FR-6), with its own list endpoint.

Verified response/request shapes (Moshi DTOs in `core-network`):

```json
// MessageOut (edit / revoke / list) — note epoch-INTEGER timestamps, `text` not `body`,
// `message_id` not `id`; NO `state` and NO `pinned`/`reactions[]` fields.
{ "message_id":"m_1","conversation_id":"c_1","sender_id":"u_2","kind":"text",
  "text":"hi","created_at":1749124800,"edited_at":null,"edited_by":null,
  "revoked_at":null,"revoked_by":null,
  "reactions_counts":{"👍":3},"my_reactions":["👍"] }

// POST …/reactions request, ReactIn:
{ "emoji":"👍","action":"add" }            // action ∈ {add, remove}, default add

// GET …/reactions/details, ReactionDetailsOut — emoji -> reactor list (note user_sub):
{ "reactions": { "👍": [ {"user_sub":"u_2","display_name":"Ann","profile_photo_url":null} ] } }

// pin / unpin / hide / unhide, MessageControlActionOut:
{ "ok":true,"conversation_id":"c_1","message_id":"m_1","action":"pinned","updated_at":1749124800 }
// action ∈ {hidden, visible, pinned, unpinned}

// GET …/pins, ConversationPinsPageOut — pin REFS, not messages:
{ "items":[ {"conversation_id":"c_1","message_id":"m_1","pinned_by_user_id":"u_2",
             "pinned_at":1749124800,"is_active":true} ], "next_cursor":null }
```

DTOs map to domain via the AND-126 mapper, extended here:
- `MessageOut.reactions_counts` + `my_reactions` → `List<Reaction>` (count from the map,
  `reactedByMe = emoji in my_reactions`).
- Lifecycle is **derived**: `revoked_at != null` → REVOKED; `edited_at != null` → EDITED
  (else ACTIVE). Delete has no payload, so DELETED is inferred from the 200 (or a 404 on a
  subsequent fetch) and applied to the cached entity.
- `ReactionDetailsOut.reactions` (`Map<emoji, ReactionUserOut[]>`) is flattened to
  `List<Reactor>` carrying `user_sub`/`display_name`/`profile_photo_url`.
- Pins list resolves `ConversationPinOut.message_id` against the cache; rows not present are
  fetched on demand.

## 6. Data & State Management

- **Room (AND-115).** `MessageEntity` gains columns: `reactions_json` (TEXT, Moshi-
  serialized `List<Reaction>`), `is_pinned` (INTEGER), `lifecycle` (TEXT),
  `edited_at` (INTEGER nullable), `is_hidden` (INTEGER). Provide a Room migration
  (schema version bump, exported schema) with `ALTER TABLE` defaults so existing cached
  rows survive. [CORRECTED] Since hide is now server-backed (FR-6), the hidden flag is
  authoritative from the server (`hidden-messages` list / hide responses) but is cached for
  offline/instant UI. A foreground `is_hidden` write may briefly run ahead of the server
  during optimism and is reconciled on the hide/unhide response; it should NOT be blindly
  clobbered by an unrelated `MessageOut` upsert (merge: preserve the local flag unless the
  upsert source is the hide-list sync). `reactions_json` may be derived from
  `reactions_counts`/`my_reactions` at map time.
- **Source of truth.** The thread renders from `MessageDao.observeThread(conversationId)`
  via SWR (AND-116). All action mutations write through Room, so optimism, persistence,
  and reconciliation share one path; UI state is a `StateFlow<UiState>` mapped from the
  DAO flow.
- **Pins list / edit history / reactor list** are fetched on demand into `Async` fields;
  pins may be cached opportunistically (pinned entities already live in the message
  table), edit history and reactor lists are not persisted (read-through only).
- **Optimistic rollback.** Each mutating call captures the prior `MessageEntity`,
  applies the optimistic entity, and restores the captured copy on error.

## 7. Error Handling & Resilience

- [CORRECTED] Two distinct error shapes exist. The control endpoints (pin/unpin,
  hide/unhide, pins list) return `MessageControlsErrorOut {detail: string, error_code?: string}`
  on 401/403/404/422/429 — prefer `error_code` for branching and `detail` for display. The
  mutation/read endpoints (reactions, edit PATCH, delete, revoke, edits) return the standard
  FastAPI `HTTPValidationError` on 422 (`detail: [{loc,msg,type}]`). Map both via AND-015,
  surface as a Snackbar (`transientError`), and roll back the optimistic mutation.
- **403** on edit/delete/revoke (not allowed / outside window) → show a precise message
  ("Revoke window expired") and revert; remove the action from the menu next time.
- **404** (message already deleted server-side) → reconcile to a deleted tombstone in
  cache rather than rolling back.
- **409/422** (e.g., reaction already toggled, validation) → re-sync that message via
  the latest server payload when provided, else leave optimistic state and warn.
- **401** → handled transparently by the AND-013 refresh authenticator (refresh once,
  retry); no special handling here.
- **Network/timeout** (dev host is unreliable, ~20s timeouts per project context) →
  roll back and offer retry. No automatic retry for these mutations (non-idempotent;
  AND-016 covers only GETs). The read sheets (reactions/pins/edits) are GETs and may use
  bounded backoff.
- [CORRECTED] **Hide** is network-backed (POST/DELETE `…/hide`), so it CAN fail; apply
  optimistically but roll back and surface an error on non-2xx, like the other mutations.
  The cached hidden flag keeps the UI responsive offline, but the action is not "always
  succeeds" as originally written.

## 8. Security & Privacy

- All requests carry the cookie session + `X-CSRF-Token` from the `ui_csrf` cookie via
  the existing CSRF interceptor (AND-012) and persistent cookie jar (AND-011); these
  mutations are state-changing and must send the CSRF header.
- Authorization is enforced server-side; the client only gates *affordances*
  (`isMine`, pin policy) for UX — never assume client gating is a security boundary.
- Reaction details expose other users' identities; only display fields the backend
  returns (no client-side enrichment from other caches).
- No message bodies, emojis, edit contents, or user ids are logged (see §10).
- [CORRECTED] Hidden-message state is server-backed per-user (FR-6), not purely local;
  the cached `is_hidden` flag is non-sensitive UX state and is fine to store unencrypted in
  Room, but the source of truth is the backend hide/unhide endpoints and the
  `hidden-messages` list.

## 9. Accessibility & i18n

- Every action affordance has a `contentDescription`/`stateDescription`: reaction chips
  announce emoji + count + "you reacted" state; pin indicator announces pinned status;
  "edited" label is a focusable element opening history.
- Action menu items, dialog buttons, and sheets meet the 48dp touch target and pass
  TalkBack focus order; confirmation dialogs are reachable and dismissible.
- All user-facing strings (Pin, Unpin, Edit, Delete, Revoke, Hide, Unhide, "edited",
  "This message was deleted", "Pinned messages", confirmation copy, error copy) live in
  `strings.xml` and route through the AND-111/112 i18n plumbing; counts use plurals
  (`quantityString`). Layouts are RTL-safe (AND-114): chip rows and pin icons use
  start/end, not left/right.

## 10. Telemetry & Logging

- Emit redacted analytics events via the AND-052 telemetry layer:
  `msg_reaction_toggled` (emoji bucketed/hashed, not raw), `msg_pinned`/`msg_unpinned`,
  `msg_edited`, `msg_deleted`, `msg_revoked`, `msg_hidden_local` — each with
  `conversation_id` and `message_id` only, no body/PII.
- Log action latency and outcome (success / error code) at DEBUG; never log bodies,
  emojis tied to a user, edit history, or reactor identities.
- Record optimistic-rollback occurrences (counter) to detect a flaky backend.

## 11. Testing Strategy

Acceptance requires each of the six actions to be tested for *thread update + persistence*.

- **Repository unit tests (core-testing + MockWebServer, AND-046):** for each action,
  assert (1) optimistic Room write happens before the network returns, (2) success maps
  the server payload into Room, (3) error rolls the entity back to its captured prior
  state. Use fixtures for the JSON shapes in §5. Include 403 (revoke window), 404
  (already deleted → tombstone), 409 (reaction conflict).
- **Mapper tests:** DTO→domain for reactions (`reacted_by_me`), lifecycle/tombstone,
  edit history ordering, reactor flattening.
- **Persistence tests (Room in-memory):** migration adds new columns with defaults;
  `is_hidden_local` survives a server upsert; thread query excludes hidden rows.
- **ViewModel tests (Turbine):** dispatch each `ThreadAction`, assert `UiState`
  transitions, `Async` sheet states, and `transientError` on failure.
- **Compose UI tests (AND-048 style):** long-press → action menu; tap emoji → chip
  appears and is highlighted; pin → indicator + pins sheet contains the message;
  edit → "edited" label + history sheet; delete/revoke → confirmation then tombstone;
  hide → message disappears and stays hidden after recreating the activity.
- Wire into CI unit (AND-050) and instrumented (AND-051) jobs.

## 12. Dependencies & Sequencing

- **Hard deps:** AND-123 (thread screen/VM), AND-120 (`MessagingApi`/DTOs/base paths),
  AND-126 (message model + mappers), AND-115 (Room base/DAOs/migrations), AND-116 (SWR
  cache repo). Indirect: AND-012/013 (CSRF, refresh), AND-015/018 (error + ApiResult).
- **Sequencing:** (1) extend `Message`/`MessageEntity` + migration; (2) add DTOs +
  `MessagingApi` action methods in core-network; (3) implement `MessageActionsRepository`
  with optimistic-write/reconcile; (4) wire `ThreadViewModel` intents; (5) build Compose
  action menu, chips, and the three read sheets; (6) tests.
- **Blocks:** nothing in the provided backlog declares AND-140 as a dependency.
- Reuse, do not fork, the AND-124 composer for edit mode and the AND-123 `LazyListState`
  for jump-to-pinned.

## 13. Risks & Open Questions

- **R1 — Endpoint shapes [now VERIFIED].** Paths/payloads for reactions, pins, edits,
  delete, revoke, and hide were confirmed against the backend OpenAPI and web client during
  this review (§5, §16); the original draft had several wrong paths/methods/fields (now
  corrected). Remaining gap: the `GET …/edits` response body is not pinned in OpenAPI
  (empty 200 schema). *Mitigation:* contract tests against captured fixtures; capture the
  live `…/edits` payload from the dev backend before finalizing `MessageEdit`.
- **R2 — Delete vs revoke semantics.** Whether delete is soft (tombstone) or hard, and
  the revoke time window, are backend-defined. *Open question:* does the backend return a
  tombstone or a 404 after delete? Handle both (§7).
- **R3 — Reaction concurrency.** Rapid toggle taps can race; debounce per (message,emoji)
  and treat the latest server payload as authoritative.
- **R4 — Jump-to-pinned outside loaded window** requires a targeted paged fetch
  (AND-123 paging); if not feasible immediately, fall back to "load until found" with a
  bounded cap.
- **R5 — Hidden-state divergence.** Server upsert must preserve `is_hidden_local`;
  covered by an explicit persistence test.

## 14. Acceptance Criteria

AC-1 Toggling a reaction updates the chip row immediately, persists to Room, and
reconciles with the server payload; rolls back on error. (Tested.)
AC-2 Reaction details sheet lists reactors grouped by emoji from the GET endpoint.
AC-3 Pin/unpin updates the bubble indicator and persists; the pins list sheet shows all
pinned messages and tapping one scrolls the thread to it. (Tested.)
AC-4 Editing the user's own message updates the body, stamps "edited", persists, and the
edit history sheet lists prior revisions newest-first. (Tested.)
AC-5 Delete removes/tombstones the message after confirmation and persists; a server 404
reconciles to a tombstone rather than re-showing the message. (Tested.)
AC-6 Revoke retracts the user's own message via the revoke endpoint within the allowed
window, with a clear error + revert when the window has expired. (Tested.)
AC-7 [CORRECTED] Hide calls `POST …/hide` (and unhide `DELETE …/hide`), suppresses the
message from this user's thread, persists the hidden flag across process death, and offers
an unhide affordance; the optimistic flag is reconciled with the server response and not
clobbered by an unrelated message upsert. (Tested.)
AC-8 Edit/Delete/Revoke affordances appear only for the current user's messages.
AC-9 All mutating requests include the CSRF header; failures map FastAPI `detail` to
a user-facing message and never crash the thread.

## 15. Definition of Done

- `MessageActionsRepository` and `MessagingApi` action methods implemented under
  `com.testlogon.android` with Moshi DTOs and AND-126-aligned mappers.
- `Message`/`MessageEntity` extended with a tested, schema-exported Room migration.
- `ThreadViewModel` exposes the `ThreadAction` intents and `MessageActionsUiState`;
  thread UI renders chips, pin indicators, "edited" labels, tombstones, and hides
  hidden messages.
- Action menu + emoji picker + the three read sheets + edit-mode composer + delete/revoke
  confirmations implemented and accessible (TalkBack, 48dp, RTL, localized strings).
- All §11 tests pass in CI (unit AND-050, instrumented AND-051); ktlint/detekt (AND-005)
  clean; no PII/body logging.
- Each of the six actions demonstrably updates the thread and persists (acceptance bar).
- Code reviewed and merged to `android-port`.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **Reaction toggle endpoint.** Claim (orig): `POST …/reactions {emoji}` + `DELETE …/reactions/{emoji}`.
   **VERDICT: Corrected.** Single `POST …/reactions` with `ReactIn{emoji, action:"add"|"remove"=add}`,
   response empty 200. Source: OpenAPI `POST /messaging/conversations/{conversation_id}/messages/{message_id}/reactions`
   (op `react_to_message`, req `ReactIn`, resp `200:`); schema `components.schemas.ReactIn`;
   `src/api/endpoints/messaging.ts: reactToMessage`.
2. **Reaction details endpoint.** Claim (orig): `GET …/reactions`.
   **VERDICT: Corrected.** Actual `GET …/reactions/details` → `ReactionDetailsOut`. Source:
   OpenAPI `GET /messaging/conversations/{conversation_id}/messages/{message_id}/reactions/details`
   (op `get_reaction_details`, resp `200:ReactionDetailsOut`); `src/api/endpoints/messaging.ts: getReactionDetails`.
3. **Reaction details shape.** **VERDICT: Corrected.** `ReactionDetailsOut.reactions` is a
   map `emoji -> ReactionUserOut[]`, where `ReactionUserOut{user_sub, display_name, profile_photo_url?}`
   — reactor id is `user_sub`, not `user_id`. Source: `components.schemas.ReactionDetailsOut`,
   `components.schemas.ReactionUserOut`; `src/api/types.ts: ReactionDetails` (line 1433).
4. **Reaction representation on a message.** Claim (orig): `reactions:[{emoji,count,reacted_by_me}]`.
   **VERDICT: Corrected.** `MessageOut` carries `reactions_counts: Map<String,Int>` and
   `my_reactions: String[]`; no `reacted_by_me` array exists. Source: `components.schemas.MessageOut`
   (props `reactions_counts`, `my_reactions`); `src/api/types.ts` lines 1203-1204.
5. **Pin / unpin.** Claim (orig): `POST …/pin` + `POST …/unpin` returning a Message.
   **VERDICT: Corrected.** `POST …/pin` and `DELETE …/pin`, both → `MessageControlActionOut`
   (`{ok, conversation_id, message_id, action, updated_at}`), not a Message. Source: OpenAPI
   `POST`/`DELETE /messaging/conversations/{conversation_id}/messages/{message_id}/pin`
   (ops `pin_message`/`unpin_message`); `components.schemas.MessageControlActionOut`;
   `src/api/endpoints/messaging.ts: pinMessage / unpinMessage`.
6. **Pins list.** Claim (orig): `GET …/pins` → pinned messages.
   **VERDICT: Corrected.** `GET …/pins` (cursor,limit) → `ConversationPinsPageOut{items:ConversationPinOut[], next_cursor}`;
   items are pin **refs** (`message_id, pinned_by_user_id, pinned_at, is_active`), not Messages.
   Source: OpenAPI `GET /messaging/conversations/{conversation_id}/pins` (op `list_conversation_pins`,
   resp `200:ConversationPinsPageOut`); `components.schemas.ConversationPinOut`;
   `src/api/endpoints/messaging.ts: getPinnedMessages`, `src/api/types.ts: ConversationPinsResp` (line 1465).
7. **Edit.** Claim (orig): `PATCH …/{mid} {body}`.
   **VERDICT: Corrected.** `PATCH …/{mid}` with `EditMessageIn{text}` (required field is `text`,
   not `body`) → `MessageOut`. Source: OpenAPI `PATCH /messaging/conversations/{conversation_id}/messages/{message_id}`
   (op `edit_message`, req `EditMessageIn`, resp `200:MessageOut`); `components.schemas.EditMessageIn`;
   `src/api/endpoints/messaging.ts: editMessage` (body `{text}`).
8. **Edit history.** **VERDICT: Verified (path) / Unverified-assumption (shape).** Path
   `GET …/{mid}/edits` (limit) exists; the response body shape is not pinned (empty 200 schema
   in OpenAPI, no frontend caller). Source: OpenAPI `GET /messaging/conversations/{conversation_id}/messages/{message_id}/edits`
   (op `get_edit_history`, resp `200:`). The `MessageEdit{revision,body,editedAt}` shape is assumed.
9. **Delete.** Claim (orig): `DELETE …/{mid}` returning a tombstone message.
   **VERDICT: Corrected.** `DELETE …/{mid}` (op `delete_message_for_me`) returns empty 200, not a
   tombstone payload; it is "delete for me". Source: OpenAPI
   `DELETE /messaging/conversations/{conversation_id}/messages/{message_id}` (resp `200:`);
   `src/api/endpoints/messaging.ts: deleteMessage`.
10. **Revoke.** Claim (orig): `POST …/{mid}/revoke`.
    **VERDICT: Corrected.** `DELETE …/{mid}/revoke` (op `revoke_message_for_all`) → `MessageOut`.
    Source: OpenAPI `DELETE /messaging/conversations/{conversation_id}/messages/{message_id}/revoke`
    (resp `200:MessageOut`). No frontend caller (revoke not used by web client).
11. **Hide.** Claim (orig): hide is client-local with **no** endpoint.
    **VERDICT: Corrected.** Hide is server-side per-user: `POST …/hide` / `DELETE …/hide` →
    `MessageControlActionOut`, plus `GET …/hidden-messages` → `HiddenMessagesResp{items:Message[],next_cursor}`.
    Source: OpenAPI `POST`/`DELETE /messaging/conversations/{conversation_id}/messages/{message_id}/hide`
    (ops `hide_message_for_me`/`unhide_message_for_me`); `src/api/endpoints/messaging.ts:
    hideMessage / unhideMessage / getHiddenMessages`; `src/api/types.ts: HiddenMessagesResp` (line 1452).
12. **MessageOut identity / body / timestamps.** Claim (orig): `id`, `body`, ISO-8601 `created_at`,
    `state` enum, `pinned` boolean. **VERDICT: Corrected.** Fields are `message_id`, `text`,
    epoch-INTEGER `created_at`/`edited_at`/`revoked_at`; there is no `state` and no `pinned` field.
    Lifecycle is derived (`revoked_at`/`edited_at`). Source: `components.schemas.MessageOut`
    (required: `conversation_id, message_id, sender_id, created_at, kind`); `src/api/types.ts` (Message, lines ~1195-1204).
13. **CSRF / auth transport.** Claim (orig): cookie session + `X-CSRF-Token` from `ui_csrf` cookie.
    **VERDICT: Verified.** Web client sends `credentials:"include"` and sets `X-CSRF-Token` from the
    `ui_csrf` cookie on every request. Source: `src/api/client.ts` (getCookie `ui_csrf` → header
    `X-CSRF-Token`, lines 167-171; `credentials:"include"` line 183). Android equivalent: persistent
    cookie jar (AND-011) + CSRF interceptor (AND-012).
14. **Control-endpoint error shape.** **VERDICT: Verified.** pin/unpin/hide/unhide/pins return
    `MessageControlsErrorOut{detail, error_code?}` on 401/403/404/422/429; other endpoints use
    `HTTPValidationError` (422). Source: OpenAPI per-endpoint `resp=...:MessageControlsErrorOut`;
    `components.schemas.MessageControlsErrorOut`; `src/api/types.ts: MessageControlsErrorResp` (line 1437).
15. **Android stack choices** (Compose/Material 3, Hilt/KSP, Retrofit/OkHttp/Moshi, Room, Coroutines).
    **VERDICT: Unverified-assumption (project convention).** Not checkable from backend/frontend
    sources; inherited from project context / sibling AND-1xx tickets. framework ref:
    Compose `https://developer.android.com/jetpack/compose`, Room migrations
    `https://developer.android.com/training/data-storage/room/migrating-db-versions`.
16. **`animateScrollToItem` for jump-to-pinned.** **VERDICT: Verified (framework).** framework ref:
    `https://developer.android.com/reference/kotlin/androidx/compose/foundation/lazy/LazyListState`.

### Corrections made

- §5 rewritten: reaction toggle is one endpoint with `action` (no DELETE-by-emoji); reaction
  details is `…/reactions/details`; unpin is `DELETE …/pin`; pin/unpin/hide return
  `MessageControlActionOut`; pins list returns `ConversationPinOut` refs (paginated); edit uses
  `text` not `body`; revoke is `DELETE …/revoke`; delete returns empty 200; hide is server-side.
- §4.1 domain model: documented that `Reaction`/`MessageLifecycle` are derived (from
  `reactions_counts`/`my_reactions` and `revoked_at`/`edited_at`); `Reactor` uses `user_sub` +
  `profile_photo_url`; corrected timestamp/`text`/`message_id` field names.
- §4.2 repository: signatures corrected (return types `Unit` where the API returns no Message;
  hide is server-backed; pins/hidden are cursor-paginated; reaction toggle takes `add`).
- FR-6 / FR-7 / AC-7 / §6 / §7 / §8 / §13-R1: hide reclassified from local-only to server-backed;
  error-shape split (`MessageControlsErrorOut` vs `HTTPValidationError`) documented.

### Open assumptions

- **`GET …/edits` response shape** — OpenAPI exposes the path but with an empty 200 schema and there
  is no web caller, so the `MessageEdit` field names/order are assumed; must be captured from the live
  dev backend before freezing the DTO.
- **Revoke window / delete-vs-tombstone semantics** — the time window for revoke and whether a deleted
  message later 404s vs returns a tombstone are backend-defined and not expressed in OpenAPI; handle
  both defensively (§7) and confirm against backend behavior.
- **Pin policy via `/config`** (FR-8) — not located in the messaging OpenAPI surface during this review;
  treated as an AND-120 dependency, default-allow if unknown.
- **Android stack/library versions** — project convention, not verifiable from the provided sources.

## 17. Test Plan

Test target legend: **JVM** = JVM unit/Robolectric (local, no device); **emu35** = headless
emulator AVD `test35` (x86_64, API 35) in CI; **A15** = physical Samsung Galaxy A15 5G
(SM-A156U, API 34, arm64-v8a, serial R5CX821TA9R). Contract tests use MockWebServer.

- **TC-AND-140-01** — Reaction toggle add: optimistic write + reconcile.
  Type: contract/MockWebServer (JVM). Target: `MessageActionsRepository.toggleReaction`.
  Preconditions: a cached `MessageEntity` with `reactions_counts={}`; MockWebServer queued
  `POST …/reactions` → 200 empty. Steps: call `toggleReaction(cid,mid,"👍",add=true)`; capture the
  request body and the DAO emissions. Expected: request is `POST …/messages/{mid}/reactions` with
  body `{"emoji":"👍","action":"add"}`; the optimistic Room upsert (count 👍=1, reactedByMe=true)
  emits before the network completes; after 200 the reconciled entity persists. Traces: AC-1.
- **TC-AND-140-02** — Reaction toggle remove + rollback on error.
  Type: contract/MockWebServer (JVM). Target: `toggleReaction`. Preconditions: cached message with
  👍 count=1, reactedByMe=true; MockWebServer → 422 `HTTPValidationError`. Steps: call
  `toggleReaction(...,add=false)`. Expected: request body `action:"remove"`; optimistic removal emits,
  then on 422 the captured prior entity is restored and `ApiResult.Error` is returned for a Snackbar.
  Traces: AC-1, AC-9.
- **TC-AND-140-03** — Reaction details mapping.
  Type: unit/contract (JVM). Target: `reactionDetails` + DTO→`List<Reactor>` mapper. Preconditions:
  MockWebServer `GET …/reactions/details` → `{"reactions":{"👍":[{"user_sub":"u_2","display_name":"Ann","profile_photo_url":null}]}}`.
  Steps: call `reactionDetails(cid,mid)`. Expected: path is `…/reactions/details`; result flattens to
  `Reactor(userSub="u_2", displayName="Ann", profilePhotoUrl=null, emoji="👍")`. Traces: AC-2.
- **TC-AND-140-04** — Pin then unpin: control responses + cache state.
  Type: contract/MockWebServer (JVM). Target: `setPinned`. Preconditions: cached message
  `is_pinned=false`; MockWebServer queues `POST …/pin` → `MessageControlActionOut{action:"pinned"}`
  then `DELETE …/pin` → `{action:"unpinned"}`. Steps: `setPinned(true)` then `setPinned(false)`.
  Expected: methods/paths are POST then DELETE on `…/pin`; response parses `MessageControlActionOut`
  (no Message); cached `is_pinned` toggles true→false and persists. Traces: AC-3.
- **TC-AND-140-05** — Pins list resolves refs (incl. a row not in cache).
  Type: contract/MockWebServer (JVM). Target: `pinnedMessages`. Preconditions: cache has m_1 only;
  `GET …/pins` → items `[{message_id:"m_1",...},{message_id:"m_2",...}]`, then a follow-up message
  fetch for m_2. Steps: call `pinnedMessages(cid)`. Expected: returns 2 Messages newest-pin-first;
  m_2 is fetched because the pins endpoint returns refs, not Messages; cursor handled. Traces: AC-3.
- **TC-AND-140-06** — Edit uses `text` field; stamps edited.
  Type: contract/MockWebServer (JVM). Target: `editMessage`. Preconditions: own message; MockWebServer
  `PATCH …/{mid}` → `MessageOut{text:"hi there", edited_at:1749124900}`. Steps: call
  `editMessage(cid,mid,"hi there")`. Expected: request is `PATCH …/messages/{mid}` with body
  `{"text":"hi there"}` (NOT `body`); mapped Message has body="hi there", lifecycle=EDITED
  (derived from non-null `edited_at`), persisted. Traces: AC-4.
- **TC-AND-140-07** — Delete (empty 200) + 404 reconciles to tombstone.
  Type: contract/MockWebServer (JVM). Target: `deleteMessage`. Preconditions: own message cached;
  case (a) `DELETE …/{mid}` → 200 empty; case (b) a subsequent fetch → 404. Steps: delete after
  confirm; then re-observe. Expected: (a) empty 200 is treated as success and the cached entity is
  marked DELETED locally (no tombstone payload parsed); (b) 404 reconciles to a deleted tombstone
  rather than re-showing the message. Traces: AC-5.
- **TC-AND-140-08** — Revoke via DELETE …/revoke + window-expired 403.
  Type: contract/MockWebServer (JVM). Target: `revokeMessage`. Preconditions: own message; case (a)
  `DELETE …/{mid}/revoke` → `MessageOut{revoked_at:...}`; case (b) → 403. Steps: revoke. Expected:
  (a) method is DELETE on `…/revoke`, mapped Message has lifecycle=REVOKED (derived from `revoked_at`),
  persisted; (b) 403 rolls back and surfaces a precise "Revoke window expired" message. Traces: AC-6, AC-9.
- **TC-AND-140-09** — Hide is server-backed and persists across process death.
  Type: contract/MockWebServer + Room-in-memory (JVM/Robolectric). Target: `setHidden` + thread query.
  Preconditions: cached visible message; `POST …/hide` → `MessageControlActionOut{action:"hidden"}`.
  Steps: call `setHidden(true)`; re-open DAO (simulated restart). Expected: a real `POST …/hide` is
  issued (hide is NOT local-only); thread query excludes the message; `is_hidden` survives reload.
  Then `DELETE …/hide` → `{action:"visible"}` unhides. Traces: AC-7.
- **TC-AND-140-10** — Room migration + hidden flag not clobbered by upsert.
  Type: persistence/migration (Robolectric/instrumented, emu35). Target: `MessageEntity` migration +
  merge logic. Preconditions: DB at prior schema version with existing rows. Steps: run migration;
  set `is_hidden=true` on a row; perform an unrelated `MessageOut` upsert for that row. Expected:
  migration adds new columns with defaults (existing rows survive); the local `is_hidden` flag is
  preserved through the unrelated upsert. Traces: AC-7.
- **TC-AND-140-11** — ViewModel intent → UiState transitions (Turbine).
  Type: unit (JVM). Target: `ThreadViewModel.onAction` + `MessageActionsUiState`. Preconditions: fake
  repo. Steps: dispatch `ToggleReaction`, `OpenReactionDetails`, `SubmitEdit`, `Delete`, `SetHidden`;
  assert `Async` Loading→Success/Error and `transientError` on a repo error. Expected: each intent
  drives the documented state transitions; failures set `transientError`. Traces: AC-1, AC-2, AC-4, AC-5, AC-7, AC-9.
- **TC-AND-140-12** — Affordance gating by `isMine`.
  Type: Compose-UI (emu35). Target: `MessageActionsSheet`. Preconditions: render the sheet for a
  message where `isMine=false`, then `isMine=true`. Steps: long-press → open sheet. Expected: Edit /
  Delete / Revoke are absent for others' messages and present for own; Reactions and Hide present in
  both. Traces: AC-8.
- **TC-AND-140-13** — End-to-end action loop on the thread (long-press → act → persist).
  Type: instrumented/e2e (emu35; or A15 if validating API-34 behavior). Target: Thread screen +
  ViewModel + repo against MockWebServer. Steps: long-press a message → tap 👍 (chip appears,
  highlighted); pin (indicator shows, pins sheet contains it, tap scrolls to it); edit (composer
  prefilled, "edited" label appears, history sheet opens); delete (confirm → tombstone/removed);
  hide (disappears, persists after `recreate()`). Expected: each action updates the thread and
  persists. Traces: AC-1, AC-3, AC-4, AC-5, AC-7.
- **TC-AND-140-14** — Flaky-host / offline behavior on mutations.
  Type: instrumented (A15 — real network toggling via airplane mode). Target: repo + ViewModel.
  Preconditions: stop the backend / enable airplane mode mid-action. Steps: toggle a reaction and
  hide a message while offline (or with a ~20s timeout). Expected: optimistic UI applies, then on
  timeout/network error the change rolls back with a retry-able Snackbar; no automatic retry of these
  non-idempotent mutations (AND-016 covers GETs only); read sheets may use bounded backoff. MUST run
  on A15 to exercise real radio/airplane-mode transitions. Traces: AC-1, AC-7, AC-9.
- **TC-AND-140-15** — CSRF header on mutations.
  Type: contract/MockWebServer (JVM). Target: OkHttp CSRF interceptor (AND-012) on these calls.
  Preconditions: `ui_csrf` cookie present in the jar. Steps: invoke reaction/pin/edit/delete/revoke/hide.
  Expected: every recorded request carries `X-CSRF-Token` equal to the `ui_csrf` cookie value and sends
  the session cookie. Traces: AC-9.
- **TC-AND-140-16** — Accessibility of action UI.
  Type: Compose-UI / instrumented a11y (emu35; TalkBack pass on A15). Target: chips, pin indicator,
  "edited" label, action sheet, confirm dialogs. Steps: run Compose semantics assertions + a TalkBack
  sweep. Expected: reaction chips announce emoji + count + "you reacted"; pin indicator announces
  pinned state; "edited" is a focusable element opening history; all targets ≥48dp; dialogs reachable
  and dismissible; RTL-safe. TalkBack verification SHOULD run on A15. Traces: AC-1, AC-3, AC-4 (and the §9 a11y bar).

### Coverage matrix

| Acceptance criterion | Covered by |
| --- | --- |
| AC-1 (reaction toggle: update + persist + rollback) | TC-01, TC-02, TC-11, TC-13, TC-14, TC-16 |
| AC-2 (reaction details from GET …/reactions/details) | TC-03, TC-11 |
| AC-3 (pin/unpin + pins list + jump-to) | TC-04, TC-05, TC-13, TC-16 |
| AC-4 (edit + "edited" + history newest-first) | TC-06, TC-11, TC-13, TC-16 |
| AC-5 (delete + 404→tombstone) | TC-07, TC-11, TC-13 |
| AC-6 (revoke within window + window-expired error) | TC-08 |
| AC-7 (hide server-backed + persist + unhide + flag preserved) | TC-09, TC-10, TC-11, TC-13, TC-14 |
| AC-8 (Edit/Delete/Revoke gated to own messages) | TC-12 |
| AC-9 (CSRF header + FastAPI detail mapping + no crash) | TC-02, TC-08, TC-11, TC-14, TC-15 |
