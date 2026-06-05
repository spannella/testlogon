---
id: AND-140
title: Reactions, pins, edits, delete/revoke
milestone: M3
epic: E19
priority: P1
size: L
status: draft
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

FR-6 **Hide.** Hide is a **client-local** action (no destructive backend call): it
suppresses a message from this user's thread view. Hidden message ids persist in the
local cache so the message stays hidden across restarts. A way to unhide is available
from a small "hidden message" affordance.

FR-7 **Optimism & reconciliation.** All six actions apply optimistically to thread
state, then reconcile with the server response. Non-2xx (for the non-local actions)
rolls the change back and surfaces a transient error. Each successful action's
resulting message state is written to Room.

FR-8 **Permissions/affordance gating.** Edit/Delete/Revoke appear only for messages
authored by the current user (`message.isMine`). Pin appears per conversation policy
exposed by `/config` (AND-120); if unknown, default to allowing pin. Reactions and
Hide are available on any message.

## 4. Technical Design

All new code lives under `feature-messaging` with DTO/API additions in `core-network`
and persistence in `core-data`.

### 4.1 Domain model additions (core-model)

```kotlin
data class Reaction(val emoji: String, val count: Int, val reactedByMe: Boolean)

data class Reactor(val userId: String, val displayName: String, val emoji: String)

data class MessageEdit(val revision: Int, val body: String, val editedAt: Instant)

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
    suspend fun toggleReaction(conversationId: String, messageId: String, emoji: String): ApiResult<Message>
    suspend fun reactionDetails(conversationId: String, messageId: String): ApiResult<List<Reactor>>
    suspend fun setPinned(conversationId: String, messageId: String, pinned: Boolean): ApiResult<Message>
    suspend fun pinnedMessages(conversationId: String): ApiResult<List<Message>>
    suspend fun editMessage(conversationId: String, messageId: String, body: String): ApiResult<Message>
    suspend fun editHistory(conversationId: String, messageId: String): ApiResult<List<MessageEdit>>
    suspend fun deleteMessage(conversationId: String, messageId: String): ApiResult<Message>
    suspend fun revokeMessage(conversationId: String, messageId: String): ApiResult<Message>
    suspend fun setHiddenLocal(messageId: String, hidden: Boolean) // local-only, no ApiResult
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

Exact paths must be confirmed against `/openapi.json`; the shapes below follow the
`frontend/src/api/endpoints/messaging.ts` reference and the AND-120 base
(`/messaging/conversations/{conversationId}/messages/{messageId}`). All are non-GET
mutations except the three read endpoints, so they are **not** eligible for the
idempotent-GET retry policy (AND-016).

```
POST   /messaging/conversations/{cid}/messages/{mid}/reactions      {"emoji":"👍"}
DELETE /messaging/conversations/{cid}/messages/{mid}/reactions/{emoji}
GET    /messaging/conversations/{cid}/messages/{mid}/reactions      -> reactor list
POST   /messaging/conversations/{cid}/messages/{mid}/pin
POST   /messaging/conversations/{cid}/messages/{mid}/unpin
GET    /messaging/conversations/{cid}/pins                          -> pinned messages
PATCH  /messaging/conversations/{cid}/messages/{mid}               {"body":"..."}
GET    /messaging/conversations/{cid}/messages/{mid}/edits          -> edit history
DELETE /messaging/conversations/{cid}/messages/{mid}               -> delete
POST   /messaging/conversations/{cid}/messages/{mid}/revoke         -> revoke
```

Representative response shapes (Moshi DTOs in `core-network`):

```json
// toggle reaction (POST/DELETE) -> updated message
{ "id":"m_1","conversation_id":"c_1","sender_id":"u_2","body":"hi",
  "created_at":"2026-06-05T12:00:00Z","edited_at":null,"pinned":false,
  "state":"active",
  "reactions":[{"emoji":"👍","count":3,"reacted_by_me":true}] }

// GET reactions -> reactors
{ "reactions":[{"emoji":"👍","users":[{"user_id":"u_2","display_name":"Ann"}]}] }

// GET edits -> history (newest first)
{ "edits":[{"revision":2,"body":"hi there","edited_at":"2026-06-05T12:05:00Z"},
            {"revision":1,"body":"hi","edited_at":"2026-06-05T12:01:00Z"}] }

// delete/revoke -> tombstone message
{ "id":"m_1","state":"deleted","body":null, ... }   // or "state":"revoked"
```

DTOs map to domain via the AND-126 mapper, extended here:
`MessageDto.state` → `MessageLifecycle`; `reacted_by_me` → `Reaction.reactedByMe`;
absent/null `body` with `state in {deleted,revoked}` → tombstone rendering. The reactor
GET response is flattened from `{emoji,users[]}` to `List<Reactor>`. Hide has **no**
endpoint — it is local-only.

## 6. Data & State Management

- **Room (AND-115).** `MessageEntity` gains columns: `reactions_json` (TEXT, Moshi-
  serialized `List<Reaction>`), `is_pinned` (INTEGER), `lifecycle` (TEXT),
  `edited_at` (INTEGER nullable), `is_hidden_local` (INTEGER). Provide a Room migration
  (schema version bump, exported schema) with `ALTER TABLE` defaults so existing cached
  rows survive. `is_hidden_local` is **never** overwritten by a server upsert — server
  mappers must preserve it (merge by reading the existing row's flag before upsert).
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

- Map FastAPI `detail` (string | `[{msg}]` | `{code,...}`) via AND-015. Surface as a
  Snackbar (`transientError`) and roll back the optimistic mutation.
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
- **Hide** never fails on network (local-only) and is always applied immediately.

## 8. Security & Privacy

- All requests carry the cookie session + `X-CSRF-Token` from the `ui_csrf` cookie via
  the existing CSRF interceptor (AND-012) and persistent cookie jar (AND-011); these
  mutations are state-changing and must send the CSRF header.
- Authorization is enforced server-side; the client only gates *affordances*
  (`isMine`, pin policy) for UX — never assume client gating is a security boundary.
- Reaction details expose other users' identities; only display fields the backend
  returns (no client-side enrichment from other caches).
- No message bodies, emojis, edit contents, or user ids are logged (see §10).
- Hidden-message ids are local UX state only; they carry no security meaning and are
  fine to store unencrypted in the app's Room DB.

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

- **R1 — Endpoint shapes unverified.** Exact paths/payloads for reactions, pins, edits,
  delete vs revoke must be confirmed against `/openapi.json`; the §5 shapes are
  reference-derived. *Mitigation:* contract tests against captured fixtures; adjust DTOs
  once OpenAPI is checked.
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
AC-7 Hide suppresses a message locally, persists the hidden flag across process death,
and offers an unhide affordance; the flag is not clobbered by server upserts. (Tested.)
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
