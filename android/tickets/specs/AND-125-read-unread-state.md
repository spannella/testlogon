---
id: AND-125
title: Read / unread state
milestone: M3
epic: E18
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-123]
blocks: []
---

# AND-125 — Read / unread state

## 1. Overview & Goal

This ticket adds **read / unread state management** to the TestLogon Android
messaging feature. When a user opens a conversation thread (the screen delivered
by AND-123), the app must mark that conversation as read on the backend via
`POST /messaging/conversations/{conversation_id}/read` and reflect the change
locally so that:

> **Review note (AND-125):** the path is `/messaging/conversations/{conversation_id}/read`
> (the `/messaging` prefix and `conversation_id` param name are confirmed against
> the OpenAPI index; an earlier draft omitted `/messaging`). The request marker
> is `last_read_at` (a numeric timestamp), **not** `last_read_message_id`, and the
> success response has **no body**. See §5 and §16 for the corrections.

- the per-conversation unread badge on the conversation-list row (AND-121)
  clears,
- the aggregate unread count surfaced by the list ViewModel (AND-122) — and any
  navigation badge that consumes it — decrements correctly,
- the change survives process death and is consistent across the cached and
  in-memory representations.

The goal is a **single source of truth** for unread state that updates
optimistically on thread open, reconciles against the server response, and
degrades gracefully when the unreliable dev backend is slow or offline. The work
sits entirely in `feature-messaging` and `core-data`; it introduces no new
screens. Success means: opening a thread marks it read, the badge disappears
within one frame, and the aggregate unread counter recomputes — all verifiable
in unit tests against fixtures and the existing fake API.

## 2. Context & References

- **Epic E18 (Messaging), Milestone M3.** This ticket is the read-state slice of
  the messaging feature.
- **Hard dependency: AND-123** (Thread / message-list screen). The mark-read
  trigger is wired into the thread screen's lifecycle and ViewModel.
- **Upstream context (already shipped in M3):**
  - **AND-120** — `MessagingApi` Retrofit interface + DTOs for
    `/messaging/conversations`, `/conversations/{id}`,
    `/conversations/{id}/messages`, `/config`. AND-125 extends this interface
    with the `read` endpoint.
  - **AND-121** — Conversation list screen: renders the unread badge this ticket
    must clear.
  - **AND-122** — Conversation list ViewModel + Paging 3 source; performs
    **unread aggregation** that this ticket must keep correct.
  - **AND-126** — Message domain model + mappers (parallel; not a dependency,
    but shares `core-model`).
- **Platform plumbing (M1):** `ApiResult<T>` (AND-018), FastAPI `detail`
  mapping (AND-015), CSRF interceptor (AND-012), 401-refresh authenticator
  (AND-013), persistent cookie jar (AND-011), Room cache (core-data),
  connectivity probe (AND-017).
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable). OpenAPI at `/openapi.json`. Web reference for the
  read endpoint contract: `frontend/src/api/endpoints/messaging.ts` and shared
  types in `frontend/src/api/types.ts`.
- **Namespace:** `com.testlogon.android`.

## 3. Functional Requirements

**FR-1 — Mark read on thread open.** When the thread screen for conversation
`id` becomes active (first composition / `ON_START`), if the conversation's
cached `unreadCount > 0`, the app issues
`POST /messaging/conversations/{conversation_id}/read`. *(Verified: the web
client gates the call on `unread_count > 0` identically — `ConversationView.tsx`
line 303.)*

**FR-2 — Idempotent re-entry.** Re-opening an already-read thread (cached
`unreadCount == 0`) must **not** issue a redundant network call within the same
session. A conversation that becomes unread again (new inbound message) re-arms
the trigger.

**FR-3 — Optimistic local clear.** On trigger, immediately set the
conversation's local `unreadCount = 0` and `isUnread = false` so the list badge
clears without waiting for the network.

**FR-4 — Server reconciliation.** On a successful response, persist the
server-authoritative state (`unread_count`, `last_read_message_id`,
`last_read_at`). On failure, the optimistic clear is **retained** locally (read
intent is not lost) but flagged dirty for a later sync attempt; the failure is
not surfaced as a blocking error to the user.

**FR-5 — Aggregate recompute.** The aggregate unread count consumed by the
conversation-list ViewModel (AND-122) must recompute reactively from the same
data source so the global badge stays consistent.

**FR-6 — Read marker position.** The request marks read up to the newest message
known to the client. **Corrected:** the marker the web client actually sends is
`last_read_at` — the numeric `created_at` timestamp of the most recent message in
the thread page (`markRead(convoId, lastMsg.created_at)`,
`src/api/endpoints/messaging.ts` line 489 / `ConversationView.tsx` line 303), not
a `last_read_message_id`. The backend `MarkReadIn` schema accepts **both**
`last_read_at` (integer, nullable) and `last_read_message_id` (string, nullable);
the Android client SHOULD mirror the web client and send `last_read_at`. If no
message is loaded yet, send `null` (omit the marker) and the server marks the
whole conversation read.

**FR-7 — Read-receipt config gate.** *(Corrected / cannot be implemented as
originally written.)* The earlier draft gated the network call on a
`read_receipts_enabled` flag from `/messaging/config`. **No such field exists**
in `MessagingConfigOut` (its booleans are `messaging_dm_lottery_enabled`,
`messaging_encrypted_messages_enabled`, `messaging_gallery_enabled`,
`messaging_hide_controls_enabled`, `messaging_mass_send_enabled`,
`messaging_pins_enabled`, `messaging_reporting_enabled`). The web client does
**not** gate mark-read on any config flag — it always POSTs when
`unread_count > 0`. Therefore AND-125 ships **without** a read-receipt config
gate: always attempt the mark-read POST after the optimistic local clear. (If a
read-receipt privacy flag is added to `/messaging/config` later, re-introduce
the gate; tracked as an open assumption in §16.)

## 4. Technical Design

All new code lives in `:feature-messaging` and `:core-data`; the API surface
extends `:core-network`.

### 4.1 API extension (core-network, builds on AND-120)

```kotlin
// com.testlogon.android.core.network.messaging.MessagingApi
interface MessagingApi {
    // ...existing AND-120 endpoints...

    // Corrected: path is "messaging/conversations/{conversation_id}/read";
    // success body is empty (200 with no schema) -> Response<Unit>.
    @POST("messaging/conversations/{conversation_id}/read")
    suspend fun markConversationRead(
        @Path("conversation_id") conversationId: String,
        @Body body: MarkReadRequestDto,
    ): Response<Unit>
}
```

> **Verified against OpenAPI:** `POST /messaging/conversations/{conversation_id}/read`
> (op `mark_read_messaging_conversations__conversation_id__read_post`),
> `req=app__routers__messaging__MarkReadIn`, `resp=200:` (empty schema) and
> `422:HTTPValidationError`. The success response carries **no body**, so there is
> no `MarkReadResponseDto` to deserialize.

### 4.2 Repository (core-data)

The repository owns the optimistic-then-reconcile logic and is the single source
of truth. It reads/writes the Room `conversations` cache (owned by AND-122) and
exposes a Flow of the aggregate.

```kotlin
// com.testlogon.android.core.data.messaging.MessagingRepository
interface MessagingRepository {
    /**
     * Optimistically clears unread, then syncs to server. Safe to call repeatedly.
     * Corrected: the marker is a numeric `last_read_at` timestamp (the newest
     * loaded message's `created_at`), mirroring the web client — not a message id.
     */
    suspend fun markConversationRead(
        conversationId: String,
        lastReadAt: Long?,
    ): ApiResult<Unit>

    /** Reactive total of unread conversations (or unread messages, per config). */
    fun observeTotalUnread(): Flow<Int>

    /** Retries any conversations left dirty (read intent not yet synced). */
    suspend fun syncPendingReads(): Unit
}
```

Implementation outline:

```kotlin
override suspend fun markConversationRead(
    conversationId: String,
    lastReadAt: Long?,
): ApiResult<Unit> = withContext(io) {
    val local = conversationDao.getById(conversationId) ?: return@withContext ApiResult.Success(Unit)
    if (local.unreadCount == 0 && !local.readDirty) return@withContext ApiResult.Success(Unit) // FR-2

    conversationDao.applyOptimisticRead(conversationId, dirty = true) // FR-3, sets unreadCount=0,isUnread=false

    // FR-7 corrected: no `read_receipts_enabled` flag exists in /messaging/config,
    // and the web client never gates on config — always attempt the POST.
    when (val r = apiCall { api.markConversationRead(conversationId, MarkReadRequestDto(lastReadAt, null)) }) {
        is ApiResult.Success -> {
            // Corrected: success has no body. Persist our own read marker and
            // clear dirty; the authoritative `unread_count` is re-fetched via the
            // conversation list / GET conversation, not returned by this endpoint.
            conversationDao.applyLocalReadCommitted(conversationId, lastReadAt) // FR-4
            ApiResult.Success(Unit)
        }
        is ApiResult.Error -> ApiResult.Error(r.error) // keep optimistic clear + dirty flag (FR-4)
        is ApiResult.Loading -> ApiResult.Loading
    }
}
```

`apiCall { ... }` is the shared wrapper from AND-018/AND-015 that maps
`Response<T>` → `ApiResult<T>` and FastAPI `detail` → typed errors.
`POST` is **not** retried by the idempotent-GET backoff (AND-016); it is retried
only by `syncPendingReads()`.

### 4.3 ViewModel + screen wiring (feature-messaging, on AND-123)

The thread screen owns a `ThreadViewModel` (AND-123). AND-125 adds a one-shot
read effect:

```kotlin
// com.testlogon.android.feature.messaging.thread.ThreadViewModel
fun onThreadVisible() {
    if (readMarked) return                         // FR-2 in-session guard
    readMarked = true
    viewModelScope.launch {
        // Corrected: pass the newest loaded message's created_at (epoch) as the
        // last_read_at marker (mirrors web ConversationView.tsx), not a message id.
        repo.markConversationRead(conversationId, newestMessageCreatedAt())
    }
}
```

```kotlin
// In ThreadScreen composable
val lifecycleOwner = LocalLifecycleOwner.current
DisposableEffect(lifecycleOwner, conversationId) {
    val obs = LifecycleEventObserver { _, e ->
        if (e == Lifecycle.Event.ON_START) viewModel.onThreadVisible()
    }
    lifecycleOwner.lifecycle.addObserver(obs)
    onDispose { lifecycleOwner.lifecycle.removeObserver(obs) }
}
```

`readMarked` resets when a new inbound message arrives while the thread is open
(re-arming FR-2). The conversation-list ViewModel (AND-122) consumes
`observeTotalUnread()` and exposes it in its `UiState` for badge rendering.

### 4.4 Threading & lifecycle

DB writes run on the IO dispatcher; the optimistic UI update flows back through
the Room-backed Flow on the main dispatcher. The network call is fire-and-forget
from the UI's perspective (no spinner, no blocking).

## 5. API Contract

### 5.1 `POST /messaging/conversations/{conversation_id}/read`

*(Path, schemas, and response shape below are verified against the OpenAPI spec
and the web reference; an earlier draft had the path, request DTO, and response
DTO wrong — corrections noted inline.)*

Auth: cookie session + `X-CSRF-Token` (echo of `ui_csrf`); on `401` the
authenticator (AND-013) calls `POST /ui/session/refresh` once and retries.
**Verified** against `src/api/client.ts`: CSRF token read from the `ui_csrf`
cookie and sent as `X-CSRF-Token`, all calls use `credentials: "include"`, and a
401 triggers a single `POST /ui/session/refresh` then one retry.

**Path param:** `conversation_id` — conversation id (string). *(Corrected from
`id`.)*

**Request body** (`MarkReadIn`; required body per OpenAPI):

```json
{ "last_read_at": 1749132202, "last_read_message_id": null }
```

The backend `MarkReadIn` schema has two nullable fields: `last_read_at`
(integer) and `last_read_message_id` (string). The web client sends only
`last_read_at` (the newest message's `created_at`). Sending `null` for both marks
the whole conversation read (FR-6). *(Corrected: the original draft's body used
only `last_read_message_id`.)*

**Success `200`:** **empty / untyped body** (OpenAPI `resp=200:` with `schema {}`).
There is **no** `MarkReadResponseDto`; do not attempt to parse a JSON object with
`conversation_id` / `unread_count` (those are returned by `GET .../conversations`
and `GET .../conversations/{conversation_id}` via `ConversationOut.unread_count`,
not by this endpoint). The authoritative post-read `unread_count` is reconciled
by re-reading the conversation list, not from this response. *(Corrected: the
original draft invented a `MarkReadResponseDto` body.)*

**DTOs (Moshi):**

```kotlin
@JsonClass(generateAdapter = true)
data class MarkReadRequestDto(
    @Json(name = "last_read_at") val lastReadAt: Long?,
    @Json(name = "last_read_message_id") val lastReadMessageId: String? = null,
)

// No response DTO: api.markConversationRead returns Response<Unit>.
```

**Error shapes** (mapped via AND-015 to `ApiError`):

- `422` → FastAPI validation `{"detail":[{"msg": "...","loc":[...],"type":"..."}]}`
  → `HTTPValidationError`. **This is the only non-200 response documented in
  OpenAPI for this op.**
- `401` → refresh-and-retry; if still 401 → `ApiError.Unauthorized`. *(Inferred
  from the global auth pipeline / AND-013; not enumerated on this op in OpenAPI —
  unverified for this specific path but consistent with platform behavior.)*
- `403` → CSRF/permission → `ApiError.Forbidden`. *(Unverified for this op; not
  in OpenAPI responses. Handle defensively.)*
- `404` → conversation gone → treat as read locally, clear dirty, log warn.
  *(Unverified for this op; not in OpenAPI responses. Defensive handling.)*
- `5xx` / timeout / IO → `ApiError.Network` / `ApiError.Server`; optimistic
  clear retained, dirty flag set.

## 6. Data & State Management

**Room (core-data, table owned by AND-122).** Extend `ConversationEntity` if not
already present:

```kotlin
@Entity(tableName = "conversations")
data class ConversationEntity(
    @PrimaryKey val id: String,
    val unreadCount: Int,
    val isUnread: Boolean,
    val lastReadMessageId: String?,
    val lastReadAt: Long?,        // epoch millis
    val readDirty: Boolean = false, // read intent not yet synced (FR-4)
    // ...existing list/preview columns...
)
```

DAO operations:

```kotlin
@Query("UPDATE conversations SET unreadCount = 0, isUnread = 0, readDirty = :dirty WHERE id = :id")
suspend fun applyOptimisticRead(id: String, dirty: Boolean)

@Query("SELECT COALESCE(SUM(CASE WHEN unreadCount > 0 THEN 1 ELSE 0 END), 0) FROM conversations")
fun observeUnreadConversationCount(): Flow<Int>

@Query("SELECT * FROM conversations WHERE readDirty = 1")
suspend fun getDirty(): List<ConversationEntity>
```

`applyLocalReadCommitted(id, lastReadAt)` records the committed read marker
(`lastReadAt`) and sets `readDirty = 0`. **Corrected:** since the endpoint returns
no body, there is no server DTO to apply — the authoritative `unread_count` is
reconciled later from `ConversationOut.unread_count` (GET conversation / list),
not from the read response.

**State exposure.** `observeTotalUnread()` returns the DAO Flow; the
conversation-list `UiState` (AND-122) carries `totalUnread: Int`. The thread
screen does not display unread state — it only triggers the mark. **DataStore is
not used** here (unread is server-derived, cache-backed). A Room schema
migration (version bump) adds the `lastReadMessageId`, `lastReadAt`, `readDirty`
columns if they do not already exist from AND-122.

## 7. Error Handling & Resilience

- **Optimistic-first:** UI never waits on the network; the badge clears
  immediately (FR-3).
- **Failure is silent to the user:** a failed `read` POST does not show an error
  banner — the user already sees the thread. Optimistic clear is retained and
  `readDirty = true` (FR-4).
- **Timeouts:** rely on the global ~20s OkHttp timeout (AND-009). No per-call
  retry of the POST (non-idempotent path is excluded from AND-016 backoff).
- **Deferred sync:** `syncPendingReads()` re-POSTs all `readDirty` rows; invoked
  on conversation-list refresh (pull-to-refresh from AND-121), on app foreground,
  and after the connectivity probe (AND-017) reports the backend reachable
  again. Each dirty row is reconciled or left dirty.
- **404:** conversation deleted server-side → clear dirty, drop locally; warn
  log only.
- **Offline:** detected via AND-017; the optimistic clear stands and the row
  stays dirty until connectivity returns.

## 8. Security & Privacy

- All requests ride the existing cookie session; the CSRF interceptor (AND-012)
  attaches `X-CSRF-Token` from the `ui_csrf` cookie. No new credentials.
- Dev backend is **plaintext HTTP** — acceptable only for the dev flavor; the
  cleartext allowance is already gated by build flavor (AND-006). No secrets are
  added to the body (only a message id).
- Read receipts are **other-user-visible metadata**: gating on
  `read_receipts_enabled` (FR-7) respects the server privacy setting. No read
  state is logged with message content.
- No PII is added to logs or telemetry beyond opaque conversation/message ids.

## 9. Accessibility & i18n

This ticket adds **no new visible UI**; it mutates an existing badge.
Requirements are on the consuming screens (AND-121/AND-122) but AND-125 must not
regress them:

- The unread badge must expose a content description that updates with the count
  (e.g. `"3 unread messages"` → cleared/absent when 0). The badge node should
  toggle its `semantics` rather than only its color, so a screen reader announces
  the change.
- All count and label strings come from `strings.xml`
  (`feature-messaging`); use plurals (`<plurals name="unread_count">`) for the
  count. No hardcoded English.
- Numbers are formatted with the device locale (`NumberFormat`).

## 10. Telemetry & Logging

- **Events** (via the app analytics facade, if present in M3; else Timber debug
  logs only):
  - `messaging_thread_read` `{conversation_id, had_unread: Boolean, marker_present: Boolean}`
  - `messaging_read_sync_failed` `{conversation_id, error_type}` (on POST
    failure, sampled).
  - `messaging_pending_read_synced` `{count}` (on `syncPendingReads`).
- **Logs:** Timber `d` for the optimistic clear, `w` for failure/404, no message
  body or username ever logged. Conversation/message ids only.
- OkHttp body logging stays at the level set in AND-009 (dev flavor only).

## 11. Testing Strategy

**Unit (core-data, JUnit + Turbine + fake `MessagingApi`):**

1. `markConversationRead` on an unread conversation → DAO `unreadCount` becomes
   `0`, `isUnread=false`, POST issued once (FR-1, FR-3).
2. Re-call on an already-read, non-dirty conversation → **no** POST (FR-2).
3. Success response → `applyServerRead` persists `lastReadMessageId`,
   `lastReadAt`; `readDirty=false` (FR-4).
4. Error response (500/IO) → optimistic clear retained, `readDirty=true`, no
   exception thrown (FR-4).
5. *(Corrected — no config gate exists.)* Mark-read always attempts the POST
   after the optimistic clear; there is no `read_receipts_enabled` short-circuit
   (FR-7 corrected). Test that a config response lacking any read-receipt flag
   does not suppress the POST.
6. `last_read_at` is set from the newest message's `created_at` and serialized as
   `{"last_read_at":<epoch>,"last_read_message_id":null}`; the null-marker path
   (no message loaded) sends `{"last_read_at":null,"last_read_message_id":null}`
   (FR-6).
7. `observeTotalUnread()` emits the recomputed aggregate after a clear (FR-5) —
   asserted with Turbine.
8. `syncPendingReads()` re-POSTs only dirty rows and reconciles them.

**ViewModel (feature-messaging):**

9. `onThreadVisible()` calls the repo once even across multiple `ON_START`
   events in one session; re-arms after a new inbound message.

**Moshi:** serialize `MarkReadRequestDto` and assert it matches the committed
request fixture (`{"last_read_at":...,"last_read_message_id":null}`). There is no
response DTO to round-trip (success body is empty). Fixtures committed under
`core-testing` resources (extends AND-120 fixtures).

**Instrumented (optional, smoke):** open thread from list (AND-121) → badge node
loses its unread semantics. Run on the build server CI (AND-008).

Coverage target: repository read logic and aggregate recompute ≥ 90% lines.

## 12. Dependencies & Sequencing

- **Depends on AND-123** (thread screen + `ThreadViewModel` to host the
  trigger). Hard blocker.
- **Builds on AND-120** (`MessagingApi`, DTOs, `/config`), **AND-122**
  (`ConversationEntity`, conversation DAO, aggregation, Paging), **AND-121**
  (badge UI), and platform tickets AND-009/011/012/013/015/016/017/018.
- **Blocks:** nothing in the current backlog. (No `blocks` entries.)
- **Sequencing:** land after AND-123 merges; coordinate the `ConversationEntity`
  column additions with AND-122's schema (single migration, no duplicate
  columns). Can proceed in parallel with AND-124 (send) and AND-126 (message
  model) since they touch disjoint repository methods.

## 13. Risks & Open Questions

- **R1 — Endpoint contract uncertainty.** **RESOLVED in this review.** Path is
  `POST /messaging/conversations/{conversation_id}/read`; it takes a required JSON
  body (`MarkReadIn`: `last_read_at` int? + `last_read_message_id` string?) and
  returns `200` with an **empty body** (no DTO). The web client sends
  `{ last_read_at: <newest msg created_at> }`
  (`src/api/endpoints/messaging.ts` line 489). See §5 and §16.
- **R2 — Unread semantics: conversations vs messages.** AND-122 may aggregate by
  unread-conversation count or unread-message count; AND-125 must mirror whatever
  AND-122 chose. *Mitigation:* reuse AND-122's DAO aggregate, do not introduce a
  second formula. **Open — confirm with AND-122.**
- **R3 — Read marker race.** Paging may not yet have loaded the newest message
  when the thread opens, so `last_read_message_id` could lag. *Mitigation:* send
  `null` (mark whole conversation) when no id is available (FR-6); optionally
  re-mark when the newest page resolves.
- **R4 — Dirty-flag thrash on a flaky backend.** Repeated failures keep rows
  dirty. *Mitigation:* `syncPendingReads()` is bounded (runs on refresh /
  foreground / connectivity-restored, not in a tight loop).
- **R5 — Read receipts privacy default.** **RESOLVED / obsolete.**
  `MessagingConfigOut` has **no** `read_receipts_enabled` field, and the web
  client never gates mark-read on config. AND-125 always attempts the POST after
  the optimistic clear (FR-7 corrected). If a read-receipt privacy flag is added
  server-side later, re-introduce the gate (tracked in §16 Open assumptions).

## 14. Acceptance Criteria

1. **Opening a thread marks read.** Opening a conversation with `unreadCount > 0`
   issues exactly one `POST /messaging/conversations/{conversation_id}/read`
   (with `last_read_at` = newest message `created_at`) and the conversation's
   local `unreadCount` becomes `0`. *(FR-1, FR-3; matches source acceptance
   "Opening a thread marks read".)*
2. **Counts update.** The per-row unread badge clears and the aggregate unread
   count exposed by the list ViewModel decrements accordingly, reactively, within
   one frame of opening the thread. *(FR-5; matches "counts update".)*
3. **No redundant calls.** Re-opening an already-read thread in the same session
   issues no network call. *(FR-2.)*
4. **Failure resilience.** A failed `read` POST does not surface a blocking
   error; the optimistic clear is retained and the row is marked dirty.
5. **Deferred sync.** `syncPendingReads()` re-POSTs dirty rows and reconciles
   them on the next list refresh / foreground / connectivity restoration.
6. **No config-gate regression.** *(Corrected — see §16.)* There is no
   `read_receipts_enabled` flag in `/messaging/config`; mark-read always attempts
   the POST after the optimistic clear. AC met when a `/messaging/config` response
   (with or without any future read-receipt flag) does not suppress the POST and
   the local clear still occurs.
7. **Tested.** Unit tests in §11 (items 1–9 + Moshi round-trip) pass in CI
   (AND-008); read-path coverage ≥ 90% lines.

## 15. Definition of Done

- `MessagingApi.markConversationRead` (returns `Response<Unit>`),
  `MarkReadRequestDto` (`last_read_at`, `last_read_message_id`; no response DTO),
  and repository methods
  (`markConversationRead`, `observeTotalUnread`, `syncPendingReads`) implemented
  under `com.testlogon.android.*` and merged to `android-port`.
- `ConversationEntity` columns + DAO queries + Room migration landed without
  conflicting with AND-122; app upgrades cleanly from the prior schema version.
- Thread screen (AND-123) triggers mark-read on `ON_START` with the in-session
  guard; conversation-list ViewModel (AND-122) consumes the aggregate.
- All unit/ViewModel/Moshi tests in §11 green on the CI build server; ktlint +
  detekt (AND-005) clean; KSP/Hilt build passes.
- No regression to AND-121/AND-122 badge accessibility semantics.
- Endpoint contract verified against `/openapi.json` and the web reference
  (R1/R2/R5 resolved or explicitly deferred with follow-up notes).
- No message content, username, or PII in logs or telemetry.
- Code reviewed and merged; spec status moved from `draft` to `done`.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer.

1. **Endpoint path is `POST /messaging/conversations/{conversation_id}/read`.**
   VERDICT: **Corrected** (original draft used `POST /conversations/{id}/read`,
   missing the `/messaging` prefix and using `id` instead of `conversation_id`).
   SOURCE: OpenAPI index `POST /messaging/conversations/{conversation_id}/read`
   (op `mark_read_messaging_conversations__conversation_id__read_post`); frontend
   `src/api/endpoints/messaging.ts: markRead` (line 489–490).

2. **Request body schema is `MarkReadIn` with nullable `last_read_at` (integer)
   and `last_read_message_id` (string); body is required.** VERDICT: **Verified.**
   SOURCE: OpenAPI `components.schemas.app__routers__messaging__MarkReadIn`
   (openapi.pretty.json line 85939); request body `required: true` referencing
   that schema (openapi.pretty.json line ~119372–119381).

3. **The marker the client sends is `last_read_at` (newest message `created_at`
   timestamp), NOT `last_read_message_id`.** VERDICT: **Corrected** (original FR-6
   and §5 built the design around `last_read_message_id`). SOURCE:
   `src/api/endpoints/messaging.ts: markRead` — `api.post(.../read, { last_read_at: lastReadAt })`
   (line 489–490); `src/pages/messages/ConversationView.tsx` line 303 —
   `markRead(convoId, lastMsg.created_at)`.

4. **Success response has an empty/untyped body (no `MarkReadResponseDto`).**
   VERDICT: **Corrected** (original draft invented a `200` JSON object with
   `conversation_id` / `unread_count` / `last_read_message_id` / `last_read_at`).
   SOURCE: OpenAPI index `resp=200:` (no schema); openapi.pretty.json responses
   `"200": { "content": { "application/json": { "schema": {} } } }`
   (line ~119382–119390).

5. **`POST /messaging/config` has no `read_receipts_enabled` flag; the web client
   does not gate mark-read on any config flag.** VERDICT: **Corrected** (FR-7,
   AC-6, R5 all assumed such a flag). SOURCE: OpenAPI
   `components.schemas.MessagingConfigOut` (openapi.pretty.json line 51378) —
   fields are `messaging_dm_lottery_enabled`, `messaging_encrypted_messages_enabled`,
   `messaging_gallery_enabled`, `messaging_hide_controls_enabled`,
   `messaging_mass_send_enabled`, `messaging_pins_enabled`,
   `messaging_reporting_enabled`; `src/pages/messages/ConversationView.tsx`
   line 300–305 (no config gate around `markRead`).

6. **Auth: cookie session + `X-CSRF-Token` echoed from the `ui_csrf` cookie;
   `credentials: include` on every call.** VERDICT: **Verified.** SOURCE:
   `src/api/client.ts` — `getCookie("ui_csrf")` then
   `headers.set("X-CSRF-Token", csrf)` (lines 167–170); `credentials: "include"`
   (lines 183, 220).

7. **On 401 the client refreshes once via `POST /ui/session/refresh` then retries
   the original request once.** VERDICT: **Verified.** SOURCE: `src/api/client.ts`
   `refreshSession()` posts `/ui/session/refresh` with `method: "POST"` (lines
   121–125); 401 handling refresh-then-retry (lines 191–225).

8. **Mark-read is fired only when the conversation has `unread_count > 0`, and
   failures are silently swallowed.** VERDICT: **Verified.** SOURCE:
   `src/pages/messages/ConversationView.tsx` lines 300–305 —
   `if (lastMsg && (conversation.unread_count ?? 0) > 0) markRead(...).catch(() => {})`.

9. **`ConversationOut.unread_count` is an integer (default 0); the conversation id
   field is `conversation_id`.** VERDICT: **Verified.** SOURCE: OpenAPI
   `components.schemas.ConversationOut.unread_count` (openapi.pretty.json line
   19670: `default 0`, `type integer`); required `conversation_id`
   (line 19677).

10. **Only `422 HTTPValidationError` is a documented non-200 response for this
    op.** VERDICT: **Verified** (for documented responses). SOURCE: OpenAPI index
    line 376 `resp=200:;422:HTTPValidationError`; openapi.pretty.json responses
    block (lines ~119382–119400). 401/403/404 handling for this path is
    **Unverified-assumption** (see Open assumptions).

11. **`apiCall` wrapper maps `Response<T>` → `ApiResult<T>` and FastAPI `detail`
    → typed errors (AND-018/AND-015).** VERDICT: **Unverified-assumption** — these
    are upstream Android tickets not present in the provided sources; assumed from
    the spec's own cross-references.

12. **Compose lifecycle APIs (`DisposableEffect`, `LifecycleEventObserver`,
    `Lifecycle.Event.ON_START`, `LocalLifecycleOwner`) for the mark-read trigger.**
    VERDICT: **Verified — framework ref.** SOURCE (framework ref):
    https://developer.android.com/jetpack/compose/side-effects (DisposableEffect)
    and https://developer.android.com/topic/libraries/architecture/lifecycle .

13. **Room schema migration / DAO Flow aggregation for the unread count.**
    VERDICT: **Verified — framework ref.** SOURCE (framework ref):
    https://developer.android.com/training/data-storage/room/migrating-db-versions .

14. **Aggregate is unread-*conversation* count vs unread-*message* count (R2).**
    VERDICT: **Unverified-assumption** — AND-122's chosen aggregation is not in the
    provided sources; the DAO query in §6 sums conversations with `unreadCount > 0`.
    Must mirror AND-122 (the source is the AND-122 ticket, not provided here).

### Corrections made

- **Path:** `POST /conversations/{id}/read` → `POST /messaging/conversations/{conversation_id}/read`
  (added `/messaging`, renamed path param to `conversation_id`). Updated in
  Overview, FR-1, §4.1, §5.1, AC-1.
- **Request marker:** replaced `last_read_message_id`-only body with the verified
  `last_read_at` (numeric timestamp) marker the web client sends; request DTO is
  now `MarkReadRequestDto(lastReadAt: Long?, lastReadMessageId: String? = null)`.
  Updated FR-6, §4.2, §4.3, §5.1, §11 items 5–6, Moshi note.
- **Response shape:** removed the fabricated `MarkReadResponseDto`; success body
  is empty, API now returns `Response<Unit>`; repository persists its own marker
  via `applyLocalReadCommitted` instead of `applyServerRead(dto)`. Updated §4.1,
  §4.2, §5.1, §6, §15.
- **Config gate (FR-7):** removed — `MessagingConfigOut` has no
  `read_receipts_enabled` and the web client never gates on config. Updated FR-7,
  §4.2, §11 item 5, AC-6, R5.
- **Error table:** demoted 401/403/404 to explicitly "unverified for this op /
  defensive"; 422 marked as the only documented non-200.
- **Risks:** R1 and R5 marked RESOLVED with sources.
- **Frontmatter:** `status: draft → reviewed`; added `reviewed_on: 2026-06-06`.

### Open assumptions

- **401/403/404 on this specific op** are not enumerated in OpenAPI (only 422).
  Their handling is assumed from the global auth/error pipeline; handle
  defensively but do not contractually rely on them. (Why unverifiable: not in
  the OpenAPI responses for this path, and the web client swallows all errors so
  it reveals no status-specific behavior.)
- **`apiCall` / `ApiResult` / FastAPI `detail` mapping (AND-018/AND-015)** —
  upstream Android tickets, not in the provided reference sources.
- **Unread aggregation unit (conversations vs messages)** — defined by AND-122,
  whose source is not provided. AND-125 must reuse AND-122's DAO aggregate.
- **`ConversationEntity` existing columns** — owned by AND-122; whether
  `lastReadMessageId`/`lastReadAt`/`readDirty` already exist is unverifiable from
  the provided sources (no Android source tree given).
- **Future read-receipt privacy flag** — if added to `/messaging/config`, the
  config gate (removed FR-7) should be reinstated.

## 17. Test Plan

Test-target legend: **JVM** = JVM unit/Robolectric (local, no device);
**Emulator** = headless AVD `test35` (x86_64, API 35); **Device** = physical
Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). Contract tests use
MockWebServer on the JVM.

- **TC-AND-125-01 — Mark read on open (happy path).** Type: unit.
  Target: JVM (`MessagingRepository`, fake `MessagingApi`).
  Preconditions: cached conversation with `unreadCount = 3`, newest loaded
  message `created_at = 1749132202`.
  Steps: call `markConversationRead("conv_8F3", 1749132202)`.
  Expected: DAO `unreadCount = 0`, `isUnread = false`; exactly one
  `POST /messaging/conversations/conv_8F3/read` issued; on success `readDirty = 0`
  and the committed marker stored. Traces: AC-1, AC-2.

- **TC-AND-125-02 — Request body shape (contract).** Type: contract/MockWebServer.
  Target: JVM (`MessagingApi` + MockWebServer).
  Preconditions: server returns `200` with empty body.
  Steps: invoke `markConversationRead("conv_8F3", 1749132202)`.
  Expected: recorded request is `POST /messaging/conversations/conv_8F3/read`,
  `Content-Type: application/json`, body `{"last_read_at":1749132202,"last_read_message_id":null}`;
  empty `200` body deserializes cleanly to `Response<Unit>` (no parse error).
  Traces: AC-1.

- **TC-AND-125-03 — Null marker path.** Type: unit.
  Target: JVM (repository, fake API).
  Preconditions: conversation `unreadCount = 1`, no messages loaded yet.
  Steps: call `markConversationRead("conv_8F3", null)`.
  Expected: body serialized as `{"last_read_at":null,"last_read_message_id":null}`;
  optimistic clear still applied. Traces: AC-1 (FR-6).

- **TC-AND-125-04 — Idempotent re-entry (no redundant call).** Type: unit.
  Target: JVM (repository, fake API).
  Preconditions: conversation already `unreadCount = 0`, `readDirty = false`.
  Steps: call `markConversationRead` again in the same session.
  Expected: no network request issued; returns `ApiResult.Success`.
  Traces: AC-3.

- **TC-AND-125-05 — ViewModel one-shot guard + re-arm.** Type: unit.
  Target: JVM (`ThreadViewModel`, Robolectric for lifecycle if needed).
  Preconditions: thread with unread; spy repository.
  Steps: deliver two `ON_START` events; then simulate a new inbound message
  (unread > 0) and another `ON_START`.
  Expected: repo `markConversationRead` called once across the first two
  `ON_START`s; called again after the re-arm. Traces: AC-3 (FR-2).

- **TC-AND-125-06 — Failure resilience (5xx/IO).** Type: contract/MockWebServer.
  Target: JVM.
  Preconditions: server returns `500` (and a separate case: socket
  disconnect/IO).
  Steps: mark read on an unread conversation.
  Expected: no exception thrown; optimistic clear retained (`unreadCount = 0`),
  `readDirty = true`; no error surfaced to UI; returns `ApiResult.Error`.
  Traces: AC-4.

- **TC-AND-125-07 — 422 validation shape.** Type: contract/MockWebServer.
  Target: JVM.
  Preconditions: server returns `422` with
  `{"detail":[{"loc":["body","last_read_at"],"msg":"...","type":"..."}]}`.
  Steps: mark read.
  Expected: mapped to typed `ApiError` from `detail`; optimistic clear retained,
  `readDirty = true`; no crash. Traces: AC-4.

- **TC-AND-125-08 — No config gate (corrected FR-7).** Type: unit.
  Target: JVM (repository, fake API + fake `/messaging/config`).
  Preconditions: `/messaging/config` response containing none of the read-receipt
  fields (because none exist).
  Steps: mark read on an unread conversation.
  Expected: the POST is **still** issued (no short-circuit); local clear occurs.
  Traces: AC-6.

- **TC-AND-125-09 — Aggregate recompute (reactive).** Type: unit.
  Target: JVM (Room in-memory + Turbine).
  Preconditions: three conversations, two unread; collect `observeTotalUnread()`.
  Steps: mark one unread conversation read.
  Expected: Flow emits the new aggregate (2 → 1) without a manual refresh.
  Traces: AC-2 (FR-5).

- **TC-AND-125-10 — Deferred sync of dirty rows.** Type: unit.
  Target: JVM (repository, fake API).
  Preconditions: two rows `readDirty = true` (prior offline failures), one clean.
  Steps: call `syncPendingReads()` with the API now succeeding.
  Expected: exactly two `POST .../read` issued (only dirty rows); both rows
  `readDirty = 0` after success; the clean row untouched. Traces: AC-5.

- **TC-AND-125-11 — Flaky/offline host then recovery (integration).**
  Type: integration. Target: Emulator (`test35`) with MockWebServer toggled
  offline→online; connectivity probe (AND-017) stubbed.
  Preconditions: backend unreachable; conversation unread.
  Steps: open thread (mark fails, row dirty) → restore connectivity → trigger
  `syncPendingReads()` via the foreground/connectivity hook.
  Expected: badge clears immediately on open and stays cleared; row dirty while
  offline; re-POSTed and reconciled (`readDirty = 0`) after recovery; no error UI.
  Traces: AC-4, AC-5.

- **TC-AND-125-12 — CSRF + 401 refresh-and-retry.** Type: contract/MockWebServer.
  Target: JVM (full OkHttp stack with CSRF interceptor + authenticator).
  Preconditions: `ui_csrf` cookie set; server returns `401` once then `200` after
  a `POST /ui/session/refresh`.
  Steps: mark read.
  Expected: first request carries `X-CSRF-Token` = `ui_csrf` value; on 401 a
  single `POST /ui/session/refresh` then one retry of the read POST; final result
  success. Traces: AC-1 (security).

- **TC-AND-125-13 — Badge accessibility semantics.** Type: Compose-UI.
  Target: Emulator (`test35`); runnable on Device for a real TalkBack pass.
  Preconditions: conversation-list row (AND-121) shows "3 unread messages".
  Steps: open the thread (triggering mark read) and return to the list.
  Expected: the badge node's content description updates/clears (semantics, not
  just color); when count is 0 the unread semantics are absent; count uses the
  `unread_count` plural from `strings.xml`. Traces: AC-2 (a11y, no regression).

- **TC-AND-125-14 — End-to-end mark-read on physical device.** Type:
  instrumented/e2e. Target: **Device (SM-A156U, API 34, arm64-v8a)** — MUST run
  on the physical device to validate real arm64/API-34 behavior and real network
  cookie/CSRF transport against the dev host.
  Preconditions: signed-in dev build pointed at the dev backend; a conversation
  with `unread_count > 0`.
  Steps: open the conversation from the list; observe the badge; background and
  foreground the app; pull-to-refresh the list.
  Expected: badge clears within one frame; exactly one read POST observed; aggregate
  badge decrements; state survives background/foreground and process death; no
  crash on arm64. Traces: AC-1, AC-2, AC-5.

### Coverage matrix

| AC (section 14) | Covered by |
| --- | --- |
| AC-1 Opening marks read | TC-01, TC-02, TC-03, TC-12, TC-14 |
| AC-2 Counts update (reactive, a11y) | TC-01, TC-09, TC-13, TC-14 |
| AC-3 No redundant calls | TC-04, TC-05 |
| AC-4 Failure resilience | TC-06, TC-07, TC-11 |
| AC-5 Deferred sync | TC-10, TC-11, TC-14 |
| AC-6 No config-gate regression | TC-08 |
| AC-7 Tested / coverage ≥ 90% | TC-01..TC-10 (JVM unit/contract suite); aggregate coverage gate |
