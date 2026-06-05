---
id: AND-125
title: Read / unread state
milestone: M3
epic: E18
priority: P1
size: M
status: draft
depends_on: [AND-123]
blocks: []
---

# AND-125 — Read / unread state

## 1. Overview & Goal

This ticket adds **read / unread state management** to the TestLogon Android
messaging feature. When a user opens a conversation thread (the screen delivered
by AND-123), the app must mark that conversation as read on the backend via
`POST /conversations/{id}/read` and reflect the change locally so that:

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
cached `unreadCount > 0`, the app issues `POST /conversations/{id}/read`.

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
known to the client (`last_read_message_id` = id of the most recent message in
the thread page, when available). If no message id is available yet, the call
sends no marker and the server marks the whole conversation read.

**FR-7 — Read-receipt config gate.** If `/messaging/config` reports read
receipts disabled (`read_receipts_enabled == false`), the local clear still
occurs but the network call is skipped (the server tracks no per-user read
position). This keeps the dependency on `/config` from AND-120.

## 4. Technical Design

All new code lives in `:feature-messaging` and `:core-data`; the API surface
extends `:core-network`.

### 4.1 API extension (core-network, builds on AND-120)

```kotlin
// com.testlogon.android.core.network.messaging.MessagingApi
interface MessagingApi {
    // ...existing AND-120 endpoints...

    @POST("conversations/{id}/read")
    suspend fun markConversationRead(
        @Path("id") conversationId: String,
        @Body body: MarkReadRequestDto,
    ): Response<MarkReadResponseDto>
}
```

### 4.2 Repository (core-data)

The repository owns the optimistic-then-reconcile logic and is the single source
of truth. It reads/writes the Room `conversations` cache (owned by AND-122) and
exposes a Flow of the aggregate.

```kotlin
// com.testlogon.android.core.data.messaging.MessagingRepository
interface MessagingRepository {
    /** Optimistically clears unread, then syncs to server. Safe to call repeatedly. */
    suspend fun markConversationRead(
        conversationId: String,
        lastReadMessageId: String?,
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
    lastReadMessageId: String?,
): ApiResult<Unit> = withContext(io) {
    val local = conversationDao.getById(conversationId) ?: return@withContext ApiResult.Success(Unit)
    if (local.unreadCount == 0 && !local.readDirty) return@withContext ApiResult.Success(Unit) // FR-2

    conversationDao.applyOptimisticRead(conversationId, dirty = true) // FR-3, sets unreadCount=0,isUnread=false

    if (!configCache.readReceiptsEnabled) {            // FR-7
        conversationDao.clearDirty(conversationId)
        return@withContext ApiResult.Success(Unit)
    }

    when (val r = apiCall { api.markConversationRead(conversationId, MarkReadRequestDto(lastReadMessageId)) }) {
        is ApiResult.Success -> {
            conversationDao.applyServerRead(conversationId, r.data)  // FR-4 persists authoritative fields
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
        repo.markConversationRead(conversationId, newestMessageId())
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

### 5.1 `POST /conversations/{id}/read`

Auth: cookie session + `X-CSRF-Token` (echo of `ui_csrf`); on `401` the
authenticator (AND-013) calls `POST /ui/session/refresh` once and retries.

**Path param:** `id` — conversation id (string).

**Request body** (`MarkReadRequestDto`):

```json
{ "last_read_message_id": "msg_01HZX9K2QF" }
```

`last_read_message_id` is optional/nullable; omit (`null`) to mark the entire
conversation read (FR-6).

**Success `200`** (`MarkReadResponseDto`):

```json
{
  "conversation_id": "conv_8F3",
  "unread_count": 0,
  "last_read_message_id": "msg_01HZX9K2QF",
  "last_read_at": "2026-06-05T14:03:22Z"
}
```

**DTOs (Moshi):**

```kotlin
@JsonClass(generateAdapter = true)
data class MarkReadRequestDto(
    @Json(name = "last_read_message_id") val lastReadMessageId: String?,
)

@JsonClass(generateAdapter = true)
data class MarkReadResponseDto(
    @Json(name = "conversation_id") val conversationId: String,
    @Json(name = "unread_count") val unreadCount: Int,
    @Json(name = "last_read_message_id") val lastReadMessageId: String?,
    @Json(name = "last_read_at") val lastReadAt: String?,
)
```

**Error shapes** (mapped via AND-015 to `ApiError`):

- `401` → refresh-and-retry; if still 401 → `ApiError.Unauthorized`.
- `403` → CSRF/permission → `ApiError.Forbidden`.
- `404` → conversation gone → treat as read locally, clear dirty, log warn.
- `422` → FastAPI validation `{"detail":[{"msg": "...","loc":[...]}]}`.
- `5xx` / timeout / IO → `ApiError.Network` / `ApiError.Server`; optimistic
  clear retained, dirty flag set.

> If `/openapi.json` reveals the live shape differs (e.g. body is empty and the
> marker is a query param, or response is `204 No Content`), the DTOs and the
> `@POST` signature are adjusted to match; the web reference
> `frontend/src/api/endpoints/messaging.ts` is the tiebreaker. This is an open
> question (§13).

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

`applyServerRead(id, dto)` writes `unreadCount`, `lastReadMessageId`,
`lastReadAt` and sets `readDirty = 0`.

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
5. `read_receipts_enabled=false` → local clear, **no** POST, dirty cleared
   (FR-7).
6. `last_read_message_id` is set from newest message id and serialized; null
   marker path sends `{"last_read_message_id":null}` (FR-6).
7. `observeTotalUnread()` emits the recomputed aggregate after a clear (FR-5) —
   asserted with Turbine.
8. `syncPendingReads()` re-POSTs only dirty rows and reconciles them.

**ViewModel (feature-messaging):**

9. `onThreadVisible()` calls the repo once even across multiple `ON_START`
   events in one session; re-arms after a new inbound message.

**Moshi:** round-trip `MarkReadRequestDto` / `MarkReadResponseDto` against JSON
fixtures committed under `core-testing` resources (extends AND-120 fixtures).

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

- **R1 — Endpoint contract uncertainty.** Whether `/conversations/{id}/read`
  takes a body marker, a query param, or none, and whether it returns `200` with
  a body or `204`. *Mitigation:* verify against `/openapi.json` and
  `frontend/src/api/endpoints/messaging.ts` before implementation; DTOs are
  thin and easily adjusted. **Open.**
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
- **R5 — Read receipts privacy default.** If `/config` omits the flag, default
  to **enabled=false** (skip network) to avoid leaking read state. **Open —
  confirm default.**

## 14. Acceptance Criteria

1. **Opening a thread marks read.** Opening a conversation with `unreadCount > 0`
   issues exactly one `POST /conversations/{id}/read` (when read receipts
   enabled) and the conversation's local `unreadCount` becomes `0`. *(FR-1, FR-3;
   matches source acceptance "Opening a thread marks read".)*
2. **Counts update.** The per-row unread badge clears and the aggregate unread
   count exposed by the list ViewModel decrements accordingly, reactively, within
   one frame of opening the thread. *(FR-5; matches "counts update".)*
3. **No redundant calls.** Re-opening an already-read thread in the same session
   issues no network call. *(FR-2.)*
4. **Failure resilience.** A failed `read` POST does not surface a blocking
   error; the optimistic clear is retained and the row is marked dirty.
5. **Deferred sync.** `syncPendingReads()` re-POSTs dirty rows and reconciles
   them on the next list refresh / foreground / connectivity restoration.
6. **Config gate.** With `read_receipts_enabled=false`, the badge clears locally
   and no network call is made.
7. **Tested.** Unit tests in §11 (items 1–9 + Moshi round-trip) pass in CI
   (AND-008); read-path coverage ≥ 90% lines.

## 15. Definition of Done

- `MessagingApi.markConversationRead`, `MarkReadRequestDto`,
  `MarkReadResponseDto`, and repository methods
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
