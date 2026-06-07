---
id: AND-313
title: Moderation
milestone: M7
epic: E41
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-281]
blocks: []
---

# AND-313 — Moderation

## 1. Overview & Goal

This ticket delivers **chat moderation** for the TestLogon Android app
(`com.testlogon.android`). A host (or a delegate acting on the host's behalf) watching
or running a live broadcast must be able to act on the chat room and its participants:
**mute** a viewer (temporary silence), **ban** a viewer (permanent removal + send
block), **delete** an individual message, **pin** a message to the top of the room,
and review a **moderation log** of recent enforcement actions. These controls are
surfaced on top of the live-chat surface built in **AND-281 — Live chat**, reusing its
`sessionId`, message models, and SSE-driven list.

The backlog acceptance bar is: **moderation actions apply + log.** Concretely, an
authorized actor invokes an action, the REST mutation succeeds, the local UI reflects
the change immediately (optimistic), the change is confirmed/reconciled by the
broadcast SSE stream (moderation frames), and the action appears in the
moderation-log view.

This ticket also wires **delegate moderation routes**: when the auth store is in
managing-as-creator mode (`managingCreator`, owned by AND-359), moderation calls target
delegate-scoped path variants so a delegate can moderate the creator's broadcast.
**[CORRECTED]** Per the backend + web reference, the moderation surface is **primarily**
delegate-scoped under `ui/broadcast/delegate/{creatorId}/...`: ban/unban, pin/unpin,
list-bans, and the moderation-log exist **only** under that prefix, so a `creatorId` is
required for those regardless of mode. Only mute and delete also have host-scoped variants.

Deliverables:
- `ModerationApi` (Retrofit) — mute/unmute, ban/unban, delete, pin/unpin, log read.
- `ModerationRepository` — `ApiResult<T>`-returning operations + delegate path routing.
- Domain models: `ModerationAction`, `ModerationTarget`, `ModerationLogEntry`,
  `MuteSpec`.
- `ModerationViewModel : StateFlow<ModerationUiState>` driving action sheets + log.
- Compose surfaces: `MessageModerationSheet` (per-message), `UserModerationSheet`
  (per-user), `ModerationLogScreen`, and a `pinned` banner slot on the chat panel.
- Integration of moderation SSE frames into the AND-281 chat reducer
  (`MessageDeleted`, `MessagePinned`, `UserMuted`, `UserBanned`).

Out of scope (owned elsewhere): the chat stream/transport (AND-281/AND-143), the
delegation auth-store + mode entry (AND-359), guest/co-host management (AND-312), and
server-side enforcement policy (FastAPI backend).

## 2. Context & References

- **Stack:** Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow,
  Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15, Paging 3 (log list). minSdk 24,
  compileSdk/targetSdk 35, JDK 17.
- **Module layering:** lives in `feature-broadcast` (alongside AND-281 live chat),
  depending on `core-network`, `core-model`, `core-ui`, `core-data`, `core-testing`.
- **Reused infrastructure:** persistent cookie jar (AND-011), CSRF interceptor
  (AND-012), 401-refresh authenticator (AND-013), `ApiResult<T>` (AND-018), FastAPI
  `detail` mapping (AND-015), retry/backoff for idempotent GETs (AND-016), state
  composables (AND-021).
- **Dependency AND-281 — Live chat:** supplies `sessionId` navigation context,
  `ChatMessage`/`ChatReaction` domain models, the `LiveChatViewModel` reducer, and the
  `LiveChatPanel`. This ticket extends the reducer and renders controls into the panel.
- **AND-359 — Delegates:** supplies `AuthStateStore.managingCreator: StateFlow<CreatorRef?>`.
  This ticket reads it to choose delegate-scoped routes; it does **not** own mode entry.
- **Web reference:** **[CORRECTED]** moderation calls live in
  `src/api/endpoints/delegateBroadcast.ts` (delegate-scoped pin/unpin/delete/mute/ban/
  unban/list-bans/moderation-log) and host-scoped delete/mute in
  `src/api/endpoints/broadcast-chat.ts`; shared DTOs in `src/api/types.ts`
  (`BroadcastMuteReq`, `BroadcastBanReq`, `BroadcastModerationLogEntry`, `BroadcastBanOut`,
  `BroadcastModeratorOut`). Transport/auth in `src/api/client.ts`. (The originally cited
  `broadcast.ts`/`delegates.ts` are not the moderation files.)
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext,
  unreliable; ~20s timeouts, bounded backoff for idempotent GETs only).

## 3. Functional Requirements

- **FR-1 Mute:** An authorized actor can mute a chat author for a chosen duration
  (preset chips: 5m / 1h / 24h, default 5m). Muted users cannot send; their existing
  messages remain unless also deleted. Mute is reversible via **unmute**.
- **FR-2 Ban:** An authorized actor can ban an author (permanent send block + removal
  from the room). Ban is confirmed via a destructive-confirmation dialog. Ban is
  reversible via **unban** from the moderation log.
- **FR-3 Delete message:** An authorized actor can delete any message by id. The
  message is removed from the visible list optimistically and confirmed by a
  **[CORRECTED]** `chat:delete` SSE frame (`{message_id}`) — not `chat.message.deleted`.
- **FR-4 Pin / unpin:** An authorized actor can pin a message; the pinned message renders
  in a sticky banner at the top of the chat panel. **[CORRECTED]** Pin/unpin are
  **delegate-scoped only** (`POST`/`DELETE .../chat/{mid}/pin`) and are **not delivered via
  any chat SSE frame**; the banner is driven from the pin/unpin response (and reconciled
  via the moderation log), not from the stream. The backend exposes single pin/unpin per
  message; whether multiple pins can coexist is unverified (OQ-1 / Section 13 risk).
- **FR-5 Moderation log:** A `ModerationLogScreen` lists recent moderation actions
  (`moderation_type`, `moderator_display_name`, target id, `details`, `ts`), newest first,
  with pull-to-refresh. **[CORRECTED]** The backend log is a **single non-paged array
  capped by `limit` (default 100)** — there is no cursor; Paging 3 cursor pagination is not
  applicable. Use a single bounded GET (raise `limit` if needed) rendered in a plain
  `LazyColumn`. Unban can be triggered from a log row; **unmute has no endpoint** and is not
  offered (or is emulated as a short re-mute, OQ-1).
- **FR-6 Authorization gate:** Moderation affordances are visible **only** when the
  current actor is the broadcast host OR `managingCreator != null` for the broadcast's
  creator. Non-authorized viewers never see the controls; a server `403` is treated as
  a non-retryable authorization error (UI hides controls + shows a snackbar).
- **FR-7 Delegate routing:** When `managingCreator != null`, all moderation mutations
  target the delegate-scoped path variant (Section 5) so the action is attributed to
  the delegate-as-creator.
- **FR-8 Optimistic + reconcile:** Each action applies optimistically, then reconciles
  to the SSE-confirmed state; on REST failure it rolls back and surfaces a typed error.
- **FR-9 Reason (optional):** **[CORRECTED]** Only **ban** accepts a free-text `reason`
  (optional, server cap **maxLength 500**; the prior "≤200 chars" and "mute/delete accept
  reason" were wrong — neither the mute nor the delete request schema has a `reason` field).
  The reason is recorded in the moderation log `details`.
- **FR-10 Idempotent log read:** The log GET is retriable with bounded backoff
  (AND-016); mutations are **not** auto-retried (non-idempotent).

## 4. Technical Design

New package `com.testlogon.android.feature.broadcast.moderation`.

**Domain models (`core-model`):**
```kotlin
enum class ModerationActionType { MUTE, UNMUTE, BAN, UNBAN, DELETE, PIN, UNPIN }

data class ModerationTarget(
    val userId: String? = null,      // for mute/ban/unmute/unban
    val messageId: String? = null,   // for delete/pin/unpin
)

data class MuteSpec(val durationSeconds: Long, val reason: String? = null)

data class ModerationLogEntry(
    val id: String,
    val action: ModerationActionType,
    val actor: ChatAuthor,               // reused from AND-281
    val target: ModerationTarget,
    val targetLabel: String,             // username or message preview
    val reason: String?,
    val createdAt: Instant,
)
```

**Repository:**
```kotlin
interface ModerationRepository {
    // creatorId required for ban/unban/pin/unpin/log (delegate-only); nullable for mute/delete (host fallback)
    suspend fun mute(sessionId: String, userId: String, spec: MuteSpec): ApiResult<Unit>
    suspend fun ban(sessionId: String, userId: String, reason: String?): ApiResult<Unit>
    suspend fun unban(sessionId: String, userId: String): ApiResult<Unit>
    suspend fun deleteMessage(sessionId: String, messageId: String): ApiResult<Unit>
    suspend fun pin(sessionId: String, messageId: String): ApiResult<Unit>
    suspend fun unpin(sessionId: String, messageId: String): ApiResult<Unit>
    suspend fun moderationLog(sessionId: String, limit: Int = 100): ApiResult<List<ModerationLogEntry>>
}
```
**[CORRECTED]** vs the original draft: `unmute(...)` is removed (no backend endpoint —
unmute is unsupported, OQ-1); `deleteMessage` drops the `reason` param (delete takes no
body); `pin`/`unpin` map to `POST`/`DELETE .../pin`; `moderationLog` returns a one-shot
`ApiResult<List<...>>` (no `Flow<PagingData>` — the log is a non-paged array). `MuteSpec`
should drop `reason` (mute has no reason field). All delegate-scoped ops require a
`creatorId` (from `managingCreator` or the broadcast's creator).
The implementation injects `ModerationApi`, `AuthStateStore`, and a `Json`-error
mapper. Before each mutation it reads `authStateStore.managingCreator.value` and
selects the base path (Section 5). Every mutation returns `ApiResult<Unit>` mapped via
AND-018/AND-015. `moderationLog` builds a `Pager(PagingConfig(pageSize = 30))` backed
by a `ModerationLogPagingSource` over the idempotent GET.

**ViewModel:**
```kotlin
@HiltViewModel
class ModerationViewModel @Inject constructor(
    private val repo: ModerationRepository,
    private val authStateStore: AuthStateStore,
    savedState: SavedStateHandle,
) : ViewModel() {
    private val sessionId: String = checkNotNull(savedState["sessionId"])
    val uiState: StateFlow<ModerationUiState>
    val log: Flow<PagingData<ModerationLogEntry>> =
        repo.moderationLog(sessionId).cachedIn(viewModelScope)

    fun canModerate(broadcast: BroadcastRef): Boolean  // FR-6 gate
    fun openMessageSheet(message: ChatMessage)
    fun openUserSheet(author: ChatAuthor)
    fun confirmMute(userId: String, spec: MuteSpec)
    fun confirmBan(userId: String, reason: String?)
    fun deleteMessage(messageId: String, reason: String?)
    fun pin(messageId: String); fun unpin(messageId: String)
    fun dismissSheet(); fun consumeEvent()
}

data class ModerationUiState(
    val sheet: Sheet? = null,                 // Message(msg) | User(author) | null
    val inFlight: Set<String> = emptySet(),   // keys "mute:usr_9", "delete:cm_1"
    val event: ModerationEvent? = null,       // one-shot snackbar
    val pinnedMessage: ChatMessage? = null,
)
```
Actions launch in `viewModelScope`, add their key to `inFlight`, call the repo, then
emit a `ModerationEvent.Success`/`Failure` and remove the key. The optimistic mutation
is applied by calling into the shared `LiveChatViewModel` reducer (Section 6) so a
single chat list reflects both chat and moderation changes; rollback re-applies prior
state on REST failure.

**UI:** `MessageModerationSheet` (Delete / Pin-or-Unpin / "Moderate author"),
`UserModerationSheet` (Mute with duration chips / Ban / Unmute / Unban),
`ModerationLogScreen` (Paging `LazyColumn` + AND-021 Loading/Empty/Error/Offline +
pull-to-refresh), and a `PinnedMessageBanner` slot rendered atop `LiveChatPanel`.
Controls are wrapped in `if (canModerate)`; long-press on a chat row opens the sheets.

## 5. API Contract

Base path (dev): `http://18.222.237.167:8000/`. **[CORRECTED]** Verified against the
OpenAPI index + `client.ts`, the real API surface differs substantially from the draft
below; the interface and shapes here are now the corrected versions. Transport: calls
ride the persistent cookie session + `X-CSRF-Token` (from the `ui_csrf` cookie) **and**
an `Authorization: Bearer <accessToken>` header; delegate/impersonation mode adds an
`X-IMPERSONATION-TOKEN` header (and `X-SESSION-ID` per the OpenAPI `params`). Paths
declared without a leading slash.

**[CORRECTED] Two endpoint families exist:**
- **Host-scoped chat ops** (no delegate prefix): only **mute** and **delete** are
  exposed here — `POST /broadcast/sessions/{id}/chat/mute` and
  `DELETE /broadcast/sessions/{id}/chat/{messageId}`.
- **Delegate-scoped moderation** under prefix **`ui/broadcast/delegate/{creatorId}/sessions/{id}/...`**
  (NOT `creators/{creatorId}/...`). This is where **ban/unban, pin/unpin, moderation-log,
  list-bans, list-moderators, delete, and mute** all live, and is the surface the web
  reference app uses for moderation. **Ban, unban, pin, unpin, list-bans, and the
  moderation-log have NO host-scoped variant — they exist ONLY under the delegate prefix.**
  FR-7's "delegate variant when `managingCreator != null`" therefore only meaningfully
  applies to mute/delete; ban/pin/log require a `creatorId` unconditionally.

```kotlin
interface ModerationApi {
    // ---- Host-scoped (no delegate prefix) ----
    @POST("broadcast/sessions/{id}/chat/mute")              // req=BroadcastChatMuteIn
    suspend fun muteHost(@Path("id") s: String, @Body b: ChatMuteRequestDto): Response<ChatMuteResponseDto>

    @DELETE("broadcast/sessions/{id}/chat/{mid}")           // NO request body
    suspend fun deleteMessageHost(@Path("id") s: String, @Path("mid") m: String): Response<DeleteResultDto>

    // ---- Delegate-scoped (the moderation surface the web app uses) ----
    @POST("ui/broadcast/delegate/{cid}/sessions/{id}/mute") // req=BroadcastMuteIn
    suspend fun mute(@Path("cid") c: String, @Path("id") s: String, @Body b: MuteRequestDto): Response<Unit>

    @POST("ui/broadcast/delegate/{cid}/sessions/{id}/ban")  // req=BroadcastBanIn
    suspend fun ban(@Path("cid") c: String, @Path("id") s: String, @Body b: BanRequestDto): Response<Unit>

    @DELETE("ui/broadcast/delegate/{cid}/sessions/{id}/ban/{uid}")
    suspend fun unban(@Path("cid") c: String, @Path("id") s: String, @Path("uid") u: String): Response<Unit>

    @GET("ui/broadcast/delegate/{cid}/sessions/{id}/bans")
    suspend fun listBans(@Path("cid") c: String, @Path("id") s: String): List<BanDto>

    @DELETE("ui/broadcast/delegate/{cid}/sessions/{id}/chat/{mid}")  // NO body
    suspend fun deleteMessage(@Path("cid") c: String, @Path("id") s: String, @Path("mid") m: String): Response<Unit>

    @POST("ui/broadcast/delegate/{cid}/sessions/{id}/chat/{mid}/pin")   // NO body
    suspend fun pin(@Path("cid") c: String, @Path("id") s: String, @Path("mid") m: String): Response<Unit>

    @DELETE("ui/broadcast/delegate/{cid}/sessions/{id}/chat/{mid}/pin") // unpin = DELETE
    suspend fun unpin(@Path("cid") c: String, @Path("id") s: String, @Path("mid") m: String): Response<Unit>

    @GET("ui/broadcast/delegate/{cid}/sessions/{id}/moderation-log")
    suspend fun log(@Path("cid") c: String, @Path("id") s: String,
                    @Query("limit") limit: Int = 100): List<ModerationLogEntryDto>  // plain array, no cursor
}
```

**[CORRECTED] Notes vs the original draft:**
- There is **no `/moderation/mute|unmute|ban|unban` path** and **no `unmute` endpoint at
  all** in the backend. The original `moderation/*` paths were invented. Unmute must be
  modeled as mute with a very short duration, or treated as not-yet-supported (OQ-1).
- **Unpin is `DELETE .../chat/{mid}/pin`**, not `POST .../unpin`.
- The **moderation log is a plain JSON array** (param `limit`, default 100), **not** a
  cursor-paged `{items,next_cursor}` object. Cursor-based Paging 3 must be replaced with a
  limit-only fetch (see Section 6 correction).

**[CORRECTED] Mute — `POST broadcast/sessions/{id}/chat/mute` (host)** req `BroadcastChatMuteIn`:
```json
{ "target_user_id": "usr_9", "duration_seconds": 300 }
```
Field is **`target_user_id`** (host schema), `duration_seconds` integer (min 30, max
86400, default 300). **No `reason` field on mute.** → `200` with `BroadcastChatMuteOut`
`{ "target_user_id", "muted_until": <epoch int>, "session_id" }`. The **delegate** mute
(`ui/broadcast/delegate/{cid}/sessions/{id}/mute`, req `BroadcastMuteIn`) uses field
**`user_id`** + `duration_seconds` (both required). No SSE `chat.user_muted` frame exists
(see SSE note); the room is not notified of mutes via the chat stream.

**[CORRECTED] Ban — `POST ui/broadcast/delegate/{cid}/sessions/{id}/ban`** req `BroadcastBanIn`:
```json
{ "user_id": "usr_9", "reason": "abuse" }
```
`user_id` required; `reason` optional, default `""`, **maxLength 500** (the draft's 200 cap
is wrong — see FR-9 / Section 7). → `200`. **No `chat.user_banned` SSE frame** — ban is
not reflected on the chat stream.

**[CORRECTED] Delete — `DELETE .../chat/{messageId}`** (host or delegate) takes **NO request
body** → `200` (host returns `{ "ok": true, "message_id": "..." }`). The draft's
`{ "reason": "off-topic" }` body and `204` were wrong. The SSE confirmation event is
**`chat:delete`** with `{"message_id":"..."}` (not `chat.message.deleted`).

**[CORRECTED] Pin — `POST .../chat/{messageId}/pin`** (delegate, no body) → `200`
`{ "ok", "message_id", "pinned" }`; **unpin = `DELETE .../chat/{messageId}/pin`** → `200`.
**There is no pin/unpin SSE frame** and no `pinned` field on the chat message model, so the
pinned banner cannot be reconciled from the chat stream — it must be driven from the
POST/DELETE response and/or the moderation log (see Risk in Section 13).

**[CORRECTED] Log — `GET ui/broadcast/delegate/{cid}/sessions/{id}/moderation-log?limit=100`**
(idempotent) returns a **plain array** of `BroadcastModerationLogEntry`:
```json
[ { "event_id":"mod_01HZ", "moderator_id":"usr_self", "moderator_display_name":"Me",
    "moderation_type":"ban", "target_user_id":"usr_9", "target_message_id":null,
    "details":{}, "ts": 1749165000 } ]
```
Fields are flat: `event_id`, `moderator_id`, `moderator_display_name`, `moderation_type`,
`target_user_id?`, `target_message_id?`, `details?`, `ts` (epoch **integer** seconds). The
draft's nested `actor`/`target` objects, `target_label`, top-level `reason`, ISO
`created_at`, and `next_cursor` do **not** exist. Map domain `ModerationLogEntry` from
these fields (timestamp = `Instant.ofEpochSecond(ts)`).

**[CORRECTED] SSE frames (consumed by the AND-281 stream parser):** the chat stream is an
`EventSource`/SSE at `GET /broadcast/sessions/{id}/chat/stream?poll_ms=500`. The only
moderation-relevant frame is delete:
```
event: chat:delete
data: {"message_id":"cm_01HXA"}
```
(Other frames: `chat:message`, `chat:reaction`, `chat:unlock`, `chat:lottery`.) The draft's
`chat.message.deleted`, `chat.message.pinned`, and `chat.user_muted` frame names are wrong;
pin/mute/ban have **no** chat-stream frames at all.

**Moshi DTOs** use `@Json` aliases for the real wire names (`target_user_id`, `user_id`,
`duration_seconds`, `muted_until`, `message_id`, `event_id`, `moderator_id`,
`moderator_display_name`, `moderation_type`, `target_message_id`, `details`, `ts`);
epoch-integer timestamps (`muted_until`, `ts`) parse via `Instant.ofEpochSecond` (the
prior `InstantJsonAdapter`/ISO-8601 assumption does not apply to these integer fields).

## 6. Data & State Management

- **Single source of truth:** moderation owns no separate persistent list. Per-message
  and per-user state lives inside the AND-281 chat list; the moderation reducer cases
  fold into the same `StateFlow<LiveChatUiState>` so chat + moderation render
  consistently. `ModerationViewModel` holds only transient sheet/in-flight/event state.
- **Reducer extensions (added to AND-281):**
  - `MessageDeleted(id)` — remove the message from the list. **[CORRECTED]** This is the
    only case the chat SSE stream actually reconciles, via the `chat:delete` frame; the
    web reference also removes optimistically on the delete response.
  - `MessagePinned(id)` / `MessageUnpinned` — set/clear `pinnedMessage`. **[CORRECTED]**
    There is **no pin SSE frame**, so these cases are driven only by the local pin/unpin
    response (and the moderation log), not by the stream.
  - `UserMuted(userId, until)` / `UserBanned(userId)` — mark the author so their rows
    render a "muted/banned" affordance and (for self) disable the composer. **[CORRECTED]**
    No `chat.user_muted`/`chat.user_banned` SSE frames exist; these are applied locally
    from the mute/ban response only (other viewers learn via send-rejection / the log).
- **Optimistic write path:** on action invoke, apply the corresponding reducer case
  immediately, snapshot the prior list, call REST; on success keep (SSE echo is a
  no-op dedup), on failure restore the snapshot and emit `ModerationEvent.Failure`.
- **Moderation log** **[CORRECTED]**: the backend returns a single capped array (no
  cursor), so this is **not** Paging-3 cursor pagination. Model it as a single
  `StateFlow<List<ModerationLogEntry>>` from one bounded GET (`limit`, default 100);
  pull-to-refresh re-issues the GET. Not cached in Room (ephemeral, like live chat).
- **Delegate context:** `managingCreator` is read at call time, not cached in
  `ModerationUiState`, so a mid-session delegate-mode toggle (AND-359) is honored.
- **Process death:** `sessionId` restored from `SavedStateHandle`; open sheets and
  in-flight sets are **not** restored (re-derived on re-entry). The chat list is
  ephemeral (per AND-281).
- **Threading:** repo calls run on `Dispatchers.IO`; state updates marshalled to the
  main-safe `StateFlow`. No blocking on the main thread.

## 7. Error Handling & Resilience

- **Mutations are non-idempotent → never auto-retried.** A failed action rolls back
  optimistic state and surfaces a typed snackbar with a manual **Retry** action.
- **`401`** → **[VERIFIED]** single `POST /ui/session/refresh` + retry, matching
  `client.ts` `refreshSession()` (AND-013 authenticator); a second `401` is fatal and
  routes to re-auth (web calls `logout("session_expired")`).
- **`403`** (not authorized / lost delegate scope) → non-retryable
  `ModerationError.Forbidden`; hide controls (`canModerate=false`) and show
  "You no longer have moderation permission."
- **`404`** (message/user gone, or session ended) → non-retryable; for delete/pin the
  optimistic removal is kept (already gone) and a neutral toast is shown.
- **`409`** (already muted/banned, or pin race) → **[UNVERIFIED]** treated as
  success-equivalent. The OpenAPI documents only `200`/`422` for these routes; `409` is an
  assumed backend behavior, not confirmed — guard defensively but do not rely on it.
- **`422`** (bad duration/`reason` length, missing `target_user_id`/`user_id`) →
  **[VERIFIED]** the documented validation error (`HTTPValidationError`); field-level error
  in the sheet via AND-015 `detail` array mapping. Note real bounds: `duration_seconds`
  30–86400, ban `reason` ≤500.
- **`429`** (`Retry-After`) → transient; show retry hint, do not auto-retry.
- **Network/timeout (~20s)** → `ModerationError.Network`, rollback + retry affordance.
- **Log GET** is the only retriable call: bounded backoff (AND-016); on persistent
  failure the screen shows AND-021 Error/Offline with retry while keeping any cached page.
- All FastAPI `detail` shapes (`string | [{msg}] | {code,...}`) decode via AND-015.

## 8. Security & Privacy

- **Authorization is server-enforced.** The client gate (FR-6) is UX-only; the backend
  is authoritative and `403` is always honored. The client never assumes an action
  succeeded without a `2xx`.
- **Session & CSRF:** **[VERIFIED + AMENDED]** all calls use the persistent cookie jar
  (AND-011), the `X-CSRF-Token` header sourced from the `ui_csrf` cookie (AND-012), **and**
  an `Authorization: Bearer <accessToken>` header (per `client.ts`). CSRF + bearer are
  mandatory on these state-changing POST/DELETE calls. The OpenAPI also lists `X-SESSION-ID`
  on every broadcast/delegate route; include it where the session-store provides it.
- **Delegate attribution:** **[CORRECTED]** delegate scope is conveyed two ways that must
  both be honored: the **`{creatorId}` path segment** (`ui/broadcast/delegate/{creatorId}/...`)
  and the **`X-IMPERSONATION-TOKEN` header** (set by the web client when impersonation is
  active). It is NOT a `creators/{creatorId}/...` prefix. The client does not spoof actor
  identity; the server attributes the action to the acting delegate.
- **Transport caveat:** dev host is plaintext HTTP — no production secrets; release
  builds require HTTPS hosts (cleartext disabled outside dev flavor per AND-006).
- **PII:** moderation reasons and target usernames are user content; they are not
  logged to logcat (Section 10) and not persisted on-device beyond the in-memory page
  cache.
- **No destructive action without confirmation:** ban and delete require an explicit
  confirm step to prevent accidental enforcement.

## 9. Accessibility & i18n

- All sheet actions, duration chips, and the pinned banner expose
  `contentDescription`/`semantics`; destructive actions (Ban, Delete) carry a
  `Role.Button` + a clear accessible label ("Ban @mira, destructive").
- Confirmation dialogs are focus-trapped; the destructive button is reachable and
  announced as destructive.
- Touch targets ≥ 48dp; sheets support TalkBack swipe order top-to-bottom.
- All strings (action labels, durations "5 minutes/1 hour/24 hours", reason
  placeholder, error messages, log row templates) live in `strings.xml`; durations and
  timestamps use locale-aware formatting (`DateUtils`/`java.time` formatter). No
  hardcoded user-facing text. RTL-safe layouts.
- Pinned banner truncates with an accessible "show full message" expand.

## 10. Telemetry & Logging

- **Structured events** (via the app analytics facade, no PII): `moderation_action`
  with attributes `{ action, target_type, has_reason, delegate_mode, result, http_status }`,
  and `moderation_log_viewed`. Reason text and usernames are **never** included.
- **Logging:** failures logged via the core logger at `WARN` with action type + status
  code only (no body, no PII); OkHttp body logging stays at the `core-network` default
  (off/headers in release per AND-009).
- A debug-only breadcrumb records optimistic-apply → reconcile/rollback transitions to
  aid race diagnosis.

## 11. Testing Strategy

- **Repository contract tests (MockWebServer, AND-046):** for each operation assert the
  correct method/path/body and `ApiResult` mapping — `204`→`Success`,
  `403`→`Forbidden`, `409`→success-equivalent, `422`→typed field error, `429`/timeout→
  retryable. Assert delegate routing: with `managingCreator` set, the request path is the
  `creators/{creatorId}/...` variant; without, the host-scoped variant.
- **Reducer unit tests:** `MessageDeleted`/`MessagePinned`/`UserMuted`/`UserBanned`
  fold correctly; optimistic-apply-then-rollback restores the prior list; SSE echo after
  a successful POST is a no-op (dedup).
- **ViewModel tests (Turbine):** `inFlight` keys added/removed around calls; one-shot
  `event` emitted once and consumed; `canModerate` true only for host/`managingCreator`.
- **Paging tests:** `ModerationLogPagingSource` paginates by cursor, surfaces
  Loading/Error states, and `refresh()` invalidates.
- **Compose UI tests (AND-021/AND-048 harness):** controls hidden for non-host; sheets
  open on long-press; ban shows confirmation; delete removes the row; pin renders the
  banner; log screen shows rows + Empty/Error/Offline; unban from a log row issues the
  call.
- **Acceptance test (maps to backlog bar):** perform mute → assert REST call + composer
  disabled for self-target + log shows the entry. Ban/delete/pin similarly verified to
  "apply + log."

## 12. Dependencies & Sequencing

- **Depends on AND-281 — Live chat** (P0): provides `sessionId`, `ChatMessage`,
  `ChatAuthor`, the `LiveChatViewModel` reducer, `LiveChatPanel`, and the SSE parser
  this ticket extends. Must merge first.
- **Soft dependency AND-359 — Delegates** (delegation API / `managingCreator`): required
  for the *delegate moderation routes* slice (FR-7). If AND-359 is not yet merged, ship
  host-scoped routing behind a flag and land delegate routing as a fast follow; the
  rest of the ticket does not block on it. Track via OQ-2.
- **Reuses (already merged):** AND-011/012/013 (cookies/CSRF/refresh), AND-015
  (errors), AND-016 (GET backoff), AND-018 (`ApiResult`), AND-021 (state composables),
  AND-046 (MockWebServer harness).
- **Blocks:** none currently in the source backlog.

## 13. Risks & Open Questions

- **OQ-1 (paths/shapes) — RESOLVED (this review):** paths/shapes verified against OpenAPI +
  `delegateBroadcast.ts`/`broadcast-chat.ts`. Findings: mute=`.../chat/mute` (host) or
  `.../delegate/{cid}/sessions/{id}/mute` (delegate); delete=`DELETE .../chat/{mid}` **no
  body**; pin=`POST`/unpin=`DELETE .../chat/{mid}/pin`. **There is NO unmute endpoint** —
  remaining open: model unmute as short re-mute or drop it. Pin cardinality (single vs
  multiple) still unconfirmed.
- **OQ-2 (delegate route shape) — RESOLVED (this review):** delegate moderation uses BOTH a
  **`{creatorId}` path segment** under `ui/broadcast/delegate/...` AND the
  **`X-IMPERSONATION-TOKEN`** header (not `creators/{creatorId}/...`). ban/unban/pin/unpin/
  log/list-bans are delegate-only; mute/delete also have host variants. `ModerationRepository`
  selects host vs delegate per op + `managingCreator`.
- **OQ-3 (SSE frame names) — RESOLVED (this review):** the only moderation chat-stream frame
  is **`chat:delete`** (`{message_id}`). There are **no** pin/mute/ban SSE frames; those are
  reconciled from REST responses + the moderation log. Align AND-281 on `chat:delete`.
- **Risk — optimistic/SSE race:** mitigated by id-based dedup in the reducer (tested).
- **Risk — single global pin assumption:** if the backend allows multiple pins, the
  banner becomes a list; confirm cardinality (OQ-1).
- **Risk — unreliable dev host:** mutations are not retried, so a timeout after the
  server applied the action can show a transient "failed" UI; SSE reconciliation
  corrects state on reconnect.

## 14. Acceptance Criteria

- **AC-1:** A host can mute a user for a selected duration; the mute REST call succeeds,
  the user's composer is blocked (when self) / row shows muted, and the action appears in
  the moderation log. Unmute reverses it.
- **AC-2:** A host can ban a user (after confirmation); the call succeeds and the action
  is logged; unban from the log reverses it.
- **AC-3:** A host can delete a message; it is removed from the list and the deletion is
  logged.
- **AC-4:** A host can pin/unpin a message; the pinned banner appears/clears and the
  action is logged; pinning a second message replaces the first.
- **AC-5:** Moderation controls are hidden for non-host viewers; a server `403` hides
  controls and shows an authorization message.
- **AC-6:** When `managingCreator != null`, moderation calls use the delegate-scoped
  route (verified by MockWebServer path assertion).
- **AC-7:** Failed mutations roll back optimistic UI and offer Retry; the log GET retries
  with bounded backoff and shows Offline/Error states.
- **AC-8:** The moderation log lists actions newest-first, paged, with pull-to-refresh.

## 15. Definition of Done

- All Section 14 acceptance criteria pass.
- `ModerationApi`, `ModerationRepository`(+impl), domain models, `ModerationViewModel`,
  and the Compose surfaces (`MessageModerationSheet`, `UserModerationSheet`,
  `ModerationLogScreen`, `PinnedMessageBanner`) are implemented in `feature-broadcast`
  under `com.testlogon.android`.
- AND-281 reducer/SSE parser extended for moderation frames with dedup.
- Delegate routing implemented (or flagged per OQ-2) and verified by tests.
- Repository contract tests, reducer/ViewModel unit tests, Paging tests, and Compose UI
  tests are green in CI (AND-050); module lint/detekt/ktlint clean (AND-005).
- No PII in telemetry/logs; CSRF + cookie session enforced on all mutations.
- All user-facing strings localized; a11y labels and destructive-action confirmations in
  place.
- OQ-1/OQ-2/OQ-3 resolved against `/openapi.json` (or explicitly deferred with a
  follow-up) and reflected in code; PR reviewed and merged to `android-port`.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. OpenAPI pointers are
`METHOD /path` from `reference/openapi.index.txt`; schema pointers are
`components.schemas.<Name>` in `reference/openapi.pretty.json`; frontend pointers are
`reference/src/...`.

1. **Mute endpoint & method.** Host: `POST /broadcast/sessions/{session_id}/chat/mute`;
   delegate: `POST /ui/broadcast/delegate/{creator_id}/sessions/{sid}/mute`. **VERDICT:
   Corrected** (draft used `POST .../moderation/mute`). Source: OpenAPI
   `POST /broadcast/sessions/{session_id}/chat/mute`,
   `POST /ui/broadcast/delegate/{creator_id}/sessions/{sid}/mute`;
   `src/api/endpoints/broadcast-chat.ts: muteChatUser`,
   `src/api/endpoints/delegateBroadcast.ts: muteViewer`.
2. **Mute request fields.** Host schema `target_user_id` + `duration_seconds`; delegate
   schema `user_id` + `duration_seconds`; `duration_seconds` min 30 / max 86400 / default
   300; **no `reason`**. **VERDICT: Corrected** (draft used `user_id` + a `reason`). Source:
   schemas `BroadcastChatMuteIn`, `BroadcastMuteIn`; `src/api/types.ts: BroadcastMuteReq`.
3. **Mute response.** `200` with `BroadcastChatMuteOut` `{target_user_id, muted_until (epoch
   int), session_id}`. **VERDICT: Corrected** (draft said `204`/`200`, no body). Source:
   schema `BroadcastChatMuteOut`; `src/api/endpoints/broadcast-chat.ts: ChatMuteResponse`.
4. **Ban endpoint.** `POST /ui/broadcast/delegate/{creator_id}/sessions/{sid}/ban` — delegate
   only. **VERDICT: Corrected** (draft used host `POST .../moderation/ban`). Source: OpenAPI
   `POST /ui/broadcast/delegate/{creator_id}/sessions/{sid}/ban`;
   `src/api/endpoints/delegateBroadcast.ts: banViewer`.
5. **Ban request fields.** `user_id` (required) + `reason` (optional, default `""`, **maxLength
   500**). **VERDICT: Corrected** (draft capped reason at 200). Source: schema `BroadcastBanIn`;
   `src/api/types.ts: BroadcastBanReq`.
6. **Unban endpoint.** `DELETE /ui/broadcast/delegate/{creator_id}/sessions/{sid}/ban/{uid}`.
   **VERDICT: Corrected** (draft used `POST .../moderation/unban`). Source: OpenAPI
   `DELETE /ui/broadcast/delegate/{creator_id}/sessions/{sid}/ban/{uid}`;
   `src/api/endpoints/delegateBroadcast.ts: unbanViewer`.
7. **Unmute endpoint.** Does **not** exist. **VERDICT: Corrected** (draft defined
   `POST .../moderation/unmute`). Source: absence in `openapi.index.txt` (no unmute path) and
   in `delegateBroadcast.ts`/`broadcast-chat.ts`.
8. **Delete message endpoint & body.** `DELETE /broadcast/sessions/{session_id}/chat/{message_id}`
   (host) and `DELETE /ui/broadcast/delegate/{creator_id}/sessions/{sid}/chat/{mid}` (delegate),
   **no request body**, resp `200`. **VERDICT: Corrected** (draft sent a `{reason}` body, claimed
   `204`). Source: OpenAPI both DELETE paths show `req=`;
   `src/api/endpoints/broadcast-chat.ts: deleteChatMessage`,
   `src/api/endpoints/delegateBroadcast.ts: deleteMessage` (both call `api.del` with no body).
9. **Pin / unpin endpoints.** Pin `POST .../delegate/{cid}/sessions/{sid}/chat/{mid}/pin` (no
   body); unpin `DELETE .../chat/{mid}/pin`. Delegate-only. **VERDICT: Corrected** (draft used
   `POST .../unpin`). Source: OpenAPI pin POST + pin DELETE paths;
   `src/api/endpoints/delegateBroadcast.ts: pinMessage / unpinMessage`.
10. **Moderation log endpoint & shape.** `GET /ui/broadcast/delegate/{creator_id}/sessions/{sid}/moderation-log?limit=`
    returns a **plain array** (no cursor). **VERDICT: Corrected** (draft used
    `GET .../moderation/log?cursor&limit` returning `{items,next_cursor}`). Source: OpenAPI
    `GET /ui/broadcast/delegate/{creator_id}/sessions/{sid}/moderation-log` (`params=...,limit`);
    `src/api/endpoints/delegateBroadcast.ts: getModerationLog` (returns `BroadcastModerationLogEntry[]`).
11. **Log entry fields.** `event_id, moderator_id, moderator_display_name, moderation_type,
    target_user_id?, target_message_id?, details?, ts (epoch int)`. **VERDICT: Corrected**
    (draft used nested `actor`/`target`, `target_label`, top-level `reason`, ISO `created_at`,
    `next_cursor`). Source: `src/api/types.ts: BroadcastModerationLogEntry`.
12. **Delegate route shape.** `ui/broadcast/delegate/{creator_id}/sessions/{sid}/...` path
    segment + `X-IMPERSONATION-TOKEN` header. **VERDICT: Corrected** (draft used
    `creators/{creatorId}/broadcast/...` prefix). Source: OpenAPI `ui/broadcast/delegate/...`
    paths; `src/api/endpoints/delegateBroadcast.ts: BASE`; `src/api/client.ts` (sets
    `X-IMPERSONATION-TOKEN` when impersonation active).
13. **Chat SSE delete frame.** Event name is `chat:delete` with `{message_id}`. **VERDICT:
    Corrected** (draft used `chat.message.deleted`). Source:
    `src/pages/broadcast/BroadcastChat.tsx` (`es.addEventListener("chat:delete", ...)`).
14. **Pin / mute / ban SSE frames.** None exist. **VERDICT: Corrected** (draft defined
    `chat.message.pinned` and `chat.user_muted`/`chat.user_banned`). Source:
    `src/pages/broadcast/BroadcastChat.tsx` (only `chat:message`, `chat:delete`,
    `chat:reaction`, `chat:unlock`, `chat:lottery` listeners).
15. **Chat stream transport.** SSE `EventSource` at
    `GET /broadcast/sessions/{id}/chat/stream?poll_ms=500`. **VERDICT: Verified.** Source:
    OpenAPI `GET /broadcast/sessions/{session_id}/chat/stream` (`params=...,after,poll_ms`);
    `src/pages/broadcast/BroadcastChat.tsx` (`new EventSource(...chat/stream?poll_ms=500)`).
16. **CSRF + cookie session on mutations.** `X-CSRF-Token` (from `ui_csrf` cookie) + cookie
    credentials are sent. **VERDICT: Verified.** Source: `src/api/client.ts` (`getCookie("ui_csrf")`
    → `X-CSRF-Token`; `credentials: "include"`).
17. **Authorization bearer + session headers.** `Authorization: Bearer <accessToken>` is also
    required; `X-SESSION-ID` / `X-IMPERSONATION-TOKEN` appear on these routes. **VERDICT:
    Corrected** (draft omitted bearer/impersonation/session headers). Source: `src/api/client.ts`
    (sets `Authorization` and `X-IMPERSONATION-TOKEN`); OpenAPI `params=...,X-SESSION-ID,
    X-IMPERSONATION-TOKEN` on every broadcast/delegate route.
18. **401 refresh path.** `POST /ui/session/refresh`, single retry, second 401 → logout.
    **VERDICT: Verified.** Source: `src/api/client.ts: refreshSession` (`/ui/session/refresh`),
    retry-once logic + `logout("session_expired")`.
19. **422 validation error shape.** `HTTPValidationError` (FastAPI `detail` array of `{msg,...}`)
    is the documented validation error. **VERDICT: Verified.** Source: OpenAPI `resp=...;422:
    HTTPValidationError` on all moderation routes; `src/api/client.ts: normalizeErrorDetail`
    (handles string | array-of-`{msg}` | object-with-`code`).
20. **403 authorization handling.** `403` surfaces an authorization message; `silent403` allows
    suppression. **VERDICT: Verified** (client gate is UX-only; server authoritative). Source:
    `src/api/client.ts` (403 branch, `mapAuthorizationError`, `role_required*` codes).
21. **List bans / list moderators / moderator register.** Real delegate endpoints not in the
    draft. **VERDICT: Verified (additional surface).** Source: OpenAPI
    `GET .../bans`, `GET .../moderators`, `POST .../moderator/register`;
    `src/api/endpoints/delegateBroadcast.ts: listBans / listModerators / registerModerator`.
22. **Android framework choices** (Compose/Material 3, Hilt+KSP, Retrofit/OkHttp/Moshi,
    Coroutines/Flow, `Instant`). **VERDICT: Unverified-assumption** (not checkable against
    backend/frontend; standard Android stack). framework ref:
    https://developer.android.com/jetpack/compose ,
    https://square.github.io/retrofit/ , https://github.com/square/moshi .
23. **AND-281 reducer / `LiveChatViewModel` / `LiveChatPanel` / `sessionId` nav contract, and
    AND-359 `managingCreator`.** **VERDICT: Unverified-assumption** — these are other Android
    tickets not present in the provided sources; treated as inherited contracts.
24. **`409` already-muted/banned → success-equivalent.** **VERDICT: Unverified-assumption** —
    OpenAPI documents only `200`/`422` for these routes; `409` behavior is assumed.

### Corrections made
- Mute path/fields/response: `/moderation/mute` → host `chat/mute` (`target_user_id`) +
  delegate `mute` (`user_id`); removed `reason`; response is `BroadcastChatMuteOut` (200).
- Ban/unban: moved to delegate prefix; `reason` cap 200 → 500.
- Removed the non-existent **unmute** endpoint (and the repo method / log-row unmute / FR-5).
- Delete: removed `{reason}` body and `204`; it is a bodiless `DELETE` returning `200`.
- Pin/unpin: unpin is `DELETE .../pin` (not `POST .../unpin`); delegate-only; no SSE frame.
- Moderation log: cursor-paged `{items,next_cursor}` → plain capped array (`limit`), flat
  entry fields (`event_id`/`moderator_*`/`moderation_type`/`target_*`/`ts`); dropped Paging 3.
- Delegate routing: `creators/{creatorId}/...` → `ui/broadcast/delegate/{creatorId}/...` +
  `X-IMPERSONATION-TOKEN` header.
- SSE frame names: `chat.message.deleted` → `chat:delete`; removed invented pin/mute/ban frames.
- Transport: added `Authorization: Bearer`, `X-IMPERSONATION-TOKEN`, `X-SESSION-ID` to the
  documented header set (CSRF + cookies were already correct).
- Timestamp adapters: log `ts` and `muted_until` are epoch integers (not ISO-8601 `Instant`).

### Open assumptions
- **Unmute UX:** no backend endpoint; whether to omit unmute or emulate via a short re-mute is
  unresolved (OQ-1) — needs product/backend decision.
- **Pin cardinality:** single-pin-per-room vs multiple pins is not expressed in the schema; the
  banner-vs-list decision is unverifiable from sources (OQ-1 risk).
- **Pin/mute/ban reconciliation for other viewers:** with no SSE frames, how non-acting clients
  learn of pins/mutes/bans (send-rejection? poll? log refresh?) is not specified by the sources.
- **`409` semantics:** assumed; only `200`/`422` are documented.
- **AND-281 / AND-359 contracts:** inherited from sibling tickets not in the provided sources.

## 17. Test Plan

Test targets: **JVM** = JVM unit/Robolectric (local, no device); **MWS** = MockWebServer
contract; **emu35** = headless AVD `test35` (x86_64, API 35); **A15** = physical Samsung
Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). Moderation has no camera/biometric/WebRTC/FCM
surface, so most instrumented/Compose cases run fine on **emu35**; one ABI/API-parity case is
called out for **A15**.

- **TC-AND-313-01 — Mute happy path (host) contract.** Type: contract/MWS. Target: MWS+JVM.
  Pre: repo wired to MockWebServer; `managingCreator == null`. Steps: call
  `repo.mute(sessionId, "usr_9", MuteSpec(300))`; capture request. Expected: `POST
  /broadcast/sessions/{id}/chat/mute`, JSON body `{"target_user_id":"usr_9","duration_seconds":300}`,
  no `reason` key; enqueue `200 {"target_user_id":"usr_9","muted_until":1749165300,"session_id":"..."}`
  → `ApiResult.Success`. Traces: AC-1.
- **TC-AND-313-02 — Mute via delegate route + headers.** Type: contract/MWS. Target: MWS+JVM.
  Pre: `managingCreator = CreatorRef("cr_7")`; impersonation token present. Steps: call
  `repo.mute(...)`. Expected: request path `ui/broadcast/delegate/cr_7/sessions/{id}/mute`,
  body `{"user_id":"usr_9","duration_seconds":300}`, headers include `X-CSRF-Token`,
  `Authorization: Bearer ...`, `X-IMPERSONATION-TOKEN`. Traces: AC-1, AC-6.
- **TC-AND-313-03 — Ban happy path + confirmation.** Type: contract/MWS + Compose-UI.
  Target: MWS+emu35. Pre: host authorized; ban sheet open. Steps: tap Ban → confirm dialog →
  confirm; capture request. Expected: confirm dialog shown first (no call until confirmed);
  then `POST ui/broadcast/delegate/{cid}/sessions/{id}/ban` body `{"user_id":"usr_9","reason":"abuse"}`;
  `200` → success event; row marked banned. Traces: AC-2.
- **TC-AND-313-04 — Ban reason length validation (422).** Type: contract/MWS. Target: MWS+JVM.
  Pre: reason > 500 chars. Steps: enqueue `422 HTTPValidationError` `{"detail":[{"loc":["body","reason"],
  "msg":"ensure this value has at most 500 characters"}]}`; call ban. Expected: AND-015 maps
  `detail[].msg` to a field-level error in the sheet; no optimistic state retained. Traces: AC-2, AC-7.
- **TC-AND-313-05 — Unban from log row.** Type: contract/MWS. Target: MWS+JVM. Pre: log row for
  `usr_9` ban. Steps: invoke `repo.unban(sessionId,"usr_9")`. Expected: `DELETE
  ui/broadcast/delegate/{cid}/sessions/{id}/ban/usr_9`, no body, `200` → success. Traces: AC-2.
- **TC-AND-313-06 — Delete message (no body) + optimistic remove + SSE reconcile.** Type:
  integration. Target: JVM (reducer) + MWS. Pre: message `cm_1` in list. Steps: call
  `repo.deleteMessage(sessionId,"cm_1")`; then feed an SSE `chat:delete {"message_id":"cm_1"}`.
  Expected: `DELETE .../chat/cm_1` with **empty body**; `MessageDeleted("cm_1")` removes the row;
  subsequent `chat:delete` is a dedup no-op. Traces: AC-3.
- **TC-AND-313-07 — Pin sets banner; unpin clears (delegate, no SSE).** Type: contract/MWS +
  Compose-UI. Target: MWS+emu35. Steps: pin `cm_1` then unpin. Expected: pin = `POST
  .../chat/cm_1/pin` (no body), unpin = `DELETE .../chat/cm_1/pin`; `PinnedMessageBanner`
  appears on pin and clears on unpin, driven by the response (no SSE frame consumed). Traces: AC-4.
- **TC-AND-313-08 — Moderation log fetch (array, no cursor) + render newest-first +
  pull-to-refresh.** Type: contract/MWS + Compose-UI. Target: MWS+emu35. Steps: enqueue a JSON
  **array** of `BroadcastModerationLogEntry`; load screen; pull-to-refresh. Expected: `GET
  ui/broadcast/delegate/{cid}/sessions/{id}/moderation-log?limit=100`; rows sorted by `ts`
  descending; `ts` rendered via `Instant.ofEpochSecond`; refresh re-issues the same GET (no
  cursor param). Traces: AC-8.
- **TC-AND-313-09 — Authorization gate hides controls; 403 handling.** Type: Compose-UI +
  contract/MWS. Target: emu35+MWS. Pre: non-host (`canModerate == false`) and a host whose
  mutate returns `403`. Steps: (a) render chat as non-host → assert no moderation affordances;
  (b) as host, enqueue `403 {"detail":"Permission denied"}` on a mute → assert controls hidden
  (`canModerate=false`) + authorization snackbar; not retried. Traces: AC-5, AC-7.
- **TC-AND-313-10 — Failed mutation rolls back optimistic UI + Retry.** Type: integration +
  Compose-UI. Target: emu35+MWS. Pre: pin `cm_1` optimistically. Steps: enqueue `500` (or socket
  timeout) on the pin POST. Expected: banner reverts to prior state; `ModerationEvent.Failure`
  snackbar with a **Retry** action; mutation **not** auto-retried (non-idempotent). Traces: AC-7.
- **TC-AND-313-11 — Flaky/offline dev host: log GET backoff + Offline state.** Type: integration.
  Target: A15 (toggle airplane mode for real offline) or emu35 (MWS socket failure). Pre: log
  screen. Steps: simulate timeout/connection-drop on the log GET. Expected: AND-016 bounded
  backoff retries the GET (idempotent), then AND-021 Error/Offline state with Retry while keeping
  any prior page; mutations are still never auto-retried. Note: prefer **A15** for genuine
  airplane-mode/offline behavior. Traces: AC-7, AC-8.
- **TC-AND-313-12 — CSRF/cookie/bearer required on mutations (security).** Type: contract/MWS.
  Target: MWS+JVM. Steps: perform mute/ban/delete/pin; inspect outgoing headers. Expected: each
  state-changing POST/DELETE carries `X-CSRF-Token`, `Authorization: Bearer`, session cookie, and
  (delegate) `X-IMPERSONATION-TOKEN`; absence in test harness yields the expected server-error
  mapping. Traces: AC-5, AC-6.
- **TC-AND-313-13 — Accessibility of sheets/banner/destructive actions.** Type: Compose-UI (a11y).
  Target: emu35 (TalkBack assertions via semantics). Steps: open `UserModerationSheet` and confirm
  dialog; inspect semantics. Expected: Ban/Delete expose `Role.Button` + destructive accessible
  labels; touch targets ≥ 48dp; confirm dialog focus-trapped; duration chips and pinned banner
  expose `contentDescription`; banner "show full message" expand is announced. Traces: AC-2, AC-4, AC-5.
- **TC-AND-313-14 — ABI/API parity (arm64 / API 34 vs x86_64 / API 35).** Type: instrumented/e2e.
  Target: **A15 (must)** + emu35 for comparison. Steps: run the mute→delete→pin→log e2e suite on
  both. Expected: identical behavior (Moshi epoch-int parsing of `muted_until`/`ts`, `java.time`
  formatting, SSE `chat:delete` handling) with no arm64-vs-x86 or API-34-vs-35 divergence. Note:
  the physical device is the authoritative target for ABI/API differences. Traces: AC-1, AC-3, AC-4, AC-8.

### Coverage matrix
- **AC-1 (mute applies + logged, unmute reverses):** TC-01, TC-02, TC-14. (Unmute has no
  endpoint — see §16 Open assumptions; not test-covered.)
- **AC-2 (ban w/ confirm + logged, unban reverses):** TC-03, TC-04, TC-05, TC-13.
- **AC-3 (delete removes + logged):** TC-06, TC-14.
- **AC-4 (pin/unpin banner + logged, replace):** TC-07, TC-13, TC-14.
- **AC-5 (controls hidden for non-host; 403 message):** TC-09, TC-12, TC-13.
- **AC-6 (delegate route via path assertion):** TC-02, TC-12.
- **AC-7 (rollback + Retry; log backoff + Offline/Error):** TC-04, TC-09, TC-10, TC-11.
- **AC-8 (log newest-first, pull-to-refresh):** TC-08, TC-11, TC-14.
