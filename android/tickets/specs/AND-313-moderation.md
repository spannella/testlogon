---
id: AND-313
title: Moderation
milestone: M7
epic: E41
priority: P1
size: M
status: draft
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
- **Web reference:** `frontend/src/api/endpoints/broadcast.ts` (moderation calls),
  `frontend/src/api/endpoints/delegates.ts`, shared types `frontend/src/api/types.ts`.
  Confirm exact paths against `/openapi.json` before merge (see OQ-1).
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
  `chat.message.deleted` SSE frame.
- **FR-4 Pin / unpin:** An authorized actor can pin exactly one message at a time; the
  pinned message renders in a sticky banner at the top of the chat panel for all
  viewers (delivered via SSE). Pinning a new message replaces the previous pin.
  Unpin clears the banner.
- **FR-5 Moderation log:** A `ModerationLogScreen` lists recent moderation actions
  (action type, actor, target, reason, timestamp), newest first, paged (Paging 3),
  with pull-to-refresh. Unban/unmute can be triggered from a log row.
- **FR-6 Authorization gate:** Moderation affordances are visible **only** when the
  current actor is the broadcast host OR `managingCreator != null` for the broadcast's
  creator. Non-authorized viewers never see the controls; a server `403` is treated as
  a non-retryable authorization error (UI hides controls + shows a snackbar).
- **FR-7 Delegate routing:** When `managingCreator != null`, all moderation mutations
  target the delegate-scoped path variant (Section 5) so the action is attributed to
  the delegate-as-creator.
- **FR-8 Optimistic + reconcile:** Each action applies optimistically, then reconciles
  to the SSE-confirmed state; on REST failure it rolls back and surfaces a typed error.
- **FR-9 Reason (optional):** Mute/ban/delete accept an optional free-text `reason`
  (≤200 chars) recorded in the log.
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
    suspend fun mute(sessionId: String, userId: String, spec: MuteSpec): ApiResult<Unit>
    suspend fun unmute(sessionId: String, userId: String): ApiResult<Unit>
    suspend fun ban(sessionId: String, userId: String, reason: String?): ApiResult<Unit>
    suspend fun unban(sessionId: String, userId: String): ApiResult<Unit>
    suspend fun deleteMessage(sessionId: String, messageId: String, reason: String?): ApiResult<Unit>
    suspend fun pin(sessionId: String, messageId: String): ApiResult<Unit>
    suspend fun unpin(sessionId: String, messageId: String): ApiResult<Unit>
    fun moderationLog(sessionId: String): Flow<PagingData<ModerationLogEntry>>
}
```
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

Base path (dev): `http://18.222.237.167:8000/`. All calls ride the cookie session +
`X-CSRF-Token`. Paths declared without a leading slash. **Host-scoped** variants are
used by default; **delegate-scoped** variants (prefix `creators/{creatorId}/`) are used
when `managingCreator != null` (FR-7). Confirm exact shapes against `/openapi.json` +
`broadcast.ts`/`delegates.ts` before merge (OQ-1).

```kotlin
interface ModerationApi {
    @POST("broadcast/sessions/{id}/moderation/mute")
    suspend fun mute(@Path("id") s: String, @Body b: MuteRequestDto): Response<Unit>

    @POST("broadcast/sessions/{id}/moderation/unmute")
    suspend fun unmute(@Path("id") s: String, @Body b: UserTargetDto): Response<Unit>

    @POST("broadcast/sessions/{id}/moderation/ban")
    suspend fun ban(@Path("id") s: String, @Body b: BanRequestDto): Response<Unit>

    @POST("broadcast/sessions/{id}/moderation/unban")
    suspend fun unban(@Path("id") s: String, @Body b: UserTargetDto): Response<Unit>

    @HTTP(method="DELETE", path="broadcast/sessions/{id}/chat/{mid}", hasBody=true)
    suspend fun deleteMessage(@Path("id") s: String, @Path("mid") m: String,
                              @Body b: DeleteRequestDto): Response<Unit>

    @POST("broadcast/sessions/{id}/chat/{mid}/pin")
    suspend fun pin(@Path("id") s: String, @Path("mid") m: String): Response<Unit>

    @POST("broadcast/sessions/{id}/chat/{mid}/unpin")
    suspend fun unpin(@Path("id") s: String, @Path("mid") m: String): Response<Unit>

    @GET("broadcast/sessions/{id}/moderation/log")
    suspend fun log(@Path("id") s: String, @Query("cursor") cursor: String?,
                    @Query("limit") limit: Int = 30): ModerationLogPageDto

    // Delegate-scoped variants mirror the above under:
    //   creators/{creatorId}/broadcast/sessions/{id}/moderation/...
}
```

**Mute — `POST broadcast/sessions/{id}/moderation/mute`**
```json
{ "user_id": "usr_9", "duration_seconds": 300, "reason": "spam" }
```
→ `204`/`200`. Reflected to room via `chat.user_muted` SSE frame.

**Ban — `POST broadcast/sessions/{id}/moderation/ban`**
```json
{ "user_id": "usr_9", "reason": "abuse" }
```
→ `204`. Reflected via `chat.user_banned` SSE frame.

**Delete — `DELETE broadcast/sessions/{id}/chat/{messageId}`** body
`{ "reason": "off-topic" }` → `204`. Reflected via `chat.message.deleted`.

**Pin — `POST broadcast/sessions/{id}/chat/{messageId}/pin`** → `204`. Reflected via
`chat.message.pinned`; unpin via `chat.message.unpinned` (`message_id: null`).

**Log — `GET broadcast/sessions/{id}/moderation/log?cursor&limit=30`** (idempotent):
```json
{ "items": [
    { "id":"mod_01HZ","action":"ban","actor":{"id":"usr_self","username":"me","display_name":"Me","is_host":true},
      "target":{"user_id":"usr_9","message_id":null},"target_label":"@mira",
      "reason":"abuse","created_at":"2026-06-05T23:10:00Z" } ],
  "next_cursor": null }
```

**New SSE frames (consumed by the AND-281 stream parser):**
```
event: chat.message.deleted
data: {"message_id":"cm_01HXA"}

event: chat.message.pinned
data: {"message_id":"cm_01HXA"}

event: chat.user_muted
data: {"user_id":"usr_9","until":"2026-06-05T23:15:00Z"}
```

**Moshi DTOs** use `@Json` aliases (`user_id`, `duration_seconds`, `message_id`,
`target_label`, `created_at`, `next_cursor`, `is_host`); timestamps parse to `Instant`
via the shared `InstantJsonAdapter` (AND-026).

## 6. Data & State Management

- **Single source of truth:** moderation owns no separate persistent list. Per-message
  and per-user state lives inside the AND-281 chat list; the moderation reducer cases
  fold into the same `StateFlow<LiveChatUiState>` so chat + moderation render
  consistently. `ModerationViewModel` holds only transient sheet/in-flight/event state.
- **Reducer extensions (added to AND-281):**
  - `MessageDeleted(id)` — remove the message from the list (already partially present
    in AND-281; this ticket guarantees it is host-triggerable).
  - `MessagePinned(id)` / `MessageUnpinned` — set/clear `pinnedMessage`.
  - `UserMuted(userId, until)` / `UserBanned(userId)` — mark the author so their rows
    render a "muted/banned" affordance and (for self) disable the composer.
- **Optimistic write path:** on action invoke, apply the corresponding reducer case
  immediately, snapshot the prior list, call REST; on success keep (SSE echo is a
  no-op dedup), on failure restore the snapshot and emit `ModerationEvent.Failure`.
- **Moderation log** is paged via Paging 3 (`PagingData`, `cachedIn(viewModelScope)`),
  cursor-based; **not** cached in Room (low value after the broadcast; ephemeral like
  live chat). Pull-to-refresh calls `invalidate()` on the `PagingSource`.
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
- **`401`** → single `POST /ui/session/refresh` + retry by the AND-013 authenticator; a
  second `401` is fatal and routes to re-auth.
- **`403`** (not authorized / lost delegate scope) → non-retryable
  `ModerationError.Forbidden`; hide controls (`canModerate=false`) and show
  "You no longer have moderation permission."
- **`404`** (message/user gone, or session ended) → non-retryable; for delete/pin the
  optimistic removal is kept (already gone) and a neutral toast is shown.
- **`409`** (already muted/banned, or pin race) → treated as success-equivalent;
  reconcile to server truth, suppress error.
- **`422`** (bad duration/reason length) → field-level error in the sheet via AND-015
  `detail` array mapping.
- **`429`** (`Retry-After`) → transient; show retry hint, do not auto-retry.
- **Network/timeout (~20s)** → `ModerationError.Network`, rollback + retry affordance.
- **Log GET** is the only retriable call: bounded backoff (AND-016); on persistent
  failure the screen shows AND-021 Error/Offline with retry while keeping any cached page.
- All FastAPI `detail` shapes (`string | [{msg}] | {code,...}`) decode via AND-015.

## 8. Security & Privacy

- **Authorization is server-enforced.** The client gate (FR-6) is UX-only; the backend
  is authoritative and `403` is always honored. The client never assumes an action
  succeeded without a `2xx`.
- **Session & CSRF:** all calls use the persistent cookie jar (AND-011) and the
  `X-CSRF-Token` header (AND-012); CSRF is mandatory on these state-changing POST/DELETE
  calls.
- **Delegate attribution:** delegate-scoped routes ensure actions are attributed to the
  acting delegate in the server-side log; the client does not spoof actor identity.
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

- **OQ-1 (paths/shapes):** exact moderation endpoint paths and request keys
  (`mute`/`unmute` vs a single `mute` toggle; delete via `DELETE` body vs a
  `moderation/delete` POST; pin path) must be confirmed against `/openapi.json` and
  `broadcast.ts` before merge. Section 5 reflects the best current reading.
- **OQ-2 (delegate route shape):** confirm whether delegate moderation uses a
  `creators/{creatorId}/...` prefix or a header/query scope (AND-359). Adjust
  `ModerationRepository` path selection accordingly.
- **OQ-3 (SSE frame names):** confirm `chat.message.deleted` / `chat.message.pinned` /
  `chat.user_muted` event names; AND-281 already handles `MessageDeleted`, so align on
  one canonical name set.
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
