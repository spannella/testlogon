---
id: AND-141
title: Drafts
milestone: M3
epic: E19
priority: P2
size: M
status: draft
depends_on: [AND-124]
blocks: []
---

# AND-141 — Drafts

## 1. Overview & Goal

Per-conversation message drafts. When a user types into the message composer of a
conversation but does not send, the composed text (and any pending attachment
references) must be persisted so that it is restored verbatim the next time the
conversation is opened, and cleared once the message is actually sent or the user
explicitly deletes the draft.

The authoritative store is the backend resource family `/conversations/{id}/drafts`
(CRUD). The Android client mirrors this through a Room cache so drafts survive
process death and brief offline periods, and reconciles with the server on
open/close. The dev backend is plaintext HTTP and unreliable (~20s timeouts), so
draft persistence must be local-first: a draft is never lost because the network
was down.

Goal acceptance (from backlog): a draft **saves**, **restores**, and **clears**,
each with automated test coverage.

This ticket depends on **AND-124 (Send text message)**, which owns the composer
UI, the `MessageComposer` composable, the conversation `ViewModel`, and the send
pipeline. AND-141 extends that composer with draft load/save/clear behavior; it
does not re-implement the composer or the send path.

## 2. Context & References

- Repo `spannella/testlogon`, monorepo Android app under `android/`, branch
  `android-port`. Namespace/applicationId base `com.testlogon.android`.
- Module layering `app -> feature-* -> core-*`. Drafts feature code lives in
  `feature-conversation` (the module introduced by AND-124); persistence types
  live in `core-data` (Room) and `core-model`; transport in `core-network`.
- Web reference: `frontend/src/api/endpoints/*.ts` and `frontend/src/api/types.ts`.
  Inspect the drafts endpoint module (e.g. `frontend/src/api/endpoints/drafts.ts`
  or the relevant `conversations.ts`) and `Draft`/`DraftPayload` types to confirm
  field names before freezing the Moshi models in §5. OpenAPI at
  `/openapi.json` is the source of truth for request/response shapes.
- Auth is cookie-based with a `ui_csrf` cookie echoed as `X-CSRF-Token`; the
  shared OkHttp stack from core-network handles the cookie jar, CSRF header
  injection, and the single `POST /ui/session/refresh`-then-retry on 401. Draft
  calls reuse that stack unchanged.
- Backend FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`. Error bodies
  use the FastAPI `detail` convention (`string | [{msg}] | {code,...}`) mapped by
  the shared `ApiResult<T>` error parser in core-network.

## 3. Functional Requirements

FR-1 **Restore on open.** When a conversation screen is opened, if a draft exists
for that conversation, the composer text field is pre-populated with the draft
body and the caret positioned at the end. Restore must succeed from the local
cache even with no network.

FR-2 **Save while typing.** Edits to the composer are persisted as a draft. Saves
are debounced (default 800ms after the last keystroke) to avoid write storms, and
flushed immediately on lifecycle stop (`onStop`) and when the conversation screen
is left.

FR-3 **Empty draft = delete.** If the composer is emptied (trimmed body is empty
and there are no pending attachments), the draft is deleted locally and remotely
rather than persisted as an empty string.

FR-4 **Clear on send.** When AND-124's send pipeline reports a successful send,
the draft for that conversation is cleared (local + remote DELETE).

FR-5 **Manual discard.** The composer overflow menu exposes a "Discard draft"
action, enabled only when a draft exists; selecting it clears the composer and
deletes the draft.

FR-6 **Local-first durability.** A draft is written to Room before (or
concurrently with) the network call; restore reads from Room. Network failures
never block save/restore and never surface a blocking error to the user.

FR-7 **Conflict resolution.** On open, the client fetches the server draft and
reconciles with the local copy using `updatedAt` (last-write-wins, newest
`updatedAt` kept). If clocks make this ambiguous, the local copy wins (the user's
device is the source of truth for in-flight typing).

FR-8 **Single draft per conversation.** At most one draft per `conversationId`.
The local key is `conversationId`.

Out of scope: draft for new (not-yet-created) conversations; multi-recipient
draft fan-out; rich-text/markdown serialization beyond plain body + attachment id
references; cross-device real-time sync (best-effort on open only).

## 4. Technical Design

### Layering

- `core-model`: `Draft` domain model.
- `core-network`: `DraftApi` Retrofit interface + Moshi DTOs + mapper.
- `core-data`: `DraftEntity` (Room), `DraftDao`, `DraftRepository` (the offline-
  first reconcile + sync logic).
- `feature-conversation`: composer wiring inside the AND-124 `ConversationViewModel`.

### Domain model (core-model)

```kotlin
data class Draft(
    val conversationId: String,
    val body: String,
    val attachmentIds: List<String> = emptyList(),
    val updatedAt: Instant,
    val remoteId: String? = null,   // server draft id once synced; null if local-only
)
```

### Room (core-data)

```kotlin
@Entity(tableName = "drafts")
data class DraftEntity(
    @PrimaryKey val conversationId: String,
    val body: String,
    val attachmentIds: String,      // JSON-encoded List<String> via a TypeConverter
    val updatedAtEpochMs: Long,
    val remoteId: String?,
    val pendingSync: Boolean = false, // true when local change not yet pushed
)

@Dao
interface DraftDao {
    @Query("SELECT * FROM drafts WHERE conversationId = :id")
    fun observe(id: String): Flow<DraftEntity?>

    @Query("SELECT * FROM drafts WHERE conversationId = :id")
    suspend fun get(id: String): DraftEntity?

    @Upsert
    suspend fun upsert(entity: DraftEntity)

    @Query("DELETE FROM drafts WHERE conversationId = :id")
    suspend fun delete(id: String)

    @Query("SELECT * FROM drafts WHERE pendingSync = 1")
    suspend fun pending(): List<DraftEntity>
}
```

A `RoomDatabase` migration adds the `drafts` table; bump the core-data DB version
and provide an `@RenameColumn`-free additive migration (new table only).

### Repository (core-data)

```kotlin
interface DraftRepository {
    fun observeDraft(conversationId: String): Flow<Draft?>
    /** Reconciles local + server on screen open; returns the draft to restore. */
    suspend fun loadAndReconcile(conversationId: String): ApiResult<Draft?>
    /** Debounced upstream of save(); persists locally then best-effort PUT. */
    suspend fun saveDraft(conversationId: String, body: String,
                          attachmentIds: List<String>): ApiResult<Draft>
    /** Deletes locally then best-effort DELETE; used on send / discard / empty. */
    suspend fun clearDraft(conversationId: String): ApiResult<Unit>
}
```

`saveDraft` writes Room with `pendingSync = true`, then attempts the network
write; on success it sets `remoteId` and `pendingSync = false`; on failure it
leaves `pendingSync = true` and returns `ApiResult.Success(localDraft)` (the
save itself succeeded locally — network is opportunistic).

### Composer wiring (feature-conversation, extends AND-124)

Inside AND-124's `ConversationViewModel`:

```kotlin
private val draftSaver = MutableSharedFlow<DraftEdit>(extraBufferCapacity = 64)

init {
    // restore
    viewModelScope.launch {
        draftRepository.loadAndReconcile(conversationId).onSuccess { d ->
            d?.let { _uiState.update { s -> s.copy(
                composerText = TextFieldValue(it.body, TextRange(it.body.length)),
                hasDraft = true) } }
        }
    }
    // debounced save
    viewModelScope.launch {
        draftSaver.debounce(800.milliseconds).collectLatest { edit ->
            if (edit.body.isBlank() && edit.attachmentIds.isEmpty())
                draftRepository.clearDraft(conversationId)
            else
                draftRepository.saveDraft(conversationId, edit.body, edit.attachmentIds)
        }
    }
}

fun onComposerChanged(value: TextFieldValue) {
    _uiState.update { it.copy(composerText = value) }
    draftSaver.tryEmit(DraftEdit(value.text, currentAttachmentIds()))
}

fun onDiscardDraft() = viewModelScope.launch {
    draftRepository.clearDraft(conversationId)
    _uiState.update { it.copy(composerText = TextFieldValue(""), hasDraft = false) }
}

override fun onCleared() { flushDraftBlocking() ; super.onCleared() }
```

Lifecycle flush on `onStop` is driven from the screen via
`LifecycleEventEffect(Lifecycle.Event.ON_STOP) { viewModel.flushDraft() }`, which
emits any buffered edit immediately (bypassing debounce).

On a successful send (AND-124's `sendMessage` result), the ViewModel calls
`draftRepository.clearDraft(conversationId)` and resets `composerText`.

## 5. API Contract

Resource: `/conversations/{id}/drafts`. Confirm exact field names against
`/openapi.json` and `frontend/src/api/types.ts` before locking the DTOs; shapes
below reflect the expected FastAPI/web contract.

```kotlin
interface DraftApi {
    @GET("conversations/{id}/drafts")
    suspend fun getDraft(@Path("id") conversationId: String): Response<DraftDto>
    // 200 with draft, or 404 if none exists

    @PUT("conversations/{id}/drafts")
    suspend fun putDraft(
        @Path("id") conversationId: String,
        @Body body: DraftPayloadDto,
    ): Response<DraftDto>

    @DELETE("conversations/{id}/drafts")
    suspend fun deleteDraft(@Path("id") conversationId: String): Response<Unit>
}
```

DTOs (Moshi):

```kotlin
@JsonClass(generateAdapter = true)
data class DraftPayloadDto(
    @Json(name = "body") val body: String,
    @Json(name = "attachment_ids") val attachmentIds: List<String> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class DraftDto(
    @Json(name = "id") val id: String?,
    @Json(name = "conversation_id") val conversationId: String,
    @Json(name = "body") val body: String,
    @Json(name = "attachment_ids") val attachmentIds: List<String> = emptyList(),
    @Json(name = "updated_at") val updatedAt: String, // ISO-8601
)
```

Request example (PUT):

```json
{ "body": "see you at 6, bring the keys", "attachment_ids": [] }
```

Response example (GET/PUT 200):

```json
{
  "id": "drf_01H...",
  "conversation_id": "cnv_8842",
  "body": "see you at 6, bring the keys",
  "attachment_ids": [],
  "updated_at": "2026-06-05T14:03:11Z"
}
```

Semantics: `GET` returns the single draft or **404** (mapped to
`ApiResult.Success(null)` — absence is not an error). `PUT` is an upsert
(create-or-replace, idempotent). `DELETE` returns 204/200 and is idempotent
(404 on delete is treated as success). All calls carry the session cookie jar +
`X-CSRF-Token`; mutating calls (PUT/DELETE) are **not** retried on transient
network errors (non-idempotent-on-the-wire policy), only the GET on open is
retried with bounded backoff.

## 6. Data & State Management

UiState additions to AND-124's conversation state:

```kotlin
data class ConversationUiState(
    /* ...existing AND-124 fields... */
    val composerText: TextFieldValue = TextFieldValue(""),
    val hasDraft: Boolean = false,
    val draftSyncState: DraftSyncState = DraftSyncState.Idle,
)

enum class DraftSyncState { Idle, Saving, SavedLocal, Synced, Error }
```

- Single source of truth for restore is Room (`DraftDao.observe`); the network
  GET only seeds/updates Room via `loadAndReconcile`.
- `hasDraft` is derived from a non-null, non-blank persisted draft and gates the
  "Discard draft" menu item.
- Reconcile (FR-7): compare `local.updatedAtEpochMs` vs server `updated_at`; keep
  newer, write the winner to Room, mark `pendingSync=false` if server won or push
  if local won.
- Process death: because Room is written on every debounced edit and on
  `ON_STOP`, the draft is recoverable after the OS kills the process; restore on
  next open reads Room first, then reconciles.
- StateFlow exposed as `val uiState: StateFlow<ConversationUiState>` per the
  project ViewModel convention.

## 7. Error Handling & Resilience

- **Local writes never fail the user.** `saveDraft`/`clearDraft` complete on the
  Room write; network is best-effort. A failed PUT leaves `pendingSync=true` and
  sets `draftSyncState = SavedLocal` (not `Error`-blocking).
- **GET on open** uses the shared ~20s timeout and bounded backoff retry (idempotent
  GET): on exhausted failure, fall back to the local Room draft and surface
  `DraftSyncState.Error` non-intrusively (no dialog).
- **404 on GET/DELETE** → success/empty, never an error toast.
- **401** is handled by the shared interceptor (single `POST /ui/session/refresh`
  then retry); if refresh fails, the draft stays local and pendingSync remains.
- **Pending-sync flush:** `DraftRepository` exposes `flushPending()` invoked on
  conversation open and on app foreground to push any `pendingSync=true` rows;
  failures are silent and retried next opportunity. No background WorkManager job
  is required for P2 (open/foreground flush is sufficient).
- **Empty/whitespace** bodies are normalized via `trimEnd()` for storage; a fully
  blank body triggers delete, not save (FR-3).
- FastAPI `detail` errors map through the shared parser; the draft layer logs the
  mapped message but does not block the composer.

## 8. Security & Privacy

- Draft bodies are user message content and may contain sensitive text. They are
  stored in the app-private Room database under `data/data/com.testlogon.android`;
  no `android:allowBackup` exfiltration — the app must set
  `android:allowBackup="false"` (verify the manifest from AND-124's app module)
  or exclude the drafts DB from auto-backup via `data_extraction_rules.xml`.
- No draft content is written to logcat (see §10); only ids and lengths.
- Transport reuses the cookie-based session + `X-CSRF-Token` on PUT/DELETE; CSRF
  header omission must fail the request (handled by the shared interceptor).
- Dev backend is plaintext HTTP; this is a known dev-only limitation. Production
  config must use HTTPS (owned by the network/config ticket, not AND-141). Do not
  add a cleartext exception beyond the existing dev `network_security_config`.
- On logout/session clear, the local drafts table should be wiped along with other
  per-user caches (hook into the existing cache-clear path).

## 9. Accessibility & i18n

- "Discard draft" menu item has a `contentDescription` and a visible label, both
  from `strings.xml` (`R.string.draft_discard`).
- Restored draft text must announce nothing intrusive; rely on the standard
  `TextField` semantics. Provide a subtle "Draft restored" assist (optional,
  non-blocking) only via existing snackbar patterns, localized.
- All user-facing strings (`draft_discard`, `draft_restored`, error fallbacks)
  go through `strings.xml`; no hardcoded literals. RTL is inherited from the
  composer; no custom layout that breaks mirroring.
- Touch target for the overflow item meets the 48dp minimum (Material 3 default).

## 10. Telemetry & Logging

- Structured analytics events (reuse the project analytics facade, no PII):
  `draft_saved` (props: `conversation_id`, `body_len`, `synced:Boolean`),
  `draft_restored` (`conversation_id`, `source: local|server|reconciled`),
  `draft_cleared` (`conversation_id`, `reason: send|discard|empty`),
  `draft_sync_failed` (`conversation_id`, `http_status?`).
- **Never log draft body content.** Log only `conversationId`, `body.length`,
  sync state, and mapped error code/message at `Timber.d/w`.
- A debug-only `Timber` tag `Drafts` traces reconcile decisions
  (`local newer / server newer / local-only`).

## 11. Testing Strategy

Backlog acceptance is "Draft saves/restores/clears (tested)". Concrete coverage:

- **DraftDao (instrumented, Room in-memory):** upsert/get/observe/delete round
  trips; `attachmentIds` TypeConverter; `pending()` filters `pendingSync`.
- **DraftRepository (unit, fake DAO + MockWebServer):**
  - save → Room written `pendingSync=true`; on 200 PUT → `remoteId` set,
    `pendingSync=false`. (**saves**)
  - blank body → `clearDraft` path, DELETE issued, row removed. (FR-3)
  - `loadAndReconcile`: server-only draft seeds Room; local-newer wins and pushes;
    server-newer overwrites Room; GET 404 → `Success(null)`; GET timeout → falls
    back to local Room copy. (**restores** + FR-7)
  - clear on send/discard removes row + issues DELETE; 404 on DELETE → success.
    (**clears**)
- **ConversationViewModel (unit, `Turbine` + `MainDispatcherRule`):**
  - typing emits debounced save (advance virtual clock 800ms → one save).
  - restore populates `composerText` with caret at end and `hasDraft=true`.
  - successful send triggers `clearDraft` and resets composer.
  - `onDiscardDraft` clears state and calls repository.
  - `ON_STOP`/`onCleared` flush emits a save bypassing debounce.
- **Compose UI (`createAndroidComposeRule`):** opening a conversation with a
  cached draft shows the text; "Discard draft" item enabled only when a draft
  exists and clears the field on tap.
- Use `core-testing` fakes, `kotlinx-coroutines-test` `StandardTestDispatcher`,
  and MockWebServer for HTTP. Target the three backlog behaviors as named tests
  so the acceptance bullet is traceable.

## 12. Dependencies & Sequencing

- **Depends on AND-124 (Send text message):** provides `feature-conversation`,
  the composer composable, `ConversationViewModel`, conversation id plumbing, and
  the send-success signal that AND-141 hooks `clearDraft` into. AND-141 must not
  start until AND-124's composer surface is merged.
- Reuses core-network OkHttp/cookie-jar/CSRF stack and `ApiResult<T>` (already
  established by earlier M1/M2 networking tickets).
- Reuses the core-data Room database; this ticket adds the `drafts` table and a
  DB migration.
- No tickets currently declared as blocked by AND-141.
- Sequencing within the ticket: (1) core-model + DTOs + `DraftApi`; (2) Room
  entity/DAO/migration; (3) `DraftRepository` + reconcile; (4) ViewModel/composer
  wiring; (5) tests.

## 13. Risks & Open Questions

- **OQ-1 Endpoint shape unverified.** Confirm against `/openapi.json` whether the
  drafts resource is singular-per-conversation (`PUT/GET/DELETE
  /conversations/{id}/drafts`, as assumed) or a collection with draft ids
  (`/conversations/{id}/drafts/{draftId}`). If collection-based, adjust `DraftApi`
  and treat the first/most-recent draft as the active one.
- **OQ-2 Field naming.** `attachment_ids` vs `attachments`; `updated_at`
  presence/format — verify before freezing Moshi adapters.
- **R-1 Clock skew** undermines `updatedAt` reconcile (FR-7); mitigated by
  local-wins tiebreak, but server clock drift could discard a newer local edit if
  the device clock is far behind. Acceptable for P2.
- **R-2 Unreliable dev host** can make GET-on-open slow; mitigated by local-first
  restore (do not block the composer on the network GET).
- **R-3 Attachment lifecycle.** Draft references attachment ids; if a referenced
  attachment is deleted server-side, restore must tolerate dangling ids
  (drop-and-continue). Full attachment-draft coupling is deferred to the
  attachments ticket.
- **OQ-3 Backup policy** — confirm app-wide `allowBackup` stance with the app
  module owner (AND-124/app config).

## 14. Acceptance Criteria

AC-1 (**saves**) Typing in the composer and leaving it idle ≥800ms (or stopping
the activity) persists a draft to Room; with network available a `PUT
/conversations/{id}/drafts` is issued and `remoteId`/`pendingSync` updated.
Verified by repository + ViewModel tests.

AC-2 (**restores**) Reopening a conversation that has a draft pre-populates the
composer with the exact saved body, caret at end, `hasDraft=true` — and does so
from local cache with no network. Server reconcile keeps the newest copy.
Verified by repository reconcile tests and a Compose UI test.

AC-3 (**clears**) A successful send clears the draft locally and issues `DELETE
/conversations/{id}/drafts`; "Discard draft" clears the composer and deletes the
draft; emptying the composer deletes rather than stores an empty draft. Verified
by ViewModel + repository tests.

AC-4 Network failures on save/clear never lose the local draft and never show a
blocking error; the draft is re-pushed on next open/foreground (`pendingSync`).

AC-5 GET 404 and DELETE 404 are treated as success (no error surfaced).

AC-6 No draft body content appears in logcat or analytics payloads.

AC-7 All three backlog behaviors (save/restore/clear) have named automated tests
that pass in CI.

## 15. Definition of Done

- `DraftApi`, DTOs+mapper, `DraftEntity`/`DraftDao`, Room migration,
  `DraftRepository`, and ViewModel/composer wiring implemented under
  `com.testlogon.android` in the correct modules (core-model/core-network/
  core-data/feature-conversation).
- All §11 tests written and green in CI; the three acceptance behaviors are
  traceable to named tests.
- Endpoint shape and field names verified against `/openapi.json` and the web
  reference; OQ-1/OQ-2 resolved or explicitly recorded in code comments.
- No draft content in logs/telemetry; drafts DB excluded from auto-backup or
  `allowBackup=false` confirmed.
- Lint/detekt/ktlint clean; no new cleartext network exceptions; Compose preview
  for the composer-with-draft state compiles.
- Code review approved; merged to `android-port`; CHANGELOG/ticket updated with
  resolved open questions.
