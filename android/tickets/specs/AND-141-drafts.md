---
id: AND-141
title: Drafts
milestone: M3
epic: E19
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
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

The authoritative store is the backend resource family
`/messaging/conversations/{conversation_id}/drafts` (a **collection**, with
per-draft ids — CORRECTED from the original `/conversations/{id}/drafts`
singular assumption; see §16). The Android client mirrors this through a Room cache so drafts survive
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
- Web reference (VERIFIED): drafts live in `src/api/endpoints/messaging.ts`
  (`listConversationDrafts`, `createConversationDraft`, `getConversationDraft`,
  `updateConversationDraft`, `deleteConversationDraft`), the
  `ConversationDraft`/`CreateConversationDraftReq`/`UpdateConversationDraftReq`/
  `ConversationDraftListResp` types in `src/api/types.ts`, and the
  `useConversationDrafts` hook + `ComposeBar.tsx`. There is **no** `drafts.ts`
  module. Field names confirmed against these and `/openapi.json`
  (`DraftOut`/`DraftCreateIn`/`DraftPatchIn`); see §5 and §16.
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
text and the caret positioned at the end. Restore must succeed from the local
cache even with no network. (Server-side the resource is a list of drafts; the
client restores the most-recent draft — newest `updated_at` — as the single
active composer draft. See §5 / OQ-1.)

FR-2 **Save while typing.** Edits to the composer are persisted as a draft. Saves
are debounced (default 800ms after the last keystroke) to avoid write storms, and
flushed immediately on lifecycle stop (`onStop`) and when the conversation screen
is left.

FR-3 **Empty draft = delete.** If the composer is emptied (trimmed text is
empty), the draft is deleted locally and remotely rather than persisted. Note the
server rejects empty text anyway: `DraftCreateIn.text`/`DraftPatchIn.text` require
`minLength: 1` (max 4000), so a blank body must never be sent. (CORRECTED: drafts
are **text-only**; there is no attachment field in the draft contract — see §16.)

FR-4 **Clear on send.** When AND-124's send pipeline reports a successful send,
the active draft for that conversation is cleared (local + remote
`DELETE /messaging/conversations/{conversation_id}/drafts/{draft_id}` when a
`remoteId`/`draft_id` exists; local-only drafts are removed without a server call,
matching the web `deleteDraft` behavior).

FR-5 **Manual discard.** The composer overflow menu exposes a "Discard draft"
action, enabled only when a draft exists; selecting it clears the composer and
deletes the draft.

FR-6 **Local-first durability.** A draft is written to Room before (or
concurrently with) the network call; restore reads from Room. Network failures
never block save/restore and never surface a blocking error to the user.

FR-7 **Conflict resolution.** On open, the client lists server drafts and merges
with local copies by id, keeping the newer `updated_at`/`saved_at` per id
(matching the web `mergeDrafts`). The active composer draft is the most-recent
entry. If clocks make this ambiguous, the local copy wins (the user's device is
the source of truth for in-flight typing). The server also tracks an integer
`version` and accepts a `client_updated_at` (epoch ms) hint on create/patch.

FR-8 **Single ACTIVE draft per conversation (client policy).** The server permits
multiple drafts per conversation (list endpoint, up to ~20). AND-141's composer
surfaces exactly one active draft — the most-recent — keyed locally by
`conversationId`, holding the server `draft_id` as `remoteId`. This is a
client-side simplification of the multi-draft server model (see OQ-1/§16).

Out of scope: draft for new (not-yet-created) conversations; multi-recipient
draft fan-out; rich-text/markdown serialization beyond plain text;
attachment-in-draft (the draft contract is text-only); a multi-draft picker UI;
cross-device real-time sync (best-effort on open only).

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
    val text: String,               // CORRECTED: server field is `text`, not `body`
    val updatedAt: Instant,         // server `updated_at` is epoch-millis (Long) — convert
    val version: Int = 1,           // server `version` (integer)
    val clientUpdatedAt: Long? = null, // echoed to server as `client_updated_at` (epoch ms)
    val remoteId: String? = null,   // server `draft_id` once synced; null if local-only
)
```

NOTE (CORRECTED): the draft contract has **no attachments** — `DraftOut`/
`DraftCreateIn`/`DraftPatchIn` expose only `text` (+ `client_updated_at`). Any
attachment references in earlier drafts of this spec were unverified and removed.
Server timestamps (`created_at`, `updated_at`, `client_updated_at`) are **integer
epochs**, not ISO-8601 strings.

### Room (core-data)

```kotlin
@Entity(tableName = "drafts")
data class DraftEntity(
    @PrimaryKey val conversationId: String,  // local active-draft key (client policy, FR-8)
    val text: String,                // CORRECTED: was `body`
    val updatedAtEpochMs: Long,
    val version: Int = 1,            // mirrors server `version`
    val remoteId: String?,           // server `draft_id`; null while local-only
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
and provide an `@RenameColumn`-free additive migration (new table only). No
TypeConverter is needed (text-only draft; no attachment-id list to encode).

### Repository (core-data)

```kotlin
interface DraftRepository {
    fun observeDraft(conversationId: String): Flow<Draft?>
    /** Reconciles local + server on screen open; returns the draft to restore. */
    suspend fun loadAndReconcile(conversationId: String): ApiResult<Draft?>
    /** Debounced upstream of save(); persists locally then best-effort upsert. */
    suspend fun saveDraft(conversationId: String, text: String): ApiResult<Draft>
    /** Deletes locally then best-effort DELETE; used on send / discard / empty. */
    suspend fun clearDraft(conversationId: String): ApiResult<Unit>
}
```

`saveDraft` writes Room with `pendingSync = true`, then attempts the network
write — **POST** `.../drafts` (with an `Idempotency-Key`) when no `remoteId`
exists, or **PATCH** `.../drafts/{draft_id}` when it does (CORRECTED: the server
has no PUT-upsert; create is POST→201, update is PATCH→200). On success it sets
`remoteId`/`version` from `DraftOut` and `pendingSync = false`; on failure it
leaves `pendingSync = true` and returns `ApiResult.Success(localDraft)` (the save
itself succeeded locally — network is opportunistic). The web client sends an
`Idempotency-Key` of `${conversationId}:${tempId}` on create; mirror that pattern.

### Composer wiring (feature-conversation, extends AND-124)

Inside AND-124's `ConversationViewModel`:

```kotlin
private val draftSaver = MutableSharedFlow<DraftEdit>(extraBufferCapacity = 64)

init {
    // restore
    viewModelScope.launch {
        draftRepository.loadAndReconcile(conversationId).onSuccess { d ->
            d?.let { _uiState.update { s -> s.copy(
                composerText = TextFieldValue(it.text, TextRange(it.text.length)),
                hasDraft = true) } }
        }
    }
    // debounced save
    viewModelScope.launch {
        draftSaver.debounce(800.milliseconds).collectLatest { edit ->
            if (edit.text.isBlank())
                draftRepository.clearDraft(conversationId)
            else
                draftRepository.saveDraft(conversationId, edit.text)
        }
    }
}

fun onComposerChanged(value: TextFieldValue) {
    _uiState.update { it.copy(composerText = value) }
    draftSaver.tryEmit(DraftEdit(value.text))
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

Resource (VERIFIED against `/openapi.json` + `src/api/endpoints/messaging.ts`):
`/messaging/conversations/{conversation_id}/drafts` is a **collection** of
text-only drafts, each with its own `draft_id`. There is **no** singular
`/conversations/{id}/drafts` endpoint and **no** PUT verb (the original spec was
wrong on both). The real operations are:

| Verb   | Path | OpenAPI op / schema |
|--------|------|---------------------|
| GET    | `/messaging/conversations/{conversation_id}/drafts` | `list_conversation_drafts...` → 200 `DraftListOut` (params: `limit`, `cursor`) |
| POST   | `/messaging/conversations/{conversation_id}/drafts` | `create_conversation_draft...` req `DraftCreateIn` → 201 `DraftEnvelope` (header `Idempotency-Key`) |
| GET    | `/messaging/conversations/{conversation_id}/drafts/{draft_id}` | `get_conversation_draft...` → 200 `DraftEnvelope` |
| PATCH  | `/messaging/conversations/{conversation_id}/drafts/{draft_id}` | `patch_conversation_draft...` req `DraftPatchIn` → 200 `DraftEnvelope` |
| DELETE | `/messaging/conversations/{conversation_id}/drafts/{draft_id}` | `delete_conversation_draft...` → **204** |

All five also declare `422 HTTPValidationError`. Auth: see §2 (cookie session +
`ui_csrf`→`X-CSRF-Token`). The OpenAPI `authorization`/`X-SESSION-ID` params are
the server-side header alternatives; the web client and this Android client use
the cookie+CSRF transport (verified `credentials:"include"` in `src/api/client.ts`).

```kotlin
interface DraftApi {
    @GET("messaging/conversations/{cid}/drafts")
    suspend fun listDrafts(
        @Path("cid") conversationId: String,
        @Query("limit") limit: Int = 20,
        @Query("cursor") cursor: String? = null,
    ): Response<DraftListDto>

    @POST("messaging/conversations/{cid}/drafts")
    suspend fun createDraft(
        @Path("cid") conversationId: String,
        @Header("Idempotency-Key") idempotencyKey: String,
        @Body body: DraftCreateDto,
    ): Response<DraftEnvelopeDto>   // 201

    @GET("messaging/conversations/{cid}/drafts/{draftId}")
    suspend fun getDraft(
        @Path("cid") conversationId: String,
        @Path("draftId") draftId: String,
    ): Response<DraftEnvelopeDto>

    @PATCH("messaging/conversations/{cid}/drafts/{draftId}")
    suspend fun patchDraft(
        @Path("cid") conversationId: String,
        @Path("draftId") draftId: String,
        @Body body: DraftPatchDto,
    ): Response<DraftEnvelopeDto>

    @DELETE("messaging/conversations/{cid}/drafts/{draftId}")
    suspend fun deleteDraft(
        @Path("cid") conversationId: String,
        @Path("draftId") draftId: String,
    ): Response<Unit>               // 204
}
```

DTOs (Moshi) — field names/types verified against `DraftOut`/`DraftCreateIn`/
`DraftPatchIn` and `ConversationDraft` in `src/api/types.ts`:

```kotlin
@JsonClass(generateAdapter = true)
data class DraftCreateDto(   // == DraftCreateIn
    @Json(name = "text") val text: String,                  // minLen 1, maxLen 4000
    @Json(name = "client_updated_at") val clientUpdatedAt: Long? = null, // epoch ms
)

@JsonClass(generateAdapter = true)
data class DraftPatchDto(     // == DraftPatchIn (same shape)
    @Json(name = "text") val text: String,
    @Json(name = "client_updated_at") val clientUpdatedAt: Long? = null,
)

@JsonClass(generateAdapter = true)
data class DraftEnvelopeDto(@Json(name = "draft") val draft: DraftDto)

@JsonClass(generateAdapter = true)
data class DraftListDto(
    @Json(name = "items") val items: List<DraftDto>,
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class DraftDto(          // == DraftOut
    @Json(name = "draft_id") val draftId: String,
    @Json(name = "conversation_id") val conversationId: String,
    @Json(name = "owner_user_id") val ownerUserId: String,
    @Json(name = "text") val text: String,
    @Json(name = "version") val version: Int,
    @Json(name = "created_at") val createdAt: Long,         // epoch (int)
    @Json(name = "updated_at") val updatedAt: Long,         // epoch (int)
    @Json(name = "client_updated_at") val clientUpdatedAt: Long? = null,
    @Json(name = "tenant_id") val tenantId: String? = null,
)
```

Request example (POST `DraftCreateIn`):

```json
{ "text": "see you at 6, bring the keys", "client_updated_at": 1749132191000 }
```

Response example (POST 201 / GET / PATCH 200 — enveloped `DraftEnvelope`):

```json
{
  "draft": {
    "draft_id": "drf_01H...",
    "conversation_id": "cnv_8842",
    "owner_user_id": "usr_123",
    "text": "see you at 6, bring the keys",
    "version": 3,
    "created_at": 1749132100000,
    "updated_at": 1749132191000,
    "client_updated_at": 1749132191000,
    "tenant_id": null
  }
}
```

List response (GET 200 — `DraftListOut`):

```json
{ "items": [ /* DraftOut... */ ], "next_cursor": null }
```

Semantics (CORRECTED): the list **GET** returns `{items, next_cursor}` — an empty
`items` array means no draft (NOT a 404). Per-draft **GET/{draft_id}** returns
`DraftEnvelope` or 404 if that id is gone. **POST** creates (201) and carries an
`Idempotency-Key`; **PATCH** updates an existing `draft_id` (200). **DELETE**
returns **204** and is treated idempotently (404 on delete → success). Mutating
calls (POST/PATCH/DELETE) are **not** retried on transient network errors; only
the list-GET on open is retried with bounded backoff. Per the web hook, a
local-only draft (no `remoteId`) is never PATCHed/DELETEd on the wire — it is
created via POST, or removed locally only.

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
  list-GET only seeds/updates Room via `loadAndReconcile`.
- `hasDraft` is derived from a non-null, non-blank persisted draft and gates the
  "Discard draft" menu item.
- Reconcile (FR-7): compare `local.updatedAtEpochMs` vs server `updated_at` (both
  epoch ms; CORRECTED — server timestamps are integers, not ISO strings); keep
  newer, write the winner to Room, mark `pendingSync=false` if server won or push
  if local won. The active draft is the most-recent `draft_id` from the list.
- Process death: because Room is written on every debounced edit and on
  `ON_STOP`, the draft is recoverable after the OS kills the process; restore on
  next open reads Room first, then reconciles.
- StateFlow exposed as `val uiState: StateFlow<ConversationUiState>` per the
  project ViewModel convention.

## 7. Error Handling & Resilience

- **Local writes never fail the user.** `saveDraft`/`clearDraft` complete on the
  Room write; network is best-effort. A failed POST/PATCH leaves `pendingSync=true`
  and sets `draftSyncState = SavedLocal` (not `Error`-blocking).
- **List-GET on open** uses the shared ~20s timeout and bounded backoff retry
  (idempotent GET): on exhausted failure, fall back to the local Room draft and
  surface `DraftSyncState.Error` non-intrusively (no dialog).
- **Empty list (no `items`)** → no draft, never an error. **404 on single-draft
  GET/DELETE** → success/empty, never an error toast. (CORRECTED: the absence of a
  draft is an empty list, not a 404 on the collection GET.)
- **422 `HTTPValidationError`** (e.g. text outside 1–4000 chars) maps through the
  shared `detail: [{msg, loc, type}]` parser; the composer never sends empty text
  (FR-3), so 422 is a defensive case only.
- **401** is handled by the shared interceptor (single `POST /ui/session/refresh`
  then retry); if refresh fails, the draft stays local and pendingSync remains.
- **Pending-sync flush:** `DraftRepository` exposes `flushPending()` invoked on
  conversation open and on app foreground to push any `pendingSync=true` rows;
  failures are silent and retried next opportunity. No background WorkManager job
  is required for P2 (open/foreground flush is sufficient).
- **Empty/whitespace** text is normalized via `trim()` for storage (the web hook
  uses `text.trim()` and refuses to save an empty string); a fully blank body
  triggers delete, not save (FR-3).
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
  - save → Room written `pendingSync=true`; on 201 POST → `remoteId`/`version`
    set, `pendingSync=false`; subsequent save with a `remoteId` issues PATCH. (**saves**)
  - blank text → `clearDraft` path, DELETE issued (when remote), row removed. (FR-3)
  - `loadAndReconcile`: server-only draft seeds Room; local-newer wins and pushes;
    server-newer overwrites Room; empty `items` list → `Success(null)`; GET timeout
    → falls back to local Room copy. (**restores** + FR-7)
  - clear on send/discard removes row + issues DELETE (204) when remote; local-only
    draft removed with no server call; 404 on DELETE → success. (**clears**)
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

- **OQ-1 Endpoint shape — RESOLVED.** Verified collection-based with draft ids:
  `GET/POST /messaging/conversations/{conversation_id}/drafts` and
  `GET/PATCH/DELETE .../drafts/{draft_id}` (no singular resource, no PUT). `DraftApi`
  in §5 reflects this; the client treats the **most-recent** draft as the single
  active one (FR-8 client policy).
- **OQ-2 Field naming — RESOLVED.** Verified: field is `text` (not `body`); there
  is **no** attachment field on drafts at all; timestamps (`created_at`,
  `updated_at`, `client_updated_at`) are **integer epochs**; responses are
  enveloped (`{ "draft": ... }` / `{ "items": [...], "next_cursor": ... }`).
- **R-1 Clock skew** undermines `updatedAt` reconcile (FR-7); mitigated by
  local-wins tiebreak, but server clock drift could discard a newer local edit if
  the device clock is far behind. Acceptable for P2.
- **R-2 Unreliable dev host** can make GET-on-open slow; mitigated by local-first
  restore (do not block the composer on the network GET).
- **R-3 Attachment lifecycle — N/A (removed).** The draft contract is text-only;
  there is no attachment reference on a draft. Attachment-in-draft, if ever
  desired, is a separate backend change, not part of AND-141.
- **R-4 Multi-draft drift.** The server allows multiple drafts per conversation;
  the client collapses to one active draft. If another client (web) creates
  several drafts, the Android composer only restores the newest and may leave
  older server drafts undeleted. Acceptable for P2 (matches "single active draft"
  UX); a multi-draft picker is out of scope.
- **OQ-3 Backup policy** — confirm app-wide `allowBackup` stance with the app
  module owner (AND-124/app config).

## 14. Acceptance Criteria

AC-1 (**saves**) Typing in the composer and leaving it idle ≥800ms (or stopping
the activity) persists a draft to Room; with network available a `POST
/messaging/conversations/{conversation_id}/drafts` (with `Idempotency-Key`) is
issued for a new draft, or `PATCH .../drafts/{draft_id}` for an existing one, and
`remoteId`/`version`/`pendingSync` are updated. Verified by repository + ViewModel
tests.

AC-2 (**restores**) Reopening a conversation that has a draft pre-populates the
composer with the exact saved `text`, caret at end, `hasDraft=true` — and does so
from local cache with no network. Server reconcile (list-GET, merge by newest
`updated_at`) keeps the newest copy. Verified by repository reconcile tests and a
Compose UI test.

AC-3 (**clears**) A successful send clears the active draft locally and issues
`DELETE .../drafts/{draft_id}` (204) when a `remoteId` exists; "Discard draft"
clears the composer and deletes the draft; emptying the composer deletes rather
than stores an empty draft (server enforces `text` minLength 1). Local-only
drafts are removed without a server call. Verified by ViewModel + repository tests.

AC-4 Network failures on save/clear never lose the local draft and never show a
blocking error; the draft is re-pushed on next open/foreground (`pendingSync`).

AC-5 An empty list (`items: []`) on the collection GET, and 404 on single-draft
GET/DELETE, are treated as success/empty (no error surfaced).

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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the authoritative source pointer.

1. **Drafts endpoint base path is `/messaging/conversations/{conversation_id}/drafts`** (not `/conversations/{id}/drafts`). VERDICT: Corrected. SOURCE: OpenAPI `GET /messaging/conversations/{conversation_id}/drafts` (op `list_conversation_drafts...`); frontend `src/api/endpoints/messaging.ts: listConversationDrafts`.
2. **The resource is a collection of drafts with per-draft ids** (`.../drafts/{draft_id}`), not a singular per-conversation draft. VERDICT: Corrected. SOURCE: OpenAPI `GET/PATCH/DELETE /messaging/conversations/{conversation_id}/drafts/{draft_id}`; frontend `messaging.ts: getConversationDraft/updateConversationDraft/deleteConversationDraft`.
3. **Create = POST → 201, returning `DraftEnvelope`; an `Idempotency-Key` header is sent.** VERDICT: Corrected (spec said PUT upsert). SOURCE: OpenAPI `POST .../drafts | req=DraftCreateIn | resp=201:DraftEnvelope | params=Idempotency-Key`; frontend `messaging.ts: createConversationDraft` (`headers: { "Idempotency-Key": ... }`), key format `${conversationId}:${tempId}` in `useConversationDrafts.ts: saveDraft`.
4. **Update = PATCH → 200 `DraftEnvelope`** (no PUT verb exists). VERDICT: Corrected. SOURCE: OpenAPI `PATCH .../drafts/{draft_id} | req=DraftPatchIn | resp=200:DraftEnvelope`; frontend `messaging.ts: updateConversationDraft`.
5. **Delete = DELETE → 204** (single draft by id). VERDICT: Corrected (spec said 204/200 on the collection path). SOURCE: OpenAPI `DELETE .../drafts/{draft_id} | resp=204`; frontend `messaging.ts: deleteConversationDraft` (`api.del(.../drafts/${draftId})`).
6. **List response shape is `{ items: DraftOut[], next_cursor?: string }`.** VERDICT: Corrected. SOURCE: `components.schemas.DraftListOut`; frontend `types.ts: ConversationDraftListResp`.
7. **Single-draft responses are enveloped: `{ "draft": DraftOut }`.** VERDICT: Corrected (spec returned a bare object). SOURCE: `components.schemas.DraftEnvelope`; frontend `messaging.ts` (`api<{ draft: ConversationDraft }>`).
8. **Draft body field is `text`, not `body`.** VERDICT: Corrected. SOURCE: `components.schemas.DraftOut.text`, `DraftCreateIn.text`, `DraftPatchIn.text`; frontend `types.ts: ConversationDraft.text`.
9. **`text` is constrained to minLength 1, maxLength 4000.** VERDICT: Verified (new, added to spec). SOURCE: `components.schemas.DraftCreateIn.text` / `DraftPatchIn.text` (`minLength:1, maxLength:4000`).
10. **There is NO attachment field on a draft** (`attachment_ids`/`attachments` do not exist in the draft contract). VERDICT: Corrected (spec invented `attachment_ids`). SOURCE: full property lists of `DraftOut`/`DraftCreateIn`/`DraftPatchIn` (only `text`, `client_updated_at`, plus server-managed ids/timestamps); frontend `types.ts: CreateConversationDraftReq`/`UpdateConversationDraftReq` (only `text` + `client_updated_at`).
11. **Timestamps (`created_at`, `updated_at`, `client_updated_at`) are integer epochs, not ISO-8601 strings.** VERDICT: Corrected. SOURCE: `DraftOut` (`created_at`/`updated_at`: `type: integer`; `client_updated_at` int); frontend `messaging.ts: adaptConversationDraft` coerces all via `Number(...)`.
12. **Drafts carry `version` (int), `owner_user_id`, optional `tenant_id`.** VERDICT: Verified (added). SOURCE: `components.schemas.DraftOut.required = [draft_id, conversation_id, owner_user_id, text, version, created_at, updated_at]`; frontend `types.ts: ConversationDraft`.
13. **Auth: cookie session + `ui_csrf` cookie echoed as `X-CSRF-Token`; `credentials: "include"`.** VERDICT: Verified. SOURCE: `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`, `credentials: "include"`). NOTE: OpenAPI also lists `authorization`/`X-SESSION-ID` params as alternative transport; the web/Android client uses cookie+CSRF.
14. **401 handling = single `POST /ui/session/refresh` then retry once; second 401 logs out.** VERDICT: Verified. SOURCE: `src/api/client.ts` (`refreshSession()` posts `/ui/session/refresh`, single in-flight `refreshPromise`, retry, `logout("session_expired")` on retry 401).
15. **Error bodies use FastAPI `detail` convention; 422 is `HTTPValidationError`.** VERDICT: Verified. SOURCE: OpenAPI (every drafts op declares `422:HTTPValidationError`); `src/api/client.ts: normalizeErrorDetail((body)?.detail, ...)`.
16. **Local-first behavior: write local first, network best-effort; local-only drafts (no remote id) are never PATCHed/DELETEd on the wire.** VERDICT: Verified (matches client policy in spec). SOURCE: `src/pages/messages/useConversationDrafts.ts` (`saveDraft` optimistic local write then async POST; `deleteDraft`/`saveExistingDraft` skip the API when `draftId.startsWith("local-")`).
17. **Reconcile = merge by id, keep newer timestamp; offline falls back to local.** VERDICT: Verified. SOURCE: `useConversationDrafts.ts: mergeDrafts` (keeps `>= saved_at`), `refresh` catch → local fallback + `classifySyncIssue`.
18. **Absence of a draft is an empty `items` list, not a 404 on the collection GET.** VERDICT: Corrected (spec mapped GET 404 → `Success(null)`). SOURCE: `DraftListOut` (always returns `items`); frontend `refresh` reads `resp.items ?? []`.
19. **Kotlin/Compose framework choices** (Room, Moshi, Retrofit, StateFlow, `LifecycleEventEffect`, `TextFieldValue`/`TextRange`, `debounce`/`collectLatest`). VERDICT: Unverified-assumption (framework ref — these are reasonable Android Jetpack choices, not derivable from the backend/frontend sources). SOURCE: framework ref — developer.android.com (Room, Compose text, Lifecycle), kotlinlang.org coroutines/Flow. The specific module layout (`core-*`/`feature-conversation`) is an AND-124-owned assumption.
20. **`allowBackup`/auto-backup exclusion for the drafts DB.** VERDICT: Unverified-assumption. SOURCE: app manifest is owned by AND-124/app-config; not present in the provided reference sources (OQ-3).

### Corrections made

- Endpoint family changed from singular `/conversations/{id}/drafts` (PUT/GET/DELETE) to the real collection `/messaging/conversations/{conversation_id}/drafts` + `/drafts/{draft_id}` with **POST (201) / PATCH (200) / DELETE (204)** verbs and an `Idempotency-Key` on create. (§1, §2, §4, §5, §7, §13, §14)
- Removed the invented `attachment_ids` field everywhere; drafts are **text-only**. (§3 FR-3, §4 model/entity/repo, §5 DTOs, §13 R-3)
- Renamed `body` → `text` in domain model, Room entity, repository, ViewModel wiring, and DTOs. (§4, §5)
- Timestamps corrected from ISO-8601 strings to **integer epochs**; added `version`, `owner_user_id`, `tenant_id`, `client_updated_at`. (§4, §5, §6)
- Responses corrected to enveloped shapes (`{draft}` / `{items,next_cursor}`); GET-absence corrected from 404 to empty list. (§5, §7, §14 AC-5)
- Single-draft assumption reframed as a **client policy** over a multi-draft server model (FR-8); added R-4 multi-draft drift. (§3, §13)
- Resolved OQ-1 and OQ-2 with source pointers. (§13)
- Save path corrected to POST-for-new / PATCH-for-existing; clear path skips server DELETE for local-only drafts. (§4, §5, §11, §14)

### Open assumptions

- **A-1 ViewModel/composer surface** (`ConversationViewModel`, `MessageComposer`, module layout) is inherited from AND-124, which is not in the provided sources — unverifiable here; flagged as a dependency.
- **A-2 `allowBackup`/auto-backup exclusion** (OQ-3) — manifest not in sources; must be confirmed with the app-module owner.
- **A-3 Android framework specifics** (Room/Moshi/Retrofit/Compose APIs, 800ms debounce default, `~20s` dev timeout) are framework-ref/engineering choices, not contract-derived.
- **A-4 Idempotency-Key format** — the web uses `${conversationId}:${tempId}`; Android should mirror it, but the server's exact key-collision/replay semantics are not documented in the index (only that the header is accepted on POST).
- **A-5 "Discard draft" overflow menu** is an Android-specific UX; the web reference exposes draft list/load/delete via `useConversationDrafts` but no identical single "Discard draft" affordance — treat as a new client surface.

## 17. Test Plan

Test target legend: JVM = JVM unit/Robolectric (local, no device); EMU = headless emulator AVD `test35` (x86_64, API 35); DEVICE = physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). Drafts is a text/storage/networking feature with no camera/biometric/WebRTC/push dependency, so most cases run on JVM/EMU; DEVICE is used only where real-hardware behavior (process-death timing, real flaky-network, on-device Room/IME) is meaningfully different.

- **TC-AND-141-01 — Save persists locally then upserts (happy path).** Type: contract/MockWebServer + unit. Target: JVM (`DraftRepository`). Preconditions: no existing remote draft; MockWebServer queued `201 DraftEnvelope`. Steps: call `saveDraft(cid, "hello")`. Expected: Room row written `pendingSync=true` first; then `POST /messaging/conversations/{cid}/drafts` issued with header `Idempotency-Key` and body `{ "text": "hello", "client_updated_at": <ms> }`; on 201, row updated with `remoteId=draft_id`, `version`, `pendingSync=false`; returns `ApiResult.Success`. Traces: AC-1, AC-7.
- **TC-AND-141-02 — Existing draft updates via PATCH (not POST).** Type: contract/MockWebServer. Target: JVM. Preconditions: Room row has `remoteId="drf_1"`; MockWebServer queued `200 DraftEnvelope` (version bumped). Steps: `saveDraft(cid, "hello world")`. Expected: request is `PATCH .../drafts/drf_1` body `{text, client_updated_at}` (no second POST); `version` updated from response. Traces: AC-1.
- **TC-AND-141-03 — Debounced save coalesces keystrokes.** Type: unit (Turbine + virtual clock). Target: JVM (`ConversationViewModel`). Preconditions: `MainDispatcherRule`, `StandardTestDispatcher`. Steps: emit 5 `onComposerChanged` within 800ms, advance virtual time 800ms. Expected: exactly one `saveDraft` invoked with the final text. Traces: AC-1.
- **TC-AND-141-04 — Restore on open from local cache, no network.** Type: unit + Compose-UI. Target: JVM repo test + EMU Compose test. Preconditions: Room seeded with a draft `text="see you at 6"`; network disabled / MockWebServer not enqueued. Steps: open conversation. Expected: `composerText` = exact text, caret `TextRange(text.length)`, `hasDraft=true`; no crash on absent network; restore source = local. Traces: AC-2, AC-7.
- **TC-AND-141-05 — Reconcile keeps newest copy; empty list = no draft.** Type: contract/MockWebServer. Target: JVM (`loadAndReconcile`). Preconditions: cases (a) server `items` newer than local, (b) local newer than server (pushes PATCH/POST), (c) `items: []`. Steps: run `loadAndReconcile(cid)`. Expected: (a) Room overwritten with server text, `pendingSync=false`; (b) local kept and pushed; (c) returns `Success(null)`, no error (NOT treated as 404). Traces: AC-2, AC-5.
- **TC-AND-141-06 — Empty composer deletes rather than stores empty.** Type: unit. Target: JVM (ViewModel + repo). Preconditions: existing draft with `remoteId`. Steps: change composer to "   " (whitespace), advance debounce. Expected: `clearDraft` path taken (no POST/PATCH of empty text; server `text` minLength 1 never violated); `DELETE .../drafts/{id}` issued; row removed. Traces: AC-3.
- **TC-AND-141-07 — Clear on successful send.** Type: unit. Target: JVM (ViewModel). Preconditions: draft present with `remoteId`; AND-124 send returns success. Steps: trigger send-success callback. Expected: `clearDraft(cid)` called, `DELETE` issued (204), `composerText` reset, `hasDraft=false`. Traces: AC-3, AC-7.
- **TC-AND-141-08 — Discard draft menu.** Type: Compose-UI. Target: EMU (`createAndroidComposeRule`). Preconditions: conversation opened (a) with a draft, (b) without. Steps: open composer overflow. Expected: "Discard draft" enabled only in (a); tapping clears the field, sets `hasDraft=false`, calls `clearDraft`; local-only draft removed without a server call. Traces: AC-3.
- **TC-AND-141-09 — Flush on ON_STOP / onCleared bypasses debounce.** Type: instrumented. Target: EMU. Preconditions: a buffered un-debounced edit exists. Steps: drive `Lifecycle.Event.ON_STOP` (and `onCleared`). Expected: a save is flushed immediately (Room write occurs before the 800ms window elapses); no edit lost. Traces: AC-1, AC-4.
- **TC-AND-141-10 — Offline/flaky dev-host: save never lost, re-pushed later.** Type: integration. Target: DEVICE (real flaky network / airplane-mode toggling on hardware best reproduces the ~20s-timeout dev host). Preconditions: network off (or MockWebServer with socket timeout). Steps: type and idle; bring network back; reopen/foreground. Expected: Room row `pendingSync=true`, no blocking error/dialog, `draftSyncState=SavedLocal`; on foreground/open `flushPending()` retries POST/PATCH and clears `pendingSync`. Traces: AC-4.
- **TC-AND-141-11 — Process-death recovery.** Type: instrumented/e2e. Target: DEVICE (real low-memory process kill differs from emulator; use `adb shell am kill` / Don't-keep-activities). Preconditions: draft typed and persisted on ON_STOP. Steps: kill the app process, relaunch, reopen conversation. Expected: composer restored from Room with exact text and caret at end. Traces: AC-2, AC-4.
- **TC-AND-141-12 — 404 on single-draft DELETE/GET treated as success.** Type: contract/MockWebServer. Target: JVM. Preconditions: MockWebServer queued `404` for `DELETE .../drafts/{id}` and for single-draft GET. Steps: `clearDraft`/`getDraft`. Expected: treated as success/empty; row removed; no error toast/surface. Traces: AC-5.
- **TC-AND-141-13 — 401 refresh-then-retry; refresh failure keeps local + pendingSync.** Type: contract/MockWebServer. Target: JVM. Preconditions: queue `401` on POST, then `200` for `/ui/session/refresh`, then `201` retry; second variant: refresh itself 401s. Steps: `saveDraft`. Expected: variant 1 → single refresh then successful retry, `pendingSync=false`; variant 2 → no infinite loop, draft stays local `pendingSync=true`, no blocking error. Traces: AC-4.
- **TC-AND-141-14 — Security/privacy: no draft text in logs or analytics; app-private storage.** Type: unit + manual. Target: JVM (analytics/logging asserts) + DEVICE (manual logcat + `run-as` storage inspection). Preconditions: analytics facade captured in test; Timber tree captured. Steps: perform save/restore/clear; capture emitted events and log lines; on device inspect `data/data/com.testlogon.android` and run a backup if `allowBackup` enabled. Expected: events contain only `conversation_id`, `body_len`/length, sync state, error code — never the draft text; no draft body in logcat; drafts DB excluded from auto-backup (or `allowBackup=false`). Traces: AC-6.
- **TC-AND-141-15 — Accessibility of Discard action.** Type: Compose-UI (instrumented a11y). Target: EMU. Preconditions: composer with a draft. Steps: assert semantics for the "Discard draft" item. Expected: non-empty `contentDescription` + visible label from `strings.xml` (`R.string.draft_discard`); touch target ≥48dp; works under RTL; TalkBack reads a meaningful label. Traces: AC-3, AC-6 (no PII announced).

### Coverage matrix (AC → TCs)

| Acceptance criterion | Covered by |
|----------------------|------------|
| AC-1 (saves; POST/PATCH + remoteId/version/pendingSync) | TC-01, TC-02, TC-03, TC-09 |
| AC-2 (restores; local-first, caret, newest reconcile) | TC-04, TC-05, TC-11 |
| AC-3 (clears; send/discard/empty → delete) | TC-06, TC-07, TC-08, TC-15 |
| AC-4 (offline never loses draft; re-push; no blocking error) | TC-09, TC-10, TC-11, TC-13 |
| AC-5 (empty list / 404 GET/DELETE → success) | TC-05, TC-12 |
| AC-6 (no draft content in logs/analytics) | TC-14, TC-15 |
| AC-7 (named save/restore/clear tests in CI) | TC-01, TC-04, TC-07 |
