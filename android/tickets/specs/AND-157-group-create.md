---
id: AND-157
title: Group create
milestone: M3
epic: E22
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-120]
blocks: []
---

# AND-157 — Group create

## 1. Overview & Goal

Add a "create group conversation" flow to the messaging area: a screen where the user names a new group, optionally picks an avatar, selects two or more participants, and submits to `POST /messaging/conversations/group` (corrected: the backlog wrote `/conversations/group`, but the real path is namespaced under `/messaging`; verified against OpenAPI and the web client). On a successful response the new group conversation is created server-side and the app **navigates directly into the new thread** (the conversation list also reflects the new group). The defining, testable outcome from the backlog is verbatim: **"Group creates and opens."** — i.e., a valid submission both (a) creates the group on the backend and (b) opens the resulting thread.

This ticket owns the *write path* for group creation only: the create-group screen, its `GroupCreateViewModel`, the `createGroup` repository/API method, and the request/response DTOs for the group-create endpoint. It consumes — and does not re-implement — the messaging foundation from AND-120 (`MessagingApi`, conversation/message DTOs, base error mapping), the conversation list (AND-121/AND-122) into which the new group appears, and the thread screen (AND-123) that is opened on success. Participant discovery (the people-picker data source) reuses the messaging/profile search surface where available; if no search endpoint exists yet, the picker degrades to manual `u/`-identifier entry (see §13 OQ-1).

## 2. Context & References

- **Module:** `feature-messaging` (Gradle module `:feature:messaging`), package `com.testlogon.android.feature.messaging.groupcreate`. The screen is a new route inside the existing messaging feature module, not a new module.
- **Layering:** `feature-messaging` -> `core-network` (Retrofit service, `ApiResult<T>`, error decoder), `core-model` (DTO/domain), `core-data` (repository + Room cache), `core-ui` (Compose components, theme, state composables), `core-testing`. No backward dependencies; ViewModel exposes `StateFlow<GroupCreateUiState>`.
- **Backend:** FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000` (plaintext HTTP, unreliable). OpenAPI at `/openapi.json`. **Auth (corrected/clarified vs the web client `src/api/client.ts`):** the web client sends *three* things on each call — `Authorization: Bearer <accessToken>` (from its auth store), `X-CSRF-Token: <ui_csrf cookie>`, and `credentials: include` (session cookies). The OpenAPI parameter list for the group endpoint also names `authorization` and `X-SESSION-ID` headers. So it is **not cookie-only**: the Android client must attach the bearer/session token *and* the CSRF header *and* the cookie jar. On `401` the web client refreshes once via `POST /ui/session/refresh` (verified `src/api/client.ts: refreshSession`) and retries; the Android OkHttp authenticator mirrors this. Persistent cookie jar plus token store required (established by the core-network/auth tickets, AND-011/AND-012/AND-013).
- **Web reference (corrected file paths):** the group-create call lives in `src/api/endpoints/messaging.ts` (`startGroupConversation` -> `POST /messaging/conversations/group`), **not** a `conversations.ts` file. Request/response types are in `src/api/types.ts` (`StartGroupConversationReq`, `Conversation`, `Participant`, `UserSearchResult`). The Android DTOs here must mirror those shapes (verified against `/openapi.json` schemas `StartGroupConversationIn`, `ConversationOut`, `app__routers__messaging__ParticipantOut`).
- **Dependency AND-120** (Messaging API + DTOs) supplies: `MessagingApi` Retrofit interface, `ConversationDto`/domain `Conversation`, the shared `apiCall { }` helper and FastAPI `detail` decoder, and the Room conversation cache. AND-157 *extends* `MessagingApi` with the group-create method and adds the screen/ViewModel.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, single-Activity Navigation-Compose, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15, Room 2.6, DataStore, Coil (avatar). minSdk 24 / compile+target 35, JDK 17, Gradle 8.9, AGP 8.7.3.
- **Avatar upload** reuses the media-upload path established for profiles (AND-074) if the group endpoint accepts a pre-uploaded media reference; otherwise avatar is optional and deferred (see §13 OQ-2).

## 3. Functional Requirements

FR-1. A "New group" entry point is available from the conversation list (AND-121) top app bar / FAB. Tapping it navigates to the `groupCreate` route via Navigation-Compose.

FR-2. The Group Create screen presents: (a) an editable **group name** field; (b) an optional **avatar** picker (tap to choose from gallery via the system photo picker / `PickVisualMedia`); (c) a **participant selector** (search + multi-select list of selectable people, with a chips row of chosen participants); (d) a **Create** action in the top app bar (or primary button).

FR-3. Group name maps to the backend `title` field (corrected: there is no `name` field — see §5). **Backend note:** in the OpenAPI schema `StartGroupConversationIn`, `title` is *optional* and has **no server-side max length**; only `participant_ids` is required. This ticket nonetheless keeps name as a **product/UX-required** field (a group without a human name is poor UX) and trims it: empty/whitespace-only name disables Create. The 80-character cap is a **client-only guard** (unverified against backend — backend does not enforce it; `description` caps at 500 and `topic` at 200 per schema, but `title` is uncapped). Over-limit is blocked with an inline counter, not silently truncated.

FR-4. Participant selection requires **at least 2** other participants (a group, distinct from a 1:1 DM). The current user is implicitly a member and is **not** counted toward, nor selectable in, that minimum. The **min-2** rule is verified against the backend (`StartGroupConversationIn.participant_ids` has `minItems: 2`). The upper bound (client default 256) is an **unverified assumption** — the schema declares no `maxItems`; enforce a client guard and rely on `422` for any server cap.

FR-5. Selecting/deselecting a participant updates a chips row; a chip's close affordance removes that participant. Already-selected people are visually marked in the list and cannot be added twice (dedupe by user id).

FR-6. Avatar is **optional**. If chosen, it is shown as a circular preview; it can be cleared. If avatar upload is not yet supported by the endpoint, the avatar control is hidden behind a build/feature flag and group creation proceeds without it (see §13 OQ-2).

FR-7. Create is enabled only when name is valid (non-empty, within limit) **and** participant count is within `[2, max]`. The button reflects a busy state while the request is in flight; the screen is non-interactive (or fields disabled) during submission to prevent double-submit.

FR-8. On successful creation, the app navigates to the new conversation's thread (AND-123) using the returned conversation `id`, **popping** the group-create screen off the back stack so Back from the thread returns to the conversation list — not to the create form. The new group also appears in the conversation list cache.

FR-9. On failure the screen stays on the form with all input preserved (name, avatar, selected participants), surfaces a mappable error (inline for validation `422`, snackbar for transient/network), and re-enables Create for retry.

FR-10. Back/cancel from the form with unsaved input prompts a discard confirmation (Material 3 `AlertDialog`) to avoid accidental loss of a partially-built group.

## 4. Technical Design

### 4.1 Navigation

A new route is registered in the authenticated messaging nav graph (AND-024/AND-022):

```kotlin
// routes
const val ROUTE_GROUP_CREATE = "messaging/group/create"

fun NavGraphBuilder.groupCreateScreen(
    onGroupCreated: (conversationId: String) -> Unit,
    onBack: () -> Unit,
) {
    composable(ROUTE_GROUP_CREATE) {
        GroupCreateRoute(onGroupCreated = onGroupCreated, onBack = onBack)
    }
}
```

`onGroupCreated` is wired by the host to:
```kotlin
navController.navigate(threadRoute(conversationId)) {
    popUpTo(ROUTE_CONVERSATION_LIST) { inclusive = false } // drop group-create form
}
```

### 4.2 UI state

```kotlin
data class ParticipantUi(
    val userId: String,
    val displayName: String,
    val handle: String,        // u/identifier
    val avatarUrl: String?,
    val selected: Boolean = false,
)

data class GroupCreateUiState(
    val name: String = "",
    val nameError: Int? = null,        // string res id, null = ok
    val charCount: Int = 0,
    val avatarUri: Uri? = null,        // local picked image, pre-upload
    val query: String = "",
    val candidates: List<ParticipantUi> = emptyList(),
    val selected: List<ParticipantUi> = emptyList(),
    val isSearching: Boolean = false,
    val isSubmitting: Boolean = false,
    val canCreate: Boolean = false,
    val error: UiError? = null,        // transient submit/search error -> snackbar
)
```

`canCreate = name.isNotBlank() && charCount <= 80 && selected.size in 2..MAX_PARTICIPANTS && !isSubmitting`.

### 4.3 ViewModel

```kotlin
@HiltViewModel
class GroupCreateViewModel @Inject constructor(
    private val repo: GroupCreateRepository,
) : ViewModel() {

    private val _state = MutableStateFlow(GroupCreateUiState())
    val state: StateFlow<GroupCreateUiState> = _state.asStateFlow()

    // one-shot navigation events
    private val _events = MutableSharedFlow<GroupCreateEvent>(extraBufferCapacity = 1)
    val events: SharedFlow<GroupCreateEvent> = _events.asSharedFlow()

    fun onNameChange(value: String)
    fun onQueryChange(value: String)          // debounced search (300ms)
    fun onToggleParticipant(userId: String)
    fun onRemoveParticipant(userId: String)
    fun onAvatarPicked(uri: Uri?)
    fun onCreateClick()
    fun onErrorShown()
}

sealed interface GroupCreateEvent {
    data class Created(val conversationId: String) : GroupCreateEvent
}
```

`onQueryChange` debounces (`@OptIn(FlowPreview)` `debounce(300)`) and calls `repo.searchParticipants(query)`; results are merged with current selections so selected people stay marked.

`onCreateClick`:
```kotlin
fun onCreateClick() {
    val s = _state.value
    if (!s.canCreate) return
    _state.update { it.copy(isSubmitting = true, error = null) }
    viewModelScope.launch {
        val avatarRef = s.avatarUri?.let { repo.uploadAvatar(it).getOrNull() } // optional
        when (val r = repo.createGroup(
            name = s.name.trim(),
            participantIds = s.selected.map { it.userId },
            avatarRef = avatarRef,
        )) {
            is ApiResult.Success -> _events.emit(GroupCreateEvent.Created(r.data.id))
            is ApiResult.Error ->
                _state.update { it.copy(isSubmitting = false, error = r.toUiError()) }
        }
    }
}
```

### 4.4 Repository

```kotlin
interface GroupCreateRepository {
    suspend fun searchParticipants(query: String): ApiResult<List<ParticipantUi>>
    suspend fun uploadAvatar(uri: Uri): ApiResult<String>     // returns media ref/url
    suspend fun createGroup(
        name: String,
        participantIds: List<String>,
        avatarRef: String?,
    ): ApiResult<Conversation>
}
```

`createGroup` builds `CreateGroupRequest` (mapping the Kotlin `name` arg -> JSON `title`, and `avatarRef` -> JSON `icon`; **not** `name`/`avatar_url`), calls `MessagingApi.createGroup`, maps `ConversationDto.toDomain()` (reading `conversation_id` and the numeric epoch `created_at` owned by AND-120), and on success **upserts** the new conversation into the Room conversation cache (AND-120) so the conversation list (AND-121/122) reflects it without a forced refresh. `searchParticipants` calls `GET /messaging/contacts/search` and maps `UserSearchResult{user_id, display_name}` -> `ParticipantUi` (handle/avatar unavailable from that endpoint). All work via the shared `apiCall { }` helper that converts non-2xx/exceptions to `ApiResult.Error` with decoded FastAPI `detail`.

### 4.5 Composables

```kotlin
@Composable fun GroupCreateRoute(
    onGroupCreated: (String) -> Unit,
    onBack: () -> Unit,
    vm: GroupCreateViewModel = hiltViewModel(),
)

@Composable fun GroupCreateScreen(
    state: GroupCreateUiState,
    onNameChange: (String) -> Unit,
    onQueryChange: (String) -> Unit,
    onToggleParticipant: (String) -> Unit,
    onRemoveParticipant: (String) -> Unit,
    onAvatarPicked: (Uri?) -> Unit,
    onCreateClick: () -> Unit,
    onBack: () -> Unit,
)
```

`GroupCreateRoute` collects `events` in a `LaunchedEffect` and calls `onGroupCreated(id)` on `Created`. Avatar uses `rememberLauncherForActivityResult(PickVisualMedia())`. The candidate list uses `LazyColumn`; selected chips use a horizontally-scrolling `FlowRow`/`LazyRow`. Loading/empty/error use the shared state composables from AND-021.

## 5. API Contract

**Primary endpoint (corrected & VERIFIED):** `POST /messaging/conversations/group` — OpenAPI op `start_group_conversation_messaging_conversations_group_post`, request `StartGroupConversationIn`, **success `200: ConversationOut`** (not `201`), error `422: HTTPValidationError`. The backlog/earlier-draft path `/conversations/group` was wrong.

**Request headers:** `Authorization: Bearer <token>` + session cookies (cookie jar) + `X-CSRF-Token: <ui_csrf>` (CSRF interceptor) + `Content-Type: application/json`. (OpenAPI lists `authorization` and `X-SESSION-ID` params; web client `src/api/client.ts` sends bearer + CSRF + `credentials: include`.)

**Request body — VERIFIED against `StartGroupConversationIn`.** Only `participant_ids` is required (`minItems: 2`). There is **no `name` field** (use `title`, optional) and **no `avatar_url`** (use `icon`, optional, maxLength 500). Other optional fields: `description` (maxLength 500), `topic` (maxLength 200), `retention_days` (1..3650).
```json
{
  "title": "Weekend Trip",
  "participant_ids": ["usr_01H...", "usr_02H..."],
  "icon": "media/abc.png"
}
```
`icon` omitted when no avatar chosen / upload unsupported. `title` may be omitted server-side but is product-required here.

**Success `200` response — VERIFIED against `ConversationOut`.** Key fields: `conversation_id` (string, **not `id`**), `type` (string, e.g. "group"), `title` (nullable, **not `name`**), `icon` (nullable, **not `avatar_url`**), `created_at` (**integer epoch, not an ISO-8601 string**), `created_by`, `participant_count`, `status`, `participants` (array of `ParticipantOut`), `unread_count` (default 0), `last_message` (nullable `MessageOut`), plus messaging/helpdesk/pin projection fields. Each `ParticipantOut` (schema `app__routers__messaging__ParticipantOut`, required `user_id`,`status`,`role`): `user_id`, `role` (string — observed values include `admin`/`member` in the web `Participant` type; no `owner` literal is guaranteed), `status`, `display_name?`, `profile_photo_url?`, `joined_at`, etc.
```json
{
  "conversation_id": "conv_01H...",
  "type": "group",
  "title": "Weekend Trip",
  "icon": "media/abc.png",
  "created_at": 1749132151,
  "created_by": "usr_self",
  "participant_count": 3,
  "status": "active",
  "participants": [
    { "user_id": "usr_self", "role": "admin", "status": "active" },
    { "user_id": "usr_01H...", "role": "member", "status": "active" }
  ],
  "unread_count": 0,
  "last_message": null
}
```

**Moshi DTO + Retrofit (extends `MessagingApi` from AND-120):**
```kotlin
@JsonClass(generateAdapter = true)
data class CreateGroupRequest(
    @Json(name = "title") val title: String,                 // group name -> backend `title`
    @Json(name = "participant_ids") val participantIds: List<String>,
    @Json(name = "icon") val icon: String? = null,           // avatar ref -> backend `icon`
    // optional, not used by this ticket: description, topic, retention_days
)

interface MessagingApi {
    @POST("messaging/conversations/group")
    suspend fun createGroup(@Body request: CreateGroupRequest): Response<ConversationDto>
    // ... existing AND-120 methods
}
```
Note: `ConversationDto` must read `conversation_id` (map to domain `id`) and treat `created_at` as a numeric epoch — AND-120's DTO already owns this; this ticket only reuses it.

**Participant search — RESOLVES OQ-4, VERIFIED.** A messaging-scoped endpoint exists: `GET /messaging/contacts/search?q=&limit=` (op `search_contact_messaging_contacts_search_get`; web `src/api/endpoints/messaging.ts: searchUsers`). It returns `UserSearchResult[]` where each item is `{ user_id: string, display_name: string }` (`src/api/types.ts: UserSearchResult`). Map to `List<ParticipantUi>` (handle/avatar are not returned by this endpoint, so the picker shows display name + id only). **Avatar/icon upload (optional):** the messaging media path uses a **presign** flow (`POST` returns `{ upload_url, bucket, key, content_type }`, then `PUT` the bytes to `upload_url`), per `src/api/endpoints/messaging.ts: uploadToPresignedUrl`; the resulting key/url is passed as `icon`. This is *not* a single "avatar_url" upload call.

**Error responses** — the documented schema for `422` is `HTTPValidationError`, whose body is `{ "detail": [ { "loc": [...], "msg": "...", "type": "..." } ] }` (FastAPI standard; verified shape — the decoder also handles `detail: string` and `detail: {code,...}` variants). Mapped by the shared decoder to `UiError`:
- `401` -> authenticator runs `POST /ui/session/refresh` once and retries (verified `src/api/client.ts: refreshSession`); second `401` -> `UiError.Unauthorized` (surface re-auth / `logout("session_expired")` analog).
- `403` -> CSRF/permission error; non-retryable hint. (Note: `403`/`404` are **not** declared as documented responses for this op — only `200`/`422` are in OpenAPI — so treat them as generic transport errors, not group-create-specific contracts. **Unverified** that this endpoint returns them.)
- `422` -> validation (too few/invalid participants, bad field); map first `detail[].msg` (and `loc`) to the relevant inline field. Backend does not validate `title` length, so a too-long-name `422` is **not** expected from the server — name length is a client-only guard.
- `404` -> if returned, a selected participant no longer exists; surface and let user deselect. (Unverified — see above.)
- `5xx` / timeout / `IOException` -> transient; snackbar with Retry, input preserved.

## 6. Data & State Management

- **Form state** lives in `GroupCreateViewModel` as `StateFlow<GroupCreateUiState>`; it is recreated per navigation to the route (no persistence required beyond the screen lifetime). Name/query are also mirrored to `SavedStateHandle` so rotation/process recreation does not lose typed input.
- **Selected participants** are held in-memory in state; dedupe by `userId`. Search results are transient and not cached to Room.
- **New conversation** returned by `createGroup` is **upserted into the Room conversation cache** (`ConversationEntity`/`ConversationDao` from AND-120) so the list screen (AND-121/122) shows the group immediately; the thread screen (AND-123) reads it by id on open.
- **Avatar** is held as a local `Uri` until submit; it is uploaded only on Create (avoid uploading then abandoning). The returned media ref is placed in the request.
- **No new tables** are introduced by this ticket; it writes to the existing conversation cache only.
- **Threading:** all network/DB writes on `Dispatchers.IO` via the repository; state collection on the main dispatcher; `stateIn`/`update` for atomic state transitions.

## 7. Error Handling & Resilience

- **Timeouts:** OkHttp call timeout ~20s (project dev-host policy). A create exceeding it resolves to `ApiResult.Error` -> snackbar with Retry; the form is re-enabled and input preserved.
- **No silent auto-retry of create:** `POST /conversations/group` is a non-idempotent write; do **not** auto-retry on timeout (risk of duplicate groups). Retry is user-initiated only. If a `client_id`/idempotency key is supported by the endpoint, include it so manual retry is safe (see §13 OQ-3); otherwise warn that a retried create may duplicate.
- **Refresh-on-401:** handled centrally by the OkHttp authenticator; the create coroutine sees only the post-refresh outcome. A double-401 surfaces re-auth.
- **Offline:** if connectivity is unavailable at submit, fail fast to "No connection — Retry"; do not enqueue an offline group-create (out of scope). Participant search returns empty + offline state.
- **Double-submit guard:** `isSubmitting` disables Create and form interaction while in flight; `canCreate` is false during submission.
- **Avatar upload failure:** if avatar upload fails, surface a recoverable error and let the user retry the upload or create the group without an avatar rather than blocking creation.
- **Partial validity:** server `422` is reconciled to the corresponding field/inline message so the user can correct and resubmit without losing other input.

## 8. Security & Privacy

- Auth/CSRF are transport concerns owned by core-network (cookie jar AND-011, `X-CSRF-Token` interceptor AND-012, refresh authenticator AND-013); this ticket adds no auth code and must not bypass them. The create `POST` must carry the CSRF header (verified by test).
- The group name and participant identifiers are user/relationship data: do not write them to logcat or telemetry payloads (see §10). Telemetry uses counts and hashed/opaque ids only.
- The dev backend is plaintext HTTP (known dev-only condition); release builds use HTTPS and the network-security-config forbids cleartext for production hosts (owned by build/network tickets; inherited here).
- Avatar image is read via the system photo picker (`PickVisualMedia`), which grants scoped, transient access without broad storage permissions (minSdk 24 compatible via the AndroidX wrapper). The picked `Uri` is uploaded over the authenticated session only.
- Request bodies are serialized by Moshi (no string interpolation) — no injection surface. Rendering uses Compose `Text` (no HTML) — no XSS surface.

## 9. Accessibility & i18n

- All Create/Back/avatar/chip-remove controls expose `contentDescription` (e.g., `cd_create_group`, `cd_pick_group_avatar`, `cd_remove_participant`); the disabled Create state is announced, not color-only.
- Selection state of each candidate row is exposed via `Modifier.semantics { selected = ... }` and a state description, so multi-select is perceivable by TalkBack without relying on the checkmark color.
- Name field has a labeled `OutlinedTextField`; the character counter and `nameError` are associated for screen-reader announcement. Search field is labeled "Search people".
- All strings in `strings.xml` (no hardcoded literals). Counters use locale-aware number formatting; layout uses start/end + `imePadding()`/`navigationBarsPadding()` and is RTL-safe. Touch targets >= 48dp for Create, chip remove, and candidate rows.

## 10. Telemetry & Logging

- Events (via the analytics facade from core-data; no names, no handles, no PII):
  - `group_create_open` { source } — entry into the screen.
  - `group_create_submit` { participantCount, hasAvatar } — on Create tap.
  - `group_create_success` { latencyMs, participantCount }.
  - `group_create_failed` { errorClass, httpStatus }.
  - `group_create_abandoned` { hadInput } — back/discard with input.
- Logging: `Timber.d`/`w` for create lifecycle with conversation id (post-success) only — **never** the group name, participant identifiers, or raw cookies. Network logging interceptor stays at `BASIC` for release (no bodies) per project policy.

## 11. Testing Strategy

- **Unit — ViewModel (core-testing, `MainDispatcherRule`, Turbine):**
  - `canCreate` is false until name is non-blank, within limit, and `selected.size in 2..max`; toggles correctly as state changes. (covers FR-3/FR-4/FR-7)
  - `onToggleParticipant` adds/removes and dedupes by `userId`; `onRemoveParticipant` removes a chip.
  - `onCreateClick` with valid state calls `repo.createGroup` with trimmed name + selected ids (+ avatar ref when present), and on `ApiResult.Success` emits `GroupCreateEvent.Created(id)`. (covers Acceptance "Group creates and opens")
  - On `ApiResult.Error`, `isSubmitting` returns to false, input is preserved, `error` is set; no navigation event.
  - Submitting twice rapidly does not fire two create calls (double-submit guard).
  - Debounced search updates `candidates` and preserves `selected` markers.
- **Repository tests:** MockWebServer returns `200`/`422`/`500`/timeout; assert correct `ApiResult`, the request path `/messaging/conversations/group`, the request JSON (`title`, `participant_ids`, optional `icon` — **not** `name`/`avatar_url`), presence of `Authorization` + `X-CSRF-Token` headers, and that a successful `ConversationOut` (with `conversation_id`) is upserted into the conversation cache.
- **DAO/cache test:** Room in-memory — created conversation is upserted and observable by the list source.
- **Compose UI tests:** name + 2 participants enables Create; tapping Create shows busy state; `422` shows inline name error; chips render and remove; content descriptions/selection semantics asserted; discard dialog appears on back-with-input.
- **Navigation test:** on `Created`, navigation pops the create route and lands on the thread route with the returned id (covers "opens").
- All async tests deterministic (`runTest`, injected `TestDispatcher`); MockWebServer for network; **no live dev-host calls in CI**.

## 12. Dependencies & Sequencing

- **Depends on AND-120** (Messaging API + DTOs): provides `MessagingApi`, `ConversationDto`/`Conversation`, the conversation Room cache, the `apiCall { }` helper, and the FastAPI `detail` decoder. AND-157 extends `MessagingApi` with `createGroup` and upserts into the existing cache. Must merge after AND-120.
- **Integrates with (not hard-blocked by):** AND-121/AND-122 (conversation list, where the new group appears and from which the screen is launched) and AND-123 (thread screen, navigated to on success). If those land after this ticket, gate the entry point and `onGroupCreated` target behind their availability; the create call and DTOs are independently testable via MockWebServer.
- **Reuses:** AND-074 profile media upload (for the optional avatar) and the messaging/profile participant-search surface; the core-network auth/CSRF/cookie-jar/refresh tickets (AND-011/012/013) and state composables (AND-021), navigation host (AND-022/024).
- **Blocks:** none recorded in the source bullets. Group management features (rename, add/remove members, leave) would build on this but are not listed as dependents here.

## 13. Risks & Open Questions

- **OQ-1 (RESOLVED):** Request schema for `POST /messaging/conversations/group` is `StartGroupConversationIn` — fields `participant_ids` (required, `minItems: 2`), `title?`, `description?`, `icon?`, `topic?`, `retention_days?`. Field is `participant_ids` (not `member_ids`/`participants`). The current user is **implicit** (the web `StartGroupConversationReq` passes only the *other* members, and the response includes the creator as `created_by`/a participant). `title` is optional server-side. `CreateGroupRequest` aligned accordingly. (Verified: `/openapi.json` `StartGroupConversationIn`; `src/api/endpoints/messaging.ts: startGroupConversation`; `src/api/types.ts: StartGroupConversationReq`.)
- **OQ-2 (RESOLVED):** Avatar is accepted **at creation time** via the optional `icon` string field on `StartGroupConversationIn` — no follow-up `PATCH` is required just to set an avatar (though `PATCH /messaging/conversations/{id}` with `UpdateConversationIn` exists for later edits). The image bytes must first be uploaded via the messaging **presign** flow (`{upload_url,bucket,key,content_type}` then `PUT`), and the resulting key/url placed in `icon`. So FR-6 stands, but the field is `icon` and the upload is presign-based, not a single avatar-URL call. No feature flag strictly required for the contract; flag only if the presign upload UI slips.
- **OQ-3 (RESOLVED — no idempotency):** `StartGroupConversationIn` has **no** `client_id`/idempotency field (verified full schema). Therefore document the duplicate-create risk and keep retry **strictly user-initiated** with no auto-retry on timeout (§7).
- **OQ-4 (RESOLVED):** A messaging-scoped search endpoint exists: `GET /messaging/contacts/search?q=&limit=` returning `UserSearchResult[]` = `{user_id, display_name}` (verified: OpenAPI op `search_contact_...`; `src/api/endpoints/messaging.ts: searchUsers`). Use it for the picker; no manual `u/`-entry fallback is needed. Caveat: this endpoint returns only id + display name (no handle/avatar), so picker rows are name+id.
- **OQ-5 (RESOLVED):** Success status is **`200`** (not `201`) per OpenAPI (`resp=200:ConversationOut`). Min participants = **2** (`minItems: 2`). **Max is unverified** — no `maxItems` in the schema; keep a client guard and rely on `422`. Still handle success via `Response.isSuccessful` for robustness.
- **Risk:** unreliable dev host yields frequent timeouts during manual QA, raising duplicate-create risk without OQ-3 idempotency. Mitigation: no auto-retry; clear single-Create busy state; MockWebServer for deterministic tests.

## 14. Acceptance Criteria

AC-1. From the conversation list, the user can open a Group Create screen with a name field, optional avatar picker, and a multi-select participant picker. *(source scope: "name/avatar/participants")*

AC-2. Create is enabled only with a non-empty name (<= 80 chars) and **at least 2** selected participants; otherwise it is disabled with the relevant inline indication. *(FR-3/FR-4/FR-7)*

AC-3. Tapping Create issues `POST /messaging/conversations/group` with the trimmed name as `title`, selected `participant_ids`, and (when chosen) an avatar reference as `icon`, carrying the `Authorization` bearer token, session cookies, and the `X-CSRF-Token` header. *(source scope corrected: `POST /messaging/conversations/group`)*

AC-4. On a successful `200` response the group is created and the app **navigates into the new thread** using the returned `conversation_id`, with the create form removed from the back stack; the new group also appears in the conversation list cache. *(source acceptance: "Group creates and opens")* — verified by ViewModel + navigation tests.

AC-5. On failure (validation/transient/network) the screen stays on the form with name, avatar, and selected participants preserved, surfaces a mapped error (inline for `422`, snackbar for transient), and re-enables Create; no duplicate create is issued automatically.

AC-6. Back/cancel with unsaved input prompts a discard confirmation; participants can be added/removed via the list and chips with dedupe by user id.

AC-7. Automated tests cover the create call + request JSON, success-navigation, failure-preservation, the enable/min-participant guards, dedupe, and cache upsert. *(source acceptance implies testable "creates and opens")*

## 15. Definition of Done

- `GroupCreateScreen`/`GroupCreateRoute`, `GroupCreateUiState`, `GroupCreateViewModel` (`onNameChange`/`onQueryChange`/`onToggleParticipant`/`onRemoveParticipant`/`onAvatarPicked`/`onCreateClick`), and `GroupCreateRepository.createGroup` implemented in `:feature:messaging` under `com.testlogon.android.feature.messaging.groupcreate`, with `MessagingApi.createGroup` + `CreateGroupRequest` in `:core:network`/`:core:model`.
- The `groupCreate` route is registered in the authenticated messaging nav graph; success navigates to the thread and pops the form; the new conversation is upserted into the AND-120 conversation cache.
- Group creation + open functional against MockWebServer and manually verified against the dev host; OQ-1 (request schema), OQ-3 (no idempotency key), OQ-4 (contacts search) and OQ-5 (200/min-2) are resolved per §13/§16 and reflected in code (`title`/`icon`/`participant_ids`, path `/messaging/conversations/group`); avatar handled via the `icon` field + presign upload per OQ-2.
- All §11 unit, repository, DAO, Compose UI, and navigation tests pass in CI; no live-host calls in CI.
- No group name or participant identifiers in logs or telemetry; `X-CSRF-Token` and cookie-jar paths verified; Detekt/ktlint clean; KSP builds.
- Strings externalized; accessibility content descriptions and selection/state semantics present; touch targets >= 48dp; RTL-safe with IME/nav insets.
- All ACs in §14 demonstrably met. PR targets the `android-port` branch and references AND-157 and AND-120.

## 16. Citations & Assumption Audit

Each key technical claim with its verdict and source pointer.

1. **Endpoint path is `POST /messaging/conversations/group`** (draft said `/conversations/group`). VERDICT: **Corrected**. SOURCE: OpenAPI `POST /messaging/conversations/group` (op `start_group_conversation_messaging_conversations_group_post`); `src/api/endpoints/messaging.ts: startGroupConversation`.
2. **Request schema = `StartGroupConversationIn`; only `participant_ids` required (`minItems: 2`).** VERDICT: **Verified**. SOURCE: OpenAPI `components.schemas.StartGroupConversationIn`.
3. **Group name maps to `title` (optional, no server maxLength), NOT a `name` field.** VERDICT: **Corrected**. SOURCE: `StartGroupConversationIn` (`title` under `anyOf string|null`, no `maxLength`); `src/api/types.ts: StartGroupConversationReq`.
4. **Avatar maps to `icon` (string, maxLength 500), NOT `avatar_url`.** VERDICT: **Corrected**. SOURCE: `StartGroupConversationIn.icon`; `src/api/types.ts: StartGroupConversationReq.icon`.
5. **Request field is `participant_ids` (not `member_ids`/`participants`); current user implicit.** VERDICT: **Verified**. SOURCE: `StartGroupConversationIn.participant_ids`; web sends only other members (`StartGroupConversationReq`).
6. **Success status is `200` with `ConversationOut` (not `201`).** VERDICT: **Corrected**. SOURCE: OpenAPI index `resp=200:ConversationOut;422:HTTPValidationError`.
7. **Response id field is `conversation_id` (not `id`).** VERDICT: **Corrected**. SOURCE: `components.schemas.ConversationOut` (required `conversation_id`); `src/api/types.ts: Conversation.conversation_id`.
8. **Response has `title`/`icon` (not `name`/`avatar_url`); `created_at` is integer epoch (not ISO string).** VERDICT: **Corrected**. SOURCE: `ConversationOut` (`created_at` type integer; `title`/`icon` nullable strings); `src/api/types.ts: Conversation`.
9. **Participants use `ParticipantOut` with required `user_id`,`status`,`role`; role values admin/member (no guaranteed `owner`).** VERDICT: **Corrected** (draft showed `role: "owner"`). SOURCE: `components.schemas.app__routers__messaging__ParticipantOut`; `src/api/types.ts: Participant` (`role?: "admin"|"member"`).
10. **Auth = `Authorization: Bearer` + `X-CSRF-Token` (from `ui_csrf` cookie) + session cookies (`credentials: include`); also `X-SESSION-ID` header per OpenAPI params.** VERDICT: **Corrected** (draft said cookie-only). SOURCE: `src/api/client.ts` (lines ~157-184: sets `Authorization`, `X-CSRF-Token`, `credentials: include`); OpenAPI params `authorization,X-SESSION-ID`.
11. **On `401`, refresh once via `POST /ui/session/refresh` then retry.** VERDICT: **Verified**. SOURCE: `src/api/client.ts: refreshSession` (`/ui/session/refresh`, POST, `credentials: include`) and the 401-handling block.
12. **Participant search = `GET /messaging/contacts/search?q=&limit=` returning `UserSearchResult[]` = `{user_id, display_name}`.** VERDICT: **Verified** (resolves OQ-4). SOURCE: OpenAPI `GET /messaging/contacts/search` (params `q,limit,authorization,X-SESSION-ID`); `src/api/endpoints/messaging.ts: searchUsers`; `src/api/types.ts: UserSearchResult`.
13. **No idempotency/`client_id` field on group create.** VERDICT: **Verified** (resolves OQ-3 negatively). SOURCE: full `StartGroupConversationIn` schema (no such property).
14. **Avatar/media upload uses a presign flow (`{upload_url,bucket,key,content_type}` then PUT), not a one-shot avatar-URL endpoint.** VERDICT: **Verified**. SOURCE: `src/api/endpoints/messaging.ts: uploadToPresignedUrl` and presign `api.post<{upload_url,bucket,key,content_type}>`.
15. **`422` body shape = `HTTPValidationError` (`detail: [{loc,msg,type}]`).** VERDICT: **Verified**. SOURCE: OpenAPI `resp=...422:HTTPValidationError`; standard FastAPI `HTTPValidationError`/`ValidationError` schema.
16. **Min participants = 2.** VERDICT: **Verified**. SOURCE: `StartGroupConversationIn.participant_ids.minItems = 2`.
17. **Client 80-char name cap.** VERDICT: **Unverified-assumption** (client-only; backend `title` is uncapped). SOURCE: `StartGroupConversationIn` (no `maxLength` on `title`).
18. **Max participants = 256.** VERDICT: **Unverified-assumption** (no `maxItems` in schema). SOURCE: `StartGroupConversationIn` (no upper bound).
19. **`403`/`404` group-create-specific behaviors.** VERDICT: **Unverified-assumption** (only `200`/`422` are documented for this op). SOURCE: OpenAPI index line for the op (`resp=200:ConversationOut;422:HTTPValidationError`).
20. **Compose/Material 3 / Navigation-Compose / `PickVisualMedia` (`ActivityResultContracts.PickVisualMedia`) choices.** VERDICT: **Framework ref** (design choices, not backend contract). SOURCE: framework ref — Android docs `developer.android.com/training/data-storage/shared/photopicker`; AndroidX Activity Result APIs.

### Corrections made
- Path `/conversations/group` -> `/messaging/conversations/group` (§1, §5, §14 AC-3).
- Request field `name` -> `title`; `avatar_url` -> `icon` (§3, §5, §14, §4.4, §11).
- Success status `201` -> `200` (§5, §13 OQ-5, §14 AC-4).
- Response `id` -> `conversation_id`; `created_at` clarified as integer epoch; `name`/`avatar_url` -> `title`/`icon`; participant `role: "owner"` softened to admin/member (no owner literal) (§5).
- Auth corrected from "cookie-only" to bearer + CSRF + cookies (+`X-SESSION-ID`) (§2, §5, §14 AC-3).
- Web reference file corrected from `conversations.ts` to `messaging.ts` (§2).
- OQ-1/2/3/4/5 marked RESOLVED with verified sources (§13); DoD updated (§15).
- FR-3 name length reframed as client-only guard; FR-4 min-2 marked verified, max-256 marked unverified.

### Open assumptions
- **Name max length (80 chars):** client-only UX guard; backend does not enforce a `title` length, so this cannot be verified against the contract.
- **Max participants (256):** no `maxItems` in the schema; the true server cap (if any) is unknown — relies on `422` at runtime.
- **`403`/`404` handling:** not documented responses for this op; whether the endpoint emits them (e.g., for a deleted participant or CSRF failure) is unverified — handled generically.
- **`X-SESSION-ID` exact value/source:** OpenAPI lists it as a param but the web client uses a Bearer token + cookies; the precise Android mapping (session id header vs bearer) is owned by core-network (AND-011/012/013) and not re-derived here.
- **`status` literal values** on `ConversationOut`/`ParticipantOut` (e.g., "active"): the schema types them as free `string`, so exact enum values are assumed, not enumerated.

## 17. Test Plan

Acceptance criteria referenced are from §14 (AC-1..AC-7). "Physical device" = Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a); "emulator" = AVD `test35` (API 35, x86_64); "JVM" = local Robolectric/unit. This ticket has no camera/biometric/push/WebRTC/Telecom behavior, so most UI cases run fine on the emulator; the photo-picker case is called out for the physical device because system photo-picker behavior is OEM-skinned on Samsung (One UI).

| ID | Type | Target | Preconditions | Steps | Expected result | Traces |
|----|------|--------|---------------|-------|-----------------|--------|
| TC-AND-157-01 | unit (JVM) | `GroupCreateViewModel` | Repo faked; `MainDispatcherRule` + Turbine | Set valid `title`, toggle 2 participants | `canCreate` flips false->true only when name non-blank, within client cap, and `selected.size in 2..max` | AC-2 |
| TC-AND-157-02 | unit (JVM) | `GroupCreateViewModel` | Faked repo | Toggle same `userId` twice; add 3 distinct; remove 1 via chip | Dedupe by `userId`; chip removal updates `selected`; count correct | AC-2, AC-6 |
| TC-AND-157-03 | unit (JVM) | `GroupCreateViewModel` | Faked repo returns `ApiResult.Success(Conversation(id=conv_1))` | Valid state, call `onCreateClick()` | Repo `createGroup` called once with trimmed `title`, selected `participant_ids`, `icon` when present; emits `GroupCreateEvent.Created("conv_1")` | AC-3, AC-4 |
| TC-AND-157-04 | unit (JVM) | `GroupCreateViewModel` | Faked repo returns `ApiResult.Error` | Valid state, `onCreateClick()` | `isSubmitting` returns to false; name/avatar/selected preserved; `error` set; **no** `Created` event | AC-5 |
| TC-AND-157-05 | unit (JVM) | `GroupCreateViewModel` | Faked repo with delayed success | Call `onCreateClick()` twice rapidly within the in-flight window | Only one `createGroup` invocation (double-submit guard via `isSubmitting`) | AC-5 |
| TC-AND-157-06 | contract/MockWebServer | `GroupCreateRepository` + `MessagingApi.createGroup` | MockWebServer enqueues `200` `ConversationOut` JSON (with `conversation_id`, integer `created_at`) | Call `createGroup(title, ids, icon)` | Recorded request: `POST /messaging/conversations/group`; body has `title`,`participant_ids`,`icon` (no `name`/`avatar_url`); headers include `Authorization` and `X-CSRF-Token`; returns `ApiResult.Success` mapped to domain with `id == conversation_id` | AC-3, AC-4 |
| TC-AND-157-07 | contract/MockWebServer | repository | MockWebServer enqueues `422` `HTTPValidationError` (`detail:[{loc:["body","participant_ids"],msg:"too few"}]`) | Submit with bad participants | Returns `ApiResult.Error` mapped to inline participant error using first `detail[].msg`; input preserved | AC-5 |
| TC-AND-157-08 | contract/MockWebServer | repository + authenticator | First enqueue `401`; enqueue `200` for `POST /ui/session/refresh`; then `200` `ConversationOut` | Submit once | Authenticator refreshes once via `/ui/session/refresh` and retries; final result Success; exactly one refresh | AC-3 |
| TC-AND-157-09 | contract/MockWebServer | repository | MockWebServer set to no-response then socket timeout; offline simulated by failing dispatcher (`IOException`) | Submit on timeout, then submit with no connectivity | Each yields `ApiResult.Error` (transient/no-connection); **no auto-retry** (single request recorded per user action); input preserved | AC-5 |
| TC-AND-157-10 | contract/MockWebServer | repository (`searchParticipants`) | MockWebServer enqueues `UserSearchResult[]` for `GET /messaging/contacts/search?q=al` | Call `searchParticipants("al")` | Request path/query correct; maps `{user_id,display_name}` -> `ParticipantUi`; selected markers preserved on merge | AC-1, AC-6 |
| TC-AND-157-11 | integration (Room, Robolectric/JVM) | `ConversationDao` upsert | In-memory Room from AND-120 | After a successful `createGroup`, observe the conversation cache | New group conversation is upserted and observable by the list source without forced refresh | AC-4, AC-7 |
| TC-AND-157-12 | Compose-UI (instrumented) | `GroupCreateScreen` | emulator `test35` | Type name, select 2 participants, tap Create; then drive a `422` state | Create disabled until valid; busy state on submit; `422` shows inline error; chips render/remove; discard `AlertDialog` shown on back-with-input | AC-1, AC-2, AC-5, AC-6 |
| TC-AND-157-13 | Compose-UI (instrumented, a11y) | `GroupCreateScreen` | emulator `test35`, TalkBack assertions via semantics | Inspect semantics of Create/Back/avatar/chip-remove and candidate rows | `contentDescription`s present (`cd_create_group`, `cd_pick_group_avatar`, `cd_remove_participant`); candidate `selected` semantics + state description exposed; disabled Create announced; touch targets >= 48dp | AC-1, AC-2, AC-6 |
| TC-AND-157-14 | instrumented/e2e (navigation + security) | nav host + OkHttp against MockWebServer | emulator `test35`; CSRF interceptor + cookie jar wired | Complete a create flow end-to-end | On `Created`, back stack pops the create route and lands on thread route with returned `conversation_id`; outbound request carries `X-CSRF-Token` + cookies; name/participant ids absent from logcat (security) | AC-3, AC-4, AC-7 |
| TC-AND-157-15 | manual (physical device) | photo picker + create flow | **Physical Galaxy A15 (API 34)** — required: Samsung One UI photo picker differs from emulator; also validates arm64/API-34 path | Pick a group avatar via system photo picker, presign-upload, create group | Scoped `PickVisualMedia` grants transient access without storage permission; `icon` ref uploaded and sent; group creates and opens on real device/network | AC-1, AC-3, AC-4 |

### Coverage matrix

| AC (§14) | Covered by |
|----------|-----------|
| AC-1 (screen with name/avatar/participant picker) | TC-10, TC-12, TC-13, TC-15 |
| AC-2 (enable rules: non-empty name + >=2) | TC-01, TC-02, TC-12, TC-13 |
| AC-3 (`POST /messaging/conversations/group` with `title`/`participant_ids`/`icon`, bearer+CSRF) | TC-03, TC-06, TC-08, TC-14, TC-15 |
| AC-4 (success creates + opens thread via `conversation_id`, pops form, cache reflects) | TC-03, TC-06, TC-11, TC-14, TC-15 |
| AC-5 (failure preserves input, mapped error, no auto-retry/double-submit) | TC-04, TC-05, TC-07, TC-09, TC-12 |
| AC-6 (discard dialog; add/remove + dedupe) | TC-02, TC-10, TC-12, TC-13 |
| AC-7 (automated coverage of call/json/nav/preservation/guards/dedupe/cache) | TC-06, TC-11, TC-14 |
