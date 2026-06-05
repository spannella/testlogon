---
id: AND-157
title: Group create
milestone: M3
epic: E22
priority: P1
size: M
status: draft
depends_on: [AND-120]
blocks: []
---

# AND-157 — Group create

## 1. Overview & Goal

Add a "create group conversation" flow to the messaging area: a screen where the user names a new group, optionally picks an avatar, selects two or more participants, and submits to `POST /conversations/group`. On a successful response the new group conversation is created server-side and the app **navigates directly into the new thread** (the conversation list also reflects the new group). The defining, testable outcome from the backlog is verbatim: **"Group creates and opens."** — i.e., a valid submission both (a) creates the group on the backend and (b) opens the resulting thread.

This ticket owns the *write path* for group creation only: the create-group screen, its `GroupCreateViewModel`, the `createGroup` repository/API method, and the request/response DTOs for the group-create endpoint. It consumes — and does not re-implement — the messaging foundation from AND-120 (`MessagingApi`, conversation/message DTOs, base error mapping), the conversation list (AND-121/AND-122) into which the new group appears, and the thread screen (AND-123) that is opened on success. Participant discovery (the people-picker data source) reuses the messaging/profile search surface where available; if no search endpoint exists yet, the picker degrades to manual `u/`-identifier entry (see §13 OQ-1).

## 2. Context & References

- **Module:** `feature-messaging` (Gradle module `:feature:messaging`), package `com.testlogon.android.feature.messaging.groupcreate`. The screen is a new route inside the existing messaging feature module, not a new module.
- **Layering:** `feature-messaging` -> `core-network` (Retrofit service, `ApiResult<T>`, error decoder), `core-model` (DTO/domain), `core-data` (repository + Room cache), `core-ui` (Compose components, theme, state composables), `core-testing`. No backward dependencies; ViewModel exposes `StateFlow<GroupCreateUiState>`.
- **Backend:** FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000` (plaintext HTTP, unreliable). OpenAPI at `/openapi.json`. Cookie-based auth: session cookies + `ui_csrf` cookie echoed as `X-CSRF-Token`; on `401` the OkHttp authenticator calls `POST /ui/session/refresh` once and retries. Persistent cookie jar required (established by the core-network/auth tickets, AND-011/AND-012/AND-013).
- **Web reference:** `frontend/src/api/endpoints/conversations.ts` (the group-create call) and `frontend/src/api/types.ts` (`Conversation`, group-create request type). The Android DTOs here must mirror those shapes. Confirm the exact field names against `/openapi.json` before coding (see §13).
- **Dependency AND-120** (Messaging API + DTOs) supplies: `MessagingApi` Retrofit interface, `ConversationDto`/domain `Conversation`, the shared `apiCall { }` helper and FastAPI `detail` decoder, and the Room conversation cache. AND-157 *extends* `MessagingApi` with the group-create method and adds the screen/ViewModel.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, single-Activity Navigation-Compose, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15, Room 2.6, DataStore, Coil (avatar). minSdk 24 / compile+target 35, JDK 17, Gradle 8.9, AGP 8.7.3.
- **Avatar upload** reuses the media-upload path established for profiles (AND-074) if the group endpoint accepts a pre-uploaded media reference; otherwise avatar is optional and deferred (see §13 OQ-2).

## 3. Functional Requirements

FR-1. A "New group" entry point is available from the conversation list (AND-121) top app bar / FAB. Tapping it navigates to the `groupCreate` route via Navigation-Compose.

FR-2. The Group Create screen presents: (a) an editable **group name** field; (b) an optional **avatar** picker (tap to choose from gallery via the system photo picker / `PickVisualMedia`); (c) a **participant selector** (search + multi-select list of selectable people, with a chips row of chosen participants); (d) a **Create** action in the top app bar (or primary button).

FR-3. Group name is required and trimmed: empty/whitespace-only name disables Create. Max length 80 characters (client guard mirroring backend; over-limit blocked with an inline counter, not silently truncated). Name is the only mandatory text field.

FR-4. Participant selection requires **at least 2** other participants (a group, distinct from a 1:1 DM). The current user is implicitly a member and is **not** counted toward, nor selectable in, that minimum. An upper bound (default 256, confirm vs backend) is enforced client-side with an inline message.

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

`createGroup` builds `CreateGroupRequest`, calls `MessagingApi.createGroup`, maps `ConversationDto.toDomain()`, and on success **upserts** the new conversation into the Room conversation cache (AND-120) so the conversation list (AND-121/122) reflects it without a forced refresh. All work via the shared `apiCall { }` helper that converts non-2xx/exceptions to `ApiResult.Error` with decoded FastAPI `detail`.

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

**Primary endpoint:** `POST /conversations/group`

**Request headers:** session cookies (auto via cookie jar) + `X-CSRF-Token: <ui_csrf>` (auto via CSRF interceptor) + `Content-Type: application/json`.

**Request body** (field names to be confirmed vs `/openapi.json` / `frontend` — see §13 OQ-1):
```json
{
  "name": "Weekend Trip",
  "participant_ids": ["usr_01H...", "usr_02H..."],
  "avatar_url": "https://.../media/abc.png"
}
```
`avatar_url` omitted when no avatar chosen / upload unsupported.

**Success `201` (or `200`) response** — a full `Conversation` object (same shape AND-120 already maps):
```json
{
  "id": "conv_01H...",
  "type": "group",
  "name": "Weekend Trip",
  "avatar_url": "https://.../media/abc.png",
  "participants": [
    { "user_id": "usr_self", "role": "owner" },
    { "user_id": "usr_01H...", "role": "member" },
    { "user_id": "usr_02H...", "role": "member" }
  ],
  "last_message": null,
  "unread_count": 0,
  "created_at": "2026-06-05T14:22:31.004Z"
}
```

**Moshi DTO + Retrofit (extends `MessagingApi` from AND-120):**
```kotlin
@JsonClass(generateAdapter = true)
data class CreateGroupRequest(
    @Json(name = "name") val name: String,
    @Json(name = "participant_ids") val participantIds: List<String>,
    @Json(name = "avatar_url") val avatarUrl: String? = null,
)

interface MessagingApi {
    @POST("conversations/group")
    suspend fun createGroup(@Body request: CreateGroupRequest): Response<ConversationDto>
    // ... existing AND-120 methods
}
```

**Participant search** (reuses an existing endpoint; confirm path — candidate `GET /messaging/users/search?q=` or profile search): mapped to `List<ParticipantUi>`. **Avatar upload** (optional): reuse profile media upload (AND-074), returning a media URL/ref.

**Error responses** — FastAPI `detail` mapped by the shared decoder (`detail: string | [{msg,loc}] | {code,...}`) to `UiError`:
- `401` -> authenticator runs `POST /ui/session/refresh` once and retries; second `401` -> `UiError.Unauthorized` (surface re-auth).
- `403` -> CSRF/permission error; non-retryable hint.
- `422` -> validation (name too long, too few/invalid participants); map first `msg` to the relevant inline field.
- `404` -> a selected participant no longer exists; surface and let user deselect.
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
- **Repository tests:** MockWebServer returns `201`/`422`/`500`/timeout; assert correct `ApiResult`, the request JSON (`name`, `participant_ids`, optional `avatar_url`), presence of `X-CSRF-Token`, and that a successful response is upserted into the conversation cache.
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

- **OQ-1 (must resolve before merge):** Exact request schema for `POST /conversations/group` — field names (`participant_ids` vs `member_ids` vs `participants`), whether the current user is implicit or must be included, and whether `name` is required. Verify against `/openapi.json` and `frontend/src/api/endpoints/conversations.ts`; align `CreateGroupRequest` accordingly.
- **OQ-2:** Does the group-create endpoint accept an avatar (URL/media ref) at creation time, or must avatar be set in a follow-up `PATCH`? If the latter, ship avatar behind a feature flag and create without it; add a follow-up ticket for group-avatar set. (Affects FR-6.)
- **OQ-3:** Idempotency — does the endpoint accept a `client_id`/idempotency key? If yes, include it so a manual retry after an uncertain timeout cannot create a duplicate group. If no, document the duplicate risk and keep retry strictly user-initiated.
- **OQ-4:** Participant discovery — is there a messaging-scoped user-search endpoint, or must we use profile search / manual `u/`-identifier entry? Determines the picker UX (search vs manual entry fallback).
- **OQ-5:** Min/max participant bounds and success status code (`200` vs `201`). Handle both via `Response.isSuccessful`; confirm bounds for the client guards in FR-4.
- **Risk:** unreliable dev host yields frequent timeouts during manual QA, raising duplicate-create risk without OQ-3 idempotency. Mitigation: no auto-retry; clear single-Create busy state; MockWebServer for deterministic tests.

## 14. Acceptance Criteria

AC-1. From the conversation list, the user can open a Group Create screen with a name field, optional avatar picker, and a multi-select participant picker. *(source scope: "name/avatar/participants")*

AC-2. Create is enabled only with a non-empty name (<= 80 chars) and **at least 2** selected participants; otherwise it is disabled with the relevant inline indication. *(FR-3/FR-4/FR-7)*

AC-3. Tapping Create issues `POST /conversations/group` with the trimmed name, selected `participant_ids`, and (when chosen and supported) an avatar reference, carrying session cookies and the `X-CSRF-Token` header. *(source scope: `POST /conversations/group`)*

AC-4. On a successful response the group is created and the app **navigates into the new thread** using the returned conversation `id`, with the create form removed from the back stack; the new group also appears in the conversation list cache. *(source acceptance: "Group creates and opens")* — verified by ViewModel + navigation tests.

AC-5. On failure (validation/transient/network) the screen stays on the form with name, avatar, and selected participants preserved, surfaces a mapped error (inline for `422`, snackbar for transient), and re-enables Create; no duplicate create is issued automatically.

AC-6. Back/cancel with unsaved input prompts a discard confirmation; participants can be added/removed via the list and chips with dedupe by user id.

AC-7. Automated tests cover the create call + request JSON, success-navigation, failure-preservation, the enable/min-participant guards, dedupe, and cache upsert. *(source acceptance implies testable "creates and opens")*

## 15. Definition of Done

- `GroupCreateScreen`/`GroupCreateRoute`, `GroupCreateUiState`, `GroupCreateViewModel` (`onNameChange`/`onQueryChange`/`onToggleParticipant`/`onRemoveParticipant`/`onAvatarPicked`/`onCreateClick`), and `GroupCreateRepository.createGroup` implemented in `:feature:messaging` under `com.testlogon.android.feature.messaging.groupcreate`, with `MessagingApi.createGroup` + `CreateGroupRequest` in `:core:network`/`:core:model`.
- The `groupCreate` route is registered in the authenticated messaging nav graph; success navigates to the thread and pops the form; the new conversation is upserted into the AND-120 conversation cache.
- Group creation + open functional against MockWebServer and manually verified against the dev host; OQ-1 (request schema) and OQ-3 (idempotency) confirmed and reflected in code before merge; avatar handled per OQ-2.
- All §11 unit, repository, DAO, Compose UI, and navigation tests pass in CI; no live-host calls in CI.
- No group name or participant identifiers in logs or telemetry; `X-CSRF-Token` and cookie-jar paths verified; Detekt/ktlint clean; KSP builds.
- Strings externalized; accessibility content descriptions and selection/state semantics present; touch targets >= 48dp; RTL-safe with IME/nav insets.
- All ACs in §14 demonstrably met. PR targets the `android-port` branch and references AND-157 and AND-120.
