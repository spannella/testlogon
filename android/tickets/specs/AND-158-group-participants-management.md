---
id: AND-158
title: Group participants management
milestone: M3
epic: E22
priority: P1
size: M
status: draft
depends_on: [AND-157]
blocks: []
---

# AND-158 — Group participants management

## 1. Overview & Goal

This ticket delivers participant lifecycle management for existing group conversations in the
TestLogon native Android app (`com.testlogon.android`): adding members, removing members, and
changing a member's role (e.g. `member` ↔ `admin`). It builds directly on AND-157 (Group create),
which produces the group conversation and provides the navigation entry point into the group detail
screen.

The goal is a robust, offline-aware participants surface where an authorized member (admin/owner)
can mutate the membership roster and have those changes **persist** to the FastAPI backend and
**reflect** immediately in the local Room cache and Compose UI. The defining acceptance criterion is:
*membership changes persist and reflect* — i.e. an add/remove/role-change survives process death and a
cold cache reload, and the roster UI updates optimistically with reconciliation on server confirmation.

Out of scope: group creation (AND-157), leaving a group as the current user (separate self-leave flow,
deferred to AND-159 unless that ticket reassigns it), group metadata edits (name/avatar — owned by the
group-settings ticket), and the message thread itself.

## 2. Context & References

- **Module:** `feature-conversations` (group sub-package), consuming `core-network`, `core-model`,
  `core-data`, `core-ui`, `core-testing`. ViewModels expose `StateFlow<UiState>`; repository returns
  typed `ApiResult<T>`.
- **Upstream dependency:** AND-157 establishes `GroupConversation`/`Participant` models, the
  `ConversationDao` group rows, and `GroupDetailScreen` scaffolding. This ticket extends those.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext HTTP, unreliable).
  OpenAPI at `/openapi.json`. Cookie + `X-CSRF-Token` auth (see §8). All mutating calls here are
  **non-idempotent or state-changing** and therefore are **not** auto-retried (§7).
- **Web reference:** `frontend/src/api/endpoints/conversations.ts` (participant PATCH/DELETE helpers)
  and shared types in `frontend/src/api/types.ts` (`Participant`, `ParticipantRole`). Mirror those
  payload shapes exactly; verify against `/openapi.json` at implementation time.
- **Auth/session:** cookie-based session with one-shot `POST /ui/session/refresh` on 401 then retry,
  handled by the shared OkHttp `Authenticator`/interceptor from core-network (no changes here).

## 3. Functional Requirements

FR-1. **Roster display.** The group detail screen renders the current participant list (avatar, display
name, role badge, online/last-seen if available) sourced from the Room cache, kept live via a
`Flow` query, and refreshed from the network on screen entry and pull-to-refresh.

FR-2. **Add participants.** An authorized user opens an "Add people" picker, selects one or more
contacts not already in the group, and confirms. The app issues a participant-add request and the new
members appear in the roster.

FR-3. **Remove participant.** An authorized user removes a member via a row overflow/swipe action with a
confirmation dialog. The removed member disappears from the roster.

FR-4. **Change role.** An authorized user changes a member's role (promote to admin / demote to member)
via a row action; the role badge updates.

FR-5. **Authorization gating.** Add/remove/role controls are visible/enabled only when the current
user's role permits the action (server is the source of truth; UI gates optimistically based on
`current_user_role`). Non-authorized members see a read-only roster. A 403 from the server reverts any
optimistic change and surfaces a non-destructive error.

FR-6. **Optimistic UI + reconciliation.** Each mutation applies optimistically to the cache/UI, then
reconciles against the server response. On failure the optimistic change is rolled back and an error
state is shown with retry.

FR-7. **Persistence.** All successful mutations write through to Room so the roster is correct after
process death / cold start without a network round trip (then refreshed when online).

FR-8. **Self-protection.** The current user cannot remove or demote themselves through these controls
(self-leave is a separate flow); the last remaining admin cannot be demoted (guarded client-side and
enforced server-side).

## 4. Technical Design

### 4.1 Models (core-model)

```kotlin
enum class ParticipantRole { OWNER, ADMIN, MEMBER }

data class Participant(
    val userId: String,
    val displayName: String,
    val avatarUrl: String?,
    val role: ParticipantRole,
    val joinedAt: Instant,
)

data class GroupRoster(
    val conversationId: String,
    val participants: List<Participant>,
    val currentUserRole: ParticipantRole,
)
```

### 4.2 Repository (core-data)

```kotlin
interface GroupParticipantsRepository {
    fun observeRoster(conversationId: String): Flow<GroupRoster?>
    suspend fun refreshRoster(conversationId: String): ApiResult<GroupRoster>
    suspend fun addParticipants(conversationId: String, userIds: List<String>): ApiResult<List<Participant>>
    suspend fun removeParticipant(conversationId: String, userId: String): ApiResult<Unit>
    suspend fun changeRole(conversationId: String, userId: String, role: ParticipantRole): ApiResult<Participant>
}
```

`GroupParticipantsRepositoryImpl` (Hilt `@Singleton`) holds `ConversationApi`, `ParticipantDao`, and a
`@IoDispatcher CoroutineDispatcher`. Read path is offline-first: `observeRoster` maps a `ParticipantDao`
Flow to domain; `refreshRoster` does a network GET and upserts into Room (single transaction, replacing
the roster for that conversation). Mutations follow optimistic write → API call → reconcile/rollback.

### 4.3 ViewModel (feature-conversations)

```kotlin
@HiltViewModel
class GroupParticipantsViewModel @Inject constructor(
    private val repo: GroupParticipantsRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val conversationId: String = checkNotNull(savedStateHandle["conversationId"])
    val uiState: StateFlow<RosterUiState>

    fun onRefresh()
    fun onAddParticipants(userIds: List<String>)
    fun onRemove(userId: String)
    fun onChangeRole(userId: String, role: ParticipantRole)
    fun onErrorConsumed()
}

sealed interface RosterUiState {
    data object Loading : RosterUiState
    data class Content(
        val roster: GroupRoster,
        val pendingUserIds: Set<String> = emptySet(), // rows with in-flight mutations
        val isRefreshing: Boolean = false,
        val canManage: Boolean,                        // derived from currentUserRole
        val error: RosterError? = null,                // transient, consumed by UI
    ) : RosterUiState
    data class Error(val message: String, val retryable: Boolean) : RosterUiState
}

data class RosterError(val message: String, val userId: String?)
```

`uiState` is built with `combine(repo.observeRoster(id), mutationState)` and exposed via
`stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), Loading)`. `pendingUserIds` drives
per-row progress; `canManage = currentUserRole in {OWNER, ADMIN}`.

### 4.4 UI (Compose, Material 3)

- `GroupParticipantsScreen(onBack, onPickContacts)` — top app bar with "Add" action (visible when
  `canManage`), `PullToRefreshBox`, `LazyColumn` of `ParticipantRow`.
- `ParticipantRow(participant, isPending, canManage, onRemove, onChangeRole)` — avatar (Coil), name,
  role badge; trailing overflow menu with "Make admin"/"Remove" (disabled while `isPending` or for
  self / protected cases). Confirm destructive remove with a Material 3 `AlertDialog`.
- Contact selection reuses the existing contact picker introduced for AND-157; results returned via the
  Navigation-Compose `savedStateHandle` back-result pattern and forwarded to `onAddParticipants`.

## 5. API Contract

Paths align with the web reference and `/openapi.json`; confirm exact field casing at build time. Base
path `/conversations/{conversationId}`. All requests carry session cookies + `X-CSRF-Token`.

**GET `/conversations/{conversationId}/participants`** — roster fetch (idempotent; eligible for bounded
backoff retry, ~20s timeout).
```json
{
  "conversation_id": "grp_abc123",
  "current_user_role": "admin",
  "participants": [
    { "user_id": "u_1", "display_name": "Ada", "avatar_url": null, "role": "owner",  "joined_at": "2026-06-01T12:00:00Z" },
    { "user_id": "u_2", "display_name": "Bri", "avatar_url": "https://…", "role": "member", "joined_at": "2026-06-02T09:30:00Z" }
  ]
}
```

**POST `/conversations/{conversationId}/participants`** — add members (non-idempotent; no auto-retry).
Request:
```json
{ "user_ids": ["u_7", "u_8"] }
```
Response `200`: `{ "added": [ { "user_id": "u_7", "display_name": "Cy", "avatar_url": null, "role": "member", "joined_at": "2026-06-05T10:00:00Z" } ] }`

**PATCH `/conversations/{conversationId}/participants/{userId}`** — change role (state-changing; no
auto-retry). Request: `{ "role": "admin" }`. Response `200`: the updated `Participant` object.

**DELETE `/conversations/{conversationId}/participants/{userId}`** — remove member (state-changing; no
auto-retry). Response `204 No Content`.

Retrofit:
```kotlin
interface ConversationApi {
    @GET("conversations/{id}/participants")
    suspend fun getParticipants(@Path("id") id: String): Response<RosterDto>

    @POST("conversations/{id}/participants")
    suspend fun addParticipants(@Path("id") id: String, @Body body: AddParticipantsRequest): Response<AddParticipantsResponse>

    @PATCH("conversations/{id}/participants/{userId}")
    suspend fun changeRole(@Path("id") id: String, @Path("userId") userId: String, @Body body: ChangeRoleRequest): Response<ParticipantDto>

    @DELETE("conversations/{id}/participants/{userId}")
    suspend fun removeParticipant(@Path("id") id: String, @Path("userId") userId: String): Response<Unit>
}
```

**Error body** follows the shared FastAPI shape `detail: string | [{msg}] | {code,...}`, parsed by the
existing core-network `ErrorBodyAdapter` into `ApiResult.Error(code, message)`. Relevant statuses:
`401` (handled by refresh-then-retry interceptor), `403` (insufficient role), `404` (group/user gone),
`409` (e.g. last-admin demotion, user already a member), `422` (validation).

## 6. Data & State Management

### 6.1 Room (core-data)

```kotlin
@Entity(
    tableName = "group_participant",
    primaryKeys = ["conversationId", "userId"],
)
data class ParticipantEntity(
    val conversationId: String,
    val userId: String,
    val displayName: String,
    val avatarUrl: String?,
    val role: String,        // ParticipantRole.name
    val joinedAt: Long,      // epoch millis
)
```

```kotlin
@Dao
interface ParticipantDao {
    @Query("SELECT * FROM group_participant WHERE conversationId = :id ORDER BY role, displayName")
    fun observe(id: String): Flow<List<ParticipantEntity>>

    @Upsert suspend fun upsertAll(rows: List<ParticipantEntity>)
    @Query("DELETE FROM group_participant WHERE conversationId = :id AND userId = :userId")
    suspend fun delete(id: String, userId: String)

    @Query("DELETE FROM group_participant WHERE conversationId = :id")
    suspend fun clearForConversation(id: String)

    @Transaction
    suspend fun replaceRoster(id: String, rows: List<ParticipantEntity>) {
        clearForConversation(id); upsertAll(rows)
    }
}
```

The group's `current_user_role` is stored on the existing conversation row (added/owned by AND-157) or
in a lightweight per-conversation meta column; this ticket updates it on every roster refresh.

### 6.2 Optimistic mutation flow

1. ViewModel adds the target `userId` to `pendingUserIds`.
2. Repository applies the optimistic change to Room (insert/delete/role-update) inside a transaction.
3. API call executes.
4. **Success:** reconcile Room with the authoritative response (e.g. server-assigned role/joinedAt);
   remove from `pendingUserIds`.
5. **Failure:** roll back the optimistic Room write (re-fetch the affected row from the last known good
   snapshot held in-repo, or trigger a `refreshRoster`), set `RosterError`, remove from
   `pendingUserIds`.

Because Room is the single source of truth and the UI observes it via Flow, both optimistic application
and rollback automatically "reflect" in the UI; persistence is satisfied because committed rows survive
process death.

## 7. Error Handling & Resilience

- **Timeouts:** OkHttp client configured (core-network) for ~20s call timeout given the unreliable dev
  host. Surfaced as `ApiResult.Error` with a retryable flag.
- **Retry policy:** only the **idempotent GET** roster fetch uses bounded exponential backoff (max 3
  attempts, jittered). POST/PATCH/DELETE are **never** auto-retried — retry is user-initiated to avoid
  duplicate adds/removes.
- **401:** the shared `Authenticator` performs a single `POST /ui/session/refresh` then retries once;
  if still 401, propagate to a session-expired state handled by the app shell.
- **403:** roll back optimistic change, show "You don't have permission to manage this group" snackbar;
  re-fetch roster to correct stale role gating.
- **409:** map to specific copy (last-admin demotion → "A group must have at least one admin"; already
  a member → silently reconcile by refreshing roster).
- **Offline / stale:** when the network is unavailable the cached roster renders with a stale banner;
  mutation actions are disabled and show "You're offline" rather than queuing (no offline write queue in
  this ticket).
- **Rollback guarantee:** every mutation path has a deterministic rollback; a unit test asserts cache
  equality before-and-after a forced failure.

## 8. Security & Privacy

- **Transport:** dev backend is plaintext HTTP; the app's network security config permits cleartext for
  the dev host only (inherited from core-network). No participant data is logged in plaintext.
- **Auth:** every mutating request must include session cookies (persistent `CookieJar`) and the
  `X-CSRF-Token` header echoing the `ui_csrf` cookie — both injected by the shared OkHttp interceptor.
  Requests without CSRF must fail closed (no silent unauthenticated mutation).
- **Authorization:** client gating is a UX convenience only; the server is authoritative. The UI must
  never assume an action succeeded without a 2xx.
- **Privacy:** participant `userId`/`displayName`/`avatarUrl` are PII; never include them in analytics
  event params (use hashed/opaque ids — see §10) and never persist to DataStore.
- **Self-protection:** client blocks self-removal/self-demote and last-admin demote to reduce
  accidental privilege loss; server enforcement is the real guard.

## 9. Accessibility & i18n

- All actionable controls (Add, overflow menu items, dialog buttons) have `contentDescription` /
  semantic labels; role badges expose text alternatives (not color-only). Minimum 48dp touch targets.
- Confirmation dialogs are focus-trapped and TalkBack-announced; destructive remove is announced as
  destructive.
- Per-row in-flight state announces "updating <name>" via `Modifier.semantics { stateDescription = … }`.
- All user-facing strings live in `res/values/strings.xml` with parameterized plurals for
  "Add N people" / "N members". No hardcoded strings in Compose. Dynamic content respects RTL and
  large-font scaling.

## 10. Telemetry & Logging

- Events (via the app's analytics abstraction in core-data): `group_participant_add`,
  `group_participant_remove`, `group_participant_role_change`, each with params
  `{ conversation_id_hash, count?, target_role?, result: success|error, error_code? }`. **No PII** (ids
  hashed/opaque).
- Roster refresh failures emit `group_roster_refresh_failed { error_code }`.
- Logging uses the core Timber tree; mutation requests log method/path/status at DEBUG (release strips
  DEBUG), never request/response bodies containing PII. Latency of each mutation recorded for the
  unreliable-host monitoring.

## 11. Testing Strategy

**Unit (core-testing + JUnit/Turbine/MockWebServer):**
- `GroupParticipantsRepositoryImplTest`: add/remove/role each assert (a) optimistic Room write,
  (b) reconcile on 2xx, (c) full rollback on 403/409/timeout. Uses in-memory Room + MockWebServer.
- `GroupParticipantsViewModelTest` (Turbine): `pendingUserIds` set/clear transitions; `canManage`
  derivation; `RosterError` emission and `onErrorConsumed`; self/last-admin guard prevents the call.
- DTO mapping tests for `RosterDto`/`ParticipantDto` including FastAPI `detail` variants.

**Persistence test (the headline acceptance):** add a participant, simulate process recreation by
re-instantiating the DAO against the same DB file, assert the roster still contains the member without a
network call; repeat for remove and role-change.

**Instrumented/UI (Compose test rule):** add flow returns from picker → row appears; remove → confirm
dialog → row disappears; role change updates badge; non-admin sees read-only roster (no Add action, no
overflow). MockWebServer drives 200/403/409 scenarios.

Coverage target consistent with module standard; all new public repo/VM functions exercised.

## 12. Dependencies & Sequencing

- **Depends on AND-157 (Group create):** requires the group conversation, `Participant`/role models,
  `ConversationDao` group rows, contact picker, and `GroupDetailScreen` entry point. Must merge after
  AND-157.
- **Depends on core-network** cookie/CSRF interceptor + `ApiResult`/error mapping (already in place).
- **Shares** the `ConversationApi` Retrofit interface with AND-157; participant endpoints added here.
- **Blocks:** none recorded in the source backlog. Self-leave / group-settings flows, if introduced
  later (e.g. AND-159+), should consume this repository rather than duplicate it.

## 13. Risks & Open Questions

- **Q1 (endpoint shape):** confirm against `/openapi.json` whether add returns the full roster or only
  `added[]`, and whether role values are `owner/admin/member` lowercase. Repository mapping isolates this.
- **Q2 (batch add semantics):** does POST add fail atomically or partially (some users invalid)? If
  partial, response must enumerate failures; current design assumes atomic 2xx with `added[]` and treats
  422 as full failure.
- **Q3 (last-admin / owner rules):** exact server rules for demoting the last admin and whether owner is
  distinct from admin — client guard mirrors assumed rules; reconcile via 409 handling.
- **Risk:** unreliable dev host causing optimistic/server divergence — mitigated by reconcile + refresh
  on every error.
- **Risk:** stale `current_user_role` causing a forbidden action to appear available — mitigated by
  refreshing roster on screen entry and on any 403.

## 14. Acceptance Criteria

AC-1. Adding one or more participants succeeds against `POST /conversations/{id}/participants`, the new
members appear in the roster, and they remain after app restart (cold cache, no network). *(persist + reflect)*

AC-2. Removing a participant succeeds against `DELETE /conversations/{id}/participants/{userId}`
(204), the row disappears after confirmation, and the removal persists across restart.

AC-3. Changing a participant's role succeeds against `PATCH /conversations/{id}/participants/{userId}`,
the role badge updates, and the new role persists across restart.

AC-4. Optimistic changes roll back fully (cache + UI) on 403/409/timeout, with a clear, retryable error
surfaced; no orphaned `pendingUserIds`.

AC-5. Non-admin members see a read-only roster (no Add action, no row management menu).

AC-6. Current user cannot self-remove/self-demote, and the last admin cannot be demoted, via the UI.

AC-7. All mutating requests include cookies + `X-CSRF-Token`; a 401 triggers exactly one refresh-retry.

AC-8. No PII appears in analytics params or release logs.

## 15. Definition of Done

- Code merged to `android-port` under `feature-conversations` (+ core-model/core-data additions),
  package `com.testlogon.android`, building on Gradle 8.9 / AGP 8.7.3 / JDK 17, minSdk 24 / target 35.
- Repository, ViewModel, DAO, DTOs, and Compose screen implemented per §4–§6 with Hilt wiring (KSP).
- Unit + persistence + Compose UI tests from §11 implemented and green in CI; the persistence test
  proving "persist + reflect" (AC-1/2/3) explicitly present.
- Strings externalized; accessibility checks (§9) pass; lint/detekt clean.
- API field shapes verified against `/openapi.json`; open questions Q1–Q3 resolved or documented as
  follow-ups.
- PR reviewed and approved; no new cleartext exceptions beyond the existing dev-host config.
