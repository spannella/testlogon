---
id: AND-158
title: Group participants management
milestone: M3
epic: E22
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
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
- **Web reference:** `src/api/endpoints/messaging.ts` (`addParticipants`, `updateParticipantRole`)
  and shared types in `src/api/types.ts` (`Participant`, `AddParticipantsReq`, `UpdateRoleReq`).
  Mirror those payload shapes exactly. NOTE (corrected during review): the web app has **no
  conversations.ts** endpoint file and exposes **no remove-participant** helper — the web
  `ParticipantsPanel.tsx` only adds members and changes roles; remove is Android-net-new against the
  backend `DELETE` endpoint that does exist (see §5). Verified against `src/api/endpoints/messaging.ts`
  and `/openapi.json`.
- **Auth/session:** the web client sends an `Authorization: Bearer <token>` header **plus** session
  cookies (`credentials: include`) **plus** an `X-CSRF-Token` header echoing the `ui_csrf` cookie
  (verified in `src/api/client.ts`). The backend additionally declares optional `authorization` and
  `X-SESSION-ID` headers on every participant endpoint (verified in `/openapi.json`). On 401 the web
  client performs a one-shot `POST /ui/session/refresh` then retries once (verified in
  `src/api/client.ts: refreshSession`). The Android `Authenticator`/interceptor from core-network must
  send all of cookies + `Authorization` + `X-CSRF-Token` (and `X-SESSION-ID` if available); no changes
  to that interceptor here.

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
// CORRECTED: backend role enum is only {admin, member}. UpdateParticipantRoleIn.role ∈ {"admin","member"}
// and frontend Participant.role is `"admin" | "member"`. There is NO `owner` role in the messaging
// participant contract (an `owner`/`owner_user_id` concept exists on other resources but not here).
// OWNER kept only as a defensive UNKNOWN-fallback bucket; do NOT send it to the server.
enum class ParticipantRole { ADMIN, MEMBER }

data class Participant(
    val userId: String,           // maps to Participant.user_id
    val displayName: String?,     // Participant.display_name is OPTIONAL in the web type — nullable
    val avatarUrl: String?,       // maps to Participant.profile_photo_url (NOT `avatar_url`)
    val role: ParticipantRole,    // Participant.role ("admin" | "member"), default member when absent
    val joinedAt: Instant?,       // Participant.joined_at is epoch seconds/millis number, OPTIONAL
)

data class GroupRoster(
    val conversationId: String,
    val participants: List<Participant>,
    // UNVERIFIED ASSUMPTION: the backend does NOT return a `current_user_role` field (the GET
    // participants response is untyped in /openapi.json and absent from web types). Derive the
    // current user's role client-side from `participants` matched against the logged-in user id.
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
per-row progress; `canManage = currentUserRole == ParticipantRole.ADMIN` (corrected: no OWNER role
exists in this contract).

### 4.4 UI (Compose, Material 3)

- `GroupParticipantsScreen(onBack, onPickContacts)` — top app bar with "Add" action (visible when
  `canManage`), `PullToRefreshBox`, `LazyColumn` of `ParticipantRow`.
- `ParticipantRow(participant, isPending, canManage, onRemove, onChangeRole)` — avatar (Coil), name,
  role badge; trailing overflow menu with "Make admin"/"Remove" (disabled while `isPending` or for
  self / protected cases). Confirm destructive remove with a Material 3 `AlertDialog`.
- Contact selection reuses the existing contact picker introduced for AND-157; results returned via the
  Navigation-Compose `savedStateHandle` back-result pattern and forwarded to `onAddParticipants`.

## 5. API Contract

All paths verified against `/openapi.json` and `src/api/endpoints/messaging.ts`. **CORRECTED:** the base
path is `/messaging/conversations/{conversation_id}` (the spec previously claimed `/conversations/...`),
the per-member path segment is `{participant_id}` (not `{userId}`), and the response shapes below replace
the previously-assumed shapes. All requests carry session cookies + `Authorization: Bearer` +
`X-CSRF-Token` (and optional `X-SESSION-ID`); see §2/§8.

**GET `/messaging/conversations/{conversation_id}/participants`** — `op=list_participants_...`
(idempotent; eligible for bounded backoff retry, ~20s timeout). The response schema is **untyped** in
`/openapi.json` (`schema: {}`) and there is no dedicated roster type in the web client; the web app
instead derives participants from `GET /messaging/conversations/{conversation_id}` →
`ConversationOut.participants` (`src/pages/messages/ParticipantsPanel.tsx`). The authoritative per-row
shape is `Participant` from `src/api/types.ts`:
```json
{
  "participants": [
    { "user_id": "u_1", "display_name": "Ada", "role": "admin",  "joined_at": 1748779200, "profile_photo_url": null, "status": "active" },
    { "user_id": "u_2", "display_name": "Bri", "role": "member", "joined_at": 1748856600, "profile_photo_url": "https://…" }
  ]
}
```
NOTE: fields are snake_case; `display_name`, `joined_at`, `profile_photo_url`, `role` are all OPTIONAL.
There is **NO `current_user_role`** field — derive it client-side (see §4.1). `joined_at` is a numeric
epoch timestamp (not an ISO-8601 string). The image field is `profile_photo_url`, not `avatar_url`.
If the Android team prefers the dedicated `/participants` GET over the conversation GET, treat its body
as a best-effort superset and map defensively (it is untyped server-side).

**POST `/messaging/conversations/{conversation_id}/participants`** — `op=add_participants_...` (request
`AddParticipantsIn`; non-idempotent; no auto-retry).
Request (**CORRECTED** — field is `participant_ids`, not `user_ids`):
```json
{ "participant_ids": ["u_7", "u_8"] }
```
Response `200` (**CORRECTED** — NOT `{ "added": [...] }`):
```json
{ "ok": true, "added_count": 2 }
```
Because the response does not echo the added member rows, the optimistic path must build provisional
rows locally and then `refreshRoster()` to obtain authoritative roles/`joined_at` (§6.2).

**PATCH `/messaging/conversations/{conversation_id}/participants/{participant_id}`** — change role
(request `UpdateParticipantRoleIn`; state-changing; no auto-retry).
Request: `{ "role": "admin" }` where `role ∈ {"admin","member"}` (**CORRECTED** — no `"owner"`).
Response `200` (**CORRECTED** — NOT the full Participant object): `{ "ok": true, "role": "admin" }`.

**DELETE `/messaging/conversations/{conversation_id}/participants/{participant_id}`** — remove member
(`op=remove_participant_...`; state-changing; no auto-retry). **CORRECTED:** response is `200` with a
JSON body (`Successful Response`), **not** `204 No Content`. This endpoint exists in the backend but is
**not** wired in the web client (no `removeParticipant` helper / no remove UI in `ParticipantsPanel.tsx`),
so the exact body is unverifiable from the web reference — treat it as `{ "ok": true }`-style and ignore
the body on 200.

Retrofit (**CORRECTED** paths/types):
```kotlin
interface ConversationApi {
    @GET("messaging/conversations/{id}/participants")
    suspend fun getParticipants(@Path("id") id: String): Response<RosterDto>

    @POST("messaging/conversations/{id}/participants")
    suspend fun addParticipants(@Path("id") id: String, @Body body: AddParticipantsRequest): Response<AddParticipantsResponse> // { ok, added_count }

    @PATCH("messaging/conversations/{id}/participants/{participantId}")
    suspend fun changeRole(@Path("id") id: String, @Path("participantId") participantId: String, @Body body: ChangeRoleRequest): Response<ChangeRoleResponse> // { ok, role }

    @DELETE("messaging/conversations/{id}/participants/{participantId}")
    suspend fun removeParticipant(@Path("id") id: String, @Path("participantId") participantId: String): Response<Unit> // 200, body ignored
}

data class AddParticipantsRequest(val participant_ids: List<String>)
data class ChangeRoleRequest(val role: String)            // "admin" | "member"
data class AddParticipantsResponse(val ok: Boolean, val added_count: Int)
data class ChangeRoleResponse(val ok: Boolean, val role: String)
```

**Error body** follows the shared FastAPI shape `detail: string | [{msg}] | {code,...}`, parsed by the
existing core-network `ErrorBodyAdapter` into `ApiResult.Error(code, message)`. Statuses documented in
`/openapi.json` for these ops are `200` and `422` (HTTPValidationError) only; `401/403/404/409` are
**assumed** by analogy with other messaging endpoints (e.g. the conversation list/get ops document
`400/401/403/429`) and the app's auth middleware — treat `403`/`404`/`409` handling as defensive and
not contractually guaranteed for the participant ops specifically: `401` (refresh-then-retry interceptor),
`403` (insufficient role — assumed), `404` (group/user gone — assumed), `409` (last-admin demotion /
already-a-member — assumed), `422` (validation — verified).

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
4. **Success:** reconcile Room with the authoritative state, then remove from `pendingUserIds`. NOTE
   (corrected): add returns only `{ ok, added_count }` and role-change returns only `{ ok, role }` —
   neither echoes full member rows — so reconciliation for **add** is a follow-up `refreshRoster()`
   (to obtain server-assigned `joined_at`/`role`); for **role-change** apply the returned `role`; for
   **remove** keep the optimistic deletion.
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
- **Auth:** every mutating request must include session cookies (persistent `CookieJar`), the
  `Authorization: Bearer <token>` header, and the `X-CSRF-Token` header echoing the `ui_csrf` cookie —
  all injected by the shared OkHttp interceptor (verified against `src/api/client.ts`: it sets
  `credentials: "include"`, `Authorization: Bearer …`, and `X-CSRF-Token` from `getCookie("ui_csrf")`).
  The backend also declares an optional `X-SESSION-ID` header on these ops; forward it when available.
  Requests without CSRF/Authorization must fail closed (no silent unauthenticated mutation).
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

- **Q1 (endpoint shape):** RESOLVED during review. Add returns `{ ok, added_count }` (no member rows);
  role values are exactly `admin`/`member` lowercase (no `owner`). Roster is fetched via the untyped
  `/participants` GET or derived from `ConversationOut.participants`. Repository mapping isolates this.
- **Q2 (batch add semantics):** does POST add fail atomically or partially (some users invalid)? Still
  OPEN — `added_count` could be < the requested count, implying partial success, but the contract is
  undocumented. Current design treats `added_count < requested` by always following with a
  `refreshRoster()` and treats `422` as full failure. Verify on the dev host.
- **Q3 (last-admin / owner rules):** PARTIALLY RESOLVED. There is no distinct `owner` role in the
  messaging participant contract (only admin/member), so the "owner vs admin" question is moot. Exact
  server rules for demoting the last admin remain UNVERIFIED (no documented `409`); client guard mirrors
  assumed rules and reconciles via error handling + refresh.
- **Risk:** unreliable dev host causing optimistic/server divergence — mitigated by reconcile + refresh
  on every error.
- **Risk:** stale `current_user_role` causing a forbidden action to appear available — mitigated by
  refreshing roster on screen entry and on any 403.

## 14. Acceptance Criteria

AC-1. Adding one or more participants succeeds against
`POST /messaging/conversations/{conversation_id}/participants` with body `{ "participant_ids": [...] }`
(response `{ ok, added_count }`), the new members appear in the roster after a follow-up refresh, and
they remain after app restart (cold cache, no network). *(persist + reflect)*

AC-2. Removing a participant succeeds against
`DELETE /messaging/conversations/{conversation_id}/participants/{participant_id}` (HTTP `200`, body
ignored), the row disappears after confirmation, and the removal persists across restart.

AC-3. Changing a participant's role succeeds against
`PATCH /messaging/conversations/{conversation_id}/participants/{participant_id}` with body
`{ "role": "admin"|"member" }` (response `{ ok, role }`), the role badge updates, and the new role
persists across restart.

AC-4. Optimistic changes roll back fully (cache + UI) on 403/409/timeout, with a clear, retryable error
surfaced; no orphaned `pendingUserIds`.

AC-5. Non-admin members see a read-only roster (no Add action, no row management menu).

AC-6. Current user cannot self-remove/self-demote, and the last admin cannot be demoted, via the UI.

AC-7. All mutating requests include cookies + `Authorization: Bearer` + `X-CSRF-Token` (and
`X-SESSION-ID` when available); a 401 triggers exactly one `POST /ui/session/refresh` then retry.

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

## 16. Citations & Assumption Audit

Each key technical claim with its VERDICT and exact source pointer. OpenAPI pointers use
`METHOD /path` / schema names from `reference/openapi.index.txt` + `reference/openapi.pretty.json`;
frontend pointers are paths under `reference/src/`.

1. **Add endpoint path & method** = `POST /messaging/conversations/{conversation_id}/participants`.
   VERDICT: Corrected (spec said `POST /conversations/{conversationId}/participants`).
   SOURCE: OpenAPI `POST /messaging/conversations/{conversation_id}/participants`
   (op=`add_participants_...`); `src/api/endpoints/messaging.ts: addParticipants`.
2. **Add request body field** = `participant_ids: string[]`. VERDICT: Corrected (spec said `user_ids`).
   SOURCE: schema `AddParticipantsIn` (property `participant_ids`); `src/api/types.ts: AddParticipantsReq`;
   `src/api/endpoints/messaging.ts` line 593; `src/pages/messages/ParticipantsPanel.tsx` line 46
   (`{ participant_ids: [userId] }`).
3. **Add response shape** = `{ ok: boolean, added_count: number }`. VERDICT: Corrected (spec said
   `{ added: [Participant…] }`). SOURCE: `src/api/endpoints/messaging.ts: addParticipants` return type
   `api.post<{ ok: boolean; added_count: number }>`. (OpenAPI response is untyped `schema: {}`.)
4. **Change-role endpoint** = `PATCH /messaging/conversations/{conversation_id}/participants/{participant_id}`.
   VERDICT: Corrected (spec path/segment said `/conversations/.../{userId}`).
   SOURCE: OpenAPI `PATCH /messaging/conversations/{conversation_id}/participants/{participant_id}`
   (op=`update_participant_role_...`); `src/api/endpoints/messaging.ts: updateParticipantRole`.
5. **Change-role request body** = `{ role: "admin" | "member" }`. VERDICT: Corrected (spec implied an
   `owner` value was possible). SOURCE: schema `UpdateParticipantRoleIn` (`role` enum `["admin","member"]`,
   required); `src/api/types.ts: UpdateRoleReq`.
6. **Change-role response shape** = `{ ok: boolean, role: string }`. VERDICT: Corrected (spec said "the
   updated Participant object"). SOURCE: `src/api/endpoints/messaging.ts: updateParticipantRole` return
   type `api.patch<{ ok: boolean; role: string }>`.
7. **Remove endpoint & response code** = `DELETE /messaging/conversations/{conversation_id}/participants/{participant_id}`,
   HTTP **200** with JSON body. VERDICT: Corrected (spec said `204 No Content`).
   SOURCE: OpenAPI `DELETE /messaging/conversations/{conversation_id}/participants/{participant_id}`
   (op=`remove_participant_...`), response `200: Successful Response`.
8. **Remove not implemented in web client.** VERDICT: Verified. SOURCE: `src/api/endpoints/messaging.ts`
   exports `addParticipants` + `updateParticipantRole` only (no `removeParticipant`);
   `src/pages/messages/ParticipantsPanel.tsx` has add + role controls but no remove UI. The backend
   endpoint nevertheless exists (citation 7), so the exact 200 body is an assumption (see Open assumptions).
9. **Roster GET endpoint** = `GET /messaging/conversations/{conversation_id}/participants`. VERDICT:
   Verified (path corrected to `/messaging/...`). SOURCE: OpenAPI
   `GET /messaging/conversations/{conversation_id}/participants` (op=`list_participants_...`).
10. **Participant DTO fields** = snake_case `user_id`, optional `display_name`, optional `role`
    (`"admin"|"member"`), optional numeric `joined_at`, optional `profile_photo_url`, `status`.
    VERDICT: Corrected (spec used `avatar_url` and ISO-string `joined_at`, and non-null fields).
    SOURCE: `src/api/types.ts: Participant` (lines 831-841).
11. **No `current_user_role` field on the roster response.** VERDICT: Corrected → Unverified-assumption.
    The spec/model assumed a server-provided `current_user_role`. SOURCE: absent from `src/api/types.ts`
    (no such field on `Participant`/`Conversation`); GET participants response is untyped in OpenAPI
    (`schema: {}`). Current user's role must be derived client-side.
12. **Role values are exactly `admin`/`member` (no `owner`).** VERDICT: Corrected.
    SOURCE: `UpdateParticipantRoleIn.role` enum; `src/api/types.ts: Participant.role` = `"admin" | "member"`.
13. **Auth headers on participant calls** = cookies (`credentials: include`) + `Authorization: Bearer` +
    `X-CSRF-Token` (from `ui_csrf` cookie); backend also declares optional `authorization` + `X-SESSION-ID`.
    VERDICT: Corrected (spec listed only cookie + `X-CSRF-Token`). SOURCE: `src/api/client.ts` lines
    124/158-159/167-170/183; OpenAPI participant ops `params=...,authorization,X-SESSION-ID`.
14. **401 handling** = one-shot `POST /ui/session/refresh` then single retry. VERDICT: Verified.
    SOURCE: `src/api/client.ts: refreshSession` (lines 121-128) and 401 handling (lines 191-236).
15. **422 returns FastAPI `HTTPValidationError` (`detail`).** VERDICT: Verified. SOURCE: all four
    participant ops list `422: HTTPValidationError` in `openapi.index.txt`; schema `HTTPValidationError`.
16. **`403`/`404`/`409` status handling.** VERDICT: Unverified-assumption. SOURCE: NOT documented on the
    participant ops (they list only `200`/`422`); inferred from sibling messaging ops
    (`GET /messaging/conversations` lists `400/401/403/429`) and app auth middleware.
17. **Framework choices** (Compose Material 3 `PullToRefreshBox`, Hilt `@HiltViewModel`/KSP, Room
    `@Upsert`/`@Transaction`, Coil, Navigation-Compose `savedStateHandle` back-result). VERDICT:
    Unverified-assumption (consistent with current AndroidX guidance; not checked against a live docs
    URL in this review). SOURCE: framework ref — Android developer docs (Compose Material 3, Hilt, Room,
    Navigation-Compose). Validate API surfaces against the versions pinned by the project at build time.

### Corrections made

- §2/§4.1/§5/§14/AC: base path corrected `/conversations/...` → `/messaging/conversations/...`; member
  path segment `{userId}` → `{participant_id}`.
- §5/§14: add request field `user_ids` → `participant_ids`.
- §5/§6.2/§14: add response `{ added: [...] }` → `{ ok, added_count }`; add reconciliation now requires a
  follow-up `refreshRoster()` since rows aren't echoed.
- §5/§14: role-change response "Participant object" → `{ ok, role }`.
- §5/§14/AC-2: DELETE response `204 No Content` → `200` with body (ignored).
- §4.1/§4.3/§13: removed the `OWNER` role (contract is `admin`/`member` only); `canManage` now
  `== ADMIN`.
- §4.1 Participant DTO: `avatar_url` → `profile_photo_url`; ISO-string `joined_at` → numeric epoch;
  `display_name`/`role`/`joined_at` made nullable.
- §2/§8/AC-7: auth corrected to cookies + `Authorization: Bearer` + `X-CSRF-Token` (+ optional
  `X-SESSION-ID`).
- §2: corrected the web-reference pointer (no `conversations.ts`; the helpers live in `messaging.ts`)
  and noted the web client has no remove-participant flow.
- §13: Q1 resolved, Q3 partially resolved (no `owner` role), Q2 left open with explicit handling.

### Open assumptions

- **`current_user_role` derivation:** server does not return it; we assume the current user id is
  available from the auth/session store and that exactly one `participants[]` row matches it. Why
  unverifiable: roster GET is untyped server-side and no web code consumes a roster-level role.
- **DELETE remove response body:** endpoint returns `200` but has no web consumer and an untyped schema;
  we assume an `{ ok: true }`-style body and ignore it. Verify against the live dev host.
- **`403`/`404`/`409` semantics** (insufficient role, last-admin demotion, already-a-member): not
  documented for the participant ops; handling is defensive. Why unverifiable: only `200`/`422` are in
  the OpenAPI spec for these ops.
- **Batch-add atomicity (Q2):** `added_count` may be partial; undocumented. We always refresh after add.
- **Pull-to-refresh / contact-picker reuse from AND-157:** assumes AND-157 landed those affordances;
  not yet present in this repo snapshot.

## 17. Test Plan

Test targets: **JVM** = local JVM/Robolectric (no device); **emu35** = headless AVD `test35` (x86_64,
API 35); **A15** = physical Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, API 34, arm64-v8a).
Most cases are device-agnostic and run fastest on JVM or emu35. A15 is reserved for cases that must
exercise real hardware / a real network path against the flaky dev host; those are flagged
"MUST run on A15". No participant feature here uses camera/biometrics/FCM/WebRTC, so the physical
device is used primarily for the real-network/offline-transition case.

- **TC-AND-158-01** — Add participants happy path (contract).
  Type: contract/MockWebServer. Target: JVM. Preconditions: in-memory Room with an existing roster
  (current user is admin); MockWebServer scripted `POST .../participants` → `200 {"ok":true,"added_count":2}`
  then `GET .../participants` → roster incl. new members. Steps: call
  `repo.addParticipants(convId, ["u_7","u_8"])`; await. Expected: request path is
  `POST /messaging/conversations/{id}/participants`, body `{"participant_ids":["u_7","u_8"]}`; result is
  `ApiResult.Success`; a follow-up refresh runs and Room now contains u_7/u_8; `pendingUserIds` cleared.
  Traces: AC-1.

- **TC-AND-158-02** — Remove participant happy path (contract).
  Type: contract/MockWebServer. Target: JVM. Preconditions: roster with member u_2; MockWebServer
  `DELETE .../participants/u_2` → `200 {"ok":true}`. Steps: call `repo.removeParticipant(convId,"u_2")`.
  Expected: request is `DELETE /messaging/conversations/{id}/participants/u_2`; 200 body ignored; u_2
  removed from Room; `ApiResult.Success`. Traces: AC-2.

- **TC-AND-158-03** — Change role happy path (contract).
  Type: contract/MockWebServer. Target: JVM. Preconditions: roster with member u_2; MockWebServer
  `PATCH .../participants/u_2` → `200 {"ok":true,"role":"admin"}`. Steps: call
  `repo.changeRole(convId,"u_2",ADMIN)`. Expected: request body `{"role":"admin"}`; Room role for u_2
  becomes ADMIN; returned `role` applied; `ApiResult.Success`. Traces: AC-3.

- **TC-AND-158-04** — Persistence across process death (the headline "persist + reflect").
  Type: integration (in-memory→file Room). Target: emu35 (instrumented Room on a real DB file).
  Preconditions: real Room DB file. Steps: perform add, remove, and role-change (each reconciled);
  close the DB and re-open a fresh DAO instance against the same file with **no network**; query roster.
  Expected: added member present, removed member absent, changed role persisted — all without a network
  call. Traces: AC-1, AC-2, AC-3.

- **TC-AND-158-05** — Optimistic rollback on 403.
  Type: unit (Turbine VM) + contract. Target: JVM. Preconditions: roster, current user admin;
  MockWebServer `PATCH .../participants/u_2` → `403 {"detail":"forbidden"}`. Steps: snapshot Room;
  `onChangeRole("u_2", ADMIN)`; observe `uiState`. Expected: role flips optimistically then rolls back to
  the pre-mutation snapshot (cache equality before==after); `RosterError` surfaced (retryable); roster
  re-fetched; no orphaned `pendingUserIds`. Traces: AC-4.

- **TC-AND-158-06** — Optimistic rollback on 409 last-admin demotion.
  Type: contract/MockWebServer. Target: JVM. Preconditions: roster where u_1 is the only admin;
  MockWebServer `PATCH .../participants/u_1` → `409 {"detail":{"code":"last_admin"}}`. Steps: attempt to
  demote u_1 to member. Expected: optimistic change rolled back; error mapped to "A group must have at
  least one admin"; cache unchanged after reconcile. Traces: AC-4, AC-6.

- **TC-AND-158-07** — Validation error (422) on add.
  Type: contract/MockWebServer. Target: JVM. Preconditions: MockWebServer `POST .../participants` →
  `422` with `HTTPValidationError` body (`{"detail":[{"loc":["body","participant_ids"],"msg":"...","type":"..."}]}`).
  Steps: `repo.addParticipants(convId, [])`. Expected: `detail[]` parsed by `ErrorBodyAdapter` into
  `ApiResult.Error`; treated as full failure; no optimistic rows remain; no auto-retry of the POST.
  Traces: AC-4.

- **TC-AND-158-08** — Auth headers + CSRF + one-shot 401 refresh.
  Type: contract/MockWebServer. Target: JVM. Preconditions: cookie jar with `ui_csrf`; auth store token;
  MockWebServer returns `401` once for `PATCH .../participants/u_2`, then `200` on retry after a
  `POST /ui/session/refresh`. Steps: change role. Expected: original + retried requests carry
  `Cookie`, `Authorization: Bearer …`, and `X-CSRF-Token: <ui_csrf>`; exactly one `/ui/session/refresh`
  is issued; exactly one retry; final `Success`. A request missing CSRF/Authorization must fail closed.
  Traces: AC-7.

- **TC-AND-158-09** — Non-idempotent mutations are never auto-retried; GET is.
  Type: unit. Target: JVM. Preconditions: MockWebServer returns a timeout/`5xx` for POST/PATCH/DELETE and
  for GET. Steps: invoke each mutation once; invoke `refreshRoster`. Expected: each POST/PATCH/DELETE hits
  the server exactly once (no retry) and returns a retryable `ApiResult.Error`; GET retries with bounded
  jittered backoff (≤3 attempts). Traces: AC-4.

- **TC-AND-158-10** — Offline path disables mutations (no write queue) against the flaky dev host.
  Type: instrumented/e2e. Target: **A15 (MUST run on physical device)** — needs real connectivity
  toggling and the real plaintext-HTTP dev host. Preconditions: app on A15 pointed at
  `http://18.222.237.167:8000`; roster cached. Steps: enable airplane mode; open group detail. Expected:
  cached roster renders with a stale banner; Add/overflow actions disabled showing "You're offline";
  re-enabling network restores actions and a refresh reconciles. Traces: AC-4 (resilience), AC-1/2/3
  (reflect-from-cache).

- **TC-AND-158-11** — Non-admin sees read-only roster.
  Type: Compose-UI. Target: emu35. Preconditions: roster where the current user's derived role is
  MEMBER. Steps: render `GroupParticipantsScreen`. Expected: no "Add" app-bar action; no per-row overflow
  menu; rows are display-only. Traces: AC-5.

- **TC-AND-158-12** — Self-protection guards (UI).
  Type: Compose-UI + unit. Target: emu35 (UI) / JVM (VM guard). Preconditions: current user is admin and
  is the last admin. Steps: open own row overflow; attempt self-remove and self-demote; attempt last-admin
  demote. Expected: self-remove/self-demote disabled or blocked client-side (no API call fired — assert at
  VM level); last-admin demote blocked client-side with explanatory copy. Traces: AC-6.

- **TC-AND-158-13** — Add → row appears; Remove → confirm dialog → row disappears; role badge updates.
  Type: Compose-UI. Target: emu35. Preconditions: MockWebServer scripting `200` add/role/remove + GET.
  Steps: drive add (picker result → `onAddParticipants`), remove (overflow → AlertDialog confirm), role
  change (overflow → Make admin). Expected: roster list updates accordingly; destructive remove requires
  confirmation; per-row progress shown while pending. Traces: AC-1, AC-2, AC-3, AC-5.

- **TC-AND-158-14** — Accessibility checks on the roster UI.
  Type: Compose-UI (semantics) + manual TalkBack. Target: emu35 (automated semantics) / A15 (manual
  TalkBack pass). Preconditions: roster rendered as admin. Steps: assert content descriptions/semantic
  labels on Add, overflow items, dialog buttons; role badges expose text (not color-only); touch targets
  ≥48dp; in-flight rows announce "updating <name>" via `stateDescription`; run a TalkBack pass on A15.
  Expected: all assertions pass; destructive remove announced as destructive. Traces: AC-5 (UI surface),
  plus §9 accessibility requirements.

- **TC-AND-158-15** — No PII in analytics params / release logs.
  Type: unit. Target: JVM. Preconditions: fake analytics sink + Timber test tree (release config). Steps:
  perform add/remove/role-change and a forced refresh failure. Expected: emitted events
  (`group_participant_add/remove/role_change`, `group_roster_refresh_failed`) contain only
  `conversation_id_hash`/`count`/`target_role`/`result`/`error_code` — no `user_id`/`display_name`/
  `profile_photo_url`; logs contain no request/response bodies. Traces: AC-8.

### Coverage matrix

| AC | Covered by |
| --- | --- |
| AC-1 (add persists + reflects) | TC-01, TC-04, TC-13 |
| AC-2 (remove persists) | TC-02, TC-04, TC-13 |
| AC-3 (role change persists) | TC-03, TC-04, TC-13 |
| AC-4 (optimistic rollback on 403/409/timeout, retryable) | TC-05, TC-06, TC-07, TC-09, TC-10 |
| AC-5 (non-admin read-only) | TC-11, TC-13, TC-14 |
| AC-6 (self/last-admin protection) | TC-06, TC-12 |
| AC-7 (auth headers + one-shot 401 refresh) | TC-08 |
| AC-8 (no PII in analytics/logs) | TC-15 |
