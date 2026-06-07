---
id: AND-355
title: Groups (social)
milestone: M7
epic: E46
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-027]
blocks: []
---

# AND-355 — Groups (social)

## 1. Overview & Goal

Deliver the **Groups (social)** feature for the TestLogon native Android app: a screen
stack that lets an authenticated user discover their groups, view a group's detail and
member roster, and — when their role permits — manage membership (invite/add, change a
member's role, remove a member, leave a group). The feature is backed by the FastAPI
`/ui/groups/*` endpoints and rides the existing cookie + CSRF session established by the
auth stack (AND-027).

The goal is a `feature-groups` module that exposes three Compose destinations
(`GroupsList`, `GroupDetail`, `GroupMembers`) wired into the single-Activity
Navigation-Compose graph, each driven by a Hilt-injected `ViewModel` exposing a
`StateFlow<UiState>`. Role-gated mutations must be enforced both in the UI (controls
hidden/disabled) and tolerated server-side (a 403 is surfaced gracefully). The acceptance
bar is: **group membership renders and can be managed.**

Out of scope: group *content* feeds/posts, group chat/messaging, group media uploads,
push notifications for invites, and group creation flows beyond what `/ui/groups/*`
exposes (creation is included only if the endpoint exists; see §5/§13).

## 2. Context & References

- **Repo / branch:** `spannella/testlogon`, Android app under `android/`, branch
  `android-port`.
- **Namespace:** module `com.testlogon.android.feature.groups`; models under
  `com.testlogon.android.core.model`.
- **Module layering:** `app -> feature-groups -> core-network, core-model, core-ui,
  core-data, core-testing`.
- **Dependency AND-027 (auth/session endpoints):** provides the authenticated Retrofit
  stack — persistent cookie jar, `X-CSRF-Token` injection from the `ui_csrf` cookie, the
  single-shot 401 → `POST /ui/session/refresh` → retry interceptor, the `ApiResult<T>`
  type, and FastAPI `detail` error mapping. AND-355 consumes that infrastructure and adds
  no new auth behavior.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext HTTP,
  unreliable). OpenAPI at `/openapi.json`. Web reference for endpoint shapes:
  `frontend/src/api/endpoints/*.ts` (look for `groups.ts`) and `frontend/src/api/types.ts`.
- **Authoritative requirement (backlog):** Type Feature · Priority P2 · Deps AND-027 ·
  Scope `/ui/groups/*` membership/roles · Acceptance "Group membership renders + manages."

> Implementation note: exact field names and the existence of mutation endpoints MUST be
> reconciled against `/openapi.json` and `frontend/src/api/endpoints/groups.ts` before
> coding. JSON shapes in §5 are the contract this spec is written against; deviations are
> tracked as open questions in §13.

## 3. Functional Requirements

FR-1 **Groups list.** On entering the Groups tab, show the current user's groups
(`GET /ui/groups` → `op=list_my_groups_ui_groups_get`, body `{ "groups": UserGroup[] }`).
Each row shows group name, member count, the viewer's role badge (`admin` / `moderator` /
`member` — **note:** the API has no `owner` role; the group "owner" is identified by
`UserGroup.admin_user_id`), and a cover image (Coil, from `cover_image_url`). Tapping a row
navigates to detail. **Correction:** the web app exposes a `discoverGroups`
(`GET /ui/groups/discover`) endpoint too; surfacing discovery is optional and tracked in §13.

FR-2 **Empty / offline / error states.** Distinct UI for: no groups (empty illustration +
copy), network failure (retry affordance + last-cached list if present), and loading
(skeleton/spinner). Pull-to-refresh re-fetches.

FR-3 **Group detail.** `GET /ui/groups/{group_id}` renders name, description, member count,
and the viewer's role. A "Members" entry navigates to the roster. A "Leave group" action is
shown to members who are not the group owner (the owner — `my_role == admin` and
`user_id == admin_user_id` — must dissolve via `DELETE /ui/groups/{group_id}`; dissolve is
out of scope → see §13).

FR-4 **Member roster.** `GET /ui/groups/{group_id}/members` lists members with
`display_name` and `role`. **Correction:** the response is `{ "members": GroupMember[],
"count": int }` and the endpoint is **NOT paginated** (no `cursor`/`limit` params in the
OpenAPI index, no `next_cursor` in the body); fetch the full roster in a single call. The
moderation surface `GET /ui/groups/{group_id}/pending` (pending/invited members) is optional
and tracked in §13. **Note:** `GroupMember` has no `username` or `avatar_url` field — only
`user_id`, `role`, `status`, `display_name`, `joined_at?`, `promoted_at?`. Avatars, if
shown, must be resolved separately (out of scope) or omitted.

FR-5 **Role-gated management.** When the viewer's role is `admin` (or the
backend authorizes the action; the server is the source of truth):
  - **Add/invite** a member (`POST /ui/groups/{group_id}/invite`, body
    `GroupInviteIn { "user_id": str }`). **Correction:** there is **no**
    `POST /ui/groups/{groupId}/members` endpoint; invitation is by `user_id`, not
    `username`/`email`. The invitee transitions to `status="invited"` and must accept via
    `POST /ui/groups/{group_id}/invites/{user_id}/respond`.
  - **Change role** of a member (`PATCH /ui/groups/{group_id}/members/{user_id}/role`,
    body `GroupUpdateRoleIn { "role": "moderator" | "member" }`). **Correction:** the path
    has a `/role` suffix, and the role enum accepts only `moderator`/`member` (you cannot
    PATCH a member to `admin`).
  - **Remove** a member (`DELETE /ui/groups/{group_id}/members/{user_id}` → `200`).
  Members with role `member`/`moderator` see a read-only roster (no management controls
  rendered). Approving join requests uses
  `POST /ui/groups/{group_id}/requests/{user_id}/review` (optional; §13).

FR-6 **Leave group.** Any non-owner member can leave via
`POST /ui/groups/{group_id}/leave` (no body) → `200`. **Correction:** there is no
`DELETE /members/me`; leaving is a dedicated POST. On success, pop back to the list and
remove the group from cache.

FR-7 **Optimistic-with-rollback mutations.** Role change and remove update the roster
immediately and roll back on failure with a snackbar; invite is pessimistic (waits for
server confirmation), and since invite returns the member in `status="invited"` (not yet
`active`), it is rendered as a pending entry rather than an active member.

FR-8 **Permission denial.** A 403 from any mutation surfaces a non-fatal snackbar ("You
don't have permission to do that") and reverts optimistic state. The UI never crashes on a
server-side permission mismatch. **Note:** the web client (`client.ts`) shows a toast on
403 unless `silent403` is set, and maps structured `detail.code` values (e.g.
`role_required`) to friendlier copy; the Android `detail` mapper should mirror this.

## 4. Technical Design

New Gradle module `feature-groups` (library, Compose enabled, Hilt + KSP). Layering and
key types:

**Corrected to match `src/api/types.ts: UserGroup` / `GroupMember`** (field names verified
against the frontend DTOs; the OpenAPI responses for these routes are untyped/empty-body so
the frontend types are authoritative):

```kotlin
// core-model — mirrors UserGroup in src/api/types.ts
@JsonClass(generateAdapter = true)
data class Group(
    @Json(name = "group_id") val id: String,             // was "id"
    val name: String,
    val description: String = "",                          // required string in DTO
    val topic: String? = null,
    val visibility: GroupVisibility = GroupVisibility.PRIVATE,  // "public" | "private"
    val status: GroupStatus = GroupStatus.ACTIVE,         // "active" | "dissolved"
    @Json(name = "admin_user_id") val adminUserId: String,// owner-equivalent
    @Json(name = "cover_image_url") val coverImageUrl: String? = null,  // was "avatar_url"
    @Json(name = "member_count") val memberCount: Int = 0,
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "updated_at") val updatedAt: Long = 0,
    @Json(name = "my_role") val myRole: GroupRole = GroupRole.MEMBER,  // optional in DTO
)

enum class GroupVisibility { @Json(name = "public") PUBLIC, @Json(name = "private") PRIVATE }
enum class GroupStatus { @Json(name = "active") ACTIVE, @Json(name = "dissolved") DISSOLVED }

// Correction: there is NO "owner" role. Roles are admin | moderator | member.
enum class GroupRole {
    @Json(name = "admin") ADMIN,
    @Json(name = "moderator") MODERATOR,
    @Json(name = "member") MEMBER,
}

// core-model — mirrors GroupMember in src/api/types.ts
@JsonClass(generateAdapter = true)
data class GroupMember(
    @Json(name = "user_id") val userId: String,
    val role: GroupRole,
    val status: MemberStatus = MemberStatus.ACTIVE,       // active | invited | pending_approval
    @Json(name = "display_name") val displayName: String,
    @Json(name = "joined_at") val joinedAt: Long? = null,
    @Json(name = "promoted_at") val promotedAt: Long? = null,
    // Correction: GroupMember has NO `username` or `avatar_url` field.
)

enum class MemberStatus {
    @Json(name = "active") ACTIVE,
    @Json(name = "invited") INVITED,
    @Json(name = "pending_approval") PENDING_APPROVAL,
}
```

**Corrected Retrofit service** (paths/verbs/bodies verified against the OpenAPI index and
`src/api/endpoints/groups.ts`):

```kotlin
// feature-groups (or core-network) — Retrofit service
interface GroupsApi {
    @GET("ui/groups")                                     // list_my_groups_ui_groups_get
    suspend fun listGroups(): Response<GroupListResponse> // { groups: [...] }

    @GET("ui/groups/{groupId}")                           // get_group_ui_groups__group_id__get
    suspend fun getGroup(@Path("groupId") groupId: String): Response<Group>

    // Correction: NOT paginated — no cursor/limit params; body is { members, count }.
    @GET("ui/groups/{groupId}/members")                   // list_members_..._members_get
    suspend fun listMembers(
        @Path("groupId") groupId: String,
    ): Response<GroupMembersResponse>                     // { members: [...], count: Int }

    // Correction: invite endpoint is POST .../invite with GroupInviteIn { user_id }.
    @POST("ui/groups/{groupId}/invite")                   // invite_to_group_..._invite_post
    suspend fun invite(
        @Path("groupId") groupId: String,
        @Body body: GroupInviteRequest,                   // { user_id: String }
    ): Response<Unit>                                     // 200, untyped body

    // Correction: path has /role suffix; role enum is moderator|member only.
    @PATCH("ui/groups/{groupId}/members/{userId}/role")   // update_member_role_..._role_patch
    suspend fun updateMemberRole(
        @Path("groupId") groupId: String,
        @Path("userId") userId: String,
        @Body body: UpdateRoleRequest,                    // { role: "moderator"|"member" }
    ): Response<Unit>                                     // 200, untyped body

    @DELETE("ui/groups/{groupId}/members/{userId}")       // remove_member_..._delete
    suspend fun removeMember(
        @Path("groupId") groupId: String,
        @Path("userId") userId: String,
    ): Response<Unit>                                     // 200 (NOT 204)

    // Correction: leaving is a dedicated POST, not a self-targeted DELETE.
    @POST("ui/groups/{groupId}/leave")                    // leave_group_..._leave_post
    suspend fun leaveGroup(@Path("groupId") groupId: String): Response<Unit>  // 200
}
```

> Optional/adjacent endpoints not in the core acceptance bar (defer per §13):
> `GET /ui/groups/discover`, `GET /ui/groups/{id}/pending`,
> `POST /ui/groups/{id}/invites/{user_id}/respond`,
> `POST /ui/groups/{id}/requests/{user_id}/review`, `POST /ui/groups/{id}/join`,
> `POST /ui/groups` (create, `CreateGroupIn`), `PATCH /ui/groups/{id}` (`UpdateGroupIn`),
> `DELETE /ui/groups/{id}` (dissolve), and the feed/treasury/fundraising surfaces.

Repository wraps every call in `ApiResult<T>` (from AND-027) and centralizes mapping +
cache writes:

```kotlin
interface GroupsRepository {
    fun observeGroups(): Flow<List<Group>>              // Room-backed, offline-first
    suspend fun refreshGroups(): ApiResult<Unit>
    suspend fun getGroup(groupId: String): ApiResult<Group>
    // Correction: roster is not paged — return the full list, not PagingData.
    suspend fun getMembers(groupId: String): ApiResult<List<GroupMember>>
    // Correction: invite is by user_id (no role param; invitee starts as `invited`).
    suspend fun inviteMember(groupId: String, userId: String): ApiResult<Unit>
    // Correction: role enum is moderator|member only; responses are untyped (Unit).
    suspend fun updateRole(groupId: String, userId: String, role: GroupRole): ApiResult<Unit>
    suspend fun removeMember(groupId: String, userId: String): ApiResult<Unit>
    suspend fun leaveGroup(groupId: String): ApiResult<Unit>
}
```

ViewModels and state:

```kotlin
@HiltViewModel
class GroupsListViewModel @Inject constructor(
    private val repo: GroupsRepository,
) : ViewModel() {
    val uiState: StateFlow<GroupsListUiState>   // Loading | Content(list, isRefreshing) | Empty | Error(msg, hasCache)
    fun refresh()
}

@HiltViewModel
class GroupDetailViewModel @Inject constructor(
    private val repo: GroupsRepository,
    savedStateHandle: SavedStateHandle,        // groupId arg
) : ViewModel() {
    val uiState: StateFlow<GroupDetailUiState>
    fun leave()
}

@HiltViewModel
class GroupMembersViewModel @Inject constructor(
    private val repo: GroupsRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {
    // Correction: roster is not paged; expose the full member list as state.
    val members: StateFlow<List<GroupMember>>
    val viewerRole: StateFlow<GroupRole>
    fun changeRole(userId: String, role: GroupRole)  // role ∈ { MODERATOR, MEMBER }
    fun remove(userId: String)
    fun invite(userId: String)                       // by user_id; no role on invite
    val events: SharedFlow<GroupEvent>               // one-shot snackbars / nav
}
```

Navigation (typed routes appended to the app nav graph):

```kotlin
sealed interface GroupsRoute {
    @Serializable data object List : GroupsRoute
    @Serializable data class Detail(val groupId: String) : GroupsRoute
    @Serializable data class Members(val groupId: String) : GroupsRoute
}
```

Composables: `GroupsListScreen`, `GroupDetailScreen`, `GroupMembersScreen`, plus
`MemberRow`, `RoleBadge`, `AddMemberSheet` (Material 3 `ModalBottomSheet`), and a
`ChangeRoleDialog`. All stateless, hoisting state from the ViewModel; preview-annotated for
each UiState variant.

## 5. API Contract

Base URL `http://18.222.237.167:8000`. All requests carry session cookies; mutations carry
`X-CSRF-Token` (handled by the AND-027 interceptor). Authoritative shapes below; verify
against `/openapi.json`.

The following has been **corrected against the OpenAPI index and
`src/api/endpoints/groups.ts`** (field shapes from `src/api/types.ts`). Note all `/ui/*`
routes also accept `X-SESSION-ID` and optional `X-IMPERSONATION-TOKEN` headers (server
side); the Android client relies on the cookie+`Authorization`+CSRF transport from AND-027.

**GET `/ui/groups`** (`list_my_groups_ui_groups_get`) → `200`
```json
{ "groups": [
  { "group_id": "g_123", "name": "Platform Team", "description": "Core infra",
    "topic": "infra", "visibility": "private", "status": "active",
    "admin_user_id": "u_1", "cover_image_url": "https://.../g.png",
    "member_count": 8, "created_at": 1730000000, "updated_at": 1730000000,
    "my_role": "admin" } ] }
```
> Corrections vs prior draft: key is `group_id` (not `id`), image is `cover_image_url`
> (not `avatar_url`), `my_role` is optional, and `admin`/`moderator`/`member` are the only
> roles (no `owner`). The OpenAPI response body for this op is untyped; `UserGroup` in
> `types.ts` is authoritative.

**GET `/ui/groups/{group_id}`** (`get_group_ui_groups__group_id__get`) → `200` → a single
`UserGroup` object (shape as above). Validation/permission failures surface as `422`
(`HTTPValidationError`) per the index; treat a missing/unauthorized group as an error state.

**GET `/ui/groups/{group_id}/members`** (`list_members_ui_groups__group_id__members_get`) →
`200`. **Correction: NOT paginated** — there are no `cursor`/`limit` query params and no
`next_cursor` in the body.
```json
{ "members": [
    { "user_id": "u_1", "role": "admin", "status": "active",
      "display_name": "Alice", "joined_at": 1730000000, "promoted_at": 1730000100 }
  ],
  "count": 8 }
```
> Corrections: response is `{ members, count }`; `GroupMember` has no `username` and no
> `avatar_url`; role values are `admin`/`moderator`/`member`.

**POST `/ui/groups/{group_id}/invite`** (`invite_to_group_ui_groups__group_id__invite_post`)
— body `GroupInviteIn`:
```json
{ "user_id": "u_bob" }
```
→ `200` (untyped body); invitee becomes `status="invited"`. `422` on validation.
> Correction: there is **no** `POST /ui/groups/{id}/members`. Invitation is by `user_id`
> only (no `role`, no `username`/`email`). Acceptance is a separate flow:
> `POST /ui/groups/{group_id}/invites/{user_id}/respond` with `{ "accept": bool }`.

**PATCH `/ui/groups/{group_id}/members/{user_id}/role`**
(`update_member_role_ui_groups__group_id__members__user_id__role_patch`) — body
`GroupUpdateRoleIn`:
```json
{ "role": "moderator" }
```
→ `200` (untyped body). `422` on validation.
> Corrections: path ends in `/role`; the role enum accepts only `"moderator"` or
> `"member"` (promotion to `admin` is not possible via this endpoint).

**DELETE `/ui/groups/{group_id}/members/{user_id}`**
(`remove_member_ui_groups__group_id__members__user_id__delete`) → **`200`** (not `204`).
> Correction: this endpoint does **not** implement "leave"; there is no `/members/me`.

**POST `/ui/groups/{group_id}/leave`** (`leave_group_ui_groups__group_id__leave_post`) → no
request body, → `200`. This is the canonical "leave group" action.

**Error body** — Every group op declares `422 → HTTPValidationError`, whose `detail` is an
array of `ValidationError` `{ "loc": [...], "msg": "...", "type": "..." }`. Non-validation
failures (`401`/`403`) return a FastAPI `detail` that the web client (`client.ts:
normalizeErrorDetail`) handles in three shapes — mirror these in the AND-027 mapper:
```json
{ "detail": "You are not an admin of this group" }                 // string
{ "detail": [{ "loc": ["body","role"], "msg": "..." , "type":"..."}] } // 422 array
{ "detail": { "code": "role_required", "required_scope": "..." } }  // object → mapped copy
```
> Note: `409 Conflict` and `404` are **not** declared for these ops in the OpenAPI index
> (only `200` and `422`). The prior draft's `409 "Already a member"` / `404 "User not
> found"` mappings are **unverified assumptions** — treat unexpected non-2xx generically.

The read path (FR-1–FR-4) and the mutation path (FR-5/FR-6) are all present in
`/openapi.json`, so OQ-1 is resolved (see §13).

## 6. Data & State Management

- **Room cache (core-data):** `groups` table (`GroupEntity`) keyed by `id` for offline
  list rendering (FR-2). `observeGroups()` emits from Room; `refreshGroups()` performs the
  network fetch then upserts and prunes stale rows in a single transaction. Members are
  **not** persisted across sessions (paged from network; optionally a short in-memory cache
  per group during a session).
- **Members (no Paging):** **Correction —** the members endpoint is unpaginated (verified:
  no `cursor`/`limit` params, body `{ members, count }`). Drop Paging 3 for the roster;
  load the full list into `StateFlow<List<GroupMember>>`. Paging may be reconsidered only if
  the backend later adds cursor params.
- **UiState:** each screen exposes a sealed `*UiState` via `StateFlow`, started with
  `WhileSubscribed(5_000)` and a `Loading` initial value. One-shot effects (snackbars, nav
  pops) flow through `SharedFlow<GroupEvent>` to avoid re-emission on config change.
- **Optimistic state:** roster mutations apply to an in-memory member list overlay; on
  `ApiResult.Error` the overlay reverts and a `GroupEvent.Snackbar` is emitted.
- **DataStore:** no new prefs required for this feature.

## 7. Error Handling & Resilience

- **Timeouts:** rely on the shared OkHttp client's ~20s call timeout (AND-027). No
  per-call override.
- **Retry policy:** only idempotent GETs (`listGroups`, `getGroup`, `listMembers`) use the
  shared bounded exponential backoff (max 2–3 attempts). Mutations (POST/PATCH/DELETE) are
  **never** auto-retried; the user re-triggers manually.
- **401 handling:** delegated to the AND-027 refresh-once interceptor; no feature-level
  logic.
- **Offline:** list renders from Room with a "showing cached data" banner; detail/members
  show an error state with retry if no cache.
- **Mutation failures:** map `ApiResult.Error` to user copy — `403` → permission snackbar +
  rollback (also map structured `detail.code` like `role_required` to friendly copy, as the
  web client does); `422` → surface the first `ValidationError.msg` field-level in the
  invite sheet; generic/network → "Couldn't reach the server. Try again."
  **Correction:** `409`/`404` are **not** declared for these endpoints, so do not special-
  case "Already a member"/"User not found"; if the server ever returns them, fall through to
  the generic mapping rather than asserting specific copy.
- **No crash on contract drift:** unknown `role` strings decode to `GroupRole.MEMBER`
  (least-privilege default) via a Moshi fallback adapter, so an unexpected role never throws.

## 8. Security & Privacy

- **Transport:** dev backend is plaintext HTTP; cleartext is permitted only for the dev
  host via the existing network-security-config (owned by AND-027 / build config), not
  globally. No new cleartext exceptions added here.
- **CSRF:** all mutations send `X-CSRF-Token` from the `ui_csrf` cookie via the shared
  interceptor; the feature adds no manual header handling.
- **Least privilege in UI:** management controls are gated on `myRole == ADMIN`
  (**correction:** there is no `OWNER` role; the owner is `admin_user_id` and always has
  `my_role == admin`). The unknown-role fallback to `MEMBER` (§7) ensures controls hide
  rather than appear on ambiguous data. Server remains the source of truth (403 enforced).
- **PII:** member `display_name`s are personal data — not logged (see §10), not written to
  disk beyond the in-session member cache, and excluded from crash payloads. (Note:
  `GroupMember` carries no `username`/`avatar_url`, so those are not handled here.)
- **No secrets** are introduced by this module.

## 9. Accessibility & i18n

- All interactive elements (rows, role badges, add/remove/leave buttons, bottom sheet
  fields) have `contentDescription` / `semantics`; touch targets ≥ 48dp.
- Role badges convey role by text label, not color alone (color-blind safe).
- Destructive actions (Remove member, Leave group) require a confirmation dialog with clear
  labels and a `semantics { role = Role.Button }` on actions.
- All user-facing strings live in `feature-groups/src/main/res/values/strings.xml` (no
  hardcoded literals); member counts use `plurals`. Layouts are RTL-safe and respect dynamic
  font scaling (no fixed-height text rows).
- TalkBack: roster announces "{name}, {role}"; after a mutation, a `liveRegion` announces
  the result ("Removed {name}").

## 10. Telemetry & Logging

- **Events** (via the app analytics interface, no PII): `groups_list_viewed`,
  `group_detail_viewed{role}`, `group_members_viewed{count_bucket}`,
  `group_member_added{result}`, `group_role_changed{from,to}`, `group_member_removed`,
  `group_left`, `group_mutation_error{op, http_status}`. Only IDs are hashed/bucketed;
  never raw usernames.
- **Logging:** Timber at `DEBUG` for request lifecycle and error mapping; production builds
  strip verbose logs. Log group/user **ids** only, never names or avatar URLs.
- **No analytics SDK changes**; reuse the existing tracker abstraction.

## 11. Testing Strategy

- **Unit (JVM, core-testing):**
  - `GroupsRepositoryTest` with MockWebServer covering each endpoint: success, `403`,
    `422` (HTTPValidationError array), malformed `detail`, network timeout, and unknown-role
    decoding. (`404`/`409` are not contractually declared — assert generic handling if
    simulated, not specific copy.)
  - ViewModel tests using `Turbine` + `MainDispatcherRule`: state transitions
    (Loading→Content/Empty/Error), optimistic apply + rollback on remove/role-change,
    permission-denied snackbar event, leave → nav event.
- **Moshi:** golden-JSON tests for `Group` (UserGroup shape: `group_id`,
  `cover_image_url`, `admin_user_id`, `visibility`, `status`), `GroupMember` (`user_id`,
  `role`, `status`, `display_name`), the `GroupInviteIn`/`GroupUpdateRoleIn` request bodies,
  and the role fallback adapter (unknown role → MEMBER). (Correction: no `PagingSource`/
  `next_cursor` test — the roster is unpaginated.)
- **Compose UI tests:** `GroupsListScreen` renders rows/empty/error; `GroupMembersScreen`
  shows management controls for ADMIN and hides them for MEMBER and MODERATOR; confirmation
  dialogs on destructive actions; snackbar on simulated 403.
- **Acceptance mapping:** "renders" verified by list/detail/members UI tests; "manages"
  verified by add/role-change/remove/leave repository + UI tests.
- **CI:** module unit + Compose tests run on the `android-port` CI matrix; no instrumented
  device-farm dependency required for merge.

## 12. Dependencies & Sequencing

- **Depends on AND-027** (auth/session endpoints): cookie jar, CSRF header injection,
  401-refresh interceptor, `ApiResult<T>`, and the FastAPI `detail` mapper. This feature
  cannot perform authenticated requests without it.
- **Soft dependency:** the app navigation host and bottom-nav/tab scaffold must expose a
  Groups entry point; if not yet present, gate behind a feature flag and land the module
  self-contained.
- **Blocks:** none recorded in the backlog. Any future "group content/feed" or
  "group invitations via push" tickets would build on this module.
- **Sequencing:** (1) models + `GroupsApi` + repository (read path) → (2) list/detail/
  members UI → (3) mutations + role gating → (4) telemetry + polish.

## 13. Risks & Open Questions

- **OQ-1 (endpoint surface) — RESOLVED.** Verified against the OpenAPI index and
  `src/api/endpoints/groups.ts`: invite is `POST /ui/groups/{id}/invite` with
  `GroupInviteIn { user_id }` (by **user_id**, not username/email); role change is
  `PATCH /ui/groups/{id}/members/{user_id}/role` (`moderator`|`member` only); remove is
  `DELETE /ui/groups/{id}/members/{user_id}` (→200); leave is `POST /ui/groups/{id}/leave`;
  members are **not paginated** (`{ members, count }`). §5 has been corrected accordingly.
- **OQ-2 (leave vs owner) — RESOLVED.** There is no `/members/me`; leaving is
  `POST /ui/groups/{id}/leave`. The owner's destructive path is `DELETE /ui/groups/{id}`
  (dissolve, `dissolve_group_...`); there is no ownership-transfer endpoint. Dissolve stays
  out of scope; UI hides "Leave" when the viewer is the owner (`user_id == admin_user_id`).
- **OQ-3 (group creation) — RESOLVED (deferred).** `POST /ui/groups` (`CreateGroupIn`) and
  `PATCH /ui/groups/{id}` (`UpdateGroupIn`) **do** exist, plus
  `GET /ui/groups/discover`. They are outside the acceptance bar and remain deferred; tracked
  here for the follow-up "group creation/management" ticket.
- **OQ-4 (avatars) — NEW.** `GroupMember` carries no avatar/username; rendering per-member
  avatars would require a separate user-profile lookup (out of scope). Roster shows
  `display_name` + role only unless a profile endpoint is wired in a follow-up.
- **OQ-5 (error codes) — NEW.** Only `200`/`422` are declared for the group ops; `403`
  payloads follow the generic FastAPI `detail` shapes but `404`/`409` are not contractually
  guaranteed. Treat them generically (see §7).
- **Risk — unreliable dev host:** flaky `18.222.237.167:8000` may make mutation UX feel
  broken; mitigated by clear retry copy and offline-first reads. Do not auto-retry
  mutations.
- **Risk — role drift:** server roles beyond admin/moderator/member would mis-gate UI; mitigated
  by the `MEMBER` fallback adapter, but new roles should be added explicitly.

## 14. Acceptance Criteria

AC-1 Opening Groups shows the user's groups from `GET /ui/groups` with name, member count,
and role badge; tapping a row opens detail. (FR-1)

AC-2 Empty, loading, offline-with-cache, and error states each render distinctly;
pull-to-refresh re-fetches. (FR-2)

AC-3 Group detail (`GET /ui/groups/{id}`) and member roster
(`GET /ui/groups/{id}/members`) render correctly. The roster is a single unpaginated fetch
(`{ members, count }`); the corrected `Group`/`GroupMember` fields decode without error.
(FR-3, FR-4)

AC-4 An ADMIN viewer can invite a member (`POST .../invite` with `user_id`), change a
member's role to `moderator`/`member` (`PATCH .../members/{id}/role`), and remove a member
(`DELETE .../members/{id}` → 200), with the roster reflecting the change after server
confirmation/optimistic update. (FR-5)

AC-5 A MEMBER or MODERATOR viewer sees a read-only roster with no management controls.
(FR-5)

AC-6 A non-owner can leave a group (`POST /ui/groups/{id}/leave` → 200) and is returned to
the list with the group removed from cache. (FR-6)

AC-7 A `403` on any mutation reverts optimistic state and shows a permission snackbar
without crashing. (FR-8)

AC-8 Unknown/unexpected role values decode safely to MEMBER and never throw. (§7)

## 15. Definition of Done

- `feature-groups` module builds on Kotlin 2.0.21 / AGP 8.7.3 / Gradle 8.9, minSdk 24 /
  compileSdk 35, JDK 17, with Hilt (KSP) wiring and no new lint/detekt regressions.
- All three screens implemented as stateless Composables with `@Preview` per UiState and
  wired into the app Navigation-Compose graph behind the Groups entry point.
- `GroupsRepository` returns `ApiResult<T>` for every call and reuses the AND-027 network
  stack (cookies, CSRF, 401-refresh, `detail` mapping) with no duplicated auth logic.
- Read path is offline-first via Room; mutations are role-gated in UI and resilient to 403.
- Unit, Moshi golden, Paging, and Compose UI tests (§11) pass in CI; coverage of repository
  + ViewModels meets the project threshold.
- All strings externalized; accessibility checks (TalkBack labels, 48dp targets, confirm
  dialogs) verified.
- Telemetry events emit with no PII; verbose logging stripped from release.
- Open questions OQ-1/OQ-2 resolved against `/openapi.json` (or explicitly deferred with
  tickets) before merge; PR opened against `android-port` and reviewed.

## 16. Citations & Assumption Audit

Each key technical claim with VERDICT and SOURCE. OpenAPI = the operation in
`reference/openapi.index.txt` / schema in `reference/openapi.pretty.json`; FE = file under
`reference/src/`.

1. **List groups is `GET /ui/groups` returning `{ groups: [...] }`.** Verified.
   Source: OpenAPI `GET /ui/groups` (`op=list_my_groups_ui_groups_get`); FE
   `src/api/endpoints/groups.ts: listMyGroups` (`api.get<{ groups: UserGroup[] }>`).

2. **Group detail is `GET /ui/groups/{group_id}`.** Verified.
   Source: OpenAPI `GET /ui/groups/{group_id}` (`op=get_group_ui_groups__group_id__get`);
   FE `src/api/endpoints/groups.ts: getGroup`.

3. **`Group`/`UserGroup` key is `group_id` (not `id`); image is `cover_image_url` (not
   `avatar_url`); includes `visibility`, `status`, `admin_user_id`, `topic`, `created_at`,
   `updated_at`; `my_role` optional.** Corrected (draft used `id`/`avatar_url` and omitted
   the rest). Source: FE `src/api/types.ts: UserGroup`.

4. **Roles are `admin | moderator | member`; there is NO `owner` role; the owner is
   `admin_user_id`.** Corrected (draft used `owner/admin/member`). Source: FE
   `src/api/types.ts: UserGroup.my_role` and `GroupMember.role`; OpenAPI schema
   `GroupUpdateRoleIn.role` enum.

5. **Members endpoint is `GET /ui/groups/{group_id}/members`, UNPAGINATED, body
   `{ members: [...], count: int }`.** Corrected (draft assumed `cursor`/`limit` +
   `next_cursor`). Source: OpenAPI `GET /ui/groups/{group_id}/members`
   (`op=list_members_...`, `params=group_id,user_sub,X-SESSION-ID,X-IMPERSONATION-TOKEN`
   only); FE `src/api/endpoints/groups.ts: listGroupMembers`
   (`api.get<{ members: GroupMember[]; count: number }>`).

6. **`GroupMember` fields are `user_id`, `role`, `status`, `display_name`, `joined_at?`,
   `promoted_at?`; NO `username`, NO `avatar_url`.** Corrected. Source:
   FE `src/api/types.ts: GroupMember`.

7. **Invite member is `POST /ui/groups/{group_id}/invite` with `GroupInviteIn { user_id }`;
   there is NO `POST /ui/groups/{id}/members`; invite is by `user_id`, not username/email,
   and carries no role.** Corrected. Source: OpenAPI `POST /ui/groups/{group_id}/invite`
   (`op=invite_to_group_...`, `req=GroupInviteIn`); schema `GroupInviteIn { user_id: str }`;
   FE `src/api/endpoints/groups.ts: inviteToGroup` (`{ user_id: userId }`).

8. **Role change is `PATCH /ui/groups/{group_id}/members/{user_id}/role` with
   `GroupUpdateRoleIn { role }`, enum = `moderator | member` only.** Corrected (draft used
   `PATCH .../members/{userId}` with `role: "admin"`). Source: OpenAPI
   `PATCH /ui/groups/{group_id}/members/{user_id}/role` (`op=update_member_role_...`,
   `req=GroupUpdateRoleIn`); schema `GroupUpdateRoleIn.role` enum `["moderator","member"]`;
   FE `src/api/endpoints/groups.ts: updateMemberRole` (path ends `/role`).

9. **Remove member is `DELETE /ui/groups/{group_id}/members/{user_id}` returning `200`
   (not `204`).** Corrected. Source: OpenAPI `DELETE /ui/groups/{group_id}/members/{user_id}`
   (`op=remove_member_...`, `resp=200:;422:`); FE `groups.ts: removeMember`.

10. **Leave group is `POST /ui/groups/{group_id}/leave` (no body, →200); there is NO
    `DELETE /members/me`.** Corrected. Source: OpenAPI `POST /ui/groups/{group_id}/leave`
    (`op=leave_group_...`); FE `src/api/endpoints/groups.ts: leaveGroup` (`api.post`).

11. **Owner's destructive path is `DELETE /ui/groups/{group_id}` (dissolve); no transfer
    endpoint.** Verified (deferred/out of scope). Source: OpenAPI
    `DELETE /ui/groups/{group_id}` (`op=dissolve_group_...`); FE `groups.ts: deleteGroup`.

12. **Create/update group exist (`POST /ui/groups` `CreateGroupIn`,
    `PATCH /ui/groups/{id}` `UpdateGroupIn`) plus `GET /ui/groups/discover`.** Verified
    (out of scope). Source: OpenAPI `POST /ui/groups` (`op=create_group_...`,
    `req=CreateGroupIn`), `PATCH /ui/groups/{group_id}` (`req=UpdateGroupIn`),
    `GET /ui/groups/discover`; FE `groups.ts: createGroup`, `updateGroup`, `discoverGroups`.

13. **Only `200` and `422`(`HTTPValidationError`) are declared for the group ops; `404`/`409`
    are NOT contractual.** Corrected (draft asserted `409 "Already a member"` /
    `404 "User not found"`). Source: OpenAPI `resp=` columns for all `/ui/groups/*` ops
    (each `200:...;422:HTTPValidationError`); schema `HTTPValidationError.detail =
    ValidationError[]`.

14. **Auth/CSRF transport: cookie session + `Authorization: Bearer` + `X-CSRF-Token` from
    the `ui_csrf` cookie; single-shot 401→`POST /ui/session/refresh`→retry; `detail`
    normalized for string/array/object shapes.** Verified (inherited from AND-027). Source:
    FE `src/api/client.ts` (`getCookie("ui_csrf")` → `X-CSRF-Token`; `refreshSession()` →
    `/ui/session/refresh`; `normalizeErrorDetail`; 403 toast unless `silent403`).

15. **`/ui/*` ops additionally accept `X-SESSION-ID` / `X-IMPERSONATION-TOKEN` server-side.**
    Verified (informational; Android uses cookie+bearer). Source: OpenAPI `params=` columns
    on every `/ui/groups/*` op.

16. **Compose / Navigation-Compose with typed routes, Hilt + KSP, Moshi codegen, Coil,
    Room, minSdk 24 / compileSdk 35.** Unverified-assumption (framework choice, not derivable
    from backend/FE). Framework ref: Navigation-Compose type-safe routes —
    https://developer.android.com/guide/navigation/design/type-safety ; Hilt —
    https://developer.android.com/training/dependency-injection/hilt-android .

17. **Optimistic-update-with-rollback UX and offline-first Room caching of the groups
    list.** Unverified-assumption (client UX design, no backend/FE contract). Framework ref:
    offline-first guidance — https://developer.android.com/topic/architecture/data-layer/offline-first .

### Corrections made

- Group key `id` → `group_id`; `avatar_url` → `cover_image_url`; added
  `visibility/status/admin_user_id/topic/created_at/updated_at`; `my_role` made optional
  (claims 3).
- Role enum `owner/admin/member` → `admin/moderator/member`; UI gating changed from
  `{OWNER, ADMIN}` to `ADMIN`; owner identified by `admin_user_id` (claims 4, §3, §8).
- `GroupMember` dropped non-existent `username`/`avatar_url`; added `status`/`joined_at`/
  `promoted_at` (claim 6).
- Members roster de-paginated: removed `cursor`/`limit`/`next_cursor`/Paging 3; body is
  `{ members, count }`; ViewModel/repo now expose a plain list (claims 5, §4, §6, §11).
- Invite corrected to `POST .../invite` `{ user_id }` (was non-existent
  `POST .../members` `{ username, role }`) (claim 7).
- Role-change path corrected to `.../members/{user_id}/role`; role enum restricted to
  `moderator|member` (claim 8).
- Remove member response `204` → `200`; leave corrected to `POST .../leave` (was
  `DELETE /members/me`) (claims 9, 10).
- Removed `409`/`404` special-case error copy; only `200`/`422` are contractual (claim 13).
- OQ-1/OQ-2 marked RESOLVED; OQ-3 resolved-deferred; added OQ-4 (avatars), OQ-5 (error
  codes).

### Open assumptions

- Android framework stack (Compose, Navigation type-safe routes, Hilt/KSP, Moshi, Coil,
  Room, Paging-removal, SDK levels) — a client design choice; not verifiable from backend
  or web sources (claims 16, 17). Carried as design decisions, not contract.
- Optimistic-with-rollback and offline-first list caching — client UX; the web reference
  does neither (it is request/response with toasts), so these are intentional Android-side
  enhancements, unverifiable against the contract.
- Exact `403` body for group ops — `client.ts` proves the *shape family* (string / array /
  `{code,...}` object) but the backend's specific group-permission `detail` strings/codes
  are not enumerated in the OpenAPI spec; mapper must handle generically.

## 17. Test Plan

Targets: **JVM/Robolectric** (local, no device), **emulator `test35`** (API 35, x86_64),
**physical A15** (SM-A156U, API 34, arm64-v8a). For this ticket (HTTP + Compose UI, no
camera/biometric/WebRTC/push/Telecom hardware), most cases run on JVM or the emulator. The
physical device is required only for genuine hardware/ABI/API-level signal (TC-AND-355-13).

- **TC-AND-355-01** — Type: contract/MockWebServer (JVM). Target: JVM/Robolectric.
  Preconditions: MockWebServer enqueues `200 { "groups": [ <UserGroup with group_id,
  cover_image_url, my_role:"admin"> ] }`. Steps: call `repo.refreshGroups()` then collect
  `observeGroups()`. Expected: one `Group` decoded with `id==group_id`,
  `coverImageUrl==cover_image_url`, `myRole==ADMIN`; row upserted into Room. Traces: AC-1.

- **TC-AND-355-02** — Type: Compose-UI. Target: emulator `test35`. Preconditions: VM seeded
  with two groups (one `admin`, one `member`). Steps: render `GroupsListScreen`; assert name,
  member-count plural, and role badge text; tap row 1. Expected: rows render; role badge
  conveys role by **text** (not color); tap emits navigate-to-Detail with the correct
  `group_id`. Traces: AC-1.

- **TC-AND-355-03** — Type: Compose-UI. Target: emulator `test35`. Preconditions: VM states
  driven to Empty, Loading, Error(hasCache=true), Error(hasCache=false). Steps: render each;
  trigger pull-to-refresh in Content. Expected: distinct empty illustration, skeleton,
  "showing cached data" banner + list, and error+retry respectively; pull-to-refresh calls
  `refresh()`. Traces: AC-2.

- **TC-AND-355-04** — Type: contract/MockWebServer (JVM). Target: JVM/Robolectric.
  Preconditions: enqueue `200` for `GET /ui/groups/{id}` and `200 { "members":[...],
  "count":N }` for `GET .../members`. Steps: call `getGroup` then `getMembers`. Expected:
  `Group` and `List<GroupMember>` (size N) decode; request to `.../members` carries **no**
  `cursor`/`limit` query params; `count` matches list size. Traces: AC-3.

- **TC-AND-355-05** — Type: unit (JVM). Target: JVM. Preconditions: Moshi adapter for
  `GroupMember`. Steps: decode a member JSON whose `role` is an unknown string
  (e.g. `"superadmin"`). Expected: decodes to `role==MEMBER` (least-privilege fallback), no
  exception thrown. Traces: AC-8.

- **TC-AND-355-06** — Type: Compose-UI. Target: emulator `test35`. Preconditions: roster
  loaded; viewerRole=ADMIN. Steps: render `GroupMembersScreen`; locate invite/remove/change-
  role affordances. Expected: management controls visible; "Add member" opens `AddMemberSheet`
  taking a `user_id`. Traces: AC-4, AC-5.

- **TC-AND-355-07** — Type: Compose-UI. Target: emulator `test35`. Preconditions: roster
  loaded; viewerRole=MEMBER (repeat parametrized with MODERATOR). Steps: render
  `GroupMembersScreen`. Expected: NO invite/remove/change-role controls rendered; roster is
  read-only. Traces: AC-5.

- **TC-AND-355-08** — Type: contract/MockWebServer (JVM). Target: JVM. Preconditions:
  enqueue `200` for `POST /ui/groups/{id}/invite`. Steps: `repo.inviteMember(gid, "u_bob")`.
  Expected: request method=POST, path ends `/invite`, body == `{"user_id":"u_bob"}` (no
  `role`/`username`); `ApiResult.Success`. Traces: AC-4.

- **TC-AND-355-09** — Type: contract/MockWebServer (JVM). Target: JVM. Preconditions:
  enqueue `200` for the role PATCH. Steps: `repo.updateRole(gid, "u_x", MODERATOR)`.
  Expected: method=PATCH, path == `.../members/u_x/role`, body == `{"role":"moderator"}`;
  Success. Negative sub-case: attempting `updateRole(..., ADMIN)` is rejected client-side
  (enum only serializes moderator|member). Traces: AC-4.

- **TC-AND-355-10** — Type: integration (ViewModel + MockWebServer, JVM/Turbine). Target:
  JVM. Preconditions: roster has member `u_x`; enqueue `DELETE .../members/u_x` → `200`.
  Steps: `vm.remove("u_x")`. Expected: roster optimistically drops `u_x`, request fires
  (DELETE, →200 not 204), state stays removed; on a second run enqueueing a network error,
  roster rolls back and a `GroupEvent.Snackbar` is emitted. Traces: AC-4, AC-7.

- **TC-AND-355-11** — Type: integration (ViewModel, JVM/Turbine). Target: JVM.
  Preconditions: enqueue `403 { "detail": { "code": "role_required", "required_scope":
  "..." } }` for a role change. Steps: `vm.changeRole("u_x", MODERATOR)`. Expected:
  optimistic change reverts; snackbar shows mapped permission copy (mirrors `client.ts`
  `mapAuthorizationError`); no crash. Repeat with `403 { "detail": "You are not an admin of
  this group" }` (string shape) → snackbar shows that string. Traces: AC-7.

- **TC-AND-355-12** — Type: integration (ViewModel + MockWebServer, JVM/Turbine). Target:
  JVM. Preconditions: detail loaded, viewer is non-owner; enqueue `POST .../leave` → `200`.
  Steps: `vm.leave()`. Expected: request method=POST path ends `/leave`; on success emits a
  nav-pop `GroupEvent` and the group is pruned from Room cache. Owner sub-case: when
  `viewer.user_id == group.admin_user_id`, the "Leave" control is not rendered. Traces: AC-6.

- **TC-AND-355-13** — Type: instrumented/e2e. Target: **physical A15 (SM-A156U, API 34,
  arm64-v8a) — MUST run on device**, with emulator `test35` as the API-35/x86_64 counterpart.
  Preconditions: app installed; backend reachable (or a local stub). Steps: open Groups,
  open a group, open Members, perform invite + role change + remove + leave end-to-end.
  Expected: identical behavior across arm64-v8a/API-34 and x86_64/API-35 (no ABI/API-level
  decode or Moshi codegen regressions; cleartext HTTP to the dev host honored only via the
  AND-027 network-security-config). Rationale for physical device: catch arm64-vs-x86 and
  API-34-vs-35 differences that the emulator alone cannot. Traces: AC-1, AC-3, AC-4, AC-6.

- **TC-AND-355-14** — Type: Compose-UI accessibility. Target: emulator `test35`.
  Preconditions: roster + destructive actions available (ADMIN). Steps: enable the a11y test
  harness; inspect semantics for rows, role badges, invite/remove/leave buttons; trigger a
  remove. Expected: every interactive element has `contentDescription`/semantics, touch
  targets ≥48dp, destructive actions require a confirm dialog, role conveyed by text, and a
  `liveRegion` announces "Removed {display_name}" after the mutation. Traces: AC-4, AC-5.

- **TC-AND-355-15** — Type: integration (offline/flaky-host, JVM + Robolectric). Target:
  JVM/Robolectric. Preconditions: Room seeded with cached groups; MockWebServer set to fail
  the connection (simulating the unreliable `18.222.237.167:8000` dev host). Steps: open the
  list offline, then attempt a mutation (invite). Expected: list renders from cache with the
  "showing cached data" banner; the mutation surfaces the generic "Couldn't reach the
  server. Try again." copy and is **not** auto-retried (per §7); no crash. Traces: AC-2,
  AC-7.

### Coverage matrix

| Acceptance criterion | Covered by |
| --- | --- |
| AC-1 (list renders, tap → detail) | TC-01, TC-02, TC-13 |
| AC-2 (empty/loading/offline-cache/error + pull-to-refresh) | TC-03, TC-15 |
| AC-3 (detail + roster render; unpaginated) | TC-04, TC-13 |
| AC-4 (admin invite/role-change/remove) | TC-06, TC-08, TC-09, TC-10, TC-13, TC-14 |
| AC-5 (member/moderator read-only roster) | TC-06, TC-07, TC-14 |
| AC-6 (leave → back to list, cache pruned) | TC-12, TC-13 |
| AC-7 (403 reverts optimistic state, snackbar, no crash) | TC-10, TC-11, TC-15 |
| AC-8 (unknown role decodes to MEMBER, no throw) | TC-05 |
