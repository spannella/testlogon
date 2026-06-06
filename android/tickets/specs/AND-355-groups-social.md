---
id: AND-355
title: Groups (social)
milestone: M7
epic: E46
priority: P2
size: M
status: draft
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
(`GET /ui/groups`). Each row shows group name, member count, the viewer's role badge
(`owner` / `admin` / `member`), and an avatar (Coil). Tapping a row navigates to detail.

FR-2 **Empty / offline / error states.** Distinct UI for: no groups (empty illustration +
copy), network failure (retry affordance + last-cached list if present), and loading
(skeleton/spinner). Pull-to-refresh re-fetches.

FR-3 **Group detail.** `GET /ui/groups/{groupId}` renders name, description, member count,
and the viewer's role. A "Members" entry navigates to the roster. A "Leave group" action
is shown to non-owners (owners must transfer/delete; out of scope → see §13).

FR-4 **Member roster.** `GET /ui/groups/{groupId}/members` lists members with name,
avatar, and role. Roster supports Paging 3 if the endpoint is paginated (cursor/page);
otherwise a single fetch.

FR-5 **Role-gated management.** When the viewer's role is `owner` or `admin`:
  - **Add/invite** a member (`POST /ui/groups/{groupId}/members`).
  - **Change role** of a member (`PATCH /ui/groups/{groupId}/members/{userId}`).
  - **Remove** a member (`DELETE /ui/groups/{groupId}/members/{userId}`).
  Members with role `member` see a read-only roster (no management controls rendered).

FR-6 **Leave group.** Any non-owner member can leave
(`DELETE /ui/groups/{groupId}/members/me` or self-targeted delete); on success, pop back to
the list and remove the group from cache.

FR-7 **Optimistic-with-rollback mutations.** Role change and remove update the roster
immediately and roll back on failure with a snackbar; add/invite is pessimistic (waits for
server confirmation) because it returns a server-generated membership record.

FR-8 **Permission denial.** A 403 from any mutation surfaces a non-fatal snackbar ("You
don't have permission to do that") and reverts optimistic state. The UI never crashes on a
server-side permission mismatch.

## 4. Technical Design

New Gradle module `feature-groups` (library, Compose enabled, Hilt + KSP). Layering and
key types:

```kotlin
// core-model
@JsonClass(generateAdapter = true)
data class Group(
    val id: String,
    val name: String,
    val description: String? = null,
    @Json(name = "member_count") val memberCount: Int = 0,
    @Json(name = "my_role") val myRole: GroupRole = GroupRole.MEMBER,
    @Json(name = "avatar_url") val avatarUrl: String? = null,
)

enum class GroupRole { @Json(name = "owner") OWNER, @Json(name = "admin") ADMIN, @Json(name = "member") MEMBER }

@JsonClass(generateAdapter = true)
data class GroupMember(
    @Json(name = "user_id") val userId: String,
    val username: String,
    @Json(name = "display_name") val displayName: String? = null,
    @Json(name = "avatar_url") val avatarUrl: String? = null,
    val role: GroupRole,
)
```

```kotlin
// feature-groups (or core-network) — Retrofit service
interface GroupsApi {
    @GET("ui/groups")
    suspend fun listGroups(): Response<GroupListResponse>

    @GET("ui/groups/{groupId}")
    suspend fun getGroup(@Path("groupId") groupId: String): Response<Group>

    @GET("ui/groups/{groupId}/members")
    suspend fun listMembers(
        @Path("groupId") groupId: String,
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int = 50,
    ): Response<GroupMembersResponse>

    @POST("ui/groups/{groupId}/members")
    suspend fun addMember(
        @Path("groupId") groupId: String,
        @Body body: AddMemberRequest,
    ): Response<GroupMember>

    @PATCH("ui/groups/{groupId}/members/{userId}")
    suspend fun updateMemberRole(
        @Path("groupId") groupId: String,
        @Path("userId") userId: String,
        @Body body: UpdateRoleRequest,
    ): Response<GroupMember>

    @DELETE("ui/groups/{groupId}/members/{userId}")
    suspend fun removeMember(
        @Path("groupId") groupId: String,
        @Path("userId") userId: String,
    ): Response<Unit>
}
```

Repository wraps every call in `ApiResult<T>` (from AND-027) and centralizes mapping +
cache writes:

```kotlin
interface GroupsRepository {
    fun observeGroups(): Flow<List<Group>>              // Room-backed, offline-first
    suspend fun refreshGroups(): ApiResult<Unit>
    suspend fun getGroup(groupId: String): ApiResult<Group>
    fun membersPager(groupId: String): Flow<PagingData<GroupMember>>
    suspend fun addMember(groupId: String, identifier: String, role: GroupRole): ApiResult<GroupMember>
    suspend fun updateRole(groupId: String, userId: String, role: GroupRole): ApiResult<GroupMember>
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
    val members: Flow<PagingData<GroupMember>>
    val viewerRole: StateFlow<GroupRole>
    fun changeRole(userId: String, role: GroupRole)
    fun remove(userId: String)
    fun add(identifier: String, role: GroupRole)
    val events: SharedFlow<GroupEvent>          // one-shot snackbars / nav
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

**GET `/ui/groups`** → `200`
```json
{ "groups": [
  { "id": "g_123", "name": "Platform Team", "description": "Core infra",
    "member_count": 8, "my_role": "admin", "avatar_url": "https://.../g.png" }
] }
```

**GET `/ui/groups/{groupId}`** → `200` → a single `Group` object (shape as above). `404`
if not a member / not found.

**GET `/ui/groups/{groupId}/members?cursor=&limit=50`** → `200`
```json
{ "members": [
    { "user_id": "u_1", "username": "alice", "display_name": "Alice",
      "avatar_url": null, "role": "owner" }
  ],
  "next_cursor": "eyJwayI6..." }
```

**POST `/ui/groups/{groupId}/members`** — body `AddMemberRequest`:
```json
{ "username": "bob", "role": "member" }
```
→ `201` with the created `GroupMember`. `409` if already a member; `403` if not authorized;
`404` if target user unknown.

**PATCH `/ui/groups/{groupId}/members/{userId}`** — body `UpdateRoleRequest`:
```json
{ "role": "admin" }
```
→ `200` with updated `GroupMember`. `403` if viewer lacks permission.

**DELETE `/ui/groups/{groupId}/members/{userId}`** → `204`. Self-targeted delete (or
`/members/me`) implements "leave." `403` if not permitted.

**Error body (FastAPI `detail`)** — mapped by the shared mapper from AND-027:
```json
{ "detail": "You are not an admin of this group" }          // string
{ "detail": [{ "loc": ["body","role"], "msg": "invalid role" }] }  // 422 array
{ "detail": { "code": "not_member", "message": "..." } }    // object
```

If `/ui/groups/*` mutation endpoints are absent in `/openapi.json`, see §13 OQ-1; the
read-only render path (FR-1–FR-4) must still ship.

## 6. Data & State Management

- **Room cache (core-data):** `groups` table (`GroupEntity`) keyed by `id` for offline
  list rendering (FR-2). `observeGroups()` emits from Room; `refreshGroups()` performs the
  network fetch then upserts and prunes stale rows in a single transaction. Members are
  **not** persisted across sessions (paged from network; optionally a short in-memory cache
  per group during a session).
- **Paging 3:** `membersPager` uses a `PagingSource` driven by `next_cursor`; page size 50.
  If the endpoint is unpaginated, fall back to a single-page source over the full list.
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
  rollback; `409` → "Already a member"; `404` → "User not found"; `422` → field-level
  message in `AddMemberSheet`; generic/network → "Couldn't reach the server. Try again."
- **No crash on contract drift:** unknown `role` strings decode to `GroupRole.MEMBER`
  (least-privilege default) via a Moshi fallback adapter, so an unexpected role never throws.

## 8. Security & Privacy

- **Transport:** dev backend is plaintext HTTP; cleartext is permitted only for the dev
  host via the existing network-security-config (owned by AND-027 / build config), not
  globally. No new cleartext exceptions added here.
- **CSRF:** all mutations send `X-CSRF-Token` from the `ui_csrf` cookie via the shared
  interceptor; the feature adds no manual header handling.
- **Least privilege in UI:** management controls are gated on `myRole ∈ {OWNER, ADMIN}`;
  the unknown-role fallback to `MEMBER` (§7) ensures controls hide rather than appear on
  ambiguous data. Server remains the source of truth (403 enforced).
- **PII:** member usernames/display names/avatars are personal data — not logged (see §10),
  not written to disk beyond the in-session member cache, and excluded from crash payloads.
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
    `404`, `409`, `422`, malformed `detail`, network timeout, and unknown-role decoding.
  - ViewModel tests using `Turbine` + `MainDispatcherRule`: state transitions
    (Loading→Content/Empty/Error), optimistic apply + rollback on remove/role-change,
    permission-denied snackbar event, leave → nav event.
- **Paging:** `PagingSource` test for cursor advance and `next_cursor == null` end of list.
- **Moshi:** golden-JSON tests for `Group`, `GroupMember`, requests, and the role fallback
  adapter.
- **Compose UI tests:** `GroupsListScreen` renders rows/empty/error; `GroupMembersScreen`
  shows management controls for ADMIN and hides them for MEMBER; confirmation dialogs on
  destructive actions; snackbar on simulated 403.
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

- **OQ-1 (endpoint surface):** The backlog only names `/ui/groups/*` generically. Confirm
  against `/openapi.json` and `frontend/src/api/endpoints/groups.ts` the exact paths/verbs
  for add/role-change/remove/leave, the member-add identifier (username vs user_id vs
  email), and whether members are paginated. JSON in §5 is the working assumption.
- **OQ-2 (leave vs owner):** Does the API support `/members/me` for leaving, and what is the
  owner's path (transfer ownership / delete group)? Owner self-removal is out of scope
  pending an endpoint; UI hides "Leave" for owners.
- **OQ-3 (group creation):** Is creating a group in scope of `/ui/groups`? Not in the
  acceptance bar; defer unless `POST /ui/groups` exists and product requests it.
- **Risk — unreliable dev host:** flaky `18.222.237.167:8000` may make mutation UX feel
  broken; mitigated by clear retry copy and offline-first reads. Do not auto-retry
  mutations.
- **Risk — role drift:** server roles beyond owner/admin/member would mis-gate UI; mitigated
  by the `MEMBER` fallback adapter, but new roles should be added explicitly.

## 14. Acceptance Criteria

AC-1 Opening Groups shows the user's groups from `GET /ui/groups` with name, member count,
and role badge; tapping a row opens detail. (FR-1)

AC-2 Empty, loading, offline-with-cache, and error states each render distinctly;
pull-to-refresh re-fetches. (FR-2)

AC-3 Group detail (`GET /ui/groups/{id}`) and member roster
(`GET /ui/groups/{id}/members`) render correctly, including pagination if the endpoint is
paged. (FR-3, FR-4)

AC-4 An OWNER/ADMIN viewer can add a member, change a member's role, and remove a member,
with the roster reflecting the change after server confirmation/optimistic update. (FR-5)

AC-5 A MEMBER viewer sees a read-only roster with no management controls. (FR-5)

AC-6 A non-owner can leave a group and is returned to the list with the group removed from
cache. (FR-6)

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
