---
id: AND-353
title: Orgs API + members/roles
milestone: M7
epic: E46
priority: P1
size: M
status: draft
depends_on: [AND-027]
blocks: []
---

# AND-353 — Orgs API + members/roles

## 1. Overview & Goal

This ticket delivers the end-to-end **organizations** capability for the
TestLogon Android client: a typed Retrofit service for the `/ui/orgs/*` surface,
the domain models and repository that wrap it, the ViewModel(s) that expose org,
member, and role state, and the Compose screens to **list members, invite new
members, and change a member's role**. The backlog scope is verbatim:
*`/ui/orgs/*` members/invite/role.* The single acceptance bullet is: *Org
members + roles manage (tested).*

An organization is a tenant grouping of users. A signed-in principal may belong
to one or more orgs; within an org each membership carries a **role** (e.g.
`owner`, `admin`, `member`, `viewer`) that gates what actions the principal may
perform. This ticket lets an authorized user (admin/owner) view the member
roster of an org, invite a new member by email with an initial role, change an
existing member's role, and remove/revoke a member or pending invite.

This ticket **owns**: the `OrgsApi` Retrofit interface, the org/member/role
DTOs + domain mappers, `OrgsRepository`, `OrgMembersViewModel` (and a small
`InviteMemberViewModel`/state), the members-list and invite Compose screens, and
their unit + UI tests. It **does not own**: the cross-cutting network plumbing
(cookie jar AND-011, CSRF interceptor AND-012, 401-refresh authenticator
AND-013, `ApiResult` AND-018) which it consumes unchanged, nor org-level billing,
SSO/SAML org provisioning, or org settings beyond membership/roles (those are out
of scope and, if needed later, will be split into follow-up tickets). It depends
on **AND-027 (AuthApi / session endpoints)** for an authenticated cookie session
and `GET /ui/me` to resolve the caller's own membership and permission to manage.

The deliverable is a working "Organization → Members" experience reachable from
the More hub, where an admin can manage members and roles against the live
backend, with offline/stale and error states handled.

## 2. Context & References

- **Repo / location:** `spannella/testlogon`, monorepo subfolder `android/`,
  branch `android-port`. Feature code lands in module **`feature-orgs`**; API +
  DTOs land in **`core-network`** / **`core-model`**; repository in
  **`core-data`**. Canonical package base **`com.testlogon.android`** everywhere
  (`com.testlogon.android.feature.orgs`,
  `com.testlogon.android.core.network.orgs`,
  `com.testlogon.android.core.model.orgs`,
  `com.testlogon.android.core.data.orgs`).
- **Stack pins relevant here:** Kotlin 2.0.21, Jetpack Compose + Material 3,
  Navigation-Compose, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 + OkHttp 4.12 +
  Moshi 1.15 (codegen via KSP), DataStore for the selected-org id, Paging 3 only
  if the roster proves large (default: a single page roster). minSdk 24,
  compileSdk/targetSdk 35, JDK 17.
- **Module layering:** `app -> feature-orgs -> core-*`. ViewModels expose
  `StateFlow<UiState>`; all network results are typed `ApiResult<T>` (AND-018);
  FastAPI `detail` mapping per AND-015 (`string | [{msg}] | {code,...}`).
- **Upstream dependency — AND-027 (AuthApi):** provides the authenticated
  cookie-based session that all `/ui/orgs/*` calls ride on, plus `GET /ui/me`
  used to determine the caller's org membership/role and whether the manage UI is
  enabled. This ticket must not re-implement session start/refresh.
- **Cross-cutting consumed (no changes here):** persistent cookie jar (AND-011),
  CSRF interceptor injecting `X-CSRF-Token` for mutating verbs (AND-012),
  401-refresh authenticator (AND-013), retry/backoff for idempotent GETs
  (AND-016), `ApiResult` (AND-018), Material 3 theme (AND-019), state composables
  loading/empty/error/offline (AND-021), nav host (AND-022/024), error model
  (AND-015).
- **Backend:** FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000`
  (plaintext, unreliable): ~20s timeouts, bounded backoff on idempotent GETs
  only. Authoritative shapes come from `/openapi.json`; the web reference app
  under `frontend/src/api/endpoints/*.ts` (org endpoints) and
  `frontend/src/api/types.ts` (org/member/role types) is the cross-check for
  exact field names. **Section 5 paths/shapes below MUST be reconciled against
  `/openapi.json` during implementation; where this spec and OpenAPI disagree,
  OpenAPI wins and the DTOs are adjusted.**

## 3. Functional Requirements

FR-1. **List organizations** the caller belongs to: fetch via `GET /ui/orgs` and
expose them so the UI can pick/scope the active org. The active org id is
persisted in DataStore (`selected_org_id`) and defaults to the caller's primary
org from `GET /ui/me` when unset.

FR-2. **List members** of the active org via `GET /ui/orgs/{org_id}/members`,
rendering each member's display name, email, role, and status
(`active` / `invited` / `suspended`). Pending invites appear in the same roster
flagged as `invited`.

FR-3. **Invite a member** via `POST /ui/orgs/{org_id}/members/invite` with an
email address and an initial role. On success the new pending invite appears in
the roster (optimistic insert reconciled with the server response).

FR-4. **Change a member's role** via
`PATCH /ui/orgs/{org_id}/members/{member_id}` (or `PUT .../role` per OpenAPI)
with the new role. The roster row reflects the new role on success and rolls
back on failure.

FR-5. **Remove a member / revoke an invite** via
`DELETE /ui/orgs/{org_id}/members/{member_id}`. The row is removed on success.

FR-6. **Permission gating:** invite, role-change, and remove controls are only
enabled when the caller's own role in the active org permits management
(`owner`/`admin`). The caller's role is derived from the members list (matching
`GET /ui/me` user id) or an org membership field. Non-managers see a read-only
roster.

FR-7. **Self-protection:** the UI must prevent the caller from removing
themselves or demoting the **sole** `owner`; such actions are disabled with an
explanatory affordance. (Server is authoritative; client adds the guard for UX.)

FR-8. **Role enumeration** is modeled as a sealed/`enum class` plus an `Unknown`
fallback so an unrecognized server role never crashes parsing.

FR-9. **States:** loading, populated, empty (org with only the caller), error
(typed), and offline/stale are all rendered using the AND-021 state composables.
Reads are SWR-friendly: a stale cached roster may render while a refresh runs.

FR-10. Invite/role/remove are **mutations** and therefore are never silently
retried by the GET backoff layer; failures surface to the user with a retry
action.

## 4. Technical Design

Production code is organized as:

```
core-model/...core/model/orgs/        Org.kt, OrgMember.kt, OrgRole.kt, dtos/
core-network/...core/network/orgs/    OrgsApi.kt, OrgsNetworkModule.kt
core-data/...core/data/orgs/          OrgsRepository.kt, OrgsRepositoryImpl.kt, OrgsDataModule.kt
feature-orgs/...feature/orgs/         nav, OrgMembersScreen.kt, InviteMemberSheet.kt,
                                      OrgMembersViewModel.kt, OrgMembersUiState.kt
```

### 4.1 Domain models (`core-model`)

```kotlin
package com.testlogon.android.core.model.orgs

enum class OrgRole(val wire: String) {
    OWNER("owner"), ADMIN("admin"), MEMBER("member"), VIEWER("viewer"), UNKNOWN("");
    companion object { fun from(s: String?) = entries.firstOrNull { it.wire == s } ?: UNKNOWN }
    val canManage get() = this == OWNER || this == ADMIN
}

enum class MemberStatus { ACTIVE, INVITED, SUSPENDED, UNKNOWN }

data class Org(val id: String, val name: String, val myRole: OrgRole)

data class OrgMember(
    val id: String,            // membership id (used for PATCH/DELETE)
    val userId: String?,       // null for not-yet-accepted invites
    val displayName: String,
    val email: String,
    val role: OrgRole,
    val status: MemberStatus,
)
```

### 4.2 Repository (`core-data`)

```kotlin
interface OrgsRepository {
    suspend fun listOrgs(): ApiResult<List<Org>>
    fun observeMembers(orgId: String): Flow<List<OrgMember>>            // cache-backed
    suspend fun refreshMembers(orgId: String): ApiResult<List<OrgMember>>
    suspend fun invite(orgId: String, email: String, role: OrgRole): ApiResult<OrgMember>
    suspend fun changeRole(orgId: String, memberId: String, role: OrgRole): ApiResult<OrgMember>
    suspend fun remove(orgId: String, memberId: String): ApiResult<Unit>
    suspend fun selectedOrgId(): Flow<String?>                          // DataStore
    suspend fun setSelectedOrgId(id: String)
}
```

`OrgsRepositoryImpl` maps DTOs → domain via mappers, wraps `OrgsApi` calls in the
shared `apiCall { }` helper (AND-018) so HTTP/IO/parse failures become typed
`ApiResult.Error`, and writes the roster into an in-memory/Room-backed cache
keyed by `orgId` for SWR reads. Mutations refresh the affected org's roster.

### 4.3 ViewModel (`feature-orgs`)

```kotlin
@HiltViewModel
class OrgMembersViewModel @Inject constructor(
    private val repo: OrgsRepository,
    private val authState: AuthStateStore,        // AND-029, for my user id
    savedState: SavedStateHandle,
) : ViewModel() {
    val state: StateFlow<OrgMembersUiState>
    fun refresh()
    fun invite(email: String, role: OrgRole)
    fun changeRole(memberId: String, role: OrgRole)
    fun remove(memberId: String)
    fun dismissError()
}

data class OrgMembersUiState(
    val orgId: String? = null,
    val members: List<OrgMember> = emptyList(),
    val myRole: OrgRole = OrgRole.UNKNOWN,
    val canManage: Boolean = false,
    val loading: Boolean = false,
    val refreshing: Boolean = false,
    val stale: Boolean = false,
    val pendingMemberIds: Set<String> = emptySet(),   // rows with in-flight mutation
    val error: UiError? = null,
)
```

The state machine: `refresh()` sets `loading`/`refreshing`, collects
`observeMembers`, recomputes `myRole`/`canManage` by matching `authState.userId`
against the roster, and surfaces typed errors. Mutations mark the target row in
`pendingMemberIds`, apply optimistically, then reconcile with the server result;
on error they roll back and set `error`.

### 4.4 UI (Compose)

- `OrgMembersScreen` — Material 3 `Scaffold` with a `TopAppBar` (org name), a
  pull-to-refresh roster (`LazyColumn` of `MemberRow`), an `ExtendedFAB`
  "Invite" visible only when `canManage`. Each `MemberRow` shows avatar (Coil),
  name, email, a role chip, and (when `canManage`) an overflow menu with
  "Change role" and "Remove". Loading/empty/error/offline are rendered with the
  AND-021 state composables.
- `InviteMemberSheet` — a `ModalBottomSheet` with an email `OutlinedTextField`
  (AND-020 input composable, inline validation) and a role selector
  (`SegmentedButton`/dropdown over manageable roles), an "Send invite" button
  with a busy state.
- `ChangeRoleDialog` — `AlertDialog` listing assignable roles; disables
  selections that would violate FR-7.

### 4.5 Navigation

A route `orgs/{orgId}/members` is added to the authenticated nav graph
(AND-024); the entry point is a "Organization" item in the More hub
(AND-067). The route reads `orgId` from `SavedStateHandle`, falling back to the
DataStore `selected_org_id`.

## 5. API Contract

All paths are relative to `http://18.222.237.167:8000/`, declared without a
leading slash. **Reconcile against `/openapi.json`; OpenAPI is authoritative.**

```kotlin
interface OrgsApi {
    @GET("ui/orgs")
    suspend fun listOrgs(): OrgListDto

    @GET("ui/orgs/{orgId}/members")
    suspend fun listMembers(@Path("orgId") orgId: String): MemberListDto

    @Headers("Content-Type: application/json")
    @POST("ui/orgs/{orgId}/members/invite")
    suspend fun invite(@Path("orgId") orgId: String, @Body body: InviteReqDto): MemberDto

    @Headers("Content-Type: application/json")
    @PATCH("ui/orgs/{orgId}/members/{memberId}")
    suspend fun changeRole(
        @Path("orgId") orgId: String,
        @Path("memberId") memberId: String,
        @Body body: RoleReqDto,
    ): MemberDto

    @DELETE("ui/orgs/{orgId}/members/{memberId}")
    suspend fun removeMember(
        @Path("orgId") orgId: String,
        @Path("memberId") memberId: String,
    ): Unit
}
```

**`GET /ui/orgs` → `OrgListDto`**
```json
{ "orgs": [ { "id": "org_123", "name": "Acme", "my_role": "admin" } ] }
```

**`GET /ui/orgs/{org_id}/members` → `MemberListDto`**
```json
{ "members": [
  { "id": "mem_1", "user_id": "usr_9", "display_name": "Jo Lee",
    "email": "jo@acme.com", "role": "owner", "status": "active" },
  { "id": "mem_2", "user_id": null, "display_name": "",
    "email": "new@acme.com", "role": "member", "status": "invited" }
] }
```

**`POST /ui/orgs/{org_id}/members/invite`** request / response:
```json
// request
{ "email": "new@acme.com", "role": "member" }
// 200/201 response: a MemberDto (status:"invited")
{ "id": "mem_2", "user_id": null, "email": "new@acme.com",
  "role": "member", "status": "invited" }
```

**`PATCH /ui/orgs/{org_id}/members/{member_id}`** request / response:
```json
// request
{ "role": "admin" }
// response: updated MemberDto
{ "id": "mem_2", "user_id": "usr_7", "email": "...", "role": "admin", "status": "active" }
```

**`DELETE /ui/orgs/{org_id}/members/{member_id}`** → `204` empty body
(decoded to `Unit`).

DTOs are Moshi `@JsonClass(generateAdapter = true)` data classes in
`core-model/.../orgs/dtos/` with `@Json(name = "...")` for snake_case fields.
The CSRF header and cookies are injected globally (AND-011/AND-012); `OrgsApi`
declares neither. Mutating verbs (POST/PATCH/DELETE) are excluded from GET
retry/backoff (AND-016).

## 6. Data & State Management

- **Source of truth:** the server. The repository caches the per-org roster
  (`Map<orgId, List<OrgMember>>` in memory, optionally a Room `org_members`
  table per AND-115 for SWR/offline) and emits it via `observeMembers`.
- **Selected org:** persisted in DataStore key `selected_org_id`; defaults to the
  primary org from `GET /ui/me`.
- **Optimistic mutations:** invite inserts a synthetic `invited` row; role-change
  swaps the row's `role`; remove drops the row. Each is tagged in
  `pendingMemberIds` and reconciled/rolled back on the server result.
- **Derived state:** `myRole`/`canManage` are computed from the roster +
  `authState.userId`, never trusted from the client alone for security (server
  still authorizes).
- **Lifecycle:** `state` is exposed with `stateIn(viewModelScope,
  SharingStarted.WhileSubscribed(5_000), initial)`; the roster Flow survives
  config changes.

## 7. Error Handling & Resilience

- All calls return `ApiResult<T>`; transport/parse exceptions become
  `ApiResult.Error` with a typed `UiError` mapped from FastAPI `detail`
  (AND-015): `string`, `[{msg}]`, or `{code,...}`.
- **Specific codes:** `401` → AND-013 authenticator refreshes once then retries;
  a second `401` surfaces a re-auth prompt. `403` → "You don't have permission to
  manage this organization" and the manage controls disable. `404` (org/member
  gone) → remove the row / show empty. `409` (e.g. demoting sole owner,
  duplicate invite) → inline message on the invite/role control. `422`
  (validation, e.g. malformed email) → field-level error on the invite form.
- **Unreliable host:** GET roster reads use the bounded backoff retry (AND-016,
  ~20s timeout). Mutations are **not** auto-retried; failures keep optimistic
  rollback and present a manual "Retry".
- **Offline/stale:** when offline, render the cached roster with a stale banner
  (AND-021); mutations are blocked with an offline message rather than queued.

## 8. Security & Privacy

- Session is cookie-based; no tokens are stored by this feature. The persistent
  cookie jar (AND-011) and `X-CSRF-Token` echo (AND-012) secure mutations.
- Member emails are PII: never log raw emails or member ids at info level;
  redact per AND-052 conventions (hash/last-domain only in diagnostics).
- Client permission gating (`canManage`, self-protection FR-7) is a UX
  convenience only; **the server is the authority** for every mutation and a
  `403`/`409` is always handled.
- Invite input is validated client-side (email format) but the server's `422`
  is the source of truth; no client-side authorization decision is cached beyond
  the current screen session.

## 9. Accessibility & i18n

- All user-facing strings live in `feature-orgs` `strings.xml` (AND-111
  plumbing); no hardcoded literals. Role names are localized via a mapping from
  `OrgRole` → string resource, not the wire value.
- Every interactive control (role chip, overflow menu, invite FAB, dialog
  options) has a `contentDescription`/semantics; the role chip announces both
  the member name and role.
- Touch targets ≥ 48dp; dynamic type and dark theme honored via Material 3
  theme (AND-019). RTL-ready layouts (AND-114). Error/empty states are
  screen-reader announced via `liveRegion`.

## 10. Telemetry & Logging

- Emit structured analytics events (no PII): `org_members_viewed { orgId }`,
  `org_invite_sent { orgId, role }`, `org_role_changed { orgId, fromRole,
  toRole }`, `org_member_removed { orgId }`, and
  `org_action_failed { action, httpStatus, errorCode }`.
- Logging is redacted (AND-052): emails/member ids never logged in cleartext;
  only org id and coarse role are included. Network logging level follows the
  shared OkHttp interceptor config (AND-009) and never logs cookies/CSRF.

## 11. Testing Strategy

The acceptance bullet requires *Org members + roles manage (tested)*. Coverage:

- **`OrgsApi` MockWebServer tests (core-network):** assert verb + resolved path
  + request body + successful decode for `listOrgs`, `listMembers`, `invite`,
  `changeRole`, `removeMember`; assert snake_case `@Json` mapping and `Unknown`
  role fallback.
- **`OrgsRepositoryImpl` unit tests (core-data):** DTO→domain mapping; SWR emit
  (stale-then-fresh); each `ApiResult.Error` mapping for 401/403/404/409/422
  detail shapes; optimistic mutation + rollback on error.
- **`OrgMembersViewModel` tests (core-testing turbine + fake repo):** state
  transitions for load/refresh/empty/error; `canManage` derivation from
  `authState.userId`; invite/changeRole/remove optimistic update and rollback;
  self-protection guards (FR-7).
- **Compose UI tests (feature-orgs):** roster renders names/roles/status; FAB and
  overflow hidden for non-managers; invite sheet validation; change-role dialog;
  loading/empty/error/offline states. Run under CI instrumented (AND-051).
- Fixtures use the AND-046 MockWebServer harness; JSON fixtures mirror Section 5.

## 12. Dependencies & Sequencing

- **Hard dependency:** AND-027 (AuthApi/session) — authenticated cookie session
  and `GET /ui/me` for caller identity/role. Implicitly requires the network
  stack (AND-009–AND-018), nav (AND-022/024), state composables (AND-021), input
  composables (AND-020), theme (AND-019), and the More-hub entry (AND-067).
- **Blocks:** none declared in the backlog. Future org-settings/billing tickets,
  if created, would build on this repository and models.
- **Sequencing:** land DTOs + `OrgsApi` (+ MockWebServer tests) → repository (+
  tests) → ViewModel (+ tests) → Compose screens (+ UI tests) → wire the More-hub
  route.

## 13. Risks & Open Questions

- **OpenAPI drift:** the exact `/ui/orgs/*` paths, the role-change verb
  (`PATCH` vs `PUT .../role`), and field names are inferred and **must** be
  confirmed against `/openapi.json` and `frontend/src/api/endpoints`. Resolve
  before finalizing DTOs.
- **Role taxonomy:** the concrete set of roles (`owner/admin/member/viewer`) and
  which are assignable by whom is unconfirmed; `OrgRole.UNKNOWN` mitigates parse
  risk but the manage UI must enumerate only server-supported roles.
- **Invite acceptance flow:** whether an invite produces a deep link / email and
  whether the client surfaces re-send/cancel beyond `DELETE` is unspecified —
  out of scope here unless OpenAPI exposes it.
- **Multi-org UX:** how prominent org switching should be (this ticket persists a
  selection but does not build a full switcher) — open product question.
- **Pagination:** roster size is assumed single-page; if the backend paginates
  members, add Paging 3 (AND-098 pattern) as a fast follow.

## 14. Acceptance Criteria

AC-1. `OrgsApi` exposes `listOrgs`, `listMembers`, `invite`, `changeRole`,
`removeMember` with verbs/paths/bodies matching the backend contract, proven by
MockWebServer tests. (FR-1..FR-5)

AC-2. The members screen lists all members of the active org with name, email,
role, and status, including pending invites flagged `invited`. (FR-2)

AC-3. An authorized (`owner`/`admin`) user can invite a member by email with an
initial role; the new pending invite appears in the roster. (FR-3, FR-6)

AC-4. An authorized user can change a member's role and the change persists and
reflects in the roster; failures roll back. (FR-4, FR-10)

AC-5. An authorized user can remove a member / revoke an invite; the row
disappears on success. (FR-5)

AC-6. Manage controls are hidden/disabled for non-managers and for
self-removal/sole-owner-demotion. (FR-6, FR-7)

AC-7. Loading, empty, typed-error (401/403/404/409/422), and offline/stale
states render correctly. (FR-9, §7)

AC-8. Unknown server roles parse to `UNKNOWN` without crashing. (FR-8)

AC-9. Repository, ViewModel, and Compose UI tests for members + role management
pass in CI (unit + instrumented). (§11) — satisfies the backlog's *tested*
requirement.

## 15. Definition of Done

- All FRs implemented; all ACs met and green in CI (unit AND-050 + instrumented
  AND-051).
- `OrgsApi`, DTOs/mappers, `OrgsRepository(Impl)`, `OrgMembersViewModel`, and the
  members/invite Compose UI merged into `feature-orgs`/`core-*` on
  `android-port`, packages under `com.testlogon.android`.
- Paths/shapes reconciled against `/openapi.json`; any divergence from Section 5
  reflected in the merged DTOs and noted in the PR.
- No hardcoded strings (i18n), accessibility semantics present, PII redaction in
  logging verified.
- Telemetry events emit with no PII; lint/detekt/ktlint (AND-005) clean.
- PR reviewed and approved; tests deterministic with the AND-046 MockWebServer
  harness; no new Retrofit/OkHttp instances created (shared client reused).
