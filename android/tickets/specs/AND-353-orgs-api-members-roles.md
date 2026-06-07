---
id: AND-353
title: Orgs API + members/roles
milestone: M7
epic: E46
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
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

FR-1. **List organizations** the caller belongs to: fetch via `GET /ui/orgs`
(VERIFIED) and expose them so the UI can pick/scope the active org. **CORRECTED:**
the response is a **bare JSON array** of org objects (`OrgOut[]`), not an
`{ "orgs": [...] }` envelope; each org's id field is **`org_id`** and the caller's
role field is **`org_role`** (not `id`/`my_role`). The active org id is persisted
in DataStore (`selected_org_id`) and defaults to the caller's primary org from
`GET /ui/me` when unset.

FR-2. **List members** of the active org via `GET /ui/orgs/{org_id}/members`
(VERIFIED), rendering each member's role and status. **CORRECTED:** the response
is a **bare array** of `OrgMemberOut`, and a member object contains
**`user_sub`, `org_role`, `status`, `joined_at`, `storage_used_bytes`,
`last_active_at?`** — there is **no `display_name`, no `email`, and no `id`** on a
member; the member identity is **`user_sub`**. Display name/avatar must therefore
be resolved separately (e.g. a profile-lookup join) or the row renders `user_sub`;
this is flagged as an open assumption (see §16). Member `status` values are not
enumerated by OpenAPI and must not be hardcoded to `active`/`invited`/`suspended`
without confirmation. Pending invites are a **separate resource**
(`GET /ui/orgs/invites/pending` → `OrgInviteOut[]`, with `invite_id`, `email`,
`org_role`, `status`), not rows inside the members array.

FR-3. **Invite a member** via `POST /ui/orgs/{org_id}/members/invite` (VERIFIED)
with an email address and an initial role. **CORRECTED:** the request body is
`OrgMemberInviteReq` = `{ "email": string, "org_role": string }` — the role field
is **`org_role`** (not `role`), is **optional** (default `"member"`), and is
constrained by regex **`^(admin|member|viewer)$`** (so **`owner` cannot be
assigned via invite**); `email` is required, length 3..254. On success the server
returns **`201`** with an **`OrgInviteOut`** (fields `invite_id`, `org_id`,
`org_name`, `email`, `org_role`, `status`, `invited_by`, `created_at`,
`expires_at`, `token?`) — **not** a member object. The new pending invite belongs
to the pending-invites list, so the optimistic-insert-into-roster behavior must be
reconsidered (see §16 corrections).

FR-4. **Change a member's role** via
`PATCH /ui/orgs/{org_id}/members/{member_sub}/role` (VERIFIED). **CORRECTED:** the
verb is `PATCH`, the path has a trailing **`/role`** segment, the path param is
**`member_sub`** (not `member_id`), and the request body is `OrgMemberRoleUpdateReq`
= `{ "org_role": string }` (field **`org_role`**, required, regex
`^(admin|member|viewer)$`). Promotion to **`owner` is NOT supported here** — that
is a distinct `POST /ui/orgs/{org_id}/transfer-ownership` with body
`{ "new_owner_user_sub": string }`. Success is `200`. The roster row reflects the
new role on success and rolls back on failure.

FR-5. **Remove a member / revoke an invite** via
`DELETE /ui/orgs/{org_id}/members/{member_sub}` (VERIFIED) — path param is
**`member_sub`** (not `member_id`); success is **`204`** (empty body). Revoking a
**pending invite** is a different operation
(`POST /ui/orgs/invites/{invite_id}/decline` is the invitee-side decline; there is
no member-side invite-revoke endpoint in OpenAPI — see §16 open assumptions). The
row is removed on success.

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
    val userSub: String,       // CORRECTED: member identity = user_sub (used for PATCH/DELETE path); no membership "id" exists
    val role: OrgRole,         // from wire field org_role
    val status: MemberStatus,
    val joinedAt: Long?,       // joined_at (epoch seconds)
    val lastActiveAt: Long?,   // last_active_at (optional)
    val displayName: String? = null, // CORRECTED: NOT returned by the members endpoint; resolved via profile lookup or null
    val email: String? = null,       // CORRECTED: NOT on a member; email only appears on OrgInviteOut (pending invites)
)
```

**CORRECTIONS to 4.1 (verified against `src/api/endpoints/orgs.ts` + OpenAPI):**
the `Org` wire shape maps `id ← org_id` and `myRole ← org_role`; `OrgRole.from`
must accept the wire token `"owner"` too (it appears on `OrgOut.org_role` and as a
member role even though it is not *assignable* via invite/role-change). The
assignable-role set for the invite/role-change UI is **`{admin, member, viewer}`**
only (OpenAPI regex `^(admin|member|viewer)$`); `owner` is reachable solely via
`transfer-ownership` and must be excluded from the role pickers. Keep `canManage`
as a client UX hint only (server authorizes).

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

**CORRECTION to 4.2:** the `changeRole`/`remove` parameters named `memberId` are
the member's **`user_sub`** (rename to `memberSub` recommended); there is no
separate membership id. `invite()` returns an **`OrgInviteOut`**, not an
`OrgMember`, so its signature should be `ApiResult<OrgInvite>` and the roster
reconciliation must read from the pending-invites resource (see §16).

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

> **This section has been corrected against OpenAPI (`openapi.index.txt` /
> `openapi.pretty.json`) and `src/api/endpoints/orgs.ts`.** The original draft had
> the wrong response envelopes (arrays, not `{orgs}`/`{members}`), wrong field
> names (`org_id`/`org_role`/`user_sub`, not `id`/`role`/`user_id`), a wrong
> role-change path (missing `/role`, wrong param), and a wrong invite response
> type (`OrgInviteOut`, not a member). See §16.

```kotlin
interface OrgsApi {
    // VERIFIED: GET /ui/orgs -> bare array OrgOut[]
    @GET("ui/orgs")
    suspend fun listOrgs(): List<OrgDto>

    // VERIFIED: GET /ui/orgs/{org_id}/members -> bare array OrgMemberOut[]
    @GET("ui/orgs/{orgId}/members")
    suspend fun listMembers(@Path("orgId") orgId: String): List<MemberDto>

    // VERIFIED: POST /ui/orgs/{org_id}/members/invite, req=OrgMemberInviteReq, resp 201=OrgInviteOut
    @Headers("Content-Type: application/json")
    @POST("ui/orgs/{orgId}/members/invite")
    suspend fun invite(@Path("orgId") orgId: String, @Body body: InviteReqDto): InviteDto

    // CORRECTED: PATCH /ui/orgs/{org_id}/members/{member_sub}/role  (trailing /role; param = member_sub)
    @Headers("Content-Type: application/json")
    @PATCH("ui/orgs/{orgId}/members/{memberSub}/role")
    suspend fun changeRole(
        @Path("orgId") orgId: String,
        @Path("memberSub") memberSub: String,
        @Body body: RoleReqDto,             // { "org_role": "admin" }
    ): MemberDto                            // 200; web client leaves it untyped (Response<Unit> also acceptable)

    // CORRECTED: DELETE /ui/orgs/{org_id}/members/{member_sub} -> 204
    @DELETE("ui/orgs/{orgId}/members/{memberSub}")
    suspend fun removeMember(
        @Path("orgId") orgId: String,
        @Path("memberSub") memberSub: String,
    ): Unit
}
```

`InviteReqDto` and `RoleReqDto` both use the wire field **`org_role`**
(`@Json(name = "org_role")`), constrained to `admin|member|viewer`.

**`GET /ui/orgs` → bare array `OrgDto[]`** (maps `OrgOut`)
```json
[ { "org_id": "org_123", "name": "Acme", "description": "…", "slug": "acme",
    "owner_user_sub": "usr_1", "status": "active", "plan": "pro",
    "member_count": 7, "storage_used_bytes": 0, "storage_limit_bytes": 0,
    "billing_mode": "org", "created_at": 0, "updated_at": 0,
    "org_role": "admin", "team_calendar_id": "cal_1" } ]
```
(Only `org_id`, `name`, `org_role` are needed by this feature; the rest may be
ignored. `org_role` is optional in the type.)

**`GET /ui/orgs/{org_id}/members` → bare array `MemberDto[]`** (maps `OrgMemberOut`)
```json
[ { "user_sub": "usr_9", "org_role": "owner", "status": "active",
    "joined_at": 0, "storage_used_bytes": 0, "last_active_at": 0 } ]
```
(NO `id`, `display_name`, or `email` fields — member identity is `user_sub`.)

**`POST /ui/orgs/{org_id}/members/invite`** request / response:
```json
// request (OrgMemberInviteReq): org_role optional, default "member", regex admin|member|viewer
{ "email": "new@acme.com", "org_role": "member" }
// 201 response (OrgInviteOut):
{ "invite_id": "inv_2", "org_id": "org_123", "org_name": "Acme",
  "email": "new@acme.com", "org_role": "member", "status": "pending",
  "invited_by": "usr_1", "created_at": 0, "expires_at": 0, "token": "…" }
```

**`PATCH /ui/orgs/{org_id}/members/{member_sub}/role`** request / response:
```json
// request (OrgMemberRoleUpdateReq): org_role required, regex admin|member|viewer
{ "org_role": "admin" }
// 200 response: updated member (OrgMemberOut shape)
{ "user_sub": "usr_7", "org_role": "admin", "status": "active",
  "joined_at": 0, "storage_used_bytes": 0 }
```

**`DELETE /ui/orgs/{org_id}/members/{member_sub}`** → `204` empty body
(decoded to `Unit`).

**Ownership transfer (out of the role-change path):**
`POST /ui/orgs/{org_id}/transfer-ownership` with `OrgTransferOwnershipReq`
`{ "new_owner_user_sub": string }` → `204`. The role UI must route any
"make owner" intent here rather than the role PATCH.

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
- **VERIFICATION NOTE on status codes:** OpenAPI declares for **every** `/ui/orgs/*`
  route only the success code (`200`/`201`/`204`) plus **`422 HTTPValidationError`**;
  it does **not** document `403`/`404`/`409` response schemas for these routes. The
  web client (`src/api/client.ts`) nonetheless handles `401` (refresh-once then
  retry, else logout), `403` (permission/geo-blocked toast), and generic non-2xx by
  reading a FastAPI `detail` (`string | [{msg}] | {code,...}`). So: `401`/`403`/`422`
  handling is **verified**; `404`/`409` handling is a **defensive assumption** (the
  server may return them at runtime even though they are undocumented) — keep the
  handlers but treat them as best-effort, and rely on the generic `detail` mapper for
  any undocumented status. The `409` "sole-owner / duplicate-invite" semantics are an
  assumption (see §16).
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

- Session transport is cross-cutting and owned by AND-011/012/013; this feature
  stores no tokens itself. **CLARIFICATION (verified against `src/api/client.ts`):**
  the web reference client is **not purely cookie-based** — every request sends
  `credentials: "include"` (cookies) **and** an `Authorization: Bearer <accessToken>`
  header from its auth store, plus `X-CSRF-Token` read from the `ui_csrf` cookie for
  all verbs, and an optional `X-IMPERSONATION-TOKEN`. The CSRF token is therefore
  sent on GETs too (not only mutating verbs as the draft implies). The 401 path
  refreshes via **`POST /ui/session/refresh`** once, then retries. The Android port
  may legitimately consolidate this into the AND-011/012/013 layers, but the
  Bearer-token + CSRF-on-all-verbs detail above is the real web contract and AND-027
  must supply the access token, not just a cookie. (Note: OpenAPI further documents a
  `user_sub` query param and `X-SESSION-ID`/`X-IMPERSONATION-TOKEN` headers on these
  routes; the web client relies on the cookie session for identity and does not send
  `user_sub` explicitly — server resolves it from the session.)
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. Sources:
OpenAPI index `reference/openapi.index.txt`, OpenAPI spec
`reference/openapi.pretty.json` (component schema names), and frontend
`reference/src/...`.

1. **`GET /ui/orgs` lists the caller's orgs.** VERIFIED.
   Source: OpenAPI `GET /ui/orgs` (op `list_orgs_ui_orgs_get`);
   `src/api/endpoints/orgs.ts: listOrgs` → `api.get<OrgOut[]>("/ui/orgs")`.
2. **`GET /ui/orgs` response is a bare array, not an `{ "orgs": [...] }` envelope.**
   CORRECTED (draft was wrong). Source: `src/api/endpoints/orgs.ts: listOrgs`
   (`OrgOut[]`).
3. **Org id field is `org_id` and caller role field is `org_role` (not `id`/`my_role`).**
   CORRECTED. Source: `src/api/endpoints/orgs.ts: OrgOut`; `src/pages/orgs/OrgsPage.tsx`
   (`org.org_id`, `org.org_role`).
4. **`GET /ui/orgs/{org_id}/members` lists members.** VERIFIED.
   Source: OpenAPI `GET /ui/orgs/{org_id}/members`
   (op `list_members_ui_orgs__org_id__members_get`); `src/api/endpoints/orgs.ts:
   listMembers` → `OrgMemberOut[]`.
5. **Members response is a bare array; a member = `{user_sub, org_role, status,
   joined_at, storage_used_bytes, last_active_at?}` with NO `id`/`display_name`/`email`.**
   CORRECTED (draft invented `id`, `display_name`, `email`, `user_id`). Source:
   `src/api/endpoints/orgs.ts: OrgMemberOut`.
6. **Member identity for PATCH/DELETE is `user_sub` (path param `member_sub`), not a
   membership `id`.** CORRECTED. Source: OpenAPI `DELETE /ui/orgs/{org_id}/members/{member_sub}`
   and `PATCH /ui/orgs/{org_id}/members/{member_sub}/role` params=`member_sub`;
   `src/api/endpoints/orgs.ts: removeMember/changeMemberRole` (`userSub`).
7. **Invite endpoint `POST /ui/orgs/{org_id}/members/invite`.** VERIFIED.
   Source: OpenAPI op `invite_member_ui_orgs__org_id__members_invite_post`;
   `src/api/endpoints/orgs.ts: inviteMember`.
8. **Invite body field is `org_role` (optional, default `member`, regex
   `^(admin|member|viewer)$`) plus required `email` (len 3..254) — NOT `role`.**
   CORRECTED. Source: OpenAPI `components.schemas.OrgMemberInviteReq`
   (`openapi.pretty.json` ~L52979).
9. **Invite returns `201` with `OrgInviteOut` (`invite_id, org_id, org_name, email,
   org_role, status, invited_by, created_at, expires_at, token?`), not a member.**
   CORRECTED. Source: OpenAPI `POST .../members/invite resp=201`;
   `src/api/endpoints/orgs.ts: inviteMember` → `OrgInviteOut`; `OrgInviteOut` type.
10. **Role-change is `PATCH /ui/orgs/{org_id}/members/{member_sub}/role` with body
    `{org_role}` (regex `^(admin|member|viewer)$`, required), resp `200`.**
    CORRECTED (draft had `PATCH .../members/{member_id}` with no `/role`, body `role`).
    Source: OpenAPI op `change_member_role_..._role_patch` +
    `components.schemas.OrgMemberRoleUpdateReq` (~L53000); `src/api/endpoints/orgs.ts:
    changeMemberRole`.
11. **`owner` is NOT assignable via invite or role-change; promotion to owner uses
    `POST /ui/orgs/{org_id}/transfer-ownership` with `{new_owner_user_sub}` → `204`.**
    CORRECTED/VERIFIED. Source: invite/role regex excludes `owner`; OpenAPI op
    `transfer_ownership_...` + `components.schemas.OrgTransferOwnershipReq` (~L53014);
    `src/api/endpoints/orgs.ts: transferOwnership`.
12. **Remove member `DELETE /ui/orgs/{org_id}/members/{member_sub}` → `204` empty body.**
    VERIFIED. Source: OpenAPI op `remove_member_...` resp=204;
    `src/api/endpoints/orgs.ts: removeMember` → `api.del`.
13. **Pending invites are a separate resource (`GET /ui/orgs/invites/pending` →
    `OrgInviteOut[]`); invites are not rows in the members array.** CORRECTED
    (draft folded invites into the roster as `status:"invited"`). Source: OpenAPI op
    `list_pending_invites_...`; `src/api/endpoints/orgs.ts: listPendingInvites`.
14. **`GET /ui/me` exists and yields caller identity.** VERIFIED.
    Source: OpenAPI `GET /ui/me` (op `ui_me_ui_me_get`); `src/api/endpoints/auth.ts:
    getMe` → `api.get<MeResp>("/ui/me")`. Exact membership/role fields of `MeResp`
    are not modeled in OpenAPI (empty 200 schema) — see Open assumptions.
15. **Transport: web client sends cookies (`credentials:"include"`) AND
    `Authorization: Bearer <accessToken>` AND `X-CSRF-Token` (from `ui_csrf` cookie)
    on ALL verbs, plus optional `X-IMPERSONATION-TOKEN`.** CORRECTED (draft said
    purely cookie-based and CSRF only on mutating verbs). Source: `src/api/client.ts`
    (the `api()` core fn).
16. **401 handling: refresh once via `POST /ui/session/refresh`, retry, else logout.**
    VERIFIED. Source: `src/api/client.ts: refreshSession` + 401 branch.
17. **FastAPI error `detail` shape is `string | [{msg}] | {code,...}`.** VERIFIED.
    Source: `src/api/client.ts: normalizeErrorDetail` / `mapAuthorizationError`;
    OpenAPI `HTTPValidationError` (the `422` body for every org route).
18. **Only `422` (and the success code) are declared per org route; `403`/`404`/`409`
    are not in the OpenAPI schemas for `/ui/orgs/*`.** VERIFIED.
    Source: `openapi.index.txt` (all org rows show `resp=...;422:HTTPValidationError`).
19. **Unknown server role tolerated via `OrgRole.UNKNOWN`.** VERIFIED (sound design;
    no source contradicts). The observed role tokens are `owner` (display, e.g.
    `OrgsPage.tsx` badge) and `admin|member|viewer` (assignable). framework ref: Moshi
    enum fallback pattern — https://github.com/square/moshi#enums.
20. **Compose + Material 3 + Retrofit/OkHttp/Moshi + Hilt stack.** framework ref
    (project pins, not backend-verifiable): Jetpack Compose
    https://developer.android.com/jetpack/compose ; Material 3
    https://m3.material.io/develop/android/jetpack-compose ; Retrofit
    https://square.github.io/retrofit/ ; Moshi codegen
    https://github.com/square/moshi#codegen ; Hilt
    https://developer.android.com/training/dependency-injection/hilt-android .

### Corrections made

- Response envelopes: `GET /ui/orgs` and `GET /ui/orgs/{org_id}/members` return
  **bare arrays**, not `{orgs}`/`{members}` objects. (FR-1, FR-2, §5)
- Field renames to the real wire shapes: `id→org_id`, `my_role→org_role`,
  member identity `user_id/id → user_sub`, role field `role → org_role`. (§4.1, §5)
- Removed nonexistent member fields `display_name`/`email`/`id` from `OrgMember`;
  flagged display-name resolution as an open assumption. (§4.1, FR-2)
- Role-change endpoint corrected to `PATCH .../members/{member_sub}/role` with body
  `{org_role}`, success `200`; param renamed `member_id → member_sub`. (FR-4, §5)
- Invite response corrected to `201` + `OrgInviteOut` (an invite, not a member);
  invite role field `org_role`, default `member`, regex `admin|member|viewer`.
  (FR-3, §5)
- Separated pending invites into their own resource; optimistic "insert invited row
  into roster" reconsidered. (FR-2, FR-3, §6)
- Added ownership-transfer endpoint as the only path to `owner`; excluded `owner`
  from invite/role pickers. (FR-4, §4.1, §5)
- Transport clarified: Bearer token + cookies + CSRF-on-all-verbs; refresh via
  `POST /ui/session/refresh`. (§8)
- Status-code reality: only `422` documented per route; `404`/`409` handling marked
  defensive/assumed. (§7)

### Open assumptions

- **Member display name / email / avatar.** UNVERIFIABLE from sources: the members
  endpoint returns only `user_sub` (no name/email). Assumption: the Android UI must
  resolve display data via a separate profile-lookup join, or render `user_sub`.
  Web reference does not render a member roster, so no UI precedent exists.
- **Member `status` value set.** UNVERIFIABLE: OpenAPI types `status` as a free
  string; the draft's `active/invited/suspended` enum is unconfirmed. Invites use
  `status:"pending"` per `OrgInviteOut`. Do not hardcode the member enum.
- **`/ui/me` membership/role fields.** UNVERIFIABLE: OpenAPI 200 body for `/ui/me`
  is untyped and `MeResp` is defined in AND-027 scope, not here. Assumption: it
  exposes the caller's `user_sub` (used to match the roster for `canManage`).
- **`409` semantics (sole-owner demotion, duplicate invite).** UNVERIFIABLE: not in
  OpenAPI; assumed server behavior. Client self-protection (FR-7) is UX-only.
- **Member-side invite revoke.** UNVERIFIABLE: OpenAPI has invitee-side
  `accept`/`decline` only; no "owner revokes a pending invite" endpoint exists.
  Assumption: revoking a not-yet-accepted invite is unsupported (or piggybacks on a
  future endpoint); FR-5 "revoke an invite" applies only to members, not pending
  invites.
- **Pagination of the members list.** UNVERIFIABLE: no cursor/limit params on
  `GET .../members` in OpenAPI; single-page assumption stands.
- **CSRF cookie name `ui_csrf` / refresh path** are web-client specifics; the Android
  equivalents live in AND-012/AND-013 and are assumed to mirror them.

## 17. Test Plan

Targets: **JVM** = JVM unit/Robolectric (no device); **emu35** = headless emulator
AVD `test35` (x86_64, API 35); **A15** = physical Samsung Galaxy A15 5G (SM-A156U,
API 34, arm64-v8a). MockWebServer/contract tests run on JVM. All fixtures must
mirror the corrected §5 shapes (bare arrays, `org_id`/`org_role`/`user_sub`,
`OrgInviteOut`).

- **TC-AND-353-01 — listOrgs/listMembers decode bare arrays.**
  Type: contract/MockWebServer. Target: JVM.
  Preconditions: MockWebServer enqueues a 200 JSON **array** body for `GET /ui/orgs`
  and `GET /ui/orgs/{id}/members` per §5.
  Steps: call `OrgsApi.listOrgs()` then `listMembers("org_123")`.
  Expected: requests use `GET` at `ui/orgs` and `ui/orgs/org_123/members`; decoding
  yields `List<OrgDto>` / `List<MemberDto>`; `org_id→id`, `org_role→role`,
  `user_sub→userSub` map correctly; no envelope unwrap is attempted.
  Traces: AC-1, AC-2.

- **TC-AND-353-02 — invite request/response contract.**
  Type: contract/MockWebServer. Target: JVM.
  Preconditions: enqueue `201` with an `OrgInviteOut` body.
  Steps: call `invite("org_123", InviteReqDto(email="new@acme.com", role=MEMBER))`.
  Expected: `POST ui/orgs/org_123/members/invite`; serialized body is
  `{"email":"new@acme.com","org_role":"member"}` (field `org_role`, not `role`);
  response decodes to an `InviteDto` with `invite_id`, `status:"pending"`.
  Traces: AC-1, AC-3.

- **TC-AND-353-03 — change-role path & body contract.**
  Type: contract/MockWebServer. Target: JVM.
  Preconditions: enqueue `200`.
  Steps: call `changeRole("org_123","usr_7", RoleReqDto(ADMIN))`.
  Expected: `PATCH ui/orgs/org_123/members/usr_7/role` (trailing `/role`, param is
  the user_sub); body `{"org_role":"admin"}`.
  Traces: AC-1, AC-4.

- **TC-AND-353-04 — remove member contract (204).**
  Type: contract/MockWebServer. Target: JVM.
  Preconditions: enqueue `204` empty.
  Steps: call `removeMember("org_123","usr_7")`.
  Expected: `DELETE ui/orgs/org_123/members/usr_7`; decodes to `Unit` with no parse
  error on empty body.
  Traces: AC-1, AC-5.

- **TC-AND-353-05 — unknown role + free-form status fallback.**
  Type: unit. Target: JVM.
  Preconditions: member JSON with `org_role:"superuser"` and `status:"archived"`.
  Steps: map DTO→domain.
  Expected: `OrgRole.from("superuser") == UNKNOWN`; mapping does not throw; unknown
  status maps to a non-crashing fallback. Also assert `OrgRole.from("owner")==OWNER`.
  Traces: AC-8.

- **TC-AND-353-06 — assignable-role set excludes owner.**
  Type: unit. Target: JVM.
  Preconditions: role picker source = manageable roles for an admin/owner caller.
  Steps: compute the invite/change-role option list.
  Expected: options are exactly `{ADMIN, MEMBER, VIEWER}`; `OWNER` is absent (owner
  is only reachable via transfer-ownership), matching the server regex.
  Traces: AC-3, AC-4, AC-6.

- **TC-AND-353-07 — typed error mapping for 422/403/401.**
  Type: unit (repository + error mapper). Target: JVM.
  Preconditions: MockWebServer enqueues, in turn, `422` with
  `{"detail":[{"msg":"value is not a valid email"}]}`, `403` with
  `{"detail":"Permission denied"}`, and a `401`.
  Steps: invoke invite/changeRole and the `ApiResult` mapper for each.
  Expected: `422`→field-level `UiError` carrying the `msg`; `403`→permission
  `UiError` and `canManage` forced false; `401`→triggers single refresh then retry
  (AND-013) and surfaces re-auth only on a second `401`. Uses the §7 `detail`
  shapes (`string | [{msg}] | {code}`).
  Traces: AC-7.

- **TC-AND-353-08 — optimistic mutation rollback.**
  Type: unit (ViewModel + fake repo, Turbine). Target: JVM.
  Preconditions: roster loaded; changeRole will fail with `409`.
  Steps: call `changeRole(userSub, ADMIN)`; let the fake repo return Error.
  Expected: row is marked in `pendingMemberIds`, optimistically shows new role, then
  on error rolls back to the prior role and sets `error`; a manual retry is offered
  (mutations are never auto-retried).
  Traces: AC-4, AC-7.

- **TC-AND-353-09 — canManage derivation & self-protection guards.**
  Type: unit (ViewModel). Target: JVM.
  Preconditions: roster has caller `usr_self` as sole `owner`; `authState.userId =
  usr_self`.
  Steps: compute UI state.
  Expected: `canManage == true`; remove-self and demote-sole-owner actions are
  disabled (FR-7); for a `member`-role caller `canManage == false` and no mutate
  controls are exposed.
  Traces: AC-6.

- **TC-AND-353-10 — roster + manage controls visibility (Compose UI).**
  Type: Compose-UI / instrumented. Target: emu35 (also smoke on A15).
  Preconditions: fake repo emits a 3-member roster; once as `admin` caller, once as
  `viewer`.
  Steps: render `OrgMembersScreen`; inspect rows and the Invite FAB / row overflow.
  Expected: each row shows role chip + status; as `admin` the Invite FAB and
  Change-role/Remove overflow are present; as `viewer` they are absent. Empty and
  error states render via AND-021 composables.
  Traces: AC-2, AC-6, AC-7.

- **TC-AND-353-11 — invite sheet validation (Compose UI).**
  Type: Compose-UI / instrumented. Target: emu35.
  Preconditions: invite sheet open.
  Steps: enter an invalid email, attempt send; then enter a valid email + role and
  send (server `201`).
  Expected: invalid email blocks send with inline error; valid send dispatches
  `org_role` from the picker; a server `422` re-surfaces as a field error.
  Traces: AC-3, AC-7.

- **TC-AND-353-12 — offline/stale behavior on flaky dev host.**
  Type: integration. Target: emu35 (airplane-mode toggle) with MockWebServer; repeat
  the real-network leg on **A15** for true radio offline.
  Preconditions: a cached roster exists; network then goes offline / host stalls past
  the ~20s timeout.
  Steps: trigger refresh while offline; then attempt a mutation.
  Expected: cached roster renders with a stale banner (AND-021); GET surfaces a
  typed timeout error after bounded backoff (AND-016) without auto-retrying
  mutations; the mutation is blocked with an offline message (not queued).
  **Must run the radio-offline leg on A15** (real connectivity transitions differ
  from emulator).
  Traces: AC-7.

- **TC-AND-353-13 — security: CSRF/cookie + no-PII redaction.**
  Type: instrumented. Target: A15 (real cookie jar / interceptor stack).
  Preconditions: authenticated session; logging at debug.
  Steps: perform invite + change-role; capture outbound headers and logcat.
  Expected: mutating requests carry the cookie session and `X-CSRF-Token`
  (AND-011/012) and, per the web contract, the `Authorization: Bearer` header from
  AND-027; logs never contain raw emails/`user_sub`/cookies/CSRF (AND-052 redaction).
  Prefer A15 to exercise the real persistent cookie jar.
  Traces: AC-3, AC-4, AC-9 (security aspect of §8).

- **TC-AND-353-14 — accessibility audit of the members screen.**
  Type: Compose-UI / instrumented. Target: emu35 (verify TalkBack on A15).
  Preconditions: roster rendered with manage controls.
  Steps: run the Compose a11y assertions; enable TalkBack on A15 and traverse.
  Expected: every interactive control (role chip, overflow, Invite FAB, dialog
  options) has a contentDescription/semantics; role chip announces member + role;
  touch targets ≥48dp; error/empty states announced via `liveRegion`; layout is
  RTL-safe and honors dynamic type/dark theme. TalkBack traversal on A15 confirms
  real screen-reader order.
  Traces: AC-2, AC-6, AC-7.

### Coverage matrix

| AC | Covered by |
|----|------------|
| AC-1 (API verbs/paths/bodies) | TC-01, TC-02, TC-03, TC-04 |
| AC-2 (roster lists members) | TC-01, TC-10, TC-14 |
| AC-3 (invite by email + role) | TC-02, TC-06, TC-11, TC-13 |
| AC-4 (change role, persists, rollback) | TC-03, TC-06, TC-08, TC-13 |
| AC-5 (remove member / revoke) | TC-04 |
| AC-6 (manage gating + self-protection) | TC-06, TC-09, TC-10, TC-14 |
| AC-7 (loading/empty/typed-error/offline) | TC-07, TC-08, TC-10, TC-11, TC-12, TC-14 |
| AC-8 (unknown role → UNKNOWN) | TC-05 |
| AC-9 (tests pass in CI; tested req.) | TC-01..TC-14 collectively; security TC-13 |
