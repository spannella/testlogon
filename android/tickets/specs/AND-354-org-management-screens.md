---
id: AND-354
title: Org management screens
milestone: M7
epic: E46
priority: P1
size: L
depends_on: [AND-353]
blocks: []
status: reviewed
reviewed_on: 2026-06-06
---

# AND-354 — Org management screens

## 1. Overview & Goal

Deliver the Compose UI layer for organization management in the TestLogon native
Android app: an **Org Overview** screen, a **Members** list with role
management, and an **Invites** flow (create, list, revoke). This ticket consumes
the org data/repository layer delivered by **AND-353** (Orgs API +
members/roles, exposing `/ui/orgs/*`); AND-354 owns no networking of its own —
it owns the `feature-org` module: screens, ViewModels, `UiState` models,
navigation wiring, and the role-gated affordances.

Goal: a signed-in user who is a member of one or more orgs can open an org, view
its profile and membership, change a member's role or remove them (when their own
role permits), and create/revoke invites — all rendering correctly under the
loading / empty / stale / offline / error states mandated by the project's
unreliable dev backend.

Success = "Org screens render + manage" (source acceptance): every screen renders
from `StateFlow<UiState>`, every mutating action round-trips through AND-353's
repository and reflects the result in the UI without a manual refresh.

## 2. Context & References

- **Module:** new `feature-org` Gradle module under `android/feature-org`,
  namespace `com.testlogon.android.feature.org`. Layering:
  `app -> feature-org -> core-* (core-data, core-model, core-ui, core-network,
  core-testing)`.
- **Upstream (AND-353):** `OrgRepository` + DTO/domain models + `ApiResult<T>`
  mappings live in `core-data` / `core-network`. AND-354 must not add Retrofit
  service interfaces; if a needed call is missing it is filed back against
  AND-353, not implemented here.
- **Web reference:** `frontend/src/api/endpoints/orgs.ts` defines the canonical
  org/member/invite DTOs (`OrgOut`, `OrgMemberOut`, `OrgInviteOut`) *inline in
  that file* — there are NO org DTOs in `frontend/src/api/types.ts` (verified;
  only unrelated `org_id`/`org` fields appear there). Mirror field names and role
  enum values from `endpoints/orgs.ts` exactly.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext, unreliable). OpenAPI at `/openapi.json`. Auth is a **Bearer access
  token** (`Authorization: Bearer <accessToken>` from the auth store) *plus* the
  `ui_csrf` cookie echoed as `X-CSRF-Token`, *plus* an optional
  `X-IMPERSONATION-TOKEN` header when impersonating (verified in
  `src/api/client.ts`). 401 (only when already authenticated) → single
  `POST /ui/session/refresh` then one retry; an unauthenticated 401 propagates
  directly. All handled in AND-353's network stack. (Correction: the prior draft
  described this as "cookie-based session" only — the Bearer token is the primary
  credential.)
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Navigation-Compose,
  Hilt (KSP), Coroutines/Flow, Coil (org avatars). (Paging 3 is NOT needed —
  the members endpoint returns a flat array; see §5 correction.)
  minSdk 24, compileSdk/targetSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.

## 3. Functional Requirements

FR-1 **Org overview.** Show org name, slug, avatar (Coil), plan/tier label,
member count, the current user's own role, and created date. Provide entry
points (tabs or nav rows) to Members and Invites.

FR-2 **Members list.** List of members showing the member's `user_sub`, role
chip, and status. **Correction:** `GET /ui/orgs/{org_id}/members` returns a flat
JSON array of `OrgMemberOut` (`{ user_sub, org_role, status, joined_at,
storage_used_bytes, last_active_at? }`) — there is **no** server pagination
(no `items`/`next_cursor`/`total`), and members carry **no** `display_name`,
`email`, or `avatar_url` (verified `endpoints/orgs.ts: listMembers` /
`OrgMemberOut`; web `OrgDashboard.tsx` renders only `user_sub` + `org_role`).
The list is therefore rendered from an in-memory list (client-side search/filter
over `user_sub`); Paging 3 is **not** required by the contract. Display-name /
email / avatar enrichment would need a separate profile lookup and is an
**unverified assumption** — out of scope unless AND-353 provides it. Empty,
loading, and error states still apply.

FR-3 **Change role.** From a member row overflow, an authorized actor (role
`owner` or `admin`) can change another member's role via a bottom-sheet role
picker. The action is optimistic-with-rollback: UI updates immediately, reverts
on failure with a snackbar.

FR-4 **Remove member.** Authorized actor can remove a member after a confirm
dialog. The current user cannot remove themselves here; the last `owner` cannot
be removed/demoted (server-enforced; UI surfaces the resulting error).

FR-5 **Invites — list.** **Correction:** there is **no** org-scoped invites-list
endpoint. The only invites-list endpoint is `GET /ui/orgs/invites/pending`, which
returns the **current user's own** pending invitations across all orgs
(`OrgInviteOut[]`), *not* the pending invites issued by a given org. An
org-admin-facing "outstanding invites for this org" list is therefore **not
backed by the current API** — treat it as an unverified assumption and either
(a) omit the org-invites list, or (b) file a new endpoint against AND-353. When a
"my pending invites" surface is wanted, render `OrgInviteOut`
(`{ invite_id, org_id, org_name, email, org_role, status, invited_by, created_at,
expires_at, token? }`) with accept/decline (see FR-7).

FR-6 **Invites — create.** Form: email (validated) + role picker. **Correction:**
invite creation is `POST /ui/orgs/{org_id}/members/invite` with body
`OrgMemberInviteReq` `{ email, org_role? }` (NOT `POST /ui/orgs/{orgId}/invites`,
NOT a `role` field). `email` is required (3–254 chars); `org_role` defaults to
`"member"` and must match `^(admin|member|viewer)$` (you **cannot** invite an
`owner`). Returns `201` + `OrgInviteOut`. The web client does not maintain an
org-invite list to prepend to, so on success refresh/invalidate the members query
(matching `OrgDashboard.tsx`) and surface the returned `token` only if present
(`OrgInviteOut.token?`, not `invite_url`).

FR-7 **Invites — respond / revoke.** **Correction:** there is **no**
`DELETE /ui/orgs/{orgId}/invites/{inviteId}` revoke endpoint. The available
actions on an invite are `POST /ui/orgs/invites/{invite_id}/accept` (body
`{ token }`, `OrgInviteAcceptReq`) and `POST /ui/orgs/invites/{invite_id}/decline`
(no body → `204`). "Revoke" (inviter rescinding an outstanding invite) is **not
in the API** — mark as an unverified assumption / file against AND-353. For the
current user's own pending invites, offer accept/decline; remove from the
in-memory list on success.

FR-8 **Role gating.** All mutating affordances (change role, remove, invite,
revoke) are hidden/disabled for actors whose role lacks the capability.
Capability is derived from the current user's role on *this* org, not a global
role.

FR-9 **Resilience states.** Every screen handles Loading, Content, Empty,
Stale (cached data shown with a banner while a refresh is in flight or failed),
Offline, and Error-with-retry.

## 4. Technical Design

### 4.1 Module & navigation

`feature-org` exposes a nav graph builder consumed by `app`:

```kotlin
const val ORG_GRAPH_ROUTE = "org"

fun NavGraphBuilder.orgGraph(navController: NavController) {
    navigation(startDestination = OrgRoute.Overview.pattern, route = ORG_GRAPH_ROUTE) {
        composable(OrgRoute.Overview.pattern, arguments = OrgRoute.Overview.args) { OrgOverviewScreen(...) }
        composable(OrgRoute.Members.pattern,  arguments = OrgRoute.Members.args)  { OrgMembersScreen(...) }
        composable(OrgRoute.Invites.pattern,  arguments = OrgRoute.Invites.args)  { OrgInvitesScreen(...) }
    }
}

sealed interface OrgRoute {
    val pattern: String
    data object Overview { const val ARG_ORG_ID = "orgId"; val pattern = "org/{orgId}" }
    data object Members  { val pattern = "org/{orgId}/members" }
    data object Invites  { val pattern = "org/{orgId}/invites" }
}
```

`orgId` is a required nav arg on every destination, read via
`SavedStateHandle`.

### 4.2 ViewModels & state

```kotlin
@HiltViewModel
class OrgOverviewViewModel @Inject constructor(
    savedState: SavedStateHandle,
    private val orgRepository: OrgRepository,   // from AND-353
    private val sessionRepository: SessionRepository,
) : ViewModel() {
    private val orgId: String = checkNotNull(savedState[OrgRoute.Overview.ARG_ORG_ID])
    val uiState: StateFlow<OrgOverviewUiState>
    fun refresh()
}

sealed interface OrgOverviewUiState {
    data object Loading : OrgOverviewUiState
    data class Content(
        val org: Org,
        val myRole: OrgRole,
        val capabilities: OrgCapabilities,
        val isStale: Boolean = false,
    ) : OrgOverviewUiState
    data class Error(val message: String, val retryable: Boolean) : OrgOverviewUiState
}
```

```kotlin
@HiltViewModel
class OrgMembersViewModel @Inject constructor(
    savedState: SavedStateHandle,
    private val orgRepository: OrgRepository,
) : ViewModel() {
    // CORRECTION: GET /ui/orgs/{org_id}/members returns a flat array (no cursor),
    // so Paging 3 is NOT required by the contract. Expose the filtered member
    // list inside the StateFlow<UiState> instead of a PagingData stream. If
    // AND-353 still chooses to wrap this in a PagingSource for cache uniformity,
    // it is a single-page, non-cursor source. memberSub is a user sub, not a
    // synthetic mem_ id.
    val uiState: StateFlow<OrgMembersUiState>           // header/role-gate/banner + members
    fun setQuery(q: String)
    fun changeRole(memberSub: String, newRole: OrgRole)
    fun removeMember(memberSub: String)
}

data class OrgMembersUiState(
    val myRole: OrgRole,
    val capabilities: OrgCapabilities,
    val pendingMemberOps: Set<String> = emptySet(),  // memberIds with in-flight mutation
    val banner: Banner? = null,                       // stale/offline/error banner
)
```

```kotlin
@HiltViewModel
class OrgInvitesViewModel @Inject constructor(
    savedState: SavedStateHandle,
    private val orgRepository: OrgRepository,
) : ViewModel() {
    val uiState: StateFlow<OrgInvitesUiState>
    fun refresh()
    fun createInvite(email: String, role: OrgRole)
    fun revokeInvite(inviteId: String)
}

sealed interface OrgInvitesUiState {
    data object Loading : OrgInvitesUiState
    data class Content(
        val invites: List<OrgInvite>,
        val capabilities: OrgCapabilities,
        val createForm: InviteFormState,
        val isStale: Boolean = false,
    ) : OrgInvitesUiState
    data class Error(val message: String, val retryable: Boolean) : OrgInvitesUiState
}

data class InviteFormState(
    val email: String = "",
    val emailError: String? = null,
    val role: OrgRole = OrgRole.MEMBER,
    val submitting: Boolean = false,
)
```

### 4.3 Capability model

Role gating is a pure function on the actor's org role; no extra network call.

```kotlin
// CORRECTION: the server does NOT expose a role enum; it uses string fields.
// `org_role` on OrgOut/OrgMemberOut is read as any of owner|admin|member|viewer,
// but the WRITE side (invite OrgMemberInviteReq.org_role, role-change
// OrgMemberRoleUpdateReq.org_role) is constrained to ^(admin|member|viewer)$ —
// OWNER CANNOT be assigned via invite or change-role (ownership moves only via
// POST /ui/orgs/{org_id}/transfer-ownership). The role picker must therefore
// offer only ADMIN/MEMBER/VIEWER. Treat unknown role strings as VIEWER.
enum class OrgRole { OWNER, ADMIN, MEMBER, VIEWER }   // read-side; OWNER not writable

data class OrgCapabilities(
    val canInvite: Boolean,
    val canChangeRole: Boolean,
    val canRemoveMember: Boolean,
    val canRevokeInvite: Boolean,
) {
    companion object {
        fun of(role: OrgRole) = OrgCapabilities(
            canInvite       = role == OWNER || role == ADMIN,
            canChangeRole   = role == OWNER || role == ADMIN,
            canRemoveMember = role == OWNER || role == ADMIN,
            canRevokeInvite = role == OWNER || role == ADMIN,
        )
    }
}
```

Server remains the source of truth: the UI gate is advisory; any 403 from a
mutation is surfaced as an error and the optimistic change is rolled back.

### 4.4 Composables

`OrgOverviewScreen`, `OrgMembersScreen`, `OrgInvitesScreen` are stateless and
hoist their `UiState`. Members renders the (filtered) `List<OrgMemberUi>` from
`UiState` inside a `LazyColumn` (no `collectAsLazyPagingItems`) with
`RoleChangeSheet` (`ModalBottomSheet`) and a
`RemoveMemberDialog` (`AlertDialog`). Invites uses an `InviteCreateCard` plus a
`LazyColumn` of `InviteRow`s. All loading/empty/error scaffolding reuses
`core-ui` components (`StateScaffold`, `StaleBanner`, `ErrorRetry`, `EmptyState`).

### 4.5 Optimistic mutation pattern (members)

`changeRole`/`removeMember` add the `memberSub` to `pendingMemberOps`,
optimistically mutate the locally-cached member list (via AND-353's Room-backed
cache), call the repository, and on `ApiResult.Failure` re-read from cache/server
to restore server truth and emit a rollback snackbar. (No `PagingSource`
invalidation — the list is not paged; see §5.)

## 5. API Contract

This ticket performs **no direct HTTP**. All calls go through `OrgRepository`
(AND-353), which owns Retrofit services, the persistent cookie jar, CSRF header
injection, the 20s timeout, idempotent-GET backoff retry, and the 401→refresh→retry
path. The contract below documents the endpoints AND-354 depends on so the
repository surface is unambiguous; if any signature differs, the discrepancy is
resolved in AND-353.

Repository surface consumed:

```kotlin
// CORRECTED to match endpoints/orgs.ts + openapi.index.txt. Paths/methods/fields
// below are verified; the prior draft had multiple wrong paths/fields (see §16).
interface OrgRepository {
    suspend fun getOrg(orgId: String): ApiResult<Org>                 // GET    /ui/orgs/{org_id}
    suspend fun listMembers(orgId: String): ApiResult<List<OrgMember>>
                                                                       // GET    /ui/orgs/{org_id}/members  (flat array, NOT paged)
    suspend fun changeMemberRole(orgId: String, memberSub: String, role: OrgRole): ApiResult<OrgMember>
                                                                       // PATCH  /ui/orgs/{org_id}/members/{member_sub}/role   body {org_role}
    suspend fun removeMember(orgId: String, memberSub: String): ApiResult<Unit>
                                                                       // DELETE /ui/orgs/{org_id}/members/{member_sub}  -> 204
    suspend fun inviteMember(orgId: String, email: String, role: OrgRole): ApiResult<OrgInvite>
                                                                       // POST   /ui/orgs/{org_id}/members/invite  body {email, org_role?} -> 201
    suspend fun listMyPendingInvites(): ApiResult<List<OrgInvite>>     // GET    /ui/orgs/invites/pending  (CURRENT USER's invites, no orgId)
    suspend fun acceptInvite(inviteId: String, token: String): ApiResult<Unit>
                                                                       // POST   /ui/orgs/invites/{invite_id}/accept   body {token}
    suspend fun declineInvite(inviteId: String): ApiResult<Unit>      // POST   /ui/orgs/invites/{invite_id}/decline -> 204
    // NOTE: no org-scoped invites list and no invite "revoke" endpoint exist;
    // getInvites(orgId)/createInvite(orgId,...)/revokeInvite(...) from the prior
    // draft are NOT in the API. File against AND-353 if genuinely required.
}
```

Representative JSON shapes — **CORRECTED** to mirror `endpoints/orgs.ts`
(`OrgOut`/`OrgMemberOut`/`OrgInviteOut`). Note: timestamps are **epoch numbers**,
not ISO strings; the org's own field is `org_id` and the caller's role is
`org_role` (not `id`/`my_role`); there is no `avatar_url` on any org DTO.

`GET /ui/orgs/{org_id}` → `OrgOut`:
```json
{ "org_id": "org_8f2", "name": "Acme QA", "description": "QA team",
  "slug": "acme-qa", "owner_user_sub": "usr_1", "status": "active",
  "plan": "team", "member_count": 12, "storage_used_bytes": 0,
  "storage_limit_bytes": 0, "billing_mode": "org",
  "created_at": 1736071200, "updated_at": 1736071200,
  "org_role": "admin", "team_calendar_id": "cal_1" }
```

`GET /ui/orgs/{org_id}/members` → **flat array** of `OrgMemberOut` (no envelope):
```json
[ { "user_sub": "usr_7", "org_role": "member", "status": "active",
    "joined_at": 1738400400, "storage_used_bytes": 0,
    "last_active_at": 1738486800 } ]
```

`POST /ui/orgs/{org_id}/members/invite` body
`{ "email": "x@y.test", "org_role": "member" }` (org_role optional, defaults
`"member"`, regex `^(admin|member|viewer)$`) → `201` + `OrgInviteOut`:
```json
{ "invite_id": "inv_55", "org_id": "org_8f2", "org_name": "Acme QA",
  "email": "x@y.test", "org_role": "member", "status": "pending",
  "invited_by": "usr_1", "created_at": 1749124800, "expires_at": 1749729600,
  "token": "opaque-token-or-omitted" }
```

Error body (FastAPI `detail`, mapped by AND-353 to typed errors): `detail` may be
a string, an array `[{ "msg": "..." }]` (422 validation), or an object
`{ "code": "...", ... }`. Verified against `src/api/client.ts:normalizeErrorDetail`
+ `mapAuthorizationError`: authorization failures use object `detail.code` values
such as `role_required`, `role_required_scope` (with `required_scope`),
`role_required_admin_profile_type`; geo-blocks use `detail.code == "geo_blocked"`.
The 422 on invite create (e.g. malformed/too-short email) maps to
`InviteFormState.emailError`. (Note: at the HTTP layer the web client surfaces a
403 via a global toast and throws `ApiError`; AND-353's Android stack is expected
to return these as typed `ApiResult.Failure` rather than toasting.)

## 6. Data & State Management

- **Domain models** (`core-model`, owned with AND-353): `Org`, `OrgMember`,
  `OrgInvite`, `OrgRole`. AND-354 adds UI-only models: `OrgMemberUi`,
  `OrgCapabilities`, `Banner`, `InviteFormState`.
- **Caching:** Members and org profile are Room-backed via AND-353. **Correction:**
  because `GET /ui/orgs/{org_id}/members` returns a non-paged flat array, no
  `RemoteMediator`/cursor `PagingSource` is needed; cache the full member list per
  org and expose it as a `Flow<List<OrgMember>>`. On open, the screen renders
  cached data immediately (`isStale = true`) while a background refresh runs; on
  refresh success the banner clears.
- **State exposure:** ViewModels expose `StateFlow<UiState>` started with
  `SharingStarted.WhileSubscribed(5_000)`; the members list is carried inside that
  `UiState` (or a `Flow<List<OrgMember>>`), not a `PagingData` stream.
- **Process death:** `orgId` and the members search query survive via
  `SavedStateHandle`. In-flight invite form text is preserved through
  `rememberSaveable` in the composable plus VM-held `InviteFormState`.
- **Single-shot events:** snackbars/navigation use a `Channel`-backed
  `Flow<OrgEvent>` collected with `LaunchedEffect`, not folded into `UiState`.

## 7. Error Handling & Resilience

- **Timeouts/offline:** 20s timeout from AND-353. On network failure with cached
  data → render `Content(isStale = true)` + `StaleBanner("Showing saved data")`.
  Without cache → `Error(retryable = true)` + `ErrorRetry`.
- **Retry:** GETs (org, members, invites) are idempotent → eligible for AND-353's
  bounded backoff. Mutations (PATCH/DELETE/POST) are **never** auto-retried;
  retry is user-initiated only.
- **401:** handled below this layer (refresh-once-then-retry). If refresh fails,
  the repository surfaces an auth error; AND-354 emits an `OrgEvent.SessionExpired`
  that routes to the login flow.
- **403 (insufficient role):** roll back optimistic change, snackbar
  "You don't have permission to do that," and recompute capabilities from a fresh
  `getOrg` (role may have changed server-side).
- **409 / business rules** (e.g., last owner, member already invited): surface the
  server `detail` message verbatim in a snackbar; no rollback needed for reads.
- **Optimistic rollback:** every member mutation re-invalidates the pager on
  failure so the UI returns to server truth.

## 8. Security & Privacy

- No tokens or secrets are handled in `feature-org`; session rides cookies +
  `X-CSRF-Token` managed by AND-353's OkHttp stack. Dev backend is plaintext
  HTTP — usual cleartext-traffic dev config applies; production builds use HTTPS
  only (enforced by the network-security config ticket, not here).
- **Least privilege in UI:** mutating affordances are gated by `OrgCapabilities`;
  server authorization remains authoritative (403 handling above).
- **PII:** member emails/names are displayed to authorized members only and are
  not written to logs (see §10). Invite URLs/tokens are sensitive: never logged,
  not persisted to DataStore, only shown transiently and shareable via the system
  share sheet at user request.
- No analytics on member email content; only hashed/opaque ids if anything.

## 9. Accessibility & i18n

- All interactive controls (role chips, overflow menus, FAB, dialog buttons) have
  `contentDescription` / `Modifier.semantics`. Role-picker bottom sheet items are
  exposed as `Role.RadioButton` with selected state.
- Touch targets ≥ 48dp; respect dynamic type (sp) and dark theme via Material 3
  tokens from `core-ui`.
- Destructive actions (remove member, revoke invite) use a confirm dialog with a
  clearly labeled destructive button and an `announceForAccessibility`-equivalent
  live-region update on completion.
- All user-facing strings live in `feature-org/src/main/res/values/strings.xml`;
  no hardcoded text in composables. Role names are localized via a
  `stringResource` map keyed by `OrgRole`. Dates formatted with the device locale
  via `java.time` + `DateTimeFormatter`. RTL-safe layouts (use start/end).

## 10. Telemetry & Logging

- Screen views: `org_overview_view`, `org_members_view`, `org_invites_view`
  (params: `org_id`, `my_role`).
- Actions: `org_member_role_changed` (`from_role`, `to_role`),
  `org_member_removed`, `org_invite_created` (`role`), `org_invite_revoked`,
  each with `result=success|failure` and `error_code` on failure.
- Logging via the project's `Logger` (Timber-style) at DEBUG for state
  transitions; **never** log emails, names, invite tokens/URLs, or cookies.
  Production tree drops below INFO. Telemetry is fire-and-forget through the
  app-level analytics interface; no new SDK is added by this ticket.

## 11. Testing Strategy

- **Unit (core-testing + Turbine):** `OrgOverviewViewModel`,
  `OrgMembersViewModel`, `OrgInvitesViewModel` against a `FakeOrgRepository`.
  Cover: loading→content; stale-on-cache+failed-refresh; optimistic role change
  success; optimistic role change failure→rollback+event; remove success/failure;
  invite email validation (empty/invalid/valid → `emailError`); create
  success prepends; revoke removes; 403→capability recompute; SessionExpired
  event on refresh failure.
- **Capability tests:** table-driven `OrgCapabilities.of(role)` for all four
  roles.
- **Members-list tests:** `listMembers` maps the flat array to UI models; search
  query filters the in-memory list (no paging). (Prior draft's `PagingData`/
  `asSnapshot` tests are removed — the endpoint is not paged.)
- **Compose UI tests (`createAndroidComposeRule`):** affordance visibility per
  role (admin sees overflow; viewer does not); confirm dialog blocks removal
  until confirmed; role-picker selection invokes VM; empty/error states render
  with correct semantics.
- **Coverage gate:** ViewModel + capability logic ≥ 85% line coverage. All run on
  JDK 17 via Robolectric where instrumentation is not required.

## 12. Dependencies & Sequencing

- **Hard dependency:** **AND-353** must land first (repository, DTO/domain models,
  `ApiResult` mappings, members `PagingSource`/cache, cookie+CSRF network stack).
  AND-354 starts against `FakeOrgRepository` in parallel and integrates when
  AND-353's interface is frozen.
- **Transitive:** AND-353 depends on AND-027 (network/session foundation); core-ui
  state scaffolding components (`StateScaffold`, `StaleBanner`, `ErrorRetry`,
  `EmptyState`) and the app nav host must exist.
- **Blocks:** none recorded in the backlog. Any "accept invite (deep link)" or
  org-switching surface is out of scope here and would be separate tickets in E46.

## 13. Risks & Open Questions

- **R1 — Role enum drift.** Server role set/order may differ from the assumed
  `OWNER/ADMIN/MEMBER/VIEWER`. *Mitigation:* derive enum from
  `frontend/src/api/types.ts` / `/openapi.json` during AND-353; treat unknown
  roles as `VIEWER` (no capabilities).
- **R2 — Capability source.** *RESOLVED:* `OrgOut` includes an optional
  `org_role` field (`endpoints/orgs.ts: OrgOut.org_role`), so the caller's role is
  derivable from `getOrg` without a separate `/ui/me` lookup. Because it is
  optional, treat a missing `org_role` as `VIEWER` (no capabilities).
- **R3 — Invite link exposure.** *RESOLVED:* the API returns an optional
  `token` on `OrgInviteOut` (`endpoints/orgs.ts: OrgInviteOut.token?`) — there is
  no `invite_url`. It is sensitive: never log/persist; if absent show "Invite
  sent" only; if present, share transiently via the system share sheet.
- **R4 — Members pagination shape.** *RESOLVED:* `GET /ui/orgs/{org_id}/members`
  is **not paged** — it returns a flat `OrgMemberOut[]` (no cursor/offset). No
  `PagingSource` is required.
- **R5 — Unreliable dev host** may make UI tests flaky if hitting live backend;
  *Mitigation:* all tests use fakes, no live network.
- **R6 — Last-owner / self-removal rules** are server-enforced; UI only reacts to
  409/403. *Open Q:* exact error `code`s to map to friendly copy.

## 14. Acceptance Criteria

AC-1 Opening an org (`org/{orgId}`) renders Overview with name, slug, avatar,
plan, member count, and the current user's role from `StateFlow<UiState>`.

AC-2 Members screen renders a searchable list (client-side filter over the flat
`OrgMemberOut[]`; not server-paged) with role + status; empty, loading, stale,
offline, and error-with-retry states all reachable and verified by tests.

AC-3 An `owner`/`admin` can change a member's role via the bottom sheet; the list
reflects the new role without manual refresh; a failed change rolls back and
shows a snackbar.

AC-4 An `owner`/`admin` can remove a member after confirmation; the member
disappears on success; server rejection (e.g., last owner) surfaces the message
and leaves the list unchanged.

AC-5 An authorized user can create an invite via
`POST /ui/orgs/{org_id}/members/invite` with a validated email + role
(`admin|member|viewer`); on `201` the members query is refreshed and any returned
`token` is surfaced. (Correction: there is no org-scoped invite *list* and no
invite *revoke* endpoint; "list pending invites" applies only to the current
user's own invites via `GET /ui/orgs/invites/pending`, which support
accept/decline — see §6/§7.)

AC-6 A `member`/`viewer` actor sees **no** mutating affordances; any 403 from the
server rolls back optimistic state and recomputes capabilities.

AC-7 No emails, names, or invite tokens appear in logs; all strings are in
`strings.xml`; interactive controls expose accessibility semantics.

AC-8 Unit + Compose tests pass on JDK 17; ViewModel/capability coverage ≥ 85%.

## 15. Definition of Done

- `feature-org` module builds with AGP 8.7.3 / Gradle 8.9; namespace
  `com.testlogon.android.feature.org`; wired into the app nav host under
  `ORG_GRAPH_ROUTE`.
- All FR-1..FR-9 implemented against `OrgRepository` (AND-353); no Retrofit/HTTP
  code added in this module.
- All `UiState` exposed as `StateFlow`; events via `Channel`; paging
  `cachedIn(viewModelScope)`.
- §11 test suite implemented and green in CI; coverage gate met; `ktlint`/detekt
  clean.
- Accessibility, i18n, telemetry, and logging requirements (§9, §10) satisfied
  and spot-checked with TalkBack on a minSdk-24 device/emulator.
- Open questions R2/R3/R4/R6 resolved with AND-353 owner and reflected in code or
  re-filed as backlog items.
- Code reviewed and merged to `android-port`.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer. Sources:
`openapi.index.txt` (the `METHOD /path | op=..` index), `openapi.pretty.json`
(`components.schemas.<Name>`), and frontend files under `reference/src/`.

1. **Org read endpoint is `GET /ui/orgs/{org_id}` returning `OrgOut`.** VERIFIED —
   `openapi.index.txt: GET /ui/orgs/{org_id} (op=get_org_ui_orgs__org_id__get)`;
   `src/api/endpoints/orgs.ts: getOrg` / `OrgOut`.
2. **`OrgOut` fields are `org_id`, `name`, `description?`, `slug`,
   `owner_user_sub`, `status`, `plan`, `member_count`, `storage_used_bytes`,
   `storage_limit_bytes`, `billing_mode`, `created_at`, `updated_at`, `org_role?`,
   `team_calendar_id?`; timestamps are epoch numbers.** VERIFIED —
   `src/api/endpoints/orgs.ts: OrgOut`. CORRECTED prior draft's `id`/`my_role`/
   `avatar_url`/ISO-string `created_at`.
3. **Caller's own role on an org is `OrgOut.org_role` (optional).** VERIFIED —
   `src/api/endpoints/orgs.ts: OrgOut.org_role`. (Resolves R2.) CORRECTED prior
   `my_role`.
4. **Members endpoint is `GET /ui/orgs/{org_id}/members` returning a flat
   `OrgMemberOut[]` (no pagination envelope).** VERIFIED —
   `openapi.index.txt: GET /ui/orgs/{org_id}/members
   (op=list_members_ui_orgs__org_id__members_get)`;
   `src/api/endpoints/orgs.ts: listMembers` returns `OrgMemberOut[]`; web
   `src/pages/orgs/OrgDashboard.tsx` consumes it as an array. CORRECTED prior
   draft's `{items,next_cursor,total}` paged shape and Paging 3 design.
5. **`OrgMemberOut` fields are `user_sub`, `org_role`, `status`, `joined_at`
   (epoch), `storage_used_bytes`, `last_active_at?` — no `display_name`/`email`/
   `avatar_url`/`id`.** VERIFIED — `src/api/endpoints/orgs.ts: OrgMemberOut`; web
   `OrgDashboard.tsx` renders only `m.user_sub` + `m.org_role`. CORRECTED prior
   member shape.
6. **Change-role endpoint is `PATCH /ui/orgs/{org_id}/members/{member_sub}/role`
   with body `OrgMemberRoleUpdateReq {org_role}` → 200.** VERIFIED —
   `openapi.index.txt: PATCH /ui/orgs/{org_id}/members/{member_sub}/role
   (op=change_member_role_..., req=OrgMemberRoleUpdateReq, resp=200)`;
   `openapi.pretty.json: components.schemas.OrgMemberRoleUpdateReq`;
   `src/api/endpoints/orgs.ts: changeMemberRole`. CORRECTED prior
   `PATCH /ui/orgs/{orgId}/members/{memberId}` (missing `/role`, wrong id name,
   wrong body field `role`).
7. **Remove-member endpoint is `DELETE /ui/orgs/{org_id}/members/{member_sub}`
   → 204.** VERIFIED — `openapi.index.txt: DELETE
   /ui/orgs/{org_id}/members/{member_sub} (op=remove_member_..., resp=204)`;
   `src/api/endpoints/orgs.ts: removeMember`. CORRECTED id name `memberId` →
   `member_sub` (a user sub).
8. **Invite-create endpoint is `POST /ui/orgs/{org_id}/members/invite`, body
   `OrgMemberInviteReq {email, org_role?}` → 201 + `OrgInviteOut`.** VERIFIED —
   `openapi.index.txt: POST /ui/orgs/{org_id}/members/invite
   (op=invite_member_..., req=OrgMemberInviteReq, resp=201)`;
   `openapi.pretty.json: components.schemas.OrgMemberInviteReq`;
   `src/api/endpoints/orgs.ts: inviteMember`. CORRECTED prior
   `POST /ui/orgs/{orgId}/invites` with body field `role`.
9. **`OrgMemberInviteReq`: `email` required (minLength 3, maxLength 254),
   `org_role` optional default `"member"`, regex `^(admin|member|viewer)$`.**
   VERIFIED — `openapi.pretty.json: components.schemas.OrgMemberInviteReq`.
10. **Role write values are constrained to `admin|member|viewer`; `owner` is NOT
    assignable via invite/change-role.** VERIFIED — regex `^(admin|member|viewer)$`
    on both `OrgMemberInviteReq.org_role` and `OrgMemberRoleUpdateReq.org_role`
    (`openapi.pretty.json`). Ownership changes only via `POST
    /ui/orgs/{org_id}/transfer-ownership` (`OrgTransferOwnershipReq`). CORRECTED
    role picker to exclude OWNER. (Partially addresses R1: server uses string
    patterns, not an enum.)
11. **`OrgInviteOut` fields: `invite_id`, `org_id`, `org_name`, `email`,
    `org_role`, `status`, `invited_by`, `created_at` (epoch), `expires_at`
    (epoch), `token?` — there is NO `invite_url`.** VERIFIED —
    `src/api/endpoints/orgs.ts: OrgInviteOut`. CORRECTED prior `invite_url`/`role`/
    ISO-string fields. (Resolves R3.)
12. **There is NO org-scoped invites list and NO invite "revoke" endpoint.**
    VERIFIED by absence in `openapi.index.txt` (only
    `GET /ui/orgs/invites/pending`,
    `POST /ui/orgs/invites/{invite_id}/accept`,
    `POST /ui/orgs/invites/{invite_id}/decline` exist) and
    `src/api/endpoints/orgs.ts` (no `revokeInvite`, no org-scoped invite list).
    CORRECTED prior `GET /ui/orgs/{orgId}/invites`,
    `DELETE /ui/orgs/{orgId}/invites/{inviteId}`.
13. **`GET /ui/orgs/invites/pending` returns the CURRENT USER's pending invites
    (`OrgInviteOut[]`), not a given org's outstanding invites.** VERIFIED —
    `openapi.index.txt: GET /ui/orgs/invites/pending (op=list_pending_invites_...,
    params=user_sub,...)` (no `org_id` path param);
    `src/api/endpoints/orgs.ts: listPendingInvites`.
14. **Accept invite is `POST /ui/orgs/invites/{invite_id}/accept` body
    `OrgInviteAcceptReq {token}`; decline is
    `POST /ui/orgs/invites/{invite_id}/decline` → 204.** VERIFIED —
    `openapi.index.txt` (both ops); `src/api/endpoints/orgs.ts: acceptInvite`
    (`{ token }`), `declineInvite`.
15. **Auth transport: `Authorization: Bearer <accessToken>` + `X-CSRF-Token` from
    the `ui_csrf` cookie + optional `X-IMPERSONATION-TOKEN`.** VERIFIED —
    `src/api/client.ts` (`Authorization` Bearer from `useAuthStore`,
    `getCookie("ui_csrf")` → `X-CSRF-Token`, `X-IMPERSONATION-TOKEN` from
    impersonation store). CORRECTED prior "cookie-based session" only.
16. **401 handling: refresh once via `POST /ui/session/refresh` then retry, only
    when already authenticated; otherwise propagate.** VERIFIED —
    `src/api/client.ts: refreshSession` + the 401 branch (guards on
    `isAuthenticated`, single in-flight `refreshPromise`, one retry, logout on
    second 401).
17. **Error body shapes: `detail` may be a string, an array `[{msg}]` (422), or an
    object with `code` (`role_required`, `role_required_scope` with
    `required_scope`, `role_required_admin_profile_type`, `geo_blocked`).**
    VERIFIED — `src/api/client.ts: normalizeErrorDetail` + `mapAuthorizationError`;
    422 schema is `HTTPValidationError` (`openapi.index.txt` resp on every org op).
18. **Web invite UI sends only `{ email }` (role omitted → server default
    `member`) and on success invalidates the members query (no separate invite
    list).** VERIFIED — `src/pages/orgs/OrgDashboard.tsx: inviteMut`
    (`inviteMember(orgId, { email })`, `invalidateQueries(["org-members"])`).
19. **Navigation/module design (`feature-org`, nav-graph, Hilt VMs, Compose M3,
    `SavedStateHandle`, `StateFlow` + `WhileSubscribed`, `Channel` events).**
    UNVERIFIED-ASSUMPTION — Android architecture choices not derivable from
    backend/frontend sources; standard Jetpack patterns
    (framework ref: https://developer.android.com/topic/architecture and
    https://developer.android.com/jetpack/compose/state).
20. **Last-owner / self-removal rules are server-enforced and surfaced via
    403/409.** UNVERIFIED-ASSUMPTION — no explicit error `code` strings for these
    found in the sources; exact codes (R6) remain open and must be confirmed with
    AND-353/backend.

### Corrections made

- **§2:** Auth corrected from "cookie-based session" to Bearer access token +
  `X-CSRF-Token` (+ optional `X-IMPERSONATION-TOKEN`); noted org DTOs live in
  `endpoints/orgs.ts`, not `types.ts`. (Claims 15, 2.)
- **§2/§4.2/§4.4/§4.5/§6/§11:** Removed the Paging-3 design for members — the
  endpoint returns a flat array. (Claim 4.)
- **§4.2/§4.3/FR-6:** Role picker restricted to `admin|member|viewer`; OWNER not
  writable. (Claim 10.)
- **§5 repository surface:** Corrected change-role path (`/role` suffix +
  `member_sub`), invite path (`/members/invite`) and body field (`org_role`),
  member id naming, and removed nonexistent org-invite list/create/revoke;
  replaced with the real `invites/pending` + accept/decline + transfer-ownership
  surface. (Claims 6, 7, 8, 12, 13, 14.)
- **§5 JSON shapes:** Corrected `OrgOut`/`OrgMemberOut`/`OrgInviteOut` field names,
  epoch timestamps, flat members array, and `token?` (not `invite_url`). (Claims
  2, 5, 11.)
- **FR-2/FR-5/FR-6/FR-7:** Rewrote to match the actual endpoints; flagged
  display-name/email/avatar enrichment, org-invite list, and invite revoke as
  unverified/out-of-scope. (Claims 4, 5, 12.)
- **§13 R2/R3/R4:** Resolved using the verified sources.
- **§14 AC-2/AC-5:** De-scoped "paged" and "revoke" claims.
- **Frontmatter:** removed duplicate `status: draft`; set `status: reviewed`,
  added `reviewed_on: 2026-06-06`.

### Open assumptions

- **Member display enrichment (name/email/avatar).** `OrgMemberOut` exposes only
  `user_sub`; the web app shows the raw `user_sub`. Showing human-friendly member
  identity needs a separate profile/`/ui/me`-style lookup not covered here — UNVERIFIED;
  treat as out-of-scope pending an AND-353-provided enrichment endpoint.
- **Org-admin view of outstanding invites & invite revoke.** No API exists
  (Claim 12). Either omit these affordances or file new endpoints against AND-353.
- **Last-owner / self-removal error codes (R6).** Server-enforced but exact
  `detail.code` strings are not in the available sources; map to friendly copy
  only after confirmation.
- **`status` value sets** for `OrgOut.status` / `OrgMemberOut.status` /
  `OrgInviteOut.status` are free-form strings in the DTOs (no enum/pattern in the
  schema); exact values (e.g. `active`/`pending`) are assumed and should be
  confirmed.
- **All Android framework/architecture choices** (Compose, Hilt, navigation,
  StateFlow patterns) are not derivable from the backend/frontend sources
  (framework ref above).

## 17. Test Plan

IDs `TC-AND-354-NN`. "Test target" names the CI/dev target. Most logic is
ViewModel/mapper/capability code that runs as JVM/Robolectric unit tests;
contract tests use MockWebServer against AND-353's client; UI tests run on the
headless emulator AVD `test35` (API 35). One accessibility pass is called out on
the **physical device** (Samsung Galaxy A15 5G, API 34) to validate real TalkBack
behavior and arm64/API-34 vs x86/API-35 rendering. No case hits the live dev
backend.

- **TC-AND-354-01 — Overview happy path.** Type: unit (JVM/Robolectric).
  Target: JVM unit. Preconditions: `FakeOrgRepository.getOrg` returns an `OrgOut`
  with `org_role="admin"`. Steps: collect `OrgOverviewViewModel.uiState`; let it
  load. Expected: emits `Loading` then `Content` with name/slug/plan/
  `member_count` and `myRole=ADMIN`; `created_at` (epoch) formatted via
  `DateTimeFormatter`. Traces: AC-1.

- **TC-AND-354-02 — Overview missing `org_role` defaults to VIEWER.** Type: unit.
  Target: JVM unit. Preconditions: `getOrg` returns `OrgOut` with `org_role`
  absent/unknown. Steps: collect state. Expected: `myRole=VIEWER`,
  `capabilities` all false (no mutating affordances). Traces: AC-1, AC-6.

- **TC-AND-354-03 — Members list maps flat array + client-side search.** Type:
  unit. Target: JVM unit. Preconditions: `listMembers` returns an
  `OrgMemberOut[]` of 3 (varying `org_role`/`status`). Steps: load; call
  `setQuery` matching one `user_sub`. Expected: list mapped to UI models (role
  chip + status), filtered to the matching member; no paging types involved.
  Traces: AC-2.

- **TC-AND-354-04 — Members contract test against real shapes.** Type:
  contract/MockWebServer. Target: JVM unit (MockWebServer). Preconditions:
  MockWebServer enqueues a flat JSON array body (per §5) for
  `GET /ui/orgs/{org_id}/members`. Steps: invoke the repository/mapper. Expected:
  parses without an envelope; fields `user_sub/org_role/status/joined_at` map
  correctly; epoch `joined_at` parsed as a number. Traces: AC-2.

- **TC-AND-354-05 — Change role success (optimistic), correct path/body.** Type:
  contract/MockWebServer. Target: JVM unit (MockWebServer). Preconditions:
  MockWebServer returns 200 for
  `PATCH /ui/orgs/{org_id}/members/{member_sub}/role`. Steps: call
  `changeRole(memberSub, ADMIN)`. Expected: request path ends `/role`, method
  PATCH, JSON body `{"org_role":"admin"}`; UI updates optimistically and settles
  on success; member id used is the `user_sub`. Traces: AC-3.

- **TC-AND-354-06 — Change role failure rolls back + snackbar.** Type: unit.
  Target: JVM unit. Preconditions: `FakeOrgRepository.changeMemberRole` returns
  `ApiResult.Failure`. Steps: trigger change; observe state + event channel.
  Expected: optimistic change reverts to server truth; a rollback snackbar
  `OrgEvent` is emitted; `pendingMemberOps` cleared. Traces: AC-3.

- **TC-AND-354-07 — Remove member success → 204.** Type: contract/MockWebServer.
  Target: JVM unit (MockWebServer). Preconditions: MockWebServer returns 204 for
  `DELETE /ui/orgs/{org_id}/members/{member_sub}`. Steps: call
  `removeMember(memberSub)` after confirm. Expected: DELETE to the correct path;
  member removed from the list; `ApiResult.Success(Unit)`. Traces: AC-4.

- **TC-AND-354-08 — Remove rejected (last owner / 409) leaves list unchanged.**
  Type: contract/MockWebServer. Target: JVM unit (MockWebServer). Preconditions:
  MockWebServer returns 409 with body `{"detail":"Cannot remove the last owner"}`
  (or `{"detail":{"code":"..."}}`). Steps: attempt remove. Expected: server
  `detail` surfaced verbatim in a snackbar; member stays in the list; no rollback
  artifacts. Traces: AC-4.

- **TC-AND-354-09 — Invite create happy path (correct endpoint/body).** Type:
  contract/MockWebServer. Target: JVM unit (MockWebServer). Preconditions:
  MockWebServer returns 201 + an `OrgInviteOut` (with `token`). Steps: submit
  email `x@y.test`, role `member`. Expected: `POST
  /ui/orgs/{org_id}/members/invite` with body `{"email":"x@y.test",
  "org_role":"member"}`; on success the members query refreshes and the returned
  `token` is exposed for the share sheet (never `invite_url`). Traces: AC-5.

- **TC-AND-354-10 — Invite email validation + 422 mapping.** Type: unit
  (+ MockWebServer for the 422 leg). Target: JVM unit. Preconditions: empty,
  malformed (`"abc"`), and a server 422 array `[{"msg":"value is not a valid
  email address"}]`. Steps: submit each. Expected: client-side empty/invalid set
  `InviteFormState.emailError` without a request; the 422 maps the normalized
  message into `emailError`. Traces: AC-5.

- **TC-AND-354-11 — Role picker excludes OWNER.** Type: unit. Target: JVM unit.
  Preconditions: open the role picker / build options. Steps: enumerate
  selectable roles for invite and change-role. Expected: only ADMIN/MEMBER/VIEWER
  offered (server regex `^(admin|member|viewer)$`); OWNER never selectable.
  Traces: AC-3, AC-5.

- **TC-AND-354-12 — Capability table for all roles.** Type: unit (table-driven).
  Target: JVM unit. Preconditions: none. Steps: `OrgCapabilities.of(role)` for
  OWNER/ADMIN/MEMBER/VIEWER. Expected: OWNER+ADMIN → all caps true; MEMBER+VIEWER
  → all false. Traces: AC-6.

- **TC-AND-354-13 — 403 on mutation rolls back + recomputes capabilities.** Type:
  contract/MockWebServer. Target: JVM unit (MockWebServer). Preconditions:
  role-change returns 403 `{"detail":{"code":"role_required"}}`, and a subsequent
  `getOrg` returns a downgraded `org_role`. Steps: attempt change. Expected:
  optimistic change rolled back; "no permission" snackbar; capabilities
  recomputed from the fresh `getOrg`. Traces: AC-6.

- **TC-AND-354-14 — Offline / flaky dev host → stale banner then error-retry.**
  Type: unit (+ MockWebServer for the timeout leg). Target: JVM unit.
  Preconditions: (a) cache present + network failure; (b) no cache + network
  failure/timeout. Steps: open Members/Overview offline. Expected: (a)
  `Content(isStale=true)` + `StaleBanner`; (b) `Error(retryable=true)` +
  `ErrorRetry`; GETs eligible for AND-353 backoff, mutations never auto-retried.
  Traces: AC-2.

- **TC-AND-354-15 — Compose UI: affordance gating + confirm dialog + a11y
  semantics.** Type: Compose-UI (instrumented). Target: headless emulator AVD
  `test35` (API 35). Preconditions: VM seeded once as ADMIN, once as VIEWER.
  Steps: render Members; open member overflow; open the role-picker sheet; trigger
  remove. Expected: ADMIN sees overflow/role-change/remove; VIEWER sees none;
  remove blocked until the confirm dialog is accepted; role-picker items expose
  `Role.RadioButton` + selected state; destructive button labeled; touch targets
  ≥48dp. Traces: AC-2, AC-3, AC-4, AC-6, AC-7.

- **TC-AND-354-16 — TalkBack accessibility pass on physical device.** Type:
  instrumented/e2e (accessibility). Target: **PHYSICAL DEVICE** Samsung Galaxy
  A15 5G (SM-A156U, API 34, arm64) — MUST run on the device to validate real
  TalkBack focus order/announcements and arm64/API-34 rendering vs emulator API
  35. Preconditions: app installed; TalkBack enabled. Steps: navigate
  Overview→Members→invite flow with TalkBack; perform a remove and observe the
  live-region completion announcement. Expected: all interactive controls are
  reachable and announced with meaningful labels; destructive completion is
  announced; no unlabeled controls. Traces: AC-7.

- **TC-AND-354-17 — No PII/tokens in logs.** Type: unit/instrumented. Target:
  JVM unit (log capture). Preconditions: run invite create + members load with a
  captured `Logger`. Steps: exercise flows; inspect emitted logs. Expected: no
  emails, `user_sub`-linked names, invite `token`s, or cookies appear in logs;
  state-transition logs only. Traces: AC-7.

- **TC-AND-354-18 — SessionExpired routing on refresh failure.** Type: unit.
  Target: JVM unit. Preconditions: repository surfaces an auth error after a
  failed refresh (per §7). Steps: trigger a load that 401s and whose refresh
  fails. Expected: `OrgEvent.SessionExpired` emitted; navigation routes to login;
  no infinite retry. Traces: AC-1, AC-2.

### Coverage matrix

| Acceptance criterion | Covered by |
| --- | --- |
| AC-1 Overview renders from `StateFlow` | TC-01, TC-02, TC-18 |
| AC-2 Members list + states (loading/empty/stale/offline/error) | TC-03, TC-04, TC-14, TC-15, TC-18 |
| AC-3 Change role + optimistic rollback | TC-05, TC-06, TC-11, TC-15 |
| AC-4 Remove member + server rejection | TC-07, TC-08, TC-15 |
| AC-5 Invite create (validated) | TC-09, TC-10, TC-11 |
| AC-6 Role gating + 403 rollback/recompute | TC-02, TC-12, TC-13, TC-15 |
| AC-7 No PII in logs, strings.xml, a11y semantics | TC-15, TC-16, TC-17 |
| AC-8 Unit + Compose green on JDK 17, ≥85% coverage | TC-01..TC-14 (JVM/Robolectric) + TC-15 (Compose) satisfy the suite; coverage gate enforced in CI |
