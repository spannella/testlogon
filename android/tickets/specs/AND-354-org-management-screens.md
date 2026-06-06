---
id: AND-354
title: Org management screens
milestone: M7
epic: E46
priority: P1
size: L
status: draft
depends_on: [AND-353]
blocks: []
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
- **Web reference:** `frontend/src/api/endpoints/orgs.ts` and shared types in
  `frontend/src/api/types.ts` define the canonical org/member/invite shapes;
  mirror field names and role enum values exactly.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext, unreliable). OpenAPI at `/openapi.json`. Cookie-based session with
  `ui_csrf` echoed as `X-CSRF-Token`; 401 → single `POST /ui/session/refresh`
  then retry (all handled in AND-353's network stack).
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Navigation-Compose,
  Hilt (KSP), Coroutines/Flow, Paging 3 (members list), Coil (org avatars).
  minSdk 24, compileSdk/targetSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.

## 3. Functional Requirements

FR-1 **Org overview.** Show org name, slug, avatar (Coil), plan/tier label,
member count, the current user's own role, and created date. Provide entry
points (tabs or nav rows) to Members and Invites.

FR-2 **Members list.** Paged list of members showing display name, email,
avatar, role chip, and status (active / pending). Sticky search/filter by
name/email. Empty, loading, and error states.

FR-3 **Change role.** From a member row overflow, an authorized actor (role
`owner` or `admin`) can change another member's role via a bottom-sheet role
picker. The action is optimistic-with-rollback: UI updates immediately, reverts
on failure with a snackbar.

FR-4 **Remove member.** Authorized actor can remove a member after a confirm
dialog. The current user cannot remove themselves here; the last `owner` cannot
be removed/demoted (server-enforced; UI surfaces the resulting error).

FR-5 **Invites — list.** Show pending invites: invitee email, intended role,
inviter, created/expiry. Empty state when none.

FR-6 **Invites — create.** Form: email (validated) + role picker. Submit creates
the invite and prepends it to the list. Show resulting invite link/token if the
API returns one.

FR-7 **Invites — revoke.** Per-invite revoke with confirm; removes from list on
success.

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
    val members: Flow<PagingData<OrgMemberUi>>          // Paging 3
    val uiState: StateFlow<OrgMembersUiState>           // header/role-gate/banner state
    fun setQuery(q: String)
    fun changeRole(memberId: String, newRole: OrgRole)
    fun removeMember(memberId: String)
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
enum class OrgRole { OWNER, ADMIN, MEMBER, VIEWER }   // mirror server enum order

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
hoist their `UiState`. Members uses `members.collectAsLazyPagingItems()` inside a
`LazyColumn` with `RoleChangeSheet` (`ModalBottomSheet`) and a
`RemoveMemberDialog` (`AlertDialog`). Invites uses an `InviteCreateCard` plus a
`LazyColumn` of `InviteRow`s. All loading/empty/error scaffolding reuses
`core-ui` components (`StateScaffold`, `StaleBanner`, `ErrorRetry`, `EmptyState`).

### 4.5 Optimistic mutation pattern (members)

`changeRole`/`removeMember` add the `memberId` to `pendingMemberOps`, optimistically
mutate the locally-cached page (via AND-353's Room-backed cache / `PagingSource`
invalidation), call the repository, and on `ApiResult.Failure` re-invalidate the
pager and emit a rollback snackbar.

## 5. API Contract

This ticket performs **no direct HTTP**. All calls go through `OrgRepository`
(AND-353), which owns Retrofit services, the persistent cookie jar, CSRF header
injection, the 20s timeout, idempotent-GET backoff retry, and the 401→refresh→retry
path. The contract below documents the endpoints AND-354 depends on so the
repository surface is unambiguous; if any signature differs, the discrepancy is
resolved in AND-353.

Repository surface consumed:

```kotlin
interface OrgRepository {
    suspend fun getOrg(orgId: String): ApiResult<Org>                 // GET /ui/orgs/{orgId}
    fun membersPager(orgId: String, query: String?): Flow<PagingData<OrgMember>>
                                                                       // GET /ui/orgs/{orgId}/members
    suspend fun changeMemberRole(orgId: String, memberId: String, role: OrgRole): ApiResult<OrgMember>
                                                                       // PATCH /ui/orgs/{orgId}/members/{memberId}
    suspend fun removeMember(orgId: String, memberId: String): ApiResult<Unit>
                                                                       // DELETE /ui/orgs/{orgId}/members/{memberId}
    suspend fun getInvites(orgId: String): ApiResult<List<OrgInvite>> // GET /ui/orgs/{orgId}/invites
    suspend fun createInvite(orgId: String, email: String, role: OrgRole): ApiResult<OrgInvite>
                                                                       // POST /ui/orgs/{orgId}/invites
    suspend fun revokeInvite(orgId: String, inviteId: String): ApiResult<Unit>
                                                                       // DELETE /ui/orgs/{orgId}/invites/{inviteId}
}
```

Representative JSON shapes (mirror `frontend/src/api/types.ts`):

`GET /ui/orgs/{orgId}` →
```json
{ "id": "org_8f2", "name": "Acme QA", "slug": "acme-qa",
  "avatar_url": "https://.../a.png", "plan": "team",
  "member_count": 12, "my_role": "admin", "created_at": "2026-01-04T10:00:00Z" }
```

`GET /ui/orgs/{orgId}/members` (paged) →
```json
{ "items": [ { "id": "mem_31", "user_id": "usr_7", "display_name": "Lee Ng",
  "email": "lee@acme.test", "avatar_url": null, "role": "member",
  "status": "active", "joined_at": "2026-02-01T09:00:00Z" } ],
  "next_cursor": "eyJrIjoibWVtXzMxIn0", "total": 12 }
```

`POST /ui/orgs/{orgId}/invites` body `{ "email": "x@y.test", "role": "member" }` →
```json
{ "id": "inv_55", "email": "x@y.test", "role": "member", "status": "pending",
  "invited_by": "usr_1", "invite_url": "https://.../accept?token=...",
  "created_at": "2026-06-05T12:00:00Z", "expires_at": "2026-06-12T12:00:00Z" }
```

Error body (FastAPI `detail`, mapped by AND-353 to typed errors): `detail` may be
a string, `[{ "msg": "..." }]`, or `{ "code": "...", ... }`. The 422 on invite
create maps to `InviteFormState.emailError`.

## 6. Data & State Management

- **Domain models** (`core-model`, owned with AND-353): `Org`, `OrgMember`,
  `OrgInvite`, `OrgRole`. AND-354 adds UI-only models: `OrgMemberUi`,
  `OrgCapabilities`, `Banner`, `InviteFormState`.
- **Caching:** Members and org profile are Room-backed via AND-353
  (`RemoteMediator`/`PagingSource` for members). On open, the screen renders
  cached data immediately (`isStale = true`) while a background refresh runs;
  on refresh success the banner clears.
- **State exposure:** ViewModels expose `StateFlow<UiState>` started with
  `SharingStarted.WhileSubscribed(5_000)`; paging via `Flow<PagingData<…>>`
  `.cachedIn(viewModelScope)`.
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
- **Paging tests:** `membersPager` emits `PagingData`, search query change
  triggers new pager, snapshot via `asSnapshot {}`.
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
- **R2 — Capability source.** Backend may not return `my_role` on `getOrg`,
  forcing a `/ui/me`-derived membership lookup. *Open Q:* confirm `my_role` is on
  the org payload (owned by AND-353).
- **R3 — Invite link exposure.** Does the API return an `invite_url`/token, and is
  it safe to display? *Open Q:* confirm with backend; if sensitive, show "Invite
  sent" only.
- **R4 — Members pagination shape.** Cursor vs offset and `next_cursor` field name
  must match AND-353's `PagingSource`.
- **R5 — Unreliable dev host** may make UI tests flaky if hitting live backend;
  *Mitigation:* all tests use fakes, no live network.
- **R6 — Last-owner / self-removal rules** are server-enforced; UI only reacts to
  409/403. *Open Q:* exact error `code`s to map to friendly copy.

## 14. Acceptance Criteria

AC-1 Opening an org (`org/{orgId}`) renders Overview with name, slug, avatar,
plan, member count, and the current user's role from `StateFlow<UiState>`.

AC-2 Members screen renders a paged, searchable list with role + status; empty,
loading, stale, offline, and error-with-retry states all reachable and verified
by tests.

AC-3 An `owner`/`admin` can change a member's role via the bottom sheet; the list
reflects the new role without manual refresh; a failed change rolls back and
shows a snackbar.

AC-4 An `owner`/`admin` can remove a member after confirmation; the member
disappears on success; server rejection (e.g., last owner) surfaces the message
and leaves the list unchanged.

AC-5 Invites screen lists pending invites; an authorized user can create an invite
with a validated email + role (prepended on success) and revoke an invite after
confirm (removed on success).

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
