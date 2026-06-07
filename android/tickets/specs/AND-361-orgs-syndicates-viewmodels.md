---
id: AND-361
title: Orgs/syndicates ViewModels
milestone: M7
epic: E46
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-353, AND-356]
blocks: [AND-354, AND-362]
---

# AND-361 — Orgs/syndicates ViewModels

## 1. Overview & Goal

This ticket delivers the **state layer** (Hilt-injected `ViewModel`s and their
`UiState` contracts) that sits between the orgs/syndicates repositories
(AND-353 for `/ui/orgs/*`, AND-356 for `/ui/syndicates/*`) and the Compose
screens (AND-354). The scope per the backlog is explicitly **State** and the
acceptance is **Unit-tested** — this ticket produces no Compose UI and no
networking code of its own; it consumes the repositories defined upstream and
exposes immutable, observable `StateFlow<UiState>` surfaces plus intent-style
action functions.

Goal: provide a complete, deterministic, fully unit-tested presentation layer
for the organization and syndicate features so that AND-354 (org management
screens) can bind directly to it without inventing its own state handling, and
so AND-362 (orgs/syndicates tests) extends rather than replaces the test suite
seeded here.

Concretely this ticket ships, in module `feature-orgs`:

- `OrgListViewModel`, `OrgDetailViewModel`, `OrgMembersViewModel`,
  `OrgInviteViewModel` (orgs domain — AND-353).
- `SyndicateListViewModel`, `SyndicateDetailViewModel` (syndicates domain —
  AND-356; covers overview, treasury, revenue-split read views).
- The matching sealed `*UiState` types and `*Action`/event channels.
- A complete unit-test suite (Turbine + `kotlinx-coroutines-test`) using fakes
  of the repository interfaces.

## 2. Context & References

- **Module:** `feature-orgs` (depends on `core-data`, `core-model`,
  `core-ui`, `core-testing`). Package root
  `com.testlogon.android.feature.orgs`.
- **Upstream repositories (already defined):**
  - AND-353 — `com.testlogon.android.core.data.repository.OrgRepository`
    (`/ui/orgs/*`, members/invite/role).
  - AND-356 — `com.testlogon.android.core.data.repository.SyndicateRepository`
    (`/ui/syndicates/*` feed, treasury, revenue-split).
- **Downstream consumers:** AND-354 (org management screens), AND-362 (tests).
- **Web reference:** `frontend/src/api/endpoints/orgs.ts`,
  `frontend/src/api/endpoints/syndicates.ts`, shared types in
  `frontend/src/api/types.ts`. Mirror the field names there for the
  `core-model` DTOs consumed here.
- **Conventions (project-wide):** ViewModels expose `StateFlow<UiState>`;
  repositories return typed `ApiResult<T>`; FastAPI `detail` errors are mapped
  to `AppError` in `core-network` and surfaced as user-facing strings. The dev
  backend `http://18.222.237.167:8000` is unreliable; resilience (timeouts,
  bounded retry for idempotent GETs) lives in `core-network`/the repositories,
  but this layer must render `Loading`/`Error`/`Stale`/`Empty` states correctly.

## 3. Functional Requirements

**Orgs**

- FR-1 **Org list.** Expose the caller's organizations. Support pull-to-refresh
  (re-fetch) and a retry action after failure. Distinguish `Empty` (member of
  no orgs) from `Error`.
- FR-2 **Org detail.** Given an `orgId`, expose org overview (name, slug, plan,
  member count, the caller's role) plus the loaded members page.
- FR-3 **Members.** Expose a paged/refreshable member list with each member's
  role. Provide a `changeRole(memberId, role)` action and a
  `removeMember(memberId)` action; both optimistically update list state and
  roll back on failure, emitting a one-shot error event.
- FR-4 **Invites.** Expose pending invites (from the caller-scoped
  `GET /ui/orgs/invites/pending`, filtered to this org) and a
  `sendInvite(email, role)` action with inline field validation (valid email,
  role from the allowed write set `admin/member/viewer`).
  **CORRECTED:** there is **no** backend revoke-invite endpoint, so a
  `revokeInvite(inviteId)` action is **out of scope** for this ticket (it cannot
  call anything). It is removed; if product needs revoke, a backend endpoint must
  be added first (tracked as an open assumption in §16).
- FR-5 **Role gating.** The detail/members/invite states must carry the
  caller's role (`OrgRole`) so screens can enable/disable management controls;
  the ViewModel rejects management actions when the caller lacks `ADMIN`/`OWNER`
  and emits a `NotAuthorized` event rather than calling the API.

**Syndicates**

- FR-6 **Syndicate list.** Expose syndicates the caller belongs to, with
  refresh + retry, `Empty` vs `Error`.
- FR-7 **Syndicate detail.** Given a `syndicateId`, expose overview, the
  treasury summary (`balance_cents`, `currency`), and the revenue-split **config**
  (mode + `weights_bps` map, `platform_fee_bps`). **CORRECTED:** these come from
  **three separate** backend GETs (`/ui/syndicates/{id}`,
  `/ui/syndicates/treasury/{id}`, `/ui/syndicates/revenue-split/{id}/config`),
  not one call — the ViewModel `combine`s them into one `SyndicateDetailUiState`.
  Revenue split is a config object, not a per-member share table. All
  **read-only** in this milestone.
- FR-8 All ViewModels survive configuration changes (state held in `ViewModel`,
  arguments read once from `SavedStateHandle`).

## 4. Technical Design

All ViewModels are `@HiltViewModel`, constructor-inject the relevant repository
and a `SavedStateHandle`, and run work in `viewModelScope`. State is produced
with `MutableStateFlow` exposed as a read-only `StateFlow`; one-shot effects use
a `Channel(Channel.BUFFERED)` exposed as `receiveAsFlow()`.

```kotlin
package com.testlogon.android.feature.orgs.viewmodel

@HiltViewModel
class OrgListViewModel @Inject constructor(
    private val orgRepository: OrgRepository,
) : ViewModel() {

    private val _state = MutableStateFlow(OrgListUiState())
    val state: StateFlow<OrgListUiState> = _state.asStateFlow()

    init { load(initial = true) }

    fun onAction(action: OrgListAction) = when (action) {
        OrgListAction.Refresh -> load(initial = false)
        OrgListAction.Retry   -> load(initial = true)
    }

    private fun load(initial: Boolean) {
        _state.update {
            it.copy(isLoading = initial, isRefreshing = !initial, error = null)
        }
        viewModelScope.launch {
            when (val r = orgRepository.listOrgs()) {
                is ApiResult.Success -> _state.update {
                    it.copy(
                        orgs = r.data, isLoading = false,
                        isRefreshing = false, isStale = false, error = null,
                    )
                }
                is ApiResult.Failure -> _state.update {
                    it.copy(
                        isLoading = false, isRefreshing = false,
                        isStale = it.orgs.isNotEmpty(),
                        error = r.error.toMessage(),
                    )
                }
            }
        }
    }
}
```

The detail/members ViewModel reads its key from `SavedStateHandle` and combines
overview + members so the screen has a single source of truth:

```kotlin
@HiltViewModel
class OrgMembersViewModel @Inject constructor(
    private val orgRepository: OrgRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val orgId: String = checkNotNull(savedStateHandle["orgId"])

    private val _state = MutableStateFlow(OrgMembersUiState(orgId = orgId))
    val state: StateFlow<OrgMembersUiState> = _state.asStateFlow()

    private val _events = Channel<OrgEvent>(Channel.BUFFERED)
    val events: Flow<OrgEvent> = _events.receiveAsFlow()

    fun onAction(action: OrgMembersAction) { /* Refresh / ChangeRole / Remove / Invite */ }

    private fun changeRole(memberId: String, role: OrgRole) {
        val caller = _state.value.callerRole
        if (!caller.canManage) {
            _events.trySend(OrgEvent.NotAuthorized); return
        }
        val snapshot = _state.value.members
        _state.update { it.copy(members = it.members.withRole(memberId, role)) } // optimistic
        viewModelScope.launch {
            // NOTE: memberId here IS the member's user_sub — the backend keys
            // role change / removal by member_sub, not an opaque membership id.
            when (val r = orgRepository.changeMemberRole(orgId, memberId, role)) {
                is ApiResult.Success -> _events.trySend(OrgEvent.RoleChanged(memberId, role))
                is ApiResult.Failure -> {
                    _state.update { it.copy(members = snapshot) }            // rollback
                    _events.trySend(OrgEvent.ActionFailed(r.error.toMessage()))
                }
            }
        }
    }
}
```

`OrgInviteViewModel.sendInvite` validates locally before any network call:

```kotlin
fun sendInvite(email: String, role: OrgRole) {
    val emailError = if (!email.isValidEmail()) R.string.err_invalid_email else null
    if (emailError != null) { _state.update { it.copy(emailError = emailError) }; return }
    if (!_state.value.callerRole.canManage) { _events.trySend(OrgEvent.NotAuthorized); return }
    _state.update { it.copy(isSubmitting = true, emailError = null) }
    viewModelScope.launch { /* orgRepository.invite(orgId, email, role) -> update/event */ }
}
```

Syndicate ViewModels follow the identical shape; `SyndicateDetailViewModel`
loads overview/treasury/revenue-split via **three** AND-356 repository calls —
`getSyndicate(id)`, `getTreasury(id)`, `getRevenueSplit(id)` — combined
(`coroutineScope { async … }` / `combine`) into one `SyndicateDetailUiState`
(see §13 R1, now realized). A partial failure (e.g. treasury 403 for non-admins)
must degrade gracefully: surface the parts that loaded and mark the missing part,
rather than failing the whole screen. No write actions are defined for syndicates
in this milestone.

`OrgRole.canManage` is `this == OrgRole.OWNER || this == OrgRole.ADMIN`.

## 5. API Contract

This ticket does **not** define or call HTTP endpoints directly — all network
access is delegated to `OrgRepository` (AND-353) and `SyndicateRepository`
(AND-356). The contract below documents only the **repository interfaces this
ticket consumes** (owned upstream) so the state mapping is unambiguous.

```kotlin
interface OrgRepository {                                   // AND-353
    suspend fun listOrgs(): ApiResult<List<Org>>            // GET /ui/orgs (resp: OrgOut[])
    suspend fun getOrg(orgId: String): ApiResult<OrgDetail> // GET /ui/orgs/{org_id} (resp: OrgOut)
    suspend fun listMembers(orgId: String): ApiResult<List<OrgMember>>      // GET /ui/orgs/{org_id}/members (resp: OrgMemberOut[])
    // CORRECTED: there is NO org-scoped pending-invites endpoint. Pending invites
    // are caller-scoped: GET /ui/orgs/invites/pending -> OrgInviteOut[]. The org
    // detail/members surface therefore shows pending invites filtered by org_id.
    suspend fun listPendingInvites(): ApiResult<List<OrgInvite>>            // GET /ui/orgs/invites/pending
    // CORRECTED: invite path is /members/invite, req=OrgMemberInviteReq{email, org_role}.
    suspend fun invite(orgId: String, email: String, role: OrgRole): ApiResult<OrgInvite>    // POST /ui/orgs/{org_id}/members/invite
    // CORRECTED: there is NO revoke-invite (DELETE) endpoint in the backend. The
    // inviter cannot revoke; only the invitee can accept/decline
    // (POST /ui/orgs/invites/{invite_id}/accept|decline). revokeInvite() must be
    // dropped from this ticket's surface — see §16 corrections and FR-4.
    // CORRECTED: role change is keyed by member_sub (user_sub), path ends /role,
    // req=OrgMemberRoleUpdateReq{org_role}.
    suspend fun changeMemberRole(orgId: String, memberSub: String, role: OrgRole): ApiResult<OrgMember> // PATCH /ui/orgs/{org_id}/members/{member_sub}/role
    // CORRECTED: removal is keyed by member_sub (user_sub), not an opaque member id.
    suspend fun removeMember(orgId: String, memberSub: String): ApiResult<Unit>               // DELETE /ui/orgs/{org_id}/members/{member_sub}
}

interface SyndicateRepository {                             // AND-356
    // CORRECTED: list returns SyndicateUserEntry[] (membership entries), not Syndicate[].
    suspend fun listSyndicates(): ApiResult<List<Syndicate>>            // GET /ui/syndicates (resp: SyndicateUserEntry[])
    // CORRECTED: GET /ui/syndicates/{syndicate_id} returns SyndicateOut ONLY — it
    // does NOT include treasury or revenue-split. Those are SEPARATE endpoints:
    //   GET /ui/syndicates/treasury/{syndicate_id}            -> SyndicateTreasuryBalanceOut
    //   GET /ui/syndicates/revenue-split/{syndicate_id}/config -> SplitConfigOut
    // R1 (§13) is therefore REALIZED: SyndicateDetailUiState must be assembled from
    // three repository calls (combine), not one. See §16.
    suspend fun getSyndicate(id: String): ApiResult<SyndicateDetail>    // GET /ui/syndicates/{syndicate_id} (resp: SyndicateOut)
    suspend fun getTreasury(id: String): ApiResult<SyndicateTreasury>   // GET /ui/syndicates/treasury/{syndicate_id}
    suspend fun getRevenueSplit(id: String): ApiResult<SplitConfig>     // GET /ui/syndicates/revenue-split/{syndicate_id}/config
}
```

Representative `core-model` shapes (mirror `frontend/src/api/types.ts`; backend
returns snake_case mapped to camelCase via Moshi adapters in `core-network`):

CORRECTED to match `OrgOut`/`OrgMemberOut`/`OrgInviteOut` in
`src/api/endpoints/orgs.ts` and the OpenAPI schemas. Field key is `org_role`
(NOT `role`/`my_role`); the org/member identity key is `org_id`/`user_sub` (NOT
`id`/`user_id`); timestamps are epoch **numbers** (NOT ISO strings); members
carry no `display_name`/`email` (those live on the invite / a separate profile
lookup).

```jsonc
// OrgOut (list item AND detail — same schema; getOrg returns one OrgOut)
{ "org_id": "org_123", "name": "Acme", "description": "...", "slug": "acme",
  "owner_user_sub": "u_1", "status": "active", "plan": "pro",
  "member_count": 12, "storage_used_bytes": 0, "storage_limit_bytes": 0,
  "billing_mode": "central", "created_at": 1714560000, "updated_at": 1714560000,
  "org_role": "admin" }                 // org_role = the CALLER's role (optional)

// OrgMemberOut
{ "user_sub": "u_42", "org_role": "member", "status": "active",
  "joined_at": 1714560000, "storage_used_bytes": 0, "last_active_at": 1717200000 }

// OrgInviteOut (from GET /ui/orgs/invites/pending; caller-scoped, filter by org_id)
{ "invite_id": "inv_3", "org_id": "org_123", "org_name": "Acme",
  "email": "new@x.io", "org_role": "member", "status": "pending",
  "invited_by": "u_1", "created_at": 1717200000, "expires_at": 1717800000 }

// Syndicate detail is ASSEMBLED from 3 calls (see §5 repo interface above):
// SyndicateOut (overview) + SyndicateTreasuryBalanceOut + SplitConfigOut.
// SyndicateTreasuryBalanceOut:
{ "syndicate_id": "syn_7", "balance_cents": 1425000, "currency": "USD",
  "total_deposited_cents": 0, "total_disbursed_cents": 0, "updated_at": 1717200000 }
// SplitConfigOut (revenue split is a CONFIG, not a per-member table):
{ "mode": "equal", "weights_bps": { "u_42": 4000 }, "platform_fee_bps": 1500,
  "performance_metric": "", "performance_window_days": 30,
  "updated_at": 0, "updated_by": "" }
```

`OrgRole` enum: the backend **settable** vocabulary is `admin | member | viewer`
only (OpenAPI `OrgMemberInviteReq.org_role` / `OrgMemberRoleUpdateReq.org_role`
pattern `^(admin|member|viewer)$`). `owner` is a real role (an org has exactly
one `owner_user_sub`) but is **not** a value you can PATCH to — ownership moves
via `POST /ui/orgs/{org_id}/transfer-ownership`. So model
`OrgRole { OWNER, ADMIN, MEMBER, VIEWER }` for *reading* the caller's/members'
role, but constrain *writes* (changeRole/invite) to `ADMIN | MEMBER | VIEWER`.
Moshi `@Json` maps lower-case strings; unknown values map to `VIEWER`.
(Confirmed: NO `BILLING`/`MANAGER` role exists — resolves R2.) FastAPI `detail`
mapping (`string | [{msg}] | {code,...}`) is handled in `core-network` and
reaches this layer as `ApiResult.Failure(AppError)`.

## 6. Data & State Management

State classes are immutable `data class`es; collections are `kotlinx`
`ImmutableList` where exposed to Compose to preserve recomposition stability.

```kotlin
data class OrgListUiState(
    val orgs: ImmutableList<Org> = persistentListOf(),
    val isLoading: Boolean = false,
    val isRefreshing: Boolean = false,
    val isStale: Boolean = false,        // showing cached data after a failed refresh
    val error: String? = null,
) { val isEmpty get() = orgs.isEmpty() && !isLoading && error == null }

data class OrgMembersUiState(
    val orgId: String,
    val callerRole: OrgRole = OrgRole.VIEWER,
    val members: ImmutableList<OrgMember> = persistentListOf(),
    val invites: ImmutableList<OrgInvite> = persistentListOf(),
    val isLoading: Boolean = false,
    val isRefreshing: Boolean = false,
    val pendingMemberIds: ImmutableSet<String> = persistentSetOf(), // in-flight optimistic ops
    val error: String? = null,
)

data class OrgInviteUiState(
    val isSubmitting: Boolean = false,
    @StringRes val emailError: Int? = null,
)

data class SyndicateDetailUiState(
    val syndicateId: String,
    val detail: SyndicateDetail? = null,
    val isLoading: Boolean = false,
    val isRefreshing: Boolean = false,
    val isStale: Boolean = false,
    val error: String? = null,
)

sealed interface OrgEvent {
    data class RoleChanged(val memberId: String, val role: OrgRole) : OrgEvent
    data class InviteSent(val email: String) : OrgEvent
    data class ActionFailed(val message: String) : OrgEvent
    data object NotAuthorized : OrgEvent
}
```

Caching and the persistent cookie jar are owned by `core-data`/`core-network`;
this layer holds only transient in-memory UI state. `isStale` is the contract
for "we have data from a previous load but the latest refresh failed" — screens
render the list with a non-blocking error banner. Optimistic mutations keep a
local `snapshot` for rollback and mark affected ids in `pendingMemberIds` so the
screen can show per-row progress.

## 7. Error Handling & Resilience

- All repository calls return `ApiResult<T>`; ViewModels never throw for
  expected failures. `AppError.toMessage()` (core-ui) produces a localized
  string; raw exception text is never surfaced.
- **Initial load failure with no data** -> `error` set, `isLoading=false`,
  `Error` UI with a `Retry` action.
- **Refresh failure with existing data** -> `isStale=true`, keep `orgs`,
  surface a dismissible banner; do not clear the list.
- **Mutation failure** (role/remove/invite) -> optimistic rollback +
  `OrgEvent.ActionFailed`; state otherwise unchanged.
- **Timeouts/unreliable host:** the ~20s timeout and bounded backoff retry for
  idempotent GETs live in `core-network`; failures arrive here as
  `ApiResult.Failure(AppError.Network)` and map to the standard `Error`/`Stale`
  paths. Mutations (PATCH/DELETE/POST) are **not** auto-retried.
- **401:** the OkHttp authenticator performs the single
  `POST /ui/session/refresh`-then-retry transparently; if it still fails the
  ViewModel receives `AppError.Unauthorized` and emits an event the app shell
  uses to route to re-auth (handled in AND-354, not here).
- Actions are idempotent against double-taps: a member id already in
  `pendingMemberIds` ignores repeated mutation requests.

## 8. Security & Privacy

- **Client-side role gating** (`OrgRole.canManage`) prevents firing privileged
  mutations the caller can't perform; this is a UX guard only — the backend
  remains authoritative and a server `403` is mapped to `NotAuthorized`.
- No credentials, cookies, or CSRF tokens are handled here; session/cookie jar
  and `X-CSRF-Token` echoing are owned by `core-network`.
- No PII (member emails, names) is logged at `info`/`debug`; see Section 10.
- State is in-memory only and cleared when the `ViewModel` is cleared; nothing
  from this layer is persisted to DataStore/Room.

## 9. Accessibility & i18n

No UI is produced by this ticket, so visual a11y is owned by AND-354. This layer
contributes:

- All user-facing strings (`emailError`, `AppError.toMessage()` keys) are
  `@StringRes`/string-resource backed — no hard-coded English in state.
- Role/plan/status enums are exposed as typed enums, not display strings, so
  AND-354 can localize and provide content descriptions.
- Currency/share rendering: treasury `balance` and `share_bps` are exposed as
  raw numeric values so the screen can format with locale-aware
  `NumberFormat`/`android.icu`; the ViewModel performs no locale formatting.

## 10. Telemetry & Logging

- Inject `Logger` (core-ui) and `Analytics` (core-data) interfaces.
- Log lifecycle and outcomes only, never payloads: `org_list_loaded {count}`,
  `org_member_role_changed {orgId, role}` (no user id/email),
  `org_invite_sent {role}`, `syndicate_detail_loaded {id}`,
  and failures as `*_failed {errorCode}`.
- Error logs include `AppError.code`/HTTP status, not response bodies (which may
  contain PII).
- Telemetry calls are behind the injected interface so tests assert them via a
  fake without a real analytics backend.

## 11. Testing Strategy

This is the acceptance focus ("Unit-tested"). Tests live in
`feature-orgs/src/test` and use JUnit4, `kotlinx-coroutines-test`
(`StandardTestDispatcher` + `MainDispatcherRule` from `core-testing`), Turbine
for `StateFlow`/event assertions, and **fakes** of `OrgRepository` /
`SyndicateRepository` (a `FakeOrgRepository` with programmable `ApiResult`
responses and call-count recording). No MockWebServer here — that belongs to the
repository tickets.

Required cases (each ViewModel):

- **Load success** -> `Loading` then `Success` with mapped data; `isEmpty`
  true on empty list.
- **Load failure (no data)** -> `error` set, list empty, `isLoading=false`;
  `Retry` re-invokes the repo and recovers.
- **Refresh failure (with data)** -> `isStale=true`, data retained, repo called
  exactly once for the refresh.
- **changeRole success** -> optimistic state visible before the call resolves,
  `RoleChanged` event emitted, no rollback.
- **changeRole failure** -> state rolled back to snapshot, `ActionFailed`
  emitted.
- **removeMember** success/failure mirror the above.
- **sendInvite** invalid email -> `emailError` set, repo **not** called.
- **sendInvite** valid -> repo called once, `InviteSent` emitted.
- **Role gating** -> caller `VIEWER`/`MEMBER` invoking a mutation emits
  `NotAuthorized` and never calls the repo.
- **Double-tap guard** -> second mutation for an in-flight member id is ignored.
- **SavedStateHandle** -> `orgId`/`syndicateId` read correctly; missing key
  throws `IllegalStateException` (asserted).
- **Syndicate detail** success maps treasury + revenue-split; read-only (no
  mutation API surface exists).

Target: 100% of public action branches covered. AND-362 extends this suite with
repository and UI-level tests.

## 12. Dependencies & Sequencing

- **Depends on (hard):** AND-353 (`OrgRepository` + org models),
  AND-356 (`SyndicateRepository` + syndicate models). Listed dep in the backlog
  is AND-353; AND-356 is added because this ticket's title explicitly covers
  syndicate state and AND-356 owns `SyndicateRepository`. Both must merge first.
- **Transitively depends on** AND-027 (auth/session + base networking),
  inherited via AND-353/356.
- **Blocks:** AND-354 (org management screens bind to these ViewModels) and
  AND-362 (orgs/syndicates tests extend this suite).
- **Sequencing:** land `core-model` DTOs + repository interfaces (upstream),
  then this state layer, then screens (AND-354). Build with KSP/Hilt; verify
  `feature-orgs` module wiring in the app DI graph.

## 13. Risks & Open Questions

- **R1 — SyndicateRepository shape. [RESOLVED — risk realized.]** Verified against
  `src/api/endpoints/syndicates.ts` + OpenAPI: treasury and revenue-split ARE
  separate endpoints (`GET /ui/syndicates/treasury/{id}`,
  `GET /ui/syndicates/revenue-split/{id}/config`); `getSyndicate` returns
  `SyndicateOut` only. `SyndicateDetailViewModel` therefore `combine`s three
  calls. Mitigation applied: keep mapping in one `private fun load()` so the
  fan-out is localized and partial failures degrade gracefully.
- **R2 — Role enum drift. [RESOLVED.]** Verified: backend settable vocabulary is
  `admin|member|viewer` (regex `^(admin|member|viewer)$`); `owner` exists but is
  not settable (moved via transfer-ownership). There is **no** `BILLING`/`MANAGER`
  role. `OrgRole { OWNER, ADMIN, MEMBER, VIEWER }` is finalized, with writes
  constrained to ADMIN/MEMBER/VIEWER.
- **R3 — Optimistic update correctness for paging.** If members move to Paging 3
  later, optimistic in-list rollback needs revisiting; current scope is a plain
  list (acceptable for typical org sizes).
- **OQ1:** Does `share_bps` always sum to 10000? If yes, the screen can show a
  validation hint; ViewModel does not enforce it (read-only).
- **OQ2:** Should `NotAuthorized` ever be reachable given the screen hides
  controls? Kept as defense-in-depth and to cover stale role state after a
  refresh.

## 14. Acceptance Criteria

- AC-1 `feature-orgs` exposes `OrgListViewModel`, `OrgDetailViewModel`,
  `OrgMembersViewModel`, `OrgInviteViewModel`, `SyndicateListViewModel`,
  `SyndicateDetailViewModel`, each `@HiltViewModel` and injectable.
- AC-2 Each ViewModel exposes a single `StateFlow<…UiState>`; one-shot effects
  go through an `events` flow. No mutable state is exposed.
- AC-3 Loading/Empty/Error/Stale states are correctly produced per Sections 3
  and 6, including stale-on-refresh-failure with data retention.
- AC-4 Member role change and removal are optimistic with rollback + event on
  failure; invite send validates email locally and is gated by caller role.
- AC-5 Syndicate detail surfaces overview + treasury + revenue-split read-only.
- AC-6 Client role gating blocks unauthorized mutations and emits
  `NotAuthorized` without a network call.
- AC-7 **Unit tests pass** covering every case in Section 11; tests use repo
  fakes and `kotlinx-coroutines-test`, run green in CI, and contain no real
  network access.
- AC-8 No PII appears in any log/telemetry call (verified by test asserting the
  fake analytics payloads).

## 15. Definition of Done

- All acceptance criteria met; code merged to `android-port`.
- Module compiles with Kotlin 2.0.21 / AGP 8.7.3 / JDK 17; Hilt KSP graph
  resolves and ViewModels are obtainable via `hiltViewModel()`.
- `./gradlew :feature-orgs:testDebugUnitTest` green; line coverage of public
  action branches ≥ the agreed threshold (target 100% of branches in Section 11).
- `ktlint`/`detekt` clean; no `TODO` left in shipped state/action code.
- No Compose UI, networking, or persistence added in this module (scope is
  State only); those remain owned by AND-354 and AND-353/356 respectively.
- PR links AND-353/AND-356 as dependencies and notes AND-354/AND-362 as
  downstream consumers; open questions R2/OQ1 recorded in the PR description.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. Sources:
`OPENAPI` = `reference/openapi.index.txt` + `reference/openapi.pretty.json`
(`components.schemas.*`); `FE` = `reference/src/...`; `framework ref` =
Android docs.

1. **`GET /ui/orgs` lists the caller's orgs.** Verified.
   OPENAPI `GET /ui/orgs` (op `list_orgs_ui_orgs_get`); FE `src/api/endpoints/orgs.ts: listOrgs` → `api.get<OrgOut[]>("/ui/orgs")`.
2. **`GET /ui/orgs/{org_id}` returns org detail.** Verified — path param is `org_id`.
   OPENAPI `GET /ui/orgs/{org_id}`; FE `src/api/endpoints/orgs.ts: getOrg`. NOTE the response is the same `OrgOut` schema as the list item (no separate `OrgDetail` schema exists server-side).
3. **`GET /ui/orgs/{org_id}/members` returns members.** Verified.
   OPENAPI `GET /ui/orgs/{org_id}/members`; FE `src/api/endpoints/orgs.ts: listMembers` → `OrgMemberOut[]`.
4. **Org pending invites live at `GET /ui/orgs/{orgId}/invites`.** Corrected → no such endpoint; pending invites are caller-scoped at `GET /ui/orgs/invites/pending`.
   OPENAPI `GET /ui/orgs/invites/pending` (op `list_pending_invites_...`); FE `src/api/endpoints/orgs.ts: listPendingInvites` → `OrgInviteOut[]`. There is no org-scoped invites GET in the index.
5. **Send invite is `POST .../invites`.** Corrected → `POST /ui/orgs/{org_id}/members/invite`, body `OrgMemberInviteReq{email, org_role?}`.
   OPENAPI `POST /ui/orgs/{org_id}/members/invite` + schema `OrgMemberInviteReq`; FE `src/api/endpoints/orgs.ts: inviteMember`.
6. **Revoke invite is `DELETE .../invites/{id}`.** Corrected → no revoke endpoint exists at all; only invitee-side `POST /ui/orgs/invites/{invite_id}/accept|decline`.
   OPENAPI has `.../accept` and `.../decline` only (ops `accept_invite_...`, `decline_invite_...`); FE `src/api/endpoints/orgs.ts: acceptInvite/declineInvite` (no revoke export). Action removed from this ticket (see §16 Open assumptions).
7. **Change member role is `PATCH .../members/{id}`.** Corrected → `PATCH /ui/orgs/{org_id}/members/{member_sub}/role`, body `OrgMemberRoleUpdateReq{org_role}`; keyed by `member_sub` (user_sub).
   OPENAPI `PATCH /ui/orgs/{org_id}/members/{member_sub}/role` + schema `OrgMemberRoleUpdateReq`; FE `src/api/endpoints/orgs.ts: changeMemberRole(orgId, userSub, {org_role})`.
8. **Remove member is `DELETE .../members/{id}`.** Corrected → `DELETE /ui/orgs/{org_id}/members/{member_sub}`, keyed by `member_sub` (user_sub).
   OPENAPI `DELETE /ui/orgs/{org_id}/members/{member_sub}`; FE `src/api/endpoints/orgs.ts: removeMember(orgId, userSub)`.
9. **Org/member/invite field names & types** (`id`, `my_role`/`role`, `display_name`, `email` on member, ISO timestamps). Corrected → keys are `org_id`/`user_sub`/`invite_id`, role field is `org_role`, timestamps are epoch **numbers**, `OrgMemberOut` has no `display_name`/`email`.
   FE `src/api/endpoints/orgs.ts: OrgOut / OrgMemberOut / OrgInviteOut`.
10. **`OrgRole` vocabulary `OWNER, ADMIN, MEMBER, VIEWER`; is there BILLING/MANAGER?** Corrected/clarified → settable roles are `admin|member|viewer` only; `owner` exists but is not settable (transfer-ownership endpoint). No BILLING/MANAGER. Resolves R2.
   OPENAPI `OrgMemberInviteReq.org_role` & `OrgMemberRoleUpdateReq.org_role` pattern `^(admin|member|viewer)$`; OPENAPI `POST /ui/orgs/{org_id}/transfer-ownership` (`OrgTransferOwnershipReq`); FE `OrgOut.owner_user_sub`.
11. **`GET /ui/syndicates` lists syndicates the caller belongs to.** Verified — but returns membership entries.
    OPENAPI `GET /ui/syndicates` (op `list_my_syndicates_...`); FE `src/api/endpoints/syndicates.ts: listMySyndicates` → `SyndicateUserEntry[]`.
12. **`getSyndicate(id)` returns combined overview + treasury + revenue-split in one call.** Corrected → returns `SyndicateOut` overview ONLY; treasury and split are separate GETs. Realizes R1.
    OPENAPI `GET /ui/syndicates/{syndicate_id}`, `GET /ui/syndicates/treasury/{syndicate_id}` → `SyndicateTreasuryBalanceOut`, `GET /ui/syndicates/revenue-split/{syndicate_id}/config` → `SplitConfigOut`; FE `src/api/endpoints/syndicates.ts: getSyndicate` (overview only).
13. **Treasury exposes `balance` + `currency`.** Corrected → `balance_cents` (integer minor units) + `currency`.
    OPENAPI/FE `SyndicateTreasuryBalanceOut { syndicate_id, balance_cents, total_deposited_cents, total_disbursed_cents, currency, updated_at }` (FE `src/api/types.ts:10335`).
14. **Revenue split is a per-member `[{user_id, display_name, share_bps}]` table.** Corrected → it is a config object `SplitConfigOut { mode, weights_bps: map<user→bps>, platform_fee_bps, ... }`; no `display_name`.
    OPENAPI `components.schemas.SplitConfigOut` (`openapi.pretty.json:68803`).
15. **401 handling: single `POST /ui/session/refresh` then retry.** Verified (web behavior; Android replicates via OkHttp authenticator).
    FE `src/api/client.ts: refreshSession()` → `POST /ui/session/refresh`, then one retry of the original request; on second 401 it logs out.
16. **CSRF: token echoed; cookies carry session.** Verified — CSRF cookie `ui_csrf` echoed as header `X-CSRF-Token`; requests use `credentials: "include"`; `Authorization: Bearer` from auth store. (Owned by `core-network`, not this layer.)
    FE `src/api/client.ts` (`getCookie("ui_csrf")` → `X-CSRF-Token`; `credentials: "include"`).
17. **FastAPI `detail` shapes: `string | [{msg}] | {code,...}`.** Verified.
    FE `src/api/client.ts: normalizeErrorDetail` / `mapAuthorizationError` (handles string, array-of-`{msg}`, and object-with-`code`); OPENAPI `HTTPValidationError` (422 array of `{loc,msg,type}`).
18. **Server `403` → `NotAuthorized` mapping for role-gated mutations.** Verified plausible — backend returns `403` with `detail.code` like `role_required` for permission failures; `core-network` maps to `AppError`.
    FE `src/api/client.ts` 403 branch + `mapAuthorizationError` (`role_required`, `role_required_scope`).
19. **`@HiltViewModel` + `SavedStateHandle` + `viewModelScope` + `StateFlow`.** Verified (framework ref).
    framework ref: developer.android.com/training/dependency-injection/hilt-jetpack (`@HiltViewModel`); developer.android.com/topic/libraries/architecture/viewmodel/viewmodel-savedstate; developer.android.com/kotlin/flow/stateflow-and-sharedflow.
20. **`ImmutableList`/`persistentListOf` for Compose recomposition stability.** Verified (framework ref).
    framework ref: developer.android.com/develop/ui/compose/performance/stability (kotlinx.collections.immutable as stable types).
21. **Dev backend host `http://18.222.237.167:8000` unreliable; ~20s timeout + bounded retry for idempotent GETs in `core-network`.** Unverified-assumption — host/timeout/retry policy are project-internal infra not present in the provided sources.

### Corrections made

- §3 FR-4: removed `revokeInvite` action (no backend endpoint); pending invites are caller-scoped, filtered by org.
- §3 FR-7 / §4 / §13 R1: syndicate detail is assembled from **three** GETs (overview, treasury, revenue-split config), not one `getSyndicate`.
- §5 repo interfaces: corrected invite path (`/members/invite`), role-change path (`/members/{member_sub}/role`), removal/role keyed by `member_sub`; replaced org-scoped `listInvites` with caller-scoped `listPendingInvites`; dropped `revokeInvite`; split syndicate detail into `getSyndicate`/`getTreasury`/`getRevenueSplit`.
- §5 DTO shapes: `id`→`org_id`/`user_sub`/`invite_id`; `role`/`my_role`→`org_role`; ISO strings→epoch numbers; removed member `display_name`/`email`; treasury `balance`→`balance_cents`; revenue split table→`SplitConfigOut` config (`weights_bps` map).
- §5 `OrgRole`: documented settable set `admin|member|viewer`; `owner` read-only (transfer-ownership); no BILLING/MANAGER.
- §13: marked R1 RESOLVED (realized) and R2 RESOLVED.

### Open assumptions

- **Dev host / timeout / retry policy** (claim 21): not in the provided sources; inherited from `core-network` (AND-027) and AND-353/356. Unverifiable here.
- **`OrgDetail` vs `OrgOut`**: spec assumes a richer `OrgDetail`; server returns the same `OrgOut` for list and detail. The Android `OrgDetail` model is an internal mapping convenience, not a distinct server schema.
- **Revoke-invite product need**: removed because no endpoint exists; if product requires it, a backend endpoint must be added (out of scope for AND-361).
- **`SyndicateUserEntry` / `SyndicateOut` exact fields**: referenced by `src/api/endpoints/syndicates.ts` (imported from `@/api/types`) but the interface bodies were not located in the provided `types.ts` slice; field mapping for the syndicate **overview** is therefore taken from the endpoint signatures, not field-verified. Treasury and split shapes ARE field-verified (claims 13–14).
- **`share_bps` summing to 10000** (OQ1): not enforced server-side in `SplitConfigOut` (weights are arbitrary bps with a separate `platform_fee_bps`); ViewModel does not enforce it (read-only).

## 17. Test Plan

All cases target JVM unit/Robolectric unless noted — this is a State-only ticket
with no UI, networking, or device dependencies, so the **physical Samsung Galaxy
A15 (SM-A156U)** and the **`test35` emulator** are **not required** for any case
here; they are reserved for downstream tickets (AND-354 Compose UI, AND-362
e2e/instrumented). Each case uses `FakeOrgRepository` / `FakeSyndicateRepository`
with programmable `ApiResult` and call-count recording, `kotlinx-coroutines-test`
(`StandardTestDispatcher` + `MainDispatcherRule`), and Turbine.

- **TC-AND-361-01 — Org list happy path.** Type: unit. Target: `OrgListViewModel` (JVM). Preconditions: fake `listOrgs()` returns `Success([OrgOut×2])`. Steps: construct VM (init load), collect `state` via Turbine. Expected: emits `isLoading=true` then `Success` with 2 orgs, `isStale=false`, `error=null`, `isEmpty=false`. Traces: AC-1, AC-2, AC-3.
- **TC-AND-361-02 — Org list empty vs error distinction.** Type: unit. Target: `OrgListViewModel` (JVM). Preconditions: fake returns `Success([])`. Steps: init, read state. Expected: `isEmpty=true`, `error=null`, `isLoading=false` (distinct from error). Traces: AC-3.
- **TC-AND-361-03 — Initial load failure (no data) + retry recovery.** Type: unit. Target: `OrgListViewModel` (JVM). Preconditions: fake first returns `Failure(AppError.Network)`, then `Success([OrgOut])`. Steps: init (fails), assert `error` set/`isLoading=false`/list empty; dispatch `Retry`; assert recovery. Expected: error state then success after retry; repo called twice. Traces: AC-3, AC-7.
- **TC-AND-361-04 — Refresh failure with existing data → stale.** Type: unit. Target: `OrgListViewModel` (JVM). Preconditions: first load `Success([orgs])`, then refresh `Failure`. Steps: init success; dispatch `Refresh`; assert. Expected: `isStale=true`, list retained, `error` set as banner, list NOT cleared; repo called exactly twice. Traces: AC-3.
- **TC-AND-361-05 — changeRole optimistic success.** Type: unit. Target: `OrgMembersViewModel` (JVM). Preconditions: caller `OWNER`/`ADMIN`; members loaded; fake `changeMemberRole` returns `Success` after a delay. Steps: dispatch `ChangeRole(userSub, MEMBER)`; assert optimistic state BEFORE resolution, then `RoleChanged` event. Expected: row shows new role immediately; `RoleChanged(userSub, MEMBER)` emitted; no rollback; repo called once with `member_sub` + `org_role`. Traces: AC-4.
- **TC-AND-361-06 — changeRole failure → rollback + event.** Type: unit. Target: `OrgMembersViewModel` (JVM). Preconditions: caller ADMIN; fake `changeMemberRole` returns `Failure`. Steps: dispatch `ChangeRole`; await. Expected: state rolled back to snapshot, `ActionFailed(message)` emitted, no `RoleChanged`. Traces: AC-4.
- **TC-AND-361-07 — removeMember success & failure.** Type: unit. Target: `OrgMembersViewModel` (JVM). Preconditions: caller ADMIN; two fake configs (Success / Failure). Steps: dispatch `Remove(userSub)` in each. Expected: success → member removed optimistically, no rollback; failure → member restored + `ActionFailed`. Traces: AC-4.
- **TC-AND-361-08 — sendInvite invalid email (no network).** Type: unit. Target: `OrgInviteViewModel` (JVM). Preconditions: caller ADMIN. Steps: `sendInvite("not-an-email", MEMBER)`. Expected: `emailError` (`@StringRes`) set, repo **not** called (call count 0), no `InviteSent`. Traces: AC-4, AC-7.
- **TC-AND-361-09 — sendInvite valid path.** Type: unit. Target: `OrgInviteViewModel` (JVM). Preconditions: caller ADMIN; fake `invite` returns `Success(OrgInviteOut)`. Steps: `sendInvite("new@x.io", MEMBER)`. Expected: `isSubmitting` toggles, repo called once with `email`+`org_role` (write role ∈ {ADMIN,MEMBER,VIEWER}), `InviteSent("new@x.io")` emitted. Traces: AC-4.
- **TC-AND-361-10 — Role gating blocks unauthorized mutation (security).** Type: unit. Target: `OrgMembersViewModel`/`OrgInviteViewModel` (JVM). Preconditions: caller `VIEWER` then `MEMBER`. Steps: attempt `ChangeRole`, `Remove`, `sendInvite`. Expected: each emits `NotAuthorized`, repo never called (count 0). Traces: AC-6, AC-8(no payload leak).
- **TC-AND-361-11 — Double-tap idempotency guard.** Type: unit. Target: `OrgMembersViewModel` (JVM). Preconditions: caller ADMIN; fake delays first `changeMemberRole`. Steps: dispatch `ChangeRole(userSub,…)` twice rapidly while first in-flight (userSub in `pendingMemberIds`). Expected: second dispatch ignored; repo called exactly once. Traces: AC-4.
- **TC-AND-361-12 — SavedStateHandle key handling.** Type: unit. Target: `OrgMembersViewModel`/`SyndicateDetailViewModel` (JVM, Robolectric for `SavedStateHandle` if needed). Preconditions: handle with/without `orgId`. Steps: construct with key → assert read; construct without key. Expected: present → state seeded with id; missing → `IllegalStateException` (checkNotNull). Traces: AC-1.
- **TC-AND-361-13 — Syndicate detail combines 3 sources read-only + partial-failure degrade.** Type: unit. Target: `SyndicateDetailViewModel` (JVM). Preconditions: fakes for `getSyndicate`=Success, `getTreasury`=Success(`balance_cents`,`currency`), `getRevenueSplit`=Success(`SplitConfig` with `weights_bps`); plus a variant where `getTreasury`=Failure(403). Steps: init; assert combined state; then variant. Expected: all-success → one `SyndicateDetailUiState` with overview+treasury+split, no write API surface exists; treasury-403 variant → overview+split present, treasury marked missing, screen not failed. Traces: AC-5, AC-7.
- **TC-AND-361-14 — Telemetry contains no PII (security/privacy).** Type: unit. Target: all VMs via `FakeAnalytics` (JVM). Preconditions: fake analytics capturing payloads. Steps: drive list-load, role-change, invite-send, syndicate-load. Expected: events `org_list_loaded{count}`, `org_member_role_changed{orgId,role}`, `org_invite_sent{role}`, `syndicate_detail_loaded{id}`, `*_failed{errorCode}`; assert NO email/user name/user_sub/response body present in any captured payload. Traces: AC-8.
- **TC-AND-361-15 — Network/offline failure maps to Error/Stale (flaky-host path).** Type: unit. Target: `OrgListViewModel`/`SyndicateDetailViewModel` (JVM). Preconditions: fake returns `Failure(AppError.Network)` (simulating the unreliable dev host / offline) for initial and for refresh. Steps: init-with-no-data → assert `Error`+`Retry`; load-with-data then refresh-fail → assert `Stale`. Expected: no exception thrown; `AppError.Network` → standard Error/Stale paths; mutations not auto-retried. Traces: AC-3, AC-7. (Real-network behavior belongs to AND-353/356 MockWebServer + AND-362 e2e; not exercised here.)

### Coverage matrix

| AC | Covered by |
|----|------------|
| AC-1 (VMs exist, Hilt-injectable) | TC-01, TC-12 |
| AC-2 (single StateFlow + events, no mutable state) | TC-01 |
| AC-3 (Loading/Empty/Error/Stale) | TC-01, TC-02, TC-03, TC-04, TC-15 |
| AC-4 (optimistic role/remove/invite + validation + gating) | TC-05, TC-06, TC-07, TC-08, TC-09, TC-11 |
| AC-5 (syndicate detail overview+treasury+split read-only) | TC-13 |
| AC-6 (role gating blocks mutation, no network) | TC-10 |
| AC-7 (unit tests pass, fakes, no real network) | TC-03, TC-08, TC-13, TC-15 |
| AC-8 (no PII in logs/telemetry) | TC-10, TC-14 |
