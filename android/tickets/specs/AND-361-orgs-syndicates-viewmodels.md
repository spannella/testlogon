---
id: AND-361
title: Orgs/syndicates ViewModels
milestone: M7
epic: E46
priority: P2
size: M
status: draft
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
- FR-4 **Invites.** Expose pending invites and a `sendInvite(email, role)`
  action with inline field validation (valid email, role from allowed set) and
  a `revokeInvite(inviteId)` action.
- FR-5 **Role gating.** The detail/members/invite states must carry the
  caller's role (`OrgRole`) so screens can enable/disable management controls;
  the ViewModel rejects management actions when the caller lacks `ADMIN`/`OWNER`
  and emits a `NotAuthorized` event rather than calling the API.

**Syndicates**

- FR-6 **Syndicate list.** Expose syndicates the caller belongs to, with
  refresh + retry, `Empty` vs `Error`.
- FR-7 **Syndicate detail.** Given a `syndicateId`, expose overview, the
  treasury summary (balance, currency), and the revenue-split table
  (per-member share). These are **read-only** in this milestone.
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
loads overview/treasury/revenue-split via the single
`syndicateRepository.getSyndicate(id)` call (AND-356) and exposes them as one
state object. No write actions are defined for syndicates in this milestone.

`OrgRole.canManage` is `this == OrgRole.OWNER || this == OrgRole.ADMIN`.

## 5. API Contract

This ticket does **not** define or call HTTP endpoints directly — all network
access is delegated to `OrgRepository` (AND-353) and `SyndicateRepository`
(AND-356). The contract below documents only the **repository interfaces this
ticket consumes** (owned upstream) so the state mapping is unambiguous.

```kotlin
interface OrgRepository {                                   // AND-353
    suspend fun listOrgs(): ApiResult<List<Org>>            // GET /ui/orgs
    suspend fun getOrg(orgId: String): ApiResult<OrgDetail> // GET /ui/orgs/{orgId}
    suspend fun listMembers(orgId: String): ApiResult<List<OrgMember>>      // GET /ui/orgs/{orgId}/members
    suspend fun listInvites(orgId: String): ApiResult<List<OrgInvite>>      // GET /ui/orgs/{orgId}/invites
    suspend fun invite(orgId: String, email: String, role: OrgRole): ApiResult<OrgInvite>    // POST .../invites
    suspend fun revokeInvite(orgId: String, inviteId: String): ApiResult<Unit>               // DELETE .../invites/{id}
    suspend fun changeMemberRole(orgId: String, memberId: String, role: OrgRole): ApiResult<OrgMember> // PATCH .../members/{id}
    suspend fun removeMember(orgId: String, memberId: String): ApiResult<Unit>               // DELETE .../members/{id}
}

interface SyndicateRepository {                             // AND-356
    suspend fun listSyndicates(): ApiResult<List<Syndicate>>            // GET /ui/syndicates
    suspend fun getSyndicate(id: String): ApiResult<SyndicateDetail>    // GET /ui/syndicates/{id}
}
```

Representative `core-model` shapes (mirror `frontend/src/api/types.ts`; backend
returns snake_case mapped to camelCase via Moshi adapters in `core-network`):

```jsonc
// Org (list item)
{ "id": "org_123", "name": "Acme", "slug": "acme", "plan": "pro",
  "member_count": 12, "my_role": "admin" }

// OrgMember
{ "id": "mem_9", "user_id": "u_42", "display_name": "Jo", "email": "jo@x.io",
  "role": "member", "joined_at": "2026-05-01T10:00:00Z" }

// OrgInvite
{ "id": "inv_3", "email": "new@x.io", "role": "member", "status": "pending",
  "invited_at": "2026-06-01T09:00:00Z" }

// SyndicateDetail (read-only)
{ "id": "syn_7", "name": "North Split", "my_role": "member",
  "treasury": { "balance": 14250, "currency": "USD" },
  "revenue_split": [ { "user_id": "u_42", "display_name": "Jo", "share_bps": 4000 } ] }
```

`OrgRole` enum: `OWNER, ADMIN, MEMBER, VIEWER` (Moshi `@Json` mapped from
lower-case strings; unknown values map to `VIEWER`). FastAPI `detail` mapping
(`string | [{msg}] | {code,...}`) is handled in `core-network` and reaches this
layer as `ApiResult.Failure(AppError)`.

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

- **R1 — SyndicateRepository shape.** If AND-356 splits treasury/revenue-split
  into separate endpoints/calls instead of one `getSyndicate`, the
  `SyndicateDetailUiState` may need a `combine` of multiple flows. Mitigation:
  keep state mapping in one `private fun load()` so the change is localized.
- **R2 — Role enum drift.** Backend role vocabulary
  (`owner/admin/member/viewer`) must match `frontend/src/api/types.ts`. Open
  question: is there a distinct `BILLING`/`MANAGER` role? Confirm against
  `/openapi.json` before finalizing `OrgRole`.
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
