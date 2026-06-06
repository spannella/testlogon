---
id: AND-378
title: Claim / assignment management
milestone: M8
epic: E49
priority: P2
size: M
status: draft
depends_on: [AND-377]
blocks: []
---

# AND-378 — Claim / assignment management

## 1. Overview & Goal

This ticket adds **claim, assign, and transfer** actions to the helpdesk agent
experience so that an authenticated agent can take ownership of an unassigned
conversation, assign a conversation to a different agent, or transfer an
in-progress conversation to another agent or queue. It builds directly on the
agent dashboard (AND-377), which renders the queue and per-agent metrics but is
read-only with respect to ownership.

The goal is a small, correct, well-tested ownership-mutation layer that:

- Exposes claim / assign / transfer as first-class actions from both the queue
  list (AND-377) and an individual conversation detail surface.
- Performs the mutation against the FastAPI backend, reflects the new
  `assignee` / `status` optimistically, and reconciles with the server response.
- Handles the unreliable dev backend gracefully (timeouts, conflicts, offline)
  without corrupting local state.
- Enforces role and ownership rules client-side as a UX guard while treating the
  server `403`/`409` responses as the source of truth.

Out of scope: the dashboard/queue rendering itself (AND-377), conversation
messaging/reply composition, SLA timers, and bulk multi-select operations.

## 2. Context & References

- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable). OpenAPI at `/openapi.json`. Cookie-based auth
  with `ui_csrf` cookie echoed as `X-CSRF-Token`; `401` → one
  `POST /ui/session/refresh` then retry.
- **Web reference:** `frontend/src/api/endpoints/*.ts` (helpdesk/conversation
  assignment endpoints) and shared types in `frontend/src/api/types.ts`. The
  Android contract must mirror the web client's request/response shapes; verify
  against `/openapi.json` before implementation since the dev host schema is the
  authority.
- **Depends on AND-377** for: `feature-helpdesk` module, `HelpdeskRepository`,
  `ConversationSummary`/`AgentSummary` models, the queue `StateFlow<UiState>`,
  and the agent-role gate. This ticket extends those rather than re-creating
  them.
- **Module layering:** `app -> feature-helpdesk -> core-{network,model,data,ui,testing}`.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Navigation-Compose, Hilt
  (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Room 2.6,
  DataStore, Paging 3. minSdk 24 / target 35, JDK 17.
- **Namespace:** `com.testlogon.android` everywhere.

## 3. Functional Requirements

FR-1 **Claim.** An agent viewing an unassigned conversation (in queue or detail)
can claim it. On success the conversation `assignee` becomes the current agent
and `status` transitions to `assigned` (or `open`→`assigned` per server).

FR-2 **Assign.** An agent (with assign permission) can assign a conversation to
another agent selected from a roster. The roster is the list of agents returned
by the dashboard/agents endpoint (reused from AND-377). Self-assign is
permitted and is functionally a claim.

FR-3 **Transfer.** An agent who currently owns a conversation can transfer it to
another agent **or** to a queue. Transfer requires a target and accepts an
optional free-text `note`/`reason`. Transferring away clears the conversation
from the current agent's "my conversations" view.

FR-4 **Action availability.** Each action is shown only when valid for the
conversation's current state and the agent's role/ownership:
- Claim: visible when `assignee == null` (unassigned).
- Assign: visible when the agent has `can_assign` capability.
- Transfer: visible when `assignee == currentAgentId` OR the agent has
  `can_assign`.
Disabled/hidden state is a UX hint only; the server remains authoritative.

FR-5 **Optimistic update + reconcile.** The selected conversation row updates
immediately; on error it rolls back to the prior value and surfaces a message.

FR-6 **Conflict handling.** If another agent claimed the conversation first
(server `409`), the UI shows "Already claimed by {name}" and refreshes the row
from the server payload instead of forcing the local change.

FR-7 **Confirmation.** Assign and Transfer open a bottom sheet (agent/queue
picker + optional note). Claim is a single-tap action with no modal but with an
undo affordance via snackbar for a short window.

FR-8 **Result feedback.** Every action produces a snackbar: success
("Claimed", "Assigned to {name}", "Transferred to {target}") or a typed error
message derived from FastAPI `detail`.

## 4. Technical Design

New code lives in `feature-helpdesk`; shared models/DTOs extend
`core-model`/`core-network` introduced in AND-377.

### 4.1 Models (`core-model`)

```kotlin
enum class AssignmentAction { CLAIM, ASSIGN, TRANSFER }

data class Assignment(
    val conversationId: String,
    val assigneeId: String?,      // null = unassigned
    val assigneeName: String?,
    val status: ConversationStatus,
    val queueId: String?,
    val updatedAt: Instant,
)

data class TransferTarget(
    val agentId: String? = null,  // exactly one of agentId / queueId
    val queueId: String? = null,
    val note: String? = null,
)
```

### 4.2 Network (`core-network`)

```kotlin
interface HelpdeskAssignmentApi {
    @POST("/ui/helpdesk/conversations/{id}/claim")
    suspend fun claim(@Path("id") id: String): Response<AssignmentDto>

    @POST("/ui/helpdesk/conversations/{id}/assign")
    suspend fun assign(
        @Path("id") id: String,
        @Body body: AssignRequestDto,
    ): Response<AssignmentDto>

    @POST("/ui/helpdesk/conversations/{id}/transfer")
    suspend fun transfer(
        @Path("id") id: String,
        @Body body: TransferRequestDto,
    ): Response<AssignmentDto>
}
```

These are non-idempotent POSTs and therefore **MUST NOT** be auto-retried by the
OkHttp backoff interceptor (which is restricted to idempotent GETs). The `401`
refresh-once-then-retry behavior is still allowed because it re-issues an
otherwise-failed request, but it must be gated so a single business-logic POST
is sent at most twice and never after a `2xx`. Final endpoint paths/method names
are confirmed against `/openapi.json`; if the web client uses a different shape
(e.g. `PATCH /ui/helpdesk/conversations/{id}` with `{assignee_id}`) the
interface adapts to match, keeping the repository surface stable.

### 4.3 Repository (`core-data` / feature)

```kotlin
interface AssignmentRepository {
    suspend fun claim(conversationId: String): ApiResult<Assignment>
    suspend fun assign(conversationId: String, agentId: String): ApiResult<Assignment>
    suspend fun transfer(conversationId: String, target: TransferTarget): ApiResult<Assignment>
    suspend fun agents(): ApiResult<List<AgentSummary>>   // reuses AND-377
}
```

The repository maps DTO→domain, writes the updated `Assignment` into the Room
cache used by the queue (so the queue and detail screens observe a single source
of truth), and returns `ApiResult<Assignment>`.

### 4.4 ViewModel & UI state (`feature-helpdesk`)

```kotlin
@HiltViewModel
class AssignmentViewModel @Inject constructor(
    private val repo: AssignmentRepository,
    private val session: SessionManager,        // current agent id + caps
) : ViewModel() {
    val uiState: StateFlow<AssignmentUiState>
    fun claim(conversationId: String)
    fun assign(conversationId: String, agentId: String)
    fun transfer(conversationId: String, target: TransferTarget)
    fun undoLastClaim()
    fun dismissError()
}

data class AssignmentUiState(
    val inFlight: Set<String> = emptySet(),     // conversationIds mutating
    val roster: List<AgentSummary> = emptyList(),
    val sheet: AssignmentSheet? = null,         // null | AssignSheet | TransferSheet
    val snackbar: AssignmentSnackbar? = null,
    val lastUndoable: UndoableClaim? = null,
)
```

Compose surface: `AssignmentActionsRow` (claim/assign/transfer buttons keyed off
availability rules), `AssignAgentSheet` and `TransferSheet`
(`ModalBottomSheet`, Material 3) containing a searchable agent/queue picker and
optional note field. Optimistic mutation is applied to the shared queue cache;
rollback restores the previous `Assignment` snapshot captured before the call.

## 5. API Contract

All requests carry session cookies + `X-CSRF-Token` (from `ui_csrf`). All bodies
and responses are JSON. Verify field names against `/openapi.json`.

**Claim** — `POST /ui/helpdesk/conversations/{id}/claim` (no body)

**Assign** — `POST /ui/helpdesk/conversations/{id}/assign`
```json
{ "assignee_id": "agt_8f21" }
```

**Transfer** — `POST /ui/helpdesk/conversations/{id}/transfer`
```json
{ "assignee_id": "agt_3c90", "queue_id": null, "note": "Escalating, needs billing" }
```
Exactly one of `assignee_id` / `queue_id` is non-null.

**Success (200)** — shared `AssignmentDto` for all three:
```json
{
  "id": "conv_1a2b",
  "assignee_id": "agt_8f21",
  "assignee_name": "Dana Lee",
  "status": "assigned",
  "queue_id": "q_tier1",
  "updated_at": "2026-06-05T17:02:11Z"
}
```

**Error shapes** (FastAPI `detail`): string, `[{ "msg": "...", "loc": [...] }]`,
or `{ "code": "...", ... }`. Mapped statuses:
- `401` → refresh once, retry once, else surface session-expired.
- `403` → "You don't have permission to assign this conversation."
- `404` → "Conversation no longer exists." (remove from cache).
- `409` → conflict: parse `detail` for current owner, show "Already claimed by
  {name}", refresh row.
- `422` → validation (e.g. missing target) → field/sheet error.

## 6. Data & State Management

- **Single source of truth:** the conversation row in the Room-backed queue cache
  (owned by AND-377). Assignment mutations update that row; both queue and detail
  observe it via Flow, so no duplicate state.
- **Optimistic write:** before the network call, snapshot the current
  `Assignment` and write the predicted new value into the cache; `inFlight` adds
  the conversationId (drives a per-row spinner / disabled buttons).
- **Reconcile:** on `2xx`, overwrite with the server `AssignmentDto`; on error,
  restore the snapshot and remove from `inFlight`.
- **Roster:** fetched once per sheet open and cached in `uiState.roster`; backed
  by the agents endpoint from AND-377. Stale roster is acceptable; assign to a
  now-removed agent surfaces as a server `422`/`404`.
- **Undo (claim):** `lastUndoable` holds the pre-claim snapshot; `undoLastClaim`
  issues a transfer/unassign back to the prior owner (or unassign) within the
  snackbar window.
- **DataStore:** not used here beyond reading the current agent id/caps already
  persisted by session (AND-377 / auth tickets).

## 7. Error Handling & Resilience

- **Timeouts:** 20s call timeout (project default). A timed-out POST is treated
  as *unknown outcome*: roll back the optimistic change, then trigger a queue
  row refresh (idempotent GET) to learn the true state rather than assuming
  failure. Snackbar: "Couldn't confirm — refreshing."
- **No POST retries:** claim/assign/transfer are non-idempotent; the backoff
  retry interceptor explicitly excludes them. Only the `401` single-refresh
  retry applies, and only when no `2xx` was received.
- **Conflict (`409`):** never overwrite local with the optimistic value;
  reconcile from server payload and inform the user.
- **Offline:** if no network, fail fast with "You're offline — assignment
  changes need a connection." No offline queueing of mutations (explicitly out
  of scope; can be revisited — see Risks).
- **Double-submit guard:** buttons for a conversation are disabled while its id
  is in `inFlight`.

## 8. Security & Privacy

- All mutations require an authenticated agent session; the cookie jar and
  `X-CSRF-Token` header are attached by the existing OkHttp interceptors (auth
  tickets). No new credential storage.
- **CSRF:** every POST must echo `ui_csrf`; a missing/expired token surfaces as
  `401`/`403` and follows the refresh path.
- **Authorization is server-enforced.** Client capability checks
  (`can_assign`, ownership) are UX-only and must never be the sole gate; a `403`
  is always honored.
- **PII:** agent names and optional transfer notes are user-visible content.
  Notes are not logged in telemetry beyond length; agent ids (opaque) may be
  logged, names must not.
- Plaintext HTTP dev host is a known dev-only risk; no real credentials beyond
  the dev session. Production must be HTTPS (tracked outside this ticket).

## 9. Accessibility & i18n

- All action buttons and sheet controls have `contentDescription` /
  `semantics`; icon-only claim/assign/transfer buttons expose text labels.
- Bottom sheets are reachable and dismissable via TalkBack; focus moves into the
  sheet on open and returns to the trigger on close.
- Snackbars announce via live region; undo action is keyboard/switch accessible.
- Touch targets ≥ 48dp. Picker rows fully labeled ("Assign to Dana Lee, Tier 1").
- All strings in `strings.xml` with parameterized placeholders
  (`%1$s` for names/targets); no concatenation. Status terms ("Unassigned",
  "Assigned", "Transferred") localizable. Layout direction RTL-safe.

## 10. Telemetry & Logging

- Emit analytics events via the existing core analytics interface:
  `helpdesk_claim`, `helpdesk_assign`, `helpdesk_transfer`, each with
  `{ conversation_id, target_type, outcome (success|conflict|error|timeout),
  latency_ms }`. Do not include agent names or note text.
- Log network failures at WARN with status code and mapped error code; never log
  cookies, CSRF token, or note bodies.
- A dedicated `409` conflict counter to monitor contention on the shared dev
  queue.

## 11. Testing Strategy

- **Unit (ViewModel, `core-testing` + Turbine):**
  - claim success → optimistic state then reconciled `assignee == currentAgent`.
  - claim `409` → no overwrite, conflict snackbar, row refreshed.
  - assign success/`403`/`422`; transfer to agent vs queue; mutual-exclusivity
    of target validated before call.
  - timeout → rollback + refresh path; `inFlight` cleared.
  - availability rules: action visibility per ownership/capability matrix.
- **Repository (MockWebServer):** request method/path/body shape, header
  presence (`X-CSRF-Token`), DTO→domain mapping, all `detail` variants,
  confirm POSTs are **not** retried by the backoff interceptor, `401`
  refresh-then-retry happens exactly once.
- **Compose UI tests:** action row renders correct buttons; assign/transfer
  sheets open, pick a target, submit; disabled state during `inFlight`; snackbar
  + undo.
- **Accessibility test:** semantics assertions for buttons/sheet/snackbar.
- Coverage target consistent with module standards; CI runs on `android-port`.

## 12. Dependencies & Sequencing

- **Hard dependency: AND-377** (Helpdesk agent dashboard) — supplies the
  `feature-helpdesk` module, queue cache/repository, `ConversationSummary` /
  `AgentSummary`, agent-role gate, and agents roster source. Must merge first.
- Transitively depends on the auth/session + interceptor tickets (cookie jar,
  `X-CSRF-Token`, `401` refresh) and `core-network` (Retrofit/OkHttp/Moshi,
  `ApiResult`).
- **Blocks:** none recorded in the backlog. Downstream messaging/reply features,
  if any, may consume the assignment state but are not listed here.
- Sequencing: confirm exact assignment endpoints from `/openapi.json` ↔
  `frontend/src/api/endpoints` before coding the Retrofit interface.

## 13. Risks & Open Questions

- **R1 — Endpoint shape unconfirmed.** Backend may use dedicated
  claim/assign/transfer routes or a single `PATCH` on the conversation.
  *Mitigation:* keep `AssignmentRepository` stable; adapt the Retrofit interface
  to `/openapi.json`. **Open:** which shape is canonical?
- **R2 — Queue targets.** Does transfer-to-queue exist server-side, or is
  transfer agent-only? **Open:** confirm `queue_id` support; if absent, hide the
  queue tab in the transfer sheet.
- **R3 — Conflict payload.** Does `409` include the winning owner's name for the
  "Already claimed by {name}" message? If not, fall back to a generic message +
  refresh.
- **R4 — Undo semantics.** Is there a true "unassign" endpoint, or must undo be
  a transfer back to the prior owner/null? **Open.**
- **R5 — Dev host contention.** Multiple testers on one shared queue will produce
  frequent `409`s; tests must not depend on stable ownership.
- **R6 — Offline mutations** are not queued; acceptable for M8 but may need
  revisiting if field agents go offline.

## 14. Acceptance Criteria

AC-1 An agent can **claim** an unassigned conversation from the queue and from
detail; on success the row shows the agent as assignee and status `assigned`.
*(Maps to backlog "Claim/assign actions work.")*

AC-2 An agent with assign capability can **assign** a conversation to another
agent via the picker sheet; the row reflects the new assignee.

AC-3 An owning agent can **transfer** a conversation to another agent (and to a
queue if supported), with an optional note; the conversation leaves the agent's
"mine" view.

AC-4 Optimistic updates apply immediately and roll back on error/timeout, with a
typed snackbar message.

AC-5 A `409` conflict does not overwrite local state; the user sees an
"already claimed" message and the row refreshes from the server.

AC-6 Action buttons follow the availability matrix and are disabled while a
mutation for that conversation is in flight (no double-submit).

AC-7 `403` from the server is always honored regardless of client capability
hints.

AC-8 Claim/assign/transfer POSTs are not auto-retried; `401` triggers exactly one
refresh-and-retry.

AC-9 All actions, sheets, and snackbars are TalkBack-accessible; all strings are
localized.

## 15. Definition of Done

- Code merged to `android-port` under `com.testlogon.android` in
  `feature-helpdesk` with `core-*` additions, following module layering.
- Endpoints verified against `/openapi.json`; Retrofit interface and DTOs match.
- All FR/AC items implemented and demonstrated against the dev backend.
- Unit, repository (MockWebServer), and Compose UI/accessibility tests pass in
  CI; coverage meets module standard.
- No lint/detekt regressions; strings externalized; no PII or secrets in logs.
- Telemetry events emitted and verified.
- Risks R1–R4 resolved or explicitly deferred with backlog follow-ups; KDoc on
  public repository/ViewModel APIs; PR links AND-377 and this ticket.
