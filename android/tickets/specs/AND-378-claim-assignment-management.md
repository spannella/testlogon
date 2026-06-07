---
id: AND-378
title: Claim / assignment management
milestone: M8
epic: E49
priority: P2
size: M
depends_on: [AND-377]
blocks: []
status: reviewed
reviewed_on: 2026-06-06
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
  (plaintext HTTP, unreliable). OpenAPI at `/openapi.json`. Auth is **cookie
  session + bearer token + CSRF**: the web client sends `Authorization: Bearer
  <accessToken>` (from the auth store), echoes the `ui_csrf` cookie as
  `X-CSRF-Token`, and includes cookies (`credentials: include`). The messaging /
  helpdesk endpoints additionally accept `X-SESSION-ID` and `authorization`
  params. `401` → one `POST /ui/session/refresh` then retry (verified in
  `src/api/client.ts`). **Correction:** the original draft described auth as
  cookie-only and omitted the bearer token; corrected here.
- **Web reference:** `src/api/endpoints/messaging.ts`
  (`claimHelpdeskConversation`, `getHelpdeskQueue`, `startHelpdeskConversation`),
  `src/pages/messages/ConversationView.tsx` (`HelpdeskRoutingBanner` + claim
  mutation), `src/pages/helpdesk/HelpdeskPage.tsx` (queue rendering), and shared
  types in `src/api/types.ts` (`Conversation`, `HelpdeskClaimOut`). The Android
  contract must mirror the web client's request/response shapes; verify against
  `/openapi.json` since the dev host schema is the authority.
  **Major correction (see §16):** the web client implements only **claim** for
  helpdesk conversations. There is **no helpdesk `assign` or `transfer`
  endpoint** in the backend. The only assignment-style routes are on the
  *tickets* domain (`POST /tickets/{ticket_id}/assign`,
  `POST /ticket-spaces/{space_id}/tickets/{ticket_id}/assign`) and moderation
  (`POST /v1/admin/moderation/tickets/{ticket_id}/claim`). This ticket's
  assign/transfer scope is therefore **unverified against the helpdesk backend**
  and must be re-scoped with product/backend before implementation.
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

**Corrected paths/shapes** (verified against `/openapi.json` and
`src/api/endpoints/messaging.ts`):

```kotlin
interface HelpdeskAssignmentApi {
    // VERIFIED: claim is the only helpdesk assignment route. Empty JSON body {}.
    // Response is HelpdeskClaimOut, NOT a shared "AssignmentDto".
    @POST("/messaging/helpdesk/conversations/{conversationId}/claim")
    suspend fun claim(
        @Path("conversationId") conversationId: String,
    ): Response<HelpdeskClaimDto>

    // VERIFIED: queue feed (reused from AND-377). Returns List<Conversation>.
    @GET("/messaging/helpdesk/queue")
    suspend fun queue(
        @Query("group_id") groupId: String,
        @Query("state") state: String? = null,
        @Query("limit") limit: Int? = null,
    ): Response<List<ConversationDto>>
}
```

**Correction (was wrong in the draft):** the original interface declared
`POST /ui/helpdesk/conversations/{id}/claim|assign|transfer` returning a shared
`AssignmentDto`. None of those paths exist. The real helpdesk endpoints are
`POST /messaging/helpdesk/conversations/{conversation_id}/claim` (empty body,
`HelpdeskClaimOut`) and `GET /messaging/helpdesk/queue`. There is **no helpdesk
`assign` and no helpdesk `transfer` route at all.**

**Unverified-assumption (assign/transfer):** if assign/transfer must ship, the
only candidate backend routes are on the *tickets* domain and use a different
contract — `POST /tickets/{ticket_id}/assign` with body
`AssignTicketReq = { "assignee_admin_sub": "<sub>" }` returning `TicketEnvelope`,
and `POST /ticket-spaces/{space_id}/tickets/{ticket_id}/assign` with
`AssignSpaceTicketReq`. These operate on *tickets*, not *conversations*, and
there is **no transfer-to-queue route anywhere**. Treat assign/transfer as
blocked pending a product decision (see §16 Open assumptions and R1/R2).

**Idempotency note (corrected):** `HelpdeskClaimOut` carries an `idempotent: bool`
flag, i.e. the **claim** endpoint is server-side idempotent (re-claiming returns
the same assignment). The draft's blanket "non-idempotent POST, never retry"
rule is therefore wrong for claim; claim MAY be safely retried. The ticket
`assign` POSTs have no idempotency flag and should still not be auto-retried by
the backoff interceptor. The `401` refresh-once-then-retry path applies to all
(verified in `src/api/client.ts`).

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

All requests carry session cookies + `Authorization: Bearer <token>` +
`X-CSRF-Token` (from `ui_csrf`). All bodies and responses are JSON. The
following is **verified against `/openapi.json` and `src/api/types.ts`** unless
flagged otherwise.

**Claim** — `POST /messaging/helpdesk/conversations/{conversation_id}/claim`
(VERIFIED). The web client posts an **empty JSON object** `{}`
(`api.post(..., {})` in `messaging.ts: claimHelpdeskConversation`). No path
`/ui/helpdesk/...` exists — that was wrong in the draft.

**Success (200)** — `HelpdeskClaimOut` (VERIFIED — NOT the draft's `AssignmentDto`):
```json
{
  "ok": true,
  "conversation_id": "conv_1a2b",
  "state": "assigned",
  "assigned_agent_user_id": "usr_8f21",
  "assignment_version": 7,
  "idempotent": false
}
```
Required fields: `ok`, `conversation_id`, `state`, `assigned_agent_user_id`,
`assignment_version`. `idempotent` defaults to `false`. There is **no**
`assignee_name`, `queue_id`, `status`, or `updated_at` in the response — agent
display names must be resolved separately (the web `HelpdeskRoutingBanner` keys
off `active_agent_user_id`, not a name).

**Queue** — `GET /messaging/helpdesk/queue?group_id=&state=&limit=` (VERIFIED) →
`Conversation[]`. Relevant per-conversation routing fields (from
`src/api/types.ts: Conversation`): `routing_mode` (e.g. `helpdesk_bridge`),
`routing_group_id`, `routing_state` (observed values: `awaiting_agent`,
`assigned`, `paused_no_agents_online`), `active_agent_user_id`,
`active_agent_claimed_at`, `assignment_version`. **Correction:** the draft's
`assignee` / `status` model does not match; use these routing fields.

**Assign / Transfer** — **UNVERIFIED / NOT AVAILABLE on the helpdesk domain.**
No `assignee_id` / `queue_id` / `note` request body is defined for any helpdesk
route. The closest real contract (tickets domain, different resource) is:
```json
// POST /tickets/{ticket_id}/assign  — AssignTicketReq (VERIFIED schema)
{ "assignee_admin_sub": "usr_3c90" }   // returns TicketEnvelope
```
Note the field is `assignee_admin_sub` (not `assignee_id`), it targets a
*ticket*, and there is **no `queue_id` and no free-text `note`** on assign. No
transfer endpoint and no transfer-to-queue exists anywhere in the spec. The
draft's assign/transfer bodies and the "exactly one of `assignee_id`/`queue_id`"
rule are unverified assumptions — see §16 and R1/R2.

**Error shapes** (VERIFIED): the helpdesk claim/queue endpoints declare only
`200` and `422: HTTPValidationError` (the FastAPI
`{ "detail": [{ "msg", "loc", "type" }] }` form). They do **not** declare typed
`401/403/404/409` envelopes. The web client treats a failing
`getHelpdeskQueue` query as "not an agent" (the 403/non-member case surfaces via
the query error, not a typed body). The richer
`ErrorEnvelope = { "error": { "code", "message", "details" } }` (schema
`ErrorDetail`, VERIFIED) applies to the **tickets / ticket-spaces** routes, not
to helpdesk. Mapped statuses for Android:
- `401` → refresh once, retry once, else surface session-expired (VERIFIED path).
- `403` → treat as "not authorized / not an agent"; hide queue (matches web).
  **No typed 403 body on helpdesk** — do not parse a `detail.code` for it.
- `404` → "Conversation no longer exists." (remove from cache) —
  *unverified assumption*: 404 is not declared on the helpdesk routes.
- `409` → conflict — *unverified assumption*: **409 is not declared on the
  helpdesk claim route**, and claim is server-idempotent, so a "first-claim
  wins" 409 may never occur. Concurrency is reflected via `assignment_version` /
  `active_agent_user_id` in the queue payload instead. Reconcile by refetching
  the queue row rather than relying on a 409 owner name.
- `422` → `HTTPValidationError` (`detail[]`) → field/sheet error (VERIFIED).

## 6. Data & State Management

- **Single source of truth:** the conversation row in the Room-backed queue cache
  (owned by AND-377). Assignment mutations update that row; both queue and detail
  observe it via Flow, so no duplicate state.
- **Optimistic write:** before the network call, snapshot the current
  `Assignment` and write the predicted new value into the cache; `inFlight` adds
  the conversationId (drives a per-row spinner / disabled buttons).
- **Reconcile:** on `2xx`, overwrite the cached row's routing fields from the
  server `HelpdeskClaimOut` (`state`→`routing_state`,
  `assigned_agent_user_id`→`active_agent_user_id`, `assignment_version`);
  **correction:** there is no `AssignmentDto`. On error, restore the snapshot and
  remove from `inFlight`.
- **Roster:** *unverified assumption* — no helpdesk agents-roster endpoint is
  surfaced in `/openapi.json` (the helpdesk surface is queue + claim only). The
  roster needed for assign/transfer is a dependency on AND-377 that could not be
  confirmed from the sources; if it does not exist, assign/transfer cannot be
  built. Flagged in §16.
- **Undo (claim):** *unverified assumption* — there is **no unassign / release /
  transfer endpoint for helpdesk conversations**, so a true undo of a claim is
  not implementable against the current backend. The web client offers no undo
  (it simply invalidates the `conversations` and `helpdesk-queue` queries). The
  `lastUndoable` design should be dropped or deferred until a release endpoint
  exists. Flagged in §16 / R4.
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
- **Conflict (`409`):** *corrected* — the helpdesk claim route does **not**
  declare a `409`, and claim is server-idempotent (`idempotent` flag), so a
  "someone else claimed first" 409 may never fire. Detect contention instead by
  comparing the returned `assigned_agent_user_id` / `assignment_version` against
  the current agent: if claim succeeds but `assigned_agent_user_id` is someone
  else (or a queue refetch shows a different owner), do not assert local
  ownership; reconcile from the server payload and inform the user. If a `409`
  ever is returned, still never overwrite local with the optimistic value.
- **Offline:** if no network, fail fast with "You're offline — assignment
  changes need a connection." No offline queueing of mutations (explicitly out
  of scope; can be revisited — see Risks).
- **Double-submit guard:** buttons for a conversation are disabled while its id
  is in `inFlight`.

## 8. Security & Privacy

- All mutations require an authenticated agent session; the cookie jar,
  `Authorization: Bearer <token>`, and `X-CSRF-Token` header are attached by the
  existing OkHttp interceptors (auth tickets). **Correction:** auth is not
  cookie-only — the web client also sends a bearer token (`src/api/client.ts`).
  No new credential storage.
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

## 16. Citations & Assumption Audit

Each key technical claim, with verdict and an exact source pointer. OpenAPI
pointers use `METHOD /path` + schema name; frontend pointers use file + symbol;
framework choices are labeled "framework ref".

1. **Claim endpoint is `POST /messaging/helpdesk/conversations/{conversation_id}/claim`
   with an empty body.** VERDICT: Corrected (draft had
   `POST /ui/helpdesk/conversations/{id}/claim`). SOURCE:
   `POST /messaging/helpdesk/conversations/{conversation_id}/claim` (op
   `claim_helpdesk_conversation...`); `src/api/endpoints/messaging.ts:
   claimHelpdeskConversation` (`api.post(..., {})`).
2. **Claim response is `HelpdeskClaimOut = { ok, conversation_id, state,
   assigned_agent_user_id, assignment_version, idempotent }`.** VERDICT:
   Corrected (draft invented `AssignmentDto` with `assignee_id/assignee_name/
   status/queue_id/updated_at`). SOURCE: schema `HelpdeskClaimOut`;
   `src/api/types.ts: HelpdeskClaimOut`.
3. **Helpdesk queue is `GET /messaging/helpdesk/queue?group_id=&state=&limit=` →
   `Conversation[]`.** VERDICT: Verified. SOURCE:
   `GET /messaging/helpdesk/queue` (op `get_helpdesk_queue...`, params
   `group_id,state,limit`); `src/api/endpoints/messaging.ts: getHelpdeskQueue`;
   `src/pages/helpdesk/HelpdeskPage.tsx`.
4. **Conversation routing fields are `routing_mode`, `routing_group_id`,
   `routing_state` (`awaiting_agent`/`assigned`/`paused_no_agents_online`),
   `active_agent_user_id`, `active_agent_claimed_at`, `assignment_version` — not
   `assignee`/`status`.** VERDICT: Corrected. SOURCE: `src/api/types.ts:
   Conversation`; `src/pages/messages/ConversationView.tsx:
   HelpdeskRoutingBanner`; `src/pages/helpdesk/HelpdeskPage.tsx:
   routingStateBadge`.
5. **There is NO helpdesk `assign` and NO helpdesk `transfer` endpoint, and no
   transfer-to-queue route anywhere.** VERDICT: Corrected / Unverified-assumption
   (the entire assign/transfer scope is unbacked). SOURCE: absence in
   `openapi.index.txt` (only `.../claim` and `/queue` exist under
   `messaging/helpdesk`); web has only a claim mutation
   (`src/pages/messages/ConversationView.tsx: claimMutation`).
6. **The only assignment-style routes are on tickets:
   `POST /tickets/{ticket_id}/assign` (`AssignTicketReq = { assignee_admin_sub }`
   → `TicketEnvelope`) and `POST /ticket-spaces/{space_id}/tickets/{ticket_id}/assign`
   (`AssignSpaceTicketReq`).** VERDICT: Verified (as the nearest contract; their
   applicability to *conversations* is Unverified). SOURCE:
   `POST /tickets/{ticket_id}/assign` + schema `AssignTicketReq`;
   `POST /ticket-spaces/{space_id}/tickets/{ticket_id}/assign`.
7. **Assign field name is `assignee_admin_sub`, not `assignee_id`; no `queue_id`
   or `note` on assign.** VERDICT: Corrected. SOURCE: schema `AssignTicketReq`
   (single required `assignee_admin_sub`).
8. **Auth = `Authorization: Bearer <accessToken>` + `X-CSRF-Token` (echo of
   `ui_csrf` cookie) + cookies (`credentials: include`).** VERDICT: Corrected
   (draft said cookie-only). SOURCE: `src/api/client.ts` (sets `Authorization`
   from `useAuthStore`, `X-CSRF-Token` from `getCookie("ui_csrf")`).
9. **`401` → one `POST /ui/session/refresh` then retry once; failure logs out.**
   VERDICT: Verified. SOURCE: `src/api/client.ts: refreshSession` +
   401-handling block (single `refreshPromise`, one retry).
10. **Error envelope `{ error: { code, message, details } }` (`ErrorDetail`)
    applies to tickets/ticket-spaces, not helpdesk; helpdesk claim/queue declare
    only `200` + `422: HTTPValidationError`.** VERDICT: Corrected (draft applied
    a generic FastAPI `detail` + 401/403/404/409 mapping to helpdesk). SOURCE:
    schema `ErrorEnvelope`/`ErrorDetail`; `openapi.index.txt` lines for
    `messaging/helpdesk/...claim` and `.../queue` (resp `200;422` only).
11. **Claim is server-idempotent (`idempotent` flag); a "first-claim-wins" `409`
    is not declared on the helpdesk claim route.** VERDICT: Corrected (draft
    treated claim as non-idempotent and built 409-conflict UX on it). SOURCE:
    schema `HelpdeskClaimOut.idempotent`; absence of `409` on the claim op in
    `openapi.index.txt`.
12. **Non-agent / unauthorized surfaces as a failing queue query, treated as
    "not an agent" (no typed 403 body).** VERDICT: Verified. SOURCE:
    `src/pages/helpdesk/HelpdeskPage.tsx` (`isAgent = !queueError`,
    `retry: false`).
13. **No helpdesk unassign/release/transfer route → no true claim-undo.**
    VERDICT: Corrected / Unverified-assumption. SOURCE: absence in
    `openapi.index.txt`; web claim mutation only invalidates queries, offers no
    undo (`src/pages/messages/ConversationView.tsx: claimMutation.onSuccess`).
14. **No helpdesk agents-roster endpoint surfaced.** VERDICT:
    Unverified-assumption (the roster AND-377 is assumed to provide could not be
    confirmed from the sources). SOURCE: no agents-roster op under
    `messaging/helpdesk` in `openapi.index.txt`.
15. **Stack/tooling: Kotlin 2.0.21, Compose + Material 3 `ModalBottomSheet`,
    Hilt/KSP, Retrofit 2.11/OkHttp 4.12/Moshi, Room 2.6, minSdk 24/target 35,
    JDK 17.** VERDICT: Unverified-assumption (project conventions inherited from
    AND-377; not checkable from backend/frontend sources). SOURCE: framework ref
    (Android Jetpack — Compose Material 3 `ModalBottomSheet`, Retrofit, Hilt;
    no authoritative pointer in this repo).

### Corrections made

- §2/§5/§8: auth corrected from "cookie-only" to **bearer + cookie + CSRF**.
- §2/§4.2/§5: claim path corrected `/ui/helpdesk/...` → `/messaging/helpdesk/
  conversations/{conversation_id}/claim`; queue path added.
- §4.2/§5/§6: response model corrected `AssignmentDto` → **`HelpdeskClaimOut`**
  with real field names; cache reconcile mapped to routing fields.
- §4.2/§5/§13: assign/transfer flagged as **not present on the helpdesk
  backend**; nearest real contract (tickets `assignee_admin_sub`) documented;
  transfer-to-queue and free-text note marked unsupported.
- §4.2/§5/§7: claim **idempotency** corrected; 409-conflict UX downgraded to a
  version/owner-based reconcile because 409 is not declared and claim is
  idempotent.
- §6: undo-claim and agents-roster reframed as unverified/likely-unimplementable.

### Open assumptions

- **Assign & Transfer scope (R1/R2):** no helpdesk endpoints exist. Either
  re-scope this ticket to **claim-only**, or define new backend routes, or
  retarget to the *tickets* domain (different resource + `assignee_admin_sub`,
  no queue/note). Unverifiable because the backend simply has no such routes.
- **Transfer-to-queue & free-text note:** no route or field anywhere — assume
  unsupported until backend adds them.
- **Claim undo / unassign (R4):** no release endpoint — assume not implementable.
- **Agents roster for the picker:** no endpoint surfaced; depends on an AND-377
  capability not visible in these sources.
- **Stack/version pins & module layering:** inherited from AND-377; not
  verifiable from backend/frontend reference here.
- **403/404 mapping on helpdesk:** not declared in OpenAPI; behavior inferred
  from web (queue-query-error = not agent). Treat as best-effort until observed
  against the live dev host.

## 17. Test Plan

IDs `TC-AND-378-NN`. Targets: JVM = local JVM/Robolectric unit; MWS =
MockWebServer contract; emu = headless AVD `test35` (x86_64, API 35); device =
physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). Use `device` for
real-hardware behavior; everything else prefers `emu`/JVM for CI speed.

**TC-AND-378-01 — Claim happy path (contract).**
Type: contract/MockWebServer (JVM). Target: MWS. Preconditions:
`AssignmentRepository` wired to MWS; conversation `conv_1` in cache with
`routing_state=awaiting_agent`. Steps: enqueue `200` `HelpdeskClaimOut`
`{ok:true, conversation_id:"conv_1", state:"assigned",
assigned_agent_user_id:"<me>", assignment_version:7, idempotent:false}`; call
`repo.claim("conv_1")`. Expected: request is
`POST /messaging/helpdesk/conversations/conv_1/claim` with body `{}` and headers
`Authorization: Bearer …` + `X-CSRF-Token`; result `ApiResult.Success`; cache row
updated `routing_state=assigned`, `active_agent_user_id=<me>`,
`assignment_version=7`. Traces: AC-1, AC-8.

**TC-AND-378-02 — Claim ViewModel optimistic then reconcile (unit).**
Type: unit (Turbine). Target: JVM. Preconditions: `AssignmentViewModel` with fake
repo. Steps: call `claim("conv_1")`; observe `uiState`. Expected: immediately
`inFlight` contains `conv_1` and predicted assigned-to-me row shows; on repo
success `inFlight` empties and row reconciles from `HelpdeskClaimOut`; success
snackbar "Claimed". Traces: AC-1, AC-4, AC-6.

**TC-AND-378-03 — Claim is idempotent on re-claim (contract).**
Type: contract/MockWebServer. Target: MWS. Preconditions: row already
`assigned` to me. Steps: enqueue `200` with `idempotent:true`, same
`assignment_version`; call `repo.claim` again. Expected: no error, no spurious
version bump, no rollback; state stays `assigned`; repository does NOT treat this
as a conflict. (Validates the idempotency correction.) Traces: AC-1, AC-5.

**TC-AND-378-04 — Contention reconcile via owner/version, not 409 (unit+contract).**
Type: contract/MockWebServer + unit. Target: MWS. Preconditions: I attempt to
claim `conv_1`. Steps: enqueue `200` `HelpdeskClaimOut` whose
`assigned_agent_user_id` is a DIFFERENT agent (`usr_other`) with higher
`assignment_version`; call claim. Expected: ViewModel does NOT assert local
ownership; row reconciles to `usr_other`; snackbar informs "Already handled by
another agent" and a queue refetch is triggered. No reliance on a `409` body.
Traces: AC-5, AC-4.

**TC-AND-378-05 — 422 validation error mapped (contract).**
Type: contract/MockWebServer. Target: MWS. Preconditions: repo→MWS. Steps:
enqueue `422` `HTTPValidationError`
`{"detail":[{"loc":["body"],"msg":"value is not a valid…","type":"value_error"}]}`;
call claim. Expected: `ApiResult.Error` with the parsed `detail[].msg`; optimistic
change rolled back; `inFlight` cleared; field/snackbar error shown. Traces: AC-4.

**TC-AND-378-06 — 401 triggers exactly one refresh-then-retry (contract).**
Type: contract/MockWebServer. Target: MWS. Preconditions: authenticated session.
Steps: enqueue `401`, then a `200` for `POST /ui/session/refresh`, then `200`
`HelpdeskClaimOut` for the retried claim. Call claim. Expected: exactly two claim
attempts (original + one retry) with one interleaved refresh; final success;
verify NO third attempt. A second consecutive `401` (no second refresh) →
session-expired surfaced. Traces: AC-8.

**TC-AND-378-07 — No auto-retry of mutating POSTs by backoff interceptor (contract).**
Type: contract/MockWebServer. Target: MWS. Preconditions: OkHttp stack with the
backoff retry interceptor (idempotent-GET only). Steps: enqueue a single `503`
for the ticket-domain `POST /tickets/{id}/assign` (the non-idempotent mutation).
Expected: exactly ONE request recorded (no backoff retries); `ApiResult.Error`
surfaced. (Claim, being idempotent, is allowed to retry and is covered by
TC-06.) Traces: AC-8.

**TC-AND-378-08 — Timeout = unknown outcome → rollback + queue refetch (unit+contract).**
Type: contract/MockWebServer + unit. Target: MWS. Preconditions: 20s call
timeout configured short for test; flaky dev-host simulation. Steps: MWS delays
beyond timeout (no response) for claim; ViewModel issues claim. Expected:
optimistic change rolled back, `inFlight` cleared, snackbar "Couldn't confirm —
refreshing.", and a follow-up idempotent `GET /messaging/helpdesk/queue` is
issued to learn true state. Traces: AC-4.

**TC-AND-378-09 — Offline fast-fail (unit).**
Type: unit. Target: JVM. Preconditions: connectivity reports offline. Steps: call
claim. Expected: no network attempt; immediate `ApiResult.Error` "You're offline
— assignment changes need a connection."; no cache mutation; no offline queueing.
Traces: AC-4.

**TC-AND-378-10 — Non-agent / unauthorized queue (contract+UI).**
Type: contract/MockWebServer + Compose-UI. Target: MWS + emu. Preconditions:
non-agent session. Steps: `GET /messaging/helpdesk/queue` returns an error
(401/403); render HelpdeskPage. Expected: queue treated as empty/hidden
("not an agent"), no claim button shown, app does not crash; 403 from server is
honored regardless of any client capability hint. Traces: AC-7, AC-6.

**TC-AND-378-11 — Claim action UI + double-submit guard (Compose-UI).**
Type: Compose-UI. Target: emu. Preconditions: queue with one
`awaiting_agent` row. Steps: tap Claim; while `inFlight`, tap again. Expected:
Claim button shows "Claiming…" and is disabled during `inFlight` (single request
fired); on success the row banner becomes "You are handling this conversation".
Traces: AC-1, AC-6.

**TC-AND-378-12 — Action availability matrix (unit).**
Type: unit. Target: JVM. Preconditions: rows in states
`awaiting_agent`/`assigned-to-me`/`assigned-to-other`; current agent caps. Steps:
evaluate availability rules. Expected: Claim visible only when
`active_agent_user_id == null` / `routing_state == awaiting_agent`; assign/
transfer affordances are GATED OFF pending backend support (per §16) and must
not be shown as functional. Traces: AC-1, AC-2, AC-3, AC-6.

**TC-AND-378-13 — Accessibility of claim action & routing banner (Compose-UI/a11y).**
Type: Compose-UI (accessibility). Target: emu. Preconditions: HelpdeskPage with
queue. Steps: assert semantics. Expected: Claim button exposes
`contentDescription`/label "Claim this helpdesk conversation"; touch target ≥
48dp; routing-state badge/banner text is announced; strings come from
`strings.xml` (no concatenation); snackbar announced via live region. Traces:
AC-9.

**TC-AND-378-14 — Real dev-host claim on physical device (instrumented/e2e).**
Type: instrumented/e2e. Target: **device (SM-A156U, API 34, arm64-v8a)** — MUST
run here, not the emulator, to validate real-network behavior against the flaky
plaintext-HTTP dev host and arm64/API-34 transport (TLS-less, cleartext-traffic
config, real latency/timeouts). Preconditions: signed-in agent; dev host
reachable. Steps: open Helpdesk, claim an `awaiting_agent` conversation. Expected:
`200 HelpdeskClaimOut`, banner flips to "You are handling this conversation",
queue/conversation lists refresh; on transient dev-host failure the timeout
rollback+refetch path (TC-08) behaves correctly on real network. Traces: AC-1,
AC-4.

### Coverage matrix

| AC | Description | Covered by |
| -- | ----------- | ---------- |
| AC-1 | Claim an unassigned conversation | TC-01, TC-02, TC-03, TC-11, TC-12, TC-14 |
| AC-2 | Assign to another agent | TC-12 (gated; assign unbacked — see §16) |
| AC-3 | Transfer to agent/queue | TC-12 (gated; transfer unbacked — see §16) |
| AC-4 | Optimistic update + rollback on error/timeout | TC-02, TC-04, TC-05, TC-08, TC-09, TC-14 |
| AC-5 | Conflict does not overwrite local state | TC-03, TC-04 |
| AC-6 | Availability matrix + no double-submit | TC-02, TC-10, TC-11, TC-12 |
| AC-7 | Server `403` always honored | TC-10 |
| AC-8 | No auto-retry; one `401` refresh-retry | TC-01, TC-06, TC-07 |
| AC-9 | TalkBack/i18n for actions, sheets, snackbars | TC-13 |

Note: AC-2 and AC-3 cannot be fully satisfied against the current backend (no
helpdesk assign/transfer endpoints). TC-12 only verifies the affordances stay
gated; full assign/transfer coverage is blocked on the §16 open assumptions.
