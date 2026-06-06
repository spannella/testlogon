---
id: AND-162
title: Helpdesk claim + reply
milestone: M3
epic: E22
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-161]
blocks: []
---

# AND-162 — Helpdesk claim + reply

## 1. Overview & Goal

AND-161 delivered the agent-facing **helpdesk queue** — a paged, read-only list of unclaimed (and assigned) helpdesk conversations rendered for users in the agent role. AND-162 adds the two write actions that turn that queue into a usable workflow: an agent can **claim** a conversation (`POST /messaging/helpdesk/conversations/{conversation_id}/claim` — CORRECTED: the path is prefixed with `/messaging` and the path param is `conversation_id`, the messaging conversation id, not a separate helpdesk id; verified against OpenAPI), and once claimed can **reply** into the underlying conversation thread.

The defining requirement of this ticket is correct handling of the **claim/assignee error surface**: a helpdesk conversation can be claimed concurrently by multiple agents, can already be assigned to someone else, can be closed, or can require a permission the current agent lacks. **CORRECTION/UNVERIFIED:** the backend's claim endpoint only documents `200:HelpdeskClaimOut` and `422:HTTPValidationError` in OpenAPI; the distinct `409`/`403` claim-conflict codes the original draft assumed (`helpdesk_already_claimed`, `helpdesk_conversation_closed`, `forbidden`) are NOT present in the sources. The web reference handles a failed claim with a single generic `toast.error("Failed to claim conversation")` (`ConversationView.tsx: claimMutation.onError`), i.e. it does NOT do distinct claim-error mapping today. The reply path, however, does emit verified distinct codes (`helpdesk_claim_required`, `helpdesk_assignee_required`, `helpdesk_claim_not_available` — `client.ts: mapAuthorizationError`). Treat the distinct claim-error surface below as an Android-side enhancement gated on backend confirmation (OQ-1), not a mirror of the web client; each error condition should still produce a distinct, correct, non-destructive UI outcome where the backend signals it — never a generic "something went wrong" that loses the agent's place in the queue or their typed reply.

Goal, restated as a testable outcome: from the AND-161 queue, an agent taps a conversation, claims it (button transitions claim → assigned-to-me → reply enabled), and sends a reply that appears in the thread. If the claim fails because another agent already claimed it (UNVERIFIED conflict shape — see §16; the backend may instead return the conversation already in `state: "assigned"` to another agent via the queue, or `idempotent: true` if it was already the caller's), the UI surfaces a specific "already claimed by {agent}" state and refreshes via the queue rather than silently failing. The claim action, assignee state model, claim-error mapping, and the reply-enablement gate are the deliverables. The generic optimistic text-send mechanics are **reused** from AND-124's composer/outbox, not re-implemented; this ticket adds the claim gate and helpdesk-specific reply wiring on top.

## 2. Context & References

- **Module:** `feature-messaging` (Gradle module `:feature:messaging`), package `com.testlogon.android.feature.messaging.helpdesk`. The claim action and assignee state extend the helpdesk queue feature introduced by AND-161; the reply path reuses the thread/composer from AND-123/AND-124.
- **Layering:** `feature-messaging` -> `core-network` (Retrofit service, `ApiResult<T>`, CSRF/cookie/refresh interceptors), `core-model` (DTO/domain + adapters), `core-data` (Room cache + repository), `core-ui` (Compose components, state composables, theme). No backward dependencies.
- **Backend:** FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000` (plaintext HTTP, unreliable). OpenAPI at `/openapi.json`. Cookie-based auth: session cookies + `ui_csrf` cookie echoed as `X-CSRF-Token`; on `401` the OkHttp authenticator calls `POST /ui/session/refresh` once and retries. Persistent cookie jar required (established by core-network/auth tickets).
- **Web reference (CORRECTED paths/names):** the helpdesk calls live in `src/api/endpoints/messaging.ts` (`claimHelpdeskConversation`, `getHelpdeskQueue`, `sendTextMessage`), NOT a `helpdesk.ts` file. The claim response type is `HelpdeskClaimOut` in `src/api/types.ts` (`{ ok, conversation_id, state, assigned_agent_user_id, assignment_version, idempotent }`) — there is no `HelpdeskConversation`/`Assignee` DTO; the queue returns `Conversation[]` whose routing fields (`routing_state`, `active_agent_user_id`, `assignment_version`) carry assignment state. Claim-error string constants are mapped in `src/api/client.ts: mapAuthorizationError` (`helpdesk_claim_required`, `helpdesk_assignee_required`, `helpdesk_claim_not_available`, `role_required*`). The Android DTOs and error-code constants must mirror these real shapes and string values exactly.
- **Dependency AND-161** supplies: `HelpdeskQueueViewModel`, `HelpdeskQueueUiState`, the Paging 3 queue source, the `HelpdeskConversation` domain model and `HelpdeskConversationDto`, the agent-role gate, and the queue list/row Composables. AND-162 adds the claim write action, the assignee/claim state, and the reply entry point.
- **Dependency AND-124 / AND-123** supply (transitively, reused not re-built): `MessageComposer`, `ComposerState`, the outbox (`OutboxMessageEntity`/`OutboxDao`), `MessageRepository.sendMessage`, optimistic-send + ack reconciliation, and the thread `LazyColumn`.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15, Room 2.6, Paging 3. minSdk 24 / target 35, JDK 17.

## 3. Functional Requirements

FR-1. From an AND-161 queue row, tapping a conversation opens a **Helpdesk conversation detail** screen showing the conversation thread (reusing the AND-123 message list) plus a claim/assignee header bar.

FR-2. The header bar reflects the conversation's **assignee state**: `UNCLAIMED` (shows a primary "Claim" button), `ASSIGNED_TO_ME` (shows "Assigned to you" + reply enabled), or `ASSIGNED_TO_OTHER` (shows "Claimed by {agentName}" + reply disabled with explanatory text).

FR-3. Tapping **Claim** issues `POST /helpdesk/conversations/{id}/claim`. While in flight the button shows a loading state and is non-tappable (prevents double-claim).

FR-4. On claim success the header transitions to `ASSIGNED_TO_ME`, the reply composer becomes enabled, and the corresponding queue row (AND-161) is updated/invalidated so it no longer shows as unclaimed.

FR-5. The **reply composer** is visible at the bottom of the detail screen but is **enabled only when `ASSIGNED_TO_ME`**. When `UNCLAIMED` it shows a hint ("Claim this conversation to reply"); when `ASSIGNED_TO_OTHER` it shows the assignee and is disabled.

FR-6. Sending a reply uses the standard conversation message send (`POST /conversations/{id}/messages` via the reused AND-124 composer/outbox) against the conversation `id` backing the helpdesk conversation. Optimistic insert, ack reconciliation, and manual retry behave exactly as in AND-124.

FR-7. Claim **errors must surface specifically** (covers Acceptance "claim errors surface correctly"). **CORRECTION:** the specific backend codes below are UNVERIFIED against OpenAPI (only `200`/`422` are documented) and the web client uses a generic toast — these are Android-side defensive enhancements pending OQ-1:
- Already claimed / assigned to another agent (UNVERIFIED conflict shape; may surface as `state: "assigned"` with a different `assigned_agent_user_id`, or a `403`/`409`): show "Already claimed by {agent}", transition header to `ASSIGNED_TO_OTHER`, refresh via queue; do **not** treat as a generic failure.
- Already assigned to me (idempotent re-claim — VERIFIED via `idempotent: true`): treat as success → `ASSIGNED_TO_ME`.
- Conversation closed (VERIFIED `state: "closed"` string; closed-error code UNVERIFIED): show "This conversation is closed", keep reply disabled.
- Not online/available to claim (VERIFIED code `helpdesk_claim_not_available`): show "You need to be online and available to claim", non-retryable until availability changes.
- Permission denied / not an agent (VERIFIED codes `role_required`/`role_required_scope`/`role_required_admin_profile_type`, `403`): show "You don't have permission to claim", non-retryable.
- Not found (`404`, UNVERIFIED for this endpoint): show "Conversation no longer available", offer back-to-queue.
- Network/timeout/`5xx`: retryable inline error on the Claim button; claim not applied.

FR-8. A claim failure never loses the agent's position: the detail screen stays open, the thread remains visible, and (where applicable) the header reflects the now-known true state.

FR-9. The agent-role gate from AND-161 still applies: non-agents cannot reach this screen; if role is lost mid-session the screen degrades to read-only with the claim/reply controls hidden.

## 4. Technical Design

### 4.1 Assignee / claim state

Add to `core-model` (or co-located helpdesk model from AND-161):

```kotlin
enum class HelpdeskAssignment { UNCLAIMED, ASSIGNED_TO_ME, ASSIGNED_TO_OTHER }

data class HelpdeskAssignee(
    val agentId: String,
    val agentName: String,
)

// HelpdeskConversation (from AND-161) gains assignee fields if not already present:
data class HelpdeskConversation(
    val id: String,                 // helpdesk conversation id
    val conversationId: String,     // underlying messaging conversation id (for replies)
    val subject: String?,
    val assignment: HelpdeskAssignment,
    val assignee: HelpdeskAssignee?,// null when UNCLAIMED
    val isClosed: Boolean = false,
)
```

### 4.2 Detail UI state

```kotlin
sealed interface ClaimState {
    data object Idle : ClaimState
    data object Claiming : ClaimState
    data class Error(val error: ClaimError, val retryable: Boolean) : ClaimState
}

enum class ClaimError { ALREADY_CLAIMED, CLOSED, FORBIDDEN, NOT_AVAILABLE, NOT_FOUND, NETWORK, UNKNOWN }
// NOT_AVAILABLE added for the verified `helpdesk_claim_not_available` code (agent must be online/available).

data class HelpdeskDetailUiState(
    val helpdeskId: String,
    val conversationId: String,
    val assignment: HelpdeskAssignment = HelpdeskAssignment.UNCLAIMED,
    val assignee: HelpdeskAssignee? = null,
    val isClosed: Boolean = false,
    val claim: ClaimState = ClaimState.Idle,
    val replyEnabled: Boolean = false, // == (assignment == ASSIGNED_TO_ME && !isClosed)
    val isLoading: Boolean = false,
    val loadError: UiError? = null,
)
```

`replyEnabled` is derived, not independently stored, so it cannot drift from `assignment`.

### 4.3 ViewModel

```kotlin
@HiltViewModel
class HelpdeskDetailViewModel @Inject constructor(
    private val repo: HelpdeskRepository,
    savedState: SavedStateHandle,
) : ViewModel() {

    private val helpdeskId: String = savedState["helpdeskId"]!!

    val uiState: StateFlow<HelpdeskDetailUiState> = /* combine repo flows */ ...

    fun onClaimClick()        // fires claim, manages ClaimState
    fun onRetryClaim()        // re-fires claim after a retryable error
    fun onDismissClaimError() // clears ClaimState.Error -> Idle
}
```

`onClaimClick`:
1. Guard: ignore if `claim is Claiming` or `assignment == ASSIGNED_TO_ME`.
2. Set `claim = Claiming`.
3. `viewModelScope.launch { when (val r = repo.claim(helpdeskId)) { ... } }`.

```kotlin
when (val r = repo.claim(helpdeskId)) {
    is ApiResult.Success -> {           // server returns updated conversation w/ assignee=me
        repo.cacheConversation(r.data)  // updates Room -> queue invalidation
        // uiState recomputes assignment = ASSIGNED_TO_ME, claim = Idle
    }
    is ApiResult.Error -> {
        val mapped = ClaimErrorMapper.map(r.error) // see §5
        // ALREADY_CLAIMED -> also refresh assignee from r.error payload / re-fetch
        if (mapped == ClaimError.ALREADY_CLAIMED) repo.refreshConversation(helpdeskId)
        // set ClaimState.Error(mapped, retryable = mapped in {NETWORK, UNKNOWN})
    }
}
```

### 4.4 Repository

```kotlin
interface HelpdeskRepository {              // extends the AND-161 interface
    suspend fun claim(helpdeskId: String): ApiResult<HelpdeskConversation>
    suspend fun refreshConversation(helpdeskId: String): ApiResult<HelpdeskConversation>
    fun observeConversation(helpdeskId: String): Flow<HelpdeskConversation?>
    suspend fun cacheConversation(c: HelpdeskConversation)
}
```

`claim` calls the service via the shared `apiCall { }` helper (converts exceptions/non-2xx into `ApiResult.Error`, decodes the FastAPI `detail` shape), then maps `HelpdeskClaimOutDto.toDomain()` (CORRECTED DTO name). **Note:** `refreshConversation` cannot use a single-conversation GET (none exists); it must re-fetch `GET /messaging/helpdesk/queue` and locate the row by `conversation_id`, or rely on AND-161's queue refresh. The claim is a **non-idempotent POST** at the HTTP layer; it must therefore be excluded from the AND-016 GET-only retry/backoff (claims are never auto-retried — see §7).

### 4.5 Composables

```kotlin
@Composable
fun HelpdeskDetailScreen(
    state: HelpdeskDetailUiState,
    onClaim: () -> Unit,
    onRetryClaim: () -> Unit,
    onSendReply: () -> Unit,           // delegates to reused MessageComposer
    composerState: ComposerState,
    onDraftChange: (String) -> Unit,
    onBack: () -> Unit,
)

@Composable
fun ClaimHeaderBar(
    assignment: HelpdeskAssignment,
    assignee: HelpdeskAssignee?,
    claim: ClaimState,
    isClosed: Boolean,
    onClaim: () -> Unit,
    onRetryClaim: () -> Unit,
)
```

The thread list is the AND-123 message list. The composer is the AND-124 `MessageComposer`, wrapped so its `enabled`/hint reflect `state.replyEnabled`. Claim errors render via the AND-021 state composables (inline error) — not a blocking dialog — except `FORBIDDEN`/`NOT_FOUND`, which render as a full-screen state with a back-to-queue action.

### 4.6 Navigation

A new authenticated route `helpdesk/{helpdeskId}` registered in the helpdesk nav graph (from AND-161). The queue row's `onClick(helpdeskId)` navigates here, passing `helpdeskId` as a typed nav arg consumed via `SavedStateHandle`.

## 5. API Contract

**Claim endpoint (CORRECTED):** `POST /messaging/helpdesk/conversations/{conversation_id}/claim` (path param `conversation_id` = the messaging conversation id). Verified: OpenAPI `POST /messaging/helpdesk/conversations/{conversation_id}/claim`, op `claim_helpdesk_conversation_*`. Params: `conversation_id`, `authorization`, `X-SESSION-ID`. There is **NO** separate "helpdesk conversation id" and **NO** `GET /helpdesk/conversations/{id}` single-conversation endpoint (the only helpdesk reads are the claim POST and `GET /messaging/helpdesk/queue`).

**Request headers:** session cookies (auto via cookie jar) + `X-CSRF-Token: <ui_csrf>` (auto via CSRF interceptor — verified `client.ts` sets `X-CSRF-Token` from the `ui_csrf` cookie, `credentials: include`). `Content-Type: application/json`. Body is empty `{}` — verified: `messaging.ts: claimHelpdeskConversation` posts `{}`, and OpenAPI lists `req=` (no request body schema).

**Success `200` response (CORRECTED — schema `HelpdeskClaimOut`):**
```json
{
  "ok": true,
  "conversation_id": "conv_01H...",
  "state": "assigned",
  "assigned_agent_user_id": "usr_01H...",
  "assignment_version": 3,
  "idempotent": false
}
```
Required fields: `ok`, `conversation_id`, `state`, `assigned_agent_user_id`, `assignment_version`; `idempotent` defaults `false`. There is **no** `id`, `subject`, nested `assignee` object, or `is_closed` in the claim response. The agent's display name is **not** returned by claim — only `assigned_agent_user_id`. To show "Claimed by {name}" the client must resolve the name from the queue `Conversation`/participant data or a user lookup (see OQ-2).

**Claim DTO (CORRECTED to match `HelpdeskClaimOut`):**
```kotlin
@JsonClass(generateAdapter = true)
data class HelpdeskClaimOutDto(
    @Json(name = "ok") val ok: Boolean,
    @Json(name = "conversation_id") val conversationId: String,
    @Json(name = "state") val state: String,                  // "assigned" | "awaiting_agent" | "paused_no_agents_online" | "closed"
    @Json(name = "assigned_agent_user_id") val assignedAgentUserId: String,
    @Json(name = "assignment_version") val assignmentVersion: Int,
    @Json(name = "idempotent") val idempotent: Boolean = false,
)

interface HelpdeskApi {                                       // extends AND-161 service
    @POST("messaging/helpdesk/conversations/{conversation_id}/claim")
    suspend fun claim(@Path("conversation_id") conversationId: String): Response<HelpdeskClaimOutDto>

    // NO single-conversation GET exists; refresh assignment state via the queue:
    @GET("messaging/helpdesk/queue")
    suspend fun queue(
        @Query("group_id") groupId: String,
        @Query("state") state: String? = null,
        @Query("limit") limit: Int? = null,
    ): Response<List<HelpdeskConversationDto>>               // queue rows are Conversation DTOs (AND-161)
}
```

`state.toDomain()` maps the backend `state` string to the client `HelpdeskAssignment`: `"assigned"` → `ASSIGNED_TO_ME` when `assignedAgentUserId == currentUserId`, else `ASSIGNED_TO_OTHER`; `"awaiting_agent"`/`"paused_no_agents_online"` → `UNCLAIMED`; `"closed"` → closed (reply disabled). These four backend strings are verified in `ConversationView.tsx: HelpdeskRoutingBanner` and `HelpdeskPage.tsx: routingStateBadge`. The `currentUserId` comes from the auth store (`authStore.userId`), not a per-claim field.

**Reply endpoint (CORRECTED):** `POST /messaging/conversations/{conversation_id}/messages` (verified OpenAPI, op `send_text_message_*`), request schema `SendTextMessageIn` (primary field `text`, maxLength 4000; no `client_id`/`idempotency_key` field in the schema), response `MessageOut`. The original draft's `POST /conversations/{id}/messages` (missing `/messaging`) and `SendMessageRequest{body, client_id}`/`MessageDto` names were wrong. The reused AND-124 send path must target this path/DTO. No new reply DTO is defined here.

**Claim error responses (CORRECTED / UNVERIFIED):** OpenAPI documents only `200:HelpdeskClaimOut` and `422:HTTPValidationError` for the claim endpoint, and the web client does **no** claim-specific code mapping (generic toast). The distinct claim conflict/closed/forbidden codes below are therefore **UNVERIFIED assumptions** pending backend confirmation (OQ-1) — implement defensively but do not assert them as contract:
- `422 HTTPValidationError` (verified) — `detail` is `[{loc,msg,type},...]`; surface a validation/unknown error.
- (UNVERIFIED) conflict where the conversation is already `assigned` to another agent — the contract may express this by returning `state: "assigned"` with a different `assigned_agent_user_id`, or via a non-2xx. If a `403`/`409` with a `detail.code` is returned, reuse the verified reply-side codes where applicable: `helpdesk_claim_not_available` (agent not online/available), `role_required*` (permission). Map to a distinct UI outcome per §7.
- `idempotent: true` (verified field) when re-claiming a conversation already assigned to the caller → treat as success → `ASSIGNED_TO_ME`.
- `401` → authenticator runs `POST /ui/session/refresh` once and retries; second `401` → re-auth (verified `client.ts: refreshSession`).
- `5xx` / timeout / `IOException` → `NETWORK`, retryable.

```kotlin
// Defensive mapper — the only VERIFIED non-success status for claim is 422.
// Conflict/closed/forbidden branches are UNVERIFIED (OQ-1) and key off the
// real reply-side codes if the backend reuses them.
object ClaimErrorMapper {
    fun map(e: UiError): ClaimError = when (e) {
        is UiError.Forbidden -> when (e.code) {              // verified codes from client.ts
            "helpdesk_claim_not_available" -> ClaimError.NOT_AVAILABLE
            "role_required", "role_required_scope",
            "role_required_admin_profile_type" -> ClaimError.FORBIDDEN
            else -> ClaimError.FORBIDDEN
        }
        is UiError.Conflict -> ClaimError.ALREADY_CLAIMED     // UNVERIFIED shape (OQ-1)
        is UiError.Validation -> ClaimError.UNKNOWN           // 422 HTTPValidationError
        is UiError.NotFound -> ClaimError.NOT_FOUND
        is UiError.Network, is UiError.Timeout, is UiError.Server -> ClaimError.NETWORK
        else -> ClaimError.UNKNOWN
    }
}
```

`detail` may be `string | [{msg,...}] | {code,...}`; reuse the existing decoder from AND-015 — verified the web client's `normalizeErrorDetail` handles exactly these three shapes (`client.ts`). The `{code,...}` form carries the helpdesk/role codes above; the error-code string constants must match `src/api/client.ts: mapAuthorizationError`.

## 6. Data & State Management

- **Source of truth for the conversation's assignee state:** the helpdesk conversation cached in Room (owned by AND-161, extended here with assignee/closed columns). The detail screen `observeConversation(helpdeskId)` flows from Room; `claim` success / `refreshConversation` write back, which both updates the detail header **and** invalidates the AND-161 queue Paging source so the row reflects the new state without a manual refresh.
- **Source of truth for reply messages:** Room `MessageEntity` + outbox (AND-123/AND-124), keyed by `conversationId`. Replies persist and reconcile exactly as standard messages.
- **Derived state:** `replyEnabled = assignment == ASSIGNED_TO_ME && !isClosed`, computed in the `combine`/mapping, never stored separately.
- **Draft persistence:** reply draft held in `SavedStateHandle` (key `draft_<conversationId>`) per AND-124, so rotation/process recreation does not lose typing.
- **Claim transient state:** `ClaimState` is ViewModel-only (in-flight/error) and intentionally **not** persisted — after process death the screen re-derives true assignment from a fresh `get`/cache, which is authoritative over any stale "claiming" state.
- **Ordering / merge / dedup** for the thread are unchanged from AND-123/AND-124.
- **Threading:** DB writes on `Dispatchers.IO`; state as `StateFlow<HelpdeskDetailUiState>` via `stateIn(viewModelScope, WhileSubscribed(5_000), initial)`.

## 7. Error Handling & Resilience

- **Claim is never auto-retried.** It is a non-idempotent POST without a client idempotency key; an automatic retry could double-claim or claim a conversation the agent has since navigated away from. Retry is **manual only**, via the explicit "Retry" affordance, and only offered for `NETWORK`/`UNKNOWN`. This explicitly excludes claim from the AND-016 idempotent-GET backoff policy.
- **Concurrent claim (the headline race):** two agents claim simultaneously; the loser must end up in `ASSIGNED_TO_OTHER`. **CORRECTION:** the exact loser signal is UNVERIFIED — OpenAPI documents no `409`/`helpdesk_already_claimed` for this endpoint. The backend may (a) return `200 HelpdeskClaimOut` with `assigned_agent_user_id` set to the winner (loser detects `assignedAgentUserId != currentUserId` → `ASSIGNED_TO_OTHER`), or (b) return a non-2xx conflict. Design must handle the `200`-with-other-agent case as the primary path and a non-2xx conflict defensively. The loser's UI must (a) not show a generic error, (b) display "Claimed by {agent}", (c) update the header to `ASSIGNED_TO_OTHER`, and (d) refresh the queue so the row is consistent. Covered by explicit tests (§11/§17). **Resolve via OQ-1 before merge.**
- **Timeouts:** OkHttp call timeout ~20s (dev-host policy). A claim exceeding it becomes a `NETWORK` retryable error; the button returns to Idle, claim not applied. The UI never hangs.
- **Closed conversation:** `CLOSED` disables reply and shows a banner; claim is not retryable.
- **Refresh-on-401:** handled centrally by the authenticator; the claim coroutine sees only the post-refresh outcome. A double-401 surfaces re-auth, not a claim error.
- **Reply errors** are handled by the reused AND-124 outbox (FAILED + manual retry, body preserved); this ticket adds no new reply error handling.
- **Stale assignee in cache:** if the cached state says `UNCLAIMED` but the server says assigned, the claim response (`state`/`assigned_agent_user_id`/`idempotent`) corrects it; on screen entry a best-effort queue re-fetch (`GET /messaging/helpdesk/queue`, since no single-conversation GET exists) reconciles before the agent acts. (CORRECTED: original draft assumed a `GET /helpdesk/conversations/{id}` and a `409`-driven correction — neither is in the sources.)

## 8. Security & Privacy

- Auth/CSRF are transport concerns handled by core-network (cookie jar + `X-CSRF-Token` interceptor + refresh authenticator). The claim POST is a state-changing request and **must** carry `X-CSRF-Token`; verify it is present (the interceptor adds it automatically — this ticket must not bypass it).
- **Authorization is server-enforced.** The client agent-role gate (AND-161) is UX only; the server returns `403` with a `role_required*` code for non-agents (VERIFIED `client.ts: mapAuthorizationError`) and signals an already-claimed conversation via the assignment state (`assigned_agent_user_id` of the winner; conflict shape UNVERIFIED — OQ-1) — the client must trust those, never assume success.
- Reply bodies and conversation content are user/customer data: do **not** write them to logcat or telemetry payloads (see §10). The outbox holds plaintext bodies in the app's private Room DB only.
- Assignee names are PII-adjacent: log assignee/agent **ids** only, never names, in telemetry.
- The dev backend is plaintext HTTP (known dev-only); release builds use HTTPS with cleartext forbidden for production hosts (owned by network/build tickets; inherited here).
- Claim/reply payloads are sent verbatim as JSON via Moshi (no string interpolation) and rendered via Compose `Text` — no injection/XSS surface introduced.

## 9. Accessibility & i18n

- The Claim button has `contentDescription = stringResource(R.string.cd_helpdesk_claim)`; its loading state is announced (`stateDescription = "Claiming"`), and its disabled state (already claimed/by other) is announced, not color-only.
- The assignee header exposes a `stateDescription` conveying assignment ("Assigned to you" / "Claimed by {name}" / "Unclaimed") so screen readers get the gate state without relying on the disabled composer alone.
- Claim error states are announced via a `liveRegion` (assertive for `ALREADY_CLAIMED`) so the agent hears the conflict outcome.
- Reply composer accessibility (label, disabled announcement, send/retry content descriptions) is inherited from AND-124.
- All strings (claim labels, error messages, assignee templates with `%s` for the agent name) live in `strings.xml`; no hardcoded literals. Templates are localizable and RTL-safe (start/end, `imePadding`). Touch targets >= 48dp for Claim, Retry, and Back.

## 10. Telemetry & Logging

- Events (via the core-data analytics facade; no PII, no message body, ids hashed where noted):
  - `helpdesk_claim_attempt` { helpdeskId (hashed) }
  - `helpdesk_claim_success` { latencyMs }
  - `helpdesk_claim_failed` { errorCode (e.g. `already_claimed`/`closed`/`forbidden`/`network`), httpStatus }
  - `helpdesk_reply_sent` { latencyMs } — emitted by the reused AND-124 path, attributed to a helpdesk context flag.
- Logging: `Timber.d`/`w` for the claim lifecycle with `helpdeskId` and `errorCode` only — **never** assignee names, reply bodies, or raw cookies. Network logging interceptor stays at `BASIC` for release (no bodies) per project policy.

## 11. Testing Strategy

- **Unit — ViewModel (core-testing, `MainDispatcherRule`, Turbine):**
  - Claim success: `claim = Claiming` → on `ApiResult.Success` assignment becomes `ASSIGNED_TO_ME`, `replyEnabled == true`, `claim == Idle`. *(covers "Claim→reply works")*
  - `409 helpdesk_already_claimed`: assignment becomes `ASSIGNED_TO_OTHER`, header shows assignee, `refreshConversation` invoked, `claim == Error(ALREADY_CLAIMED, retryable=false)`, reply stays disabled. *(covers "claim errors surface correctly")*
  - `helpdesk_conversation_closed` → `CLOSED`, reply disabled, non-retryable.
  - `403 forbidden` → `FORBIDDEN`, non-retryable, full-screen permission state.
  - `404` → `NOT_FOUND`, back-to-queue offered.
  - Network/timeout/`5xx` → `NETWORK`, retryable; `onRetryClaim` re-fires.
  - Idempotent re-claim (already assigned to me) resolves to `ASSIGNED_TO_ME` success, no error.
  - `replyEnabled` is false in every state except `ASSIGNED_TO_ME && !isClosed`.
- **`ClaimErrorMapper` unit tests:** each `UiError`/code maps to the correct `ClaimError` and `retryable` flag.
- **Repository tests:** MockWebServer returns `200`, `409`(each code), `403`, `404`, `500`, timeout; assert correct `ApiResult`/`UiError.code`, presence of `X-CSRF-Token` header, and that claim is excluded from GET retry/backoff.
- **DAO / cache tests:** claim success/refresh updates the cached helpdesk conversation and invalidates the queue source (asserted via a Paging invalidation observer).
- **Compose UI tests:** `UNCLAIMED` shows Claim + disabled composer with hint; tapping Claim shows loading; success enables composer; `409` shows "Already claimed by {agent}" and disabled composer; content/state descriptions present.
- **Reply path** relies on the existing AND-124 tests; add one integration test that a reply send is blocked until `ASSIGNED_TO_ME`.
- All async tests deterministic (`runTest`, injected `TestDispatcher`); MockWebServer for network; **no live dev-host calls in CI**.

## 12. Dependencies & Sequencing

- **Depends on AND-161** (Helpdesk queue): provides the queue, `HelpdeskRepository`/`HelpdeskApi` base, `HelpdeskConversation` model + DTO, the agent-role gate, the helpdesk nav graph, and Room cache for helpdesk conversations. Must merge after AND-161.
- **Transitive (reused):** AND-123 (thread message list), AND-124 (composer + outbox + `sendMessage`), AND-120 (messaging foundation), AND-015 (`detail` error decoder), AND-016 (GET-only retry policy — claim is deliberately excluded), AND-018 (`ApiResult`), AND-021 (state composables), and the core-network auth/CSRF/cookie-jar/refresh tickets.
- **Blocks:** none recorded in the source bullets. Later helpdesk features (e.g., reassign, close/resolve, canned replies) build on this claim/assignee model but are not listed as dependents here.

## 13. Risks & Open Questions

- **OQ-1 (PARTIALLY RESOLVED):** `POST /messaging/helpdesk/conversations/{conversation_id}/claim` takes an **empty `{}` body** (resolved: `messaging.ts` + OpenAPI `req=`). **Still open:** what does the backend return for an already-claimed-by-other or closed conversation? OpenAPI documents only `200:HelpdeskClaimOut` and `422:HTTPValidationError`; the web client does no claim-specific mapping. Confirm whether the loser gets `200` (with winner's `assigned_agent_user_id`) or a non-2xx with a `detail.code`, and the exact closed-conversation behavior. **Must be resolved before merge.**
- **OQ-2 (RESOLVED→follow-up needed):** The claim response (`HelpdeskClaimOut`) returns only `assigned_agent_user_id`, **not** an agent display name. To show "Claimed by {name}" the client must resolve the name from the queue `Conversation` participants or a user lookup. There is **no** single-conversation GET; refresh is via `GET /messaging/helpdesk/queue`. Confirm the queue row exposes the assignee's display name.
- **OQ-3 (RESOLVED):** Re-claiming a conversation already assigned to me returns `200` with `idempotent: true` (verified field in `HelpdeskClaimOut`). Code treats this as success → `ASSIGNED_TO_ME`.
- **OQ-4 (RESOLVED):** Reply endpoint is `POST /messaging/conversations/{conversation_id}/messages` (verified), request `SendTextMessageIn` (field `text`), response `MessageOut`. The claim response's `conversation_id` IS the messaging conversation id used for replies, so no separate lookup is needed. AND-161's queue rows (`Conversation`) expose `conversation_id`.
- **OQ-5 (RESOLVED):** Claim success status is `200` (OpenAPI). Still handle via `Response.isSuccessful` defensively.
- **Risk:** assignee/queue cache going stale between queue render and claim, producing surprising `409`s during QA on the unreliable dev host. Mitigation: best-effort `get` on screen entry + the `409`→refresh path; deterministic MockWebServer tests.
- **Risk:** treating `409 already_claimed` as a generic failure (the exact bug this ticket guards against). Mitigation: dedicated mapper + tests asserting the specific `ASSIGNED_TO_OTHER` outcome.

## 14. Acceptance Criteria

AC-1. From the AND-161 queue, an agent can open a conversation, tap **Claim**, see the header transition to "Assigned to you", and then send a reply that appears in the thread. *(source: "Claim→reply works")*

AC-2. The reply composer is enabled **only** when the conversation is assigned to the current agent and not closed; it is disabled with an explanatory hint when `UNCLAIMED` or `ASSIGNED_TO_OTHER`.

AC-3. A concurrent claim that loses (CORRECTED: the loser signal is the winner's `assigned_agent_user_id` in `HelpdeskClaimOut` and/or a non-2xx conflict — exact shape per OQ-1, **not** the originally-assumed `409 helpdesk_already_claimed`) results in the UI showing "Claimed by {agent}", transitioning the header to `ASSIGNED_TO_OTHER`, refreshing the row, and keeping reply disabled — **not** a generic error. *(source: "claim errors surface correctly")* — verified by automated test.

AC-4. Closed (`helpdesk_conversation_closed`), permission-denied (`403 forbidden`), and not-found (`404`) claim attempts each produce their own specific, correct message and the right (non-)retryable affordance.

AC-5. Network/timeout/`5xx` claim failures show a retryable inline error; claim is never auto-retried and is excluded from the GET backoff policy; the screen and any typed reply draft are preserved.

AC-6. A successful claim invalidates the AND-161 queue so the row no longer appears as unclaimed, without a manual refresh.

AC-7. Automated tests cover claim success→reply, each claim error code mapping, the assignee-gated reply enablement, queue invalidation on claim, and the `ClaimErrorMapper`. *(source: "claim errors surface correctly")*

## 15. Definition of Done

- `HelpdeskDetailScreen`, `ClaimHeaderBar`, `HelpdeskDetailViewModel` (`onClaimClick`/`onRetryClaim`/`onDismissClaimError`), `ClaimState`/`ClaimError`/`ClaimErrorMapper`, and `HelpdeskRepository.claim`/`refreshConversation`/`observeConversation` implemented in `:feature:messaging` under `com.testlogon.android.feature.messaging.helpdesk`, with `HelpdeskApi.claim`/`get` and DTOs in `:core:network`/`:core:model`.
- Reply uses the reused AND-124 `MessageComposer`/outbox against the conversation `id`, gated by `replyEnabled`; no duplicate composer/outbox logic introduced.
- Claim success, the concurrent-claim `409` path, and all other claim error codes functional against MockWebServer and manually verified against the dev host.
- All §11 unit, mapper, repository, DAO/cache, and Compose UI tests pass in CI; no live-host calls in CI.
- No reply bodies or assignee names in logs/telemetry; `X-CSRF-Token` present on the claim POST; claim excluded from GET retry/backoff; Detekt/ktlint clean; KSP builds.
- Strings externalized (incl. assignee templates); accessibility content/state descriptions and live-region announcements present; touch targets >= 48dp.
- All ACs in §14 demonstrably met; OQ-1 (claim body + error-code strings) and OQ-4 (underlying `conversation_id`) confirmed and reflected in code before merge.
- PR targets the `android-port` branch and references AND-162 and AND-161.

## 16. Citations & Assumption Audit

Each key technical claim with its VERDICT and exact SOURCE pointer.

1. **Claim endpoint is `POST /messaging/helpdesk/conversations/{conversation_id}/claim`** (path param `conversation_id`). VERDICT: **Corrected** (draft said `POST /helpdesk/conversations/{id}/claim`). SOURCE: OpenAPI `POST /messaging/helpdesk/conversations/{conversation_id}/claim` (op `claim_helpdesk_conversation_*`, params `conversation_id,authorization,X-SESSION-ID`); `src/api/endpoints/messaging.ts: claimHelpdeskConversation`.
2. **Claim request body is empty `{}`** (no request schema). VERDICT: **Verified**. SOURCE: OpenAPI claim entry `req=` (empty); `src/api/endpoints/messaging.ts: claimHelpdeskConversation` posts `{}`.
3. **Claim success returns `200 HelpdeskClaimOut` = `{ ok, conversation_id, state, assigned_agent_user_id, assignment_version, idempotent }`.** VERDICT: **Corrected** (draft invented `HelpdeskConversationDto` with `id/subject/assignment/assignee{agent_id,agent_name}/is_closed`). SOURCE: OpenAPI `components.schemas.HelpdeskClaimOut` (required: `ok, conversation_id, state, assigned_agent_user_id, assignment_version`; `idempotent` default false); `src/api/types.ts: HelpdeskClaimOut`.
4. **No nested assignee object and no agent display name in the claim response.** VERDICT: **Corrected**. SOURCE: `components.schemas.HelpdeskClaimOut` (only `assigned_agent_user_id: string`).
5. **No single-conversation GET (`GET /helpdesk/conversations/{id}`) exists; the only helpdesk reads are claim POST and `GET /messaging/helpdesk/queue`.** VERDICT: **Corrected** (draft defined `HelpdeskApi.get(id)` / `refreshConversation` via single GET). SOURCE: OpenAPI index — only two helpdesk lines: `POST .../claim` and `GET /messaging/helpdesk/queue` (params `group_id,state,limit,authorization,X-SESSION-ID`).
6. **Backend assignment is a `state` string with values `awaiting_agent` / `assigned` / `paused_no_agents_online` / `closed`.** VERDICT: **Corrected** (draft used an `assignment` enum `"unclaimed"|"assigned"` and a client-only `UNCLAIMED/ASSIGNED_TO_ME/ASSIGNED_TO_OTHER` mapping with no source basis). The client enum is an acceptable derivation but must map from these real strings. SOURCE: `src/pages/messages/ConversationView.tsx: HelpdeskRoutingBanner` (states `awaiting_agent`, `assigned`, `paused_no_agents_online`, `closed`); `src/pages/helpdesk/HelpdeskPage.tsx: routingStateBadge`.
7. **`ASSIGNED_TO_ME` vs `ASSIGNED_TO_OTHER` is decided by `assigned_agent_user_id == currentUserId` (auth store), not a per-claim field.** VERDICT: **Verified**. SOURCE: `ConversationView.tsx: HelpdeskRoutingBanner` (`state === "assigned" && assignedAgent === currentUserId`); `useAuthStore((s) => s.userId)`.
8. **Idempotent re-claim returns `200` with `idempotent: true`.** VERDICT: **Verified** (resolves OQ-3). SOURCE: `components.schemas.HelpdeskClaimOut.idempotent`.
9. **Reply endpoint is `POST /messaging/conversations/{conversation_id}/messages`, req `SendTextMessageIn` (field `text`, maxLength 4000), resp `MessageOut`.** VERDICT: **Corrected** (draft said `POST /conversations/{id}/messages` with `SendMessageRequest{body, client_id}` → `MessageDto`). SOURCE: OpenAPI `POST /messaging/conversations/{conversation_id}/messages` (op `send_text_message_*`); `components.schemas.SendTextMessageIn`; `src/api/endpoints/messaging.ts: sendTextMessage`; `src/api/types.ts: SendTextMessageReq` (`text?: string`).
10. **`SendTextMessageIn` has no `client_id`/`idempotency_key` field.** VERDICT: **Corrected**. SOURCE: `components.schemas.SendTextMessageIn` (fields: `text, body, encryption, reply_to_message_id, parent_message_id, thread_id, ...` — no client id).
11. **Auth is cookie-based; `ui_csrf` cookie is echoed as `X-CSRF-Token` on requests; `credentials: include`.** VERDICT: **Verified**. SOURCE: `src/api/client.ts` (`const csrf = getCookie("ui_csrf"); headers.set("X-CSRF-Token", csrf)`, `credentials: "include"`).
12. **On `401`, the client calls `POST /ui/session/refresh` once then retries; failure logs out.** VERDICT: **Verified**. SOURCE: `src/api/client.ts: refreshSession` (`fetch(withApiBase("/ui/session/refresh"), { method: "POST", credentials: "include" })`).
13. **FastAPI `detail` is `string | [{msg,...}] | {code,...}` and the `{code,...}` form carries helpdesk/role codes.** VERDICT: **Verified**. SOURCE: `src/api/client.ts: normalizeErrorDetail` + `mapAuthorizationError`.
14. **Real helpdesk/role error codes are `helpdesk_claim_required`, `helpdesk_assignee_required`, `helpdesk_claim_not_available`, `role_required`, `role_required_scope`, `role_required_admin_profile_type`.** VERDICT: **Corrected** (draft invented `helpdesk_already_claimed`, `helpdesk_conversation_closed`, `forbidden`). SOURCE: `src/api/client.ts: mapAuthorizationError`.
15. **The web client does NOT do claim-specific error mapping — failed claim shows a generic `toast.error("Failed to claim conversation")`.** VERDICT: **Verified** (this means the distinct claim-error UI is an Android-side enhancement, not a web mirror). SOURCE: `src/pages/messages/ConversationView.tsx: claimMutation.onError`.
16. **Claim shown only when `state === "awaiting_agent"`.** VERDICT: **Verified**. SOURCE: `ConversationView.tsx: HelpdeskRoutingBanner` (`showClaim = true` only in the `awaiting_agent` branch).
17. **Successful claim invalidates the conversations + helpdesk-queue caches in the web client.** VERDICT: **Verified** (supports AC-6 / queue invalidation). SOURCE: `ConversationView.tsx: claimMutation.onSuccess` (`invalidateQueries(["conversations"])`, `invalidateQueries(["helpdesk-queue"])`).
18. **Claim success status is `200` (not `201`).** VERDICT: **Corrected→Verified** (draft hedged `200`/`201`). SOURCE: OpenAPI claim `resp=200:HelpdeskClaimOut`.
19. **Concurrent-claim "loser" gets a distinct `409 helpdesk_already_claimed` with assignee payload.** VERDICT: **Unverified-assumption** (the OpenAPI claim entry documents only `200`/`422`; loser shape unknown). SOURCE: none — see Open assumptions.
20. **Kotlin/Android framework choices (Compose, Hilt, Paging 3, Retrofit/OkHttp/Moshi, `stateIn`/`WhileSubscribed`).** VERDICT: **Unverified-assumption** (framework choices, not backend contract; consistent with the project stack in §2). SOURCE: framework ref — Android Jetpack docs (developer.android.com/jetpack/compose, /topic/libraries/architecture/paging/v3-overview).

### Corrections made
- Endpoint path `/helpdesk/...` → `/messaging/helpdesk/conversations/{conversation_id}/claim`; path param `id` → `conversation_id` (#1).
- Claim response DTO completely replaced: `HelpdeskConversationDto` → `HelpdeskClaimOut` (`ok/conversation_id/state/assigned_agent_user_id/assignment_version/idempotent`); removed invented `id/subject/assignee{}/is_closed` (#3, #4).
- Removed the non-existent `GET /helpdesk/conversations/{id}` and `HelpdeskApi.get`; `refreshConversation` now uses `GET /messaging/helpdesk/queue` (#5).
- Backend assignment modeled as a `state` string (`awaiting_agent/assigned/paused_no_agents_online/closed`), not an `assignment` enum (#6).
- Reply endpoint path/DTO corrected to `POST /messaging/conversations/{conversation_id}/messages`, `SendTextMessageIn` (`text`) → `MessageOut`; dropped `client_id` (#9, #10).
- Claim error codes replaced with the real `mapAuthorizationError` codes; added `ClaimError.NOT_AVAILABLE` for `helpdesk_claim_not_available`; rewrote `ClaimErrorMapper` defensively (#14).
- Web reference file path corrected to `src/api/endpoints/messaging.ts` (no `helpdesk.ts` exists) (#1, #15).
- AC-3 / FR-7 / §7 / §8 reworded to drop the unverified `409 helpdesk_already_claimed` as contract.
- OQ-2/OQ-3/OQ-4/OQ-5 marked resolved; OQ-1 narrowed to the still-open loser/closed shape.
- Status set to `reviewed`, `reviewed_on: 2026-06-06`.

### Open assumptions
- **A1 (loser/conflict shape).** Whether a concurrent-claim loser receives `200` with the winner's `assigned_agent_user_id`, or a non-2xx with a code, is unknowable from the sources (OpenAPI documents only `200`/`422`; web does generic handling). Implement both paths; resolve via OQ-1 before merge.
- **A2 (closed-claim behavior).** What the backend returns when claiming a `closed` conversation (a `422`? a `200` with `state: "closed"`? a distinct code?) is undocumented. The `closed` state itself is verified; the claim-against-closed response is not.
- **A3 (`404` on claim).** Not-found for the claim endpoint is not documented (only `200`/`422`); treat as defensive.
- **A4 (assignee display name).** The claim response carries only `assigned_agent_user_id`; "Claimed by {name}" requires resolving the name from queue/participant data — confirm the queue row exposes it (OQ-2).
- **A5 (Android framework specifics).** All Kotlin/Jetpack class shapes are design proposals, not verifiable against backend/web sources.

## 17. Test Plan

Acceptance criteria referenced are §14 AC-1..AC-7. "Physical device" = Samsung Galaxy A15 5G (SM-A156U, API 34, arm64); "emulator" = AVD `test35` (API 35, x86_64); "JVM" = local Robolectric/unit. Network cases use MockWebServer (no live dev host in CI).

- **TC-AND-162-01 — Claim success → reply enabled (happy path).** Type: unit (ViewModel, Turbine). Target: JVM. Preconditions: `HelpdeskDetailViewModel` with `assignment=UNCLAIMED`, repo stub returns `ApiResult.Success(HelpdeskClaimOut(ok=true, state="assigned", assigned_agent_user_id=currentUserId, assignment_version=3, idempotent=false))`. Steps: call `onClaimClick()`; collect `uiState`. Expected: emits `claim=Claiming` then `assignment=ASSIGNED_TO_ME`, `replyEnabled=true`, `claim=Idle`. Traces: AC-1, AC-7.
- **TC-AND-162-02 — Reply send blocked until ASSIGNED_TO_ME.** Type: integration (ViewModel + reused AND-124 send). Target: JVM. Preconditions: `assignment=UNCLAIMED`. Steps: attempt `onSendReply()`; then claim (success); attempt `onSendReply()` again. Expected: first send is a no-op / composer disabled (`replyEnabled=false`); after claim, send invokes `POST /messaging/conversations/{conversation_id}/messages` with `SendTextMessageIn{text=...}`. Traces: AC-1, AC-2.
- **TC-AND-162-03 — `replyEnabled` derivation matrix.** Type: unit. Target: JVM. Preconditions: none. Steps: assert `replyEnabled == (assignment==ASSIGNED_TO_ME && !isClosed)` across `{UNCLAIMED, ASSIGNED_TO_ME, ASSIGNED_TO_OTHER} × {closed, open}`. Expected: true only for `ASSIGNED_TO_ME && open`. Traces: AC-2.
- **TC-AND-162-04 — Idempotent re-claim treated as success.** Type: contract (MockWebServer). Target: JVM. Preconditions: server returns `200 {ok:true, state:"assigned", assigned_agent_user_id:currentUserId, idempotent:true}`. Steps: claim. Expected: `assignment=ASSIGNED_TO_ME`, no error state, `claim=Idle`. Traces: AC-1, AC-7.
- **TC-AND-162-05 — Concurrent-claim loser (200 with other agent).** Type: contract (MockWebServer). Target: JVM. Preconditions: server returns `200 {ok:true, state:"assigned", assigned_agent_user_id:"other_usr", assignment_version:4}`. Steps: claim while local cache says UNCLAIMED. Expected: `assignment=ASSIGNED_TO_OTHER`, header "Claimed by {agent}", `replyEnabled=false`, queue refresh invoked, NOT a generic error. Traces: AC-3, AC-6, AC-7. (Primary loser path per OQ-1/A1.)
- **TC-AND-162-06 — Concurrent-claim loser (non-2xx conflict, defensive).** Type: contract (MockWebServer). Target: JVM. Preconditions: server returns a `409`/`403` with `detail.code` conflict (defensive — shape per OQ-1). Steps: claim. Expected: mapped to `ALREADY_CLAIMED` → `ASSIGNED_TO_OTHER`, `refreshConversation` (queue) invoked, non-retryable, screen + draft preserved. Traces: AC-3, AC-5, AC-7.
- **TC-AND-162-07 — Permission denied (`403 role_required*`).** Type: contract (MockWebServer). Target: JVM. Preconditions: server returns `403 {detail:{code:"role_required"}}`. Steps: claim. Expected: `ClaimError.FORBIDDEN`, non-retryable, full-screen permission state with back-to-queue; reply stays disabled. Traces: AC-4, AC-7.
- **TC-AND-162-08 — Not-available (`helpdesk_claim_not_available`).** Type: contract (MockWebServer). Target: JVM. Preconditions: server returns `{detail:{code:"helpdesk_claim_not_available"}}`. Steps: claim. Expected: `ClaimError.NOT_AVAILABLE`, message "You need to be online and available to claim", non-retryable. Traces: AC-4, AC-7.
- **TC-AND-162-09 — Network/timeout/5xx is retryable; never auto-retried.** Type: contract (MockWebServer). Target: JVM. Preconditions: server returns `500`, then a delayed/socket-closed response to simulate timeout. Steps: claim (assert no automatic re-fire), then `onRetryClaim()`. Expected: `ClaimError.NETWORK` retryable inline; claim issued exactly once per user action (excluded from AND-016 GET backoff); typed reply draft preserved across the failure. Traces: AC-5, AC-7.
- **TC-AND-162-10 — `ClaimErrorMapper` mapping table.** Type: unit. Target: JVM. Preconditions: none. Steps: feed each `UiError`/code into `ClaimErrorMapper.map` and check `ClaimError` + `retryable`. Expected: Forbidden+`role_required*`→FORBIDDEN(non-retryable); Forbidden+`helpdesk_claim_not_available`→NOT_AVAILABLE; Conflict→ALREADY_CLAIMED; Validation(422)→UNKNOWN; NotFound→NOT_FOUND; Network/Timeout/Server→NETWORK(retryable). Traces: AC-4, AC-5, AC-7.
- **TC-AND-162-11 — CSRF header present on claim POST.** Type: contract (MockWebServer). Target: JVM. Preconditions: `ui_csrf` cookie set in cookie jar. Steps: claim; inspect recorded request. Expected: request carries `X-CSRF-Token` equal to the `ui_csrf` cookie; session cookies present. Traces: AC-3 (security), AC-7.
- **TC-AND-162-12 — Claim success invalidates the AND-161 queue (cache).** Type: integration (Room + Paging invalidation observer). Target: JVM (Robolectric). Preconditions: queue Paging source active with the row UNCLAIMED. Steps: claim success writes back. Expected: queue Paging source invalidated and the row reflects `assigned` (no manual refresh). Traces: AC-6, AC-7.
- **TC-AND-162-13 — Compose UI: claim → loading → enabled composer; conflict shows "Claimed by {agent}".** Type: Compose-UI. Target: emulator `test35`. Preconditions: detail screen with UNCLAIMED state and the fake VM. Steps: assert Claim button + disabled composer with hint; tap Claim → loading; drive success → composer enabled; drive `ASSIGNED_TO_OTHER` → "Claimed by {agent}" + disabled composer. Expected: each state renders correctly; no generic error on conflict. Traces: AC-1, AC-2, AC-3.
- **TC-AND-162-14 — Accessibility: content/state descriptions + live region.** Type: Compose-UI (semantics). Target: emulator `test35`. Preconditions: detail screen. Steps: assert Claim button `contentDescription`, `stateDescription="Claiming"` while in flight; header `stateDescription` for each assignment; `ALREADY_CLAIMED` announced via assertive `liveRegion`; touch targets ≥48dp for Claim/Retry/Back. Expected: all semantics present. Traces: AC-3 (a11y), AC-4.
- **TC-AND-162-15 — Real-host claim→reply on physical device (manual/e2e).** Type: manual / instrumented e2e. Target: **PHYSICAL DEVICE (SM-A156U, API 34, arm64)** — MUST run here to validate arm64 ABI + API-34 behavior against the flaky plaintext dev host, real cookie-jar/CSRF transport, and FCM/notification behavior the emulator cannot fully reproduce. Preconditions: agent account; dev host reachable; a conversation in `awaiting_agent`. Steps: open from queue, Claim, observe header "Assigned to you", send a reply, confirm it appears in the thread; then kill network mid-claim to observe the retryable NETWORK path; relaunch to confirm state re-derives from a fresh queue fetch (no stale "claiming"). Expected: claim→reply works end-to-end; offline/flaky-host path is retryable and non-destructive. Traces: AC-1, AC-5.

### Coverage matrix
| AC | Covered by |
|----|-----------|
| AC-1 (claim→reply works) | TC-01, TC-02, TC-04, TC-13, TC-15 |
| AC-2 (reply gated by assignment) | TC-02, TC-03, TC-13 |
| AC-3 (concurrent loser → ASSIGNED_TO_OTHER, not generic) | TC-05, TC-06, TC-11, TC-13, TC-14 |
| AC-4 (closed/forbidden/not-found/not-available specific msgs) | TC-07, TC-08, TC-10, TC-14 |
| AC-5 (network retryable, never auto-retried, draft preserved) | TC-06, TC-09, TC-10, TC-15 |
| AC-6 (claim invalidates queue) | TC-05, TC-12 |
| AC-7 (automated coverage of success/errors/mapper/gate/invalidation) | TC-01, TC-04, TC-05, TC-06, TC-07, TC-08, TC-09, TC-10, TC-11, TC-12 |
