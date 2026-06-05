---
id: AND-162
title: Helpdesk claim + reply
milestone: M3
epic: E22
priority: P2
size: M
status: draft
depends_on: [AND-161]
blocks: []
---

# AND-162 — Helpdesk claim + reply

## 1. Overview & Goal

AND-161 delivered the agent-facing **helpdesk queue** — a paged, read-only list of unclaimed (and assigned) helpdesk conversations rendered for users in the agent role. AND-162 adds the two write actions that turn that queue into a usable workflow: an agent can **claim** a conversation (`POST /helpdesk/conversations/{id}/claim`), and once claimed can **reply** into the underlying conversation thread.

The defining requirement of this ticket is correct handling of the **claim/assignee error surface**: a helpdesk conversation can be claimed concurrently by multiple agents, can already be assigned to someone else, can be closed, or can require a permission the current agent lacks. These conditions return distinct backend error codes and must each produce a distinct, correct, non-destructive UI outcome — never a generic "something went wrong" that loses the agent's place in the queue or their typed reply.

Goal, restated as a testable outcome: from the AND-161 queue, an agent taps a conversation, claims it (button transitions claim → assigned-to-me → reply enabled), and sends a reply that appears in the thread. If the claim fails because another agent already claimed it (`409`/assignee conflict), the UI surfaces a specific "already claimed by {agent}" state and refreshes the row rather than silently failing. The claim action, assignee state model, claim-error mapping, and the reply-enablement gate are the deliverables. The generic optimistic text-send mechanics are **reused** from AND-124's composer/outbox, not re-implemented; this ticket adds the claim gate and helpdesk-specific reply wiring on top.

## 2. Context & References

- **Module:** `feature-messaging` (Gradle module `:feature:messaging`), package `com.testlogon.android.feature.messaging.helpdesk`. The claim action and assignee state extend the helpdesk queue feature introduced by AND-161; the reply path reuses the thread/composer from AND-123/AND-124.
- **Layering:** `feature-messaging` -> `core-network` (Retrofit service, `ApiResult<T>`, CSRF/cookie/refresh interceptors), `core-model` (DTO/domain + adapters), `core-data` (Room cache + repository), `core-ui` (Compose components, state composables, theme). No backward dependencies.
- **Backend:** FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000` (plaintext HTTP, unreliable). OpenAPI at `/openapi.json`. Cookie-based auth: session cookies + `ui_csrf` cookie echoed as `X-CSRF-Token`; on `401` the OkHttp authenticator calls `POST /ui/session/refresh` once and retries. Persistent cookie jar required (established by core-network/auth tickets).
- **Web reference:** `frontend/src/api/endpoints/helpdesk.ts` (the `claimConversation` / queue calls) and `frontend/src/api/types.ts` (`HelpdeskConversation`, `Assignee`, claim error code constants). The Android DTOs and error-code constants here must mirror those shapes and string values exactly.
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

FR-7. Claim **errors must surface specifically** (covers Acceptance "claim errors surface correctly"):
- Already claimed / assignee conflict (`409`, code `helpdesk_already_claimed`): show "Already claimed by {agent}", transition header to `ASSIGNED_TO_OTHER`, refresh the row; do **not** treat as a generic failure.
- Already assigned to me (idempotent re-claim): treat as success → `ASSIGNED_TO_ME`.
- Conversation closed (`409`/`422`, code `helpdesk_conversation_closed`): show "This conversation is closed", keep reply disabled.
- Permission denied / not an agent (`403`, code `forbidden`): show "You don't have permission to claim", non-retryable.
- Not found (`404`): show "Conversation no longer available", offer back-to-queue.
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

enum class ClaimError { ALREADY_CLAIMED, CLOSED, FORBIDDEN, NOT_FOUND, NETWORK, UNKNOWN }

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

`claim` calls the service via the shared `apiCall { }` helper (converts exceptions/non-2xx into `ApiResult.Error`, decodes the FastAPI `detail` shape), then maps `HelpdeskConversationDto.toDomain()`. The claim is a **non-idempotent POST** at the HTTP layer; it must therefore be excluded from the AND-016 GET-only retry/backoff (claims are never auto-retried — see §7).

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

**Claim endpoint:** `POST /helpdesk/conversations/{id}/claim` (path param `id` = helpdesk conversation id).

**Request headers:** session cookies (auto via cookie jar) + `X-CSRF-Token: <ui_csrf>` (auto via CSRF interceptor). `Content-Type: application/json`. Body is empty (`{}`) unless `/openapi.json` specifies otherwise (see OQ-1).

**Success `200`/`201` response** (updated helpdesk conversation, now assigned to the caller):
```json
{
  "id": "hd_01H...",
  "conversation_id": "conv_01H...",
  "subject": "Login issue",
  "assignment": "assigned",
  "assignee": { "agent_id": "usr_01H...", "agent_name": "Sam Agent" },
  "is_closed": false
}
```

**Claim DTO:**
```kotlin
@JsonClass(generateAdapter = true)
data class HelpdeskConversationDto(
    @Json(name = "id") val id: String,
    @Json(name = "conversation_id") val conversationId: String,
    @Json(name = "subject") val subject: String?,
    @Json(name = "assignment") val assignment: String,        // "unclaimed"|"assigned"
    @Json(name = "assignee") val assignee: AssigneeDto?,
    @Json(name = "is_closed") val isClosed: Boolean = false,
)

@JsonClass(generateAdapter = true)
data class AssigneeDto(
    @Json(name = "agent_id") val agentId: String,
    @Json(name = "agent_name") val agentName: String,
)

interface HelpdeskApi {                                       // extends AND-161 service
    @POST("helpdesk/conversations/{id}/claim")
    suspend fun claim(@Path("id") id: String): Response<HelpdeskConversationDto>

    @GET("helpdesk/conversations/{id}")
    suspend fun get(@Path("id") id: String): Response<HelpdeskConversationDto>
}
```

`assignment.toDomain()` maps `"assigned"` to `ASSIGNED_TO_ME` when `assignee.agentId == currentUserId` (from `GET /ui/me`), else `ASSIGNED_TO_OTHER`; `"unclaimed"` → `UNCLAIMED`.

**Reply endpoint:** `POST /conversations/{conversation_id}/messages` — the exact AND-124 contract (`SendMessageRequest{body, client_id}` → `MessageDto`). No new reply DTO is defined here.

**Claim error responses** (FastAPI `detail`, mapped by the shared decoder into `UiError`, then by `ClaimErrorMapper` into `ClaimError`):
- `409` `detail.code = "helpdesk_already_claimed"` (payload may include the current `assignee`) → `ALREADY_CLAIMED`; transition to `ASSIGNED_TO_OTHER`, refresh.
- `409`/`422` `detail.code = "helpdesk_conversation_closed"` → `CLOSED`.
- `403` `detail.code = "forbidden"` (or detail string) → `FORBIDDEN`, non-retryable.
- `404` → `NOT_FOUND`.
- `401` → authenticator runs `POST /ui/session/refresh` once and retries; second `401` → `UiError.Unauthorized` (re-auth).
- `5xx` / timeout / `IOException` → `NETWORK`, retryable.

```kotlin
object ClaimErrorMapper {
    fun map(e: UiError): ClaimError = when (e) {
        is UiError.Conflict -> when (e.code) {
            "helpdesk_already_claimed" -> ClaimError.ALREADY_CLAIMED
            "helpdesk_conversation_closed" -> ClaimError.CLOSED
            else -> ClaimError.UNKNOWN
        }
        is UiError.Forbidden -> ClaimError.FORBIDDEN
        is UiError.NotFound -> ClaimError.NOT_FOUND
        is UiError.Network, is UiError.Timeout, is UiError.Server -> ClaimError.NETWORK
        else -> ClaimError.UNKNOWN
    }
}
```

`detail` may be `string | [{msg,...}] | {code,...}`; reuse the existing `DetailErrorAdapter` from AND-015. The `{code,...}` form carries the helpdesk codes above; the error-code string constants must match `frontend/src/api/types.ts`.

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
- **Concurrent claim (the headline race):** two agents claim simultaneously; the loser receives `409 helpdesk_already_claimed`. The loser's UI must (a) not show a generic error, (b) display "Already claimed by {agent}", (c) update the header to `ASSIGNED_TO_OTHER`, and (d) refresh so the queue row is consistent. This is covered by an explicit test (§11).
- **Timeouts:** OkHttp call timeout ~20s (dev-host policy). A claim exceeding it becomes a `NETWORK` retryable error; the button returns to Idle, claim not applied. The UI never hangs.
- **Closed conversation:** `CLOSED` disables reply and shows a banner; claim is not retryable.
- **Refresh-on-401:** handled centrally by the authenticator; the claim coroutine sees only the post-refresh outcome. A double-401 surfaces re-auth, not a claim error.
- **Reply errors** are handled by the reused AND-124 outbox (FAILED + manual retry, body preserved); this ticket adds no new reply error handling.
- **Stale assignee in cache:** if the cached state says `UNCLAIMED` but the server says assigned, the `409` on claim corrects it; on screen entry a best-effort `get` reconciles before the agent acts.

## 8. Security & Privacy

- Auth/CSRF are transport concerns handled by core-network (cookie jar + `X-CSRF-Token` interceptor + refresh authenticator). The claim POST is a state-changing request and **must** carry `X-CSRF-Token`; verify it is present (the interceptor adds it automatically — this ticket must not bypass it).
- **Authorization is server-enforced.** The client agent-role gate (AND-161) is UX only; the server returns `403 forbidden` for non-agents and `409 helpdesk_already_claimed` for losers — the client must trust those, never assume success.
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

- **OQ-1:** Does `POST /helpdesk/conversations/{id}/claim` require a request body, and what exact `detail.code` strings does the backend emit for already-claimed vs. closed? Verify against `/openapi.json` and `frontend/src/api/endpoints/helpdesk.ts`; the `ClaimError` mapping and string constants must match. **Must be resolved before merge.**
- **OQ-2:** Does the `409 already_claimed` response include the winning `assignee` payload, or must the client follow up with `GET /helpdesk/conversations/{id}` to learn who claimed it? Design assumes a follow-up `refreshConversation` either way; confirm to avoid a redundant round-trip.
- **OQ-3:** Is re-claiming a conversation already assigned to me a `200` (idempotent) or an error? Code treats "assigned to me" as success regardless; confirm.
- **OQ-4:** Is the reply endpoint the standard `POST /conversations/{conversation_id}/messages`, or a helpdesk-scoped variant? AND-161's queue DTO must expose the underlying `conversation_id`; confirm it is present.
- **OQ-5:** Success status code for claim — `200` vs `201`? Handle both via `Response.isSuccessful`.
- **Risk:** assignee/queue cache going stale between queue render and claim, producing surprising `409`s during QA on the unreliable dev host. Mitigation: best-effort `get` on screen entry + the `409`→refresh path; deterministic MockWebServer tests.
- **Risk:** treating `409 already_claimed` as a generic failure (the exact bug this ticket guards against). Mitigation: dedicated mapper + tests asserting the specific `ASSIGNED_TO_OTHER` outcome.

## 14. Acceptance Criteria

AC-1. From the AND-161 queue, an agent can open a conversation, tap **Claim**, see the header transition to "Assigned to you", and then send a reply that appears in the thread. *(source: "Claim→reply works")*

AC-2. The reply composer is enabled **only** when the conversation is assigned to the current agent and not closed; it is disabled with an explanatory hint when `UNCLAIMED` or `ASSIGNED_TO_OTHER`.

AC-3. A concurrent claim that loses returns `409 helpdesk_already_claimed` and the UI shows "Already claimed by {agent}", transitions the header to `ASSIGNED_TO_OTHER`, refreshes the row, and keeps reply disabled — **not** a generic error. *(source: "claim errors surface correctly")* — verified by automated test.

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
