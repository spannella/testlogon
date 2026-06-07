---
id: AND-380
title: Helpdesk ViewModel
milestone: M8
epic: E49
priority: P2
size: M
depends_on: [AND-377]
blocks: [AND-381]
status: reviewed
reviewed_on: 2026-06-06
---

# AND-380 — Helpdesk ViewModel

## 1. Overview & Goal

This ticket delivers the state-holding layer for the helpdesk **agent** experience: a
`HelpdeskViewModel` (plus its `HelpdeskUiState` model and intent surface) that drives the
agent dashboard shipped in AND-377 (queue + metrics). The ViewModel owns all screen state,
orchestrates the repository calls, maps `ApiResult<T>` into a single immutable
`StateFlow<HelpdeskUiState>`, and exposes a small set of intents (refresh, filter, claim,
select conversation, send reply, dismiss error) for the Compose UI to call.

The scope of AND-380 is explicitly **State** with an acceptance bar of **Unit-tested**. No
new Composables, navigation, or DI graph wiring beyond the ViewModel itself are in scope;
the dashboard screen and its UI tests are owned by AND-377 and AND-381 respectively. The
goal is a deterministic, side-effect-free-to-test state machine: given a sequence of
intents and faked repository results, the emitted `HelpdeskUiState` sequence is fully
predictable and exercised by `core-testing` JUnit tests on a `TestDispatcher`.

The ViewModel must correctly express the agent role's three concurrent concerns — the
claimable queue, the at-a-glance metrics, and the currently-claimed conversation with its
reply composer — while remaining resilient to the unreliable dev backend (timeouts, 401
refresh, claim-conflict races) per project conventions.

## 2. Context & References

- **Module:** `feature-helpdesk` (`com.testlogon.android.feature.helpdesk`). The ViewModel
  lives at `feature-helpdesk/src/main/java/com/testlogon/android/feature/helpdesk/HelpdeskViewModel.kt`.
- **Layering:** `feature-helpdesk` → `core-data` (`HelpdeskRepository`), `core-model`
  (`Conversation`, `HelpdeskMetrics`, role types), `core-network` (`ApiResult`), `core-ui`
  (`UiText`), `core-testing` (test rules/fakes). The ViewModel never touches Retrofit
  directly.
- **Upstream dependency AND-377 — Helpdesk agent dashboard** (queue, metrics) consumes this
  ViewModel. AND-377 in turn depends on **AND-161 — Helpdesk queue** (`/messaging/helpdesk/queue`)
  and the claim/reply behavior defined in **AND-162** (`/messaging/helpdesk/conversations/{conversation_id}/claim`
  — corrected; the bare `/helpdesk/...` path in earlier drafts does not exist in the backend).
  This ticket reuses the `HelpdeskRepository` and DTOs established by AND-161/AND-162 and
  the messaging DTOs from **AND-120**.
- **Downstream dependency AND-381 — Helpdesk tests** (repo + UI tests) builds on the unit
  tests delivered here; AND-381 owns instrumented Compose UI tests against the AND-377 screen.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext, slow).
  OpenAPI at `/openapi.json`. Web reference: `frontend/src/api/endpoints/*.ts`, shared types
  `frontend/src/api/types.ts`.
- **Conventions:** ViewModels expose `StateFlow<UiState>`; session auth with a one-shot
  `POST /ui/session/refresh` on 401 then a single retry (verified in `src/api/client.ts`).
  Transport sends `credentials: include` (session cookies), an `X-CSRF-Token` header echoed
  from the `ui_csrf` cookie, and an `Authorization: Bearer <accessToken>` header when an access
  token is present — i.e. it is **not** cookie-only (correction to an earlier draft claim).
  FastAPI `detail` mapping (`string | [{msg}] | {code,...}`).

## 3. Functional Requirements

FR-1. On creation the ViewModel loads the helpdesk queue for the current agent's group,
surfacing a loading state until it resolves. At-a-glance metrics (unclaimed / mine / total)
are **derived from the loaded queue**, not fetched separately — there is no metrics endpoint
(corrected; see §5/§13/§16).

FR-2. The ViewModel exposes a `refresh()` intent that re-fetches the queue (and thereby
recomputes derived metrics); a
pull-to-refresh on the dashboard maps to this. Refresh must not clear already-loaded data
(stale-while-revalidate): it sets `isRefreshing = true` and keeps the prior `queue` (and thus
the prior derived metrics).

FR-3. A `setFilter(filter: QueueFilter)` intent filters the queue client-side by status
(`ALL`, `UNCLAIMED`, `MINE`). Filtering is derived state and must not trigger a network call.

FR-4. A `claim(conversationId: String)` intent claims an unclaimed conversation. While the
request is in flight the affected row is marked `claiming`. On success the conversation moves
to the agent's ownership and becomes the `selectedConversation`. On a claim conflict (already
claimed by another agent) the queue item is refreshed and a non-fatal banner is surfaced.

FR-5. A `selectConversation(conversationId: String?)` intent sets/clears the detail pane
target. Passing `null` returns to the queue-only view.

FR-6. A `sendReply(conversationId: String, body: String)` intent posts a reply to a claimed
conversation. Empty/blank bodies are rejected locally (no network call). While sending,
`isSending = true`; on success the composer clears and the conversation thread is reloaded.

FR-7. A `dismissError()` intent clears any transient banner/error without affecting data.

FR-8. All long-running intents are cancellation-safe and re-entrancy-safe: a second
`refresh()` while one is in flight cancels/joins rather than racing two emissions.

FR-9. State emissions are distinct (no duplicate equal emissions) and always reflect a
single source of truth — the UI never derives network state independently.

## 4. Technical Design

`HelpdeskViewModel` is a Hilt `@HiltViewModel` with constructor-injected
`HelpdeskRepository` and a `@Dispatcher(IO)` `CoroutineDispatcher` (injected, never
hard-coded, so tests substitute a `TestDispatcher`).

```kotlin
@HiltViewModel
class HelpdeskViewModel @Inject constructor(
    private val repository: HelpdeskRepository,
    @IoDispatcher private val io: CoroutineDispatcher,
) : ViewModel() {

    private val _state = MutableStateFlow(HelpdeskUiState())
    val state: StateFlow<HelpdeskUiState> = _state.asStateFlow()

    private var loadJob: Job? = null

    init { refresh() }

    fun onIntent(intent: HelpdeskIntent) = when (intent) {
        HelpdeskIntent.Refresh            -> refresh()
        is HelpdeskIntent.SetFilter       -> setFilter(intent.filter)
        is HelpdeskIntent.Claim           -> claim(intent.conversationId)
        is HelpdeskIntent.Select          -> selectConversation(intent.conversationId)
        is HelpdeskIntent.SendReply       -> sendReply(intent.conversationId, intent.body)
        HelpdeskIntent.DismissError       -> dismissError()
    }

    fun refresh() { /* cancel loadJob, set isRefreshing, await both fetches */ }
    fun setFilter(filter: QueueFilter) { _state.update { it.copy(filter = filter) } }
    fun claim(conversationId: String) { /* … */ }
    fun selectConversation(conversationId: String?) { /* … */ }
    fun sendReply(conversationId: String, body: String) { /* … */ }
    fun dismissError() { _state.update { it.copy(banner = null) } }
}
```

Intents are a sealed interface so the UI has a single typed entry point and tests enumerate
the surface exhaustively:

```kotlin
sealed interface HelpdeskIntent {
    data object Refresh : HelpdeskIntent
    data class SetFilter(val filter: QueueFilter) : HelpdeskIntent
    data class Claim(val conversationId: String) : HelpdeskIntent
    data class Select(val conversationId: String?) : HelpdeskIntent
    data class SendReply(val conversationId: String, val body: String) : HelpdeskIntent
    data object DismissError : HelpdeskIntent
}
```

`refresh()` fetches the queue (metrics are derived from it — there is no metrics endpoint, §5):

```kotlin
loadJob = viewModelScope.launch(io) {
    _state.update { it.copy(isRefreshing = true) }
    // group_id is required by GET /messaging/helpdesk/queue; supplied by the repository
    // (env/config default e.g. "e2e-helpdesk"), not by the ViewModel.
    reduceQueue(repository.getQueue())   // ApiResult<List<Conversation>>
    _state.update { it.copy(isRefreshing = false, isLoading = false) }
}
```

The repository (owned upstream by AND-161/162) exposes (corrected: **no `getMetrics`** —
metrics are derived; `claim` returns `HelpdeskClaimOut`, not `Conversation`; the `group_id` is
internal to the repository):

```kotlin
interface HelpdeskRepository {
    suspend fun getQueue(): ApiResult<List<Conversation>>          // GET .../helpdesk/queue?group_id=…
    suspend fun claim(conversationId: String): ApiResult<HelpdeskClaimOut>
    suspend fun getThread(conversationId: String): ApiResult<List<Message>>
    suspend fun reply(conversationId: String, text: String): ApiResult<Message>  // body field = "text"
}
```

`HelpdeskClaimOut` mirrors the backend schema: `ok, conversation_id, state,
assigned_agent_user_id, assignment_version, idempotent`. On a successful claim the reducer
patches the matching queue row's `activeAgentUserId`/`routingState`/`assignmentVersion` from the
result (it does not receive a full updated `Conversation` from the claim call).

Derived state (`filteredQueue`) is computed in a private function over `queue` + `filter`,
not stored as a duplicate field, so it cannot drift. `claim` and `sendReply` use per-id
in-flight sets (`claimingIds`, `isSending`) so multiple rows can show progress independently.

## 5. API Contract

This is a state ticket; it does not define new endpoints. It consumes the repository, which
wraps these existing endpoints. **The shapes below were re-verified against
`reference/openapi.index.txt`, `reference/openapi.pretty.json`, and the web client
(`src/api/endpoints/messaging.ts`, `src/api/types.ts`); several claims in the original draft
were wrong and are corrected here — see §16.**

`GET /messaging/helpdesk/queue` → 200 returns a JSON **array of `ConversationOut`** (verified:
`get_helpdesk_queue_...`, params `group_id, state, limit, authorization, X-SESSION-ID`). The
`group_id` query param is **required** (the web client always passes it, defaulting to the
`VITE_HELPDESK_GROUP_ID` env, e.g. `e2e-helpdesk`); `state` is an optional server-side filter.
Field names below are corrected to the real `Conversation` DTO (`src/api/types.ts: Conversation`):

```json
[
  {
    "conversation_id": "conv_01HF…",
    "type": "dm",
    "title": "Cannot log in",
    "created_by": "usr_pat",
    "created_at": 1749132069,
    "last_message_at": 1749132069,
    "unread_count": 2,
    "routing_mode": "helpdesk_bridge",
    "routing_group_id": "e2e-helpdesk",
    "routing_state": "awaiting_agent",
    "active_agent_user_id": null,
    "assignment_version": 0,
    "participants": [ { "user_id": "usr_pat", "display_name": "Pat Q." } ]
  }
]
```

Corrections vs. the original draft: `id`→`conversation_id`; `subject`→`title`;
`status: "open"`→`routing_state` (enum observed in the web app:
`awaiting_agent | assigned | paused_no_agents_online`); `assignee_id`→`active_agent_user_id`;
`requester`→`participants[]`; timestamps are **Unix epoch seconds (numbers)**, not ISO-8601
strings. There is also a `routing_mode` (`"helpdesk_bridge"`) and an `assignment_version`
integer used for optimistic-concurrency on claims.

**There is no `GET /messaging/helpdesk/metrics` endpoint** — it does not exist anywhere in the
OpenAPI index, and the web Helpdesk page renders no metrics. This was a fabricated assumption.
`getMetrics()` must be **dropped**; any "open/unclaimed/mine" counters must be **derived
client-side** from the queue list (count by `routing_state` / `active_agent_user_id`). See §13 R1
and §16 Open assumptions. The rest of this spec treats metrics as a derived projection of the
queue, not a network call.

`POST /messaging/helpdesk/conversations/{conversation_id}/claim` (empty `{}` body) → 200 returns
**`HelpdeskClaimOut`**, NOT a `Conversation` (verified `HelpdeskClaimOut` schema /
`src/api/endpoints/messaging.ts: claimHelpdeskConversation`):

```json
{
  "ok": true,
  "conversation_id": "conv_01HF…",
  "state": "assigned",
  "assigned_agent_user_id": "usr_me",
  "assignment_version": 3,
  "idempotent": false
}
```

The claim is **idempotent**: claiming a conversation you already own returns `idempotent: true`
with `ok: true`. There is **no 409 `already_claimed` response** (the OpenAPI lists only
`200:HelpdeskClaimOut; 422:HTTPValidationError`, plus the transport-level `403` for non-agents);
the `{ "detail": { "code": "already_claimed", … } }` shape in the original draft was invented.
A lost claim race (another agent already assigned) surfaces either as a non-`ok`/conflicting
`state`/`assigned_agent_user_id != me` in `HelpdeskClaimOut`, or as a `422` validation error —
the repository normalizes this to an `ApiResult.Failure`/conflict signal; the ViewModel re-runs
`refresh()` and shows a non-fatal banner. The mapping uses `state` + `assigned_agent_user_id`,
not a `409`.

`POST /messaging/conversations/{conversation_id}/messages` (reply) → **200** returns the created
**`MessageOut`** (verified `send_text_message_...`, `req=SendTextMessageIn`, `resp=200:MessageOut`).
The body is `SendTextMessageIn`/`SendTextMessageReq`; the text goes in the **`text`** field
(`minLength 1, maxLength 4000`), **not** `body` as the original draft claimed (a nullable `body`
field also exists but the web client uses `text`). Thread reload uses
`GET /messaging/conversations/{conversation_id}/messages` (returns an array of `MessageOut`, or
`{ messages, next_cursor }` — the web client tolerates both). The repository method names in §4
(`reply`, `getThread`) map to these.

All requests carry session cookies (`credentials: include`) + an `X-CSRF-Token` header echoed
from the `ui_csrf` cookie, plus `Authorization: Bearer` when an access token is present; a 401
triggers a single `POST /ui/session/refresh` then one retry — handled in `core-network`,
transparent to this ViewModel (it only observes the final `ApiResult`). Non-agents receive a
`403` on the queue (the web client treats it as a silent/expected non-error).

## 6. Data & State Management

```kotlin
data class HelpdeskUiState(
    val isLoading: Boolean = true,
    val isRefreshing: Boolean = false,
    val queue: List<Conversation> = emptyList(),
    // No stored metrics field: metrics are derived from `queue` (see derived `metrics` below).
    val filter: QueueFilter = QueueFilter.ALL,
    val claimingIds: Set<String> = emptySet(),
    val selectedConversation: Conversation? = null,
    val thread: List<Message> = emptyList(),
    val isSending: Boolean = false,
    val replyDraft: String = "",
    val isStale: Boolean = false,
    val banner: UiText? = null,
) {
    val filteredQueue: List<Conversation>
        get() = when (filter) {
            // Field is activeAgentUserId (maps to ConversationOut.active_agent_user_id),
            // NOT assignee_id — corrected per §5 verification.
            QueueFilter.ALL       -> queue
            QueueFilter.UNCLAIMED -> queue.filter { it.activeAgentUserId == null }
            QueueFilter.MINE      -> queue.filter { it.activeAgentUserId == currentAgentId }
        }

    // Metrics are DERIVED from the queue (no /metrics endpoint exists — see §5/§16),
    // so HelpdeskMetrics is a client-side projection, not a network DTO:
    val metrics: HelpdeskMetrics
        get() = HelpdeskMetrics(
            unclaimed = queue.count { it.activeAgentUserId == null },
            mine      = queue.count { it.activeAgentUserId == currentAgentId },
            total     = queue.size,
        )
}

enum class QueueFilter { ALL, UNCLAIMED, MINE }
```

`Conversation` and `Message` are `core-model` types from AND-120/161; `HelpdeskMetrics` is a
**client-derived** value type computed from the queue (there is no metrics endpoint — §5/§16).
`currentAgentId` is provided via a session accessor injected through the repository (the
ViewModel does not read DataStore directly). State is in-memory and survives configuration
changes via `viewModelScope`/`SavedStateHandle` for `filter`, `selectedConversation.id`, and
`replyDraft` only (re-fetch on process death rather than persisting list bodies). No Room
writes are added here; queue caching is the repository's responsibility (AND-161).

## 7. Error Handling & Resilience

All repository results are `ApiResult<T>` (`Success`, `Failure(error)`). The reducer maps:

- **Network/timeout (`ApiResult.Failure(NetworkError.Timeout|NoConnection)`):** if data
  already loaded → set `isStale = true`, keep data, show a dismissible `banner`; if first
  load → set `isLoading = false` and an `errorState` empty view. Honors the ~20s timeout and
  bounded backoff applied by `core-network` for idempotent GETs only (queue/metrics);
  claim/reply (POST) are never auto-retried here.
- **Claim conflict:** do not surface as a hard error. **Note:** there is no `409
  already_claimed` response (corrected — see §5/§16); the claim endpoint returns only
  `200:HelpdeskClaimOut` or `422:HTTPValidationError` (plus transport `403` for non-agents).
  A lost race is detected from `HelpdeskClaimOut` (e.g. `assigned_agent_user_id != currentAgentId`,
  or `state`/`ok` indicating the conversation is already assigned elsewhere) or from a `422`.
  In that case: remove the row from `claimingIds`, trigger a queue `refresh()`, and emit
  `banner = R.string.helpdesk_already_claimed` ("Already claimed by another agent."). A claim on
  a conversation the agent already owns returns `idempotent = true` and is treated as success.
- **Validation (blank reply):** rejected before any call; emit
  `banner = "Reply can't be empty."`, no `isSending` toggle.
- **FastAPI `detail` mapping:** delegated to `core-network`'s parser producing
  `ApiError(code, message)`; the ViewModel maps `message` into a `UiText`.
- **Re-entrancy:** `refresh()` cancels the prior `loadJob`; per-id sets guard double claims.

## 8. Security & Privacy

No new auth surface. The ViewModel relies entirely on the cookie-based session + persistent
cookie jar and `X-CSRF-Token` echo handled in `core-network`; it never stores credentials,
tokens, or cookies. Queue/conversation contents are PII (requester names, message bodies)
and must not be logged at INFO or above (see §10) and must not be persisted to disk by this
layer. Role gating (agent-only) is enforced server-side and by the AND-377 navigation guard;
the ViewModel assumes an authenticated agent session and surfaces a permission error banner
if the repository returns 403. `SavedStateHandle` persists only the draft text and ids, not
message bodies or requester PII.

## 9. Accessibility & i18n

As a state layer there is no direct UI, but the ViewModel emits user-facing strings only as
`UiText` (string-resource references resolved in Compose, AND-377), never hard-coded English,
so localization and TalkBack-readable content are preserved. Numeric metrics are emitted as
raw values; formatting/pluralization (e.g., "5 unclaimed") is the Composable's responsibility
using Android plurals. Banner messages map to `R.string.*` resources. No locale-specific date
formatting occurs in the ViewModel (timestamps stay ISO-8601 in state).

## 10. Telemetry & Logging

Use the project `Logger` (Timber-backed). Log at DEBUG: intent received (name only), refresh
start/end with result kind (`success|stale|error`) and item counts — never message bodies or
requester identities. Log at WARN: claim conflicts and timeouts (with `conversationId`, no
PII). Emit analytics events through the injected `AnalyticsClient` interface:
`helpdesk_queue_loaded { count, duration_ms, stale }`, `helpdesk_claim
{ result }`, `helpdesk_reply_sent { length_bucket }`. All telemetry is fire-and-forget and
must never block state emission or be asserted on in unit tests beyond a fake recording call
counts.

## 11. Testing Strategy

This is the heart of the ticket (acceptance: **Unit-tested**). Tests live in
`feature-helpdesk/src/test/java/com/testlogon/android/feature/helpdesk/HelpdeskViewModelTest.kt`
using JUnit4, Turbine for `StateFlow`, and a `FakeHelpdeskRepository` plus the
`MainDispatcherRule` from `core-testing`. Coverage target ≥ 90% lines on the ViewModel.

- **Initial load happy path:** init emits `isLoading=true` then a state with populated
  `queue` and correctly **derived** `metrics`, `isLoading=false`. (FR-1)
- **Derived metrics:** given a seeded queue, `metrics.unclaimed/mine/total` match the counts by
  `activeAgentUserId`; no second repository call is made for metrics. (FR-1)
- **Refresh keeps stale data:** seed loaded state, fake returns `Timeout` → `isStale=true`,
  `queue` unchanged, `banner` set, `isRefreshing` returns to false. (FR-2, §7)
- **Filtering is local:** `SetFilter(UNCLAIMED)` changes `filteredQueue` with **zero** new
  repository calls. (FR-3)
- **Claim success:** `Claim(id)` toggles `claimingIds` then clears it; the row's
  `activeAgentUserId == currentAgentId` (patched from `HelpdeskClaimOut`) and the conversation
  becomes `selectedConversation`. (FR-4)
- **Claim conflict (no 409):** fake returns a `HelpdeskClaimOut` with
  `assigned_agent_user_id != currentAgentId` (or a `422` failure) → triggers a `refresh()`,
  sets banner, clears the id from `claimingIds`, no crash. (FR-4, §7)
- **Idempotent claim:** fake returns `idempotent=true` for a conversation already owned →
  treated as success, no conflict banner. (FR-4)
- **Reply validation:** `SendReply(id, "  ")` emits empty-body banner and makes no call;
  valid reply toggles `isSending`, clears `replyDraft`, reloads thread. (FR-6)
- **Re-entrancy:** two rapid `Refresh` intents result in a single coherent final emission
  (prior job cancelled). (FR-8)
- **Distinct emissions:** assert no two consecutive equal `HelpdeskUiState` values. (FR-9)
- **dismissError clears banner only**, leaving data intact. (FR-7)

`runTest` + `advanceUntilIdle()` drive virtual time; no real delays. AND-381 adds repository
integration and Compose UI tests on top of these.

## 12. Dependencies & Sequencing

- **Depends on AND-377** (agent dashboard) for the screen that hosts this ViewModel, and
  transitively on **AND-161** (queue endpoint + `HelpdeskRepository.getQueue`) and **AND-162**
  (claim + reply repository methods and error codes). The repository interface methods used
  in §4 must exist before this ticket can compile; if AND-161/162 have not exposed
  `getMetrics`/`getThread`, those are added as part of wiring here and back-filled to the
  repository owner.
- **Blocks AND-381** (Helpdesk tests) which depends on AND-380 and extends its unit tests
  with repo + UI tests.
- Reuses `core-network` `ApiResult`, the 401-refresh interceptor, and `core-testing`
  `MainDispatcherRule`/Turbine setup. No Gradle, manifest, or DI-graph changes beyond adding
  `HelpdeskViewModel` to the Hilt-generated factory (automatic via `@HiltViewModel`).

## 13. Risks & Open Questions

- **R1 — Metrics endpoint shape: RESOLVED (no endpoint).** Verification against the OpenAPI
  index confirms there is **no** `/messaging/helpdesk/metrics` (or any helpdesk-metrics) route,
  and the web Helpdesk page renders no metrics. Decision: `getMetrics()` is **removed**; metrics
  are derived client-side from the queue (`unclaimed`/`mine`/`total` by `active_agent_user_id`).
  See §5/§6/§16.
- **R2 — `currentAgentId` source: RESOLVED (available).** `GET /ui/me` exists
  (`ui_me_ui_me_get`) and the web app keeps `userId` in its auth store (`useAuthStore`), used
  directly by `HelpdeskPage.tsx`. The agent id is available without an extra per-screen
  round-trip (injected via the repository/session accessor per §6). The `MINE` filter compares
  `active_agent_user_id == currentAgentId`; only if the id is unavailable does it fall back to
  `active_agent_user_id != null`.
- **R3 — Claim race window:** between queue load and claim, another agent may claim. Handled
  via conflict-detection on `HelpdeskClaimOut` (`assigned_agent_user_id`/`state`) or a `422`
  → refresh (there is no `409`; corrected per §5/§16), but rapid conflicts could flicker the
  banner; debounce if QA flags it.
- **R4 — Thread pagination:** large conversations may need Paging 3; out of scope here, thread
  is loaded as a bounded list. Flag to AND-377/AND-162 if threads exceed page limits.
- **Open question:** should refresh poll on an interval for live queue updates, or is
  pull-to-refresh sufficient for M8? Defaulting to manual refresh.

## 14. Acceptance Criteria

AC-1. `HelpdeskViewModel`, `HelpdeskUiState`, `HelpdeskIntent`, and `QueueFilter` exist in
`com.testlogon.android.feature.helpdesk` and compile against the `core-data`
`HelpdeskRepository`.

AC-2. The ViewModel exposes a single `StateFlow<HelpdeskUiState>` and a single `onIntent`
entry point; the UI cannot mutate state directly.

AC-3. All functional requirements FR-1 through FR-9 are implemented and observable via state.

AC-4. Unit tests in `HelpdeskViewModelTest` cover every scenario in §11, run on a
`TestDispatcher` with no real delays, and pass deterministically. Line coverage on the
ViewModel ≥ 90%.

AC-5. Claim conflicts (detected from `HelpdeskClaimOut` — `assigned_agent_user_id`/`state` —
or a `422`; there is no `409 already_claimed`, corrected per §5/§16) and GET timeouts produce
non-fatal, dismissible banners with prior data retained; blank replies are rejected without a
network call — each proven by a test.

AC-6. No PII or message bodies are logged at INFO+ and none are persisted by this layer
(verified by review against §8/§10).

## 15. Definition of Done

- Code merged to `android-port` under `feature-helpdesk` following module layering
  (`feature-helpdesk` → `core-*` only).
- `HelpdeskViewModel` injected via Hilt (`@HiltViewModel`) with an injected dispatcher; no
  hard-coded `Dispatchers.IO`.
- Unit test suite green in CI (`./gradlew :feature-helpdesk:testDebugUnitTest`) with the
  coverage threshold met; tests use Turbine + `MainDispatcherRule`.
- ktlint/detekt clean; no new lint baseline entries.
- All user-facing strings are `UiText`/string resources; no hard-coded copy in the ViewModel.
- AC-1 through AC-6 verified and signed off; AND-377 dashboard wires to this ViewModel
  without modification and AND-381 can build its repo/UI tests on top.
- Spec references to AND-377, AND-161, AND-162, AND-120, and AND-381 remain consistent with
  the backlog; any deviations (R1/R2 resolutions) recorded back into the depended-on tickets.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source. Sources: OpenAPI =
`reference/openapi.index.txt` / `reference/openapi.pretty.json`; FE = `reference/src/...`.

1. **Helpdesk queue endpoint is `GET /messaging/helpdesk/queue`.** Verified. OpenAPI
   `GET /messaging/helpdesk/queue` (`op=get_helpdesk_queue_...`); FE
   `src/api/endpoints/messaging.ts: getHelpdeskQueue`.
2. **The queue request requires a `group_id` query param (and accepts optional `state`,
   `limit`).** Verified / Corrected (original draft omitted it). OpenAPI params
   `group_id,state,limit,authorization,X-SESSION-ID`; FE `getHelpdeskQueue(groupId, state?)`
   passes `{ group_id, state? }` (`src/pages/helpdesk/HelpdeskPage.tsx` defaults
   `VITE_HELPDESK_GROUP_ID ?? "e2e-helpdesk"`).
3. **Queue returns an array of `ConversationOut`/`Conversation`.** Verified. FE
   `getHelpdeskQueue` returns `Conversation[]`; OpenAPI 200 body is the helpdesk queue array
   (`get_helpdesk_queue_...`).
4. **Queue item field names: `conversation_id`, `title`, `routing_state`,
   `active_agent_user_id`, `routing_mode`, `assignment_version`, `participants[]`,
   `unread_count`; timestamps are epoch-second numbers.** Corrected (draft used `id`,
   `subject`, `status:"open"`, `assignee_id`, `requester{}`, ISO-8601). Source
   `src/api/types.ts: Conversation` (lines ~775-806); routing-state enum values
   (`awaiting_agent | assigned | paused_no_agents_online`) from
   `src/pages/helpdesk/HelpdeskPage.tsx: routingStateBadge`.
5. **No helpdesk metrics endpoint exists; metrics must be derived client-side.** Corrected /
   Verified-absent. No `metrics` route under `helpdesk` in OpenAPI index; the FE Helpdesk page
   renders no metrics widget (`src/pages/helpdesk/HelpdeskPage.tsx`). The original
   `GET /messaging/helpdesk/metrics` and its `{open,unclaimed,mine,avg_first_response_sec}`
   body were fabricated.
6. **Claim endpoint is `POST /messaging/helpdesk/conversations/{conversation_id}/claim`.**
   Corrected (draft said `POST /helpdesk/conversations/{id}/claim`). OpenAPI
   `POST /messaging/helpdesk/conversations/{conversation_id}/claim`
   (`op=claim_helpdesk_conversation_...`); FE
   `src/api/endpoints/messaging.ts: claimHelpdeskConversation` posts `{}`.
7. **Claim returns `HelpdeskClaimOut` = `{ok, conversation_id, state,
   assigned_agent_user_id, assignment_version, idempotent}`, not a `Conversation`.** Corrected.
   `components.schemas.HelpdeskClaimOut` (openapi.pretty.json) and
   `src/api/types.ts: HelpdeskClaimOut`.
8. **There is no `409 already_claimed` claim-conflict response; claim is idempotent and
   conflicts are inferred from the result/`422`.** Corrected. OpenAPI lists only
   `resp=200:HelpdeskClaimOut;422:HTTPValidationError` for the claim op; `idempotent` flag in
   `HelpdeskClaimOut`. The `{detail:{code:"already_claimed",...}}` shape was invented.
9. **Reply endpoint is `POST /messaging/conversations/{conversation_id}/messages`, returns
   `200 MessageOut`, body field is `text` (1..4000 chars), not `body`, and not 201.** Corrected
   (draft said 201 and `{"body":"…"}`). OpenAPI `send_text_message_...`
   (`req=SendTextMessageIn`, `resp=200:MessageOut`); `components.schemas.SendTextMessageIn`
   (`text`: minLength 1/maxLength 4000); FE `src/api/endpoints/messaging.ts: sendTextMessage` +
   `src/api/types.ts: SendTextMessageReq` (`text?`).
10. **Thread reload uses `GET /messaging/conversations/{conversation_id}/messages`
    (array, or `{messages,next_cursor}`).** Verified. OpenAPI `list_messages_...`; FE
    `src/api/endpoints/messaging.ts: getMessages` tolerates both shapes.
11. **Auth/transport: session cookies (`credentials: include`) + `X-CSRF-Token` echoed from the
    `ui_csrf` cookie + `Authorization: Bearer <accessToken>` when present.** Corrected (draft
    implied cookie-only). FE `src/api/client.ts` (getCookie("ui_csrf") → X-CSRF-Token;
    Authorization Bearer; `credentials:"include"`).
12. **401 handling: one `POST /ui/session/refresh`, then a single retry.** Verified. OpenAPI
    `POST /ui/session/refresh` (`ui_session_refresh_...`); FE `src/api/client.ts:
    refreshSession` + single retry block.
13. **Non-agents receive `403` on the queue (expected/silent).** Verified. FE
    `getHelpdeskQueue` passes `silent403: true`; `HelpdeskPage.tsx` treats `queueError` as
    "not an agent". (Transport 403 is not enumerated per-op in the index but is handled
    generically in `src/api/client.ts`.)
14. **`currentAgentId` is available from `GET /ui/me` / the auth store.** Verified. OpenAPI
    `GET /ui/me` (`ui_me_ui_me_get`); FE `useAuthStore((s) => s.userId)` in
    `src/pages/helpdesk/HelpdeskPage.tsx`.
15. **The `MINE`/`UNCLAIMED`/`ALL` client-side filter is an Android-app addition.**
    Unverified-assumption (no contradiction). The web app does not expose these three filters;
    it filters by `routing_mode === "helpdesk_bridge"` and shows the agent queue separately
    (`HelpdeskPage.tsx`). The tri-state filter is a reasonable mobile UX choice but is not a
    backend contract.
16. **ViewModel/Hilt/coroutine framework choices** (`@HiltViewModel`, injected
    `CoroutineDispatcher`, `StateFlow`, `viewModelScope`, Turbine, `runTest`/`StandardTestDispatcher`).
    Verified (framework ref): Android architecture / ViewModel
    (https://developer.android.com/topic/libraries/architecture/viewmodel),
    Hilt (https://developer.android.com/training/dependency-injection/hilt-android),
    coroutines testing (https://developer.android.com/kotlin/coroutines/test),
    StateFlow (https://developer.android.com/kotlin/flow/stateflow-and-sharedflow).

### Corrections made

- Claim path `/helpdesk/conversations/{id}/claim` → `/messaging/helpdesk/conversations/{conversation_id}/claim` (§2, §5).
- Claim response `Conversation` → `HelpdeskClaimOut` (§4, §5, §7, §11, §14).
- Removed the fabricated `409 already_claimed` conflict shape; conflicts inferred from
  `HelpdeskClaimOut`/`422`; claim is idempotent (§5, §7, §11, §13-R3, §14).
- Removed the fabricated `GET /messaging/helpdesk/metrics` endpoint and its body; metrics are
  now derived client-side from the queue (§1, §2, §3-FR1/FR2, §4, §5, §6, §11, §13-R1).
- Queue DTO field names corrected to the real `Conversation` shape and timestamps changed from
  ISO-8601 to epoch seconds (§5, §6).
- Added the required `group_id` query param for the queue (§4, §5).
- Reply: `201` → `200`, body field `body` → `text` (1..4000) / `SendTextMessageReq`,
  `MessageOut` response (§5).
- Auth corrected from "cookie-based only" to cookies + `X-CSRF-Token` (`ui_csrf`) + optional
  `Authorization: Bearer` (§2, §5).
- `MINE` filter field `assignee_id`/`assigneeId` → `active_agent_user_id`/`activeAgentUserId` (§6).
- R1 and R2 marked RESOLVED with sources (§13).

### Open assumptions

- **Tri-state `QueueFilter` (ALL/UNCLAIMED/MINE)** is an Android-side UX construct, not a
  backend filter (the server `state` query param is separate). Unverifiable as a contract
  because the web app does not implement it (claim #15).
- **Exact lost-claim signal.** The backend returns `200 HelpdeskClaimOut` for claims and `422`
  for validation; whether a lost race comes back as a non-`ok`/different `assigned_agent_user_id`
  in a `200`, or as a `422`, is not pinned down by the available sources (the FE
  `onClaimSuccess` only consumes the success path). The ViewModel handles both defensively;
  confirm the exact server behavior with AND-162 during implementation.
- **`HelpdeskMetrics` shape** (the derived `unclaimed/mine/total` value type) is a local
  invention since no metrics DTO exists; field choice is not backed by any source.
- **`routing_state` enum completeness.** Only `awaiting_agent`, `assigned`,
  `paused_no_agents_online` are observed in `HelpdeskPage.tsx`; the backend may emit others.
  The reducer must treat unknown states as pass-through (no crash).

## 17. Test Plan

All cases target `HelpdeskViewModel` + `HelpdeskUiState` unless noted. The ticket's acceptance
bar is **Unit-tested**, so the core suite is JVM unit (`FakeHelpdeskRepository`, Turbine,
`MainDispatcherRule`, `runTest`/`StandardTestDispatcher`) — these run on **JVM unit/Robolectric
(no device)**. A few contract/instrumented cases are included to validate the real wire shapes
this ViewModel depends on and the offline/flaky-host path; they note their target.

- **TC-AND-380-01 — Initial load happy path.** Type: unit. Target: ViewModel (JVM).
  Preconditions: `FakeHelpdeskRepository.getQueue()` returns `Success(listOf(conv1, conv2))`.
  Steps: construct ViewModel; collect `state` via Turbine; `advanceUntilIdle()`. Expected:
  first emission `isLoading=true`, then `isLoading=false`, `isRefreshing=false`, `queue` has 2
  items, `banner=null`. Traces: AC-3 (FR-1), AC-2.

- **TC-AND-380-02 — Derived metrics correctness.** Type: unit. Target: ViewModel (JVM).
  Preconditions: queue = 3 unclaimed + 2 owned-by-me + 1 owned-by-other.
  Steps: load; read `state.metrics`. Expected: `unclaimed=3`, `mine=2`, `total=6`; the fake
  records **no** separate metrics call (no `getMetrics` exists). Traces: AC-3 (FR-1).

- **TC-AND-380-03 — Refresh is stale-while-revalidate on timeout.** Type: unit. Target:
  ViewModel (JVM). Preconditions: seed a loaded `queue`; next `getQueue()` returns
  `Failure(NetworkError.Timeout)`. Steps: dispatch `Refresh`; advance. Expected: prior `queue`
  retained, `isStale=true`, dismissible `banner` set, `isRefreshing` ends `false`, no crash.
  Traces: AC-5, AC-3 (FR-2).

- **TC-AND-380-04 — Filtering is local, zero network.** Type: unit. Target: ViewModel (JVM).
  Preconditions: loaded queue with mixed `activeAgentUserId`. Steps: dispatch
  `SetFilter(UNCLAIMED)` then `SetFilter(MINE)`. Expected: `filteredQueue` recomputes by
  `activeAgentUserId` (UNCLAIMED → null owner; MINE → `== currentAgentId`); fake records zero
  additional `getQueue` calls. Traces: AC-3 (FR-3).

- **TC-AND-380-05 — Claim success patches row from `HelpdeskClaimOut`.** Type: unit. Target:
  ViewModel (JVM). Preconditions: `claim(id)` returns
  `Success(HelpdeskClaimOut(ok=true, state="assigned", assigned_agent_user_id=currentAgentId,
  assignment_version=3, idempotent=false))`. Steps: dispatch `Claim(id)`. Expected: `claimingIds`
  contains `id` mid-flight then clears; the queue row's `activeAgentUserId == currentAgentId`
  and `assignmentVersion=3`; conversation becomes `selectedConversation`. Traces: AC-3 (FR-4).

- **TC-AND-380-06 — Idempotent claim treated as success.** Type: unit. Target: ViewModel (JVM).
  Preconditions: `claim(id)` returns `HelpdeskClaimOut(ok=true, idempotent=true,
  assigned_agent_user_id=currentAgentId)`. Steps: dispatch `Claim(id)`. Expected: success path,
  no conflict banner, row owned by me. Traces: AC-3 (FR-4).

- **TC-AND-380-07 — Lost claim race → refresh + non-fatal banner (no 409).** Type: unit.
  Target: ViewModel (JVM). Preconditions: `claim(id)` returns a `HelpdeskClaimOut` with
  `assigned_agent_user_id != currentAgentId` (and a second variant returning
  `Failure(ApiError(422,...))`). Steps: dispatch `Claim(id)`; advance. Expected: `claimingIds`
  cleared, a `refresh()` is triggered (fake records an extra `getQueue`), `banner` =
  already-claimed string, no crash, no `409` assumed. Traces: AC-5, AC-3 (FR-4).

- **TC-AND-380-08 — Reply validation rejects blank without a call.** Type: unit. Target:
  ViewModel (JVM). Preconditions: loaded + selected conversation. Steps: dispatch
  `SendReply(id, "   ")`. Expected: `banner` = empty-reply string, `isSending` never toggles,
  fake records zero `reply` calls. Traces: AC-5, AC-3 (FR-6).

- **TC-AND-380-09 — Reply happy path clears composer and reloads thread.** Type: unit. Target:
  ViewModel (JVM). Preconditions: `reply(id, "hi")` returns `Success(message)`; `getThread`
  returns updated list. Steps: set `replyDraft="hi"`; dispatch `SendReply(id, "hi")`; advance.
  Expected: `isSending` toggles true→false, `replyDraft` cleared, `thread` reloaded, `banner`
  null. Traces: AC-3 (FR-6).

- **TC-AND-380-10 — Re-entrancy: two rapid refreshes → one coherent final state.** Type: unit.
  Target: ViewModel (JVM). Preconditions: first `getQueue` suspends; dispatch `Refresh` twice.
  Steps: advance. Expected: prior `loadJob` cancelled, exactly one final coherent emission,
  `isRefreshing=false`; no interleaved double application. Traces: AC-3 (FR-8).

- **TC-AND-380-11 — Distinct emissions + `dismissError` clears banner only.** Type: unit.
  Target: ViewModel (JVM). Preconditions: a state with a `banner` and populated `queue`. Steps:
  collect with Turbine across a sequence (load, set filter twice to same value, dismiss).
  Expected: no two consecutive equal `HelpdeskUiState` values; `DismissError` sets `banner=null`
  while `queue`/`filter`/`selectedConversation` unchanged. Traces: AC-3 (FR-7, FR-9), AC-2.

- **TC-AND-380-12 — Contract: claim/queue/reply wire shapes (MockWebServer).** Type:
  contract/MockWebServer. Target: `HelpdeskRepository` + Retrofit/Moshi mapping (JVM).
  Preconditions: MockWebServer enqueues canned JSON exactly matching §5 (queue array with
  `conversation_id`/`routing_state`/`active_agent_user_id`; claim → `HelpdeskClaimOut`; reply
  → `MessageOut`). Steps: call `getQueue` (asserts `group_id` query param sent), `claim`
  (asserts path `/messaging/helpdesk/conversations/{id}/claim`, empty body, `X-CSRF-Token`
  header present), `reply` (asserts body has `text`, path `.../messages`). Expected: deserialized
  models match; request paths/headers/fields are exactly as corrected in §5. Traces: AC-1, AC-5.

- **TC-AND-380-13 — Offline / flaky dev-host path (401 refresh + timeout).** Type:
  contract/MockWebServer (JVM; optionally instrumented). Target: `core-network` interceptor +
  repository → ViewModel. Preconditions: server first returns `401`, then `200` after the
  ViewModel-transparent `POST /ui/session/refresh`; a second scenario returns a socket timeout.
  Steps: trigger `refresh`/`claim`. Expected: 401 path performs exactly one refresh + one retry
  and the ViewModel only sees the final `Success`; timeout path yields `Failure(Timeout)` →
  stale banner per TC-03. Traces: AC-5.

- **TC-AND-380-14 — Security/permission: 403 non-agent and no-PII logging.** Type: unit +
  manual review. Target: ViewModel + `Logger`/`AnalyticsClient` fakes (JVM). Preconditions:
  `getQueue` returns `Failure(ApiError(403,...))`; a recording `Logger` fake. Steps: load;
  dispatch a claim/reply. Expected: a permission banner (not a crash) on 403; assert the
  `Logger` fake captured **no** message bodies or requester display names at INFO+ (only DEBUG
  intent names/counts), and `SavedStateHandle` holds only `filter`/`selectedConversation.id`/
  `replyDraft` — never PII. Traces: AC-6, §8.

### Coverage matrix

- **AC-1** (types exist & compile vs. repository): TC-12.
- **AC-2** (single `StateFlow` + single `onIntent`, no direct mutation): TC-01, TC-11.
- **AC-3 / FR-1** (load + derived metrics): TC-01, TC-02.
- **AC-3 / FR-2** (refresh, stale-while-revalidate): TC-03.
- **AC-3 / FR-3** (local filter, no network): TC-04.
- **AC-3 / FR-4** (claim flow, conflict, idempotent): TC-05, TC-06, TC-07.
- **AC-3 / FR-5** (select/clear conversation): TC-05 (select on claim), TC-11.
- **AC-3 / FR-6** (reply validation + happy path): TC-08, TC-09.
- **AC-3 / FR-7** (dismissError): TC-11.
- **AC-3 / FR-8** (re-entrancy/cancellation): TC-10.
- **AC-3 / FR-9** (distinct emissions): TC-11.
- **AC-4** (suite runs on TestDispatcher, deterministic, ≥90%): all unit cases TC-01..TC-11, TC-14.
- **AC-5** (conflict/timeout banners, blank-reply rejection): TC-03, TC-07, TC-08, TC-12, TC-13.
- **AC-6** (no PII/bodies logged or persisted): TC-14.

No case in this plan requires the physical Samsung Galaxy A15 (SM-A156U) or the `test35`
emulator: AND-380 is a pure JVM state/logic layer with no camera, biometrics, FCM, WebRTC,
Telecom, or streaming surface. Hardware-dependent helpdesk behavior (real push, device UI) is
owned by AND-377/AND-381; if those suites want an instrumented variant of TC-12/TC-13, run them
on the `test35` emulator (fast CI), reserving the physical device only for AND-381's real-network
or notification-tap cases.
