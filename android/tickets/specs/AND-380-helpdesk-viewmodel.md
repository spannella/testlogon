---
id: AND-380
title: Helpdesk ViewModel
milestone: M8
epic: E49
priority: P2
size: M
status: draft
depends_on: [AND-377]
blocks: [AND-381]
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
  and the claim/reply behavior defined in **AND-162** (`/helpdesk/conversations/{id}/claim`).
  This ticket reuses the `HelpdeskRepository` and DTOs established by AND-161/AND-162 and
  the messaging DTOs from **AND-120**.
- **Downstream dependency AND-381 — Helpdesk tests** (repo + UI tests) builds on the unit
  tests delivered here; AND-381 owns instrumented Compose UI tests against the AND-377 screen.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext, slow).
  OpenAPI at `/openapi.json`. Web reference: `frontend/src/api/endpoints/*.ts`, shared types
  `frontend/src/api/types.ts`.
- **Conventions:** ViewModels expose `StateFlow<UiState>`; cookie-based auth with one-shot
  `/ui/session/refresh` on 401; FastAPI `detail` mapping (`string | [{msg}] | {code,...}`).

## 3. Functional Requirements

FR-1. On creation the ViewModel loads, in parallel, the helpdesk queue and the helpdesk
metrics for the current agent, surfacing a combined loading state until both resolve.

FR-2. The ViewModel exposes a `refresh()` intent that re-fetches queue and metrics; a
pull-to-refresh on the dashboard maps to this. Refresh must not clear already-loaded data
(stale-while-revalidate): it sets `isRefreshing = true` and keeps prior `queue`/`metrics`.

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

`refresh()` runs the two GETs concurrently:

```kotlin
loadJob = viewModelScope.launch(io) {
    _state.update { it.copy(isRefreshing = true) }
    val queueDeferred   = async { repository.getQueue() }      // ApiResult<List<Conversation>>
    val metricsDeferred = async { repository.getMetrics() }    // ApiResult<HelpdeskMetrics>
    reduceQueue(queueDeferred.await())
    reduceMetrics(metricsDeferred.await())
    _state.update { it.copy(isRefreshing = false, isLoading = false) }
}
```

The repository (owned upstream by AND-161/162) exposes:

```kotlin
interface HelpdeskRepository {
    suspend fun getQueue(): ApiResult<List<Conversation>>
    suspend fun getMetrics(): ApiResult<HelpdeskMetrics>
    suspend fun claim(conversationId: String): ApiResult<Conversation>
    suspend fun getThread(conversationId: String): ApiResult<List<Message>>
    suspend fun reply(conversationId: String, body: String): ApiResult<Message>
}
```

Derived state (`filteredQueue`) is computed in a private function over `queue` + `filter`,
not stored as a duplicate field, so it cannot drift. `claim` and `sendReply` use per-id
in-flight sets (`claimingIds`, `isSending`) so multiple rows can show progress independently.

## 5. API Contract

This is a state ticket; it does not define new endpoints. It consumes the repository, which
wraps these existing endpoints (authoritative shapes per AND-161/162 and `/openapi.json`).

`GET /messaging/helpdesk/queue` → 200:

```json
[
  {
    "id": "conv_01HF…",
    "subject": "Cannot log in",
    "status": "open",
    "assignee_id": null,
    "requester": { "id": "usr_…", "display_name": "Pat Q." },
    "last_message_at": "2026-06-05T14:21:09Z",
    "unread_count": 2
  }
]
```

`GET /messaging/helpdesk/metrics` → 200:

```json
{ "open": 12, "unclaimed": 5, "mine": 3, "avg_first_response_sec": 184 }
```

`POST /helpdesk/conversations/{id}/claim` → 200 returns the updated `Conversation`
(`assignee_id` now set to the agent). Claim conflict → 409:

```json
{ "detail": { "code": "already_claimed", "assignee_id": "usr_other" } }
```

`POST /messaging/conversations/{id}/messages` (reply) body `{ "body": "…" }` → 201 returns
the created `Message`. All requests carry session cookies + `X-CSRF-Token`; a 401 triggers a
single `POST /ui/session/refresh` then one retry — handled in `core-network`, transparent to
this ViewModel (it only observes the final `ApiResult`).

## 6. Data & State Management

```kotlin
data class HelpdeskUiState(
    val isLoading: Boolean = true,
    val isRefreshing: Boolean = false,
    val queue: List<Conversation> = emptyList(),
    val metrics: HelpdeskMetrics? = null,
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
            QueueFilter.ALL       -> queue
            QueueFilter.UNCLAIMED -> queue.filter { it.assigneeId == null }
            QueueFilter.MINE      -> queue.filter { it.assigneeId == currentAgentId }
        }
}

enum class QueueFilter { ALL, UNCLAIMED, MINE }
```

`HelpdeskMetrics`, `Conversation`, and `Message` are `core-model` types from AND-120/161.
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
- **Claim conflict (409 `already_claimed`):** do not surface as a hard error. Remove the row
  from `claimingIds`, trigger a queue `refresh()`, and emit `banner = "Already claimed by
  another agent."`
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
  `queue` + `metrics`, `isLoading=false`. (FR-1)
- **Concurrent fetch:** queue and metrics are requested via `async` and both awaited; verify
  with a fake that records call order/overlap on a `StandardTestDispatcher`.
- **Refresh keeps stale data:** seed loaded state, fake returns `Timeout` → `isStale=true`,
  `queue` unchanged, `banner` set, `isRefreshing` returns to false. (FR-2, §7)
- **Filtering is local:** `SetFilter(UNCLAIMED)` changes `filteredQueue` with **zero** new
  repository calls. (FR-3)
- **Claim success:** `Claim(id)` toggles `claimingIds` then clears it, conversation becomes
  `selectedConversation` with `assigneeId == currentAgentId`. (FR-4)
- **Claim conflict (409 already_claimed):** triggers a `refresh()`, sets banner, clears the
  id from `claimingIds`, no crash. (FR-4, §7)
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

- **R1 — Metrics endpoint shape:** `/messaging/helpdesk/metrics` is assumed; if the backend
  only returns metrics embedded in the queue response, drop `getMetrics()` and derive metrics
  client-side from the queue. Verify against `/openapi.json` during implementation.
- **R2 — `currentAgentId` source:** the `MINE` filter needs the agent's id. Confirm it is
  available from the session/`/ui/me` (AND-001x) without an extra round-trip; otherwise the
  `MINE` filter falls back to `assignee_id != null`.
- **R3 — Claim race window:** between queue load and claim, another agent may claim. Handled
  via 409 → refresh, but rapid conflicts could flicker the banner; debounce if QA flags it.
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

AC-5. Claim conflicts (409 `already_claimed`) and GET timeouts produce non-fatal,
dismissible banners with prior data retained; blank replies are rejected without a network
call — each proven by a test.

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
