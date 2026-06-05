---
id: AND-282
title: Tips & goals
milestone: M6
epic: E38
priority: P1
size: M
status: draft
depends_on: [AND-281, AND-031]
blocks: []
---

# AND-282 — Tips & goals

## 1. Overview & Goal

This ticket adds a tipping experience and a goal-progress display to the live
stream/chat surface delivered by AND-281 (Live chat). A viewer can send a tip
to the broadcaster via the `chat/tip` endpoint, the running tip total for the
session is summarized inline, and any active broadcaster goals render their
progress (current amount vs. target, percentage, completion state).

The goal is a production-quality, testable feature slice that:

- Lets an authenticated, finalized session submit a tip of a chosen amount.
- Reflects the new tip optimistically and then reconciles with the server's
  authoritative tips summary.
- Renders one or more goals with live progress that updates as tips arrive,
  including over the AND-281 SSE chat/event stream.
- Degrades gracefully when the unreliable dev backend is slow, offline, or
  returns stale data.

Non-goals: payment-processor integration / real money movement (the dev
backend treats tip `amount` as an abstract unit), tip leaderboards, and goal
authoring/editing (broadcaster-side, out of scope for the viewer app).

## 2. Context & References

- Repo `spannella/testlogon`, Android app in `android/`, branch `android-port`.
- Namespace / applicationId base: `com.testlogon.android`.
- Feature module: `feature-stream` (the module that owns AND-281 live chat).
  Tips & goals are added as a sub-package `feature-stream/tips` rather than a
  new module, since they share the same screen, ViewModel scope, and SSE
  stream as live chat.
- Core deps: `core-network` (Retrofit/OkHttp/Moshi, `ApiResult<T>`, CSRF + cookie
  jar, refresh-on-401), `core-model` (DTO/domain types), `core-ui` (Compose M3
  components, formatting), `core-data` (repositories), `core-testing`.
- Dev backend `http://18.222.237.167:8000` (plaintext HTTP, unreliable).
  OpenAPI at `/openapi.json`. Web reference: `frontend/src/api/endpoints/*.ts`
  and `frontend/src/api/types.ts`.
- Auth is cookie-based and already established before this screen is reachable:
  `POST /ui/session/start` → MFA → `POST /ui/session/finalize` → `GET /ui/me`.
  The persistent cookie jar and `X-CSRF-Token` (from the `ui_csrf` cookie) are
  provided by `core-network`; tip submission is a mutating POST and MUST carry
  the CSRF header.

Upstream tickets:

- **AND-281 (Live chat, P0)** — owns the `StreamScreen`, the chat SSE stream
  (`/ui/chat/stream`), the send path, and the shared `StreamViewModel`/scope.
  This ticket plugs into that ViewModel and consumes goal-update events from
  the same SSE stream.
- **AND-031 (LoginViewModel, P0)** — establishes the `StateFlow<UiState>` +
  submit-handler + result-mapping pattern reused verbatim here.

## 3. Functional Requirements

FR-1. The stream screen shows a **tips summary** band: session tip total and
tip count, e.g. "1,250 tips · 18 tippers".

FR-2. A **Tip** affordance (button) opens a tip composer (bottom sheet) where
the user selects/enters an amount and optionally a short message (≤140 chars).
Quick-amount chips (e.g. 5 / 10 / 25 / 50 / 100) plus a free-entry field.

FR-3. Submitting a tip calls `POST /ui/chat/tip`. On success the composer
closes, the tip is shown optimistically in the tips summary and (if a message
was attached) appears in the chat list owned by AND-281.

FR-4. The submit button is disabled while a request is in flight and when the
amount is empty/≤0/non-numeric; a spinner shows on the button during the call.

FR-5. **Goals** render as a list (commonly one active goal) showing title,
current amount, target amount, a determinate progress bar, percentage, and a
"Reached!" state when `current >= target`.

FR-6. Goal progress updates **live**: when a `goal_update` event arrives over
the AND-281 SSE stream, the displayed goal(s) update without a manual refresh.
If no SSE event arrives within the goal cache TTL, a bounded background refresh
of the tips/goals summary keeps the display from going stale.

FR-7. On entering the screen, goals and tips summary load once (idempotent
GETs) in parallel with the chat history load from AND-281.

FR-8. Errors (network, validation `detail`, 401) surface as user-readable
messages without crashing or losing the composer's entered amount.

## 4. Technical Design

### 4.1 Layering

```
feature-stream/tips
  ui/        TipsSummaryBar, GoalList, TipComposerSheet (Compose)
  TipsGoalsViewModel (extends/composed into StreamViewModel)
core-data
  TipsRepository (interface) -> TipsRepositoryImpl
core-network
  TipsApi (Retrofit)
core-model
  Tip, TipsSummary, Goal (+ DTOs)
```

Tips & goals state is exposed by the existing `StreamViewModel` (AND-281) via a
delegated `TipsGoalsViewModel`, so the SSE stream is subscribed once. Both use
`StateFlow<UiState>` per the AND-031 pattern.

### 4.2 Models (core-model)

```kotlin
data class TipsSummary(
    val totalAmount: Long,
    val tipperCount: Int,
    val tipCount: Int,
)

data class Goal(
    val id: String,
    val title: String,
    val currentAmount: Long,
    val targetAmount: Long,
) {
    val fraction: Float get() =
        if (targetAmount <= 0) 0f
        else (currentAmount.toFloat() / targetAmount).coerceIn(0f, 1f)
    val isReached: Boolean get() = currentAmount >= targetAmount && targetAmount > 0
}

data class Tip(
    val id: String,
    val amount: Long,
    val message: String?,
    val createdAt: Instant,
)
```

### 4.3 Retrofit API (core-network)

```kotlin
interface TipsApi {
    @POST("ui/chat/tip")
    suspend fun submitTip(@Body body: TipRequestDto): TipResponseDto

    @GET("ui/chat/tips")
    suspend fun getTipsSummary(@Query("channel_id") channelId: String): TipsSummaryDto

    @GET("ui/chat/goals")
    suspend fun getGoals(@Query("channel_id") channelId: String): GoalsResponseDto
}
```

The CSRF header and cookies are attached by the shared OkHttp interceptor/cookie
jar from `core-network`; do not re-implement them here.

### 4.4 Repository (core-data)

```kotlin
interface TipsRepository {
    fun observeTipsSummary(channelId: String): Flow<TipsSummary>
    fun observeGoals(channelId: String): Flow<List<Goal>>
    suspend fun refresh(channelId: String): ApiResult<Unit>
    suspend fun submitTip(
        channelId: String,
        amount: Long,
        message: String?,
    ): ApiResult<Tip>
    /** Apply a goal_update / tip event decoded from the AND-281 SSE stream. */
    fun applyStreamEvent(event: StreamEvent)
}
```

`TipsRepositoryImpl` holds in-memory `MutableStateFlow`s for the current
channel's summary and goals (single live channel at a time; no Room cache
needed — tips/goals are session-scoped and ephemeral). On `submitTip` success
it optimistically merges the returned tip; SSE events from AND-281 are the
authoritative reconciliation path via `applyStreamEvent`.

### 4.5 ViewModel

```kotlin
data class TipsGoalsUiState(
    val summary: TipsSummary? = null,
    val goals: List<Goal> = emptyList(),
    val loading: Boolean = true,
    val stale: Boolean = false,
    val error: String? = null,
    val tipInFlight: Boolean = false,
    val tipError: String? = null,
)

@HiltViewModel
class TipsGoalsViewModel @Inject constructor(
    private val repo: TipsRepository,
    private val streamEvents: StreamEventBus,   // from AND-281
    savedState: SavedStateHandle,
) : ViewModel() {
    private val channelId: String = checkNotNull(savedState["channelId"])
    val uiState: StateFlow<TipsGoalsUiState>

    fun onScreenEntered()
    fun submitTip(amount: Long, message: String?)
    fun dismissTipError()
    fun retry()
}
```

`submitTip` mirrors the AND-031 submit handler: validate → set `tipInFlight =
true` → call repo → map `ApiResult` to either close + optimistic update or
`tipError`. SSE `goal_update` events are collected from `streamEvents` and
forwarded to `repo.applyStreamEvent`; `uiState` is built by combining
`observeTipsSummary` + `observeGoals`.

### 4.6 Compose UI (core-ui / feature-stream)

```kotlin
@Composable fun TipsSummaryBar(summary: TipsSummary?, modifier: Modifier)
@Composable fun GoalList(goals: List<Goal>, modifier: Modifier)
@Composable fun GoalRow(goal: Goal)   // LinearProgressIndicator(progress = { goal.fraction })
@Composable fun TipComposerSheet(
    inFlight: Boolean,
    error: String?,
    onSubmit: (amount: Long, message: String?) -> Unit,
    onDismiss: () -> Unit,
)
```

These compose into the AND-281 `StreamScreen`. `TipComposerSheet` is a Material 3
`ModalBottomSheet`.

## 5. API Contract

### 5.1 Submit tip — `POST /ui/chat/tip`

Request:

```json
{ "channel_id": "ch_abc123", "amount": 25, "message": "great stream!" }
```

Headers: cookies (session) + `X-CSRF-Token: <ui_csrf value>`.

Response 200:

```json
{
  "tip": { "id": "tip_001", "amount": 25, "message": "great stream!",
           "created_at": "2026-06-05T18:22:01Z" },
  "summary": { "total_amount": 1275, "tipper_count": 19, "tip_count": 142 },
  "goals": [ { "id": "g1", "title": "New mic", "current_amount": 1275,
               "target_amount": 2000 } ]
}
```

The POST response is authoritative and updates summary + goals immediately.

### 5.2 Tips summary — `GET /ui/chat/tips?channel_id=ch_abc123`

```json
{ "total_amount": 1250, "tipper_count": 18, "tip_count": 141 }
```

### 5.3 Goals — `GET /ui/chat/goals?channel_id=ch_abc123`

```json
{ "goals": [ { "id": "g1", "title": "New mic",
               "current_amount": 1250, "target_amount": 2000 } ] }
```

### 5.4 SSE goal/tip events (consumed via AND-281 `/ui/chat/stream`)

```
event: goal_update
data: {"goal":{"id":"g1","current_amount":1300,"target_amount":2000}}

event: tip
data: {"tip":{"id":"tip_002","amount":50,"message":null},
       "summary":{"total_amount":1300,"tipper_count":20,"tip_count":143}}
```

Field names are confirmed against `/openapi.json` and `frontend/src/api/types.ts`
during implementation; exact paths verified before merge (see Open Questions).

### 5.5 Error shape (FastAPI `detail`)

`detail` may be a string, `[{"msg": "...", "loc": [...]}]`, or
`{"code": "...", ...}`. Map via the shared `core-network` error mapper to a
single user string. Example 422:

```json
{ "detail": [ { "msg": "amount must be positive", "loc": ["body","amount"] } ] }
```

## 6. Data & State Management

- Source of truth: `TipsRepositoryImpl` `MutableStateFlow<TipsSummary?>` and
  `MutableStateFlow<List<Goal>>`, keyed to the single active channel.
- No persistence: tips/goals are session-ephemeral, so no Room table and no
  DataStore key are added. (DataStore is unaffected.)
- Reconciliation order of precedence: SSE event > POST response > GET refresh.
  All writers funnel through repo merge functions that key goals by `id` and
  take the newest `current_amount`.
- Optimistic update: on local submit, `total_amount`, `tip_count` and matching
  goal `current_amount` increment immediately; the POST response (5.1) then
  overwrites with server values. If the POST fails, the optimistic delta is
  rolled back.
- `uiState` derived with `combine(summaryFlow, goalsFlow, loadingFlow,
  errorFlow)` and exposed via `stateIn(viewModelScope, WhileSubscribed(5_000),
  TipsGoalsUiState())`.

## 7. Error Handling & Resilience

- All API calls return `ApiResult<T>` (`Success`/`Error(message, cause)`).
- Dev host is unreliable: GETs (`/ui/chat/tips`, `/ui/chat/goals`) use a ~20s
  call timeout and bounded exponential backoff (max 3 attempts) since they are
  idempotent. The tip POST is **not** retried automatically (non-idempotent;
  could double-tip) — failures surface for explicit user retry.
- On `401`, the shared `core-network` authenticator performs `POST
  /ui/session/refresh` once and replays the request; a second 401 propagates as
  an auth error that bubbles to the session/login flow.
- Offline / load failure: `uiState.error` set, a retry control shown; existing
  optimistic/cached values remain visible with `stale = true` once the goal
  cache TTL (30s without an SSE event) elapses.
- SSE drop is owned by AND-281's reconnect logic; on reconnect this feature
  triggers `repo.refresh(channelId)` to resync goals/summary.

## 8. Security & Privacy

- Mutating `POST /ui/chat/tip` MUST include `X-CSRF-Token` echoed from the
  `ui_csrf` cookie; requests without it are rejected by the backend.
- Session rides on the persistent cookie jar from `core-network`; no tokens are
  stored by this feature.
- Plaintext HTTP is a dev-host limitation only. The OkHttp client permits
  cleartext **only** for the dev base URL via a network-security-config domain
  allowlist (owned by core-network); release builds must not allow cleartext to
  arbitrary hosts.
- No PII is collected by this feature beyond the optional tip `message`, which
  is user-authored. Tip messages are not logged.
- Tip amounts are abstract units on the dev backend; no payment credentials are
  handled in this ticket.

## 9. Accessibility & i18n

- All amounts/counts formatted via `core-ui` locale-aware formatters
  (`NumberFormat`); no hardcoded grouping separators.
- All strings in `strings.xml` with plurals for "tips"/"tippers" via
  `<plurals>`; quantity-aware `pluralStringResource`.
- `GoalRow` progress exposes a `contentDescription`/`stateDescription` such as
  "New mic goal, 62 percent, 1,250 of 2,000". `LinearProgressIndicator` carries
  the semantic progress value.
- Tip button and quick-amount chips have content descriptions; composer sheet
  is reachable and dismissible by TalkBack; min touch target 48dp.
- Color is not the sole signal for "Reached!" — an icon + text label accompany
  the color change. Contrast meets WCAG AA.

## 10. Telemetry & Logging

- Analytics events (via `core-data` analytics interface): `tip_composer_open`,
  `tip_submit_attempt {amount_bucket}`, `tip_submit_success`,
  `tip_submit_error {reason}`, `goal_reached {goal_id}`.
- `amount` is bucketed (e.g. 1-9 / 10-49 / 50+) in analytics — raw amounts and
  message text are never sent to analytics or logs.
- Diagnostic logging via Timber at `debug` for SSE goal/tip event application
  and refresh outcomes; no PII; disabled in release except warn/error.

## 11. Testing Strategy

Unit (core-testing, `kotlinx-coroutines-test` + Turbine):

- `TipsGoalsViewModelTest`: validation disables submit for empty/0/negative;
  `tipInFlight` toggles around the call; success closes composer + optimistic
  update; error sets `tipError` and preserves entered amount; SSE `goal_update`
  updates `goals`; `goal_reached` analytics fires once on crossing target.
- `TipsRepositoryImplTest`: merge precedence (SSE > POST > GET); optimistic
  rollback on POST failure; goal keyed by `id`.
- Error-mapper tests for the three `detail` shapes.

Network (MockWebServer in core-network):

- `TipsApiTest`: request body/headers (`X-CSRF-Token` present), JSON
  serialization round-trips, 200/422/401 handling, GET backoff on 503, POST
  not retried.

UI (Compose test):

- `TipComposerSheetTest`: button disabled states, spinner during in-flight,
  error text rendering.
- `GoalRowTest`: progress fraction, "Reached!" state, semantics/content
  descriptions.

Acceptance verification maps to Section 14.

## 12. Dependencies & Sequencing

- **Depends on AND-281 (Live chat):** required — provides `StreamScreen`,
  `StreamViewModel`/scope, the SSE `/ui/chat/stream` connection and event bus,
  and the chat list where tip messages appear. This ticket cannot land before
  AND-281's stream + event bus exist.
- **Depends on AND-031 (LoginViewModel):** pattern dependency — supplies the
  established `StateFlow<UiState>` + submit-handler + result-mapping convention
  reused by `TipsGoalsViewModel`, and a finalized authenticated session is a
  precondition for reaching this screen.
- Transitively relies on `core-network` (cookie jar, CSRF, refresh-on-401,
  `ApiResult`) and `core-ui` formatters/components.
- Blocks: none currently.
- Build order: AND-281 stream/event bus → this ticket's repo/API → ViewModel →
  UI integration into `StreamScreen`.

## 13. Risks & Open Questions

- R1: Exact dev-backend paths/field names for tip/tips/goals are assumed
  (`/ui/chat/tip`, `/ui/chat/tips`, `/ui/chat/goals`). **Open:** confirm against
  `/openapi.json` and `frontend/src/api/types.ts` before implementation; adjust
  DTOs accordingly.
- R2: SSE event names (`goal_update`, `tip`) and payload nesting depend on
  AND-281's decoder. **Open:** align on the shared `StreamEvent` sealed type.
- R3: Double-tip risk if the client retries the POST. Mitigation: no auto-retry;
  consider a client-generated idempotency key if the backend supports one
  (**open question** for backend).
- R4: Unreliable host may make optimistic vs. authoritative reconciliation flap.
  Mitigation: strict precedence ordering and goal-keyed merges.
- R5: Multiple concurrent goals' ordering is unspecified. Assume server order;
  confirm with backend.

## 14. Acceptance Criteria

AC-1 (from backlog: "Tip submits"): With a finalized session, entering a valid
amount and tapping submit issues `POST /ui/chat/tip` with cookies +
`X-CSRF-Token`; on 200 the composer closes and the tips summary increments.
Covered by `TipsApiTest` + `TipsGoalsViewModelTest`.

AC-2 (from backlog: "goal progress shows"): Goals render with title, current /
target, a determinate progress bar and percentage; crossing the target shows
"Reached!". Covered by `GoalRowTest`.

AC-3: Goal progress updates live from an SSE `goal_update` event with no manual
refresh. Covered by `TipsGoalsViewModelTest`.

AC-4: Submit button is disabled and shows a spinner while in flight, and is
disabled for empty/≤0/non-numeric amounts. Covered by `TipComposerSheetTest`.

AC-5: A failed tip submit shows a readable error, keeps the entered amount, and
does not auto-retry. Covered by `TipsGoalsViewModelTest` + `TipsApiTest`.

AC-6: On a 401, the client refreshes the session once and replays the request;
a second 401 surfaces as an auth error. Covered by `TipsApiTest`.

AC-7: GETs time out at ~20s and back off (≤3 tries); the screen shows a retry
control and `stale` state on failure. Covered by `TipsApiTest` +
`TipsRepositoryImplTest`.

## 15. Definition of Done

- All Section 14 acceptance criteria pass in CI.
- Code merged to `android-port` under `com.testlogon.android`, in
  `feature-stream/tips`, `core-network`, `core-data`, `core-model` per layering.
- Unit, network (MockWebServer), and Compose UI tests added and green; overall
  module coverage not reduced.
- No new lint/detekt errors; ktlint clean; `assembleDebug` + `testDebugUnitTest`
  green on JDK 17 / Gradle 8.9 / AGP 8.7.3.
- Strings externalized with plurals; TalkBack pass on composer + goal rows.
- No raw tip amounts or message text in logs/analytics; CSRF header verified on
  the POST.
- Assumed endpoint paths/field names reconciled against `/openapi.json`; any
  deltas reflected in DTOs and this spec updated.
- Integrated into the AND-281 `StreamScreen` and manually verified end-to-end
  against the dev backend (tip submit + live goal update).
