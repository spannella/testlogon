---
id: AND-282
title: Tips & goals
milestone: M6
epic: E38
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-281, AND-031]
blocks: []
---

# AND-282 — Tips & goals

## 1. Overview & Goal

This ticket adds a tipping experience and a goal-progress display to the live
stream/chat surface delivered by AND-281 (Live chat). A viewer can send a tip
to the broadcaster via the `POST /broadcast/sessions/{session_id}/chat/tip`
endpoint (CORRECTED: the spec previously referenced `chat/tip` / `/ui/chat/tip`,
which does not exist — see §16), the running tip total for the session is
summarized inline, and any active broadcaster goals render their progress
(current amount vs. target, percentage, completion state).

> NOTE (correction): tip amounts are denominated in **cents** (`amount_cents`,
> backend min 100 / max 100000), not abstract units, and the backend REQUIRES a
> `payment_method_id` on every tip. This materially changes the composer and the
> "no payment credentials" claim that appeared in earlier drafts — see §8 and §16.

The goal is a production-quality, testable feature slice that:

- Lets an authenticated, finalized session submit a tip of a chosen amount.
- Reflects the new tip optimistically and then reconciles with the server's
  authoritative tips summary.
- Renders one or more goals with live progress that updates as tips arrive,
  including over the AND-281 SSE chat/event stream.
- Degrades gracefully when the unreliable dev backend is slow, offline, or
  returns stale data.

Non-goals: adding/managing payment methods (the tip flow selects an existing
`payment_method_id` fetched from `GET /ui/billing/payment-methods`; method
authoring is out of scope), tip leaderboards (the backend does expose
`top_tippers`/`recent_tips` in the summary but rendering a leaderboard is not in
this slice), and goal authoring/editing (broadcaster-side: `POST/DELETE
/broadcast/sessions/{session_id}/goals`, out of scope for the viewer app).

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
- Auth is established before this screen is reachable:
  `POST /ui/session/start` → MFA → `POST /ui/session/finalize` → `GET /ui/me`.
  CORRECTION: the web client (`src/api/client.ts`) is not purely cookie-based —
  every request sends `credentials: "include"` (cookie jar) AND, when present, an
  `Authorization: Bearer <accessToken>` header from the auth store AND
  `X-CSRF-Token` (from the `ui_csrf` cookie). The `/broadcast/...` endpoints also
  accept an `X-SESSION-ID` header/param (and `X-IMPERSONATION-TOKEN` for admin
  impersonation). `core-network` must therefore attach cookies, the CSRF header,
  and the bearer token (and `X-SESSION-ID` where the transport expects it); tip
  submission is a mutating POST and MUST carry the CSRF header.

Upstream tickets:

- **AND-281 (Live chat, P0)** — owns the `StreamScreen`, the chat SSE stream
  (CORRECTED: actual path `GET /broadcast/sessions/{session_id}/chat/stream`,
  consumed via `EventSource` with `?poll_ms=500`, NOT `/ui/chat/stream`), the
  send path, and the shared `StreamViewModel`/scope. This ticket plugs into that
  ViewModel. IMPORTANT (corrected): the web stream emits named events
  `chat:message`, `chat:delete`, `chat:reaction`, `chat:unlock`, `chat:lottery`
  — there is **no `goal_update` and no `tip` event**. A tip arrives as a
  `chat:message` carrying `tip_amount_cents`/`tip_total_cents`; goal progress is
  not pushed over SSE in the web client (it is refetched via query invalidation).
  See §5.4 and §16.
- **AND-031 (LoginViewModel, P0)** — establishes the `StateFlow<UiState>` +
  submit-handler + result-mapping pattern reused verbatim here.

## 3. Functional Requirements

FR-1. The stream screen shows a **tips summary** band: session tip total and
tip count, e.g. "$12.50 · 141 tips". CORRECTED: the summary DTO
(`BroadcastTipSummaryOut`) has `total_cents` and `tip_count` but **no
`tipper_count`** field, so a "18 tippers" style count cannot be derived directly
(only `top_tippers.length` is available, which is a truncated top-N list, not the
distinct tipper count). Display total (formatted from cents) and tip count.

FR-2. A **Tip** affordance (button) opens a tip composer (bottom sheet) where
the user selects/enters an amount, selects a **payment method**, and optionally a
short message. CORRECTED: message field is `text` with backend `maxLength` 280
(not ≤140). Quick-amount chips reflect the web presets (CORRECTED: $1 / $5 / $10
/ $25 i.e. 100 / 500 / 1000 / 2500 cents) plus a free-entry field. Amount is
validated against the session's `tip_min_cents`/`tip_max_cents` (web) and the
backend's hard bounds (min 100, max 100000 cents). A payment method is REQUIRED;
if the user has none, surface a "no payment methods — add one in Billing" empty
state and disable submit (payment-method management is out of scope, FR none).

FR-3. Submitting a tip calls `POST /broadcast/sessions/{session_id}/chat/tip`
with body `{ amount_cents, payment_method_id, text?, currency? }`. CORRECTED: on
success the backend returns **201** with a `BroadcastChatMessageOut` (the tip
rendered as a chat message), NOT a `{tip, summary, goals}` object. The composer
closes; the tip message arrives in the chat list owned by AND-281 (via the
`chat:message` SSE event); the tips summary and goals are refreshed by re-GETting
the summary/goals endpoints (web invalidates the `["broadcast","tips"]` query).

FR-4. The submit button is disabled while a request is in flight and when the
amount is empty/≤0/non-numeric; a spinner shows on the button during the call.

FR-5. **Goals** render as a list (commonly one active goal) showing the goal
`label` (CORRECTED: field is `label`, not `title`), `current_cents` /
`target_cents` (formatted from cents), a determinate progress bar, percentage,
and a "Reached!" state driven by the server `reached` flag (the web app keys off
`goal.reached`; client-side `current >= target` is only a fallback). Goals are
ordered by `sort_order`.

FR-6. Goal progress updates after tips arrive. CORRECTED: there is **no
`goal_update` SSE event** in the reference contract. The web client refreshes
goals/summary by re-GETting after a successful tip and on a `chat:message` SSE
event. This ticket SHOULD therefore: (a) re-fetch `GET .../goals` and
`GET .../tips/summary` on tip success and when a `chat:message` event indicating
a tip arrives over the AND-281 stream; and (b) run a bounded background refresh
on a TTL so the display does not go stale if no event arrives. (An optimistic
local bump of goal `current_cents` is allowed but the GET is authoritative.)

FR-7. On entering the screen, goals (`GET /broadcast/sessions/{session_id}/goals`)
and tips summary (`GET /broadcast/sessions/{session_id}/tips/summary`) load once
(idempotent GETs) in parallel with the chat history load from AND-281.

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

CORRECTED to match `BroadcastTipSummaryOut` / `BroadcastTipGoalOut` /
`BroadcastChatMessageOut`. All amounts are integer **cents**; timestamps are
epoch integers (seconds), not ISO-8601 strings.

```kotlin
data class TipsSummary(
    val sessionId: String,
    val totalCents: Long,      // BroadcastTipSummaryOut.total_cents
    val tipCount: Int,         // BroadcastTipSummaryOut.tip_count
    val currency: String = "USD",
    // top_tippers / recent_tips available but not rendered in this slice.
    // NOTE: there is NO distinct-tipper count field in the API.
)

data class Goal(
    val goalId: String,        // BroadcastTipGoalOut.goal_id
    val sessionId: String,
    val label: String,         // .label  (was incorrectly "title")
    val currentCents: Long,    // .current_cents
    val targetCents: Long,     // .target_cents
    val reached: Boolean,      // server-authoritative .reached
    val reachedAt: Long?,      // .reached_at (epoch seconds, nullable)
    val sortOrder: Int,        // .sort_order
) {
    val fraction: Float get() =
        if (targetCents <= 0) 0f
        else (currentCents.toFloat() / targetCents).coerceIn(0f, 1f)
    // Prefer the server flag; fall back to local comparison only if absent.
    val isReached: Boolean get() = reached || (currentCents >= targetCents && targetCents > 0)
}

// A submitted tip is returned as a chat message (BroadcastChatMessageOut),
// not a dedicated Tip object.
data class TipMessage(
    val messageId: String,         // .message_id
    val tipAmountCents: Long?,     // .tip_amount_cents
    val tipCurrency: String?,      // .tip_currency
    val text: String?,             // .text (nullable)
    val createdAt: Long,           // .created_at (epoch seconds)
)
```

### 4.3 Retrofit API (core-network)

CORRECTED: paths are `/broadcast/sessions/{session_id}/...`, the session is a
**path** parameter (not a `channel_id` query), the request DTO is
`BroadcastChatTipIn` (`amount_cents`, `payment_method_id`, optional `text`,
optional `currency`), the tip response is `BroadcastChatMessageOut` (HTTP 201),
the summary is `BroadcastTipSummaryOut`, and goals is `BroadcastTipGoalsListOut`
(`{ session_id, goals: [...] }`).

```kotlin
interface TipsApi {
    @POST("broadcast/sessions/{sessionId}/chat/tip")
    suspend fun submitTip(
        @Path("sessionId") sessionId: String,
        @Body body: BroadcastChatTipInDto,   // amount_cents, payment_method_id, text?, currency?
    ): BroadcastChatMessageDto              // 201

    @GET("broadcast/sessions/{sessionId}/tips/summary")
    suspend fun getTipsSummary(
        @Path("sessionId") sessionId: String,
        @Query("top_limit") topLimit: Int? = null,
        @Query("recent_limit") recentLimit: Int? = null,
    ): BroadcastTipSummaryDto

    @GET("broadcast/sessions/{sessionId}/goals")
    suspend fun getGoals(
        @Path("sessionId") sessionId: String,
    ): BroadcastTipGoalsListDto
}
```

NOTE: the backend declares `X-SESSION-ID` (and `X-IMPERSONATION-TOKEN`) among
these endpoints' params; `core-network` attaches `X-SESSION-ID` where the
transport expects it. There is no `channel_id` concept — use the broadcast
`session_id` everywhere this spec previously said `channelId`/`channel_id`.

The CSRF header and cookies are attached by the shared OkHttp interceptor/cookie
jar from `core-network`; do not re-implement them here.

### 4.4 Repository (core-data)

```kotlin
interface TipsRepository {
    fun observeTipsSummary(sessionId: String): Flow<TipsSummary>
    fun observeGoals(sessionId: String): Flow<List<Goal>>
    suspend fun refresh(sessionId: String): ApiResult<Unit>   // re-GET summary + goals
    suspend fun submitTip(
        sessionId: String,
        amountCents: Long,
        paymentMethodId: String,   // REQUIRED by backend
        text: String?,
        currency: String = "USD",
    ): ApiResult<TipMessage>
    /**
     * Apply a chat:message event (decoded by AND-281) that represents a tip
     * (carries tip_amount_cents/tip_total_cents). CORRECTED: there is no
     * goal_update / tip event; tips arrive as chat:message. Goal/summary
     * reconciliation is done by triggering refresh(), since SSE does not push
     * goal progress.
     */
    fun onTipChatMessage(message: TipMessage)
}
```

`TipsRepositoryImpl` holds in-memory `MutableStateFlow`s for the current
session's summary and goals (single live session at a time; no Room cache
needed — tips/goals are session-scoped and ephemeral). On `submitTip` success it
may optimistically bump the summary/goals, then calls `refresh()` because the
201 response is a chat message, not a summary/goals snapshot. On a tip
`chat:message` from AND-281 it likewise triggers `refresh()` (the SSE event does
not carry goal progress).

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
    private val sessionId: String = checkNotNull(savedState["sessionId"])
    val uiState: StateFlow<TipsGoalsUiState>

    fun onScreenEntered()
    fun submitTip(amountCents: Long, paymentMethodId: String, text: String?)
    fun dismissTipError()
    fun retry()
}
```

`submitTip` mirrors the AND-031 submit handler: validate (amount within
`[tip_min_cents, tip_max_cents]` ∩ backend `[100, 100000]`; `paymentMethodId`
non-empty) → set `tipInFlight = true` → call repo → map `ApiResult` to either
close + refresh or `tipError`. CORRECTED: `streamEvents` are filtered for
tip-bearing `chat:message` events (not `goal_update`) and forwarded to
`repo.onTipChatMessage`, which triggers a goals/summary refresh; `uiState` is
built by combining `observeTipsSummary` + `observeGoals`.

### 4.6 Compose UI (core-ui / feature-stream)

```kotlin
@Composable fun TipsSummaryBar(summary: TipsSummary?, modifier: Modifier)
@Composable fun GoalList(goals: List<Goal>, modifier: Modifier)
@Composable fun GoalRow(goal: Goal)   // LinearProgressIndicator(progress = { goal.fraction })
@Composable fun TipComposerSheet(
    inFlight: Boolean,
    error: String?,
    minCents: Long,
    maxCents: Long,
    paymentMethods: List<PaymentMethod>,   // from GET /ui/billing/payment-methods
    onSubmit: (amountCents: Long, paymentMethodId: String, text: String?) -> Unit,
    onDismiss: () -> Unit,
)
```

CORRECTED: the composer must collect a `payment_method_id` (required) and
present amounts in dollars while submitting cents; presets are 100/500/1000/2500
cents. Submit is disabled unless an amount within bounds AND a payment method are
selected.

These compose into the AND-281 `StreamScreen`. `TipComposerSheet` is a Material 3
`ModalBottomSheet`.

## 5. API Contract

All shapes below are VERIFIED against the OpenAPI spec (`components.schemas.*`)
and `frontend/src/api/endpoints/broadcast-tips.ts` / `broadcast.ts`. The prior
draft of this section was largely fabricated and has been replaced.

### 5.1 Submit tip — `POST /broadcast/sessions/{session_id}/chat/tip`

Request (`BroadcastChatTipIn`):

```json
{ "amount_cents": 2500, "payment_method_id": "pm_abc123",
  "text": "great stream!", "currency": "USD" }
```

- `amount_cents` (int, REQUIRED): min 100, max 100000.
- `payment_method_id` (string, REQUIRED): 1–200 chars.
- `text` (string, optional, default ""): max 280 chars.
- `currency` (string, optional, default "USD"): pattern `^[A-Z]{3}$`.

Headers: cookies (session) + `X-CSRF-Token: <ui_csrf value>` + (when present)
`Authorization: Bearer <token>` + `X-SESSION-ID`.

Response **201** (`BroadcastChatMessageOut`) — the tip rendered as a chat
message, NOT a summary/goals snapshot:

```json
{
  "message_id": "msg_001", "session_id": "sess_abc", "sender_id": "u1",
  "sender_display_name": "Alice", "text": "great stream!", "kind": "tip",
  "created_at": 1749146521, "deleted": false,
  "tip_amount_cents": 2500, "tip_currency": "USD", "tip_total_cents": 127500
}
```

The summary and goals are NOT in this response; refresh them via 5.2/5.3.

### 5.2 Tips summary — `GET /broadcast/sessions/{session_id}/tips/summary`

Optional query params: `top_limit`, `recent_limit`. Response
(`BroadcastTipSummaryOut`):

```json
{
  "session_id": "sess_abc", "total_cents": 125000, "tip_count": 141,
  "currency": "USD",
  "top_tippers": [ { "user_id": "u1", "display_name": "Alice",
                     "total_cents": 5000, "tip_count": 4 } ],
  "recent_tips": [ /* BroadcastRecentTipItem[] */ ]
}
```

Note: only `session_id` is required; `total_cents`/`tip_count` default to 0.
There is **no `tipper_count`** field (see FR-1).

### 5.3 Goals — `GET /broadcast/sessions/{session_id}/goals`

Response (`BroadcastTipGoalsListOut`):

```json
{ "session_id": "sess_abc",
  "goals": [ { "goal_id": "g1", "session_id": "sess_abc", "label": "New mic",
               "current_cents": 125000, "target_cents": 200000,
               "reached": false, "reached_at": null, "sort_order": 0,
               "created_at": 1749100000 } ] }
```

Required goal fields: `goal_id`, `session_id`, `label`, `target_cents`,
`created_at`. `current_cents`/`reached`/`sort_order` default; `reached_at` is
nullable.

### 5.4 SSE events (consumed via AND-281 `/broadcast/sessions/{session_id}/chat/stream`)

CORRECTED: the reference web client (`src/pages/broadcast/BroadcastChat.tsx`)
opens an `EventSource` at `/broadcast/sessions/{session_id}/chat/stream?poll_ms=500`
and listens for these NAMED events only — there is **no `goal_update` and no
`tip` event**:

```
event: chat:message     # a new chat message; a tip is one of these (kind="tip")
event: chat:delete      # {"message_id": "..."}
event: chat:reaction    # {"message_id": "...", "counts": {...}}
event: chat:unlock      # {"message_id": "...", "text": "..."}
event: chat:lottery     # a ChatMessage for lottery
```

A tip event is delivered as `event: chat:message` whose data is a
`BroadcastChatMessageOut` carrying `tip_amount_cents`/`tip_total_cents`. Goal
progress is NOT pushed; the web client re-fetches goals/summary after tips. This
ticket consumes the tip-bearing `chat:message` from AND-281 and triggers a
goals/summary refresh. Reconnect uses exponential backoff capped at 15s (owned
by AND-281).

### 5.5 Error shape (FastAPI `detail`)

VERIFIED: FastAPI returns 422 as `HTTPValidationError` = `{ "detail":
[ ValidationError ] }`, where each `ValidationError` has required fields `loc`
(array), `msg` (string), and `type` (string). In practice `detail` may also be a
plain string for non-validation 4xx (the web client's `normalizeErrorDetail`
handles both). Map via the shared `core-network` error mapper to a single user
string. Example 422 for an out-of-range amount:

```json
{ "detail": [ { "type": "greater_than_equal",
                "loc": ["body", "amount_cents"],
                "msg": "Input should be greater than or equal to 100" } ] }
```

NOTE: `BroadcastChatTipIn` enforces `amount_cents` ∈ [100, 100000] and
`payment_method_id` length 1–200 at the schema level, so client-side validation
should mirror these to avoid round-trips.

## 6. Data & State Management

- Source of truth: `TipsRepositoryImpl` `MutableStateFlow<TipsSummary?>` and
  `MutableStateFlow<List<Goal>>`, keyed to the single active broadcast
  `session_id`.
- No persistence: tips/goals are session-ephemeral, so no Room table and no
  DataStore key are added. (DataStore is unaffected.)
- Reconciliation order of precedence (CORRECTED — the POST response is a chat
  message, not a summary/goals snapshot, and SSE does not push goal progress):
  **GET refresh > optimistic local bump**. A successful tip POST and a
  tip-bearing `chat:message` SSE event are both treated as *signals to refresh*,
  after which the authoritative GET result wins. All writers funnel through repo
  merge functions that key goals by `goal_id`, take the newest `current_cents`,
  and respect the server `reached` flag.
- Optimistic update: on local submit, `total_cents`, `tip_count` and the matching
  goal `current_cents` may be incremented immediately for responsiveness; the
  subsequent GET refresh then overwrites with server values. If the POST fails,
  the optimistic delta is rolled back.
- `uiState` derived with `combine(summaryFlow, goalsFlow, loadingFlow,
  errorFlow)` and exposed via `stateIn(viewModelScope, WhileSubscribed(5_000),
  TipsGoalsUiState())`.

## 7. Error Handling & Resilience

- All API calls return `ApiResult<T>` (`Success`/`Error(message, cause)`).
- Dev host is unreliable: GETs (`/broadcast/sessions/{session_id}/tips/summary`,
  `/broadcast/sessions/{session_id}/goals`) use a ~20s call timeout and bounded
  exponential backoff (max 3 attempts) since they are idempotent. The tip POST
  (`/broadcast/sessions/{session_id}/chat/tip`) is **not** retried automatically
  (non-idempotent; would double-charge the payment method) — failures surface for
  explicit user retry.
- On `401`, the shared `core-network` authenticator performs `POST
  /ui/session/refresh` once and replays the request; a second 401 propagates as
  an auth error that bubbles to the session/login flow.
- Offline / load failure: `uiState.error` set, a retry control shown; existing
  optimistic/cached values remain visible with `stale = true` once the goal
  cache TTL (30s without an SSE event) elapses.
- SSE drop is owned by AND-281's reconnect logic (VERIFIED: web uses exponential
  backoff `min(1000 * 2^retry, 15000)` ms); on reconnect this feature triggers
  `repo.refresh(sessionId)` to resync goals/summary.

## 8. Security & Privacy

- Mutating `POST /ui/chat/tip` MUST include `X-CSRF-Token` echoed from the
  `ui_csrf` cookie; requests without it are rejected by the backend.
- Session rides on the persistent cookie jar from `core-network`; no tokens are
  stored by this feature.
- Plaintext HTTP is a dev-host limitation only. The OkHttp client permits
  cleartext **only** for the dev base URL via a network-security-config domain
  allowlist (owned by core-network); release builds must not allow cleartext to
  arbitrary hosts.
- No PII is collected by this feature beyond the optional tip `text`, which
  is user-authored. Tip messages are not logged.
- CORRECTED: tip amounts are real currency in **cents**, and a tip REQUIRES a
  `payment_method_id`. This ticket does NOT capture or store raw payment
  credentials — it only references an existing tokenized `payment_method_id`
  fetched from `GET /ui/billing/payment-methods`. The `payment_method_id` must be
  treated as sensitive: never logged and not sent to analytics.

## 9. Accessibility & i18n

- All amounts are stored in cents and formatted via `core-ui` locale- and
  currency-aware formatters (`NumberFormat.getCurrencyInstance`, using the
  summary/tip `currency`); no hardcoded grouping separators or `$` symbols.
- All strings in `strings.xml` with plurals for "tips"/"tippers" via
  `<plurals>`; quantity-aware `pluralStringResource`.
- `GoalRow` progress exposes a `contentDescription`/`stateDescription` such as
  "New mic goal, 62 percent, $1,250.00 of $2,000.00 reached".
  `LinearProgressIndicator` carries the semantic progress value
  (`progress = { goal.fraction }`).
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

- `TipsGoalsViewModelTest`: validation disables submit for empty/0/negative,
  below `min_cents` or above `max_cents`, or with no `payment_method_id`;
  `tipInFlight` toggles around the call; success closes composer + triggers
  refresh; error sets `tipError` and preserves entered amount; a tip-bearing
  `chat:message` SSE event triggers a goals/summary refresh that updates `goals`;
  `goal_reached` analytics fires once on the server `reached` flag flipping true.
- `TipsRepositoryImplTest`: refresh-wins precedence (GET overwrites optimistic);
  optimistic rollback on POST failure; goal keyed by `goal_id`; respects server
  `reached`.
- Error-mapper tests for the three `detail` shapes.

Network (MockWebServer in core-network):

- `TipsApiTest`: request body (`amount_cents`/`payment_method_id`/`text`) and
  headers (`X-CSRF-Token` present), JSON serialization round-trips, 201 tip /
  422 / 401 handling, GET backoff on 503, POST not retried.

UI (Compose test):

- `TipComposerSheetTest`: button disabled states, spinner during in-flight,
  error text rendering.
- `GoalRowTest`: progress fraction, "Reached!" state, semantics/content
  descriptions.

Acceptance verification maps to Section 14.

## 12. Dependencies & Sequencing

- **Depends on AND-281 (Live chat):** required — provides `StreamScreen`,
  `StreamViewModel`/scope, the SSE `/ui/chat/stream` connection and event bus,
  and the chat list where tip messages appear. CORRECTED: the SSE stream is
  `/broadcast/sessions/{session_id}/chat/stream` (named events `chat:*`), not
  `/ui/chat/stream`. This ticket cannot land before AND-281's stream + event bus
  exist.
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

- R1: RESOLVED (this review). Paths/fields are now verified against
  `/openapi.json` and the frontend: `POST/GET` under
  `/broadcast/sessions/{session_id}/...` with cents-denominated fields and a
  required `payment_method_id`. The previously assumed `/ui/chat/*` paths do not
  exist. DTOs updated in §4–§5.
- R2: RESOLVED (this review). SSE event names are `chat:message` / `chat:delete`
  / `chat:reaction` / `chat:unlock` / `chat:lottery`; there is NO `goal_update`
  or `tip` event. Tips arrive as `chat:message`; goal progress is obtained by
  re-GET, not pushed. Align the shared `StreamEvent` sealed type on the `chat:*`
  names. **Open (minor):** whether the dev backend emits any goal-specific event
  not used by the web client — none found in the OpenAPI (the stream endpoint has
  no declared response schema). Treat refresh-on-tip as the contract.
- R3: Double-charge risk if the client retries the POST (real money). Mitigation:
  no auto-retry. VERIFIED: `BroadcastChatTipIn` has NO idempotency-key field and
  the endpoint declares no idempotency header, so a client-generated key is not
  currently honored — rely on no-auto-retry + disabling the button in flight.
  **Open question** for backend: add an idempotency key.
- R4: Unreliable host may make optimistic vs. authoritative reconciliation flap.
  Mitigation: strict precedence ordering and goal-keyed merges.
- R5: RESOLVED (this review). `BroadcastTipGoalOut` includes a `sort_order`
  integer; render goals ordered by `sort_order` (then `created_at` as a stable
  tiebreaker).

## 14. Acceptance Criteria

AC-1 (from backlog: "Tip submits"): With a finalized session, entering a valid
`amount_cents` (within bounds), selecting a `payment_method_id`, and tapping
submit issues `POST /broadcast/sessions/{session_id}/chat/tip` with cookies +
`X-CSRF-Token`; on **201** the composer closes and the tips summary increments
after refresh. Covered by `TipsApiTest` + `TipsGoalsViewModelTest`.

AC-2 (from backlog: "goal progress shows"): Goals render with `label`,
current / target (formatted from cents), a determinate progress bar and
percentage; the server `reached` flag shows "Reached!". Covered by `GoalRowTest`.

AC-3: Goal progress updates without manual refresh after a tip — i.e. a
tip-bearing `chat:message` SSE event (or a successful local tip) triggers a
goals/summary re-fetch that updates the display. Covered by
`TipsGoalsViewModelTest`.

AC-4: Submit button is disabled and shows a spinner while in flight, and is
disabled for empty/≤0/non-numeric amounts, amounts outside
`[min_cents, max_cents]`, or when no payment method is selected. Covered by
`TipComposerSheetTest`.

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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **Tip submit endpoint is `POST /broadcast/sessions/{session_id}/chat/tip`.**
   VERDICT: Corrected (spec said `chat/tip` / `/ui/chat/tip`).
   SOURCE: OpenAPI `POST /broadcast/sessions/{session_id}/chat/tip`
   (op `send_tip_message_route...chat_tip_post`); `src/api/endpoints/broadcast-tips.ts: sendBroadcastTip`.
2. **Tip request body is `BroadcastChatTipIn` = `{ amount_cents, payment_method_id, text?, currency? }`; `amount_cents` ∈ [100,100000], `payment_method_id` required (1–200), `text` ≤280, `currency` `^[A-Z]{3}$` default USD.**
   VERDICT: Corrected (spec said `{channel_id, amount, message}`, message ≤140, no payment method).
   SOURCE: OpenAPI `components.schemas.BroadcastChatTipIn`; `src/api/endpoints/broadcast-tips.ts: SendTipIn`.
3. **Tip response is `BroadcastChatMessageOut` at HTTP 201 (a chat message with `tip_amount_cents`/`tip_total_cents`), NOT a `{tip,summary,goals}` object.**
   VERDICT: Corrected.
   SOURCE: OpenAPI `POST .../chat/tip` → `resp=201:BroadcastChatMessageOut`; `components.schemas.BroadcastChatMessageOut`; `src/api/endpoints/broadcast-chat.ts: ChatMessage`.
4. **Tips summary endpoint is `GET /broadcast/sessions/{session_id}/tips/summary` returning `BroadcastTipSummaryOut`.**
   VERDICT: Corrected (spec said `GET /ui/chat/tips?channel_id=`).
   SOURCE: OpenAPI `GET /broadcast/sessions/{session_id}/tips/summary` (op `get_tip_summary_route...`); `src/api/endpoints/broadcast-tips.ts: getTipSummary`.
5. **Summary fields are `session_id, total_cents, tip_count, currency, top_tippers[], recent_tips[]`; there is NO `tipper_count`, NO `total_amount`.**
   VERDICT: Corrected.
   SOURCE: OpenAPI `components.schemas.BroadcastTipSummaryOut`; `src/api/endpoints/broadcast.ts: BroadcastTipSummary`.
6. **Goals endpoint is `GET /broadcast/sessions/{session_id}/goals` returning `BroadcastTipGoalsListOut` = `{ session_id, goals[] }`.**
   VERDICT: Corrected (spec said `GET /ui/chat/goals?channel_id=`).
   SOURCE: OpenAPI `GET /broadcast/sessions/{session_id}/goals` (op `list_tip_goals_route...`); `src/api/endpoints/broadcast-tips.ts: listTipGoals`.
7. **Goal fields are `goal_id, session_id, label, target_cents, current_cents, reached, reached_at, sort_order, created_at`; NOT `id/title/current_amount/target_amount`.**
   VERDICT: Corrected.
   SOURCE: OpenAPI `components.schemas.BroadcastTipGoalOut`; `src/api/endpoints/broadcast.ts: BroadcastTipGoal`; UI uses `goal.reached`/`goal_id`/`label` in `src/pages/broadcast/TipGoalBar.tsx`.
8. **The SSE stream is `GET /broadcast/sessions/{session_id}/chat/stream` (EventSource, `?poll_ms=500`), NOT `/ui/chat/stream`.**
   VERDICT: Corrected.
   SOURCE: OpenAPI `GET /broadcast/sessions/{session_id}/chat/stream` (op `broadcast_chat_stream_route...`, params `after,poll_ms`); `src/pages/broadcast/BroadcastChat.tsx` (EventSource URL).
9. **SSE event names are `chat:message`, `chat:delete`, `chat:reaction`, `chat:unlock`, `chat:lottery`; there is NO `goal_update` and NO `tip` event. Tips arrive as `chat:message`; goal progress is re-fetched, not pushed.**
   VERDICT: Corrected.
   SOURCE: `src/pages/broadcast/BroadcastChat.tsx` (`es.addEventListener(...)` calls); no goal/tip event in OpenAPI (stream endpoint declares no response schema).
10. **Tip presets are 100/500/1000/2500 cents ($1/$5/$10/$25).**
    VERDICT: Corrected (spec said 5/10/25/50/100).
    SOURCE: `src/pages/broadcast/BroadcastTipButton.tsx` (`const PRESETS = [100,500,1000,2500]`).
11. **A `payment_method_id` is required and is selected from existing methods via `GET /ui/billing/payment-methods`; the UI blocks submit when none exist.**
    VERDICT: Corrected (spec claimed no payment credentials handled).
    SOURCE: `src/pages/broadcast/BroadcastTipButton.tsx` (`pmQuery`, `disabled={... || !selectedPmId ...}`); request schema requires `payment_method_id`.
12. **Mutating requests carry `X-CSRF-Token` from the `ui_csrf` cookie.**
    VERDICT: Verified.
    SOURCE: `src/api/client.ts` (`const csrf = getCookie("ui_csrf"); headers.set("X-CSRF-Token", csrf)`).
13. **On 401 the client refreshes via `POST /ui/session/refresh` once and replays; a second 401 logs out.**
    VERDICT: Verified.
    SOURCE: `src/api/client.ts: refreshSession` + the 401 retry block (`retryRes.status === 401 → logout`).
14. **Transport is not purely cookie-based: it also sends `Authorization: Bearer <token>` and supports `X-SESSION-ID` / `X-IMPERSONATION-TOKEN`.**
    VERDICT: Corrected (spec said "Auth is cookie-based").
    SOURCE: `src/api/client.ts` (`Authorization: Bearer`, `X-IMPERSONATION-TOKEN`, `credentials: "include"`); OpenAPI broadcast endpoints list `X-SESSION-ID,X-IMPERSONATION-TOKEN` params.
15. **422 error shape is `HTTPValidationError` = `{ detail: ValidationError[] }`, `ValidationError = { loc, msg, type }`; `detail` may also be a plain string.**
    VERDICT: Corrected/Verified (refined the loose claim).
    SOURCE: OpenAPI `components.schemas.HTTPValidationError` + `ValidationError`; `src/api/client.ts: normalizeErrorDetail`.
16. **SSE reconnect backoff is `min(1000 * 2^retry, 15000)` ms.**
    VERDICT: Verified.
    SOURCE: `src/pages/broadcast/BroadcastChat.tsx: es.onerror`.
17. **Goals are ordered by `sort_order`.**
    VERDICT: Verified (resolves prior open question R5).
    SOURCE: OpenAPI `BroadcastTipGoalOut.sort_order`; `src/api/endpoints/broadcast.ts: BroadcastTipGoal.sort_order`.
18. **No idempotency key on the tip POST.**
    VERDICT: Verified (no such field/header exists).
    SOURCE: OpenAPI `BroadcastChatTipIn` (no idempotency field); `POST .../chat/tip` params do not include one.
19. **Goal-authoring endpoints exist but are out of scope (`POST /broadcast/sessions/{session_id}/goals`, `DELETE .../goals/{goal_id}`).**
    VERDICT: Verified.
    SOURCE: OpenAPI `POST/DELETE /broadcast/sessions/{session_id}/goals[/{goal_id}]`; `src/api/endpoints/broadcast-tips.ts: createTipGoal/deleteTipGoal`.
20. **Android framework choices: Compose Material 3 `ModalBottomSheet`, `LinearProgressIndicator(progress = {…})`, Hilt `@HiltViewModel`, `StateFlow.stateIn(WhileSubscribed)`.**
    VERDICT: Unverified-assumption (framework ref — not derivable from backend/frontend; standard AndroidX APIs).
    SOURCE: framework ref — developer.android.com (Compose Material3 `ModalBottomSheet`, `LinearProgressIndicator`; Hilt; Kotlin Flow `stateIn`).

### Corrections made

- Endpoint paths: `/ui/chat/tip|tips|goals` and `/ui/chat/stream` → the
  `/broadcast/sessions/{session_id}/...` family (claims 1,4,6,8). `channel_id`
  query → `session_id` path param throughout.
- Request body: `{channel_id, amount, message}` → `BroadcastChatTipIn`
  (`amount_cents`, required `payment_method_id`, `text` ≤280, `currency`)
  (claims 2,11).
- Tip response: invented `{tip, summary, goals}` (200) → `BroadcastChatMessageOut`
  (201); summary/goals must be re-fetched (claim 3).
- Money model: "abstract units" → real currency in **cents**; added currency
  formatting and bounds (claims 2,5,7; §1, §4.2, §9).
- Summary/goal DTO fields renamed to real ones; removed fabricated `tipper_count`
  and `total_amount`; goal `title`→`label`, `id`→`goal_id`, amounts→cents, added
  `reached`/`sort_order` (claims 5,7).
- SSE: removed invented `goal_update`/`tip` events; reconciliation reframed as
  refresh-on-tip (claims 8,9; §3 FR-6, §5.4, §6).
- Auth: "cookie-based" → cookies + Bearer + CSRF + `X-SESSION-ID` (claim 14).
- Presets corrected; payment-method requirement threaded through composer,
  validation, security, and ACs (claims 10,11).
- Resolved former open questions R1, R2, R5; refined R3 (no idempotency key).
- Frontmatter `status: reviewed`, `reviewed_on: 2026-06-06`.

### Open assumptions

- (Claim 20) Android UI/architecture framework choices are not derivable from the
  backend/frontend sources; treated as standard AndroidX/Compose/Hilt usage
  (framework ref). Unverifiable against the provided sources by design.
- The broadcast chat-stream endpoint declares **no response schema** in OpenAPI,
  so the exact wire format / event-name set is taken from the web client
  (`BroadcastChat.tsx`). If the dev backend emits a goal-specific event the web
  client ignores, this spec would miss it; mitigated by refresh-on-tip. Verify
  against a live stream during AND-281 integration.
- Distinct-tipper count cannot be shown: no field exists; `top_tippers` is a
  truncated top-N list, not a distinct count. Assumed acceptable to omit.
- `X-SESSION-ID` is listed as a backend param but the web client relies on the
  cookie session; whether the Android client must set it explicitly is an
  integration detail owned by `core-network` (unverified here).

## 17. Test Plan

Test targets: JVM = local JVM/Robolectric (no device); EMU = headless AVD
`test35` (x86_64, API 35); DEVICE = physical Samsung Galaxy A15 5G (SM-A156U,
serial R5CX821TA9R, API 34, arm64-v8a). "Traces" link to §14 acceptance criteria.

- **TC-AND-282-01** — Tip happy path (contract).
  Type: contract/MockWebServer. Target: JVM (`TipsApiTest`).
  Preconditions: MockWebServer enqueues 201 with a `BroadcastChatMessageOut`
  (`tip_amount_cents`, `tip_total_cents`). Steps: call
  `submitTip(sessionId, amount_cents=2500, payment_method_id="pm_1", text="hi")`.
  Expected: request is `POST /broadcast/sessions/{sessionId}/chat/tip`, body has
  `amount_cents=2500`, `payment_method_id="pm_1"`, `text="hi"`; `X-CSRF-Token`
  header present; result is `ApiResult.Success<TipMessage>` mapped from 201.
  Traces: AC-1.

- **TC-AND-282-02** — Load summary + goals (contract).
  Type: contract/MockWebServer. Target: JVM (`TipsApiTest`/`TipsRepositoryImplTest`).
  Preconditions: enqueue 200 `BroadcastTipSummaryOut` and 200
  `BroadcastTipGoalsListOut`. Steps: `getTipsSummary` + `getGoals`. Expected:
  parsed `TipsSummary(totalCents, tipCount, currency)` and
  `List<Goal>` with `goalId/label/currentCents/targetCents/reached/sortOrder`;
  goals sorted by `sortOrder`. Traces: AC-2.

- **TC-AND-282-03** — Validation blocks submit (unit/UI).
  Type: unit + Compose-UI. Target: JVM/Robolectric
  (`TipsGoalsViewModelTest`, `TipComposerSheetTest`). Preconditions:
  min=100,max=100000. Steps: try amounts "", "0", "-5", "abc", 99, 100001; and a
  valid 500 with NO payment method. Expected: submit disabled in every case;
  enabled only with in-bounds amount AND a selected `payment_method_id`. Traces:
  AC-4.

- **TC-AND-282-04** — In-flight spinner + disabled (Compose-UI).
  Type: Compose-UI. Target: EMU (`TipComposerSheetTest`). Preconditions: composer
  open, valid amount + PM. Steps: trigger submit with a suspended/slow repo.
  Expected: button shows spinner, is disabled during flight; on success composer
  dismisses. Traces: AC-1, AC-4.

- **TC-AND-282-05** — Goal row rendering + Reached state (Compose-UI).
  Type: Compose-UI. Target: EMU (`GoalRowTest`). Preconditions: goals
  current=125000/target=200000 (reached=false) and current=200000/target=200000
  (reached=true). Steps: render `GoalRow`. Expected: progress fraction ≈0.625 and
  1.0; percentage text; "Reached!" with icon+text only when server `reached=true`;
  amounts currency-formatted from cents. Traces: AC-2.

- **TC-AND-282-06** — Live update after tip via SSE chat:message (unit).
  Type: unit. Target: JVM (`TipsGoalsViewModelTest`). Preconditions: VM
  subscribed to a fake `StreamEventBus`; repo `refresh` stubbed to return updated
  goal/summary. Steps: emit a `chat:message` event carrying `tip_amount_cents`.
  Expected: VM triggers `repo.refresh`; `uiState.goals`/`summary` reflect the
  refreshed values without manual action; `goal_reached` analytics fires once when
  `reached` flips true. Traces: AC-3.

- **TC-AND-282-07** — Tip POST not retried; error preserves input (unit/contract).
  Type: unit + contract/MockWebServer. Target: JVM
  (`TipsGoalsViewModelTest`+`TipsApiTest`). Preconditions: enqueue a single 503
  (or network failure) for the tip POST. Steps: submit a valid tip. Expected:
  exactly ONE POST is made (no auto-retry); `tipError` set to a readable message;
  entered amount/text retained in composer; optimistic delta rolled back. Traces:
  AC-5.

- **TC-AND-282-08** — 422 validation error mapping (contract).
  Type: contract/MockWebServer. Target: JVM (`TipsApiTest`). Preconditions:
  enqueue 422 `{ "detail": [ { "type":"greater_than_equal",
  "loc":["body","amount_cents"], "msg":"Input should be >= 100" } ] }`. Steps:
  submit. Expected: error mapper yields the `msg` string; surfaced as `tipError`;
  no crash. Traces: AC-5.

- **TC-AND-282-09** — 401 refresh-and-replay (contract).
  Type: contract/MockWebServer. Target: JVM (`TipsApiTest`). Preconditions:
  enqueue 401, then 200 for `POST /ui/session/refresh`, then 201 for the replayed
  tip; second scenario: 401 then refresh fails → second 401. Steps: submit.
  Expected: first scenario replays once and succeeds; second scenario surfaces an
  auth error that bubbles to the session flow (logout). Traces: AC-6.

- **TC-AND-282-10** — Flaky-host GET backoff + stale state (unit/contract).
  Type: unit + contract/MockWebServer. Target: JVM (`TipsRepositoryImplTest`,
  `TipsApiTest`). Preconditions: enqueue 503,503,200 for the summary/goals GET
  with a ~20s call timeout. Steps: `refresh`. Expected: ≤3 attempts with
  exponential backoff, eventual success; on total failure `uiState.error` set,
  retry control shown, prior values kept with `stale=true` after TTL. Traces:
  AC-7.

- **TC-AND-282-11** — Offline / no network (instrumented).
  Type: instrumented/e2e. Target: DEVICE (real airplane-mode toggle). MUST run on
  the physical device (real radio/connectivity transitions, arm64/API-34).
  Preconditions: stream screen open, device put offline. Steps: attempt a tip,
  then re-enable network and retry. Expected: offline submit shows a readable
  network error without crash and keeps input; on reconnect the screen
  `refresh`es summary/goals and a retried tip succeeds. Traces: AC-5, AC-7.

- **TC-AND-282-12** — CSRF header enforced end-to-end (contract/security).
  Type: contract/MockWebServer (security). Target: JVM (`TipsApiTest`).
  Preconditions: `ui_csrf` cookie present in the jar. Steps: submit a tip; also a
  negative case with the cookie absent. Expected: `X-CSRF-Token` is attached when
  the cookie exists; the request never logs the raw `payment_method_id`, tip
  amount, or `text` (assert log/analytics scrubbing). Traces: AC-1.

- **TC-AND-282-13** — Accessibility / TalkBack (instrumented a11y).
  Type: Compose-UI + instrumented. Target: EMU (a11y assertions) with a manual
  TalkBack pass on DEVICE. Preconditions: composer open, one goal at 62%.
  Steps: run accessibility checks; navigate composer + goal row with TalkBack.
  Expected: tip button, quick-amount chips, and PM selector have content
  descriptions; min touch target 48dp; `GoalRow` exposes
  stateDescription "...62 percent, $1,250.00 of $2,000.00..."; "Reached!" conveyed
  by icon+text (not color alone); composer dismissible by TalkBack. Traces: AC-2,
  AC-4.

- **TC-AND-282-14** — Full e2e against dev backend (manual).
  Type: manual e2e. Target: DEVICE (build host adb). MUST run on the physical
  device for realistic end-to-end behavior over the flaky dev host. Preconditions:
  finalized session, at least one payment method, an active goal. Steps: open the
  stream, send a $5 tip with a message, observe chat + summary + goal. Expected:
  201 tip; the tip message appears via `chat:message`; summary `total_cents`/
  `tip_count` and goal `current_cents` increase after refresh; "Reached!" shows
  when target crossed. Traces: AC-1, AC-2, AC-3.

### Coverage matrix

| AC | Covered by |
| --- | --- |
| AC-1 (tip submits, 201 + CSRF) | TC-01, TC-04, TC-12, TC-14 |
| AC-2 (goals render: label/current/target/%/reached) | TC-02, TC-05, TC-13, TC-14 |
| AC-3 (live update after tip, no manual refresh) | TC-06, TC-14 |
| AC-4 (submit disabled/spinner; bounds + PM) | TC-03, TC-04, TC-13 |
| AC-5 (failed submit: readable error, keep input, no auto-retry) | TC-07, TC-08, TC-11 |
| AC-6 (401 refresh-once-and-replay) | TC-09 |
| AC-7 (GET ~20s timeout + ≤3 backoff; retry + stale) | TC-10, TC-11 |
