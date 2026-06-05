---
id: AND-315
title: Tips config & private shows
milestone: M7
epic: E41
priority: P2
size: L
status: draft
depends_on: [AND-282]
blocks: []
---

# AND-315 — Tips config & private shows

## 1. Overview & Goal

This ticket delivers two host-facing broadcast monetization capabilities: **tips configuration** and the **private show / private chat lifecycle**. Tips configuration lets a host set the tipping options exposed to viewers — the suggested tip menu, custom-amount bounds, currency, and goal linkage — building on the viewer-side tipping primitives from AND-282 (`chat/tip`, tips summary, goals display). The private show feature implements the full request → accept → in-progress → end state machine for monetized one-to-one sessions branching off a public broadcast: a viewer requests a private show at a host-defined per-minute rate, the host accepts or declines, both sides enter the session, and either side can end it, producing a billable summary.

The goal is a working, testable private show lifecycle plus a tips-config editor, wired to the FastAPI broadcast endpoints, resilient to the unreliable dev backend, and observing the cookie/CSRF auth model. Success means: a host can save tip settings that persist and re-load; a viewer-initiated request appears to the host in real time, can be accepted/declined, transitions to an active billable session, and can be ended cleanly by either party with the summary surfaced.

## 2. Context & References

- **Repo / module:** `spannella/testlogon`, Android app in `android/`, branch `android-port`. This ticket lives in `feature-broadcast` (host area), consuming `core-network`, `core-model`, `core-ui`, `core-data`.
- **Namespace:** `com.testlogon.android` (e.g. `com.testlogon.android.feature.broadcast.privateshow`).
- **Dependency AND-282 (Tips & goals):** provides `chat/tip` submission, tips summary, and goals display models (`TipMenuItem`, `GoalProgress`, viewer `TipApi`). AND-315 reuses these models and adds the host-side *configuration* of the menu/goals and the private-show flow.
- **Upstream broadcast tickets:** AND-278 (broadcast API DTOs), AND-281 (live chat / SSE channel used to deliver private-show request events), AND-307–AND-313 (host session create, controls, moderation) provide the host session context (`broadcast_id`) this ticket operates within.
- **Web reference:** `frontend/src/api/endpoints/broadcast*.ts` and `frontend/src/api/types.ts` for the request/response shapes; OpenAPI at `http://18.222.237.167:8000/openapi.json` is authoritative for paths and field names — reconcile drift at implementation and record it in section 13.
- **Auth:** Cookie session + `ui_csrf` echoed as `X-CSRF-Token`; on 401 the OkHttp authenticator (AND-013) performs one `POST /ui/session/refresh` then retries. Persistent cookie jar (AND-011) and CSRF interceptor (AND-012) assumed in place.
- **Real-time:** Private-show events arrive over the broadcast SSE stream from AND-281/AND-143; this ticket subscribes and reconciles, it does not build the SSE transport.

## 3. Functional Requirements

**Tips configuration (host):**
1. Host can open a "Tip settings" editor for the active/owned broadcast and view current config.
2. Host can edit: ordered list of suggested tip amounts (label + amount), enable/disable custom amounts, min/max custom amount, currency (read-only display, server-driven), and whether tips are enabled at all.
3. Host can link the tip menu to an active goal (from AND-282 goals) so tips contribute to goal progress.
4. Saving validates locally (amounts > 0, min ≤ max, at least one menu item when tips enabled, no duplicate amounts) before POST/PUT; server validation errors map back to per-field messages.
5. On success the editor reflects the persisted config; on failure it remains dirty and shows the mapped error.

**Private shows (host):**
6. Host can configure private-show availability and per-minute rate as part of, or adjacent to, tip settings (rate, min duration, accepting yes/no).
7. When a viewer requests a private show, the host receives an in-app request item (via SSE) showing requester, requested rate/duration, and request timestamp; requests have a TTL and auto-expire.
8. Host can **accept** or **decline** a pending request. Accept transitions the session to `ACTIVE` and surfaces an in-progress private-show bar (elapsed time, running cost, participant).
9. Host can **end** an active private show; the viewer can also end it (host receives the end event and reconciles).
10. On end, a session summary (duration, total amount, participant) is shown and the broadcast returns to its prior public state.
11. State transitions are idempotent and survive process death / reconnect: on resubscribe the current private-show state is rehydrated from a status GET.

## 4. Technical Design

**Module placement:** `feature-broadcast/.../privateshow/` and `.../tipsconfig/`.

**State machine.** Private show is modeled as an explicit sealed state to keep transitions testable:

```kotlin
sealed interface PrivateShowState {
    data object Idle : PrivateShowState
    data class Pending(val request: PrivateShowRequest) : PrivateShowState   // host has a pending request
    data class Active(val session: PrivateShowSession, val elapsed: Duration, val accruedCents: Long) : PrivateShowState
    data class Ending(val sessionId: String) : PrivateShowState
    data class Ended(val summary: PrivateShowSummary) : PrivateShowState
}
```

**ViewModels** expose `StateFlow<UiState>` per layering rules:

```kotlin
@HiltViewModel
class TipsConfigViewModel @Inject constructor(
    private val repo: BroadcastMonetizationRepository,
    savedState: SavedStateHandle,
) : ViewModel() {
    private val broadcastId: String = savedState["broadcastId"]!!
    val uiState: StateFlow<TipsConfigUiState>          // Loading | Editing(config, dirty, fieldErrors) | Saving | Error | Offline
    fun onMenuItemChanged(index: Int, item: TipMenuItem)
    fun onAddMenuItem(); fun onRemoveMenuItem(index: Int)
    fun onCustomBoundsChanged(minCents: Long?, maxCents: Long?)
    fun onPrivateShowConfigChanged(cfg: PrivateShowConfig)
    fun onSave()
    fun onRetry()
}

@HiltViewModel
class PrivateShowViewModel @Inject constructor(
    private val repo: BroadcastMonetizationRepository,
    private val events: BroadcastEventSource,           // SSE from AND-281/143
    savedState: SavedStateHandle,
) : ViewModel() {
    val uiState: StateFlow<PrivateShowUiState>          // wraps PrivateShowState + transient action errors
    fun accept(requestId: String)
    fun decline(requestId: String)
    fun endShow()
    fun refreshStatus()                                 // idempotent rehydrate
}
```

`Active.elapsed`/`accruedCents` derive from a 1 Hz `tickerFlow` started in `viewModelScope` once `ACTIVE`, combined with server `started_at` and `rate_per_minute_cents`; the displayed cost is client-estimated and reconciled against the server summary on end (server is source of truth for billing).

**Repository** sits in `core-data`/feature layer and returns `ApiResult<T>` (AND-018):

```kotlin
interface BroadcastMonetizationRepository {
    suspend fun getTipsConfig(broadcastId: String): ApiResult<TipsConfig>
    suspend fun saveTipsConfig(broadcastId: String, body: TipsConfig): ApiResult<TipsConfig>
    suspend fun getPrivateShowStatus(broadcastId: String): ApiResult<PrivateShowStatus>
    suspend fun acceptPrivateShow(broadcastId: String, requestId: String): ApiResult<PrivateShowSession>
    suspend fun declinePrivateShow(broadcastId: String, requestId: String): ApiResult<Unit>
    suspend fun endPrivateShow(broadcastId: String, sessionId: String): ApiResult<PrivateShowSummary>
}
```

**Event reconciliation.** `PrivateShowViewModel` collects `events.privateShowEvents(broadcastId)` (a `Flow<PrivateShowEvent>` decoded from SSE) and folds them into `PrivateShowState`. Event types: `request.created`, `request.expired`, `session.started`, `session.ended`. Because SSE is lossy, every UI-initiated transition also calls the corresponding REST endpoint (REST response is authoritative); events drive *peer-initiated* changes (viewer ends, new request arrives). On (re)subscribe or `onStart` the VM calls `getPrivateShowStatus` to rehydrate, preventing stale state after reconnect/process death.

**Compose UI.** Stateless screens driven by `uiState`:
- `TipsConfigScreen(state, onEvent)` — menu editor (reorderable list of amount rows), custom-bounds toggle + numeric fields, private-show config card, sticky Save button using core-ui state composables (AND-021) for Loading/Error/Offline.
- `PrivateShowRequestSheet` — bottom sheet for an incoming `Pending` request with Accept/Decline.
- `PrivateShowActiveBar` — persistent bar with elapsed timer, running cost, End button.
- `PrivateShowSummaryDialog` — end-of-session summary.

DI: a Hilt `@Module` binds `BroadcastMonetizationRepository` and provides the Retrofit `BroadcastMonetizationApi` (KSP).

## 5. API Contract

Paths below follow the broadcast/UI session conventions; field names must be reconciled against `/openapi.json` and `frontend/src/api/types.ts` at implementation. All calls carry session cookies + `X-CSRF-Token`.

**Retrofit interface:**

```kotlin
interface BroadcastMonetizationApi {
    @GET("ui/broadcast/{id}/tips/config")
    suspend fun getTipsConfig(@Path("id") id: String): TipsConfigDto

    @PUT("ui/broadcast/{id}/tips/config")
    suspend fun putTipsConfig(@Path("id") id: String, @Body body: TipsConfigDto): TipsConfigDto

    @GET("ui/broadcast/{id}/private-show/status")
    suspend fun getPrivateShowStatus(@Path("id") id: String): PrivateShowStatusDto

    @POST("ui/broadcast/{id}/private-show/{requestId}/accept")
    suspend fun acceptPrivateShow(@Path("id") id: String, @Path("requestId") requestId: String): PrivateShowSessionDto

    @POST("ui/broadcast/{id}/private-show/{requestId}/decline")
    suspend fun declinePrivateShow(@Path("id") id: String, @Path("requestId") requestId: String): Response<Unit>

    @POST("ui/broadcast/{id}/private-show/{sessionId}/end")
    suspend fun endPrivateShow(@Path("id") id: String, @Path("sessionId") sessionId: String): PrivateShowSummaryDto
}
```

**`GET .../tips/config` → 200:**
```json
{
  "tips_enabled": true,
  "currency": "USD",
  "menu": [
    {"id": "m1", "label": "Coffee", "amount_cents": 500},
    {"id": "m2", "label": "Big tip", "amount_cents": 5000}
  ],
  "custom_amount_enabled": true,
  "custom_min_cents": 100,
  "custom_max_cents": 100000,
  "linked_goal_id": "goal_123",
  "private_show": {
    "accepting": true,
    "rate_per_minute_cents": 2000,
    "min_duration_seconds": 300
  }
}
```
`PUT` accepts the same shape (without server-assigned `id`s on new menu items) and returns the persisted object.

**`GET .../private-show/status` → 200** (one of):
```json
{ "state": "idle" }
{ "state": "pending", "request": {"request_id":"req_9","viewer":{"u":"u_42","display_name":"Ada"},"rate_per_minute_cents":2000,"requested_duration_seconds":600,"expires_at":"2026-06-05T18:00:30Z"} }
{ "state": "active", "session": {"session_id":"ps_7","viewer":{"u":"u_42","display_name":"Ada"},"rate_per_minute_cents":2000,"started_at":"2026-06-05T17:55:00Z"} }
```

**`POST .../{requestId}/accept` → 200:** `PrivateShowSessionDto` (as in `active.session`).
**`POST .../{sessionId}/end` → 200:**
```json
{"session_id":"ps_7","duration_seconds":420,"total_amount_cents":14000,"currency":"USD","viewer":{"u":"u_42","display_name":"Ada"}}
```

**SSE events** (over AND-281 channel): `event: private_show` with `data` `{"type":"request.created|request.expired|session.started|session.ended", ...payload matching the DTOs above}`.

**Errors:** FastAPI `detail` mapped per AND-015 (`string | [{msg}] | {code,...}`). Notable: `409` (request already accepted/expired, or session already ended), `404` (stale `requestId`/`sessionId`), `403` (not the host / not authorized). Idempotent re-`end`/`decline` on an already-terminal resource is treated as success by the VM.

## 6. Data & State Management

**Domain models (`core-model`):**
```kotlin
data class TipMenuItem(val id: String?, val label: String, val amountCents: Long)   // reused from AND-282
data class PrivateShowConfig(val accepting: Boolean, val ratePerMinuteCents: Long, val minDurationSeconds: Int)
data class TipsConfig(
    val tipsEnabled: Boolean, val currency: String, val menu: List<TipMenuItem>,
    val customAmountEnabled: Boolean, val customMinCents: Long?, val customMaxCents: Long?,
    val linkedGoalId: String?, val privateShow: PrivateShowConfig,
)
data class PrivateShowRequest(val requestId: String, val viewer: ViewerRef, val ratePerMinuteCents: Long, val requestedDurationSeconds: Int, val expiresAt: Instant)
data class PrivateShowSession(val sessionId: String, val viewer: ViewerRef, val ratePerMinuteCents: Long, val startedAt: Instant)
data class PrivateShowSummary(val sessionId: String, val durationSeconds: Int, val totalAmountCents: Long, val currency: String, val viewer: ViewerRef)
```
DTOs live in `core-network` with Moshi adapters; `Instant`/`Long`-cents conversions in mapper functions (`TipsConfigDto.toDomain()`).

**Persistence.** Tips config is cached read-through in Room (AND-115/116 SWR pattern) keyed by `broadcastId` so the editor opens with last-known values when offline; writes are online-only (no offline queue — config edits require server validation). Private-show state is **session-scoped and not persisted to disk**: it is rehydrated from `getPrivateShowStatus` on VM start/reconnect. No DataStore prefs are introduced here.

**State holders.** `TipsConfigUiState` keeps `serverConfig`, `draftConfig`, `dirty`, `fieldErrors: Map<Field, String>`. `PrivateShowUiState` wraps `PrivateShowState` plus a transient `actionError: ErrorState?` and `inFlightAction` flag to disable Accept/Decline/End buttons during a call. The elapsed-time ticker is cancelled when leaving `Active`.

## 7. Error Handling & Resilience

- **Timeouts:** rely on the 20s OkHttp timeouts (AND-009). Action calls (accept/decline/end) show a per-action spinner and a snackbar on failure; the underlying `PrivateShowState` is only advanced on success (or on an authoritative SSE event).
- **Retry/backoff:** only idempotent GETs (`getTipsConfig`, `getPrivateShowStatus`) use bounded backoff retry (AND-016). `PUT`/`accept`/`decline`/`end` are **not** auto-retried; user retries manually. `decline`/`end` are server-idempotent so manual retry after an ambiguous timeout is safe.
- **409/404 reconciliation:** an accept on an expired request, or end on an already-ended session, triggers an immediate `refreshStatus()` so the UI converges to the true state rather than showing a hard error.
- **Offline / stale:** if `getTipsConfig` is offline, render cached config with an Offline banner (AND-021/045) and disable Save. Private-show actions are disabled offline.
- **SSE gaps:** on reconnect (AND-149), `refreshStatus()` is called; missed `request.created` events are recovered because `status=pending` is returned; missed `session.ended` is recovered because `status` returns `idle`/summary.
- **401:** handled transparently by the refresh authenticator (AND-013); a second 401 surfaces as session-expired and routes to re-auth.

## 8. Security & Privacy

- All endpoints are host-authorized; the app must only render the editor and private-show controls for broadcasts the authenticated user owns (`GET /ui/me` identity vs broadcast host). A `403` is treated as "not your broadcast" and navigates back, never silently retried.
- CSRF: every mutating call (PUT/accept/decline/end) carries `X-CSRF-Token` via the AND-012 interceptor; missing token is a bug, not a recoverable runtime path.
- Dev backend is plaintext HTTP — no PII beyond viewer display name/`u` id is logged; amounts and rates are non-sensitive but the viewer identity in private-show requests must be redacted in logs (see section 10).
- Monetary authority: client-side accrued-cost display is explicitly an estimate; only the server `total_amount_cents` from the end summary is treated as billable, preventing client tampering from affecting charges.
- No new credentials/tokens are stored; relies on the shared persistent cookie jar.

## 9. Accessibility & i18n

- All strings via `core-ui` i18n plumbing (AND-111/112); no hardcoded literals. New keys: `tips_config_title`, `tips_menu_add`, `tips_custom_bounds`, `private_show_request_title`, `private_show_accept`, `private_show_decline`, `private_show_end`, `private_show_active_cost`, `private_show_summary_total`, plus error keys.
- Currency and amount formatting use locale-aware formatting (`NumberFormat.getCurrencyInstance`) seeded by the server `currency`; cents→display conversion centralized in a `formatCents(cents, currency)` util.
- Elapsed timer and running cost expose `contentDescription` (e.g. "Private show active, 7 minutes, 140 dollars") updated on tick; the Accept/Decline/End buttons have ≥48dp touch targets and descriptive labels.
- Reorderable tip-menu rows provide accessibility move-up/move-down actions in addition to drag. RTL-ready layouts per AND-114. Request bottom sheet is announced when it appears (live region).

## 10. Telemetry & Logging

- Reuse the redacted telemetry pattern (AND-052). Events (no PII payloads):
  - `tips_config_opened`, `tips_config_saved {menu_size, custom_enabled, private_show_accepting}`, `tips_config_save_failed {error_code}`
  - `private_show_request_received`, `private_show_accepted {rate_cents}`, `private_show_declined`, `private_show_ended {duration_seconds, total_cents}`, `private_show_action_failed {action, error_code}`
- Viewer identity (`u`, `display_name`) is **never** logged; only counts/codes/amounts. Network logging (AND-009) runs at BODY only in debug builds.
- A single structured log line per state transition (`PrivateShowState X -> Y via {event|rest}`) aids reconnect debugging.

## 11. Testing Strategy

**Unit (core-testing + MockWebServer, AND-046):**
- `TipsConfigViewModel`: load→edit→save happy path; local validation (min>max, duplicate amounts, empty menu while enabled) produces field errors and blocks POST; server 422 maps to per-field errors; offline load shows cached + disabled Save.
- `PrivateShowViewModel` state machine: `Idle→Pending` on `request.created`; `Pending→Idle` on `request.expired`; `Pending→Active` on accept (REST) and on `session.started` (SSE); `Active→Ended` on host `end`; `Active→Ended` on peer `session.ended`; ticker produces increasing `accruedCents`; accept on expired request (409) triggers `refreshStatus` and converges to `Idle`.
- Repository contract tests (AND-047 style) over MockWebServer for each endpoint incl. 401-refresh-retry and 409 idempotency.
- DTO↔domain mapper round-trips, incl. all three `status` variants and the cents/`Instant` conversions.

**Compose UI (AND-048/049 style, instrumented, AND-051):**
- Tips editor: add/remove/reorder menu rows, toggle custom bounds, Save disabled while invalid/offline, error surface on failure.
- Incoming request sheet renders requester + rate, Accept/Decline invoke VM; active bar shows ticking timer and End; summary dialog shows server totals.

**Reliability:** simulated SSE drop + reconnect test asserts `refreshStatus` rehydration. CI runs unit (AND-050) and instrumented headless emulator (AND-051) suites.

## 12. Dependencies & Sequencing

- **Hard dep (`depends_on`): AND-282** (Tips & goals) — reuses `TipMenuItem`, goals models, and the viewer `chat/tip` semantics; tips config edits the menu AND-282 displays.
- **Implicit upstream:** AND-278 (broadcast DTOs), AND-281 (live chat / SSE channel for private-show events), AND-143/149 (SSE core + reconnect), AND-307/309 (host session context & controls). Core infra: AND-011/012/013 (cookie/CSRF/refresh), AND-015 (error mapping), AND-016 (GET retry), AND-018 (ApiResult), AND-021 (state composables), AND-115/116 (cache).
- **Sequencing:** implement DTOs/mappers + repository + MockWebServer contract tests first; then `TipsConfigViewModel`/screen; then `PrivateShowViewModel` state machine + event reconciliation; then private-show Compose surfaces; finally telemetry + instrumented tests.
- **Blocks:** none recorded in backlog. Viewer-side private-show *request* UI (if a separate ticket) would consume the rate/accepting config saved here.

## 13. Risks & Open Questions

- **Endpoint/field drift:** exact paths and field names (`tips/config` vs `monetization/tips`, `private-show` vs `private_show`) must be confirmed against `/openapi.json`; this spec's paths are best-effort from web reference conventions. Resolve before coding and update section 5.
- **SSE event schema:** whether private-show events ride the existing live-chat SSE channel (AND-281) or a dedicated stream is unconfirmed; if dedicated, an additional `BroadcastEventSource` subscription is needed.
- **Billing authority & metering:** does the server meter private-show cost server-side and bill on `end`, or expect periodic heartbeats? Spec assumes server-side metering with client-estimated display; confirm to avoid double-charging or under-billing on abrupt disconnect.
- **Abrupt termination:** behavior if host process dies mid-session (does the server auto-end after a timeout?) affects whether a stale `Active` must be force-ended on next launch. Mitigated by `refreshStatus` rehydrate, but server auto-end policy is an open question.
- **Goal linkage semantics:** whether private-show payments contribute to the linked goal, or only tips, needs confirmation for goal-progress accuracy.

## 14. Acceptance Criteria

1. Host opens Tip settings for an owned broadcast and sees current config loaded from `GET .../tips/config` (or cached values + Offline banner when offline).
2. Host edits menu items, custom bounds, and private-show config; invalid input (min>max, duplicate/zero amount, empty menu while enabled) blocks Save with per-field errors; valid Save issues `PUT` and reflects the persisted response.
3. A viewer-initiated private-show request appears to the host (via SSE or status poll) showing requester, rate, and requested duration, and auto-expires per `expires_at`.
4. Host **Accept** transitions to an active session (`POST .../accept` → 200) with a visible elapsed timer and running estimated cost; **Decline** removes the request (`POST .../decline`).
5. Host **End** (`POST .../end` → 200) shows a summary with server `duration_seconds`/`total_amount_cents` and returns the broadcast to public; viewer-initiated end is reflected on the host via `session.ended`.
6. State survives reconnect/process death: relaunching or reconnecting rehydrates the correct `idle/pending/active` state from `GET .../private-show/status`.
7. 409/404 on a stale request/session converges the UI to true state without a dead-end error; 401 is transparently refreshed.
8. Viewer identity is never logged; telemetry events fire with redacted, code/amount-only payloads.

## 15. Definition of Done

- All section 14 criteria met and demonstrated against the dev backend (`http://18.222.237.167:8000`).
- Code under `com.testlogon.android.feature.broadcast.{tipsconfig,privateshow}`, ViewModels expose `StateFlow<UiState>`, repository returns `ApiResult<T>`, DTO mappers + Moshi adapters complete, Hilt/KSP wiring builds.
- Unit + repository contract tests (MockWebServer) and Compose instrumented tests pass in CI (AND-050/051), including the SSE-drop/reconnect rehydration test and the state-machine transition matrix.
- Strings externalized (no hardcoded UI text), currency/amount formatting locale-aware, accessibility labels and ≥48dp targets verified; RTL-clean.
- Lint/format/static analysis (AND-005) clean; redacted telemetry verified to contain no viewer PII.
- Section 13 open questions (endpoint drift, SSE channel, billing authority) resolved or explicitly deferred with owning ticket noted; PR merged to `android-port`.
