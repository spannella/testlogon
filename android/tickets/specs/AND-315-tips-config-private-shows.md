---
id: AND-315
title: Tips config & private shows
milestone: M7
epic: E41
priority: P2
size: L
status: reviewed
reviewed_on: 2026-06-06
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
- **Web reference:** `src/api/endpoints/broadcast-tips.ts`, `src/api/endpoints/broadcastPrivate.ts`, `src/api/endpoints/broadcast.ts`, and `src/components/broadcast/PrivateRequestNotification.tsx` for the request/response shapes and host UX; OpenAPI at `http://18.222.237.167:8000/openapi.json` is authoritative for paths and field names — reconcile drift at implementation and record it in section 13. **[CORRECTED]** The real endpoints live under `/broadcast/sessions/{session_id}/...` (no `/ui` prefix; path param is `session_id`), not the `/ui/broadcast/{id}/...` paths originally drafted in section 5.
- **Auth:** Cookie session + `ui_csrf` cookie echoed as `X-CSRF-Token`, **plus** an `Authorization: Bearer <accessToken>` header that the web client (`src/api/client.ts`) attaches to every call from its auth store; an optional `X-IMPERSONATION-TOKEN` header is sent only when impersonating (not used by this host flow). On 401 the OkHttp authenticator (AND-013) performs one `POST /ui/session/refresh` then retries. Persistent cookie jar (AND-011) and CSRF interceptor (AND-012) assumed in place. **[CORRECTED]** Original draft omitted the bearer token; mirror `client.ts` (cookie + CSRF + bearer).
- **Real-time:** **[CORRECTED]** The web reference does NOT use SSE for private-show state — `PrivateRequestNotification.tsx` polls `GET /broadcast/sessions/{id}/private/requests` every 5 s (and `BroadcastPage` polls session detail every 5 s). This spec's original SSE-driven design is unverified against the reference; treat polling as the contract-confirmed mechanism. If an SSE channel exists (AND-281/AND-143) it MAY be used as an optimization, but the baseline implementation must poll `listPrivateRequests` / `getPrivateStatus` on an interval. See §13 and the audit in §16.

## 3. Functional Requirements

> **[REVIEW NOTE — scope correction]** The verified API supports only `tip_enabled` / `tip_min_cents` / `tip_max_cents` for tip config (PATCH), with goals as a separate resource and per-minute private-show rate set by the viewer on the request. The richer tip-menu / currency / custom-bounds / goal-linkage / host private-show-rate config described below (items 2,3,6) is **not backed by the current backend** and is retained as a product aspiration; implement only what the API supports unless a backend change lands. See §5 and §16.

**Tips configuration (host):**
1. Host can open a "Tip settings" editor for the active/owned broadcast and view current config (read from the session object's tip fields; there is no dedicated config GET).
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

**[CORRECTED — this section was substantially rewritten to match the verified OpenAPI index and the web reference.]** All calls carry session cookies + `X-CSRF-Token` + `Authorization: Bearer`. The base path is `/broadcast/sessions/{session_id}/...` (no `/ui` prefix). Field names below are taken verbatim from the OpenAPI schemas and `broadcastPrivate.ts`/`broadcast.ts`; see §16 for per-claim sources.

> **Tips "config" is much smaller than originally drafted.** The server has NO tip-menu, currency, custom-bounds, or `linked_goal_id` config object, and NO `GET tips/config`. Tip config is a single `PATCH .../tips/config` taking `BroadcastTipConfigIn = {tip_enabled?, tip_min_cents?, tip_max_cents?}` (both cents fields bounded 100–100000) and returning the full `BroadcastSession` (`BroadcastSessionOut`). The current values are read from the session object's `tip_enabled` / `tip_min_cents` / `tip_max_cents` fields (via `GET /broadcast/sessions/{id}`), not a dedicated config GET. "Goals" are a separate resource (`GET/POST/DELETE .../goals`); there is no menu↔goal linkage field. Any richer "tip menu" / custom-amount editor described elsewhere in this spec is an **unverified product assumption** not backed by the API and must not be implemented against a non-existent endpoint without a backend change (see §13/§16).

> **Private-show per-minute rate is set by the VIEWER on the request, not by host config.** `PrivateRequestIn` carries `rate_per_minute_cents` (100–10000) and `payment_method_id`; there is no host-side "accepting / rate / min-duration" config endpoint in the API. The host's role is to poll incoming requests and accept (choosing a broadcast `behavior`) / decline.

**Retrofit interface (corrected paths & shapes):**

```kotlin
interface BroadcastMonetizationApi {
    // Tip config: PATCH only; returns the full session. No GET tips/config exists.
    @PATCH("broadcast/sessions/{id}/tips/config")
    suspend fun patchTipConfig(@Path("id") id: String, @Body body: BroadcastTipConfigInDto): BroadcastSessionDto

    // Read current tip config + status via the session object.
    @GET("broadcast/sessions/{id}")
    suspend fun getSession(@Path("id") id: String): BroadcastSessionDto

    // Host: list pending private-show requests (POLLED every ~5s in the web client).
    @GET("broadcast/sessions/{id}/private/requests")
    suspend fun listPrivateRequests(@Path("id") id: String): PrivateRequestListDto

    // Current private session status for the broadcast.
    @GET("broadcast/sessions/{id}/private/status")
    suspend fun getPrivateStatus(@Path("id") id: String): PrivateStatusDto

    // Accept REQUIRES a body: behavior = pause | end | continue (what happens to the public broadcast).
    @POST("broadcast/sessions/{id}/private/{requestId}/accept")
    suspend fun acceptPrivateRequest(
        @Path("id") id: String,
        @Path("requestId") requestId: String,
        @Body body: PrivateRequestAcceptInDto,   // {"behavior":"pause"}
    ): PrivateAcceptDto

    @POST("broadcast/sessions/{id}/private/{requestId}/decline")
    suspend fun declinePrivateRequest(@Path("id") id: String, @Path("requestId") requestId: String): Response<Unit>

    // End uses the PRIVATE SESSION id (private_session_id), not the request id.
    @POST("broadcast/sessions/{id}/private/{privateId}/end")
    suspend fun endPrivateSession(@Path("id") id: String, @Path("privateId") privateId: String): PrivateSessionEndDto
}
```

**`PATCH .../tips/config`** body `BroadcastTipConfigIn` → 200 `BroadcastSessionOut`:
```json
// request body (all optional, cents 100..100000)
{ "tip_enabled": true, "tip_min_cents": 100, "tip_max_cents": 50000 }
// response: full BroadcastSession; relevant fields:
{ "id": "sess_1", "status": "live", "tip_enabled": true, "tip_min_cents": 100, "tip_max_cents": 50000, "tip_total_cents": 0, "tip_count": 0 /* ...many other session fields... */ }
```

**`GET .../private/requests` → 200 `PrivateRequestListOut`:** `{ "requests": [PrivateRequestOut, ...] }`. Each `PrivateRequestOut` (timestamps are **epoch integers**, viewer fields are **flat**, not nested):
```json
{
  "request_id": "req_9",
  "private_session_id": "ps_7",
  "session_id": "sess_1",
  "viewer_id": "u_42",
  "viewer_display_name": "Ada",
  "rate_per_minute_cents": 2000,
  "status": "pending",
  "behavior": null,
  "call_id": null,
  "max_duration_minutes": 60,
  "requested_at": 1749146400,
  "accepted_at": null, "started_at": null, "ended_at": null, "ended_by": null,
  "total_billed_cents": 0
}
```
Required fields: `request_id, private_session_id, session_id, viewer_id, rate_per_minute_cents, status, requested_at`. There is **no `expires_at`** field — TTL/expiry is not exposed in the schema (see §13/§16).

**`GET .../private/status` → 200 `PrivateStatusResponse`** (web type; OpenAPI declares an untyped 200 body). Fields: `status` plus optional `request_id, private_session_id, session_id, viewer_id, viewer_display_name, rate_per_minute_cents, behavior, call_id`.

**`POST .../{requestId}/accept`** body `{"behavior":"pause"|"end"|"continue"}` → 200 `PrivateAcceptOut`:
```json
{ "private_session_id":"ps_7", "session_id":"sess_1", "status":"active", "behavior":"pause", "call_id":"call_123", "rate_per_minute_cents":2000 }
```
(`behavior` controls the public broadcast on accept; `call_id` is the WebRTC call handle for the private session.)

**`POST .../{requestId}/decline` → 200** empty body in OpenAPI; web client types it as `{ "ok": true, "request_id": "req_9" }`. **`POST .../{requestId}/cancel`** is the viewer-side cancellation (out of host scope here, listed for completeness).

**`POST .../{privateId}/end` → 200 `PrivateSessionEndOut`** (note `total_billed_cents`, not `total_amount_cents`; no `currency`/viewer in the summary):
```json
{ "private_session_id":"ps_7", "session_id":"sess_1", "status":"ended", "duration_seconds":420, "total_billed_cents":14000, "ended_by":"host" }
```

**Real-time:** **[CORRECTED]** Delivery of new requests / status changes is by **polling** in the web reference (`listPrivateRequests` @5s, session detail @5s), not SSE. No `event: private_show` SSE schema is present in the reference; the previously-described event types (`request.created` etc.) are **unverified assumptions**. Baseline Android implementation must poll; an SSE fast-path is optional and unconfirmed.

**Errors:** FastAPI returns `422:HTTPValidationError` for body/param validation (the only documented error response on these routes); `detail` mapped per AND-015 (`string | [{msg}] | {code,...}`, per `normalizeErrorDetail` in `client.ts`). `401` → one `POST /ui/session/refresh` + retry (per `client.ts`); `403` → permission denied / not your broadcast. `404`/`409` for stale/terminal request/session are plausible but **not documented in the OpenAPI for these routes** (only 200 + 422 are declared) — treat them as defensive handling, not a verified contract (see §16). Idempotent re-`end`/`decline` on an already-terminal resource is treated by the VM as success/converge-to-truth.

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
// [CORRECTED] viewer fields are FLAT (viewer_id/viewer_display_name), timestamps are epoch seconds (Long/Instant from epoch),
// duration is max_duration_MINUTES, summary uses total_billed_cents and has no currency/viewer. No expires_at exists.
data class PrivateShowRequest(val requestId: String, val privateSessionId: String, val viewerId: String, val viewerDisplayName: String, val ratePerMinuteCents: Long, val status: String, val maxDurationMinutes: Int, val requestedAt: Instant)
data class PrivateShowSession(val privateSessionId: String, val sessionId: String, val status: String, val behavior: String, val callId: String, val ratePerMinuteCents: Long)
data class PrivateShowSummary(val privateSessionId: String, val sessionId: String, val status: String, val durationSeconds: Int, val totalBilledCents: Long, val endedBy: String)
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

- **Endpoint/field drift:** **[RESOLVED in this review]** verified against the OpenAPI index and web reference. Correct base path is `/broadcast/sessions/{session_id}/...`; tip config is `PATCH .../tips/config` with `{tip_enabled,tip_min_cents,tip_max_cents}` only; private routes are `.../private/{requests,status,{id}/accept,{id}/decline,{id}/end,{id}/cancel}`. Section 5 has been corrected. Remaining product-level gap: the rich tip-menu/custom-bounds/host-rate config has no backend support and needs a backend ticket if desired.
- **SSE event schema:** **[CORRECTED]** the web reference uses 5s polling (`listPrivateRequests`, session detail), not SSE, for private-show state. No private-show SSE event schema exists in the reference. Baseline = polling; an SSE fast-path remains an unconfirmed optimization that would need a backend channel + schema.
- **Request expiry / TTL:** `PrivateRequestOut` exposes no `expires_at`; the assumed auto-expire/TTL behavior is unverified. Confirm whether expiry is server-driven (and how it is surfaced) before relying on it in the UI.
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

## 16. Citations & Assumption Audit

Each key technical claim with VERDICT and an exact source pointer. Sources: OpenAPI index `reference/openapi.index.txt`, OpenAPI spec `reference/openapi.pretty.json` (schemas under `components.schemas`), and frontend files under `reference/src/`.

1. **Tip config endpoint is `PATCH /broadcast/sessions/{session_id}/tips/config` (not GET+PUT `/ui/broadcast/{id}/tips/config`).** — VERDICT: Corrected. SOURCE: OpenAPI `PATCH /broadcast/sessions/{session_id}/tips/config` (op `update_tip_config_route...`, req=`BroadcastTipConfigIn`, resp=`200:BroadcastSessionOut`); `src/api/endpoints/broadcast-tips.ts: updateTipConfig` (uses `api.patch`).
2. **`BroadcastTipConfigIn` contains only `tip_enabled`, `tip_min_cents`, `tip_max_cents` (cents bounded 100–100000); no menu/currency/custom-bounds/linked_goal/private_show.** — VERDICT: Corrected. SOURCE: `components.schemas.BroadcastTipConfigIn` (openapi.pretty.json ~L12662); `src/api/endpoints/broadcast.ts: BroadcastTipConfigIn` (L108-112).
3. **There is no `GET tips/config`; current tip config is read from the `BroadcastSession` object's `tip_enabled`/`tip_min_cents`/`tip_max_cents` fields.** — VERDICT: Corrected. SOURCE: `src/api/endpoints/broadcast.ts: BroadcastSession` (L57-62, "Tipping fields (BCAST-013)"); no `tips/config` GET in OpenAPI index.
4. **Tip goals are a separate resource (`GET/POST/DELETE /broadcast/sessions/{id}/goals`); no menu↔goal `linked_goal_id` config field exists.** — VERDICT: Corrected (refutes spec's goal-linkage config). SOURCE: OpenAPI `GET/POST /broadcast/sessions/{session_id}/goals`, `DELETE .../goals/{goal_id}`; `src/api/endpoints/broadcast-tips.ts: createTipGoal/listTipGoals/deleteTipGoal`.
5. **Private-show base path is `/broadcast/sessions/{session_id}/private/...` (not `/ui/broadcast/{id}/private-show/...`).** — VERDICT: Corrected. SOURCE: OpenAPI index lines 212-218; `src/api/endpoints/broadcastPrivate.ts` (all functions).
6. **Host lists pending requests via `GET .../private/requests` → `PrivateRequestListOut {requests:[PrivateRequestOut]}`.** — VERDICT: Verified/Corrected (path & shape). SOURCE: OpenAPI `GET .../private/requests` (resp=`PrivateRequestListOut`); `components.schemas.PrivateRequestListOut`; `src/api/endpoints/broadcastPrivate.ts: listPrivateRequests`.
7. **`PrivateRequestOut` viewer fields are flat (`viewer_id`, `viewer_display_name`) and timestamps are epoch integers (`requested_at` etc.); the spec's nested `viewer:{u,display_name}` + ISO `expires_at` was wrong.** — VERDICT: Corrected. SOURCE: `components.schemas.PrivateRequestOut` (openapi.pretty.json L57945-58067); `src/api/endpoints/broadcastPrivate.ts: PrivateRequest` (L5-22).
8. **No `expires_at` / TTL field exists on the request schema; auto-expire is unverified.** — VERDICT: Unverified-assumption. SOURCE: absence in `components.schemas.PrivateRequestOut` (no expiry/ttl property).
9. **Accept = `POST .../private/{request_id}/accept` with REQUIRED body `PrivateRequestAcceptIn {behavior: "pause"|"end"|"continue"}` → `PrivateAcceptOut` (200).** — VERDICT: Corrected (spec had a bodyless accept). SOURCE: OpenAPI `POST .../private/{request_id}/accept` (req=`PrivateRequestAcceptIn`); `components.schemas.PrivateRequestAcceptIn` (pattern `^(pause|end|continue)$`, L57889); `src/api/endpoints/broadcastPrivate.ts: acceptPrivateRequest`; `src/components/broadcast/PrivateRequestNotification.tsx` (L32-47,101-116) shows the behavior selector.
10. **`PrivateAcceptOut` fields: `private_session_id, session_id, status, behavior, call_id, rate_per_minute_cents` (includes WebRTC `call_id`).** — VERDICT: Verified. SOURCE: `components.schemas.PrivateAcceptOut` (L57335-57371); `src/api/endpoints/broadcastPrivate.ts: PrivateAcceptResponse`.
11. **Decline = `POST .../private/{request_id}/decline` (no body); OpenAPI declares empty 200, web types it `{ok, request_id}`.** — VERDICT: Verified/Corrected (return shape). SOURCE: OpenAPI `POST .../private/{request_id}/decline` (resp=`200:` empty); `src/api/endpoints/broadcastPrivate.ts: declinePrivateRequest`.
12. **End = `POST .../private/{private_id}/end` keyed by the PRIVATE SESSION id (not the request id) → `PrivateSessionEndOut`.** — VERDICT: Corrected (spec keyed end by `sessionId` ambiguously / wrong path segment). SOURCE: OpenAPI `POST .../private/{private_id}/end` (resp=`PrivateSessionEndOut`); `src/api/endpoints/broadcastPrivate.ts: endPrivateSession`.
13. **End summary uses `total_billed_cents` (not `total_amount_cents`), plus `duration_seconds`, `status`, `ended_by`, `private_session_id`, `session_id`; no `currency`/viewer.** — VERDICT: Corrected. SOURCE: `components.schemas.PrivateSessionEndOut` (L58069-58105); `src/api/endpoints/broadcastPrivate.ts: PrivateSessionEndResponse`.
14. **Status = `GET .../private/status`; OpenAPI declares an untyped 200, web type `PrivateStatusResponse {status, request_id?, private_session_id?, session_id?, viewer_id?, viewer_display_name?, rate_per_minute_cents?, behavior?, call_id?}`.** — VERDICT: Verified (path) / Corrected (state-key names; spec used `state` + nested objects). SOURCE: OpenAPI `GET .../private/status` (resp=`200:` untyped); `src/api/endpoints/broadcastPrivate.ts: getPrivateStatus`/`PrivateStatusResponse`.
15. **Real-time delivery is 5s POLLING, not SSE.** — VERDICT: Corrected. SOURCE: `src/components/broadcast/PrivateRequestNotification.tsx` (L36-41, `refetchInterval: 5000` on `listPrivateRequests`); `src/pages/broadcast/BroadcastPage.tsx` (L148-153, session detail `refetchInterval: 5_000`). No `private_show` SSE schema found in `reference/src`.
16. **Auth model = cookie session + `ui_csrf` cookie echoed as `X-CSRF-Token` + `Authorization: Bearer <accessToken>`; optional `X-IMPERSONATION-TOKEN`.** — VERDICT: Corrected (spec omitted the bearer token). SOURCE: `src/api/client.ts` (L156-171 sets Authorization from auth store, X-CSRF-Token from `ui_csrf`, X-IMPERSONATION-TOKEN when impersonating).
17. **401 handling: one `POST /ui/session/refresh` then retry; second 401 → logout/session_expired.** — VERDICT: Verified. SOURCE: `src/api/client.ts` (L121-130 `refreshSession`, L194-237 retry-once logic).
18. **Error `detail` shapes: `string | [{msg}] | {code,...}` normalized.** — VERDICT: Verified. SOURCE: `src/api/client.ts: normalizeErrorDetail` (L66-102) and `mapAuthorizationError` (L34-64).
19. **Documented error responses on these routes are only `422 HTTPValidationError` (+200); 404/409 are not in the OpenAPI for them.** — VERDICT: Unverified-assumption (defensive handling). SOURCE: OpenAPI index lines 212-218 & 247 (`resp` columns show only `200`/`201` and `422:HTTPValidationError`).
20. **Private-show per-minute rate + payment method are set by the VIEWER on `PrivateRequestIn {rate_per_minute_cents(100..10000), payment_method_id, max_duration_minutes(5..120, default 60)}`; there is no host "accepting/rate/min-duration" config endpoint.** — VERDICT: Corrected (refutes spec's host private-show config, FR item 6). SOURCE: `components.schemas.PrivateRequestIn` (L57903-57930); `src/api/endpoints/broadcastPrivate.ts: submitPrivateRequest`.
21. **Cancel (`POST .../private/{request_id}/cancel`) exists as the viewer-side cancel; not a host action.** — VERDICT: Verified (added for completeness). SOURCE: OpenAPI index line 217; `src/api/endpoints/broadcastPrivate.ts: cancelPrivateRequest`.
22. **`Active.elapsed`/`accruedCents` is client-estimated; server `total_billed_cents` on end is authoritative.** — VERDICT: Unverified-assumption (billing/metering model). SOURCE: no metering/heartbeat endpoint in OpenAPI for these routes; `total_billed_cents` present on `PrivateRequestOut`/`PrivateSessionEndOut` only — server-side metering is assumed, not proven.
23. **Framework choices (Hilt `@HiltViewModel`, `StateFlow`, Retrofit `@PATCH`/`@POST`/`@Path`/`@Body`, Compose stateless screens, Moshi).** — VERDICT: Verified (framework ref). SOURCE: framework ref — Android `StateFlow` (developer.android.com/kotlin/flow/stateflow-and-sharedflow), Hilt (developer.android.com/training/dependency-injection/hilt-android), Retrofit (square.github.io/retrofit), Jetpack Compose state (developer.android.com/jetpack/compose/state).

### Corrections made
- §2: web-reference file list updated to the actual files; **auth corrected** to include `Authorization: Bearer` (+ optional impersonation header); **real-time corrected** from SSE to 5s polling.
- §3: added scope-correction note — server tip config is only `tip_enabled/min/max`; rich menu/custom-bounds/goal-linkage/host private-show-rate config (FR 2,3,6) is not backed by the API.
- §5: rewritten — base path `/broadcast/sessions/{session_id}/...`; `PATCH tips/config` (no GET/PUT, minimal body, returns full session); private routes & corrected DTO shapes (flat viewer fields, epoch-int timestamps, `max_duration_minutes`, accept requires `behavior` body, end keyed by `private_session_id`, summary `total_billed_cents`); removed invented SSE event schema; corrected error-contract notes.
- §6: domain models corrected to flat viewer fields, epoch timestamps, `maxDurationMinutes`, `total_billed_cents`, no `currency`/`expires_at`; added `behavior`/`callId`.
- §13: marked endpoint/field drift RESOLVED, SSE→polling corrected, added request-TTL open question.

### Open assumptions
- **Auto-expire / TTL of pending requests** — no `expires_at`/ttl in `PrivateRequestOut`; whether and how requests expire is unconfirmed (claim 8).
- **404/409 reconciliation behavior** — these statuses are not documented for the private routes (only 200/201/422); converge-on-409/404 logic is defensive, not contract-backed (claim 19).
- **Billing/metering model** — server-side metering with client-estimated display is assumed; no heartbeat/metering endpoint observed; abrupt-disconnect billing is unknown (claim 22; §13).
- **SSE fast-path** — existence of a private-show SSE channel (AND-281/143) is unconfirmed; baseline must poll (claim 15).
- **Goal contribution from private-show payments** — not expressible in the API (no linkage field); unresolved product question (§13).
- **`X-SESSION-ID` / `user_sub` params** shown in the OpenAPI index params column are not used by the web client (which relies on cookie+bearer); their role for the Android client is unverified.

## 17. Test Plan

Acceptance Criteria (AC) referenced are from §14 (AC-1..AC-8). Targets: JVM = JVM/Robolectric unit; MWS = MockWebServer contract; EMU = headless emulator AVD `test35` (API 35 x86_64); DEV = physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). Compose-UI tests run on EMU unless ABI/API-specific.

- **TC-AND-315-01** — Type: contract/MockWebServer (MWS, JVM). Target: `BroadcastMonetizationApi.patchTipConfig` + mapper. Preconditions: MWS enqueues 200 with a full `BroadcastSessionOut` echoing `tip_enabled/tip_min_cents/tip_max_cents`. Steps: call `saveTipsConfig` with `{tip_enabled=true, tip_min_cents=100, tip_max_cents=50000}`. Expected: request is `PATCH /broadcast/sessions/{id}/tips/config` with exactly those three fields; response maps to domain config from the session's tip fields; `ApiResult.Success`. Traces: AC-2.
- **TC-AND-315-02** — Type: unit (JVM). Target: `TipsConfigViewModel` local validation. Preconditions: VM in `Editing`. Steps: set `tip_min_cents=60000`, `tip_max_cents=50000` (min>max) and a below-bound value (`50` < 100). Expected: per-field errors; Save blocked; no network call. Traces: AC-2.
- **TC-AND-315-03** — Type: contract/MockWebServer (MWS, JVM). Target: `patchTipConfig` 422 mapping. Preconditions: MWS enqueues 422 `HTTPValidationError` with `detail=[{loc:[...,"tip_max_cents"],msg:"..."}]`. Steps: call save. Expected: error normalized per `normalizeErrorDetail`; mapped to the `tip_max_cents` field; state stays dirty. Traces: AC-2.
- **TC-AND-315-04** — Type: contract/MockWebServer (MWS, JVM). Target: `listPrivateRequests` + `getPrivateStatus` decode. Preconditions: MWS returns `PrivateRequestListOut` with one `PrivateRequestOut` (flat `viewer_id`/`viewer_display_name`, epoch `requested_at`, `max_duration_minutes`, no `expires_at`). Steps: poll once. Expected: DTO→domain maps flat viewer fields and epoch→Instant correctly; state becomes `Pending(request)`. Traces: AC-3.
- **TC-AND-315-05** — Type: unit (JVM). Target: `PrivateShowViewModel` polling reconciliation. Preconditions: fake repo returns empty list, then a pending request, then active status, then idle. Steps: advance virtual time across poll intervals. Expected: state machine walks `Idle→Pending→Active→Idle` purely from polled status (no SSE); ticker starts on `Active`, stops on leave. Traces: AC-3, AC-6.
- **TC-AND-315-06** — Type: contract/MockWebServer (MWS, JVM). Target: `acceptPrivateRequest` body + response. Preconditions: MWS 200 `PrivateAcceptOut`. Steps: call `accept(requestId)` with behavior `pause`. Expected: request body is `{"behavior":"pause"}`, path `.../private/{requestId}/accept`; response maps `private_session_id`, `call_id`, `rate_per_minute_cents`; state → `Active`. Traces: AC-4.
- **TC-AND-315-07** — Type: contract/MockWebServer (MWS, JVM). Target: `endPrivateSession`. Preconditions: MWS 200 `PrivateSessionEndOut` with `total_billed_cents=14000, duration_seconds=420, ended_by="host"`. Steps: from `Active`, call `endShow()` using `private_session_id`. Expected: path `.../private/{privateId}/end`; summary maps `total_billed_cents` (server-authoritative) overriding client estimate; state → `Ended(summary)`. Traces: AC-5.
- **TC-AND-315-08** — Type: unit/contract (JVM+MWS). Target: peer-end + decline idempotency. Preconditions: MWS returns idle status after a session that the VM still thinks is `Active`; decline enqueues 200 empty then a repeat. Steps: poll status (peer ended) → expect converge to `Idle`/summary; call `decline` twice. Expected: peer-end reconciled without error; second decline treated as success/converge. Traces: AC-5, AC-7.
- **TC-AND-315-09** — Type: contract/MockWebServer (MWS, JVM). Target: 401 refresh-retry. Preconditions: MWS returns 401, then (after `POST /ui/session/refresh` 200) 200 on retry of `getPrivateStatus`. Steps: poll status while session expired. Expected: exactly one refresh call then a successful retry; no user-visible error. Traces: AC-7.
- **TC-AND-315-10** — Type: integration (JVM+MWS). Target: offline / flaky-dev-host path. Preconditions: tip config cached in Room; network disabled (MWS connection failure / `ApiError(0)`); private actions attempted offline. Steps: open editor offline; attempt accept/end offline. Expected: cached config rendered with Offline banner, Save disabled; private-show action buttons disabled offline; no crash; on reconnect a poll rehydrates state. Traces: AC-1, AC-6.
- **TC-AND-315-11** — Type: Compose-UI (instrumented, EMU). Target: `TipsConfigScreen` + `PrivateShowRequestSheet`/`PrivateShowActiveBar`/`PrivateShowSummaryDialog`. Preconditions: VM seeded with fake states. Steps: render `Pending` (sheet shows `viewer_display_name`, rate/min, Accept+Decline with behavior selector), tap Accept → `Active` (ticking timer + running estimated cost + End), tap End → summary dialog with server totals. Expected: each surface renders the corrected fields and invokes the right VM actions. Traces: AC-3, AC-4, AC-5.
- **TC-AND-315-12** — Type: instrumented (EMU). Target: security/ownership + CSRF/bearer headers. Preconditions: MWS (via test transport) returns 403 for a non-owned broadcast; CSRF interceptor + auth header configured. Steps: open editor for a broadcast the user does not host; inspect outgoing mutating request headers. Expected: 403 navigates back ("not your broadcast"), never silently retried; every mutating call carries `X-CSRF-Token` (from `ui_csrf`) and `Authorization: Bearer`. Traces: AC-7, AC-8.
- **TC-AND-315-13** — Type: instrumented/unit (EMU). Target: telemetry redaction. Preconditions: in-memory telemetry sink. Steps: drive request-received → accepted → ended; capture emitted events. Expected: events contain only counts/codes/amounts (`rate_cents`, `duration_seconds`, `total_cents`, `error_code`); NO `viewer_id`/`viewer_display_name` anywhere. Traces: AC-8.
- **TC-AND-315-14** — Type: Compose-UI accessibility (instrumented, EMU). Target: active bar + request sheet + Accept/Decline/End buttons. Steps: enable a11y assertions; verify the elapsed/cost `contentDescription` updates on tick, buttons have ≥48dp targets and descriptive labels, request sheet announced as a live region. Expected: all a11y assertions pass; RTL layout clean. Traces: AC-4 (UI quality; supports AC-3/AC-5 surfaces).
- **TC-AND-315-15** — Type: instrumented/e2e on PHYSICAL DEVICE (DEV — MUST run on SM-A156U, arm64/API 34). Target: full host private-show lifecycle against the dev backend, including the WebRTC `call_id` returned on accept and arm64-vs-x86 / API-34-vs-35 differences. Preconditions: real broadcast session live on dev backend (`http://18.222.237.167:8000`); a viewer submits a private request. Steps: poll surfaces the request → Accept (behavior=pause) → media/`call_id` wiring engages on real hardware → End → summary. Expected: lifecycle completes on the physical device with real arm64 build; billing summary from `PrivateSessionEndOut` shown; no ABI/API-34-specific failure. Note: MUST be the physical device (real WebRTC media/`call_id` + ABI/API coverage); the emulator cannot validate the arm64 path. Traces: AC-4, AC-5, AC-6.

### Coverage matrix
- **AC-1** (load config / cached + offline banner): TC-01-ish read path, TC-10.
- **AC-2** (edit + validation + persist via PATCH): TC-01, TC-02, TC-03.
- **AC-3** (request appears with requester/rate/duration): TC-04, TC-05, TC-11.
- **AC-4** (Accept→active timer/cost; Decline): TC-06, TC-11, TC-14, TC-15.
- **AC-5** (End→summary; viewer-end reflected): TC-07, TC-08, TC-11, TC-15.
- **AC-6** (survive reconnect/process death via status): TC-05, TC-10, TC-15.
- **AC-7** (409/404 converge; 401 refresh): TC-08, TC-09, TC-12.
- **AC-8** (no viewer PII logged; redacted telemetry; ownership): TC-12, TC-13.
