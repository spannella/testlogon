---
id: AND-301
title: Call billing
milestone: M7
epic: E40
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-296, AND-031]
blocks: []
---

# AND-301 — Call billing

## 1. Overview & Goal

Some 1:1 voice/video calls in TestLogon are *paid*: the backend charges the
caller a per-minute rate (set by the creator/callee), drawn down from the
caller's wallet balance, and reports running cost + balance for the duration and
at teardown. This ticket adds the client-side billing layer on top of the
outgoing call flow delivered by AND-296 (`outgoing-call-flow`).

> CORRECTION (review AND-301): The original draft assumed a *pre-connect
> authorization-token* model (a `POST .../billing/authorize` that gates
> `Ringing → Connected`). **No such endpoint or token exists.** Verified against
> the OpenAPI index and the web reference (`src/api/endpoints/callBilling.ts`,
> `src/components/calls/*`): the real model is (1) the call invite carries flat
> `paid` / `rate_cents_per_minute` fields; (2) the caller confirms a *rate +
> minimum-balance* dialog (`RateNegotiationDialog`) before starting — a purely
> client-side balance check, not a server authorization mutation; (3) once
> connected, the client sends periodic **heartbeats** and the *backend*
> computes/returns the authoritative running cost, balance, and warnings; (4)
> the backend ends the call itself when balance is depleted or max duration is
> reached. Sections below are corrected to this model.

The goal is a `callBilling` capability in the `feature-call` module that:

1. Detects, from the call invite response, whether a call is paid
   (`paid == true`) and surfaces the **per-minute rate** to the user *before*
   start.
2. Shows a **paid-call confirm** step (rate + minimum-balance + estimated
   duration; `RateNegotiationDialog` equivalent) before the call starts. This is
   a client-side affordance/balance check, NOT a server-side authorization
   mutation. Cancelling does not start the call.
3. Renders a live **running cost** overlay while connected. The authoritative
   cost/balance comes from the periodic **heartbeat** response
   (`PATCH .../heartbeat` → `HeartbeatOut`); a local estimate may bridge between
   heartbeats. A **final cost** summary is shown on `Ended`.
4. Maps and surfaces billing-related conditions (low/depleted balance, max
   duration reached, heartbeat timeout) into the call `UiState`.

Non-goals: payment-method management, balance top-up, post-call receipts/history
screens, group-call split billing. Those are downstream/out of scope.

## 2. Context & References

- **Repo / module:** `spannella/testlogon`, branch `android-port`, app under
  `android/`. Code lands in `feature-call` with shared types in `core-model` and
  network in `core-network`. Namespace base `com.testlogon.android`
  (`com.testlogon.android.feature.call.billing`).
- **Stack:** Kotlin 2.0.21, Jetpack Compose + Material 3, Hilt (KSP), Retrofit
  2.11 / OkHttp 4.12 / Moshi 1.15, Coroutines/Flow, DataStore for prefs.
  minSdk 24 / compileSdk 35, JDK 17.
- **Depends on:**
  - **AND-296** (`outgoing-call-flow`) — owns the call state machine
    (`Idle → Inviting → Ringing → Connecting → Connected → Ending → Ended`),
    `CallViewModel`, `CallScreen`, and the call invite/connect/end endpoints.
    Billing hooks into that machine; it does not re-implement it.
  - **AND-031** (`LoginViewModel`) — establishes the cookie-based authenticated
    session (`POST /ui/session/start` → MFA → `/ui/session/finalize` →
    `/ui/me`) and the CSRF header convention. A valid `ui_csrf` session is a
    precondition for any billing call.
- **Auth model:** (Corrected against `src/api/client.ts`.) Requests carry **both**
  an `Authorization: Bearer <accessToken>` header (from the auth store) **and**
  the `ui_csrf` cookie echoed as the `X-CSRF-Token` header, with cookies sent via
  `credentials: include`. The web client sets `X-CSRF-Token` on **every** request
  when the cookie is present (not only mutating ones); the Android layer should
  match this. The call-domain endpoints additionally take an `authorization`
  header param and `X-SESSION-ID` (see OpenAPI params for
  `/messaging/messages/calls/*`). On `401` the network layer performs one
  `POST /ui/session/refresh` then retries the original request once (verified).
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable; see §7). OpenAPI at `/openapi.json`; FastAPI
  `detail` shapes (`string | [{msg}] | {code,...}`) decoded by the shared error
  mapper in `core-network`.
- **Web reference:** `frontend/src/api/endpoints/*.ts` and
  `frontend/src/api/types.ts` for the canonical billing field names; mirror the
  field naming there into the Moshi DTOs below.

## 3. Functional Requirements

FR-1. When an outgoing call's invite response indicates the call is paid
(`paid == true`, `rate_cents_per_minute != null`), the pre-start Ringing UI MUST
display the per-minute rate, the minimum balance required, and the caller's
wallet balance / estimated duration (`RateNegotiationDialog` equivalent).

FR-2. For a paid call the user MUST explicitly confirm before the call starts.
The default UI is a confirm dialog/sheet with **Start Paid Call** / **Cancel**
actions. Cancelling does not start the call. This is a local confirm + balance
check, not a server authorization request.

FR-3. For a non-paid call (`paid == false`), no confirm step is shown and the
existing AND-296 flow proceeds unchanged.

FR-4. While `Connected`, a running cost MUST be displayed and update at least
once per second. The authoritative figure is the backend heartbeat
`total_cost_cents`; between heartbeats a local estimate
(`ceil(elapsedSeconds/60) × rate_cents_per_minute`) MAY bridge, flagged as an
estimate. Display in currency (USD cents).

FR-5. On `Ended`, the final `total_cost_cents` (from the end flow or
`GET .../billing`) MUST be displayed; if unavailable, fall back to the last
locally computed estimate, labelled "estimated".

FR-6. Mid-call billing terminations (balance depleted, max duration reached,
heartbeat timeout) MUST end the call cleanly, surface an actionable message, and
show the final cost summary. The pre-start confirm MUST block starting when the
wallet balance is insufficient for the minimum.

FR-7. Heartbeat warnings (`warn_low_balance`, `max_duration_warning`) MUST be
surfaced in-call before the backend tears the call down.

FR-8. Billing state MUST survive configuration changes (rotation) and brief
process death during an active call (rehydrate from the call session).

## 4. Technical Design

New code in `com.testlogon.android.feature.call.billing`. The call FSM and
`CallViewModel` from AND-296 are extended, not replaced.

### 4.1 Domain model (`core-model`)

Field names below mirror the verified backend schemas (`CallInviteOut`,
`HeartbeatOut`, `CallBillingStatusOut`) — cents-per-minute, no minor/increment/
rate_version concepts.

```kotlin
// Derived from CallInviteOut: flat `paid` + nullable `rate_cents_per_minute`.
data class CallBilling(
    val paid: Boolean,
    val rateCentsPerMinute: Int,     // 0 when not paid
    val currency: String = "USD",    // NOTE: not returned by the call endpoints;
                                     // amounts are USD cents. Treat as assumption.
)

// Pre-start confirm step (RateNegotiationDialog equivalent). There is NO server
// authorization mutation; this is a local affordance + balance check only.
sealed interface PaidCallConfirmState {
    data object NotPaid : PaidCallConfirmState        // free call, no UI
    data object AwaitingConfirm : PaidCallConfirmState
    data object Confirmed : PaidCallConfirmState
    data object Cancelled : PaidCallConfirmState
}

// Conditions surfaced from heartbeat/end, NOT from an authorize call.
enum class BillingCondition {
    LOW_BALANCE,        // HeartbeatOut.warn_low_balance
    MAX_DURATION_WARNING, // HeartbeatOut.max_duration_warning
    BALANCE_DEPLETED,   // end reason "balance_depleted"
    MAX_DURATION_REACHED, // end reason "max_duration_reached"
    HEARTBEAT_TIMEOUT,  // end reason "heartbeat_timeout"
    NETWORK, UNKNOWN
}

// Authoritative figures come from the heartbeat/billing-status responses.
data class RunningCost(
    val elapsedSeconds: Long,
    val totalCostCents: Int,
    val balanceRemainingCents: Int,
    val minutesRemaining: Double,
    val isEstimate: Boolean,         // true only when bridging between heartbeats
)
```

### 4.2 Cost calculator (pure, unit-tested)

The calculator only produces a **display estimate** to bridge the gap between
heartbeats; the backend's `total_cost_cents` (from heartbeat / billing status) is
always authoritative and overwrites the estimate when it arrives.

```kotlin
object BillingCalculator {
    /** ceil(elapsedMinutes) * rateCentsPerMinute. Per-minute granularity is
     *  implied by `rate_cents_per_minute`; the backend defines the exact rounding
     *  (billing_cycle_count). This is an UNVERIFIED local approximation. */
    fun estimateCostCents(elapsedSeconds: Long, billing: CallBilling): Int {
        if (!billing.paid) return 0
        val minutes = ((elapsedSeconds + 59) / 60).coerceAtLeast(1)
        return (minutes * billing.rateCentsPerMinute).toInt()
    }

    /** USD cents → "$X.YY" (web reference uses cents/100 .toFixed(2)). Use
     *  NumberFormat for the device locale; default 2 fraction digits. */
    fun formatCents(cents: Int, currency: String = "USD"): String
}
```

`formatCents` mirrors the web reference (`$${cents/100}.toFixed(2)`) but should
use `NumberFormat.getCurrencyInstance` with `Currency.getInstance(currency)` for
locale-correct symbols/grouping. The call endpoints do not return a currency
code, so "USD" is the working assumption (see §16).

### 4.3 Repository (`core-data`)

```kotlin
interface CallBillingRepository {
    /** PATCH /messaging/messages/calls/{call_id}/heartbeat -> HeartbeatOut.
     *  Sent periodically while connected; backend bills and returns cost/balance. */
    suspend fun heartbeat(callId: String, clientTs: Long): ApiResult<HeartbeatOut>

    /** GET /messaging/messages/calls/{call_id}/billing -> CallBillingStatusOut.
     *  Final/spot billing snapshot (idempotent GET, retryable). */
    suspend fun billingStatus(callId: String): ApiResult<CallBillingStatusOut>
}
```

> CORRECTION: the draft's `authorize(...)` and `finalCost(...)` methods targeted
> non-existent endpoints. Replaced with the verified `heartbeat` and
> `billingStatus` calls.

Backed by `CallBillingApi` (Retrofit, §5). `ApiResult<T>` is the project-wide
sealed result (`Success | Error(ApiError) | NetworkError`).

### 4.4 ViewModel integration

`CallBillingDelegate` is `@AssistedInject`-constructed and held by the AND-296
`CallViewModel`; it owns billing sub-state and emits into the shared
`StateFlow<CallUiState>`.

```kotlin
class CallBillingDelegate @Inject constructor(
    private val repo: CallBillingRepository,
    private val clock: Clock,
) {
    val confirmState: StateFlow<PaidCallConfirmState>
    val runningCost: StateFlow<RunningCost?>
    val condition: StateFlow<BillingCondition?>

    fun onInvite(paid: Boolean, rateCentsPerMin: Int?)  // from CallInviteOut (FR-1)
    fun confirmPaidCall()                               // local confirm (FR-2)
    fun cancel()                                        // declines start, no call
    fun onConnected(connectedAtEpochSec: Long)          // starts heartbeat + 1Hz tick
    fun onHeartbeat(out: HeartbeatOut)                  // authoritative cost/balance
    fun onEnded(status: CallBillingStatusOut?, endReason: String?) // FR-5
}
```

> CORRECTION: `confirmAuthorization()` (which posted an auth token) is replaced by
> `confirmPaidCall()` — a local confirm that opens the start gate. There is no
> server authorization round-trip. `onHeartbeat` feeds the authoritative running
> cost.

`CallUiState` (defined in AND-296) gains a `billing: BillingUiSlice?` field so
billing is purely additive:

```kotlin
data class BillingUiSlice(
    val rateLabel: String?,         // "$0.05/min"
    val confirm: PaidCallConfirmState,
    val runningCost: String?,       // formatted (from heartbeat)
    val balanceLabel: String?,      // "Bal: $4.20"
    val finalCost: String?,         // formatted, set on Ended
    val finalIsEstimate: Boolean,
    val condition: BillingCondition?,
)
```

State precedence rule: billing **gates** start. The FSM may transition
`Ringing → Connecting` only when `confirmState ∈ {NotPaid, Confirmed}`. (No
server token is awaited — the gate is opened by the local `confirmPaidCall()`.)

### 4.5 Running-cost ticker

A `flow { while(true){ emit(now); delay(1.seconds) } }` started in `onConnected`,
scoped to `viewModelScope`, cancelled in `onEnded`. Elapsed is derived from
`clock.now() - connectedAt` (wall clock), not from tick count, so it stays
correct after backgrounding/missed ticks.

## 5. API Contract

> CORRECTION: This section originally described a nested `billing` object on the
> invite response plus `POST .../billing/authorize` and
> `GET .../billing/summary` endpoints. **None of those exist.** Verified against
> the OpenAPI index, `CallInviteOut`/`HeartbeatOut`/`CallBillingStatusOut`
> schemas, and `src/api/endpoints/callBilling.ts`. The corrected contract is
> below. The call domain is rooted at `/messaging/messages/calls/...` (NOT
> `/ui/calls/...`).

Billing reuses the AND-296 call endpoints (invite/end) and uses two
billing-specific endpoints (heartbeat + billing status). All paths require the
authenticated session (Bearer + cookies + `X-CSRF-Token`, plus the
`authorization` / `X-SESSION-ID` call headers). Exact field names mirror
`src/api/endpoints/callBilling.ts` and the OpenAPI schemas; confirm against
`/openapi.json` during implementation.

**Paid flags on the AND-296 invite response (`CallInviteOut`)** — flat fields,
no nested `billing` object:

```json
{
  "call_id": "c_8f3a...",
  "conversation_id": "...",
  "caller_user_id": "...",
  "callee_user_id": "...",
  "state": "ringing",
  "initial_mode": "audio",
  "start_ts": 1717600000,
  "paid": true,
  "rate_cents_per_minute": 5
}
```
For a free call, `paid` is `false` and `rate_cents_per_minute` is `null`.
(`CallInviteIn` accepts `paid` and `rate_cents_per_min` on the request side.)
There is **no** currency field on the call endpoints — amounts are USD cents.

**Heartbeat (authoritative running cost):**
`PATCH /messaging/messages/calls/{call_id}/heartbeat`
Body (`HeartbeatIn`):
```json
{ "client_ts": 1717600060 }
```
`200` (`HeartbeatOut`):
```json
{
  "call_id": "c_8f3a", "elapsed_seconds": 60, "total_cost_cents": 5,
  "rate_cents_per_minute": 5, "balance_remaining_cents": 495,
  "next_bill_in_seconds": 60, "minutes_remaining": 99.0,
  "warn_low_balance": false, "max_duration_warning": false, "action": "ok"
}
```
The client sends heartbeats periodically while connected; the backend bills and
returns the authoritative cost/balance/warnings. `action` may instruct the client
(e.g. terminate) — exact non-"ok" values are unverified (see §16).

**Billing status / final cost:**
`GET /messaging/messages/calls/{call_id}/billing`
`200` (`CallBillingStatusOut`; required fields `call_id`, `paid`; all others
default to 0/""):
```json
{
  "call_id": "c_8f3a", "paid": true, "rate_cents_per_minute": 5,
  "total_cost_cents": 15, "total_billed_seconds": 130,
  "billing_cycle_count": 3, "caller_balance_remaining_cents": 485,
  "platform_fee_bps": 0, "max_duration_seconds": 0, "elapsed_seconds": 130,
  "billing_status": ""
}
```
On `Ended`, read the final `total_cost_cents` from the end-call flow or this GET
(idempotent, retryable). If unavailable, fall back to the last local estimate
labelled "estimated" (FR-5).

The heartbeat is a `PATCH` (mutation) but is naturally repeated on a timer, so a
*missed* heartbeat is simply re-sent on the next tick rather than auto-retried
mid-tick. The billing-status `GET` is idempotent and participates in bounded
backoff retry (§7). End reasons observed in the web reference:
`ended`, `balance_depleted`, `max_duration_reached`, `heartbeat_timeout`.

**Rate negotiation (creator side, present in web ref, not in the index):**
`negotiateCallRate` posts `POST /messaging/messages/calls/{call_id}/rate`
with `{ "rate_cents_per_minute": N }`. Per-creator default rate is managed via
`/ui/calls/rates` (`CallRateIn`/`CallRateOut`). Out of scope for the caller-side
billing display but noted for completeness.

## 6. Data & State Management

- Source of truth: in-memory `CallUiState.billing` for the active call;
  billing has no persistent cache (per-call ephemeral).
- The active call session (call_id, paid flag, rate_cents_per_minute,
  connectedAt, last HeartbeatOut snapshot) is held by the AND-296 call session
  holder; billing rehydrates from it after rotation or short process death
  (FR-8). No Room table is introduced. (No authId/auth token exists in this
  model.)
- DataStore: a single boolean pref
  `call_billing_prompt_seen` (`core-data` prefs) to optionally suppress a
  one-time explainer; not used to bypass per-call authorization.
- Running cost shown is the latest backend `total_cost_cents` (from heartbeat /
  billing status); between heartbeats a local estimate may be derived from
  `connectedAt` and `rateCentsPerMinute` and flagged `isEstimate`.
- Thread-safety: all billing state mutated on the main dispatcher via the
  ViewModel; the ticker uses `flowOn(Dispatchers.Default)` only for the delay
  loop, mapping back through `viewModelScope`.

## 7. Error Handling & Resilience

> CORRECTION: rewritten to remove the non-existent authorize/summary endpoints,
> the `402/403/409` auth error mappings, `rate_version`, and `expires_at`. The
> real resilience surface is the heartbeat loop + billing-status GET.

- **Timeouts:** heartbeat and billing-status use the project default ~20s OkHttp
  timeout against the unreliable dev host (§2).
- **Heartbeat loop:** heartbeats are sent on a timer while connected. A single
  failed/timed-out heartbeat is logged and retried on the next scheduled tick
  (not mid-tick). The backend ends a call whose heartbeats stop
  (`heartbeat_timeout`), so the client must surface `HEARTBEAT_TIMEOUT` if the
  call is torn down for that reason.
- **Retry policy:** the billing-status `GET` is idempotent and uses bounded
  exponential backoff (max 3 attempts, jittered). The heartbeat `PATCH` is not
  retried within a tick (the next tick supersedes it).
- **401 handling:** inherited — the network layer does one
  `POST /ui/session/refresh` then retries the original request once (verified in
  `src/api/client.ts`).
- **Insufficient balance before start:** the pre-start confirm computes
  `required = rate × min_balance_minutes` vs the caller's wallet balance and
  disables "Start Paid Call" when insufficient (matches `RateNegotiationDialog`).
  Wallet balance is fetched separately (`/ui/billing/balance` /
  `/ui/billing/wallet`); the call endpoints do not gate on balance at invite.
- **Balance depleted / max duration mid-call:** the backend ends the call and
  the end reason is `balance_depleted` / `max_duration_reached`; the client maps
  these to `BillingCondition` and shows the summary (FR-6). Heartbeat
  `warn_low_balance` / `max_duration_warning` drive in-call warnings before
  teardown.
- **Network error on billing-status:** show final cost as the last local estimate
  with `finalIsEstimate = true` (FR-5).
- **Negative/overflow guards:** `elapsedSeconds` clamped to ≥0; cost handled in
  integer cents (no floating point) to avoid rounding drift.

## 8. Security & Privacy

- All billing requests require the authenticated session: `Authorization: Bearer`
  + cookies (`credentials: include`) + `X-CSRF-Token` (echoed from `ui_csrf`),
  plus the call-domain `authorization` / `X-SESSION-ID` headers. The web client
  sends `X-CSRF-Token` on every request when the cookie is present, so the
  heartbeat `PATCH` and billing-status `GET` both carry it.
- No payment instrument data (card/PAN, balance) is requested, stored, or logged
  by this ticket — the client only handles per-call rate/cost figures.
- Cost/rate values are not written to disk; they live only in memory for the
  active call. The persistent cookie jar (required by the auth model) is the only
  persisted sensitive artifact and is owned by `core-network`, not here.
- Dev backend is plaintext HTTP — acceptable only for the dev host; production
  config MUST enforce HTTPS (cleartext allowed for the dev IP via network
  security config, owned by the network module).
- The paid-call confirm action is an explicit, user-initiated step (local gate) —
  never auto-confirmed, never bypassed by a stored pref. (It is not a server
  mutation; it only opens the local start gate.)

## 9. Accessibility & i18n

- Rate, running cost, and final cost are real text nodes with Compose
  `semantics`/`contentDescription` (e.g. "Billed at 5 cents per minute,
  current cost 15 cents"), not icon-only. The running cost has a polite
  `liveRegion` so updates are announced without spamming (announce on increment
  change, not every second).
- All currency formatting via `java.util.Currency` + `NumberFormat` for the
  device locale's grouping/decimal symbols, with the call's currency code.
- All strings in `strings.xml` with placeholders (`%1$s` rate, `%2$s` cost);
  no concatenation. Plurals for "minute(s)" via `plurals`.
- Confirm sheet buttons meet 48dp touch targets and Material 3 contrast; the
  sheet is dismissible and focus-managed for TalkBack.

## 10. Telemetry & Logging

- Events (via the project analytics interface, names lower_snake):
  `call_billing_shown {call_id, rate_cents_per_minute}`,
  `call_billing_confirmed {call_id, rate_cents_per_minute}`,
  `call_billing_condition {call_id, condition}` (low_balance / balance_depleted /
  max_duration_reached / heartbeat_timeout),
  `call_billing_final {call_id, total_cost_cents, is_estimate}`.
- Logging: `Timber` at `d` for state transitions; `w` for billing errors. Never
  log full request/response bodies of heartbeat/billing-status (they include
  balance context). Redact to codes/booleans only.
- Crash reporting attaches the current `PaidCallConfirmState` / `BillingCondition`
  name (not amounts) as a breadcrumb.

## 11. Testing Strategy

Unit (JUnit + Turbine + MockWebServer, in `core-testing`):
- `BillingCalculator`: per-minute rounding estimate (0s, 1s, 59s, 60s, 61s,
  120s), `paid == false` → 0, cents→string formatting.
- `CallBillingDelegate`: `onInvite(paid=false)` → `NotPaid`; `onInvite(paid=true)`
  → `AwaitingConfirm`; `confirmPaidCall()` → `Confirmed` and gate opens;
  `onHeartbeat` updates authoritative cost/balance and `warn_low_balance` /
  `max_duration_warning` → `BillingCondition`; `onEnded` with/without
  `total_cost_cents` (estimate fallback); end reasons map to conditions.
- Ticker: `Clock`-injected fake advances time; estimate updates and is wall-clock
  derived (correct after a simulated gap); heartbeat value overrides estimate.
- Repository: `MockWebServer` for heartbeat (next-tick re-send on 5xx, no
  mid-tick retry) and billing-status GET (retry/backoff on 5xx, succeeds on 3rd).
- FSM gating: start blocked while `AwaitingConfirm`/`Cancelled`; allowed on
  `Confirmed`/`NotPaid`.

Instrumented (Compose UI test):
- Confirm dialog shows correct rate label and **Start Paid Call**/Cancel; Cancel
  does not start the call; Start disabled on insufficient balance.
- Running cost label updates from heartbeat; final cost shown on Ended; estimate
  label shown on billing-status failure.
- Semantics/liveRegion assertions for accessibility.

## 12. Dependencies & Sequencing

- **Blocked by AND-296** — requires the call FSM, `CallViewModel`, `CallScreen`,
  and the invite/end endpoints to attach to. Cannot start until the `paid` /
  `rate_cents_per_minute` fields on `CallInviteOut` and the heartbeat loop are
  wired into the call session.
- **Blocked by AND-031** — requires the authenticated cookie/CSRF session.
- **Network prerequisites:** the shared `ApiResult`, FastAPI `detail` error
  mapper, persistent cookie jar, and 401-refresh authenticator (owned by
  `core-network`) must be in place.
- **Blocks:** none currently. Any future post-call receipt/billing-history
  ticket would depend on this.
- Sequencing within the ticket: (1) DTOs + calculator + repo (pure, testable),
  (2) delegate + state wiring, (3) Compose confirm sheet + cost overlay,
  (4) error mapping + accessibility + telemetry.

## 13. Risks & Open Questions

- **Resolved (this review):** Field names confirmed against `CallInviteOut`,
  `HeartbeatOut`, `CallBillingStatusOut` and `src/api/endpoints/callBilling.ts`:
  flat `paid` + `rate_cents_per_minute`, cents-based, no nested billing object,
  no `authorize`/`summary` endpoints. Moshi `@Json(name=...)` per §5.
- **Q:** Does the AND-296 end-call response carry `total_cost_cents`, or must the
  client always call `GET .../billing`? `CallActionOut`/`CallEndIn` were not
  fully audited; default to the billing-status GET on end. (Open.)
- **Q:** Exact billing rounding rule (`billing_cycle_count` semantics) and the
  meaning of `next_bill_in_seconds` / non-"ok" `action` values from heartbeat —
  not documented in schemas. The local estimate is best-effort only; trust the
  backend `total_cost_cents`. (Open.)
- **Q:** Currency — call endpoints return no currency code; `CallRate` (creator
  rate) has a `currency` field but the call-billing responses use bare cents.
  Assume USD; confirm. (Open.)
- **Risk:** Client running cost diverging from backend (clock skew, billing-cycle
  boundaries). Mitigated by labelling the bridge value an estimate and always
  trusting heartbeat/billing-status figures.
- **Q:** Wallet balance source for the pre-start confirm — web uses a separately
  fetched wallet/balance; confirm whether `/ui/billing/balance` or
  `/ui/billing/wallet` is the canonical source for the Android confirm dialog.
- **Open:** Should free-tier users see a "free call" affordance, or nothing?
  Assume nothing (FR-3) unless product specifies.

## 14. Acceptance Criteria

AC-1. (Backlog) A paid call shows its rate and requires an explicit confirm: the
Ringing/pre-start UI displays the per-minute rate, and the call start is gated
behind an explicit **Start Paid Call** confirm (local affordance, not a server
authorization). Verified by Compose UI test.

AC-2. A non-paid call (`paid == false`) connects with no billing UI and no
behavior change vs AND-296. Verified by UI + delegate unit test (`NotPaid`).

AC-3. While connected, a running cost is shown and updates at least once per
second; the authoritative value comes from the heartbeat `total_cost_cents`, with
a local estimate bridging between heartbeats, formatted as currency (USD cents).
Verified by ticker + calculator unit tests and a UI test.

AC-4. On Ended, the backend's final `total_cost_cents` (from end flow or
`GET .../billing`) is displayed; on billing-status failure the last estimate is
shown labelled "estimated". Verified by unit tests for both paths.

AC-5. Mid-call billing conditions are surfaced: heartbeat `warn_low_balance` /
`max_duration_warning` show in-call warnings, and end reasons
`balance_depleted` / `max_duration_reached` / `heartbeat_timeout` map to the
correct `BillingCondition` and end the call cleanly. The pre-start confirm
disables start when wallet balance < rate × min-balance-minutes. Verified by
`MockWebServer` + delegate unit tests.

AC-6. The billing-status GET retries with bounded backoff; a failed heartbeat is
re-sent on the next tick (not auto-retried mid-tick). Verified by `MockWebServer`
request-count assertions.

AC-7. Billing state survives rotation and rehydrates after short process death
during an active connected call. Verified by instrumented test.

AC-8. Cost/rate text exposes correct semantics and a polite live region;
currency formatting follows device locale. Verified by accessibility UI test.

## 15. Definition of Done

- All FRs and ACs met; new code in `feature-call.billing`, `core-model`,
  `core-data`, `core-network` per layering (`app → feature-* → core-*`).
- Package `com.testlogon.android.feature.call.billing` throughout.
- Unit + instrumented tests pass in CI; calculator and delegate ≥ 90% line
  coverage; ticket-level coverage gate green.
- No Detekt/ktlint violations; no new lint errors; cleartext config unchanged.
- Strings externalized + extracted for translation; accessibility checks pass.
- Telemetry events fire with redacted payloads (no balance/PII logged).
- DTO field names verified against `/openapi.json` and the web reference;
  open questions in §13 either resolved or filed as follow-up tickets.
- PR on `android-port` reviewed and merged; demo: a paid outgoing 1:1 call shows
  rate, the user confirms (Start Paid Call), running cost updates from heartbeat,
  and the final cost summary shows on end.

## 16. Citations & Assumption Audit

Sources: OpenAPI index `reference/openapi.index.txt`, full spec
`reference/openapi.pretty.json` (`components.schemas.<Name>`), and the web
reference under `reference/src/`.

1. **Call billing endpoint base is `/messaging/messages/calls/...`, not
   `/ui/calls/...`.** VERDICT: Corrected. SOURCE: OpenAPI
   `GET /messaging/messages/calls/{call_id}/billing`,
   `PATCH /messaging/messages/calls/{call_id}/heartbeat`;
   `src/api/endpoints/callBilling.ts: getCallBilling, sendCallHeartbeat`.
2. **A `POST /ui/calls/{call_id}/billing/authorize` endpoint with an auth token
   gates connect.** VERDICT: Corrected (endpoint does not exist). SOURCE: absent
   from OpenAPI index (only `/messaging/messages/calls/{call_id}/billing` +
   `/heartbeat` exist); `src/api/endpoints/callBilling.ts` has no authorize call;
   web gate is `src/components/calls/RateNegotiationDialog.tsx` (local balance
   check, button "Start Paid Call").
3. **A `GET /ui/calls/{call_id}/billing/summary` endpoint returns the final
   cost.** VERDICT: Corrected (does not exist). SOURCE: final/spot cost comes from
   `GET /messaging/messages/calls/{call_id}/billing` → `CallBillingStatusOut`.
4. **The invite/connect response carries a nested `billing` object
   (`billed`, `rate_per_increment_minor`, `increment_seconds`,
   `authorization_required`, `estimated_minimum_minor`, `rate_version`).**
   VERDICT: Corrected. SOURCE: `CallInviteOut` schema has flat `paid` (bool) and
   `rate_cents_per_minute` (nullable int) only; `CallInviteIn` has `paid` and
   `rate_cents_per_min`. No nested object, no minor/increment/rate_version fields.
5. **Cost is in "minor units per increment".** VERDICT: Corrected — billing is
   `rate_cents_per_minute` (USD cents, per minute). SOURCE: `CallBillingStatusOut`,
   `HeartbeatOut`, `CallInviteOut`; web `formatDollars(cents)` = `cents/100`.
6. **Final cost field is `billed_minor`.** VERDICT: Corrected → `total_cost_cents`.
   SOURCE: `CallBillingStatusOut.total_cost_cents`, `HeartbeatOut.total_cost_cents`.
7. **Running cost is computed locally as the authoritative figure
   (`ceil(elapsed/increment) × rate`).** VERDICT: Corrected — the backend
   heartbeat returns the authoritative `total_cost_cents`; local value is only an
   inter-heartbeat estimate. SOURCE: `HeartbeatOut`
   (`total_cost_cents`, `balance_remaining_cents`, `next_bill_in_seconds`);
   `src/components/calls/CallBillingOverlay.tsx` renders backend `totalCostCents`.
8. **Heartbeat mechanism (`PATCH .../heartbeat` with `{client_ts}` →
   cost/balance/warnings).** VERDICT: Verified. SOURCE: OpenAPI
   `PATCH /messaging/messages/calls/{call_id}/heartbeat`, `HeartbeatIn`/
   `HeartbeatOut` schemas; `src/api/endpoints/callBilling.ts: sendCallHeartbeat`.
9. **Billing-specific error codes/HTTP: `402 insufficient_balance`,
   `403 auth_declined`, `409 rate_changed`.** VERDICT: Corrected
   (Unverified/fabricated). SOURCE: no such codes anywhere in `reference/`; the
   billing endpoints declare only `200` + `422 HTTPValidationError`. Real
   mid-call terminations use end reasons `balance_depleted`,
   `max_duration_reached`, `heartbeat_timeout`
   (`src/components/calls/CallBillingSummary.tsx: humanizeEndReason`).
10. **Pre-start insufficient-balance gating.** VERDICT: Verified (client-side).
    SOURCE: `RateNegotiationDialog.tsx` (`required = rate × min_balance_minutes`,
    `hasSufficientBalance`, Start button disabled). `CallRate` exposes
    `min_balance_minutes`, `max_duration_minutes` (`callBilling.ts: CallRate`).
11. **Auth: cookie session + `X-CSRF-Token` (echoed `ui_csrf`) on mutating
    requests only.** VERDICT: Corrected. SOURCE: `src/api/client.ts` sends
    `Authorization: Bearer <accessToken>` AND `X-CSRF-Token` (from `ui_csrf`
    cookie) on **every** request with `credentials: include`; call endpoints also
    take `authorization` + `X-SESSION-ID` params (OpenAPI params for
    `/messaging/messages/calls/*`).
12. **On 401, one `POST /ui/session/refresh` then a single retry.** VERDICT:
    Verified. SOURCE: `src/api/client.ts: refreshSession` + single retry block.
13. **FastAPI `detail` shapes (`string | [{msg}] | {code,...}`) decoded by a
    shared mapper.** VERDICT: Verified. SOURCE: `src/api/client.ts:
    normalizeErrorDetail` / `mapAuthorizationError`; `HTTPValidationError` in
    OpenAPI.
14. **Rate negotiation `POST /messaging/messages/calls/{call_id}/rate`.**
    VERDICT: Verified (web wrapper); Unverified in OpenAPI index. SOURCE:
    `src/api/endpoints/callBilling.ts: negotiateCallRate`; not present in
    `openapi.index.txt` (likely a creator-side route). Out of scope for caller
    billing display.
15. **Stack/framework choices (Compose, Material 3 `liveRegion`, `NumberFormat`/
    `java.util.Currency`, Robolectric, MockWebServer, Compose UI test).** VERDICT:
    Unverified-assumption (framework ref — project/tooling conventions, not in the
    backend/web sources). framework ref: Jetpack Compose accessibility
    (`developer.android.com/jetpack/compose/accessibility`), `MockWebServer`
    (`github.com/square/okhttp/tree/master/mockwebserver`).

### Corrections made
- §1/§3/§5/§7/§8/§14: removed the non-existent pre-connect *authorization-token*
  model; replaced with the verified *creator-rate + wallet-balance + heartbeat*
  model and a local "Start Paid Call" confirm.
- §5: replaced fabricated `POST .../billing/authorize` and
  `GET .../billing/summary` with `PATCH .../heartbeat` and `GET .../billing`;
  corrected the call base path to `/messaging/messages/calls/...`; replaced the
  nested `billing` object with flat `paid` / `rate_cents_per_minute`.
- §4.1–§4.4: domain model, calculator, repository, and delegate rewritten to
  cents/per-minute/heartbeat field names (`total_cost_cents`,
  `rate_cents_per_minute`, `balance_remaining_cents`, etc.); removed
  `BillingAuthState`/`rate_version`/`authId`/`expires_at`.
- §2/§8: corrected auth model to Bearer + cookies + `X-CSRF-Token` on all
  requests (+ `authorization`/`X-SESSION-ID` call headers).
- §7: removed `402/403/409` mappings and `expires_at`; documented heartbeat-loop
  resilience and backend-driven end reasons.
- §10/§11/§13/§14: telemetry field names, test cases, and ACs realigned.

### Open assumptions
- **Currency = USD.** The call billing endpoints return bare cents with no
  currency code (`CallBillingStatusOut`, `HeartbeatOut`); only the creator
  `CallRate` carries a `currency` field. Unverifiable from the call responses.
- **Final cost on end.** Whether the AND-296 end response (`CallActionOut`/
  `CallEndIn`) carries `total_cost_cents` was not fully audited; the spec defaults
  to a billing-status GET on end. Needs confirmation against the end-call schema.
- **Billing rounding rule** (`billing_cycle_count` semantics, first-minute
  charging) and **non-"ok" `HeartbeatOut.action` values** are undocumented in the
  schemas; the local estimate is best-effort only.
- **Wallet balance source** for the pre-start confirm (web fetches it separately;
  likely `/ui/billing/balance` or `/ui/billing/wallet`) — not wired through the
  call endpoints.
- **Framework/tooling choices** (Compose, Hilt, Robolectric, MockWebServer) are
  project conventions, not derivable from the backend/web reference.

## 17. Test Plan

Acceptance traces refer to §14 (AC-1..AC-8). "Physical device" = Samsung Galaxy
A15 5G (SM-A156U, API 34, arm64-v8a, serial R5CX821TA9R); "emulator" = AVD
`test35` (API 35, x86_64). Pure logic/contract/Compose-semantics cases run on
JVM/Robolectric or the emulator; only real-audio/WebRTC call behavior requires the
physical device.

- **TC-AND-301-01** — Type: unit (JVM). Target: `BillingCalculator`.
  Preconditions: none. Steps: call `estimateCostCents` for elapsed
  {0,1,59,60,61,120}s at `rate_cents_per_minute = 5`; and `paid = false`. Expected:
  paid=false → 0; 0/1/59/60s → 5; 61/120s → 10 (ceil minutes, ≥1). `formatCents(15)`
  → "$0.15". Traces: AC-3.
- **TC-AND-301-02** — Type: unit (JVM). Target: `CallBillingDelegate`.
  Preconditions: fresh delegate. Steps: `onInvite(paid=false, rate=null)`. Expected:
  `confirmState = NotPaid`, no rate label, start gate open, no billing UI slice.
  Traces: AC-2.
- **TC-AND-301-03** — Type: unit (JVM). Target: `CallBillingDelegate`.
  Preconditions: fresh delegate. Steps: `onInvite(paid=true, rate=5)` →
  `confirmPaidCall()`. Expected: `AwaitingConfirm` then `Confirmed`; rate label
  "$0.05/min"; start gate opens only after confirm. Traces: AC-1.
- **TC-AND-301-04** — Type: Compose-UI (Robolectric/emulator). Target: paid-call
  confirm dialog (`RateNegotiationDialog` equivalent). Preconditions: paid call,
  wallet balance ≥ required. Steps: render; tap **Start Paid Call**. Expected:
  dialog shows rate, minimum balance, wallet, estimated duration; Start enabled;
  tapping confirms start. Traces: AC-1.
- **TC-AND-301-05** — Type: Compose-UI (emulator). Target: confirm dialog,
  insufficient balance. Preconditions: wallet balance < rate × min_balance_minutes.
  Steps: render; attempt Start. Expected: "insufficient balance" message; **Start
  Paid Call** disabled; call not started. Traces: AC-1, AC-5.
- **TC-AND-301-06** — Type: contract/MockWebServer. Target: `CallBillingRepository.
  heartbeat`. Preconditions: MockWebServer enqueues a `HeartbeatOut`
  (`total_cost_cents=5, balance_remaining_cents=495, warn_low_balance=false`).
  Steps: call `heartbeat(callId, clientTs)`. Expected: request is
  `PATCH /messaging/messages/calls/{id}/heartbeat` with `{client_ts}` body and
  `X-CSRF-Token` header; parsed fields match. Traces: AC-3.
- **TC-AND-301-07** — Type: unit (JVM) + Compose-UI. Target: delegate ticker +
  overlay. Preconditions: injected fake `Clock`; connected at t0. Steps: advance
  clock, deliver `onHeartbeat(total_cost_cents=10)` mid-interval. Expected: running
  cost shows backend value (10) overriding the local estimate; updates ≥1×/sec;
  wall-clock derived after a simulated gap. Traces: AC-3.
- **TC-AND-301-08** — Type: contract/MockWebServer. Target: `billingStatus` retry.
  Preconditions: server returns 503,503,then 200 `CallBillingStatusOut`. Steps:
  call `billingStatus`. Expected: bounded backoff, succeeds on 3rd attempt
  (request-count = 3); `total_cost_cents` parsed. Traces: AC-4, AC-6.
- **TC-AND-301-09** — Type: unit (JVM). Target: `onEnded` final-cost paths.
  Preconditions: connected; last estimate = 12. Steps: (a) `onEnded(status with
  total_cost_cents=15)`; (b) `onEnded(status=null)` after a billing-status failure.
  Expected: (a) final "$0.15", `finalIsEstimate=false`; (b) final "$0.12",
  `finalIsEstimate=true`, "estimated" label. Traces: AC-4.
- **TC-AND-301-10** — Type: unit (JVM). Target: delegate condition mapping.
  Preconditions: connected. Steps: deliver `onHeartbeat(warn_low_balance=true,
  minutes_remaining=0.5)`, then end with reasons `balance_depleted`,
  `max_duration_reached`, `heartbeat_timeout`. Expected: low-balance warning shown;
  end reasons map to `BALANCE_DEPLETED` / `MAX_DURATION_REACHED` /
  `HEARTBEAT_TIMEOUT`; call ends cleanly and summary renders. Traces: AC-5.
- **TC-AND-301-11** — Type: contract/MockWebServer. Target: 401 refresh + auth
  headers. Preconditions: server returns 401 then 200; valid `ui_csrf` cookie and
  bearer token configured. Steps: call `billingStatus`. Expected: one
  `POST /ui/session/refresh` then a single retry; both attempts carry
  `Authorization: Bearer` and `X-CSRF-Token`. Traces: AC-6 (security/auth).
- **TC-AND-301-12** — Type: instrumented/e2e (emulator). Target: state survival.
  Preconditions: paid call connected, last heartbeat applied. Steps: rotate device;
  trigger short process death + restore. Expected: billing slice (rate, last
  cost/balance, confirm=Confirmed) rehydrates from the call session; no
  re-confirm prompt. Traces: AC-7.
- **TC-AND-301-13** — Type: Compose-UI accessibility (emulator). Target: cost/rate
  semantics. Preconditions: connected paid call. Steps: assert semantics on rate,
  running cost, balance; assert running cost is a polite `liveRegion` announcing on
  value change (not every second); verify 48dp confirm-button targets and
  locale-formatted currency. Traces: AC-8.
- **TC-AND-301-14** — Type: instrumented/e2e (PHYSICAL DEVICE — required). Target:
  end-to-end paid call. Rationale: needs real WebRTC audio + sustained heartbeat
  delivery over a real network; emulator audio/WebRTC is unreliable. Preconditions:
  test creator with a per-minute rate, caller wallet funded, physical device.
  Steps: place a paid 1:1 call; confirm Start Paid Call; stay connected ~3 min;
  observe running cost climb via heartbeats; end the call. Expected: rate shown
  pre-start, running cost tracks `total_cost_cents`, low-balance warning when it
  triggers, final summary with `total_cost_cents` + duration on end. Traces: AC-1,
  AC-3, AC-4, AC-5.
- **TC-AND-301-15** — Type: integration (emulator, flaky-host/offline). Target:
  heartbeat-loop resilience against the unreliable dev host. Preconditions: connected
  paid call; toggle network/host failures between ticks. Steps: drop one heartbeat
  (timeout), restore for the next tick; then force billing-status failure on end.
  Expected: dropped heartbeat is not retried mid-tick and is superseded next tick;
  no crash; on end, last estimate shown labelled "estimated". Traces: AC-4, AC-6.

### Coverage matrix
| AC | Covered by |
| --- | --- |
| AC-1 (paid shows rate + confirm gate) | TC-03, TC-04, TC-05, TC-14 |
| AC-2 (non-paid: no billing UI) | TC-02 |
| AC-3 (running cost from heartbeat) | TC-01, TC-06, TC-07, TC-14 |
| AC-4 (final cost / estimate fallback) | TC-08, TC-09, TC-15 |
| AC-5 (conditions: low/depleted/max/timeout) | TC-05, TC-10, TC-14 |
| AC-6 (status retries; heartbeat next-tick; auth) | TC-08, TC-11, TC-15 |
| AC-7 (state survives rotation/process death) | TC-12 |
| AC-8 (a11y semantics + locale formatting) | TC-13 |
