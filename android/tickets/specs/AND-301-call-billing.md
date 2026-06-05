---
id: AND-301
title: Call billing
milestone: M7
epic: E40
priority: P2
size: M
status: draft
depends_on: [AND-296, AND-031]
blocks: []
---

# AND-301 — Call billing

## 1. Overview & Goal

Some 1:1 voice/video calls in TestLogon are *billed*: the backend charges the
caller a per-minute rate that must be authorized before the call connects and
displayed (running cost + final cost) for the duration and at teardown. This
ticket adds the client-side billing layer on top of the outgoing call flow
delivered by AND-296 (`outgoing-call-flow`).

The goal is a `callBilling` capability in the `feature-call` module that:

1. Detects, from the call invite/connect responses, whether a call is billable
   and surfaces the **per-minute rate + currency** to the user *before* connect.
2. Requires explicit **billing authorization** (a confirm step that posts an
   authorization token to the backend) when the call is billed, gating the
   transition from `Ringing` to `Connected`.
3. Renders a live **running cost** overlay while connected (rate × elapsed
   minutes, rounded per the backend rounding rule) and a **final cost** summary
   on `Ended`.
4. Maps and surfaces billing-specific errors (insufficient balance, auth
   declined, rate changed) into the call `UiState`.

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
- **Auth model:** Session rides on cookies; the `ui_csrf` cookie is echoed as
  the `X-CSRF-Token` header on mutating requests (billing authorize is mutating).
  On `401` the network layer performs one `POST /ui/session/refresh` then retries.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable; see §7). OpenAPI at `/openapi.json`; FastAPI
  `detail` shapes (`string | [{msg}] | {code,...}`) decoded by the shared error
  mapper in `core-network`.
- **Web reference:** `frontend/src/api/endpoints/*.ts` and
  `frontend/src/api/types.ts` for the canonical billing field names; mirror the
  field naming there into the Moshi DTOs below.

## 3. Functional Requirements

FR-1. When an outgoing call's invite/connect response indicates the call is
billable (`billing != null`), the pre-connect Ringing UI MUST display the rate,
currency, billing increment, and an estimated minimum charge.

FR-2. For a billed call the user MUST explicitly authorize billing before audio
connects. The default UI is an inline confirm sheet on the Ringing screen with
**Authorize & connect** / **Cancel** actions. Cancelling ends the call (no
charge).

FR-3. For a non-billed call (`billing == null`), no authorization step is shown
and the existing AND-296 flow proceeds unchanged.

FR-4. While `Connected`, a running cost MUST be displayed and update at least
once per second, computed locally as
`ceil(elapsedSeconds / incrementSeconds) * ratePerIncrement`, formatted in the
call's currency. The displayed running cost is an *estimate*; the authoritative
amount is the backend's final figure.

FR-5. On `Ended`, the final billed amount returned by the end-call response MUST
be displayed; if the backend omits it, fall back to the last locally computed
estimate, labelled "estimated".

FR-6. Authorization failures (insufficient balance, declined, rate-changed) MUST
keep the call from connecting, show an actionable message, and end the call
cleanly without leaving a half-open billed session.

FR-7. If the backend reports a **rate change** between invite and authorize, the
user MUST be re-prompted with the new rate before connect.

FR-8. Billing state MUST survive configuration changes (rotation) and brief
process death during an active call (rehydrate from the call session).

## 4. Technical Design

New code in `com.testlogon.android.feature.call.billing`. The call FSM and
`CallViewModel` from AND-296 are extended, not replaced.

### 4.1 Domain model (`core-model`)

```kotlin
data class CallBilling(
    val billed: Boolean,
    val currency: String,            // ISO-4217, e.g. "USD"
    val ratePerIncrementMinor: Long, // minor units (cents) per increment
    val incrementSeconds: Int,       // billing granularity, e.g. 60
    val authorizationRequired: Boolean,
    val estimatedMinimumMinor: Long, // pre-auth minimum charge
    val rateVersion: String,         // opaque; changes invalidate prior auth
)

sealed interface BillingAuthState {
    data object NotRequired : BillingAuthState
    data object Pending : BillingAuthState            // awaiting user confirm
    data object Authorizing : BillingAuthState        // request in flight
    data class Authorized(val authId: String) : BillingAuthState
    data class Failed(val reason: BillingError) : BillingAuthState
}

enum class BillingError {
    INSUFFICIENT_BALANCE, AUTH_DECLINED, RATE_CHANGED, EXPIRED, NETWORK, UNKNOWN
}

data class RunningCost(
    val elapsedSeconds: Long,
    val amountMinor: Long,
    val currency: String,
    val isEstimate: Boolean,
)
```

### 4.2 Cost calculator (pure, unit-tested)

```kotlin
object BillingCalculator {
    /** ceil(elapsed/increment) * rate; first increment charged on connect. */
    fun runningCostMinor(elapsedSeconds: Long, billing: CallBilling): Long {
        val inc = billing.incrementSeconds.coerceAtLeast(1)
        val units = ((elapsedSeconds + inc - 1) / inc).coerceAtLeast(1)
        return units * billing.ratePerIncrementMinor
    }

    fun formatMinor(amountMinor: Long, currency: String): String // java.util.Currency
}
```

`formatMinor` uses `Currency.getInstance(currency).defaultFractionDigits` to scale
minor units; falls back to 2 digits on unknown currency code.

### 4.3 Repository (`core-data`)

```kotlin
interface CallBillingRepository {
    suspend fun authorize(callId: String, rateVersion: String): ApiResult<BillingAuthorization>
    suspend fun finalCost(callId: String): ApiResult<CallBillingSummary>
}
```

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
    val authState: StateFlow<BillingAuthState>
    val runningCost: StateFlow<RunningCost?>

    fun onCallNegotiated(billing: CallBilling?)        // from invite/connect resp
    fun confirmAuthorization()                         // FR-2
    fun cancel()
    fun onConnected(connectedAtEpochSec: Long)         // starts 1Hz tick
    fun onEnded(summary: CallBillingSummary?)          // FR-5
}
```

`CallUiState` (defined in AND-296) gains a `billing: BillingUiSlice?` field so
billing is purely additive:

```kotlin
data class BillingUiSlice(
    val rateLabel: String?,         // "$0.05 / min"
    val auth: BillingAuthState,
    val runningCost: String?,       // formatted
    val finalCost: String?,         // formatted, set on Ended
    val finalIsEstimate: Boolean,
    val error: BillingError?,
)
```

State precedence rule: billing **gates** connect. The FSM may transition
`Ringing → Connecting` only when `authState ∈ {NotRequired, Authorized}`.

### 4.5 Running-cost ticker

A `flow { while(true){ emit(now); delay(1.seconds) } }` started in `onConnected`,
scoped to `viewModelScope`, cancelled in `onEnded`. Elapsed is derived from
`clock.now() - connectedAt` (wall clock), not from tick count, so it stays
correct after backgrounding/missed ticks.

## 5. API Contract

Billing reuses the AND-296 call endpoints for invite/connect/end (which carry the
`billing` object) and adds two endpoints. All paths are under the cookie session;
mutating requests send `X-CSRF-Token`. Exact field names mirror
`frontend/src/api/types.ts`; confirm against `/openapi.json` during
implementation.

**Billing object embedded in the AND-296 connect/invite response:**

```json
{
  "call_id": "c_8f3a...",
  "state": "ringing",
  "billing": {
    "billed": true,
    "currency": "USD",
    "rate_per_increment_minor": 5,
    "increment_seconds": 60,
    "authorization_required": true,
    "estimated_minimum_minor": 5,
    "rate_version": "rv_2026_05"
  }
}
```
When the call is free, `billing` is `null` or `{"billed": false}`.

**Authorize:** `POST /ui/calls/{call_id}/billing/authorize`
Headers: `X-CSRF-Token: <ui_csrf>`. Body:
```json
{ "rate_version": "rv_2026_05" }
```
`200`:
```json
{ "authorization_id": "auth_1c2d", "authorized_minor": 5, "expires_at": "2026-06-05T17:00:00Z" }
```
Errors (FastAPI `detail`):
- `402` `{"detail":{"code":"insufficient_balance"}}` → `INSUFFICIENT_BALANCE`
- `409` `{"detail":{"code":"rate_changed","rate_version":"rv_2026_06"}}` → `RATE_CHANGED` (re-prompt, FR-7)
- `403` `{"detail":{"code":"auth_declined"}}` → `AUTH_DECLINED`

**Final cost:** `GET /ui/calls/{call_id}/billing/summary`
`200`:
```json
{ "call_id":"c_8f3a", "currency":"USD", "billed_minor": 15,
  "billable_seconds": 130, "increments": 3, "rate_version":"rv_2026_05" }
```
The end-call response from AND-296 SHOULD include `billed_minor`; if absent the
client calls `summary` once (idempotent GET, retryable) to obtain the final
figure.

Authorize is **non-idempotent** (a mutation) → **never** auto-retried; only
`summary` (GET) participates in bounded backoff retry (§7).

## 6. Data & State Management

- Source of truth: in-memory `CallUiState.billing` for the active call;
  billing has no persistent cache (per-call ephemeral).
- The active call session (call_id, billing object, connectedAt, authId) is held
  by the AND-296 call session holder; billing rehydrates from it after rotation
  or short process death (FR-8). No Room table is introduced.
- DataStore: a single boolean pref
  `call_billing_prompt_seen` (`core-data` prefs) to optionally suppress a
  one-time explainer; not used to bypass per-call authorization.
- Running cost is computed, never stored; `RunningCost.amountMinor` is derived
  each tick from `connectedAt` and the immutable `CallBilling`.
- Thread-safety: all billing state mutated on the main dispatcher via the
  ViewModel; the ticker uses `flowOn(Dispatchers.Default)` only for the delay
  loop, mapping back through `viewModelScope`.

## 7. Error Handling & Resilience

- **Timeouts:** authorize and summary use the project default ~20s OkHttp
  timeout against the unreliable dev host.
- **Retry policy:** `authorize` (POST/mutation) is **never** retried
  automatically — a silent retry could double-authorize/charge. `summary` (GET,
  idempotent) uses bounded exponential backoff (max 3 attempts, jittered).
- **401 handling:** inherited — the OkHttp authenticator does one
  `POST /ui/session/refresh` then retries the original request once.
- **Connect gating:** if authorize fails for any reason the FSM stays in/returns
  to `Ringing` with `BillingAuthState.Failed`, then ends the call (no half-open
  billed session, FR-6). The end request always fires even on auth failure so the
  backend tears down the reservation.
- **Rate change (409):** parse new `rate_version`, refresh `CallBilling`, set
  `authState = Pending`, re-render the confirm sheet (FR-7).
- **Expired authorization:** if connect is attempted after `expires_at`, treat as
  `EXPIRED` and re-prompt.
- **Network error on summary:** show final cost as the last local estimate with
  `finalIsEstimate = true` (FR-5).
- **Negative/overflow guards:** `elapsedSeconds` clamped to ≥0; cost computed in
  `Long` minor units (no floating point) to avoid rounding drift.

## 8. Security & Privacy

- All billing requests require the authenticated cookie session and a valid
  `ui_csrf` echoed via `X-CSRF-Token`; mutations without it are rejected
  server-side.
- No payment instrument data (card/PAN, balance) is requested, stored, or logged
  by this ticket — the client only handles per-call rate/cost figures.
- Cost/rate values are not written to disk; they live only in memory for the
  active call. The persistent cookie jar (required by the auth model) is the only
  persisted sensitive artifact and is owned by `core-network`, not here.
- Dev backend is plaintext HTTP — acceptable only for the dev host; production
  config MUST enforce HTTPS (cleartext allowed for the dev IP via network
  security config, owned by the network module).
- The authorization confirm action is an explicit, user-initiated mutation —
  never auto-confirmed, never bypassed by a stored pref.

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
  `call_billing_shown {call_id, currency, rate_per_increment_minor}`,
  `call_billing_authorized {call_id, authorized_minor}`,
  `call_billing_auth_failed {call_id, reason}`,
  `call_billing_final {call_id, billed_minor, is_estimate}`.
- Logging: `Timber` at `d` for state transitions; `w` for billing errors. Never
  log full request/response bodies of authorize/summary (may include balance/
  account context). Redact to codes only.
- Crash reporting attaches the current `BillingAuthState` class name (not
  amounts) as a breadcrumb.

## 11. Testing Strategy

Unit (JUnit + Turbine + MockWebServer, in `core-testing`):
- `BillingCalculator`: increment rounding (0s, 1s, 59s, 60s, 61s, 120s),
  first-increment-on-connect, currency scaling for 0/2/3-fraction currencies.
- `CallBillingDelegate`: `onCallNegotiated(null)` → `NotRequired`;
  billable → `Pending`; `confirmAuthorization` success → `Authorized` and gate
  opens; `402/403/409` map to correct `BillingError`; rate-change re-prompt;
  `onEnded` with/without `billed_minor` (estimate fallback).
- Ticker: `Clock`-injected fake advances time; running cost updates and is wall-
  clock derived (correct after a simulated gap).
- Repository: `MockWebServer` for authorize (no retry on 5xx) and summary
  (retry/backoff on 5xx, succeeds on 3rd).
- FSM gating: connect blocked while `Pending`/`Failed`; allowed on
  `Authorized`/`NotRequired`.

Instrumented (Compose UI test):
- Confirm sheet shows correct rate label and Authorize/Cancel; Cancel ends call.
- Running cost label updates; final cost shown on Ended; estimate label shown on
  summary failure.
- Semantics/liveRegion assertions for accessibility.

## 12. Dependencies & Sequencing

- **Blocked by AND-296** — requires the call FSM, `CallViewModel`, `CallScreen`,
  and the invite/connect/end endpoints to attach to. Cannot start until the
  `billing` field is present on those responses.
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

- **Q:** Exact field names and casing in the invite/connect `billing` object —
  must be confirmed against `/openapi.json` and `frontend/src/api/types.ts`
  (snake_case assumed). **Mitigation:** Moshi `@Json(name=...)` once confirmed.
- **Q:** Does the end-call response already include `billed_minor`, or is a
  `summary` GET always required? Spec supports both; confirm to avoid an extra
  round-trip.
- **Risk:** First-increment-on-connect billing assumption (units `≥ 1`). If the
  backend bills from `0` until the first whole increment, adjust
  `runningCostMinor`. Verify against backend rounding rule.
- **Risk:** Client running cost diverging from backend final (clock skew,
  connect-time definition). Mitigated by labelling running cost an estimate and
  always trusting the backend final figure.
- **Risk:** Authorization reservation leak if the app is killed between authorize
  and connect. Backend `expires_at` should auto-release; confirm TTL.
- **Open:** Should free-tier users see a "free call" affordance, or nothing?
  Assume nothing (FR-3) unless product specifies.

## 14. Acceptance Criteria

AC-1. (Backlog) A billed call shows its cost and requires authorization: the
Ringing UI displays the per-minute rate/currency, and connect is gated behind an
explicit **Authorize & connect** action. Verified by Compose UI test.

AC-2. A non-billed call connects with no billing UI and no behavior change vs
AND-296. Verified by UI + delegate unit test (`NotRequired`).

AC-3. While connected, a running cost is shown and updates every second,
computed as `ceil(elapsed/increment) × rate`, locale-formatted in the call
currency. Verified by ticker + calculator unit tests and a UI test.

AC-4. On Ended, the backend's final `billed_minor` is displayed; on summary
failure the last estimate is shown labelled "estimated". Verified by unit tests
for both paths.

AC-5. `402`/`403`/`409` authorize responses map to
`INSUFFICIENT_BALANCE`/`AUTH_DECLINED`/`RATE_CHANGED`, the call does not connect,
and (for 409) the user is re-prompted with the new rate. Verified by
`MockWebServer` unit tests.

AC-6. The `authorize` POST is never auto-retried; `summary` GET retries with
bounded backoff. Verified by `MockWebServer` request-count assertions.

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
- PR on `android-port` reviewed and merged; demo: a billed outgoing 1:1 call
  shows rate, authorizes, displays running cost, and shows final cost on end.
