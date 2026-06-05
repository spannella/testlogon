---
id: AND-237
title: Manage / cancel subscription
milestone: M5
epic: E32
priority: P1
size: M
status: draft
depends_on: [AND-236]
blocks: []
---

# AND-237 — Manage / cancel subscription

## 1. Overview & Goal

Provide an authenticated, single-screen "Manage Subscription" surface in the TestLogon
Android app (`com.testlogon.android`) that lets an entitled user (1) view the current
state and details of their subscription, (2) cancel an active subscription (scheduling it
to end at the current period end, not immediately revoking access), and (3) renew /
reactivate a subscription that is set to cancel or has lapsed. The defining acceptance
condition is that a cancel or renew action issued from this screen is durably reflected
in the UI: after the network round-trip succeeds, the screen state updates to the new
canonical server state, and re-entering the screen (or pull-to-refresh) shows the same
state.

This ticket consumes the entitlement/subscription primitives created by the subscribe
flow (AND-236) and the billing/plan models established earlier in epic E32. It does NOT
implement purchase, payment-method capture, or plan upgrade/downgrade — those are owned
by AND-236 (subscribe + payment + entitlement) and any later plan-change ticket. AND-237
is strictly the post-purchase lifecycle management surface: view, cancel, renew.

## 2. Context & References

- Repo: `spannella/testlogon`, branch `android-port`, Android app under `android/`.
- Module layering: `app -> feature-subscription -> core-* (core-network, core-model,
  core-data, core-ui, core-testing)`. This screen lives in `feature-subscription`,
  reusing the subscription repository introduced by AND-236.
- Web reference: `frontend/src/api/endpoints/*.ts` (subscription/billing endpoints) and
  `frontend/src/api/types.ts` for the canonical `Subscription` / `Entitlement` shapes.
  Mirror field names exactly into Moshi models in `core-model`.
- OpenAPI: `http://18.222.237.167:8000/openapi.json` — treat as source of truth for the
  exact `/ui/subscription/*` paths and bodies; reconcile any drift from this spec against
  it before implementation.
- Auth: cookie-based session established via `/ui/session/start` → MFA → `/ui/session/finalize`.
  All calls here are authenticated and require the `X-CSRF-Token` header (echo of the
  `ui_csrf` cookie) for mutating verbs. A persistent cookie jar and the shared OkHttp
  auth/CSRF/refresh interceptor stack (core-network) are prerequisites.
- Backend is FastAPI + DynamoDB on an unreliable plaintext dev host: design for ~20s
  timeouts, bounded backoff retry for idempotent GETs only, and explicit offline/stale UI.
- Stack: Kotlin 2.0.21, Compose + Material 3, Navigation-Compose, Hilt (KSP),
  Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, DataStore for prefs.

## 3. Functional Requirements

FR-1. The screen displays, for the current user's subscription: plan name, price &
billing interval, status (`active`, `canceled`, `past_due`, `expired`, `trialing`),
current period end date, and whether the subscription is scheduled to cancel at period
end (`cancel_at_period_end`).

FR-2. When the subscription is `active` and `cancel_at_period_end == false`, a primary
"Cancel subscription" action is shown. Tapping it opens a Material 3 confirmation dialog
explaining that access continues until the period end date; confirming issues the cancel
request.

FR-3. When the subscription is `active` and `cancel_at_period_end == true` (cancellation
scheduled), the screen shows a "Will end on <date>" banner and a primary "Resume /
Keep subscription" action that clears the scheduled cancellation (renew).

FR-4. When the subscription is `canceled`/`expired`, the screen shows a "Renew" /
"Reactivate" action. If renewal requires a fresh payment authorization, the screen does
NOT attempt it inline; it surfaces a message and routes the user to the AND-236 subscribe
flow (`subscribeRoute`). Renew handled here covers only the no-new-payment reactivation /
un-cancel path; payment is AND-236's responsibility.

FR-5. Every successful mutating action updates the in-memory `UiState` to the
server-returned subscription object and persists the latest snapshot to cache so the
state survives navigation and process death.

FR-6. The screen supports pull-to-refresh and an automatic load on first composition.
Loading, success, empty (no subscription → CTA to subscribe), error, and offline/stale
states are all distinctly rendered.

FR-7. Action buttons are disabled and show an inline progress indicator while a mutation
is in flight; the screen prevents concurrent duplicate mutations.

## 4. Technical Design

New/modified files in `feature-subscription`:

```
feature-subscription/
  ui/manage/ManageSubscriptionScreen.kt
  ui/manage/ManageSubscriptionViewModel.kt
  ui/manage/ManageSubscriptionUiState.kt
  ui/manage/ManageSubscriptionRoute.kt   // nav entry + arg-less route constant
```

Navigation route (registered in app `NavHost`):

```kotlin
const val manageSubscriptionRoute = "subscription/manage"

fun NavGraphBuilder.manageSubscriptionScreen(
    onNavigateToSubscribe: () -> Unit,
    onBack: () -> Unit,
) {
    composable(manageSubscriptionRoute) {
        ManageSubscriptionScreen(
            onNavigateToSubscribe = onNavigateToSubscribe,
            onBack = onBack,
        )
    }
}
```

UiState:

```kotlin
sealed interface ManageSubscriptionUiState {
    data object Loading : ManageSubscriptionUiState
    data object NoSubscription : ManageSubscriptionUiState           // empty -> CTA subscribe
    data class Content(
        val subscription: Subscription,
        val mutation: MutationStatus = MutationStatus.Idle,
        val isStale: Boolean = false,                                // served from cache
        val confirmCancelVisible: Boolean = false,
    ) : ManageSubscriptionUiState
    data class Error(val message: String, val retryable: Boolean) : ManageSubscriptionUiState
}

sealed interface MutationStatus {
    data object Idle : MutationStatus
    data object Canceling : MutationStatus
    data object Renewing : MutationStatus
    data class Failed(val message: String) : MutationStatus
}
```

ViewModel:

```kotlin
@HiltViewModel
class ManageSubscriptionViewModel @Inject constructor(
    private val repository: SubscriptionRepository,   // from AND-236
) : ViewModel() {

    val uiState: StateFlow<ManageSubscriptionUiState>

    fun refresh()
    fun onCancelClicked()                 // toggles confirmCancelVisible = true
    fun onCancelDismissed()
    fun onCancelConfirmed()               // -> repository.cancel()
    fun onRenewClicked()                  // -> repository.renew() or emits NavToSubscribe effect
    fun onErrorRetry()
}
```

Repository surface (extend the AND-236 `SubscriptionRepository`; add management methods):

```kotlin
interface SubscriptionRepository {
    fun observeSubscription(): Flow<Subscription?>          // backed by DataStore/cache
    suspend fun getSubscription(forceRefresh: Boolean): ApiResult<Subscription?>
    suspend fun cancelSubscription(): ApiResult<Subscription>
    suspend fun renewSubscription(): ApiResult<Subscription> // un-cancel / reactivate, no new payment
}
```

The ViewModel composes `observeSubscription()` (cache) with a triggered `getSubscription`
network refresh so the cached snapshot renders immediately (marked `isStale=true`) and is
replaced by the authoritative network result. Mutations call the repository, and on
success the repository writes the returned `Subscription` back to cache, which propagates
through `observeSubscription()` so a single source of truth drives the UI (satisfies FR-5).

Compose screen exposes a `Scaffold` + `PullToRefreshBox`; primary action rendered as a
filled `Button` whose label and handler are derived from `subscription.status` and
`cancel_at_period_end`. A `AlertDialog` provides cancel confirmation. One-shot navigation
to the subscribe flow uses a `Channel`-backed effect collected with
`LaunchedEffect`/`flowWithLifecycle`.

## 5. API Contract

All endpoints are authenticated (session cookies) and prefixed `/ui`. Mutating calls send
`X-CSRF-Token`. Reconcile exact paths/casing against `/openapi.json` before coding.

Retrofit service (in `core-network`, extend the AND-236 service):

```kotlin
interface SubscriptionApi {
    @GET("ui/subscription")
    suspend fun getSubscription(): Response<SubscriptionDto?>

    @POST("ui/subscription/cancel")
    suspend fun cancel(@Body body: CancelRequestDto = CancelRequestDto()): Response<SubscriptionDto>

    @POST("ui/subscription/renew")
    suspend fun renew(@Body body: RenewRequestDto = RenewRequestDto()): Response<SubscriptionDto>
}
```

GET `/ui/subscription` → 200:

```json
{
  "id": "sub_8f1c2",
  "plan_id": "pro_monthly",
  "plan_name": "Pro Monthly",
  "status": "active",
  "amount_cents": 999,
  "currency": "USD",
  "interval": "month",
  "current_period_end": "2026-07-05T00:00:00Z",
  "cancel_at_period_end": false,
  "started_at": "2026-05-05T00:00:00Z"
}
```

A user with no subscription returns 200 with `null` (or 404 → mapped to `NoSubscription`).

POST `/ui/subscription/cancel` — body `{ "at_period_end": true }` (default). Cancels at
period end; returns the full updated `SubscriptionDto` with `cancel_at_period_end: true`
(status remains `active` until the period ends).

POST `/ui/subscription/renew` — body `{}`. Clears a scheduled cancellation or reactivates
a still-eligible canceled subscription; returns the updated `SubscriptionDto` with
`cancel_at_period_end: false` / `status: "active"`. If the backend rejects with a billing
error indicating payment is required (HTTP 402 or `detail.code == "payment_required"`),
the client surfaces this and routes to AND-236 rather than retrying.

FastAPI error envelope handling (shared mapper in core-network): `detail` may be a string,
a list of `{msg}`, or an object `{code, ...}`. The repository maps these to a typed
`ApiResult.Error(code, message)`.

## 6. Data & State Management

- Single source of truth: the cached `Subscription` snapshot. Store it as a serialized
  Moshi JSON value in a dedicated DataStore preferences key
  (`subscription_snapshot`) keyed under the current user; this is per-user, low-volume,
  and read-on-launch, so DataStore (not Room) is appropriate.
- `observeSubscription()` emits the deserialized snapshot; mutations and refreshes write
  through it. UI never holds subscription state independently of this flow.
- `current_period_end` / `started_at` are parsed as `Instant` (ISO-8601 UTC) and formatted
  for display with the device locale and zone via `java.time` (`DateTimeFormatter`
  localized medium date).
- `isStale` is true whenever the rendered `Content` came from cache and the most recent
  network refresh has not yet succeeded; cleared on a successful GET.
- Process-death: `uiState` is rebuilt from the cache flow on ViewModel re-creation; no
  `SavedStateHandle` payload is needed beyond the route (it is arg-less). Transient dialog
  visibility (`confirmCancelVisible`) is held in `SavedStateHandle` to survive
  configuration changes.

## 7. Error Handling & Resilience

- GET `/ui/subscription` is idempotent: apply the shared bounded backoff (max 3 attempts,
  ~250ms → ~1s jittered) and a ~20s OkHttp call timeout for this dev host.
- POST cancel/renew are NOT auto-retried (non-idempotent at the mutation boundary). On
  network/timeout failure the screen shows a `MutationStatus.Failed` inline message with a
  manual "Try again" affordance; the user explicitly re-triggers.
- 401 → handled transparently by the core-network interceptor: one `POST /ui/session/refresh`
  then retry; if refresh fails, propagate as an auth error and let the app route to login.
- Offline (no connectivity): if a cache snapshot exists, render `Content(isStale=true)`
  with an offline banner and disabled mutation actions; otherwise render
  `Error(retryable=true)`.
- Mutation in flight guards: `onCancelConfirmed`/`onRenewClicked` no-op if `mutation` is
  not `Idle`, preventing duplicate POSTs.
- Optimistic update is intentionally avoided for cancel/renew; the UI commits only to the
  server-returned object to guarantee the acceptance criterion (state is the canonical
  server state).

## 8. Security & Privacy

- All requests ride the existing authenticated cookie session; no credentials are handled
  on this screen. Mutating POSTs MUST include `X-CSRF-Token` (interceptor-supplied).
- No card/PAN or payment-instrument data is read, displayed, or stored here; payment is
  out of scope (AND-236). Only plan/price/status metadata is shown.
- The cached `subscription_snapshot` contains no secrets (plan id, status, dates, amount);
  it is non-sensitive but still scoped to the logged-in user and cleared on logout (hook
  into the existing session-clear that purges DataStore/cookies).
- No subscription identifiers are logged at any level above debug; see §10.
- Network is plaintext HTTP on the dev host only; production must be HTTPS — flagged as an
  open question (§13), not changed here.

## 9. Accessibility & i18n

- All actionable controls have `contentDescription` / merged semantics; the primary action
  button announces its current intent ("Cancel subscription", "Keep subscription",
  "Renew"). The confirmation dialog is fully focus-trapped (Material 3 `AlertDialog`).
- Status, period-end date, and the cancel-scheduled banner are exposed as a single readable
  semantics node for TalkBack.
- All user-facing strings live in `feature-subscription/src/main/res/values/strings.xml`;
  no hardcoded literals in Compose. Plurals/dates use `java.time` locale formatting and
  Android resource plurals where needed.
- Touch targets ≥ 48dp; supports dynamic font scaling and dark theme via core-ui Material 3
  theme; layout reflows without truncation at 200% font scale.

## 10. Telemetry & Logging

- Emit analytics events via the shared analytics interface (core-data): `subscription_manage_viewed`,
  `subscription_cancel_confirmed { plan_id }`, `subscription_cancel_succeeded`,
  `subscription_renew_clicked`, `subscription_renew_succeeded`, and
  `subscription_action_failed { action, error_code }`. No PII in event payloads.
- Logging via the shared logger: network failures and error-envelope codes at `WARN`;
  successful state transitions at `INFO` without identifiers; raw subscription ids only at
  `DEBUG` in debug builds.
- Telemetry calls never block the UI thread and never gate state transitions.

## 11. Testing Strategy

Unit (core-testing, JUnit + Turbine + MockWebServer / fake repository):
- ViewModel: load success → `Content`; load with null body → `NoSubscription`; cache-first
  then network → emits stale `Content` then fresh `Content` with `isStale=false`.
- `onCancelConfirmed` success → `MutationStatus` cycles Canceling → Idle and
  `subscription.cancel_at_period_end == true`; failure → `MutationStatus.Failed`.
- `onRenewClicked` success → `cancel_at_period_end == false`; 402/`payment_required` →
  emits NavToSubscribe effect, no state corruption.
- Concurrent-mutation guard: second action while in flight is ignored.
- Repository: MockWebServer asserts cancel/renew send `X-CSRF-Token`, correct paths/bodies;
  GET applies retry on 5xx but cancel/renew do not; error-envelope (string | list | object)
  maps to the correct typed error.
- Cache: snapshot persisted on success and re-emitted via `observeSubscription()`.

Compose UI tests (`createAndroidComposeRule`):
- Active subscription renders "Cancel subscription"; tapping shows dialog; confirm shows
  inline progress then "Will end on <date>" banner and "Keep subscription".
- Scheduled-cancel state renders resume action; renew flips back to active labeling.
- Empty state renders subscribe CTA; error state renders retry.
- Acceptance check: after a stubbed cancel, navigating away and back (re-reading cache)
  still shows the canceled-at-period-end state.

## 12. Dependencies & Sequencing

- Hard dependency: AND-236 (Subscribe flow) — provides `SubscriptionRepository`,
  `SubscriptionApi`, the `Subscription`/`SubscriptionDto` models, entitlement plumbing,
  and the `feature-subscription` module + subscribe route this screen links out to.
  AND-237 cannot start until AND-236's repository/model surface is merged.
- Transitively depends on the core-network auth/CSRF/refresh interceptor stack and
  persistent cookie jar (E32 networking groundwork).
- Blocks: none recorded in the backlog.
- Sequencing: extend the existing `SubscriptionRepository`/`SubscriptionApi` (add cancel/
  renew) → ViewModel → Compose screen → wire route in app `NavHost` → tests.

## 13. Risks & Open Questions

- R1: Exact `/ui/subscription/*` paths, the cancel body field name (`at_period_end`), and
  whether renew is a distinct endpoint vs. `cancel` with `at_period_end:false` are assumed;
  verify against `/openapi.json` and the web reference before coding.
- R2: Whether reactivating a fully `expired`/`canceled` subscription is possible without a
  new payment is backend-dependent; the design degrades to routing into AND-236 on a
  `payment_required` signal.
- R3: Dev host is plaintext HTTP and flaky; flows must remain usable under timeouts/offline.
  Production HTTPS + cleartext-traffic config is out of scope here.
- R4: No webhook/push for backend-side state changes (e.g., dunning moving status to
  `past_due`); the UI relies on refresh-on-view + pull-to-refresh. Real-time sync is a
  potential follow-up.
- R5: Plan upgrade/downgrade is explicitly out of scope; confirm no PM expectation that
  it lands here.

## 14. Acceptance Criteria

AC-1. Opening the screen loads and displays the current subscription's plan, price, status,
period-end date, and cancel-scheduled state; a user with no subscription sees the empty
CTA. (FR-1, FR-6)

AC-2. Confirming "Cancel subscription" issues `POST /ui/subscription/cancel`, and on
success the screen reflects `cancel_at_period_end == true` with a "Will end on <date>"
banner and a "Keep subscription" action — the cancel is reflected. (Backlog acceptance;
FR-2, FR-5)

AC-3. "Keep subscription" / "Renew" issues `POST /ui/subscription/renew`, and on success
the screen reflects `cancel_at_period_end == false` / `status == active` — the renew is
reflected. (Backlog acceptance; FR-3, FR-4)

AC-4. The reflected state survives navigation away and back and process death (read from
cache), matching the last server-confirmed state. (FR-5)

AC-5. Mutating requests carry `X-CSRF-Token`; a 401 triggers a single transparent refresh+retry.

AC-6. Action buttons disable with inline progress during a mutation and reject concurrent
duplicates; mutation failures surface a retry affordance without leaving stale optimistic
state. (FR-7, §7)

AC-7. Offline with a cached snapshot renders a stale/offline state with disabled actions;
offline with no cache renders a retryable error.

AC-8. A renew that the backend rejects with `payment_required`/402 routes the user to the
AND-236 subscribe flow.

## 15. Definition of Done

- All Acceptance Criteria pass; unit and Compose UI tests added and green in CI.
- `ManageSubscriptionScreen`, `ManageSubscriptionViewModel`, `ManageSubscriptionUiState`,
  and the route are merged in `feature-subscription`; repository extended with
  `cancelSubscription()` / `renewSubscription()`; route wired into the app `NavHost`.
- No hardcoded user-facing strings; all in `strings.xml`. TalkBack pass on the screen.
- Endpoint paths/bodies reconciled against `/openapi.json`; error-envelope mapping reuses
  the shared core-network mapper.
- ktlint/detekt clean; no new lint regressions; builds under JDK 17 / AGP 8.7.3 /
  Gradle 8.9 with `compileSdk/targetSdk 35`, `minSdk 24`.
- Telemetry events emit as specified; no subscription identifiers logged above DEBUG.
- PR reviewed and merged to `android-port`; ticket linked to AND-236.
