---
id: AND-237
title: Manage / cancel subscription
milestone: M5
epic: E32
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
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
- OpenAPI: `http://18.222.237.167:8000/openapi.json` — treat as source of truth.
  CORRECTED: the subscription endpoints are NOT under `/ui/subscription/*`. They live under
  `/api/subscriptions` and `/api/subscriptions/{subscription_id}/...` (verified against the
  OpenAPI index and `frontend/src/api/endpoints/subscriptions.ts`). See §5.
- Auth: CORRECTED/clarified. The shared web transport (`frontend/src/api/client.ts`) sends
  `Authorization: Bearer <accessToken>` (from the auth store), `credentials: include`
  (session cookies), and `X-CSRF-Token` echoed from the `ui_csrf` cookie on every request
  (verified). HOWEVER, the subscription server ALSO authenticates the acting user via an
  `X-User-Id` header (frontend `subscriptions.ts` `userIdHeader()`; OpenAPI declares an
  optional `x-user-id` header param on every `/api/subscriptions/*` op). The Android client
  MUST set `X-User-Id` (current user sub) on these calls in addition to the standard
  auth/CSRF stack. A persistent cookie jar + the shared OkHttp auth/CSRF/refresh
  interceptor stack (core-network) remain prerequisites.
- Backend is FastAPI + DynamoDB on an unreliable plaintext dev host: design for ~20s
  timeouts, bounded backoff retry for idempotent GETs only, and explicit offline/stale UI.
- Stack: Kotlin 2.0.21, Compose + Material 3, Navigation-Compose, Hilt (KSP),
  Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, DataStore for prefs.

## 3. Functional Requirements

FR-1. The screen displays, for the current user's subscription: plan name (CORRECTED:
there is no top-level `plan_name` field — derive from the embedded `plan` object or resolve
`plan_id`, falling back to `plan_id`), price (`price_cents` + `currency`) & billing
interval, status (`active`, `canceled`, `past_due`, `expired`, `trialing` — note: these
exact string values are an UNVERIFIED assumption; `status` is a free-form string in
`SubscriptionOut`), current period end date, and whether the subscription is scheduled to
cancel at period end (`cancel_at_period_end`).

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

CORRECTED. The original spec asserted single-resource `/ui/subscription` paths; these do
NOT exist. The real contract (verified against the OpenAPI index and
`frontend/src/api/endpoints/subscriptions.ts`) is:

| Action | Method + path | Request schema | Response |
| --- | --- | --- | --- |
| List my subscriptions | `GET /api/subscriptions` (params: `subscriber_id`, `include_profile`, `include_summary`) | — | `200: SubscriptionOut[]` (ARRAY) |
| Cancel | `POST /api/subscriptions/{subscription_id}/cancel` | `SubscriptionCancelIn` | `200: SubscriptionOut` |
| Resume (un-cancel a paused/canceled sub) | `POST /api/subscriptions/{subscription_id}/resume` | `SubscriptionResumeIn` | `200: SubscriptionOut` |
| Renewal (toggle auto-renew / clear scheduled cancel) | `POST /api/subscriptions/{subscription_id}/renewal` | `SubscriptionRenewalIn` | `200: SubscriptionOut` |
| (optional) Summary | `GET /api/subscriptions/{subscription_id}/summary` | — | `200: SubscriptionSummaryOut` |

CORRECTIONS:
- There is NO single-object `GET /ui/subscription`. Use `GET /api/subscriptions` (returns
  an array). The "no subscription" case is an EMPTY array, not a `null` body and not a 404.
  The ViewModel selects the user's current subscription from the list (empty → `NoSubscription`).
- There is NO `/ui/subscription/renew` endpoint. "Renew / keep / un-cancel" maps to
  `POST .../renewal` with `{ "auto_renew": true }` (clears a scheduled cancel) or
  `POST .../resume` for a paused/canceled subscription. Pick per the source state.
- Every mutating call requires the `{subscription_id}` PATH param AND the `X-User-Id`
  header (see §2 / §8). All calls are HTTP, ride the cookie session + `X-CSRF-Token`.

Retrofit service (in `core-network`, extend the AND-236 service):

```kotlin
interface SubscriptionApi {
    @GET("api/subscriptions")
    suspend fun listSubscriptions(
        @Query("include_summary") includeSummary: Boolean = true,
    ): Response<List<SubscriptionDto>>

    @POST("api/subscriptions/{id}/cancel")
    suspend fun cancel(
        @Path("id") subscriptionId: String,
        @Body body: SubscriptionCancelIn = SubscriptionCancelIn(),  // { cancel_at_period_end=true }
    ): Response<SubscriptionDto>

    @POST("api/subscriptions/{id}/resume")
    suspend fun resume(
        @Path("id") subscriptionId: String,
        @Body body: SubscriptionResumeIn = SubscriptionResumeIn(),  // { reason? }
    ): Response<SubscriptionDto>

    @POST("api/subscriptions/{id}/renewal")
    suspend fun renewal(
        @Path("id") subscriptionId: String,
        @Body body: SubscriptionRenewalIn = SubscriptionRenewalIn(autoRenew = true),
    ): Response<SubscriptionDto>
}
```
(`X-User-Id` is added by the core-network interceptor for `/api/subscriptions/*`.)

`SubscriptionOut` (verified — `components.schemas.SubscriptionOut`, mirror into
`SubscriptionDto`). NOTE the corrected field names/types:

```json
{
  "subscription_id": "sub_8f1c2",
  "plan_id": "pro_monthly",
  "creator_id": "cr_123",
  "subscriber_id": "usr_456",
  "interval": "month",
  "provider": "ccbill",
  "provider_subscription_id": "ccb_789",
  "status": "active",
  "start_at": 1746403200,
  "current_period_end": 1751673600,
  "cancel_at_period_end": false,
  "price_cents": 999,
  "currency": "USD",
  "auto_renew": true,
  "created_at": 1746403200,
  "updated_at": 1746403200
}
```

CORRECTED field names vs. the original draft:
- `id` → `subscription_id`; `amount_cents` → `price_cents`; `started_at` → `start_at`.
- There is NO `plan_name` field on `SubscriptionOut`. Plan display name comes from the
  optional embedded `plan` object (frontend `SubscriptionOut.plan?: SubscriptionPlan`) or
  by resolving `plan_id` via the plans endpoint — show `plan_id` as a fallback. UPDATE
  FR-1/§9 accordingly (use `plan_id`/embedded plan, not a top-level `plan_name`).
- `start_at`, `current_period_end`, `created_at`, `updated_at`, `trial_start`,
  `trial_end` are EPOCH-SECONDS INTEGERS, not ISO-8601 strings. Parse via
  `Instant.ofEpochSecond(...)` (see corrected §6).

POST `/api/subscriptions/{id}/cancel` — body `SubscriptionCancelIn`
`{ "cancel_at_period_end": true (default), "reason"?: string }`. CORRECTED: the field is
`cancel_at_period_end`, NOT `at_period_end`. `requestBody` is required. Returns the updated
`SubscriptionOut` with `cancel_at_period_end: true` (status stays `active` until period end).

POST `/api/subscriptions/{id}/renewal` — body `SubscriptionRenewalIn`
`{ "auto_renew": true (default), "effective": "period_end"|"immediate", "renewal_policy"?:
"auto"|"manual"|"cancel_at_period_end", "reason"?: string }`. Sending `auto_renew: true`
clears a scheduled cancellation; returns updated `SubscriptionOut`.

POST `/api/subscriptions/{id}/resume` — body `SubscriptionResumeIn` `{ "reason"?: string }`.
Reactivates a paused/canceled-but-eligible subscription.

UNVERIFIED ASSUMPTION (corrected): the original "HTTP 402 / `detail.code == payment_required`"
re-route is NOT supported by the sources. The OpenAPI declares only `422 HTTPValidationError`
on these ops; there is no `402` and no `payment_required` code anywhere in the spec. Treat
the "renew requires fresh payment → route to AND-236" path as an UNVERIFIED backend
assumption (§13 R2, §16 Open assumptions). Implement it defensively (any non-2xx error code
from renewal/resume that the shared mapper classifies as "payment/billing" routes to
AND-236) but do not hard-code `402`/`payment_required` as a contract.

FastAPI error envelope (VERIFIED): the only documented error on these endpoints is
`422` with `HTTPValidationError` = `{ "detail": [ { "loc": [...], "msg": "...",
"type": "..." } ] }` (`detail` is an ARRAY of `ValidationError`). The shared core-network
mapper should handle `detail` as a list-of-objects; a plain-string or object `detail`
(seen on other FastAPI HTTPException routes) is a defensive extra, not guaranteed here.

## 6. Data & State Management

- Single source of truth: the cached `Subscription` snapshot. Store it as a serialized
  Moshi JSON value in a dedicated DataStore preferences key
  (`subscription_snapshot`) keyed under the current user; this is per-user, low-volume,
  and read-on-launch, so DataStore (not Room) is appropriate.
- `observeSubscription()` emits the deserialized snapshot; mutations and refreshes write
  through it. UI never holds subscription state independently of this flow.
- CORRECTED: `current_period_end` / `start_at` (the field is `start_at`, not `started_at`)
  are EPOCH-SECONDS INTEGERS, not ISO-8601 strings. Parse with
  `Instant.ofEpochSecond(value)` and format for display with the device locale and zone via
  `java.time` (`DateTimeFormatter` localized medium date).
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
  (VERIFIED: `frontend/src/api/client.ts` does exactly one `/ui/session/refresh` on 401 then
  retries, and logs out on refresh failure.)
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
  on this screen. Every request includes `X-CSRF-Token` (echo of `ui_csrf`, interceptor-
  supplied — VERIFIED in `client.ts`, applied to all verbs, not just mutating ones) plus
  `Authorization: Bearer`. CORRECTED/ADDED: `/api/subscriptions/*` calls MUST also send the
  `X-User-Id` header (acting user sub) — required by the subscription service per
  `frontend/src/api/endpoints/subscriptions.ts` and the OpenAPI `x-user-id` param.
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

- R1: RESOLVED during this review. The paths are `/api/subscriptions/{id}/{cancel,resume,
  renewal}` (NOT `/ui/subscription/*`); the cancel field is `cancel_at_period_end` (NOT
  `at_period_end`); un-cancel/renew is `renewal {auto_renew:true}` or `resume`, NOT a
  `/renew` endpoint. See §5 and §16 for the verified contract.
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

AC-2. Confirming "Cancel subscription" issues `POST /api/subscriptions/{id}/cancel`
(CORRECTED path) with body `{cancel_at_period_end:true}`, and on success the screen reflects
`cancel_at_period_end == true` with a "Will end on <date>" banner and a "Keep subscription"
action — the cancel is reflected. (Backlog acceptance; FR-2, FR-5)

AC-3. "Keep subscription" / "Renew" issues `POST /api/subscriptions/{id}/renewal`
(CORRECTED path; `{auto_renew:true}`) or `POST /api/subscriptions/{id}/resume` for a
paused/canceled sub, and on success the screen reflects `cancel_at_period_end == false` /
`status == active` — the renew is reflected. (Backlog acceptance; FR-3, FR-4)

AC-4. The reflected state survives navigation away and back and process death (read from
cache), matching the last server-confirmed state. (FR-5)

AC-5. Mutating requests carry `X-CSRF-Token`; a 401 triggers a single transparent refresh+retry.

AC-6. Action buttons disable with inline progress during a mutation and reject concurrent
duplicates; mutation failures surface a retry affordance without leaving stale optimistic
state. (FR-7, §7)

AC-7. Offline with a cached snapshot renders a stale/offline state with disabled actions;
offline with no cache renders a retryable error.

AC-8. A renew/resume that the backend rejects with a payment/billing error routes the user
to the AND-236 subscribe flow. (NOTE: the specific `payment_required`/`402` trigger is an
UNVERIFIED assumption — see §5 and §16; the contract only documents `422`. Implement against
the mapper's billing-error classification, not a hard-coded 402.)

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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **List endpoint is `GET /api/subscriptions` returning a `SubscriptionOut[]` array.**
   VERDICT: Corrected (draft said `GET /ui/subscription` returning a single object/`null`).
   SOURCE: OpenAPI `GET /api/subscriptions` (op `list_subscriptions_api_subscriptions_get`,
   resp `200` array); `src/api/endpoints/subscriptions.ts: listSubscriptions` (typed
   `SubscriptionOut[]`).

2. **Cancel endpoint is `POST /api/subscriptions/{subscription_id}/cancel`.**
   VERDICT: Corrected (draft said `POST /ui/subscription/cancel`).
   SOURCE: OpenAPI `POST /api/subscriptions/{subscription_id}/cancel` (req
   `SubscriptionCancelIn`, resp `200: SubscriptionOut`); `src/api/endpoints/subscriptions.ts:
   cancelSubscription`.

3. **Cancel request field is `cancel_at_period_end` (default `true`), with optional `reason`.**
   VERDICT: Corrected (draft said `at_period_end`).
   SOURCE: schema `SubscriptionCancelIn` (`cancel_at_period_end: boolean default true`,
   `reason: string|null`); `src/api/endpoints/subscriptions.ts: cancelSubscription` body
   `{ cancel_at_period_end?, reason? }`.

4. **There is no `/ui/subscription/renew` endpoint; un-cancel/renew = `POST .../renewal`
   (`SubscriptionRenewalIn`, `auto_renew:true`) or `POST .../resume` (`SubscriptionResumeIn`).**
   VERDICT: Corrected.
   SOURCE: OpenAPI `POST /api/subscriptions/{subscription_id}/renewal` and
   `.../resume`; schemas `SubscriptionRenewalIn` (`auto_renew default true`, `effective`,
   `renewal_policy`), `SubscriptionResumeIn` (`reason?`); `src/api/endpoints/subscriptions.ts:
   updateRenewal`, `resumeSubscription`.

5. **`SubscriptionOut` field names/types: `subscription_id`, `price_cents`, `start_at`,
   `current_period_end`, `created_at`, `updated_at` are integers (epoch seconds); no
   `plan_name`/`id`/`amount_cents`/`started_at`.**
   VERDICT: Corrected (draft used `id`, `plan_name`, `amount_cents`, `started_at`, and ISO
   string dates).
   SOURCE: schema `components.schemas.SubscriptionOut` (required list + `type: integer` on
   the date fields); `src/api/types.ts: SubscriptionOut` (lines ~2713-2737, `number` epochs).

6. **Plan display name comes from embedded `plan`/`plan_id`, not a top-level `plan_name`.**
   VERDICT: Corrected.
   SOURCE: `src/api/types.ts: SubscriptionOut.plan?: SubscriptionPlan`; schema
   `SubscriptionOut` has no `plan_name` property.

7. **Mutating calls require the `{subscription_id}` path param and an `X-User-Id` header.**
   VERDICT: Verified (and added — draft omitted `X-User-Id`).
   SOURCE: OpenAPI cancel/resume/renewal ops declare path param `subscription_id` + header
   param `x-user-id`; `src/api/endpoints/subscriptions.ts: userIdHeader()` / `subPost`.

8. **Global transport sends `X-CSRF-Token` (from `ui_csrf` cookie) + `Authorization: Bearer`
   + `credentials: include` on every request.**
   VERDICT: Verified (draft's CSRF claim correct; refined that it applies to all verbs, and
   that Bearer + cookies are also sent).
   SOURCE: `src/api/client.ts` (getCookie `ui_csrf` → `X-CSRF-Token`; `Authorization` Bearer
   from auth store; `credentials: "include"`).

9. **401 → exactly one `POST /ui/session/refresh` then retry; logout on refresh failure.**
   VERDICT: Verified.
   SOURCE: `src/api/client.ts: refreshSession` + the 401 branch in `api<T>`.

10. **Cancel returns updated `SubscriptionOut` with `cancel_at_period_end:true`, `status`
    stays active until period end.**
    VERDICT: Verified (shape) / Unverified-assumption (status-stays-active timing — the
    backend's exact status transition is not described by the schema).
    SOURCE: OpenAPI cancel resp `200: SubscriptionOut`; timing behavior not in spec.

11. **Renew rejection trigger is HTTP `402` / `detail.code == "payment_required"`.**
    VERDICT: Unverified-assumption (and corrected to remove the hard contract).
    SOURCE: NOT present — no `402` or `payment_required` token anywhere in
    `openapi.pretty.json`; cancel/resume/renewal document only `422 HTTPValidationError`.

12. **Error envelope on these endpoints is `422 HTTPValidationError` with `detail` = array of
    `ValidationError {loc,msg,type}`.**
    VERDICT: Verified.
    SOURCE: schemas `HTTPValidationError` (`detail: ValidationError[]`) and `ValidationError`;
    cancel/resume/renewal ops list only `422`.

13. **Status enum values `active|canceled|past_due|expired|trialing`.**
    VERDICT: Unverified-assumption.
    SOURCE: `SubscriptionOut.status` is a free-form `string` (no enum in schema/`types.ts`).

14. **Persisting the snapshot in DataStore (not Room) and arg-less route.**
    VERDICT: Unverified-assumption (Android design choice; reasonable). framework ref:
    DataStore https://developer.android.com/topic/libraries/architecture/datastore

15. **Compose `PullToRefreshBox` + Material 3 `AlertDialog` + Navigation-Compose
    `composable(route)`.**
    VERDICT: Unverified-assumption (framework design choice). framework ref:
    Material 3 https://developer.android.com/develop/ui/compose/components/pull-to-refresh ,
    Navigation-Compose https://developer.android.com/develop/ui/compose/navigation

### Corrections made

- Endpoint base path family corrected from `/ui/subscription/*` to `/api/subscriptions/*`
  (list, `{id}/cancel`, `{id}/resume`, `{id}/renewal`).
- List endpoint returns an ARRAY (`SubscriptionOut[]`); "no subscription" = empty array,
  not a `null` body / 404.
- Cancel body field `at_period_end` → `cancel_at_period_end`.
- Removed the non-existent `/renew` endpoint; mapped renew/keep to `renewal {auto_renew:true}`
  or `resume`.
- `SubscriptionOut` fields: `id`→`subscription_id`, `amount_cents`→`price_cents`,
  `started_at`→`start_at`; removed `plan_name`; dates are epoch-second integers (not ISO
  strings) — updated FR-1 and §6 parsing.
- Added the required `X-User-Id` header for `/api/subscriptions/*` (§2, §5, §8).
- Demoted the `402`/`payment_required` re-route from contract to a defensive, unverified
  assumption (§5, AC-8).
- Annotated `status` enum values as unverified (free-form string).

### Open assumptions

- Whether reactivating a fully `expired`/`canceled` subscription needs a fresh payment, and
  what error the backend returns if so — NOT in the OpenAPI (only `422`). Why: no `402`,
  no `payment_required`, no billing-error schema on these ops. Implement defensively.
- Exact `status` string values and their transition timing after cancel/renew. Why: schema
  types `status` as a bare string with no enum.
- Whether the user has exactly one "current" subscription (the screen assumes one). Why:
  `GET /api/subscriptions` returns a list; selection logic ("which one is *the* sub") is not
  specified by the sources.
- Android-side persistence/UI framework choices (DataStore, PullToRefreshBox, route shape).
  Why: implementation decisions, not backend contract; backed by framework docs only.

## 17. Test Plan

Test targets: JVM = JVM/Robolectric local; EMU = headless emulator AVD `test35`
(x86_64, API 35); DEVICE = physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a).

- **TC-AND-237-01** — Type: unit (JVM). Target: JVM. Precondition: fake/Mock repo returns a
  one-element list with an `active`, `cancel_at_period_end=false` `SubscriptionOut`.
  Steps: create ViewModel, collect `uiState`. Expected: emits `Loading` then
  `Content(subscription.status="active")`; primary action label resolves to "Cancel
  subscription". Traces: AC-1.

- **TC-AND-237-02** — Type: unit (JVM). Target: JVM. Precondition: repo returns an EMPTY
  list. Steps: init ViewModel; collect. Expected: terminal state `NoSubscription` (empty
  array → CTA-to-subscribe), NOT `Error`/`Content`. Traces: AC-1.

- **TC-AND-237-03** — Type: contract/MockWebServer. Target: JVM. Precondition: MockWebServer
  enqueues `200` `SubscriptionOut` for `POST /api/subscriptions/{id}/cancel`. Steps: call
  `repository.cancelSubscription(id)`; capture the recorded request. Expected: path =
  `/api/subscriptions/{id}/cancel`, method `POST`, body JSON `{"cancel_at_period_end":true}`,
  headers include `X-CSRF-Token` and `X-User-Id`; result `ApiResult.Success` with
  `cancel_at_period_end==true`. Traces: AC-2, AC-5.

- **TC-AND-237-04** — Type: contract/MockWebServer. Target: JVM. Precondition: server enqueues
  `200` for `POST /api/subscriptions/{id}/renewal`. Steps: call `repository.renewSubscription
  (id)`. Expected: path `/api/subscriptions/{id}/renewal`, body `{"auto_renew":true}`, carries
  `X-CSRF-Token`+`X-User-Id`; result `cancel_at_period_end==false`/`status=="active"`.
  Traces: AC-3, AC-5.

- **TC-AND-237-05** — Type: contract/MockWebServer. Target: JVM. Precondition: cancel/renewal
  enqueue a `5xx` then a `200`; GET list enqueues a `5xx` then `200`. Steps: invoke GET and a
  mutation. Expected: GET is retried (bounded backoff, ≤3 attempts) and succeeds; the
  mutation is NOT auto-retried (exactly one request observed, surfaces `Failed`).
  Traces: AC-6, §7.

- **TC-AND-237-06** — Type: contract/MockWebServer. Target: JVM. Precondition: cancel enqueues
  `422` `HTTPValidationError` (`{"detail":[{"loc":["body","cancel_at_period_end"],
  "msg":"...","type":"..."}]}`). Steps: call cancel. Expected: shared mapper produces a typed
  `ApiResult.Error` reading the array `detail[].msg`; ViewModel → `MutationStatus.Failed(msg)`,
  no state corruption. Traces: AC-6.

- **TC-AND-237-07** — Type: unit (JVM). Target: JVM. Precondition: repo `cancelSubscription`
  suspends (in-flight). Steps: call `onCancelConfirmed()` twice rapidly. Expected: second
  call no-ops while `mutation != Idle`; exactly one repository invocation. Traces: AC-6.

- **TC-AND-237-08** — Type: unit (JVM). Target: JVM. Precondition: renewal/resume returns a
  billing-class error (mapper classifies as payment-required; simulated, since `402` is
  unverified). Steps: `onRenewClicked()`. Expected: emits the one-shot NavToSubscribe effect,
  state not corrupted; if a normal `422` is returned instead, it surfaces `Failed` and does
  NOT navigate. Traces: AC-8.

- **TC-AND-237-09** — Type: unit (JVM, cache). Target: JVM. Precondition: DataStore-backed
  cache holds a prior snapshot; network refresh pending. Steps: init ViewModel; collect.
  Expected: first `Content(isStale=true)` from cache, then `Content(isStale=false)` after the
  GET; on a successful cancel the returned object is written through `observeSubscription()`.
  Traces: AC-4, FR-5.

- **TC-AND-237-10** — Type: Compose-UI. Target: EMU (`test35`). Precondition: stubbed repo,
  `active`/not-scheduled subscription. Steps: launch screen; tap primary; confirm in dialog.
  Expected: tap shows Material 3 confirmation dialog; confirm shows inline progress; on
  success the "Will end on <date>" banner and "Keep subscription" action render. Traces:
  AC-2, AC-6.

- **TC-AND-237-11** — Type: Compose-UI. Target: EMU (`test35`). Precondition: stubbed repo;
  variants for scheduled-cancel, empty, and error. Steps: render each variant. Expected:
  scheduled-cancel → resume/keep action; empty → subscribe CTA; error → retry affordance.
  Traces: AC-1, AC-3, AC-7.

- **TC-AND-237-12** — Type: instrumented/e2e (offline). Target: DEVICE (real airplane-mode /
  radio toggle; must run on the physical device for true OS-level connectivity loss).
  Precondition: a cached snapshot exists; device set offline. Steps: open the screen offline.
  Expected: renders `Content(isStale=true)` with offline banner and DISABLED cancel/renew
  actions; with cache cleared + offline, renders a retryable `Error`. Traces: AC-7.

- **TC-AND-237-13** — Type: instrumented (security/permission). Target: EMU (`test35`).
  Precondition: MockWebServer; logout invoked. Steps: perform a mutation (assert headers),
  then trigger logout. Expected: every `/api/subscriptions/*` request carries `X-CSRF-Token`
  + `X-User-Id`; after logout the `subscription_snapshot` DataStore key and cookies are
  purged (no stale subscription readable). Traces: AC-5, §8.

- **TC-AND-237-14** — Type: Compose-UI (accessibility). Target: EMU (`test35`); confirm
  TalkBack pass on DEVICE. Precondition: scheduled-cancel `Content`. Steps: run Compose
  a11y/semantics assertions; manual TalkBack sweep on the A15. Expected: primary button
  exposes its current intent via semantics; status/period-end/banner form one readable node;
  touch targets ≥48dp; layout reflows without truncation at 200% font scale. Traces: AC-1,
  §9.

### Coverage matrix

| AC | Covered by |
| --- | --- |
| AC-1 | TC-01, TC-02, TC-11, TC-14 |
| AC-2 | TC-03, TC-10 |
| AC-3 | TC-04, TC-11 |
| AC-4 | TC-09 |
| AC-5 | TC-03, TC-04, TC-13 |
| AC-6 | TC-05, TC-06, TC-07, TC-10 |
| AC-7 | TC-11, TC-12 |
| AC-8 | TC-08 |
