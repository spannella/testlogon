---
id: AND-236
title: Subscribe flow
milestone: M5
epic: E32
priority: P0
size: L
status: draft
depends_on: [AND-235, AND-227]
blocks: []
---

# AND-236 — Subscribe flow

## 1. Overview & Goal

Implement the end-to-end consumer **subscribe flow** in the native Android app: a fan selects a
creator subscription tier (surfaced by AND-235), completes payment via the Stripe checkout session
established in AND-227, and the resulting **entitlement** is confirmed and reflected in app state so
gated content and the creator profile immediately show the subscribed status.

The flow spans three backend interactions: (1) creating a checkout session for the selected tier,
(2) returning from the Stripe-hosted payment surface, and (3) reconciling entitlement by polling
`/ui/billing/subscriptions` and refreshing `/ui/me`. The acceptance bar is concrete and testable:
**a subscription activates in the Stripe test environment and the app transitions to a confirmed,
entitled state.**

Goal of this ticket specifically:

- Own the `feature-subscribe` module: the confirm-tier sheet, the payment hand-off, the
  return/poll reconciliation, and success/failure terminal states.
- Reuse, not re-implement, tier rendering (AND-235) and the checkout-session primitive (AND-227).
- Produce a deterministic, idempotent activation path tolerant of the unreliable dev backend.

Out of scope: managing/cancelling existing subscriptions, refunds, wallet top-ups, payment-method
CRUD, and the tier-browse list itself.

## 2. Context & References

- Repo `spannella/testlogon`, Android app under `android/`, branch `android-port`.
- Namespace / applicationId base: `com.testlogon.android`. Feature module package
  `com.testlogon.android.feature.subscribe`.
- Web reference: `frontend/src/api/endpoints/*.ts` (billing/fan-club endpoints), shared types
  `frontend/src/api/types.ts`. OpenAPI: `http://18.222.237.167:8000/openapi.json`.
- Backend endpoints used (verified in OpenAPI):
  - `POST /ui/billing/checkout_session` — owned by AND-227, reused here.
  - `GET /ui/billing/subscriptions` — entitlement reconciliation.
  - `GET /ui/fan-club/tiers` — tier source (AND-235); a tier id/price drives this flow.
  - `POST /ui/syndicates/{syndicate_id}/plans/{plan_id}/subscribe` — in-app bundle subscribe
    variant (used when the tier maps to a syndicate plan rather than a one-off checkout).
  - `GET /ui/me` — post-activation identity/entitlement refresh.
- Auth is cookie-based with `X-CSRF-Token` echo and a one-shot `POST /ui/session/refresh` on 401;
  the persistent cookie jar and `ApiResult<T>` wrapper come from `core-network`.
- Dev backend is **plaintext HTTP and unreliable**: 20s timeouts, bounded backoff retry for
  idempotent GETs only, explicit offline/stale UI states.

Dependencies:

- **AND-235 (Subscription tiers browse)** provides `SubscriptionTier` (id, price, currency, label)
  and the entry point that navigates into this flow.
- **AND-227 (Checkout session billing)** provides `BillingRepository.createCheckoutSession(...)`
  and the Stripe payment completion mechanics; this ticket consumes that repository function.

## 3. Functional Requirements

FR-1. From a tier card (AND-235), the user can tap **Subscribe** and is presented a confirm sheet
showing tier name, recurring price (formatted from minor units + ISO-4217 currency), and creator.

FR-2. Confirming creates a checkout session via AND-227's repository for the selected tier amount,
yielding a Stripe-hosted payment URL. The app hands off to that URL (Custom Tab) for card entry.

FR-3. On return from the payment surface, the app enters a **reconciling** state and polls
`GET /ui/billing/subscriptions` (bounded) until the target subscription appears `active`, then
refreshes `/ui/me`.

FR-4. On confirmed activation the flow shows a terminal **success** state, emits a result so the
originating screen (creator profile / tier list) updates entitlement, and unlocks gated content.

FR-5. If the tier maps to a syndicate plan, confirming instead calls
`POST /ui/syndicates/{syndicate_id}/plans/{plan_id}/subscribe` (server-side immediate activation),
skipping the Stripe Custom Tab hand-off but using the same reconcile + success path.

FR-6. If payment is cancelled, fails, or reconciliation times out, show a recoverable error state
with **Retry** (re-creates the checkout session) and **Cancel**.

FR-7. The flow is idempotent: re-entering after a partially completed purchase detects an already
`active` subscription during reconcile and routes straight to success without double-charging.

FR-8. While offline, the confirm action is disabled with an offline banner; reconciliation surfaces
a stale/offline state rather than a hard failure.

## 4. Technical Design

New module `feature-subscribe` (`feature-subscribe -> core-network, core-model, core-data,
core-ui, core-testing`). Single-Activity Navigation-Compose; the flow is a nested nav graph
`subscribeGraph(tierId, creatorId)`.

State and ViewModel:

```kotlin
package com.testlogon.android.feature.subscribe

sealed interface SubscribeUiState {
    data object Loading : SubscribeUiState
    data class Confirm(
        val tier: SubscriptionTier,
        val creatorName: String,
        val offline: Boolean = false,
        val submitting: Boolean = false,
    ) : SubscribeUiState
    data class AwaitingPayment(val checkoutUrl: String, val sessionRef: String) : SubscribeUiState
    data class Reconciling(val attempt: Int, val maxAttempts: Int) : SubscribeUiState
    data class Success(val subscriptionId: String, val tierId: String) : SubscribeUiState
    data class Error(val kind: SubscribeError, val retryable: Boolean) : SubscribeUiState
}

enum class SubscribeError { CHECKOUT_FAILED, PAYMENT_CANCELLED, RECONCILE_TIMEOUT, NETWORK, UNKNOWN }

@HiltViewModel
class SubscribeViewModel @Inject constructor(
    private val subscribeRepo: SubscribeRepository,
    private val billingRepo: BillingRepository,            // from AND-227
    savedState: SavedStateHandle,
) : ViewModel() {
    val uiState: StateFlow<SubscribeUiState>

    fun confirmSubscribe()                                 // FR-2 / FR-5
    fun onReturnFromPayment(result: PaymentReturn)         // FR-3
    fun retry()
    fun cancel()
}
```

Repository:

```kotlin
interface SubscribeRepository {
    suspend fun loadTier(tierId: String): ApiResult<SubscriptionTier>
    suspend fun startCheckout(tier: SubscriptionTier): ApiResult<CheckoutSession>          // wraps AND-227
    suspend fun subscribeToPlan(syndicateId: String, planId: String): ApiResult<Unit>     // FR-5
    suspend fun listSubscriptions(): ApiResult<List<Subscription>>                         // reconcile
    suspend fun refreshMe(): ApiResult<UiMe>
}
```

Reconciliation is a `flow`-based bounded poll: up to `maxAttempts = 6` attempts with backoff
`1s, 2s, 4s, 8s, 8s, 8s` (cap 8s), cancelled the moment a matching `active` subscription is found.
Each poll is an idempotent GET, so `core-network`'s GET-only backoff applies on top.

Payment hand-off uses an AndroidX **Custom Tabs** intent to `checkoutUrl`. Return is detected via a
deep link (`com.testlogon.android://billing/return`) plus lifecycle `ON_RESUME` fallback (Custom
Tabs gives no reliable result code). On resume without an explicit cancel deep link, the flow
optimistically enters `Reconciling`; reconcile is the source of truth, not the return signal.

Compose surface: `SubscribeRoute` collects `uiState` and renders `ConfirmSheet`,
`ReconcilingScreen` (progress + attempt text), `SuccessScreen` (entitlement confirmed, CTA back to
content), and `ErrorScreen` (retry/cancel). Navigation result is published via a typed
`SavedStateHandle` key `"subscribe_result"` consumed by AND-235's tier list / creator profile.

## 5. API Contract

**Create checkout session** (reused from AND-227):

`POST /ui/billing/checkout_session`  — headers: cookies + `X-CSRF-Token`.

Request (`BillingCheckoutReq`):
```json
{ "amount_cents": 999, "currency": "usd", "description": "Subscribe: Gold tier — @creator" }
```
`amount_cents` (required, int, minor units) is derived from `SubscriptionTier.priceCents`.

Response `200` — object map of strings (Stripe handoff); treated as `Map<String,String>`:
```json
{ "url": "https://checkout.stripe.com/c/pay/cs_test_...", "session_id": "cs_test_..." }
```
Client reads `url` (payment surface) and `session_id` (`sessionRef`).

**Syndicate-plan subscribe** (FR-5 variant):

`POST /ui/syndicates/{syndicate_id}/plans/{plan_id}/subscribe` — body none; cookies + CSRF.
Response `200`: object; success implies server-side activation, then reconcile confirms.

**List subscriptions** (reconcile, idempotent GET):

`GET /ui/billing/subscriptions?limit=50`

Response `200` is an open object; the client maps to:
```json
{ "subscriptions": [
  { "id": "sub_...", "tier_id": "tier_gold", "status": "active",
    "current_period_end": 1717545600, "creator_id": "creator_123" }
] }
```
Activation predicate: any entry where `tier_id == targetTierId && status == "active"`.

**Identity refresh:** `GET /ui/me` → `UiMe` (entitlement flags) after activation.

Error envelope (FastAPI `detail`): handled by `core-network`'s mapper supporting
`string | [{msg}] | {code,...}`.

## 6. Data & State Management

- `SubscriptionTier` (id, label, priceCents, currency, creatorId, optional syndicatePlanId)
  lives in `core-model`, shared with AND-235.
- `Subscription` (id, tierId, status, currentPeriodEnd, creatorId) added to `core-model`.
- StateFlow-only UI state per the layering rule; no mutable state escapes the ViewModel.
- DataStore (prefs) records `last_pending_checkout` = `{tierId, sessionRef, ts}` so an interrupted
  flow (process death during Custom Tab) resumes into `Reconciling` on relaunch (FR-7). Cleared on
  terminal success/cancel.
- Room cache (`core-data`): the active subscriptions set is cached for fast gated-content checks;
  on successful activation the cache is upserted optimistically and confirmed by the reconcile GET.
- No PII (card data) ever touches the app — payment is Stripe-hosted. Only opaque ids are stored.

## 7. Error Handling & Resilience

- Timeouts: 20s socket/read per call (OkHttp config from `core-network`).
- Checkout creation (POST) is **non-idempotent** → no automatic retry; failure → `Error(CHECKOUT_FAILED, retryable=true)`, user-driven retry only.
- Reconcile GETs use bounded backoff (six attempts, cap 8s); exhaustion → `Error(RECONCILE_TIMEOUT,
  retryable=true)` with a "we'll keep checking" affordance that re-runs the poll.
- 401 mid-flow → `core-network` performs one `POST /ui/session/refresh` then retries the original
  request transparently; a second 401 surfaces `NETWORK` and routes to re-auth.
- Cancelled payment (cancel deep link or resume with no new subscription after one poll) →
  `Error(PAYMENT_CANCELLED, retryable=true)`; no charge implied.
- Offline (no connectivity): confirm disabled + banner (FR-8); reconcile shows stale state and
  resumes automatically on connectivity regain.
- Idempotency guard: before creating a new checkout the ViewModel runs one `listSubscriptions()`;
  if already `active`, short-circuit to `Success` (prevents double purchase, FR-7).

## 8. Security & Privacy

- All payment card entry is delegated to the Stripe-hosted Custom Tab; the app handles no card data,
  meeting "no card PII in-app." Only `session_id`, `subscription_id`, and `tier_id` are persisted.
- CSRF: every state-changing POST (`checkout_session`, syndicate subscribe) sends `X-CSRF-Token`
  from the `ui_csrf` cookie via the shared OkHttp interceptor.
- Deep-link return (`com.testlogon.android://billing/return`) carries **no secrets**; activation is
  confirmed server-side via the authenticated session, never trusted from the redirect params.
- Dev backend is plaintext HTTP; `usesCleartextTraffic` is gated to the dev flavor only and never
  shipped in release. No payment data flows over cleartext (Stripe is HTTPS in the Custom Tab).
- DataStore pending-checkout entry holds only non-sensitive ids and is cleared on terminal state.

## 9. Accessibility & i18n

- All strings (tier label is dynamic; static labels: "Subscribe", "Confirm", "Processing
  payment…", "Subscription active", retry/cancel) in `strings.xml`; no hardcoded text.
- Price formatting via `java.text.NumberFormat.getCurrencyInstance(locale)` from minor units +
  currency code — never string-concatenated; respects RTL and locale decimal/grouping.
- Confirm/Retry/Cancel are ≥48dp touch targets with `contentDescription`; the reconciling spinner
  exposes a `liveRegion` announcing progress and the success terminal state to TalkBack.
- Dynamic type / font-scale honored; ConfirmSheet content scrolls when text scales up.

## 10. Telemetry & Logging

Structured events via the app analytics facade (no PII, ids hashed where required):

- `subscribe_confirm_tapped` { tierId, creatorId, amount_cents }
- `subscribe_checkout_created` { tierId, sessionRef }
- `subscribe_payment_returned` { tierId, viaDeepLink: bool }
- `subscribe_reconcile_attempt` { tierId, attempt }
- `subscribe_activated` { tierId, subscriptionId, elapsedMs }
- `subscribe_failed` { tierId, kind, retryable }

Logging: redact `session_id`/`subscription_id` to last 6 chars in logs; never log cookies or CSRF
token. Reconcile attempts log at DEBUG, terminal states at INFO, transport failures at WARN.

## 11. Testing Strategy

Unit (`core-testing` + Turbine + MockWebServer):

- `SubscribeViewModelTest`: confirm → checkout success → AwaitingPayment → reconcile finds active →
  Success (asserts emitted state sequence).
- Reconcile backoff: subscription becomes active on the 3rd poll → success at attempt 3; never
  active → `RECONCILE_TIMEOUT` after 6.
- Idempotency: pre-existing active subscription → confirm short-circuits to Success, **no**
  `checkout_session` POST issued (verify MockWebServer recorded no request).
- Cancelled payment / 401-refresh-retry / offline paths produce the specified error/stale states.
- Syndicate-plan variant calls the subscribe endpoint, not checkout_session.

Repository: MockWebServer fixtures for `checkout_session` (string-map body), `subscriptions`
(active/inactive/empty), and `/ui/me`; assert `amount_cents` and `X-CSRF-Token` on the POST.

Instrumented/UI (Compose test rule): ConfirmSheet renders formatted price; tapping Confirm shows
progress; Success screen exposes correct semantics. Custom Tab launch is abstracted behind a
`PaymentLauncher` interface and faked in tests.

**Acceptance test (gating):** against the Stripe **test** environment, drive confirm → test card →
reconcile and assert the subscription reaches `active` and the flow lands on Success — satisfying
"Subscription activates (test)."

## 12. Dependencies & Sequencing

- Hard deps: **AND-235** (tier model + entry point) and **AND-227** (checkout session repository +
  Stripe completion). This ticket must land after both.
- Transitively requires the cookie session stack (session start/finalize, CSRF interceptor,
  refresh-on-401) and `core-network` `ApiResult`/error mapping.
- Provides the navigation result contract consumed by AND-235's tier list and the creator-profile
  entitlement display.
- Blocks: none recorded in the source backlog.

## 13. Risks & Open Questions

- **Custom Tab return is unreliable** (no result code): mitigated by treating reconcile as source of
  truth + DataStore resume. Risk that a slow Stripe webhook delays `active` beyond the poll window →
  surface RECONCILE_TIMEOUT with continue-checking, do not declare failure.
- **`/ui/billing/subscriptions` response is an open object** in OpenAPI (additionalProperties:true);
  exact field names (`tier_id` vs `tier`, `status` enum values) need confirmation against a live dev
  response or `frontend/src/api/types.ts`. *Open question.*
- Tier→checkout mapping: does every tier go through `checkout_session`, or do creator tiers use the
  syndicate-plan subscribe path? Source scope says "Subscribe + payment + entitlement"; design
  supports both and selects on `tier.syndicatePlanId` presence. *Confirm with AND-235 output.*
- Dev backend flakiness may cause acceptance-test nondeterminism; pin to Stripe test mode and allow
  generous reconcile budget in CI.

## 14. Acceptance Criteria

- AC-1. Selecting a tier and confirming creates a `POST /ui/billing/checkout_session` with the
  correct `amount_cents`/`currency` and `X-CSRF-Token`, and opens the returned Stripe URL.
- AC-2. After completing payment with a Stripe **test** card, the app reconciles and reaches the
  Success state with a `subscriptionId` whose `status == "active"` and matching `tier_id`
  (satisfies "Subscription activates (test)").
- AC-3. Entitlement is reflected: the originating screen receives the subscribe result and gated
  content for that tier is unlocked after `/ui/me` refresh.
- AC-4. Re-entering the flow with an already-active subscription routes to Success with **no** new
  checkout_session request (idempotent, no double charge).
- AC-5. Cancelled/failed payment and reconcile timeout yield retryable error states; Retry
  re-creates the session and proceeds.
- AC-6. Offline disables confirm with a banner; reconcile shows a stale state and auto-resumes.
- AC-7. No card PII is stored or logged; only opaque ids persist, cleared on terminal state.
- AC-8. Syndicate-plan tiers activate via the plan subscribe endpoint and reach the same Success.

## 15. Definition of Done

- `feature-subscribe` module merged on `android-port` with package
  `com.testlogon.android.feature.subscribe`, wired into the nav graph from AND-235.
- ViewModel/Repository/Compose surfaces implemented per sections 4–6 with StateFlow-only exposure.
- All ACs in section 14 pass; the Stripe-test activation acceptance test is green in CI.
- Unit + repository + Compose UI tests added (section 11); coverage of state-machine branches and
  the idempotency guard.
- Strings externalized; price formatting locale-correct; TalkBack semantics verified.
- Telemetry events emitted with redaction; no secrets logged.
- Lint/detekt/ktlint clean; builds against compileSdk/targetSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- Open questions in section 13 resolved or explicitly deferred with a tracked follow-up.
