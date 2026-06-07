---
id: AND-236
title: Subscribe flow
milestone: M5
epic: E32
priority: P0
size: L
status: reviewed
reviewed_on: 2026-06-06
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
`GET /ui/billing/subscriptions`. (Correction: `GET /ui/me` does **not** carry entitlement flags —
verified `MeResp` is `{ user_sub, session_id, ip }` only; entitlement is derived solely from the
subscriptions list. The optional `/ui/me` call serves only as an authenticated-session liveness
check, not as the entitlement source.) The acceptance bar is concrete and testable:
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
  - `GET /ui/me` — post-activation **identity/session** liveness check only (returns
    `{ user_sub, session_id, ip }`; **no** entitlement flags — corrected, see §1/§16).
- Auth (verified against `frontend/src/api/client.ts`): requests send **both** an
  `Authorization: Bearer <accessToken>` header (from the auth store) **and** session cookies
  (`credentials: "include"`), plus an `X-CSRF-Token` header echoed from the `ui_csrf` cookie on every
  request. (Correction: the spec previously described auth as "cookie-based" only; a Bearer access
  token is also sent.) A one-shot `POST /ui/session/refresh` runs on 401, then the original request
  is retried once. The persistent cookie jar / Bearer-token store and `ApiResult<T>` wrapper come
  from `core-network`. Note: the OpenAPI also declares optional `X-SESSION-ID`, `X-IMPERSONATION-TOKEN`
  headers and a `user_sub` query param on these ops; the web client does not set `X-SESSION-ID`/`user_sub`
  and only sets `X-IMPERSONATION-TOKEN` during impersonation (not relevant to the fan subscribe flow).
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
`GET /ui/billing/subscriptions` (bounded) until the target subscription appears `active` (matched
by `plan_id`, not `tier_id` — see §5 correction). An optional `GET /ui/me` afterward is a
session-liveness check only; it is **not** the entitlement source.

FR-4. On confirmed activation the flow shows a terminal **success** state, emits a result so the
originating screen (creator profile / tier list) updates entitlement, and unlocks gated content.

FR-5. If the tier maps to a syndicate plan, confirming instead calls
`POST /ui/syndicates/{syndicate_id}/plans/{plan_id}/subscribe` with an (optional) JSON body
`BundleSubscribeIn` = `{ payment_method_id?: string }` (server-side immediate activation; the web
client posts `{}` when no saved method is selected). This skips the Stripe Custom Tab hand-off but
uses the same reconcile + success path. (Correction: the spec previously said "body none"; the
endpoint accepts an optional `BundleSubscribeIn` object.)

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

`POST /ui/syndicates/{syndicate_id}/plans/{plan_id}/subscribe` — optional JSON body
`BundleSubscribeIn` = `{ "payment_method_id": "pm_..." }` (the field is nullable/optional; the web
client posts `{}` by default); auth headers + CSRF as in §2. Response `200` is `BundleSubscriptionOut`;
success implies server-side activation, then reconcile confirms. (Correction: spec previously said
"body none"; verified `req=BundleSubscribeIn` and `frontend/src/api/endpoints/syndicates.ts: subscribeToBundlePlan`.)

**List subscriptions** (reconcile, idempotent GET):

`GET /ui/billing/subscriptions?limit=50`

Response `200` is an open object **keyed `items`** (corrected from `subscriptions`); the web client
types it as `{ items: Subscription[] }`. The verified `Subscription` shape is:
```json
{ "items": [
  { "subscription_id": "sub_...", "plan_id": "plan_gold", "status": "active",
    "billing_cycle": "monthly", "next_billing_date": "2026-07-06" }
] }
```
`Subscription` is open (`[key: string]: unknown`) and has **no** `tier_id`, `id`, `creator_id`, or
`current_period_end` fields (those were spec errors). The link from a tier to a subscription is via
`plan_id`: `TierOut` carries `plan_id` (and `tier_id`, `creator_id`), so the flow must resolve the
selected tier's `plan_id` and match on that.
**Activation predicate (corrected):** any entry where `plan_id == targetTier.plan_id && status == "active"`.
`status` is a free-form string in the schema; treat `"active"` as the activation value (web client
does not constrain it to an enum — confirm exact casing against a live dev response, see §16 open
assumptions).

**Identity refresh:** `GET /ui/me` → `MeResp` = `{ user_sub, session_id, ip }` — **identity/session
only, no entitlement flags** (corrected: spec previously claimed `UiMe` "entitlement flags").
Entitlement is derived entirely from the subscriptions list above; the `/ui/me` call is an optional
post-activation session-liveness check.

Error envelope (FastAPI `detail`): handled by `core-network`'s mapper supporting
`string | [{msg}] | {code,...}`.

## 6. Data & State Management

- `SubscriptionTier` (id, label, priceCents, currency, creatorId, **planId**, optional
  syndicatePlanId) lives in `core-model`, shared with AND-235. Note: the backend `TierOut`
  (verified `src/api/types.ts: TierOut`) exposes `tier_id`, `creator_id`, `plan_id`, `name`,
  `level`, `benefits`, etc. but **does not carry a price on the tier itself** — the recurring price
  (`price_cents`) lives on the associated plan (`SubscriptionPlan`/`BundlePlanOut`). AND-235 is
  responsible for resolving and supplying `priceCents`/`currency` and `planId`; this flow consumes
  them. (Unverified-assumption: exact `SubscriptionTier` Kotlin field set is owned by AND-235.)
- `Subscription` added to `core-model` mapping the verified backend shape:
  `subscriptionId` (`subscription_id`), `planId` (`plan_id`), `status`, optional `billingCycle`
  (`billing_cycle`), optional `nextBillingDate` (`next_billing_date`). (Corrected: there is no
  `tier_id`/`creator_id`/`current_period_end` on the subscription; entitlement is matched by
  `plan_id`. The model should retain the tier→plan link by carrying `SubscriptionTier.planId`.)
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
- **`/ui/billing/subscriptions` response** — *Resolved during review.* Verified against
  `frontend/src/api/endpoints/billing.ts: getSubscriptions` and `src/api/types.ts: Subscription`:
  the response is keyed `items` (`{ items: Subscription[] }`) and each entry uses `subscription_id`,
  `plan_id`, `status` (+ open extra keys). There is **no** `tier_id`; match by `plan_id`. The only
  residual unknown is the exact `status` string casing/enum values, which the schema leaves
  free-form — confirm against a live dev response (carried to §16 open assumptions).
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the authoritative source pointer.

1. **`POST /ui/billing/checkout_session` exists, takes `BillingCheckoutReq`.** Verified.
   Source: OpenAPI `POST /ui/billing/checkout_session` (op `create_checkout_session_ui_billing_checkout_session_post`,
   `req=BillingCheckoutReq`); `frontend/src/api/endpoints/billing.ts: createCheckoutSession`.
2. **`BillingCheckoutReq` = `{ amount_cents (required int), currency? (string|null), description? (string|null) }`.**
   Verified. Source: OpenAPI `components.schemas.BillingCheckoutReq`; `src/api/types.ts: BillingCheckoutReq`.
3. **checkout_session 200 response is a string→string map exposing `url` + `session_id`.** Verified.
   Source: OpenAPI 200 schema `additionalProperties: {type: string}`; `frontend/src/api/endpoints/billing.ts`
   types it `{ session_id: string; url: string }`.
4. **`GET /ui/billing/subscriptions` exists with `limit` query param.** Verified.
   Source: OpenAPI `GET /ui/billing/subscriptions` (`params=limit,...`); `billing.ts: getSubscriptions` posts `{ limit }`.
5. **List-subscriptions response key is `items` (NOT `subscriptions`).** Corrected.
   Source: `frontend/src/api/endpoints/billing.ts: getSubscriptions` → `{ items: Subscription[] }`.
6. **`Subscription` fields are `subscription_id`, `plan_id`, `status`, `billing_cycle?`, `next_billing_date?`
   (open object); no `tier_id`/`id`/`creator_id`/`current_period_end`.** Corrected (spec claimed
   `id/tier_id/current_period_end/creator_id`). Source: `src/api/types.ts: Subscription`.
7. **Activation predicate must match on `plan_id` (resolved from the tier), not `tier_id`.** Corrected.
   Source: `src/api/types.ts: Subscription` (no `tier_id`) + `src/api/types.ts: TierOut` (carries `plan_id`).
8. **`GET /ui/me` → `MeResp` = `{ user_sub, session_id, ip }`; no entitlement flags.** Corrected
   (spec claimed `UiMe` with "entitlement flags"). Source: OpenAPI `GET /ui/me`; `src/api/types.ts: MeResp`;
   `frontend/src/api/endpoints/auth.ts: getMe`.
9. **`POST /ui/syndicates/{syndicate_id}/plans/{plan_id}/subscribe` exists; takes optional
   `BundleSubscribeIn` body `{ payment_method_id?: string|null }` (NOT "body none").** Corrected.
   Source: OpenAPI op `subscribe_to_bundle_...` (`req=BundleSubscribeIn`); `components.schemas.BundleSubscribeIn`;
   `frontend/src/api/endpoints/syndicates.ts: subscribeToBundlePlan` (posts `{}` by default) → `BundleSubscriptionOut`.
10. **`GET /ui/fan-club/tiers` is the tier source; `TierOut` carries `tier_id`, `creator_id`,
    `plan_id`, `name`, `benefits`, etc. but no price on the tier (price lives on the plan).** Verified.
    Source: OpenAPI `GET /ui/fan-club/tiers`; `src/api/types.ts: TierOut`; `frontend/src/api/endpoints/fan-club.ts: listTiers`.
11. **Auth: `Authorization: Bearer <accessToken>` header AND cookies (`credentials: include`) AND
    `X-CSRF-Token` from the `ui_csrf` cookie.** Corrected (spec said "cookie-based" only; omitted the
    Bearer token). Source: `frontend/src/api/client.ts` (lines ~157–171).
12. **401 handling: one-shot `POST /ui/session/refresh`, then retry the original request once; second
    401 → logout/re-auth.** Verified. Source: `frontend/src/api/client.ts: refreshSession` + 401 branch.
13. **Error envelope is FastAPI `detail` supporting `string | [{msg}] | {code,...}`.** Verified.
    Source: `frontend/src/api/client.ts: normalizeErrorDetail`; validation errors are `HTTPValidationError`
    (422) per OpenAPI on all four ops.
14. **Validation failures return HTTP 422 `HTTPValidationError`.** Verified.
    Source: OpenAPI `resp=...;422:HTTPValidationError` on checkout_session, subscriptions, syndicate subscribe, /ui/me.
15. **Custom Tabs gives no reliable result code; reconcile (not the return signal) is the source of truth.**
    Unverified-assumption (framework behavior, not in the backend/frontend sources).
    Framework ref: https://developer.chrome.com/docs/android/custom-tabs/ (no Activity result is returned).
16. **AndroidX Browser Custom Tabs / `CustomTabsIntent` for the Stripe hand-off.** Framework ref:
    https://developer.android.com/develop/ui/views/layout/web/loading-pages-in-app (Custom Tabs guidance).
17. **DataStore Preferences for `last_pending_checkout` resume state.** Unverified-assumption (Android
    impl choice). Framework ref: https://developer.android.com/topic/libraries/architecture/datastore.
18. **Price formatting via `java.text.NumberFormat.getCurrencyInstance(locale)` from minor units.**
    Unverified-assumption (impl choice, locale-correct). Framework ref:
    https://developer.android.com/reference/java/text/NumberFormat#getCurrencyInstance(java.util.Locale).
19. **`POST /ui/session/refresh` endpoint exists and is the refresh mechanism.** Verified.
    Source: `frontend/src/api/client.ts: refreshSession` calls `POST /ui/session/refresh`.

### Corrections made

- §1, §2, §3 (FR-3), §5, §16: `GET /ui/me` does **not** return entitlement flags; `MeResp` is
  `{ user_sub, session_id, ip }`. Entitlement is derived from the subscriptions list only.
- §2, §16: Auth is Bearer token **plus** cookies **plus** `X-CSRF-Token`, not "cookie-based" alone.
- §3 (FR-5), §5: Syndicate subscribe takes an optional `BundleSubscribeIn` `{ payment_method_id? }`
  body, not "body none".
- §5: List-subscriptions response is keyed `items` (was `subscriptions`); `Subscription` fields
  corrected to `subscription_id/plan_id/status/billing_cycle?/next_billing_date?` (removed the
  fictional `id/tier_id/creator_id/current_period_end`).
- §3 (FR-3), §5, §6, §13: Activation predicate matches on `plan_id` (resolved from the tier), not
  `tier_id`, since `Subscription` has no `tier_id`.
- §6: Clarified that `TierOut` carries no price; the recurring price lives on the plan.
- §13: Marked the subscriptions-response open question as resolved.

### Open assumptions

- **`status` value casing/enum for an active subscription.** The OpenAPI/`Subscription` type leave
  `status` a free-form string; `"active"` is assumed but unconfirmed because the schema is open and
  no enum is published. Confirm against a live dev response before pinning the predicate.
- **Custom Tabs return semantics / deep-link `com.testlogon.android://billing/return`.** The deep-link
  scheme and the "no result code" behavior are Android-side assumptions; not derivable from the
  backend/frontend sources (the web client uses an in-page redirect, not an Android Custom Tab).
- **Process-death resume via DataStore, Room cache of active subscriptions, telemetry event names,
  and the `SubscriptionTier`/`PaymentLauncher` Kotlin shapes.** All Android implementation choices
  with no authoritative backend/frontend counterpart; owned by this ticket / AND-235.
- **`SubscriptionTier.priceCents`/`currency`/`planId` resolution.** Owned by AND-235; the price is
  not on `TierOut` and must be sourced from the plan. Confirm exact mapping with AND-235 output.

## 17. Test Plan

Test targets: **JVM** = local JVM unit/Robolectric; **MWS** = JVM + MockWebServer (contract);
**emu35** = headless emulator AVD `test35` (x86_64, API 35); **A15** = physical Samsung Galaxy A15 5G
(SM-A156U, serial R5CX821TA9R, API 34, arm64-v8a). Compose-UI cases run on emu35 unless they need
real hardware. Traces link to §14 acceptance criteria.

- **TC-AND-236-01 — Happy path: confirm → checkout → reconcile → success.**
  Type: unit (JVM + Turbine + MockWebServer). Target: MWS.
  Preconditions: MWS stubs `POST /ui/billing/checkout_session` → 200 `{ "url":"https://checkout.stripe.com/...","session_id":"cs_test_1" }`;
  `GET /ui/billing/subscriptions` → first empty `{ "items":[] }`, then `{ "items":[{ "subscription_id":"sub_1","plan_id":"plan_gold","status":"active" }] }`.
  Steps: load tier (planId=`plan_gold`); call `confirmSubscribe()`; simulate `onReturnFromPayment(success)`; advance poll scheduler.
  Expected: emitted state sequence `Confirm → AwaitingPayment → Reconciling → Success(subscriptionId="sub_1", tierId)`;
  checkout POST body has `amount_cents` matching tier and a `currency`; activation matched on `plan_id`.
  Traces: AC-1, AC-2.

- **TC-AND-236-02 — Checkout request contract: body + CSRF + Bearer headers.**
  Type: contract/MockWebServer. Target: MWS.
  Preconditions: auth store seeded with access token + `ui_csrf` cookie; tier priceCents=999, currency=usd.
  Steps: `confirmSubscribe()`; inspect the recorded `checkout_session` request.
  Expected: `POST /ui/billing/checkout_session`; JSON body `{ "amount_cents":999, "currency":"usd", ... }`;
  headers include `X-CSRF-Token` and `Authorization: Bearer ...`; client reads `url` + `session_id` from the string-map response.
  Traces: AC-1, AC-7.

- **TC-AND-236-03 — Reconcile backoff: active on 3rd poll.**
  Type: unit. Target: JVM (virtual time / TestScheduler).
  Preconditions: MWS returns inactive/empty for polls 1–2, active (matching `plan_id`) on poll 3.
  Steps: enter `Reconciling`; advance virtual clock through backoff `1s,2s,4s`.
  Expected: success at attempt 3; no further polls issued after the match; backoff schedule honored.
  Traces: AC-2.

- **TC-AND-236-04 — Reconcile timeout after 6 attempts.**
  Type: unit. Target: JVM.
  Preconditions: subscriptions never returns an active matching entry.
  Steps: enter `Reconciling`; exhaust all 6 attempts (cap 8s).
  Expected: `Error(RECONCILE_TIMEOUT, retryable=true)` with continue-checking affordance; exactly 6 polls.
  Traces: AC-5.

- **TC-AND-236-05 — Idempotency: pre-existing active subscription short-circuits, no checkout POST.**
  Type: contract/MockWebServer. Target: MWS.
  Preconditions: `GET /ui/billing/subscriptions` already returns `{ "items":[{ "plan_id":"plan_gold","status":"active","subscription_id":"sub_x" }] }`.
  Steps: `confirmSubscribe()`.
  Expected: routes straight to `Success`; **zero** `POST /ui/billing/checkout_session` requests recorded by MWS (no double charge).
  Traces: AC-4.

- **TC-AND-236-06 — Syndicate-plan variant uses subscribe endpoint, not checkout_session.**
  Type: contract/MockWebServer. Target: MWS.
  Preconditions: tier has `syndicatePlanId`; MWS stubs `POST /ui/syndicates/{sid}/plans/{pid}/subscribe` → 200 `BundleSubscriptionOut`; subscriptions then returns active.
  Steps: `confirmSubscribe()`.
  Expected: a `POST .../subscribe` is issued with optional body `{}` (or `{ payment_method_id }`); **no** `checkout_session` POST; no Custom Tab launch; reconcile → `Success`.
  Traces: AC-8.

- **TC-AND-236-07 — Cancelled payment yields retryable error; retry re-creates session.**
  Type: unit. Target: JVM/MWS.
  Preconditions: return-from-payment signals cancel (cancel deep link or resume with no new subscription after one poll).
  Steps: `onReturnFromPayment(cancel)`; then `retry()`.
  Expected: `Error(PAYMENT_CANCELLED, retryable=true)` (no charge implied); `retry()` issues a fresh `checkout_session` POST and re-enters the flow.
  Traces: AC-5.

- **TC-AND-236-08 — 401 mid-flow triggers one session refresh then retry.**
  Type: contract/MockWebServer. Target: MWS.
  Preconditions: first `checkout_session` (or reconcile GET) → 401; `POST /ui/session/refresh` → 200; retry → 200.
  Steps: drive the call that 401s.
  Expected: exactly one `POST /ui/session/refresh`, original request retried once and succeeds; a *second* 401 surfaces `Error(NETWORK)` and routes to re-auth.
  Traces: AC-5.

- **TC-AND-236-09 — Validation error (422 HTTPValidationError) surfaces a readable error.**
  Type: contract/MockWebServer. Target: MWS.
  Preconditions: `checkout_session` → 422 `{ "detail":[{ "loc":["body","amount_cents"], "msg":"field required", "type":"value_error" }] }`.
  Steps: `confirmSubscribe()`.
  Expected: error mapper extracts `msg` ("field required"); state `Error(CHECKOUT_FAILED, retryable=true)`; no crash on the array-of-objects detail shape.
  Traces: AC-5.

- **TC-AND-236-10 — Offline: confirm disabled + banner; reconcile shows stale and auto-resumes.**
  Type: instrumented/integration. Target: emu35 (toggle connectivity via emulator).
  Preconditions: connectivity off at Confirm; turn on after entering reconcile.
  Steps: open ConfirmSheet offline; observe disabled confirm + banner; go online during reconcile.
  Expected: confirm disabled with offline banner (no hard failure); reconcile renders stale/offline state and auto-resumes polling on connectivity regain.
  Traces: AC-6.

- **TC-AND-236-11 — Process-death resume into Reconciling.**
  Type: instrumented/e2e. Target: A15 (real Custom Tab + process death; arm64/API-34 behavior).
  Preconditions: `last_pending_checkout` persisted in DataStore; kill the app while the Stripe Custom Tab is foreground.
  Steps: relaunch the app.
  Expected: app restores into `Reconciling` (not a fresh confirm), polls subscriptions, and reaches `Success`/error; DataStore entry cleared on terminal state.
  *Must run on physical device* (real Custom Tab hand-off + process death are unreliable on headless emulator).
  Traces: AC-4, AC-2.

- **TC-AND-236-12 — Stripe-test acceptance: real payment activates subscription.**
  Type: instrumented/e2e (gating). Target: A15 (real Custom Tab, real network to Stripe test mode).
  Preconditions: Stripe test mode; dev backend reachable; generous reconcile budget.
  Steps: confirm → enter Stripe **test** card in the Custom Tab → return → reconcile.
  Expected: subscription reaches `status=="active"` (matched by `plan_id`); flow lands on `Success` with a `subscriptionId`; satisfies "Subscription activates (test)".
  *Must run on physical device* (real HTTPS Custom Tab + real Stripe interaction).
  Traces: AC-2, AC-3.

- **TC-AND-236-13 — Entitlement result propagates; gated content unlocks.**
  Type: integration. Target: emu35.
  Preconditions: reconcile returns active; originating screen registered for the `"subscribe_result"` SavedStateHandle key.
  Steps: complete flow; return to creator profile / tier list.
  Expected: originating screen receives the subscribe result and re-renders entitled state; gated content for that tier is unlocked (Room cache upserted, confirmed by reconcile). Entitlement is taken from the subscriptions list, not `/ui/me`.
  Traces: AC-3.

- **TC-AND-236-14 — No card PII stored/logged; only opaque ids; cleared on terminal state.**
  Type: unit + manual log inspection. Target: JVM (asserts) + A15 (logcat scan).
  Preconditions: run a full happy-path flow.
  Steps: inspect DataStore/Room contents and logcat output.
  Expected: only `session_id`/`subscription_id`/`tier_id`/`plan_id` persisted; `session_id`/`subscription_id` redacted to last 6 chars in logs; no cookies/CSRF/Bearer token logged; pending-checkout cleared on terminal success/cancel.
  Traces: AC-7.

- **TC-AND-236-15 — Accessibility: ConfirmSheet/Reconciling/Success semantics.**
  Type: Compose-UI. Target: emu35 (TalkBack/semantics assertions).
  Preconditions: launch each surface with sample data; large font scale.
  Steps: assert price string is locale-formatted (NumberFormat, not concatenated); confirm/retry/cancel are ≥48dp with contentDescription; reconciling spinner is a `liveRegion`; ConfirmSheet scrolls at large font scale.
  Expected: all semantics present; success terminal state announced to TalkBack.
  Traces: AC-1, AC-2, AC-6.

### Coverage matrix

| AC (§14) | Covered by |
| --- | --- |
| AC-1 | TC-AND-236-01, -02, -15 |
| AC-2 | TC-AND-236-01, -03, -11, -12, -15 |
| AC-3 | TC-AND-236-12, -13 |
| AC-4 | TC-AND-236-05, -11 |
| AC-5 | TC-AND-236-04, -07, -08, -09 |
| AC-6 | TC-AND-236-10, -15 |
| AC-7 | TC-AND-236-02, -14 |
| AC-8 | TC-AND-236-06 |
