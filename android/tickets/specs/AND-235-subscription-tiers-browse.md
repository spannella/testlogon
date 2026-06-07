---
id: AND-235
title: Subscription tiers browse
milestone: M5
epic: E32
priority: P0
size: M
depends_on: [AND-234]
blocks: []
status: reviewed
reviewed_on: 2026-06-06
---

# AND-235 — Subscription tiers browse

## 1. Overview & Goal

Provide a read-only browse experience that renders a creator's published subscription
tiers with pricing inside the Android app. A fan viewing a creator profile must be able
to see every active tier the creator offers, the per-tier price and billing interval,
the benefits/perks attached to each tier, and which tier (if any) the current viewer is
already subscribed to. This ticket delivers the `feature-subscriptions` browse screen,
its `ViewModel`, `UiState`, Compose UI, and the repository wiring that consumes the
typed API surface and DTO/domain mappers delivered by **AND-234** (Subscriptions API +
DTOs).

Out of scope: initiating a purchase/checkout, payment processing, Google Play Billing
integration, tier management/editing (creator side), and subscription cancellation.
Those are downstream tickets in epic E32; this screen's only actionable affordance is a
"Subscribe" CTA that emits a navigation event to a not-yet-built checkout route
(stubbed behind a feature flag — see §3 and §13). The goal is strictly **display tiers
with pricing**, satisfying the acceptance bullet "Tiers render with pricing."

Success means: given a `creatorId`, the screen loads the creator's tiers (with cache),
renders each tier card with name, price, interval, and perks, marks the viewer's current
tier, and degrades gracefully to loading/empty/error and offline/stale states.

## 2. Context & References

- **Module layering:** `app -> feature-subscriptions -> core-* (core-network,
  core-model, core-data, core-ui, core-testing)`. This ticket adds the browse screen to
  `feature-subscriptions`. The API client, DTOs, domain models, and mappers live in
  `core-network`/`core-model`/`core-data` and are owned by **AND-234**.
- **Upstream (AND-234):** `SubscriptionsApi` (Retrofit), `TierDto`/`SubscriptionDto`
  Moshi DTOs, `SubscriptionTier`/`Subscription` domain models, and
  `Tier(s)/Sub(s) map` mappers (tested). This ticket depends on those types existing and
  compiling. AND-234 depends on AND-027 (core-network/HTTP client + cookie jar +
  ApiResult).
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext
  HTTP, unreliable). OpenAPI at `/openapi.json`. Web reference:
  `frontend/src/api/endpoints/subscriptions.ts` and shared types in
  `frontend/src/api/types.ts` — these are the source of truth for endpoint paths and
  JSON shapes; AND-234's DTOs mirror them. **CORRECTED:** the feature is modelled
  server-side as subscription **plans**, not "tiers"; the web client lists a creator's
  plans via `GET /api/creators/{creatorId}/plans` (returns `SubscriptionPlan[]`) and the
  viewer's subscriptions via `GET /api/subscriptions`. The `/ui/...subscription-tiers`
  paths used in earlier drafts of this spec do not exist for this flow (see §5 and §16).
- **Auth:** the shared transport (web `src/api/client.ts`) attaches, on **every** call:
  `Authorization: Bearer <accessToken>` (from the auth store), the `X-CSRF-Token` header
  echoed from the `ui_csrf` cookie, and session cookies (`credentials: "include"`). The
  subscription endpoints additionally send an `X-User-Id` header for the *authenticated*
  reads (`GET /api/subscriptions`); the **public** plans list
  (`GET /api/creators/{creatorId}/plans`) does not require `X-User-Id`. A single 401 ->
  `POST /ui/session/refresh` -> retry is handled centrally and is transparent to this
  screen; on the Android side AND-027 owns the cookie jar / token / CSRF / refresh
  interceptor. **CORRECTED:** prior draft described this as purely cookie-based; the web
  reference also sends a Bearer token and (for `me` reads) `X-User-Id`.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Navigation-Compose, Hilt (KSP),
  Coroutines/Flow, Retrofit 2.11/OkHttp 4.12/Moshi 1.15, Room 2.6, Coil. minSdk 24,
  compileSdk/targetSdk 35, JDK 17.

## 3. Functional Requirements

FR-1. The screen accepts a required `creatorId: String` nav argument and an optional
`creatorDisplayName: String?` for the header before data loads.

FR-2. On entry the screen requests the creator's tiers and the viewer's current
subscription state for that creator in a single combined load.

FR-3. Each tier (plan) renders as a card showing: plan name, formatted price + currency,
billing interval (e.g. "/month"), an optional short description, and a list of perks.
**CORRECTED:** the backend `SubscriptionPlan` has no `perks`/`benefits` array; the web
client (`PlanBrowser.tsx`) renders the plan's `assets[].name` list as the feature
bullets. Android maps perks from `assets[].name` (AND-234 mapper); if AND-234 instead
surfaces a dedicated benefits field, the mapper is the single point of change. Ordering:
the web client does **not** sort and there is no `sort_order` field on the plan — it
preserves server order and marks the middle plan "popular". Android's ascending-price
sort is a deliberate product choice (see §16 open assumptions), with ties broken by name
(no `sortOrder` field exists).

FR-4. Only active plans are shown. **CORRECTED:** activeness is `status == "active"` (a
string field on `SubscriptionPlan`), not an `isActive`/`is_active` boolean. The web
client filters `plans.filter(p => p.status === "active")`; Android filters the same way
client-side as a defensive measure even if the backend already filters.

FR-5. Price formatting: prices arrive as integer cents (`price_cents`) plus an ISO-4217
`currency` code. **CORRECTED:** the field is `price_cents`, not `price_minor`. They MUST
be rendered using `java.text.NumberFormat.getCurrencyInstance`
with the device locale, with the currency forced to the tier's `currency` code (do not
trust the locale's default currency). Free tiers (`priceCents == 0`) render the
localized string "Free". **NOTE:** the web client has no "Free" special-case (it always
formats `cents/100` as currency) — the "Free" rendering is an Android product choice
(see §16 open assumptions).

FR-6. If the viewer is currently subscribed to one of the listed tiers, that card is
visually distinguished ("Current plan" badge + selected styling) and its CTA reads
"Manage" (disabled stub) instead of "Subscribe".

FR-7. The "Subscribe" CTA emits a one-shot `SubscriptionsEvent.NavigateToCheckout(
tierId)` navigation event. When the checkout feature flag is off (default for this
milestone), the CTA is shown but tapping it emits a `ShowSnackbar("Coming soon")`
event instead. This keeps the screen self-contained and testable without the checkout
route.

FR-8. States: Loading (skeleton/shimmer list), Content (tier list), Empty ("This
creator has no subscription tiers yet."), Error (message + Retry). A `stale` flag
overlays a non-blocking banner when content is served from cache while the network call
is in flight or failed.

FR-9. Pull-to-refresh re-fetches tiers (idempotent GET; bounded backoff retry applies —
see §7).

FR-10. The screen must function on minSdk 24 and survive configuration changes
(rotation) without re-fetching, restoring the last `UiState` from the `ViewModel`.

## 4. Technical Design

New module artifacts under `feature-subscriptions`
(`com.testlogon.android.feature.subscriptions.browse`):

```kotlin
// Navigation route
object SubscriptionTiersRoute {
    const val PATH = "subscriptions/tiers/{creatorId}"
    const val ARG_CREATOR_ID = "creatorId"
    const val ARG_DISPLAY_NAME = "creatorDisplayName" // optional query param
    fun build(creatorId: String, displayName: String? = null): String
}

fun NavGraphBuilder.subscriptionTiersScreen(
    onNavigateToCheckout: (tierId: String) -> Unit,
    onBack: () -> Unit,
)
```

UI state and events:

```kotlin
data class SubscriptionTiersUiState(
    val isLoading: Boolean = false,
    val isRefreshing: Boolean = false,
    val creatorDisplayName: String? = null,
    val tiers: List<TierUiModel> = emptyList(),
    val currentTierId: String? = null,   // viewer's active tier, if any
    val stale: Boolean = false,          // content served from cache
    val error: UiError? = null,          // mutually exclusive w/ non-empty tiers only when no cache
) {
    val isEmpty: Boolean get() = !isLoading && error == null && tiers.isEmpty()
}

data class TierUiModel(
    val id: String,
    val name: String,
    val description: String?,
    val formattedPrice: String,   // e.g. "$4.99" or "Free"
    val intervalLabel: String,    // e.g. "/month", "/year", "" for free
    val perks: List<String>,
    val isCurrent: Boolean,
)

sealed interface SubscriptionsEvent {
    data class NavigateToCheckout(val tierId: String) : SubscriptionsEvent
    data class ShowSnackbar(val message: String) : SubscriptionsEvent
}
```

ViewModel (Hilt, `StateFlow<UiState>` per project convention):

```kotlin
@HiltViewModel
class SubscriptionTiersViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val repository: SubscriptionsRepository,   // from AND-234/core-data
    private val priceFormatter: PriceFormatter,        // core-ui util
    private val featureFlags: FeatureFlags,            // core-data DataStore
) : ViewModel() {

    private val creatorId: String = checkNotNull(savedStateHandle[ARG_CREATOR_ID])

    private val _uiState = MutableStateFlow(SubscriptionTiersUiState(isLoading = true))
    val uiState: StateFlow<SubscriptionTiersUiState> = _uiState.asStateFlow()

    private val _events = Channel<SubscriptionsEvent>(Channel.BUFFERED)
    val events: Flow<SubscriptionsEvent> = _events.receiveAsFlow()

    init { load(forceRefresh = false) }

    fun onRefresh() = load(forceRefresh = true)
    fun onRetry() = load(forceRefresh = true)
    fun onSubscribeClick(tierId: String) { /* flag gate -> emit event */ }

    private fun load(forceRefresh: Boolean) { /* collect repo flow, map to UiState */ }
}
```

Repository contract consumed (declared in AND-234, restated here so the dependency is
explicit):

```kotlin
interface SubscriptionsRepository {
    // Emits cache-first then network; ApiResult carries stale flag via Resource wrapper
    fun observeCreatorTiers(creatorId: String): Flow<Resource<CreatorTiers>>
    suspend fun refreshCreatorTiers(creatorId: String): ApiResult<Unit>
}

data class CreatorTiers(
    val tiers: List<SubscriptionTier>,
    val currentSubscription: Subscription?,
)
```

`PriceFormatter` (core-ui) wraps `NumberFormat` and is injected to keep formatting unit
testable:

```kotlin
class PriceFormatter @Inject constructor(@ApplicationContext ctx: Context) {
    fun format(priceCents: Long, currency: String, locale: Locale = Locale.getDefault()): String
    fun intervalLabel(interval: BillingInterval): String
}
```

Compose layer: a stateless `SubscriptionTiersContent(state, onRefresh, onRetry,
onSubscribeClick)` composable plus a stateful `SubscriptionTiersScreen(viewModel,
onNavigateToCheckout, onBack)` that collects `uiState` with
`collectAsStateWithLifecycle()` and consumes `events` in a
`LaunchedEffect(Unit) { events.collect { ... } }`. Tier cards use Material 3 `Card`
with `LazyColumn`; loading uses a shimmer placeholder list of 3 cards. Pull-to-refresh
via Material 3 `PullToRefreshBox`.

## 5. API Contract

This screen issues no new endpoints; it consumes the typed `SubscriptionsApi` from
**AND-234**. Paths/shapes mirror `frontend/src/api/endpoints/subscriptions.ts` and
`frontend/src/api/types.ts` and are restated here, **verified against the web reference
and `/openapi.json`** (see §16). The paths below replace the non-existent
`/ui/...subscription-tiers` and `/ui/me/subscriptions` paths from earlier drafts.

`GET /api/creators/{creatorId}/plans` — list a creator's subscription plans (this is the
"tiers" browse source). Query params: `include_profile` (optional). **Public** — does not
require `X-User-Id` (still carries the standard Bearer/CSRF/cookies). Returns a **bare
JSON array** of `SubscriptionPlan` (NOT an object wrapped in `{"tiers": [...]}`).
Verified: OpenAPI `GET /api/creators/{creator_id}/plans` (op `list_plans_...`); web
`src/api/endpoints/subscriptions.ts: listPlans`; type `src/api/types.ts: SubscriptionPlan`.

```jsonc
// SubscriptionPlan[]  — bare array
[
  {
    "plan_id": "plan_01H...",
    "creator_id": "usr_01H...",
    "name": "Supporter",
    "description": "Early access posts",
    "price_cents": 499,
    "currency": "USD",
    "interval": "month",
    "annual_price_cents": 4999,
    "status": "active",
    "metadata": {},
    "assets": [
      { "path": "...", "name": "Early access", "type": "...", "size": 0, "content_type": "..." }
    ],
    "created_at": 1730000000,
    "updated_at": 1730000000
  }
]
```

Field corrections vs earlier draft: `id` -> `plan_id`; `price_minor` -> `price_cents`;
`billing_interval` -> `interval`; `is_active` (bool) -> `status` (string, e.g.
`"active"`); there is **no** `perks` field (perks come from `assets[].name`) and **no**
`sort_order` field.

`GET /api/subscriptions` — viewer's own subscriptions, used to derive `currentTierId`.
**CORRECTED:** there is no `?creator_id=` filter on this endpoint — the web client calls
it with only an optional `include_summary=true` (and `include_profile`/`subscriber_id`
exist per OpenAPI but are not used by the browse flow); filter to the current creator
client-side by matching `creator_id` on each returned `SubscriptionOut`. Sends `X-User-Id`
(authenticated). Returns a **bare JSON array** of `SubscriptionOut` (NOT
`{"subscriptions": [...]}`). The active entry (`status == "active"`, not past
`current_period_end`) whose `creator_id` matches selects the current plan; its `plan_id`
becomes `currentTierId`. Verified: OpenAPI `GET /api/subscriptions` (op
`list_subscriptions_api_subscriptions_get`); web `subscriptions.ts: listSubscriptions`;
type `src/api/types.ts: SubscriptionOut`.

```jsonc
// SubscriptionOut[]  — bare array
[
  {
    "subscription_id": "sub_01H...",
    "plan_id": "plan_01H...",
    "creator_id": "usr_01H...",
    "subscriber_id": "usr_me...",
    "interval": "month",
    "status": "active",
    "current_period_end": 1751328000,
    "cancel_at_period_end": false,
    "price_cents": 499,
    "currency": "USD",
    "auto_renew": true
  }
]
```

Field corrections vs earlier draft: `id` -> `subscription_id`; `tier_id` -> `plan_id`;
`current_period_end` is a **Unix epoch number** (seconds), not an ISO-8601 string.

Mapping notes (owned by AND-234, asserted by this ticket's integration tests):
`price_cents` (int cents) -> `priceCents: Long`; `interval` string -> `BillingInterval`
enum (`MONTH`/`YEAR`/`WEEK`, unknown -> `MONTH` with logged warning); `status == "active"`
-> active filter; `assets[].name` -> `perks`. Both calls are idempotent GETs and eligible
for bounded backoff retry. FastAPI error bodies use the shared `detail` mapping (string |
array of `{loc,msg,type}` from `HTTPValidationError` on 422 | object `{code,...}` for
authz errors) handled by AND-027's error mapper into `UiError` — verified against
`src/api/client.ts: normalizeErrorDetail` and OpenAPI `HTTPValidationError`.

## 6. Data & State Management

- **Source of truth:** `SubscriptionsRepository` exposes a cache-first `Flow<Resource<
  CreatorTiers>>`. The ViewModel maps `Resource.Loading/Success/Error` (each carrying an
  optional cached payload + `fromCache` flag) into `SubscriptionTiersUiState`.
- **Room cache (AND-234):** tiers persist in a `subscription_tiers` table keyed by
  `(creatorId, id)`; viewer subs in `subscriptions`. This screen reads through the
  repository only — no direct DAO access. On a cold start with cache present, the screen
  shows cached tiers immediately with `stale = true` until the network refresh resolves.
- **DataStore (prefs):** `FeatureFlags.subscriptionCheckoutEnabled: Flow<Boolean>`
  (default `false`) gates the Subscribe CTA behavior.
- **Combining streams:** `currentTierId` is derived by joining the viewer-subscription
  list against the tier list inside the repository's `CreatorTiers` so the UI receives a
  single consistent snapshot (avoids flicker between two independent flows).
- **Process death:** `creatorId`/`creatorDisplayName` survive via `SavedStateHandle`;
  `uiState` is reconstructed from the cache-first flow on recreation, so no explicit
  `UiState` parceling is needed. Rotation reuses the retained `ViewModel`.

## 7. Error Handling & Resilience

- **Timeouts:** OkHttp call/read/connect timeouts ~20s (from AND-027) given the
  unreliable dev host. The screen shows the Error state with a Retry action on timeout
  when no cache exists; with cache it keeps content and shows the stale banner.
- **Retry/backoff:** both GETs are idempotent, so the repository applies bounded
  exponential backoff (e.g. 3 attempts, base 500ms, jitter, cap ~4s) for transient
  failures (timeouts, 5xx, connection reset). No retry on 4xx (other than the single
  transparent 401 -> `/ui/session/refresh` -> retry handled by the auth interceptor).
- **Error taxonomy -> UiError:** network/IO -> "Can't reach TestLogon. Check your
  connection."; 401 after refresh fails -> emit auth event to route to sign-in (handled
  by app shell); 404 (creator not found) -> Empty state with a distinct message; 5xx /
  parse error -> generic "Something went wrong" + Retry. All map via AND-027's
  `detail` parser.
- **Empty vs error disambiguation:** a successful 200 with zero active tiers -> Empty;
  failure with no cache -> Error; failure with cache -> stale Content.
- **Refresh failure:** pull-to-refresh that fails while cached content is shown does not
  clear the list; it emits `ShowSnackbar` and sets `stale = true`.

## 8. Security & Privacy

- All requests ride the persistent cookie jar + `X-CSRF-Token` header from AND-027; this
  screen adds no auth logic. No tokens or credentials are logged.
- Tier and pricing data is not PII, but the viewer's `currentSubscription` reveals what
  the signed-in user pays for; it must never be cached unencrypted under a shared key —
  it is stored in the app-private Room DB (default app sandbox) and cleared on
  sign-out via the existing session-clear hook (AND-027). Add `subscriptions` and
  `subscription_tiers` table wipes to that hook if AND-234 has not already.
- Dev backend is plaintext HTTP; cleartext is permitted only for the dev flavor's
  `network_security_config`. Production builds disallow cleartext. No change owned here
  beyond confirming the dev base URL is flavor-scoped.
- No deep-link exposure of another user's subscription state: the `currentTierId`
  derivation uses `GET /api/subscriptions` (CORRECTED path), which is scoped to the
  session owner server-side (via session cookie + `X-User-Id`).

## 9. Accessibility & i18n

- All user-facing strings live in `feature-subscriptions/src/main/res/values/strings.xml`
  (`R.string.subs_tiers_*`). No hardcoded text in composables. Includes: title, empty,
  error, retry, "Free", "Current plan", "Subscribe", "Manage", "Coming soon", stale
  banner.
- Price/interval formatting is locale-aware (`NumberFormat.getCurrencyInstance`,
  `Locale.getDefault()`); the currency symbol/position follows the user's locale while
  honoring the tier's ISO-4217 code.
- Each tier `Card` exposes a merged semantics node:
  `contentDescription = "<name>, <price> <interval>, current plan"` so TalkBack reads a
  single coherent label. CTA buttons have distinct `contentDescription`s.
- Touch targets >= 48dp; tier cards and CTAs meet this. Text uses Material 3 typography
  scales and respects font scaling (no fixed `sp` lockouts); cards reflow with
  `wrapContentHeight`.
- Color is not the sole signal for the current tier (badge text + icon, not just
  border color). Contrast meets WCAG AA via Material 3 theme tokens.
- RTL supported via `start/end` paddings and `LazyColumn` default mirroring.

## 10. Telemetry & Logging

- Analytics events (via the app's existing `Analytics` facade, no PII):
  `subs_tiers_viewed { creator_id, tier_count, has_current_sub }`,
  `subs_tier_subscribe_tapped { creator_id, tier_id, flag_enabled }`,
  `subs_tiers_load_failed { creator_id, error_type }`,
  `subs_tiers_refreshed { creator_id, from_cache }`.
- Logging: structured `Timber` logs at `d` for state transitions and `w` for unknown
  unknown `interval` enum fallback and parse warnings. Never log cookies, CSRF tokens,
  or full response bodies. Network-layer logging uses the shared OkHttp logging
  interceptor (BODY level only in debug builds).
- The stale-banner display and retry taps are logged at `d` to aid diagnosing the
  unreliable dev host.

## 11. Testing Strategy

Unit (JVM, `core-testing` + Turbine + MockK):
- `PriceFormatterTest`: 499/USD -> "$4.99" under en-US; 0 -> "Free"; EUR under de-DE
  formats correctly; unknown currency code does not crash.
- `SubscriptionTiersViewModelTest`: loading -> success maps tiers sorted by price;
  `currentTierId` derived correctly; empty list -> `isEmpty`; error with no cache ->
  Error state; error with cache -> stale Content; inactive tiers filtered;
  `onSubscribeClick` emits `NavigateToCheckout` when flag on and `ShowSnackbar` when
  off; `onRefresh` toggles `isRefreshing`. Use a fake `SubscriptionsRepository`
  emitting scripted `Resource` values; assert `StateFlow` emissions with Turbine.

Repository contract (owned by AND-234 but asserted here via a thin integration test):
- DTO->domain->UiModel round trip for the sample JSON in §5 produces expected
  `TierUiModel`s.

UI (Compose, `createComposeRule`):
- `SubscriptionTiersContent` renders N cards with price text; shows Empty node; shows
  Error + Retry and invokes callback on click; current-tier card shows "Current plan"
  and "Manage"; Subscribe click invokes callback. Verify semantics
  `contentDescription`s for TalkBack.

Instrumentation (optional, MockWebServer): full screen against canned
`/api/creators/{creatorId}/plans` + `/api/subscriptions` responses (CORRECTED paths),
including a timeout scenario to assert the stale/error path.

Coverage target: ViewModel and PriceFormatter branch coverage >= 85%.

## 12. Dependencies & Sequencing

- **Hard dependency:** AND-234 (Subscriptions API + DTOs) must merge first — this ticket
  imports `SubscriptionsApi`, `SubscriptionTier`/`Subscription` domain models,
  `SubscriptionsRepository`, and the Room cache. AND-234 in turn depends on AND-027
  (core-network/cookie jar/ApiResult).
- **Soft / downstream:** the checkout/purchase ticket (later in E32) owns the
  `NavigateToCheckout` destination and the `subscriptionCheckoutEnabled` flag flip; until
  then the CTA is stubbed (FR-7). Tier management (creator side) is a separate E32
  ticket and not coupled here.
- **Sequencing within this ticket:** (1) `PriceFormatter` + tests, (2) `UiState`/events
  + `ViewModel` + tests, (3) Compose UI + nav wiring, (4) UI tests, (5) telemetry +
  strings/a11y pass.

## 13. Risks & Open Questions

- **R1 (API shape drift):** RESOLVED for the read paths — §5 field names are now verified
  against the web reference and `/openapi.json` (see §16): the path is
  `GET /api/creators/{creatorId}/plans` (not `subscription-tiers`), the price field is
  `price_cents`, the interval field is `interval`, activeness is `status`, and both
  responses are bare arrays. Residual risk: the OpenAPI response schema for `/plans` and
  `/api/subscriptions` is untyped (`{}`) server-side, so the field set is taken from the
  web `types.ts`; mappers and tests centralize the contract in AND-234 and this screen
  only touches domain models.
- **R2 (current-sub join):** if the backend has no single endpoint returning both tiers
  and the viewer's sub, two GETs are combined in the repository; partial failure (tiers
  succeed, subs fail) should still render tiers without a current-tier badge. Decision:
  treat subs failure as non-fatal — render tiers, omit badge, log `w`.
- **R3 (multiple active subs / proration):** assume at most one active sub per creator;
  if multiple are returned, pick the most recent by `current_period_end`. Confirm
  backend invariant. Open question for product.
- **R4 (currency mismatch):** tiers from one creator are assumed single-currency; mixed
  currencies render per-tier correctly but no aggregate. No action needed.
- **Open question:** should free tiers show a Subscribe CTA or auto-join? Assumed
  Subscribe (stub) for now.

## 14. Acceptance Criteria

AC-1. Navigating to `subscriptions/tiers/{creatorId}` loads and renders the creator's
active tiers; each tier card displays name, formatted price with correct currency,
billing interval, and perks. (Maps to backlog "Tiers render with pricing.")
AC-2. Tiers are sorted ascending by price; inactive tiers are not shown.
AC-3. A `priceCents == 0` tier renders "Free" with no interval suffix.
AC-4. When the viewer has an active subscription to a listed tier, that card shows a
"Current plan" badge and a "Manage" (disabled) CTA; all other cards show "Subscribe".
AC-5. With the checkout flag off, tapping Subscribe shows a "Coming soon" snackbar and
emits no navigation; with the flag on it emits `NavigateToCheckout(tierId)`.
AC-6. Empty state shows when the creator has zero active tiers; Error state with Retry
shows on load failure with no cache; Retry re-fetches.
AC-7. With cached tiers present and the network failing/slow, cached tiers render
immediately with a non-blocking stale banner.
AC-8. Pull-to-refresh re-fetches; a failed refresh keeps existing content and surfaces a
snackbar.
AC-9. Rotation preserves state without a re-fetch; price/interval formatting respects
device locale while honoring the tier currency code.
AC-10. ViewModel and PriceFormatter unit tests and the Compose UI tests in §11 pass in
CI; branch coverage >= 85% for those classes.

## 15. Definition of Done

- All AC-1..AC-10 pass; code merged to `android-port` under `android/feature-subscriptions`.
- No hardcoded user-facing strings; all in `strings.xml`; TalkBack reads coherent tier
  labels; touch targets >= 48dp.
- Uses `com.testlogon.android.feature.subscriptions.browse` package; Hilt-injected
  `ViewModel` exposing `StateFlow<SubscriptionTiersUiState>` and a one-shot event
  `Channel`.
- Consumes AND-234's `SubscriptionsRepository`/DTOs only — no new endpoint definitions,
  no direct DAO/HTTP calls from the feature module.
- Unit + Compose tests added and green in CI; lint/detekt/ktlint clean; no new cleartext
  permitted outside the dev flavor.
- Telemetry events from §10 emitted and verified in a debug build; no secrets logged.
- Screen verified manually against the dev backend for content, empty, error, and
  offline/stale paths.
- Spec reviewers (Android lead + product owner for E32) sign off; open questions R3 and
  the free-tier CTA question recorded as follow-ups if unresolved.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. OpenAPI references
are to `reference/openapi.index.txt` / `reference/openapi.pretty.json`; frontend
references are paths under `reference/src/`.

1. **Claim:** Tiers are listed at `GET /ui/creators/{creator_id}/subscription-tiers`.
   **VERDICT: Corrected.** No such path exists. The web client lists a creator's
   subscription plans (the "tiers") at `GET /api/creators/{creatorId}/plans`.
   **Source:** OpenAPI `GET /api/creators/{creator_id}/plans` (op
   `list_plans_api_creators__creator_id__plans_get`, params `creator_id,include_profile`);
   `src/api/endpoints/subscriptions.ts: listPlans`.

2. **Claim:** The plans-list response is an object `{"tiers": [...]}`.
   **VERDICT: Corrected.** It is a bare JSON array `SubscriptionPlan[]`.
   **Source:** `src/api/endpoints/subscriptions.ts: listPlans` (`api.get<SubscriptionPlan[]>`);
   `src/pages/subscriptions/PlanBrowser.tsx` (`(plans ?? []).filter(...)`).

3. **Claim:** Price field is `price_minor` (minor units).
   **VERDICT: Corrected.** Field is `price_cents` (integer cents).
   **Source:** `src/api/types.ts: SubscriptionPlan.price_cents`; `PlanBrowser.tsx`
   `formatPrice(plan.price_cents, plan.currency)` with `cents / 100`.

4. **Claim:** Interval field is `billing_interval`.
   **VERDICT: Corrected.** Field is `interval` (string, e.g. `"month"`/`"year"`).
   **Source:** `src/api/types.ts: SubscriptionPlan.interval`; `PlanCreateReq.interval:
   "month" | "year"`.

5. **Claim:** Active filter uses an `is_active` boolean.
   **VERDICT: Corrected.** Active is `status == "active"` (string field).
   **Source:** `src/api/types.ts: SubscriptionPlan.status`; `PlanBrowser.tsx`
   `(plans ?? []).filter((p) => p.status === "active")`.

6. **Claim:** Each tier has a `perks: string[]` array (and a `sort_order` field).
   **VERDICT: Corrected.** `SubscriptionPlan` has neither. The web client renders the
   feature list from `assets[].name`; there is no `sort_order`.
   **Source:** `src/api/types.ts: SubscriptionPlan` (fields: plan_id, creator_id, name,
   description?, price_cents, currency, interval, annual_price_cents?, status, metadata?,
   assets?, created_at, updated_at, creator_profile?); `PlanBrowser.tsx` renders
   `plan.assets.map(... asset.name ...)`.

7. **Claim:** Plan identifier is `id` (e.g. `tier_01H...`).
   **VERDICT: Corrected.** Identifier is `plan_id`.
   **Source:** `src/api/types.ts: SubscriptionPlan.plan_id`; `PlanBrowser.tsx`
   `key={plan.plan_id}`.

8. **Claim:** Viewer subscriptions are at `GET /ui/me/subscriptions?creator_id={id}`
   returning `{"subscriptions": [...]}`.
   **VERDICT: Corrected.** Path is `GET /api/subscriptions` (no `creator_id` query
   param), returning a bare `SubscriptionOut[]`; filter by `creator_id` client-side.
   **Source:** OpenAPI `GET /api/subscriptions` (op
   `list_subscriptions_api_subscriptions_get`, params
   `subscriber_id,include_profile,include_summary,x-user-id`);
   `src/api/endpoints/subscriptions.ts: listSubscriptions` (`subGet<SubscriptionOut[]>("/api/subscriptions", ...)`,
   only `include_summary` query param).

9. **Claim:** Subscription entry uses `id` and `tier_id`; `current_period_end` is an
   ISO-8601 string.
   **VERDICT: Corrected.** Fields are `subscription_id` and `plan_id`;
   `current_period_end` is a Unix epoch number (seconds).
   **Source:** `src/api/types.ts: SubscriptionOut` (`subscription_id`, `plan_id`,
   `creator_id`, `status`, `current_period_end: number`, ...).

10. **Claim:** "Free" (`price == 0`) renders the localized string "Free".
    **VERDICT: Unverified-assumption (Android product choice).** The web client has no
    "Free" branch — it always formats `cents/100` as currency (so $0.00).
    **Source:** `src/pages/subscriptions/PlanBrowser.tsx: formatPrice` (no zero special
    case). Acceptable as an Android UX decision; flagged below.

11. **Claim:** Tiers are sorted ascending by price (ties by name).
    **VERDICT: Unverified-assumption (Android product choice).** The web client does not
    sort; it preserves server order and marks the middle plan "popular". No `sort_order`
    field exists to break ties.
    **Source:** `src/pages/subscriptions/PlanBrowser.tsx` (`activePlans` keeps order;
    `popularIdx = Math.floor(activePlans.length / 2)`). Acceptable as an Android UX
    decision; flagged below.

12. **Claim:** Auth is purely cookie-based session + `X-CSRF-Token`.
    **VERDICT: Corrected (incomplete).** The shared transport sends, on every call:
    `Authorization: Bearer <accessToken>`, `X-CSRF-Token` (from the `ui_csrf` cookie), and
    session cookies (`credentials: "include"`). The authenticated subscription read
    (`GET /api/subscriptions`) additionally sends `X-User-Id`; the public `/plans` list
    does not require it.
    **Source:** `src/api/client.ts` (sets `Authorization` Bearer, `X-CSRF-Token` from
    `getCookie("ui_csrf")`, `credentials: "include"`); `src/api/endpoints/subscriptions.ts:
    userIdHeader` / `subGet` (adds `X-User-Id`); `listPlans` uses plain `api.get` (no
    `X-User-Id`).

13. **Claim:** Single 401 -> `POST /ui/session/refresh` -> retry, handled centrally.
    **VERDICT: Verified.** The web client refreshes once via `POST /ui/session/refresh`
    and retries; on the Android side AND-027 owns the equivalent interceptor.
    **Source:** `src/api/client.ts: refreshSession` (`fetch("/ui/session/refresh", {method:
    "POST", credentials: "include"})`) and the 401 retry block.

14. **Claim:** FastAPI error bodies follow a `detail` mapping (string | array of
    `{msg}` | object `{code,...}`); 422 is `HTTPValidationError`.
    **VERDICT: Verified.** **Source:** `src/api/client.ts: normalizeErrorDetail` (handles
    string, array of `{msg}`, and object `{code,...}` via `mapAuthorizationError`); OpenAPI
    `422:HTTPValidationError` on both endpoints; schema `components.schemas.HTTPValidationError`
    (array of `{loc,msg,type}`).

15. **Claim:** Dev backend is plaintext HTTP at `http://18.222.237.167:8000`, cleartext
    only in dev flavor.
    **VERDICT: Unverified-assumption.** The dev host/URL is project context, not present
    in the OpenAPI or frontend sources reviewed. Cleartext-config policy is an Android
    build concern. **Source:** none in `reference/`; carried from project context (AND-027).

16. **Claim:** Price rendering via `NumberFormat.getCurrencyInstance` with device locale,
    currency forced to the tier's ISO-4217 code.
    **VERDICT: Verified (parity with web).** The web client uses
    `Intl.NumberFormat(undefined, {style:"currency", currency: currency || "USD",
    minimumFractionDigits: 2}).format(cents/100)` — locale-default formatting with the
    tier's currency. The Android `NumberFormat` approach is the JVM equivalent.
    **Source:** `src/pages/subscriptions/PlanBrowser.tsx: formatPrice`. (Framework ref:
    `java.text.NumberFormat.getCurrencyInstance` —
    https://developer.android.com/reference/java/text/NumberFormat#getCurrencyInstance().)

17. **Claim:** Empty state copy "This creator has no subscription tiers yet."
    **VERDICT: Unverified-assumption (Android string choice).** The web client shows title
    "No plans available" / "Check back later for subscription plans." Android wording is a
    local string decision (must live in `strings.xml`, §9).
    **Source:** `src/pages/subscriptions/PlanBrowser.tsx` `EmptyState` props.

18. **Claim (framework choices):** Compose Material 3 `PullToRefreshBox`,
    `collectAsStateWithLifecycle`, Hilt `@HiltViewModel`, `SavedStateHandle` for nav args,
    one-shot events via `Channel`/`receiveAsFlow`.
    **VERDICT: Unverified-assumption (framework refs, not in `reference/`).** These are
    standard Android Jetpack patterns, appropriate for the stack in §2.
    **Source:** framework ref —
    https://developer.android.com/jetpack/compose/components/pull-to-refresh ;
    https://developer.android.com/topic/libraries/architecture/viewmodel/viewmodel-savedstate ;
    https://developer.android.com/training/dependency-injection/hilt-android .

### Corrections made

- Endpoint path for listing tiers: `GET /ui/creators/{creator_id}/subscription-tiers` ->
  `GET /api/creators/{creatorId}/plans` (§2, §5, §11, §13).
- Endpoint for viewer subscriptions: `GET /ui/me/subscriptions?creator_id=` ->
  `GET /api/subscriptions` (filter by `creator_id` client-side) (§2, §5, §8, §11).
- Response shapes: both responses are bare JSON arrays, not `{"tiers": [...]}` /
  `{"subscriptions": [...]}` (§5).
- Field renames: `id` -> `plan_id` / `subscription_id`; `tier_id` -> `plan_id`;
  `price_minor` -> `price_cents`; `billing_interval` -> `interval`; `is_active` (bool) ->
  `status` (string); removed non-existent `perks` and `sort_order` (perks sourced from
  `assets[].name`); `current_period_end` is epoch number, not ISO string (§3, §4, §5).
- `PriceFormatter.format` signature `priceMinor` -> `priceCents` (§4); AC-3 `priceMinor`
  -> `priceCents` (§14).
- Auth description corrected from "purely cookie-based" to Bearer + CSRF + cookies, plus
  `X-User-Id` on the authenticated read (§2, §8).
- Telemetry log note `billing_interval` -> unknown `interval` (§10).

### Open assumptions

- **"Free" rendering for `price_cents == 0`** — not in the web client; Android product
  choice. Why unverifiable: no source shows zero-price handling; needs product sign-off.
- **Ascending-price sort with name tie-break** — web preserves server order and has no
  `sort_order` field. Why unverifiable: no ordering contract in the sources; Android UX
  decision (R3/ordering is an open product question).
- **Perks source** — assumed `assets[].name`; if AND-234 exposes a dedicated benefits
  field, the mapper changes. Why unverifiable: the `/plans` OpenAPI response schema is
  untyped (`{}`); only the web `types.ts` shape is authoritative, and it has no `perks`.
- **Empty/error/"Coming soon"/"Current plan"/"Manage" copy** — Android-local strings; web
  equivalents differ ("No plans available"). Why unverifiable: copy is a UX decision.
- **Dev host / cleartext policy** — from project context (AND-027), not in `reference/`.
- **Current-plan badge + "Manage"/"Subscribe" CTA logic and checkout flag gating** — no
  web equivalent (web's `PlanBrowser` always shows "Subscribe" and performs the subscribe
  inline). The current-plan distinction and the stubbed checkout flag are Android-only
  product behavior. Why unverifiable: no web reference for this affordance.
- **OpenAPI response schemas for `/plans` and `/api/subscriptions` are untyped (`{}`)** —
  field set is taken from the web `types.ts`; server may carry additional/renamed fields
  not visible here. Mitigation: AND-234 mappers + contract tests are the single source of
  truth.

## 17. Test Plan

Test targets per case: **JVM** = local JVM unit/Robolectric (no device); **emulator** =
headless AVD `test35` (x86_64, API 35) on the CI build server; **device** = physical
Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, API 34, arm64-v8a) on the build
host. This ticket is a read-only Compose screen with no camera/biometrics/WebRTC/push, so
most cases run on JVM or the emulator; the few that touch real rendering/a11y/locale or
ABI/API-level differences are noted. Hardware-specific targets are called out where they
genuinely matter.

- **TC-AND-235-01 — Happy path: plans render with pricing.**
  Type: unit (ViewModel, Turbine). Target: JVM.
  Preconditions: fake `SubscriptionsRepository` emits `Resource.Success(CreatorTiers(tiers=[Supporter $4.99/mo USD, Premium $9.99/mo USD], currentSubscription=null))`; checkout flag off.
  Steps: construct VM with `creatorId`; collect `uiState`.
  Expected: terminal state has `isLoading=false`, `error=null`, two `TierUiModel`s with
  `formattedPrice` "$4.99"/"$9.99" (en-US), `intervalLabel` "/month", `isCurrent=false`,
  perks populated from mapped `assets[].name`.
  Traces: AC-1, AC-2.

- **TC-AND-235-02 — Price formatting & "Free".**
  Type: unit (`PriceFormatterTest`). Target: JVM.
  Preconditions: none.
  Steps: format(499,"USD",en-US); format(0,"USD",en-US); format(1000,"EUR",de-DE);
  format(499,"ZZZ" invalid code).
  Expected: "$4.99"; "Free" (Android choice, see §16 #10); "10,00 €" (locale-correct EUR
  position); invalid currency does not throw (falls back gracefully).
  Traces: AC-1, AC-3, AC-9.

- **TC-AND-235-03 — Sorting and inactive filtering.**
  Type: unit (ViewModel). Target: JVM.
  Preconditions: repo emits plans `[B $9.99 status=active, A $4.99 status=active,
  C $4.99 status=archived, D $4.99 status=active]`.
  Steps: collect `uiState.tiers`.
  Expected: order is `A, D` then `B` (ascending `price_cents`, name tie-break A before D);
  archived `C` (`status != "active"`) excluded.
  Traces: AC-2.

- **TC-AND-235-04 — Current-plan derivation & CTA labels.**
  Type: unit (ViewModel). Target: JVM.
  Preconditions: tiers include `plan_id=plan_X`; viewer `SubscriptionOut[status="active",
  plan_id="plan_X", creator_id=this, current_period_end=future]`.
  Steps: collect `uiState`.
  Expected: the `plan_X` `TierUiModel.isCurrent=true` (badge "Current plan", CTA "Manage"
  disabled); all other cards CTA "Subscribe". An expired (`current_period_end` past) or
  non-active sub yields no current plan.
  Traces: AC-4.

- **TC-AND-235-05 — Subscribe CTA flag gating.**
  Type: unit (ViewModel, Turbine on `events`). Target: JVM.
  Preconditions: two scenarios via `FeatureFlags.subscriptionCheckoutEnabled` false/true.
  Steps: call `onSubscribeClick("plan_Y")` in each.
  Expected: flag off -> emits `ShowSnackbar("Coming soon")`, no `NavigateToCheckout`; flag
  on -> emits `NavigateToCheckout("plan_Y")`.
  Traces: AC-5.

- **TC-AND-235-06 — Contract: list plans (MockWebServer, real shapes).**
  Type: contract/MockWebServer. Target: emulator (or JVM via Robolectric+OkHttp).
  Preconditions: MockWebServer returns a **bare array** `SubscriptionPlan[]` for
  `GET /api/creators/{creatorId}/plans` with fields `plan_id, price_cents, currency,
  interval, status, assets`.
  Steps: drive repository/API; assert the dispatched request path and method, and that the
  parsed domain models match.
  Expected: request is `GET /api/creators/{creatorId}/plans` (NOT
  `/ui/.../subscription-tiers`); parser handles the bare array; `price_cents`/`interval`/
  `status`/`assets` map correctly; no crash on the unwrapped array.
  Traces: AC-1, AC-2.

- **TC-AND-235-07 — Contract: viewer subscriptions path & filtering.**
  Type: contract/MockWebServer. Target: emulator.
  Preconditions: MockWebServer returns bare `SubscriptionOut[]` (one matching this
  `creator_id`, one for a different creator) for `GET /api/subscriptions`.
  Steps: invoke the combined load; inspect the recorded request.
  Expected: request is `GET /api/subscriptions` carrying the `X-User-Id` header and no
  `creator_id` query param; only the matching-`creator_id` active sub drives
  `currentTierId`; the other-creator entry is ignored client-side.
  Traces: AC-4.

- **TC-AND-235-08 — Validation/error response (422 / HTTPValidationError).**
  Type: contract/MockWebServer. Target: emulator.
  Preconditions: `/plans` returns 422 with body
  `{"detail":[{"loc":["query","x"],"msg":"bad","type":"value_error"}]}`; no cache present.
  Steps: load; collect `uiState`.
  Expected: maps via the shared `detail` parser to a generic Error state with Retry
  (no crash on the array-shaped `detail`); Retry re-issues the GET.
  Traces: AC-6.

- **TC-AND-235-09 — 404 creator-not-found vs empty.**
  Type: unit/contract. Target: JVM/emulator.
  Preconditions: scenario A `/plans` 200 with `[]`; scenario B `/plans` 404.
  Steps: load each.
  Expected: A -> Empty state ("no tiers" copy); B -> Empty state with the distinct
  not-found message (per §7), not a generic error.
  Traces: AC-6.

- **TC-AND-235-10 — Flaky dev host / offline: stale cache path.**
  Type: integration (MockWebServer + Room). Target: emulator.
  Preconditions: Room has cached plans for `creatorId`; network call times out / returns
  connection reset after the bounded backoff exhausts.
  Steps: cold-start the screen; observe states.
  Expected: cached tiers render immediately with `stale=true` (non-blocking banner); no
  Error state shown; bounded backoff attempted (<=3 tries) then gives up keeping content.
  Traces: AC-7.

- **TC-AND-235-11 — Pull-to-refresh failure keeps content.**
  Type: integration (MockWebServer). Target: emulator.
  Preconditions: content loaded; refresh call fails (5xx/timeout).
  Steps: trigger pull-to-refresh; collect `uiState` + `events`.
  Expected: existing tiers remain; `isRefreshing` toggles true->false; `ShowSnackbar`
  emitted; `stale=true`; list not cleared.
  Traces: AC-8.

- **TC-AND-235-12 — Compose UI states & accessibility semantics.**
  Type: Compose-UI (`createComposeRule`). Target: emulator.
  Preconditions: render `SubscriptionTiersContent` with stateful fixtures (content list,
  current-plan card, empty, error).
  Steps: assert N price texts; click Retry -> callback; click Subscribe -> callback;
  assert current card shows "Current plan"+"Manage"; assert each card's merged
  `contentDescription` reads "<name>, <price> <interval>, current plan"; assert CTA touch
  targets >= 48dp and distinct content descriptions.
  Expected: all assertions pass; no hardcoded strings (resolved from `strings.xml`).
  Traces: AC-1, AC-4, AC-6, AC-10.

- **TC-AND-235-13 — Rotation/config-change preserves state without re-fetch.**
  Type: instrumented/e2e. Target: emulator (also spot-check on device, see note).
  Preconditions: screen loaded with content from a single network call (MockWebServer
  request counter at 1).
  Steps: rotate the device/emulator; recompose.
  Expected: same `UiState` restored from the retained ViewModel; MockWebServer request
  count stays 1 (no re-fetch). Note: rotation behavior is identical on emulator; run once
  on **device** to confirm OEM (Samsung One UI) does not force an extra Activity
  re-creation/fetch.
  Traces: AC-9.

- **TC-AND-235-14 — Locale-aware currency on real device (API 34, arm64).**
  Type: instrumented. Target: **device** (must run on the physical A15).
  Preconditions: app installed on SM-A156U; switch device locale en-US -> de-DE -> ja-JP.
  Steps: open the screen for a creator with USD and EUR plans under each locale.
  Expected: `NumberFormat` renders symbol/grouping/position per device locale while
  honoring each plan's ISO-4217 currency (e.g. "$4.99", "4,99 $" style differences),
  matching JVM expectations from TC-02. **Why device:** validates real on-device ICU/locale
  data and the API-34/arm64-v8a target (vs the emulator's API-35/x86_64), catching
  ABI/API-level locale or rounding differences.
  Traces: AC-9.

- **TC-AND-235-15 — Security: no secrets logged; subscription cache is app-private.**
  Type: instrumented + manual log inspection. Target: device (or emulator).
  Preconditions: debug build with BODY-level OkHttp logging on; sign in; load the screen.
  Steps: capture logcat during load; sign out; inspect Room DB file location/permissions.
  Steps cont.: confirm `subscription_tiers`/`subscriptions` tables are wiped on sign-out.
  Expected: no cookies, `X-CSRF-Token`, Bearer token, or full response bodies leaked at
  non-debug levels; DB resides in the app-private sandbox; sign-out clears cached
  subscription rows (session-clear hook).
  Traces: AC-7 (cache), and Definition-of-Done security items.

### Coverage matrix

| Acceptance criterion (§14) | Covered by |
| --- | --- |
| AC-1 (render name/price/interval/perks) | TC-01, TC-02, TC-06, TC-12 |
| AC-2 (ascending sort; inactive hidden) | TC-01, TC-03, TC-06 |
| AC-3 ("Free" for price 0) | TC-02 |
| AC-4 (current-plan badge + Manage/Subscribe) | TC-04, TC-07, TC-12 |
| AC-5 (checkout flag gating of Subscribe) | TC-05 |
| AC-6 (empty / error+retry; retry re-fetches) | TC-08, TC-09, TC-12 |
| AC-7 (cache + stale banner on slow/failed net) | TC-10, TC-15 |
| AC-8 (pull-to-refresh failure keeps content) | TC-11 |
| AC-9 (rotation no re-fetch; locale + currency) | TC-02, TC-13, TC-14 |
| AC-10 (VM/formatter/UI tests pass; coverage) | TC-01..TC-05, TC-12 |
