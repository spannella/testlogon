---
id: AND-235
title: Subscription tiers browse
milestone: M5
epic: E32
priority: P0
size: M
status: draft
depends_on: [AND-234]
blocks: []
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
  JSON shapes; AND-234's DTOs mirror them.
- **Auth:** cookie-based session (see project context). All subscription reads require
  an authenticated session; the cookie jar + `X-CSRF-Token` echo + single 401
  `POST /ui/session/refresh` retry are handled in the shared OkHttp interceptor from
  AND-027 and are transparent to this screen.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Navigation-Compose, Hilt (KSP),
  Coroutines/Flow, Retrofit 2.11/OkHttp 4.12/Moshi 1.15, Room 2.6, Coil. minSdk 24,
  compileSdk/targetSdk 35, JDK 17.

## 3. Functional Requirements

FR-1. The screen accepts a required `creatorId: String` nav argument and an optional
`creatorDisplayName: String?` for the header before data loads.

FR-2. On entry the screen requests the creator's tiers and the viewer's current
subscription state for that creator in a single combined load.

FR-3. Each tier renders as a card showing: tier name, formatted price + currency,
billing interval (e.g. "/month"), an optional short description, and a list of perks
(benefits). Tiers are ordered by ascending price (ties broken by `sortOrder`, then
name).

FR-4. Only tiers with `isActive == true` are shown. Inactive/archived tiers are
filtered out client-side as a defensive measure even if the backend already filters.

FR-5. Price formatting: prices arrive as integer minor units (cents) plus an ISO-4217
`currency` code. They MUST be rendered using `java.text.NumberFormat.getCurrencyInstance`
with the device locale, with the currency forced to the tier's `currency` code (do not
trust the locale's default currency). Free tiers (`priceMinor == 0`) render the
localized string "Free".

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
    fun format(priceMinor: Long, currency: String, locale: Locale = Locale.getDefault()): String
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
**AND-234**. Paths/shapes mirror `frontend/src/api/endpoints/subscriptions.ts` and are
restated here for implementation reference. Confirm exact field names against
`/openapi.json` during AND-234.

`GET /ui/creators/{creator_id}/subscription-tiers` — list a creator's tiers.

```json
{
  "tiers": [
    {
      "id": "tier_01H...",
      "creator_id": "usr_01H...",
      "name": "Supporter",
      "description": "Early access posts",
      "price_minor": 499,
      "currency": "USD",
      "billing_interval": "month",
      "perks": ["Early access", "Supporter badge"],
      "is_active": true,
      "sort_order": 0
    }
  ]
}
```

`GET /ui/me/subscriptions?creator_id={creator_id}` — viewer's subscription(s) for this
creator (used to derive `currentTierId`). Returns an array; the active, non-expired entry
matching `creator_id` selects the current tier.

```json
{
  "subscriptions": [
    {
      "id": "sub_01H...",
      "tier_id": "tier_01H...",
      "creator_id": "usr_01H...",
      "status": "active",
      "current_period_end": "2026-07-01T00:00:00Z"
    }
  ]
}
```

Mapping notes (owned by AND-234, asserted by this ticket's integration tests): `price_minor`
(int, minor units) -> `priceMinor: Long`; `billing_interval` string -> `BillingInterval`
enum (`MONTH`/`YEAR`/`WEEK`, unknown -> `MONTH` with logged warning); `is_active` ->
`isActive`. Both calls are idempotent GETs and eligible for bounded backoff retry.
FastAPI error bodies follow the shared `detail` mapping (string | `[{msg}]` |
`{code,...}`) handled by AND-027's error mapper into `UiError`.

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
  derivation uses `GET /ui/me/subscriptions`, which is always scoped to the session
  owner server-side.

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
  `billing_interval` enum fallback and parse warnings. Never log cookies, CSRF tokens,
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
`/ui/creators/{id}/subscription-tiers` + `/ui/me/subscriptions` responses, including a
timeout scenario to assert the stale/error path.

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

- **R1 (API shape drift):** §5 field names are inferred from the web reference; exact
  names (`price_minor` vs `amount_cents`, `subscription-tiers` path segment) must be
  verified against `/openapi.json` during AND-234. Mitigation: mappers and tests centralize
  the contract in AND-234; this screen only touches domain models.
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
AC-3. A `priceMinor == 0` tier renders "Free" with no interval suffix.
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
