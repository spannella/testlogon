---
id: AND-241
title: Subscriptions/fan-club ViewModels
milestone: M5
epic: E32
priority: P1
size: M
status: draft
depends_on: [AND-234]
blocks: [AND-242]
---

# AND-241 — Subscriptions/fan-club ViewModels

## 1. Overview & Goal

This ticket delivers the presentation-layer logic for the Subscriptions and Fan-club
surfaces of the TestLogon Android app: a set of Hilt-injected `ViewModel`s that own the
screen state for viewing available subscription tiers, the current user's active
subscriptions, and a creator's fan-club tiers/membership, plus the **entitlement**
derivation that gates premium content and UI affordances across the feature module.

The scope of AND-241 is explicitly **State + entitlement** — the ViewModels, their
`UiState` models, the reducer logic that maps repository results to state, and an
`EntitlementResolver` that answers "is the current user entitled to X?". It does **not**
own the network DTOs/endpoints (AND-234), the fan-club members listing endpoint
(AND-240), the Compose screens that render this state, or the test suite (AND-242). The
goal is a fully unit-tested, screen-ready state layer that consumes the
`SubscriptionsRepository` produced by AND-234 and exposes `StateFlow<UiState>` per the
project's MVVM contract.

Success means: each ViewModel exposes a single immutable `StateFlow`, loads via the
repository with the project-standard `ApiResult<T>` handling (timeouts, retry-for-GET,
offline/stale states), derives entitlement deterministically, and is covered by unit
tests with a fake repository and `TestDispatcher`.

## 2. Context & References

- **Repo:** `spannella/testlogon`, Android app under `android/`, branch `android-port`.
- **Namespace / applicationId base:** `com.testlogon.android`.
- **Module:** `feature-subscriptions` (depends on `core-network`, `core-model`,
  `core-data`, `core-ui`, `core-testing`). The ViewModels live in
  `com.testlogon.android.feature.subscriptions.viewmodel`; entitlement logic in
  `com.testlogon.android.feature.subscriptions.entitlement`.
- **Dependency AND-234** supplies `core-network`/`core-model` artifacts:
  `SubscriptionsApi` (Retrofit), the DTOs, and a `SubscriptionsRepository` that maps the
  web reference `subscriptions.ts` endpoints and the tiers/subs domain model. This
  ticket consumes those types and must not redefine them.
- **Web reference:** `frontend/src/api/endpoints/subscriptions.ts` and shared types in
  `frontend/src/api/types.ts` are the source of truth for the tier/subscription/
  entitlement shapes; mirror their field names where DTOs from AND-234 expose them.
- **Backend:** FastAPI + DynamoDB; dev host `http://18.222.237.167:8000` (plaintext,
  unreliable). All network is via AND-234's repository; this ticket inherits its
  ~20s timeout, bounded-backoff-for-idempotent-GET, and cookie/CSRF behavior.
- **Auth:** cookie-based session (`/ui/session/start` → MFA → `/ui/session/finalize` →
  `GET /ui/me`); `ui_csrf` echoed as `X-CSRF-Token`; on 401 refresh once then retry. All
  handled inside `core-network`; entitlement here keys off the authenticated `me` state.
- **State contract:** ViewModels expose `StateFlow<UiState>`; typed `ApiResult<T>`;
  FastAPI `detail` mapping (`string | [{msg}] | {code,...}`) is already normalized by
  AND-234's repository into domain errors.

## 3. Functional Requirements

FR-1 **Available tiers.** A ViewModel shall load the catalog of subscription tiers for a
given creator/plan context and expose them as a list with price, period, perks, and a
per-tier `entitled`/`owned` flag derived from the user's active subscriptions.

FR-2 **My subscriptions.** A ViewModel shall load the current user's active and lapsed
subscriptions, exposing renewal date, status (`ACTIVE`, `PAST_DUE`, `CANCELED`,
`EXPIRED`), and the tier each maps to.

FR-3 **Fan-club tiers.** A ViewModel shall load a creator's fan-club tiers (and, when
AND-240 lands, hold the slot for members), exposing the viewer's current membership tier
and whether they can upgrade/downgrade.

FR-4 **Entitlement derivation.** An `EntitlementResolver` shall, given the user's
subscriptions/memberships and a content/feature key, return a deterministic
`Entitlement` verdict (`Granted`, `Denied(reason)`, `RequiresUpgrade(minTier)`,
`Unknown`). Resolution must be pure (no I/O) and unit-testable in isolation.

FR-5 **Reactive refresh.** Each ViewModel shall expose a `refresh()` that re-fetches from
the repository, preserving the last successful data while showing a refreshing indicator
(stale-while-revalidate), and a `retry()` for the error path.

FR-6 **State surfaces.** Each ViewModel shall represent at minimum: `Loading`, `Content`
(with `isStale`/`isRefreshing`), `Empty`, and `Error(message, retryable)`.

FR-7 **No I/O in init beyond a single load.** Construction triggers exactly one initial
load via the repository; subsequent loads are user/refresh driven.

FR-8 **Entitlement consistency.** Tier ownership shown in FR-1 must be computed by the
same `EntitlementResolver` used in FR-4 so the UI cannot disagree with the gate.

## 4. Technical Design

Three ViewModels plus one pure resolver, all in `feature-subscriptions`.

```kotlin
// entitlement/Entitlement.kt
sealed interface Entitlement {
    data object Granted : Entitlement
    data class Denied(val reason: String) : Entitlement
    data class RequiresUpgrade(val minTier: TierId) : Entitlement
    data object Unknown : Entitlement
}

// entitlement/EntitlementResolver.kt
class EntitlementResolver @Inject constructor() {
    fun resolve(
        subscriptions: List<Subscription>,   // from core-model (AND-234)
        memberships: List<FanClubMembership>, // from core-model (AND-234)
        required: EntitlementKey,
    ): Entitlement

    fun ownsTier(subscriptions: List<Subscription>, tierId: TierId): Boolean
}

// EntitlementKey identifies what is being gated.
sealed interface EntitlementKey {
    data class Tier(val tierId: TierId) : EntitlementKey
    data class Content(val contentId: String, val minTier: TierId?) : EntitlementKey
    data class FanClub(val creatorId: String, val minTier: TierId?) : EntitlementKey
}
```

ViewModel skeleton (representative; the three follow the same shape):

```kotlin
// viewmodel/SubscriptionTiersViewModel.kt
@HiltViewModel
class SubscriptionTiersViewModel @Inject constructor(
    private val repository: SubscriptionsRepository,   // from AND-234
    private val entitlements: EntitlementResolver,
    private val savedState: SavedStateHandle,
) : ViewModel() {

    private val creatorId: String = checkNotNull(savedState["creatorId"])

    private val _uiState = MutableStateFlow(SubscriptionTiersUiState.initial())
    val uiState: StateFlow<SubscriptionTiersUiState> = _uiState.asStateFlow()

    init { load(initial = true) }

    fun refresh() = load(initial = false)
    fun retry() = load(initial = false)

    private fun load(initial: Boolean) {
        _uiState.update { it.copy(isLoading = initial, isRefreshing = !initial) }
        viewModelScope.launch {
            val tiers = repository.getTiers(creatorId)        // ApiResult<List<Tier>>
            val subs  = repository.getMySubscriptions()       // ApiResult<List<Subscription>>
            _uiState.update { reduce(it, tiers, subs) }
        }
    }

    private fun reduce(
        prev: SubscriptionTiersUiState,
        tiers: ApiResult<List<Tier>>,
        subs: ApiResult<List<Subscription>>,
    ): SubscriptionTiersUiState { /* see §6 */ }
}
```

`MySubscriptionsViewModel` and `FanClubViewModel` mirror this. `FanClubViewModel` reads
`creatorId` from `SavedStateHandle`, calls `repository.getFanClubTiers(creatorId)`, and
keeps a nullable `members` slot wired to AND-240's endpoint once available
(`/ui/fan-club/tiers/{id}/members`); until then `members` is `null` and the UI hides that
section.

Concurrency: all repository calls run on `viewModelScope` with the injected
`@IoDispatcher` already applied inside the repository (AND-234). The two parallel calls in
`load()` use structured concurrency (`async`/`awaitAll`) so a slow tiers fetch does not
serialize behind subs. Cancellation is automatic on `onCleared`.

DI: `EntitlementResolver` is `@Inject`-constructable (no module needed). ViewModels use
`@HiltViewModel` and are obtained via `hiltViewModel()` in the (out-of-scope) screens.

## 5. API Contract

This ticket performs **no direct network calls**. All HTTP is owned by AND-234's
`SubscriptionsRepository`/`SubscriptionsApi`. The contract below documents the repository
methods consumed and the upstream endpoints they wrap (for reviewer context); the
authoritative DTOs live in `core-model` from AND-234.

Consumed repository surface:

```kotlin
interface SubscriptionsRepository {              // defined in AND-234
    suspend fun getTiers(creatorId: String): ApiResult<List<Tier>>
    suspend fun getMySubscriptions(): ApiResult<List<Subscription>>
    suspend fun getFanClubTiers(creatorId: String): ApiResult<List<FanClubTier>>
    // AND-240: suspend fun getFanClubMembers(tierId: String): ApiResult<List<FanClubMember>>
}
```

Upstream endpoints (wrapped by the repository; cookie session + `X-CSRF-Token`):

- `GET /ui/subscriptions/tiers?creator_id={id}` → `200` list of tiers.
- `GET /ui/subscriptions/me` → `200` list of the caller's subscriptions.
- `GET /ui/fan-club/{creatorId}/tiers` → `200` list of fan-club tiers.
- `GET /ui/fan-club/tiers/{id}/members` → owned by AND-240 (not consumed here yet).

Representative success shape (mirrors `frontend/src/api/types.ts`; final field names per
AND-234 DTOs):

```json
{
  "tiers": [
    { "id": "tier_gold", "name": "Gold", "price_cents": 999,
      "currency": "USD", "period": "MONTH", "perks": ["hd","chat"] }
  ]
}
```

```json
{
  "subscriptions": [
    { "id": "sub_123", "tier_id": "tier_gold", "status": "ACTIVE",
      "renews_at": "2026-07-01T00:00:00Z", "auto_renew": true }
  ]
}
```

Error responses surface to this layer only as the normalized `ApiResult.Failure`
(AND-234 maps FastAPI `detail: string | [{msg}] | {code,...}` to a domain
`AppError`). This ticket maps `AppError` → user-facing `Error` state (see §7). N/A: no
new endpoints are defined by AND-241.

## 6. Data & State Management

UiState models are immutable `data class`es exposed only as `StateFlow`. Example:

```kotlin
data class SubscriptionTiersUiState(
    val isLoading: Boolean = false,
    val isRefreshing: Boolean = false,
    val isStale: Boolean = false,
    val tiers: List<TierRow> = emptyList(),
    val error: ErrorState? = null,
) {
    val isEmpty: Boolean get() = !isLoading && error == null && tiers.isEmpty()
    companion object { fun initial() = SubscriptionTiersUiState(isLoading = true) }
}

data class TierRow(
    val tier: Tier,
    val owned: Boolean,            // EntitlementResolver.ownsTier(...)
    val callToAction: TierCta,     // SUBSCRIBE | UPGRADE | CURRENT | MANAGE
)

data class ErrorState(val message: String, val retryable: Boolean)
```

Reducer rules (`reduce` in §4):

- **Both Success:** compute `TierRow` per tier using `EntitlementResolver.ownsTier` and
  `resolve` to choose the CTA; set `tiers`, clear `error`, `isStale = false`,
  `isLoading/isRefreshing = false`. If list empty → `isEmpty` becomes true.
- **Tiers Success, Subs Failure:** still render tiers but mark `owned = false`/CTA
  `SUBSCRIBE`, set `isStale = true` (entitlement unknown), keep any prior subs-derived
  flags if present; no blocking error.
- **Tiers Failure with cached data present:** keep `prev.tiers`, set `isStale = true` and
  a non-blocking `error` only if no data exists; otherwise surface a transient banner via
  `isStale`.
- **Tiers Failure, no data:** `error = ErrorState(msg, retryable)`, `tiers` empty.

State holding: ViewModels are the single source of truth; no Room/DataStore writes occur
here (caching, if any, is in AND-234's repository). `SavedStateHandle` carries navigation
args (`creatorId`) and survives process death; transient UI state is rebuilt by the
`init` load. No `mutableStateOf` in the ViewModel — Compose reads the `StateFlow` via
`collectAsStateWithLifecycle()` in the (out-of-scope) screens.

Entitlement is **derived, never stored**: every render recomputes from the current
`subscriptions`/`memberships` lists so it cannot drift from the source data.

## 7. Error Handling & Resilience

- Repository returns `ApiResult<T>` = `Success | Failure(AppError)`. This layer never sees
  raw exceptions, HTTP codes, or `detail` payloads.
- `AppError → ErrorState` mapping: `Network/Timeout` → "Couldn't reach the server.",
  `retryable = true`; `Auth(401 after refresh)` → "Please sign in again.",
  `retryable = false` (signals navigation to auth, handled by host); `Server(5xx)` →
  "Something went wrong.", `retryable = true`; `NotFound` → empty/`isEmpty`; `Unknown` →
  generic retryable message.
- **Stale-while-revalidate:** a failed `refresh()` keeps last-good `tiers` and sets
  `isStale = true` rather than discarding content — matches the unreliable dev host.
- **Timeouts/retry:** the ~20s timeout and bounded-backoff retry for idempotent GETs are
  enforced by `core-network`/AND-234; this ticket only reflects the final result. No
  retry loop is implemented in the ViewModel beyond the explicit user `retry()`.
- **Partial failure:** independent `async` legs mean one failed call degrades gracefully
  (FR/§6) instead of failing the whole screen.
- **Entitlement under uncertainty:** when subscription data is unavailable, the resolver
  returns `Unknown`; the UI must treat `Unknown` as "not entitled" for gating (fail
  closed) while clearly showing the stale/error banner.

## 8. Security & Privacy

- No credentials, cookies, or CSRF tokens are handled in this layer; all session
  material stays in `core-network`'s persistent cookie jar.
- **Fail-closed entitlement:** premium gates resolve to denied on `Unknown`/error so a
  network failure never grants access. Client-side entitlement is a UX optimization only;
  the backend remains the authoritative gate on premium content fetches.
- No PII is logged. Subscription IDs/tier IDs are non-sensitive identifiers; user
  identity is never written to logs (see §10).
- ViewModels hold only in-memory state; nothing is persisted to disk by this ticket,
  avoiding at-rest exposure of entitlement data.
- `SavedStateHandle` stores only navigation args (`creatorId`), not user subscription
  data.

## 9. Accessibility & i18n

- This ticket produces no Composables, so contrast/touch-target/focus concerns belong to
  the screens (downstream of AND-242's UI tests / the screen ticket). N/A here for
  rendering.
- **i18n obligation that IS in scope:** all user-facing strings produced by the ViewModel
  (the `ErrorState.message` values and any CTA labels resolved to text) must be `R.string`
  resource IDs resolved via an injected string provider, **not** hardcoded literals, so
  they are translatable. Provide a `StringProvider` (from `core-ui`) abstraction so
  ViewModels remain unit-testable without an Android `Context`:

```kotlin
fun interface StringProvider { fun get(@StringRes id: Int, vararg args: Any): String }
```

- Currency/price formatting is deferred to the screen using `NumberFormat`/locale; the
  ViewModel exposes raw `price_cents` + `currency` so formatting respects device locale.
- Dates (`renews_at`) are exposed as `Instant`; locale-aware formatting happens at render.

## 10. Telemetry & Logging

- Emit structured analytics via the `core-ui`/`core-data` `Analytics` interface (injected;
  no-op in tests): `subscriptions_tiers_viewed { creatorId, tierCount }`,
  `subscription_cta_clicked { tierId, cta }` (event raised from screen, but the CTA enum
  is defined here), `entitlement_resolved { key, verdict }` (sampled, no user id),
  `subscriptions_load_failed { errorType, retryable }`.
- Logging via `core-ui` `Logger` (Timber-backed) at `DEBUG` for state transitions and
  `WARN` for `Failure`/stale fallbacks. Never log subscription contents or identity.
- All telemetry is fire-and-forget and must not affect state or block `viewModelScope`.
- Analytics/Logger are injected interfaces so unit tests assert calls against fakes from
  `core-testing`.

## 11. Testing Strategy

Per the acceptance ("Unit-tested"), AND-241 ships its own unit tests; broader repo/UI
tests are AND-242.

- **Harness:** JUnit4 + `kotlinx-coroutines-test` (`StandardTestDispatcher`,
  `runTest`), Turbine for `StateFlow` assertions, MockK or hand-written fakes from
  `core-testing`. A `MainDispatcherRule` swaps `Dispatchers.Main`.
- **FakeSubscriptionsRepository** (in `core-testing`) returns scripted
  `ApiResult` sequences (success, timeout, 401, 5xx, empty, slow).
- **EntitlementResolver tests (pure):** matrix over {no subs, active sub at tier,
  higher tier owned, lower tier owned, lapsed sub, multiple subs} × {Tier, Content,
  FanClub keys} asserting exact `Entitlement` verdicts, including `RequiresUpgrade(minTier)`
  and fail-closed `Unknown`/Denied.
- **ViewModel tests:** assert the emitted `UiState` sequence for: initial `Loading` →
  `Content`; empty list → `isEmpty`; tiers-ok/subs-fail → `isStale` + CTAs `SUBSCRIBE`;
  full failure → `Error(retryable)`; `refresh()` keeps prior data + `isRefreshing`;
  `retry()` recovers; partial-failure degradation; cancellation on `onCleared`.
- **CTA correctness:** for an owned tier CTA is `CURRENT`/`MANAGE`; for a lower-priced
  tier than owned, `MANAGE`; for higher, `UPGRADE`; otherwise `SUBSCRIBE`.
- **Coverage target:** 100% of `EntitlementResolver` branches; ≥85% line coverage of the
  three ViewModels. Tests run under `./gradlew :feature-subscriptions:testDebugUnitTest`.

## 12. Dependencies & Sequencing

- **Depends on AND-234** (Subscriptions API + DTOs): provides `SubscriptionsRepository`,
  `SubscriptionsApi`, and the `Tier`/`Subscription`/`FanClubTier` models. Must merge
  first; this ticket fails to compile without those types.
- **Soft-coupled to AND-240** (Fan-club tiers/members): `FanClubViewModel` reserves a
  nullable `members` slot but does not require AND-240 to ship; the members section stays
  hidden until the `getFanClubMembers` method exists.
- **Blocks AND-242** (Subscriptions/fan-club tests): AND-242's repo+UI tests build on the
  ViewModels and `EntitlementResolver` defined here.
- Transitively relies on `core-network` (AND-027 lineage) for the `ApiResult` type,
  cookie jar, and CSRF handling; consumed via AND-234.
- Sequencing: AND-234 → **AND-241** → AND-242, with AND-240 landing in parallel.

## 13. Risks & Open Questions

- **R1 — DTO field names:** exact field names (`price_cents` vs `priceCents`,
  `renews_at`) depend on AND-234's Moshi mapping. Mitigation: depend only on the
  `core-model` domain types AND-234 exposes, not raw DTOs.
- **R2 — Entitlement source of truth:** does the backend expose a dedicated entitlement
  endpoint, or must the client derive it from subscriptions? Current assumption: derive
  client-side, fail closed. **Open question for AND-234/backend owner.**
- **R3 — Tier ordering for upgrade/downgrade:** comparing tiers requires a total order
  (by `price_cents`? by an explicit `rank`?). Assumption: `price_cents` ascending. Confirm
  whether tiers can be incomparable (e.g., add-ons).
- **R4 — Unreliable dev host** makes manual verification flaky; mitigated by the fake
  repository for all unit tests.
- **R5 — Fan-club vs subscription overlap:** whether a fan-club membership counts as a
  subscription for `EntitlementKey.Content`. Assumption: both lists feed `resolve`.

## 14. Acceptance Criteria

- AC-1: `SubscriptionTiersViewModel`, `MySubscriptionsViewModel`, and `FanClubViewModel`
  exist in `com.testlogon.android.feature.subscriptions.viewmodel`, are `@HiltViewModel`,
  and each expose a single `StateFlow<…UiState>`.
- AC-2: Each ViewModel loads via `SubscriptionsRepository` on construction and exposes
  working `refresh()` and `retry()`.
- AC-3: `EntitlementResolver` resolves `Granted`/`Denied`/`RequiresUpgrade`/`Unknown`
  deterministically and fails closed on missing data; `ownsTier` drives `TierRow.owned`.
- AC-4: UiState surfaces `Loading`, `Content` (with `isStale`/`isRefreshing`), `Empty`,
  and `Error(message, retryable)`; partial failures degrade per §6.
- AC-5: All user-facing strings come from `R.string` via `StringProvider`; no hardcoded
  literals in ViewModels.
- AC-6: Unit tests cover the EntitlementResolver matrix (100% branches) and the three
  ViewModels' state sequences; `:feature-subscriptions:testDebugUnitTest` passes green.
- AC-7: No network/cookie/CSRF code or persistence is introduced in this layer; entitlement
  is derived, never stored.

## 15. Definition of Done

- Code merged to `android-port` under `feature-subscriptions`, building with Kotlin
  2.0.21 / AGP 8.7.3 / JDK 17 and passing `./gradlew :feature-subscriptions:lint
  detekt testDebugUnitTest`.
- The three ViewModels and `EntitlementResolver` implemented with the signatures in §4,
  using `ApiResult` from AND-234 and Hilt (KSP) DI.
- `FakeSubscriptionsRepository` and the `Analytics`/`Logger`/`StringProvider` fakes are
  available in `core-testing` for downstream AND-242.
- Unit tests meet the coverage targets in §11; CI green.
- KDoc on each public ViewModel/resolver and on the `Entitlement`/`EntitlementKey` types.
- Open questions R2/R3 either resolved with the backend owner or recorded as TODOs with
  the chosen default (derive client-side, order by `price_cents`).
- PR description links AND-234 (dependency) and AND-242 (blocked) and notes the AND-240
  soft coupling.
