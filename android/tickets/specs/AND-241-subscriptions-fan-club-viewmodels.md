---
id: AND-241
title: Subscriptions/fan-club ViewModels
milestone: M5
epic: E32
priority: P1
size: M
depends_on: [AND-234]
blocks: [AND-242]
status: reviewed
reviewed_on: 2026-06-06
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
  web reference `subscriptions.ts` + `fan-club.ts` endpoints and the plans/subs/fan-club
  domain model. This ticket consumes those types and must not redefine them.
- **Web reference:** `frontend/src/api/endpoints/subscriptions.ts`,
  `frontend/src/api/endpoints/fan-club.ts`, and shared types in
  `frontend/src/api/types.ts` are the source of truth for the plan/subscription/fan-club-tier/
  entitlement shapes; mirror their field names where DTOs from AND-234 expose them.
  NOTE (review correction): the catalog the user "subscribes to" is a **subscription
  plan** (`SubscriptionPlan`, web `listPlans`), not a "subscription tier". Fan-club
  "tiers" (`TierOut`, web `listTiers`/`getPublicTiers`) are a **separate** concept with a
  `level`/`sort_order` rank and `benefits[]`. The two must not be conflated.
- **Backend:** FastAPI + DynamoDB; dev host `http://18.222.237.167:8000` (plaintext,
  unreliable). All network is via AND-234's repository; this ticket inherits its
  ~20s timeout, bounded-backoff-for-idempotent-GET, and cookie/CSRF behavior.
- **Auth:** cookie-based session (`POST /ui/session/start` → MFA → `POST
  /ui/session/finalize` → `GET /ui/me`); `ui_csrf` cookie echoed as the `X-CSRF-Token`
  header; on 401 the client refreshes once via `POST /ui/session/refresh` then retries.
  All handled inside `core-network`; entitlement here keys off the authenticated `me`
  state. CAVEAT (review correction): only the `/ui/*` endpoints (fan-club tiers) use this
  session-cookie path. The subscription **plan/subscription** endpoints under `/api/*`
  authenticate with an `X-User-Id` header (see `subscriptions.ts`), not the session
  cookie; AND-234's repository is responsible for attaching it. This layer is unaffected
  either way (no transport here).
- **State contract:** ViewModels expose `StateFlow<UiState>`; typed `ApiResult<T>`;
  FastAPI `detail` mapping (`string | [{msg}] | {code,...}`) is already normalized by
  AND-234's repository into domain errors.

## 3. Functional Requirements

FR-1 **Available tiers.** A ViewModel shall load the catalog of subscription tiers for a
given creator/plan context and expose them as a list with price, period, perks, and a
per-tier `entitled`/`owned` flag derived from the user's active subscriptions.

FR-2 **My subscriptions.** A ViewModel shall load the current user's active and lapsed
subscriptions, exposing the end-of-period renewal date (`current_period_end`), status,
and the **plan** each maps to (subscriptions reference `plan_id`/`creator_id`, not a
fan-club `tier_id`). Review correction: the real status values are lowercase strings
observed in the web client — `active`, `trialing`, `canceling`, `canceled`, `past_due`
(no `EXPIRED`). The backend schema types `status` as a free `string`, so the domain layer
should map known values and treat unknown values defensively rather than assume a closed
uppercase enum.

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
(`GET /ui/fan-club/tiers/{tier_id}/members`, paginated by `limit`/`cursor`); until then
`members` is `null` and the UI hides that section.

> Review note (endpoint mapping for AND-234): the public fan-club tier catalog for a given
> creator is `GET /api/creators/{creator_id}/tiers` (web `getPublicTiers`), while the
> caller's own/managed tiers come from `GET /ui/fan-club/tiers` (web `listTiers`, session
> auth, **no** `creator_id` path/query param). `repository.getFanClubTiers(creatorId)`
> should map to the public-by-creator endpoint. The members endpoint path above is correct
> (verified). There is no `/ui/fan-club/{creatorId}/tiers` route (see §5 correction).

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

Upstream endpoints (wrapped by the repository). **Review correction:** the paths/methods
and auth below were verified against the OpenAPI index and the web client; the original
draft's `/ui/subscriptions/tiers`, `/ui/subscriptions/me`, and `/ui/fan-club/{creatorId}/tiers`
paths **do not exist** and have been replaced:

- `GET /api/creators/{creator_id}/plans` → `200` `SubscriptionPlan[]` — the creator's
  subscription **plan** catalog (web `listPlans`; public, no `X-User-Id` required).
- `GET /api/subscriptions?include_summary=true` → `200` `SubscriptionOut[]` — the caller's
  subscriptions (web `listSubscriptions`; `X-User-Id` header auth, **not** cookie session).
- `GET /api/creators/{creator_id}/tiers` → `200` `TierOut[]` — public fan-club tier catalog
  for a creator (web `getPublicTiers`). (Caller-owned tiers: `GET /ui/fan-club/tiers`,
  session auth.)
- `GET /ui/fan-club/tiers/{tier_id}/members?limit=&cursor=` → owned by AND-240 (not
  consumed here yet; session + `X-CSRF-Token`).

Representative success shapes — **bare JSON arrays** (verified; the original `{ "tiers": [] }` /
`{ "subscriptions": [] }` envelopes were wrong), field names per `frontend/src/api/types.ts`:

```json
// SubscriptionPlan[]  (GET /api/creators/{creator_id}/plans)
[
  { "plan_id": "plan_gold", "creator_id": "cr_1", "name": "Gold",
    "price_cents": 999, "currency": "USD", "interval": "month",
    "annual_price_cents": 9999, "status": "active",
    "created_at": 1719792000, "updated_at": 1719792000 }
]
```

```json
// SubscriptionOut[]  (GET /api/subscriptions)
[
  { "subscription_id": "sub_123", "plan_id": "plan_gold", "creator_id": "cr_1",
    "subscriber_id": "u_1", "interval": "month", "provider": "ccbill",
    "status": "active", "start_at": 1717200000, "current_period_end": 1751328000,
    "cancel_at_period_end": false, "price_cents": 999, "currency": "USD",
    "auto_renew": true, "created_at": 1717200000, "updated_at": 1717200000 }
]
```

```json
// TierOut[]  (GET /api/creators/{creator_id}/tiers)
[
  { "tier_id": "tier_gold", "creator_id": "cr_1", "plan_id": "plan_gold",
    "name": "Gold", "level": 2, "color": "#FFD700", "benefits": [{ "type": "early_access" }],
    "member_count": 42, "sort_order": 1, "active": true,
    "created_at": 1719792000, "updated_at": 1719792000 }
]
```

Note: epoch fields (`current_period_end`, `start_at`, `created_at`) are Unix seconds
(numbers), not ISO-8601 strings; AND-234's DTO/domain mapping converts them to `Instant`.

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
- Dates (renewal/period end = `current_period_end`, a Unix-seconds epoch upstream) are
  exposed as `Instant`; locale-aware formatting happens at render. (Corrected: the field is
  `current_period_end`, not `renews_at`.)

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

- **R1 — DTO field names:** exact field names depend on AND-234's Moshi mapping. Verified
  upstream names (§5): plans use `plan_id`/`price_cents`/`interval`; subscriptions use
  `subscription_id`/`plan_id`/`current_period_end`/`auto_renew`; fan-club tiers use
  `tier_id`/`level`/`sort_order`/`benefits`. Mitigation: depend only on the `core-model`
  domain types AND-234 exposes, not raw DTOs.
- **R2 — Entitlement source of truth:** does the backend expose a dedicated entitlement
  endpoint, or must the client derive it from subscriptions? Current assumption: derive
  client-side, fail closed. **Open question for AND-234/backend owner.**
- **R3 — Tier/plan ordering for upgrade/downgrade:** Resolved by the sources. Fan-club
  tiers expose an explicit rank (`level` and `sort_order` on `TierOut`) — use `level` for
  comparison, not price. Subscription **plans** have no rank field, so order plans by
  `price_cents` ascending. The two domains must be compared independently. Remaining open
  point: whether plan add-ons can be incomparable (no signal in the sources).
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer. Sources: the backend
OpenAPI (`reference/openapi.index.txt` / `reference/openapi.pretty.json`,
`components.schemas.<Name>`) and the frontend reference app (`reference/src/...`).

1. **Catalog the user subscribes to is a "subscription tier" fetched at
   `GET /ui/subscriptions/tiers?creator_id={id}`.** VERDICT: Corrected. No such route
   exists. The catalog is a **subscription plan** list: `GET /api/creators/{creator_id}/plans`
   → `SubscriptionPlan[]`. SOURCE: `src/api/endpoints/subscriptions.ts: listPlans`;
   OpenAPI `GET /api/creators/{creator_id}/plans` is the wrapped concept (index also shows
   the public tier route `GET /api/creators/{creator_id}/tiers`).
2. **Caller's subscriptions at `GET /ui/subscriptions/me`.** VERDICT: Corrected. Real
   route is `GET /api/subscriptions` (optional `?include_summary=true`) → `SubscriptionOut[]`.
   SOURCE: `src/api/endpoints/subscriptions.ts: listSubscriptions`; OpenAPI
   `GET /api/subscriptions | op=list_subscriptions_api_subscriptions_get | params=subscriber_id,include_profile,include_summary,x-user-id`.
3. **Fan-club tiers at `GET /ui/fan-club/{creatorId}/tiers`.** VERDICT: Corrected. No such
   route. Public per-creator tiers: `GET /api/creators/{creator_id}/tiers` → `TierOut[]`
   (web `getPublicTiers`). Caller-owned/managed tiers: `GET /ui/fan-club/tiers` (web
   `listTiers`, session auth, no `creator_id`). SOURCE: `src/api/endpoints/fan-club.ts:
   getPublicTiers` and `listTiers`; OpenAPI `GET /api/creators/{creator_id}/tiers` and
   `GET /ui/fan-club/tiers | op=api_list_tiers_ui_fan_club_tiers_get`.
4. **Fan-club members endpoint `/ui/fan-club/tiers/{id}/members` (AND-240).** VERDICT:
   Verified (path correct; paginated by `limit`/`cursor`). SOURCE: OpenAPI
   `GET /ui/fan-club/tiers/{tier_id}/members | op=api_tier_members_... | params=tier_id,limit,cursor,...`.
5. **Response envelopes `{ "tiers": [...] }` and `{ "subscriptions": [...] }`.** VERDICT:
   Corrected. All three list endpoints return **bare JSON arrays** (`SubscriptionPlan[]`,
   `SubscriptionOut[]`, `TierOut[]`), not wrapper objects. SOURCE: `src/api/endpoints/subscriptions.ts`
   (`listPlans` returns `SubscriptionPlan[]`, `listSubscriptions` returns `SubscriptionOut[]`),
   `src/api/endpoints/fan-club.ts: getPublicTiers` returns `TierOut[]`.
6. **Subscription has `id` and `tier_id`, renewal date `renews_at` (ISO string).**
   VERDICT: Corrected. `SubscriptionOut` uses `subscription_id`, references `plan_id` +
   `creator_id` (no `tier_id`), and the period-end date is `current_period_end` as a
   **Unix-seconds number** (not ISO). `auto_renew` is present and correct. SOURCE:
   `src/api/types.ts: SubscriptionOut` (lines ~2713-2737).
7. **Tier/plan fields `id`, `price_cents`, `currency`, `period: "MONTH"`, `perks[]`.**
   VERDICT: Corrected. `SubscriptionPlan` uses `plan_id`, `price_cents`, `currency`, and
   `interval` (lowercase string e.g. `"month"`) — there is no `period`/`perks`. Fan-club
   `TierOut` uses `tier_id`, `level`, `color`, `sort_order`, `benefits: TierBenefit[]`,
   `member_count`, `active` — no `price_cents`/`perks`. SOURCE: `src/api/types.ts:
   SubscriptionPlan` (~2696), `TierOut` (~4658), `TierBenefit` (~4635).
8. **Subscription `status` is the enum `ACTIVE | PAST_DUE | CANCELED | EXPIRED`.** VERDICT:
   Corrected. Backend types `status` as a free `string`; the web client branches on
   lowercase values `active | trialing | canceling | canceled | past_due` (no `EXPIRED`).
   SOURCE: `src/api/types.ts: SubscriptionOut.status: string`; `src/pages/subscriptions/MySubscriptions.tsx`
   (status switch cases `active`/`trialing`/`canceled`/`past_due`; `canCancel`/`canResume`).
9. **Auth flow: `POST /ui/session/start` → MFA → `POST /ui/session/finalize` →
   `GET /ui/me`.** VERDICT: Verified. SOURCE: OpenAPI `POST /ui/session/start`
   (`req=UiSessionStartReq resp=200:UiSessionStartResp`), `POST /ui/session/finalize`
   (`req=UiSessionFinalizeReq`), `GET /ui/me | op=ui_me_ui_me_get`.
10. **`ui_csrf` cookie echoed as `X-CSRF-Token`; on 401 refresh once then retry.** VERDICT:
    Verified. SOURCE: `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`;
    `refreshSession()` posts `/ui/session/refresh`, single-flight `refreshPromise`, retries once).
11. **All subscription network uses the cookie session + CSRF.** VERDICT: Corrected
    (partial). The `/ui/*` fan-club endpoints use the session cookie + CSRF, but the
    `/api/*` subscription plan/subscription endpoints authenticate via an `X-User-Id`
    header. SOURCE: `src/api/endpoints/subscriptions.ts` (`userIdHeader()` → `X-User-Id`;
    explicit comment "authenticates via X-User-Id header (not Bearer token)"); OpenAPI
    `/api/subscriptions` lists `x-user-id` param.
12. **FastAPI `detail` normalized as `string | [{msg}] | {code,...}`.** VERDICT: Verified.
    SOURCE: `src/api/client.ts: normalizeErrorDetail` (string passthrough; array of `{msg}`
    joined; object with `code` mapped via `mapAuthorizationError`; OpenAPI error responses
    are `422:HTTPValidationError`).
13. **Tier ordering by `price_cents` ascending (R3).** VERDICT: Corrected. Fan-club tiers
    carry an explicit `level`/`sort_order` rank; order by `level`. Plans have no rank, so
    order plans by `price_cents`. SOURCE: `src/api/types.ts: TierOut.level`/`sort_order`,
    `SubscriptionPlan.price_cents`.
14. **Network error / offline surfaces as a retryable failure (the flaky dev host path).**
    VERDICT: Verified at the web layer. SOURCE: `src/api/client.ts` catch block → throws
    `ApiError(0, "Network error", err)` ("offline, DNS failure, etc."); AND-234 maps this
    to `ApiResult.Failure(Network)`.
15. **Framework choices: Hilt `@HiltViewModel`, `StateFlow`, `SavedStateHandle`,
    `viewModelScope`, `collectAsStateWithLifecycle`, `StandardTestDispatcher`/`runTest`,
    Turbine.** VERDICT: Unverified-assumption (project convention; not derivable from the
    backend/frontend sources). These are standard AndroidX/Compose/coroutines-test
    primitives (framework ref: developer.android.com guides for ViewModel, Kotlin flows in
    UI, and `kotlinx-coroutines-test`). Accepted as the established Android-port MVVM
    contract inherited from AND-234/AND-027.

### Corrections made

- §2 (References): clarified plan-vs-fan-club-tier distinction; corrected the auth note to
  reflect `/ui/*` session-cookie auth vs `/api/*` `X-User-Id` header auth; named the
  `/ui/session/refresh` single-flight refresh.
- §2 (FR-2): replaced the invented uppercase status enum with the real lowercase values and
  noted `status` is a free string; corrected the subscription→plan mapping (no `tier_id`).
- §4: corrected the fan-club members endpoint to `GET /ui/fan-club/tiers/{tier_id}/members`
  with `limit`/`cursor`, and added the public-vs-owned tier endpoint mapping for AND-234.
- §5: replaced the three non-existent `/ui/...` paths with the verified
  `/api/creators/{creator_id}/plans`, `/api/subscriptions`, `/api/creators/{creator_id}/tiers`
  (and `/ui/fan-club/tiers` for owned); replaced the wrapper-object JSON with bare-array
  examples carrying the real field names; noted epoch-seconds date fields.
- §9: corrected `renews_at` → `current_period_end` (epoch seconds).
- §13: R1 updated with verified field names; R3 resolved (fan-club by `level`, plans by
  `price_cents`).

### Open assumptions

- **A1 — Dedicated entitlement endpoint (R2).** No client-facing entitlement endpoint
  appears in the sources for this surface; the web client derives access from
  subscriptions/memberships. Deriving client-side and failing closed remains an assumption
  pending the backend owner. (Why unverifiable: absence of a route is not proof one will
  not be added in AND-234.)
- **A2 — Repository method names/shapes** (`getTiers`, `getMySubscriptions`,
  `getFanClubTiers`, `ApiResult<T>`, domain `Tier`/`Subscription`/`FanClubTier`/
  `FanClubMembership` types). Owned by AND-234; not present in the reference sources. The
  upstream endpoints they wrap are verified (citations 1-4), but the Kotlin signatures are
  an inter-ticket contract assumption.
- **A3 — Fan-club membership counts as a subscription for `EntitlementKey.Content` (R5).**
  No source signal on cross-domain entitlement. Assumption: both lists feed `resolve`.
- **A4 — `level` semantics (higher number = higher tier).** `TierOut.level` exists and is
  numeric, but the sources do not state the ordering direction; assumed ascending (higher
  `level` is the more-privileged tier). Confirm with backend/AND-234.
- **A5 — Android MVVM/test framework stack** (citation 15) is a project convention, not
  verifiable from backend/frontend sources.

## 17. Test Plan

Test targets: **JVM** = JVM/Robolectric unit (local, no device); **emu35** = headless AVD
`test35` (x86_64, API 35) for instrumented/Compose suites in CI; **deviceA15** = physical
Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, Android 14 / API 34, arm64-v8a). This
ticket is a pure state/entitlement layer (no Composables, no I/O, no hardware), so the bulk
runs on **JVM**. A few cases exercise process-death restore and ABI parity; those that
genuinely need on-device behavior are flagged, with the rest noted as emulator-sufficient.

- **TC-AND-241-01 — Initial load happy path.** Type: unit (JVM). Target:
  `SubscriptionTiersViewModel`. Preconditions: `FakeSubscriptionsRepository` scripted so
  `getTiers`/`listPlans` and `getMySubscriptions` both return `Success` (3 plans; user owns
  one). Steps: construct VM with `SavedStateHandle{creatorId}` under `StandardTestDispatcher`;
  collect `uiState` via Turbine; advance dispatcher. Expected: first emission `isLoading=true`
  (Content empty), then a Content emission with 3 `TierRow`s, `error=null`,
  `isLoading=isRefreshing=isStale=false`, and the owned plan's CTA = `CURRENT`. Traces: AC-1,
  AC-2, AC-4.
- **TC-AND-241-02 — Empty catalog.** Type: unit (JVM). Target: `SubscriptionTiersViewModel`.
  Preconditions: repo returns `Success(emptyList())` for plans, `Success` for subs. Steps:
  construct; advance. Expected: terminal state has `isEmpty=true`, `tiers` empty, `error=null`,
  `isLoading=false`. Traces: AC-4.
- **TC-AND-241-03 — EntitlementResolver verdict matrix.** Type: unit (JVM), pure. Target:
  `EntitlementResolver`. Preconditions: none (no I/O). Steps: table-driven over {no subs;
  active sub at required tier; higher tier owned; lower tier owned; lapsed/`canceled` sub;
  multiple subs} × {`Tier`, `Content(minTier)`, `FanClub(minTier)`}. Expected: exact verdicts
  — `Granted` when owned/at-or-above required `level`; `RequiresUpgrade(minTier)` when below;
  `Denied(reason)` for lapsed-only; and `ownsTier` true only for an active sub at the tier.
  100% branch coverage. Traces: AC-3.
- **TC-AND-241-04 — Fail-closed on Unknown.** Type: unit (JVM), pure. Target:
  `EntitlementResolver`. Preconditions: subscriptions list is null/absent (data unavailable).
  Steps: call `resolve(...)` for a premium `Content` key with empty/absent data. Expected:
  returns `Unknown`, and the gate treats `Unknown` as not-entitled (no `Granted`). Traces:
  AC-3, AC-7.
- **TC-AND-241-05 — Status-value mapping (contract).** Type: unit (JVM). Target:
  `MySubscriptionsViewModel` + domain status mapping. Preconditions: repo returns subs with
  the real lowercase statuses `active`, `trialing`, `canceling`, `canceled`, `past_due`, plus
  one unknown value `"foo"`. Steps: load; inspect mapped state. Expected: each known value
  maps to its domain status; unknown is handled defensively (treated as inactive/unknown, not
  a crash). Confirms §5/FR-2 correction. Traces: AC-3, AC-4.
- **TC-AND-241-06 — Partial failure degradation (tiers ok, subs fail).** Type: unit (JVM).
  Target: `SubscriptionTiersViewModel`. Preconditions: `getTiers`=`Success(3)`,
  `getMySubscriptions`=`Failure(Network)`. Steps: load; advance. Expected: tiers render with
  `owned=false`/CTA `SUBSCRIBE`, `isStale=true`, no blocking `error`. Verifies independent
  `async` legs. Traces: AC-4.
- **TC-AND-241-07 — Stale-while-revalidate on refresh failure (flaky dev host path).** Type:
  unit (JVM). Target: `SubscriptionTiersViewModel`. Preconditions: first load `Success`; then
  `refresh()` returns `Failure(Timeout)`. Steps: load → assert Content; call `refresh()` →
  during fetch assert `isRefreshing=true`; on failure assert prior `tiers` retained,
  `isStale=true`, no destructive `error`. Expected: last-good data preserved; matches the
  unreliable dev host. Traces: AC-2, AC-4.
- **TC-AND-241-08 — Full failure then retry() recovers.** Type: unit (JVM). Target:
  `MySubscriptionsViewModel`. Preconditions: first load `Failure(Server 5xx)` with no cached
  data; second call `Success`. Steps: construct → assert `Error(message, retryable=true)`,
  empty tiers; call `retry()` → assert Content. Expected: error→recovery transition; error
  message resolved via `StringProvider` (R.string), not a literal. Traces: AC-2, AC-4, AC-5.
- **TC-AND-241-09 — Auth failure maps to non-retryable sign-in error.** Type: unit (JVM).
  Target: any ViewModel. Preconditions: repo returns `Failure(Auth)` (401 after the single
  refresh-retry already exhausted in `core-network`). Steps: load. Expected: `error` with
  `retryable=false` and the "please sign in again" string id; no credentials/cookies touched
  in this layer. Traces: AC-4, AC-7.
- **TC-AND-241-10 — No hardcoded user-facing strings.** Type: unit (JVM). Target: all three
  ViewModels. Preconditions: fake `StringProvider` records requested `@StringRes` ids. Steps:
  drive each error/CTA path. Expected: every user-facing message/label is produced via
  `StringProvider.get(id, ...)`; assert no raw literals leak into state. Traces: AC-5.
- **TC-AND-241-11 — Single init load; cancellation on onCleared.** Type: unit (JVM). Target:
  `SubscriptionTiersViewModel`. Preconditions: repo counts invocations; one call is slow.
  Steps: construct (assert exactly one initial load); trigger `onCleared()` mid-flight via the
  ViewModel test harness. Expected: construction triggers exactly one repository load (FR-7);
  in-flight coroutine is cancelled, no state emitted post-clear. Traces: AC-2.
- **TC-AND-241-12 — Fan-club tiers load with hidden members slot.** Type: unit (JVM). Target:
  `FanClubViewModel`. Preconditions: `getFanClubTiers(creatorId)` `Success(TierOut list with
  level/sort_order)`; `getFanClubMembers` not wired (AND-240 absent). Steps: load. Expected:
  tiers ordered by `level`; viewer membership/upgrade flags computed via the same
  `EntitlementResolver`; `members=null` and members section hidden. Confirms tiers ordered by
  `level` not price. Traces: AC-1, AC-3, AC-4.
- **TC-AND-241-13 — SavedStateHandle process-death restore (instrumented).** Type:
  instrumented. Target: `FanClubViewModel` with real `SavedStateHandle`. Run on: **emu35**
  (emulator-sufficient; not hardware-dependent). Preconditions: `creatorId` saved in handle.
  Steps: simulate process death by recreating the VM from a restored `SavedStateHandle`;
  observe re-load. Expected: `creatorId` survives; `init` re-runs the single load; only nav
  args (not subscription data) are restored. Traces: AC-2, AC-7.
- **TC-AND-241-14 — ABI/API parity smoke (arm64/API34 vs x86_64/API35).** Type:
  instrumented/e2e. Target: `:feature-subscriptions:testDebugUnitTest` + the resolver matrix.
  Run on: **deviceA15** (physical, arm64-v8a / API 34) AND **emu35** (x86_64 / API 35).
  Preconditions: built feature module. Steps: run the resolver + ViewModel suite on both
  targets. Expected: identical verdicts/state sequences on both — no ABI- or API-level-driven
  divergence in the pure entitlement math. MUST run on the physical device for the arm64/API-34
  half (emulator cannot represent arm64). Traces: AC-3, AC-6.

Coverage matrix (section-14 AC → covering TCs):

| AC   | Covered by |
|------|------------|
| AC-1 | TC-01, TC-12 |
| AC-2 | TC-01, TC-07, TC-08, TC-09(impl.), TC-11, TC-13 |
| AC-3 | TC-03, TC-04, TC-05, TC-12, TC-14 |
| AC-4 | TC-01, TC-02, TC-05, TC-06, TC-07, TC-08, TC-09, TC-12 |
| AC-5 | TC-08, TC-10 |
| AC-6 | TC-03 (100% resolver branches), TC-14 (suite green on both targets) |
| AC-7 | TC-04, TC-09, TC-13 |
