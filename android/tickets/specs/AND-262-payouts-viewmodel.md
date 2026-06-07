---
id: AND-262
title: Payouts ViewModel
milestone: M6
epic: E35
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-258]
blocks: [AND-263]
---

# AND-262 — Payouts ViewModel

> **Reviewer correction banner (2026-06-06):** The original draft was written against
> an assumed `PayoutAccount` model (`payoutsEnabled`, `kycTier`, `defaultMethodId`,
> `methods`) reached via `GET /ui/payouts/account`, plus a `getPayout(id)` detail
> endpoint. **None of these exist** in the authoritative sources. The real contract
> (verified against `openapi.index.txt`, `PayoutBalanceOut`/`PayoutListOut`/`PayoutOut`
> schemas, and `frontend/src/api/endpoints/payouts.ts` + `pages/payouts/PayoutDashboard.tsx`)
> is: `GET /ui/payouts/balance` → `PayoutBalanceOut`, `GET /ui/payouts` → `PayoutListOut`,
> `POST /ui/payouts/request`, `POST /ui/payouts/{payout_id}/cancel`. The web app's
> "gating" is **client-side amount validation** against `minimum_payout_cents` /
> `available_cents` from the balance — there is no `payoutsEnabled`/`kycTier` gate.
> Sections below have been corrected in place; the gate has been re-scoped to a
> balance-derived `PayoutGate`. See §16 for the full audit. Where the old gate
> vocabulary (KYC tiers / restricted accounts) is retained as a *future* design, it is
> flagged as an unverified assumption, not current contract.

## 1. Overview & Goal

This ticket delivers the presentation-layer state holder for the Payouts domain of
the TestLogon native Android app: a Hilt-injected `PayoutsViewModel` that exposes a
single `StateFlow<PayoutsUiState>`, owns the load/refresh/paging orchestration over
`PayoutsRepository` (AND-258), and centralizes the **gating logic** that decides
what the user is allowed to do with payouts. **[Corrected]** Gating is derived from
the user's **payout balance** (`available_cents`, `pending_cents`, `hold_cents`,
`minimum_payout_cents`) returned by `GET /ui/payouts/balance` (`PayoutBalanceOut`),
not from a non-existent `PayoutAccount`/`payoutsEnabled`/`kycTier` model. It is the
Android port of the eligibility logic the web reference app implements inline in
`frontend/src/pages/payouts/PayoutDashboard.tsx` (the `amountError` / `canSubmit`
computation) on top of `frontend/src/api/endpoints/payouts.ts`.

Scope is strictly **state + gating logic**, as the backlog says. This ticket does
**not** render Compose UI (the setup screen is AND-259, history is AND-260, bulk
read views are AND-261), does not implement the KYC tier API (AND-320), and does
not add network code (AND-258). The deliverable is a fully unit-tested ViewModel
whose `PayoutsUiState` and `PayoutGate` outputs can be collected by any of those
screens without re-deriving gating rules.

The single hard acceptance signal from the backlog is **"Unit-tested."**
Concretely: every state transition (loading → loaded → error → refresh →
paginate), every gate outcome, and every error mapping is provable by JVM unit
tests using a fake `PayoutsRepository` and a test coroutine dispatcher, with no
Android instrumentation required.

Goal restated for engineers: when this ticket merges, a screen can write
`val state by viewModel.uiState.collectAsStateWithLifecycle()` and read a complete,
already-gated view of the user's payout situation, plus call `onRefresh()`,
`onLoadMore()`, `onRetry()`, and `onSelectPayout(id)` without knowing anything
about Retrofit, cursors, or gate thresholds.

## 2. Context & References

- **Repo / branch:** `spannella/testlogon`, Android app under `android/`, branch
  `android-port`.
- **Namespace:** all code lands under `com.testlogon.android` — specifically
  `com.testlogon.android.feature.payouts` for the ViewModel, `UiState`, and gate
  types. **[Corrected]** Domain models reused from
  `com.testlogon.android.core.model.payout` (AND-258) are `Payout`, `PayoutPage`
  (cursor-paged list), and `PayoutBalance` — **not** `PayoutAccount` (does not exist).
  Per the verified wire shapes, `Payout.status` and `Payout.method` are plain
  **strings** (`PayoutOut.status`/`method`), not a `PayoutStatus` enum or
  `PayoutMethod` object; if AND-258 introduces a `PayoutStatus` enum it is a
  client-side convenience, not a server type. These are **not** redeclared here.
- **Module placement:** `feature-payouts`. Layering rule
  `feature-payouts -> core-data -> core-model` is respected. The ViewModel injects
  the `PayoutsRepository` interface from `core-data`; it never touches
  `core-network`/Retrofit directly.
- **Web reference:** `frontend/src/api/endpoints/payouts.ts`, the payout shapes in
  `frontend/src/api/types.ts` (`PayoutBalance`, `Payout`, `PayoutListResp`), and the
  page logic in `frontend/src/pages/payouts/PayoutDashboard.tsx`. **[Corrected]** The
  web app does **not** derive a "can configure payouts" / "needs verification" boolean
  from any account state — there is no such state. It computes a per-request
  eligibility (`canSubmit`) from `minimum_payout_cents` ≤ amount ≤ `available_cents`.
  This ViewModel reproduces that as `PayoutGate` (see corrected §3).
- **Dependencies:** AND-258 (`PayoutsApi` + `PayoutsRepository` + domain models +
  `ApiResult`/`apiCall`) is the prerequisite and supplies every type this ticket
  consumes. The shared `ApiResult<T>` envelope and FastAPI `detail` error mapping
  from AND-027 are reused as surfaced by the repository.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext
  HTTP, unreliable). This ticket performs no direct HTTP; it inherits the
  repository's ~20s timeouts, idempotent-GET retry, and error mapping.
- **Blocks:** AND-263 (Payouts tests) extends the unit tests authored here and adds
  UI tests against the screens; AND-259/260/261 consume this ViewModel's state.

## 3. Functional Requirements

FR-1. Expose exactly one observable state: `val uiState: StateFlow<PayoutsUiState>`,
created with `stateIn(viewModelScope, WhileSubscribed(5_000), PayoutsUiState.Loading)`.

FR-2. **[Corrected]** On first active subscription (and on `onRetry()`), load the
payout **balance** (`getPayoutBalance()` → `GET /ui/payouts/balance`) and the first
page of history (`getPayouts(cursor = null)` → `GET /ui/payouts`) concurrently,
combine them into a single `PayoutsUiState.Content`, and surface a single combined
loading state until both complete. (There is no `getPayoutAccount()` endpoint.)

FR-3. **[Corrected]** Derive a **gate decision** (`PayoutGate`) purely from
`PayoutBalance` (fields verified in `PayoutBalanceOut`: `available_cents`,
`pending_cents`, `hold_cents`, `total_earned_cents`, `currency`,
`minimum_payout_cents`). The web app (`PayoutDashboard.tsx`) has only two gate-like
outcomes; we model them plus indeterminate/empty:
- `Ready` — `available_cents >= minimum_payout_cents` (a payout of at least the
  minimum can be requested). Mirrors the web `canSubmit` lower bound.
- `BelowMinimum` — `0 < available_cents < minimum_payout_cents` (funds exist but not
  enough to withdraw yet). Carries `available_cents`/`minimum_payout_cents` for the
  "Minimum payout is $X" message the web shows.
- `NoFunds` — `available_cents == 0` (nothing withdrawable).
- `Unknown` — balance is indeterminate (e.g., balance load failed but history
  loaded); treated as not-`Ready` and surfaced with a retry affordance.
The gate is a **pure function** `gateOf(balance: PayoutBalance?): PayoutGate` so it
is independently unit-testable.
> **Unverified-assumption (future):** a KYC/verification gate
> (`NeedsVerification`/`Disabled` from `payoutsEnabled`+`kycTier`) is **not** part of
> the current `/ui/payouts` contract. KYC tier lives on a separate surface
> (`GET /v1/kyc/tiers/me`, AND-320). If a verification gate is wanted, it must compose
> this balance gate with that endpoint in AND-259/AND-320 — out of scope here.

FR-4. Support cursor pagination via `onLoadMore()`: when `nextCursor != null` and no
load is in flight, fetch the next page, append items, and update `nextCursor`. A
null `nextCursor` means end-of-list and `onLoadMore()` becomes a no-op.

FR-5. Support `onRefresh()`: re-fetch account + first page, preserving the current
selection, and expose `isRefreshing` distinctly from initial `Loading` so the UI
can show a pull-to-refresh spinner over existing content rather than a full-screen
loader.

FR-6. Expose `onSelectPayout(id: String?)` to set/clear the currently selected
payout id in state (detail navigation is the screen's job; the ViewModel only holds
selection). Selecting an id that is already in `items` requires no network call.

FR-7. Map repository errors (`ApiResult.Error`) into a `PayoutsError` UI model
(category + human message from the shared FastAPI `detail` mapper) and represent
two failure shapes: **full-screen error** (initial load failed entirely) vs.
**inline/snackbar error** (refresh or load-more failed while content is shown).

FR-8. Be lifecycle-safe and configuration-change-safe: state survives rotation via
`viewModelScope`; in-flight loads are not duplicated on re-subscription (guard with
an in-progress flag / job de-duplication).

FR-9. Expose only intent functions (`onRefresh`, `onLoadMore`, `onRetry`,
`onSelectPayout`) and the `StateFlow`. No `LiveData`, no exposed `MutableStateFlow`,
no suspend functions in the public API.

## 4. Technical Design

ViewModel and its public surface (`feature-payouts`):

```kotlin
package com.testlogon.android.feature.payouts

@HiltViewModel
class PayoutsViewModel @Inject constructor(
    private val repository: PayoutsRepository,
    @IoDispatcher private val io: CoroutineDispatcher,
) : ViewModel() {

    private val internal = MutableStateFlow(PayoutsState())   // private mutable
    val uiState: StateFlow<PayoutsUiState> =
        internal
            .onStart { loadInitialOnce() }
            .map(::toUiState)
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), PayoutsUiState.Loading)

    fun onRefresh() { ... }
    fun onLoadMore() { ... }
    fun onRetry() { loadInitial(force = true) }
    fun onSelectPayout(id: String?) { internal.update { it.copy(selectedId = id) } }
}
```

Internal working state (never exposed directly):

```kotlin
internal data class PayoutsState(
    val balance: PayoutBalance? = null,   // [Corrected] was PayoutAccount? account
    val items: List<Payout> = emptyList(),
    val nextCursor: String? = null,
    val initialLoaded: Boolean = false,
    val isRefreshing: Boolean = false,
    val isLoadingMore: Boolean = false,
    val selectedId: String? = null,
    val fatalError: PayoutsError? = null,     // initial-load failure
    val transientError: PayoutsError? = null, // refresh / load-more failure
)
```

Public UI state and gate:

```kotlin
sealed interface PayoutsUiState {
    data object Loading : PayoutsUiState
    data class Error(val error: PayoutsError) : PayoutsUiState   // initial load failed
    data class Content(
        val gate: PayoutGate,
        val balance: PayoutBalance?,          // [Corrected] was account: PayoutAccount?
        val payouts: List<Payout>,
        val canLoadMore: Boolean,
        val isRefreshing: Boolean,
        val isLoadingMore: Boolean,
        val selected: Payout?,
        val transientError: PayoutsError?,   // shown as snackbar, then cleared
    ) : PayoutsUiState
}

// [Corrected] Balance-derived gate (was a non-existent account/KYC gate).
sealed interface PayoutGate {
    data object Ready : PayoutGate                                   // available >= minimum
    data class BelowMinimum(                                          // 0 < available < minimum
        val availableCents: Long,
        val minimumCents: Long,
    ) : PayoutGate
    data object NoFunds : PayoutGate                                  // available == 0
    data object Unknown : PayoutGate                                  // balance load failed
}

data class PayoutsError(val category: ErrorCategory, val message: String)
enum class ErrorCategory { NETWORK, AUTH, NOT_FOUND, VALIDATION, SERVER, UNKNOWN }
```

Pure gating selector (the testable heart of "gating logic"):

```kotlin
// [Corrected] Pure balance-derived gate. Mirrors PayoutDashboard.tsx canSubmit/amountError.
internal fun gateOf(balance: PayoutBalance?): PayoutGate = when {
    balance == null -> PayoutGate.Unknown
    balance.availableCents >= balance.minimumPayoutCents -> PayoutGate.Ready
    balance.availableCents > 0 -> PayoutGate.BelowMinimum(
        availableCents = balance.availableCents,
        minimumCents = balance.minimumPayoutCents,
    )
    else -> PayoutGate.NoFunds
}

// Per-request validation helper (mirrors web canSubmit), reused by AND-259's form:
internal fun PayoutBalance.canRequest(amountCents: Long): Boolean =
    amountCents in minimumPayoutCents..availableCents
```
> Field names above use the AND-258 domain model. The wire shape is snake_case
> (`available_cents`, `minimum_payout_cents`) per `PayoutBalanceOut`; AND-258 owns the
> JSON↔Kotlin mapping. `*_cents` are integers (use `Long` to be safe; web treats them
> as `number`).

Initial load (concurrent, de-duplicated):

```kotlin
private var loadJob: Job? = null

private fun loadInitial(force: Boolean = false) {
    if (loadJob?.isActive == true && !force) return
    loadJob = viewModelScope.launch(io) {
        internal.update { it.copy(fatalError = null) }
        // [Corrected] getPayoutBalance() (GET /ui/payouts/balance), not getPayoutAccount()
        val balanceDeferred = async { repository.getPayoutBalance() }
        val pageDeferred = async { repository.getPayouts(cursor = null) }
        val balance = balanceDeferred.await()
        val page = pageDeferred.await()
        reduce(balance, page, isInitial = !internal.value.initialLoaded)
    }
}
```

Reduction rules **[Corrected: "account" → "balance"]**:
- Both succeed → `Content` with combined data, `initialLoaded = true`,
  `gate = gateOf(balance)`.
- History succeeds, balance fails → `Content` with `gate = Unknown` and a
  `transientError` (history is still usable; gate cannot be trusted).
- History fails on **initial** load → `fatalError` → `PayoutsUiState.Error`.
- History fails on **refresh / load-more** (content already present) →
  `transientError`, items unchanged.

`onLoadMore()` reads `internal.value.nextCursor`; if non-null and
`!isLoadingMore`, fetches `repository.getPayouts(cursor = nextCursor)` and appends.
`canLoadMore = nextCursor != null` in `Content`. Errors are mapped from
`ApiResult.Error` to `PayoutsError` via a small `Throwable/ApiError -> ErrorCategory`
helper that consumes the message already produced by AND-027's `detail` mapper.

DI: the ViewModel is constructed by Hilt's `@HiltViewModel`; no module is added in
this ticket (the `PayoutsRepository` binding and `@IoDispatcher` qualifier come from
AND-258 / core). `selected` in `Content` is resolved by `items.find { it.id == selectedId }`.

## 5. API Contract

This ticket defines **no new HTTP endpoints**. It consumes the repository contract
established by AND-258. **[Corrected]** The verified consumed surface is:

```kotlin
// [Corrected] getPayoutBalance() replaces the non-existent getPayoutAccount().
suspend fun getPayoutBalance(): ApiResult<PayoutBalance>
suspend fun getPayouts(cursor: String? = null, limit: Int = 20): ApiResult<PayoutPage>
// NOTE: there is NO GET /ui/payouts/{id} detail endpoint — getPayout(id) removed.
```

The backing endpoints — **verified** against `openapi.index.txt` and the web client
(`frontend/src/api/endpoints/payouts.ts`) — are:
- `GET /ui/payouts/balance` → `200: PayoutBalanceOut` (op `payout_balance_ui_payouts_balance_get`).
- `GET /ui/payouts` with query `limit`, `cursor` → `200: PayoutListOut` (op `list_payouts_ui_payouts_get`).
  `PayoutListOut = { items: PayoutOut[], next_cursor: string|null }`.

**Corrections to the original draft:**
- `GET /ui/payouts/account` **does not exist**. Balance comes from `/ui/payouts/balance`.
- `GET /ui/payouts/{payoutId}` (single-payout detail) **does not exist** in the
  contract. Selection MUST be satisfied from already-loaded `items`; there is no
  fallback `getPayout(id)` fetch. The deep-link-to-uncached-id path (old §5/R5) is
  removed — if a detail id is not in `items`, the screen must re-list or show
  not-found, not call a non-existent endpoint.

Related write endpoints exist but are **out of scope** for this state/gating ticket
(they belong to AND-259's request/cancel actions): `POST /ui/payouts/request`
(`req=PayoutRequestIn`, `201: PayoutCreateOut`) and
`POST /ui/payouts/{payout_id}/cancel` (`200: PayoutActionOut`). All `/ui/payouts/*`
endpoints additionally accept `user_sub`, `X-SESSION-ID`, `X-IMPERSONATION-TOKEN`
params per the index; auth/CSRF transport is owned by AND-027/AND-258 (see §8).

The only contract this ticket adds is the **internal mapping** `PayoutBalance` →
`PayoutGate` and the `canRequest(amountCents)` helper (see §4), pure in-process
functions with no wire representation.

## 6. Data & State Management

- **No persistent state.** This ticket adds no Room table and no DataStore key; all
  state lives in `viewModelScope`-bound flows and dies with the ViewModel. Disk
  caching of payout history is explicitly deferred to AND-260 / a future Paging 3 +
  Room mediator; the `nextCursor` carried here is the integration seam.
- **Single source of truth:** the private `MutableStateFlow<PayoutsState>` is the
  only mutable holder; `uiState` is a derived, read-only projection
  (`map(::toUiState)`), guaranteeing the UI cannot mutate state.
- **Pagination state** (`items`, `nextCursor`, `isLoadingMore`) is accumulated in
  `PayoutsState`; appending is `current.items + page.items`. Duplicate-page guards
  rely on `isLoadingMore` plus the monotonic cursor; defensive de-dup by `id` is
  applied when appending to tolerate overlapping pages from the flaky backend.
- **Selection** is stored as `selectedId: String?` and projected to a `Payout?`,
  so rotation preserves the selected detail without a refetch.
- **Lifecycle:** `WhileSubscribed(5_000)` keeps state warm across short
  configuration changes; `onStart` triggers the one-time initial load via an
  `initialLoaded` guard so re-subscription does not re-fetch.

## 7. Error Handling & Resilience

- The ViewModel never calls the network directly, so it relies on AND-258's
  idempotent-GET bounded backoff retry and ~20s timeouts. It does **not** add its
  own retry loop; `onRetry()` is a user-initiated single re-load.
- **Two-tier error model:** initial-load failure → `PayoutsUiState.Error`
  (full-screen, with `onRetry`); refresh/load-more failure while content exists →
  `Content.transientError` (snackbar) leaving existing items intact. After the
  snackbar is shown, the screen calls a `onTransientErrorShown()` clear hook (or the
  ViewModel clears it on next successful action) so the error is not re-emitted.
- **Partial success:** account fails but history succeeds → content renders with
  `PayoutGate.Unknown` and a transient error rather than blocking the whole screen.
- **Auth failure:** a bare `ApiResult.Error` with `ErrorCategory.AUTH` (refresh
  interceptor exhausted upstream) is surfaced so the host can route to login; the
  ViewModel does not attempt its own refresh.
- **Empty history** (`items == []`, `nextCursor == null`) is a valid `Content`
  state with `canLoadMore = false`, never an error.
- **Concurrency safety:** `loadJob` de-duplication prevents overlapping initial
  loads; `isLoadingMore`/`isRefreshing` flags prevent overlapping page/refresh
  requests. All updates go through `MutableStateFlow.update { }` for atomicity.

## 8. Security & Privacy

- Payout data is financial PII (amounts, `notes`, `reject_reason`, `user_id`). The
  ViewModel must **never** log `Payout`, `PayoutBalance`, amounts/`*_cents`, or any
  free-text (`notes`/`reject_reason`). Any breadcrumb is limited to non-PII (action
  name, `ErrorCategory`, HTTP status if available). **[Corrected]** There is no
  `method.last4`/bank-label field in the contract (`PayoutOut.method` is a plain
  string like `bank_transfer`/`paypal`); the prior "`last4`/bank labels" wording was
  an unverified assumption — removed.
- No tokens or cookies are handled here; auth is owned by AND-027/AND-258.
  **[Clarified]** The web transport (`src/api/client.ts`) is cookie-session **plus**
  a `Bearer` access token header **plus** a CSRF token (`ui_csrf` cookie → `X-CSRF-Token`
  header), with `credentials: include`; not cookie-only as the draft implied. This
  ViewModel still touches none of it.
- `PayoutsState` and `PayoutsUiState` are in-memory only and are **not** written to
  `SavedStateHandle` (which can persist to disk); selection is the only thing that
  could be persisted and it is just an opaque id, but to avoid any at-rest PII this
  ticket keeps all state in `viewModelScope` and does not use `SavedStateHandle`.
- The gate must **fail closed**: any indeterminate account state resolves to
  `Unknown`/not-`Ready`, never to `Ready`, so the UI cannot accidentally expose a
  payout action to an unverified or restricted account.

## 9. Accessibility & i18n

- No Compose UI is produced, so screen-level a11y (focus order, content
  descriptions, touch targets) is **N/A here and owned by AND-259/260/261**.
- i18n contract: the ViewModel emits **no user-facing display strings of its own**
  for gate states — `PayoutGate` is a typed enum/sealed type, and the consuming
  screens map each case to string resources. **[Corrected]** `Payout.status` is a
  raw server string (e.g. `requested`, `approved`, `processing`, `completed`,
  `rejected`, `cancelled` — the values the web `STATUS_BADGE_VARIANT` map handles),
  passed through verbatim; the screen maps it to a localized label, not the ViewModel.
- The only strings the ViewModel surfaces are `PayoutsError.message` (already
  human-readable from the FastAPI `detail` mapper) and server-provided values
  (`Disabled.reason`, `NeedsVerification.currentTier`); these are passed verbatim
  and the screen decides whether to localize or display as-is.
- `Money` remains amount-minor + currency, so screens format with locale-aware
  `NumberFormat.getCurrencyInstance(locale)`; the ViewModel performs no formatting.

## 10. Telemetry & Logging

- Network timing/outcome telemetry is captured at the OkHttp layer (AND-027) and
  inherited via the repository; this ticket adds no network telemetry.
- The ViewModel may emit **non-PII** breadcrumbs only: `payouts_load_initial`,
  `payouts_refresh`, `payouts_load_more`, `payouts_retry`, each tagged with
  outcome (`success`/`error`) and, on error, `ErrorCategory` — never amounts, ids,
  or method details.
- **[Corrected]** A single gate-outcome breadcrumb
  (`payout_gate=ready|below_minimum|no_funds|unknown`) may be emitted on initial load
  to aid funnel analysis. It carries only the enum label — **never** the actual
  `available_cents`/`minimum_payout_cents` values from `BelowMinimum` (those are PII).
- All logging routes through the shared logger with the PII redactor; no
  `Log.d`/`println` of state objects.

## 11. Testing Strategy

This is the core acceptance criterion ("Unit-tested"). All tests are JVM unit tests
using a fake `PayoutsRepository`, `kotlinx-coroutines-test` (`StandardTestDispatcher`
+ `runTest`), Turbine for `StateFlow` assertions, and the `MainDispatcherRule` /
fake `@IoDispatcher` from `core-testing`. No Android instrumentation.

Gating logic — pure `gateOf(...)` **[Corrected to balance-derived gate]**:
1. `available_cents >= minimum_payout_cents` (e.g. 5000 ≥ 1000) → `Ready`.
2. `available_cents == minimum_payout_cents` (boundary, e.g. 1000 == 1000) → `Ready`.
3. `0 < available_cents < minimum_payout_cents` (e.g. 500 < 1000) →
   `BelowMinimum(available=500, minimum=1000)`.
4. `available_cents == 0` → `NoFunds` (regardless of `pending`/`hold`).
5. `balance == null` → `Unknown`.
6. `canRequest(amount)` true only for `minimum <= amount <= available`; false below
   minimum and false above available (mirrors web `amountError`).
7. Fail-closed: an indeterminate/null balance never yields `Ready`.

State machine — ViewModel:
8. Initial subscription emits `Loading` then `Content` once both calls succeed, with
   correct `gate`, merged `items`, and `canLoadMore`.
9. Balance + history fetched **concurrently** (assert both repo methods invoked
   before either result is consumed; fake records call order/overlap).
10. Initial history failure → `PayoutsUiState.Error`; `onRetry()` re-loads and
    transitions to `Content`.
11. Balance failure + history success → `Content` with `gate=Unknown` and a
    `transientError`; items present.
12. `onRefresh()` sets `isRefreshing=true` over existing `Content`, then clears it;
    selection is preserved across refresh.
13. `onLoadMore()` with non-null `nextCursor` appends the next page, updates
    `nextCursor`, and toggles `isLoadingMore`; with null `nextCursor` it is a no-op.
14. `onLoadMore()` failure leaves existing items intact and sets `transientError`.
15. Overlapping `onLoadMore()`/`onRefresh()`/initial loads are de-duplicated (only
    one in-flight request; assert fake call count).
16. `onSelectPayout(id)` for an in-list id sets `selected` with **no** repository
    call; `onSelectPayout(null)` clears it.
17. Empty history (`items=[]`, `nextCursor=null`) → `Content` with
    `canLoadMore=false`, not `Error`.
18. `ApiResult.Error` categories map to the correct `ErrorCategory`
    (network/auth/not-found/validation/server/unknown).

Coverage target: 100% of `gateOf`, the reducer, the error mapper, and every public
intent function; every `PayoutsUiState`/`PayoutGate` branch exercised. AND-263
builds on this suite and adds UI tests against the screens.

## 12. Dependencies & Sequencing

- **Depends on AND-258** (Payouts API): supplies `PayoutsRepository`, the domain
  models (`Payout`, `PayoutPage`, `PayoutBalance`), `ApiResult`/`apiCall`, and the
  `nextCursor` pagination seam. **[Corrected]** It does **not** supply `PayoutAccount`,
  `PayoutMethod`, or a `PayoutStatus`/`Money` server type — those are not in the
  contract (`status`/`method` are strings, `*_cents` integers). This ticket must not
  reimplement any AND-258 type. AND-258 must expose `getPayoutBalance()`.
- **Depends transitively** on AND-027 (cookie/CSRF/refresh stack, FastAPI `detail`
  error mapper) and on the `core-testing` coroutine test utilities and
  `@IoDispatcher` qualifier from M1.
- **Blocks AND-263** (Payouts tests), which extends this unit suite and adds UI
  tests; **enables** AND-259 (consumes `PayoutGate` + `canRequest()` for the request
  form), AND-260 (consumes `items`/`nextCursor`/selection for history), and
  AND-261 (reuses load/state patterns for bulk read views).
- **[Corrected] Note on AND-320:** the deeper KYC tier model
  (`GET /v1/kyc/tiers/me`, evaluate/requirements) belongs to AND-259/AND-320 and is a
  **separate endpoint**, not part of `/ui/payouts`. This ticket's gate derives purely
  from `PayoutBalance`; any verification gate is composed on top by AND-259/AND-320.
- Sequencing within the ticket: define `PayoutsUiState`/`PayoutGate`/`PayoutsError`
  → write `gateOf` + its unit tests → implement the reducer + load/refresh/loadMore
  → wire intents + `stateIn` projection → complete the state-machine unit tests.

## 13. Risks & Open Questions

- **R1 — Gate vocabulary [Corrected/Resolved].** The original `PayoutAccount.status`
  / `payoutsEnabled` gate does not exist. Resolved: the gate is balance-derived
  (`available_cents` vs `minimum_payout_cents`, both verified in `PayoutBalanceOut`).
  Remaining open: the `Payout.status` vocabulary is a free-form server string; the
  values web handles are `requested/approved/processing/completed/rejected/cancelled`
  but the backend does not enumerate them in the schema — treat as open-ended.
- **R2 — KYC ownership overlap with AND-259/AND-320 [Corrected].** This ticket owns
  the *balance-derived* gate only. Any KYC/verification gate is a separate concern
  built on `GET /v1/kyc/tiers/me` by AND-259/AND-320. The `gateOf(balance)` function
  is the single shared balance primitive.
- **R3 — Pagination correctness on the flaky dev host.** Overlapping or repeated
  pages could duplicate items. Mitigation: de-dup by `id` on append plus
  `isLoadingMore` guard; **open:** confirm whether the backend cursor is stable.
- **R4 — Transient error UX hook.** Whether the ViewModel auto-clears
  `transientError` on next action or requires an explicit `onTransientErrorShown()`.
  Current design provides the explicit hook and also clears on next success; the
  consuming screens (AND-259/260) finalize the snackbar contract.
- **R5 — Deep-link selection [Corrected].** There is **no** `GET /ui/payouts/{id}`
  detail endpoint, so a deep-link to an id not in `items` **cannot** be satisfied by a
  `getPayout(id)` fetch. Selection is resolved only from loaded `items`
  (`items.find { it.id == selectedId }`); an unknown id yields `selected == null` and
  the screen must re-list or show not-found. The prior `getPayout(id)` fallback is
  removed entirely.

## 14. Acceptance Criteria

1. `PayoutsViewModel`, `PayoutsUiState`, `PayoutGate`, `PayoutsError`, and the
   `gateOf(...)` selector exist under `com.testlogon.android.feature.payouts` on
   branch `android-port`, with `feature-payouts -> core-data -> core-model` layering
   and **no** direct Retrofit/`core-network` dependency.
2. The ViewModel exposes exactly one `StateFlow<PayoutsUiState>` plus the intent
   functions `onRefresh()`, `onLoadMore()`, `onRetry()`, `onSelectPayout(id)`; no
   mutable state, `LiveData`, or suspend functions are public.
3. **[Corrected]** Initial load fetches **balance** (`GET /ui/payouts/balance`) +
   first history page (`GET /ui/payouts`) **concurrently** and combines them into a
   single `Content`, with a single combined loading state.
4. **[Corrected]** `gateOf(balance)` returns `Ready`/`BelowMinimum`/`NoFunds`/`Unknown`
   per §3, is a pure function, and **fails closed** (null/indeterminate ≠ `Ready`).
5. Pagination works: `onLoadMore()` appends pages using `nextCursor`, exposes
   `canLoadMore`, de-dups by id, and is a no-op when `nextCursor == null`.
6. The two-tier error model is implemented: initial failure → `Error`;
   refresh/load-more failure → `transientError` over preserved content; empty
   history is a valid `Content`.
7. State survives configuration change and re-subscription does not re-fetch
   (one-time initial load); concurrent loads are de-duplicated.
8. The full unit-test suite from §11 (gating + state machine + error mapping) is
   present and green (**"Unit-tested"**), with 100% coverage of `gateOf`, the
   reducer, the error mapper, and every public intent.
9. No payout PII is logged in any build configuration.

## 15. Definition of Done

- All §14 acceptance criteria met; CI green (`assembleDebug`, `ktlint`/detekt, and
  the `feature-payouts` unit-test task).
- Tests run as fast JVM unit tests with a fake `PayoutsRepository`,
  `kotlinx-coroutines-test`, and Turbine; no Android instrumentation is required for
  this ticket's suite.
- No new network code, no new endpoints, no Room/DataStore additions; the ViewModel
  depends only on the AND-258 repository contract.
- Public surface (`PayoutsViewModel`, `PayoutsUiState`, `PayoutGate`, `gateOf`) has
  KDoc; the gate semantics and the `nextCursor`/selection contract are documented
  for AND-259/260/261.
- No financial PII in logs; gate verified to fail closed by test.
- Code reviewed and merged to `android-port`; AND-263 can extend the test suite and
  AND-259/260/261 can collect `uiState` with no further state-logic changes.
- Open questions R1–R5 either resolved against `/openapi.json` + a captured live
  response or recorded as follow-up notes on AND-259/AND-320.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. Sources:
OpenAPI index (`reference/openapi.index.txt`), OpenAPI schemas
(`reference/openapi.pretty.json` → `components.schemas.<Name>`), and frontend
(`reference/src/...`).

1. **History list endpoint is `GET /ui/payouts` with `limit`/`cursor`, returns a
   cursor-paged list.** — **Verified.** OpenAPI `GET /ui/payouts | op=list_payouts_ui_payouts_get | resp=200:PayoutListOut | params=limit,cursor,user_sub,X-SESSION-ID,X-IMPERSONATION-TOKEN`; `src/api/endpoints/payouts.ts: listPayouts`. `PayoutListOut = { items: PayoutOut[], next_cursor: string|null }` (`components.schemas.PayoutListOut`; `src/api/types.ts: PayoutListResp`).
2. **Balance endpoint is `GET /ui/payouts/balance` → `PayoutBalanceOut`.** —
   **Verified.** OpenAPI `GET /ui/payouts/balance | op=payout_balance_ui_payouts_balance_get | resp=200:PayoutBalanceOut`; `src/api/endpoints/payouts.ts: getPayoutBalance`.
3. **`PayoutBalanceOut` fields: `available_cents`, `pending_cents`, `hold_cents`,
   `total_earned_cents`, `currency`, `minimum_payout_cents` (all integers, currency
   default "USD", minimum default 1000).** — **Verified.**
   `components.schemas.PayoutBalanceOut`; mirrored in `src/api/types.ts: PayoutBalance`.
4. **`GET /ui/payouts/account` exists and returns a `PayoutAccount`.** — **Corrected
   (does not exist).** No `*/payouts/account` row in `openapi.index.txt`; no
   `getPayoutAccount` in `src/api/endpoints/payouts.ts`. Replaced with `/ui/payouts/balance`.
5. **`PayoutAccount` has `payoutsEnabled`, `kycTier`, `defaultMethodId`, `methods`.**
   — **Corrected (no such schema/fields).** Grep for `payouts_enabled|defaultMethod|kyc_tier|payout_methods` across `reference/` returns no payout-account hits (only unrelated MFA `defaultMethod` in `src/pages/Login.tsx` and the separate KYC-tiers API). No `PayoutAccount` schema in `openapi.pretty.json`.
6. **`GET /ui/payouts/{payoutId}` single-payout detail endpoint exists.** —
   **Corrected (does not exist).** `openapi.index.txt` payout rows are only
   `/ui/payouts`, `/ui/payouts/balance`, `/ui/payouts/request`,
   `/ui/payouts/{payout_id}/cancel`. No GET-by-id. `getPayout(id)` removed.
7. **`Payout`/`PayoutOut` fields are `payout_id, user_id, amount_cents, method,
   status, created_at, updated_at, notes, reject_reason, approved_by, completed_at`;
   `status` and `method` are plain strings.** — **Verified.**
   `components.schemas.PayoutOut`; `src/api/types.ts: Payout`.
8. **Pagination cursor field is `next_cursor` (string|null), list field is `items`.**
   — **Verified.** `components.schemas.PayoutListOut`; used in `PayoutDashboard.tsx`
   (`payoutsQ.data.next_cursor`, `payoutsQ.data.items`).
9. **The web app derives a payout "gate" from account/KYC state.** — **Corrected.**
   `src/pages/payouts/PayoutDashboard.tsx` has no account/KYC gate; eligibility is the
   inline `amountError`/`canSubmit` check: `minCents = minimum_payout_cents`,
   `availCents = available_cents`, valid when `minCents <= amountCents <= availCents`.
   Re-modeled as balance-derived `PayoutGate` (`Ready`/`BelowMinimum`/`NoFunds`/`Unknown`).
10. **Auth is cookie-based.** — **Corrected/Clarified.** `src/api/client.ts` uses
    `credentials: "include"` (cookies) **plus** `Authorization: Bearer <accessToken>`
    from the auth store **plus** CSRF: `getCookie("ui_csrf")` → header `X-CSRF-Token`.
    So it is cookie+bearer+CSRF, not cookie-only. (This ticket handles none of it.)
11. **401 handling: single session refresh then retry.** — **Verified.**
    `src/api/client.ts`: on 401, `POST /ui/session/refresh` once (deduped via
    `refreshPromise`), retry original request; on repeated 401 → `logout("session_expired")`.
12. **Network/offline error surfaces as a distinct error.** — **Verified.**
    `src/api/client.ts` catch block throws `new ApiError(0, "Network error", err)`
    on fetch failure (offline/DNS) — supports the flaky-dev-host/offline test path.
13. **Server validation errors use FastAPI `detail` / `HTTPValidationError`.** —
    **Verified.** All payout ops list `422:HTTPValidationError` in the index;
    `components.schemas.HTTPValidationError`/`ValidationError`. `client.ts` normalizes
    `body.detail` into `ApiError.detail`.
14. **`requestPayout` 409 means "already have a pending payout request".** —
    **Verified (web behavior).** `src/pages/payouts/PayoutDashboard.tsx`
    `requestMut.onError`: `if (err.status === 409) toast.error("You already have a
    pending payout request")`. (Request/cancel are out of scope here but inform AND-259.)
15. **`POST /ui/payouts/request` (`PayoutRequestIn` → 201 `PayoutCreateOut`) and
    `POST /ui/payouts/{payout_id}/cancel` (→ `PayoutActionOut`) exist; cancel offered
    only for `requested`/`approved`.** — **Verified.** OpenAPI index rows;
    `PayoutDashboard.tsx` shows Cancel only when `status === "requested" || "approved"`.
16. **Observed `Payout.status` values: requested/approved/processing/completed/
    rejected/cancelled.** — **Verified (web), Unverified (server enum).** Values come
    from `STATUS_BADGE_VARIANT` in `PayoutDashboard.tsx`; `PayoutOut.status` is an
    unconstrained string in the schema, so the set is not server-enforced.
17. **AND-258 supplies the repository + domain models (`PayoutsRepository`,
    `getPayoutBalance`, `getPayouts`, `Payout`, `PayoutPage`, `PayoutBalance`).** —
    **Unverified-assumption (cross-ticket).** AND-258 is a sibling spec, not in the
    authoritative sources here; its exact Kotlin surface cannot be confirmed. This
    ticket asserts the names it needs (notably `getPayoutBalance()` must exist).
18. **`@HiltViewModel` + `StateFlow` + `stateIn(WhileSubscribed)` is the idiomatic
    Android pattern for a UI state holder.** — **framework ref.**
    https://developer.android.com/topic/architecture/ui-layer/stateholders and
    https://developer.android.com/kotlin/flow/stateflow-and-sharedflow .
19. **Dev host `http://18.222.237.167:8000` (plaintext, unreliable).** —
    **Unverified-assumption.** Not present in the authoritative sources provided;
    carried over from AND-258 context and unconfirmable here.

### Corrections made

- **§1/§2/§3/§4/§5/§11/§12/§13/§14:** replaced the non-existent `PayoutAccount` model
  and `getPayoutAccount()`/`GET /ui/payouts/account` with `PayoutBalance` /
  `getPayoutBalance()` / `GET /ui/payouts/balance` (claims 4, 5, 2, 3).
- **§3/§4/§11/§14:** re-modeled `PayoutGate` from
  `Ready/NeedsMethod/NeedsVerification/Disabled/Unknown` (account/KYC-based, invented)
  to balance-derived `Ready/BelowMinimum/NoFunds/Unknown`, plus a `canRequest(amount)`
  helper mirroring the web `canSubmit` (claim 9).
- **§5/§13-R5:** removed the `GET /ui/payouts/{payoutId}` detail endpoint and the
  `getPayout(id)` deep-link fallback — no such endpoint exists (claim 6).
- **§2/§9/§12:** corrected the model list — `Payout.status`/`method` are strings, not
  `PayoutStatus`/`PayoutMethod` types; removed `Money`/`PayoutAccount` as server types
  (claim 7).
- **§8:** removed the invented `method.last4`/bank-label PII fields (no such fields);
  clarified auth is cookie+bearer+CSRF (claims 7, 10).
- **§10:** corrected the gate-outcome breadcrumb enum to the new gate vocabulary.
- **§13-R1/R2:** rewrote to reflect the real (balance) gate and the separate KYC API.

### Open assumptions

- **AND-258 Kotlin surface (claim 17):** the repository method names/types
  (`getPayoutBalance`, `PayoutPage`, `ApiResult`) are assumed from a sibling spec not
  in the provided sources; if AND-258 names them differently, align on integration.
- **`Payout.status` vocabulary (claim 16):** server schema leaves `status` an open
  string; the six observed values are web-side conventions, not contract-guaranteed.
- **Dev host / transport reliability (claim 19):** host address and "~20s timeout /
  idempotent-GET retry" behavior are inherited from AND-258/AND-027, unverifiable here.
- **`pending_cents`/`hold_cents` semantics:** present in the schema and shown in the UI
  ("In transit" / "Within hold period") but not used by the gate; their precise
  business meaning is not documented in the sources.

## 17. Test Plan

All tests are JVM/Robolectric unless noted. IDs trace to §14 Acceptance Criteria
(AC-1..AC-9). Targets: **JVM** (local unit/Robolectric, no device); **emulator**
(headless AVD `test35`, API 35 x86_64) for instrumented/UI; **physical** (Samsung
Galaxy A15 5G, SM-A156U, serial R5CX821TA9R, API 34 arm64-v8a) only where real
hardware/ABI matters. This ticket is pure state/gating logic with **no UI and no
hardware**, so the suite is JVM-first; a couple of optional ABI/integration cases are
included for completeness and noted as such.

- **TC-AND-262-01 — Gate: Ready at/above minimum** · Type: unit · Target: JVM ·
  Pre: fake `PayoutBalance(available_cents=5000, minimum_payout_cents=1000)`.
  Steps: call `gateOf(balance)`; also `gateOf` with `available==minimum==1000`.
  Expected: both → `PayoutGate.Ready`. Traces: AC-4.
- **TC-AND-262-02 — Gate: BelowMinimum** · Type: unit · Target: JVM ·
  Pre: `available_cents=500, minimum_payout_cents=1000`. Steps: `gateOf(balance)`.
  Expected: `BelowMinimum(availableCents=500, minimumCents=1000)`. Traces: AC-4.
- **TC-AND-262-03 — Gate: NoFunds and Unknown (fail-closed)** · Type: unit ·
  Target: JVM · Pre: (a) `available_cents=0`; (b) `balance=null`. Steps: `gateOf`
  for each; assert no input ever returns `Ready` except when `available>=minimum`.
  Expected: (a) `NoFunds`, (b) `Unknown`; never `Ready`. Traces: AC-4.
- **TC-AND-262-04 — `canRequest()` boundaries** · Type: unit · Target: JVM ·
  Pre: `available_cents=5000, minimum_payout_cents=1000`. Steps: `canRequest` for
  999, 1000, 5000, 5001. Expected: false, true, true, false (mirrors web `amountError`).
  Traces: AC-4.
- **TC-AND-262-05 — Happy path: initial load combines balance + first page** ·
  Type: unit (Turbine) · Target: JVM · Pre: fake repo returns
  `ApiResult.Success(balance)` and `Success(PayoutPage(items=[p1,p2], next_cursor="c2"))`.
  Steps: subscribe to `uiState`; advance dispatcher. Expected: emits `Loading` then
  `Content` with `gate=gateOf(balance)`, `payouts=[p1,p2]`, `canLoadMore=true`,
  single combined loading state. Traces: AC-3, AC-1.
- **TC-AND-262-06 — Concurrency: balance + history fetched in parallel** ·
  Type: unit · Target: JVM · Pre: fake repo records invocation timestamps/overlap.
  Steps: trigger initial load. Expected: both `getPayoutBalance` and `getPayouts`
  invoked before either result is consumed (overlapping). Traces: AC-3.
- **TC-AND-262-07 — Initial history failure → full-screen Error, then retry** ·
  Type: unit (Turbine) · Target: JVM · Pre: first `getPayouts` →
  `ApiResult.Error`; on retry returns `Success`. Steps: subscribe; observe `Error`;
  call `onRetry()`. Expected: `Loading`→`Error(error)`→(retry)→`Content`. Traces:
  AC-6, AC-2.
- **TC-AND-262-08 — Partial success: balance fails, history succeeds** ·
  Type: unit · Target: JVM · Pre: `getPayoutBalance` → Error, `getPayouts` → Success.
  Steps: initial load. Expected: `Content` with `gate=Unknown`, `transientError` set,
  `payouts` present. Traces: AC-6, AC-4.
- **TC-AND-262-09 — Pagination: load more appends; null cursor is no-op; de-dup by
  id** · Type: unit · Target: JVM · Pre: page1 `items=[p1,p2] next="c2"`, page2
  `items=[p2,p3] next=null` (overlap p2). Steps: `onLoadMore()` then `onLoadMore()`
  again. Expected: after first → `[p1,p2,p3]` (p2 de-duped), `canLoadMore=false`;
  second call makes no repo call. Traces: AC-5.
- **TC-AND-262-10 — Refresh preserves selection; isRefreshing toggles** ·
  Type: unit (Turbine) · Target: JVM · Pre: loaded `Content`, `onSelectPayout(p1.id)`.
  Steps: `onRefresh()`. Expected: `isRefreshing=true` over existing content then
  `false`; initial `Loading` state not re-emitted; `selected` still p1. Traces:
  AC-6, AC-2.
- **TC-AND-262-11 — Load-more failure keeps items, sets transientError** ·
  Type: unit · Target: JVM · Pre: loaded `Content` with `next!=null`; next page →
  Error. Steps: `onLoadMore()`. Expected: items unchanged, `transientError` set,
  no `Error` state. Traces: AC-6.
- **TC-AND-262-12 — De-duplication of overlapping loads** · Type: unit ·
  Target: JVM · Pre: fake repo counts calls; slow suspend. Steps: trigger
  initial load + `onRefresh()` + `onLoadMore()` rapidly. Expected: only one in-flight
  request per kind (`loadJob`/`isRefreshing`/`isLoadingMore` guards); assert call
  counts. Traces: AC-7.
- **TC-AND-262-13 — Re-subscription does not re-fetch (one-time init)** ·
  Type: unit · Target: JVM · Pre: `WhileSubscribed(5_000)`; `initialLoaded` guard.
  Steps: collect, cancel within 5s, re-collect. Expected: no second initial fetch;
  state retained. Traces: AC-7.
- **TC-AND-262-14 — Selection without network; clear selection** · Type: unit ·
  Target: JVM · Pre: loaded `Content` with p1 in items. Steps: `onSelectPayout(p1.id)`
  then `onSelectPayout(null)`; also select an id NOT in items. Expected: in-list id →
  `selected=p1`, **zero** repo calls (no `getPayout` endpoint exists); null → cleared;
  unknown id → `selected=null` (no fetch attempted). Traces: AC-2, AC-5.
- **TC-AND-262-15 — Empty history is valid Content, not Error** · Type: unit ·
  Target: JVM · Pre: `getPayouts` → `PayoutPage(items=[], next_cursor=null)`,
  balance Success. Steps: initial load. Expected: `Content`, `payouts=[]`,
  `canLoadMore=false`, no `Error`. Traces: AC-6.
- **TC-AND-262-16 — Error mapping incl. offline/flaky-host & auth** · Type:
  contract/MockWebServer · Target: JVM (Robolectric/OkHttp MockWebServer) · Pre: fake
  repo / MockWebServer returns: network failure (`ApiError(0)`), 401, 404, 422
  (`HTTPValidationError` body with `detail`), 500. Steps: map each via the
  `ApiResult.Error → PayoutsError` helper. Expected: `ErrorCategory` =
  NETWORK/AUTH/NOT_FOUND/VALIDATION/SERVER respectively; offline → NETWORK surfaces a
  transient (content present) or fatal (initial) error per the two-tier model; AUTH is
  surfaced (not silently retried by the ViewModel). Traces: AC-6.
- **TC-AND-262-17 — Security: no PII in logs** · Type: unit · Target: JVM ·
  Pre: capture log/breadcrumb sink; loaded `Content` with amounts and `notes`.
  Steps: run load/refresh/error flows. Expected: breadcrumbs contain only action
  name + `ErrorCategory` + gate enum label; **no** `*_cents`, `notes`,
  `reject_reason`, `user_id`, or `payout_id`. Traces: AC-9.
- **TC-AND-262-18 — (Optional) ABI / API-level sanity on physical device** ·
  Type: instrumented/e2e · Target: **physical** (SM-A156U, arm64-v8a, API 34) —
  MUST run on the physical device (arm64 vs the emulator's x86_64; API 34 vs 35).
  Pre: app built with `feature-payouts`. Steps: instantiate `PayoutsViewModel` via a
  minimal host, drive a load with a fake repo, assert `Content`/gate on-device.
  Expected: identical state results to JVM; no arm64/API-34-specific coroutine or
  `stateIn` behavior differences. Note: not strictly required for a pure-logic ticket;
  run only if AND-263 needs an on-device baseline. Traces: AC-1, AC-3.

### Coverage matrix

| AC (§14) | Covered by |
|---|---|
| AC-1 (types exist, layering, no Retrofit dep) | TC-05, TC-18 |
| AC-2 (single StateFlow + intents, no mutable/LiveData/suspend public) | TC-07, TC-10, TC-14 |
| AC-3 (concurrent balance+history → single Content) | TC-05, TC-06, TC-18 |
| AC-4 (gateOf branches + fail-closed) | TC-01, TC-02, TC-03, TC-04, TC-08 |
| AC-5 (pagination append/de-dup/no-op; selection from items) | TC-09, TC-14 |
| AC-6 (two-tier error model; empty = Content) | TC-07, TC-08, TC-10, TC-11, TC-15, TC-16 |
| AC-7 (config-change survival, no re-fetch, de-dup) | TC-12, TC-13 |
| AC-8 (full suite green, 100% gateOf/reducer/mapper/intents) | TC-01..TC-17 (whole suite) |
| AC-9 (no payout PII logged) | TC-17 |
