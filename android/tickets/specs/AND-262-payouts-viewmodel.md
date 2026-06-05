---
id: AND-262
title: Payouts ViewModel
milestone: M6
epic: E35
priority: P1
size: M
status: draft
depends_on: [AND-258]
blocks: [AND-263]
---

# AND-262 — Payouts ViewModel

## 1. Overview & Goal

This ticket delivers the presentation-layer state holder for the Payouts domain of
the TestLogon native Android app: a Hilt-injected `PayoutsViewModel` that exposes a
single `StateFlow<PayoutsUiState>`, owns the load/refresh/paging orchestration over
`PayoutsRepository` (AND-258), and centralizes the **gating logic** that decides
what the user is allowed to do with payouts based on their payout-account state
(`payoutsEnabled`, `kycTier`, presence of a default method). It is the Android port
of the state/selector logic that the web reference app keeps in its payouts hooks
and store slices on top of `frontend/src/api/endpoints/payouts.ts`.

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
  types. Domain models (`Payout`, `PayoutPage`, `PayoutAccount`, `Money`,
  `PayoutStatus`, `PayoutMethod`) are reused from `com.testlogon.android.core.model.payout`
  (AND-258); they are **not** redeclared here.
- **Module placement:** `feature-payouts`. Layering rule
  `feature-payouts -> core-data -> core-model` is respected. The ViewModel injects
  the `PayoutsRepository` interface from `core-data`; it never touches
  `core-network`/Retrofit directly.
- **Web reference:** `frontend/src/api/endpoints/payouts.ts` and the payout-related
  shapes/selectors in `frontend/src/api/types.ts`. Where the web app derives a
  "can configure payouts" / "needs verification" boolean from account state, this
  ViewModel reproduces that logic as `PayoutGate`.
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

FR-2. On first active subscription (and on `onRetry()`), load the payout account
(`getPayoutAccount()`) and the first page of history (`getPayouts(cursor = null)`)
concurrently, combine them into a single `PayoutsUiState.Content`, and surface a
single combined loading state until both complete.

FR-3. Derive a **gate decision** (`PayoutGate`) purely from `PayoutAccount`:
- `Ready` — `payoutsEnabled == true` and a default method exists.
- `NeedsMethod` — `payoutsEnabled == true` but no default method
  (`defaultMethodId == null` and `methods` empty or none default).
- `NeedsVerification` — `payoutsEnabled == false` and `kycTier` indicates the user
  has not reached the payout-required tier (insufficient KYC).
- `Disabled` — `payoutsEnabled == false` for a non-KYC reason (e.g., account
  `status` is `"restricted"`/`"closed"`), carrying the server `status` for display.
- `Unknown` — account state is indeterminate (e.g., account load failed but history
  loaded); treated as not-ready and surfaced with a retry affordance.
The gate is a **pure function** `gateOf(account: PayoutAccount?): PayoutGate` so it
is independently unit-testable and reused by AND-259's KYC-gate panel.

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
    val account: PayoutAccount? = null,
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
        val account: PayoutAccount?,
        val payouts: List<Payout>,
        val canLoadMore: Boolean,
        val isRefreshing: Boolean,
        val isLoadingMore: Boolean,
        val selected: Payout?,
        val transientError: PayoutsError?,   // shown as snackbar, then cleared
    ) : PayoutsUiState
}

sealed interface PayoutGate {
    data object Ready : PayoutGate
    data object NeedsMethod : PayoutGate
    data class NeedsVerification(val currentTier: String?) : PayoutGate
    data class Disabled(val reason: String?) : PayoutGate
    data object Unknown : PayoutGate
}

data class PayoutsError(val category: ErrorCategory, val message: String)
enum class ErrorCategory { NETWORK, AUTH, NOT_FOUND, VALIDATION, SERVER, UNKNOWN }
```

Pure gating selector (the testable heart of "gating logic"):

```kotlin
internal fun gateOf(account: PayoutAccount?): PayoutGate = when {
    account == null -> PayoutGate.Unknown
    account.payoutsEnabled && account.hasDefaultMethod() -> PayoutGate.Ready
    account.payoutsEnabled -> PayoutGate.NeedsMethod
    account.status.isRestricted() -> PayoutGate.Disabled(account.status)
    else -> PayoutGate.NeedsVerification(account.kycTier)
}

private fun PayoutAccount.hasDefaultMethod(): Boolean =
    defaultMethodId != null || methods.any { it.isDefault }

private fun String?.isRestricted(): Boolean =
    this?.lowercase() in setOf("restricted", "closed", "disabled", "rejected")
```

Initial load (concurrent, de-duplicated):

```kotlin
private var loadJob: Job? = null

private fun loadInitial(force: Boolean = false) {
    if (loadJob?.isActive == true && !force) return
    loadJob = viewModelScope.launch(io) {
        internal.update { it.copy(fatalError = null) }
        val accountDeferred = async { repository.getPayoutAccount() }
        val pageDeferred = async { repository.getPayouts(cursor = null) }
        val account = accountDeferred.await()
        val page = pageDeferred.await()
        reduce(account, page, isInitial = !internal.value.initialLoaded)
    }
}
```

Reduction rules:
- Both succeed → `Content` with combined data, `initialLoaded = true`,
  `gate = gateOf(account)`.
- History succeeds, account fails → `Content` with `gate = Unknown` and a
  `transientError` (content is still usable; gate cannot be trusted).
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
established by AND-258:

```kotlin
suspend fun getPayoutAccount(): ApiResult<PayoutAccount>
suspend fun getPayouts(cursor: String? = null, limit: Int = 20): ApiResult<PayoutPage>
suspend fun getPayout(payoutId: String): ApiResult<Payout>
```

The backing endpoints (`GET /ui/payouts/account`, `GET /ui/payouts?cursor=&limit=`,
`GET /ui/payouts/{payoutId}`), their JSON shapes, cookie/CSRF auth, and FastAPI
error bodies are owned and documented by **AND-258 §5**. The only contract this
ticket adds is the **internal mapping** from `PayoutAccount` → `PayoutGate`
(see §4), which is a pure in-process function with no wire representation.

`getPayout(id)` is available but not required by the default flow: selection is
satisfied from already-loaded `items`. If a future deep-link enters with an id not
in `items`, `onSelectPayout` may trigger a single `getPayout(id)` fetch; that path
is specified but gated behind an `items.none { it.id == id }` check to avoid
redundant calls.

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

- Payout data is financial PII (amounts, method `last4`, bank labels). The
  ViewModel must **never** log `Payout`, `PayoutAccount`, `Money`, amounts, ids of
  financial methods, or `last4`. Any breadcrumb is limited to non-PII (action name,
  `ErrorCategory`, HTTP status if available).
- No tokens or cookies are handled here; auth remains cookie-based and owned by
  AND-027/AND-258.
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
  screens map each case to string resources. `PayoutStatus` (from AND-258) is
  likewise passed through as an enum, not a localized string.
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
- A single gate-outcome breadcrumb (`payout_gate=ready|needs_method|needs_verification|disabled|unknown`)
  may be emitted on initial load to aid funnel analysis; the tier string in
  `NeedsVerification` is **not** included if it could be considered sensitive.
- All logging routes through the shared logger with the PII redactor; no
  `Log.d`/`println` of state objects.

## 11. Testing Strategy

This is the core acceptance criterion ("Unit-tested"). All tests are JVM unit tests
using a fake `PayoutsRepository`, `kotlinx-coroutines-test` (`StandardTestDispatcher`
+ `runTest`), Turbine for `StateFlow` assertions, and the `MainDispatcherRule` /
fake `@IoDispatcher` from `core-testing`. No Android instrumentation.

Gating logic — pure `gateOf(...)`:
1. `payoutsEnabled=true` + `defaultMethodId` set → `Ready`.
2. `payoutsEnabled=true` + a method with `isDefault=true` (no `defaultMethodId`) → `Ready`.
3. `payoutsEnabled=true` + no default method → `NeedsMethod`.
4. `payoutsEnabled=false` + status `active` → `NeedsVerification(kycTier)`.
5. `payoutsEnabled=false` + status `restricted`/`closed`/`rejected` → `Disabled(status)`.
6. `account == null` → `Unknown`.
7. Fail-closed: an unexpected combination never yields `Ready`.

State machine — ViewModel:
8. Initial subscription emits `Loading` then `Content` once both calls succeed, with
   correct `gate`, merged `items`, and `canLoadMore`.
9. Account + history fetched **concurrently** (assert both repo methods invoked
   before either result is consumed; fake records call order/overlap).
10. Initial history failure → `PayoutsUiState.Error`; `onRetry()` re-loads and
    transitions to `Content`.
11. Account failure + history success → `Content` with `gate=Unknown` and a
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
  models (`Payout`, `PayoutPage`, `PayoutAccount`, `PayoutMethod`, `Money`,
  `PayoutStatus`), `ApiResult`/`apiCall`, and the `nextCursor` pagination seam. This
  ticket must not reimplement any of those.
- **Depends transitively** on AND-027 (cookie/CSRF/refresh stack, FastAPI `detail`
  error mapper) and on the `core-testing` coroutine test utilities and
  `@IoDispatcher` qualifier from M1.
- **Blocks AND-263** (Payouts tests), which extends this unit suite and adds UI
  tests; **enables** AND-259 (consumes `PayoutGate` for the KYC-gate panel),
  AND-260 (consumes `items`/`nextCursor`/selection for history + detail), and
  AND-261 (reuses load/state patterns for bulk read views).
- **Note on AND-320:** the deeper KYC tier model (`TierStatus`,
  `requiredTierForPayouts`, `evaluate()`) belongs to AND-259/AND-320. This ticket's
  gate intentionally derives `NeedsVerification` from `PayoutAccount.payoutsEnabled`
  + `kycTier` only; AND-259 may layer the full tier comparison on top of this gate.
- Sequencing within the ticket: define `PayoutsUiState`/`PayoutGate`/`PayoutsError`
  → write `gateOf` + its unit tests → implement the reducer + load/refresh/loadMore
  → wire intents + `stateIn` projection → complete the state-machine unit tests.

## 13. Risks & Open Questions

- **R1 — Gate vocabulary.** The exact `PayoutAccount.status` values and the precise
  meaning of `payoutsEnabled=false` (KYC vs. restriction vs. onboarding incomplete)
  are unconfirmed against the live backend. Mitigation: `isRestricted()` set is
  centralized and the gate fails closed; **open:** confirm the authoritative status
  vocabulary and whether a distinct `requirements`/`disabled_reason` field exists.
- **R2 — KYC ownership overlap with AND-259/AND-320.** Risk of duplicating gate
  logic. Decision: this ticket owns the *account-derived* gate; AND-259 composes it
  with full tier requirements. The `gateOf` function is the single shared primitive.
- **R3 — Pagination correctness on the flaky dev host.** Overlapping or repeated
  pages could duplicate items. Mitigation: de-dup by `id` on append plus
  `isLoadingMore` guard; **open:** confirm whether the backend cursor is stable.
- **R4 — Transient error UX hook.** Whether the ViewModel auto-clears
  `transientError` on next action or requires an explicit `onTransientErrorShown()`.
  Current design provides the explicit hook and also clears on next success; the
  consuming screens (AND-259/260) finalize the snackbar contract.
- **R5 — Deep-link selection.** Selecting an id not in `items` triggering
  `getPayout(id)` is specified but unexercised until AND-260 adds detail
  navigation; kept behind a guard to avoid premature network calls.

## 14. Acceptance Criteria

1. `PayoutsViewModel`, `PayoutsUiState`, `PayoutGate`, `PayoutsError`, and the
   `gateOf(...)` selector exist under `com.testlogon.android.feature.payouts` on
   branch `android-port`, with `feature-payouts -> core-data -> core-model` layering
   and **no** direct Retrofit/`core-network` dependency.
2. The ViewModel exposes exactly one `StateFlow<PayoutsUiState>` plus the intent
   functions `onRefresh()`, `onLoadMore()`, `onRetry()`, `onSelectPayout(id)`; no
   mutable state, `LiveData`, or suspend functions are public.
3. Initial load fetches account + first history page **concurrently** and combines
   them into a single `Content`, with a single combined loading state.
4. `gateOf` returns `Ready`/`NeedsMethod`/`NeedsVerification`/`Disabled`/`Unknown`
   per §3, is a pure function, and **fails closed** (indeterminate ≠ `Ready`).
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
