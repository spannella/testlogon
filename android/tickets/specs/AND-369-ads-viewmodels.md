---
id: AND-369
title: Ads ViewModels
milestone: M8
epic: E47
priority: P2
size: M
status: draft
depends_on: [AND-363]
blocks: []
---

# AND-369 — Ads ViewModels

## 1. Overview & Goal

This ticket delivers the presentation-layer state holders for the Ads surface of the
TestLogon Android app: the ViewModels that drive the advertiser account list, the
per-account billing summary, and the per-account campaigns (read-only) screens. The
goal is a fully unit-tested state layer that consumes the Ads repository introduced in
AND-363 and exposes immutable, Compose-friendly `StateFlow<UiState>` to the (later)
feature screens.

Scope per the backlog is narrowly **State**: this ticket owns ViewModel classes, their
`UiState` models, the reducer/loader logic, error mapping into UI-presentable form, and
their exhaustive unit tests. It does **not** own Composable screens or navigation wiring
(a downstream `feature-ads` UI ticket), nor the DTOs/Retrofit service/repository (owned
by AND-363). The acceptance bar from the backlog is simply "Unit-tested"; in practice
that means deterministic coverage of every loading/success/error/empty branch plus the
manual-refresh and account-selection paths, using fakes for the repository and a test
dispatcher.

These ViewModels live in `feature-ads` and depend only on the `core-*` modules (model,
data, ui) plus the Ads repository contract from AND-363. They must conform to the
project's standard ViewModel idiom: a single `StateFlow<UiState>` per screen, no
`LiveData`, no exposure of Retrofit/Room types, and all I/O routed through an injected
`CoroutineDispatcher`.

## 2. Context & References

- **Module:** `feature-ads` (Gradle module `:feature-ads`), package
  `com.testlogon.android.feature.ads`. State holders under `.viewmodel`, UI state models
  under `.state`.
- **Upstream (AND-363, Ads accounts API):** provides `core-model` DTOs/domain types and
  the `AdsRepository` interface returning `ApiResult<T>`. AND-363 covers
  `/ui/ads/accounts*` — accounts, billing, and campaigns (read). This ticket consumes
  that contract; it must not redefine DTOs.
- **Transitive upstream:** AND-027 (core-network: Retrofit/OkHttp/Moshi, cookie jar,
  CSRF header, 401→refresh→retry interceptor, `ApiResult<T>`, FastAPI `detail` mapping).
- **Stack:** Kotlin 2.0.21, Coroutines/Flow, Hilt (KSP), Jetpack Compose + Material 3,
  single-Activity Navigation-Compose. minSdk 24 / compileSdk 35, JDK 17, AGP 8.7.3,
  Gradle 8.9.
- **Backend:** FastAPI + DynamoDB at dev `http://18.222.237.167:8000` (plaintext,
  unreliable). Ads endpoints are cookie-authenticated and CSRF-protected per the global
  network layer. OpenAPI at `/openapi.json`; web reference under `frontend/src/api/`.
- **Conventions:** ViewModels expose `StateFlow<UiState>`; sealed `ApiResult<T>`; FastAPI
  error `detail` is `string | [{msg}] | {code,...}` and is normalized upstream into a
  domain error type before reaching this layer.

## 3. Functional Requirements

FR-1 **Accounts list state.** `AdsAccountsViewModel` loads the advertiser accounts the
authenticated user can access (`GET /ui/ads/accounts`) on init and exposes
`AdsAccountsUiState` with explicit loading, content (non-empty list), empty (no
accounts), and error variants.

FR-2 **Manual refresh.** Each ViewModel supports a `refresh()` intent that re-fetches
without discarding the last successful content (pull-to-refresh semantics): a
`isRefreshing` flag overlays existing content rather than reverting to a full-screen
spinner.

FR-3 **Account selection.** `AdsAccountsViewModel.onAccountSelected(accountId: String)`
records the chosen account (for navigation by the UI ticket) and exposes it as part of
state; selection does not itself trigger network I/O.

FR-4 **Billing state.** `AdsBillingViewModel` takes an `accountId` (via
`SavedStateHandle` nav arg) and loads the billing summary
(`GET /ui/ads/accounts/{accountId}/billing`), exposing `AdsBillingUiState`
(loading/content/error). Content includes balance, currency, and any payment-method
summary fields provided by the AND-363 domain model.

FR-5 **Campaigns state (read-only).** `AdsCampaignsViewModel` takes an `accountId` and
loads campaigns (`GET /ui/ads/accounts/{accountId}/campaigns`), exposing
`AdsCampaignsUiState` with loading/content/empty/error. No mutate operations are in
scope.

FR-6 **Stale/offline indication.** When a refresh fails but cached content from a prior
success exists, the ViewModel keeps content visible and surfaces a non-blocking
`transientError` (one-shot, consumable) rather than replacing content with a full error.

FR-7 **Idempotent retry only.** All three loads are GETs and are idempotent; the
ViewModels rely on the network layer's bounded backoff for GETs (AND-027) and additionally
expose a user-driven `retry()` for terminal errors.

FR-8 **No leakage.** UI state exposes only `core-model` domain types and primitives — never
Retrofit `Response`, Moshi types, or `Throwable` stack traces.

## 4. Technical Design

### 4.1 Module & dependencies

`:feature-ads` depends on `:core-model`, `:core-data` (for `AdsRepository`), `:core-ui`
(for shared `UiText`/error formatting), and `:core-testing` (test-only). Hilt provides the
`AdsRepository` binding from AND-363; ViewModels are `@HiltViewModel`.

### 4.2 UiState models

```kotlin
package com.testlogon.android.feature.ads.state

import com.testlogon.android.core.model.ads.AdsAccount
import com.testlogon.android.core.model.ads.AdsBilling
import com.testlogon.android.core.model.ads.AdsCampaign
import com.testlogon.android.core.ui.error.UiText

data class AdsAccountsUiState(
    val isLoading: Boolean = false,
    val isRefreshing: Boolean = false,
    val accounts: List<AdsAccount> = emptyList(),
    val selectedAccountId: String? = null,
    val error: UiText? = null,          // terminal, full-screen error
    val transientError: UiText? = null, // one-shot snackbar; consume via onErrorShown()
) {
    val isEmpty: Boolean get() = !isLoading && error == null && accounts.isEmpty()
}

data class AdsBillingUiState(
    val isLoading: Boolean = false,
    val isRefreshing: Boolean = false,
    val billing: AdsBilling? = null,
    val error: UiText? = null,
    val transientError: UiText? = null,
)

data class AdsCampaignsUiState(
    val isLoading: Boolean = false,
    val isRefreshing: Boolean = false,
    val campaigns: List<AdsCampaign> = emptyList(),
    val error: UiText? = null,
    val transientError: UiText? = null,
) {
    val isEmpty: Boolean get() = !isLoading && error == null && campaigns.isEmpty()
}
```

`UiText` (from `core-ui`) is a sealed wrapper over either a string-resource id (+args) or a
literal string, so error text is resolved in the Composable, not in the ViewModel — keeping
ViewModels free of `Context`.

### 4.3 ViewModels

```kotlin
package com.testlogon.android.feature.ads.viewmodel

@HiltViewModel
class AdsAccountsViewModel @Inject constructor(
    private val repository: AdsRepository,
    private val errorMapper: AdsUiErrorMapper,
    @IoDispatcher private val io: CoroutineDispatcher,
) : ViewModel() {

    private val _state = MutableStateFlow(AdsAccountsUiState())
    val state: StateFlow<AdsAccountsUiState> = _state.asStateFlow()

    init { load(initial = true) }

    fun refresh() = load(initial = false)
    fun retry() = load(initial = true)

    fun onAccountSelected(accountId: String) {
        _state.update { it.copy(selectedAccountId = accountId) }
    }

    fun onErrorShown() { _state.update { it.copy(transientError = null) } }

    private fun load(initial: Boolean) {
        if (initial) _state.update { it.copy(isLoading = it.accounts.isEmpty(), error = null) }
        else _state.update { it.copy(isRefreshing = true) }
        viewModelScope.launch(io) {
            when (val r = repository.getAccounts()) {
                is ApiResult.Success ->
                    _state.update {
                        it.copy(isLoading = false, isRefreshing = false,
                                accounts = r.data, error = null)
                    }
                is ApiResult.Failure -> _state.update { reduceFailure(it, r, initial) }
            }
        }
    }

    private fun reduceFailure(
        s: AdsAccountsUiState, r: ApiResult.Failure, initial: Boolean,
    ): AdsAccountsUiState {
        val msg = errorMapper.toUiText(r.error)
        return if (s.accounts.isNotEmpty())
            s.copy(isLoading = false, isRefreshing = false, transientError = msg)
        else s.copy(isLoading = false, isRefreshing = false, error = msg)
    }
}
```

`AdsBillingViewModel` and `AdsCampaignsViewModel` follow the identical shape but read
`accountId` from `SavedStateHandle`:

```kotlin
@HiltViewModel
class AdsBillingViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val repository: AdsRepository,
    private val errorMapper: AdsUiErrorMapper,
    @IoDispatcher private val io: CoroutineDispatcher,
) : ViewModel() {
    private val accountId: String =
        requireNotNull(savedStateHandle["accountId"]) { "accountId nav arg required" }
    private val _state = MutableStateFlow(AdsBillingUiState())
    val state: StateFlow<AdsBillingUiState> = _state.asStateFlow()
    init { load(initial = true) }
    fun refresh() = load(initial = false)
    fun retry() = load(initial = true)
    fun onErrorShown() { _state.update { it.copy(transientError = null) } }
    // load() calls repository.getBilling(accountId): ApiResult<AdsBilling>
}
```

`AdsCampaignsViewModel` mirrors this against `repository.getCampaigns(accountId):
ApiResult<List<AdsCampaign>>`.

### 4.4 Repository contract (consumed, defined in AND-363)

```kotlin
interface AdsRepository {
    suspend fun getAccounts(): ApiResult<List<AdsAccount>>
    suspend fun getBilling(accountId: String): ApiResult<AdsBilling>
    suspend fun getCampaigns(accountId: String): ApiResult<List<AdsCampaign>>
}
```

If any method name differs in the merged AND-363 implementation, this ticket adapts the
ViewModel call sites; it must not change the DTOs.

### 4.5 Error mapper

```kotlin
class AdsUiErrorMapper @Inject constructor() {
    fun toUiText(error: ApiError): UiText = when (error) {
        is ApiError.Network -> UiText.Res(R.string.ads_error_offline)
        is ApiError.Timeout -> UiText.Res(R.string.ads_error_timeout)
        is ApiError.Unauthorized -> UiText.Res(R.string.ads_error_session)
        is ApiError.Http -> UiText.Res(R.string.ads_error_server, error.status)
        is ApiError.Detail -> UiText.Literal(error.message)
        else -> UiText.Res(R.string.ads_error_generic)
    }
}
```

`ApiError` is the normalized domain error from AND-027 (FastAPI `detail` already collapsed
into a single message for the `Detail` case).

## 5. API Contract

This ticket performs **no direct HTTP**; all network calls go through `AdsRepository`
(AND-363) over the shared `core-network` client (AND-027). The contract is reproduced here
only to fix the response shapes the ViewModels map into UiState. The Retrofit service,
endpoint paths, and Moshi adapters are **owned by AND-363**.

Consumed endpoints (cookie-auth, `X-CSRF-Token` echoed by interceptor):

- `GET /ui/ads/accounts`
- `GET /ui/ads/accounts/{accountId}/billing`
- `GET /ui/ads/accounts/{accountId}/campaigns`

Representative success bodies (authoritative shape lives in AND-363 DTOs):

```json
// GET /ui/ads/accounts
{ "accounts": [
  { "id": "acct_123", "name": "Acme Ads", "status": "active", "currency": "USD" }
] }
```

```json
// GET /ui/ads/accounts/acct_123/billing
{ "account_id": "acct_123", "balance_cents": 4210, "currency": "USD",
  "payment_method": { "brand": "visa", "last4": "4242" } }
```

```json
// GET /ui/ads/accounts/acct_123/campaigns
{ "campaigns": [
  { "id": "camp_1", "name": "Spring", "status": "paused", "daily_budget_cents": 1000 }
] }
```

Error bodies surface as `ApiResult.Failure(ApiError)` per the global mapping
(`detail: string | [{msg}] | {code,...}`); `401` triggers one
`POST /ui/session/refresh` + retry **inside the network layer** before a failure reaches
this ViewModel.

## 6. Data & State Management

- **Single source of truth:** one `MutableStateFlow<UiState>` per ViewModel, exposed
  read-only via `asStateFlow()`. State is updated only through `update {}` to guarantee
  atomic, copy-based transitions.
- **State survival:** ViewModels survive configuration changes via the standard
  ViewModel lifecycle; `accountId` is read from `SavedStateHandle` so process-death
  restoration of the nav arg is automatic. Loaded content is **not** persisted by this
  ticket — any disk cache is the repository's concern (AND-363/Room).
- **Refresh vs. load distinction:** first paint uses `isLoading`; subsequent fetches use
  `isRefreshing` and preserve prior `accounts`/`billing`/`campaigns`.
- **Consumable events:** `transientError` is a one-shot; the screen calls `onErrorShown()`
  after displaying a snackbar. `selectedAccountId` is plain state (navigation is the UI
  ticket's job).
- **Collection contract for UI:** screens collect with
  `collectAsStateWithLifecycle()` so flows are not collected in the background.

## 7. Error Handling & Resilience

- All repository results are sealed `ApiResult<T>`; ViewModels exhaustively `when` over
  `Success`/`Failure` — no `try/catch` around repo calls (the repo never throws for
  network errors).
- **Terminal vs. transient:** failure with no existing content → full-screen `error`
  exposing `retry()`; failure with existing content → `transientError` (content stays
  visible) per FR-6.
- **Timeouts/backoff:** the ~20s timeout and bounded backoff for idempotent GETs are
  enforced in `core-network` (AND-027); ViewModels do not implement their own retry loop,
  only a user-triggered `retry()`/`refresh()`.
- **401 handling:** transparent to this layer (refresh+retry upstream); a persistent
  `Unauthorized` maps to `ads_error_session` prompting re-auth via the UI ticket.
- **Cancellation:** loads run in `viewModelScope`; a new `refresh()` does not cancel an
  in-flight load by default — to avoid races, `load()` may be guarded by a `Job` reference
  that is cancelled before relaunch (implementation detail covered by a unit test asserting
  only the latest result wins).

## 8. Security & Privacy

- No credentials, cookies, or CSRF tokens are handled in `feature-ads`; auth rides entirely
  on the `core-network` cookie jar + CSRF interceptor.
- UiState carries only display-grade data. Billing exposes a payment-method **summary**
  (brand + last4) as provided by the backend; no PAN/full card data is requested, stored,
  or logged.
- No PII or financial figures are written to logs (see Section 10). `Throwable` details are
  never surfaced into `UiText`.
- Account/campaign identifiers are opaque server ids and are safe to hold in memory; they
  are not persisted by this ticket.

## 9. Accessibility & i18n

- All user-facing error text is `UiText.Res` backed by `strings.xml` resources
  (`ads_error_offline`, `ads_error_timeout`, `ads_error_session`, `ads_error_server`,
  `ads_error_generic`); the only literal is the server-provided `detail` message, which is
  already localized server-side or shown verbatim as a last resort.
- ViewModels expose currency as `currency` code + integer cents so the UI can format with
  the device locale (`NumberFormat.getCurrencyInstance`); no locale assumptions are baked
  into state.
- No `Context`/resource resolution occurs in the ViewModel, keeping the layer locale- and
  configuration-agnostic. Actual content-description and screen-reader work belongs to the
  downstream UI ticket; this ticket only guarantees the state contract supports it.

## 10. Telemetry & Logging

- Lightweight, structured logging via the project `Logger` (no PII/financials): log load
  start, success (with count for lists, never balances), and failure (`ApiError` category
  only — `network`/`timeout`/`http:{status}`/`detail`), tagged `feature-ads`.
- Optional analytics events (behind the app's analytics facade, if wired by M8):
  `ads_accounts_view`, `ads_billing_view`, `ads_campaigns_view`, and
  `ads_load_error{screen, category}`. These are emitted from the ViewModel on terminal
  error only; the events carry no monetary values or account names, only opaque ids.
- Logging must be assertable in unit tests via an injected `Logger` fake.

## 11. Testing Strategy

Unit tests are the primary deliverable (backlog acceptance: "Unit-tested"). Use JUnit4 +
`kotlinx-coroutines-test` (`StandardTestDispatcher` + `runTest`), Turbine for `StateFlow`
assertions, and a hand-written `FakeAdsRepository` (in `core-testing` or test source set)
returning scripted `ApiResult`. Inject the test dispatcher via the `@IoDispatcher`
qualifier.

Required cases per ViewModel:

- **Accounts:** (a) init → `isLoading=true` then `accounts` populated, `error=null`;
  (b) empty list → `isEmpty=true`; (c) failure on first load → `error` set, `retry()`
  recovers to content; (d) `refresh()` success keeps content, toggles `isRefreshing`;
  (e) `refresh()` failure with existing content → `transientError` set, content retained,
  `onErrorShown()` clears it; (f) `onAccountSelected` updates `selectedAccountId` without
  any repo call (verify via fake call count); (g) latest-wins ordering when two loads race.
- **Billing:** (a) `accountId` resolved from `SavedStateHandle`; (b) missing arg throws on
  construction; (c) success maps balance/currency/payment-method summary; (d) failure →
  error/retry; (e) refresh transient-error path.
- **Campaigns:** (a) success populates list; (b) empty → `isEmpty`; (c) failure → error;
  (d) refresh paths.
- **Error mapper:** table-driven test mapping each `ApiError` subtype to the expected
  `UiText`.

Coverage target: 100% of branches in the ViewModels and mapper. No instrumented/UI tests
in this ticket. A `MainDispatcherRule` (JUnit `TestWatcher`) sets `Dispatchers.Main` for
`viewModelScope`.

## 12. Dependencies & Sequencing

- **Hard dependency:** AND-363 (Ads accounts API) must be merged first — it supplies
  `AdsAccount`/`AdsBilling`/`AdsCampaign` domain models and the `AdsRepository` contract.
  If AND-363 is in flight, this ticket may proceed against an agreed interface stub but
  cannot land until AND-363 merges.
- **Transitive:** AND-027 (core-network: `ApiResult`, `ApiError`, cookie/CSRF, 401 refresh,
  GET backoff/timeout).
- **Blocks:** the downstream `feature-ads` UI/screens ticket (Composables, navigation,
  pull-to-refresh, snackbar host) consumes these ViewModels; not yet ticketed here, so
  `blocks: []`.
- **Within M8/E47:** sequence after AND-363; can run in parallel with other M8 state work
  since it touches only `feature-ads`.

## 13. Risks & Open Questions

- **R1 (DTO field drift):** Exact billing/campaign field names depend on AND-363's mapping
  of the FastAPI payloads. Mitigation: depend on AND-363 domain types only; verify against
  `/openapi.json` and `frontend/src/api/types.ts` before finalizing tests.
- **R2 (race semantics):** Whether `refresh()` should cancel an in-flight load. Decision:
  latest-result-wins via a tracked `Job`; covered by a test. Open to revisiting if the UI
  ticket needs strict single-flight.
- **R3 (unreliable dev host):** Frequent timeouts on `18.222.237.167:8000` make manual
  verification flaky; mitigated by the fake-repository unit tests being the gate.
- **OQ1:** Does billing return a list of payment methods or a single summary? Assumed
  single summary; adjust `AdsBilling` consumption if AND-363 models a list.
- **OQ2:** Should campaigns paginate (Paging 3)? Out of scope here (read-only flat list);
  if the backend paginates, a follow-up ticket adds `PagingData`.

## 14. Acceptance Criteria

- AC-1 `AdsAccountsViewModel`, `AdsBillingViewModel`, `AdsCampaignsViewModel` exist in
  `com.testlogon.android.feature.ads.viewmodel`, are `@HiltViewModel`, and each expose a
  single read-only `StateFlow<UiState>`.
- AC-2 Each ViewModel correctly transitions loading → content/empty/error and supports
  `refresh()`/`retry()`; refresh preserves existing content and toggles `isRefreshing`.
- AC-3 Failure with existing content yields a consumable `transientError`; failure without
  content yields a terminal `error`; `onErrorShown()` clears the transient error.
- AC-4 `onAccountSelected(id)` updates `selectedAccountId` and performs no network call.
- AC-5 Billing/Campaigns ViewModels resolve `accountId` from `SavedStateHandle` and throw
  on a missing arg.
- AC-6 `AdsUiErrorMapper` maps every `ApiError` subtype to a defined `UiText`.
- AC-7 UiState exposes only `core-model`/primitive types — no Retrofit/Moshi/`Throwable`
  leakage (enforced by review + compile-time types).
- AC-8 Unit tests cover all branches listed in Section 11 and pass deterministically under
  `StandardTestDispatcher`; the `feature-ads` module builds and its test task is green.

## 15. Definition of Done

- Code merged to `android-port` under `android/feature-ads/`, package
  `com.testlogon.android.feature.ads`, conforming to module layering
  (`feature-ads → core-*`) with no `app`/other-feature dependencies.
- All Section 14 acceptance criteria met; all Section 11 unit tests written and passing in
  CI (`:feature-ads:testDebugUnitTest`).
- ktlint/detekt clean; no new lint warnings; KSP/Hilt graph compiles.
- String resources for all error `UiText` added to `feature-ads` `strings.xml`.
- No direct HTTP, DTO, or navigation code introduced (boundaries respected vs. AND-363 and
  the downstream UI ticket).
- Spec reviewed; any DTO-field assumptions reconciled against the merged AND-363 models;
  open questions OQ1/OQ2 either resolved or explicitly deferred with a follow-up note.
- PR description links AND-369 and AND-363 and lists the covered test cases.
