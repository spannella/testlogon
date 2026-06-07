---
id: AND-369
title: Ads ViewModels
milestone: M8
epic: E47
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
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
`SavedStateHandle` nav arg) and loads the billing **history**
(`GET /ui/ads/accounts/{account_id}/billing`, optional `limit` query param, default 50),
exposing `AdsBillingUiState` (loading/content/empty/error). **[Corrected]** The backend
returns a **list** of ledger entries (`AdBillingEntry[]`), not a single balance/currency/
payment-method summary. Each entry carries `entry_id`, `account_id`, `campaign_id`,
`entry_type`, `amount_cents`, `state`, `reason`, `meta`, and `created_at`. The account's
running **balance** is `balance_cents` on the `AdAccount` (from `GET /ui/ads/accounts`),
not on the billing endpoint. There is **no `currency` field** anywhere in these models —
the web client hard-codes USD formatting (`$X.XX`); see §16. So billing content is the
entry list (and, if the UI ticket needs it, the selected account's `balance_cents`).

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
import com.testlogon.android.core.model.ads.AdsBillingEntry
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
    // [Corrected] /billing returns a LIST of ledger entries, not a single summary.
    val entries: List<AdsBillingEntry> = emptyList(),
    // Optional running balance, sourced from the selected AdAccount.balance_cents
    // (the /billing endpoint does NOT return a balance). May be null until accounts load.
    val balanceCents: Long? = null,
    val error: UiText? = null,
    val transientError: UiText? = null,
) {
    val isEmpty: Boolean get() = !isLoading && error == null && entries.isEmpty()
}

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
    // load() calls repository.getBilling(accountId): ApiResult<List<AdsBillingEntry>>
}
```

`AdsCampaignsViewModel` mirrors this against `repository.getCampaigns(accountId):
ApiResult<List<AdsCampaign>>`.

### 4.4 Repository contract (consumed, defined in AND-363)

```kotlin
interface AdsRepository {
    suspend fun getAccounts(): ApiResult<List<AdsAccount>>
    // [Corrected] /billing returns a list of ledger entries (history), not a summary.
    suspend fun getBilling(accountId: String, limit: Int = 50): ApiResult<List<AdsBillingEntry>>
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

Consumed endpoints (verified against OpenAPI index lines 784/787/789 and
`src/api/endpoints/ads.ts`). The real backend path param is **`{account_id}`**
(snake_case); auth is **Bearer token + cookies** with a **`X-CSRF-Token`** header sourced
from the `ui_csrf` cookie (web `client.ts`). Note these `/ui/*` routes also accept
`user_sub`, `X-SESSION-ID`, and `X-IMPERSONATION-TOKEN` params in the OpenAPI spec, but the
web client does not send them on these calls; they are not this layer's concern (AND-027).

- `GET /ui/ads/accounts` — op `list_my_accounts...` → returns `AdAccount[]` (bare array).
- `GET /ui/ads/accounts/{account_id}/billing` — op `billing_history_endpoint...`, optional
  `limit` query (default 50) → returns `AdBillingEntry[]` (bare array, billing **history**).
- `GET /ui/ads/accounts/{account_id}/campaigns` — op `list_campaigns_endpoint...` →
  returns `Campaign[]` (bare array).

**[Corrected]** All three responses are **bare JSON arrays**, NOT `{accounts:[…]}` /
`{campaigns:[…]}` envelopes, and there is **no `currency` field** on any model. Authoritative
shapes from `src/api/types.ts`:

```json
// GET /ui/ads/accounts  →  AdAccount[]
[ { "account_id": "acct_123", "owner_sub": "user_1", "company_name": "Acme Ads",
    "billing_email": "ops@acme.test", "status": "active",
    "balance_cents": 4210, "lifetime_spend_cents": 99000,
    "created_at": 1700000000, "updated_at": 1700000100 } ]
```

```json
// GET /ui/ads/accounts/acct_123/billing?limit=50  →  AdBillingEntry[]
[ { "entry_id": "ent_1", "account_id": "acct_123", "campaign_id": "camp_1",
    "entry_type": "impression_charge", "amount_cents": -120, "state": "settled",
    "reason": "cpm", "meta": {}, "created_at": 1700000200 } ]
```

```json
// GET /ui/ads/accounts/acct_123/campaigns  →  Campaign[]
[ { "campaign_id": "camp_1", "account_id": "acct_123", "name": "Spring",
    "objective": "traffic", "budget_cents": 50000, "budget_type": "lifetime",
    "daily_budget_cents": 1000, "spent_today_cents": 120, "lifetime_spent_cents": 8400,
    "status": "paused", "created_at": 1700000000, "updated_at": 1700000300 } ]
```

(Field names above are the FastAPI/web wire shapes; AND-363 owns the Moshi→domain mapping.
This ticket consumes whatever AND-363 names the domain types but must not assume an
envelope, a single billing summary, or a `currency` field that the backend does not send.)

Error bodies surface as `ApiResult.Failure(ApiError)` per the global mapping
(`detail: string | [{msg}] | {code,...}`, verified in `client.ts: normalizeErrorDetail`).
Validation failures on these GETs return **HTTP 422 with `HTTPValidationError`**
(`{"detail":[{"loc","msg","type"}]}`); `401` triggers one
`POST /ui/session/refresh` + a single retry **inside the network layer** (verified in
`client.ts: refreshSession`) before a failure reaches this ViewModel.

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
- UiState carries only display-grade data. **[Corrected]** The billing endpoint returns
  ledger entries (amounts/types/timestamps) — there is **no payment-method/card data**
  (no brand, no last4, no PAN) in any of the three consumed responses, so none is requested,
  stored, or logged. Monetary fields are integer cents.
- No PII or financial figures are written to logs (see Section 10). `Throwable` details are
  never surfaced into `UiText`.
- Account/campaign identifiers are opaque server ids and are safe to hold in memory; they
  are not persisted by this ticket.

## 9. Accessibility & i18n

- All user-facing error text is `UiText.Res` backed by `strings.xml` resources
  (`ads_error_offline`, `ads_error_timeout`, `ads_error_session`, `ads_error_server`,
  `ads_error_generic`); the only literal is the server-provided `detail` message, which is
  already localized server-side or shown verbatim as a last resort.
- ViewModels expose monetary amounts as integer cents. **[Corrected]** The backend provides
  **no `currency` field** on these models; the web client hard-codes USD (`$X.XX`). This
  ticket therefore exposes cents only and treats the currency as an app-level constant (USD)
  for UI formatting (`NumberFormat.getCurrencyInstance(Locale.US)`), pending a backend
  currency field (see §16 Open assumptions). No other locale assumptions are baked into state.
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
  construction; (c) success maps the **entry list** (`AdsBillingEntry[]`), empty list →
  `isEmpty=true` (no balance/currency/payment-method mapping — those fields do not exist);
  (d) failure → error/retry; (e) refresh transient-error path.
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
- **OQ1 [RESOLVED]:** Billing returns neither a payment-method list nor a single summary —
  it returns a **billing-history list** (`AdBillingEntry[]`, op `billing_history_endpoint`,
  `limit` default 50), verified against OpenAPI line 787 and `src/api/types.ts:AdBillingEntry`.
  `AdsBillingUiState` now models `entries: List<AdsBillingEntry>`; the account balance comes
  from `AdAccount.balance_cents`. No follow-up needed.
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **`GET /ui/ads/accounts` lists the user's advertiser accounts.** VERIFIED.
   OpenAPI `GET /ui/ads/accounts` (op `list_my_accounts_ui_ads_accounts_get`, index line 784);
   `src/api/endpoints/ads.ts: listMyAdAccounts`.
2. **Accounts response is a bare `AdAccount[]` array, NOT an `{accounts:[…]}` envelope.**
   CORRECTED (spec originally showed an envelope). `src/api/endpoints/ads.ts: listMyAdAccounts`
   returns `AdAccount[]`; `src/pages/ads/AdBillingPage.tsx` consumes `AdAccount[]`.
3. **`AdAccount` fields are `account_id`, `owner_sub`, `company_name`, `billing_email`,
   `status`, `balance_cents`, `lifetime_spend_cents`, `created_at`, `updated_at`.** CORRECTED
   (spec used `id`/`name`/`currency`). `src/api/types.ts: AdAccount` (lines ~5698-5708).
   There is **no `id`, no top-level `name` (it is `company_name`), and no `currency`.**
4. **`GET /ui/ads/accounts/{account_id}/campaigns` returns campaigns for an account.** VERIFIED.
   OpenAPI line 789 (op `list_campaigns_endpoint...`); `src/api/endpoints/ads.ts: listCampaigns`.
5. **Campaigns response is a bare `Campaign[]` array, NOT a `{campaigns:[…]}` envelope.**
   CORRECTED. `src/api/endpoints/ads.ts: listCampaigns` returns `Campaign[]`.
6. **`Campaign` fields include `campaign_id`, `account_id`, `name`, `objective`, `budget_cents`,
   `budget_type`, `daily_budget_cents`, `spent_today_cents`, `lifetime_spent_cents`, `status`,
   `created_at`, `updated_at`.** CORRECTED (spec used `id`). `src/api/types.ts: Campaign`
   (lines ~5710-5723). Primary key is `campaign_id`, not `id`.
7. **`GET /ui/ads/accounts/{account_id}/billing` returns a single balance/currency/
   payment-method summary.** CORRECTED — it returns a **billing-history list**
   (`AdBillingEntry[]`) with an optional `limit` query (default 50). OpenAPI line 787
   (op `billing_history_endpoint...`, param `limit`); `src/api/endpoints/ads.ts:
   getAdBillingHistory` returns `AdBillingEntry[]`; `src/pages/ads/AdBillingPage.tsx`
   names the query `["ad-billing", …]` over `entries`.
8. **`AdBillingEntry` fields: `entry_id`, `account_id`, `campaign_id`, `entry_type`,
   `amount_cents`, `state`, `reason`, `meta`, `created_at`.** VERIFIED.
   `src/api/types.ts: AdBillingEntry` (lines ~5727-5737). No `balance_cents`, no `currency`,
   no `payment_method`/`brand`/`last4` on this shape.
9. **Account balance is exposed as `balance_cents` on `AdAccount` (not on /billing).** VERIFIED.
   `src/api/types.ts: AdAccount.balance_cents`.
10. **No `currency` field exists on any of the three consumed models; the web UI hard-codes
    USD.** VERIFIED. No `currency` key in `AdAccount`/`Campaign`/`AdBillingEntry`
    (`src/api/types.ts`); `src/pages/ads/AdBillingPage.tsx: formatCents` produces `$X.XX`.
11. **Path parameter is `{account_id}` (snake_case), not `{accountId}`.** VERIFIED.
    OpenAPI lines 787/789 list `params=account_id,...`. (Kotlin code may use a camelCase
    nav-arg key; the wire path segment is unaffected since AND-363 builds the Retrofit path.)
12. **Auth/CSRF: requests carry an `Authorization: Bearer` header AND cookies; CSRF token is
    read from the `ui_csrf` cookie and sent as the `X-CSRF-Token` header.** VERIFIED with a
    nuance — spec said "cookie-authenticated"; it is **Bearer token + cookies**, not cookie-only.
    `src/api/client.ts` (Authorization at L157-160, `ui_csrf`→`X-CSRF-Token` at L168-171,
    `credentials: "include"`).
13. **A 401 triggers exactly one `POST /ui/session/refresh` + a single retry inside the
    network layer.** VERIFIED. `src/api/client.ts: refreshSession` (POST `/ui/session/refresh`,
    L121-130) and the single-flight refresh+retry block (L194-237).
14. **FastAPI error `detail` is `string | [{msg}] | {code,...}` and is normalized to one
    message.** VERIFIED. `src/api/client.ts: normalizeErrorDetail` (L66-102) and
    `mapAuthorizationError` for `{code,...}` shapes (e.g. `role_required_scope`).
15. **Validation errors on these GETs are HTTP 422 `HTTPValidationError`.** VERIFIED.
    OpenAPI lines 784/787/789 all declare `422:HTTPValidationError`. Network error (offline/
    DNS) is surfaced by the web client as status `0` (`client.ts` L185-189) — the Android
    analogue is `ApiError.Network` (AND-027).
16. **`SavedStateHandle` survives process death for nav args; ViewModels survive config
    changes.** VERIFIED (framework ref): https://developer.android.com/topic/libraries/architecture/viewmodel/viewmodel-savedstate
    and https://developer.android.com/topic/libraries/architecture/viewmodel
17. **`collectAsStateWithLifecycle()` for safe StateFlow collection in Compose.** VERIFIED
    (framework ref): https://developer.android.com/topic/architecture/ui-layer/state-production#state-flow-compose
18. **`@HiltViewModel` + KSP for ViewModel injection.** VERIFIED (framework ref):
    https://developer.android.com/training/dependency-injection/hilt-jetpack
19. **`StandardTestDispatcher` + `runTest` + `MainDispatcherRule` for deterministic VM tests;
    Turbine for StateFlow.** VERIFIED (framework refs):
    https://developer.android.com/kotlin/coroutines/test and
    https://github.com/cashapp/turbine
20. **Bearer 401 refresh/backoff/timeout live in `core-network` (AND-027), not this layer.**
    UNVERIFIED-ASSUMPTION at the Android level — AND-027 source is not in the provided
    reference tree. The behavior is consistent with the web `client.ts` model (single refresh,
    network status `0`), but the exact Kotlin `ApiError` taxonomy and backoff are taken on
    faith from AND-027.

### Corrections made

- **C1 (response envelopes):** Accounts and campaigns return **bare arrays**, not
  `{accounts:[…]}`/`{campaigns:[…]}`. Fixed §5 JSON examples (claims 2, 5).
- **C2 (account fields):** `AdAccount` uses `account_id`/`company_name`/`balance_cents` and
  has **no `id`/`name`/`currency`**. Fixed §5 (claim 3).
- **C3 (campaign fields):** primary key is `campaign_id`, not `id`. Fixed §5 (claim 6).
- **C4 (billing shape — the big one):** `/billing` is a **history list** (`AdBillingEntry[]`,
  `limit` default 50), not a single balance/currency/payment-method summary. Rewrote FR-4,
  `AdsBillingUiState` (now `entries`/`balanceCents`), the repository `getBilling` signature,
  §5 example, §11 billing test case (c), and resolved OQ1 (claims 7, 8).
- **C5 (no payment-method PII):** removed the brand/last4 payment-method-summary claim from
  §8 — that data is not in any consumed response (claim 8).
- **C6 (no currency):** removed `currency`-code claims from §9 and elsewhere; amounts are
  integer cents, USD assumed app-side (claim 10).
- **C7 (auth nuance):** §5 now states Bearer token + cookies + `X-CSRF-Token` from `ui_csrf`,
  rather than "cookie-authenticated" only (claim 12).
- **C8 (path param):** noted the real wire param is `{account_id}` (claim 11).

### Open assumptions

- **OA1 (AND-027 internals):** The Android `ApiResult`/`ApiError` taxonomy, GET backoff, ~20s
  timeout, and 401-refresh-retry are assumed from AND-027; that module's source is **not** in
  the reference tree. Web `client.ts` corroborates the single-refresh + network-status-0 model
  but not the exact Kotlin types. (Claim 20.)
- **OA2 (AND-363 domain mapping):** The exact Kotlin domain type names
  (`AdsAccount`/`AdsBillingEntry`/`AdsCampaign`) and the Moshi field mapping are owned by
  AND-363 and assumed; this spec verified the **wire shapes** only. If AND-363 names types
  differently, adapt call sites (not DTOs).
- **OA3 (currency):** No backend currency field exists today; USD is assumed app-side. If the
  backend later adds a `currency`, billing/account state must surface it.
- **OA4 (campaigns pagination):** OQ2 — the campaigns endpoint exposes no pagination params in
  OpenAPI (line 789 has only `account_id` + auth params), so the flat-list assumption holds
  for now; revisit if the backend adds cursors.
- **OA5 (`limit` exposure):** Whether the UI needs to vary the billing `limit` (default 50) is
  unconfirmed; this spec defaults it and leaves tuning to the UI ticket.

## 17. Test Plan

All cases are JVM/Robolectric unit tests on the **JVM unit** target unless noted — this
ticket is a pure state layer with no UI, no device dependency, and no real network. The
unreliable dev host is never contacted; `FakeAdsRepository` returns scripted `ApiResult`.
Tools: JUnit4, `kotlinx-coroutines-test` (`StandardTestDispatcher` + `runTest`),
`MainDispatcherRule`, Turbine.

- **TC-AND-369-01** — Type: unit (JVM). Target: `AdsAccountsViewModel`.
  Preconditions: `FakeAdsRepository.getAccounts` scripted to return
  `ApiResult.Success(listOf(account))`. Steps: construct VM (triggers `init` load); advance
  dispatcher; collect `state`. Expected: emits `isLoading=true` (first paint) then
  `accounts=[account]`, `isLoading=false`, `error=null`, `isEmpty=false`.
  Traces: AC-1, AC-2.
- **TC-AND-369-02** — Type: unit (JVM). Target: `AdsAccountsViewModel`.
  Preconditions: `getAccounts` → `Success(emptyList())`. Steps: construct; advance.
  Expected: `accounts=[]`, `isLoading=false`, `error=null`, `isEmpty=true`.
  Traces: AC-2.
- **TC-AND-369-03** — Type: unit (JVM). Target: `AdsAccountsViewModel`.
  Preconditions: `getAccounts` → `Failure(ApiError.Network)` on first call, then
  `Success(listOf(account))` on the second. Steps: construct; advance → assert terminal
  `error` set, `accounts=[]`; call `retry()`; advance. Expected: after retry, `error=null`,
  `accounts=[account]`. (Flaky-host/offline path simulated via `ApiError.Network`.)
  Traces: AC-2, AC-6.
- **TC-AND-369-04** — Type: unit (JVM). Target: `AdsAccountsViewModel`.
  Preconditions: first load `Success(listOf(a))`; refresh load `Success(listOf(a,b))`.
  Steps: construct; advance; call `refresh()`; assert `isRefreshing=true` mid-flight (content
  retained); advance. Expected: during refresh `accounts` still `[a]` and `isRefreshing=true`;
  after, `accounts=[a,b]`, `isRefreshing=false`, `isLoading` never re-toggles to a full spinner.
  Traces: AC-2.
- **TC-AND-369-05** — Type: unit (JVM). Target: `AdsAccountsViewModel`.
  Preconditions: first load `Success(listOf(a))`; refresh `Failure(ApiError.Timeout)`.
  Steps: construct; advance; `refresh()`; advance; then call `onErrorShown()`.
  Expected: after failed refresh, `accounts=[a]` retained, `transientError != null`,
  `error == null`; after `onErrorShown()`, `transientError == null`.
  (Offline/flaky-host transient path.) Traces: AC-3.
- **TC-AND-369-06** — Type: unit (JVM). Target: `AdsAccountsViewModel`.
  Preconditions: any loaded state; `FakeAdsRepository` records call counts.
  Steps: call `onAccountSelected("acct_123")`. Expected: `selectedAccountId == "acct_123"`
  and `FakeAdsRepository` network call count is **unchanged** (no fetch).
  Traces: AC-4.
- **TC-AND-369-07** — Type: unit (JVM). Target: `AdsAccountsViewModel` (concurrency).
  Preconditions: two loads race — slow first (`Success(stale)`), fast second
  (`Success(fresh)`) via controlled dispatcher ordering. Steps: trigger `refresh()` twice;
  control completion order so the stale result resolves last. Expected: final `accounts`
  reflect the **latest-issued** load (fresh), proving latest-wins (job cancellation/guard).
  Traces: AC-2.
- **TC-AND-369-08** — Type: unit (JVM). Target: `AdsBillingViewModel`.
  Preconditions: `SavedStateHandle` seeded with `accountId="acct_123"`; `getBilling` →
  `Success(listOf(entry))`. Steps: construct; advance. Expected: `entries=[entry]`,
  `isLoading=false`, `error=null`; the fake received `accountId="acct_123"` and default
  `limit=50`. Traces: AC-5, AC-2.
- **TC-AND-369-09** — Type: unit (JVM). Target: `AdsBillingViewModel`.
  Preconditions: `SavedStateHandle` **missing** `accountId`. Steps: attempt construction.
  Expected: constructor throws `IllegalArgumentException` ("accountId nav arg required")
  via `requireNotNull`. Traces: AC-5.
- **TC-AND-369-10** — Type: unit (JVM). Target: `AdsBillingViewModel`.
  Preconditions: `getBilling` → `Success(emptyList())` then (on refresh)
  `Failure(ApiError.Http(500))`. Steps: construct; advance (assert `isEmpty=true`);
  `refresh()`; advance. Expected: empty state first; after failed refresh with no prior
  content, terminal `error` set (no content to retain). Traces: AC-2, AC-3.
- **TC-AND-369-11** — Type: unit (JVM). Target: `AdsCampaignsViewModel`.
  Preconditions: `SavedStateHandle` `accountId="acct_123"`; `getCampaigns` →
  `Success(listOf(c1,c2))`. Steps: construct; advance. Expected: `campaigns=[c1,c2]`,
  `isLoading=false`, `isEmpty=false`. Traces: AC-2, AC-5.
- **TC-AND-369-12** — Type: unit (JVM). Target: `AdsCampaignsViewModel`.
  Preconditions: `getCampaigns` → `Success(emptyList())`; then `Failure(ApiError.Network)`
  on `retry()` is not used here — instead first `Failure(ApiError.Unauthorized)`.
  Steps: script `getCampaigns` → `Failure(ApiError.Unauthorized)`; construct; advance.
  Expected: terminal `error` mapped to the session message; `campaigns=[]`. (Persistent-401
  path that survived upstream refresh.) Traces: AC-2, AC-6.
- **TC-AND-369-13** — Type: unit (JVM). Target: `AdsUiErrorMapper`.
  Preconditions: none. Steps: table-driven — map each `ApiError` subtype
  (`Network`, `Timeout`, `Unauthorized`, `Http(503)`, `Detail("server says no")`, and an
  unknown/`else`). Expected: each maps to the documented `UiText` —
  `ads_error_offline`, `ads_error_timeout`, `ads_error_session`, `ads_error_server` (with the
  status arg), `UiText.Literal("server says no")`, `ads_error_generic` respectively.
  Traces: AC-6.
- **TC-AND-369-14** — Type: unit (JVM). Target: ViewModels (no-leakage / logging).
  Preconditions: injected `Logger` fake; load success + load failure. Steps: drive a success
  and a failure; inspect (a) the public `state` type and (b) logged records. Expected: every
  field reachable from `state` is a `core-model`/primitive/`UiText` type — **no** Retrofit
  `Response`, Moshi, or `Throwable` is exposed; logs contain only the `ApiError` category
  (`network`/`timeout`/`http:{status}`/`detail`) and list counts, **never** balances, account
  names, or stack traces. Traces: AC-7.

(No instrumented/Compose-UI/e2e cases: this ticket ships no UI and no device-dependent code,
so neither the `test35` emulator nor the physical Galaxy A15 is required. Accessibility/i18n
is asserted indirectly — TC-14 confirms state carries cents + `UiText.Res` keys so the
downstream UI ticket can localize; there is no UI here to run TalkBack against. Security is
covered by TC-06 (no I/O on selection) and TC-14 (no PII/financials leaked or logged).)

### Coverage matrix

| Acceptance criterion | Covered by |
|---|---|
| AC-1 (VMs exist, `@HiltViewModel`, single `StateFlow`) | TC-01 |
| AC-2 (loading→content/empty/error; refresh/retry; isRefreshing) | TC-01, TC-02, TC-03, TC-04, TC-07, TC-08, TC-10, TC-11, TC-12 |
| AC-3 (transient vs terminal error; `onErrorShown`) | TC-05, TC-10 |
| AC-4 (`onAccountSelected` no network) | TC-06 |
| AC-5 (`accountId` from `SavedStateHandle`; throws if missing) | TC-08, TC-09, TC-11 |
| AC-6 (`AdsUiErrorMapper` covers every `ApiError`) | TC-03, TC-12, TC-13 |
| AC-7 (no Retrofit/Moshi/`Throwable` leakage) | TC-14 |
| AC-8 (all §11 branches pass deterministically) | TC-01 … TC-14 (all) |
