---
id: AND-367
title: Ad billing / deposit
milestone: M8
epic: E47
priority: P2
size: M
status: draft
depends_on: [AND-363, AND-031]
blocks: []
---

# AND-367 — Ad billing / deposit

## 1. Overview & Goal

Deliver the **ads account billing + deposit** surface for the TestLogon native Android app: a
read view of an advertiser account's billing/spend summary (balance, current spend, credit limit,
payment status, billing period, and the embedded invoice references) plus the ability to **add
funds (deposit)** to that account. This is the first *mutating* ads feature in epic E47 — every
ticket before it (AND-363 and its consumers) is read-only.

Scope, verbatim from the backlog: *account billing + deposit (read + deposit)*. The single backlog
acceptance criterion is: *Deposit + invoices render.* This ticket therefore owns (a) a
`feature-ads-billing` module that renders the billing summary and the account's invoice list from
the `AdsBillingDto` payload produced by **AND-363**, (b) a deposit flow that POSTs a funding request
to `/ui/ads/accounts/{id}/billing/deposit` and reflects the new balance, and (c) the
repository/ViewModel/Compose/test stack to make both render reliably against the unreliable plaintext
dev backend (offline/stale reads, bounded retry for the GET, no auto-retry for the deposit POST).

Success means: given a valid session and an `accountId`, the billing screen renders the spend
summary and invoice references; tapping "Add funds", entering an amount, and confirming issues a
CSRF-protected deposit POST that, on success, updates the displayed balance and shows confirmation;
failures surface actionable, non-duplicating error states.

## 2. Context & References

- Repo: `spannella/testlogon`, branch `android-port`, Android app under `android/` (monorepo).
- Namespace / `applicationId` base: `com.testlogon.android`. This feature module:
  `com.testlogon.android.feature.adsbilling`.
- Stack: Kotlin 2.0.21, Compose + Material 3, single-Activity Navigation-Compose, Hilt (KSP),
  Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Room 2.6 (cache) + DataStore (prefs),
  Coil. minSdk 24, compile/target 35, JDK 17, Gradle 8.9, AGP 8.7.3.
- Module layering: `app -> feature-ads-billing -> core-network, core-model, core-data, core-ui,
  core-testing`. ViewModels expose `StateFlow<UiState<…>>`; typed `ApiResult<T>`; FastAPI `detail`
  error mapping (`string | [{msg}] | {code,...}`) via the shared core-network mapper (AND-015).
- Web reference (authoritative for wire names/paths): `frontend/src/api/endpoints/ads.ts` for the
  `/ui/ads/accounts*/billing` and deposit operations; shared types in `frontend/src/api/types.ts`
  (`AdsBilling`, `AdsInvoiceRef`, money types). Backend OpenAPI: `/openapi.json` on
  `http://18.222.237.167:8000` (PLAINTEXT HTTP dev host, unreliable). Mirror snake_case wire keys
  exactly; do not invent camelCase keys.
- Auth: cookie-based session. Persistent cookie jar (AND-011) + `ui_csrf` cookie echoed as the
  `X-CSRF-Token` header (AND-012); on `401` the network layer performs `POST /ui/session/refresh`
  once then retries (AND-013). All consumed here; not re-implemented.

### Upstream dependencies (from backlog)

- **AND-363 (Ads accounts API)** — provides `AdsAccountsApi`, the `core-model.ads` DTOs
  (`AdsBillingDto`, `MoneyDto`, `AdsInvoiceRefDto`, `AdsAccountDetailDto`), and `getAdsAccountBilling`.
  This ticket consumes that billing-read surface and **extends** it with the deposit POST.
- **AND-031 (LoginViewModel)** — establishes the authenticated session and the `StateFlow<UiState>`
  ViewModel pattern (submit handler, loading/disabled handling, result→navigation/error mapping)
  that the deposit ViewModel mirrors. A valid session is a precondition for all `/ui/ads/*` calls.

## 3. Functional Requirements

FR-1. **Billing summary (read).** For a given `accountId`, render the `AdsBillingDto`: account
currency, balance, current spend, credit limit, payment status badge (`paid` / `past_due` / …),
masked payment method, and billing period (`period_start`–`period_end`). All monetary values use
`MoneyDto` (minor-unit integer + ISO-4217 code); if the backend supplies a `display` string, prefer
it, otherwise format from minor units + currency.

FR-2. **Invoices render.** Render the `invoices: List<AdsInvoiceRefDto>` embedded in the billing
payload as a list — each row shows invoice id, amount, status, and issue date. Empty list →
"No invoices yet". (Full invoice detail/PDF is out of scope; see §13 Q-2.)

FR-3. **Deposit (mutating).** A primary "Add funds" action opens a deposit sheet where the user
enters an amount (in the account currency) and confirms. On confirm, issue
`POST /ui/ads/accounts/{id}/billing/deposit` with `{ "amount_minor": <Long>, "currency": "<code>" }`,
cookies, and `X-CSRF-Token`. On `200`, update the displayed balance/current spend from the response
and show a success confirmation.

FR-4. **Amount validation.** The deposit amount must be > 0 and within an optional
backend-advertised min/max (if `/openapi.json` exposes them; otherwise client min = 1 minor unit).
Input is parsed locale-aware into minor units; the confirm button is disabled for empty/invalid/zero
amounts and while a deposit is in flight.

FR-5. **In-flight & duplicate protection.** The confirm button is disabled and shows a spinner while
the POST is in flight; a debounce + in-flight guard prevents duplicate deposits from a double-tap.

FR-6. **States.** The billing screen renders distinct loading, success (with `isStale` flag),
error (retryable), and offline/stale states per the core-ui state contract (AND-021). The deposit
sub-flow has its own `Idle | Submitting | Success | Error` state so it never clobbers the read state.

FR-7. **Offline & stale.** On network failure/timeout with a populated cache, render the cached
billing summary + invoices with a "Showing saved data" stale badge; the "Add funds" action is
disabled while offline. With an empty cache, show a retryable error.

FR-8. **Refresh.** Pull-to-refresh re-fetches the billing summary and revalidates the cache; a
successful deposit also triggers a silent re-fetch so balance/spend reflect server truth.

## 4. Technical Design

New module `feature-ads-billing`, package root `com.testlogon.android.feature.adsbilling`.

### Networking (extends AND-363)

The billing **GET** is already on `AdsAccountsApi` (AND-363). This ticket adds the deposit **POST**.
To avoid touching `core-network` for a feature-specific mutation, the POST lives on a small
extension interface provided from the shared `Retrofit`:

```kotlin
package com.testlogon.android.core.network.ads

interface AdsBillingApi {
    @GET("ui/ads/accounts/{id}/billing")
    suspend fun getBilling(@Path("id") accountId: String): AdsBillingDto   // shared w/ AND-363

    @POST("ui/ads/accounts/{id}/billing/deposit")
    suspend fun deposit(
        @Path("id") accountId: String,
        @Body body: AdsDepositRequestDto,
    ): AdsDepositResultDto
}
```

The cookie jar + `X-CSRF-Token` header are injected by the shared OkHttp interceptors; the deposit
POST is mutating and depends on CSRF. The GET is idempotent and uses the shared bounded-backoff retry
(AND-016); the deposit POST is **never** auto-retried.

### Repository (`core-data` boundary, lives in feature module)

```kotlin
class AdsBillingRepository @Inject constructor(
    private val api: AdsBillingApi,
    private val dao: AdsBillingDao,
    private val mapper: AdsBillingMapper,
    private val connectivity: ConnectivityObserver,
    @IoDispatcher private val io: CoroutineDispatcher,
) {
    fun observeBilling(accountId: String): Flow<AdsBilling?>          // Room-backed
    suspend fun refreshBilling(accountId: String): ApiResult<AdsBilling>
    suspend fun deposit(accountId: String, amountMinor: Long, currency: String): ApiResult<AdsDepositResult>
}
```

`refreshBilling` follows stale-while-revalidate: emit cache immediately via `observeBilling`, fetch,
upsert to Room, stamp `last_sync`. `deposit` maps DTO→domain and, on success, upserts the returned
balance so the UI updates without a round-trip (then FR-8 re-fetch confirms).

### ViewModel (mirrors AND-031 pattern)

```kotlin
@HiltViewModel
class AdsBillingViewModel @Inject constructor(
    private val repo: AdsBillingRepository,
    savedState: SavedStateHandle,
) : ViewModel() {
    private val accountId: String = checkNotNull(savedState["accountId"])

    val uiState: StateFlow<UiState<AdsBilling>>          // Loading | Success(data,isStale) | Empty | Error
    val depositState: StateFlow<DepositUiState>          // Idle | Submitting | Success(newBalance) | Error(msg)
    val canDeposit: StateFlow<Boolean>                   // online && amount valid && !submitting

    fun onAmountChanged(raw: String)                     // locale-parse → minorUnits, validate
    fun onDepositConfirmed()                             // debounced + in-flight guarded
    fun dismissDepositResult()
    fun retry()
    fun refresh()
}

sealed interface DepositUiState {
    data object Idle : DepositUiState
    data object Submitting : DepositUiState
    data class Success(val newBalance: Money) : DepositUiState
    data class Error(val message: String, val code: String?) : DepositUiState
}
```

`UiState<T>` is the shared core-ui sealed type (`Loading`, `Success(data, isStale)`, `Empty`,
`Error(message, retryable)`). State is collected via `collectAsStateWithLifecycle`.

### UI (Compose)

- `AdsBillingScreen(onBack: () -> Unit)` — `Scaffold` + `TopAppBar(back)`, `PullToRefreshBox`,
  a `BillingSummaryCard` (balance, current spend, credit limit, payment-status badge, period),
  an `InvoicesSection` (`LazyColumn` of `AdsInvoiceRow`), and a primary `Button("Add funds")`.
- `DepositBottomSheet(state, onAmountChange, onConfirm, onDismiss)` — `ModalBottomSheet` with a
  currency-prefixed amount field, inline validation error, and a confirm `Button` disabled per
  `canDeposit` with an inline progress indicator while `Submitting`. Result shown via snackbar /
  inline confirmation, then `dismissDepositResult()`.
- State composables from core-ui (AND-021): `LoadingState`, `ErrorState(onRetry)`, `OfflineState`.

### Navigation

```kotlin
const val ADS_BILLING_ROUTE = "ads/accounts/{accountId}/billing"

fun NavGraphBuilder.adsBillingGraph(nav: NavController) {
    composable(
        ADS_BILLING_ROUTE,
        arguments = listOf(navArgument("accountId") { type = NavType.StringType }),
    ) { AdsBillingScreen(onBack = { nav.popBackStack() }) }
}
```

Hilt `AdsBillingModule` provides `AdsBillingApi` from the shared `Retrofit` and binds
`AdsBillingRepository`/`AdsBillingMapper`. The route is registered in the app nav host and reached
from the ads-account detail screen (downstream consumer of AND-363).

## 5. API Contract

All paths relative to base `http://18.222.237.167:8000`; confirm field names against `/openapi.json`
and `frontend/src/api/endpoints/ads.ts` at implementation time and align Moshi `@Json(name=…)`.

**GET `/ui/ads/accounts/{id}/billing`** → `200` (shape from AND-363 `AdsBillingDto`):

```json
{
  "account_id": "ad_acct_88",
  "currency": "USD",
  "balance": { "amount_minor": 125000, "currency": "USD", "display": "$1,250.00" },
  "current_spend": { "amount_minor": 43200, "currency": "USD", "display": "$432.00" },
  "credit_limit": { "amount_minor": 500000, "currency": "USD", "display": "$5,000.00" },
  "payment_status": "paid",
  "payment_method": "visa ****4242",
  "period_start": "2026-05-01T00:00:00Z",
  "period_end": "2026-05-31T23:59:59Z",
  "invoices": [
    { "id": "in_ad_5001", "amount": { "amount_minor": 43200, "currency": "USD" },
      "status": "paid", "issued_at": "2026-05-31T12:00:00Z" }
  ]
}
```

**POST `/ui/ads/accounts/{id}/billing/deposit`** (headers: `X-CSRF-Token: <ui_csrf>`, cookies)
request:

```json
{ "amount_minor": 50000, "currency": "USD" }
```

→ `200` (shape confirmed against `/openapi.json`, Q-1):

```json
{
  "ok": true,
  "account_id": "ad_acct_88",
  "balance": { "amount_minor": 175000, "currency": "USD", "display": "$1,750.00" },
  "transaction_id": "txn_ad_9012"
}
```

DTOs (new in this ticket; `MoneyDto`/`AdsBillingDto`/`AdsInvoiceRefDto` reused from AND-363
`core-model.ads`):

```kotlin
@JsonClass(generateAdapter = true)
data class AdsDepositRequestDto(
    @Json(name = "amount_minor") val amountMinor: Long,
    val currency: String,
)

@JsonClass(generateAdapter = true)
data class AdsDepositResultDto(
    val ok: Boolean = true,
    @Json(name = "account_id") val accountId: String? = null,
    val balance: MoneyDto? = null,
    @Json(name = "transaction_id") val transactionId: String? = null,
)
```

Monetary amounts are integer minor units; never use floats. Errors follow FastAPI `detail`
(`string | [{msg}] | {code,...}`) mapped by AND-015 into `ApiResult.Error(message, code)`. Notable
statuses: `400`/`422` (invalid amount / currency mismatch → field error, non-retryable), `401`
(single refresh+retry in the interceptor), `402`/`409` (payment declined / insufficient — surfaced
verbatim from `detail`), `404` (account not found → read Error, non-retryable), `429`/`5xx`
(transient → GET retried; deposit shows manual-retry guidance).

## 6. Data & State Management

Room caches the billing read so the screen survives the unreliable backend:

```kotlin
@Entity(tableName = "ads_billing")
data class AdsBillingEntity(
    @PrimaryKey val accountId: String,
    val currency: String,
    val balanceMinor: Long?, val balanceDisplay: String?,
    val currentSpendMinor: Long?, val creditLimitMinor: Long?,
    val paymentStatus: String?, val paymentMethod: String?,
    val periodStart: String?, val periodEnd: String?,
    val invoicesJson: String,   // serialized List<AdsInvoiceRefDto> (Moshi TypeConverter)
    val cachedAt: Long,
)
```

`AdsBillingDao` exposes `observe(accountId)`, `upsert(entity)`, `clear(accountId)`. Last-sync per
account lives in DataStore (`ads_billing_last_sync_<accountId>`); `isStale = now - lastSync > 5m`
drives the stale badge. Domain models in `core-model`: `AdsBilling`, `Money`, `AdsInvoiceRef`,
`PaymentStatus` (enum with `UNKNOWN` fallback), `AdsDepositResult`. `AdsBillingMapper` converts
DTO ↔ entity ↔ domain; ISO-8601 strings parsed at the mapper boundary, money kept as
`{ amountMinor: Long, currency: String, display: String? }` losslessly.

Read state is `StateFlow<UiState<AdsBilling>>`; the deposit flow uses the separate
`DepositUiState` so a deposit error never overwrites the rendered summary. Amount-entry state
(raw string, parsed minor units, validation message) is held in the ViewModel and survives config
changes via `SavedStateHandle`.

## 7. Error Handling & Resilience

- **Timeouts:** shared OkHttp call/connect/read ≈ 20s; spinners always interruptible.
- **Retry:** the billing GET uses shared bounded exponential backoff w/ jitter (≈3 attempts) for
  transient (`5xx`, timeout, connection) errors (AND-016). The **deposit POST is never auto-retried**
  — the user re-confirms manually; this prevents double funding.
- **401:** handled centrally — one `POST /ui/session/refresh` then retry; a second `401` surfaces a
  re-auth error routed to the auth flow.
- **Offline / stale:** read failure with non-empty cache → cached summary + stale badge; empty cache
  → `Error(retryable=true)`. "Add funds" disabled while offline (connectivity via core-data) and
  re-enabled on reconnect.
- **Deposit failures:** `400`/`422` map to an inline field error under the amount input; `402`/`409`
  (declined/insufficient/limit) map to a `DepositUiState.Error` with the server `detail` message and
  a retry affordance; the sheet stays open with the entered amount preserved.
- **Duplicate-send protection:** in-flight guard + ~1s debounce on `onDepositConfirmed()`; confirm
  button disabled for the entire request lifecycle. On unknown/timeout outcome the user is advised to
  refresh and check balance before retrying (deposit is not idempotent).
- **404 on read:** non-retryable Error with "Ads account not found" and a back affordance.

## 8. Security & Privacy

- All requests carry session cookies via the persistent jar (AND-011); the mutating deposit POST
  includes `X-CSRF-Token` from the `ui_csrf` cookie (AND-012) — verified present in tests.
- No card numbers, tokens, or PANs are handled client-side: `payment_method` arrives **already
  masked** by the backend and is rendered verbatim; the deposit body carries only an amount +
  currency, never raw payment credentials.
- The Room cache holds only billing metadata already authorized for this session; clear the
  `ads_billing` cache for the account on logout (hook the session-clear broadcast from the auth
  module).
- Dev backend is plaintext HTTP; cleartext is permitted **only** for the dev host via the
  network-security-config owned by core-network. Release logging redacts amounts, balances,
  `payment_method`, and `transaction_id` (see §10).
- Amount is server-validated; the client validates defensively but the backend is authoritative for
  limits, currency match, and funding eligibility.

## 9. Accessibility & i18n

- All strings in `feature-ads-billing/src/main/res/values/strings.xml`; no hardcoded UI text.
- Money/dates formatted via `NumberFormat.getCurrencyInstance(locale)` and locale-aware
  `DateTimeFormatter`; never string-concatenate currency symbols. The amount input uses a
  locale-aware decimal parser and the account currency's symbol/grouping.
- Payment-status and invoice-status badges expose `contentDescription` (e.g., "Payment status:
  past due"). The deposit result is announced via a snackbar/live region.
- Touch targets ≥48dp; the amount field has an associated label and error text exposed to TalkBack;
  the confirm button announces its disabled/loading state. Logical focus order:
  summary → invoices → "Add funds" → sheet (amount → confirm).
- Dynamic type respected (Material 3 typography, no fixed `sp` overrides); light/dark from core-ui;
  RTL-safe layouts (amount prefix mirrors correctly).

## 10. Telemetry & Logging

- Analytics via core-data telemetry sink: `ads_billing_viewed { account_id }`,
  `ads_billing_load_error { account_id, code }`, `ads_deposit_opened { account_id }`,
  `ads_deposit_submitted { account_id }` (no amount), `ads_deposit_succeeded { account_id }`,
  `ads_deposit_failed { account_id, code }`.
- Logging via Timber; release builds **redact** `amount_minor`, balances, `payment_method`, and
  `transaction_id`. Network failures logged at WARN with endpoint + HTTP status + error `code` only
  (no request/response bodies).
- No amounts or transaction ids sent to crash reporting; only opaque `account_id` and error codes.

## 11. Testing Strategy

- **Unit (core-testing + JUnit5 + Turbine + MockWebServer):**
  - `AdsBillingMapperTest` — `AdsBillingDto`→entity→domain mapping; `MoneyDto` lossless minor-unit
    handling; null optionals; unknown `payment_status` → `PaymentStatus.UNKNOWN`; invoices list
    round-trips through the JSON column.
  - `AdsBillingRepositoryTest` — MockWebServer success, `404`, `5xx`→retry, offline→cached+stale;
    `deposit` success updates cached balance; `deposit` failure (`402`/`422`) maps to `ApiResult.Error`
    with `detail` message; asserts **`X-CSRF-Token` present on POST** and **no auto-retry on POST**.
  - `AdsBillingViewModelTest` — `uiState` transitions; `depositState` Idle→Submitting→Success /
    →Error; `canDeposit` gating (online + valid amount + not submitting); amount parse/validation
    (zero, negative, non-numeric, > limit); debounce/in-flight guard prevents a duplicate POST on
    double-tap.
- **Instrumented/Compose (`createAndroidComposeRule`):** summary card + invoices render from a
  fixture; empty-invoices state; "Add funds" opens the sheet; confirm disabled until a valid amount;
  confirm shows progress then success confirmation and updated balance; error snackbar with retry;
  offline state disables "Add funds".
- **Contract:** golden JSON fixtures derived from `/openapi.json` and `ads.ts` guard against drift.
- Acceptance gate: "Deposit + invoices render" → Compose tests for the summary/invoices and the
  deposit happy path are green, plus repository/ViewModel deposit tests.

## 12. Dependencies & Sequencing

- **Depends on AND-363 (Ads accounts API)** — must merge first; provides `AdsAccountsApi`,
  `getAdsAccountBilling`, and the `core-model.ads` DTOs (`AdsBillingDto`, `MoneyDto`,
  `AdsInvoiceRefDto`) this ticket renders. The deposit POST DTOs (`AdsDepositRequestDto`,
  `AdsDepositResultDto`) and the `AdsBillingApi.deposit` method are added here (extending the AND-363
  network surface).
- **Depends on AND-031 (LoginViewModel)** — a valid authenticated session is required for all
  `/ui/ads/*` calls, and the deposit ViewModel mirrors AND-031's `StateFlow<UiState>` + submit-handler
  pattern (loading/disabled handling, result→nav/error mapping).
- Transitively depends on the core-network cookie/CSRF/refresh/retry stack (AND-011/012/013/016),
  `ApiResult<T>` (AND-018), `detail` error mapping (AND-015), core-ui state composables (AND-021),
  and the Navigation host in `app` (AND-022).
- Sequencing: AND-363 lands → this ticket lands `feature-ads-billing` and registers
  `adsBillingGraph`, reached from the ads-account detail screen. No tickets currently block on AND-367.

## 13. Risks & Open Questions

- Q-1: Exact deposit endpoint path, request keys (`amount_minor` vs `amount`), and the success
  response shape (does it return the new `balance` and a `transaction_id`?) are unconfirmed — verify
  against `/openapi.json` and `ads.ts`; adjust `AdsDepositRequestDto`/`AdsDepositResultDto`.
- Q-2: Whether invoice references are detail-linkable (PDF/detail screen) or display-only. This
  ticket treats them as display-only rows; deep linking to AND-243-style invoice detail is a
  follow-up if the ads invoice id maps to `/ui/invoices/{n}`.
- Q-3: Does the backend advertise min/max deposit amounts or a closed set of fundable currencies? If
  so, model and enforce them; otherwise client uses min = 1 minor unit and the account currency.
- Q-4: Idempotency of the deposit POST — if the backend accepts an idempotency key, send one to make
  retries safe; until confirmed, the client does **not** auto-retry (R: double-funding).
- Q-5: Does deposit require a pre-attached payment method (returning `402`/redirect) rather than
  funding from balance/credit? If a redirect/SCA step is needed, that is an out-of-scope follow-up.
- R-1: Unreliable dev host may flake instrumented tests — mock the network in CI; reserve live runs
  for manual verification.

## 14. Acceptance Criteria

- AC-1 (Invoices render): Given a valid session and `accountId`, the billing screen renders the spend
  summary (balance, current spend, credit limit, payment status, period) and the embedded invoice
  references (id, amount, status, date); an empty list shows "No invoices yet".
- AC-2 (Deposit renders + happy path): "Add funds" opens the deposit sheet; entering a valid amount
  enables confirm; confirm issues `POST /ui/ads/accounts/{id}/billing/deposit` with cookies +
  `X-CSRF-Token`, shows progress, and on `200` shows success and the updated balance.
- AC-3 (Validation): Confirm is disabled for empty/zero/negative/non-numeric amounts and (if known)
  amounts outside backend min/max; invalid input shows an inline field error.
- AC-4 (Duplicate protection): A double-tap on confirm issues exactly one POST (debounce/in-flight
  guard verified); the deposit POST is never auto-retried.
- AC-5 (Deposit failure): A non-2xx deposit response (`402`/`409`/`422`) shows the server `detail`
  message with retry, keeps the sheet open with the entered amount, and does not corrupt the summary.
- AC-6 (Resilience): With no network and a populated cache, the screen renders cached billing +
  invoices with a stale indicator and "Add funds" disabled; with an empty cache it shows a retryable
  error.
- AC-7 (Auth): A `401` triggers exactly one `POST /ui/session/refresh` + retry before surfacing a
  re-auth error.
- AC-8 (Tests): Mapper, repository, ViewModel, and Compose tests for AC-1..AC-6 pass in CI.

## 15. Definition of Done

- `feature-ads-billing` merged on `android-port` under `com.testlogon.android.feature.adsbilling`,
  wired into the app nav host via `adsBillingGraph` and reachable from the ads-account detail screen.
- Billing summary + invoice references render from `AdsBillingDto`; deposit flow implemented per FRs
  with offline/stale and error states and duplicate-send protection.
- `AdsDepositRequestDto`/`AdsDepositResultDto` + `AdsBillingApi.deposit` added; GET reused from
  AND-363; CSRF asserted on the POST; GET retried, POST not.
- All §11 tests written and green in CI; Compose acceptance tests cover AC-1..AC-6.
- No hardcoded strings; a11y content descriptions, locale money/date formatting, and dynamic type
  verified with TalkBack; RTL-safe.
- Release logging redacts amounts/balance/payment method/transaction id; `ads_billing` cache cleared
  on logout.
- Lint/detekt/ktlint clean; KSP builds with no new warnings; DTO field names reconciled against
  `/openapi.json` (Q-1 resolved or documented as a follow-up); PR reviewed and approved.
