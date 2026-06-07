---
id: AND-367
title: Ad billing / deposit
milestone: M8
epic: E47
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
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
`feature-ads-billing` module that renders the account balance/lifetime-spend summary (from the
`AdAccount` payload produced by **AND-363**) plus the billing-history ledger (`AdBillingEntry[]`
from `GET /ui/ads/accounts/{account_id}/billing`) and the monthly invoice
(`AdInvoice` from `GET /ui/ads/accounts/{account_id}/invoices/{month}`), (b) a deposit flow that
POSTs a funding request to `POST /ui/ads/accounts/{account_id}/deposit` and reflects the new balance,
and (c) the repository/ViewModel/Compose/test stack to make both render reliably against the
unreliable plaintext dev backend (offline/stale reads, bounded retry for the GET, no auto-retry for
the deposit POST).

> CORRECTION (review 2026-06-06): The original draft assumed a single `AdsBillingDto` summary object
> with embedded `invoices`, a deposit path of `/ui/ads/accounts/{id}/billing/deposit`, and a
> `{amount_minor, currency}` body. None of these match the backend or web client. The real contract
> (verified — see §16): the deposit endpoint is `POST /ui/ads/accounts/{account_id}/deposit` with body
> `AdDepositIn = {amount_cents:int (required), payment_method_id?:string}` (no currency); the billing
> GET returns a **flat `AdBillingEntry[]` ledger** (not a summary object) and has a `limit` query
> param; **invoices are a separate monthly endpoint** `…/invoices/{month}` returning `AdInvoice`;
> balance/lifetime-spend live on the `AdAccount` object, not in a billing payload. All amounts are
> integer **cents** with no per-record ISO currency code or `display` string.

Success means: given a valid session and an `accountId`, the billing screen renders the account
balance + lifetime-spend summary, the billing-history ledger, and the current monthly invoice;
tapping "Add funds", entering an amount, and confirming issues a deposit POST (Bearer token + session
cookies + `X-CSRF-Token`) that, on success, updates the displayed balance and shows confirmation;
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
- Web reference (authoritative for wire names/paths): `src/api/endpoints/ads.ts` — `depositAdFunds`,
  `getAdBillingHistory`, `getAdInvoice` (verified) for the deposit, billing-history, and monthly-invoice
  operations; shared types in `src/api/types.ts` (`AdAccount`, `AdBillingEntry`, `AdInvoice`,
  `AdInvoiceCampaignLine` — verified). Backend OpenAPI: `/openapi.json` on
  `http://18.222.237.167:8000` (PLAINTEXT HTTP dev host, unreliable). Mirror snake_case wire keys
  exactly; do not invent camelCase keys. NOTE: there is **no** `AdsBilling`/`AdsInvoiceRef`/`MoneyDto`
  type in the web client; those were invented by the original draft and are removed below.
- Auth: the web client (`src/api/client.ts`, verified) sends **`Authorization: Bearer <accessToken>`**
  (from the auth store) on every request, plus session cookies (`credentials: include`) via the
  persistent cookie jar (AND-011), plus the `ui_csrf` cookie echoed as the `X-CSRF-Token` header
  (AND-012) on **all** requests (not just mutations). On `401`, the layer calls `POST /ui/session/refresh`
  once (only if already authenticated) then retries the original request; a second `401` logs out
  (AND-013). All consumed here; not re-implemented.

### Upstream dependencies (from backlog)

- **AND-363 (Ads accounts API)** — provides `AdsAccountsApi`, the `core-model.ads` DTOs
  (`AdAccountDto` with `balance_cents`/`lifetime_spend_cents`, `AdBillingEntryDto`, `AdInvoiceDto`,
  `AdInvoiceCampaignLineDto`), and the account-read calls. This ticket consumes that read surface and
  **extends** it with the billing-history GET, the monthly-invoice GET, and the deposit POST.
  (Original draft named `AdsBillingDto`/`MoneyDto`/`AdsInvoiceRefDto` — those names do not exist in the
  web contract; corrected to the verified `AdAccount`/`AdBillingEntry`/`AdInvoice` shapes.)
- **AND-031 (LoginViewModel)** — establishes the authenticated session and the `StateFlow<UiState>`
  ViewModel pattern (submit handler, loading/disabled handling, result→navigation/error mapping)
  that the deposit ViewModel mirrors. A valid session is a precondition for all `/ui/ads/*` calls.

## 3. Functional Requirements

FR-1. **Account summary (read).** For a given `accountId`, render the `AdAccount` fields:
`company_name`, `status`, `balance_cents`, and `lifetime_spend_cents` (the account object — not a
separate billing object — carries balance/spend; verified `src/api/types.ts: AdAccount`). All
monetary values are integer **cents**; there is no per-record ISO currency code and no `display`
string in the contract, so format cents via a fixed display currency (USD assumed; see §16 Open
assumptions). (CORRECTED: original draft's `currency`, `credit_limit`, `payment_status`,
`payment_method`, `period_start`/`period_end` fields do not exist on any verified ads schema and are
removed.)

FR-2. **Billing history + invoices render.** Render `GET /ui/ads/accounts/{account_id}/billing?limit=N`
→ `AdBillingEntry[]` as a ledger list — each row shows `entry_type`, `amount_cents`, `state`,
`reason`, and `created_at` (epoch seconds → locale date). Empty list → "No billing activity yet".
Additionally render the current monthly invoice via `GET /ui/ads/accounts/{account_id}/invoices/{month}`
→ `AdInvoice` (`month`, `total_charges_cents`, `total_deposits_cents`, `entry_count`, and the
per-campaign lines `campaigns: AdInvoiceCampaignLine[]` = `{campaign_id, impressions, clicks,
conversions, total_cents}`). (CORRECTED: invoices are NOT embedded in the billing payload as a
`List<AdsInvoiceRefDto>`; they are a separate per-month endpoint.) `month` is an
unverified format assumption — see §16.

FR-3. **Deposit (mutating).** A primary "Add funds" action opens a deposit sheet where the user
enters an amount (USD) and confirms. On confirm, issue
`POST /ui/ads/accounts/{account_id}/deposit` with body `AdDepositIn = { "amount_cents": <Int>,
"payment_method_id"?: "<id>" }` plus Bearer token, session cookies, and `X-CSRF-Token`. On `200`,
update the displayed balance from the response `new_balance_cents` and show a success confirmation.
(CORRECTED: path was `/billing/deposit`; body was `{amount_minor, currency}` — neither exists.)

FR-4. **Amount validation.** The deposit amount must satisfy the backend-advertised bounds from
`AdDepositIn`: `amount_cents` integer, **minimum 1** (schema) but the **service enforces a $50 minimum**
(5000 cents) returning `400` with a "Minimum deposit" message, and **maximum 10,000,000 cents
($100k)** (verified `components.schemas.AdDepositIn`). The client validates `>= 5000` and `<= 10000000`
defensively; input is parsed locale-aware into integer cents; the confirm button is disabled for
empty/invalid/out-of-range amounts and while a deposit is in flight.

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
    @GET("ui/ads/accounts/{account_id}/billing")
    suspend fun getBillingHistory(
        @Path("account_id") accountId: String,
        @Query("limit") limit: Int = 50,
    ): List<AdBillingEntryDto>

    @GET("ui/ads/accounts/{account_id}/invoices/{month}")
    suspend fun getInvoice(
        @Path("account_id") accountId: String,
        @Path("month") month: String,
    ): AdInvoiceDto

    @POST("ui/ads/accounts/{account_id}/deposit")
    suspend fun deposit(
        @Path("account_id") accountId: String,
        @Body body: AdDepositRequestDto,        // { amount_cents, payment_method_id? }
    ): AdDepositResultDto                        // { ok, entry_id, new_balance_cents }
}
```

The path param is `account_id` (not `id`), the billing GET takes a `limit` query param, invoices are a
separate per-`month` endpoint, and the deposit lives at `…/{account_id}/deposit` (no `/billing/`
segment) — all verified against the OpenAPI index and `src/api/endpoints/ads.ts`. The Bearer token +
cookie jar + `X-CSRF-Token` header are injected by the shared OkHttp interceptors; the deposit POST is
mutating and depends on CSRF (CSRF is in fact sent on every request by the shared client, GET included).
The GETs are idempotent and use the shared bounded-backoff retry (AND-016); the deposit POST is
**never** auto-retried.

### Repository (`core-data` boundary, lives in feature module)

```kotlin
class AdsBillingRepository @Inject constructor(
    private val api: AdsBillingApi,
    private val dao: AdsBillingDao,
    private val mapper: AdsBillingMapper,
    private val connectivity: ConnectivityObserver,
    @IoDispatcher private val io: CoroutineDispatcher,
) {
    fun observeBilling(accountId: String): Flow<AdsBillingScreenData?>   // Room-backed (account + ledger + invoice)
    suspend fun refreshBilling(accountId: String): ApiResult<AdsBillingScreenData>
    suspend fun deposit(accountId: String, amountCents: Int, paymentMethodId: String? = null): ApiResult<AdDepositResult>
}
```

`AdsBillingScreenData` aggregates the verified reads: the `AdAccount` summary (balance_cents,
lifetime_spend_cents), the `AdBillingEntry[]` ledger, and the current `AdInvoice`. `deposit` takes an
**Int cents** amount (not `Long` minor units) and an optional `paymentMethodId`; there is no `currency`
argument. `refreshBilling` follows stale-while-revalidate: emit cache immediately via `observeBilling`,
fetch, upsert to Room, stamp `last_sync`. `deposit` maps DTO→domain and, on success, upserts the
returned `new_balance_cents` so the UI updates without a round-trip (then FR-8 re-fetch confirms).

### ViewModel (mirrors AND-031 pattern)

```kotlin
@HiltViewModel
class AdsBillingViewModel @Inject constructor(
    private val repo: AdsBillingRepository,
    savedState: SavedStateHandle,
) : ViewModel() {
    private val accountId: String = checkNotNull(savedState["accountId"])

    val uiState: StateFlow<UiState<AdsBillingScreenData>> // Loading | Success(data,isStale) | Empty | Error
    val depositState: StateFlow<DepositUiState>          // Idle | Submitting | Success(newBalanceCents) | Error(msg)
    val canDeposit: StateFlow<Boolean>                   // online && amount valid && !submitting

    fun onAmountChanged(raw: String)                     // locale-parse → cents (Int), validate
    fun onDepositConfirmed()                             // debounced + in-flight guarded
    fun dismissDepositResult()
    fun retry()
    fun refresh()
}

sealed interface DepositUiState {
    data object Idle : DepositUiState
    data object Submitting : DepositUiState
    data class Success(val newBalanceCents: Long) : DepositUiState
    data class Error(val message: String, val code: String?) : DepositUiState
}
```

`UiState<T>` is the shared core-ui sealed type (`Loading`, `Success(data, isStale)`, `Empty`,
`Error(message, retryable)`). State is collected via `collectAsStateWithLifecycle`.

### UI (Compose)

- `AdsBillingScreen(onBack: () -> Unit)` — `Scaffold` + `TopAppBar(back)`, `PullToRefreshBox`,
  a `BillingSummaryCard` (company name, account status, balance, lifetime spend — the verified
  `AdAccount` fields), a `BillingLedgerSection` (`LazyColumn` of `AdBillingEntryRow`: entry_type,
  amount, state, reason, date), an `InvoiceSection` (monthly `AdInvoice`: totals + per-campaign lines),
  and a primary `Button("Add funds")`. (CORRECTED: no credit-limit, payment-status, or period UI —
  those fields don't exist in the contract.)
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

All paths relative to base `http://18.222.237.167:8000`. The shapes below are **verified** against the
OpenAPI index/spec and `src/api/endpoints/ads.ts` + `src/api/types.ts` (review 2026-06-06); align Moshi
`@Json(name=…)` to the snake_case wire keys exactly.

**GET `/ui/ads/accounts/{account_id}/billing?limit=N`** → `200` is a JSON **array** of `AdBillingEntry`
(verified `src/api/endpoints/ads.ts: getAdBillingHistory` returns `AdBillingEntry[]`; query param `limit`,
default 50). The response body has **no named schema** in OpenAPI (resp `200:` empty), so the array
element shape is taken from the web `AdBillingEntry` type:

```json
[
  {
    "entry_id": "be_5001",
    "account_id": "ad_acct_88",
    "campaign_id": "cmp_12",
    "entry_type": "charge",
    "amount_cents": 43200,
    "state": "settled",
    "reason": "impression batch",
    "meta": {},
    "created_at": 1748692800
  }
]
```

**GET `/ui/ads/accounts/{account_id}/invoices/{month}`** → `200` `AdInvoice` (verified
`getAdInvoice` / `src/api/types.ts: AdInvoice`):

```json
{
  "account_id": "ad_acct_88",
  "month": "2026-05",
  "campaigns": [
    { "campaign_id": "cmp_12", "impressions": 10000, "clicks": 320,
      "conversions": 18, "total_cents": 43200 }
  ],
  "total_charges_cents": 43200,
  "total_deposits_cents": 50000,
  "entry_count": 7
}
```

**Account summary** (balance/lifetime spend) comes from `AdAccount` via AND-363
(`GET /ui/ads/accounts/{account_id}` → `balance_cents`, `lifetime_spend_cents`, `company_name`,
`status`); there is no separate "billing summary" object.

**POST `/ui/ads/accounts/{account_id}/deposit`** (headers: `Authorization: Bearer <token>`,
`X-CSRF-Token: <ui_csrf>`, session cookies) request body `AdDepositIn` (verified
`components.schemas.AdDepositIn`):

```json
{ "amount_cents": 50000, "payment_method_id": "" }
```

`amount_cents` is required (integer, min 1 by schema, but the service enforces a **$50 minimum** →
`400` "Minimum deposit", max **10,000,000** = $100k). `payment_method_id` is optional (default `""`).
There is **no `currency` field**.

→ `200` (shape from `src/api/endpoints/ads.ts: depositAdFunds`; OpenAPI resp `200:` has no named
schema):

```json
{ "ok": true, "entry_id": "be_5002", "new_balance_cents": 175000 }
```

DTOs (new in this ticket; `AdBillingEntryDto`/`AdInvoiceDto`/`AdInvoiceCampaignLineDto`/`AdAccountDto`
reused from AND-363 `core-model.ads`):

```kotlin
@JsonClass(generateAdapter = true)
data class AdDepositRequestDto(
    @Json(name = "amount_cents") val amountCents: Int,
    @Json(name = "payment_method_id") val paymentMethodId: String? = null,
)

@JsonClass(generateAdapter = true)
data class AdDepositResultDto(
    val ok: Boolean = true,
    @Json(name = "entry_id") val entryId: String? = null,
    @Json(name = "new_balance_cents") val newBalanceCents: Long? = null,
)
```

Monetary amounts are integer **cents**; never use floats. Errors follow FastAPI `detail`
(`string | [{msg}] | {code,...}`) mapped by AND-015 into `ApiResult.Error(message, code)`. Notable
statuses (verified `422:HTTPValidationError` on these endpoints; others are the standard FastAPI/web
behaviors confirmed in `src/api/client.ts`): `400` (below-minimum / over-max amount → field error,
non-retryable — the service returns a clear "Minimum deposit" message), `422` (request validation →
field error, non-retryable), `401` (single refresh+retry in the interceptor, verified
`client.ts: refreshSession`), `403` (permission/geo denied — `detail.code` mapped), `404` (account not
found → read Error, non-retryable), `5xx`/timeout (transient → GET retried; deposit shows manual-retry
guidance). NOTE: `402`/`409` are NOT documented for these endpoints in OpenAPI (only `200`/`422`); the
client should still surface any non-2xx `detail` verbatim, but a dedicated `402`/`409` path is an
**unverified assumption** — see §16.

## 6. Data & State Management

Room caches the billing read so the screen survives the unreliable backend:

```kotlin
@Entity(tableName = "ads_billing")
data class AdsBillingEntity(
    @PrimaryKey val accountId: String,
    val companyName: String?, val status: String?,
    val balanceCents: Long?, val lifetimeSpendCents: Long?,   // from AdAccount
    val ledgerJson: String,     // serialized List<AdBillingEntryDto> (Moshi TypeConverter)
    val invoiceJson: String?,   // serialized current-month AdInvoiceDto (nullable)
    val invoiceMonth: String?,
    val cachedAt: Long,
)
```

(CORRECTED: dropped `currency`, `balanceDisplay`, `currentSpend`, `creditLimit`, `paymentStatus`,
`paymentMethod`, `periodStart`/`periodEnd` — none exist in the verified contract. Balance/lifetime-spend
come from `AdAccount`; the ledger and invoice are the verified read shapes.)

`AdsBillingDao` exposes `observe(accountId)`, `upsert(entity)`, `clear(accountId)`. Last-sync per
account lives in DataStore (`ads_billing_last_sync_<accountId>`); `isStale = now - lastSync > 5m`
drives the stale badge. Domain models in `core-model`: `AdsBillingScreenData`, `AdBillingEntry`,
`AdInvoice`, `AdInvoiceCampaignLine`, `AdDepositResult`. `AdsBillingMapper` converts DTO ↔ entity ↔
domain; `created_at` is **epoch seconds** (Long) parsed at the mapper boundary (not ISO-8601), `month`
is a string like `"2026-05"`, and money is kept as integer cents (Long) — no currency code or display
string in the wire contract.

Read state is `StateFlow<UiState<AdsBillingScreenData>>`; the deposit flow uses the separate
`DepositUiState` so a deposit error never overwrites the rendered summary. Amount-entry state
(raw string, parsed cents, validation message) is held in the ViewModel and survives config
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
- **Deposit failures:** `400` (below $50 minimum / above $100k maximum — verified) and `422`
  (validation) map to an inline field error under the amount input using the server `detail`
  message; any other non-2xx (e.g. a hypothetical `402`/`409` decline — unverified for this endpoint)
  maps to a `DepositUiState.Error` with the server `detail` and a retry affordance; the sheet stays
  open with the entered amount preserved.
- **Duplicate-send protection:** in-flight guard + ~1s debounce on `onDepositConfirmed()`; confirm
  button disabled for the entire request lifecycle. On unknown/timeout outcome the user is advised to
  refresh and check balance before retrying (deposit is not idempotent).
- **404 on read:** non-retryable Error with "Ads account not found" and a back affordance.

## 8. Security & Privacy

- All requests carry the `Authorization: Bearer <token>` header and session cookies via the persistent
  jar (AND-011); the deposit POST includes `X-CSRF-Token` from the `ui_csrf` cookie (AND-012) — verified
  present in tests. (CSRF is in fact attached to every request by the shared client.)
- No card numbers, tokens, or PANs are handled client-side. The deposit body carries only
  `amount_cents` and an optional opaque `payment_method_id` (an id from the billing system, never raw
  payment credentials). (CORRECTED: there is no masked `payment_method` field on any verified ads
  schema; the original draft's "masked payment method rendered verbatim" claim is removed.)
- The Room cache holds only billing metadata already authorized for this session; clear the
  `ads_billing` cache for the account on logout (hook the session-clear broadcast from the auth
  module).
- Dev backend is plaintext HTTP; cleartext is permitted **only** for the dev host via the
  network-security-config owned by core-network. Release logging redacts `amount_cents`,
  `new_balance_cents`/`balance_cents`, and `entry_id` (see §10).
- Amount is server-validated; the client validates defensively (>= $50, <= $100k) but the backend is
  authoritative for limits and funding eligibility.

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
- Logging via Timber; release builds **redact** `amount_cents`, balances (`balance_cents`,
  `new_balance_cents`), and `entry_id`. Network failures logged at WARN with endpoint + HTTP status +
  error `code` only (no request/response bodies).
- No amounts or entry ids sent to crash reporting; only opaque `account_id` and error codes.

## 11. Testing Strategy

- **Unit (core-testing + JUnit5 + Turbine + MockWebServer):**
  - `AdsBillingMapperTest` — `AdBillingEntryDto[]`/`AdInvoiceDto`/`AdAccountDto`→entity→domain mapping;
    integer-cents handling (Long, no float); `created_at` epoch-seconds parsing; null/optional
    (`payment_method_id`, empty ledger, missing invoice); ledger + invoice round-trip through the JSON
    columns.
  - `AdsBillingRepositoryTest` — MockWebServer success, `404`, `5xx`→retry, offline→cached+stale;
    `deposit` success updates cached balance from `new_balance_cents`; `deposit` failure (`400`
    below-minimum / `422`) maps to `ApiResult.Error` with `detail` message; asserts **`X-CSRF-Token`
    and `Authorization` present on POST** and **no auto-retry on POST**.
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

- Q-1: RESOLVED (review 2026-06-06). Deposit is `POST /ui/ads/accounts/{account_id}/deposit`, body
  `AdDepositIn = {amount_cents:int, payment_method_id?:string}` (verified `components.schemas.AdDepositIn`),
  response `{ok, entry_id, new_balance_cents}` (verified `src/api/endpoints/ads.ts: depositAdFunds`).
  No `amount_minor`, no `currency`, no `transaction_id`, no `/billing/` path segment. DTOs corrected to
  `AdDepositRequestDto`/`AdDepositResultDto`.
- Q-2: PARTLY RESOLVED. There is a real per-month invoice endpoint
  `GET /ui/ads/accounts/{account_id}/invoices/{month}` → `AdInvoice` (campaign lines + totals); this
  ticket renders the **current** month's invoice inline. A month-picker / historical-invoice browser
  and any PDF export remain a follow-up. The exact accepted `{month}` string format (`"2026-05"` vs
  `"2026-05-01"` vs other) is an unverified assumption — see §16.
- Q-3: RESOLVED (review 2026-06-06). `AdDepositIn` advertises `amount_cents` min 1 / max 10,000,000
  ($100k); the service additionally enforces a **$50 minimum** (returns `400` "Minimum deposit"). There
  is no currency field at all — amounts are bare cents (USD assumed; see §16 Open assumptions). Client
  enforces `5000 <= amount_cents <= 10000000` defensively.
- Q-4: Idempotency of the deposit POST — if the backend accepts an idempotency key, send one to make
  retries safe; until confirmed, the client does **not** auto-retry (R: double-funding).
- Q-5: PARTLY RESOLVED. `AdDepositIn` accepts an optional `payment_method_id` ("Payment method ID from
  billing system", default `""`); deposit is settled server-side against that method. Whether an empty
  `payment_method_id` is accepted (default method) or returns an error, and whether any SCA/redirect
  step exists, is not expressed in OpenAPI (resp `200`/`422` only) and remains an out-of-scope
  follow-up if a redirect is required. This ticket sends `payment_method_id` only if the caller supplies
  one (the source for that id is itself an open assumption — see §16).
- R-1: Unreliable dev host may flake instrumented tests — mock the network in CI; reserve live runs
  for manual verification.

## 14. Acceptance Criteria

- AC-1 (Invoices render): Given a valid session and `accountId`, the billing screen renders the account
  summary (company name, status, balance, lifetime spend from `AdAccount`), the billing-history ledger
  (`AdBillingEntry[]`: entry type, amount, state, reason, date), and the current monthly invoice
  (`AdInvoice`: totals + campaign lines); an empty ledger shows "No billing activity yet".
- AC-2 (Deposit renders + happy path): "Add funds" opens the deposit sheet; entering a valid amount
  enables confirm; confirm issues `POST /ui/ads/accounts/{account_id}/deposit` with body
  `{amount_cents}` plus Bearer token + cookies + `X-CSRF-Token`, shows progress, and on `200` shows
  success and the updated balance (from `new_balance_cents`).
- AC-3 (Validation): Confirm is disabled for empty/zero/negative/non-numeric amounts and amounts
  outside the backend min/max ($50–$100k); invalid input shows an inline field error.
- AC-4 (Duplicate protection): A double-tap on confirm issues exactly one POST (debounce/in-flight
  guard verified); the deposit POST is never auto-retried.
- AC-5 (Deposit failure): A non-2xx deposit response (`400` below-minimum / `422` validation; or any
  other non-2xx with a `detail`) shows the server `detail` message with retry, keeps the sheet open with
  the entered amount, and does not corrupt the summary.
- AC-6 (Resilience): With no network and a populated cache, the screen renders cached billing +
  invoices with a stale indicator and "Add funds" disabled; with an empty cache it shows a retryable
  error.
- AC-7 (Auth): A `401` triggers exactly one `POST /ui/session/refresh` + retry before surfacing a
  re-auth error.
- AC-8 (Tests): Mapper, repository, ViewModel, and Compose tests for AC-1..AC-6 pass in CI.

## 15. Definition of Done

- `feature-ads-billing` merged on `android-port` under `com.testlogon.android.feature.adsbilling`,
  wired into the app nav host via `adsBillingGraph` and reachable from the ads-account detail screen.
- Account summary (`AdAccount`), billing ledger (`AdBillingEntry[]`), and current monthly invoice
  (`AdInvoice`) render; deposit flow implemented per FRs with offline/stale and error states and
  duplicate-send protection.
- `AdDepositRequestDto`/`AdDepositResultDto` + `AdsBillingApi.deposit`/`getBillingHistory`/`getInvoice`
  added; account read reused from AND-363; CSRF + Bearer asserted on the POST; GETs retried, POST not.
- All §11 tests written and green in CI; Compose acceptance tests cover AC-1..AC-6.
- No hardcoded strings; a11y content descriptions, locale money/date formatting, and dynamic type
  verified with TalkBack; RTL-safe.
- Release logging redacts `amount_cents`/balances/`entry_id`; `ads_billing` cache cleared on logout.
- Lint/detekt/ktlint clean; KSP builds with no new warnings; DTO field names reconciled against
  `/openapi.json` (Q-1/Q-3 resolved; see §16); PR reviewed and approved.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. "OpenAPI" = the index
(`reference/openapi.index.txt`) and/or full spec (`reference/openapi.pretty.json
components.schemas.<Name>`); frontend pointers are paths under `reference/src/`.

1. **Deposit endpoint is `POST /ui/ads/accounts/{account_id}/deposit`.** VERDICT: Corrected (draft had
   `POST …/{id}/billing/deposit`). SOURCE: OpenAPI `POST /ui/ads/accounts/{account_id}/deposit`
   (op `deposit_endpoint_…`); `src/api/endpoints/ads.ts: depositAdFunds`.
2. **Path parameter is `account_id`, not `id`.** VERDICT: Corrected. SOURCE: OpenAPI
   `params=account_id,…` on the deposit/billing/invoice rows.
3. **Deposit request body is `AdDepositIn = {amount_cents:int (required), payment_method_id?:string}`;
   no `currency`, no `amount_minor`.** VERDICT: Corrected. SOURCE: OpenAPI
   `components.schemas.AdDepositIn`; `src/api/endpoints/ads.ts: depositAdFunds` (`{amount_cents, payment_method_id?}`).
4. **Deposit `amount_cents` bounds: schema min 1 / max 10,000,000 ($100k); service-enforced $50
   minimum → `400` "Minimum deposit".** VERDICT: Verified. SOURCE: OpenAPI
   `components.schemas.AdDepositIn` (`minimum:1, maximum:1.0e7`, plus the field `description` stating the
   $50 service minimum and the 400 message).
5. **Deposit success response is `{ok, entry_id, new_balance_cents}`; no `balance`/`transaction_id`/`account_id`.**
   VERDICT: Corrected. SOURCE: `src/api/endpoints/ads.ts: depositAdFunds` return type. (OpenAPI lists
   `resp=200:` with no named schema, so the frontend type is authoritative.)
6. **Billing GET is `GET /ui/ads/accounts/{account_id}/billing?limit=N` returning a flat
   `AdBillingEntry[]` ledger — NOT a single `AdsBillingDto` summary with embedded `invoices`.**
   VERDICT: Corrected. SOURCE: OpenAPI `GET /ui/ads/accounts/{account_id}/billing` (op
   `billing_history_endpoint_…`, `params=account_id,limit,…`); `src/api/endpoints/ads.ts: getAdBillingHistory`
   (`AdBillingEntry[]`).
7. **`AdBillingEntry` shape = `{entry_id, account_id, campaign_id, entry_type, amount_cents, state,
   reason, meta, created_at}`; `created_at` is epoch seconds (number).** VERDICT: Verified. SOURCE:
   `src/api/types.ts: AdBillingEntry`.
8. **Invoices are a separate per-month endpoint `GET /ui/ads/accounts/{account_id}/invoices/{month}`
   returning `AdInvoice = {account_id, month, campaigns: AdInvoiceCampaignLine[], total_charges_cents,
   total_deposits_cents, entry_count}`.** VERDICT: Corrected (draft embedded `invoices` in the billing
   payload). SOURCE: OpenAPI `GET /ui/ads/accounts/{account_id}/invoices/{month}` (op `invoice_endpoint_…`);
   `src/api/endpoints/ads.ts: getAdInvoice`; `src/api/types.ts: AdInvoice` / `AdInvoiceCampaignLine`.
9. **Account balance/lifetime-spend live on `AdAccount` (`balance_cents`, `lifetime_spend_cents`,
   `company_name`, `status`), not in a billing object; no `credit_limit`/`payment_status`/`payment_method`/
   `period_*`/`currency` fields exist on any ads schema.** VERDICT: Corrected. SOURCE:
   `src/api/types.ts: AdAccount`.
10. **All money is integer cents (`*_cents`); no per-record ISO currency code, no `display` string, no
    `MoneyDto`.** VERDICT: Corrected. SOURCE: `src/api/types.ts` (`AdAccount`, `AdBillingEntry`,
    `AdInvoice` all use `*_cents:number`); absence of any `Money`/currency type in `ads.ts`/`types.ts`.
11. **Transport: `Authorization: Bearer <accessToken>` + session cookies (`credentials: include`) +
    `X-CSRF-Token` from the `ui_csrf` cookie, on every request.** VERDICT: Corrected/clarified (draft
    omitted the Bearer token and implied CSRF only on mutations). SOURCE: `src/api/client.ts`
    (lines setting `Authorization`, `X-CSRF-Token` from `getCookie("ui_csrf")`, and `credentials: include`).
12. **On `401`: one `POST /ui/session/refresh` then retry; second `401` → logout; refresh only if already
    authenticated.** VERDICT: Verified. SOURCE: `src/api/client.ts: refreshSession` and the 401 branch.
13. **FastAPI `detail` error mapping (`string | [{msg}] | {code,...}`).** VERDICT: Verified. SOURCE:
    `src/api/client.ts: normalizeErrorDetail`; OpenAPI `422:HTTPValidationError` on all four endpoints.
14. **Network/offline failures throw `ApiError(0, "Network error")` (distinct offline path).** VERDICT:
    Verified. SOURCE: `src/api/client.ts` catch block around `fetch`.
15. **Android stack choices (Compose/Material 3, Navigation-Compose, Hilt+KSP, Retrofit/OkHttp/Moshi,
    Room+DataStore, `collectAsStateWithLifecycle`, `PullToRefreshBox`).** VERDICT: Unverified-assumption
    (carried from the project's platform conventions / AND-363/AND-031; not checkable from the backend or
    web sources). Framework ref: developer.android.com/jetpack/compose and
    developer.android.com/training/dependency-injection/hilt-android.

### Corrections made

- Deposit path `…/{id}/billing/deposit` → `POST /ui/ads/accounts/{account_id}/deposit` (claims 1, 2).
- Deposit body `{amount_minor:Long, currency}` → `AdDepositIn {amount_cents:Int, payment_method_id?}` (claim 3).
- Deposit response `{ok, account_id, balance:MoneyDto, transaction_id}` → `{ok, entry_id, new_balance_cents}` (claim 5).
- Billing read: single `AdsBillingDto` summary w/ embedded `invoices` → flat `AdBillingEntry[]` ledger
  + separate monthly `AdInvoice` endpoint (claims 6, 8).
- Removed nonexistent fields: `currency`, `credit_limit`, `payment_status`, `payment_method`,
  `period_start`/`period_end`, `display`, `MoneyDto` (claims 9, 10). Balance/spend sourced from `AdAccount`.
- Money model: `Long` minor units + currency code → integer **cents** (Long), USD assumed (claim 10).
- `created_at` ISO-8601 parsing → epoch-seconds parsing (claim 7).
- Transport: added the missing `Authorization: Bearer` header; clarified CSRF is sent on all requests (claim 11).
- Updated DTO/domain/entity names, Room schema, UI composables, telemetry/redaction field names, tests,
  acceptance criteria, and §13 Q-1/Q-2/Q-3/Q-5 to the verified contract.
- Deposit bounds set to $50–$100k from the verified `AdDepositIn` schema (claim 4).

### Open assumptions

- **Display currency is USD.** The wire contract carries no currency code anywhere; cents are rendered
  as USD. Unverifiable from the sources — neither OpenAPI nor the web types expose a currency for ads
  money. If accounts can be non-USD, this needs a backend confirmation.
- **`{month}` path-segment format** for the invoice endpoint (assumed `"YYYY-MM"`, e.g. `"2026-05"`,
  matching `AdInvoice.month`). OpenAPI types `month` only as a path string; the exact accepted format is
  not specified. Confirm at integration time.
- **`payment_method_id` provenance.** `AdDepositIn` accepts an optional payment-method id "from billing
  system", but no ads endpoint in the index lists/creates ad-account payment methods. Whether deposit
  works with an empty id (default method) or requires a pre-attached method is not expressed in OpenAPI
  (resp `200`/`422` only). Treated as optional; source of the id is out of scope (see §13 Q-5).
- **`402`/`409` decline semantics.** The draft assumed payment-declined/insufficient statuses; OpenAPI
  documents only `200`/`422` for the deposit endpoint. The client surfaces any non-2xx `detail`
  generically; a dedicated decline UX is unverified.
- **Android framework/library versions and the AND-011/012/013/015/016/018/021/022 core modules** are
  taken on faith from sibling tickets; not checkable against the provided sources.

## 17. Test Plan

IDs `TC-AND-367-NN`. "MockWebServer" cases are JVM/Robolectric (no device). Compose-UI / instrumented
cases run on the **headless emulator AVD `test35` (API 35, x86_64)** unless a real-hardware/ABI/API-34
concern requires the **physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a)** — called out per
case. None of this ticket's behavior touches camera/biometrics/FCM/WebRTC/Telecom, so the physical
device is only needed for the API-34/arm64 parity smoke (TC-AND-367-12).

- **TC-AND-367-01** — Type: contract/MockWebServer. Target: `AdsBillingMapper` + `AdsBillingApi.getBillingHistory`.
  Preconditions: MockWebServer enqueues a `200` `AdBillingEntry[]` fixture (from §5) and an `AdAccount`
  fixture. Steps: call repository `refreshBilling`; map to domain. Expected: account summary
  (balance_cents, lifetime_spend_cents, company_name, status) and ledger rows (entry_type, amount_cents,
  state, reason, created_at as epoch→date) map losslessly; integer cents kept as Long, no float.
  Traces: AC-1.
- **TC-AND-367-02** — Type: contract/MockWebServer. Target: `AdsBillingApi.getInvoice` + mapper.
  Preconditions: enqueue `200` `AdInvoice` fixture. Steps: fetch current-month invoice; map. Expected:
  `month`, `total_charges_cents`, `total_deposits_cents`, `entry_count`, and `campaigns[]`
  (campaign_id/impressions/clicks/conversions/total_cents) render; request path is
  `/ui/ads/accounts/{account_id}/invoices/{month}`. Traces: AC-1.
- **TC-AND-367-03** — Type: Compose-UI. Target: `AdsBillingScreen` (summary + ledger + invoice).
  Preconditions: ViewModel seeded with a Success fixture. Steps: render. Expected: `BillingSummaryCard`
  shows company/status/balance/lifetime-spend; ledger list shows entries; invoice section shows totals +
  campaign lines; no credit-limit/payment-status/period UI exists. Traces: AC-1.
- **TC-AND-367-04** — Type: Compose-UI. Target: empty-ledger state. Preconditions: Success fixture with
  empty `AdBillingEntry[]`. Steps: render. Expected: "No billing activity yet" shown; screen otherwise
  renders the account summary. Traces: AC-1.
- **TC-AND-367-05** — Type: contract/MockWebServer. Target: `AdsBillingApi.deposit` happy path.
  Preconditions: enqueue `200` `{ok:true, entry_id, new_balance_cents:175000}`. Steps: call
  `repo.deposit(accountId, amountCents=50000)`. Expected: request is `POST /ui/ads/accounts/{account_id}/deposit`
  with JSON body `{"amount_cents":50000}` (no `currency`); recorded request carries `Authorization` and
  `X-CSRF-Token` headers; result maps to `AdDepositResult` and cached balance updates to 175000.
  Traces: AC-2, AC-7(headers).
- **TC-AND-367-06** — Type: unit. Target: `AdsBillingViewModel` amount validation / `canDeposit`.
  Preconditions: ViewModel online. Steps: feed amounts — empty, "0", "-5", "abc", "10" ($0.10, below
  $50 min), "5000.00" (= $5000, in range), "200000" ($200k, above $100k max). Expected: `canDeposit`
  false for all except the in-range value; below-min and above-max show inline field errors; parsing is
  to integer cents. Traces: AC-3.
- **TC-AND-367-07** — Type: unit. Target: ViewModel duplicate-send guard. Preconditions: deposit
  in-flight. Steps: invoke `onDepositConfirmed()` twice in rapid succession (double-tap) within the
  debounce window. Expected: exactly one POST issued; second invocation is a no-op while `Submitting`;
  confirm disabled for the request lifecycle. Traces: AC-4.
- **TC-AND-367-08** — Type: contract/MockWebServer. Target: deposit not auto-retried + error mapping.
  Preconditions: enqueue a single `400` `{"detail":"Minimum deposit is $50.00"}`. Steps: call
  `repo.deposit(amountCents=100)`. Expected: exactly **one** request hits the server (no auto-retry on
  POST); result is `ApiResult.Error` with the `detail` message and the `400`/code surfaced; cache
  unchanged. Traces: AC-4, AC-5.
- **TC-AND-367-09** — Type: Compose-UI. Target: deposit sheet flow. Preconditions: screen rendered,
  online. Steps: tap "Add funds"; confirm disabled; enter a valid amount; confirm enables; tap confirm;
  observe spinner; backend returns `200`. Expected: progress shown while Submitting, then success
  confirmation (snackbar/inline) and the displayed balance updates to `new_balance_cents`. Traces: AC-2.
- **TC-AND-367-10** — Type: Compose-UI. Target: deposit failure keeps sheet + amount. Preconditions:
  backend returns `422` validation `detail`. Steps: enter amount, confirm. Expected: sheet stays open
  with the entered amount preserved, inline field error shows the server `detail`, the underlying
  summary is not corrupted, and a retry affordance is available. Traces: AC-5.
- **TC-AND-367-11** — Type: integration (Robolectric + Room + MockWebServer). Target: offline/stale +
  "Add funds" gating. Preconditions: Room pre-populated with a cached billing fixture; MockWebServer set
  to fail/timeout; `ConnectivityObserver` reports offline. Steps: open screen; then simulate empty cache
  + offline in a second pass. Expected: with cache → cached summary + ledger render with a stale badge
  and "Add funds" disabled; with empty cache → retryable `Error` state; on reconnect "Add funds"
  re-enables. Traces: AC-6, AC-3(gating).
- **TC-AND-367-12** — Type: instrumented/e2e — **MUST run on the physical Samsung A15 (API 34,
  arm64-v8a)**. Target: full screen + deposit happy path against a MockWebServer (network mocked; dev
  host is unreliable, R-1). Preconditions: app installed on `R5CX821TA9R`; MockWebServer dispatcher for
  account/billing/invoice/deposit. Steps: launch to the billing route, verify summary/ledger/invoice
  render, perform a valid deposit, verify balance update. Expected: identical behavior to the emulator
  run (API-34/arm64 vs API-35/x86_64 parity); no ABI/JSON/Moshi-codegen differences. Rationale for
  device: arm64-vs-x86 ABI and API-34-vs-35 parity per test-target guidance. Traces: AC-1, AC-2, AC-8.
- **TC-AND-367-13** — Type: contract/MockWebServer. Target: `401` refresh-and-retry. Preconditions:
  enqueue `401`, then `200` for `POST /ui/session/refresh`, then `200` for the original GET. Steps:
  trigger `refreshBilling`. Expected: exactly one `POST /ui/session/refresh` then a single retry of the
  original request that succeeds; a second consecutive `401` surfaces a re-auth error (no infinite loop).
  Traces: AC-7.
- **TC-AND-367-14** — Type: instrumented/Compose-UI accessibility. Target: a11y on the billing screen +
  deposit sheet. Preconditions: TalkBack-style semantics assertions; emulator `test35`. Steps: inspect
  semantics. Expected: status/entry badges expose `contentDescription`; amount field has an associated
  label + error text exposed; confirm button announces disabled/loading; touch targets ≥48dp; focus
  order summary → ledger/invoice → "Add funds" → sheet(amount → confirm); deposit result announced via
  live region. Traces: AC-1, AC-2, AC-8.

### Coverage matrix

| AC (section 14) | Covered by |
| --- | --- |
| AC-1 (summary + ledger + invoice render; empty state) | TC-01, TC-02, TC-03, TC-04, TC-12, TC-14 |
| AC-2 (deposit happy path + updated balance) | TC-05, TC-09, TC-12, TC-14 |
| AC-3 (amount validation / gating) | TC-06, TC-11 |
| AC-4 (duplicate protection; no auto-retry) | TC-07, TC-08 |
| AC-5 (deposit failure surfaced, sheet preserved) | TC-08, TC-10 |
| AC-6 (offline/stale; empty-cache error) | TC-11 |
| AC-7 (401 → one refresh + retry; CSRF/Bearer headers) | TC-05, TC-13 |
| AC-8 (mapper/repo/VM/Compose tests green in CI) | TC-01, TC-02, TC-05, TC-06, TC-07, TC-08, TC-12, TC-14 |
