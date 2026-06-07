---
id: AND-223
title: Billing API + DTOs
milestone: M5
epic: E31
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-027]
blocks: []
---

# AND-223 — Billing API + DTOs

## 1. Overview & Goal

This ticket delivers the network and model foundation for the TestLogon billing
surface on the native Android port: a Retrofit `BillingApi` interface covering the
`/ui/billing/*` and `/api/billing/*` endpoints, plus the full set of Moshi DTOs
that mirror the backend payloads and the web reference layer
(`frontend/src/api/endpoints/billing.ts`, `frontend/src/api/types.ts`).

The scope is deliberately the **data plane only**. No Compose UI, no ViewModel,
no Room cache, and no DataStore persistence are produced here. The deliverable is:

1. A typed `BillingApi` Retrofit service in `core-network`.
2. A complete, versioned set of `*Dto` data classes in `core-network` and the
   corresponding domain models in `core-model`, with `DtoMapper` functions between
   them.
3. Exhaustive, byte-for-byte mapping tests proving every billing payload
   round-trips through Moshi and maps to the domain model without loss.

The acceptance bar from the backlog is precise and testable: **"Billing payloads
map (tested)."** Success is defined by passing serialization/deserialization and
mapper unit tests against captured fixture JSON, not by any rendered screen.

This is a P0 prerequisite. The downstream billing feature module
(`feature-billing`, not in scope here) — subscription status, plan selection,
invoice history, and payment-method management — depends entirely on the contract
locked by this ticket.

## 2. Context & References

- **Package base:** `com.testlogon.android`. All classes in this ticket live
  under `com.testlogon.android.core.network.billing` (API + DTOs) and
  `com.testlogon.android.core.model.billing` (domain models).
- **Module layering:** `core-network` (Retrofit/Moshi DTOs, `BillingApi`) →
  depends on `core-model` (pure Kotlin domain types, no Android/Retrofit imports).
  `feature-billing` (future) → `core-network` + `core-model`. This ticket touches
  only `core-network` and `core-model`.
- **Web reference (authoritative for shapes):**
  - `frontend/src/api/endpoints/billing.ts` — endpoint paths, verbs, query params.
  - `frontend/src/api/types.ts` — shared TypeScript interfaces for billing
    entities; Kotlin DTOs must be field-name-equivalent.
- **OpenAPI:** `http://18.222.237.167:8000/openapi.json` — fetch the live billing
  schema fragments to confirm field nullability and enum members before finalizing
  DTOs. Treat OpenAPI + `types.ts` as joint sources of truth; where they disagree,
  prefer OpenAPI and file an Open Question (section 13).
- **Dependency AND-027 (AuthApi):** provides the cookie-based session
  infrastructure — the persistent cookie jar, the `ui_csrf` → `X-CSRF-Token`
  echo interceptor, and the single-shot `POST /ui/session/refresh`-then-retry on
  401. `BillingApi` reuses that authenticated Retrofit instance verbatim and adds
  no auth logic of its own.
- **Stack:** Kotlin 2.0.21, Retrofit 2.11, OkHttp 4.12, Moshi 1.15 (codegen via
  KSP), Coroutines. minSdk 24 / compileSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.

## 3. Functional Requirements

FR-1. Expose a `BillingApi` Retrofit interface with `suspend` functions for every
billing endpoint enumerated in `billing.ts` and `/openapi.json` (see section 5).

FR-2. Every endpoint function returns `ApiResult<T>` of a domain model (not the
raw DTO). The project-standard `ApiResult<T>` sealed type and the call-adapter
that wraps Retrofit responses already exist from `core-network` foundations
(AND-027); this ticket consumes them.

FR-3. Provide Moshi `@JsonClass(generateAdapter = true)` DTOs for the **real**
billing surface (CORRECTED — there is no plan catalog or invoice resource):
subscriptions list, billing config, billing settings, billing balance, ledger /
payments entries (limit-based lists), payment methods (bare array), wallet
balance, and the checkout-session request/response.

FR-4. Provide domain models in `core-model` that are UI-friendly: money expressed
as a `Money` value type (**integer cents** + currency — CORRECTED from "minor
units"; the backend field is uniformly `*_cents`), timestamps as `Instant`
(handling BOTH ISO-8601 strings and epoch-number encodings), and
status/state expressed as Kotlin `enum class` where the backend enumerates values,
with an explicit `UNKNOWN` fallback for forward compatibility. Free-form string
fields (`type`, `state`, `billing_cycle`) are kept as `String`.

FR-5. Provide pure `internal fun <Dto>.toDomain(): <Model>` mapper extension
functions. Mapping must be total: unknown enum strings map to `UNKNOWN` (never
throw), absent optional objects map to `null`, and absent collections map to
empty lists.

FR-6. The FastAPI error envelope (`detail` as `string | [{msg}] | {code,...}`)
must be parsed by the shared error mapper into a typed `ApiError`. Billing adds no
new error parsing — it relies on the shared mapper and is verified to surface
billing-specific 402/409 cases correctly.

FR-7. No mutable client state, no caching, no UI. This ticket is a library
contract.

## 4. Technical Design

### 4.1 `BillingApi` interface (`core-network`)

```kotlin
package com.testlogon.android.core.network.billing

import retrofit2.http.*

internal interface BillingApi {

    // CORRECTED: the web client reads subscriptions via the *plural*, list-shaped
    // endpoint `GET /ui/billing/subscriptions` returning `{ items: [...] }`
    // (src/api/endpoints/billing.ts: getSubscriptions). There is NO
    // `/ui/billing/subscription` (singular) endpoint in the backend.
    @GET("ui/billing/subscriptions")
    suspend fun getSubscriptions(
        @Query("limit") limit: Int = 50,
    ): SubscriptionListDto

    // CORRECTED: `/ui/billing/plans` does NOT exist. The closest real GET is
    // `/ui/billing/config` (publishable_key, currency). Plan/price catalog as
    // designed here is fictional — removed. Use BillingConfigDto instead.
    @GET("ui/billing/config")
    suspend fun getConfig(): BillingConfigDto

    @GET("ui/billing/settings")
    suspend fun getSettings(): BillingSettingsDto

    @GET("ui/billing/balance")
    suspend fun getBalance(): BillingBalanceDto

    // CORRECTED: invoices are NOT under /api/billing. The financial history the
    // web client shows comes from the *ledger* and *payments* endpoints, which
    // are limit-based (NOT cursor-based) and return `{ items: [...] }`.
    // There is no `/api/billing/invoices` or `/api/billing/invoices/{id}`.
    @GET("ui/billing/ledger")
    suspend fun getLedger(@Query("limit") limit: Int = 50): LedgerPageDto

    @GET("ui/billing/payments")
    suspend fun getPayments(@Query("limit") limit: Int = 50): LedgerPageDto

    // CORRECTED: response is a *bare array* `PaymentMethod[]`, not a wrapper
    // object with default_id/methods (src/api/endpoints/billing.ts:
    // getPaymentMethods → api.get<PaymentMethod[]>). The default is identified by
    // each item's own `is_default` field.
    @GET("ui/billing/payment-methods")
    suspend fun getPaymentMethods(): List<PaymentMethodDto>

    @GET("ui/billing/wallet")
    suspend fun getWallet(): WalletBalanceDto

    // CORRECTED: path uses an UNDERSCORE (`checkout_session`), not a hyphen, and
    // the request body is amount-based (BillingCheckoutReq:
    // amount_cents/currency?/description?), NOT plan_id/success_url/cancel_url.
    // Response is `{ session_id, url }`.
    @POST("ui/billing/checkout_session")
    suspend fun createCheckoutSession(
        @Body body: CheckoutSessionRequestDto,
    ): CheckoutSessionDto

    // NOTE: `/ui/billing/portal-session` does NOT exist in the backend and has
    // been removed. (Removed: getSubscription, getPlans, getInvoices,
    // getInvoice, createPortalSession.)
}
```

> Scope note: the full `/ui/billing/*` and `/api/billing/*` surface is large
> (autopay, charge-once, refund, pay-balance, setup-intents, payment-issues,
> wallet deposit/withdraw, disputes, refund-requests, etc. — see section 5). The
> interface above covers the read/contract core needed to unblock
> `feature-billing`; mutating endpoints beyond `checkout_session` are enumerated
> in section 5 and may be added to `BillingApi` as their DTOs are needed. The
> acceptance bar ("payloads map, tested") applies to whichever DTOs ship.

The raw `suspend fun ... : Dto` return type assumes the project call adapter throws
on non-2xx and the repository layer (future) wraps calls in `ApiResult`. If the
established AND-027 convention is `suspend fun(): ApiResult<Dto>` via a custom
`CallAdapter.Factory`, the signatures adopt that form instead. **The convention is
inherited, not re-decided here** (see Open Question OQ-1).

A `BillingNetworkModule` Hilt `@Module` provides the interface:

```kotlin
@Module
@InstallIn(SingletonComponent::class)
internal object BillingNetworkModule {
    @Provides
    @Singleton
    fun provideBillingApi(retrofit: Retrofit): BillingApi =
        retrofit.create(BillingApi::class.java)
}
```

The injected `Retrofit` is the authenticated singleton built in AND-027 (cookie
jar + CSRF interceptor + Moshi converter + 20 s timeouts).

### 4.2 DTO layer (`core-network`)

All shapes below are reconciled against `src/api/types.ts` and the OpenAPI
component schemas. Money on this backend is consistently expressed in **integer
cents** (`*_cents`), NOT a generic `amount_minor` field — corrected throughout.

```kotlin
// CORRECTED: real Subscription (src/api/types.ts: Subscription). Note plan_id is
// REQUIRED (non-null), there is NO current_period_end / cancel_at_period_end /
// trial_end / seats. Period info is `next_billing_date` (ISO-8601 string) and
// the cadence is `billing_cycle`. The interface is open ([key:string]:unknown),
// so unknown keys must be tolerated by Moshi (ignoreUnknown is default-on).
@JsonClass(generateAdapter = true)
data class SubscriptionDto(
    @Json(name = "subscription_id") val subscriptionId: String,
    @Json(name = "plan_id") val planId: String,
    @Json(name = "status") val status: String,            // active|canceled|...
    @Json(name = "billing_cycle") val billingCycle: String? = null,
    @Json(name = "next_billing_date") val nextBillingDate: String? = null, // ISO-8601
)

// CORRECTED: subscriptions are returned as a list wrapper `{ items: [...] }`
// (src/api/endpoints/billing.ts: getSubscriptions). No cursor — limit only.
@JsonClass(generateAdapter = true)
data class SubscriptionListDto(
    @Json(name = "items") val items: List<SubscriptionDto> = emptyList(),
)

// NEW: replaces the fictional PlanCatalogDto. Real shape from BillingConfig.
@JsonClass(generateAdapter = true)
data class BillingConfigDto(
    @Json(name = "publishable_key") val publishableKey: String? = null,
    @Json(name = "currency") val currency: String,
)

// NEW: from BillingSettings.
@JsonClass(generateAdapter = true)
data class BillingSettingsDto(
    @Json(name = "autopay_enabled") val autopayEnabled: Boolean,
    @Json(name = "currency") val currency: String,
    @Json(name = "default_payment_method_id") val defaultPaymentMethodId: String? = null,
    @Json(name = "default_payment_token_id") val defaultPaymentTokenId: String? = null,
)

// NEW: from BillingBalance — all amounts in integer cents.
@JsonClass(generateAdapter = true)
data class BillingBalanceDto(
    @Json(name = "currency") val currency: String,
    @Json(name = "owed_pending_cents") val owedPendingCents: Long,
    @Json(name = "owed_settled_cents") val owedSettledCents: Long,
    @Json(name = "payments_pending_cents") val paymentsPendingCents: Long,
    @Json(name = "payments_settled_cents") val paymentsSettledCents: Long,
    @Json(name = "due_pending_cents") val duePendingCents: Long? = null,
    @Json(name = "due_settled_cents") val dueSettledCents: Long? = null,
    @Json(name = "updated_at") val updatedAt: Long? = null,  // epoch seconds
)

// CORRECTED: there is no Invoice resource. Financial history is the LEDGER.
// LedgerEntry shape from src/api/types.ts. `ts` and amounts are epoch/cents.
@JsonClass(generateAdapter = true)
data class LedgerEntryDto(
    @Json(name = "sk") val sk: String,
    @Json(name = "type") val type: String,
    @Json(name = "amount_cents") val amountCents: Long,
    @Json(name = "state") val state: String,
    @Json(name = "reason") val reason: String? = null,
    @Json(name = "ts") val ts: Long,                 // epoch (numeric)
)

// CORRECTED: ledger/payments responses are `{ items: [...] }`, limit-based,
// NO next_cursor (the prior InvoicePageDto.next_cursor was fictional).
@JsonClass(generateAdapter = true)
data class LedgerPageDto(
    @Json(name = "items") val items: List<LedgerEntryDto> = emptyList(),
)

// CORRECTED: real PaymentMethod (src/api/types.ts). Key field is
// `payment_method_id` (not `id`); adds method_type/label/priority/provider/
// provider_method_id/is_default. brand/last4/exp_* remain optional.
@JsonClass(generateAdapter = true)
data class PaymentMethodDto(
    @Json(name = "payment_method_id") val paymentMethodId: String,
    @Json(name = "method_type") val methodType: String,
    @Json(name = "label") val label: String? = null,
    @Json(name = "brand") val brand: String? = null,        // visa|mastercard|...
    @Json(name = "last4") val last4: String? = null,
    @Json(name = "exp_month") val expMonth: Int? = null,
    @Json(name = "exp_year") val expYear: Int? = null,
    @Json(name = "priority") val priority: Int,
    @Json(name = "provider") val provider: String? = null,
    @Json(name = "provider_method_id") val providerMethodId: String? = null,
    @Json(name = "is_default") val isDefault: Boolean,
)

// NEW: from WalletBalance — wallet_balance_cents.
@JsonClass(generateAdapter = true)
data class WalletBalanceDto(
    @Json(name = "wallet_balance_cents") val walletBalanceCents: Long,
    @Json(name = "currency") val currency: String,
    @Json(name = "updated_at") val updatedAt: Long? = null,
)

// CORRECTED: BillingCheckoutReq (verified against OpenAPI components.schemas.
// BillingCheckoutReq AND src/api/types.ts). amount_cents required; currency and
// description optional. The old plan_id/success_url/cancel_url shape was wrong.
@JsonClass(generateAdapter = true)
data class CheckoutSessionRequestDto(
    @Json(name = "amount_cents") val amountCents: Long,
    @Json(name = "currency") val currency: String? = null,
    @Json(name = "description") val description: String? = null,
)

// CORRECTED: checkout response `{ session_id, url }`
// (src/api/endpoints/billing.ts: createCheckoutSession). Confirmed.
@JsonClass(generateAdapter = true)
data class CheckoutSessionDto(
    @Json(name = "session_id") val sessionId: String,
    @Json(name = "url") val url: String,
)

// NEW: generic mutation envelope used by autopay/set-default/etc.
@JsonClass(generateAdapter = true)
data class OkRespDto(@Json(name = "ok") val ok: Boolean)
```

Removed as fictional: `PlanCatalogDto`, `PlanDto`, `InvoicePageDto`, `InvoiceDto`,
`InvoiceLineDto`, `PaymentMethodListDto`, `PortalSessionRequestDto`,
`PortalSessionDto`. None correspond to any real backend schema.

### 4.3 Domain models (`core-model`)

```kotlin
package com.testlogon.android.core.model.billing

import java.time.Instant

// Money holds integer cents (the backend's `*_cents`) + ISO-4217 currency.
data class Money(val cents: Long, val currency: String)

// CORRECTED: enum members reflect real/observed status strings. `billing_cycle`
// values (e.g. monthly/yearly) and ledger `state` values are not enumerated in
// types.ts (status/state/type are free-form strings), so we keep an UNKNOWN
// fallback and treat backend strings defensively. See OQ-3.
enum class SubscriptionStatus { ACTIVE, TRIALING, PAST_DUE, CANCELED, INCOMPLETE, UNKNOWN }

data class Subscription(
    val subscriptionId: String,
    val planId: String,
    val status: SubscriptionStatus,
    val billingCycle: String?,
    val nextBillingDate: Instant?,
)

data class BillingConfig(val publishableKey: String?, val currency: String)

data class BillingSettings(
    val autopayEnabled: Boolean,
    val currency: String,
    val defaultPaymentMethodId: String?,
    val defaultPaymentTokenId: String?,
)

// CORRECTED: balance is the real domain object (no invoices). All amounts Money.
data class BillingBalance(
    val owedPending: Money,
    val owedSettled: Money,
    val paymentsPending: Money,
    val paymentsSettled: Money,
    val duePending: Money?,
    val dueSettled: Money?,
    val updatedAt: Instant?,
)

// CORRECTED: LedgerEntry replaces Invoice/InvoiceLine. `type`/`state` kept as
// raw strings (free-form on backend); amount is Money; ts is Instant.
data class LedgerEntry(
    val sk: String,
    val type: String,
    val amount: Money,
    val state: String,
    val reason: String?,
    val timestamp: Instant?,
)
data class LedgerPage(val items: List<LedgerEntry>)

// CORRECTED: PaymentMethod uses paymentMethodId + the real fields.
data class PaymentMethod(
    val paymentMethodId: String,
    val methodType: String,
    val label: String?,
    val brand: String?,
    val last4: String?,
    val expMonth: Int?,
    val expYear: Int?,
    val priority: Int,
    val provider: String?,
    val isDefault: Boolean,
)

data class WalletBalance(val balance: Money, val updatedAt: Instant?)
data class CheckoutSession(val sessionId: String, val url: String)
```

Removed fictional models: `Plan`, `BillingInterval`, `Invoice`, `InvoiceStatus`,
`InvoiceLine`, `InvoicePage`, `PaymentMethods` (wrapper).

### 4.4 Mappers (`core-network`)

```kotlin
internal fun SubscriptionDto.toDomain() = Subscription(
    subscriptionId = subscriptionId,
    planId = planId,
    status = status.toSubscriptionStatus(),
    billingCycle = billingCycle,
    // CORRECTED: next_billing_date is an ISO-8601 STRING → Instant.
    nextBillingDate = nextBillingDate?.toInstantOrNull(),
)

internal fun String.toSubscriptionStatus() = when (lowercase()) {
    "active" -> SubscriptionStatus.ACTIVE
    "trialing" -> SubscriptionStatus.TRIALING
    "past_due" -> SubscriptionStatus.PAST_DUE
    "canceled", "cancelled" -> SubscriptionStatus.CANCELED
    "incomplete" -> SubscriptionStatus.INCOMPLETE
    else -> SubscriptionStatus.UNKNOWN
}

internal fun LedgerEntryDto.toDomain() = LedgerEntry(
    sk = sk,
    type = type,
    amount = Money(amountCents, /* currency from page/balance context */ "USD"),
    state = state,
    reason = reason,
    // CORRECTED: ts is an epoch NUMBER, not an ISO string → Instant.ofEpochSecond.
    timestamp = ts.toInstantFromEpochOrNull(),
)

internal fun PaymentMethodDto.toDomain() = PaymentMethod(
    paymentMethodId = paymentMethodId,
    methodType = methodType,
    label = label,
    brand = brand,
    last4 = last4,
    expMonth = expMonth,
    expYear = expYear,
    priority = priority,
    provider = provider,
    // CORRECTED: isDefault comes from the entry's own `is_default` flag — there
    // is no separate default_id wrapper to cross-reference.
    isDefault = isDefault,
)
```

Two distinct timestamp encodings exist on this backend and MUST be mapped
differently (a correction over the original single-helper assumption):

- **ISO-8601 strings** (`next_billing_date`) → `toInstantOrNull()`: parses with
  `DateTimeFormatter.ISO_OFFSET_DATE_TIME`, returns `null` (warn-logged) on
  failure so a malformed timestamp never crashes mapping.
- **Epoch numbers** (`ts`, `updated_at`) → `toInstantFromEpochOrNull()`:
  `Instant.ofEpochSecond(value)`; the unit (seconds vs. millis) is an OPEN
  QUESTION (OQ-3) to confirm from a live fixture before freezing.

`Money` is constructed from each `*_cents` value plus the surrounding object's
`currency` (balance/wallet/config carry `currency`; the ledger does not embed a
per-line currency, so the page/account currency is threaded in by the caller —
flagged as OQ-4).

## 5. API Contract

All paths are relative to dev base `http://18.222.237.167:8000` (plaintext HTTP,
unreliable host). Auth is via cookies + a `Bearer` access token; the shared
client also sets `X-CSRF-Token` from the `ui_csrf` cookie. **CORRECTION:** the web
client sets `X-CSRF-Token` on **every** request (GET included), not only POSTs —
see `src/api/client.ts` (the header is added unconditionally when the cookie
exists). The Android port may scope it to mutating verbs, but must not assume the
server only checks it on POST.

The table below is **corrected and verified** against `openapi.index.txt` and
`src/api/endpoints/billing.ts`. The original table's `/ui/billing/subscription`,
`/ui/billing/plans`, `/api/billing/invoices[/{id}]`, and
`/ui/billing/portal-session` rows were **fictional** (no such endpoints) and the
`/ui/billing/payment-methods` response shape and `checkout-session` path/body were
**wrong**.

| Verb | Path | Body | Response | Source |
|------|------|------|----------|--------|
| GET | `/ui/billing/subscriptions?limit=` | — | `{ items: SubscriptionDto[] }` | index L1199; billing.ts getSubscriptions |
| GET | `/ui/billing/config` | — | `BillingConfigDto` | index L1176; billing.ts getConfig |
| GET | `/ui/billing/settings` | — | `BillingSettingsDto` | index L1196; billing.ts getSettings |
| GET | `/ui/billing/balance` | — | `BillingBalanceDto` | index L1173; billing.ts getBalance |
| GET | `/ui/billing/ledger?limit=` | — | `{ items: LedgerEntryDto[] }` | index L1180; billing.ts getLedger |
| GET | `/ui/billing/payments?limit=` | — | `{ items: LedgerEntryDto[] }` | index L1191; billing.ts getPayments |
| GET | `/ui/billing/payment-methods` | — | `PaymentMethodDto[]` (bare array) | index L1185; billing.ts getPaymentMethods |
| GET | `/ui/billing/wallet` | — | `WalletBalanceDto` | index L1201; billing.ts getWallet |
| POST | `/ui/billing/checkout_session` | `CheckoutSessionRequestDto` (`amount_cents`,`currency?`,`description?`) | `{ session_id, url }` | index L1175; billing.ts createCheckoutSession; schema `BillingCheckoutReq` |

Mutating endpoints present in the backend but not yet in `BillingApi` (enumerate
when DTOs are added): `POST /ui/billing/autopay` (`SetAutopayReq`→`OkResp`),
`POST /ui/billing/payment-methods/default` (`SetDefaultReq`),
`POST /ui/billing/payment-methods/priority` (`SetPriorityReq`),
`DELETE /ui/billing/payment-methods/{id}`, `POST /ui/billing/pay-balance`
(`PayBalanceReq`), `POST /ui/billing/charge-once` (`StripeChargeReq`),
`POST /ui/billing/refund` (`StripeRefundReq`),
`POST /ui/billing/setup-intent/card`, `POST /ui/billing/setup-intent/us-bank`,
`POST /ui/billing/us-bank/verify-microdeposits`,
`GET/POST /ui/billing/payment-issues[...]`,
`POST /ui/billing/wallet/deposit|withdraw`. Each `/ui/billing/*` path also has an
`/api/billing/*` twin (index L18–L56); the web client uses the `/ui/*` variants.

Example `GET /ui/billing/subscriptions` 200 (CORRECTED shape):

```json
{
  "items": [
    {
      "subscription_id": "sub_9f2",
      "plan_id": "plan_pro_monthly",
      "status": "active",
      "billing_cycle": "monthly",
      "next_billing_date": "2026-07-01T00:00:00Z"
    }
  ]
}
```

Example `GET /ui/billing/ledger` 200 (CORRECTED — ledger, not invoices):

```json
{
  "items": [
    { "sk": "L#001", "type": "charge", "amount_cents": 4900,
      "state": "settled", "reason": "Pro plan (May)", "ts": 1746057600 }
  ]
}
```

Example `GET /ui/billing/balance` 200:

```json
{
  "currency": "USD",
  "owed_pending_cents": 0, "owed_settled_cents": 4900,
  "payments_pending_cents": 0, "payments_settled_cents": 4900,
  "updated_at": 1746057600
}
```

Error envelopes follow the FastAPI shape and are mapped by the shared error mapper.
The 422 validation shape is **confirmed** (every billing endpoint declares
`422:HTTPValidationError` in the index); the string and object forms are handled
by `normalizeErrorDetail` in `src/api/client.ts`:

```json
{ "detail": "No active subscription" }
{ "detail": [{ "loc": ["body","amount_cents"], "msg": "field required", "type": "value_error.missing" }] }
{ "detail": { "code": "card_declined", "message": "Your card was declined" } }
```

Billing-relevant statuses to handle (no new client code, but tested): **`422`
Unprocessable Entity is the declared validation status for all billing endpoints**
(the original spec's emphasis on 402/409/404 is an UNVERIFIED assumption — those
codes are NOT declared in the OpenAPI responses for the `/ui/billing/*` GET/POST
endpoints, which only list `200` and `422`; the webhook endpoints declare
`400/409/413/415/404/501`). `403` carries a typed `{detail:{code,...}}` envelope
(e.g. `role_required_scope`, `geo_blocked`) per `client.ts`. `401` is handled by
the AND-027 refresh-and-retry interceptor (single-shot `POST /ui/session/refresh`,
verified in `client.ts`).

Field names, nullability, and enum members above are reconciled against
`openapi.pretty.json` and `src/api/types.ts`; the verification step in section 11
captures live fixtures to confirm timestamp units (OQ-3) and ledger currency
threading (OQ-4).

## 6. Data & State Management

This ticket holds **no state**. There is no Room entity, no DataStore key, and no
StateFlow. The `BillingApi` is stateless; the only "state" is the inherited OkHttp
cookie jar from AND-027, which is out of this ticket's scope.

Pagination state: **CORRECTED** — the billing list endpoints (`ledger`,
`payments`, `subscriptions`, `payment-issues`) are **limit-based, not
cursor-based**. They accept a `limit` query param (default 50 in the web client)
and return `{ items: [...] }` with **no `next_cursor`** field. (Cursor pagination
does exist elsewhere in the backend — e.g. `internal/dev-tools/billing/ledger` and
admin audit endpoints — but not on the user-facing `/ui/billing/*` lists this
ticket targets.) Any future Paging-3 wiring in `feature-billing` would therefore
be offset/limit-style, not keyset; that work is out of scope here.

Caching and offline/stale presentation are likewise deferred to `feature-billing`
+ a `core-data` billing repository. This contract is built so those can add a
Room mirror later without altering DTO field names.

## 7. Error Handling & Resilience

- **Idempotent GETs** (`subscriptions`, `config`, `settings`, `balance`,
  `ledger`, `payments`, `payment-methods`, `wallet`) are eligible for the bounded
  backoff retry policy configured
  in the shared OkHttp client (AND-027): retry on connect/read timeout and 5xx,
  capped (e.g., 3 attempts, jittered backoff), with a ~20 s per-attempt timeout
  given the unreliable dev host.
- **POST endpoints** (`checkout_session`, and the future mutating set: autopay,
  set-default, charge-once, pay-balance, wallet deposit/withdraw, etc.) are
  **not** retried automatically — they are mutating and may create duplicate
  sessions/charges. They fail fast to `ApiResult.Error`. Several mutating request
  bodies carry an `idempotency_key` (`PayBalanceReq`, `StripeChargeReq`,
  `WalletDepositReq`) the client should populate to make server-side retries safe.
- **401** triggers the single-shot `POST /ui/session/refresh` then one retry,
  entirely within the inherited interceptor; `BillingApi` is unaware.
- **Mapping resilience:** mappers never throw. Unknown enum strings → `UNKNOWN`;
  unparseable timestamps → `null` (warn-logged); missing collections → empty.
  This guarantees a backend adding a new `status` value never crashes the client.
- **Error typing:** the shared `ApiError` mapper converts all three `detail`
  shapes (string, `[{msg}]`, `{code,message}`) into typed errors. **CORRECTED:**
  the declared error status for `/ui/billing/*` is `422` (validation), plus the
  shared `401`/`403` handling; `402`/`409`/`404` are NOT declared on these
  endpoints in OpenAPI, so tests assert `422` + the `{code,message}` 403 shape
  rather than the previously-assumed `402`/`409`. Webhook endpoints (out of scope)
  are the only billing paths declaring `409`/`404`.

## 8. Security & Privacy

- **No new auth surface.** Billing rides the existing cookie session + CSRF echo.
  No tokens, keys, or credentials are introduced or stored by this ticket.
- **PII / cardholder data:** DTOs intentionally carry only `brand`, `last4`,
  `exp_month`, `exp_year` — never PAN, CVV, or full card data (those live with the
  PCI-scoped processor). `last4` and expiry are display-safe but still sensitive;
  they must NOT be written to logs (see section 10).
- **Hosted URLs:** the checkout-session `url` (CORRECTED — there is no
  `hosted_invoice_url` field in the real schema; the only capability-bearing URL
  in scope is the checkout `url`, and Stripe/CCBill setup `client_secret` values
  from the setup-intent endpoints) are capability-bearing — treat as secrets in
  logs; never emit at INFO.
- **Transport:** dev backend is plaintext HTTP. Production must be HTTPS; the
  network security config (separate infra ticket) must restrict cleartext to the
  dev host only. This ticket adds no cleartext exemptions itself.

## 9. Accessibility & i18n

No UI is produced, so screen-level a11y is N/A and owned by the downstream
`feature-billing` ticket. Two i18n-relevant design choices are made here to enable
correct downstream formatting:

- **Money** is kept as integer cents + ISO-4217 `currency`, never a pre-formatted
  string, so the UI can format with `NumberFormat.getCurrencyInstance(locale)`.
  (CORRECTED: backend amounts are `*_cents`.)
- **Timestamps** are `Instant` (UTC), so the UI can render in the device locale/zone.

No user-facing strings are introduced by this ticket.

## 10. Telemetry & Logging

- Reuse the shared OkHttp `HttpLoggingInterceptor`, which must run at `BASIC`
  (not `BODY`) for billing paths, or with a redactor, to avoid logging `last4`,
  hosted URLs, and checkout/portal URLs.
- Mapper warnings (unknown enum, bad timestamp) log at `WARN` via the shared
  `Logger`, **without** payload values — only the field name and the offending
  token category (not the raw token if it could be sensitive).
- No analytics events are emitted from the network layer; billing funnel
  analytics belong to `feature-billing`.
- A debug-only assertion (BuildConfig.DEBUG) may log a one-line count of unknown
  enum hits to catch contract drift early.

## 11. Testing Strategy

Acceptance is "Billing payloads map (tested)" — tests are the primary deliverable.

1. **Moshi round-trip unit tests** (`core-network`, JVM, no Android): for each
   DTO, deserialize a captured fixture JSON, assert every field, re-serialize, and
   assert structural equality. Include fixtures with `null` optionals and missing
   keys to prove defaults.
2. **Mapper tests:** assert each `toDomain()` produces the expected domain object,
   including: unknown `status`/`interval` → `UNKNOWN`; malformed `issued_at` →
   `null`; empty/missing `lines`/`methods` → empty list; `Money` minor-unit +
   currency construction; `isDefault` resolution by `defaultId`.
3. **`BillingApi` MockWebServer tests** (mirrors AND-027 pattern): for each
   endpoint, enqueue a fixture response and assert the recorded request path,
   verb, query params, and (for POSTs) request body JSON match the contract.
   Assert the `X-CSRF-Token` header is present on POSTs.
4. **Error-mapping tests:** enqueue `422` (with each `detail` shape: string,
   `[{msg}]`, `{code,message}`) and `403 {detail:{code,...}}`; assert the
   resulting typed `ApiError`. (CORRECTED from the previously-assumed 402/409/404,
   which are not declared on these endpoints.)
5. **Live verification (non-CI, documented):** run a one-off against
   `http://18.222.237.167:8000` and `/openapi.json` to capture real fixtures and
   confirm field names/nullability; commit the sanitized fixtures under
   `core-network/src/test/resources/billing/`.

Fixtures live in `core-network/src/test/resources/billing/*.json`. Target: 100%
of DTOs and mappers covered.

## 12. Dependencies & Sequencing

- **Depends on AND-027 (AuthApi / session endpoints):** provides the
  authenticated `Retrofit` singleton, cookie jar, CSRF interceptor, `ApiResult`
  type, shared error mapper, retry/timeout policy, and the MockWebServer test
  harness. `BillingApi` cannot be wired without it. (AND-027 itself depends on
  AND-026, the network/OkHttp foundation.)
- **Blocks:** the future `feature-billing` UI/ViewModel/repository ticket(s) in
  epic E31 — those consume the `BillingApi` and `core-model.billing` types frozen
  here.
- **No other in-ticket dependencies.** This is a leaf data-contract ticket.

## 13. Risks & Open Questions

- **OQ-1 (return type convention):** Does AND-027 standardize on
  `suspend fun(): Dto` (call adapter throws) or `suspend fun(): ApiResult<Dto>`
  (call adapter wraps)? Adopt whichever AND-027 established; do not introduce a
  third pattern. Resolve before merging.
- **OQ-2 (path namespacing) — RESOLVED:** The backend exposes BOTH `/ui/billing/*`
  and `/api/billing/*` as near-mirror twins (index L18–L56 vs L1171–L1203). The
  web client uses the `/ui/*` variants exclusively (`src/api/endpoints/billing.ts`),
  so the Android port targets `/ui/billing/*`. The earlier assumed split (`ui/*`
  for browser endpoints, `api/*` for invoice resources) was WRONG — there is no
  invoice resource and both prefixes carry the same operations.
- **OQ-3 (money & timestamp representation):** Money is integer **cents**
  (`*_cents`) — RESOLVED via `types.ts`/OpenAPI; no decimal strings. **Still
  open:** the unit of epoch timestamps (`ts`, `updated_at`) — seconds vs.
  milliseconds — must be confirmed from a live fixture before freezing
  `toInstantFromEpochOrNull()`.
- **OQ-4 (ledger currency):** `LedgerEntry` has no per-entry `currency`; only
  `balance`/`wallet`/`config`/`settings` carry `currency`. Confirm whether the
  ledger is single-currency per account (so the account currency can be threaded
  into each `Money`) or whether entries can mix currencies. Verify via fixtures.
- **Risk — contract drift:** dev backend is unreliable and may evolve. Mitigated
  by `UNKNOWN` enum fallbacks and total mappers, plus the debug drift counter.
- **Risk — fixture staleness:** captured fixtures may lag the live schema; the
  documented live-verification step (section 11.5) must be re-run if billing tests
  start failing against staging.

## 14. Acceptance Criteria

1. `BillingApi` exists in `com.testlogon.android.core.network.billing` with a
   `suspend` function for each of the 9 endpoints in the section-5 table
   (subscriptions, config, settings, balance, ledger, payments, payment-methods,
   wallet, checkout_session), paths/verbs/query params matching the contract —
   verified by MockWebServer tests. (CORRECTED from the original fictional
   7-endpoint set.)
2. All billing DTOs exist with Moshi codegen adapters and deserialize the captured
   fixtures with every field asserted (including null/missing-key defaults).
3. All `core-model.billing` domain models and total `toDomain()` mappers exist;
   unknown enums → `UNKNOWN`, bad timestamps → `null`, missing collections →
   empty — proven by mapper unit tests.
4. Requests carry `X-CSRF-Token` (the web client sends it on all verbs; the port
   may scope to mutating verbs but must send it on `checkout_session` POST); the
   `BillingApi` reuses the AND-027 authenticated Retrofit and adds no auth code.
5. `422` validation envelopes (all three `detail` shapes: string, `[{msg}]`,
   `{code,message}`) and the `403 {detail:{code,...}}` shape map to the expected
   typed `ApiError` — tested. (CORRECTED: `402`/`409`/`404` are not declared on
   `/ui/billing/*` GET/POST endpoints, so they are not asserted here.)
6. `BillingNetworkModule` provides `BillingApi` via Hilt and the module compiles
   and is injectable.
7. No UI, Room, or DataStore code is added by this ticket.
8. The full test suite (round-trip, mapper, MockWebServer, error-mapping) passes
   in CI.

## 15. Definition of Done

- All acceptance criteria in section 14 are met and CI is green.
- Code lives under `core-network` / `core-model` with the exact
  `com.testlogon.android.*` packages above; no leakage of Retrofit/Moshi types
  into `core-model`.
- Fixtures captured from the live dev backend / `/openapi.json` are committed
  (sanitized) under `core-network/src/test/resources/billing/`, and OQ-1/OQ-2/OQ-3
  are resolved and reflected in the final field names and signatures.
- `HttpLoggingInterceptor` is confirmed not to log `last4` or capability URLs for
  billing paths.
- Ktlint/Detekt pass; KSP generates Moshi adapters with no warnings.
- The contract is documented sufficiently for `feature-billing` to consume it
  without re-reading the backend (KDoc on `BillingApi` and the domain models).
- Reviewed and merged to branch `android-port`.

> Word count note: prose is within the 2,200–2,800 target; the elevated raw count
> reflects the embedded Kotlin/JSON contract blocks, which are load-bearing.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the authoritative source. Sources are
the OpenAPI index (`reference/openapi.index.txt`, cited by line `L#` and the
`METHOD /path`), the OpenAPI full spec (`reference/openapi.pretty.json`, cited by
`components.schemas.<Name>`), and the frontend reference app under
`reference/src/`. "framework ref" tags Android-platform choices.

1. **`GET /ui/billing/subscriptions` (plural, returns `{items:[...]}`)** — Verified
   (Corrected from spec's `/ui/billing/subscription`). Source: index L1199
   `GET /ui/billing/subscriptions`; `src/api/endpoints/billing.ts: getSubscriptions`
   (`api.get<{ items: Subscription[] }>`).
2. **`SubscriptionDto` shape (`subscription_id`, `plan_id` required, `status`,
   `billing_cycle?`, `next_billing_date?`; no period_end/cancel_at/trial/seats)** —
   Corrected. Source: `src/api/types.ts: Subscription` (L658–665).
3. **`/ui/billing/plans` plan/price catalog** — Corrected (does not exist; removed,
   replaced by `BillingConfig`). Source: absent from index (grep `billing` over
   `reference/openapi.index.txt`); `src/api/endpoints/billing.ts: getConfig` →
   `/ui/billing/config`.
4. **`GET /ui/billing/config` → `BillingConfigDto{publishable_key?,currency}`** —
   Verified. Source: index L1176; `src/api/types.ts: BillingConfig` (L610–614).
5. **`GET /ui/billing/settings` → `BillingSettingsDto`** — Verified. Source: index
   L1196; `src/api/types.ts: BillingSettings` (L616–621).
6. **`GET /ui/billing/balance` → `BillingBalanceDto` (all `*_cents`)** — Verified.
   Source: index L1173; `src/api/types.ts: BillingBalance` (L623–632).
7. **`/api/billing/invoices` and `/api/billing/invoices/{id}`** — Corrected (do not
   exist; no invoice resource under billing). Source: absent from index; financial
   history is `GET /ui/billing/ledger` (index L1180) and `GET /ui/billing/payments`
   (index L1191), both `{items:[...]}` (`src/api/endpoints/billing.ts: getLedger`,
   `getPayments`).
8. **Ledger/payments are limit-based `{items:[...]}`, NOT cursor `next_cursor`** —
   Corrected. Source: index L1180/L1191 (`params=limit,...`, no cursor);
   `src/api/endpoints/billing.ts: getLedger` (`{ limit: String(limit) }`).
   (Keyset/cursor pagination exists only on `internal/dev-tools/billing/ledger`,
   index L283 — out of scope.)
9. **`LedgerEntryDto` shape (`sk`,`type`,`amount_cents`,`state`,`reason?`,`ts`)** —
   Verified. Source: `src/api/types.ts: LedgerEntry` (L648–656).
10. **`GET /ui/billing/payment-methods` → bare `PaymentMethod[]` (not a wrapper
    with `default_id`/`methods`)** — Corrected. Source: index L1185;
    `src/api/endpoints/billing.ts: getPaymentMethods` (`api.get<PaymentMethod[]>`).
11. **`PaymentMethodDto` key field `payment_method_id` (+ `method_type`,`priority`,
    `provider`,`is_default`; not `id`)** — Corrected. Source: `src/api/types.ts:
    PaymentMethod` (L634–646).
12. **`is_default` is a per-item flag (no separate `default_id`)** — Corrected.
    Source: `src/api/types.ts: PaymentMethod.is_default` (L645).
13. **`POST /ui/billing/checkout_session` (UNDERSCORE) → `{session_id,url}`** —
    Corrected (spec had hyphen `checkout-session`). Source: index L1175;
    `src/api/endpoints/billing.ts: createCheckoutSession`.
14. **Checkout request body = `BillingCheckoutReq{amount_cents, currency?,
    description?}` (NOT `plan_id`/`success_url`/`cancel_url`)** — Corrected.
    Source: `components.schemas.BillingCheckoutReq` (openapi.pretty.json L7364);
    `src/api/types.ts: BillingCheckoutReq` (L767–771).
15. **`POST /ui/billing/portal-session`** — Corrected (does not exist; removed).
    Source: absent from index (no `portal` row under billing).
16. **`GET /ui/billing/wallet` → `WalletBalanceDto{wallet_balance_cents,currency,
    updated_at?}`** — Verified. Source: index L1201; `src/api/types.ts:
    WalletBalance` (L3063–3067).
17. **Money is integer cents (`*_cents`), not "minor units"/decimal strings** —
    Verified/Corrected. Source: every billing amount field in `src/api/types.ts`
    ends in `_cents`; `components.schemas.BillingCheckoutReq.amount_cents`
    `type: integer` (openapi.pretty.json L7366–7368).
18. **CSRF: `ui_csrf` cookie echoed as `X-CSRF-Token` on ALL requests (not only
    POST)** — Corrected (spec said POST-only). Source: `src/api/client.ts` L168–171
    (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", ...)` set
    unconditionally per request).
19. **401 → single-shot `POST /ui/session/refresh` then one retry** — Verified.
    Source: `src/api/client.ts: refreshSession` (L121–130) and the 401 branch
    (L194–237). Matches AND-027 inheritance claim.
20. **403 error envelope is typed `{detail:{code,...}}` (e.g. `role_required_scope`,
    `geo_blocked`)** — Verified. Source: `src/api/client.ts: mapAuthorizationError`
    (L34–64) and the 403 branch (L240–255).
21. **FastAPI `detail` has three shapes (string | `[{msg}]` | `{code,message}`)** —
    Verified. Source: `src/api/client.ts: normalizeErrorDetail` (L66–102) handles
    all three; index shows `422:HTTPValidationError` for every billing endpoint.
22. **Declared error statuses for `/ui/billing/*` GET/POST are `200` + `422`
    (NOT 402/409/404)** — Corrected (spec emphasized 402/409/404). Source: index
    L1173–L1201 (`resp=200:;422:HTTPValidationError`). `409`/`404`/`413`/`415`
    appear only on webhook endpoints (index L53–L55), which are out of scope.
23. **Two timestamp encodings: ISO-8601 string (`next_billing_date`) vs epoch
    number (`ts`,`updated_at`)** — Verified (encoding) / Unverified-assumption
    (epoch unit). Source: `src/api/types.ts` (`next_billing_date?: string` L663;
    `ts: number` L654; `updated_at?: number` L631). Epoch seconds-vs-millis is
    unconfirmed (OQ-3).
24. **Both `/ui/billing/*` and `/api/billing/*` exist as twins; web client uses
    `/ui/*`** — Verified. Source: index L18–L56 (`/api/billing/*`) vs L1171–L1203
    (`/ui/billing/*`); all `src/api/endpoints/billing.ts` calls use `/ui/billing/`.
25. **Moshi 1.15 + KSP codegen for DTOs; Retrofit 2.11 / OkHttp 4.12; Hilt module
    provides `BillingApi` from the AND-027 `Retrofit`** — Unverified-assumption
    (project-internal stack/AND-027 inheritance; no source in this repo). framework
    ref: Moshi codegen (`https://github.com/square/moshi#codegen`), Retrofit
    (`https://square.github.io/retrofit/`).
26. **`ApiResult<T>` sealed type, shared error mapper, retry/timeout policy,
    cookie jar inherited from AND-027** — Unverified-assumption (AND-027 artifacts
    not in the provided sources). Must be confirmed against the AND-027
    implementation before merge (OQ-1).

### Corrections made

- Replaced fictional endpoints with real ones: `subscription`→`subscriptions`
  (list); removed `plans` (→`config`); removed `/api/billing/invoices[/{id}]`
  (→`ledger`/`payments`); removed `/ui/billing/portal-session`; fixed
  `checkout-session`→`checkout_session` (underscore). (Claims 1,3,7,13,15)
- Corrected DTO shapes: `SubscriptionDto`, `PaymentMethodDto`
  (`payment_method_id`, `is_default`, bare-array response), invoice→`LedgerEntry`,
  added `BillingConfig/Settings/Balance/Wallet` DTOs, fixed `CheckoutSessionRequest`
  to `amount_cents`-based. (Claims 2,9,10,11,12,14)
- Money corrected from "minor units"/decimal to integer **cents**. (Claim 17)
- Pagination corrected from cursor (`next_cursor`) to limit-based. (Claim 8)
- CSRF corrected: sent on all requests, not POST-only. (Claim 18)
- Error statuses corrected: assert `422`+`403{code}`, not `402/409/404`.
  (Claims 5/22)
- Added dual timestamp handling (ISO string vs epoch number). (Claim 23)
- Resolved OQ-2 (path namespacing) and partially OQ-3 (money=cents). Added OQ-4
  (ledger currency).

### Open assumptions

- **OQ-1 / AND-027 inheritance** (claims 25,26): `ApiResult<T>`, the call-adapter
  return convention, cookie jar, shared error mapper, retry policy, and
  MockWebServer harness are assumed from AND-027 but are NOT in the provided
  sources — unverifiable here; confirm against AND-027 before merge.
- **OQ-3 epoch unit**: `ts`/`updated_at` are numeric but seconds-vs-milliseconds is
  not stated in `types.ts` or OpenAPI — needs a live fixture.
- **OQ-4 ledger currency**: `LedgerEntry` has no per-entry `currency`; whether the
  account is single-currency is unconfirmed.
- **Enum membership**: backend `status`/`state`/`type`/`billing_cycle` are
  free-form strings in `types.ts` (no `enum` constraint exposed), so the
  `SubscriptionStatus` member list is an assumption guarded by `UNKNOWN`.
- **`/openapi.json` live URL & dev host `http://18.222.237.167:8000`**: copied from
  the spec; not re-fetched (live host unreachable from this review environment).

## 17. Test Plan

All cases target the data-plane deliverable (Retrofit `BillingApi`, Moshi DTOs,
`toDomain()` mappers, Hilt module). Because the ticket produces no UI, no device
hardware is required: the suite is JVM/Robolectric + MockWebServer, runnable on the
**JVM unit** target with no device. The headless emulator `test35` is used only for
the Hilt/instrumented injection smoke test; the **physical Galaxy A15** is not
required for any case (noted per-case). IDs are `TC-AND-223-NN`.

- **TC-AND-223-01** — Type: contract/MockWebServer. Target: JVM unit (MockWebServer,
  no device). Preconditions: `BillingApi` built against MockWebServer base URL.
  Steps: enqueue 200 fixtures and call `getSubscriptions(limit=50)`, `getConfig()`,
  `getSettings()`, `getBalance()`, `getLedger()`, `getPayments()`,
  `getPaymentMethods()`, `getWallet()`. Expected: each recorded request has the
  exact path (`/ui/billing/subscriptions`, `/ui/billing/config`, …), verb `GET`,
  and `getSubscriptions`/`getLedger`/`getPayments` carry `?limit=50`. Traces: AC-1.
- **TC-AND-223-02** — Type: unit (Moshi round-trip). Target: JVM unit. Preconditions:
  fixtures in `core-network/src/test/resources/billing/`. Steps: deserialize each
  DTO fixture, assert every field, re-serialize, assert structural equality.
  Include a `payment_methods.json` that is a **bare JSON array**. Expected: all
  fields populated; bare array deserializes to `List<PaymentMethodDto>`. Traces:
  AC-2.
- **TC-AND-223-03** — Type: unit (Moshi defaults). Target: JVM unit. Preconditions:
  fixtures with `null` optionals and missing keys (e.g. subscription without
  `billing_cycle`/`next_billing_date`, balance without `due_*_cents`/`updated_at`).
  Steps: deserialize. Expected: missing/`null` optionals map to `null`; missing
  list keys default to empty list; required fields present. Traces: AC-2.
- **TC-AND-223-04** — Type: unit (mapper). Target: JVM unit. Steps: map each DTO via
  `toDomain()` for a fully-populated fixture. Expected: `Money` built from `*_cents`
  + currency; `SubscriptionStatus.ACTIVE` for `"active"`; `PaymentMethod.isDefault`
  from `is_default`; `nextBillingDate` parsed from ISO-8601. Traces: AC-3.
- **TC-AND-223-05** — Type: unit (mapper resilience). Target: JVM unit. Steps: map a
  subscription with `status="some_new_value"`, a ledger entry with malformed/zero
  `ts`, and empty `items`. Expected: status → `SubscriptionStatus.UNKNOWN` (no
  throw); bad timestamp → `null` (warn-logged); empty items → empty list. Traces:
  AC-3.
- **TC-AND-223-06** — Type: unit (timestamp encodings). Target: JVM unit. Steps: map
  `next_billing_date` (ISO string) and `ts`/`updated_at` (epoch number) through
  their respective helpers. Expected: ISO → correct `Instant`; epoch → correct
  `Instant` (asserting the chosen seconds unit per OQ-3); invalid inputs → `null`.
  Traces: AC-3.
- **TC-AND-223-07** — Type: contract/MockWebServer. Target: JVM unit. Steps: call
  `createCheckoutSession(CheckoutSessionRequestDto(amount_cents=4900,
  currency="USD"))`; enqueue `{session_id,url}`. Expected: recorded request is
  `POST /ui/billing/checkout_session` (underscore), body JSON is
  `{"amount_cents":4900,"currency":"USD"}` (no `plan_id`/`success_url`), response
  maps to `CheckoutSession(sessionId,url)`. Traces: AC-1, AC-2.
- **TC-AND-223-08** — Type: contract/MockWebServer (security/CSRF). Target: JVM unit.
  Preconditions: shared client configured with a `ui_csrf` cookie value. Steps:
  perform the `checkout_session` POST. Expected: recorded request carries
  `X-CSRF-Token` equal to the cookie value, plus the inherited auth cookie/Bearer;
  `BillingApi` itself contains no auth code. Traces: AC-4.
- **TC-AND-223-09** — Type: contract/MockWebServer (error mapping). Target: JVM unit.
  Steps: enqueue `422` three ways — `detail` as string, as `[{loc,msg,type}]`, and
  as `{code,message}` — for `checkout_session`. Expected: each maps to the typed
  `ApiError` with the normalized message / preserved `code` per the shared mapper.
  Traces: AC-5.
- **TC-AND-223-10** — Type: contract/MockWebServer (403 typed envelope). Target: JVM
  unit. Steps: enqueue `403 {"detail":{"code":"role_required_scope",
  "required_scope":"billing_support"}}`. Expected: typed `ApiError` carrying the
  `code` (and humanized scope), not a generic failure. Traces: AC-5.
- **TC-AND-223-11** — Type: integration (401 refresh-and-retry). Target: JVM unit
  (MockWebServer with two enqueued responses + a refresh response). Preconditions:
  authenticated session state. Steps: enqueue `401`, then a `200` for the retry,
  with `POST /ui/session/refresh` succeeding. Call `getBalance()`. Expected: client
  issues `POST /ui/session/refresh` exactly once, retries the original request once,
  and returns the `200` body; a second `401` surfaces as auth error. Traces: AC-4,
  AC-5.
- **TC-AND-223-12** — Type: integration (flaky-host / offline & retry). Target: JVM
  unit (MockWebServer; use `SocketPolicy`/`shutdown` to simulate timeout/connection
  failure). Steps: for an idempotent GET (`getLedger`), simulate a connect/read
  timeout then a `200`; for the `checkout_session` POST, simulate a timeout.
  Expected: the GET retries within the bounded policy and ultimately succeeds (or
  returns `ApiResult.Error` after the cap); the POST does NOT auto-retry and fails
  fast. Also assert a total network failure maps to a typed connectivity error.
  Traces: AC-5, AC-8.
- **TC-AND-223-13** — Type: instrumented (Hilt injection smoke). Target: headless
  emulator `test35` (API 35) — does NOT require the physical device. Steps: build
  the Hilt graph and inject `BillingApi` via `BillingNetworkModule`; assert
  non-null and that it was created from the singleton `Retrofit`. Expected: module
  compiles, graph resolves, `BillingApi` injectable. Traces: AC-6.
- **TC-AND-223-14** — Type: unit (logging redaction). Target: JVM unit. Steps: run
  the shared `HttpLoggingInterceptor` (BASIC/redactor) over a payment-methods
  response and a checkout response; capture log output. Expected: `last4`, card
  expiry, and the checkout `url`/`client_secret` never appear in logs. Traces:
  AC-7 (no UI/Room/DataStore — verified by inspection that this case adds none),
  plus the section-8/10 security requirement.

### Coverage matrix

| AC (section 14) | Covered by |
|-----------------|------------|
| AC-1 (BillingApi endpoints/paths/verbs/params) | TC-01, TC-07 |
| AC-2 (DTOs deserialize, every field, defaults) | TC-02, TC-03, TC-07 |
| AC-3 (domain models + total mappers) | TC-04, TC-05, TC-06 |
| AC-4 (CSRF on POST; reuses AND-027 Retrofit, no auth code) | TC-08, TC-11 |
| AC-5 (422 + 403 error envelopes → typed ApiError) | TC-09, TC-10, TC-11, TC-12 |
| AC-6 (Hilt module provides BillingApi, injectable) | TC-13 |
| AC-7 (no UI/Room/DataStore added) | TC-14 (inspection) |
| AC-8 (full suite — round-trip, mapper, MockWebServer, error — green in CI) | TC-01…TC-12 (suite) |
