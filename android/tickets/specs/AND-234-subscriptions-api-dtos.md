---
id: AND-234
title: Subscriptions API + DTOs
milestone: M5
epic: E32
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-027]
blocks: [AND-235]
---

# AND-234 — Subscriptions API + DTOs

## 1. Overview & Goal

This ticket delivers the typed HTTP seam and Moshi-backed DTOs for the
TestLogon **subscriptions** surface: listing the subscription **plans** a creator
offers (the product is called a "plan", not a "tier" — verified), reading the
current viewer's active **subscription(s)**, and the subscribe / change-plan /
cancel mutations that drive the M5 "Subscription tiers + manage" screen (E32). It
is the native-Android equivalent of the web reference
`frontend/src/api/endpoints/subscriptions.ts`. [REVIEW 2026-06-06: the concrete
paths/verbs/DTOs in this spec were corrected against the backend OpenAPI and the
web client — see the banners in §4/§5 and the audit in §16.]

Scope, verbatim from the backlog: *`subscriptions.ts` endpoints/DTOs.* The single
acceptance criterion is: *Tiers/subs map (tested)* — i.e. the tier list and the
viewer-subscription payloads must (de)serialize exactly the documented JSON and be
callable end-to-end, proven with `MockWebServer`.

This is a **transport + DTO definition** ticket. It owns:
- the immutable Moshi `@JsonClass(generateAdapter = true)` DTOs that model the
  subscriptions wire format (`SubscriptionTier`, `Subscription`, the request
  bodies, and the list/envelope responses), in `core-model`;
- the Retrofit `SubscriptionsApi` interface (verbs, paths, `@Body`/`@Path`
  bindings) in `core-network`;
- the Hilt provider that constructs the service from the shared Retrofit.

It deliberately does **not** own: the repository that wraps these calls in
`ApiResult<T>` and applies caching/offline policy (AND-235, downstream),
ViewModels/Compose UI, the persistent cookie jar (AND-011), CSRF injection
(AND-012), the 401-refresh `Authenticator` (AND-013), `ApiResult`/error mapping
(AND-015/AND-018), or any payment-provider/checkout flow (M5 billing, separate
epic). Those attach to the shared `OkHttpClient` or live in higher layers and take
effect for `SubscriptionsApi` calls without changes here.

The deliverable: compiling DTOs + `SubscriptionsApi` + its Hilt provider, plus a
`MockWebServer`/round-trip test suite asserting each endpoint's verb, resolved
path, request body shape, and decoded response — with explicit coverage of the
**tiers** list and the **viewer-subscription** mapping.

## 2. Context & References

- **Repo / location:** `spannella/testlogon`, monorepo subfolder `android/`,
  branch `android-port`. DTOs land in **`core-model`** under
  `com.testlogon.android.core.model.subscription`; the Retrofit interface +
  provider land in **`core-network`** under
  `com.testlogon.android.core.network.subscription`.
- **Canonical package:** `com.testlogon.android` everywhere.
- **Stack pins relevant here:** Kotlin 2.0.21, Retrofit **2.11.0**, OkHttp
  **4.12.0**, Moshi **1.15.x** (codegen via KSP), Hilt (KSP), Coroutines, JDK 17,
  minSdk 24 / compileSdk 35, AGP 8.7.3 / Gradle 8.9.
- **Module layering:** `app -> feature-* -> core-*`. `SubscriptionsApi` lives in
  `core-network`, consumes DTOs from `core-model`, and is consumed by the
  subscriptions repository in `core-data` (AND-235). No `feature-*`/`app` symbols
  leak into `core-network`/`core-model`.
- **Upstream dependency — AND-027 (AuthApi / session endpoints):** establishes the
  authenticated cookie-based session that the `/api/subscriptions/*` and
  `/api/plans/*` calls ride on. [CORRECTED: the endpoints live under `api/…`, not
  `ui/subscriptions/…`.] These calls carry the session cookies plus the `ui_csrf`
  → `X-CSRF-Token` header (mutations) injected by AND-012 by the shared transport,
  and a `401` triggers the AND-013 refresh-then-retry (web `/ui/session/refresh`).
  **[CORRECTED — additional auth header]** The subscription server **also**
  requires an **`X-User-Id`** header on the authenticated endpoints
  (`subscriptions.ts: userIdHeader()`; OpenAPI `params=…,x-user-id`). This is NOT
  cookie/CSRF and is NOT supplied by AND-012; this ticket DOES surface it (as a
  per-method `@Header`, or via a shared interceptor — see §4.5/§16). The public
  plan-list endpoint omits it.
- **Transitive upstream:** AND-026/AND-010 (shared `Moshi`, adapter-set hook and
  Retrofit/Moshi converter), AND-009 (shared `OkHttpClient`, redacting logger,
  ~20s timeouts), AND-006 (`BuildConfig.API_BASE_URL`). Base URL for `dev`
  resolves to `http://18.222.237.167:8000/`.
- **Backend:** FastAPI + DynamoDB; dev host is plaintext HTTP and unreliable
  (~20s timeouts; bounded backoff for idempotent GETs owned by AND-009/AND-016).
  OpenAPI at `/openapi.json`. **Web reference for exact field names:**
  `frontend/src/api/endpoints/subscriptions.ts` and shared types in
  `frontend/src/api/types.ts` — mirror the backend snake_case names; do not invent
  camelCase wire keys.
- **Plan context:** PORT_PLAN §7.10 (Subscriptions area), M5 Commerce, Epic E32
  ("Tiers, subscribe/manage, fan-club channels").

## 3. Functional Requirements

FR-1. [CORRECTED] Define request DTOs: `SubscribeReq` (`SubscribeIn` — all fields
optional; plan id is a path param), `ChangePlanReq` (`SubscriptionChangePlanIn` —
`plan_id` required), and `CancelSubscriptionReq` (`SubscriptionCancelIn` —
`cancel_at_period_end`/`reason`). [Cancellation DOES carry a body, contrary to the
original draft.]

FR-2. [CORRECTED] Define response DTOs: `SubscriptionPlan` (the "tier"),
`Subscription` (`SubscriptionOut`), and `SubscriptionSummary` (single read). Both
list endpoints return **bare** `List<…>` (verified — no envelope, no `TiersResp`/
`SubscriptionsResp`). Price is **flat** (`price_cents`/`currency`/`interval`) —
there is no `TierPrice` sub-object.

FR-3. Every DTO field maps to the backend's snake_case wire name via
`@Json(name = …)` where the Kotlin property is camelCase. Unknown/extra JSON keys
must be tolerated (additive backend evolution must not throw).

FR-4. Nullable vs. required must match the contract: optional fields are Kotlin
nullable with a `null` (or sensible) default; required fields are non-null and
absence surfaces as a deserialization error (fail fast).

FR-5. The subscription **status** and the tier **interval** are modeled as enums
with an `UNKNOWN` fallback so a new backend value never crashes deserialization,
serialized/deserialized via lowercase string tokens.

FR-6. [CORRECTED] Declare a single Retrofit interface `SubscriptionsApi` covering
exactly: `plans(creatorId)`, `mySubscriptions(userId)`,
`subscriptionSummary(userId, id)`, `subscribe(userId, planId, body)`,
`changePlan(userId, id, body)`, `cancel(userId, id, body)`. All methods are
`suspend` and return the typed DTO body (`SubscriptionOut`/`SubscriptionSummary`/
`List<…>`). No `OkResp` return (cancel returns `SubscriptionOut`).

FR-7. HTTP verbs/paths match the backend contract (Section 5, verified). Paths are
declared **without** a leading slash (per AND-010 convention). Request bodies use
`@Body` with the DTOs; path params use `@Path`. No raw `Map`/`JsonObject` bodies.

FR-8. The CSRF header is **not** declared per-method; AND-012's interceptor
injects `X-CSRF-Token` on mutating verbs. [CORRECTED] However the interface is NOT
fully header-agnostic: the mandatory `X-User-Id` header is declared per-method via
`@Header` (mirroring the web client), unless a shared interceptor is adopted (§16).

FR-9. A Hilt `@Provides @Singleton fun provideSubscriptionsApi(retrofit:
Retrofit): SubscriptionsApi` constructs the service from the shared Retrofit
(AND-010). No new Retrofit/OkHttp instance is created.

FR-10. The custom enum adapters are registered on the **shared** `Moshi` via the
AND-026 adapter-set multibinding hook (`@AppMoshiAdapter @IntoSet`) — no second
`Moshi` instance.

## 4. Technical Design

DTOs land in
`core-model/src/main/kotlin/com/testlogon/android/core/model/subscription/`.
Retrofit interface, provider, and enum adapters land in
`core-network/src/main/kotlin/com/testlogon/android/core/network/subscription/`.

### 4.1 DTOs (`core-model`)

> **[REVIEW 2026-06-06 — DTO SHAPES CORRECTED]** The verified wire shapes are
> `SubscriptionPlan` (the "tier") and `SubscriptionOut` (the viewer subscription)
> from `reference/src/api/types.ts` + `openapi.pretty.json`. Corrections vs. the
> original draft: `plan_id` (not `tier_id`); **flat** price
> `price_cents`/`currency`/`interval` (no nested `TierPrice`); no `benefits`,
> no `sort_order`, no `is_active`; timestamps are **epoch `Long`** (not ISO-8601
> strings); `SubscriptionOut` carries `subscriber_id`, `provider`,
> `provider_subscription_id`, `start_at`, `price_cents`, `currency`,
> `auto_renew`; request bodies are `SubscribeIn`/`SubscriptionChangePlanIn`/
> `SubscriptionCancelIn` (plan id is a path param, NOT in the subscribe body).

```kotlin
package com.testlogon.android.core.model.subscription

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/** Recurring billing interval. Backend enum is exactly {month, year}. */
enum class BillingInterval(val token: String) {
    MONTH("month"), YEAR("year"), UNKNOWN("unknown");
    companion object {
        fun fromToken(t: String): BillingInterval =
            entries.firstOrNull { it.token == t } ?: UNKNOWN
    }
}

/** Lifecycle state of a viewer's subscription. Tokens are modeled with an
 *  UNKNOWN fallback; the backend does not publish a closed enum for this field
 *  (it is a free `status` string), so this set is an assumption — see §16. */
enum class SubscriptionStatus(val token: String) {
    ACTIVE("active"), TRIALING("trialing"), PAST_DUE("past_due"),
    CANCELED("canceled"), EXPIRED("expired"), UNKNOWN("unknown");
    companion object {
        fun fromToken(t: String): SubscriptionStatus =
            entries.firstOrNull { it.token == t } ?: UNKNOWN
    }
}

/** Creator-offered plan (the "tier"). Verified: types.ts `SubscriptionPlan`. */
@JsonClass(generateAdapter = true)
data class SubscriptionPlan(
    @Json(name = "plan_id") val planId: String,
    @Json(name = "creator_id") val creatorId: String,
    val name: String,
    val description: String? = null,
    @Json(name = "price_cents") val priceCents: Long,        // minor units
    val currency: String,                                    // ISO-4217, e.g. "usd"
    val interval: BillingInterval = BillingInterval.MONTH,
    @Json(name = "annual_price_cents") val annualPriceCents: Long? = null,
    val status: String,                                      // "active" | "archived" | …
    val metadata: Map<String, Any?>? = null,
    @Json(name = "created_at") val createdAt: Long,          // epoch seconds
    @Json(name = "updated_at") val updatedAt: Long,
    // `assets` and `creator_profile` are tolerated-but-unused here; model in
    // AND-235 if needed. Extra keys are ignored (lenient Moshi).
)

/** Viewer subscription. Verified: types.ts `SubscriptionOut`. */
@JsonClass(generateAdapter = true)
data class Subscription(
    @Json(name = "subscription_id") val subscriptionId: String,
    @Json(name = "plan_id") val planId: String,
    @Json(name = "creator_id") val creatorId: String,
    @Json(name = "subscriber_id") val subscriberId: String,
    val interval: BillingInterval = BillingInterval.MONTH,
    val provider: String,
    @Json(name = "provider_subscription_id") val providerSubscriptionId: String,
    val status: SubscriptionStatus,
    @Json(name = "start_at") val startAt: Long,              // epoch seconds
    @Json(name = "current_period_end") val currentPeriodEnd: Long,
    @Json(name = "cancel_at_period_end") val cancelAtPeriodEnd: Boolean = false,
    @Json(name = "price_cents") val priceCents: Long,
    val currency: String,
    @Json(name = "auto_renew") val autoRenew: Boolean = true,
    @Json(name = "trial_start") val trialStart: Long? = null,
    @Json(name = "trial_end") val trialEnd: Long? = null,
    @Json(name = "created_at") val createdAt: Long,
    @Json(name = "updated_at") val updatedAt: Long,
    val plan: SubscriptionPlan? = null,                      // embedded when present
)

/** Single-subscription read projection. Verified: SubscriptionSummaryOut. */
@JsonClass(generateAdapter = true)
data class SubscriptionSummary(
    @Json(name = "subscription_id") val subscriptionId: String,
    val status: SubscriptionStatus,
    @Json(name = "cancel_at_period_end") val cancelAtPeriodEnd: Boolean = false,
    @Json(name = "total_paid_cents") val totalPaidCents: Long,
    val currency: String,
    @Json(name = "next_amount_cents") val nextAmountCents: Long,
    @Json(name = "next_renewal_at") val nextRenewalAt: Long? = null,
    @Json(name = "last_invoice_at") val lastInvoiceAt: Long? = null,
)

/** Subscribe request. Verified: SubscribeIn — ALL fields optional; the plan id
 *  is a PATH param, not a body field. Web client posts `{}` by default. */
@JsonClass(generateAdapter = true)
data class SubscribeReq(
    val interval: String? = null,                           // "month" | "year"
    @Json(name = "discount_code") val discountCode: String? = null,
    @Json(name = "trial_days") val trialDays: Int? = null,
    @Json(name = "subscriber_id") val subscriberId: String? = null,
)

/** Change-plan request. Verified: SubscriptionChangePlanIn — `plan_id` required. */
@JsonClass(generateAdapter = true)
data class ChangePlanReq(
    @Json(name = "plan_id") val planId: String,
    val interval: String? = null,
    val effective: String = "immediate",                   // immediate | period_end
    @Json(name = "proration_policy") val prorationPolicy: String = "full",
    val reason: String? = null,
)

/** Cancel request. Verified: SubscriptionCancelIn. */
@JsonClass(generateAdapter = true)
data class CancelSubscriptionReq(
    @Json(name = "cancel_at_period_end") val cancelAtPeriodEnd: Boolean = true,
    val reason: String? = null,
)
```

There is **no array envelope**: both list endpoints return bare JSON arrays
(verified — resolves Q-1/Q-2), so `TiersResp`/`SubscriptionsResp` are **dropped**.
Epoch timestamps stay `Long` at this layer; parsing to `Instant` is a
domain-mapping concern in AND-235. `OkResp` from AND-026 is **not** used here —
the cancel endpoint returns `SubscriptionOut`, not `{"ok": true}` (corrected).

### 4.2 Enum adapters (`core-network`)

```kotlin
package com.testlogon.android.core.network.subscription

import com.squareup.moshi.FromJson
import com.squareup.moshi.ToJson
import com.testlogon.android.core.model.subscription.BillingInterval
import com.testlogon.android.core.model.subscription.SubscriptionStatus

object BillingIntervalAdapter {
    @FromJson fun fromJson(v: String) = BillingInterval.fromToken(v)
    @ToJson fun toJson(i: BillingInterval) = i.token
}

object SubscriptionStatusAdapter {
    @FromJson fun fromJson(v: String) = SubscriptionStatus.fromToken(v)
    @ToJson fun toJson(s: SubscriptionStatus) = s.token
}
```

Registered via the AND-026 multibinding hook so both adapters join the single
shared `Moshi`:

```kotlin
@Module
@InstallIn(SingletonComponent::class)
object SubscriptionMoshiModule {
    @Provides @IntoSet @AppMoshiAdapter
    fun billingIntervalAdapter(): Any = BillingIntervalAdapter
    @Provides @IntoSet @AppMoshiAdapter
    fun subscriptionStatusAdapter(): Any = SubscriptionStatusAdapter
}
```

### 4.3 The `SubscriptionsApi` interface (`core-network`)

> **[REVIEW 2026-06-06 — INTERFACE CORRECTED]** Verbs/paths below match the
> verified OpenAPI ops and `subscriptions.ts`. Corrections: paths are under
> `api/…` (not `ui/subscriptions/…`); the plan list is
> `api/creators/{creatorId}/plans`; the single read is `…/summary`; `subscribe`
> takes the plan id as a **path** param; change is `/change-plan`; cancel is a
> **POST** to `…/cancel` returning `SubscriptionOut` (not `DELETE`+`OkResp`).
> The mandatory `X-User-Id` header is added as a parameter (see §4.5/§16).

```kotlin
package com.testlogon.android.core.network.subscription

import com.testlogon.android.core.model.subscription.CancelSubscriptionReq
import com.testlogon.android.core.model.subscription.ChangePlanReq
import com.testlogon.android.core.model.subscription.Subscription
import com.testlogon.android.core.model.subscription.SubscriptionPlan
import com.testlogon.android.core.model.subscription.SubscriptionSummary
import com.testlogon.android.core.model.subscription.SubscribeReq
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Header
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

interface SubscriptionsApi {

    /** Plans ("tiers") a creator currently offers. PUBLIC — no X-User-Id.
     *  Idempotent GET (AND-016 backoff eligible). */
    @GET("api/creators/{creatorId}/plans")
    suspend fun plans(
        @Path("creatorId") creatorId: String,
        @Query("include_profile") includeProfile: Boolean? = null,
    ): List<SubscriptionPlan>

    /** The viewer's own subscriptions. Requires X-User-Id. Idempotent GET. */
    @GET("api/subscriptions")
    suspend fun mySubscriptions(
        @Header("X-User-Id") userId: String,
        @Query("include_summary") includeSummary: Boolean? = null,
    ): List<Subscription>

    /** Single-subscription read (the /summary projection). Idempotent GET. */
    @GET("api/subscriptions/{subscriptionId}/summary")
    suspend fun subscriptionSummary(
        @Header("X-User-Id") userId: String,
        @Path("subscriptionId") subscriptionId: String,
    ): SubscriptionSummary

    /** Subscribe to a plan (plan id is a PATH param). Returns the created sub. */
    @Headers("Content-Type: application/json")
    @POST("api/plans/{planId}/subscribe")
    suspend fun subscribe(
        @Header("X-User-Id") userId: String,
        @Path("planId") planId: String,
        @Body body: SubscribeReq,
    ): Subscription

    /** Move an existing subscription to a different plan. */
    @Headers("Content-Type: application/json")
    @POST("api/subscriptions/{subscriptionId}/change-plan")
    suspend fun changePlan(
        @Header("X-User-Id") userId: String,
        @Path("subscriptionId") subscriptionId: String,
        @Body body: ChangePlanReq,
    ): Subscription

    /** Cancel a subscription (POST … /cancel → updated SubscriptionOut). */
    @Headers("Content-Type: application/json")
    @POST("api/subscriptions/{subscriptionId}/cancel")
    suspend fun cancel(
        @Header("X-User-Id") userId: String,
        @Path("subscriptionId") subscriptionId: String,
        @Body body: CancelSubscriptionReq,
    ): Subscription
}
```

Both list endpoints return **bare arrays** (verified), so no `TiersResp`/
`SubscriptionsResp` envelope is needed (Q-1/Q-2 resolved). Whether `X-User-Id`
should be a per-method `@Header` (as above, mirroring the web client) or injected
by a shared interceptor (cleaner; analogous to AND-012's CSRF) is an open design
choice — see §16 Open assumptions.

### 4.4 Hilt provider

```kotlin
package com.testlogon.android.core.network.subscription.di

import com.testlogon.android.core.network.subscription.SubscriptionsApi
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object SubscriptionsApiModule {
    @Provides @Singleton
    fun provideSubscriptionsApi(retrofit: Retrofit): SubscriptionsApi =
        retrofit.create(SubscriptionsApi::class.java)
}
```

The injected `Retrofit` is the AND-010 singleton built on AND-009's shared
`OkHttpClient`. No client/Retrofit is constructed here.

### 4.5 Path & verb conventions  [CORRECTED]

- Relative paths, no leading slash: `@GET("api/subscriptions")` resolves against
  `http://18.222.237.167:8000/` → `…/api/subscriptions`. (Paths are under `api/`,
  not `ui/subscriptions/`.)
- Mutating verbs (verified): `subscribe` (POST `api/plans/{planId}/subscribe`),
  `changePlan` (POST `…/change-plan`), `cancel` (POST `…/cancel`, NOT DELETE) —
  AND-012 attaches `X-CSRF-Token`; this ticket additionally sends `X-User-Id`.
- Idempotent GETs: `plans`, `mySubscriptions`, `subscriptionSummary` — eligible
  for AND-016 bounded backoff and AND-235 stale-cache reads.
- **`X-User-Id`**: required on all endpoints except the public `plans` list.
  Modeled here as a per-method `@Header` mirroring the web client; a shared
  interceptor is the cleaner alternative (open — §16).

### 4.6 Gradle wiring

No new dependencies. `core-model` already has Moshi codegen (KSP) from AND-010/026;
`core-network` already has Retrofit, Moshi converter, Hilt, and (test)
MockWebServer. This ticket adds source files only and relies on `:core-model`
being an `implementation` dependency of `:core-network` (already true).

## 5. API Contract

> **[REVIEW 2026-06-06 — CONTRACT CORRECTED]** The original draft invented a
> `ui/subscriptions/*` surface with a nested-`price`/`tier_id` shape. None of
> those paths exist in the backend OpenAPI, and the web client uses a different
> contract. This section has been rewritten to the **verified** contract from
> `reference/openapi.index.txt`, `reference/openapi.pretty.json`, and
> `reference/src/api/endpoints/subscriptions.ts` + `types.ts`. The domain object
> is a **plan** (`SubscriptionPlan`, `plan_id`), not a "tier". See §16 for the
> full audit. Wire field names mirror the verified `SubscriptionPlan` /
> `SubscriptionOut` DTOs.

Base path (`dev`): `http://18.222.237.167:8000/`. All bodies are JSON.
Auth (verified): the subscription server authenticates via an **`X-User-Id`
header** (`reference/src/api/endpoints/subscriptions.ts`, `userIdHeader()`), in
addition to the session cookies + `X-CSRF-Token` (from the `ui_csrf` cookie)
that the global transport (`client.ts`) attaches to every call. `GET
/api/creators/{creator_id}/plans` is **public** (no `X-User-Id`); all other
endpoints below require `X-User-Id` (OpenAPI `params=…,x-user-id`).

### GET `api/creators/{creatorId}/plans`  (the "tiers" list)
Verified: `op=list_plans_api_creators__creator_id__plans_get`,
`params=creator_id,include_profile`. **Public** (no `x-user-id`).
Response `200`: bare `List<SubscriptionPlan>` (no envelope — resolves Q-1).
```json
[
  {
    "plan_id": "plan_basic",
    "creator_id": "usr_42",
    "name": "Supporter",
    "description": "Early access + monthly Q&A",
    "price_cents": 499,
    "currency": "usd",
    "interval": "month",
    "annual_price_cents": 4990,
    "status": "active",
    "metadata": {},
    "assets": [],
    "created_at": 1749124800,
    "updated_at": 1749124800
  }
]
```
Note (verified): price is **flat** (`price_cents`/`currency`/`interval`), NOT a
nested `price` object; there is no `benefits`, no `sort_order`, no `is_active`
boolean (use `status` string); `created_at`/`updated_at` are **epoch numbers**.

### GET `api/subscriptions`  (the viewer's subscriptions, "/me")
Verified: `op=list_subscriptions_api_subscriptions_get`,
`params=subscriber_id,include_profile,include_summary,x-user-id`. Requires
`X-User-Id`. Response `200`: bare `List<SubscriptionOut>` (resolves Q-2).
```json
[
  {
    "subscription_id": "sub_01HRY",
    "plan_id": "plan_basic",
    "creator_id": "usr_42",
    "subscriber_id": "usr_99",
    "interval": "month",
    "provider": "ccbill",
    "provider_subscription_id": "ccb_123",
    "status": "active",
    "start_at": 1749124800,
    "current_period_end": 1751716800,
    "cancel_at_period_end": false,
    "price_cents": 499,
    "currency": "usd",
    "auto_renew": true,
    "created_at": 1749124800,
    "updated_at": 1749124800
  }
]
```
Note (verified): `plan_id` not `tier_id`; `current_period_end`/`start_at`/
`created_at` are **epoch numbers**, not ISO-8601 strings.

### GET `api/subscriptions/{subscriptionId}/summary`  (single-subscription read)
Verified: `op=get_subscription_summary_…`, `resp=200:SubscriptionSummaryOut`,
`params=subscription_id,x-user-id`. There is **no** `GET /api/subscriptions/{id}`
bare-read endpoint; the single-subscription read is the `/summary` projection
(`SubscriptionSummary`: `subscription_id,status,cancel_at_period_end,
total_paid_cents,currency,next_amount_cents,next_renewal_at?,last_invoice_at?`).
`422` (HTTPValidationError) on bad id. (There is also
`GET api/subscriptions/{id}/invoices` → `List<SubscriptionInvoice>`.)

### POST `api/plans/{planId}/subscribe`  (subscribe)
Verified: `op=subscribe_api_plans__plan_id__subscribe_post`, `req=SubscribeIn`,
`resp=200:SubscriptionOut`, `params=plan_id,x-user-id`. The plan id is a **path
param** — it is NOT in the body.
Request (`SubscribeIn`, all fields optional; web sends `{}` by default):
```json
{ "interval": "month", "discount_code": "PROMO10", "trial_days": 7 }
```
(`subscriber_id?` also accepted.) Response `200`: the created `SubscriptionOut`.
Non-2xx surfaces as `HttpException`; documented `422` validation is the only
declared error code in OpenAPI (no `402`/`409` are declared — see §16).

### POST `api/subscriptions/{subscriptionId}/change-plan`  (change tier/plan)
Verified: `op=change_subscription_plan_…`, `req=SubscriptionChangePlanIn`,
`resp=200:SubscriptionOut`, `params=subscription_id,x-user-id`. Path is
`/change-plan`, NOT `/change-tier`.
Request (`SubscriptionChangePlanIn`, `plan_id` required):
```json
{ "plan_id": "plan_pro", "interval": "month", "effective": "immediate",
  "proration_policy": "full" }
```
(`effective` ∈ {immediate, period_end}; `proration_policy` ∈
{none, charge, credit, full}; `reason?`, `provider_invoice_id?`,
`proration_amount_cents?` also accepted.) Response `200`: updated
`SubscriptionOut`.

### POST `api/subscriptions/{subscriptionId}/cancel`  (cancel)
Verified: `op=cancel_subscription_api_subscriptions__subscription_id__cancel_post`,
`req=SubscriptionCancelIn`, `resp=200:SubscriptionOut`,
`params=subscription_id,x-user-id`. Cancel is **POST … /cancel** returning the
updated `SubscriptionOut` — it is NOT `DELETE` and does NOT return `{"ok":true}`.
Request (`SubscriptionCancelIn`): `{ "cancel_at_period_end": true, "reason": "…" }`
(`cancel_at_period_end` defaults to `true`). Response `200`: the updated
`SubscriptionOut` (typically `cancel_at_period_end: true`, still `active` until
period end). Related: `POST api/subscriptions/{id}/resume` (`SubscriptionResumeIn`)
and `POST api/subscriptions/{id}/renewal` (`SubscriptionRenewalIn`).

**Error envelope (all endpoints):** FastAPI `HTTPValidationError` =
`{ "detail": [ { "loc": [...], "msg": "...", "type": "..." } ] }` (per
`components.schemas.HTTPValidationError`/`ValidationError`; `loc` items are
string|int). The OpenAPI declares `200` + `422` only for these ops. Typed
mapping to `ApiError` is owned by **AND-015**; this ticket lets non-2xx surface
as `retrofit2.HttpException` so AND-015/AND-018 can map it.

## 6. Data & State Management

`SubscriptionsApi` is **stateless** — a singleton interface proxy with no fields;
DTOs are transient wire types.

- **Session state** lives entirely in cookies (AND-011 jar); this layer neither
  reads nor writes cookies. `X-CSRF-Token` is injected by AND-012.
- **No Room / DataStore here.** Caching the tier list and the viewer's
  subscriptions (for offline/stale UI per the unreliable dev host) is owned by the
  subscriptions repository in `core-data` (AND-235), which also maps DTOs → domain
  models and wraps calls in `ApiResult<T>` (AND-018).
- **No `StateFlow`/`UiState`.** This interface returns plain DTOs (happy path) and
  throws on failure; ViewModels consume the repository, not the API directly.
- **Enums carry behavior, not state:** `UNKNOWN` fallbacks on `BillingInterval`
  and `SubscriptionStatus` keep deserialization total.
- **Threading:** suspend methods are invoked from a coroutine on an IO dispatcher
  injected at the repository layer; this ticket imposes no dispatcher.
- **Serialization:** uses the shared Moshi codegen adapters + the two enum
  adapters from §4.2; unknown keys ignored, absent optional fields fall back to
  Kotlin defaults (lenient).

## 7. Error Handling & Resilience

Responsibilities are narrow: declare endpoints/DTOs so failures propagate cleanly.

- **Non-2xx** surfaces as `retrofit2.HttpException` carrying the raw error body for
  AND-015 to decode the FastAPI `detail`. [CORRECTED] The OpenAPI declares only
  `422` (`HTTPValidationError`) for these ops, plus `401` (unauthenticated, from
  the global auth layer). The `402`/`409`/`404` codes assumed by the original
  draft are NOT in the published contract — treat them as unverified business-rule
  possibilities, not guaranteed (§16).
- **`401`** on any call is intercepted by the AND-013 `Authenticator`, which calls
  `AuthApi.sessionRefresh()` once then retries; only a second `401` propagates →
  caller treats the session as expired and routes to login (AND-025).
- **Transport failures** (`SocketTimeoutException`, `UnknownHostException`,
  `IOException`) propagate unchanged. The ~20s timeouts and bounded backoff for the
  idempotent GETs (`tiers`, `mySubscriptions`, `subscription`) are owned by
  AND-009/AND-016 on the shared client. The repository (AND-235) decides
  offline/stale presentation.
- **Deserialization failures** surface as `JsonDataException`; lenient parsing +
  enum `UNKNOWN` fallbacks minimize these against the evolving dev backend. A
  **missing required field** (e.g. `tier_id`, `price`, `status`) is intentional
  fail-fast and asserted in tests.
- **Mutation idempotency:** `subscribe` is **not** safe to auto-retry (it could
  create duplicate subscriptions/charges); only GETs are retried by AND-016. This
  ticket documents that constraint; enforcement is in AND-016's verb gate.
- This ticket maps **no** errors itself — that is AND-015 (`ApiError`) and
  AND-018 (`ApiResult`).

## 8. Security & Privacy

- **Session-scoped, server-enforced ownership:** `mySubscriptions`,
  `subscription`, `changeTier`, and `cancel` operate only on the authenticated
  viewer's own subscriptions; the client passes the cookie-scoped identity
  implicitly and never sends a user id for these.
- **[CORRECTED] Identity header `X-User-Id`:** session auth rides on HttpOnly
  cookies + CSRF as before, but the subscription server additionally requires a
  non-secret `X-User-Id` header carrying the caller's user id (verified:
  `subscriptions.ts: userIdHeader()`). This is an identifier, not a credential —
  server-side ownership checks still gate access — but note the client DOES send a
  user id on these calls (contradicting the original "never sends a user id"
  claim). Still no bearer tokens / no manual `Cookie` header from this layer.
- **Cleartext on dev:** these calls ride plaintext HTTP on `dev`
  (`http://18.222.237.167:8000`) — a known dev-only risk permitted by the scoped
  cleartext config (AND-006); `staging`/`prod` are HTTPS-only.
- **No sensitive payloads to redact:** request bodies contain only a `plan_id`
  (path/body), interval, optional discount code and cancellation reason — no card
  data (payment-method handling is a separate provider flow). The `X-User-Id`
  header is a non-secret identifier.
  No bodies are logged by this ticket; the AND-009 logging interceptor (debug
  only) governs HTTP logging.
- **Money fields** are integer minor units (`amount_cents: Long`) to avoid
  floating-point rounding; currency is a separate field. No client-side price math
  beyond display formatting (owned by feature UI).

## 9. Accessibility & i18n

Not applicable — this is a headless transport + DTO layer with no UI surface and
no user-facing strings. `benefits` tokens and `delivery`/`description` text are
passed through verbatim. Accessibility, currency/price formatting, and
localization of tier/benefit labels are owned by the subscriptions feature UI and
`core-ui` (downstream of AND-235). No `strings.xml` entries are added here.

## 10. Telemetry & Logging

- **HTTP logging** is inherited from AND-009's `HttpLoggingInterceptor` (debug
  builds only). No new logging here.
- **No analytics events** emitted by this layer. Subscribe-success/failure,
  change-tier, and cancel events are emitted by the subscriptions feature
  ViewModels (their own ticket), derived from `ApiResult` outcomes — not from
  `SubscriptionsApi` directly.
- **Build-time signal:** KSP must have generated Moshi adapters for every DTO in
  §4.1 and the shared `Moshi` must include `BillingIntervalAdapter` /
  `SubscriptionStatusAdapter`; a missing adapter fails the build (no reflection
  fallback, per AND-010 policy).

## 11. Testing Strategy

> **[REVIEW 2026-06-06]** The illustrative tests T-1…T-11 below predate the
> contract correction and still reference the old `ui/subscriptions/*` paths,
> `tier_id`/nested-`price` shapes, and `DELETE`+`OkResp` cancel. They are kept for
> intent but are **superseded** by the verified, enumerated cases in **§17 Test
> Plan** (TC-AND-234-NN), which use the real paths/DTOs/headers. When in conflict,
> §17 wins.

Two test surfaces, both JVM unit tests, no Android instrumentation:
(a) DTO round-trip tests in `core-model`; (b) `MockWebServer` endpoint tests in
`core-network` using the production Moshi/Retrofit configuration.

Test harness (core-network):
```kotlin
private fun api(server: MockWebServer): SubscriptionsApi {
    val moshi = Moshi.Builder()
        .add(BillingIntervalAdapter)
        .add(SubscriptionStatusAdapter)
        .build() // mirrors the shared provideMoshi() adapter set
    val retrofit = Retrofit.Builder()
        .baseUrl(server.url("/"))
        .addConverterFactory(MoshiConverterFactory.create(moshi))
        .build()
    return retrofit.create(SubscriptionsApi::class.java)
}
```

**T-1 — `tiers` mapping (backlog: "tiers map").**
```kotlin
@Test fun tiers_getsAndDecodesTierList() = runTest {
    val server = MockWebServer().apply {
        enqueue(MockResponse().setBody(
            """[{"tier_id":"tier_basic","creator_id":"usr_42","name":"Supporter",
                "price":{"amount_cents":499,"currency":"usd","interval":"month"},
                "benefits":["early_access"],"is_active":true,"sort_order":0}]"""))
        start()
    }
    val tiers = api(server).tiers("usr_42")
    val req = server.takeRequest()
    assertEquals("GET", req.method)
    assertEquals("/ui/subscriptions/tiers/usr_42", req.path)
    assertEquals("tier_basic", tiers.single().tierId)
    assertEquals(499L, tiers.single().price.amountCents)
    assertEquals(BillingInterval.MONTH, tiers.single().price.interval)
    server.shutdown()
}
```

**T-2 — `mySubscriptions` mapping (backlog: "subs map").** `GET
/ui/subscriptions/me` decodes `List<Subscription>` including snake_case fields
(`current_period_end`, `cancel_at_period_end`) and `status == ACTIVE`.

**T-3 — `subscription(id)`** issues `GET /ui/subscriptions/sub_1` (path
interpolated) and decodes a single `Subscription` with an embedded `tier`.

**T-4 — `subscribe`** posts `{"tier_id":"tier_basic"}` to `ui/subscriptions`
(verb POST), and decodes the returned `Subscription`; asserts the request body
contains `"tier_id"` and never `"tierId"`.

**T-5 — `changeTier`** posts `{"tier_id":"tier_pro"}` to
`ui/subscriptions/sub_1/change-tier` and decodes the updated `Subscription`.

**T-6 — `cancel`** issues `DELETE /ui/subscriptions/sub_1` and decodes `OkResp`.

**T-7 — enum fallback.** A subscription with `"status":"frozen"` decodes to
`SubscriptionStatus.UNKNOWN`; a tier with `"interval":"daily"` decodes to
`BillingInterval.UNKNOWN`; no exception thrown.

**T-8 — unknown-key tolerance.** A tier payload with an extra `"server_time"` key
deserializes without error (additive backend safe).

**T-9 — required-field failure.** Removing `"price"` from a tier sample (or
`"status"` from a subscription) causes `fromJson`/decoding to throw
`JsonDataException` (fail-fast).

**T-10 — error propagation.** A `402` response from `subscribe()` throws
`retrofit2.HttpException` with `code() == 402` (non-2xx not swallowed).

**T-11 — Hilt provider.** Minimal `core-testing`/`@HiltAndroidTest` harness
injects `SubscriptionsApi` and asserts a non-null singleton built on the shared
Retrofit (same instance on repeated injection).

DTO round-trip tests (`core-model`,
`com.testlogon.android.core.model.subscription.SubscriptionDtoRoundTripTest`):
every DTO in §4.1 has a committed fixture under
`core-model/src/test/resources/subscription/<name>.json`, asserts parsed-tree
equality on serialize→deserialize→serialize, and verifies snake_case keys
(`amount_cents`, `tier_id`, `cancel_at_period_end`).

Coverage target: ≥90% on the new surface; each of the six endpoints has at least
one verb/path assertion, and the **tiers** and **subs** payloads each have an
explicit mapping test (satisfying the backlog acceptance).

## 12. Dependencies & Sequencing

**Hard upstream (must merge first):**
- **AND-027** — AuthApi / session endpoints. Establishes the authenticated
  cookie-based session that all `/ui/subscriptions/*` calls require; the test and
  integration patterns (MockWebServer harness, snake_case adapters, Hilt provider)
  follow AND-027. Blocking per the backlog `Deps: AND-027`.

**Transitive upstream (already required via AND-027):** AND-026 (shared `Moshi` +
`@AppMoshiAdapter` multibinding hook, `OkResp`), AND-010 (Retrofit/Moshi),
AND-009 (shared `OkHttpClient`, timeouts, redacting logger), AND-016 (GET
backoff), AND-006 (`BuildConfig`), AND-003/AND-004 (module structure, Hilt
baseline).

**Downstream (this ticket blocks):**
- **AND-235** — Subscriptions repository (`core-data`): wraps `SubscriptionsApi`
  in `ApiResult<T>`, maps DTOs → domain models, and owns caching/offline/stale
  policy. (`blocks: [AND-235]`; align the exact downstream id to the live E32
  backlog during grooming — the repository/ViewModel/Compose tiers-and-manage
  screen consume this seam.)
- Error mapping for these endpoints is consumed via the shared AND-015 `ApiError`
  / AND-018 `ApiResult`, which need no change for this ticket.

**Sequencing within the ticket:** (1) confirm field names/envelopes against
`/openapi.json` and `frontend/src/api/endpoints/subscriptions.ts`; (2) define DTOs
+ enum adapters in `core-model`/`core-network`; (3) declare `SubscriptionsApi` +
`SubscriptionsApiModule`; (4) write round-trip + MockWebServer tests T-1…T-11.

## 13. Risks & Open Questions

- **R-1 List envelope shape.** `GET .../tiers/{creatorId}` and
  `GET .../me` may return bare arrays or `{tiers:[…]}` / `{subscriptions:[…]}`
  wrappers. Mitigation: inspect the web reference + OpenAPI before coding; switch
  return types to `TiersResp`/`SubscriptionsResp` if wrapped. Guarded by T-1/T-2.
- **R-2 Cancel semantics & verb.** Cancel may be `DELETE /ui/subscriptions/{id}`
  returning `OkResp`, or `POST /ui/subscriptions/{id}/cancel` returning the
  updated `Subscription`. Mitigation: confirm via OpenAPI; spec assumes `DELETE`
  +`OkResp`. Adjust the annotation/return type if the contract differs (T-6).
- **R-3 Money representation.** Spec assumes integer `amount_cents` + ISO-4217
  `currency`. If the backend sends decimal strings/floats, switch `TierPrice` to a
  string-amount field to avoid precision loss; do **not** use `Double`. *Open:*
  confirm via `/openapi.json`.
- **R-4 Subscribe payment coupling.** `subscribe` may require a payment-method/
  provider token (M5 billing) rather than just `tier_id`, or may return a
  redirect/`client_secret`. Mitigation: confirm the request/response contract;
  if a payment field is required, extend `SubscribeReq` and surface the
  provider hand-off to the billing epic (out of scope here). *Open.*
- **R-5 Tier scoping path.** `tiers` may be keyed by `creator_id` path param (as
  spec'd) or by query (`?creator_id=`) or be a flat catalog. *Open:* match the web
  reference. Guarded by T-1.
- **R-6 Field-name drift.** Appendix-style assumptions (`tier_id` vs `id`,
  `current_period_end` presence) may lag the live contract. Mitigation: capture
  fixtures directly from the dev host; treat `/openapi.json` as authoritative.
- **Q-1** Is `GET .../tiers/{creatorId}` a bare array or wrapped? *Proposed:* match
  web reference; default `List<SubscriptionTier>`.
- **Q-2** Is `GET .../me` a bare array or wrapped? *Proposed:* default
  `List<Subscription>`.
- **Q-3** Does `cancel` return `OkResp` (DELETE) or the updated `Subscription`
  (POST `/cancel`)? *Proposed:* `DELETE` + `OkResp`; adjust per OpenAPI.

## 14. Acceptance Criteria

- **AC-1 (backlog — tiers/subs map, tested).** `SubscriptionTier` and
  `Subscription` (with `TierPrice`, the two enums, and request DTOs)
  (de)serialize the documented JSON exactly, proven by
  `SubscriptionDtoRoundTripTest` (parsed-tree equality, snake_case keys) and by
  the `tiers`/`mySubscriptions` mapping tests (T-1/T-2).
- **AC-2.** [CORRECTED] `SubscriptionsApi` declares all six operations (`plans`,
  `mySubscriptions`, `subscriptionSummary`, `subscribe`, `changePlan`, `cancel`);
  the module compiles against the §4.1 DTOs. (No `OkResp` reuse — cancel returns
  `SubscriptionOut`.)
- **AC-3.** Each endpoint is callable and its **verb + resolved path + request
  body** match Section 5, asserted with MockWebServer (T-1…T-6).
- **AC-4.** [CORRECTED] `changePlan` serializes `{ "plan_id": … }` exactly (never
  `planId`); `subscribe` carries the plan id in the **path** and posts the
  optional `SubscribeIn` body. Responses decode snake_case fields (`price_cents`,
  `current_period_end`, `cancel_at_period_end`, epoch `Long` timestamps) via the
  codegen + enum adapters (see §17 TC-04/TC-05).
- **AC-5.** Unknown enum tokens map to `UNKNOWN`; unknown JSON keys are tolerated;
  a missing required field throws `JsonDataException` (T-7/T-8/T-9).
- **AC-6.** [CORRECTED] Non-2xx (e.g. `422` validation, the only error code the
  OpenAPI declares for these ops; `401` on expired session) surfaces as
  `HttpException` and is not swallowed (§17 TC-08). [The original `402`/`409` codes
  are not declared in the contract — unverified; see §16.]
- **AC-7.** `SubscriptionsApi` is Hilt-provided as a `@Singleton` built on the
  shared Retrofit; repeated injection yields the same instance (T-11). No new
  `OkHttpClient`/`Retrofit`, no per-method CSRF/cookie headers.
- **AC-8.** The enum adapters are registered on the **single** shared `Moshi` via
  the AND-026 multibinding hook (no second `Moshi`).
- **AC-9.** All tests pass in CI; modules build clean under AGP 8.7.3 / Gradle 8.9
  / JDK 17 with KSP-generated adapters present and no detekt/lint regressions.

## 15. Definition of Done

- DTOs (`com.testlogon.android.core.model.subscription`), enum adapters +
  `SubscriptionMoshiModule`, `SubscriptionsApi`
  (`com.testlogon.android.core.network.subscription`), and
  `SubscriptionsApiModule` (`…subscription.di`) are implemented on `android-port`,
  reusing AND-026's `OkResp` and the shared `Moshi`/Retrofit (nothing redefined).
- Open questions Q-1/Q-2/Q-3 (and risks R-1…R-5) are resolved against
  `/openapi.json` and `frontend/src/api/endpoints/subscriptions.ts`; return types,
  verbs, and the money representation reflect the confirmed contract.
- `SubscriptionDtoRoundTripTest` + MockWebServer tests T-1…T-11 are implemented
  and green in CI; ≥90% line coverage on the new surface; committed JSON fixtures
  under `core-model/src/test/resources/subscription/`; every endpoint has a
  verb/path assertion and the tiers/subs mapping is explicitly tested.
- No second `OkHttpClient`/`Retrofit`; no manual cookie/CSRF/auth headers in the
  interface; no body logging added.
- `./gradlew :core-model:test :core-network:assemble :core-network:testDebugUnitTest`
  passes locally and in CI with no new lint/detekt violations (AND-005 config).
- Code reviewed and merged to `android-port`; the subscriptions repository
  (AND-235) and the E32 tiers-and-manage feature are unblocked.
- A one-line note in the `core-network` README (owned by AND-007) records the
  `SubscriptionsApi` path/verb map and the delegation of cookie/CSRF/refresh to
  AND-011/AND-012/AND-013.

## 16. Citations & Assumption Audit

Sources: OpenAPI index `reference/openapi.index.txt`, OpenAPI spec
`reference/openapi.pretty.json` (`components.schemas.*`), and the web client
under `reference/src/api/`. Each claim below lists VERDICT + exact SOURCE.

1. **Plan-list endpoint = `GET api/creators/{creatorId}/plans`** (returns a bare
   `List<SubscriptionPlan>`). VERDICT: **Corrected** (draft had
   `GET ui/subscriptions/tiers/{creatorId}`, which does not exist). SOURCE:
   OpenAPI `GET /api/creators/{creator_id}/plans`
   (`op=list_plans_api_creators__creator_id__plans_get`,
   `params=creator_id,include_profile`); `src/api/endpoints/subscriptions.ts:
   listPlans`.
2. **Viewer-subscriptions endpoint = `GET api/subscriptions`** (bare
   `List<SubscriptionOut>`). VERDICT: **Corrected** (draft had
   `GET ui/subscriptions/me`). SOURCE: OpenAPI `GET /api/subscriptions`
   (`op=list_subscriptions_api_subscriptions_get`,
   `params=subscriber_id,include_profile,include_summary,x-user-id`);
   `src/api/endpoints/subscriptions.ts: listSubscriptions`.
3. **Single-subscription read = `GET api/subscriptions/{id}/summary`** →
   `SubscriptionSummaryOut`. VERDICT: **Corrected** (draft had a bare
   `GET ui/subscriptions/{id}` returning a full `Subscription`; no such bare-read
   op exists). SOURCE: OpenAPI `GET /api/subscriptions/{subscription_id}/summary`
   (`resp=200:SubscriptionSummaryOut`); `src/api/endpoints/subscriptions.ts:
   getSubscriptionSummary`.
4. **Subscribe = `POST api/plans/{planId}/subscribe`**, body `SubscribeIn`, plan
   id in the **path**. VERDICT: **Corrected** (draft had `POST ui/subscriptions`
   with `{tier_id}` in the body). SOURCE: OpenAPI `POST /api/plans/{plan_id}/
   subscribe` (`req=SubscribeIn`, `resp=200:SubscriptionOut`);
   `components.schemas.SubscribeIn`; `src/api/endpoints/subscriptions.ts:
   subscribe`.
5. **`SubscribeIn` fields are ALL optional** = `interval`∈{month,year},
   `discount_code`, `trial_days`(1–365), `subscriber_id`; web posts `{}`. VERDICT:
   **Corrected** (draft required `tier_id`). SOURCE:
   `components.schemas.SubscribeIn` (no `required` array);
   `src/api/endpoints/subscriptions.ts: subscribe(planId, body?)`.
6. **Change = `POST api/subscriptions/{id}/change-plan`**, body
   `SubscriptionChangePlanIn` with required `plan_id`. VERDICT: **Corrected**
   (draft had `POST ui/subscriptions/{id}/change-tier` with `{tier_id}`). SOURCE:
   OpenAPI `POST /api/subscriptions/{subscription_id}/change-plan`
   (`req=SubscriptionChangePlanIn`); `components.schemas.SubscriptionChangePlanIn`
   (`required:[plan_id]`, `effective`∈{immediate,period_end},
   `proration_policy`∈{none,charge,credit,full});
   `src/api/endpoints/subscriptions.ts: changePlan`.
7. **Cancel = `POST api/subscriptions/{id}/cancel`**, body `SubscriptionCancelIn`,
   returns `SubscriptionOut`. VERDICT: **Corrected** (draft had
   `DELETE ui/subscriptions/{id}` returning `OkResp`/`{"ok":true}`). SOURCE:
   OpenAPI `POST /api/subscriptions/{subscription_id}/cancel`
   (`req=SubscriptionCancelIn`, `resp=200:SubscriptionOut`);
   `components.schemas.SubscriptionCancelIn` (`cancel_at_period_end` default true,
   `reason?`); `src/api/endpoints/subscriptions.ts: cancelSubscription`.
8. **Plan/tier DTO = `SubscriptionPlan`** with `plan_id`, flat
   `price_cents`/`currency`/`interval`, `annual_price_cents?`, `status`,
   `metadata?`, `assets?`, numeric `created_at`/`updated_at`. VERDICT:
   **Corrected** (draft had `SubscriptionTier` with `tier_id`, nested `price`
   object, `benefits`, `is_active`, `sort_order`, string timestamps — none of
   those exist). SOURCE: `src/api/types.ts: SubscriptionPlan`;
   `components.schemas` plan shape.
9. **Subscription DTO = `SubscriptionOut`** with `plan_id`, `subscriber_id`,
   `provider`, `provider_subscription_id`, `start_at`, `price_cents`, `currency`,
   `auto_renew`, numeric `current_period_end`. VERDICT: **Corrected** (draft had
   `tier_id` and ISO-8601 string timestamps; omitted most fields). SOURCE:
   `src/api/types.ts: SubscriptionOut`.
10. **Timestamps are epoch numbers (Long), not ISO-8601 strings.** VERDICT:
    **Corrected**. SOURCE: `src/api/types.ts` (`created_at: number`,
    `current_period_end: number`, etc.).
11. **Auth: subscription endpoints require an `X-User-Id` header** (plus the
    global cookie session + `X-CSRF-Token`). VERDICT: **Corrected / augmented**
    (draft said "this ticket adds no auth headers" and "never sends a user id").
    SOURCE: `src/api/endpoints/subscriptions.ts: userIdHeader()` ("authenticates
    via X-User-Id header (not Bearer token)"); OpenAPI `params=…,x-user-id` on the
    authenticated ops.
12. **Global transport sends cookies (`credentials: include`) + `X-CSRF-Token`
    from the `ui_csrf` cookie; 401 → one refresh via `/ui/session/refresh`.**
    VERDICT: **Verified** (this part of the draft's auth model is correct, just
    incomplete re #11). SOURCE: `src/api/client.ts` (lines ~124, ~167-170,
    ~121-130, ~194).
13. **Plan list is PUBLIC (no `X-User-Id`).** VERDICT: **Verified**. SOURCE:
    OpenAPI `GET /api/creators/{creator_id}/plans` (`params` lacks `x-user-id`);
    `subscriptions.ts: listPlans` uses `api.get` without `userIdHeader()`.
14. **List endpoints are bare arrays, not `{tiers:[…]}`/`{subscriptions:[…]}`
    envelopes** (resolves Q-1/Q-2). VERDICT: **Verified**. SOURCE:
    `subscriptions.ts` (`SubscriptionPlan[]`, `SubscriptionOut[]`); OpenAPI list
    ops have unschematized array `200` responses.
15. **Declared error codes are `422` (HTTPValidationError) + `401`; no
    `402`/`409`/`404`.** VERDICT: **Corrected** (draft asserted `402`/`409`/`404`).
    SOURCE: OpenAPI ops show `resp=200:…;422:HTTPValidationError`;
    `components.schemas.HTTPValidationError`/`ValidationError`; `client.ts` 401
    handling.
16. **`interval` enum is exactly {month, year}.** VERDICT: **Corrected** (draft
    `BillingInterval` also had `WEEK`). SOURCE: `components.schemas.SubscribeIn`
    /`SubscriptionChangePlanIn` (`interval` enum [month, year]);
    `types.ts: PlanCreateReq.interval`.
17. **Subscription `status` is a free string (no published closed enum).**
    VERDICT: **Unverified-assumption** (modeling it as a `SubscriptionStatus` enum
    with UNKNOWN fallback is a safe design choice, but the specific token set
    active/trialing/past_due/canceled/expired is assumed). SOURCE: `types.ts`
    (`status: string`); no enum in `components.schemas`.
18. **Hilt `@Provides @Singleton provideSubscriptionsApi(retrofit)` on the shared
    Retrofit; suspend Retrofit interface; Moshi codegen + enum adapters.** VERDICT:
    **Verified-by-framework** (standard Retrofit/Moshi/Hilt usage). SOURCE:
    framework ref — Retrofit https://square.github.io/retrofit/ ; Moshi codegen
    https://github.com/square/moshi#codegen ; Hilt
    https://dagger.dev/hilt/ . (The upstream AND-009/010/026 wiring itself is not
    in these sources — see Open assumptions.)
19. **Stack pins (Retrofit 2.11.0, OkHttp 4.12.0, Moshi 1.15.x, Kotlin 2.0.21,
    minSdk 24/compileSdk 35, AGP 8.7.3/Gradle 8.9) and base URL
    `http://18.222.237.167:8000/`.** VERDICT: **Unverified-assumption** (carried
    from the plan; not checkable against the provided OpenAPI/frontend sources).

### Corrections made

- Endpoint surface rewritten from the fictional `ui/subscriptions/*` set to the
  verified `api/creators/{id}/plans`, `api/subscriptions`,
  `api/subscriptions/{id}/summary`, `api/plans/{id}/subscribe`,
  `api/subscriptions/{id}/change-plan`, `api/subscriptions/{id}/cancel` (§4.3, §5).
- Cancel changed from `DELETE`→`OkResp` to `POST …/cancel` with
  `SubscriptionCancelIn` body → `SubscriptionOut` (§4.1, §4.3, §4.5, §5).
- Change endpoint `/change-tier`→`/change-plan`; request `{tier_id}`→
  `SubscriptionChangePlanIn{plan_id,…}` (§4.1, §4.3, §5).
- Subscribe: plan id moved to path; body is the optional `SubscribeIn`, not
  `{tier_id}` (§4.1, §4.3, §5, FR-1).
- DTOs replaced: `SubscriptionTier`/`TierPrice` → `SubscriptionPlan` (flat price);
  `Subscription` aligned to `SubscriptionOut`; added `SubscriptionSummary`; request
  DTOs renamed/reshaped; timestamps `String`→`Long` epoch; dropped
  `TiersResp`/`SubscriptionsResp` envelopes and the `benefits`/`sort_order`/
  `is_active` fields (§4.1).
- Added the mandatory `X-User-Id` header to all non-public methods and corrected
  the "no auth headers"/"never sends a user id" claims (§2, §4.5, §8, FR-8).
- `BillingInterval` token set trimmed to {month, year, UNKNOWN} (removed WEEK).
- Error codes corrected to `422`/`401` (removed unverified `402`/`409`/`404`)
  (§5, §7, AC-6).
- Frontmatter: `status: reviewed`, `reviewed_on: 2026-06-06`.
- §11 marked superseded by §17; AC-2/AC-4/AC-6 updated to the real contract.

### Open assumptions

- **Subscription `status` token set** (claim 17): the backend exposes `status` as
  a free string; the enum tokens are assumed. Mitigation: `UNKNOWN` fallback keeps
  deserialization total; confirm the live token vocabulary from dev fixtures.
- **`X-User-Id` injection strategy**: per-method `@Header` (mirrors web) vs. a
  shared OkHttp interceptor (cleaner). Web client uses per-call; Android may prefer
  an interceptor pulling the id from the auth store. Not dictated by the sources.
- **Upstream AND-009/010/011/012/013/026 contracts** (shared OkHttp/Retrofit/Moshi,
  cookie jar, CSRF interceptor, 401 Authenticator, adapter multibinding): assumed
  from the port plan; not present in the OpenAPI/frontend reference, so unverifiable
  here.
- **Stack pins and dev base URL** (claim 19): assumed from the plan; not in the
  provided sources.
- **`402`/`409` business outcomes**: a payment-required or already-subscribed
  result is plausible at runtime but is NOT in the published OpenAPI; treated as a
  runtime possibility, not a contract guarantee.
- **`provider`/`provider_subscription_id`** semantics (e.g. "ccbill"): present in
  the DTO but provider-flow behavior is out of scope (M5 billing epic).

## 17. Test Plan

All cases target JVM/Robolectric or the headless emulator unless a real-hardware
behavior is involved. This ticket is a headless transport+DTO layer, so most cases
are **unit** or **contract (MockWebServer)**; UI/instrumented/physical-device cases
are minimal and noted explicitly. IDs trace to the §14 Acceptance Criteria.

Shared harness (contract cases): a `MockWebServer` + a `Retrofit` built on a
`Moshi` carrying `BillingIntervalAdapter`+`SubscriptionStatusAdapter` (mirrors the
shared `provideMoshi()` adapter set), `retrofit.create(SubscriptionsApi::class)`.

- **TC-AND-234-01 — Plans list happy path (the "tiers map").**
  Type: contract/MockWebServer. Target: JVM unit (Robolectric not required).
  Preconditions: server enqueues the §5 `GET …/plans` 200 body (one
  `SubscriptionPlan`). Steps: call `plans("usr_42")`; capture the request. Expected:
  method `GET`, path `/api/creators/usr_42/plans`; decoded `planId=="plan_basic"`,
  `priceCents==499L`, `interval==BillingInterval.MONTH`, `status=="active"`,
  `createdAt==1749124800L`; no `X-User-Id` header sent (public). Traces: AC-1, AC-3.

- **TC-AND-234-02 — My-subscriptions list happy path (the "subs map").**
  Type: contract/MockWebServer. Target: JVM unit. Preconditions: server enqueues
  the §5 `GET /api/subscriptions` 200 array (one `SubscriptionOut`). Steps: call
  `mySubscriptions("usr_99")`. Expected: method `GET`, path `/api/subscriptions`,
  request header `X-User-Id: usr_99`; decoded `planId`, `subscriberId=="usr_99"`,
  `status==ACTIVE`, `currentPeriodEnd==1751716800L` (Long), `cancelAtPeriodEnd==
  false`. Traces: AC-1, AC-3, AC-4.

- **TC-AND-234-03 — Subscription summary read.**
  Type: contract/MockWebServer. Target: JVM unit. Preconditions: server enqueues a
  `SubscriptionSummary` 200 body. Steps: call `subscriptionSummary("usr_99",
  "sub_01HRY")`. Expected: method `GET`, path
  `/api/subscriptions/sub_01HRY/summary`, header `X-User-Id`; decoded
  `subscriptionId`, `totalPaidCents`, `nextAmountCents`, nullable
  `nextRenewalAt`/`lastInvoiceAt` tolerated when absent. Traces: AC-2, AC-3.

- **TC-AND-234-04 — Subscribe serializes correctly (plan id in path, optional body).**
  Type: contract/MockWebServer. Target: JVM unit. Preconditions: server enqueues a
  `SubscriptionOut` 200. Steps: call `subscribe("usr_99","plan_basic",
  SubscribeReq(interval="month", trialDays=7))`; read the recorded request body.
  Expected: method `POST`, path `/api/plans/plan_basic/subscribe`, header
  `X-User-Id` + `Content-Type: application/json`; body contains `"interval":"month"`
  and `"trial_days":7`, contains NO `plan_id`/`tier_id` key; response decodes to
  `Subscription`. Traces: AC-3, AC-4.

- **TC-AND-234-05 — Change-plan serializes `plan_id` (never `planId`/`tier_id`).**
  Type: contract/MockWebServer. Target: JVM unit. Preconditions: server enqueues a
  `SubscriptionOut` 200. Steps: call `changePlan("usr_99","sub_1",
  ChangePlanReq(planId="plan_pro"))`; inspect body. Expected: method `POST`, path
  `/api/subscriptions/sub_1/change-plan`; body JSON contains `"plan_id":"plan_pro"`,
  `"effective":"immediate"`, `"proration_policy":"full"`, never `"planId"`/
  `"tier_id"`; response decodes. Traces: AC-3, AC-4.

- **TC-AND-234-06 — Cancel is POST …/cancel returning SubscriptionOut.**
  Type: contract/MockWebServer. Target: JVM unit. Preconditions: server enqueues a
  `SubscriptionOut` 200 with `cancel_at_period_end:true`. Steps: call
  `cancel("usr_99","sub_1", CancelSubscriptionReq())`. Expected: method `POST`
  (NOT DELETE), path `/api/subscriptions/sub_1/cancel`; body
  `"cancel_at_period_end":true`; decoded `Subscription.cancelAtPeriodEnd==true`,
  `status` still `ACTIVE`. Traces: AC-3.

- **TC-AND-234-07 — Enum UNKNOWN fallback + unknown-key tolerance.**
  Type: unit (Moshi). Target: JVM unit. Preconditions: build the shared Moshi.
  Steps: decode a `SubscriptionOut` with `"status":"frozen"` and an extra
  `"server_time":123` key, and a `SubscriptionPlan` with `"interval":"daily"`.
  Expected: `status==SubscriptionStatus.UNKNOWN`, `interval==BillingInterval.
  UNKNOWN`, no exception; extra key ignored. Traces: AC-5.

- **TC-AND-234-08 — Error propagation (422 + 401) not swallowed.**
  Type: contract/MockWebServer. Target: JVM unit. Preconditions: enqueue a `422`
  with an `HTTPValidationError` body (`{"detail":[{"loc":["body","plan_id"],
  "msg":"field required","type":"value_error.missing"}]}`), then a separate `401`.
  Steps: call `changePlan(...)` against `422`; call `mySubscriptions(...)` against
  `401`. Expected: each throws `retrofit2.HttpException` with `code()==422` /
  `code()==401`; raw error body preserved for AND-015; nothing swallowed. Traces:
  AC-6.

- **TC-AND-234-09 — Required-field fail-fast (DTO round-trip).**
  Type: unit (Moshi). Target: JVM unit. Preconditions: committed fixtures under
  `core-model/src/test/resources/subscription/`. Steps: remove `plan_id` from a
  `SubscriptionOut` fixture (and `plan_id`/`price_cents` from a `SubscriptionPlan`)
  and decode. Expected: `JsonDataException` (required non-null missing); a complete
  fixture round-trips with parsed-tree equality and snake_case keys (`plan_id`,
  `price_cents`, `cancel_at_period_end`, `current_period_end`). Traces: AC-1, AC-5.

- **TC-AND-234-10 — Public vs. authenticated header policy.**
  Type: contract/MockWebServer. Target: JVM unit. Preconditions: enqueue 200s.
  Steps: call `plans(...)` and `mySubscriptions("usr_99")`; inspect both recorded
  requests. Expected: `plans` request has NO `X-User-Id` header; `mySubscriptions`
  has `X-User-Id: usr_99`. (Security: confirms the identity header is sent only
  where required and is a plain identifier, never a token.) Traces: AC-7.

- **TC-AND-234-11 — Hilt singleton on shared Retrofit.**
  Type: integration (`@HiltAndroidTest`, Robolectric). Target: JVM/Robolectric.
  Preconditions: minimal `core-testing` Hilt graph providing the shared Retrofit.
  Steps: inject `SubscriptionsApi` twice. Expected: non-null; the same singleton
  instance on repeated injection; no second `Retrofit`/`OkHttpClient` created.
  Traces: AC-7, AC-8.

- **TC-AND-234-12 — Flaky-dev-host / offline transport pass-through.**
  Type: contract/MockWebServer. Target: JVM unit. Preconditions: configure the
  MockWebServer to delay beyond the client read timeout (or use
  `SocketPolicy.NO_RESPONSE_THEN_CLOSE` for a connection drop). Steps: call an
  idempotent GET (`plans`/`mySubscriptions`). Expected: a transport exception
  (`SocketTimeoutException`/`IOException`) propagates unchanged from the suspend
  call (not swallowed, not converted) — AND-016 backoff / AND-235 stale policy own
  any retry/offline UX, not this layer. Traces: AC-3, AC-6.

- **TC-AND-234-13 — Real dev-host smoke against `api/creators/{id}/plans`
  (physical device).** Type: instrumented/e2e. Target: **PHYSICAL DEVICE — Samsung
  Galaxy A15 5G (SM-A156U, R5CX821TA9R), Android 14 / API 34, arm64-v8a.** Rationale:
  exercises the real cleartext dev host over a real cellular/Wi-Fi network and the
  arm64-v8a ABI (the emulator is x86_64/API 35), validating that the public plan
  list actually decodes against the live FastAPI contract end-to-end. Preconditions:
  device on host adb; `BuildConfig.API_BASE_URL=http://18.222.237.167:8000/`;
  cleartext permitted on `dev`. Steps: install debug build; invoke `plans(<known
  creatorId>)` from an instrumented harness. Expected: `200` with a decodable
  `List<SubscriptionPlan>` (or a clean `HttpException`/timeout if the dev host is
  down — recorded, not a hard failure). MUST run on the physical device for the
  real-network + arm64/API-34 coverage; the emulator (test35) provides the fast CI
  variant of the contract suite (TC-01…TC-12). Traces: AC-1, AC-3, AC-9.

(No accessibility cases: this layer has no UI surface — see §9. Accessibility is
owned downstream of AND-235.)

### Coverage matrix

| §14 Acceptance Criterion | Covered by |
| --- | --- |
| AC-1 (tiers/subs (de)serialize, mapping tested) | TC-01, TC-02, TC-09, TC-13 |
| AC-2 (all six ops declared, compiles vs §4.1 DTOs) | TC-03, TC-04, TC-05, TC-06 (collectively exercise all six) |
| AC-3 (verb + resolved path + request body per §5) | TC-01, TC-02, TC-03, TC-04, TC-05, TC-06, TC-12, TC-13 |
| AC-4 (`plan_id` serialized exactly; snake_case decode) | TC-04, TC-05, TC-02 |
| AC-5 (UNKNOWN enum; unknown keys tolerated; missing required throws) | TC-07, TC-09 |
| AC-6 (non-2xx → HttpException, not swallowed) | TC-08, TC-12 |
| AC-7 (Hilt @Singleton on shared Retrofit; no per-method cookie/CSRF) | TC-10, TC-11 |
| AC-8 (enum adapters on the single shared Moshi) | TC-07, TC-11 |
| AC-9 (tests pass in CI; clean build) | TC-13 + full suite green in CI |
