---
id: AND-234
title: Subscriptions API + DTOs
milestone: M5
epic: E32
priority: P0
size: M
status: draft
depends_on: [AND-027]
blocks: [AND-235]
---

# AND-234 — Subscriptions API + DTOs

## 1. Overview & Goal

This ticket delivers the typed HTTP seam and Moshi-backed DTOs for the
TestLogon **subscriptions** surface: listing the subscription **tiers** a creator
offers, reading the current viewer's active **subscription(s)**, and the
subscribe / change-tier / cancel mutations that drive the M5 "Subscription tiers
+ manage" screen (E32). It is the native-Android equivalent of the web reference
`frontend/src/api/endpoints/subscriptions.ts`.

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
  authenticated cookie-based session that every `/ui/subscriptions/*` call rides
  on. All endpoints here are session-scoped: they require the session cookies plus
  the `ui_csrf` → `X-CSRF-Token` header (mutations) injected by AND-012, and a
  `401` triggers the AND-013 refresh-then-retry. This ticket adds no auth headers.
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

FR-1. Define request DTOs: `SubscribeReq` (subscribe to a tier) and
`ChangeTierReq` (move an existing subscription to a different tier of the same
creator). Cancellation carries no body (subscription id is a path param).

FR-2. Define response DTOs: `SubscriptionTier`, `Subscription`, and the list
envelopes `TiersResp` (or bare `List<SubscriptionTier>` per Q-1) and
`SubscriptionsResp` (or bare `List<Subscription>` per Q-2). Define the price
sub-object `TierPrice`.

FR-3. Every DTO field maps to the backend's snake_case wire name via
`@Json(name = …)` where the Kotlin property is camelCase. Unknown/extra JSON keys
must be tolerated (additive backend evolution must not throw).

FR-4. Nullable vs. required must match the contract: optional fields are Kotlin
nullable with a `null` (or sensible) default; required fields are non-null and
absence surfaces as a deserialization error (fail fast).

FR-5. The subscription **status** and the tier **interval** are modeled as enums
with an `UNKNOWN` fallback so a new backend value never crashes deserialization,
serialized/deserialized via lowercase string tokens.

FR-6. Declare a single Retrofit interface `SubscriptionsApi` covering exactly:
`tiers(creatorId)`, `mySubscriptions()`, `subscription(id)`, `subscribe(body)`,
`changeTier(id, body)`, `cancel(id)`. All methods are `suspend` and return the
typed DTO body (or `Unit`/`OkResp` where no meaningful body is returned).

FR-7. HTTP verbs/paths match the backend contract (Section 5). Paths are declared
**without** a leading slash (per AND-010 convention). Request bodies use `@Body`
with the DTOs; path params use `@Path`. No raw `Map`/`JsonObject` bodies.

FR-8. The CSRF header is **not** declared per-method; AND-012's interceptor
injects `X-CSRF-Token` on mutating verbs. The interface stays header-agnostic for
cookies/CSRF.

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

```kotlin
package com.testlogon.android.core.model.subscription

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/** Recurring billing interval for a tier. */
enum class BillingInterval(val token: String) {
    MONTH("month"), YEAR("year"), WEEK("week"), UNKNOWN("unknown");
    companion object {
        fun fromToken(t: String): BillingInterval =
            entries.firstOrNull { it.token == t } ?: UNKNOWN
    }
}

/** Lifecycle state of a viewer's subscription. */
enum class SubscriptionStatus(val token: String) {
    ACTIVE("active"), TRIALING("trialing"), PAST_DUE("past_due"),
    CANCELED("canceled"), EXPIRED("expired"), UNKNOWN("unknown");
    companion object {
        fun fromToken(t: String): SubscriptionStatus =
            entries.firstOrNull { it.token == t } ?: UNKNOWN
    }
}

@JsonClass(generateAdapter = true)
data class TierPrice(
    @Json(name = "amount_cents") val amountCents: Long,    // minor units
    val currency: String,                                  // ISO-4217, e.g. "usd"
    val interval: BillingInterval = BillingInterval.MONTH,
)

@JsonClass(generateAdapter = true)
data class SubscriptionTier(
    @Json(name = "tier_id") val tierId: String,
    @Json(name = "creator_id") val creatorId: String,
    val name: String,
    val description: String? = null,
    val price: TierPrice,
    val benefits: List<String> = emptyList(),
    @Json(name = "is_active") val isActive: Boolean = true,    // creator-offered
    @Json(name = "sort_order") val sortOrder: Int = 0,
)

@JsonClass(generateAdapter = true)
data class Subscription(
    @Json(name = "subscription_id") val subscriptionId: String,
    @Json(name = "tier_id") val tierId: String,
    @Json(name = "creator_id") val creatorId: String,
    val status: SubscriptionStatus,
    @Json(name = "current_period_end") val currentPeriodEnd: String? = null, // ISO-8601
    @Json(name = "cancel_at_period_end") val cancelAtPeriodEnd: Boolean = false,
    @Json(name = "created_at") val createdAt: String? = null,
    val tier: SubscriptionTier? = null,                       // embedded when expanded
)

@JsonClass(generateAdapter = true)
data class SubscribeReq(
    @Json(name = "tier_id") val tierId: String,
)

@JsonClass(generateAdapter = true)
data class ChangeTierReq(
    @Json(name = "tier_id") val tierId: String,
)

/** Envelopes (used only if the backend wraps the arrays — see Q-1/Q-2). */
@JsonClass(generateAdapter = true)
data class TiersResp(val tiers: List<SubscriptionTier> = emptyList())

@JsonClass(generateAdapter = true)
data class SubscriptionsResp(val subscriptions: List<Subscription> = emptyList())
```

`OkResp` (the generic `{"ok": true}` ack) is reused from AND-026; it is **not**
redefined here. ISO-8601 timestamps remain `String` at this layer; parsing to
`Instant` is a domain-mapping concern in AND-235.

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

```kotlin
package com.testlogon.android.core.network.subscription

import com.testlogon.android.core.model.auth.OkResp
import com.testlogon.android.core.model.subscription.ChangeTierReq
import com.testlogon.android.core.model.subscription.Subscription
import com.testlogon.android.core.model.subscription.SubscriptionTier
import com.testlogon.android.core.model.subscription.SubscribeReq
import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Path

interface SubscriptionsApi {

    /** Tiers a creator currently offers. Idempotent GET (AND-016 backoff eligible). */
    @GET("ui/subscriptions/tiers/{creatorId}")
    suspend fun tiers(@Path("creatorId") creatorId: String): List<SubscriptionTier>

    /** The viewer's own subscriptions across all creators. Idempotent GET. */
    @GET("ui/subscriptions/me")
    suspend fun mySubscriptions(): List<Subscription>

    /** A single subscription by id (viewer-scoped). Idempotent GET. */
    @GET("ui/subscriptions/{subscriptionId}")
    suspend fun subscription(@Path("subscriptionId") subscriptionId: String): Subscription

    /** Subscribe to a tier. Returns the created subscription. */
    @Headers("Content-Type: application/json")
    @POST("ui/subscriptions")
    suspend fun subscribe(@Body body: SubscribeReq): Subscription

    /** Move an existing subscription to a different tier of the same creator. */
    @Headers("Content-Type: application/json")
    @POST("ui/subscriptions/{subscriptionId}/change-tier")
    suspend fun changeTier(
        @Path("subscriptionId") subscriptionId: String,
        @Body body: ChangeTierReq,
    ): Subscription

    /** Cancel a subscription (effective at period end per backend policy). */
    @DELETE("ui/subscriptions/{subscriptionId}")
    suspend fun cancel(@Path("subscriptionId") subscriptionId: String): OkResp
}
```

If `/openapi.json` shows the array endpoints are wrapped (`{tiers:[…]}`,
`{subscriptions:[…]}`), the return types switch to `TiersResp` /
`SubscriptionsResp` from §4.1 (resolved by Q-1/Q-2 before coding).

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

### 4.5 Path & verb conventions

- Relative paths, no leading slash: `@GET("ui/subscriptions/me")` resolves against
  `http://18.222.237.167:8000/` → `…/ui/subscriptions/me`.
- Mutating verbs: `subscribe` (POST), `changeTier` (POST), `cancel` (DELETE) —
  AND-012 attaches `X-CSRF-Token`.
- Idempotent GETs: `tiers`, `mySubscriptions`, `subscription` — eligible for
  AND-016 bounded backoff and AND-235 stale-cache reads.

### 4.6 Gradle wiring

No new dependencies. `core-model` already has Moshi codegen (KSP) from AND-010/026;
`core-network` already has Retrofit, Moshi converter, Hilt, and (test)
MockWebServer. This ticket adds source files only and relies on `:core-model`
being an `implementation` dependency of `:core-network` (already true).

## 5. API Contract

Base path (`dev`): `http://18.222.237.167:8000/`. All bodies are JSON.
All endpoints are session-scoped (cookies + `X-CSRF-Token` on mutations).

### GET `ui/subscriptions/tiers/{creatorId}`
Response `200`:
```json
[
  {
    "tier_id": "tier_basic",
    "creator_id": "usr_42",
    "name": "Supporter",
    "description": "Early access + monthly Q&A",
    "price": { "amount_cents": 499, "currency": "usd", "interval": "month" },
    "benefits": ["early_access", "monthly_qa"],
    "is_active": true,
    "sort_order": 0
  }
]
```

### GET `ui/subscriptions/me`
Response `200`:
```json
[
  {
    "subscription_id": "sub_01HRY",
    "tier_id": "tier_basic",
    "creator_id": "usr_42",
    "status": "active",
    "current_period_end": "2026-07-05T12:00:00Z",
    "cancel_at_period_end": false,
    "created_at": "2026-06-05T12:00:00Z"
  }
]
```

### GET `ui/subscriptions/{subscriptionId}`
Response `200`: a single `Subscription` (optionally with embedded `tier`). `404`
if the id is unknown or not owned by the viewer.

### POST `ui/subscriptions`
Request:
```json
{ "tier_id": "tier_basic" }
```
Response `200`/`201`: the created `Subscription` (status `active` or `trialing`).
`402`/`409` if payment is required or the viewer is already subscribed to that
creator (mapped by AND-015).

### POST `ui/subscriptions/{subscriptionId}/change-tier`
Request: `{ "tier_id": "tier_pro" }`. Response `200`: the updated `Subscription`.

### DELETE `ui/subscriptions/{subscriptionId}`
Response `200`: `{ "ok": true }`. Per backend policy the subscription typically
remains `active` with `cancel_at_period_end: true` until period end. `404` if
unknown/already canceled.

**Error envelope (all endpoints):** FastAPI `detail` union
(`string | [{msg, type, loc}] | {code, …}`). Typed mapping to `ApiError` is owned
by **AND-015**; this ticket lets non-2xx surface as `retrofit2.HttpException` so
AND-015/AND-018 can map it.

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
  AND-015 to decode the FastAPI `detail`. Notable codes: `402` (payment required
  on `subscribe`), `409` (already subscribed), `404` (unknown id), `401`
  (unauthenticated).
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
- **No credential/token handling:** auth rides on HttpOnly cookies invisible to
  this layer; no bearer tokens, no `Authorization` header, no manual `Cookie`
  header introduced.
- **Cleartext on dev:** these calls ride plaintext HTTP on `dev`
  (`http://18.222.237.167:8000`) — a known dev-only risk permitted by the scoped
  cleartext config (AND-006); `staging`/`prod` are HTTPS-only.
- **No sensitive payloads to redact:** request bodies contain only a `tier_id`
  (no PII, no card data — payment-method handling is a separate provider flow).
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
- **AC-2.** `SubscriptionsApi` declares all six operations (`tiers`,
  `mySubscriptions`, `subscription`, `subscribe`, `changeTier`, `cancel`); the
  module compiles against the §4.1 DTOs and reuses `OkResp` from AND-026.
- **AC-3.** Each endpoint is callable and its **verb + resolved path + request
  body** match Section 5, asserted with MockWebServer (T-1…T-6).
- **AC-4.** `subscribe`/`changeTier` serialize `{ "tier_id": … }` exactly (never
  `tierId`), and responses decode snake_case fields (`amount_cents`,
  `current_period_end`, `cancel_at_period_end`) via the codegen + enum adapters
  (T-4/T-5).
- **AC-5.** Unknown enum tokens map to `UNKNOWN`; unknown JSON keys are tolerated;
  a missing required field throws `JsonDataException` (T-7/T-8/T-9).
- **AC-6.** Non-2xx (e.g. `402` from `subscribe`) surfaces as `HttpException` and
  is not swallowed (T-10).
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
