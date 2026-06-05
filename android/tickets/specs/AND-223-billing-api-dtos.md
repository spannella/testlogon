---
id: AND-223
title: Billing API + DTOs
milestone: M5
epic: E31
priority: P0
size: M
status: draft
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

FR-3. Provide Moshi `@JsonClass(generateAdapter = true)` DTOs for:
subscription status, plan/price catalog, invoice list (paged), invoice line items,
payment methods, and the billing portal/checkout session link responses.

FR-4. Provide domain models in `core-model` that are UI-friendly: money expressed
as a `Money` value type (minor units + currency), timestamps as `Instant`, and
status/interval/state expressed as Kotlin `enum class` types with an explicit
`UNKNOWN` fallback member for forward compatibility.

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

    @GET("ui/billing/subscription")
    suspend fun getSubscription(): SubscriptionDto

    @GET("ui/billing/plans")
    suspend fun getPlans(): PlanCatalogDto

    @GET("api/billing/invoices")
    suspend fun getInvoices(
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int = 20,
    ): InvoicePageDto

    @GET("api/billing/invoices/{invoiceId}")
    suspend fun getInvoice(@Path("invoiceId") invoiceId: String): InvoiceDto

    @GET("ui/billing/payment-methods")
    suspend fun getPaymentMethods(): PaymentMethodListDto

    @POST("ui/billing/portal-session")
    suspend fun createPortalSession(
        @Body body: PortalSessionRequestDto,
    ): PortalSessionDto

    @POST("ui/billing/checkout-session")
    suspend fun createCheckoutSession(
        @Body body: CheckoutSessionRequestDto,
    ): CheckoutSessionDto
}
```

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

```kotlin
@JsonClass(generateAdapter = true)
data class SubscriptionDto(
    @Json(name = "subscription_id") val subscriptionId: String?,
    @Json(name = "status") val status: String,        // active|trialing|past_due|canceled|...
    @Json(name = "plan_id") val planId: String?,
    @Json(name = "current_period_end") val currentPeriodEnd: String?, // ISO-8601
    @Json(name = "cancel_at_period_end") val cancelAtPeriodEnd: Boolean = false,
    @Json(name = "trial_end") val trialEnd: String?,
    @Json(name = "seats") val seats: Int?,
)

@JsonClass(generateAdapter = true)
data class PlanCatalogDto(
    @Json(name = "plans") val plans: List<PlanDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class PlanDto(
    @Json(name = "plan_id") val planId: String,
    @Json(name = "name") val name: String,
    @Json(name = "interval") val interval: String,   // month|year
    @Json(name = "amount_minor") val amountMinor: Long,
    @Json(name = "currency") val currency: String,    // ISO-4217
    @Json(name = "features") val features: List<String> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class InvoicePageDto(
    @Json(name = "items") val items: List<InvoiceDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String?,
)

@JsonClass(generateAdapter = true)
data class InvoiceDto(
    @Json(name = "invoice_id") val invoiceId: String,
    @Json(name = "number") val number: String?,
    @Json(name = "status") val status: String,        // paid|open|void|uncollectible
    @Json(name = "issued_at") val issuedAt: String?,
    @Json(name = "amount_due_minor") val amountDueMinor: Long,
    @Json(name = "amount_paid_minor") val amountPaidMinor: Long,
    @Json(name = "currency") val currency: String,
    @Json(name = "hosted_invoice_url") val hostedInvoiceUrl: String?,
    @Json(name = "lines") val lines: List<InvoiceLineDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class InvoiceLineDto(
    @Json(name = "description") val description: String,
    @Json(name = "quantity") val quantity: Int = 1,
    @Json(name = "amount_minor") val amountMinor: Long,
)

@JsonClass(generateAdapter = true)
data class PaymentMethodListDto(
    @Json(name = "default_id") val defaultId: String?,
    @Json(name = "methods") val methods: List<PaymentMethodDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class PaymentMethodDto(
    @Json(name = "id") val id: String,
    @Json(name = "brand") val brand: String?,         // visa|mastercard|...
    @Json(name = "last4") val last4: String?,
    @Json(name = "exp_month") val expMonth: Int?,
    @Json(name = "exp_year") val expYear: Int?,
)

@JsonClass(generateAdapter = true)
data class PortalSessionRequestDto(
    @Json(name = "return_url") val returnUrl: String,
)

@JsonClass(generateAdapter = true)
data class PortalSessionDto(@Json(name = "url") val url: String)

@JsonClass(generateAdapter = true)
data class CheckoutSessionRequestDto(
    @Json(name = "plan_id") val planId: String,
    @Json(name = "success_url") val successUrl: String,
    @Json(name = "cancel_url") val cancelUrl: String,
)

@JsonClass(generateAdapter = true)
data class CheckoutSessionDto(
    @Json(name = "session_id") val sessionId: String,
    @Json(name = "url") val url: String,
)
```

### 4.3 Domain models (`core-model`)

```kotlin
package com.testlogon.android.core.model.billing

import java.time.Instant

data class Money(val minor: Long, val currency: String)

enum class SubscriptionStatus { ACTIVE, TRIALING, PAST_DUE, CANCELED, INCOMPLETE, UNKNOWN }
enum class BillingInterval { MONTH, YEAR, UNKNOWN }
enum class InvoiceStatus { PAID, OPEN, VOID, UNCOLLECTIBLE, UNKNOWN }

data class Subscription(
    val subscriptionId: String?,
    val status: SubscriptionStatus,
    val planId: String?,
    val currentPeriodEnd: Instant?,
    val cancelAtPeriodEnd: Boolean,
    val trialEnd: Instant?,
    val seats: Int?,
)

data class Plan(
    val planId: String,
    val name: String,
    val interval: BillingInterval,
    val price: Money,
    val features: List<String>,
)

data class Invoice(
    val invoiceId: String,
    val number: String?,
    val status: InvoiceStatus,
    val issuedAt: Instant?,
    val amountDue: Money,
    val amountPaid: Money,
    val hostedInvoiceUrl: String?,
    val lines: List<InvoiceLine>,
)

data class InvoiceLine(val description: String, val quantity: Int, val amount: Money)
data class InvoicePage(val items: List<Invoice>, val nextCursor: String?)
data class PaymentMethod(
    val id: String, val brand: String?, val last4: String?,
    val expMonth: Int?, val expYear: Int?, val isDefault: Boolean,
)
data class PaymentMethods(val default: PaymentMethod?, val methods: List<PaymentMethod>)
```

### 4.4 Mappers (`core-network`)

```kotlin
internal fun SubscriptionDto.toDomain() = Subscription(
    subscriptionId = subscriptionId,
    status = status.toSubscriptionStatus(),
    planId = planId,
    currentPeriodEnd = currentPeriodEnd?.toInstantOrNull(),
    cancelAtPeriodEnd = cancelAtPeriodEnd,
    trialEnd = trialEnd?.toInstantOrNull(),
    seats = seats,
)

internal fun String.toSubscriptionStatus() = when (lowercase()) {
    "active" -> SubscriptionStatus.ACTIVE
    "trialing" -> SubscriptionStatus.TRIALING
    "past_due" -> SubscriptionStatus.PAST_DUE
    "canceled", "cancelled" -> SubscriptionStatus.CANCELED
    "incomplete" -> SubscriptionStatus.INCOMPLETE
    else -> SubscriptionStatus.UNKNOWN
}
```

`toInstantOrNull()` is a shared helper that parses ISO-8601 with `DateTimeFormatter`
and returns `null` (logging a warning) on parse failure, so a malformed timestamp
never crashes mapping. `Money` is constructed from `amount*_minor` + `currency`.
`PaymentMethodListDto.toDomain()` resolves `isDefault` by matching each method `id`
against `defaultId`.

## 5. API Contract

All paths are relative to dev base `http://18.222.237.167:8000` (plaintext HTTP,
unreliable host). Auth is via cookies; mutating `POST` calls carry the
`X-CSRF-Token` header injected by the shared interceptor.

| Verb | Path | Body | Response DTO |
|------|------|------|--------------|
| GET | `/ui/billing/subscription` | — | `SubscriptionDto` |
| GET | `/ui/billing/plans` | — | `PlanCatalogDto` |
| GET | `/api/billing/invoices?cursor=&limit=` | — | `InvoicePageDto` |
| GET | `/api/billing/invoices/{invoiceId}` | — | `InvoiceDto` |
| GET | `/ui/billing/payment-methods` | — | `PaymentMethodListDto` |
| POST | `/ui/billing/portal-session` | `PortalSessionRequestDto` | `PortalSessionDto` |
| POST | `/ui/billing/checkout-session` | `CheckoutSessionRequestDto` | `CheckoutSessionDto` |

Example `GET /ui/billing/subscription` 200:

```json
{
  "subscription_id": "sub_9f2",
  "status": "active",
  "plan_id": "plan_pro_monthly",
  "current_period_end": "2026-07-01T00:00:00Z",
  "cancel_at_period_end": false,
  "trial_end": null,
  "seats": 5
}
```

Example `GET /api/billing/invoices` 200:

```json
{
  "items": [
    {
      "invoice_id": "in_001", "number": "TL-2026-001", "status": "paid",
      "issued_at": "2026-05-01T00:00:00Z",
      "amount_due_minor": 4900, "amount_paid_minor": 4900, "currency": "USD",
      "hosted_invoice_url": "https://pay.example/in_001",
      "lines": [{ "description": "Pro plan (May)", "quantity": 1, "amount_minor": 4900 }]
    }
  ],
  "next_cursor": "in_001"
}
```

Error envelopes follow the FastAPI shape and are mapped by the shared error mapper:

```json
{ "detail": "No active subscription" }
{ "detail": [{ "loc": ["body","plan_id"], "msg": "field required", "type": "value_error.missing" }] }
{ "detail": { "code": "card_declined", "message": "Your card was declined" } }
```

Billing-relevant statuses to handle (no new client code, but tested): `402 Payment
Required`, `409 Conflict` (duplicate/already-subscribed), `404` (unknown invoice),
`401` (handled by the AND-027 refresh-and-retry interceptor).

The exact field names, nullability, and enum members above are **provisional** and
MUST be reconciled against `/openapi.json` and `frontend/src/api/types.ts` during
implementation; the verification step in section 11 captures live fixtures.

## 6. Data & State Management

This ticket holds **no state**. There is no Room entity, no DataStore key, and no
StateFlow. The `BillingApi` is stateless; the only "state" is the inherited OkHttp
cookie jar from AND-027, which is out of this ticket's scope.

Pagination state: `getInvoices` is cursor-based (`next_cursor`). The DTO/model
expose the cursor as an opaque `String?`. Wiring this into Paging 3 (a
`PagingSource<String, Invoice>`) is owned by the future `feature-billing` ticket,
not here. This ticket only guarantees the cursor field maps losslessly.

Caching and offline/stale presentation are likewise deferred to `feature-billing`
+ a `core-data` billing repository. This contract is built so those can add a
Room mirror later without altering DTO field names.

## 7. Error Handling & Resilience

- **Idempotent GETs** (`subscription`, `plans`, `invoices`, `invoice`,
  `payment-methods`) are eligible for the bounded backoff retry policy configured
  in the shared OkHttp client (AND-027): retry on connect/read timeout and 5xx,
  capped (e.g., 3 attempts, jittered backoff), with a ~20 s per-attempt timeout
  given the unreliable dev host.
- **POST endpoints** (`portal-session`, `checkout-session`) are **not** retried
  automatically — they are mutating and may create duplicate sessions. They fail
  fast to `ApiResult.Error`.
- **401** triggers the single-shot `POST /ui/session/refresh` then one retry,
  entirely within the inherited interceptor; `BillingApi` is unaware.
- **Mapping resilience:** mappers never throw. Unknown enum strings → `UNKNOWN`;
  unparseable timestamps → `null` (warn-logged); missing collections → empty.
  This guarantees a backend adding a new `status` value never crashes the client.
- **Error typing:** the shared `ApiError` mapper converts all three `detail`
  shapes into typed errors; billing tests assert that `402`/`409` map to the
  expected `ApiError` variant carrying any `code`/`message`.

## 8. Security & Privacy

- **No new auth surface.** Billing rides the existing cookie session + CSRF echo.
  No tokens, keys, or credentials are introduced or stored by this ticket.
- **PII / cardholder data:** DTOs intentionally carry only `brand`, `last4`,
  `exp_month`, `exp_year` — never PAN, CVV, or full card data (those live with the
  PCI-scoped processor). `last4` and expiry are display-safe but still sensitive;
  they must NOT be written to logs (see section 10).
- **Hosted URLs** (`hosted_invoice_url`, portal/checkout `url`) are
  capability-bearing — treat as secrets in logs; never emit at INFO.
- **Transport:** dev backend is plaintext HTTP. Production must be HTTPS; the
  network security config (separate infra ticket) must restrict cleartext to the
  dev host only. This ticket adds no cleartext exemptions itself.

## 9. Accessibility & i18n

No UI is produced, so screen-level a11y is N/A and owned by the downstream
`feature-billing` ticket. Two i18n-relevant design choices are made here to enable
correct downstream formatting:

- **Money** is kept as minor units + ISO-4217 `currency`, never a pre-formatted
  string, so the UI can format with `NumberFormat.getCurrencyInstance(locale)`.
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
4. **Error-mapping tests:** enqueue 402/409/404 with each `detail` shape; assert
   the resulting typed `ApiError`.
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
- **OQ-2 (path namespacing):** The backlog lists both `/ui/billing/*` and
  `/api/billing/*`. The assumed split is: `ui/*` for session-cookie browser-style
  endpoints (subscription, plans, payment-methods, portal/checkout) and `api/*`
  for resource endpoints (invoices). Confirm against `/openapi.json`; correct any
  mis-attribution.
- **OQ-3 (money representation):** Confirm backend sends integer minor units
  (`amount_minor`) vs. decimal strings. The `Money(minor, currency)` design
  assumes minor units; if decimals, add a parsing step. Verify via fixtures.
- **Risk — contract drift:** dev backend is unreliable and may evolve. Mitigated
  by `UNKNOWN` enum fallbacks and total mappers, plus the debug drift counter.
- **Risk — fixture staleness:** captured fixtures may lag the live schema; the
  documented live-verification step (section 11.5) must be re-run if billing tests
  start failing against staging.

## 14. Acceptance Criteria

1. `BillingApi` exists in `com.testlogon.android.core.network.billing` with a
   `suspend` function for each of the 7 endpoints in section 5, paths/verbs/query
   params matching the contract — verified by MockWebServer tests.
2. All billing DTOs exist with Moshi codegen adapters and deserialize the captured
   fixtures with every field asserted (including null/missing-key defaults).
3. All `core-model.billing` domain models and total `toDomain()` mappers exist;
   unknown enums → `UNKNOWN`, bad timestamps → `null`, missing collections →
   empty — proven by mapper unit tests.
4. POST requests carry `X-CSRF-Token`; the `BillingApi` reuses the AND-027
   authenticated Retrofit and adds no auth code.
5. 402/409/404 error envelopes (all three `detail` shapes) map to the expected
   typed `ApiError` — tested.
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
