---
id: AND-319
title: KYC API + DTOs
milestone: M7
epic: E42
priority: P0
size: M
status: draft
depends_on: [AND-027]
blocks: [AND-320, AND-321, AND-322]
---

# AND-319 — KYC API + DTOs

## 1. Overview & Goal

This ticket delivers the typed Retrofit service interface `KycApi` plus the
Moshi-backed data-transfer objects (DTOs) that model the wire format of the
TestLogon Know-Your-Customer (KYC) surface under `/v1/kyc/*`. It is the typed
HTTP seam through which the KYC feature (`feature-kyc`) and the KYC repository
(`core-data`) read the user's KYC tier, current status, the document/field
requirements for advancing a tier, the result of evaluating a submission, and
the list of open compliance cases.

Scope, verbatim from the backlog: *`/v1/kyc/*` DTOs (tiers/me, requirements,
evaluate, cases).* The single acceptance criterion is that **KYC payloads map
(tested)** — every documented request/response payload (de)serializes exactly,
and every endpoint is callable with its verb/path/body matching the backend
contract, proven with `MockWebServer`.

This is a **transport + serialization** ticket. It owns: the `KycApi` Retrofit
interface (`@GET`/`@POST` annotations, `@Body`/`@Path`/`@Query` bindings), the
`@JsonClass(generateAdapter = true)` DTOs in `core-model`, any custom Moshi
adapters (KYC status / tier enums), and the Hilt providers that construct the
service from the shared Retrofit (AND-010) and register adapters on the shared
`Moshi` (AND-010). It deliberately does **not** own: the persistent cookie jar
(AND-011), CSRF injection (AND-012), the 401-refresh `Authenticator` (AND-013),
`ApiResult`/`ApiError` mapping (AND-015/AND-018), retry-backoff (AND-016), or
any repository / ViewModel / Compose UI (downstream M7 tickets AND-320+).

Deliverable: a compiling `KycApi`, its DTOs and adapters, the Hilt wiring, and a
`MockWebServer`/round-trip test suite asserting each endpoint's verb, resolved
path, request body, and decoded response, plus DTO round-trip fidelity.

## 2. Context & References

- **Repo / location:** `spannella/testlogon`, monorepo subfolder `android/`,
  branch `android-port`. DTOs land in module **`core-model`** under package
  `com.testlogon.android.core.model.kyc`; the `KycApi` interface, adapters, and
  Hilt modules land in **`core-network`** under
  `com.testlogon.android.core.network.kyc`.
- **Canonical package:** `com.testlogon.android` everywhere.
- **Stack pins relevant here:** Kotlin 2.0.21, Retrofit **2.11.0**, OkHttp
  **4.12.0**, Moshi **1.15.x** (codegen via KSP), Hilt (KSP), Coroutines, JDK 17,
  minSdk 24 / compileSdk 35, AGP 8.7.3 / Gradle 8.9.
- **Module layering:** `app -> feature-* -> core-*`. `KycApi` lives in
  `core-network`, consumes DTOs from `core-model`, and is consumed by `core-data`
  repositories. No `feature-*`/`app` symbols leak into `core-network`.
- **Upstream dependency — AND-027 (AuthApi / session endpoints):** establishes
  the shared, cookie-authenticated Retrofit/OkHttp seam (cookie jar AND-011, CSRF
  AND-012, 401-refresh AND-013) on which all authenticated `/v1/*` calls — KYC
  included — depend. KYC endpoints require an authenticated session; without the
  session pipeline they 401. This ticket reuses that pipeline unchanged.
- **Transitive upstream:** AND-010 (shared Retrofit + Moshi + KSP codegen),
  AND-009 (shared `OkHttpClient`, ~20s timeouts, redacting logger), AND-006
  (`BuildConfig.API_BASE_URL`; `dev` → `http://18.222.237.167:8000/`).
- **Backend:** FastAPI + DynamoDB; dev host is plaintext HTTP and unreliable
  (~20s timeouts; bounded backoff for idempotent GETs owned by AND-016). OpenAPI
  at `/openapi.json` (inspect the `/v1/kyc/*` schemas before coding). Web
  reference for exact field names: `frontend/src/api/endpoints/kyc.ts` and shared
  types in `frontend/src/api/types.ts` — mirror snake_case names; do not invent
  camelCase wire keys.
- **Error envelope:** FastAPI `detail` union (`string | [{msg,type,loc}] |
  {code,...}`); typed mapping to `ApiError` is owned by **AND-015**. This ticket
  lets non-2xx surface as `retrofit2.HttpException`.

## 3. Functional Requirements

FR-1. Declare a single Retrofit interface `KycApi` covering exactly these
operations: `tiers` (catalog of all tiers), `me` (the caller's KYC status/tier),
`requirements` (what is needed to reach a target tier), `evaluate` (submit
field/document data for assessment), and `cases` (list compliance cases) with
`case(caseId)` for a single case.

FR-2. Each method's HTTP verb and relative path match the backend contract
(Section 5). Paths are declared **without** a leading slash (AND-010 convention)
so they append to the normalized base URL.

FR-3. All methods are `suspend` functions returning the typed DTO body. GETs
(`tiers`, `me`, `requirements`, `cases`, `case`) are idempotent and eligible for
AND-016 bounded backoff; `evaluate` is a non-idempotent POST and is **not**
retried by AND-016.

FR-4. Request bodies use `@Body` with request DTOs; path parameters use `@Path`;
the target-tier selector on `requirements` uses a `@Query` parameter. No raw
`Map`/`JsonObject` bodies.

FR-5. POST methods carry `@Headers("Content-Type: application/json")`. The CSRF
header (`X-CSRF-Token`) is injected globally by AND-012 for mutating verbs and is
**not** declared per-method here. `KycApi` stays cookie/CSRF-agnostic.

FR-6. Define request DTOs: `KycEvaluateReq` (with a nested
`KycFieldSubmission`/document-reference structure). Define response DTOs:
`KycTier`, `KycTiersResp`, `KycMeResp`, `KycRequirement`, `KycRequirementsResp`,
`KycEvaluateResp`, `KycCase`, `KycCasesResp`. Model the KYC status and tier
identifiers as enums with an `UNKNOWN` fallback so additive backend values never
crash deserialization (FR-9).

FR-7. Every DTO field maps to the backend snake_case name via `@Json(name=…)`
when the Kotlin property is camelCase. Unknown/extra JSON keys are tolerated
(Moshi codegen default). Optional fields are Kotlin-nullable with `null`
defaults; required fields are non-null and their absence must throw
`JsonDataException` (fail fast).

FR-8. All DTOs are immutable `data class`es exposing read-only `List<T>` (no
mutable collections). Timestamps stay `String` (ISO-8601) at this layer; parsing
to `Instant` is deferred to the domain-mapping/repository ticket.

FR-9. KYC status (`unverified | pending | verified | rejected | review`) and tier
id (`tier0 | tier1 | tier2 | ...`) (de)serialize via custom Moshi adapters that
fall back to an `UNKNOWN` enum member for unrecognized tokens.

FR-10. Hilt `@Provides @Singleton fun provideKycApi(retrofit: Retrofit): KycApi`
constructs the service from the shared Retrofit (AND-010). No new
Retrofit/OkHttp instance is created. The KYC adapters register onto the shared
`Moshi` via the AND-010 adapter-set multibinding (same mechanism AND-026 used for
`MfaFactorAdapter`).

## 4. Technical Design

DTOs land in
`core-model/src/main/kotlin/com/testlogon/android/core/model/kyc/`; the
interface, adapters, and Hilt modules land in
`core-network/src/main/kotlin/com/testlogon/android/core/network/kyc/`.

### 4.1 Enums + adapters

```kotlin
package com.testlogon.android.core.model.kyc

enum class KycStatus(val token: String) {
    UNVERIFIED("unverified"),
    PENDING("pending"),
    REVIEW("review"),
    VERIFIED("verified"),
    REJECTED("rejected"),
    UNKNOWN("unknown");
    companion object { fun fromToken(t: String) =
        entries.firstOrNull { it.token == t } ?: UNKNOWN }
}

enum class KycTierId(val token: String) {
    TIER0("tier0"), TIER1("tier1"), TIER2("tier2"), TIER3("tier3"),
    UNKNOWN("unknown");
    companion object { fun fromToken(t: String) =
        entries.firstOrNull { it.token == t } ?: UNKNOWN }
}
```

```kotlin
package com.testlogon.android.core.network.kyc

import com.squareup.moshi.FromJson
import com.squareup.moshi.ToJson
import com.testlogon.android.core.model.kyc.KycStatus
import com.testlogon.android.core.model.kyc.KycTierId

object KycStatusAdapter {
    @FromJson fun fromJson(v: String) = KycStatus.fromToken(v)
    @ToJson fun toJson(s: KycStatus) = s.token
}
object KycTierIdAdapter {
    @FromJson fun fromJson(v: String) = KycTierId.fromToken(v)
    @ToJson fun toJson(t: KycTierId) = t.token
}
```

### 4.2 Response + request DTOs

```kotlin
package com.testlogon.android.core.model.kyc

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
data class KycTier(
    val id: KycTierId,
    val name: String,
    @Json(name = "limit_currency") val limitCurrency: String? = null,
    @Json(name = "daily_limit") val dailyLimit: Long? = null,
    @Json(name = "required_factors") val requiredFactors: List<String> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class KycTiersResp(val tiers: List<KycTier> = emptyList())

@JsonClass(generateAdapter = true)
data class KycMeResp(
    @Json(name = "user_id") val userId: String,
    val status: KycStatus,
    @Json(name = "current_tier") val currentTier: KycTierId,
    @Json(name = "next_tier") val nextTier: KycTierId? = null,
    @Json(name = "submitted_at") val submittedAt: String? = null,    // ISO-8601
    @Json(name = "reviewed_at") val reviewedAt: String? = null,
    @Json(name = "reject_reason") val rejectReason: String? = null,
)

@JsonClass(generateAdapter = true)
data class KycRequirement(
    val key: String,                                                 // e.g. "id_document"
    val label: String,
    val type: String,                                                // "document" | "field" | "selfie"
    val required: Boolean = true,
    val satisfied: Boolean = false,
    @Json(name = "accepted_formats") val acceptedFormats: List<String> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class KycRequirementsResp(
    @Json(name = "target_tier") val targetTier: KycTierId,
    val requirements: List<KycRequirement> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class KycFieldSubmission(
    val key: String,
    val value: String? = null,                                       // field value
    @Json(name = "document_id") val documentId: String? = null,      // ref to prior upload
)

@JsonClass(generateAdapter = true)
data class KycEvaluateReq(
    @Json(name = "target_tier") val targetTier: KycTierId,
    val fields: List<KycFieldSubmission> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class KycEvaluateResp(
    val status: KycStatus,                                           // resulting status
    @Json(name = "granted_tier") val grantedTier: KycTierId? = null,
    @Json(name = "case_id") val caseId: String? = null,             // opened when review needed
    @Json(name = "unmet_requirements") val unmetRequirements: List<String> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class KycCase(
    @Json(name = "case_id") val caseId: String,
    val status: KycStatus,
    @Json(name = "target_tier") val targetTier: KycTierId,
    @Json(name = "opened_at") val openedAt: String,                 // ISO-8601
    @Json(name = "updated_at") val updatedAt: String? = null,
    val note: String? = null,
)

@JsonClass(generateAdapter = true)
data class KycCasesResp(val cases: List<KycCase> = emptyList())
```

(If `/openapi.json` returns a bare array for any list endpoint instead of a
wrapper object, the corresponding method returns `List<KycTier>` /
`List<KycCase>` directly and the wrapper DTO is dropped — resolved per Q-1
before coding.)

### 4.3 The `KycApi` interface

```kotlin
package com.testlogon.android.core.network.kyc

import com.testlogon.android.core.model.kyc.KycCase
import com.testlogon.android.core.model.kyc.KycCasesResp
import com.testlogon.android.core.model.kyc.KycEvaluateReq
import com.testlogon.android.core.model.kyc.KycEvaluateResp
import com.testlogon.android.core.model.kyc.KycMeResp
import com.testlogon.android.core.model.kyc.KycRequirementsResp
import com.testlogon.android.core.model.kyc.KycTiersResp
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

interface KycApi {

    /** Catalog of all KYC tiers and their limits/requirements. Idempotent GET. */
    @GET("v1/kyc/tiers")
    suspend fun tiers(): KycTiersResp

    /** Caller's current KYC status + tier. Idempotent GET. */
    @GET("v1/kyc/me")
    suspend fun me(): KycMeResp

    /** Requirements to reach [targetTier]. Idempotent GET. */
    @GET("v1/kyc/requirements")
    suspend fun requirements(@Query("target_tier") targetTier: String): KycRequirementsResp

    /** Submit fields/documents for assessment toward a target tier. Non-idempotent. */
    @Headers("Content-Type: application/json")
    @POST("v1/kyc/evaluate")
    suspend fun evaluate(@Body body: KycEvaluateReq): KycEvaluateResp

    /** Caller's KYC/compliance cases. Idempotent GET. */
    @GET("v1/kyc/cases")
    suspend fun cases(): KycCasesResp

    /** A single case by id. Idempotent GET. */
    @GET("v1/kyc/cases/{caseId}")
    suspend fun case(@Path("caseId") caseId: String): KycCase
}
```

### 4.4 Hilt wiring

```kotlin
package com.testlogon.android.core.network.kyc.di

import com.testlogon.android.core.network.kyc.KycApi
import com.testlogon.android.core.network.kyc.KycStatusAdapter
import com.testlogon.android.core.network.kyc.KycTierIdAdapter
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import dagger.multibindings.IntoSet
import retrofit2.Retrofit
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object KycNetworkModule {

    @Provides @Singleton
    fun provideKycApi(retrofit: Retrofit): KycApi = retrofit.create(KycApi::class.java)

    // Registers onto the shared Moshi via AND-010's @AppMoshiAdapter set multibinding.
    @Provides @IntoSet @com.testlogon.android.core.network.di.AppMoshiAdapter
    fun kycStatusAdapter(): Any = KycStatusAdapter

    @Provides @IntoSet @com.testlogon.android.core.network.di.AppMoshiAdapter
    fun kycTierIdAdapter(): Any = KycTierIdAdapter
}
```

The injected `Retrofit` is the singleton from AND-010's `NetworkModule`, built on
AND-009's shared `OkHttpClient` (cookie jar, CSRF, 401-refresh already attached).
No client/Retrofit/Moshi is constructed here.

### 4.5 Gradle wiring

No new dependencies. `core-network` already has Retrofit, Moshi, Hilt, and (test)
MockWebServer; `core-model` already has Moshi codegen via KSP. This ticket adds
source files only. `core-network` already declares `implementation(project(":core-model"))`.

## 5. API Contract

Base path (`dev`): `http://18.222.237.167:8000/`. All bodies JSON. All endpoints
require an authenticated session (cookies + `X-CSRF-Token` on the POST).

### GET `v1/kyc/tiers`
Response `200`:
```json
{ "tiers": [
  { "id": "tier0", "name": "Basic", "limit_currency": "USD", "daily_limit": 0,
    "required_factors": [] },
  { "id": "tier1", "name": "Verified", "limit_currency": "USD",
    "daily_limit": 1000, "required_factors": ["id_document", "selfie"] }
] }
```

### GET `v1/kyc/me`
Response `200`:
```json
{ "user_id": "usr_42", "status": "pending", "current_tier": "tier0",
  "next_tier": "tier1", "submitted_at": "2026-06-05T12:00:00Z",
  "reviewed_at": null, "reject_reason": null }
```
`401` when unauthenticated → AND-013 refresh-then-retry once.

### GET `v1/kyc/requirements?target_tier=tier1`
Response `200`:
```json
{ "target_tier": "tier1", "requirements": [
  { "key": "id_document", "label": "Government ID", "type": "document",
    "required": true, "satisfied": false,
    "accepted_formats": ["jpeg", "png", "pdf"] },
  { "key": "full_name", "label": "Full legal name", "type": "field",
    "required": true, "satisfied": false, "accepted_formats": [] }
] }
```

### POST `v1/kyc/evaluate`
Request:
```json
{ "target_tier": "tier1",
  "fields": [
    { "key": "full_name", "value": "Alice A." },
    { "key": "id_document", "document_id": "doc_abc123" }
  ] }
```
Response `200`:
```json
{ "status": "review", "granted_tier": null, "case_id": "case_77",
  "unmet_requirements": [] }
```
(or, on immediate grant, `{ "status": "verified", "granted_tier": "tier1",
"case_id": null, "unmet_requirements": [] }`). `422` with the FastAPI `detail`
list when the body fails validation → surfaces as `HttpException` for AND-015.

### GET `v1/kyc/cases`
Response `200`:
```json
{ "cases": [
  { "case_id": "case_77", "status": "review", "target_tier": "tier1",
    "opened_at": "2026-06-05T12:01:00Z", "updated_at": null, "note": null }
] }
```

### GET `v1/kyc/cases/{caseId}`
Path: `v1/kyc/cases/case_77`. Response `200`: a single `KycCase` object (shape
above). `404` if the case id is unknown or not owned by the caller.

**Error envelope (all endpoints):** FastAPI `detail` union; mapping owned by
AND-015. This ticket lets non-2xx surface as `retrofit2.HttpException`.

## 6. Data & State Management

`KycApi` is **stateless** — a singleton interface proxy with no fields. DTOs are
transient wire types.

- **No Room / DataStore here.** Caching `KycMeResp`, tiers, or cases is a
  `core-data`/repository concern (downstream M7). DTOs must **not** be persisted
  directly; they map to domain models in the repository ticket.
- **No `StateFlow`/`UiState`.** ViewModels consume the KYC repository, which wraps
  these calls in `ApiResult<T>` (AND-018). This layer returns plain DTOs on the
  happy path and throws on failure.
- **Session state** lives in cookies, persisted by the AND-011 jar; the `ui_csrf`
  cookie → `X-CSRF-Token` header is handled by AND-012. `KycApi` is unaware of
  both.
- **Threading:** suspend methods are invoked from a coroutine on an IO dispatcher
  injected at the repository layer; this ticket imposes no dispatcher.
- **Serialization:** uses the shared Moshi (KSP codegen adapters + the two custom
  enum adapters). Unknown keys are skipped; absent optional fields fall back to
  Kotlin defaults. ISO-8601 timestamps remain `String`; `Instant` parsing is
  deferred downstream. `KycStatus.UNKNOWN` / `KycTierId.UNKNOWN` are the only
  behavioral fallbacks and exist solely to keep deserialization total.

## 7. Error Handling & Resilience

Responsibilities are narrow: declare endpoints/DTOs so failures propagate cleanly.

- **Non-2xx** surfaces as `retrofit2.HttpException` carrying the raw error body
  for AND-015 to decode the FastAPI `detail` union. `401` on any call is
  intercepted by the AND-013 `Authenticator` (refresh once, retry once); only a
  second `401` propagates and the repository routes to login (AND-025).
- **`422` from `evaluate`** (validation) surfaces as `HttpException(422)`; the
  repository/ViewModel maps `detail[].msg`/`loc` to field errors via AND-015.
  This ticket does not map it.
- **Transport failures** (`SocketTimeoutException`, `UnknownHostException`,
  `IOException`) propagate unchanged; ~20s timeouts and bounded backoff for the
  idempotent GETs (`tiers`, `me`, `requirements`, `cases`, `case`) are owned by
  AND-009/AND-016. `evaluate` (POST, non-idempotent) is excluded from retry.
- **Deserialization failures** surface as `JsonDataException`; missing required
  fields fail fast (asserted in tests). Unknown enum tokens map to `UNKNOWN`
  rather than throwing, so additive backend status/tier values are safe.
- **Empty/`404` cases:** `case(caseId)` with an unknown id returns `404` →
  `HttpException(404)`; the repository treats it as "case not found". This layer
  does not special-case it.
- This ticket maps **no** errors itself (AND-015/AND-018 own that) and adds no
  offline/stale UI (downstream feature ticket + AND-045-style baseline).

## 8. Security & Privacy

- **PII in payloads.** `KycEvaluateReq.fields` can carry personal data (legal
  name, document references). These DTOs and request bodies must **not** be
  logged. The AND-009 redacting `HttpLoggingInterceptor` must redact
  `v1/kyc/evaluate` request bodies (documented here as a constraint for AND-009;
  add the path to its redaction list). A code-review check confirms KYC bodies
  never reach logcat in any build.
- **Redacting `toString()`.** `KycFieldSubmission` and `KycEvaluateReq` override
  `toString()` to mask field values:
  ```kotlin
  override fun toString() = "KycFieldSubmission(key=$key, value=***, documentId=$documentId)"
  ```
- **Transport.** On `dev` these calls ride plaintext HTTP — a known dev-only risk
  permitted by the scoped cleartext config (AND-006); `staging`/`prod` are
  HTTPS-only. No KYC PII should be exercised against the plaintext dev host beyond
  synthetic test data.
- **No credential/token storage.** Auth is cookie-based; `KycApi` declares no
  manual `Cookie`/`Authorization` headers. Cases/requirements are server-scoped
  to the authenticated principal (server-enforced); the client passes the
  cookie-scoped identity implicitly — no user id is sent in KYC paths.
- **Fixtures** use synthetic identities/documents only; no real PII in committed
  JSON samples.

## 9. Accessibility & i18n

Not applicable — this is a headless transport + serialization layer with no UI
surface and no user-facing strings. `KycRequirement.label`, `reject_reason`, and
`note` are backend-supplied display strings passed through verbatim; localization
and presentation are owned by the downstream KYC feature UI (AND-321/AND-322).
No `strings.xml` entries are added here. Accessibility is owned by `core-ui` and
the KYC screens.

## 10. Telemetry & Logging

- **HTTP logging** is inherited from AND-009's redacting interceptor (debug builds
  only); no new logging here, and `v1/kyc/evaluate` bodies must be redacted
  (Section 8).
- **No analytics events** emitted by this layer. KYC funnel events
  (tier-view, requirement-start, evaluate-submit/result) are emitted by the KYC
  feature ViewModels (their own M7 ticket) derived from `ApiResult` outcomes — not
  from `KycApi`.
- **Build-time signal:** KSP must generate Moshi adapters for every DTO, and the
  two custom enum adapters must be registered on the shared `Moshi`; a missing
  adapter fails the build (no reflection fallback, per AND-010 policy).

## 11. Testing Strategy

Two suites: DTO round-trip tests in `core-model` and `MockWebServer` endpoint
tests in `core-network`, both using the production Moshi/Retrofit configuration
(including the KYC enum adapters).

Test harness:
```kotlin
private fun api(server: MockWebServer): KycApi {
    val moshi = Moshi.Builder()
        .add(KycStatusAdapter).add(KycTierIdAdapter)   // mirrors provideMoshi()
        .build()
    val retrofit = Retrofit.Builder()
        .baseUrl(server.url("/"))
        .addConverterFactory(MoshiConverterFactory.create(moshi))
        .build()
    return retrofit.create(KycApi::class.java)
}
```

**T-1 — `tiers` contract.** Enqueue the Section-5 tiers body; assert
`GET /v1/kyc/tiers`, and that `tiers[1].id == KycTierId.TIER1` and
`requiredFactors == ["id_document","selfie"]`.

**T-2 — `me` contract.** Assert `GET /v1/kyc/me`; decode snake_case fields
(`current_tier`, `next_tier`, `submitted_at`) and `status == KycStatus.PENDING`.

**T-3 — `requirements` query.** Call `requirements("tier1")`; assert the request
path is `/v1/kyc/requirements?target_tier=tier1` and the list decodes with
`type`/`accepted_formats`.

**T-4 — `evaluate` request + response.** Call `evaluate(...)`; assert
`POST /v1/kyc/evaluate`, the serialized body contains `"target_tier":"tier1"` and
the nested `"document_id":"doc_abc123"`, and the response decodes `case_id` and
`status == KycStatus.REVIEW`.

**T-5 — `cases` / `case`.** Assert `GET /v1/kyc/cases` decodes the list and
`GET /v1/kyc/cases/case_77` (path param interpolated) decodes a single `KycCase`.

**T-6 — unknown enum tolerance.** A `me` body with `"status":"escalated"` decodes
to `KycStatus.UNKNOWN` and does not throw; a tier id `"tier9"` → `KycTierId.UNKNOWN`.

**T-7 — required-field fail-fast.** A `me` body missing `current_tier` throws
`JsonDataException`; an extra `"server_time"` key is tolerated.

**T-8 — error propagation.** A `422` from `evaluate` and a `404` from
`case("nope")` each throw `retrofit2.HttpException` with the matching `code()`
(confirms non-2xx is not swallowed).

**T-9 — round-trip fidelity.** For each response DTO a captured sample lives at
`core-model/src/test/resources/kyc/<name>.json`; the test asserts
deserialize→serialize→parse-tree equality (ignoring key order/whitespace) and
that serialized output uses snake_case keys and lowercase enum tokens.

**T-10 — redaction.** `KycEvaluateReq(...).toString()` and
`KycFieldSubmission(...).toString()` must not contain field `value` content.

**T-11 — Hilt provider.** `@HiltAndroidTest` (or `core-testing` harness) injects
`KycApi` and asserts a non-null singleton built on the shared Retrofit (same
instance on repeated injection).

Coverage target: ≥90% on the new surface; every endpoint has at least one
verb/path assertion and every DTO has at least one round-trip test + committed
fixture. Test classes: `KycApiContractTest` (`core-network`),
`KycDtoRoundTripTest` (`core-model`).

## 12. Dependencies & Sequencing

**Hard upstream (must merge first):**
- **AND-027** — AuthApi / session endpoints. Establishes the authenticated,
  cookie-bearing Retrofit/OkHttp pipeline (with AND-011/AND-012/AND-013) that all
  `/v1/kyc/*` calls ride; KYC endpoints 401 without it. Blocking.

**Transitive upstream (already required by AND-027):** AND-026 (Auth DTOs +
adapter-set hook), AND-010 (shared Retrofit/Moshi/KSP + `@AppMoshiAdapter`
multibinding), AND-009 (shared `OkHttpClient`), AND-006 (`BuildConfig`),
AND-003/AND-004 (module structure, Hilt baseline). AND-015/AND-016/AND-018 are
relied on at runtime but are not compile-time blockers for this interface.

**Downstream (this ticket blocks):**
- The **KYC repository** in `core-data` and the **KYC feature** ViewModels/UI
  consume `KycApi` and these DTOs (M7 tickets AND-320 = repository, AND-321 =
  ViewModel/state, AND-322 = Compose screens — align ids to the actual backlog
  during grooming; listed in `blocks` as placeholders).

**Sequencing within the ticket:** (1) inspect `/v1/kyc/*` in `/openapi.json` and
`frontend/src/api/endpoints/kyc.ts`, resolving Q-1..Q-3; (2) define DTOs + enum
adapters in `core-model`/`core-network`; (3) declare `KycApi`; (4) add
`KycNetworkModule`; (5) write round-trip + MockWebServer tests T-1..T-11.

## 13. Risks & Open Questions

- **R-1 List envelopes.** `tiers`/`cases` may return bare arrays or
  `{tiers:[...]}` / `{cases:[...]}` wrappers. Mitigation: confirm against
  `/openapi.json` + web reference before coding; pick the matching DTO. Guarded by
  T-1/T-5. (Q-1)
- **R-2 Tier id space.** `KycTierId` assumes `tier0..tier3`; the backend may use
  numeric ids or named tiers. The `UNKNOWN` fallback prevents crashes, but the UI
  could mis-render an unmodeled tier. Mitigation: enumerate actual tier ids from
  `tiers` schema; treat ids as opaque strings in addition to the enum if needed.
  (Q-2)
- **R-3 `evaluate` body shape.** Field-vs-document submission structure
  (`fields[]` with `value`/`document_id`) is inferred. Mitigation: confirm the
  request schema; document upload itself (multipart) may be a separate endpoint
  owned by another M7 ticket — this ticket only references uploaded
  `document_id`s. (Q-3)
- **R-4 PII redaction gap.** If AND-009's redaction list does not yet include
  `v1/kyc/evaluate`, KYC PII could leak to logcat in debug. Mitigation: add the
  path to AND-009's redaction set and assert via the `toString()` redaction tests
  (T-10); flag for AND-009.
- **R-5 Status enum drift.** Backend KYC states may differ from the assumed set;
  `UNKNOWN` keeps deserialization total but downstream UI must surface an
  unrecognized required status as a non-silent state (noted for AND-321).
- **Q-1** Are list endpoints wrapped or bare arrays? *Proposed:* match
  `/openapi.json`; default to wrapper DTOs.
- **Q-2** What is the canonical tier-id token set? *Proposed:* derive from the
  live `tiers` response; extend `KycTierId` accordingly.
- **Q-3** Does `evaluate` accept inline field values and document refs in one
  body, and where are documents uploaded? *Proposed:* confirm via OpenAPI; this
  ticket consumes `document_id` refs only.

## 14. Acceptance Criteria

- **AC-1 (backlog).** All KYC DTOs in Section 4 exist in
  `com.testlogon.android.core.model.kyc` as immutable
  `@JsonClass(generateAdapter = true)` data classes, and `KycStatusAdapter` +
  `KycTierIdAdapter` are registered on the shared `Moshi`.
- **AC-2 (backlog).** Every documented KYC payload (Sections 4–5) **maps
  (de)serializes the documented JSON exactly** — proven by `KycDtoRoundTripTest`
  with committed fixtures (parsed-tree equality, snake_case keys, lowercase enum
  tokens). [T-9]
- **AC-3.** `KycApi` declares all six operations (`tiers`, `me`, `requirements`,
  `evaluate`, `cases`, `case`); each endpoint's **verb + resolved path + request
  body/query** match Section 5, asserted with MockWebServer. [T-1..T-5]
- **AC-4.** `requirements` sends `?target_tier=tier1` as a query param; `evaluate`
  serializes the nested `fields[].document_id`/`value` body exactly. [T-3, T-4]
- **AC-5.** Unknown KYC status/tier tokens decode to `UNKNOWN` without throwing;
  missing required fields throw `JsonDataException`; unknown keys are tolerated.
  [T-6, T-7]
- **AC-6.** Non-2xx (e.g. `422` from `evaluate`, `404` from `case`) surfaces as
  `HttpException` with the correct `code()` and is not swallowed. [T-8]
- **AC-7.** `KycApi` is Hilt-provided as a `@Singleton` on the shared Retrofit;
  repeated injection yields the same instance; no new `OkHttpClient`/`Retrofit`
  is constructed and no per-method CSRF/cookie headers are declared. [T-11]
- **AC-8.** `KycEvaluateReq`/`KycFieldSubmission` `toString()` redact field
  values; `v1/kyc/evaluate` bodies are redacted in logs (verified). [T-10]
- **AC-9.** All tests pass in CI; modules build clean under AGP 8.7.3 / Gradle 8.9
  / JDK 17 with KSP-generated adapters present and no detekt/lint regressions.

## 15. Definition of Done

- DTOs (`core-model/.../kyc`), `KycStatusAdapter`/`KycTierIdAdapter`, `KycApi`,
  and `KycNetworkModule` (`core-network/.../kyc`) are implemented, package base
  `com.testlogon.android`; DTOs are referenced only (no redefinition of shared
  types).
- Open questions Q-1/Q-2/Q-3 (list envelopes, tier-id token set, `evaluate` body)
  are resolved against `/openapi.json` and `frontend/src/api/endpoints/kyc.ts`,
  and the interface's return types/verbs/queries reflect the confirmed contract.
- `KycDtoRoundTripTest` and `KycApiContractTest` (T-1..T-11) are implemented and
  green in CI; ≥90% line coverage on the new surface; committed fixtures under
  `core-model/src/test/resources/kyc/`; every endpoint has a verb/path assertion.
- No second `OkHttpClient`/`Retrofit`; no manual cookie/CSRF/auth headers in the
  interface; `v1/kyc/evaluate` body and KYC field values are redacted in logs and
  `toString()` (verified).
- `./gradlew :core-model:testDebugUnitTest :core-network:assemble
  :core-network:testDebugUnitTest` passes locally and in CI with no new
  lint/detekt violations (AND-005 config).
- Code reviewed and merged to `android-port`; the KYC repository / feature
  (AND-320+) is unblocked.
- A one-line note in the `core-network` README (owned by AND-007) records the
  `KycApi` path/verb map and the delegation of cookie/CSRF/refresh to
  AND-011/AND-012/AND-013.
