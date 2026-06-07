---
id: AND-319
title: KYC API + DTOs
milestone: M7
epic: E42
priority: P0
size: M
depends_on: [AND-027]
blocks: [AND-320, AND-321, AND-322]
status: reviewed
reviewed_on: 2026-06-06
---

# AND-319 — KYC API + DTOs

> **REVIEW NOTE (2026-06-06).** This spec was drafted against an *assumed* KYC
> contract (`/v1/kyc/{tiers,me,requirements,evaluate,cases}` with a tier/status
> model). Verification against the backend OpenAPI and the web reference client
> shows the real surface is materially different. The backlog scope words
> ("tiers/me, requirements, evaluate, cases") map onto **two** real routers:
> (1) the **tier** endpoints under `/v1/kyc/tiers/me*`, and (2) the **KYC
> self-service case** endpoints under `/v1/kyc/cases*` (router
> `app/routers/kyc_cases.py`, web wrappers in
> `src/api/endpoints/kyc.ts`). The most load-bearing claims have been corrected
> inline below; every correction is itemized in **§16 Citations & Assumption
> Audit**. Where this review changed the contract, the §16 verdict is the
> authority. Sample JSON bodies that were invented (Section 5) are marked
> corrected or flagged as illustrative.

## 1. Overview & Goal

This ticket delivers the typed Retrofit service interface `KycApi` plus the
Moshi-backed data-transfer objects (DTOs) that model the wire format of the
TestLogon Know-Your-Customer (KYC) surface under `/v1/kyc/*`. It is the typed
HTTP seam through which the KYC feature (`feature-kyc`) and the KYC repository
(`core-data`) read the user's KYC tier, current status, the document/field
requirements for advancing a tier, the result of evaluating a submission, and
the list of open compliance cases.

Scope, verbatim from the backlog: *`/v1/kyc/*` DTOs (tiers/me, requirements,
evaluate, cases).* **[CORRECTED]** Verified against OpenAPI, these scope words
resolve to: `GET /v1/kyc/tiers/me` (caller's tier), `POST
/v1/kyc/tiers/me/evaluate` (re-evaluate tier; **no request body**), `GET
/v1/kyc/tiers/me/requirements/{target_tier}` (**path param**, not a query), and
the self-service **case** lifecycle under `/v1/kyc/cases*` (`GET`/`POST
/v1/kyc/cases`, `GET`/`PATCH /v1/kyc/cases/{case_id}`, plus `…/files`,
`…/readiness`, `…/submit`, `…/start-questionnaire`, `…/questionnaire-status`,
`…/signature-packet`, `…/signature-status`, and `/v1/kyc/cases/estimated-wait`).
There is **no** public `GET /v1/kyc/tiers` catalog (only admin `…/tiers/admin/*`),
**no** `GET /v1/kyc/me`, **no** `GET /v1/kyc/requirements?target_tier=`, and **no**
`POST /v1/kyc/evaluate`. The single acceptance criterion is that **KYC payloads map
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
  the shared, authenticated Retrofit/OkHttp seam (cookie jar AND-011, CSRF
  AND-012, 401-refresh AND-013) on which all authenticated `/v1/*` calls — KYC
  included — depend. KYC endpoints require an authenticated session; without the
  session pipeline they 401. This ticket reuses that pipeline unchanged.
  **[CORRECTED] Auth is not cookie-only:** the web reference client
  (`src/api/client.ts`) sends **`Authorization: Bearer <accessToken>`** (from the
  auth store) **and** an `X-CSRF-Token` header (from the `ui_csrf` cookie) **and**
  `credentials: include` (cookies) on every call; admin/impersonation calls add
  `X-IMPERSONATION-TOKEN`. Whether the Android session seam (AND-027) carries the
  Bearer header, the cookie jar, or both must be confirmed there — `KycApi` stays
  agnostic either way, but the §8 claim "auth is cookie-based" is **overstated**.
- **Transitive upstream:** AND-010 (shared Retrofit + Moshi + KSP codegen),
  AND-009 (shared `OkHttpClient`, ~20s timeouts, redacting logger), AND-006
  (`BuildConfig.API_BASE_URL`; `dev` → `http://18.222.237.167:8000/`).
- **Backend:** FastAPI + DynamoDB; dev host is plaintext HTTP and unreliable
  (~20s timeouts; bounded backoff for idempotent GETs owned by AND-016). OpenAPI
  at `/openapi.json` (inspect the `/v1/kyc/*` schemas before coding). Web
  reference for exact field names: `src/api/endpoints/kyc.ts` and shared
  types in `src/api/types.ts` — mirror snake_case names; do not invent
  camelCase wire keys. **[VERIFIED]** Both files exist and define the
  self-service case wrappers (`createKycCase`, `listKycCases`, `getKycCase`,
  `patchKycDraft`, `attachKycFile`, `getKycReadiness`, `submitKycCase`,
  `startKycQuestionnaire`, `getKycQuestionnaireStatus`, `linkKycSignaturePacket`,
  `getKycSignatureStatus`, `getKycEstimatedWait`) and DTO shapes
  (`KycSelfServiceCase`, `KycCaseStatus`, `KycSelfServiceFileType`, envelopes).
- **Error envelope:** FastAPI `detail` union (`string | [{msg,type,loc}] |
  {code,...}`); typed mapping to `ApiError` is owned by **AND-015**. This ticket
  lets non-2xx surface as `retrofit2.HttpException`. **[VERIFIED]** The OpenAPI
  documents exactly two responses for every user-facing `/v1/kyc/*` endpoint:
  the success code and `422: HTTPValidationError`, where
  `HTTPValidationError = { detail: ValidationError[] }` and
  `ValidationError = { loc, msg, type }`. `401` is produced by the auth
  middleware (not declared per-endpoint); `403` (`{detail:{code,...}}`) is the
  authorization shape the web client maps in `src/api/client.ts`. No `404` is
  documented for an unknown case id (see §7 correction).

## 3. Functional Requirements

FR-1. **[CORRECTED]** Declare a single Retrofit interface `KycApi` covering the
verified operations. Tier surface: `tierMe` → `GET v1/kyc/tiers/me`;
`evaluateTier` → `POST v1/kyc/tiers/me/evaluate` (**no body**); `tierRequirements`
→ `GET v1/kyc/tiers/me/requirements/{target_tier}` (**path param**). Case
surface: `createCase` → `POST v1/kyc/cases`; `listCases` → `GET v1/kyc/cases`;
`getCase` → `GET v1/kyc/cases/{case_id}`; `patchDraft` → `PATCH
v1/kyc/cases/{case_id}`; `attachFile` → `POST v1/kyc/cases/{case_id}/files`;
`readiness` → `GET v1/kyc/cases/{case_id}/readiness`; `submitCase` → `POST
v1/kyc/cases/{case_id}/submit`; `estimatedWait` → `GET
v1/kyc/cases/estimated-wait`; (questionnaire/signature endpoints optional per
grooming). The previously listed `tiers` catalog, `me`, query-style
`requirements`, and `evaluate`-with-body operations **do not exist** on the
backend and are removed.

FR-2. Each method's HTTP verb and relative path match the backend contract
(Section 5). Paths are declared **without** a leading slash (AND-010 convention)
so they append to the normalized base URL.

FR-3. All methods are `suspend` functions returning the typed DTO body. GETs
(`tierMe`, `tierRequirements`, `listCases`, `getCase`, `readiness`,
`estimatedWait`) are idempotent and eligible for AND-016 bounded backoff; the
POSTs (`createCase`, `evaluateTier`, `attachFile`, `submitCase`) and the `PATCH`
(`patchDraft`) are non-idempotent and **not** retried by AND-016. **[NOTE]** The
case mutations use optimistic concurrency (`expected_version`), so a blind retry
of a mutation would fail with a version conflict — another reason they are
retry-excluded.

FR-4. **[CORRECTED]** Request bodies use `@Body` with request DTOs; path
parameters use `@Path`. The target-tier selector on `tierRequirements` is a
**`@Path`** segment (`/requirements/{target_tier}`), **not** a `@Query`. No raw
`Map`/`JsonObject` bodies. (No `/v1/kyc/*` user endpoint takes a query parameter
in this ticket's scope.)

FR-5. POST methods carry `@Headers("Content-Type: application/json")`. The CSRF
header (`X-CSRF-Token`) is injected globally by AND-012 for mutating verbs and is
**not** declared per-method here. `KycApi` stays cookie/CSRF-agnostic.

FR-6. **[CORRECTED]** Define request DTOs that match the OpenAPI schemas:
`KycCaseCreateRequest` (`{ intake_profile?: String }`), `KycCaseDraftPatchRequest`
(`{ expected_version: Int, intake_profile?: String }`), `KycFileAttachmentRequest`
(`{ expected_version: Int, path: String, file_type: KycFileType }`),
`KycSubmitCaseRequest` (`{ expected_version: Int }`), and (if questionnaire/
signature are in scope) `KycStartQuestionnaireRequest` (`{ published_slug }`) and
`KycLinkSignaturePacketRequest` (`{ expected_version, source_path,
origin_channel?, origin_ref? }`). Define response DTOs: `KycCaseOut` (the case),
`KycCaseEnvelope` (`{ case }`), `KycCaseListEnvelope` (`{ items, next_cursor }`),
`KycReadinessEnvelope`/`KycReadinessResult`, `KycEstimatedWaitEnvelope`/Result,
and (if in scope) questionnaire/signature status envelopes. The invented
`KycEvaluateReq`/`KycFieldSubmission`/`KycTier`/`KycTiersResp`/`KycMeResp`/
`KycRequirement(s)Resp`/`KycEvaluateResp`/`KycCasesResp` are dropped. Model the
KYC **case status** as an enum with an `UNKNOWN` fallback (FR-9). The tier
response bodies (`/v1/kyc/tiers/me*`) have **no documented schema** in OpenAPI —
keep them loosely typed (see §13 R-2) until the backend publishes a model.

FR-7. Every DTO field maps to the backend snake_case name via `@Json(name=…)`
when the Kotlin property is camelCase. Unknown/extra JSON keys are tolerated
(Moshi codegen default). Optional fields are Kotlin-nullable with `null`
defaults; required fields are non-null and their absence must throw
`JsonDataException` (fail fast).

FR-8. **[CORRECTED]** All DTOs are immutable `data class`es exposing read-only
`List<T>` (no mutable collections). Case timestamps (`created_at`, `updated_at`)
are **epoch-second integers** (`Long`) on the wire — **not** ISO-8601 strings;
keep them `Long` at this layer and defer any `Instant` conversion downstream.
(Other timestamp-like refs such as `decided_at` are also numeric/nullable.)

FR-9. **[CORRECTED]** KYC **case status** (`draft | submitted | under_review |
needs_more_info | approved | rejected | expired`) and the **file type**
(`id_front | id_back | selfie | proof_of_address`) (de)serialize via custom Moshi
adapters that fall back to an `UNKNOWN` enum member for unrecognized tokens. The
previously-assumed status set (`unverified|pending|verified|rejected|review`) and
`KycTierId` token set (`tier0..tier3`) are **not** the backend's case-status
vocabulary; `KycTierId` (if retained) applies only to the loosely-typed tier
endpoints and its real token set is unverified (§13 R-2).

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

**[CORRECTED]** The case-status vocabulary and file-type vocabulary below are
verified against `KycCaseOut.status` / `KycFileAttachmentRequest.file_type` in the
OpenAPI and against `KycCaseStatus` / `KycSelfServiceFileType` in
`src/api/types.ts`.

```kotlin
package com.testlogon.android.core.model.kyc

enum class KycCaseStatus(val token: String) {
    DRAFT("draft"),
    SUBMITTED("submitted"),
    UNDER_REVIEW("under_review"),
    NEEDS_MORE_INFO("needs_more_info"),
    APPROVED("approved"),
    REJECTED("rejected"),
    EXPIRED("expired"),
    UNKNOWN("unknown");
    companion object { fun fromToken(t: String) =
        entries.firstOrNull { it.token == t } ?: UNKNOWN }
}

enum class KycFileType(val token: String) {
    ID_FRONT("id_front"), ID_BACK("id_back"),
    SELFIE("selfie"), PROOF_OF_ADDRESS("proof_of_address"),
    UNKNOWN("unknown");
    companion object { fun fromToken(t: String) =
        entries.firstOrNull { it.token == t } ?: UNKNOWN }
}
```

```kotlin
package com.testlogon.android.core.network.kyc

import com.squareup.moshi.FromJson
import com.squareup.moshi.ToJson
import com.testlogon.android.core.model.kyc.KycCaseStatus
import com.testlogon.android.core.model.kyc.KycFileType

object KycCaseStatusAdapter {
    @FromJson fun fromJson(v: String) = KycCaseStatus.fromToken(v)
    @ToJson fun toJson(s: KycCaseStatus) = s.token
}
object KycFileTypeAdapter {
    @FromJson fun fromJson(v: String) = KycFileType.fromToken(v)
    @ToJson fun toJson(t: KycFileType) = t.token
}
```

### 4.2 Response + request DTOs

**[CORRECTED — entirely rewritten]** Shapes below match OpenAPI
`KycCaseOut`, `KycCaseEnvelope`, `KycCaseListEnvelope`, `KycCaseCreateRequest`,
`KycCaseDraftPatchRequest`, `KycFileAttachmentRequest`, `KycSubmitCaseRequest`,
and the `src/api/types.ts` interfaces of the same shape.

```kotlin
package com.testlogon.android.core.model.kyc

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

// ---- Nested case refs (all fields optional/nullable per OpenAPI) ----
@JsonClass(generateAdapter = true)
data class KycCaseQuestionnaireRef(
    @Json(name = "questionnaire_id") val questionnaireId: String? = null,
    @Json(name = "version_id") val versionId: String? = null,
    @Json(name = "response_session_id") val responseSessionId: String? = null,
    @Json(name = "response_pdf_ref") val responsePdfRef: String? = null,
)

@JsonClass(generateAdapter = true)
data class KycCaseSignatureRef(
    @Json(name = "packet_id") val packetId: String? = null,
    val status: String? = null,
    @Json(name = "final_pdf_ref") val finalPdfRef: String? = null,
    @Json(name = "legal_notice_version") val legalNoticeVersion: String? = null,
    @Json(name = "legal_notice_accepted") val legalNoticeAccepted: Boolean? = null,
)

@JsonClass(generateAdapter = true)
data class KycCaseReviewRef(
    @Json(name = "ticket_id") val ticketId: String? = null,
    @Json(name = "assigned_admin_sub") val assignedAdminSub: String? = null,
    val decision: String? = null,
    @Json(name = "decided_at") val decidedAt: Long? = null,          // epoch seconds
    @Json(name = "reason_codes") val reasonCodes: List<String> = emptyList(),
)

// files[] is an array of open objects in OpenAPI; model leniently.
@JsonClass(generateAdapter = true)
data class KycCaseFile(
    val type: String? = null,                                        // KycFileType token
    val path: String? = null,
    @Json(name = "uploaded_at") val uploadedAt: Long? = null,
    val size: Long? = null,
    @Json(name = "verification_state") val verificationState: String? = null,
)

// ---- The case (OpenAPI KycCaseOut / web KycSelfServiceCase) ----
@JsonClass(generateAdapter = true)
data class KycCaseOut(
    @Json(name = "contract_version") val contractVersion: String = "2026-03-kyc-v1",
    @Json(name = "kyc_case_id") val kycCaseId: String,
    @Json(name = "user_sub") val userSub: String,
    val status: KycCaseStatus,
    @Json(name = "intake_profile") val intakeProfile: String? = null,
    val questionnaire: KycCaseQuestionnaireRef? = null,
    val files: List<KycCaseFile> = emptyList(),
    val signature: KycCaseSignatureRef? = null,
    val submission: Map<String, Any?> = emptyMap(),
    val review: KycCaseReviewRef? = null,
    @Json(name = "verification_call") val verificationCall: Map<String, Any?>? = null,
    @Json(name = "created_at") val createdAt: Long,                  // epoch seconds (required)
    @Json(name = "updated_at") val updatedAt: Long,                 // epoch seconds (required)
    val version: Int,                                               // required (optimistic lock)
    @Json(name = "missing_requirements") val missingRequirements: List<String> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class KycCaseEnvelope(val case: KycCaseOut)

@JsonClass(generateAdapter = true)
data class KycCaseListEnvelope(
    val items: List<KycCaseOut> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

// ---- Readiness / estimated-wait response envelopes ----
@JsonClass(generateAdapter = true)
data class KycReadinessResult(
    @Json(name = "contract_version") val contractVersion: String = "2026-03-kyc-v1",
    @Json(name = "kyc_case_id") val kycCaseId: String,
    val status: KycCaseStatus,
    @Json(name = "ready_to_submit") val readyToSubmit: Boolean,
    @Json(name = "missing_requirements") val missingRequirements: List<String> = emptyList(),
    @Json(name = "missing_hints") val missingHints: List<String> = emptyList(),
    val checks: Map<String, Boolean> = emptyMap(),
    val requirements: List<Map<String, Any?>> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class KycReadinessEnvelope(val readiness: KycReadinessResult)

@JsonClass(generateAdapter = true)
data class KycEstimatedWaitResult(
    @Json(name = "contract_version") val contractVersion: String = "2026-03-kyc-v1",
    @Json(name = "estimated_hours") val estimatedHours: Double,
    @Json(name = "queue_position") val queuePosition: Int? = null,
    val message: String,
)

@JsonClass(generateAdapter = true)
data class KycEstimatedWaitEnvelope(
    @Json(name = "estimated_wait") val estimatedWait: KycEstimatedWaitResult,
)

// ---- Request DTOs (verified against OpenAPI request schemas) ----
@JsonClass(generateAdapter = true)
data class KycCaseCreateRequest(
    @Json(name = "intake_profile") val intakeProfile: String? = null,
)

@JsonClass(generateAdapter = true)
data class KycCaseDraftPatchRequest(
    @Json(name = "expected_version") val expectedVersion: Int,      // required, >=1
    @Json(name = "intake_profile") val intakeProfile: String? = null,
)

@JsonClass(generateAdapter = true)
data class KycFileAttachmentRequest(
    @Json(name = "expected_version") val expectedVersion: Int,      // required, >=1
    val path: String,                                              // required, 1..1024
    @Json(name = "file_type") val fileType: KycFileType,           // required
)

@JsonClass(generateAdapter = true)
data class KycSubmitCaseRequest(
    @Json(name = "expected_version") val expectedVersion: Int,      // required, >=1
)
```

Notes: list endpoints are **object-wrapped**, not bare arrays — `GET
/v1/kyc/cases` → `{ items, next_cursor }` and `GET /v1/kyc/cases/{id}` → `{ case }`
(Q-1 resolved). `created_at`/`updated_at`/`version` are **required**; their
absence must throw `JsonDataException`. Optional questionnaire/signature
status-envelope DTOs (`KycQuestionnaireStatusEnvelope`,
`KycSignatureStatusEnvelope`) mirror `src/api/types.ts` if those endpoints are in
scope for this ticket.

### 4.3 The `KycApi` interface

**[CORRECTED]** Verbs/paths/params verified against the OpenAPI index. Note
`tierRequirements` uses a `@Path` segment; `evaluateTier` has **no body**; the
list/get endpoints return **envelopes**.

```kotlin
package com.testlogon.android.core.network.kyc

import com.testlogon.android.core.model.kyc.KycCaseCreateRequest
import com.testlogon.android.core.model.kyc.KycCaseDraftPatchRequest
import com.testlogon.android.core.model.kyc.KycCaseEnvelope
import com.testlogon.android.core.model.kyc.KycCaseListEnvelope
import com.testlogon.android.core.model.kyc.KycEstimatedWaitEnvelope
import com.testlogon.android.core.model.kyc.KycFileAttachmentRequest
import com.testlogon.android.core.model.kyc.KycReadinessEnvelope
import com.testlogon.android.core.model.kyc.KycSubmitCaseRequest
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.PATCH
import retrofit2.http.POST
import retrofit2.http.Path

interface KycApi {

    // ---- Tier surface (response bodies undocumented; see §13 R-2) ----

    /** Caller's current tier. Idempotent GET. Response untyped pending schema. */
    @GET("v1/kyc/tiers/me")
    suspend fun tierMe(): okhttp3.ResponseBody

    /** Re-evaluate caller's tier. NO request body. Non-idempotent POST. */
    @POST("v1/kyc/tiers/me/evaluate")
    suspend fun evaluateTier(): okhttp3.ResponseBody

    /** Requirements to reach [targetTier] — target tier is a PATH segment. GET. */
    @GET("v1/kyc/tiers/me/requirements/{target_tier}")
    suspend fun tierRequirements(@Path("target_tier") targetTier: String): okhttp3.ResponseBody

    // ---- Self-service case surface ----

    /** Create a KYC case (draft). 200 (not 201). Non-idempotent. */
    @Headers("Content-Type: application/json")
    @POST("v1/kyc/cases")
    suspend fun createCase(@Body body: KycCaseCreateRequest): KycCaseEnvelope

    /** List the caller's KYC cases. Idempotent GET. */
    @GET("v1/kyc/cases")
    suspend fun listCases(): KycCaseListEnvelope

    /** Estimated review wait. Idempotent GET. (Static segment, not a case id.) */
    @GET("v1/kyc/cases/estimated-wait")
    suspend fun estimatedWait(): KycEstimatedWaitEnvelope

    /** A single case by id. Idempotent GET. */
    @GET("v1/kyc/cases/{case_id}")
    suspend fun getCase(@Path("case_id") caseId: String): KycCaseEnvelope

    /** Patch a draft case (optimistic concurrency). Non-idempotent. */
    @Headers("Content-Type: application/json")
    @PATCH("v1/kyc/cases/{case_id}")
    suspend fun patchDraft(
        @Path("case_id") caseId: String,
        @Body body: KycCaseDraftPatchRequest,
    ): KycCaseEnvelope

    /** Attach an already-uploaded file to a case. Non-idempotent. */
    @Headers("Content-Type: application/json")
    @POST("v1/kyc/cases/{case_id}/files")
    suspend fun attachFile(
        @Path("case_id") caseId: String,
        @Body body: KycFileAttachmentRequest,
    ): KycCaseEnvelope

    /** Submit-readiness for a case. Idempotent GET. */
    @GET("v1/kyc/cases/{case_id}/readiness")
    suspend fun readiness(@Path("case_id") caseId: String): KycReadinessEnvelope

    /** Submit a case for review (optimistic concurrency). Non-idempotent. */
    @Headers("Content-Type: application/json")
    @POST("v1/kyc/cases/{case_id}/submit")
    suspend fun submitCase(
        @Path("case_id") caseId: String,
        @Body body: KycSubmitCaseRequest,
    ): KycCaseEnvelope
}
```

> The tier endpoints return `okhttp3.ResponseBody` only because OpenAPI publishes
> **no** response schema for them (`resp=200:` with no model). If grooming
> requires typed tier DTOs, the backend must publish the schema first; until then
> typing them would be an invented contract. The case endpoints carry the
> "payloads map (tested)" acceptance weight.

### 4.4 Hilt wiring

```kotlin
package com.testlogon.android.core.network.kyc.di

import com.testlogon.android.core.network.kyc.KycApi
import com.testlogon.android.core.network.kyc.KycCaseStatusAdapter
import com.testlogon.android.core.network.kyc.KycFileTypeAdapter
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
    fun kycCaseStatusAdapter(): Any = KycCaseStatusAdapter

    @Provides @IntoSet @com.testlogon.android.core.network.di.AppMoshiAdapter
    fun kycFileTypeAdapter(): Any = KycFileTypeAdapter
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

**[CORRECTED — section rewritten to the verified contract.]** Base path (`dev`):
`http://18.222.237.167:8000/`. All bodies JSON. All endpoints require an
authenticated session (Bearer + cookies + `X-CSRF-Token` on mutating verbs; see
§2 correction). Every endpoint below documents exactly two responses: the
success code and `422: HTTPValidationError` (`{ "detail": [{ "loc", "msg",
"type" }] }`). All case timestamps are **epoch-second integers**.

### GET `v1/kyc/tiers/me`
Caller's current tier. Response `200` — **no schema published in OpenAPI**; treat
the body as opaque JSON until the backend publishes one (see §13 R-2). Do not
invent a tier/status shape.

### POST `v1/kyc/tiers/me/evaluate`
Re-evaluate the caller's tier. **No request body.** Response `200` — schema
unpublished (opaque), as above.

### GET `v1/kyc/tiers/me/requirements/{target_tier}`
`target_tier` is a **path segment** (e.g. `v1/kyc/tiers/me/requirements/tier1`),
not a query parameter. Response `200` — schema unpublished (opaque).

### POST `v1/kyc/cases`
Create a draft case. Request (`KycCaseCreateRequest`):
```json
{ "intake_profile": "standard" }
```
(`intake_profile` is optional/nullable; an empty `{}` is valid.) Response **`200`**
(`KycCaseEnvelope`):
```json
{ "case": {
  "contract_version": "2026-03-kyc-v1",
  "kyc_case_id": "kyc_01HXYZ", "user_sub": "auth0|abc", "status": "draft",
  "intake_profile": "standard",
  "questionnaire": { "questionnaire_id": null, "version_id": null,
    "response_session_id": null, "response_pdf_ref": null },
  "files": [],
  "signature": { "packet_id": null, "status": null, "final_pdf_ref": null,
    "legal_notice_version": null, "legal_notice_accepted": null },
  "submission": {},
  "review": { "ticket_id": null, "assigned_admin_sub": null, "decision": null,
    "decided_at": null, "reason_codes": [] },
  "verification_call": null,
  "created_at": 1749124800, "updated_at": 1749124800, "version": 1,
  "missing_requirements": ["id_front", "id_back", "selfie"]
} }
```

### GET `v1/kyc/cases`
List the caller's cases. Response `200` (`KycCaseListEnvelope`):
```json
{ "items": [ { "kyc_case_id": "kyc_01HXYZ", "user_sub": "auth0|abc",
  "status": "draft", "created_at": 1749124800, "updated_at": 1749124800,
  "version": 1 } ], "next_cursor": null }
```
(`items[]` are full `KycCaseOut` objects; trimmed here for brevity.
`next_cursor` is nullable.)

### GET `v1/kyc/cases/estimated-wait`
Static segment (resolved before `{case_id}`). Response `200`
(`KycEstimatedWaitEnvelope`):
```json
{ "estimated_wait": { "contract_version": "2026-03-kyc-v1",
  "estimated_hours": 12.5, "queue_position": 7, "message": "About half a day" } }
```

### GET `v1/kyc/cases/{case_id}`
Response `200`: a `KycCaseEnvelope` (`{ "case": { … } }`, shape above). **There is
no documented `404`** — an unknown/unowned id surfaces as `422` or an empty/error
per the auth+validation layer; do not assume `404` (see §7 correction).

### PATCH `v1/kyc/cases/{case_id}`
Request (`KycCaseDraftPatchRequest`): `{ "expected_version": 1,
"intake_profile": "premium" }` (`expected_version` required, ≥1). Response `200`:
`KycCaseEnvelope` with bumped `version`. A stale `expected_version` is a
validation/conflict error (`422`).

### POST `v1/kyc/cases/{case_id}/files`
Request (`KycFileAttachmentRequest`): `{ "expected_version": 1, "path":
"/kyc/kyc_01HXYZ/id_front_1749124800.jpg", "file_type": "id_front" }` (all three
required; `file_type` ∈ `selfie|id_front|id_back|proof_of_address`). Response
`200`: `KycCaseEnvelope`. (The file bytes are uploaded separately via the file
manager — `src/api/endpoints/kyc.ts: uploadAndAttachKycFile` uploads then
attaches the resulting `path`. Multipart upload is out of scope for this ticket.)

### GET `v1/kyc/cases/{case_id}/readiness`
Response `200` (`KycReadinessEnvelope`):
```json
{ "readiness": { "contract_version": "2026-03-kyc-v1",
  "kyc_case_id": "kyc_01HXYZ", "status": "draft", "ready_to_submit": false,
  "missing_requirements": ["selfie"], "missing_hints": ["Take a selfie"],
  "checks": { "id_front": true, "selfie": false }, "requirements": [] } }
```

### POST `v1/kyc/cases/{case_id}/submit`
Request (`KycSubmitCaseRequest`): `{ "expected_version": 2 }` (required). Response
`200`: `KycCaseEnvelope` with `status` advanced to `submitted` (or `422` if not
ready / version mismatch).

**Error envelope (all endpoints):** `422: HTTPValidationError`
(`{ detail: ValidationError[] }`); `401` from auth middleware; `403`
(`{detail:{code,...}}`) for authorization. Typed mapping is owned by AND-015;
this ticket lets non-2xx surface as `retrofit2.HttpException`.

## 6. Data & State Management

`KycApi` is **stateless** — a singleton interface proxy with no fields. DTOs are
transient wire types.

- **No Room / DataStore here.** Caching the tier response, cases, or readiness is
  a `core-data`/repository concern (downstream M7). DTOs must **not** be persisted
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
  Kotlin defaults. **[CORRECTED]** Timestamps (`created_at`/`updated_at`/
  `decided_at`/`uploaded_at`) are epoch-second **`Long`**s, not ISO strings; any
  `Instant` parsing is deferred downstream. `KycCaseStatus.UNKNOWN` /
  `KycFileType.UNKNOWN` are the only behavioral fallbacks and exist solely to keep
  deserialization total.

## 7. Error Handling & Resilience

Responsibilities are narrow: declare endpoints/DTOs so failures propagate cleanly.

- **Non-2xx** surfaces as `retrofit2.HttpException` carrying the raw error body
  for AND-015 to decode the FastAPI `detail` union. `401` on any call is
  intercepted by the AND-013 `Authenticator` (refresh once, retry once); only a
  second `401` propagates and the repository routes to login (AND-025).
- **[CORRECTED] `422` from any mutating endpoint** (`createCase`, `patchDraft`,
  `attachFile`, `submitCase`, and the unpublished `evaluateTier`) surfaces as
  `HttpException(422)` carrying `HTTPValidationError`; the repository/ViewModel
  maps `detail[].msg`/`loc` to field errors via AND-015. `422` is the **only**
  documented validation failure for these endpoints — it also covers stale
  `expected_version` (optimistic-concurrency conflict) and "case not ready to
  submit". This ticket does not map it.
- **Transport failures** (`SocketTimeoutException`, `UnknownHostException`,
  `IOException`) propagate unchanged; ~20s timeouts and bounded backoff for the
  idempotent GETs (`tierMe`, `tierRequirements`, `listCases`, `getCase`,
  `readiness`, `estimatedWait`) are owned by AND-009/AND-016. The POST/PATCH
  mutations are non-idempotent and excluded from retry.
- **Deserialization failures** surface as `JsonDataException`; missing required
  fields fail fast (asserted in tests). Unknown enum tokens map to `UNKNOWN`
  rather than throwing, so additive backend status/tier values are safe.
- **[CORRECTED] Unknown case id:** OpenAPI does **not** document a `404` for
  `getCase(caseId)` — only `200`/`422`. An unknown or unowned id is expected to
  surface as `422` (or an auth `403`); the spec's prior "`404` → case not found"
  claim is unverified and removed. Whatever non-2xx the backend returns, it
  surfaces as `HttpException` for the repository to interpret. This layer does not
  special-case it.
- This ticket maps **no** errors itself (AND-015/AND-018 own that) and adds no
  offline/stale UI (downstream feature ticket + AND-045-style baseline).

## 8. Security & Privacy

- **[CORRECTED] PII in payloads.** The PII-bearing surface is **not**
  `KycEvaluateReq` (which does not exist). In this ticket's scope the
  privacy-sensitive bodies/responses are: `KycCaseOut` (carries `user_sub`,
  `files[].path`, nested submission/review refs), `KycFileAttachmentRequest.path`
  (file-manager paths to ID/selfie/proof-of-address documents), and the case
  `submission`/`questionnaire` blobs. **Plaintext document PII (legal name, DOB,
  decrypted ID fields) lives on the out-of-scope `/v1/kyc/cases/{id}/pii*`
  endpoints (write/decrypt/masked), which this ticket does not declare** — flag
  them for the repository ticket. The AND-009 redacting `HttpLoggingInterceptor`
  must redact `v1/kyc/cases` request *and* response bodies (add the path prefix to
  its redaction list). A code-review check confirms KYC bodies never reach logcat
  in any build.
- **Redacting `toString()`.** `KycCaseOut`, `KycCaseFile`, and
  `KycFileAttachmentRequest` override `toString()` to mask `user_sub` and file
  `path`s:
  ```kotlin
  override fun toString() = "KycFileAttachmentRequest(expectedVersion=$expectedVersion, path=***, fileType=$fileType)"
  ```
- **Transport.** On `dev` these calls ride plaintext HTTP — a known dev-only risk
  permitted by the scoped cleartext config (AND-006); `staging`/`prod` are
  HTTPS-only. No KYC PII should be exercised against the plaintext dev host beyond
  synthetic test data.
- **[CORRECTED] No credential/token storage.** `KycApi` declares no manual
  `Cookie`/`Authorization`/`X-CSRF-Token` headers — they are attached globally by
  the AND-027 session pipeline. Note the web client authenticates with a **Bearer
  token + CSRF cookie + session cookies** (not cookie-only; see §2). Cases are
  server-scoped to the authenticated principal (server-enforced via `user_sub`);
  no user id is sent in KYC paths by the client.
- **Fixtures** use synthetic identities/documents only; no real PII in committed
  JSON samples.

## 9. Accessibility & i18n

Not applicable — this is a headless transport + serialization layer with no UI
surface and no user-facing strings. **[CORRECTED]** Backend-supplied display
strings passed through verbatim are `KycEstimatedWaitResult.message`,
`KycReadinessResult.missing_hints`, and `review.reason_codes`; localization and
presentation are owned by the downstream KYC feature UI (AND-321/AND-322).
No `strings.xml` entries are added here. Accessibility is owned by `core-ui` and
the KYC screens.

## 10. Telemetry & Logging

- **HTTP logging** is inherited from AND-009's redacting interceptor (debug builds
  only); no new logging here, and **`v1/kyc/cases` request/response bodies must be
  redacted** (Section 8). [CORRECTED: was `v1/kyc/evaluate`.]
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

**[CORRECTED]** Test harness:
```kotlin
private fun api(server: MockWebServer): KycApi {
    val moshi = Moshi.Builder()
        .add(KycCaseStatusAdapter).add(KycFileTypeAdapter)   // mirrors provideMoshi()
        .build()
    val retrofit = Retrofit.Builder()
        .baseUrl(server.url("/"))
        .addConverterFactory(MoshiConverterFactory.create(moshi))
        .build()
    return retrofit.create(KycApi::class.java)
}
```

**T-1 — `createCase` contract.** Enqueue the Section-5 create body; call
`createCase(KycCaseCreateRequest("standard"))`; assert `POST /v1/kyc/cases`, the
serialized body is `{"intake_profile":"standard"}`, and the response decodes
`case.kycCaseId`, `case.status == KycCaseStatus.DRAFT`, `case.createdAt` (Long),
`case.version == 1`.

**T-2 — `listCases` contract.** Assert `GET /v1/kyc/cases`; decode
`{items, next_cursor}` with `items[0].userSub` and a null `nextCursor`.

**T-3 — `tierRequirements` path param.** Call `tierRequirements("tier1")`; assert
the request path is `/v1/kyc/tiers/me/requirements/tier1` (path segment, **no**
`?target_tier=`).

**T-4 — `attachFile` request + response.** Call `attachFile("kyc_01HXYZ",
KycFileAttachmentRequest(1, "/kyc/.../id_front.jpg", KycFileType.ID_FRONT))`;
assert `POST /v1/kyc/cases/kyc_01HXYZ/files`, body contains
`"file_type":"id_front"` and `"expected_version":1`, and the response decodes a
`KycCaseEnvelope`. Also assert `submitCase` sends `{"expected_version":N}` to
`POST /v1/kyc/cases/{id}/submit`.

**T-5 — `getCase` / `readiness`.** Assert `GET /v1/kyc/cases/kyc_01HXYZ` (path
param interpolated) decodes `{case}` and `GET
/v1/kyc/cases/kyc_01HXYZ/readiness` decodes `{readiness}` with
`readyToSubmit`/`checks`. Assert `GET /v1/kyc/cases/estimated-wait` resolves to
the static path (not treated as a `{case_id}`).

**T-6 — unknown enum tolerance.** A case body with `"status":"escalated"` decodes
to `KycCaseStatus.UNKNOWN` and does not throw; a `file_type` `"passport"` →
`KycFileType.UNKNOWN`.

**T-7 — required-field fail-fast.** A case body missing `kyc_case_id` (or
`created_at`/`version`) throws `JsonDataException`; an extra `"server_time"` key is
tolerated.

**T-8 — error propagation.** A `422` (HTTPValidationError) from `submitCase`
(stale `expected_version`) and from `getCase("nope")` each throw
`retrofit2.HttpException` with `code() == 422` (confirms non-2xx is not swallowed;
no `404` is assumed).

**T-9 — round-trip fidelity.** For each response DTO a captured sample lives at
`core-model/src/test/resources/kyc/<name>.json`; the test asserts
deserialize→serialize→parse-tree equality (ignoring key order/whitespace) and
that serialized output uses snake_case keys, lowercase enum tokens, and **integer
epoch** timestamps.

**T-10 — redaction.** `KycFileAttachmentRequest(...).toString()` and
`KycCaseOut(...).toString()` must not contain the file `path` or `user_sub`.

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
`src/api/endpoints/kyc.ts`, resolving Q-1..Q-3; (2) define DTOs + enum
adapters in `core-model`/`core-network`; (3) declare `KycApi`; (4) add
`KycNetworkModule`; (5) write round-trip + MockWebServer tests T-1..T-11.

## 13. Risks & Open Questions

- **R-1 List envelopes — RESOLVED.** Verified: `GET /v1/kyc/cases` returns
  `{items, next_cursor}` (`KycCaseListEnvelope`), and `GET /v1/kyc/cases/{id}`
  returns `{case}` (`KycCaseEnvelope`) — both object-wrapped, not bare arrays.
  `next_cursor` implies cursor pagination the repository must handle (Q-1).
- **R-2 Tier response schema is undocumented.** The three tier endpoints
  (`/v1/kyc/tiers/me`, `…/me/evaluate`, `…/me/requirements/{target_tier}`)
  publish **no** OpenAPI response model (`resp=200:` only). This ticket types them
  as `okhttp3.ResponseBody`; the real tier/status vocabulary and shape are
  **unverified**. Mitigation: get the backend to publish the schema, or defer
  typed tier DTOs to a follow-up; do not invent a `tier0..tier3`/status model.
  (Q-2)
- **R-3 Optimistic concurrency.** Every case mutation (`patchDraft`, `attachFile`,
  `submitCase`) requires a correct `expected_version`; a stale value yields a
  `422` conflict. Mitigation: the repository must thread `version` from the latest
  `KycCaseOut` into the next mutation; blind retries are unsafe (drives FR-3's
  retry-exclusion). (Q-3)
- **R-4 PII redaction gap.** If AND-009's redaction list does not include the
  `v1/kyc/cases` path prefix, KYC PII (file paths, `user_sub`, submission blobs)
  could leak to logcat in debug. Mitigation: add the prefix to AND-009's redaction
  set and assert via the `toString()` redaction tests (T-10); flag for AND-009.
- **R-5 Case-status enum drift.** Verified status set is
  `draft|submitted|under_review|needs_more_info|approved|rejected|expired`;
  `UNKNOWN` keeps deserialization total but downstream UI must surface an
  unrecognized required status as a non-silent state (noted for AND-321).
- **R-6 PII endpoints out of scope.** Plaintext document fields move through the
  encrypted `/v1/kyc/cases/{id}/pii*` endpoints (write/decrypt/masked/audit-log),
  **not** declared in this ticket. Confirm whether the Android client ever calls
  them and route to the repository ticket if so.
- **Q-1** Cursor pagination on `listCases` — does the client need to follow
  `next_cursor`? *Proposed:* repository handles paging; DTO exposes it.
- **Q-2** What are the tier endpoints' response shapes? *Proposed:* keep opaque
  until the backend publishes schemas.
- **Q-3** How is `version` sourced for the first mutation after `createCase`?
  *Proposed:* use the `version` returned by the preceding call (create returns
  `version: 1`).

## 14. Acceptance Criteria

**[CORRECTED to the verified contract.]**

- **AC-1 (backlog).** All KYC DTOs in Section 4 exist in
  `com.testlogon.android.core.model.kyc` as immutable
  `@JsonClass(generateAdapter = true)` data classes, and `KycCaseStatusAdapter` +
  `KycFileTypeAdapter` are registered on the shared `Moshi`.
- **AC-2 (backlog).** Every documented KYC case payload (Sections 4–5) **maps /
  (de)serializes the documented JSON exactly** — proven by `KycDtoRoundTripTest`
  with committed fixtures (parsed-tree equality, snake_case keys, lowercase enum
  tokens, integer epoch timestamps). [T-9]
- **AC-3.** `KycApi` declares the verified operations (`tierMe`, `evaluateTier`,
  `tierRequirements`, `createCase`, `listCases`, `getCase`, `patchDraft`,
  `attachFile`, `readiness`, `submitCase`, `estimatedWait`); each endpoint's
  **verb + resolved path + request body** match Section 5, asserted with
  MockWebServer. [T-1..T-5]
- **AC-4.** `tierRequirements` sends `target_tier` as a **path segment**
  (`/requirements/{target_tier}`), not a query; `attachFile`/`submitCase`/
  `patchDraft` serialize their `expected_version`/`file_type`/`path` bodies
  exactly; `evaluateTier` sends an empty (no) body. [T-3, T-4]
- **AC-5.** Unknown case-status/file-type tokens decode to `UNKNOWN` without
  throwing; missing required fields (`kyc_case_id`/`created_at`/`version`) throw
  `JsonDataException`; unknown keys are tolerated. [T-6, T-7]
- **AC-6.** Non-2xx (e.g. `422` HTTPValidationError from `submitCase` or
  `getCase`) surfaces as `HttpException` with the correct `code()` and is not
  swallowed; no `404` is assumed. [T-8]
- **AC-7.** `KycApi` is Hilt-provided as a `@Singleton` on the shared Retrofit;
  repeated injection yields the same instance; no new `OkHttpClient`/`Retrofit`
  is constructed and no per-method CSRF/cookie/Authorization headers are declared.
  [T-11]
- **AC-8.** `KycFileAttachmentRequest`/`KycCaseOut` `toString()` redact file
  `path`/`user_sub`; `v1/kyc/cases` bodies are redacted in logs (verified). [T-10]
- **AC-9.** All tests pass in CI; modules build clean under AGP 8.7.3 / Gradle 8.9
  / JDK 17 with KSP-generated adapters present and no detekt/lint regressions.

## 15. Definition of Done

- DTOs (`core-model/.../kyc`), `KycCaseStatusAdapter`/`KycFileTypeAdapter`,
  `KycApi`, and `KycNetworkModule` (`core-network/.../kyc`) are implemented,
  package base `com.testlogon.android`; DTOs are referenced only (no redefinition
  of shared types).
- Open questions Q-1/Q-2/Q-3 (cursor pagination, undocumented tier schema,
  version sourcing) are resolved against `/openapi.json` and
  `src/api/endpoints/kyc.ts`, and the interface's return types/verbs/path params
  reflect the confirmed contract.
- `KycDtoRoundTripTest` and `KycApiContractTest` (T-1..T-11) are implemented and
  green in CI; ≥90% line coverage on the new surface; committed fixtures under
  `core-model/src/test/resources/kyc/`; every endpoint has a verb/path assertion.
- No second `OkHttpClient`/`Retrofit`; no manual cookie/CSRF/Authorization headers
  in the interface; `v1/kyc/cases` bodies and KYC file paths/`user_sub` are
  redacted in logs and `toString()` (verified).
- `./gradlew :core-model:testDebugUnitTest :core-network:assemble
  :core-network:testDebugUnitTest` passes locally and in CI with no new
  lint/detekt violations (AND-005 config).
- Code reviewed and merged to `android-port`; the KYC repository / feature
  (AND-320+) is unblocked.
- A one-line note in the `core-network` README (owned by AND-007) records the
  `KycApi` path/verb map and the delegation of cookie/CSRF/refresh to
  AND-011/AND-012/AND-013.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the authoritative source. Sources are
exact pointers: OpenAPI `METHOD /path` / schema name (from
`reference/openapi.index.txt` + `reference/openapi.pretty.json`), or a frontend
path, or a framework reference URL.

1. **Scope = `/v1/kyc/tiers/me*` + `/v1/kyc/cases*` (self-service portal), not
   `/v1/kyc/{tiers,me,requirements,evaluate,cases}`.** VERDICT: **Corrected.**
   SOURCE: OpenAPI `GET /v1/kyc/tiers/me`, `POST /v1/kyc/tiers/me/evaluate`,
   `GET /v1/kyc/tiers/me/requirements/{target_tier}`, `GET|POST /v1/kyc/cases`,
   `GET|PATCH /v1/kyc/cases/{case_id}`; `src/api/endpoints/kyc.ts` (header comment
   "wrap the EXISTING /v1/kyc/cases endpoints (app/routers/kyc_cases.py)").
2. **No public `GET /v1/kyc/tiers` catalog, no `GET /v1/kyc/me`, no
   `GET /v1/kyc/requirements?…`, no `POST /v1/kyc/evaluate`.** VERDICT:
   **Corrected** (these paths are absent from the index). SOURCE:
   `reference/openapi.index.txt` (grep `v1/kyc` — only `tiers/me*`, `tiers/admin*`,
   and `cases*` exist; tier catalog is admin-only `GET /v1/kyc/tiers/admin/...`).
3. **`tierRequirements` target tier is a PATH param, not a query.** VERDICT:
   **Corrected.** SOURCE: OpenAPI `GET /v1/kyc/tiers/me/requirements/{target_tier}`
   (`params=target_tier` as a path placeholder).
4. **`evaluateTier` (`POST /v1/kyc/tiers/me/evaluate`) takes NO request body.**
   VERDICT: **Corrected.** SOURCE: OpenAPI index `req=` (empty) for
   `evaluate_my_tier_v1_kyc_tiers_me_evaluate_post`.
5. **Tier endpoints publish no response schema.** VERDICT:
   **Unverified-assumption** (typed shape unknown — modeled as `ResponseBody`).
   SOURCE: OpenAPI index `resp=200:` (no schema name) for the three `tiers/me*`
   ops; not present in `components.schemas`.
6. **`POST /v1/kyc/cases` returns `200` (not `201`) with `KycCaseEnvelope`.**
   VERDICT: **Corrected.** SOURCE: OpenAPI `POST /v1/kyc/cases`
   `resp=200:KycCaseEnvelope`; schema `KycCaseEnvelope = { case: KycCaseOut }`
   (openapi.pretty.json line 41484).
7. **List endpoint is `{ items, next_cursor }` (`KycCaseListEnvelope`), not
   `{ cases: [...] }`.** VERDICT: **Corrected.** SOURCE: schema
   `KycCaseListEnvelope` (openapi.pretty.json 41496) `required:[items]`;
   `src/api/types.ts: KycSelfServiceCaseListEnvelope { items, next_cursor }`.
8. **Single case is `{ case }` (`KycCaseEnvelope`), not a bare `KycCase`.**
   VERDICT: **Corrected.** SOURCE: OpenAPI `GET /v1/kyc/cases/{case_id}`
   `resp=200:KycCaseEnvelope`.
9. **Case id field is `kyc_case_id`, not `case_id`.** VERDICT: **Corrected.**
   SOURCE: schema `KycCaseOut.kyc_case_id` (openapi.pretty.json 41554);
   `src/api/types.ts: KycSelfServiceCase.kyc_case_id`.
10. **Case status vocabulary = `draft|submitted|under_review|needs_more_info|
    approved|rejected|expired`, NOT `unverified|pending|verified|rejected|
    review`.** VERDICT: **Corrected.** SOURCE: `KycCaseOut.status.enum`
    (openapi.pretty.json 41574-41586); `src/api/types.ts: KycCaseStatus`.
11. **Timestamps (`created_at`/`updated_at`) are epoch-second INTEGERS, not
    ISO-8601 strings.** VERDICT: **Corrected.** SOURCE: `KycCaseOut.created_at`/
    `updated_at` `type:integer`, `required` (openapi.pretty.json 41531, 41592,
    41617-41624); `src/api/types.ts: KycSelfServiceCase.created_at: number`.
12. **`KycCaseOut` required fields = `kyc_case_id, user_sub, status, created_at,
    updated_at, version`.** VERDICT: **Verified.** SOURCE: `KycCaseOut.required`
    (openapi.pretty.json 41617-41624). `version` is an integer optimistic lock.
13. **`KycFileAttachmentRequest = { expected_version(int,≥1), path(str 1..1024),
    file_type }` with `file_type ∈ selfie|id_front|id_back|proof_of_address`.**
    VERDICT: **Verified.** SOURCE: schema `KycFileAttachmentRequest`
    (openapi.pretty.json 42626-42656); `src/api/types.ts: KycSelfServiceFileType`.
14. **`KycCaseCreateRequest = { intake_profile? }`,
    `KycCaseDraftPatchRequest = { expected_version(req), intake_profile? }`,
    `KycSubmitCaseRequest = { expected_version(req) }`.** VERDICT: **Verified.**
    SOURCE: schemas at openapi.pretty.json 41438, 41457, 46065.
15. **All user-facing `/v1/kyc/*` error responses are `422: HTTPValidationError`
    (`{ detail: ValidationError[] }`, `ValidationError = {loc,msg,type}`); no
    documented `404` for an unknown case id.** VERDICT: **Corrected** (spec
    assumed `404` on `case`). SOURCE: OpenAPI index `resp=...;422:HTTPValidationError`
    on every kyc op; `HTTPValidationError` schema (openapi.pretty.json 37133).
16. **Web auth = `Authorization: Bearer <accessToken>` + `X-CSRF-Token` (from
    `ui_csrf` cookie) + session cookies (`credentials:include`); 401 triggers one
    `POST /ui/session/refresh` then retry.** VERDICT: **Corrected** (spec said
    "cookie-based" only). SOURCE: `src/api/client.ts` (lines ~157-171 Bearer+CSRF;
    ~121-130 + ~204-236 refresh-and-retry).
17. **`estimated-wait` is a static segment under `/v1/kyc/cases/` (resolves before
    `{case_id}`).** VERDICT: **Verified.** SOURCE: OpenAPI
    `GET /v1/kyc/cases/estimated-wait` (`KycEstimatedWaitEnvelope`); web
    `src/api/endpoints/kyc.ts: getKycEstimatedWait`.
18. **Plaintext document PII lives on out-of-scope `/v1/kyc/cases/{id}/pii*`
    endpoints (write/decrypt/masked/audit-log), not in this ticket's DTOs.**
    VERDICT: **Verified** (informs §8 redaction scope). SOURCE: OpenAPI
    `POST /v1/kyc/cases/{case_id}/pii`, `…/pii/decrypt`, `…/pii/masked`,
    `…/pii/audit-log`.
19. **Module/stack pins (Retrofit 2.11.0, Moshi 1.15.x KSP, Hilt, JDK 17,
    minSdk 24 / compileSdk 35, AGP 8.7.3 / Gradle 8.9) and Hilt `@IntoSet`
    Moshi-adapter multibinding.** VERDICT: **Unverified-assumption** (internal
    Android-port conventions; no source in the provided references — inherited from
    AND-010/AND-009/AND-003). SOURCE: none available to confirm here.
20. **Dev base URL `http://18.222.237.167:8000/` (cleartext).** VERDICT:
    **Unverified-assumption** (AND-006 config; not in provided references).
    SOURCE: none available to confirm here.
21. **Retrofit `@Path`/`@Query`/`@Body`/`@Headers` and `suspend` returns; Moshi
    `@JsonClass(generateAdapter=true)`, `@Json(name=…)`, `@FromJson`/`@ToJson`.**
    VERDICT: **Verified (framework ref).** SOURCE:
    https://square.github.io/retrofit/ and https://github.com/square/moshi.

### Corrections made

- **Endpoint set / verbs / paths** rewritten to the real two routers (tier +
  self-service case); removed nonexistent `tiers`/`me`/query-`requirements`/
  body-`evaluate` (claims 1-4, 6).
- **`requirements` query → path param** (claim 3); **`evaluate` body removed**
  (claim 4).
- **DTOs entirely rewritten** to `KycCaseOut`/envelopes/request schemas; dropped
  `KycTier*`/`KycMeResp`/`KycRequirement*`/`KycEvaluate*`/`KycFieldSubmission`/
  `KycCasesResp` (claims 6-9, 13-14).
- **Status enum** `KycStatus` → `KycCaseStatus` with the real 7-value set; added
  `KycFileType`; renamed adapters to `KycCaseStatusAdapter`/`KycFileTypeAdapter`
  (claims 10) — propagated to §4.1/§4.4/§11/§14/§15.
- **Timestamps** `String` ISO-8601 → `Long` epoch seconds (claim 11) — §4.2/§6/§8.
- **Envelopes** list `{cases}` → `{items,next_cursor}`, single → `{case}`
  (claims 7-8) — §4.2/§5/§13 R-1.
- **Error model** 401/404-centric → 422 HTTPValidationError; removed the
  `404`-on-unknown-case claim (claim 15) — §2/§5/§7/§14 AC-6.
- **Auth** "cookie-based" → Bearer + CSRF + cookies (claim 16) — §2/§8.
- **PII/redaction** retargeted from `v1/kyc/evaluate`/`KycEvaluateReq` to
  `v1/kyc/cases` bodies + `KycFileAttachmentRequest.path`/`user_sub` (claim 18) —
  §8/§10/§13 R-4.
- **Frontend path** corrected from `frontend/src/api/...` to `src/api/...`
  (actual reference location) — §2/§12/§15.

### Open assumptions

- **Tier endpoint response shapes (claim 5):** unverifiable — OpenAPI publishes no
  schema for `tiers/me`, `tiers/me/evaluate`, `tiers/me/requirements/{target_tier}`.
  Typed `ResponseBody` until the backend publishes a model. (§13 R-2)
- **Stack/version pins and dev base URL (claims 19-20):** internal Android-port
  conventions inherited from upstream AND tickets; not present in the provided
  backend/frontend references, so accepted as-is, unverified.
- **Cursor pagination semantics on `listCases` (`next_cursor`):** the param name
  is verified; how the client passes a cursor back (query? header?) is not shown in
  `src/api/endpoints/kyc.ts: listKycCases` (no cursor arg) — assume repository
  concern. (§13 Q-1)
- **Exact non-2xx code for an unknown/unowned case id:** OpenAPI documents only
  `200`/`422`; whether the backend returns `422`, `403`, or `404` at runtime is
  not provable from the spec — treated as generic `HttpException`. (§7)

## 17. Test Plan

Test targets: **JVM** = JVM/Robolectric local unit (no device); **emulator** =
headless AVD `test35` (x86_64, API 35); **device** = physical Samsung Galaxy A15
5G (SM-A156U, API 34, arm64-v8a). This ticket is a headless transport/
serialization layer, so most cases are JVM contract/round-trip; a few
instrumented cases verify Hilt wiring and the redaction-in-logcat constraint on
real hardware.

- **TC-AND-319-01 — `createCase` happy path (contract/MockWebServer).**
  Target: JVM. Preconditions: MockWebServer enqueues the §5 create `200` body.
  Steps: build `KycApi` via the §11 harness; call
  `createCase(KycCaseCreateRequest("standard"))`; capture `RecordedRequest`.
  Expected: method `POST`, path `/v1/kyc/cases`, body `{"intake_profile":
  "standard"}`; response decodes `case.kycCaseId`, `case.status==DRAFT`,
  `case.createdAt: Long`, `case.version==1`, `missingRequirements` non-empty.
  Traces: AC-2, AC-3.

- **TC-AND-319-02 — `listCases` envelope + empty-body (contract/MockWebServer).**
  Target: JVM. Preconditions: enqueue `{ "items":[…], "next_cursor":null }` and,
  in a second dispatch, `{ "items":[], "next_cursor":"c2" }`. Steps: call
  `listCases()` twice. Expected: `GET /v1/kyc/cases`; first decodes `items[0]`
  fields and `nextCursor==null`; second yields empty `items` and
  `nextCursor=="c2"` (no crash on empty list). Traces: AC-3.

- **TC-AND-319-03 — `tierRequirements` path-param resolution
  (contract/MockWebServer).** Target: JVM. Preconditions: enqueue any `200` body.
  Steps: call `tierRequirements("tier1")`; inspect `RecordedRequest.path`.
  Expected: path is exactly `/v1/kyc/tiers/me/requirements/tier1` — **no**
  `?target_tier=` query string. Traces: AC-3, AC-4.

- **TC-AND-319-04 — `evaluateTier` empty body + `attachFile`/`submitCase` bodies
  (contract/MockWebServer).** Target: JVM. Steps: call `evaluateTier()`;
  `attachFile("kyc_1", KycFileAttachmentRequest(1,"/kyc/1/id_front.jpg",
  ID_FRONT))`; `submitCase("kyc_1", KycSubmitCaseRequest(2))`. Expected:
  `evaluateTier` → `POST /v1/kyc/tiers/me/evaluate` with **empty/zero-length
  body**; `attachFile` → `POST /v1/kyc/cases/kyc_1/files` with body containing
  `"file_type":"id_front"` and `"expected_version":1`; `submitCase` → `POST
  /v1/kyc/cases/kyc_1/submit` with `{"expected_version":2}`. Traces: AC-3, AC-4.

- **TC-AND-319-05 — `getCase`/`readiness`/`estimatedWait` decode + path routing
  (contract/MockWebServer).** Target: JVM. Steps: call `getCase("kyc_1")`,
  `readiness("kyc_1")`, `estimatedWait()`. Expected: paths
  `/v1/kyc/cases/kyc_1`, `/v1/kyc/cases/kyc_1/readiness`,
  `/v1/kyc/cases/estimated-wait` (the last NOT captured by `{case_id}`); decode
  `{case}`, `{readiness}` (`readyToSubmit`, `checks` map), `{estimated_wait}`
  (`estimatedHours: Double`, nullable `queuePosition`, `message`). Traces: AC-3.

- **TC-AND-319-06 — unknown enum tolerance (unit/round-trip).** Target: JVM.
  Steps: deserialize a case body with `"status":"escalated"` and a file with
  `"file_type":"passport"`. Expected: `status==KycCaseStatus.UNKNOWN`,
  `fileType==KycFileType.UNKNOWN`; no exception. Traces: AC-5.

- **TC-AND-319-07 — required-field fail-fast + unknown-key tolerance
  (unit/round-trip).** Target: JVM. Steps: (a) deserialize a case body missing
  `kyc_case_id` (and separately `created_at`, `version`); (b) deserialize a valid
  case body with an extra `"server_time":123` key. Expected: (a) each throws
  `com.squareup.moshi.JsonDataException`; (b) decodes successfully, extra key
  ignored. Traces: AC-5.

- **TC-AND-319-08 — error propagation `422`/no-`404` (contract/MockWebServer).**
  Target: JVM. Preconditions: enqueue a `422` with an `HTTPValidationError` body
  for `submitCase` (stale version) and for `getCase("nope")`. Steps: call each.
  Expected: both throw `retrofit2.HttpException` with `code()==422`; the raw error
  body is accessible (`response().errorBody()`); the suite does **not** assert a
  `404`. Traces: AC-6.

- **TC-AND-319-09 — round-trip fidelity with epoch + snake_case
  (unit/round-trip).** Target: JVM. Preconditions: committed fixtures under
  `core-model/src/test/resources/kyc/*.json` for `KycCaseOut`,
  `KycCaseEnvelope`, `KycCaseListEnvelope`, readiness, estimated-wait, and each
  request DTO. Steps: deserialize→serialize→parse-tree compare. Expected:
  parsed-tree equality (key order/whitespace ignored); serialized keys are
  snake_case, enum tokens lowercase, and `created_at`/`updated_at` are **JSON
  integers** (not strings). Traces: AC-1, AC-2.

- **TC-AND-319-10 — PII `toString()` redaction (unit).** Target: JVM. Steps:
  build `KycFileAttachmentRequest(1,"/kyc/secret/id.jpg",ID_FRONT)` and a
  `KycCaseOut` with a real `user_sub`/file path; call `.toString()`. Expected:
  output masks `path` and `user_sub` (e.g. contains `path=***`, not the literal
  path); `expected_version`/`file_type`/`status` may remain. Traces: AC-8.

- **TC-AND-319-11 — Hilt singleton on shared Retrofit (instrumented).**
  Target: emulator (`test35`) — sufficient; `@HiltAndroidTest`. Steps: inject
  `KycApi` twice; inspect the providing graph. Expected: non-null, same instance
  on repeated injection; built from the shared `Retrofit` (no new
  `OkHttpClient`/`Retrofit`); no per-method cookie/CSRF/Authorization header is
  declared on the interface (reflection check on annotations). Traces: AC-7.

- **TC-AND-319-12 — redaction reaches no logcat on real hardware
  (instrumented/e2e).** Target: **device** (physical A15 — MUST run on device to
  read real logcat over adb and confirm OS-level logging behavior on API 34
  arm64, vs CI emulator). Preconditions: debug build with AND-009 redacting
  interceptor; MockWebServer (or loopback) serving a `KycCaseEnvelope` whose
  `case` carries a fake `user_sub` and file `path`. Steps: run `createCase` then
  `attachFile`; capture `adb logcat` during the call. Expected: the raw file
  `path`/`user_sub`/request body never appear in logcat (redacted); request
  succeeds. Traces: AC-8.

- **TC-AND-319-13 — flaky-dev-host / offline transport (contract/MockWebServer).**
  Target: JVM. Steps: (a) configure MockWebServer to delay the response beyond the
  client read timeout for a GET (`listCases`); (b) point the client at a closed
  port to simulate offline, call `listCases`. Expected: (a) a
  `java.net.SocketTimeoutException` (or `IOException`) propagates **unmapped** from
  the suspend call; (b) a `java.io.IOException`/`ConnectException` propagates
  unmapped (this layer adds no retry/offline handling — owned by AND-016/AND-018).
  Traces: AC-6 (clean propagation of non-HTTP failures).

- **TC-AND-319-14 — optimistic-concurrency conflict surfaces as `422` (manual /
  integration against dev).** Target: device or JVM integration against the dev
  host when reachable (flaky — skip/retry if host down). Preconditions: a real
  draft case; capture its `version`. Steps: call `patchDraft` once (succeeds, bumps
  version), then call `submitCase` with the **stale** `expected_version`. Expected:
  second call returns `422` (`HttpException(422)`) carrying an `HTTPValidationError`
  detail; no client-side mutation/retry. (If the dev host is unreachable, this is
  covered structurally by TC-08; documented as manual.) Traces: AC-6.

### Coverage matrix

| §14 AC | Covered by |
|--------|------------|
| AC-1 (DTOs + adapters exist/registered) | TC-09, TC-11 |
| AC-2 (payloads (de)serialize exactly)   | TC-01, TC-09 |
| AC-3 (verbs/paths/bodies per §5)        | TC-01, TC-02, TC-03, TC-04, TC-05 |
| AC-4 (path-param `target_tier`; bodies; empty `evaluate`) | TC-03, TC-04 |
| AC-5 (UNKNOWN fallback; fail-fast; extra keys) | TC-06, TC-07 |
| AC-6 (non-2xx → `HttpException`, no swallow; clean transport propagation) | TC-08, TC-13, TC-14 |
| AC-7 (Hilt singleton on shared Retrofit; no extra client; no manual headers) | TC-11 |
| AC-8 (`toString()` + log redaction)     | TC-10, TC-12 |
| AC-9 (CI build/tests/lint clean)        | All TCs run in CI (TC-12/TC-14 on device/dev) |
